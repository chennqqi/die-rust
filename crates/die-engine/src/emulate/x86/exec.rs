//! Interpreter backend — faithful port of upstream `_execOp`, `step`,
//! `run` and their helpers (`arch/xemux86.cpp`, pin `655e6da`).
//!
//! Upstream executes cached translation blocks; this port decodes each
//! instruction at the current RIP inside `run`, which is observationally
//! identical (the TB cache is a pure optimization) and makes
//! self-modifying code coherent by construction — there is no stale
//! translation to invalidate.

use super::mmx::*;
use super::*;

impl<'a> X86<'a> {
    /// Resolve a memory operand to a linear address
    /// (upstream `_resolveAddr`). With `offset_only` (LEA) the raw
    /// effective offset is returned without the segment base.
    pub(crate) fn resolve_addr(
        &mut self,
        op: &MicroOp,
        operand: &Operand,
        regs: &Registers,
    ) -> u64 {
        self.resolve_addr_ex(op, operand, regs, false)
    }

    /// `resolve_addr` with the upstream `bOffsetOnly` flag.
    pub(crate) fn resolve_addr_ex(
        &mut self,
        op: &MicroOp,
        operand: &Operand,
        regs: &Registers,
        offset_only: bool,
    ) -> u64 {
        let addr_size = if self.bits == 64 { 8 } else { 4 };

        let mut address: u64;
        if operand.rip_rel {
            address = op
                .address
                .wrapping_add(op.length as u64)
                .wrapping_add(operand.disp as u64);
        } else {
            let mut value = operand.disp;
            if operand.base_reg >= 0 {
                value =
                    value.wrapping_add(regs.get_gpr(operand.base_reg as usize, addr_size) as i64);
            }
            if operand.index_reg >= 0 {
                value = value.wrapping_add(
                    (regs.get_gpr(operand.index_reg as usize, addr_size) as i64)
                        .wrapping_mul(operand.scale as i64),
                );
            }
            address = value as u64;
            if addr_size == 4 {
                address &= 0xFFFF_FFFF;
            }
        }

        if offset_only {
            return if self.bits == 16 {
                address & 0xFFFF
            } else {
                address
            };
        }

        if operand.seg_source == 1 {
            address = address.wrapping_add(regs.fs_base);
        } else if operand.seg_source == 2 {
            address = address.wrapping_add(regs.gs_base);
        } else if self.bits == 16 {
            // Real mode: offset wraps at 64 KiB, linear = (seg << 4) + off.
            // Default segment is SS for BP/SP-based addressing, else DS.
            let seg: u16 = match operand.seg_source {
                3 => regs.es,
                4 => regs.cs,
                5 => regs.ss,
                6 => regs.ds,
                _ => {
                    if operand.base_reg == GPR_RBP as i32 || operand.base_reg == GPR_RSP as i32 {
                        regs.ss
                    } else {
                        regs.ds
                    }
                }
            };
            address = (address & 0xFFFF) + ((seg as u64) << 4);
        }

        self.wrap_a20(address)
    }

    /// Read an operand (register or memory) at `size`
    /// (upstream `_readOpnd`); a failed memory read latches the
    /// execute-time fault with its linear address.
    fn read_opnd(&mut self, op: &MicroOp, operand: &Operand, regs: &Registers, size: i32) -> u64 {
        if operand.is_reg {
            if operand.high8 {
                return (regs.get_gpr(operand.reg as usize, 2) >> 8) & 0xFF; // AH/CH/DH/BH
            }
            return regs.get_gpr(operand.reg as usize, size as usize);
        }

        let address = self.resolve_addr(op, operand, regs);
        let value = match size {
            1 => self.mem.read_u8(address).map(u64::from),
            2 => self.mem.read_u16(address).map(u64::from),
            4 => self.mem.read_u32(address).map(u64::from),
            _ => self.mem.read_u64(address),
        };
        match value {
            Some(v) => v,
            None => {
                self.exec_fault = true;
                self.fault_addr = address;
                0
            }
        }
    }

    /// Write an operand at `size` (upstream `_writeOpnd`); a failed
    /// memory write latches the execute-time fault.
    fn write_opnd(
        &mut self,
        op: &MicroOp,
        operand: &Operand,
        regs: &mut Registers,
        size: i32,
        value: u64,
    ) {
        if operand.is_reg {
            if operand.high8 {
                let cur = regs.get_gpr(operand.reg as usize, 2);
                regs.set_gpr(
                    operand.reg as usize,
                    2,
                    (cur & 0x00FF) | ((value & 0xFF) << 8),
                );
                return;
            }
            regs.set_gpr(operand.reg as usize, size as usize, value);
            return;
        }

        let address = self.resolve_addr(op, operand, regs);
        let ok = match size {
            1 => self.mem.write_u8(address, value as u8),
            2 => self.mem.write_u16(address, value as u16),
            4 => self.mem.write_u32(address, value as u32),
            _ => self.mem.write_u64(address, value),
        };
        if !ok {
            self.exec_fault = true;
            self.fault_addr = address;
        }
    }

    /// Push `value` at `size` bytes (upstream `_push`); the real-mode
    /// target linear address is (SS << 4) + SP.
    fn push(&mut self, regs: &mut Registers, value: u64, size: i32) {
        let sp_size = if self.bits == 64 {
            8
        } else if self.bits == 16 {
            2
        } else {
            4
        };
        let sp = regs.get_gpr(GPR_RSP, sp_size).wrapping_sub(size as u64);
        regs.set_gpr(GPR_RSP, sp_size, sp);

        // Re-read the masked SP — a wrap must land inside the stack segment.
        let mut sp_linear = regs.get_gpr(GPR_RSP, sp_size);
        if self.bits == 16 {
            sp_linear += (regs.ss as u64) << 4;
        }

        let ok = match size {
            2 => self.mem.write_u16(sp_linear, value as u16),
            4 => self.mem.write_u32(sp_linear, value as u32),
            _ => self.mem.write_u64(sp_linear, value),
        };
        if !ok {
            self.exec_fault = true;
            self.fault_addr = sp_linear;
        }
    }

    /// Pop `size` bytes (upstream `_pop`).
    fn pop(&mut self, regs: &mut Registers, size: i32) -> u64 {
        let sp_size = if self.bits == 64 {
            8
        } else if self.bits == 16 {
            2
        } else {
            4
        };
        let sp_offset = regs.get_gpr(GPR_RSP, sp_size);

        let mut sp = sp_offset;
        if self.bits == 16 {
            sp += (regs.ss as u64) << 4;
        }

        let value = match size {
            2 => self.mem.read_u16(sp).map(u64::from),
            4 => self.mem.read_u32(sp).map(u64::from),
            _ => self.mem.read_u64(sp),
        };
        let value = match value {
            Some(v) => v,
            None => {
                self.exec_fault = true;
                self.fault_addr = sp;
                0
            }
        };

        regs.set_gpr(GPR_RSP, sp_size, sp_offset.wrapping_add(size as u64));
        value
    }

    /// Sized memory element read (upstream `_memReadSized`) with the
    /// real-mode A20 wrap; faults latch the execute-time fault.
    pub(crate) fn mem_read_sized(&mut self, address: u64, size: i32) -> u64 {
        let address = self.wrap_a20(address);
        let value = match size {
            1 => self.mem.read_u8(address).map(u64::from),
            2 => self.mem.read_u16(address).map(u64::from),
            4 => self.mem.read_u32(address).map(u64::from),
            _ => self.mem.read_u64(address),
        };
        match value {
            Some(v) => v,
            None => {
                self.exec_fault = true;
                self.fault_addr = address;
                0
            }
        }
    }

    /// Sized memory element write (upstream `_memWriteSized`).
    pub(crate) fn mem_write_sized(&mut self, address: u64, value: u64, size: i32) {
        let address = self.wrap_a20(address);
        let ok = match size {
            1 => self.mem.write_u8(address, value as u8),
            2 => self.mem.write_u16(address, value as u16),
            4 => self.mem.write_u32(address, value as u32),
            _ => self.mem.write_u64(address, value),
        };
        if !ok {
            self.exec_fault = true;
            self.fault_addr = address;
        }
    }

    // --- Flags --------------------------------------------------------------

    /// ADD flags (upstream `_setFlagsAdd`).
    fn set_flags_add(&self, regs: &mut Registers, a: u64, b: u64, res: u64, size: i32) {
        let mask = Self::mask(size);
        let sign = Self::sign_bit(size);
        let a = a & mask;
        let b = b & mask;
        let r = res & mask;

        let cf = if size < 8 {
            ((a + b) >> (size * 8)) & 1 != 0
        } else {
            r < a
        };
        let of = (!(a ^ b) & (a ^ r) & sign) != 0;
        let af = (a ^ b ^ r) & 0x10 != 0;

        regs.set_flag(FLAG_CF, cf);
        regs.set_flag(FLAG_OF, of);
        regs.set_flag(FLAG_AF, af);
        regs.set_flag(FLAG_ZF, r == 0);
        regs.set_flag(FLAG_SF, (r & sign) != 0);
        regs.set_flag(FLAG_PF, Self::parity(r as u8));
    }

    /// SUB/CMP flags (upstream `_setFlagsSub`).
    fn set_flags_sub(&self, regs: &mut Registers, a: u64, b: u64, res: u64, size: i32) {
        let mask = Self::mask(size);
        let sign = Self::sign_bit(size);
        let a = a & mask;
        let b = b & mask;
        let r = res & mask;

        regs.set_flag(FLAG_CF, a < b);
        regs.set_flag(FLAG_OF, (a ^ b) & (a ^ r) & sign != 0);
        regs.set_flag(FLAG_AF, (a ^ b ^ r) & 0x10 != 0);
        regs.set_flag(FLAG_ZF, r == 0);
        regs.set_flag(FLAG_SF, (r & sign) != 0);
        regs.set_flag(FLAG_PF, Self::parity(r as u8));
    }

    /// ADC flags with the true carry-out of a+b+carry
    /// (upstream `_setFlagsAdc`).
    fn set_flags_adc(&self, regs: &mut Registers, a: u64, b: u64, carry: u64, res: u64, size: i32) {
        let mask = Self::mask(size);
        let sign = Self::sign_bit(size);
        let a = a & mask;
        let b = b & mask;
        let r = res & mask;

        let cf = if size < 8 {
            ((a + b + carry) >> (size * 8)) & 1 != 0
        } else {
            let low = a.wrapping_add(b);
            (low < a) || (low.wrapping_add(carry) < low)
        };

        regs.set_flag(FLAG_CF, cf);
        regs.set_flag(FLAG_OF, (!(a ^ b) & (a ^ r) & sign) != 0);
        regs.set_flag(FLAG_AF, ((a & 0xF) + (b & 0xF) + carry) & 0x10 != 0);
        regs.set_flag(FLAG_ZF, r == 0);
        regs.set_flag(FLAG_SF, (r & sign) != 0);
        regs.set_flag(FLAG_PF, Self::parity(r as u8));
    }

    /// SBB flags (upstream `_setFlagsSbb`); underflow is a<=b with
    /// borrow, a<b without.
    fn set_flags_sbb(
        &self,
        regs: &mut Registers,
        a: u64,
        b: u64,
        borrow: u64,
        res: u64,
        size: i32,
    ) {
        let mask = Self::mask(size);
        let sign = Self::sign_bit(size);
        let a = a & mask;
        let b = b & mask;
        let r = res & mask;

        let cf = if borrow != 0 { a <= b } else { a < b };

        regs.set_flag(FLAG_CF, cf);
        regs.set_flag(FLAG_OF, (a ^ b) & (a ^ r) & sign != 0);
        regs.set_flag(
            FLAG_AF,
            (a & 0xF).wrapping_sub(b & 0xF).wrapping_sub(borrow) & 0x10 != 0,
        );
        regs.set_flag(FLAG_ZF, r == 0);
        regs.set_flag(FLAG_SF, (r & sign) != 0);
        regs.set_flag(FLAG_PF, Self::parity(r as u8));
    }

    /// Logic-op flags (upstream `_setFlagsLogic`): CF/OF/AF cleared.
    fn set_flags_logic(&self, regs: &mut Registers, res: u64, size: i32) {
        let r = res & Self::mask(size);
        regs.set_flag(FLAG_CF, false);
        regs.set_flag(FLAG_OF, false);
        regs.set_flag(FLAG_AF, false);
        regs.set_flag(FLAG_ZF, r == 0);
        regs.set_flag(FLAG_SF, (r & Self::sign_bit(size)) != 0);
        regs.set_flag(FLAG_PF, Self::parity(r as u8));
    }

    /// INC/DEC flags — CF is preserved by the caller not writing it
    /// (upstream `_setFlagsIncDec`).
    fn set_flags_incdec(&self, regs: &mut Registers, a: u64, res: u64, size: i32, inc: bool) {
        let mask = Self::mask(size);
        let sign = Self::sign_bit(size);
        let a = a & mask;
        let r = res & mask;

        regs.set_flag(
            FLAG_OF,
            ((if inc { !(a ^ 1) } else { a ^ 1 }) & (a ^ r) & sign) != 0,
        );
        regs.set_flag(FLAG_AF, (a ^ 1 ^ r) & 0x10 != 0);
        regs.set_flag(FLAG_ZF, r == 0);
        regs.set_flag(FLAG_SF, (r & sign) != 0);
        regs.set_flag(FLAG_PF, Self::parity(r as u8));
    }

    /// ALU compute + flags (upstream `_aluCompute`); returns the masked
    /// result and whether to write it back (CMP suppresses writeback).
    fn alu_compute(
        &self,
        regs: &mut Registers,
        alu_op: i32,
        a: u64,
        b: u64,
        size: i32,
    ) -> (u64, bool) {
        let mut write_back = true;
        let carry = if regs.flag(FLAG_CF) { 1 } else { 0 };
        let result = match alu_op {
            0 => {
                let r = a.wrapping_add(b);
                self.set_flags_add(regs, a, b, r, size);
                r
            }
            1 => {
                let r = a | b;
                self.set_flags_logic(regs, r, size);
                r
            }
            2 => {
                let r = a.wrapping_add(b).wrapping_add(carry);
                self.set_flags_adc(regs, a, b, carry, r, size);
                r
            }
            3 => {
                let r = a.wrapping_sub(b).wrapping_sub(carry);
                self.set_flags_sbb(regs, a, b, carry, r, size);
                r
            }
            4 => {
                let r = a & b;
                self.set_flags_logic(regs, r, size);
                r
            }
            5 => {
                let r = a.wrapping_sub(b);
                self.set_flags_sub(regs, a, b, r, size);
                r
            }
            6 => {
                let r = a ^ b;
                self.set_flags_logic(regs, r, size);
                r
            }
            _ => {
                let r = a.wrapping_sub(b);
                self.set_flags_sub(regs, a, b, r, size);
                write_back = false;
                r
            }
        };
        (result & Self::mask(size), write_back)
    }

    /// Shift/rotate with flags (upstream `_doShift`). Count 0 is a
    /// no-op that returns `None` upstream's early-exit equivalent: the
    /// value unchanged and flags untouched.
    fn do_shift(
        &self,
        regs: &mut Registers,
        shift_op: i32,
        value: u64,
        size: i32,
        count: u8,
    ) -> u64 {
        let mask = Self::mask(size);
        let sign = Self::sign_bit(size);
        let bits = size * 8;
        let mut v = value & mask;

        // x86 masks the count to 5 bits (6 for a 64-bit operand).
        let cnt = if size == 8 {
            count & 0x3F
        } else {
            count & 0x1F
        };
        if cnt == 0 {
            return v; // no operation, flags unaffected
        }

        let mut cf = regs.flag(FLAG_CF);
        let mut of: bool;

        match shift_op {
            0 => {
                // ROL
                for _ in 0..cnt {
                    let msb = (v & sign) != 0;
                    v = ((v << 1) | u64::from(msb)) & mask;
                    cf = msb;
                }
                of = ((v & sign) != 0) != cf;
            }
            1 => {
                // ROR
                for _ in 0..cnt {
                    let lsb = (v & 1) != 0;
                    v = ((v >> 1) | if lsb { sign } else { 0 }) & mask;
                    cf = lsb;
                }
                of = ((v & sign) != 0) != ((v << 1) & sign != 0);
            }
            2 => {
                // RCL (rotate through carry)
                for _ in 0..cnt {
                    let msb = (v & sign) != 0;
                    v = ((v << 1) | u64::from(cf)) & mask;
                    cf = msb;
                }
                of = ((v & sign) != 0) != cf;
            }
            3 => {
                // RCR
                for _ in 0..cnt {
                    let lsb = (v & 1) != 0;
                    let old_cf = cf;
                    cf = lsb;
                    v = ((v >> 1) | if old_cf { sign } else { 0 }) & mask;
                }
                of = ((v & sign) != 0) != ((v << 1) & sign != 0);
            }
            4 | 6 => {
                // SHL / SAL
                cf = if cnt <= bits as u8 {
                    ((v >> (bits - cnt as i32)) & 1) != 0
                } else {
                    false
                };
                v = v.wrapping_shl(cnt as u32) & mask;
                of = ((v & sign) != 0) != cf;
            }
            5 => {
                // SHR (logical)
                cf = ((v >> (cnt - 1)) & 1) != 0;
                of = (value & sign) != 0; // OF (count 1) = MSB of original
                v = (v >> cnt) & mask;
            }
            _ => {
                // SAR (arithmetic): at count >= width every shifted-out bit
                // is the sign, so CF settles on the sign.
                let eff = cnt.min(bits as u8);
                cf = ((v >> (eff - 1)) & 1) != 0;
                v = (Self::sign_extend(v, size) >> cnt) as u64 & mask;
                of = false;
            }
        }

        // OF for multi-bit shifts is "undefined" but real x86 is
        // consistent: SHL keeps OF = MSB(result) ^ CF; SHR clears it
        // for count > 1.
        if shift_op == 5 && cnt > 1 {
            of = false;
        }

        regs.set_flag(FLAG_CF, cf);
        regs.set_flag(FLAG_OF, of);

        if shift_op >= 4 {
            // Shifts (not rotates) also set SF/ZF/PF; AF is "undefined"
            // but real x86 sets it — packers fold it into their keys.
            regs.set_flag(FLAG_ZF, (v & mask) == 0);
            regs.set_flag(FLAG_SF, (v & sign) != 0);
            regs.set_flag(FLAG_PF, Self::parity(v as u8));
            regs.set_flag(FLAG_AF, true);
        }

        v & mask
    }

    /// Condition-code evaluation (upstream `_evalCond`).
    fn eval_cond(&self, regs: &Registers, cond: u8) -> bool {
        let cf = regs.flag(FLAG_CF);
        let zf = regs.flag(FLAG_ZF);
        let sf = regs.flag(FLAG_SF);
        let of = regs.flag(FLAG_OF);
        let pf = regs.flag(FLAG_PF);

        let base = match cond >> 1 {
            0 => of,
            1 => cf,
            2 => zf,
            3 => cf || zf,
            4 => sf,
            5 => pf,
            6 => sf != of,
            _ => zf || (sf != of),
        };

        if cond & 1 != 0 { !base } else { base }
    }

    // --- Executor -------------------------------------------------------------

    /// Execute one decoded micro-op (upstream `_execOp`). `regs` is the
    /// guest register file; `info` receives the step outcome.
    fn exec_op(&mut self, op: &MicroOp, regs: &mut Registers, info: &mut StepInfo) {
        self.exec_fault = false;
        self.insn_count += 1; // physical time base for the PIT/retrace models
        let tf_before = regs.flag(FLAG_TF); // for the single-step trap below

        info.result = StepResult::Ok;
        info.address = op.address;
        info.length = op.length;
        info.text = op.text.clone();

        let n_fall = op.address.wrapping_add(op.length as u64);
        let mut branch = false;
        let ptr_size = if self.bits == 64 {
            8
        } else if self.bits == 16 {
            2
        } else {
            4
        };

        // Real mode keeps a linear PC, but a near ret / indirect near
        // jmp|call recovers only the 16-bit IP: re-form the linear
        // address as (CS << 4) + IP for those.
        let code_seg_base = if self.bits == 16 {
            (regs.cs as u64) << 4
        } else {
            0
        };

        match op.kind {
            MicroOpKind::Nop => {}
            MicroOpKind::AluRmR | MicroOpKind::AluRRm => {
                let a = self.read_opnd(op, &op.dst, regs, op.size);
                let b = self.read_opnd(op, &op.src, regs, op.size);
                let (r, write_back) = self.alu_compute(regs, op.alu_op, a, b, op.size);
                if write_back {
                    self.write_opnd(op, &op.dst, regs, op.size, r);
                }
            }
            MicroOpKind::AluRaxImm => {
                let a = regs.get_gpr(GPR_RAX, op.size as usize);
                let (r, write_back) =
                    self.alu_compute(regs, op.alu_op, a, op.imm & Self::mask(op.size), op.size);
                if write_back {
                    regs.set_gpr(GPR_RAX, op.size as usize, r);
                }
            }
            MicroOpKind::AluRmImm => {
                let a = self.read_opnd(op, &op.dst, regs, op.size);
                let (r, write_back) = self.alu_compute(regs, op.alu_op, a, op.imm, op.size);
                if write_back {
                    self.write_opnd(op, &op.dst, regs, op.size, r);
                }
            }
            MicroOpKind::Mov => {
                let v = self.read_opnd(op, &op.src, regs, op.size);
                self.write_opnd(op, &op.dst, regs, op.size, v);
            }
            MicroOpKind::MovImm => {
                self.write_opnd(op, &op.dst, regs, op.size, op.imm);
            }
            MicroOpKind::Lea => {
                let ea = self.resolve_addr_ex(op, &op.src, regs, true) & Self::mask(op.size);
                regs.set_gpr(op.dst.reg as usize, op.size as usize, ea);
            }
            MicroOpKind::Movzx => {
                let v = self.read_opnd(op, &op.src, regs, op.src_size) & Self::mask(op.src_size);
                regs.set_gpr(op.dst.reg as usize, op.size as usize, v);
            }
            MicroOpKind::Movsx => {
                let v =
                    Self::sign_extend(self.read_opnd(op, &op.src, regs, op.src_size), op.src_size)
                        as u64
                        & Self::mask(op.size);
                regs.set_gpr(op.dst.reg as usize, op.size as usize, v);
            }
            MicroOpKind::Test => {
                let a = self.read_opnd(op, &op.dst, regs, op.size);
                let b = self.read_opnd(op, &op.src, regs, op.size);
                self.set_flags_logic(regs, a & b, op.size);
            }
            MicroOpKind::TestImm => {
                let v = self.read_opnd(op, &op.dst, regs, op.size);
                self.set_flags_logic(regs, v & op.imm, op.size);
            }
            MicroOpKind::Push => {
                let v = if op.src.is_reg || op.src.is_mem {
                    self.read_opnd(op, &op.src, regs, op.size)
                } else {
                    op.imm
                };
                self.push(regs, v, op.size);
            }
            MicroOpKind::Pop => {
                let v = self.pop(regs, op.size);
                self.write_opnd(op, &op.dst, regs, op.size, v);
            }
            MicroOpKind::IncDec => {
                let a = self.read_opnd(op, &op.dst, regs, op.size);
                let r = if op.alu_op == 0 {
                    a.wrapping_add(1)
                } else {
                    a.wrapping_sub(1)
                };
                self.set_flags_incdec(regs, a, r, op.size, op.alu_op == 0);
                self.write_opnd(op, &op.dst, regs, op.size, r);
            }
            MicroOpKind::Setcc => {
                let v = if self.eval_cond(regs, op.cond) { 1 } else { 0 };
                self.write_opnd(op, &op.dst, regs, 1, v);
            }
            MicroOpKind::Cmovcc => {
                if self.eval_cond(regs, op.cond) {
                    let v = self.read_opnd(op, &op.src, regs, op.size);
                    regs.set_gpr(op.dst.reg as usize, op.size as usize, v);
                }
            }
            MicroOpKind::Jmp => {
                regs.rip = wrap_near_branch(self.bits, code_seg_base, op.branch_target);
                branch = true;
            }
            MicroOpKind::JmpInd => {
                let t = self.read_opnd(op, &op.src, regs, op.size);
                regs.rip =
                    wrap_near_branch(self.bits, code_seg_base, code_seg_base.wrapping_add(t));
                branch = true;
            }
            MicroOpKind::Jcc => {
                regs.rip = if self.eval_cond(regs, op.cond) {
                    wrap_near_branch(self.bits, code_seg_base, op.branch_target)
                } else {
                    n_fall
                };
                branch = true;
            }
            MicroOpKind::Call => {
                // Real mode pushes the 16-bit return IP (offset within CS).
                let ret = if self.bits == 16 {
                    n_fall.wrapping_sub(code_seg_base)
                } else {
                    n_fall
                };
                self.push(regs, ret, ptr_size);
                regs.rip = wrap_near_branch(self.bits, code_seg_base, op.branch_target);
                branch = true;
            }
            MicroOpKind::CallInd => {
                let t = self.read_opnd(op, &op.src, regs, op.size);
                let target =
                    wrap_near_branch(self.bits, code_seg_base, code_seg_base.wrapping_add(t));
                let ret = if self.bits == 16 {
                    n_fall.wrapping_sub(code_seg_base)
                } else {
                    n_fall
                };
                self.push(regs, ret, ptr_size);
                regs.rip = target;
                branch = true;
            }
            MicroOpKind::JmpFar => {
                let new_cs = op.imm as u16;
                regs.cs = new_cs;
                regs.rip = ((new_cs as u64) << 4).wrapping_add(op.branch_target & 0xFFFF);
                branch = true;
            }
            MicroOpKind::CallFar => {
                let new_cs = op.imm as u16;
                let ret_ip = (n_fall.wrapping_sub(code_seg_base) & 0xFFFF) as u16;
                self.push(regs, regs.cs as u64, 2); // CS then IP (RETF pops IP first)
                self.push(regs, ret_ip as u64, 2);
                regs.cs = new_cs;
                regs.rip = ((new_cs as u64) << 4).wrapping_add(op.branch_target & 0xFFFF);
                branch = true;
            }
            MicroOpKind::JmpFarInd | MicroOpKind::CallFarInd => {
                let ptr = self.resolve_addr(op, &op.src, regs);
                let new_ip = self.mem.read_u16(ptr);
                let new_cs = self.mem.read_u16(ptr.wrapping_add(op.size as u64));
                let (new_ip, new_cs) = match (new_ip, new_cs) {
                    (Some(ip), Some(cs)) => (ip, cs),
                    _ => {
                        self.exec_fault = true;
                        self.fault_addr = ptr;
                        (0, 0)
                    }
                };
                if !self.exec_fault {
                    if op.kind == MicroOpKind::CallFarInd {
                        let ret_ip = (n_fall.wrapping_sub(code_seg_base) & 0xFFFF) as u16;
                        self.push(regs, regs.cs as u64, 2);
                        self.push(regs, ret_ip as u64, 2);
                    }
                    regs.cs = new_cs;
                    regs.rip = ((new_cs as u64) << 4).wrapping_add(new_ip as u64);
                    branch = true;
                }
            }
            MicroOpKind::LoadFar => {
                let ptr = self.resolve_addr(op, &op.src, regs);
                let off = self.mem_read_sized(ptr, op.size);
                let seg = self.mem_read_sized(ptr.wrapping_add(op.size as u64), 2) as u16;
                if !self.exec_fault {
                    regs.set_gpr(op.dst.reg as usize, op.size as usize, off);
                    match op.cond {
                        0 => regs.es = seg,
                        1 => regs.ds = seg,
                        2 => {
                            regs.ss = seg;
                            self.ss_block = true; // LSS inhibits the trap for one insn
                        }
                        3 => {
                            regs.fs = seg;
                            regs.fs_base = (seg as u64) << 4;
                        }
                        _ => {
                            regs.gs = seg;
                            regs.gs_base = (seg as u64) << 4;
                        }
                    }
                }
            }
            MicroOpKind::Retf => {
                if self.bits == 16 {
                    // Real-mode far return: pop IP then CS.
                    let new_ip = self.pop(regs, 2) as u16;
                    let new_cs = self.pop(regs, 2) as u16;
                    regs.cs = new_cs;
                    regs.rip = ((new_cs as u64) << 4).wrapping_add(new_ip as u64);
                } else {
                    // Protected-mode far return: pop operand-size EIP/RIP
                    // then the (zero-extended) CS selector.
                    let n_op = if op.size > 0 { op.size } else { ptr_size };
                    let new_ip = self.pop(regs, n_op);
                    let new_cs = self.pop(regs, n_op);
                    regs.cs = new_cs as u16;
                    regs.rip = code_seg_base.wrapping_add(new_ip);
                }
                if op.imm != 0 {
                    let sp_size = if self.bits == 16 { 2 } else { 4 };
                    let sp = regs.get_gpr(GPR_RSP, sp_size).wrapping_add(op.imm);
                    regs.set_gpr(GPR_RSP, sp_size, sp);
                }
                branch = true;
            }
            MicroOpKind::Iret => {
                // Real-mode interrupt return: pop IP, CS, FLAGS.
                let new_ip = self.pop(regs, 2) as u16;
                let new_cs = self.pop(regs, 2) as u16;
                let new_flags = self.pop(regs, 2) as u16;
                regs.cs = new_cs;
                regs.rip = ((new_cs as u64) << 4).wrapping_add(new_ip as u64);
                regs.rflags = (regs.rflags & !0xFFFF) | new_flags as u64;
                regs.rflags |= 0x2;
                regs.rflags &= !0x8028; // reserved bits 3, 5, 15 always 0
                branch = true;
            }
            MicroOpKind::Ret => {
                let target = code_seg_base.wrapping_add(self.pop(regs, ptr_size));
                if op.imm != 0 {
                    let sp_size = if self.bits == 64 {
                        8
                    } else if self.bits == 16 {
                        2
                    } else {
                        4
                    };
                    let sp = regs.get_gpr(GPR_RSP, sp_size).wrapping_add(op.imm);
                    regs.set_gpr(GPR_RSP, sp_size, sp);
                }
                regs.rip = target;
                branch = true;
            }
            MicroOpKind::Halt => {
                info.result = StepResult::Halt;
                regs.rip = n_fall;
                return;
            }
            MicroOpKind::Rdtsc => {
                self.tsc += 0x100;
                regs.set_gpr(GPR_RAX, 4, self.tsc & 0xFFFF_FFFF);
                regs.set_gpr(GPR_RDX, 4, (self.tsc >> 32) & 0xFFFF_FFFF);
            }
            MicroOpKind::Cpuid => {
                let leaf = regs.get_gpr(GPR_RAX, 4) as u32;
                let (mut a, mut b, mut c, mut d) = (0u32, 0u32, 0u32, 0u32);
                if leaf == 0 {
                    a = 1;
                    b = 0x756E_6547; // "Genu"
                    d = 0x4965_6E69; // "ineI"
                    c = 0x6C65_746E; // "ntel"
                } else if leaf == 1 {
                    a = 0x0000_0601;
                    d = 0x078B_FBFF;
                }
                regs.set_gpr(GPR_RAX, 4, a as u64);
                regs.set_gpr(GPR_RBX, 4, b as u64);
                regs.set_gpr(GPR_RCX, 4, c as u64);
                regs.set_gpr(GPR_RDX, 4, d as u64);
            }
            MicroOpKind::Pusha => {
                let sz = op.size;
                let orig_sp = regs.get_gpr(GPR_RSP, ptr_size as usize);
                const ORDER: [i32; 8] = [
                    GPR_RAX as i32,
                    GPR_RCX as i32,
                    GPR_RDX as i32,
                    GPR_RBX as i32,
                    -1, // orig ESP
                    GPR_RBP as i32,
                    GPR_RSI as i32,
                    GPR_RDI as i32,
                ];
                for index in ORDER {
                    let v = if index < 0 {
                        orig_sp
                    } else {
                        regs.get_gpr(index as usize, sz as usize)
                    };
                    self.push(regs, v, sz);
                }
            }
            MicroOpKind::Popa => {
                let sz = op.size;
                let v = self.pop(regs, sz);
                regs.set_gpr(GPR_RDI, sz as usize, v);
                let v = self.pop(regs, sz);
                regs.set_gpr(GPR_RSI, sz as usize, v);
                let v = self.pop(regs, sz);
                regs.set_gpr(GPR_RBP, sz as usize, v);
                let _ = self.pop(regs, sz); // discard the saved ESP slot
                let v = self.pop(regs, sz);
                regs.set_gpr(GPR_RBX, sz as usize, v);
                let v = self.pop(regs, sz);
                regs.set_gpr(GPR_RDX, sz as usize, v);
                let v = self.pop(regs, sz);
                regs.set_gpr(GPR_RCX, sz as usize, v);
                let v = self.pop(regs, sz);
                regs.set_gpr(GPR_RAX, sz as usize, v);
            }
            MicroOpKind::PushF => {
                // Reserved bit 15 / VM / RF read 0; AC (18) is settable in
                // 16-bit real mode (the 386 reference) and masked elsewhere.
                let v = regs.rflags & !(if self.bits == 16 { 0x238000 } else { 0x78000 });
                self.push(regs, v, op.size);
            }
            MicroOpKind::PopF => {
                let v = self.pop(regs, op.size);
                let mask = match op.size {
                    2 => 0xFFFFu64,
                    8 => u64::MAX,
                    _ => 0xFFFF_FFFF,
                };
                regs.rflags = (regs.rflags & !mask) | (v & mask);
                regs.rflags |= 0x2; // reserved bit 1 reads 1
                regs.rflags &= !(if self.bits == 16 { 0x208028 } else { 0x48028 });
            }
            MicroOpKind::Sahf => {
                // EFLAGS[SF ZF 0 AF 0 PF 1 CF] <- AH (mask 0xD5).
                let rax_size = if self.bits == 64 { 8 } else { 4 };
                let ah = (regs.get_gpr(GPR_RAX, rax_size) >> 8) & 0xFF;
                regs.rflags = (regs.rflags & !0xD5) | (ah & 0xD5);
            }
            MicroOpKind::Lahf => {
                let rax_size = if self.bits == 64 { 8 } else { 4 };
                let ah = (regs.rflags & 0xD5) | 0x02;
                let rax = (regs.get_gpr(GPR_RAX, rax_size) & !0xFF00) | (ah << 8);
                regs.set_gpr(GPR_RAX, rax_size, rax);
            }
            MicroOpKind::Enter => {
                let level = op.alu_op & 0x1F;
                let bp = regs.get_gpr(GPR_RBP, ptr_size as usize);
                self.push(regs, bp, ptr_size);
                let frame = regs.get_gpr(GPR_RSP, ptr_size as usize);
                for _ in 1..level {
                    let bp = regs.get_gpr(GPR_RBP, ptr_size as usize);
                    regs.set_gpr(GPR_RBP, ptr_size as usize, bp.wrapping_sub(ptr_size as u64));
                    let addr = (if self.bits == 16 {
                        (regs.ss as u64) << 4
                    } else {
                        0
                    })
                    .wrapping_add(bp.wrapping_sub(ptr_size as u64) & Self::mask(ptr_size));
                    let v = self.mem_read_sized(addr, ptr_size);
                    self.push(regs, v, ptr_size);
                }
                if level > 0 {
                    self.push(regs, frame, ptr_size);
                }
                regs.set_gpr(GPR_RBP, ptr_size as usize, frame);
                let sp = regs
                    .get_gpr(GPR_RSP, ptr_size as usize)
                    .wrapping_sub(op.imm);
                regs.set_gpr(GPR_RSP, ptr_size as usize, sp);
            }
            MicroOpKind::Leave => {
                let bp = regs.get_gpr(GPR_RBP, ptr_size as usize);
                regs.set_gpr(GPR_RSP, ptr_size as usize, bp);
                let v = self.pop(regs, ptr_size);
                regs.set_gpr(GPR_RBP, ptr_size as usize, v);
            }
            MicroOpKind::In => {
                // Modeled low-ISA ports (PIC/PIT/keyboard); everything
                // else is open-bus all-ones.
                let port = if op.cond == 0 {
                    op.imm as u16
                } else {
                    regs.get_gpr(GPR_RDX, 2) as u16
                };
                let mut value = Self::mask(op.size);
                if (0x40..=0x42).contains(&port) {
                    // 8253/8254 PIT: count down from 0xFFFF off the
                    // instruction counter; alternate lo/hi reads.
                    let count =
                        (0xFFFFu32.wrapping_sub((self.insn_count >> 2) as u32 & 0xFFFF)) as u16;
                    self.pit_hi_byte = !self.pit_hi_byte;
                    value = if self.pit_hi_byte {
                        (count & 0xFF) as u64
                    } else {
                        ((count >> 8) & 0xFF) as u64
                    };
                } else if port == 0x3DA || port == 0x3BA {
                    // VGA Input Status #1 modeled off the instruction
                    // count: ~1 frame per 3072 instructions.
                    const FRAME: u32 = 3072;
                    let phase = (self.insn_count % FRAME as u64) as u32;
                    let mut stat = 0u8;
                    if phase >= FRAME - 768 {
                        stat |= 0x01; // blanking
                    }
                    if phase >= FRAME - 256 {
                        stat |= 0x08; // vertical retrace
                    }
                    value = stat as u64;
                } else if port < 0x400 {
                    value = self.io_ports[port as usize] as u64;
                    if op.size >= 2 {
                        value |= (self.io_ports[((port + 1) & 0x3FF) as usize] as u64) << 8;
                    }
                    if op.size == 4 {
                        value |= ((self.io_ports[((port + 2) & 0x3FF) as usize] as u64) << 16)
                            | ((self.io_ports[((port + 3) & 0x3FF) as usize] as u64) << 24);
                    }
                }
                regs.set_gpr(GPR_RAX, op.size as usize, value & Self::mask(op.size));
            }
            MicroOpKind::Out => {
                // Latch writes to modeled ports; elsewhere discarded.
                let port = if op.cond == 0 {
                    op.imm as u16
                } else {
                    regs.get_gpr(GPR_RDX, 2) as u16
                };
                let v = regs.get_gpr(GPR_RAX, op.size as usize);
                if port < 0x400 {
                    self.io_ports[port as usize] = v as u8;
                    if op.size >= 2 {
                        self.io_ports[((port + 1) & 0x3FF) as usize] = (v >> 8) as u8;
                    }
                    if op.size == 4 {
                        self.io_ports[((port + 2) & 0x3FF) as usize] = (v >> 16) as u8;
                        self.io_ports[((port + 3) & 0x3FF) as usize] = (v >> 24) as u8;
                    }
                }
            }
            MicroOpKind::Salc => {
                regs.set_gpr(GPR_RAX, 1, if regs.flag(FLAG_CF) { 0xFF } else { 0x00 });
            }
            MicroOpKind::Smsw => {
                // MSW = CR0 low bits; real mode on a 386+FPU reads 0x0010
                // (ET set, PE clear).
                self.write_opnd(op, &op.dst, regs, op.size, 0x0010 & Self::mask(op.size));
            }
            MicroOpKind::Lsl => {
                self.write_opnd(op, &op.dst, regs, op.size, op.imm & Self::mask(op.size));
                regs.set_flag(FLAG_ZF, true);
            }
            MicroOpKind::MovDr => {
                // DR4/DR5 alias DR6/DR7; the write masks are the reserved-bit
                // behavior the CPU applies.
                let dr = if op.alu_op == 4 {
                    6
                } else if op.alu_op == 5 {
                    7
                } else {
                    op.alu_op
                } as usize;
                if op.cond == 0 {
                    let v = self.dr[dr & 7] as u64;
                    self.write_opnd(op, &op.dst, regs, 4, v);
                } else {
                    let mut v = self.read_opnd(op, &op.src, regs, 4) as u32;
                    if dr == 6 {
                        v = (v | 0xFFFF_0FF0) & 0xFFFF_EFFF;
                    } else if dr == 7 {
                        v = (v | 0x0000_0400) & 0xFFFF_2FFF;
                    }
                    self.dr[dr & 7] = v;
                }
            }
            MicroOpKind::MovFromCr => {
                // CR0 = 0x00000010 (ET set, real mode); CR2/3/4 read 0.
                let v = if op.alu_op == 0 { 0x0000_0010 } else { 0 };
                self.write_opnd(op, &op.dst, regs, 4, v);
            }
            MicroOpKind::Xlat => {
                // AL = [seg:(BX + AL)].
                let bx = regs.get_gpr(GPR_RBX, op.size as usize);
                let al = regs.get_gpr(GPR_RAX, 1);
                let off = bx.wrapping_add(al) & Self::mask(op.size);
                let mut seg_base = 0u64;
                if op.src.seg_source == 1 {
                    seg_base = regs.fs_base;
                } else if op.src.seg_source == 2 {
                    seg_base = regs.gs_base;
                } else if self.bits == 16 {
                    let seg = match op.src.seg_source {
                        3 => regs.es,
                        4 => regs.cs,
                        5 => regs.ss,
                        _ => regs.ds, // 0 or 6 -> DS
                    };
                    seg_base = (seg as u64) << 4;
                }
                let v = self.mem_read_sized(seg_base.wrapping_add(off), 1);
                regs.set_gpr(GPR_RAX, 1, v);
            }
            MicroOpKind::PushSeg => {
                let seg = match op.alu_op {
                    0 => regs.es,
                    1 => regs.cs,
                    2 => regs.ss,
                    4 => regs.fs,
                    5 => regs.gs,
                    _ => regs.ds,
                };
                self.push(regs, seg as u64, ptr_size);
            }
            MicroOpKind::PopSeg => {
                let seg = self.pop(regs, ptr_size) as u16;
                match op.alu_op {
                    0 => regs.es = seg,
                    2 => {
                        regs.ss = seg;
                        self.ss_block = true; // POP SS inhibits the next trap
                    }
                    4 => {
                        regs.fs = seg;
                        regs.fs_base = (seg as u64) << 4;
                    }
                    5 => {
                        regs.gs = seg;
                        regs.gs_base = (seg as u64) << 4;
                    }
                    _ => regs.ds = seg,
                }
            }
            MicroOpKind::Into => {
                if regs.flag(FLAG_OF) {
                    regs.rip = n_fall;
                    info.result = StepResult::Syscall;
                    info.vector = 4;
                    info.comment = "into".into();
                    return;
                }
            }
            MicroOpKind::Arpl => {
                let dst = self.read_opnd(op, &op.dst, regs, 2) as u16;
                let src = self.read_opnd(op, &op.src, regs, 2) as u16;
                if (dst & 3) < (src & 3) {
                    self.write_opnd(op, &op.dst, regs, 2, ((dst & !3) | (src & 3)) as u64);
                    regs.set_flag(FLAG_ZF, true);
                } else {
                    regs.set_flag(FLAG_ZF, false);
                }
            }
            MicroOpKind::Bcd => {
                let al = regs.get_gpr(GPR_RAX, 1) as u8;
                let ah = ((regs.get_gpr(GPR_RAX, 2) >> 8) & 0xFF) as u8;
                let mut cf = regs.flag(FLAG_CF);
                let mut af = regs.flag(FLAG_AF);
                match op.alu_op {
                    0 | 1 => {
                        // DAA / DAS
                        let mut al = al;
                        let old_al = al;
                        let old_cf = cf;
                        let mut new_cf = false;
                        if (al & 0x0F) > 9 || af {
                            let r = if op.alu_op == 0 {
                                al as i32 + 6
                            } else {
                                al as i32 - 6
                            };
                            al = r as u8;
                            new_cf = old_cf || (r & 0x100) != 0;
                            af = true;
                        } else {
                            af = false;
                        }
                        if old_al > 0x99 || old_cf {
                            al = if op.alu_op == 0 {
                                al.wrapping_add(0x60)
                            } else {
                                al.wrapping_sub(0x60)
                            };
                            new_cf = true;
                        }
                        regs.set_gpr(GPR_RAX, 1, al as u64);
                        self.set_flags_logic(regs, al as u64, 1);
                        regs.set_flag(FLAG_CF, new_cf);
                        regs.set_flag(FLAG_AF, af);
                    }
                    2 | 3 => {
                        // AAA / AAS: adjust the whole AX by 0x106.
                        let mut ax = regs.get_gpr(GPR_RAX, 2) as u16;
                        if (ax & 0x0F) > 9 || af {
                            ax = if op.alu_op == 2 {
                                ax.wrapping_add(0x106)
                            } else {
                                ax.wrapping_sub(0x106)
                            };
                            af = true;
                            cf = true;
                        } else {
                            af = false;
                            cf = false;
                        }
                        ax &= 0xFF0F;
                        regs.set_gpr(GPR_RAX, 2, ax as u64);
                        regs.set_flag(FLAG_AF, af);
                        regs.set_flag(FLAG_CF, cf);
                    }
                    4 => {
                        // AAM: AH = AL / base, AL = AL % base.
                        let base = if op.imm as u8 != 0 { op.imm as u8 } else { 10 };
                        set_ax_bytes(regs, al % base, al / base);
                        self.set_flags_logic(regs, (al % base) as u64, 1);
                    }
                    _ => {
                        // AAD: AL = (AL + AH*base) & 0xFF, AH = 0.
                        let base = if op.imm as u8 != 0 { op.imm as u8 } else { 10 };
                        let res = al.wrapping_add(ah.wrapping_mul(base));
                        set_ax_bytes(regs, res, 0);
                        self.set_flags_logic(regs, res as u64, 1);
                    }
                }
            }
            MicroOpKind::MovSeg => {
                if op.cond == 0 {
                    // mov Sreg, r/m16.
                    let v = self.read_opnd(op, &op.src, regs, 2) as u16;
                    match op.alu_op {
                        0 => regs.es = v,
                        1 => regs.cs = v,
                        2 => {
                            regs.ss = v;
                            self.ss_block = true; // MOV SS inhibits the next trap
                        }
                        3 => regs.ds = v,
                        4 => {
                            regs.fs = v;
                            regs.fs_base = (v as u64) << 4;
                        }
                        _ => {
                            regs.gs = v;
                            regs.gs_base = (v as u64) << 4;
                        }
                    }
                } else {
                    // mov r/m16, Sreg.
                    let v = match op.alu_op {
                        0 => regs.es,
                        1 => regs.cs,
                        2 => regs.ss,
                        3 => regs.ds,
                        4 => regs.fs,
                        _ => regs.gs,
                    };
                    self.write_opnd(op, &op.dst, regs, 2, v as u64);
                }
            }
            MicroOpKind::Fpu => self.exec_fpu(op, regs),
            MicroOpKind::Shift => {
                let count = if op.cond == 1 {
                    regs.get_gpr(GPR_RCX, 1) as u8
                } else {
                    op.imm as u8
                };
                let a = self.read_opnd(op, &op.dst, regs, op.size);
                let r = self.do_shift(regs, op.alu_op, a, op.size, count);
                self.write_opnd(op, &op.dst, regs, op.size, r);
            }
            MicroOpKind::ShiftD => {
                // SHLD/SHRD dst, src, count.
                let bits = op.size * 8;
                let mut count = if op.cond == 1 {
                    regs.get_gpr(GPR_RCX, 1) as u8
                } else {
                    op.imm as u8
                };
                count &= if op.size == 8 { 0x3F } else { 0x1F };
                if count != 0 {
                    let mask = Self::mask(op.size);
                    let sign = Self::sign_bit(op.size);
                    let dst = self.read_opnd(op, &op.dst, regs, op.size) & mask;
                    let src = self.read_opnd(op, &op.src, regs, op.size) & mask;

                    let (v, cf) = if op.alu_op == 0 {
                        // SHLD: dst <<= count, low bits filled from src's high end.
                        let cf = if count <= bits as u8 {
                            ((dst >> (bits - count as i32)) & 1) != 0
                        } else {
                            false
                        };
                        let fill = if count < bits as u8 {
                            src >> (bits - count as i32)
                        } else {
                            0
                        };
                        (((dst << count) | fill) & mask, cf)
                    } else {
                        // SHRD: dst >>= count, high bits filled from src's low end.
                        let cf = ((dst >> (count - 1)) & 1) != 0;
                        let fill = if count < bits as u8 {
                            src << (bits - count as i32)
                        } else {
                            0
                        };
                        (((dst >> count) | fill) & mask, cf)
                    };

                    // OF = sign change on the final 1-bit step.
                    let v_prev = {
                        let prev = count - 1;
                        if prev == 0 {
                            dst
                        } else if op.alu_op == 0 {
                            ((dst << prev) | (src >> (bits - prev as i32))) & mask
                        } else {
                            ((dst >> prev) | (src << (bits - prev as i32))) & mask
                        }
                    };
                    let of = ((v & sign) != 0) != ((v_prev & sign) != 0);

                    self.write_opnd(op, &op.dst, regs, op.size, v);
                    if !self.exec_fault {
                        regs.set_flag(FLAG_CF, cf);
                        regs.set_flag(FLAG_OF, of);
                        regs.set_flag(FLAG_ZF, (v & mask) == 0);
                        regs.set_flag(FLAG_SF, (v & sign) != 0);
                        regs.set_flag(FLAG_PF, Self::parity(v as u8));
                        regs.set_flag(FLAG_AF, true); // undefined; real x86 sets it
                    }
                }
            }
            MicroOpKind::Mmx => match op.alu_op {
                MMX_EMMS => {}
                MMX_MOVD_TO => {
                    let v = if op.src_size == 8 {
                        self.read_opnd(op, &op.src, regs, 8)
                    } else {
                        (self.read_opnd(op, &op.src, regs, 4) as u32) as u64
                    };
                    self.write_mmx(op, &op.dst, regs, v);
                }
                MMX_MOVD_FROM => {
                    let v = self.read_mmx(op, &op.src, regs);
                    let v = if op.size == 8 { v } else { (v as u32) as u64 };
                    self.write_opnd(op, &op.dst, regs, op.size, v);
                }
                MMX_MOVQ_TO | MMX_MOVQ_FROM => {
                    let v = self.read_mmx(op, &op.src, regs);
                    self.write_mmx(op, &op.dst, regs, v);
                }
                MMX_PSHUFW => {
                    let s = self.read_mmx(op, &op.src, regs);
                    let ctrl = op.imm as u8;
                    let mut v = 0u64;
                    for i in 0..4 {
                        let sel = ((ctrl >> (i * 2)) & 3) as u64;
                        v |= ((s >> (sel * 16)) as u16 as u64) << (i * 16);
                    }
                    self.write_mmx(op, &op.dst, regs, v);
                }
                _ => {
                    if mmx_is_shift(op.alu_op) {
                        let a = self.read_mmx(op, &op.dst, regs);
                        let count = if op.cond == 1 {
                            op.imm
                        } else {
                            self.read_mmx(op, &op.src, regs)
                        };
                        let r = self.mmx_shift(op.alu_op, a, count);
                        self.write_mmx(op, &op.dst, regs, r);
                    } else {
                        let a = self.read_mmx(op, &op.dst, regs);
                        let b = self.read_mmx(op, &op.src, regs);
                        let r = self.mmx_alu(op.alu_op, a, b);
                        self.write_mmx(op, &op.dst, regs, r);
                    }
                }
            },
            MicroOpKind::Bt => {
                // BT/BTS/BTR/BTC; CF = tested bit, others undefined.
                let bits = op.size * 8;
                let raw_index = if op.cond == 1 {
                    Self::sign_extend(self.read_opnd(op, &op.src, regs, op.size), op.size)
                } else {
                    op.imm as i64
                };
                let bit;

                if op.dst.is_reg || op.cond == 0 {
                    // Register destination, or memory with an immediate
                    // offset: index modulo operand size.
                    let index = (raw_index as u64) & (bits as u64 - 1);
                    let mask = 1u64 << index;
                    let a = self.read_opnd(op, &op.dst, regs, op.size);
                    bit = (a & mask) != 0;
                    if op.alu_op != 0 {
                        let r = match op.alu_op {
                            1 => a | mask,
                            2 => a & !mask,
                            _ => a ^ mask,
                        };
                        self.write_opnd(op, &op.dst, regs, op.size, r);
                    }
                } else {
                    // Memory destination with a register offset: operate on
                    // the single addressed byte.
                    let addr = self.resolve_addr(op, &op.dst, regs);
                    let byte_addr = (addr as i64).wrapping_add(raw_index >> 3) as u64;
                    let bit_in_byte = (raw_index & 7) as u32;
                    let mask = 1u8 << bit_in_byte;
                    let byte = self.mem_read_sized(byte_addr, 1) as u8;
                    bit = (byte & mask) != 0;
                    if !self.exec_fault && op.alu_op != 0 {
                        let new = match op.alu_op {
                            1 => byte | mask,
                            2 => byte & !mask,
                            _ => byte ^ mask,
                        };
                        self.mem_write_sized(byte_addr, new as u64, 1);
                    }
                }

                regs.set_flag(FLAG_CF, bit);
            }
            MicroOpKind::Xchg => {
                let a = self.read_opnd(op, &op.dst, regs, op.size);
                let b = self.read_opnd(op, &op.src, regs, op.size);
                self.write_opnd(op, &op.dst, regs, op.size, b);
                self.write_opnd(op, &op.src, regs, op.size, a);
            }
            MicroOpKind::Xadd => {
                // TEMP = DEST + SRC (ADD flags); SRC = DEST; DEST = TEMP.
                let a = self.read_opnd(op, &op.dst, regs, op.size);
                let b = self.read_opnd(op, &op.src, regs, op.size);
                let (r, _) = self.alu_compute(regs, 0, a, b, op.size);
                self.write_opnd(op, &op.src, regs, op.size, a & Self::mask(op.size));
                self.write_opnd(op, &op.dst, regs, op.size, r);
            }
            MicroOpKind::Cdq => {
                if op.alu_op == 0 {
                    // cbw/cwde/cdqe: sign-extend the accumulator's lower half.
                    let src = (op.size / 2) as usize;
                    let v = regs.get_gpr(GPR_RAX, src);
                    let r = Self::sign_extend(v, src as i32) as u64 & Self::mask(op.size);
                    regs.set_gpr(GPR_RAX, op.size as usize, r);
                } else {
                    // cwd/cdq/cqo: replicate the sign across rDX.
                    let v = regs.get_gpr(GPR_RAX, op.size as usize);
                    let neg = (v & Self::sign_bit(op.size)) != 0;
                    regs.set_gpr(
                        GPR_RDX,
                        op.size as usize,
                        if neg { Self::mask(op.size) } else { 0 },
                    );
                }
            }
            MicroOpKind::Bswap => {
                let v = self.read_opnd(op, &op.dst, regs, op.size);
                let r = if op.size == 8 {
                    v.swap_bytes()
                } else {
                    // 4-byte form (bswap on a 16-bit register is undefined).
                    ((v & 0xFF) << 24)
                        | ((v & 0xFF00) << 8)
                        | ((v >> 8) & 0xFF00)
                        | ((v >> 24) & 0xFF)
                };
                self.write_opnd(op, &op.dst, regs, op.size, r & Self::mask(op.size));
            }
            MicroOpKind::Bsf | MicroOpKind::Bsr => {
                let src = self.read_opnd(op, &op.src, regs, op.size) & Self::mask(op.size);
                if src == 0 {
                    regs.set_flag(FLAG_ZF, true);
                } else {
                    let idx = if op.kind == MicroOpKind::Bsf {
                        src.trailing_zeros() as i32
                    } else {
                        // src is width-masked, so 63 - lz gives the bit
                        // index within the operand width.
                        (63 - src.leading_zeros()) as i32
                    };
                    regs.set_gpr(op.dst.reg as usize, op.size as usize, idx as u64);
                    regs.set_flag(FLAG_ZF, false);
                }
            }
            MicroOpKind::Imul2 => {
                // Two-operand (0F AF) or three-operand (0x69/0x6B).
                let a = Self::sign_extend(self.read_opnd(op, &op.src, regs, op.size), op.size);
                let b = if op.src_size < 0 {
                    op.imm as i64
                } else {
                    Self::sign_extend(self.read_opnd(op, &op.dst, regs, op.size), op.size)
                };
                let full = a.wrapping_mul(b);
                let r = (full as u64) & Self::mask(op.size);
                regs.set_gpr(op.dst.reg as usize, op.size as usize, r);
                let over = Self::sign_extend(r, op.size) != full;
                regs.set_flag(FLAG_CF, over);
                regs.set_flag(FLAG_OF, over);
            }
            MicroOpKind::MulDiv => {
                let a = self.read_opnd(op, &op.dst, regs, op.size);
                let sz_mask = Self::mask(op.size);

                if op.alu_op == 2 {
                    // NOT (no flags).
                    self.write_opnd(op, &op.dst, regs, op.size, !a & sz_mask);
                } else if op.alu_op == 3 {
                    // NEG
                    let r = (0u64.wrapping_sub(a)) & sz_mask;
                    self.set_flags_sub(regs, 0, a, r, op.size);
                    regs.set_flag(FLAG_CF, (a & sz_mask) != 0);
                    self.write_opnd(op, &op.dst, regs, op.size, r);
                } else if op.alu_op == 4 || op.alu_op == 5 {
                    // MUL / IMUL (one-operand).
                    let acc = regs.get_gpr(GPR_RAX, op.size as usize) & sz_mask;
                    let (lo, hi);
                    let over;
                    if op.alu_op == 4 {
                        // unsigned
                        if op.size <= 4 {
                            let prod = acc * (a & sz_mask);
                            lo = prod & sz_mask;
                            hi = (prod >> (op.size * 8)) & sz_mask;
                        } else {
                            lo = acc.wrapping_mul(a & sz_mask);
                            hi = 0; // 64-bit high half not modeled (upstream)
                        }
                        over = hi != 0;
                    } else {
                        // signed
                        let prod = Self::sign_extend(acc, op.size)
                            .wrapping_mul(Self::sign_extend(a, op.size));
                        lo = (prod as u64) & sz_mask;
                        hi = ((prod as u64) >> (op.size * 8)) & sz_mask;
                        over = Self::sign_extend(lo, op.size) != prod;
                    }
                    if op.size == 1 {
                        regs.set_gpr(GPR_RAX, 2, ((hi & 0xFF) << 8) | (lo & 0xFF));
                    } else {
                        regs.set_gpr(GPR_RAX, op.size as usize, lo);
                        regs.set_gpr(GPR_RDX, op.size as usize, hi);
                    }
                    regs.set_flag(FLAG_CF, over);
                    regs.set_flag(FLAG_OF, over);
                    // 16-bit-era CPUs materialise ZF from the low half;
                    // 32/64-bit leave the other flags unchanged.
                    if self.bits == 16 {
                        regs.set_flag(FLAG_ZF, (lo & sz_mask) == 0);
                    }
                } else {
                    // DIV (6) / IDIV (7).
                    if (a & sz_mask) == 0 {
                        // #DE: dispatch to a guest INT 0 handler if a real
                        // one is installed in the IVT; else stop faulted.
                        let h_off = self.mem_read_sized(0, 2) as u16;
                        let h_seg = self.mem_read_sized(2, 2) as u16;
                        if !self.exec_fault && h_seg != 0 && h_seg != 0xF000 {
                            let ret_ip = (op.address.wrapping_sub(code_seg_base) & 0xFFFF) as u16;
                            let flags = regs.rflags & 0xFFFF;
                            self.push(regs, flags, 2);
                            self.push(regs, regs.cs as u64, 2);
                            self.push(regs, ret_ip as u64, 2);
                            regs.set_flag(FLAG_IF, false);
                            regs.set_flag(FLAG_TF, false);
                            regs.cs = h_seg;
                            regs.rip = ((h_seg as u64) << 4).wrapping_add(h_off as u64);
                            branch = true;
                        } else {
                            self.exec_fault = false;
                            info.result = StepResult::Fault;
                            info.comment = "divide by zero".into();
                            return;
                        }
                    } else if op.size == 1 {
                        let num = regs.get_gpr(GPR_RAX, 2) as u16;
                        if op.alu_op == 6 {
                            let d = a as u8;
                            regs.set_gpr(
                                GPR_RAX,
                                2,
                                (((num % d as u16) << 8) | (num / d as u16)) as u64,
                            );
                        } else {
                            let s_num = num as i16;
                            let d = a as u8 as i8;
                            regs.set_gpr(
                                GPR_RAX,
                                2,
                                ((((s_num % d as i16) as u8 as u16) << 8)
                                    | ((s_num / d as i16) as u8 as u16))
                                    as u64,
                            );
                        }
                    } else {
                        let hi = regs.get_gpr(GPR_RDX, op.size as usize) & sz_mask;
                        let lo = regs.get_gpr(GPR_RAX, op.size as usize) & sz_mask;
                        if op.size <= 4 {
                            if op.alu_op == 6 {
                                // unsigned
                                let num = (hi << (op.size * 8)) | lo;
                                let d = a & sz_mask;
                                regs.set_gpr(GPR_RAX, op.size as usize, (num / d) & sz_mask);
                                regs.set_gpr(GPR_RDX, op.size as usize, (num % d) & sz_mask);
                            } else {
                                // signed
                                let mut num = ((hi << (op.size * 8)) | lo) as i64;
                                if op.size == 2 {
                                    num = (num as u32) as i32 as i64;
                                }
                                let d = Self::sign_extend(a, op.size);
                                regs.set_gpr(GPR_RAX, op.size as usize, (num / d) as u64 & sz_mask);
                                regs.set_gpr(GPR_RDX, op.size as usize, (num % d) as u64 & sz_mask);
                            }
                        } else {
                            // 64-bit: best-effort using rAX only (upstream).
                            let d = a & sz_mask;
                            regs.set_gpr(GPR_RAX, 8, lo / d);
                            regs.set_gpr(GPR_RDX, 8, lo % d);
                        }
                    }
                }
            }
            MicroOpKind::String => {
                let addr = if self.bits == 64 {
                    8
                } else if self.bits == 16 {
                    2
                } else {
                    4
                };
                let delta: i64 = if regs.flag(FLAG_DF) {
                    -(op.size as i64)
                } else {
                    op.size as i64
                };
                let rep = op.cond != 0;
                let mut count = if rep { regs.get_gpr(GPR_RCX, addr) } else { 1 };
                let mut host_iterations: u32 = 0;
                const MAX_HOST_ITERATIONS_PER_STEP: u32 = 65536;

                // Real mode: source at DS:SI (overridable), destination at
                // ES:DI. Flat mode: bases 0 except FS/GS.
                let mut src_seg_base: u64;
                let dst_seg_base: u64;
                if self.bits == 16 {
                    let src_seg = match op.src.seg_source {
                        3 => regs.es,
                        4 => regs.cs,
                        5 => regs.ss,
                        6 => regs.ds,
                        _ => regs.ds,
                    };
                    src_seg_base = (src_seg as u64) << 4;
                    dst_seg_base = (regs.es as u64) << 4;
                } else {
                    src_seg_base = 0;
                    dst_seg_base = 0;
                }
                if op.src.seg_source == 1 {
                    src_seg_base = regs.fs_base;
                } else if op.src.seg_source == 2 {
                    src_seg_base = regs.gs_base;
                }

                while count > 0 {
                    let esi = regs.get_gpr(GPR_RSI, addr);
                    let edi = regs.get_gpr(GPR_RDI, addr);
                    let src = src_seg_base.wrapping_add(esi);
                    let dst = dst_seg_base.wrapping_add(edi);

                    match op.alu_op {
                        0 => {
                            // movs
                            let v = self.mem_read_sized(src, op.size);
                            self.mem_write_sized(dst, v, op.size);
                            regs.set_gpr(GPR_RSI, addr, esi.wrapping_add(delta as u64));
                            regs.set_gpr(GPR_RDI, addr, edi.wrapping_add(delta as u64));
                        }
                        1 => {
                            // stos
                            let v = regs.get_gpr(GPR_RAX, op.size as usize);
                            self.mem_write_sized(dst, v, op.size);
                            regs.set_gpr(GPR_RDI, addr, edi.wrapping_add(delta as u64));
                        }
                        2 => {
                            // lods
                            let v = self.mem_read_sized(src, op.size);
                            regs.set_gpr(GPR_RAX, op.size as usize, v);
                            regs.set_gpr(GPR_RSI, addr, esi.wrapping_add(delta as u64));
                        }
                        3 => {
                            // scas: cmp accumulator, [ES:DI]
                            let acc = regs.get_gpr(GPR_RAX, op.size as usize);
                            let mem = self.mem_read_sized(dst, op.size);
                            self.set_flags_sub(regs, acc, mem, acc.wrapping_sub(mem), op.size);
                            regs.set_gpr(GPR_RDI, addr, edi.wrapping_add(delta as u64));
                        }
                        4 => {
                            // cmps
                            let v1 = self.mem_read_sized(src, op.size);
                            let v2 = self.mem_read_sized(dst, op.size);
                            self.set_flags_sub(regs, v1, v2, v1.wrapping_sub(v2), op.size);
                            regs.set_gpr(GPR_RSI, addr, esi.wrapping_add(delta as u64));
                            regs.set_gpr(GPR_RDI, addr, edi.wrapping_add(delta as u64));
                        }
                        5 => {
                            // ins: [ES:DI] = open-bus all-ones.
                            let v = Self::mask(op.size);
                            self.mem_write_sized(dst, v, op.size);
                            regs.set_gpr(GPR_RDI, addr, edi.wrapping_add(delta as u64));
                        }
                        _ => {
                            // outs: port write is a no-op; SI advances.
                            let _ = self.mem_read_sized(src, op.size);
                            regs.set_gpr(GPR_RSI, addr, esi.wrapping_add(delta as u64));
                        }
                    }

                    if self.exec_fault {
                        break;
                    }
                    if !rep {
                        break;
                    }

                    count -= 1;
                    regs.set_gpr(GPR_RCX, addr, count);

                    // repe stops on ZF=0; repne on ZF=1 (scas/cmps only).
                    if op.alu_op == 3 || op.alu_op == 4 {
                        let zf = regs.flag(FLAG_ZF);
                        if (op.cond == 1 && !zf) || (op.cond == 2 && zf) {
                            break;
                        }
                    }
                    host_iterations += 1;
                    if count > 0 && host_iterations >= MAX_HOST_ITERATIONS_PER_STEP {
                        // Re-issue the same instruction with the reduced RCX.
                        regs.rip = op.address;
                        branch = true;
                        break;
                    }
                }
            }
            MicroOpKind::Loop => {
                let addr = if self.bits == 64 {
                    8
                } else if self.bits == 16 {
                    2
                } else {
                    4
                };
                let jump = if op.alu_op == 3 {
                    // jecxz: branch when (E)CX == 0, no decrement.
                    regs.get_gpr(GPR_RCX, addr) == 0
                } else {
                    let count =
                        regs.get_gpr(GPR_RCX, addr).wrapping_sub(1) & Self::mask(addr as i32);
                    regs.set_gpr(GPR_RCX, addr, count);
                    let zf = regs.flag(FLAG_ZF);
                    match op.alu_op {
                        0 => count != 0 && !zf, // loopne
                        1 => count != 0 && zf,  // loope
                        _ => count != 0,        // loop
                    }
                };
                regs.rip = if jump {
                    wrap_near_branch(self.bits, code_seg_base, op.branch_target)
                } else {
                    n_fall
                };
                branch = true;
            }
            MicroOpKind::Syscall => {
                // Real-mode software interrupt: leave the FLAGS/CS/IP
                // frame in memory below SP (observable side effect).
                if self.bits == 16 && op.alu_op == 2 {
                    let ss_base = (regs.ss as u64) << 4;
                    let sp = regs.get_gpr(GPR_RSP, 2) as u16;
                    let ret_ip = (n_fall.wrapping_sub(code_seg_base) & 0xFFFF) as u16;
                    self.mem_write_sized(
                        ss_base.wrapping_add(sp.wrapping_sub(2) as u64),
                        regs.rflags & 0xFFFF,
                        2,
                    );
                    self.mem_write_sized(
                        ss_base.wrapping_add(sp.wrapping_sub(4) as u64),
                        regs.cs as u64,
                        2,
                    );
                    self.mem_write_sized(
                        ss_base.wrapping_add(sp.wrapping_sub(6) as u64),
                        ret_ip as u64,
                        2,
                    );
                }
                regs.rip = n_fall;
                info.result = StepResult::Syscall;
                info.vector = if op.alu_op >= 1 {
                    (op.imm & 0xFF) as i32
                } else {
                    -1 // bare 0F05 syscall
                };
                info.comment = match op.alu_op {
                    1 => "int 0x80".into(),
                    2 => "int".into(),
                    _ => "syscall".into(),
                };
                return;
            }
            MicroOpKind::FlagOp => {
                match op.alu_op {
                    0 => regs.set_flag(FLAG_CF, false),               // clc
                    1 => regs.set_flag(FLAG_CF, true),                // stc
                    2 => regs.set_flag(FLAG_CF, !regs.flag(FLAG_CF)), // cmc
                    3 => regs.set_flag(FLAG_DF, false),               // cld
                    4 => regs.set_flag(FLAG_DF, true),                // std
                    5 => regs.set_flag(FLAG_IF, false),               // cli
                    _ => regs.set_flag(FLAG_IF, true),                // sti
                }
            }
            MicroOpKind::Unimpl => {
                info.result = StepResult::Unimplemented;
                info.comment = "opcode not implemented".into();
                return; // leave RIP at the faulting instruction
            }
        }

        if self.exec_fault {
            info.result = StepResult::Fault;
            info.comment = format!("memory access violation @linear 0x{:x}", self.fault_addr);
            return; // leave RIP at the faulting instruction
        }

        if !branch {
            regs.rip = n_fall;
        }

        self.maybe_trap(regs, tf_before, info);
    }

    /// The single-step (TF) trap tail of `_execOp`: a POPF/IRET that
    /// sets TF does not trap after itself, while an SS load inhibits the
    /// trap after the NEXT instruction (`ss_block` consumed here).
    /// 16-bit mode only; an unset vector (segment 0) or a handler in the
    /// ROM area (>= A000) does not trap.
    fn maybe_trap(&mut self, regs: &mut Registers, tf_before: bool, info: &StepInfo) {
        let ss_blocked = self.ss_block;
        self.ss_block = false; // consumed: covers exactly one trap
        if !tf_before || ss_blocked || info.result != StepResult::Ok || self.bits != 16 {
            return;
        }
        let Some(h_off) = self.mem.read_u16(4) else {
            return;
        };
        let Some(h_seg) = self.mem.read_u16(6) else {
            return;
        };
        if h_seg == 0 || h_seg >= 0xA000 {
            return;
        }
        let ret_ip = (regs.rip.wrapping_sub((regs.cs as u64) << 4) & 0xFFFF) as u16;
        let flags = regs.rflags & 0xFFFF;
        self.push(regs, flags, 2);
        self.push(regs, regs.cs as u64, 2);
        self.push(regs, ret_ip as u64, 2);
        regs.set_flag(FLAG_IF, false);
        regs.set_flag(FLAG_TF, false); // the handler runs untraced
        regs.cs = h_seg;
        regs.rip = ((h_seg as u64) << 4) + h_off as u64;
        self.trap_taken = true; // tells run() to continue from the handler
    }

    /// Execute a single instruction at `regs.rip` (upstream `step`).
    pub fn step(&mut self, regs: &mut Registers) -> StepInfo {
        let mut info = StepInfo::ok();
        let Some(op) = self.decode_insn(regs.rip) else {
            info.result = StepResult::Fault;
            info.address = regs.rip;
            info.comment = "cannot fetch instruction".into();
            return info;
        };
        self.exec_op(&op, regs, &mut info);
        info
    }

    /// Execute up to `max_insns` instructions (upstream `run`);
    /// `max_insns <= 0` is unbounded. Returns the executed instruction
    /// count (including the terminating step); `stop_info` receives the
    /// last step's outcome.
    pub fn run(&mut self, regs: &mut Registers, max_insns: i64, stop_info: &mut StepInfo) -> i64 {
        let mut count: i64 = 0;
        let mut last = StepInfo::ok();

        while max_insns <= 0 || count < max_insns {
            let Some(op) = self.decode_insn(regs.rip) else {
                last = StepInfo {
                    result: StepResult::Fault,
                    address: regs.rip,
                    comment: "cannot fetch instruction".into(),
                    ..StepInfo::ok()
                };
                break;
            };

            let mut info = StepInfo::ok();
            self.exec_op(&op, regs, &mut info);
            last = info;
            count += 1;

            if last.result != StepResult::Ok {
                break;
            }
            // A block-terminating control transfer already updated RIP;
            // the next loop decodes at the new target — identical to the
            // upstream outer re-translate.
            if self.trap_taken {
                self.trap_taken = false;
            }
        }

        *stop_info = last;
        count
    }
}

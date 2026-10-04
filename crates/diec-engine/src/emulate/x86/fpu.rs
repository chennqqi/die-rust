//! x87 FPU model — faithful port of the FPU block in upstream
//! `arch/xemux86.cpp` (pin `655e6da`). The eight registers form a stack
//! over physical slots `fpu_reg[(fpu_top + i) & 7]`; values are held as
//! `f64` — 80-bit extended precision is approximated, exact for the
//! integer-valued and ordinary arithmetic code the unpackers rely on.
//! `fpu_int`/`fpu_is_int` shadow the exact 64-bit integer across FILD
//! so a later FIST/FISTP stores it losslessly above 2^53.

use super::*;

/// Decode an 80-bit extended float from guest memory
/// (upstream `readF80Value`).
fn read_f80(mem: &MemoryManager, address: u64) -> f64 {
    let mut mantissa: u64 = 0;
    for i in 0..8u64 {
        mantissa |= (mem.read_u8(address + i).unwrap_or(0) as u64) << (i * 8);
    }
    let signed_exp = mem.read_u8(address + 8).unwrap_or(0) as u16
        | ((mem.read_u8(address + 9).unwrap_or(0) as u16) << 8);
    let sign = (signed_exp >> 15) & 1;
    let exponent = signed_exp & 0x7FFF;
    if exponent == 0 && mantissa == 0 {
        return if sign == 1 { -0.0 } else { 0.0 };
    }
    let value = (mantissa as f64) * 2f64.powi(exponent as i32 - 16383 - 63);
    if sign == 1 { -value } else { value }
}

/// Encode a double as an 80-bit extended float in guest memory
/// (upstream `writeF80Value`).
fn write_f80(mem: &mut MemoryManager, address: u64, value: f64) {
    let mut mantissa: u64 = 0;
    let mut signed_exp: u16 = 0;
    if value != 0.0 && !value.is_nan() && !value.is_infinite() {
        let sign = if value.is_sign_negative() { 1u16 } else { 0 };
        let magnitude = value.abs();
        // frexp: magnitude = fraction * 2^exponent, fraction in [0.5, 1).
        let (fraction, exponent) = frexp(magnitude);
        mantissa = (fraction * 2f64.powi(64)) as u64;
        signed_exp =
            (sign << 15) | ((exponent as u16).wrapping_sub(1).wrapping_add(16383) & 0x7FFF);
    }
    for i in 0..8u64 {
        let _ = mem.write_u8(address + i, (mantissa >> (i * 8)) as u8);
    }
    let _ = mem.write_u8(address + 8, (signed_exp & 0xFF) as u8);
    let _ = mem.write_u8(address + 9, (signed_exp >> 8) as u8);
}

/// `frexp` equivalent: returns `(fraction, exponent)` with the fraction
/// in `[0.5, 1)`. Zero/infinity/NaN callers are filtered out upstream.
fn frexp(value: f64) -> (f64, i32) {
    if value == 0.0 {
        return (0.0, 0);
    }
    let bits = value.to_bits();
    let exp_field = ((bits >> 52) & 0x7FF) as i32;
    if exp_field == 0 {
        // Subnormal: scale up by 2^64 then re-extract.
        let scaled = value * 2f64.powi(64);
        let (f, e) = frexp(scaled);
        return (f, e - 64);
    }
    let fraction = f64::from_bits((bits & !(0x7FFu64 << 52)) | (1022u64 << 52));
    (fraction, exp_field - 1022)
}

/// FPU arithmetic selector (upstream `fpuArithmetic`):
/// 0 FADD, 1 FMUL, 4 FSUB, 5 FSUBR, 6 FDIV, 7 FDIVR.
fn fpu_arithmetic(selector: i32, first: f64, second: f64) -> f64 {
    match selector {
        0 => first + second,
        1 => first * second,
        4 => first - second,
        5 => second - first,
        6 => first / second,
        _ => second / first,
    }
}

impl<'a> X86<'a> {
    /// Reset the FPU to its post-FINIT state (upstream `_fpuInit`).
    pub(crate) fn fpu_init(&mut self) {
        for i in 0..8 {
            self.fpu_reg[i] = 0.0;
            self.fpu_int[i] = 0;
            self.fpu_is_int[i] = false;
            self.fpu_tag[i] = 3; // empty
        }
        self.fpu_top = 0;
        self.fpu_control = 0x037F; // all exceptions masked, round-to-nearest
        self.fpu_status_cc = 0;
        self.fpu_init_done = true;
    }

    /// Read ST(i) (upstream `_fpuGet`).
    fn fpu_get(&self, i: usize) -> f64 {
        self.fpu_reg[(self.fpu_top as usize + i) & 7]
    }

    /// Write ST(i) (upstream `_fpuSet`).
    fn fpu_set(&mut self, i: usize, v: f64) {
        let phys = (self.fpu_top as usize + i) & 7;
        self.fpu_reg[phys] = v;
        self.fpu_is_int[phys] = false;
        self.fpu_tag[phys] = if v == 0.0 { 1 } else { 0 };
    }

    /// Push a real value (upstream `_fpuPush`).
    fn fpu_push(&mut self, v: f64) {
        self.fpu_top = (self.fpu_top - 1) & 7;
        self.fpu_reg[self.fpu_top as usize] = v;
        self.fpu_is_int[self.fpu_top as usize] = false;
        self.fpu_tag[self.fpu_top as usize] = if v == 0.0 { 1 } else { 0 };
    }

    /// Push an exact 64-bit integer with the double shadow (FILD).
    fn fpu_push_int(&mut self, v: i64) {
        self.fpu_top = (self.fpu_top - 1) & 7;
        self.fpu_reg[self.fpu_top as usize] = v as f64;
        self.fpu_int[self.fpu_top as usize] = v;
        self.fpu_is_int[self.fpu_top as usize] = true;
        self.fpu_tag[self.fpu_top as usize] = if v == 0 { 1 } else { 0 };
    }

    /// Pop ST(0) (upstream `_fpuPop`).
    fn fpu_pop(&mut self) {
        self.fpu_tag[self.fpu_top as usize] = 3;
        self.fpu_is_int[self.fpu_top as usize] = false;
        self.fpu_top = (self.fpu_top + 1) & 7;
    }

    /// Whether ST(i) is empty (upstream `_fpuEmpty`).
    fn fpu_empty(&self, i: usize) -> bool {
        self.fpu_tag[(self.fpu_top as usize + i) & 7] == 3
    }

    /// Record a compare result into the C3/C2/C0 status bits
    /// (upstream `_fpuCompare`; C1 stays 0).
    fn fpu_compare(&mut self, a: f64, b: f64) {
        self.fpu_status_cc &= !((1u16 << 14) | (1 << 10) | (1 << 9) | (1 << 8));
        if a.is_nan() || b.is_nan() {
            self.fpu_status_cc |= (1 << 14) | (1 << 10) | (1 << 8); // unordered
        } else if a > b {
            // C3=C2=C0=0
        } else if a < b {
            self.fpu_status_cc |= 1 << 8; // C0=1
        } else {
            self.fpu_status_cc |= 1 << 14; // C3=1 (equal)
        }
    }

    /// Status word: condition bits plus TOP (upstream `_fpuStatusWord`).
    fn fpu_status_word(&self) -> u16 {
        (self.fpu_status_cc & ((1 << 14) | (1 << 10) | (1 << 9) | (1 << 8)))
            | (((self.fpu_top & 7) as u16) << 11)
    }

    /// Read a memory operand as a double per `op.src_size`
    /// (upstream `FPU_MEMORY_ACCESS::readReal`).
    fn fpu_read_real(&mut self, op: &MicroOp, addr: u64) -> f64 {
        match op.src_size {
            1 => f32::from_bits(self.mem_read_sized(addr, 4) as u32) as f64,
            2 => f64::from_bits(self.mem_read_sized(addr, 8)),
            3 => read_f80(self.mem, addr),
            4 => self.mem_read_sized(addr, 2) as u16 as i16 as f64,
            5 => self.mem_read_sized(addr, 4) as u32 as i32 as f64,
            6 => self.mem_read_sized(addr, 8) as i64 as f64,
            _ => 0.0,
        }
    }

    /// Write a double to a memory operand per `op.src_size`
    /// (upstream `FPU_MEMORY_ACCESS::writeReal`).
    fn fpu_write_real(&mut self, op: &MicroOp, addr: u64, v: f64) {
        match op.src_size {
            1 => self.mem_write_sized(addr, ((v as f32).to_bits() as u64) & 0xFFFF_FFFF, 4),
            2 => self.mem_write_sized(addr, v.to_bits(), 8),
            3 => write_f80(self.mem, addr, v),
            4 => self.mem_write_sized(addr, (v.round() as i64 as i16) as u16 as u64, 2),
            5 => self.mem_write_sized(addr, (v.round() as i64 as i32) as u32 as u64, 4),
            6 => self.mem_write_sized(addr, v.round() as i64 as u64, 8),
            _ => {}
        }
    }

    /// Read a memory operand as an integer per `op.src_size`
    /// (upstream `FPU_MEMORY_ACCESS::readInteger`).
    fn fpu_read_integer(&mut self, op: &MicroOp, addr: u64) -> i64 {
        match op.src_size {
            4 => self.mem_read_sized(addr, 2) as u16 as i16 as i64,
            5 => self.mem_read_sized(addr, 4) as u32 as i32 as i64,
            6 => self.mem_read_sized(addr, 8) as i64,
            _ => 0,
        }
    }

    /// Store ST(0) as an integer per `op.src_size`, keeping exact FILD
    /// values lossless (upstream `storeTopInteger`).
    fn fpu_store_top_integer(&mut self, op: &MicroOp, addr: u64) {
        let top = self.fpu_top as usize;
        let iv = if self.fpu_is_int[top] {
            self.fpu_int[top]
        } else {
            self.fpu_get(0).round() as i64
        };
        match op.src_size {
            4 => self.mem_write_sized(addr, (iv as i16) as u16 as u64, 2),
            5 => self.mem_write_sized(addr, (iv as i32) as u32 as u64, 4),
            6 => self.mem_write_sized(addr, iv as u64, 8),
            _ => {}
        }
    }

    /// Execute one x87 micro-op (upstream `_execFpu`).
    pub(crate) fn exec_fpu(&mut self, op: &MicroOp, regs: &mut Registers) {
        if !self.fpu_init_done {
            self.fpu_init();
        }

        let opcode = op.alu_op as u8;
        let modrm = op.imm as u8;
        let n_mod = modrm >> 6;
        let n_reg = (modrm >> 3) & 7;
        let n_rm = modrm & 7;
        let is_mem = n_mod != 3;

        let addr = if is_mem {
            self.resolve_addr(op, &op.dst, regs)
        } else {
            0
        };

        if is_mem {
            match opcode {
                0xD8 | 0xDC | 0xDA | 0xDE => {
                    // arith ST(0), mXXreal/int (reg selects; 2/3 are FCOM/FCOMP).
                    let m = self.fpu_read_real(op, addr);
                    if n_reg == 2 || n_reg == 3 {
                        let st0 = self.fpu_get(0);
                        self.fpu_compare(st0, m);
                        if n_reg == 3 {
                            self.fpu_pop();
                        }
                    } else {
                        let st0 = self.fpu_get(0);
                        let r = fpu_arithmetic(n_reg as i32, st0, m);
                        self.fpu_set(0, r);
                    }
                }
                0xD9 => {
                    // FLD m32 / FST/FSTP / FLDCW / FNSTCW / (FLDENV/FNSTENV no-op).
                    if n_reg == 0 {
                        let v = self.fpu_read_real(op, addr);
                        self.fpu_push(v);
                    } else if n_reg == 2 || n_reg == 3 {
                        let st0 = self.fpu_get(0);
                        self.fpu_write_real(op, addr, st0);
                        if n_reg == 3 {
                            self.fpu_pop();
                        }
                    } else if n_reg == 5 {
                        // FLDCW
                        let cw = self.mem_read_sized(addr, 2) as u16;
                        self.fpu_control = cw;
                    } else if n_reg == 7 {
                        // FNSTCW
                        let cw = self.fpu_control;
                        self.mem_write_sized(addr, cw as u64, 2);
                    }
                }
                0xDB => {
                    // FILD m32 / FISTP m32 / FLD m80 / FSTP m80.
                    if n_reg == 0 {
                        let v = self.fpu_read_integer(op, addr);
                        self.fpu_push_int(v);
                    } else if n_reg == 2 || n_reg == 3 {
                        self.fpu_store_top_integer(op, addr);
                        if n_reg == 3 {
                            self.fpu_pop();
                        }
                    } else if n_reg == 5 {
                        let v = self.fpu_read_real(op, addr);
                        self.fpu_push(v);
                    } else if n_reg == 7 {
                        let st0 = self.fpu_get(0);
                        self.fpu_write_real(op, addr, st0);
                        self.fpu_pop();
                    }
                }
                0xDD => {
                    // FLD m64 / FST/FSTP m64 / FNSTSW m16.
                    if n_reg == 0 {
                        let v = self.fpu_read_real(op, addr);
                        self.fpu_push(v);
                    } else if n_reg == 2 || n_reg == 3 {
                        let st0 = self.fpu_get(0);
                        self.fpu_write_real(op, addr, st0);
                        if n_reg == 3 {
                            self.fpu_pop();
                        }
                    } else if n_reg == 7 {
                        let sw = self.fpu_status_word();
                        self.mem_write_sized(addr, sw as u64, 2);
                    }
                }
                0xDF => {
                    // FILD m16/m64 / FISTP m16/m64.
                    if n_reg == 0 || n_reg == 5 {
                        let v = self.fpu_read_integer(op, addr);
                        self.fpu_push_int(v);
                    } else if n_reg == 2 || n_reg == 3 {
                        self.fpu_store_top_integer(op, addr);
                        if n_reg == 3 {
                            self.fpu_pop();
                        }
                    } else if n_reg == 7 {
                        self.fpu_store_top_integer(op, addr);
                        self.fpu_pop();
                    }
                }
                _ => {}
            }
            return;
        }

        // ---- register form (mod == 3) ----
        let i = n_rm as usize; // ST(i)
        match opcode {
            0xD8 => {
                // arith ST(0), ST(i).
                if n_reg == 2 || n_reg == 3 {
                    let (a, b) = (self.fpu_get(0), self.fpu_get(i));
                    self.fpu_compare(a, b);
                    if n_reg == 3 {
                        self.fpu_pop();
                    }
                } else {
                    let (a, b) = (self.fpu_get(0), self.fpu_get(i));
                    let r = fpu_arithmetic(n_reg as i32, a, b);
                    self.fpu_set(0, r);
                }
            }
            0xDC => {
                // arith ST(i), ST(0) — reversed operand order for SUB/DIV.
                let (st0, sti) = (self.fpu_get(0), self.fpu_get(i));
                match n_reg {
                    0 => self.fpu_set(i, sti + st0),
                    1 => self.fpu_set(i, sti * st0),
                    4 => self.fpu_set(i, st0 - sti),
                    5 => self.fpu_set(i, sti - st0),
                    6 => self.fpu_set(i, st0 / sti),
                    _ => self.fpu_set(i, sti / st0),
                }
            }
            0xDE => {
                // F?P forms (pop afterwards); 0xDED9 = FCOMPP.
                if modrm == 0xD9 {
                    let (a, b) = (self.fpu_get(0), self.fpu_get(1));
                    self.fpu_compare(a, b);
                    self.fpu_pop();
                    self.fpu_pop();
                } else {
                    let (st0, sti) = (self.fpu_get(0), self.fpu_get(i));
                    let r = match n_reg {
                        0 => sti + st0,
                        1 => sti * st0,
                        4 => st0 - sti,
                        5 => sti - st0,
                        6 => st0 / sti,
                        _ => sti / st0,
                    };
                    self.fpu_set(i, r);
                    self.fpu_pop();
                }
            }
            0xD9 => {
                // FLD ST(i) / FXCH / constants / unary / transcendental.
                if n_reg == 0 {
                    let v = self.fpu_get(i);
                    self.fpu_push(v);
                } else if n_reg == 1 {
                    let (a, b) = (self.fpu_get(0), self.fpu_get(i));
                    self.fpu_set(0, b);
                    self.fpu_set(i, a);
                } else if n_reg == 4 {
                    // FCHS/FABS/FTST/FXAM (rm selects).
                    if n_rm == 0 {
                        let v = self.fpu_get(0);
                        self.fpu_set(0, -v);
                    } else if n_rm == 1 {
                        let v = self.fpu_get(0);
                        self.fpu_set(0, v.abs());
                    } else if n_rm == 4 {
                        let v = self.fpu_get(0);
                        self.fpu_compare(v, 0.0);
                    } else if n_rm == 5 {
                        // FXAM
                        let v = self.fpu_get(0);
                        self.fpu_status_cc &= !((1u16 << 14) | (1 << 10) | (1 << 9) | (1 << 8));
                        if v.is_sign_negative() {
                            self.fpu_status_cc |= 1 << 9; // C1 = sign
                        }
                        if self.fpu_empty(0) {
                            self.fpu_status_cc |= (1 << 14) | (1 << 8);
                        } else if v.is_nan() {
                            self.fpu_status_cc |= 1 << 8;
                        } else if v.is_infinite() {
                            self.fpu_status_cc |= (1 << 10) | (1 << 8);
                        } else if v == 0.0 {
                            self.fpu_status_cc |= 1 << 14;
                        } else {
                            self.fpu_status_cc |= 1 << 10;
                        }
                    }
                } else if n_reg == 5 {
                    // Load constants.
                    const C: [f64; 8] = [
                        1.0,
                        std::f64::consts::LOG2_10,
                        std::f64::consts::LOG2_E,
                        std::f64::consts::PI,
                        std::f64::consts::LOG10_2,
                        std::f64::consts::LN_2,
                        0.0,
                        0.0,
                    ];
                    if n_rm <= 6 {
                        self.fpu_push(C[n_rm as usize]);
                    }
                } else if n_reg == 6 {
                    // F2XM1/FYL2X/FPTAN/FPATAN/FXTRACT/FPREM1/FDECSTP/FINCSTP.
                    if n_rm == 0 {
                        let v = self.fpu_get(0);
                        self.fpu_set(0, v.exp2() - 1.0);
                    } else if n_rm == 1 {
                        let (st0, st1) = (self.fpu_get(0), self.fpu_get(1));
                        self.fpu_set(1, st1 * st0.log2());
                        self.fpu_pop();
                    } else if n_rm == 2 {
                        let t = self.fpu_get(0).tan();
                        self.fpu_set(0, t);
                        self.fpu_push(1.0);
                    } else if n_rm == 3 {
                        let r = self.fpu_get(1).atan2(self.fpu_get(0));
                        self.fpu_set(1, r);
                        self.fpu_pop();
                    } else if n_rm == 6 {
                        self.fpu_top = (self.fpu_top - 1) & 7; // FDECSTP
                    } else if n_rm == 7 {
                        self.fpu_top = (self.fpu_top + 1) & 7; // FINCSTP
                    }
                } else if n_reg == 7 {
                    // FPREM/FYL2XP1/FSQRT/FSINCOS/FRNDINT/FSCALE/FSIN/FCOS.
                    if n_rm == 0 {
                        let (a, b) = (self.fpu_get(0), self.fpu_get(1));
                        self.fpu_set(0, a % b);
                    } else if n_rm == 1 {
                        let (st0, st1) = (self.fpu_get(0), self.fpu_get(1));
                        self.fpu_set(1, st1 * (st0 + 1.0).log2());
                        self.fpu_pop();
                    } else if n_rm == 2 {
                        let v = self.fpu_get(0);
                        self.fpu_set(0, v.sqrt());
                    } else if n_rm == 3 {
                        let v = self.fpu_get(0);
                        let (s, c2) = (v.sin(), v.cos());
                        self.fpu_set(0, s);
                        self.fpu_push(c2);
                    } else if n_rm == 4 {
                        let v = self.fpu_get(0);
                        self.fpu_set(0, v.round_ties_even()); // nearbyint
                    } else if n_rm == 5 {
                        let (st0, st1) = (self.fpu_get(0), self.fpu_get(1));
                        self.fpu_set(0, st0 * 2f64.powi(st1 as i32));
                    } else if n_rm == 6 {
                        let v = self.fpu_get(0);
                        self.fpu_set(0, v.sin());
                    } else if n_rm == 7 {
                        let v = self.fpu_get(0);
                        self.fpu_set(0, v.cos());
                    }
                }
                // n_reg == 2 FNOP / n_reg == 3 (FSTP1): no-op.
            }
            0xDA => {
                // FCMOVcc ST(0), ST(i) (0xDAE9 = FUCOMPP).
                if modrm == 0xE9 {
                    let (a, b) = (self.fpu_get(0), self.fpu_get(1));
                    self.fpu_compare(a, b);
                    self.fpu_pop();
                    self.fpu_pop();
                } else {
                    let cc = match n_reg {
                        0 => regs.flag(FLAG_CF),
                        1 => regs.flag(FLAG_ZF),
                        2 => regs.flag(FLAG_CF) || regs.flag(FLAG_ZF),
                        _ => !regs.flag(FLAG_PF),
                    };
                    if cc {
                        let v = self.fpu_get(i);
                        self.fpu_set(0, v);
                    }
                }
            }
            0xDB => {
                // FCMOVcc / FCLEX / FINIT / FUCOMI / FCOMI.
                if modrm == 0xE2 {
                    self.fpu_status_cc = 0; // FNCLEX
                } else if modrm == 0xE3 {
                    self.fpu_init(); // FNINIT
                } else if n_reg == 5 || n_reg == 6 {
                    // FUCOMI/FCOMI ST(0),ST(i): set EFLAGS ZF/PF/CF.
                    let (a, b) = (self.fpu_get(0), self.fpu_get(i));
                    let unordered = a.is_nan() || b.is_nan();
                    regs.set_flag(FLAG_ZF, unordered || a == b);
                    regs.set_flag(FLAG_PF, unordered);
                    regs.set_flag(FLAG_CF, unordered || a < b);
                } else if n_reg <= 3 {
                    // FCMOVcc (NB / NE / NBE / NU).
                    let cc = match n_reg {
                        0 => !regs.flag(FLAG_CF),
                        1 => !regs.flag(FLAG_ZF),
                        2 => !(regs.flag(FLAG_CF) || regs.flag(FLAG_ZF)),
                        _ => regs.flag(FLAG_PF),
                    };
                    if cc {
                        let v = self.fpu_get(i);
                        self.fpu_set(0, v);
                    }
                }
            }
            0xDD => {
                // FFREE / FST/FSTP ST(i) / FUCOM/FUCOMP ST(i).
                if n_reg == 0 {
                    let phys = (self.fpu_top as usize + i) & 7;
                    self.fpu_tag[phys] = 3; // FFREE
                    self.fpu_is_int[phys] = false;
                } else if n_reg == 2 || n_reg == 3 {
                    let v = self.fpu_get(0);
                    self.fpu_set(i, v);
                    if n_reg == 3 {
                        self.fpu_pop();
                    }
                } else if n_reg == 4 || n_reg == 5 {
                    let (a, b) = (self.fpu_get(0), self.fpu_get(i));
                    self.fpu_compare(a, b);
                    if n_reg == 5 {
                        self.fpu_pop();
                    }
                }
            }
            0xDF => {
                // FNSTSW AX / FUCOMIP / FCOMIP.
                if modrm == 0xE0 {
                    regs.set_gpr(GPR_RAX, 2, self.fpu_status_word() as u64);
                } else if n_reg == 5 || n_reg == 6 {
                    let (a, b) = (self.fpu_get(0), self.fpu_get(i));
                    let unordered = a.is_nan() || b.is_nan();
                    regs.set_flag(FLAG_ZF, unordered || a == b);
                    regs.set_flag(FLAG_PF, unordered);
                    regs.set_flag(FLAG_CF, unordered || a < b);
                    self.fpu_pop();
                }
            }
            _ => {}
        }
    }
}

//! Instruction decoding — faithful port of upstream `_decodeInsn`,
//! `_decodeModRM`, `_decodeTwoByte`, `_decodeMMX`, and `_decodeFpu`
//! (`arch/xemux86.cpp`, pin `655e6da`). Each decode produces one
//! `MicroOp`; decode-time fetch faults return `None` exactly like the
//! upstream `bFault` path.

use super::mmx::*;
use super::*;

const ALU_NAMES: [&str; 8] = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];

impl<'a> X86<'a> {
    /// Decode ModR/M + SIB + displacement (upstream `_decodeModRM`).
    /// Returns `(reg_field, rm_operand)`; `reg_field` already has REX.R folded in.
    fn decode_modrm(&mut self, dec: &mut Dec) -> (i32, Operand) {
        let modrm = self.fetch8(dec);
        let n_mod = modrm >> 6;
        let n_reg = (modrm >> 3) & 7;
        let n_rm = modrm & 7;

        let reg_field = n_reg as i32 + if dec.rex_r { 8 } else { 0 };

        let mut rm = Operand {
            seg_source: dec.seg_source,
            ..Operand::default()
        };

        if n_mod == 3 {
            rm.is_reg = true;
            rm.reg = n_rm as i32 + if dec.rex_b { 8 } else { 0 };
            return (reg_field, rm);
        }

        rm.is_mem = true;

        // 16-bit addressing: fixed base+index pairs, 16-bit displacements, no SIB.
        if dec.addr_size == 2 {
            match n_rm {
                0 => {
                    rm.base_reg = GPR_RBX as i32;
                    rm.index_reg = GPR_RSI as i32;
                }
                1 => {
                    rm.base_reg = GPR_RBX as i32;
                    rm.index_reg = GPR_RDI as i32;
                }
                2 => {
                    rm.base_reg = GPR_RBP as i32;
                    rm.index_reg = GPR_RSI as i32;
                }
                3 => {
                    rm.base_reg = GPR_RBP as i32;
                    rm.index_reg = GPR_RDI as i32;
                }
                4 => rm.base_reg = GPR_RSI as i32,
                5 => rm.base_reg = GPR_RDI as i32,
                6 => {
                    if n_mod == 0 {
                        rm.disp = self.fetch16(dec) as i16 as i64;
                    } else {
                        rm.base_reg = GPR_RBP as i32;
                    }
                }
                _ => rm.base_reg = GPR_RBX as i32,
            }
            rm.scale = 1;
            if n_mod == 1 {
                rm.disp += self.fetch8(dec) as i8 as i64;
            } else if n_mod == 2 {
                rm.disp += self.fetch16(dec) as i16 as i64;
            }
            return (reg_field, rm);
        }

        if n_rm == 4 {
            // SIB byte.
            let sib = self.fetch8(dec);
            let scale = 1i32 << (sib >> 6);
            let index_field = (sib >> 3) & 7;
            let index = index_field as i32 + if dec.rex_x { 8 } else { 0 };
            let base = (sib & 7) as i32 + if dec.rex_b { 8 } else { 0 };

            if !(index_field == 4 && !dec.rex_x) {
                // index == RSP without REX.X means "no index".
                rm.index_reg = index;
                rm.scale = scale;
            }

            if (sib & 7) == 5 && n_mod == 0 {
                rm.disp = self.fetch32(dec) as i32 as i64;
            } else {
                rm.base_reg = base;
            }
        } else if n_rm == 5 && n_mod == 0 {
            let disp = self.fetch32(dec) as i32 as i64;
            if dec.addr_size == 8 {
                rm.rip_rel = true; // RIP-relative in long mode
                rm.disp = disp;
            } else {
                rm.disp = disp as u32 as i64; // absolute disp32
            }
        } else {
            rm.base_reg = n_rm as i32 + if dec.rex_b { 8 } else { 0 };
        }

        if n_mod == 1 {
            rm.disp += self.fetch8(dec) as i8 as i64;
        } else if n_mod == 2 {
            rm.disp += self.fetch32(dec) as i32 as i64;
        }
        (reg_field, rm)
    }

    /// Two-byte (0F) opcode map (upstream `_decodeTwoByte`).
    fn decode_two_byte(&mut self, dec: &mut Dec, op: &mut MicroOp) {
        let opcode = self.fetch8(dec);

        if opcode == 0x00 {
            // Group 6: sldt/str/... — sldt /0 and str /1 store 0 (real mode);
            // the rest are benign no-ops.
            let (reg_field, rm) = self.decode_modrm(dec);
            if reg_field == 0 || reg_field == 1 {
                op.kind = MicroOpKind::MovImm;
                op.dst = rm;
                op.size = if rm.is_reg { dec.op_size } else { 2 };
                op.imm = 0;
                op.text = if reg_field == 0 {
                    "sldt".into()
                } else {
                    "str".into()
                };
            } else {
                op.kind = MicroOpKind::Nop;
                op.text = "grp6".into();
            }
        } else if opcode == 0x01 {
            // Group 7: only smsw (/4) matters; the rest are no-ops.
            let (reg_field, rm) = self.decode_modrm(dec);
            if reg_field == 4 {
                op.kind = MicroOpKind::Smsw;
                op.dst = rm;
                op.size = if rm.is_reg { dec.op_size } else { 2 };
                op.text = "smsw".into();
            } else {
                op.kind = MicroOpKind::Nop;
                op.text = "grp7".into();
            }
        } else if opcode == 0x02 || opcode == 0x03 {
            // LAR / LSL: return flat-model values with ZF=1.
            let (reg_field, rm) = self.decode_modrm(dec);
            let _ = rm;
            op.kind = MicroOpKind::Lsl;
            op.dst = Operand::reg(reg_field);
            op.size = dec.op_size;
            op.imm = if opcode == 0x03 {
                0xFFFF_FFFF
            } else {
                0x00CF_FB00
            };
            op.text = if opcode == 0x03 {
                "lsl".into()
            } else {
                "lar".into()
            };
        } else if opcode == 0x20 {
            // mov r32, crN.
            let (cr, rm) = self.decode_modrm(dec);
            op.kind = MicroOpKind::MovFromCr;
            op.dst = rm;
            op.alu_op = cr;
            op.size = 4;
            op.text = "mov r,cr".into();
        } else if opcode == 0x22 {
            let (_cr, _rm) = self.decode_modrm(dec);
            op.kind = MicroOpKind::Nop;
            op.text = "mov cr,r".into();
        } else if opcode == 0x21 {
            // mov r32, DRx.
            let (dr, rm) = self.decode_modrm(dec);
            op.kind = MicroOpKind::MovDr;
            op.dst = rm;
            op.alu_op = dr & 7;
            op.cond = 0; // read
            op.size = 4;
            op.text = "mov r,dr".into();
        } else if opcode == 0x23 {
            // mov DRx, r32.
            let (dr, rm) = self.decode_modrm(dec);
            op.kind = MicroOpKind::MovDr;
            op.src = rm;
            op.alu_op = dr & 7;
            op.cond = 1; // write
            op.size = 4;
            op.text = "mov dr,r".into();
        } else if opcode == 0xA0 || opcode == 0xA8 {
            op.kind = MicroOpKind::PushSeg;
            op.alu_op = if opcode == 0xA0 { 4 } else { 5 }; // 4 FS, 5 GS
            op.text = if opcode == 0xA0 {
                "push fs".into()
            } else {
                "push gs".into()
            };
        } else if opcode == 0xA1 || opcode == 0xA9 {
            op.kind = MicroOpKind::PopSeg;
            op.alu_op = if opcode == 0xA1 { 4 } else { 5 };
            op.text = if opcode == 0xA1 {
                "pop fs".into()
            } else {
                "pop gs".into()
            };
        } else if opcode == 0xB2 || opcode == 0xB4 || opcode == 0xB5 {
            // lss/lfs/lgs: far pointer load into a GP reg + SS/FS/GS.
            let (reg_field, rm) = self.decode_modrm(dec);
            op.kind = MicroOpKind::LoadFar;
            op.dst = Operand::reg(reg_field);
            op.src = rm;
            op.size = dec.op_size;
            op.cond = if opcode == 0xB2 {
                2
            } else if opcode == 0xB4 {
                3
            } else {
                4
            }; // 2 SS, 3 FS, 4 GS
            op.text = if opcode == 0xB2 {
                "lss".into()
            } else if opcode == 0xB4 {
                "lfs".into()
            } else {
                "lgs".into()
            };
        } else if opcode == 0x0B {
            // ud2: software interrupt vector 6.
            op.kind = MicroOpKind::Syscall;
            op.imm = 6;
            op.alu_op = 2;
            op.text = "ud2".into();
        } else if (0x80..=0x8F).contains(&opcode) {
            // Near Jcc: rel16/rel32 by operand size.
            let rel = if dec.op_size == 2 {
                self.fetch16(dec) as i16 as i32
            } else {
                self.fetch32(dec) as i32
            };
            op.kind = MicroOpKind::Jcc;
            op.cond = opcode - 0x80;
            op.branch_target = dec.fetch.wrapping_add(rel as i64 as u64);
            op.text = "jcc".into();
        } else if (0x40..=0x4F).contains(&opcode) {
            // cmovcc reg, r/m.
            let (reg_field, rm) = self.decode_modrm(dec);
            op.kind = MicroOpKind::Cmovcc;
            op.cond = opcode - 0x40;
            op.dst = Operand::reg(reg_field);
            op.src = rm;
            op.size = dec.op_size;
            op.text = "cmovcc".into();
        } else if (0x90..=0x9F).contains(&opcode) {
            let (reg_field, rm) = self.decode_modrm(dec);
            let _ = reg_field;
            op.kind = MicroOpKind::Setcc;
            op.cond = opcode - 0x90;
            op.dst = rm;
            op.size = 1;
            op.text = "setcc".into();
        } else if opcode == 0xB6 || opcode == 0xB7 || opcode == 0xBE || opcode == 0xBF {
            let (reg_field, rm) = self.decode_modrm(dec);
            op.kind = if opcode == 0xBE || opcode == 0xBF {
                MicroOpKind::Movsx
            } else {
                MicroOpKind::Movzx
            };
            op.dst = Operand::reg(reg_field);
            op.src = rm;
            op.src_size = if opcode == 0xB6 || opcode == 0xBE {
                1
            } else {
                2
            };
            op.size = dec.op_size;
            op.text = if op.kind == MicroOpKind::Movsx {
                "movsx".into()
            } else {
                "movzx".into()
            };
        } else if opcode == 0x1F {
            let (_reg, _rm) = self.decode_modrm(dec);
            op.kind = MicroOpKind::Nop;
            op.text = "nop".into();
        } else if opcode == 0x1E {
            let _ = self.fetch8(dec); // endbr32/endbr64 -> nop
            op.kind = MicroOpKind::Nop;
            op.text = "nop".into();
        } else if opcode == 0x05 {
            op.kind = MicroOpKind::Syscall;
            op.alu_op = 0;
            op.text = "syscall".into();
        } else if opcode == 0x31 {
            op.kind = MicroOpKind::Rdtsc;
            op.text = "rdtsc".into();
        } else if opcode == 0xA2 {
            op.kind = MicroOpKind::Cpuid;
            op.text = "cpuid".into();
        } else if opcode == 0xAF {
            let (reg_field, rm) = self.decode_modrm(dec);
            op.kind = MicroOpKind::Imul2;
            op.dst = Operand::reg(reg_field);
            op.src = rm;
            op.src_size = 0; // two-operand form
            op.size = dec.op_size;
            op.text = "imul".into();
        } else if opcode == 0xC0 || opcode == 0xC1 {
            // XADD r/m, reg (0xC0 byte form).
            let (reg_field, rm) = self.decode_modrm(dec);
            op.kind = MicroOpKind::Xadd;
            op.dst = rm;
            op.src = Operand::reg(reg_field);
            op.size = if opcode == 0xC0 { 1 } else { dec.op_size };
            op.text = "xadd".into();
        } else if opcode == 0xBC || opcode == 0xBD {
            // BSF/BSR reg, r/m.
            let (reg_field, rm) = self.decode_modrm(dec);
            op.kind = if opcode == 0xBC {
                MicroOpKind::Bsf
            } else {
                MicroOpKind::Bsr
            };
            op.dst = Operand::reg(reg_field);
            op.src = rm;
            op.size = dec.op_size;
            op.text = if opcode == 0xBC {
                "bsf".into()
            } else {
                "bsr".into()
            };
        } else if (0xC8..=0xCF).contains(&opcode) {
            op.kind = MicroOpKind::Bswap;
            op.dst = Operand::reg((opcode - 0xC8) as i32 + if dec.rex_b { 8 } else { 0 });
            op.size = dec.op_size;
            op.text = "bswap".into();
        } else if self.decode_mmx(dec, op, opcode) {
            // MMX packed-integer instruction handled.
        } else if opcode == 0xA4 || opcode == 0xA5 || opcode == 0xAC || opcode == 0xAD {
            // SHLD/SHRD r/m, reg, imm8|CL.
            let (reg_field, rm) = self.decode_modrm(dec);
            op.kind = MicroOpKind::ShiftD;
            op.alu_op = if opcode == 0xA4 || opcode == 0xA5 {
                0
            } else {
                1
            }; // 0 SHLD, 1 SHRD
            op.cond = if opcode == 0xA5 || opcode == 0xAD {
                1
            } else {
                0
            }; // 1 = CL, 0 = imm8
            op.dst = rm;
            op.src = Operand::reg(reg_field);
            op.size = dec.op_size;
            if op.cond == 0 {
                op.imm = self.fetch8(dec) as u64;
            }
            op.text = if op.alu_op == 0 {
                "shld".into()
            } else {
                "shrd".into()
            };
        } else if opcode == 0xA3 || opcode == 0xAB || opcode == 0xB3 || opcode == 0xBB {
            // BT/BTS/BTR/BTC r/m, reg.
            let (reg_field, rm) = self.decode_modrm(dec);
            op.kind = MicroOpKind::Bt;
            op.alu_op = match opcode {
                0xA3 => 0,
                0xAB => 1,
                0xB3 => 2,
                _ => 3,
            };
            op.cond = 1; // register bit index
            op.dst = rm;
            op.src = Operand::reg(reg_field);
            op.size = dec.op_size;
            op.text = "bt-group".into();
        } else if opcode == 0xBA {
            // Group 8: BT/BTS/BTR/BTC r/m, imm8. REX.R must be ignored on the
            // opcode-extension field.
            let (reg_field, rm) = self.decode_modrm(dec);
            let ext = reg_field & 7;
            op.imm = self.fetch8(dec) as u64;
            if ext >= 4 {
                op.kind = MicroOpKind::Bt;
                op.alu_op = ext - 4; // 0 BT .. 3 BTC
                op.cond = 0; // immediate bit index
                op.dst = rm;
                op.size = dec.op_size;
                op.text = "bt-group".into();
            } else {
                op.kind = MicroOpKind::Unimpl;
                op.text = format!("db 0f ba /{ext}");
            }
        } else {
            op.kind = MicroOpKind::Unimpl;
            op.text = format!("db 0f {opcode:02x}");
        }
    }

    /// MMX two-byte opcode decode (upstream `_decodeMMX`). Returns false
    /// when the opcode is not an MMX instruction or when a mandatory
    /// 66/F2/F3 prefix selects an SSE form we do not model.
    fn decode_mmx(&mut self, dec: &mut Dec, op: &mut MicroOp, opcode: u8) -> bool {
        if dec.op_size16 || dec.rep != 0 {
            return false;
        }

        match opcode {
            0x6E => {
                // MOVD mm, r/m32 (REX.W -> MOVQ mm, r/m64).
                let (reg_field, rm) = self.decode_modrm(dec);
                op.kind = MicroOpKind::Mmx;
                op.alu_op = MMX_MOVD_TO;
                op.dst = Operand::mmx_reg(reg_field);
                op.src = rm;
                op.size = 8;
                op.src_size = if dec.rex_w { 8 } else { 4 };
                op.text = "movd".into();
                return true;
            }
            0x7E => {
                // MOVD r/m32, mm (REX.W -> MOVQ r/m64, mm).
                let (reg_field, rm) = self.decode_modrm(dec);
                op.kind = MicroOpKind::Mmx;
                op.alu_op = MMX_MOVD_FROM;
                op.dst = rm;
                op.src = Operand::mmx_reg(reg_field);
                op.size = if dec.rex_w { 8 } else { 4 };
                op.text = "movd".into();
                return true;
            }
            0x6F => {
                // MOVQ mm, mm/m64.
                let (reg_field, rm) = self.decode_modrm(dec);
                op.kind = MicroOpKind::Mmx;
                op.alu_op = MMX_MOVQ_TO;
                op.dst = Operand::mmx_reg(reg_field);
                op.src = if rm.is_reg {
                    Operand::mmx_reg(rm.reg)
                } else {
                    rm
                };
                op.size = 8;
                op.text = "movq".into();
                return true;
            }
            0x7F => {
                // MOVQ mm/m64, mm.
                let (reg_field, rm) = self.decode_modrm(dec);
                op.kind = MicroOpKind::Mmx;
                op.alu_op = MMX_MOVQ_FROM;
                op.dst = if rm.is_reg {
                    Operand::mmx_reg(rm.reg)
                } else {
                    rm
                };
                op.src = Operand::mmx_reg(reg_field);
                op.size = 8;
                op.text = "movq".into();
                return true;
            }
            0x77 => {
                // EMMS.
                op.kind = MicroOpKind::Mmx;
                op.alu_op = MMX_EMMS;
                op.text = "emms".into();
                return true;
            }
            0x70 => {
                // PSHUFW mm, mm/m64, imm8.
                let (reg_field, rm) = self.decode_modrm(dec);
                op.imm = self.fetch8(dec) as u64;
                op.kind = MicroOpKind::Mmx;
                op.alu_op = MMX_PSHUFW;
                op.dst = Operand::mmx_reg(reg_field);
                op.src = if rm.is_reg {
                    Operand::mmx_reg(rm.reg)
                } else {
                    rm
                };
                op.size = 8;
                op.text = "pshufw".into();
                return true;
            }
            0x71..=0x73 => {
                // PSxxW/D/Q mm, imm8 shift group.
                let (reg_field, rm) = self.decode_modrm(dec);
                op.imm = self.fetch8(dec) as u64;
                let sub = reg_field & 7;
                let nop: i32 = if opcode == 0x71 {
                    if sub == 2 {
                        MMX_PSRLW
                    } else if sub == 4 {
                        MMX_PSRAW
                    } else if sub == 6 {
                        MMX_PSLLW
                    } else {
                        -1
                    }
                } else if opcode == 0x72 {
                    if sub == 2 {
                        MMX_PSRLD
                    } else if sub == 4 {
                        MMX_PSRAD
                    } else if sub == 6 {
                        MMX_PSLLD
                    } else {
                        -1
                    }
                } else if sub == 2 {
                    MMX_PSRLQ
                } else if sub == 6 {
                    MMX_PSLLQ
                } else {
                    -1
                };
                if nop < 0 {
                    op.kind = MicroOpKind::Unimpl;
                    op.text = format!("db 0f {opcode:02x} /{sub}");
                    return true;
                }
                op.kind = MicroOpKind::Mmx;
                op.alu_op = nop;
                op.cond = 1; // count is imm8
                op.dst = Operand::mmx_reg(rm.reg); // the r/m must be a register
                op.size = 8;
                op.text = "psh-imm".into();
                return true;
            }
            _ => {}
        }

        // Generic form: dst = mm(reg), src = mm/m64.
        let nop: i32 = match opcode {
            0x60 => MMX_PUNPCKLBW,
            0x61 => MMX_PUNPCKLWD,
            0x62 => MMX_PUNPCKLDQ,
            0x63 => MMX_PACKSSWB,
            0x64 => MMX_PCMPGTB,
            0x65 => MMX_PCMPGTW,
            0x66 => MMX_PCMPGTD,
            0x67 => MMX_PACKUSWB,
            0x68 => MMX_PUNPCKHBW,
            0x69 => MMX_PUNPCKHWD,
            0x6A => MMX_PUNPCKHDQ,
            0x6B => MMX_PACKSSDW,
            0x74 => MMX_PCMPEQB,
            0x75 => MMX_PCMPEQW,
            0x76 => MMX_PCMPEQD,
            0xD1 => MMX_PSRLW,
            0xD2 => MMX_PSRLD,
            0xD3 => MMX_PSRLQ,
            0xD4 => MMX_PADDQ,
            0xD5 => MMX_PMULLW,
            0xD8 => MMX_PSUBUSB,
            0xD9 => MMX_PSUBUSW,
            0xDA => MMX_PMINUB,
            0xDB => MMX_PAND,
            0xDC => MMX_PADDUSB,
            0xDD => MMX_PADDUSW,
            0xDE => MMX_PMAXUB,
            0xDF => MMX_PANDN,
            0xE0 => MMX_PAVGB,
            0xE1 => MMX_PSRAW,
            0xE2 => MMX_PSRAD,
            0xE3 => MMX_PAVGW,
            0xE4 => MMX_PMULHUW,
            0xE5 => MMX_PMULHW,
            0xE8 => MMX_PSUBSB,
            0xE9 => MMX_PSUBSW,
            0xEA => MMX_PMINSW,
            0xEB => MMX_POR,
            0xEC => MMX_PADDSB,
            0xED => MMX_PADDSW,
            0xEE => MMX_PMAXSW,
            0xEF => MMX_PXOR,
            0xF1 => MMX_PSLLW,
            0xF2 => MMX_PSLLD,
            0xF3 => MMX_PSLLQ,
            0xF5 => MMX_PMADDWD,
            0xF6 => MMX_PSADBW,
            0xF8 => MMX_PSUBB,
            0xF9 => MMX_PSUBW,
            0xFA => MMX_PSUBD,
            0xFB => MMX_PSUBQ,
            0xFC => MMX_PADDB,
            0xFD => MMX_PADDW,
            0xFE => MMX_PADDD,
            _ => return false,
        };

        let (reg_field, rm) = self.decode_modrm(dec);
        op.kind = MicroOpKind::Mmx;
        op.alu_op = nop;
        op.dst = Operand::mmx_reg(reg_field);
        op.src = if rm.is_reg {
            Operand::mmx_reg(rm.reg)
        } else {
            rm
        };
        op.size = 8;
        op.text = "mmx".into();
        true
    }

    /// x87 ESC decode (upstream `_decodeFpu`). The opcode and the raw
    /// ModR/M byte ride in `alu_op`/`imm`; for the memory form `dst` is
    /// the resolved operand and `src_size`/`size` describe the type.
    fn decode_fpu(&mut self, dec: &mut Dec, op: &mut MicroOp, opcode: u8) {
        let modrm = self.mem.fetch_u8(dec.fetch).unwrap_or_else(|| {
            dec.fault = true;
            0
        }); // peek — do not consume yet
        let n_mod = modrm >> 6;
        let n_reg = (modrm >> 3) & 7;

        op.kind = MicroOpKind::Fpu;
        op.alu_op = opcode as i32;
        op.imm = modrm as u64;
        op.size = 0;
        op.src_size = 0; // memory type: 0 none, 1 f32, 2 f64, 3 f80, 4 i16, 5 i32, 6 i64
        op.text = "fpu".into();

        if n_mod != 3 {
            let (n_type, n_bytes) = match opcode {
                0xD8 => (1, 4), // m32real
                0xDC => (2, 8), // m64real
                0xDA => (5, 4), // m32int
                0xDE => (4, 2), // m16int
                0xD9 => {
                    if n_reg == 5 || n_reg == 7 {
                        (4, 2)
                    } else {
                        (1, 4)
                    }
                }
                0xDB => {
                    if n_reg == 5 || n_reg == 7 {
                        (3, 10)
                    } else {
                        (5, 4)
                    }
                }
                0xDD => {
                    if n_reg == 7 {
                        (4, 2)
                    } else {
                        (2, 8)
                    }
                }
                _ => {
                    // 0xDF
                    if n_reg == 5 || n_reg == 7 {
                        (6, 8) // FILD/FISTP m64int
                    } else if n_reg == 4 || n_reg == 6 {
                        (3, 10) // FBLD/FBSTP m80
                    } else {
                        (4, 2) // FILD/FISTP m16int
                    }
                }
            };
            op.src_size = n_type;
            op.size = n_bytes;
            let (_reg_field, dst) = self.decode_modrm(dec);
            op.dst = dst; // consumes ModR/M + displacement
        } else {
            let _ = self.fetch8(dec); // register form: just consume ModR/M
        }
    }

    /// Decode one instruction at `address` (upstream `_decodeInsn`).
    /// `None` signals a fetch fault mid-decode.
    pub(crate) fn decode_insn(&mut self, address: u64) -> Option<MicroOp> {
        let mut dec = Dec {
            start: address,
            fetch: address,
            addr_size: match self.bits {
                16 => 2,
                64 => 8,
                _ => 4,
            },
            ..Dec::new()
        };

        let mut op = MicroOp {
            address,
            ..MicroOp::default()
        };

        // Prefixes.
        let opcode: u8;
        loop {
            let b = self.fetch8(&mut dec);
            if dec.fault {
                return None;
            }

            if b == 0x66 {
                dec.op_size16 = true;
                dec.rex_w = false;
                dec.rex_r = false;
                dec.rex_x = false;
                dec.rex_b = false;
                dec.has_rex = false;
            } else if b == 0x67 {
                dec.addr_size = match self.bits {
                    16 => 4,
                    64 => 4,
                    32 => 2,
                    _ => 8,
                };
                dec.rex_w = false;
                dec.rex_r = false;
                dec.rex_x = false;
                dec.rex_b = false;
                dec.has_rex = false;
            } else if b == 0xF0 || b == 0xF2 || b == 0xF3 {
                if b == 0xF3 {
                    dec.rep = 1; // rep / repe
                } else if b == 0xF2 {
                    dec.rep = 2; // repne
                }
                dec.rex_w = false;
                dec.rex_r = false;
                dec.rex_x = false;
                dec.rex_b = false;
                dec.has_rex = false;
            } else if b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 {
                // Segment override (ES/CS/SS/DS).
                dec.seg_source = match b {
                    0x26 => 3,
                    0x2E => 4,
                    0x36 => 5,
                    _ => 6,
                };
                dec.rex_w = false;
                dec.rex_r = false;
                dec.rex_x = false;
                dec.rex_b = false;
                dec.has_rex = false;
            } else if b == 0x64 {
                dec.seg_source = 1;
                dec.rex_w = false;
                dec.rex_r = false;
                dec.rex_x = false;
                dec.rex_b = false;
                dec.has_rex = false;
            } else if b == 0x65 {
                dec.seg_source = 2;
                dec.rex_w = false;
                dec.rex_r = false;
                dec.rex_x = false;
                dec.rex_b = false;
                dec.has_rex = false;
            } else if self.bits == 64 && (0x40..=0x4F).contains(&b) {
                dec.has_rex = true;
                dec.rex_w = (b & 8) != 0;
                dec.rex_r = (b & 4) != 0;
                dec.rex_x = (b & 2) != 0;
                dec.rex_b = (b & 1) != 0;
            } else {
                opcode = b;
                break;
            }
        }

        // Default operand size: 16 in real mode, 32 otherwise; 0x66 toggles
        // and REX.W forces 64.
        let default_op_size = if self.bits == 16 { 2 } else { 4 };
        dec.op_size = if dec.rex_w {
            8
        } else if dec.op_size16 {
            6 - default_op_size
        } else {
            default_op_size
        };

        if opcode < 0x40 && (opcode & 7) < 6 {
            let alu_op = (opcode >> 3) as i32;
            let variant = opcode & 7;
            let size = if variant == 0 || variant == 2 || variant == 4 {
                1
            } else {
                dec.op_size
            };
            op.size = size;
            op.alu_op = alu_op;
            op.text = ALU_NAMES[alu_op as usize].into();

            if variant <= 3 {
                let (reg_field, rm) = self.decode_modrm(&mut dec);
                if variant <= 1 {
                    op.kind = MicroOpKind::AluRmR;
                    op.dst = rm;
                    op.src = Operand::reg(reg_field);
                } else {
                    op.kind = MicroOpKind::AluRRm;
                    op.dst = Operand::reg(reg_field);
                    op.src = rm;
                }
            } else {
                op.kind = MicroOpKind::AluRaxImm;
                if variant == 4 {
                    op.imm = self.fetch8(&mut dec) as u64;
                } else if size == 2 {
                    op.imm = self.fetch16(&mut dec) as u64;
                } else {
                    op.imm = Self::sign_extend(self.fetch32(&mut dec) as u64, 4) as u64;
                }
            }
        } else if self.bits != 64 && (0x40..=0x4F).contains(&opcode) {
            // Single-byte inc/dec reg (REX in 64-bit mode, handled above).
            op.kind = MicroOpKind::IncDec;
            op.dst = Operand::reg((opcode & 7) as i32);
            op.size = dec.op_size;
            op.alu_op = if opcode < 0x48 { 0 } else { 1 };
            op.text = if opcode < 0x48 {
                "inc".into()
            } else {
                "dec".into()
            };
        } else if (0x50..=0x57).contains(&opcode) {
            op.kind = MicroOpKind::Push;
            op.src = Operand::reg((opcode - 0x50) as i32 + if dec.rex_b { 8 } else { 0 });
            op.size = self.stack_size(&dec);
            op.text = "push".into();
        } else if (0x58..=0x5F).contains(&opcode) {
            op.kind = MicroOpKind::Pop;
            op.dst = Operand::reg((opcode - 0x58) as i32 + if dec.rex_b { 8 } else { 0 });
            op.size = self.stack_size(&dec);
            op.text = "pop".into();
        } else if opcode == 0x68 {
            // push imm16/imm32 by operand size.
            op.kind = MicroOpKind::Push;
            if dec.op_size == 2 {
                op.imm = Self::sign_extend(self.fetch16(&mut dec) as u64, 2) as u64;
            } else {
                op.imm = Self::sign_extend(self.fetch32(&mut dec) as u64, 4) as u64;
            }
            op.size = self.stack_size(&dec);
            op.text = "push".into();
        } else if opcode == 0x6A {
            op.kind = MicroOpKind::Push;
            op.imm = Self::sign_extend(self.fetch8(&mut dec) as u64, 1) as u64;
            op.size = self.stack_size(&dec);
            op.text = "push".into();
        } else if opcode == 0x69 || opcode == 0x6B {
            // imul r, r/m, imm (three-operand).
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::Imul2;
            op.dst = Operand::reg(reg_field);
            op.src = rm;
            op.size = dec.op_size;
            op.src_size = -1; // three-operand (immediate) form
            if opcode == 0x6B {
                op.imm = Self::sign_extend(self.fetch8(&mut dec) as u64, 1) as u64;
            } else if dec.op_size == 2 {
                op.imm = Self::sign_extend(self.fetch16(&mut dec) as u64, 2) as u64;
            } else {
                op.imm = Self::sign_extend(self.fetch32(&mut dec) as u64, 4) as u64;
            }
            op.text = "imul".into();
        } else if opcode == 0x88 || opcode == 0x89 || opcode == 0x8A || opcode == 0x8B {
            let size = if opcode == 0x88 || opcode == 0x8A {
                1
            } else {
                dec.op_size
            };
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::Mov;
            op.size = size;
            if opcode == 0x88 || opcode == 0x89 {
                op.dst = rm;
                op.src = Operand::reg(reg_field);
            } else {
                op.dst = Operand::reg(reg_field);
                op.src = rm;
            }
            op.text = "mov".into();
        } else if opcode == 0x8D {
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::Lea;
            op.dst = Operand::reg(reg_field);
            op.src = rm;
            op.size = dec.op_size;
            op.text = "lea".into();
        } else if opcode == 0x8C || opcode == 0x8E {
            // mov r/m16,Sreg (0x8C) / mov Sreg,r/m16 (0x8E).
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::MovSeg;
            op.alu_op = reg_field & 7; // 0 ES,1 CS,2 SS,3 DS,4 FS,5 GS
            op.size = 2;
            if opcode == 0x8E {
                op.cond = 0; // to segment
                op.src = rm;
            } else {
                op.cond = 1; // from segment
                op.dst = rm;
            }
            op.text = "mov".into();
        } else if self.bits == 64 && opcode == 0x63 {
            // movsxd r64, r/m32.
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::Movsx;
            op.dst = Operand::reg(reg_field);
            op.src = rm;
            op.src_size = 4;
            op.size = dec.op_size;
            op.text = "movsxd".into();
        } else if (0xB0..=0xB7).contains(&opcode) {
            op.kind = MicroOpKind::MovImm;
            op.dst = Operand::reg8((opcode - 0xB0) as i32, dec.has_rex, dec.rex_b); // AH/CH/DH/BH when no REX
            op.size = 1;
            op.imm = self.fetch8(&mut dec) as u64;
            op.text = "mov".into();
        } else if (0xB8..=0xBF).contains(&opcode) {
            op.kind = MicroOpKind::MovImm;
            op.dst = Operand::reg((opcode - 0xB8) as i32 + if dec.rex_b { 8 } else { 0 });
            op.size = dec.op_size;
            if dec.op_size == 8 {
                op.imm = self.fetch64(&mut dec);
            } else if dec.op_size == 2 {
                op.imm = self.fetch16(&mut dec) as u64;
            } else {
                op.imm = self.fetch32(&mut dec) as u64;
            }
            op.text = "mov".into();
        } else if (0xA0..=0xA3).contains(&opcode) {
            // MOV accumulator <-> moffs.
            let size = if opcode == 0xA0 || opcode == 0xA2 {
                1
            } else {
                dec.op_size
            };
            let mut mem = Operand {
                is_mem: true,
                seg_source: dec.seg_source,
                ..Operand::default()
            };
            mem.disp = if dec.addr_size == 2 {
                self.fetch16(&mut dec) as i64
            } else if dec.addr_size == 8 {
                self.fetch64(&mut dec) as i64
            } else {
                self.fetch32(&mut dec) as i64
            };
            op.kind = MicroOpKind::Mov;
            op.size = size;
            if opcode == 0xA0 || opcode == 0xA1 {
                op.dst = Operand::reg(0); // AL/AX/eAX/rAX
                op.src = mem;
            } else {
                op.dst = mem;
                op.src = Operand::reg(0);
            }
            op.text = "mov".into();
        } else if opcode == 0xC6 || opcode == 0xC7 {
            let size = if opcode == 0xC6 { 1 } else { dec.op_size };
            let (_reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::MovImm;
            op.dst = rm;
            op.size = size;
            if opcode == 0xC6 {
                op.imm = self.fetch8(&mut dec) as u64;
            } else if size == 2 {
                op.imm = self.fetch16(&mut dec) as u64;
            } else {
                op.imm =
                    Self::sign_extend(self.fetch32(&mut dec) as u64, 4) as u64 & Self::mask(size);
            }
            op.text = "mov".into();
        } else if opcode == 0x80 || opcode == 0x82 || opcode == 0x81 || opcode == 0x83 {
            // Group 1: ALU r/m, imm (0x82 is the undocumented alias of 0x80).
            let size = if opcode == 0x80 || opcode == 0x82 {
                1
            } else {
                dec.op_size
            };
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::AluRmImm;
            op.dst = rm;
            op.size = size;
            op.alu_op = reg_field & 7;
            if opcode == 0x80 || opcode == 0x82 {
                op.imm = self.fetch8(&mut dec) as u64;
            } else if opcode == 0x83 {
                op.imm =
                    Self::sign_extend(self.fetch8(&mut dec) as u64, 1) as u64 & Self::mask(size);
            } else if size == 2 {
                op.imm = self.fetch16(&mut dec) as u64;
            } else {
                op.imm =
                    Self::sign_extend(self.fetch32(&mut dec) as u64, 4) as u64 & Self::mask(size);
            }
            op.text = ALU_NAMES[(op.alu_op & 7) as usize].into();
        } else if opcode == 0x84 || opcode == 0x85 {
            let size = if opcode == 0x84 { 1 } else { dec.op_size };
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::Test;
            op.dst = rm;
            op.src = Operand::reg(reg_field);
            op.size = size;
            op.text = "test".into();
        } else if opcode == 0xA8 || opcode == 0xA9 {
            let size = if opcode == 0xA8 { 1 } else { dec.op_size };
            op.kind = MicroOpKind::TestImm;
            op.dst = Operand::reg(GPR_RAX as i32);
            op.size = size;
            if opcode == 0xA8 {
                op.imm = self.fetch8(&mut dec) as u64;
            } else if size == 2 {
                op.imm = self.fetch16(&mut dec) as u64;
            } else {
                op.imm = self.fetch32(&mut dec) as u64;
            }
            op.text = "test".into();
        } else if opcode == 0x8F {
            let (_reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::Pop;
            op.dst = rm;
            op.size = self.stack_size(&dec);
            op.text = "pop".into();
        } else if opcode == 0xFE || opcode == 0xFF {
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            let ext = reg_field & 7;

            if opcode == 0xFE || ext == 0 || ext == 1 {
                op.kind = MicroOpKind::IncDec;
                op.dst = rm;
                op.size = if opcode == 0xFE { 1 } else { dec.op_size };
                op.alu_op = if ext == 0 { 0 } else { 1 };
                op.text = if ext == 0 { "inc".into() } else { "dec".into() };
            } else if ext == 2 {
                op.kind = MicroOpKind::CallInd;
                op.src = rm;
                op.size = if self.bits == 64 { 8 } else { dec.op_size };
                op.text = "call".into();
            } else if ext == 3 {
                op.kind = MicroOpKind::CallFarInd;
                op.src = rm;
                op.size = dec.op_size;
                op.text = "callf".into();
            } else if ext == 4 {
                op.kind = MicroOpKind::JmpInd;
                op.src = rm;
                op.size = if self.bits == 64 { 8 } else { dec.op_size };
                op.text = "jmp".into();
            } else if ext == 5 {
                op.kind = MicroOpKind::JmpFarInd;
                op.src = rm;
                op.size = dec.op_size;
                op.text = "jmpf".into();
            } else if ext == 6 {
                op.kind = MicroOpKind::Push;
                op.src = rm;
                op.size = self.stack_size(&dec);
                op.text = "push".into();
            } else {
                op.kind = MicroOpKind::Unimpl;
                op.text = "ff /?".into();
            }
        } else if opcode == 0xE8 {
            let rel = if dec.op_size == 2 {
                self.fetch16(&mut dec) as i16 as i32
            } else {
                self.fetch32(&mut dec) as i32
            };
            op.kind = MicroOpKind::Call;
            op.branch_target = dec.fetch.wrapping_add(rel as i64 as u64);
            op.text = "call".into();
        } else if opcode == 0xE9 {
            let rel = if dec.op_size == 2 {
                self.fetch16(&mut dec) as i16 as i32
            } else {
                self.fetch32(&mut dec) as i32
            };
            op.kind = MicroOpKind::Jmp;
            op.branch_target = dec.fetch.wrapping_add(rel as i64 as u64);
            op.text = "jmp".into();
        } else if opcode == 0xEB {
            let rel = self.fetch8(&mut dec) as i8;
            op.kind = MicroOpKind::Jmp;
            op.branch_target = dec.fetch.wrapping_add(rel as i64 as u64);
            op.text = "jmp".into();
        } else if opcode == 0xEA || opcode == 0x9A {
            // Far direct jmp/call ptr16:16.
            let off = if dec.op_size == 2 {
                self.fetch16(&mut dec) as u32
            } else {
                self.fetch32(&mut dec)
            };
            let seg = self.fetch16(&mut dec);
            op.kind = if opcode == 0xEA {
                MicroOpKind::JmpFar
            } else {
                MicroOpKind::CallFar
            };
            op.branch_target = off as u64;
            op.imm = seg as u64;
            op.text = if opcode == 0xEA {
                "jmpf".into()
            } else {
                "callf".into()
            };
        } else if matches!(
            opcode,
            0xE4 | 0xE5 | 0xE6 | 0xE7 | 0xEC | 0xED | 0xEE | 0xEF
        ) {
            // Port I/O.
            let is_out = matches!(opcode, 0xE6 | 0xE7 | 0xEE | 0xEF);
            let is_byte = matches!(opcode, 0xE4 | 0xE6 | 0xEC | 0xEE);
            let is_imm_port = (0xE4..=0xE7).contains(&opcode);
            op.kind = if is_out {
                MicroOpKind::Out
            } else {
                MicroOpKind::In
            };
            op.size = if is_byte { 1 } else { dec.op_size };
            op.cond = if is_imm_port { 0 } else { 1 }; // 0 = imm8 port, 1 = DX
            if is_imm_port {
                op.imm = self.fetch8(&mut dec) as u64;
            }
            op.text = if is_out { "out".into() } else { "in".into() };
        } else if (0xE0..=0xE3).contains(&opcode) {
            let rel = self.fetch8(&mut dec) as i8;
            op.kind = MicroOpKind::Loop;
            op.alu_op = (opcode - 0xE0) as i32; // 0 loopne, 1 loope, 2 loop, 3 jecxz
            op.branch_target = dec.fetch.wrapping_add(rel as i64 as u64);
            op.text = if opcode == 0xE3 {
                "jecxz".into()
            } else {
                "loop".into()
            };
        } else if (0x70..=0x7F).contains(&opcode) {
            let rel = self.fetch8(&mut dec) as i8;
            op.kind = MicroOpKind::Jcc;
            op.cond = opcode - 0x70;
            op.branch_target = dec.fetch.wrapping_add(rel as i64 as u64);
            op.text = "jcc".into();
        } else if opcode == 0xC3 {
            op.kind = MicroOpKind::Ret;
            op.text = "ret".into();
        } else if opcode == 0xC2 {
            op.kind = MicroOpKind::Ret;
            op.imm = self.fetch16(&mut dec) as u64;
            op.text = "ret".into();
        } else if opcode == 0xC4 || opcode == 0xC5 {
            // les/lds reg, m16:16.
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::LoadFar;
            op.dst = Operand::reg(reg_field);
            op.src = rm;
            op.size = dec.op_size;
            op.cond = if opcode == 0xC4 { 0 } else { 1 }; // 0 = ES, 1 = DS
            op.text = if opcode == 0xC4 {
                "les".into()
            } else {
                "lds".into()
            };
        } else if opcode == 0xCB {
            op.kind = MicroOpKind::Retf;
            op.size = dec.op_size;
            op.text = "retf".into();
        } else if opcode == 0xCA {
            op.kind = MicroOpKind::Retf;
            op.size = dec.op_size;
            op.imm = self.fetch16(&mut dec) as u64;
            op.text = "retf".into();
        } else if opcode == 0xCF {
            op.kind = MicroOpKind::Iret;
            op.text = "iret".into();
        } else if matches!(opcode, 0xF5 | 0xF8 | 0xF9 | 0xFA | 0xFB | 0xFC | 0xFD) {
            op.kind = MicroOpKind::FlagOp;
            match opcode {
                0xF8 => {
                    op.alu_op = 0;
                    op.text = "clc".into();
                }
                0xF9 => {
                    op.alu_op = 1;
                    op.text = "stc".into();
                }
                0xF5 => {
                    op.alu_op = 2;
                    op.text = "cmc".into();
                }
                0xFC => {
                    op.alu_op = 3;
                    op.text = "cld".into();
                }
                0xFD => {
                    op.alu_op = 4;
                    op.text = "std".into();
                }
                0xFA => {
                    op.alu_op = 5;
                    op.text = "cli".into();
                }
                _ => {
                    op.alu_op = 6;
                    op.text = "sti".into();
                }
            }
        } else if opcode == 0x90 {
            op.kind = MicroOpKind::Nop;
            op.text = "nop".into();
        } else if opcode == 0x9B {
            // fwait/wait: no-op (a following D8-DF is decoded separately).
            op.kind = MicroOpKind::Nop;
            op.text = "fwait".into();
        } else if opcode == 0x9C {
            op.kind = MicroOpKind::PushF;
            op.size = if self.bits == 64 { 8 } else { dec.op_size };
            op.text = match op.size {
                2 => "pushf".into(),
                8 => "pushfq".into(),
                _ => "pushfd".into(),
            };
        } else if opcode == 0x9D {
            op.kind = MicroOpKind::PopF;
            op.size = if self.bits == 64 { 8 } else { dec.op_size };
            op.text = match op.size {
                2 => "popf".into(),
                8 => "popfq".into(),
                _ => "popfd".into(),
            };
        } else if opcode == 0x9E {
            op.kind = MicroOpKind::Sahf;
            op.text = "sahf".into();
        } else if opcode == 0x9F {
            op.kind = MicroOpKind::Lahf;
            op.text = "lahf".into();
        } else if opcode == 0xC8 {
            op.kind = MicroOpKind::Enter;
            op.imm = self.fetch16(&mut dec) as u64; // frame size
            op.alu_op = self.fetch8(&mut dec) as i32; // nesting level
            op.text = "enter".into();
        } else if opcode == 0xC9 {
            op.kind = MicroOpKind::Leave;
            op.text = "leave".into();
        } else if opcode == 0xD6 {
            // salc/setalc (undocumented): AL = CF ? 0xFF : 0x00.
            op.kind = MicroOpKind::Salc;
            op.text = "salc".into();
        } else if opcode == 0xD7 {
            op.kind = MicroOpKind::Xlat;
            op.size = dec.addr_size; // (r)BX width
            op.src.seg_source = dec.seg_source; // honor a segment override
            op.text = "xlat".into();
        } else if matches!(opcode, 0x06 | 0x0E | 0x16 | 0x1E) {
            op.kind = MicroOpKind::PushSeg;
            op.alu_op = match opcode {
                0x06 => 0,
                0x0E => 1,
                0x16 => 2,
                _ => 3,
            }; // ES / CS / SS / DS
            op.text = "push".into();
        } else if matches!(opcode, 0x07 | 0x17 | 0x1F) {
            op.kind = MicroOpKind::PopSeg;
            op.alu_op = match opcode {
                0x07 => 0,
                0x17 => 2,
                _ => 3,
            }; // ES / SS / DS
            op.text = "pop".into();
        } else if opcode == 0x62 {
            // bound r, m: consume the ModR/M and skip the check.
            let (_reg_field, _rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::Nop;
            op.text = "bound".into();
        } else if matches!(opcode, 0x27 | 0x2F | 0x37 | 0x3F) {
            op.kind = MicroOpKind::Bcd;
            op.alu_op = match opcode {
                0x27 => 0,
                0x2F => 1,
                0x37 => 2,
                _ => 3,
            }; // DAA/DAS/AAA/AAS
            op.text = "bcd".into();
        } else if opcode == 0xD4 || opcode == 0xD5 {
            op.kind = MicroOpKind::Bcd;
            op.alu_op = if opcode == 0xD4 { 4 } else { 5 }; // AAM / AAD
            op.imm = self.fetch8(&mut dec) as u64; // base
            op.text = if opcode == 0xD4 {
                "aam".into()
            } else {
                "aad".into()
            };
        } else if opcode == 0xCC {
            // int3: software interrupt vector 3.
            op.kind = MicroOpKind::Syscall;
            op.imm = 3;
            op.alu_op = 2;
            op.text = "int3".into();
        } else if opcode == 0xF4 {
            op.kind = MicroOpKind::Halt;
            op.text = "hlt".into();
        } else if opcode == 0xCD {
            // Software interrupt; vector rides in `imm`.
            let vector = self.fetch8(&mut dec);
            op.kind = MicroOpKind::Syscall;
            op.imm = vector as u64;
            op.alu_op = if vector == 0x80 { 1 } else { 2 };
            op.text = format!("int 0x{vector:02x}");
        } else if opcode == 0xCE {
            // into: interrupt 4 if OF is set.
            op.kind = MicroOpKind::Into;
            op.text = "into".into();
        } else if opcode == 0xF1 {
            // icebp/int1 (undocumented): software interrupt 1.
            op.kind = MicroOpKind::Syscall;
            op.imm = 1;
            op.alu_op = 2;
            op.text = "icebp".into();
        } else if opcode == 0x63 && self.bits != 64 {
            // arpl r/m16, r16.
            let (reg, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::Arpl;
            op.dst = rm;
            op.src = Operand::reg(reg);
            op.size = 2;
            op.text = "arpl".into();
        } else if opcode == 0x60 {
            op.kind = MicroOpKind::Pusha;
            op.size = dec.op_size;
            op.text = "pushad".into();
        } else if opcode == 0x61 {
            op.kind = MicroOpKind::Popa;
            op.size = dec.op_size;
            op.text = "popad".into();
        } else if matches!(opcode, 0xC0 | 0xC1 | 0xD0 | 0xD1 | 0xD2 | 0xD3) {
            let size = if matches!(opcode, 0xC0 | 0xD0 | 0xD2) {
                1
            } else {
                dec.op_size
            };
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::Shift;
            op.dst = rm;
            op.size = size;
            op.alu_op = reg_field & 7; // 0 rol,1 ror,2 rcl,3 rcr,4 shl,5 shr,6 sal,7 sar
            if opcode == 0xC0 || opcode == 0xC1 {
                op.cond = 0;
                op.imm = self.fetch8(&mut dec) as u64;
            } else if opcode == 0xD0 || opcode == 0xD1 {
                op.cond = 0;
                op.imm = 1;
            } else {
                op.cond = 1; // count from CL
            }
            op.text = "shift".into();
        } else if opcode == 0xF6 || opcode == 0xF7 {
            let size = if opcode == 0xF6 { 1 } else { dec.op_size };
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            let ext = reg_field & 7;
            op.size = size;
            op.dst = rm;
            if ext == 0 || ext == 1 {
                // test rm, imm
                op.kind = MicroOpKind::TestImm;
                if opcode == 0xF6 {
                    op.imm = self.fetch8(&mut dec) as u64;
                } else if size == 2 {
                    op.imm = self.fetch16(&mut dec) as u64;
                } else {
                    op.imm = self.fetch32(&mut dec) as u64;
                }
                op.text = "test".into();
            } else {
                // not/neg/mul/imul/div/idiv
                op.kind = MicroOpKind::MulDiv;
                op.alu_op = ext;
                op.text = "grp3".into();
            }
        } else if opcode == 0x86 || opcode == 0x87 {
            let size = if opcode == 0x86 { 1 } else { dec.op_size };
            let (reg_field, rm) = self.decode_modrm(&mut dec);
            op.kind = MicroOpKind::Xchg;
            op.dst = rm;
            op.src = Operand::reg(reg_field);
            op.size = size;
            op.text = "xchg".into();
        } else if (0x91..=0x97).contains(&opcode) {
            op.kind = MicroOpKind::Xchg;
            op.dst = Operand::reg(GPR_RAX as i32);
            op.src = Operand::reg((opcode - 0x90) as i32 + if dec.rex_b { 8 } else { 0 });
            op.size = dec.op_size;
            op.text = "xchg".into();
        } else if opcode == 0x98 || opcode == 0x99 {
            op.kind = MicroOpKind::Cdq;
            op.alu_op = if opcode == 0x98 { 0 } else { 1 };
            op.size = dec.op_size;
            op.text = if opcode == 0x98 {
                "cwde".into()
            } else {
                "cdq".into()
            };
        } else if matches!(
            opcode,
            0xA4 | 0xA5 | 0xAA | 0xAB | 0xAC | 0xAD | 0xAE | 0xAF | 0xA6 | 0xA7
        ) {
            let is_byte = (opcode & 1) == 0;
            op.kind = MicroOpKind::String;
            op.size = if is_byte { 1 } else { dec.op_size };
            op.cond = dec.rep as u8; // 0 none, 1 rep/repe, 2 repne
            op.src.seg_source = dec.seg_source; // override applies to the SOURCE
            match opcode {
                0xA4 | 0xA5 => {
                    op.alu_op = 0;
                    op.text = "movs".into();
                }
                0xAA | 0xAB => {
                    op.alu_op = 1;
                    op.text = "stos".into();
                }
                0xAC | 0xAD => {
                    op.alu_op = 2;
                    op.text = "lods".into();
                }
                0xAE | 0xAF => {
                    op.alu_op = 3;
                    op.text = "scas".into();
                }
                _ => {
                    op.alu_op = 4;
                    op.text = "cmps".into();
                }
            }
        } else if matches!(opcode, 0x6C..=0x6F) {
            // ins/outs string port I/O.
            let is_byte = (opcode & 1) == 0;
            op.kind = MicroOpKind::String;
            op.size = if is_byte { 1 } else { dec.op_size };
            op.cond = dec.rep as u8;
            op.src.seg_source = dec.seg_source; // override applies to the outs source
            op.alu_op = if opcode <= 0x6D { 5 } else { 6 }; // 5 ins, 6 outs
            op.text = if opcode <= 0x6D {
                "ins".into()
            } else {
                "outs".into()
            };
        } else if (0xD8..=0xDF).contains(&opcode) {
            self.decode_fpu(&mut dec, &mut op, opcode);
        } else if opcode == 0x0F {
            self.decode_two_byte(&mut dec, &mut op);
        } else {
            op.kind = MicroOpKind::Unimpl;
            op.text = format!("db {opcode:02x}");
        }

        if dec.fault {
            return None;
        }

        // Legacy high-byte fixup now that operand widths are known.
        if !dec.has_rex {
            fix_high8(&mut op.dst, op.size);
            fix_high8(&mut op.src, op.size);
            if op.kind == MicroOpKind::Movzx || op.kind == MicroOpKind::Movsx {
                fix_high8(&mut op.src, op.src_size);
            }
        }

        op.length = dec.fetch.wrapping_sub(dec.start) as u32;
        Some(op)
    }

    /// Single-instruction decode for oracle/debug dumps
    /// (upstream `decodeMicroOpSnapshot`).
    pub fn decode_micro_op_snapshot(&mut self, address: u64) -> Option<MicroOp> {
        self.decode_insn(address)
    }
}

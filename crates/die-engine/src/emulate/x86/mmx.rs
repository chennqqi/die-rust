//! MMX packed-integer execution — faithful port of the MMX block in
//! upstream `arch/xemux86.cpp` (pin `655e6da`). The `MMX_*` constants are
//! the `nAluOp` ids carried inside `MOP_MMX` micro-ops; the contiguous
//! shift range `PSLLW..PSRAD` must be preserved (`mmx_is_shift` relies
//! on it).

use super::*;

pub(crate) const MMX_PAND: i32 = 0;
pub(crate) const MMX_PANDN: i32 = 1;
pub(crate) const MMX_POR: i32 = 2;
pub(crate) const MMX_PXOR: i32 = 3;
pub(crate) const MMX_PADDB: i32 = 4;
pub(crate) const MMX_PADDW: i32 = 5;
pub(crate) const MMX_PADDD: i32 = 6;
pub(crate) const MMX_PADDQ: i32 = 7;
pub(crate) const MMX_PADDSB: i32 = 8;
pub(crate) const MMX_PADDSW: i32 = 9;
pub(crate) const MMX_PADDUSB: i32 = 10;
pub(crate) const MMX_PADDUSW: i32 = 11;
pub(crate) const MMX_PSUBB: i32 = 12;
pub(crate) const MMX_PSUBW: i32 = 13;
pub(crate) const MMX_PSUBD: i32 = 14;
pub(crate) const MMX_PSUBQ: i32 = 15;
pub(crate) const MMX_PSUBSB: i32 = 16;
pub(crate) const MMX_PSUBSW: i32 = 17;
pub(crate) const MMX_PSUBUSB: i32 = 18;
pub(crate) const MMX_PSUBUSW: i32 = 19;
pub(crate) const MMX_PCMPEQB: i32 = 20;
pub(crate) const MMX_PCMPEQW: i32 = 21;
pub(crate) const MMX_PCMPEQD: i32 = 22;
pub(crate) const MMX_PCMPGTB: i32 = 23;
pub(crate) const MMX_PCMPGTW: i32 = 24;
pub(crate) const MMX_PCMPGTD: i32 = 25;
pub(crate) const MMX_PACKSSWB: i32 = 26;
pub(crate) const MMX_PACKSSDW: i32 = 27;
pub(crate) const MMX_PACKUSWB: i32 = 28;
pub(crate) const MMX_PUNPCKLBW: i32 = 29;
pub(crate) const MMX_PUNPCKLWD: i32 = 30;
pub(crate) const MMX_PUNPCKLDQ: i32 = 31;
pub(crate) const MMX_PUNPCKHBW: i32 = 32;
pub(crate) const MMX_PUNPCKHWD: i32 = 33;
pub(crate) const MMX_PUNPCKHDQ: i32 = 34;
pub(crate) const MMX_PMULLW: i32 = 35;
pub(crate) const MMX_PMULHW: i32 = 36;
pub(crate) const MMX_PMULHUW: i32 = 37;
pub(crate) const MMX_PMADDWD: i32 = 38;
pub(crate) const MMX_PAVGB: i32 = 39;
pub(crate) const MMX_PAVGW: i32 = 40;
pub(crate) const MMX_PMINUB: i32 = 41;
pub(crate) const MMX_PMAXUB: i32 = 42;
pub(crate) const MMX_PMINSW: i32 = 43;
pub(crate) const MMX_PMAXSW: i32 = 44;
pub(crate) const MMX_PSADBW: i32 = 45;
pub(crate) const MMX_PSLLW: i32 = 46;
pub(crate) const MMX_PSLLD: i32 = 47;
pub(crate) const MMX_PSLLQ: i32 = 48;
pub(crate) const MMX_PSRLW: i32 = 49;
pub(crate) const MMX_PSRLD: i32 = 50;
pub(crate) const MMX_PSRLQ: i32 = 51;
pub(crate) const MMX_PSRAW: i32 = 52;
pub(crate) const MMX_PSRAD: i32 = 53;
pub(crate) const MMX_PSHUFW: i32 = 54;
pub(crate) const MMX_EMMS: i32 = 55;
pub(crate) const MMX_MOVD_TO: i32 = 56;
pub(crate) const MMX_MOVD_FROM: i32 = 57;
pub(crate) const MMX_MOVQ_TO: i32 = 58;
pub(crate) const MMX_MOVQ_FROM: i32 = 59;

/// Whether `op` is one of the packed shift ids (upstream `mmxIsShift`).
pub(crate) fn mmx_is_shift(op: i32) -> bool {
    (MMX_PSLLW..=MMX_PSRAD).contains(&op)
}

fn msat_u8(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

fn msat_s8(v: i32) -> u8 {
    v.clamp(-128, 127) as i8 as u8
}

fn msat_u16(v: i32) -> u16 {
    v.clamp(0, 65535) as u16
}

fn msat_s16(v: i32) -> u16 {
    v.clamp(-32768, 32767) as i16 as u16
}

/// Byte lane `i` of a 64-bit MMX value (upstream `gB`).
fn gb(v: u64, i: usize) -> u8 {
    (v >> (i * 8)) as u8
}

/// Word lane `i` of a 64-bit MMX value (upstream `gW`).
fn gw(v: u64, i: usize) -> u16 {
    (v >> (i * 16)) as u16
}

/// Dword lane `i` of a 64-bit MMX value (upstream `gD`).
fn gd(v: u64, i: usize) -> u32 {
    (v >> (i * 32)) as u32
}

impl<'a> X86<'a> {
    /// Read an MMX operand (register or 8-byte memory).
    pub(crate) fn read_mmx(&mut self, op: &MicroOp, operand: &Operand, regs: &Registers) -> u64 {
        if operand.is_reg {
            return regs.mmx[(operand.reg & 7) as usize];
        }
        {
            let a = self.resolve_addr(op, operand, regs);
            self.mem_read_sized(a, 8)
        }
    }

    /// Write an MMX operand (register or 8-byte memory).
    pub(crate) fn write_mmx(
        &mut self,
        op: &MicroOp,
        operand: &Operand,
        regs: &mut Registers,
        value: u64,
    ) {
        if operand.is_reg {
            regs.mmx[(operand.reg & 7) as usize] = value;
            return;
        }
        {
            let a = self.resolve_addr(op, operand, regs);
            self.mem_write_sized(a, value, 8)
        };
    }

    /// Packed ALU operation (upstream `_mmxALU`); lane-wise wrapping
    /// arithmetic with the same saturation helpers as upstream.
    pub(crate) fn mmx_alu(&self, op: i32, a: u64, b: u64) -> u64 {
        let mut r: u64 = 0;
        match op {
            MMX_PAND => return a & b,
            MMX_PANDN => return !a & b,
            MMX_POR => return a | b,
            MMX_PXOR => return a ^ b,

            // ---- byte lanes (8) ----
            MMX_PADDB => {
                for i in 0..8 {
                    r |= (gb(a, i).wrapping_add(gb(b, i)) as u64) << (i * 8);
                }
            }
            MMX_PSUBB => {
                for i in 0..8 {
                    r |= (gb(a, i).wrapping_sub(gb(b, i)) as u64) << (i * 8);
                }
            }
            MMX_PADDSB => {
                for i in 0..8 {
                    r |= (msat_s8(gb(a, i) as i8 as i32 + gb(b, i) as i8 as i32) as u64) << (i * 8);
                }
            }
            MMX_PSUBSB => {
                for i in 0..8 {
                    r |= (msat_s8(gb(a, i) as i8 as i32 - gb(b, i) as i8 as i32) as u64) << (i * 8);
                }
            }
            MMX_PADDUSB => {
                for i in 0..8 {
                    r |= (msat_u8(gb(a, i) as i32 + gb(b, i) as i32) as u64) << (i * 8);
                }
            }
            MMX_PSUBUSB => {
                for i in 0..8 {
                    r |= (msat_u8(gb(a, i) as i32 - gb(b, i) as i32) as u64) << (i * 8);
                }
            }
            MMX_PCMPEQB => {
                for i in 0..8 {
                    r |= (if gb(a, i) == gb(b, i) { 0xFF } else { 0 }) << (i * 8);
                }
            }
            MMX_PCMPGTB => {
                for i in 0..8 {
                    r |= (if gb(a, i) as i8 > gb(b, i) as i8 {
                        0xFF
                    } else {
                        0
                    }) << (i * 8);
                }
            }
            MMX_PMINUB => {
                for i in 0..8 {
                    r |= (gb(a, i).min(gb(b, i)) as u64) << (i * 8);
                }
            }
            MMX_PMAXUB => {
                for i in 0..8 {
                    r |= (gb(a, i).max(gb(b, i)) as u64) << (i * 8);
                }
            }
            MMX_PAVGB => {
                for i in 0..8 {
                    r |= ((((gb(a, i) as i32 + gb(b, i) as i32 + 1) >> 1) as u8) as u64) << (i * 8);
                }
            }

            // ---- word lanes (4) ----
            MMX_PADDW => {
                for i in 0..4 {
                    r |= (gw(a, i).wrapping_add(gw(b, i)) as u64) << (i * 16);
                }
            }
            MMX_PSUBW => {
                for i in 0..4 {
                    r |= (gw(a, i).wrapping_sub(gw(b, i)) as u64) << (i * 16);
                }
            }
            MMX_PADDSW => {
                for i in 0..4 {
                    r |= (msat_s16(gw(a, i) as i16 as i32 + gw(b, i) as i16 as i32) as u64)
                        << (i * 16);
                }
            }
            MMX_PSUBSW => {
                for i in 0..4 {
                    r |= (msat_s16(gw(a, i) as i16 as i32 - gw(b, i) as i16 as i32) as u64)
                        << (i * 16);
                }
            }
            MMX_PADDUSW => {
                for i in 0..4 {
                    r |= (msat_u16(gw(a, i) as i32 + gw(b, i) as i32) as u64) << (i * 16);
                }
            }
            MMX_PSUBUSW => {
                for i in 0..4 {
                    r |= (msat_u16(gw(a, i) as i32 - gw(b, i) as i32) as u64) << (i * 16);
                }
            }
            MMX_PCMPEQW => {
                for i in 0..4 {
                    r |= (if gw(a, i) == gw(b, i) { 0xFFFF } else { 0 }) << (i * 16);
                }
            }
            MMX_PCMPGTW => {
                for i in 0..4 {
                    r |= (if gw(a, i) as i16 > gw(b, i) as i16 {
                        0xFFFF
                    } else {
                        0
                    }) << (i * 16);
                }
            }
            MMX_PMINSW => {
                for i in 0..4 {
                    r |= ((gw(a, i) as i16).min(gw(b, i) as i16) as u16 as u64) << (i * 16);
                }
            }
            MMX_PMAXSW => {
                for i in 0..4 {
                    r |= ((gw(a, i) as i16).max(gw(b, i) as i16) as u16 as u64) << (i * 16);
                }
            }
            MMX_PAVGW => {
                for i in 0..4 {
                    r |= ((((gw(a, i) as i32 + gw(b, i) as i32 + 1) >> 1) as u16) as u64)
                        << (i * 16);
                }
            }
            MMX_PMULLW => {
                for i in 0..4 {
                    r |= (((gw(a, i) as i16 as i32 * gw(b, i) as i16 as i32) as u16) as u64)
                        << (i * 16);
                }
            }
            MMX_PMULHW => {
                for i in 0..4 {
                    r |= ((((gw(a, i) as i16 as i32 * gw(b, i) as i16 as i32) >> 16) as u16)
                        as u64)
                        << (i * 16);
                }
            }
            MMX_PMULHUW => {
                for i in 0..4 {
                    r |= ((((gw(a, i) as u32 * gw(b, i) as u32) >> 16) as u16) as u64) << (i * 16);
                }
            }

            // ---- dword lanes (2) ----
            MMX_PADDD => {
                for i in 0..2 {
                    r |= (gd(a, i).wrapping_add(gd(b, i)) as u64) << (i * 32);
                }
            }
            MMX_PSUBD => {
                for i in 0..2 {
                    r |= (gd(a, i).wrapping_sub(gd(b, i)) as u64) << (i * 32);
                }
            }
            MMX_PCMPEQD => {
                for i in 0..2 {
                    r |= (if gd(a, i) == gd(b, i) { 0xFFFF_FFFF } else { 0 }) << (i * 32);
                }
            }
            MMX_PCMPGTD => {
                for i in 0..2 {
                    r |= (if gd(a, i) as i32 > gd(b, i) as i32 {
                        0xFFFF_FFFF
                    } else {
                        0
                    }) << (i * 32);
                }
            }

            // ---- qword lane (1) ----
            MMX_PADDQ => return a.wrapping_add(b),
            MMX_PSUBQ => return a.wrapping_sub(b),

            // ---- multiply-add ----
            MMX_PMADDWD => {
                for i in 0..2 {
                    let lo = gw(a, i * 2) as i16 as i32 * gw(b, i * 2) as i16 as i32;
                    let hi = gw(a, i * 2 + 1) as i16 as i32 * gw(b, i * 2 + 1) as i16 as i32;
                    r |= (lo.wrapping_add(hi) as u32 as u64) << (i * 32);
                }
            }

            // ---- pack (dst lanes low, src lanes high) ----
            MMX_PACKSSWB => {
                for i in 0..4 {
                    r |= (msat_s8(gw(a, i) as i16 as i32) as u64) << (i * 8);
                }
                for i in 0..4 {
                    r |= (msat_s8(gw(b, i) as i16 as i32) as u64) << ((i + 4) * 8);
                }
            }
            MMX_PACKUSWB => {
                for i in 0..4 {
                    r |= (msat_u8(gw(a, i) as i16 as i32) as u64) << (i * 8);
                }
                for i in 0..4 {
                    r |= (msat_u8(gw(b, i) as i16 as i32) as u64) << ((i + 4) * 8);
                }
            }
            MMX_PACKSSDW => {
                for i in 0..2 {
                    r |= (msat_s16(gd(a, i) as i32) as u64) << (i * 16);
                }
                for i in 0..2 {
                    r |= (msat_s16(gd(b, i) as i32) as u64) << ((i + 2) * 16);
                }
            }

            // ---- unpack (interleave) ----
            MMX_PUNPCKLBW => {
                for i in 0..4 {
                    r |= (gb(a, i) as u64) << (i * 16);
                    r |= (gb(b, i) as u64) << (i * 16 + 8);
                }
            }
            MMX_PUNPCKHBW => {
                for i in 0..4 {
                    r |= (gb(a, i + 4) as u64) << (i * 16);
                    r |= (gb(b, i + 4) as u64) << (i * 16 + 8);
                }
            }
            MMX_PUNPCKLWD => {
                for i in 0..2 {
                    r |= (gw(a, i) as u64) << (i * 32);
                    r |= (gw(b, i) as u64) << (i * 32 + 16);
                }
            }
            MMX_PUNPCKHWD => {
                for i in 0..2 {
                    r |= (gw(a, i + 2) as u64) << (i * 32);
                    r |= (gw(b, i + 2) as u64) << (i * 32 + 16);
                }
            }
            MMX_PUNPCKLDQ => return gd(a, 0) as u64 | ((gd(b, 0) as u64) << 32),
            MMX_PUNPCKHDQ => return gd(a, 1) as u64 | ((gd(b, 1) as u64) << 32),

            // ---- sum of absolute differences ----
            MMX_PSADBW => {
                let mut sum: u32 = 0;
                for i in 0..8 {
                    let d = gb(a, i) as i32 - gb(b, i) as i32;
                    sum = sum.wrapping_add(d.unsigned_abs());
                }
                return (sum & 0xFFFF) as u64;
            }

            _ => return 0,
        }
        r
    }

    /// Packed shift by a full (unmasked) count; counts at or above the
    /// lane width clear or sign-fill the lane (upstream `_mmxShift`).
    pub(crate) fn mmx_shift(&self, op: i32, a: u64, count: u64) -> u64 {
        let mut r: u64 = 0;
        let n = count;
        match op {
            MMX_PSLLW => {
                for i in 0..4 {
                    let s = if n >= 16 {
                        0
                    } else {
                        gw(a, i).wrapping_shl(n as u32)
                    };
                    r |= (s as u64) << (i * 16);
                }
            }
            MMX_PSRLW => {
                for i in 0..4 {
                    let s = if n >= 16 { 0 } else { gw(a, i) >> n };
                    r |= (s as u64) << (i * 16);
                }
            }
            MMX_PSRAW => {
                for i in 0..4 {
                    let v = gw(a, i) as i16;
                    let s = if n >= 16 {
                        if v < 0 { 0xFFFF } else { 0 }
                    } else {
                        (v >> n) as u16
                    };
                    r |= (s as u64) << (i * 16);
                }
            }
            MMX_PSLLD => {
                for i in 0..2 {
                    let s = if n >= 32 {
                        0
                    } else {
                        gd(a, i).wrapping_shl(n as u32)
                    };
                    r |= (s as u64) << (i * 32);
                }
            }
            MMX_PSRLD => {
                for i in 0..2 {
                    let s = if n >= 32 { 0 } else { gd(a, i) >> n };
                    r |= (s as u64) << (i * 32);
                }
            }
            MMX_PSRAD => {
                for i in 0..2 {
                    let v = gd(a, i) as i32;
                    let s = if n >= 32 {
                        if v < 0 { 0xFFFF_FFFF } else { 0 }
                    } else {
                        (v >> n) as u32
                    };
                    r |= (s as u64) << (i * 32);
                }
            }
            MMX_PSLLQ => return if n >= 64 { 0 } else { a << n },
            MMX_PSRLQ => return if n >= 64 { 0 } else { a >> n },
            _ => return a,
        }
        r
    }
}

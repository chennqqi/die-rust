//! aPLib-style depacker shared by the FSG and MEW static unpackers
//! (upstream `unfsg`/`unmew` use the same bitstream: aPLib's
//! sentinel-bit refill with interleaved bit/byte cursors).

use super::upx::UnpackError;

/// `fsgGetBit`/`mewGetBit`: single-bit reader with the aPLib
/// sentinel-bit refill scheme. Bit reads and raw byte reads share the
/// same source cursor; `s`/`s_end` are absolute indices into the
/// buffer passed to each call so the depacker can work in place.
struct BitReader {
    s: usize,
    s_end: usize,
    mydl: u8,
}

impl BitReader {
    fn new(s: usize, s_end: usize) -> Self {
        Self {
            s,
            s_end,
            mydl: 0x80,
        }
    }

    fn get_bit(&mut self, buf: &[u8]) -> Option<u32> {
        let old = self.mydl;
        self.mydl = self.mydl.wrapping_mul(2);
        if old & 0x7f == 0 {
            if self.s >= self.s_end.saturating_sub(1) {
                return None;
            }
            let b = *buf.get(self.s)?;
            self.s += 1;
            self.mydl = b.wrapping_mul(2).wrapping_add(1);
            return Some(u32::from(b >> 7));
        }
        Some(u32::from(old >> 7))
    }

    fn read_byte(&mut self, buf: &[u8]) -> Option<u32> {
        if self.s >= self.s_end {
            return None;
        }
        let b = *buf.get(self.s)?;
        self.s += 1;
        Some(u32::from(b))
    }
}

/// `XFSG::_aplibDepack`/`XMEW::_aplibDepack` on disjoint buffers.
/// Returns (bytes written, bytes consumed) or `Malformed` on error.
pub(crate) fn aplib_depack(src: &[u8], dst: &mut [u8]) -> Result<(usize, usize), UnpackError> {
    if src.is_empty() || dst.is_empty() {
        return Err(UnpackError::Malformed("aplib: empty buffers"));
    }
    aplib_depack_ranges(src, dst)
}

/// In-place variant for the MEW work buffer: `src` and `dst` are
/// absolute ranges inside one `buf` and may overlap — matching the
/// upstream in-buffer depack where destination writes can clobber
/// source bytes the decoder has already consumed.
pub(crate) fn aplib_depack_in_place(
    buf: &mut [u8],
    src_off: usize,
    src_len: usize,
    dst_off: usize,
    dst_len: usize,
) -> Result<(usize, usize), UnpackError> {
    if src_len == 0 || dst_len == 0 {
        return Err(UnpackError::Malformed("aplib: empty buffers"));
    }
    let s_end = src_off
        .checked_add(src_len)
        .ok_or(UnpackError::Malformed("aplib: src range"))?;
    let d_end = dst_off
        .checked_add(dst_len)
        .ok_or(UnpackError::Malformed("aplib: dst range"))?;
    if s_end > buf.len() || d_end > buf.len() {
        return Err(UnpackError::Malformed("aplib: range"));
    }
    let mut bits = BitReader::new(src_off, s_end);
    let mut d = dst_off;
    let mut oldback = 0u32;
    let mut lostbit = 1u32;

    buf[d] = buf[bits.s];
    bits.s += 1;
    d += 1;

    let err = || UnpackError::Malformed("aplib: stream overrun");
    loop {
        if bits.get_bit(buf).ok_or_else(err)? != 0 {
            let mut backsize = 0u32;
            let mut backbytes: u32;
            if bits.get_bit(buf).ok_or_else(err)? != 0 {
                if bits.get_bit(buf).ok_or_else(err)? != 0 {
                    lostbit = 1;
                    backsize += 1;
                    backbytes = 0x10;
                    while backbytes < 0x100 {
                        backbytes = backbytes * 2 + bits.get_bit(buf).ok_or_else(err)?;
                    }
                    backbytes &= 0xff;
                    if backbytes == 0 {
                        if d >= d_end {
                            return Err(err());
                        }
                        buf[d] = 0;
                        d += 1;
                        continue;
                    }
                } else {
                    let byte = bits.read_byte(buf).ok_or_else(err)?;
                    backsize = backsize * 2 + (byte & 1);
                    backbytes = byte >> 1;
                    if backbytes == 0 {
                        break; // end-of-stream marker
                    }
                    backsize += 2;
                    oldback = backbytes;
                    lostbit = 0;
                }
            } else {
                backsize = 1;
                loop {
                    backsize = backsize * 2 + bits.get_bit(buf).ok_or_else(err)?;
                    if bits.get_bit(buf).ok_or_else(err)? == 0 {
                        break;
                    }
                }
                backsize = backsize.saturating_sub(1 + lostbit);
                if backsize == 0 {
                    backsize = 1;
                    loop {
                        backsize = backsize * 2 + bits.get_bit(buf).ok_or_else(err)?;
                        if bits.get_bit(buf).ok_or_else(err)? == 0 {
                            break;
                        }
                    }
                    backbytes = oldback;
                } else {
                    backbytes = bits.read_byte(buf).ok_or_else(err)? + ((backsize - 1) << 8);
                    backsize = 1;
                    loop {
                        backsize = backsize * 2 + bits.get_bit(buf).ok_or_else(err)?;
                        if bits.get_bit(buf).ok_or_else(err)? == 0 {
                            break;
                        }
                    }
                    if backbytes >= 0x7d00 {
                        backsize += 1;
                    }
                    if backbytes >= 0x500 {
                        backsize += 1;
                    }
                    if backbytes <= 0x7f {
                        backsize += 2;
                    }
                    oldback = backbytes;
                }
                lostbit = 0;
            }

            if backbytes == 0 || backbytes as usize > d - dst_off || d + backsize as usize > d_end {
                return Err(err());
            }
            for _ in 0..backsize {
                buf[d] = buf[d - backbytes as usize];
                d += 1;
            }
        } else {
            if d >= d_end {
                return Err(err());
            }
            buf[d] = bits.read_byte(buf).ok_or_else(err)? as u8;
            d += 1;
            lostbit = 1;
        }
    }
    Ok((d - dst_off, bits.s - src_off))
}

/// Separate-slice core shared by `aplib_depack`: identical logic on a
/// source read closure.
fn aplib_depack_ranges(src: &[u8], dst: &mut [u8]) -> Result<(usize, usize), UnpackError> {
    let mut bits = BitReader::new(0, src.len());
    let mut d = 0usize;
    let mut oldback = 0u32;
    let mut lostbit = 1u32;

    dst[d] = src[bits.s];
    bits.s += 1;
    d += 1;

    let err = || UnpackError::Malformed("aplib: stream overrun");
    loop {
        if bits.get_bit(src).ok_or_else(err)? != 0 {
            let mut backsize = 0u32;
            let mut backbytes: u32;
            if bits.get_bit(src).ok_or_else(err)? != 0 {
                if bits.get_bit(src).ok_or_else(err)? != 0 {
                    lostbit = 1;
                    backsize += 1;
                    backbytes = 0x10;
                    while backbytes < 0x100 {
                        backbytes = backbytes * 2 + bits.get_bit(src).ok_or_else(err)?;
                    }
                    backbytes &= 0xff;
                    if backbytes == 0 {
                        if d >= dst.len() {
                            return Err(err());
                        }
                        dst[d] = 0;
                        d += 1;
                        continue;
                    }
                } else {
                    let byte = bits.read_byte(src).ok_or_else(err)?;
                    backsize = backsize * 2 + (byte & 1);
                    backbytes = byte >> 1;
                    if backbytes == 0 {
                        break; // end-of-stream marker
                    }
                    backsize += 2;
                    oldback = backbytes;
                    lostbit = 0;
                }
            } else {
                backsize = 1;
                loop {
                    backsize = backsize * 2 + bits.get_bit(src).ok_or_else(err)?;
                    if bits.get_bit(src).ok_or_else(err)? == 0 {
                        break;
                    }
                }
                backsize = backsize.saturating_sub(1 + lostbit);
                if backsize == 0 {
                    backsize = 1;
                    loop {
                        backsize = backsize * 2 + bits.get_bit(src).ok_or_else(err)?;
                        if bits.get_bit(src).ok_or_else(err)? == 0 {
                            break;
                        }
                    }
                    backbytes = oldback;
                } else {
                    backbytes = bits.read_byte(src).ok_or_else(err)? + ((backsize - 1) << 8);
                    backsize = 1;
                    loop {
                        backsize = backsize * 2 + bits.get_bit(src).ok_or_else(err)?;
                        if bits.get_bit(src).ok_or_else(err)? == 0 {
                            break;
                        }
                    }
                    if backbytes >= 0x7d00 {
                        backsize += 1;
                    }
                    if backbytes >= 0x500 {
                        backsize += 1;
                    }
                    if backbytes <= 0x7f {
                        backsize += 2;
                    }
                    oldback = backbytes;
                }
                lostbit = 0;
            }

            if backbytes == 0 || backbytes as usize > d || d + backsize as usize > dst.len() {
                return Err(err());
            }
            for _ in 0..backsize {
                dst[d] = dst[d - backbytes as usize];
                d += 1;
            }
        } else {
            if d >= dst.len() {
                return Err(err());
            }
            dst[d] = bits.read_byte(src).ok_or_else(err)? as u8;
            d += 1;
            lostbit = 1;
        }
    }
    Ok((d, bits.s))
}

//! NRV2B/NRV2D/NRV2E decompression, ported from UCL `n2b_d.c`, `n2d_d.c` and
//! `n2e_d.c` (the decode semantics used by UPX). UPX uses three bit-buffer
//! granularities per algorithm: 8-bit, little-endian 16-bit and little-endian
//! 32-bit (`getbit_8`/`getbit_le16`/`getbit_le32` in `getbit.h`).
//!
//! All inputs are untrusted: every read and copy is bounds-checked and the
//! output size is fixed up front by the caller.

/// NRV algorithm family selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NrvAlgorithm {
    /// UCL nrv2b (`n2b_d.c`).
    B,
    /// UCL nrv2d (`n2d_d.c`): alternate offset coding, 0x500 threshold.
    D,
    /// UCL nrv2e (`n2e_d.c`): 2D offset coding plus different length tree.
    E,
}

/// Bit-buffer granularity used by the compressed stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitWidth {
    /// `getbit_8`: one byte at a time, sentinel-bit scheme.
    W8,
    /// `getbit_le16`: one little-endian u16 at a time, sentinel-bit scheme.
    Le16,
    /// `getbit_le32`: one little-endian u32 at a time, explicit bit counter.
    Le32,
}

/// Errors produced by the NRV decompressors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NrvError {
    /// Compressed input was exhausted where more bits/bytes were required.
    InputOverrun,
    /// Decompressed output would exceed the caller-provided buffer size.
    OutputOverrun,
    /// A match offset pointed before the start of the output.
    LookbehindOverrun,
    /// Decoding finished but input bytes remain unconsumed.
    InputNotConsumed,
}

impl core::fmt::Display for NrvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::InputOverrun => "input overrun",
            Self::OutputOverrun => "output overrun",
            Self::LookbehindOverrun => "lookbehind overrun",
            Self::InputNotConsumed => "input not consumed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for NrvError {}

/// Bit reader mirroring the `getbit` macros from UCL `getbit.h`. Owns the
/// shared input position: literal copies and bit refills advance the same
/// cursor exactly like the single `ilen` in the C original.
struct BitReader<'a> {
    src: &'a [u8],
    ilen: usize,
    /// Bit buffer; semantics depend on `width`.
    bb: u32,
    /// Remaining bits in `bb` (LE32 variant only).
    bc: u32,
    width: BitWidth,
}

impl<'a> BitReader<'a> {
    fn new(src: &'a [u8], width: BitWidth) -> Self {
        Self {
            src,
            ilen: 0,
            bb: 0,
            bc: 0,
            width,
        }
    }

    /// Reads the next bit, MSB-first within each loaded unit.
    ///
    /// Mirrors:
    /// - `getbit_8`:    `bb = bb&0x7f ? bb*2 : src[ilen++]*2+1; (bb>>8)&1`
    /// - `getbit_le16`: `bb*=2; bb&0xffff ? (bb>>16)&1 : refill16`
    /// - `getbit_le32`: `bc>0 ? (bb>>--bc)&1 : (bc=31; bb=le32; bb>>31)`
    #[inline]
    fn getbit(&mut self) -> Result<u32, NrvError> {
        match self.width {
            BitWidth::W8 => {
                self.bb = if self.bb & 0x7f != 0 {
                    self.bb << 1
                } else {
                    let byte = *self.src.get(self.ilen).ok_or(NrvError::InputOverrun)?;
                    self.ilen += 1;
                    (byte as u32) * 2 + 1
                };
                Ok((self.bb >> 8) & 1)
            }
            BitWidth::Le16 => {
                self.bb <<= 1;
                if self.bb & 0xffff != 0 {
                    return Ok((self.bb >> 16) & 1);
                }
                let lo = *self.src.get(self.ilen).ok_or(NrvError::InputOverrun)? as u32;
                let hi = *self.src.get(self.ilen + 1).ok_or(NrvError::InputOverrun)? as u32;
                self.ilen += 2;
                self.bb = (lo + hi * 256) * 2 + 1;
                Ok((self.bb >> 16) & 1)
            }
            BitWidth::Le32 => {
                if self.bc > 0 {
                    self.bc -= 1;
                    return Ok((self.bb >> self.bc) & 1);
                }
                self.bc = 31;
                let end = self.ilen.checked_add(4).ok_or(NrvError::InputOverrun)?;
                let chunk = self.src.get(self.ilen..end).ok_or(NrvError::InputOverrun)?;
                self.bb = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                self.ilen = end;
                Ok(self.bb >> 31)
            }
        }
    }

    /// Reads one raw byte (literal or low offset byte), advancing the shared
    /// input cursor.
    #[inline]
    fn getbyte(&mut self) -> Result<u32, NrvError> {
        let byte = *self.src.get(self.ilen).ok_or(NrvError::InputOverrun)?;
        self.ilen += 1;
        Ok(byte as u32)
    }
}

/// Decompresses an NRV stream into `dst`, which must already be sized to the
/// expected uncompressed length. Returns the number of bytes produced,
/// matching `*dst_len` semantics of `ucl_nrv2{b,d,e}_decompress_{8,le16,le32}`
/// SAFE variants: every bounds violation is an error instead of UB, and
/// success requires the input to be fully consumed.
pub fn nrv_decompress(
    src: &[u8],
    dst: &mut [u8],
    algorithm: NrvAlgorithm,
    width: BitWidth,
) -> Result<usize, NrvError> {
    let mut bits = BitReader::new(src, width);
    let mut olen = 0usize;
    let mut last_m_off: u32 = 1;
    let oend = dst.len();

    loop {
        // Literal run.
        while bits.getbit()? != 0 {
            let byte = bits.getbyte()? as u8;
            if olen >= oend {
                return Err(NrvError::OutputOverrun);
            }
            dst[olen] = byte;
            olen += 1;
        }

        // Match offset tree.
        let mut m_off: u32 = 1;
        if algorithm == NrvAlgorithm::B {
            // n2b_d.c: `do { m_off = m_off*2 + bit } while (!bit)`.
            loop {
                m_off = m_off.wrapping_mul(2).wrapping_add(bits.getbit()?);
                if m_off > 0xffffff + 3 {
                    return Err(NrvError::LookbehindOverrun);
                }
                if bits.getbit()? != 0 {
                    break;
                }
            }
        } else {
            // n2d_d.c / n2e_d.c interleaved low-bit coding.
            loop {
                m_off = m_off.wrapping_mul(2).wrapping_add(bits.getbit()?);
                if m_off > 0xffffff + 3 {
                    return Err(NrvError::LookbehindOverrun);
                }
                if bits.getbit()? != 0 {
                    break;
                }
                m_off = (m_off - 1) * 2 + bits.getbit()?;
            }
        }

        let mut m_len: u32;
        if m_off == 2 {
            // Repeat previous match distance.
            m_off = last_m_off;
            m_len = bits.getbit()?;
        } else {
            let low = bits.getbyte()?;
            m_off = (m_off - 3).wrapping_mul(256).wrapping_add(low);
            if m_off == 0xffff_ffff {
                break;
            }
            if algorithm == NrvAlgorithm::B {
                m_off += 1;
                last_m_off = m_off;
                m_len = bits.getbit()?;
            } else {
                m_len = !m_off & 1;
                m_off >>= 1;
                m_off += 1;
                last_m_off = m_off;
            }
        }

        // Match length tail. NRV2E has no shared `m_len*2+bit` step: the
        // initial m_len (repeat-path bit or inverted low offset bit) selects
        // the length tree directly.
        let threshold = if algorithm == NrvAlgorithm::B {
            0xd00
        } else {
            0x500
        };
        if algorithm == NrvAlgorithm::E {
            if m_len != 0 {
                m_len = 1 + bits.getbit()?;
            } else if bits.getbit()? != 0 {
                m_len = 3 + bits.getbit()?;
            } else {
                m_len += 1;
                loop {
                    m_len = m_len.wrapping_mul(2).wrapping_add(bits.getbit()?);
                    if m_len as usize >= oend {
                        return Err(NrvError::OutputOverrun);
                    }
                    if bits.getbit()? != 0 {
                        break;
                    }
                }
                m_len += 3;
            }
        } else {
            m_len = m_len.wrapping_mul(2).wrapping_add(bits.getbit()?);
            if m_len == 0 {
                m_len += 1;
                loop {
                    m_len = m_len.wrapping_mul(2).wrapping_add(bits.getbit()?);
                    if m_len as usize >= oend {
                        return Err(NrvError::OutputOverrun);
                    }
                    if bits.getbit()? != 0 {
                        break;
                    }
                }
                m_len += 2;
            }
        }
        m_len += u32::from(m_off > threshold);

        // Copy m_len + 1 bytes from earlier output (overlapping allowed).
        let count = m_len as usize + 1;
        if m_off as usize > olen {
            return Err(NrvError::LookbehindOverrun);
        }
        if olen + count > oend {
            return Err(NrvError::OutputOverrun);
        }
        for m_pos in (olen - m_off as usize..).take(count) {
            dst[olen] = dst[m_pos];
            olen += 1;
        }
    }

    if bits.ilen == src.len() {
        Ok(olen)
    } else if bits.ilen < src.len() {
        Err(NrvError::InputNotConsumed)
    } else {
        Err(NrvError::InputOverrun)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Stream-construction unit tests are impractical without an NRV
    // compressor; correctness coverage comes from real UPX-packed fixtures in
    // the integration tests, which validate the whole pipeline against the
    // pack header's Adler32 checksum and `upx -d` output.

    #[test]
    fn empty_input_fails() {
        let mut dst = [0u8; 4];
        assert!(nrv_decompress(&[], &mut dst, NrvAlgorithm::B, BitWidth::W8).is_err());
    }

    #[test]
    fn truncated_stream_fails() {
        let mut dst = [0u8; 16];
        assert!(nrv_decompress(&[0x80], &mut dst, NrvAlgorithm::B, BitWidth::W8).is_err());
        assert!(nrv_decompress(&[0x80], &mut dst, NrvAlgorithm::D, BitWidth::Le16).is_err());
        assert!(nrv_decompress(&[0x80, 0, 0], &mut dst, NrvAlgorithm::E, BitWidth::Le32).is_err());
    }

    #[test]
    fn zero_size_output_fails_on_literal() {
        // A literal bit with a zero-length destination must overrun.
        let mut dst = [];
        assert!(nrv_decompress(&[0xff; 64], &mut dst, NrvAlgorithm::B, BitWidth::W8).is_err());
    }
}

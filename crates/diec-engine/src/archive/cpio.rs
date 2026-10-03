//! CPIO record enumeration — port of upstream `xcpio.cpp::_parseRecord`
//! and `_scanArchive`.
//!
//! Five on-disk variants share one walker: `070701` (newc, 110-byte hex
//! header, 4-aligned data), `070702` (crc — same layout plus a data
//! checksum that is verified while listing), `070707` (odc, 76-byte
//! octal header), `070727` (afio large-ASCII header), and `0x71C7`
//! binary LE/BE (26-byte header, 2-aligned data).
//!
//! Enumeration only succeeds when a `TRAILER!!!` record with zero data
//! size is reached — upstream `_scanArchive` clears the record list
//! otherwise.

use super::SecondaryRecord;

const MODE_IFMT: u32 = 0o170000;
const MODE_IFDIR: u32 = 0o040000;
/// Upstream `CPIO_MAX_RECORDS`.
const MAX_RECORDS: usize = 0x100000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Newc,
    Crc,
    Odc,
    Afio,
    BinLe,
    BinBe,
}

/// `_detectFormat` at `off`.
fn detect(d: &[u8], off: usize) -> Option<Format> {
    if off >= d.len() {
        return None;
    }
    if d.len() - off >= 6 {
        match &d[off..off + 6] {
            b"070701" => return Some(Format::Newc),
            b"070702" => return Some(Format::Crc),
            b"070707" => return Some(Format::Odc),
            b"070727" => return Some(Format::Afio),
            _ => {}
        }
    }
    if d.len() - off >= 2 {
        let le = u16::from_le_bytes([d[off], d[off + 1]]);
        if le == 0x71C7 {
            return Some(Format::BinLe);
        }
        let be = u16::from_be_bytes([d[off], d[off + 1]]);
        if be == 0x71C7 {
            return Some(Format::BinBe);
        }
    }
    None
}

/// `_readHexValue`: strict hex field parse, -1 on bad digit/overflow.
fn hex(d: &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for &c in d {
        let digit = match c {
            b'0'..=b'9' => u64::from(c - b'0'),
            b'a'..=b'f' => u64::from(c - b'a' + 10),
            b'A'..=b'F' => u64::from(c - b'A' + 10),
            _ => return None,
        };
        v = v.checked_mul(16)?.checked_add(digit)?;
    }
    Some(v)
}

/// `_readOctValue`: strict octal field parse.
fn oct(d: &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for &c in d {
        if !(b'0'..=b'7').contains(&c) {
            return None;
        }
        v = v.checked_mul(8)?.checked_add(u64::from(c - b'0'))?;
    }
    Some(v)
}

fn rd16(d: &[u8], off: usize, be: bool) -> Option<u16> {
    let b: [u8; 2] = d.get(off..off + 2)?.try_into().ok()?;
    Some(if be {
        u16::from_be_bytes(b)
    } else {
        u16::from_le_bytes(b)
    })
}

/// `_readBinaryUInt32`: high/low u16 pair in the record's endianness.
fn rd32pair(d: &[u8], off: usize, be: bool) -> Option<u32> {
    let hi = rd16(d, off, be)? as u32;
    let lo = rd16(d, off + 2, be)? as u32;
    Some((hi << 16) | lo)
}

struct Info {
    name: String,
    mode: u32,
    data_off: usize,
    data_size: usize,
    next: usize,
}

/// `_parseRecord` for one entry at `off`.
fn parse(d: &[u8], off: usize) -> Option<Info> {
    let fmt = detect(d, off)?;
    let total = d.len();
    let (name_size, data_size, mode, _mtime, hdr_size, expect_check) = match fmt {
        Format::Newc | Format::Crc => {
            let h = d.get(off..off + 110)?;
            // Every fixed field must be valid hex (upstream checks all 13).
            let fields: [std::ops::Range<usize>; 13] = [
                6..14,
                14..22,
                22..30,
                30..38,
                38..46,
                46..54,
                54..62,
                62..70,
                70..78,
                78..86,
                86..94,
                94..102,
                102..110,
            ];
            for f in &fields {
                hex(&h[f.clone()])?;
            }
            (
                hex(&h[94..102])? as usize,
                hex(&h[54..62])? as usize,
                hex(&h[14..22])? as u32,
                hex(&h[46..54])?,
                110,
                if fmt == Format::Crc {
                    hex(&h[102..110])
                } else {
                    Some(0)
                },
            )
        }
        Format::Odc => {
            // magic(6) dev(6) ino(6) mode(6) uid(6) gid(6) nlink(6)
            // rdev(6) mtime(11) namesize(6) filesize(11) = 76 bytes.
            let h = d.get(off..off + 76)?;
            // Validate all octal fields like upstream does.
            oct(&h[6..12])?;
            oct(&h[12..18])?;
            oct(&h[24..30])?;
            oct(&h[30..36])?;
            oct(&h[36..42])?;
            oct(&h[42..48])?;
            (
                oct(&h[59..65])? as usize,
                oct(&h[65..76])? as usize,
                oct(&h[18..24])? as u32,
                oct(&h[48..59])?,
                76,
                Some(0),
            )
        }
        Format::Afio => {
            // magic(6) dev(8) ino(16) 'm' mode(6) uid(8) gid(8)
            // nlink(8) rdev(8) mtime(16) 'n' namesize(4) flag(4)
            // xsize(4) 's' filesize(16) ':' = 116 bytes.
            let h = d.get(off..off + 116)?;
            if h[30] != b'm' || h[85] != b'n' || h[98] != b's' || h[115] != b':' {
                return None;
            }
            // Validate all numeric fields like upstream does.
            hex(&h[6..14])?;
            hex(&h[14..30])?;
            hex(&h[37..45])?;
            hex(&h[45..53])?;
            hex(&h[53..61])?;
            hex(&h[61..69])?;
            hex(&h[90..94])?;
            hex(&h[94..98])?;
            (
                hex(&h[86..90])? as usize,
                hex(&h[99..115])? as usize,
                oct(&h[31..37])? as u32,
                hex(&h[69..85])?,
                116,
                Some(0),
            )
        }
        Format::BinLe | Format::BinBe => {
            let be = fmt == Format::BinBe;
            if off.checked_add(26)? > total {
                return None;
            }
            // magic dev ino mode uid gid nlink rdev mtimeHigh mtimeLow
            // namesize filesizeHigh filesizeLow = 26 bytes.
            (
                rd16(d, off + 20, be)? as usize,
                rd32pair(d, off + 22, be)? as usize,
                u32::from(rd16(d, off + 6, be)?),
                u64::from(rd32pair(d, off + 16, be)?),
                26,
                Some(0),
            )
        }
    };

    if name_size == 0 || name_size > 0x10000 {
        return None;
    }
    let name_off = off.checked_add(hdr_size)?;
    if name_size > total.checked_sub(name_off)? {
        return None;
    }
    let name_raw = d.get(name_off..name_off + name_size)?;
    if name_raw.is_empty() || *name_raw.last().unwrap() != 0 {
        return None;
    }
    let name_body = &name_raw[..name_raw.len() - 1];
    if name_body.contains(&0) {
        return None;
    }
    let name = String::from_utf8_lossy(name_body).into_owned();

    let mut data_off = name_off + name_size;
    if matches!(fmt, Format::Newc | Format::Crc) {
        data_off = data_off.checked_add(3)? & !3;
    } else if matches!(fmt, Format::BinLe | Format::BinBe) {
        data_off = data_off.checked_add(1)? & !1;
    }
    if data_off > total || data_size > total - data_off {
        return None;
    }
    let mut next = data_off.checked_add(data_size)?;
    if matches!(fmt, Format::Newc | Format::Crc) {
        next = next.checked_add(3)? & !3;
    } else if matches!(fmt, Format::BinLe | Format::BinBe) {
        next = next.checked_add(1)? & !1;
    }
    if next <= off || next > total {
        return None;
    }

    // CRC format verifies the data checksum while walking (upstream).
    if fmt == Format::Crc {
        let want = expect_check?;
        let sum: u64 = d[data_off..data_off + data_size]
            .iter()
            .map(|&b| u64::from(b))
            .sum();
        if sum != want {
            return None;
        }
    }

    Some(Info {
        name,
        mode,
        data_off,
        data_size,
        next,
    })
}

/// `XCPIO::isValid` — first record parses (trailer check happens in
/// `list`, matching `_scanArchive`).
pub fn is_cpio(d: &[u8]) -> bool {
    !d.is_empty() && parse(d, 0).is_some()
}

/// `_scanArchive`: walk records until the `TRAILER!!!` terminator;
/// without it the archive is rejected entirely.
pub fn list(d: &[u8]) -> Option<Vec<SecondaryRecord>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut saw_trailer = false;
    while off < d.len() {
        let info = match parse(d, off) {
            Some(i) => i,
            None => break,
        };
        if info.name == "TRAILER!!!" {
            if info.data_size != 0 {
                break;
            }
            saw_trailer = true;
            break;
        }
        if out.len() >= MAX_RECORDS {
            break;
        }
        out.push(SecondaryRecord {
            is_directory: (info.mode & MODE_IFMT) == MODE_IFDIR || info.name.ends_with('/'),
            name: info.name,
            size: info.data_size as u64,
            packed_size: info.data_size as u64,
            // Upstream records do not surface mtime in the member list.
            modified: None,
            data_offset: info.data_off as u64,
            method: 0,
        });
        off = info.next;
    }
    saw_trailer.then_some(out)
}

//! Port of `NFDArchiveHeaders` — structural validators for archive
//! formats whose headers carry CRCs or checksums strong enough to claim
//! a detection without a full parse: 7z, RAR (1.5-4.x and 5.x), LHA,
//! tar, plus the compressed-stream headers compress(.Z), LZIP and lzop.
//!
//! Every record emitted here is `RECORD_TYPE_FORMAT` inserted into
//! `mapResultArchives` with `id.fileType = FT_ARCHIVE`.

use crate::gen_names::{ft, name as n, rtype as rt};
use crate::scans::{ResultMaps, ScanRecord};

fn byte(d: &[u8], off: usize) -> u8 {
    d.get(off).copied().unwrap_or(0)
}
fn le16(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([byte(d, off), byte(d, off + 1)])
}
fn le32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([
        byte(d, off),
        byte(d, off + 1),
        byte(d, off + 2),
        byte(d, off + 3),
    ])
}
fn le64(d: &[u8], off: usize) -> u64 {
    let lo = le32(d, off) as u64;
    let hi = le32(d, off + 4) as u64;
    (hi << 32) | lo
}
fn be16(d: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([byte(d, off), byte(d, off + 1)])
}
fn be32(d: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([
        byte(d, off),
        byte(d, off + 1),
        byte(d, off + 2),
        byte(d, off + 3),
    ])
}

/// `XBinary::_getCRC32` with the EDB88320 table — standard zlib CRC32.
fn crc32(d: &[u8]) -> u32 {
    crc32fast::hash(d)
}

/// `getScansStruct` + `scansToScan` + insert into `mapResultArchives`.
fn add(
    res: &mut ResultMaps,
    name: u16,
    version: &str,
    detail: &str,
    sname: Option<&'static str>,
) -> bool {
    let mut rec = ScanRecord {
        name,
        rtype: rt::RECORD_TYPE_FORMAT,
        ft: ft::FT_ARCHIVE,
        variant: 0,
        version: version.to_string(),
        info: detail.to_string(),
        heuristic: false,
        unknown: false,
        sname: sname.map(std::borrow::Cow::Borrowed),
        stype: None,
    };
    rec.ft = ft::FT_ARCHIVE;
    res.archives.insert(rec.name, rec);
    true
}

/// LEB128-style vint reader used by RAR5 header fields.
fn vint(d: &[u8], off: &mut usize, value: &mut u64) -> bool {
    *value = 0;
    for i in 0..10 {
        if *off >= d.len() {
            return false;
        }
        let ch = byte(d, *off);
        *off += 1;
        if i == 9 && ch > 1 {
            return false;
        }
        *value |= u64::from(ch & 0x7f) << (7 * i);
        if ch & 0x80 == 0 {
            return true;
        }
    }
    false
}

/// LHA/LZH (`-lhX-`/`-pmX-`/`-lzs-`...) header validation with level-0..3
/// extended-header walk.
fn lha(d: &[u8], header: &[u8], res: &mut ResultMaps) -> bool {
    if header.len() < 24 {
        return false;
    }
    let method = &header[2..7];
    let pma = method == b"-pm0-" || method == b"-pm1-" || method == b"-pm2-";
    let lh = method.len() == 5
        && method.starts_with(b"-lh")
        && method.ends_with(b"-")
        && b"0123456789abcdex".contains(&method[3]);
    let lz = method == b"-lzs-" || method == b"-lz4-" || method == b"-lz5-";
    if !pma && !lh && !lz {
        return false;
    }
    let level = byte(header, 20);
    if level > 3 || (pma && level != 0) {
        return false;
    }
    let mut header_size = if level < 2 {
        u64::from(byte(header, 0)) + 2
    } else {
        u64::from(le16(header, 0))
    };
    if level == 3 {
        if header.len() < 32 || le16(header, 0) != 4 {
            return false;
        }
        header_size = u64::from(le32(header, 24));
    }
    // LHA for OS-9/68k excludes its first two bytes from the size field.
    if level == 2 && byte(header, 23) == b'K' {
        header_size += 2;
    }
    let minimum: u64 = match level {
        0 => 24,
        1 => 27,
        2 => 26,
        _ => 32,
    };
    let size = d.len() as u64;
    if header_size < minimum
        || header_size > 1024 * 1024
        || header_size > size
        || u64::from(le32(header, 7)) > size - header_size
    {
        return false;
    }
    let full = &d[..header_size as usize];
    if level < 2 {
        let sum: u32 = full[2..].iter().map(|&b| u32::from(b)).sum();
        if (sum & 0xff) != u32::from(byte(full, 1)) || byte(full, 21) as u64 > header_size - minimum
        {
            return false;
        }
    } else {
        // Extended headers carry their own length; require the terminator
        // inside the declared header, never walk packed file data.
        let mut pos: usize = if level == 2 { 24 } else { 28 };
        let width = if level == 2 { 2 } else { 4 };
        loop {
            if pos > full.len().saturating_sub(width) {
                return false;
            }
            let length = if width == 2 {
                u32::from(le16(full, pos))
            } else {
                le32(full, pos)
            };
            if length == 0 {
                break;
            }
            if length < (width + 1) as u32 || length as usize > full.len() - pos {
                return false;
            }
            pos += length as usize;
        }
    }
    let name = if pma {
        n::RECORD_NAME_UNKNOWN
    } else {
        n::RECORD_NAME_LHA
    };
    let sname = if pma { Some("PMA") } else { None };
    add(
        res,
        name,
        "",
        &format!(
            "header level {}, method {}",
            level,
            String::from_utf8_lossy(method)
        ),
        sname,
    )
}

/// 7z start-header CRC + optional next-header CRC verification.
fn seven_zip(d: &[u8], header: &[u8], res: &mut ResultMaps) -> bool {
    if header.len() < 32 || header[..6] != [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return false;
    }
    if crc32(&header[12..32]) != le32(header, 8) {
        return false;
    }
    let next_off = le64(header, 12);
    let next_size = le64(header, 20);
    let available = d.len() as u64 - 32;
    let detail: String;
    if next_off > available || next_size > available - next_off {
        detail = "start header CRC verified; next header outside this file".to_string();
    } else if next_size <= 1024 * 1024 {
        let next = &d[32 + next_off as usize..32 + (next_off + next_size) as usize];
        if crc32(next) != le32(header, 28) {
            return false;
        }
        detail = if next_size != 0 {
            "header CRC verified".to_string()
        } else {
            "empty archive".to_string()
        };
    } else {
        detail = "start header CRC verified".to_string();
    }
    add(
        res,
        n::RECORD_NAME_7Z,
        &format!("{}.{}", byte(header, 6), byte(header, 7)),
        &detail,
        None,
    )
}

/// RAR 1.5-4.x (`Rar!\x1A\x07\x00`) main-header CRC, and RAR5
/// (`Rar!\x1A\x07\x01\x00`) block CRC + structure walk.
fn rar(d: &[u8], header: &[u8], res: &mut ResultMaps) -> bool {
    if header.len() >= 20 && header[..7] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] {
        let flags = le16(header, 10);
        let size = le16(header, 12) as usize;
        if byte(header, 9) != 0x73 || size < 13 || size as u64 > d.len() as u64 - 7 {
            return false;
        }
        // RAR <=2.9 embeds comments in HEAD_SIZE but excludes them from
        // the main header CRC (UnRAR arcread.cpp).
        let checked = if flags & 2 != 0 { 13 } else { size };
        let main = &d[9..9 + checked - 2];
        if (crc32(main) & 0xffff) != u32::from(le16(header, 7)) {
            return false;
        }
        let mut detail = "archive header CRC verified".to_string();
        if flags & 1 != 0 {
            detail += ", volume";
        }
        if flags & 0x80 != 0 {
            detail += ", encrypted headers";
        }
        return add(res, n::RECORD_NAME_RAR, "1.5-4.x", &detail, None);
    }
    if header.len() >= 15 && header[..8] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00] {
        let mut pos = 12usize;
        let mut size = 0u64;
        if !vint(header, &mut pos, &mut size)
            || !(3..=1024 * 1024).contains(&size)
            || size > d.len() as u64 - pos as u64
        {
            return false;
        }
        let block = &d[12..pos + size as usize];
        if crc32(block) != le32(header, 8) {
            return false;
        }
        let mut cursor = pos - 12;
        let mut btype = 0u64;
        let mut flags = 0u64;
        let mut extra_size = 0u64;
        let mut data_size = 0u64;
        if !vint(block, &mut cursor, &mut btype)
            || (btype != 1 && btype != 4)
            || !vint(block, &mut cursor, &mut flags)
        {
            return false;
        }
        if flags & 1 != 0 && !vint(block, &mut cursor, &mut extra_size) {
            return false;
        }
        if flags & 2 != 0 && !vint(block, &mut cursor, &mut data_size) {
            return false;
        }
        if extra_size > (block.len() - cursor) as u64 {
            return false;
        }
        let body = &block[..block.len() - extra_size as usize];
        let mut value = 0u64;
        if !vint(body, &mut cursor, &mut value) {
            return false;
        }
        if btype == 1 {
            if value & 2 != 0 && !vint(body, &mut cursor, &mut value) {
                return false;
            }
        } else {
            if value != 0 || !vint(body, &mut cursor, &mut value) {
                return false;
            }
            let required = 17 + if value & 1 != 0 { 12 } else { 0 };
            if body.len() - cursor < required {
                return false;
            }
        }
        if data_size > d.len() as u64 - 12 - block.len() as u64 {
            return false;
        }
        return add(
            res,
            n::RECORD_NAME_RAR,
            "5.0",
            if btype == 4 {
                "RAR5 format; encrypted archive header CRC verified"
            } else {
                "RAR5 format; archive header CRC verified"
            },
            None,
        );
    }
    false
}

/// tar checksum validation over the first 512-byte block plus ustar/
/// GNU/pax flavour detection.
fn tar(header: &[u8], res: &mut ResultMaps) -> bool {
    if header.len() < 512 || byte(header, 0) == 0 {
        return false;
    }
    let mut field = header[148..156].to_vec();
    for b in field.iter_mut() {
        if *b == 0 {
            *b = b' ';
        }
    }
    // The checksum field is octal ASCII.
    let s = String::from_utf8_lossy(&field);
    let Ok(expected) = u32::from_str_radix(s.trim(), 8) else {
        return false;
    };
    let (mut sum, mut signed_sum) = (0u32, 0i64);
    for i in 0..512 {
        let ch = if (148..156).contains(&i) {
            32u8
        } else {
            byte(header, i)
        };
        sum += u32::from(ch);
        signed_sum += if ch < 128 { ch as i64 } else { ch as i64 - 256 };
    }
    if expected != sum && (signed_sum < 0 || expected != signed_sum as u32) {
        return false;
    }
    let magic6 = &header[257..263];
    let detail = if magic6 == b"ustar\0" {
        if byte(header, 156) == b'x' || byte(header, 156) == b'g' {
            "POSIX pax header"
        } else {
            "POSIX ustar header"
        }
    } else if magic6 == b"ustar " {
        "GNU header"
    } else if magic6 == [0u8; 6] {
        "V7 header"
    } else {
        return false;
    };
    add(res, n::RECORD_NAME_TAR, "", detail, None)
}

/// lzop "9.4x"-style BCD version formatting (`versionText`).
fn version_text(number: u16) -> String {
    let mut text = format!("{}.{:02x}", number >> 12, (number >> 4) & 0xff);
    if number & 15 != 0 {
        text += &format!(".{}", number & 15);
    }
    text
}

/// compress(.Z) / LZIP / lzop stream headers.
fn compression(d: &[u8], header: &[u8], res: &mut ResultMaps) -> bool {
    if header.len() >= 6 && header[..2] == [0x1F, 0x9D] {
        let flags = byte(header, 2);
        let bits = flags & 0x1f;
        if flags & 0x60 == 0 && (9..=16).contains(&bits) && byte(header, 4) & 1 == 0 {
            return add(
                res,
                n::RECORD_NAME_UNKNOWN,
                "",
                &format!(
                    "LZW, {}-bit maximum{}",
                    bits,
                    if flags & 0x80 != 0 {
                        ", block mode"
                    } else {
                        ""
                    }
                ),
                Some("compress (Z)"),
            );
        }
    }
    if header.len() >= 36 && header[..4] == *b"LZIP" && byte(header, 4) == 1 {
        let bits = byte(header, 5) & 31;
        if !(12..=29).contains(&bits) || byte(header, 6) != 0 {
            return false;
        }
        if d.len() < 20 {
            return false;
        }
        let trailer = &d[d.len() - 20..];
        let member_size = le64(trailer, 12);
        if member_size < 36 || member_size > d.len() as u64 {
            return false;
        }
        let last = &d[d.len() - member_size as usize..][..6];
        if last[..4] != *b"LZIP" || byte(last, 4) != 1 {
            return false;
        }
        return add(
            res,
            n::RECORD_NAME_LZIP,
            "1",
            "member header and trailer",
            Some("LZIP"),
        );
    }
    if header.len() >= 31 && header[..9] == [0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A] {
        let version = be16(header, 9);
        if version < 0x900 {
            return false;
        }
        let mut pos = if version >= 0x940 { 15 } else { 13 };
        if version >= 0x940 && be16(header, 13) < 0x900 {
            return false;
        }
        let method = byte(header, pos);
        pos += 1;
        if !(1..=3).contains(&method) {
            return false;
        }
        if version >= 0x940 {
            if byte(header, pos) > 9 {
                return false;
            }
            pos += 1;
        }
        if pos > header.len() - 4 {
            return false;
        }
        let flags = be32(header, pos) as usize;
        pos += 4;
        if flags & 0x800 != 0 {
            pos += 4;
        }
        pos += if version >= 0x940 { 12 } else { 8 };
        if pos >= header.len() {
            return false;
        }
        let end = pos + 1 + byte(header, pos) as usize;
        if end + 4 < 9 || d.len() < end + 4 {
            return false;
        }
        let full = &d[9..end + 4];
        let checked = &full[..full.len() - 4];
        let checksum = if flags & 0x1000 != 0 {
            crc32(checked)
        } else {
            // Adler-32
            let (mut a, mut b) = (1u32, 0u32);
            for &ch in checked {
                a = (a + u32::from(ch)) % 65521;
                b = (b + a) % 65521;
            }
            (b << 16) | a
        };
        if checksum != be32(full, full.len() - 4) {
            return false;
        }
        let mut detail = format!(
            "header checksum verified, method {}, writer {}, LZO library {}",
            method,
            version_text(version),
            version_text(be16(header, 11))
        );
        if version >= 0x940 {
            detail += &format!(", minimum reader {}", version_text(be16(header, 13)));
        }
        return add(res, n::RECORD_NAME_UNKNOWN, "", &detail, Some("lzop"));
    }
    false
}

/// `NFDArchiveHeaders::detect` — try every structural validator in
/// upstream order; the first success wins.
pub fn detect(d: &[u8], res: &mut ResultMaps) -> bool {
    if d.is_empty() {
        return false;
    }
    let header = &d[..d.len().min(512)];
    seven_zip(d, header, res)
        || rar(d, header, res)
        || lha(d, header, res)
        || tar(header, res)
        || compression(d, header, res)
}

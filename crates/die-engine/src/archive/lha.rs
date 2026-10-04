//! LHA/LZH record enumeration — port of upstream `xlha.cpp::_readMember`.
//!
//! Member headers carry no magic of their own; a header starts with a
//! `-lh?-` / `-lz?-` / `-pm?-` method tag at offset 2 and is bound-checked
//! per level (0/1 byte-sized, 2/3 word-sized). Level 0/1 headers are
//! additionally gated by their own checksum byte, which is what makes the
//! signature-free container safe to claim (mirrors upstream).
//!
//! Level 1's declared packed size includes the extended-header chain, so
//! the chain length is subtracted to get the data-stream length.

use super::SecondaryRecord;

/// Smallest header the member parser accepts (`nFileSize - nOffset >= 22`).
const MIN_HEADER: usize = 22;
/// Extended/base header bound (upstream `nHeaderLimit`).
const HEADER_LIMIT: usize = 1024 * 1024;
/// Enumeration bound.
const MAX_ENTRIES: usize = 10000;

fn rd16(d: &[u8], off: usize) -> u16 {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

fn rd32(d: &[u8], off: usize) -> u32 {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

/// `_isMemberTag`: `-lh`/`-lz`/`-pm` at offset 2 and `-` at offset 6.
fn is_member_tag(d: &[u8]) -> bool {
    d.len() >= 21 && matches!(&d[2..5], b"-lh" | b"-lz" | b"-pm") && d[6] == b'-'
}

/// `_isHeaderChecksumValid` for level 0/1 headers.
fn header_checksum_ok(d: &[u8]) -> bool {
    if d.len() < 3 {
        return false;
    }
    let n = d[0] as usize;
    if n < 2 || d.len() < 2 + n {
        return false;
    }
    let sum: u32 = d[2..2 + n].iter().map(|&b| u32::from(b)).sum();
    (sum & 0xff) == u32::from(d[1])
}

struct Member {
    header_size: usize,
    compressed: usize,
    original: u32,
    directory: bool,
    method: [u8; 5],
    name: String,
}

/// `_readMember`: parse one member header; returns `None` on any bounds
/// or consistency violation (upstream returns false the same way).
fn read_member(d: &[u8], off: usize) -> Option<Member> {
    if off.checked_add(MIN_HEADER)? > d.len() {
        return None;
    }
    let prefix = d.get(off..off.checked_add(32)?.min(d.len()))?;
    if prefix.len() < MIN_HEADER || !is_member_tag(prefix) {
        return None;
    }

    let level = prefix[20];
    let method: [u8; 5] = prefix[2..7].try_into().ok()?;
    let mut compressed = rd32(prefix, 7) as usize;
    let original = rd32(prefix, 11);

    let base = match level {
        0 | 1 => {
            let b = prefix[0] as usize + 2;
            if b < if level == 0 { 24 } else { 27 } {
                return None;
            }
            b
        }
        2 => {
            if prefix.len() < 26 {
                return None;
            }
            let mut b = rd16(prefix, 0) as usize;
            if b < 26 {
                return None;
            }
            if prefix[23] == b'K' {
                b += 2;
            }
            b
        }
        3 => {
            if prefix.len() < 32 || rd16(prefix, 0) != 4 {
                return None;
            }
            let b = rd32(prefix, 24) as usize;
            if b < 32 {
                return None;
            }
            b
        }
        _ => return None,
    };
    if base > HEADER_LIMIT || base > d.len() - off {
        return None;
    }
    let mut header = d.get(off..off + base)?.to_vec();

    let mut name: Vec<u8> = Vec::new();
    let mut path: Vec<u8> = Vec::new();
    let mut ext_pos: i64 = -1;
    let mut unix_mode = 0u16;
    let mut n_os = 0u8;

    if level <= 1 {
        if !header_checksum_ok(&header) {
            return None;
        }
        let name_len = header[21] as usize;
        let min_fixed = if level == 0 { 24 } else { 27 };
        if min_fixed + name_len > base {
            return None;
        }
        name = header[22..22 + name_len].to_vec();
        if level == 1 {
            n_os = header[24 + name_len];
            ext_pos = (base - 2) as i64;
            // Level 1: extended headers follow the base header inside the
            // declared packed size; fold them into the header.
            let mut ext_total = 0usize;
            loop {
                let next = rd16(&header, header.len() - 2) as usize;
                if next == 0 {
                    break;
                }
                if next < 3
                    || next > HEADER_LIMIT - header.len()
                    || next > compressed.saturating_sub(ext_total)
                    || next > d.len() - off - header.len()
                {
                    return None;
                }
                let extra = d.get(off + header.len()..off + header.len() + next)?;
                header.extend_from_slice(extra);
                ext_total += next;
            }
            compressed = compressed.checked_sub(ext_total)?;
        }
    } else {
        n_os = header[23];
        ext_pos = if level == 2 { 24 } else { 28 };
    }

    // Extended-header chain (levels 1/2/3): word-sized entries, type byte
    // 0=common CRC / 1=filename / 2=dirname (0xff→'/') / 0x50=unix mode /
    // 0x42=large-file sizes (must agree with the 32-bit fields).
    let mut common_crc_off = -1i64;
    if ext_pos >= 0 {
        let word = if level == 3 { 4usize } else { 2 };
        let mut pos = ext_pos as usize;
        loop {
            if pos > header.len().saturating_sub(word) {
                return None;
            }
            let ext_size = if word == 4 {
                rd32(&header, pos) as usize
            } else {
                rd16(&header, pos) as usize
            };
            if ext_size == 0 {
                break;
            }
            if ext_size < word + 1 || ext_size > header.len() - pos - word {
                return None;
            }
            let ty = header[pos + word];
            let data_pos = pos + word + 1;
            let data_size = ext_size - word - 1;
            match ty {
                0 => {
                    if data_size < 2 || common_crc_off >= 0 {
                        return None;
                    }
                    common_crc_off = data_pos as i64;
                }
                1 => name = header[data_pos..data_pos + data_size].to_vec(),
                2 => {
                    path = header[data_pos..data_pos + data_size]
                        .iter()
                        .map(|&b| if b == 0xff { b'/' } else { b })
                        .collect();
                    if !path.is_empty() && *path.last().unwrap() != b'/' {
                        path.push(b'/');
                    }
                }
                0x50 => {
                    if data_size < 2 {
                        return None;
                    }
                    unix_mode = rd16(&header, data_pos);
                }
                0x42 if data_size < 16
                    || rd32(&header, data_pos + 4) != 0
                    || rd32(&header, data_pos + 12) != 0
                    || rd32(&header, data_pos) != compressed as u32
                    || rd32(&header, data_pos + 8) != original =>
                {
                    return None;
                }
                _ => {}
            }
            pos += ext_size;
        }
    }
    if common_crc_off >= 0 {
        let pos = common_crc_off as usize;
        let want = rd16(&header, pos);
        let mut hdr = header.clone();
        hdr[pos] = 0;
        hdr[pos + 1] = 0;
        let mut crc = 0u16;
        for &b in &hdr {
            crc ^= u16::from(b);
            for _ in 0..8 {
                crc = (crc >> 1) ^ if crc & 1 != 0 { 0xa001 } else { 0 };
            }
        }
        if crc != want {
            return None;
        }
    }

    let header_size = header.len();
    if compressed > d.len() - off - header_size {
        return None;
    }
    // MorphOS quirk: a NUL inside the declared filename ends the name.
    if let Some(end) = name.iter().position(|&b| b == 0) {
        name.truncate(end);
    }
    if path.contains(&0) {
        return None;
    }
    let mut full = path;
    full.extend_from_slice(&name);
    let name = String::from_utf8_lossy(&full).replace('\\', "/");
    let directory = &method == b"-lhd-" && (unix_mode & 0o170000) != 0o120000;
    if name.is_empty() && !directory {
        return None;
    }
    // LHARK: level-1 OS 0x20 -lh7- uses a different bitstream; the method
    // tag is remapped so extraction dispatch can distinguish it.
    let method = if level == 1 && n_os == 0x20 && &method == b"-lh7-" {
        *b"-lk7-"
    } else {
        method
    };
    Some(Member {
        header_size,
        compressed,
        original,
        directory,
        method,
        name,
    })
}

/// `XLHA::isValid` member-tag gate (first member parses at offset 0).
/// PMA SFX envelopes (`-pms-` with a stub) are out of scope for the plain
/// listing path — upstream handles them via `lhaFirstMemberOffset`.
pub fn is_lha(d: &[u8]) -> bool {
    read_member(d, 0).is_some()
}

/// Enumerate LHA members (upstream `_readMember` walk from offset 0).
pub fn list(d: &[u8]) -> Option<Vec<SecondaryRecord>> {
    if !is_lha(d) {
        return None;
    }
    let mut out = Vec::new();
    let mut off = 0usize;
    while out.len() < MAX_ENTRIES {
        let m = match read_member(d, off) {
            Some(m) => m,
            None => break,
        };
        out.push(SecondaryRecord {
            name: m.name,
            size: u64::from(m.original),
            packed_size: m.compressed as u64,
            is_directory: m.directory,
            modified: None,
            data_offset: (off + m.header_size) as u64,
            // First 4 tag bytes: "-lh0"/"-lhd"/"-lz4" etc.
            method: u32::from_be_bytes(m.method[..4].try_into().unwrap()),
            window_size: 0,
        });
        let next = off.checked_add(m.header_size)?.checked_add(m.compressed)?;
        if next <= off {
            break;
        }
        off = next;
    }
    Some(out)
}

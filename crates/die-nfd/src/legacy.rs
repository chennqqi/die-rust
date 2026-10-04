//! Port of `NFDLegacy` — validators for legacy/wrapper formats:
//! MacBinary, AppleSingle/Double, BinHex 4.0, uuencode, Microsoft
//! SZDD/KWAJ compression, ARC, ARJ, ZOO, LZX, DMS, Disk Doubler and
//! StuffIt/StuffIt X.
//!
//! Wrapper formats (`wrapper = true`) land in `mapResultFormats`; plain
//! archives go to `mapResultArchives`. Non-wrapper hits also set
//! `id.fileType = FT_ARCHIVE` upstream — the caller tracks that through
//! the return value when needed.

use std::collections::HashSet;

use crate::gen_names::{ft, name as n, rtype as rt};
use crate::scans::{ResultMaps, ScanRecord};

/// Recognition budgets, independent of declared payload size.
const MAX_READ: u64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 16384;

fn within(total: u64, offset: u64, length: u64) -> bool {
    offset <= total && length <= total - offset
}

/// Bounded reader over the input buffer (the QIODevice `Reader` in
/// upstream — the buffer variant needs no seeking or position guard).
struct Reader<'a> {
    d: &'a [u8],
    budget: u64,
}

impl<'a> Reader<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self {
            d,
            budget: MAX_READ,
        }
    }
    fn size(&self) -> u64 {
        self.d.len() as u64
    }
    fn read(&mut self, offset: u64, length: u64) -> Option<&'a [u8]> {
        if !within(self.size(), offset, length) || length > self.budget {
            return None;
        }
        self.budget -= length;
        Some(&self.d[offset as usize..(offset + length) as usize])
    }
}

fn u8at(b: &[u8], n: usize) -> u8 {
    b.get(n).copied().unwrap_or(0)
}
fn be16(b: &[u8], n: usize) -> u16 {
    u16::from_be_bytes([u8at(b, n), u8at(b, n + 1)])
}
fn be32(b: &[u8], n: usize) -> u32 {
    u32::from_be_bytes([u8at(b, n), u8at(b, n + 1), u8at(b, n + 2), u8at(b, n + 3)])
}
fn le16(b: &[u8], n: usize) -> u16 {
    u16::from_le_bytes([u8at(b, n), u8at(b, n + 1)])
}
fn le32(b: &[u8], n: usize) -> u32 {
    u32::from_le_bytes([u8at(b, n), u8at(b, n + 1), u8at(b, n + 2), u8at(b, n + 3)])
}

/// CRC16 — CCITT (poly 0x1021, MSB-first) or ARC-style (0xA001,
/// LSB-first).
fn crc16(b: &[u8], start: usize, length: usize, ccitt: bool) -> u16 {
    let mut crc = 0u32;
    for i in start..start + length {
        if ccitt {
            crc ^= u32::from(u8at(b, i)) << 8;
            for _ in 0..8 {
                crc = ((crc << 1) ^ if crc & 0x8000 != 0 { 0x1021 } else { 0 }) & 0xffff;
            }
        } else {
            crc ^= u32::from(u8at(b, i));
            for _ in 0..8 {
                crc = (crc >> 1) ^ if crc & 1 != 0 { 0xa001 } else { 0 };
            }
        }
    }
    crc as u16
}

fn crc32(b: &[u8]) -> u32 {
    crc32fast::hash(b)
}

fn padded(n: u64) -> u64 {
    (n + 127) & !127
}

#[derive(Default)]
struct Result {
    name: String,
    version: String,
    info: String,
    record: u16,
    wrapper: bool,
}

/// MacBinary I/II/III — reserved-byte rules plus fork framing.
fn mac_binary(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 128
        || u8at(h, 0) != 0
        || u8at(h, 74) != 0
        || u8at(h, 82) != 0
        || u8at(h, 1) < 1
        || u8at(h, 1) > 63
    {
        return false;
    }
    let version = u8at(h, 122);
    let minimum = u8at(h, 123);
    match version {
        0 => {
            // MacBinary I has no magic or CRC; require reserved/name
            // padding and exact fork framing.
            if minimum != 0 || be16(h, 124) != 0 {
                return false;
            }
            for i in 2 + u8at(h, 1) as usize..65 {
                if u8at(h, i) != 0 {
                    return false;
                }
            }
            if h[101..128].iter().any(|&b| b != 0) {
                return false;
            }
        }
        129 => {
            if minimum != 129 || be16(h, 124) != crc16(h, 0, 124, true) {
                return false;
            }
        }
        130 => {
            if h[102..106] != *b"mBIN"
                || ![0, 129, 130].contains(&minimum)
                || be16(h, 124) != crc16(h, 0, 124, true)
            {
                return false;
            }
        }
        _ => return false,
    }
    let data = u64::from(be32(h, 83));
    let resource = u64::from(be32(h, 87));
    let comment = u64::from(be16(h, 99));
    let secondary = u64::from(be16(h, 120));
    if data == 0 && resource == 0 && comment == 0 {
        return false;
    }
    let end = 128 + padded(secondary) + padded(data) + padded(resource) + padded(comment);
    if end != r.size() {
        return false;
    }
    out.name = "MacBinary".to_string();
    out.version = match version {
        0 => "I",
        129 => "II",
        _ => "III",
    }
    .to_string();
    out.wrapper = true;
    true
}

/// AppleSingle/AppleDouble — directory entry walk with overlap checks.
fn apple_single(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 26 || (be32(h, 0) != 0x00051600 && be32(h, 0) != 0x00051607) {
        return false;
    }
    let version = be32(h, 4);
    let count = be16(h, 24) as usize;
    if ![0x00010000, 0x00020000].contains(&version) || !(1..=4096).contains(&count) {
        return false;
    }
    let floor = (26 + count * 12) as u64;
    let directory = match r.read(26, (count * 12) as u64) {
        Some(d) if d.len() == count * 12 => d,
        _ => return false,
    };
    let mut ids = HashSet::new();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut end = floor;
    for i in 0..count {
        let id = be32(directory, i * 12);
        let offset = u64::from(be32(directory, i * 12 + 4));
        let length = u64::from(be32(directory, i * 12 + 8));
        if id == 0 || ids.contains(&id) || offset < floor || !within(r.size(), offset, length) {
            return false;
        }
        ids.insert(id);
        if length != 0 {
            ranges.push((offset, offset + length));
        }
        end = end.max(offset + length);
    }
    ranges.sort_unstable();
    for w in ranges.windows(2) {
        if w[1].0 < w[0].1 {
            return false;
        }
    }
    if end != r.size() {
        return false;
    }
    out.name = if be32(h, 0) == 0x00051600 {
        "AppleSingle"
    } else {
        "AppleDouble"
    }
    .to_string();
    out.version = if version == 0x00010000 { "1" } else { "2" }.to_string();
    out.wrapper = true;
    true
}

/// BinHex 4.0 — banner, 6-bit transport alphabet, RLE-compressed header,
/// header CRC and the trailing `:` terminator.
fn binhex(r: &mut Reader, prefix: &[u8], out: &mut Result) -> bool {
    const BANNER: &[u8] = b"(This file must be converted with BinHex 4.0)";
    const ALPHABET: &[u8] = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
    if !prefix.starts_with(BANNER) {
        return false;
    }
    let mut pos = BANNER.len();
    while pos < prefix.len() && matches!(prefix[pos], b'\r' | b'\n' | b' ' | b'\t') {
        pos += 1;
    }
    if pos == prefix.len() || prefix[pos] != b':' {
        return false;
    }
    pos += 1;
    let mut header: Vec<u8> = Vec::new();
    let mut bits = 0u32;
    let mut available = 0;
    let mut wanted = 1usize;
    let mut escaped = false;
    while pos < prefix.len() && header.len() < wanted {
        let c = prefix[pos];
        pos += 1;
        if c == b'\r' || c == b'\n' {
            continue;
        }
        let Some(digit) = ALPHABET.iter().position(|&a| a == c) else {
            return false;
        };
        bits = (bits << 6) | digit as u32;
        available += 6;
        if available < 8 {
            continue;
        }
        available -= 8;
        let value = ((bits >> available) & 0xff) as u8;
        if escaped {
            escaped = false;
            if value == 0 {
                header.push(0x90);
            } else {
                if value == 1 || header.is_empty() {
                    return false;
                }
                // Decode only the at-most-85-byte transport header even
                // when an RLE run continues into the data fork.
                let prev = *header.last().unwrap();
                let copies = (value as usize - 1).min(wanted - header.len());
                header.extend(std::iter::repeat_n(prev, copies));
            }
        } else if value == 0x90 {
            escaped = true;
        } else {
            header.push(value);
        }
        if wanted == 1 && !header.is_empty() {
            let name_len = u8at(&header, 0) as usize;
            if !(1..=63).contains(&name_len) {
                return false;
            }
            wanted = name_len + 22;
        }
    }
    if header.len() != wanted
        || u8at(&header, u8at(&header, 0) as usize + 1) != 0
        || be16(&header, wanted - 2) != crc16(&header, 0, wanted - 2, true)
    {
        return false;
    }
    let tail_start = r.size().saturating_sub(128);
    let tail = match r.read(tail_start, r.size() - tail_start) {
        Some(t) => t,
        None => return false,
    };
    let trimmed: Vec<u8> = tail
        .iter()
        .skip_while(|&&b| b == b' ' || b == b'\t' || b == b'\r' || b == b'\n')
        .copied()
        .collect();
    let trimmed: &[u8] = {
        let mut end = trimmed.len();
        while end > 0 && matches!(trimmed[end - 1], b' ' | b'\t' | b'\r' | b'\n') {
            end -= 1;
        }
        &trimmed[..end]
    };
    if !trimmed.ends_with(b":") {
        return false;
    }
    out.name = "BinHex".to_string();
    out.version = "4.0".to_string();
    out.info = "Header CRC verified".to_string();
    out.wrapper = true;
    true
}

/// One logical line: bounded at 1024 bytes, CRLF/LF/CR terminated.
fn next_line<'a>(b: &'a [u8], pos: &mut usize) -> &'a [u8] {
    let start = *pos;
    while *pos < b.len() && b[*pos] != b'\r' && b[*pos] != b'\n' && *pos - start <= 1024 {
        *pos += 1;
    }
    let value = &b[start..*pos];
    if *pos < b.len() && b[*pos] == b'\r' {
        *pos += 1;
    }
    if *pos < b.len() && b[*pos] == b'\n' {
        *pos += 1;
    }
    value
}

/// uuencode — optional printable preamble, `begin <mode> <name>`, then
/// counted 6-bit rows down to the `end` line.
fn uuencode(r: &mut Reader, prefix: &[u8], out: &mut Result) -> bool {
    let mut start = 0usize;
    loop {
        let Some(found) = prefix[start..]
            .windows(6)
            .position(|w| w == b"begin ")
            .map(|p| p + start)
        else {
            return false;
        };
        start = found;
        if start > 4096 {
            return false;
        }
        if start == 0 || prefix[start - 1] == b'\n' || prefix[start - 1] == b'\r' {
            break;
        }
        start += 1;
    }
    for &c in &prefix[..start] {
        if (c < 0x20 && c != b'\n' && c != b'\r' && c != b'\t') || c > 0x7e {
            return false;
        }
    }
    if r.size() > MAX_READ - 8192 {
        return false;
    }
    let b = match r.read(0, r.size()) {
        Some(b) if b.len() as u64 == r.size() => b,
        _ => return false,
    };
    let mut pos = start;
    let begin = next_line(b, &mut pos).to_vec();
    if begin.len() < 11 || begin.len() > 1024 {
        return false;
    }
    let mut name = 6;
    while name < begin.len() && (b'0'..=b'7').contains(&begin[name]) {
        name += 1;
    }
    if (name != 9 && name != 10) || name + 1 >= begin.len() || begin[name] != b' ' {
        return false;
    }
    for &c in &begin[name + 1..] {
        if c < 0x20 || c == 0x7f {
            return false;
        }
    }
    let mut data_seen = false;
    for _records in 0..262144 {
        if pos >= b.len() {
            return false;
        }
        let row = next_line(b, &mut pos).to_vec();
        if row.is_empty() {
            return false;
        }
        let count = (u8at(&row, 0).wrapping_sub(0x20)) & 63;
        if u8at(&row, 0) < 0x20 || u8at(&row, 0) > 0x60 || count > 45 {
            return false;
        }
        if count == 0 {
            if row.len() != 1 || !data_seen || next_line(b, &mut pos) != b"end" {
                return false;
            }
            if !b[pos..]
                .iter()
                .all(|&c| matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
            {
                return false;
            }
            out.name = "UUE".to_string();
            out.info = "uuencode".to_string();
            out.wrapper = true;
            return true;
        }
        if row.len() != 1 + 4 * (count as usize).div_ceil(3) {
            return false;
        }
        if row[1..].iter().any(|&c| !(0x20..=0x60).contains(&c)) {
            return false;
        }
        data_seen = true;
    }
    false
}

fn skip_bytes(n: usize, end: usize, pos: &mut usize) -> bool {
    if n > end.saturating_sub(*pos) {
        return false;
    }
    *pos += n;
    true
}

/// Microsoft SZDD / QBasic-variant / KWAJ compression headers.
fn microsoft_compress(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 12 {
        return false;
    }
    if h.starts_with(&[0x53, 0x5A, 0x44, 0x44, 0x88, 0xF0, 0x27, 0x33]) {
        if h.len() < 14 || h[8] != b'A' || (le32(h, 10) != 0 && r.size() == 14) {
            return false;
        }
        out.name = "SZDD".to_string();
        out.info = "LZSS".to_string();
        return true;
    }
    if h.starts_with(&[0x53, 0x5A, 0x20, 0x88, 0xF0, 0x27, 0x33, 0xD1]) {
        if le32(h, 8) != 0 && r.size() == 12 {
            return false;
        }
        out.name = "SZDD".to_string();
        out.info = "QBasic variant".to_string();
        return true;
    }
    if !h.starts_with(&[0x4B, 0x57, 0x41, 0x4A, 0x88, 0xF0, 0x27, 0xD1]) || h.len() < 14 {
        return false;
    }
    let method = le16(h, 8) as usize;
    let end = le16(h, 10) as usize;
    let flags = le16(h, 12);
    if method > 4 || end < 14 || end as u64 > r.size() || flags & !63 != 0 {
        return false;
    }
    let header = match r.read(0, end as u64) {
        Some(x) if x.len() == end => x,
        _ => return false,
    };
    let mut pos = 14usize;
    let mut unpacked = 0u32;
    if flags & 1 != 0 {
        if !skip_bytes(4, end, &mut pos) {
            return false;
        }
        unpacked = le32(header, pos - 4);
    }
    if flags & 2 != 0 && !skip_bytes(2, end, &mut pos) {
        return false;
    }
    if flags & 4 != 0 {
        if !skip_bytes(2, end, &mut pos) {
            return false;
        }
        if !skip_bytes(le16(header, pos - 2) as usize, end, &mut pos) {
            return false;
        }
    }
    for flag in [8u16, 16] {
        if flags & flag != 0 {
            let limit = end.min(pos + if flag == 8 { 9 } else { 4 });
            while pos < limit && header[pos] != 0 {
                pos += 1;
            }
            if pos == limit {
                return false;
            }
            pos += 1;
        }
    }
    if flags & 32 != 0 {
        if !skip_bytes(2, end, &mut pos) {
            return false;
        }
        if !skip_bytes(le16(header, pos - 2) as usize, end, &mut pos) {
            return false;
        }
    }
    if flags & 1 != 0
        && ((unpacked != 0 && end as u64 == r.size())
            || (method <= 1 && u64::from(unpacked) != r.size() - end as u64))
    {
        return false;
    }
    const METHODS: [&str; 5] = ["Stored", "XOR", "LZSS", "LZH", "MSZIP"];
    out.name = "KWAJ".to_string();
    out.info = METHODS[method].to_string();
    true
}

/// ARC (0x1A method) entry walk until the terminator record.
fn arc(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 25 || u8at(h, 0) != 0x1a {
        return false;
    }
    let mut pos = 0u64;
    for count in 0..MAX_RECORDS {
        let entry = match r.read(pos, 2) {
            Some(e) if e.len() == 2 => e,
            _ => return false,
        };
        if u8at(entry, 0) != 0x1a {
            return false;
        }
        let method = u8at(entry, 1);
        if method == 0 {
            if count == 0 {
                return false;
            }
            out.name = "ARC".to_string();
            return true;
        }
        if !(1..=10).contains(&method) && method != 0x7f {
            return false;
        }
        let header_size = if method == 1 { 25 } else { 29 };
        let entry = match r.read(pos, header_size) {
            Some(e) if e.len() == header_size as usize => e,
            _ => return false,
        };
        let filename = &entry[2..15];
        let Some(name_end) = filename.iter().position(|&b| b == 0) else {
            return false;
        };
        if name_end < 1 {
            return false;
        }
        if filename[..name_end]
            .iter()
            .any(|&c| !(0x20..=0x7e).contains(&c))
        {
            return false;
        }
        let packed = u64::from(le32(entry, 15));
        if !within(r.size(), pos + header_size, packed)
            || (method == 2 && packed != u64::from(le32(entry, 25)))
        {
            return false;
        }
        pos += header_size + packed;
    }
    false
}

/// ARJ — main-header CRC plus the extended-header chain.
fn arj(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 4 || le16(h, 0) != 0xea60 {
        return false;
    }
    let length = le16(h, 2) as usize;
    if !(30..=2600).contains(&length) {
        return false;
    }
    let header = match r.read(4, (length + 4) as u64) {
        Some(x) if x.len() == length + 4 => x,
        _ => return false,
    };
    if u8at(header, 0) < 30
        || u8at(header, 0) as usize > length - 2
        || u8at(header, 6) != 2
        || crc32(&header[..length]) != le32(header, length)
    {
        return false;
    }
    let first_hdr_len = u8at(header, 0) as usize;
    let Some(name_end) = header[first_hdr_len..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| p + first_hdr_len)
    else {
        return false;
    };
    if name_end >= length {
        return false;
    }
    let second_nul = header[name_end + 1..].iter().position(|&b| b == 0);
    match second_nul {
        Some(p) if name_end + 1 + p < length => {}
        _ => return false,
    }
    let mut pos = 8 + length;
    let mut terminated = false;
    for _ in 0..256 {
        let size = match r.read(pos as u64, 2) {
            Some(s) if s.len() == 2 => s,
            _ => return false,
        };
        let extra_len = le16(size, 0) as usize;
        pos += 2;
        if extra_len == 0 {
            terminated = true;
            break;
        }
        let extra = match r.read(pos as u64, (extra_len + 4) as u64) {
            Some(e) if e.len() == extra_len + 4 => e,
            _ => return false,
        };
        if crc32(&extra[..extra_len]) != le32(extra, extra_len) {
            return false;
        }
        pos += extra_len + 4;
    }
    let next = match r.read(pos as u64, 4) {
        Some(x) if x.len() == 4 => x,
        _ => return false,
    };
    if !terminated
        || le16(next, 0) != 0xea60
        || !within(r.size(), pos as u64 + 4, u64::from(le16(next, 2)))
    {
        return false;
    }
    out.name = "ARJ".to_string();
    out.record = n::RECORD_NAME_ARJ;
    out.info = format!(
        "Header revision {}; minimum extractor revision {}",
        u8at(header, 1),
        u8at(header, 2)
    );
    true
}

/// ZOO archive — header magic + linked directory walk.
fn zoo(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 34
        || !h.starts_with(b"ZOO ")
        || le32(h, 20) != 0xfdc4a7dc
        || le32(h, 24).wrapping_add(le32(h, 28)) != 0
    {
        return false;
    }
    let mut pos = u64::from(le32(h, 24));
    if pos < 34 {
        return false;
    }
    for count in 0..MAX_RECORDS {
        let e = match r.read(pos, 51) {
            Some(e) if e.len() == 51 => e,
            _ => return false,
        };
        if le32(e, 0) != 0xfdc4a7dc || u8at(e, 4) > 2 {
            return false;
        }
        let next = u64::from(le32(e, 6));
        if next == 0 {
            if count == 0 {
                return false;
            }
            out.name = "ZOO".to_string();
            out.info = format!("Minimum extractor version {}.{}", u8at(h, 32), u8at(h, 33));
            return true;
        }
        if next <= pos
            || u8at(e, 5) > 2
            || !within(r.size(), u64::from(le32(e, 10)), u64::from(le32(e, 24)))
            || (u8at(e, 5) == 0 && le32(e, 20) != le32(e, 24))
        {
            return false;
        }
        pos = next;
    }
    false
}

/// LZX (Amiga) — per-entry CRC over the fixed part of each header.
fn lzx(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 10 || !h.starts_with(b"LZX") {
        return false;
    }
    let mut pos = 10u64;
    let mut group_size = 0u64;
    let mut count = 0usize;
    while pos < r.size() && count < MAX_RECORDS {
        let e = match r.read(pos, 31) {
            Some(e) if e.len() == 31 => e.to_vec(),
            _ => return false,
        };
        if u8at(&e, 30) == 0 || (u8at(&e, 11) != 0 && u8at(&e, 11) != 2) {
            return false;
        }
        let length = 31 + u8at(&e, 30) as usize + u8at(&e, 14) as usize;
        let packed = u64::from(le32(&e, 6));
        // At most MAX_RECORDS * u32::MAX — cannot overflow u64.
        group_size += u64::from(le32(&e, 2));
        if packed != 0
            && ((u8at(&e, 11) == 0 && packed != group_size)
                || (u8at(&e, 11) == 2 && packed & 1 != 0))
        {
            return false;
        }
        let e = match r.read(pos, length as u64) {
            Some(e) if e.len() == length => e.to_vec(),
            _ => return false,
        };
        if !within(r.size(), pos + length as u64, packed) {
            return false;
        }
        let stored = le32(&e, 26);
        let mut e2 = e.clone();
        e2[26..30].fill(0);
        if crc32(&e2) != stored {
            return false;
        }
        if packed != 0 {
            group_size = 0;
        }
        pos += length as u64 + packed;
        count += 1;
    }
    if count == 0 || pos != r.size() || group_size != 0 {
        return false;
    }
    out.name = "LZX".to_string();
    out.info = "Amiga archive; header CRCs verified".to_string();
    true
}

/// DMS (Disk Masher System) — header + first track-header CRCs.
fn dms(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 56
        || !h.starts_with(b"DMS!")
        || be16(h, 50) > 6
        || crc16(h, 4, 50, false) != be16(h, 54)
    {
        return false;
    }
    let track = match r.read(56, 20) {
        Some(t) if t.len() == 20 => t,
        _ => return false,
    };
    if !track.starts_with(b"TR")
        || u8at(track, 13) > 6
        || crc16(track, 0, 18, false) != be16(track, 18)
        || !within(r.size(), 76, u64::from(be16(track, 6)))
    {
        return false;
    }
    out.name = "DMS".to_string();
    out.info = "Disk Masher System; header CRCs verified".to_string();
    true
}

/// Disk Doubler — three signature families (ABCD0054, DDAR, DDA2).
fn disk_doubler(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 62 {
        return false;
    }
    let magic = be32(h, 0);
    if magic == 0xabcd0054 {
        if h.len() < 84 {
            return false;
        }
        let stored = be16(h, 82);
        if stored != 0 && crc16(h, 0, 82, true) != stored {
            return false;
        }
        let packed = u64::from(be32(h, 8)) + u64::from(be32(h, 16));
        let end = 84 + packed;
        if !within(r.size(), 84, packed) || u8at(h, 20) & 0x7f > 10 || u8at(h, 21) & 0x7f > 10 {
            return false;
        }
        if (u8at(h, 20) & 0x7f == 0 && be32(h, 4) != be32(h, 8))
            || (u8at(h, 21) & 0x7f == 0 && be32(h, 12) != be32(h, 16))
        {
            return false;
        }
        if end != r.size() {
            if r.size() - end != 84 {
                return false;
            }
            match r.read(end, 84) {
                Some(t) if t == &h[..84] => {}
                _ => return false,
            }
        }
        out.name = "Disk Doubler".to_string();
        return true;
    }
    if magic == 0x44444152 {
        // "DDAR"
        if h.len() < 78 || crc16(h, 0, 76, true) != be16(h, 76) || u64::from(be32(h, 8)) != r.size()
        {
            return false;
        }
        let entry = match r.read(78, 124) {
            Some(e) if e.len() == 124 => e,
            _ => return false,
        };
        if !entry.starts_with(b"DDAR") || u8at(entry, 8) > 63 {
            return false;
        }
        out.name = "DDAR".to_string();
        out.info = "Disk Doubler archive; header CRC verified".to_string();
        return true;
    }
    if magic == 0x44444132 {
        // "DDA2"
        if be16(h, 4) != 62 || crc16(h, 0, 60, true) != be16(h, 60) {
            return false;
        }
        let mut pos = 62u64;
        for count in 0..MAX_RECORDS {
            let e = match r.read(pos, 6) {
                Some(e) if e.len() == 6 => e,
                _ => return false,
            };
            if !e.starts_with(b"DDA2") {
                return false;
            }
            if be16(e, 4) == 0xbbbb {
                if count == 0 || r.size() - pos - 6 > 4096 {
                    return false;
                }
                out.name = "DDA2".to_string();
                out.info = "Disk Doubler archive; header CRC verified".to_string();
                return true;
            }
            let e = match r.read(pos, 46) {
                Some(e) if e.len() == 46 => e,
                _ => return false,
            };
            if u8at(e, 6) > 31 || be32(e, 42) < 46 || !within(r.size(), pos, u64::from(be32(e, 42)))
            {
                return false;
            }
            pos += u64::from(be32(e, 42));
        }
    }
    false
}

/// StuffIt (SIT!/rLau) and StuffIt 5 (`StuffIt (c)1997-` banner).
fn stuff_it(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() >= 22 && h.starts_with(b"SIT!") && h[10..14] == *b"rLau" {
        if u64::from(be32(h, 6)) != r.size() || be16(h, 4) == 0 {
            return false;
        }
        let entry = match r.read(22, 112) {
            Some(e) if e.len() == 112 => e,
            _ => return false,
        };
        if u8at(entry, 2) > 63 || crc16(entry, 0, 110, false) != be16(entry, 110) {
            return false;
        }
        out.name = "StuffIt".to_string();
        out.version = format!("{}", u8at(h, 14));
        out.info = "Archive header revision".to_string();
        return true;
    }
    const SUFFIX: &[u8] = b" Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\r\n";
    if h.len() >= 100 && h.starts_with(b"StuffIt (c)1997-") && h[20..20 + SUFFIX.len()] == *SUFFIX {
        if u8at(h, 82) != 5 || u64::from(be32(h, 84)) != r.size() || be16(h, 92) == 0 {
            return false;
        }
        let pos = u64::from(be32(h, 94));
        let entry = match r.read(pos, 34) {
            Some(e) if e.len() == 34 => e,
            _ => return false,
        };
        if pos < 100 || be32(entry, 0) != 0xa5a5a5a5 || be16(entry, 6) < 48 {
            return false;
        }
        let length = be16(entry, 6) as usize;
        let entry = match r.read(pos, length as u64) {
            Some(e) if e.len() == length => e.to_vec(),
            _ => return false,
        };
        let stored = be16(&entry, 32);
        let mut e2 = entry.clone();
        e2[32] = 0;
        e2[33] = 0;
        if crc16(&e2, 0, length, false) != stored {
            return false;
        }
        out.name = "StuffIt".to_string();
        out.version = "5".to_string();
        out.info = "Archive format; header CRC verified".to_string();
        return true;
    }
    false
}

fn next_bit(h: &[u8], pos: &mut usize) -> i32 {
    if *pos >= h.len() * 8 {
        return -1;
    }
    let value = ((u8at(h, *pos / 8) >> (*pos % 8)) & 1) as i32;
    *pos += 1;
    value
}

fn next_integer(h: &[u8], pos: &mut usize, value: &mut u64) -> bool {
    let mut ones = 1u32;
    loop {
        let b = next_bit(h, pos);
        if b < 0 || ones >= 64 {
            return false;
        }
        if b == 0 {
            break;
        }
        ones += 1;
    }
    let mut encoded = 0u64;
    let mut i = 0;
    while i < 64 && ones != 0 {
        let b = next_bit(h, pos);
        if b < 0 {
            return false;
        }
        if b != 0 {
            ones -= 1;
            encoded |= 1u64 << i;
        }
        i += 1;
    }
    if ones != 0 || encoded == 0 {
        return false;
    }
    *value = encoded - 1;
    true
}

/// StuffIt X — bit-coded first element; validate both bounded key/value
/// lists rather than trusting the eight-byte signature.
fn stuff_it_x(h: &[u8], out: &mut Result) -> bool {
    if !h.starts_with(b"StuffIt!") || h.len() < 10 {
        return false;
    }
    let mut pos = 64usize;
    let mut etype = 0u64;
    if next_bit(h, &mut pos) < 0
        || !next_integer(h, &mut pos, &mut etype)
        || etype == 0
        || etype > 15
    {
        return false;
    }
    for list in 0..2 {
        let mut keys = HashSet::new();
        let mut terminated = false;
        for _ in 0..32 {
            let mut key = 0u64;
            let mut value = 0u64;
            if !next_integer(h, &mut pos, &mut key) {
                return false;
            }
            if key == 0 {
                terminated = true;
                break;
            }
            if key > if list == 1 { 6 } else { 10 }
                || keys.contains(&key)
                || !next_integer(h, &mut pos, &mut value)
            {
                return false;
            }
            keys.insert(key);
            if list == 1 && key == 4 && !next_integer(h, &mut pos, &mut value) {
                return false;
            }
        }
        if !terminated {
            return false;
        }
    }
    out.name = "StuffIt X".to_string();
    true
}

/// `NFDLegacy::detect` — first hit wins; wrapper formats insert into
/// `mapResultFormats`, archives into `mapResultArchives`.
pub fn detect(d: &[u8], res: &mut ResultMaps) -> bool {
    if d.len() < 2 {
        return false;
    }
    let mut r = Reader::new(d);
    let h = r.read(0, r.size().min(8192)).unwrap_or(&[]).to_vec();
    if h.is_empty() {
        return false;
    }
    let mut result = Result::default();
    let found = apple_single(&mut r, &h, &mut result)
        || mac_binary(&mut r, &h, &mut result)
        || binhex(&mut r, &h, &mut result)
        || uuencode(&mut r, &h, &mut result)
        || microsoft_compress(&mut r, &h, &mut result)
        || arc(&mut r, &h, &mut result)
        || arj(&mut r, &h, &mut result)
        || zoo(&mut r, &h, &mut result)
        || lzx(&mut r, &h, &mut result)
        || dms(&mut r, &h, &mut result)
        || disk_doubler(&mut r, &h, &mut result)
        || stuff_it(&mut r, &h, &mut result)
        || stuff_it_x(&h, &mut result);
    if !found {
        return false;
    }
    let rec = ScanRecord {
        name: if result.record == 0 {
            n::RECORD_NAME_UNKNOWN
        } else {
            result.record
        },
        rtype: rt::RECORD_TYPE_FORMAT,
        ft: if result.wrapper {
            ft::FT_BINARY
        } else {
            ft::FT_ARCHIVE
        },
        variant: 0,
        version: result.version.clone(),
        info: result.info.clone(),
        heuristic: false,
        unknown: false,
        sname: None,
        stype: None,
    };
    let mut rec = rec;
    // sname is the upstream `sName` display override ("ARJ", "MacBinary"…).
    rec.sname = leak_name(&result.name).map(std::borrow::Cow::Borrowed);
    if result.wrapper {
        res.formats.insert(rec.name, rec);
    } else {
        res.archives.insert(rec.name, rec);
    }
    true
}

/// Display names produced by this engine are compile-time constants in
/// upstream; map the handful used back to `&'static` for `sname`.
fn leak_name(s: &str) -> Option<&'static str> {
    Some(match s {
        "MacBinary" => "MacBinary",
        "AppleSingle" => "AppleSingle",
        "AppleDouble" => "AppleDouble",
        "BinHex" => "BinHex",
        "UUE" => "UUE",
        "SZDD" => "SZDD",
        "KWAJ" => "KWAJ",
        "ARC" => "ARC",
        "ARJ" => "ARJ",
        "ZOO" => "ZOO",
        "LZX" => "LZX",
        "DMS" => "DMS",
        "Disk Doubler" => "Disk Doubler",
        "DDAR" => "DDAR",
        "DDA2" => "DDA2",
        "StuffIt" => "StuffIt",
        "StuffIt X" => "StuffIt X",
        _ => return None,
    })
}

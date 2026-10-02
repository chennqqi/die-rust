//! Bounded format parsers used by the format-specific scan passes.
//!
//! Each helper mirrors the offset/VA resolution that the upstream
//! `Formats` classes (`XELF`, `XNE`, `XDEX`, `XArchive`) perform for
//! `NFD_*::getInfo`. All inputs are untrusted: every read is bounds
//! checked and every loop is capped.

/// Read a little-endian `u16` at `off`, or `None` when out of bounds.
fn rd_u16(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}

/// Read a little-endian `u32` at `off`, or `None` when out of bounds.
fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// Read a little-endian `u64` at `off`, or `None` when out of bounds.
fn rd_u64(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Resolve an ELF `e_entry` virtual address to a file offset via the
/// PT_LOAD program headers (`XELF::getEntryPointOffset`).
///
/// Returns `None` for non-ELF input, invalid headers, or an entry point
/// that does not land inside any loaded segment.
pub fn elf_entry_offset(d: &[u8]) -> Option<usize> {
    if !d.starts_with(b"\x7FELF") {
        return None;
    }
    let is64 = d.get(4) == Some(&2);
    let (entry, phoff, phentsize, phnum) = if is64 {
        (
            rd_u64(d, 0x18)?,
            rd_u64(d, 0x20)? as usize,
            rd_u16(d, 0x36)? as usize,
            rd_u16(d, 0x38)? as usize,
        )
    } else {
        (
            rd_u32(d, 0x18)? as u64,
            rd_u32(d, 0x1C)? as usize,
            rd_u16(d, 0x2A)? as usize,
            rd_u16(d, 0x2C)? as usize,
        )
    };
    if phentsize == 0 {
        return None;
    }
    for i in 0..phnum.min(1024) {
        let p = phoff.checked_add(i.checked_mul(phentsize)?)?;
        let (ptype, poff, vaddr, filesz) = if is64 {
            (
                rd_u32(d, p)?,
                rd_u64(d, p + 8)?,
                rd_u64(d, p + 16)?,
                rd_u64(d, p + 32)?,
            )
        } else {
            (
                rd_u32(d, p)?,
                rd_u32(d, p + 4)? as u64,
                rd_u32(d, p + 8)? as u64,
                rd_u32(d, p + 16)? as u64,
            )
        };
        // PT_LOAD only; entry inside [vaddr, vaddr+filesz).
        if ptype == 1 && entry >= vaddr && entry < vaddr.saturating_add(filesz) {
            return Some(poff.checked_add(entry - vaddr)? as usize);
        }
    }
    None
}

/// Resolve the NE entry point (CS:IP) to a file offset via the segment
/// table (`XNE::_getEntryPointAddress` + `addressToOffset`).
///
/// NE header layout at `ne_off`: CS:IP is the `u32` at +0x14 (IP low,
/// 1-based segment index high), segment count at +0x1C, segment table
/// offset (relative to `ne_off`) at +0x22, sector-align shift at +0x32.
/// Each 8-byte segment record starts with a logical sector index; the
/// file offset is `(sector << align) + ip`.
pub fn ne_entry_offset(d: &[u8]) -> Option<usize> {
    let ne_off = rd_u32(d, 0x3C)? as usize;
    if d.get(ne_off..ne_off + 2) != Some(b"NE") {
        return None;
    }
    let ip = rd_u16(d, ne_off + 0x14)? as usize;
    let cs = rd_u16(d, ne_off + 0x16)? as usize;
    let cseg = rd_u16(d, ne_off + 0x1C)? as usize;
    let segtab = ne_off + rd_u16(d, ne_off + 0x22)? as usize;
    let align = rd_u16(d, ne_off + 0x32)? as u32;
    if cs == 0 || cs > cseg || align > 20 {
        return None;
    }
    let rec = segtab + (cs - 1).checked_mul(8)?;
    let sector = rd_u16(d, rec)? as u64;
    Some((sector << align) as usize + ip)
}

/// Decode a ULEB128 value at `off`; returns `(value, next_offset)`.
fn rd_uleb(d: &[u8], mut off: usize) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for i in 0..10 {
        let b = *d.get(off)?;
        v |= u64::from(b & 0x7F) << (i * 7);
        off += 1;
        if b & 0x80 == 0 {
            return Some((v, off));
        }
    }
    None
}

/// Collect DEX `string_ids` contents (MUTF-8 payloads, length-delimited)
/// and the `type_ids` descriptor strings — the `listStrings` and
/// `listTypeItemStrings` inputs of `NFD_DEX::getInfo`.
///
/// Header fields: `string_ids_size`/`off` at 0x38/0x3C, `type_ids_size`/
/// `off` at 0x40/0x44. Each `string_id` is a `u32` offset pointing at a
/// `uleb128` UTF-16 length followed by NUL-terminated MUTF-8 bytes.
/// Each `type_id` is a `u32` `descriptor_idx` into `string_ids`.
pub fn dex_strings(d: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut strings = Vec::new();
    let mut types = Vec::new();
    if !d.starts_with(b"dex\n") {
        return (strings, types);
    }
    let Some(n_str) = rd_u32(d, 0x38).map(|v| v.min(1 << 20) as usize) else {
        return (strings, types);
    };
    let Some(str_off) = rd_u32(d, 0x3C).map(|v| v as usize) else {
        return (strings, types);
    };
    let Some(n_ty) = rd_u32(d, 0x40).map(|v| v.min(1 << 20) as usize) else {
        return (strings, types);
    };
    let Some(ty_off) = rd_u32(d, 0x44).map(|v| v as usize) else {
        return (strings, types);
    };

    let read_string = |idx: usize| -> Option<String> {
        let sid = str_off.checked_add(idx.checked_mul(4)?)?;
        let data_off = rd_u32(d, sid)? as usize;
        let (_utf16_len, mut p) = rd_uleb(d, data_off)?;
        // MUTF-8 is NUL-terminated; cap the byte length at 64 KiB.
        let start = p;
        while p < d.len() && p - start < 65536 && d[p] != 0 {
            p += 1;
        }
        // MUTF-8 differs from UTF-8 only for NUL (encoded as C0 80) and
        // supplementary chars; for matching purposes lossy UTF-8 is fine.
        Some(String::from_utf8_lossy(&d[start..p]).into_owned())
    };

    for i in 0..n_str {
        if let Some(s) = read_string(i) {
            strings.push(s);
        }
    }
    for i in 0..n_ty {
        let tid = match ty_off.checked_add(i * 4) {
            Some(v) => v,
            None => break,
        };
        let Some(desc_idx) = rd_u32(d, tid).map(|v| v as usize) else {
            break;
        };
        if let Some(s) = read_string(desc_idx) {
            types.push(s);
        }
    }
    (strings, types)
}

/// Collect ZIP member names from the central directory — the
/// `listArchiveRecords` input of `NFD_APK::getInfo`.
///
/// The EOCD record is located by scanning the trailing 64 KiB for the
/// `PK\x05\x06` signature; entries are walked via the central directory
/// header fields (name length @+28, extra @+30, comment @+32, name @+46).
pub fn zip_member_names(d: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    // End of central directory signature.
    let lo = d.len().saturating_sub(65557);
    let mut eocd = None;
    for i in (lo..d.len().saturating_sub(3)).rev() {
        if d[i..i + 4] == [0x50, 0x4B, 0x05, 0x06] {
            eocd = Some(i);
            break;
        }
    }
    let Some(eocd) = eocd else {
        return names;
    };
    let Some(count) = rd_u16(d, eocd + 10).map(|v| v as usize) else {
        return names;
    };
    let Some(mut p) = rd_u32(d, eocd + 16).map(|v| v as usize) else {
        return names;
    };
    for _ in 0..count.min(65536) {
        if d.get(p..p + 4) != Some(&[0x50, 0x4B, 0x01, 0x02]) {
            break;
        }
        let (Some(nl), Some(el), Some(cl)) = (
            rd_u16(d, p + 28).map(|v| v as usize),
            rd_u16(d, p + 30).map(|v| v as usize),
            rd_u16(d, p + 32).map(|v| v as usize),
        ) else {
            break;
        };
        let name_off = p + 46;
        if let Some(nb) = d.get(name_off..name_off + nl) {
            names.push(String::from_utf8_lossy(nb).into_owned());
        }
        let Some(next) = name_off.checked_add(nl + el + cl) else {
            break;
        };
        p = next;
    }
    names
}

/// ANSI plain-text classification (`XBinary::isPlainTextType`):
/// NUL or BOM rejects; printable+extended >= 0.85, control <= 0.05,
/// extended <= 0.50.
pub fn is_plain_text(d: &[u8]) -> bool {
    if d.is_empty() {
        return false;
    }
    if d.len() >= 3 && d[..3] == [0xEF, 0xBB, 0xBF] {
        return false;
    }
    if d.len() >= 2 && (d[..2] == [0xFF, 0xFE] || d[..2] == [0xFE, 0xFF]) {
        return false;
    }
    let (mut ctl, mut print, mut ext) = (0usize, 0usize, 0usize);
    for &b in d {
        match b {
            0x00 => return false,
            0x09 | 0x0A | 0x0D | 0x20..=0x7E => print += 1,
            0x80..=0xFF => ext += 1,
            _ => ctl += 1,
        }
    }
    let n = d.len() as f64;
    (print + ext) as f64 / n >= 0.85 && ctl as f64 / n <= 0.05 && ext as f64 / n <= 0.50
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal ELF64 with one PT_LOAD: vaddr 0x400000 -> offset 0, filesz
    /// 0x1000; entry = 0x400800 -> file offset 0x800.
    #[test]
    fn elf64_entry_maps_via_ptload() {
        let mut d = vec![0u8; 0x1000];
        d[..4].copy_from_slice(b"\x7FELF");
        d[4] = 2; // ELFCLASS64
        d[0x18..0x20].copy_from_slice(&0x400800u64.to_le_bytes());
        d[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes()); // phoff
        d[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        d[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes()); // phnum
        d[0x40..0x44].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        d[0x48..0x50].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        d[0x50..0x58].copy_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
        d[0x60..0x68].copy_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
        assert_eq!(elf_entry_offset(&d), Some(0x800));
    }

    #[test]
    fn elf_entry_outside_segments_returns_none() {
        let mut d = vec![0u8; 0x1000];
        d[..4].copy_from_slice(b"\x7FELF");
        d[4] = 2;
        d[0x18..0x20].copy_from_slice(&0x900000u64.to_le_bytes());
        d[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        d[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        d[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());
        d[0x40..0x44].copy_from_slice(&1u32.to_le_bytes());
        d[0x48..0x50].copy_from_slice(&0u64.to_le_bytes());
        d[0x50..0x58].copy_from_slice(&0x400000u64.to_le_bytes());
        d[0x60..0x68].copy_from_slice(&0x1000u64.to_le_bytes());
        assert_eq!(elf_entry_offset(&d), None);
    }

    /// NE stub: DOS header + e_lfanew=0x40; NE header with cs=1, ip=0x10,
    /// align=4, one segment at sector 0x20 -> file offset 0x200+0x10.
    #[test]
    fn ne_entry_maps_via_segment_table() {
        let mut d = vec![0u8; 0x400];
        d[..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        d[0x40..0x42].copy_from_slice(b"NE");
        d[0x54..0x56].copy_from_slice(&0x10u16.to_le_bytes()); // ip
        d[0x56..0x58].copy_from_slice(&1u16.to_le_bytes()); // cs = seg 1
        d[0x5C..0x5E].copy_from_slice(&1u16.to_le_bytes()); // cseg
        d[0x62..0x64].copy_from_slice(&0x40u16.to_le_bytes()); // segtab rel
        d[0x72..0x74].copy_from_slice(&4u16.to_le_bytes()); // align shift
        d[0x80..0x82].copy_from_slice(&0x20u16.to_le_bytes()); // seg1 sector
        assert_eq!(ne_entry_offset(&d), Some(0x210));
    }

    #[test]
    fn ne_cs_zero_has_no_entry() {
        let mut d = vec![0u8; 0x400];
        d[..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        d[0x40..0x42].copy_from_slice(b"NE");
        d[0x56..0x58].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(ne_entry_offset(&d), None);
    }

    #[test]
    fn zip_members_walk_central_directory() {
        let mut d = Vec::new();
        d.extend_from_slice(b"PK\x03\x04");
        d.extend_from_slice(&[0u8; 18]);
        d.extend_from_slice(&3u16.to_le_bytes());
        d.extend_from_slice(&[0u8; 2]);
        d.extend_from_slice(b"a.c");
        let cd = d.len();
        d.extend_from_slice(b"PK\x01\x02");
        d.extend_from_slice(&[0u8; 24]);
        d.extend_from_slice(&3u16.to_le_bytes());
        d.extend_from_slice(&[0u8; 8]);
        d.extend_from_slice(&[0u8; 8]);
        d.extend_from_slice(b"a.c");
        d.extend_from_slice(b"PK\x05\x06");
        d.extend_from_slice(&[0u8; 4]);
        d.extend_from_slice(&1u16.to_le_bytes());
        d.extend_from_slice(&1u16.to_le_bytes());
        d.extend_from_slice(&49u32.to_le_bytes());
        d.extend_from_slice(&(cd as u32).to_le_bytes());
        d.extend_from_slice(&[0u8; 2]);
        assert_eq!(zip_member_names(&d), vec!["a.c".to_string()]);
    }

    #[test]
    fn dex_parser_reads_strings() {
        let mut d = vec![0u8; 0x70];
        d[..8].copy_from_slice(b"dex\n035\0");
        d[0x38..0x3C].copy_from_slice(&1u32.to_le_bytes());
        d[0x3C..0x40].copy_from_slice(&0x70u32.to_le_bytes());
        d.resize(0x74, 0);
        d[0x70..0x74].copy_from_slice(&0x74u32.to_le_bytes());
        d.push(3); // uleb128 len
        d.extend_from_slice(b"abc");
        d.push(0);
        let (strings, _) = dex_strings(&d);
        assert_eq!(strings, vec!["abc".to_string()]);
    }

    #[test]
    fn text_classification_bounds() {
        assert!(is_plain_text(b"hello world\n"));
        assert!(!is_plain_text(&[]));
        assert!(!is_plain_text(&[0, 1, 2, 3]));
        assert!(!is_plain_text(b"\xEF\xBB\xBFutf8 bom"));
    }
}

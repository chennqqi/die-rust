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
/// LE u32 at `off`.
pub fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
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

/// One ZIP central-directory member (`XArchive::RECORD` subset).
pub struct ZipMember {
    /// Entry name.
    pub name: String,
    /// "Version needed to extract" low byte (reader compatibility).
    pub version_needed: u16,
    /// Whether the entry carries the encrypted flag (bit 0).
    pub encrypted: bool,
}

/// Collect ZIP member metadata from the central directory — the
/// `listArchiveRecords` input of `NFD_APK`/`NFD_ZIP::getInfo`.
///
/// The EOCD record is located by scanning the trailing 64 KiB for the
/// `PK\x05\x06` signature; entries are walked via the central directory
/// header fields (version_needed @+6, flags @+8, name length @+28,
/// extra @+30, comment @+32, name @+46).
pub fn zip_members(d: &[u8]) -> Vec<ZipMember> {
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
        let (Some(ver), Some(flags), Some(nl), Some(el), Some(cl)) = (
            rd_u16(d, p + 6),
            rd_u16(d, p + 8),
            rd_u16(d, p + 28).map(|v| v as usize),
            rd_u16(d, p + 30).map(|v| v as usize),
            rd_u16(d, p + 32).map(|v| v as usize),
        ) else {
            break;
        };
        let name_off = p + 46;
        let name = d
            .get(name_off..name_off + nl)
            .map(|nb| String::from_utf8_lossy(nb).into_owned())
            .unwrap_or_default();
        names.push(ZipMember {
            name,
            version_needed: ver & 0xFF,
            encrypted: flags & 1 != 0,
        });
        let Some(next) = name_off.checked_add(nl + el + cl) else {
            break;
        };
        p = next;
    }
    names
}

/// ZIP member names only — convenience wrapper of [`zip_members`].
pub fn zip_member_names(d: &[u8]) -> Vec<String> {
    zip_members(d).into_iter().map(|m| m.name).collect()
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

/// Endianness-aware `u16`/`u32`/`u64` readers (`XBinary::read_uint*`
/// with explicit `bIsBigEndian`).
pub fn rd_u16_be_le(d: &[u8], off: usize, big: bool) -> Option<u16> {
    let b = d.get(off..off + 2)?;
    Some(if big {
        u16::from_be_bytes([b[0], b[1]])
    } else {
        u16::from_le_bytes([b[0], b[1]])
    })
}

/// See [`rd_u16_be_le`].
pub fn rd_u32_be_le(d: &[u8], off: usize, big: bool) -> Option<u32> {
    let b = d.get(off..off + 4)?;
    Some(if big {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    })
}

/// See [`rd_u16_be_le`].
pub fn rd_u64_be_le(d: &[u8], off: usize, big: bool) -> Option<u64> {
    let b = d.get(off..off + 8)?;
    Some(if big {
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    } else {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

/// Mach-O FAT header validity check (`XBinary::getFileTypeId` fat
/// branch): `CAFEBABE`/`CAFEBABF` magic, plausible arch count, and every
/// `fat_arch`/`fat_arch_64` record passing the upstream field checks.
pub fn macho_fat_valid(d: &[u8]) -> bool {
    let Some(magic) = d.get(..4) else {
        return false;
    };
    let is64 = magic == [0xCA, 0xFE, 0xBA, 0xBF];
    if !(magic == [0xCA, 0xFE, 0xBA, 0xBE] || is64) {
        return false;
    }
    let be32 = |o: usize| -> Option<u32> {
        d.get(o..o + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    let be64 = |o: usize| -> Option<u64> {
        d.get(o..o + 8)
            .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    };
    let Some(n) = be32(4).map(|v| v as usize) else {
        return false;
    };
    let rec_sz = if is64 { 32 } else { 20 };
    let Some(rows) = n.checked_mul(rec_sz) else {
        return false;
    };
    let Some(table_end) = 8usize.checked_add(rows) else {
        return false;
    };
    if n == 0 || n > 1_000_000 || table_end > d.len() {
        return false;
    }
    for i in 0..n {
        let r = 8 + i * rec_sz;
        let (Some(cpu), Some(aoff), Some(asz), Some(align)) = (
            be32(r),
            if is64 {
                be64(r + 8)
            } else {
                be32(r + 8).map(|v| v as u64)
            },
            if is64 {
                be64(r + 16)
            } else {
                be32(r + 12).map(|v| v as u64)
            },
            be32(r + if is64 { 24 } else { 16 }),
        ) else {
            return false;
        };
        let reserved_ok = !is64 || be32(r + 28) == Some(0);
        let mask = if align > 63 {
            0
        } else if align > 0 {
            (1u64 << align) - 1
        } else {
            0
        };
        let ok = cpu != 0
            && asz != 0
            && align <= 63
            && reserved_ok
            && aoff >= table_end as u64
            && (aoff & mask) == 0
            && aoff <= d.len() as u64
            && asz <= d.len() as u64 - aoff;
        if !ok {
            return false;
        }
    }
    true
}

/// Find an ANSI byte string inside `[offset, offset+size)`
/// (`XBinary::find_ansiString`). Returns the offset or `None`.
pub fn find_ansi(d: &[u8], offset: usize, size: usize, needle: &[u8]) -> Option<usize> {
    let end = offset.saturating_add(size).min(d.len());
    if offset >= end || needle.is_empty() || end - offset < needle.len() {
        return None;
    }
    d[offset..end]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| offset + p)
}

/// Read a NUL-terminated ANSI string at `off` (max 64 KiB,
/// `XBinary::read_ansiString`).
pub fn read_ansi_string(d: &[u8], off: usize) -> Option<String> {
    d.get(off)?; // ensure in-bounds
    let mut end = off;
    while end < d.len() && end - off < 65536 && d[end] != 0 {
        end += 1;
    }
    Some(String::from_utf8_lossy(&d[off..end]).into_owned())
}

/// Parse the APK Signing Block immediately preceding the ZIP central
/// directory and return the contained block ids.
///
/// Layout: `[u64 size][entries][u64 size]["APK Sig Block 42"]`, where
/// each entry is `[u64 len][u32 id][value]`. Used by
/// `NFD_APK::getInfo` for v2/v3 signing-scheme, Walle and Google Play
/// stamps (`XAPK::getAPKSignaturesBlockRecordsList`).
pub fn apk_sig_block_ids(d: &[u8]) -> Vec<u32> {
    const MAGIC: &[u8; 16] = b"APK Sig Block 42";
    // Central directory start (EOCD +16).
    let lo = d.len().saturating_sub(65557);
    let mut eocd = None;
    for i in (lo..d.len().saturating_sub(3)).rev() {
        if d[i..i + 4] == [0x50, 0x4B, 0x05, 0x06] {
            eocd = Some(i);
            break;
        }
    }
    let Some(eocd) = eocd else {
        return Vec::new();
    };
    let Some(cd) = rd_u32(d, eocd + 16).map(|v| v as usize) else {
        return Vec::new();
    };
    // Footer sits right before the central directory.
    if cd < 24 || d.get(cd - 16..cd) != Some(MAGIC.as_slice()) {
        return Vec::new();
    }
    let Some(footer_size) = rd_u64(d, cd - 24).map(|v| v as usize) else {
        return Vec::new();
    };
    // `size` counts everything after the first u64 field, i.e.
    // entries + trailing size(8) + magic(16); entries therefore span
    // `[cd - size, cd - 24)`.
    let Some(entries_start) = cd.checked_sub(footer_size) else {
        return Vec::new();
    };
    let block_start = entries_start;
    let entries_end = cd - 24;
    if block_start >= entries_end {
        return Vec::new();
    }
    let mut ids = Vec::new();
    let mut p = block_start;
    while p + 12 <= entries_end && ids.len() < 4096 {
        let Some(len) = rd_u64(d, p).map(|v| v as usize) else {
            break;
        };
        if len < 4 || p + len > entries_end + 8 {
            break;
        }
        if let Some(id) = rd_u32(d, p + 8) {
            ids.push(id);
        }
        let Some(next) = p.checked_add(len + 8) else {
            break;
        };
        p = next;
    }
    ids
}

/// Parsed ELF section record (name resolved via shstrtab).
#[derive(Debug, Clone)]
pub struct ElfSection {
    /// Section name (shstrtab).
    pub name: String,
    /// `sh_type`.
    pub typ: u32,
    /// `sh_offset`.
    pub off: usize,
    /// `sh_size`.
    pub size: usize,
    /// `sh_entsize`.
    pub entsize: usize,
}

/// ELF structural summary used by the `NFD_ELF` handlers.
#[derive(Debug, Default)]
pub struct ElfInfo {
    /// ELFCLASS64.
    pub is64: bool,
    /// ELFDATA2MSB.
    pub big_endian: bool,
    /// EI_OSABI (ident[7]).
    pub osabi: u8,
    /// PT_INTERP interpreter path.
    pub interp: String,
    /// Section records.
    pub sections: Vec<ElfSection>,
    /// `.comment` contents split on NUL (`XELF::getCommentStrings`).
    pub comments: Vec<String>,
    /// PT_NOTE + SHT_NOTE entries as `(name, desc)`.
    pub notes: Vec<(String, Vec<u8>)>,
    /// DT_NEEDED library names.
    pub needed: Vec<String>,
    /// DT_RUNPATH / DT_RPATH value.
    pub runpath: String,
}

/// Parse ELF headers, sections, notes, dynamic tags and the `.comment`
/// strings (`XELF::getFileFormatInfo` inputs). Returns `None` for
/// non-ELF input; every field is bounded.
pub fn elf_info(d: &[u8]) -> Option<ElfInfo> {
    if !d.starts_with(b"\x7FELF") {
        return None;
    }
    let is64 = d.get(4) == Some(&2);
    let big = d.get(5) == Some(&2);
    let osabi = *d.get(7)?;
    let ru16 = |o: usize| -> Option<u16> {
        let b = d.get(o..o + 2)?;
        Some(if big {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        })
    };
    let ru32 = |o: usize| -> Option<u32> {
        let b = d.get(o..o + 4)?;
        Some(if big {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        })
    };
    let ru64 = |o: usize| -> Option<u64> {
        let b = d.get(o..o + 8)?;
        Some(if big {
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        })
    };

    let (phoff, phentsize, phnum, shoff, shentsize, shnum, shstrndx) = if is64 {
        (
            ru64(0x20)? as usize,
            ru16(0x36)? as usize,
            ru16(0x38)? as usize,
            ru64(0x28)? as usize,
            ru16(0x3A)? as usize,
            ru16(0x3C)? as usize,
            ru16(0x3E)? as usize,
        )
    } else {
        (
            ru32(0x1C)? as usize,
            ru16(0x2A)? as usize,
            ru16(0x2C)? as usize,
            ru32(0x20)? as usize,
            ru16(0x2E)? as usize,
            ru16(0x30)? as usize,
            ru16(0x32)? as usize,
        )
    };

    let mut info = ElfInfo {
        is64,
        big_endian: big,
        osabi,
        ..Default::default()
    };

    // Program headers: PT_INTERP(3) path, PT_NOTE(4) notes, PT_DYNAMIC(2).
    let mut dyn_seg: Option<(usize, usize)> = None;
    if phentsize > 0 {
        for i in 0..phnum.min(1024) {
            let Some(p) = phoff.checked_add(i.checked_mul(phentsize)?) else {
                break;
            };
            let (ptype, poff, filesz) = if is64 {
                (ru32(p)?, ru64(p + 8)? as usize, ru64(p + 32)? as usize)
            } else {
                (ru32(p)?, ru32(p + 4)? as usize, ru32(p + 16)? as usize)
            };
            match ptype {
                3 => {
                    if let Some(end) = poff.checked_add(filesz.min(4096))
                        && let Some(s) = d.get(poff..end.min(d.len()))
                    {
                        info.interp = String::from_utf8_lossy(s)
                            .trim_end_matches('\0')
                            .to_string();
                    }
                }
                4 => elf_notes(d, poff, filesz.min(1 << 20), &ru32, &mut info.notes),
                2 => dyn_seg = Some((poff, filesz.min(1 << 20))),
                _ => {}
            }
        }
    }

    // Sections via shstrtab.
    if shentsize > 0 && shnum > 0 && shstrndx < shnum {
        let mut raw: Vec<(u32, u32, usize, usize, usize)> = Vec::new(); // name_off, type, off, size, entsize
        for i in 0..shnum.min(4096) {
            let Some(p) = shoff.checked_add(i.checked_mul(shentsize)?) else {
                break;
            };
            let (name_off, typ, off, size, entsize) = if is64 {
                (
                    ru32(p)?,
                    ru32(p + 4)?,
                    ru64(p + 24)? as usize,
                    ru64(p + 32)? as usize,
                    ru64(p + 56)? as usize,
                )
            } else {
                (
                    ru32(p)?,
                    ru32(p + 4)?,
                    ru32(p + 16)? as usize,
                    ru32(p + 20)? as usize,
                    ru32(p + 36)? as usize,
                )
            };
            raw.push((name_off, typ, off, size, entsize));
        }
        if let Some(shstr) = raw.get(shstrndx) {
            let strs = d
                .get(shstr.2..shstr.2.saturating_add(shstr.3).min(d.len()))
                .unwrap_or(&[]);
            for &(name_off, typ, off, size, entsize) in &raw {
                let noff = name_off as usize;
                let mut e = noff;
                while e < strs.len() && strs[e] != 0 {
                    e += 1;
                }
                let name = String::from_utf8_lossy(strs.get(noff..e).unwrap_or(&[])).into_owned();
                info.sections.push(ElfSection {
                    name,
                    typ,
                    off,
                    size,
                    entsize,
                });
            }
        }
    }

    // SHT_NOTE(7) sections supplement PT_NOTE notes (Go buildid etc.).
    let sec_notes: Vec<(usize, usize)> = info
        .sections
        .iter()
        .filter(|s| s.typ == 7)
        .map(|s| (s.off, s.size))
        .collect();
    for (off, size) in sec_notes {
        elf_notes(d, off, size.min(1 << 20), &ru32, &mut info.notes);
    }

    // `.comment` strings.
    if let Some(c) = info.sections.iter().find(|s| s.name == ".comment")
        && let Some(buf) = d.get(c.off..c.off.saturating_add(c.size).min(d.len()))
    {
        info.comments = buf
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
    }

    // Dynamic tags from PT_DYNAMIC (fall back to SHT_DYNAMIC section).
    let dyn_rng = dyn_seg.or_else(|| {
        info.sections
            .iter()
            .find(|s| s.typ == 6)
            .map(|s| (s.off, s.size.min(1 << 20)))
    });
    if let Some((doff, dsize)) = dyn_rng {
        let dynstr = info.sections.iter().find(|s| s.name == ".dynstr");
        let (str_off, str_size) = dynstr.map(|s| (s.off, s.size)).unwrap_or((0, 0));
        let entsz = if is64 { 16 } else { 8 };
        let mut p = doff;
        while p + entsz <= doff + dsize && p + entsz <= d.len() {
            let (tag, val) = if is64 {
                (ru64(p)? as i64, ru64(p + 8)?)
            } else {
                (ru32(p)? as i32 as i64, ru32(p + 4)? as u64)
            };
            if tag == 0 {
                break;
            }
            if let Some(so) = str_off.checked_add(val as usize)
                && so < str_off + str_size
                && let Some(s) = read_ansi_string(d, so)
            {
                match tag {
                    1 => info.needed.push(s),                               // DT_NEEDED
                    15 | 29 if info.runpath.is_empty() => info.runpath = s, // RPATH/RUNPATH
                    _ => {}
                }
            }
            p += entsz;
        }
    }

    Some(info)
}

/// Parse ELF note entries inside `[off, off+size)`: each note is
/// `[u32 namesz][u32 descsz][u32 type][name][desc]`, 4-aligned.
fn elf_notes(
    d: &[u8],
    off: usize,
    size: usize,
    ru32: &dyn Fn(usize) -> Option<u32>,
    out: &mut Vec<(String, Vec<u8>)>,
) {
    let end = off.saturating_add(size).min(d.len());
    let mut p = off;
    while p + 12 <= end && out.len() < 256 {
        let (Some(nsz), Some(dsz), Some(_typ)) = (ru32(p), ru32(p + 4), ru32(p + 8)) else {
            break;
        };
        let (nsz, dsz) = (nsz as usize, dsz as usize);
        if nsz > 4096 || dsz > (1 << 20) {
            break;
        }
        let name_off = p + 12;
        let desc_off = (name_off + nsz + 3) & !3;
        let Some(name_raw) = d.get(name_off..name_off + nsz) else {
            break;
        };
        let name = String::from_utf8_lossy(name_raw)
            .trim_end_matches('\0')
            .to_string();
        let desc = d.get(desc_off..desc_off + dsz).unwrap_or(&[]).to_vec();
        out.push((name, desc));
        let Some(next) = desc_off.checked_add(dsz + 3).map(|v| v & !3) else {
            break;
        };
        if next <= p {
            break;
        }
        p = next;
    }
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

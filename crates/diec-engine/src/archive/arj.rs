//! ARJ record enumeration — port of upstream `xarj.cpp` entry parsing.
//!
//! Layout: each entry starts with `60 EA` + u16 basic-header-size
//! (`ARJ_ENTRY_PREFIX_SIZE`). The basic header holds 30 fixed bytes
//! (first-header-size, flags, method, file type, DOS datetime,
//! compressed/original sizes, CRC32) followed by a NUL-terminated name.
//! After the basic header comes a u16 header CRC and a chain of extended
//! headers (`u16 size`, `size` bytes, u32 CRC) terminated by size 0;
//! `header_size` spans everything up to the data stream.
//!
//! The archive main header sits at offset 0; its "compressed/original
//! size" fields hold archive datetimes, so the first file record starts
//! at `header_size(0)` rather than `header_size + compressed_size`.

use super::SecondaryRecord;

const MARKER: [u8; 2] = [0x60, 0xEA];
const PREFIX: usize = 4; // marker(2) + basic size(2)
const FIXED: usize = 30;
const MAX_BASIC: u16 = 2600;
const CRC_SZ: usize = 4;
const EXT_SZ: usize = 2;
/// Basic-header field offsets (past the 4-byte prefix).
const FH_SIZE: usize = 0;
const METHOD: usize = 5;
const DOS_DT: usize = 8;
const COMP: usize = 12;
const ORIG: usize = 16;
const MAX_ENTRIES: usize = 10000;

fn rd16(d: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(off..off + 2)?.try_into().ok()?))
}

fn rd32(d: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(off..off + 4)?.try_into().ok()?))
}

/// `XARJ::isValid`: marker at 0, basic size in `[30, 2600]`, first header
/// size >= 30.
pub fn is_arj(d: &[u8]) -> bool {
    if d.len() < PREFIX + FIXED || d[0] != MARKER[0] || d[1] != MARKER[1] {
        return false;
    }
    let basic = match rd16(d, 2) {
        Some(b) => b,
        None => return false,
    };
    if basic < FIXED as u16 || basic > MAX_BASIC {
        return false;
    }
    // First header size byte sits at offset 4 (start of basic header).
    d.get(PREFIX).is_some_and(|&fh| fh >= FIXED as u8)
}

/// `readEntryHeaderSize`: total bytes from the marker to the data stream.
/// Returns `PREFIX` for the end-of-archive marker (basic size 0).
fn header_size(d: &[u8], off: usize) -> Option<usize> {
    if off.checked_add(PREFIX)? > d.len() || d[off] != MARKER[0] || d[off + 1] != MARKER[1] {
        return None;
    }
    let basic = rd16(d, off + 2)? as usize;
    if basic == 0 {
        return Some(PREFIX);
    }
    if PREFIX + basic + CRC_SZ > d.len() - off {
        return None;
    }
    let mut pos = off + PREFIX + basic + CRC_SZ;
    loop {
        if pos > d.len() || EXT_SZ > d.len() - pos {
            break;
        }
        let ext = rd16(d, pos)? as usize;
        pos += EXT_SZ;
        if ext == 0 {
            break;
        }
        pos += ext + CRC_SZ;
        if pos > d.len() {
            break;
        }
    }
    Some(pos - off)
}

/// `dosDateTimeToDateTime` rendered as a fixed string when the fields are
/// plausible (mirrors `QDateTime::isValid` gating).
fn format_dos(dt: u32) -> Option<String> {
    let year = ((dt >> 25) & 0x7f) + 1980;
    let month = (dt >> 21) & 0x0f;
    let day = (dt >> 16) & 0x1f;
    let hour = (dt >> 11) & 0x1f;
    let minute = (dt >> 5) & 0x3f;
    let second = (dt & 0x1f) * 2;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
    ))
}

/// `readEntryInfo` for one file record. `None` stops enumeration.
struct Entry {
    name: String,
    method: u8,
    compressed: u32,
    original: u32,
    dos_dt: u32,
    header: usize,
    end_of_archive: bool,
}

fn read_entry(d: &[u8], off: usize) -> Option<Entry> {
    let header = header_size(d, off)?;
    let basic = rd16(d, off + 2)? as usize;
    if basic == 0 {
        return Some(Entry {
            name: String::new(),
            method: 0,
            compressed: 0,
            original: 0,
            dos_dt: 0,
            header,
            end_of_archive: true,
        });
    }
    if basic < FIXED {
        return None;
    }
    let bh = d.get(off + PREFIX..off + PREFIX + basic)?;
    let first = bh[FH_SIZE] as usize;
    if first < 1 || first >= bh.len() {
        return None;
    }
    let name_bytes = &bh[first..];
    let end = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len());
    let name = String::from_utf8_lossy(&name_bytes[..end]).replace('\\', "/");
    let compressed = rd32(bh, COMP).unwrap_or(0);
    let stream_off = off.checked_add(header)?;
    // Upstream rejects entries whose stream would run past the file.
    if stream_off > d.len() || compressed as usize > d.len() - stream_off {
        return None;
    }
    Some(Entry {
        name,
        method: bh[METHOD],
        compressed,
        original: rd32(bh, ORIG).unwrap_or(0),
        dos_dt: rd32(bh, DOS_DT).unwrap_or(0),
        header,
        end_of_archive: false,
    })
}

/// `firstFileRecordOffset`: main header measured by header size only.
fn first_record_offset(d: &[u8]) -> Option<usize> {
    let header = header_size(d, 0)?;
    if rd16(d, 2)? == 0 {
        return Some(0);
    }
    (header > 0).then_some(header)
}

/// Enumerate ARJ file records (upstream `countFileRecords` walk).
pub fn list(d: &[u8]) -> Option<Vec<SecondaryRecord>> {
    if !is_arj(d) {
        return None;
    }
    let mut off = first_record_offset(d)?;
    let mut out = Vec::new();
    while off < d.len() && out.len() < MAX_ENTRIES {
        let e = read_entry(d, off)?;
        if e.end_of_archive {
            break;
        }
        out.push(SecondaryRecord {
            name: e.name,
            size: u64::from(e.original),
            packed_size: u64::from(e.compressed),
            // Upstream ARJ records never set FPART_PROP_ISFOLDER, even
            // for file_type 3 entries.
            is_directory: false,
            modified: format_dos(e.dos_dt),
            data_offset: (off + e.header) as u64,
            method: u32::from(e.method),
        });
        off = off
            .checked_add(e.header)?
            .checked_add(e.compressed as usize)?;
    }
    Some(out)
}

//! Minimal TIFF/EXIF IFD parsing ported from upstream `XTiff::isValid`,
//! `getIFDChain`, `getIFDInfo`, `getIFDChunk`, `getChunks` and
//! `getExifCameraName` (DIE-engine `dep/Formats/images/xtiff.cpp` @
//! pinned baseline). Only what `Jpeg.getExifCameraName` needs is
//! implemented: endian detection, the IFD chain walk, and tag records.

/// Upstream `XTIFF_MAX_IFD_TABLES` guard against link loops.
const MAX_IFD_TABLES: usize = 4096;
/// Upstream `XTIFF_MAX_IFD_ENTRIES` guard against pathological tables.
const MAX_IFD_ENTRIES: u64 = 256 * 1024;
/// Size of one TIFF IFD entry (tag, type, count, offset).
const IFD_ENTRY_SIZE: usize = 12;

/// A TIFF tag's resolved data location (upstream `XTiff::CHUNK`).
#[derive(Debug, Clone, Copy)]
pub struct TiffChunk {
    /// Tag id (e.g. 0x010F Make).
    pub tag: u16,
    /// Offset of the tag data inside the TIFF stream.
    pub offset: usize,
    /// Byte size of the tag data.
    pub size: usize,
}

struct IfdInfo {
    offset: usize,
    size: usize,
    count: u16,
    next_offset: u32,
}

/// Detect byte order from the TIFF signature (upstream `getEndian`).
/// Returns `Some(true)` for big-endian, `Some(false)` for little-endian.
fn tiff_endian(data: &[u8]) -> Option<bool> {
    if data.len() < 4 {
        return None;
    }
    if data[0] == b'I' && data[1] == b'I' && data[2] == 0x2A && data[3] == 0 {
        Some(false)
    } else if data[0] == b'M' && data[1] == b'M' && data[2] == 0 && data[3] == 0x2A {
        Some(true)
    } else {
        None
    }
}

fn read_u16(data: &[u8], off: usize, be: bool) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(if be {
        u16::from_be_bytes([b[0], b[1]])
    } else {
        u16::from_le_bytes([b[0], b[1]])
    })
}

fn read_u32(data: &[u8], off: usize, be: bool) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(if be {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    })
}

/// Per-type element size in bytes (upstream `getBaseTypeSize`).
fn base_type_size(t: u16) -> usize {
    match t {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 => 4,
        5 | 10 | 12 => 8,
        _ => 0,
    }
}

/// Parse one IFD table header (upstream `getIFDInfo`).
fn ifd_info(data: &[u8], offset: usize, be: bool) -> Option<IfdInfo> {
    let total = data.len();
    if offset < 8 || total < 14 || offset > total - 6 {
        return None;
    }
    let count = read_u16(data, offset, be)?;
    let table_size = 2usize + IFD_ENTRY_SIZE * count as usize + 4;
    if offset > total - table_size {
        return None;
    }
    let next_field = offset + 2 + IFD_ENTRY_SIZE * count as usize;
    let next_offset = read_u32(data, next_field, be)?;
    Some(IfdInfo {
        offset,
        size: table_size,
        count,
        next_offset,
    })
}

/// Walk the linked IFD chain (upstream `getIFDChain`). Stops at offset 0,
/// visited-table cycles, overlapping tables, and the upstream caps.
fn ifd_chain(data: &[u8], be: bool) -> Vec<IfdInfo> {
    let mut infos = Vec::new();
    let total = data.len();
    if total < 14 {
        return infos;
    }
    let Some(mut table_offset) = read_u32(data, 4, be) else {
        return infos;
    };
    let mut visited = std::collections::HashSet::new();
    let mut total_entries: u64 = 0;
    while table_offset != 0 && infos.len() < MAX_IFD_TABLES {
        if !visited.insert(table_offset) {
            break;
        }
        let Some(info) = ifd_info(data, table_offset as usize, be) else {
            break;
        };
        if total_entries > MAX_IFD_ENTRIES - u64::from(info.count) {
            break;
        }
        // Distinct IFDs cannot share structural bytes.
        let overlaps = infos.iter().any(|p: &IfdInfo| {
            info.offset < p.offset + p.size && p.offset < info.offset + info.size
        });
        if overlaps {
            break;
        }
        total_entries += u64::from(info.count);
        infos.push(info);
        table_offset = infos.last().map(|i| i.next_offset).unwrap_or(0);
    }
    infos
}

/// Upstream `XTiff::isValid`: size >= 14, known endian, at least one IFD.
pub fn tiff_is_valid(data: &[u8]) -> bool {
    if data.len() < 14 {
        return false;
    }
    let Some(be) = tiff_endian(data) else {
        return false;
    };
    !ifd_chain(data, be).is_empty()
}

/// Resolve one IFD entry to its data location (upstream `getIFDChunk`).
fn ifd_chunk(data: &[u8], entry_off: usize, be: bool) -> Option<TiffChunk> {
    let total = data.len();
    if total < IFD_ENTRY_SIZE || entry_off > total - IFD_ENTRY_SIZE {
        return None;
    }
    let tag = read_u16(data, entry_off, be)?;
    let ty = read_u16(data, entry_off + 2, be)?;
    let count = read_u32(data, entry_off + 4, be)? as usize;
    let base = base_type_size(ty);
    if base == 0 || count == 0 {
        return None;
    }
    let size = base.checked_mul(count)?;
    let mut offset = entry_off + 8;
    if size > 4 {
        offset = read_u32(data, offset, be)? as usize;
        if size > total || offset > total - size {
            return None;
        }
    }
    Some(TiffChunk { tag, offset, size })
}

/// Collect all tag chunks across the IFD chain (upstream `getChunks`).
pub fn tiff_chunks(data: &[u8]) -> Vec<TiffChunk> {
    let mut result = Vec::new();
    let Some(be) = tiff_endian(data) else {
        return result;
    };
    for info in ifd_chain(data, be) {
        let mut entry_off = info.offset + 2;
        for _ in 0..info.count {
            if let Some(chunk) = ifd_chunk(data, entry_off, be) {
                result.push(chunk);
            }
            entry_off += IFD_ENTRY_SIZE;
        }
    }
    result
}

/// Read an ANSI string (up to the first NUL) at `offset`/`size` inside the
/// TIFF stream.
fn tiff_ansi_string(data: &[u8], offset: usize, size: usize) -> String {
    if offset >= data.len() || size == 0 {
        return String::new();
    }
    let len = size.min(data.len() - offset);
    let raw = &data[offset..offset + len];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Upstream `XTiff::getExifCameraName`: `Make(Model)` from tags 0x010F and
/// 0x0110 of a valid TIFF stream, empty when neither is present.
pub fn exif_camera_name(tiff_data: &[u8]) -> String {
    if !tiff_is_valid(tiff_data) {
        return String::new();
    }
    let chunks = tiff_chunks(tiff_data);
    let make = chunks
        .iter()
        .find(|c| c.tag == 0x10F)
        .map(|c| tiff_ansi_string(tiff_data, c.offset, c.size))
        .unwrap_or_default();
    let model = chunks
        .iter()
        .find(|c| c.tag == 0x110)
        .map(|c| tiff_ansi_string(tiff_data, c.offset, c.size))
        .unwrap_or_default();
    if make.is_empty() && model.is_empty() {
        return String::new();
    }
    format!("{make}({model})")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal little-endian TIFF with one Make tag.
    fn tiff_with_make() -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(b"II\x2A\x00");
        d.extend_from_slice(&8u32.to_le_bytes()); // IFD at 8
        // IFD: count=1, entry (tag 0x10F, type ASCII(2), count 6, offset 26),
        // next=0.
        d.extend_from_slice(&1u16.to_le_bytes());
        d.extend_from_slice(&0x10Fu16.to_le_bytes());
        d.extend_from_slice(&2u16.to_le_bytes());
        d.extend_from_slice(&6u32.to_le_bytes());
        d.extend_from_slice(&26u32.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        // Data at 26.
        d.extend_from_slice(b"Canon\0");
        d
    }

    #[test]
    fn tiff_camera_name_make_only() {
        let d = tiff_with_make();
        assert_eq!(exif_camera_name(&d), "Canon()");
    }

    #[test]
    fn tiff_invalid_rejected() {
        assert!(!tiff_is_valid(b"not a tiff"));
        assert_eq!(exif_camera_name(b"xxxx"), "");
    }
}

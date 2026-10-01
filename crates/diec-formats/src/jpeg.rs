//! JPEG chunk parsing ported from upstream `XJpeg::getChunks` /
//! `_readChunk` / `isValid` (DIE-engine `dep/Formats/images/xjpeg.cpp`
//! @ pinned baseline).
//!
//! A buffer is a valid JPEG only when the marker chain starts with SOI,
//! every segment is well-formed, entropy-coded data after SOS is skipped
//! correctly (stuffed 0xFF00 and restart markers), and the walk terminates
//! at EOI. Files truncated before EOI are rejected, matching upstream.

/// Minimum size upstream requires before probing (`JPEG_MIN_SIZE`).
const JPEG_MIN_SIZE: usize = 20;
/// Size of the two-byte marker prefix (`JPEG_SIGNATURE_SIZE`).
const SIGNATURE_SIZE: usize = 2;
/// Marker (2) + length field (2) (`JPEG_SEGMENT_HEADER_SIZE`).
const SEGMENT_HEADER_SIZE: usize = 4;
/// Offset of TIFF data inside an APP1 segment (`JPEG_EXIF_DATA_OFFSET`).
const EXIF_DATA_OFFSET: usize = 10;
/// Upstream `JPEG_MAX_CHUNK_COUNT` guard against pathological files.
const MAX_CHUNK_COUNT: usize = 65536;

const MARKER_PREFIX: u8 = 0xFF;
const MARKER_STUFFED_ZERO: u8 = 0x00;
const MARKER_SOI: u8 = 0xD8;
const MARKER_EOI: u8 = 0xD9;
const MARKER_SOS: u8 = 0xDA;
const MARKER_DQT: u8 = 0xDB;
const MARKER_APP1: u8 = 0xE1;
const MARKER_COM: u8 = 0xFE;
const MARKER_TEM: u8 = 0x01;

/// A parsed JPEG marker segment (upstream `XJpeg::CHUNK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JpegChunk {
    /// Marker identifier (byte after 0xFF).
    pub id: u8,
    /// File offset of the marker prefix.
    pub data_offset: usize,
    /// Total segment size including the two marker bytes.
    pub data_size: usize,
    /// True for the synthetic entropy-coded-data record upstream inserts
    /// after SOS.
    pub entropy: bool,
}

/// Whether a marker carries no length field (upstream `isMarkerWithoutLength`).
fn is_restart_marker(id: u8) -> bool {
    (0xD0..=0xD7).contains(&id)
}

/// Whether a marker carries no length field (upstream `isMarkerWithoutLength`).
fn is_marker_without_length(id: u8) -> bool {
    id == MARKER_SOI || id == MARKER_EOI || id == MARKER_TEM || is_restart_marker(id)
}

/// Read one marker segment at `offset` (upstream `XJpeg::_readChunk`).
/// Returns `None` when the bytes at `offset` do not form a valid segment.
fn read_chunk(data: &[u8], offset: usize) -> Option<JpegChunk> {
    let total = data.len();
    if offset + SIGNATURE_SIZE > total {
        return None;
    }
    if data[offset] != MARKER_PREFIX {
        return None;
    }
    let id = *data.get(offset + 1)?;
    let data_size = if is_marker_without_length(id) {
        SIGNATURE_SIZE
    } else if id != MARKER_STUFFED_ZERO && id != MARKER_PREFIX {
        if offset + SEGMENT_HEADER_SIZE > total {
            return None;
        }
        let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        if length < 2 {
            return None;
        }
        SIGNATURE_SIZE + length
    } else {
        return None;
    };
    if data_size > total - offset {
        return None;
    }
    Some(JpegChunk {
        id,
        data_offset: offset,
        data_size,
        entropy: false,
    })
}

/// Walk the JPEG marker chain (upstream `XJpeg::getChunks`).
///
/// Returns the chunk list only when the chain completes at EOI; any
/// malformed segment or missing EOI yields an empty list, exactly like
/// upstream (`bComplete` gate).
pub fn jpeg_chunks(data: &[u8]) -> Vec<JpegChunk> {
    let total = data.len();
    let mut result = Vec::new();
    let mut offset = 0usize;
    let mut complete = false;

    // The loop has exits beyond `read_chunk` failing (count cap, non-SOI
    // first chunk, missing post-SOS marker), so `loop` stays clearer than
    // `while let`.
    #[allow(clippy::while_let_loop)]
    loop {
        let Some(chunk) = read_chunk(data, offset) else {
            break;
        };
        if result.len() >= MAX_CHUNK_COUNT {
            result.clear();
            return result;
        }
        if result.is_empty() && chunk.id != MARKER_SOI {
            break;
        }
        let next = chunk.data_offset + chunk.data_size;
        result.push(chunk);

        offset = next;

        if chunk.id == MARKER_SOS {
            let data_offset = offset;
            let mut entropy_end = total;
            let mut next_marker = None;
            // Scan entropy-coded data for the next real marker, skipping
            // stuffed 0xFF00 bytes and restart markers.
            while offset < total {
                let Some(prefix) = data[offset..].iter().position(|&b| b == MARKER_PREFIX) else {
                    break;
                };
                let prefix_off = offset + prefix;
                if prefix_off >= total - 1 {
                    break;
                }
                let mut id_off = prefix_off + 1;
                while id_off < total && data[id_off] == MARKER_PREFIX {
                    id_off += 1;
                }
                if id_off >= total {
                    break;
                }
                let id = data[id_off];
                if id == MARKER_STUFFED_ZERO || is_restart_marker(id) {
                    offset = id_off + 1;
                    continue;
                }
                entropy_end = prefix_off;
                next_marker = Some(id_off - 1);
                break;
            }

            if entropy_end > data_offset {
                if result.len() >= MAX_CHUNK_COUNT {
                    result.clear();
                    return result;
                }
                result.push(JpegChunk {
                    id: 0,
                    data_offset,
                    data_size: entropy_end - data_offset,
                    entropy: true,
                });
            }

            let Some(next_off) = next_marker else {
                break;
            };
            offset = next_off;
        }

        if chunk.id == MARKER_EOI {
            complete = true;
            break;
        }
    }

    if !complete {
        result.clear();
    }
    result
}

/// Upstream `XJpeg::isValid`: minimum size, one of the three accepted
/// signature forms, and a complete SOI..EOI chunk chain.
pub fn jpeg_is_valid(data: &[u8]) -> bool {
    if data.len() < JPEG_MIN_SIZE {
        return false;
    }
    let signature_ok =
        (data.len() >= 11 && data[0..4] == [0xFF, 0xD8, 0xFF, 0xE0] && &data[6..11] == b"JFIF\0")
            || (data.len() >= 12
                && data[0..4] == [0xFF, 0xD8, 0xFF, 0xE1]
                && &data[6..12] == b"Exif\0\0")
            || data[0..4] == [0xFF, 0xD8, 0xFF, 0xDB];
    if !signature_ok {
        return false;
    }
    let chunks = jpeg_chunks(data);
    !chunks.is_empty()
        && !chunks[0].entropy
        && chunks[0].id == MARKER_SOI
        && !chunks[chunks.len() - 1].entropy
        && chunks[chunks.len() - 1].id == MARKER_EOI
}

/// Whether the chunk list contains a segment with marker `id`
/// (upstream `XJpeg::isChunkPresent`).
pub fn is_chunk_present(chunks: &[JpegChunk], id: u8) -> bool {
    chunks.iter().any(|c| c.id == id)
}

/// Concatenate all COM segment payloads (upstream `XJpeg::getComment`):
/// at most 100 bytes total, `\r`/`\n` stripped, ANSI string semantics
/// (reads stop at the first NUL byte).
pub fn jpeg_comment(data: &[u8], chunks: &[JpegChunk]) -> String {
    const MAX_COMMENT: usize = 100;
    let mut result = String::new();
    for chunk in chunks.iter().filter(|c| c.id == MARKER_COM) {
        let remaining = MAX_COMMENT.saturating_sub(result.len());
        if remaining == 0 {
            break;
        }
        if chunk.data_size < SEGMENT_HEADER_SIZE
            || chunk.data_offset > data.len()
            || chunk.data_size > data.len() - chunk.data_offset
        {
            continue;
        }
        let start = chunk.data_offset + SEGMENT_HEADER_SIZE;
        let len = remaining.min(chunk.data_size - SEGMENT_HEADER_SIZE);
        let raw = &data[start..start + len];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        result.push_str(&String::from_utf8_lossy(&raw[..end]));
    }
    result.replace(['\r', '\n'], "")
}

/// Collect the concatenated payloads of all DQT segments for hashing
/// (upstream `XJpeg::getDqtMD5` feeds every DQT payload to MD5).
pub fn jpeg_dqt_payloads(data: &[u8], chunks: &[JpegChunk]) -> Vec<u8> {
    let mut buf = Vec::new();
    for chunk in chunks.iter().filter(|c| c.id == MARKER_DQT) {
        if chunk.data_size < SEGMENT_HEADER_SIZE
            || chunk.data_offset > data.len()
            || chunk.data_size > data.len() - chunk.data_offset
        {
            continue;
        }
        let start = chunk.data_offset + SEGMENT_HEADER_SIZE;
        buf.extend_from_slice(&data[start..chunk.data_offset + chunk.data_size]);
    }
    buf
}

/// Locate the EXIF (TIFF) block inside the first APP1 segment carrying the
/// `Exif\0\0` preamble (upstream `XJpeg::getExif`). Returns the offset and
/// size of the embedded TIFF data.
pub fn jpeg_exif(data: &[u8], chunks: &[JpegChunk]) -> Option<(usize, usize)> {
    let chunk = chunks.iter().find(|c| c.id == MARKER_APP1)?;
    if chunk.data_size <= EXIF_DATA_OFFSET
        || chunk.data_size > data.len().saturating_sub(chunk.data_offset)
    {
        return None;
    }
    let start = chunk.data_offset + SEGMENT_HEADER_SIZE;
    if data.get(start..start + 6)? != b"Exif\0\0" {
        return None;
    }
    Some((
        chunk.data_offset + EXIF_DATA_OFFSET,
        chunk.data_size - EXIF_DATA_OFFSET,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal structurally complete JPEG: SOI + DQT + EOI.
    fn minimal_jpeg() -> Vec<u8> {
        let mut d = vec![0xFF, 0xD8];
        // DQT segment: FF DB, length 67 (2+65), 64-byte table + Pq/Tq byte.
        d.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43]);
        d.extend_from_slice(&[0u8; 65]);
        d.extend_from_slice(&[0xFF, 0xD9]);
        d
    }

    #[test]
    fn jpeg_dqt_only_is_valid() {
        let d = minimal_jpeg();
        assert!(jpeg_is_valid(&d));
        let chunks = jpeg_chunks(&d);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].id, MARKER_SOI);
        assert_eq!(chunks[2].id, MARKER_EOI);
    }

    #[test]
    fn truncated_jpeg_is_rejected() {
        let d = minimal_jpeg();
        // Drop EOI.
        assert!(!jpeg_is_valid(&d[..d.len() - 2]));
        assert!(jpeg_chunks(&d[..d.len() - 2]).is_empty());
    }

    #[test]
    fn bare_magic_is_rejected() {
        let d = [0xFF, 0xD8, 0xFF, 0x00];
        assert!(!jpeg_is_valid(&d));
    }

    #[test]
    fn comment_chunk_text() {
        let mut d = vec![0xFF, 0xD8];
        // COM: FF FE <len=2+5> "hello"
        d.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x07]);
        d.extend_from_slice(b"hello");
        d.extend_from_slice(&[0xFF, 0xD9]);
        let chunks = jpeg_chunks(&d);
        // Signature gate requires JFIF/Exif/DQT form; use raw chunks here.
        assert_eq!(jpeg_comment(&d, &chunks), "hello");
    }

    #[test]
    fn sos_entropy_skip() {
        let mut d = vec![0xFF, 0xD8];
        d.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43]);
        d.extend_from_slice(&[0u8; 65]);
        // SOS header.
        d.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08]);
        d.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
        // Entropy data with stuffed FF and restart marker.
        d.extend_from_slice(&[0x11, 0xFF, 0x00, 0x22, 0xFF, 0xD0, 0x33]);
        d.extend_from_slice(&[0xFF, 0xD9]);
        assert!(jpeg_is_valid(&d));
        let chunks = jpeg_chunks(&d);
        assert!(chunks.iter().any(|c| c.entropy));
    }
}

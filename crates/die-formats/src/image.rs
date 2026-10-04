//! Image format probes (CAP-DISPATCH-007).
//!
//! - JPEG: magic `\xFF\xD8\xFF`.
//! - PNG: magic `\x89PNG\r\n\x1A\n` (8 bytes).

use crate::probe::{FormatProbe, ProbeError, ProbeOutcome, strong_deferred};
use die_core::format::FileType;
use die_core::input::ByteView;

/// JPEG format probe.
#[derive(Debug, Default)]
pub struct JpegProbe;

/// PNG format probe.
#[derive(Debug, Default)]
pub struct PngProbe;

/// JPEG magic: `\xFF\xD8\xFF`.
const JPEG_MAGIC: [u8; 3] = [0xFF, 0xD8, 0xFF];
/// PNG magic: `\x89PNG\r\n\x1A\n`.
const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

impl FormatProbe for JpegProbe {
    fn file_type(&self) -> FileType {
        FileType::new("JPEG")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        if view.len() < 4 {
            return Ok(None);
        }
        let mut magic = [0u8; 3];
        view.read_exact_at(0, &mut magic)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("JPEG"),
                cause,
            })?;
        if magic != JPEG_MAGIC {
            return Ok(None);
        }
        // Upstream `XJpeg::isValid`: the buffer must start with one of the
        // JFIF/Exif/DQT signature forms and its marker chain must walk
        // cleanly to EOI — a bare FFD8FF magic is not enough.
        let mut head = [0u8; 12];
        if view.read_exact_at(0, &mut head).is_err() {
            return Ok(None);
        }
        let signature_ok = (head[3] == 0xE0 && &head[6..11] == b"JFIF\0")
            || (head[3] == 0xE1 && &head[6..12] == b"Exif\0\0")
            || head[3] == 0xDB;
        if !signature_ok {
            return Ok(None);
        }
        if !jpeg_walk_to_eoi(view) {
            return Ok(None);
        }
        Ok(Some(ProbeOutcome {
            candidate: strong_deferred("JPEG"),
        }))
    }
}

/// Whether a JPEG marker carries no length field (upstream
/// `isMarkerWithoutLength`: SOI/EOI/TEM and restart markers).
fn jpeg_marker_without_length(id: u8) -> bool {
    id == 0xD8 || id == 0xD9 || id == 0x01 || (0xD0..=0xD7).contains(&id)
}

/// Walk the marker chain like upstream `XJpeg::getChunks`, returning true
/// only when the walk terminates at an EOI marker.
fn jpeg_walk_to_eoi(view: &ByteView<'_>) -> bool {
    const MAX_CHUNKS: u32 = 65536;
    let size = view.len();
    let mut off = 0u64;
    let mut count = 0u32;
    let mut complete = false;

    while count < MAX_CHUNKS {
        // _readChunk: marker prefix + id + optional BE16 length.
        if off + 2 > size || view.read_u8(off).unwrap_or(0) != 0xFF {
            break;
        }
        let id = view.read_u8(off + 1).unwrap_or(0);
        let seg_size = if jpeg_marker_without_length(id) {
            2u64
        } else if id != 0x00 && id != 0xFF {
            if off + 4 > size {
                break;
            }
            let len = u64::from(view.read_u16_be(off + 2).unwrap_or(0));
            if len < 2 {
                break;
            }
            2 + len
        } else {
            break;
        };
        if seg_size > size - off {
            break;
        }
        if count == 0 && id != 0xD8 {
            break;
        }
        count += 1;
        off += seg_size;

        if id == 0xDA {
            // SOS: skip entropy-coded data until the next real marker,
            // passing over stuffed 0xFF00 bytes and restart markers.
            let mut next_marker = None;
            while off < size {
                // Find the next 0xFF.
                let mut prefix = None;
                let mut scan = off;
                while scan < size {
                    let n = (size - scan).min(4096);
                    let mut buf = vec![0u8; n as usize];
                    if view.read_exact_at(scan, &mut buf).is_err() {
                        break;
                    }
                    if let Some(p) = buf.iter().position(|&b| b == 0xFF) {
                        prefix = Some(scan + p as u64);
                        break;
                    }
                    scan += n;
                }
                let Some(p_off) = prefix else { break };
                if p_off >= size - 1 {
                    break;
                }
                let mut id_off = p_off + 1;
                while id_off < size && view.read_u8(id_off).unwrap_or(0) == 0xFF {
                    id_off += 1;
                }
                if id_off >= size {
                    break;
                }
                let mid = view.read_u8(id_off).unwrap_or(0);
                if mid == 0x00 || (0xD0..=0xD7).contains(&mid) {
                    off = id_off + 1;
                    continue;
                }
                next_marker = Some(id_off - 1);
                break;
            }
            let Some(next) = next_marker else { break };
            count += 1; // entropy-coded pseudo chunk
            if count >= MAX_CHUNKS {
                return false;
            }
            off = next;
        }

        if id == 0xD9 {
            complete = true;
            break;
        }
    }
    complete
}

/// Maximum chunks walked by the structural check (bound used by upstream
/// `XPNG::_getStructuredSize` is `PNG_MAX_CHUNK_COUNT`).
const PNG_MAX_CHUNKS: u32 = 1024;
/// Block size used when streaming chunk data through the CRC32 check.
const CRC_BLOCK: u64 = 64 * 1024;

/// CRC-32 (IEEE 802.3) table, lazily initialized.
fn crc32_table() -> &'static [u32; 256] {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        t
    })
}

/// Accumulate CRC-32 over `data` into `crc` (init/final-xor applied by
/// `crc32_ieee_finish`).
fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let t = crc32_table();
    let mut c = crc;
    for &b in data {
        c = t[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    c
}

/// CRC-32 of the PNG chunk contents: `name ++ data`, checked against the
/// trailing CRC field — mirrors upstream `XPNG::_isChunkCRCValid`.
fn chunk_crc_valid(view: &ByteView<'_>, off: u64, name: &[u8; 4], data_size: u64) -> bool {
    let mut crc = crc32_update(0xFFFF_FFFF, name);
    let mut pos = off + 8;
    let mut left = data_size;
    let mut buf = [0u8; CRC_BLOCK as usize];
    while left > 0 {
        let n = left.min(CRC_BLOCK) as usize;
        if view.read_exact_at(pos, &mut buf[..n]).is_err() {
            return false;
        }
        crc = crc32_update(crc, &buf[..n]);
        pos += n as u64;
        left -= n as u64;
    }
    let stored = view.read_u32_be(off + 8 + data_size).unwrap_or(u32::MAX);
    !crc == stored
}

/// PNG color-type/bit-depth validity (PNG spec combinations, as enforced by
/// upstream `isValidPngColorDepth`).
fn valid_png_color_depth(color_type: u8, depth: u8) -> bool {
    match color_type {
        0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
        2 | 4 | 6 => matches!(depth, 8 | 16),
        3 => matches!(depth, 1 | 2 | 4 | 8),
        _ => false,
    }
}

/// Structural validation mirroring upstream `XPNG::_getStructuredSize`
/// (Formats/images/xpng.cpp): a well-formed IHDR followed by a CRC-checked
/// chunk chain that ends in IEND with at least one non-empty IDAT.
fn is_valid_png(view: &ByteView<'_>) -> bool {
    let size = view.len();
    if size < 33 {
        return false;
    }
    let mut magic = [0u8; 8];
    if view.read_exact_at(0, &mut magic).is_err() || magic != PNG_MAGIC {
        return false;
    }

    // First chunk must be IHDR with a 13-byte body.
    if view.read_u32_be(8).unwrap_or(0) != 13 {
        return false;
    }
    let mut name = [0u8; 4];
    if view.read_exact_at(12, &mut name).is_err() || &name != b"IHDR" {
        return false;
    }
    let width = view.read_u32_be(16).unwrap_or(0);
    let height = view.read_u32_be(20).unwrap_or(0);
    let depth = view.read_u8(24).unwrap_or(0);
    let color_type = view.read_u8(25).unwrap_or(0);
    let compression = view.read_u8(26).unwrap_or(0xFF);
    let filter = view.read_u8(27).unwrap_or(0xFF);
    let interlace = view.read_u8(28).unwrap_or(0xFF);
    if width == 0
        || height == 0
        || !valid_png_color_depth(color_type, depth)
        || compression != 0
        || filter != 0
        || interlace > 1
    {
        return false;
    }

    let mut has_palette = false;
    let mut has_image_data = false;
    let mut has_nonempty_idat = false;
    let mut image_data_ended = false;
    let mut off = 8u64;

    for _ in 0..PNG_MAX_CHUNKS {
        // Chunk: len(4) + name(4) + data + crc(4) = 12 + data.
        if off > size.saturating_sub(12) {
            return false;
        }
        let data_size = u64::from(view.read_u32_be(off).unwrap_or(0));
        if data_size > size - off - 12 {
            return false;
        }
        if view.read_exact_at(off + 4, &mut name).is_err()
            || !name.iter().all(|c| c.is_ascii_alphabetic())
        {
            return false;
        }
        if !chunk_crc_valid(view, off, &name, data_size) {
            return false;
        }
        let data_off = off + 8;
        off += 12 + data_size;

        match &name {
            b"IHDR" => {
                if data_off != 16 {
                    return false;
                }
            }
            b"PLTE" => {
                let entries = data_size / 3;
                if has_palette
                    || has_image_data
                    || data_size == 0
                    || data_size % 3 != 0
                    || entries > 256
                    || (color_type == 3 && entries > (1u64 << depth))
                    || color_type == 0
                    || color_type == 4
                {
                    return false;
                }
                has_palette = true;
            }
            b"IDAT" => {
                if image_data_ended || (color_type == 3 && !has_palette) {
                    return false;
                }
                has_image_data = true;
                has_nonempty_idat |= data_size != 0;
            }
            b"IEND" => {
                return data_size == 0 && has_image_data && has_nonempty_idat;
            }
            _ => {
                image_data_ended |= has_image_data;
                // Unknown critical chunk (uppercase first letter).
                if name[0].is_ascii_uppercase() {
                    return false;
                }
            }
        }
    }
    false
}

impl FormatProbe for PngProbe {
    fn file_type(&self) -> FileType {
        FileType::new("PNG")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        if view.len() < 8 {
            return Ok(None);
        }
        let mut magic = [0u8; 8];
        view.read_exact_at(0, &mut magic)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("PNG"),
                cause,
            })?;
        if magic != PNG_MAGIC {
            return Ok(None);
        }
        Ok(is_valid_png(view).then_some(ProbeOutcome {
            candidate: strong_deferred("PNG"),
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::probe::FormatProbe;
    use die_core::format::FormatStrength;
    use die_core::input::{ByteRange, ByteSource, ByteView, MemorySource};

    fn view_of<'a>(src: &'a MemorySource<'a>) -> ByteView<'a> {
        ByteView::new(src, ByteRange::new(0, src.len()).unwrap()).unwrap()
    }

    /// Build a minimal structurally valid JPEG matching upstream
    /// `XJpeg::isValid`: SOI + JFIF APP0 + EOI.
    fn minimal_jpeg() -> Vec<u8> {
        let mut d = vec![0xFF, 0xD8];
        d.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        d.extend_from_slice(b"JFIF\0");
        d.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
        d.extend_from_slice(&[0xFF, 0xD9]);
        d
    }

    #[test]
    fn jpeg_matches() {
        let data = minimal_jpeg();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = JpegProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "JPEG");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
    }

    #[test]
    fn jpeg_truncated_no_eoi_does_not_match() {
        // Upstream XJpeg::getChunks requires the marker chain to reach EOI.
        let data = minimal_jpeg();
        let src = MemorySource::new(&data[..data.len() - 2]);
        let view = view_of(&src);
        assert!(JpegProbe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn jpeg_too_short_does_not_match() {
        let data = [0xFFu8, 0xD8];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = JpegProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    /// Append a PNG chunk (len + name + data + CRC32) to `d`.
    fn png_chunk(d: &mut Vec<u8>, name: &[u8; 4], data: &[u8]) {
        d.extend_from_slice(&(data.len() as u32).to_be_bytes());
        d.extend_from_slice(name);
        d.extend_from_slice(data);
        let mut crc = crc32_update(0xFFFF_FFFF, name);
        crc = crc32_update(crc, data);
        d.extend_from_slice(&(!crc).to_be_bytes());
    }

    /// Build a minimal structurally valid PNG (IHDR + 1-byte IDAT + IEND).
    pub(crate) fn minimal_png() -> Vec<u8> {
        let mut d = PNG_MAGIC.to_vec();
        let ihdr = [
            0, 0, 0, 1, // width = 1
            0, 0, 0, 1, // height = 1
            8, // bit depth
            2, // color type: truecolor
            0, // compression
            0, // filter
            0, // interlace
        ];
        png_chunk(&mut d, b"IHDR", &ihdr);
        png_chunk(&mut d, b"IDAT", &[0x00]);
        png_chunk(&mut d, b"IEND", &[]);
        d
    }

    #[test]
    fn png_matches() {
        let data = minimal_png();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PngProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PNG");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
    }

    #[test]
    fn png_magic_only_does_not_match() {
        // Bare 8-byte signature: upstream XPNG::isValid requires a valid
        // IHDR + chunk chain.
        let data = PNG_MAGIC.to_vec();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(PngProbe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn png_bad_chunk_crc_does_not_match() {
        let mut data = minimal_png();
        // Corrupt the IHDR CRC.
        let n = PNG_MAGIC.len() + 8 + 13;
        data[n] ^= 0xFF;
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(PngProbe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn png_too_short_does_not_match() {
        let data = &PNG_MAGIC[..4];
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = PngProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    // --- Malformed / non-matching tests ---

    #[test]
    fn jpeg_non_jpeg_does_not_match() {
        let data = [0xFFu8, 0xD8, 0x00, 0xE0]; // third byte should be 0xFF
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = JpegProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn png_non_png_does_not_match() {
        let data = [0x89u8, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0B]; // last byte wrong
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PngProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    // --- Boundary tests: exact minimum size ---

    #[test]
    fn jpeg_boundary_exact_3_bytes_does_not_match() {
        // Bare magic is insufficient under upstream XJpeg::isValid.
        let data = &JPEG_MAGIC;
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = JpegProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn jpeg_boundary_2_bytes_does_not_match() {
        let data = &JPEG_MAGIC[..2];
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = JpegProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn png_boundary_exact_8_bytes_does_not_match() {
        // Magic alone is not enough: upstream XPNG::isValid requires the
        // IHDR chunk and a CRC-checked chunk chain.
        let data = &PNG_MAGIC;
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = PngProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn png_boundary_7_bytes_does_not_match() {
        let data = &PNG_MAGIC[..7];
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = PngProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn empty_input_does_not_match_any_image() {
        let data: [u8; 0] = [];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(JpegProbe.probe(&view).unwrap().is_none());
        assert!(PngProbe.probe(&view).unwrap().is_none());
    }
}

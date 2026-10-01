//! JPEG host-API helpers backed by the chunk walker in
//! `diec_formats::jpeg` (upstream `XJpeg`/`Jpeg_Script` @ pinned baseline).

use diec_formats::jpeg;
use diec_formats::tiff;
use md5::{Digest, Md5};

/// Upstream `Jpeg_Script::isChunkPresent`: marker `id` appears in the
/// chunk list of a complete SOI..EOI JPEG.
pub fn is_chunk_present(data: &[u8], id: u8) -> bool {
    let chunks = jpeg::jpeg_chunks(data);
    jpeg::is_chunk_present(&chunks, id)
}

/// Upstream `Jpeg_Script::getComment`: concatenated COM segment payloads,
/// 100-byte cap, CR/LF stripped.
pub fn get_comment(data: &[u8]) -> String {
    let chunks = jpeg::jpeg_chunks(data);
    jpeg::jpeg_comment(data, &chunks)
}

/// Upstream `Jpeg_Script::getDqtMD5`: MD5 (lowercase hex) over the
/// concatenated payloads of every DQT segment.
pub fn get_dqt_md5(data: &[u8]) -> String {
    let chunks = jpeg::jpeg_chunks(data);
    let payload = jpeg::jpeg_dqt_payloads(data, &chunks);
    if payload.is_empty() {
        return String::new();
    }
    let mut h = Md5::new();
    h.update(&payload);
    format!("{:x}", h.finalize())
}

/// Upstream `Jpeg_Script::getExifCameraName`: TIFF Make/Model from the
/// first APP1 segment carrying an `Exif\0\0` preamble.
pub fn get_exif_camera_name(data: &[u8]) -> String {
    let chunks = jpeg::jpeg_chunks(data);
    let Some((offset, size)) = jpeg::jpeg_exif(data, &chunks) else {
        return String::new();
    };
    let Some(end) = offset.checked_add(size) else {
        return String::new();
    };
    let Some(tiff_data) = data.get(offset..end) else {
        return String::new();
    };
    tiff::exif_camera_name(tiff_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jpeg_with_app1_exif() -> Vec<u8> {
        // TIFF payload: II* + IFD with Make="Canon".
        let mut tiff = Vec::new();
        tiff.extend_from_slice(b"II\x2A\x00");
        tiff.extend_from_slice(&8u32.to_le_bytes());
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&0x10Fu16.to_le_bytes());
        tiff.extend_from_slice(&2u16.to_le_bytes());
        tiff.extend_from_slice(&6u32.to_le_bytes());
        tiff.extend_from_slice(&26u32.to_le_bytes());
        tiff.extend_from_slice(&0u32.to_le_bytes());
        tiff.extend_from_slice(b"Canon\0");

        let mut app1_body = Vec::new();
        app1_body.extend_from_slice(b"Exif\0\0");
        app1_body.extend_from_slice(&tiff);

        let mut d = vec![0xFF, 0xD8];
        d.extend_from_slice(&[0xFF, 0xE1]);
        d.extend_from_slice(&((app1_body.len() + 2) as u16).to_be_bytes());
        d.extend_from_slice(&app1_body);
        d.extend_from_slice(&[0xFF, 0xD9]);
        d
    }

    #[test]
    fn exif_camera_name_from_app1() {
        let d = jpeg_with_app1_exif();
        assert_eq!(get_exif_camera_name(&d), "Canon()");
    }

    #[test]
    fn chunk_present_and_comment() {
        let mut d = vec![0xFF, 0xD8];
        d.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x07]);
        d.extend_from_slice(b"hello");
        d.extend_from_slice(&[0xFF, 0xEE, 0x00, 0x02]);
        d.extend_from_slice(&[0xFF, 0xD9]);
        assert!(is_chunk_present(&d, 0xEE));
        assert!(!is_chunk_present(&d, 0xEF));
        assert_eq!(get_comment(&d), "hello");
    }

    #[test]
    fn dqt_md5_matches_known() {
        let mut d = vec![0xFF, 0xD8];
        d.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43]);
        d.extend_from_slice(&[0u8; 65]);
        d.extend_from_slice(&[0xFF, 0xD9]);
        // MD5 of 65 zero bytes.
        let mut h = Md5::new();
        h.update([0u8; 65]);
        let expect = format!("{:x}", h.finalize());
        assert_eq!(get_dqt_md5(&d), expect);
    }
}

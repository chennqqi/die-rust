//! BMP and WAV (RIFF) format probes.
//!
//! - BMP: magic `BM` (2 bytes). BMP files start with the 2-byte signature
//!   "BM" followed by a 4-byte file size (little-endian).
//! - WAV: RIFF container with `WAVE` format. Magic is `RIFF` at offset 0
//!   (4 bytes) + `WAVE` at offset 8 (4 bytes). Total minimum: 12 bytes.

use crate::probe::{FormatProbe, ProbeError, ProbeOutcome, strong_deferred};
use die_core::format::FileType;
use die_core::input::ByteView;

/// BMP format probe.
#[derive(Debug, Default)]
pub struct BmpProbe;

/// WAV (RIFF/WAVE) format probe.
#[derive(Debug, Default)]
pub struct WavProbe;

/// BMP magic: `BM`.
const BMP_MAGIC: [u8; 2] = [0x42, 0x4D];
/// RIFF magic at offset 0.
const RIFF_MAGIC: [u8; 4] = [0x52, 0x49, 0x46, 0x46];
/// WAVE format at offset 8.
const WAVE_MAGIC: [u8; 4] = [0x57, 0x41, 0x56, 0x45];

impl FormatProbe for BmpProbe {
    fn file_type(&self) -> FileType {
        FileType::new("BMP")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        if view.len() < 2 {
            return Ok(None);
        }
        let mut magic = [0u8; 2];
        view.read_exact_at(0, &mut magic)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("BMP"),
                cause,
            })?;
        if magic == BMP_MAGIC {
            Ok(Some(ProbeOutcome {
                candidate: strong_deferred("BMP"),
            }))
        } else {
            Ok(None)
        }
    }
}

impl FormatProbe for WavProbe {
    fn file_type(&self) -> FileType {
        FileType::new("WAV")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        // WAV needs at least 12 bytes: RIFF(4) + size(4) + WAVE(4).
        if view.len() < 12 {
            return Ok(None);
        }
        let mut riff = [0u8; 4];
        view.read_exact_at(0, &mut riff)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("WAV"),
                cause,
            })?;
        if riff != RIFF_MAGIC {
            return Ok(None);
        }
        let mut wave = [0u8; 4];
        view.read_exact_at(8, &mut wave)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("WAV"),
                cause,
            })?;
        if wave == WAVE_MAGIC {
            Ok(Some(ProbeOutcome {
                candidate: strong_deferred("WAV"),
            }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::FormatProbe;
    use die_core::format::FormatStrength;
    use die_core::input::{ByteRange, ByteSource, ByteView, MemorySource};

    fn view_of<'a>(src: &'a MemorySource<'a>) -> ByteView<'a> {
        ByteView::new(src, ByteRange::new(0, src.len()).unwrap()).unwrap()
    }

    // --- BMP tests ---

    #[test]
    fn bmp_matches() {
        let data = [0x42u8, 0x4D, 0x3A, 0x00, 0x00, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = BmpProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "BMP");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
    }

    #[test]
    fn bmp_too_short_does_not_match() {
        let data = [0x42u8];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = BmpProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn bmp_non_bmp_does_not_match() {
        let data = [0x42u8, 0x43, 0x00, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = BmpProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn bmp_boundary_exact_2_bytes_matches() {
        let data = &BMP_MAGIC;
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = BmpProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn bmp_boundary_1_byte_does_not_match() {
        let data = &BMP_MAGIC[..1];
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = BmpProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn bmp_empty_input_does_not_match() {
        let data: [u8; 0] = [];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = BmpProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    // --- WAV tests ---

    #[test]
    fn wav_matches() {
        let mut data = RIFF_MAGIC.to_vec();
        data.extend_from_slice(&[0x26, 0x00, 0x00, 0x00]); // size
        data.extend_from_slice(&WAVE_MAGIC);
        data.extend_from_slice(&[0u8; 16]);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = WavProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "WAV");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
    }

    #[test]
    fn wav_too_short_does_not_match() {
        let data = [0x52u8, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = WavProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn wav_non_riff_does_not_match() {
        let data = [
            0x52u8, 0x49, 0x46, 0x45, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45,
        ];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = WavProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn wav_riff_but_not_wave_does_not_match() {
        let mut data = RIFF_MAGIC.to_vec();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(b"AVI "); // RIFF but not WAVE
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = WavProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn wav_boundary_exact_12_bytes_matches() {
        let mut data = RIFF_MAGIC.to_vec();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&WAVE_MAGIC);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = WavProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn wav_boundary_11_bytes_does_not_match() {
        let mut data = RIFF_MAGIC.to_vec();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&WAVE_MAGIC[..3]);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = WavProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn wav_empty_input_does_not_match() {
        let data: [u8; 0] = [];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = WavProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }
}

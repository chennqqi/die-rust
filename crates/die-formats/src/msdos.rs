//! MS-DOS format probe.
//!
//! MS-DOS COM and EXE (MZ) detection. The MZ header is the first 2 bytes
//! `0x4D 0x5A` ("MZ"). This is a weak match because many PE files also start
//! with MZ; the PE probe runs after and supersedes with a strong match.

use crate::probe::{FormatProbe, ProbeError, ProbeOutcome, weak};
use die_core::format::FileType;
use die_core::input::ByteView;

/// MS-DOS MZ executable probe.
#[derive(Debug, Default)]
pub struct MsdosProbe;

impl FormatProbe for MsdosProbe {
    fn file_type(&self) -> FileType {
        FileType::new("MSDOS")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        // Need at least 2 bytes for the MZ magic.
        if view.len() < 2 {
            return Ok(None);
        }
        let magic = view.read_u16_le(0).map_err(ProbeError::Io)?;
        // Upstream XMSDOS::isValid accepts both "MZ" (0x5A4D) and the
        // byte-swapped "ZM" (0x4D5A) magics.
        if magic == 0x5A4D || magic == 0x4D5A {
            // Weak because PE/NE/LE files also start with these magics.
            Ok(Some(ProbeOutcome {
                candidate: weak("MSDOS"),
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

    #[test]
    fn mz_magic_matches() {
        let data = [0x4Du8, 0x5A, 0x90, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MsdosProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "MSDOS");
        assert_eq!(outcome.candidate.strength, FormatStrength::Weak);
    }

    #[test]
    fn non_mz_does_not_match() {
        let data = [0x7Fu8, 0x45, 0x4C, 0x46];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MsdosProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn too_short_does_not_match() {
        let data = [0x4Du8];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MsdosProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    // --- Boundary tests ---

    #[test]
    fn boundary_exact_2_bytes_matches() {
        let data = [0x4Du8, 0x5A];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MsdosProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn boundary_1_byte_does_not_match() {
        let data = [0x4Du8];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MsdosProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn empty_input_does_not_match() {
        let data: [u8; 0] = [];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MsdosProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn zm_le_matches() {
        // Upstream XMSDOS::isValid accepts the byte-swapped "ZM" magic.
        let data = [0x5Au8, 0x4D];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MsdosProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "MSDOS");
    }
}

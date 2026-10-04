//! NE / LE / LX executable probes (16-bit OS/2-Windows and VxD formats).
//!
//! All three formats are MZ-based executables distinguished by the
//! signature stored at `e_lfanew` (DWORD at offset 0x3C of the DOS
//! header). This mirrors upstream `XNE::isValid` and `XLE::isValid`:
//!
//! - NE: MZ magic + `lfanew` in range + `u16 @ lfanew == "NE"` (0x454E)
//! - LE: MZ magic + `lfanew` in range + `u32 @ lfanew == "LE\0\0"`
//! - LX: same with `"LX\0\0"`
//!
//! Upstream accepts only the MZ magic here (ZM is a PE/MSDOS quirk), and
//! requires the signature field to lie fully inside the file.

use crate::probe::{FormatProbe, ProbeError, ProbeOutcome, strong_deferred};
use die_core::format::FileType;
use die_core::input::ByteView;

/// MZ DOS header minimum size (upstream reads the full IMAGE_DOS_HEADER).
const MZ_MIN_SIZE: u64 = 64;
/// Offset of `e_lfanew` in the MZ header.
const E_LFANEW_OFFSET: u64 = 0x3C;
/// "MZ" little-endian u16.
const MZ_MAGIC: u16 = 0x5A4D;
/// "NE" little-endian u16 (XNE_DEF::S_IMAGE_OS2_SIGNATURE).
const NE_SIGNATURE: u16 = 0x454E;
/// "LE\0\0" little-endian u32 (XLE_DEF::S_IMAGE_VXD_SIGNATURE).
const LE_SIGNATURE: u32 = 0x454C;
/// "LX\0\0" little-endian u32 (XLE_DEF::S_IMAGE_LX_SIGNATURE).
const LX_SIGNATURE: u32 = 0x584C;

/// Read the secondary header offset (`e_lfanew`) of an MZ file, applying
/// upstream offset validity semantics: the value must be a readable
/// position inside the file.
fn dos_header_offset(view: &ByteView<'_>) -> Option<u64> {
    if view.len() < MZ_MIN_SIZE {
        return None;
    }
    let magic = view.read_u16_le(0).ok()?;
    if magic != MZ_MAGIC {
        return None;
    }
    let lfanew = u64::from(view.read_u32_le(E_LFANEW_OFFSET).ok()?);
    // XNE::getImageOS2HeaderOffset / XLE::getImageVxdHeaderOffset return
    // -1 when lfanew is not a valid offset.
    if lfanew >= view.len() {
        return None;
    }
    Some(lfanew)
}

/// NE (New Executable) probe.
#[derive(Debug, Default)]
pub struct NeProbe;

impl FormatProbe for NeProbe {
    fn file_type(&self) -> FileType {
        FileType::new("NE")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        let Some(offset) = dos_header_offset(view) else {
            return Ok(None);
        };
        // Upstream requires lfanew+1 to be a valid offset before reading
        // the u16 signature.
        let Ok(sig) = view.read_u16_le(offset) else {
            return Ok(None);
        };
        if sig == NE_SIGNATURE {
            Ok(Some(ProbeOutcome {
                candidate: strong_deferred("NE"),
            }))
        } else {
            Ok(None)
        }
    }
}

/// LE/LX (Linear Executable / VxD) probe.
///
/// Emits file type "LE" for the 0x454C signature and "LX" for 0x584C,
/// matching upstream `XLE::isValid` + `XLE::getFileType`.
#[derive(Debug, Default)]
pub struct LeLxProbe;

impl FormatProbe for LeLxProbe {
    fn file_type(&self) -> FileType {
        FileType::new("LE")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        let Some(offset) = dos_header_offset(view) else {
            return Ok(None);
        };
        // Upstream requires lfanew+3 to be a valid offset before reading
        // the u32 signature.
        let Ok(sig) = view.read_u32_le(offset) else {
            return Ok(None);
        };
        let name = match sig {
            LE_SIGNATURE => "LE",
            LX_SIGNATURE => "LX",
            _ => return Ok(None),
        };
        Ok(Some(ProbeOutcome {
            candidate: strong_deferred(name),
        }))
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

    /// Build an MZ file with the given 4-byte signature at e_lfanew=0x10.
    fn build_mz_sig(sig: &[u8; 4]) -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[0x3C..0x40].copy_from_slice(&0x10u32.to_le_bytes());
        buf[0x10..0x14].copy_from_slice(sig);
        buf
    }

    #[test]
    fn ne_matches() {
        let data = build_mz_sig(b"NE\0\0");
        let src = MemorySource::new(&data);
        let outcome = NeProbe.probe(&view_of(&src)).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "NE");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
    }

    #[test]
    fn le_matches() {
        let data = build_mz_sig(b"LE\0\0");
        let src = MemorySource::new(&data);
        let outcome = LeLxProbe.probe(&view_of(&src)).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "LE");
    }

    #[test]
    fn lx_matches() {
        let data = build_mz_sig(b"LX\0\0");
        let src = MemorySource::new(&data);
        let outcome = LeLxProbe.probe(&view_of(&src)).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "LX");
    }

    #[test]
    fn mocks_ne_layout_matches() {
        // corkami mocks_ne.bin layout: "MZ" + magic 0x000F + e_lfanew=0x10
        // + "NE\0\0" + "KULE NE" + trailing zeroes, 64 bytes total.
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0x4D, 0x5A, 0x0F, 0x00]);
        buf[4..10].copy_from_slice(b"MZ mag");
        buf[0x3C..0x40].copy_from_slice(&0x10u32.to_le_bytes());
        buf[0x10..0x14].copy_from_slice(b"NE\0\0");
        let src = MemorySource::new(&buf);
        assert!(NeProbe.probe(&view_of(&src)).unwrap().is_some());
        assert!(LeLxProbe.probe(&view_of(&src)).unwrap().is_none());
    }

    #[test]
    fn non_mz_does_not_match() {
        let data = [0x7Fu8; 64];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(NeProbe.probe(&view).unwrap().is_none());
        assert!(LeLxProbe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn zm_magic_does_not_match() {
        // Upstream XNE/XLE accept only MZ, not the swapped ZM magic.
        let mut data = build_mz_sig(b"NE\0\0");
        data[0] = 0x5A;
        data[1] = 0x4D;
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(NeProbe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn lfanew_out_of_bounds_does_not_match() {
        let mut data = build_mz_sig(b"NE\0\0");
        data[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(NeProbe.probe(&view).unwrap().is_none());
        assert!(LeLxProbe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn truncated_signature_does_not_match() {
        // lfanew at size-1: signature read is out of bounds.
        let mut buf = vec![0u8; 64];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[0x3C..0x40].copy_from_slice(&63u32.to_le_bytes());
        let src = MemorySource::new(&buf);
        let view = view_of(&src);
        assert!(NeProbe.probe(&view).unwrap().is_none());
        assert!(LeLxProbe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn short_file_does_not_match() {
        let data = [0x4Du8, 0x5A, 0x90, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(NeProbe.probe(&view).unwrap().is_none());
        assert!(LeLxProbe.probe(&view).unwrap().is_none());
    }
}

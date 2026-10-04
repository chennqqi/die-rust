//! `die-formats` provides format probing and safe parsing, returning format
//! facts via checked input.
//!
//! It does not decide whether to scan overlays, enable aggressive mode or
//! which rule to run first. Format candidates are driven by an explicit,
//! versioned ordered probe table. Parsers access bytes only through
//! `die-core`'s checked input and never write final detections or read the
//! rule database. See `docs/design/architecture.md` section 8.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod archive;
pub mod dex_class_pyc;
pub mod elf;
pub mod image;
pub mod image_extra;
pub mod jpeg;
pub mod macho;
pub mod msdos;
pub mod ne_lx;
pub mod pdf_cfbf;
pub mod pe;
pub mod probe;
pub mod tiff;

pub use probe::{FormatProbe, PROBE_TABLE_VERSION, ProbeError, ProbeOutcome, ProbeTable};

/// Placeholder retained for backward compatibility; format modules land in
/// Phase 2.
pub fn placeholder() -> &'static str {
    "die-formats"
}

#[cfg(test)]
mod tests {
    use super::*;
    use die_core::format::FormatStrength;
    use die_core::input::{ByteRange, ByteSource, ByteView, MemorySource};

    fn view_of<'a>(src: &'a MemorySource<'a>) -> ByteView<'a> {
        ByteView::new(src, ByteRange::new(0, src.len()).unwrap()).unwrap()
    }

    #[test]
    fn placeholder_is_reachable() {
        assert_eq!(placeholder(), "die-formats");
    }

    #[test]
    fn default_table_detects_pe32() {
        let mut buf = vec![0u8; 256];
        // MZ magic
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        // e_lfanew -> 0x80
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE sig
        buf[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);
        // PE32 opt magic at 0x98
        buf[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes());
        let src = MemorySource::new(&buf);
        let view = view_of(&src);
        let table = ProbeTable::default_phase2();
        let (cands, errs) = table.probe_all(&view);
        assert!(errs.is_empty(), "unexpected errors: {errs:?}");
        // MSDOS weak + PE32 strong
        assert_eq!(cands.len(), 2);
        assert_eq!(cands[0].file_type.name, "MSDOS");
        assert_eq!(cands[0].strength, FormatStrength::Weak);
        assert_eq!(cands[1].file_type.name, "PE32");
        assert_eq!(cands[1].strength, FormatStrength::Strong);
    }

    #[test]
    fn default_table_detects_elf64() {
        let data = [0x7Fu8, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let table = ProbeTable::default_phase2();
        let (cands, errs) = table.probe_all(&view);
        assert!(errs.is_empty());
        // Only ELF matches (MSDOS/PE/Mach-O do not)
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].file_type.name, "ELF64");
        assert_eq!(cands[0].strength, FormatStrength::Strong);
    }

    #[test]
    fn default_table_detects_macho_64() {
        // Minimal structurally valid Mach-O 64 BE header (ncmds=0).
        let mut data = 0xFEEDFACFu32.to_be_bytes().to_vec();
        data.extend_from_slice(&7u32.to_be_bytes()); // cputype
        data.extend_from_slice(&3u32.to_be_bytes()); // cpusubtype
        data.extend_from_slice(&2u32.to_be_bytes()); // filetype = EXECUTE
        data.extend_from_slice(&0u32.to_be_bytes()); // ncmds
        data.extend_from_slice(&0u32.to_be_bytes()); // sizeofcmds
        data.extend_from_slice(&0u32.to_be_bytes()); // flags
        data.extend_from_slice(&0u32.to_be_bytes()); // reserved
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let table = ProbeTable::default_phase2();
        let (cands, errs) = table.probe_all(&view);
        assert!(errs.is_empty());
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].file_type.name, "Mach-O 64");
    }

    #[test]
    fn default_table_detects_zip() {
        // Minimal ZIP: end-of-central-directory record only.
        let mut data = vec![0x50u8, 0x4B, 0x05, 0x06];
        data.extend_from_slice(&[0u8; 18]);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let table = ProbeTable::default_phase2();
        let (cands, errs) = table.probe_all(&view);
        assert!(errs.is_empty());
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].file_type.name, "ZIP");
    }

    #[test]
    fn default_table_detects_pdf() {
        let data = b"%PDF-1.4\nrest";
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let table = ProbeTable::default_phase2();
        let (cands, errs) = table.probe_all(&view);
        assert!(errs.is_empty());
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].file_type.name, "PDF");
    }

    #[test]
    fn default_table_detects_dex() {
        let data = b"dex\n035\0extra";
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let table = ProbeTable::default_phase2();
        let (cands, errs) = table.probe_all(&view);
        assert!(errs.is_empty());
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].file_type.name, "DEX");
    }

    #[test]
    fn default_table_detects_png() {
        let data = crate::image::tests::minimal_png();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let table = ProbeTable::default_phase2();
        let (cands, errs) = table.probe_all(&view);
        assert!(errs.is_empty());
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].file_type.name, "PNG");
    }

    #[test]
    fn default_table_no_match_for_unknown() {
        let data = [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let table = ProbeTable::default_phase2();
        let (cands, errs) = table.probe_all(&view);
        assert!(cands.is_empty());
        assert!(errs.is_empty());
    }

    #[test]
    fn default_table_empty_input_no_match() {
        let data: [u8; 0] = [];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let table = ProbeTable::default_phase2();
        let (cands, errs) = table.probe_all(&view);
        assert!(cands.is_empty());
        assert!(errs.is_empty());
    }

    // --- Property-based tests (deterministic, no external dependency) ---
    // These tests generate random byte sequences and verify that the probe
    // table never panics, never hangs, and always returns a consistent
    // (candidates, errors) pair. See testing.md section 14.

    /// Simple xorshift64 PRNG.
    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    fn property_probe_table_never_panics_on_random_input() {
        let table = ProbeTable::default_phase2();
        let mut state: u64 = 0xFEDCBA9876543210;
        for _ in 0..2000 {
            // Generate random-length input (0..512 bytes).
            let len = (xorshift64(&mut state) % 512) as usize;
            let mut data = vec![0u8; len];
            for byte in &mut data {
                *byte = (xorshift64(&mut state) & 0xFF) as u8;
            }
            let src = MemorySource::new(&data);
            let view = view_of(&src);
            let (cands, errs) = table.probe_all(&view);
            // Invariant: candidates and errors are consistent.
            // No candidate should have FormatStrength::None.
            for c in &cands {
                assert_ne!(
                    c.strength,
                    die_core::format::FormatStrength::None,
                    "candidate with None strength"
                );
            }
            // Errors should only be Truncated or InvalidHeader, not Io with
            // a memory source (which never produces I/O errors).
            for e in &errs {
                match e {
                    probe::ProbeError::Truncated { .. }
                    | probe::ProbeError::InvalidHeader { .. } => {}
                    probe::ProbeError::Io(_) => {
                        panic!("MemorySource should not produce Io errors: {e:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn property_probe_table_deterministic() {
        let table = ProbeTable::default_phase2();
        let data: Vec<u8> = (0..128u8).collect();
        let src1 = MemorySource::new(&data);
        let view1 = view_of(&src1);
        let (cands1, errs1) = table.probe_all(&view1);
        // Run again on the same input.
        let src2 = MemorySource::new(&data);
        let view2 = view_of(&src2);
        let (cands2, errs2) = table.probe_all(&view2);
        assert_eq!(cands1, cands2);
        assert_eq!(errs1, errs2);
    }

    #[test]
    fn property_probe_table_all_zeros_no_match() {
        let data = vec![0u8; 512];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let table = ProbeTable::default_phase2();
        let (cands, errs) = table.probe_all(&view);
        assert!(errs.is_empty(), "unexpected errors on all-zeros: {errs:?}");
        // All-zeros should not match any format (MZ is 4D 5A, ELF is 7F 45 4C 46, etc.)
        assert!(
            cands.is_empty(),
            "unexpected candidates on all-zeros: {cands:?}"
        );
    }

    #[test]
    fn property_probe_table_single_byte_no_panic() {
        let table = ProbeTable::default_phase2();
        for b in 0..=255u8 {
            let data = [b];
            let src = MemorySource::new(&data);
            let view = view_of(&src);
            let _ = table.probe_all(&view);
        }
    }
}

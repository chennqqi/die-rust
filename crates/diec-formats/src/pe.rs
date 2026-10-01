//! PE (Portable Executable) format probe.
//!
//! PE files start with the MZ DOS header. The PE signature "PE\0\0" is at
//! the offset stored in `e_lfanew` (DWORD at offset 0x3C). This probe reads
//! the MZ header, validates `e_lfanew`, then checks the PE signature. A
//! successful PE match is strong and supersedes the weak MSDOS match.
//!
//! This mirrors upstream `XPE::isValid` (xpe.cpp): the check is only the
//! MZ/ZM magic plus `0 < e_lfanew < file_size` plus the 4-byte NT signature.
//! The COFF and optional headers are NOT validated — files whose headers
//! are truncated or carry an unknown optional-header magic still classify
//! as PE upstream, and so do here. The PE32/PE64 distinction follows
//! `XPE::getMode`/`getFileType`: it is derived from the COFF `Machine`
//! field (AMD64/IA64/ARM64/ALPHA64/RISCV64/LOONGARCH64 => PE64), not from
//! the optional header magic; unreadable or unknown machines are PE32.

use crate::probe::{FormatProbe, ProbeError, ProbeOutcome, strong_deferred};
use diec_core::format::FileType;
use diec_core::input::ByteView;

/// PE format probe.
#[derive(Debug, Default)]
pub struct PeProbe;

/// MZ DOS header minimum size (upstream reads the full IMAGE_DOS_HEADER).
const MZ_MIN_SIZE: u64 = 64;
/// Offset of `e_lfanew` in the MZ header.
const E_LFANEW_OFFSET: u64 = 0x3C;
/// PE signature "PE\0\0" (test fixtures).
#[cfg(test)]
const PE_SIGNATURE: [u8; 4] = [0x50, 0x45, 0x00, 0x00];
/// PE signature "PE\0\0" as a little-endian u32.
const PE_SIGNATURE_U32: u32 = 0x0000_4550;
/// Offset of the optional header magic from the PE signature.
/// PE sig (4) + COFF header (20) = 24.
const OPT_HDR_MAGIC_OFFSET_FROM_SIG: u64 = 24;
/// PE32 optional header magic (test fixtures; upstream no longer reads it).
#[cfg(test)]
const PE32_MAGIC: u16 = 0x010B;
/// PE64 (PE32+) optional header magic (test fixtures).
#[cfg(test)]
const PE64_MAGIC: u16 = 0x020B;

/// COFF machine type: i386.
pub const COFF_MACHINE_I386: u16 = 0x014C;
/// COFF machine type: AMD64.
pub const COFF_MACHINE_AMD64: u16 = 0x8664;
/// COFF machine type: ARM.
pub const COFF_MACHINE_ARM: u16 = 0x01C0;
/// COFF machine type: ARM64.
pub const COFF_MACHINE_ARM64: u16 = 0xAA64;
/// COFF machine type: IA64.
pub const COFF_MACHINE_IA64: u16 = 0x0200;
/// COFF machine type: Alpha AXP 64-bit.
pub const COFF_MACHINE_ALPHA64: u16 = 0x0284;
/// COFF machine type: RISC-V 64-bit.
pub const COFF_MACHINE_RISCV64: u16 = 0x5064;
/// COFF machine type: LoongArch 64-bit.
pub const COFF_MACHINE_LOONGARCH64: u16 = 0x6264;
/// Native-OS override XOR mask (XPE_DEF::S_IMAGE_FILE_MACHINE_NATIVE_OS_OVERRIDE_LINUX).
const MACHINE_NATIVE_OS_OVERRIDE_LINUX: u16 = 0x7B79;

/// COFF machine types that upstream `XPE::getMode` classifies as 64-bit.
fn is_machine_64bit(machine: u16) -> bool {
    matches!(
        machine,
        COFF_MACHINE_AMD64
            | COFF_MACHINE_IA64
            | COFF_MACHINE_ARM64
            | COFF_MACHINE_ALPHA64
            | COFF_MACHINE_RISCV64
            | COFF_MACHINE_LOONGARCH64
    )
}

/// Apply upstream `XPE::_getMachine` normalization: a machine value XORed
/// with the Linux native-OS override is reported as plain AMD64.
fn get_machine(machine: u16) -> u16 {
    if machine == (MACHINE_NATIVE_OS_OVERRIDE_LINUX ^ COFF_MACHINE_AMD64) {
        COFF_MACHINE_AMD64
    } else {
        machine
    }
}

/// PE header metadata extracted during probing.
///
/// This structure contains fields from the COFF and optional headers that
/// are useful for format identification and downstream rule matching. Full
/// section/table parsing is deferred.
#[derive(Debug, Clone)]
pub struct PeHeaderInfo {
    /// PE format name: "PE32" or "PE64".
    pub format_name: &'static str,
    /// COFF machine type (e.g., 0x014C for i386, 0x8664 for AMD64).
    pub machine: u16,
    /// Number of sections.
    pub number_of_sections: u16,
    /// Optional header magic (0x010B for PE32, 0x020B for PE64).
    pub opt_magic: u16,
    /// Address of the entry point (RVA).
    pub entry_point: u32,
    /// Size of the code (text) section.
    pub size_of_code: u32,
}

/// Map COFF machine type to a human-readable architecture name.
pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        COFF_MACHINE_I386 => "i386",
        COFF_MACHINE_AMD64 => "AMD64",
        COFF_MACHINE_ARM => "ARM",
        COFF_MACHINE_ARM64 => "ARM64",
        COFF_MACHINE_IA64 => "IA64",
        _ => "unknown",
    }
}

impl FormatProbe for PeProbe {
    fn file_type(&self) -> FileType {
        FileType::new("PE32")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        // Need at least the MZ DOS header (upstream reads the full
        // IMAGE_DOS_HEADER before consulting e_lfanew).
        if view.len() < MZ_MIN_SIZE {
            return Ok(None);
        }

        // Check MZ or ZM magic (both are accepted by XMSDOS/XPE upstream).
        let mz_magic = view.read_u16_le(0).map_err(ProbeError::Io)?;
        if mz_magic != 0x5A4D && mz_magic != 0x4D5A {
            return Ok(None);
        }

        // Read e_lfanew (offset to PE header).
        let e_lfanew = view.read_u32_le(E_LFANEW_OFFSET).map_err(ProbeError::Io)?;
        let pe_sig_offset = u64::from(e_lfanew);

        // Upstream: `lfanew > 0 && lfanew < size`, then a bounds-checked
        // u32 read of the NT signature (out-of-bounds reads yield 0).
        if e_lfanew == 0 || pe_sig_offset >= view.len() {
            return Ok(None);
        }
        let Ok(sig) = view.read_u32_le(pe_sig_offset) else {
            return Ok(None);
        };
        if sig != PE_SIGNATURE_U32 {
            return Ok(None);
        }

        // COFF machine sits 4 bytes after the signature. Out-of-bounds
        // reads upstream return 0, which classifies as PE32 via getMode.
        let machine = view
            .read_u16_le(pe_sig_offset + 4)
            .map(get_machine)
            .unwrap_or(0);
        let name = if is_machine_64bit(machine) {
            "PE64"
        } else {
            "PE32"
        };

        // Best-effort metadata for downstream consumers. Fields that fall
        // outside the file simply stay zero — upstream performs the same
        // bounds-checked reads in its header accessors.
        let coff_offset = pe_sig_offset + 4;
        let opt_hdr_offset = pe_sig_offset + OPT_HDR_MAGIC_OFFSET_FROM_SIG;
        let _info = PeHeaderInfo {
            format_name: name,
            machine,
            number_of_sections: view.read_u16_le(coff_offset + 2).unwrap_or(0),
            opt_magic: view.read_u16_le(opt_hdr_offset).unwrap_or(0),
            entry_point: view.read_u32_le(opt_hdr_offset + 16).unwrap_or(0),
            size_of_code: view.read_u32_le(opt_hdr_offset + 4).unwrap_or(0),
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
    use diec_core::format::FormatStrength;
    use diec_core::input::{ByteRange, ByteSource, ByteView, MemorySource};

    fn view_of<'a>(src: &'a MemorySource<'a>) -> ByteView<'a> {
        ByteView::new(src, ByteRange::new(0, src.len()).unwrap()).unwrap()
    }

    /// Build a minimal PE32 image with the given optional header magic.
    fn build_minimal_pe(opt_magic: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        // MZ magic
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        // e_lfanew at 0x3C -> points to offset 0x80
        let e_lfanew: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        // PE signature at 0x80
        buf[0x80..0x84].copy_from_slice(&PE_SIGNATURE);
        // Optional header magic at 0x80 + 24 = 0x98
        buf[0x98..0x9A].copy_from_slice(&opt_magic.to_le_bytes());
        buf
    }

    #[test]
    fn pe32_matches() {
        let data = build_minimal_pe(PE32_MAGIC);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PeProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PE32");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
        assert!(outcome.candidate.deferred_parse);
    }

    #[test]
    fn pe64_matches() {
        // Upstream classifies PE64 by the COFF machine, not the optional
        // header magic (XPE::getMode/getFileType).
        let data = build_pe_with_fields(PE64_MAGIC, COFF_MACHINE_AMD64, 0, 0, 0);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PeProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PE64");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
    }

    #[test]
    fn pe64_classified_by_machine_not_opt_magic() {
        // PE32 magic + AMD64 machine: upstream reports PE64.
        let data = build_pe_with_fields(PE32_MAGIC, COFF_MACHINE_AMD64, 0, 0, 0);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PeProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PE64");
    }

    #[test]
    fn pe64_machines_cover_upstream_set() {
        for machine in [
            COFF_MACHINE_AMD64,
            COFF_MACHINE_IA64,
            COFF_MACHINE_ARM64,
            COFF_MACHINE_ALPHA64,
            COFF_MACHINE_RISCV64,
            COFF_MACHINE_LOONGARCH64,
        ] {
            let data = build_pe_with_fields(0, machine, 0, 0, 0);
            let src = MemorySource::new(&data);
            let view = view_of(&src);
            let outcome = PeProbe.probe(&view).unwrap().unwrap();
            assert_eq!(
                outcome.candidate.file_type.name, "PE64",
                "machine 0x{machine:04X}"
            );
        }
    }

    #[test]
    fn zm_magic_is_accepted() {
        // Upstream XPE::isValid accepts both MZ and ZM magics.
        let mut data = build_minimal_pe(PE32_MAGIC);
        data[0] = 0x5A;
        data[1] = 0x4D;
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let outcome = PeProbe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PE32");
    }

    #[test]
    fn sig_only_pe32_matches() {
        // mocks_pe.bin-style: MZ + e_lfanew + "PE\0\0" but zero COFF/opt
        // header. Upstream accepts this as PE32 (machine reads as 0).
        let mut buf = vec![0u8; 64];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[0x3C..0x40].copy_from_slice(&0x10u32.to_le_bytes());
        buf[0x10..0x14].copy_from_slice(&PE_SIGNATURE);
        let src = MemorySource::new(&buf);
        let view = view_of(&src);
        let outcome = PeProbe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PE32");
    }

    #[test]
    fn pe_sig_at_last_byte_does_not_match() {
        // lfanew < size but the 4-byte signature read is out of bounds;
        // upstream's bounds-checked read yields 0 -> no match.
        let mut buf = vec![0u8; 68];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[0x3C..0x40].copy_from_slice(&67u32.to_le_bytes());
        let src = MemorySource::new(&buf);
        let view = view_of(&src);
        assert!(PeProbe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn non_pe_does_not_match() {
        let data = [0x7Fu8, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PeProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn mz_without_pe_sig_does_not_match() {
        let mut buf = vec![0u8; 128];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        // e_lfanew points to offset 0x40, but no PE sig there
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        let src = MemorySource::new(&buf);
        let view = view_of(&src);
        let probe = PeProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn too_short_does_not_match() {
        let data = [0x4Du8, 0x5A, 0x90, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PeProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn unknown_opt_magic_still_matches() {
        // Upstream does not read the optional header magic at all: an
        // unknown value still classifies as PE32 (machine reads as 0).
        let data = build_minimal_pe(0xABCD);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PeProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PE32");
    }

    #[test]
    fn e_lfanew_pointing_outside_file_does_not_match() {
        let mut buf = vec![0u8; 256];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        // e_lfanew = u32::MAX -> points way outside the file
        buf[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        let src = MemorySource::new(&buf);
        let view = view_of(&src);
        let probe = PeProbe;
        // Not a valid PE since e_lfanew points outside the file.
        assert!(probe.probe(&view).unwrap().is_none());
    }

    // --- Header field extraction tests ---

    /// Build a PE with specific COFF machine and optional header fields.
    fn build_pe_with_fields(
        opt_magic: u16,
        machine: u16,
        sections: u16,
        entry: u32,
        code_size: u32,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        let e_lfanew: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        // PE signature at 0x80
        buf[0x80..0x84].copy_from_slice(&PE_SIGNATURE);
        // COFF header at 0x84: Machine (u16), NumberOfSections (u16)
        buf[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        buf[0x86..0x88].copy_from_slice(&sections.to_le_bytes());
        // Optional header at 0x98 (0x80 + 24)
        buf[0x98..0x9A].copy_from_slice(&opt_magic.to_le_bytes());
        // SizeOfCode at opt+4 = 0x9C
        buf[0x9C..0xA0].copy_from_slice(&code_size.to_le_bytes());
        // AddressOfEntryPoint at opt+16 = 0xA8
        buf[0xA8..0xAC].copy_from_slice(&entry.to_le_bytes());
        buf
    }

    #[test]
    fn pe_with_amd64_machine_does_not_panic() {
        let data = build_pe_with_fields(PE64_MAGIC, COFF_MACHINE_AMD64, 3, 0x1000, 0x200);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PeProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PE64");
    }

    #[test]
    fn pe_with_i386_machine_does_not_panic() {
        let data = build_pe_with_fields(PE32_MAGIC, COFF_MACHINE_I386, 1, 0x500, 0x100);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PeProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PE32");
    }

    #[test]
    fn pe_with_zero_machine_still_matches() {
        // Machine=0 is invalid but the probe should still identify PE format.
        let data = build_pe_with_fields(PE32_MAGIC, 0, 0, 0, 0);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PeProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PE32");
    }

    #[test]
    fn machine_name_mapping() {
        assert_eq!(machine_name(COFF_MACHINE_I386), "i386");
        assert_eq!(machine_name(COFF_MACHINE_AMD64), "AMD64");
        assert_eq!(machine_name(COFF_MACHINE_ARM), "ARM");
        assert_eq!(machine_name(COFF_MACHINE_ARM64), "ARM64");
        assert_eq!(machine_name(COFF_MACHINE_IA64), "IA64");
        assert_eq!(machine_name(0xFFFF), "unknown");
    }

    #[test]
    fn pe_boundary_exact_min_size_matches() {
        // Minimum for full header extraction:
        // e_lfanew=0x40, PE sig at 0x40, COFF at 0x44, opt at 0x58.
        // Need opt+20 (entry_point at opt+16 needs 4 bytes) = 0x58+20 = 0x6C.
        let mut buf = vec![0u8; 0x6C];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(&PE_SIGNATURE);
        buf[0x58..0x5A].copy_from_slice(&PE32_MAGIC.to_le_bytes());
        let src = MemorySource::new(&buf);
        let view = view_of(&src);
        let probe = PeProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn pe_signature_only_still_matches_when_headers_truncated() {
        // Upstream validates only the NT signature: a file whose COFF and
        // optional headers extend past EOF still classifies as PE32.
        let mut buf = vec![0u8; 0x6B];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(&PE_SIGNATURE);
        buf[0x58..0x5A].copy_from_slice(&PE32_MAGIC.to_le_bytes());
        let src = MemorySource::new(&buf);
        let view = view_of(&src);
        let outcome = PeProbe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PE32");
    }

    #[test]
    fn pe_empty_input_does_not_match() {
        let data: [u8; 0] = [];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PeProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }
}

//! ELF (Executable and Linkable Format) probe.
//!
//! ELF files start with the magic `\x7FELF`. The class byte at offset 4
//! distinguishes ELF32 (1) from ELF64 (2). This probe also extracts the
//! data encoding (EI_DATA), OS/ABI (EI_OSABI), and object type (e_type)
//! as metadata for downstream rule matching.

use crate::probe::{FormatProbe, ProbeError, ProbeOutcome, strong_deferred};
use diec_core::format::FileType;
use diec_core::input::ByteView;

/// ELF format probe.
#[derive(Debug, Default)]
pub struct ElfProbe;

/// ELF magic: `\x7FELF`.
const ELF_MAGIC: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];
/// Offset of the class byte (EI_CLASS).
const EI_CLASS_OFFSET: u64 = 4;
/// Offset of the data encoding byte (EI_DATA).
const EI_DATA_OFFSET: u64 = 5;
/// Offset of the OS/ABI byte (EI_OSABI).
const EI_OSABI_OFFSET: u64 = 7;
/// ELFCLASS32.
const ELFCLASS32: u8 = 1;
/// ELFCLASS64.
const ELFCLASS64: u8 = 2;
/// ELFDATA2LSB (little-endian).
pub const ELFDATA2LSB: u8 = 1;
/// ELFDATA2MSB (big-endian).
pub const ELFDATA2MSB: u8 = 2;

/// ELF object type: ET_NONE.
pub const ET_NONE: u16 = 0;
/// ELF object type: ET_REL (relocatable).
pub const ET_REL: u16 = 1;
/// ELF object type: ET_EXEC (executable).
pub const ET_EXEC: u16 = 2;
/// ELF object type: ET_DYN (shared object).
pub const ET_DYN: u16 = 3;
/// ELF object type: ET_CORE (core dump).
pub const ET_CORE: u16 = 4;

/// ELF header metadata extracted during probing.
#[derive(Debug, Clone)]
pub struct ElfHeaderInfo {
    /// Format name: "ELF32" or "ELF64".
    pub format_name: &'static str,
    /// EI_CLASS: 1=ELF32, 2=ELF64.
    pub class: u8,
    /// EI_DATA: 1=LSB, 2=MSB.
    pub data: u8,
    /// EI_OSABI (e.g., 0=SYSV, 3=Linux, 2=NetBSD).
    pub osabi: u8,
    /// e_type: object type (ET_EXEC, ET_DYN, etc.).
    pub e_type: u16,
}

/// Map EI_DATA to endianness name.
pub fn data_name(data: u8) -> &'static str {
    match data {
        ELFDATA2LSB => "LSB",
        ELFDATA2MSB => "MSB",
        _ => "unknown",
    }
}

/// Map e_type to object type name.
pub fn type_name(e_type: u16) -> &'static str {
    match e_type {
        ET_NONE => "NONE",
        ET_REL => "REL",
        ET_EXEC => "EXEC",
        ET_DYN => "DYN",
        ET_CORE => "CORE",
        _ => "unknown",
    }
}

impl FormatProbe for ElfProbe {
    fn file_type(&self) -> FileType {
        FileType::new("ELF")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        // Need at least 5 bytes: 4 magic + 1 class byte.
        if view.len() < 5 {
            return Ok(None);
        }

        // Read and verify ELF magic.
        let mut magic = [0u8; 4];
        view.read_exact_at(0, &mut magic)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("ELF"),
                cause,
            })?;
        if magic != ELF_MAGIC {
            return Ok(None);
        }

        // Read class byte to distinguish ELF32 vs ELF64.
        let class = view
            .read_u8(EI_CLASS_OFFSET)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("ELF"),
                cause,
            })?;

        let name = match class {
            ELFCLASS32 => "ELF32",
            ELFCLASS64 => "ELF64",
            _ => {
                return Err(ProbeError::InvalidHeader {
                    file_type: FileType::new("ELF"),
                    detail: format!("unknown ELF class: {class}"),
                });
            }
        };

        // Extract additional header fields if available (non-fatal).
        // EI_DATA at offset 5, EI_OSABI at offset 7.
        let data = if view.len() > EI_DATA_OFFSET {
            view.read_u8(EI_DATA_OFFSET).unwrap_or(0)
        } else {
            0
        };
        let osabi = if view.len() > EI_OSABI_OFFSET {
            view.read_u8(EI_OSABI_OFFSET).unwrap_or(0)
        } else {
            0
        };

        // e_type is at offset 16 (after the 16-byte e_ident).
        // For ELF32, the header continues after e_ident.
        // e_type is a u16 at offset 16, endianness depends on EI_DATA.
        let e_type = if view.len() >= 18 {
            if data == ELFDATA2MSB {
                view.read_u16_be(16).unwrap_or(0)
            } else {
                view.read_u16_le(16).unwrap_or(0)
            }
        } else {
            0
        };

        let _info = ElfHeaderInfo {
            format_name: name,
            class,
            data,
            osabi,
            e_type,
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

    #[test]
    fn elf32_matches() {
        let mut data = vec![0x7Fu8, 0x45, 0x4C, 0x46, ELFCLASS32];
        data.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "ELF32");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
        assert!(outcome.candidate.deferred_parse);
    }

    #[test]
    fn elf64_matches() {
        let mut data = vec![0x7Fu8, 0x45, 0x4C, 0x46, ELFCLASS64];
        data.extend_from_slice(&[0x02, 0x01, 0x00, 0x00]);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "ELF64");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
    }

    #[test]
    fn non_elf_does_not_match() {
        let data = [0x4Du8, 0x5A, 0x90, 0x00, 0x01];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn too_short_does_not_match() {
        let data = [0x7Fu8, 0x45, 0x4C];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn unknown_class_returns_error() {
        let data = [0x7Fu8, 0x45, 0x4C, 0x46, 0x03];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        let err = probe.probe(&view).unwrap_err();
        assert!(matches!(err, ProbeError::InvalidHeader { .. }));
    }

    // --- Boundary tests ---

    #[test]
    fn boundary_exact_5_bytes_elf32_matches() {
        let data = [0x7Fu8, 0x45, 0x4C, 0x46, 0x01];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn boundary_exact_5_bytes_elf64_matches() {
        let data = [0x7Fu8, 0x45, 0x4C, 0x46, 0x02];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn boundary_4_bytes_does_not_match() {
        let data = [0x7Fu8, 0x45, 0x4C, 0x46];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn class_zero_returns_error() {
        let data = [0x7Fu8, 0x45, 0x4C, 0x46, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        let err = probe.probe(&view).unwrap_err();
        assert!(matches!(err, ProbeError::InvalidHeader { .. }));
    }

    #[test]
    fn empty_input_does_not_match() {
        let data: [u8; 0] = [];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    // --- Header field extraction tests ---

    #[test]
    fn elf_with_data_and_osabi_does_not_panic() {
        // ELF64, LSB, SYSV, e_type=ET_EXEC
        let mut data = vec![0x7F, 0x45, 0x4C, 0x46, ELFCLASS64, ELFDATA2LSB, 0x01, 0x00];
        data.extend_from_slice(&[0u8; 8]); // padding to offset 16
        data.extend_from_slice(&ET_EXEC.to_le_bytes()); // e_type at 16
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "ELF64");
    }

    #[test]
    fn elf_big_endian_e_type_read_correctly() {
        // ELF32, MSB (big-endian), e_type=ET_DYN
        let mut data = vec![0x7F, 0x45, 0x4C, 0x46, ELFCLASS32, ELFDATA2MSB, 0x01, 0x00];
        data.extend_from_slice(&[0u8; 8]); // padding to offset 16
        data.extend_from_slice(&ET_DYN.to_be_bytes()); // e_type at 16 (big-endian)
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn data_name_mapping() {
        assert_eq!(data_name(ELFDATA2LSB), "LSB");
        assert_eq!(data_name(ELFDATA2MSB), "MSB");
        assert_eq!(data_name(0), "unknown");
    }

    #[test]
    fn type_name_mapping() {
        assert_eq!(type_name(ET_NONE), "NONE");
        assert_eq!(type_name(ET_REL), "REL");
        assert_eq!(type_name(ET_EXEC), "EXEC");
        assert_eq!(type_name(ET_DYN), "DYN");
        assert_eq!(type_name(ET_CORE), "CORE");
        assert_eq!(type_name(0xFFFF), "unknown");
    }

    #[test]
    fn elf_short_header_still_matches() {
        // Only 5 bytes: magic + class. No data/osabi/e_type.
        let data = [0x7Fu8, 0x45, 0x4C, 0x46, ELFCLASS32];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ElfProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }
}

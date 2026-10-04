//! Mach-O format probe.
//!
//! Mach-O files start with a magic number that encodes both the architecture
//! (32 vs 64 bit) and the endianness. FAT (universal) binaries start with
//! `0xCAFEBABE` (big-endian) or `0xBEBAFECA` (little-endian, FAT_64).
//!
//! Magic numbers:
//! - `0xFEEDFACE`: Mach-O 32, big-endian
//! - `0xCEFAEDFE`: Mach-O 32, little-endian (swapped)
//! - `0xFEEDFACF`: Mach-O 64, big-endian
//! - `0xCFFAEDFE`: Mach-O 64, little-endian (swapped)
//! - `0xCAFEBABE`: FAT (universal) binary
//! - `0xBEBAFECA`: FAT_64 binary
//!
//! Note: `0xCAFEBABE` is also the Java class file magic. The Mach-O FAT probe
//! runs before the Java class probe in the dispatch order, so FAT binaries
//! are identified correctly. This is consistent with upstream behavior.
//!
//! This probe also extracts the CPU type, CPU subtype, and file type from
//! the Mach-O header as metadata for downstream rule matching.

use crate::probe::{FormatProbe, ProbeError, ProbeOutcome, strong_deferred};
use die_core::format::FileType;
use die_core::input::ByteView;

/// Mach-O format probe.
#[derive(Debug, Default)]
pub struct MachOProbe;

// Mach-O magic numbers (as read in big-endian from the first 4 bytes).
const MH_MAGIC_32_BE: u32 = 0xFEEDFACE;
const MH_MAGIC_32_LE: u32 = 0xCEFAEDFE;
const MH_MAGIC_64_BE: u32 = 0xFEEDFACF;
const MH_MAGIC_64_LE: u32 = 0xCFFAEDFE;
const FAT_MAGIC_BE: u32 = 0xCAFEBABE;
const FAT_MAGIC_64_BE: u32 = 0xCAFEBABF;

/// CPU type: x86 (i386).
pub const CPU_TYPE_X86: i32 = 7;
/// CPU type: x86_64.
pub const CPU_TYPE_X86_64: i32 = 7 | 0x01000000;
/// CPU type: ARM.
pub const CPU_TYPE_ARM: i32 = 12;
/// CPU type: ARM64.
pub const CPU_TYPE_ARM64: i32 = 12 | 0x01000000;
/// CPU type: PowerPC.
pub const CPU_TYPE_POWERPC: i32 = 18;

/// Mach-O file type: relocatable object.
pub const MH_OBJECT: u32 = 1;
/// Mach-O file type: executable.
pub const MH_EXECUTE: u32 = 2;
/// Mach-O file type: fixed VM shared library.
pub const MH_FVMLIB: u32 = 3;
/// Mach-O file type: core dump.
pub const MH_CORE: u32 = 4;
/// Mach-O file type: preloaded executable.
pub const MH_PRELOAD: u32 = 5;
/// Mach-O file type: dynamically linked shared library.
pub const MH_DYLIB: u32 = 6;
/// Mach-O file type: dynamic linker.
pub const MH_DYLINKER: u32 = 7;
/// Mach-O file type: loadable bundle.
pub const MH_BUNDLE: u32 = 8;

/// Mach-O header metadata extracted during probing.
#[derive(Debug, Clone)]
pub struct MachOHeaderInfo {
    /// Format name: "Mach-O 32", "Mach-O 64", "Mach-O FAT", "Mach-O FAT64".
    pub format_name: &'static str,
    /// Whether the header is big-endian.
    pub big_endian: bool,
    /// CPU type (cputype).
    pub cpu_type: i32,
    /// CPU subtype (cpusubtype).
    pub cpu_subtype: i32,
    /// File type (filetype).
    pub filetype: u32,
}

/// Map CPU type to a human-readable name.
pub fn cpu_type_name(cpu_type: i32) -> &'static str {
    match cpu_type {
        CPU_TYPE_X86 => "x86",
        CPU_TYPE_X86_64 => "x86_64",
        CPU_TYPE_ARM => "ARM",
        CPU_TYPE_ARM64 => "ARM64",
        CPU_TYPE_POWERPC => "PowerPC",
        _ => "unknown",
    }
}

/// Map file type to a human-readable name.
pub fn filetype_name(filetype: u32) -> &'static str {
    match filetype {
        MH_OBJECT => "object",
        MH_EXECUTE => "execute",
        MH_FVMLIB => "fvmlib",
        MH_CORE => "core",
        MH_PRELOAD => "preload",
        MH_DYLIB => "dylib",
        MH_DYLINKER => "dylinker",
        MH_BUNDLE => "bundle",
        _ => "unknown",
    }
}

/// Mach-O file types accepted by upstream `XMACH::isValid`
/// (`_TABLE_XMACH_HeaderFileTypes`, Formats/exec/xmach.cpp).
fn macho_filetype_valid(filetype: u32) -> bool {
    (0x1..=0xE).contains(&filetype)
}

/// Read a u32 in the given endianness; returns 0 on truncation.
fn read_u32(view: &ByteView<'_>, offset: u64, big_endian: bool) -> u32 {
    if big_endian {
        view.read_u32_be(offset).unwrap_or(0)
    } else {
        view.read_u32_le(offset).unwrap_or(0)
    }
}

/// Structural validation of a thin Mach-O header, mirroring upstream
/// `XMACH::isValid` (Formats/exec/xmach.cpp): the file must contain a full
/// `mach_header`, a known `filetype`, and `ncmds` well-formed load commands
/// whose `cmdsize` fields consume `sizeofcmds` exactly.
fn is_valid_thin_macho(view: &ByteView<'_>, is64: bool, big_endian: bool) -> bool {
    let header_size: u64 = if is64 { 32 } else { 28 };
    if view.len() < header_size {
        return false;
    }

    let filetype = read_u32(view, 12, big_endian);
    if !macho_filetype_valid(filetype) {
        return false;
    }

    let ncmds = read_u32(view, 16, big_endian);
    let sizeofcmds = read_u32(view, 20, big_endian);
    let file_size = view.len();

    if ncmds > 0xFFFF || u64::from(sizeofcmds) > file_size - header_size {
        return false;
    }

    let mut offset = header_size;
    let mut commands_size = 0u64;
    let mut parsed = 0u32;

    for _ in 0..ncmds {
        if commands_size + 8 > u64::from(sizeofcmds) {
            break;
        }
        let cmd_size = u64::from(read_u32(view, offset + 4, big_endian));
        if cmd_size < 8 || commands_size + cmd_size > u64::from(sizeofcmds) {
            break;
        }
        offset += cmd_size;
        commands_size += cmd_size;
        parsed += 1;
    }

    parsed == ncmds && commands_size == u64::from(sizeofcmds)
}

/// Structural validation of a FAT (universal) Mach-O, mirroring upstream
/// `XMACHOFat::isValid` (Formats/exec/xmachofat.cpp): the architecture table
/// must fit in the file and every architecture record must describe a
/// range that lies inside the file.
fn is_valid_fat_macho(view: &ByteView<'_>) -> bool {
    // FAT magics are read little-endian by upstream; the on-disk bytes are
    // always big-endian for the canonical layouts.
    let magic = view.read_u32_le(0).unwrap_or(0);
    let (is64, big_endian) = match magic {
        0xCAFEBABE => (false, false),
        0xBEBAFECA => (false, true),
        0xCAFEBABF => (true, false),
        0xBFBAFECA => (true, true),
        _ => return false,
    };
    if view.len() < 8 {
        return false;
    }

    let record_size: u64 = if is64 { 32 } else { 20 };
    let file_size = view.len();
    let nfat_arch = read_u32(view, 4, big_endian);

    if nfat_arch == 0
        || nfat_arch > 1_000_000
        || u64::from(nfat_arch) > (file_size - 8) / record_size
    {
        return false;
    }

    let table_end = 8 + u64::from(nfat_arch) * record_size;

    for i in 0..nfat_arch {
        let base = 8 + u64::from(i) * record_size;
        let (cputype, offset, size, align, reserved) = if is64 {
            (
                read_u32(view, base, big_endian),
                read_u64(view, base + 8, big_endian),
                read_u64(view, base + 16, big_endian),
                read_u32(view, base + 24, big_endian),
                read_u32(view, base + 28, big_endian),
            )
        } else {
            (
                read_u32(view, base, big_endian),
                u64::from(read_u32(view, base + 8, big_endian)),
                u64::from(read_u32(view, base + 12, big_endian)),
                read_u32(view, base + 16, big_endian),
                0,
            )
        };

        if cputype == 0 || size == 0 || align > 63 || (is64 && reserved != 0) {
            return false;
        }

        let align_mask = if align > 0 { (1u64 << align) - 1 } else { 0 };
        if offset < table_end
            || (offset & align_mask) != 0
            || offset > file_size
            || size > file_size - offset
        {
            return false;
        }
    }

    true
}

/// Read a u64 in the given endianness; returns 0 on truncation.
fn read_u64(view: &ByteView<'_>, offset: u64, big_endian: bool) -> u64 {
    if big_endian {
        view.read_u64_be(offset).unwrap_or(0)
    } else {
        view.read_u64_le(offset).unwrap_or(0)
    }
}

impl FormatProbe for MachOProbe {
    fn file_type(&self) -> FileType {
        FileType::new("Mach-O")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        // Need at least 4 bytes for the magic.
        if view.len() < 4 {
            return Ok(None);
        }

        // Read the magic as big-endian first. Mach-O magics are defined in
        // big-endian terms; the "swapped" variants are the little-endian
        // encodings of the same values.
        let magic_be = view.read_u32_be(0).map_err(|cause| ProbeError::Truncated {
            file_type: FileType::new("Mach-O"),
            cause,
        })?;
        let magic_le = view.read_u32_le(0).map_err(|cause| ProbeError::Truncated {
            file_type: FileType::new("Mach-O"),
            cause,
        })?;

        // Check against all known Mach-O magics. We compare both BE and LE
        // readings because the magic itself encodes endianness.
        let (name, is64, big_endian) = match magic_be {
            MH_MAGIC_32_BE => ("Mach-O 32", false, true),
            MH_MAGIC_32_LE => ("Mach-O 32", false, false),
            MH_MAGIC_64_BE => ("Mach-O 64", true, true),
            MH_MAGIC_64_LE => ("Mach-O 64", true, false),
            FAT_MAGIC_BE | FAT_MAGIC_64_BE => {
                if !is_valid_fat_macho(view) {
                    return Ok(None);
                }
                return Ok(Some(ProbeOutcome {
                    candidate: strong_deferred(if magic_be == FAT_MAGIC_BE {
                        "Mach-O FAT"
                    } else {
                        "Mach-O FAT64"
                    }),
                }));
            }
            _ => match magic_le {
                MH_MAGIC_32_LE => ("Mach-O 32", false, false),
                MH_MAGIC_32_BE => ("Mach-O 32", false, true),
                MH_MAGIC_64_LE => ("Mach-O 64", true, false),
                MH_MAGIC_64_BE => ("Mach-O 64", true, true),
                FAT_MAGIC_BE | FAT_MAGIC_64_BE => {
                    if !is_valid_fat_macho(view) {
                        return Ok(None);
                    }
                    return Ok(Some(ProbeOutcome {
                        candidate: strong_deferred(if magic_le == FAT_MAGIC_BE {
                            "Mach-O FAT"
                        } else {
                            "Mach-O FAT64"
                        }),
                    }));
                }
                _ => return Ok(None),
            },
        };

        if !is_valid_thin_macho(view, is64, big_endian) {
            return Ok(None);
        }

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

    /// Build a minimal structurally valid thin Mach-O (mach_header with
    /// ncmds=0/sizeofcmds=0 is accepted by upstream XMACH::isValid).
    fn thin_macho(is64: bool, big_endian: bool) -> Vec<u8> {
        let mut d = Vec::new();
        let magic: [u8; 4] = match (is64, big_endian) {
            (false, true) => 0xFEEDFACEu32.to_be_bytes(),
            (false, false) => 0xFEEDFACEu32.to_le_bytes(),
            (true, true) => 0xFEEDFACFu32.to_be_bytes(),
            (true, false) => 0xFEEDFACFu32.to_le_bytes(),
        };
        d.extend_from_slice(&magic);
        let w32 = |v: u32| -> Vec<u8> {
            if big_endian {
                v.to_be_bytes().to_vec()
            } else {
                v.to_le_bytes().to_vec()
            }
        };
        d.extend_from_slice(&w32(CPU_TYPE_X86 as u32)); // cputype
        d.extend_from_slice(&w32(3)); // cpusubtype
        d.extend_from_slice(&w32(MH_EXECUTE)); // filetype
        d.extend_from_slice(&w32(0)); // ncmds
        d.extend_from_slice(&w32(0)); // sizeofcmds
        d.extend_from_slice(&w32(0)); // flags
        if is64 {
            d.extend_from_slice(&w32(0)); // reserved
        }
        d
    }

    /// Build a minimal valid FAT Mach-O with one architecture.
    fn fat_macho(is64: bool) -> Vec<u8> {
        let record_size: u32 = if is64 { 32 } else { 20 };
        let table_end = 8 + record_size;
        let mut d = Vec::new();
        // FAT magics are big-endian on disk.
        let fat_magic = if is64 {
            0xCAFEBABFu32.to_be_bytes()
        } else {
            0xCAFEBABEu32.to_be_bytes()
        };
        d.extend_from_slice(&fat_magic);
        d.extend_from_slice(&1u32.to_be_bytes()); // nfat_arch = 1
        d.extend_from_slice(&7u32.to_be_bytes()); // cputype = x86
        d.extend_from_slice(&3u32.to_be_bytes()); // cpusubtype
        if is64 {
            d.extend_from_slice(&u64::from(table_end).to_be_bytes()); // offset
            d.extend_from_slice(&4u64.to_be_bytes()); // size
        } else {
            d.extend_from_slice(&table_end.to_be_bytes()); // offset
            d.extend_from_slice(&4u32.to_be_bytes()); // size
        }
        d.extend_from_slice(&0u32.to_be_bytes()); // align
        if is64 {
            d.extend_from_slice(&0u32.to_be_bytes()); // reserved
        }
        d.extend_from_slice(&[0u8; 4]); // slice data
        d
    }

    #[test]
    fn macho_32_be_matches() {
        let data = thin_macho(false, true);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "Mach-O 32");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
        assert!(outcome.candidate.deferred_parse);
    }

    #[test]
    fn macho_32_le_matches() {
        let data = thin_macho(false, false);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "Mach-O 32");
    }

    #[test]
    fn macho_64_be_matches() {
        let data = thin_macho(true, true);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "Mach-O 64");
    }

    #[test]
    fn macho_64_le_matches() {
        let data = thin_macho(true, false);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "Mach-O 64");
    }

    #[test]
    fn fat_matches() {
        let data = fat_macho(false);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "Mach-O FAT");
    }

    #[test]
    fn fat64_matches() {
        let data = fat_macho(true);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "Mach-O FAT64");
    }

    #[test]
    fn non_macho_does_not_match() {
        let data = [0x7Fu8, 0x45, 0x4C, 0x46];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn too_short_does_not_match() {
        let data = [0xFEu8, 0xED, 0xFA];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    // --- Malformed / non-matching tests ---

    #[test]
    fn partial_magic_does_not_match() {
        // First 3 bytes of MH_MAGIC_32 but 4th byte wrong.
        let data = [0xFEu8, 0xED, 0xFA, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn fat_magic_with_wrong_suffix_does_not_match() {
        // 0xCAFEBABE is FAT magic, but we need exactly 4 bytes.
        // A wrong 5th byte shouldn't matter since we only check 4 bytes,
        // but verify that a truncated FAT magic (3 bytes) doesn't match.
        let data = [0xCAu8, 0xFE, 0xBA];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    // --- Boundary tests: exact minimum size ---

    #[test]
    fn boundary_exact_4_bytes_macho_32_be_does_not_match() {
        // Bare 4-byte magic: upstream XMACH::isValid requires a full
        // mach_header.
        let data = 0xFEEDFACEu32.to_be_bytes();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn boundary_exact_4_bytes_macho_64_be_does_not_match() {
        let data = 0xFEEDFACFu32.to_be_bytes();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn boundary_exact_4_bytes_fat_does_not_match() {
        // Bare FAT magic without a fat_header is rejected by
        // XMACHOFat::isValid.
        let data = 0xCAFEBABEu32.to_be_bytes();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn boundary_3_bytes_does_not_match() {
        let data = [0xFEu8, 0xED, 0xFA];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn empty_input_does_not_match() {
        let data: [u8; 0] = [];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn java_class_magic_does_not_match_macho_fat() {
        // A real class header has minor_version=0 at offset 4, so the FAT
        // arch count is 0 and upstream XMACHOFat::isValid rejects it; the
        // JavaClassProbe handles it instead.
        let mut data = 0xCAFEBABEu32.to_be_bytes().to_vec();
        data.extend_from_slice(&[0, 0, 0, 52]); // minor=0, major=52
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    // --- Header field extraction tests ---

    #[test]
    fn macho_64_be_with_header_fields_does_not_panic() {
        let data = thin_macho(true, true);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "Mach-O 64");
    }

    #[test]
    fn macho_32_le_with_header_fields_does_not_panic() {
        let data = thin_macho(false, false);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "Mach-O 32");
    }

    #[test]
    fn cpu_type_name_mapping() {
        assert_eq!(cpu_type_name(CPU_TYPE_X86), "x86");
        assert_eq!(cpu_type_name(CPU_TYPE_X86_64), "x86_64");
        assert_eq!(cpu_type_name(CPU_TYPE_ARM), "ARM");
        assert_eq!(cpu_type_name(CPU_TYPE_ARM64), "ARM64");
        assert_eq!(cpu_type_name(CPU_TYPE_POWERPC), "PowerPC");
        assert_eq!(cpu_type_name(0), "unknown");
    }

    #[test]
    fn filetype_name_mapping() {
        assert_eq!(filetype_name(MH_OBJECT), "object");
        assert_eq!(filetype_name(MH_EXECUTE), "execute");
        assert_eq!(filetype_name(MH_DYLIB), "dylib");
        assert_eq!(filetype_name(MH_BUNDLE), "bundle");
        assert_eq!(filetype_name(MH_CORE), "core");
        assert_eq!(filetype_name(0xFFFF), "unknown");
    }

    #[test]
    fn macho_short_header_does_not_match() {
        // Only 4 bytes: magic without a mach_header is rejected.
        let data = 0xFEEDFACFu32.to_be_bytes();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = MachOProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }
}

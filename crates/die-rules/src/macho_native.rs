//! Native Mach-O host API methods backed by the `goblin` crate.
//!
//! This module replaces the hand-written JavaScript Mach-O parsing code in
//! `host_api_bridge.rs` with native Rust implementations using `goblin`.
//! The methods are registered as JavaScript functions on the `MACH` object.
//!
//! Benefits over the JS implementation:
//! - Battle-tested Mach-O parsing (goblin is widely used and fuzzed)
//! - Better performance (no per-byte JS->Rust FFI round-trips)
//! - Correctness guarantees from goblin's validation

use goblin::mach::MachO;

/// Mach-O magic numbers.
const MH_MAGIC: u32 = 0xFEEDFACE;
const MH_CIGAM: u32 = 0xCEFAEDFE;
const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_CIGAM_64: u32 = 0xCFFAEDFE;

/// Check if the data starts with a Mach-O magic.
pub fn is_macho(data: &[u8]) -> bool {
    if data.len() < 28 {
        return false;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    matches!(magic, MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64)
}

/// Safely parse a Mach-O file, catching panics from goblin's unsafe code.
///
/// Returns `None` if the data is not a valid Mach-O or if parsing panics.
fn macho_from_bytes(data: &[u8]) -> Option<MachO<'_>> {
    if !is_macho(data) {
        return None;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| MachO::parse(data, 0)))
        .ok()
        .and_then(|r| r.ok())
}

/// Get the Mach-O import library names (LC_LOAD_DYLIB entries).
///
/// Returns an empty vector if not a valid Mach-O or no imports.
pub fn get_import_libraries(data: &[u8]) -> Vec<String> {
    macho_from_bytes(data)
        .map(|mach| mach.libs.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

/// Get the Mach-O entry point address.
///
/// Returns 0 if not a valid Mach-O.
pub fn get_entry_point(data: &[u8]) -> u64 {
    macho_from_bytes(data).map(|mach| mach.entry).unwrap_or(0)
}

/// Check if the Mach-O file is 64-bit.
///
/// Returns false if not a valid Mach-O.
pub fn is_64bit(data: &[u8]) -> bool {
    macho_from_bytes(data)
        .map(|mach| mach.is_64)
        .unwrap_or(false)
}

/// Check if the Mach-O file is little-endian.
///
/// Returns false if not a valid Mach-O.
pub fn is_little_endian(data: &[u8]) -> bool {
    macho_from_bytes(data)
        .map(|mach| mach.little_endian)
        .unwrap_or(false)
}

/// Get the CPU type from the Mach-O header.
///
/// Returns 0 if not a valid Mach-O.
pub fn get_cpu_type(data: &[u8]) -> u32 {
    macho_from_bytes(data)
        .map(|mach| mach.header.cputype)
        .unwrap_or(0)
}

/// Get the file type from the Mach-O header.
///
/// Returns 0 if not a valid Mach-O.
pub fn get_file_type(data: &[u8]) -> u32 {
    macho_from_bytes(data)
        .map(|mach| mach.header.filetype)
        .unwrap_or(0)
}

/// Get the number of load commands.
///
/// Returns 0 if not a valid Mach-O.
pub fn get_ncmds(data: &[u8]) -> u32 {
    macho_from_bytes(data)
        .map(|mach| mach.header.ncmds as u32)
        .unwrap_or(0)
}

/// Get all section names from all segments.
///
/// Returns an empty vector if not a valid Mach-O or no sections.
pub fn get_section_names(data: &[u8]) -> Vec<String> {
    let mach = macho_from_bytes(data);
    let Some(mach) = mach else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for segment in &mach.segments {
        if let Ok(sections) = segment.sections() {
            for (section, _section_data) in sections {
                if let Ok(name) = section.name() {
                    names.push(name.to_string());
                }
            }
        }
    }
    names
}

/// Get the number of sections across all segments.
///
/// Returns 0 if not a valid Mach-O.
pub fn get_number_of_sections(data: &[u8]) -> usize {
    let mach = macho_from_bytes(data);
    let Some(mach) = mach else {
        return 0;
    };
    let mut count = 0;
    for segment in &mach.segments {
        if let Ok(sections) = segment.sections() {
            count += sections.len();
        }
    }
    count
}

/// Get the number of segments (LC_SEGMENT/LC_SEGMENT_64 commands).
///
/// Returns 0 if not a valid Mach-O.
pub fn get_number_of_segments(data: &[u8]) -> usize {
    macho_from_bytes(data)
        .map(|mach| mach.segments.iter().count())
        .unwrap_or(0)
}

/// Get the number of libraries (LC_LOAD_DYLIB entries).
///
/// Returns 0 if not a valid Mach-O.
pub fn get_number_of_libraries(data: &[u8]) -> usize {
    macho_from_bytes(data)
        .map(|mach| mach.libs.len())
        .unwrap_or(0)
}

/// Check if a section name is present.
///
/// Returns false if not a valid Mach-O or section not found.
pub fn is_section_name_present(data: &[u8], name: &str) -> bool {
    get_section_names(data).iter().any(|n| n == name)
}

/// Check if a library is present in the LC_LOAD_DYLIB entries.
///
/// Returns false if not a valid Mach-O or library not found.
pub fn is_library_present(data: &[u8], name: &str) -> bool {
    get_import_libraries(data).iter().any(|lib| lib == name)
}

/// Get the image base (lowest vmaddr among segments).
///
/// Returns 0 if not a valid Mach-O or no segments.
pub fn get_image_base(data: &[u8]) -> u64 {
    let mach = macho_from_bytes(data);
    let Some(mach) = mach else {
        return 0;
    };
    let mut base: Option<u64> = None;
    for segment in &mach.segments {
        let vmaddr = segment.vmaddr;
        if base.is_none() || vmaddr < base.unwrap() {
            base = Some(vmaddr);
        }
    }
    base.unwrap_or(0)
}

/// Get the overlay offset (data after the last segment's file data).
///
/// Returns -1 if no overlay or not a valid Mach-O.
pub fn get_overlay_offset(data: &[u8]) -> i64 {
    let mach = macho_from_bytes(data);
    let Some(mach) = mach else {
        return -1;
    };
    let mut max_end: u64 = 0;
    for segment in &mach.segments {
        let end = segment.fileoff.saturating_add(segment.filesize);
        if end > max_end {
            max_end = end;
        }
    }
    if max_end >= data.len() as u64 {
        return -1;
    }
    max_end as i64
}

/// Mach-O file type names.
fn mach_file_type_name(filetype: u32) -> String {
    use goblin::mach::header::*;
    match filetype {
        MH_OBJECT => "object".to_string(),
        MH_EXECUTE => "executable".to_string(),
        MH_FVMLIB => "fixed vm shared library".to_string(),
        MH_CORE => "core".to_string(),
        MH_PRELOAD => "preloaded executable".to_string(),
        MH_DYLIB => "dynamic library".to_string(),
        MH_DYLINKER => "dynamic linker".to_string(),
        MH_BUNDLE => "bundle".to_string(),
        MH_DYLIB_STUB => "dynamic library stub".to_string(),
        _ => format!("type{filetype}"),
    }
}

/// Mach-O CPU type names (subset matching the JS implementation).
fn mach_cpu_type_name(cputype: u32) -> String {
    use goblin::mach::constants::cputype::*;
    match cputype {
        CPU_TYPE_X86 => "x86".to_string(),
        CPU_TYPE_X86_64 => "x86-64".to_string(),
        CPU_TYPE_ARM => "ARM".to_string(),
        CPU_TYPE_ARM64 => "AArch64".to_string(),
        _ => format!("cpu{cputype}"),
    }
}

/// Get the Mach-O type name.
///
/// Returns empty string if not a valid Mach-O.
pub fn get_type_name(data: &[u8]) -> String {
    macho_from_bytes(data)
        .map(|mach| mach_file_type_name(mach.header.filetype))
        .unwrap_or_default()
}

/// Get the Mach-O machine (CPU) name.
///
/// Returns empty string if not a valid Mach-O.
pub fn get_machine_name(data: &[u8]) -> String {
    macho_from_bytes(data)
        .map(|mach| mach_cpu_type_name(mach.header.cputype))
        .unwrap_or_default()
}

/// Get the general options string (type + machine + bits).
///
/// Returns empty string if not a valid Mach-O.
pub fn get_general_options(data: &[u8]) -> String {
    let mach = macho_from_bytes(data);
    let Some(mach) = mach else {
        return String::new();
    };
    let ft = mach_file_type_name(mach.header.filetype);
    let m = mach_cpu_type_name(mach.header.cputype);
    let b = if mach.is_64 { "64" } else { "32" };
    format!("{ft} {m}{b}")
}

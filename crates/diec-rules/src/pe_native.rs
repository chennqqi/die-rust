//! Native PE host API methods backed by the `pelite` crate.
//!
//! This module replaces the hand-written JavaScript PE parsing code in
//! `host_api_bridge.rs` with native Rust implementations using `pelite`.
//! The methods are registered as JavaScript functions on the `PE` object.
//!
//! Benefits over the JS implementation:
//! - Battle-tested PE parsing (pelite is widely used and fuzzed)
//! - Built-in support for Resource directory, Manifest, .NET metadata
//! - Better performance (no per-byte JS→Rust FFI round-trips)
//! - Correctness guarantees from pelite's validation

use crate::host_api::HostApi;
use std::sync::Arc;

// Pelite traits must be imported to use provided methods on PeFile.
use pelite::pe32::Pe as Pe32;
use pelite::pe64::Pe as Pe64;

/// Safely parse a PE64 file, catching panics from pelite's unsafe code.
///
/// pelite uses `unsafe` pointer casts internally which can panic on
/// misaligned addresses in debug builds. This wrapper pre-checks
/// alignment to avoid the misaligned pointer dereference UB.
fn pe64_from_bytes(data: &[u8]) -> Option<pelite::pe64::PeFile<'_>> {
    // Pre-check: pelite's pe32 and pe64 share the same validate_headers
    // code which casts to IMAGE_NT_HEADERS64 (8-byte aligned).
    // If e_lfanew is not 8-byte aligned, skip pelite entirely.
    if !check_pe_alignment_safe(data, 8) {
        return None;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pelite::pe64::PeFile::from_bytes(data)
    }))
    .ok()
    .and_then(|r| r.ok())
}

/// Safely parse a PE32 file, catching panics from pelite's unsafe code.
fn pe32_from_bytes(data: &[u8]) -> Option<pelite::pe32::PeFile<'_>> {
    // Pre-check: pelite's pe32 module uses IMAGE_NT_HEADERS32 (4-byte aligned).
    // The validate_headers code is shared from pe64 but resolves types via
    // `use super::image::*` which maps to pe32::image in the pe32 context.
    if !check_pe_alignment_safe(data, 4) {
        return None;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pelite::pe32::PeFile::from_bytes(data)
    }))
    .ok()
    .and_then(|r| r.ok())
}

/// Check if the PE e_lfanew value is safe for the given alignment.
///
/// Returns false if the file is too small, not a PE, or if e_lfanew
/// would cause a misaligned pointer dereference.
fn check_pe_alignment_safe(data: &[u8], align: usize) -> bool {
    if data.len() < 64 {
        return false;
    }
    // Check MZ signature.
    if data[0] != 0x4D || data[1] != 0x5A {
        return false;
    }
    // Read e_lfanew at offset 0x3C.
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
    // Check alignment.
    if !(e_lfanew as usize).is_multiple_of(align) {
        return false;
    }
    // Check bounds.
    if e_lfanew as usize + 24 > data.len() {
        return false;
    }
    // Check PE signature.
    &data[e_lfanew as usize..e_lfanew as usize + 4] == b"PE\0\0"
}

/// Check if the file data is a valid PE by parsing with pelite.
///
/// Returns `true` if the data can be parsed as a PE32/PE32+ file.
pub fn is_pe(data: &[u8]) -> bool {
    pe64_from_bytes(data).is_some() || pe32_from_bytes(data).is_some()
}

/// Get the PE image base (preferred load address).
///
/// Returns 0 if the file is not a valid PE.
pub fn get_image_base(data: &[u8]) -> u64 {
    if let Some(file) = pe64_from_bytes(data) {
        return file.optional_header().ImageBase;
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.optional_header().ImageBase as u64;
    }
    0
}

/// Get the entry point RVA.
///
/// Returns 0 if the file is not a valid PE.
pub fn get_entry_point(data: &[u8]) -> u64 {
    if let Some(file) = pe64_from_bytes(data) {
        return file.optional_header().AddressOfEntryPoint as u64;
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.optional_header().AddressOfEntryPoint as u64;
    }
    0
}

/// Get the number of sections.
///
/// Returns 0 if the file is not a valid PE.
pub fn get_number_of_sections(data: &[u8]) -> u32 {
    if let Some(file) = pe64_from_bytes(data) {
        return file.file_header().NumberOfSections as u32;
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.file_header().NumberOfSections as u32;
    }
    0
}

/// Get the section index by name (case-insensitive).
///
/// Returns -1 if not found or not a valid PE.
pub fn get_section_number(data: &[u8], name: &str) -> i32 {
    let lookup = name.to_lowercase();
    if let Some(file) = pe64_from_bytes(data) {
        for (i, sec) in file.section_headers().iter().enumerate() {
            if String::from_utf8_lossy(sec.name_bytes()).to_lowercase() == lookup {
                return i as i32;
            }
        }
        return -1;
    }
    if let Some(file) = pe32_from_bytes(data) {
        for (i, sec) in file.section_headers().iter().enumerate() {
            if String::from_utf8_lossy(sec.name_bytes()).to_lowercase() == lookup {
                return i as i32;
            }
        }
    }
    -1
}

/// Get the section name by index.
///
/// Returns empty string if index is out of range or not a valid PE.
pub fn get_section_name(data: &[u8], index: u32) -> String {
    if let Some(file) = pe64_from_bytes(data) {
        let sections = file.section_headers().iter().collect::<Vec<_>>();
        if (index as usize) < sections.len() {
            return String::from_utf8_lossy(sections[index as usize].name_bytes()).to_string();
        }
        return String::new();
    }
    if let Some(file) = pe32_from_bytes(data) {
        let sections = file.section_headers().iter().collect::<Vec<_>>();
        if (index as usize) < sections.len() {
            return String::from_utf8_lossy(sections[index as usize].name_bytes()).to_string();
        }
    }
    String::new()
}

/// Get the section file offset by index.
///
/// Returns 0 if index is out of range or not a valid PE.
pub fn get_section_file_offset(data: &[u8], index: u32) -> u64 {
    if let Some(file) = pe64_from_bytes(data) {
        let sections = file.section_headers().iter().collect::<Vec<_>>();
        if (index as usize) < sections.len() {
            return sections[index as usize].PointerToRawData as u64;
        }
        return 0;
    }
    if let Some(file) = pe32_from_bytes(data) {
        let sections = file.section_headers().iter().collect::<Vec<_>>();
        if (index as usize) < sections.len() {
            return sections[index as usize].PointerToRawData as u64;
        }
    }
    0
}

/// Get the section file size by index.
///
/// Returns 0 if index is out of range or not a valid PE.
pub fn get_section_file_size(data: &[u8], index: u32) -> u64 {
    if let Some(file) = pe64_from_bytes(data) {
        let sections = file.section_headers().iter().collect::<Vec<_>>();
        if (index as usize) < sections.len() {
            return sections[index as usize].SizeOfRawData as u64;
        }
        return 0;
    }
    if let Some(file) = pe32_from_bytes(data) {
        let sections = file.section_headers().iter().collect::<Vec<_>>();
        if (index as usize) < sections.len() {
            return sections[index as usize].SizeOfRawData as u64;
        }
    }
    0
}

/// Get the section virtual address by index.
///
/// Returns 0 if index is out of range or not a valid PE.
pub fn get_section_virtual_address(data: &[u8], index: u32) -> u64 {
    if let Some(file) = pe64_from_bytes(data) {
        let sections = file.section_headers().iter().collect::<Vec<_>>();
        if (index as usize) < sections.len() {
            return sections[index as usize].VirtualAddress as u64;
        }
        return 0;
    }
    if let Some(file) = pe32_from_bytes(data) {
        let sections = file.section_headers().iter().collect::<Vec<_>>();
        if (index as usize) < sections.len() {
            return sections[index as usize].VirtualAddress as u64;
        }
    }
    0
}

/// Get the section virtual size by index.
///
/// Returns 0 if index is out of range or not a valid PE.
pub fn get_section_virtual_size(data: &[u8], index: u32) -> u64 {
    if let Some(file) = pe64_from_bytes(data) {
        let sections = file.section_headers().iter().collect::<Vec<_>>();
        if (index as usize) < sections.len() {
            return sections[index as usize].VirtualSize as u64;
        }
        return 0;
    }
    if let Some(file) = pe32_from_bytes(data) {
        let sections = file.section_headers().iter().collect::<Vec<_>>();
        if (index as usize) < sections.len() {
            return sections[index as usize].VirtualSize as u64;
        }
    }
    0
}

/// Convert an RVA to a file offset.
///
/// Returns -1 if the RVA is not within any section or not a valid PE.
pub fn rva_to_file_offset(data: &[u8], rva: u64) -> i64 {
    if let Some(file) = pe64_from_bytes(data) {
        return match file.rva_to_file_offset(rva as u32) {
            Ok(off) => off as i64,
            Err(_) => -1,
        };
    }
    if let Some(file) = pe32_from_bytes(data) {
        return match file.rva_to_file_offset(rva as u32) {
            Ok(off) => off as i64,
            Err(_) => -1,
        };
    }
    -1
}

/// Get the PE machine type string (e.g. "i386", "amd64").
///
/// Returns empty string if not a valid PE.
pub fn get_machine(data: &[u8]) -> String {
    let machine_name = |m: u16| -> &str {
        match m {
            0x14C => "i386",
            0x8664 => "amd64",
            0x1C0 => "ARM",
            0xAA64 => "ARM64",
            _ => "unknown",
        }
    };
    if let Some(file) = pe64_from_bytes(data) {
        return machine_name(file.file_header().Machine).to_string();
    }
    if let Some(file) = pe32_from_bytes(data) {
        return machine_name(file.file_header().Machine).to_string();
    }
    String::new()
}

/// Get the PE subsystem string (e.g. "Windows GUI", "Windows CUI").
///
/// Returns empty string if not a valid PE.
pub fn get_subsystem(data: &[u8]) -> String {
    let sub_name = |s: u16| -> &str {
        match s {
            1 => "Native",
            2 => "Windows GUI",
            3 => "Windows CUI",
            5 => "OS/2 CUI",
            7 => "POSIX CUI",
            9 => "Windows CE GUI",
            10 => "EFI Application",
            11 => "EFI Boot Service Driver",
            12 => "EFI Runtime Driver",
            13 => "EFI ROM",
            14 => "XBOX",
            _ => "Unknown",
        }
    };
    if let Some(file) = pe64_from_bytes(data) {
        return sub_name(file.optional_header().Subsystem).to_string();
    }
    if let Some(file) = pe32_from_bytes(data) {
        return sub_name(file.optional_header().Subsystem).to_string();
    }
    String::new()
}

/// Check if the PE is a DLL (IMAGE_FILE_HEADER: IMAGE_FILE_DLL bit).
///
/// Returns false if not a valid PE.
pub fn is_dynamic_link_library(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        return file.file_header().Characteristics & 0x2000 != 0;
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.file_header().Characteristics & 0x2000 != 0;
    }
    false
}

/// Check if the PE is a console application (subsystem == 3).
///
/// Returns false if not a valid PE.
pub fn is_console(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        return file.optional_header().Subsystem == 3;
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.optional_header().Subsystem == 3;
    }
    false
}

/// Check if the PE is a 64-bit (PE32+) binary.
///
/// Returns false if not a valid PE.
pub fn is_64bit(data: &[u8]) -> bool {
    pelite::pe64::PeFile::from_bytes(data).is_ok()
}

/// Get the size of the image (SizeOfImage from optional header).
///
/// Returns 0 if not a valid PE.
pub fn get_size_of_image(data: &[u8]) -> u64 {
    if let Some(file) = pe64_from_bytes(data) {
        return file.optional_header().SizeOfImage as u64;
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.optional_header().SizeOfImage as u64;
    }
    0
}

/// Get the overlay offset (data after the last section's raw data).
///
/// Returns -1 if no overlay or not a valid PE.
pub fn get_overlay_offset(data: &[u8]) -> i64 {
    let calc_overlay = |max_end: u64| -> i64 {
        if max_end >= data.len() as u64 {
            return -1;
        }
        max_end as i64
    };
    if let Some(file) = pe64_from_bytes(data) {
        let mut max_end: u64 = 0;
        for sec in file.section_headers().iter() {
            let end = sec.PointerToRawData as u64 + sec.SizeOfRawData as u64;
            if end > max_end {
                max_end = end;
            }
        }
        return calc_overlay(max_end);
    }
    if let Some(file) = pe32_from_bytes(data) {
        let mut max_end: u64 = 0;
        for sec in file.section_headers().iter() {
            let end = sec.PointerToRawData as u64 + sec.SizeOfRawData as u64;
            if end > max_end {
                max_end = end;
            }
        }
        return calc_overlay(max_end);
    }
    -1
}

/// Get the overlay size (file size - overlay offset).
///
/// Returns 0 if no overlay or not a valid PE.
pub fn get_overlay_size(data: &[u8]) -> u64 {
    let off = get_overlay_offset(data);
    if off < 0 {
        return 0;
    }
    data.len() as u64 - off as u64
}

/// Check if the PE has an overlay.
pub fn is_overlay_present(data: &[u8]) -> bool {
    get_overlay_offset(data) >= 0
}

/// Get the PE manifest XML string from resources (RT_MANIFEST, type 24).
///
/// Returns empty string if no manifest or not a valid PE.
pub fn get_manifest(data: &[u8]) -> String {
    if let Some(file) = pe64_from_bytes(data) {
        if let Ok(res) = file.resources()
            && let Ok(xml) = res.manifest()
        {
            return xml.to_string();
        }
        return String::new();
    }
    if let Some(file) = pe32_from_bytes(data)
        && let Ok(res) = file.resources()
        && let Ok(xml) = res.manifest()
    {
        return xml.to_string();
    }
    String::new()
}

/// Check if the PE has a .NET CLR header (data directory index 14).
pub fn is_net(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        return file.data_directory().get(14).is_some_and(|d| d.Size != 0);
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.data_directory().get(14).is_some_and(|d| d.Size != 0);
    }
    false
}

/// Batch PE parse result: imports, exports, and metadata in one pass.
pub struct PeBatchInfo {
    /// Imported library (DLL) names.
    pub libraries: Vec<String>,
    /// Imported function names.
    pub functions: Vec<String>,
    /// Exported function names.
    pub exports: Vec<String>,
    /// Whether the PE has a .NET CLR header.
    pub is_net: bool,
    /// Whether the PE has an Authenticode security directory.
    pub is_signed: bool,
    /// PE manifest XML string from resources.
    pub manifest: String,
    /// File version string from VS_FIXEDFILEINFO.
    pub file_version: String,
    /// Product version string from VS_FIXEDFILEINFO.
    pub product_version: String,
    /// Total number of resource data entries.
    pub number_of_resources: usize,
}

/// Parse all PE information in a single pass to avoid repeated PeFile construction.
///
/// Returns None if not a valid PE.
pub fn parse_batch(data: &[u8]) -> Option<PeBatchInfo> {
    // Try PE64 first.
    if let Some(file) = pe64_from_bytes(data) {
        return Some(parse_batch_pe64(file));
    }
    // Try PE32.
    if let Some(file) = pe32_from_bytes(data) {
        return Some(parse_batch_pe32(file));
    }
    None
}

/// Parse batch info from a PE64 file.
fn parse_batch_pe64(file: pelite::pe64::PeFile<'_>) -> PeBatchInfo {
    let mut libraries = Vec::new();
    let mut functions = Vec::new();
    if let Ok(imports) = file.imports() {
        for desc in imports.iter() {
            if let Ok(name) = desc.dll_name()
                && let Ok(s) = name.to_str()
                && !libraries.contains(&s.to_string())
            {
                libraries.push(s.to_string());
            }
            if let Ok(int) = desc.int() {
                for imp in int {
                    if let Ok(pelite::pe64::imports::Import::ByName { name, .. }) = imp
                        && let Ok(s) = name.to_str()
                    {
                        functions.push(s.to_string());
                    }
                }
            }
        }
    }

    let mut exports = Vec::new();
    if let Ok(exp) = file.exports()
        && let Ok(by) = exp.by()
    {
        for (name, _) in by.iter_names() {
            if let Ok(n) = name
                && let Ok(s) = n.to_str()
            {
                exports.push(s.to_string());
            }
        }
    }

    let is_net = file.data_directory().get(14).is_some_and(|d| d.Size != 0);
    let is_signed = file
        .data_directory()
        .get(4)
        .is_some_and(|d| d.VirtualAddress != 0);

    let (manifest, file_version, product_version, number_of_resources) =
        parse_resource_info_pe64(&file);

    PeBatchInfo {
        libraries,
        functions,
        exports,
        is_net,
        is_signed,
        manifest,
        file_version,
        product_version,
        number_of_resources,
    }
}

/// Parse batch info from a PE32 file.
fn parse_batch_pe32(file: pelite::pe32::PeFile<'_>) -> PeBatchInfo {
    let mut libraries = Vec::new();
    let mut functions = Vec::new();
    if let Ok(imports) = file.imports() {
        for desc in imports.iter() {
            if let Ok(name) = desc.dll_name()
                && let Ok(s) = name.to_str()
                && !libraries.contains(&s.to_string())
            {
                libraries.push(s.to_string());
            }
            if let Ok(int) = desc.int() {
                for imp in int {
                    if let Ok(pelite::pe32::imports::Import::ByName { name, .. }) = imp
                        && let Ok(s) = name.to_str()
                    {
                        functions.push(s.to_string());
                    }
                }
            }
        }
    }

    let mut exports = Vec::new();
    if let Ok(exp) = file.exports()
        && let Ok(by) = exp.by()
    {
        for (name, _) in by.iter_names() {
            if let Ok(n) = name
                && let Ok(s) = n.to_str()
            {
                exports.push(s.to_string());
            }
        }
    }

    let is_net = file.data_directory().get(14).is_some_and(|d| d.Size != 0);
    let is_signed = file
        .data_directory()
        .get(4)
        .is_some_and(|d| d.VirtualAddress != 0);

    let (manifest, file_version, product_version, number_of_resources) =
        parse_resource_info_pe32(&file);

    PeBatchInfo {
        libraries,
        functions,
        exports,
        is_net,
        is_signed,
        manifest,
        file_version,
        product_version,
        number_of_resources,
    }
}

/// Extract resource info (manifest, version, resource count) from a PE file.
fn parse_resource_info_pe64(file: &pelite::pe64::PeFile<'_>) -> (String, String, String, usize) {
    let Ok(res) = file.resources() else {
        return (String::new(), String::new(), String::new(), 0);
    };
    let manifest = res.manifest().map(String::from).unwrap_or_default();
    let (file_version, product_version) = if let Ok(vi) = res.version_info() {
        let fv = vi
            .fixed()
            .map(|f| format_version(&f.dwFileVersion))
            .unwrap_or_default();
        let pv = vi
            .fixed()
            .map(|f| format_version(&f.dwProductVersion))
            .unwrap_or_default();
        (fv, pv)
    } else {
        (String::new(), String::new())
    };
    let number_of_resources = if let Ok(root) = res.root() {
        let count = std::cell::Cell::new(0usize);
        let visit = CountResources(&count);
        count_resources_dir(&root, &visit);
        count.get()
    } else {
        0
    };
    (manifest, file_version, product_version, number_of_resources)
}

/// Extract resource info from a PE32 file.
fn parse_resource_info_pe32(file: &pelite::pe32::PeFile<'_>) -> (String, String, String, usize) {
    let Ok(res) = file.resources() else {
        return (String::new(), String::new(), String::new(), 0);
    };
    let manifest = res.manifest().map(String::from).unwrap_or_default();
    let (file_version, product_version) = if let Ok(vi) = res.version_info() {
        let fv = vi
            .fixed()
            .map(|f| format_version(&f.dwFileVersion))
            .unwrap_or_default();
        let pv = vi
            .fixed()
            .map(|f| format_version(&f.dwProductVersion))
            .unwrap_or_default();
        (fv, pv)
    } else {
        (String::new(), String::new())
    };
    let number_of_resources = if let Ok(root) = res.root() {
        let count = std::cell::Cell::new(0usize);
        let visit = CountResources(&count);
        count_resources_dir(&root, &visit);
        count.get()
    } else {
        0
    };
    (manifest, file_version, product_version, number_of_resources)
}

/// Get the PE import library names.
///
/// Returns empty vector if not a valid PE or no imports.
pub fn get_import_libraries(data: &[u8]) -> Vec<String> {
    if let Some(file) = pe64_from_bytes(data) {
        if let Ok(imports) = file.imports() {
            let mut libs = Vec::new();
            for desc in imports.iter() {
                if let Ok(name) = desc.dll_name()
                    && let Ok(s) = name.to_str()
                    && !libs.contains(&s.to_string())
                {
                    libs.push(s.to_string());
                }
            }
            return libs;
        }
        return Vec::new();
    }
    if let Some(file) = pe32_from_bytes(data)
        && let Ok(imports) = file.imports()
    {
        let mut libs = Vec::new();
        for desc in imports.iter() {
            if let Ok(name) = desc.dll_name()
                && let Ok(s) = name.to_str()
                && !libs.contains(&s.to_string())
            {
                libs.push(s.to_string());
            }
        }
        return libs;
    }
    Vec::new()
}

/// Get the PE import function names.
///
/// Returns empty vector if not a valid PE or no imports.
pub fn get_import_functions(data: &[u8]) -> Vec<String> {
    if let Some(file) = pe64_from_bytes(data) {
        if let Ok(imports) = file.imports() {
            let mut funcs = Vec::new();
            for desc in imports.iter() {
                if let Ok(int) = desc.int() {
                    for imp in int {
                        if let Ok(pelite::pe64::imports::Import::ByName { name, .. }) = imp
                            && let Ok(s) = name.to_str()
                        {
                            funcs.push(s.to_string());
                        }
                    }
                }
            }
            return funcs;
        }
        return Vec::new();
    }
    if let Some(file) = pe32_from_bytes(data)
        && let Ok(imports) = file.imports()
    {
        let mut funcs = Vec::new();
        for desc in imports.iter() {
            if let Ok(int) = desc.int() {
                for imp in int {
                    if let Ok(pelite::pe32::imports::Import::ByName { name, .. }) = imp
                        && let Ok(s) = name.to_str()
                    {
                        funcs.push(s.to_string());
                    }
                }
            }
        }
        return funcs;
    }
    Vec::new()
}

/// Get the PE export function names.
///
/// Returns empty vector if not a valid PE or no exports.
pub fn get_export_names(data: &[u8]) -> Vec<String> {
    if let Some(file) = pe64_from_bytes(data) {
        if let Ok(exports) = file.exports()
            && let Ok(by) = exports.by()
        {
            let mut names = Vec::new();
            for (name, _export) in by.iter_names() {
                if let Ok(n) = name
                    && let Ok(s) = n.to_str()
                {
                    names.push(s.to_string());
                }
            }
            return names;
        }
        return Vec::new();
    }
    if let Some(file) = pe32_from_bytes(data)
        && let Ok(exports) = file.exports()
        && let Ok(by) = exports.by()
    {
        let mut names = Vec::new();
        for (name, _export) in by.iter_names() {
            if let Ok(n) = name
                && let Ok(s) = n.to_str()
            {
                names.push(s.to_string());
            }
        }
        return names;
    }
    Vec::new()
}

/// Check if the PE has an export table.
pub fn is_export_present(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        return file.data_directory().first().is_some_and(|d| d.Size != 0);
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.data_directory().first().is_some_and(|d| d.Size != 0);
    }
    false
}

/// Check if the PE has an import table.
pub fn is_import_present(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        return file.data_directory().get(1).is_some_and(|d| d.Size != 0);
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.data_directory().get(1).is_some_and(|d| d.Size != 0);
    }
    false
}

/// Check if the PE has a resource directory.
pub fn is_resources_present(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        return file.data_directory().get(2).is_some_and(|d| d.Size != 0);
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.data_directory().get(2).is_some_and(|d| d.Size != 0);
    }
    false
}

/// Check if the PE has a TLS directory.
pub fn is_tls_present(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        return file.data_directory().get(9).is_some_and(|d| d.Size != 0);
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.data_directory().get(9).is_some_and(|d| d.Size != 0);
    }
    false
}

/// Check if the PE has an Authenticode signature (security directory, index 4).
pub fn is_signed(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        return file.data_directory().get(4).is_some_and(|d| d.Size != 0);
    }
    if let Some(file) = pe32_from_bytes(data) {
        return file.data_directory().get(4).is_some_and(|d| d.Size != 0);
    }
    false
}

// --- Validation methods ---

/// Check if the entry point RVA is within a section.
pub fn is_entry_point_correct(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        let ep = file.optional_header().AddressOfEntryPoint;
        if ep == 0 {
            return true;
        }
        return file.rva_to_file_offset(ep).is_ok();
    }
    if let Some(file) = pe32_from_bytes(data) {
        let ep = file.optional_header().AddressOfEntryPoint;
        if ep == 0 {
            return true;
        }
        return file.rva_to_file_offset(ep).is_ok();
    }
    false
}

/// Check if SectionAlignment is a power of 2 and >= 512.
pub fn is_section_alignment_correct(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        let sa = file.optional_header().SectionAlignment;
        if sa < 512 {
            return false;
        }
        return (sa & (sa - 1)) == 0;
    }
    if let Some(file) = pe32_from_bytes(data) {
        let sa = file.optional_header().SectionAlignment;
        if sa < 512 {
            return false;
        }
        return (sa & (sa - 1)) == 0;
    }
    false
}

/// Check if FileAlignment is a power of 2, >= 512 and <= 65536.
pub fn is_file_alignment_correct(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        let fa = file.optional_header().FileAlignment;
        if !(512..=65536).contains(&fa) {
            return false;
        }
        return (fa & (fa - 1)) == 0;
    }
    if let Some(file) = pe32_from_bytes(data) {
        let fa = file.optional_header().FileAlignment;
        if !(512..=65536).contains(&fa) {
            return false;
        }
        return (fa & (fa - 1)) == 0;
    }
    false
}

/// Check if the PE header fields are valid (sections > 0, opt header >= 24, chars != 0).
pub fn is_header_correct(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        let fh = file.file_header();
        if fh.NumberOfSections == 0 {
            return false;
        }
        if fh.SizeOfOptionalHeader < 24 {
            return false;
        }
        return fh.Characteristics != 0;
    }
    if let Some(file) = pe32_from_bytes(data) {
        let fh = file.file_header();
        if fh.NumberOfSections == 0 {
            return false;
        }
        if fh.SizeOfOptionalHeader < 24 {
            return false;
        }
        return fh.Characteristics != 0;
    }
    false
}

/// Check if the export table RVA is within a section.
pub fn is_export_table_correct(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        let rva = file
            .data_directory()
            .first()
            .map_or(0, |d| d.VirtualAddress);
        if rva == 0 {
            return true;
        }
        return file.rva_to_file_offset(rva).is_ok();
    }
    if let Some(file) = pe32_from_bytes(data) {
        let rva = file
            .data_directory()
            .first()
            .map_or(0, |d| d.VirtualAddress);
        if rva == 0 {
            return true;
        }
        return file.rva_to_file_offset(rva).is_ok();
    }
    false
}

/// Check if the import table RVA is within a section.
pub fn is_import_table_correct(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        let rva = file.data_directory().get(1).map_or(0, |d| d.VirtualAddress);
        if rva == 0 {
            return true;
        }
        return file.rva_to_file_offset(rva).is_ok();
    }
    if let Some(file) = pe32_from_bytes(data) {
        let rva = file.data_directory().get(1).map_or(0, |d| d.VirtualAddress);
        if rva == 0 {
            return true;
        }
        return file.rva_to_file_offset(rva).is_ok();
    }
    false
}

/// Check if the relocations table RVA is within a section.
pub fn is_relocs_table_correct(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        let rva = file.data_directory().get(5).map_or(0, |d| d.VirtualAddress);
        if rva == 0 {
            return true;
        }
        return file.rva_to_file_offset(rva).is_ok();
    }
    if let Some(file) = pe32_from_bytes(data) {
        let rva = file.data_directory().get(5).map_or(0, |d| d.VirtualAddress);
        if rva == 0 {
            return true;
        }
        return file.rva_to_file_offset(rva).is_ok();
    }
    false
}

//----------------------------------------------------------------
// Resource / Version Info / .NET metadata
//----------------------------------------------------------------

/// Helper to parse version info from a PE file.
fn version_info_from_bytes(
    data: &[u8],
) -> Option<pelite::resources::version_info::VersionInfo<'_>> {
    if let Some(file) = pe64_from_bytes(data)
        && let Ok(res) = file.resources()
        && let Ok(vi) = res.version_info()
    {
        return Some(vi);
    }
    if let Some(file) = pe32_from_bytes(data)
        && let Ok(res) = file.resources()
        && let Ok(vi) = res.version_info()
    {
        return Some(vi);
    }
    None
}

/// Format a VS_VERSION as "Major.Minor.Build.Patch".
fn format_version(v: &pelite::image::VS_VERSION) -> String {
    format!("{}.{}.{}.{}", v.Major, v.Minor, v.Build, v.Patch)
}

/// Get the PE file version string (from VS_FIXEDFILEINFO).
///
/// Returns empty string if not a valid PE or no version info.
pub fn get_file_version(data: &[u8]) -> String {
    if let Some(vi) = version_info_from_bytes(data)
        && let Some(fixed) = vi.fixed()
    {
        return format_version(&fixed.dwFileVersion);
    }
    String::new()
}

/// Get the PE product version string (from VS_FIXEDFILEINFO).
///
/// Returns empty string if not a valid PE or no version info.
pub fn get_product_version(data: &[u8]) -> String {
    if let Some(vi) = version_info_from_bytes(data)
        && let Some(fixed) = vi.fixed()
    {
        return format_version(&fixed.dwProductVersion);
    }
    String::new()
}

/// Get a string value from the PE version info's StringFileInfo table.
///
/// Common keys: CompanyName, FileDescription, FileVersion, InternalName,
/// LegalCopyright, OriginalFilename, ProductName, ProductVersion, Comments.
///
/// Returns empty string if not found or not a valid PE.
pub fn get_version_string(data: &[u8], key: &str) -> String {
    let Some(vi) = version_info_from_bytes(data) else {
        return String::new();
    };
    // Get the first translation language.
    let translations = vi.translation();
    if translations.is_empty() {
        return String::new();
    }
    let lang = translations[0];
    vi.value(lang, key).unwrap_or_default()
}

/// Get the CompanyName from the PE version info.
pub fn get_company_name(data: &[u8]) -> String {
    get_version_string(data, "CompanyName")
}

/// Get the ProductName from the PE version info.
pub fn get_product_name(data: &[u8]) -> String {
    get_version_string(data, "ProductName")
}

/// Get the OriginalFilename from the PE version info.
pub fn get_original_filename(data: &[u8]) -> String {
    get_version_string(data, "OriginalFilename")
}

/// Get the InternalName from the PE version info.
pub fn get_internal_name(data: &[u8]) -> String {
    get_version_string(data, "InternalName")
}

/// Get the LegalCopyright from the PE version info.
pub fn get_copyright(data: &[u8]) -> String {
    get_version_string(data, "LegalCopyright")
}

/// Get the Comments from the PE version info.
pub fn get_comments(data: &[u8]) -> String {
    get_version_string(data, "Comments")
}

/// Get the FileDescription from the PE version info.
pub fn get_file_description(data: &[u8]) -> String {
    get_version_string(data, "FileDescription")
}

/// Count the total number of resource data entries.
///
/// Returns 0 if not a valid PE or no resources.
pub fn get_number_of_resources(data: &[u8]) -> usize {
    let count = std::cell::Cell::new(0usize);
    let visit = CountResources(&count);
    if let Some(file) = pe64_from_bytes(data) {
        if let Ok(res) = file.resources()
            && let Ok(root) = res.root()
        {
            count_resources_dir(&root, &visit);
        }
    } else if let Some(file) = pe32_from_bytes(data)
        && let Ok(res) = file.resources()
        && let Ok(root) = res.root()
    {
        count_resources_dir(&root, &visit);
    }
    count.get()
}

/// Recursively count data entries in a resource directory.
fn count_resources_dir(dir: &pelite::resources::Directory<'_>, visit: &CountResources) {
    for entry in dir.entries() {
        if let Ok(e) = entry.entry() {
            if let Some(subdir) = e.dir() {
                count_resources_dir(&subdir, visit);
            } else if e.data().is_some() {
                visit.0.set(visit.0.get() + 1);
            }
        }
    }
}

/// Helper struct for counting resources.
struct CountResources<'a>(&'a std::cell::Cell<usize>);

/// A resource data entry with its extracted bytes and metadata.
///
/// Used by the nested scanner to recursively scan PE resources.
#[derive(Debug, Clone)]
pub struct ResourceData {
    /// Resource type path (e.g., "RT_VERSION/1/0").
    pub type_path: String,
    /// The resource data bytes.
    pub data: Vec<u8>,
}

/// Enumerate all resource data entries in a PE file and extract their bytes.
///
/// Returns a list of resource data entries. Returns an empty vector if the
/// file is not a valid PE or has no resources.
///
/// Upstream uses `getFileParts()` to enumerate resources for recursive scanning.
/// This is the Rust equivalent.
pub fn get_resource_data(data: &[u8]) -> Vec<ResourceData> {
    if let Some(file) = pe64_from_bytes(data) {
        return collect_resource_data_pe64(&file);
    }
    if let Some(file) = pe32_from_bytes(data) {
        return collect_resource_data_pe32(&file);
    }
    Vec::new()
}

/// Collect resource data from a PE64 file.
fn collect_resource_data_pe64(file: &pelite::pe64::PeFile<'_>) -> Vec<ResourceData> {
    let mut entries = Vec::new();
    let Ok(res) = file.resources() else {
        return entries;
    };
    let Ok(root) = res.root() else {
        return entries;
    };
    collect_resource_data_dir(&root, "", &mut entries);
    entries
}

/// Collect resource data from a PE32 file.
fn collect_resource_data_pe32(file: &pelite::pe32::PeFile<'_>) -> Vec<ResourceData> {
    let mut entries = Vec::new();
    let Ok(res) = file.resources() else {
        return entries;
    };
    let Ok(root) = res.root() else {
        return entries;
    };
    collect_resource_data_dir(&root, "", &mut entries);
    entries
}

/// Format a resource Name as a string.
fn format_resource_name(name: &pelite::resources::Name<'_>) -> String {
    match name {
        pelite::resources::Name::Wide(s) => String::from_utf16_lossy(s),
        pelite::resources::Name::Id(id) => format!("#{id}"),
        pelite::resources::Name::Str(s) => s.to_string(),
    }
}

/// Recursively walk a resource directory and collect data entries.
fn collect_resource_data_dir(
    dir: &pelite::resources::Directory<'_>,
    parent_type: &str,
    entries: &mut Vec<ResourceData>,
) {
    for entry in dir.entries() {
        let Ok(e) = entry.entry() else {
            continue;
        };
        // Build type/name string.
        let type_name = match entry.name() {
            Ok(ref n) => format_resource_name(n),
            Err(_) => format!("#{}", entry.image().Name),
        };
        let full_type = if parent_type.is_empty() {
            type_name.clone()
        } else {
            format!("{parent_type}/{type_name}")
        };
        if let Some(subdir) = e.dir() {
            collect_resource_data_dir(&subdir, &full_type, entries);
        } else if let Some(data) = e.data() {
            // Extract the actual resource bytes.
            if let Ok(bytes) = data.bytes() {
                entries.push(ResourceData {
                    type_path: full_type,
                    data: bytes.to_vec(),
                });
            }
        }
    }
}

/// Check if a resource name is present in the resource directory.
///
/// Returns false if not a valid PE or resource not found.
pub fn is_resource_name_present(data: &[u8], name: &str) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        if let Ok(res) = file.resources()
            && let Ok(root) = res.root()
        {
            for entry in root.entries() {
                if let Ok(n) = entry.name()
                    && n == *name
                {
                    return true;
                }
            }
        }
        return false;
    }
    if let Some(file) = pe32_from_bytes(data)
        && let Ok(res) = file.resources()
        && let Ok(root) = res.root()
    {
        for entry in root.entries() {
            if let Ok(n) = entry.name()
                && n == *name
            {
                return true;
            }
        }
    }
    false
}

/// Get the resource section file offset (data directory index 2).
///
/// Returns -1 if not a valid PE or no resource section.
pub fn get_resource_section_offset(data: &[u8]) -> i64 {
    if let Some(file) = pe64_from_bytes(data) {
        let dd = file.data_directory().get(2).map_or(0, |d| d.VirtualAddress);
        if dd == 0 {
            return -1;
        }
        return file.rva_to_file_offset(dd).map_or(-1, |o| o as i64);
    }
    if let Some(file) = pe32_from_bytes(data) {
        let dd = file.data_directory().get(2).map_or(0, |d| d.VirtualAddress);
        if dd == 0 {
            return -1;
        }
        return file.rva_to_file_offset(dd).map_or(-1, |o| o as i64);
    }
    -1
}

/// Check if the resources table RVA is within a section.
pub fn is_resources_table_correct(data: &[u8]) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        let rva = file.data_directory().get(2).map_or(0, |d| d.VirtualAddress);
        if rva == 0 {
            return true;
        }
        return file.rva_to_file_offset(rva).is_ok();
    }
    if let Some(file) = pe32_from_bytes(data) {
        let rva = file.data_directory().get(2).map_or(0, |d| d.VirtualAddress);
        if rva == 0 {
            return true;
        }
        return file.rva_to_file_offset(rva).is_ok();
    }
    false
}

/// Get the file data slice from the host API.
///
/// This is a helper that reads the entire file data from the host.
pub fn host_data(host: &Arc<dyn HostApi + Send + Sync>) -> Vec<u8> {
    let size = host.file_size() as usize;
    let mut data = Vec::with_capacity(size);
    for offset in 0..size as u64 {
        match host.read_u8(offset) {
            Ok(b) => data.push(b),
            Err(_) => break,
        }
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        // Ensure module compiles and links.
        let _ = is_pe;
        let _ = get_image_base;
    }
}

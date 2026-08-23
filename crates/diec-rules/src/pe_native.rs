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

/// Parse the .NET CLR runtime version string from the metadata root.
///
/// The CLR header (COR20_HEADER) is at the VA specified by data directory
/// entry 14. It contains a `MetaData` directory entry pointing to the
/// metadata root, which starts with a BSJB signature followed by a
/// version string (e.g., "v4.0.30319").
///
/// Returns an empty string if the PE is not .NET or the version cannot
/// be parsed.
pub fn get_net_version(data: &[u8]) -> String {
    let clr_rva = if let Some(file) = pe64_from_bytes(data) {
        match file.data_directory().get(14) {
            Some(d) if d.Size != 0 => d.VirtualAddress as u64,
            _ => return String::new(),
        }
    } else if let Some(file) = pe32_from_bytes(data) {
        match file.data_directory().get(14) {
            Some(d) if d.Size != 0 => d.VirtualAddress as u64,
            _ => return String::new(),
        }
    } else {
        return String::new();
    };

    let clr_offset = match rva_to_file_offset(data, clr_rva) {
        o if o >= 0 => o as usize,
        _ => return String::new(),
    };

    // COR20_HEADER layout:
    //   0: cb (4 bytes)
    //   4: MajorRuntimeVersion (2 bytes)
    //   6: MinorRuntimeVersion (2 bytes)
    //   8: MetaData.VirtualAddress (4 bytes)
    //  12: MetaData.Size (4 bytes)
    let md_rva = read_u32_le(data, clr_offset + 8);
    if md_rva == 0 {
        return String::new();
    }
    let md_offset = match rva_to_file_offset(data, md_rva as u64) {
        o if o >= 0 => o as usize,
        _ => return String::new(),
    };

    // Metadata root layout:
    //   0: Signature (4 bytes, 0x424A5342 = "BSJB")
    //   4: MajorVersion (2 bytes)
    //   6: MinorVersion (2 bytes)
    //   8: Reserved (4 bytes)
    //  12: VersionLength (4 bytes)
    //  16: Version string (VersionLength bytes, padded to 4-byte boundary)
    if data.len() < md_offset + 16 {
        return String::new();
    }
    let sig = read_u32_le(data, md_offset);
    if sig != 0x424A5342 {
        // "BSJB" in little-endian
        return String::new();
    }
    let ver_len = read_u32_le(data, md_offset + 12) as usize;
    if ver_len == 0 || data.len() < md_offset + 16 + ver_len {
        return String::new();
    }
    let ver_bytes = &data[md_offset + 16..md_offset + 16 + ver_len];
    let version = String::from_utf8_lossy(ver_bytes)
        .trim_end_matches('\0')
        .to_string();
    if version.is_empty() {
        return String::new();
    }
    // Prefix with "v" if not already present (upstream convention).
    if version.starts_with('v') || version.starts_with('V') {
        version
    } else {
        format!("v{version}")
    }
}

/// Extract .NET user strings (UTF-16LE) and ANSI strings from metadata heaps.
///
/// Returns (unicode_strings, ansi_strings). Empty vectors if not .NET or
/// metadata cannot be parsed.
pub fn get_net_strings(data: &[u8]) -> (Vec<String>, Vec<String>) {
    // Get CLR header RVA from data directory entry 14.
    let clr_rva = if let Some(file) = pe64_from_bytes(data) {
        match file.data_directory().get(14) {
            Some(d) if d.Size != 0 => d.VirtualAddress as u64,
            _ => return (Vec::new(), Vec::new()),
        }
    } else if let Some(file) = pe32_from_bytes(data) {
        match file.data_directory().get(14) {
            Some(d) if d.Size != 0 => d.VirtualAddress as u64,
            _ => return (Vec::new(), Vec::new()),
        }
    } else {
        return (Vec::new(), Vec::new());
    };

    let clr_offset = match rva_to_file_offset(data, clr_rva) {
        o if o >= 0 => o as usize,
        _ => return (Vec::new(), Vec::new()),
    };

    // COR20_HEADER: MetaData at offset 8 (RVA) + 12 (Size)
    let md_rva = read_u32_le(data, clr_offset + 8) as u64;
    let md_size = read_u32_le(data, clr_offset + 12) as usize;
    if md_rva == 0 || md_size == 0 {
        return (Vec::new(), Vec::new());
    }
    let md_offset = match rva_to_file_offset(data, md_rva) {
        o if o >= 0 => o as usize,
        _ => return (Vec::new(), Vec::new()),
    };
    let md_end = (md_offset + md_size).min(data.len());

    // Metadata root:
    //   0: Signature (4, "BSJB")
    //   4: MajorVersion (2)
    //   6: MinorVersion (2)
    //   8: Reserved (4)
    //  12: VersionLength (4)
    //  16: Version string (padded to 4-byte boundary)
    //  16+ver_padded: Flags (2)
    //  18+ver_padded: Streams (2)
    //  20+ver_padded: Stream headers
    if data.len() < md_offset + 20 {
        return (Vec::new(), Vec::new());
    }
    let sig = read_u32_le(data, md_offset);
    if sig != 0x424A5342 {
        return (Vec::new(), Vec::new());
    }
    let ver_len = read_u32_le(data, md_offset + 12) as usize;
    // Version string is padded to 4-byte boundary.
    let ver_padded = (ver_len + 3) & !3;
    let streams_off = md_offset + 16 + ver_padded + 4; // +4 for Flags(2)+Streams(2)
    if streams_off + 4 > md_end {
        return (Vec::new(), Vec::new());
    }
    let n_streams = read_u16_le(data, streams_off - 2) as usize;

    // Parse stream headers: each is Offset(4) + Size(4) + Name(null-terminated, padded to 4)
    let mut us_offset = 0usize;
    let mut us_size = 0usize;
    let mut strings_offset = 0usize;
    let mut strings_size = 0usize;
    let mut pos = streams_off;
    for _ in 0..n_streams {
        if pos + 8 > md_end {
            break;
        }
        let s_off = read_u32_le(data, pos) as usize;
        let s_size = read_u32_le(data, pos + 4) as usize;
        pos += 8;
        // Read null-terminated name, padded to 4-byte boundary.
        let name_start = pos;
        while pos < md_end && data[pos] != 0 {
            pos += 1;
        }
        let name = String::from_utf8_lossy(&data[name_start..pos]);
        // Skip null terminator + padding to 4-byte boundary.
        pos += 1; // null terminator
        pos = (pos + 3) & !3; // pad to 4
        match name.as_ref() {
            "#US" => {
                us_offset = md_offset + s_off;
                us_size = s_size;
            }
            "#Strings" => {
                strings_offset = md_offset + s_off;
                strings_size = s_size;
            }
            _ => {}
        }
    }

    let mut unicode_strings = Vec::new();
    let mut ansi_strings = Vec::new();

    // Parse #US heap: starts at offset 0 with a null byte.
    // Each entry: CompressedLength (1 or 2 bytes) + UTF-16LE string bytes.
    // Simple: length byte, if 0x80 bit set then 2-byte length (big endian).
    if us_size > 1 && us_offset + us_size <= data.len() {
        let us_end = us_offset + us_size;
        let mut i = us_offset + 1; // skip initial null byte
        while i < us_end {
            let len_byte = data[i];
            let (str_len, hdr_size) = if len_byte & 0x80 != 0 {
                // 2-byte compressed length
                if i + 2 > us_end {
                    break;
                }
                let len = ((len_byte & 0x7F) as usize) << 8 | data[i + 1] as usize;
                (len, 2)
            } else {
                (len_byte as usize, 1)
            };
            i += hdr_size;
            if str_len == 0 || i + str_len > us_end {
                i += str_len;
                continue;
            }
            // UTF-16LE string (str_len bytes, includes trailing byte sometimes)
            let str_bytes = &data[i..i + str_len];
            let utf16_len = str_len / 2;
            let mut u16s = Vec::with_capacity(utf16_len);
            for j in 0..utf16_len {
                if j * 2 + 1 < str_len {
                    u16s.push(u16::from_le_bytes([str_bytes[j * 2], str_bytes[j * 2 + 1]]));
                }
            }
            let s = String::from_utf16_lossy(&u16s);
            if !s.is_empty() && s.chars().all(|c| !c.is_control() || c == ' ') {
                unicode_strings.push(s);
            }
            i += str_len;
        }
    }

    // Parse #Strings heap: null-terminated UTF-8 strings, starting at offset 1.
    if strings_size > 1 && strings_offset + strings_size <= data.len() {
        let s_end = strings_offset + strings_size;
        let mut i = strings_offset + 1; // skip initial null byte
        while i < s_end {
            let start = i;
            while i < s_end && data[i] != 0 {
                i += 1;
            }
            if i > start {
                let s = String::from_utf8_lossy(&data[start..i]).to_string();
                if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    ansi_strings.push(s);
                }
            }
            i += 1; // skip null
        }
    }

    (unicode_strings, ansi_strings)
}

/// Read a little-endian u16 from data at the given offset.
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if data.len() < offset + 2 {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a little-endian u32 from data at the given offset.
/// Returns 0 if out of bounds.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if data.len() < offset + 4 {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Imported library with its functions, grouped by DLL.
#[derive(Clone, Debug, Default)]
pub struct PeImportLibrary {
    /// DLL name (e.g., "KERNEL32.DLL").
    pub name: String,
    /// Function names imported from this library, in import-table order.
    pub functions: Vec<String>,
}

/// Batch PE parse result: imports, exports, and metadata in one pass.
pub struct PeBatchInfo {
    /// Imported library (DLL) names (flat list, backward compatible).
    pub libraries: Vec<String>,
    /// Imported function names (flat list, backward compatible).
    pub functions: Vec<String>,
    /// Imports grouped by library (for per-library queries).
    pub imports: Vec<PeImportLibrary>,
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
    /// .NET CLR runtime version string (e.g., "v4.0.30319"), empty if not .NET.
    pub net_version: String,
    /// Resource entries: (name_or_id, type_id, offset, size).
    pub resource_entries: Vec<(String, u32, u32, u32)>,
    /// .NET user strings (UTF-16) from #US heap, empty if not .NET.
    pub net_unicode_strings: Vec<String>,
    /// .NET ANSI strings from #Strings heap, empty if not .NET.
    pub net_ansi_strings: Vec<String>,
    /// CRC32C hashes of concatenated import function names per library.
    /// Used by PE.isImportPositionHashPresent(libraryIndex, hash).
    pub import_position_hashes: Vec<u32>,
}

/// Compute CRC32C (Castagnoli) with initial value 0 and final XOR.
/// This matches XBinary::getStringCustomCRC32 from upstream DIE-engine.
fn string_custom_crc32(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut result: u32 = 0;
    for &byte in bytes {
        result ^= byte as u32;
        for _ in 0..8 {
            if result & 1 != 0 {
                result = (result >> 1) ^ 0x82f63b78;
            } else {
                result >>= 1;
            }
        }
    }
    !result
}

/// Compute import position hashes for all libraries.
/// Each hash is CRC32C of the concatenation of all function names in that library.
fn compute_import_position_hashes(imports: &[PeImportLibrary]) -> Vec<u32> {
    imports
        .iter()
        .map(|lib| {
            let concatenated: String = lib.functions.iter().cloned().collect();
            string_custom_crc32(&concatenated)
        })
        .collect()
}

/// Parse all PE information in a single pass to avoid repeated PeFile construction.
///
/// Returns None if not a valid PE.
pub fn parse_batch(data: &[u8]) -> Option<PeBatchInfo> {
    // Parse .NET version and strings once (used for both PE32 and PE64 paths).
    let net_version = get_net_version(data);
    let (net_unicode_strings, net_ansi_strings) = get_net_strings(data);
    // Try PE64 first.
    if let Some(file) = pe64_from_bytes(data) {
        let mut info = parse_batch_pe64(file);
        info.net_version = net_version;
        info.net_unicode_strings = net_unicode_strings;
        info.net_ansi_strings = net_ansi_strings;
        return Some(info);
    }
    // Try PE32.
    if let Some(file) = pe32_from_bytes(data) {
        let mut info = parse_batch_pe32(file);
        info.net_version = net_version;
        info.net_unicode_strings = net_unicode_strings;
        info.net_ansi_strings = net_ansi_strings;
        return Some(info);
    }
    None
}

/// Parse batch info from a PE64 file.
fn parse_batch_pe64(file: pelite::pe64::PeFile<'_>) -> PeBatchInfo {
    let mut libraries = Vec::new();
    let mut functions = Vec::new();
    let mut imports = Vec::new();
    if let Ok(imports_data) = file.imports() {
        for desc in imports_data.iter() {
            let mut lib_funcs = Vec::new();
            let mut lib_name = String::new();
            if let Ok(name) = desc.dll_name()
                && let Ok(s) = name.to_str()
            {
                lib_name = s.to_string();
                if !libraries.contains(&lib_name) {
                    libraries.push(lib_name.clone());
                }
            }
            // Try INT (OriginalFirstThunk) first, fall back to IAT (FirstThunk)
            // when OFT is 0 (common in packed/minified PE files).
            let parsed_funcs = parse_import_thunks_pe64(&desc);
            for s in parsed_funcs {
                functions.push(s.clone());
                lib_funcs.push(s);
            }
            if !lib_name.is_empty() || !lib_funcs.is_empty() {
                imports.push(PeImportLibrary {
                    name: lib_name,
                    functions: lib_funcs,
                });
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
    let resource_entries = parse_resource_entries_pe64(&file);
    let import_position_hashes = compute_import_position_hashes(&imports);

    PeBatchInfo {
        libraries,
        functions,
        imports,
        exports,
        is_net,
        is_signed,
        manifest,
        file_version,
        product_version,
        number_of_resources,
        net_version: String::new(),
        resource_entries,
        net_unicode_strings: Vec::new(),
        net_ansi_strings: Vec::new(),
        import_position_hashes,
    }
}

/// Parse import function names from a PE64 import descriptor.
/// Tries INT (OriginalFirstThunk) first, falls back to IAT (FirstThunk).
fn parse_import_thunks_pe64(
    desc: &pelite::pe64::imports::Desc<'_, pelite::pe64::PeFile<'_>>,
) -> Vec<String> {
    // Try INT (OriginalFirstThunk) first.
    if let Ok(int) = desc.int() {
        let mut funcs = Vec::new();
        for imp in int {
            if let Ok(pelite::pe64::imports::Import::ByName { name, .. }) = imp
                && let Ok(s) = name.to_str()
            {
                funcs.push(s.to_string());
            }
        }
        if !funcs.is_empty() {
            return funcs;
        }
    }
    // Fall back to IAT (FirstThunk) when OFT is 0 or empty.
    // Manually resolve each VA to import hint/name.
    let pe = desc.pe();
    let Ok(iat) = desc.iat() else {
        return Vec::new();
    };
    let mut funcs = Vec::new();
    for &va in iat {
        if va == 0 {
            break;
        }
        const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;
        if va & IMAGE_ORDINAL_FLAG64 != 0 {
            // Import by ordinal, skip (no name).
            continue;
        }
        let rva = va as u32;
        if let Ok(name) = pe.derva_c_str(rva + 2)
            && let Ok(s) = name.to_str()
        {
            funcs.push(s.to_string());
        }
    }
    funcs
}

/// Parse batch info from a PE32 file.
fn parse_batch_pe32(file: pelite::pe32::PeFile<'_>) -> PeBatchInfo {
    let mut libraries = Vec::new();
    let mut functions = Vec::new();
    let mut imports = Vec::new();
    if let Ok(imports_data) = file.imports() {
        for desc in imports_data.iter() {
            let mut lib_funcs = Vec::new();
            let mut lib_name = String::new();
            if let Ok(name) = desc.dll_name()
                && let Ok(s) = name.to_str()
            {
                lib_name = s.to_string();
                if !libraries.contains(&lib_name) {
                    libraries.push(lib_name.clone());
                }
            }
            // Try INT (OriginalFirstThunk) first, fall back to IAT (FirstThunk)
            // when OFT is 0 (common in packed/minified PE files).
            let parsed_funcs = parse_import_thunks_pe32(&desc);
            for s in parsed_funcs {
                functions.push(s.clone());
                lib_funcs.push(s);
            }
            if !lib_name.is_empty() || !lib_funcs.is_empty() {
                imports.push(PeImportLibrary {
                    name: lib_name,
                    functions: lib_funcs,
                });
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
    let resource_entries = parse_resource_entries_pe32(&file);
    let import_position_hashes = compute_import_position_hashes(&imports);

    PeBatchInfo {
        libraries,
        functions,
        imports,
        exports,
        is_net,
        is_signed,
        manifest,
        file_version,
        product_version,
        number_of_resources,
        net_version: String::new(),
        resource_entries,
        net_unicode_strings: Vec::new(),
        net_ansi_strings: Vec::new(),
        import_position_hashes,
    }
}

/// Parse import function names from a PE32 import descriptor.
/// Tries INT (OriginalFirstThunk) first, falls back to IAT (FirstThunk).
fn parse_import_thunks_pe32(
    desc: &pelite::pe32::imports::Desc<'_, pelite::pe32::PeFile<'_>>,
) -> Vec<String> {
    // Try INT (OriginalFirstThunk) first.
    if let Ok(int) = desc.int() {
        let mut funcs = Vec::new();
        for imp in int {
            if let Ok(pelite::pe32::imports::Import::ByName { name, .. }) = imp
                && let Ok(s) = name.to_str()
            {
                funcs.push(s.to_string());
            }
        }
        if !funcs.is_empty() {
            return funcs;
        }
    }
    // Fall back to IAT (FirstThunk) when OFT is 0 or empty.
    let pe = desc.pe();
    let Ok(iat) = desc.iat() else {
        return Vec::new();
    };
    let mut funcs = Vec::new();
    for &va in iat {
        if va == 0 {
            break;
        }
        const IMAGE_ORDINAL_FLAG32: u32 = 0x80000000;
        if va & IMAGE_ORDINAL_FLAG32 != 0 {
            // Import by ordinal, skip (no name).
            continue;
        }
        let rva = va;
        if let Ok(name) = pe.derva_c_str(rva + 2)
            && let Ok(s) = name.to_str()
        {
            funcs.push(s.to_string());
        }
    }
    funcs
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

/// Extract resource entries (name_or_id, type_id, file_offset, size) from a PE64 file.
/// Handles 3-level resource directory nesting (type → name → language).
/// Converts RVAs to file offsets for use by PE.getResourceOffsetByNumber.
fn parse_resource_entries_pe64(file: &pelite::pe64::PeFile<'_>) -> Vec<(String, u32, u32, u32)> {
    let Ok(res) = file.resources() else {
        return Vec::new();
    };
    let Ok(root) = res.root() else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for type_entry in root.entries() {
        let type_id = match type_entry.name() {
            Ok(pelite::resources::Name::Id(id)) => id,
            _ => 0,
        };
        if let Ok(pelite::resources::Entry::Directory(type_dir)) = type_entry.entry() {
            collect_resource_entries_pe64(file, &type_dir, type_id, &mut entries);
        }
    }
    entries
}

/// Recursively collect resource data entries from a PE64 resource directory.
fn collect_resource_entries_pe64(
    file: &pelite::pe64::PeFile<'_>,
    dir: &pelite::resources::Directory<'_>,
    type_id: u32,
    entries: &mut Vec<(String, u32, u32, u32)>,
) {
    for res_entry in dir.entries() {
        let name = match res_entry.name() {
            Ok(pelite::resources::Name::Id(id)) => format!("#{}", id),
            Ok(pelite::resources::Name::Wide(ws)) => String::from_utf16_lossy(ws),
            _ => String::new(),
        };
        match res_entry.entry() {
            Ok(pelite::resources::Entry::DataEntry(data)) => {
                let rva = data.image().OffsetToData;
                let file_off = file.rva_to_file_offset(rva).unwrap_or(0) as u32;
                entries.push((name, type_id, file_off, data.image().Size));
            }
            Ok(pelite::resources::Entry::Directory(sub_dir)) => {
                collect_resource_entries_pe64(file, &sub_dir, type_id, entries);
            }
            _ => {}
        }
    }
}

/// Extract resource entries (name_or_id, type_id, file_offset, size) from a PE32 file.
/// Handles 3-level resource directory nesting (type → name → language).
/// Converts RVAs to file offsets for use by PE.getResourceOffsetByNumber.
fn parse_resource_entries_pe32(file: &pelite::pe32::PeFile<'_>) -> Vec<(String, u32, u32, u32)> {
    let Ok(res) = file.resources() else {
        return Vec::new();
    };
    let Ok(root) = res.root() else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for type_entry in root.entries() {
        let type_id = match type_entry.name() {
            Ok(pelite::resources::Name::Id(id)) => id,
            _ => 0,
        };
        if let Ok(pelite::resources::Entry::Directory(type_dir)) = type_entry.entry() {
            collect_resource_entries_pe32(file, &type_dir, type_id, &mut entries);
        }
    }
    entries
}

/// Recursively collect resource data entries from a PE32 resource directory.
fn collect_resource_entries_pe32(
    file: &pelite::pe32::PeFile<'_>,
    dir: &pelite::resources::Directory<'_>,
    type_id: u32,
    entries: &mut Vec<(String, u32, u32, u32)>,
) {
    for res_entry in dir.entries() {
        let name = match res_entry.name() {
            Ok(pelite::resources::Name::Id(id)) => format!("#{}", id),
            Ok(pelite::resources::Name::Wide(ws)) => String::from_utf16_lossy(ws),
            _ => String::new(),
        };
        match res_entry.entry() {
            Ok(pelite::resources::Entry::DataEntry(data)) => {
                let rva = data.image().OffsetToData;
                let file_off = file.rva_to_file_offset(rva).unwrap_or(0) as u32;
                entries.push((name, type_id, file_off, data.image().Size));
            }
            Ok(pelite::resources::Entry::Directory(sub_dir)) => {
                collect_resource_entries_pe32(file, &sub_dir, type_id, entries);
            }
            _ => {}
        }
    }
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

/// Check if a resource group (type-level directory) with the given name exists.
///
/// PE resources are organized as root -> type -> name -> language.
/// A "resource group" is a type-level directory entry. This checks whether
/// any type-level entry has a name matching `group_name` (case-sensitive).
/// Returns false if not a valid PE or the group is not found.
pub fn is_resource_group_name_present(data: &[u8], group_name: &str) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        if let Ok(res) = file.resources()
            && let Ok(root) = res.root()
        {
            for entry in root.entries() {
                if let Ok(n) = entry.name()
                    && format_resource_name(&n) == group_name
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
                && format_resource_name(&n) == group_name
            {
                return true;
            }
        }
    }
    false
}

/// Check if a resource group (type-level directory) with the given ID exists.
///
/// PE resources are organized as root -> type -> name -> language.
/// Standard type IDs include 1 (CURSOR), 2 (BITMAP), 3 (ICON), 4 (MENU),
/// 5 (DIALOG), 6 (STRING), 7 (FONTDIR), 8 (FONT), 9 (ACCELERATOR),
/// 10 (RCDATA), 11 (MESSAGETABLE), 12 (GROUP_CURSOR), 14 (GROUP_ICON),
/// 16 (VERSION), 24 (MANIFEST).
/// Returns false if not a valid PE or the group is not found.
pub fn is_resource_group_id_present(data: &[u8], group_id: u32) -> bool {
    if let Some(file) = pe64_from_bytes(data) {
        if let Ok(res) = file.resources()
            && let Ok(root) = res.root()
        {
            for entry in root.entries() {
                if entry.image().Name == group_id {
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
            if entry.image().Name == group_id {
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

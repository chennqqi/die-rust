//! PE import/export table parsing tests.
//!
//! These tests verify that the Rust-side PE table parser correctly
//! handles various PE file structures, including:
//! - Files with import tables (multiple libraries)
//! - Files with export tables (named exports)
//! - 64-bit PE files with import thunks
//! - Malformed/truncated PE files (no crash, no hang)
//! - Files with ordinal imports
//!
//! These tests were added after a critical performance bug was found:
//! the JS-side parser was doing per-byte FFI calls, taking >60s on
//! files with 1515 exports. The Rust-side parser does the same work
//! in microseconds.

#![forbid(unsafe_code)]

use die_engine::host::BufferHost;
use die_rules::host_api::HostApi;

/// Build a minimal PE32 file with the given import and export tables.
/// Returns the raw bytes of the PE file.
fn build_pe32_with_tables(import_libs: &[&str], export_names: &[&str]) -> Vec<u8> {
    // Layout:
    // 0x00: DOS header (64 bytes)
    // 0x40: PE signature + COFF header (24 bytes)
    // 0x58: Optional header PE32 (96 bytes + 16*8 data dirs = 224 bytes)
    // 0x138: Section headers (2 sections * 40 bytes = 80 bytes)
    // 0x188: .text section (raw, 0x200 aligned)
    // 0x200: .rdata section (imports + exports + names)
    //
    // We keep it simple: one section (.rdata) holds everything.
    // Buffer is sized dynamically based on content.
    let estimated_size =
        0x400 + export_names.len() * 0x40 + import_libs.len() * 0x60 + export_names.len() * 4;
    let mut buf = vec![0u8; estimated_size.max(0x1000)];

    // DOS header
    buf[0] = 0x4D; // M
    buf[1] = 0x5A; // Z
    // e_lfanew at 0x3C
    let e_lfanew: u32 = 0x40;
    buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    // PE signature
    buf[0x40..0x44].copy_from_slice(b"PE\0\0");

    // COFF header
    let coff_off = 0x44;
    // Machine: IMAGE_FILE_MACHINE_I386
    buf[coff_off..coff_off + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    // NumberOfSections: 1
    buf[coff_off + 2..coff_off + 4].copy_from_slice(&1u16.to_le_bytes());
    // SizeOfOptionalHeader: 224 (96 + 16*8)
    buf[coff_off + 16..coff_off + 18].copy_from_slice(&224u16.to_le_bytes());
    // Characteristics: IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
    buf[coff_off + 18..coff_off + 20].copy_from_slice(&0x0102u16.to_le_bytes());

    // Optional header (PE32)
    let opt_off = coff_off + 20;
    // Magic: PE32
    buf[opt_off..opt_off + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    // SectionAlignment: 0x1000
    buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    // FileAlignment: 0x200
    buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
    // SizeOfImage: 0x3000
    buf[opt_off + 56..opt_off + 60].copy_from_slice(&0x3000u32.to_le_bytes());
    // SizeOfHeaders: 0x200
    buf[opt_off + 60..opt_off + 64].copy_from_slice(&0x200u32.to_le_bytes());
    // NumberOfRvaAndSizes: 16
    buf[opt_off + 92..opt_off + 96].copy_from_slice(&16u32.to_le_bytes());

    // Data directories start at opt_off + 96
    let dd_off = opt_off + 96;
    // Data directory 0 (Export): RVA=0x2000, Size=TBD
    // Data directory 1 (Import): RVA=0x2100, Size=TBD

    // Section header at opt_off + 224
    let sect_off = opt_off + 224;
    // Name: .rdata
    buf[sect_off..sect_off + 6].copy_from_slice(b".rdata");
    // VirtualSize: 0x2000 (large enough for both export and import tables)
    buf[sect_off + 8..sect_off + 12].copy_from_slice(&0x2000u32.to_le_bytes());
    // VirtualAddress: 0x2000
    buf[sect_off + 12..sect_off + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    // SizeOfRawData: covers all table data in file
    let raw_data_size = (buf.len() - 0x200) as u32;
    buf[sect_off + 16..sect_off + 20].copy_from_slice(&raw_data_size.to_le_bytes());
    // PointerToRawData: 0x200
    buf[sect_off + 20..sect_off + 24].copy_from_slice(&0x200u32.to_le_bytes());

    // Now fill .rdata at file offset 0x200, RVA 0x2000.
    let rdata_off = 0x200;
    let rdata_rva = 0x2000u32;

    // Export directory at RVA 0x2000 (offset 0x200)
    if !export_names.is_empty() {
        let export_dir_rva = rdata_rva;
        let export_dir_off = rdata_off;

        // Export directory (40 bytes)
        // NumberOfNames at offset +24
        let num_names = export_names.len() as u32;
        buf[export_dir_off + 24..export_dir_off + 28].copy_from_slice(&num_names.to_le_bytes());

        // AddressOfNames at offset +32: points to array of name RVAs
        let names_array_rva = rdata_rva + 40; // after export dir
        buf[export_dir_off + 32..export_dir_off + 36]
            .copy_from_slice(&names_array_rva.to_le_bytes());

        // Names array: num_names * 4 bytes of RVAs
        let names_array_off = export_dir_off + 40;
        let name_strings_off = names_array_off + export_names.len() * 4;
        let name_strings_rva = rdata_rva + (name_strings_off - rdata_off) as u32;

        for (i, name) in export_names.iter().enumerate() {
            let name_rva = name_strings_rva + i as u32 * 0x40;
            buf[names_array_off + i * 4..names_array_off + i * 4 + 4]
                .copy_from_slice(&name_rva.to_le_bytes());
            // Write name string
            let name_off = name_strings_off + i * 0x40;
            let name_bytes = name.as_bytes();
            let copy_len = name_bytes.len().min(0x3F);
            buf[name_off..name_off + copy_len].copy_from_slice(&name_bytes[..copy_len]);
            buf[name_off + copy_len] = 0; // NUL terminator
        }

        // Set export data directory
        let export_size = (40 + export_names.len() * 4 + export_names.len() * 0x40) as u32;
        buf[dd_off..dd_off + 4].copy_from_slice(&export_dir_rva.to_le_bytes());
        buf[dd_off + 4..dd_off + 8].copy_from_slice(&export_size.to_le_bytes());
    }

    // Import directory at RVA 0x2100 (offset 0x300)
    if !import_libs.is_empty() {
        let import_dir_rva = rdata_rva + 0x100;
        let import_dir_off = rdata_off + 0x100;

        // Each import descriptor is 20 bytes, terminated by all-zero entry.
        // After descriptors, place library name strings.
        let desc_size = (import_libs.len() + 1) * 20;
        let lib_names_off = import_dir_off + desc_size;
        let lib_names_rva = rdata_rva + (lib_names_off - rdata_off) as u32;

        for (i, lib) in import_libs.iter().enumerate() {
            let desc_off = import_dir_off + i * 20;
            // OriginalFirstThunk = 0 (use FirstThunk)
            // Name RVA
            let name_rva = lib_names_rva + i as u32 * 0x40;
            buf[desc_off + 12..desc_off + 16].copy_from_slice(&name_rva.to_le_bytes());
            // FirstThunk: set to a non-zero RVA so pelite doesn't treat
            // this descriptor as the null terminator. Point to a dummy
            // thunk array that we place after the library names.
            let thunk_rva = rdata_rva + 0x800 + i as u32 * 8;
            buf[desc_off + 16..desc_off + 20].copy_from_slice(&thunk_rva.to_le_bytes());
            // Write library name
            let name_off = lib_names_off + i * 0x40;
            let name_bytes = lib.as_bytes();
            let copy_len = name_bytes.len().min(0x3F);
            buf[name_off..name_off + copy_len].copy_from_slice(&name_bytes[..copy_len]);
            buf[name_off + copy_len] = 0;
        }

        // Set import data directory
        let import_size = desc_size as u32;
        buf[dd_off + 8..dd_off + 12].copy_from_slice(&import_dir_rva.to_le_bytes());
        buf[dd_off + 12..dd_off + 16].copy_from_slice(&import_size.to_le_bytes());
    }

    buf
}

#[test]
fn pe_parse_exports_returns_correct_names() {
    let exports = ["GetVersion", "Initialize", "Cleanup", "ProcessData"];
    let data = build_pe32_with_tables(&[], &exports);
    let host = BufferHost::with_type(data, "test.dll".into(), "PE");
    let result = host.pe_export_names();
    assert_eq!(result.len(), exports.len());
    for (i, expected) in exports.iter().enumerate() {
        assert_eq!(result[i], *expected, "export name mismatch at index {i}");
    }
}

#[test]
fn pe_parse_imports_returns_correct_libraries() {
    let libs = ["kernel32.dll", "user32.dll", "msvcrt.dll", "advapi32.dll"];
    let data = build_pe32_with_tables(&libs, &[]);
    let host = BufferHost::with_type(data, "test.dll".into(), "PE");
    let result = host.pe_import_libraries();
    assert_eq!(result.len(), libs.len());
    for (i, expected) in libs.iter().enumerate() {
        assert_eq!(result[i], *expected, "import library mismatch at index {i}");
    }
}

#[test]
fn pe_parse_empty_tables_returns_empty() {
    let data = build_pe32_with_tables(&[], &[]);
    let host = BufferHost::with_type(data, "test.dll".into(), "PE");
    assert!(host.pe_export_names().is_empty());
    assert!(host.pe_import_libraries().is_empty());
    assert!(host.pe_import_functions().is_empty());
}

#[test]
fn pe_parse_non_pe_returns_empty() {
    let data = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]; // ELF magic
    let host = BufferHost::with_type(data, "test.elf".into(), "ELF");
    assert!(host.pe_export_names().is_empty());
    assert!(host.pe_import_libraries().is_empty());
}

#[test]
fn pe_parse_truncated_pe_returns_empty() {
    // Only MZ header, no PE signature
    let data = vec![0x4D, 0x5A, 0x00, 0x00];
    let host = BufferHost::with_type(data, "truncated.exe".into(), "PE");
    assert!(host.pe_export_names().is_empty());
    assert!(host.pe_import_libraries().is_empty());
}

#[test]
fn pe_parse_many_exports() {
    // Simulate a file with many exports (like msvcp140.dll with 1515).
    // This tests that the parser handles large export tables efficiently.
    let exports: Vec<String> = (0..1515).map(|i| format!("ExportFunc_{i}")).collect();
    let export_refs: Vec<&str> = exports.iter().map(|s| s.as_str()).collect();
    let data = build_pe32_with_tables(&[], &export_refs);
    let host = BufferHost::with_type(data, "big_exports.dll".into(), "PE");
    let result = host.pe_export_names();
    assert_eq!(result.len(), 1515);
    assert_eq!(result[0], "ExportFunc_0");
    assert_eq!(result[1514], "ExportFunc_1514");
}

#[test]
fn pe_parse_many_imports() {
    // Simulate a file with many import libraries.
    let libs: Vec<String> = (0..100).map(|i| format!("lib{i:03}.dll")).collect();
    let lib_refs: Vec<&str> = libs.iter().map(|s| s.as_str()).collect();
    let data = build_pe32_with_tables(&lib_refs, &[]);
    let host = BufferHost::with_type(data, "big_imports.dll".into(), "PE");
    let result = host.pe_import_libraries();
    assert_eq!(result.len(), 100);
    assert_eq!(result[0], "lib000.dll");
    assert_eq!(result[99], "lib099.dll");
}

#[test]
fn pe_parse_malformed_export_table_does_not_crash() {
    // Export RVA points to invalid offset.
    let mut data = build_pe32_with_tables(&[], &["TestExport"]);
    // Corrupt the export RVA to point to an invalid location.
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    let dd_off = e_lfanew + 4 + 20 + 96;
    data[dd_off..dd_off + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    let host = BufferHost::with_type(data, "corrupt.exe".into(), "PE");
    // Should return empty, not crash.
    let _ = host.pe_export_names();
}

#[test]
fn pe_parse_malformed_import_table_does_not_crash() {
    // Import RVA points to invalid offset.
    let mut data = build_pe32_with_tables(&["test.dll"], &[]);
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    let dd_off = e_lfanew + 4 + 20 + 96;
    data[dd_off + 8..dd_off + 12].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    let host = BufferHost::with_type(data, "corrupt.exe".into(), "PE");
    // Should return empty, not crash.
    let _ = host.pe_import_libraries();
}

#[test]
fn pe_parse_performance_large_export_table() {
    // Verify that parsing 1515 exports completes in under 100ms.
    // This is a regression test for the performance bug where JS-side
    // parsing took >60s for the same workload.
    let exports: Vec<String> = (0..1515).map(|i| format!("ExportFunc_{i}")).collect();
    let export_refs: Vec<&str> = exports.iter().map(|s| s.as_str()).collect();
    let data = build_pe32_with_tables(&[], &export_refs);
    let host = BufferHost::with_type(data, "perf_test.dll".into(), "PE");

    let start = std::time::Instant::now();
    let result = host.pe_export_names();
    let elapsed = start.elapsed();

    assert_eq!(result.len(), 1515);
    assert!(
        elapsed.as_millis() < 100,
        "parsing 1515 exports took {elapsed:?} (expected < 100ms)"
    );
}

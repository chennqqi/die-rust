//! PE rule end-to-end execution tests.
//!
//! These tests verify that PE-specific rules execute correctly against
//! real PE files with import/export tables. They were added after
//! discovering that:
//!
//! 1. PE rules were never tested with real PE host API (batch_load_pe.rs
//!    used DummyHost returning empty values).
//! 2. The JS-side import/export parser had a f64 precision bug for
//!    64-bit PE thunks that caused infinite loops.
//! 3. findSignature 3-arg form searched the entire file instead of
//!    the specified range, causing >60s timeouts on large files.
//!
//! These tests use the full scanner with the upstream database to
//! verify PE rules produce correct detections on real PE files.

#![forbid(unsafe_code)]

use die_core::cancel::CancellationToken;
use die_engine::{DatabaseBuilder, ScanFlags, scan_bytes};
use die_rules::host_api::HostApi;
use std::path::PathBuf;

/// Resolve the upstream database directory.
fn db_root() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let binding = PathBuf::from(manifest_dir);
    let root = binding
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    root.join("upstream/Detect-It-Easy/db")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

/// Resolve the corpus directory.
fn corpus_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("corpus"))
        .unwrap_or_else(|| PathBuf::from("corpus"))
}

/// Build a minimal PE32 file with an import table referencing msvcrt.dll.
/// This triggers the _Microsoft.6.sg rule which checks for Microsoft
/// runtime library imports.
fn build_pe_with_msvcrt_import() -> Vec<u8> {
    // Reuse the PE builder from pe_table_parsing tests.
    // We need a PE with "msvcrt.dll" in imports to trigger compiler detection.
    let mut buf = vec![0u8; 0x1000];

    // DOS header
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());

    // PE signature
    buf[0x40..0x44].copy_from_slice(b"PE\0\0");

    // COFF header
    let coff_off = 0x44;
    buf[coff_off..coff_off + 2].copy_from_slice(&0x014Cu16.to_le_bytes()); // I386
    buf[coff_off + 2..coff_off + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    buf[coff_off + 16..coff_off + 18].copy_from_slice(&224u16.to_le_bytes()); // OptHdr size
    buf[coff_off + 18..coff_off + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

    // Optional header (PE32)
    let opt_off = coff_off + 20;
    buf[opt_off..opt_off + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    buf[opt_off + 56..opt_off + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    buf[opt_off + 60..opt_off + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
    buf[opt_off + 92..opt_off + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    let dd_off = opt_off + 96;

    // Section header
    let sect_off = opt_off + 224;
    buf[sect_off..sect_off + 6].copy_from_slice(b".rdata");
    buf[sect_off + 8..sect_off + 12].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualSize
    buf[sect_off + 12..sect_off + 16].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
    buf[sect_off + 16..sect_off + 20].copy_from_slice(&0x800u32.to_le_bytes()); // SizeOfRawData
    buf[sect_off + 20..sect_off + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData

    // Import directory at RVA 0x2000 (file offset 0x200)
    let import_dir_rva = 0x2000u32;
    let import_dir_off = 0x200;

    // One import descriptor for msvcrt.dll + terminator
    // Descriptor: OFT(4) TimeDateStamp(4) ForwarderChain(4) Name(4) FirstThunk(4)
    let lib_name_off = import_dir_off + 40; // after 2 descriptors (20*2)
    let lib_name_rva = import_dir_rva + (lib_name_off - import_dir_off) as u32;

    // Descriptor for msvcrt.dll
    buf[import_dir_off + 12..import_dir_off + 16].copy_from_slice(&lib_name_rva.to_le_bytes());
    // FirstThunk = 0x2200 (RVA), points to a zero terminator
    buf[import_dir_off + 16..import_dir_off + 20].copy_from_slice(&0x2200u32.to_le_bytes());

    // Terminator (all zeros, already zero)

    // Library name string
    let name = b"msvcrt.dll\0";
    buf[lib_name_off..lib_name_off + name.len()].copy_from_slice(name);

    // Thunk at RVA 0x2200 (file offset 0x300) - just a zero terminator
    // Already zero in buf.

    // Set import data directory
    buf[dd_off + 8..dd_off + 12].copy_from_slice(&import_dir_rva.to_le_bytes());
    buf[dd_off + 12..dd_off + 16].copy_from_slice(&40u32.to_le_bytes()); // size

    buf
}

#[test]
fn pe_rule_executes_without_crash_on_synthetic_pe() {
    // Verify that PE rules can execute against a synthetic PE file
    // with an import table without crashing or hanging.
    // This is a regression test for the f64 precision bug that caused
    // infinite loops in 64-bit PE thunk parsing.
    let db_path = db_root();
    let database = match DatabaseBuilder::new(&db_path).build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            return;
        }
    };

    let data = build_pe_with_msvcrt_import();
    let cancel = CancellationToken::new();
    let start = std::time::Instant::now();
    let result = scan_bytes(&database, "test.dll", data, ScanFlags::default(), &cancel)
        .expect("scan should succeed");
    let elapsed = start.elapsed();

    // We don't assert specific detections because the synthetic PE
    // lacks a DOS stub and other features that real linker rules check.
    // The key assertion is that it completes without crashing or hanging.
    eprintln!(
        "synthetic PE scan: {} detections, {} diagnostics, {:?}",
        result.detections.len(),
        result.diagnostics.len(),
        elapsed
    );

    // Must complete in under 5 seconds (regression test for >60s hang).
    assert!(
        elapsed.as_secs() < 5,
        "synthetic PE scan took {elapsed:?} (expected < 5s)"
    );
}

#[test]
fn pe_scan_completes_quickly_for_synthetic_file() {
    // Regression test: verify PE scan completes in under 5 seconds.
    // Before the batch parsing optimization, even small PE files with
    // imports could take >60s due to per-byte JS→Rust FFI overhead.
    let db_path = db_root();
    let database = match DatabaseBuilder::new(&db_path).build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            return;
        }
    };

    let data = build_pe_with_msvcrt_import();
    let cancel = CancellationToken::new();
    let start = std::time::Instant::now();
    let _ = scan_bytes(&database, "test.dll", data, ScanFlags::default(), &cancel);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 5,
        "PE scan took {elapsed:?} (expected < 5s)"
    );
}

#[test]
fn pe_scan_corpus_with_tables_completes_quickly() {
    // Regression test: the corpus/with-tables.exe sample has real
    // import/export tables. Verify it scans without hanging.
    let db_path = db_root();
    let database = match DatabaseBuilder::new(&db_path).build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            return;
        }
    };

    let path = corpus_dir().join("with-tables.exe");
    if !path.exists() {
        eprintln!("SKIP: corpus/with-tables.exe not found");
        return;
    }

    let data = std::fs::read(&path).expect("read with-tables.exe");
    let cancel = CancellationToken::new();
    let start = std::time::Instant::now();
    let result = scan_bytes(
        &database,
        "with-tables.exe",
        data,
        ScanFlags::default(),
        &cancel,
    )
    .expect("scan should succeed");
    let elapsed = start.elapsed();

    eprintln!(
        "with-tables.exe: {} detections, {} diagnostics, {:?}",
        result.detections.len(),
        result.diagnostics.len(),
        elapsed
    );

    // Must complete in under 2 seconds (regression test for performance).
    assert!(
        elapsed.as_secs() < 2,
        "with-tables.exe scan took {elapsed:?} (expected < 2s)"
    );
}

#[test]
fn pe_rule_islibrarypresent_works_with_real_imports() {
    // Verify that PE.isLibraryPresent() works correctly when the PE file
    // has a real import table. This is a regression test for the batch
    // parsing optimization: previously, JS-side parsing had f64 precision
    // bugs that caused incorrect import counts and names.

    // Use corpus/with-tables.exe which imports "kernel32.dll".
    let path = corpus_dir().join("with-tables.exe");
    if !path.exists() {
        eprintln!("SKIP: corpus/with-tables.exe not found");
        return;
    }

    let data = std::fs::read(&path).expect("read with-tables.exe");

    // Verify at the host API level that imports are parsed correctly.
    let host = die_engine::host::BufferHost::with_type(data, "test.dll".into(), "PE");
    let libs = host.pe_import_libraries();
    assert!(
        libs.iter().any(|l| l.to_lowercase().contains("kernel32")),
        "expected kernel32.dll in imports, got: {libs:?}"
    );

    let exports = host.pe_export_names();
    assert!(
        exports.iter().any(|e| e == "ExportA"),
        "expected ExportA in exports, got: {exports:?}"
    );
    assert!(
        exports.iter().any(|e| e == "ExportB"),
        "expected ExportB in exports, got: {exports:?}"
    );
}

#[test]
fn pe_scan_real_exe_detects_linker() {
    // Test against the project's own diec.exe if available.
    let db_path = db_root();
    let database = match DatabaseBuilder::new(&db_path).build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            return;
        }
    };

    // Try to find diec.exe in target/release
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let diec_exe = PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("target/release/diec.exe"))
        .unwrap_or_else(|| PathBuf::from("target/release/diec.exe"));

    if !diec_exe.exists() {
        eprintln!("SKIP: diec.exe not found at {diec_exe:?}");
        return;
    }

    let data = match std::fs::read(&diec_exe) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: cannot read diec.exe: {e}");
            return;
        }
    };

    let cancel = CancellationToken::new();
    let start = std::time::Instant::now();
    let result = scan_bytes(&database, "diec.exe", data, ScanFlags::default(), &cancel)
        .expect("scan should succeed");
    let elapsed = start.elapsed();

    // diec.exe is compiled with MSVC, so it should detect Microsoft Linker.
    let has_linker = result
        .detections
        .iter()
        .any(|d| d.type_name == "linker" && d.name.to_lowercase().contains("microsoft"));
    assert!(
        has_linker,
        "expected Microsoft Linker detection, got: {:?}",
        result
            .detections
            .iter()
            .map(|d| format!("{}:{}", d.type_name, d.name))
            .collect::<Vec<_>>()
    );

    // Should complete in under 5 seconds.
    assert!(
        elapsed.as_secs() < 5,
        "diec.exe scan took {elapsed:?} (expected < 5s)"
    );
}

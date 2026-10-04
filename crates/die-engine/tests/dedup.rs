//! Unit tests for result deduplication (ADR 0027).
//!
//! These tests verify that `--alltypes` mode deduplicates detections
//! by default, and that `--no-dedup` preserves all detections.

#![forbid(unsafe_code)]

use die_core::cancel::CancellationToken;
use die_engine::{DatabaseBuilder, ScanDetection, ScanFlags, scan_bytes};
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

/// Build a minimal PE32 file (MZ + PE signature + minimal headers).
fn build_minimal_pe() -> Vec<u8> {
    let mut buf = vec![0u8; 0x400];
    // DOS header
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    // PE signature
    buf[0x40..0x44].copy_from_slice(b"PE\0\0");
    // COFF header (I386, 0 sections, optional header size 0)
    let coff_off = 0x44;
    buf[coff_off..coff_off + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    // Optional header (PE32 magic)
    let opt_off = coff_off + 20;
    buf[opt_off..opt_off + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    buf
}

/// Check if the upstream database is available.
fn db_available() -> bool {
    std::path::Path::new(&db_root()).is_dir()
}

/// Build the database from the upstream rules.
fn build_db() -> die_engine::Database {
    let db_path = db_root();
    DatabaseBuilder::new(&db_path)
        .build()
        .expect("database build")
}

/// Scan a PE file with `--alltypes` and verify dedup removes cross-group duplicates.
#[test]
fn alltypes_dedup_removes_duplicates() {
    if !db_available() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    let db = build_db();
    let data = build_minimal_pe();
    let cancel = CancellationToken::new();

    let flags = ScanFlags {
        all_types: true,
        no_dedup: false,
        ..Default::default()
    };

    let result = scan_bytes(&db, "test.exe", data, flags, &cancel).expect("scan ok");

    // Collect (type_name, name) pairs and check for duplicates.
    let mut seen = std::collections::HashSet::new();
    for d in &result.detections {
        let key = (d.type_name.clone(), d.name.clone());
        assert!(
            seen.insert(key),
            "Duplicate detection found after dedup: type_name={}, name={}",
            d.type_name,
            d.name
        );
    }
}

/// Scan a PE file with `--alltypes --no-dedup` and verify it has >= detections.
#[test]
fn no_dedup_produces_more_or_equal_detections() {
    if !db_available() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    let db = build_db();
    let cancel = CancellationToken::new();

    // With dedup (default)
    let flags_dedup = ScanFlags {
        all_types: true,
        no_dedup: false,
        ..Default::default()
    };
    let result_dedup =
        scan_bytes(&db, "test.exe", build_minimal_pe(), flags_dedup, &cancel).expect("scan ok");

    // Without dedup
    let flags_no_dedup = ScanFlags {
        all_types: true,
        no_dedup: true,
        ..Default::default()
    };
    let result_no_dedup =
        scan_bytes(&db, "test.exe", build_minimal_pe(), flags_no_dedup, &cancel).expect("scan ok");

    assert!(
        result_no_dedup.detections.len() >= result_dedup.detections.len(),
        "no-dedup should have >= detections than dedup (got {} vs {})",
        result_no_dedup.detections.len(),
        result_dedup.detections.len()
    );
}

/// Verify that dedup does not affect non-alltypes scans (single file_type).
#[test]
fn dedup_does_not_affect_single_type_scan() {
    if !db_available() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    let db = build_db();
    let cancel = CancellationToken::new();

    let flags1 = ScanFlags {
        all_types: false,
        no_dedup: false,
        ..Default::default()
    };
    let result1 =
        scan_bytes(&db, "test.exe", build_minimal_pe(), flags1, &cancel).expect("scan ok");

    let flags2 = ScanFlags {
        all_types: false,
        no_dedup: true,
        ..Default::default()
    };
    let result2 =
        scan_bytes(&db, "test.exe", build_minimal_pe(), flags2, &cancel).expect("scan ok");

    assert_eq!(
        result1.detections.len(),
        result2.detections.len(),
        "Single-type scan should not be affected by dedup"
    );
}

/// Verify ScanDetection fields used in dedup key.
#[test]
fn scan_detection_has_dedup_key_fields() {
    let d = ScanDetection {
        file_type: "PE".to_string(),
        type_name: "format".to_string(),
        name: "PE".to_string(),
        version: Some("1.0".to_string()),
        options: None,
        signature_path: None,
        id: None,
        parent_id: None,
        file_part: None,
        offset: Some(0),
        size: Some(256),
        is_heuristic: None,
        is_a_heuristic: None,
        original_name: None,
        engine: None,
    };
    // Verify the fields used in dedup key are accessible.
    assert_eq!(d.type_name, "format");
    assert_eq!(d.name, "PE");
    assert_eq!(d.version.as_deref(), Some("1.0"));
    assert_eq!(d.options.as_deref(), None);
    assert_eq!(d.offset, Some(0));
    assert_eq!(d.size, Some(256));
}

/// Verify that ScanFlags.no_dedup defaults to false (dedup on).
#[test]
fn scan_flags_no_dedup_defaults_false() {
    let flags = ScanFlags::default();
    assert!(!flags.no_dedup, "no_dedup should default to false");
}

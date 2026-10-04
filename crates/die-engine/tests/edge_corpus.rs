//! Edge-case differential test: verify scanner handles malformed/truncated
//! inputs without crashing, panicking, or producing spurious detections.
//!
//! This test runs the scanner on each edge-case sample from `corpus/edge/`
//! and verifies:
//! - No panic or crash
//! - Scan completes (Ok or structured Err)
//! - No spurious detections on truncated/malformed input
//!
//! See `corpus/edge/manifest.json` and `tools/corpus/generate_edge_corpus.py`.

#![forbid(unsafe_code)]

use die_core::cancel::CancellationToken;
use die_engine::{DatabaseBuilder, ScanFlags, scan_bytes};
use std::path::PathBuf;

/// Edge-case samples that should produce no detections.
/// These are inputs with no recognizable magic bytes or structure.
/// Note: truncated files with valid magic headers MAY produce
/// magic-based detections; this is correct behavior, not spurious.
const NO_DETECTION_SAMPLES: &[&str] = &[
    "malformed-elf-bad-class.bin",
    "malformed-pe-bad-lfanew.bin",
    "random-256.bin",
    "zeros-256.bin",
    "ff-256.bin",
    "single-byte.bin",
    "two-bytes.bin",
];

/// Resolve the edge corpus directory.
fn edge_corpus_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join("corpus")
        .join("edge")
}

/// Resolve the upstream database directory.
fn db_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join("upstream/Detect-It-Easy/db")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

/// Resolve the upstream db_extra directory.
fn db_extra_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join("upstream/Detect-It-Easy/db_extra")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

/// Build a database with both db/ and db_extra/ rules.
fn build_full_database() -> Option<die_engine::Database> {
    let db = db_path();
    let extra = db_extra_path();
    let mut builder = DatabaseBuilder::new(&db);
    if std::path::Path::new(&extra).is_dir() {
        builder = builder.with_extra(&extra);
    }
    match builder.build() {
        Ok(db) => Some(db),
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            None
        }
    }
}

/// Verify that scanning an edge-case sample does not crash or panic.
/// Returns Ok(()) if the scan completed (regardless of result).
fn scan_without_crash(
    database: &die_engine::Database,
    filename: &str,
    data: Vec<u8>,
) -> Result<(), String> {
    let cancel = CancellationToken::new();
    match scan_bytes(database, filename, data, ScanFlags::default(), &cancel) {
        Ok(_result) => Ok(()),
        Err(e) => Err(format!("scan error (expected for malformed input): {e}")),
    }
}

#[test]
fn edge_corpus_no_crash_on_malformed() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };

    let edge_dir = edge_corpus_dir();
    if !edge_dir.exists() {
        eprintln!("SKIP: edge corpus not found at {edge_dir:?}");
        return;
    }

    let mut tested = 0usize;
    let mut errors = Vec::new();

    // Samples that should produce no detections.
    for filename in NO_DETECTION_SAMPLES {
        let path = edge_dir.join(filename);
        if !path.exists() {
            eprintln!("SKIP: {filename} not found");
            continue;
        }

        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                errors.push(format!("{filename}: cannot read: {e}"));
                continue;
            }
        };

        match scan_without_crash(&database, filename, data) {
            Ok(()) => {}
            Err(e) => {
                // Scan errors are acceptable for malformed input, but
                // we log them for visibility.
                eprintln!("  {filename}: {e}");
            }
        }
        tested += 1;
    }

    assert!(tested > 0, "no edge samples were tested");
    assert!(errors.is_empty(), "read errors:\n{}", errors.join("\n"));
    eprintln!("edge corpus no-crash: {tested} tested, 0 crashes");
}

#[test]
fn edge_corpus_no_spurious_detections() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };

    let edge_dir = edge_corpus_dir();
    if !edge_dir.exists() {
        eprintln!("SKIP: edge corpus not found at {edge_dir:?}");
        return;
    }

    let cancel = CancellationToken::new();
    let mut tested = 0usize;
    let mut spurious = Vec::new();

    for filename in NO_DETECTION_SAMPLES {
        let path = edge_dir.join(filename);
        if !path.exists() {
            continue;
        }

        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        if let Ok(result) = scan_bytes(&database, filename, data, ScanFlags::default(), &cancel) {
            // Check for spurious detections.
            // The "Unknown" placeholder is not spurious — it matches upstream.
            if result.detections.iter().any(|d| d.name != "Unknown") {
                let detections: Vec<String> = result
                    .detections
                    .iter()
                    .filter(|d| d.name != "Unknown")
                    .map(|d| format!("{}:{}", d.type_name, d.name))
                    .collect();
                spurious.push(format!(
                    "{filename}: expected no detections, got: [{}]",
                    detections.join(", ")
                ));
            }
            // Phase 15.2c: Hard assertion — zero script exceptions on edge cases.
            if !result.structured_diagnostics.is_empty() {
                let diags: Vec<String> = result
                    .structured_diagnostics
                    .iter()
                    .map(|d| format!("{}: {}", d.file, d.message))
                    .collect();
                spurious.push(format!(
                    "{filename}: {} script exception(s):\n  {}",
                    result.structured_diagnostics.len(),
                    diags.join("\n  ")
                ));
            }
        }
        tested += 1;
    }

    assert!(tested > 0, "no edge samples were tested");
    assert!(
        spurious.is_empty(),
        "spurious detections on malformed input ({}):\n{}",
        spurious.len(),
        spurious.join("\n")
    );
    eprintln!("edge corpus no-spurious: {tested} tested, 0 spurious detections");
}

#[test]
fn edge_corpus_truncated_does_not_hang() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };

    let edge_dir = edge_corpus_dir();
    if !edge_dir.exists() {
        eprintln!("SKIP: edge corpus not found at {edge_dir:?}");
        return;
    }

    // Scan each truncated sample with a short timeout to verify no hang.
    let truncated_files = [
        "truncated-elf-4bytes.bin",
        "truncated-pe-mz-only.bin",
        "truncated-macho-magic.bin",
        "truncated-zip-sig.bin",
        "truncated-pdf-header.bin",
        "truncated-png-sig.bin",
        "truncated-jpeg-soi.bin",
        "truncated-class-magic.bin",
        "truncated-dex-magic.bin",
        "truncated-gzip-header.bin",
    ];

    let cancel = CancellationToken::new();
    let mut tested = 0usize;

    for filename in &truncated_files {
        let path = edge_dir.join(filename);
        if !path.exists() {
            continue;
        }

        let data = std::fs::read(&path).unwrap_or_default();
        let start = std::time::Instant::now();

        let _ = scan_bytes(&database, filename, data, ScanFlags::default(), &cancel);

        let elapsed = start.elapsed();
        // Truncated samples should complete in under 2 seconds.
        // This is a regression guard: before the batch PE parsing
        // optimization, even small files could take >60s due to
        // per-byte JS→Rust FFI overhead in import/export parsing.
        assert!(
            elapsed.as_secs() < 2,
            "{filename} took {elapsed:?} (expected < 2s)"
        );
        tested += 1;
    }

    assert!(tested > 0, "no truncated samples were tested");
    eprintln!("edge corpus no-hang: {tested} truncated samples completed quickly");
}

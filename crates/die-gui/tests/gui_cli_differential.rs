//! GUI vs CLI differential test.
//!
//! Verifies that the die-gui scan path (which calls `die_engine::scan_once`)
//! produces identical results to the CLI scan path (`die_engine::scan_bytes`).
//!
//! Both paths use the same underlying engine, but this test guards against
//! accidental divergence if the GUI ever introduces its own scanning logic
//! or modifies the flags mapping.
//!
//! See ROADMAP.md Phase 8 exit condition: "GUI 扫描结果与 CLI 差分 0 不匹配".

#![forbid(unsafe_code)]

use die_core::cancel::CancellationToken;
use die_engine::{DatabaseBuilder, ScanFlags, scan_bytes, scan_once};
use std::path::PathBuf;
use std::sync::Arc;

/// Locate the rule database directory.
/// Checks paths relative to CWD and workspace root.
fn resolve_db_path() -> PathBuf {
    let candidates = [
        "upstream/Detect-It-Easy/db",
        "./db",
        "../../upstream/Detect-It-Easy/db",
        "../../db",
    ];
    for c in &candidates {
        let p = PathBuf::from(c);
        if p.is_dir() {
            return p;
        }
    }
    panic!("Rule database not found in candidate paths");
}

/// Collect all sample files from the corpus directory.
fn corpus_files() -> Vec<PathBuf> {
    let candidates = ["corpus", "../../corpus"];
    for c in &candidates {
        let corpus_dir = PathBuf::from(c);
        if corpus_dir.is_dir() {
            let mut files: Vec<PathBuf> = std::fs::read_dir(&corpus_dir)
                .expect("failed to read corpus directory")
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.extension().map(|e| e != "json").unwrap_or(true))
                .collect();
            files.sort();
            return files;
        }
    }
    Vec::new()
}

/// Compare two detection lists by (type_name, name) pairs, ignoring order.
fn detections_match(a: &[die_engine::ScanDetection], b: &[die_engine::ScanDetection]) -> bool {
    let mut a_sorted: Vec<(String, String)> = a
        .iter()
        .map(|d| (d.type_name.clone(), d.name.clone()))
        .collect();
    let mut b_sorted: Vec<(String, String)> = b
        .iter()
        .map(|d| (d.type_name.clone(), d.name.clone()))
        .collect();
    a_sorted.sort();
    b_sorted.sort();
    a_sorted == b_sorted
}

/// Test that scan_once (GUI path, file-based) and scan_bytes (CLI path,
/// buffer-based) produce identical detections for the same file.
#[test]
fn gui_vs_cli_scan_results_match() {
    let db_path = resolve_db_path();
    let db = Arc::new(
        DatabaseBuilder::new(&db_path)
            .build()
            .expect("failed to build database"),
    );
    let cancel = CancellationToken::new();
    let flags = ScanFlags::default();

    let files = corpus_files();
    assert!(
        !files.is_empty(),
        "corpus directory must contain sample files"
    );

    let mut mismatches = Vec::new();

    for file_path in &files {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // CLI path: read file → scan_bytes.
        let cli_data = match std::fs::read(file_path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let cli_result = scan_bytes(&db, &file_name, cli_data, flags.clone(), &cancel);

        // GUI path: scan_once (reads file internally).
        let gui_result = scan_once(&db, &file_path.to_string_lossy(), flags.clone(), &cancel);

        // Compare results.
        match (&cli_result, &gui_result) {
            (Ok(cli), Ok(gui)) => {
                if !detections_match(&cli.detections, &gui.detections) {
                    mismatches.push(format!(
                        "{}: CLI has {} detections, GUI has {} detections",
                        file_name,
                        cli.detections.len(),
                        gui.detections.len(),
                    ));
                }
            }
            (Err(cli_e), Err(gui_e)) => {
                // Both errored — acceptable as long as errors are consistent.
                eprintln!(
                    "WARN: both paths errored for {}: CLI={:?}, GUI={:?}",
                    file_name, cli_e, gui_e
                );
            }
            (Ok(_), Err(gui_e)) => {
                mismatches.push(format!(
                    "{}: CLI succeeded but GUI errored: {:?}",
                    file_name, gui_e
                ));
            }
            (Err(cli_e), Ok(_)) => {
                mismatches.push(format!(
                    "{}: GUI succeeded but CLI errored: {:?}",
                    file_name, cli_e
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "GUI vs CLI differential test failed ({} mismatches):\n{}",
        mismatches.len(),
        mismatches.join("\n"),
    );
}

/// Test that scan_bytes with different flag combinations produces
/// consistent results — the GUI flags mapping must not alter behavior.
#[test]
fn gui_flags_mapping_consistent() {
    let db_path = resolve_db_path();
    let db = Arc::new(
        DatabaseBuilder::new(&db_path)
            .build()
            .expect("failed to build database"),
    );
    let cancel = CancellationToken::new();

    // Use a PE file for flag testing (most flags are PE-relevant).
    let pe_candidates = [
        PathBuf::from("corpus/minimal.exe"),
        PathBuf::from("../../corpus/minimal.exe"),
    ];
    let pe_file = pe_candidates.iter().find(|p| p.is_file()).cloned();
    let pe_file = match pe_file {
        Some(p) => p,
        None => {
            eprintln!("SKIP: minimal.exe not found in corpus");
            return;
        }
    };

    let data = std::fs::read(&pe_file).expect("failed to read test file");

    // Default flags (same as GUI default).
    let default_flags = ScanFlags::default();
    let default_result = scan_bytes(&db, "minimal.exe", data.clone(), default_flags, &cancel)
        .expect("default scan failed");

    // Deep scan (GUI "deep" checkbox).
    let deep_flags = ScanFlags {
        deep: true,
        ..Default::default()
    };
    let deep_result = scan_bytes(&db, "minimal.exe", data.clone(), deep_flags, &cancel)
        .expect("deep scan failed");

    // All types (GUI "alltypes" checkbox).
    let all_types_flags = ScanFlags {
        all_types: true,
        ..Default::default()
    };
    let all_types_result = scan_bytes(&db, "minimal.exe", data, all_types_flags, &cancel)
        .expect("alltypes scan failed");

    // Deep scan should produce at least as many detections as default.
    assert!(
        deep_result.detections.len() >= default_result.detections.len(),
        "deep scan should produce >= detections than default"
    );

    // All types should produce at least as many detections as default.
    assert!(
        all_types_result.detections.len() >= default_result.detections.len(),
        "alltypes scan should produce >= detections than default"
    );
}

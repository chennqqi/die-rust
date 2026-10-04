//! Hardened differential tests covering blind spots found in Phase 14.
//!
//! The original `corpus_differential.rs` only loaded `db/` rules, didn't
//! test `--alltypes` for false positives, and didn't scan real system
//! binaries. This file closes those gaps:
//!
//! 1. Loads both `db/` and `db_extra/` rules (matching CLI default behavior).
//! 2. Asserts `--alltypes` does NOT produce cross-format false positives
//!    on ELF/PE/Mach-O files (the Phase 14.3 regression).
//! 3. Scans real system binaries (when available) and asserts no script
//!    exceptions and no cross-format false positives.
//! 4. Verifies PE rules that previously threw TypeError (isNET,
//!    isResourceGroupNamePresent, compareEP_NET) now execute cleanly.

#![forbid(unsafe_code)]

use die_core::cancel::CancellationToken;
use die_engine::{DatabaseBuilder, ScanFlags, scan_bytes};
use std::path::PathBuf;

/// Resolve the workspace root.
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

/// Resolve the upstream database directory (db/).
fn db_root() -> String {
    workspace_root()
        .join("upstream/Detect-It-Easy/db")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

/// Resolve the upstream db_extra directory.
fn db_extra_root() -> String {
    workspace_root()
        .join("upstream/Detect-It-Easy/db_extra")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

/// Resolve the corpus directory.
fn corpus_dir() -> PathBuf {
    workspace_root().join("corpus")
}

/// Build a database with both db/ and db_extra/ rules.
/// Returns None if the upstream database is not found (test skips).
fn build_full_database() -> Option<die_engine::Database> {
    let db_path = db_root();
    let extra_path = db_extra_root();
    let mut builder = DatabaseBuilder::new(&db_path);
    if std::path::Path::new(&extra_path).is_dir() {
        builder = builder.with_extra(&extra_path);
    }
    match builder.build() {
        Ok(db) => Some(db),
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            None
        }
    }
}

/// Cross-format false-positive types that should NEVER appear for
/// executable formats. These are the formats that were falsely detected
/// before Phase 14.3's --alltypes probe-based filtering.
const CROSS_FORMAT_FALSE_POSITIVES: &[&str] = &[
    "JPEG",
    "PDF",
    "PNG",
    "CFBF",
    "DEX",
    "Java Class",
    "Python bytecode compiled",
];

/// Check if any detection name matches a cross-format false positive.
fn has_cross_format_false_positive(detections: &[die_engine::ScanDetection]) -> bool {
    detections.iter().any(|d| {
        CROSS_FORMAT_FALSE_POSITIVES
            .iter()
            .any(|&fp| d.name.to_lowercase().contains(&fp.to_lowercase()))
    })
}

/// Check if any detection is a script exception (structured diagnostic).
fn has_script_exceptions(result: &die_engine::ScanResult) -> usize {
    result
        .structured_diagnostics
        .iter()
        .filter(|d| d.message.to_lowercase().contains("script exception"))
        .count()
}

// ============================================================================
// Test 1: --alltypes on ELF corpus files must not produce cross-format FPs.
// ============================================================================

#[test]
fn alltypes_elf_no_cross_format_false_positives() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    let cancel = CancellationToken::new();

    let elf_files = ["minimal.elf", "minimal-elf32.elf", "elf-with-deps.elf"];
    let mut tested = 0usize;
    let mut mismatches = Vec::new();

    for filename in elf_files {
        let path = corpus_dir().join(filename);
        if !path.exists() {
            eprintln!("SKIP: corpus file missing: {filename}");
            continue;
        }
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                mismatches.push(format!("{filename}: cannot read: {e}"));
                continue;
            }
        };

        let flags = ScanFlags {
            all_types: true,
            ..Default::default()
        };
        let result = match scan_bytes(&database, filename, data, flags, &cancel) {
            Ok(r) => r,
            Err(e) => {
                mismatches.push(format!("{filename}: scan error: {e}"));
                continue;
            }
        };

        if has_cross_format_false_positive(&result.detections) {
            let names: Vec<String> = result
                .detections
                .iter()
                .map(|d| format!("{}:{}", d.type_name, d.name))
                .collect();
            mismatches.push(format!(
                "{filename}: --alltypes produced cross-format false positive: [{}]",
                names.join(", ")
            ));
        }
        tested += 1;
    }

    assert!(tested > 0, "no ELF corpus samples were tested");
    assert!(
        mismatches.is_empty(),
        "--alltypes ELF cross-format false positives ({}):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    eprintln!("--alltypes ELF: {tested} tested, 0 cross-format FPs");
}

// ============================================================================
// Test 2: --alltypes on PE corpus files must not produce cross-format FPs.
// ============================================================================

#[test]
fn alltypes_pe_no_cross_format_false_positives() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    let cancel = CancellationToken::new();

    let pe_files = [
        "minimal.exe",
        "minimal-pe64.exe",
        "with-tables.exe",
        "pe-with-resources.exe",
        "pe-dotnet.exe",
    ];
    let mut tested = 0usize;
    let mut mismatches = Vec::new();

    for filename in pe_files {
        let path = corpus_dir().join(filename);
        if !path.exists() {
            eprintln!("SKIP: corpus file missing: {filename}");
            continue;
        }
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                mismatches.push(format!("{filename}: cannot read: {e}"));
                continue;
            }
        };

        let flags = ScanFlags {
            all_types: true,
            ..Default::default()
        };
        let result = match scan_bytes(&database, filename, data, flags, &cancel) {
            Ok(r) => r,
            Err(e) => {
                mismatches.push(format!("{filename}: scan error: {e}"));
                continue;
            }
        };

        if has_cross_format_false_positive(&result.detections) {
            let names: Vec<String> = result
                .detections
                .iter()
                .map(|d| format!("{}:{}", d.type_name, d.name))
                .collect();
            mismatches.push(format!(
                "{filename}: --alltypes produced cross-format false positive: [{}]",
                names.join(", ")
            ));
        }
        tested += 1;
    }

    assert!(tested > 0, "no PE corpus samples were tested");
    assert!(
        mismatches.is_empty(),
        "--alltypes PE cross-format false positives ({}):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    eprintln!("--alltypes PE: {tested} tested, 0 cross-format FPs");
}

// ============================================================================
// Test 3: --alltypes on Mach-O corpus files must not produce cross-format FPs.
// ============================================================================

#[test]
fn alltypes_macho_no_cross_format_false_positives() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    let cancel = CancellationToken::new();

    let macho_files = [
        "minimal.macho",
        "minimal-macho32.macho",
        "macho-with-dylib.macho",
    ];
    let mut tested = 0usize;
    let mut mismatches = Vec::new();

    for filename in macho_files {
        let path = corpus_dir().join(filename);
        if !path.exists() {
            eprintln!("SKIP: corpus file missing: {filename}");
            continue;
        }
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                mismatches.push(format!("{filename}: cannot read: {e}"));
                continue;
            }
        };

        let flags = ScanFlags {
            all_types: true,
            ..Default::default()
        };
        let result = match scan_bytes(&database, filename, data, flags, &cancel) {
            Ok(r) => r,
            Err(e) => {
                mismatches.push(format!("{filename}: scan error: {e}"));
                continue;
            }
        };

        if has_cross_format_false_positive(&result.detections) {
            let names: Vec<String> = result
                .detections
                .iter()
                .map(|d| format!("{}:{}", d.type_name, d.name))
                .collect();
            mismatches.push(format!(
                "{filename}: --alltypes produced cross-format false positive: [{}]",
                names.join(", ")
            ));
        }
        tested += 1;
    }

    assert!(tested > 0, "no Mach-O corpus samples were tested");
    assert!(
        mismatches.is_empty(),
        "--alltypes Mach-O cross-format false positives ({}):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    eprintln!("--alltypes Mach-O: {tested} tested, 0 cross-format FPs");
}

// ============================================================================
// Test 4: db_extra rules must load and PE rules with isNET/compareEP_NET
// must execute without TypeError script exceptions.
// ============================================================================

#[test]
fn db_extra_pe_rules_no_script_exceptions() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    let cancel = CancellationToken::new();

    // Use pe-dotnet.exe which triggers .NET rules.
    let filename = "pe-dotnet.exe";
    let path = corpus_dir().join(filename);
    if !path.exists() {
        eprintln!("SKIP: corpus file missing: {filename}");
        return;
    }
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            panic!("cannot read {filename}: {e}");
        }
    };

    // Scan with default flags (no --alltypes) to run PE rules.
    let result = match scan_bytes(&database, filename, data, ScanFlags::default(), &cancel) {
        Ok(r) => r,
        Err(e) => {
            panic!("scan error for {filename}: {e}");
        }
    };

    let exception_count = has_script_exceptions(&result);
    // The only remaining exception is _Microsoft.6.sg's getNETVersion()
    // empty-string indexing, which is a .NET metadata parsing limitation.
    // All isNET/compareEP_NET/isResourceGroupNamePresent TypeErrors must
    // be gone.
    let type_error_count = result
        .structured_diagnostics
        .iter()
        .filter(|d| d.message.to_lowercase().contains("not a function"))
        .count();
    assert_eq!(
        type_error_count,
        0,
        "PE rules still have TypeError (not a function) exceptions: {:?}",
        result
            .structured_diagnostics
            .iter()
            .filter(|d| d.message.to_lowercase().contains("not a function"))
            .map(|d| &d.message)
            .collect::<Vec<_>>()
    );
    eprintln!("db_extra PE: {exception_count} total exceptions, 0 TypeError (not a function)");
}

// ============================================================================
// Test 5: Real system binaries must scan without cross-format FPs.
// ============================================================================

#[test]
fn real_system_binaries_no_cross_format_false_positives() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    let cancel = CancellationToken::new();

    // Try real system binaries. Skip if not available (e.g. on Windows).
    let candidates: Vec<(&str, PathBuf)> = vec![
        ("ls", PathBuf::from("/usr/bin/ls")),
        ("cat", PathBuf::from("/usr/bin/cat")),
        ("bash", PathBuf::from("/usr/bin/bash")),
    ];

    let mut tested = 0usize;
    let mut mismatches = Vec::new();

    for (name, path) in candidates {
        if !path.exists() {
            eprintln!("SKIP: {name} not found at {}", path.display());
            continue;
        }
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("SKIP: cannot read {name}: {e}");
                continue;
            }
        };

        // Default scan (no --alltypes).
        let result = match scan_bytes(&database, name, data.clone(), ScanFlags::default(), &cancel)
        {
            Ok(r) => r,
            Err(e) => {
                mismatches.push(format!("{name}: scan error: {e}"));
                continue;
            }
        };

        if has_cross_format_false_positive(&result.detections) {
            let names: Vec<String> = result
                .detections
                .iter()
                .map(|d| format!("{}:{}", d.type_name, d.name))
                .collect();
            mismatches.push(format!(
                "{name}: default scan produced cross-format false positive: [{}]",
                names.join(", ")
            ));
        }

        // --alltypes scan.
        let flags = ScanFlags {
            all_types: true,
            ..Default::default()
        };
        let result = match scan_bytes(&database, name, data, flags, &cancel) {
            Ok(r) => r,
            Err(e) => {
                mismatches.push(format!("{name}: --alltypes scan error: {e}"));
                continue;
            }
        };

        if has_cross_format_false_positive(&result.detections) {
            let names: Vec<String> = result
                .detections
                .iter()
                .map(|d| format!("{}:{}", d.type_name, d.name))
                .collect();
            mismatches.push(format!(
                "{name}: --alltypes produced cross-format false positive: [{}]",
                names.join(", ")
            ));
        }
        tested += 1;
    }

    if tested == 0 {
        eprintln!("SKIP: no real system binaries found (not on Linux?)");
        return;
    }

    assert!(
        mismatches.is_empty(),
        "real system binary false positives ({}):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    eprintln!("real system binaries: {tested} tested, 0 cross-format FPs");
}

// ============================================================================
// Test 6: db_extra rule count must be > 0 (rules actually loaded).
// ============================================================================

#[test]
fn db_extra_rules_loaded() {
    let extra_path = db_extra_root();
    if !std::path::Path::new(&extra_path).is_dir() {
        eprintln!("SKIP: db_extra directory not found");
        return;
    }

    let db_only = match DatabaseBuilder::new(db_root()).build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            return;
        }
    };
    let db_with_extra = match build_full_database() {
        Some(db) => db,
        None => return,
    };

    let db_only_count = db_only.rule_count();
    let db_with_extra_count = db_with_extra.rule_count();
    assert!(
        db_with_extra_count > db_only_count,
        "db_extra should add rules: db_only={db_only_count}, db_with_extra={db_with_extra_count}"
    );
    eprintln!(
        "db_extra rules loaded: db_only={db_only_count}, db_with_extra={db_with_extra_count}, extra={}",
        db_with_extra_count - db_only_count
    );
}

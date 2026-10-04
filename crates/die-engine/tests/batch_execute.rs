//! Rule execution coverage matrix — Phase 15.2.
//!
//! Unlike `batch_load_*.rs` which only tests `load_database()` (syntax
//! parsing), this test exercises the full `scan_bytes()` pipeline
//! (`load_database + init + evaluate_rule`) for every format type that
//! has a corpus sample, using both `db/` and `db_extra/` rules.
//!
//! It outputs a coverage matrix and asserts that the total script
//! exception count is zero. This closes the "load success ≠ execution
//! success" blind spot identified in the Phase 14 retrospective.

#![forbid(unsafe_code)]

use die_core::cancel::CancellationToken;
use die_engine::{DatabaseBuilder, ScanFlags, scan_bytes};
use std::collections::BTreeMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn db_root() -> String {
    workspace_root()
        .join("upstream/Detect-It-Easy/db")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

fn db_extra_root() -> String {
    workspace_root()
        .join("upstream/Detect-It-Easy/db_extra")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

fn corpus_dir() -> PathBuf {
    workspace_root().join("corpus")
}

// ---------------------------------------------------------------------------
// Format → corpus sample mapping
// ---------------------------------------------------------------------------

/// A corpus sample mapped to the format types it should trigger.
struct FormatSample {
    /// Corpus file name (relative to corpus/).
    filename: &'static str,
    /// Format types this sample is expected to trigger.
    /// (The scanner's probe determines the actual types; this is just
    ///  for reporting which sample was used for each format.)
    format_types: &'static [&'static str],
}

const FORMAT_SAMPLES: &[FormatSample] = &[
    FormatSample {
        filename: "minimal.elf",
        format_types: &["ELF", "Binary"],
    },
    FormatSample {
        filename: "minimal-elf32.elf",
        format_types: &["ELF", "Binary"],
    },
    FormatSample {
        filename: "elf-with-deps.elf",
        format_types: &["ELF", "Binary"],
    },
    FormatSample {
        filename: "minimal.exe",
        format_types: &["PE", "MSDOS", "Binary"],
    },
    FormatSample {
        filename: "minimal-pe64.exe",
        format_types: &["PE", "MSDOS", "Binary"],
    },
    FormatSample {
        filename: "with-tables.exe",
        format_types: &["PE", "MSDOS", "Binary"],
    },
    FormatSample {
        filename: "pe-with-resources.exe",
        format_types: &["PE", "MSDOS", "Binary"],
    },
    FormatSample {
        filename: "pe-dotnet.exe",
        format_types: &["PE", "MSDOS", "Binary"],
    },
    FormatSample {
        filename: "minimal.macho",
        format_types: &["MACH", "Binary"],
    },
    FormatSample {
        filename: "minimal-macho32.macho",
        format_types: &["MACH", "Binary"],
    },
    FormatSample {
        filename: "macho-with-dylib.macho",
        format_types: &["MACH", "Binary"],
    },
    FormatSample {
        filename: "minimal-fat.macho",
        format_types: &["MACHOFAT", "MACH", "Binary"],
    },
    FormatSample {
        filename: "minimal.apk",
        format_types: &["APK", "ZIP", "Archive"],
    },
    FormatSample {
        filename: "minimal.jar",
        format_types: &["JAR", "ZIP", "Archive"],
    },
    FormatSample {
        filename: "minimal.ipa",
        format_types: &["IPA", "ZIP", "Archive"],
    },
    FormatSample {
        filename: "payload.zip",
        format_types: &["ZIP", "Archive"],
    },
    FormatSample {
        filename: "payload.tar",
        format_types: &["Archive"],
    },
    FormatSample {
        filename: "payload.txt.gz",
        format_types: &["Archive"],
    },
    FormatSample {
        filename: "minimal.cfbf",
        format_types: &["CFBF"],
    },
    FormatSample {
        filename: "minimal.dex",
        format_types: &["DEX"],
    },
    FormatSample {
        filename: "Minimal.class",
        format_types: &["JavaClass"],
    },
    FormatSample {
        filename: "minimal.pyc",
        format_types: &["PYC"],
    },
    FormatSample {
        filename: "minimal.pdf",
        format_types: &["PDF"],
    },
    FormatSample {
        filename: "minimal.iso",
        format_types: &["ISO9660"],
    },
    FormatSample {
        filename: "minimal.rar",
        format_types: &["RAR", "Archive"],
    },
    FormatSample {
        filename: "pixel.png",
        format_types: &["PNG", "Image"],
    },
    FormatSample {
        filename: "pixel.jpg",
        format_types: &["JPEG", "Image"],
    },
    FormatSample {
        filename: "pixel.bmp",
        format_types: &["Image"],
    },
    FormatSample {
        filename: "plain.txt",
        format_types: &["Binary"],
    },
];

// ---------------------------------------------------------------------------
// Database builder
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Exception categorisation
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct ExceptionStats {
    total: usize,
    reference_errors: usize,
    type_errors: usize,
    syntax_errors: usize,
    host_api_errors: usize,
    budget_exceeded: usize,
    other: usize,
    /// (rule_path, message) pairs for the first few exceptions.
    samples: Vec<(String, String)>,
}

impl ExceptionStats {
    fn from_diagnostics(diagnostics: &[die_engine::ScanResult]) -> Self {
        // This is called per-scan, so we expect a single ScanResult.
        let mut stats = Self::default();
        if let Some(result) = diagnostics.first() {
            for d in &result.structured_diagnostics {
                stats.total += 1;
                let msg_lower = d.message.to_lowercase();
                if msg_lower.contains("referenceerror") || msg_lower.contains("is not defined") {
                    stats.reference_errors += 1;
                } else if msg_lower.contains("typeerror") || msg_lower.contains("not a function") {
                    stats.type_errors += 1;
                } else if msg_lower.contains("syntaxerror") {
                    stats.syntax_errors += 1;
                } else if msg_lower.contains("hostapi") || msg_lower.contains("not implemented") {
                    stats.host_api_errors += 1;
                } else if msg_lower.contains("budget") || msg_lower.contains("timeout") {
                    stats.budget_exceeded += 1;
                } else {
                    stats.other += 1;
                }
                if stats.samples.len() < 5 {
                    stats.samples.push((d.file.clone(), d.message.clone()));
                }
            }
        }
        stats
    }
}

// ---------------------------------------------------------------------------
// Coverage matrix test
// ---------------------------------------------------------------------------

/// Run scan_bytes for a single corpus sample and return the exception stats.
fn scan_sample(
    database: &die_engine::Database,
    filename: &str,
) -> Option<(ExceptionStats, usize, usize)> {
    let path = corpus_dir().join(filename);
    if !path.exists() {
        return None;
    }
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  WARN: cannot read {filename}: {e}");
            return None;
        }
    };
    let cancel = CancellationToken::new();
    let result = match scan_bytes(database, filename, data, ScanFlags::default(), &cancel) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  ERROR: scan failed for {filename}: {e}");
            return None;
        }
    };
    let detection_count = result.detections.len();
    let diag_count = result.structured_diagnostics.len();
    let stats = ExceptionStats::from_diagnostics(&[result]);
    Some((stats, detection_count, diag_count))
}

#[test]
fn batch_execute_coverage_matrix() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };

    let total_rules = database.rule_count();
    eprintln!("=== Rule Execution Coverage Matrix (Phase 15.2) ===");
    eprintln!("Database: {total_rules} rules (db/ + db_extra/)");
    eprintln!();

    // Track per-format stats.
    let mut format_stats: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
    // format -> (samples_tested, total_exceptions, total_detections)

    let mut grand_exceptions = 0usize;
    let mut grand_detections = 0usize;
    let mut grand_samples = 0usize;
    let mut all_exception_samples: Vec<(String, String, String)> = Vec::new();
    // (filename, rule_path, message)

    for sample in FORMAT_SAMPLES {
        let (stats, detections, _) = match scan_sample(&database, sample.filename) {
            Some(s) => s,
            None => {
                eprintln!(
                    "  SKIP: {} (file not found) — formats: {:?}",
                    sample.filename, sample.format_types
                );
                continue;
            }
        };

        grand_samples += 1;
        grand_exceptions += stats.total;
        grand_detections += detections;

        for &ft in sample.format_types {
            let entry = format_stats.entry(ft).or_insert((0, 0, 0));
            entry.0 += 1;
            entry.1 += stats.total;
            entry.2 += detections;
        }

        if stats.total > 0 {
            eprintln!(
                "  {}: {} exceptions, {} detections",
                sample.filename, stats.total, detections
            );
            for (rule, msg) in &stats.samples {
                all_exception_samples.push((
                    sample.filename.to_string(),
                    rule.clone(),
                    msg.clone(),
                ));
            }
        } else {
            eprintln!(
                "  {}: 0 exceptions, {} detections",
                sample.filename, detections
            );
        }
    }

    // Print coverage matrix.
    eprintln!();
    eprintln!("--- Per-format coverage ---");
    eprintln!(
        "{:<12} {:>8} {:>10} {:>12}",
        "Format", "Samples", "Exceptions", "Detections"
    );
    eprintln!("{}", "-".repeat(44));
    for (ft, (samples, exc, det)) in &format_stats {
        eprintln!("{ft:<12} {samples:>8} {exc:>10} {det:>12}");
    }
    eprintln!("{}", "-".repeat(44));
    eprintln!(
        "{:<12} {:>8} {:>10} {:>12}",
        "TOTAL", grand_samples, grand_exceptions, grand_detections
    );

    // Print exception samples.
    if !all_exception_samples.is_empty() {
        eprintln!();
        eprintln!("--- Exception samples (first 20) ---");
        for (filename, rule, msg) in all_exception_samples.iter().take(20) {
            eprintln!("  [{filename}] {rule}: {msg}");
        }
    }

    eprintln!();
    eprintln!("=== Coverage matrix complete ===");

    // Hard assertion: zero script exceptions across all corpus samples.
    // This is the Phase 15.2 gate — "load success ≠ execution success" must
    // be eliminated. If exceptions exist, they must be fixed or waived.
    assert_eq!(
        grand_exceptions, 0,
        "Rule execution exceptions detected ({} total). \
         See exception samples above. Each exception is a rule that loads \
         successfully but fails at runtime — the exact blind spot from the \
         Phase 14 retrospective.",
        grand_exceptions
    );
}

// ---------------------------------------------------------------------------
// Per-format execution tests (granular, for targeted debugging)
// ---------------------------------------------------------------------------

/// Helper to run a single format's samples and assert zero exceptions.
fn assert_format_no_exceptions(database: &die_engine::Database, filenames: &[&str]) {
    let cancel = CancellationToken::new();
    let mut tested = 0;
    let mut exceptions = Vec::new();

    for filename in filenames {
        let path = corpus_dir().join(filename);
        if !path.exists() {
            continue;
        }
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let result = match scan_bytes(database, filename, data, ScanFlags::default(), &cancel) {
            Ok(r) => r,
            Err(e) => {
                exceptions.push(format!("{filename}: scan error: {e}"));
                continue;
            }
        };
        tested += 1;
        for d in &result.structured_diagnostics {
            exceptions.push(format!("{filename} | {} | {}", d.file, d.message));
        }
    }

    assert!(tested > 0, "no samples tested for this format");
    assert_eq!(
        exceptions.len(),
        0,
        "Script exceptions found ({}):\n{}",
        exceptions.len(),
        exceptions.join("\n")
    );
}

#[test]
fn batch_execute_elf_no_exceptions() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    assert_format_no_exceptions(
        &database,
        &["minimal.elf", "minimal-elf32.elf", "elf-with-deps.elf"],
    );
}

#[test]
fn batch_execute_pe_no_exceptions() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    assert_format_no_exceptions(
        &database,
        &[
            "minimal.exe",
            "minimal-pe64.exe",
            "with-tables.exe",
            "pe-with-resources.exe",
            "pe-dotnet.exe",
        ],
    );
}

#[test]
fn batch_execute_macho_no_exceptions() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    assert_format_no_exceptions(
        &database,
        &[
            "minimal.macho",
            "minimal-macho32.macho",
            "macho-with-dylib.macho",
            "minimal-fat.macho",
        ],
    );
}

#[test]
fn batch_execute_archive_no_exceptions() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    assert_format_no_exceptions(
        &database,
        &[
            "minimal.apk",
            "minimal.jar",
            "minimal.ipa",
            "payload.zip",
            "payload.tar",
            "minimal.rar",
        ],
    );
}

#[test]
fn batch_execute_bytecode_no_exceptions() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    assert_format_no_exceptions(&database, &["Minimal.class", "minimal.dex", "minimal.pyc"]);
}

#[test]
fn batch_execute_document_no_exceptions() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    assert_format_no_exceptions(&database, &["minimal.pdf", "minimal.cfbf", "minimal.iso"]);
}

#[test]
fn batch_execute_image_no_exceptions() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    assert_format_no_exceptions(&database, &["pixel.png", "pixel.jpg", "pixel.bmp"]);
}

// ---------------------------------------------------------------------------
// Real system binary execution test
// ---------------------------------------------------------------------------

#[test]
fn batch_execute_real_system_binaries_no_exceptions() {
    let database = match build_full_database() {
        Some(db) => db,
        None => return,
    };
    let cancel = CancellationToken::new();

    let candidates = [
        ("ls", "/usr/bin/ls"),
        ("cat", "/usr/bin/cat"),
        ("bash", "/usr/bin/bash"),
        ("grep", "/usr/bin/grep"),
    ];

    let mut tested = 0;
    let mut exceptions = Vec::new();

    for (name, path) in candidates {
        let path = PathBuf::from(path);
        if !path.exists() {
            continue;
        }
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let result = match scan_bytes(&database, name, data, ScanFlags::default(), &cancel) {
            Ok(r) => r,
            Err(e) => {
                exceptions.push(format!("{name}: scan error: {e}"));
                continue;
            }
        };
        tested += 1;
        for d in &result.structured_diagnostics {
            exceptions.push(format!("{name} | {} | {}", d.file, d.message));
        }
    }

    if tested == 0 {
        eprintln!("SKIP: no real system binaries found (not on Linux?)");
        return;
    }

    assert_eq!(
        exceptions.len(),
        0,
        "Real system binary script exceptions ({}):\n{}",
        exceptions.len(),
        exceptions.join("\n")
    );
    eprintln!("Real system binaries: {tested} tested, 0 exceptions");
}

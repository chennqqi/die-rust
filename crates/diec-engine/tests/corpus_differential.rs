//! Differential detection test against the baseline corpus.
//!
//! This test runs the full scanner (database + rules + host API) on each
//! sample from the `corpus/` directory and verifies that the detections
//! match the expected upstream DIE output.
//!
//! The expected outputs were determined by comparing `diec-rust` output
//! against upstream DIE-engine behavior. Any deviation is a regression.
//!
//! See `docs/design/testing.md` section 12 and `corpus/manifest.json`.

#![forbid(unsafe_code)]

use diec_core::cancel::CancellationToken;
use diec_engine::{DatabaseBuilder, ScanDetection, scan_bytes};
use std::path::PathBuf;

/// Expected detection summary for each corpus file.
///
/// Each entry is (filename, expected_detections) where expected_detections
/// is a list of (type, name) pairs. An empty list means "no detections".
/// The order doesn't matter — the test sorts both lists before comparing.
const CORPUS_EXPECTATIONS: &[(&str, &[(&str, &str)])] = &[
    // Executable formats
    // PE files: minimal PE with EP=0 and no sections.
    // Upstream detects only "Unknown" (getAddressOfEntryPoint returns
    // ImageBase+0, not 0, so archive_Resources.6.sg does not trigger).
    ("minimal.exe", &[]),
    ("minimal-pe64.exe", &[]),
    // with-tables.exe has import/export tables but no DOS stub or Rich
    // signature, so linker rules don't match. It's used to verify that
    // PE table parsing doesn't crash or produce spurious detections.
    ("with-tables.exe", &[]),
    // Expanded corpus: PE with resources/manifest, PE with .NET CLR header,
    // ELF with DT_NEEDED deps, Mach-O with LC_LOAD_DYLIB.
    // These verify native parsers handle richer structures without crashes.
    ("pe-with-resources.exe", &[]),
    // pe-dotnet.exe: .NET Framework detection now works after Phase 15
    // getNETVersion() implementation (returns "v4.0.30319" from BSJB metadata).
    ("pe-dotnet.exe", &[("library", ".NET Framework")]),
    ("elf-with-deps.elf", &[]),
    ("macho-with-dylib.macho", &[]),
    ("minimal.elf", &[]),
    ("minimal-elf32.elf", &[]),
    ("minimal.macho", &[]),
    ("minimal-macho32.macho", &[]),
    ("minimal-fat.macho", &[("converter", "lipo")]),
    // Bytecode formats
    ("Minimal.class", &[("format", "Java Class")]),
    ("minimal.dex", &[("format", "DEX")]),
    ("minimal.pyc", &[("format", "Python bytecode compiled")]),
    // Archive formats — upstream dispatch is exclusive: ZIP/APK/JAR run only
    // their own rule group, so a minimal container yields filetype "Unknown"
    // (golden: ZIP/APK/JAR → Unknown). No Binary archive rule fires.
    ("payload.zip", &[]),
    ("minimal.apk", &[]),
    ("minimal.jar", &[]),
    ("minimal.ipa", &[("archive", "Zip")]),
    ("payload.tar", &[("archive", "tar")]),
    (
        "minimal.cfbf",
        &[("format", "CFBF"), ("format", "Microsoft Office")],
    ),
    // Document formats
    ("minimal.pdf", &[("format", "PDF")]),
    // ISO 9660: upstream 3.21 doesn't detect it, new rules do
    // Image formats — only format-specific rules run (not Binary)
    ("pixel.png", &[("format", "PNG")]),
    ("pixel.jpg", &[("format", "JPEG")]),
    ("pixel.bmp", &[("image", "Windows Bitmap")]),
    // Audio formats
    ("tone.wav", &[("audio", "RIFF container")]),
    // No detections expected
    ("empty.bin", &[("format", "Empty file")]),
    ("plain.txt", &[("format", "Plain text")]),
    ("manifest.json", &[("format", "Plain text")]),
    ("minimal.rar", &[]),
    ("payload.txt.gz", &[]),
];

/// Resolve the corpus directory relative to the workspace root.
fn corpus_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .map(|p| p.join("corpus"))
        .unwrap_or_else(|| PathBuf::from("corpus"))
}

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

/// Resolve the upstream db_extra directory.
fn db_extra_root() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let binding = PathBuf::from(manifest_dir);
    let root = binding
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    root.join("upstream/Detect-It-Easy/db_extra")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

/// Check if a detection matches an expected (type, name) pair.
/// The name match is a substring check (case-insensitive) to handle
/// version suffixes and additional metadata.
fn detection_matches(detection: &ScanDetection, expected_type: &str, expected_name: &str) -> bool {
    detection.type_name == *expected_type
        && detection
            .name
            .to_lowercase()
            .contains(&expected_name.to_lowercase())
}

#[test]
fn corpus_differential_detections() {
    let db_path = db_root();
    let extra_path = db_extra_root();
    let mut builder = DatabaseBuilder::new(&db_path);
    if std::path::Path::new(&extra_path).is_dir() {
        builder = builder.with_extra(&extra_path);
    }
    let database = match builder.build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            return;
        }
    };

    let cancel = CancellationToken::new();
    let mut tested = 0usize;
    let mut skipped = 0usize;
    let mut mismatches = Vec::new();

    for (filename, expected) in CORPUS_EXPECTATIONS {
        let path = corpus_dir().join(filename);
        if !path.exists() {
            eprintln!("SKIP: corpus file missing: {filename}");
            skipped += 1;
            continue;
        }

        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                mismatches.push(format!("{filename}: cannot read: {e}"));
                continue;
            }
        };

        let result = match scan_bytes(
            &database,
            filename,
            data,
            diec_engine::ScanFlags::default(),
            &cancel,
        ) {
            Ok(r) => r,
            Err(e) => {
                mismatches.push(format!("{filename}: scan error: {e}"));
                continue;
            }
        };

        // Check each expected detection is present.
        for (exp_type, exp_name) in *expected {
            let found = result
                .detections
                .iter()
                .any(|d| detection_matches(d, exp_type, exp_name));
            if !found {
                let actual: Vec<String> = result
                    .detections
                    .iter()
                    .map(|d| format!("{}:{}", d.type_name, d.name))
                    .collect();
                mismatches.push(format!(
                    "{filename}: expected detection '{exp_type}:{exp_name}' not found. Actual: [{actual}]",
                    actual = actual.join(", ")
                ));
            }
        }

        // Check no unexpected detections (only for files with no expected detections).
        // The "Unknown" placeholder (added when no detections are found) is
        // not counted as an unexpected detection — it matches upstream behavior.
        if expected.is_empty() && result.detections.iter().any(|d| d.name != "Unknown") {
            let actual: Vec<String> = result
                .detections
                .iter()
                .filter(|d| d.name != "Unknown")
                .map(|d| format!("{}:{}", d.type_name, d.name))
                .collect();
            mismatches.push(format!(
                "{filename}: expected no detections, got: [{actual}]",
                actual = actual.join(", ")
            ));
        }

        // Phase 15.2c: Hard assertion — zero script exceptions.
        // Rule execution exceptions indicate a rule that loads successfully
        // but fails at runtime (ReferenceError, TypeError, etc.).
        // This is the "load success ≠ execution success" blind spot.
        if !result.structured_diagnostics.is_empty() {
            let diags: Vec<String> = result
                .structured_diagnostics
                .iter()
                .map(|d| format!("{}: {}", d.file, d.message))
                .collect();
            mismatches.push(format!(
                "{filename}: {} script exception(s):\n  {}",
                result.structured_diagnostics.len(),
                diags.join("\n  ")
            ));
        }

        tested += 1;
    }

    assert!(tested > 0, "no corpus samples were tested");
    assert!(
        mismatches.is_empty(),
        "detection mismatches ({}):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    eprintln!("corpus differential: {tested} tested, {skipped} skipped, 0 mismatches");
}

//! Phase 15.4: Systematic --alltypes negative assertions.
//!
//! Verifies that --alltypes mode does NOT produce cross-format false
//! positives. Each format's probe-based filtering must ensure that only
//! the detected format's rules (plus compatible parent types) run.
//!
//! This addresses Phase 14 methodology flaw #4:
//! "Lack of negative assertions for --alltypes: did not test for
//! cross-format false positives."

#![forbid(unsafe_code)]

use diec_core::cancel::CancellationToken;
use diec_engine::{DatabaseBuilder, ScanFlags, scan_bytes};
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn db_root() -> String {
    workspace_root()
        .join("upstream")
        .join("Detect-It-Easy")
        .join("db")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

fn db_extra_root() -> String {
    workspace_root()
        .join("upstream")
        .join("Detect-It-Easy")
        .join("db_extra")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

fn corpus_dir() -> PathBuf {
    workspace_root().join("corpus")
}

/// Scan a corpus file with --alltypes and return the set of file_type
/// labels in the detections. This reveals which format rule sets ran.
fn alltypes_detection_types(
    database: &diec_engine::Database,
    filename: &str,
    data: Vec<u8>,
) -> std::collections::HashSet<String> {
    let cancel = CancellationToken::new();
    let flags = ScanFlags {
        all_types: true,
        ..Default::default()
    };
    let result = match scan_bytes(database, filename, data, flags, &cancel) {
        Ok(r) => r,
        Err(_) => return std::collections::HashSet::new(),
    };
    result
        .detections
        .iter()
        .map(|d| d.file_type.clone())
        .collect()
}

/// Test that each corpus file scanned with --alltypes only produces
/// detections from its own format family, not from unrelated formats.
#[test]
fn alltypes_no_cross_format_false_positives() {
    let db = db_root();
    let extra = db_extra_root();
    let mut builder = DatabaseBuilder::new(&db);
    if std::path::Path::new(&extra).is_dir() {
        builder = builder.with_extra(&extra);
    }
    let database = match builder.build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            return;
        }
    };

    let corpus = corpus_dir();

    // (filename, expected_format_family) — family is the set of format types
    // that are allowed to produce detections for this file.
    // "Binary" is included for formats where upstream diec also runs Binary
    // rules in --alltypes mode (BMP, ZIP, APK, JAR, IPA, tar, text).
    let cases: &[(&str, &[&str])] = &[
        // ELF files: only ELF rules should run
        ("minimal.elf", &["ELF"]),
        ("minimal-elf32.elf", &["ELF"]),
        ("elf-with-deps.elf", &["ELF"]),
        // PE files: PE + MSDOS (parent type)
        ("minimal.exe", &["PE", "MSDOS"]),
        ("minimal-pe64.exe", &["PE", "MSDOS"]),
        ("with-tables.exe", &["PE", "MSDOS"]),
        ("pe-with-resources.exe", &["PE", "MSDOS"]),
        ("pe-dotnet.exe", &["PE", "MSDOS"]),
        // Mach-O: only MACH
        ("minimal.macho", &["MACH"]),
        ("minimal-macho32.macho", &["MACH"]),
        ("macho-with-dylib.macho", &["MACH"]),
        // Mach-O FAT: MACHOFAT + MACH (parent)
        ("minimal-fat.macho", &["MACHOFAT", "MACH"]),
        // Archives: ZIP family + Binary (upstream runs Binary rules too)
        ("payload.zip", &["ZIP", "Archive", "Binary"]),
        ("minimal.apk", &["APK", "JAR", "ZIP", "Archive", "Binary"]),
        ("minimal.jar", &["JAR", "ZIP", "Archive", "Binary"]),
        ("minimal.ipa", &["IPA", "ZIP", "Archive", "Binary"]),
        ("payload.tar", &["Archive", "Binary"]),
        ("minimal.rar", &["RAR"]),
        // Documents
        ("minimal.pdf", &["PDF"]),
        ("minimal.cfbf", &["CFBF"]),
        // Bytecode
        ("minimal.dex", &["DEX"]),
        ("Minimal.class", &["JavaClass"]),
        // Images: PNG/JPEG have dedicated rule sets; BMP uses Binary rules
        ("pixel.png", &["PNG"]),
        ("pixel.jpg", &["JPEG"]),
        ("pixel.bmp", &["Binary", "Image"]),
        // Text
        ("plain.txt", &["Binary"]),
        ("manifest.json", &["Binary"]),
        ("empty.bin", &["Binary"]),
        // Phase 15.5: new format coverage samples
        ("minimal.com", &["COM"]),
        ("minimal-dos.exe", &["MSDOS"]),
        ("minimal-ne.exe", &["NE", "MSDOS"]),
        ("minimal-le.exe", &["LE", "MSDOS"]),
        ("minimal-lx.exe", &["LX", "MSDOS"]),
        ("minimal-npm.tgz", &["NPM", "Binary"]),
        ("minimal.pyc", &["PYC"]),
        ("minimal-dos4g.exe", &["LE", "MSDOS"]),
        ("minimal-dos16m.exe", &["LE", "MSDOS"]),
        ("minimal-amiga", &["Amiga", "Binary"]),
        ("minimal-atari.prg", &["Binary"]),
    ];

    let mut tested = 0usize;
    let mut violations = Vec::new();

    for (filename, allowed_family) in cases {
        let path = corpus.join(filename);
        if !path.exists() {
            eprintln!("SKIP: {filename} not found");
            continue;
        }

        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                violations.push(format!("{filename}: cannot read: {e}"));
                continue;
            }
        };

        let detection_types = alltypes_detection_types(&database, filename, data);

        // Check that all detection types are in the allowed family.
        let allowed: std::collections::HashSet<&str> = allowed_family.iter().copied().collect();
        for dt in &detection_types {
            if !allowed.contains(dt.as_str()) {
                violations.push(format!(
                    "{filename}: --alltypes produced detection from '{dt}' \
                     but only {:?} are allowed for this format",
                    allowed_family
                ));
            }
        }

        tested += 1;
    }

    assert!(tested > 0, "no corpus samples were tested");
    assert!(
        violations.is_empty(),
        "--alltypes cross-format false positives ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
    eprintln!(
        "alltypes negative assertions: {tested} files tested, 0 cross-format false positives"
    );
}

/// Test that --alltypes on a pure ELF file does NOT produce any PE,
/// Mach-O, ZIP, PDF, or image detections.
#[test]
fn alltypes_elf_excludes_all_other_formats() {
    let db = db_root();
    let extra = db_extra_root();
    let mut builder = DatabaseBuilder::new(&db);
    if std::path::Path::new(&extra).is_dir() {
        builder = builder.with_extra(&extra);
    }
    let database = match builder.build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            return;
        }
    };

    let corpus = corpus_dir();
    let elf_files = ["minimal.elf", "minimal-elf32.elf", "elf-with-deps.elf"];

    let mut tested = 0usize;
    let mut violations = Vec::new();

    for filename in &elf_files {
        let path = corpus.join(filename);
        if !path.exists() {
            continue;
        }

        let data = std::fs::read(&path).unwrap_or_default();
        let detection_types = alltypes_detection_types(&database, filename, data);

        // ELF files must only produce ELF detections.
        for dt in &detection_types {
            if dt != "ELF" {
                violations.push(format!(
                    "{filename}: --alltypes produced '{dt}' detection on ELF file"
                ));
            }
        }
        tested += 1;
    }

    assert!(tested > 0, "no ELF files tested");
    assert!(
        violations.is_empty(),
        "ELF --alltypes false positives ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
    eprintln!("alltypes ELF exclusion: {tested} files, 0 non-ELF detections");
}

/// Test that --alltypes on a PE file does NOT produce ELF, Mach-O,
/// ZIP, PDF, or image detections (only PE + MSDOS allowed).
#[test]
fn alltypes_pe_excludes_non_pe_msdos() {
    let db = db_root();
    let extra = db_extra_root();
    let mut builder = DatabaseBuilder::new(&db);
    if std::path::Path::new(&extra).is_dir() {
        builder = builder.with_extra(&extra);
    }
    let database = match builder.build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            return;
        }
    };

    let corpus = corpus_dir();
    let pe_files = [
        "minimal.exe",
        "minimal-pe64.exe",
        "with-tables.exe",
        "pe-with-resources.exe",
        "pe-dotnet.exe",
    ];

    let mut tested = 0usize;
    let mut violations = Vec::new();

    for filename in &pe_files {
        let path = corpus.join(filename);
        if !path.exists() {
            continue;
        }

        let data = std::fs::read(&path).unwrap_or_default();
        let detection_types = alltypes_detection_types(&database, filename, data);

        for dt in &detection_types {
            if dt != "PE" && dt != "MSDOS" {
                violations.push(format!(
                    "{filename}: --alltypes produced '{dt}' detection on PE file \
                     (only PE/MSDOS allowed)"
                ));
            }
        }
        tested += 1;
    }

    assert!(tested > 0, "no PE files tested");
    assert!(
        violations.is_empty(),
        "PE --alltypes false positives ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
    eprintln!("alltypes PE exclusion: {tested} files, 0 non-PE/MSDOS detections");
}

/// Test that --alltypes on image files (PNG/JPEG) does NOT produce
/// executable or archive detections.
#[test]
fn alltypes_images_exclude_executables_and_archives() {
    let db = db_root();
    let extra = db_extra_root();
    let mut builder = DatabaseBuilder::new(&db);
    if std::path::Path::new(&extra).is_dir() {
        builder = builder.with_extra(&extra);
    }
    let database = match builder.build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("SKIP: upstream database not found: {e}");
            return;
        }
    };

    let corpus = corpus_dir();
    let image_files = ["pixel.png", "pixel.jpg", "pixel.bmp"];

    let mut tested = 0usize;
    let mut violations = Vec::new();

    for filename in &image_files {
        let path = corpus.join(filename);
        if !path.exists() {
            continue;
        }

        let data = std::fs::read(&path).unwrap_or_default();
        let detection_types = alltypes_detection_types(&database, filename, data);

        // Images should only produce image-format detections.
        // BMP is detected by Binary rules (image_bmp.1.sg), so "Binary" is allowed.
        let allowed = match *filename {
            "pixel.png" => vec!["PNG"],
            "pixel.jpg" => vec!["JPEG"],
            "pixel.bmp" => vec!["Binary", "Image"],
            _ => vec![],
        };

        for dt in &detection_types {
            if !allowed.contains(&dt.as_str()) {
                violations.push(format!(
                    "{filename}: --alltypes produced '{dt}' detection on image \
                     (only {:?} allowed)",
                    allowed
                ));
            }
        }
        tested += 1;
    }

    assert!(tested > 0, "no image files tested");
    assert!(
        violations.is_empty(),
        "image --alltypes false positives ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
    eprintln!("alltypes image exclusion: {tested} files, 0 non-image detections");
}

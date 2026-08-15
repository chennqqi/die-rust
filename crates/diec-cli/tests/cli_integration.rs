//! CLI integration tests.
//!
//! These tests invoke the `diec` binary end-to-end against the
//! upstream rule database and verify output and exit codes.

use std::io::Write;
use std::process::Command;

/// Find the upstream database directory.
fn db_root() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    root.join("upstream/Detect-It-Easy/db")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

/// Find the built `diec` binary.
fn diec_binary() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let target = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("target/debug/diec");
    // On Windows, add .exe extension.
    let path = if cfg!(windows) {
        let mut p = target.to_path_buf();
        p.set_extension("exe");
        p
    } else {
        target
    };
    path.to_str().expect("utf-8 path").to_string()
}

/// Write test data to a temp file and return its path.
fn write_temp_file(name: &str, data: &[u8]) -> String {
    let dir = std::env::temp_dir().join("diec_cli_tests");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).expect("create temp file");
    f.write_all(data).expect("write temp file");
    path.to_str().expect("utf-8 path").to_string()
}

/// Run the diec binary with the given arguments.
fn run_diec(args: &[&str]) -> (bool, String, String) {
    let bin = diec_binary();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .expect("failed to execute diec");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status.success(), stdout, stderr)
}

#[test]
fn cli_scans_7z_file() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    // 7z magic: 37 7A BC AF 27 1C + version bytes
    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli.7z", &data);

    let db = db_root();
    let (success, stdout, stderr) = run_diec(&["--db", &db, &path]);

    assert!(success, "diec should exit 0, stderr: {stderr}");
    assert!(
        stdout.contains("7-Zip"),
        "stdout should contain 7-Zip detection: {stdout}"
    );
}

#[test]
fn cli_json_output() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_json.7z", &data);

    let (success, stdout, _stderr) = run_diec(&["--db", &db_root(), "--output", "json", &path]);

    assert!(success, "diec should exit 0");
    assert!(
        stdout.contains("\"7-Zip\""),
        "JSON should contain 7-Zip: {stdout}"
    );
    assert!(
        stdout.contains("\"detections\""),
        "JSON should have detections array: {stdout}"
    );
    assert!(
        stdout.trim_start().starts_with('{'),
        "JSON should start with {{: {stdout}"
    );
}

#[test]
fn cli_version_flag() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let (success, stdout, _stderr) = run_diec(&["--version"]);
    assert!(success);
    assert!(stdout.starts_with("diec "), "version output: {stdout}");
}

#[test]
fn cli_help_flag() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let (success, _stdout, stderr) = run_diec(&["--help"]);
    assert!(success);
    assert!(
        stderr.contains("Usage:"),
        "help should contain Usage: {stderr}"
    );
}

#[test]
fn cli_no_args_exits_with_usage_error() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let (success, _stdout, stderr) = run_diec(&[]);
    assert!(!success, "diec with no args should fail");
    assert!(
        stderr.contains("no input files") || stderr.contains("Usage:"),
        "stderr should mention no input files: {stderr}"
    );
}

#[test]
fn cli_scans_bzip2_file() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    // BZip2 magic: "BZh" + level + block magic
    let mut data = b"BZh9".to_vec();
    data.extend_from_slice(&[0x31, 0x41, 0x59, 0x26, 0x53, 0x59]);
    data.resize(64, 0);
    let path = write_temp_file("test_cli.bz2", &data);

    let db = db_root();
    let (success, stdout, stderr) = run_diec(&["--db", &db, &path]);

    assert!(success, "diec should exit 0, stderr: {stderr}");
    assert!(
        stdout.to_lowercase().contains("bzip"),
        "stdout should contain BZip detection: {stdout}"
    );
}

#[test]
fn cli_recursive_directory_scan() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    // Create a temp directory with two test files.
    let dir = std::env::temp_dir().join("diec_cli_dir_test");
    std::fs::create_dir_all(&dir).ok();
    let sub = dir.join("sub");
    std::fs::create_dir_all(&sub).ok();

    // 7z file in top dir
    let mut data7z = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data7z.resize(64, 0);
    std::fs::write(dir.join("a.7z"), &data7z).ok();

    // BZip2 file in subdir
    let mut bz2 = b"BZh9".to_vec();
    bz2.extend_from_slice(&[0x31, 0x41, 0x59, 0x26, 0x53, 0x59]);
    bz2.resize(64, 0);
    std::fs::write(sub.join("b.bz2"), &bz2).ok();

    let dir_str = dir.to_str().unwrap();
    let db = db_root();
    // ADR 0028: --recursive-dir (-R) replaces old --recursive for directory recursion.
    let (success, stdout, stderr) = run_diec(&["--db", &db, "--recursive-dir", dir_str]);

    assert!(success, "diec should exit 0, stderr: {stderr}");
    assert!(stdout.contains("7-Zip"), "should detect 7z: {stdout}");
    assert!(
        stdout.to_lowercase().contains("bzip"),
        "should detect bzip2: {stdout}"
    );

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_directory_without_recursive_errors() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let dir = std::env::temp_dir().join("diec_cli_norec_test");
    std::fs::create_dir_all(&dir).ok();

    let dir_str = dir.to_str().unwrap();
    let (success, _stdout, stderr) = run_diec(&[dir_str]);

    assert!(
        !success,
        "diec should fail without --recursive-dir on a dir"
    );
    assert!(
        stderr.contains("is a directory") || stderr.contains("--recursive-dir"),
        "stderr should mention directory: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_recursivescan_pe_intra_file() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    // ADR 0028: -r/--recursivescan enables intra-file recursive scanning
    // (PE resources + overlay), NOT directory recursion.
    // Test on a PE file from the corpus.
    let pe_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("minimal.exe");
    if !pe_path.exists() {
        eprintln!("Skipping: corpus/minimal.exe not found");
        return;
    }

    let pe_str = pe_path.to_str().unwrap();
    let db = db_root();

    // Without -r: should NOT have nested resource detections.
    let (success, stdout_base, _stderr) = run_diec(&["--db", &db, pe_str]);
    assert!(success, "diec should exit 0 without -r");

    // With -r: should have nested resource detections (may have more detections).
    let (success, stdout_recursive, _stderr) = run_diec(&["--db", &db, "-r", pe_str]);
    assert!(success, "diec should exit 0 with -r");

    // The -r output should be at least as long as the base output
    // (it may have additional nested detections).
    assert!(
        stdout_recursive.len() >= stdout_base.len(),
        "-r should produce at least as much output as without -r"
    );
}

#[test]
fn cli_archives_zip_extraction() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    // Use the nested ZIP corpus file that contains embedded PE/ELF members.
    let zip_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("nested-zip-with-pe.zip");
    if !zip_path.exists() {
        eprintln!("Skipping: corpus/nested-zip-with-pe.zip not found");
        return;
    }

    let zip_str = zip_path.to_str().unwrap();
    let db = db_root();

    // Without --archives: should detect ZIP but not nested members.
    let (success, stdout_base, _stderr) = run_diec(&["--db", &db, zip_str]);
    assert!(success, "diec should exit 0 without --archives");

    // With --archives: should detect ZIP and attempt to scan members.
    let (success, stdout_archives, _stderr) = run_diec(&["--db", &db, "--archives", zip_str]);
    assert!(
        success,
        "diec should exit 0 with --archives, stderr: {_stderr}"
    );

    // The --archives output should be at least as long as the base output.
    assert!(
        stdout_archives.len() >= stdout_base.len(),
        "--archives should produce at least as much output as without --archives"
    );
}

#[test]
fn cli_help_shows_new_flags() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let (success, stdout, _stderr) = run_diec(&["--help"]);
    assert!(success);
    // ADR 0028: -r is now recursivescan, -R is recursive-dir.
    assert!(
        stdout.contains("--recursivescan") || _stderr.contains("--recursivescan"),
        "help should show --recursivescan"
    );
    assert!(
        stdout.contains("--recursive-dir") || _stderr.contains("--recursive-dir"),
        "help should show --recursive-dir"
    );
    assert!(
        stdout.contains("--archives") || _stderr.contains("--archives"),
        "help should show --archives"
    );
}

#[test]
fn cli_xml_output() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_xml.7z", &data);

    let (success, stdout, _stderr) = run_diec(&["--db", &db_root(), "--output", "xml", &path]);

    assert!(success, "diec should exit 0");
    assert!(
        stdout.contains("<?xml"),
        "XML should start with declaration: {stdout}"
    );
    assert!(
        stdout.contains("<Result>"),
        "XML should have Result element: {stdout}"
    );
    assert!(
        stdout.contains("7-Zip"),
        "XML should contain 7-Zip: {stdout}"
    );
}

#[test]
fn cli_csv_output() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_csv.7z", &data);

    let (success, stdout, _stderr) = run_diec(&["--db", &db_root(), "--output", "csv", &path]);

    assert!(success, "diec should exit 0");
    assert!(
        stdout.contains("path,file_type,type,name,version,options"),
        "CSV should have header: {stdout}"
    );
    assert!(
        stdout.contains("7-Zip"),
        "CSV should contain 7-Zip: {stdout}"
    );
}

#[test]
fn cli_tsv_output() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_tsv.7z", &data);

    let (success, stdout, _stderr) = run_diec(&["--db", &db_root(), "--output", "tsv", &path]);

    assert!(success, "diec should exit 0");
    assert!(
        stdout.contains("path\tfile_type\ttype\tname\tversion\toptions"),
        "TSV should have header: {stdout}"
    );
    assert!(
        stdout.contains("7-Zip"),
        "TSV should contain 7-Zip: {stdout}"
    );
}

#[test]
fn cli_alltypes_flag() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    // Use a minimal PE file: with --alltypes it should produce more
    // detections than without (e.g. MSDOS, CFBF, etc.).
    let mut data = vec![0x4D, 0x5A]; // MZ header
    data.resize(256, 0);
    let path = write_temp_file("test_cli_alltypes.exe", &data);

    let (_success, stdout_normal, _) = run_diec(&["--db", &db_root(), "--output", "json", &path]);
    let (_success, stdout_alltypes, _) =
        run_diec(&["--db", &db_root(), "--output", "json", "--alltypes", &path]);

    let normal_count = stdout_normal.matches("\"name\"").count();
    let alltypes_count = stdout_alltypes.matches("\"name\"").count();
    assert!(
        alltypes_count >= normal_count,
        "--alltypes should produce at least as many detections: normal={normal_count}, alltypes={alltypes_count}"
    );
}

#[test]
fn cli_no_dedup_flag() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    // Use a minimal PE file: --alltypes --no-dedup should produce >= detections
    // than --alltypes alone (dedup removes cross-group duplicates by default).
    let mut data = vec![0x4D, 0x5A]; // MZ header
    data.resize(256, 0);
    let path = write_temp_file("test_cli_no_dedup.exe", &data);

    let (_success, stdout_dedup, _) =
        run_diec(&["--db", &db_root(), "--output", "json", "--alltypes", &path]);
    let (_success, stdout_no_dedup, _) = run_diec(&[
        "--db",
        &db_root(),
        "--output",
        "json",
        "--alltypes",
        "--no-dedup",
        &path,
    ]);

    let dedup_count = stdout_dedup.matches("\"name\"").count();
    let no_dedup_count = stdout_no_dedup.matches("\"name\"").count();
    assert!(
        no_dedup_count >= dedup_count,
        "--no-dedup should produce >= detections than default dedup: dedup={dedup_count}, no_dedup={no_dedup_count}"
    );
}

#[test]
fn cli_invalid_output_format() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let (success, _stdout, stderr) = run_diec(&["--output", "yaml", "somefile.bin"]);
    assert!(!success, "diec should reject unknown output format");
    assert!(
        stderr.contains("unsupported output format"),
        "stderr should mention unsupported format: {stderr}"
    );
}

#[test]
fn cli_deepscan_flag_accepted() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_deep.7z", &data);

    // --deepscan should be accepted and not cause errors.
    let (success, _stdout, stderr) = run_diec(&["--db", &db_root(), "--deepscan", &path]);
    assert!(success, "diec with --deepscan should exit 0: {stderr}");
}

#[test]
fn cli_heuristicscan_flag_accepted() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_heur.7z", &data);

    let (success, _stdout, stderr) = run_diec(&["--db", &db_root(), "--heuristicscan", &path]);
    assert!(success, "diec with --heuristicscan should exit 0: {stderr}");
}

#[test]
fn cli_format_flag() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_format.7z", &data);

    let (success, stdout_normal, _) = run_diec(&["--db", &db_root(), &path]);
    let (success_fmt, stdout_fmt, _) = run_diec(&["--db", &db_root(), "--format", &path]);

    assert!(success, "diec should exit 0");
    assert!(success_fmt, "diec with --format should exit 0");
    // Formatted output should differ from normal (extra spacing).
    assert_ne!(
        stdout_normal, stdout_fmt,
        "--format should change output spacing"
    );
    assert!(
        stdout_fmt.contains("7-Zip"),
        "formatted output should contain 7-Zip: {stdout_fmt}"
    );
}

#[test]
fn cli_profiling_flag() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_prof.7z", &data);

    let (success, _stdout, stderr) = run_diec(&["--db", &db_root(), "--profiling", &path]);
    assert!(success, "diec with --profiling should exit 0: {stderr}");
    // Profiling info goes to stderr.
    assert!(
        stderr.contains("Scanned") && stderr.contains("s"),
        "profiling output should contain timing: {stderr}"
    );
}

#[test]
fn cli_messages_flag() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_msg.7z", &data);

    // --messages should be accepted and not cause errors.
    let (success, _stdout, _stderr) = run_diec(&["--db", &db_root(), "--messages", &path]);
    assert!(success, "diec with --messages should exit 0");
}

#[test]
fn cli_entropy_mode() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_entropy.7z", &data);

    let (success, stdout, _stderr) = run_diec(&["--entropy", &path]);
    assert!(success, "diec --entropy should exit 0");
    assert!(
        stdout.contains("entropy"),
        "entropy output should contain 'entropy': {stdout}"
    );
}

#[test]
fn cli_entropy_json_mode() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_entropy_json.7z", &data);

    let (success, stdout, _stderr) = run_diec(&["--entropy", "--output", "json", &path]);
    assert!(success, "diec --entropy --output json should exit 0");
    assert!(
        stdout.contains("\"entropy\""),
        "JSON entropy output should contain 'entropy' key: {stdout}"
    );
}

#[test]
fn cli_info_mode() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let data = b"hello world".to_vec();
    let path = write_temp_file("test_cli_info.txt", &data);

    let (success, stdout, _stderr) = run_diec(&["--info", &path]);
    assert!(success, "diec --info should exit 0");
    assert!(
        stdout.contains("size"),
        "info output should contain 'size': {stdout}"
    );
}

#[test]
fn cli_showdatabase() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let (success, stdout, _stderr) = run_diec(&["--db", &db_root(), "--showdatabase"]);
    assert!(success, "diec --showdatabase should exit 0");
    assert!(
        stdout.contains("Main database"),
        "showdatabase should show main database: {stdout}"
    );
    assert!(
        stdout.contains("Binary"),
        "showdatabase should list file types: {stdout}"
    );
}

#[test]
fn cli_showstructs() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let (success, stdout, _stderr) = run_diec(&["--showstructs"]);
    assert!(success, "diec --showstructs should exit 0");
    assert!(
        stdout.contains("Structures"),
        "showstructs should list structures: {stdout}"
    );
    // Upstream --showstructs outputs 4 general methods (hardcoded FT_UNKNOWN).
    assert!(
        stdout.contains("Info"),
        "showstructs should list Info method: {stdout}"
    );
    assert!(
        stdout.contains("Hash"),
        "showstructs should list Hash method: {stdout}"
    );
    assert!(
        stdout.contains("Entropy"),
        "showstructs should list Entropy method: {stdout}"
    );
    assert!(
        stdout.contains("Check format"),
        "showstructs should list Check format method: {stdout}"
    );
}

#[test]
fn cli_struct_hash_mode() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let data = b"hello world";
    let path = write_temp_file("test_struct_hash.bin", data);

    // --struct Hash should output all 7 hash algorithms.
    let (success, stdout, _stderr) = run_diec(&["--struct", "Hash", &path]);
    assert!(success, "diec --struct Hash should exit 0: {_stderr}");
    assert!(
        stdout.contains("MD5"),
        "--struct Hash should contain MD5: {stdout}"
    );
    assert!(
        stdout.contains("SHA256"),
        "--struct Hash should contain SHA256: {stdout}"
    );
    // MD5 of "hello world" is 5eb63bbbe01eeed093cb22bb8f5acdc3.
    assert!(
        stdout.contains("5eb63bbbe01eeed093cb22bb8f5acdc3"),
        "--struct Hash MD5 value should match: {stdout}"
    );
}

#[test]
fn cli_struct_hash_md5_filter() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let data = b"hello world";
    let path = write_temp_file("test_struct_md5.bin", data);

    // --struct Hash#MD5 should output only MD5.
    let (success, stdout, _stderr) = run_diec(&["--struct", "Hash#MD5", &path]);
    assert!(success, "diec --struct Hash#MD5 should exit 0: {_stderr}");
    assert!(
        stdout.contains("MD5"),
        "--struct Hash#MD5 should contain MD5: {stdout}"
    );
    assert!(
        !stdout.contains("SHA256"),
        "--struct Hash#MD5 should NOT contain SHA256: {stdout}"
    );
}

#[test]
fn cli_struct_empty_file_hash() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let path = write_temp_file("test_struct_empty.bin", b"");

    // Empty file Hash#MD5 should return empty string (upstream boundary behavior).
    let (success, stdout, _stderr) = run_diec(&["--struct", "Hash#MD5", &path]);
    assert!(
        success,
        "diec --struct Hash#MD5 on empty file should exit 0: {_stderr}"
    );
    // The MD5 value should be empty, not the standard empty-input MD5.
    assert!(
        !stdout.contains("d41d8cd98f00b204e9800998ecf8427e"),
        "empty file MD5 should be empty string, not standard empty MD5: {stdout}"
    );
}

#[test]
fn cli_struct_info_mode() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let data = b"hello world";
    let path = write_temp_file("test_struct_info.bin", data);

    let (success, stdout, _stderr) = run_diec(&["--struct", "Info", &path]);
    assert!(success, "diec --struct Info should exit 0: {_stderr}");
    assert!(
        stdout.contains("File name"),
        "--struct Info should contain File name: {stdout}"
    );
    assert!(
        stdout.contains("Size"),
        "--struct Info should contain Size: {stdout}"
    );
}

#[test]
fn cli_struct_entropy_mode() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let data = b"hello world";
    let path = write_temp_file("test_struct_entropy.bin", data);

    let (success, stdout, _stderr) = run_diec(&["--struct", "Entropy", &path]);
    assert!(success, "diec --struct Entropy should exit 0: {_stderr}");
    assert!(
        stdout.contains("total"),
        "--struct Entropy should contain total: {stdout}"
    );
}

#[test]
fn cli_struct_unknown_method() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let data = b"hello world";
    let path = write_temp_file("test_struct_unknown.bin", data);

    // Unknown method should not error, exit 0.
    let (success, _stdout, _stderr) = run_diec(&["--struct", "NoSuchMethod", &path]);
    assert!(
        success,
        "diec --struct NoSuchMethod should exit 0: {_stderr}"
    );
}

#[test]
fn cli_struct_json_output() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let data = b"hello world";
    let path = write_temp_file("test_struct_json.bin", data);

    let (success, stdout, _stderr) = run_diec(&["--struct", "Hash#MD5", "--json", &path]);
    assert!(
        success,
        "diec --struct Hash#MD5 --json should exit 0: {_stderr}"
    );
    assert!(
        stdout.contains("\"data\""),
        "--struct --json should contain data key: {stdout}"
    );
    assert!(
        stdout.contains("5eb63bbbe01eeed093cb22bb8f5acdc3"),
        "--struct --json should contain MD5 value: {stdout}"
    );
}

#[test]
fn cli_struct_short_flag() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let data = b"hello world";
    let path = write_temp_file("test_struct_short.bin", data);

    // -S is the short form of --struct.
    let (success, stdout, _stderr) = run_diec(&["-S", "Hash#MD5", &path]);
    assert!(success, "diec -S Hash#MD5 should exit 0: {_stderr}");
    assert!(
        stdout.contains("MD5"),
        "-S Hash#MD5 should contain MD5: {stdout}"
    );
}

#[test]
fn cli_extradb_flag() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_extradb.7z", &data);

    // --extradb with a non-existent path should still work (just skipped).
    let (success, _stdout, _stderr) =
        run_diec(&["--db", &db_root(), "--extradb", "/nonexistent/path", &path]);
    assert!(success, "diec with --extradb should exit 0");
}

#[test]
fn cli_upstream_json_format_flag() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_upstream_json.7z", &data);

    let (success, stdout, _stderr) = run_diec(&["--database", &db_root(), "--json", &path]);
    assert!(success, "diec --json should exit 0");
    assert!(
        stdout.contains("\"7-Zip\""),
        "JSON output should contain 7-Zip: {stdout}"
    );
    assert!(
        stdout.trim_start().starts_with('{'),
        "JSON should start with {{: {stdout}"
    );
}

#[test]
fn cli_upstream_xml_format_flag() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_upstream_xml.7z", &data);

    let (success, stdout, _stderr) = run_diec(&["--database", &db_root(), "--xml", &path]);
    assert!(success, "diec --xml should exit 0");
    assert!(
        stdout.contains("<?xml"),
        "XML should start with declaration: {stdout}"
    );
    assert!(
        stdout.contains("7-Zip"),
        "XML should contain 7-Zip: {stdout}"
    );
}

#[test]
fn cli_upstream_csv_tsv_plaintext_flags() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path_csv = write_temp_file("test_cli_upstream_csv.7z", &data);
    let path_tsv = write_temp_file("test_cli_upstream_tsv.7z", &data);
    let path_plain = write_temp_file("test_cli_upstream_plain.7z", &data);

    let (success, stdout, _stderr) = run_diec(&["--database", &db_root(), "--csv", &path_csv]);
    assert!(success, "diec --csv should exit 0");
    assert!(
        stdout.contains("path,file_type,type,name,version,options"),
        "CSV should have header: {stdout}"
    );

    let (success, stdout, _stderr) = run_diec(&["--database", &db_root(), "--tsv", &path_tsv]);
    assert!(success, "diec --tsv should exit 0");
    assert!(
        stdout.contains("path\tfile_type\ttype\tname\tversion\toptions"),
        "TSV should have header: {stdout}"
    );

    let (success, stdout, _stderr) =
        run_diec(&["--database", &db_root(), "--plaintext", &path_plain]);
    assert!(success, "diec --plaintext should exit 0");
    assert!(
        stdout.contains("7-Zip"),
        "plain text should contain 7-Zip: {stdout}"
    );
}

#[test]
fn cli_upstream_database_and_struct_aliases() {
    if !std::path::Path::new(&db_root()).is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    let path = write_temp_file("test_cli_upstream_aliases.7z", &data);

    // Upstream-style database switches should be accepted as aliases.
    let (success, _stdout, _stderr) = run_diec(&[
        "--database",
        &db_root(),
        "--extradatabase",
        "/nonexistent/extra",
        "--customdatabase",
        "/nonexistent/custom",
        "-d",
        "-a",
        &path,
    ]);
    assert!(
        success,
        "diec with upstream database aliases and -d/-a should exit 0"
    );

    // Upstream uses --showmethods rather than --showstructs.
    let (success, stdout, _stderr) = run_diec(&["--showmethods"]);
    assert!(success, "diec --showmethods should exit 0");
    // Upstream --showmethods outputs 4 general methods (same as --showstructs).
    assert!(
        stdout.contains("Hash"),
        "--showmethods should list Hash method: {stdout}"
    );
    assert!(
        stdout.contains("Entropy"),
        "--showmethods should list Entropy method: {stdout}"
    );
}

#[test]
fn cli_short_version_and_help_flags() {
    if !std::path::Path::new(&diec_binary()).exists() {
        eprintln!("Skipping: diec binary not built");
        return;
    }

    let (success, stdout, _stderr) = run_diec(&["-v"]);
    assert!(success, "diec -v should exit 0");
    assert!(stdout.starts_with("diec "), "version output: {stdout}");

    let (success, _stdout, stderr) = run_diec(&["-h"]);
    assert!(success, "diec -h should exit 0");
    assert!(
        stderr.contains("Usage:"),
        "help should contain Usage: {stderr}"
    );
}

//! Seed-corpus replay for all fuzz harnesses.
//!
//! Runs every fuzz harness body over all committed seed files in
//! `fuzz/corpus/<target>/`. This verifies the core release invariant —
//! "no crash, no panic, no hang on the seed corpus" — on stable Rust
//! without requiring nightly or libFuzzer. It is the deterministic
//! counterpart to the coverage-guided libFuzzer run executed in CI.
//!
//! See `docs/design/testing.md` section 14 and `RELEASE.md` "Fuzz".
//!
//! Run with:
//!   cd fuzz && cargo test --no-default-features --features replay

#![cfg(feature = "replay")]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use die_core::input::{ByteRange, ByteSource, ByteView, MemorySource};
use die_formats::ProbeTable;

// ---- corpus discovery ---------------------------------------------------

/// Manifest dir for the fuzz crate (`fuzz/`).
const FUZZ_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// List all seed files under `fuzz/corpus/<target>/`.
fn corpus_files(target: &str) -> Vec<PathBuf> {
    let dir = Path::new(FUZZ_DIR).join("corpus").join(target);
    let mut out = Vec::new();
    if !dir.exists() {
        return out;
    }
    for entry in std::fs::read_dir(&dir).expect("read corpus dir") {
        let entry = entry.expect("read dir entry");
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            out.push(entry.path());
        }
    }
    out.sort();
    out
}

/// Read a seed file as bytes.
fn read_seed(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read seed {path:?}: {e}"))
}

/// Count total seeds across all targets for the summary test.
fn total_seed_count() -> usize {
    [
        "byte_source",
        "byte_view",
        "format_probe",
        "scan_engine",
        "output_render",
        "scan_ffi",
    ]
    .iter()
    .map(|t| corpus_files(t).len())
    .sum()
}

// ---- harness bodies (mirrors fuzz_targets/*.rs) -------------------------

fn harness_byte_source(data: &[u8]) {
    let src = MemorySource::new(data);
    for offset in [0u64, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        let mut out = [0u8; 64];
        let _ = src.read_at(offset, &mut out);
    }
    for offset in [0u64, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        let mut out = [0u8; 64];
        let _ = src.read_exact_at(offset, &mut out);
    }
    let _ = src.read_exact_at(0, &mut []);
    let _ = src.read_at(0, &mut []);
}

fn harness_byte_view(data: &[u8]) {
    let src = MemorySource::new(data);
    let total_len = src.len();
    if total_len == 0 {
        return;
    }
    let range = ByteRange::new(0, total_len).unwrap();
    let view = ByteView::new(&src, range).unwrap();
    for offset in [0u64, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        for length in [0u64, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
            if let Some(sub) = view.subview(offset, length) {
                let mut out = [0u8; 64];
                let _ = sub.read_at(0, &mut out);
                let _ = sub.read_at(offset, &mut out);
                let _ = sub.read_exact_at(0, &mut out);
                let _ = sub.read_u8(0);
                let _ = sub.read_u16_le(0);
                let _ = sub.read_u16_be(0);
                let _ = sub.read_u32_le(0);
                let _ = sub.read_u32_be(0);
                let _ = sub.read_u64_le(0);
                let _ = sub.read_u64_be(0);
            }
        }
    }
    for offset in [0u64, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        let _ = view.read_u8(offset);
        let _ = view.read_u16_le(offset);
        let _ = view.read_u16_be(offset);
        let _ = view.read_u32_le(offset);
        let _ = view.read_u32_be(offset);
        let _ = view.read_u64_le(offset);
        let _ = view.read_u64_be(offset);
    }
}

fn harness_format_probe(data: &[u8]) {
    let src = MemorySource::new(data);
    let range = ByteRange::new(0, src.len()).unwrap();
    let view = ByteView::new(&src, range).unwrap();
    let table = ProbeTable::default_phase2();
    let (candidates, errors) = table.probe_all(&view);
    for c in &candidates {
        assert_ne!(
            c.strength,
            die_core::format::FormatStrength::None,
            "candidate with None strength"
        );
    }
    for e in &errors {
        match e {
            die_formats::ProbeError::Truncated { .. }
            | die_formats::ProbeError::InvalidHeader { .. } => {}
            die_formats::ProbeError::Io(_) => {
                panic!("MemorySource should not produce Io errors: {e:?}");
            }
        }
    }
}

fn harness_output_render(data: &[u8]) {
    if data.is_empty() {
        let result = die_engine::ScanResult {
            path: "empty".to_string(),
            detections: vec![],
            diagnostics: vec![],
            structured_diagnostics: vec![],
            profiling: vec![],
        };
        let json = die_output::render_json(&result);
        assert!(!json.is_empty(), "JSON output should be non-empty");
        let _ = die_output::render_text(&result);
        return;
    }
    let path = String::from_utf8_lossy(data).replace('\0', "_");
    let mut detections = Vec::new();
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let name_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let type_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if name_len == 0 || type_len == 0 {
            break;
        }
        let name_end = offset + name_len.min(data.len() - offset);
        let type_end = name_end + type_len.min(data.len().saturating_sub(name_end));
        if type_end > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[offset..name_end]).to_string();
        let type_name = String::from_utf8_lossy(&data[name_end..type_end]).to_string();
        detections.push(die_engine::ScanDetection {
            file_type: "fuzz".to_string(),
            type_name: if type_name.is_empty() {
                "unknown".to_string()
            } else {
                type_name
            },
            name: if name.is_empty() {
                "unknown".to_string()
            } else {
                name
            },
            version: Some("1.0".to_string()),
            options: None,
            signature_path: None,
            id: None,
            parent_id: None,
            file_part: None,
            offset: None,
            size: None,
            is_heuristic: None,
            is_a_heuristic: None,
            original_name: None,
            engine: None,
        });
        offset = type_end;
        if offset >= data.len() {
            break;
        }
    }
    let result = die_engine::ScanResult {
        path,
        detections,
        diagnostics: vec!["fuzz diagnostic".to_string()],
        structured_diagnostics: vec![],
        profiling: vec![],
    };
    let json = die_output::render_json(&result);
    assert!(!json.is_empty(), "JSON output should be non-empty");
    let _ = serde_json::from_str::<serde_json::Value>(&json);
    let _ = die_output::render_text(&result);
    let _ = die_output::render_text_formatted(&result);
    let _ = die_output::render_xml(&result);
    let _ = die_output::render_csv(&result);
    let _ = die_output::render_tsv(&result);
}

// ---- scan engine + FFI database (loaded once) ---------------------------

static DATABASE: OnceLock<Option<die_engine::Database>> = OnceLock::new();

fn get_database() -> Option<&'static die_engine::Database> {
    let opt = DATABASE.get_or_init(|| {
        let db_path = Path::new(FUZZ_DIR)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("upstream/Detect-It-Easy/db"))
            .unwrap_or_else(|| PathBuf::from("upstream/Detect-It-Easy/db"));
        let s = db_path.to_str().unwrap_or("upstream/Detect-It-Easy/db");
        match die_engine::DatabaseBuilder::new(s).build() {
            Ok(db) => Some(db),
            Err(e) => {
                eprintln!("seed_replay: cannot load database: {e}");
                None
            }
        }
    });
    opt.as_ref()
}

fn harness_scan_engine(data: &[u8]) {
    let db = match get_database() {
        Some(db) => db,
        None => return,
    };
    let cancel = die_core::cancel::CancellationToken::new();
    let result = die_engine::scan_bytes(
        db,
        "fuzz_input",
        data.to_vec(),
        die_engine::ScanFlags::default(),
        &cancel,
    );
    if let Ok(result) = result {
        for d in &result.detections {
            assert!(!d.type_name.is_empty(), "empty type_name in detection");
            assert!(!d.name.is_empty(), "empty name in detection");
        }
    }
    let flags = die_engine::ScanFlags {
        heuristic: true,
        ..Default::default()
    };
    let _ = die_engine::scan_bytes(db, "fuzz_input", data.to_vec(), flags, &cancel);
    let flags = die_engine::ScanFlags {
        all_types: true,
        ..Default::default()
    };
    let _ = die_engine::scan_bytes(db, "fuzz_input", data.to_vec(), flags, &cancel);
}

// FFI handle types (re-exported by die-ffi at crate root). Using the
// typed handles instead of `*mut c_void` matches the real C ABI function
// signatures and keeps the rlib member alive so the linker does not strip
// the `#[no_mangle]` symbols.
use die_ffi::{
    die_v1_database_builder_add_path_utf8, die_v1_database_builder_build,
    die_v1_database_builder_free, die_v1_database_builder_new, die_v1_error_free,
    die_v1_result_free, die_v1_scan_bytes, DieDatabase, DieDatabaseBuilder, DieError,
    DieResult,
};

/// Wrapper that makes the raw database pointer `Send + Sync`. The handle
/// is only mutated through `die_v1_scan_bytes` which uses panic
/// containment and is documented as thread-neutral.
struct SendPtr(*mut DieDatabase);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

static FFI_DB: OnceLock<SendPtr> = OnceLock::new();

fn ffi_database() -> *mut DieDatabase {
    let ptr = FFI_DB.get_or_init(|| {
        let db_path = Path::new(FUZZ_DIR)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("upstream/Detect-It-Easy/db"))
            .unwrap_or_else(|| PathBuf::from("upstream/Detect-It-Easy/db"));
        let s = db_path.to_str().unwrap_or("upstream/Detect-It-Easy/db");
        let path_bytes = s.as_bytes();
        let mut builder: *mut DieDatabaseBuilder = std::ptr::null_mut();
        let mut error: *mut DieError = std::ptr::null_mut();
        unsafe {
            if die_v1_database_builder_new(&mut builder, &mut error) != 0 {
                return SendPtr(std::ptr::null_mut());
            }
            if die_v1_database_builder_add_path_utf8(
                builder,
                0,
                path_bytes.as_ptr(),
                path_bytes.len() as u64,
                0,
                &mut error,
            ) != 0
            {
                die_v1_database_builder_free(&mut builder);
                return SendPtr(std::ptr::null_mut());
            }
            let mut database: *mut DieDatabase = std::ptr::null_mut();
            let status = die_v1_database_builder_build(builder, &mut database, &mut error);
            die_v1_database_builder_free(&mut builder);
            if status != 0 {
                return SendPtr(std::ptr::null_mut());
            }
            SendPtr(database)
        }
    });
    ptr.0
}

fn harness_scan_ffi(data: &[u8]) {
    let db = ffi_database();
    if db.is_null() {
        return;
    }
    let mut result: *mut DieResult = std::ptr::null_mut();
    let mut error: *mut DieError = std::ptr::null_mut();
    let status = unsafe {
        die_v1_scan_bytes(
            db,
            data.as_ptr(),
            data.len() as u64,
            std::ptr::null(),
            std::ptr::null(),
            &mut result,
            &mut error,
        )
    };
    assert!(status <= 15, "invalid status code from FFI: {status}");
    if !result.is_null() {
        unsafe { die_v1_result_free(&mut result) };
        assert!(result.is_null(), "result not nulled after free");
    }
    if !error.is_null() {
        unsafe { die_v1_error_free(&mut error) };
        assert!(error.is_null(), "error not nulled after free");
    }
    unsafe {
        die_v1_result_free(&mut result);
        die_v1_error_free(&mut error);
    }
}

// ---- per-target replay tests -------------------------------------------

#[test]
fn replay_byte_source() {
    for f in corpus_files("byte_source") {
        harness_byte_source(&read_seed(&f));
    }
}

#[test]
fn replay_byte_view() {
    for f in corpus_files("byte_view") {
        harness_byte_view(&read_seed(&f));
    }
}

#[test]
fn replay_format_probe() {
    for f in corpus_files("format_probe") {
        harness_format_probe(&read_seed(&f));
    }
}

#[test]
fn replay_scan_engine() {
    for f in corpus_files("scan_engine") {
        harness_scan_engine(&read_seed(&f));
    }
}

#[test]
fn replay_output_render() {
    for f in corpus_files("output_render") {
        harness_output_render(&read_seed(&f));
    }
}

#[test]
fn replay_scan_ffi() {
    for f in corpus_files("scan_ffi") {
        harness_scan_ffi(&read_seed(&f));
    }
}

#[test]
fn replay_seed_count_matches_release() {
    // RELEASE.md / COMPATIBILITY.md record 165 seeds across 6 targets.
    let n = total_seed_count();
    assert_eq!(n, 165, "seed corpus count changed: expected 165, got {n}");
}

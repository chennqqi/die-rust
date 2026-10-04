//! Fuzz target: full scan engine on arbitrary input.
//!
//! Invariant: no panic, no hang, no unbounded allocation. The scanner
//! must return Ok(ScanResult) or Err(ScanError) for any input.
//!
//! This target requires the upstream database to be available at
//! `upstream/Detect-It-Easy/db`. If the database cannot be loaded,
//! the target exits early (libFuzzer treats this as a no-op).
//!
//! See `docs/design/testing.md` section 14.

#![no_main]

use die_core::cancel::CancellationToken;
use die_engine::{scan_bytes, DatabaseBuilder, ScanFlags};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Load the database once and cache it across fuzz iterations.
static DATABASE: OnceLock<Option<die_engine::Database>> = OnceLock::new();

/// Get the cached database, or None if it cannot be loaded.
fn get_database() -> Option<&'static die_engine::Database> {
    let opt = DATABASE.get_or_init(|| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let db_path = std::path::Path::new(manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("upstream/Detect-It-Easy/db"))
            .unwrap_or_else(|| std::path::PathBuf::from("upstream/Detect-It-Easy/db"));

        let db_path_str = db_path.to_str().unwrap_or("upstream/Detect-It-Easy/db");
        match DatabaseBuilder::new(db_path_str).build() {
            Ok(db) => Some(db),
            Err(e) => {
                eprintln!("fuzz_scan_engine: cannot load database: {e}");
                None
            }
        }
    });
    opt.as_ref()
}

fuzz_target!(|data: &[u8]| {
    let db = match get_database() {
        Some(db) => db,
        None => return,
    };

    let cancel = CancellationToken::new();

    // Scan with default flags - must not panic or hang.
    let result = scan_bytes(
        db,
        "fuzz_input",
        data.to_vec(),
        ScanFlags::default(),
        &cancel,
    );
    if let Ok(result) = result {
        // Invariant: detections have non-empty type_name and name.
        for d in &result.detections {
            assert!(!d.type_name.is_empty(), "empty type_name in detection");
            assert!(!d.name.is_empty(), "empty name in detection");
        }
    }

    // Scan with heuristic flags - must not panic or hang.
    let flags = ScanFlags {
        heuristic: true,
        ..Default::default()
    };
    let _ = scan_bytes(db, "fuzz_input", data.to_vec(), flags, &cancel);

    // Scan with all_types flags - must not panic or hang.
    let flags = ScanFlags {
        all_types: true,
        ..Default::default()
    };
    let _ = scan_bytes(db, "fuzz_input", data.to_vec(), flags, &cancel);
});

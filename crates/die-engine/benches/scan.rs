//! Benchmarks for the scan engine.
//!
//! Measures end-to-end scan time on corpus samples of varying complexity:
//! - Simple format detection (ELF, PE, Mach-O)
//! - Archive detection (Zip, tar)
//! - Document detection (PDF)
//! - Rule execution with database (7-Zip, Zip with rules)
//!
//! Run with: cargo bench -p die-engine

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use die_core::cancel::CancellationToken;
use die_engine::{DatabaseBuilder, ScanFlags, scan_bytes};
use std::path::PathBuf;

/// Resolve the workspace root from CARGO_MANIFEST_DIR.
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Resolve the corpus directory.
fn corpus_dir() -> PathBuf {
    workspace_root().join("corpus")
}

/// Resolve the upstream database directory.
fn db_path() -> String {
    workspace_root()
        .join("upstream/Detect-It-Easy/db")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

/// Load the database once for all benchmarks.
fn load_database() -> Option<die_engine::Database> {
    let path = db_path();
    match DatabaseBuilder::new(&path).build() {
        Ok(db) => Some(db),
        Err(e) => {
            eprintln!("bench: cannot load database: {e}");
            None
        }
    }
}

/// Benchmark scanning corpus files with the full database.
fn bench_scan_corpus(c: &mut Criterion) {
    let db = match load_database() {
        Some(db) => db,
        None => {
            eprintln!("bench_scan_corpus: database unavailable, skipping");
            return;
        }
    };
    let cancel = CancellationToken::new();
    let corpus = corpus_dir();

    // Representative samples of varying complexity.
    let samples = [
        ("minimal.elf", "ELF64 minimal"),
        ("minimal.exe", "PE32 minimal"),
        ("minimal.macho", "Mach-O 64 minimal"),
        ("payload.zip", "Zip archive"),
        ("payload.tar", "tar archive"),
        ("minimal.pdf", "PDF document"),
        ("pixel.png", "PNG image"),
        ("Minimal.class", "Java class"),
        ("minimal.dex", "DEX"),
    ];

    let mut group = c.benchmark_group("scan_corpus");
    group.sample_size(20);

    for (filename, label) in &samples {
        let path = corpus.join(filename);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("bench: skipping {filename}: file not found");
                continue;
            }
        };

        group.bench_with_input(BenchmarkId::new("full_db", label), &data, |b, data| {
            b.iter(|| {
                let _ = scan_bytes(&db, filename, data.clone(), ScanFlags::default(), &cancel);
            });
        });
    }

    group.finish();
}

/// Benchmark scanning with different flag combinations.
fn bench_scan_flags(c: &mut Criterion) {
    let db = match load_database() {
        Some(db) => db,
        None => {
            eprintln!("bench_scan_flags: database unavailable, skipping");
            return;
        }
    };
    let cancel = CancellationToken::new();
    let corpus = corpus_dir();

    let zip_path = corpus.join("payload.zip");
    let zip_data = match std::fs::read(&zip_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("bench_scan_flags: payload.zip not found, skipping");
            return;
        }
    };

    let mut group = c.benchmark_group("scan_flags");
    group.sample_size(20);

    // Default flags (no heuristic, no deep, no all-types).
    group.bench_function("default", |b| {
        b.iter(|| {
            let _ = scan_bytes(
                &db,
                "payload.zip",
                zip_data.clone(),
                ScanFlags::default(),
                &cancel,
            );
        });
    });

    // Heuristic scan.
    group.bench_function("heuristic", |b| {
        b.iter(|| {
            let flags = ScanFlags {
                heuristic: true,
                ..Default::default()
            };
            let _ = scan_bytes(&db, "payload.zip", zip_data.clone(), flags, &cancel);
        });
    });

    // All-types scan.
    group.bench_function("all_types", |b| {
        b.iter(|| {
            let flags = ScanFlags {
                all_types: true,
                ..Default::default()
            };
            let _ = scan_bytes(&db, "payload.zip", zip_data.clone(), flags, &cancel);
        });
    });

    // Deep scan.
    group.bench_function("deep", |b| {
        b.iter(|| {
            let flags = ScanFlags {
                deep: true,
                ..Default::default()
            };
            let _ = scan_bytes(&db, "payload.zip", zip_data.clone(), flags, &cancel);
        });
    });

    group.finish();
}

/// Benchmark database loading (expensive operation).
fn bench_database_load(c: &mut Criterion) {
    let path = db_path();
    if !PathBuf::from(&path).exists() {
        eprintln!("bench_database_load: database unavailable, skipping");
        return;
    }

    let mut group = c.benchmark_group("database_load");
    group.sample_size(10);

    group.bench_function("full_load", |b| {
        b.iter(|| {
            let _ = DatabaseBuilder::new(&path).build();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_scan_corpus,
    bench_scan_flags,
    bench_database_load
);
criterion_main!(benches);

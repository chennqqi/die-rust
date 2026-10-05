//! Scan performance benchmark harness.
//!
//! Loads a rule database once, scans a set of files, and reports
//! per-file and aggregate timing statistics (mean/p50/p95/max), plus a
//! phase breakdown between rule evaluation and fixed overhead.
//!
//! Usage:
//!   cargo run --release -p die-engine --example scan_bench -- \
//!       --db /path/to/db --files /path/to/dir [--count 500] [--scanner]
//!
//! Options:
//!   --db <path>       rule database directory (required)
//!   --extra <path>    extra database directory (repeatable)
//!   --files <dir>     directory of files to scan (required)
//!   --count <n>       limit number of files (default: all)
//!   --scanner         use the runtime-reusing Scanner instead of scan_once
//!   --json <path>     also write per-file results as JSON lines

use die_core::cancel::CancellationToken;
use die_engine::{DatabaseBuilder, ScanFlags, Scanner};
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let mut db_path: Option<String> = None;
    let mut extra_paths: Vec<String> = Vec::new();
    let mut files_dir: Option<String> = None;
    let mut count: Option<usize> = None;
    let mut use_scanner = false;
    let mut json_out: Option<String> = None;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                db_path = Some(args[i].clone());
            }
            "--extra" => {
                i += 1;
                extra_paths.push(args[i].clone());
            }
            "--files" => {
                i += 1;
                files_dir = Some(args[i].clone());
            }
            "--count" => {
                i += 1;
                count = Some(args[i].parse().expect("--count must be a number"));
            }
            "--scanner" => use_scanner = true,
            "--json" => {
                i += 1;
                json_out = Some(args[i].clone());
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let db_path = db_path.expect("--db required");
    let files_dir = files_dir.expect("--files required");

    // Build database.
    let t = Instant::now();
    let mut builder = DatabaseBuilder::new(&db_path);
    for extra in &extra_paths {
        builder = builder.with_extra(extra);
    }
    let database = match builder.build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("error: database build failed: {e}");
            std::process::exit(1);
        }
    };
    let db_load_ms = t.elapsed().as_secs_f64() * 1000.0;

    // Collect files (deterministic order).
    let mut files: Vec<PathBuf> = std::fs::read_dir(&files_dir)
        .expect("files dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    if let Some(n) = count {
        files.truncate(n);
    }

    eprintln!(
        "scan_bench: db={db_path} rules={} files={} db_load={db_load_ms:.1}ms mode={}",
        database.rule_count(),
        files.len(),
        if use_scanner { "scanner" } else { "scan_once" },
    );

    let cancel = CancellationToken::new();
    let flags = ScanFlags::default();
    let mut scanner = use_scanner.then(|| Scanner::new(std::sync::Arc::new(database.clone())));

    let mut times_ms: Vec<f64> = Vec::with_capacity(files.len());
    let mut rule_ms: Vec<f64> = Vec::with_capacity(files.len());
    let mut n_detections = 0usize;
    let mut json_lines = String::new();

    let total_start = Instant::now();
    for file in &files {
        let path_str = file.to_string_lossy().to_string();
        let t = Instant::now();
        let result = if let Some(s) = scanner.as_mut() {
            s.scan_file(&path_str, flags.clone(), &cancel)
        } else {
            die_engine::scan_once(&database, &path_str, flags.clone(), &cancel)
        };
        let elapsed = t.elapsed().as_secs_f64() * 1000.0;
        match result {
            Ok(r) => {
                n_detections += r.detections.len();
                let rules_sum: u64 = r.profiling.iter().map(|p| p.elapsed_ms).sum();
                times_ms.push(elapsed);
                rule_ms.push(rules_sum as f64);
                if json_out.is_some() {
                    json_lines.push_str(&format!(
                        "{{\"file\":{:?},\"ms\":{elapsed:.3},\"rules_ms\":{rules_sum},\"detections\":{}}}\n",
                        path_str,
                        r.detections.len()
                    ));
                }
            }
            Err(e) => {
                eprintln!("scan error {}: {e}", path_str);
            }
        }
    }
    let total_s = total_start.elapsed().as_secs_f64();

    times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = times_ms.len();
    if n == 0 {
        eprintln!("no files scanned");
        std::process::exit(1);
    }
    let mean = times_ms.iter().sum::<f64>() / n as f64;
    let p50 = times_ms[n / 2];
    let p95 = times_ms[(n * 95) / 100];
    let min = times_ms[0];
    let max = times_ms[n - 1];
    let rules_total: f64 = rule_ms.iter().sum();
    let other_total = total_s * 1000.0 - rules_total;

    println!("files:        {n}");
    println!("total:        {total_s:.2}s");
    println!("mean:         {mean:.1}ms");
    println!("p50:          {p50:.1}ms");
    println!("p95:          {p95:.1}ms");
    println!("min:          {min:.1}ms");
    println!("max:          {max:.1}ms");
    println!("rules_total:  {rules_total:.0}ms");
    println!("other_total:  {other_total:.0}ms");
    println!("detections:   {n_detections}");

    if let Some(path) = json_out {
        std::fs::write(&path, json_lines).expect("write json");
    }
}

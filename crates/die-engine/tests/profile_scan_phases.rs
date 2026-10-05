//! Per-phase scan profiling harness (ignored; run explicitly).
//!
//! Reproduces the `scan_bytes` inner pipeline on a real file with the
//! real `BufferHost` so the per-rule numbers include actual host work
//! (PE parsing, signature scans), complementing the die-rules
//! `profile_eval_compile_exec_split` microbenchmark which measures the
//! pure compile/deserialize/dispatch split.
//!
//! Run explicitly:
//!   DIE_PROF_DB=/tmp/die_db_trim3 DIE_PROF_FILE=/path/to/pe.exe \
//!       cargo test -p die-engine --release --test profile_scan_phases \
//!       -- --ignored --nocapture

use die_core::cancel::CancellationToken;
use die_core::input::ByteSource;
use die_engine::DatabaseBuilder;
use die_engine::host::{BufferHost, ScanFlags};
use die_rules::backend_rquickjs::RquickjsRuntime;
use die_rules::runtime::{RuleRuntime, RuntimeConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// Locate a profiling input file: `DIE_PROF_FILE`, else the first file
/// in `DIE_PROF_DIR` (default: upstream PE corpus is not assumed).
fn profile_input() -> Option<(String, Vec<u8>)> {
    if let Ok(p) = std::env::var("DIE_PROF_FILE") {
        let data = std::fs::read(&p).ok()?;
        return Some((p, data));
    }
    let dir = std::env::var("DIE_PROF_DIR").ok()?;
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    let p = files.into_iter().next()?;
    let data = std::fs::read(&p).ok()?;
    Some((p.to_string_lossy().to_string(), data))
}

/// Measure the full per-file pipeline with phase breakdown.
#[test]
#[ignore = "profiling harness; run explicitly with --ignored"]
fn profile_scan_phases() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let default_db = Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("upstream/Detect-It-Easy/db");
    let db_dir = std::env::var("DIE_PROF_DB")
        .unwrap_or_else(|_| default_db.to_str().expect("utf-8 db path").to_string());

    let Some((file_name, data)) = profile_input() else {
        eprintln!("no profile input: set DIE_PROF_FILE or DIE_PROF_DIR");
        return;
    };
    eprintln!("input: {file_name} ({} bytes)", data.len());

    let t = Instant::now();
    let database = DatabaseBuilder::new(&db_dir).build().unwrap();
    let t_db_build = t.elapsed();

    let snapshot = database.snapshot();
    let file_type = "PE";
    let rules: Vec<_> = snapshot.rules_for_type(file_type).collect();
    let cancel = CancellationToken::new();
    let flags = ScanFlags::default();

    // ---- format detection (probe table build + probe_all) ----
    let t = Instant::now();
    let source = die_core::input::MemorySource::new(&data);
    let range = die_core::input::ByteRange::new(0, source.len()).unwrap();
    let view = die_core::input::ByteView::new(&source, range).unwrap();
    let table = die_formats::probe::ProbeTable::default_phase2();
    let t_probe_build = t.elapsed();
    let t = Instant::now();
    let (cands, _) = table.probe_all(&view);
    let t_probe = t.elapsed();
    eprintln!(
        "probe: build={:.3}ms all={:.3}ms candidates={:?}",
        t_probe_build.as_secs_f64() * 1e3,
        t_probe.as_secs_f64() * 1e3,
        cands
            .iter()
            .map(|c| c.file_type.name.as_str())
            .collect::<Vec<_>>()
    );
    // nested-PE gate runs on every scan
    let t = Instant::now();
    let is_pe = die_rules::pe_native::is_pe(&data);
    let t_ispe = t.elapsed();
    eprintln!(
        "gates: is_pe={} ({:.3}ms)",
        is_pe,
        t_ispe.as_secs_f64() * 1e3
    );

    // ---- per-scan fixed overhead (fresh runtime, as in scan_bytes) ----
    let t = Instant::now();
    let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
    let t_rt = t.elapsed();

    let t = Instant::now();
    let host = Arc::new(BufferHost::new(data.clone(), file_name.clone()).with_flags(flags));
    runtime.register_host_api(host.clone()).unwrap();
    let t_host = t.elapsed();

    let type_init: Vec<(String, String)> = snapshot
        .type_init_scripts
        .iter()
        .filter(|(ft, _)| ft == file_type)
        .cloned()
        .collect();
    let framework = die_rules::runtime::DatabaseSnapshot {
        rules: Vec::new(),
        init_script: snapshot.init_script.clone(),
        type_init_scripts: type_init,
        include_scripts: snapshot.include_scripts.clone(),
        bytecode: None,
    };
    let t = Instant::now();
    runtime.load_database(&framework).unwrap();
    let t_load = t.elapsed();

    let t = Instant::now();
    runtime.init(&*host).unwrap();
    let t_init = t.elapsed();

    let t = Instant::now();
    runtime.begin_result_group().unwrap();
    let t_group = t.elapsed();

    // ---- per-rule loop (compile + real execution) ----
    let mut sum_eval = std::time::Duration::ZERO;
    let mut errors = 0usize;
    let mut max_eval = std::time::Duration::ZERO;
    let mut max_rule = String::new();
    for rule in &rules {
        let t = Instant::now();
        let r = runtime.evaluate_loaded_rule_in_group(rule, &cancel);
        let d = t.elapsed();
        sum_eval += d;
        if d > max_eval {
            max_eval = d;
            max_rule = rule.path.clone();
        }
        if r.is_err() {
            errors += 1;
        }
    }

    let t = Instant::now();
    let results = runtime.read_results().unwrap();
    let t_read = t.elapsed();

    // ---- warm path: a second runtime reusing the process-wide shim
    // bytecode cache and the snapshot's framework bytecode ----
    let t = Instant::now();
    let mut runtime2 = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
    let t_rt2 = t.elapsed();
    let t = Instant::now();
    runtime2.register_host_api(host.clone()).unwrap();
    let t_host2 = t.elapsed();
    let t = Instant::now();
    runtime2.load_database(&framework).unwrap();
    let t_load2 = t.elapsed();
    let t = Instant::now();
    runtime2.init(&*host).unwrap();
    let t_init2 = t.elapsed();
    let t = Instant::now();
    runtime2.begin_result_group().unwrap();
    let mut sum_eval2 = std::time::Duration::ZERO;
    for rule in &rules {
        let t = Instant::now();
        let _ = runtime2.evaluate_loaded_rule_in_group(rule, &cancel);
        sum_eval2 += t.elapsed();
    }
    let t_loop2 = t.elapsed();
    let _ = t_loop2;

    // Runtime/context teardown cost (JSGC of the populated global scope).
    let t = Instant::now();
    drop(runtime);
    let t_drop1 = t.elapsed();
    let t = Instant::now();
    drop(runtime2);
    let t_drop2 = t.elapsed();

    let n = rules.len() as f64;
    eprintln!("=== profile_scan_phases ===");
    eprintln!("db: {db_dir}  {file_type} rules: {}", rules.len());
    eprintln!(
        "db_build(one-time): {:>9.3} ms",
        t_db_build.as_secs_f64() * 1e3
    );
    eprintln!("--- per-scan fixed ---");
    eprintln!("runtime_new:   {:>9.3} ms", t_rt.as_secs_f64() * 1e3);
    eprintln!("host_api:      {:>9.3} ms", t_host.as_secs_f64() * 1e3);
    eprintln!("load_database: {:>9.3} ms", t_load.as_secs_f64() * 1e3);
    eprintln!("init:          {:>9.3} ms", t_init.as_secs_f64() * 1e3);
    eprintln!("result_group:  {:>9.3} ms", t_group.as_secs_f64() * 1e3);
    eprintln!("--- per-rule (compile + real exec) ---");
    eprintln!(
        "rules total:   {:>9.1} ms, {:.3} ms/rule",
        sum_eval.as_secs_f64() * 1e3,
        sum_eval.as_secs_f64() * 1e3 / n
    );
    eprintln!(
        "slowest rule:  {:>9.3} ms ({})",
        max_eval.as_secs_f64() * 1e3,
        max_rule
    );
    eprintln!("read_results:  {:>9.3} ms", t_read.as_secs_f64() * 1e3);
    eprintln!("rule errors:   {errors}  results: {}", results.len());
    eprintln!("--- warm second runtime (all bytecode caches hot) ---");
    eprintln!("runtime_new2:  {:>9.3} ms", t_rt2.as_secs_f64() * 1e3);
    eprintln!("host_api2:     {:>9.3} ms", t_host2.as_secs_f64() * 1e3);
    eprintln!("load_db2:      {:>9.3} ms", t_load2.as_secs_f64() * 1e3);
    eprintln!("init2:         {:>9.3} ms", t_init2.as_secs_f64() * 1e3);
    eprintln!(
        "rules2 total:  {:>9.1} ms, {:.3} ms/rule",
        sum_eval2.as_secs_f64() * 1e3,
        sum_eval2.as_secs_f64() * 1e3 / n
    );
    eprintln!("rt_drop(loaded): {:>7.3} ms", t_drop1.as_secs_f64() * 1e3);
    eprintln!("rt_drop2:        {:>7.3} ms", t_drop2.as_secs_f64() * 1e3);
}

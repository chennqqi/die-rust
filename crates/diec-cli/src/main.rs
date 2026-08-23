//! `diec` is the thin CLI adapter binary.
//!
//! It owns arguments, file input, exit codes and terminal output. It depends
//! on `diec-engine` and `diec-output` and never copies core scan logic.

#![forbid(unsafe_code)]

use diec_core::cancel::CancellationToken;
use diec_engine::{
    DatabaseBuilder, ScanFlags, StructSelector, evaluate_struct_default, general_method_names,
    scan_once,
};
use std::process::ExitCode;

/// CLI exit codes (see docs/design/api.md section 16).
const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 2;
const EXIT_DATABASE: u8 = 3;
const EXIT_INPUT: u8 = 4;

fn print_usage() {
    eprintln!("Usage: diec [OPTIONS] <file>...");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --database, --db <path>   Database directory (default: ./db)");
    eprintln!("  --extradatabase, --extradb <path>");
    eprintln!("                            Extra database directory");
    eprintln!("  --customdatabase, --customdb <path>");
    eprintln!("                            Custom database directory");
    eprintln!("  --json                    Output as JSON");
    eprintln!("  --json-upstream           Output as upstream DIE-engine compatible JSON");
    eprintln!("  --xml                     Output as XML");
    eprintln!("  --csv                     Output as CSV");
    eprintln!("  --tsv                     Output as TSV");
    eprintln!("  --plaintext               Output as plain text");
    eprintln!(
        "  --output <format>         Output format: text, json, json-upstream, xml, csv, tsv, plaintext"
    );
    eprintln!(
        "  --recursivescan, -r       Enable intra-file recursive scan (PE resources + overlay)"
    );
    eprintln!("  --recursive-dir, -R       Recursively scan directories");
    eprintln!("  --archives                Extract and scan archive members (ZIP/7Z/RAR)");
    eprintln!("  --deepscan, -d            Enable deep scan mode");
    eprintln!("  --heuristicscan           Enable heuristic scan mode");
    eprintln!("  --verbose                 Enable verbose output");
    eprintln!("  --aggressivescan, -a      Enable aggressive scan mode");
    eprintln!("  --alltypes                Scan all format types");
    eprintln!("  --hideunknown             Hide unknown detections");
    eprintln!("  --no-dedup                Disable result deduplication (default: dedup on)");
    eprintln!("  --format                  Format the output result (spacing)");
    eprintln!("  --profiling               Profile signatures during scan");
    eprintln!("  --messages                Display scan messages and warnings");
    eprintln!("  --entropy                 Show entropy information");
    eprintln!("  --info                    Show file info");
    eprintln!("  --struct, -S <value>      Show structure info (e.g., Hash#MD5, Info, Entropy)");
    eprintln!("  --showdatabase            Show database paths and rule counts");
    eprintln!("  --showmethods, --showstructs");
    eprintln!("                            List available struct methods");
    eprintln!("  --version, -v             Print version and exit");
    eprintln!("  --help, -h                Print this help and exit");
}

/// Expand a target path: if it's a directory and `recursive` is true,
/// collect all files within it recursively. Otherwise return the path
/// as-is (if it's a file) or report an error (if it's a directory and
/// recursive is false).
fn expand_target(
    target: &str,
    recursive_dir: bool,
    files: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    let path = std::path::Path::new(target);
    if !path.exists() {
        errors.push(format!("path not found: {target}"));
        return;
    }
    if path.is_dir() {
        if !recursive_dir {
            errors.push(format!("is a directory (use --recursive-dir): {target}"));
            return;
        }
        collect_files(path, files);
    } else {
        files.push(target.to_string());
    }
}

/// Recursively collect all regular files under a directory.
fn collect_files(dir: &std::path::Path, files: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut sorted_entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    sorted_entries.sort_by_key(|e| e.path());
    for entry in sorted_entries {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, files);
        } else if path.is_file()
            && let Some(s) = path.to_str()
        {
            files.push(s.to_string());
        }
    }
}

/// Compute Shannon entropy of a byte buffer (0.0 to 8.0).
fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let mut db_path = String::new();
    let mut output_format = "text".to_string();
    let mut recursive_dir = false;
    let mut flags = ScanFlags::default();
    let mut format_result = false;
    let mut profiling = false;
    let mut messages = false;
    let mut entropy_mode = false;
    let mut info_mode = false;
    let mut struct_value: Option<String> = None;
    let mut extra_db_path = String::new();
    let mut custom_db_path = String::new();
    let mut show_database = false;
    let mut show_structs = false;
    let mut targets: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" | "-?" => {
                print_usage();
                return ExitCode::from(EXIT_OK);
            }
            "--version" | "-V" | "-v" => {
                println!("diec {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::from(EXIT_OK);
            }
            // -r/--recursivescan: intra-file recursive scanning (PE resources + overlay).
            // This matches upstream DIE-engine semantics. See ADR 0028.
            "--recursivescan" | "-r" => {
                flags.recursive = true;
            }
            // --recursive-dir/-R: directory-level recursion (replaces old -r directory behavior).
            "--recursive-dir" | "-R" | "--recursive" => {
                recursive_dir = true;
            }
            // --archives: extract and scan archive members (ZIP/7Z/RAR).
            "--archives" => {
                flags.archives = true;
            }
            "--deepscan" | "-d" => {
                flags.deep = true;
            }
            "--heuristicscan" => {
                flags.heuristic = true;
            }
            "--verbose" => {
                flags.verbose = true;
            }
            "--aggressivescan" | "-a" => {
                flags.aggressive = true;
            }
            "--alltypes" => {
                flags.all_types = true;
            }
            "--hideunknown" => {
                flags.hide_unknown = true;
            }
            "--no-dedup" => {
                flags.no_dedup = true;
            }
            "--format" => {
                format_result = true;
            }
            "--profiling" => {
                profiling = true;
            }
            "--messages" => {
                messages = true;
            }
            "--entropy" => {
                entropy_mode = true;
            }
            "--info" => {
                info_mode = true;
            }
            "--struct" | "-S" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --struct requires a value argument");
                    return ExitCode::from(EXIT_USAGE);
                }
                struct_value = Some(args[i].clone());
            }
            "--extradb" | "--extradatabase" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --extradb requires a path argument");
                    return ExitCode::from(EXIT_USAGE);
                }
                extra_db_path = args[i].clone();
            }
            "--customdb" | "--customdatabase" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --customdb requires a path argument");
                    return ExitCode::from(EXIT_USAGE);
                }
                custom_db_path = args[i].clone();
            }
            "--showdatabase" => {
                show_database = true;
            }
            "--showstructs" | "--showmethods" => {
                show_structs = true;
            }
            "--db" | "--database" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --db requires a path argument");
                    return ExitCode::from(EXIT_USAGE);
                }
                db_path = args[i].clone();
            }
            "--json" => {
                output_format = "json".to_string();
            }
            "--json-upstream" => {
                output_format = "json-upstream".to_string();
            }
            "--xml" => {
                output_format = "xml".to_string();
            }
            "--csv" => {
                output_format = "csv".to_string();
            }
            "--tsv" => {
                output_format = "tsv".to_string();
            }
            "--plaintext" => {
                output_format = "text".to_string();
            }
            "--output" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --output requires a format argument");
                    return ExitCode::from(EXIT_USAGE);
                }
                output_format = args[i].clone();
                if output_format == "plaintext" {
                    output_format = "text".to_string();
                }
                if !matches!(
                    output_format.as_str(),
                    "text" | "json" | "json-upstream" | "xml" | "csv" | "tsv"
                ) {
                    eprintln!("error: unsupported output format: {output_format}");
                    return ExitCode::from(EXIT_USAGE);
                }
            }
            s if s.starts_with("--") => {
                eprintln!("error: unknown option: {s}");
                return ExitCode::from(EXIT_USAGE);
            }
            s => {
                targets.push(s.to_string());
            }
        }
        i += 1;
    }

    if targets.is_empty() && !show_structs && !show_database {
        eprintln!("error: no input files specified");
        print_usage();
        return ExitCode::from(EXIT_USAGE);
    }

    // --showstructs: list available struct methods (no database or files needed).
    // Upstream outputs exactly 4 general methods (hardcoded FT_UNKNOWN).
    if show_structs {
        println!("Structures:");
        for m in general_method_names() {
            println!("\t{m}");
        }
        return ExitCode::from(EXIT_OK);
    }

    // Expand targets: directories are recursively scanned if --recursive.
    let mut files = Vec::new();
    let mut expand_errors = Vec::new();
    for target in &targets {
        expand_target(target, recursive_dir, &mut files, &mut expand_errors);
    }
    for err in &expand_errors {
        eprintln!("error: {err}");
    }
    if files.is_empty() && !show_database {
        eprintln!("error: no files to scan");
        return ExitCode::from(EXIT_INPUT);
    }

    // --entropy mode: compute and display file entropy, no rule database needed.
    if entropy_mode {
        for file in &files {
            let data = match std::fs::read(file) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: reading {file}: {e}");
                    continue;
                }
            };
            let entropy = compute_entropy(&data);
            match output_format.as_str() {
                "json" => {
                    println!(
                        "{{\"path\":\"{file}\",\"entropy\":{entropy:.6},\"size\":{}}}",
                        data.len()
                    );
                }
                _ => {
                    println!("{file}: entropy: {entropy:.6} ({})", data.len());
                }
            }
        }
        return ExitCode::from(EXIT_OK);
    }

    // --struct mode: display structure info, no rule database needed.
    // Priority: entropy > struct > info > normal scan.
    if let Some(ref raw) = struct_value
        && let Some(selector) = StructSelector::parse(raw)
    {
        for file in &files {
            let data = match std::fs::read(file) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: reading {file}: {e}");
                    continue;
                }
            };
            let node = evaluate_struct_default(&selector, file, &data);
            // Multi-target framing: print "<filename>:\n" before output.
            if files.len() > 1 {
                println!("{file}:");
            }
            match output_format.as_str() {
                "json" => {
                    if let Some(ref n) = node {
                        println!("{}", diec_output::render_struct_json(n));
                    } else {
                        println!("{{\"data\":\"\"}}");
                    }
                }
                "xml" => {
                    if let Some(ref n) = node {
                        print!("{}", diec_output::render_struct_xml(n));
                    }
                }
                "csv" => {
                    if let Some(ref n) = node {
                        print!("{}", diec_output::render_struct_csv(n));
                    }
                }
                "tsv" => {
                    if let Some(ref n) = node {
                        print!("{}", diec_output::render_struct_tsv(n));
                    }
                }
                _ => {
                    if let Some(ref n) = node {
                        print!("{}", diec_output::render_struct_text(n));
                    }
                }
            }
        }
        return ExitCode::from(EXIT_OK);
    }

    // --info mode: display file info, no rule database needed.
    if info_mode {
        for file in &files {
            let metadata = match std::fs::metadata(file) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("error: reading metadata {file}: {e}");
                    continue;
                }
            };
            let size = metadata.len();
            match output_format.as_str() {
                "json" => {
                    println!("{{\"path\":\"{file}\",\"size\":{size}}}");
                }
                _ => {
                    println!("{file}: size: {size}");
                }
            }
        }
        return ExitCode::from(EXIT_OK);
    }

    // Find the database directory.
    if db_path.is_empty() {
        // 1. DIEC_DB_PATH environment variable (highest priority).
        if let Ok(env_path) = std::env::var("DIEC_DB_PATH")
            && std::path::Path::new(&env_path).is_dir()
        {
            db_path = env_path;
        }

        // 2. db/ directory adjacent to the executable (release layout).
        if db_path.is_empty()
            && let Ok(exe) = std::env::current_exe()
            && let Some(exe_dir) = exe.parent()
        {
            let adjacent = exe_dir.join("db");
            if adjacent.is_dir() {
                db_path = adjacent.to_string_lossy().to_string();
            }
        }

        // 3. System-wide install paths.
        if db_path.is_empty() {
            let system_paths = [
                "/usr/share/diec/db",
                "/usr/local/share/diec/db",
                "/opt/diec/db",
            ];
            for c in &system_paths {
                if std::path::Path::new(c).is_dir() {
                    db_path = c.to_string();
                    break;
                }
            }
        }

        // 4. Development environment paths (lowest priority).
        if db_path.is_empty() {
            let candidates = [
                "upstream/Detect-It-Easy/db",
                "../upstream/Detect-It-Easy/db",
                "../../upstream/Detect-It-Easy/db",
                "db",
            ];
            for c in &candidates {
                if std::path::Path::new(c).is_dir() {
                    db_path = c.to_string();
                    break;
                }
            }
        }

        if db_path.is_empty() {
            eprintln!("error: database directory not found.");
            eprintln!("  Set DIEC_DB_PATH or use --db <path>");
            eprintln!("  Or place rules in a 'db/' directory next to the executable.");
            return ExitCode::from(EXIT_DATABASE);
        }
    }

    // Auto-discover db_extra/ and db_custom/ alongside the main db/ directory
    // if the user did not explicitly specify --extradb or --customdb.
    // This matches the upstream DIE-engine behavior where all three
    // directories are loaded together from the same data root.
    if extra_db_path.is_empty() {
        let db_parent = std::path::Path::new(&db_path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let auto_extra = db_parent.join("db_extra");
        if auto_extra.is_dir() {
            extra_db_path = auto_extra.to_string_lossy().to_string();
        }
    }
    if custom_db_path.is_empty() {
        let db_parent = std::path::Path::new(&db_path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let auto_custom = db_parent.join("db_custom");
        if auto_custom.is_dir() {
            custom_db_path = auto_custom.to_string_lossy().to_string();
        }
    }

    // Build the database (main + optional extra/custom databases).
    let mut builder = DatabaseBuilder::new(&db_path);
    if !extra_db_path.is_empty() {
        builder = builder.with_extra(&extra_db_path);
    }
    if !custom_db_path.is_empty() {
        builder = builder.with_extra(&custom_db_path);
    }
    let database = match builder.build() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("error: failed to load database from {db_path}: {e}");
            return ExitCode::from(EXIT_DATABASE);
        }
    };

    // --showdatabase: print database paths and per-type rule counts.
    if show_database {
        println!("Main database: {db_path}");
        if !extra_db_path.is_empty() {
            println!("Extra database: {extra_db_path}");
        }
        if !custom_db_path.is_empty() {
            println!("Custom database: {custom_db_path}");
        }
        // Count rules per file type.
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for rule in database.rules() {
            *counts.entry(rule.file_type.clone()).or_insert(0) += 1;
        }
        for (ft, count) in &counts {
            println!("\t{ft}: {count}");
        }
        return ExitCode::from(EXIT_OK);
    }

    let cancel = CancellationToken::new();
    let mut had_error = !expand_errors.is_empty();
    let mut results = Vec::new();

    let scan_start = std::time::Instant::now();
    for file in &files {
        match scan_once(&database, file, flags.clone(), &cancel) {
            Ok(result) => results.push(result),
            Err(e) => {
                eprintln!("error: scanning {file}: {e}");
                had_error = true;
            }
        }
    }
    let scan_elapsed = scan_start.elapsed();

    // --messages: print diagnostics to stderr.
    if messages {
        for r in &results {
            for diag in &r.diagnostics {
                eprintln!("{diag}");
            }
        }
    }

    // --profiling: print timing information to stderr.
    if profiling {
        eprintln!(
            "Scanned {} files in {:.3}s",
            results.len(),
            scan_elapsed.as_secs_f64()
        );
    }

    // Render output.
    match output_format.as_str() {
        "json" => {
            if results.len() == 1 {
                println!("{}", diec_output::render_json(&results[0]));
            } else {
                // Batch: wrap in array.
                print!("[");
                for (i, r) in results.iter().enumerate() {
                    if i > 0 {
                        print!(",");
                    }
                    print!("{}", diec_output::render_json(r));
                }
                println!("]");
            }
        }
        "json-upstream" => {
            // Upstream DIE-engine compatible JSON: array of detection objects.
            if results.len() == 1 {
                println!("{}", diec_output::render_json_upstream(&results[0]));
            } else {
                // Batch: concatenate arrays.
                print!("[");
                for (i, r) in results.iter().enumerate() {
                    if i > 0 {
                        print!(",");
                    }
                    // render_json_upstream returns an array without outer brackets;
                    // strip them to merge into the batch array.
                    let inner = diec_output::render_json_upstream(r);
                    let trimmed = inner
                        .strip_prefix('[')
                        .and_then(|s| s.strip_suffix(']'))
                        .unwrap_or(&inner);
                    print!("{}", trimmed);
                }
                println!("]");
            }
        }
        "xml" => {
            for r in &results {
                print!("{}", diec_output::render_xml(r));
            }
        }
        "csv" => {
            for r in &results {
                print!("{}", diec_output::render_csv(r));
            }
        }
        "tsv" => {
            for r in &results {
                print!("{}", diec_output::render_tsv(r));
            }
        }
        _ => {
            for r in &results {
                if format_result {
                    print!("{}", diec_output::render_text_formatted(r));
                } else {
                    print!("{}", diec_output::render_text(r));
                }
            }
        }
    }

    if had_error {
        ExitCode::from(EXIT_INPUT)
    } else {
        ExitCode::from(EXIT_OK)
    }
}

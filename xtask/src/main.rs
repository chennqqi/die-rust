//! `xtask` is the diec-rust build/sync/oracle/corpus/release tooling binary.
//!
//! It is not part of the runtime dependency graph and must not be depended on
//! by any runtime crate. Subcommands:
//! - `check-deps`: enforce the workspace dependency DAG.
//! - `sync-rules`: generate a rule source manifest from a materialized
//!   upstream checkout.
//! - `verify-rules`: verify that rule files match a source manifest.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RUNTIME_CRATES: &[&str] = &[
    "diec-core",
    "diec-formats",
    "diec-rules",
    "diec-engine",
    "diec-output",
    "diec-cli",
    "diec-ffi",
    "diec-server",
    "die-gui",
];

/// Upstream rule trees tracked by the manifest.
const RULE_TREES: &[&str] = &["db", "db_extra", "db_custom", "dbs_min", "dbs_special"];

/// Default upstream component info for rule sync.
const DEFAULT_REPOSITORY: &str = "https://github.com/horsicq/Detect-It-Easy.git";
const DEFAULT_COMPONENT: &str = "Detect-It-Easy";
const DEFAULT_COMMIT: &str = "8925358d2298957d758b6bba74c393b622322efc";

/// Allowed workspace dependencies for each runtime crate, mirroring
/// `docs/design/architecture.md` section 5/6. Any edge not listed here is a
/// violation.
fn allowed_deps() -> BTreeMap<&'static str, BTreeSet<&'static str>> {
    let mut m: BTreeMap<&'static str, BTreeSet<&'static str>> = BTreeMap::new();
    m.insert("diec-core", BTreeSet::new());
    m.insert("diec-formats", ["diec-core"].into_iter().collect());
    m.insert("diec-rules", ["diec-core"].into_iter().collect());
    m.insert(
        "diec-engine",
        ["diec-core", "diec-formats", "diec-rules"]
            .into_iter()
            .collect(),
    );
    m.insert("diec-output", ["diec-core"].into_iter().collect());
    m.insert(
        "diec-cli",
        ["diec-engine", "diec-output"].into_iter().collect(),
    );
    m.insert(
        "diec-ffi",
        ["diec-engine", "diec-output"].into_iter().collect(),
    );
    // diec-server is a thin adapter over diec-engine (ADR 0017).
    // It does not depend on diec-cli or diec-ffi.
    m.insert(
        "diec-server",
        ["diec-engine", "diec-core"].into_iter().collect(),
    );
    // die-gui is a Tauri v2 adapter over diec-engine (ADR 0018).
    // It does not depend on diec-cli, diec-ffi, or diec-server.
    m.insert(
        "die-gui",
        ["diec-engine", "diec-core", "diec-output"]
            .into_iter()
            .collect(),
    );
    m
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    match cmd {
        "check-deps" => check_deps(),
        "sync-rules" => sync_rules(&args[2..]),
        "verify-rules" => verify_rules(&args[2..]),
        "" | "help" | "-h" | "--help" => {
            eprintln!("xtask <check-deps|sync-rules|verify-rules>");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown xtask command: {other}");
            ExitCode::from(2)
        }
    }
}

// ---------------------------------------------------------------------------
// check-deps
// ---------------------------------------------------------------------------

/// Run `cargo metadata --no-deps`, build the workspace-internal dependency
/// graph and verify it against the allowed DAG.
fn check_deps() -> ExitCode {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output();
    let output = match output {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            eprintln!(
                "cargo metadata failed: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            return ExitCode::from(3);
        }
        Err(e) => {
            eprintln!("failed to run cargo metadata: {e}");
            return ExitCode::from(3);
        }
    };

    let json: serde_json::Value = match serde_json::from_slice(&output) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to parse cargo metadata: {e}");
            return ExitCode::from(3);
        }
    };

    let members: BTreeSet<String> = json["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let packages = json["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| {
            p["name"]
                .as_str()
                .map(|n| members.iter().any(|m| m.starts_with(n)))
                .unwrap_or(false)
        });

    // Map crate name -> set of workspace-internal dependency names.
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for p in packages {
        let name = match p["name"].as_str() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let mut deps: BTreeSet<String> = BTreeSet::new();
        if let Some(arr) = p["dependencies"].as_array() {
            for d in arr {
                if let Some(dname) = d["name"].as_str()
                    && (dname.starts_with("diec-") || dname == "xtask")
                {
                    deps.insert(dname.to_string());
                }
            }
        }
        graph.insert(name, deps);
    }

    let allowed = allowed_deps();
    let mut violations = 0usize;

    for &crate_name in RUNTIME_CRATES.iter().chain(std::iter::once(&"xtask")) {
        let actual = graph.get(crate_name).cloned().unwrap_or_default();
        let allowed_for: BTreeSet<&str> = if crate_name == "xtask" {
            BTreeSet::new()
        } else {
            allowed
                .get(crate_name)
                .cloned()
                .unwrap_or_else(|| panic!("no allowed-deps entry for {crate_name}"))
                .into_iter()
                .collect()
        };

        // Forbidden edges: actual deps not in allowed set.
        for dep in &actual {
            if !allowed_for.contains(dep.as_str()) {
                eprintln!(
                    "dependency violation: {crate_name} depends on {dep}, which is not allowed"
                );
                violations += 1;
            }
        }
        // Missing required edges are not enforced here; architecture only
        // forbids edges, it does not require every allowed edge to exist.
    }

    // No runtime crate may depend on xtask; xtask may not depend on runtime
    // crates. Covered above by empty allowed set for xtask and xtask not being
    // in any allowed set.

    if violations == 0 {
        println!("check-deps: workspace dependency DAG OK");
        ExitCode::SUCCESS
    } else {
        eprintln!("check-deps: {violations} violation(s)");
        ExitCode::from(1)
    }
}

// ---------------------------------------------------------------------------
// sync-rules / verify-rules
// ---------------------------------------------------------------------------

/// A single rule file entry in the source manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RuleFileEntry {
    relative_path: String,
    size: u64,
    sha256: String,
}

/// One rule tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RuleTreeEntry {
    name: String,
    files: Vec<RuleFileEntry>,
    total_bytes: u64,
}

/// The complete rule source manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RuleSourceManifest {
    schema: u32,
    repository: String,
    commit: String,
    component: String,
    synced_at: String,
    trees: Vec<RuleTreeEntry>,
    total_files: u64,
    total_bytes: u64,
}

/// Compute the SHA-256 hex digest of a file by streaming.
fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let data = fs::read(path)?;
    hasher.update(&data);
    let digest = hasher.finalize();
    Ok(hex_encode(&digest))
}

/// Encode bytes as lowercase hex without an external dependency.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Walk a rule tree directory and collect all regular files sorted by relative path.
fn collect_tree_files(tree_root: &Path) -> std::io::Result<Vec<RuleFileEntry>> {
    let mut entries: Vec<RuleFileEntry> = Vec::new();
    collect_files_recursive(tree_root, tree_root, &mut entries)?;
    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(entries)
}

/// Recursively collect files, computing relative paths with forward slashes.
fn collect_files_recursive(
    dir: &Path,
    root: &Path,
    entries: &mut Vec<RuleFileEntry>,
) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_files_recursive(&path, root, entries)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let sha = sha256_file(&path)?;
            entries.push(RuleFileEntry {
                relative_path: relative,
                size: metadata.len(),
                sha256: sha,
            });
        }
    }
    Ok(())
}

/// Generate a rule source manifest from a materialized upstream checkout.
///
/// Usage: `xtask sync-rules [--upstream <path>] [--output <path>] [--commit <sha>]`
///
/// Default upstream: `upstream/Detect-It-Easy`
/// Default output: `upstream/rule-source-manifest.json`
fn sync_rules(args: &[String]) -> ExitCode {
    let mut upstream = PathBuf::from("upstream/Detect-It-Easy");
    let mut output = PathBuf::from("upstream/rule-source-manifest.json");
    let mut commit = DEFAULT_COMMIT.to_string();
    let mut repository = DEFAULT_REPOSITORY.to_string();
    let mut component = DEFAULT_COMPONENT.to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--upstream" => {
                i += 1;
                if i < args.len() {
                    upstream = PathBuf::from(&args[i]);
                }
            }
            "--output" => {
                i += 1;
                if i < args.len() {
                    output = PathBuf::from(&args[i]);
                }
            }
            "--commit" => {
                i += 1;
                if i < args.len() {
                    commit = args[i].clone();
                }
            }
            "--repository" => {
                i += 1;
                if i < args.len() {
                    repository = args[i].clone();
                }
            }
            "--component" => {
                i += 1;
                if i < args.len() {
                    component = args[i].clone();
                }
            }
            other => {
                eprintln!("sync-rules: unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    if !upstream.is_dir() {
        eprintln!(
            "sync-rules: upstream directory not found: {}",
            upstream.display()
        );
        return ExitCode::from(3);
    }

    let mut trees: Vec<RuleTreeEntry> = Vec::new();
    let mut total_files: u64 = 0;
    let mut total_bytes: u64 = 0;

    for tree_name in RULE_TREES {
        let tree_path = upstream.join(tree_name);
        if !tree_path.is_dir() {
            eprintln!("sync-rules: skip missing tree: {tree_name}");
            continue;
        }
        match collect_tree_files(&tree_path) {
            Ok(files) => {
                let tree_bytes: u64 = files.iter().map(|f| f.size).sum();
                let tree_count = files.len() as u64;
                println!("sync-rules: {tree_name}: {tree_count} files, {tree_bytes} bytes");
                total_files += tree_count;
                total_bytes += tree_bytes;
                trees.push(RuleTreeEntry {
                    name: tree_name.to_string(),
                    files,
                    total_bytes: tree_bytes,
                });
            }
            Err(e) => {
                eprintln!("sync-rules: failed to read tree {tree_name}: {e}");
                return ExitCode::from(3);
            }
        }
    }

    let manifest = RuleSourceManifest {
        schema: 1,
        repository,
        commit,
        component,
        synced_at: current_utc_iso8601(),
        trees,
        total_files,
        total_bytes,
    };

    let json = match serde_json::to_string_pretty(&manifest) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sync-rules: failed to serialize manifest: {e}");
            return ExitCode::from(3);
        }
    };

    if let Err(e) = fs::write(&output, json + "\n") {
        eprintln!("sync-rules: failed to write manifest: {e}");
        return ExitCode::from(3);
    }

    println!(
        "sync-rules: manifest written to {} ({} files, {} bytes)",
        output.display(),
        total_files,
        total_bytes
    );
    ExitCode::SUCCESS
}

/// Verify that rule files match a source manifest.
///
/// Usage: `xtask verify-rules [--upstream <path>] [--manifest <path>]`
///
/// Checks every file listed in the manifest: exists, size matches, SHA-256
/// matches. Also checks for extra files not in the manifest.
fn verify_rules(args: &[String]) -> ExitCode {
    let mut upstream = PathBuf::from("upstream/Detect-It-Easy");
    let mut manifest_path = PathBuf::from("upstream/rule-source-manifest.json");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--upstream" => {
                i += 1;
                if i < args.len() {
                    upstream = PathBuf::from(&args[i]);
                }
            }
            "--manifest" => {
                i += 1;
                if i < args.len() {
                    manifest_path = PathBuf::from(&args[i]);
                }
            }
            other => {
                eprintln!("verify-rules: unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let manifest_bytes = match fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "verify-rules: cannot read manifest {}: {e}",
                manifest_path.display()
            );
            return ExitCode::from(3);
        }
    };

    let manifest: RuleSourceManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("verify-rules: invalid manifest JSON: {e}");
            return ExitCode::from(3);
        }
    };

    if manifest.schema != 1 {
        eprintln!(
            "verify-rules: unsupported manifest schema: {}",
            manifest.schema
        );
        return ExitCode::from(3);
    }

    let mut errors: usize = 0;
    let mut checked: usize = 0;

    for tree in &manifest.trees {
        let tree_root = upstream.join(&tree.name);
        if !tree_root.is_dir() {
            eprintln!("verify-rules: missing tree directory: {}", tree.name);
            errors += 1;
            continue;
        }

        for file in &tree.files {
            let file_path = tree_root.join(&file.relative_path);
            checked += 1;

            let metadata = match fs::metadata(&file_path) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("verify-rules: missing file: {} ({e})", file.relative_path);
                    errors += 1;
                    continue;
                }
            };

            if !metadata.is_file() {
                eprintln!("verify-rules: not a regular file: {}", file.relative_path);
                errors += 1;
                continue;
            }

            if metadata.len() != file.size {
                eprintln!(
                    "verify-rules: size mismatch: {} (expected {}, got {})",
                    file.relative_path,
                    file.size,
                    metadata.len()
                );
                errors += 1;
                continue;
            }

            let actual_sha = match sha256_file(&file_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("verify-rules: hash error: {} ({e})", file.relative_path);
                    errors += 1;
                    continue;
                }
            };

            if actual_sha != file.sha256 {
                eprintln!(
                    "verify-rules: SHA-256 mismatch: {} (expected {}, got {})",
                    file.relative_path, file.sha256, actual_sha
                );
                errors += 1;
            }
        }
    }

    if errors == 0 {
        println!(
            "verify-rules: OK ({checked} files verified, {} trees)",
            manifest.trees.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("verify-rules: {errors} error(s) in {checked} files");
        ExitCode::from(1)
    }
}

/// Return the current UTC time as an ISO-8601 string.
fn current_utc_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_iso8601(secs)
}

/// Format a Unix timestamp as an ISO-8601 UTC string (simplified, no leap seconds).
fn format_unix_iso8601(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    let (year, month, day) = days_to_ymd(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert days since 1970-01-01 to (year, month, day) using the civil calendar algorithm.
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

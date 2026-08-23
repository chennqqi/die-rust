//! Database loading and snapshot management.
//!
//! The database is built from a directory of `.sg` rule files and
//! framework scripts. After building, it is immutable and can be
//! shared across scans via `Arc<Database>`.

use diec_rules::runtime::{DatabaseSnapshot, LoadedRule};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Error type for database operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseError {
    /// The database directory does not exist or is not a directory.
    NotFound {
        /// The path that was not found.
        path: String,
    },
    /// An I/O error occurred while reading a file.
    IoError {
        /// The file path that could not be read.
        path: String,
        /// The I/O error detail.
        detail: String,
    },
    /// The database directory contains no rules.
    Empty,
}

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseError::NotFound { path } => {
                write!(f, "database directory not found: {path}")
            }
            DatabaseError::IoError { path, detail } => {
                write!(f, "I/O error reading {path}: {detail}")
            }
            DatabaseError::Empty => write!(f, "database directory contains no rules"),
        }
    }
}

impl std::error::Error for DatabaseError {}

/// Builder for constructing a `Database` from rule directories.
#[derive(Debug, Clone, Default)]
pub struct DatabaseBuilder {
    db_paths: Vec<PathBuf>,
}

impl DatabaseBuilder {
    /// Create a new builder pointing at the given database directory.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            db_paths: vec![path.into()],
        }
    }

    /// Add an extra database directory (e.g. db_extra, db_custom).
    /// Rules from all directories are merged together.
    pub fn with_extra(mut self, path: impl Into<PathBuf>) -> Self {
        self.db_paths.push(path.into());
        self
    }

    /// Build the immutable `Database` by reading and parsing all rules.
    pub fn build(self) -> Result<Database, DatabaseError> {
        if self.db_paths.is_empty() || self.db_paths[0].as_os_str().is_empty() {
            return Err(DatabaseError::NotFound {
                path: "(empty path)".into(),
            });
        }
        let main_path = &self.db_paths[0];
        if !main_path.is_dir() {
            return Err(DatabaseError::NotFound {
                path: main_path.display().to_string(),
            });
        }

        // Collect rules from each format-type subdirectory.
        // This must match the upstream Detect-It-Easy db/ directory layout.
        let format_types = [
            "Binary",
            "PE",
            "ELF",
            "MACH",
            "MACHOFAT",
            "APK",
            "Archive",
            "CFBF",
            "COM",
            "DEX",
            "DOS16M",
            "DOS4G",
            "Amiga",
            "AtariST",
            "IPA",
            "ISO9660",
            "JAR",
            "JavaClass",
            "JPEG",
            "LE",
            "LX",
            "MSDOS",
            "NE",
            "NPM",
            "PDF",
            "PNG",
            "PYC",
            "RAR",
            "ZIP",
            "Image",
        ];

        // Phase 1: collect all .sg file paths and metadata sequentially
        // (directory traversal is cheap; file reads are the bottleneck).
        struct RuleFile {
            path: PathBuf,
            file_type: &'static str,
            file_name: String,
        }
        let mut rule_files: Vec<RuleFile> = Vec::new();
        for db_path in &self.db_paths {
            if !db_path.is_dir() {
                continue;
            }
            for ft in &format_types {
                let ft_dir = db_path.join(ft);
                if !ft_dir.is_dir() {
                    continue;
                }
                if let Ok(entries) = std::fs::read_dir(&ft_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) == Some("sg") {
                            let name = path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("?")
                                .to_string();
                            rule_files.push(RuleFile {
                                path,
                                file_type: ft,
                                file_name: name,
                            });
                        }
                    }
                }
            }
        }

        if rule_files.is_empty() {
            return Err(DatabaseError::Empty);
        }

        // Phase 2: read file contents in parallel using scoped threads.
        // Each thread reads a chunk of files and returns the results.
        // This avoids unsafe code while parallelizing the I/O bottleneck.
        let file_count = rule_files.len();
        let contents: Vec<Result<String, DatabaseError>> = {
            let paths: Vec<&Path> = rule_files.iter().map(|rf| rf.path.as_path()).collect();
            std::thread::scope(|s| {
                let num_threads = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
                    .min(file_count);
                let chunk_size = file_count.div_ceil(num_threads);
                let handles: Vec<_> = paths
                    .chunks(chunk_size)
                    .map(|chunk| {
                        s.spawn(move || {
                            chunk
                                .iter()
                                .map(|&path| {
                                    std::fs::read_to_string(path).map_err(|e| {
                                        DatabaseError::IoError {
                                            path: path.display().to_string(),
                                            detail: e.to_string(),
                                        }
                                    })
                                })
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().unwrap())
                    .collect()
            })
        };

        // Phase 3: assemble LoadedRule structs in order.
        // TODO: sort rules using upstream's sort_signature_prio logic.
        let mut rules: Vec<LoadedRule> = Vec::with_capacity(file_count);
        for (i, rf) in rule_files.iter().enumerate() {
            let source = match &contents[i] {
                Ok(s) => s.clone(),
                Err(e) => return Err(e.clone()),
            };
            rules.push(LoadedRule {
                path: format!("{}/{}", rf.file_type, rf.file_name),
                ordinal: i as u64,
                file_type: rf.file_type.to_string(),
                source,
            });
        }

        // Load the global _init script from the main database.
        let init_script = std::fs::read_to_string(main_path.join("_init")).ok();

        // Load all include scripts from all databases (main first, then extras).
        let mut include_scripts: BTreeMap<String, String> = BTreeMap::new();
        for db_path in &self.db_paths {
            if db_path.is_dir() {
                load_include_scripts(db_path, &mut include_scripts);
            }
        }

        // Load type-specific _init scripts from all databases.
        let mut type_init_scripts: BTreeMap<String, String> = BTreeMap::new();
        for db_path in &self.db_paths {
            if !db_path.is_dir() {
                continue;
            }
            for ft in &format_types {
                let init_path = db_path.join(ft).join("_init");
                if type_init_scripts.contains_key(*ft) {
                    continue;
                }
                if let Ok(source) = std::fs::read_to_string(&init_path) {
                    type_init_scripts.insert(ft.to_string(), source);
                }
            }
        }
        let type_init_scripts: Vec<(String, String)> = type_init_scripts.into_iter().collect();

        let db_path = self.db_paths.into_iter().next().unwrap_or_default();

        // Load version info from rule-source-manifest.json if it exists
        // alongside the database directory (ADR 0017).
        let version = load_version_from_manifest(&db_path, rules.len());

        Ok(Database {
            snapshot: DatabaseSnapshot {
                rules,
                init_script,
                type_init_scripts,
                include_scripts,
            },
            db_path,
            version,
        })
    }
}

/// Try to load `DatabaseVersion` from `rule-source-manifest.json`.
///
/// The manifest is expected at the parent of the db directory (e.g.
/// `upstream/rule-source-manifest.json` when db is at
/// `upstream/Detect-It-Easy/db`). Falls back to `DatabaseVersion::unknown`
/// if the manifest is not found or cannot be parsed.
fn load_version_from_manifest(db_path: &Path, rule_count: usize) -> Option<DatabaseVersion> {
    // Look for rule-source-manifest.json in several candidate locations:
    // 1. The db directory itself
    // 2. The parent of the db directory (e.g. upstream/Detect-It-Easy/)
    // 3. The grandparent (e.g. upstream/)
    let candidates: Vec<PathBuf> = [
        Some(db_path.join("rule-source-manifest.json")),
        db_path
            .parent()
            .map(|p| p.join("rule-source-manifest.json")),
        db_path
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("rule-source-manifest.json")),
    ]
    .into_iter()
    .flatten()
    .collect();

    let manifest_path = candidates.into_iter().find(|p| p.is_file())?;

    let content = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(_) => return None,
    };

    // Minimal JSON parsing without serde dependency: extract commit and
    // synced_at fields. This avoids adding serde as a dependency to
    // diec-engine just for manifest parsing.
    let commit = extract_json_string(&content, "commit").unwrap_or_else(|| "unknown".to_string());
    let synced_at =
        extract_json_string(&content, "synced_at").unwrap_or_else(|| "unknown".to_string());

    Some(DatabaseVersion {
        commit,
        rule_count,
        synced_at,
    })
}

/// Extract a string value for a key from a JSON object (minimal parser).
///
/// Handles simple `"key": "value"` patterns. Returns the first match.
/// This is sufficient for the manifest format which has flat top-level
/// string fields.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let pos = json.find(&pattern)?;
    let after_key = &json[pos + pattern.len()..];
    // Skip whitespace and colon.
    let after_colon = after_key.trim_start();
    let after_colon = after_colon.strip_prefix(':')?;
    let after_colon = after_colon.trim_start();
    // Expect a string value.
    let after_quote = after_colon.strip_prefix('"')?;
    let end = after_quote.find('"')?;
    Some(after_quote[..end].to_string())
}

/// Recursively load include scripts from the database root.
fn load_include_scripts(db: &Path, includes: &mut BTreeMap<String, String>) {
    // Load files at the root level (no extension).
    if let Ok(entries) = std::fs::read_dir(db) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && path.extension().is_none()
                && let Some(name) = path.file_name().and_then(|n| n.to_str())
                && let Ok(source) = std::fs::read_to_string(&path)
            {
                includes.insert(name.to_string(), source);
            }
        }
    }

    // Load files in subdirectories: db/<dir>/<dir> and db/<dir>/<other>.
    if let Ok(entries) = std::fs::read_dir(db) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir()
                && let Some(dir_name) = path.file_name().and_then(|n| n.to_str())
            {
                // db/<dir>/<dir> file.
                let inner = path.join(dir_name);
                if inner.is_file()
                    && !includes.contains_key(dir_name)
                    && let Ok(source) = std::fs::read_to_string(&inner)
                {
                    includes.insert(dir_name.to_string(), source);
                }
                // Other files in the subdirectory.
                if let Ok(sub_entries) = std::fs::read_dir(&path) {
                    for sub_entry in sub_entries.flatten() {
                        let sub_path = sub_entry.path();
                        if sub_path.is_file()
                            && sub_path.extension().is_none()
                            && let Some(name) = sub_path.file_name().and_then(|n| n.to_str())
                            && !includes.contains_key(name)
                            && let Ok(source) = std::fs::read_to_string(&sub_path)
                        {
                            includes.insert(name.to_string(), source);
                        }
                    }
                }
            }
        }
    }
}

/// An immutable, reusable database of rules and framework scripts.
#[derive(Debug, Clone)]
pub struct Database {
    /// The loaded database snapshot.
    pub snapshot: DatabaseSnapshot,
    /// The path the database was loaded from.
    pub db_path: PathBuf,
    /// Optional version info loaded from `rule-source-manifest.json`.
    version: Option<DatabaseVersion>,
}

/// Database version information for service responses (ADR 0017).
///
/// Loaded from `rule-source-manifest.json` if present alongside the
/// database directory. Falls back to `rule_count` with `"unknown"`
/// commit/synced_at when the manifest is not available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseVersion {
    /// Upstream commit SHA (40-hex lowercase), or `"unknown"`.
    pub commit: String,
    /// Number of rules loaded in this database.
    pub rule_count: usize,
    /// ISO-8601 sync timestamp (UTC), or `"unknown"`.
    pub synced_at: String,
}

impl DatabaseVersion {
    /// Create a version with `"unknown"` commit and synced_at.
    pub fn unknown(rule_count: usize) -> Self {
        Self {
            commit: "unknown".to_string(),
            rule_count,
            synced_at: "unknown".to_string(),
        }
    }
}

impl Database {
    /// Get a reference to the database snapshot.
    pub fn snapshot(&self) -> &DatabaseSnapshot {
        &self.snapshot
    }

    /// Get the number of rules in the database.
    pub fn rule_count(&self) -> usize {
        self.snapshot.rules.len()
    }

    /// Get an iterator over the loaded rules.
    pub fn rules(&self) -> &[LoadedRule] {
        &self.snapshot.rules
    }

    /// Get the database version information (ADR 0017).
    ///
    /// Returns the version loaded from `rule-source-manifest.json` if
    /// available, otherwise a fallback with `"unknown"` commit/synced_at
    /// and the actual rule count.
    pub fn version(&self) -> DatabaseVersion {
        self.version
            .clone()
            .unwrap_or_else(|| DatabaseVersion::unknown(self.rule_count()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_version_unknown_has_correct_defaults() {
        let v = DatabaseVersion::unknown(42);
        assert_eq!(v.commit, "unknown");
        assert_eq!(v.rule_count, 42);
        assert_eq!(v.synced_at, "unknown");
    }

    #[test]
    fn extract_json_string_finds_value() {
        let json = r#"{"commit": "abc123", "synced_at": "2026-07-31"}"#;
        assert_eq!(
            extract_json_string(json, "commit"),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_json_string(json, "synced_at"),
            Some("2026-07-31".to_string())
        );
    }

    #[test]
    fn extract_json_string_returns_none_for_missing_key() {
        let json = r#"{"commit": "abc123"}"#;
        assert_eq!(extract_json_string(json, "missing"), None);
    }

    #[test]
    fn extract_json_string_handles_whitespace() {
        let json = r#"{ "commit" : "abc123" }"#;
        assert_eq!(
            extract_json_string(json, "commit"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn database_version_loads_from_manifest() {
        let db_path = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .ok()
            .and_then(|p| p.parent().and_then(|p| p.parent()).map(|p| p.to_path_buf()))
            .expect("workspace root");
        let db_dir = db_path.join("upstream/Detect-It-Easy/db");
        if !db_dir.is_dir() {
            eprintln!("Skipping: upstream database not found");
            return;
        }
        let database = DatabaseBuilder::new(&db_dir)
            .build()
            .expect("build should succeed");
        let version = database.version();
        // If manifest exists, commit should not be "unknown".
        let manifest_exists = db_path.join("upstream/rule-source-manifest.json").is_file();
        if manifest_exists {
            assert_ne!(
                version.commit, "unknown",
                "commit should be loaded from manifest"
            );
            assert_ne!(
                version.synced_at, "unknown",
                "synced_at should be loaded from manifest"
            );
        }
        assert!(version.rule_count > 0, "rule_count should be positive");
    }
}

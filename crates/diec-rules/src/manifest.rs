//! Rule source manifest and integrity verification types.
//!
//! The manifest records the upstream origin (repository, commit, path) and
//! per-file SHA-256 of every synced rule asset. Rule source files are never
//! formatted or hand-corrected; the manifest is the trust anchor for
//! differential testing and cache key derivation.
//!
//! See `docs/design/architecture.md` section 9: "加载清单记录上游路径、commit、
//! 文件哈希和同步时间".

/// Schema version of the rule source manifest format.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// A single rule file entry in the source manifest.
///
/// `relative_path` is forward-slash separated and relative to the rule tree
/// root (e.g. `db/Binary/ELF.1.sg`). `sha256` is the lowercase hex digest of
/// the file's raw bytes at sync time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFileEntry {
    /// Forward-slash path relative to the rule tree root.
    pub relative_path: String,
    /// File size in bytes.
    pub size: u64,
    /// Lowercase SHA-256 hex digest of the file's raw bytes.
    pub sha256: String,
}

/// One rule tree (e.g. `db`, `db_extra`, `db_custom`, `dbs_min`, `dbs_special`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTreeEntry {
    /// Tree name, matching the upstream directory name (e.g. `db`).
    pub name: String,
    /// Files in this tree, sorted by relative_path.
    pub files: Vec<RuleFileEntry>,
    /// Total byte count across all files.
    pub total_bytes: u64,
}

/// The complete rule source manifest.
///
/// Records the upstream origin and per-file hashes for all synced rule trees.
/// This is the trust anchor: cache keys bind to the manifest's content
/// identity, not just file count or total size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSourceManifest {
    /// Manifest schema version.
    pub schema: u32,
    /// Upstream repository URL.
    pub repository: String,
    /// Upstream commit SHA (40-hex lowercase).
    pub commit: String,
    /// Upstream component name (e.g. `Detect-It-Easy`).
    pub component: String,
    /// ISO-8601 sync timestamp (UTC).
    pub synced_at: String,
    /// Rule trees included in this manifest.
    pub trees: Vec<RuleTreeEntry>,
    /// Total file count across all trees.
    pub total_files: u64,
    /// Total byte count across all trees.
    pub total_bytes: u64,
}

impl RuleSourceManifest {
    /// Create a new manifest with the given upstream origin and empty trees.
    pub fn new(
        repository: impl Into<String>,
        commit: impl Into<String>,
        component: impl Into<String>,
        synced_at: impl Into<String>,
    ) -> Self {
        Self {
            schema: MANIFEST_SCHEMA_VERSION,
            repository: repository.into(),
            commit: commit.into(),
            component: component.into(),
            synced_at: synced_at.into(),
            trees: Vec::new(),
            total_files: 0,
            total_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_schema_version_is_stable() {
        assert_eq!(MANIFEST_SCHEMA_VERSION, 1);
    }

    #[test]
    fn new_manifest_has_empty_trees() {
        let manifest = RuleSourceManifest::new(
            "https://github.com/horsicq/Detect-It-Easy.git",
            "8925358d2298957d758b6bba74c393b622322efc",
            "Detect-It-Easy",
            "2026-07-31T00:00:00Z",
        );
        assert_eq!(manifest.schema, 1);
        assert!(manifest.trees.is_empty());
        assert_eq!(manifest.total_files, 0);
        assert_eq!(manifest.total_bytes, 0);
    }
}

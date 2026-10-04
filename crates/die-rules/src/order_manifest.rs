//! Pinned rule order manifest (ADR 0008).
//!
//! The upstream `sort_signature_prio()` comparator is non-transitive. The
//! product runtime must not implement or call it. Instead, the database
//! build phase generates a versioned order manifest with explicit execution
//! ordinals. The runtime only iterates by ordinal and independently applies
//! file type, signature/path, deep/heuristic, database enable and cancel
//! filters.
//!
//! See `docs/design/decisions/0008-pinned-rule-order-manifest.md`.

use std::collections::BTreeMap;

/// Schema version of the pinned order manifest format.
pub const ORDER_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// A single entry in the pinned rule order manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderEntry {
    /// Relative path of the rule file (e.g. "db/Binary/ELF.1.sg").
    pub path: String,
    /// Execution ordinal (0-based, monotonically increasing within a file type).
    pub ordinal: u64,
    /// File type this rule targets (e.g. "Binary", "PE", "ELF").
    pub file_type: String,
    /// Rule layer: "main", "extra", or "custom".
    pub layer: RuleLayer,
}

/// Which rule database layer an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleLayer {
    /// Main database (`db`).
    Main,
    /// Extra database (`db_extra`).
    Extra,
    /// Custom database (`db_custom`).
    Custom,
}

impl RuleLayer {
    /// String representation matching the upstream directory name.
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleLayer::Main => "main",
            RuleLayer::Extra => "extra",
            RuleLayer::Custom => "custom",
        }
    }
}

/// The complete pinned rule order manifest.
///
/// Records the execution order for all rules across all file types and
/// layers. This is the trust anchor for runtime execution order: the runtime
/// must not re-sort rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderManifest {
    /// Manifest schema version.
    pub schema: u32,
    /// Upstream commit SHA this manifest was generated from.
    pub upstream_commit: String,
    /// Platform this manifest was collected on (e.g. "windows-x64").
    pub platform: String,
    /// All order entries, sorted by (file_type, ordinal).
    pub entries: Vec<OrderEntry>,
}

impl OrderManifest {
    /// Create a new empty manifest.
    pub fn new(upstream_commit: impl Into<String>, platform: impl Into<String>) -> Self {
        Self {
            schema: ORDER_MANIFEST_SCHEMA_VERSION,
            upstream_commit: upstream_commit.into(),
            platform: platform.into(),
            entries: Vec::new(),
        }
    }

    /// Number of entries in the manifest.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the manifest is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get entries for a specific file type, sorted by ordinal.
    pub fn entries_for_type(&self, file_type: &str) -> Vec<&OrderEntry> {
        let mut result: Vec<&OrderEntry> = self
            .entries
            .iter()
            .filter(|e| e.file_type == file_type)
            .collect();
        result.sort_by_key(|e| e.ordinal);
        result
    }

    /// Get all file types present in the manifest.
    pub fn file_types(&self) -> Vec<String> {
        let mut types: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.file_type.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        types.sort();
        types
    }

    /// Validate that all ordinals are unique within each file type.
    ///
    /// Returns `Err` with the first duplicate found, or `Ok(())`.
    pub fn validate_unique_ordinals(&self) -> Result<(), String> {
        let mut seen: BTreeMap<(String, u64), &OrderEntry> = BTreeMap::new();
        for entry in &self.entries {
            let key = (entry.file_type.clone(), entry.ordinal);
            if let Some(existing) = seen.get(&key) {
                return Err(format!(
                    "duplicate ordinal {} for file type '{}': '{}' and '{}'",
                    entry.ordinal, entry.file_type, existing.path, entry.path
                ));
            }
            seen.insert(key, entry);
        }
        Ok(())
    }

    /// Validate that ordinals are contiguous (0..N-1) within each file type.
    ///
    /// Returns `Err` with the first gap found, or `Ok(())`.
    pub fn validate_contiguous_ordinals(&self) -> Result<(), String> {
        let file_types = self.file_types();
        for ft in file_types {
            let entries = self.entries_for_type(&ft);
            for (i, entry) in entries.iter().enumerate() {
                if entry.ordinal != i as u64 {
                    return Err(format!(
                        "non-contiguous ordinal for file type '{}': expected {}, got {} at path '{}'",
                        ft, i, entry.ordinal, entry.path
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_manifest() {
        let m = OrderManifest::new("abc123", "windows-x64");
        assert_eq!(m.schema, ORDER_MANIFEST_SCHEMA_VERSION);
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn entries_for_type() {
        let m = OrderManifest {
            schema: 1,
            upstream_commit: "abc".into(),
            platform: "windows-x64".into(),
            entries: vec![
                OrderEntry {
                    path: "db/Binary/a.sg".into(),
                    ordinal: 0,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
                OrderEntry {
                    path: "db/PE/b.sg".into(),
                    ordinal: 0,
                    file_type: "PE".into(),
                    layer: RuleLayer::Main,
                },
                OrderEntry {
                    path: "db/Binary/c.sg".into(),
                    ordinal: 1,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
            ],
        };

        let binary = m.entries_for_type("Binary");
        assert_eq!(binary.len(), 2);
        assert_eq!(binary[0].path, "db/Binary/a.sg");
        assert_eq!(binary[1].path, "db/Binary/c.sg");

        let pe = m.entries_for_type("PE");
        assert_eq!(pe.len(), 1);
    }

    #[test]
    fn file_types_sorted() {
        let m = OrderManifest {
            schema: 1,
            upstream_commit: "abc".into(),
            platform: "windows-x64".into(),
            entries: vec![
                OrderEntry {
                    path: "a.sg".into(),
                    ordinal: 0,
                    file_type: "PE".into(),
                    layer: RuleLayer::Main,
                },
                OrderEntry {
                    path: "b.sg".into(),
                    ordinal: 0,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
                OrderEntry {
                    path: "c.sg".into(),
                    ordinal: 0,
                    file_type: "ELF".into(),
                    layer: RuleLayer::Main,
                },
            ],
        };
        assert_eq!(m.file_types(), vec!["Binary", "ELF", "PE"]);
    }

    #[test]
    fn validate_unique_ordinals_ok() {
        let m = OrderManifest {
            schema: 1,
            upstream_commit: "abc".into(),
            platform: "windows-x64".into(),
            entries: vec![
                OrderEntry {
                    path: "a.sg".into(),
                    ordinal: 0,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
                OrderEntry {
                    path: "b.sg".into(),
                    ordinal: 1,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
            ],
        };
        assert!(m.validate_unique_ordinals().is_ok());
    }

    #[test]
    fn validate_unique_ordinals_detects_duplicate() {
        let m = OrderManifest {
            schema: 1,
            upstream_commit: "abc".into(),
            platform: "windows-x64".into(),
            entries: vec![
                OrderEntry {
                    path: "a.sg".into(),
                    ordinal: 0,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
                OrderEntry {
                    path: "b.sg".into(),
                    ordinal: 0,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
            ],
        };
        let err = m.validate_unique_ordinals().unwrap_err();
        assert!(err.contains("duplicate ordinal"));
    }

    #[test]
    fn validate_contiguous_ordinals_ok() {
        let m = OrderManifest {
            schema: 1,
            upstream_commit: "abc".into(),
            platform: "windows-x64".into(),
            entries: vec![
                OrderEntry {
                    path: "a.sg".into(),
                    ordinal: 0,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
                OrderEntry {
                    path: "b.sg".into(),
                    ordinal: 1,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
                OrderEntry {
                    path: "c.sg".into(),
                    ordinal: 2,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
            ],
        };
        assert!(m.validate_contiguous_ordinals().is_ok());
    }

    #[test]
    fn validate_contiguous_ordinals_detects_gap() {
        let m = OrderManifest {
            schema: 1,
            upstream_commit: "abc".into(),
            platform: "windows-x64".into(),
            entries: vec![
                OrderEntry {
                    path: "a.sg".into(),
                    ordinal: 0,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
                OrderEntry {
                    path: "b.sg".into(),
                    ordinal: 2, // gap: missing ordinal 1
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
            ],
        };
        let err = m.validate_contiguous_ordinals().unwrap_err();
        assert!(err.contains("non-contiguous"));
    }

    #[test]
    fn rule_layer_as_str() {
        assert_eq!(RuleLayer::Main.as_str(), "main");
        assert_eq!(RuleLayer::Extra.as_str(), "extra");
        assert_eq!(RuleLayer::Custom.as_str(), "custom");
    }

    #[test]
    fn same_ordinal_different_file_types_ok() {
        let m = OrderManifest {
            schema: 1,
            upstream_commit: "abc".into(),
            platform: "windows-x64".into(),
            entries: vec![
                OrderEntry {
                    path: "a.sg".into(),
                    ordinal: 0,
                    file_type: "Binary".into(),
                    layer: RuleLayer::Main,
                },
                OrderEntry {
                    path: "b.sg".into(),
                    ordinal: 0,
                    file_type: "PE".into(),
                    layer: RuleLayer::Main,
                },
            ],
        };
        assert!(m.validate_unique_ordinals().is_ok());
        assert!(m.validate_contiguous_ordinals().is_ok());
    }
}

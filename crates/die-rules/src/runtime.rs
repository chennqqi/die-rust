//! Rule runtime port.
//!
//! `RuleRuntime` is the interface through which the engine loads, initializes
//! and executes rule scripts. It is defined here in `die-rules` and
//! implemented by a private backend (rquickjs/QuickJS-NG per ADR 0006).
//!
//! The runtime lifecycle follows the upstream DIE pattern:
//! 1. `load_database` — load all rule files into the runtime.
//! 2. `init` — execute the global `_init` script and type-specific init scripts.
//! 3. `evaluate_rule` — execute a single rule's `detect()` function.
//! 4. `collect_results` — gather detection results set by `_setResult`.
//!
//! See `docs/design/architecture.md` section 9: "`RuleRuntime` 的生命周期必须
//! 表达上游所需的 init、include、单规则求值、函数抽取、取消和预算".

use crate::budget::RuleBudgetProfile;
use crate::error::RuleError;
use crate::host_api::HostApi;
use die_core::cancel::CancellationToken;

/// A single detection result produced by a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionResult {
    /// Detection type (e.g. "info", "packer", "compiler", "installer").
    pub type_name: String,
    /// Detected name (e.g. "UPX", "Microsoft Visual C++").
    pub name: String,
    /// Version string, if detected.
    pub version: String,
    /// Options string, if detected.
    pub options: String,
    /// Detected language, if any.
    pub lang: String,
    /// Language version, if any.
    pub lang_version: String,
    /// Optional unique identifier for nested tree building.
    pub id: Option<String>,
    /// Optional parent detection id for nested results.
    pub parent_id: Option<String>,
    /// Optional file part where the detection originated.
    pub file_part: Option<String>,
    /// Optional offset of the detected region.
    pub offset: Option<u64>,
    /// Optional size of the detected region.
    pub size: Option<u64>,
    /// Optional heuristic detection marker.
    pub is_heuristic: Option<bool>,
    /// Optional A-Heuristic detection marker.
    pub is_a_heuristic: Option<bool>,
    /// Optional original name for archive/container entries.
    pub original_name: Option<String>,
    /// Path of the rule that produced this result. Populated when results
    /// accumulate across a rule group (upstream `m_pListScanStructs`
    /// semantics); empty for single-rule evaluations that did not stamp it.
    pub rule_path: String,
}

/// A loaded rule ready for execution.
#[derive(Debug, Clone)]
pub struct LoadedRule {
    /// Relative path of the rule file (e.g. "db/Binary/ELF.1.sg").
    pub path: String,
    /// Execution ordinal (from the pinned order manifest, ADR 0008).
    pub ordinal: u64,
    /// File type this rule targets (e.g. "Binary", "PE", "ELF").
    pub file_type: String,
    /// The raw script source text.
    pub source: String,
    /// Precompiled QuickJS bytecode of the wrapped rule program
    /// (`const`-preprocessed source in the per-rule IIFE), produced once
    /// at database build by `precompile_snapshot`. `None` means the rule
    /// is evaluated from source as before (e.g. when compilation failed
    /// during the build so the eval-time diagnostic is preserved).
    /// The image is only valid for the vendored QuickJS build that
    /// produced it and is never persisted or deserialized from external
    /// input.
    pub bytecode: Option<std::sync::Arc<[u8]>>,
}

/// Immutable database snapshot loaded into the runtime.
///
/// Contains all loaded rules in execution order. Once created, the snapshot
/// is not modified during a scan. See architecture.md section 9:
/// "数据库完成校验后形成 immutable snapshot".
#[derive(Debug, Clone)]
pub struct DatabaseSnapshot {
    /// All loaded rules, sorted by execution ordinal.
    pub rules: Vec<LoadedRule>,
    /// The global `_init` script source, if present.
    pub init_script: Option<String>,
    /// Type-specific init scripts (e.g. "PE" -> init source).
    pub type_init_scripts: Vec<(String, String)>,
    /// Include script registry: script name -> source text.
    ///
    /// These are the shared helper scripts that rules include via
    /// `includeScript("name")`. They are loaded into the runtime
    /// and made available for runtime include evaluation.
    pub include_scripts: std::collections::BTreeMap<String, String>,
    /// Precompiled QuickJS bytecode for the framework scripts eagerly
    /// evaluated by `load_database`/`init` (`_init`, type init, and the
    /// `read` include). `None` means every script runs from source.
    /// Populated by `precompile_snapshot` at database build.
    pub bytecode: Option<SnapshotBytecode>,
}

/// Precompiled QuickJS bytecode for a snapshot's framework scripts.
///
/// Each image was produced by compiling the corresponding script source
/// with `JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_COMPILE_ONLY` and is
/// executed via `JS_ReadObject` + `JS_EvalFunction`, which is
/// observably identical to the previous sloppy `eval` (same `this`,
/// same pending-exception behavior).
#[derive(Debug, Clone, Default)]
pub struct SnapshotBytecode {
    /// Compiled `_init` program (corresponds to `init_script`).
    pub init: Option<std::sync::Arc<[u8]>>,
    /// Compiled type-init programs keyed by type name (e.g. "PE").
    pub type_init: std::collections::BTreeMap<String, std::sync::Arc<[u8]>>,
    /// Compiled `include_scripts["read"]` image; `includeScript` still
    /// resolves by source — this only covers the eager `read` preload
    /// in `load_database`.
    pub read: Option<std::sync::Arc<[u8]>>,
}

impl DatabaseSnapshot {
    /// Create an empty snapshot.
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            init_script: None,
            type_init_scripts: Vec::new(),
            include_scripts: std::collections::BTreeMap::new(),
            bytecode: None,
        }
    }

    /// Number of rules in the snapshot.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Iterate rules targeting the given file type.
    pub fn rules_for_type(&self, file_type: &str) -> impl Iterator<Item = &LoadedRule> {
        self.rules.iter().filter(move |r| r.file_type == file_type)
    }
}

/// Rule runtime port.
///
/// Implementations load rule scripts, execute them against host data, and
/// collect detection results. The runtime must enforce resource budgets
/// (ADR 0006) and include cycle detection (ADR 0010).
///
/// The runtime is NOT required to be `Send`. Per ADR 0006, each scan uses
/// a shared runtime/context owned by a single worker thread; cross-thread
/// communication uses only cancel/deadline tokens, not live JS handles.
pub trait RuleRuntime {
    /// Load a database snapshot into the runtime.
    ///
    /// This parses and compiles all rule scripts. Unknown syntax produces
    /// `RuleError::UnsupportedSyntax` — never silently skipped.
    fn load_database(&mut self, snapshot: &DatabaseSnapshot) -> Result<(), RuleError>;

    /// Initialize the runtime by executing the global and type-specific
    /// init scripts.
    fn init(&mut self, host: &dyn HostApi) -> Result<(), RuleError>;

    /// Evaluate a single rule against the host data.
    ///
    /// Returns the detection results produced by this rule (if any).
    /// The runtime must enforce the configured budget and cancel token.
    fn evaluate_rule(
        &mut self,
        rule: &LoadedRule,
        host: &dyn HostApi,
        cancel: &CancellationToken,
    ) -> Result<Vec<DetectionResult>, RuleError>;

    /// Shut down the runtime and release all resources.
    fn shutdown(&mut self);
}

/// Configuration for creating a rule runtime instance.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Resource budget profile.
    pub budget: RuleBudgetProfile,
    /// Whether to enable the legacy high-resource profile.
    pub legacy_mode: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            budget: RuleBudgetProfile::MODERN,
            legacy_mode: false,
        }
    }
}

impl RuntimeConfig {
    /// Create a configuration with the legacy high-resource profile.
    pub fn legacy() -> Self {
        Self {
            budget: RuleBudgetProfile::LEGACY_HIGH_RESOURCE,
            legacy_mode: true,
        }
    }
}

/// A factory that creates rule runtime instances.
///
/// This allows the engine to create runtime instances without depending
/// on a specific backend. The backend (rquickjs) implements this trait
/// in a private module.
pub trait RuleRuntimeFactory: Send + Sync {
    /// Create a new rule runtime with the given configuration.
    fn create(&self, config: RuntimeConfig) -> Result<Box<dyn RuleRuntime>, RuleError>;
}

/// A no-op runtime factory for testing.
///
/// Returns a runtime that always produces empty results. Useful for
/// engine integration tests before the real backend is connected.
pub struct NullRuntimeFactory;

impl RuleRuntimeFactory for NullRuntimeFactory {
    fn create(&self, config: RuntimeConfig) -> Result<Box<dyn RuleRuntime>, RuleError> {
        Ok(Box::new(NullRuntime { _config: config }))
    }
}

/// A no-op runtime that produces no detections.
pub struct NullRuntime {
    _config: RuntimeConfig,
}

impl RuleRuntime for NullRuntime {
    fn load_database(&mut self, _snapshot: &DatabaseSnapshot) -> Result<(), RuleError> {
        Ok(())
    }

    fn init(&mut self, _host: &dyn HostApi) -> Result<(), RuleError> {
        Ok(())
    }

    fn evaluate_rule(
        &mut self,
        _rule: &LoadedRule,
        _host: &dyn HostApi,
        _cancel: &CancellationToken,
    ) -> Result<Vec<DetectionResult>, RuleError> {
        Ok(Vec::new())
    }

    fn shutdown(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot() {
        let snap = DatabaseSnapshot::empty();
        assert!(snap.is_empty());
        assert_eq!(snap.len(), 0);
    }

    #[test]
    fn snapshot_rules_for_type() {
        let snap = DatabaseSnapshot {
            rules: vec![
                LoadedRule {
                    path: "db/Binary/a.sg".into(),
                    ordinal: 0,
                    file_type: "Binary".into(),
                    source: "".into(),
                    bytecode: None,
                },
                LoadedRule {
                    path: "db/PE/b.sg".into(),
                    ordinal: 1,
                    file_type: "PE".into(),
                    source: "".into(),
                    bytecode: None,
                },
                LoadedRule {
                    path: "db/Binary/c.sg".into(),
                    ordinal: 2,
                    file_type: "Binary".into(),
                    source: "".into(),
                    bytecode: None,
                },
            ],
            init_script: None,
            type_init_scripts: Vec::new(),
            include_scripts: std::collections::BTreeMap::new(),
            bytecode: None,
        };
        let binary_rules: Vec<_> = snap.rules_for_type("Binary").collect();
        assert_eq!(binary_rules.len(), 2);
        assert_eq!(binary_rules[0].path, "db/Binary/a.sg");
        assert_eq!(binary_rules[1].path, "db/Binary/c.sg");

        let pe_rules: Vec<_> = snap.rules_for_type("PE").collect();
        assert_eq!(pe_rules.len(), 1);
    }

    #[test]
    fn null_runtime_factory_creates_runtime() {
        let factory = NullRuntimeFactory;
        let mut runtime = factory.create(RuntimeConfig::default()).unwrap();
        let snap = DatabaseSnapshot::empty();
        runtime.load_database(&snap).unwrap();
    }

    #[test]
    fn runtime_config_default_is_modern() {
        let config = RuntimeConfig::default();
        assert!(!config.legacy_mode);
        assert_eq!(config.budget, RuleBudgetProfile::MODERN);
    }

    #[test]
    fn runtime_config_legacy_uses_legacy_profile() {
        let config = RuntimeConfig::legacy();
        assert!(config.legacy_mode);
        assert_eq!(config.budget, RuleBudgetProfile::LEGACY_HIGH_RESOURCE);
    }

    #[test]
    fn detection_result_fields() {
        let r = DetectionResult {
            type_name: "packer".into(),
            name: "UPX".into(),
            version: "3.96".into(),
            options: "".into(),
            lang: "".into(),
            lang_version: "".into(),
            id: None,
            parent_id: None,
            file_part: None,
            offset: None,
            size: None,
            is_heuristic: None,
            is_a_heuristic: None,
            original_name: None,
            rule_path: String::new(),
        };
        assert_eq!(r.type_name, "packer");
        assert_eq!(r.name, "UPX");
        assert_eq!(r.version, "3.96");
    }
}

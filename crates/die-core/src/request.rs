//! Scan request, mode and option types.
//!
//! `ScanRequest::default()` uses safe, documented, versioned project defaults
//! and never reads environment variables. Upstream flag-to-field mapping is
//! performed explicitly by the CLI adapter. The typed API allows exactly one
//! `ScanMode` per request to avoid contradictory combinations. See
//! `docs/design/api.md` sections 7.

use crate::limits::ScanLimits;

/// The scan mode dispatched by the engine. Legacy CLI mode dispatch keeps the
/// `entropy > struct > info > detect` priority; the typed API picks one mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanMode {
    /// Default detection mode.
    Detect,
    /// Per-symbol entropy accumulation and `>= 6.5` packed判定.
    Entropy,
    /// File info/structure dump.
    Info,
    /// Struct section dump with a selector.
    Struct(StructSelector),
}

/// Legacy-compatible struct selector. The legacy parser is case-insensitive,
/// tolerates trailing section wildcards and falls back to detect on empty
/// input; the canonical typed constructor may reject ambiguous selectors but
/// must map the difference explicitly in the legacy adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructSelector {
    /// Raw selector string preserved as supplied for legacy compatibility.
    pub raw: String,
}

impl StructSelector {
    /// Construct a selector from a raw string.
    pub fn new(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }
}

/// Detection behaviour options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DetectionOptions {
    /// Deep scan.
    pub deep: bool,
    /// Heuristic detections.
    pub heuristic: bool,
    /// Aggressive mode raises compatibility thresholds only; it never disables
    /// hard safety limits.
    pub aggressive: bool,
    /// Probe all format types instead of a single preferred type.
    pub all_types: bool,
    /// Emit format display.
    pub format_display: bool,
    /// Hide unknown detections.
    pub hide_unknown: bool,
}

/// Nesting options. Upstream `--recursivescan` maps to `resources + overlays`
/// and does not imply directory enumeration; archives are an independent
/// engine capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NestingOptions {
    /// Descend into PE/ELF/etc. resources.
    pub resources: bool,
    /// Descend into overlays.
    pub overlays: bool,
    /// Descend into archive entries.
    pub archives: bool,
}

/// Diagnostic emission options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiagnosticOptions {
    /// Emit verbose diagnostics.
    pub verbose: bool,
    /// Emit script/runtime diagnostics.
    pub script: bool,
}

/// A typed scan request. All source entry points share the same checked input
/// and scan service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest {
    /// Scan mode.
    pub mode: ScanMode,
    /// Detection options.
    pub detection: DetectionOptions,
    /// Nesting options.
    pub nesting: NestingOptions,
    /// Resource limits.
    pub limits: ScanLimits,
    /// Diagnostic options.
    pub diagnostics: DiagnosticOptions,
}

impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            mode: ScanMode::Detect,
            detection: DetectionOptions::default(),
            nesting: NestingOptions::default(),
            limits: ScanLimits::default(),
            diagnostics: DiagnosticOptions::default(),
        }
    }
}

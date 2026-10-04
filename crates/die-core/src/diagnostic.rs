//! Diagnostics, severity, diagnostic codes and scan stages.
//!
//! `max_diagnostics` counts typed diagnostic facts produced by the core, not
//! CLI text lines, JSON object counts or FFI view calls. Reaching the limit
//! never silently truncates: no `limit+1` item is created and `Completion`
//! carries a `LimitReached` that does not occupy a diagnostic slot. See
//! `docs/design/api.md` sections 8 and 12.

use crate::input::ByteRange;
use crate::node::{NodeId, RuleIdentity};

/// Diagnostic severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Informational.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
}

/// The scan stage where a diagnostic or termination was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStage {
    /// Request/option validation.
    RequestValidation,
    /// Database build/load.
    Database,
    /// Format probing.
    Probe,
    /// Format parsing.
    Parse,
    /// Rule runtime execution.
    Rule,
    /// Nested scan work queue processing.
    Nested,
    /// Output rendering.
    Output,
}

/// A stable diagnostic code used for programmatic classification. Message text
/// is for display only and is not guaranteed byte-stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticCode {
    /// Unknown rule syntax (must not be silently ignored).
    UnknownSyntax,
    /// Rule parse error.
    ParseError,
    /// Include failure.
    IncludeFailure,
    /// Host API error.
    HostApiError,
    /// Runtime exception.
    RuntimeException,
    /// Unsupported format or feature.
    Unsupported,
    /// Malformed input recovered at a node.
    MalformedInput,
    /// Database conflict.
    DatabaseConflict,
    /// I/O issue at a node.
    Io,
    /// Other diagnostic.
    Other(String),
}

/// A stable identifier referring to a diagnostic within a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiagnosticId(pub u32);

/// A typed diagnostic fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Severity.
    pub severity: Severity,
    /// Diagnostic code.
    pub code: DiagnosticCode,
    /// Scan stage.
    pub stage: ScanStage,
    /// Owning node, if any.
    pub node: Option<NodeId>,
    /// Byte range, if any.
    pub byte_range: Option<ByteRange>,
    /// Rule that produced the diagnostic, if any.
    pub rule: Option<RuleIdentity>,
    /// Human-readable message (display only, not byte-stable).
    pub message: String,
}

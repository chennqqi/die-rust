//! Typed error classification.
//!
//! Public error codes/variants are the programmatic decision basis; messages
//! are for display and are not guaranteed byte-stable. Errors preserve a
//! source chain but canonical JSON must not leak native absolute paths,
//! memory addresses or platform-sensitive debug data unless the caller
//! explicitly opts in and marks it non-stable. Malformed or unknown files are
//! not top-level errors: if a safe scan completed, a `Complete` report with
//! unknown detections or parser diagnostics is returned. See
//! `docs/design/api.md` section 12.

use core::fmt;

use crate::input::IoError;
use crate::limits::LimitReached;

/// Database build/load error classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseError {
    /// No database found at the requested location.
    NotFound,
    /// The database is empty.
    Empty,
    /// An archive source is invalid.
    InvalidArchive,
    /// A manifest or content hash mismatch.
    HashMismatch,
    /// An unknown syntax, parse or include failure (must not be silently ignored).
    RuleLoad(String),
    /// A literal include cycle.
    IncludeCycle(String),
    /// A database conflict.
    Conflict(String),
    /// Another database error.
    Other(String),
}

/// Unsupported format or feature error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedError {
    /// What is unsupported.
    pub feature: String,
}

/// Context recorded when a scan is terminated by cancel or timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationContext {
    /// The scan stage where termination was observed.
    pub stage: crate::diagnostic::ScanStage,
    /// Optional node where termination was observed.
    pub node: Option<crate::node::NodeId>,
}

/// Script/runtime failure classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptError {
    /// A script parse error.
    Parse(String),
    /// A runtime exception.
    Runtime(String),
    /// A host API failure.
    HostApi(String),
}

/// Internal invariant failure or panic boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalError {
    /// Internal detail (not exposed in canonical JSON by default).
    pub detail: String,
}

/// The unified scan error type. Maps to C ABI status codes per
/// `docs/design/api.md` section 12.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// Invalid request field or argument.
    InvalidRequest {
        /// The invalid field name.
        field: &'static str,
        /// The reason.
        reason: String,
    },
    /// Input/path I/O error.
    Io(IoError),
    /// Database build/init error.
    Database(DatabaseError),
    /// Unsupported feature or syntax.
    Unsupported(UnsupportedError),
    /// A hard limit was reached with no usable report.
    LimitExceeded(LimitReached),
    /// Cancellation was requested.
    Cancelled(TerminationContext),
    /// The deadline was reached.
    Timeout(TerminationContext),
    /// A scan-level script failure.
    Script(ScriptError),
    /// An allocation failed.
    AllocationFailed,
    /// An internal invariant failure or panic boundary.
    Internal(InternalError),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::InvalidRequest { field, reason } => {
                write!(f, "invalid request field `{field}`: {reason}")
            }
            ScanError::Io(e) => write!(f, "io error: {e}"),
            ScanError::Database(e) => write!(f, "database error: {e:?}"),
            ScanError::Unsupported(u) => write!(f, "unsupported: {}", u.feature),
            ScanError::LimitExceeded(l) => {
                write!(
                    f,
                    "limit exceeded: {:?} ({}/{})",
                    l.kind, l.observed, l.configured
                )
            }
            ScanError::Cancelled(_) => f.write_str("cancelled"),
            ScanError::Timeout(_) => f.write_str("timeout"),
            ScanError::Script(e) => write!(f, "script error: {e:?}"),
            ScanError::AllocationFailed => f.write_str("allocation failed"),
            ScanError::Internal(e) => write!(f, "internal error: {}", e.detail),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<IoError> for ScanError {
    fn from(e: IoError) -> Self {
        ScanError::Io(e)
    }
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatabaseError::NotFound => f.write_str("database not found"),
            DatabaseError::Empty => f.write_str("database empty"),
            DatabaseError::InvalidArchive => f.write_str("invalid database archive"),
            DatabaseError::HashMismatch => f.write_str("database hash mismatch"),
            DatabaseError::RuleLoad(m) => write!(f, "rule load error: {m}"),
            DatabaseError::IncludeCycle(m) => write!(f, "include cycle: {m}"),
            DatabaseError::Conflict(m) => write!(f, "database conflict: {m}"),
            DatabaseError::Other(m) => write!(f, "database error: {m}"),
        }
    }
}

impl std::error::Error for DatabaseError {}

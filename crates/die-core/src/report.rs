//! Scan report envelope, completion status, metadata and resource usage.
//!
//! Returning `Ok(report)` means the report is self-consistent and
//! serializable, not that every rule hit or that no node diagnostic exists.
//! `Completion::Limited` is only for deterministic boundaries (e.g. the first
//! N ordered entries completed and the N+1 would exceed a node/entry/depth/
//! decompressed cap). Cancel/timeout return `Err` with no report. See
//! `docs/design/api.md` section 10.

use crate::diagnostic::Diagnostic;
use crate::limits::LimitReached;
use crate::node::NodeId;
use crate::node::ScanNode;
use crate::request::ScanRequest;

/// Canonical result schema version, independent from crate semver, C ABI
/// version, database/manifest/cache version and the pinned upstream commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaVersion {
    /// Major version: field semantic changes or removals.
    pub major: u32,
    /// Minor version: additive, backward-compatible fields.
    pub minor: u32,
}

impl SchemaVersion {
    /// The initial skeleton schema version. Still Draft until the JSON Schema
    /// and golden corpus in `testing.md` are established.
    pub const SKELETON: SchemaVersion = SchemaVersion { major: 0, minor: 1 };
}

/// Engine metadata embedded in a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineMetadata {
    /// Engine name.
    pub name: String,
    /// Engine version string.
    pub version: String,
}

/// Database identity carried by a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseIdentity {
    /// Engine version recorded in the database manifest.
    pub engine_version: String,
    /// Pinned DIE-engine upstream commit.
    pub upstream_commit: String,
    /// Pinned Detect-It-Easy rule commit.
    pub rule_commit: String,
    /// Manifest SHA-256.
    pub manifest_sha256: String,
}

/// The effective request after option normalization, recorded for
/// reproducibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveRequest {
    /// The normalized scan request.
    pub request: ScanRequest,
}

/// Input metadata captured after opening the root source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputMetadata {
    /// Stable logical length in bytes.
    pub logical_length: u64,
    /// Display name, if any.
    pub display_name: Option<String>,
    /// Logical path, if any.
    pub logical_path: Option<String>,
}

/// Completion status of a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// The scan completed within all limits.
    Complete,
    /// The scan completed a deterministic prefix and stopped at a hard limit.
    Limited {
        /// The limit that was reached.
        reason: LimitReached,
    },
}

/// Resource usage observed during a scan. Profiling/timing fields, if added to
/// canonical JSON, go in a clearly marked non-canonical extension that is off
/// by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceUsage {
    /// Number of result nodes produced.
    pub nodes: u64,
    /// Number of typed diagnostics produced.
    pub diagnostics: u64,
    /// Cumulative bytes read.
    pub bytes_read: u64,
    /// Cumulative bytes decompressed.
    pub bytes_decompressed: u64,
}

/// The complete, deterministic, traceable tree result of a single scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    /// Canonical schema version.
    pub schema_version: SchemaVersion,
    /// Engine metadata.
    pub engine: EngineMetadata,
    /// Database identity.
    pub database: DatabaseIdentity,
    /// Effective request.
    pub request: EffectiveRequest,
    /// Input metadata.
    pub input: InputMetadata,
    /// Completion status.
    pub completion: Completion,
    /// All scan nodes.
    pub nodes: Vec<ScanNode>,
    /// Root node id.
    pub root: NodeId,
    /// Top-level diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// Resource usage.
    pub usage: ResourceUsage,
}

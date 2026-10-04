//! Scan tree nodes, detections and provenance.
//!
//! `NodeId` is valid only within its owning report and never serializes a
//! memory address or random UUID. Parent/children links must stay consistent
//! and children are ordered by discovery ordinal. Offset/size relative to the
//! root versus the parent view are distinguished by field names, not by
//! overloading a single field. Detections preserve upstream original spelling
//! and display (e.g. `Complier` is not auto-corrected). See
//! `docs/design/api.md` section 11.

use crate::diagnostic::DiagnosticId;
use crate::format::{FilePart, FileType, FormatCandidate};
use crate::input::ByteRange;

/// A stable node identifier valid only within its owning `ScanReport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u32);

/// The kind of detection. Upstream distinguishes compiler/linker/packer/etc.
/// and unknown; `Unknown` is an explicit detection representation, not a
/// missing field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionKind {
    /// A normal detection.
    Normal,
    /// A heuristic detection.
    Heuristic,
    /// An explicit unknown detection (subject to `hide_unknown`).
    Unknown,
}

/// Stable rule identity. Preserves source path, database layer and a stable
/// rule id/hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleIdentity {
    /// Source path within the database source.
    pub source_path: String,
    /// Database layer (main/extra/custom).
    pub layer: String,
    /// Stable rule hash or id.
    pub rule_id: String,
}

/// How a node's bytes originated. Provenance is independent of `FilePart`;
/// a nested-overlay's file-part and overlay offset/size must be separately
/// expressible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceKind {
    /// The root input.
    Root,
    /// A resource child.
    Resource,
    /// An overlay child.
    Overlay,
    /// An archive entry child.
    ArchiveEntry,
    /// A debug-data child.
    DebugData,
}

/// Provenance describing where a node's bytes came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The provenance kind.
    pub kind: ProvenanceKind,
    /// The parent-relative byte range, when applicable.
    pub parent_range: Option<ByteRange>,
    /// The root-relative byte range, when applicable.
    pub root_range: Option<ByteRange>,
    /// Optional transform information (decompression, extraction).
    pub transform: Option<String>,
}

/// A single detection attached to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// The file type the detection applies to.
    pub file_type: FileType,
    /// The detection kind.
    pub kind: DetectionKind,
    /// The detection name (upstream original spelling preserved).
    pub name: String,
    /// Optional version string.
    pub version: Option<String>,
    /// Optional info string.
    pub info: Option<String>,
    /// The display string rendered in output.
    pub display: String,
    /// The rule that produced the detection, if any.
    pub rule: Option<RuleIdentity>,
    /// Whether this detection is heuristic.
    pub heuristic: bool,
}

/// A node in the scan result tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanNode {
    /// This node's id.
    pub id: NodeId,
    /// Parent node id, `None` for the root.
    pub parent: Option<NodeId>,
    /// Discovery ordinal among siblings.
    pub child_ordinal: u32,
    /// The semantic file part.
    pub part: FilePart,
    /// Provenance of this node's bytes.
    pub provenance: Provenance,
    /// Byte range covered by this node.
    pub range: ByteRange,
    /// Format probe candidates.
    pub format_candidates: Vec<FormatCandidate>,
    /// Detections produced for this node.
    pub detections: Vec<Detection>,
    /// Diagnostics attached to this node.
    pub diagnostics: Vec<DiagnosticId>,
    /// Child node ids, ordered by discovery ordinal.
    pub children: Vec<NodeId>,
}

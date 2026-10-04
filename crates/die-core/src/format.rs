//! Format identity, probe candidates and file-part classification.
//!
//! Format candidates and rule detections are distinct sets. `FilePart` can
//! express root, resource, debug-data, overlay, stream/archive entry and
//! unknown; being able to express a part does not mean it is scheduled by
//! default (legacy-compatible recursive dispatch only schedules
//! resource/overlay). See `docs/design/api.md` section 11 and
//! `docs/design/architecture.md` section 8.

/// The file type identity used in detections and format candidates. The
/// spelling preserves upstream display strings and is not auto-corrected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileType {
    /// Upstream display name, e.g. `PE32`, `ELF64`, `Binary`.
    pub name: String,
}

impl FileType {
    /// Construct a file type from a display name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Probe match strength. Format probing is driven by an explicit, versioned
/// ordered table; a candidate reports whether it matches and how strongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatStrength {
    /// The probe did not match.
    None,
    /// A weak/primary magic match that may be superseded.
    Weak,
    /// A strong, validated match.
    Strong,
}

/// A format probe candidate attached to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatCandidate {
    /// The detected file type.
    pub file_type: FileType,
    /// Match strength.
    pub strength: FormatStrength,
    /// Whether expensive parsing is deferred.
    pub deferred_parse: bool,
}

/// The semantic role of a byte region within a scan tree. `Resource` keeps the
/// upstream type id `24` as the string scan id `"24"` so original rules such
/// as `win_resources.1.sg` resolve correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilePart {
    /// The root input.
    Root,
    /// A PE/ELF/etc. resource. `scan_id` carries the upstream resource type id
    /// as a string (e.g. `"24"` for manifests).
    Resource {
        /// Upstream resource type id as a string (e.g. `"24"` for manifests).
        scan_id: String,
    },
    /// Debug data (representable but not scheduled by default legacy scans).
    DebugData,
    /// An overlay region.
    Overlay,
    /// A stream or archive entry.
    Entry,
    /// An unknown part.
    Unknown,
}

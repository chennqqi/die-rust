//! `die-core` is the innermost crate of the die-rust workspace.
//!
//! It owns the checked input model, the unified public value model, the typed
//! error and diagnostic classification, the resource limit contracts, the
//! cancellation token and the result arena types. Every inner consumer
//! (`die-formats`, `die-rules`, `die-engine`, `die-output`) depends on
//! this crate; it must not depend on any of them, on CLI/FFI layers or on GUI
//! frameworks (see `docs/design/architecture.md` section 6).
//!
//! The types in this crate are the first frozen internal result model. The
//! public C ABI remains experimental and is owned by `die-ffi`. Field names
//! and type shapes follow `docs/design/api.md`; concrete constructors that
//! enforce invariants are added as implementation progresses, so the public
//! fields here are a design scaffold and not a bypassable stable contract yet.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cancel;
pub mod diagnostic;
pub mod error;
pub mod format;
pub mod input;
pub mod limits;
pub mod node;
pub mod report;
pub mod request;
pub mod signature;

pub use cancel::CancellationToken;
pub use diagnostic::{Diagnostic, DiagnosticCode, DiagnosticId, ScanStage, Severity};
pub use error::{
    DatabaseError, InternalError, ScanError, ScriptError, TerminationContext, UnsupportedError,
};
pub use format::{FilePart, FileType, FormatCandidate, FormatStrength};
pub use input::{ByteRange, ByteSource, ByteView, InputIdentity, IoError, ScanSource};
pub use limits::{
    DatabaseLimits, LimitKind, LimitReached, ScanLimits, ScriptLimits, TraversalLimits,
};
pub use node::{
    Detection, DetectionKind, NodeId, Provenance, ProvenanceKind, RuleIdentity, ScanNode,
};
pub use report::{
    Completion, DatabaseIdentity, EffectiveRequest, EngineMetadata, InputMetadata, ResourceUsage,
    ScanReport, SchemaVersion,
};
pub use request::{
    DetectionOptions, DiagnosticOptions, NestingOptions, ScanMode, ScanRequest, StructSelector,
};

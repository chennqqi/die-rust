//! `diec-engine` is the sole scan orchestration layer.
//!
//! A request runs: option/input/hard-limit validation, immutable database
//! snapshot fixation, scan context creation, ordered format probe collection,
//! host adapter construction, global/type init and ordered rule execution,
//! detection/diagnostic/child-work aggregation, and bounded work-queue
//! processing of resource/overlay/archive file-parts. CLI, FFI and output
//! crates never duplicate any detection branch. See
//! `docs/design/architecture.md` section 10.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod archive_unpack;
mod database;
pub mod host;
mod nested_scan;
mod scanner;
pub mod struct_mode;

pub use database::{Database, DatabaseBuilder, DatabaseError, DatabaseVersion};
pub use host::{BufferHost, ScanFlags};
pub use scanner::{ScanDetection, ScanError, ScanResult, Scanner, scan_bytes, scan_once};
pub use struct_mode::{
    StructNode, StructSelector, evaluate_struct, evaluate_struct_default, general_method_names,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_module_is_reachable() {
        // Smoke test: ensure the engine module compiles and exports types.
        let _ = DatabaseBuilder::default();
    }
}

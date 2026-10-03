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

pub mod archive;
mod archive_unpack;
mod database;
pub mod host;
mod nested_scan;
mod scanner;
pub mod struct_mode;
pub mod unpack;

pub use archive_unpack::{ArchiveKind, ArchiveMemberInfo, extract_member, list_archive_members};
pub use database::{Database, DatabaseBuilder, DatabaseError, DatabaseVersion};
pub use host::{BufferHost, ScanFlags};
pub use scanner::{ScanDetection, ScanError, ScanResult, Scanner, nfd_scan, scan_bytes, scan_once};
pub use struct_mode::{
    StructNode, StructSelector, evaluate_struct, evaluate_struct_default, general_method_names,
};
pub use unpack::{
    AspackInfo, FsgInfo, MewInfo, NsPackInfo, PackedInfo, PackerKind, PetiteInfo, UnpackError,
    UpxInfo, YodaInfo, detect_aspack, detect_fsg, detect_mew, detect_nspack, detect_packed,
    detect_petite, detect_upx, detect_yoda, is_upx_packed, unpack_any as unpack_static,
    unpack_aspack, unpack_fsg, unpack_mew, unpack_nspack, unpack_petite, unpack_yoda,
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

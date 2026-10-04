//! `die-ffi` is the stable C ABI adapter.
//!
//! It exposes opaque handles, fixed-layout C types, explicit ownership and
//! release functions, thread-safety annotations and an ABI version. Panics
//! never cross the FFI boundary. See `docs/design/c-abi.md` and `include/die.h`.
//!
//! # Safety
//!
//! All `#[no_mangle] extern "C"` functions are designed to be safe to call
//! from C. They validate pointers, catch panics, and never expose Rust
//! layout across the boundary.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod handles;
mod panic;
pub mod scan;
mod status;

pub use handles::{DieCancel, DieDatabase, DieDatabaseBuilder, DieError, DieResult, DieScanner};
pub use scan::DieScanOptions;
pub use scan::*;
pub use status::DieStatus;

/// ABI version encoded as (major << 16) | minor.
pub const DIE_ABI_VERSION: u32 = 0x0001_0000;

/// The current ABI major version.
pub const DIE_ABI_MAJOR: u32 = 1;

/// The current ABI minor version.
pub const DIE_ABI_MINOR: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_v1_0() {
        assert_eq!(DIE_ABI_VERSION, 0x0001_0000);
        assert_eq!(DIE_ABI_MAJOR, 1);
        assert_eq!(DIE_ABI_MINOR, 0);
    }
}

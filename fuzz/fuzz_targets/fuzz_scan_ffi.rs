//! Fuzz target: FFI scan_bytes on arbitrary input.
//!
//! Invariant: no panic crosses the FFI boundary, no crash, no hang.
//! The C ABI must return a valid status code for any input.
//!
//! This target requires the upstream database and the die-ffi crate.
//! If the database cannot be loaded, the target exits early.
//!
//! See `docs/design/testing.md` section 14 and `docs/design/c-abi.md`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::ffi::c_void;
use std::sync::OnceLock;

// Force the linker to retain die-ffi's #[no_mangle] symbols.
// Without direct Rust references, dead code elimination removes
// them from the rlib, causing "undefined symbol" errors when the
// extern "C" block below tries to resolve them at link time.
const _: () = {
    let _ = die_ffi::scan::die_v1_database_builder_new;
    let _ = die_ffi::scan::die_v1_database_builder_add_path_utf8;
    let _ = die_ffi::scan::die_v1_database_builder_build;
    let _ = die_ffi::scan::die_v1_database_builder_free;
    let _ = die_ffi::scan::die_v1_database_free;
    let _ = die_ffi::scan::die_v1_scan_bytes;
    let _ = die_ffi::scan::die_v1_result_free;
    let _ = die_ffi::scan::die_v1_error_free;
};

/// Opaque database handle type (matches die_v1_database).
type DieDatabaseHandle = *mut c_void;
type DieResultHandle = *mut c_void;
type DieErrorHandle = *mut c_void;

/// Load the database via FFI once and cache the handle.
/// Wrapped in a wrapper struct that is Send+Sync (the handle is only
/// used from the fuzz thread after initialization).
struct SendPtr(*mut c_void);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

static DATABASE_HANDLE: OnceLock<SendPtr> = OnceLock::new();

extern "C" {
    fn die_v1_database_builder_new(
        out_builder: *mut *mut c_void,
        out_error: *mut *mut c_void,
    ) -> u32;
    fn die_v1_database_builder_add_path_utf8(
        builder: *mut c_void,
        database_kind: u32,
        path: *const u8,
        path_length: u64,
        source_flags: u32,
        out_error: *mut *mut c_void,
    ) -> u32;
    fn die_v1_database_builder_build(
        builder: *const c_void,
        out_database: *mut *mut c_void,
        out_error: *mut *mut c_void,
    ) -> u32;
    fn die_v1_database_builder_free(in_out_builder: *mut *mut c_void) -> u32;
    fn die_v1_database_free(in_out_database: *mut *mut c_void) -> u32;
    fn die_v1_scan_bytes(
        database: *const c_void,
        data: *const u8,
        length: u64,
        options: *const c_void,
        cancel: *const c_void,
        out_result: *mut *mut c_void,
        out_error: *mut *mut c_void,
    ) -> u32;
    fn die_v1_result_free(in_out_result: *mut *mut c_void) -> u32;
    fn die_v1_error_free(in_out_error: *mut *mut c_void) -> u32;
}

/// Get the cached database handle, or null if it cannot be loaded.
fn get_database() -> DieDatabaseHandle {
    let ptr = DATABASE_HANDLE.get_or_init(|| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let db_path = std::path::Path::new(manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("upstream/Detect-It-Easy/db"))
            .unwrap_or_else(|| std::path::PathBuf::from("upstream/Detect-It-Easy/db"));

        let db_path_str = db_path.to_str().unwrap_or("upstream/Detect-It-Easy/db");
        let path_bytes = db_path_str.as_bytes();

        let mut builder: *mut c_void = std::ptr::null_mut();
        let mut error: *mut c_void = std::ptr::null_mut();

        unsafe {
            let status = die_v1_database_builder_new(&mut builder, &mut error);
            if status != 0 {
                return SendPtr(std::ptr::null_mut());
            }

            let status = die_v1_database_builder_add_path_utf8(
                builder,
                0,
                path_bytes.as_ptr(),
                path_bytes.len() as u64,
                0,
                &mut error,
            );
            if status != 0 {
                die_v1_database_builder_free(&mut builder);
                return SendPtr(std::ptr::null_mut());
            }

            let mut database: *mut c_void = std::ptr::null_mut();
            let status = die_v1_database_builder_build(builder, &mut database, &mut error);
            die_v1_database_builder_free(&mut builder);

            if status != 0 {
                return SendPtr(std::ptr::null_mut());
            }
            SendPtr(database)
        }
    });
    ptr.0
}

fuzz_target!(|data: &[u8]| {
    let db = get_database();
    if db.is_null() {
        return;
    }

    let mut result: DieResultHandle = std::ptr::null_mut();
    let mut error: DieErrorHandle = std::ptr::null_mut();

    // Call FFI scan_bytes - must not crash or panic across boundary.
    let status = unsafe {
        die_v1_scan_bytes(
            db,
            data.as_ptr(),
            data.len() as u64,
            std::ptr::null(),
            std::ptr::null(),
            &mut result,
            &mut error,
        )
    };

    // Status must be a valid u32 (0=OK or 1-15 error code).
    assert!(status <= 15, "invalid status code from FFI: {status}");

    // Clean up handles - must not crash.
    if !result.is_null() {
        unsafe {
            die_v1_result_free(&mut result);
        }
        assert!(result.is_null(), "result not nulled after free");
    }

    if !error.is_null() {
        unsafe {
            die_v1_error_free(&mut error);
        }
        assert!(error.is_null(), "error not nulled after free");
    }

    // Double-free safety: freeing null handles must not crash.
    unsafe {
        die_v1_result_free(&mut result);
        die_v1_error_free(&mut error);
    }
});

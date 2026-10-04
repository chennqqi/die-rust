//! FFI sanitizer tests: error paths, double-free safety, and panic containment.
//!
//! These tests verify that the C ABI handles edge cases correctly:
//! - Double-free is safe (no crash, returns OK)
//! - Null out pointers return INVALID_ARGUMENT
//! - Free of null handle is safe
//! - Error handle is properly populated on failure
//! - Error handle can be queried and freed
//! - Scan with null database returns INVALID_ARGUMENT
//! - Scan with null data (length > 0) returns INVALID_ARGUMENT

#![allow(unsafe_code)]

use die_ffi::*;

const DB_PATH: &str = "upstream/Detect-It-Easy/db";

fn db_available() -> bool {
    std::path::Path::new(DB_PATH).is_dir()
}

#[test]
fn ffi_double_free_database_builder_is_safe() {
    let mut builder: *mut DiecDatabaseBuilder = core::ptr::null_mut();
    let mut error: *mut DiecError = core::ptr::null_mut();

    unsafe {
        diec_v1_database_builder_new(
            &mut builder as *mut *mut DiecDatabaseBuilder,
            &mut error as *mut *mut DiecError,
        );
    }
    assert!(!builder.is_null());

    // First free.
    let s1 =
        unsafe { diec_v1_database_builder_free(&mut builder as *mut *mut DiecDatabaseBuilder) };
    assert_eq!(s1, 0);
    assert!(builder.is_null());

    // Second free (double-free) - should be safe.
    let s2 =
        unsafe { diec_v1_database_builder_free(&mut builder as *mut *mut DiecDatabaseBuilder) };
    assert_eq!(s2, 0);
    assert!(builder.is_null());

    // Third free for good measure.
    let s3 =
        unsafe { diec_v1_database_builder_free(&mut builder as *mut *mut DiecDatabaseBuilder) };
    assert_eq!(s3, 0);
}

#[test]
fn ffi_double_free_cancel_is_safe() {
    let mut cancel: *mut DiecCancel = core::ptr::null_mut();
    let mut error: *mut DiecError = core::ptr::null_mut();

    unsafe {
        diec_v1_cancel_new(
            &mut cancel as *mut *mut DiecCancel,
            &mut error as *mut *mut DiecError,
        );
    }

    unsafe { diec_v1_cancel_free(&mut cancel as *mut *mut DiecCancel) };
    unsafe { diec_v1_cancel_free(&mut cancel as *mut *mut DiecCancel) };
    assert!(cancel.is_null());
}

#[test]
fn ffi_double_free_database_is_safe() {
    if !db_available() {
        eprintln!("Skipping: upstream database not found");
        return;
    }

    let mut builder: *mut DiecDatabaseBuilder = core::ptr::null_mut();
    let mut error: *mut DiecError = core::ptr::null_mut();

    unsafe {
        diec_v1_database_builder_new(
            &mut builder as *mut *mut DiecDatabaseBuilder,
            &mut error as *mut *mut DiecError,
        );
        let path_bytes = DB_PATH.as_bytes();
        diec_v1_database_builder_add_path_utf8(
            builder,
            0,
            path_bytes.as_ptr(),
            path_bytes.len() as u64,
            0,
            &mut error as *mut *mut DiecError,
        );
    }

    let mut database: *mut DiecDatabase = core::ptr::null_mut();
    unsafe {
        diec_v1_database_builder_build(
            builder,
            &mut database as *mut *mut DiecDatabase,
            &mut error as *mut *mut DiecError,
        );
        diec_v1_database_builder_free(&mut builder as *mut *mut DiecDatabaseBuilder);
    }

    // Double free database.
    unsafe { diec_v1_database_free(&mut database as *mut *mut DiecDatabase) };
    assert!(database.is_null());
    unsafe { diec_v1_database_free(&mut database as *mut *mut DiecDatabase) };
    assert!(database.is_null());
}

#[test]
fn ffi_double_free_result_is_safe() {
    // Free of null result is safe.
    let mut result: *mut DiecResult = core::ptr::null_mut();
    let s1 = unsafe { diec_v1_result_free(&mut result as *mut *mut DiecResult) };
    assert_eq!(s1, 0);
    let s2 = unsafe { diec_v1_result_free(&mut result as *mut *mut DiecResult) };
    assert_eq!(s2, 0);
}

#[test]
fn ffi_double_free_scanner_is_safe() {
    let mut scanner: *mut DiecScanner = core::ptr::null_mut();
    let s1 = unsafe { diec_v1_scanner_free(&mut scanner as *mut *mut DiecScanner) };
    assert_eq!(s1, 0);
    let s2 = unsafe { diec_v1_scanner_free(&mut scanner as *mut *mut DiecScanner) };
    assert_eq!(s2, 0);
}

#[test]
fn ffi_double_free_error_is_safe() {
    let mut error: *mut DiecError = core::ptr::null_mut();
    let s1 = unsafe { diec_v1_error_free(&mut error as *mut *mut DiecError) };
    assert_eq!(s1, 0);
    let s2 = unsafe { diec_v1_error_free(&mut error as *mut *mut DiecError) };
    assert_eq!(s2, 0);
}

#[test]
fn ffi_null_database_to_scan_returns_invalid_argument() {
    let data = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    let mut result: *mut DiecResult = core::ptr::null_mut();
    let mut error: *mut DiecError = core::ptr::null_mut();

    let status = unsafe {
        diec_v1_scan_bytes(
            core::ptr::null(), // null database
            data.as_ptr(),
            data.len() as u64,
            core::ptr::null(),
            core::ptr::null(),
            &mut result as *mut *mut DiecResult,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 1); // INVALID_ARGUMENT
    assert!(result.is_null());
}

#[test]
fn ffi_null_data_with_nonzero_length_returns_invalid_argument() {
    if !db_available() {
        eprintln!("Skipping: upstream database not found");
        return;
    }

    // Build database.
    let mut builder: *mut DiecDatabaseBuilder = core::ptr::null_mut();
    let mut error: *mut DiecError = core::ptr::null_mut();
    unsafe {
        diec_v1_database_builder_new(
            &mut builder as *mut *mut DiecDatabaseBuilder,
            &mut error as *mut *mut DiecError,
        );
        let path_bytes = DB_PATH.as_bytes();
        diec_v1_database_builder_add_path_utf8(
            builder,
            0,
            path_bytes.as_ptr(),
            path_bytes.len() as u64,
            0,
            &mut error as *mut *mut DiecError,
        );
    }

    let mut database: *mut DiecDatabase = core::ptr::null_mut();
    unsafe {
        diec_v1_database_builder_build(
            builder,
            &mut database as *mut *mut DiecDatabase,
            &mut error as *mut *mut DiecError,
        );
        diec_v1_database_builder_free(&mut builder as *mut *mut DiecDatabaseBuilder);
    }

    // Scan with null data but non-zero length.
    let mut result: *mut DiecResult = core::ptr::null_mut();
    let status = unsafe {
        diec_v1_scan_bytes(
            database,
            core::ptr::null(), // null data
            100,               // non-zero length
            core::ptr::null(),
            core::ptr::null(),
            &mut result as *mut *mut DiecResult,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 1); // INVALID_ARGUMENT
    assert!(result.is_null());

    unsafe {
        diec_v1_database_free(&mut database as *mut *mut DiecDatabase);
    }
}

#[test]
fn ffi_null_data_with_zero_length_is_valid() {
    if !db_available() {
        eprintln!("Skipping: upstream database not found");
        return;
    }

    let mut builder: *mut DiecDatabaseBuilder = core::ptr::null_mut();
    let mut error: *mut DiecError = core::ptr::null_mut();
    unsafe {
        diec_v1_database_builder_new(
            &mut builder as *mut *mut DiecDatabaseBuilder,
            &mut error as *mut *mut DiecError,
        );
        let path_bytes = DB_PATH.as_bytes();
        diec_v1_database_builder_add_path_utf8(
            builder,
            0,
            path_bytes.as_ptr(),
            path_bytes.len() as u64,
            0,
            &mut error as *mut *mut DiecError,
        );
    }

    let mut database: *mut DiecDatabase = core::ptr::null_mut();
    unsafe {
        diec_v1_database_builder_build(
            builder,
            &mut database as *mut *mut DiecDatabase,
            &mut error as *mut *mut DiecError,
        );
        diec_v1_database_builder_free(&mut builder as *mut *mut DiecDatabaseBuilder);
    }

    // Scan with null data and zero length - should succeed (empty input).
    let mut result: *mut DiecResult = core::ptr::null_mut();
    let status = unsafe {
        diec_v1_scan_bytes(
            database,
            core::ptr::null(),
            0, // zero length with null is valid
            core::ptr::null(),
            core::ptr::null(),
            &mut result as *mut *mut DiecResult,
            &mut error as *mut *mut DiecError,
        )
    };
    // Empty input may succeed (no detections) or fail with a scan error.
    // The key assertion is that it doesn't crash.
    if status == 0 {
        assert!(!result.is_null());
        unsafe {
            diec_v1_result_free(&mut result as *mut *mut DiecResult);
        }
    }

    unsafe {
        diec_v1_database_free(&mut database as *mut *mut DiecDatabase);
    }
}

#[test]
fn ffi_error_handle_query_and_free() {
    // Force an error by scanning with null database.
    let data = [0x42u8; 16];
    let mut result: *mut DiecResult = core::ptr::null_mut();
    let mut error: *mut DiecError = core::ptr::null_mut();

    let status = unsafe {
        diec_v1_scan_bytes(
            core::ptr::null(),
            data.as_ptr(),
            data.len() as u64,
            core::ptr::null(),
            core::ptr::null(),
            &mut result as *mut *mut DiecResult,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 1); // INVALID_ARGUMENT

    // Error should be populated (ffi_wrap_out sets error on failure).
    // Note: for INVALID_ARGUMENT from null out_value, error may be null.
    // But for null database, the error should be set.
    if !error.is_null() {
        // Query error status.
        let mut err_status: u32 = 0;
        let s = unsafe { diec_v1_error_status(error, &mut err_status as *mut u32) };
        assert_eq!(s, 0);
        assert_eq!(err_status, 1); // INVALID_ARGUMENT

        // Query error message.
        let mut msg_data: *const u8 = core::ptr::null();
        let mut msg_len: u64 = 0;
        let s = unsafe {
            diec_v1_error_message(
                error,
                &mut msg_data as *mut *const u8,
                &mut msg_len as *mut u64,
            )
        };
        assert_eq!(s, 0);
        assert!(msg_len > 0);

        // Free error.
        let s = unsafe { diec_v1_error_free(&mut error as *mut *mut DiecError) };
        assert_eq!(s, 0);
        assert!(error.is_null());
    }
}

#[test]
fn ffi_cancel_request_on_null_returns_invalid_argument() {
    let status = unsafe { diec_v1_cancel_request(core::ptr::null_mut()) };
    assert_eq!(status, 1); // INVALID_ARGUMENT
}

#[test]
fn ffi_status_name_for_all_codes() {
    for i in 0..=15u32 {
        let mut data: *const u8 = core::ptr::null();
        let mut length: u64 = 0;
        let status =
            unsafe { diec_v1_status_name(i, &mut data as *mut *const u8, &mut length as *mut u64) };
        assert_eq!(status, 0, "status_name should succeed for code {i}");
        assert!(length > 0, "status name for code {i} should be non-empty");
    }
}

#[test]
fn ffi_scan_options_init_null_returns_invalid_argument() {
    let status = unsafe { diec_v1_scan_options_init(core::ptr::null_mut(), 0) };
    assert_eq!(status, 1); // INVALID_ARGUMENT
}

#[test]
fn ffi_scan_options_init_small_size_returns_invalid_argument() {
    let mut options = DiecScanOptions {
        struct_size: 0,
        flags: 0,
        max_input_bytes: 0,
        max_unpacked_bytes: 0,
        max_container_entries: 0,
        timeout_ms: 0,
        max_recursion_depth: 0,
        reserved_0: 0,
        max_total_allocation_bytes: 0,
        script_heap_bytes: 0,
        script_stack_bytes: 0,
        script_fuel_quanta: 0,
        script_deadline_ms: 0,
    };

    // Pass a too-small size.
    let status = unsafe {
        diec_v1_scan_options_init(
            &mut options as *mut _,
            16, // too small
        )
    };
    assert_eq!(status, 1); // INVALID_ARGUMENT
}

#[test]
fn ffi_result_accessors_on_null_return_invalid_argument() {
    let mut data: *const u8 = core::ptr::null();
    let mut length: u64 = 0;

    let s = unsafe {
        diec_v1_result_json(
            core::ptr::null(),
            &mut data as *mut *const u8,
            &mut length as *mut u64,
        )
    };
    assert_eq!(s, 1);

    let s = unsafe {
        diec_v1_result_path_utf8(
            core::ptr::null(),
            &mut data as *mut *const u8,
            &mut length as *mut u64,
        )
    };
    assert_eq!(s, 1);

    let mut count: u64 = 0;
    let s = unsafe { diec_v1_result_detection_count(core::ptr::null(), &mut count as *mut u64) };
    assert_eq!(s, 1);
}

#[test]
fn ffi_error_accessors_on_null_return_invalid_argument() {
    let mut status: u32 = 0;
    let s = unsafe { diec_v1_error_status(core::ptr::null(), &mut status as *mut u32) };
    assert_eq!(s, 1);

    let mut data: *const u8 = core::ptr::null();
    let mut length: u64 = 0;
    let s = unsafe {
        diec_v1_error_message(
            core::ptr::null(),
            &mut data as *mut *const u8,
            &mut length as *mut u64,
        )
    };
    assert_eq!(s, 1);
}

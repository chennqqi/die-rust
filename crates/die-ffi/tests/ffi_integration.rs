//! Integration tests for the C ABI.
//!
//! These tests call the FFI functions directly from Rust to verify
//! the complete lifecycle: database builder, scan, result accessors,
//! and handle cleanup.

#![allow(unsafe_code)]
#![allow(clippy::unnecessary_safety_comment)]

use die_ffi::*;

const DB_PATH: &str = "upstream/Detect-It-Easy/db";

/// Check if the upstream database is available.
fn db_available() -> bool {
    std::path::Path::new(DB_PATH).is_dir()
}

/// 7-Zip magic header.
fn seven_zip_header() -> Vec<u8> {
    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0);
    data
}

#[test]
fn ffi_abi_version_is_v1() {
    let version = unsafe { diec_abi_version() };
    assert_eq!(version, 0x0001_0000);
}

#[test]
fn ffi_abi_compatible_with_v1_0() {
    let compatible = unsafe { diec_abi_is_compatible(0x0001_0000) };
    assert_eq!(compatible, 1);
}

#[test]
fn ffi_abi_incompatible_with_v2() {
    let compatible = unsafe { diec_abi_is_compatible(0x0002_0000) };
    assert_eq!(compatible, 0);
}

#[test]
fn ffi_status_name_ok() {
    let mut data: *const u8 = core::ptr::null();
    let mut length: u64 = 0;
    let status =
        unsafe { diec_v1_status_name(0, &mut data as *mut *const u8, &mut length as *mut u64) };
    assert_eq!(status, 0);
    assert_eq!(length, 2);
    // The bytes should be "OK".
    let bytes = unsafe { core::slice::from_raw_parts(data, length as usize) };
    assert_eq!(bytes, b"OK");
}

#[test]
fn ffi_status_name_unknown() {
    let mut data: *const u8 = core::ptr::null();
    let mut length: u64 = 0;
    let status =
        unsafe { diec_v1_status_name(99, &mut data as *mut *const u8, &mut length as *mut u64) };
    assert_eq!(status, 0);
    let bytes = unsafe { core::slice::from_raw_parts(data, length as usize) };
    assert_eq!(bytes, b"UNKNOWN");
}

#[test]
fn ffi_null_pointer_returns_invalid_argument() {
    let mut error: *mut DiecError = core::ptr::null_mut();
    let status = unsafe {
        diec_v1_database_builder_new(core::ptr::null_mut(), &mut error as *mut *mut DiecError)
    };
    assert_eq!(status, 1); // INVALID_ARGUMENT
    // Error should be null on invalid argument (out_value was null).
    assert!(error.is_null());
}

#[test]
fn ffi_database_builder_lifecycle() {
    let mut builder: *mut DiecDatabaseBuilder = core::ptr::null_mut();
    let mut error: *mut DiecError = core::ptr::null_mut();

    // Create builder.
    let status = unsafe {
        diec_v1_database_builder_new(
            &mut builder as *mut *mut DiecDatabaseBuilder,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0);
    assert!(!builder.is_null());
    assert!(error.is_null());

    // Free builder.
    let status =
        unsafe { diec_v1_database_builder_free(&mut builder as *mut *mut DiecDatabaseBuilder) };
    assert_eq!(status, 0);
    assert!(builder.is_null());

    // Double free is safe.
    let status =
        unsafe { diec_v1_database_builder_free(&mut builder as *mut *mut DiecDatabaseBuilder) };
    assert_eq!(status, 0);
}

#[test]
fn ffi_cancel_lifecycle() {
    let mut cancel: *mut DiecCancel = core::ptr::null_mut();
    let mut error: *mut DiecError = core::ptr::null_mut();

    let status = unsafe {
        diec_v1_cancel_new(
            &mut cancel as *mut *mut DiecCancel,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0);
    assert!(!cancel.is_null());

    // Request cancellation.
    let status = unsafe { diec_v1_cancel_request(cancel) };
    assert_eq!(status, 0);

    // Free.
    let status = unsafe { diec_v1_cancel_free(&mut cancel as *mut *mut DiecCancel) };
    assert_eq!(status, 0);
    assert!(cancel.is_null());
}

#[test]
fn ffi_scan_bytes_full_lifecycle() {
    if !db_available() {
        eprintln!("Skipping: upstream database not found");
        return;
    }

    // Build database.
    let mut builder: *mut DiecDatabaseBuilder = core::ptr::null_mut();
    let mut error: *mut DiecError = core::ptr::null_mut();

    let status = unsafe {
        diec_v1_database_builder_new(
            &mut builder as *mut *mut DiecDatabaseBuilder,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0);

    // Add main database path.
    let path_bytes = DB_PATH.as_bytes();
    let status = unsafe {
        diec_v1_database_builder_add_path_utf8(
            builder,
            0, // DATABASE_KIND_MAIN
            path_bytes.as_ptr(),
            path_bytes.len() as u64,
            0,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0, "add_path should succeed");

    // Build database.
    let mut database: *mut DiecDatabase = core::ptr::null_mut();
    let status = unsafe {
        diec_v1_database_builder_build(
            builder,
            &mut database as *mut *mut DiecDatabase,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0, "build should succeed");
    assert!(!database.is_null());

    // Free builder (database is independent).
    unsafe {
        diec_v1_database_builder_free(&mut builder as *mut *mut DiecDatabaseBuilder);
    }

    // Scan 7-Zip header.
    let data = seven_zip_header();
    let mut result: *mut DiecResult = core::ptr::null_mut();
    let status = unsafe {
        diec_v1_scan_bytes(
            database,
            data.as_ptr(),
            data.len() as u64,
            core::ptr::null(), // default options
            core::ptr::null(), // no cancel
            &mut result as *mut *mut DiecResult,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0, "scan should succeed");
    assert!(!result.is_null());

    // Get JSON.
    let mut json_data: *const u8 = core::ptr::null();
    let mut json_length: u64 = 0;
    let status = unsafe {
        diec_v1_result_json(
            result,
            &mut json_data as *mut *const u8,
            &mut json_length as *mut u64,
        )
    };
    assert_eq!(status, 0);
    assert!(json_length > 0);
    let json_bytes = unsafe { core::slice::from_raw_parts(json_data, json_length as usize) };
    let json_str = std::str::from_utf8(json_bytes).unwrap();
    assert!(
        json_str.contains("7-Zip"),
        "JSON should contain 7-Zip: {json_str}"
    );

    // Get detection count.
    let mut count: u64 = 0;
    let status = unsafe { diec_v1_result_detection_count(result, &mut count as *mut u64) };
    assert_eq!(status, 0);
    assert!(count > 0);

    // Free result.
    let status = unsafe { diec_v1_result_free(&mut result as *mut *mut DiecResult) };
    assert_eq!(status, 0);
    assert!(result.is_null());

    // Free database.
    let status = unsafe { diec_v1_database_free(&mut database as *mut *mut DiecDatabase) };
    assert_eq!(status, 0);
    assert!(database.is_null());
}

#[test]
fn ffi_reusable_scanner_lifecycle() {
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
        )
    };

    let path_bytes = DB_PATH.as_bytes();
    unsafe {
        diec_v1_database_builder_add_path_utf8(
            builder,
            0,
            path_bytes.as_ptr(),
            path_bytes.len() as u64,
            0,
            &mut error as *mut *mut DiecError,
        )
    };

    let mut database: *mut DiecDatabase = core::ptr::null_mut();
    unsafe {
        diec_v1_database_builder_build(
            builder,
            &mut database as *mut *mut DiecDatabase,
            &mut error as *mut *mut DiecError,
        )
    };
    unsafe {
        diec_v1_database_builder_free(&mut builder as *mut *mut DiecDatabaseBuilder);
    }

    // Create scanner.
    let mut scanner: *mut DiecScanner = core::ptr::null_mut();
    let status = unsafe {
        diec_v1_scanner_new(
            database,
            &mut scanner as *mut *mut DiecScanner,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0);
    assert!(!scanner.is_null());

    // Scan with scanner.
    let data = seven_zip_header();
    let mut result: *mut DiecResult = core::ptr::null_mut();
    let status = unsafe {
        diec_v1_scanner_scan_bytes(
            scanner,
            data.as_ptr(),
            data.len() as u64,
            core::ptr::null(),
            core::ptr::null(),
            &mut result as *mut *mut DiecResult,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0);
    assert!(!result.is_null());

    // Verify result.
    let mut json_data: *const u8 = core::ptr::null();
    let mut json_length: u64 = 0;
    unsafe {
        diec_v1_result_json(
            result,
            &mut json_data as *mut *const u8,
            &mut json_length as *mut u64,
        )
    };
    let json_bytes = unsafe { core::slice::from_raw_parts(json_data, json_length as usize) };
    let json_str = std::str::from_utf8(json_bytes).unwrap();
    assert!(json_str.contains("7-Zip"));

    // Cleanup.
    unsafe {
        diec_v1_result_free(&mut result as *mut *mut DiecResult);
        diec_v1_scanner_free(&mut scanner as *mut *mut DiecScanner);
        diec_v1_database_free(&mut database as *mut *mut DiecDatabase);
    }
    assert!(scanner.is_null());
    assert!(database.is_null());
}

#[test]
fn ffi_error_handle_lifecycle() {
    // Force an error by passing null out_value to a builder function.
    let mut error: *mut DiecError = core::ptr::null_mut();

    // Create builder with null out_builder to trigger error.
    let status = unsafe {
        diec_v1_database_builder_new(core::ptr::null_mut(), &mut error as *mut *mut DiecError)
    };
    assert_eq!(status, 1); // INVALID_ARGUMENT

    // Free error (should be safe even if null).
    let status = unsafe { diec_v1_error_free(&mut error as *mut *mut DiecError) };
    assert_eq!(status, 0);
}

#[test]
fn ffi_scan_options_init_works() {
    let mut options = die_ffi::DiecScanOptions {
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

    let status = unsafe {
        diec_v1_scan_options_init(
            &mut options as *mut _,
            core::mem::size_of::<die_ffi::DiecScanOptions>() as u32,
        )
    };
    assert_eq!(status, 0);
    assert_eq!(options.flags, 0);
}

#[test]
fn ffi_scan_flag_no_dedup_bit() {
    // Verify that the 0x40 bit maps to no_dedup in the engine.
    // We test this by constructing DiecScanOptions with flags=0x40 and
    // verifying the scan completes successfully.
    if !db_available() {
        eprintln!("Skipping: upstream database not found");
        return;
    }

    let mut builder: *mut DiecDatabaseBuilder = core::ptr::null_mut();
    let mut error: *mut DiecError = core::ptr::null_mut();

    let status = unsafe {
        diec_v1_database_builder_new(
            &mut builder as *mut *mut DiecDatabaseBuilder,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0);

    let path_bytes = DB_PATH.as_bytes();
    let status = unsafe {
        diec_v1_database_builder_add_path_utf8(
            builder,
            0,
            path_bytes.as_ptr(),
            path_bytes.len() as u64,
            0,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0);

    let mut database: *mut DiecDatabase = core::ptr::null_mut();
    let status = unsafe {
        diec_v1_database_builder_build(
            builder,
            &mut database as *mut *mut DiecDatabase,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0);

    unsafe {
        diec_v1_database_builder_free(&mut builder as *mut *mut DiecDatabaseBuilder);
    }

    // Build options with ALL_TYPES (0x04) + NO_DEDUP (0x40) = 0x44.
    let mut options = die_ffi::DiecScanOptions {
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

    let status = unsafe {
        diec_v1_scan_options_init(
            &mut options as *mut _,
            core::mem::size_of::<die_ffi::DiecScanOptions>() as u32,
        )
    };
    assert_eq!(status, 0);
    // scan_options_init resets flags to 0; set our flags after init.
    options.flags = 0x44; // ALL_TYPES (0x04) + NO_DEDUP (0x40)

    // Scan a minimal MZ file.
    let data = {
        let mut d = vec![0x4Du8, 0x5A];
        d.resize(256, 0);
        d
    };

    let mut result: *mut DiecResult = core::ptr::null_mut();
    let status = unsafe {
        diec_v1_scan_bytes(
            database,
            data.as_ptr(),
            data.len() as u64,
            &options as *const _,
            core::ptr::null(),
            &mut result as *mut *mut DiecResult,
            &mut error as *mut *mut DiecError,
        )
    };
    assert_eq!(status, 0, "scan with no_dedup flag should succeed");
    assert!(!result.is_null());

    // Free result and database.
    unsafe {
        diec_v1_result_free(&mut result as *mut *mut DiecResult);
        diec_v1_database_free(&mut database as *mut *mut DiecDatabase);
    }
}

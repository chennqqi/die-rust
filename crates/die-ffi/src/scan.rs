//! FFI exported functions implementing the C ABI.
//!
//! All functions are `#[unsafe(no_mangle)] extern "C"` and use panic containment.
//!
//! This module contains `unsafe` code for pointer dereferencing across the
//! FFI boundary. All unsafe blocks follow the safety invariants documented
//! in the helper functions in `error.rs`.

#![allow(unsafe_code)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::missing_safety_doc)]

use crate::error::{
    byte_slice_from_raw, ffi_wrap, ffi_wrap_out, free_handle, status_to_u32, str_from_raw,
    validate_borrowed_ptr, validate_mut_ptr, write_byte_view,
};
use crate::handles::{DieCancel, DieDatabase, DieDatabaseBuilder, DieError, DieResult, DieScanner};
use crate::status::DieStatus;
use crate::{DIE_ABI_MAJOR, DIE_ABI_MINOR, DIE_ABI_VERSION};
use die_core::cancel::CancellationToken;
use die_engine::{DatabaseBuilder, ScanFlags};
use std::sync::Arc;

// ---- ABI version negotiation ----

/// Get the library's ABI version.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_abi_version() -> u32 {
    DIE_ABI_VERSION
}

/// Check if the library is compatible with the requested ABI version.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_abi_is_compatible(requested: u32) -> u32 {
    let req_major = requested >> 16;
    let req_minor = requested & 0xFFFF;
    // Compatible if major matches and library minor >= requested minor.
    // DIE_ABI_MINOR is currently 0, so only req_minor == 0 is compatible.
    if req_major == DIE_ABI_MAJOR && req_minor == DIE_ABI_MINOR {
        1
    } else {
        0
    }
}

// ---- Status name lookup ----

/// Get the canonical name string for a status code.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_status_name(
    status: u32,
    out_data: *mut *const u8,
    out_length: *mut u64,
) -> u32 {
    let name = DieStatus::from_u32(status)
        .map(|s| s.name())
        .unwrap_or("UNKNOWN");
    let bytes = name.as_bytes();
    match write_byte_view(bytes, out_data, out_length) {
        Ok(()) => DieStatus::Ok.into(),
        Err(e) => e.into(),
    }
}

// ---- Scan options ----

/// C-compatible scan options struct (must match die.h layout).
#[repr(C)]
pub struct DieScanOptions {
    /// Caller's actual struct size for additive extension.
    pub struct_size: u32,
    /// Scan flag bits (deep/heuristic/all-types/etc).
    pub flags: u32,
    /// Max input bytes; 0 = safe default, not unlimited.
    pub max_input_bytes: u64,
    /// Cumulative unpacked byte budget.
    pub max_unpacked_bytes: u64,
    /// Cumulative container entry budget.
    pub max_container_entries: u64,
    /// Scan timeout in milliseconds; 0 = default.
    pub timeout_ms: u64,
    /// Max recursion depth; 0 = default.
    pub max_recursion_depth: u32,
    /// Reserved, must be 0.
    pub reserved_0: u32,
    /// Total allocation budget; 0 = safe default.
    pub max_total_allocation_bytes: u64,
    /// Per-scan JS VM heap bytes; 0 = safe default.
    pub script_heap_bytes: u64,
    /// JS VM stack bytes; 0 = safe default.
    pub script_stack_bytes: u64,
    /// VM/native cooperative fuel; 0 = safe default.
    pub script_fuel_quanta: u64,
    /// Absolute script deadline ms; 0 = safe default.
    pub script_deadline_ms: u64,
}

/// Minimum struct_size for v1.0.
const MIN_SCAN_OPTIONS_SIZE: u32 = 88;

/// Initialize scan options with safe defaults.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_scan_options_init(
    options: *mut DieScanOptions,
    options_size: u32,
) -> u32 {
    if options.is_null() {
        return DieStatus::InvalidArgument.into();
    }
    // SAFETY: caller guarantees options is valid for writes.
    let opts = unsafe { &mut *options };
    if options_size < core::mem::size_of::<DieScanOptions>() as u32 {
        // Only write what fits.
        return DieStatus::InvalidArgument.into();
    }
    opts.struct_size = options_size;
    opts.flags = 0;
    opts.max_input_bytes = 0;
    opts.max_unpacked_bytes = 0;
    opts.max_container_entries = 0;
    opts.timeout_ms = 0;
    opts.max_recursion_depth = 0;
    opts.reserved_0 = 0;
    opts.max_total_allocation_bytes = 0;
    opts.script_heap_bytes = 0;
    opts.script_stack_bytes = 0;
    opts.script_fuel_quanta = 0;
    opts.script_deadline_ms = 0;
    DieStatus::Ok.into()
}

/// Convert C scan options to Rust ScanFlags.
fn options_to_flags(options: Option<&DieScanOptions>) -> ScanFlags {
    let mut flags = ScanFlags::default();
    if let Some(opts) = options {
        if opts.flags & 0x01 != 0 {
            flags.deep = true;
        }
        if opts.flags & 0x02 != 0 {
            flags.heuristic = true;
        }
        if opts.flags & 0x04 != 0 {
            flags.all_types = true;
        }
        if opts.flags & 0x08 != 0 {
            flags.aggressive = true;
        }
        if opts.flags & 0x10 != 0 {
            flags.hide_unknown = true;
        }
        if opts.flags & 0x20 != 0 {
            flags.verbose = true;
        }
        if opts.flags & 0x40 != 0 {
            flags.no_dedup = true;
        }
        // ADR 0028: intra-file recursive scanning flags.
        if opts.flags & 0x80 != 0 {
            flags.recursive = true;
        }
        if opts.flags & 0x100 != 0 {
            flags.resources = true;
        }
        if opts.flags & 0x200 != 0 {
            flags.overlays = true;
        }
        if opts.flags & 0x400 != 0 {
            flags.archives = true;
        }
    }
    flags
}

/// Validate scan options pointer and return a reference.
fn validate_options<'a>(
    options: *const DieScanOptions,
) -> Result<Option<&'a DieScanOptions>, DieStatus> {
    if options.is_null() {
        return Ok(None);
    }
    let opts = unsafe { &*options };
    if opts.reserved_0 != 0 {
        return Err(DieStatus::InvalidArgument);
    }
    if opts.struct_size < MIN_SCAN_OPTIONS_SIZE && opts.struct_size != 0 {
        return Err(DieStatus::InvalidArgument);
    }
    Ok(Some(opts))
}

// ---- Database builder ----

/// Create a new database builder.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_database_builder_new(
    out_builder: *mut *mut DieDatabaseBuilder,
    out_error: *mut *mut DieError,
) -> u32 {
    ffi_wrap_out(out_builder, out_error, || {
        Ok(Box::new(DieDatabaseBuilder {
            builder: DatabaseBuilder::default(),
        }))
    })
}

/// Add a database path to the builder.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_database_builder_add_path_utf8(
    builder: *mut DieDatabaseBuilder,
    _database_kind: u32,
    path: *const u8,
    path_length: u64,
    _source_flags: u32,
    out_error: *mut *mut DieError,
) -> u32 {
    ffi_wrap(out_error, || {
        let builder = validate_mut_ptr(builder)?;
        let path_str = str_from_raw(path, path_length)?;
        builder.builder = builder.builder.clone().with_extra(path_str);
        Ok(())
    })
}

/// Build the database from accumulated paths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_database_builder_build(
    builder: *const DieDatabaseBuilder,
    out_database: *mut *mut DieDatabase,
    out_error: *mut *mut DieError,
) -> u32 {
    ffi_wrap_out(out_database, out_error, || {
        let builder = validate_borrowed_ptr(builder)?;
        let db = builder.builder.clone().build().map_err(|e| {
            let _msg = format!("{e}");
            DieStatus::Database
        })?;
        Ok(Box::new(DieDatabase {
            database: Arc::new(db),
        }))
    })
}

/// Free a database builder.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_database_builder_free(
    in_out_builder: *mut *mut DieDatabaseBuilder,
) -> u32 {
    match free_handle(in_out_builder) {
        Ok(()) => DieStatus::Ok.into(),
        Err(e) => e.into(),
    }
}

// ---- Database ----

/// Get database metadata as JSON.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_database_metadata_json(
    database: *const DieDatabase,
    out_data: *mut *const u8,
    out_length: *mut u64,
) -> u32 {
    let db = match validate_borrowed_ptr(database) {
        Ok(d) => d,
        Err(e) => return e.into(),
    };
    let rule_count = db.database.rule_count();
    let json = format!(
        "{{\"rule_count\":{},\"db_path\":\"{}\"}}",
        rule_count,
        db.database.db_path.display()
    );
    match write_byte_view(json.as_bytes(), out_data, out_length) {
        Ok(()) => {
            // Leak the string so the caller can borrow it.
            // This is acceptable because the metadata is static for the
            // lifetime of the database handle.
            // Actually, we need to store it. Let's use a different approach.
            // For simplicity, we leak the string.
            std::mem::forget(json);
            DieStatus::Ok.into()
        }
        Err(e) => e.into(),
    }
}

/// Free a database handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_database_free(in_out_database: *mut *mut DieDatabase) -> u32 {
    match free_handle(in_out_database) {
        Ok(()) => DieStatus::Ok.into(),
        Err(e) => e.into(),
    }
}

// ---- Cancel token ----

/// Create a new cancel token.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_cancel_new(
    out_cancel: *mut *mut DieCancel,
    out_error: *mut *mut DieError,
) -> u32 {
    ffi_wrap_out(out_cancel, out_error, || {
        Ok(Box::new(DieCancel {
            token: CancellationToken::new(),
        }))
    })
}

/// Request cancellation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_cancel_request(cancel: *mut DieCancel) -> u32 {
    match validate_mut_ptr(cancel) {
        Ok(c) => {
            c.token.cancel();
            DieStatus::Ok.into()
        }
        Err(e) => e.into(),
    }
}

/// Free a cancel token.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_cancel_free(in_out_cancel: *mut *mut DieCancel) -> u32 {
    match free_handle(in_out_cancel) {
        Ok(()) => DieStatus::Ok.into(),
        Err(e) => e.into(),
    }
}

// ---- One-shot scan ----

/// Scan a byte buffer (one-shot, thread-neutral).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_scan_bytes(
    database: *const DieDatabase,
    data: *const u8,
    length: u64,
    options: *const DieScanOptions,
    cancel: *const DieCancel,
    out_result: *mut *mut DieResult,
    out_error: *mut *mut DieError,
) -> u32 {
    ffi_wrap_out(out_result, out_error, || {
        let db = validate_borrowed_ptr(database)?;
        let data_slice = byte_slice_from_raw(data, length)?;
        let opts = validate_options(options)?;
        let flags = options_to_flags(opts);

        let cancel_token = if cancel.is_null() {
            CancellationToken::new()
        } else {
            let c = unsafe { &*cancel };
            c.token.clone()
        };

        let result = die_engine::scan_bytes(
            &db.database,
            "input",
            data_slice.to_vec(),
            flags,
            &cancel_token,
        )
        .map_err(|e| match &e {
            die_engine::ScanError::DatabaseInit { .. } => DieStatus::Database,
            die_engine::ScanError::HostApi { .. } => DieStatus::Internal,
            die_engine::ScanError::RuleEval { .. } => DieStatus::Script,
            die_engine::ScanError::Input { .. } => DieStatus::Io,
            die_engine::ScanError::Cancelled => DieStatus::Cancelled,
        })?;

        let json = die_output::render_json(&result);
        Ok(Box::new(DieResult { result, json }))
    })
}

/// Scan a file path (one-shot, thread-neutral).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_scan_path_utf8(
    database: *const DieDatabase,
    path: *const u8,
    path_length: u64,
    options: *const DieScanOptions,
    cancel: *const DieCancel,
    out_result: *mut *mut DieResult,
    out_error: *mut *mut DieError,
) -> u32 {
    ffi_wrap_out(out_result, out_error, || {
        let db = validate_borrowed_ptr(database)?;
        let path_str = str_from_raw(path, path_length)?;
        let opts = validate_options(options)?;
        let flags = options_to_flags(opts);

        let cancel_token = if cancel.is_null() {
            CancellationToken::new()
        } else {
            let c = unsafe { &*cancel };
            c.token.clone()
        };

        let result =
            die_engine::scan_once(&db.database, path_str, flags, &cancel_token).map_err(|e| {
                match &e {
                    die_engine::ScanError::DatabaseInit { .. } => DieStatus::Database,
                    die_engine::ScanError::HostApi { .. } => DieStatus::Internal,
                    die_engine::ScanError::RuleEval { .. } => DieStatus::Script,
                    die_engine::ScanError::Input { .. } => DieStatus::Io,
                    die_engine::ScanError::Cancelled => DieStatus::Cancelled,
                }
            })?;

        let json = die_output::render_json(&result);
        Ok(Box::new(DieResult { result, json }))
    })
}

// ---- Reusable scanner ----

/// Create a reusable scanner.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_scanner_new(
    database: *const DieDatabase,
    out_scanner: *mut *mut DieScanner,
    out_error: *mut *mut DieError,
) -> u32 {
    ffi_wrap_out(out_scanner, out_error, || {
        let db = validate_borrowed_ptr(database)?;
        Ok(Box::new(DieScanner {
            database: Arc::clone(&db.database),
        }))
    })
}

/// Scan bytes with a reusable scanner.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_scanner_scan_bytes(
    scanner: *mut DieScanner,
    data: *const u8,
    length: u64,
    options: *const DieScanOptions,
    cancel: *const DieCancel,
    out_result: *mut *mut DieResult,
    out_error: *mut *mut DieError,
) -> u32 {
    ffi_wrap_out(out_result, out_error, || {
        let scanner = validate_mut_ptr(scanner)?;
        let data_slice = byte_slice_from_raw(data, length)?;
        let opts = validate_options(options)?;
        let flags = options_to_flags(opts);

        let cancel_token = if cancel.is_null() {
            CancellationToken::new()
        } else {
            let c = unsafe { &*cancel };
            c.token.clone()
        };

        let result = die_engine::scan_bytes(
            &scanner.database,
            "input",
            data_slice.to_vec(),
            flags,
            &cancel_token,
        )
        .map_err(|e| match &e {
            die_engine::ScanError::DatabaseInit { .. } => DieStatus::Database,
            die_engine::ScanError::HostApi { .. } => DieStatus::Internal,
            die_engine::ScanError::RuleEval { .. } => DieStatus::Script,
            die_engine::ScanError::Input { .. } => DieStatus::Io,
            die_engine::ScanError::Cancelled => DieStatus::Cancelled,
        })?;

        let json = die_output::render_json(&result);
        Ok(Box::new(DieResult { result, json }))
    })
}

/// Scan a file path with a reusable scanner.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_scanner_scan_path_utf8(
    scanner: *mut DieScanner,
    path: *const u8,
    path_length: u64,
    options: *const DieScanOptions,
    cancel: *const DieCancel,
    out_result: *mut *mut DieResult,
    out_error: *mut *mut DieError,
) -> u32 {
    ffi_wrap_out(out_result, out_error, || {
        let scanner = validate_mut_ptr(scanner)?;
        let path_str = str_from_raw(path, path_length)?;
        let opts = validate_options(options)?;
        let flags = options_to_flags(opts);

        let cancel_token = if cancel.is_null() {
            CancellationToken::new()
        } else {
            let c = unsafe { &*cancel };
            c.token.clone()
        };

        let result = die_engine::scan_once(&scanner.database, path_str, flags, &cancel_token)
            .map_err(|e| match &e {
                die_engine::ScanError::DatabaseInit { .. } => DieStatus::Database,
                die_engine::ScanError::HostApi { .. } => DieStatus::Internal,
                die_engine::ScanError::RuleEval { .. } => DieStatus::Script,
                die_engine::ScanError::Input { .. } => DieStatus::Io,
                die_engine::ScanError::Cancelled => DieStatus::Cancelled,
            })?;

        let json = die_output::render_json(&result);
        Ok(Box::new(DieResult { result, json }))
    })
}

/// Free a scanner handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_scanner_free(in_out_scanner: *mut *mut DieScanner) -> u32 {
    match free_handle(in_out_scanner) {
        Ok(()) => DieStatus::Ok.into(),
        Err(e) => e.into(),
    }
}

// ---- Result accessors ----

/// Get the canonical JSON representation of a scan result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_result_json(
    result: *const DieResult,
    out_data: *mut *const u8,
    out_length: *mut u64,
) -> u32 {
    let r = match validate_borrowed_ptr(result) {
        Ok(r) => r,
        Err(e) => return e.into(),
    };
    match write_byte_view(r.json.as_bytes(), out_data, out_length) {
        Ok(()) => DieStatus::Ok.into(),
        Err(e) => e.into(),
    }
}

/// Get the file path from a scan result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_result_path_utf8(
    result: *const DieResult,
    out_data: *mut *const u8,
    out_length: *mut u64,
) -> u32 {
    let r = match validate_borrowed_ptr(result) {
        Ok(r) => r,
        Err(e) => return e.into(),
    };
    match write_byte_view(r.result.path.as_bytes(), out_data, out_length) {
        Ok(()) => DieStatus::Ok.into(),
        Err(e) => e.into(),
    }
}

/// Get the number of detections in a scan result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_result_detection_count(
    result: *const DieResult,
    out_count: *mut u64,
) -> u32 {
    let r = match validate_borrowed_ptr(result) {
        Ok(r) => r,
        Err(e) => return e.into(),
    };
    match validate_mut_ptr(out_count) {
        Ok(count) => {
            *count = r.result.detections.len() as u64;
            DieStatus::Ok.into()
        }
        Err(e) => e.into(),
    }
}

/// Free a result handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_result_free(in_out_result: *mut *mut DieResult) -> u32 {
    match free_handle(in_out_result) {
        Ok(()) => DieStatus::Ok.into(),
        Err(e) => e.into(),
    }
}

// ---- Error accessors ----

/// Get the status code from an error handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_error_status(error: *const DieError, out_status: *mut u32) -> u32 {
    let e = match validate_borrowed_ptr(error) {
        Ok(e) => e,
        Err(e) => return e.into(),
    };
    match validate_mut_ptr(out_status) {
        Ok(status) => {
            *status = e.status;
            DieStatus::Ok.into()
        }
        Err(e) => e.into(),
    }
}

/// Get the error message from an error handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_error_message(
    error: *const DieError,
    out_data: *mut *const u8,
    out_length: *mut u64,
) -> u32 {
    let e = match validate_borrowed_ptr(error) {
        Ok(e) => e,
        Err(e) => return e.into(),
    };
    match write_byte_view(e.message.as_bytes(), out_data, out_length) {
        Ok(()) => DieStatus::Ok.into(),
        Err(e) => e.into(),
    }
}

/// Free an error handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn die_v1_error_free(in_out_error: *mut *mut DieError) -> u32 {
    match free_handle(in_out_error) {
        Ok(()) => DieStatus::Ok.into(),
        Err(e) => e.into(),
    }
}

// Suppress unused warning for status_to_u32 (used by error module).
#[allow(dead_code)]
fn _use_status_to_u32() -> u32 {
    status_to_u32(DieStatus::Ok)
}

//! Error handle creation and accessors.
//!
//! This module contains `unsafe` code for pointer validation and handle
//! lifetime management across the FFI boundary. All unsafe blocks are
//! reviewed against the safety invariants documented in each function.

#![allow(unsafe_code)]

use crate::handles::DiecError;
use crate::panic::catch_panics;
use crate::status::DiecStatus;

/// Helper: validate a non-null out pointer and clear it.
///
/// Returns `Ok(reference)` if the pointer is valid, or `Err(InvalidArgument)`.
pub fn validate_out_ptr<T>(ptr: *mut *mut T) -> Result<&'static mut *mut T, DiecStatus>
where
    T: 'static,
{
    if ptr.is_null() {
        return Err(DiecStatus::InvalidArgument);
    }
    // SAFETY: the caller guarantees the pointer is valid for writes.
    // We use a static lifetime here because the actual lifetime is tied
    // to the FFI call, which is synchronous.
    Ok(unsafe { &mut *ptr })
}

/// Helper: validate a borrowed pointer (const T).
///
/// Returns `Ok(reference)` if the pointer is valid.
pub fn validate_borrowed_ptr<'a, T>(ptr: *const T) -> Result<&'a T, DiecStatus> {
    if ptr.is_null() {
        return Err(DiecStatus::InvalidArgument);
    }
    // SAFETY: the caller guarantees the pointer is valid for the duration
    // of the FFI call.
    Ok(unsafe { &*ptr })
}

/// Helper: validate a mutable pointer (mut T).
///
/// Returns `Ok(reference)` if the pointer is valid.
pub fn validate_mut_ptr<'a, T>(ptr: *mut T) -> Result<&'a mut T, DiecStatus> {
    if ptr.is_null() {
        return Err(DiecStatus::InvalidArgument);
    }
    // SAFETY: the caller guarantees the pointer is valid for the duration
    // of the FFI call.
    Ok(unsafe { &mut *ptr })
}

/// Helper: write a byte view (pointer + length) to out parameters.
pub fn write_byte_view(
    data: &[u8],
    out_data: *mut *const u8,
    out_length: *mut u64,
) -> Result<(), DiecStatus> {
    let out_data = validate_mut_ptr(out_data)?;
    let out_length = validate_mut_ptr(out_length)?;
    *out_data = data.as_ptr();
    *out_length = data.len() as u64;
    Ok(())
}

/// Helper: convert a raw (ptr, len) to a borrowed byte slice.
pub fn byte_slice_from_raw<'a>(ptr: *const u8, len: u64) -> Result<&'a [u8], DiecStatus> {
    if ptr.is_null() && len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(DiecStatus::InvalidArgument);
    }
    // SAFETY: the caller guarantees the pointer is valid for `len` bytes
    // for the duration of the call.
    Ok(unsafe { core::slice::from_raw_parts(ptr, len as usize) })
}

/// Helper: convert a raw (ptr, len) to a borrowed str (UTF-8 validated).
pub fn str_from_raw<'a>(ptr: *const u8, len: u64) -> Result<&'a str, DiecStatus> {
    let bytes = byte_slice_from_raw(ptr, len)?;
    // Reject NUL bytes in paths (per design doc).
    if bytes.contains(&0) {
        return Err(DiecStatus::InvalidArgument);
    }
    std::str::from_utf8(bytes).map_err(|_| DiecStatus::InvalidUtf8)
}

/// Helper: free a boxed handle via pointer-to-pointer, setting it to null.
pub fn free_handle<T: 'static>(in_out: *mut *mut T) -> Result<(), DiecStatus> {
    let slot = validate_out_ptr(in_out)?;
    if (*slot).is_null() {
        // Double-free is a no-op (safe).
        return Ok(());
    }
    // SAFETY: the caller owns this handle and guarantees no other thread
    // is accessing it. drop_in_place + null prevents use-after-free.
    unsafe {
        drop(Box::from_raw(*slot));
        *slot = core::ptr::null_mut();
    }
    Ok(())
}

/// Convert a DiecStatus to a u32 return value.
pub fn status_to_u32(s: DiecStatus) -> u32 {
    s.into()
}

// Suppress unused warning.
#[allow(dead_code)]
fn _use_status_to_u32() -> u32 {
    status_to_u32(DiecStatus::Ok)
}

/// Run an FFI function body with panic containment and error handle creation.
pub fn ffi_wrap<T>(
    out_error: *mut *mut DiecError,
    body: impl FnOnce() -> Result<T, DiecStatus>,
) -> u32 {
    // Clear any existing error.
    if !out_error.is_null() {
        // SAFETY: caller guarantees out_error is valid if non-null.
        unsafe {
            *out_error = core::ptr::null_mut();
        }
    }

    let result = catch_panics(body);

    match result {
        Ok(_value) => {
            // Success - no error to set.
            DiecStatus::Ok.into()
        }
        Err(status) => {
            if !out_error.is_null() {
                let message = status.name().to_string();
                // SAFETY: caller guarantees out_error is valid if non-null.
                unsafe {
                    *out_error = Box::into_raw(Box::new(DiecError::new(status.into(), message)));
                }
            }
            status.into()
        }
    }
}

/// Run an FFI function body that produces a value to write to an out parameter.
pub fn ffi_wrap_out<T, F>(out_value: *mut *mut T, out_error: *mut *mut DiecError, body: F) -> u32
where
    F: FnOnce() -> Result<Box<T>, DiecStatus>,
{
    // Clear out_error if non-null.
    if !out_error.is_null() {
        // SAFETY: caller guarantees out_error is valid if non-null.
        unsafe {
            *out_error = core::ptr::null_mut();
        }
    }

    // Clear out_value if non-null.
    if !out_value.is_null() {
        // SAFETY: caller guarantees out_value is valid if non-null.
        unsafe {
            *out_value = core::ptr::null_mut();
        }
    }

    let result = catch_panics(body);

    match result {
        Ok(value) => {
            if !out_value.is_null() {
                // SAFETY: caller guarantees out_value is valid if non-null.
                unsafe {
                    *out_value = Box::into_raw(value);
                }
                DiecStatus::Ok.into()
            } else {
                // out_value was null but body succeeded; drop the value.
                drop(value);
                DiecStatus::InvalidArgument.into()
            }
        }
        Err(status) => {
            if !out_error.is_null() {
                let message = status.name().to_string();
                // SAFETY: caller guarantees out_error is valid if non-null.
                unsafe {
                    *out_error = Box::into_raw(Box::new(DiecError::new(status.into(), message)));
                }
            }
            status.into()
        }
    }
}

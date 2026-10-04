#![deny(unsafe_op_in_unsafe_fn)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::slice;

const ABI_VERSION: u32 = 1;
const STATUS_OK: u32 = 0;
const STATUS_INVALID_ARGUMENT: u32 = 1;
const STATUS_INPUT_TOO_LARGE: u32 = 2;
const STATUS_PANIC: u32 = 3;
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

#[cfg(not(panic = "unwind"))]
compile_error!("the C static-link spike requires panic=unwind");

#[repr(C)]
pub struct DieSpikeResult {
    json: Box<[u8]>,
}

fn ffi_boundary(operation: impl FnOnce() -> Result<(), u32>) -> u32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(status)) => status,
        Err(_) => STATUS_PANIC,
    }
}

fn status_bytes(status: u32) -> Option<&'static [u8]> {
    match status {
        STATUS_OK => Some(b"ok"),
        STATUS_INVALID_ARGUMENT => Some(b"invalid argument"),
        STATUS_INPUT_TOO_LARGE => Some(b"input too large"),
        STATUS_PANIC => Some(b"panic contained at FFI boundary"),
        _ => None,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn die_spike_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
/// Creates an owned result from a borrowed input byte range.
///
/// # Safety
///
/// `out_result` must be writable. When `length` is nonzero, `data` must
/// address at least `length` readable bytes for the duration of this call.
pub unsafe extern "C" fn die_spike_scan(
    data: *const u8,
    length: u64,
    out_result: *mut *mut DieSpikeResult,
) -> u32 {
    ffi_boundary(|| {
        if out_result.is_null() {
            return Err(STATUS_INVALID_ARGUMENT);
        }

        // SAFETY: A non-null output pointer is required by the C contract.
        unsafe {
            *out_result = ptr::null_mut();
        }

        if length > MAX_INPUT_BYTES {
            return Err(STATUS_INPUT_TOO_LARGE);
        }
        if length != 0 && data.is_null() {
            return Err(STATUS_INVALID_ARGUMENT);
        }

        let length = usize::try_from(length).map_err(|_| STATUS_INPUT_TOO_LARGE)?;
        let bytes = if length == 0 {
            &[]
        } else {
            // SAFETY: The C contract requires `data` to address `length`
            // readable bytes for the duration of this call. Length is capped
            // before the slice is constructed.
            unsafe { slice::from_raw_parts(data, length) }
        };
        let sum = bytes
            .iter()
            .fold(0_u64, |total, byte| total + u64::from(*byte));
        let json = format!(
            "{{\"schema_version\":1,\"size\":{},\"sum\":{sum}}}",
            bytes.len()
        )
        .into_bytes()
        .into_boxed_slice();
        let result = Box::into_raw(Box::new(DieSpikeResult { json }));

        // SAFETY: `out_result` was checked above and the newly allocated
        // result transfers exactly one ownership reference to the caller.
        unsafe {
            *out_result = result;
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// Returns a byte view borrowed from an owned result.
///
/// # Safety
///
/// `result` must be null or a live handle returned by `die_spike_scan`.
/// Both output pointers must be writable when non-null.
pub unsafe extern "C" fn die_spike_result_json(
    result: *const DieSpikeResult,
    out_data: *mut *const u8,
    out_length: *mut u64,
) -> u32 {
    ffi_boundary(|| {
        if out_data.is_null() || out_length.is_null() {
            return Err(STATUS_INVALID_ARGUMENT);
        }

        // SAFETY: Both output pointers were checked above.
        unsafe {
            *out_data = ptr::null();
            *out_length = 0;
        }
        if result.is_null() {
            return Err(STATUS_INVALID_ARGUMENT);
        }

        // SAFETY: A non-null opaque result must originate from
        // `die_spike_scan` and remain owned by the caller.
        let result = unsafe { &*result };
        let length = u64::try_from(result.json.len()).map_err(|_| STATUS_INPUT_TOO_LARGE)?;

        // SAFETY: Both output pointers are valid by contract. The returned
        // byte view remains valid until the owning result is freed.
        unsafe {
            *out_data = result.json.as_ptr();
            *out_length = length;
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// Releases a result and writes null to the caller's handle variable.
///
/// # Safety
///
/// `in_out_result` must be writable. Its pointee must be null or the unique
/// live handle returned by `die_spike_scan`.
pub unsafe extern "C" fn die_spike_result_free(in_out_result: *mut *mut DieSpikeResult) -> u32 {
    ffi_boundary(|| {
        if in_out_result.is_null() {
            return Err(STATUS_INVALID_ARGUMENT);
        }

        // SAFETY: The outer pointer is non-null and writable by contract.
        let result = unsafe {
            let result = *in_out_result;
            *in_out_result = ptr::null_mut();
            result
        };
        if !result.is_null() {
            // SAFETY: A non-null pointer must be the unique allocation
            // returned by `die_spike_scan`. It is nulled before destruction,
            // making a second call with the same C variable idempotent.
            unsafe {
                drop(Box::from_raw(result));
            }
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// Returns a static byte view describing a status code.
///
/// # Safety
///
/// Both output pointers must be writable when non-null.
pub unsafe extern "C" fn die_spike_status_message(
    status: u32,
    out_data: *mut *const u8,
    out_length: *mut u64,
) -> u32 {
    ffi_boundary(|| {
        if out_data.is_null() || out_length.is_null() {
            return Err(STATUS_INVALID_ARGUMENT);
        }

        // SAFETY: Both output pointers were checked above.
        unsafe {
            *out_data = ptr::null();
            *out_length = 0;
        }
        let message = status_bytes(status).ok_or(STATUS_INVALID_ARGUMENT)?;
        let length = u64::try_from(message.len()).map_err(|_| STATUS_INPUT_TOO_LARGE)?;

        // SAFETY: Both output pointers are valid by contract. Message bytes
        // have static lifetime and never require caller deallocation.
        unsafe {
            *out_data = message.as_ptr();
            *out_length = length;
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn die_spike_force_panic() -> u32 {
    ffi_boundary(|| -> Result<(), u32> {
        panic!("intentional C ABI containment probe");
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ABI_VERSION, DieSpikeResult, MAX_INPUT_BYTES, STATUS_INPUT_TOO_LARGE,
        STATUS_INVALID_ARGUMENT, STATUS_OK, die_spike_abi_version, die_spike_result_free,
        die_spike_result_json, die_spike_scan, die_spike_status_message,
    };
    use std::ptr;
    use std::slice;

    #[test]
    fn scan_returns_borrowed_json_and_free_nulls_handle() {
        let input = [1_u8, 2, 3, 4];
        let mut result = ptr::null_mut();
        // SAFETY: Input and output ranges remain valid for the calls.
        unsafe {
            assert_eq!(
                die_spike_scan(input.as_ptr(), input.len() as u64, &mut result),
                STATUS_OK
            );
        }
        assert!(!result.is_null());

        let mut json_data = ptr::null();
        let mut json_length = 0;
        // SAFETY: `result` is live and both output pointers are writable.
        unsafe {
            assert_eq!(
                die_spike_result_json(result, &mut json_data, &mut json_length),
                STATUS_OK
            );
        }
        // SAFETY: The result remains alive and owns this reported byte range.
        let json = unsafe { slice::from_raw_parts(json_data, json_length as usize) };
        assert_eq!(json, br#"{"schema_version":1,"size":4,"sum":10}"#);

        // SAFETY: The handle variable is writable and owns the live result.
        assert_eq!(unsafe { die_spike_result_free(&mut result) }, STATUS_OK);
        assert!(result.is_null());
        // SAFETY: A writable null handle is accepted and remains null.
        assert_eq!(unsafe { die_spike_result_free(&mut result) }, STATUS_OK);
    }

    #[test]
    fn invalid_inputs_clear_output_and_return_status() {
        let mut result = ptr::dangling_mut::<DieSpikeResult>();
        // SAFETY: The output pointer is writable; invalid input is the case
        // under test and is rejected before dereference.
        unsafe {
            assert_eq!(
                die_spike_scan(ptr::null(), 1, &mut result),
                STATUS_INVALID_ARGUMENT
            );
        }
        assert!(result.is_null());

        let byte = 0_u8;
        // SAFETY: The output pointer is writable and the oversized length is
        // rejected before the one-byte input could be read.
        unsafe {
            assert_eq!(
                die_spike_scan(&byte, MAX_INPUT_BYTES + 1, &mut result),
                STATUS_INPUT_TOO_LARGE
            );
        }
        assert!(result.is_null());
        // SAFETY: Null pointers intentionally exercise argument validation.
        unsafe {
            assert_eq!(
                die_spike_scan(ptr::null(), 0, ptr::null_mut()),
                STATUS_INVALID_ARGUMENT
            );
        }
    }

    #[test]
    fn version_and_static_status_message_are_stable() {
        assert_eq!(die_spike_abi_version(), ABI_VERSION);
        let mut data = ptr::null();
        let mut length = 0;
        // SAFETY: Both output pointers are writable.
        unsafe {
            assert_eq!(
                die_spike_status_message(STATUS_INPUT_TOO_LARGE, &mut data, &mut length),
                STATUS_OK
            );
        }
        // SAFETY: Status messages have static lifetime.
        let message = unsafe { slice::from_raw_parts(data, length as usize) };
        assert_eq!(message, b"input too large");
    }
}

#![deny(unsafe_op_in_unsafe_fn)]

use rquickjs::{Context, Runtime};
use std::panic::{AssertUnwindSafe, catch_unwind};

const STATUS_OK: u32 = 0;
const STATUS_INVALID_ARGUMENT: u32 = 1;
const STATUS_RUNTIME_ERROR: u32 = 2;
const STATUS_PANIC: u32 = 3;

#[cfg(not(panic = "unwind"))]
compile_error!("the rquickjs static-link spike requires panic=unwind");

fn ffi_boundary(operation: impl FnOnce() -> Result<(), u32>) -> u32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(status)) => status,
        Err(_) => STATUS_PANIC,
    }
}

fn evaluate() -> Result<i32, u32> {
    let runtime = Runtime::new().map_err(|_| STATUS_RUNTIME_ERROR)?;
    let context = Context::full(&runtime).map_err(|_| STATUS_RUNTIME_ERROR)?;
    context.with(|context| {
        context
            .eval::<i32, _>("40 + 2")
            .map_err(|_| STATUS_RUNTIME_ERROR)
    })
}

#[unsafe(no_mangle)]
/// Creates a real QuickJS-NG runtime/context and evaluates `40 + 2`.
///
/// # Safety
///
/// `out_value` must be writable for one `i32`.
pub unsafe extern "C" fn die_rquickjs_spike_eval(out_value: *mut i32) -> u32 {
    ffi_boundary(|| {
        if out_value.is_null() {
            return Err(STATUS_INVALID_ARGUMENT);
        }
        let value = evaluate()?;
        // SAFETY: The C contract requires a writable non-null output pointer.
        unsafe {
            *out_value = value;
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn die_rquickjs_spike_force_panic() -> u32 {
    ffi_boundary(|| -> Result<(), u32> {
        panic!("intentional rquickjs static-link containment probe");
    })
}

#[cfg(test)]
mod tests {
    use super::{
        STATUS_INVALID_ARGUMENT, STATUS_OK, STATUS_PANIC, die_rquickjs_spike_eval,
        die_rquickjs_spike_force_panic,
    };
    use std::ptr;

    #[test]
    fn evaluates_with_real_runtime_repeatedly() {
        for _ in 0..16 {
            let mut value = 0;
            // SAFETY: `value` is writable for the duration of the call.
            let status = unsafe { die_rquickjs_spike_eval(&mut value) };
            assert_eq!(status, STATUS_OK);
            assert_eq!(value, 42);
        }
    }

    #[test]
    fn ffi_boundary_rejects_null_and_contains_panic() {
        // SAFETY: Null intentionally exercises argument validation.
        let status = unsafe { die_rquickjs_spike_eval(ptr::null_mut()) };
        assert_eq!(status, STATUS_INVALID_ARGUMENT);
        assert_eq!(die_rquickjs_spike_force_panic(), STATUS_PANIC);
    }
}

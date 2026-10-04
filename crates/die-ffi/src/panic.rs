//! Panic containment for FFI boundary.
//!
//! All FFI functions must catch panics to prevent unwinding across the
//! C boundary, which is undefined behavior. This module provides a
//! helper that wraps a closure in `catch_unwind`.

use crate::status::DieStatus;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Run a closure with panic containment.
///
/// Returns `Ok(result)` on success, or `Err(DieStatus::Panic)` if a panic
/// was caught. The closure's `Result` error type should be converted to
/// a `DieStatus` by the caller.
pub fn catch_panics<F, T>(f: F) -> Result<T, DieStatus>
where
    F: FnOnce() -> Result<T, DieStatus>,
{
    // AssertUnwindSafe is acceptable here because:
    // 1. FFI functions do not share mutable state across calls.
    // 2. On panic, the handle is left in a consistent state (the error
    //    path does not use any partially-constructed values from the closure).
    // 3. The closure is consumed (FnOnce), so there is no aliasing.
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(inner) => inner,
        Err(_) => Err(DieStatus::Panic),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_panic() {
        let result: Result<i32, DieStatus> = catch_panics(|| {
            panic!("test panic");
        });
        assert_eq!(result, Err(DieStatus::Panic));
    }

    #[test]
    fn passes_through_ok() {
        let result = catch_panics(|| Ok::<_, DieStatus>(42));
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn passes_through_err() {
        let result = catch_panics(|| Err::<i32, _>(DieStatus::Io));
        assert_eq!(result, Err(DieStatus::Io));
    }
}

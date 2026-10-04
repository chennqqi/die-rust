//! One-way, idempotent cancellation token.
//!
//! The token is `Clone + Send + Sync` and shares its cancellation state across
//! clones, so requesting cancellation on any clone is observed by all holders.
//! The Rust API does not provide a reset during a scan; callers create a new
//! token for reuse to avoid reset/reader races. The C ABI reset, if retained,
//! may only be called when no scan holds a reference. See
//! `docs/design/api.md` section 9 and ADR 0009.

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// One-way, idempotent cancellation token backed by a shared atomic flag.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Construct a non-cancelled token.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request cancellation. Idempotent: repeated calls have no extra effect.
    /// Visible to all clones of this token.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// `true` if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::CancellationToken;

    #[test]
    fn cancellation_propagates_to_clones() {
        let parent = CancellationToken::new();
        let child = parent.clone();
        assert!(!parent.is_cancelled());
        assert!(!child.is_cancelled());
        parent.cancel();
        assert!(parent.is_cancelled());
        assert!(child.is_cancelled());
    }

    #[test]
    fn cancel_is_idempotent() {
        let t = CancellationToken::new();
        t.cancel();
        t.cancel();
        assert!(t.is_cancelled());
    }
}

//! Opaque handle types for the C ABI.
//!
//! Each handle is a heap-allocated Rust struct that is only exposed to C
//! as an opaque forward declaration. The C side never sees the layout.

use die_core::cancel::CancellationToken;
use die_engine::{Database, DatabaseBuilder, ScanResult};
use std::sync::Arc;

/// Opaque database builder handle.
pub struct DiecDatabaseBuilder {
    /// The inner Rust builder.
    pub builder: DatabaseBuilder,
}

/// Opaque database handle.
/// Wrapped in Arc so scanner can share ownership.
pub struct DiecDatabase {
    /// The inner Rust database, shared with scanners.
    pub database: Arc<Database>,
}

/// Opaque scanner handle.
pub struct DiecScanner {
    /// Shared database reference.
    pub database: Arc<Database>,
}

/// Opaque cancel token handle.
pub struct DiecCancel {
    /// The inner cancellation token.
    pub token: CancellationToken,
}

/// Opaque result handle.
pub struct DiecResult {
    /// The inner scan result.
    pub result: ScanResult,
    /// Pre-rendered canonical JSON.
    pub json: String,
}

/// Opaque error handle.
pub struct DiecError {
    /// The status code.
    pub status: u32,
    /// Human-readable error message (UTF-8).
    pub message: String,
}

impl DiecError {
    /// Create a new error handle from a status and message.
    pub fn new(status: u32, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

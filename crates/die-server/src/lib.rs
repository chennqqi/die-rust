//! `die-server` is the HTTP/JSON scan service layer (ADR 0017).
//!
//! It is a thin adapter over `die-engine`, providing:
//! - `GET /health` — service status and version info
//! - `POST /scan/path` — scan a local file by path
//! - `POST /scan/bytes` — scan uploaded file content
//!
//! The service layer never duplicates detection logic. It delegates to
//! `die_engine::scan_bytes` for each request. The `Database` is loaded
//! once at startup and shared via `Arc`, avoiding repeated rule loading
//! (the main cost in CLI subprocess invocation).
//!
//! Runtime reuse (ADR 0016 `Scanner`) requires a dedicated worker thread
//! because `RquickjsRuntime` is `!Send`. This is a future optimization;
//! the current server already eliminates the per-process database load
//! cost, which is the primary overhead in batch CLI invocation.
//!
//! See `docs/design/decisions/0017-scan-service-layer.md` for the full
//! design and security boundary.

#![forbid(unsafe_code)]

mod config;
mod error;
mod handlers;
pub mod routes;

pub use config::ServerConfig;
pub use error::ServerError;

use std::sync::Arc;

use die_engine::Database;

/// Shared application state accessible to all request handlers.
///
/// Contains the immutable database (loaded once, shared across all
/// requests) and server configuration.
pub struct AppState {
    /// The immutable database, shared across all scans.
    pub database: Arc<Database>,
    /// Server configuration (limits, allowed roots, etc.).
    pub config: ServerConfig,
}

impl AppState {
    /// Create new application state from a database and config.
    pub fn new(database: Arc<Database>, config: ServerConfig) -> Self {
        Self { database, config }
    }
}

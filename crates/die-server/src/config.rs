//! Server configuration (ADR 0017).

use std::path::PathBuf;

/// Configuration for the diec scan server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Bind address (default: `127.0.0.1:0` — local only).
    pub bind: String,
    /// Maximum file size for `/scan/path` in bytes (default: 256 MiB).
    pub max_file_size: usize,
    /// Maximum request body size for `/scan/bytes` in bytes (default: 256 MiB).
    pub max_request_size: usize,
    /// Scan timeout in seconds (default: 30).
    pub scan_timeout_secs: u64,
    /// Optional allowed root directory for `/scan/path`.
    /// If set, file paths must canonicalize under this root.
    pub allow_root: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:0".to_string(),
            max_file_size: 256 * 1024 * 1024,
            max_request_size: 256 * 1024 * 1024,
            scan_timeout_secs: 30,
            allow_root: None,
        }
    }
}

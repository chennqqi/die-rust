//! Managed application state for the die-gui Tauri backend.
//!
//! `AppState` holds the scan engine `Database` (loaded once, reused
//! across scans via `Arc`) and the current `CancellationToken` for
//! cooperative scan cancellation.

use die_core::cancel::CancellationToken;
use die_engine::{Database, DatabaseBuilder};
use std::sync::{Arc, Mutex};

/// The managed state shared across all Tauri IPC commands.
pub struct AppState {
    /// The rule database, loaded lazily on first scan.
    /// Stored behind `Arc` for cheap cloning into scan tasks.
    database: Mutex<Option<Arc<Database>>>,
    /// The current scan's cancellation token, if a scan is running.
    cancel_token: Mutex<Option<CancellationToken>>,
    /// The database path key (joined paths) for cache invalidation.
    db_path_key: Mutex<String>,
}

impl AppState {
    /// Create a new `AppState` with no loaded database.
    pub fn new() -> Self {
        Self {
            database: Mutex::new(None),
            cancel_token: Mutex::new(None),
            db_path_key: Mutex::new(String::new()),
        }
    }

    /// Get or load the database, returning an `Arc` clone.
    ///
    /// The database is loaded on first call and cached for subsequent
    /// scans. If the `db_paths` key changes, the cached database is
    /// discarded and reloaded.
    ///
    /// # Arguments
    /// * `db_paths` - One or more database directory paths. The first is
    ///   the main database; subsequent paths are merged as extra databases.
    pub fn database(&self, db_paths: &[String]) -> Result<Arc<Database>, String> {
        let key = db_paths.join(";");
        let mut guard = self.database.lock().expect("database mutex poisoned");
        let mut cached_key = self.db_path_key.lock().expect("db_path_key mutex poisoned");
        if let Some(ref db) = *guard
            && *cached_key == key
        {
            return Ok(Arc::clone(db));
        }

        if db_paths.is_empty() {
            return Err("No database path provided".to_string());
        }
        let mut builder = DatabaseBuilder::new(&db_paths[0]);
        for extra in &db_paths[1..] {
            builder = builder.with_extra(extra);
        }
        let db = builder.build().map_err(|e| e.to_string())?;
        let arc = Arc::new(db);
        *guard = Some(Arc::clone(&arc));
        *cached_key = key;
        Ok(arc)
    }

    /// Start a new scan, returning a `CancellationToken` that the
    /// frontend can trigger via `stop_scan`.
    pub fn start_scan(&self) -> CancellationToken {
        let token = CancellationToken::new();
        *self
            .cancel_token
            .lock()
            .expect("cancel_token mutex poisoned") = Some(token.clone());
        token
    }

    /// Cancel the current scan, if any.
    pub fn stop_scan(&self) {
        if let Some(token) = self
            .cancel_token
            .lock()
            .expect("cancel_token mutex poisoned")
            .take()
        {
            token.cancel();
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

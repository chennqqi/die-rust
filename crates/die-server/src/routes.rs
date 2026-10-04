//! HTTP route definitions (ADR 0017).

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::AppState;
use crate::handlers;

/// Build the application router with all routes.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/scan/path", post(handlers::scan_path))
        .route("/scan/bytes", post(handlers::scan_bytes))
        .with_state(state)
}

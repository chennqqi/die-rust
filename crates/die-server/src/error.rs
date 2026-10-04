//! Error types for the scan service (ADR 0017).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Error type for server operations.
#[derive(Debug)]
pub enum ServerError {
    /// The requested file path was not found.
    NotFound(String),
    /// The file path is outside the allowed root.
    PathNotAllowed(String),
    /// The file exceeds the maximum size limit.
    FileTooLarge { path: String, size: u64, max: usize },
    /// The request body exceeds the maximum size limit.
    RequestTooLarge { size: usize, max: usize },
    /// A scan error from the engine.
    ScanError(String),
    /// An I/O error.
    IoError(String),
    /// The scan timed out.
    Timeout,
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::NotFound(msg) => write!(f, "not found: {msg}"),
            ServerError::PathNotAllowed(msg) => write!(f, "path not allowed: {msg}"),
            ServerError::FileTooLarge { path, size, max } => {
                write!(f, "file too large: {path} is {size} bytes (max {max})")
            }
            ServerError::RequestTooLarge { size, max } => {
                write!(f, "request too large: {size} bytes (max {max})")
            }
            ServerError::ScanError(msg) => write!(f, "scan error: {msg}"),
            ServerError::IoError(msg) => write!(f, "I/O error: {msg}"),
            ServerError::Timeout => write!(f, "scan timed out"),
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ServerError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            ServerError::PathNotAllowed(_) => (StatusCode::FORBIDDEN, self.to_string()),
            ServerError::FileTooLarge { .. } => (StatusCode::PAYLOAD_TOO_LARGE, self.to_string()),
            ServerError::RequestTooLarge { .. } => {
                (StatusCode::PAYLOAD_TOO_LARGE, self.to_string())
            }
            ServerError::ScanError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ServerError::IoError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ServerError::Timeout => (StatusCode::REQUEST_TIMEOUT, self.to_string()),
        };
        let body = json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

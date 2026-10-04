//! Request handlers for the scan service (ADR 0017).

use std::path::Path;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::error::ServerError;

/// Scan flags passed by the client, mirroring `diec_engine::ScanFlags`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanFlagsRequest {
    /// Enable all file type rules (--alltypes).
    #[serde(default)]
    pub all_types: bool,
    /// Enable deep scan mode.
    #[serde(default)]
    pub deep: bool,
    /// Enable heuristic scan mode.
    #[serde(default)]
    pub heuristic: bool,
    /// Enable aggressive scan mode.
    #[serde(default)]
    pub aggressive: bool,
    /// Hide unknown detections.
    #[serde(default)]
    pub hide_unknown: bool,
    /// Enable verbose output.
    #[serde(default)]
    pub verbose: bool,
    /// Disable result deduplication (--no-dedup).
    #[serde(default)]
    pub no_dedup: bool,
    /// Intra-file recursive scan (-r/--recursivescan).
    #[serde(default)]
    pub recursive: bool,
    /// Scan PE resources.
    #[serde(default)]
    pub resources: bool,
    /// Scan PE overlay.
    #[serde(default)]
    pub overlays: bool,
    /// Scan archive members.
    #[serde(default)]
    pub archives: bool,
    /// Optional archive extraction bounds override (ADR 0030).
    #[serde(default)]
    pub archive_limits: Option<diec_engine::ArchiveLimits>,
}

impl From<ScanFlagsRequest> for diec_engine::ScanFlags {
    fn from(req: ScanFlagsRequest) -> Self {
        diec_engine::ScanFlags {
            all_types: req.all_types,
            deep: req.deep,
            heuristic: req.heuristic,
            aggressive: req.aggressive,
            hide_unknown: req.hide_unknown,
            verbose: req.verbose,
            nfd: false,
            no_dedup: req.no_dedup,
            file_type: None,
            recursive: req.recursive,
            resources: req.resources,
            overlays: req.overlays,
            archives: req.archives,
            archive_limits: req.archive_limits.unwrap_or_default(),
        }
    }
}

/// Request body for `/scan/path`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanPathRequest {
    /// Absolute or relative file path on the server.
    pub path: String,
    /// Scan flags.
    #[serde(default)]
    pub flags: ScanFlagsRequest,
}

/// A single detection in the response.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionResponse {
    pub file_type: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub name: String,
    pub version: Option<String>,
    pub options: Option<String>,
    pub id: Option<String>,
    pub parent_id: Option<String>,
    pub file_part: Option<String>,
    pub offset: Option<u64>,
    pub size: Option<u64>,
    pub is_heuristic: Option<bool>,
    pub is_a_heuristic: Option<bool>,
    pub original_name: Option<String>,
}

/// Database version info in the response.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseVersionResponse {
    pub commit: String,
    pub rule_count: usize,
    pub synced_at: String,
}

/// Health check response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: String,
    pub program_version: String,
    pub db_version: DatabaseVersionResponse,
}

/// A structured diagnostic entry.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredDiagnosticResponse {
    pub file: String,
    pub line: Option<u32>,
    pub message: String,
    pub kind: String,
}

/// Per-signature profiling entry.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureProfileResponse {
    pub file: String,
    pub elapsed_ms: u64,
}

/// Scan result response (used by both `/scan/path` and `/scan/bytes`).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResponse {
    pub path: String,
    pub detections: Vec<DetectionResponse>,
    pub diagnostics: Vec<String>,
    pub structured_diagnostics: Vec<StructuredDiagnosticResponse>,
    pub profiling: Vec<SignatureProfileResponse>,
    pub program_version: String,
    pub db_version: DatabaseVersionResponse,
}

/// `GET /health` — return service status and version info.
pub async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let db_version = state.database.version();
    Json(HealthResponse {
        status: "ok".to_string(),
        program_version: env!("CARGO_PKG_VERSION").to_string(),
        db_version: DatabaseVersionResponse {
            commit: db_version.commit,
            rule_count: db_version.rule_count,
            synced_at: db_version.synced_at,
        },
    })
}

/// `POST /scan/path` — scan a local file by path.
pub async fn scan_path(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanPathRequest>,
) -> Result<Json<ScanResponse>, ServerError> {
    // Validate and canonicalize the path.
    let path = Path::new(&req.path);
    if !path.exists() {
        return Err(ServerError::NotFound(req.path.clone()));
    }

    // Canonicalize to resolve symlinks and `..`.
    let canonical = path
        .canonicalize()
        .map_err(|e| ServerError::IoError(format!("canonicalize {}: {e}", req.path)))?;

    // Check allowed root if configured.
    if let Some(ref allow_root) = state.config.allow_root {
        let allow_canonical = allow_root
            .canonicalize()
            .map_err(|e| ServerError::IoError(format!("canonicalize allow_root: {e}")))?;
        if !canonical.starts_with(&allow_canonical) {
            return Err(ServerError::PathNotAllowed(req.path.clone()));
        }
    }

    // Check file size.
    let metadata = std::fs::metadata(&canonical)
        .map_err(|e| ServerError::IoError(format!("metadata {}: {e}", req.path)))?;
    let file_size = metadata.len() as usize;
    if file_size > state.config.max_file_size {
        return Err(ServerError::FileTooLarge {
            path: req.path.clone(),
            size: metadata.len(),
            max: state.config.max_file_size,
        });
    }

    // Read the file content.
    let data = std::fs::read(&canonical)
        .map_err(|e| ServerError::IoError(format!("read {}: {e}", req.path)))?;

    let file_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&req.path)
        .to_string();

    let flags = diec_engine::ScanFlags::from(req.flags);

    // Run the scan on a blocking thread.
    let database = state.database.clone();
    let timeout_secs = state.config.scan_timeout_secs;
    let scan_file_name = file_name.clone();
    let result = tokio::task::spawn_blocking(move || {
        let cancel = diec_core::cancel::CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Spawn a timeout thread that cancels the scan.
        let timeout_handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(timeout_secs));
            cancel_clone.cancel();
        });

        let result = diec_engine::scan_bytes(&database, &scan_file_name, data, flags, &cancel);
        // The timeout thread may still be sleeping; we don't need to join it.
        drop(timeout_handle);
        result
    })
    .await
    .map_err(|e| ServerError::ScanError(format!("blocking task panicked: {e}")))?
    .map_err(|e| ServerError::ScanError(e.to_string()))?;

    let db_version = state.database.version();
    Ok(Json(build_scan_response(&file_name, result, &db_version)))
}

/// `POST /scan/bytes` — scan uploaded file content.
///
/// The request body is the raw file bytes (`application/octet-stream`).
/// Scan flags are passed as query parameters.
pub async fn scan_bytes(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<ScanBytesQuery>,
    body: axum::body::Bytes,
) -> Result<Json<ScanResponse>, ServerError> {
    let data = body.to_vec();

    let flags = diec_engine::ScanFlags {
        all_types: params.all_types.unwrap_or(false),
        deep: params.deep.unwrap_or(false),
        heuristic: params.heuristic.unwrap_or(false),
        aggressive: params.aggressive.unwrap_or(false),
        hide_unknown: params.hide_unknown.unwrap_or(false),
        verbose: params.verbose.unwrap_or(false),
        nfd: false,
        no_dedup: false,
        file_type: None,
        recursive: params.recursive.unwrap_or(false),
        resources: params.resources.unwrap_or(false),
        overlays: params.overlays.unwrap_or(false),
        archives: params.archives.unwrap_or(false),
        // Query params are scalar; the request-body /scan/path API carries
        // the typed override instead.
        archive_limits: Default::default(),
    };

    let file_name = params.name.unwrap_or_else(|| "uploaded.bin".to_string());

    // Run the scan on a blocking thread.
    let database = state.database.clone();
    let timeout_secs = state.config.scan_timeout_secs;
    let file_name_clone = file_name.clone();
    let result = tokio::task::spawn_blocking(move || {
        let cancel = diec_core::cancel::CancellationToken::new();
        let cancel_clone = cancel.clone();

        let timeout_handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(timeout_secs));
            cancel_clone.cancel();
        });

        let result = diec_engine::scan_bytes(&database, &file_name_clone, data, flags, &cancel);
        drop(timeout_handle);
        result
    })
    .await
    .map_err(|e| ServerError::ScanError(format!("blocking task panicked: {e}")))?
    .map_err(|e| ServerError::ScanError(e.to_string()))?;

    let db_version = state.database.version();
    Ok(Json(build_scan_response(&file_name, result, &db_version)))
}

/// Query parameters for `/scan/bytes`.
#[derive(Debug, Deserialize)]
pub struct ScanBytesQuery {
    pub name: Option<String>,
    pub all_types: Option<bool>,
    pub deep: Option<bool>,
    pub heuristic: Option<bool>,
    pub aggressive: Option<bool>,
    pub hide_unknown: Option<bool>,
    pub verbose: Option<bool>,
    pub recursive: Option<bool>,
    pub resources: Option<bool>,
    pub overlays: Option<bool>,
    pub archives: Option<bool>,
}

/// Build a `ScanResponse` from a `ScanResult`.
fn build_scan_response(
    file_name: &str,
    result: diec_engine::ScanResult,
    db_version: &diec_engine::DatabaseVersion,
) -> ScanResponse {
    ScanResponse {
        path: file_name.to_string(),
        detections: result
            .detections
            .into_iter()
            .map(|d| DetectionResponse {
                file_type: d.file_type,
                type_name: d.type_name,
                name: d.name,
                version: d.version,
                options: d.options,
                id: d.id,
                parent_id: d.parent_id,
                file_part: d.file_part,
                offset: d.offset,
                size: d.size,
                is_heuristic: d.is_heuristic,
                is_a_heuristic: d.is_a_heuristic,
                original_name: d.original_name,
            })
            .collect(),
        diagnostics: result.diagnostics,
        structured_diagnostics: result
            .structured_diagnostics
            .iter()
            .map(|d| StructuredDiagnosticResponse {
                file: d.file.clone(),
                line: d.line,
                message: d.message.clone(),
                kind: d.kind.clone(),
            })
            .collect(),
        profiling: result
            .profiling
            .iter()
            .map(|p| SignatureProfileResponse {
                file: p.file.clone(),
                elapsed_ms: p.elapsed_ms,
            })
            .collect(),
        program_version: env!("CARGO_PKG_VERSION").to_string(),
        db_version: DatabaseVersionResponse {
            commit: db_version.commit.clone(),
            rule_count: db_version.rule_count,
            synced_at: db_version.synced_at.clone(),
        },
    }
}

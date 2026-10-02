//! Tauri IPC commands for die-gui.
//!
//! These commands are the bridge between the React frontend and the
//! `diec-engine` Rust backend. The frontend calls them via
//! `invoke('command_name', { args })`.

use crate::settings::AppSettings;
use crate::state::AppState;
use diec_engine::{ScanDetection, ScanError, ScanFlags, ScanResult, scan_bytes, scan_once};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tauri::Emitter;

/// Structured error DTO for all IPC commands.
///
/// Replaces bare `String` errors to enable frontend error
/// classification, i18n, and logging. See `docs/design/phase8-gui.md`
/// section "IPC Error Model".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiError {
    /// Machine-readable error code (e.g. "DATABASE_LOAD_FAILED").
    pub code: String,
    /// Human-readable message (English, frontend i18n translates).
    pub message: String,
}

impl GuiError {
    /// Create a new `GuiError` with the given code and message.
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

impl From<ScanError> for GuiError {
    fn from(e: ScanError) -> Self {
        let (code, message) = match &e {
            ScanError::DatabaseInit { detail } => ("DATABASE_INIT_FAILED", detail.clone()),
            ScanError::HostApi { detail } => ("HOST_API_FAILED", detail.clone()),
            ScanError::RuleEval { path, detail } => {
                ("RULE_EVAL_FAILED", format!("{}: {}", path, detail))
            }
            ScanError::Input { path, detail } => ("INPUT_ERROR", format!("{}: {}", path, detail)),
            ScanError::Cancelled => ("CANCELLED", "Scan cancelled".to_string()),
        };
        Self::new(code, message)
    }
}

/// Scan flags mirroring upstream `XScanEngine::SF_*` and `comboBoxFlags`.
///
/// Field mapping to `diec-engine::ScanFlags`:
/// - `deep`/`heuristic`/`verbose`/`aggressive`/`alltypes`/`hide_unknown`
///   map directly to `ScanFlags` struct fields.
/// - `recursive`/`overlay`/`resources`/`archives`/`first_wrapper_only`
///   control nested-scan behavior in the engine's work-queue; they are
///   passed as scan-options metadata rather than `ScanFlags` struct fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFlagsDto {
    /// Recursive scan (resource/overlay).
    pub recursive: bool,
    /// Deep scan mode.
    pub deep: bool,
    /// Heuristic scan mode.
    pub heuristic: bool,
    /// Verbose output.
    pub verbose: bool,
    /// Aggressive scan mode.
    pub aggressive: bool,
    /// All types scan mode.
    pub alltypes: bool,
    /// Overlay scan.
    pub overlay: bool,
    /// Resources scan.
    pub resources: bool,
    /// Archives scan.
    pub archives: bool,
    /// First wrapper only.
    pub first_wrapper_only: bool,
    /// Hide unknown detections.
    pub hide_unknown: bool,
    /// Disable result deduplication (--no-dedup).
    pub no_dedup: bool,
    /// Optional file type override (e.g. "PE", "ELF"). When set, only rules
    /// for the specified file type are run, bypassing auto-detection.
    pub file_type: Option<String>,
}

impl From<ScanFlagsDto> for ScanFlags {
    fn from(dto: ScanFlagsDto) -> Self {
        ScanFlags {
            deep: dto.deep,
            heuristic: dto.heuristic,
            verbose: dto.verbose,
            aggressive: dto.aggressive,
            all_types: dto.alltypes,
            hide_unknown: dto.hide_unknown,
            no_dedup: dto.no_dedup,
            file_type: dto.file_type,
            recursive: dto.recursive,
            resources: dto.resources,
            overlays: dto.overlay,
            archives: dto.archives,
        }
    }
}

/// A single detection result, serializable for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDetectionDto {
    /// The file type that produced this detection.
    pub file_type: String,
    /// The detection type (e.g. "archive", "compiler", "linker").
    pub type_name: String,
    /// The detection name (e.g. "7-Zip", "Borland C++").
    pub name: String,
    /// Optional version string.
    pub version: Option<String>,
    /// Optional options/info string.
    pub options: Option<String>,
    /// Path to the signature file that produced this detection (relative to db root).
    pub signature_path: Option<String>,
    /// Optional unique identifier for nested tree building.
    pub id: Option<String>,
    /// Optional parent detection id for nested results.
    pub parent_id: Option<String>,
    /// Optional file part where the detection originated.
    pub file_part: Option<String>,
    /// Optional offset of the detected region.
    pub offset: Option<u64>,
    /// Optional size of the detected region.
    pub size: Option<u64>,
    /// Optional heuristic detection marker.
    pub is_heuristic: Option<bool>,
    /// Optional A-Heuristic detection marker.
    pub is_a_heuristic: Option<bool>,
    /// Optional original name for archive/container entries.
    pub original_name: Option<String>,
}

impl From<ScanDetection> for ScanDetectionDto {
    fn from(d: ScanDetection) -> Self {
        Self {
            file_type: d.file_type,
            type_name: d.type_name,
            name: d.name,
            version: d.version,
            options: d.options,
            signature_path: d.signature_path,
            id: d.id,
            parent_id: d.parent_id,
            file_part: d.file_part,
            offset: d.offset,
            size: d.size,
            is_heuristic: d.is_heuristic,
            is_a_heuristic: d.is_a_heuristic,
            original_name: d.original_name,
        }
    }
}

/// A structured diagnostic entry with file/line/kind separation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredDiagnosticDto {
    pub file: String,
    pub line: Option<u32>,
    pub message: String,
    pub kind: String,
}

/// Per-signature profiling entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureProfileDto {
    pub file: String,
    pub elapsed_ms: u64,
}

/// The result of scanning a single file, serializable for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultDto {
    /// The file path that was scanned.
    pub path: String,
    /// All detections found.
    pub detections: Vec<ScanDetectionDto>,
    /// Diagnostics (errors, warnings) encountered during scanning.
    pub diagnostics: Vec<String>,
    /// Structured diagnostics with file/line/kind separation.
    pub structured_diagnostics: Vec<StructuredDiagnosticDto>,
    /// Per-signature profiling data (elapsed time per rule file).
    pub profiling: Vec<SignatureProfileDto>,
    /// Scan time in milliseconds.
    pub scan_time_ms: u64,
    /// Scan log entries (rule loading, matching, skipping details).
    #[serde(default)]
    pub scan_log: Vec<String>,
}

impl From<ScanResult> for ScanResultDto {
    fn from(r: ScanResult) -> Self {
        let detections = r.detections.into_iter().map(Into::into).collect();
        let structured_diagnostics = r
            .structured_diagnostics
            .into_iter()
            .map(|d| StructuredDiagnosticDto {
                file: d.file,
                line: d.line,
                message: d.message,
                kind: d.kind,
            })
            .collect();
        let profiling = r
            .profiling
            .into_iter()
            .map(|p| SignatureProfileDto {
                file: p.file,
                elapsed_ms: p.elapsed_ms,
            })
            .collect();
        Self {
            path: r.path,
            detections,
            diagnostics: r.diagnostics.clone(),
            structured_diagnostics,
            profiling,
            scan_time_ms: 0,
            scan_log: r.diagnostics,
        }
    }
}

/// Progress events streamed to the frontend via Tauri Channel.
///
/// Reserved for 7A-1 streaming scan progress; not yet wired into
/// `scan_file`/`scan_bytes_cmd`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum ScanProgress {
    /// Scan started.
    Started {
        /// File name being scanned.
        file_name: String,
        /// File size in bytes.
        file_size: u64,
    },
    /// Scan progress update.
    Progress {
        /// Current progress (0..=total).
        current: u64,
        /// Total work units.
        total: u64,
        /// Human-readable progress message.
        message: String,
    },
    /// Scan finished successfully.
    Finished {
        /// The scan result.
        result: ScanResultDto,
    },
    /// Scan failed.
    Error {
        /// Error message.
        message: String,
    },
}

/// Signature group for the signature browser tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureGroupDto {
    /// File type name (e.g. "PE", "ELF", "MACH").
    pub file_type: String,
    /// Signatures in this group.
    pub signatures: Vec<SignatureInfoDto>,
}

/// Individual signature info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfoDto {
    /// Signature name.
    pub name: String,
    /// Signature file path relative to database root.
    pub file_path: String,
}

/// Signature source code response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSourceDto {
    /// Signature source code.
    pub source: String,
    /// Signature file path.
    pub file_path: String,
}

/// Result of running a single signature against a file (signature browser).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSignatureResultDto {
    /// Detections from the specified signature only.
    pub detections: Vec<ScanDetectionDto>,
    /// Diagnostics filtered to the signature (only in debug mode).
    pub diagnostics: Vec<String>,
    /// Time spent scanning (ms).
    pub elapsed_ms: u64,
    /// The signature file path that was run.
    pub signature_path: String,
}

/// Directory scan progress events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum DirectoryScanProgress {
    /// Directory scan started.
    Started {
        /// Number of files to scan.
        total_files: usize,
    },
    /// A file scan completed.
    FileScanned {
        /// File index (0-based).
        index: usize,
        /// File path.
        file_path: String,
        /// Scan result.
        result: ScanResultDto,
    },
    /// Directory scan finished.
    Finished {
        /// Total number of files scanned.
        total: usize,
    },
    /// Directory scan error.
    Error {
        /// Error message.
        message: String,
    },
}

/// Database info response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfoDto {
    /// Database path.
    pub path: String,
    /// Number of loaded rules.
    pub rule_count: usize,
    /// Database version commit SHA.
    pub commit: String,
    /// Database version sync timestamp.
    pub synced_at: String,
}

// ---------------------------------------------------------------------------
// IPC Commands
// ---------------------------------------------------------------------------

/// Resolve the database directory by checking candidate paths in order.
///
/// Candidates (checked in order):
/// 1. Path relative to the executable directory (`<exe_dir>/db`)
/// 2. Current working directory (`./db`)
/// 3. Development layout (`upstream/Detect-It-Easy/db`)
///
/// The exe-relative path ensures the bundled application finds its
/// database regardless of the current working directory.
/// Resolve the data root directory (where db/, db_extra/, peid_rules/,
/// yara_rules/ etc. live). Checks exe-adjacent, exe-parent, cwd, and
/// upstream dev paths in order.
fn resolve_data_root() -> std::path::PathBuf {
    // 1. Relative to the executable directory.
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        let exe_db = exe_dir.join("db");
        if exe_db.is_dir() {
            return exe_dir.to_path_buf();
        }
        // macOS .app bundle: exe is in Contents/MacOS/, resources in Contents/Resources/
        #[cfg(target_os = "macos")]
        {
            if let Some(contents_dir) = exe_dir.parent() {
                let resources_db = contents_dir.join("Resources").join("db");
                if resources_db.is_dir() {
                    return contents_dir.join("Resources");
                }
            }
        }
        // Also check one level up (e.g. target/release/ -> target/db).
        if let Some(project_dir) = exe_dir.parent() {
            let project_db = project_dir.join("db");
            if project_db.is_dir() {
                return project_dir.to_path_buf();
            }
        }
    }

    // 2. Current working directory / upstream dev paths.
    let candidates = [".", "upstream/Detect-It-Easy"];
    for c in &candidates {
        let p = std::path::Path::new(c);
        if p.join("db").is_dir() {
            return p.to_path_buf();
        }
    }

    std::path::PathBuf::from(".")
}

/// Resolve the main database path (db/) and any extra database paths
/// (db_extra/, db_custom/) that exist alongside it.
fn resolve_db_paths() -> Vec<String> {
    let root = resolve_data_root();
    let mut paths = Vec::new();

    // Main database (required).
    let main_db = root.join("db");
    paths.push(main_db.to_string_lossy().to_string());

    // Extra database (optional, merged into scan results).
    let extra_db = root.join("db_extra");
    if extra_db.is_dir() {
        paths.push(extra_db.to_string_lossy().to_string());
    }

    // Custom database (optional, user-defined rules).
    let custom_db = root.join("db_custom");
    if custom_db.is_dir() {
        paths.push(custom_db.to_string_lossy().to_string());
    }

    paths
}

/// Database path info for the frontend Databases dropdown.
#[derive(Debug, Clone, Serialize)]
pub struct DatabasePathInfo {
    /// Database key: "main", "extra", "custom".
    pub key: String,
    /// Absolute or relative path to the database directory.
    pub path: String,
    /// Whether the database directory exists.
    pub exists: bool,
}

/// List available database paths for the frontend Databases dropdown.
/// Returns info for main, extra, and custom databases.
#[tauri::command]
pub fn list_database_paths() -> Vec<DatabasePathInfo> {
    let root = resolve_data_root();
    let entries = [
        ("main", "db"),
        ("extra", "db_extra"),
        ("custom", "db_custom"),
    ];
    entries
        .iter()
        .map(|(key, dir)| {
            let p = root.join(dir);
            DatabasePathInfo {
                key: key.to_string(),
                path: p.to_string_lossy().to_string(),
                exists: p.is_dir(),
            }
        })
        .collect()
}

/// Backward-compatible single-path resolver (used by commands that only
/// need the main db path for source file reading).
fn resolve_db_path() -> String {
    resolve_data_root().join("db").to_string_lossy().to_string()
}

/// Scan a file by path.
///
/// `database_paths` is optional: when `None`, the auto-detected database
/// paths (db + db_extra + db_custom) are used. When `Some`, only the
/// specified paths are loaded, allowing the user to select specific
/// databases via the GUI Databases dropdown.
#[tauri::command]
pub async fn scan_file(
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
    path: String,
    flags: ScanFlagsDto,
    database_paths: Option<Vec<String>>,
) -> Result<ScanResultDto, GuiError> {
    let db_paths = database_paths.unwrap_or_else(resolve_db_paths);

    let _ = app.emit(
        "scan_progress",
        serde_json::json!({ "phase": "loading_database" }),
    );

    let db = state
        .database(&db_paths)
        .map_err(|e| GuiError::new("DATABASE_LOAD_FAILED", e))?;
    let cancel = state.start_scan();
    let engine_flags: ScanFlags = flags.into();

    let _ = app.emit(
        "scan_progress",
        serde_json::json!({ "phase": "scanning", "path": &path }),
    );

    let start = Instant::now();
    let result = tokio::task::spawn_blocking({
        let path = path.clone();
        let db = Arc::clone(&db);
        move || scan_once(&db, &path, engine_flags, &cancel)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?
    .map_err(GuiError::from)?;

    let elapsed = start.elapsed().as_millis() as u64;
    let _ = app.emit(
        "scan_progress",
        serde_json::json!({ "phase": "complete", "elapsed_ms": elapsed }),
    );

    let mut dto: ScanResultDto = result.into();
    dto.scan_time_ms = elapsed;
    Ok(dto)
}

/// Scan a byte buffer (for drag-and-drop or remote content).
///
/// `database_paths` is optional: when `None`, the auto-detected database
/// paths are used. When `Some`, only the specified paths are loaded.
#[tauri::command]
pub async fn scan_bytes_cmd(
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
    file_name: String,
    data: Vec<u8>,
    flags: ScanFlagsDto,
    database_paths: Option<Vec<String>>,
) -> Result<ScanResultDto, GuiError> {
    let db_paths = database_paths.unwrap_or_else(resolve_db_paths);

    let _ = app.emit(
        "scan_progress",
        serde_json::json!({ "phase": "loading_database" }),
    );

    let db = state
        .database(&db_paths)
        .map_err(|e| GuiError::new("DATABASE_LOAD_FAILED", e))?;
    let cancel = state.start_scan();
    let engine_flags: ScanFlags = flags.into();

    let _ = app.emit(
        "scan_progress",
        serde_json::json!({ "phase": "scanning", "path": &file_name }),
    );

    let start = Instant::now();
    let result = tokio::task::spawn_blocking({
        let file_name = file_name.clone();
        let db = Arc::clone(&db);
        move || scan_bytes(&db, &file_name, data, engine_flags, &cancel)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?
    .map_err(GuiError::from)?;

    let elapsed = start.elapsed().as_millis() as u64;
    let _ = app.emit(
        "scan_progress",
        serde_json::json!({ "phase": "complete", "elapsed_ms": elapsed }),
    );

    let mut dto: ScanResultDto = result.into();
    dto.scan_time_ms = start.elapsed().as_millis() as u64;
    Ok(dto)
}

/// Stop the current scan.
#[tauri::command]
pub async fn stop_scan(state: tauri::State<'_, AppState>) -> Result<(), GuiError> {
    state.stop_scan();
    Ok(())
}

/// List all signatures grouped by file type.
#[tauri::command]
pub async fn list_signatures(
    _state: tauri::State<'_, AppState>,
) -> Result<Vec<SignatureGroupDto>, GuiError> {
    let db_path = resolve_db_path();
    let db_dir = std::path::Path::new(&db_path);
    let mut groups = Vec::new();

    let Ok(entries) = std::fs::read_dir(db_dir) else {
        return Ok(groups);
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let file_type = entry.file_name().to_string_lossy().to_string();
        // Skip non-signature directories (e.g. _icons, .vscode).
        if file_type.starts_with('_') || file_type.starts_with('.') {
            continue;
        }

        let mut sigs = Vec::new();
        if let Ok(sig_entries) = std::fs::read_dir(&path) {
            for sig_entry in sig_entries.flatten() {
                let sig_path = sig_entry.path();
                if !sig_path.is_file() {
                    continue;
                }
                let ext = sig_path
                    .extension()
                    .map(|e| e.to_string_lossy().to_string())
                    .unwrap_or_default();
                if ext != "sg" {
                    continue;
                }
                let name = sig_entry.file_name().to_string_lossy().to_string();
                let rel_path = format!("{}/{}", file_type, name);
                sigs.push(SignatureInfoDto {
                    name,
                    file_path: rel_path,
                });
            }
        }

        if !sigs.is_empty() {
            sigs.sort_by(|a, b| a.name.cmp(&b.name));
            groups.push(SignatureGroupDto {
                file_type,
                signatures: sigs,
            });
        }
    }

    groups.sort_by(|a, b| a.file_type.cmp(&b.file_type));
    Ok(groups)
}

/// Get the source code of a specific signature.
#[tauri::command]
pub async fn get_signature_source(
    _state: tauri::State<'_, AppState>,
    file_type: String,
    name: String,
) -> Result<SignatureSourceDto, GuiError> {
    let db_path = resolve_db_path();
    let file_path = format!("{}/{}/{}", db_path, file_type, name);
    let source = std::fs::read_to_string(&file_path)
        .map_err(|e| GuiError::new("SIGNATURE_READ_ERROR", e.to_string()))?;
    Ok(SignatureSourceDto {
        source,
        file_path: format!("{}/{}", file_type, name),
    })
}

/// Save signature source code (for signature browser edit feature).
#[tauri::command]
pub async fn save_signature_source(
    _state: tauri::State<'_, AppState>,
    file_type: String,
    name: String,
    source: String,
) -> Result<(), GuiError> {
    let db_path = resolve_db_path();
    let file_path = format!("{}/{}/{}", db_path, file_type, name);
    std::fs::write(&file_path, source)
        .map_err(|e| GuiError::new("SIGNATURE_WRITE_ERROR", e.to_string()))
}

/// Run a single signature against a file (for signature browser).
/// Executes a full scan then filters detections to only those from the
/// specified signature file. Returns profiling info (per-signature time).
#[tauri::command]
pub async fn run_signature(
    state: tauri::State<'_, AppState>,
    file_path: String,
    file_type: String,
    signature_name: String,
    debug: bool,
) -> Result<RunSignatureResultDto, GuiError> {
    let db_paths = resolve_db_paths();
    let db = state
        .database(&db_paths)
        .map_err(|e| GuiError::new("DATABASE_LOAD_FAILED", e))?;
    let cancel = state.start_scan();
    let engine_flags = ScanFlags {
        deep: true,
        heuristic: true,
        all_types: true,
        verbose: debug,
        ..Default::default()
    };

    let start = Instant::now();
    let result = tokio::task::spawn_blocking({
        let path = file_path.clone();
        let db = Arc::clone(&db);
        move || scan_once(&db, &path, engine_flags, &cancel)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?
    .map_err(GuiError::from)?;

    let elapsed_ms = start.elapsed().as_millis() as u64;
    let sig_rel_path = format!("{}/{}", file_type, signature_name);

    // Filter detections to only those from the specified signature.
    let filtered: Vec<ScanDetectionDto> = result
        .detections
        .into_iter()
        .filter(|d| {
            d.signature_path
                .as_ref()
                .map(|p| p == &sig_rel_path || p.ends_with(&format!("/{}", signature_name)))
                .unwrap_or(false)
        })
        .map(ScanDetectionDto::from)
        .collect();

    let diagnostics = if debug {
        result
            .diagnostics
            .into_iter()
            .filter(|d| d.contains(&signature_name) || d.contains(&file_type))
            .collect()
    } else {
        Vec::new()
    };

    Ok(RunSignatureResultDto {
        detections: filtered,
        diagnostics,
        elapsed_ms,
        signature_path: sig_rel_path,
    })
}

/// Scan a directory recursively.
#[tauri::command]
pub async fn scan_directory(
    state: tauri::State<'_, AppState>,
    dir: String,
    flags: ScanFlagsDto,
    subdirectories: bool,
    on_progress: tauri::ipc::Channel<DirectoryScanProgress>,
) -> Result<Vec<ScanResultDto>, GuiError> {
    let db_paths = resolve_db_paths();
    let db = state
        .database(&db_paths)
        .map_err(|e| GuiError::new("DATABASE_LOAD_FAILED", e))?;
    let cancel = state.start_scan();
    let engine_flags: ScanFlags = flags.into();

    // Collect files to scan.
    let files = collect_files(&dir, subdirectories);
    let total = files.len();
    let _ = on_progress.send(DirectoryScanProgress::Started { total_files: total });

    let mut results = Vec::with_capacity(total);
    for (index, file_path) in files.into_iter().enumerate() {
        if cancel.is_cancelled() {
            let _ = on_progress.send(DirectoryScanProgress::Error {
                message: "Cancelled".to_string(),
            });
            break;
        }

        let db = Arc::clone(&db);
        let cancel = cancel.clone();
        let path_str = file_path.to_string_lossy().to_string();
        let flags_for_file = engine_flags.clone();
        let scan_result =
            tokio::task::spawn_blocking(move || scan_once(&db, &path_str, flags_for_file, &cancel))
                .await
                .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;

        match scan_result {
            Ok(r) => {
                let dto: ScanResultDto = r.into();
                let _ = on_progress.send(DirectoryScanProgress::FileScanned {
                    index,
                    file_path: dto.path.clone(),
                    result: dto.clone(),
                });
                results.push(dto);
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = on_progress.send(DirectoryScanProgress::Error {
                    message: format!("{}: {}", file_path.display(), err_msg),
                });
            }
        }
    }

    let _ = on_progress.send(DirectoryScanProgress::Finished {
        total: results.len(),
    });
    Ok(results)
}

/// Collect files in a directory, optionally recursing into subdirectories.
fn collect_files(dir: &str, recursive: bool) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    collect_files_inner(std::path::Path::new(dir), recursive, &mut files);
    files
}

/// Recursive helper for `collect_files`.
/// Silently skips directories with permission errors.
fn collect_files_inner(
    dir: &std::path::Path,
    recursive: bool,
    files: &mut Vec<std::path::PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        // Permission denied or other I/O error — skip this directory.
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                collect_files_inner(&path, recursive, files);
            }
        } else if path.is_file() {
            files.push(path);
        }
    }
}

/// Demangle a C++ or Rust symbol.
#[tauri::command]
pub async fn demangle(symbol: String, compiler: String) -> Result<String, GuiError> {
    Ok(crate::demangle::demangle_symbol(&symbol, &compiler))
}

/// Read a hex dump of a file region.
#[tauri::command]
pub async fn read_hex(
    path: String,
    offset: u64,
    max_bytes: Option<usize>,
) -> Result<crate::hex_viewer::HexDump, GuiError> {
    let max = max_bytes.unwrap_or(4096);
    crate::hex_viewer::read_hex_dump(&path, offset, max)
        .map_err(|e| GuiError::new("HEX_READ_ERROR", e))
}

/// Search for a byte pattern in a file.
///
/// The pattern can be a hex string (e.g. "48 89 5C") or an ASCII string
/// (e.g. "Hello"). Search starts at `start_offset` and returns up to
/// `max_hits` matches (default 1000).
#[tauri::command]
pub async fn search_hex(
    path: String,
    pattern: String,
    start_offset: Option<u64>,
    max_hits: Option<usize>,
) -> Result<crate::hex_viewer::SearchResult, GuiError> {
    crate::hex_viewer::search_bytes(
        &path,
        &pattern,
        start_offset.unwrap_or(0),
        max_hits.unwrap_or(1000),
    )
    .map_err(|e| GuiError::new("HEX_SEARCH_ERROR", e))
}

/// Disassemble a byte range from a file.
///
/// `arch` selects the disassembler architecture (x86/x64/arm/arm64).
/// `max_bytes` defaults to 4096 (not 256 — the old limit was too small).
/// `bitness` is deprecated — use `arch` instead. When `arch` is not
/// provided, `bitness` is used to infer x86 (32) or x64 (64).
#[tauri::command]
pub async fn disassemble(
    path: String,
    offset: u64,
    max_bytes: Option<usize>,
    bitness: Option<u32>,
    syntax: Option<crate::disassembler::Syntax>,
    arch: Option<crate::disassembler::Arch>,
) -> Result<crate::disassembler::DisassemblyResult, GuiError> {
    let max = max_bytes.unwrap_or(4096);
    let syn = syntax.unwrap_or(crate::disassembler::Syntax::Intel);
    let architecture = arch.unwrap_or_else(|| {
        // Backward compat: infer arch from bitness.
        match bitness.unwrap_or(64) {
            32 => crate::disassembler::Arch::X86,
            _ => crate::disassembler::Arch::X64,
        }
    });
    crate::disassembler::disassemble_file(&path, offset, max, architecture, syn)
        .map_err(|e| GuiError::new("DISASM_ERROR", e))
}

/// Get application settings from the persistent store.
#[tauri::command]
pub async fn get_settings(app: tauri::AppHandle) -> Result<AppSettings, GuiError> {
    use tauri_plugin_store::StoreExt;
    let store = app
        .store("settings.json")
        .map_err(|e| GuiError::new("STORE_ERROR", e.to_string()))?;
    match store.get("app_settings") {
        Some(val) => serde_json::from_value::<AppSettings>(val)
            .map_err(|e| GuiError::new("SETTINGS_PARSE_ERROR", e.to_string())),
        None => Ok(AppSettings::default()),
    }
}

/// Save application settings to the persistent store.
#[tauri::command]
pub async fn save_settings(app: tauri::AppHandle, settings: AppSettings) -> Result<(), GuiError> {
    use tauri_plugin_store::StoreExt;
    let store = app
        .store("settings.json")
        .map_err(|e| GuiError::new("STORE_ERROR", e.to_string()))?;
    let val = serde_json::to_value(&settings)
        .map_err(|e| GuiError::new("SETTINGS_SERIALIZE_ERROR", e.to_string()))?;
    store.set("app_settings", val);
    store
        .save()
        .map_err(|e| GuiError::new("STORE_SAVE_ERROR", e.to_string()))?;
    Ok(())
}

/// Get database info (path, rule count, version).
#[tauri::command]
pub async fn get_database_info(
    state: tauri::State<'_, AppState>,
) -> Result<DatabaseInfoDto, GuiError> {
    let db_paths = resolve_db_paths();
    let db = state
        .database(&db_paths)
        .map_err(|e| GuiError::new("DATABASE_LOAD_FAILED", e))?;
    let version = db.version();
    Ok(DatabaseInfoDto {
        path: db_paths.join(";"),
        rule_count: db.rule_count(),
        commit: version.commit,
        synced_at: version.synced_at,
    })
}

/// Scan a file with YARA rules.
#[tauri::command]
pub async fn yara_scan(
    rules_source: String,
    file_path: String,
) -> Result<crate::yara_scanner::YaraScanResult, GuiError> {
    // yara-x types are !Send, so run in spawn_blocking.
    let result = tokio::task::spawn_blocking(move || {
        crate::yara_scanner::scan_with_yara(&rules_source, &file_path)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("YARA_ERROR", e))
}

/// Scan a PE file with PEID signatures.
#[tauri::command]
pub async fn peid_scan(
    userdb_path: String,
    file_path: String,
) -> Result<crate::peid_scanner::PeidScanResult, GuiError> {
    crate::peid_scanner::scan_with_peid(&userdb_path, &file_path)
        .map_err(|e| GuiError::new("PEID_ERROR", e))
}

/// Get file information: size, hashes, entropy, format, sections, symbols.
#[tauri::command]
pub async fn get_file_info(path: String) -> Result<crate::file_info::FileInfo, GuiError> {
    let result = tokio::task::spawn_blocking(move || crate::file_info::gather_file_info(&path))
        .await
        .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("FILE_INFO_ERROR", e))
}

/// Get 2D visualization data for a file.
#[tauri::command]
pub async fn get_visualization(
    path: String,
    method: crate::visualization::VizMethod,
    block_size: Option<u32>,
    width: Option<u32>,
) -> Result<crate::visualization::VisualizationData, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        crate::visualization::generate_visualization(&path, method, block_size, width)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("VISUALIZATION_ERROR", e))
}

/// List extractable items from a file.
#[tauri::command]
pub async fn list_extractable(path: String) -> Result<crate::extractor::ExtractItemList, GuiError> {
    let result = tokio::task::spawn_blocking(move || crate::extractor::list_extractable(&path))
        .await
        .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("EXTRACTOR_ERROR", e))
}

/// Get deep DEX tables (strings/types/protos/fields/methods/class_defs/map)
/// for the DEX viewer sub-tabs, mirroring upstream DEX widget.
#[tauri::command]
pub async fn get_dex_deep_view(
    path: String,
) -> Result<Option<crate::misc_viewer::DexDeepView>, GuiError> {
    tokio::task::spawn_blocking(move || {
        std::fs::read(&path)
            .ok()
            .and_then(|data| crate::misc_viewer::parse_dex_deep_view(&data))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))
}

/// Get the DEX header view.
#[tauri::command]
pub async fn get_dex_view(path: String) -> Result<Option<crate::misc_viewer::DexView>, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        std::fs::read(&path)
            .ok()
            .and_then(|data| crate::misc_viewer::parse_dex_view(&data))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    Ok(result)
}

/// Get MSDOS view data for a file.
#[tauri::command]
pub async fn get_msdos_view(
    path: String,
) -> Result<Option<crate::misc_viewer::MsdosView>, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        std::fs::read(&path)
            .ok()
            .and_then(|data| crate::misc_viewer::parse_msdos_view(&data))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    Ok(result)
}

/// Get NE view data for a file.
#[tauri::command]
pub async fn get_ne_view(path: String) -> Result<Option<crate::misc_viewer::NeView>, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        std::fs::read(&path)
            .ok()
            .and_then(|data| crate::misc_viewer::parse_ne_view(&data))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    Ok(result)
}

/// Get LE view data for a file.
#[tauri::command]
pub async fn get_le_view(path: String) -> Result<Option<crate::misc_viewer::LeView>, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        std::fs::read(&path)
            .ok()
            .and_then(|data| crate::misc_viewer::parse_le_view(&data))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    Ok(result)
}

/// Search for a hex signature pattern with wildcards.
#[tauri::command]
pub async fn search_signature(
    path: String,
    pattern: String,
    start_offset: u64,
    max_hits: usize,
) -> Result<crate::search::SearchResult, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        crate::search::search_signature(&path, &pattern, start_offset, max_hits)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("SEARCH_ERROR", e))
}

/// Search for an integer value in the file.
#[tauri::command]
pub async fn search_value(
    path: String,
    value: u64,
    value_type: crate::search::ValueType,
    start_offset: u64,
    max_hits: usize,
) -> Result<crate::search::SearchResult, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        crate::search::search_value(&path, value, value_type, start_offset, max_hits)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("SEARCH_ERROR", e))
}

/// Detect common packers in a file.
#[tauri::command]
pub async fn detect_packers(path: String) -> Result<Vec<crate::search::PackerInfo>, GuiError> {
    let result = tokio::task::spawn_blocking(move || crate::search::detect_packers(&path))
        .await
        .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("SEARCH_ERROR", e))
}

// =========================================================================
// PE TOOLS: DosStub and Overlay dump/remove/add commands.
// =========================================================================

/// Dump DOS stub bytes from a PE file.
#[tauri::command]
pub async fn pe_dump_dos_stub(path: String) -> Result<Vec<u8>, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        crate::pe_viewer::dump_dos_stub(&data)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("PE_TOOLS_ERROR", e))
}

/// Remove DOS stub from a PE file (creates .bak backup).
#[tauri::command]
pub async fn pe_remove_dos_stub(path: String) -> Result<(), GuiError> {
    let result = tokio::task::spawn_blocking(move || crate::pe_viewer::remove_dos_stub(&path))
        .await
        .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("PE_TOOLS_ERROR", e))
}

/// Add DOS stub to a PE file (creates .bak backup).
#[tauri::command]
pub async fn pe_add_dos_stub(path: String, stub_bytes: Vec<u8>) -> Result<(), GuiError> {
    let result =
        tokio::task::spawn_blocking(move || crate::pe_viewer::add_dos_stub(&path, &stub_bytes))
            .await
            .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("PE_TOOLS_ERROR", e))
}

/// Dump overlay bytes from a PE file.
#[tauri::command]
pub async fn pe_dump_overlay(path: String) -> Result<Vec<u8>, GuiError> {
    let result = tokio::task::spawn_blocking(move || crate::pe_viewer::dump_overlay(&path))
        .await
        .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("PE_TOOLS_ERROR", e))
}

/// Remove overlay from a PE file (creates .bak backup).
#[tauri::command]
pub async fn pe_remove_overlay(path: String) -> Result<(), GuiError> {
    let result = tokio::task::spawn_blocking(move || crate::pe_viewer::remove_overlay(&path))
        .await
        .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("PE_TOOLS_ERROR", e))
}

/// Add overlay to a PE file (creates .bak backup).
#[tauri::command]
pub async fn pe_add_overlay(path: String, overlay_bytes: Vec<u8>) -> Result<(), GuiError> {
    let result =
        tokio::task::spawn_blocking(move || crate::pe_viewer::add_overlay(&path, &overlay_bytes))
            .await
            .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("PE_TOOLS_ERROR", e))
}

/// Edit a string at a given file offset (creates .bak backup).
#[tauri::command]
pub async fn edit_string_at_offset(
    path: String,
    offset: usize,
    new_value: String,
    is_utf16: bool,
) -> Result<(), GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        crate::string_extractor::edit_string_at_offset(&path, offset, &new_value, is_utf16)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("STRING_EDIT_ERROR", e))
}

/// Write raw bytes at a file offset (hex-viewer edit entry; creates .bak).
#[tauri::command]
pub async fn edit_bytes_at_offset(
    path: String,
    offset: usize,
    bytes: Vec<u8>,
) -> Result<(), GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        crate::string_extractor::edit_bytes_at_offset(&path, offset, &bytes)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("BYTE_EDIT_ERROR", e))
}

/// Extract an item from a file to an output directory.
#[tauri::command]
pub async fn extract_item(
    path: String,
    item_name: String,
    output_dir: String,
) -> Result<String, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        crate::extractor::extract_item(&path, &item_name, &output_dir)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("EXTRACTOR_ERROR", e))
}

/// Extract a raw byte range from a file.
#[tauri::command]
pub async fn extract_range(
    path: String,
    offset: u64,
    size: u64,
    output_dir: String,
    output_name: String,
) -> Result<String, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        crate::extractor::extract_range(&path, offset, size, &output_dir, &output_name)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("EXTRACTOR_ERROR", e))
}

/// Heuristic extraction: scan for embedded file magic signatures.
#[tauri::command]
pub async fn extract_heuristic(
    path: String,
    deep_scan: bool,
) -> Result<Vec<crate::extractor::ExtractItem>, GuiError> {
    let result =
        tokio::task::spawn_blocking(move || crate::extractor::extract_heuristic(&path, deep_scan))
            .await
            .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("EXTRACTOR_ERROR", e))
}

/// Analyze an extractable item: identify format and compute entropy.
#[tauri::command]
pub async fn analyze_item(
    path: String,
    offset: u64,
    size: u64,
) -> Result<crate::extractor::AnalyzeResult, GuiError> {
    let result =
        tokio::task::spawn_blocking(move || crate::extractor::analyze_item(&path, offset, size))
            .await
            .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("EXTRACTOR_ERROR", e))
}

/// Get entropy graph data for a file (block-level entropy for plotting).
#[tauri::command]
pub async fn get_entropy_graph(
    path: String,
    block_size: Option<u64>,
) -> Result<crate::file_info::EntropyGraph, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        crate::file_info::compute_entropy_graph(&path, block_size)
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("ENTROPY_ERROR", e))
}

/// Get PE-specific view data: imports, exports, resources, overlay, .NET,
/// manifest, version info, TLS, Rich Header.
#[tauri::command]
pub async fn get_pe_view(path: String) -> Result<Option<crate::pe_viewer::PeView>, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        Ok::<_, String>(crate::pe_viewer::parse_pe_view(&data))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("PE_VIEW_ERROR", e))
}

/// Get ELF-specific view data: program headers, section headers, dynamic
/// entries, libraries, interpreter, notes, and symbol table.
#[tauri::command]
pub async fn get_elf_view(path: String) -> Result<Option<crate::elf_viewer::ElfView>, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        Ok::<_, String>(crate::elf_viewer::parse_elf_view(&data))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("ELF_VIEW_ERROR", e))
}

/// Get Mach-O-specific view data: header, load commands, segments,
/// sections, and libraries.
#[tauri::command]
pub async fn get_macho_view(
    path: String,
) -> Result<Option<crate::macho_viewer::MachView>, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        Ok::<_, String>(crate::macho_viewer::parse_macho_view(&data))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("MACHO_VIEW_ERROR", e))
}

/// Extract strings from a binary file (ASCII and UTF-16LE).
#[tauri::command]
pub async fn extract_strings(
    path: String,
    params: crate::string_extractor::StringExtractParams,
) -> Result<Vec<crate::string_extractor::StringEntry>, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        Ok::<_, String>(crate::string_extractor::extract_strings(&data, &params))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;
    result.map_err(|e| GuiError::new("STRING_EXTRACT_ERROR", e))
}

/// Write text content to a file (for "Save results" feature).
#[tauri::command]
pub async fn write_text_file(path: String, content: String) -> Result<(), GuiError> {
    tokio::task::spawn_blocking(move || std::fs::write(&path, content))
        .await
        .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?
        .map_err(|e| GuiError::new("FILE_WRITE_ERROR", e.to_string()))
}

/// Write binary data to a file.
#[tauri::command]
pub async fn write_binary_file(path: String, data: Vec<u8>) -> Result<(), GuiError> {
    tokio::task::spawn_blocking(move || std::fs::write(&path, &data))
        .await
        .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?
        .map_err(|e| GuiError::new("FILE_WRITE_ERROR", e.to_string()))
}

/// A single entry in an archive file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntryDto {
    /// Entry name (path within the archive).
    pub name: String,
    /// Uncompressed size in bytes.
    pub size: u64,
    /// Compressed size in bytes.
    pub compressed_size: u64,
    /// Whether this entry is a directory.
    pub is_directory: bool,
    /// Last modified time (ISO 8601 or null).
    pub modified: Option<String>,
}

/// Archive listing result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveResultDto {
    /// Archive format (ZIP, etc.).
    pub format: String,
    /// All entries in the archive.
    pub entries: Vec<ArchiveEntryDto>,
    /// Total number of entries.
    pub total_entries: usize,
}

/// List the contents of an archive file.
/// ZIP/7Z/RAR go through `diec_engine::list_archive_members` (upstream
/// `XArchive::getRecords` equivalent); TAR/GZIP+TAR stay GUI-side.
/// For unsupported formats, returns an error.
#[tauri::command]
pub async fn list_archive(path: String) -> Result<ArchiveResultDto, GuiError> {
    let result = tokio::task::spawn_blocking(move || -> Result<ArchiveResultDto, String> {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;

        // ZIP/7Z/RAR: engine metadata listing (upstream XArchive::getRecords).
        if let Some((kind, members)) = diec_engine::list_archive_members(&data) {
            let entries: Vec<ArchiveEntryDto> = members
                .into_iter()
                .map(|m| ArchiveEntryDto {
                    name: m.name,
                    size: m.size,
                    compressed_size: m.packed_size,
                    is_directory: m.is_directory,
                    modified: m.modified,
                })
                .collect();
            return Ok(ArchiveResultDto {
                format: kind.display_name().to_string(),
                total_entries: entries.len(),
                entries,
            });
        }

        // GZIP: 1F 8B — try decompress and parse as TAR.
        if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
            let decoder = flate2::read::GzDecoder::new(&data[..]);
            let mut archive = tar::Archive::new(decoder);
            let mut entries = Vec::new();
            let iter = match archive.entries() {
                Ok(it) => it,
                Err(_) => return Err("Failed to read GZIP/TAR entries.".to_string()),
            };
            for entry_result in iter {
                let entry = match entry_result {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let header = entry.header();
                entries.push(ArchiveEntryDto {
                    name: header
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    size: header.size().unwrap_or(0),
                    compressed_size: 0,
                    is_directory: header.entry_type().is_dir(),
                    modified: header
                        .mtime()
                        .ok()
                        .filter(|&s| s > 0)
                        .map(chrono_secs_to_string),
                });
            }
            return Ok(ArchiveResultDto {
                format: "GZIP/TAR".to_string(),
                total_entries: entries.len(),
                entries,
            });
        }

        // TAR: check for "ustar" magic at offset 257.
        if data.len() >= 262 && &data[257..262] == b"ustar" {
            let cursor = std::io::Cursor::new(data);
            let mut archive = tar::Archive::new(cursor);
            let mut entries = Vec::new();
            let iter = match archive.entries() {
                Ok(it) => it,
                Err(_) => return Err("Failed to read TAR entries.".to_string()),
            };
            for entry_result in iter {
                let entry = match entry_result {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let header = entry.header();
                entries.push(ArchiveEntryDto {
                    name: header
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    size: header.size().unwrap_or(0),
                    compressed_size: 0,
                    is_directory: header.entry_type().is_dir(),
                    modified: header
                        .mtime()
                        .ok()
                        .filter(|&s| s > 0)
                        .map(chrono_secs_to_string),
                });
            }
            return Ok(ArchiveResultDto {
                format: "TAR".to_string(),
                total_entries: entries.len(),
                entries,
            });
        }

        Err("Unsupported archive format. Supported: ZIP, 7Z, RAR, TAR, GZIP/TAR.".to_string())
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?
    .map_err(|e| GuiError::new("ARCHIVE_READ_ERROR", e))?;

    Ok(result)
}

/// One named hash result for the GUI hash panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashResultDto {
    /// Algorithm name (uppercase, e.g. "SHA3_256").
    pub algorithm: String,
    /// Hex digest.
    pub value: String,
}

/// List selectable hash algorithms (upstream `XHashWidget` method list).
#[tauri::command]
pub fn list_hash_algorithms() -> Vec<String> {
    crate::file_info::HASH_ALGORITHMS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Compute the requested hash algorithms for a file
/// (upstream `XHashWidget` equivalent — arbitrary subset on demand).
#[tauri::command]
pub async fn compute_hash(
    path: String,
    algorithms: Vec<String>,
) -> Result<Vec<HashResultDto>, GuiError> {
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<HashResultDto>, String> {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        Ok(algorithms
            .iter()
            .filter_map(|a| {
                crate::file_info::compute_named_hash(&data, a).map(|v| HashResultDto {
                    algorithm: a.clone(),
                    value: v,
                })
            })
            .collect())
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;

    result.map_err(|e| GuiError::new("FILE_READ_ERROR", e))
}

/// Extract a single archive member by name to an output directory
/// (upstream `XArchive::decompress(record)` equivalent). Supports
/// ZIP/7Z/RAR via `diec_engine::extract_member`.
#[tauri::command]
pub async fn extract_archive_member(
    path: String,
    member_name: String,
    output_dir: String,
) -> Result<String, GuiError> {
    let result = tokio::task::spawn_blocking(move || -> Result<String, String> {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        let bytes = diec_engine::extract_member(&data, &member_name);
        if bytes.is_empty() {
            return Err(format!("Member '{}' not found or empty.", member_name));
        }
        let safe_name: String = member_name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '.' || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        std::fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;
        let out = std::path::PathBuf::from(&output_dir).join(safe_name);
        std::fs::write(&out, &bytes).map_err(|e| e.to_string())?;
        Ok(out.to_string_lossy().to_string())
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?;

    result.map_err(|e| GuiError::new("ARCHIVE_READ_ERROR", e))
}

/// Convert Unix seconds since epoch to a human-readable date string.
fn chrono_secs_to_string(secs: u64) -> String {
    // Simple conversion without chrono dependency.
    // Format: YYYY-MM-DD HH:MM:SS
    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let minutes = (rem_secs % 3600) / 60;
    let seconds = rem_secs % 60;

    // Calculate date from days since 1970-01-01.
    let (year, month, day) = days_to_date(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since 1970-01-01 to (year, month, day).
fn days_to_date(days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let month_lengths = if is_leap_year(year) {
        [31u64, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u64;
    for &mlen in &month_lengths {
        if remaining_days < mlen {
            break;
        }
        remaining_days -= mlen;
        month += 1;
    }

    (year, month, remaining_days + 1)
}

/// Check if a year is a leap year.
fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

// ---------------------------------------------------------------------------
// Data paths — expose bundled data directories to the frontend
// ---------------------------------------------------------------------------

/// DTO describing available bundled data directories.
#[derive(Debug, Clone, Serialize)]
pub struct DataPathsDto {
    /// Main rule database directory (db/).
    pub db: String,
    /// Extra rule database directory (db_extra/), if present.
    pub db_extra: Option<String>,
    /// Custom rule database directory (db_custom/), if present.
    pub db_custom: Option<String>,
    /// PEID rules directory (peid_rules/), if present.
    pub peid_rules: Option<String>,
    /// YARA rules directory (yara_rules/), if present.
    pub yara_rules: Option<String>,
    /// List of available YARA rule files (relative paths under yara_rules/).
    pub yara_rule_files: Vec<String>,
    /// List of available PEID userdb files (relative paths under peid_rules/).
    pub peid_userdb_files: Vec<String>,
}

/// Get the paths to all bundled data directories (db, db_extra, peid_rules,
/// yara_rules, etc.). The frontend uses this to provide default file
/// locations for PEID and YARA scanners.
#[tauri::command]
pub async fn get_data_paths() -> Result<DataPathsDto, GuiError> {
    let root = resolve_data_root();

    let db = root.join("db").to_string_lossy().to_string();
    let db_extra = {
        let p = root.join("db_extra");
        if p.is_dir() {
            Some(p.to_string_lossy().to_string())
        } else {
            None
        }
    };
    let db_custom = {
        let p = root.join("db_custom");
        if p.is_dir() {
            Some(p.to_string_lossy().to_string())
        } else {
            None
        }
    };
    let peid_rules = {
        let p = root.join("peid_rules");
        if p.is_dir() {
            Some(p.to_string_lossy().to_string())
        } else {
            None
        }
    };
    let yara_rules = {
        let p = root.join("yara_rules");
        if p.is_dir() {
            Some(p.to_string_lossy().to_string())
        } else {
            None
        }
    };

    // Enumerate YARA rule files (top-level only).
    let yara_rule_files = yara_rules
        .as_ref()
        .map(|dir| {
            let base = std::path::Path::new(dir);
            std::fs::read_dir(base)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    if e.file_type().ok()?.is_file() {
                        let path = e.path();
                        let rel = path.strip_prefix(base).ok()?;
                        let ext = rel.extension()?.to_string_lossy().to_lowercase();
                        if ext == "yar" || ext == "yara" {
                            return Some(rel.to_string_lossy().to_string());
                        }
                    }
                    None
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Enumerate PEID userdb files (up to 2 levels deep).
    let peid_userdb_files = peid_rules
        .as_ref()
        .map(|dir| {
            let base = std::path::Path::new(dir);
            let mut files = Vec::new();
            if let Ok(entries) = std::fs::read_dir(base) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(rel) = path.strip_prefix(base) {
                            let name = rel.to_string_lossy().to_string();
                            if name.ends_with(".txt") {
                                files.push(name);
                            }
                        }
                    } else if path.is_dir() {
                        // One level deeper (e.g. peid_rules/PE/userdb.txt).
                        if let Ok(sub_entries) = std::fs::read_dir(&path) {
                            for sub in sub_entries.flatten() {
                                let sub_path = sub.path();
                                if sub_path.is_file()
                                    && let Ok(rel) = sub_path.strip_prefix(base)
                                {
                                    let name = rel.to_string_lossy().to_string();
                                    if name.ends_with(".txt") {
                                        files.push(name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            files.sort();
            files
        })
        .unwrap_or_default();

    Ok(DataPathsDto {
        db,
        db_extra,
        db_custom,
        peid_rules,
        yara_rules,
        yara_rule_files,
        peid_userdb_files,
    })
}

/// Read a bundled data file by relative path (e.g. "yara_rules/packer.yar").
/// This allows the frontend to load built-in YARA/PEID rules without
/// needing direct filesystem access permissions.
#[tauri::command]
pub async fn read_data_file(relative_path: String) -> Result<String, GuiError> {
    let root = resolve_data_root();
    let full_path = root.join(&relative_path);

    // Security: ensure the resolved path is within the data root.
    let canonical_root = root.canonicalize().unwrap_or(root.clone());
    let canonical_full = full_path
        .canonicalize()
        .map_err(|e| GuiError::new("FILE_NOT_FOUND", format!("{}: {}", relative_path, e)))?;
    if !canonical_full.starts_with(&canonical_root) {
        return Err(GuiError::new(
            "PATH_TRAVERSAL",
            "Relative path escapes data root",
        ));
    }

    std::fs::read_to_string(&full_path)
        .map_err(|e| GuiError::new("FILE_READ_ERROR", format!("{}: {}", relative_path, e)))
}

// ---------------------------------------------------------------------------
// Context menu integration (Windows registry-based file/dir shell entries)
// ---------------------------------------------------------------------------

/// Result DTO for context menu status check.
#[derive(Debug, Clone, Serialize)]
pub struct ContextMenuStatus {
    /// Whether the context menu entry is currently installed.
    pub installed: bool,
    /// The exe path that would be invoked (current binary).
    pub exe_path: String,
    /// Platform support: "windows", "linux", "macos", or "unsupported".
    pub platform: String,
}

/// Registry sub-key path for the DIE context menu entry (file context).
#[cfg(windows)]
const REG_FILE_KEY: &str = "Software\\Classes\\*\\shell\\DIE";
/// Registry sub-key path for the DIE context menu entry (directory context).
#[cfg(windows)]
const REG_DIR_KEY: &str = "Software\\Classes\\Directory\\shell\\DIE";
/// Registry sub-key path for the DIE context menu entry (directory background).
#[cfg(windows)]
const REG_DIR_BG_KEY: &str = "Software\\Classes\\Directory\\Background\\shell\\DIE";

/// Get the current context menu integration status.
#[tauri::command]
pub async fn get_context_menu_status() -> Result<ContextMenuStatus, GuiError> {
    let exe_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    let platform = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unsupported"
    };

    #[cfg(windows)]
    let installed = is_context_menu_installed();
    #[cfg(not(windows))]
    let installed = false;

    Ok(ContextMenuStatus {
        installed,
        exe_path,
        platform: platform.to_string(),
    })
}

/// Add "Scan with DIE" to the Windows Explorer context menu for files and
/// directories. On non-Windows platforms, returns an error.
#[tauri::command]
pub async fn add_context_menu() -> Result<(), GuiError> {
    if !cfg!(target_os = "windows") {
        return Err(GuiError::new(
            "PLATFORM_UNSUPPORTED",
            "Context menu integration is only supported on Windows",
        ));
    }

    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::*;

        let exe_path =
            std::env::current_exe().map_err(|e| GuiError::new("EXE_PATH_FAILED", e.to_string()))?;
        let exe_str = exe_path.display().to_string();
        let command = format!("\"{}\" \"%1\"", exe_str);

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        // File context menu: right-click on any file → "Scan with DIE"
        let (file_key, _) = hkcu
            .create_subkey(REG_FILE_KEY)
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        file_key
            .set_value("MUIVerb", &"Scan with DIE")
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        file_key
            .set_value("Icon", &exe_str)
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        let (file_cmd, _) = file_key
            .create_subkey("command")
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        file_cmd
            .set_value("", &command)
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;

        // Directory context menu: right-click on a folder → "Scan with DIE"
        let (dir_key, _) = hkcu
            .create_subkey(REG_DIR_KEY)
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        dir_key
            .set_value("MUIVerb", &"Scan with DIE")
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        dir_key
            .set_value("Icon", &exe_str)
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        let (dir_cmd, _) = dir_key
            .create_subkey("command")
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        dir_cmd
            .set_value("", &command)
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;

        // Directory background: right-click inside a folder → "Scan with DIE"
        let (bg_key, _) = hkcu
            .create_subkey(REG_DIR_BG_KEY)
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        bg_key
            .set_value("MUIVerb", &"Scan with DIE")
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        bg_key
            .set_value("Icon", &exe_str)
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        let (bg_cmd, _) = bg_key
            .create_subkey("command")
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
        // %V = current folder when right-clicking in directory background
        let bg_command = format!("\"{}\" \"%V\"", exe_str);
        bg_cmd
            .set_value("", &bg_command)
            .map_err(|e| GuiError::new("REG_WRITE_FAILED", e.to_string()))?;
    }

    Ok(())
}

/// Remove "Scan with DIE" from the Windows Explorer context menu.
/// On non-Windows platforms, returns an error.
#[tauri::command]
pub async fn remove_context_menu() -> Result<(), GuiError> {
    if !cfg!(target_os = "windows") {
        return Err(GuiError::new(
            "PLATFORM_UNSUPPORTED",
            "Context menu integration is only supported on Windows",
        ));
    }

    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::*;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        // Delete file context menu key (recursively).
        delete_reg_tree(&hkcu, REG_FILE_KEY);
        // Delete directory context menu key.
        delete_reg_tree(&hkcu, REG_DIR_KEY);
        // Delete directory background context menu key.
        delete_reg_tree(&hkcu, REG_DIR_BG_KEY);
    }

    Ok(())
}

/// Check if the context menu entry is currently installed.
#[cfg(windows)]
fn is_context_menu_installed() -> bool {
    use winreg::RegKey;
    use winreg::enums::*;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    hkcu.open_subkey(REG_FILE_KEY).is_ok()
}

/// Recursively delete a registry key and all its subkeys.
#[cfg(windows)]
fn delete_reg_tree(root: &winreg::RegKey, path: &str) {
    // First delete subkeys recursively.
    if let Ok(key) = root.open_subkey(path) {
        let subkeys: Vec<String> = key.enum_keys().filter_map(|k| k.ok()).collect();
        for sub in subkeys {
            let full = format!("{}\\{}", path, sub);
            delete_reg_tree(root, &full);
        }
    }
    // Then delete the key itself.
    let _ = root.delete_subkey(path);
}

/// Open the VirusTotal website for a file in the default browser.
///
/// Uses **MD5** to match upstream `XVirusTotalWidget::showInBrowser`
/// (`xvirustotalwidget.cpp:245-248`, `xvirustotal.cpp:146-149`).
#[tauri::command]
pub async fn virustotal_open_browser(path: String) -> Result<(), GuiError> {
    let md5 = tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        Ok::<_, String>(crate::file_info::compute_md5(&data))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?
    .map_err(|e| GuiError::new("FILE_READ_FAILED", e))?;

    crate::virustotal::open_in_browser(&md5);
    Ok(())
}

/// Query the VirusTotal API v3 for file scan info.
///
/// Requires an API key. Uses MD5 as the file identifier, matching
/// upstream `xvirustotalwidget.cpp:56`.
#[tauri::command]
pub async fn virustotal_query(
    path: String,
    api_key: String,
) -> Result<crate::virustotal::VtScanInfo, GuiError> {
    if api_key.is_empty() {
        return Err(GuiError::new(
            "NO_API_KEY",
            "VirusTotal API key is not configured",
        ));
    }

    let md5 = tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        Ok::<_, String>(crate::file_info::compute_md5(&data))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?
    .map_err(|e| GuiError::new("FILE_READ_FAILED", e))?;

    let info = crate::virustotal::query_scan_info(&md5, &api_key).await;
    Ok(info)
}

// ---------------------------------------------------------------------------
// Struct / Entropy / Info mode commands (Phase 13 CLI parity)
// ---------------------------------------------------------------------------

/// A serializable struct node tree for the `--struct` GUI mode.
///
/// Mirrors `diec_engine::StructNode` but with serde derives for IPC.
pub type StructNodeDto = diec_engine::struct_mode::StructNode;

/// Evaluate a `--struct` selector on a file and return the structured result.
///
/// `selector` is the same string as CLI `--struct` value, e.g. "Hash#MD5",
/// "Info", "Entropy", "Check format", or format-specific like "PE#Imports".
#[tauri::command]
pub async fn evaluate_struct(
    path: String,
    selector: String,
) -> Result<Option<StructNodeDto>, GuiError> {
    let parsed = diec_engine::struct_mode::StructSelector::parse(&selector).ok_or_else(|| {
        GuiError::new(
            "INVALID_SELECTOR",
            format!("Cannot parse selector: {selector}"),
        )
    })?;

    let result = tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        Ok::<_, String>(diec_engine::struct_mode::evaluate_struct_default(
            &parsed, &path, &data,
        ))
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?
    .map_err(|e| GuiError::new("FILE_READ_FAILED", e))?;

    Ok(result)
}

/// List available struct method names for the GUI method picker.
///
/// Returns general methods (Info, Hash, Entropy, Check format) plus
/// format-specific method names.
#[tauri::command]
pub async fn list_struct_methods() -> Vec<String> {
    let mut methods: Vec<String> = diec_engine::struct_mode::general_method_names()
        .iter()
        .map(|s| s.to_string())
        .collect();
    // Format-specific methods.
    methods.extend_from_slice(&[
        "PE#Imports".to_string(),
        "PE#Exports".to_string(),
        "PE#Resources".to_string(),
        "PE#Overlay".to_string(),
        "PE#Rich".to_string(),
        "PE#Directories".to_string(),
        "ELF#Header".to_string(),
        "ELF#Sections".to_string(),
        "Mach-O#Header".to_string(),
        "Mach-O#Segments".to_string(),
        "DEX#Header".to_string(),
    ]);
    methods
}

/// Compute entropy information for a file (GUI `--entropy` mode).
///
/// Returns the overall file entropy and optional per-section entropy.
#[tauri::command]
pub async fn get_entropy_info(path: String) -> Result<EntropyInfoDto, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        let entropy = diec_engine::struct_mode::shannon_entropy(&data);
        Ok::<_, String>(EntropyInfoDto {
            file_size: data.len() as u64,
            entropy,
        })
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?
    .map_err(|e| GuiError::new("FILE_READ_FAILED", e))?;

    Ok(result)
}

/// Entropy information DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyInfoDto {
    /// File size in bytes.
    pub file_size: u64,
    /// Shannon entropy (0.0 - 8.0).
    pub entropy: f64,
}

/// Get file info (GUI `--info` mode).
///
/// Returns basic file metadata: size, type, hash.
#[tauri::command]
pub async fn get_scan_info(path: String) -> Result<ScanInfoDto, GuiError> {
    let result = tokio::task::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        let md5 = crate::file_info::compute_md5(&data);
        let sha256 = crate::file_info::compute_sha256(&data);
        Ok::<_, String>(ScanInfoDto {
            file_size: data.len() as u64,
            md5,
            sha256,
        })
    })
    .await
    .map_err(|e| GuiError::new("TASK_JOIN_FAILED", e.to_string()))?
    .map_err(|e| GuiError::new("FILE_READ_FAILED", e))?;

    Ok(result)
}

/// File info DTO for `--info` mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanInfoDto {
    /// File size in bytes.
    pub file_size: u64,
    /// MD5 hash hex string.
    pub md5: String,
    /// SHA-256 hash hex string.
    pub sha256: String,
}

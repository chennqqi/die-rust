//! Settings persistence for die-gui.
//!
//! Settings are stored as JSON in the Tauri app config directory.
//! This module defines the settings structure and provides
//! load/save helpers using `tauri-plugin-store`.

use serde::{Deserialize, Serialize};

/// Application settings mirroring upstream `XOptions` categories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// View settings (theme, language, fonts, stay-on-top, advanced).
    pub view: ViewSettings,
    /// File settings (last directory, recent files, backup).
    pub file: FileSettings,
    /// Scan settings (flags, hide unknown, sort, profiling).
    pub scan: ScanSettings,
    /// Database paths (main, extra, custom).
    pub database: DatabaseSettings,
    /// Engine enable flags (DIE, NFD, PEID, YARA).
    pub engine: EngineSettings,
    /// Online tools settings (VirusTotal API key, etc.).
    pub online_tools: OnlineToolsSettings,
    /// Keyboard shortcut configuration.
    pub shortcuts: ShortcutSettings,
}

/// Online tools settings (upstream `XOptions::ID_ONLINETOOLS_*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnlineToolsSettings {
    /// VirusTotal API key (empty = browser jump mode, non-empty = API query mode).
    /// Upstream uses MD5 hash for both modes.
    pub virustotal_apikey: String,
}

/// View-related settings (upstream `XOptions::ID_VIEW_*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewSettings {
    /// Theme name: "light", "dark", "system", a built-in theme class
    /// ("solarized-dark", ...), or "custom".
    pub theme: String,
    /// Custom-theme CSS variable overrides (`--name: r g b` per line),
    /// used when `theme == "custom"` (Phase 49).
    #[serde(default)]
    pub custom_theme: String,
    /// Language code: "en", "zh-CN", "ru", etc.
    pub language: String,
    /// Stay on top of other windows.
    pub stay_on_top: bool,
    /// Advanced mode (shows Demangle button, advanced scan widget).
    pub advanced: bool,
}

/// File-related settings (upstream `XOptions::ID_FILE_*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSettings {
    /// Last opened directory.
    pub last_directory: String,
    /// Recent files list (most recent first).
    pub recent_files: Vec<String>,
    /// Save backup of edited signatures.
    pub save_backup: bool,
}

/// Scan-related settings (upstream `XOptions::ID_SCAN_*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSettings {
    /// Scan after opening a file.
    pub scan_after_open: bool,
    /// Hide unknown detections.
    pub hide_unknown: bool,
    /// Sort results.
    pub sort: bool,
    /// Log profiling data.
    pub log_profiling: bool,
    /// Default scan flags.
    pub flags: ScanFlagDefaults,
}

/// Default scan flag values (upstream `XOptions::ID_SCAN_FLAG_*`).
///
/// Field names match `ScanFlagsDto` in `commands.rs` for direct
/// frontend-to-backend round-trip without renaming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFlagDefaults {
    pub recursive: bool,
    pub deep: bool,
    pub heuristic: bool,
    pub verbose: bool,
    pub aggressive: bool,
    pub alltypes: bool,
    pub overlay: bool,
    pub resources: bool,
    pub archives: bool,
    pub first_wrapper_only: bool,
    pub hide_unknown: bool,
    /// Disable result deduplication (--no-dedup).
    pub no_dedup: bool,
    /// Optional archive extraction bounds override (ADR 0030). Absent or
    /// partially-filled fields fall back to the engine defaults.
    #[serde(default)]
    pub archive_limits: Option<die_engine::ArchiveLimits>,
}

/// Database path settings (upstream `XOptions::ID_SCAN_DIE_DATABASE_*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseSettings {
    /// Main database path.
    pub main_path: String,
    /// Extra database path.
    pub extra_path: String,
    /// Custom database path.
    pub custom_path: String,
    /// Enable extra database.
    pub extra_enabled: bool,
    /// Enable custom database.
    pub custom_enabled: bool,
}

/// Engine enable flags (upstream `XOptions::ID_SCAN_ENGINE_*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineSettings {
    /// DIE engine enabled.
    pub die_enabled: bool,
    /// NFD engine enabled.
    pub nfd_enabled: bool,
    /// PEID engine enabled.
    pub peid_enabled: bool,
    /// YARA engine enabled.
    pub yara_enabled: bool,
}

/// Keyboard shortcut configuration (upstream `XShortcuts`).
///
/// Each shortcut is a comma-separated list of modifier+key strings,
/// e.g. "Ctrl+O", "Ctrl+Shift+S".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShortcutSettings {
    /// Open file (default: Ctrl+O).
    pub open_file: String,
    /// Save results (default: Ctrl+S).
    pub save_results: String,
    /// Scan file (default: F5).
    pub scan: String,
    /// Stop scan (default: Escape).
    pub stop_scan: String,
    /// Toggle hex view (default: Ctrl+H).
    pub toggle_hex: String,
    /// Toggle strings view (default: Ctrl+T).
    pub toggle_strings: String,
    /// Open settings (default: Ctrl+,).
    pub open_settings: String,
    /// Quit application (default: Ctrl+Q).
    pub quit: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            view: ViewSettings {
                theme: "system".to_string(),
                custom_theme: String::new(),
                language: "en".to_string(),
                stay_on_top: false,
                advanced: false,
            },
            file: FileSettings {
                last_directory: String::new(),
                recent_files: Vec::new(),
                save_backup: true,
            },
            scan: ScanSettings {
                scan_after_open: true,
                hide_unknown: false,
                sort: false,
                log_profiling: false,
                flags: ScanFlagDefaults {
                    recursive: true,
                    deep: false,
                    heuristic: false,
                    verbose: false,
                    aggressive: false,
                    alltypes: false,
                    overlay: true,
                    resources: true,
                    archives: true,
                    first_wrapper_only: false,
                    hide_unknown: false,
                    no_dedup: false,
                    archive_limits: None,
                },
            },
            database: DatabaseSettings {
                main_path: "./db".to_string(),
                extra_path: String::new(),
                custom_path: String::new(),
                extra_enabled: false,
                custom_enabled: false,
            },
            engine: EngineSettings {
                die_enabled: true,
                nfd_enabled: false,
                peid_enabled: false,
                yara_enabled: false,
            },
            online_tools: OnlineToolsSettings {
                virustotal_apikey: String::new(),
            },
            shortcuts: ShortcutSettings {
                open_file: "Ctrl+O".to_string(),
                save_results: "Ctrl+S".to_string(),
                scan: "F5".to_string(),
                stop_scan: "Escape".to_string(),
                toggle_hex: "Ctrl+H".to_string(),
                toggle_strings: "Ctrl+T".to_string(),
                open_settings: "Ctrl+,".to_string(),
                quit: "Ctrl+Q".to_string(),
            },
        }
    }
}

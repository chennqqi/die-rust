//! Settings persistence for die-gui.
//!
//! Settings are stored as JSON in the Tauri app config directory.
//! This module defines the settings structure and provides
//! load/save helpers using `tauri-plugin-store`.

use serde::{Deserialize, Serialize};

/// Application settings mirroring upstream `XOptions` categories.
///
/// `#[serde(default)]` fills fields missing from settings files written
/// by older versions (e.g. `online_tools`, `shortcuts`) instead of
/// failing deserialization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OnlineToolsSettings {
    /// VirusTotal API key (empty = browser jump mode, non-empty = API query mode).
    /// Upstream uses MD5 hash for both modes.
    pub virustotal_apikey: String,
}

/// View-related settings (upstream `XOptions::ID_VIEW_*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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

impl Default for ViewSettings {
    fn default() -> Self {
        Self {
            theme: "system".to_string(),
            custom_theme: String::new(),
            language: "en".to_string(),
            stay_on_top: false,
            advanced: false,
        }
    }
}

impl Default for FileSettings {
    fn default() -> Self {
        Self {
            last_directory: String::new(),
            recent_files: Vec::new(),
            save_backup: true,
        }
    }
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            scan_after_open: true,
            hide_unknown: false,
            sort: false,
            log_profiling: false,
            flags: ScanFlagDefaults::default(),
        }
    }
}

impl Default for ScanFlagDefaults {
    fn default() -> Self {
        Self {
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
        }
    }
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self {
            main_path: "./db".to_string(),
            extra_path: String::new(),
            custom_path: String::new(),
            extra_enabled: false,
            custom_enabled: false,
        }
    }
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            die_enabled: true,
            nfd_enabled: false,
            peid_enabled: false,
            yara_enabled: false,
        }
    }
}

impl Default for ShortcutSettings {
    fn default() -> Self {
        Self {
            open_file: "Ctrl+O".to_string(),
            save_results: "Ctrl+S".to_string(),
            scan: "F5".to_string(),
            stop_scan: "Escape".to_string(),
            toggle_hex: "Ctrl+H".to_string(),
            toggle_strings: "Ctrl+T".to_string(),
            open_settings: "Ctrl+,".to_string(),
            quit: "Ctrl+Q".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AppSettings;

    /// Settings files written by older versions may lack fields added
    /// later (`online_tools`, `shortcuts`, `scan.flags.no_dedup`, ...).
    /// Deserialization must fill them from defaults instead of failing
    /// (die-rust issue #1).
    #[test]
    fn settings_missing_new_fields_fall_back_to_defaults() {
        let old = serde_json::json!({
            "view": { "theme": "dark", "language": "zh-CN", "stay_on_top": true, "advanced": true },
            "file": { "last_directory": "/tmp", "recent_files": ["a.exe"], "save_backup": false },
            "scan": {
                "scan_after_open": false,
                "hide_unknown": true,
                "sort": true,
                "log_profiling": true,
                "flags": {
                    "recursive": false,
                    "deep": true,
                    "heuristic": true,
                    "verbose": true,
                    "aggressive": true,
                    "alltypes": true,
                    "overlay": false,
                    "resources": false,
                    "archives": false,
                    "first_wrapper_only": true,
                    "hide_unknown": true
                }
            },
            "database": {
                "main_path": "/opt/db",
                "extra_path": "/opt/extra",
                "custom_path": "",
                "extra_enabled": true,
                "custom_enabled": false
            },
            "engine": { "die_enabled": true, "nfd_enabled": true, "peid_enabled": false, "yara_enabled": false }
        });
        let s: AppSettings = serde_json::from_value(old).expect("legacy settings parse");
        // Stored values preserved.
        assert_eq!(s.view.theme, "dark");
        assert!(s.scan.flags.deep);
        assert!(s.engine.nfd_enabled);
        // Missing fields filled from defaults.
        assert_eq!(s.online_tools.virustotal_apikey, "");
        assert_eq!(s.shortcuts.open_file, "Ctrl+O");
        assert!(!s.scan.flags.no_dedup);
        assert_eq!(s.view.custom_theme, "");
    }

    /// A wholly empty settings object yields the full default set.
    #[test]
    fn settings_empty_object_uses_defaults() {
        let s: AppSettings = serde_json::from_str("{}").expect("empty settings parse");
        assert_eq!(s.view.theme, "system");
        assert!(s.scan.flags.recursive);
        assert_eq!(s.database.main_path, "./db");
    }
}

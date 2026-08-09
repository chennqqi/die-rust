//! `die-gui` is the Tauri v2 GUI adapter binary for diec.
//!
//! It owns the Tauri application lifecycle, IPC command registration,
//! and managed state. It depends on `diec-engine` for scan logic and
//! never duplicates detection branches. See `docs/design/phase8-gui.md`.

// Hide the console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod commands;
mod demangle;
mod disassembler;
mod elf_viewer;
mod extractor;
mod file_info;
mod hex_viewer;
mod macho_viewer;
mod misc_viewer;
mod pe_viewer;
mod peid_scanner;
mod search;
mod settings;
mod state;
mod string_extractor;
mod virustotal;
mod visualization;
mod yara_scanner;

use state::AppState;
use tauri::{Emitter, Manager};

/// Entry point for the die-gui Tauri application.
fn main() {
    // Collect any file path passed as command-line argument (from context menu).
    let initial_file: Option<String> = std::env::args_os()
        .nth(1)
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.starts_with('-'));

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            // Focus the existing window when a second instance is launched.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
                // If a file path was passed (context menu), emit it to frontend.
                if let Some(path) = argv.get(1)
                    && !path.starts_with('-')
                {
                    let _ = app.emit("context-menu-file", path);
                }
            }
        }))
        .plugin(tauri_plugin_store::Builder::default().build())
        .manage(AppState::new())
        .setup(move |app| {
            // If launched with a file path (context menu), emit it to frontend.
            if let Some(ref file_path) = initial_file {
                let _ = app.emit("context-menu-file", file_path);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan_file,
            commands::scan_bytes_cmd,
            commands::stop_scan,
            commands::list_signatures,
            commands::get_signature_source,
            commands::scan_directory,
            commands::demangle,
            commands::read_hex,
            commands::search_hex,
            commands::disassemble,
            commands::get_settings,
            commands::save_settings,
            commands::get_database_info,
            commands::yara_scan,
            commands::peid_scan,
            commands::get_file_info,
            commands::get_visualization,
            commands::list_extractable,
            commands::extract_item,
            commands::extract_range,
            commands::get_dex_view,
            commands::get_msdos_view,
            commands::get_ne_view,
            commands::get_le_view,
            commands::search_signature,
            commands::search_value,
            commands::detect_packers,
            commands::pe_dump_dos_stub,
            commands::pe_remove_dos_stub,
            commands::pe_add_dos_stub,
            commands::pe_dump_overlay,
            commands::pe_remove_overlay,
            commands::pe_add_overlay,
            commands::edit_string_at_offset,
            commands::extract_heuristic,
            commands::analyze_item,
            commands::write_binary_file,
            commands::get_entropy_graph,
            commands::get_pe_view,
            commands::get_elf_view,
            commands::get_macho_view,
            commands::extract_strings,
            commands::write_text_file,
            commands::save_signature_source,
            commands::run_signature,
            commands::list_archive,
            commands::get_data_paths,
            commands::read_data_file,
            commands::list_database_paths,
            commands::get_context_menu_status,
            commands::add_context_menu,
            commands::remove_context_menu,
            commands::virustotal_open_browser,
            commands::virustotal_query,
        ])
        .run(tauri::generate_context!())
        .expect("error while running DIE application");
}

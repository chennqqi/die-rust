//! Phase 48: Tauri auto-update commands — thin wrappers over
//! `tauri-plugin-updater` (`XOnlineTools`/`XUpdate` product-equivalent;
//! upstream Qt update flow is not on the diec console path).
//!
//! The update manifest is served from GitHub Releases (`latest.json`);
//! artifacts are minisign-verified against the dev pubkey embedded in
//! `tauri.conf.json`. The private signing key never enters the repo
//! (`tools/updater/dev.key`, gitignored) — see
//! `tools/gen_updater_dev.py` for regeneration and fixture signing.

use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;

/// `check_for_update` — query the configured update endpoints and
/// report whether a newer signed release is available.
///
/// Returns `{available, version, notes, body}`; `available` is false on
/// any error (offline, unsigned, malformed manifest) with `error` set —
/// the UI keeps this non-fatal so a failed check never blocks usage.
#[tauri::command]
pub async fn check_for_update(app: AppHandle) -> Result<serde_json::Value, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    match updater.check().await {
        Ok(Some(update)) => Ok(serde_json::json!({
            "available": true,
            "version": update.version,
            "notes": update.body.unwrap_or_default(),
            "error": serde_json::Value::Null,
        })),
        Ok(None) => Ok(serde_json::json!({
            "available": false,
            "version": serde_json::Value::Null,
            "notes": serde_json::Value::Null,
            "error": serde_json::Value::Null,
        })),
        Err(e) => Ok(serde_json::json!({
            "available": false,
            "version": serde_json::Value::Null,
            "notes": serde_json::Value::Null,
            "error": e.to_string(),
        })),
    }
}

/// `install_update` — check, download, verify the signature and install
/// the update, then relaunch the app. Signature verification happens
/// before install (`Update::download`); an invalid or unsigned artifact
/// aborts with an error and leaves the running binary untouched.
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<serde_json::Value, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    let Some(update) = updater.check().await.map_err(|e| e.to_string())? else {
        return Ok(serde_json::json!({"installed": false, "error": "no update available"}));
    };
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| e.to_string())?;
    // On Linux/macOS a relaunch is required to run the installed build;
    // on Windows the installer exits the process itself.
    #[cfg(not(target_os = "windows"))]
    app.restart();
    #[cfg(target_os = "windows")]
    return Ok(serde_json::json!({"installed": true}));
}

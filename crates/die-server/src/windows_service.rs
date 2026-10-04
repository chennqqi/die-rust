//! Windows Service integration for `died` (ADR 0017).
//!
//! Provides `install` and `uninstall` subcommands that register/unregister
//! the daemon as a Windows service via the Service Control Manager (SCM).
//!
//! The service runs `died --db <path> --bind <addr> ...` in foreground mode
//! under the SCM. The SCM handles start/stop/restart.

use std::path::Path;
use std::process::Command;

/// Install `died` as a Windows service.
///
/// Uses `sc.exe` for broad compatibility (no need for the service binary
/// to implement the SCM protocol itself). The service is configured to
/// run `died --db <path> --bind <addr> ...` in foreground mode.
pub fn install_windows_service(
    service_name: &str,
    exe_path: &Path,
    db_path: &str,
    bind: &str,
    allow_root: Option<&Path>,
) {
    // Build the service command line: "died --db <path> --bind <addr>"
    let mut bin_path = format!(
        "\"{}\" --db \"{}\" --bind {}",
        exe_path.display(),
        db_path,
        bind
    );
    if let Some(root) = allow_root {
        bin_path.push_str(&format!(" --allow-root \"{}\"", root.display()));
    }

    // Create the service via sc.exe.
    let create_result = Command::new("sc")
        .args([
            "create",
            service_name,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "DisplayName=",
            "diec scan daemon (died)",
        ])
        .output();

    match create_result {
        Ok(output) if output.status.success() => {
            eprintln!("Service '{service_name}' installed successfully.");
            eprintln!("  binPath: {bin_path}");
            eprintln!();
            eprintln!("Start with:  sc start {service_name}");
            eprintln!("Stop with:   sc stop {service_name}");
            eprintln!("Configure:   sc config {service_name}");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            eprintln!("error: sc create failed:");
            if !stdout.is_empty() {
                eprintln!("  stdout: {stdout}");
            }
            if !stderr.is_empty() {
                eprintln!("  stderr: {stderr}");
            }
            eprintln!();
            eprintln!("Hint: Run this command as Administrator.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: failed to run sc.exe: {e}");
            eprintln!("Hint: sc.exe is available on all Windows systems.");
            std::process::exit(1);
        }
    }

    // Also set the service description.
    let _ = Command::new("sc")
        .args([
            "description",
            service_name,
            "HTTP/JSON scan service for diec (Detect It Easy). Provides local and remote file identification via a REST API.",
        ])
        .output();
}

/// Uninstall a Windows service by name.
pub fn uninstall_windows_service(service_name: &str) {
    // Try to stop the service first (ignore errors if it's not running).
    let _ = Command::new("sc").args(["stop", service_name]).output();

    // Delete the service.
    let delete_result = Command::new("sc").args(["delete", service_name]).output();

    match delete_result {
        Ok(output) if output.status.success() => {
            eprintln!("Service '{service_name}' uninstalled successfully.");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            eprintln!("error: sc delete failed:");
            if !stdout.is_empty() {
                eprintln!("  stdout: {stdout}");
            }
            if !stderr.is_empty() {
                eprintln!("  stderr: {stderr}");
            }
            eprintln!();
            eprintln!("Hint: Run this command as Administrator.");
            eprintln!("       The service may need to be stopped first: sc stop {service_name}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: failed to run sc.exe: {e}");
            std::process::exit(1);
        }
    }
}

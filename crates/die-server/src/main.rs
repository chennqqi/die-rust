//! `died` (die daemon) is the HTTP/JSON scan service binary (ADR 0017).
//!
//! Usage:
//!   died --db <path> [--bind 127.0.0.1:8080] [--allow-root <dir>]
//!        [--max-file-size <bytes>] [--max-request-size <bytes>]
//!        [--scan-timeout <secs>]
//!   died install --db <path> [--bind ...] [--service-name died]
//!   died uninstall [--service-name died]
//!   died --help
//!   died --version
//!
//! On Windows, `died install` registers a Windows service that runs
//! `died run --db <path> ...` under the Service Control Manager.
//! On Linux/macOS, `install`/`uninstall` print a message indicating
//! that systemd/launchd integration is not yet implemented; use a
//! process supervisor or run `died` directly.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use die_server::routes;
use die_server::{AppState, ServerConfig};

/// Default Windows service name.
const DEFAULT_SERVICE_NAME: &str = "died";

fn print_usage() {
    eprintln!("died (die daemon) — HTTP/JSON scan service for diec");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  died [OPTIONS] --db <path>");
    eprintln!("  died install [SERVICE_OPTIONS] --db <path>");
    eprintln!("  died uninstall [--service-name <name>]");
    eprintln!();
    eprintln!("Run mode (default):");
    eprintln!("  --db <path>              Database directory (required)");
    eprintln!("  --bind <addr>            Bind address (default: 127.0.0.1:0)");
    eprintln!("  --allow-root <dir>       Allowed root directory for /scan/path");
    eprintln!("  --max-file-size <bytes>  Max file size for /scan/path (default: 256MB)");
    eprintln!("  --max-request-size <bytes>  Max body size for /scan/bytes (default: 256MB)");
    eprintln!("  --scan-timeout <secs>    Scan timeout in seconds (default: 30)");
    eprintln!();
    eprintln!("Service management:");
    eprintln!("  install                  Install as a Windows service (or print");
    eprintln!("                           systemd unit template on Linux)");
    eprintln!("  uninstall                Uninstall the Windows service");
    eprintln!("  --service-name <name>    Service name (default: died)");
    eprintln!();
    eprintln!("Other:");
    eprintln!("  --help, -h               Print this help and exit");
    eprintln!("  --version, -v            Print version and exit");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Check for subcommands first.
    if args.len() >= 2 {
        match args[1].as_str() {
            "install" => {
                run_install(&args[2..]);
                return;
            }
            "uninstall" => {
                run_uninstall(&args[2..]);
                return;
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            "--version" | "-v" => {
                println!("died {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            _ => {}
        }
    }

    // Default: run the server in foreground.
    run_server(&args[1..]).await;
}

/// Parse server options and run the HTTP server in the foreground.
async fn run_server(args: &[String]) {
    let mut db_path = String::new();
    let mut config = ServerConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_usage();
                return;
            }
            "--version" | "-v" => {
                println!("died {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--db" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --db requires a path argument");
                    std::process::exit(2);
                }
                db_path = args[i].clone();
            }
            "--bind" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --bind requires an address argument");
                    std::process::exit(2);
                }
                config.bind = args[i].clone();
            }
            "--allow-root" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --allow-root requires a directory argument");
                    std::process::exit(2);
                }
                config.allow_root = Some(PathBuf::from(&args[i]));
            }
            "--max-file-size" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --max-file-size requires a numeric argument");
                    std::process::exit(2);
                }
                config.max_file_size = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid --max-file-size value: {}", args[i]);
                    std::process::exit(2);
                });
            }
            "--max-request-size" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --max-request-size requires a numeric argument");
                    std::process::exit(2);
                }
                config.max_request_size = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid --max-request-size value: {}", args[i]);
                    std::process::exit(2);
                });
            }
            "--scan-timeout" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --scan-timeout requires a numeric argument");
                    std::process::exit(2);
                }
                config.scan_timeout_secs = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid --scan-timeout value: {}", args[i]);
                    std::process::exit(2);
                });
            }
            s if s.starts_with("--") => {
                eprintln!("error: unknown option: {s}");
                std::process::exit(2);
            }
            s => {
                eprintln!("error: unexpected argument: {s}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if db_path.is_empty() {
        db_path = find_db_path();
    }

    // Build the database.
    let database = match die_engine::DatabaseBuilder::new(&db_path).build() {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("error: failed to load database from {db_path}: {e}");
            std::process::exit(3);
        }
    };

    eprintln!(
        "died {} starting on {} (db: {}, rules: {})",
        env!("CARGO_PKG_VERSION"),
        config.bind,
        db_path,
        database.rule_count()
    );

    let state = Arc::new(AppState::new(database, config.clone()));
    let app = routes::build_router(state);

    let listener = tokio::net::TcpListener::bind(&config.bind)
        .await
        .unwrap_or_else(|e| {
            eprintln!("error: failed to bind {}: {e}", config.bind);
            std::process::exit(1);
        });

    let local_addr = listener.local_addr().unwrap_or_else(|_| {
        eprintln!("error: could not determine local address");
        std::process::exit(1);
    });

    eprintln!("Listening on http://{local_addr}");

    axum::serve(listener, app).await.unwrap_or_else(|e| {
        eprintln!("error: server failed: {e}");
        std::process::exit(1);
    });
}

/// Find the database path from environment variables or common locations.
fn find_db_path() -> String {
    // Try DIE_DB_PATH environment variable.
    if let Ok(env_path) = std::env::var("DIE_DB_PATH")
        && std::path::Path::new(&env_path).is_dir()
    {
        return env_path;
    }

    // Try db/ adjacent to executable.
    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        let adjacent = exe_dir.join("db");
        if adjacent.is_dir() {
            return adjacent.to_string_lossy().to_string();
        }
    }

    // Try development paths.
    let candidates = [
        "upstream/Detect-It-Easy/db",
        "../upstream/Detect-It-Easy/db",
        "../../upstream/Detect-It-Easy/db",
        "db",
    ];
    for c in &candidates {
        if std::path::Path::new(c).is_dir() {
            return c.to_string();
        }
    }

    eprintln!("error: database directory not found.");
    eprintln!("  Set DIE_DB_PATH or use --db <path>");
    std::process::exit(3);
}

/// Parse install subcommand arguments.
fn run_install(args: &[String]) {
    let mut service_name = DEFAULT_SERVICE_NAME.to_string();
    let mut db_path = String::new();
    let mut bind = "127.0.0.1:18080".to_string();
    let mut allow_root: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --db requires a path argument");
                    std::process::exit(2);
                }
                db_path = args[i].clone();
            }
            "--bind" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --bind requires an address argument");
                    std::process::exit(2);
                }
                bind = args[i].clone();
            }
            "--service-name" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --service-name requires a name argument");
                    std::process::exit(2);
                }
                service_name = args[i].clone();
            }
            "--allow-root" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --allow-root requires a directory argument");
                    std::process::exit(2);
                }
                allow_root = Some(PathBuf::from(&args[i]));
            }
            s if s.starts_with("--") => {
                eprintln!("error: unknown install option: {s}");
                std::process::exit(2);
            }
            s => {
                eprintln!("error: unexpected install argument: {s}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if db_path.is_empty() {
        db_path = find_db_path();
    }

    // Resolve the executable path for the service binary.
    let exe_path = std::env::current_exe().unwrap_or_else(|e| {
        eprintln!("error: cannot determine executable path: {e}");
        std::process::exit(1);
    });

    #[cfg(windows)]
    {
        install_windows_service(
            &service_name,
            &exe_path,
            &db_path,
            &bind,
            allow_root.as_deref(),
        );
    }

    #[cfg(not(windows))]
    {
        print_systemd_unit(
            &service_name,
            &exe_path,
            &db_path,
            &bind,
            allow_root.as_deref(),
        );
    }
}

/// Parse uninstall subcommand arguments.
fn run_uninstall(args: &[String]) {
    let mut service_name = DEFAULT_SERVICE_NAME.to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--service-name" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --service-name requires a name argument");
                    std::process::exit(2);
                }
                service_name = args[i].clone();
            }
            s if s.starts_with("--") => {
                eprintln!("error: unknown uninstall option: {s}");
                std::process::exit(2);
            }
            s => {
                eprintln!("error: unexpected uninstall argument: {s}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    #[cfg(windows)]
    {
        uninstall_windows_service(&service_name);
    }

    #[cfg(not(windows))]
    {
        eprintln!("Uninstall: on Linux, remove the systemd unit file:");
        eprintln!("  sudo systemctl stop {service_name}");
        eprintln!("  sudo rm /etc/systemd/system/{service_name}.service");
        eprintln!("  sudo systemctl daemon-reload");
    }
}

// ---------------------------------------------------------------------------
// Windows service support
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod windows_service;

#[cfg(windows)]
use windows_service::{install_windows_service, uninstall_windows_service};

// ---------------------------------------------------------------------------
// Linux systemd unit template
// ---------------------------------------------------------------------------

/// Print a systemd unit file template for manual installation.
#[cfg(not(windows))]
fn print_systemd_unit(
    service_name: &str,
    exe_path: &std::path::Path,
    db_path: &str,
    bind: &str,
    allow_root: Option<&std::path::Path>,
) {
    let mut args = format!("--db {db_path} --bind {bind}");
    if let Some(root) = allow_root {
        args.push_str(&format!(" --allow-root {}", root.display()));
    }

    let unit = format!(
        "# /etc/systemd/system/{service_name}.service\n\
         # Install with:\n\
         #   sudo cp {service_name}.service /etc/systemd/system/\n\
         #   sudo systemctl daemon-reload\n\
         #   sudo systemctl enable {service_name}\n\
         #   sudo systemctl start {service_name}\n\
         \n\
         [Unit]\n\
         Description=diec scan daemon (died)\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} {args}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         User=nobody\n\
         Group=nogroup\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe = exe_path.display(),
        args = args,
    );

    println!("{unit}");
    eprintln!("Service unit template printed to stdout.");
    eprintln!("Save it to /etc/systemd/system/{service_name}.service and run:");
    eprintln!("  sudo systemctl daemon-reload");
    eprintln!("  sudo systemctl enable --now {service_name}");
}

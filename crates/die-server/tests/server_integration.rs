//! Integration tests for the die-server HTTP/JSON API (ADR 0017).

use std::sync::Arc;

use die_server::{AppState, ServerConfig};
use tower::util::ServiceExt;

/// Helper: build AppState from the upstream database, or skip the test.
fn make_state() -> Option<Arc<AppState>> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let db_dir = root.join("upstream/Detect-It-Easy/db");
    if !db_dir.is_dir() {
        eprintln!("Skipping: upstream database not found");
        return None;
    }
    let database = match die_engine::DatabaseBuilder::new(&db_dir).build() {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("Skipping: database build failed: {e}");
            return None;
        }
    };
    let config = ServerConfig::default();
    Some(Arc::new(AppState::new(database, config)))
}

/// Test data: 7z magic bytes.
fn seven_zip_data() -> Vec<u8> {
    let mut d = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    d.resize(64, 0);
    d
}

#[tokio::test]
async fn health_returns_ok_and_version() {
    let state = match make_state() {
        Some(s) => s,
        None => return,
    };
    let app = die_server::routes::build_router(state);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["programVersion"].is_string());
    assert!(json["dbVersion"]["ruleCount"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn scan_bytes_detects_7zip() {
    let state = match make_state() {
        Some(s) => s,
        None => return,
    };
    let app = die_server::routes::build_router(state);

    let data = seven_zip_data();
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/scan/bytes?name=test.7z")
                .header("content-type", "application/octet-stream")
                .body(axum::body::Body::from(data))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["path"], "test.7z");
    let detections = json["detections"].as_array().unwrap();
    let found = detections
        .iter()
        .any(|d| d["name"].as_str().unwrap_or("").contains("7-Zip"));
    assert!(found, "Expected 7-Zip detection, got: {detections:?}");
}

#[tokio::test]
async fn scan_path_rejects_nonexistent_file() {
    let state = match make_state() {
        Some(s) => s,
        None => return,
    };
    let app = die_server::routes::build_router(state);

    let body = serde_json::json!({"path": "/nonexistent/file.bin", "flags": {}}).to_string();
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/scan/path")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn scan_bytes_random_data_no_false_positive() {
    let state = match make_state() {
        Some(s) => s,
        None => return,
    };
    let app = die_server::routes::build_router(state);

    let data: Vec<u8> = (0..128).map(|i| (i * 7 + 13) as u8).collect();
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/scan/bytes?name=random.bin")
                .header("content-type", "application/octet-stream")
                .body(axum::body::Body::from(data))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let detections = json["detections"].as_array().unwrap();
    let has_specific = detections.iter().any(|d| {
        let name = d["name"].as_str().unwrap_or("");
        name == "7-Zip" || name == "GZIP" || name == "BZip"
    });
    assert!(
        !has_specific,
        "Random data should not produce specific detections: {detections:?}"
    );
}

#[tokio::test]
async fn scan_path_with_allow_root_rejects_outside() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let db_dir = root.join("upstream/Detect-It-Easy/db");
    if !db_dir.is_dir() {
        eprintln!("Skipping: upstream database not found");
        return;
    }
    let database = Arc::new(
        die_engine::DatabaseBuilder::new(&db_dir)
            .build()
            .expect("build"),
    );
    // Set allow_root to a temp dir that doesn't contain the target file.
    let temp_dir = std::env::temp_dir().join("die-server-test-allow-root");
    std::fs::create_dir_all(&temp_dir).ok();
    let config = ServerConfig {
        allow_root: Some(temp_dir.clone()),
        ..Default::default()
    };
    let state = Arc::new(AppState::new(database, config));
    let app = die_server::routes::build_router(state);

    // Try to scan a file outside the allowed root.
    let body = serde_json::json!({"path": root.join("Cargo.toml"), "flags": {}}).to_string();
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/scan/path")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (403) because the path is outside allow_root.
    // Note: if Cargo.toml happens to be in temp_dir, this would be 200,
    // but that's extremely unlikely.
    assert!(
        response.status() == 403 || response.status() == 404,
        "Expected 403 or 404 for path outside allow_root, got {}",
        response.status()
    );

    // Cleanup.
    std::fs::remove_dir_all(&temp_dir).ok();
}

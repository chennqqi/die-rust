//! Phase 48: `tauri-plugin-updater` end-to-end flow tests.
//!
//! Fixtures under `corpus/updater/` are produced by
//! `tools/gen_updater_dev.py` with the gitignored dev key
//! (`tools/updater/dev.key`): a minisign-signed artifact plus `.sig`
//! texts embedded into manifests at serve time.
//!
//! Covered matrix (no install is ever performed — `Update::download`
//! verifies the signature and returns bytes):
//! - newer version + valid signature -> offered, bytes verified
//! - tampered signature -> download rejected
//! - signed-version mismatch -> download rejected
//! - unreachable endpoint -> check fails closed
//! - older manifest version -> no update offered (downgrade protection)

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread::JoinHandle;

use tauri_plugin_updater::UpdaterExt;

/// Dev pubkey from `tauri.conf.json` (`tools/gen_updater_dev.py pubkey`).
const DEV_PUB: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IGRpZWMtcnVzdCBkZXYgdXBkYXRlciBrZXkKUldSa2FXVmpaR1YyTWZNazhSZWZvMXRpaWZqTUVyNmRvdk85WVBKb1RhTEt5WW1IWUhhVUhZd1YK";

fn corpus(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/updater")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Spawn an HTTP/1.0 file server on a random localhost port. `build`
/// receives the server base URL and returns path -> body routes.
fn serve(build: impl FnOnce(&str) -> Vec<(String, Vec<u8>)>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let routes = build(&base);
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming().take(32) {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() || line.is_empty() {
                continue;
            }
            // Drain the rest of the request headers.
            let mut sink = String::new();
            while reader.read_line(&mut sink).is_ok_and(|n| n > 2) {
                sink.clear();
            }
            let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
            let route = routes.iter().find(|(p, _)| p == &path);
            let (status, body) = match route {
                Some((_, b)) => ("200 OK", b.clone()),
                None => ("404 Not Found", Vec::new()),
            };
            let head = format!(
                "HTTP/1.0 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });
    (base, handle)
}

/// Manifest JSON for `version` with the given `.sig` (base64-encoded
/// signature-file text) and artifact URL.
fn manifest(version: &str, signature_b64: &str, artifact_url: &str) -> Vec<u8> {
    format!(
        r#"{{"version":"{version}","notes":"dev fixture","pub_date":"2026-10-12T00:00:00Z","platforms":{{"linux-x86_64":{{"signature":"{signature_b64}","url":"{artifact_url}"}}}}}}"#
    )
    .into_bytes()
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = c.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b)) << ((3 - c.len()) * 8);
        for i in 0..4 {
            out.push(if i < 4 - (3 - c.len()) {
                T[((n >> (18 - i * 6)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn sig_b64(file: &str) -> String {
    base64_encode(&corpus(file))
}

fn build_updater(
    app: &tauri::App<tauri::test::MockRuntime>,
    endpoint: &str,
) -> tauri_plugin_updater::Updater {
    app.updater_builder()
        .endpoints(vec![endpoint.parse().unwrap()])
        .expect("valid endpoint")
        .pubkey(DEV_PUB)
        .target("linux-x86_64")
        .build()
        .expect("updater build")
}

fn mock_app() -> tauri::App<tauri::test::MockRuntime> {
    // The real tauri.conf.json carries `plugins.updater`; tests override
    // endpoints/pubkey via `updater_builder` anyway, so the embedded
    // config only needs to deserialize.
    tauri::test::mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(tauri::generate_context!("tauri.conf.json"))
        .expect("mock app")
}

/// Newer manifest + valid signature: `check` offers the update and
/// `download` returns the exact artifact bytes after signature verify.
#[test]
fn update_available_and_download_verifies() {
    let artifact = corpus("update.bin");
    let sig = sig_b64("update.sig.txt");
    let (base, _srv) = serve(|base| {
        vec![
            (
                "/latest.json".into(),
                manifest("99.0.0", &sig, &format!("{base}/update.bin")),
            ),
            ("/update.bin".into(), artifact.clone()),
        ]
    });
    let app = mock_app();
    let updater = build_updater(&app, &format!("{base}/latest.json"));
    let update = tauri::async_runtime::block_on(updater.check())
        .expect("check")
        .expect("update expected");
    assert_eq!(update.version, "99.0.0");
    let bytes = tauri::async_runtime::block_on(update.download(|_, _| {}, || {}))
        .expect("download verifies signature");
    assert_eq!(bytes, artifact);
}

/// Tampered signature: `check` still offers (the signature is verified
/// at download time) but `download` must reject.
#[test]
fn tampered_signature_rejected() {
    let artifact = corpus("update.bin");
    let bad_sig = {
        let mut s = sig_b64("update.sig.txt").into_bytes();
        let i = s.len() / 2;
        s[i] = if s[i] == b'A' { b'B' } else { b'A' };
        String::from_utf8(s).unwrap()
    };
    let (base, _srv) = serve(|base| {
        vec![
            (
                "/latest.json".into(),
                manifest("99.0.0", &bad_sig, &format!("{base}/update.bin")),
            ),
            ("/update.bin".into(), artifact.clone()),
        ]
    });
    let app = mock_app();
    let updater = build_updater(&app, &format!("{base}/latest.json"));
    let update = tauri::async_runtime::block_on(updater.check())
        .expect("check")
        .expect("update expected");
    let res = tauri::async_runtime::block_on(update.download(|_, _| {}, || {}));
    assert!(res.is_err(), "tampered signature must be rejected");
}

/// Signed-version mismatch: the artifact was signed for version 1.0.0
/// while the manifest announces 99.0.0 — the plugin must reject the
/// pair (protects against pairing a new version with an older release).
#[test]
fn signed_version_mismatch_rejected() {
    let artifact = corpus("update.bin");
    let mismatch_sig = sig_b64("update.sig.100.txt");
    let (base, _srv) = serve(|base| {
        vec![
            (
                "/latest.json".into(),
                manifest("99.0.0", &mismatch_sig, &format!("{base}/update.bin")),
            ),
            ("/update.bin".into(), artifact.clone()),
        ]
    });
    let app = mock_app();
    let updater = build_updater(&app, &format!("{base}/latest.json"));
    let update = tauri::async_runtime::block_on(updater.check())
        .expect("check")
        .expect("update expected");
    let res = tauri::async_runtime::block_on(update.download(|_, _| {}, || {}));
    assert!(res.is_err(), "signed-version mismatch must be rejected");
}

/// Older or equal manifest versions must not be offered — the built-in
/// version comparator is the downgrade protection.
#[test]
fn downgrade_not_offered() {
    let sig = sig_b64("update.sig.txt");
    for version in ["0.0.1", "0.1.0"] {
        let artifact = corpus("update.bin");
        let sig = sig.clone();
        let (base, _srv) = serve(|base| {
            vec![
                (
                    "/latest.json".into(),
                    manifest(version, &sig, &format!("{base}/update.bin")),
                ),
                ("/update.bin".into(), artifact.clone()),
            ]
        });
        let app = mock_app();
        let updater = build_updater(&app, &format!("{base}/latest.json"));
        let res = tauri::async_runtime::block_on(updater.check());
        match res {
            Ok(None) => {}
            other => panic!(
                "version {version}: expected no update, got {:?}",
                other.map(|o| o.map(|u| u.version))
            ),
        }
    }
}

/// Unreachable endpoint: `check` must fail closed with an error, not a
/// false "no update" or a panic.
#[test]
fn offline_endpoint_fails_closed() {
    // Bind then immediately drop a listener to obtain a dead port.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let app = mock_app();
    let updater = build_updater(&app, &format!("http://127.0.0.1:{port}/latest.json"));
    let res = tauri::async_runtime::block_on(updater.check());
    assert!(res.is_err(), "offline endpoint must error, got ok");
}

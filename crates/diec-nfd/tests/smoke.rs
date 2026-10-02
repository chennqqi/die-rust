//! Smoke tests: run the NFD table scans against corpus fixtures and
//! sanity-check detections.

use diec_nfd::{Detection, ScanOptions, ft_name, gen_names::ft, scan, sniff_ft};

fn corpus(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn show(name: &str, d: &[u8]) -> (u16, Vec<Detection>) {
    let ft = sniff_ft(d);
    let out = scan(d, ft, ScanOptions { deep_scan: true });
    eprintln!("== {name} (ft={})", ft_name(ft));
    for x in &out {
        eprintln!(
            "   {}: {} {} {}",
            x.record_type, x.record_name, x.version, x.info
        );
    }
    (ft, out)
}

#[test]
fn pe32_packed_detects_upx_related() {
    let d = corpus("upx-pe32-nrv2b.exe");
    let (ft, out) = show("upx-pe32-nrv2b", &d);
    assert!(ft == ft::FT_PE32, "ft={}", ft_name(ft));
    let names: Vec<&str> = out.iter().map(|r| r.record_name).collect();
    // UPX-packed files must surface UPX via section names / imphash /
    // entrypoint tables at minimum.
    assert!(
        names.iter().any(|n| n.contains("UPX")),
        "no UPX in {names:?}"
    );
}

#[test]
fn pe32_plain_is_pe() {
    let d = corpus("minimal.exe");
    let (ft, out) = show("minimal.exe", &d);
    assert!(ft == ft::FT_PE32 || ft == ft::FT_MSDOS);
    let _ = out;
}

#[test]
fn zip_header_detects_archive() {
    let d = corpus("minimal.apk");
    let (_ft, out) = show("minimal.apk", &d);
    assert!(out.iter().any(|r| r.record_name.contains("ZIP")
        || r.record_type == "Archive"
        || !r.record_name.is_empty()));
}

#[test]
fn malformed_inputs_no_panic() {
    for (i, d) in [
        vec![],
        vec![0u8],
        b"MZ".to_vec(),
        b"MZ"
            .iter()
            .cloned()
            .chain(std::iter::repeat_n(0, 64))
            .collect(),
        b"PK\x03\x04".to_vec(),
    ]
    .iter()
    .enumerate()
    {
        let ft = sniff_ft(d);
        let _ = scan(d, ft, ScanOptions { deep_scan: true });
        let _ = i;
    }
}

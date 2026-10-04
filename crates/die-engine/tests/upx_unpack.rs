//! UPX static-unpack differential tests.
//!
//! Fixtures under `corpus/` are UPX 5.2.1-packed builds of a trivial
//! mingw-w64/clang program plus their `upx -d` oracle outputs. The oracle is
//! independent: the pack header's own Adler32 fields validate the
//! decompression layer, and the `upx -d` files validate the PE rebuild.

use std::path::PathBuf;

use die_engine::{detect_upx, unpack_static as unpack};

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(name)
}

fn load(name: &str) -> Option<Vec<u8>> {
    std::fs::read(corpus(name)).ok()
}

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Minimal PE section view for structural comparison.
struct PeView {
    is64: bool,
    sections: Vec<(u32, u32, u32, u32)>, // va, vsize, raw_ptr, raw_size
    entry_rva: u32,
    image_base: u64,
}

fn pe_view(data: &[u8]) -> Option<PeView> {
    if data.len() < 64 || &data[0..2] != b"MZ" {
        return None;
    }
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if data.get(pe..pe + 4) != Some(b"PE\0\0") {
        return None;
    }
    let coff = pe + 4;
    let nsec = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().ok()?) as usize;
    let opt = coff + 20;
    let magic = u16::from_le_bytes(data[opt..opt + 2].try_into().ok()?);
    let is64 = magic == 0x20b;
    let entry = u32::from_le_bytes(data[opt + 16..opt + 20].try_into().ok()?);
    let image_base = if is64 {
        u64::from_le_bytes(data[opt + 24..opt + 32].try_into().ok()?)
    } else {
        u32::from_le_bytes(data[opt + 28..opt + 32].try_into().ok()?) as u64
    };
    let opt_size = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().ok()?) as usize;
    let table = opt + opt_size;
    let mut sections = Vec::new();
    for i in 0..nsec {
        let s = table + i * 40;
        if s + 40 > data.len() {
            return None;
        }
        sections.push((
            u32::from_le_bytes(data[s + 12..s + 16].try_into().ok()?),
            u32::from_le_bytes(data[s + 8..s + 12].try_into().ok()?),
            u32::from_le_bytes(data[s + 20..s + 24].try_into().ok()?),
            u32::from_le_bytes(data[s + 16..s + 20].try_into().ok()?),
        ));
    }
    Some(PeView {
        is64,
        sections,
        entry_rva: entry,
        image_base,
    })
}

fn section_bytes(data: &[u8], raw_ptr: u32, raw_size: u32) -> &[u8] {
    let start = raw_ptr as usize;
    let end = (raw_ptr as usize)
        .saturating_add(raw_size as usize)
        .min(data.len());
    data.get(start..end).unwrap_or(&[])
}

/// Differential check between our rebuilt image and the `upx -d` oracle:
/// same section layout and identical section contents up to the oracle's
/// meaningful bytes.
fn assert_matches_oracle(ours: &[u8], oracle: &[u8]) {
    let o = pe_view(ours).expect("unpacked output is not a valid PE");
    let r = pe_view(oracle).expect("oracle is not a valid PE");
    assert_eq!(o.is64, r.is64, "PE width changed");
    assert_eq!(o.entry_rva, r.entry_rva, "entry point RVA differs");
    assert_eq!(o.image_base, r.image_base, "image base differs");
    assert_eq!(o.sections.len(), r.sections.len(), "section count differs");
    for (i, (s, t)) in o.sections.iter().zip(r.sections.iter()).enumerate() {
        assert_eq!(s.0, t.0, "section {i} VA differs");
        if s.3 == 0 || t.3 == 0 {
            continue;
        }
        let ours_data = section_bytes(ours, s.2, s.3.min(t.3));
        let oracle_data = section_bytes(oracle, t.2, s.3.min(t.3));
        assert_eq!(ours_data, oracle_data, "section {i} contents differ");
    }
}

#[test]
fn detects_pe32_nrv2b() {
    let Some(data) = load("upx-pe32-nrv2b.exe") else {
        eprintln!("SKIP: fixture missing");
        return;
    };
    let info = detect_upx(&data).expect("UPX not detected");
    assert_eq!(info.method, 2, "expected NRV2B_LE32");
    assert_eq!(info.format, 9, "expected W32PE");
    assert!(info.u_len > 0 && info.c_len > 0);
}

#[test]
fn unpack_pe32_nrv2b_matches_oracle() {
    let (Some(data), Some(oracle)) = (
        load("upx-pe32-nrv2b.exe"),
        load("upx-pe32-nrv2b.unpacked.exe"),
    ) else {
        eprintln!("SKIP: fixtures missing");
        return;
    };
    let info = detect_upx(&data).unwrap();
    let compressed = &data[info.data_offset..info.data_offset + info.c_len as usize];
    assert_eq!(
        adler32(compressed),
        info.c_adler,
        "compressed adler mismatch"
    );
    let out = unpack(&data).expect("unpack failed");
    assert_matches_oracle(&out, &oracle);
}

#[test]
fn unpack_pe32_lzma_matches_oracle() {
    let (Some(data), Some(oracle)) = (
        load("upx-pe32-lzma.exe"),
        load("upx-pe32-lzma.unpacked.exe"),
    ) else {
        eprintln!("SKIP: fixtures missing");
        return;
    };
    let info = detect_upx(&data).expect("UPX not detected");
    assert_eq!(info.method, 14, "expected LZMA");
    let out = unpack(&data).expect("unpack failed");
    assert_matches_oracle(&out, &oracle);
}

#[test]
fn unpack_pe32_nrv2e_matches_oracle() {
    let (Some(data), Some(oracle)) = (
        load("upx-pe32-nrv2e.exe"),
        load("upx-pe32-nrv2e.unpacked.exe"),
    ) else {
        eprintln!("SKIP: fixtures missing");
        return;
    };
    let info = detect_upx(&data).expect("UPX not detected");
    assert_eq!(info.method, 8, "expected NRV2E_LE32");
    let out = unpack(&data).expect("unpack failed");
    assert_matches_oracle(&out, &oracle);
}

#[test]
fn unpack_pe64_nrv2b_matches_oracle() {
    let (Some(data), Some(oracle)) = (
        load("upx-pe64-nrv2b.exe"),
        load("upx-pe64-nrv2b.unpacked.exe"),
    ) else {
        eprintln!("SKIP: fixtures missing");
        return;
    };
    let info = detect_upx(&data).expect("UPX not detected");
    assert_eq!(info.format, 36, "expected W64PE");
    let out = unpack(&data).expect("unpack failed");
    assert_matches_oracle(&out, &oracle);
}

#[test]
fn decompressed_payload_adler_matches() {
    // Intrinsic oracle: pack header u_adler covers the decompressed payload.
    for name in [
        "upx-pe32-nrv2b.exe",
        "upx-pe32-lzma.exe",
        "upx-pe32-nrv2e.exe",
        "upx-pe64-nrv2b.exe",
    ] {
        let Some(data) = load(name) else {
            continue;
        };
        let info = detect_upx(&data).unwrap();
        let compressed = &data[info.data_offset..info.data_offset + info.c_len as usize];
        let payload =
            die_engine::unpack::decompress_payload(compressed, info.u_len as usize, info.method)
                .unwrap_or_else(|e| panic!("{name}: decompress failed: {e}"));
        assert_eq!(
            adler32(&payload),
            info.u_adler,
            "{name}: decompressed adler mismatch"
        );
    }
}

#[test]
fn rejects_non_upx_and_malformed() {
    assert!(!die_engine::is_upx_packed(b"MZ"));
    assert!(detect_upx(&[]).is_none());
    // Plain PE without UPX! magic.
    if let Some(pe) = load("minimal-pe64.exe") {
        assert!(!die_engine::is_upx_packed(&pe));
        assert!(unpack(&pe).is_err());
    }
    // Truncated packed file: no panic, clean error.
    if let Some(data) = load("upx-pe32-nrv2b.exe") {
        for cut in [64usize, 0x200, 0x300] {
            let _ = unpack(&data[..cut]);
        }
        // Corrupted compressed stream: no panic.
        let mut bad = data.clone();
        let info = detect_upx(&bad).unwrap();
        for i in 0..16.min(bad.len() - info.data_offset) {
            bad[info.data_offset + i] ^= 0xff;
        }
        let _ = unpack(&bad);
    }
}

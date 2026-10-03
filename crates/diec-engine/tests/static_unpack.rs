//! FSG/MEW static-unpack oracle differential tests.
//!
//! Fixtures under `corpus/` are deterministic synthetic packed PEs produced
//! by `tools/gen_fsg_corpus.py` / `tools/gen_mew_corpus.py`; the
//! `*.unpacked.exe` files are byte outputs of the upstream `XStaticUnpacker`
//! oracle build (`tools/nfd-oracle/build/unpack-oracle`), so the comparison
//! is an independent oracle, not a self-authored expectation.

use std::path::PathBuf;

use diec_engine::unpack::{
    PackerKind, detect_fsg, detect_mew, detect_packed, detect_petite, unpack_any, unpack_fsg,
    unpack_mew, unpack_petite,
};

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(name)
}

fn load(name: &str) -> Vec<u8> {
    std::fs::read(corpus(name)).expect(name)
}

#[test]
fn fsg_v100_minimal_matches_oracle() {
    let packed = load("fsg-v100-minimal.exe");
    let info = detect_fsg(&packed).expect("fsg detection");
    assert_eq!(info.sversion, "1.0-1.3");
    let ours = unpack_fsg(&packed, -1).expect("fsg unpack");
    let oracle = load("fsg-v100-minimal.unpacked.exe");
    assert_eq!(ours, oracle, "fsg v100 output must match upstream oracle");
}

#[test]
fn fsg_v100_two_sections_matches_oracle() {
    let packed = load("fsg-v100-two.exe");
    assert!(detect_fsg(&packed).is_some());
    let ours = unpack_fsg(&packed, -1).expect("fsg unpack");
    let oracle = load("fsg-v100-two.unpacked.exe");
    assert_eq!(ours, oracle, "fsg two-section output must match oracle");
}

#[test]
fn mew11_aplib_matches_oracle() {
    let packed = load("mew11-minimal.exe");
    let info = detect_mew(&packed).expect("mew detection");
    assert_eq!(info.sversion, "11 SE");
    assert!(!info.uses_lzma);
    let ours = unpack_mew(&packed, -1).expect("mew unpack");
    let oracle = load("mew11-minimal.unpacked.exe");
    assert_eq!(ours, oracle, "mew 11 aPLib output must match oracle");
}

#[test]
fn mew10_matches_oracle() {
    let packed = load("mew10-minimal.exe");
    let info = detect_mew(&packed).expect("mew detection");
    assert_eq!(info.sversion, "10");
    let ours = unpack_mew(&packed, -1).expect("mew unpack");
    let oracle = load("mew10-minimal.unpacked.exe");
    assert_eq!(ours, oracle, "mew 10 output must match oracle");
}

#[test]
fn mew_rejects_malformed() {
    // Truncations and corruptions must fail closed, never panic.
    let packed = load("mew11-minimal.exe");
    for cut in [0x100usize, 0x153, 0x200, 0x230, 0x3ff] {
        let t = &packed[..cut.min(packed.len())];
        assert!(detect_mew(t).is_none() || unpack_mew(t, -1).is_err());
    }
    let mut bad = packed.clone();
    bad[0x154] = 0x00; // stub opener
    assert!(detect_mew(&bad).is_none());
    let mut bad2 = packed;
    bad2[0x22f] = 0xFF; // corrupt stream end marker
    let _ = unpack_mew(&bad2, 0x400);
}

#[test]
fn petite2_minimal_matches_oracle() {
    let packed = load("petite2-minimal.exe");
    let info = detect_petite(&packed).expect("petite detection");
    assert_eq!(info.sversion, "2.x");
    let ours = unpack_petite(&packed, -1).expect("petite unpack");
    let oracle = load("petite2-minimal.unpacked.exe");
    assert_eq!(ours, oracle, "petite 2.x output must match oracle");
}

#[test]
fn petite_rejects_malformed() {
    let packed = load("petite2-minimal.exe");
    let mut bad = packed.clone();
    bad[0x600] = 0x00; // break the `mov eax` detection byte
    assert!(detect_petite(&bad).is_none());
    for cut in [0x80usize, 0x600, 0x605, 0x800] {
        let t = &packed[..cut];
        assert!(detect_petite(t).is_none() || unpack_petite(t, -1).is_err());
    }
    let mut bad2 = packed;
    bad2[0x808] = 0xFF; // corrupt first op entry
    let _ = unpack_petite(&bad2, 0x400);
}

#[test]
fn unpack_any_dispatches_by_packer() {
    for (fixture, kind, name) in [
        ("fsg-v100-minimal.exe", PackerKind::Fsg, "FSG"),
        ("mew11-minimal.exe", PackerKind::Mew, "MEW"),
        ("petite2-minimal.exe", PackerKind::Petite, "Petite"),
    ] {
        let packed = load(fixture);
        let info = detect_packed(&packed).expect(fixture);
        assert_eq!(info.kind, kind, "{fixture}");
        assert_eq!(info.name, name, "{fixture}");
        let ours = unpack_any(&packed).expect(fixture);
        let oracle = load(&fixture.replace(".exe", ".unpacked.exe"));
        assert_eq!(ours, oracle, "{fixture}");
    }
}

#[test]
fn detect_packed_rejects_plain_pe() {
    // Petite fixture stripped of its signature bytes must not match anything.
    let mut plain = load("petite2-minimal.exe");
    for b in &mut plain[0x600..0x640] {
        *b = 0x90;
    }
    plain[0x800..0x860].fill(0);
    assert!(detect_packed(&plain).is_none());
    assert!(unpack_any(&plain).is_err());
    assert!(detect_packed(b"not a pe").is_none());
}

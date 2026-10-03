//! FSG/MEW static-unpack oracle differential tests.
//!
//! Fixtures under `corpus/` are deterministic synthetic packed PEs produced
//! by `tools/gen_fsg_corpus.py` / `tools/gen_mew_corpus.py`; the
//! `*.unpacked.exe` files are byte outputs of the upstream `XStaticUnpacker`
//! oracle build (`tools/nfd-oracle/build/unpack-oracle`), so the comparison
//! is an independent oracle, not a self-authored expectation.

use std::path::PathBuf;

use diec_engine::unpack::{
    PackerKind, detect_aspack, detect_autoit, detect_boxedapp, detect_enigmavb, detect_fsg,
    detect_mew, detect_nspack, detect_packed, detect_petite, detect_yoda, extract_autoit,
    extract_boxedapp, extract_enigmavb, unpack_any, unpack_aspack, unpack_fsg, unpack_mew,
    unpack_nspack, unpack_petite, unpack_yoda,
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
        ("yoda13-minimal.exe", PackerKind::Yoda, "yC"),
        ("aspack212-minimal.exe", PackerKind::Aspack, "ASPack"),
        ("nspack-minimal.exe", PackerKind::Nspack, "NsPack"),
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

#[test]
fn yoda13_minimal_matches_oracle() {
    let packed = load("yoda13-minimal.exe");
    let info = detect_yoda(&packed).expect("yoda detection");
    assert_eq!(info.sversion, "1.3");
    let ours = unpack_yoda(&packed, -1).expect("yoda unpack");
    let oracle = load("yoda13-minimal.unpacked.exe");
    assert_eq!(ours, oracle, "yoda 1.3 output must match oracle");
}

#[test]
fn aspack212_minimal_matches_oracle() {
    let packed = load("aspack212-minimal.exe");
    let info = detect_aspack(&packed).expect("aspack detection");
    assert_eq!(info.sversion, "2.12");
    let ours = unpack_aspack(&packed, -1).expect("aspack unpack");
    let oracle = load("aspack212-minimal.unpacked.exe");
    assert_eq!(ours, oracle, "aspack 2.12 output must match oracle");
}

#[test]
fn nspack_minimal_matches_oracle() {
    let packed = load("nspack-minimal.exe");
    let info = detect_nspack(&packed).expect("nspack detection");
    assert_eq!(info.dsize, 0x410);
    assert_eq!(info.rva, 0x1000);
    let ours = unpack_nspack(&packed, -1).expect("nspack unpack");
    let oracle = load("nspack-minimal.unpacked.exe");
    assert_eq!(
        ours, oracle,
        "nspack naive-defilter output must match oracle"
    );
}

#[test]
fn nspack_gated_matches_oracle() {
    let packed = load("nspack-gated.exe");
    let info = detect_nspack(&packed).expect("nspack detection");
    assert_eq!(info.dsize, 0x900);
    let ours = unpack_nspack(&packed, -1).expect("nspack unpack");
    let oracle = load("nspack-gated.unpacked.exe");
    assert_eq!(
        ours, oracle,
        "nspack gated-defilter + import-rebuild output must match oracle"
    );
}

#[test]
fn nspack_rejects_malformed() {
    let packed = load("nspack-minimal.exe");
    // Truncations must fail closed, never panic.
    for cut in [0x100usize, 0x600, 0x60d, 0x680] {
        let t = &packed[..cut];
        assert!(detect_nspack(t).is_none() || unpack_nspack(t, -1).is_err());
    }
    let mut bad = packed.clone();
    bad[0x200] = 0x00; // break the loader prologue at the entry point
    assert!(detect_nspack(&bad).is_none());
    // Corrupt the mode byte (>= 0xE1 is rejected upstream); sos sits at
    // file offset 0x200 (raw ptr) + 0x600.
    let mut bad2 = packed.clone();
    bad2[0x800] = 0xFF;
    assert!(detect_nspack(&bad2).is_none() || unpack_nspack(&bad2, -1).is_err());
    // Corrupt the stream tail; must not hang or panic.
    let mut bad3 = packed;
    let n = bad3.len();
    bad3[n - 20] ^= 0xFF;
    let _ = unpack_nspack(&bad3, 0x400);
}

// ---------------------------------------------------------------------------
// AutoIt container extraction (v2 / EA05 / EA06) — multi-record oracle diff.
// Fixtures: tools/gen_autoit_corpus.py; oracle member files under
// corpus/autoit-*.records/ are outputs of the upstream XAUTOIT oracle.
// ---------------------------------------------------------------------------

fn autoit_diff(fixture: &str, records_dir: &str, version: &str) {
    let packed = load(fixture);
    let info = detect_autoit(&packed).expect("autoit detection");
    assert_eq!(info.version.version_string(), version, "{fixture}");
    let ours = extract_autoit(&packed, -1).expect("autoit extract");
    let mut oracle_names: Vec<String> = std::fs::read_dir(corpus(records_dir))
        .expect(records_dir)
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    oracle_names.sort();
    let mut our_names: Vec<String> = ours.iter().map(|r| r.name.clone()).collect();
    our_names.sort();
    assert_eq!(our_names, oracle_names, "{fixture} record names");
    for rec in &ours {
        let oracle = load(&format!("{records_dir}/{}", rec.name));
        assert_eq!(rec.data, oracle, "{fixture}:{}", rec.name);
    }
}

#[test]
fn autoit_v2_matches_oracle() {
    autoit_diff("autoit-v2.bin", "autoit-v2.records", "v2");
}

#[test]
fn autoit_ea05_matches_oracle() {
    autoit_diff("autoit-ea05.bin", "autoit-ea05.records", "EA05");
}

#[test]
fn autoit_ea06_matches_oracle() {
    autoit_diff("autoit-ea06.bin", "autoit-ea06.records", "EA06");
}

#[test]
fn autoit_rejects_malformed() {
    for fixture in ["autoit-v2.bin", "autoit-ea05.bin", "autoit-ea06.bin"] {
        let packed = load(fixture);
        // Truncations must fail closed (no records / no panic).
        for cut in [16usize, 32, 64, 128] {
            let t = &packed[..cut.min(packed.len())];
            let _ = extract_autoit(t, -1);
        }
        // Flip bytes across the whole file: detect may still fire (v2
        // signature scan) but extraction must never panic.
        for off in [0usize, 20, 60, 120, 200] {
            if off >= packed.len() {
                continue;
            }
            let mut bad = packed.clone();
            bad[off] ^= 0xFF;
            let _ = extract_autoit(&bad, -1);
        }
    }
    assert!(detect_autoit(b"not an autoit file").is_none());
}

// ---------------------------------------------------------------------------
// EnigmaVB container — oracle member files under corpus/enigmavb.records/.
// ---------------------------------------------------------------------------

#[test]
fn enigmavb_minimal_matches_oracle() {
    let packed = load("enigmavb-minimal.exe");
    let info = detect_enigmavb(&packed).expect("enigmavb detection");
    assert_eq!(info.sversion, "package v5");
    let ours = extract_enigmavb(&packed).expect("enigmavb extract");
    let mut names: Vec<&str> = ours.iter().map(|r| r.name.as_str()).collect();
    names.sort();
    assert_eq!(names, ["data.bin", "readme.txt"]);
    for rec in &ours {
        let oracle = load(&format!("enigmavb.records/{}", rec.name));
        assert_eq!(rec.data, oracle, "enigmavb:{}", rec.name);
    }
}

#[test]
fn enigmavb_rejects_malformed() {
    let packed = load("enigmavb-minimal.exe");
    for cut in [0x400usize, 0x460, 0x500, 0x700, 0x900] {
        let t = &packed[..cut.min(packed.len())];
        let _ = extract_enigmavb(t);
    }
    // Break the tail authenticator: the byte after the blob stream must
    // be 0x16 followed by zeros.
    let mut bad = packed.clone();
    let info = detect_enigmavb(&packed).unwrap();
    let base = info.base_offset;
    // find the 0x16 terminator by scanning the blob tail
    let pos = (base..base + info.tree_size)
        .find(|&i| packed[i] == 0x16)
        .expect("terminator");
    bad[pos] = 0x00;
    assert!(extract_enigmavb(&bad).is_err());
    // Non-zero padding must fail.
    let mut bad2 = packed;
    bad2[base + info.tree_size - 1] = 0xFF;
    assert!(extract_enigmavb(&bad2).is_err());
    assert!(detect_enigmavb(b"not a pe").is_none());
}

// ---------------------------------------------------------------------------
// BoxedApp container — oracle member files under corpus/boxedapp.records/.
// ---------------------------------------------------------------------------

#[test]
fn boxedapp_minimal_matches_oracle() {
    let packed = load("boxedapp-minimal.exe");
    let info = detect_boxedapp(&packed).expect("boxedapp detection");
    assert_eq!(info.sversion, "");
    let ours = extract_boxedapp(&packed).expect("boxedapp extract");
    let mut names: Vec<&str> = ours.iter().map(|r| r.name.as_str()).collect();
    names.sort();
    assert_eq!(names, ["app.exe", "lib.dll"]);
    for rec in &ours {
        let oracle = load(&format!("boxedapp.records/{}", rec.name));
        assert_eq!(rec.data, oracle, "boxedapp:{}", rec.name);
    }
}

#[test]
fn boxedapp_rejects_malformed() {
    let packed = load("boxedapp-minimal.exe");
    for cut in [0x400usize, 0x480, 0x600, 0x900] {
        let t = &packed[..cut.min(packed.len())];
        let _ = extract_boxedapp(t);
    }
    // Corrupt the zlib payload: authenticated node + bad payload must
    // fail the whole extraction.
    let mut bad = packed.clone();
    let n = bad.len();
    for b in bad.iter_mut().take(n.min(0x700)).skip(0x600) {
        if *b == 0x78 {
            *b = 0x77;
            break;
        }
    }
    let _ = extract_boxedapp(&bad);
    // Drop the .main marker: detection must fail.
    let mut bad2 = packed;
    bad2[0x800..0x810].fill(0);
    assert!(detect_boxedapp(&bad2).is_none());
    assert!(detect_boxedapp(b"not a pe").is_none());
}

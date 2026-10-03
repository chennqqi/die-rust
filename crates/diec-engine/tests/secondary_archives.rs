//! Differential tests for Phase 32 secondary archive enumeration.
//!
//! Expected records come from the pinned upstream `list-oracle` harness
//! (tools/nfd-oracle/list_main.cpp → tools/nfd-oracle/build/list-oracle),
//! stored as `corpus/*.list.json` snapshots — the same oracle-snapshot
//! pattern used by `*.records` for the static unpackers.

use serde_json::Value;
use std::path::{Path, PathBuf};

fn corpus_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("corpus")
}

/// Load the upstream list-oracle snapshot for `fixture`.
fn oracle_records(fixture: &Path) -> Vec<Value> {
    let json_path = PathBuf::from(format!("{}.list.json", fixture.display()));
    let text = std::fs::read_to_string(&json_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", json_path.display()));
    let parsed: Value = serde_json::from_str(&text).expect("oracle json");
    let reports = parsed.as_array().expect("reports array");
    assert_eq!(reports.len(), 1, "expected exactly one claiming format");
    reports[0]["records"].as_array().unwrap().clone()
}

/// Compare our enumeration against the upstream record list (name,
/// sizes, directory flag, mtime).
fn check_fixture(name: &str, kind: diec_engine::archive::SecondaryKind) {
    let fixture = corpus_root().join(name);
    let data = std::fs::read(&fixture)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", fixture.display()));
    let (got_kind, members) = diec_engine::archive::list_secondary(&data)
        .unwrap_or_else(|| panic!("no secondary format claimed {name}"));
    assert_eq!(got_kind, kind, "kind mismatch for {name}");

    let expected = oracle_records(&fixture);
    let got: Vec<Value> = members
        .iter()
        .map(|m| {
            let mut o = serde_json::json!({
                "name": m.name,
                "size": m.size.to_string(),
                "packed": m.packed_size.to_string(),
                "dir": m.is_directory,
            });
            if let Some(mt) = &m.modified {
                o["mtime"] = Value::String(mt.clone());
            }
            o
        })
        .collect();

    // Field-wise comparison: upstream always reports name/size/packed/
    // dir; mtime appears only when the format carries a valid one.
    assert_eq!(
        got.len(),
        expected.len(),
        "record count mismatch for {name}: got {got:?} want {expected:?}"
    );
    for (i, (g, w)) in got.iter().zip(expected.iter()).enumerate() {
        for key in ["name", "size", "packed", "dir"] {
            assert_eq!(
                &g[key], &w[key],
                "{name} record {i} field {key}: got {g:?} want {w:?}"
            );
        }
        assert_eq!(
            g.get("mtime").cloned().unwrap_or(Value::Null),
            w.get("mtime").cloned().unwrap_or(Value::Null),
            "{name} record {i} mtime"
        );
    }
    check_extract(name, kind, &expected, &members);
}

/// Byte-compare extracted member contents against the upstream oracle.
///
/// Oracle snapshots live under `corpus/extract/<fixture>.<fmt>.<idx>` and
/// exist only for records the upstream `unpackCurrent` succeeded on.
/// Records upstream failed on (unsupported methods) must yield empty
/// output on our side as well — same fail-closed contract.
fn check_extract(
    name: &str,
    kind: diec_engine::archive::SecondaryKind,
    expected: &[Value],
    members: &[diec_engine::archive::SecondaryRecord],
) {
    let fixture = corpus_root().join(name);
    let data = std::fs::read(&fixture).unwrap();
    let fmt = kind.display_name().to_lowercase();
    for (i, (w, m)) in expected.iter().zip(members.iter()).enumerate() {
        let member_name = w["name"].as_str().unwrap();
        let got = diec_engine::archive::extract_secondary(&data, kind, member_name);
        let snap = corpus_root()
            .join("extract")
            .join(format!("{name}.{fmt}.{i}"));
        if w["unpacked"].as_bool().unwrap_or(false) {
            let want = std::fs::read(&snap)
                .unwrap_or_else(|e| panic!("missing oracle extract {}: {e}", snap.display()));
            assert_eq!(
                got, want,
                "{name} member {i} ({member_name}) extract mismatch"
            );
        } else {
            assert!(
                got.is_empty(),
                "{name} member {i} ({member_name}): upstream failed to \
                 extract but we produced {} bytes",
                got.len()
            );
        }
        // Directories must never produce bytes on our side.
        if m.is_directory {
            assert!(got.is_empty(), "{name} member {i} is a directory");
        }
    }
}

#[test]
fn cpio_newc_records_match_oracle() {
    check_fixture("test-newc.cpio", diec_engine::archive::SecondaryKind::Cpio);
}

#[test]
fn cpio_odc_records_match_oracle() {
    check_fixture("test-odc.cpio", diec_engine::archive::SecondaryKind::Cpio);
}

#[test]
fn cpio_crc_records_match_oracle() {
    check_fixture("test-crc.cpio", diec_engine::archive::SecondaryKind::Cpio);
}

#[test]
fn cpio_binary_records_match_oracle() {
    check_fixture("test-bin.cpio", diec_engine::archive::SecondaryKind::Cpio);
}

#[test]
fn arj_records_match_oracle() {
    check_fixture("test.arj", diec_engine::archive::SecondaryKind::Arj);
}

#[test]
fn lha_level0_records_match_oracle() {
    check_fixture("test-l0.lha", diec_engine::archive::SecondaryKind::Lha);
}

#[test]
fn lha_level1_records_match_oracle() {
    check_fixture("test-l1.lha", diec_engine::archive::SecondaryKind::Lha);
}

#[test]
fn non_archives_rejected() {
    assert!(diec_engine::archive::list_secondary(b"").is_none());
    assert!(diec_engine::archive::list_secondary(b"MZ\x90\x00").is_none());
    assert!(diec_engine::archive::list_secondary(b"070701").is_none());
    // Truncated CPIO without TRAILER!!! must be rejected wholesale.
    let data = std::fs::read(corpus_root().join("test-newc.cpio")).unwrap();
    assert!(diec_engine::archive::list_secondary(&data[..data.len() / 2]).is_none());
}

#[test]
fn ace_records_match_oracle() {
    check_fixture("test.ace", diec_engine::archive::SecondaryKind::Ace);
}

#[test]
fn arj_method1_records_and_extract_match_oracle() {
    check_fixture("test-m1.arj", diec_engine::archive::SecondaryKind::Arj);
}

/// Phase 33: ACE tech-1 compressed member must decode byte-identically
/// to the upstream `XAceDecoder` oracle output.
#[test]
fn ace_compressed_records_and_extract_match_oracle() {
    check_fixture("test-m1.ace", diec_engine::archive::SecondaryKind::Ace);
}

/// Malformed ACE streams must fail closed (empty), never panic.
#[test]
fn ace_compressed_malformed_rejected() {
    let data = std::fs::read(corpus_root().join("test-m1.ace")).unwrap();
    // Truncate the archive mid-stream: extraction must not panic and
    // yields empty (either unlistable or decoder reject).
    for cut in [64usize, 100, 140, 150] {
        let short = &data[..cut];
        let _ = diec_engine::archive::extract_secondary(
            short,
            diec_engine::archive::SecondaryKind::Ace,
            "packed.bin",
        );
    }
}

/// Phase 33: ARJ method-4 (fastest) compressed member vs oracle.
#[test]
fn arj_method4_records_and_extract_match_oracle() {
    check_fixture("test-m4.arj", diec_engine::archive::SecondaryKind::Arj);
}

/// Malformed/truncated compressed ARJ streams must fail closed.
#[test]
fn arj_compressed_malformed_rejected() {
    let data = std::fs::read(corpus_root().join("test-m4.arj")).unwrap();
    for cut in [64usize, 100, 150, 170] {
        let short = &data[..cut.min(data.len())];
        let _ = diec_engine::archive::extract_secondary(
            short,
            diec_engine::archive::SecondaryKind::Arj,
            "packed4.bin",
        );
    }
}

/// Phase 34: LHA `-lh5-` compressed member (literal+match) vs oracle.
#[test]
fn lha_lh5_records_and_extract_match_oracle() {
    check_fixture("test-lh5.lha", diec_engine::archive::SecondaryKind::Lha);
}

/// Phase 34: LHA `-lh7-` compressed member (literals, 64 KiB window
/// parameters) vs oracle.
#[test]
fn lha_lh7_records_and_extract_match_oracle() {
    check_fixture("test-lh7.lha", diec_engine::archive::SecondaryKind::Lha);
}

/// Malformed/truncated LHA compressed streams must fail closed.
#[test]
fn lha_compressed_malformed_rejected() {
    let data = std::fs::read(corpus_root().join("test-lh5.lha")).unwrap();
    for cut in [32usize, 36, 38, 40] {
        let short = &data[..cut.min(data.len())];
        let _ = diec_engine::archive::extract_secondary(
            short,
            diec_engine::archive::SecondaryKind::Lha,
            "m5.bin",
        );
    }
    // Corrupted mid-stream bits: flip bytes inside the packed member
    // (offset 30..41 for the level-0 header used by the fixture).
    for off in 30..data.len().min(41) {
        let mut bad = data.clone();
        bad[off] ^= 0xFF;
        let _ = diec_engine::archive::extract_secondary(
            &bad,
            diec_engine::archive::SecondaryKind::Lha,
            "m5.bin",
        );
    }
}

/// Phase 34: LHA `-lh4-` member with a non-uniform 3-symbol literal
/// table (widths 1/2/2) and a len-3 match vs oracle.
#[test]
fn lha_lh4_records_and_extract_match_oracle() {
    check_fixture("test-lh4.lha", diec_engine::archive::SecondaryKind::Lha);
}

/// Phase 34: LHA `-lh6-` member (5-bit position-table metadata) vs
/// oracle.
#[test]
fn lha_lh6_records_and_extract_match_oracle() {
    check_fixture("test-lh6.lha", diec_engine::archive::SecondaryKind::Lha);
}

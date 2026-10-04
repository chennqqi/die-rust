//! Real-world packed-sample parity vs the upstream XStaticUnpacker oracle.
//!
//! Samples are third-party binaries (official packer distributions and the
//! public unipacker test corpus) fetched by
//! `tools/corpus/fetch_real_unpack_samples.py` into
//! `corpus/real-unpack/` and verified against `manifest.json` sha256s. The
//! binaries are not committed; the test skips gracefully per missing
//! sample. Expected results were captured from the pinned upstream build
//! (`tools/xemulator-oracle unpack`), not hand-written.
//!
//! Note the shape difference: the oracle prints an empty `{}` for each
//! non-claiming class while the Rust report omits them; `expect` models
//! the per-class observable result (claims / init_unpack / version) so
//! both failure paths and success paths are compared semantically.

use die_engine::unpack;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/real-unpack")
}

/// Run detect+unpack for one packer and return (claims, init_unpack, version).
fn run_packer(name: &str, data: &[u8]) -> (bool, Option<bool>, String) {
    match name {
        "installsimple" => {
            if unpack::detect_installsimple(data).is_none() {
                return (false, None, String::new());
            }
            match unpack::extract_installsimple(data, -1) {
                Ok(_records) => (true, Some(true), String::new()),
                Err(_) => (true, Some(false), String::new()),
            }
        }
        "aspack" => match unpack::detect_aspack(data) {
            None => (false, None, String::new()),
            Some(info) => {
                let ver = info.sversion.to_string();
                match unpack::unpack_aspack(data, -1) {
                    Ok(_out) => (true, Some(true), ver),
                    Err(_) => (true, Some(false), ver),
                }
            }
        },
        "petite" => match unpack::detect_petite(data) {
            None => (false, None, String::new()),
            Some(info) => {
                let ver = info.sversion.to_string();
                match unpack::unpack_petite(data, -1) {
                    Ok(_out) => (true, Some(true), ver),
                    Err(_) => (true, Some(false), ver),
                }
            }
        },
        _ => panic!("unknown packer {name}"),
    }
}

#[test]
fn real_samples_match_upstream_oracle() {
    let manifest_path = corpus_dir().join("manifest.json");
    let manifest_text = match std::fs::read_to_string(&manifest_path) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("SKIP: real-unpack manifest missing");
            return;
        }
    };
    let manifest: Value = serde_json::from_str(&manifest_text).expect("manifest json");
    let samples = manifest["samples"].as_array().expect("samples array");

    let mut compared = 0usize;
    let mut skipped = 0usize;
    for sample in samples {
        let name = sample["name"].as_str().unwrap();
        let path = corpus_dir().join(name);
        if !path.exists() {
            skipped += 1;
            eprintln!("SKIP: {name} not fetched (run tools/corpus/fetch_real_unpack_samples.py)");
            continue;
        }
        let data = std::fs::read(&path).expect("read sample");
        let digest = format!("{:x}", Sha256::digest(&data));
        assert_eq!(
            digest,
            sample["sha256"].as_str().unwrap(),
            "{name} sha256 mismatch vs manifest"
        );

        for packer in ["installsimple", "aspack", "petite"] {
            let expect = &sample["expect"][packer];
            let (claims, init_unpack, version) = run_packer(packer, &data);
            if expect.is_null() {
                // Oracle emitted `{}`: class must not claim the sample.
                assert!(
                    !claims,
                    "{name}: {packer} claims sample but upstream oracle does not"
                );
                continue;
            }
            let want_claims = expect["claims"].as_bool().unwrap();
            assert_eq!(
                claims, want_claims,
                "{name}: {packer} claims mismatch vs oracle"
            );
            if !claims {
                continue;
            }
            let want_init = expect["init_unpack"].as_bool().unwrap();
            assert_eq!(
                init_unpack,
                Some(want_init),
                "{name}: {packer} init_unpack mismatch vs oracle"
            );
            assert_eq!(
                version,
                expect["version"].as_str().unwrap(),
                "{name}: {packer} version mismatch vs oracle"
            );
        }
        compared += 1;
    }

    eprintln!("real-unpack parity: {compared} compared, {skipped} skipped");
    assert!(
        compared > 0 || skipped == samples.len(),
        "manifest present but no samples processed"
    );
}

//! i18n catalog parity gate — Phase 45.
//!
//! Asserts every locale JSON under `frontend/src/i18n/locales/` keeps the
//! same dotted-key set as `en.json`, preserves `{{var}}` interpolation
//! placeholders and %-format specifiers, and that English-identical
//! (untranslated) values are covered by the locale's draft manifest
//! (`<lang>.draft.json` `drafts` + `same`). Mirrors
//! `tools/i18n/check_i18n.py` for the cargo test gate.

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn locales_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("frontend/src/i18n/locales")
}

/// Flattens a nested JSON object into dotted-path -> string entries.
fn flatten(obj: &serde_json::Map<String, Value>, prefix: &str, out: &mut BTreeMap<String, String>) {
    for (key, value) in obj {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            Value::Object(inner) => flatten(inner, &path, out),
            Value::String(s) => {
                out.insert(path, s.clone());
            }
            other => panic!("non-string leaf at {path}: {other}"),
        }
    }
}

fn load_catalog(path: &Path) -> BTreeMap<String, String> {
    let text =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let json: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON {}: {e}", path.display()));
    let mut flat = BTreeMap::new();
    flatten(
        json.as_object().expect("locale root must be an object"),
        "",
        &mut flat,
    );
    flat
}

/// Extracts `{{name}}` interpolation variables in order of appearance.
fn placeholders(value: &str) -> Vec<String> {
    let mut vars = Vec::new();
    for part in value.split("{{").skip(1) {
        if let Some(end) = part.find("}}") {
            vars.push(part[..end].trim().to_string());
        }
    }
    vars.sort();
    vars
}

/// Extracts `%`-style format specifiers (e.g. `%d`, `%.2f`) in order.
fn format_specifiers(value: &str) -> Vec<String> {
    let mut specs = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'%') {
            specs.push("%%".to_string());
            i += 2;
            continue;
        }
        let mut j = i + 1;
        while j < bytes.len() && matches!(bytes[j], b'0'..=b'9' | b'-' | b'+' | b'.' | b' ') {
            j += 1;
        }
        if j < bytes.len() && bytes[j].is_ascii_alphabetic() {
            specs.push(value[i..=j].to_string());
            i = j + 1;
            continue;
        }
        i += 1;
    }
    specs
}

#[test]
fn i18n_catalogs_keep_key_parity_and_draft_manifests() {
    let dir = locales_dir();
    let en = load_catalog(&dir.join("en.json"));
    assert!(
        en.len() > 200,
        "en catalog should have ~269 keys, got {}",
        en.len()
    );

    let mut catalogs: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("locales dir must exist")
        .filter_map(|e| {
            let p = e.ok()?.path();
            let name = p.file_name()?.to_str()?.to_string();
            (name.ends_with(".json") && !name.ends_with(".draft.json") && name != "en.json")
                .then_some(p)
        })
        .collect();
    catalogs.sort();
    assert!(
        catalogs.len() >= 20,
        "expected 23+ non-en catalogs, got {}",
        catalogs.len()
    );

    let mut failures = Vec::new();
    for catalog in catalogs {
        let code = catalog.file_stem().unwrap().to_str().unwrap().to_string();
        let flat = load_catalog(&catalog);

        let missing: Vec<_> = en.keys().filter(|k| !flat.contains_key(*k)).collect();
        let extra: Vec<_> = flat.keys().filter(|k| !en.contains_key(*k)).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{code}: key mismatch missing={missing:?} extra={extra:?}"
        );

        for (path, enval) in &en {
            let val = &flat[path];
            assert_eq!(
                placeholders(enval),
                placeholders(val),
                "{code}:{path} placeholder mismatch"
            );
            assert_eq!(
                format_specifiers(enval),
                format_specifiers(val),
                "{code}:{path} format specifiers mismatch"
            );
        }

        let draft_path = catalog.with_file_name(format!("{code}.draft.json"));
        let untranslated: std::collections::BTreeSet<_> = flat
            .iter()
            .filter(|(p, v)| en.get(*p) == Some(*v))
            .map(|(p, _)| p.clone())
            .collect();
        assert!(draft_path.exists(), "{code}: missing draft manifest");
        let manifest: Value =
            serde_json::from_str(&fs::read_to_string(&draft_path).unwrap()).unwrap();
        let mut marked: std::collections::BTreeSet<String> = manifest["drafts"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .chain(manifest["same"].as_array().unwrap_or(&vec![]).iter())
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        let unmarked: Vec<_> = untranslated
            .iter()
            .filter(|p| !marked.contains(*p))
            .collect();
        if !unmarked.is_empty() {
            failures.push(format!(
                "{code}: {} unmarked untranslated keys, e.g. {:?}",
                unmarked.len(),
                &unmarked[..unmarked.len().min(3)]
            ));
        }
        marked.retain(|p| !untranslated.contains(p));
        if !marked.is_empty() {
            let stale: Vec<_> = marked.iter().take(3).collect();
            failures.push(format!(
                "{code}: {} manifest keys not English-identical, e.g. {stale:?}",
                marked.len()
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

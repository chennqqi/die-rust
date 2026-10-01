//! Archive record host API tests (Archive_Script / ZIP_Script / JAR_Script /
//! NPM_Script upstream semantics at XScanEngine 2550d2da).
//!
//! Verifies that `isArchiveRecordPresent`, `isArchiveRecordPresentExp`,
//! `getManifestRecord`, `getPackageJsonRecord` and `PE.isDosStubPresent`
//! behave per upstream source, backed by real ZIP member enumeration.

#![forbid(unsafe_code)]

use diec_core::cancel::CancellationToken;
use diec_engine::BufferHost;
use diec_rules::backend_rquickjs::RquickjsRuntime;
use diec_rules::host_api::HostApi;
use diec_rules::runtime::{DatabaseSnapshot, DetectionResult, RuleRuntime, RuntimeConfig};
use std::io::Write;
use std::sync::Arc;

/// Build an in-memory ZIP with the given (name, content) members.
fn make_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, content) in members {
        w.start_file(*name, opts).expect("start_file");
        w.write_all(content).expect("write");
    }
    w.finish().expect("finish").into_inner()
}

/// Create an initialized runtime bound to `host` (empty snapshot suffices:
/// rules are evaluated by source via `eval_rule`).
fn runtime_for(host: Arc<BufferHost>) -> RquickjsRuntime {
    let mut rt = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
    rt.load_database(&DatabaseSnapshot::empty()).unwrap();
    rt.register_host_api(host.clone()).unwrap();
    rt.init(&*host).unwrap();
    rt
}

/// Evaluate `rule` against `host` and return its detection results.
fn eval_rule(rt: &mut RquickjsRuntime, rule: &str) -> Vec<DetectionResult> {
    rt.evaluate_rule_source("test.sg", rule, &CancellationToken::new())
        .unwrap()
}

/// Host-level name enumeration: exact member list from the ZIP central
/// directory, empty for non-ZIP input.
#[test]
fn archive_record_names_lists_zip_members() {
    let zip = make_zip(&[("a.txt", b"hi"), ("dir/b.bin", b"xx")]);
    let host = BufferHost::new(zip, "test.zip".into());
    let mut names = host.archive_record_names();
    names.sort();
    assert_eq!(names, vec!["a.txt".to_string(), "dir/b.bin".to_string()]);

    let plain = BufferHost::new(b"not a zip".to_vec(), "t.bin".into());
    assert!(plain.archive_record_names().is_empty());
}

/// Upstream XArchive::isArchiveRecordPresent is an exact member-name match,
/// not a substring search of the file image.
#[test]
fn is_archive_record_present_exact_name_match() {
    // The name "a.txt" must match; "a" (substring) and "A.TXT" (case) must not.
    let zip = make_zip(&[("dir/a.txt", b"hi")]);
    let host = Arc::new(BufferHost::new(zip, "test.zip".into()));
    let mut rt = runtime_for(host);
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            var present = ZIP.isArchiveRecordPresent("dir/a.txt");
            var sub = ZIP.isArchiveRecordPresent("a.txt");
            var upper = ZIP.isArchiveRecordPresent("DIR/A.TXT");
            if (present && !sub && !upper)
                _setResult("info", "exact", "", "");
        }"#,
    );
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "exact");
}

/// Upstream isArchiveRecordPresentExp applies the pattern as a regex over
/// each record name and requires a non-empty whole match.
#[test]
fn is_archive_record_present_exp_regex_match() {
    let zip = make_zip(&[("package/package.json", b"{}"), ("src/main.js", b"")]);
    let host = Arc::new(BufferHost::new(zip, "test.npm".into()));
    let mut rt = runtime_for(host);
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            var hitsJs = NPM.isArchiveRecordPresentExp("(.*?).js");
            var hitsTs = NPM.isArchiveRecordPresentExp("(.*?).ts");
            if (hitsJs && !hitsTs)
                _setResult("info", "npm", "", "");
        }"#,
    );
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "npm");
}

/// Qt converts a RegExp argument to "/src/flags" text before applying it as
/// a pattern, so upstream effectively never matches regex literals passed
/// directly. The bridge reproduces that observable behavior.
#[test]
fn is_archive_record_present_exp_regexp_literal_matches_upstream_quirk() {
    let zip = make_zip(&[("assets/lib.arm64-v8a.so", b"")]);
    let host = Arc::new(BufferHost::new(zip, "test.apk".into()));
    let mut rt = runtime_for(host);
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            // Passing a RegExp literal: upstream returns false (the pattern
            // becomes "/assets\/lib\.arm64-v8a\.so/" with literal slashes).
            if (!APK.isArchiveRecordPresentExp(/assets\/lib\.arm64-v8a\.so/))
                _setResult("info", "quirk", "", "");
        }"#,
    );
    assert_eq!(results.len(), 1);
}

/// Upstream JAR_Script::getManifestRecord extracts "Key: value" lines from
/// META-INF/MANIFEST.MF, stripping \r.
#[test]
fn jar_get_manifest_record_reads_manifest() {
    let manifest = b"Manifest-Version: 1.0\r\nCreated-By: singlejar\r\n";
    let zip = make_zip(&[("META-INF/MANIFEST.MF", manifest)]);
    let host = Arc::new(BufferHost::new(zip, "test.jar".into()));
    let mut rt = runtime_for(host);
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            var v = JAR.getManifestRecord("Created-By");
            var missing = JAR.getManifestRecord("NoSuch");
            if (v === "singlejar" && missing === "")
                _setResult("info", "jar", "", "");
        }"#,
    );
    assert_eq!(results.len(), 1);
}

/// Upstream NPM_Script::getPackageJsonRecord returns the JSON string field
/// of package/package.json; non-string values map to "".
#[test]
fn npm_get_package_json_record() {
    let pkg = br#"{"name":"mypkg","version":"1.2.3","private":true}"#;
    let zip = make_zip(&[("package/package.json", pkg)]);
    let host = Arc::new(BufferHost::new(zip, "test.npm".into()));
    let mut rt = runtime_for(host);
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            var n = NPM.getPackageJsonRecord("name");
            var v = NPM.getPackageJsonRecord("version");
            var b = NPM.getPackageJsonRecord("private");
            var m = NPM.getPackageJsonRecord("missing");
            if (n === "mypkg" && v === "1.2.3" && b === "" && m === "")
                _setResult("info", "npm-pkg", "", "");
        }"#,
    );
    assert_eq!(results.len(), 1);
}

/// PE.isDosStubPresent mirrors MSDOS_Script::isDosStubPresent: true when the
/// DOS stub region (0x40..e_lfanew) is non-empty.
#[test]
fn pe_is_dos_stub_present() {
    // Minimal PE: MZ header, e_lfanew=0x80, stub 0x40..0x80 filled, PE sig.
    let mut pe = vec![0u8; 0x200];
    pe[0] = 0x4D;
    pe[1] = 0x5A;
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x40] = 0x54; // 'T' — non-zero stub content
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    // COFF header: machine, sections=1, ..., SizeOfOptionalHeader=0xE0
    pe[0x84..0x86].copy_from_slice(&0x14Cu16.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
    // Optional header magic PE32 at 0x98.
    pe[0x98..0x9A].copy_from_slice(&0x10Bu16.to_le_bytes());
    // Section header at 0x98+0xE0=0x178: name ".text", raw data in bounds.
    pe[0x178..0x180].copy_from_slice(b".text\0\0\0");
    pe[0x190..0x194].copy_from_slice(&0x10u32.to_le_bytes()); // SizeOfRawData
    pe[0x194..0x198].copy_from_slice(&0x180u32.to_le_bytes()); // PtrToRawData

    let host = Arc::new(BufferHost::new(pe, "test.exe".into()));
    let mut rt = runtime_for(host);
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            if (PE.isDosStubPresent() && PE.getDosStubOffset() === 0x40 &&
                PE.getDosStubSize() === 0x40)
                _setResult("info", "stub", "", "");
        }"#,
    );
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "stub");
}

/// PE without a DOS stub (e_lfanew <= 0x40): isDosStubPresent must be false.
#[test]
fn pe_no_dos_stub() {
    let mut pe = vec![0u8; 0x200];
    pe[0] = 0x4D;
    pe[1] = 0x5A;
    pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // PE right after header
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    pe[0x44..0x46].copy_from_slice(&0x14Cu16.to_le_bytes());
    pe[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    pe[0x54..0x56].copy_from_slice(&0xE0u16.to_le_bytes());
    pe[0x58..0x5A].copy_from_slice(&0x10Bu16.to_le_bytes());
    pe[0x138..0x140].copy_from_slice(b".text\0\0\0");
    pe[0x150..0x154].copy_from_slice(&0x10u32.to_le_bytes());
    pe[0x154..0x158].copy_from_slice(&0x180u32.to_le_bytes());

    let host = Arc::new(BufferHost::new(pe, "test.exe".into()));
    let mut rt = runtime_for(host);
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            if (!PE.isDosStubPresent() && PE.getDosStubSize() === 0)
                _setResult("info", "nostub", "", "");
        }"#,
    );
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "nostub");
}

/// Build a minimal NE16 DLL-type executable: MZ + e_lfanew -> "NE",
/// ne_flags 0x8000 (library), empty non-resident name table.
fn make_ne(flags: u16, nrt_off: u32, nrt_size: u16, tail: &[u8]) -> Vec<u8> {
    let lfanew = 0x80usize;
    let mut buf = vec![0u8; lfanew + 56 + tail.len()];
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    buf[0x3C..0x40].copy_from_slice(&(lfanew as u32).to_le_bytes());
    buf[lfanew] = 0x4E;
    buf[lfanew + 1] = 0x45;
    buf[lfanew + 12..lfanew + 14].copy_from_slice(&flags.to_le_bytes());
    buf[lfanew + 32..lfanew + 34].copy_from_slice(&nrt_size.to_le_bytes());
    buf[lfanew + 44..lfanew + 48].copy_from_slice(&nrt_off.to_le_bytes());
    buf[lfanew + 56..].copy_from_slice(tail);
    buf
}

#[test]
fn ne_type_methods_detect_driver_font_dll() {
    // NE DLL with non-resident name table containing "WONDERDRV".
    // Entry: len byte + name + 2-byte ordinal; terminated by len 0.
    let nrt_off = 0x100u32;
    let mut nrt = Vec::new();
    nrt.push(9u8);
    nrt.extend_from_slice(b"MYDRIVER1");
    nrt.extend_from_slice(&1u16.to_le_bytes());
    nrt.push(0u8);
    let mut data = make_ne(0x8000, nrt_off, nrt.len() as u16, &[]);
    if data.len() < nrt_off as usize + nrt.len() {
        data.resize(nrt_off as usize + nrt.len(), 0);
    }
    data[nrt_off as usize..nrt_off as usize + nrt.len()].copy_from_slice(&nrt);
    let host = Arc::new(BufferHost::new(data, "test.drv".into()));
    let mut rt = runtime_for(host);
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            if (NE.isNE16() && NE.isDriver() && !NE.isFont() && !NE.isDll()) {
                _setResult("ne", "driver", "", "");
            }
        }"#,
    );
    assert_eq!(
        results.len(),
        1,
        "NE driver classification expected: {results:?}"
    );
}

#[test]
fn ne_type_font_and_exe() {
    // FONT: flags 0x8000 + name table containing "FONTLIB".
    let nrt_off = 0x100u32;
    let mut nrt = Vec::new();
    nrt.push(7u8);
    nrt.extend_from_slice(b"FONTLIB");
    nrt.extend_from_slice(&1u16.to_le_bytes());
    nrt.push(0u8);
    let mut data = make_ne(0x8000, nrt_off, nrt.len() as u16, &[]);
    data.resize(nrt_off as usize + nrt.len(), 0);
    data[nrt_off as usize..nrt_off as usize + nrt.len()].copy_from_slice(&nrt);
    let host = Arc::new(BufferHost::new(data, "test.fon".into()));
    let mut rt = runtime_for(host);
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            if (NE.isFont() && !NE.isDriver() && !NE.isDll()) {
                _setResult("ne", "font", "", "");
            }
        }"#,
    );
    assert_eq!(
        results.len(),
        1,
        "NE font classification expected: {results:?}"
    );

    // EXE: flags without 0x8000 → all type predicates false.
    let host = Arc::new(BufferHost::new(
        make_ne(0x0300, 0, 0, &[]),
        "test.exe".into(),
    ));
    let mut rt = runtime_for(host);
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            if (!NE.isDriver() && !NE.isFont() && !NE.isDll()) {
                _setResult("ne", "exe", "", "");
            }
        }"#,
    );
    assert_eq!(
        results.len(),
        1,
        "NE exe classification expected: {results:?}"
    );
}

#[test]
fn pe_find_signatures_batch() {
    let mut data = vec![0u8; 0x200];
    data[0] = 0xAA;
    data[0x40..0x42].copy_from_slice(&[0xDE, 0xAD]);
    data[0x100..0x102].copy_from_slice(&[0xBE, 0xEF]);
    let host = Arc::new(BufferHost::new(data, "test.bin".into()));
    let mut rt = runtime_for(host);
    // Returns per-signature offsets, -1 for misses; [] on invalid input.
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            var found = Binary.findSignatures(0, 0x200, ["DEAD", "BEEF", "0011"]);
            if (found.length !== 3) return;
            if (found[0] !== 0x40 || found[1] !== 0x100 || found[2] !== -1) return;
            if (Binary.findSignatures(-5, 0x200, ["AA"]).length !== 1) return;
            if (Binary.findSignatures(0, 0x200, ["AA"])[0] !== 0x00) return;
            if (Binary.findSignatures(0, -1, ["DEAD"])[0] !== 0x40) return;
            _setResult("ok", "batch", "", "");
        }"#,
    );
    assert_eq!(
        results.len(),
        1,
        "findSignatures batch semantics: {results:?}"
    );
}

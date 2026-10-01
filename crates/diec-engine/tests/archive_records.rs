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

/// Build a minimal binary AXML manifest (ResXMLTree) for APK decoding tests.
///
/// Layout: root chunk (RES_XML_TYPE) -> string pool -> start namespace
/// (android prefix) -> start element "manifest" with attributes
/// `package` (string) and `android:versionName` (string) -> end element.
fn make_axml_manifest(package: &str, version_name: &str) -> Vec<u8> {
    // String pool contents.
    let pool_strs: Vec<&str> = vec![
        "http://schemas.android.com/apk/res/android", // 0 ns uri
        "android",                                    // 1 prefix
        "manifest",                                   // 2 element name
        "package",                                    // 3 attr name
        package,                                      // 4 attr value
        "versionName",                                // 5 attr name
        version_name,                                 // 6 attr value
    ];
    // Encode pool strings as UTF-8: len16(1B) + len8(1B) + bytes + NUL.
    let mut pool_data = Vec::new();
    let mut offsets = Vec::new();
    for s in &pool_strs {
        offsets.push(pool_data.len() as u32);
        pool_data.push(s.len() as u8); // utf16 char count
        pool_data.push(s.len() as u8); // utf8 byte count
        pool_data.extend_from_slice(s.as_bytes());
        pool_data.push(0);
    }
    let str_count = pool_strs.len() as u32;
    let offsets_len = str_count * 4;
    let strings_start = 28 + offsets_len; // pool header(28) + offsets
    let pool_size = strings_start + pool_data.len() as u32;

    let mut pool = Vec::new();
    pool.extend_from_slice(&0x0001u16.to_le_bytes()); // RES_STRING_POOL_TYPE
    pool.extend_from_slice(&28u16.to_le_bytes()); // headerSize
    pool.extend_from_slice(&pool_size.to_le_bytes());
    pool.extend_from_slice(&str_count.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes()); // styleCount
    pool.extend_from_slice(&0x100u32.to_le_bytes()); // UTF8 flag
    pool.extend_from_slice(&strings_start.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
    for o in &offsets {
        pool.extend_from_slice(&o.to_le_bytes());
    }
    pool.extend_from_slice(&pool_data);

    // START_NAMESPACE chunk (24 bytes).
    let mut start_ns = Vec::new();
    start_ns.extend_from_slice(&0x0100u16.to_le_bytes());
    start_ns.extend_from_slice(&16u16.to_le_bytes());
    start_ns.extend_from_slice(&24u32.to_le_bytes());
    start_ns.extend_from_slice(&0u32.to_le_bytes()); // lineNumber
    start_ns.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
    start_ns.extend_from_slice(&1u32.to_le_bytes()); // prefix "android"
    start_ns.extend_from_slice(&0u32.to_le_bytes()); // uri

    // START_ELEMENT "manifest" (36 bytes header) + 2 attrs (20 bytes each).
    let attr = |ns: u32, name: u32, dtype: u8, data: u32| -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&ns.to_le_bytes());
        a.extend_from_slice(&name.to_le_bytes());
        a.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // rawValue
        a.extend_from_slice(&8u16.to_le_bytes()); // size
        a.push(0); // reserved
        a.push(dtype);
        a.extend_from_slice(&data.to_le_bytes());
        a
    };
    let mut start_el = Vec::new();
    start_el.extend_from_slice(&0x0102u16.to_le_bytes());
    start_el.extend_from_slice(&16u16.to_le_bytes());
    start_el.extend_from_slice(&(36u32 + 40).to_le_bytes());
    start_el.extend_from_slice(&0u32.to_le_bytes()); // lineNumber
    start_el.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
    start_el.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns (none)
    start_el.extend_from_slice(&2u32.to_le_bytes()); // name "manifest"
    start_el.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
    start_el.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
    start_el.extend_from_slice(&2u16.to_le_bytes()); // attributeCount
    start_el.extend_from_slice(&0u16.to_le_bytes()); // idIndex
    start_el.extend_from_slice(&0u16.to_le_bytes()); // classIndex
    start_el.extend_from_slice(&0u16.to_le_bytes()); // styleIndex
    start_el.extend_from_slice(&attr(0xFFFF_FFFF, 3, 3, 4)); // package="..."
    start_el.extend_from_slice(&attr(0, 5, 3, 6)); // android:versionName="..."

    // END_ELEMENT "manifest" (24 bytes).
    let mut end_el = Vec::new();
    end_el.extend_from_slice(&0x0103u16.to_le_bytes());
    end_el.extend_from_slice(&16u16.to_le_bytes());
    end_el.extend_from_slice(&24u32.to_le_bytes());
    end_el.extend_from_slice(&0u32.to_le_bytes());
    end_el.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    end_el.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    end_el.extend_from_slice(&2u32.to_le_bytes());

    let total = 8 + pool.len() + start_ns.len() + start_el.len() + end_el.len();
    let mut axml = Vec::new();
    axml.extend_from_slice(&0x0003u16.to_le_bytes()); // RES_XML_TYPE
    axml.extend_from_slice(&8u16.to_le_bytes());
    axml.extend_from_slice(&(total as u32).to_le_bytes());
    axml.extend_from_slice(&pool);
    axml.extend_from_slice(&start_ns);
    axml.extend_from_slice(&start_el);
    axml.extend_from_slice(&end_el);
    axml
}

#[test]
fn apk_get_android_manifest_record_decodes_axml() {
    let axml = make_axml_manifest("com.example.app", "1.2.3");
    let zip = make_zip(&[("AndroidManifest.xml", &axml)]);
    let host = Arc::new(BufferHost::new(zip, "test.apk".into()));
    eprintln!("manifest: {}", host.android_manifest());
    let mut rt = runtime_for(host);
    let results = eval_rule(
        &mut rt,
        r#"function detect() {
            var pkg = APK.getAndroidManifestRecord("package");
            var ver = APK.getAndroidManifestRecord("android:versionName");
            var missing = APK.getAndroidManifestRecord("nope");
            if (pkg === "com.example.app" && ver === "1.2.3" && missing === "")
                _setResult("apk", "decoded", "", "");
        }"#,
    );
    assert_eq!(results.len(), 1, "APK manifest decode: {results:?}");
}

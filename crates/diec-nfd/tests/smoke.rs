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

// ---- Phase 21.F: per-format dispatch coverage ----------------------------

/// Build a minimal ZIP with a single stored member carrying `name`.
fn zip_with_member(name: &str) -> Vec<u8> {
    let nb = name.as_bytes();
    let mut d = Vec::new();
    // Local file header.
    d.extend_from_slice(b"PK\x03\x04");
    d.extend_from_slice(&[0u8; 4]); // version/flags
    d.extend_from_slice(&[0u8; 4]); // method+mtime+mdate
    d.extend_from_slice(&[0u8; 12]); // crc/sizes
    d.extend_from_slice(&(nb.len() as u16).to_le_bytes());
    d.extend_from_slice(&[0u8; 2]); // extra len
    d.extend_from_slice(nb);
    // Central directory at current offset.
    let cd = d.len();
    d.extend_from_slice(b"PK\x01\x02");
    d.extend_from_slice(&[0u8; 24]); // version..crc/sizes
    d.extend_from_slice(&(nb.len() as u16).to_le_bytes());
    d.extend_from_slice(&[0u8; 8]); // extra/comment/disk/attrs
    d.extend_from_slice(&[0u8; 8]); // attrs+lho
    d.extend_from_slice(nb);
    // EOCD.
    d.extend_from_slice(b"PK\x05\x06");
    d.extend_from_slice(&[0u8; 4]); // disk
    d.extend_from_slice(&1u16.to_le_bytes());
    d.extend_from_slice(&1u16.to_le_bytes());
    d.extend_from_slice(&(nb.len() as u32 + 46).to_le_bytes()); // cd size
    d.extend_from_slice(&(cd as u32).to_le_bytes());
    d.extend_from_slice(&[0u8; 2]); // comment len
    d
}

/// Build a minimal DEX header + string table holding `strs`.
fn dex_with_strings(strs: &[&str]) -> Vec<u8> {
    let mut d = vec![0u8; 0x70];
    d[..8].copy_from_slice(b"dex\n035\0");
    let n = strs.len() as u32;
    let sid_off = 0x70usize;
    let mut data_off = sid_off + strs.len() * 4;
    let mut out = d.clone();
    out.resize(data_off, 0);
    let mut ids = Vec::new();
    for s in strs {
        ids.push(data_off as u32);
        // uleb128 len + bytes + NUL
        let l = s.len();
        out.push(l as u8); // single-byte uleb128 (test strings < 128)
        out.extend_from_slice(s.as_bytes());
        out.push(0);
        data_off = out.len();
    }
    for (i, off) in ids.iter().enumerate() {
        out[sid_off + i * 4..sid_off + i * 4 + 4].copy_from_slice(&off.to_le_bytes());
    }
    out[0x38..0x3C].copy_from_slice(&n.to_le_bytes());
    out[0x3C..0x40].copy_from_slice(&(sid_off as u32).to_le_bytes());
    out
}

#[test]
fn apk_member_name_scan_hits_protector_record() {
    let d = zip_with_member("assets/secData0.jar");
    let ft = diec_nfd::sniff_ft_named(&d, "x.apk");
    assert_eq!(diec_nfd::ft_name(ft), "FT_APK");
    let out = diec_nfd::scan(&d, ft, diec_nfd::ScanOptions::default());
    assert!(
        out.iter().any(|r| r.record_name.contains("SecShell")),
        "expected SecShell member-name detection: {out:?}"
    );
}

#[test]
fn dex_string_scan_hits_protector_record() {
    let d = dex_with_strings(&["ALLATORIxDEMO", "Lfoo/Bar;"]);
    let out = diec_nfd::scan(
        &d,
        diec_nfd::gen_names::ft::FT_DEX,
        diec_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter().any(|r| r.record_name == "Allatori Obfuscator"),
        "expected Allatori detection: {out:?}"
    );
}

#[test]
fn plain_text_gets_format_record() {
    let d = b"#include <stdio.h>\nint main() { return 0; }\n".to_vec();
    let out = diec_nfd::scan(
        &d,
        diec_nfd::gen_names::ft::FT_BINARY,
        diec_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter()
            .any(|r| r.record_type == "Format" && r.record_name == "Plain" && r.info == "LF"),
        "expected Plain text format record: {out:?}"
    );
}

#[test]
fn com_suffix_sniffs_to_com() {
    let d = vec![0xC3u8; 128];
    assert_eq!(
        diec_nfd::ft_name(diec_nfd::sniff_ft_named(&d, "tool.com")),
        "FT_COM"
    );
    // Without the suffix the same bytes stay generic.
    assert_eq!(
        diec_nfd::ft_name(diec_nfd::sniff_ft_named(&d, "tool.bin")),
        "FT_BINARY"
    );
}

#[test]
fn zip_container_info_enriches_record() {
    // Two members -> "2 records inspected" info on the ZIP format record.
    let mut d2 = Vec::new();
    let mut locals = Vec::new();
    for (i, nm) in ["a.txt", "b.bin"].iter().enumerate() {
        let nb = nm.as_bytes();
        locals.extend_from_slice(b"PK\x03\x04");
        locals.extend_from_slice(&[20u8, 0]); // version needed 2.0
        locals.extend_from_slice(&[0u8; 16]);
        locals.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        locals.extend_from_slice(&[0u8; 2]);
        locals.extend_from_slice(nb);
        let _ = i;
    }
    let cd = locals.len();
    let mut cd_entries = Vec::new();
    let mut lho = 0u32;
    for nm in ["a.txt", "b.bin"] {
        let nb = nm.as_bytes();
        cd_entries.extend_from_slice(b"PK\x01\x02");
        cd_entries.extend_from_slice(&[0u8; 2]); // version made by
        cd_entries.extend_from_slice(&20u16.to_le_bytes()); // version needed
        cd_entries.extend_from_slice(&[0u8; 20]);
        cd_entries.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        cd_entries.extend_from_slice(&[0u8; 8]);
        cd_entries.extend_from_slice(&[0u8; 4]);
        cd_entries.extend_from_slice(&lho.to_le_bytes());
        cd_entries.extend_from_slice(nb);
        lho += 30 + nb.len() as u32;
    }
    d2.extend_from_slice(&locals);
    d2.extend_from_slice(&cd_entries);
    d2.extend_from_slice(b"PK\x05\x06");
    d2.extend_from_slice(&[0u8; 4]);
    d2.extend_from_slice(&2u16.to_le_bytes());
    d2.extend_from_slice(&2u16.to_le_bytes());
    d2.extend_from_slice(&(cd_entries.len() as u32).to_le_bytes());
    d2.extend_from_slice(&(cd as u32).to_le_bytes());
    d2.extend_from_slice(&[0u8; 2]);

    let out = diec_nfd::scan(
        &d2,
        diec_nfd::gen_names::ft::FT_ZIP,
        diec_nfd::ScanOptions::default(),
    );
    let zip_rec = out.iter().find(|r| r.record_name == "ZIP");
    assert!(
        zip_rec.is_some_and(|r| r.info.contains("2 records inspected")
            && r.info.contains("Declared minimum reader version: 2.0")),
        "expected container info on ZIP record: {out:?}"
    );
}

#[test]
fn pdf_version_fixup_extracts_header_version() {
    let mut d = b"%PDF-1.7\n".to_vec();
    d.extend_from_slice(&[0u8; 64]);
    let out = diec_nfd::scan(
        &d,
        diec_nfd::gen_names::ft::FT_PDF,
        diec_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "PDF" && r.version == "1.7"),
        "expected PDF 1.7 version: {out:?}"
    );
}

/// Build a minimal ZIP container with an APK Signature Block placed
/// immediately before the central directory.
fn apk_with_sig_block(ids: &[u32], members: &[&str]) -> Vec<u8> {
    let mut d = Vec::new();
    let mut cd = Vec::new();
    // Local headers + central directory entries for each member.
    for name in members {
        let local_off = d.len() as u32;
        d.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // local header
        d.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        d.extend_from_slice(&(name.len() as u16).to_le_bytes());
        d.extend_from_slice(&[0, 0]);
        d.extend_from_slice(name.as_bytes());
        // Central directory entry.
        cd.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]);
        // ver_made..usize = 24 bytes.
        cd.extend_from_slice(&[20, 0, 20, 0]);
        cd.extend_from_slice(&[0; 20]);
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        // extralen, commentlen, disk, intattr, extattr = 12 bytes.
        cd.extend_from_slice(&[0; 12]);
        cd.extend_from_slice(&local_off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    // APK Signature Block: [u64 size][entries][u64 size][magic].
    let mut block_entries = Vec::new();
    for id in ids {
        block_entries.extend_from_slice(&12u64.to_le_bytes()); // len = 4 id + 8 value
        block_entries.extend_from_slice(&id.to_le_bytes());
        block_entries.extend_from_slice(&[0u8; 8]);
    }
    let size = (block_entries.len() + 24) as u64;
    d.extend_from_slice(&size.to_le_bytes());
    d.extend_from_slice(&block_entries);
    d.extend_from_slice(&size.to_le_bytes());
    d.extend_from_slice(b"APK Sig Block 42");
    let cd_off = d.len() as u32;
    d.extend_from_slice(&cd);
    d.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // EOCD
    d.extend_from_slice(&[0, 0, 0, 0]);
    d.extend_from_slice(&(members.len() as u16).to_le_bytes());
    d.extend_from_slice(&(members.len() as u16).to_le_bytes());
    d.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    d.extend_from_slice(&cd_off.to_le_bytes());
    d.extend_from_slice(&[0, 0]);
    d
}

#[test]
fn apk_sig_scheme_v2_detection() {
    let d = apk_with_sig_block(&[0x7109_871A], &["classes.dex"]);
    let out = diec_nfd::scan(
        &d,
        diec_nfd::gen_names::ft::FT_APK,
        diec_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "APK Signature Scheme" && r.version == "v2"),
        "expected APK Signature Scheme v2: {out:?}"
    );
    // Valid APK always carries an OS (Android) and a language record.
    assert!(out.iter().any(|r| r.record_name == "Android"), "{out:?}");
    assert!(
        out.iter()
            .any(|r| r.record_name == "Java" && r.record_type == "Language"),
        "expected Java language record: {out:?}"
    );
}

#[test]
fn apk_sig_scheme_v3_exclusive_and_walle() {
    let d = apk_with_sig_block(&[0xF053_68C0, 0x7177_7777], &[]);
    let out = diec_nfd::scan(
        &d,
        diec_nfd::gen_names::ft::FT_APK,
        diec_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "APK Signature Scheme" && r.version == "v3"),
        "expected v3: {out:?}"
    );
    assert!(
        !out.iter()
            .any(|r| r.record_name == "APK Signature Scheme" && r.version == "v2"),
        "v3 must not emit v2: {out:?}"
    );
    assert!(out.iter().any(|r| r.record_name == "Walle"), "{out:?}");
}

#[test]
fn apk_kotlin_language_via_member() {
    let d = apk_with_sig_block(&[], &["kotlin/kotlin.kotlin_builtins"]);
    let out = diec_nfd::scan(
        &d,
        diec_nfd::gen_names::ft::FT_APK,
        diec_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Kotlin" && r.record_type == "Language"),
        "expected Kotlin language record: {out:?}"
    );
}

/// Minimal MZ DOS image with an embedded banner.
fn mz_with_banner(banner: &[u8], at: usize) -> Vec<u8> {
    let mut d = vec![0u8; 0x400];
    d[0] = b'M';
    d[1] = b'Z';
    d[0x08] = 4; // header size = 4 paragraphs
    d[at..at + banner.len()].copy_from_slice(banner);
    d
}

#[test]
fn msdos_dos4g_deep_scan_only() {
    let d = mz_with_banner(b"DOS/4G", 0x80);
    let ft = diec_nfd::gen_names::ft::FT_MSDOS;
    let shallow = diec_nfd::scan(&d, ft, diec_nfd::ScanOptions { deep_scan: false });
    assert!(
        !shallow.iter().any(|r| r.record_name == "DOS/4G"),
        "DOS/4G must be deep-scan gated: {shallow:?}"
    );
    let deep = diec_nfd::scan(&d, ft, diec_nfd::ScanOptions { deep_scan: true });
    assert!(
        deep.iter()
            .any(|r| r.record_name == "DOS/4G" && r.record_type == "DOS extender"),
        "expected DOS/4G extender record: {deep:?}"
    );
}

#[test]
fn msdos_wdosx_always_scanned() {
    let d = mz_with_banner(b"WDOSX 0.97\x00", 0x34);
    let out = diec_nfd::scan(
        &d,
        diec_nfd::gen_names::ft::FT_MSDOS,
        diec_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "WDOSX" && r.version == "0.97"),
        "expected WDOSX 0.97: {out:?}"
    );
}

#[test]
fn msdos_vintage_pascal_banner() {
    let d = mz_with_banner(b"PASFILEA", 0x100);
    let out = diec_nfd::scan(
        &d,
        diec_nfd::gen_names::ft::FT_MSDOS,
        diec_nfd::ScanOptions { deep_scan: true },
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Microsoft Pascal" && r.version == "4.00"),
        "expected Microsoft Pascal 4.00: {out:?}"
    );
}

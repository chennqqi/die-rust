//! Smoke tests: run the NFD table scans against corpus fixtures and
//! sanity-check detections.

use die_nfd::{Detection, ScanOptions, ft_name, gen_names::ft, scan, sniff_ft};

fn corpus(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn show(name: &str, d: &[u8]) -> (u16, Vec<Detection>) {
    let ft = sniff_ft(d);
    let out = scan(
        d,
        ft,
        ScanOptions {
            deep_scan: true,
            ..Default::default()
        },
    );
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
    let names: Vec<&str> = out.iter().map(|r| r.record_name.as_ref()).collect();
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
        let _ = scan(
            d,
            ft,
            ScanOptions {
                deep_scan: true,
                ..Default::default()
            },
        );
        let _ = i;
    }
}

// ---- Phase 21.F: per-format dispatch coverage ----------------------------

/// Build a minimal ZIP with a single stored member carrying `name`.
#[allow(dead_code)]
fn zip_with_member(name: &str) -> Vec<u8> {
    zip_with_members(&[(name, &[][..])])
}

/// Multi-member stored-method ZIP: `(name, data)` pairs.
fn zip_with_members(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut d = Vec::new();
    let mut cd_entries = Vec::new();
    for (name, data) in members {
        let nb = name.as_bytes();
        let local_off = d.len() as u32;
        // Local file header.
        d.extend_from_slice(b"PK\x03\x04");
        d.extend_from_slice(&[0u8; 4]); // version/flags
        d.extend_from_slice(&[0u8; 6]); // method+mtime+mdate
        d.extend_from_slice(&[0u8; 4]); // crc
        d.extend_from_slice(&(data.len() as u32).to_le_bytes()); // csize
        d.extend_from_slice(&(data.len() as u32).to_le_bytes()); // usize
        d.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        d.extend_from_slice(&[0u8; 2]); // extra len
        d.extend_from_slice(nb);
        d.extend_from_slice(data);
        cd_entries.push((nb, data.len() as u32, local_off));
    }
    let cd = d.len();
    let mut cd_size = 0u32;
    for (nb, size, local_off) in &cd_entries {
        d.extend_from_slice(b"PK\x01\x02");
        d.extend_from_slice(&[0u8; 16]); // version..crc
        d.extend_from_slice(&size.to_le_bytes()); // csize
        d.extend_from_slice(&size.to_le_bytes()); // usize
        d.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        d.extend_from_slice(&[0u8; 8]); // extra/comment/disk/attrs
        d.extend_from_slice(&[0u8; 4]); // attrs
        d.extend_from_slice(&local_off.to_le_bytes());
        d.extend_from_slice(nb);
        cd_size += 46 + nb.len() as u32;
    }
    // EOCD.
    d.extend_from_slice(b"PK\x05\x06");
    d.extend_from_slice(&[0u8; 4]); // disk
    d.extend_from_slice(&(cd_entries.len() as u16).to_le_bytes());
    d.extend_from_slice(&(cd_entries.len() as u16).to_le_bytes());
    d.extend_from_slice(&cd_size.to_le_bytes());
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
    // Upstream `XAPK::isValid` requires a non-empty AndroidManifest.xml
    // member before `APK_handle` runs at all.
    let d = zip_with_members(&[
        ("AndroidManifest.xml", b"<manifest/>\n"),
        ("assets/secData0.jar", b"x"),
    ]);
    let ft = die_nfd::sniff_ft_named(&d, "x.apk");
    assert_eq!(die_nfd::ft_name(ft), "FT_APK");
    let out = die_nfd::scan(&d, ft, die_nfd::ScanOptions::default());
    assert!(
        out.iter().any(|r| r.record_name.contains("SecShell")),
        "expected SecShell member-name detection: {out:?}"
    );
}

#[test]
fn dex_string_scan_hits_protector_record() {
    let d = dex_with_strings(&["ALLATORIxDEMO", "Lfoo/Bar;"]);
    let out = die_nfd::scan(
        &d,
        die_nfd::gen_names::ft::FT_DEX,
        die_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter().any(|r| r.record_name == "Allatori Obfuscator"),
        "expected Allatori detection: {out:?}"
    );
}

#[test]
fn plain_text_gets_format_record() {
    let d = b"#include <stdio.h>\nint main() { return 0; }\n".to_vec();
    let out = die_nfd::scan(
        &d,
        die_nfd::gen_names::ft::FT_BINARY,
        die_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter()
            .any(|r| r.record_type == "Format" && r.record_name == "Plain text" && r.info == "LF"),
        "expected Plain text format record: {out:?}"
    );
}

#[test]
fn com_suffix_sniffs_to_com() {
    let d = vec![0xC3u8; 128];
    assert_eq!(
        die_nfd::ft_name(die_nfd::sniff_ft_named(&d, "tool.com")),
        "FT_COM"
    );
    // Without the suffix the same bytes stay generic.
    assert_eq!(
        die_nfd::ft_name(die_nfd::sniff_ft_named(&d, "tool.bin")),
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

    let out = die_nfd::scan(
        &d2,
        die_nfd::gen_names::ft::FT_ZIP,
        die_nfd::ScanOptions::default(),
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
    let out = die_nfd::scan(
        &d,
        die_nfd::gen_names::ft::FT_PDF,
        die_nfd::ScanOptions::default(),
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
    // Upstream `XAPK::isValid` gates `APK_handle` on a non-empty
    // AndroidManifest.xml member.
    let mut all: Vec<(&str, &[u8])> = vec![("AndroidManifest.xml", b"<manifest/>\n")];
    all.extend(members.iter().map(|n| (*n, &[][..])));
    // Local headers + central directory entries for each member.
    for (name, data) in &all {
        let local_off = d.len() as u32;
        d.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // local header
        d.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // ver..mdate
        d.extend_from_slice(&[0; 4]); // crc
        d.extend_from_slice(&(data.len() as u32).to_le_bytes());
        d.extend_from_slice(&(data.len() as u32).to_le_bytes());
        d.extend_from_slice(&(name.len() as u16).to_le_bytes());
        d.extend_from_slice(&[0, 0]);
        d.extend_from_slice(name.as_bytes());
        d.extend_from_slice(data);
        // Central directory entry.
        cd.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]);
        // ver_made..usize = 24 bytes.
        cd.extend_from_slice(&[20, 0, 20, 0]);
        cd.extend_from_slice(&[0; 12]); // flags..crc
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
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
    d.extend_from_slice(&(all.len() as u16).to_le_bytes());
    d.extend_from_slice(&(all.len() as u16).to_le_bytes());
    d.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    d.extend_from_slice(&cd_off.to_le_bytes());
    d.extend_from_slice(&[0, 0]);
    d
}

#[test]
fn apk_sig_scheme_v2_detection() {
    let d = apk_with_sig_block(&[0x7109_871A], &["classes.dex"]);
    let out = die_nfd::scan(
        &d,
        die_nfd::gen_names::ft::FT_APK,
        die_nfd::ScanOptions::default(),
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
    let out = die_nfd::scan(
        &d,
        die_nfd::gen_names::ft::FT_APK,
        die_nfd::ScanOptions::default(),
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
    let out = die_nfd::scan(
        &d,
        die_nfd::gen_names::ft::FT_APK,
        die_nfd::ScanOptions::default(),
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
    let ft = die_nfd::gen_names::ft::FT_MSDOS;
    let shallow = die_nfd::scan(
        &d,
        ft,
        die_nfd::ScanOptions {
            deep_scan: false,
            ..Default::default()
        },
    );
    assert!(
        !shallow.iter().any(|r| r.record_name == "DOS/4G"),
        "DOS/4G must be deep-scan gated: {shallow:?}"
    );
    let deep = die_nfd::scan(
        &d,
        ft,
        die_nfd::ScanOptions {
            deep_scan: true,
            ..Default::default()
        },
    );
    assert!(
        deep.iter()
            .any(|r| r.record_name == "DOS/4G" && r.record_type == "DOS extender"),
        "expected DOS/4G extender record: {deep:?}"
    );
}

#[test]
fn msdos_wdosx_always_scanned() {
    let d = mz_with_banner(b"WDOSX 0.97\x00", 0x34);
    let out = die_nfd::scan(
        &d,
        die_nfd::gen_names::ft::FT_MSDOS,
        die_nfd::ScanOptions::default(),
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
    let out = die_nfd::scan(
        &d,
        die_nfd::gen_names::ft::FT_MSDOS,
        die_nfd::ScanOptions {
            deep_scan: true,
            ..Default::default()
        },
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Microsoft Pascal" && r.version == "4.00"),
        "expected Microsoft Pascal 4.00: {out:?}"
    );
}

/// Build a minimal ELF64 with the given section payloads. Sections are
/// `[("name", type, bytes)]`; shstrtab is appended automatically.
fn elf64_with(sections: &[(&str, u32, &[u8])], osabi: u8, machine: u16, etype: u16) -> Vec<u8> {
    let mut names = String::from("\0");
    let mut offs = Vec::new();
    let mut d = vec![0u8; 0x40];
    d[0..4].copy_from_slice(b"\x7FELF");
    d[4] = 2; // ELFCLASS64
    d[5] = 1; // LSB
    d[7] = osabi;
    d[0x10..0x12].copy_from_slice(&etype.to_le_bytes());
    d[0x12..0x14].copy_from_slice(&machine.to_le_bytes());
    d[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    for (name, _, payload) in sections {
        offs.push((names.len() as u32, d.len()));
        names.push_str(name);
        names.push('\0');
        d.extend_from_slice(payload);
        while !d.len().is_multiple_of(8) {
            d.push(0);
        }
    }
    // shstrtab holds the full name pool.
    let shstr_off_in_names = names.len() as u32;
    names.push_str(".shstrtab\0");
    let shstr_file_off = d.len();
    d.extend_from_slice(names.as_bytes());
    while !d.len().is_multiple_of(8) {
        d.push(0);
    }
    let shoff = d.len();
    // shnum = 1 (null) + sections + shstrtab.
    let shnum = 1 + sections.len() + 1;
    let mut sh = vec![0u8; 64]; // null section
    for (i, (_, typ, payload)) in sections.iter().enumerate() {
        let (name_off, file_off) = offs[i];
        sh.extend_from_slice(&name_off.to_le_bytes());
        sh.extend_from_slice(&typ.to_le_bytes());
        sh.extend_from_slice(&[0u8; 16]); // flags+addr
        sh.extend_from_slice(&(file_off as u64).to_le_bytes());
        sh.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        sh.extend_from_slice(&[0u8; 16]); // link+info+align
        // entsize
        let entsz: u64 = if *typ == 2 { 24 } else { 0 };
        sh.extend_from_slice(&entsz.to_le_bytes());
    }
    // shstrtab section (type STRTAB=3).
    sh.extend_from_slice(&shstr_off_in_names.to_le_bytes());
    sh.extend_from_slice(&3u32.to_le_bytes());
    sh.extend_from_slice(&[0u8; 16]);
    sh.extend_from_slice(&(shstr_file_off as u64).to_le_bytes());
    sh.extend_from_slice(&(names.len() as u64).to_le_bytes());
    sh.extend_from_slice(&[0u8; 24]);
    d.extend_from_slice(&sh);
    d[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
    d[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
    d[0x3C..0x3E].copy_from_slice(&(shnum as u16).to_le_bytes());
    d[0x3E..0x40].copy_from_slice(&(shnum as u16 - 1).to_le_bytes());
    d
}

#[test]
fn elf_comment_gcc_and_os() {
    let d = elf64_with(
        &[(".comment", 1, b"GCC: (GNU) 11.4.0\0")],
        0,  // ELFOSABI_SYSV
        62, // EM_AMD64
        2,  // ET_EXEC
    );
    let out = die_nfd::scan(
        &d,
        die_nfd::gen_names::ft::FT_ELF64,
        die_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter().any(|r| r.record_name == "GCC"
            && r.version == "11.4.0"
            && r.record_type == "Compiler"),
        "expected GCC 11.4.0 compiler record: {out:?}"
    );
    // SysV OSABI defaults to UNIX; sInfo carries arch/mode/type.
    assert!(
        out.iter().any(|r| r.record_name == "Unix"
            && r.record_type == "Operation system"
            && r.info.contains("AMD64")
            && r.info.contains("64-bit")
            && r.info.contains("EXEC")),
        "expected UNIX OS record with arch info: {out:?}"
    );
}

#[test]
fn elf_comment_clang_and_ubuntu_os() {
    let d = elf64_with(
        &[(".comment", 1, b"Ubuntu clang version 14.0.0-1ubuntu1\0")],
        3, // ELFOSABI_LINUX
        183,
        3,
    );
    let out = die_nfd::scan(
        &d,
        die_nfd::gen_names::ft::FT_ELF64,
        die_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Ubuntu clang" && r.version == "14.0.0-1ubuntu1"),
        "expected Ubuntu clang 14.0.0: {out:?}"
    );
    assert!(
        out.iter().any(|r| r.record_name == "Ubuntu Linux"),
        "expected Ubuntu Linux OS record: {out:?}"
    );
}

#[test]
fn elf_debug_sections() {
    // 3 fake symbols (entsize 24 each → count 3).
    let d = elf64_with(
        &[
            (".symtab", 2, &[0u8; 72]),
            (".stab", 1, &[0u8; 12]),
            (".stabstr", 3, &[0u8; 4]),
            (".debug_info", 1, &[0, 0, 0, 0, 5, 0, 0, 0, 0, 0]),
        ],
        3,
        62,
        3,
    );
    let out = die_nfd::scan(
        &d,
        die_nfd::gen_names::ft::FT_ELF64,
        die_nfd::ScanOptions::default(),
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Symbol Table" && r.info.contains("3 symbols")),
        "expected symbol table record: {out:?}"
    );
    assert!(
        out.iter().any(|r| r.record_name == "STABS Debug Info"),
        "{out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "DWARF Debug Info" && r.version == "5.0"),
        "{out:?}"
    );
}

/// Build a thin Mach-O 64-bit (little-endian, x86_64) fixture with a
/// `__TEXT.__cstring` section containing the Zig marker, a Foundation
/// `LC_LOAD_DYLIB`, `LC_VERSION_MIN_MACOSX`, and `LC_CODE_SIGNATURE`.
fn macho64_fixture() -> Vec<u8> {
    let mut cmds: Vec<u8> = Vec::new();

    // LC_SEGMENT_64 with one __cstring section. Data placed right after
    // the command area (offset filled below).
    let path = b"/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation\0";
    let dylib_sz = ((24 + path.len()) + 7) & !7;
    let seg_sz = 72 + 80;
    let data_off = 32 + seg_sz + dylib_sz + 16 + 16;
    let cstring = b"ZIG_DEBUG_COLOR\0padding";

    let mut seg = vec![0u8; seg_sz];
    seg[0..4].copy_from_slice(&0x19u32.to_le_bytes()); // LC_SEGMENT_64
    seg[4..8].copy_from_slice(&(seg_sz as u32).to_le_bytes());
    seg[8..14].copy_from_slice(b"__TEXT");
    seg[64..68].copy_from_slice(&1u32.to_le_bytes()); // nsects
    // section_64 at +72: sectname[16], segname[16], addr8, size8, offset4.
    seg[72..81].copy_from_slice(b"__cstring");
    seg[88..94].copy_from_slice(b"__TEXT");
    seg[72 + 40..72 + 48].copy_from_slice(&(cstring.len() as u64).to_le_bytes());
    seg[72 + 48..72 + 52].copy_from_slice(&(data_off as u32).to_le_bytes());
    cmds.extend(seg);

    // LC_LOAD_DYLIB: Foundation current_version 1255.0.0 → SDK 10.11.0.
    let mut dl = vec![0u8; dylib_sz];
    dl[0..4].copy_from_slice(&0x0Cu32.to_le_bytes()); // LC_LOAD_DYLIB
    dl[4..8].copy_from_slice(&(dylib_sz as u32).to_le_bytes());
    dl[8..12].copy_from_slice(&24u32.to_le_bytes()); // name rel offset
    dl[16..20].copy_from_slice(&(1255u32 << 16).to_le_bytes()); // current_version
    dl[24..24 + path.len()].copy_from_slice(path);
    cmds.extend(dl);

    // LC_VERSION_MIN_MACOSX: version/sdk = 10.14.0.
    let mut vm = vec![0u8; 16];
    vm[0..4].copy_from_slice(&0x24u32.to_le_bytes());
    vm[4..8].copy_from_slice(&16u32.to_le_bytes());
    vm[8..12].copy_from_slice(&((10u32 << 16) | (14 << 8)).to_le_bytes());
    vm[12..16].copy_from_slice(&((10u32 << 16) | (14 << 8)).to_le_bytes());
    cmds.extend(vm);

    // LC_CODE_SIGNATURE.
    let mut cs = vec![0u8; 16];
    cs[0..4].copy_from_slice(&0x1Du32.to_le_bytes());
    cs[4..8].copy_from_slice(&16u32.to_le_bytes());
    cmds.extend(cs);

    let mut d = Vec::new();
    d.extend(&0xFEEDFACFu32.to_le_bytes()); // MH_MAGIC_64 (LE view)
    d.extend(&0x0100_0007u32.to_le_bytes()); // cputype x86_64
    d.extend(&3u32.to_le_bytes()); // cpusubtype
    d.extend(&2u32.to_le_bytes()); // filetype MH_EXECUTE
    d.extend(&4u32.to_le_bytes()); // ncmds
    d.extend(&(cmds.len() as u32).to_le_bytes()); // sizeofcmds
    d.extend(&0u32.to_le_bytes()); // flags
    d.extend(&0u32.to_le_bytes()); // reserved
    d.extend(cmds);
    d.resize(data_off, 0);
    d.extend_from_slice(cstring);
    d
}

#[test]
fn macho64_load_command_semantics() {
    let d = macho64_fixture();
    let (ft, out) = show("macho64-synth", &d);
    assert_eq!(ft_name(ft), "FT_MACHO64");
    assert!(
        out.iter()
            .any(|r| r.record_type == "Operation system" && r.record_name == "macOS"),
        "no macOS OS record: {out:?}"
    );
    assert!(
        out.iter().any(|r| r.record_name == "codesign"),
        "no codesign: {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Foundation" && r.version == "1255.0.0"),
        "no Foundation: {out:?}"
    );
    // LC_VERSION_MIN_MACOSX sdk=10.14.0 overwrites the Foundation-derived
    // SDK version (upstream writes recordSDK later in handle_Tools);
    // SDK 10.14 → Xcode 10.0 → clang 10.0.0 / swift 4.2 toolchain records.
    assert!(
        out.iter()
            .any(|r| r.record_name == "macOS SDK" && r.version == "10.14.0"),
        "no SDK record: {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Xcode" && r.version == "10.0"),
        "no Xcode: {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "clang" && r.version == "10.0.0"),
        "no clang: {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Swift" && r.version == "4.2"),
        "no Swift: {out:?}"
    );
    assert!(
        out.iter().any(|r| r.record_name == "Zig"),
        "no Zig: {out:?}"
    );
}

#[test]
fn macho_fat_disambiguates_java_class() {
    // FAT header (CAFEBABE, nfat_arch=1, valid arch record) → FT_MACHOFAT;
    // the same magic with u32be@4 > 10 stays JAVACLASS.
    let mut fat = Vec::new();
    fat.extend(&[0xCA, 0xFE, 0xBA, 0xBE]); // FAT_MAGIC
    fat.extend(&1u32.to_be_bytes()); // nfat_arch
    fat.extend(&0x0100_0007u32.to_be_bytes()); // cputype
    fat.extend(&3u32.to_be_bytes()); // cpusubtype
    fat.extend(&0x100u32.to_be_bytes()); // offset (>= table end 28)
    fat.extend(&0x40u32.to_be_bytes()); // size
    fat.extend(&8u32.to_be_bytes()); // align
    fat.resize(0x100, 0);
    fat.resize(0x140, 0);
    assert_eq!(ft_name(sniff_ft(&fat)), "FT_MACHOFAT");

    let mut cls = Vec::new();
    cls.extend(&[0xCA, 0xFE, 0xBA, 0xBE]);
    cls.extend(&52u32.to_be_bytes()); // minor<<16|major = 52 > 10
    cls.resize(64, 0);
    assert_eq!(ft_name(sniff_ft(&cls)), "FT_JAVACLASS");
}

#[test]
fn macho_truncated_inputs_do_not_panic() {
    let full = macho64_fixture();
    for cut in [1, 4, 16, 28, 31, 32, 33, 100, 300, 350] {
        let d = &full[..cut.min(full.len())];
        let ft = sniff_ft(d);
        let _ = scan(
            d,
            ft,
            ScanOptions {
                deep_scan: true,
                ..Default::default()
            },
        );
    }
    // Big-endian thin Mach-O and a FAT header truncated mid-table.
    let mut be = full.clone();
    be[0..4].copy_from_slice(&[0xFE, 0xED, 0xFA, 0xCF]);
    let _ = scan(
        &be[..32],
        sniff_ft(&be[..32]),
        ScanOptions {
            deep_scan: true,
            ..Default::default()
        },
    );
    let _ = scan(
        &[0xCA, 0xFE, 0xBA, 0xBE],
        sniff_ft(&[0xCA, 0xFE, 0xBA, 0xBE]),
        ScanOptions {
            deep_scan: true,
            ..Default::default()
        },
    );
}

/// Minimal PE32 with one `.text` section and a single `MFC42.DLL`
/// import thunk — exercises `handle_Microsoft` (MFC lib → Visual C/C++
/// version → linker-version fill → VS tool) and `handle_OperationSystem`.
fn pe32_mfc_fixture() -> Vec<u8> {
    let mut d = vec![0u8; 0x400];
    // DOS + COFF headers.
    d[0..2].copy_from_slice(b"MZ");
    d[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    d[0x40..0x44].copy_from_slice(b"PE\0\0");
    d[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes()); // I386
    d[0x46..0x48].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    d[0x54..0x56].copy_from_slice(&0xE0u16.to_le_bytes()); // opt size
    d[0x56..0x58].copy_from_slice(&0x010Fu16.to_le_bytes()); // chars
    let opt = 0x58;
    d[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
    d[opt + 2] = 14; // MajorLinkerVersion
    d[opt + 3] = 0; // MinorLinkerVersion
    d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // EP rva
    d[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // image base
    d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // sect align
    d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
    d[opt + 40..opt + 42].copy_from_slice(&5u16.to_le_bytes()); // MajorOS
    d[opt + 42..opt + 44].copy_from_slice(&1u16.to_le_bytes()); // MinorOS → 5.1
    d[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem CUI
    d[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // num dirs
    // Import directory (dir 1): rva 0x1000 → file 0x200.
    d[opt + 96 + 8..opt + 96 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    d[opt + 96 + 12..opt + 96 + 16].copy_from_slice(&40u32.to_le_bytes());
    // Section .text: vaddr 0x1000, raw 0x200/0x200, code+exec+read.
    let sec = opt + 0xE0;
    d[sec..sec + 5].copy_from_slice(b".text");
    d[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); // vsize
    d[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // vaddr
    d[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
    d[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
    d[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    // Import descriptor @0x200: oft=0x1010, name=0x1030, ft=0x1010.
    d[0x200..0x204].copy_from_slice(&0x1010u32.to_le_bytes());
    d[0x20C..0x210].copy_from_slice(&0x1030u32.to_le_bytes());
    d[0x210..0x214].copy_from_slice(&0x1010u32.to_le_bytes());
    // Thunk @0x210 (rva 0x1010 → off 0x210): hint/name @0x1020.
    d[0x210..0x214].copy_from_slice(&0x1020u32.to_le_bytes());
    d[0x214..0x218].copy_from_slice(&0u32.to_le_bytes());
    // Hint/name @0x220: hint=0, "Foo".
    d[0x220..0x222].copy_from_slice(&0u16.to_le_bytes());
    d[0x222..0x226].copy_from_slice(b"Foo\0");
    // Lib name @0x230: "MFC42.DLL".
    d[0x230..0x23A].copy_from_slice(b"MFC42.DLL\0");
    d
}

#[test]
fn pe32_mfc_triggers_microsoft_handler() {
    let d = pe32_mfc_fixture();
    let (ft, out) = show("pe32-mfc-synth", &d);
    assert_eq!(ft_name(ft), "FT_PE32");
    assert!(
        out.iter().any(|r| r.record_type == "Operation system"
            && r.record_name == "Windows"
            && r.version == "XP"),
        "no Windows XP OS record: {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "MFC" && r.version == "4.20"),
        "no MFC 4.20: {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Visual C/C++" && r.version == "10.20"),
        "no Visual C/C++ 10.20 (MFC-derived): {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Microsoft linker" && r.version == "14.00"),
        "no linker version fill: {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Microsoft Visual Studio" && r.version == "2015"),
        "no VS 2015 tool record: {out:?}"
    );
}

/// PE32 with `.text` + `.rdata` (flags 0x40000040) holding
/// "GCC: (GNU) 9.2.0" and linker version 2.25 — exercises
/// `handle_GCC` (heur + GCC: version + MinGW minor table +
/// GNU linker fill).
fn pe32_gcc_fixture() -> Vec<u8> {
    let mut d = vec![0u8; 0x800];
    // Standard MS-DOS stub matching the GENERICLINKER v0 header record
    // (e_lfanew 0x80, "This program cannot be run in DOS mode.").
    d[0..2].copy_from_slice(b"MZ");
    d[2..4].copy_from_slice(&0x90u16.to_le_bytes());
    d[4..6].copy_from_slice(&3u16.to_le_bytes());
    d[8..10].copy_from_slice(&4u16.to_le_bytes());
    d[0x0C..0x0E].copy_from_slice(&0xFFFFu16.to_le_bytes());
    d[0x10..0x12].copy_from_slice(&0xB8u16.to_le_bytes());
    d[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes());
    d[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let stub = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21This program cannot be run in DOS mode.\r\r\n$\0\0\0\0";
    d[0x40..0x40 + stub.len()].copy_from_slice(stub);
    d[0x80..0x84].copy_from_slice(b"PE\0\0");
    d[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
    d[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    d[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
    d[0x96..0x98].copy_from_slice(&0x010Fu16.to_le_bytes());
    let opt = 0x98;
    d[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    d[opt + 2] = 2; // MajorLinkerVersion
    d[opt + 3] = 25; // MinorLinkerVersion → MinGW 5.3.0
    d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    d[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    d[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    d[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
    // [0] .text raw 0x200/0x200.
    let s0 = opt + 0xE0;
    d[s0..s0 + 5].copy_from_slice(b".text");
    d[s0 + 8..s0 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    d[s0 + 12..s0 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    d[s0 + 16..s0 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    d[s0 + 20..s0 + 24].copy_from_slice(&0x200u32.to_le_bytes());
    d[s0 + 36..s0 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    // [1] .rdata raw 0x400/0x200, chars 0x40000040 (const data).
    let s1 = s0 + 40;
    d[s1..s1 + 6].copy_from_slice(b".rdata");
    d[s1 + 8..s1 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    d[s1 + 12..s1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    d[s1 + 16..s1 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    d[s1 + 20..s1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    d[s1 + 36..s1 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
    // .rdata: first ANSI string carries the lowercase "gcc" marker
    // (`sDllLib`), "GCC:" version string sits later in the section.
    let dll_s = b"gcc library helpers\0";
    d[0x400..0x400 + dll_s.len()].copy_from_slice(dll_s);
    let gcc_s = b"GCC: (GNU) 9.2.0\0";
    d[0x420..0x420 + gcc_s.len()].copy_from_slice(gcc_s);
    d
}

#[test]
fn pe32_gcc_mingw_handler() {
    let d = pe32_gcc_fixture();
    let (ft, out) = show("pe32-gcc-synth", &d);
    assert_eq!(ft_name(ft), "FT_PE32");
    assert!(
        out.iter()
            .any(|r| r.record_name == "GCC" && r.version == "9.2.0"),
        "no GCC 9.2.0 compiler record: {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "MinGW" && r.version == "5.3.0"),
        "no MinGW tool record (linker 2.25 → 5.3.0): {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "GNU ld" && r.version == "2.25"),
        "no GNU linker record: {out:?}"
    );
}

/// PE32 with "Open Watcom ... 2002-10.5" at the entry point —
/// exercises `handle_Watcom` (vi string → OPENWATCOMCCPP + inferred
/// WATCOMLINKER).
fn pe32_watcom_fixture() -> Vec<u8> {
    let mut d = vec![0u8; 0x600];
    d[0..2].copy_from_slice(b"MZ");
    d[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    d[0x40..0x44].copy_from_slice(b"PE\0\0");
    d[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes());
    d[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    d[0x54..0x56].copy_from_slice(&0xE0u16.to_le_bytes());
    d[0x56..0x58].copy_from_slice(&0x010Fu16.to_le_bytes());
    let opt = 0x58;
    d[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    d[opt + 2] = 13;
    d[opt + 3] = 0;
    d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    d[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    d[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
    let sec = opt + 0xE0;
    d[sec..sec + 5].copy_from_slice(b".text");
    d[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes());
    d[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    d[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
    d[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
    d[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    // Entry-point region (file 0x200): Watcom version string.
    let ws = b"Open Watcom C++ ver 2002-10.5x\0pad";
    d[0x200..0x200 + ws.len()].copy_from_slice(ws);
    d
}

#[test]
fn pe32_watcom_handler() {
    let d = pe32_watcom_fixture();
    let (ft, out) = show("pe32-watcom-synth", &d);
    assert_eq!(ft_name(ft), "FT_PE32");
    assert!(
        out.iter()
            .any(|r| r.record_name == "Open Watcom C/C++" && r.version == "10.5"),
        "no Open Watcom compiler record: {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name.contains("Watcom") && r.record_type == "Linker"),
        "no inferred Watcom linker record: {out:?}"
    );
}

/// PE32 with a security-directory WIN_CERTIFICATE (rev 0x200, type 2)
/// and a single `NOVEXSTUB.DLL` import — exercises `handle_Signtools`
/// and `handle_DongleProtection`.
fn pe32_cert_dongle_fixture() -> Vec<u8> {
    let mut d = pe32_mfc_fixture();
    // Security dir (entry 4): file offset 0x300, size 0x28.
    let opt = 0x58;
    d[opt + 96 + 32..opt + 96 + 36].copy_from_slice(&0x300u32.to_le_bytes());
    d[opt + 96 + 36..opt + 96 + 40].copy_from_slice(&0x28u32.to_le_bytes());
    // WIN_CERTIFICATE at file 0x300: dwLength=0x28, rev=0x200, type=2.
    d[0x300..0x304].copy_from_slice(&0x28u32.to_le_bytes());
    d[0x304..0x306].copy_from_slice(&0x0200u16.to_le_bytes());
    d[0x306..0x308].copy_from_slice(&2u16.to_le_bytes());
    // Single import lib NOVEXSTUB.DLL.
    let lib = b"NOVEXSTUB.DLL\0";
    d[0x230..0x230 + lib.len()].copy_from_slice(lib);
    d
}

#[test]
fn pe32_cert_and_dongle_handlers() {
    let d = pe32_cert_dongle_fixture();
    let (ft, out) = show("pe32-cert-dongle-synth", &d);
    assert_eq!(ft_name(ft), "FT_PE32");
    assert!(
        out.iter()
            .any(|r| r.record_name == "Windows Authenticode" && r.version == "2.0"),
        "no WinAuth signtool record: {out:?}"
    );
    assert!(
        out.iter().any(|r| r.record_name == "Guardian Stealth"),
        "no dongle record: {out:?}"
    );
}

/// PE32 with Pascal metadata in `.text` (`\x07TObject` + `\x06string`)
/// — exercises `handle_Borland` Delphi path (Delphi 2 + Object Pascal
/// 9.0 + inferred TurboLinker).
fn pe32_delphi_fixture() -> Vec<u8> {
    let mut d = vec![0u8; 0x800];
    d[0..2].copy_from_slice(b"MZ");
    d[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    d[0x40..0x44].copy_from_slice(b"PE\0\0");
    d[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes());
    d[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    d[0x54..0x56].copy_from_slice(&0xE0u16.to_le_bytes());
    d[0x56..0x58].copy_from_slice(&0x010Fu16.to_le_bytes());
    let opt = 0x58;
    d[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    d[opt + 2] = 2;
    d[opt + 3] = 1;
    d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    d[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    d[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
    let sec = opt + 0xE0;
    d[sec..sec + 5].copy_from_slice(b".text");
    d[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes());
    d[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    d[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
    d[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
    d[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    // Length-prefixed Pascal type names in the code section.
    d[0x200..0x208].copy_from_slice(b"\x07TObject");
    d[0x210..0x217].copy_from_slice(b"\x06string");
    d
}

#[test]
fn pe32_delphi_handler() {
    let d = pe32_delphi_fixture();
    let (ft, out) = show("pe32-delphi-synth", &d);
    assert_eq!(ft_name(ft), "FT_PE32");
    assert!(
        out.iter()
            .any(|r| r.record_name == "Borland Delphi" && r.version == "2"),
        "no Borland Delphi 2 tool: {out:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name.contains("Object Pascal") && r.version == "9.0"),
        "no Object Pascal 9.0 compiler: {out:?}"
    );
    assert!(
        out.iter().any(|r| r.record_name == "Turbo linker"),
        "no inferred TurboLinker: {out:?}"
    );
}

/// PE32 with "Borland C++ - Copyright 1994" in a DATA section —
/// C++Builder path of `handle_Borland`.
fn pe32_bcb_fixture() -> Vec<u8> {
    let mut d = pe32_delphi_fixture();
    // Second section: DATA (rdata-like, writable) holding the banner.
    let opt = 0x58;
    let s0 = opt + 0xE0;
    d[0x46..0x48].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    let s1 = s0 + 40;
    d[s1..s1 + 4].copy_from_slice(b"DATA");
    d[s1 + 8..s1 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    d[s1 + 12..s1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    d[s1 + 16..s1 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    d[s1 + 20..s1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    d[s1 + 36..s1 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());
    // Remove the lowercase-string marker so the C++ copyright path wins
    // (string_l would otherwise classify as Delphi).
    d[0x210..0x217].copy_from_slice(&[0u8; 7]);
    let banner = b"Borland C++ - Copyright 1994 Borland Intl.\0";
    d[0x400..0x400 + banner.len()].copy_from_slice(banner);
    d
}

#[test]
fn pe32_bcb_handler() {
    let d = pe32_bcb_fixture();
    let (ft, out) = show("pe32-bcb-synth", &d);
    assert_eq!(ft_name(ft), "FT_PE32");
    assert!(
        out.iter()
            .any(|r| r.record_name == "Borland C++" && r.version == "1994"),
        "no Borland C++ 1994 compiler: {out:?}"
    );
    assert!(
        out.iter().any(|r| r.record_name == "Borland C++ Builder"),
        "no C++ Builder tool: {out:?}"
    );
}

/// Build a `VS_VERSION_INFO` blob: root (fixed info, FileVersionMS
/// 3.2.0.0) → StringFileInfo → "040904b0" → key/value leaves.
fn vs_version_info_blob() -> Vec<u8> {
    fn w16(v: u16, out: &mut Vec<u8>) {
        out.extend(v.to_le_bytes());
    }
    let mut fd = Vec::new();
    // level-3 node "FileDescription":"Compiled AutoIt Script"
    let key = "FileDescription";
    let val = "Compiled AutoIt Script";
    let keyw: Vec<u8> = key
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .chain([0, 0])
        .collect();
    let valw: Vec<u8> = val
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .chain([0, 0])
        .collect();
    let kdelta = (6 + keyw.len()).div_ceil(4) * 4;
    w16((kdelta + valw.len()) as u16, &mut fd); // wLength
    w16((val.len() + 1) as u16, &mut fd); // wValueLength (chars incl NUL)
    w16(1, &mut fd); // wType text
    fd.extend(&keyw);
    fd.resize(kdelta, 0);
    fd.extend(&valw);
    fd.resize(fd.len().div_ceil(4) * 4, 0); // siblings walk ALIGN4 steps
    let fv = {
        let key = "FileVersion";
        let val = "3.2.0.0";
        let keyw: Vec<u8> = key
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .chain([0, 0])
            .collect();
        let valw: Vec<u8> = val
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .chain([0, 0])
            .collect();
        let kdelta = (6 + keyw.len()).div_ceil(4) * 4;
        let mut n = Vec::new();
        w16((kdelta + valw.len()) as u16, &mut n);
        w16((val.len() + 1) as u16, &mut n);
        w16(1, &mut n);
        n.extend(&keyw);
        n.resize(kdelta, 0);
        n.extend(&valw);
        n
    };
    // level-2 "040904b0" node
    let mut lang = Vec::new();
    let lw: Vec<u8> = "040904b0"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .chain([0, 0])
        .collect();
    let ldelta = (6 + lw.len()).div_ceil(4) * 4;
    let llen = ldelta + fd.len() + fv.len(); // fd already 4-aligned
    w16(llen as u16, &mut lang);
    w16(0, &mut lang);
    w16(0, &mut lang);
    lang.extend(&lw);
    lang.resize(ldelta, 0);
    lang.extend(&fd);
    lang.extend(&fv);
    // level-1 "StringFileInfo"
    let mut sfi = Vec::new();
    let sw: Vec<u8> = "StringFileInfo"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .chain([0, 0])
        .collect();
    let sdelta = (6 + sw.len()).div_ceil(4) * 4;
    w16((sdelta + lang.len()) as u16, &mut sfi);
    w16(0, &mut sfi);
    w16(0, &mut sfi);
    sfi.extend(&sw);
    sfi.resize(sdelta, 0);
    sfi.extend(&lang);
    // root "VS_VERSION_INFO" + VS_FIXEDFILEINFO
    let mut root = Vec::new();
    let rw: Vec<u8> = "VS_VERSION_INFO"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .chain([0, 0])
        .collect();
    let rdelta = (6 + rw.len()).div_ceil(4) * 4;
    w16((rdelta + 52 + sfi.len()) as u16, &mut root);
    w16(52, &mut root);
    w16(0, &mut root);
    root.extend(&rw);
    root.resize(rdelta, 0);
    let mut ffi = vec![0u8; 52];
    ffi[0..4].copy_from_slice(&0xFEEF04BDu32.to_le_bytes());
    ffi[8..12].copy_from_slice(&0x0003_0002u32.to_le_bytes()); // FileVersionMS 3.2
    ffi[16..20].copy_from_slice(&0x0003_0002u32.to_le_bytes());
    root.extend(&ffi);
    root.extend(&sfi);
    root
}

/// PE32 carrying a RT_VERSION resource → `resources_version` lookup.
fn pe32_version_resource_fixture() -> Vec<u8> {
    let mut d = pe32_delphi_fixture();
    d[0x210..0x217].copy_from_slice(&[0u8; 7]); // drop Delphi markers
    d.resize(0xC00, 0);
    // Resource dir (dir 2): rva 0x2000 → file 0x400.
    let opt = 0x58;
    d[opt + 96 + 16..opt + 96 + 20].copy_from_slice(&0x2000u32.to_le_bytes());
    d[opt + 96 + 20..opt + 96 + 24].copy_from_slice(&0x200u32.to_le_bytes());
    // Second section covers rva 0x2000 at file 0x400.
    let s0 = opt + 0xE0;
    d[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
    let s1 = s0 + 40;
    d[s1..s1 + 5].copy_from_slice(b".rsrc");
    d[s1 + 8..s1 + 12].copy_from_slice(&0x400u32.to_le_bytes());
    d[s1 + 12..s1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    d[s1 + 16..s1 + 20].copy_from_slice(&0x400u32.to_le_bytes());
    d[s1 + 20..s1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    d[s1 + 36..s1 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
    // Tree @0x400: root(dir) → type 16 → dir2 → id 1 → dir3 → lang → data.
    d[0x400 + 14..0x400 + 16].copy_from_slice(&1u16.to_le_bytes()); // n_id=1
    d[0x410..0x414].copy_from_slice(&16u32.to_le_bytes()); // type=RT_VERSION
    d[0x414..0x418].copy_from_slice(&0x8000_0018u32.to_le_bytes()); // →dir2
    d[0x418 + 14..0x418 + 16].copy_from_slice(&1u16.to_le_bytes());
    d[0x428..0x42C].copy_from_slice(&1u32.to_le_bytes()); // name id=1
    d[0x42C..0x430].copy_from_slice(&0x8000_0030u32.to_le_bytes()); // →dir3
    d[0x430 + 14..0x430 + 16].copy_from_slice(&1u16.to_le_bytes());
    d[0x440..0x444].copy_from_slice(&0x409u32.to_le_bytes()); // lang
    d[0x444..0x448].copy_from_slice(&0x50u32.to_le_bytes()); // →data @0x450
    let blob = vs_version_info_blob();
    d[0x450..0x454].copy_from_slice(&0x2060u32.to_le_bytes()); // data rva →0x460
    d[0x454..0x458].copy_from_slice(&(blob.len() as u32).to_le_bytes());
    d[0x460..0x460 + blob.len()].copy_from_slice(&blob);
    d
}

#[test]
fn pe32_version_resource_parsed() {
    let d = pe32_version_resource_fixture();
    let rv = die_nfd::pe_version::resources_version(&d);
    assert_eq!(rv.value("FileDescription"), "Compiled AutoIt Script");
    assert_eq!(rv.value("FileVersion"), "3.2.0.0");
    assert_eq!(rv.file_version_ms_str(), "3.2");
}

/// PE32 with a .NET CLI directory: `#Strings` heap carries
/// "Microsoft.VisualBasic"; `#US` carries one UTF-16 entry.
fn pe32_dotnet_fixture() -> Vec<u8> {
    pe32_dotnet_fixture_heap(b"Microsoft.VisualBasic\0")
}

/// Variant with a custom #Strings payload.
fn pe32_dotnet_fixture_heap(ansi: &[u8]) -> Vec<u8> {
    let mut d = pe32_delphi_fixture();
    d[0x210..0x217].copy_from_slice(&[0u8; 7]);
    d.resize(0xC00, 0);
    // Second section maps rva 0x2000 → file 0x400 (holds CLR+metadata).
    let opt = 0x58;
    let s0 = opt + 0xE0;
    d[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
    let s1 = s0 + 40;
    d[s1..s1 + 5].copy_from_slice(b".corm");
    d[s1 + 8..s1 + 12].copy_from_slice(&0x400u32.to_le_bytes());
    d[s1 + 12..s1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    d[s1 + 16..s1 + 20].copy_from_slice(&0x400u32.to_le_bytes());
    d[s1 + 20..s1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    d[s1 + 36..s1 + 40].copy_from_slice(&0x4000_0020u32.to_le_bytes());
    // Data dir 14 (CLR runtime) → rva 0x2000, file 0x400.
    d[opt + 96 + 14 * 8..opt + 96 + 14 * 8 + 4].copy_from_slice(&0x2000u32.to_le_bytes());
    d[opt + 96 + 14 * 8 + 4..opt + 96 + 14 * 8 + 8].copy_from_slice(&0x48u32.to_le_bytes());
    // CLI header @0x400: cb, runtime ver, MetaData{rva=0x2040,size}, flags, entry.
    d[0x400..0x404].copy_from_slice(&0x48u32.to_le_bytes());
    d[0x404..0x406].copy_from_slice(&2u16.to_le_bytes());
    d[0x406..0x408].copy_from_slice(&5u16.to_le_bytes());
    d[0x408..0x40C].copy_from_slice(&0x2040u32.to_le_bytes());
    d[0x40C..0x410].copy_from_slice(&0x200u32.to_le_bytes());
    // Metadata root @0x440 (rva 0x2040).
    let m = 0x440usize;
    d[m..m + 4].copy_from_slice(&0x424A_5342u32.to_le_bytes());
    d[m + 4..m + 6].copy_from_slice(&1u16.to_le_bytes());
    d[m + 6..m + 8].copy_from_slice(&1u16.to_le_bytes());
    let ver = b"v4.0.30319\0\0\0\0";
    d[m + 12..m + 16].copy_from_slice(&(ver.len() as u32).to_le_bytes());
    d[m + 16..m + 16 + ver.len()].copy_from_slice(ver);
    let sbase = m + 16 + ver.len();
    d[sbase..sbase + 2].copy_from_slice(&0u16.to_le_bytes()); // flags
    d[sbase + 2..sbase + 4].copy_from_slice(&2u16.to_le_bytes()); // streams
    let mut so = sbase + 4;
    // "#Strings" stream @ meta+0x80 (file 0x4C0), "#US" @ +0x100.
    let name_off = |n: &str, off: u32, size: u32, buf: &mut Vec<u8>, p: &mut usize| {
        buf[*p..*p + 4].copy_from_slice(&off.to_le_bytes());
        buf[*p + 4..*p + 8].copy_from_slice(&size.to_le_bytes());
        let nb = n.as_bytes();
        buf[*p + 8..*p + 8 + nb.len()].copy_from_slice(nb);
        *p += 8 + (nb.len() + 1).div_ceil(4) * 4;
    };
    name_off("#Strings", 0x80, 0x40, &mut d, &mut so);
    name_off("#US", 0x100, 0x40, &mut d, &mut so);
    // #Strings heap @0x4C0: index0=NUL, then "Microsoft.VisualBasic\0X\0".
    let hp = m + 0x80;
    d[hp] = 0;
    d[hp + 1..hp + 1 + ansi.len()].copy_from_slice(ansi);
    // #US heap @0x540: idx0=0, entry len=8 "Hi\0\0US!!" utf16.
    let up = m + 0x100;
    d[up] = 0;
    d[up + 1] = 8;
    let w: Vec<u8> = "Hi!!"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    d[up + 2..up + 2 + w.len()].copy_from_slice(&w);
    d
}

#[test]
fn pe32_dotnet_heaps_parsed() {
    let d = pe32_dotnet_fixture();
    let pe = die_nfd::pe::collect(&d).expect("pe");
    assert!(pe.is_dotnet);
    assert_eq!(pe.dotnet_version, "v4.0.30319");
    assert!(pe.dotnet_ansi.iter().any(|s| s == "Microsoft.VisualBasic"));
    assert!(pe.dotnet_unicode.iter().any(|s| s == "Hi!!"));
    // Truncated heaps must not panic.
    let mut t = d.clone();
    t.truncate(0x4D0);
    let _ = die_nfd::scan(&t, die_nfd::sniff_ft(&t), die_nfd::ScanOptions::default());
}

/// PE32 with "Inno" magic at 0x30 (old Inno Setup loader marker) —
/// the header signature record and the installer handler both fire.
fn pe32_innosetup_fixture() -> Vec<u8> {
    let mut d = pe32_delphi_fixture();
    d[0x210..0x217].copy_from_slice(&[0u8; 7]);
    d[0x30..0x34].copy_from_slice(b"Inno");
    d[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // ldr table = 0
    d
}

/// PE32 whose RT_VERSION resource claims ProductName "7-Zip" +
/// RT_MANIFEST carrying "Nullsoft.NSIS" (two level-1 resource types).
fn pe32_7zip_nsis_fixture() -> Vec<u8> {
    fn w16(v: u16, out: &mut Vec<u8>) {
        out.extend(v.to_le_bytes());
    }
    // Build VS_VERSION_INFO with ProductName=7-Zip, ProductVersion=24.05.
    fn kv(key: &str, val: &str) -> Vec<u8> {
        let kw: Vec<u8> = key
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .chain([0, 0])
            .collect();
        let vw: Vec<u8> = val
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .chain([0, 0])
            .collect();
        let kd = (6 + kw.len()).div_ceil(4) * 4;
        let mut n = Vec::new();
        w16((kd + vw.len()) as u16, &mut n);
        w16((val.len() + 1) as u16, &mut n);
        w16(1, &mut n);
        n.extend(&kw);
        n.resize(kd, 0);
        n.extend(&vw);
        n.resize(n.len().div_ceil(4) * 4, 0);
        n
    }
    let kids = [kv("ProductName", "7-Zip"), kv("ProductVersion", "24.05")].concat();
    let mut lang = Vec::new();
    let lw: Vec<u8> = "040904b0"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .chain([0, 0])
        .collect();
    let ld = (6 + lw.len()).div_ceil(4) * 4;
    w16((ld + kids.len()) as u16, &mut lang);
    w16(0, &mut lang);
    w16(0, &mut lang);
    lang.extend(&lw);
    lang.resize(ld, 0);
    lang.extend(&kids);
    let mut sfi = Vec::new();
    let sw: Vec<u8> = "StringFileInfo"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .chain([0, 0])
        .collect();
    let sd = (6 + sw.len()).div_ceil(4) * 4;
    w16((sd + lang.len()) as u16, &mut sfi);
    w16(0, &mut sfi);
    w16(0, &mut sfi);
    sfi.extend(&sw);
    sfi.resize(sd, 0);
    sfi.extend(&lang);
    let mut root = Vec::new();
    let rw: Vec<u8> = "VS_VERSION_INFO"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .chain([0, 0])
        .collect();
    let rd = (6 + rw.len()).div_ceil(4) * 4;
    w16((rd + 52 + sfi.len()) as u16, &mut root);
    w16(52, &mut root);
    w16(0, &mut root);
    root.extend(&rw);
    root.resize(rd, 0);
    let mut ffi = vec![0u8; 52];
    ffi[0..4].copy_from_slice(&0xFEEF04BDu32.to_le_bytes());
    root.extend(&ffi);
    root.extend(&sfi);

    let manifest = b"<?xml version=\"1.0\"?><assembly><assemblyIdentity name=\"Nullsoft.NSIS\"/>Nullsoft Install System v3.10<";

    let mut d = pe32_delphi_fixture();
    d[0x210..0x217].copy_from_slice(&[0u8; 7]);
    d.resize(0xD00, 0);
    let opt = 0x58;
    d[opt + 96 + 16..opt + 96 + 20].copy_from_slice(&0x2000u32.to_le_bytes());
    d[opt + 96 + 20..opt + 96 + 24].copy_from_slice(&0x200u32.to_le_bytes());
    let s0 = opt + 0xE0;
    d[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
    let s1 = s0 + 40;
    d[s1..s1 + 5].copy_from_slice(b".rsrc");
    d[s1 + 8..s1 + 12].copy_from_slice(&0x400u32.to_le_bytes());
    d[s1 + 12..s1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    d[s1 + 16..s1 + 20].copy_from_slice(&0x400u32.to_le_bytes());
    d[s1 + 20..s1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    d[s1 + 36..s1 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
    // Resource root @0x400, two level-1 id entries: 16 (version),
    // 24 (manifest).
    d[0x400 + 14..0x400 + 16].copy_from_slice(&2u16.to_le_bytes());
    d[0x410..0x414].copy_from_slice(&16u32.to_le_bytes());
    d[0x414..0x418].copy_from_slice(&0x8000_0030u32.to_le_bytes());
    d[0x418..0x41C].copy_from_slice(&24u32.to_le_bytes());
    d[0x41C..0x420].copy_from_slice(&0x8000_0048u32.to_le_bytes());
    // dir2 for version @0x430 → dir3 @0x448 → data @0x460.
    d[0x430 + 14..0x430 + 16].copy_from_slice(&1u16.to_le_bytes());
    d[0x440..0x444].copy_from_slice(&1u32.to_le_bytes());
    d[0x444..0x448].copy_from_slice(&0x8000_0060u32.to_le_bytes());
    d[0x460 + 14..0x460 + 16].copy_from_slice(&1u16.to_le_bytes());
    d[0x470..0x474].copy_from_slice(&0x409u32.to_le_bytes());
    d[0x474..0x478].copy_from_slice(&0x80u32.to_le_bytes());
    d[0x480..0x484].copy_from_slice(&0x2100u32.to_le_bytes()); // →0x500
    d[0x484..0x488].copy_from_slice(&(root.len() as u32).to_le_bytes());
    d[0x500..0x500 + root.len()].copy_from_slice(&root);
    // dir2 for manifest @0x448 → dir3 @0x490 → data @0x4A8.
    d[0x448 + 14..0x448 + 16].copy_from_slice(&1u16.to_le_bytes());
    d[0x458..0x45C].copy_from_slice(&1u32.to_le_bytes());
    d[0x45C..0x460].copy_from_slice(&0x8000_0090u32.to_le_bytes());
    d[0x490 + 14..0x490 + 16].copy_from_slice(&1u16.to_le_bytes());
    d[0x4A0..0x4A4].copy_from_slice(&0x409u32.to_le_bytes());
    d[0x4A4..0x4A8].copy_from_slice(&0xA8u32.to_le_bytes());
    d[0x4A8..0x4AC].copy_from_slice(&0x2200u32.to_le_bytes()); // →0x600
    d[0x4AC..0x4B0].copy_from_slice(&(manifest.len() as u32).to_le_bytes());
    d[0x600..0x600 + manifest.len()].copy_from_slice(manifest);
    d
}

#[test]
fn pe32_innosetup_detected() {
    let d = pe32_innosetup_fixture();
    let out = die_nfd::scan(&d, die_nfd::sniff_ft(&d), die_nfd::ScanOptions::default());
    let hits: Vec<String> = out
        .iter()
        .map(|x| format!("{}:{}:{}", x.record_type, x.record_name, x.version))
        .collect();
    assert!(
        hits.iter().any(|h| h.contains("Installer")
            && h.contains("Inno Setup")
            && h.contains("1.XX-5.1.X")),
        "{hits:?}"
    );
}

#[test]
fn pe32_7zip_sfx_and_nsis() {
    let d = pe32_7zip_nsis_fixture();
    let out = die_nfd::scan(&d, die_nfd::sniff_ft(&d), die_nfd::ScanOptions::default());
    let hits: Vec<String> = out
        .iter()
        .map(|x| {
            format!(
                "{}:{}:{}:{}",
                x.record_type, x.record_name, x.version, x.info
            )
        })
        .collect();
    assert!(
        hits.iter()
            .any(|h| h.contains("SFX") && h.contains("7-Zip") && h.contains("24.05")),
        "{hits:?}"
    );
    assert!(
        hits.iter().any(|h| {
            h.contains("Installer") && h.contains("Nullsoft Scriptable") && h.contains("3.10")
        }),
        "{hits:?}"
    );
}

#[test]
fn pe32_dotnet_ansi_heap_promotes_dotfuscator() {
    let d = pe32_dotnet_fixture_heap(b"DotfuscatorAttribute\0");
    let out = die_nfd::scan(&d, die_nfd::sniff_ft(&d), die_nfd::ScanOptions::default());
    assert!(
        out.iter().any(|x| x.record_name.contains("Dotfuscator")),
        "{:?}",
        out.iter()
            .map(|x| x.record_name.clone())
            .collect::<Vec<_>>()
    );
}

/// Two-section PE32 named `.aspack`/`.adata` exercising
/// `handle_UnknownProtection`'s ASPack section-name heuristic.
fn pe32_aspack_sections_fixture() -> Vec<u8> {
    let mut d = vec![0u8; 0x600];
    d[0..2].copy_from_slice(b"MZ");
    d[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    d[0x40..0x44].copy_from_slice(b"PE\0\0");
    d[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes());
    d[0x46..0x48].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    d[0x54..0x56].copy_from_slice(&0xE0u16.to_le_bytes());
    let opt = 0x58;
    d[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    d[opt + 2] = 2;
    d[opt + 3] = 25;
    d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    d[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    d[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
    let sec = opt + 0xE0;
    d[sec..sec + 7].copy_from_slice(b".aspack");
    d[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes());
    d[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    d[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
    d[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
    d[sec + 36..sec + 40].copy_from_slice(&0xE000_0060u32.to_le_bytes());
    let s2 = sec + 40;
    d[s2..s2 + 6].copy_from_slice(b".adata");
    d[s2 + 8..s2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    d[s2 + 12..s2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    d[s2 + 16..s2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    d[s2 + 20..s2 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    d[s2 + 36..s2 + 40].copy_from_slice(&0xE000_0060u32.to_le_bytes());
    d
}

#[test]
fn pe32_aspack_section_heuristic() {
    let d = pe32_aspack_sections_fixture();
    let (_ft, out) = show("pe32-aspack-synth", &d);
    let a = out.iter().find(|r| r.record_name == "ASPack");
    let a = a.unwrap_or_else(|| panic!("no ASPack in {out:?}"));
    assert!(a.heuristic, "ASPack record must be flagged heuristic");
    assert_eq!(a.version, "2.12-2.XX");
}

/// PE32 with an encoded Rich header in the DOS stub: `DanS` + 3 zero
/// dwords + entries {MSLINKER id=258 build=30000, UTC id=261 build=30000}.
/// `handle_Microsoft` should derive linker `14.29.30000` (minor from the
/// optional header) and Visual C++ `19.28.30000` (build threshold table).
fn pe32_rich_fixture() -> Vec<u8> {
    let mut d = vec![0u8; 0x800];
    let key: u32 = 0x1234_5678;
    let w32 = |d: &mut [u8], off: usize, v: u32| {
        d[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    d[0..2].copy_from_slice(b"MZ");
    w32(&mut d, 0x3C, 0x200); // e_lfanew
    // Rich block inside the stub region.
    w32(&mut d, 0x180, 0x536E_6144 ^ key); // DanS
    w32(&mut d, 0x184, key); // zero
    w32(&mut d, 0x188, key);
    w32(&mut d, 0x18C, key);
    w32(&mut d, 0x190, ((258u32 << 16) | 30000) ^ key); // MICROSOFTLINKER
    w32(&mut d, 0x194, 3 ^ key);
    w32(&mut d, 0x198, ((261u32 << 16) | 30000) ^ key); // UTC C/C++
    w32(&mut d, 0x19C, 1 ^ key);
    d[0x1A0..0x1A4].copy_from_slice(b"Rich");
    w32(&mut d, 0x1A4, key);
    // PE headers.
    d[0x200..0x204].copy_from_slice(b"PE\0\0");
    w32(&mut d, 0x204, 0);
    d[0x204..0x206].copy_from_slice(&0x014Cu16.to_le_bytes()); // I386
    d[0x206..0x208].copy_from_slice(&1u16.to_le_bytes());
    d[0x214..0x216].copy_from_slice(&0xE0u16.to_le_bytes());
    d[0x216..0x218].copy_from_slice(&0x010Fu16.to_le_bytes());
    let opt = 0x218;
    d[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    d[opt + 2] = 14; // MajorLinkerVersion
    d[opt + 3] = 29; // MinorLinkerVersion
    w32(&mut d, opt + 16, 0x1000); // EP rva
    w32(&mut d, opt + 28, 0x0040_0000);
    w32(&mut d, opt + 32, 0x1000);
    w32(&mut d, opt + 36, 0x200);
    d[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    w32(&mut d, opt + 92, 16);
    // .text @0x2F8: vaddr 0x1000, raw 0x400/0x200.
    let sec = opt + 0xE0;
    d[sec..sec + 5].copy_from_slice(b".text");
    w32(&mut d, sec + 8, 0x200);
    w32(&mut d, sec + 12, 0x1000);
    w32(&mut d, sec + 16, 0x200);
    w32(&mut d, sec + 20, 0x400);
    w32(&mut d, sec + 36, 0x6000_0020);
    d
}

#[test]
fn pe32_rich_toolchain_chain() {
    let d = pe32_rich_fixture();
    let (_ft, out) = show("pe32-rich-synth", &d);
    let linker = out
        .iter()
        .find(|x| x.record_type == "Linker" && x.record_name.contains("Microsoft"))
        .expect("rich-derived Microsoft linker");
    assert_eq!(linker.version, "14.29.30000");
    let cpp = out
        .iter()
        .find(|x| x.record_type == "Compiler" && x.record_name.contains("Visual C/C++"))
        .expect("rich-derived Visual C++");
    assert_eq!(cpp.version, "19.28.30000");
}

/// ELF64 + a 0x24-byte UPX tail block (`_get_UPX_vi` at size-0x24):
/// `magic` occupies the UPX! position; format=10/method=2(NRV2B_LE32)/
/// level=8(best), u_len 0x2000 > c_len 0x1000.
fn elf_upx_tail(magic: u32) -> Vec<u8> {
    let mut d = elf64_with(&[], 0, 0x3E, 2);
    let base = d.len();
    d.resize(base + 0x40, 0); // pad so the tail block lands at end
    let off = d.len() - 0x24;
    d[off..off + 4].copy_from_slice(&magic.to_le_bytes());
    d[off + 4] = 4; // version
    d[off + 5] = 10; // format
    d[off + 6] = 2; // method NRV2B_LE32
    d[off + 7] = 8; // level best
    d[off + 16..off + 20].copy_from_slice(&0x2000u32.to_le_bytes());
    d[off + 20..off + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    d
}

#[test]
fn elf_upx_tail_protection() {
    let d = elf_upx_tail(0x2158_5055); // "UPX!"
    let (_ft, out) = show("elf-upx-tail", &d);
    let upx = out
        .iter()
        .find(|r| r.record_name == "UPX")
        .expect("UPX packer record");
    assert!(upx.info.contains("NRV2B_LE32"), "info: {}", upx.info);
    assert!(upx.info.contains("best"));
}

#[test]
fn elf_secneo_tag_at_upx_tail() {
    let d = elf_upx_tail(0x2143_4553); // "SEC!"
    let (_ft, out) = show("elf-secneo-tail", &d);
    assert!(
        out.iter()
            .any(|r| r.record_name == "SecNeo" && r.version == "Old" && r.info == "UPX"),
        "{:?}",
        out.iter()
            .map(|r| r.record_name.clone())
            .collect::<Vec<_>>()
    );
    // The tail block still parses as a (modified) UPX record.
    let upx = out
        .iter()
        .find(|r| r.record_name == "UPX")
        .expect("UPX packer record");
    assert!(upx.info.contains("Modified"), "info: {}", upx.info);
}

/// Minimal NE image: MZ stub with e_lfanew=0x40, NE header with
/// exetyp=2 (Windows) and a single segment covering 0x80..0x180; EP
/// (CS:IP) lands in that segment where a Watcom banner sits; byte 0xFB
/// at 0x1E + 0x40 at 0x1F emulates the TurboLinker trailer
/// (0x40/16 = 4.0).
fn ne_fixture() -> Vec<u8> {
    let mut d = vec![0u8; 0x400];
    d[0..2].copy_from_slice(b"MZ");
    d[0x1E] = 0xFB;
    d[0x1F] = 0x40;
    d[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    let ne = 0x40;
    d[ne..ne + 2].copy_from_slice(b"NE");
    d[ne + 0x0C..ne + 0x0E].copy_from_slice(&0x0000u16.to_le_bytes()); // flags
    d[ne + 0x14..ne + 0x16].copy_from_slice(&0x10u16.to_le_bytes()); // IP
    d[ne + 0x16..ne + 0x18].copy_from_slice(&1u16.to_le_bytes()); // CS = seg 1
    d[ne + 0x1C..ne + 0x1E].copy_from_slice(&1u16.to_le_bytes()); // cseg
    d[ne + 0x22..ne + 0x24].copy_from_slice(&0x40u16.to_le_bytes()); // segtab rel
    d[ne + 0x32..ne + 0x34].copy_from_slice(&4u16.to_le_bytes()); // align = 4
    d[ne + 0x36] = 2; // exetyp = Windows
    // Segment entry @0x80: sector 8 (=> file 0x80), size 0x100.
    d[0x80..0x82].copy_from_slice(&8u16.to_le_bytes());
    d[0x82..0x84].copy_from_slice(&0x100u16.to_le_bytes());
    // EP = sector 8<<4 + 0x10 = 0x90; Watcom banner there.
    d[0x90..0x9E].copy_from_slice(b"Open Watcom C\0");
    d[0xA0..0xAB].copy_from_slice(b"x 2002-1234");
    d
}

#[test]
fn ne_semantic_handlers() {
    let d = ne_fixture();
    let (ft, out) = show("ne-synth", &d);
    assert_eq!(ft_name(ft), "FT_NE");
    let names: Vec<String> = out
        .iter()
        .map(|r| format!("{}:{}", r.record_type, r.record_name))
        .collect();
    assert!(names.iter().any(|s| s.contains("Windows")), "{names:?}");
    assert!(
        out.iter()
            .any(|r| r.record_name == "Turbo linker" && r.version == "4.0"),
        "{names:?}"
    );
    assert!(
        out.iter()
            .any(|r| r.record_name == "Open Watcom C/C++" && r.version == "1234"),
        "{names:?}"
    );
    assert!(out.iter().any(|r| r.record_name == "Watcom linker"));
}

/// `NFD_COM::handle_Protection` — a HACKSTOP header detection promotes
/// the MS-DOS OS record; CP/M-call dominance flips it to CP/M.
#[test]
fn com_protection_os_record() {
    let mut d = vec![0u8; 256];
    d[..6].copy_from_slice(&[0xFA, 0xBD, 0x00, 0x00, 0xFF, 0xE5]);
    let out = die_nfd::scan(&d, ft::FT_COM, ScanOptions::default());
    let names: Vec<String> = out
        .iter()
        .map(|r| {
            format!(
                "{}:{} {} {}",
                r.record_type, r.record_name, r.version, r.info
            )
        })
        .collect();
    eprintln!("com: {names:?}");
    assert!(names.iter().any(|s| s.contains("HackStop")), "{names:?}");
    assert!(
        names
            .iter()
            .any(|s| s.contains("MS-DOS") && s.contains("8086, 16-bit, EXE")),
        "{names:?}"
    );

    // CP/M flavour: BDOS calls (CD 05 00) outnumber INT 21h (CD 21).
    let mut d2 = vec![0u8; 64];
    d2[..6].copy_from_slice(&[0xFA, 0xBD, 0x00, 0x00, 0xFF, 0xE5]);
    d2[16..19].copy_from_slice(&[0xCD, 0x05, 0x00]);
    d2[24..27].copy_from_slice(&[0xCD, 0x05, 0x00]);
    let out2 = die_nfd::scan(&d2, ft::FT_COM, ScanOptions::default());
    let n2: Vec<String> = out2
        .iter()
        .map(|r| format!("{}:{} {}", r.record_type, r.record_name, r.info))
        .collect();
    assert!(
        n2.iter()
            .any(|s| s.contains("CP/M") && s.contains("8080/Z80")),
        "{n2:?}"
    );
}

/// `NFD_CFBF::getInfo` — the u16 at 0x200/0x1000 promotes the compound
/// document to Microsoft Installer / Word 97-2003; deep scan finds the
/// Advanced Installer marker.
#[test]
fn cfbf_subtype_promotion() {
    let mut msi = vec![0u8; 0x1200];
    msi[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    msi[0x1000..0x1002].copy_from_slice(&0xFFFDu16.to_le_bytes());
    let out = die_nfd::scan(&msi, ft::FT_CFBF, ScanOptions::default());
    let names: Vec<String> = out.iter().map(|r| r.record_name.to_string()).collect();
    assert!(
        names.iter().any(|s| s.starts_with("Microsoft Installer")),
        "{names:?}"
    );
    assert!(
        !names.iter().any(|s| s == "Microsoft Compound"),
        "{names:?}"
    );

    let mut word = vec![0u8; 0x400];
    word[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    word[0x200..0x202].copy_from_slice(&0xA5ECu16.to_le_bytes());
    let out = die_nfd::scan(&word, ft::FT_CFBF, ScanOptions::default());
    let names: Vec<String> = out
        .iter()
        .map(|r| format!("{}:{}", r.record_name, r.version))
        .collect();
    assert!(
        names.iter().any(|s| s == "Microsoft Office Word:97-2003"),
        "{names:?}"
    );

    let mut ai = vec![0u8; 0x400];
    ai[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    ai[0x100..]
        .iter_mut()
        .take(17)
        .zip(b"AI_PACKAGING_TOOL")
        .for_each(|(b, s)| *b = *s);
    ai[0x111..]
        .iter_mut()
        .take(23)
        .zip(b"Advanced Installer 19.3\r\n")
        .for_each(|(b, s)| *b = *s);
    let out = die_nfd::scan(
        &ai,
        ft::FT_CFBF,
        ScanOptions {
            deep_scan: true,
            ..Default::default()
        },
    );
    let names: Vec<String> = out
        .iter()
        .map(|r| format!("{}:{} {}", r.record_type, r.record_name, r.version))
        .collect();
    assert!(
        names
            .iter()
            .any(|s| s.contains("Advanced Installer") && s.contains("19.3")),
        "{names:?}"
    );
}

/// `NFD_PDF::getInfo` — `/Encrypt` becomes an `Unknown` protector with
/// the encryption description; `/Producer` becomes a tool record.
#[test]
fn pdf_encrypt_and_producer() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Encrypt << /V 4 /R 4 /Length 128 /CF << /CFM /AESV2 >> /P -3904 >> /Producer (Acrobat Distiller 9.0) >>\nendobj\n%%EOF";
    let out = die_nfd::scan(pdf, ft::FT_PDF, ScanOptions::default());
    let names: Vec<String> = out
        .iter()
        .map(|r| {
            format!(
                "{}:{} {} {}",
                r.record_type, r.record_name, r.version, r.info
            )
        })
        .collect();
    eprintln!("pdf: {names:?}");
    assert!(names.iter().any(|s| s.contains("PDF")), "{names:?}");
    assert!(
        names.iter().any(|s| {
            s.contains("Protector")
                && s.contains("V4 R4 128-bit AESV2 P=-3904")
                && s.contains("Encrypted")
        }),
        "{names:?}"
    );
    assert!(
        names.iter().any(|s| s.contains("Acrobat Distiller 9.0")),
        "{names:?}"
    );
}

/// `NFD_Amiga::getInfo` — hunk magic sniffs to FT_AMIGAHUNK and emits
/// the Amiga OS record with 68K/16-bit info.
#[test]
fn amiga_hunk_os_record() {
    let mut d = vec![0u8; 32];
    d[..4].copy_from_slice(&[0x00, 0x00, 0x03, 0xF3]);
    assert_eq!(ft_name(sniff_ft(&d)), "FT_AMIGAHUNK");
    let out = die_nfd::scan(&d, ft::FT_AMIGAHUNK, ScanOptions::default());
    let names: Vec<String> = out
        .iter()
        .map(|r| format!("{}:{} {}", r.record_type, r.record_name, r.info))
        .collect();
    assert!(
        names
            .iter()
            .any(|s| s.contains("Amiga") && s.contains("68K, 16-bit, EXE, BE")),
        "{names:?}"
    );
}

/// Build a minimal stored-method ZIP with the given members.
fn zip_stored(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut d = Vec::new();
    let mut centrals = Vec::new();
    for (name, body) in entries {
        let local_off = d.len() as u32;
        d.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        d.extend_from_slice(&20u16.to_le_bytes()); // version needed
        d.extend_from_slice(&0u16.to_le_bytes()); // flags
        d.extend_from_slice(&0u16.to_le_bytes()); // stored
        d.extend_from_slice(&0u32.to_le_bytes()); // time/date
        d.extend_from_slice(&0u32.to_le_bytes()); // crc
        d.extend_from_slice(&(body.len() as u32).to_le_bytes());
        d.extend_from_slice(&(body.len() as u32).to_le_bytes());
        d.extend_from_slice(&(name.len() as u16).to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes()); // extra len
        d.extend_from_slice(name.as_bytes());
        d.extend_from_slice(body);
        centrals.push((name.to_string(), body.len() as u32, local_off));
    }
    let cd_off = d.len() as u32;
    for (name, size, local_off) in &centrals {
        d.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]);
        d.extend_from_slice(&20u16.to_le_bytes()); // version made
        d.extend_from_slice(&20u16.to_le_bytes()); // version needed
        d.extend_from_slice(&0u16.to_le_bytes()); // flags
        d.extend_from_slice(&0u16.to_le_bytes()); // method
        d.extend_from_slice(&0u32.to_le_bytes()); // time/date
        d.extend_from_slice(&0u32.to_le_bytes()); // crc
        d.extend_from_slice(&size.to_le_bytes());
        d.extend_from_slice(&size.to_le_bytes());
        d.extend_from_slice(&(name.len() as u16).to_le_bytes());
        d.extend_from_slice(&[0u8; 8]); // extra+comment+disk+int attr
        d.extend_from_slice(&0u32.to_le_bytes()); // ext attr
        d.extend_from_slice(&local_off.to_le_bytes());
        d.extend_from_slice(name.as_bytes());
    }
    let cd_size = d.len() as u32 - cd_off;
    d.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    d.extend_from_slice(&[0u8; 4]); // disk numbers
    d.extend_from_slice(&(centrals.len() as u16).to_le_bytes());
    d.extend_from_slice(&(centrals.len() as u16).to_le_bytes());
    d.extend_from_slice(&cd_size.to_le_bytes());
    d.extend_from_slice(&cd_off.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d
}

/// `NFD_JAR::getInfo` — upstream emits the XZip FFI OS record
/// (`Unknown [NOEXEC, Data, Archive]`) plus MANIFEST.MF vendor/JDK/Ant
/// tool detections and the trailing ZIP container record.
#[test]
fn jar_manifest_and_class_version() {
    let mut class = vec![0u8; 16];
    class[..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    class[4..6].copy_from_slice(&0u16.to_be_bytes()); // minor
    class[6..8].copy_from_slice(&0x34u16.to_be_bytes()); // major 52 -> Java SE 8
    let manifest = b"Manifest-Version: 1.0\r\nCreated-By: 1.8.0_252 (Oracle Corporation)\r\nAnt-Version: Apache Ant 1.10.12\r\n";
    let jar = zip_stored(&[
        ("META-INF/MANIFEST.MF", manifest),
        ("com/acme/Main.class", &class),
    ]);
    let out = die_nfd::scan(&jar, ft::FT_JAR, ScanOptions::default());
    let names: Vec<String> = out
        .iter()
        .map(|r| {
            format!(
                "{}:{} {} {}",
                r.record_type, r.record_name, r.version, r.info
            )
        })
        .collect();
    eprintln!("jar: {names:?}");
    assert!(
        names
            .iter()
            .any(|s| s.contains("Operation system:Unknown") && s.contains("NOEXEC, Data, Archive")),
        "{names:?}"
    );
    assert!(
        names
            .iter()
            .any(|s| s.contains("JDK") && s.contains("1.8.0_252")),
        "{names:?}"
    );
    assert!(
        names
            .iter()
            .any(|s| s.contains("Apache Ant") && s.contains("1.10.12")),
        "{names:?}"
    );
}

/// `NFD_Binary::handle_Texts` — source-language heuristics: include-guard
/// C header, shebang interpreter, Python class/def/self/imports.
#[test]
fn text_source_heuristics() {
    let c_hdr = b"#ifndef MY_HEADER_H\n#define MY_HEADER_H\n\nint square(int);\n#endif\n";
    let out = die_nfd::scan(c_hdr, ft::FT_BINARY, ScanOptions::default());
    let names: Vec<String> = out
        .iter()
        .map(|r| format!("{}:{} {}", r.record_type, r.record_name, r.info))
        .collect();
    eprintln!("hdr: {names:?}");
    assert!(
        names
            .iter()
            .any(|s| s.contains("C/C++") && s.contains("header")),
        "{names:?}"
    );

    let py = b"#!/usr/bin/env python3\nimport os\nclass Foo:\n    def bar(self):\n        pass\n";
    let out = die_nfd::scan(py, ft::FT_BINARY, ScanOptions::default());
    let names: Vec<String> = out
        .iter()
        .map(|r| format!("{}:{} {}", r.record_type, r.record_name, r.info))
        .collect();
    eprintln!("py: {names:?}");
    assert!(names.iter().any(|s| s.contains("Python")), "{names:?}");
    assert!(
        names
            .iter()
            .any(|s| s.contains("Shell") && s.contains("Python3")),
        "{names:?}"
    );
}

#[test]
fn apk_debug_members() {
    let d = zip_with_members(&[
        ("AndroidManifest.xml", b"<manifest/>\n"),
        ("assets/secData0.jar", b"x"),
    ]);
    let ms = die_nfd::parse::zip_members(&d);
    for m in &ms {
        eprintln!(
            "member: {} unc={} method={} comp={}",
            m.name, m.unc_size, m.method, m.comp_size
        );
    }
    let mm = ms.iter().find(|m| m.name == "AndroidManifest.xml").unwrap();
    let raw = die_nfd::parse::zip_member_data(&d, mm, 1024);
    eprintln!("manifest raw: {:?}", raw);
}

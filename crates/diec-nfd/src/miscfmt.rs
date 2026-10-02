//! Small-format semantic handlers — the post-scan `getInfo` fixups of
//! `NFD_COM`, `NFD_PDF`, `NFD_CFBF` and `NFD_Amiga`:
//!
//! * COM: `handle_Protection` transfers header detections into the result
//!   maps (a no-op in our merged map, since header records drain to output)
//!   and emits the MS-DOS / CP/M OS record when a packer/protector/tool
//!   detection was promoted; `isCPM` counts BDOS vs DOS service calls.
//! * PDF: `/Encrypt` dictionary -> `Unknown` protector with the encryption
//!   description, `/Producer` and `/Creator` strings -> `UNKNOWN0+i` tool
//!   records.
//! * CFBF: subtype override at 0x200/0x1000 (Microsoft Installer,
//!   Word 97-2003) and the deep-scan `AI_PACKAGING_TOOL` -> Advanced
//!   Installer heuristic.
//! * Amiga hunk: OS record with hunk-derived arch/mode/type info.

use crate::parse;
use crate::scans::{DetectMap, ScanRecord};
use crate::{gen_names::ft, gen_names::name as n, gen_names::rtype as rt};

fn emit(map: &mut DetectMap, ft_id: u16, rtype: u8, name: u16, ver: &str, info: &str) {
    map.entry(name).or_insert_with(|| ScanRecord {
        name,
        rtype,
        ft: ft_id,
        variant: 0,
        version: ver.to_string(),
        info: info.to_string(),
        heuristic: false,
        unknown: false,
    });
}

/// `NFD_COM::isCPM` — a COM image is CP/M when BDOS calls (`CD 05 00`)
/// dominate DOS calls (`CD 21`), it opens with a Z80 `JP` (`C3`), or it
/// starts with the canonical `LHLD 0006 / SPHL` prologue (`2A 06 00 F9`).
fn is_cpm(d: &[u8]) -> bool {
    if d.is_empty() || d.len() > 0x10000 || d.len() < 4 {
        return false;
    }
    let mut bdos = 0u32;
    let mut int21 = 0u32;
    for w in d.windows(3) {
        if w[0] == 0xCD {
            if w[1] == 0x05 && w[2] == 0x00 {
                bdos += 1;
            } else if w[1] == 0x21 {
                int21 += 1;
            }
        }
    }
    if bdos > 0 && bdos >= int21 {
        return true;
    }
    if d[0] == 0xC3 && int21 == 0 {
        return true;
    }
    d[0] == 0x2A && d[1] == 0x06 && d[2] == 0x00 && d[3] == 0xF9
}

/// `NFD_COM::handle_Protection` — the header->result transfers are implicit
/// (header records drain to output); the observable side effect is the OS
/// record emitted when a packer/protector/tool name was promoted.
const COM_PROTECTION_NAMES: &[u16] = &[
    n::RECORD_NAME_PKLITE,
    n::RECORD_NAME_UPX,
    n::RECORD_NAME_HACKSTOP,
    n::RECORD_NAME_CRYPTDISMEMBER,
    n::RECORD_NAME_SPIRIT,
    n::RECORD_NAME_ICE,
    n::RECORD_NAME_DIET,
    n::RECORD_NAME_624,
    n::RECORD_NAME_LGLZ,
    n::RECORD_NAME_PACK,
    n::RECORD_NAME_SCRNCH,
    n::RECORD_NAME_XPACK,
    n::RECORD_NAME_PCOM,
    n::RECORD_NAME_BESTPROTECTIONKIT,
    n::RECORD_NAME_DIGPAK,
    n::RECORD_NAME_MIDPAK,
    n::RECORD_NAME_GPATCH,
    n::RECORD_NAME_WOLVERINEPATCHER,
    n::RECORD_NAME_PKZIPMINISFX,
    n::RECORD_NAME_CRYPTORBYEVILGENIUS,
    n::RECORD_NAME_EXE2COM,
    n::RECORD_NAME_MASK,
    n::RECORD_NAME_EXECOMCONVERTERS,
];

/// `NFD_COM::getInfo` tail — emit the DOS/CP-M OS record when a protection
/// header detection exists (or unconditionally in verbose mode upstream;
/// our dispatch is always verbose-equivalent).
pub fn com_semantic_scan(d: &[u8], header: &DetectMap, misc: &mut DetectMap) {
    if !COM_PROTECTION_NAMES
        .iter()
        .any(|nm| header.contains_key(nm))
    {
        return;
    }
    if is_cpm(d) {
        emit(
            misc,
            ft::FT_COM,
            rt::RECORD_TYPE_OPERATIONSYSTEM,
            n::RECORD_NAME_CPM,
            "",
            "8080/Z80",
        );
    } else {
        emit(
            misc,
            ft::FT_COM,
            rt::RECORD_TYPE_OPERATIONSYSTEM,
            n::RECORD_NAME_MSDOS,
            "",
            "8086, 16-bit, EXE",
        );
    }
}

/// `NFD_Amiga::getInfo` — `detectOperationSystem` on the hunk header:
/// arch `68K` (`PPC` when a `HUNK_PPC_CODE` hunk is present), mode `16-bit`
/// (`32-bit` with `HUNK_RELOC32`), type `EXE` for `HUNK_HEADER` and `Object`
/// for `HUNK_UNIT`.
pub fn amiga_semantic_scan(d: &[u8], misc: &mut DetectMap) {
    let is_header = parse::rd_u32_be_le(d, 0, true).unwrap_or(0) == 0x3F3;
    let arch = if hunk_present(d, 0x4E9) { "PPC" } else { "68K" };
    let mode = if hunk_present(d, 0x3EC) {
        "32-bit"
    } else {
        "16-bit"
    };
    let ty = if is_header { "EXE" } else { "Object" };
    emit(
        misc,
        ft::FT_AMIGAHUNK,
        rt::RECORD_TYPE_OPERATIONSYSTEM,
        n::RECORD_NAME_AMIGA,
        "",
        &format!("{arch}, {mode}, {ty}, BE"),
    );
}

/// Bounded hunk-id walk: hunk headers are `u32be` ids stored in the first
/// longword of each hunk. Mirrors `XAmigaHunk::isHunkPresent` loosely —
/// scans big-endian words anywhere in the file (upstream parses the hunk
/// chain; a linear scan over 4-byte words is equivalent for presence).
fn hunk_present(d: &[u8], id: u32) -> bool {
    d.chunks_exact(4)
        .any(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]) & 0x3FFF_FFFF == id)
}

/// `NFD_CFBF::getInfo` — subtype promotion from the u16 at 0x200/0x1000,
/// plus the deep-scan `AI_PACKAGING_TOOL` -> Advanced Installer heuristic.
/// The generic Microsoft Compound format record is replaced on promotion.
pub fn cfbf_semantic_scan(d: &[u8], deep: bool, header: &mut DetectMap, misc: &mut DetectMap) {
    let sub1 = parse::rd_u16(d, 0x200).unwrap_or(0);
    let sub2 = parse::rd_u16(d, 0x1000).unwrap_or(0);
    if sub1 == 0 && sub2 == 0xFFFD {
        header.remove(&n::RECORD_NAME_MICROSOFTCOMPOUND);
        emit(
            misc,
            ft::FT_CFBF,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_MICROSOFTINSTALLER,
            "",
            "",
        );
    } else if sub1 == 0xA5EC {
        header.remove(&n::RECORD_NAME_MICROSOFTCOMPOUND);
        emit(
            misc,
            ft::FT_CFBF,
            rt::RECORD_TYPE_FORMAT,
            n::RECORD_NAME_MICROSOFTOFFICEWORD,
            "97-2003",
            "",
        );
    }
    if !deep {
        return;
    }
    let Some(off) = find_ansi(d, b"AI_PACKAGING_TOOL") else {
        return;
    };
    let mut ver = String::new();
    // `get_ansiStringValue`-style tail: when the bytes right after the
    // marker start with "Advanced Installer", the next word is the
    // version (`Advanced Installer 19.3` -> `19.3`).
    let tail = &d[(off + 17).min(d.len())..];
    if tail.starts_with(b"Advanced Installer")
        && let Some(v) = tail_word_after(tail, b"Advanced Installer")
    {
        ver = v;
    }
    emit(
        misc,
        ft::FT_CFBF,
        rt::RECORD_TYPE_INSTALLER,
        n::RECORD_NAME_ADVANCEDINSTALLER,
        &ver,
        "",
    );
}

fn find_ansi(d: &[u8], needle: &[u8]) -> Option<usize> {
    d.windows(needle.len()).position(|w| w == needle)
}

/// Return the first whitespace-separated token after `marker`, or `None`.
fn tail_word_after(d: &[u8], marker: &[u8]) -> Option<String> {
    let rest = d.get(marker.len()..)?;
    let rest = rest
        .iter()
        .position(|b| !b.is_ascii_whitespace() && *b != 0)?;
    let word: Vec<u8> = d[marker.len() + rest..]
        .iter()
        .take_while(|b| b.is_ascii_graphic())
        .copied()
        .collect();
    if word.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&word).into_owned())
    }
}

/// `NFD_PDF::getInfo` — `/Encrypt` dictionary -> `Unknown` protector with
/// the `Standard V<v> R<r> <bits>-bit <method> P=<perm>` description and
/// `Encrypted` info; `/Producer` and `/Creator` strings -> `UNKNOWN0+i`
/// tool records.
pub fn pdf_semantic_scan(d: &[u8], misc: &mut DetectMap) {
    if let Some(enc) = pdf_encrypt_info(d) {
        emit(
            misc,
            ft::FT_PDF,
            rt::RECORD_TYPE_PROTECTOR,
            n::RECORD_NAME_UNKNOWN,
            &enc,
            "Encrypted",
        );
    }
    for (i, s) in pdf_key_strings(d, b"/Producer", 10).iter().enumerate() {
        emit(
            misc,
            ft::FT_PDF,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_UNKNOWN0 + i as u16,
            "",
            s,
        );
    }
    for (i, s) in pdf_key_strings(d, b"/Creator", 10).iter().enumerate() {
        emit(
            misc,
            ft::FT_PDF,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_UNKNOWN0 + i as u16,
            "",
            s,
        );
    }
}

/// Reconstruct the `XPDF::getEncryption` description from a `/Encrypt`
/// dictionary: `Standard V<v> R<r> [<bits>-bit ]<method> P=<perm>`.
fn pdf_encrypt_info(d: &[u8]) -> Option<String> {
    let pos = find_ansi(d, b"/Encrypt")?;
    // The /Encrypt dict object follows within the same object body; bound
    // the window to the next 512 bytes like upstream's object parsing.
    let win = &d[pos..(pos + 512).min(d.len())];
    let dict = find_ansi(win, b"<<")?;
    // Keep the whole window: the encrypt dictionary may embed sub-dicts
    // (`/CF << /CFM /AESV2 >>`), so truncating at the first `>>` loses
    // trailing keys like `/P`.
    let w = &win[dict..];
    let v = pdf_int_key(w, b"/V");
    let r = pdf_int_key(w, b"/R");
    let length = pdf_int_key(w, b"/Length");
    let p = pdf_int_key(w, b"/P");
    // Method name: /CFM inside /CF entries, else derive from V.
    let method = pdf_name_value(w, b"/CFM").unwrap_or_else(|| match v {
        Some(4) | Some(5) => "AESV2".to_string(),
        _ => "RC4".to_string(),
    });
    let mut s = String::from("Standard");
    if let Some(v) = v {
        s.push_str(&format!(" V{v}"));
    }
    if let Some(r) = r {
        s.push_str(&format!(" R{r}"));
    }
    if let Some(l) = length {
        s.push_str(&format!(" {l}-bit"));
    }
    s.push(' ');
    s.push_str(&method);
    if let Some(p) = p {
        s.push_str(&format!(" P={p}"));
    }
    Some(s)
}

/// Locate `key` followed by a non-alphabetic delimiter, so `/P` does
/// not match `/Producer` or `/Perms`.
fn find_key(d: &[u8], key: &[u8]) -> Option<usize> {
    let mut off = 0usize;
    loop {
        let pos = off + find_ansi(&d[off..], key)?;
        let next = d.get(pos + key.len()).copied();
        if next.is_none_or(|b| !b.is_ascii_alphanumeric()) {
            return Some(pos);
        }
        off = pos + key.len();
    }
}

/// Read an integer PDF dictionary value: `/Key <int>`.
fn pdf_int_key(d: &[u8], key: &[u8]) -> Option<i64> {
    let pos = find_key(d, key)?;
    let rest = d.get(pos + key.len()..)?;
    let skip = rest.iter().position(|b| *b == b'-' || b.is_ascii_digit())?;
    let num: String = rest[skip..]
        .iter()
        .take_while(|b| **b == b'-' || b.is_ascii_digit())
        .map(|b| *b as char)
        .collect();
    num.parse().ok()
}

/// Read a name PDF dictionary value: `/CFM /AESV2` -> `AESV2`.
fn pdf_name_value(d: &[u8], key: &[u8]) -> Option<String> {
    let pos = find_key(d, key)?;
    let rest = d.get(pos + key.len()..)?;
    let slash = rest.iter().position(|b| *b == b'/')?;
    let name: String = rest[slash + 1..]
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric())
        .map(|b| *b as char)
        .collect();
    if name.is_empty() { None } else { Some(name) }
}

/// Collect string values of a PDF key: `/Key (literal)` or `/Key <hex>`,
/// up to `cap` occurrences, mirroring `getValuesByKey`.
fn pdf_key_strings(d: &[u8], key: &[u8], cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while out.len() < cap {
        let rel = find_ansi(&d[off..], key);
        let Some(rel) = rel else { break };
        let pos = off + rel;
        // The next key must not be a longer key sharing our prefix
        // ("/Producer" must not match "/ProducerX").
        let rest = &d[pos + key.len()..];
        if rest.first().is_some_and(|b| b.is_ascii_alphabetic()) {
            off = pos + key.len();
            continue;
        }
        if let Some(s) = pdf_string_value(rest) {
            out.push(s);
        }
        off = pos + key.len();
    }
    out
}

/// Parse a literal `(…)` or hex `<…>` PDF string at the head of `rest`
/// (after whitespace). Bounded, paren-nesting aware.
fn pdf_string_value(rest: &[u8]) -> Option<String> {
    let i = rest.iter().position(|b| *b == b'(' || *b == b'<')?;
    match rest[i] {
        b'(' => {
            let mut depth = 1u32;
            let mut out = Vec::new();
            let mut j = i + 1;
            while j < rest.len() && depth > 0 && out.len() < 0x1000 {
                let c = rest[j];
                if c == b'\\' && j + 1 < rest.len() {
                    out.push(rest[j + 1]);
                    j += 2;
                    continue;
                }
                if c == b'(' {
                    depth += 1;
                } else if c == b')' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                out.push(c);
                j += 1;
            }
            if depth == 0 {
                Some(String::from_utf8_lossy(&out).into_owned())
            } else {
                None
            }
        }
        b'<' => {
            if rest.get(i + 1) == Some(&b'<') {
                return None;
            }
            let hex: String = rest[i + 1..]
                .iter()
                .take_while(|b| **b != b'>')
                .filter(|b| b.is_ascii_hexdigit())
                .map(|b| *b as char)
                .take(0x2000)
                .collect();
            let bytes: Vec<u8> = (0..hex.len() / 2)
                .filter_map(|k| u8::from_str_radix(&hex[k * 2..k * 2 + 2], 16).ok())
                .collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

/// `XJavaClass::_getJDKVersion` — class-file major/minor -> JDK name.
fn jdk_version(major: u16, minor: u16) -> String {
    let base = match major {
        0x2D => "JDK 1.1",
        0x2E => "JDK 1.2",
        0x2F => "JDK 1.3",
        0x30 => "JDK 1.4",
        0x31 => "Java SE 5.0",
        0x32 => "Java SE 6",
        0x33 => "Java SE 7",
        0x34 => "Java SE 8",
        0x35 => "Java SE 9",
        0x36 => "Java SE 10",
        0x37 => "Java SE 11",
        0x38 => "Java SE 12",
        0x39 => "Java SE 13",
        0x3A => "Java SE 14",
        0x3B => "Java SE 15",
        0x3C => "Java SE 16",
        0x3D => "Java SE 17",
        0x3E => "Java SE 18",
        0x3F => "Java SE 19",
        0x40 => "Java SE 20",
        0x41 => "Java SE 21",
        0x42 => "Java SE 22",
        0x43 => "Java SE 23",
        0x44 => "Java SE 24",
        0x45 => "Java SE 25",
        0x46 => "Java SE 26",
        0x47 => "Java SE 27",
        0x48 => "Java SE 28",
        0x49 => "Java SE 29",
        0x4A => "Java SE 30",
        _ => "",
    };
    if !base.is_empty() && minor != 0 {
        return format!("{base}.{minor}");
    }
    base.to_string()
}

/// `JAR_Script::getManifestRecord` — first `Key: value` line of
/// META-INF/MANIFEST.MF (CRLF or LF separated).
fn manifest_record(manifest: &str, key: &str) -> String {
    for line in manifest.lines() {
        if let Some(v) = line.strip_prefix(key).and_then(|r| r.strip_prefix(':')) {
            return v.trim().to_string();
        }
    }
    String::new()
}

/// `NFD_JAR::getInfo` — JVM virtual-machine record (version = first
/// `.class` member's JDK level) and MANIFEST.MF tool detections
/// (Created-By vendor list, Build-Jdk, Apache Ant).
pub fn jar_semantic_scan(d: &[u8], misc: &mut DetectMap) {
    let members = parse::zip_members(d);
    let has_manifest = members.iter().any(|m| m.name == "META-INF/MANIFEST.MF");
    let has_module = members.iter().any(|m| m.name == "module-info.class");
    if !has_manifest && !has_module {
        return;
    }
    // `XJAR::getFileFormatInfo` — bIsVM, arch Universal, mode Data,
    // type Package; version from the first class member.
    let mut ver = String::new();
    for m in &members {
        if m.name.rsplit('.').next() != Some("class") {
            continue;
        }
        if let Some(head) = parse::zip_member_data(d, m, 0x100)
            && head.len() > 10
            && head[..4] == [0xCA, 0xFE, 0xBA, 0xBE]
        {
            let minor = u16::from_be_bytes([head[4], head[5]]);
            let major = u16::from_be_bytes([head[6], head[7]]);
            ver = jdk_version(major, minor);
            break;
        }
    }
    emit(
        misc,
        ft::FT_JAR,
        rt::RECORD_TYPE_VIRTUALMACHINE,
        n::RECORD_NAME_JVM,
        &ver,
        "Universal, Data, Package",
    );

    let Some(m) = members.iter().find(|m| m.name == "META-INF/MANIFEST.MF") else {
        return;
    };
    let Some(bytes) = parse::zip_member_data(d, m, 0x10000) else {
        return;
    };
    let manifest = String::from_utf8_lossy(&bytes);
    let created_by = manifest_record(&manifest, "Created-By");
    let ant_version = manifest_record(&manifest, "Ant-Version");
    let build_jdk = manifest_record(&manifest, "Build-Jdk");
    // sProtectedBy is read upstream but never used (dead read).
    let has = |sub: &str| created_by.contains(sub);
    if has("(Apple Inc.)") {
        emit(
            misc,
            ft::FT_JAR,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_APPLEJDK,
            "",
            "",
        );
    }
    if has("(IBM Corporation)") {
        emit(
            misc,
            ft::FT_JAR,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_IBMJDK,
            "",
            "",
        );
    }
    if has("(AdoptOpenJdk)") {
        emit(
            misc,
            ft::FT_JAR,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_OPENJDK,
            "",
            "",
        );
    }
    const VENDORS: &[&str] = &[
        "(Sun Microsystems Inc.)",
        "(BEA Systems, Inc.)",
        "(The FreeBSD Foundation)",
        "(Oracle Corporation)",
        "(Apple Inc.)",
        "(Google Inc.)",
        "(Jeroen Frijters)",
        "(IBM Corporation)",
        "(JetBrains s.r.o)",
        "(Alibaba)",
    ];
    if VENDORS.iter().any(|v| has(v)) {
        let v = created_by.split_whitespace().next().unwrap_or("");
        emit(
            misc,
            ft::FT_JAR,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_JDK,
            v,
            "",
        );
    }
    if !build_jdk.is_empty() {
        emit(
            misc,
            ft::FT_JAR,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_JDK,
            &build_jdk,
            "",
        );
    }
    if ant_version.contains("Apache Ant") {
        let v = ant_version
            .strip_prefix("Apache Ant")
            .map(|s| {
                s.trim_start_matches(|c: char| c.is_whitespace() || c == '-')
                    .to_string()
            })
            .unwrap_or_default();
        emit(
            misc,
            ft::FT_JAR,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_APACHEANT,
            &v,
            "",
        );
    }
    if has("(JetBrains s.r.o)") {
        emit(
            misc,
            ft::FT_JAR,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_JETBRAINS,
            "",
            "",
        );
    }
    if has("(Jeroen Frijters)") {
        emit(
            misc,
            ft::FT_JAR,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_IKVMDOTNET,
            "",
            "",
        );
    }
    if has("(BEA Systems, Inc.)") {
        emit(
            misc,
            ft::FT_JAR,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_BEAWEBLOGIC,
            "",
            "",
        );
    }
}

/// `NFD_Binary::handle_Texts` — source-language regex heuristics over the
/// header text: C/C++ guards and includes, HTML, Python, XML/PHP tags,
/// and the shebang interpreter record.
pub fn text_semantic_scan(d: &[u8], misc: &mut DetectMap) {
    let head = &d[..d.len().min(4096)];
    let text = String::from_utf8_lossy(&d[..d.len().min(0x40000)]);
    // C/C++ detection.
    let b_header = fancy_regex::Regex::new(r"(?m)^#ifndef\s+(\w+)[^\r\n]*\s+^#define\s+\1\b")
        .ok()
        .is_some_and(|r| r.find(&text).ok().flatten().is_some())
        || fancy_regex::Regex::new(r"#\s*pragma\s+(?:once|hdrstop)")
            .ok()
            .is_some_and(|r| r.find(&text).ok().flatten().is_some());
    let b_cpp = fancy_regex::Regex::new(r"(?m)^(?:class\b|virtual\b|public:|private:|template\b)")
        .ok()
        .is_some_and(|r| r.find(&text).ok().flatten().is_some())
        && !fancy_regex::Regex::new(r"\sdef\s")
            .ok()
            .is_some_and(|r| r.find(&text).ok().flatten().is_some());
    let mut b_csrc = b_header || b_cpp;
    if let Ok(r) = fancy_regex::Regex::new(r#"(?m)^#include\s+[\"<].*?[>\"]"#) {
        let mut cur = r.find_iter(&text);
        let mut i = 0;
        while let Some(Ok(m)) = cur.next() {
            b_csrc = true;
            // Upstream also records extension-less includes to pick the
            // "C++" display name; our record name has no sName override
            // channel, so only the C-source flag matters here.
            let _ = !m.as_str().contains('.');
            i += 1;
            if i > 4096 {
                break;
            }
        }
    }
    if !b_csrc {
        b_csrc = fancy_regex::Regex::new(r"(?m)^#define\b")
            .ok()
            .is_some_and(|r| r.find(&text).ok().flatten().is_some());
    }
    let _ = b_cpp;
    if b_csrc {
        emit(
            misc,
            ft::FT_BINARY,
            rt::RECORD_TYPE_SOURCECODE,
            n::RECORD_NAME_CCPP,
            "",
            if b_header { "header" } else { "" },
        );
    }
    if let Ok(r) = fancy_regex::Regex::new(r"(?im)^<\s*(?:!DOCTYPE\s+)?html\b[^>]*>")
        && r.find(&text).ok().flatten().is_some()
    {
        emit(
            misc,
            ft::FT_BINARY,
            rt::RECORD_TYPE_SOURCECODE,
            n::RECORD_NAME_HTML,
            "",
            "",
        );
    }
    let has = |pat: &str| {
        fancy_regex::Regex::new(pat)
            .ok()
            .is_some_and(|r| r.find(&text).ok().flatten().is_some())
    };
    if has(r"import\s") && has(r"class\s") && text.contains("self") && has(r"\sdef\s") {
        emit(
            misc,
            ft::FT_BINARY,
            rt::RECORD_TYPE_SOURCECODE,
            n::RECORD_NAME_PYTHON,
            "",
            "",
        );
    }
    if text.starts_with("<?xml") {
        let ver = fancy_regex::Regex::new(r#"version="(.*?)""#)
            .ok()
            .and_then(|r| r.captures(&text).ok().flatten())
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            .unwrap_or_default();
        emit(
            misc,
            ft::FT_BINARY,
            rt::RECORD_TYPE_SOURCECODE,
            n::RECORD_NAME_XML,
            &ver,
            "",
        );
    }
    if text.starts_with("<?php") {
        emit(
            misc,
            ft::FT_BINARY,
            rt::RECORD_TYPE_SOURCECODE,
            n::RECORD_NAME_PHP,
            "",
            "",
        );
    }
    let _ = head;
    // Shebang interpreter on the first line.
    let first = text.lines().next().unwrap_or("").trim();
    if let Some(cap) = fancy_regex::Regex::new(r"^#!\s*(?:.*/)?(?:env\s+)?([^\s]+)")
        .ok()
        .and_then(|r| r.captures(first).ok().flatten())
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
    {
        let mut interp = cap.as_str();
        if interp.to_ascii_lowercase().ends_with(".exe") {
            interp = &interp[..interp.len() - 4];
        }
        let name = if interp.eq_ignore_ascii_case("sh") {
            "Shell".to_string()
        } else if !interp.is_empty() {
            let mut s = interp.to_lowercase();
            if let Some(c) = s.get_mut(0..1) {
                c.make_ascii_uppercase();
            }
            s
        } else {
            String::new()
        };
        if !name.is_empty() {
            emit(
                misc,
                ft::FT_BINARY,
                rt::RECORD_TYPE_SOURCECODE,
                n::RECORD_NAME_SHELL,
                "",
                &name,
            );
        }
    }
}

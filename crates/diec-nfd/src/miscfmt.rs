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
use crate::scans::{DetectMap, EmitTarget, ResultMaps, ScanRecord};
use crate::{gen_names::ft, gen_names::name as n, gen_names::rtype as rt};

fn emit(map: &mut impl EmitTarget, ft_id: u16, rtype: u8, name: u16, ver: &str, info: &str) {
    crate::scans::push(map, ft_id, rtype, name, ver, info, None, None);
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

/// `NFD_COM::handle_Protection` — `addHeaderDetectToResults` transfers:
/// header detections move into the matching result map.
/// Columns: record name, destination (`0`=packers `1`=protectors
/// `2`=tools `3`=sfx).
const COM_TRANSFERS: &[(u16, u8)] = &[
    (n::RECORD_NAME_PKLITE, 0),
    (n::RECORD_NAME_UPX, 0),
    (n::RECORD_NAME_HACKSTOP, 1),
    (n::RECORD_NAME_CRYPTDISMEMBER, 1),
    (n::RECORD_NAME_SPIRIT, 1),
    (n::RECORD_NAME_ICE, 0),
    (n::RECORD_NAME_DIET, 0),
    (n::RECORD_NAME_624, 0),
    (n::RECORD_NAME_LGLZ, 0),
    (n::RECORD_NAME_PACK, 0),
    (n::RECORD_NAME_SCRNCH, 0),
    (n::RECORD_NAME_XPACK, 0),
    (n::RECORD_NAME_PCOM, 1),
    (n::RECORD_NAME_BESTPROTECTIONKIT, 1),
    (n::RECORD_NAME_DIGPAK, 2),
    (n::RECORD_NAME_MIDPAK, 2),
    (n::RECORD_NAME_GPATCH, 2),
    (n::RECORD_NAME_WOLVERINEPATCHER, 2),
    (n::RECORD_NAME_PKZIPMINISFX, 3),
    (n::RECORD_NAME_CRYPTORBYEVILGENIUS, 1),
    (n::RECORD_NAME_EXE2COM, 2),
    (n::RECORD_NAME_MASK, 1),
    (n::RECORD_NAME_EXECOMCONVERTERS, 2),
];

/// CP/M compiler names — each present header record moves into
/// `mapResultCompilers` (upstream `handle_Protection` tail).
const COM_COMPILER_NAMES: &[u16] = &[
    n::RECORD_NAME_ARNORBCPL,
    n::RECORD_NAME_AZTECC80,
    n::RECORD_NAME_BDSC,
    n::RECORD_NAME_CB80,
    n::RECORD_NAME_CBASIC,
    n::RECORD_NAME_CLIVEPARTRIDGEBCPL,
    n::RECORD_NAME_DIGITALRESEARCHMTPASCAL,
    n::RECORD_NAME_DIGITALRESEARCHPLI80,
    n::RECORD_NAME_DRACO,
    n::RECORD_NAME_FTLMODULA2,
    n::RECORD_NAME_HISOFTPASCAL,
    n::RECORD_NAME_HITECHC,
    n::RECORD_NAME_HOCHSTRASSERMODULA2,
    n::RECORD_NAME_INTERSYSTEMSPASCALZ,
    n::RECORD_NAME_JANUSADA,
    n::RECORD_NAME_MIC,
    n::RECORD_NAME_MICROSOFTBASIC,
    n::RECORD_NAME_MICROSOFTCOBOL,
    n::RECORD_NAME_MICROSOFTFORTRAN,
    n::RECORD_NAME_MIXC,
    n::RECORD_NAME_NEVADAFORTRAN,
    n::RECORD_NAME_OXFORDPASCAL,
    n::RECORD_NAME_PLMX,
    n::RECORD_NAME_PROPASCAL,
    n::RECORD_NAME_QCCOMPILER,
    n::RECORD_NAME_SBASIC,
    n::RECORD_NAME_SMALLC,
    n::RECORD_NAME_SOFTWARETOOLWORKSC80,
    n::RECORD_NAME_SUPERSOFTADA,
    n::RECORD_NAME_SUPERSOFTC,
    n::RECORD_NAME_SUPERSOFTFORTRAN,
    n::RECORD_NAME_TCLPASCAL,
    n::RECORD_NAME_VANVALZAHPASCAL,
    n::RECORD_NAME_WHITESMITHSC,
    n::RECORD_NAME_Z80BCPL,
];

/// `NFD_COM::getInfo` tail — verbose `handle_OperationSystem` (always
/// emitted in verbose mode), `handle_Protection` header->result
/// transfers, then the conditional OS re-emit when a protection record
/// was promoted.
pub fn com_semantic_scan(d: &[u8], verbose: bool, header: &DetectMap, misc: &mut ResultMaps) {
    let emit_os = |misc: &mut ResultMaps| {
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
    };
    if verbose {
        emit_os(misc);
    }
    for &(name, dest) in COM_TRANSFERS {
        if let Some(ss) = header.get(&name) {
            let map = match dest {
                0 => &mut misc.packers,
                1 => &mut misc.protectors,
                2 => &mut misc.tools,
                _ => &mut misc.sfx,
            };
            map.insert(ss.name, ss.clone());
        }
    }
    for &name in COM_COMPILER_NAMES {
        if let Some(ss) = header.get(&name) {
            misc.compilers.insert(ss.name, ss.clone());
        }
    }
    if !misc.protectors.is_empty() || !misc.packers.is_empty() || !misc.tools.is_empty() {
        emit_os(misc);
    }
}

/// `NFD_Amiga::getInfo` — `detectOperationSystem` on the hunk header:
/// arch `68K` (`PPC` when a `HUNK_PPC_CODE` hunk is present), mode `16-bit`
/// (`32-bit` with `HUNK_RELOC32`), type `EXE` for `HUNK_HEADER` and `Object`
/// for `HUNK_UNIT`.
pub fn amiga_semantic_scan(d: &[u8], misc: &mut ResultMaps) {
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

/// `NFD_CFBF::getInfo` — a single `ssFormat` built from
/// `XCFBF::getFileFormatInfo` (`Microsoft Compound`, version
/// `{u16@0x1A}.{u16@0x18}`) is rewritten in place by the subtype check at
/// 0x200/0x1000 and inserted once into `mapResultFormats`; the deep-scan
/// `AI_PACKAGING_TOOL` marker adds an Advanced Installer record.
pub fn cfbf_semantic_scan(d: &[u8], deep: bool, misc: &mut ResultMaps) {
    let dll = parse::rd_u16(d, 0x1A).unwrap_or(0);
    let minor = parse::rd_u16(d, 0x18).unwrap_or(0);
    let mut rtype = rt::RECORD_TYPE_FORMAT;
    let mut name = n::RECORD_NAME_MICROSOFTCOMPOUND;
    let mut ver = format!("{dll}.{minor}");
    let sub1 = parse::rd_u16(d, 0x200).unwrap_or(0);
    let sub2 = parse::rd_u16(d, 0x1000).unwrap_or(0);
    if sub1 == 0 && sub2 == 0xFFFD {
        rtype = rt::RECORD_TYPE_INSTALLER;
        name = n::RECORD_NAME_MICROSOFTINSTALLER;
        ver.clear();
    } else if sub1 == 0xA5EC {
        name = n::RECORD_NAME_MICROSOFTOFFICEWORD;
        ver = "97-2003".to_string();
    }
    // Upstream inserts into `mapResultFormats` even when the subtype
    // record is typed INSTALLER; write the formats map directly.
    misc.formats.insert(
        name,
        ScanRecord {
            name,
            rtype,
            ft: ft::FT_CFBF,
            variant: 0,
            version: ver,
            info: String::new(),
            heuristic: false,
            unknown: false,
            sname: None,
            stype: None,
        },
    );
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
pub fn pdf_semantic_scan(d: &[u8], misc: &mut ResultMaps) {
    // `getFormatScansStruct(pdf.getFileFormatInfo())` — "%PDF-" may sit
    // anywhere in the first 1024 bytes; version is the 3 chars after it.
    let hdr = parse::find_ansi(d, 0, d.len().min(1024), b"%PDF-");
    let ver = hdr
        .and_then(|p| d.get(p + 5..p + 8))
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default();
    let enc = pdf_encrypt_info(d);
    emit(
        misc,
        ft::FT_PDF,
        rt::RECORD_TYPE_FORMAT,
        n::RECORD_NAME_PDF,
        &ver,
        if enc.is_some() { "Encrypted" } else { "" },
    );
    if let Some(enc) = enc {
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
pub fn jar_semantic_scan(d: &[u8], misc: &mut ResultMaps) {
    let members = parse::zip_members(d);
    // `NFD_JAR::getInfo` — the operation-system record comes from the
    // plain `XZip` FFI (arch `NOEXEC`, mode `Data`, type `Archive`);
    // the OS name stays `Unknown`.
    emit(
        misc,
        ft::FT_JAR,
        rt::RECORD_TYPE_OPERATIONSYSTEM,
        n::RECORD_NAME_UNKNOWN,
        "",
        "NOEXEC, Data, Archive",
    );

    let Some(m) = members.iter().find(|m| m.name == "META-INF/MANIFEST.MF") else {
        jar_tail(d, misc);
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
    jar_tail(d, misc);
}

/// `NFD_JAR::getInfo` tail — `NFD_ZIP::handle_Container` emits the ZIP
/// archive record when not in all-types mode (the caller never sets it
/// on this path).
fn jar_tail(d: &[u8], misc: &mut ResultMaps) {
    if let Some(records) = crate::promote::zip_records(d) {
        crate::promote::zip_container(&records, misc);
    }
}

/// `XBinary::isStringInListPresentExp` — true when any list element
/// matches the regex.
fn str_in_list_exp(list: &[String], pat: &str) -> bool {
    let Ok(re) = fancy_regex::Regex::new(pat) else {
        return false;
    };
    list.iter().any(|s| re.find(s).ok().flatten().is_some())
}

/// DEX `TYPE_*_ITEM` constants (`XDEX_DEF`) — the toolchain map lists
/// from `NFD_DEX::handle_Tools`.
mod dex_ty {
    pub const HEADER: u16 = 0x0000;
    pub const STRING_ID: u16 = 0x0001;
    pub const TYPE_ID: u16 = 0x0002;
    pub const PROTO_ID: u16 = 0x0003;
    pub const FIELD_ID: u16 = 0x0004;
    pub const METHOD_ID: u16 = 0x0005;
    pub const CLASS_DEF: u16 = 0x0006;
    pub const CALL_SITE_ID: u16 = 0x0007;
    pub const METHOD_HANDLE: u16 = 0x0008;
    pub const MAP_LIST: u16 = 0x1000;
    pub const TYPE_LIST: u16 = 0x1001;
    pub const ANNOTATION_SET_REF: u16 = 0x1002;
    pub const ANNOTATION_SET: u16 = 0x1003;
    pub const CLASS_DATA: u16 = 0x2000;
    pub const CODE: u16 = 0x2001;
    pub const STRING_DATA: u16 = 0x2002;
    pub const DEBUG_INFO: u16 = 0x2003;
    pub const ANNOTATION: u16 = 0x2004;
    pub const ENCODED_ARRAY: u16 = 0x2005;
    pub const ANNOTATIONS_DIRECTORY: u16 = 0x2006;
    pub const HIDDENAPI_CLASS_DATA: u16 = 0xF000;
}

/// `NFD_Binary::get_R8_marker_vi` — `(version, info)` from an R8/D8
/// marker JSON comment.
fn r8_marker_vi(d: &[u8]) -> Option<(String, String)> {
    let off = parse::find_ansi(d, 0, d.len(), b"\"compilation-mode\":\"")?;
    if off <= 20 {
        return None;
    }
    let marker_off = parse::find_ansi(d, off - 21, 20, b"~~")?;
    let s = parse::read_ansi_string(d, marker_off)?;
    let ver = crate::scans::reg_exp(r#""version":"(.*?)""#, &s, 1);
    let info = if s.contains("~~D8") || s.contains("~~R8") {
        crate::scans::reg_exp(r#""compilation-mode":"(.*?)""#, &s, 1)
    } else {
        format!("CHECK D8: {s}")
    };
    Some((ver, info))
}

/// `NFD_DEX::getInfo` — `handle_Tools` + `handle_Protection` +
/// `handle_Dexguard`: Android SDK tool, Android OS record, the map-item
/// compiler classifier, and the string/type-detect protector transfers.
#[allow(clippy::too_many_arguments)]
pub fn dex_semantic_scan(
    d: &[u8],
    deep: bool,
    heuristic: bool,
    strings: &[String],
    types: &[String],
    strings_m: &DetectMap,
    types_m: &DetectMap,
    misc: &mut ResultMaps,
) {
    if !parse::dex_is_valid(d) {
        return;
    }
    use dex_ty as ty;
    let version = parse::dex_version(d).unwrap_or_default();
    let map_items = parse::dex_map_item_types(d);
    let sorted = parse::dex_string_pool_sorted(d);
    let overlay_size = parse::dex_overlay_size(d);

    // Android SDK tool record: dex version -> API level.
    let api = match version.as_str() {
        "035" => Some(14),
        "037" => Some(24),
        "038" => Some(26),
        "039" => Some(28),
        "040" => Some(29),
        _ => None,
    };
    let sdk_ver = api
        .map(|a| format!("API {a}"))
        .unwrap_or_else(|| version.clone());
    emit(
        misc,
        ft::FT_DEX,
        rt::RECORD_TYPE_TOOL,
        n::RECORD_NAME_ANDROIDSDK,
        &sdk_ver,
        "",
    );
    // OS record via `getFileFormatInfo`: Android, arch Dalvik,
    // mode 32-bit, type "Main module"; version is the dex-version ->
    // Android API mapping (raw version when unmapped).
    let os_ver = api
        .map(|a| parse::android_version_from_api(a).to_string())
        .filter(|s| s != "Unknown")
        .unwrap_or_else(|| version.clone());
    emit(
        misc,
        ft::FT_DEX,
        rt::RECORD_TYPE_OPERATIONSYSTEM,
        n::RECORD_NAME_ANDROID,
        &os_ver,
        "Dalvik, 32-bit, Main module",
    );

    let list_dx: &[u16] = &[
        ty::HEADER,
        ty::STRING_ID,
        ty::TYPE_ID,
        ty::PROTO_ID,
        ty::FIELD_ID,
        ty::METHOD_ID,
        ty::CLASS_DEF,
        ty::CALL_SITE_ID,
        ty::METHOD_HANDLE,
        ty::ANNOTATION_SET_REF,
        ty::ANNOTATION_SET,
        ty::CODE,
        ty::ANNOTATIONS_DIRECTORY,
        ty::TYPE_LIST,
        ty::STRING_DATA,
        ty::DEBUG_INFO,
        ty::ANNOTATION,
        ty::ENCODED_ARRAY,
        ty::CLASS_DATA,
        ty::MAP_LIST,
    ];
    let list_dexlib2: &[u16] = &[
        ty::HEADER,
        ty::STRING_ID,
        ty::TYPE_ID,
        ty::PROTO_ID,
        ty::FIELD_ID,
        ty::METHOD_ID,
        ty::CLASS_DEF,
        ty::CALL_SITE_ID,
        ty::METHOD_HANDLE,
        ty::ANNOTATION_SET_REF,
        ty::ANNOTATION_SET,
        ty::CODE,
        ty::ANNOTATIONS_DIRECTORY,
        ty::TYPE_LIST,
        ty::STRING_DATA,
        ty::DEBUG_INFO,
        ty::ANNOTATION,
        ty::ENCODED_ARRAY,
        ty::CLASS_DATA,
        ty::HIDDENAPI_CLASS_DATA,
        ty::MAP_LIST,
    ];
    let list_dexlib2heur: &[u16] = &[
        ty::HEADER,
        ty::STRING_ID,
        ty::TYPE_ID,
        ty::PROTO_ID,
        ty::FIELD_ID,
        ty::METHOD_ID,
        ty::CLASS_DEF,
        ty::STRING_DATA,
    ];
    let list_r8 = list_dx;
    let list_dexmerge: &[u16] = &[
        ty::HEADER,
        ty::STRING_ID,
        ty::TYPE_ID,
        ty::PROTO_ID,
        ty::CLASS_DEF,
        ty::MAP_LIST,
        ty::TYPE_LIST,
        ty::ANNOTATION_SET_REF,
        ty::ANNOTATION_SET,
        ty::DEBUG_INFO,
        ty::ANNOTATION,
        ty::ANNOTATIONS_DIRECTORY,
    ];
    let list_fastproxy: &[u16] = &[
        ty::HEADER,
        ty::STRING_ID,
        ty::TYPE_ID,
        ty::PROTO_ID,
        ty::FIELD_ID,
        ty::METHOD_ID,
        ty::CLASS_DEF,
        ty::STRING_DATA,
        ty::MAP_LIST,
    ];

    let vi_r8 = r8_marker_vi(d);
    let b_r8 = parse::dex_compare_map_items(&map_items, list_r8);
    let b_dx = parse::dex_compare_map_items(&map_items, list_dx);
    let b_dexlib2 = parse::dex_compare_map_items(&map_items, list_dexlib2);
    let b_dexlib2heur = parse::dex_compare_map_items(&map_items, list_dexlib2heur);
    let b_dexmerge = parse::dex_compare_map_items(&map_items, list_dexmerge);
    let b_fastproxy = parse::dex_compare_map_items(&map_items, list_fastproxy);

    let add_compiler = |misc: &mut ResultMaps, name: u16, ver: &str, info: &str| {
        emit(misc, ft::FT_DEX, rt::RECORD_TYPE_COMPILER, name, ver, info);
    };

    if let Some((ver, info)) = &vi_r8 {
        add_compiler(misc, n::RECORD_NAME_R8, ver, info);
    } else if !sorted {
        add_compiler(misc, n::RECORD_NAME_DEXLIB, "", "");
    } else if b_dx {
        add_compiler(misc, n::RECORD_NAME_DX, "", "");
    } else if b_dexlib2 {
        add_compiler(misc, n::RECORD_NAME_DEXLIB2, "", "");
    } else if b_r8 {
        add_compiler(misc, n::RECORD_NAME_R8, "", "");
    } else if b_dexlib2heur {
        add_compiler(misc, n::RECORD_NAME_DEXLIB2, "", "");
    } else if b_fastproxy {
        add_compiler(misc, n::RECORD_NAME_FASTPROXY, "", "");
    }
    if b_dexmerge {
        add_compiler(misc, n::RECORD_NAME_DEXMERGE, "", "");
    }
    if vi_r8.is_some()
        && !b_r8
        && let Some((ver, info)) = &vi_r8
    {
        let info = if info.is_empty() {
            "CHECK !!!".to_string()
        } else {
            crate::promote::append_comma(info, "CHECK !!!")
        };
        add_compiler(misc, n::RECORD_NAME_R8, ver, &info);
    }
    if deep {
        // `^emitter: jack` string -> JACK compiler, version after '-'.
        if let Some(s) = strings.iter().find(|s| {
            fancy_regex::Regex::new("^emitter: jack")
                .map(|re| re.find(s).ok().flatten().is_some())
                .unwrap_or(false)
        }) {
            let ver = s.split('-').skip(1).collect::<Vec<_>>().join("-");
            add_compiler(misc, n::RECORD_NAME_JACK, &ver, "");
        }
    }
    if misc.compilers.is_empty() {
        add_compiler(
            misc,
            n::RECORD_NAME_UNKNOWN,
            &parse::dex_map_items_hash(&map_items),
            "",
        );
    }
    // metainfo transfers: APKTOOLPLUS type -> tools, UNICOMSDK -> libs.
    if let Some(ss) = types_m.get(&n::RECORD_NAME_APKTOOLPLUS) {
        misc.tools.insert(ss.name, ss.clone());
    }
    if let Some(ss) = types_m.get(&n::RECORD_NAME_UNICOMSDK) {
        misc.libraries.insert(ss.name, ss.clone());
    }

    // `handle_Protection`.
    let add_protector = |misc: &mut ResultMaps, name: u16| {
        emit(misc, ft::FT_DEX, rt::RECORD_TYPE_PROTECTOR, name, "", "");
    };
    if overlay_size == 0x60 || (deep && str_in_list_exp(types, r"\/dexprotector\/")) {
        add_protector(misc, n::RECORD_NAME_DEXPROTECTOR);
    }
    for &name in &[
        n::RECORD_NAME_EASYPROTECTOR,
        n::RECORD_NAME_QDBH,
        n::RECORD_NAME_JIAGU,
        n::RECORD_NAME_BANGCLEPROTECTION,
        n::RECORD_NAME_ALLATORIOBFUSCATOR,
        n::RECORD_NAME_PANGXIE,
        n::RECORD_NAME_NAGAPTPROTECTION,
        n::RECORD_NAME_MODGUARD,
        n::RECORD_NAME_KIWIVERSIONOBFUSCATOR,
    ] {
        if let Some(ss) = strings_m.get(&name) {
            misc.protectors.insert(ss.name, ss.clone());
        }
    }
    if let Some(ss) = strings_m.get(&n::RECORD_NAME_APKPROTECT) {
        misc.protectors.insert(ss.name, ss.clone());
    } else if deep && str_in_list_exp(strings, "http://www\\.apkprotect\\.net/") {
        add_protector(misc, n::RECORD_NAME_APKPROTECT);
    }
    if heuristic {
        if let Some(ss) = strings_m.get(&n::RECORD_NAME_AESOBFUSCATOR) {
            misc.protectors.insert(ss.name, ss.clone());
        } else if deep && str_in_list_exp(strings, "licensing/AESObfuscator;") {
            add_protector(misc, n::RECORD_NAME_AESOBFUSCATOR);
        }
    }
    for &name in &[
        n::RECORD_NAME_BTWORKSCODEGUARD,
        n::RECORD_NAME_QIHOO360PROTECTION,
        n::RECORD_NAME_ALIBABAPROTECTION,
        n::RECORD_NAME_BAIDUPROTECTION,
        n::RECORD_NAME_TENCENTPROTECTION,
        n::RECORD_NAME_SECNEO,
        n::RECORD_NAME_LIAPP,
        n::RECORD_NAME_VDOG,
        n::RECORD_NAME_APPSOLID,
        n::RECORD_NAME_MEDUSAH,
        n::RECORD_NAME_NQSHIELD,
        n::RECORD_NAME_YIDUN,
        n::RECORD_NAME_APKENCRYPTOR,
    ] {
        if let Some(ss) = types_m.get(&name) {
            misc.protectors.insert(ss.name, ss.clone());
        }
    }
    if let Some(ss) = types_m.get(&n::RECORD_NAME_PROGUARD) {
        misc.protectors.insert(ss.name, ss.clone());
    } else if deep && str_in_list_exp(types, "\\/proguard\\/") {
        add_protector(misc, n::RECORD_NAME_PROGUARD);
    }

    // `handle_Dexguard`.
    if deep && str_in_list_exp(types, "dexguard\\/") {
        add_protector(misc, n::RECORD_NAME_DEXGUARD);
    }
}

/// `NFD_APK::getInfo` — `APK_handle` + `APK_handle_FixDetects` plus the
/// `NFD_ZIP::handle_Container` leg.
///
/// `XAPK::isValid(records)` requires an `AndroidManifest.xml` member with
/// non-zero uncompressed size; the *decompressed* manifest gates every
/// archive/metainfo transfer (upstream checks raw bytes, so a stored
/// plain-text manifest opens the gate while its regexes simply miss).
///
/// `archive` is `mapArchiveDetects` (member-name scans); `metainfos` is
/// `mapMetainfosDetects`, only populated by the JAR manifest block in
/// this upstream pin — callers pass an empty map for APK.
#[allow(clippy::too_many_arguments)]
pub fn apk_semantic_scan(
    d: &[u8],
    members: &[parse::ZipMember],
    archive: &DetectMap,
    metainfos: &DetectMap,
    dex_protectors: &DetectMap,
    verbose: bool,
    all_types: bool,
    misc: &mut ResultMaps,
) {
    // XZip::isValid — a parseable central directory.
    if members.is_empty() {
        return;
    }
    // XAPK::isValid(records): AndroidManifest.xml with size > 0.
    let Some(manifest_member) = members
        .iter()
        .find(|m| m.name == "AndroidManifest.xml" && m.unc_size > 0)
    else {
        return;
    };
    let manifest_raw =
        parse::zip_member_data(d, manifest_member, 4 * 1024 * 1024).unwrap_or_default();

    // `getOperationSystemScansStruct(XAPK::getFileFormatInfo)` — arch
    // Universal, mode Data, type Package; version from the decoded
    // manifest's sdk-version attributes.
    let manifest_text = crate::axml::decode_axml(&manifest_raw);
    let num_ok = |s: &str, lo: u32, hi: u32| -> bool {
        s.parse::<u32>().is_ok_and(|v| (lo..=hi).contains(&v))
    };
    let mut os_version = String::new();
    if !manifest_raw.is_empty() {
        let get = |key: &str| -> String {
            crate::scans::reg_exp(&format!("{key}=\"(.*?)\""), &manifest_text, 1)
        };
        let compile = get("android:compileSdkVersion");
        let codename = get("android:compileSdkVersionCodename");
        let plat_code = get("platformBuildVersionCode");
        let plat_name = get("platformBuildVersionName");
        let target = get("android:targetSdkVersion");
        let min = get("android:minSdkVersion");
        let compile = if num_ok(&compile, 1, 40) {
            compile
        } else {
            String::new()
        };
        let target = if num_ok(&target, 1, 40) {
            target
        } else {
            String::new()
        };
        let min = if num_ok(&min, 1, 40) {
            min
        } else {
            String::new()
        };
        let plat_code = if num_ok(&plat_code, 1, 40) {
            plat_code
        } else {
            String::new()
        };
        let first = |s: &str| s.split('.').next().unwrap_or("").to_string();
        let codename = if num_ok(&first(&codename), 1, 15) {
            codename
        } else {
            String::new()
        };
        let plat_name = if num_ok(&first(&plat_name), 1, 15) {
            plat_name
        } else {
            String::new()
        };
        // `XAPK::getFileFormatInfo` sOsVersion chain.
        let mut v = String::new();
        if v.is_empty() {
            v = target.clone();
        }
        if v.is_empty() {
            v = min.clone();
        }
        if v.is_empty() {
            v = compile.clone();
        }
        if v.is_empty() {
            v = plat_code;
        }
        let mut av = String::new();
        if av.is_empty() {
            av = codename;
        }
        if av.is_empty() {
            av = plat_name;
        }
        if av.is_empty() {
            av = parse::android_version_from_api(v.parse().unwrap_or(0)).to_string();
        }
        if !v.is_empty() {
            os_version = av;
        }
    }
    emit(
        misc,
        ft::FT_APK,
        rt::RECORD_TYPE_OPERATIONSYSTEM,
        n::RECORD_NAME_ANDROID,
        &os_version,
        "Universal, Data, Package",
    );

    // APK Signature Scheme blocks.
    let ids = parse::apk_sig_block_ids(d);
    if ids.contains(&0x7109_871A) {
        emit(
            misc,
            ft::FT_APK,
            rt::RECORD_TYPE_SIGNTOOL,
            n::RECORD_NAME_APKSIGNATURESCHEME,
            "v2",
            "",
        );
    } else if ids.contains(&0xF053_68C0) {
        emit(
            misc,
            ft::FT_APK,
            rt::RECORD_TYPE_SIGNTOOL,
            n::RECORD_NAME_APKSIGNATURESCHEME,
            "v3",
            "",
        );
    }
    if ids.contains(&0x7177_7777) {
        emit(
            misc,
            ft::FT_APK,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_WALLE,
            "",
            "",
        );
    }
    if ids.contains(&0x2146_444E) {
        emit(
            misc,
            ft::FT_APK,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_GOOGLEPLAY,
            "",
            "",
        );
    }
    // Kotlin iff the KTX/builtins markers are present, else Java.
    let kotlin = members.iter().any(|m| {
        m.name == "META-INF/androidx.core_core-ktx.version"
            || m.name == "kotlin/kotlin.kotlin_builtins"
    });
    emit(
        misc,
        ft::FT_APK,
        rt::RECORD_TYPE_LANGUAGE,
        if kotlin {
            n::RECORD_NAME_KOTLIN
        } else {
            n::RECORD_NAME_JAVA
        },
        "",
        "",
    );

    if verbose {
        // Verbose UNKNOWN0+i signtool records for unrecognized block ids.
        for (i, id) in ids.iter().enumerate() {
            if *id > 0xFFFF && *id != 0x7109_871A && *id != 0xF053_68C0 && *id != 0x4272_6577 {
                emit(
                    misc,
                    ft::FT_APK,
                    rt::RECORD_TYPE_SIGNTOOL,
                    n::RECORD_NAME_UNKNOWN0 + i as u16,
                    &format!("{id:x}"),
                    "",
                );
            }
        }
    }

    if manifest_raw.is_empty() {
        // Transfers below are gated on `baAndroidManifest.size() > 0`.
        if !all_types {
            crate::promote::zip_container_members(members, misc);
        }
        return;
    }

    // `AndroidManifest.xml` decoded — SDK version attributes -> tool.
    if !os_version.is_empty() || !manifest_text.is_empty() {
        let get = |key: &str| -> String {
            crate::scans::reg_exp(&format!("{key}=\"(.*?)\""), &manifest_text, 1)
        };
        let compile = get("android:compileSdkVersion");
        let target = get("android:targetSdkVersion");
        let min = get("android:minSdkVersion");
        let mut api = String::new();
        if num_ok(&compile, 1, 40) {
            api = compile;
        }
        if api.is_empty() && num_ok(&min, 1, 40) {
            api = min;
        }
        if api.is_empty() && num_ok(&target, 1, 40) {
            api = target;
        }
        if !api.is_empty() {
            emit(
                misc,
                ft::FT_APK,
                rt::RECORD_TYPE_TOOL,
                n::RECORD_NAME_ANDROIDSDK,
                &format!("API {api}"),
                "",
            );
        }
    }

    // Jetpack library version member.
    if let Some(jet) = members
        .iter()
        .find(|m| m.name == "META-INF/androidx.core_core.version")
        && let Some(b) = parse::zip_member_data(d, jet, 1024)
        && !b.is_empty()
    {
        let s = String::from_utf8_lossy(&b);
        let ver = s.lines().next().unwrap_or("").trim_end_matches('\r');
        emit(
            misc,
            ft::FT_APK,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_ANDROIDJETPACK,
            ver,
            "",
        );
    }

    // Metainfo transfers (map is empty in this upstream pin — kept for
    // parity once `handle_Metainfos` lands).
    for name in [n::RECORD_NAME_TINYSIGN, n::RECORD_NAME_COMEXSIGNAPK] {
        if let Some(ss) = metainfos.get(&name) {
            misc.signtools.insert(ss.name, ss.clone());
        }
    }
    for name in [
        n::RECORD_NAME_ECLIPSE,
        n::RECORD_NAME_HIAPKCOM,
        n::RECORD_NAME_ANDROIDGRADLE,
        n::RECORD_NAME_ANDROIDMAVENPLUGIN,
        n::RECORD_NAME_RADIALIX,
        n::RECORD_NAME_MOTODEVSTUDIOFORANDROID,
        n::RECORD_NAME_ANTILVL,
        n::RECORD_NAME_APKEDITOR,
        n::RECORD_NAME_BUNDLETOOL,
        n::RECORD_NAME_DEX2JAR,
        n::RECORD_NAME_D2JAPKSIGN,
        n::RECORD_NAME_PSEUDOAPKSIGNER,
    ] {
        if let Some(ss) = metainfos.get(&name) {
            misc.tools.insert(ss.name, ss.clone());
        }
    }
    if let Some(ss) = metainfos.get(&n::RECORD_NAME_DX) {
        misc.compilers.insert(ss.name, ss.clone());
    }

    // `mapArchiveDetects` -> `mapResultAPKProtectors` allowlist.
    for name in [
        n::RECORD_NAME_SECSHELL,
        n::RECORD_NAME_JIAGU,
        n::RECORD_NAME_IJIAMI,
        n::RECORD_NAME_TENCENTPROTECTION,
        n::RECORD_NAME_APPGUARD,
        n::RECORD_NAME_KIRO,
        n::RECORD_NAME_DXSHIELD,
        n::RECORD_NAME_QDBH,
        n::RECORD_NAME_BANGCLEPROTECTION,
        n::RECORD_NAME_QIHOO360PROTECTION,
        n::RECORD_NAME_ALIBABAPROTECTION,
        n::RECORD_NAME_BAIDUPROTECTION,
        n::RECORD_NAME_NQSHIELD,
        n::RECORD_NAME_NAGAPTPROTECTION,
        n::RECORD_NAME_SECNEO,
        n::RECORD_NAME_LIAPP,
        n::RECORD_NAME_YIDUN,
        n::RECORD_NAME_PANGXIE,
        n::RECORD_NAME_HDUS_WJUS,
        n::RECORD_NAME_MEDUSAH,
        n::RECORD_NAME_APPSOLID,
        n::RECORD_NAME_PROGUARD,
        n::RECORD_NAME_APKPROTECT,
        n::RECORD_NAME_OLLVMTLL,
    ] {
        if let Some(ss) = archive.get(&name) {
            misc.apk_protectors.insert(ss.name, ss.clone());
        }
    }
    // TencentLegu / Mobile-Tencent-Protect — version from libshella-*.
    if archive.contains_key(&n::RECORD_NAME_TENCENTLEGU)
        || archive.contains_key(&n::RECORD_NAME_MOBILETENCENTPROTECT)
    {
        let mut ss = archive
            .get(&n::RECORD_NAME_TENCENTLEGU)
            .or_else(|| archive.get(&n::RECORD_NAME_MOBILETENCENTPROTECT))
            .cloned()
            .unwrap_or_else(|| {
                ScanRecord::from_basic(&crate::records::BasicRecord {
                    variant: 0,
                    ft: ft::FT_APK,
                    rtype: rt::RECORD_TYPE_PROTECTOR,
                    name: n::RECORD_NAME_TENCENTLEGU,
                    version: "",
                    info: "",
                })
            });
        for m in members {
            for prefix in [
                "lib/arm64-v8a/libshella-",
                "lib/armeabi-v7a/libshella-",
                "lib/armeabi/libshella-",
                "lib/x86/libshella-",
            ] {
                if m.name.contains(prefix) {
                    ss.version = crate::scans::reg_exp(&format!("{prefix}(.*?).so"), &m.name, 1);
                    break;
                }
            }
        }
        misc.apk_protectors.insert(ss.name, ss);
    }
    // VDog — version from the `assets/version` member.
    if let Some(ss) = archive.get(&n::RECORD_NAME_VDOG).cloned() {
        let mut ss = ss;
        if let Some(v) = members
            .iter()
            .find(|m| m.name == "assets/version")
            .and_then(|m| parse::zip_member_data(d, m, 4096))
        {
            let s = String::from_utf8_lossy(&v);
            if let Some(tail) = s.split("VDOG-").nth(1) {
                ss.version = tail.split('_').next().unwrap_or("").to_string();
            }
        }
        misc.apk_protectors.insert(ss.name, ss);
    }
    // DexGuard — metainfos or the classes.dex sub-scan protectors.
    if metainfos.contains_key(&n::RECORD_NAME_DEXGUARD)
        || dex_protectors.contains_key(&n::RECORD_NAME_DEXGUARD)
    {
        let mut ss = ScanRecord::from_basic(&crate::records::BasicRecord {
            variant: 0,
            ft: ft::FT_APK,
            rtype: rt::RECORD_TYPE_PROTECTOR,
            name: n::RECORD_NAME_DEXGUARD,
            version: "",
            info: "",
        });
        if let Some(m) = metainfos.get(&n::RECORD_NAME_DEXGUARD) {
            ss.version.clone_from(&m.version);
        } else if let Some(m) = metainfos.get(&n::RECORD_NAME_GENERIC) {
            ss.version.clone_from(&m.version);
        }
        misc.apk_protectors.insert(ss.name, ss);
    }
    // DexProtector / ApkProtector — metainfos preferred, else archive.
    for name in [n::RECORD_NAME_DEXPROTECTOR, n::RECORD_NAME_APKPROTECTOR] {
        let ss = metainfos.get(&name).or_else(|| archive.get(&name));
        if let Some(ss) = ss {
            misc.apk_protectors.insert(ss.name, ss.clone());
        }
    }
    // Archive -> libraries allowlist.
    for name in [
        n::RECORD_NAME_SANDHOOK,
        n::RECORD_NAME_UNICOMSDK,
        n::RECORD_NAME_UNITY,
        n::RECORD_NAME_IL2CPP,
        n::RECORD_NAME_BASIC4ANDROID,
        n::RECORD_NAME_QML,
    ] {
        if let Some(ss) = archive.get(&name) {
            misc.libraries.insert(ss.name, ss.clone());
        }
    }
    if let Some(ss) = archive.get(&n::RECORD_NAME_APKTOOLPLUS) {
        misc.tools.insert(ss.name, ss.clone());
    }

    // `APK_handle_FixDetects` — verbose MANIFEST.MF protector probes
    // (only when `mapMetainfosDetects` stayed empty).
    if verbose && metainfos.is_empty() {
        let mf_text = members
            .iter()
            .find(|m| m.name == "META-INF/MANIFEST.MF")
            .and_then(|m| parse::zip_member_data(d, m, 1024 * 1024))
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        let field = |key: &str| -> String {
            crate::scans::reg_exp(&format!("{key}: (.*?)\n"), &mf_text, 1).replace('\r', "")
        };
        let protected_by = field("Protected-By");
        let created_by = field("Created-By");
        let built_by = field("Built-By");
        let apk_prot = |misc: &mut ResultMaps, name: u16, ver: String| {
            emit(misc, ft::FT_APK, rt::RECORD_TYPE_PROTECTOR, name, &ver, "");
        };
        if !protected_by.is_empty() {
            apk_prot(
                misc,
                n::RECORD_NAME_UNKNOWN0,
                format!("Protected: {protected_by}"),
            );
        }
        if !created_by.is_empty() && created_by != "1.0 (Android)" {
            apk_prot(
                misc,
                n::RECORD_NAME_UNKNOWN1,
                format!("Created: {created_by}"),
            );
        }
        if !built_by.is_empty() {
            apk_prot(misc, n::RECORD_NAME_UNKNOWN2, format!("Built: {built_by}"));
        }
        if !protected_by.is_empty()
            && !created_by.is_empty()
            && !built_by.is_empty()
            && mf_text.contains("-By")
        {
            apk_prot(misc, n::RECORD_NAME_UNKNOWN0, "CHECK".to_string());
        }
    }

    if !all_types {
        crate::promote::zip_container_members(members, misc);
    }
}

// ---------------------------------------------------------------------------
// JPEG (`XJpeg` + `NFD_JPEG::getInfo`)
// ---------------------------------------------------------------------------

/// `XJpeg::_readChunk` — one JPEG marker segment starting at `off`.
/// Returns `(marker_id, end_offset)`; `None` when the segment is
/// malformed or extends past the buffer.
fn jpeg_chunk(d: &[u8], off: usize) -> Option<(u8, usize)> {
    let total = d.len();
    // `nOffset > nTotalSize - JPEG_SIGNATURE_SIZE` rejects.
    if off + 2 > total || d[off] != 0xFF {
        return None;
    }
    let id = d[off + 1];
    // `isMarkerWithoutLength`: SOI/EOI/TEM and RST0-RST7 carry no
    // length field.
    let size = if matches!(id, 0xD8 | 0xD9 | 0x01) || (0xD0..=0xD7).contains(&id) {
        2usize
    } else if id != 0x00 && id != 0xFF {
        if off + 4 > total {
            return None;
        }
        let len = u16::from_be_bytes([d[off + 2], d[off + 3]]) as usize;
        if len < 2 {
            return None;
        }
        2 + len
    } else {
        return None;
    };
    if size > total - off {
        return None;
    }
    Some((id, off + size))
}

/// `XJpeg::getChunks` — walk markers from SOI to EOI. Returns `false`
/// when the walk fails or the stream does not terminate at EOI.
fn jpeg_chunks_valid(d: &[u8]) -> bool {
    const MAX_CHUNKS: usize = 65536;
    let total = d.len();
    let mut off = 0usize;
    let mut count = 0usize;
    let mut first = true;
    loop {
        let Some((id, end)) = jpeg_chunk(d, off) else {
            return false;
        };
        count += 1;
        if count > MAX_CHUNKS {
            return false;
        }
        if first && id != 0xD8 {
            return false;
        }
        first = false;
        off = end;
        if id == 0xDA {
            // SOS: entropy-coded data until the next non-stuffed marker.
            while off < total {
                let Some(prefix) = parse::find_ansi(d, off, total - off, &[0xFF]) else {
                    return false;
                };
                if prefix + 1 >= total {
                    return false;
                }
                let mut id_off = prefix + 1;
                while id_off < total && d[id_off] == 0xFF {
                    id_off += 1;
                }
                if id_off >= total {
                    return false;
                }
                let nid = d[id_off];
                if nid == 0x00 || (0xD0..=0xD7).contains(&nid) {
                    off = id_off + 1;
                    continue;
                }
                off = id_off - 1;
                break;
            }
            if off >= total {
                return false;
            }
        }
        if id == 0xD9 {
            return true;
        }
    }
}

/// `XJpeg::isValid` — size floor, one of the three start signatures and
/// a complete SOI..EOI chunk walk.
fn jpeg_valid(d: &[u8]) -> bool {
    if d.len() < 20 {
        return false;
    }
    let sig_ok = (d.starts_with(&[0xFF, 0xD8, 0xFF, 0xE0]) && d.get(6..11) == Some(b"JFIF\0"))
        || (d.starts_with(&[0xFF, 0xD8, 0xFF, 0xE1]) && d.get(6..11) == Some(b"Exif\0"))
        || d.starts_with(&[0xFF, 0xD8, 0xFF, 0xDB]);
    sig_ok && jpeg_chunks_valid(d)
}

/// `XJpeg::getVersion` — the JFIF APP0 extension version (`u8` major at
/// `JFIF+5`, `u8` minor at `JFIF+6`), empty when no valid APP0 exists.
fn jpeg_version(d: &[u8]) -> String {
    let mut off = 0usize;
    let mut first = true;
    while let Some((id, end)) = jpeg_chunk(d, off) {
        if first && id != 0xD8 {
            break;
        }
        first = false;
        // APP0 with "JFIF\0" at payload start; data size must hold the
        // 14-byte JFIF header plus the 4-byte segment header.
        if id == 0xE0 && end - off >= 18 && d.get(off + 4..off + 9) == Some(b"JFIF\0") {
            let jfif = off + 4;
            let jfif_size = end - jfif;
            if jfif_size >= 14 {
                return format!("{}.{}", d[jfif + 5], d[jfif + 6]);
            }
            break;
        }
        if id == 0xDA || id == 0xD9 {
            break;
        }
        off = end;
    }
    String::new()
}

/// `NFD_JPEG::getInfo` — emit the JPEG format record with the JFIF
/// version when the stream is a valid JPEG.
pub fn jpeg_semantic_scan(d: &[u8], misc: &mut ResultMaps) {
    if !jpeg_valid(d) {
        return;
    }
    emit(
        misc,
        ft::FT_JPEG,
        rt::RECORD_TYPE_FORMAT,
        n::RECORD_NAME_JPEG,
        &jpeg_version(d),
        "",
    );
}

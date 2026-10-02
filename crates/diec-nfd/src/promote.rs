//! Promotion layer of the generic binary path (`NFD_Binary::getInfo`).
//!
//! After the header/signature scans fill the intermediate detect maps,
//! upstream runs a fixed chain of `handle_*` functions that copy,
//! enrich (version/info) or synthesize records into the result maps.
//! Only the `mapResult*` collections are drained into the output list;
//! intermediate maps never reach the caller.

use crate::gen_names::{ft, name as n, rtype as rt};
use crate::parse;
use crate::scans::{DetectMap, ResultMaps, ScanRecord};
use crate::{archiveheaders, containers, legacy};

/// Which upstream `FILEPART` this scan was invoked for.
/// `XScanEngine::SCANID::filePart` — which file part produced a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilePart {
    /// `FILEPART_HEADER` — the main scan.
    #[default]
    Header,
    /// `FILEPART_OVERLAY` — appended-data rescan.
    Overlay,
    /// `FILEPART_RESOURCE` — embedded resource rescan (`varInfo` = type id).
    Resource,
    /// `FILEPART_DEBUGDATA` — debug-data rescan.
    DebugData,
    /// `FILEPART_STREAM` — archive member rescan.
    Stream,
}

/// Inputs shared by every promotion handler — mirrors the fields of
/// `NFD_Binary::BINARYINFO_STRUCT` the handlers consult.
pub struct PromoteCtx<'a> {
    /// Whole buffer of the (sub)device being scanned.
    pub data: &'a [u8],
    /// `basic_info.sHeaderSignature` — hex dump of the first 150 bytes.
    pub header_sig: &'a str,
    /// `mapHeaderDetects` from the table scans.
    pub header: &'a DetectMap,
    /// `bIsPlainText` (`XBinary::isPlainTextType`).
    pub is_plain_text: bool,
    /// `bIsUTF8` (`XBinary::isUTF8TextType`).
    pub is_utf8: bool,
    /// `unicodeType != UNICODE_TYPE_NONE`.
    pub unicode: bool,
    /// `sHeaderText` — text used by the source-language heuristics.
    pub header_text: String,
    /// `parentId.filePart` of this scan.
    pub parent_part: FilePart,
    /// `pOptions->varInfo` — resource type id for `FilePart::Resource`.
    // Read once the `FILEPART_RESOURCE` promotion branch is wired.
    #[allow(dead_code)]
    pub res_type_id: u32,
}

/// `XBinary::hexToString` over `sHeaderSignature` — decode `len` hex
/// chars starting at hex position `off` into an ASCII string.
fn hex_to_str(sig: &str, off: usize, len: usize) -> String {
    let hex: String = sig.chars().skip(off).take(len).collect();
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .filter_map(|k| u8::from_str_radix(&hex[k * 2..k * 2 + 2], 16).ok())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `getScansStruct` — a fresh record carrying only type/name/ver/info.
fn scans_struct(ft_id: u16, rtype: u8, name: u16, ver: &str, info: &str) -> ScanRecord {
    ScanRecord {
        name,
        rtype,
        ft: ft_id,
        variant: 0,
        version: ver.to_string(),
        info: info.to_string(),
        heuristic: false,
        unknown: false,
        sname: None,
        stype: None,
    }
}

/// `addTextRecord` — a source/script record into `mapResultTexts`.
fn add_text_record(res: &mut ResultMaps, name: u16, sname: &'static str, info: &str) {
    let mut r = scans_struct(ft::FT_BINARY, rt::RECORD_TYPE_SOURCECODE, name, "", info);
    r.stype = Some("source");
    r.sname = Some(std::borrow::Cow::Borrowed(sname));
    res.texts.insert(r.name, r);
}

/// `handle_Texts` — plain/UTF-8 format record, C/C++/HTML/Python/XML/PHP
/// source heuristics and the shebang interpreter record.
fn handle_texts(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let is_text = ctx.is_plain_text || ctx.unicode || ctx.is_utf8;
    if is_text {
        // DiE reports text files under the Binary root with the encoding
        // folded into the format record name.
        let mut fmt = scans_struct(
            ft::FT_BINARY,
            rt::RECORD_TYPE_FORMAT,
            n::RECORD_NAME_PLAIN,
            "",
            "",
        );
        fmt.stype = Some("format");
        fmt.sname = Some(std::borrow::Cow::Borrowed(if ctx.is_utf8 {
            "UTF-8 text"
        } else {
            "Plain text"
        }));
        let head = &ctx.data[..ctx.data.len().min(4096)];
        if let Some(lf) = head.iter().position(|&b| b == b'\n') {
            let crlf =
                (lf > 0 && head[lf - 1] == b'\r') || (lf + 1 < head.len() && head[lf + 1] == b'\r');
            fmt.info = if crlf { "CRLF" } else { "LF" }.to_string();
        } else if head.contains(&b'\r') {
            fmt.info = "CR".to_string();
        }
        res.formats.insert(fmt.name, fmt);

        let text = &ctx.header_text;
        let re_find = |pat: &str| -> bool {
            fancy_regex::Regex::new(pat)
                .ok()
                .and_then(|r| r.find(text).ok().flatten())
                .is_some()
        };
        let b_header = re_find(r"(?m)^#ifndef\s+(\w+)[^\r\n]*\s+^#define\s+\1\b")
            || re_find(r"#\s*pragma\s+(?:once|hdrstop)");
        let mut b_cpp = re_find(r"(?m)^(?:class\b|virtual\b|public:|private:|template\b)")
            && !re_find(r"\sdef\s");
        let mut b_csrc = b_header || b_cpp;
        if let Ok(re) = fancy_regex::Regex::new(r#"(?m)^#include\s+["<].*?[>"]"#) {
            let mut it = re.find_iter(text);
            let mut count = 0;
            while let Some(Ok(m)) = it.next() {
                b_csrc = true;
                if !m.as_str().contains('.') {
                    b_cpp = true;
                }
                count += 1;
                if count > 4096 {
                    break;
                }
            }
        }
        if !b_csrc {
            b_csrc = re_find(r"(?m)^#define\b");
        }
        if b_csrc {
            let sname: &'static str = if b_cpp { "C++" } else { "C/C++" };
            let mut r = scans_struct(
                ft::FT_BINARY,
                rt::RECORD_TYPE_SOURCECODE,
                n::RECORD_NAME_CCPP,
                "",
                "",
            );
            r.stype = Some("source");
            r.sname = Some(std::borrow::Cow::Borrowed(sname));
            if b_header {
                r.info = "header".to_string();
            }
            res.texts.insert(r.name, r);
        }
        if re_find(r"(?im)^<\s*(?:!DOCTYPE\s+)?html\b[^>]*>") {
            add_text_record(res, n::RECORD_NAME_HTML, "HTML", "");
        }
        if re_find(r"import\s")
            && re_find(r"class\s")
            && text.contains("self")
            && re_find(r"\sdef\s")
        {
            add_text_record(res, n::RECORD_NAME_PYTHON, "Python", "");
        }
        if text.starts_with("<?xml") {
            let ver = fancy_regex::Regex::new(r#"version="(.*?)""#)
                .ok()
                .and_then(|r| r.captures(text).ok().flatten())
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
                .unwrap_or_default();
            let mut r = scans_struct(
                ft::FT_BINARY,
                rt::RECORD_TYPE_SOURCECODE,
                n::RECORD_NAME_XML,
                "",
                "",
            );
            r.stype = Some("source");
            r.sname = Some(std::borrow::Cow::Borrowed("XML"));
            r.version = ver;
            res.texts.insert(r.name, r);
        }
        if text.starts_with("<?php") {
            add_text_record(res, n::RECORD_NAME_PHP, "PHP", "");
        }
    }

    // A script may carry a binary payload (Makeself), so the shebang check
    // is not restricted to plain-text files.
    let first_line = ctx.header_text.split('\n').next().unwrap_or("").trim();
    if let Ok(re) = fancy_regex::Regex::new(r"^#!\s*(?:.*/)?(?:env\s+)?([^\s]+)")
        && let Some(cap) = re.captures(first_line).ok().flatten()
        && let Some(m) = cap.get(1)
    {
        let mut interp = m.as_str().to_string();
        if interp.to_ascii_lowercase().ends_with(".exe") {
            interp.truncate(interp.len() - 4);
        }
        let sname: String = if interp.eq_ignore_ascii_case("sh") {
            "Shell".to_string()
        } else if !interp.is_empty() {
            let mut c = interp.to_lowercase();
            if let Some(first) = c.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            c
        } else {
            String::new()
        };
        if !sname.is_empty() {
            let mut r = scans_struct(
                ft::FT_BINARY,
                rt::RECORD_TYPE_SOURCECODE,
                n::RECORD_NAME_SHELL,
                "",
                "",
            );
            r.stype = Some("script");
            // sname is &'static — store through the owned version field
            // path: emit into texts with an owned display override is not
            // representable; keep the record name SHELL and stash the
            // interpreter in `info` when it is not "Shell".
            r.sname = if sname == "Shell" {
                Some(std::borrow::Cow::Borrowed("Shell"))
            } else {
                None
            };
            if r.sname.is_none() {
                r.info = sname;
            }
            res.texts.insert(r.name, r);
        }
    }
}

/// First leg of `handle_Formats` — the big else-if chain over header
/// detections plus the ISO9660 volume-descriptor check.
fn handle_formats(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let d = ctx.data;
    let hdr = ctx.header;
    let sz = d.len() as u64;
    if sz == 0 {
        res.formats.insert(
            n::RECORD_NAME_EMPTYFILE,
            scans_struct(
                ft::FT_BINARY,
                rt::RECORD_TYPE_FORMAT,
                n::RECORD_NAME_EMPTYFILE,
                "",
                "",
            ),
        );
    } else if hdr.contains_key(&n::RECORD_NAME_PDF) && sz >= 8 {
        let mut ss = hdr[&n::RECORD_NAME_PDF].clone();
        ss.version = hex_to_str(ctx.header_sig, 5 * 2, 6);
        res.formats.insert(ss.name, ss);
    } else if hdr.contains_key(&n::RECORD_NAME_MICROSOFTCOMPOUND) && sz >= 8 {
        let mut ss = hdr[&n::RECORD_NAME_MICROSOFTCOMPOUND].clone();
        let sub1 = parse::rd_u16(d, 0x200).unwrap_or(0);
        let sub2 = parse::rd_u16(d, 0x1000).unwrap_or(0);
        if sub1 == 0 && sub2 == 0xFFFD {
            ss.rtype = rt::RECORD_TYPE_INSTALLER;
            ss.name = n::RECORD_NAME_MICROSOFTINSTALLER;
            ss.version.clear();
            ss.info.clear();
        } else if sub1 == 0xA5EC {
            ss.rtype = rt::RECORD_TYPE_FORMAT;
            ss.name = n::RECORD_NAME_MICROSOFTOFFICEWORD;
            ss.version = "97-2003".to_string();
            ss.info.clear();
        }
        res.formats.insert(ss.name, ss);
    } else if hdr.contains_key(&n::RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP) && sz >= 8 {
        res.formats.insert(
            n::RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP,
            hdr[&n::RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP].clone(),
        );
    } else if hdr.contains_key(&n::RECORD_NAME_AUTOIT) && sz >= 8 {
        res.formats
            .insert(n::RECORD_NAME_AUTOIT, hdr[&n::RECORD_NAME_AUTOIT].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_RTF) && sz >= 8 {
        res.formats
            .insert(n::RECORD_NAME_RTF, hdr[&n::RECORD_NAME_RTF].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_LUACOMPILED) && sz >= 8 {
        res.formats.insert(
            n::RECORD_NAME_LUACOMPILED,
            hdr[&n::RECORD_NAME_LUACOMPILED].clone(),
        );
    } else if hdr.contains_key(&n::RECORD_NAME_JAVACOMPILEDCLASS) && sz >= 8 {
        let minor = parse::rd_u16_be_le(d, 4, true).unwrap_or(0);
        let major = parse::rd_u16_be_le(d, 6, true).unwrap_or(0);
        if major != 0 {
            let ver = jdk_version(major, minor);
            if !ver.is_empty() {
                let mut ss = hdr[&n::RECORD_NAME_JAVACOMPILEDCLASS].clone();
                ss.version = ver;
                res.formats.insert(ss.name, ss);
            }
        }
    } else if hdr.contains_key(&n::RECORD_NAME_COFF) && sz >= 76 {
        let mut ss = hdr[&n::RECORD_NAME_COFF].clone();
        let off = parse::rd_u32_be_le(d, 72, true).unwrap_or(0) as usize + 58;
        if exp_match(d, "600A4C01", off) || exp_match(d, "600A0000FFFF....4C01", off) {
            ss.info = "I386".to_string();
        }
        if exp_match(d, "600A6486", off) || exp_match(d, "600A0000FFFF....6486", off) {
            ss.info = "AMD64".to_string();
        }
        if !ss.info.is_empty() {
            res.formats.insert(ss.name, ss);
        }
    } else if hdr.contains_key(&n::RECORD_NAME_DEX) && sz >= 8 {
        let mut ss = hdr[&n::RECORD_NAME_DEX].clone();
        ss.version = hex_to_str(ctx.header_sig, 8, 6);
        res.formats.insert(ss.name, ss);
    } else if hdr.contains_key(&n::RECORD_NAME_SWF) && sz >= 8 {
        let mut ss = hdr[&n::RECORD_NAME_SWF].clone();
        ss.version = format!("{}", d.get(3).copied().unwrap_or(0));
        res.formats.insert(ss.name, ss);
    } else {
        // Straight promotions in upstream else-if order. The first hit
        // wins; all need size >= 8 except where noted.
        const PROMOTE: &[(u16, u64)] = &[
            (n::RECORD_NAME_MICROSOFTWINHELP, 8),
            (n::RECORD_NAME_MP3, 8),
            (n::RECORD_NAME_MP4, 8),
            (n::RECORD_NAME_WINDOWSMEDIA, 8),
            (n::RECORD_NAME_FLASHVIDEO, 8),
            (n::RECORD_NAME_WAV, 8),
            (n::RECORD_NAME_AU, 8),
            (n::RECORD_NAME_DEB, 8),
            (n::RECORD_NAME_AVI, 8),
            (n::RECORD_NAME_WEBP, 8),
            (n::RECORD_NAME_TTF, 8),
            (n::RECORD_NAME_ANDROIDARSC, 8),
            (n::RECORD_NAME_ANDROIDXML, 8),
            (n::RECORD_NAME_AR, 8),
        ];
        for &(nm, min) in PROMOTE {
            if hdr.contains_key(&nm) && sz >= min {
                res.formats.insert(nm, hdr[&nm].clone());
                break;
            }
        }
    }

    // ISO9660 primary volume descriptor at sector 16 (independent of the
    // else-if chain — upstream checks it unconditionally).
    if sz >= 0x8010 && exp_match(d, "01'CD001'01", 0x8000) {
        res.formats.insert(
            n::RECORD_NAME_ISO9660,
            scans_struct(
                ft::FT_BINARY,
                rt::RECORD_TYPE_FORMAT,
                n::RECORD_NAME_ISO9660,
                "",
                "",
            ),
        );
    }
}

/// `XJavaClass::_getJDKVersion` — duplicated from `miscfmt` so the
/// promotion layer does not depend on the format modules.
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
        _ => "",
    };
    if !base.is_empty() && minor != 0 {
        return format!("{base}.{minor}");
    }
    base.to_string()
}

/// `compareSignature` on raw bytes (table syntax subset: hex nibbles,
/// `.` wildcards, quoted ASCII runs).
fn exp_match(data: &[u8], sig: &str, offset: usize) -> bool {
    let Ok(elements) = diec_core::signature::parse_signature(sig) else {
        return false;
    };
    diec_core::signature::match_signature(data, offset, &elements)
}

/// `handle_Databases` — PDB / linker DB / Access version detection.
fn handle_databases(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let d = ctx.data;
    let hdr = ctx.header;
    let sz = d.len() as u64;
    if hdr.contains_key(&n::RECORD_NAME_PDB) && sz >= 32 {
        res.databases
            .insert(n::RECORD_NAME_PDB, hdr[&n::RECORD_NAME_PDB].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_MICROSOFTLINKERDATABASE) && sz >= 32 {
        res.databases.insert(
            n::RECORD_NAME_MICROSOFTLINKERDATABASE,
            hdr[&n::RECORD_NAME_MICROSOFTLINKERDATABASE].clone(),
        );
    } else if hdr.contains_key(&n::RECORD_NAME_MICROSOFTACCESS) && sz >= 128 {
        let mut ss = hdr[&n::RECORD_NAME_MICROSOFTACCESS].clone();
        ss.version = match parse::rd_u32(d, 0x14).unwrap_or(0) {
            0x0000 => "JET3",
            0x0001 => "JET4",
            0x0002 => "2007",
            0x0103 => "2010",
            _ => "",
        }
        .to_string();
        res.databases.insert(ss.name, ss);
    }
}

/// `handle_Images` — JPEG/GIF/TIFF/ICO/CUR/BMP/PNG/DjVu promotion with
/// version/dimension extraction.
fn handle_images(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let d = ctx.data;
    let hdr = ctx.header;
    let sz = d.len() as u64;
    if hdr.contains_key(&n::RECORD_NAME_JPEG) && sz >= 8 {
        let mut ss = hdr[&n::RECORD_NAME_JPEG].clone();
        let major =
            u32::from_str_radix(&hex_to_str_raw(ctx.header_sig, 11 * 2, 2), 16).unwrap_or(0);
        let minor =
            u32::from_str_radix(&hex_to_str_raw(ctx.header_sig, 12 * 2, 2), 16).unwrap_or(0);
        ss.version = format!("{major}.{minor:02}");
        res.images.insert(ss.name, ss);
    } else if hdr.contains_key(&n::RECORD_NAME_GIF) && sz >= 8 {
        res.images
            .insert(n::RECORD_NAME_GIF, hdr[&n::RECORD_NAME_GIF].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_TIFF) && sz >= 8 {
        res.images
            .insert(n::RECORD_NAME_TIFF, hdr[&n::RECORD_NAME_TIFF].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_WINDOWSICON) && sz >= 20 {
        res.images.insert(
            n::RECORD_NAME_WINDOWSICON,
            hdr[&n::RECORD_NAME_WINDOWSICON].clone(),
        );
    } else if hdr.contains_key(&n::RECORD_NAME_WINDOWSCURSOR) && sz >= 20 {
        res.images.insert(
            n::RECORD_NAME_WINDOWSCURSOR,
            hdr[&n::RECORD_NAME_WINDOWSCURSOR].clone(),
        );
    } else if hdr.contains_key(&n::RECORD_NAME_WINDOWSBITMAP) && sz >= 40 {
        // `qFromBigEndian(hexToUInt(...))` == the little-endian u32 stored
        // in the header.
        let declared = parse::rd_u32(d, 2).unwrap_or(0) as u64;
        if sz >= declared {
            let ver = match parse::rd_u32(d, 14).unwrap_or(0) {
                40 => "3",
                108 => "4",
                124 => "5",
                _ => "",
            };
            if !ver.is_empty() {
                let mut ss = hdr[&n::RECORD_NAME_WINDOWSBITMAP].clone();
                ss.version = ver.to_string();
                res.images.insert(ss.name, ss);
            }
        }
    } else if hdr.contains_key(&n::RECORD_NAME_PNG) && sz >= 8 {
        let mut ss = hdr[&n::RECORD_NAME_PNG].clone();
        let w = parse::rd_u32_be_le(d, 16, true).unwrap_or(0);
        let h = parse::rd_u32_be_le(d, 20, true).unwrap_or(0);
        ss.info = format!("{w}x{h}");
        res.images.insert(ss.name, ss);
    } else if hdr.contains_key(&n::RECORD_NAME_DJVU) && sz >= 8 {
        res.images
            .insert(n::RECORD_NAME_DJVU, hdr[&n::RECORD_NAME_DJVU].clone());
    }
}

/// Read `len` hex chars of the signature starting at `off` (positions in
/// the hex string, not decoded bytes).
fn hex_to_str_raw(sig: &str, off: usize, len: usize) -> String {
    sig.chars().skip(off).take(len).collect()
}

/// `handle_Archives` — container sub-engines first, then the ZIP/CAB/
/// MachOFat/RAR-old/zlib/XZ/BZIP2 promotions.
fn handle_archives(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let d = ctx.data;
    let hdr = ctx.header;
    let sz = d.len() as u64;

    // Outer containers first: a DMG data fork can itself start with zlib.
    if containers::detect(d, res)
        || legacy::detect(d, res)
        || archiveheaders::detect(d, res)
        || crate::compression_detect::detect(d, res)
    {
        res.formats.remove(&n::RECORD_NAME_PLAIN);
        res.texts.clear();
        // Prefer the structural archive result over an earlier
        // header-only record for the same family.
        let names: Vec<u16> = res
            .archives
            .keys()
            .copied()
            .filter(|k| *k != n::RECORD_NAME_UNKNOWN)
            .collect();
        for k in names {
            res.formats.remove(&k);
        }
        return;
    }

    if hdr.contains_key(&n::RECORD_NAME_ZIP) && sz >= 22 {
        if let Some(records) = zip_records(d) {
            zip_container(&records, res);
        } else if container_header(d, res) {
            // handle_ContainerHeader fallback recorded the ZIP record.
        }
    } else if hdr.contains_key(&n::RECORD_NAME_GZIP) && sz >= 9 {
        res.archives
            .insert(n::RECORD_NAME_GZIP, hdr[&n::RECORD_NAME_GZIP].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_XAR) && sz >= 9 {
        res.archives
            .insert(n::RECORD_NAME_XAR, hdr[&n::RECORD_NAME_XAR].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_LZFSE) && sz >= 9 {
        res.archives
            .insert(n::RECORD_NAME_LZFSE, hdr[&n::RECORD_NAME_LZFSE].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_CAB) && sz >= 30 {
        // `XCab::getVersion` returns ""; `getNumberOfRecords` is CFFOLDER.
        if let Some(count) = cab_folders(d) {
            let mut ss = hdr[&n::RECORD_NAME_CAB].clone();
            ss.info = format!("{count} records");
            res.archives.insert(ss.name, ss);
        }
    } else if hdr.contains_key(&n::RECORD_NAME_MACHOFAT) && sz >= 30 {
        if parse::macho_fat_valid(d) {
            let mut ss = hdr[&n::RECORD_NAME_MACHOFAT].clone();
            let count = parse::rd_u32_be_le(d, 4, true).unwrap_or(0);
            ss.info = format!("{count} records");
            res.archives.insert(ss.name, ss);
        }
    } else if hdr.contains_key(&n::RECORD_NAME_RAR) && d.get(..4) == Some(b"RE~^") && sz >= 7 {
        // Old-style RAR (RE~^ signature) only; RAR 1.5+/5.x is claimed by
        // `archiveheaders::detect` above.
        res.archives
            .insert(n::RECORD_NAME_RAR, hdr[&n::RECORD_NAME_RAR].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_ZLIB) && sz >= 32 {
        res.archives
            .insert(n::RECORD_NAME_ZLIB, hdr[&n::RECORD_NAME_ZLIB].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_XZ) && sz >= 32 {
        res.archives
            .insert(n::RECORD_NAME_XZ, hdr[&n::RECORD_NAME_XZ].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_BZIP2) && sz >= 9 {
        res.archives
            .insert(n::RECORD_NAME_BZIP2, hdr[&n::RECORD_NAME_BZIP2].clone());
    }
    if !res.archives.is_empty() {
        res.formats.remove(&n::RECORD_NAME_PLAIN);
        res.texts.clear();
    }
}

/// Per-member metadata needed by `handle_Container` — the low byte of
/// `version needed` plus the encrypted flag.
pub struct ZipRecordInfo {
    /// `FPART_PROP_VERSIONNEEDED & 0xFF`.
    pub version_needed: u32,
    /// `FPART_PROP_ENCRYPTED`.
    pub encrypted: bool,
}

/// `XZip::isValid` + `getRecords` subset: parse the central directory
/// and return per-entry version/encryption info.
pub(crate) fn zip_records(d: &[u8]) -> Option<Vec<ZipRecordInfo>> {
    // `XZip::isValid` accepts an archive as soon as a consistent EOCD is
    // found, so an EOCD with zero entries still takes the
    // `handle_Container` path ("0 records inspected", no verified suffix).
    let pos = d.len();
    let tail_start = pos.saturating_sub(0x10000 + 22);
    let mut eocd = None;
    let mut i = pos;
    while i > tail_start {
        i -= 1;
        if d.get(i..i + 4) == Some(b"PK\x05\x06") {
            eocd = Some(i);
            break;
        }
    }
    let eocd = eocd?;
    let members = parse::zip_members(d);
    // Re-parse the central directory for the version-needed and flag
    // fields `zip_members` does not retain.
    let mut out = Vec::with_capacity(members.len());
    let cd_off = parse::rd_u32(d, eocd + 16)? as usize;
    let cd_count = parse::rd_u16(d, eocd + 10)? as usize;
    let mut cur = cd_off;
    for _ in 0..cd_count.min(20000) {
        if d.get(cur..cur + 4) != Some(b"PK\x01\x02") {
            return None;
        }
        let ver = parse::rd_u16(d, cur + 6)? as u32;
        let flags = parse::rd_u16(d, cur + 8)?;
        let method = parse::rd_u16(d, cur + 10)?;
        let name_len = parse::rd_u16(d, cur + 28)? as usize;
        let extra_len = parse::rd_u16(d, cur + 30)? as usize;
        let comment_len = parse::rd_u16(d, cur + 32)? as usize;
        out.push(ZipRecordInfo {
            version_needed: ver & 0xFF,
            encrypted: (flags & 1) != 0 || method == 99,
        });
        cur = cur.checked_add(46 + name_len + extra_len + comment_len)?;
    }
    Some(out)
}

/// `NFD_ZIP::handle_Container` — the ZIP format record with the
/// "records inspected / minimum reader version" info string.
pub fn zip_container(records: &[ZipRecordInfo], res: &mut ResultMaps) {
    let mut minimum = 0u32;
    let mut encrypted = false;
    for r in records {
        minimum = minimum.max(r.version_needed);
        encrypted |= r.encrypted;
    }
    let mut ss = scans_struct(
        ft::FT_ARCHIVE,
        rt::RECORD_TYPE_FORMAT,
        n::RECORD_NAME_ZIP,
        "",
        "",
    );
    ss.info = format!("{} records inspected", records.len());
    if minimum != 0 {
        ss.info = append_comma(
            &ss.info,
            &format!(
                "Declared minimum reader version: {}.{} (inspected entries)",
                minimum / 10,
                minimum % 10
            ),
        );
    }
    if encrypted {
        ss.info = append_comma(&ss.info, "Encrypted");
    }
    res.archives.insert(ss.name, ss);
}

/// `NFD_ZIP::handle_ContainerHeader` — EOCD walk used when `XZip::isValid`
/// fails; validates the central directory and emits the ZIP record with
/// the "central/local headers verified" suffix.
fn container_header(d: &[u8], res: &mut ResultMaps) -> bool {
    let size = d.len();
    if size < 22 {
        return false;
    }
    let tail_off = size.saturating_sub(65557);
    let tail = &d[tail_off..];
    // Equivalent of the `lastIndexOf` walk: try every EOCD candidate from
    // the back until the comment-length check passes.
    let mut end: Option<usize> = None;
    let mut hits: Vec<usize> = Vec::new();
    for (i, w) in tail.windows(4).enumerate() {
        if w == b"PK\x05\x06" {
            hits.push(i);
        }
    }
    for &e in hits.iter().rev() {
        if tail.len() - e >= 22 && parse::rd_u16(tail, e + 20) == Some((tail.len() - e - 22) as u16)
        {
            end = Some(e);
            break;
        }
        if e == 0 {
            break;
        }
    }
    let Some(e) = end else {
        return false;
    };
    if parse::rd_u16(tail, e + 4).unwrap_or(1) != 0 || parse::rd_u16(tail, e + 6).unwrap_or(1) != 0
    {
        return false;
    }
    let count = parse::rd_u16(tail, e + 10).unwrap_or(0) as usize;
    if count > 20000 || parse::rd_u16(tail, e + 8).unwrap_or(0) as usize != count {
        return false;
    }
    let dir_size = parse::rd_u32(tail, e + 12).unwrap_or(0) as usize;
    let dir_off = parse::rd_u32(tail, e + 16).unwrap_or(0) as usize;
    let end_off = tail_off + e;
    if dir_size > 4 * 1024 * 1024
        || dir_size < count * 46
        || dir_off > end_off
        || dir_size != end_off - dir_off
    {
        return false;
    }
    let Some(dir) = d.get(dir_off..dir_off + dir_size) else {
        return false;
    };
    let mut records = Vec::with_capacity(count);
    let mut cursor = 0usize;
    for _ in 0..count {
        if dir.len() - cursor < 46 || parse::rd_u32(dir, cursor) != Some(0x02014B50) {
            return false;
        }
        let name_size = parse::rd_u16(dir, cursor + 28).unwrap_or(0) as usize;
        let rec_size = 46
            + name_size
            + parse::rd_u16(dir, cursor + 30).unwrap_or(0) as usize
            + parse::rd_u16(dir, cursor + 32).unwrap_or(0) as usize;
        if rec_size > dir.len() - cursor || parse::rd_u16(dir, cursor + 34).unwrap_or(1) != 0 {
            return false;
        }
        let local_off = parse::rd_u32(dir, cursor + 42).unwrap_or(0) as usize;
        let packed = parse::rd_u32(dir, cursor + 20).unwrap_or(0) as usize;
        if local_off > dir_off || dir_off - local_off < 30 || packed == 0xFFFF_FFFF {
            return false;
        }
        let Some(local) = d.get(local_off..local_off + 30) else {
            return false;
        };
        if parse::rd_u32(local, 0) != Some(0x04034B50)
            || parse::rd_u16(local, 8) != parse::rd_u16(dir, cursor + 10)
            || parse::rd_u16(local, 26).unwrap_or(0) as usize != name_size
        {
            return false;
        }
        let data_off = local_off + 30 + name_size + parse::rd_u16(local, 28).unwrap_or(0) as usize;
        if data_off > dir_off || packed > dir_off - data_off {
            return false;
        }
        if d.get(local_off + 30..local_off + 30 + name_size)
            != dir.get(cursor + 46..cursor + 46 + name_size)
        {
            return false;
        }
        records.push(ZipRecordInfo {
            version_needed: parse::rd_u16(dir, cursor + 6).unwrap_or(0) as u32,
            encrypted: (parse::rd_u16(dir, cursor + 8).unwrap_or(0) & 1) != 0
                || parse::rd_u16(dir, cursor + 10).unwrap_or(0) == 99,
        });
        cursor += rec_size;
    }
    if cursor != dir.len() {
        return false;
    }
    zip_container(&records, res);
    if let Some(rec) = res.archives.get_mut(&n::RECORD_NAME_ZIP) {
        rec.info = append_comma(&rec.info, "central/local headers verified");
    }
    true
}

/// `NFD_ZIP::getInfo` container leg — the valid-archive path emits the
/// member-metadata record (`handle_Container`); invalid archives fall
/// back to the strict central-directory walk (`handle_ContainerHeader`).
/// The Metainfos/Office/OpenOffice/JAR/IPA member handlers are Phase
/// 23.C pending items.
pub(crate) fn zip_scan(d: &[u8], res: &mut ResultMaps) {
    if let Some(records) = zip_records(d) {
        zip_container(&records, res);
    } else {
        container_header(d, res);
    }
}

/// `handle_Container` over an already-parsed member list (APK/JAR paths
/// share the ZIP container emit).
pub(crate) fn zip_container_members(members: &[crate::parse::ZipMember], res: &mut ResultMaps) {
    let records: Vec<ZipRecordInfo> = members
        .iter()
        .map(|m| ZipRecordInfo {
            version_needed: u32::from(m.version_needed),
            encrypted: m.encrypted,
        })
        .collect();
    if !records.is_empty() {
        zip_container(&records, res);
    }
}

/// `XCab::getNumberOfRecords` — CFFOLDER count at offset 8.
fn cab_folders(d: &[u8]) -> Option<u16> {
    if d.get(..4) != Some(b"MSCF") {
        return None;
    }
    parse::rd_u16(d, 8)
}

/// `XBinary::appendComma` — "a, b" or just "b" when `a` is empty.
pub fn append_comma(a: &str, b: &str) -> String {
    if a.is_empty() {
        b.to_string()
    } else {
        format!("{a}, {b}")
    }
}

/// `handle_Certificates` — WINAUTH length check then promotion.
fn handle_certificates(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let hdr = ctx.header;
    let sz = ctx.data.len() as u64;
    if hdr.contains_key(&n::RECORD_NAME_WINAUTH) && sz >= 8 {
        let length = u32::from_str_radix(&hex_to_str_raw(ctx.header_sig, 0, 8), 16).unwrap_or(0);
        if u64::from(length) >= sz {
            res.certificates
                .insert(n::RECORD_NAME_WINAUTH, hdr[&n::RECORD_NAME_WINAUTH].clone());
        }
    }
}

/// `handle_DebugData` — MinGW/PDB-link promotion, Borland TDS, Watcom
/// tail stamps (0x8386 + NB05-NB11), DWARF Watcom block.
fn handle_debugdata(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let d = ctx.data;
    let hdr = ctx.header;
    let sz = d.len();
    if hdr.contains_key(&n::RECORD_NAME_MINGW) && sz >= 8 {
        res.debugdata
            .insert(n::RECORD_NAME_MINGW, hdr[&n::RECORD_NAME_MINGW].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_PDBFILELINK) && sz >= 8 {
        res.debugdata.insert(
            n::RECORD_NAME_PDBFILELINK,
            hdr[&n::RECORD_NAME_PDBFILELINK].clone(),
        );
    }
    if hdr.contains_key(&n::RECORD_NAME_BORLANDDEBUGINFO) && sz >= 16 {
        if parse::rd_u16(d, 0) == Some(0x52FB) {
            let mut ss = scans_struct(
                ft::FT_BINARY,
                rt::RECORD_TYPE_DEBUGDATA,
                n::RECORD_NAME_BORLANDDEBUGINFO,
                "",
                "",
            );
            let major = d.get(3).copied().unwrap_or(0);
            let minor = d.get(2).copied().unwrap_or(0);
            let syms = parse::rd_u16(d, 0xE).unwrap_or(0);
            ss.version = format!("{:.2}", major as f64 + minor as f64 / 100.0);
            ss.info = "TDS".to_string();
            if syms != 0 {
                ss.info = append_comma(&ss.info, &format!("{syms} symbols"));
            }
            res.debugdata.insert(ss.name, ss);
        } else {
            res.debugdata.insert(
                n::RECORD_NAME_BORLANDDEBUGINFO,
                hdr[&n::RECORD_NAME_BORLANDDEBUGINFO].clone(),
            );
        }
    }
    if sz > 16 && parse::rd_u16(d, sz - 14) == Some(0x8386) {
        let hoff = sz - 14;
        // Upstream assigns `read_uint16` results into `quint8` — the
        // values truncate to the low byte.
        let major = parse::rd_u16(d, hoff + 2).unwrap_or(0) as u8;
        let minor = parse::rd_u16(d, hoff + 3).unwrap_or(0) as u8;
        let debug_size = parse::rd_u32(d, hoff + 10).unwrap_or(0) as usize;
        if debug_size <= sz {
            let mut ss = scans_struct(
                ft::FT_BINARY,
                rt::RECORD_TYPE_DEBUGDATA,
                n::RECORD_NAME_WATCOMDEBUGINFO,
                "",
                "",
            );
            ss.version = format!("{major}.{minor}");
            ss.info = format!("0x{debug_size:X} bytes");
            res.debugdata.insert(ss.name, ss);
        }
    }
    if sz > 16
        && parse::rd_u16(d, sz - 8) == Some(0x424E)
        && let Some(sig) = parse::read_ansi_string_len(d, sz - 8, 4)
        && matches!(
            sig.as_str(),
            "NB05" | "NB07" | "NB08" | "NB09" | "NB10" | "NB11"
        )
    {
        let hoff = sz - 8;
        let debug_size = parse::rd_u32(d, hoff + 4).unwrap_or(0) as usize;
        if debug_size <= sz {
            // CodeView NBxx trailer → DEBUGDATA record "4.0".
            let mut ss = scans_struct(
                ft::FT_BINARY,
                rt::RECORD_TYPE_DEBUGDATA,
                n::RECORD_NAME_CODEVIEWDEBUGINFO,
                "4.0",
                "",
            );
            ss.info = format!("0x{debug_size:X} bytes");
            res.debugdata.insert(ss.name, ss);
        }
    }
    if sz > 16 && parse::rd_u32(d, sz - 16) == Some(0x534954) {
        // TIS trailer (Watcom debug info block).
        let hoff = sz - 16;
        let vendor = parse::rd_u32(d, hoff + 4).unwrap_or(1);
        let ty = parse::rd_u32(d, hoff + 8).unwrap_or(1);
        let debug_size = parse::rd_u32(d, hoff + 12).unwrap_or(0) as usize;
        if vendor == 0 && ty == 0 && debug_size <= hoff {
            // `get_DWRAF_vi`: int16 at block offset +4 in 0..=7 → "N.0".
            let dbg_off = hoff - debug_size;
            if let Some(v) = parse::rd_u16(d, dbg_off + 4)
                && (v as i16) >= 0
                && v <= 7
            {
                let mut ss = scans_struct(
                    ft::FT_BINARY,
                    rt::RECORD_TYPE_DEBUGDATA,
                    n::RECORD_NAME_DWARFDEBUGINFO,
                    &format!("{v}.0"),
                    "",
                );
                ss.info = append_comma(&format!("0x{debug_size:X} bytes"), "Watcom");
                res.debugdata.insert(ss.name, ss);
            }
        }
    }
}

/// `handle_InstallerData` — installer payload records found at the
/// header (self-extracting installers keep their stub data first).
fn handle_installerdata(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let hdr = ctx.header;
    let sz = ctx.data.len() as u64;
    let promote = |nm: u16, min: u64, res: &mut ResultMaps| {
        if hdr.contains_key(&nm) && sz >= min {
            res.installerdata.insert(nm, hdr[&nm].clone());
            return true;
        }
        false
    };
    if promote(n::RECORD_NAME_INNOSETUP, 8, res)
        || promote(n::RECORD_NAME_INSTALLANYWHERE, 8, res)
        || promote(n::RECORD_NAME_GHOSTINSTALLER, 8, res)
        || promote(n::RECORD_NAME_NSIS, 8, res)
        || promote(n::RECORD_NAME_SIXXPACK, 8, res)
        || promote(n::RECORD_NAME_THINSTALL, 8, res)
    {
        return;
    }
    if hdr.contains_key(&n::RECORD_NAME_SMARTINSTALLMAKER) && sz >= 30 {
        let mut ss = hdr[&n::RECORD_NAME_SMARTINSTALLMAKER].clone();
        ss.version = hex_to_str(ctx.header_sig, 46, 14);
        res.installerdata.insert(ss.name, ss);
        return;
    }
    for &(nm, min) in &[
        (n::RECORD_NAME_TARMAINSTALLER, 20u64),
        (n::RECORD_NAME_CLICKTEAM, 20),
        (n::RECORD_NAME_QTINSTALLER, 20),
        (n::RECORD_NAME_ADVANCEDINSTALLER, 20),
        (n::RECORD_NAME_OPERA, 20),
        (n::RECORD_NAME_GPINSTALL, 20),
        (n::RECORD_NAME_AVASTANTIVIRUS, 20),
        (n::RECORD_NAME_INSTALLSHIELD, 8),
        (n::RECORD_NAME_SETUPFACTORY, 8),
        (n::RECORD_NAME_ACTUALINSTALLER, 8),
        (n::RECORD_NAME_INSTALL4J, 8),
        (n::RECORD_NAME_VMWARE, 8),
        (n::RECORD_NAME_NOSINSTALLER, 8),
    ] {
        if promote(nm, min, res) {
            return;
        }
    }
}

/// `handle_SFXData` — Makeself shebang recognition plus WINRAR/Squeez/7z
/// SFX payload records.
fn handle_sfxdata(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let d = ctx.data;
    let hdr = ctx.header;
    let sz = d.len() as u64;
    if sz >= 64 && d.first() == Some(&b'#') && d.get(1) == Some(&b'!') {
        let head = String::from_utf8_lossy(&d[..d.len().min(16384)]);
        if let Ok(re) = fancy_regex::Regex::new(
            r#"(?i)(?:ms_version\s*=\s*\"?([0-9.]+)\"?|makeself version\s+([0-9.]+))"#,
        ) {
            let m = re.captures(&head).ok().flatten();
            if m.is_some() || head.to_lowercase().contains("ms_version=") {
                let ver = m
                    .and_then(|c| {
                        c.get(1)
                            .or_else(|| c.get(2))
                            .map(|g| g.as_str().to_string())
                    })
                    .unwrap_or_default();
                let mut ss = scans_struct(
                    ft::FT_BINARY,
                    rt::RECORD_TYPE_SFX,
                    n::RECORD_NAME_UNKNOWN,
                    &ver,
                    "",
                );
                ss.stype = Some("sfx");
                ss.sname = Some(std::borrow::Cow::Borrowed("Makeself SFX archive"));
                res.sfx.insert(ss.name, ss);
            }
        }
    }
    if hdr.contains_key(&n::RECORD_NAME_WINRAR) && sz >= 20 {
        res.sfxdata
            .insert(n::RECORD_NAME_WINRAR, hdr[&n::RECORD_NAME_WINRAR].clone());
    } else if hdr.contains_key(&n::RECORD_NAME_SQUEEZSFX) && sz >= 20 {
        res.sfxdata.insert(
            n::RECORD_NAME_SQUEEZSFX,
            hdr[&n::RECORD_NAME_SQUEEZSFX].clone(),
        );
    } else if hdr.contains_key(&n::RECORD_NAME_7Z) && sz >= 20 {
        let ss = hdr[&n::RECORD_NAME_7Z].clone();
        if ss.rtype == rt::RECORD_TYPE_SFXDATA {
            res.sfxdata.insert(ss.name, ss);
        }
    }
}

/// `handle_ProtectorData` — protector payload records found at the
/// header (else-if chain, SecuROM carries a version string).
fn handle_protectordata(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let hdr = ctx.header;
    let sz = ctx.data.len() as u64;
    let promote = |nm: u16, min: u64, res: &mut ResultMaps| {
        if hdr.contains_key(&nm) && sz >= min {
            res.protectordata.insert(nm, hdr[&nm].clone());
            return true;
        }
        false
    };
    for &(nm, min) in &[
        (n::RECORD_NAME_FISHNET, 8u64),
        (n::RECORD_NAME_XENOCODE, 8),
        (n::RECORD_NAME_MOLEBOXULTRA, 8),
        (n::RECORD_NAME_1337EXECRYPTER, 8),
        (n::RECORD_NAME_ACTIVEMARK, 8),
        (n::RECORD_NAME_AGAINNATIVITYCRYPTER, 8),
        (n::RECORD_NAME_ARCRYPT, 8),
        (n::RECORD_NAME_NOXCRYPT, 8),
        (n::RECORD_NAME_FASTFILECRYPT, 8),
        (n::RECORD_NAME_LIGHTNINGCRYPTERSCANTIME, 8),
        (n::RECORD_NAME_ZELDACRYPT, 8),
        (n::RECORD_NAME_WOUTHRSEXECRYPTER, 8),
        (n::RECORD_NAME_WLCRYPT, 8),
        (n::RECORD_NAME_DOTNETSHRINK, 8),
        (n::RECORD_NAME_SPOONSTUDIO, 8),
    ] {
        if promote(nm, min, res) {
            return;
        }
    }
    if hdr.contains_key(&n::RECORD_NAME_SECUROM) && sz >= 30 {
        let mut ss = hdr[&n::RECORD_NAME_SECUROM].clone();
        ss.version = parse::read_ansi_string(ctx.data, 8).unwrap_or_default();
        res.protectordata.insert(ss.name, ss);
        return;
    }
    let _ = promote(n::RECORD_NAME_SERGREENAPPACKER, 30, res);
}

/// `handle_LibraryData` — Python binary stub embedded under a shebang.
fn handle_librarydata(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let is_text = ctx.is_plain_text || ctx.unicode || ctx.is_utf8;
    if !is_text
        && ctx.header.contains_key(&n::RECORD_NAME_SHELL)
        && ctx.data.len() >= 8
        && let Some(s) = parse::read_ansi_string_len(ctx.data, 0, ctx.data.len().min(256))
        && s.contains("python")
    {
        res.librarydata.insert(
            n::RECORD_NAME_PYTHON,
            scans_struct(
                ft::FT_BINARY,
                rt::RECORD_TYPE_LIBRARY,
                n::RECORD_NAME_PYTHON,
                "",
                "",
            ),
        );
    }
}

/// `handle_Resources` — promoted only for `FilePart::Resource` scans;
/// the header record was synthesized from the resource type id.
fn handle_resources(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let d = ctx.data;
    let hdr = ctx.header;
    let sz = d.len() as u64;
    if hdr.contains_key(&n::RECORD_NAME_RESOURCE_VERSIONINFO) && sz >= 30 {
        res.resources.insert(
            n::RECORD_NAME_RESOURCE_VERSIONINFO,
            hdr[&n::RECORD_NAME_RESOURCE_VERSIONINFO].clone(),
        );
    } else if hdr.contains_key(&n::RECORD_NAME_BITMAPINFOHEADER) && sz >= 30 {
        let mut ss = hdr[&n::RECORD_NAME_BITMAPINFOHEADER].clone();
        let w = parse::rd_u32(d, 4).unwrap_or(0);
        let h = parse::rd_u32(d, 8).unwrap_or(0);
        ss.info = format!("{w}x{h}");
        res.resources.insert(ss.name, ss);
    } else {
        for nm in [
            n::RECORD_NAME_RESOURCE_STRINGTABLE,
            n::RECORD_NAME_RESOURCE_DIALOG,
            n::RECORD_NAME_RESOURCE_ICON,
            n::RECORD_NAME_RESOURCE_CURSOR,
            n::RECORD_NAME_RESOURCE_MENU,
        ] {
            if hdr.contains_key(&nm) {
                res.resources.insert(nm, hdr[&nm].clone());
                break;
            }
        }
    }
}

/// `handle_FixDetects` (binary level) — a PDF clears text results.
fn handle_fixdetects(ctx: &PromoteCtx, res: &mut ResultMaps) {
    let _ = ctx;
    if res.formats.contains_key(&n::RECORD_NAME_PDF) {
        res.texts.clear();
    }
}

/// The full binary-path promotion chain in upstream call order.
pub fn binary_promote(ctx: &PromoteCtx, res: &mut ResultMaps) {
    handle_texts(ctx, res);
    handle_formats(ctx, res);
    handle_databases(ctx, res);
    handle_images(ctx, res);
    handle_archives(ctx, res);
    handle_certificates(ctx, res);
    handle_debugdata(ctx, res);
    handle_installerdata(ctx, res);
    handle_sfxdata(ctx, res);
    handle_protectordata(ctx, res);
    handle_librarydata(ctx, res);
    if ctx.parent_part == FilePart::Resource {
        handle_resources(ctx, res);
    }
    handle_fixdetects(ctx, res);
}

/// `getLanguage` — derive language records from linker/compiler/library/
/// tool/packer maps (upstream iterates each map and translates the name).
fn get_language(src: &DetectMap, langs: &mut DetectMap) {
    for rec in src.values() {
        let lang = match rec.name {
            x if x == n::RECORD_NAME_C
                || x == n::RECORD_NAME_ARMC
                || x == n::RECORD_NAME_LCCLNK
                || x == n::RECORD_NAME_LCCWIN
                || x == n::RECORD_NAME_MICROSOFTC
                || x == n::RECORD_NAME_THUMBC
                || x == n::RECORD_NAME_TINYC
                || x == n::RECORD_NAME_TURBOC
                || x == n::RECORD_NAME_WATCOMC =>
            {
                Some(n::RECORD_NAME_C)
            }
            x if x == n::RECORD_NAME_CCPP
                || x == n::RECORD_NAME_ARMCCPP
                || x == n::RECORD_NAME_ARMNEONCCPP
                || x == n::RECORD_NAME_ARMTHUMBCCPP
                || x == n::RECORD_NAME_BORLANDCCPP
                || x == n::RECORD_NAME_MINGW
                || x == n::RECORD_NAME_MSYS
                || x == n::RECORD_NAME_MSYS2
                || x == n::RECORD_NAME_VISUALCCPP
                || x == n::RECORD_NAME_OPENWATCOMCCPP
                || x == n::RECORD_NAME_WATCOMCCPP =>
            {
                Some(n::RECORD_NAME_CCPP)
            }
            x if x == n::RECORD_NAME_CLANG
                || x == n::RECORD_NAME_GCC
                || x == n::RECORD_NAME_ALIBABACLANG
                || x == n::RECORD_NAME_ALIPAYCLANG
                || x == n::RECORD_NAME_ALPINECLANG
                || x == n::RECORD_NAME_ANDROIDCLANG
                || x == n::RECORD_NAME_APPLELLVM
                || x == n::RECORD_NAME_APPORTABLECLANG
                || x == n::RECORD_NAME_BYTEDANCESECCOMPILER
                || x == n::RECORD_NAME_PLEXCLANG
                || x == n::RECORD_NAME_UBUNTUCLANG
                || x == n::RECORD_NAME_DEBIANCLANG =>
            {
                // GCC/Clang-family: Objective-C when the detect info says so.
                Some(if rec.info.contains("Objective-C") {
                    n::RECORD_NAME_OBJECTIVEC
                } else {
                    n::RECORD_NAME_CCPP
                })
            }
            x if x == n::RECORD_NAME_CPP
                || x == n::RECORD_NAME_BORLANDCPP
                || x == n::RECORD_NAME_BORLANDCPPBUILDER
                || x == n::RECORD_NAME_CODEGEARCPP
                || x == n::RECORD_NAME_CODEGEARCPPBUILDER
                || x == n::RECORD_NAME_EMBARCADEROCPP
                || x == n::RECORD_NAME_EMBARCADEROCPPBUILDER
                || x == n::RECORD_NAME_MICROSOFTCPP
                || x == n::RECORD_NAME_TURBOCPP =>
            {
                Some(n::RECORD_NAME_CPP)
            }
            x if x == n::RECORD_NAME_ASSEMBLER
                || x == n::RECORD_NAME_ARMASSEMBLER
                || x == n::RECORD_NAME_ARMTHUMBMACROASSEMBLER
                || x == n::RECORD_NAME_DYNASM
                || x == n::RECORD_NAME_GNUASSEMBLER
                || x == n::RECORD_NAME_ILASM
                || x == n::RECORD_NAME_ROSASM =>
            {
                Some(n::RECORD_NAME_ASSEMBLER)
            }
            x if x == n::RECORD_NAME_FASM
                || x == n::RECORD_NAME_GOASM
                || x == n::RECORD_NAME_MASM
                || x == n::RECORD_NAME_MASM32
                || x == n::RECORD_NAME_NASM =>
            {
                Some(n::RECORD_NAME_X86ASSEMBLER)
            }
            x if x == n::RECORD_NAME_AUTOIT => Some(n::RECORD_NAME_AUTOIT),
            x if x == n::RECORD_NAME_OBJECTPASCAL
                || x == n::RECORD_NAME_LAZARUS
                || x == n::RECORD_NAME_FPC
                || x == n::RECORD_NAME_VIRTUALPASCAL
                || x == n::RECORD_NAME_IBMPCPASCAL =>
            {
                Some(n::RECORD_NAME_OBJECTPASCAL)
            }
            x if x == n::RECORD_NAME_BORLANDDELPHI
                || x == n::RECORD_NAME_BORLANDDELPHIDOTNET
                || x == n::RECORD_NAME_BORLANDOBJECTPASCALDELPHI
                || x == n::RECORD_NAME_CODEGEARDELPHI
                || x == n::RECORD_NAME_CODEGEAROBJECTPASCALDELPHI
                || x == n::RECORD_NAME_EMBARCADERODELPHI
                || x == n::RECORD_NAME_EMBARCADERODELPHIDOTNET
                || x == n::RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI =>
            {
                Some(n::RECORD_NAME_OBJECTPASCALDELPHI)
            }
            x if x == n::RECORD_NAME_D
                || x == n::RECORD_NAME_DMD
                || x == n::RECORD_NAME_DMD32
                || x == n::RECORD_NAME_LDC =>
            {
                Some(n::RECORD_NAME_D)
            }
            x if x == n::RECORD_NAME_CSHARP || x == n::RECORD_NAME_DOTNET => {
                Some(n::RECORD_NAME_CSHARP)
            }
            x if x == n::RECORD_NAME_GO => Some(n::RECORD_NAME_GO),
            x if x == n::RECORD_NAME_JAVA
                || x == n::RECORD_NAME_JVM
                || x == n::RECORD_NAME_JDK
                || x == n::RECORD_NAME_OPENJDK
                || x == n::RECORD_NAME_IBMJDK
                || x == n::RECORD_NAME_APPLEJDK =>
            {
                Some(n::RECORD_NAME_JAVA)
            }
            x if x == n::RECORD_NAME_JSCRIPT => Some(n::RECORD_NAME_ECMASCRIPT),
            x if x == n::RECORD_NAME_KOTLIN => Some(n::RECORD_NAME_KOTLIN),
            x if x == n::RECORD_NAME_FORTRAN || x == n::RECORD_NAME_LAYHEYFORTRAN90 => {
                Some(n::RECORD_NAME_FORTRAN)
            }
            x if x == n::RECORD_NAME_NIM => Some(n::RECORD_NAME_NIM),
            x if x == n::RECORD_NAME_OBJECTIVEC => Some(n::RECORD_NAME_OBJECTIVEC),
            x if x == n::RECORD_NAME_BASIC
                || x == n::RECORD_NAME_BASIC4ANDROID
                || x == n::RECORD_NAME_POWERBASIC
                || x == n::RECORD_NAME_PUREBASIC
                || x == n::RECORD_NAME_TURBOBASIC
                || x == n::RECORD_NAME_VBNET
                || x == n::RECORD_NAME_VISUALBASIC =>
            {
                Some(n::RECORD_NAME_BASIC)
            }
            x if x == n::RECORD_NAME_RUST => Some(n::RECORD_NAME_RUST),
            x if x == n::RECORD_NAME_RUBY => Some(n::RECORD_NAME_RUBY),
            x if x == n::RECORD_NAME_PYTHON || x == n::RECORD_NAME_PYINSTALLER => {
                Some(n::RECORD_NAME_PYTHON)
            }
            x if x == n::RECORD_NAME_SWIFT => Some(n::RECORD_NAME_SWIFT),
            x if x == n::RECORD_NAME_PERL => Some(n::RECORD_NAME_PERL),
            x if x == n::RECORD_NAME_PHP => Some(n::RECORD_NAME_PHP),
            x if x == n::RECORD_NAME_ZIG => Some(n::RECORD_NAME_ZIG),
            x if x == n::RECORD_NAME_QML => Some(n::RECORD_NAME_QML),
            _ => None,
        };
        if let Some(lname) = lang {
            let mut ss = rec.clone();
            ss.rtype = rt::RECORD_TYPE_LANGUAGE;
            ss.name = lname;
            ss.info.clear();
            ss.version.clear();
            langs.insert(ss.name, ss);
        }
    }
}

/// `fixLanguage` — merge C and C++ into the C/C++ record.
fn fix_language(langs: &mut DetectMap) {
    if langs.contains_key(&n::RECORD_NAME_C)
        && langs.contains_key(&n::RECORD_NAME_CPP)
        && let Some(mut ss) = langs.get(&n::RECORD_NAME_C).cloned()
    {
        ss.name = n::RECORD_NAME_CCPP;
        langs.insert(ss.name, ss);
    }
    if langs.contains_key(&n::RECORD_NAME_C) && langs.contains_key(&n::RECORD_NAME_CCPP) {
        langs.remove(&n::RECORD_NAME_C);
    }
    if langs.contains_key(&n::RECORD_NAME_CPP) && langs.contains_key(&n::RECORD_NAME_CCPP) {
        langs.remove(&n::RECORD_NAME_CPP);
    }
}

/// `_handleResult` — language aggregation, fixup, then ordered drain of
/// every result map.
pub fn handle_result(res: &mut ResultMaps) -> Vec<ScanRecord> {
    // Order of aggregation sources matches upstream: linkers, compilers,
    // libraries, tools, packers.
    get_language(&res.linkers, &mut res.languages);
    get_language(&res.compilers, &mut res.languages);
    get_language(&res.libraries, &mut res.languages);
    get_language(&res.tools, &mut res.languages);
    get_language(&res.packers, &mut res.languages);
    fix_language(&mut res.languages);
    res.ordered_values().into_iter().cloned().collect()
}

//! Scan dispatch and result assembly, mirroring
//! `SpecAbstract::_processDetect` and the per-format `getInfo` drivers.
//!
//! Scope note: the upstream `handle_*` heuristic fixups (version
//! enrichment, cross-record inference) are not yet ported; records carry
//! their static table version/info. This is the table-driven core.

use diec_core::signature::{match_signature, parse_signature};

use crate::gen_names::{FT_STR, RECORD_NAME_STR, RECORD_TYPE_STR, ft, name, rtype};
use crate::gen_tables as t;
use crate::parse;
use crate::pe;
use crate::records::SignatureRecord;
use crate::scans::{
    DetectMap, ScanRecord, archive_exp_scan, archive_scan, const_scan, msrich_scan, signature_scan,
    string_scan,
};
use crate::signature::get_signature;

/// One emitted detection (normalized `SCANSTRUCT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// `RECORD_TYPE` display string (e.g. `"Packer"`).
    pub record_type: &'static str,
    /// `RECORD_NAME` display string (e.g. `"UPX"`).
    pub record_name: &'static str,
    /// Version string.
    pub version: String,
    /// Info string.
    pub info: String,
    /// Whether this record is heuristic-only.
    pub heuristic: bool,
    /// Whether this is the synthetic Unknown record.
    pub unknown: bool,
}

/// Scan options mirroring the subset of `XScanEngine::SCAN_OPTIONS` that
/// the ported paths consult.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanOptions {
    /// Deep scan: enables whole-section memory scans.
    pub deep_scan: bool,
}

fn to_detection(r: &ScanRecord) -> Detection {
    Detection {
        record_type: RECORD_TYPE_STR
            .get(r.rtype as usize)
            .copied()
            .unwrap_or("Unknown"),
        record_name: RECORD_NAME_STR
            .get(r.name as usize)
            .copied()
            .unwrap_or("Unknown"),
        version: r.version.clone(),
        info: r.info.clone(),
        heuristic: r.heuristic,
        unknown: r.unknown,
    }
}

/// Collect a detect map into detections.
fn drain(map: &DetectMap, out: &mut Vec<Detection>) {
    let mut v: Vec<&ScanRecord> = map.values().collect();
    v.sort_by_key(|r| r.name);
    out.extend(v.into_iter().map(to_detection));
}

fn exp_match(data: &[u8], sig: &str, offset: usize) -> bool {
    let Ok(elements) = parse_signature(sig) else {
        return false;
    };
    match_signature(data, offset, &elements)
}

/// Port of `NFD_Binary::signatureExpScan`: `compareSignature` at an
/// absolute offset for every matching record.
fn signature_exp_scan(
    map: &mut DetectMap,
    data: &[u8],
    offset: usize,
    records: &[SignatureRecord],
    ft1: u16,
    ft2: u16,
) {
    for rec in records {
        if (rec.basic.ft != ft1 && rec.basic.ft != ft2) || map.contains_key(&rec.basic.name) {
            continue;
        }
        if exp_match(data, rec.signature, offset) {
            map.insert(rec.basic.name, ScanRecord::from_basic(&rec.basic));
        }
    }
}

/// Port of `NFD_Binary::memoryScan`: find each signature anywhere inside
/// `[offset, offset+size)`.
fn memory_scan(
    map: &mut DetectMap,
    data: &[u8],
    offset: usize,
    size: usize,
    records: &[SignatureRecord],
    ft1: u16,
    ft2: u16,
) {
    if size == 0 {
        return;
    }
    let end = offset.saturating_add(size).min(data.len());
    if offset >= end {
        return;
    }
    for rec in records {
        if (rec.basic.ft != ft1 && rec.basic.ft != ft2) || map.contains_key(&rec.basic.name) {
            continue;
        }
        let Ok(elements) = parse_signature(rec.signature) else {
            continue;
        };
        let n = elements.len();
        if n == 0 || end - offset < n {
            continue;
        }
        for i in offset..=end - n {
            if match_signature(data, i, &elements) {
                map.insert(rec.basic.name, ScanRecord::from_basic(&rec.basic));
                break;
            }
        }
    }
}

/// Sniff the broad file class from magic bytes. Mirrors the dispatch in
/// `SpecAbstract::_processDetect`; callers may override with a real
/// format detection.
pub fn sniff_ft(data: &[u8]) -> u16 {
    if data.len() >= 4 {
        if data.starts_with(b"MZ") {
            // e_lfanew points at the secondary signature: PE\0\0 for
            // Win32, NE/LX/LE for the 16/32-bit OS/2-DOS families.
            if data.len() > 0x40 {
                let pe_off =
                    u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
                match data.get(pe_off..pe_off + 2) {
                    Some(b"PE") if data.get(pe_off + 2..pe_off + 4) == Some(b"\0\0") => {
                        let magic_off = pe_off + 24;
                        return match data.get(magic_off..magic_off + 2) {
                            Some(&[0x0B, 0x01]) => ft::FT_PE32,
                            Some(&[0x0B, 0x02]) => ft::FT_PE64,
                            _ => ft::FT_MSDOS,
                        };
                    }
                    Some(b"NE") => return ft::FT_NE,
                    Some(b"LX") => return ft::FT_LX,
                    Some(b"LE") => return ft::FT_LE,
                    _ => {}
                }
            }
            return ft::FT_MSDOS;
        }
        if data.starts_with(b"\x7FELF") {
            return match data.get(4) {
                Some(1) => ft::FT_ELF32,
                Some(2) => ft::FT_ELF64,
                _ => ft::FT_ELF,
            };
        }
        if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
            return ft::FT_ZIP;
        }
        if data.starts_with(b"dex\n") {
            return ft::FT_DEX;
        }
        match data.get(..4) {
            // Thin Mach-O (stored byte order).
            Some([0xCE, 0xFA, 0xED, 0xFE]) | Some([0xFE, 0xED, 0xFA, 0xCE]) => {
                return ft::FT_MACHO32;
            }
            Some([0xCF, 0xFA, 0xED, 0xFE]) | Some([0xFE, 0xED, 0xFA, 0xCF]) => {
                return ft::FT_MACHO64;
            }
            _ => {}
        }
        if data.starts_with(b"\xCA\xFE\xBA\xBE") || data.starts_with(b"\xCA\xFE\xBA\xBF") {
            // Mach-O FAT vs Java Class — `XBinary::getFileTypeId` runs
            // the FAT record validity walk first, then falls back to the
            // JAVACLASS u32be@4 > 10 check.
            if parse::macho_fat_valid(data) {
                return ft::FT_MACHOFAT;
            }
            if data
                .get(4..8)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                .is_some_and(|v| v > 10)
            {
                return ft::FT_JAVACLASS;
            }
            return ft::FT_BINARY;
        }
        if data.starts_with(b"%PDF") {
            return ft::FT_PDF;
        }
        if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return ft::FT_JPEG;
        }
        if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
            return ft::FT_CFBF;
        }
    }
    ft::FT_BINARY
}

/// [`sniff_ft`] plus filename-derived types: `.com` (bounded DOS COM
/// images), `.apk` and `.jar` ZIP subtypes.
pub fn sniff_ft_named(data: &[u8], file_name: &str) -> u16 {
    let lower = file_name.to_ascii_lowercase();
    // COM images have no signature; upstream requires the .com suffix
    // and a <=64 KiB image (DOS COM loading model). Only generic types
    // (MZ-less BINARY or a bare MZ stub) are reclassified.
    let ft = sniff_ft(data);
    if lower.ends_with(".com")
        && data.len() <= 0x10000
        && (ft == ft::FT_BINARY || ft == ft::FT_MSDOS)
    {
        return ft::FT_COM;
    }
    match ft {
        x if x == ft::FT_MSDOS => ft::FT_MSDOS,
        x if x == ft::FT_ZIP => {
            if lower.ends_with(".apk") {
                ft::FT_APK
            } else if lower.ends_with(".jar") {
                ft::FT_JAR
            } else {
                ft::FT_ZIP
            }
        }
        x => x,
    }
}

/// Scan `data` with the NFD engine. `hint_ft` is a `gen_names::ft::*`
/// index (use [`sniff_ft`] when unknown).
///
/// The return order follows upstream `_handleResult` category ordering.
pub fn scan(data: &[u8], hint_ft: u16, opts: ScanOptions) -> Vec<Detection> {
    let file_type = hint_ft;
    let header_sig = get_signature(data, 0, 150);

    let mut header: DetectMap = DetectMap::new();
    let mut overlay: DetectMap = DetectMap::new();
    let mut entrypoint: DetectMap = DetectMap::new();
    let mut section_names: DetectMap = DetectMap::new();
    let mut imports: DetectMap = DetectMap::new();
    let mut resources: DetectMap = DetectMap::new();
    let mut code_section: DetectMap = DetectMap::new();
    let mut ep_section: DetectMap = DetectMap::new();
    let mut strings_m: DetectMap = DetectMap::new();
    let mut types_m: DetectMap = DetectMap::new();
    let mut archive_m: DetectMap = DetectMap::new();
    let mut misc: DetectMap = DetectMap::new();

    // Header scans run for every file (binary + archive tables filter on
    // FT_BINARY/FT_ARCHIVE which are always the secondary ft).
    signature_scan(
        &mut header,
        &header_sig,
        t::G_BINARY_RECORDS,
        file_type,
        ft::FT_BINARY,
    );
    if file_type == ft::FT_BINARY && parse::is_plain_text(data) {
        // NFD_Binary::handle_Texts — format record "Plain text"/
        // "UTF-8 text" with the line-ending info. The C++/script regex
        // heuristics of handle_Texts are not ported.
        let mut rec = ScanRecord::from_basic(&crate::records::BasicRecord {
            variant: 0,
            ft: ft::FT_BINARY,
            rtype: rtype::RECORD_TYPE_FORMAT,
            name: name::RECORD_NAME_PLAIN,
            version: "",
            info: "",
        });
        let head = &data[..data.len().min(4096)];
        rec.info = if let Some(lf) = head.iter().position(|&b| b == b'\n') {
            let crlf =
                (lf > 0 && head[lf - 1] == b'\r') || (lf + 1 < head.len() && head[lf + 1] == b'\r');
            if crlf {
                "CRLF".to_string()
            } else {
                "LF".to_string()
            }
        } else if head.contains(&b'\r') {
            "CR".to_string()
        } else {
            String::new()
        };
        header.insert(name::RECORD_NAME_PLAIN, rec);
    }
    signature_scan(
        &mut header,
        &header_sig,
        t::G_ARCHIVE_RECORDS,
        file_type,
        ft::FT_ARCHIVE,
    );

    match file_type {
        x if x == ft::FT_PE32 || x == ft::FT_PE64 => {
            pe_scan(
                data,
                opts,
                &mut misc,
                &header_sig,
                &mut header,
                &mut overlay,
                &mut entrypoint,
                &mut section_names,
                &mut imports,
                &mut resources,
                &mut code_section,
                &mut ep_section,
            );
        }
        x if x == ft::FT_MSDOS => {
            msdos_scan(
                data,
                opts,
                &header_sig,
                &mut header,
                &mut entrypoint,
                &mut misc,
            );
        }
        x if x == ft::FT_COM => {
            // NFD_COM::getInfo — header signatures at 0 plus the
            // expression records, both into the header map.
            signature_scan(
                &mut header,
                &header_sig,
                t::G_COM_RECORDS,
                file_type,
                ft::FT_COM,
            );
            signature_exp_scan(
                &mut header,
                data,
                0,
                t::G_COM_EXP_RECORDS,
                file_type,
                ft::FT_COM,
            );
        }
        x if x == ft::FT_NE => {
            // NFD_NE::getInfo — linker header records plus entry-point
            // signatures at the CS:IP-derived offset.
            signature_scan(
                &mut header,
                &header_sig,
                t::G_MSDOS_LINKER_HEADER_RECORDS,
                file_type,
                ft::FT_MSDOS,
            );
            if let Some(ep_off) = parse::ne_entry_offset(data) {
                let ep_sig = get_signature(data, ep_off, 150);
                signature_scan(
                    &mut entrypoint,
                    &ep_sig,
                    t::G_NE_ENTRYPOINT_RECORDS,
                    file_type,
                    ft::FT_NE,
                );
            }
        }
        x if x == ft::FT_LE || x == ft::FT_LX => {
            // NFD_LE/NFD_LX::getInfo — header linker records (the rest of
            // each module is heuristic fixup, not yet ported).
            signature_scan(
                &mut header,
                &header_sig,
                t::G_MSDOS_LINKER_HEADER_RECORDS,
                file_type,
                ft::FT_MSDOS,
            );
        }
        x if x == ft::FT_ELF32 || x == ft::FT_ELF64 || x == ft::FT_ELF => {
            // NFD_ELF::getInfo — entry-point signatures plus the
            // semantic handlers (OS, .comment toolchain strings, GCC
            // fixup, debug data, tools).
            if let Some(ep_off) = parse::elf_entry_offset(data) {
                let ep_sig = get_signature(data, ep_off, 150);
                signature_scan(
                    &mut entrypoint,
                    &ep_sig,
                    t::G_ELF_ENTRYPOINT_RECORDS,
                    file_type,
                    ft::FT_ELF,
                );
            }
            crate::elf::elf_semantic_scan(data, ft::FT_ELF, &mut misc);
        }
        x if x == ft::FT_MACHO32 || x == ft::FT_MACHO64 || x == ft::FT_MACHO => {
            // NFD_MACH::getInfo — load-command driven semantic handlers.
            crate::mach::mach_semantic_scan(data, ft::FT_MACHO, &mut misc);
        }
        x if x == ft::FT_DEX => {
            // NFD_DEX::getInfo — string-id contents and type descriptors.
            let (strings, types) = parse::dex_strings(data);
            string_scan(
                &mut strings_m,
                &strings,
                t::G_DEX_STRING_RECORDS,
                file_type,
                ft::FT_DEX,
            );
            string_scan(
                &mut types_m,
                &types,
                t::G_DEX_TYPE_RECORDS,
                file_type,
                ft::FT_DEX,
            );
        }
        x if x == ft::FT_APK => {
            // NFD_APK::getInfo — member-name CRC scan and regex scan over
            // the ZIP central directory names.
            let names = parse::zip_member_names(data);
            archive_scan(
                &mut archive_m,
                &names,
                t::G_APK_FILE_RECORDS,
                file_type,
                ft::FT_APK,
            );
            archive_exp_scan(
                &mut archive_m,
                &names,
                t::G_APK_FILEEXP_RECORDS,
                file_type,
                ft::FT_APK,
            );

            // `NFD_APK::getInfo` — APK Signature Scheme block ids.
            // `0x7109871a`=v2, `0xf05368c0`=v3 (mutually exclusive),
            // `0x71777777`=Walle, `0x2146444e`=Google Play
            // (`XAPK::getAPKSignaturesBlockRecordsList`).
            let ids = parse::apk_sig_block_ids(data);
            let emit = |misc: &mut DetectMap, rtype_id: u8, name_id: u16, ver: &'static str| {
                misc.entry(name_id).or_insert_with(|| {
                    ScanRecord::from_basic(&crate::records::BasicRecord {
                        variant: 0,
                        ft: ft::FT_APK,
                        rtype: rtype_id,
                        name: name_id,
                        version: ver,
                        info: "",
                    })
                });
            };
            // Upstream emits a single signtool record: v2 if present,
            // else v3.
            if ids.contains(&0x7109_871A) {
                emit(
                    &mut misc,
                    rtype::RECORD_TYPE_SIGNTOOL,
                    name::RECORD_NAME_APKSIGNATURESCHEME,
                    "v2",
                );
            } else if ids.contains(&0xF053_68C0) {
                emit(
                    &mut misc,
                    rtype::RECORD_TYPE_SIGNTOOL,
                    name::RECORD_NAME_APKSIGNATURESCHEME,
                    "v3",
                );
            }
            if ids.contains(&0x7177_7777) {
                emit(
                    &mut misc,
                    rtype::RECORD_TYPE_TOOL,
                    name::RECORD_NAME_WALLE,
                    "",
                );
            }
            if ids.contains(&0x2146_444E) {
                emit(
                    &mut misc,
                    rtype::RECORD_TYPE_TOOL,
                    name::RECORD_NAME_GOOGLEPLAY,
                    "",
                );
            }
            // Language: Kotlin iff `META-INF/androidx.core_core-ktx.version`
            // or `kotlin/kotlin.kotlin_builtins` is present, else Java.
            let kotlin = names.iter().any(|n| {
                n == "META-INF/androidx.core_core-ktx.version"
                    || n == "kotlin/kotlin.kotlin_builtins"
            });
            emit(
                &mut misc,
                rtype::RECORD_TYPE_LANGUAGE,
                if kotlin {
                    name::RECORD_NAME_KOTLIN
                } else {
                    name::RECORD_NAME_JAVA
                },
                "",
            );
            // `XAPK::getFileFormatInfo` — every APK is an Android image.
            emit(
                &mut misc,
                rtype::RECORD_TYPE_OPERATIONSYSTEM,
                name::RECORD_NAME_ANDROID,
                "",
            );
        }
        _ => {}
    }

    // Post-dispatch fixups mirroring the cheap container metadata of
    // `NFD_ZIP::handle_Container` and `NFD_PDF::getInfo` format versions.
    zip_container_fixup(data, file_type, &mut header);
    pdf_version_fixup(data, file_type, &mut header);

    // Assembly order mirrors `_handleResult` (formats first for the
    // binary path is an approximation — upstream sorts result maps by
    // fixed category order).
    let mut out = Vec::new();
    drain(&header, &mut out);
    drain(&overlay, &mut out);
    drain(&entrypoint, &mut out);
    drain(&imports, &mut out);
    drain(&resources, &mut out);
    drain(&section_names, &mut out);
    drain(&code_section, &mut out);
    drain(&ep_section, &mut out);
    drain(&archive_m, &mut out);
    drain(&strings_m, &mut out);
    drain(&types_m, &mut out);
    drain(&misc, &mut out);
    out
}

/// PE scan pipeline: header records, entry-point signature + expression
/// scans (with NOP/JZ/E9-follow loop), overlay, imports hashes, resource
/// names, section names and optional deep section scans.
#[allow(clippy::too_many_arguments)]
fn pe_scan(
    data: &[u8],
    opts: ScanOptions,
    misc: &mut DetectMap,
    header_sig: &str,
    header: &mut DetectMap,
    overlay: &mut DetectMap,
    entrypoint: &mut DetectMap,
    section_names: &mut DetectMap,
    imports: &mut DetectMap,
    resources: &mut DetectMap,
    code_section: &mut DetectMap,
    ep_section: &mut DetectMap,
) {
    let Some(pe) = pe::collect(data) else {
        return;
    };
    let ftpe = ft::FT_PE;
    let actual = if pe.is64 { ft::FT_PE64 } else { ft::FT_PE32 };

    signature_scan(header, header_sig, t::PE_HEADER_RECORDS, actual, ftpe);
    signature_scan(
        header,
        header_sig,
        t::G_MSDOS_LINKER_HEADER_RECORDS,
        actual,
        ft::FT_MSDOS,
    );

    // Entry-point signature + follow loop (NOP / JZ 00 / JZ 01 / JMP rel32).
    if pe.entry_point_offset >= 0 {
        let ep = pe.entry_point_offset as usize;
        let mut ep_sig = get_signature(data, ep, 150);
        signature_scan(entrypoint, &ep_sig, t::PE_ENTRYPOINT_RECORDS, actual, ftpe);

        let mut n_offset: usize = 0;
        loop {
            let mut cont = false;
            if crate::signature::compare_signature_strings(&ep_sig, "90") {
                cont = true;
                n_offset += 1;
                ep_sig = ep_sig[2..].to_string();
            }
            if crate::signature::compare_signature_strings(&ep_sig, "7500") {
                cont = true;
                n_offset += 2;
                ep_sig = ep_sig[4..].to_string();
            }
            if crate::signature::compare_signature_strings(&ep_sig, "7501") {
                cont = true;
                n_offset += 3;
                ep_sig = ep_sig[6..].to_string();
            }
            if crate::signature::compare_signature_strings(&ep_sig, "E9") {
                cont = true;
                n_offset += 1;
                ep_sig = ep_sig[2..].to_string();
                // hexToInt32 reads the next 4 bytes little-endian.
                if ep_sig.len() < 8 {
                    break;
                }
                let raw = u32::from_str_radix(&ep_sig[..8], 16).unwrap_or(0);
                let addr = i32::from_le_bytes(raw.to_be_bytes());
                n_offset += 4;
                let Some(pe_layout) = pe::collect_layout(data) else {
                    break;
                };
                let target_rva = pe_layout
                    .entry_rva
                    .wrapping_add(n_offset as u32)
                    .wrapping_add(addr as u32);
                match pe::rva_to_off_pub(&pe_layout, target_rva) {
                    Some(o) => ep_sig = get_signature(data, o, 150),
                    None => break,
                }
            }
            if n_offset != 0 {
                signature_scan(entrypoint, &ep_sig, t::PE_ENTRYPOINT_RECORDS, actual, ftpe);
                signature_exp_scan(
                    entrypoint,
                    data,
                    ep + n_offset,
                    t::PE_ENTRYPOINTEXP_RECORDS,
                    actual,
                    ftpe,
                );
            }
            if n_offset > 20 || !cont {
                break;
            }
        }
    }

    // Overlay scans.
    if pe.overlay_offset >= 0 {
        let ov_sig = get_signature(data, pe.overlay_offset as usize, 150);
        signature_scan(overlay, &ov_sig, t::G_BINARY_RECORDS, actual, ft::FT_BINARY);
        signature_scan(
            overlay,
            &ov_sig,
            t::G_ARCHIVE_RECORDS,
            actual,
            ft::FT_ARCHIVE,
        );
        signature_scan(overlay, &ov_sig, t::G_PE_OVERLAY_RECORDS, actual, ftpe);
    }

    // Import hashes.
    let hash64: u64 = pe
        .imports
        .iter()
        .map(|r| {
            u64::from(crate::signature::string_custom_crc32(&format!(
                "{} {}",
                r.library, r.function
            )))
        })
        .sum();
    let joined: String = pe
        .imports
        .iter()
        .map(|r| format!("{}{}", r.library, r.function))
        .collect();
    let hash32 = crate::signature::string_custom_crc32(&joined);
    const_scan(
        imports,
        hash64,
        u64::from(hash32),
        t::PE_IMPORTHASH_RECORDS,
        actual,
        ftpe,
    );
    const_scan(
        imports,
        hash64,
        u64::from(hash32),
        t::PE_IMPORTHASH_RECORDS_ARMADILLO,
        actual,
        ftpe,
    );
    for h in &pe.import_headers {
        // Position hash: per-library function string concat; upstream
        // appends library name only when bLibraryName (false here).
        let s: String = h.positions.concat();
        let crc = crate::signature::string_custom_crc32(&s);
        const_scan(
            imports,
            0,
            u64::from(crc),
            t::PE_IMPORTPOSITIONHASH_RECORDS,
            actual,
            ftpe,
        );
    }

    // Section-name string scan.
    string_scan(
        section_names,
        &pe.section_names,
        t::PE_SECTIONNAMES_RECORDS,
        actual,
        ftpe,
    );

    // Resource scan (name/id pairs flattened from the resource tree).
    let res = pe::collect_resources(data);
    if !res.is_empty() {
        crate::scans::resources_scan(resources, &res, t::PE_RESOURCES_RECORDS, actual, ftpe);
    }

    // Rich records -> MSDOS table (upstream reuses it for PE).
    if !pe.rich.is_empty() {
        let entries: Vec<crate::scans::MsRichEntry> = pe
            .rich
            .iter()
            .map(|&(id, build, _count)| crate::scans::MsRichEntry { id, build })
            .collect();
        msrich_scan(header, &entries, t::G_MS_RICH_RECORDS, actual, ftpe);
    }

    // Deep scans over code / entrypoint sections.
    if opts.deep_scan {
        if let Some((off, size)) = pe.code_section_extent(data) {
            memory_scan(
                code_section,
                data,
                off,
                size,
                t::PE_CODESECTION_RECORDS,
                actual,
                ftpe,
            );
            if pe.is_dotnet {
                memory_scan(
                    code_section,
                    data,
                    off,
                    size,
                    t::PE_DOT_CODESECTION_RECORDS,
                    actual,
                    ftpe,
                );
            }
        }
        if let Some((off, size)) = pe.entrypoint_section_extent(data) {
            memory_scan(
                ep_section,
                data,
                off,
                size,
                t::PE_ENTRYPOINTSECTION_RECORDS,
                actual,
                ftpe,
            );
        }
    }

    // Semantic handlers (bounded handle_* subset).
    crate::pe_handlers::operation_system(&pe, ftpe, misc);
    crate::pe_handlers::import_heuristics(&pe, ftpe, imports);
    crate::pe_handlers::debug_data(data, &pe, ftpe, misc);
    crate::pe_handlers::microsoft(data, &pe, opts.deep_scan, ftpe, header, entrypoint, misc);
}

/// MSDOS scan pipeline: linker-header + header records, entry-point
/// signature and expression scans.
fn msdos_scan(
    data: &[u8],
    opts: ScanOptions,
    header_sig: &str,
    header: &mut DetectMap,
    entrypoint: &mut DetectMap,
    misc: &mut DetectMap,
) {
    signature_scan(
        header,
        header_sig,
        t::G_MSDOS_LINKER_HEADER_RECORDS,
        ft::FT_MSDOS,
        ft::FT_MSDOS,
    );
    signature_scan(
        header,
        header_sig,
        t::G_MSDOS_HEADER_RECORDS,
        ft::FT_MSDOS,
        ft::FT_MSDOS,
    );

    // MZ entry point: header_paragraphs*16 + CS*16 + IP.
    let ep_off = (|| {
        let hdr = usize::from(u16::from_le_bytes([*data.get(0x08)?, *data.get(0x09)?])) * 16;
        let ip = usize::from(u16::from_le_bytes([*data.get(0x14)?, *data.get(0x15)?]));
        let cs = usize::from(u16::from_le_bytes([*data.get(0x16)?, *data.get(0x17)?]));
        Some(hdr + cs * 16 + ip)
    })();
    let Some(ep_off) = ep_off else { return };
    if ep_off >= data.len() {
        return;
    }
    let ep_sig = get_signature(data, ep_off, 150);
    signature_scan(
        entrypoint,
        &ep_sig,
        t::G_MSDOS_ENTRYPOINT_RECORDS,
        ft::FT_MSDOS,
        ft::FT_MSDOS,
    );
    signature_exp_scan(
        entrypoint,
        data,
        ep_off,
        t::G_MSDOS_ENTRYPOINTEXP_RECORDS,
        ft::FT_MSDOS,
        ft::FT_MSDOS,
    );

    msdos_extender_scan(data, opts, misc);
    msdos_vintage_scan(data, opts, misc);
}

/// `NFD_MSDOS::handle_DosExtenders` — DOS extender banners:
/// WDOSX at 0x34 (always), CWSDPMI/DOS4G/DOS16M on deep scan only.
fn msdos_extender_scan(data: &[u8], opts: ScanOptions, misc: &mut DetectMap) {
    // WDOSX: ANSI banner at fixed offset 0x34 ("WDOSX <ver>").
    let wdosx =
        parse::read_ansi_string(data, 0x34).filter(|b| b.split(' ').next() == Some("WDOSX"));
    if let Some(banner) = wdosx {
        let ver = banner.split(' ').nth(1).unwrap_or("").to_string();
        misc.entry(name::RECORD_NAME_WDOSX).or_insert_with(|| {
            let mut r = ScanRecord::from_basic(&crate::records::BasicRecord {
                variant: 0,
                ft: ft::FT_MSDOS,
                rtype: rtype::RECORD_TYPE_DOSEXTENDER,
                name: name::RECORD_NAME_WDOSX,
                version: "",
                info: "",
            });
            r.version = ver;
            r
        });
    }
    if !opts.deep_scan {
        return;
    }
    // CWSDPMI: banner inside the first 0x100 bytes.
    let cwsdpmi = parse::find_ansi(data, 0, 0x100, b"CWSDPMI")
        .and_then(|off| parse::read_ansi_string(data, off))
        .filter(|b| b.split(' ').next() == Some("CWSDPMI"));
    if let Some(banner) = cwsdpmi {
        let ver = banner.split(' ').nth(1).unwrap_or("").to_string();
        misc.entry(name::RECORD_NAME_CWSDPMI).or_insert_with(|| {
            let mut r = ScanRecord::from_basic(&crate::records::BasicRecord {
                variant: 0,
                ft: ft::FT_MSDOS,
                rtype: rtype::RECORD_TYPE_DOSEXTENDER,
                name: name::RECORD_NAME_CWSDPMI,
                version: "",
                info: "",
            });
            r.version = ver;
            r
        });
    }
    // DOS/4G and DOS/16M markers in the first 4 KiB.
    let limit = data.len().min(0x1000);
    if parse::find_ansi(data, 0, limit, b"DOS/4G").is_some() {
        misc.entry(name::RECORD_NAME_DOS4G).or_insert_with(|| {
            ScanRecord::from_basic(&crate::records::BasicRecord {
                variant: 0,
                ft: ft::FT_MSDOS,
                rtype: rtype::RECORD_TYPE_DOSEXTENDER,
                name: name::RECORD_NAME_DOS4G,
                version: "",
                info: "",
            })
        });
    }
    if parse::find_ansi(
        data,
        0,
        limit,
        b"DOS/16M Copyright (C) Tenberry Software Inc",
    )
    .is_some()
    {
        misc.entry(name::RECORD_NAME_DOS16M).or_insert_with(|| {
            ScanRecord::from_basic(&crate::records::BasicRecord {
                variant: 0,
                ft: ft::FT_MSDOS,
                rtype: rtype::RECORD_TYPE_DOSEXTENDER,
                name: name::RECORD_NAME_DOS16M,
                version: "",
                info: "",
            })
        });
    }
}

/// `NFD_MSDOS::handle_VintageCompilers` — vendor banner strings of
/// vintage runtime libraries (deep scan only). Order matters: more
/// specific strings first.
fn msdos_vintage_scan(data: &[u8], opts: ScanOptions, misc: &mut DetectMap) {
    if !opts.deep_scan {
        return;
    }
    const VINTAGE: &[(&str, u16, &str)] = &[
        ("pasuxm.pas", name::RECORD_NAME_MICROSOFTPASCAL, "1.00"),
        ("conuxm.pas", name::RECORD_NAME_MICROSOFTPASCAL, "2.00"),
        ("pasuxu.pas", name::RECORD_NAME_MICROSOFTFORTRAN, "3.3X"),
        ("PASFILEA", name::RECORD_NAME_MICROSOFTPASCAL, "4.00"),
        (
            "foruxm.pas",
            name::RECORD_NAME_MICROSOFTFORTRAN,
            "3.1X-3.2X",
        ),
        ("foruxu.pas", name::RECORD_NAME_MICROSOFTFORTRAN, "3.3X"),
        (
            "Must link with BCOM10.LIB",
            name::RECORD_NAME_MICROSOFTQUICKBASIC,
            "1.00",
        ),
        (
            "**COBOL: Attempt to use non-updated runtime module (COBRUN.EXE).",
            name::RECORD_NAME_MICROSOFTCOBOL,
            "1.12",
        ),
        (
            "Insufficient environment space to run COBOL",
            name::RECORD_NAME_MICROSOFTCOBOL,
            "3.00A",
        ),
        (
            "V1.1 CLEAR library.  Copyright 1983 by Digital Research.",
            name::RECORD_NAME_DIGITALRESEARCHC,
            "1.1",
        ),
        (
            "Proc: \"        \" not found ovl:",
            name::RECORD_NAME_DIGITALRESEARCHMTPASCAL,
            "3.1X",
        ),
        (
            "FREE Request Out-of-Range$",
            name::RECORD_NAME_DIGITALRESEARCHPLI86,
            "",
        ),
        ("$typeguard check failed", name::RECORD_NAME_OBERONM, "1.2"),
        (
            "Artek Ada Runtime Module (C) ",
            name::RECORD_NAME_ARTEKADA,
            "1.25",
        ),
        (
            "$stack overflow$heap overflow$function return error$",
            name::RECORD_NAME_LOGITECHMODULA2,
            "3.X",
        ),
    ];
    for &(s, name_id, ver) in VINTAGE {
        if misc.contains_key(&name_id) {
            continue;
        }
        if parse::find_ansi(data, 0, data.len(), s.as_bytes()).is_some() {
            let mut r = ScanRecord::from_basic(&crate::records::BasicRecord {
                variant: 0,
                ft: ft::FT_MSDOS,
                rtype: rtype::RECORD_TYPE_COMPILER,
                name: name_id,
                version: "",
                info: "",
            });
            r.version = ver.to_string();
            misc.insert(name_id, r);
        }
    }
}

/// True when the file has an NFD detection path beyond the generic
/// header scans (used by the engine to skip the pass cheaply).
pub fn supported_ft(file_type: u16) -> bool {
    matches!(file_type, x if x == ft::FT_PE32 || x == ft::FT_PE64 || x == ft::FT_MSDOS || x == ft::FT_BINARY || x == ft::FT_ARCHIVE)
        || file_type == ft::FT_ZIP
        || file_type == ft::FT_JAR
        || file_type == ft::FT_APK
        || file_type == ft::FT_ELF32
        || file_type == ft::FT_ELF64
        || file_type == ft::FT_MACHO32
        || file_type == ft::FT_MACHO64
        || file_type == ft::FT_DEX
        || file_type == ft::FT_JAVACLASS
        || file_type == ft::FT_PDF
        || file_type == ft::FT_JPEG
        || file_type == ft::FT_CFBF
        || file_type == ft::FT_COM
        || file_type == ft::FT_NE
        || file_type == ft::FT_LE
        || file_type == ft::FT_LX
}

/// Look up a `gen_names::name::*` constant id by display string.
pub fn name_id(display: &str) -> Option<u16> {
    RECORD_NAME_STR
        .iter()
        .position(|&s| s == display)
        .map(|i| i as u16)
}

/// Look up a `gen_names::rtype::*` id by display string.
pub fn rtype_id(display: &str) -> Option<u8> {
    RECORD_TYPE_STR
        .iter()
        .position(|&s| s == display)
        .map(|i| i as u8)
}

/// `FT_STR` entry name for a ft index (diagnostics).
pub fn ft_name(file_type: u16) -> &'static str {
    FT_STR
        .get(file_type as usize)
        .copied()
        .unwrap_or("FT_UNKNOWN")
}

/// `NFD_ZIP::handle_Container`: enrich the ZIP format record with the
/// inspected-entry count, the minimum reader version and the encryption
/// flag for ZIP-family containers (ZIP/APK/JAR/IPA/NPM).
fn zip_container_fixup(data: &[u8], file_type: u16, header: &mut DetectMap) {
    let is_zip_family = file_type == ft::FT_ZIP
        || file_type == ft::FT_APK
        || file_type == ft::FT_JAR
        || file_type == ft::FT_IPA
        || file_type == ft::FT_NPM;
    if !is_zip_family {
        return;
    }
    let members = parse::zip_members(data);
    if members.is_empty() {
        return;
    }
    let min_ver = members.iter().map(|m| m.version_needed).max().unwrap_or(0);
    let encrypted = members.iter().any(|m| m.encrypted);
    let mut info = format!("{} records inspected", members.len());
    if min_ver != 0 {
        info.push_str(&format!(
            ", Declared minimum reader version: {}.{} (inspected entries)",
            min_ver / 10,
            min_ver % 10
        ));
    }
    if encrypted {
        info.push_str(", Encrypted");
    }
    if let Some(rec) = header.get_mut(&name::RECORD_NAME_ZIP) {
        rec.info = info;
    }
}

/// `NFD_PDF::getInfo` format record: attach the `%PDF-X.Y` version to the
/// PDF format detection.
fn pdf_version_fixup(data: &[u8], file_type: u16, header: &mut DetectMap) {
    if file_type != ft::FT_PDF || !data.starts_with(b"%PDF-") {
        return;
    }
    let ver: String = data[5..data.len().min(16)]
        .iter()
        .take_while(|b| b.is_ascii_digit() || **b == b'.')
        .map(|b| *b as char)
        .collect();
    if ver.is_empty() {
        return;
    }
    if let Some(rec) = header.get_mut(&name::RECORD_NAME_PDF) {
        rec.version = ver;
    }
}

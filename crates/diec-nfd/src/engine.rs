//! Scan dispatch and result assembly, mirroring
//! `SpecAbstract::_processDetect` and the per-format `getInfo` drivers.
//!
//! Scope note: the upstream `handle_*` heuristic fixups (version
//! enrichment, cross-record inference) are not yet ported; records carry
//! their static table version/info. This is the table-driven core.

use diec_core::signature::{match_signature, parse_signature};

use crate::gen_names::{FT_STR, RECORD_NAME_STR, RECORD_TYPE_STR, ft};
use crate::gen_tables as t;
use crate::pe;
use crate::records::SignatureRecord;
use crate::scans::{DetectMap, ScanRecord, const_scan, msrich_scan, signature_scan, string_scan};
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
            // PE iff a sane e_lfanew + PE\0\0 signature.
            if data.len() > 0x40 {
                let pe_off =
                    u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
                if data.get(pe_off..pe_off + 4) == Some(b"PE\0\0") {
                    let magic_off = pe_off + 24;
                    return match data.get(magic_off..magic_off + 2) {
                        Some(&[0x0B, 0x01]) => ft::FT_PE32,
                        Some(&[0x0B, 0x02]) => ft::FT_PE64,
                        _ => ft::FT_MSDOS,
                    };
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
        if data.starts_with(b"\xCA\xFE\xBA\xBE") {
            return ft::FT_JAVACLASS;
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
        if data.starts_with(b"\x7F") && data.get(1..4) == Some(b"LE\0".as_slice()) {
            return ft::FT_LE;
        }
    }
    ft::FT_BINARY
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

    // Header scans run for every file (binary + archive tables filter on
    // FT_BINARY/FT_ARCHIVE which are always the secondary ft).
    signature_scan(
        &mut header,
        &header_sig,
        t::G_BINARY_RECORDS,
        file_type,
        ft::FT_BINARY,
    );
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
            msdos_scan(data, &header_sig, &mut header, &mut entrypoint);
        }
        _ => {}
    }

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
    out
}

/// PE scan pipeline: header records, entry-point signature + expression
/// scans (with NOP/JZ/E9-follow loop), overlay, imports hashes, resource
/// names, section names and optional deep section scans.
#[allow(clippy::too_many_arguments)]
fn pe_scan(
    data: &[u8],
    opts: ScanOptions,
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
}

/// MSDOS scan pipeline: linker-header + header records, entry-point
/// signature and expression scans.
fn msdos_scan(data: &[u8], header_sig: &str, header: &mut DetectMap, entrypoint: &mut DetectMap) {
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

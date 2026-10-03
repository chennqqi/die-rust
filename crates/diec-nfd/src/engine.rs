//! Scan dispatch and result assembly, mirroring
//! `SpecAbstract::_processDetect` and the per-format `getInfo` drivers.
//!
//! Scope note: the upstream `handle_*` heuristic fixups (version
//! enrichment, cross-record inference) are not yet ported; records carry
//! their static table version/info. This is the table-driven core.

use diec_core::signature::{SigCtx, match_signature_ctx, parse_signature};

use crate::gen_names::{FT_STR, RECORD_NAME_STR, RECORD_TYPE_STR, ft, name, rtype};
use crate::gen_tables as t;
use crate::parse;
use crate::pe;
use crate::records::SignatureRecord;
use crate::scans::{
    DetectMap, ResultMaps, ScanRecord, archive_exp_scan, archive_scan, const_scan, signature_scan,
    string_scan,
};
use crate::signature::get_signature;

/// One emitted detection (normalized `SCANSTRUCT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// `RECORD_TYPE` display string (e.g. `"Packer"`); `sType` override
    /// when the record carries one.
    pub record_type: std::borrow::Cow<'static, str>,
    /// `RECORD_NAME` display string (e.g. `"UPX"`); `sName` override
    /// when the record carries one (e.g. "UTF-8 text").
    pub record_name: std::borrow::Cow<'static, str>,
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
    /// Heuristic scan: enables the `bIsHeuristicScan` gated branches.
    pub heuristic_scan: bool,
    /// Verbose: emits OS/format records gated on `bIsVerbose`.
    pub verbose: bool,
    /// All-types scan (`bIsAllTypesScan`): JAR skips the ZIP container
    /// record, matching upstream.
    pub all_types: bool,
    /// Archives scan (`bIsArchivesScan`): unpack and scan ZIP members.
    pub archives_scan: bool,
    /// Recursive scan (`bIsRecursiveScan`): enables resource and overlay
    /// file parts.
    pub recursive_scan: bool,
    /// Resources scan (`bIsResourcesScan`): scan resource file parts.
    pub resources_scan: bool,
    /// Overlay scan (`bIsOverlayScan`): scan the overlay file part.
    pub overlay_scan: bool,
    /// Aggressive scan (`bIsAggressiveScan`): drops the `isScanable`
    /// gate on archive members.
    pub aggressive_scan: bool,
}

fn to_detection(r: &ScanRecord) -> Detection {
    // `XScanEngine::translateType`: strip `~`/`!` heuristic markers from
    // the sType override, then capitalize the first character.
    let stype = r.stype.map(|s| {
        let s = s.strip_prefix('~').unwrap_or(s);
        let s = s.strip_prefix('!').unwrap_or(s);
        let mut c = s.chars();
        match c.next() {
            Some(f) => std::borrow::Cow::Owned(format!("{}{}", f.to_uppercase(), c.as_str())),
            None => std::borrow::Cow::Owned(s.to_string()),
        }
    });
    Detection {
        record_type: stype
            .or_else(|| {
                RECORD_TYPE_STR
                    .get(r.rtype as usize)
                    .copied()
                    .map(std::borrow::Cow::Borrowed)
            })
            .unwrap_or(std::borrow::Cow::Borrowed("Unknown")),
        record_name: r
            .sname
            .clone()
            .or_else(|| {
                RECORD_NAME_STR
                    .get(r.name as usize)
                    .copied()
                    .map(std::borrow::Cow::Borrowed)
            })
            .unwrap_or(std::borrow::Cow::Borrowed("Unknown")),
        version: r.version.clone(),
        info: r.info.clone(),
        heuristic: r.heuristic,
        unknown: r.unknown,
    }
}

fn exp_match(data: &[u8], sig: &str, offset: usize, ctx: &SigCtx) -> bool {
    let Ok(elements) = parse_signature(sig) else {
        return false;
    };
    match_signature_ctx(data, offset, &elements, ctx)
}

/// `XMSDOS::_MEMORY_MAP` signature context: `$$` wraps inside the
/// current 16-bit segment and `#` resolves 2-byte values via
/// `nCodeBase` (0 upstream) and seg:off pairs via `nStartLoadOffset`.
fn msdos_sig_ctx(hdr: usize) -> SigCtx {
    let hdr = hdr as u64;
    SigCtx {
        // Post-header region mapped at segment address 0x10000000.
        off_to_addr: Some(Box::new(move |o| {
            (o >= hdr).then_some(0x1000_0000 + o - hdr)
        })),
        addr_to_off: Some(Box::new(move |a| {
            (a >= 0x1000_0000).then(|| a - 0x1000_0000 + hdr)
        })),
        seg_wrap16: true,
        msdos_addr: Some((0, hdr as i64)),
    }
}

/// `XBinary::compareSignature` entry with the file's detected memory
/// map: `$$`/`#` elements resolve through the format's address space
/// (PE section extents, COM image base, MSDOS segment map); all other
/// formats use flat offsets.
pub fn match_signature_mapped(
    data: &[u8],
    file_name: &str,
    offset: usize,
    elements: &[diec_core::signature::SigElement],
) -> bool {
    let ft = sniff_ft_named(data, file_name);
    let ctx = sig_ctx_for(data, ft);
    match_signature_ctx(data, offset, elements, &ctx)
}

/// Build the `SigCtx` for a detected file type.
pub fn sig_ctx_for(data: &[u8], ft: u16) -> SigCtx {
    if matches!(ft, x if x == ft::FT_PE || x == ft::FT_PE32 || x == ft::FT_PE64)
        && let Some(pe) = pe::collect(data)
    {
        return pe.sig_ctx();
    }
    if ft == ft::FT_MSDOS {
        let hdr = parse::rd_u16(data, 0x08).map_or(0, |v| usize::from(v) * 16);
        return msdos_sig_ctx(hdr);
    }
    if ft == ft::FT_COM {
        let com_code = data.len().min(0x10000 - 0x100) as u64;
        return SigCtx {
            off_to_addr: Some(Box::new(|o| o.checked_add(0x100))),
            addr_to_off: Some(Box::new(move |a| {
                (a >= 0x100 && a < 0x100 + com_code).then_some(a - 0x100)
            })),
            seg_wrap16: true,
            msdos_addr: None,
        };
    }
    SigCtx::flat()
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
    ctx: &SigCtx,
) {
    for rec in records {
        if (rec.basic.ft != ft1 && rec.basic.ft != ft2) || map.contains_key(&rec.basic.name) {
            continue;
        }
        if exp_match(data, rec.signature, offset, ctx) {
            map.insert(rec.basic.name, ScanRecord::from_basic(&rec.basic));
        }
    }
}

/// Port of `NFD_Binary::memoryScan`: find each signature anywhere inside
/// `[offset, offset+size)`.
#[allow(clippy::too_many_arguments)]
fn memory_scan(
    map: &mut DetectMap,
    data: &[u8],
    offset: usize,
    size: usize,
    records: &[SignatureRecord],
    ft1: u16,
    ft2: u16,
    ctx: &SigCtx,
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
            if match_signature_ctx(data, i, &elements, ctx) {
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
    // `XMSDOS::isValid` accepts a bare two-byte MZ/ZM magic.
    if data.len() >= 2 {
        if data.starts_with(b"MZ") || data.starts_with(b"ZM") {
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
            // `XELF::isValid` requires a known ELFCLASS byte; anything
            // else falls back to FT_BINARY.
            return match data.get(4) {
                Some(1) => ft::FT_ELF32,
                Some(2) => ft::FT_ELF64,
                _ => ft::FT_BINARY,
            };
        }
        if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
            return ft::FT_ZIP;
        }
        // `XDEX::isValid` — `compareSignature("'dex\n'......00")`:
        // `.` is a NIBBLE wildcard, so `......` covers bytes 4-6 and
        // `00` lands on offset 7 (the version-field NUL), then
        // `_getVersion() >= 35` (e.g. "035").
        if data.len() >= 8
            && data.starts_with(b"dex\n")
            && data[7] == 0
            && parse::dex_version(data).is_some_and(|v| v.parse::<u32>().unwrap_or(0) >= 35)
        {
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
        // `XAmigaHunk::isValid` — HUNK_HEADER (0x3F3) or HUNK_UNIT (0x3E7)
        // big-endian magic; upstream checks it in the executables group
        // once no other type claimed the file.
        if data.len() > 8 {
            match u32::from_be_bytes([data[0], data[1], data[2], data[3]]) {
                0x3E7 | 0x3F3 => return ft::FT_AMIGAHUNK,
                _ => {}
            }
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
        x if x == ft::FT_ZIP => zip_subtype(data),
        x => x,
    }
}

/// `XFormats::getFileTypesZIP` — content-based ZIP subtyping in upstream
/// order (APKS > APK > IPA > JAR). Extension is not consulted upstream;
/// a ZIP whose members match none of the rules stays `FT_ZIP`.
fn zip_subtype(d: &[u8]) -> u16 {
    const MANIFEST_LIMIT: u32 = 16 * 1024 * 1024;
    let members = parse::zip_members(d);
    // `XAPKS::isValid` — a member that is itself an .apk package.
    if members.iter().any(|m| m.name.ends_with(".apk")) {
        return ft::FT_APKS;
    }
    // Full `XAPK::isValid` / `XJAR::isValid` — the manifest member must
    // be non-empty and decompress to exactly its declared size.
    let manifest_ok = |name: &str| -> bool {
        let Some(m) = members
            .iter()
            .find(|m| m.name == name && m.unc_size > 0 && m.unc_size <= MANIFEST_LIMIT)
        else {
            return false;
        };
        parse::zip_member_data(d, m, MANIFEST_LIMIT as usize + 1)
            .is_some_and(|b| b.len() as u32 == m.unc_size)
    };
    if manifest_ok("AndroidManifest.xml") {
        return ft::FT_APK;
    }
    // `XIPA::isInfoPlistRecord` — "Payload/<app>.app/Info.plist".
    let is_ipa = members.iter().any(|m| {
        let name = m.name.replace('\\', "/");
        name.starts_with("Payload/") && name.ends_with("/Info.plist") && m.unc_size > 0 && {
            let app = &name[8..name.len() - 11];
            !app.contains('/') && app.len() > 4 && app.ends_with(".app")
        }
    });
    if is_ipa {
        return ft::FT_IPA;
    }
    if manifest_ok("META-INF/MANIFEST.MF") {
        return ft::FT_JAR;
    }
    ft::FT_ZIP
}

/// `XScanEngine::isScanable` — whether an intra-file part (archive
/// member, resource) is scanned at all. Upstream scans only executable
/// and structured formats; plain text and data members are skipped.
pub fn is_scanable_ft(ft: u16) -> bool {
    matches!(
        ft,
        x if x == ft::FT_MSDOS
            || x == ft::FT_NE
            || x == ft::FT_LE
            || x == ft::FT_LX
            || x == ft::FT_PE32
            || x == ft::FT_PE64
            || x == ft::FT_ELF32
            || x == ft::FT_ELF64
            || x == ft::FT_ELF
            || x == ft::FT_MACHO32
            || x == ft::FT_MACHO64
            || x == ft::FT_MACHO
            || x == ft::FT_MACHOFAT
            || x == ft::FT_DEX
            || x == ft::FT_PDF
            || x == ft::FT_ARCHIVE
            || x == ft::FT_DOS16M
            || x == ft::FT_DOS4G
    )
}

/// Scan `data` with the NFD engine. `hint_ft` is a `gen_names::ft::*`
/// index (use [`sniff_ft`] when unknown).
///
/// The return order follows upstream `_handleResult` category ordering.
pub fn scan(data: &[u8], hint_ft: u16, opts: ScanOptions) -> Vec<Detection> {
    let mut out = Vec::new();
    scan_recursive(
        data,
        hint_ft,
        &opts,
        &mut out,
        0,
        crate::promote::FilePart::Header,
        0,
    );
    out
}

/// `XScanEngine::scanProcess` file-part tail: archive members (STREAM,
/// `isScanable` gated) recurse on the freshly detected member type;
/// RESOURCE and OVERLAY parts are enumerated only at the root scan —
/// upstream sub-scans run with `bInit=false`, leaving `ftInit` at
/// `FT_UNKNOWN` whose `getFileParts` yields no parts.
fn scan_recursive(
    data: &[u8],
    hint_ft: u16,
    opts: &ScanOptions,
    out: &mut Vec<Detection>,
    depth: u32,
    parent_part: crate::promote::FilePart,
    res_type_id: u32,
) {
    out.extend(scan_file(data, hint_ft, *opts, parent_part, res_type_id));
    if depth >= 8 {
        return;
    }
    if opts.archives_scan
        && matches!(
            hint_ft,
            ft::FT_ZIP
                | ft::FT_7Z
                | ft::FT_RAR
                | ft::FT_CAB
                | ft::FT_ISO9660
                | ft::FT_APK
                | ft::FT_APKS
                | ft::FT_JAR
                | ft::FT_IPA
                | ft::FT_NPM
        )
    {
        let limit = if opts.aggressive_scan { 100000 } else { 20 };
        for member in parse::zip_members(data).iter().take(limit) {
            let Some(bytes) = parse::zip_member_data(data, member, 0x800_000) else {
                continue;
            };
            if bytes.is_empty() {
                continue;
            }
            let sub_ft = sniff_ft(&bytes);
            if !(opts.aggressive_scan || is_scanable_ft(sub_ft)) {
                continue;
            }
            scan_recursive(
                &bytes,
                sub_ft,
                opts,
                out,
                depth + 1,
                crate::promote::FilePart::Stream,
                0,
            );
        }
    }
    if depth != 0 {
        return;
    }
    // RESOURCE parts (upstream nLimit=10000, scanned while <=20
    // `isScanable`-gated) — PE resource leaves.
    if opts.resources_scan || opts.recursive_scan {
        let mut scanned = 0usize;
        for (off, size, type_id) in resource_parts(data, hint_ft) {
            if scanned > 20 && !opts.aggressive_scan {
                break;
            }
            let Some(bytes) = data.get(off..off.saturating_add(size)) else {
                continue;
            };
            if bytes.is_empty() {
                continue;
            }
            let sub_ft = sniff_ft(bytes);
            if !(opts.aggressive_scan || is_scanable_ft(sub_ft)) {
                continue;
            }
            scan_recursive(
                bytes,
                sub_ft,
                opts,
                out,
                depth + 1,
                crate::promote::FilePart::Resource,
                type_id,
            );
            scanned += 1;
        }
    }
    // OVERLAY part — scanned unconditionally when the option is on.
    if !(opts.overlay_scan || opts.recursive_scan) {
        return;
    }
    let Some(off) = overlay_offset(data, hint_ft) else {
        return;
    };
    if off >= data.len() {
        return;
    }
    let sub = &data[off..];
    if sub.is_empty() {
        return;
    }
    scan_recursive(
        sub,
        sniff_ft(sub),
        opts,
        out,
        depth + 1,
        crate::promote::FilePart::Overlay,
        0,
    );
}

/// `FILEPART_RESOURCE` enumeration — currently only PE resource leaves
/// carry `(offset, size, type_id)` tuples.
fn resource_parts(data: &[u8], ft_id: u16) -> Vec<(usize, usize, u32)> {
    if !(ft_id == ft::FT_PE32 || ft_id == ft::FT_PE64) {
        return Vec::new();
    }
    if pe::collect(data).is_none() {
        return Vec::new();
    }
    pe::collect_resources(data)
        .into_iter()
        .filter(|r| r.data_off != 0 && r.data_size != 0)
        .map(|r| (r.data_off, r.data_size, r.id1))
        .collect()
}

/// `XBinary::getFileParts(FILEPART_OVERLAY)` dispatch: the per-format
/// overlay offset (`nMaxOffset` of the memory map).
fn overlay_offset(data: &[u8], ft: u16) -> Option<usize> {
    match ft {
        ft::FT_MSDOS => parse::msdos_overlay_offset(data),
        ft::FT_NE => parse::ne_overlay_offset(data),
        // Upstream quirk: `XLE::getFileParts` counts header/object ends
        // only when those parts are requested, so an OVERLAY-only query
        // leaves `nMaxOffset` at 0 — the overlay is the whole file.
        ft::FT_LE | ft::FT_LX => Some(0),
        ft::FT_PE32 | ft::FT_PE64 => pe_overlay_offset(data),
        ft::FT_DEX => parse::dex_overlay_offset(data),
        // XZip covers the whole ZIP family (APK/JAR/IPA inherit it).
        ft::FT_ZIP | ft::FT_APK | ft::FT_APKS | ft::FT_JAR | ft::FT_IPA | ft::FT_NPM => {
            parse::zip_overlay_offset(data)
        }
        // ELF/Mach-O and the generic binary class do not override
        // `getFileParts` — upstream produces no overlay part for them.
        _ => None,
    }
}

/// `XPE::getFileParts(FILEPART_OVERLAY)` — `nMaxOffset` is the largest
/// of `SizeOfHeaders` and `align_down(raw_ptr, FileAlignment) +
/// raw_size + (raw_ptr - aligned)` per section (clamped to the file).
fn pe_overlay_offset(data: &[u8]) -> Option<usize> {
    let lfanew = parse::rd_u32(data, 0x3C)? as usize;
    let opt = lfanew.checked_add(0x18)?;
    let nsec = usize::from(parse::rd_u16(data, lfanew + 6)?).min(96);
    let opt_size = usize::from(parse::rd_u16(data, lfanew + 0x14)?);
    let magic = parse::rd_u16(data, opt)?;
    if magic != 0x10B && magic != 0x20B {
        return None;
    }
    let mut file_align = u64::from(parse::rd_u32(data, opt + 0x24)?);
    if file_align > 0x10000 {
        file_align = 0x200;
    }
    let file_align = file_align.max(1);
    let mut end = u64::from(parse::rd_u32(data, opt + 0x3C)?).min(data.len() as u64);
    let sectab = opt.checked_add(opt_size)?;
    for i in 0..nsec {
        let sh = sectab.checked_add(i.checked_mul(40)?)?;
        let mut raw_ptr = u64::from(parse::rd_u32(data, sh + 0x14)?);
        let mut raw_size = u64::from(parse::rd_u32(data, sh + 0x10)?);
        if raw_ptr > data.len() as u64 {
            raw_ptr = 0;
        }
        if raw_ptr + raw_size > data.len() as u64 {
            raw_size = (data.len() as u64).saturating_sub(raw_ptr);
        }
        let aligned = raw_ptr - raw_ptr % file_align;
        end = end.max(aligned + raw_size + (raw_ptr - aligned));
    }
    let end = usize::try_from(end.min(data.len() as u64)).ok()?;
    (end < data.len()).then_some(end)
}

/// `NFD_Binary::getInfo` + the format-dedicated `getInfo` paths for one
/// device. File-part recursion lives in [`scan_recursive`].
fn scan_file(
    data: &[u8],
    hint_ft: u16,
    opts: ScanOptions,
    parent_part: crate::promote::FilePart,
    res_type_id: u32,
) -> Vec<Detection> {
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
    let mut misc = ResultMaps::default();
    // .NET string-heap scan results feed handle_NETProtection (Phase
    // 21.L); upstream keeps them as intermediate maps, so they are not
    // drained into the output list.
    let mut dot_ansi: DetectMap = DetectMap::new();
    let mut dot_unicode: DetectMap = DetectMap::new();

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
    if parent_part == crate::promote::FilePart::Overlay {
        signature_scan(
            &mut header,
            &header_sig,
            t::G_PE_OVERLAY_RECORDS,
            file_type,
            ft::FT_BINARY,
        );
    }
    if parent_part == crate::promote::FilePart::DebugData {
        signature_scan(
            &mut header,
            &header_sig,
            t::G_DEBUGDATA_RECORDS,
            file_type,
            ft::FT_BINARY,
        );
    }
    if parent_part == crate::promote::FilePart::Resource && header.is_empty() {
        let rn = match res_type_id {
            5 => name::RECORD_NAME_RESOURCE_DIALOG,
            6 => name::RECORD_NAME_RESOURCE_STRINGTABLE,
            16 => name::RECORD_NAME_RESOURCE_VERSIONINFO,
            3 => name::RECORD_NAME_RESOURCE_ICON,
            1 => name::RECORD_NAME_RESOURCE_CURSOR,
            4 => name::RECORD_NAME_RESOURCE_MENU,
            _ => name::RECORD_NAME_UNKNOWN,
        };
        if rn != name::RECORD_NAME_UNKNOWN {
            header.insert(
                rn,
                ScanRecord {
                    ft: file_type,
                    rtype: rtype::RECORD_TYPE_FORMAT,
                    name: rn,
                    variant: 0,
                    version: String::new(),
                    info: String::new(),
                    heuristic: false,
                    unknown: false,
                    sname: None,
                    stype: None,
                },
            );
        }
    }

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
                &mut dot_ansi,
                &mut dot_unicode,
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
            let com_code = data.len().min(0x10000 - 0x100) as u64;
            let com_ctx = SigCtx {
                off_to_addr: Some(Box::new(|o| o.checked_add(0x100))),
                addr_to_off: Some(Box::new(move |a| {
                    (a >= 0x100 && a < 0x100 + com_code).then_some(a - 0x100)
                })),
                seg_wrap16: true,
                msdos_addr: None,
            };
            signature_exp_scan(
                &mut header,
                data,
                0,
                t::G_COM_EXP_RECORDS,
                file_type,
                ft::FT_COM,
                &com_ctx,
            );
            // `NFD_COM::getInfo` tail — verbose OS record,
            // `handle_Protection` header->result transfers, conditional
            // OS re-emit.
            crate::miscfmt::com_semantic_scan(data, opts.verbose, &header, &mut misc);
        }
        x if x == ft::FT_AMIGAHUNK => {
            // `NFD_Amiga::getInfo` — hunk-derived OS record.
            crate::miscfmt::amiga_semantic_scan(data, &mut misc);
        }
        x if x == ft::FT_CFBF => {
            // `NFD_CFBF::getInfo` — MSI/Word subtype promotion and the
            // deep-scan Advanced Installer marker.
            crate::miscfmt::cfbf_semantic_scan(data, opts.deep_scan, &mut misc);
        }
        x if x == ft::FT_PDF => {
            // `NFD_PDF::getInfo` — /Encrypt protector record and
            // /Producer//Creator tool records.
            crate::miscfmt::pdf_semantic_scan(data, &mut misc);
        }
        x if x == ft::FT_JAR => {
            // `NFD_JAR::getInfo` — JVM virtual-machine record (version
            // from the first .class member) and MANIFEST.MF tool
            // detections; upstream also runs `NFD_ZIP::handle_Container`
            // unless an all-types scan is in progress.
            crate::miscfmt::jar_semantic_scan(data, &mut misc);
            if !opts.all_types
                && let Some(records) = crate::promote::zip_records(data)
            {
                crate::promote::zip_container(&records, &mut misc);
            }
        }
        x if x == ft::FT_NE => {
            // NFD_NE::getInfo — linker header records plus entry-point
            // signatures at the CS:IP-derived offset, then the semantic
            // fixups (EP promotion, deep banners, OS, TurboLinker,
            // Watcom).
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
            crate::ne::ne_semantic_scan(data, opts.deep_scan, ft::FT_NE, &entrypoint, &mut misc);
        }
        x if x == ft::FT_LE || x == ft::FT_LX => {
            // NFD_LE/NFD_LX::getInfo — header linker records + OS record,
            // TurboLinker trailer and Watcom entry-point banner.
            signature_scan(
                &mut header,
                &header_sig,
                t::G_MSDOS_LINKER_HEADER_RECORDS,
                file_type,
                ft::FT_MSDOS,
            );
            crate::ne::le_semantic_scan(data, file_type, &mut misc);
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
            crate::elf::elf_semantic_scan(data, ft::FT_ELF, &entrypoint, &mut misc);
        }
        x if x == ft::FT_MACHO32 || x == ft::FT_MACHO64 || x == ft::FT_MACHO => {
            // NFD_MACH::getInfo — load-command driven semantic handlers.
            crate::mach::mach_semantic_scan(data, ft::FT_MACHO, &mut misc);
        }
        x if x == ft::FT_DEX => {
            // NFD_DEX::getInfo — string-id contents and type
            // descriptors feed the string/type detect maps, then the
            // semantic handlers emit tool/OS/compiler/protector
            // records.
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
            crate::miscfmt::dex_semantic_scan(
                data,
                opts.deep_scan,
                opts.heuristic_scan,
                &strings,
                &types,
                &strings_m,
                &types_m,
                &mut misc,
            );
        }
        x if x == ft::FT_APK => {
            // NFD_APK::getInfo — member-name CRC scan and regex scan over
            // the ZIP central directory names into `mapArchiveDetects`.
            let members = parse::zip_members(data);
            let names: Vec<String> = members.iter().map(|m| m.name.clone()).collect();
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
            // `dexInfoClasses` — the classes.dex sub-scan whose protector
            // records feed the DexGuard check.
            let mut dex_res = ResultMaps::default();
            if let Some(dex_member) = members.iter().find(|m| m.name == "classes.dex")
                && let Some(dex) = parse::zip_member_data(data, dex_member, 64 * 1024 * 1024)
            {
                let (dstrings, dtypes) = parse::dex_strings(&dex);
                let mut ds: DetectMap = DetectMap::new();
                let mut dt: DetectMap = DetectMap::new();
                string_scan(
                    &mut ds,
                    &dstrings,
                    t::G_DEX_STRING_RECORDS,
                    file_type,
                    ft::FT_DEX,
                );
                string_scan(
                    &mut dt,
                    &dtypes,
                    t::G_DEX_TYPE_RECORDS,
                    file_type,
                    ft::FT_DEX,
                );
                crate::miscfmt::dex_semantic_scan(
                    &dex,
                    opts.deep_scan,
                    opts.heuristic_scan,
                    &dstrings,
                    &dtypes,
                    &ds,
                    &dt,
                    &mut dex_res,
                );
            }
            crate::miscfmt::apk_semantic_scan(
                data,
                &members,
                &archive_m,
                &DetectMap::new(),
                &dex_res.protectors,
                opts.verbose,
                opts.all_types,
                &mut misc,
            );
        }
        x if x == ft::FT_JPEG => {
            // `NFD_JPEG::getInfo` — the format record with the JFIF
            // APP0 version.
            crate::miscfmt::jpeg_semantic_scan(data, &mut misc);
        }
        x if x == ft::FT_ZIP || x == ft::FT_IPA => {
            // `NFD_ZIP::getInfo` container leg — member metadata record
            // or the strict central-directory fallback.
            crate::promote::zip_scan(data, &mut misc);
        }
        _ => {}
    }

    // Non-dedicated types take the `NFD_Binary::getInfo` promotion
    // chain over the intermediate maps (texts -> formats -> databases
    // -> images -> archives -> certificates -> debug/installer/sfx/
    // protector/library data -> resources -> fixups). Dedicated formats
    // run their own `getInfo` handlers above and skip this chain.
    if !is_dedicated_ft(file_type) {
        let unicode = parse::unicode_type(data);
        let is_utf8 = unicode == parse::UnicodeType::None && parse::is_utf8_text(data);
        let is_plain = unicode == parse::UnicodeType::None && parse::is_plain_text(data);
        let limit = data.len().min(0x1000);
        let header_text = if unicode != parse::UnicodeType::None {
            parse::read_unicode(data, 2, limit.min(data.len().saturating_sub(2)), unicode)
        } else if is_utf8 {
            String::from_utf8_lossy(&data[3.min(data.len())..limit.max(3).min(data.len())])
                .into_owned()
        } else if is_plain {
            String::from_utf8_lossy(&data[..limit]).into_owned()
        } else if data.starts_with(b"#!") {
            String::from_utf8_lossy(&data[..data.len().min(0x4000)]).into_owned()
        } else {
            String::new()
        };
        let ctx = crate::promote::PromoteCtx {
            data,
            header_sig: &header_sig,
            header: &header,
            is_plain_text: is_plain,
            is_utf8,
            unicode: unicode != parse::UnicodeType::None,
            header_text,
            parent_part,
            res_type_id,
        };
        crate::promote::binary_promote(&ctx, &mut misc);
    }

    // `SpecAbstract::_processDetect` — the root scan appends a bare
    // Unknown record when nothing was detected (`bAddUnknown`), except
    // for the generic-FAT/binary probing paths where upstream passes
    // `false`.
    let add_unknown = file_type != ft::FT_MACHOFAT;
    let mut out: Vec<Detection> = crate::promote::handle_result(&mut misc)
        .iter()
        .map(to_detection)
        .collect();
    if out.is_empty() && add_unknown {
        out.push(Detection {
            record_type: std::borrow::Cow::Borrowed("Unknown"),
            record_name: std::borrow::Cow::Borrowed("Unknown"),
            version: String::new(),
            info: String::new(),
            heuristic: false,
            unknown: true,
        });
    }
    out
}

/// True when `file_type` is served by a dedicated upstream `getInfo`
/// module rather than the generic `NFD_Binary` promotion chain.
fn is_dedicated_ft(file_type: u16) -> bool {
    file_type == ft::FT_PE32
        || file_type == ft::FT_PE64
        || file_type == ft::FT_MSDOS
        || file_type == ft::FT_COM
        || file_type == ft::FT_AMIGAHUNK
        || file_type == ft::FT_CFBF
        || file_type == ft::FT_PDF
        || file_type == ft::FT_JAR
        || file_type == ft::FT_APK
        || file_type == ft::FT_ZIP
        || file_type == ft::FT_IPA
        || file_type == ft::FT_NE
        || file_type == ft::FT_LE
        || file_type == ft::FT_LX
        || file_type == ft::FT_ELF
        || file_type == ft::FT_ELF32
        || file_type == ft::FT_ELF64
        || file_type == ft::FT_MACHO
        || file_type == ft::FT_MACHO32
        || file_type == ft::FT_MACHO64
        || file_type == ft::FT_DEX
        || file_type == ft::FT_JAVACLASS
        || file_type == ft::FT_JPEG
}

/// PE scan pipeline: header records, entry-point signature + expression
/// scans (with NOP/JZ/E9-follow loop), overlay, imports hashes, resource
/// names, section names and optional deep section scans.
#[allow(clippy::too_many_arguments)]
fn pe_scan(
    data: &[u8],
    opts: ScanOptions,
    misc: &mut ResultMaps,
    header_sig: &str,
    header: &mut DetectMap,
    overlay: &mut DetectMap,
    entrypoint: &mut DetectMap,
    section_names: &mut DetectMap,
    imports: &mut DetectMap,
    resources: &mut DetectMap,
    code_section: &mut DetectMap,
    ep_section: &mut DetectMap,
    dot_ansi: &mut DetectMap,
    dot_unicode: &mut DetectMap,
) {
    let Some(pe) = pe::collect(data) else {
        return;
    };
    let ftpe = ft::FT_PE;
    // `_MEMORY_MAP` resolution for `$$`/`#` signature elements
    // (XPE::offsetToAddress/addressToOffset over section extents).
    let pe_ctx = pe.sig_ctx();
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
                    &pe_ctx,
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
        signature_scan(
            overlay,
            &ov_sig,
            t::G_PE_OVERLAY_RECORDS,
            actual,
            ft::FT_BINARY,
        );
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
    if !pe.resources.is_empty() {
        crate::scans::resources_scan(
            resources,
            &pe.resources,
            t::PE_RESOURCES_RECORDS,
            actual,
            ftpe,
        );
    }

    // .NET `#Strings`/`#US` heap scans (`mapDotAnsiStringsDetects` /
    // `mapDotUnicodeStringsDetects`) — consumed by handle_NETProtection.
    if !pe.dotnet_ansi.is_empty() {
        string_scan(
            dot_ansi,
            &pe.dotnet_ansi,
            t::PE_DOT_ANSISTRINGS_RECORDS,
            actual,
            ftpe,
        );
    }
    if !pe.dotnet_unicode.is_empty() {
        string_scan(
            dot_unicode,
            &pe.dotnet_unicode,
            t::PE_DOT_UNICODESTRINGS_RECORDS,
            actual,
            ftpe,
        );
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
                &pe_ctx,
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
                    &pe_ctx,
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
                &pe_ctx,
            );
        }
    }

    // Semantic handlers — upstream `getInfo` call order:
    // import -> OS -> Protection -> small protector handlers ->
    // NETProtection -> PolyMorph -> Microsoft -> Borland -> Watcom ->
    // Tools -> wxWidgets -> GCC -> Signtools -> SFX -> Installers ->
    // Dongle -> NeoLite -> PrivateEXE -> VBCryptors -> DelphiCryptors ->
    // Joiners -> PETools -> DebugData -> UnknownProtection -> FixDetects.
    crate::pe_handlers::import_heuristics(&pe, ftpe, imports);
    crate::pe_handlers::operation_system(&pe, ftpe, misc);
    crate::pe_handlers::protection(
        data,
        &pe,
        opts.deep_scan,
        ftpe,
        header,
        overlay,
        entrypoint,
        ep_section,
        section_names,
        imports,
        misc,
    );
    crate::pe_handlers::safeengine(data, &pe, ftpe, entrypoint, misc);
    crate::pe_handlers::vprotect(data, &pe, opts.deep_scan, ftpe, misc);
    crate::pe_handlers::ttprotect(&pe, ftpe, misc);
    crate::pe_handlers::vmprotect(&pe, entrypoint, misc);
    crate::pe_handlers::telock(&pe, entrypoint, misc);
    crate::pe_handlers::armadillo(&pe, ftpe, imports, misc);
    crate::pe_handlers::obsidium(data, &pe, ftpe, misc);
    crate::pe_handlers::themida(&pe, ftpe, entrypoint, misc);
    crate::pe_handlers::starforce(&pe, ftpe, misc);
    crate::pe_handlers::petite(&pe, entrypoint, section_names, misc);
    crate::pe_handlers::net_protection(
        data,
        &pe,
        opts.deep_scan,
        ftpe,
        dot_ansi,
        dot_unicode,
        code_section,
        overlay,
        imports,
        entrypoint,
        misc,
    );
    // `handle_PolyMorph` sits here in the upstream chain — its body is
    // entirely Q_UNUSED + a `// ExeSax` comment at the pinned commit, a
    // no-op; nothing to port.
    crate::pe_handlers::microsoft(
        data,
        &pe,
        opts.deep_scan,
        ftpe,
        header,
        entrypoint,
        dot_ansi,
        misc,
    );
    crate::pe_handlers::borland(
        data,
        &pe,
        opts.deep_scan,
        ftpe,
        header,
        entrypoint,
        dot_ansi,
        misc,
    );
    crate::pe_handlers::watcom(data, &pe, ftpe, header, entrypoint, misc);
    crate::pe_handlers::tools(
        data,
        &pe,
        opts.deep_scan,
        ftpe,
        header,
        overlay,
        entrypoint,
        section_names,
        code_section,
        misc,
    );
    crate::pe_handlers::wx_widgets(data, &pe, opts.deep_scan, ftpe, misc);
    crate::pe_handlers::gcc(
        data,
        &pe,
        opts.deep_scan,
        ftpe,
        header,
        overlay,
        entrypoint,
        misc,
    );
    crate::pe_handlers::signtools(data, &pe, ftpe, misc);
    crate::pe_handlers::sfx(data, &pe, opts.deep_scan, ftpe, overlay, misc);
    crate::pe_handlers::installers(
        data,
        &pe,
        opts.deep_scan,
        ftpe,
        overlay,
        header,
        section_names,
        misc,
    );
    crate::pe_handlers::dongle(&pe, ftpe, misc);
    crate::pe_handlers::neolite(data, &pe, opts.deep_scan, ftpe, misc);
    crate::pe_handlers::private_exe(&pe, ftpe, header, misc);
    crate::pe_handlers::vb_cryptors(&pe, overlay, imports, misc);
    crate::pe_handlers::delphi_cryptors(&pe, imports, misc);
    crate::pe_handlers::joiners(data, &pe, ftpe, imports, entrypoint, misc);
    crate::pe_handlers::petools(section_names, ftpe, misc);
    crate::pe_handlers::debug_data(data, &pe, ftpe, misc);
    crate::pe_handlers::unknown_protection(
        data,
        &pe,
        ftpe,
        header,
        section_names,
        imports,
        entrypoint,
        misc,
    );
    crate::pe_handlers::fix_detects(misc);
}

/// MSDOS scan pipeline: linker-header + header records, entry-point
/// signature and expression scans.
fn msdos_scan(
    data: &[u8],
    opts: ScanOptions,
    header_sig: &str,
    header: &mut DetectMap,
    entrypoint: &mut DetectMap,
    misc: &mut ResultMaps,
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

    // `NFD_MSDOS::handle_OperationSystem` — unconditional MS-DOS OS
    // record from `XMSDOS::getFileFormatInfo` (arch 8086, 16-bit, EXE).
    crate::scans::push(
        misc,
        ft::FT_MSDOS,
        rtype::RECORD_TYPE_OPERATIONSYSTEM,
        name::RECORD_NAME_MSDOS,
        "",
        "8086, 16-bit, EXE",
        None,
        None,
    );

    // MZ entry point: header_paragraphs*16 + CS*16 + IP.
    let hdr = usize::from(u16::from_le_bytes([
        *data.get(0x08).unwrap_or(&0),
        *data.get(0x09).unwrap_or(&0),
    ])) * 16;
    let ep_off = (|| {
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
    // Upstream maps the post-header region at segment address
    // 0x10000000 (`XMSDOS::getMemoryMap`); `$$` wraps in 16 bits and
    // `#` resolves against nCodeBase/nStartLoadOffset.
    let msdos_ctx = msdos_sig_ctx(hdr);
    signature_exp_scan(
        entrypoint,
        data,
        ep_off,
        t::G_MSDOS_ENTRYPOINTEXP_RECORDS,
        ft::FT_MSDOS,
        ft::FT_MSDOS,
        &msdos_ctx,
    );

    msdos_extender_scan(data, opts, misc);
    msdos_vintage_scan(data, opts, misc);
}

/// `NFD_MSDOS::handle_DosExtenders` — DOS extender banners:
/// WDOSX at 0x34 (always), CWSDPMI/DOS4G/DOS16M on deep scan only.
fn msdos_extender_scan(data: &[u8], opts: ScanOptions, misc: &mut ResultMaps) {
    // WDOSX: ANSI banner at fixed offset 0x34 ("WDOSX <ver>").
    let wdosx =
        parse::read_ansi_string(data, 0x34).filter(|b| b.split(' ').next() == Some("WDOSX"));
    if let Some(banner) = wdosx {
        let ver = banner.split(' ').nth(1).unwrap_or("").to_string();
        misc.entry_or_insert(name::RECORD_NAME_WDOSX, || {
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
        misc.entry_or_insert(name::RECORD_NAME_CWSDPMI, || {
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
        misc.entry_or_insert(name::RECORD_NAME_DOS4G, || {
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
        misc.entry_or_insert(name::RECORD_NAME_DOS16M, || {
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
fn msdos_vintage_scan(data: &[u8], opts: ScanOptions, misc: &mut ResultMaps) {
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

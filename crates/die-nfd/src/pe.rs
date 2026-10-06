//! Minimal bounded PE reader producing the inputs required by the NFD
//! PE scans: entry-point signature offset, section names, import
//! records (library/function per thunk), resource name/id pairs,
//! Rich header entries and overlay offset.
//!
//! All offsets and counts are bounds-checked; malformed inputs return
//! `None`/empty lists rather than panicking. No `unsafe`.

/// One import thunk resolution, mirroring `XPE::IMPORT_RECORD`.
#[derive(Debug, Clone)]
pub struct ImportRecord {
    /// Importing library name (ANSI, not case-normalized).
    pub library: String,
    /// Function name, or decimal ordinal string for ordinal imports.
    pub function: String,
}

/// One import descriptor (library + positions), mirroring
/// `XPE::IMPORT_HEADER` used by `getImportPositionHashes`.
#[derive(Debug, Clone)]
pub struct ImportHeader {
    /// Library name.
    #[allow(dead_code)] // kept for the bLibraryName position-hash variant.
    pub name: String,
    /// Function/ordinal strings per thunk.
    pub positions: Vec<String>,
}

/// Extracted PE facts consumed by the NFD scan passes.
#[derive(Debug, Default)]
pub struct PeInfo {
    /// True for PE32+.
    pub is64: bool,
    /// File offset of the entry point (-1 when unresolvable).
    pub entry_point_offset: i64,
    /// File offset of the overlay (end of last section), -1 when none.
    pub overlay_offset: i64,
    /// Uppercased section names.
    pub section_names: Vec<String>,
    /// File offset of the first section (entrypoint-section sig input).
    pub first_section_offset: i64,
    /// Flattened import records.
    pub imports: Vec<ImportRecord>,
    /// Per-library import headers for position hashes.
    pub import_headers: Vec<ImportHeader>,
    /// Rich-signature (compid, build, count) entries.
    pub rich: Vec<(u16, u32, u32)>,
    /// Whether the image has a CLI/.NET data directory.
    pub is_dotnet: bool,
    /// .NET metadata version string ("BSJB" root), empty when absent.
    pub dotnet_version: String,
    /// `#Strings` heap entries (`XCLIAssembly::getAnsiStrings`):
    /// NUL-separated ANSI strings walked from index 1.
    pub dotnet_ansi: Vec<String>,
    /// `#US` heap entries (`XCLIAssembly::getUnicodeStrings`):
    /// single-byte-length-prefixed UTF-16 strings walked from index 1.
    pub dotnet_unicode: Vec<String>,
    /// Optional-header linker version bytes (`MajorLinkerVersion`,
    /// `MinorLinkerVersion`) — `nMajorLinkerVersion`/`nMinorLinkerVersion`.
    pub major_linker: u8,
    /// See [`Self::major_linker`].
    pub minor_linker: u8,
    /// Optional-header `Subsystem`.
    pub subsystem: u16,
    /// COFF `Machine`.
    pub machine: u16,
    /// COFF `Characteristics` (DLL flag check for `getType`).
    pub characteristics: u16,
    /// Packed OS version `Major<<16|Minor` (`getOperatingSystemVersion`).
    pub os_version: u32,
    /// Image base (`getImageBase`).
    pub image_base: u64,
    /// Optional-header `SectionAlignment` (memory-map virtual extents).
    pub section_alignment: u32,
    /// Optional-header `FileAlignment` (memory-map file extents).
    pub file_alignment: u32,
    /// Section extents for deep scans.
    pub extents: Vec<SectionExtent>,
    /// Import-directory section index (`getImageDirectoryEntrySection`),
    /// -1 when not found.
    pub import_section: i32,
    /// Exported function names (name-pointer table), capped — Borland
    /// `__CPPdebugHook` detection etc.
    pub export_names: Vec<String>,
    /// TLS directory (dir 9) present — gates `handle_Tools` Rust path.
    pub tls_present: bool,
    /// Security-directory (dir 4) file offset — `VirtualAddress` there is
    /// a file offset, not an RVA (`handle_Signtools` cert table).
    pub cert_offset: usize,
    /// See [`Self::cert_offset`]; `Size` field of the security dir.
    pub cert_size: usize,
    /// Overlay size in bytes (0 when `overlay_offset` is -1).
    pub overlay_size: usize,
    /// Section index containing the resource directory
    /// (`getImageDirectoryEntrySection(RESOURCE)`), -1 when absent.
    pub resources_section: i32,
    /// Export DLL name (`IMAGE_EXPORT_DIRECTORY.Name`), empty when the
    /// image has no export table.
    pub export_dll_name: String,
    /// Flattened resource entries (level-3 leaf offsets resolved).
    pub resources: Vec<crate::scans::ResourceEntry>,
    /// `getResourceManifest` — first `RT_MANIFEST` resource body as an
    /// ANSI string, capped at 4000 bytes upstream.
    pub manifest: String,
    /// Parsed `VS_VERSIONINFO` (`getResourcesVersion` subset).
    pub res_version: crate::pe_version::ResourcesVersion,
    /// Entry-point RVA (`nEntryPointAddress`).
    pub entry_rva: u32,
    /// COFF `e_lfanew` — PE header file offset (MKFpack "llydd" probe).
    pub e_lfanew: u32,
    /// COFF `TimeDateStamp` (ExeFog header gate).
    pub time_stamp: u32,
    /// PE32 optional-header `BaseOfData` (0 for PE32+).
    pub base_of_data: u32,
    /// Optional-header `MinorImageVersion` (WinUpack build probe).
    pub minor_image: u16,
}

fn rd_u16(d: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(off..off + 2)?.try_into().ok()?))
}

fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(off..off + 4)?.try_into().ok()?))
}

fn rd_u64(d: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(off..off + 8)?.try_into().ok()?))
}

fn rd_str(d: &[u8], off: usize, max: usize) -> Option<String> {
    let mut s = Vec::new();
    for i in 0..max {
        let &b = d.get(off + i)?;
        if b == 0 {
            return Some(String::from_utf8_lossy(&s).into_owned());
        }
        if !(0x20..=0x7E).contains(&b) && b != 0x80 {
            return None;
        }
        s.push(b);
    }
    Some(String::from_utf8_lossy(&s).into_owned())
}

struct Section {
    name: String,
    vaddr: u32,
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
    /// `PointerToRelocations` — PECompact build-number probe.
    ptr_reloc: u32,
    /// `PointerToLinenumbers` — PECompact build-number probe.
    ptr_linenum: u32,
    flags: u32,
}

/// Parsed PE layout; exposed for signature-expression RVA resolution.
pub struct PeLayout {
    /// True for PE32+.
    pub is64: bool,
    #[allow(dead_code)] // retained for future heuristic ports.
    opt_off: usize,
    sec_off: usize,
    /// Entry point RVA.
    pub entry_rva: u32,
    /// Image base.
    #[allow(dead_code)] // retained for RVA arithmetic in Exp scans.
    pub image_base: u64,
    /// COFF `e_lfanew` — PE header file offset (MKFpack "llydd" probe).
    pub e_lfanew: u32,
    /// COFF `TimeDateStamp` (ExeFog header gate).
    pub time_stamp: u32,
    /// PE32 optional-header `BaseOfData` (0 for PE32+).
    pub base_of_data: u32,
    /// Optional-header `MinorImageVersion` (WinUpack build probe).
    pub minor_image: u16,
    /// Optional-header `SectionAlignment`.
    pub section_alignment: u32,
    /// Optional-header `FileAlignment`.
    pub file_alignment: u32,
    dir_rva: [u32; 16],
    #[allow(dead_code)] // retained for future resource/debug scans.
    dir_size: [u32; 16],
    sections: Vec<Section>,
}

fn parse_layout(d: &[u8]) -> Option<PeLayout> {
    if d.get(0..2) != Some(b"MZ") {
        return None;
    }
    let pe_off = rd_u32(d, 0x3C)? as usize;
    if d.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return None;
    }
    let coff = pe_off + 4;
    let nsects = rd_u16(d, coff + 2)? as usize;
    if nsects > 96 {
        return None;
    }
    let opt_size = rd_u16(d, coff + 16)? as usize;
    let opt_off = coff + 20;
    let magic = rd_u16(d, opt_off)?;
    let is64 = match magic {
        0x10B => false,
        0x20B => true,
        _ => return None,
    };
    let entry_rva = rd_u32(d, opt_off + 16)?;
    let image_base = if is64 {
        rd_u64(d, opt_off + 24)?
    } else {
        u64::from(rd_u32(d, opt_off + 28)?)
    };
    let dir_base = opt_off + if is64 { 112 } else { 96 };
    let mut dir_rva = [0u32; 16];
    let mut dir_size = [0u32; 16];
    for i in 0..16 {
        if let (Some(r), Some(s)) = (rd_u32(d, dir_base + i * 8), rd_u32(d, dir_base + i * 8 + 4)) {
            dir_rva[i] = r;
            dir_size[i] = s;
        }
    }
    // `XPE` resolves long section names (`/N`) through the COFF string
    // table that follows the symbol table.
    let strtab_off = rd_u32(d, coff + 8)
        .and_then(|p| rd_u32(d, coff + 12).map(|n| p as usize + n as usize * 18))
        .filter(|&o| o + 4 <= d.len());
    let sec_off = opt_off + opt_size;
    let mut sections = Vec::with_capacity(nsects);
    for i in 0..nsects {
        let so = sec_off + i * 40;
        let name_raw = d.get(so..so + 8)?;
        let end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
        // Upstream keeps the raw name (`SECTION_RECORD.sName`); every
        // downstream compare (`isSectionNamePresent`, section-name scan
        // records, `listSectionNames.at(i) == "..."`) is case-sensitive.
        let mut name = String::from_utf8_lossy(&name_raw[..end]).into_owned();
        if let Some(idx) = name
            .strip_prefix('/')
            .and_then(|t| t.parse::<usize>().ok())
            .filter(|&idx| idx >= 4)
            && let Some(st) = strtab_off
            && let Some(start) = st.checked_add(idx)
            && start < d.len()
        {
            let tail = &d[start..d.len().min(start + 256)];
            let tend = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
            name = String::from_utf8_lossy(&tail[..tend]).into_owned();
        }
        sections.push(Section {
            name,
            vaddr: rd_u32(d, so + 12)?,
            vsize: rd_u32(d, so + 8)?,
            raw_ptr: rd_u32(d, so + 20)?,
            raw_size: rd_u32(d, so + 16)?,
            ptr_reloc: rd_u32(d, so + 24)?,
            ptr_linenum: rd_u32(d, so + 28)?,
            flags: rd_u32(d, so + 36)?,
        });
    }
    Some(PeLayout {
        is64,
        opt_off,
        sec_off,
        sections,
        entry_rva,
        image_base,
        e_lfanew: pe_off as u32,
        time_stamp: rd_u32(d, coff + 4).unwrap_or(0),
        base_of_data: if is64 {
            0
        } else {
            rd_u32(d, opt_off + 24).unwrap_or(0)
        },
        minor_image: rd_u16(d, opt_off + 46).unwrap_or(0),
        section_alignment: rd_u32(d, opt_off + 32).unwrap_or(0),
        file_alignment: rd_u32(d, opt_off + 36).unwrap_or(0),
        dir_rva,
        dir_size,
    })
}

/// Map RVA to file offset via section table (raw_size clipping only;
/// header RVAs map to themselves).
/// Public RVA→file-offset mapping used by signature-expression scans.
pub fn rva_to_off_pub(l: &PeLayout, rva: u32) -> Option<usize> {
    rva_to_off(l, rva)
}

fn rva_to_off(l: &PeLayout, rva: u32) -> Option<usize> {
    for s in &l.sections {
        let span = s.raw_size.max(s.vsize);
        if rva >= s.vaddr && rva < s.vaddr.saturating_add(span.max(1)) {
            let delta = (rva - s.vaddr) as usize;
            return Some(s.raw_ptr as usize + delta);
        }
    }
    // Some packers address headers by RVA.
    if (rva as usize) < l.sec_off {
        return Some(rva as usize);
    }
    None
}

const DIR_IMPORT: usize = 1;
const DIR_EXPORT: usize = 0;
const DIR_RESOURCE: usize = 2;
const DIR_CLR: usize = 14;

/// Exported function names from the export directory (dir 0):
/// `NumberOfNames`/`AddressOfNames` RVA array → ANSI strings, capped at
/// 4096 entries and 256-byte names. Missing/malformed table → empty.
fn collect_export_names(d: &[u8], l: &PeLayout) -> Vec<String> {
    let mut out = Vec::new();
    let Some(exp_off) = rva_to_off(l, l.dir_rva[DIR_EXPORT]) else {
        return out;
    };
    let (Some(n_names), Some(names_rva)) = (
        rd_u32(d, exp_off + 24).map(|v| v as usize),
        rd_u32(d, exp_off + 32),
    ) else {
        return out;
    };
    let Some(names_off) = rva_to_off(l, names_rva) else {
        return out;
    };
    for i in 0..n_names.min(4096) {
        let Some(nr) = rd_u32(d, names_off + i * 4) else {
            break;
        };
        let Some(no) = rva_to_off(l, nr) else {
            continue;
        };
        if let Some(s) = crate::parse::read_ansi_string_len(d, no, 256) {
            out.push(s);
        }
    }
    out
}

/// `IMAGE_EXPORT_DIRECTORY.Name` (exp_off+12) → ANSI DLL name
/// (`exportHeader.sName`).
fn export_dll_name(d: &[u8], l: &PeLayout) -> String {
    let Some(exp_off) = rva_to_off(l, l.dir_rva[DIR_EXPORT]) else {
        return String::new();
    };
    let Some(name_rva) = rd_u32(d, exp_off + 12) else {
        return String::new();
    };
    let Some(no) = rva_to_off(l, name_rva) else {
        return String::new();
    };
    crate::parse::read_ansi_string_len(d, no, 256).unwrap_or_default()
}

/// Index of the section containing a data-directory RVA
/// (`XPE::getImageDirectoryEntrySection`), -1 when unmapped.
fn dir_section_index(l: &PeLayout, rva: u32) -> i32 {
    if rva == 0 {
        return -1;
    }
    for (i, s) in l.sections.iter().enumerate() {
        let span = s.raw_size.max(s.vsize);
        if rva >= s.vaddr && rva < s.vaddr.saturating_add(span.max(1)) {
            return i as i32;
        }
    }
    -1
}

/// `XPE::getImageDirectoryEntrySection(RESOURCE)` — section index of
/// the resource tree, -1 when absent.
fn import_section_index(l: &PeLayout) -> i32 {
    dir_section_index(l, l.dir_rva[DIR_IMPORT])
}

/// See [`import_section_index`]; resource-directory variant.
fn resources_section_index(l: &PeLayout) -> i32 {
    dir_section_index(l, l.dir_rva[DIR_RESOURCE])
}

/// .NET metadata version: CLI header (dir 14) → metadata root →
/// `BSJB` + version-length + ANSI string (`XPE::CliInfo` subset).
fn dotnet_metadata_version(d: &[u8], l: &PeLayout) -> String {
    let Some(cli_off) = rva_to_off(l, l.dir_rva[DIR_CLR]) else {
        return String::new();
    };
    let Some(meta_rva) = rd_u32(d, cli_off + 8) else {
        return String::new();
    };
    let Some(meta_off) = rva_to_off(l, meta_rva) else {
        return String::new();
    };
    if d.get(meta_off..meta_off + 4) != Some(b"BSJB") {
        return String::new();
    }
    let Some(ver_len) = rd_u32(d, meta_off + 12).map(|v| v as usize) else {
        return String::new();
    };
    if ver_len == 0 || ver_len > 256 {
        return String::new();
    }
    d.get(meta_off + 16..meta_off + 16 + ver_len)
        .map(|b| {
            let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
            String::from_utf8_lossy(&b[..end]).into_owned()
        })
        .unwrap_or_default()
}

/// Locate `.NET` metadata streams: CLI header (dir 14) → `BSJB` root
/// → `{offset, size, name}` stream headers (`XCLIAssembly::getCliInfo`
/// subset, name fields 4-aligned as upstream).
fn dotnet_streams(d: &[u8], l: &PeLayout) -> Vec<(String, usize, usize)> {
    let Some(cli_off) = rva_to_off(l, l.dir_rva[DIR_CLR]) else {
        return Vec::new();
    };
    let Some(meta_rva) = rd_u32(d, cli_off + 8) else {
        return Vec::new();
    };
    let Some(meta_off) = rva_to_off(l, meta_rva) else {
        return Vec::new();
    };
    if rd_u32(d, meta_off) != Some(0x424A_5342) {
        return Vec::new();
    }
    let Some(ver_len) = rd_u32(d, meta_off + 12).map(|v| v as usize) else {
        return Vec::new();
    };
    if ver_len > 512 {
        return Vec::new();
    }
    let Some(n_streams) = rd_u16(d, meta_off + 18 + ver_len).map(|v| v as usize) else {
        return Vec::new();
    };
    let mut off = meta_off + 20 + ver_len;
    let mut out = Vec::new();
    for _ in 0..n_streams.min(64) {
        let (Some(so), Some(ss)) = (rd_u32(d, off), rd_u32(d, off + 4)) else {
            break;
        };
        let name = crate::parse::read_ansi_string_len(d, off + 8, 32).unwrap_or_default();
        if name.is_empty() {
            break;
        }
        // Stream offsets are relative to the metadata root; clamp the
        // extent inside the file as upstream does.
        let so = meta_off + so as usize;
        let ss = (ss as usize).min(d.len().saturating_sub(so));
        out.push((name.clone(), so, ss));
        off += 8 + (name.len() + 1).div_ceil(4) * 4;
        if off >= d.len() {
            break;
        }
    }
    out
}

/// `getAnsiStrings`: split `#Strings` at NULs starting at index 1.
fn dotnet_ansi_strings(heap: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 1usize;
    while pos < heap.len() {
        let end = heap[pos..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| pos + p)
            .unwrap_or(heap.len());
        out.push(String::from_utf8_lossy(&heap[pos..end]).into_owned());
        pos = end + 1;
    }
    out
}

/// `getUnicodeStrings`: `#US` entries are `<u8 len><utf16 data>`;
/// a 0x80 length reads as zero (upstream does not decode the full
/// compressed-uint form — quirk kept verbatim).
fn dotnet_unicode_strings(heap: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if heap.len() <= 1 {
        return out;
    }
    let mut pos = 1usize;
    while pos < heap.len() {
        let mut size = heap[pos] as usize;
        if size == 0x80 {
            size = 0;
        }
        if size > heap.len() - pos {
            break;
        }
        pos += 1;
        let mut s = String::new();
        for i in 0..size / 2 {
            let Some(w) = rd_u16(heap, pos + i * 2) else {
                break;
            };
            if let Some(c) = char::from_u32(u32::from(w)) {
                s.push(c);
            }
        }
        out.push(s);
        pos += size;
    }
    out
}

/// Collect PE facts needed by the NFD scans. Returns `None` when the
/// buffer is not a plausible PE.
pub fn collect(d: &[u8]) -> Option<PeInfo> {
    let l = parse_layout(d)?;
    let mut info = PeInfo {
        is64: l.is64,
        ..Default::default()
    };

    info.entry_point_offset = rva_to_off(&l, l.entry_rva).map(|o| o as i64).unwrap_or(-1);
    info.first_section_offset = l
        .sections
        .iter()
        .map(|s| s.raw_ptr)
        .filter(|&p| p != 0)
        .min()
        .map(|p| p as i64)
        .unwrap_or(-1);
    info.section_names = l.sections.iter().map(|s| s.name.clone()).collect();

    // Overlay: end of the highest raw section extent.
    let mut end = 0u64;
    for s in &l.sections {
        if s.raw_ptr != 0 && s.raw_size != 0 {
            end = end.max(s.raw_ptr as u64 + s.raw_size as u64);
        }
    }
    if end != 0 && end < d.len() as u64 {
        info.overlay_offset = end as i64;
        info.overlay_size = d.len() - end as usize;
    } else {
        info.overlay_offset = -1;
        info.overlay_size = 0;
    }

    info.is_dotnet = l.dir_rva[DIR_CLR] != 0;
    info.dotnet_version = dotnet_metadata_version(d, &l);
    if info.is_dotnet {
        let streams = dotnet_streams(d, &l);
        let strings = streams.iter().find(|(n, _, _)| n == "#Strings");
        let us = streams.iter().find(|(n, _, _)| n == "#US");
        if let Some((_, o, sz)) = strings
            && *o < d.len()
        {
            info.dotnet_ansi = dotnet_ansi_strings(&d[*o..*o + *sz]);
        }
        if let Some((_, o, sz)) = us
            && *o < d.len()
        {
            info.dotnet_unicode = dotnet_unicode_strings(&d[*o..*o + *sz]);
        }
    }

    // Optional-header / COFF fields used by handle_OperationSystem and
    // handle_Microsoft.
    info.major_linker = d.get(l.opt_off + 2).copied().unwrap_or(0);
    info.minor_linker = d.get(l.opt_off + 3).copied().unwrap_or(0);
    // PE32 and PE32+ share these offsets: the wider ImageBase is exactly
    // compensated by the absent BaseOfData field.
    let (osv_off, subsys_off) = (40, 68);
    let maj_os = rd_u16(d, l.opt_off + osv_off).unwrap_or(0);
    let min_os = rd_u16(d, l.opt_off + osv_off + 2).unwrap_or(0);
    info.os_version = (u32::from(maj_os) << 16) | u32::from(min_os);
    info.subsystem = rd_u16(d, l.opt_off + subsys_off).unwrap_or(0);
    info.machine = rd_u16(d, l.opt_off - 20).unwrap_or(0);
    info.characteristics = rd_u16(d, l.opt_off - 20 + 18).unwrap_or(0);
    info.image_base = l.image_base;
    info.import_section = import_section_index(&l);
    info.export_names = collect_export_names(d, &l);
    info.export_dll_name = export_dll_name(d, &l);
    info.resources_section = resources_section_index(&l);
    info.resources = collect_resources_l(d, &l);
    // getResourceManifest: first RT_MANIFEST(24) leaf, ANSI, <=4000 B.
    if let Some(r) = info
        .resources
        .iter()
        .find(|r| r.id1 == 24 && r.data_off != 0 && r.data_off < d.len())
    {
        let n = r.data_size.min(4000).min(d.len() - r.data_off);
        info.manifest = String::from_utf8_lossy(&d[r.data_off..r.data_off + n]).into_owned();
    }
    info.res_version = crate::pe_version::resources_version_from(d, &info.resources);
    info.tls_present = l.dir_rva[9] != 0;
    info.cert_offset = l.dir_rva[4] as usize;
    info.cert_size = l.dir_size[4] as usize;
    info.entry_rva = l.entry_rva;
    info.e_lfanew = l.e_lfanew;
    info.time_stamp = l.time_stamp;
    info.base_of_data = l.base_of_data;
    info.minor_image = l.minor_image;
    info.section_alignment = l.section_alignment;
    info.file_alignment = l.file_alignment;

    info.extents = l
        .sections
        .iter()
        .map(|s| SectionExtent {
            name: s.name.clone(),
            off: s.raw_ptr as usize,
            size: s.raw_size as usize,
            flags: s.flags,
            code: s.flags & 0x2000_0000 != 0,
            vaddr: s.vaddr,
            vsize: s.vsize,
            ptr_reloc: s.ptr_reloc,
            ptr_linenum: s.ptr_linenum,
        })
        .collect();

    collect_imports(d, &l, &mut info);
    collect_rich(d, &mut info);

    Some(info)
}

fn collect_imports(d: &[u8], l: &PeLayout, info: &mut PeInfo) {
    let mut desc_off = match rva_to_off(l, l.dir_rva[DIR_IMPORT]) {
        Some(o) => o,
        None => return,
    };
    let thunk_w = if l.is64 { 8usize } else { 4usize };
    for _ in 0..256 {
        let (chars, name_rva, first_thunk) = match (
            rd_u32(d, desc_off),
            rd_u32(d, desc_off + 12),
            rd_u32(d, desc_off + 16),
        ) {
            (Some(c), Some(n), Some(f)) => (c, n, f),
            _ => return,
        };
        if chars == 0 && name_rva == 0 {
            break;
        }
        let Some(lib_off) = rva_to_off(l, name_rva) else {
            break;
        };
        let Some(lib) = rd_str(d, lib_off, 256) else {
            break;
        };
        if lib.is_empty() {
            break;
        }
        // Field at +0 is the OriginalFirstThunk/Characteristics union;
        // fall back to FirstThunk exactly like XPE::getImportRecords.
        let thunk_rva = if chars != 0 { chars } else { first_thunk };
        let Some(mut toff) = rva_to_off(l, thunk_rva) else {
            desc_off += 20;
            continue;
        };
        let mut header = ImportHeader {
            name: lib.clone(),
            positions: Vec::new(),
        };
        for _ in 0..65536 {
            let Some(val) = (if l.is64 {
                rd_u64(d, toff)
            } else {
                rd_u32(d, toff).map(u64::from)
            }) else {
                break;
            };
            if val == 0 {
                break;
            }
            let ord_flag = if l.is64 { 1u64 << 63 } else { 1u64 << 31 };
            let func = if val & ord_flag != 0 {
                (val & (ord_flag - 1)).to_string()
            } else {
                let Some(noff) = rva_to_off(l, val as u32) else {
                    break;
                };
                let Some(name) = rd_str(d, noff + 2, 512) else {
                    break;
                };
                if name.is_empty() {
                    break;
                }
                name
            };
            info.imports.push(ImportRecord {
                library: lib.clone(),
                function: func.clone(),
            });
            header.positions.push(func);
            toff += thunk_w;
        }
        info.import_headers.push(header);
        desc_off += 20;
    }
}

fn collect_rich(d: &[u8], info: &mut PeInfo) {
    // `getRichSignatureRecords`: "Rich" inside the DOS stub; backwards
    // 4-byte XOR walk to "DanS", then a forward pass of (id<<16|build,
    // count) pairs.
    let limit = d.len().min(0x400);
    let Some(pos) = d[..limit].windows(4).position(|w| w == b"Rich") else {
        return;
    };
    let Some(key) = rd_u32(d, pos + 4) else {
        return;
    };
    let mut off = pos as i64 - 4;
    while off > 0x40 {
        let v = rd_u32(d, off as usize).unwrap_or(0) ^ key;
        if v == 0x536E_6144 {
            let mut i = off as usize + 16;
            while i + 4 < pos {
                let v1 = rd_u32(d, i).unwrap_or(0) ^ key;
                let count = rd_u32(d, i + 4).unwrap_or(0) ^ key;
                info.rich.push(((v1 >> 16) as u16, v1 & 0xFFFF, count));
                i += 8;
            }
            break;
        }
        off -= 4;
    }
}

/// Flattened resource `(type, name)` pairs — level-1 and level-2 of the
/// PE resource tree — for `NFD_Binary::PE_resourcesScan`.
/// Resource-tree walk bound to an already-parsed layout.
fn collect_resources_l(d: &[u8], l: &PeLayout) -> Vec<crate::scans::ResourceEntry> {
    use crate::scans::ResourceEntry;
    let Some(root) = rva_to_off(l, l.dir_rva[DIR_RESOURCE]) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // Level 1: type directory.
    let Some(named) = rd_u16(d, root + 12).map(|v| v as usize) else {
        return out;
    };
    let Some(ided) = rd_u16(d, root + 14).map(|v| v as usize) else {
        return out;
    };
    for i in 0..(named + ided).min(256) {
        let e = root + 16 + i * 8;
        let (Some(id1), Some(sub)) = (rd_u32(d, e), rd_u32(d, e + 4)) else {
            continue;
        };
        let (name1, t1) = if id1 & 0x8000_0000 != 0 {
            let so = root + (id1 & 0x7FFF_FFFF) as usize;
            match rd_res_name(d, so) {
                Some(s) => (Some(s), 0),
                None => continue,
            }
        } else {
            (None, id1 & 0xFFFF)
        };
        if sub & 0x8000_0000 == 0 {
            continue;
        }
        let dir2 = root + (sub & 0x7FFF_FFFF) as usize;
        let (Some(n2), Some(i2)) = (
            rd_u16(d, dir2 + 12).map(|v| v as usize),
            rd_u16(d, dir2 + 14).map(|v| v as usize),
        ) else {
            continue;
        };
        for j in 0..(n2 + i2).min(4096) {
            let e2 = dir2 + 16 + j * 8;
            let Some(id2) = rd_u32(d, e2) else { continue };
            let (name2, nid2) = if id2 & 0x8000_0000 != 0 {
                let so = root + (id2 & 0x7FFF_FFFF) as usize;
                match rd_res_name(d, so) {
                    Some(s) => (Some(s), 0),
                    None => continue,
                }
            } else {
                (None, id2 & 0xFFFF)
            };
            // Level-3 leaf: language entry → data entry (rva, size).
            let (mut data_off, mut data_size) = (0usize, 0usize);
            if let Some(sub2) = rd_u32(d, e2 + 4)
                && sub2 & 0x8000_0000 != 0
            {
                let dir3 = root + (sub2 & 0x7FFF_FFFF) as usize;
                if let Some(e3sub) = rd_u32(d, dir3 + 16 + 4)
                    && e3sub & 0x8000_0000 == 0
                {
                    let dentry = root + e3sub as usize;
                    if let (Some(rva), Some(sz)) = (rd_u32(d, dentry), rd_u32(d, dentry + 4))
                        && let Some(foff) = rva_to_off(l, rva)
                    {
                        data_off = foff;
                        data_size = sz as usize;
                    }
                }
            }
            out.push(ResourceEntry {
                name1: name1.clone(),
                id1: t1,
                name2,
                id2: nid2,
                data_off,
                data_size,
            });
        }
    }
    out
}

/// Read a UTF-16LE resource name string at `off`.
/// `XPE::isResourcePresent` — two-level match on (type, name-or-id).
/// `want` is either a numeric level-2 id or a level-2 name string.
pub fn resource_present(
    res: &[crate::scans::ResourceEntry],
    id1: u32,
    name2: Option<&str>,
    id2: Option<u32>,
) -> bool {
    res.iter().any(|r| {
        if r.id1 != id1 {
            return false;
        }
        match (name2, id2) {
            (Some(n), _) => r.name2.as_deref() == Some(n),
            (None, Some(i)) => r.id2 == i,
            (None, None) => true,
        }
    })
}

/// `XPE::getResourceRecord` — first leaf of (type, level-2 id);
/// returns (data_off, data_size).
pub fn resource_record(
    res: &[crate::scans::ResourceEntry],
    id1: u32,
    id2: u32,
) -> Option<(usize, usize)> {
    res.iter()
        .find(|r| r.id1 == id1 && r.id2 == id2)
        .map(|r| (r.data_off, r.data_size))
        .filter(|(o, _)| *o != 0)
}

/// Collect the flattened resource list (parses layout internally).
pub fn collect_resources(d: &[u8]) -> Vec<crate::scans::ResourceEntry> {
    let Some(l) = parse_layout(d) else {
        return Vec::new();
    };
    collect_resources_l(d, &l)
}

fn rd_res_name(d: &[u8], off: usize) -> Option<String> {
    let len = rd_u16(d, off)? as usize;
    let mut s = String::with_capacity(len);
    for i in 0..len.min(256) {
        let w = rd_u16(d, off + 2 + i * 2)?;
        s.push(char::from_u32(u32::from(w))?);
    }
    Some(s)
}

impl PeInfo {
    /// File offset/size of the largest code-ish section (first
    /// executable section), mirroring `osCodeSection`.
    pub fn code_section_extent(&self, _data: &[u8]) -> Option<(usize, usize)> {
        self.extents
            .iter()
            .find(|e| e.code)
            .map(|e| (e.off, e.size))
    }

    /// `XPE::addressToOffset` subset: interpret `va` as a VA
    /// (`va - image_base` → RVA) when above the image base, else as a
    /// bare RVA; map through section extents (raw file offsets).
    pub fn va_to_off(&self, va: u32) -> Option<usize> {
        let rva = if u64::from(va) >= self.image_base {
            u64::from(va).checked_sub(self.image_base)? as u32
        } else {
            va
        };
        for e in &self.extents {
            let span = e.size.max(e.vsize as usize);
            if rva >= e.vaddr && (rva - e.vaddr) < span as u32 && e.size != 0 {
                return Some(e.off + (rva - e.vaddr) as usize);
            }
        }
        None
    }

    /// `XPE::offsetToAddress` subset for signature jumps: map a file
    /// offset inside a section's raw extent to its RVA.
    pub fn off_to_rva(&self, off: usize) -> Option<u32> {
        for e in &self.extents {
            if off >= e.off && (off - e.off) < e.size {
                return Some(e.vaddr.wrapping_add((off - e.off) as u32));
            }
        }
        None
    }

    /// Owned `SigCtx` resolving `$$`/`#` signature elements through the
    /// PE address map (`offsetToAddress`/`addressToOffset` over section
    /// extents — upstream `XPE` `_MEMORY_MAP` semantics).
    pub fn sig_ctx(&self) -> die_core::signature::SigCtx {
        let ext = self.extents.clone();
        let ib = self.image_base;
        let o2a = move |o: u64| -> Option<u64> {
            let off = usize::try_from(o).ok()?;
            for e in &ext {
                if off >= e.off && (off - e.off) < e.size {
                    return Some(u64::from(e.vaddr.wrapping_add((off - e.off) as u32)));
                }
            }
            None
        };
        let ext = self.extents.clone();
        let a2o = move |a: u64| -> Option<u64> {
            let rva = if a >= ib { a.checked_sub(ib)? } else { a };
            let rva = u32::try_from(rva).ok()?;
            for e in &ext {
                let span = e.size.max(e.vsize as usize);
                if rva >= e.vaddr && (rva - e.vaddr) < span as u32 && e.size != 0 {
                    return Some((e.off + (rva - e.vaddr) as usize) as u64);
                }
            }
            None
        };
        die_core::signature::SigCtx {
            off_to_addr: Some(Box::new(o2a)),
            addr_to_off: Some(Box::new(a2o)),
            seg_wrap16: false,
            msdos_addr: None,
        }
    }

    /// `XPE::isSectionNamePresent` — case-sensitive name membership test
    /// (`sName == sSectionName` in upstream xpe.cpp:2458).
    pub fn has_section_name(&self, name: &str) -> bool {
        self.section_names.iter().any(|n| n == name)
    }

    /// Index of the section containing the entry point
    /// (`nEntryPointSection`). Upstream resolves the EP **virtual
    /// address** against the memory map: `image_base + entry_rva` must
    /// fall inside `[va, va + max(align_up(vsize, SectionAlignment),
    /// raw file size))` of a section; records are scanned in reverse so
    /// overlapping sections resolve to the last one (`getMemoryRecordByAddress`).
    /// Returns -1 when `entry_rva == 0` or outside every extent.
    pub fn entrypoint_section_index(&self) -> i32 {
        if self.entry_rva == 0 {
            return -1;
        }
        let va = self.image_base.wrapping_add(u64::from(self.entry_rva));
        for (i, e) in self.extents.iter().enumerate().rev() {
            let lo = self.image_base.wrapping_add(u64::from(e.vaddr));
            // File record: SizeOfRawData + (raw_ptr - align_down(raw_ptr, FileAlignment)).
            let fa = u64::from(self.file_alignment).max(1);
            let file_size = e.size as u64 + (e.off as u64).saturating_sub(e.off as u64 / fa * fa);
            let sa = u64::from(self.section_alignment).max(1);
            let virt_size = u64::from(e.vsize).div_ceil(sa) * sa;
            let hi = lo.wrapping_add(file_size.max(virt_size));
            if va >= lo && va < hi {
                return i as i32;
            }
        }
        -1
    }

    /// File offset/size of the section containing the entry point,
    /// mirroring `osEntryPointSection`.
    pub fn entrypoint_section_extent(&self, _data: &[u8]) -> Option<(usize, usize)> {
        let ep = self.entry_point_offset;
        if ep < 0 {
            return None;
        }
        self.extents
            .iter()
            .find(|e| ep as usize >= e.off && (ep as usize) < e.off + e.size)
            .map(|e| (e.off, e.size))
    }
}

/// Internal section extent record kept inside `PeInfo`.
#[derive(Debug, Clone)]
pub struct SectionExtent {
    /// Section name (uppercased by upstream convention).
    pub name: String,
    /// File offset.
    pub off: usize,
    /// File size (`SizeOfRawData`).
    pub size: usize,
    /// Raw `Characteristics` (masked with 0xFF0000FF by callers).
    pub flags: u32,
    /// Executable flag (`IMAGE_SCN_MEM_EXECUTE`).
    pub code: bool,
    /// `VirtualAddress` (RVA base of the section).
    pub vaddr: u32,
    /// `VirtualSize` (`Misc.VirtualSize`).
    pub vsize: u32,
    /// `PointerToRelocations` — PECompact build-number probe.
    pub ptr_reloc: u32,
    /// `PointerToLinenumbers` — PECompact build-number probe.
    pub ptr_linenum: u32,
}

/// Parse and return the PE layout for signature-expression resolution.
pub fn collect_layout(d: &[u8]) -> Option<PeLayout> {
    parse_layout(d)
}

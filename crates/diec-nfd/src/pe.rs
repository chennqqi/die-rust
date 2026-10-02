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
    /// Section extents for deep scans.
    pub extents: Vec<SectionExtent>,
    /// Import-directory section index (`getImageDirectoryEntrySection`),
    /// -1 when not found.
    pub import_section: i32,
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
    if nsects == 0 || nsects > 96 {
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
    let sec_off = opt_off + opt_size;
    let mut sections = Vec::with_capacity(nsects);
    for i in 0..nsects {
        let so = sec_off + i * 40;
        let name_raw = d.get(so..so + 8)?;
        let end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
        sections.push(Section {
            name: String::from_utf8_lossy(&name_raw[..end]).to_uppercase(),
            vaddr: rd_u32(d, so + 12)?,
            vsize: rd_u32(d, so + 8)?,
            raw_ptr: rd_u32(d, so + 20)?,
            raw_size: rd_u32(d, so + 16)?,
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
const DIR_RESOURCE: usize = 2;
const DIR_CLR: usize = 14;

/// Index of the section containing the import directory
/// (`XPE::getImageDirectoryEntrySection`), -1 when unmapped.
fn import_section_index(l: &PeLayout) -> i32 {
    let rva = l.dir_rva[DIR_IMPORT];
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
    info.overlay_offset = if end != 0 && end < d.len() as u64 {
        end as i64
    } else {
        -1
    };

    info.is_dotnet = l.dir_rva[DIR_CLR] != 0;
    info.dotnet_version = dotnet_metadata_version(d, &l);

    // Optional-header / COFF fields used by handle_OperationSystem and
    // handle_Microsoft.
    info.major_linker = d.get(l.opt_off + 2).copied().unwrap_or(0);
    info.minor_linker = d.get(l.opt_off + 3).copied().unwrap_or(0);
    let (osv_off, subsys_off) = if l.is64 { (44, 72) } else { (40, 68) };
    let maj_os = rd_u16(d, l.opt_off + osv_off).unwrap_or(0);
    let min_os = rd_u16(d, l.opt_off + osv_off + 2).unwrap_or(0);
    info.os_version = (u32::from(maj_os) << 16) | u32::from(min_os);
    info.subsystem = rd_u16(d, l.opt_off + subsys_off).unwrap_or(0);
    info.machine = rd_u16(d, l.opt_off - 20).unwrap_or(0);
    info.characteristics = rd_u16(d, l.opt_off - 20 + 18).unwrap_or(0);
    info.image_base = l.image_base;
    info.import_section = import_section_index(&l);

    info.extents = l
        .sections
        .iter()
        .map(|s| SectionExtent {
            name: s.name.clone(),
            off: s.raw_ptr as usize,
            size: s.raw_size as usize,
            flags: s.flags,
            code: s.flags & 0x2000_0000 != 0,
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
    // Rich header: search first 1 KiB for "Rich" marker; backwards XOR walk.
    let limit = d.len().min(0x400);
    let Some(pos) = d[..limit].windows(4).position(|w| w == b"Rich") else {
        return;
    };
    let Some(key) = rd_u32(d, pos + 4) else {
        return;
    };
    let mut off = pos as i64 - 4;
    while off >= 4 {
        let v = rd_u32(d, off as usize).unwrap_or(0) ^ key;
        if v == 0x536E_6144 {
            break; // "DanS"
        }
        let id_raw = v;
        let count = rd_u32(d, off as usize + 4).unwrap_or(0) ^ key;
        let compid = (id_raw & 0xFFFF) as u16;
        let build = id_raw >> 16;
        info.rich.push((compid, build, count));
        off -= 8;
    }
}

/// Flattened resource `(type, name)` pairs — level-1 and level-2 of the
/// PE resource tree — for `NFD_Binary::PE_resourcesScan`.
pub fn collect_resources(d: &[u8]) -> Vec<crate::scans::ResourceEntry> {
    use crate::scans::ResourceEntry;
    let Some(l) = parse_layout(d) else {
        return Vec::new();
    };
    let Some(root) = rva_to_off(&l, l.dir_rva[DIR_RESOURCE]) else {
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
            out.push(ResourceEntry {
                name1: name1.clone(),
                id1: t1,
                name2,
                id2: nid2,
            });
        }
    }
    out
}

/// Read a UTF-16LE resource name string at `off`.
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
}

/// Parse and return the PE layout for signature-expression resolution.
pub fn collect_layout(d: &[u8]) -> Option<PeLayout> {
    parse_layout(d)
}

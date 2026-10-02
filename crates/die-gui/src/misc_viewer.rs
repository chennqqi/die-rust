//! DEX, MSDOS, NE, LE format viewers.
//!
//! Provides dedicated views for less common executable formats,
//! mirroring upstream DIE-engine format widgets.

use serde::{Deserialize, Serialize};

// ============================================================================
// DEX (Dalvik Executable)
// ============================================================================

/// DEX header fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexView {
    /// Magic string ("dex\n").
    pub magic: String,
    /// DEX version (e.g. "035", "037", "038", "039").
    pub version: String,
    /// Checksum (adler32).
    pub checksum: u32,
    /// SHA-1 signature (hex string).
    pub signature: String,
    /// File size.
    pub file_size: u32,
    /// Header size (usually 0x70).
    pub header_size: u32,
    /// Endian tag (0x12345678 for little-endian).
    pub endian_tag: u32,
    /// Link size.
    pub link_size: u32,
    /// Link offset.
    pub link_off: u32,
    /// Map offset.
    pub map_off: u32,
    /// String IDs size.
    pub string_ids_size: u32,
    /// String IDs offset.
    pub string_ids_off: u32,
    /// Type IDs size.
    pub type_ids_size: u32,
    /// Type IDs offset.
    pub type_ids_off: u32,
    /// Proto IDs size.
    pub proto_ids_size: u32,
    /// Proto IDs offset.
    pub proto_ids_off: u32,
    /// Field IDs size.
    pub field_ids_size: u32,
    /// Field IDs offset.
    pub field_ids_off: u32,
    /// Method IDs size.
    pub method_ids_size: u32,
    /// Method IDs offset.
    pub method_ids_off: u32,
    /// Class defs size.
    pub class_defs_size: u32,
    /// Class defs offset.
    pub class_defs_off: u32,
    /// Data size.
    pub data_size: u32,
    /// Data offset.
    pub data_off: u32,
}

/// Parse DEX view from raw bytes.
pub fn parse_dex_view(data: &[u8]) -> Option<DexView> {
    // DEX magic: "dex\n" followed by version (3 digits) + "\n".
    if data.len() < 0x70 {
        return None;
    }
    if &data[0..4] != b"dex\n" {
        return None;
    }
    let version = String::from_utf8_lossy(&data[4..7]).to_string();
    let u32le =
        |off: usize| u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    let signature = data[12..32]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    Some(DexView {
        magic: "dex\n".to_string(),
        version,
        checksum: u32le(8),
        signature,
        file_size: u32le(0x20),
        header_size: u32le(0x24),
        endian_tag: u32le(0x28),
        link_size: u32le(0x2c),
        link_off: u32le(0x30),
        map_off: u32le(0x34),
        string_ids_size: u32le(0x38),
        string_ids_off: u32le(0x3c),
        type_ids_size: u32le(0x40),
        type_ids_off: u32le(0x44),
        proto_ids_size: u32le(0x48),
        proto_ids_off: u32le(0x4c),
        field_ids_size: u32le(0x50),
        field_ids_off: u32le(0x54),
        method_ids_size: u32le(0x58),
        method_ids_off: u32le(0x5c),
        class_defs_size: u32le(0x60),
        class_defs_off: u32le(0x64),
        data_size: u32le(0x68),
        data_off: u32le(0x6c),
    })
}

/// Maximum entries parsed per DEX id table (defensive bound against
/// malformed counts).
const MAX_DEX_TABLE: usize = 1_000_000;
/// Maximum bytes read for a single DEX string (display safety bound).
const MAX_DEX_STRING: usize = 4096;

/// A resolved DEX proto_id entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexProto {
    /// Shorty descriptor string.
    pub shorty: String,
    /// Return type descriptor.
    pub return_type: String,
    /// Parameter type descriptors.
    pub parameters: Vec<String>,
}

/// A resolved DEX field_id entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexField {
    /// Declaring class descriptor.
    pub class: String,
    /// Field type descriptor.
    pub field_type: String,
    /// Field name.
    pub name: String,
}

/// A resolved DEX method_id entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexMethod {
    /// Declaring class descriptor.
    pub class: String,
    /// Method name.
    pub name: String,
    /// Proto descriptor in `()ret` notation.
    pub proto: String,
}

/// A resolved DEX class_def entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexClassDef {
    /// Class descriptor.
    pub class: String,
    /// Access flags bitmask.
    pub access_flags: u32,
    /// Superclass descriptor ("-" for NO_INDEX).
    pub superclass: String,
    /// Source file name ("-" for NO_INDEX).
    pub source_file: String,
}

/// A DEX map_list item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexMapItem {
    /// Item type code (e.g. 0x0001 for string_id).
    pub item_type: u16,
    /// Human-readable type name.
    pub type_name: String,
    /// Item count covered by this map entry.
    pub size: u32,
    /// File offset of the section.
    pub offset: u32,
}

/// Deep DEX view: resolved string/type/proto/field/method/class_def tables
/// plus the map list, mirroring upstream DEX widget tabs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexDeepView {
    /// Decoded string_data items (index = string_idx).
    pub strings: Vec<String>,
    /// Type descriptors (index = type_idx).
    pub types: Vec<String>,
    /// Proto table.
    pub protos: Vec<DexProto>,
    /// Field table.
    pub fields: Vec<DexField>,
    /// Method table.
    pub methods: Vec<DexMethod>,
    /// Class definitions.
    pub class_defs: Vec<DexClassDef>,
    /// Map list items.
    pub map_items: Vec<DexMapItem>,
    /// True when any table hit the entry cap.
    pub truncated: bool,
}

/// Read a little-endian u16, returning `None` on out-of-range access.
fn dex_u16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Read a little-endian u32, returning `None` on out-of-range access.
fn dex_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a uleb128 value at `off`, returning `(value, next_offset)`.
fn dex_uleb128(data: &[u8], mut off: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let b = *data.get(off)?;
        result |= u64::from(b & 0x7f) << shift;
        off += 1;
        if b & 0x80 == 0 {
            return Some((result, off));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

/// Decode the NUL-terminated MUTF-8 payload of a string_data item at `off`,
/// bounded by `MAX_DEX_STRING` bytes.
fn dex_string_at(data: &[u8], off: usize) -> Option<String> {
    let (_, mut pos) = dex_uleb128(data, off)?;
    let end = pos.saturating_add(MAX_DEX_STRING).min(data.len());
    let start = pos;
    while pos < end && data[pos] != 0 {
        pos += 1;
    }
    Some(String::from_utf8_lossy(&data[start..pos]).into_owned())
}

/// Human-readable name for a DEX map item type code.
fn dex_map_type_name(t: u16) -> &'static str {
    match t {
        0x0000 => "header_item",
        0x0001 => "string_id_item",
        0x0002 => "type_id_item",
        0x0003 => "proto_id_item",
        0x0004 => "field_id_item",
        0x0005 => "method_id_item",
        0x0006 => "class_def_item",
        0x0007 => "call_site_id_item",
        0x0008 => "method_handle_item",
        0x2000 => "map_list",
        0x2001 => "type_list",
        0x2002 => "annotation_set_ref_list",
        0x2003 => "annotation_set_item",
        0x2004 => "class_data_item",
        0x2005 => "code_item",
        0x2006 => "string_data_item",
        0x2007 => "debug_info_item",
        0x2008 => "annotation_item",
        0x2009 => "encoded_array_item",
        0x200A => "annotations_directory_item",
        0x200B => "hiddenapi_class_data_item",
        _ => "unknown",
    }
}

/// Parse the deep DEX tables (strings/types/protos/fields/methods/class_defs/
/// map). Returns `None` for non-DEX input; malformed sections yield
/// `Err`-free partial data — entries that fail bounds checks are simply
/// absent.
pub fn parse_dex_deep_view(data: &[u8]) -> Option<DexDeepView> {
    let h = parse_dex_view(data)?;
    let len = data.len();
    let mut truncated = false;

    let capped = |count: u32, item_size: usize, off: u32, trunc: &mut bool| -> Option<usize> {
        let n = count as usize;
        if n > MAX_DEX_TABLE {
            *trunc = true;
        }
        let n = n.min(MAX_DEX_TABLE);
        let end = (off as usize).checked_add(n.checked_mul(item_size)?)?;
        if end > len {
            *trunc = true;
            // Clamp to what is actually present.
            let avail = len.saturating_sub(off as usize) / item_size;
            return Some(avail);
        }
        Some(n)
    };

    // --- strings ---
    let mut strings = Vec::new();
    if let Some(n) = capped(h.string_ids_size, 4, h.string_ids_off, &mut truncated) {
        for i in 0..n {
            let s = dex_u32(data, h.string_ids_off as usize + i * 4)
                .and_then(|soff| dex_string_at(data, soff as usize))
                .unwrap_or_default();
            strings.push(s);
        }
    }
    let str_get = |idx: u32| -> String { strings.get(idx as usize).cloned().unwrap_or_default() };

    // --- types ---
    let mut types = Vec::new();
    if let Some(n) = capped(h.type_ids_size, 4, h.type_ids_off, &mut truncated) {
        for i in 0..n {
            let t = dex_u32(data, h.type_ids_off as usize + i * 4)
                .map(str_get)
                .unwrap_or_default();
            types.push(t);
        }
    }
    let type_get = |idx: u32| -> String { types.get(idx as usize).cloned().unwrap_or_default() };

    // --- protos ---
    let mut protos = Vec::new();
    if let Some(n) = capped(h.proto_ids_size, 12, h.proto_ids_off, &mut truncated) {
        for i in 0..n {
            let base = h.proto_ids_off as usize + i * 12;
            let shorty_idx = dex_u32(data, base).unwrap_or(0);
            let return_type_idx = dex_u32(data, base + 4).unwrap_or(0);
            let parameters_off = dex_u32(data, base + 8).unwrap_or(0);
            let mut parameters = Vec::new();
            if parameters_off != 0
                && let Some(n_params) = dex_u32(data, parameters_off as usize)
            {
                let n_params = n_params.min(MAX_DEX_TABLE as u32);
                for p in 0..n_params {
                    let poff = parameters_off as usize + 4 + p as usize * 2;
                    match dex_u16(data, poff) {
                        Some(t) => parameters.push(type_get(u32::from(t))),
                        None => break,
                    }
                }
            }
            protos.push(DexProto {
                shorty: str_get(shorty_idx),
                return_type: type_get(return_type_idx),
                parameters,
            });
        }
    }

    // --- fields ---
    let mut fields = Vec::new();
    if let Some(n) = capped(h.field_ids_size, 8, h.field_ids_off, &mut truncated) {
        for i in 0..n {
            let base = h.field_ids_off as usize + i * 8;
            fields.push(DexField {
                class: type_get(u32::from(dex_u16(data, base).unwrap_or(0))),
                field_type: type_get(u32::from(dex_u16(data, base + 2).unwrap_or(0))),
                name: str_get(dex_u32(data, base + 4).unwrap_or(0)),
            });
        }
    }

    // --- methods ---
    let mut methods = Vec::new();
    if let Some(n) = capped(h.method_ids_size, 8, h.method_ids_off, &mut truncated) {
        for i in 0..n {
            let base = h.method_ids_off as usize + i * 8;
            let class = type_get(u32::from(dex_u16(data, base).unwrap_or(0)));
            let proto_idx = u32::from(dex_u16(data, base + 2).unwrap_or(0));
            let name = str_get(dex_u32(data, base + 4).unwrap_or(0));
            let proto = protos
                .get(proto_idx as usize)
                .map(|p| format!("({}){}", p.parameters.join(""), p.return_type))
                .unwrap_or_default();
            methods.push(DexMethod { class, name, proto });
        }
    }

    // --- class defs ---
    let mut class_defs = Vec::new();
    if let Some(n) = capped(h.class_defs_size, 32, h.class_defs_off, &mut truncated) {
        for i in 0..n {
            let base = h.class_defs_off as usize + i * 32;
            let class_idx = dex_u32(data, base).unwrap_or(0);
            let access_flags = dex_u32(data, base + 4).unwrap_or(0);
            let superclass_idx = dex_u32(data, base + 8).unwrap_or(0xFFFF_FFFF);
            let source_file_idx = dex_u32(data, base + 16).unwrap_or(0xFFFF_FFFF);
            class_defs.push(DexClassDef {
                class: type_get(class_idx),
                access_flags,
                superclass: if superclass_idx == 0xFFFF_FFFF {
                    "-".to_string()
                } else {
                    type_get(superclass_idx)
                },
                source_file: if source_file_idx == 0xFFFF_FFFF {
                    "-".to_string()
                } else {
                    str_get(source_file_idx)
                },
            });
        }
    }

    // --- map list ---
    let mut map_items = Vec::new();
    if h.map_off != 0
        && let Some(n) = dex_u32(data, h.map_off as usize)
    {
        let n = n.min(MAX_DEX_TABLE as u32) as usize;
        for i in 0..n {
            let base = h.map_off as usize + 4 + i * 12;
            let (t, size, offset) = match (
                dex_u16(data, base),
                dex_u32(data, base + 4),
                dex_u32(data, base + 8),
            ) {
                (Some(t), Some(s), Some(o)) => (t, s, o),
                _ => break,
            };
            map_items.push(DexMapItem {
                item_type: t,
                type_name: dex_map_type_name(t).to_string(),
                size,
                offset,
            });
        }
    }

    Some(DexDeepView {
        strings,
        types,
        protos,
        fields,
        methods,
        class_defs,
        map_items,
        truncated,
    })
}

// ============================================================================
// MSDOS (DOS MZ executable)
// ============================================================================

/// MSDOS MZ header view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsdosView {
    /// MZ magic.
    pub magic: String,
    /// Bytes on last page.
    pub e_cblp: u16,
    /// Pages in file.
    pub e_cp: u16,
    /// Relocations.
    pub e_crlc: u16,
    /// Header size in paragraphs.
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs.
    pub e_minalloc: u16,
    /// Maximum extra paragraphs.
    pub e_maxalloc: u16,
    /// Initial SS.
    pub e_ss: u16,
    /// Initial SP.
    pub e_sp: u16,
    /// Checksum.
    pub e_csum: u16,
    /// Initial IP.
    pub e_ip: u16,
    /// Initial CS.
    pub e_cs: u16,
    /// Relocation table offset.
    pub e_lfarlc: u16,
    /// Overlay number.
    pub e_ovno: u16,
    /// OEM ID.
    pub e_oemid: u16,
    /// OEM info.
    pub e_oeminfo: u16,
    /// PE header offset (e_lfanew).
    pub e_lfanew: u32,
    /// Has PE header.
    pub has_pe: bool,
}

/// Parse MSDOS MZ view from raw bytes.
pub fn parse_msdos_view(data: &[u8]) -> Option<MsdosView> {
    if data.len() < 64 {
        return None;
    }
    if &data[0..2] != b"MZ" {
        return None;
    }
    let u16le = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);
    let u32le =
        |off: usize| u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    let e_lfanew = u32le(60);
    let has_pe = e_lfanew > 0
        && e_lfanew as usize + 4 <= data.len()
        && &data[e_lfanew as usize..e_lfanew as usize + 4] == b"PE\x00\x00";
    Some(MsdosView {
        magic: "MZ".to_string(),
        e_cblp: u16le(2),
        e_cp: u16le(4),
        e_crlc: u16le(6),
        e_cparhdr: u16le(8),
        e_minalloc: u16le(10),
        e_maxalloc: u16le(12),
        e_ss: u16le(14),
        e_sp: u16le(16),
        e_csum: u16le(18),
        e_ip: u16le(20),
        e_cs: u16le(22),
        e_lfarlc: u16le(24),
        e_ovno: u16le(26),
        e_oemid: u16le(36),
        e_oeminfo: u16le(38),
        e_lfanew,
        has_pe,
    })
}

// ============================================================================
// NE (New Executable, Windows 16-bit)
// ============================================================================

/// NE header view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeView {
    /// NE magic ("NE").
    pub magic: String,
    /// Linker version.
    pub linker_version: u8,
    /// Linker revision.
    pub linker_revision: u8,
    /// Entry table offset (from NE header).
    pub entry_table_offset: u16,
    /// Entry table length.
    pub entry_table_length: u16,
    /// File load size (32-bit).
    pub file_load_size: u32,
    /// Non-resident name table offset.
    pub non_resident_name_offset: u32,
    /// Non-resident name table length.
    pub non_resident_name_length: u16,
    /// Module description offset.
    pub module_description_offset: u16,
    /// Module description length.
    pub module_description_length: u16,
    /// Segment count.
    pub segment_count: u16,
    /// Module references count.
    pub module_refs_count: u16,
    /// Movable segments count.
    pub movable_segments: u16,
    /// Alignment shift count.
    pub alignment_shift: u16,
    /// Number of resource segments.
    pub resource_segments: u16,
    /// Target OS (1=DOS, 2=Windows, 3=OS/2, 4=Windows 386).
    pub target_os: u8,
    /// OS version.
    pub os_version: u16,
    /// Windows version.
    pub windows_version: u16,
}

/// Parse NE view from raw bytes.
pub fn parse_ne_view(data: &[u8]) -> Option<NeView> {
    if data.len() < 64 {
        return None;
    }
    // NE header is at e_lfanew offset from MZ header.
    let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if e_lfanew + 2 > data.len() {
        return None;
    }
    if &data[e_lfanew..e_lfanew + 2] != b"NE" {
        return None;
    }
    let off = e_lfanew;
    if off + 64 > data.len() {
        return None;
    }
    let u16le = |o: usize| u16::from_le_bytes([data[off + o], data[off + o + 1]]);
    let u32le = |o: usize| {
        u32::from_le_bytes([
            data[off + o],
            data[off + o + 1],
            data[off + o + 2],
            data[off + o + 3],
        ])
    };
    Some(NeView {
        magic: "NE".to_string(),
        linker_version: data[off + 2],
        linker_revision: data[off + 3],
        entry_table_offset: u16le(4),
        entry_table_length: u16le(6),
        file_load_size: u32le(8),
        non_resident_name_offset: u32le(12),
        non_resident_name_length: u16le(16),
        module_description_offset: u16le(18),
        module_description_length: u16le(20),
        segment_count: u16le(22),
        module_refs_count: u16le(24),
        movable_segments: u16le(26),
        alignment_shift: u16le(32),
        resource_segments: u16le(34),
        target_os: data[off + 54],
        os_version: u16le(58),
        windows_version: u16le(60),
    })
}

// ============================================================================
// LE (Linear Executable, OS/2 / Windows 386)
// ============================================================================

/// LE header view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeView {
    /// LE magic ("LE").
    pub magic: String,
    /// Byte order (0=LE, 1=BE).
    pub byte_order: u16,
    /// Word order.
    pub word_order: u16,
    /// Executable format level.
    pub exe_format_level: u32,
    /// CPU type.
    pub cpu_type: u16,
    /// OS type.
    pub os_type: u16,
    /// Module version.
    pub module_version: u32,
    /// Module flags.
    pub module_flags: u32,
    /// Number of module pages.
    pub module_page_count: u32,
    /// Initial object count (EIP object).
    pub init_object_count: u32,
    /// Object count.
    pub object_count: u32,
    /// Object page map offset.
    pub object_page_map_offset: u32,
    /// Object iterated data offset.
    pub object_iterated_data_offset: u32,
    /// Offset of resource table.
    pub resource_table_offset: u32,
    /// Number of resource entries.
    pub resource_table_count: u32,
    /// Resident name table offset.
    pub resident_name_table_offset: u32,
    /// Entry table offset.
    pub entry_table_offset: u32,
    /// Module directives offset.
    pub module_directives_offset: u32,
    /// Number of module directives.
    pub module_directives_count: u32,
    /// Fixup page table offset.
    pub fixup_page_table_offset: u32,
    /// Fixup record table offset.
    pub fixup_record_table_offset: u32,
    /// Imported modules name table offset.
    pub imported_modules_name_table_offset: u32,
    /// Number of imported modules.
    pub imported_modules_count: u32,
}

/// Parse LE view from raw bytes.
pub fn parse_le_view(data: &[u8]) -> Option<LeView> {
    if data.len() < 64 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if e_lfanew + 2 > data.len() {
        return None;
    }
    if &data[e_lfanew..e_lfanew + 2] != b"LE" {
        return None;
    }
    let off = e_lfanew;
    if off + 88 > data.len() {
        return None;
    }
    let u16le = |o: usize| u16::from_le_bytes([data[off + o], data[off + o + 1]]);
    let u32le = |o: usize| {
        u32::from_le_bytes([
            data[off + o],
            data[off + o + 1],
            data[off + o + 2],
            data[off + o + 3],
        ])
    };
    Some(LeView {
        magic: "LE".to_string(),
        byte_order: u16le(2),
        word_order: u16le(4),
        exe_format_level: u32le(6),
        cpu_type: u16le(10),
        os_type: u16le(12),
        module_version: u32le(14),
        module_flags: u32le(18),
        module_page_count: u32le(22),
        init_object_count: u32le(26),
        object_count: u32le(30),
        object_page_map_offset: u32le(34),
        object_iterated_data_offset: u32le(38),
        resource_table_offset: u32le(42),
        resource_table_count: u32le(46),
        resident_name_table_offset: u32le(50),
        entry_table_offset: u32le(54),
        module_directives_offset: u32le(58),
        module_directives_count: u32le(62),
        fixup_page_table_offset: u32le(66),
        fixup_record_table_offset: u32le(70),
        imported_modules_name_table_offset: u32le(74),
        imported_modules_count: u32le(78),
    })
}

/// Get the target OS name for NE format.
#[allow(dead_code)]
pub fn ne_target_os_name(target_os: u8) -> String {
    match target_os {
        1 => "DOS".into(),
        2 => "Windows".into(),
        3 => "OS/2".into(),
        4 => "Windows 386".into(),
        _ => format!("Unknown (0x{:02x})", target_os),
    }
}

/// Get the CPU type name for LE format.
#[allow(dead_code)]
pub fn le_cpu_type_name(cpu_type: u16) -> String {
    match cpu_type {
        1 => "80286".into(),
        2 => "80386".into(),
        3 => "80486".into(),
        _ => format!("Unknown (0x{:04x})", cpu_type),
    }
}

/// Get the OS type name for LE format.
#[allow(dead_code)]
pub fn le_os_type_name(os_type: u16) -> String {
    match os_type {
        1 => "OS/2".into(),
        2 => "Windows".into(),
        3 => "DOS 4.x".into(),
        4 => "Windows 386".into(),
        _ => format!("Unknown (0x{:04x})", os_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic DEX with one of each id-table entry.
    ///
    /// Layout: header(0x70) | string_ids(8) | type_ids(4) | proto_ids(12) |
    /// field_ids(8) | method_ids(8) | class_defs(32) | map_list | data.
    fn build_test_dex() -> Vec<u8> {
        let mut d = vec![0u8; 0x70];
        d[0..4].copy_from_slice(b"dex\n");
        d[4..7].copy_from_slice(b"035");
        let w32 =
            |d: &mut Vec<u8>, off: usize, v: u32| d[off..off + 4].copy_from_slice(&v.to_le_bytes());
        let w16 =
            |d: &mut Vec<u8>, off: usize, v: u16| d[off..off + 2].copy_from_slice(&v.to_le_bytes());

        // Section offsets.
        let string_ids = d.len();
        d.extend_from_slice(&[0u8; 8]); // 2 string_id items
        let type_ids = d.len();
        d.extend_from_slice(&[0u8; 4]); // 1 type_id item
        let proto_ids = d.len();
        d.extend_from_slice(&[0u8; 12]); // 1 proto_id item
        let field_ids = d.len();
        d.extend_from_slice(&[0u8; 8]); // 1 field_id item
        let method_ids = d.len();
        d.extend_from_slice(&[0u8; 8]); // 1 method_id item
        let class_defs = d.len();
        d.extend_from_slice(&[0u8; 32]); // 1 class_def item
        let map_off = d.len();
        d.extend_from_slice(&[0u8; 4 + 12]); // map_list: size + 1 item
        let str0 = d.len();
        d.extend_from_slice(b"\x03Lx;\0"); // utf16_len=3? -> bytes "Lx;"
        let str1 = d.len();
        d.extend_from_slice(b"\x04name\0");
        let file_size = d.len() as u32;

        // string_ids -> string_data offsets.
        w32(&mut d, string_ids, str0 as u32);
        w32(&mut d, string_ids + 4, str1 as u32);
        // type_id: descriptor_idx = 0.
        w32(&mut d, type_ids, 0);
        // proto_id: shorty_idx=1, return_type_idx=0, parameters_off=0.
        w32(&mut d, proto_ids, 1);
        w32(&mut d, proto_ids + 4, 0);
        w32(&mut d, proto_ids + 8, 0);
        // field_id: class=0, type=0, name=1.
        w16(&mut d, field_ids, 0);
        w16(&mut d, field_ids + 2, 0);
        w32(&mut d, field_ids + 4, 1);
        // method_id: class=0, proto=0, name=1.
        w16(&mut d, method_ids, 0);
        w16(&mut d, method_ids + 2, 0);
        w32(&mut d, method_ids + 4, 1);
        // class_def: class=0, flags=1, super=NO_INDEX, source=1.
        w32(&mut d, class_defs, 0);
        w32(&mut d, class_defs + 4, 1);
        w32(&mut d, class_defs + 8, 0xFFFF_FFFF);
        w32(&mut d, class_defs + 16, 1);
        // map_list: 1 item of type string_id_item.
        w32(&mut d, map_off, 1);
        w16(&mut d, map_off + 4, 0x0001);
        w32(&mut d, map_off + 8, 2);
        w32(&mut d, map_off + 12, string_ids as u32);

        // Header fields.
        w32(&mut d, 0x20, file_size);
        w32(&mut d, 0x24, 0x70);
        w32(&mut d, 0x28, 0x12345678);
        w32(&mut d, 0x34, map_off as u32);
        w32(&mut d, 0x38, 2);
        w32(&mut d, 0x3c, string_ids as u32);
        w32(&mut d, 0x40, 1);
        w32(&mut d, 0x44, type_ids as u32);
        w32(&mut d, 0x48, 1);
        w32(&mut d, 0x4c, proto_ids as u32);
        w32(&mut d, 0x50, 1);
        w32(&mut d, 0x54, field_ids as u32);
        w32(&mut d, 0x58, 1);
        w32(&mut d, 0x5c, method_ids as u32);
        w32(&mut d, 0x60, 1);
        w32(&mut d, 0x64, class_defs as u32);
        w32(&mut d, 0x68, (str0) as u32);
        w32(&mut d, 0x6c, str0 as u32);
        d
    }

    #[test]
    fn test_parse_dex_deep_view() {
        let d = build_test_dex();
        let v = parse_dex_deep_view(&d).unwrap();
        assert_eq!(v.strings, vec!["Lx;".to_string(), "name".to_string()]);
        assert_eq!(v.types, vec!["Lx;".to_string()]);
        assert_eq!(v.protos.len(), 1);
        assert_eq!(v.protos[0].return_type, "Lx;");
        assert_eq!(v.fields[0].name, "name");
        assert_eq!(v.methods[0].name, "name");
        assert_eq!(v.methods[0].proto, "()Lx;");
        assert_eq!(v.class_defs[0].class, "Lx;");
        assert_eq!(v.class_defs[0].superclass, "-");
        assert_eq!(v.class_defs[0].source_file, "name");
        assert_eq!(v.map_items.len(), 1);
        assert_eq!(v.map_items[0].type_name, "string_id_item");
        assert!(!v.truncated);
    }

    #[test]
    fn test_parse_dex_deep_view_truncated() {
        let mut d = build_test_dex();
        // Claim more string_ids than exist: count beyond file must clamp.
        d[0x38..0x3c].copy_from_slice(&100u32.to_le_bytes());
        let v = parse_dex_deep_view(&d).unwrap();
        assert!(v.truncated);
        // Clamped to what physically fits in the file, still bounded.
        assert!(v.strings.len() < 100);
        assert_eq!(v.strings[0], "Lx;");
    }

    #[test]
    fn test_parse_dex_view_not_dex() {
        let data = vec![0u8; 0x70];
        assert!(parse_dex_view(&data).is_none());
    }

    #[test]
    fn test_parse_dex_view_too_short() {
        let data = b"dex\n035";
        assert!(parse_dex_view(data).is_none());
    }

    #[test]
    fn test_parse_msdos_view_not_mz() {
        let data = vec![0u8; 64];
        assert!(parse_msdos_view(&data).is_none());
    }

    #[test]
    fn test_parse_msdos_view_basic() {
        let mut data = vec![0u8; 64];
        data[0] = b'M';
        data[1] = b'Z';
        let view = parse_msdos_view(&data).unwrap();
        assert_eq!(view.magic, "MZ");
        assert!(!view.has_pe);
    }

    #[test]
    fn test_parse_ne_view_not_ne() {
        let mut data = vec![0u8; 128];
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 0x40;
        data[64] = b'P';
        data[65] = b'E';
        assert!(parse_ne_view(&data).is_none());
    }

    #[test]
    fn test_parse_le_view_not_le() {
        let mut data = vec![0u8; 128];
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 0x40;
        data[64] = b'N';
        data[65] = b'E';
        assert!(parse_le_view(&data).is_none());
    }

    #[test]
    fn test_ne_target_os_name() {
        assert_eq!(ne_target_os_name(1), "DOS");
        assert_eq!(ne_target_os_name(2), "Windows");
        assert_eq!(ne_target_os_name(3), "OS/2");
    }

    #[test]
    fn test_le_cpu_type_name() {
        assert_eq!(le_cpu_type_name(1), "80286");
        assert_eq!(le_cpu_type_name(2), "80386");
    }

    #[test]
    fn test_le_os_type_name() {
        assert_eq!(le_os_type_name(1), "OS/2");
        assert_eq!(le_os_type_name(2), "Windows");
    }
}

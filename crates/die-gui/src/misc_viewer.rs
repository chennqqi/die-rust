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

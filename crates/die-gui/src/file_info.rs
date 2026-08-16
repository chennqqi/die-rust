//! File information: size, hashes, entropy, PE/ELF/Mach-O sections, symbols,
//! and complete header field trees.
//!
//! Provides the backend for the file info panel and the entropy/hash views.
//! The header tree mirrors upstream `XFileInfo` + `XFileInfoModel` by
//! recursively structuring every parsed header field with name, value,
//! and optional comment (e.g. flag-bit decodings).

use serde::{Deserialize, Serialize};

/// File hash digests (MD5, SHA1, SHA256, CRC32).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashes {
    /// MD5 hex digest.
    pub md5: String,
    /// SHA-1 hex digest.
    pub sha1: String,
    /// SHA-256 hex digest.
    pub sha256: String,
    /// CRC32 hex digest.
    pub crc32: String,
}

/// Complete file information for the info panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// File path.
    pub path: String,
    /// File name (basename).
    pub file_name: String,
    /// File size in bytes.
    pub size: u64,
    /// File size formatted as human-readable string (e.g. "1.23 MB").
    pub size_human: String,
    /// Shannon entropy of the file content (0.0..=8.0).
    pub entropy: f64,
    /// Hash digests.
    pub hashes: FileHashes,
    /// Detected file format (PE32, ELF64, Mach-O, etc.) or "Unknown".
    pub format: String,
    /// PE/ELF/Mach-O sections (empty for non-binary files).
    pub sections: Vec<SectionInfo>,
    /// PE/ELF/Mach-O symbols (empty for non-binary or stripped files).
    pub symbols: Vec<SymbolInfo>,
    /// Structured header field tree (PE/ELF/Mach-O header fields).
    /// Empty for non-binary files or when header parsing fails.
    #[serde(default)]
    pub header_tree: Vec<HeaderField>,
    /// MIME type (e.g. "application/x-dosexec", "application/x-elf").
    #[serde(default)]
    pub mime_type: String,
    /// Image base address (PE ImageBase, ELF entry, Mach-O base). 0 if N/A.
    #[serde(default)]
    pub base_address: u64,
    /// Entry point address (PE AddressOfEntryPoint, ELF e_entry, Mach-O entry). 0 if N/A.
    #[serde(default)]
    pub entry_point: u64,
    /// Number of detected formats (sections count for binary files).
    #[serde(default)]
    pub format_count: u32,
}

/// A single field in a structured header tree.
///
/// Mirrors upstream `XFileInfoModel` items: each field has a name
/// (e.g. "e_magic"), a value (e.g. "0x5A4D"), an optional comment
/// (e.g. "MZ signature"), and optional nested children for grouped
/// structures (e.g. IMAGE_DOS_HEADER → e_lfanew, e_cblp, ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderField {
    /// Field name (e.g. "e_magic", "Machine", "Characteristics").
    pub name: String,
    /// Field value as hex string or raw value (e.g. "0x5A4D", "0x014C").
    pub value: String,
    /// Optional human-readable comment (e.g. "MZ signature",
    /// "IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Nested child fields (e.g. section header entries under
    /// "Section Headers", import entries under "Import Directory").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<HeaderField>,
}

impl HeaderField {
    /// Create a leaf field with no children.
    fn leaf(name: &str, value: impl std::fmt::Display) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
            comment: None,
            children: Vec::new(),
        }
    }

    /// Create a leaf field with a comment.
    fn leaf_c(name: &str, value: impl std::fmt::Display, comment: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
            comment: Some(comment.into()),
            children: Vec::new(),
        }
    }

    /// Create a group node with children.
    fn group(name: &str, children: Vec<HeaderField>) -> Self {
        Self {
            name: name.to_string(),
            value: String::new(),
            comment: None,
            children,
        }
    }

    /// Create a group node with a value and children.
    fn group_v(name: &str, value: impl std::fmt::Display, children: Vec<HeaderField>) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
            comment: None,
            children,
        }
    }
}

/// A single section/segment in a binary file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Section name (e.g. ".text", ".data").
    pub name: String,
    /// Virtual address (offset in memory).
    pub virtual_address: u64,
    /// Virtual size.
    pub virtual_size: u64,
    /// Raw offset in file.
    pub raw_offset: u64,
    /// Raw size in file.
    pub raw_size: u64,
    /// Section entropy (0.0..=8.0).
    pub entropy: f64,
}

/// A single symbol in a binary file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    /// Symbol name (possibly mangled).
    pub name: String,
    /// Symbol address.
    pub address: u64,
    /// Symbol size (0 if unknown).
    pub size: u64,
    /// Symbol kind (function, data, object, etc.).
    pub kind: String,
}

/// Compute Shannon entropy of a byte buffer.
///
/// Returns a value in [0.0, 8.0] where 8.0 means maximum randomness
/// (uniform distribution of all 256 byte values).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Format a byte count as a human-readable string.
fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

/// Compute MD5, SHA-1, SHA-256, and CRC32 hashes of a file.
fn compute_hashes(data: &[u8]) -> FileHashes {
    use md5::Digest as _;
    let md5 = compute_md5(data);
    let sha1 = hex::encode(sha1::Sha1::digest(data));
    let sha256 = hex::encode(sha2::Sha256::digest(data));
    let crc32 = format!("{:08X}", crc32fast::hash(data));
    FileHashes {
        md5,
        sha1,
        sha256,
        crc32,
    }
}

/// Compute the MD5 hex digest of a byte slice.
///
/// Used by VirusTotal integration to match upstream behavior
/// (`xvirustotalwidget.cpp:56` uses MD5, not SHA-256).
pub fn compute_md5(data: &[u8]) -> String {
    use md5::Digest as _;
    hex::encode(md5::Md5::digest(data))
}

/// Compute the SHA-256 hex digest of a byte slice.
pub fn compute_sha256(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

/// Detect the binary format from magic bytes.
///
/// First tries diec-formats probe table (20+ format probes) for Strong
/// matches. If only Weak matches are found, falls back to hand-written
/// magic byte checks for PE/ELF/Mach-O sub-typing (32 vs 64 bit).
fn detect_format(data: &[u8]) -> String {
    if data.len() < 4 {
        return "Unknown".to_string();
    }

    // --- Phase 1: diec-formats probe table ---
    // Provides 20+ format detection (PE, ELF, Mach-O, ZIP, RAR, 7Z, GZIP,
    // TAR, ISO9660, CAB, DEX, JavaClass, PYC, PDF, CFBF, JPEG, PNG, BMP, WAV).
    let table = diec_formats::ProbeTable::default_phase2();
    let source = diec_core::input::MemorySource::new(data);
    let range = diec_core::input::ByteRange::new(0, data.len() as u64).unwrap_or(
        diec_core::input::ByteRange {
            start: 0,
            length: 0,
        },
    );
    if let Some(view) = diec_core::input::ByteView::new(&source, range) {
        let (candidates, _errors) = table.probe_all(&view);
        // Prefer Strong matches from diec-formats.
        if let Some(strong) = candidates
            .iter()
            .find(|c| c.strength == diec_core::format::FormatStrength::Strong)
        {
            // diec-formats returns "PE32"/"PE64" — normalize to GUI's
            // "PE32"/"PE32+" naming convention.
            return match strong.file_type.name.as_str() {
                "PE64" => "PE32+".to_string(),
                other => other.to_string(),
            };
        }
    }

    // --- Phase 2: hand-written magic bytes (sub-typing for PE/ELF/Mach-O) ---
    // PE: MZ header at start, PE signature at e_lfanew offset.
    if data.starts_with(b"MZ") {
        if data.len() >= 0x40 {
            let pe_offset =
                u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
            if pe_offset + 4 <= data.len() && &data[pe_offset..pe_offset + 4] == b"PE\0\0" {
                // Check machine type for 32 vs 64 bit.
                if pe_offset + 6 <= data.len() {
                    let machine = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);
                    return match machine {
                        0x14c => "PE32".to_string(),
                        0x8664 => "PE32+".to_string(),
                        _ => "PE".to_string(),
                    };
                }
                return "PE".to_string();
            }
        }
        return "DOS MZ".to_string();
    }
    // ELF: 0x7f 'E' 'L' 'F'
    if data.starts_with(b"\x7fELF") {
        return match data.get(4) {
            Some(1) => "ELF32".to_string(),
            Some(2) => "ELF64".to_string(),
            _ => "ELF".to_string(),
        };
    }
    // Mach-O FAT (Universal Binary): 0xCAFEBABE (big-endian) or
    // 0xBEBAFECA (little-endian). Contains multiple architecture slices.
    let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic_be == 0xCAFEBABE || magic_be == 0xBEBAFECA {
        return "Mach-O FAT".to_string();
    }

    // Mach-O: 0xFEEDFACE/0xFEEDFACF (32/64-bit big-endian)
    //         0xCEFAEDFE/0xCFFAEDFE (32/64-bit little-endian)
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    match magic {
        0xFEEDFACE => "Mach-O 32".to_string(),
        0xFEEDFACF => "Mach-O 64".to_string(),
        _ => {
            let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            match magic_le {
                0xFEEDFACE => "Mach-O 32".to_string(),
                0xFEEDFACF => "Mach-O 64".to_string(),
                _ => "Unknown".to_string(),
            }
        }
    }
}

/// Parse PE sections, imports, and exports using goblin.
fn parse_pe_sections(data: &[u8]) -> (Vec<SectionInfo>, Vec<SymbolInfo>) {
    let mut sections = Vec::new();
    let mut symbols = Vec::new();

    if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(data) {
        for sec in &pe.sections {
            let name = String::from_utf8_lossy(
                &sec.name[..sec.name.iter().position(|&b| b == 0).unwrap_or(8)],
            )
            .to_string();
            let raw_start = sec.pointer_to_raw_data as usize;
            let raw_end = raw_start
                .saturating_add(sec.size_of_raw_data as usize)
                .min(data.len());
            let sec_data = &data[raw_start..raw_end];
            sections.push(SectionInfo {
                name,
                virtual_address: sec.virtual_address as u64,
                virtual_size: sec.virtual_size as u64,
                raw_offset: sec.pointer_to_raw_data as u64,
                raw_size: sec.size_of_raw_data as u64,
                entropy: shannon_entropy(sec_data),
            });
        }
        // Exports
        for export in &pe.exports {
            if let Some(ref name) = export.name {
                symbols.push(SymbolInfo {
                    name: name.to_string(),
                    address: export.rva as u64,
                    size: export.size as u64,
                    kind: "export".to_string(),
                });
            }
        }
        // Imports — goblin provides PE imports as (DLL name, import name, RVA)
        for import in &pe.imports {
            symbols.push(SymbolInfo {
                name: format!("{}.{}", import.dll, import.name),
                address: import.offset as u64,
                size: 0,
                kind: "import".to_string(),
            });
        }
    }

    (sections, symbols)
}

/// Parse ELF sections and symbols using goblin.
fn parse_elf_sections(data: &[u8]) -> (Vec<SectionInfo>, Vec<SymbolInfo>) {
    let mut sections = Vec::new();
    let mut symbols = Vec::new();

    if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(data) {
        for sec in &elf.section_headers {
            let name = elf
                .shdr_strtab
                .get_at(sec.sh_name)
                .unwrap_or("?")
                .to_string();
            let sec_data = &data[sec.sh_offset as usize..(sec.sh_offset + sec.sh_size) as usize];
            sections.push(SectionInfo {
                name,
                virtual_address: sec.sh_addr,
                virtual_size: sec.sh_size,
                raw_offset: sec.sh_offset,
                raw_size: sec.sh_size,
                entropy: shannon_entropy(sec_data),
            });
        }
        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                symbols.push(SymbolInfo {
                    name: name.to_string(),
                    address: sym.st_value,
                    size: sym.st_size,
                    kind: match sym.st_type() {
                        2 => "function".to_string(),
                        1 => "data".to_string(),
                        0 => "notype".to_string(),
                        _ => "other".to_string(),
                    },
                });
            }
        }
    }

    (sections, symbols)
}

/// Parse Mach-O sections and symbols using goblin.
fn parse_macho_sections(data: &[u8]) -> (Vec<SectionInfo>, Vec<SymbolInfo>) {
    let mut sections = Vec::new();
    let mut symbols = Vec::new();

    // goblin::Object::Mach is an enum (Mach::Binary for single-arch).
    if let Ok(goblin::Object::Mach(mach)) = goblin::Object::parse(data)
        && let goblin::mach::Mach::Binary(macho) = mach
    {
        for seg in macho.segments.iter() {
            if let Ok(sec_iter) = seg.sections() {
                for (sec, sec_data) in sec_iter {
                    let name = sec.name().unwrap_or_default();
                    sections.push(SectionInfo {
                        name: name.to_string(),
                        virtual_address: sec.addr,
                        virtual_size: sec.size,
                        raw_offset: sec.offset as u64,
                        raw_size: sec.size,
                        entropy: shannon_entropy(sec_data),
                    });
                }
            }
        }
        for (name, nlist) in macho.symbols().flatten() {
            if nlist.is_stab() {
                continue;
            }
            symbols.push(SymbolInfo {
                name: name.to_string(),
                address: nlist.n_value,
                size: 0,
                kind: if nlist.get_type() == 0x0f {
                    "function".to_string()
                } else {
                    "symbol".to_string()
                },
            });
        }
    }

    (sections, symbols)
}

// ---------------------------------------------------------------------------
// Header tree parsing — PE / ELF / Mach-O
// ---------------------------------------------------------------------------

/// PE section characteristics flag names.
const PE_SECTION_FLAGS: &[(u32, &str)] = &[
    (0x00000020, "IMAGE_SCN_CNT_CODE"),
    (0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA"),
    (0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_DATA"),
    (0x00001000, "IMAGE_SCN_LNK_COMDAT"),
    (0x00004000, "IMAGE_SCN_NO_DEFER_SPEC_EXC"),
    (0x00008000, "IMAGE_SCN_GPREL"),
    (0x02000000, "IMAGE_SCN_MEM_DISCARDABLE"),
    (0x04000000, "IMAGE_SCN_MEM_NOT_CACHED"),
    (0x08000000, "IMAGE_SCN_MEM_NOT_PAGED"),
    (0x10000000, "IMAGE_SCN_MEM_SHARED"),
    (0x20000000, "IMAGE_SCN_MEM_EXECUTE"),
    (0x40000000, "IMAGE_SCN_MEM_READ"),
    (0x80000000, "IMAGE_SCN_MEM_WRITE"),
];

/// PE file characteristics flag names.
const PE_FILE_CHARS: &[(u16, &str)] = &[
    (0x0001, "IMAGE_FILE_RELOCS_STRIPPED"),
    (0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE"),
    (0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED"),
    (0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"),
    (0x0010, "IMAGE_FILE_AGGRESSIVE_WS_TRIM"),
    (0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE"),
    (0x0080, "IMAGE_FILE_BYTES_REVERSED_LO"),
    (0x0100, "IMAGE_FILE_32BIT_MACHINE"),
    (0x0200, "IMAGE_FILE_DEBUG_STRIPPED"),
    (0x0400, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP"),
    (0x1000, "IMAGE_FILE_SYSTEM"),
    (0x2000, "IMAGE_FILE_DLL"),
    (0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY"),
    (0x8000, "IMAGE_FILE_BYTES_REVERSED_HI"),
];

/// PE machine type names.
fn pe_machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "IMAGE_FILE_MACHINE_I386",
        0x0162 => "IMAGE_FILE_MACHINE_R3000",
        0x0166 => "IMAGE_FILE_MACHINE_R4000",
        0x0168 => "IMAGE_FILE_MACHINE_R10000",
        0x0169 => "IMAGE_FILE_MACHINE_WCEMIPSV2",
        0x0184 => "IMAGE_FILE_MACHINE_ALPHA",
        0x01a2 => "IMAGE_FILE_MACHINE_SH3",
        0x01a3 => "IMAGE_FILE_MACHINE_SH3DSP",
        0x01a6 => "IMAGE_FILE_MACHINE_SH4",
        0x01a8 => "IMAGE_FILE_MACHINE_SH5",
        0x01c0 => "IMAGE_FILE_MACHINE_ARM",
        0x01c2 => "IMAGE_FILE_MACHINE_THUMB",
        0x01c4 => "IMAGE_FILE_MACHINE_ARMNT",
        0x01d3 => "IMAGE_FILE_MACHINE_AM33",
        0x01f0 => "IMAGE_FILE_MACHINE_POWERPC",
        0x01f1 => "IMAGE_FILE_MACHINE_POWERPCFP",
        0x0200 => "IMAGE_FILE_MACHINE_IA64",
        0x0266 => "IMAGE_FILE_MACHINE_MIPS16",
        0x0284 => "IMAGE_FILE_MACHINE_ALPHA64",
        0x0366 => "IMAGE_FILE_MACHINE_MIPSFPU",
        0x0466 => "IMAGE_FILE_MACHINE_MIPSFPU16",
        0x0ebc => "IMAGE_FILE_MACHINE_EBC",
        0x8664 => "IMAGE_FILE_MACHINE_AMD64",
        0x9041 => "IMAGE_FILE_MACHINE_M32R",
        0xaa64 => "IMAGE_FILE_MACHINE_ARM64",
        _ => "UNKNOWN",
    }
}

/// Decode PE section characteristics flags into a readable string.
fn decode_pe_section_flags(chars: u32) -> String {
    let parts: Vec<&str> = PE_SECTION_FLAGS
        .iter()
        .filter(|(bit, _)| chars & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if parts.is_empty() {
        format!("0x{:08X}", chars)
    } else {
        parts.join(" | ")
    }
}

/// Decode PE file characteristics flags into a readable string.
fn decode_pe_file_chars(chars: u16) -> String {
    let parts: Vec<&str> = PE_FILE_CHARS
        .iter()
        .filter(|(bit, _)| chars & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if parts.is_empty() {
        format!("0x{:04X}", chars)
    } else {
        parts.join(" | ")
    }
}

/// Parse PE header tree using pelite (PE32 and PE32+).
///
/// Returns a vector of top-level groups: DOS Header, NT Headers,
/// Optional Header, Section Headers, Entry Point.
fn parse_pe_header_tree(data: &[u8]) -> Vec<HeaderField> {
    // Try PE64 first, then PE32.
    if let Some(file) = safe_pe64_from_bytes(data) {
        return build_pe64_header_tree(&file, data);
    }
    if let Some(file) = safe_pe32_from_bytes(data) {
        return build_pe32_header_tree(&file, data);
    }
    // Fallback: manual DOS header parse (always possible for MZ files).
    build_dos_header_only(data)
}

/// Safely parse a PE64 file, catching panics from pelite.
fn safe_pe64_from_bytes(data: &[u8]) -> Option<pelite::pe64::PeFile<'_>> {
    if !is_pe_aligned(data, 8) {
        return None;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pelite::pe64::PeFile::from_bytes(data)
    }))
    .ok()
    .and_then(|r| r.ok())
}

/// Safely parse a PE32 file, catching panics from pelite.
fn safe_pe32_from_bytes(data: &[u8]) -> Option<pelite::pe32::PeFile<'_>> {
    if !is_pe_aligned(data, 4) {
        return None;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pelite::pe32::PeFile::from_bytes(data)
    }))
    .ok()
    .and_then(|r| r.ok())
}

/// Check PE alignment safety (mirrors pe_native.rs logic).
fn is_pe_aligned(data: &[u8], align: usize) -> bool {
    if data.len() < 64 {
        return false;
    }
    if data[0] != 0x4D || data[1] != 0x5A {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
    if !(e_lfanew as usize).is_multiple_of(align) {
        return false;
    }
    if e_lfanew as usize + 24 > data.len() {
        return false;
    }
    &data[e_lfanew as usize..e_lfanew as usize + 4] == b"PE\0\0"
}

/// Build the DOS header fields from raw bytes (always available for MZ files).
fn build_dos_header(data: &[u8]) -> Vec<HeaderField> {
    if data.len() < 64 {
        return Vec::new();
    }
    let read_u16 = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);
    vec![
        HeaderField::leaf_c("e_magic", format!("0x{:04X}", read_u16(0)), "MZ signature"),
        HeaderField::leaf("e_cblp", format!("0x{:04X}", read_u16(2))),
        HeaderField::leaf("e_cp", format!("0x{:04X}", read_u16(4))),
        HeaderField::leaf("e_crlc", format!("0x{:04X}", read_u16(6))),
        HeaderField::leaf("e_cparhdr", format!("0x{:04X}", read_u16(8))),
        HeaderField::leaf("e_minalloc", format!("0x{:04X}", read_u16(10))),
        HeaderField::leaf("e_maxalloc", format!("0x{:04X}", read_u16(12))),
        HeaderField::leaf("e_ss", format!("0x{:04X}", read_u16(14))),
        HeaderField::leaf("e_sp", format!("0x{:04X}", read_u16(16))),
        HeaderField::leaf("e_csum", format!("0x{:04X}", read_u16(18))),
        HeaderField::leaf("e_ip", format!("0x{:04X}", read_u16(20))),
        HeaderField::leaf("e_cs", format!("0x{:04X}", read_u16(22))),
        HeaderField::leaf("e_lfarlc", format!("0x{:04X}", read_u16(24))),
        HeaderField::leaf("e_ovno", format!("0x{:04X}", read_u16(26))),
        HeaderField::leaf_c(
            "e_lfanew",
            format!(
                "0x{:08X}",
                u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]])
            ),
            "PE header offset",
        ),
    ]
}

/// Build header tree for DOS-only files (no PE signature).
fn build_dos_header_only(data: &[u8]) -> Vec<HeaderField> {
    vec![HeaderField::group(
        "IMAGE_DOS_HEADER",
        build_dos_header(data),
    )]
}

/// Build PE64 header tree using pelite.
fn build_pe64_header_tree(file: &pelite::pe64::PeFile<'_>, data: &[u8]) -> Vec<HeaderField> {
    use pelite::pe64::Pe as _;

    let mut tree = Vec::new();

    // DOS Header
    tree.push(HeaderField::group(
        "IMAGE_DOS_HEADER",
        build_dos_header(data),
    ));

    // NT Headers
    let nt_headers = file.file_header();
    let opt_header = file.optional_header();
    let machine = nt_headers.Machine;
    let num_sections = nt_headers.NumberOfSections;
    let chars = nt_header_characteristics(nt_headers);

    let nt_children = vec![
        HeaderField::leaf_c("Signature", "0x00004550", "PE\\0\\0"),
        HeaderField::leaf_c(
            "Machine",
            format!("0x{:04X}", machine),
            pe_machine_name(machine),
        ),
        HeaderField::leaf("NumberOfSections", num_sections),
        HeaderField::leaf(
            "TimeDateStamp",
            format!("0x{:08X}", nt_headers.TimeDateStamp),
        ),
        HeaderField::leaf(
            "PointerToSymbolTable",
            format!("0x{:08X}", nt_headers.PointerToSymbolTable),
        ),
        HeaderField::leaf("NumberOfSymbols", nt_headers.NumberOfSymbols),
        HeaderField::leaf(
            "SizeOfOptionalHeader",
            format!("0x{:04X}", nt_headers.SizeOfOptionalHeader),
        ),
        HeaderField::leaf_c(
            "Characteristics",
            format!("0x{:04X}", chars),
            decode_pe_file_chars(chars),
        ),
    ];
    tree.push(HeaderField::group("IMAGE_FILE_HEADER", nt_children));

    // Optional Header (PE32+)
    let opt_children = vec![
        HeaderField::leaf_c(
            "Magic",
            format!("0x{:04X}", opt_header.Magic),
            "PE32+ (64-bit)",
        ),
        HeaderField::leaf("MajorLinkerVersion", opt_header.LinkerVersion.Major),
        HeaderField::leaf("MinorLinkerVersion", opt_header.LinkerVersion.Minor),
        HeaderField::leaf("SizeOfCode", format!("0x{:08X}", opt_header.SizeOfCode)),
        HeaderField::leaf(
            "SizeOfInitializedData",
            format!("0x{:08X}", opt_header.SizeOfInitializedData),
        ),
        HeaderField::leaf(
            "SizeOfUninitializedData",
            format!("0x{:08X}", opt_header.SizeOfUninitializedData),
        ),
        HeaderField::leaf(
            "AddressOfEntryPoint",
            format!("0x{:08X}", opt_header.AddressOfEntryPoint),
        ),
        HeaderField::leaf("BaseOfCode", format!("0x{:08X}", opt_header.BaseOfCode)),
        HeaderField::leaf("ImageBase", format!("0x{:016X}", opt_header.ImageBase)),
        HeaderField::leaf(
            "SectionAlignment",
            format!("0x{:08X}", opt_header.SectionAlignment),
        ),
        HeaderField::leaf(
            "FileAlignment",
            format!("0x{:08X}", opt_header.FileAlignment),
        ),
        HeaderField::leaf(
            "MajorOperatingSystemVersion",
            opt_header.OperatingSystemVersion.Major,
        ),
        HeaderField::leaf(
            "MinorOperatingSystemVersion",
            opt_header.OperatingSystemVersion.Minor,
        ),
        HeaderField::leaf("MajorImageVersion", opt_header.ImageVersion.Major),
        HeaderField::leaf("MinorImageVersion", opt_header.ImageVersion.Minor),
        HeaderField::leaf("MajorSubsystemVersion", opt_header.SubsystemVersion.Major),
        HeaderField::leaf("MinorSubsystemVersion", opt_header.SubsystemVersion.Minor),
        HeaderField::leaf(
            "Win32VersionValue",
            format!("0x{:08X}", opt_header.Win32VersionValue),
        ),
        HeaderField::leaf("SizeOfImage", format!("0x{:08X}", opt_header.SizeOfImage)),
        HeaderField::leaf(
            "SizeOfHeaders",
            format!("0x{:08X}", opt_header.SizeOfHeaders),
        ),
        HeaderField::leaf("CheckSum", format!("0x{:08X}", opt_header.CheckSum)),
        HeaderField::leaf_c(
            "Subsystem",
            format!("0x{:04X}", opt_header.Subsystem),
            pe_subsystem_name(opt_header.Subsystem),
        ),
        HeaderField::leaf(
            "DllCharacteristics",
            format!("0x{:04X}", opt_header.DllCharacteristics),
        ),
        HeaderField::leaf(
            "SizeOfStackReserve",
            format!("0x{:016X}", opt_header.SizeOfStackReserve),
        ),
        HeaderField::leaf(
            "SizeOfStackCommit",
            format!("0x{:016X}", opt_header.SizeOfStackCommit),
        ),
        HeaderField::leaf(
            "SizeOfHeapReserve",
            format!("0x{:016X}", opt_header.SizeOfHeapReserve),
        ),
        HeaderField::leaf(
            "SizeOfHeapCommit",
            format!("0x{:016X}", opt_header.SizeOfHeapCommit),
        ),
        HeaderField::leaf("LoaderFlags", format!("0x{:08X}", opt_header.LoaderFlags)),
        HeaderField::leaf(
            "NumberOfRvaAndSizes",
            format!("0x{:08X}", opt_header.NumberOfRvaAndSizes),
        ),
    ];
    tree.push(HeaderField::group(
        "IMAGE_OPTIONAL_HEADER (PE32+)",
        opt_children,
    ));

    // Section Headers
    let mut sec_children = Vec::new();
    for sec in file.section_headers().iter() {
        let name = String::from_utf8_lossy(sec.name_bytes())
            .trim_end_matches('\0')
            .to_string();
        let sec_chars = sec.Characteristics;
        sec_children.push(HeaderField::group_v(
            &name,
            format!("@0x{:08X}", sec.VirtualAddress),
            vec![
                HeaderField::leaf("VirtualSize", format!("0x{:08X}", sec.VirtualSize)),
                HeaderField::leaf("VirtualAddress", format!("0x{:08X}", sec.VirtualAddress)),
                HeaderField::leaf("SizeOfRawData", format!("0x{:08X}", sec.SizeOfRawData)),
                HeaderField::leaf(
                    "PointerToRawData",
                    format!("0x{:08X}", sec.PointerToRawData),
                ),
                HeaderField::leaf(
                    "PointerToRelocations",
                    format!("0x{:08X}", sec.PointerToRelocations),
                ),
                HeaderField::leaf(
                    "PointerToLinenumbers",
                    format!("0x{:08X}", sec.PointerToLinenumbers),
                ),
                HeaderField::leaf("NumberOfRelocations", sec.NumberOfRelocations),
                HeaderField::leaf("NumberOfLinenumbers", sec.NumberOfLinenumbers),
                HeaderField::leaf_c(
                    "Characteristics",
                    format!("0x{:08X}", sec_chars),
                    decode_pe_section_flags(sec_chars),
                ),
            ],
        ));
    }
    tree.push(HeaderField::group("Section Headers", sec_children));

    // Entry Point
    let entry = opt_header.AddressOfEntryPoint;
    let image_base = opt_header.ImageBase;
    tree.push(HeaderField::leaf_c(
        "Entry Point",
        format!(
            "RVA=0x{:08X}, VA=0x{:016X}",
            entry,
            image_base + entry as u64
        ),
        "Program entry point",
    ));

    tree
}

/// Build PE32 header tree using pelite.
fn build_pe32_header_tree(file: &pelite::pe32::PeFile<'_>, data: &[u8]) -> Vec<HeaderField> {
    use pelite::pe32::Pe as _;

    let mut tree = Vec::new();

    // DOS Header
    tree.push(HeaderField::group(
        "IMAGE_DOS_HEADER",
        build_dos_header(data),
    ));

    // NT Headers
    let nt_headers = file.file_header();
    let opt_header = file.optional_header();
    let machine = nt_headers.Machine;
    let num_sections = nt_headers.NumberOfSections;
    let chars = nt_header_characteristics(nt_headers);

    let nt_children = vec![
        HeaderField::leaf_c("Signature", "0x00004550", "PE\\0\\0"),
        HeaderField::leaf_c(
            "Machine",
            format!("0x{:04X}", machine),
            pe_machine_name(machine),
        ),
        HeaderField::leaf("NumberOfSections", num_sections),
        HeaderField::leaf(
            "TimeDateStamp",
            format!("0x{:08X}", nt_headers.TimeDateStamp),
        ),
        HeaderField::leaf(
            "PointerToSymbolTable",
            format!("0x{:08X}", nt_headers.PointerToSymbolTable),
        ),
        HeaderField::leaf("NumberOfSymbols", nt_headers.NumberOfSymbols),
        HeaderField::leaf(
            "SizeOfOptionalHeader",
            format!("0x{:04X}", nt_headers.SizeOfOptionalHeader),
        ),
        HeaderField::leaf_c(
            "Characteristics",
            format!("0x{:04X}", chars),
            decode_pe_file_chars(chars),
        ),
    ];
    tree.push(HeaderField::group("IMAGE_FILE_HEADER", nt_children));

    // Optional Header (PE32)
    let opt_children = vec![
        HeaderField::leaf_c(
            "Magic",
            format!("0x{:04X}", opt_header.Magic),
            "PE32 (32-bit)",
        ),
        HeaderField::leaf("MajorLinkerVersion", opt_header.LinkerVersion.Major),
        HeaderField::leaf("MinorLinkerVersion", opt_header.LinkerVersion.Minor),
        HeaderField::leaf("SizeOfCode", format!("0x{:08X}", opt_header.SizeOfCode)),
        HeaderField::leaf(
            "SizeOfInitializedData",
            format!("0x{:08X}", opt_header.SizeOfInitializedData),
        ),
        HeaderField::leaf(
            "SizeOfUninitializedData",
            format!("0x{:08X}", opt_header.SizeOfUninitializedData),
        ),
        HeaderField::leaf(
            "AddressOfEntryPoint",
            format!("0x{:08X}", opt_header.AddressOfEntryPoint),
        ),
        HeaderField::leaf("BaseOfCode", format!("0x{:08X}", opt_header.BaseOfCode)),
        HeaderField::leaf("BaseOfData", format!("0x{:08X}", opt_header.BaseOfData)),
        HeaderField::leaf("ImageBase", format!("0x{:08X}", opt_header.ImageBase)),
        HeaderField::leaf(
            "SectionAlignment",
            format!("0x{:08X}", opt_header.SectionAlignment),
        ),
        HeaderField::leaf(
            "FileAlignment",
            format!("0x{:08X}", opt_header.FileAlignment),
        ),
        HeaderField::leaf(
            "MajorOperatingSystemVersion",
            opt_header.OperatingSystemVersion.Major,
        ),
        HeaderField::leaf(
            "MinorOperatingSystemVersion",
            opt_header.OperatingSystemVersion.Minor,
        ),
        HeaderField::leaf("MajorImageVersion", opt_header.ImageVersion.Major),
        HeaderField::leaf("MinorImageVersion", opt_header.ImageVersion.Minor),
        HeaderField::leaf("MajorSubsystemVersion", opt_header.SubsystemVersion.Major),
        HeaderField::leaf("MinorSubsystemVersion", opt_header.SubsystemVersion.Minor),
        HeaderField::leaf(
            "Win32VersionValue",
            format!("0x{:08X}", opt_header.Win32VersionValue),
        ),
        HeaderField::leaf("SizeOfImage", format!("0x{:08X}", opt_header.SizeOfImage)),
        HeaderField::leaf(
            "SizeOfHeaders",
            format!("0x{:08X}", opt_header.SizeOfHeaders),
        ),
        HeaderField::leaf("CheckSum", format!("0x{:08X}", opt_header.CheckSum)),
        HeaderField::leaf_c(
            "Subsystem",
            format!("0x{:04X}", opt_header.Subsystem),
            pe_subsystem_name(opt_header.Subsystem),
        ),
        HeaderField::leaf(
            "DllCharacteristics",
            format!("0x{:04X}", opt_header.DllCharacteristics),
        ),
        HeaderField::leaf(
            "SizeOfStackReserve",
            format!("0x{:08X}", opt_header.SizeOfStackReserve),
        ),
        HeaderField::leaf(
            "SizeOfStackCommit",
            format!("0x{:08X}", opt_header.SizeOfStackCommit),
        ),
        HeaderField::leaf(
            "SizeOfHeapReserve",
            format!("0x{:08X}", opt_header.SizeOfHeapReserve),
        ),
        HeaderField::leaf(
            "SizeOfHeapCommit",
            format!("0x{:08X}", opt_header.SizeOfHeapCommit),
        ),
        HeaderField::leaf("LoaderFlags", format!("0x{:08X}", opt_header.LoaderFlags)),
        HeaderField::leaf(
            "NumberOfRvaAndSizes",
            format!("0x{:08X}", opt_header.NumberOfRvaAndSizes),
        ),
    ];
    tree.push(HeaderField::group(
        "IMAGE_OPTIONAL_HEADER (PE32)",
        opt_children,
    ));

    // Section Headers
    let mut sec_children = Vec::new();
    for sec in file.section_headers().iter() {
        let name = String::from_utf8_lossy(sec.name_bytes())
            .trim_end_matches('\0')
            .to_string();
        let sec_chars = sec.Characteristics;
        sec_children.push(HeaderField::group_v(
            &name,
            format!("@0x{:08X}", sec.VirtualAddress),
            vec![
                HeaderField::leaf("VirtualSize", format!("0x{:08X}", sec.VirtualSize)),
                HeaderField::leaf("VirtualAddress", format!("0x{:08X}", sec.VirtualAddress)),
                HeaderField::leaf("SizeOfRawData", format!("0x{:08X}", sec.SizeOfRawData)),
                HeaderField::leaf(
                    "PointerToRawData",
                    format!("0x{:08X}", sec.PointerToRawData),
                ),
                HeaderField::leaf(
                    "PointerToRelocations",
                    format!("0x{:08X}", sec.PointerToRelocations),
                ),
                HeaderField::leaf(
                    "PointerToLinenumbers",
                    format!("0x{:08X}", sec.PointerToLinenumbers),
                ),
                HeaderField::leaf("NumberOfRelocations", sec.NumberOfRelocations),
                HeaderField::leaf("NumberOfLinenumbers", sec.NumberOfLinenumbers),
                HeaderField::leaf_c(
                    "Characteristics",
                    format!("0x{:08X}", sec_chars),
                    decode_pe_section_flags(sec_chars),
                ),
            ],
        ));
    }
    tree.push(HeaderField::group("Section Headers", sec_children));

    // Entry Point
    let entry = opt_header.AddressOfEntryPoint;
    let image_base = opt_header.ImageBase as u64;
    tree.push(HeaderField::leaf_c(
        "Entry Point",
        format!(
            "RVA=0x{:08X}, VA=0x{:08X}",
            entry,
            image_base + entry as u64
        ),
        "Program entry point",
    ));

    tree
}

/// Extract Characteristics from PE file header (works for both PE32 and PE32+).
fn nt_header_characteristics(file_header: &pelite::image::IMAGE_FILE_HEADER) -> u16 {
    file_header.Characteristics
}

/// PE subsystem names.
fn pe_subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        0 => "IMAGE_SUBSYSTEM_UNKNOWN",
        1 => "IMAGE_SUBSYSTEM_NATIVE",
        2 => "IMAGE_SUBSYSTEM_WINDOWS_GUI",
        3 => "IMAGE_SUBSYSTEM_WINDOWS_CUI",
        5 => "IMAGE_SUBSYSTEM_OS2_CUI",
        7 => "IMAGE_SUBSYSTEM_POSIX_CUI",
        8 => "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
        9 => "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
        10 => "IMAGE_SUBSYSTEM_EFI_APPLICATION",
        11 => "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
        12 => "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
        13 => "IMAGE_SUBSYSTEM_EFI_ROM",
        14 => "IMAGE_SUBSYSTEM_XBOX",
        16 => "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
        _ => "UNKNOWN",
    }
}

// --- ELF header parsing ---

/// ELF section header type names.
fn elf_sh_type(sh_type: u32) -> &'static str {
    match sh_type {
        0 => "SHT_NULL",
        1 => "SHT_PROGBITS",
        2 => "SHT_SYMTAB",
        3 => "SHT_STRTAB",
        4 => "SHT_RELA",
        5 => "SHT_HASH",
        6 => "SHT_DYNAMIC",
        7 => "SHT_NOTE",
        8 => "SHT_NOBITS",
        9 => "SHT_REL",
        10 => "SHT_SHLIB",
        11 => "SHT_DYNSYM",
        14 => "SHT_INIT_ARRAY",
        15 => "SHT_FINI_ARRAY",
        16 => "SHT_PREINIT_ARRAY",
        17 => "SHT_GROUP",
        18 => "SHT_SYMTAB_SHNDX",
        0x6ffffff5 => "SHT_GNU_ATTRIBUTES",
        0x6ffffff6 => "SHT_GNU_HASH",
        0x6ffffffd => "SHT_GNU_verdef",
        0x6ffffffe => "SHT_GNU_verneed",
        0x6fffffff => "SHT_GNU_versym",
        _ => "UNKNOWN",
    }
}

/// ELF machine type names.
fn elf_machine_name(machine: u16) -> &'static str {
    match machine {
        0 => "EM_NONE",
        2 => "EM_SPARC",
        3 => "EM_386",
        4 => "EM_68K",
        7 => "EM_860",
        8 => "EM_MIPS",
        20 => "EM_PPC",
        21 => "EM_PPC64",
        22 => "EM_S390",
        40 => "EM_ARM",
        42 => "EM_SH",
        43 => "EM_SPARCV9",
        50 => "EM_IA_64",
        62 => "EM_X86_64",
        183 => "EM_AARCH64",
        243 => "EM_RISCV",
        _ => "UNKNOWN",
    }
}

/// ELF type names.
fn elf_type_name(e_type: u16) -> &'static str {
    match e_type {
        0 => "ET_NONE",
        1 => "ET_REL",
        2 => "ET_EXEC",
        3 => "ET_DYN",
        4 => "ET_CORE",
        _ => "UNKNOWN",
    }
}

/// Parse ELF header tree using goblin.
fn parse_elf_header_tree(data: &[u8]) -> Vec<HeaderField> {
    let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(data) else {
        return Vec::new();
    };
    let header = &elf.header;
    let is64 = header.e_ident[EI_CLASS] == ELFCLASS64;

    let mut tree = Vec::new();

    // ELF Header (Ehdr)
    let ehdr_children = vec![
        HeaderField::leaf_c(
            "e_ident[EI_MAG]",
            format!(
                "0x{:02X} 0x{:02X} 0x{:02X} 0x{:02X}",
                header.e_ident[0], header.e_ident[1], header.e_ident[2], header.e_ident[3]
            ),
            "\\x7fELF",
        ),
        HeaderField::leaf_c(
            "e_ident[EI_CLASS]",
            format!("0x{:02X}", header.e_ident[EI_CLASS]),
            if is64 { "ELFCLASS64" } else { "ELFCLASS32" },
        ),
        HeaderField::leaf_c(
            "e_ident[EI_DATA]",
            format!("0x{:02X}", header.e_ident[EI_DATA]),
            if header.e_ident[EI_DATA] == 1 {
                "ELFDATA2LSB (little-endian)"
            } else {
                "ELFDATA2MSB (big-endian)"
            },
        ),
        HeaderField::leaf_c(
            "e_ident[EI_VERSION]",
            format!("0x{:02X}", header.e_ident[EI_VERSION]),
            "EV_CURRENT",
        ),
        HeaderField::leaf_c(
            "e_ident[EI_OSABI]",
            format!("0x{:02X}", header.e_ident[EI_OSABI]),
            elf_osabi_name(header.e_ident[EI_OSABI]),
        ),
        HeaderField::leaf(
            "e_ident[EI_ABIVERSION]",
            format!("0x{:02X}", header.e_ident[EI_ABIVERSION]),
        ),
        HeaderField::leaf_c(
            "e_type",
            format!("0x{:04X}", header.e_type),
            elf_type_name(header.e_type),
        ),
        HeaderField::leaf_c(
            "e_machine",
            format!("0x{:04X}", header.e_machine),
            elf_machine_name(header.e_machine),
        ),
        HeaderField::leaf_c(
            "e_version",
            format!("0x{:08X}", header.e_version),
            "EV_CURRENT",
        ),
        HeaderField::leaf("e_entry", format!("0x{:016X}", header.e_entry)),
        HeaderField::leaf("e_phoff", format!("0x{:016X}", header.e_phoff)),
        HeaderField::leaf("e_shoff", format!("0x{:016X}", header.e_shoff)),
        HeaderField::leaf("e_flags", format!("0x{:08X}", header.e_flags)),
        HeaderField::leaf("e_ehsize", header.e_ehsize),
        HeaderField::leaf("e_phentsize", header.e_phentsize),
        HeaderField::leaf("e_phnum", header.e_phnum),
        HeaderField::leaf("e_shentsize", header.e_shentsize),
        HeaderField::leaf("e_shnum", header.e_shnum),
        HeaderField::leaf("e_shstrndx", header.e_shstrndx),
    ];
    tree.push(HeaderField::group("ELF Header (Ehdr)", ehdr_children));

    // Program Headers (Phdr)
    let mut phdr_children = Vec::new();
    for (i, ph) in elf.program_headers.iter().enumerate() {
        phdr_children.push(HeaderField::group_v(
            &format!("Phdr[{}]", i),
            elf_ph_type(ph.p_type),
            vec![
                HeaderField::leaf_c(
                    "p_type",
                    format!("0x{:08X}", ph.p_type),
                    elf_ph_type(ph.p_type),
                ),
                HeaderField::leaf("p_flags", format!("0x{:08X}", ph.p_flags)),
                HeaderField::leaf("p_offset", format!("0x{:016X}", ph.p_offset)),
                HeaderField::leaf("p_vaddr", format!("0x{:016X}", ph.p_vaddr)),
                HeaderField::leaf("p_paddr", format!("0x{:016X}", ph.p_paddr)),
                HeaderField::leaf("p_filesz", format!("0x{:016X}", ph.p_filesz)),
                HeaderField::leaf("p_memsz", format!("0x{:016X}", ph.p_memsz)),
                HeaderField::leaf("p_align", format!("0x{:016X}", ph.p_align)),
            ],
        ));
    }
    if !phdr_children.is_empty() {
        tree.push(HeaderField::group("Program Headers (Phdr)", phdr_children));
    }

    // Section Headers (Shdr)
    let mut shdr_children = Vec::new();
    for (i, sh) in elf.section_headers.iter().enumerate() {
        let name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or("?")
            .to_string();
        shdr_children.push(HeaderField::group_v(
            &format!("[{}] {}", i, name),
            elf_sh_type(sh.sh_type),
            vec![
                HeaderField::leaf_c("sh_name", format!("0x{:08X}", sh.sh_name), &name),
                HeaderField::leaf_c(
                    "sh_type",
                    format!("0x{:08X}", sh.sh_type),
                    elf_sh_type(sh.sh_type),
                ),
                HeaderField::leaf("sh_flags", format!("0x{:016X}", sh.sh_flags)),
                HeaderField::leaf("sh_addr", format!("0x{:016X}", sh.sh_addr)),
                HeaderField::leaf("sh_offset", format!("0x{:016X}", sh.sh_offset)),
                HeaderField::leaf("sh_size", format!("0x{:016X}", sh.sh_size)),
                HeaderField::leaf("sh_link", sh.sh_link),
                HeaderField::leaf("sh_info", sh.sh_info),
                HeaderField::leaf("sh_addralign", format!("0x{:016X}", sh.sh_addralign)),
                HeaderField::leaf("sh_entsize", format!("0x{:016X}", sh.sh_entsize)),
            ],
        ));
    }
    if !shdr_children.is_empty() {
        tree.push(HeaderField::group("Section Headers (Shdr)", shdr_children));
    }

    tree
}

/// ELF program header type names.
fn elf_ph_type(p_type: u32) -> &'static str {
    match p_type {
        0 => "PT_NULL",
        1 => "PT_LOAD",
        2 => "PT_DYNAMIC",
        3 => "PT_INTERP",
        4 => "PT_NOTE",
        5 => "PT_SHLIB",
        6 => "PT_PHDR",
        7 => "PT_TLS",
        0x6474e550 => "PT_GNU_EH_FRAME",
        0x6474e551 => "PT_GNU_STACK",
        0x6474e552 => "PT_GNU_RELRO",
        0x6474e553 => "PT_GNU_PROPERTY",
        _ => "UNKNOWN",
    }
}

/// ELF OS/ABI names.
fn elf_osabi_name(osabi: u8) -> &'static str {
    match osabi {
        0 => "ELFOSABI_NONE (System V)",
        1 => "ELFOSABI_HPUX",
        2 => "ELFOSABI_NETBSD",
        3 => "ELFOSABI_LINUX",
        6 => "ELFOSABI_SOLARIS",
        7 => "ELFOSABI_AIX",
        8 => "ELFOSABI_IRIX",
        9 => "ELFOSABI_FREEBSD",
        10 => "ELFOSABI_TRU64",
        11 => "ELFOSABI_MODESTO",
        12 => "ELFOSABI_OPENBSD",
        64 => "ELFOSABI_ARM_AEABI",
        97 => "ELFOSABI_ARM",
        _ => "UNKNOWN",
    }
}

// ELF e_ident indices (from goblin constants).
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_VERSION: usize = 6;
const EI_OSABI: usize = 7;
const EI_ABIVERSION: usize = 8;
const ELFCLASS64: u8 = 2;

// --- Mach-O header parsing ---

/// Mach-O magic values.
fn macho_magic_name(magic: u32) -> &'static str {
    match magic {
        0xFEEDFACE => "MH_MAGIC (32-bit, big-endian)",
        0xFEEDFACF => "MH_MAGIC_64 (64-bit, big-endian)",
        0xCEFAEDFE => "MH_CIGAM (32-bit, little-endian)",
        0xCFFAEDFE => "MH_CIGAM_64 (64-bit, little-endian)",
        0xCAFEBABE => "FAT_MAGIC (Universal Binary)",
        _ => "UNKNOWN",
    }
}

/// Mach-O CPU type names.
fn macho_cputype_name(cputype: u32) -> &'static str {
    match cputype {
        0x00000007 => "CPU_TYPE_X86",
        0x01000007 => "CPU_TYPE_X86_64",
        0x0000000c => "CPU_TYPE_ARM",
        0x0100000c => "CPU_TYPE_ARM64",
        0x00000012 => "CPU_TYPE_POWERPC",
        0x01000012 => "CPU_TYPE_POWERPC64",
        _ => "UNKNOWN",
    }
}

/// Mach-O file type names.
fn macho_filetype_name(filetype: u32) -> &'static str {
    match filetype {
        1 => "MH_OBJECT",
        2 => "MH_EXECUTE",
        3 => "MH_FVMLIB",
        4 => "MH_CORE",
        5 => "MH_PRELOAD",
        6 => "MH_DYLIB",
        7 => "MH_DYLINKER",
        8 => "MH_BUNDLE",
        9 => "MH_DYLIB_STUB",
        10 => "MH_FILESET",
        _ => "UNKNOWN",
    }
}

/// Parse Mach-O header tree using goblin.
fn parse_macho_header_tree(data: &[u8]) -> Vec<HeaderField> {
    // Handle FAT Mach-O.
    let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic_be == 0xCAFEBABE || magic_be == 0xBEBAFECA {
        return parse_macho_fat_header_tree(data, magic_be);
    }

    let Ok(goblin::Object::Mach(mach)) = goblin::Object::parse(data) else {
        return Vec::new();
    };
    let goblin::mach::Mach::Binary(macho) = mach else {
        return Vec::new();
    };

    let mut tree = Vec::new();

    // Determine magic and 64-bit flag from raw data.
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let is_64 = magic == 0xFEEDFACF || magic == 0xCFFAEDFE;

    // mach_header fields (goblin mach::Header).
    let header = &macho.header;
    let header_children = vec![
        HeaderField::leaf_c(
            "magic",
            format!("0x{:08X}", header.magic),
            macho_magic_name(header.magic),
        ),
        HeaderField::leaf_c(
            "cputype",
            format!("0x{:08X}", header.cputype),
            macho_cputype_name(header.cputype),
        ),
        HeaderField::leaf("cpusubtype", format!("0x{:08X}", header.cpusubtype)),
        HeaderField::leaf_c(
            "filetype",
            format!("0x{:08X}", header.filetype),
            macho_filetype_name(header.filetype),
        ),
        HeaderField::leaf("ncmds", header.ncmds),
        HeaderField::leaf("sizeofcmds", format!("0x{:08X}", header.sizeofcmds)),
        HeaderField::leaf("flags", format!("0x{:08X}", header.flags)),
        HeaderField::leaf("reserved", format!("0x{:08X}", header.reserved)),
    ];
    let header_name = if is_64 {
        "mach_header_64"
    } else {
        "mach_header"
    };
    tree.push(HeaderField::group(header_name, header_children));

    // Load Commands.
    let mut lc_children = Vec::new();
    for (i, lc) in macho.load_commands.iter().enumerate() {
        let cmd = lc.command.cmd();
        let cmdsize = lc.command.cmdsize();
        let cmd_name = macho_lc_name(cmd);
        lc_children.push(HeaderField::group_v(
            &format!("LC[{}]", i),
            cmd_name,
            vec![
                HeaderField::leaf_c("cmd", format!("0x{:08X}", cmd), cmd_name),
                HeaderField::leaf("cmdsize", format!("0x{:08X}", cmdsize)),
            ],
        ));
    }
    if !lc_children.is_empty() {
        tree.push(HeaderField::group("Load Commands", lc_children));
    }

    // Segments and Sections.
    let mut seg_children = Vec::new();
    for seg in macho.segments.iter() {
        let seg_name = seg.name().unwrap_or("?").trim_end_matches('\0').to_string();
        let mut seg_fields = vec![
            HeaderField::leaf_c(
                "cmd",
                "LC_SEGMENT",
                if is_64 { "LC_SEGMENT_64" } else { "LC_SEGMENT" },
            ),
            HeaderField::leaf("segname", &seg_name),
            HeaderField::leaf("vmaddr", format!("0x{:016X}", seg.vmaddr)),
            HeaderField::leaf("vmsize", format!("0x{:016X}", seg.vmsize)),
            HeaderField::leaf("fileoff", format!("0x{:016X}", seg.fileoff)),
            HeaderField::leaf("filesize", format!("0x{:016X}", seg.filesize)),
            HeaderField::leaf("maxprot", format!("0x{:08X}", seg.maxprot)),
            HeaderField::leaf("initprot", format!("0x{:08X}", seg.initprot)),
            HeaderField::leaf("nsects", seg.nsects),
            HeaderField::leaf("flags", format!("0x{:08X}", seg.flags)),
        ];

        // Sections within this segment.
        if let Ok(sections) = seg.sections() {
            for (sec, _sec_data) in sections {
                let sec_name = sec.name().unwrap_or("?").trim_end_matches('\0').to_string();
                seg_fields.push(HeaderField::group_v(
                    &sec_name,
                    format!("@0x{:016X}", sec.addr),
                    vec![
                        HeaderField::leaf("sectname", &sec_name),
                        HeaderField::leaf("segname", seg_name.trim_end_matches('\0')),
                        HeaderField::leaf("addr", format!("0x{:016X}", sec.addr)),
                        HeaderField::leaf("size", format!("0x{:016X}", sec.size)),
                        HeaderField::leaf("offset", format!("0x{:08X}", sec.offset)),
                        HeaderField::leaf("align", format!("0x{:08X}", sec.align)),
                        HeaderField::leaf("reloff", format!("0x{:08X}", sec.reloff)),
                        HeaderField::leaf("nreloc", sec.nreloc),
                        HeaderField::leaf("flags", format!("0x{:08X}", sec.flags)),
                    ],
                ));
            }
        }

        seg_children.push(HeaderField::group_v(
            &seg_name,
            format!("@0x{:016X}", seg.vmaddr),
            seg_fields,
        ));
    }
    if !seg_children.is_empty() {
        tree.push(HeaderField::group("Segments & Sections", seg_children));
    }

    // Libraries (DYLD loaded libraries).
    // DylibCommand.dylib.name is a LcStr (u32 offset) relative to the load
    // command start. We read the C string from the raw file data at
    // lc.offset + name_offset.
    let mut lib_names = Vec::new();
    for lc in macho.load_commands.iter() {
        let name_offset = match &lc.command {
            goblin::mach::load_command::CommandVariant::LoadDylib(ld)
            | goblin::mach::load_command::CommandVariant::IdDylib(ld)
            | goblin::mach::load_command::CommandVariant::LoadWeakDylib(ld)
            | goblin::mach::load_command::CommandVariant::ReexportDylib(ld)
            | goblin::mach::load_command::CommandVariant::LazyLoadDylib(ld)
            | goblin::mach::load_command::CommandVariant::LoadUpwardDylib(ld) => {
                lc.offset + ld.dylib.name as usize
            }
            _ => continue,
        };
        if name_offset >= data.len() {
            continue;
        }
        // Read NUL-terminated string.
        let end = data[name_offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_offset + p)
            .unwrap_or(data.len());
        if let Ok(name) = std::str::from_utf8(&data[name_offset..end])
            && !name.is_empty()
        {
            lib_names.push(HeaderField::leaf("library", name));
        }
    }
    if !lib_names.is_empty() {
        tree.push(HeaderField::group("Libraries (DYLD)", lib_names));
    }

    tree
}

/// Parse FAT (Universal Binary) Mach-O header tree.
fn parse_macho_fat_header_tree(data: &[u8], magic: u32) -> Vec<HeaderField> {
    let mut tree = Vec::new();

    // FAT header: magic (u32) + nfat_arch (u32).
    if data.len() < 8 {
        return tree;
    }
    let nfat_arch = if magic == 0xCAFEBABE {
        u32::from_be_bytes([data[4], data[5], data[6], data[7]])
    } else {
        u32::from_le_bytes([data[4], data[5], data[6], data[7]])
    };

    tree.push(HeaderField::group(
        "fat_header",
        vec![
            HeaderField::leaf_c("magic", format!("0x{:08X}", magic), macho_magic_name(magic)),
            HeaderField::leaf("nfat_arch", nfat_arch),
        ],
    ));

    // Parse each architecture slice's fat_arch header.
    let mut arch_children = Vec::new();
    let arch_size = 20; // fat_arch is 20 bytes: cputype(4) + cpusubtype(4) + offset(4) + size(4) + align(4)
    for i in 0..nfat_arch as usize {
        let off = 8 + i * arch_size;
        if off + arch_size > data.len() {
            break;
        }
        let read_u32_be =
            |o: usize| u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let read_u32_le =
            |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let (cputype, cpusubtype, offset, size, align) = if magic == 0xCAFEBABE {
            (
                read_u32_be(off),
                read_u32_be(off + 4),
                read_u32_be(off + 8),
                read_u32_be(off + 12),
                read_u32_be(off + 16),
            )
        } else {
            (
                read_u32_le(off),
                read_u32_le(off + 4),
                read_u32_le(off + 8),
                read_u32_le(off + 12),
                read_u32_le(off + 16),
            )
        };
        arch_children.push(HeaderField::group_v(
            &format!("fat_arch[{}]", i),
            macho_cputype_name(cputype),
            vec![
                HeaderField::leaf_c(
                    "cputype",
                    format!("0x{:08X}", cputype),
                    macho_cputype_name(cputype),
                ),
                HeaderField::leaf("cpusubtype", format!("0x{:08X}", cpusubtype)),
                HeaderField::leaf("offset", format!("0x{:08X}", offset)),
                HeaderField::leaf("size", format!("0x{:08X}", size)),
                HeaderField::leaf("align", format!("0x{:08X}", align)),
            ],
        ));
    }
    tree.push(HeaderField::group("fat_arch", arch_children));

    tree
}

/// Mach-O load command names.
fn macho_lc_name(cmd: u32) -> &'static str {
    match cmd {
        0x01 => "LC_SEGMENT",
        0x02 => "LC_SYMTAB",
        0x03 => "LC_SYMSEG",
        0x04 => "LC_THREAD",
        0x05 => "LC_UNIXTHREAD",
        0x06 => "LC_LOADFVMLIB",
        0x07 => "LC_IDFVMLIB",
        0x08 => "LC_IDENT",
        0x09 => "LC_FVMFILE",
        0x0a => "LC_PREPAGE",
        0x0b => "LC_DYSYMTAB",
        0x0c => "LC_LOAD_DYLIB",
        0x0d => "LC_ID_DYLIB",
        0x0e => "LC_LOAD_DYLINKER",
        0x0f => "LC_ID_DYLINKER",
        0x10 => "LC_PREBOUND_DYLIB",
        0x11 => "LC_ROUTINES",
        0x12 => "LC_SUB_FRAMEWORK",
        0x13 => "LC_SUB_UMBRELLA",
        0x14 => "LC_SUB_CLIENT",
        0x15 => "LC_SUB_LIBRARY",
        0x16 => "LC_TWOLEVEL_HINTS",
        0x17 => "LC_PREBIND_CKSUM",
        0x19 => "LC_SEGMENT_64",
        0x1a => "LC_ROUTINES_64",
        0x1b => "LC_UUID",
        0x1c => "LC_RPATH",
        0x1d => "LC_CODE_SIGNATURE",
        0x1e => "LC_SEGMENT_SPLIT_INFO",
        0x1f => "LC_REEXPORT_DYLIB",
        0x20 => "LC_LAZY_LOAD_DYLIB",
        0x21 => "LC_ENCRYPTION_INFO",
        0x22 => "LC_DYLD_INFO",
        0x24 => "LC_DYLD_INFO_ONLY",
        0x25 => "LC_LOAD_WEAK_DYLIB",
        0x26 => "LC_SEGMENT_64",
        0x29 => "LC_REEXPORT_DYLIB",
        0x2a => "LC_DYLIB_CODE_SIGN_DRS",
        0x2b => "LC_LINKER_OPTION",
        0x2c => "LC_SEGMENT_SPLIT_INFO",
        0x31 => "LC_ENCRYPTION_INFO_64",
        0x32 => "LC_LINKER_OPTIMIZATION_HINT",
        0x33 => "LC_VERSION_MIN_TVOS",
        0x34 => "LC_VERSION_MIN_WATCHOS",
        0x35 => "LC_NOTE",
        0x36 => "LC_BUILD_VERSION",
        0x80000002 => "LC_LOAD_DYLIB (LC_REQ_DYLD)",
        0x80000022 => "LC_DYLD_INFO_ONLY (LC_REQ_DYLD)",
        0x80000025 => "LC_LOAD_WEAK_DYLIB (LC_REQ_DYLD)",
        0x80000029 => "LC_REEXPORT_DYLIB (LC_REQ_DYLD)",
        _ => "UNKNOWN",
    }
}

/// Parse header tree based on detected format.
fn parse_header_tree(format: &str, data: &[u8]) -> Vec<HeaderField> {
    match format {
        "PE32" | "PE32+" | "PE" => parse_pe_header_tree(data),
        "ELF32" | "ELF64" | "ELF" => parse_elf_header_tree(data),
        "Mach-O 32" | "Mach-O 64" | "Mach-O FAT" => parse_macho_header_tree(data),
        "DOS MZ" => build_dos_header_only(data),
        _ => Vec::new(),
    }
}
///
/// Reads the file, computes hashes and entropy, detects the format,
/// and parses PE/ELF/Mach-O sections and symbols if applicable.
pub fn gather_file_info(path: &str) -> Result<FileInfo, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let file_name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());

    let format = detect_format(&data);
    let hashes = compute_hashes(&data);
    let entropy = shannon_entropy(&data);

    let (sections, symbols) = match format.as_str() {
        "PE32" | "PE32+" | "PE" => parse_pe_sections(&data),
        "ELF32" | "ELF64" | "ELF" => parse_elf_sections(&data),
        "Mach-O 32" | "Mach-O 64" => parse_macho_sections(&data),
        _ => (Vec::new(), Vec::new()),
    };

    let header_tree = parse_header_tree(&format, &data);
    let mime_type = detect_mime_type(&format, &data);
    let (base_address, entry_point) = extract_base_and_entry(&format, &data);
    let format_count = sections.len() as u32;

    Ok(FileInfo {
        path: path.to_string(),
        file_name,
        size: data.len() as u64,
        size_human: format_size(data.len() as u64),
        entropy,
        hashes,
        format,
        sections,
        symbols,
        header_tree,
        mime_type,
        base_address,
        entry_point,
        format_count,
    })
}

/// Extract base address and entry point from PE/ELF/Mach-O headers.
fn extract_base_and_entry(format: &str, data: &[u8]) -> (u64, u64) {
    match format {
        "PE32" | "PE32+" | "PE" => {
            // Try PE viewer for base/entry.
            if let Some(view) = crate::pe_viewer::parse_pe_view(data)
                && let Some(oh) = &view.optional_header
            {
                return (oh.image_base, oh.address_of_entry_point as u64);
            }
            (0, 0)
        }
        "ELF32" | "ELF64" | "ELF" => {
            if let Some(view) = crate::elf_viewer::parse_elf_view(data) {
                return (0, view.entry);
            }
            (0, 0)
        }
        "MACH-O" | "Mach-O" | "MACHO" => {
            if let Some(view) = crate::macho_viewer::parse_macho_view(data) {
                // Mach-O entry is in the entry_point field or from LC_MAIN.
                let entry = view.entry_point.map(|ep| ep.entryoff).unwrap_or(0);
                return (0, entry);
            }
            (0, 0)
        }
        _ => (0, 0),
    }
}

/// Detect MIME type from the detected format and file magic bytes.
///
/// Uses the format string from `detect_format` and falls back to
/// magic byte inspection for common types.
fn detect_mime_type(format: &str, data: &[u8]) -> String {
    match format {
        "PE32" | "PE32+" | "PE" | "MSDOS" => "application/x-dosexec".to_string(),
        "ELF32" | "ELF64" | "ELF" => "application/x-elf".to_string(),
        "Mach-O 32" | "Mach-O 64" | "Mach-O FAT" => "application/x-mach-binary".to_string(),
        "ZIP" => "application/zip".to_string(),
        "GZIP" => "application/gzip".to_string(),
        "TAR" => "application/x-tar".to_string(),
        "GZIP/TAR" => "application/gzip".to_string(),
        "RAR" => "application/vnd.rar".to_string(),
        "7Z" => "application/x-7z-compressed".to_string(),
        "ISO9660" => "application/x-iso9660-image".to_string(),
        "CAB" => "application/vnd.ms-cab-compressed".to_string(),
        "PDF" => "application/pdf".to_string(),
        "CFBF" => "application/x-cfb".to_string(),
        "JPEG" => "image/jpeg".to_string(),
        "PNG" => "image/png".to_string(),
        "BMP" => "image/bmp".to_string(),
        "WAV" => "audio/wav".to_string(),
        "DEX" => "application/vnd.android.dex".to_string(),
        "JavaClass" => "application/java-vm".to_string(),
        "PYC" => "application/x-python-code".to_string(),
        _ => {
            // Fall back to magic byte checks for unknown formats.
            if data.starts_with(b"\x89PNG") {
                "image/png".to_string()
            } else if data.starts_with(b"\xFF\xD8\xFF") {
                "image/jpeg".to_string()
            } else if data.starts_with(b"%PDF") {
                "application/pdf".to_string()
            } else if data.starts_with(b"PK\x03\x04") {
                "application/zip".to_string()
            } else if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
                "application/gzip".to_string()
            } else if data.starts_with(b"BM") {
                "image/bmp".to_string()
            } else if data.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WAVE" {
                "audio/wav".to_string()
            } else if data
                .iter()
                .all(|&b| b == 0 || (0x09..=0x0D).contains(&b) || (0x20..=0x7E).contains(&b))
            {
                "text/plain".to_string()
            } else {
                "application/octet-stream".to_string()
            }
        }
    }
}

/// Compute entropy for a file region (for the entropy view).
///
/// Returns entropy values for fixed-size blocks of the file,
/// suitable for plotting an entropy graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyGraph {
    /// Block size in bytes.
    pub block_size: u64,
    /// Entropy value for each block.
    pub blocks: Vec<f64>,
    /// Overall file entropy.
    pub overall: f64,
}

/// Compute entropy graph data for a file.
pub fn compute_entropy_graph(path: &str, block_size: Option<u64>) -> Result<EntropyGraph, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let bs = block_size.unwrap_or(256) as usize;
    let bs = bs.max(1);
    let mut blocks = Vec::new();
    for chunk in data.chunks(bs) {
        blocks.push(shannon_entropy(chunk));
    }
    let overall = shannon_entropy(&data);
    Ok(EntropyGraph {
        block_size: bs as u64,
        blocks,
        overall,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_format_macho_fat_be() {
        // FAT Mach-O magic (big-endian): 0xCAFEBABE
        let data = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0];
        assert_eq!(detect_format(&data), "Mach-O FAT");
    }

    #[test]
    fn test_detect_format_macho_fat_le() {
        // FAT Mach-O magic (little-endian): 0xBEBAFECA
        let data = [0xBE, 0xBA, 0xFE, 0xCA, 0, 0, 0, 0];
        assert_eq!(detect_format(&data), "Mach-O FAT");
    }

    #[test]
    fn test_detect_format_macho_64() {
        // Mach-O 64-bit magic (big-endian): 0xFEEDFACF
        let data = [0xFE, 0xED, 0xFA, 0xCF, 0, 0, 0, 0];
        assert_eq!(detect_format(&data), "Mach-O 64");
    }

    #[test]
    fn test_detect_format_pe32() {
        // Minimal PE32: MZ header + e_lfanew pointing to PE signature
        let mut data = vec![0u8; 0x80];
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew at 0x3c = 0x40
        data[0x3c] = 0x40;
        // PE signature at 0x40
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        // Machine type at 0x44 = 0x14c (i386)
        data[0x44] = 0x4c;
        data[0x45] = 0x01;
        assert_eq!(detect_format(&data), "PE32");
    }

    #[test]
    fn test_detect_format_elf64() {
        // ELF 64-bit
        let data = [0x7f, b'E', b'L', b'F', 2, 0, 0, 0];
        assert_eq!(detect_format(&data), "ELF64");
    }

    #[test]
    fn test_detect_format_unknown() {
        let data = [0x00, 0x01, 0x02, 0x03];
        assert_eq!(detect_format(&data), "Unknown");
    }

    #[test]
    fn test_detect_format_too_short() {
        let data = [0x00, 0x01];
        assert_eq!(detect_format(&data), "Unknown");
    }

    // --- Header tree tests ---

    #[test]
    fn test_header_field_leaf() {
        let f = HeaderField::leaf("test", 42);
        assert_eq!(f.name, "test");
        assert_eq!(f.value, "42");
        assert!(f.comment.is_none());
        assert!(f.children.is_empty());
    }

    #[test]
    fn test_header_field_leaf_with_comment() {
        let f = HeaderField::leaf_c("e_magic", "0x5A4D", "MZ signature");
        assert_eq!(f.name, "e_magic");
        assert_eq!(f.value, "0x5A4D");
        assert_eq!(f.comment.as_deref(), Some("MZ signature"));
    }

    #[test]
    fn test_header_field_group() {
        let f = HeaderField::group(
            "DOS Header",
            vec![
                HeaderField::leaf("e_magic", "0x5A4D"),
                HeaderField::leaf("e_lfanew", "0x40"),
            ],
        );
        assert_eq!(f.name, "DOS Header");
        assert_eq!(f.children.len(), 2);
    }

    #[test]
    fn test_parse_pe_header_tree_dos_only() {
        // MZ file without PE signature → DOS header only.
        let mut data = vec![0u8; 128];
        data[0] = b'M';
        data[1] = b'Z';
        let tree = parse_pe_header_tree(&data);
        // Should at least have DOS header.
        assert!(!tree.is_empty());
        assert_eq!(tree[0].name, "IMAGE_DOS_HEADER");
        // DOS header should have e_magic and e_lfanew fields.
        let dos_fields: Vec<&str> = tree[0].children.iter().map(|f| f.name.as_str()).collect();
        assert!(dos_fields.contains(&"e_magic"));
        assert!(dos_fields.contains(&"e_lfanew"));
    }

    #[test]
    fn test_parse_pe_header_tree_full_pe32() {
        // Minimal PE32 with aligned e_lfanew.
        // pelite requires a complete Optional Header, so if pelite fails
        // we fall back to DOS header only. Verify at least DOS header is present.
        let mut data = vec![0u8; 0x200];
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew at 0x3c = 0x40 (8-byte aligned for pe64, 4-byte for pe32).
        data[0x3c] = 0x40;
        // PE signature at 0x40.
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        // Machine = 0x14c (i386) at 0x44.
        data[0x44] = 0x4c;
        data[0x45] = 0x01;
        // NumberOfSections = 1 at 0x46.
        data[0x46] = 0x01;
        // SizeOfOptionalHeader = 0xE0 at 0x54.
        data[0x54] = 0xe0;
        // Magic = 0x10b (PE32) at optional header offset 0x58.
        data[0x58] = 0x0b;
        data[0x59] = 0x01;

        let tree = parse_pe_header_tree(&data);
        // Should at least have DOS header (pelite may fail on incomplete PE).
        assert!(!tree.is_empty());
        assert_eq!(tree[0].name, "IMAGE_DOS_HEADER");
    }

    #[test]
    fn test_parse_elf_header_tree() {
        // Minimal ELF64 header.
        let mut data = vec![0u8; 64];
        data[0] = 0x7f;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB
        data[6] = 1; // EV_CURRENT
        // e_type = ET_EXEC (2) at offset 16.
        data[16] = 2;
        // e_machine = EM_X86_64 (62) at offset 18.
        data[18] = 62;
        data[19] = 0;
        // e_entry at offset 24 (8 bytes, already 0).
        // e_phoff at offset 32.
        // e_shoff at offset 40.
        // e_ehsize = 64 at offset 52.
        data[52] = 64;

        let tree = parse_elf_header_tree(&data);
        assert!(!tree.is_empty());
        // First group should be ELF Header.
        assert!(tree[0].name.starts_with("ELF Header"));
        // Should contain e_ident fields.
        let names: Vec<&str> = tree[0].children.iter().map(|f| f.name.as_str()).collect();
        assert!(names.iter().any(|n| n.contains("EI_MAG")));
        assert!(names.contains(&"e_type"));
        assert!(names.contains(&"e_machine"));
    }

    #[test]
    fn test_parse_macho_header_tree_64() {
        // Minimal Mach-O 64-bit header (big-endian magic).
        let mut data = vec![0u8; 0x100];
        // magic = 0xFEEDFACF (MH_MAGIC_64, big-endian).
        data[0] = 0xFE;
        data[1] = 0xED;
        data[2] = 0xFA;
        data[3] = 0xCF;
        // cputype = CPU_TYPE_X86_64 (0x01000007) big-endian.
        data[4] = 0x01;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x07;
        // filetype = MH_EXECUTE (2) big-endian.
        data[8] = 0x00;
        data[9] = 0x00;
        data[10] = 0x00;
        data[11] = 0x02;
        // ncmds = 0.
        // sizeofcmds = 0.

        let tree = parse_macho_header_tree(&data);
        assert!(!tree.is_empty());
        // First group should be mach_header_64.
        assert!(tree[0].name.contains("mach_header"));
    }

    #[test]
    fn test_parse_macho_fat_header_tree() {
        // FAT Mach-O: magic=0xCAFEBABE, nfat_arch=2.
        let mut data = vec![0u8; 8 + 2 * 20];
        data[0] = 0xCA;
        data[1] = 0xFE;
        data[2] = 0xBA;
        data[3] = 0xBE;
        // nfat_arch = 2 (big-endian).
        data[4] = 0x00;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x02;
        // First arch: cputype=CPU_TYPE_X86 (7).
        data[8] = 0x00;
        data[9] = 0x00;
        data[10] = 0x00;
        data[11] = 0x07;

        let tree = parse_macho_fat_header_tree(&data, 0xCAFEBABE);
        assert!(!tree.is_empty());
        assert_eq!(tree[0].name, "fat_header");
        // Should have fat_arch group with 2 entries.
        assert_eq!(tree.len(), 2);
        assert_eq!(tree[1].name, "fat_arch");
        assert_eq!(tree[1].children.len(), 2);
    }

    #[test]
    fn test_decode_pe_section_flags() {
        // .text section: CODE + EXECUTE + READ = 0x20 | 0x20000000 | 0x40000000 = 0x60000020
        let flags = decode_pe_section_flags(0x60000020);
        assert!(flags.contains("IMAGE_SCN_CNT_CODE"));
        assert!(flags.contains("IMAGE_SCN_MEM_EXECUTE"));
        assert!(flags.contains("IMAGE_SCN_MEM_READ"));
    }

    #[test]
    fn test_decode_pe_file_chars() {
        // EXECUTABLE_IMAGE | 32BIT_MACHINE = 0x0002 | 0x0100 = 0x0102
        let chars = decode_pe_file_chars(0x0102);
        assert!(chars.contains("IMAGE_FILE_EXECUTABLE_IMAGE"));
        assert!(chars.contains("IMAGE_FILE_32BIT_MACHINE"));
    }

    #[test]
    fn test_pe_machine_name() {
        assert_eq!(pe_machine_name(0x014c), "IMAGE_FILE_MACHINE_I386");
        assert_eq!(pe_machine_name(0x8664), "IMAGE_FILE_MACHINE_AMD64");
        assert_eq!(pe_machine_name(0xaa64), "IMAGE_FILE_MACHINE_ARM64");
    }

    #[test]
    fn test_elf_machine_name() {
        assert_eq!(elf_machine_name(62), "EM_X86_64");
        assert_eq!(elf_machine_name(3), "EM_386");
        assert_eq!(elf_machine_name(183), "EM_AARCH64");
    }

    #[test]
    fn test_gather_file_info_includes_header_tree() {
        // Create a minimal PE32 file and verify header_tree is populated.
        let mut data = vec![0u8; 0x200];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3c] = 0x40;
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        data[0x44] = 0x4c;
        data[0x45] = 0x01;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.exe");
        std::fs::write(&path, &data).unwrap();

        let info = gather_file_info(path.to_str().unwrap()).unwrap();
        assert!(
            !info.header_tree.is_empty(),
            "header_tree should be populated for PE files"
        );
        assert!(
            info.header_tree[0].name.contains("DOS")
                || info.header_tree[0].name.contains("IMAGE_DOS")
        );
    }

    #[test]
    fn test_gather_file_info_header_tree_unknown_format() {
        // Non-binary file → empty header_tree.
        let data = b"Hello, World!";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, data).unwrap();

        let info = gather_file_info(path.to_str().unwrap()).unwrap();
        assert!(
            info.header_tree.is_empty(),
            "header_tree should be empty for unknown formats"
        );
    }

    // --- Format detection extension tests (Phase 11.2) ---

    #[test]
    fn test_detect_format_pdf() {
        // PDF magic: %PDF
        let data = b"%PDF-1.4\n%test";
        assert_eq!(detect_format(data), "PDF");
    }

    #[test]
    fn test_detect_format_png() {
        // PNG magic: 89 50 4E 47 0D 0A 1A 0A
        let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_format(&data), "PNG");
    }

    #[test]
    fn test_detect_format_jpeg() {
        // JPEG magic: FF D8 FF
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert_eq!(detect_format(&data), "JPEG");
    }

    #[test]
    fn test_detect_format_zip() {
        // ZIP magic: PK 03 04
        let data = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_format(&data), "ZIP");
    }

    #[test]
    fn test_detect_format_gzip() {
        // GZIP magic: 1F 8B
        let data = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_format(&data), "GZIP");
    }

    #[test]
    fn test_detect_format_iso9660() {
        // ISO9660 magic: "CD001" at offset 0x8001 (32769)
        let mut data = vec![0u8; 0x8006];
        data[0x8001] = b'C';
        data[0x8002] = b'D';
        data[0x8003] = b'0';
        data[0x8004] = b'0';
        data[0x8005] = b'1';
        assert_eq!(detect_format(&data), "ISO9660");
    }

    // --- MIME type detection tests (Phase 11.8) ---

    #[test]
    fn test_detect_mime_type_pe32() {
        let mut data = vec![0u8; 0x80];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3c] = 0x40;
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        data[0x44] = 0x4c;
        data[0x45] = 0x01;
        data[0x58] = 0x0b;
        data[0x59] = 0x01;
        assert_eq!(detect_mime_type("PE32", &data), "application/x-dosexec");
    }

    #[test]
    fn test_detect_mime_type_elf() {
        let data = [0x7F, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00];
        assert_eq!(detect_mime_type("ELF64", &data), "application/x-elf");
    }

    #[test]
    fn test_detect_mime_type_pdf() {
        let data = b"%PDF-1.4";
        assert_eq!(detect_mime_type("PDF", data), "application/pdf");
    }

    #[test]
    fn test_detect_mime_type_png() {
        let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_mime_type("PNG", &data), "image/png");
    }

    #[test]
    fn test_detect_mime_type_zip() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_mime_type("ZIP", &data), "application/zip");
    }

    #[test]
    fn test_detect_mime_type_unknown() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        assert_eq!(
            detect_mime_type("Unknown", &data),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_detect_mime_type_text() {
        let data = b"Hello, World!";
        assert_eq!(detect_mime_type("Unknown", data), "text/plain");
    }
}

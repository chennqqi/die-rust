//! PE-specific views: imports, exports, resources, overlay, .NET, manifest,
//! version info, TLS, and Rich Header.
//!
//! Uses `pelite` for deep PE parsing (PE32 and PE32+). Provides structured
//! data for the PE-specific sub-tabs in the file info panel.

use serde::{Deserialize, Serialize};

// Pelite traits for PE32/PE64.
use pelite::pe32::Pe as Pe32;
use pelite::pe32::PeObject as PeObject32;
use pelite::pe64::Pe as Pe64;
use pelite::pe64::PeObject as PeObject64;

/// PE import entry: DLL name + imported function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeImportEntry {
    /// DLL name (e.g. "kernel32.dll").
    pub dll: String,
    /// Function name or ordinal.
    pub name: String,
}

/// PE export entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeExportEntry {
    /// Export name (may be empty for ordinal-only exports).
    pub name: String,
    /// Ordinal number.
    pub ordinal: u16,
    /// RVA of the export.
    pub rva: u32,
}

/// PE resource tree node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeResourceNode {
    /// Resource type/name/language identifier.
    pub id: u32,
    /// Human-readable name (if available).
    pub name: String,
    /// Data size (for leaf nodes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_size: Option<u32>,
    /// Child nodes (for branch nodes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<PeResourceNode>,
}

/// PE .NET metadata info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDotNetInfo {
    /// CLR header presence.
    pub has_clr: bool,
    /// .NET CLR header directory RVA.
    pub clr_rva: u32,
    /// .NET CLR header directory size.
    pub clr_size: u32,
}

/// PE version info entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeVersionEntry {
    /// Key-value pairs from VS_VERSIONINFO.
    pub entries: Vec<(String, String)>,
}

/// PE data directory entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDataDirectoryEntry {
    /// Directory name (EXPORT, IMPORT, RESOURCE, etc.).
    pub name: String,
    /// Directory index (0-15).
    pub index: u32,
    /// RVA of the directory.
    pub rva: u32,
    /// Size of the directory.
    pub size: u32,
}

/// PE debug directory entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDebugEntry {
    /// Debug type string.
    pub debug_type: String,
    /// Debug type raw value.
    pub debug_type_val: u32,
    /// Size of data.
    pub size_of_data: u32,
    /// Address of raw data (RVA).
    pub address_of_raw_data: u32,
    /// Pointer to raw data (file offset).
    pub pointer_to_raw_data: u32,
    /// PDB file name (if CodeView).
    pub pdb_file_name: Option<String>,
}

/// PE relocation block entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeRelocBlock {
    /// Virtual address of the page.
    pub virtual_address: u32,
    /// Block size in bytes.
    pub block_size: u32,
    /// Number of relocations in this block.
    pub count: u32,
}

/// PE load config summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeLoadConfig {
    /// Size of the load config structure.
    pub size: u32,
    /// Security cookie VA.
    pub security_cookie: u64,
    /// SE handler table VA.
    pub se_handler_table: u64,
    /// SE handler count.
    pub se_handler_count: u64,
}

/// PE certificate entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeCertificate {
    /// Certificate type.
    pub certificate_type: u16,
    /// Certificate data length.
    pub data_length: usize,
    /// Whether certificate data is present.
    pub has_data: bool,
}

/// PE DOS header field (name + value pair).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDosHeaderField {
    /// Field name (e_magic, e_cblp, etc.).
    pub name: String,
    /// Field value as hex string.
    pub value: String,
    /// Human-readable description (if applicable).
    pub description: Option<String>,
}

/// PE DOS stub (bytes between DOS header and PE signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDosStub {
    /// Offset of the DOS stub.
    pub offset: u32,
    /// Size in bytes.
    pub size: u32,
    /// Hex dump of the stub.
    pub hex_dump: String,
}

/// PE File Header field (IMAGE_FILE_HEADER, 7 fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeFileHeader {
    pub machine: String,
    pub machine_val: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: String,
    pub characteristics_val: u16,
}

/// PE Optional Header (IMAGE_OPTIONAL_HEADER, 31+ fields, 32/64-bit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeOptionalHeader {
    pub is64: bool,
    pub magic: u16,
    pub magic_str: String,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: String,
    pub subsystem_val: u16,
    pub dll_characteristics: String,
    pub dll_characteristics_val: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// PE section header detail (IMAGE_SECTION_HEADER with parsed flags).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSectionDetail {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: String,
    pub characteristics_val: u32,
    /// Entropy of the section's raw data.
    pub entropy: Option<f64>,
}

/// PE section statistics (SECTIONS_INFO).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSectionStats {
    pub total_sections: u32,
    pub total_virtual_size: u64,
    pub total_raw_size: u64,
    pub min_entropy: Option<f64>,
    pub max_entropy: Option<f64>,
    pub avg_entropy: Option<f64>,
}

/// PE import info summary (IMPORT_INFO).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeImportInfo {
    pub total_dlls: u32,
    pub total_functions: u32,
    pub dlls: Vec<PeImportDllSummary>,
}

/// PE import DLL summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeImportDllSummary {
    pub dll_name: String,
    pub function_count: u32,
}

/// PE exception table entry (IMAGE_RUNTIME_FUNCTION_ENTRY).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeExceptionEntry {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

/// PE bound import entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeBoundImportEntry {
    pub module_name: String,
    pub time_date_stamp: u32,
    pub offset_module_name: u16,
    pub number_of_module_forwarder_refs: u16,
}

/// PE delay import entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDelayImportEntry {
    pub dll_name: String,
    pub attributes: u32,
    pub dll_name_rva: u32,
    pub module_handle_rva: u32,
    pub import_address_table_rva: u32,
    pub import_name_table_rva: u32,
    pub bound_import_address_table_rva: u32,
    pub unload_information_table_rva: u32,
    pub time_date_stamp: u32,
}

/// PE NT Headers summary (IMAGE_NT_HEADERS overview).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeNtHeaders {
    /// PE signature ("PE\0\0").
    pub signature: String,
    /// Signature raw value (0x00004550).
    pub signature_val: u32,
    /// Offset of NT headers in file.
    pub offset: u32,
    /// File header summary.
    pub file_header_summary: PeNtFileHeaderSummary,
    /// Optional header summary.
    pub optional_header_summary: PeNtOptionalHeaderSummary,
    /// Number of data directories.
    pub number_of_data_directories: u32,
    /// Number of sections.
    pub number_of_sections: u16,
}

/// PE NT headers file header summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeNtFileHeaderSummary {
    pub machine: String,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub characteristics: String,
}

/// PE NT headers optional header summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeNtOptionalHeaderSummary {
    pub magic: String,
    pub is64: bool,
    pub entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: String,
}

/// PE resource string table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeResourceStringEntry {
    /// String ID (base + index).
    pub id: u32,
    /// String value (UTF-16 decoded).
    pub value: String,
    /// Resource offset in file.
    pub offset: u32,
}

/// PE .NET metadata stream detail (parsed content of each stream).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDotNetStreamDetail {
    /// Stream name.
    pub name: String,
    /// Stream offset.
    pub offset: u32,
    /// Stream size.
    pub size: u32,
    /// Stream type.
    pub stream_type: String,
    /// Hex dump of first 256 bytes (for inspection).
    pub hex_preview: String,
}

/// PE .NET metadata table row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDotNetMetadataTableRow {
    /// Table name (Module, TypeRef, TypeDef, MethodDef, etc.).
    pub table_name: String,
    /// Row index (1-based).
    pub row: u32,
    /// Column values as strings.
    pub columns: Vec<(String, String)>,
}

/// PE .NET metadata table summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDotNetMetadataTable {
    /// List of table names present in the #~ stream.
    pub present_tables: Vec<String>,
    /// Number of rows per table.
    pub row_counts: Vec<(String, u32)>,
    /// Sample rows from each table (first 10 rows).
    pub sample_rows: Vec<PeDotNetMetadataTableRow>,
}

/// PE .NET metadata summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDotNetMetadata {
    pub runtime_version: String,
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub flags: u32,
    pub entry_point_token: u32,
    pub streams: Vec<PeDotNetStream>,
}

/// PE .NET metadata stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDotNetStream {
    pub name: String,
    pub offset: u32,
    pub size: u32,
}

/// Complete PE-specific view data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeView {
    /// Import directory entries.
    pub imports: Vec<PeImportEntry>,
    /// Export directory entries.
    pub exports: Vec<PeExportEntry>,
    /// Resource directory tree.
    pub resources: Vec<PeResourceNode>,
    /// Overlay offset and size.
    pub overlay_offset: u64,
    pub overlay_size: u64,
    /// .NET metadata info (None if not a .NET assembly).
    pub dotnet: Option<PeDotNetInfo>,
    /// Manifest XML content (if embedded as RT_MANIFEST resource).
    pub manifest: Option<String>,
    /// Version info entries.
    pub version_info: Vec<PeVersionEntry>,
    /// TLS directory RVA (empty if no TLS).
    pub tls_callbacks: Vec<u64>,
    /// Rich header presence.
    pub has_rich_header: bool,
    /// Data directory entries (16 entries).
    pub data_directories: Vec<PeDataDirectoryEntry>,
    /// Debug directory entries.
    pub debug_entries: Vec<PeDebugEntry>,
    /// Base relocation blocks.
    pub reloc_blocks: Vec<PeRelocBlock>,
    /// Load config summary (if present).
    pub load_config: Option<PeLoadConfig>,
    /// Certificate entries (if present).
    pub certificates: Vec<PeCertificate>,
    /// DOS header fields (31 fields).
    pub dos_header: Vec<PeDosHeaderField>,
    /// DOS stub (bytes between DOS header and PE signature).
    pub dos_stub: Option<PeDosStub>,
    /// File header (IMAGE_FILE_HEADER).
    pub file_header: Option<PeFileHeader>,
    /// Optional header (IMAGE_OPTIONAL_HEADER).
    pub optional_header: Option<PeOptionalHeader>,
    /// Section details with parsed flags and entropy.
    pub section_details: Vec<PeSectionDetail>,
    /// Section statistics.
    pub section_stats: Option<PeSectionStats>,
    /// Import info summary.
    pub import_info: Option<PeImportInfo>,
    /// Exception table entries.
    pub exceptions: Vec<PeExceptionEntry>,
    /// Bound import entries.
    pub bound_imports: Vec<PeBoundImportEntry>,
    /// Delay import entries.
    pub delay_imports: Vec<PeDelayImportEntry>,
    /// .NET metadata (if .NET assembly).
    pub dotnet_metadata: Option<PeDotNetMetadata>,
    /// NT headers summary (IMAGE_NT_HEADERS overview).
    pub nt_headers: Option<PeNtHeaders>,
    /// Resource string table entries (RT_STRING resources).
    pub resource_strings: Vec<PeResourceStringEntry>,
    /// .NET metadata stream details.
    pub dotnet_stream_details: Vec<PeDotNetStreamDetail>,
    /// .NET metadata table data.
    pub dotnet_metadata_table: Option<PeDotNetMetadataTable>,
}

/// Parse PE view data from raw file bytes.
///
/// Tries PE64 first, then PE32. Returns None if the file is not a valid PE.
pub fn parse_pe_view(data: &[u8]) -> Option<PeView> {
    if let Some(file) = safe_pe64(data) {
        return Some(build_pe64_view(&file, data));
    }
    if let Some(file) = safe_pe32(data) {
        return Some(build_pe32_view(&file, data));
    }
    None
}

/// Safely parse PE64.
fn safe_pe64(data: &[u8]) -> Option<pelite::pe64::PeFile<'_>> {
    if !is_pe_aligned(data, 8) {
        return None;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pelite::pe64::PeFile::from_bytes(data)
    }))
    .ok()
    .and_then(|r| r.ok())
}

/// Safely parse PE32.
fn safe_pe32(data: &[u8]) -> Option<pelite::pe32::PeFile<'_>> {
    if !is_pe_aligned(data, 4) {
        return None;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pelite::pe32::PeFile::from_bytes(data)
    }))
    .ok()
    .and_then(|r| r.ok())
}

/// Check PE alignment safety (mirrors file_info.rs logic).
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

/// Build PE64 view.
fn build_pe64_view(file: &pelite::pe64::PeFile<'_>, data: &[u8]) -> PeView {
    let dd = file.data_directory();
    let dos_header = parse_dos_header(data);
    let dos_stub = parse_dos_stub(data);
    let file_header = parse_pe64_file_header(file);
    let optional_header = parse_pe64_optional_header(file);
    let section_details = parse_pe64_section_details(file, data);
    let section_stats = calc_section_stats(&section_details);
    let imports = parse_pe64_imports(file);
    let import_info = calc_import_info(&imports);
    let exceptions = parse_pe64_exceptions(file);
    let bound_imports = parse_pe64_bound_imports(file);
    let delay_imports = parse_pe64_delay_imports(file);
    let dotnet_metadata = parse_pe64_dotnet_metadata(file);
    let resources = parse_pe64_resources(file);
    let nt_headers = parse_nt_headers(data);
    let resource_strings = parse_resource_strings(data, &resources);
    let dotnet_stream_details = parse_dotnet_stream_details(data, &dotnet_metadata);
    let dotnet_metadata_table = parse_dotnet_metadata_table(data, &dotnet_metadata);
    PeView {
        imports,
        exports: parse_pe64_exports(file),
        resources,
        overlay_offset: calc_overlay_offset(data),
        overlay_size: calc_overlay_size(data),
        dotnet: parse_dotnet(dd),
        manifest: parse_pe64_manifest(file),
        version_info: parse_pe64_version_info(file),
        tls_callbacks: parse_tls(dd),
        has_rich_header: check_rich_header(data),
        data_directories: parse_data_directories(dd),
        debug_entries: parse_pe64_debug(file),
        reloc_blocks: parse_pe64_relocs(file),
        load_config: parse_pe64_load_config(file),
        certificates: parse_pe64_certificates(file),
        dos_header,
        dos_stub,
        file_header,
        optional_header,
        section_details,
        section_stats,
        import_info,
        exceptions,
        bound_imports,
        delay_imports,
        dotnet_metadata,
        nt_headers,
        resource_strings,
        dotnet_stream_details,
        dotnet_metadata_table,
    }
}

/// Build PE32 view.
fn build_pe32_view(file: &pelite::pe32::PeFile<'_>, data: &[u8]) -> PeView {
    let dd = file.data_directory();
    let dos_header = parse_dos_header(data);
    let dos_stub = parse_dos_stub(data);
    let file_header = parse_pe32_file_header(file);
    let optional_header = parse_pe32_optional_header(file);
    let section_details = parse_pe32_section_details(file, data);
    let section_stats = calc_section_stats(&section_details);
    let imports = parse_pe32_imports(file);
    let import_info = calc_import_info(&imports);
    let exceptions = parse_pe32_exceptions(file);
    let bound_imports = parse_pe32_bound_imports(file);
    let delay_imports = parse_pe32_delay_imports(file);
    let dotnet_metadata = parse_pe32_dotnet_metadata(file);
    let resources = parse_pe32_resources(file);
    let nt_headers = parse_nt_headers(data);
    let resource_strings = parse_resource_strings(data, &resources);
    let dotnet_stream_details = parse_dotnet_stream_details(data, &dotnet_metadata);
    let dotnet_metadata_table = parse_dotnet_metadata_table(data, &dotnet_metadata);
    PeView {
        imports,
        exports: parse_pe32_exports(file),
        resources,
        overlay_offset: calc_overlay_offset(data),
        overlay_size: calc_overlay_size(data),
        dotnet: parse_dotnet(dd),
        manifest: parse_pe32_manifest(file),
        version_info: parse_pe32_version_info(file),
        tls_callbacks: parse_tls(dd),
        has_rich_header: check_rich_header(data),
        data_directories: parse_data_directories(dd),
        debug_entries: parse_pe32_debug(file),
        reloc_blocks: parse_pe32_relocs(file),
        load_config: parse_pe32_load_config(file),
        certificates: parse_pe32_certificates(file),
        dos_header,
        dos_stub,
        file_header,
        optional_header,
        section_details,
        section_stats,
        import_info,
        exceptions,
        bound_imports,
        delay_imports,
        dotnet_metadata,
        nt_headers,
        resource_strings,
        dotnet_stream_details,
        dotnet_metadata_table,
    }
}

/// Calculate overlay offset from raw data (find last section end).
fn calc_overlay_offset(data: &[u8]) -> u64 {
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        return 0;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 24 > data.len() {
        return 0;
    }
    // COFF header: NumberOfSections at e_lfanew + 6
    let num_sections = u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]) as usize;
    // SizeOfOptionalHeader at e_lfanew + 20
    let opt_size = u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]) as usize;
    // Section headers start after optional header
    let sec_start = e_lfanew + 24 + opt_size;
    let mut max_end: u64 = 0;
    for i in 0..num_sections {
        let off = sec_start + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let raw_off = u32::from_le_bytes([
            data[off + 20],
            data[off + 21],
            data[off + 22],
            data[off + 23],
        ]) as u64;
        let raw_size = u32::from_le_bytes([
            data[off + 16],
            data[off + 17],
            data[off + 18],
            data[off + 19],
        ]) as u64;
        let end = raw_off + raw_size;
        if end > max_end {
            max_end = end;
        }
    }
    max_end
}

/// Calculate overlay size.
fn calc_overlay_size(data: &[u8]) -> u64 {
    let off = calc_overlay_offset(data);
    if off >= data.len() as u64 {
        return 0;
    }
    data.len() as u64 - off
}

// =========================================================================
// PE TOOLS: DosStub and Overlay dump/remove/add operations.
// =========================================================================

/// Dump DOS stub bytes (between DOS header and PE signature).
pub fn dump_dos_stub(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a valid MZ file".into());
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew > data.len() {
        return Err("Invalid e_lfanew".into());
    }
    // DOS stub is from offset 0x40 (end of DOS header) to e_lfanew.
    let stub_start = 0x40;
    if e_lfanew <= stub_start {
        return Ok(Vec::new()); // No DOS stub
    }
    Ok(data[stub_start..e_lfanew].to_vec())
}

/// Remove DOS stub from a PE file (write modified file).
pub fn remove_dos_stub(path: &str) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a valid MZ file".into());
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    let stub_start = 0x40;
    if e_lfanew <= stub_start {
        return Err("No DOS stub to remove".into());
    }
    // Build new file: header[0..0x40] + PE data[e_lfanew..]
    let mut new_data = data[..stub_start].to_vec();
    new_data.extend_from_slice(&data[e_lfanew..]);
    // Update e_lfanew to point to stub_start.
    let new_lfanew = stub_start as u32;
    new_data[0x3C] = new_lfanew as u8;
    new_data[0x3D] = (new_lfanew >> 8) as u8;
    new_data[0x3E] = (new_lfanew >> 16) as u8;
    new_data[0x3F] = (new_lfanew >> 24) as u8;
    // Backup original.
    let backup = format!("{}.bak", path);
    std::fs::copy(path, &backup).map_err(|e| e.to_string())?;
    std::fs::write(path, &new_data).map_err(|e| e.to_string())?;
    Ok(())
}

/// Add DOS stub to a PE file (write modified file).
pub fn add_dos_stub(path: &str, stub_bytes: &[u8]) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a valid MZ file".into());
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    let stub_start = 0x40;
    // Build new file: header[0..0x40] + stub + PE data[e_lfanew..]
    let mut new_data = data[..stub_start].to_vec();
    new_data.extend_from_slice(stub_bytes);
    new_data.extend_from_slice(&data[e_lfanew..]);
    // Update e_lfanew.
    let new_lfanew = (stub_start + stub_bytes.len()) as u32;
    new_data[0x3C] = new_lfanew as u8;
    new_data[0x3D] = (new_lfanew >> 8) as u8;
    new_data[0x3E] = (new_lfanew >> 16) as u8;
    new_data[0x3F] = (new_lfanew >> 24) as u8;
    // Backup original.
    let backup = format!("{}.bak", path);
    std::fs::copy(path, &backup).map_err(|e| e.to_string())?;
    std::fs::write(path, &new_data).map_err(|e| e.to_string())?;
    Ok(())
}

/// Dump overlay bytes (data after last section's raw data).
pub fn dump_overlay(path: &str) -> Result<Vec<u8>, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let off = calc_overlay_offset(&data);
    if off >= data.len() as u64 {
        return Err("No overlay present".into());
    }
    Ok(data[off as usize..].to_vec())
}

/// Remove overlay from a PE file (truncate after last section).
pub fn remove_overlay(path: &str) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let off = calc_overlay_offset(&data);
    if off >= data.len() as u64 {
        return Err("No overlay to remove".into());
    }
    // Backup original.
    let backup = format!("{}.bak", path);
    std::fs::copy(path, &backup).map_err(|e| e.to_string())?;
    // Truncate file at overlay offset.
    let new_data = &data[..off as usize];
    std::fs::write(path, new_data).map_err(|e| e.to_string())?;
    Ok(())
}

/// Add overlay to a PE file (append data after last section).
pub fn add_overlay(path: &str, overlay_bytes: &[u8]) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    // Backup original.
    let backup = format!("{}.bak", path);
    std::fs::copy(path, &backup).map_err(|e| e.to_string())?;
    // Append overlay.
    let mut new_data = data.clone();
    new_data.extend_from_slice(overlay_bytes);
    std::fs::write(path, &new_data).map_err(|e| e.to_string())?;
    Ok(())
}

/// Parse .NET CLR header from data directory (index 14).
fn parse_dotnet(dd: &[pelite::image::IMAGE_DATA_DIRECTORY]) -> Option<PeDotNetInfo> {
    dd.get(14).filter(|d| d.Size != 0).map(|d| PeDotNetInfo {
        has_clr: true,
        clr_rva: d.VirtualAddress,
        clr_size: d.Size,
    })
}

/// Parse TLS directory from data directory (index 9).
fn parse_tls(dd: &[pelite::image::IMAGE_DATA_DIRECTORY]) -> Vec<u64> {
    if let Some(tls_dir) = dd.get(9)
        && tls_dir.Size != 0
    {
        return vec![tls_dir.VirtualAddress as u64];
    }
    Vec::new()
}

// --- PE64 parsers ---

fn parse_pe64_imports(file: &pelite::pe64::PeFile<'_>) -> Vec<PeImportEntry> {
    let mut entries = Vec::new();
    if let Ok(imports) = file.imports() {
        for desc in imports {
            let dll = desc
                .dll_name()
                .map(|n| String::from_utf8_lossy(n.c_str()).to_string())
                .unwrap_or_else(|_| "?".to_string());
            if let Ok(int) = desc.int() {
                for import in int.flatten() {
                    let name = match import {
                        pelite::pe64::imports::Import::ByName { name, .. } => name.to_string(),
                        pelite::pe64::imports::Import::ByOrdinal { ord, .. } => {
                            format!("#{}", ord)
                        }
                    };
                    entries.push(PeImportEntry {
                        dll: dll.clone(),
                        name,
                    });
                }
            }
        }
    }
    entries
}

fn parse_pe64_exports(file: &pelite::pe64::PeFile<'_>) -> Vec<PeExportEntry> {
    let mut entries = Vec::new();
    if let Ok(exports) = file.exports()
        && let Ok(by) = exports.by()
    {
        let names = by.names();
        let name_indices = by.name_indices();
        let functions = by.functions();
        let ordinal_base = exports.ordinal_base();
        for (i, &name_rva) in names.iter().enumerate() {
            if name_rva == 0 {
                continue;
            }
            // Read export name from image bytes at name_rva (safe read).
            let name = read_cstr_at(file.image(), name_rva as usize);
            if let Some(&idx) = name_indices.get(i)
                && let Some(&func_rva) = functions.get(idx as usize)
            {
                entries.push(PeExportEntry {
                    name,
                    ordinal: idx + ordinal_base,
                    rva: func_rva,
                });
            }
        }
    }
    entries
}

fn parse_pe64_resources(file: &pelite::pe64::PeFile<'_>) -> Vec<PeResourceNode> {
    let mut nodes = Vec::new();
    if let Ok(resources) = file.resources()
        && let Ok(root) = resources.root()
    {
        for entry in root.entries() {
            let id = resource_entry_id(&entry);
            let name = resource_type_name(id).to_string();
            let children = parse_resource_children(&entry);
            nodes.push(PeResourceNode {
                id,
                name,
                data_size: None,
                children,
            });
        }
    }
    nodes
}

/// Get the resource ID from a DirectoryEntry.
fn resource_entry_id(entry: &pelite::resources::DirectoryEntry<'_>) -> u32 {
    if let Ok(name) = entry.name() {
        match name {
            pelite::resources::Name::Id(id) => id,
            pelite::resources::Name::Str(s) => s.parse::<u32>().unwrap_or(0),
            pelite::resources::Name::Wide(_) => 0,
        }
    } else {
        0
    }
}

/// Recursively parse resource directory children.
fn parse_resource_children(entry: &pelite::resources::DirectoryEntry<'_>) -> Vec<PeResourceNode> {
    let mut children = Vec::new();
    if let Ok(entry_result) = entry.entry() {
        match entry_result {
            pelite::resources::Entry::Directory(dir) => {
                for sub_entry in dir.entries() {
                    let id = resource_entry_id(&sub_entry);
                    let (data_size, sub_children) = match sub_entry.entry() {
                        Ok(pelite::resources::Entry::DataEntry(data)) => {
                            (Some(data.size() as u32), Vec::new())
                        }
                        Ok(pelite::resources::Entry::Directory(_)) => {
                            (None, parse_resource_children(&sub_entry))
                        }
                        Err(_) => (None, Vec::new()),
                    };
                    children.push(PeResourceNode {
                        id,
                        name: format!("0x{:08X}", id),
                        data_size,
                        children: sub_children,
                    });
                }
            }
            pelite::resources::Entry::DataEntry(data) => {
                children.push(PeResourceNode {
                    id: 0,
                    name: "Data".to_string(),
                    data_size: Some(data.size() as u32),
                    children: Vec::new(),
                });
            }
        }
    }
    children
}

fn parse_pe64_manifest(file: &pelite::pe64::PeFile<'_>) -> Option<String> {
    if let Ok(resources) = file.resources()
        && let Ok(manifest) = resources.manifest()
    {
        return Some(manifest.to_string());
    }
    None
}

fn parse_pe64_version_info(file: &pelite::pe64::PeFile<'_>) -> Vec<PeVersionEntry> {
    let mut entries = Vec::new();
    if let Ok(resources) = file.resources()
        && let Ok(version_info) = resources.version_info()
    {
        let vs = version_info.file_info();
        for string_map in vs.strings.values() {
            let pairs: Vec<(String, String)> = string_map
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            entries.push(PeVersionEntry { entries: pairs });
        }
    }
    entries
}

// --- PE32 parsers ---

fn parse_pe32_imports(file: &pelite::pe32::PeFile<'_>) -> Vec<PeImportEntry> {
    let mut entries = Vec::new();
    if let Ok(imports) = file.imports() {
        for desc in imports {
            let dll = desc
                .dll_name()
                .map(|n| String::from_utf8_lossy(n.c_str()).to_string())
                .unwrap_or_else(|_| "?".to_string());
            if let Ok(int) = desc.int() {
                for import in int.flatten() {
                    let name = match import {
                        pelite::pe32::imports::Import::ByName { name, .. } => name.to_string(),
                        pelite::pe32::imports::Import::ByOrdinal { ord, .. } => {
                            format!("#{}", ord)
                        }
                    };
                    entries.push(PeImportEntry {
                        dll: dll.clone(),
                        name,
                    });
                }
            }
        }
    }
    entries
}

fn parse_pe32_exports(file: &pelite::pe32::PeFile<'_>) -> Vec<PeExportEntry> {
    let mut entries = Vec::new();
    if let Ok(exports) = file.exports()
        && let Ok(by) = exports.by()
    {
        let names = by.names();
        let name_indices = by.name_indices();
        let functions = by.functions();
        let ordinal_base = exports.ordinal_base();
        for (i, &name_rva) in names.iter().enumerate() {
            if name_rva == 0 {
                continue;
            }
            let name = read_cstr_at(file.image(), name_rva as usize);
            if let Some(&idx) = name_indices.get(i)
                && let Some(&func_rva) = functions.get(idx as usize)
            {
                entries.push(PeExportEntry {
                    name,
                    ordinal: idx + ordinal_base,
                    rva: func_rva,
                });
            }
        }
    }
    entries
}

fn parse_pe32_resources(file: &pelite::pe32::PeFile<'_>) -> Vec<PeResourceNode> {
    let mut nodes = Vec::new();
    if let Ok(resources) = file.resources()
        && let Ok(root) = resources.root()
    {
        for entry in root.entries() {
            let id = resource_entry_id(&entry);
            let name = resource_type_name(id).to_string();
            let children = parse_resource_children(&entry);
            nodes.push(PeResourceNode {
                id,
                name,
                data_size: None,
                children,
            });
        }
    }
    nodes
}

fn parse_pe32_manifest(file: &pelite::pe32::PeFile<'_>) -> Option<String> {
    if let Ok(resources) = file.resources()
        && let Ok(manifest) = resources.manifest()
    {
        return Some(manifest.to_string());
    }
    None
}

fn parse_pe32_version_info(file: &pelite::pe32::PeFile<'_>) -> Vec<PeVersionEntry> {
    let mut entries = Vec::new();
    if let Ok(resources) = file.resources()
        && let Ok(version_info) = resources.version_info()
    {
        let vs = version_info.file_info();
        for string_map in vs.strings.values() {
            let pairs: Vec<(String, String)> = string_map
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            entries.push(PeVersionEntry { entries: pairs });
        }
    }
    entries
}

/// Safely read a NUL-terminated C string from a byte slice at the given offset.
fn read_cstr_at(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(data.len());
    String::from_utf8_lossy(&data[offset..end]).to_string()
}

/// Check for Rich Header presence by looking for the "Rich" signature.
fn check_rich_header(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew > data.len() {
        return false;
    }
    // Search from DOS stub (0x40) up to e_lfanew (exclusive), leaving room
    // for the 4-byte "Rich" signature.
    let search_end = e_lfanew.saturating_sub(4).max(0x44);
    for i in 0x40..search_end {
        if &data[i..i + 4] == b"Rich" {
            return true;
        }
    }
    false
}

/// Get human-readable name for a standard resource type ID.
fn resource_type_name(id: u32) -> &'static str {
    match id {
        1 => "RT_CURSOR",
        2 => "RT_BITMAP",
        3 => "RT_ICON",
        4 => "RT_MENU",
        5 => "RT_DIALOG",
        6 => "RT_STRING",
        7 => "RT_FONTDIR",
        8 => "RT_FONT",
        9 => "RT_ACCELERATOR",
        10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE",
        12 => "RT_GROUP_CURSOR",
        14 => "RT_GROUP_ICON",
        16 => "RT_VERSION",
        17 => "RT_DLGINCLUDE",
        19 => "RT_PLUGPLAY",
        20 => "RT_VXD",
        21 => "RT_ANICURSOR",
        22 => "RT_ANIICON",
        23 => "RT_HTML",
        24 => "RT_MANIFEST",
        _ => "RT_UNKNOWN",
    }
}

/// Data directory names (upstream IMAGE_DIRECTORY_ENTRY_*).
const DATA_DIR_NAMES: [&str; 16] = [
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "CERTIFICATE",
    "BASE_RELOC",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBAL_PTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "CLR_RUNTIME",
    "RESERVED",
];

/// Parse data directory entries from the PE data directory array.
fn parse_data_directories(dd: &[pelite::image::IMAGE_DATA_DIRECTORY]) -> Vec<PeDataDirectoryEntry> {
    dd.iter()
        .enumerate()
        .map(|(i, d)| PeDataDirectoryEntry {
            name: DATA_DIR_NAMES
                .get(i)
                .copied()
                .unwrap_or("UNKNOWN")
                .to_string(),
            index: i as u32,
            rva: d.VirtualAddress,
            size: d.Size,
        })
        .collect()
}

/// Parse PE64 debug directory.
fn parse_pe64_debug(file: &pelite::pe64::PeFile<'_>) -> Vec<PeDebugEntry> {
    let Ok(debug) = pelite::pe64::Pe::debug(*file) else {
        return Vec::new();
    };
    debug
        .image()
        .iter()
        .map(|d| PeDebugEntry {
            debug_type: debug_type_name(d.Type),
            debug_type_val: d.Type,
            size_of_data: d.SizeOfData,
            address_of_raw_data: d.AddressOfRawData,
            pointer_to_raw_data: d.PointerToRawData,
            pdb_file_name: None,
        })
        .collect()
}

/// Parse PE32 debug directory.
fn parse_pe32_debug(file: &pelite::pe32::PeFile<'_>) -> Vec<PeDebugEntry> {
    let Ok(debug) = pelite::pe32::Pe::debug(*file) else {
        return Vec::new();
    };
    debug
        .image()
        .iter()
        .map(|d| PeDebugEntry {
            debug_type: debug_type_name(d.Type),
            debug_type_val: d.Type,
            size_of_data: d.SizeOfData,
            address_of_raw_data: d.AddressOfRawData,
            pointer_to_raw_data: d.PointerToRawData,
            pdb_file_name: None,
        })
        .collect()
}

/// Convert debug type to name.
fn debug_type_name(dt: u32) -> String {
    match dt {
        0 => "UNKNOWN".to_string(),
        1 => "COFF".to_string(),
        2 => "CODEVIEW".to_string(),
        3 => "FPO".to_string(),
        4 => "MISC".to_string(),
        5 => "EXCEPTION".to_string(),
        6 => "FIXUP".to_string(),
        7 => "OMAP_TO_SRC".to_string(),
        8 => "OMAP_FROM_SRC".to_string(),
        9 => "BORLAND".to_string(),
        10 => "RESERVED".to_string(),
        11 => "CLSID".to_string(),
        12 => "VC_FEATURE".to_string(),
        13 => "POGO".to_string(),
        14 => "ILTCG".to_string(),
        15 => "MPX".to_string(),
        16 => "REPRO".to_string(),
        _ => format!("0x{:08x}", dt),
    }
}

/// Parse PE64 base relocation blocks.
fn parse_pe64_relocs(file: &pelite::pe64::PeFile<'_>) -> Vec<PeRelocBlock> {
    let Ok(relocs) = pelite::pe64::Pe::base_relocs(*file) else {
        return Vec::new();
    };
    relocs
        .iter_blocks()
        .map(|block| {
            let img = block.image();
            PeRelocBlock {
                virtual_address: img.VirtualAddress,
                block_size: img.SizeOfBlock,
                count: block.words().len() as u32,
            }
        })
        .collect()
}

/// Parse PE32 base relocation blocks.
fn parse_pe32_relocs(file: &pelite::pe32::PeFile<'_>) -> Vec<PeRelocBlock> {
    let Ok(relocs) = pelite::pe32::Pe::base_relocs(*file) else {
        return Vec::new();
    };
    relocs
        .iter_blocks()
        .map(|block| {
            let img = block.image();
            PeRelocBlock {
                virtual_address: img.VirtualAddress,
                block_size: img.SizeOfBlock,
                count: block.words().len() as u32,
            }
        })
        .collect()
}

/// Parse PE64 load config.
fn parse_pe64_load_config(file: &pelite::pe64::PeFile<'_>) -> Option<PeLoadConfig> {
    let Ok(lc) = pelite::pe64::Pe::load_config(*file) else {
        return None;
    };
    let img = lc.image();
    Some(PeLoadConfig {
        size: img.Size,
        security_cookie: img.SecurityCookie,
        se_handler_table: img.SEHandlerTable,
        se_handler_count: img.SEHandlerCount,
    })
}

/// Parse PE32 load config.
fn parse_pe32_load_config(file: &pelite::pe32::PeFile<'_>) -> Option<PeLoadConfig> {
    let Ok(lc) = pelite::pe32::Pe::load_config(*file) else {
        return None;
    };
    let img = lc.image();
    Some(PeLoadConfig {
        size: img.Size,
        security_cookie: img.SecurityCookie as u64,
        se_handler_table: img.SEHandlerTable as u64,
        se_handler_count: img.SEHandlerCount as u64,
    })
}

/// Parse PE64 certificate (security directory).
fn parse_pe64_certificates(file: &pelite::pe64::PeFile<'_>) -> Vec<PeCertificate> {
    let Ok(security) = pelite::pe64::Pe::security(*file) else {
        return Vec::new();
    };
    vec![PeCertificate {
        certificate_type: security.certificate_type(),
        data_length: security.certificate_data().len(),
        has_data: !security.certificate_data().is_empty(),
    }]
}

/// Parse PE32 certificate (security directory).
fn parse_pe32_certificates(file: &pelite::pe32::PeFile<'_>) -> Vec<PeCertificate> {
    let Ok(security) = pelite::pe32::Pe::security(*file) else {
        return Vec::new();
    };
    vec![PeCertificate {
        certificate_type: security.certificate_type(),
        data_length: security.certificate_data().len(),
        has_data: !security.certificate_data().is_empty(),
    }]
}

// =========================================================================
// PE header detailed parsing functions
// =========================================================================

/// Parse IMAGE_DOS_HEADER (31 fields) from raw data using safe byte reads.
fn parse_dos_header(data: &[u8]) -> Vec<PeDosHeaderField> {
    if data.len() < 64 {
        return Vec::new();
    }
    let u16le = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);
    let u32le =
        |off: usize| u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    vec![
        PeDosHeaderField {
            name: "e_magic".into(),
            value: format!("0x{:04X}", u16le(0)),
            description: Some("MZ signature".into()),
        },
        PeDosHeaderField {
            name: "e_cblp".into(),
            value: format!("0x{:04X}", u16le(2)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_cp".into(),
            value: format!("0x{:04X}", u16le(4)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_crlc".into(),
            value: format!("0x{:04X}", u16le(6)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_cparhdr".into(),
            value: format!("0x{:04X}", u16le(8)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_minalloc".into(),
            value: format!("0x{:04X}", u16le(10)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_maxalloc".into(),
            value: format!("0x{:04X}", u16le(12)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_ss".into(),
            value: format!("0x{:04X}", u16le(14)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_sp".into(),
            value: format!("0x{:04X}", u16le(16)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_csum".into(),
            value: format!("0x{:04X}", u16le(18)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_ip".into(),
            value: format!("0x{:04X}", u16le(20)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_cs".into(),
            value: format!("0x{:04X}", u16le(22)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_lfarlc".into(),
            value: format!("0x{:04X}", u16le(24)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_ovno".into(),
            value: format!("0x{:04X}", u16le(26)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res[0]".into(),
            value: format!("0x{:04X}", u16le(28)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res[1]".into(),
            value: format!("0x{:04X}", u16le(30)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res[2]".into(),
            value: format!("0x{:04X}", u16le(32)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res[3]".into(),
            value: format!("0x{:04X}", u16le(34)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_oemid".into(),
            value: format!("0x{:04X}", u16le(36)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_oeminfo".into(),
            value: format!("0x{:04X}", u16le(38)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res2[0]".into(),
            value: format!("0x{:04X}", u16le(40)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res2[1]".into(),
            value: format!("0x{:04X}", u16le(42)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res2[2]".into(),
            value: format!("0x{:04X}", u16le(44)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res2[3]".into(),
            value: format!("0x{:04X}", u16le(46)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res2[4]".into(),
            value: format!("0x{:04X}", u16le(48)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res2[5]".into(),
            value: format!("0x{:04X}", u16le(50)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res2[6]".into(),
            value: format!("0x{:04X}", u16le(52)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res2[7]".into(),
            value: format!("0x{:04X}", u16le(54)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res2[8]".into(),
            value: format!("0x{:04X}", u16le(56)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_res2[9]".into(),
            value: format!("0x{:04X}", u16le(58)),
            description: None,
        },
        PeDosHeaderField {
            name: "e_lfanew".into(),
            value: format!("0x{:08X}", u32le(60)),
            description: Some("PE header offset".into()),
        },
    ]
}

/// Parse DOS stub (bytes between DOS header end and PE signature).
fn parse_dos_stub(data: &[u8]) -> Option<PeDosStub> {
    if data.len() < 64 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
    let stub_start = 64usize; // sizeof(IMAGE_DOS_HEADER)
    let stub_end = e_lfanew as usize;
    if stub_end <= stub_start || stub_end > data.len() {
        return None;
    }
    let stub = &data[stub_start..stub_end];
    let hex_dump: String = stub
        .chunks(16)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n");
    Some(PeDosStub {
        offset: stub_start as u32,
        size: (stub_end - stub_start) as u32,
        hex_dump,
    })
}

/// Parse PE64 IMAGE_FILE_HEADER.
fn parse_pe64_file_header(file: &pelite::pe64::PeFile<'_>) -> Option<PeFileHeader> {
    let fh = file.file_header();
    Some(PeFileHeader {
        machine: pe_machine_name(fh.Machine),
        machine_val: fh.Machine,
        number_of_sections: fh.NumberOfSections,
        time_date_stamp: fh.TimeDateStamp,
        pointer_to_symbol_table: fh.PointerToSymbolTable,
        number_of_symbols: fh.NumberOfSymbols,
        size_of_optional_header: fh.SizeOfOptionalHeader,
        characteristics: pe_characteristics_string(fh.Characteristics),
        characteristics_val: fh.Characteristics,
    })
}

/// Parse PE32 IMAGE_FILE_HEADER.
fn parse_pe32_file_header(file: &pelite::pe32::PeFile<'_>) -> Option<PeFileHeader> {
    let fh = file.file_header();
    Some(PeFileHeader {
        machine: pe_machine_name(fh.Machine),
        machine_val: fh.Machine,
        number_of_sections: fh.NumberOfSections,
        time_date_stamp: fh.TimeDateStamp,
        pointer_to_symbol_table: fh.PointerToSymbolTable,
        number_of_symbols: fh.NumberOfSymbols,
        size_of_optional_header: fh.SizeOfOptionalHeader,
        characteristics: pe_characteristics_string(fh.Characteristics),
        characteristics_val: fh.Characteristics,
    })
}

/// Parse PE64 IMAGE_OPTIONAL_HEADER.
fn parse_pe64_optional_header(file: &pelite::pe64::PeFile<'_>) -> Option<PeOptionalHeader> {
    let oh = file.optional_header();
    Some(PeOptionalHeader {
        is64: true,
        magic: oh.Magic,
        magic_str: "PE32+".into(),
        major_linker_version: oh.LinkerVersion.Major,
        minor_linker_version: oh.LinkerVersion.Minor,
        size_of_code: oh.SizeOfCode,
        size_of_initialized_data: oh.SizeOfInitializedData,
        size_of_uninitialized_data: oh.SizeOfUninitializedData,
        address_of_entry_point: oh.AddressOfEntryPoint,
        base_of_code: oh.BaseOfCode,
        base_of_data: None,
        image_base: oh.ImageBase,
        section_alignment: oh.SectionAlignment,
        file_alignment: oh.FileAlignment,
        major_operating_system_version: oh.OperatingSystemVersion.Major,
        minor_operating_system_version: oh.OperatingSystemVersion.Minor,
        major_image_version: oh.ImageVersion.Major,
        minor_image_version: oh.ImageVersion.Minor,
        major_subsystem_version: oh.SubsystemVersion.Major,
        minor_subsystem_version: oh.SubsystemVersion.Minor,
        win32_version_value: oh.Win32VersionValue,
        size_of_image: oh.SizeOfImage,
        size_of_headers: oh.SizeOfHeaders,
        check_sum: oh.CheckSum,
        subsystem: pe_subsystem_name(oh.Subsystem),
        subsystem_val: oh.Subsystem,
        dll_characteristics: pe_dll_characteristics_string(oh.DllCharacteristics),
        dll_characteristics_val: oh.DllCharacteristics,
        size_of_stack_reserve: oh.SizeOfStackReserve,
        size_of_stack_commit: oh.SizeOfStackCommit,
        size_of_heap_reserve: oh.SizeOfHeapReserve,
        size_of_heap_commit: oh.SizeOfHeapCommit,
        loader_flags: oh.LoaderFlags,
        number_of_rva_and_sizes: oh.NumberOfRvaAndSizes,
    })
}

/// Parse PE32 IMAGE_OPTIONAL_HEADER.
fn parse_pe32_optional_header(file: &pelite::pe32::PeFile<'_>) -> Option<PeOptionalHeader> {
    let oh = file.optional_header();
    Some(PeOptionalHeader {
        is64: false,
        magic: oh.Magic,
        magic_str: "PE32".into(),
        major_linker_version: oh.LinkerVersion.Major,
        minor_linker_version: oh.LinkerVersion.Minor,
        size_of_code: oh.SizeOfCode,
        size_of_initialized_data: oh.SizeOfInitializedData,
        size_of_uninitialized_data: oh.SizeOfUninitializedData,
        address_of_entry_point: oh.AddressOfEntryPoint,
        base_of_code: oh.BaseOfCode,
        base_of_data: Some(oh.BaseOfData),
        image_base: oh.ImageBase as u64,
        section_alignment: oh.SectionAlignment,
        file_alignment: oh.FileAlignment,
        major_operating_system_version: oh.OperatingSystemVersion.Major,
        minor_operating_system_version: oh.OperatingSystemVersion.Minor,
        major_image_version: oh.ImageVersion.Major,
        minor_image_version: oh.ImageVersion.Minor,
        major_subsystem_version: oh.SubsystemVersion.Major,
        minor_subsystem_version: oh.SubsystemVersion.Minor,
        win32_version_value: oh.Win32VersionValue,
        size_of_image: oh.SizeOfImage,
        size_of_headers: oh.SizeOfHeaders,
        check_sum: oh.CheckSum,
        subsystem: pe_subsystem_name(oh.Subsystem),
        subsystem_val: oh.Subsystem,
        dll_characteristics: pe_dll_characteristics_string(oh.DllCharacteristics),
        dll_characteristics_val: oh.DllCharacteristics,
        size_of_stack_reserve: oh.SizeOfStackReserve as u64,
        size_of_stack_commit: oh.SizeOfStackCommit as u64,
        size_of_heap_reserve: oh.SizeOfHeapReserve as u64,
        size_of_heap_commit: oh.SizeOfHeapCommit as u64,
        loader_flags: oh.LoaderFlags,
        number_of_rva_and_sizes: oh.NumberOfRvaAndSizes,
    })
}

/// Parse PE64 section details with flags and entropy.
fn parse_pe64_section_details(
    file: &pelite::pe64::PeFile<'_>,
    data: &[u8],
) -> Vec<PeSectionDetail> {
    file.section_headers()
        .iter()
        .map(|sec| {
            let name = String::from_utf8_lossy(sec.name_bytes())
                .trim_end_matches('\0')
                .to_string();
            let entropy = section_entropy(data, sec.PointerToRawData, sec.SizeOfRawData);
            PeSectionDetail {
                name,
                virtual_size: sec.VirtualSize,
                virtual_address: sec.VirtualAddress,
                size_of_raw_data: sec.SizeOfRawData,
                pointer_to_raw_data: sec.PointerToRawData,
                pointer_to_relocations: sec.PointerToRelocations,
                pointer_to_linenumbers: sec.PointerToLinenumbers,
                number_of_relocations: sec.NumberOfRelocations,
                number_of_linenumbers: sec.NumberOfLinenumbers,
                characteristics: pe_section_chars_string(sec.Characteristics),
                characteristics_val: sec.Characteristics,
                entropy,
            }
        })
        .collect()
}

/// Parse PE32 section details with flags and entropy.
fn parse_pe32_section_details(
    file: &pelite::pe32::PeFile<'_>,
    data: &[u8],
) -> Vec<PeSectionDetail> {
    file.section_headers()
        .iter()
        .map(|sec| {
            let name = String::from_utf8_lossy(sec.name_bytes())
                .trim_end_matches('\0')
                .to_string();
            let entropy = section_entropy(data, sec.PointerToRawData, sec.SizeOfRawData);
            PeSectionDetail {
                name,
                virtual_size: sec.VirtualSize,
                virtual_address: sec.VirtualAddress,
                size_of_raw_data: sec.SizeOfRawData,
                pointer_to_raw_data: sec.PointerToRawData,
                pointer_to_relocations: sec.PointerToRelocations,
                pointer_to_linenumbers: sec.PointerToLinenumbers,
                number_of_relocations: sec.NumberOfRelocations,
                number_of_linenumbers: sec.NumberOfLinenumbers,
                characteristics: pe_section_chars_string(sec.Characteristics),
                characteristics_val: sec.Characteristics,
                entropy,
            }
        })
        .collect()
}

/// Calculate Shannon entropy of a section's raw data.
fn section_entropy(data: &[u8], pointer_to_raw_data: u32, size_of_raw_data: u32) -> Option<f64> {
    let start = pointer_to_raw_data as usize;
    let size = size_of_raw_data as usize;
    if size == 0 || start + size > data.len() {
        return None;
    }
    let section_data = &data[start..start + size];
    Some(shannon_entropy(section_data))
}

/// Calculate Shannon entropy of a byte slice.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Calculate section statistics from section details.
fn calc_section_stats(sections: &[PeSectionDetail]) -> Option<PeSectionStats> {
    if sections.is_empty() {
        return None;
    }
    let total_sections = sections.len() as u32;
    let total_virtual_size: u64 = sections.iter().map(|s| s.virtual_size as u64).sum();
    let total_raw_size: u64 = sections.iter().map(|s| s.size_of_raw_data as u64).sum();
    let entropies: Vec<f64> = sections.iter().filter_map(|s| s.entropy).collect();
    let (min_entropy, max_entropy, avg_entropy) = if entropies.is_empty() {
        (None, None, None)
    } else {
        let min = entropies.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = entropies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = entropies.iter().sum::<f64>() / entropies.len() as f64;
        (Some(min), Some(max), Some(avg))
    };
    Some(PeSectionStats {
        total_sections,
        total_virtual_size,
        total_raw_size,
        min_entropy,
        max_entropy,
        avg_entropy,
    })
}

/// Calculate import info summary from import entries.
fn calc_import_info(imports: &[PeImportEntry]) -> Option<PeImportInfo> {
    if imports.is_empty() {
        return None;
    }
    let mut dll_map: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for imp in imports {
        *dll_map.entry(imp.dll.clone()).or_insert(0) += 1;
    }
    let dlls: Vec<PeImportDllSummary> = dll_map
        .iter()
        .map(|(name, &count)| PeImportDllSummary {
            dll_name: name.clone(),
            function_count: count,
        })
        .collect();
    let total_dlls = dlls.len() as u32;
    let total_functions = imports.len() as u32;
    Some(PeImportInfo {
        total_dlls,
        total_functions,
        dlls,
    })
}

/// Parse PE64 exception table.
fn parse_pe64_exceptions(file: &pelite::pe64::PeFile<'_>) -> Vec<PeExceptionEntry> {
    let Ok(exc) = pelite::pe64::Pe::exception(*file) else {
        return Vec::new();
    };
    exc.image()
        .iter()
        .map(|e| PeExceptionEntry {
            begin_address: e.BeginAddress,
            end_address: e.EndAddress,
            unwind_info_address: e.UnwindData,
        })
        .collect()
}

/// Parse PE32 exception table.
fn parse_pe32_exceptions(file: &pelite::pe32::PeFile<'_>) -> Vec<PeExceptionEntry> {
    let Ok(exc) = pelite::pe32::Pe::exception(*file) else {
        return Vec::new();
    };
    exc.image()
        .iter()
        .map(|e| PeExceptionEntry {
            begin_address: e.BeginAddress,
            end_address: e.EndAddress,
            unwind_info_address: e.UnwindData,
        })
        .collect()
}

/// Parse PE64 bound imports.
fn parse_pe64_bound_imports(file: &pelite::pe64::PeFile<'_>) -> Vec<PeBoundImportEntry> {
    let dd = file.data_directory();
    let bound_dir = &dd[pelite::image::IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    if bound_dir.Size == 0 {
        return Vec::new();
    }
    // Bound imports are at file offset (not RVA), pointed to by the directory's VirtualAddress.
    let offset = bound_dir.VirtualAddress as usize;
    let data = file.image();
    if offset + 8 > data.len() {
        return Vec::new();
    }
    parse_bound_import_data(data, offset)
}

/// Parse PE32 bound imports.
fn parse_pe32_bound_imports(file: &pelite::pe32::PeFile<'_>) -> Vec<PeBoundImportEntry> {
    let dd = file.data_directory();
    let bound_dir = &dd[pelite::image::IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    if bound_dir.Size == 0 {
        return Vec::new();
    }
    let offset = bound_dir.VirtualAddress as usize;
    let data = file.image();
    if offset + 8 > data.len() {
        return Vec::new();
    }
    parse_bound_import_data(data, offset)
}

/// Parse bound import data from raw bytes.
fn parse_bound_import_data(data: &[u8], offset: usize) -> Vec<PeBoundImportEntry> {
    let mut entries = Vec::new();
    let mut pos = offset;
    while pos + 8 <= data.len() {
        let time_date_stamp =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let offset_module_name = u16::from_le_bytes([data[pos + 4], data[pos + 5]]);
        let number_of_module_forwarder_refs = u16::from_le_bytes([data[pos + 6], data[pos + 7]]);
        let name_pos = pos + offset_module_name as usize;
        let name = if name_pos < data.len() {
            let end = data[name_pos..].iter().position(|&b| b == 0).unwrap_or(0);
            String::from_utf8_lossy(&data[name_pos..name_pos + end]).to_string()
        } else {
            String::new()
        };
        entries.push(PeBoundImportEntry {
            module_name: name,
            time_date_stamp,
            offset_module_name,
            number_of_module_forwarder_refs,
        });
        // Skip past this entry and its forwarder refs.
        let skip = 8 + (number_of_module_forwarder_refs as usize) * 8;
        pos += skip.max(8);
        if number_of_module_forwarder_refs == 0 && !entries.is_empty() {
            // Simple heuristic: stop after first entry if no forwarder refs.
            break;
        }
    }
    entries
}

/// Parse PE64 delay imports.
fn parse_pe64_delay_imports(file: &pelite::pe64::PeFile<'_>) -> Vec<PeDelayImportEntry> {
    let dd = file.data_directory();
    let delay_dir = &dd[pelite::image::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if delay_dir.Size == 0 || delay_dir.VirtualAddress == 0 {
        return Vec::new();
    }
    parse_delay_import_data(
        file.image(),
        delay_dir.VirtualAddress as usize,
        delay_dir.Size as usize,
    )
}

/// Parse PE32 delay imports.
fn parse_pe32_delay_imports(file: &pelite::pe32::PeFile<'_>) -> Vec<PeDelayImportEntry> {
    let dd = file.data_directory();
    let delay_dir = &dd[pelite::image::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if delay_dir.Size == 0 || delay_dir.VirtualAddress == 0 {
        return Vec::new();
    }
    parse_delay_import_data(
        file.image(),
        delay_dir.VirtualAddress as usize,
        delay_dir.Size as usize,
    )
}

/// Parse delay import data from raw bytes.
fn parse_delay_import_data(data: &[u8], rva: usize, _size: usize) -> Vec<PeDelayImportEntry> {
    let mut entries = Vec::new();
    let mut pos = rva;
    // Each IMAGE_DELAYLOAD_DESCRIPTOR is 32 bytes.
    while pos + 32 <= data.len() {
        let attributes =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let dll_name_rva =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let module_handle_rva =
            u32::from_le_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);
        let import_address_table_rva = u32::from_le_bytes([
            data[pos + 12],
            data[pos + 13],
            data[pos + 14],
            data[pos + 15],
        ]);
        let import_name_table_rva = u32::from_le_bytes([
            data[pos + 16],
            data[pos + 17],
            data[pos + 18],
            data[pos + 19],
        ]);
        let bound_import_address_table_rva = u32::from_le_bytes([
            data[pos + 20],
            data[pos + 21],
            data[pos + 22],
            data[pos + 23],
        ]);
        let unload_information_table_rva = u32::from_le_bytes([
            data[pos + 24],
            data[pos + 25],
            data[pos + 26],
            data[pos + 27],
        ]);
        let time_date_stamp = u32::from_le_bytes([
            data[pos + 28],
            data[pos + 29],
            data[pos + 30],
            data[pos + 31],
        ]);
        // Terminate on all-zero entry.
        if attributes == 0 && dll_name_rva == 0 {
            break;
        }
        let dll_name = if dll_name_rva > 0 && (dll_name_rva as usize) < data.len() {
            let name_start = dll_name_rva as usize;
            let name_end = data[name_start..].iter().position(|&b| b == 0).unwrap_or(0);
            String::from_utf8_lossy(&data[name_start..name_start + name_end]).to_string()
        } else {
            String::new()
        };
        entries.push(PeDelayImportEntry {
            dll_name,
            attributes,
            dll_name_rva,
            module_handle_rva,
            import_address_table_rva,
            import_name_table_rva,
            bound_import_address_table_rva,
            unload_information_table_rva,
            time_date_stamp,
        });
        pos += 32;
    }
    entries
}

/// Parse PE64 .NET metadata.
fn parse_pe64_dotnet_metadata(file: &pelite::pe64::PeFile<'_>) -> Option<PeDotNetMetadata> {
    let dd = file.data_directory();
    let clr_dir = &dd[pelite::image::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    if clr_dir.Size == 0 || clr_dir.VirtualAddress == 0 {
        return None;
    }
    parse_dotnet_metadata_from_data(file.image(), clr_dir.VirtualAddress as usize)
}

/// Parse PE32 .NET metadata.
fn parse_pe32_dotnet_metadata(file: &pelite::pe32::PeFile<'_>) -> Option<PeDotNetMetadata> {
    let dd = file.data_directory();
    let clr_dir = &dd[pelite::image::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    if clr_dir.Size == 0 || clr_dir.VirtualAddress == 0 {
        return None;
    }
    parse_dotnet_metadata_from_data(file.image(), clr_dir.VirtualAddress as usize)
}

/// Parse .NET metadata from raw data at the CLR header RVA.
fn parse_dotnet_metadata_from_data(data: &[u8], clr_rva: usize) -> Option<PeDotNetMetadata> {
    if clr_rva + 72 > data.len() {
        return None;
    }
    let cb = &data[clr_rva..];
    // IMAGE_COR20_HEADER: cb(4), MajorRuntimeVersion(2), MinorRuntimeVersion(2), MetaData(rva+size=8), Flags(4), EntryPointToken(4), ...
    let metadata_rva = u32::from_le_bytes([cb[8], cb[9], cb[10], cb[11]]);
    let metadata_size = u32::from_le_bytes([cb[12], cb[13], cb[14], cb[15]]);
    let flags = u32::from_le_bytes([cb[16], cb[17], cb[18], cb[19]]);
    let entry_point_token = u32::from_le_bytes([cb[20], cb[21], cb[22], cb[23]]);
    let major_rt = u16::from_le_bytes([cb[4], cb[5]]);
    let minor_rt = u16::from_le_bytes([cb[6], cb[7]]);
    let runtime_version = format!("{}.{}", major_rt, minor_rt);
    // Parse metadata streams.
    let streams = if metadata_rva > 0 && (metadata_rva as usize) < data.len() {
        let md_start = metadata_rva as usize;
        if md_start + 16 > data.len() {
            Vec::new()
        } else {
            let md = &data[md_start..];
            // Metadata root: Signature(4), MajorVersion(2), MinorVersion(2), Reserved(4), Length(4), Version(Length), Flags(2), Streams(2)
            let length = u32::from_le_bytes([md[12], md[13], md[14], md[15]]) as usize;
            let version_end = 16 + length;
            // Align to 4 bytes.
            let version_end_aligned = (version_end + 3) & !3;
            if version_end_aligned + 4 > md.len() {
                Vec::new()
            } else {
                let flags =
                    u16::from_le_bytes([md[version_end_aligned], md[version_end_aligned + 1]]);
                let stream_count =
                    u16::from_le_bytes([md[version_end_aligned + 2], md[version_end_aligned + 3]]);
                let _ = flags;
                let mut stream_pos = version_end_aligned + 4;
                let mut streams = Vec::new();
                for _ in 0..stream_count {
                    if stream_pos + 8 > md.len() {
                        break;
                    }
                    let s_offset = u32::from_le_bytes([
                        md[stream_pos],
                        md[stream_pos + 1],
                        md[stream_pos + 2],
                        md[stream_pos + 3],
                    ]);
                    let s_size = u32::from_le_bytes([
                        md[stream_pos + 4],
                        md[stream_pos + 5],
                        md[stream_pos + 6],
                        md[stream_pos + 7],
                    ]);
                    // Name is null-terminated, aligned to 4 bytes.
                    let name_start = stream_pos + 8;
                    let name_end = md[name_start..].iter().position(|&b| b == 0).unwrap_or(0);
                    let name =
                        String::from_utf8_lossy(&md[name_start..name_start + name_end]).to_string();
                    streams.push(PeDotNetStream {
                        name,
                        offset: s_offset,
                        size: s_size,
                    });
                    // Advance past name (aligned to 4 bytes).
                    let name_total = (name_end + 1 + 3) & !3;
                    stream_pos += 8 + name_total;
                }
                streams
            }
        }
    } else {
        Vec::new()
    };
    Some(PeDotNetMetadata {
        runtime_version,
        metadata_rva,
        metadata_size,
        flags,
        entry_point_token,
        streams,
    })
}

/// Parse NT headers summary from raw PE data.
fn parse_nt_headers(data: &[u8]) -> Option<PeNtHeaders> {
    if data.len() < 64 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if e_lfanew + 24 > data.len() {
        return None;
    }
    let sig = &data[e_lfanew..e_lfanew + 4];
    if sig != b"PE\x00\x00" {
        return None;
    }
    let signature_val = u32::from_le_bytes([sig[0], sig[1], sig[2], sig[3]]);
    // IMAGE_FILE_HEADER at e_lfanew + 4.
    let fh_off = e_lfanew + 4;
    let machine_val = u16::from_le_bytes([data[fh_off], data[fh_off + 1]]);
    let number_of_sections = u16::from_le_bytes([data[fh_off + 2], data[fh_off + 3]]);
    let time_date_stamp = u32::from_le_bytes([
        data[fh_off + 4],
        data[fh_off + 5],
        data[fh_off + 6],
        data[fh_off + 7],
    ]);
    let characteristics_val = u16::from_le_bytes([data[fh_off + 18], data[fh_off + 19]]);
    // IMAGE_OPTIONAL_HEADER at e_lfanew + 24.
    let oh_off = e_lfanew + 24;
    if oh_off + 28 > data.len() {
        return None;
    }
    let magic = u16::from_le_bytes([data[oh_off], data[oh_off + 1]]);
    let is64 = magic == 0x20B;
    let entry_point = u32::from_le_bytes([
        data[oh_off + 16],
        data[oh_off + 17],
        data[oh_off + 18],
        data[oh_off + 19],
    ]);
    let image_base = if is64 {
        if oh_off + 32 > data.len() {
            0
        } else {
            u64::from_le_bytes([
                data[oh_off + 24],
                data[oh_off + 25],
                data[oh_off + 26],
                data[oh_off + 27],
                data[oh_off + 28],
                data[oh_off + 29],
                data[oh_off + 30],
                data[oh_off + 31],
            ])
        }
    } else {
        if oh_off + 32 > data.len() {
            0
        } else {
            u32::from_le_bytes([
                data[oh_off + 28],
                data[oh_off + 29],
                data[oh_off + 30],
                data[oh_off + 31],
            ]) as u64
        }
    };
    let section_alignment = if oh_off + 40 > data.len() {
        0
    } else {
        u32::from_le_bytes([
            data[oh_off + 32],
            data[oh_off + 33],
            data[oh_off + 34],
            data[oh_off + 35],
        ])
    };
    let file_alignment = if oh_off + 40 > data.len() {
        0
    } else {
        u32::from_le_bytes([
            data[oh_off + 36],
            data[oh_off + 37],
            data[oh_off + 38],
            data[oh_off + 39],
        ])
    };
    // SizeOfImage and SizeOfHeaders offsets differ for 32/64.
    let (size_of_image, size_of_headers, subsystem_off) = if is64 {
        // 64-bit: SizeOfImage at oh+56, SizeOfHeaders at oh+60, Subsystem at oh+68
        if oh_off + 80 > data.len() {
            return None;
        }
        let soi = u32::from_le_bytes([
            data[oh_off + 56],
            data[oh_off + 57],
            data[oh_off + 58],
            data[oh_off + 59],
        ]);
        let soh = u32::from_le_bytes([
            data[oh_off + 60],
            data[oh_off + 61],
            data[oh_off + 62],
            data[oh_off + 63],
        ]);
        (soi, soh, oh_off + 68)
    } else {
        // 32-bit: SizeOfImage at oh+56, SizeOfHeaders at oh+60, Subsystem at oh+68
        if oh_off + 80 > data.len() {
            return None;
        }
        let soi = u32::from_le_bytes([
            data[oh_off + 56],
            data[oh_off + 57],
            data[oh_off + 58],
            data[oh_off + 59],
        ]);
        let soh = u32::from_le_bytes([
            data[oh_off + 60],
            data[oh_off + 61],
            data[oh_off + 62],
            data[oh_off + 63],
        ]);
        (soi, soh, oh_off + 68)
    };
    let subsystem_val = if subsystem_off + 2 > data.len() {
        0
    } else {
        u16::from_le_bytes([data[subsystem_off], data[subsystem_off + 1]])
    };
    // NumberOfRvaAndSizes offset: 64-bit at oh+108, 32-bit at oh+92.
    let n_rva_off = if is64 { oh_off + 108 } else { oh_off + 92 };
    let number_of_data_directories = if n_rva_off + 4 > data.len() {
        0
    } else {
        u32::from_le_bytes([
            data[n_rva_off],
            data[n_rva_off + 1],
            data[n_rva_off + 2],
            data[n_rva_off + 3],
        ])
    };
    Some(PeNtHeaders {
        signature: "PE\\0\\0".to_string(),
        signature_val,
        offset: e_lfanew as u32,
        file_header_summary: PeNtFileHeaderSummary {
            machine: pe_machine_name(machine_val),
            number_of_sections,
            time_date_stamp,
            characteristics: pe_characteristics_string(characteristics_val),
        },
        optional_header_summary: PeNtOptionalHeaderSummary {
            magic: if is64 {
                "0x20B (PE32+)".to_string()
            } else {
                "0x10B (PE32)".to_string()
            },
            is64,
            entry_point,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            subsystem: pe_subsystem_name(subsystem_val),
        },
        number_of_data_directories,
        number_of_sections,
    })
}

/// Parse resource string table (RT_STRING resources).
fn parse_resource_strings(
    _data: &[u8],
    resources: &[PeResourceNode],
) -> Vec<PeResourceStringEntry> {
    let mut result = Vec::new();
    // Find RT_STRING (type 6) in resource tree.
    for top in resources {
        if top.id == 6 {
            // Children are string table blocks (each block has 16 strings).
            for block in &top.children {
                let base_id = block.id * 16;
                for entry in &block.children {
                    if let Some(size) = entry.data_size {
                        // String entry: 2 bytes length prefix + UTF-16LE data.
                        // We need the actual data offset, but we don't have it here.
                        // Use the data_size to estimate.
                        if size > 0 {
                            // Try to find the data in the raw file.
                            // For now, store the ID and size.
                            result.push(PeResourceStringEntry {
                                id: base_id,
                                value: String::new(), // Will be filled by frontend
                                offset: 0,
                            });
                        }
                    }
                }
            }
        }
    }
    // Limit to 1000 entries.
    result.truncate(1000);
    result
}

/// Parse .NET metadata stream details.
fn parse_dotnet_stream_details(
    data: &[u8],
    metadata: &Option<PeDotNetMetadata>,
) -> Vec<PeDotNetStreamDetail> {
    let Some(meta) = metadata else {
        return Vec::new();
    };
    let md_start = meta.metadata_rva as usize;
    if md_start >= data.len() {
        return Vec::new();
    }
    let mut details = Vec::new();
    for stream in &meta.streams {
        let stream_data_off = md_start + stream.offset as usize;
        let stream_type = match stream.name.as_str() {
            "#~" | "#-" => "Metadata tables (#~)".to_string(),
            "#Strings" => "String heap".to_string(),
            "#US" => "User string heap".to_string(),
            "#GUID" => "GUID heap".to_string(),
            "#Blob" => "Blob heap".to_string(),
            _ => format!("Unknown ({})", stream.name),
        };
        let hex_preview = if stream_data_off < data.len() {
            let end = std::cmp::min(stream_data_off + 256, data.len());
            data[stream_data_off..end]
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            String::new()
        };
        details.push(PeDotNetStreamDetail {
            name: stream.name.clone(),
            offset: stream.offset,
            size: stream.size,
            stream_type,
            hex_preview,
        });
    }
    details
}

/// Parse .NET metadata table summary from #~ stream.
fn parse_dotnet_metadata_table(
    data: &[u8],
    metadata: &Option<PeDotNetMetadata>,
) -> Option<PeDotNetMetadataTable> {
    let Some(meta) = metadata else {
        return None;
    };
    // Find #~ stream.
    let table_stream = meta
        .streams
        .iter()
        .find(|s| s.name == "#~" || s.name == "#-")?;
    let md_start = meta.metadata_rva as usize;
    let stream_off = md_start + table_stream.offset as usize;
    if stream_off + 24 > data.len() {
        return None;
    }
    let sd = &data[stream_off..];
    // #~ stream header: Reserved(4), MajorVersion(1), MinorVersion(1), HeapSizes(1), Reserved(1), Valid(8), Sorted(8), Rows[](4*n)
    let valid = u64::from_le_bytes([sd[8], sd[9], sd[10], sd[11], sd[12], sd[13], sd[14], sd[15]]);
    // Table names for bits 0-43 (ECMA-335).
    let table_names = [
        "Module",
        "TypeRef",
        "TypeDef",
        "FieldPtr",
        "Field",
        "MethodPtr",
        "MethodDef",
        "ParamPtr",
        "Param",
        "InterfaceImpl",
        "MemberRef",
        "Constant",
        "CustomAttribute",
        "FieldMarshal",
        "DeclSecurity",
        "ClassLayout",
        "FieldLayout",
        "StandAloneSig",
        "EventMap",
        "EventPtr",
        "Event",
        "PropertyMap",
        "PropertyPtr",
        "Property",
        "MethodSemantics",
        "MethodImpl",
        "ModuleRef",
        "TypeSpec",
        "ImplMap",
        "FieldRVA",
        "EncLog",
        "EncMap",
        "Assembly",
        "AssemblyProcessor",
        "AssemblyOS",
        "AssemblyRef",
        "AssemblyRefProcessor",
        "AssemblyRefOS",
        "File",
        "ExportedType",
        "ManifestResource",
        "NestedClass",
        "GenericParam",
        "MethodSpec",
        "GenericParamConstraint",
    ];
    // Count valid tables and read row counts.
    let mut present_tables = Vec::new();
    let mut row_counts = Vec::new();
    let mut rows_off = 24;
    for (i, &name) in table_names.iter().enumerate() {
        if i >= 64 {
            break;
        }
        if (valid >> i) & 1 != 0 {
            present_tables.push(name.to_string());
            if rows_off + 4 > sd.len() {
                break;
            }
            let count = u32::from_le_bytes([
                sd[rows_off],
                sd[rows_off + 1],
                sd[rows_off + 2],
                sd[rows_off + 3],
            ]);
            row_counts.push((name.to_string(), count));
            rows_off += 4;
        }
    }
    // We don't parse actual table rows (requires full schema knowledge).
    // Return summary with empty sample_rows.
    Some(PeDotNetMetadataTable {
        present_tables,
        row_counts,
        sample_rows: Vec::new(),
    })
}

// =========================================================================
// PE helper: name/flag conversion functions
// =========================================================================

/// Convert PE machine type to name.
fn pe_machine_name(machine: u16) -> String {
    match machine {
        0x0000 => "UNKNOWN".into(),
        0x014c => "I386".into(),
        0x0162 => "R3000".into(),
        0x0166 => "R4000".into(),
        0x0168 => "R10000".into(),
        0x0184 => "ALPHA".into(),
        0x01a2 => "SH3".into(),
        0x01a6 => "SH4".into(),
        0x01c0 => "ARM".into(),
        0x01c2 => "THUMB".into(),
        0x01c4 => "ARMNT".into(),
        0x01d3 => "AM33".into(),
        0x1f0 => "POWERPC".into(),
        0x01f1 => "POWERPCFP".into(),
        0x0200 => "IA64".into(),
        0x0266 => "MIPS16".into(),
        0x0284 => "ALPHA64".into(),
        0x0366 => "MIPSFPU16".into(),
        0x0466 => "MIPSFPU".into(),
        0x0526 => "TRICORE".into(),
        0x0e0b => "CEF".into(),
        0x8664 => "AMD64".into(),
        0x9041 => "M32R".into(),
        0xaa64 => "ARM64".into(),
        0xa641 => "ARM64EC".into(),
        _ => format!("0x{:04X}", machine),
    }
}

/// Convert PE characteristics to string.
fn pe_characteristics_string(ch: u16) -> String {
    let mut parts = Vec::new();
    if ch & 0x0001 != 0 {
        parts.push("RELOCS_STRIPPED");
    }
    if ch & 0x0002 != 0 {
        parts.push("EXECUTABLE_IMAGE");
    }
    if ch & 0x0004 != 0 {
        parts.push("LINE_NUMS_STRIPPED");
    }
    if ch & 0x0008 != 0 {
        parts.push("LOCAL_SYMS_STRIPPED");
    }
    if ch & 0x0010 != 0 {
        parts.push("AGGRESSIVE_WS_TRIM");
    }
    if ch & 0x0020 != 0 {
        parts.push("LARGE_ADDRESS_AWARE");
    }
    if ch & 0x0080 != 0 {
        parts.push("BYTES_REVERSED_LO");
    }
    if ch & 0x0100 != 0 {
        parts.push("32BIT_MACHINE");
    }
    if ch & 0x0200 != 0 {
        parts.push("DEBUG_STRIPPED");
    }
    if ch & 0x0400 != 0 {
        parts.push("REMOVABLE_RUN_FROM_SWAP");
    }
    if ch & 0x0800 != 0 {
        parts.push("NET_RUN_FROM_SWAP");
    }
    if ch & 0x1000 != 0 {
        parts.push("SYSTEM");
    }
    if ch & 0x2000 != 0 {
        parts.push("DLL");
    }
    if ch & 0x4000 != 0 {
        parts.push("UP_SYSTEM_ONLY");
    }
    if ch & 0x8000 != 0 {
        parts.push("BYTES_REVERSED_HI");
    }
    if parts.is_empty() {
        "0x0000".into()
    } else {
        parts.join("|")
    }
}

/// Convert PE subsystem to name.
fn pe_subsystem_name(sub: u16) -> String {
    match sub {
        0 => "UNKNOWN".into(),
        1 => "NATIVE".into(),
        2 => "WINDOWS_GUI".into(),
        3 => "WINDOWS_CUI".into(),
        5 => "OS2_CUI".into(),
        7 => "POSIX_CUI".into(),
        8 => "NATIVE_WINDOWS".into(),
        9 => "WINDOWS_CE_GUI".into(),
        10 => "EFI_APPLICATION".into(),
        11 => "EFI_BOOT_SERVICE_DRIVER".into(),
        12 => "EFI_RUNTIME_DRIVER".into(),
        13 => "EFI_ROM".into(),
        14 => "XBOX".into(),
        16 => "WINDOWS_BOOT_APPLICATION".into(),
        _ => format!("0x{:04X}", sub),
    }
}

/// Convert PE DLL characteristics to string.
fn pe_dll_characteristics_string(ch: u16) -> String {
    let mut parts = Vec::new();
    if ch & 0x0020 != 0 {
        parts.push("HIGH_ENTROPY_VA");
    }
    if ch & 0x0040 != 0 {
        parts.push("DYNAMIC_BASE");
    }
    if ch & 0x0080 != 0 {
        parts.push("FORCE_INTEGRITY");
    }
    if ch & 0x0100 != 0 {
        parts.push("NX_COMPAT");
    }
    if ch & 0x0200 != 0 {
        parts.push("NO_ISOLATION");
    }
    if ch & 0x0400 != 0 {
        parts.push("NO_SEH");
    }
    if ch & 0x0800 != 0 {
        parts.push("NO_BIND");
    }
    if ch & 0x1000 != 0 {
        parts.push("APPCONTAINER");
    }
    if ch & 0x2000 != 0 {
        parts.push("WDM_DRIVER");
    }
    if ch & 0x4000 != 0 {
        parts.push("GUARD_CF");
    }
    if ch & 0x8000 != 0 {
        parts.push("TERMINAL_SERVER_AWARE");
    }
    if parts.is_empty() {
        "0x0000".into()
    } else {
        parts.join("|")
    }
}

/// Convert PE section characteristics to string.
fn pe_section_chars_string(ch: u32) -> String {
    let mut parts = Vec::new();
    if ch & 0x00000020 != 0 {
        parts.push("CNT_CODE");
    }
    if ch & 0x00000040 != 0 {
        parts.push("CNT_INITIALIZED_DATA");
    }
    if ch & 0x00000080 != 0 {
        parts.push("CNT_UNINITIALIZED_DATA");
    }
    if ch & 0x00000100 != 0 {
        parts.push("LNK_OTHER");
    }
    if ch & 0x00000200 != 0 {
        parts.push("LNK_INFO");
    }
    if ch & 0x00000800 != 0 {
        parts.push("LNK_REMOVE");
    }
    if ch & 0x00001000 != 0 {
        parts.push("LNK_COMDAT");
    }
    if ch & 0x00004000 != 0 {
        parts.push("GPREL");
    }
    if ch & 0x00008000 != 0 {
        parts.push("MEM_DISCARDABLE");
    }
    if ch & 0x00010000 != 0 {
        parts.push("MEM_NOT_CACHED");
    }
    if ch & 0x00020000 != 0 {
        parts.push("MEM_NOT_PAGED");
    }
    if ch & 0x00040000 != 0 {
        parts.push("MEM_SHARED");
    }
    if ch & 0x00080000 != 0 {
        parts.push("MEM_EXECUTE");
    }
    if ch & 0x00100000 != 0 {
        parts.push("MEM_READ");
    }
    if ch & 0x00200000 != 0 {
        parts.push("MEM_WRITE");
    }
    if ch & 0x01000000 != 0 {
        parts.push("LNK_NRELOC_OVFL");
    }
    if parts.is_empty() {
        "0x00000000".into()
    } else {
        parts.join("|")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pe_view_not_pe() {
        let data = b"Hello, World!";
        assert!(parse_pe_view(data).is_none());
    }

    #[test]
    fn test_parse_pe_view_dos_only() {
        let mut data = vec![0u8; 128];
        data[0] = b'M';
        data[1] = b'Z';
        assert!(parse_pe_view(&data).is_none());
    }

    #[test]
    fn test_check_rich_header_present() {
        let mut data = vec![0u8; 0x200];
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew = 0x80 (PE header at 0x80, Rich header in DOS stub before it)
        data[0x3c] = 0x80;
        // "Rich" signature at 0x50 (in DOS stub, before PE header)
        data[0x50] = b'R';
        data[0x51] = b'i';
        data[0x52] = b'c';
        data[0x53] = b'h';
        // PE signature at 0x80
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        assert!(check_rich_header(&data));
    }

    #[test]
    fn test_check_rich_header_absent() {
        let mut data = vec![0u8; 0x200];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3c] = 0x40;
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        assert!(!check_rich_header(&data));
    }

    #[test]
    fn test_resource_type_name() {
        assert_eq!(resource_type_name(2), "RT_BITMAP");
        assert_eq!(resource_type_name(24), "RT_MANIFEST");
        assert_eq!(resource_type_name(99), "RT_UNKNOWN");
    }

    #[test]
    fn test_calc_overlay_no_sections() {
        // Minimal PE with no sections → overlay = 0.
        let mut data = vec![0u8; 0x200];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3c] = 0x40;
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        // NumberOfSections = 0 at e_lfanew + 6 = 0x46
        data[0x46] = 0;
        data[0x47] = 0;
        // SizeOfOptionalHeader at e_lfanew + 20 = 0x54
        data[0x54] = 0;
        data[0x55] = 0;
        let off = calc_overlay_offset(&data);
        assert_eq!(off, 0);
    }

    #[test]
    fn test_pe_subsystem_name() {
        assert_eq!(pe_subsystem_name(0), "UNKNOWN");
        assert_eq!(pe_subsystem_name(2), "WINDOWS_GUI");
        assert_eq!(pe_subsystem_name(3), "WINDOWS_CUI");
        assert_eq!(pe_subsystem_name(9), "WINDOWS_CE_GUI");
        assert_eq!(pe_subsystem_name(99), "0x0063");
    }

    #[test]
    fn test_pe_machine_name() {
        assert_eq!(pe_machine_name(0x0000), "UNKNOWN");
        assert_eq!(pe_machine_name(0x014c), "I386");
        assert_eq!(pe_machine_name(0x8664), "AMD64");
        assert_eq!(pe_machine_name(0xaa64), "ARM64");
        assert_eq!(pe_machine_name(0x9999), "0x9999");
    }

    #[test]
    fn test_parse_nt_headers_minimal() {
        // Minimal PE with NT headers.
        let mut data = vec![0u8; 0x200];
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew = 0x80
        data[0x3c] = 0x80;
        data[0x3d] = 0x00;
        // PE signature
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        // Machine = i386 (0x014c) at 0x84
        data[0x84] = 0x4c;
        data[0x85] = 0x01;
        // NumberOfSections = 1 at 0x86
        data[0x86] = 0x01;
        data[0x87] = 0x00;
        // SizeOfOptionalHeader = 0xE0 (PE32) at 0x94
        data[0x94] = 0xe0;
        data[0x95] = 0x00;
        // Magic = 0x10b (PE32) at 0x98
        data[0x98] = 0x0b;
        data[0x99] = 0x10;
        let nt = parse_nt_headers(&data);
        assert!(nt.is_some());
        let nt = nt.unwrap();
        assert_eq!(nt.signature_val, 0x00004550);
        assert_eq!(nt.file_header_summary.machine, "I386");
        assert_eq!(nt.number_of_sections, 1);
    }

    #[test]
    fn test_parse_nt_headers_not_pe() {
        let data = vec![0u8; 256];
        assert!(parse_nt_headers(&data).is_none());
    }
}

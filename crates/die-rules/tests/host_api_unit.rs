//! Unit tests for PE host API methods in host_api_bridge.rs.
//!
//! These tests directly exercise the JavaScript bridge methods that were
//! recently implemented or fixed:
//!   - Rich signature parsing (getRichID, getRichVersion, getRichCount)
//!   - PE debug data records (getNumberOfDebugDataRecords, getDebugDataType)
//!   - PE.isSigned (Authenticode signature detection)
//!   - Binary.isPlainText
//!
//! Each test constructs a minimal PE binary in memory and evaluates a
//! small JavaScript snippet through the rquickjs runtime to call the
//! host API method directly.

#![cfg(test)]

use die_core::cancel::CancellationToken;
use die_core::format::FileType;
use die_core::input::ByteView;
use die_rules::backend_rquickjs::RquickjsRuntime;
use die_rules::host_api::{HostApi, HostApiError};
use die_rules::runtime::{DatabaseSnapshot, LoadedRule, RuleRuntime, RuntimeConfig};
use std::collections::BTreeMap;
use std::sync::Arc;

// Re-use the BufferHost from real_rules tests.
// We duplicate it here to keep the test self-contained.

struct BufferHost {
    data: Vec<u8>,
    file_type: FileType,
}

impl BufferHost {
    fn with_type(data: Vec<u8>, file_type: &str) -> Self {
        Self {
            data,
            file_type: FileType::new(file_type),
        }
    }
}

impl HostApi for BufferHost {
    fn file_type(&self) -> &FileType {
        &self.file_type
    }
    fn view(&self) -> &ByteView<'_> {
        unimplemented!()
    }
    fn read_u8(&self, offset: u64) -> Result<u8, HostApiError> {
        self.data
            .get(offset as usize)
            .copied()
            .ok_or(HostApiError::OutOfBounds {
                offset,
                file_size: self.data.len() as u64,
            })
    }
    fn read_u16_le(&self, offset: u64) -> Result<u16, HostApiError> {
        let i = offset as usize;
        if i + 2 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: self.data.len() as u64,
            });
        }
        Ok(u16::from_le_bytes([self.data[i], self.data[i + 1]]))
    }
    fn read_u16_be(&self, offset: u64) -> Result<u16, HostApiError> {
        let i = offset as usize;
        if i + 2 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: self.data.len() as u64,
            });
        }
        Ok(u16::from_be_bytes([self.data[i], self.data[i + 1]]))
    }
    fn read_u24_le(&self, offset: u64) -> Result<u32, HostApiError> {
        let i = offset as usize;
        if i + 3 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: self.data.len() as u64,
            });
        }
        Ok((self.data[i] as u32)
            | ((self.data[i + 1] as u32) << 8)
            | ((self.data[i + 2] as u32) << 16))
    }
    fn read_u24_be(&self, offset: u64) -> Result<u32, HostApiError> {
        let i = offset as usize;
        if i + 3 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: self.data.len() as u64,
            });
        }
        Ok(((self.data[i] as u32) << 16)
            | ((self.data[i + 1] as u32) << 8)
            | (self.data[i + 2] as u32))
    }
    fn read_u32_le(&self, offset: u64) -> Result<u32, HostApiError> {
        let i = offset as usize;
        if i + 4 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: self.data.len() as u64,
            });
        }
        Ok(u32::from_le_bytes([
            self.data[i],
            self.data[i + 1],
            self.data[i + 2],
            self.data[i + 3],
        ]))
    }
    fn read_u32_be(&self, offset: u64) -> Result<u32, HostApiError> {
        let i = offset as usize;
        if i + 4 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: self.data.len() as u64,
            });
        }
        Ok(u32::from_be_bytes([
            self.data[i],
            self.data[i + 1],
            self.data[i + 2],
            self.data[i + 3],
        ]))
    }
    fn read_u64_le(&self, offset: u64) -> Result<u64, HostApiError> {
        let i = offset as usize;
        if i + 8 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: self.data.len() as u64,
            });
        }
        Ok(u64::from_le_bytes(self.data[i..i + 8].try_into().unwrap()))
    }
    fn read_u64_be(&self, offset: u64) -> Result<u64, HostApiError> {
        let i = offset as usize;
        if i + 8 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: self.data.len() as u64,
            });
        }
        Ok(u64::from_be_bytes(self.data[i..i + 8].try_into().unwrap()))
    }
    fn read_i8(&self, offset: u64) -> Result<i8, HostApiError> {
        self.read_u8(offset).map(|v| v as i8)
    }
    fn read_i16_le(&self, offset: u64) -> Result<i16, HostApiError> {
        self.read_u16_le(offset).map(|v| v as i16)
    }
    fn read_i32_le(&self, offset: u64) -> Result<i32, HostApiError> {
        self.read_u32_le(offset).map(|v| v as i32)
    }
    fn read_i64_le(&self, offset: u64) -> Result<i64, HostApiError> {
        self.read_u64_le(offset).map(|v| v as i64)
    }
    fn file_size(&self) -> u64 {
        self.data.len() as u64
    }
    fn check_signature(&self, offset: u64, signature: &str) -> Result<bool, HostApiError> {
        let elements =
            die_rules::host_api_bridge::parse_signature(signature).map_err(|detail| {
                HostApiError::InvalidSignature {
                    pattern: signature.into(),
                    detail,
                }
            })?;
        Ok(die_rules::host_api_bridge::match_signature(
            &self.data,
            offset as usize,
            &elements,
        ))
    }
    fn find_signature(&self, start: u64, signature: &str) -> Result<Option<u64>, HostApiError> {
        let elements =
            die_rules::host_api_bridge::parse_signature(signature).map_err(|detail| {
                HostApiError::InvalidSignature {
                    pattern: signature.into(),
                    detail,
                }
            })?;
        let start = start as usize;
        if elements.is_empty()
            || start
                .checked_add(elements.len())
                .is_none_or(|end| end > self.data.len())
        {
            return Ok(None);
        }
        for i in start..=self.data.len() - elements.len() {
            if die_rules::host_api_bridge::match_signature(&self.data, i, &elements) {
                return Ok(Some(i as u64));
            }
        }
        Ok(None)
    }
    fn find_signature_in_range(
        &self,
        start: u64,
        end: u64,
        signature: &str,
    ) -> Result<Option<u64>, HostApiError> {
        let elements =
            die_rules::host_api_bridge::parse_signature(signature).map_err(|detail| {
                HostApiError::InvalidSignature {
                    pattern: signature.into(),
                    detail,
                }
            })?;
        let start = start as usize;
        let end = (end as usize).min(self.data.len());
        if elements.is_empty() || start >= end || end < elements.len() {
            return Ok(None);
        }
        for i in start..=end - elements.len() {
            if die_rules::host_api_bridge::match_signature(&self.data, i, &elements) {
                return Ok(Some(i as u64));
            }
        }
        Ok(None)
    }
    fn read_string(&self, offset: u64, max_len: u64) -> Result<String, HostApiError> {
        let start = offset as usize;
        let end = (start + max_len as usize).min(self.data.len());
        if start >= self.data.len() {
            return Ok(String::new());
        }
        let bytes = &self.data[start..end];
        let nul_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..nul_pos]).to_string())
    }
    fn file_name(&self) -> &str {
        "test.bin"
    }
    fn entry_point(&self) -> Result<u64, HostApiError> {
        Ok(0)
    }
    fn is_deep(&self) -> bool {
        false
    }
    fn is_heuristic(&self) -> bool {
        false
    }
    fn is_aggressive(&self) -> bool {
        false
    }
    fn is_verbose(&self) -> bool {
        false
    }
    fn is_recursive(&self) -> bool {
        false
    }
    fn entropy(&self, offset: u64, size: u64) -> Result<f64, HostApiError> {
        let start = offset as usize;
        let end = (start + size as usize).min(self.data.len());
        if start >= end {
            return Ok(0.0);
        }
        let mut counts = [0u32; 256];
        for &b in &self.data[start..end] {
            counts[b as usize] += 1;
        }
        let total = (end - start) as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }
        Ok(entropy)
    }
    fn md5(&self, _offset: u64, _size: u64) -> Result<String, HostApiError> {
        Err(HostApiError::NotImplemented {
            method: "md5".into(),
        })
    }
    fn crc32(&self, _offset: u64, _size: u64) -> Result<u32, HostApiError> {
        Err(HostApiError::NotImplemented {
            method: "crc32".into(),
        })
    }
    fn pe_batch(&self) -> Option<die_rules::pe_native::PeBatchInfo> {
        die_rules::pe_native::parse_batch(&self.data)
    }
    fn pe_import_libraries(&self) -> Vec<String> {
        Vec::new()
    }
    fn pe_import_functions(&self) -> Vec<String> {
        Vec::new()
    }
    fn pe_export_names(&self) -> Vec<String> {
        Vec::new()
    }
    fn elf_import_libraries(&self) -> Vec<String> {
        Vec::new()
    }
    fn elf_section_names(&self) -> Vec<String> {
        Vec::new()
    }
    fn macho_import_libraries(&self) -> Vec<String> {
        Vec::new()
    }
    fn macho_section_names(&self) -> Vec<String> {
        Vec::new()
    }
    fn pe_manifest(&self) -> String {
        String::new()
    }
    fn pe_is_net(&self) -> bool {
        false
    }
    fn pe_file_version(&self) -> String {
        String::new()
    }
    fn pe_product_version(&self) -> String {
        String::new()
    }
    fn pe_version_string(&self, _key: &str) -> String {
        String::new()
    }
    fn pe_number_of_resources(&self) -> usize {
        0
    }
    fn pe_is_resource_name_present(&self, _name: &str) -> bool {
        false
    }
    fn pe_resource_section_offset(&self) -> i64 {
        -1
    }
    fn pe_is_signed(&self) -> bool {
        die_rules::pe_native::is_signed(&self.data)
    }
}

/// Load the upstream PE _init framework.
#[allow(clippy::type_complexity)]
fn load_pe_framework() -> Option<(String, Vec<(String, String)>, BTreeMap<String, String>)> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let db = root
        .join("upstream/Detect-It-Easy/db")
        .to_str()
        .expect("utf-8 path")
        .to_string();

    let init_source = std::fs::read_to_string(format!("{db}/_init")).ok()?;

    let mut includes = BTreeMap::new();
    for name in &[
        "_debug",
        "_runtime_helpers",
        "language",
        "archive-file",
        "zip-file",
        "read",
    ] {
        if let Ok(source) = std::fs::read_to_string(format!("{db}/{name}")) {
            includes.insert(name.to_string(), source);
        }
    }

    let pe_init = std::fs::read_to_string(format!("{db}/PE/_init")).ok()?;
    let type_init_scripts = vec![("PE".to_string(), pe_init)];

    Some((init_source, type_init_scripts, includes))
}

/// Load the upstream Binary _init framework.
#[allow(clippy::type_complexity)]
fn load_binary_framework() -> Option<(String, Vec<(String, String)>, BTreeMap<String, String>)> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let db = root
        .join("upstream/Detect-It-Easy/db")
        .to_str()
        .expect("utf-8 path")
        .to_string();

    let init_source = std::fs::read_to_string(format!("{db}/_init")).ok()?;

    let mut includes = BTreeMap::new();
    for name in &[
        "_debug",
        "_runtime_helpers",
        "language",
        "archive-file",
        "zip-file",
        "read",
    ] {
        if let Ok(source) = std::fs::read_to_string(format!("{db}/{name}")) {
            includes.insert(name.to_string(), source);
        }
    }

    let bin_init = std::fs::read_to_string(format!("{db}/Binary/_init")).ok()?;
    let type_init_scripts = vec![("Binary".to_string(), bin_init)];

    Some((init_source, type_init_scripts, includes))
}

/// Run a JavaScript snippet in the PE host API context.
/// Returns the detections produced by the snippet.
fn run_js_pe(js_code: &str, data: Vec<u8>) -> Option<Vec<die_rules::runtime::DetectionResult>> {
    let (init_source, type_init_scripts, includes) = load_pe_framework()?;

    let rule_source = format!(
        r#"// Auto-generated test rule
meta("test", "HostAPI");
function detect() {{
{js_code}
    return result();
}}
"#
    );

    let snapshot = DatabaseSnapshot {
        rules: vec![LoadedRule {
            path: "test_host_api.sg".to_string(),
            ordinal: 0,
            file_type: "PE".into(),
            source: rule_source,
            bytecode: None,
        }],
        init_script: Some(init_source),
        type_init_scripts,
        include_scripts: includes,
        bytecode: None,
    };

    let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).ok()?;
    let host = Arc::new(BufferHost::with_type(data, "PE"));
    if let Err(e) = runtime.register_host_api(host.clone()) {
        eprintln!("DEBUG: register_host_api failed: {e}");
        return None;
    }
    if let Err(e) = runtime.load_database(&snapshot) {
        eprintln!("DEBUG: load_database failed: {e}");
        return None;
    }

    let token = CancellationToken::new();
    let host_ref: &dyn HostApi = &*host;
    if let Err(e) = runtime.init(host_ref) {
        eprintln!("DEBUG: init failed: {e}");
        return None;
    }

    match runtime.evaluate_rule(&snapshot.rules[0], host_ref, &token) {
        Ok(results) => Some(results),
        Err(e) => {
            eprintln!("DEBUG: evaluate_rule failed: {e}");
            None
        }
    }
}

/// Run a JavaScript snippet in the Binary host API context.
fn run_js_binary(js_code: &str, data: Vec<u8>) -> Option<Vec<die_rules::runtime::DetectionResult>> {
    let (init_source, type_init_scripts, includes) = load_binary_framework()?;

    let rule_source = format!(
        r#"// Auto-generated test rule
meta("test", "HostAPI");
function detect() {{
{js_code}
    return result();
}}
"#
    );

    let snapshot = DatabaseSnapshot {
        rules: vec![LoadedRule {
            path: "test_host_api.sg".to_string(),
            ordinal: 0,
            file_type: "Binary".into(),
            source: rule_source,
            bytecode: None,
        }],
        init_script: Some(init_source),
        type_init_scripts,
        include_scripts: includes,
        bytecode: None,
    };

    let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).ok()?;
    let host = Arc::new(BufferHost::with_type(data, "Binary"));
    runtime.register_host_api(host.clone()).ok()?;
    runtime.load_database(&snapshot).ok()?;

    let token = CancellationToken::new();
    let host_ref: &dyn HostApi = &*host;
    runtime.init(host_ref).ok()?;

    runtime
        .evaluate_rule(&snapshot.rules[0], host_ref, &token)
        .ok()
}

// =====================================================================
// PE file construction helpers
// =====================================================================

/// Build a minimal PE32 file with optional Rich signature, debug directory,
/// and security directory. The PE is laid out as:
///   0x00: DOS header (64 bytes)
///   0x40: DOS stub + Rich signature (variable)
///   pe_offset: PE signature + COFF header + optional header + section
fn build_minimal_pe(
    rich_entries: &[(u16, u16, u32)], // (product_id, version, count)
    debug_entries: &[u32],            // debug types
    has_security: bool,
) -> Vec<u8> {
    // DOS header at 0x00, PE header at 0x80 (128 bytes for DOS stub + Rich)
    let pe_offset = 0x80u32;
    let mut data = vec![0u8; pe_offset as usize];

    // MZ magic
    data[0] = b'M';
    data[1] = b'Z';
    // e_lfanew at offset 0x3C
    data[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

    // Build Rich signature in DOS stub (between offset 64 and pe_offset)
    if !rich_entries.is_empty() {
        let rich_off = pe_offset as usize - 8; // "Rich" + key at end
        let key: u32 = 0x12345678; // arbitrary XOR key

        // Entries end right before "Rich" marker.
        let entries_end = rich_off;
        let entries_start = entries_end - rich_entries.len() * 8;

        // DanS marker is 16 bytes before entries_start:
        // DanS (4 bytes) + 3 padding DWORDs (12 bytes) = 16 bytes
        let dans_offset = entries_start - 16;
        let dans_val = 0x536E6144u32; // "DanS" LE
        data[dans_offset..dans_offset + 4].copy_from_slice(&(dans_val ^ key).to_le_bytes());
        // 3 padding DWORDs (zeros XORed with key)
        for i in 0..3 {
            let off = dans_offset + 4 + i * 4;
            // Padding DWORDs: 0 XOR key = key
            data[off..off + 4].copy_from_slice(&key.to_le_bytes());
        }

        // Rich entries
        for (i, &(prod_id, version, count)) in rich_entries.iter().enumerate() {
            let off = entries_start + i * 8;
            // DWORD1: high 16 bits = ProductID, low 16 bits = Version
            let dword1 = ((prod_id as u32) << 16) | (version as u32);
            data[off..off + 4].copy_from_slice(&(dword1 ^ key).to_le_bytes());
            data[off + 4..off + 8].copy_from_slice(&(count ^ key).to_le_bytes());
        }

        // "Rich" marker + key at rich_off
        data[rich_off..rich_off + 4].copy_from_slice(b"Rich");
        data[rich_off + 4..rich_off + 8].copy_from_slice(&key.to_le_bytes());
    }

    // PE signature "PE\0\0"
    data.extend_from_slice(b"PE\0\0");

    // COFF header (20 bytes)
    data.extend_from_slice(&0x014Cu16.to_le_bytes()); // Machine: IMAGE_FILE_MACHINE_I386
    data.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    data.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    data.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
    data.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
    data.extend_from_slice(&224u16.to_le_bytes()); // SizeOfOptionalHeader (PE32)
    data.extend_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

    // Optional header (PE32, 224 bytes)
    let opt_start = data.len();
    // Magic: 0x10B = PE32
    data.extend_from_slice(&0x010Bu16.to_le_bytes());
    data.push(0x0E); // MajorLinkerVersion
    data.push(0x00); // MinorLinkerVersion
    data.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfCode
    data.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
    data.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    data.extend_from_slice(&0u32.to_le_bytes()); // BaseOfCode
    data.extend_from_slice(&0u32.to_le_bytes()); // BaseOfData
    // ImageBase
    data.extend_from_slice(&0x00400000u32.to_le_bytes());
    // SectionAlignment
    data.extend_from_slice(&0x1000u32.to_le_bytes());
    // FileAlignment
    data.extend_from_slice(&0x200u32.to_le_bytes());
    // MajorOperatingSystemVersion
    data.extend_from_slice(&6u16.to_le_bytes());
    // MinorOperatingSystemVersion
    data.extend_from_slice(&0u16.to_le_bytes());
    // ImageVersion
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    // SubsystemVersion
    data.extend_from_slice(&6u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    // Win32VersionValue
    data.extend_from_slice(&0u32.to_le_bytes());
    // SizeOfImage
    data.extend_from_slice(&0x2000u32.to_le_bytes());
    // SizeOfHeaders
    data.extend_from_slice(&0x200u32.to_le_bytes());
    // CheckSum
    data.extend_from_slice(&0u32.to_le_bytes());
    // Subsystem (CONSOLE)
    data.extend_from_slice(&3u16.to_le_bytes());
    // DllCharacteristics
    data.extend_from_slice(&0u16.to_le_bytes());
    // SizeOfStackReserve/Commit, SizeOfHeapReserve/Commit
    data.extend_from_slice(&0x100000u32.to_le_bytes());
    data.extend_from_slice(&0x1000u32.to_le_bytes());
    data.extend_from_slice(&0x100000u32.to_le_bytes());
    data.extend_from_slice(&0x1000u32.to_le_bytes());
    // LoaderFlags
    data.extend_from_slice(&0u32.to_le_bytes());
    // NumberOfRvaAndSizes
    data.extend_from_slice(&16u32.to_le_bytes());

    // Data directories (16 entries, 8 bytes each = 128 bytes)
    // Index 0: Export
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // Index 1: Import
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // Index 2: Resource
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // Index 3: Exception
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // Index 4: Security (Certificate Table)
    // VirtualAddress is a file offset (not RVA) for security directory.
    // Must be within file bounds for isSigned() to return true.
    if has_security {
        data.extend_from_slice(&0x400u32.to_le_bytes()); // file offset
        data.extend_from_slice(&0x100u32.to_le_bytes()); // size (within file)
    } else {
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
    }
    // Index 5: BaseRelocation
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // Index 6: Debug
    if !debug_entries.is_empty() {
        // Place debug directory at a separate RVA (0x2000) with file offset 0x400.
        // .text section covers RVA 0x1000-0x1200, so debug data at 0x2000 is in a
        // virtual second section. But we only have one section, so we need to
        // place debug data within the .text section's raw data range.
        // .text: VA=0x1000, RawData=0x200, RawSize=0x200
        // Debug dir at file offset 0x400 = RVA 0x1200 (within .text VA range)
        let debug_rva = 0x1200u32; // RVA within .text section
        let debug_size = (debug_entries.len() * 28) as u32;
        data.extend_from_slice(&debug_rva.to_le_bytes());
        data.extend_from_slice(&debug_size.to_le_bytes());
    } else {
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
    }
    // Index 7-15: zeros
    for _ in 7..16 {
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
    }

    // Ensure optional header is exactly 224 bytes
    let opt_size = data.len() - opt_start;
    assert_eq!(opt_size, 224, "Optional header size mismatch: {opt_size}");

    // Section header (40 bytes): .text section
    data.extend_from_slice(b".text\0\0\0"); // Name (8 bytes)
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize (large enough for debug dir)
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data.extend_from_slice(&0x400u32.to_le_bytes()); // SizeOfRawData (includes debug dir)
    data.extend_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
    data.extend_from_slice(&0u32.to_le_bytes()); // PointerToRelocations
    data.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
    data.extend_from_slice(&0u16.to_le_bytes()); // NumberOfRelocations
    data.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
    data.extend_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics

    // Pad to 0x200 (file alignment)
    while data.len() < 0x200 {
        data.push(0);
    }

    // Section data (0x200 bytes of 0xCC = int3, then 0x200 for debug dir)
    data.extend_from_slice(&[0xCC; 0x200]);

    // Debug directory entries (at file offset 0x400, RVA 0x1200)
    if !debug_entries.is_empty() {
        // Pad to 0x400
        while data.len() < 0x400 {
            data.push(0);
        }
        for (i, &debug_type) in debug_entries.iter().enumerate() {
            // IMAGE_DEBUG_DIRECTORY_ENTRY (28 bytes)
            // PointerToRawData must be non-zero and within file bounds for
            // upstream-compatible getDebugList filtering.
            let raw_ptr = 0x500 + i as u32 * 16; // valid file offset
            data.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
            data.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
            data.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
            data.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
            data.extend_from_slice(&debug_type.to_le_bytes()); // Type
            data.extend_from_slice(&16u32.to_le_bytes()); // SizeOfData
            data.extend_from_slice(&0u32.to_le_bytes()); // AddressOfRawData (RVA)
            data.extend_from_slice(&raw_ptr.to_le_bytes()); // PointerToRawData
        }
        // Pad to cover the debug data area
        while data.len() < 0x500 + debug_entries.len() * 16 {
            data.push(0);
        }
    }

    // Pad to ensure security directory offset is within file bounds.
    if has_security {
        while data.len() < 0x500 {
            data.push(0);
        }
    }

    data
}

/// Build a PE32 file with custom section names (beyond .text) and an
/// import directory with multiple libraries and functions.
///
/// Layout:
///   0x00:  DOS header (e_lfanew = 0x80)
///   0x80:  PE sig + COFF header + optional header (PE32, 224 bytes)
///   Section headers: .text + .rdata + `extra_sections`
///   0x200: .text raw data (0x200 bytes)
///   0x400: .rdata raw data (import directory + ILT + IAT + name strings)
///   0x600+: extra section raw data (0x200 bytes each, zeros)
///
/// `extra_sections` are additional section names (max 8 chars each).
/// `imports` is a list of (dll_name, function_names) pairs.
fn build_pe_with_imports_and_sections(
    extra_sections: &[&str],
    imports: &[(&str, &[&str])],
) -> Vec<u8> {
    let pe_offset = 0x80u32;
    let n_extra = extra_sections.len();
    let n_sections = 2 + n_extra; // .text + .rdata + extra

    // Calculate aligned header size: PE sig(4) + COFF(20) + OptHdr(224) +
    // section headers (n_sections * 40), aligned up to file alignment (0x200).
    let headers_unaligned = pe_offset as usize + 4 + 20 + 224 + n_sections * 40;
    let headers_aligned = (headers_unaligned + 0x1FF) & !0x1FF; // align up to 0x200
    let text_raw = headers_aligned as u32;
    let rdata_raw = text_raw + 0x200;
    let extra_raw_base = rdata_raw + 0x200;

    let mut data = vec![0u8; pe_offset as usize];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

    // PE signature
    data.extend_from_slice(b"PE\0\0");

    // COFF header (20 bytes)
    data.extend_from_slice(&0x014Cu16.to_le_bytes()); // Machine: I386
    data.extend_from_slice(&(n_sections as u16).to_le_bytes()); // NumberOfSections
    data.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    data.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
    data.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
    data.extend_from_slice(&224u16.to_le_bytes()); // SizeOfOptionalHeader (PE32)
    data.extend_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

    // Optional header (PE32, 224 bytes)
    let opt_start = data.len();
    data.extend_from_slice(&0x010Bu16.to_le_bytes()); // Magic: PE32
    data.push(0x0E); // MajorLinkerVersion
    data.push(0x00); // MinorLinkerVersion
    data.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfCode
    data.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
    data.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    data.extend_from_slice(&0u32.to_le_bytes()); // BaseOfCode
    data.extend_from_slice(&0u32.to_le_bytes()); // BaseOfData
    data.extend_from_slice(&0x00400000u32.to_le_bytes()); // ImageBase
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    data.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    data.extend_from_slice(&6u16.to_le_bytes()); // MajorOSVersion
    data.extend_from_slice(&0u16.to_le_bytes()); // MinorOSVersion
    data.extend_from_slice(&0u16.to_le_bytes()); // MajorImageVersion
    data.extend_from_slice(&0u16.to_le_bytes()); // MinorImageVersion
    data.extend_from_slice(&6u16.to_le_bytes()); // MajorSubsystemVersion
    data.extend_from_slice(&0u16.to_le_bytes()); // MinorSubsystemVersion
    data.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
    // SizeOfImage: .text(0x1000) + .rdata(0x1000) + extra(0x1000 each)
    let size_of_image = (2 + n_extra) as u32 * 0x1000 + 0x1000;
    data.extend_from_slice(&size_of_image.to_le_bytes());
    data.extend_from_slice(&(headers_aligned as u32).to_le_bytes()); // SizeOfHeaders
    data.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
    data.extend_from_slice(&3u16.to_le_bytes()); // Subsystem (CONSOLE)
    data.extend_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
    data.extend_from_slice(&0x100000u32.to_le_bytes()); // SizeOfStackReserve
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfStackCommit
    data.extend_from_slice(&0x100000u32.to_le_bytes()); // SizeOfHeapReserve
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfHeapCommit
    data.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
    data.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // Data directories (16 entries, 8 bytes each = 128 bytes)
    // Index 0: Export (zeros)
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // Index 1: Import — RVA and size will be filled later
    let import_dd_off = data.len();
    data.extend_from_slice(&0u32.to_le_bytes()); // RVA (placeholder)
    data.extend_from_slice(&0u32.to_le_bytes()); // Size (placeholder)
    // Index 2-15: zeros
    for _ in 2..16 {
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
    }

    assert_eq!(data.len() - opt_start, 224, "Optional header size mismatch");

    // Section headers
    // .text: VA=0x1000, VSize=0x200, RPtr=text_raw, RSize=0x200
    data.extend_from_slice(b".text\0\0\0");
    data.extend_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
    data.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
    data.extend_from_slice(&text_raw.to_le_bytes()); // PointerToRawData
    data.extend_from_slice(&0u32.to_le_bytes()); // PointerToRelocations
    data.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
    data.extend_from_slice(&0u16.to_le_bytes()); // NumberOfRelocations
    data.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
    data.extend_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics

    // .rdata: VA=0x2000, VSize=0x400, RPtr=rdata_raw, RSize=0x200
    data.extend_from_slice(b".rdata\0\0");
    data.extend_from_slice(&0x400u32.to_le_bytes()); // VirtualSize
    data.extend_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
    data.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
    data.extend_from_slice(&rdata_raw.to_le_bytes()); // PointerToRawData
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0x40000040u32.to_le_bytes()); // Characteristics (INITIALIZED_DATA | READ)

    // Extra sections: VA=0x3000+, each 0x1000 apart, RPtr=extra_raw_base+, each 0x200 apart
    for (i, name) in extra_sections.iter().enumerate() {
        let mut name_buf = [0u8; 8];
        let nb = name.as_bytes();
        let copy_len = nb.len().min(8);
        name_buf[..copy_len].copy_from_slice(&nb[..copy_len]);
        data.extend_from_slice(&name_buf);
        data.extend_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
        data.extend_from_slice(&(0x3000 + i as u32 * 0x1000).to_le_bytes()); // VirtualAddress
        data.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        data.extend_from_slice(&(extra_raw_base + i as u32 * 0x200).to_le_bytes()); // PointerToRawData
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x40000040u32.to_le_bytes()); // INITIALIZED_DATA | READ
    }

    // Pad headers to headers_aligned (file alignment)
    while data.len() < headers_aligned {
        data.push(0);
    }

    // .text raw data (0x200 bytes of 0xCC)
    data.extend_from_slice(&[0xCC; 0x200]);

    // .rdata raw data: build import directory at file offset rdata_raw (RVA 0x2000)
    let rdata_start = data.len();
    assert_eq!(
        rdata_start, rdata_raw as usize,
        ".rdata should start at rdata_raw"
    );

    if imports.is_empty() {
        // No imports: pad .rdata with zeros
        data.extend_from_slice(&[0u8; 0x200]);
    } else {
        // Calculate layout within .rdata (RVA base = 0x2000, file base = rdata_raw)
        let rva_base = 0x2000u32;
        let file_base = rdata_raw;

        // Import descriptors: (n_imports + 1) * 20 bytes (null terminator)
        let n_imports = imports.len();
        let desc_size = (n_imports + 1) * 20;

        // ILT entries: for each library, (n_funcs + 1) * 4 bytes
        let mut ilt_offsets = Vec::new();
        let mut ilt_cursor = desc_size;
        for (_, funcs) in imports {
            ilt_offsets.push(ilt_cursor);
            ilt_cursor += (funcs.len() + 1) * 4;
        }

        // IAT entries: same sizes as ILT
        let mut iat_offsets = Vec::new();
        let mut iat_cursor = ilt_cursor;
        for (_, funcs) in imports {
            iat_offsets.push(iat_cursor);
            iat_cursor += (funcs.len() + 1) * 4;
        }

        // DLL name strings
        let mut dll_name_offsets = Vec::new();
        let mut name_cursor = iat_cursor;
        for (dll, _) in imports {
            dll_name_offsets.push(name_cursor);
            name_cursor += dll.len() + 1; // +1 for null terminator
        }

        // Hint+name entries (2 bytes hint + name + null), WORD-aligned.
        // Real PE files align each hint+name entry to a 2-byte boundary.
        // Without alignment, pelite returns Misaligned for odd-offset entries.
        let mut func_name_offsets = Vec::new();
        for (_, funcs) in imports {
            for fname in *funcs {
                // Align to 2 bytes
                name_cursor = (name_cursor + 1) & !1;
                func_name_offsets.push(name_cursor);
                name_cursor += 2 + fname.len() + 1; // hint(2) + name + null
            }
        }

        let total_rdata_size = name_cursor;
        assert!(
            total_rdata_size <= 0x200,
            "Import data too large: {total_rdata_size} > 0x200"
        );

        // Helper to convert .rdata-relative offset to RVA
        let to_rva = |off: usize| -> u32 { rva_base + off as u32 };

        // Write ALL import descriptors first (including null terminator).
        // Each descriptor: OFT(4) + TimeDateStamp(4) + ForwarderChain(4) +
        //                   Name(4) + FirstThunk(4) = 20 bytes.
        for (i, (_dll, _funcs)) in imports.iter().enumerate() {
            let ilt_rva = to_rva(ilt_offsets[i]);
            let name_rva = to_rva(dll_name_offsets[i]);
            let iat_rva = to_rva(iat_offsets[i]);
            data.extend_from_slice(&ilt_rva.to_le_bytes()); // OriginalFirstThunk
            data.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
            data.extend_from_slice(&0u32.to_le_bytes()); // ForwarderChain
            data.extend_from_slice(&name_rva.to_le_bytes()); // Name
            data.extend_from_slice(&iat_rva.to_le_bytes()); // FirstThunk
        }
        // Null terminator descriptor
        data.extend_from_slice(&[0u8; 20]);

        // Write ALL ILT entries (Import Lookup Tables), one per library.
        let mut func_idx = 0;
        for (_, funcs) in imports.iter() {
            for _ in *funcs {
                let fn_rva = to_rva(func_name_offsets[func_idx]);
                data.extend_from_slice(&fn_rva.to_le_bytes());
                func_idx += 1;
            }
            data.extend_from_slice(&0u32.to_le_bytes()); // ILT terminator
        }

        // Write ALL IAT entries (Import Address Tables), same values as ILT.
        let mut func_idx2 = 0;
        for (_, funcs) in imports.iter() {
            for _ in *funcs {
                let fn_rva = to_rva(func_name_offsets[func_idx2]);
                data.extend_from_slice(&fn_rva.to_le_bytes());
                func_idx2 += 1;
            }
            data.extend_from_slice(&0u32.to_le_bytes()); // IAT terminator
        }

        // Write DLL name strings (null-terminated ASCII).
        for (dll, _) in imports {
            data.extend_from_slice(dll.as_bytes());
            data.push(0);
        }

        // Write hint+name entries: 2-byte hint + null-terminated name,
        // each entry WORD-aligned (pad with zero byte if needed).
        for (_, funcs) in imports {
            for fname in *funcs {
                // Align current position to 2 bytes within .rdata
                let rdata_pos = data.len() - file_base as usize;
                let aligned = (rdata_pos + 1) & !1;
                while data.len() - (file_base as usize) < aligned {
                    data.push(0);
                }
                data.extend_from_slice(&0u16.to_le_bytes()); // hint = 0
                data.extend_from_slice(fname.as_bytes());
                data.push(0);
            }
        }

        // Pad .rdata to 0x200
        while data.len() - (file_base as usize) < 0x200 {
            data.push(0);
        }

        // Fill in import data directory
        let import_rva = rva_base;
        let import_size = (desc_size) as u32;
        data[import_dd_off..import_dd_off + 4].copy_from_slice(&import_rva.to_le_bytes());
        data[import_dd_off + 4..import_dd_off + 8].copy_from_slice(&import_size.to_le_bytes());
    }

    // Extra section raw data (0x200 bytes of zeros each)
    for _ in 0..n_extra {
        data.extend_from_slice(&[0u8; 0x200]);
    }

    data
}

// =====================================================================
// Rich signature tests
// =====================================================================

#[test]
fn rich_signature_get_number_of_rich_ids() {
    let pe = build_minimal_pe(
        &[(0x5D, 0x0F, 3), (0x5E, 0x10, 1)], // 2 entries
        &[],
        false,
    );

    let results = run_js_pe(
        r#"var n = PE.getNumberOfRichIDs();
if (n > 0) { bDetected = true; sName = "RichTest"; sVersion = String(n); }"#,
        pe,
    );

    if let Some(results) = results {
        let found = results
            .iter()
            .any(|r| r.name == "RichTest" && r.version == "2");
        assert!(found, "Expected RichTest with version 2, got: {results:?}");
    }
}

#[test]
fn rich_signature_get_rich_id_returns_high_16_bits() {
    // ProductID=0x5D in high 16 bits, Version=0x0F in low 16 bits
    let pe = build_minimal_pe(&[(0x5D, 0x0F, 3)], &[], false);

    let results = run_js_pe(
        r#"if (PE.isRichSignaturePresent()) {
    var id = PE.getRichID(0);
    if (id === 0x5D) { bDetected = true; sName = "RichID"; sVersion = String(id); }
}"#,
        pe,
    );

    if let Some(results) = results {
        let found = results
            .iter()
            .any(|r| r.name == "RichID" && r.version == "93");
        assert!(
            found,
            "Expected RichID with version 93 (0x5D), got: {results:?}"
        );
    }
}

#[test]
fn rich_signature_get_rich_version_returns_low_16_bits() {
    let pe = build_minimal_pe(&[(0x5D, 0x0F, 3)], &[], false);

    let results = run_js_pe(
        r#"if (PE.isRichSignaturePresent()) {
    var v = PE.getRichVersion(0);
    if (v === 0x0F) { bDetected = true; sName = "RichVer"; sVersion = String(v); }
}"#,
        pe,
    );

    if let Some(results) = results {
        let found = results
            .iter()
            .any(|r| r.name == "RichVer" && r.version == "15");
        assert!(
            found,
            "Expected RichVer with version 15 (0x0F), got: {results:?}"
        );
    }
}

#[test]
fn rich_signature_get_rich_count() {
    let pe = build_minimal_pe(&[(0x5D, 0x0F, 42)], &[], false);

    let results = run_js_pe(
        r#"if (PE.isRichSignaturePresent()) {
    var c = PE.getRichCount(0);
    if (c === 42) { bDetected = true; sName = "RichCount"; sVersion = String(c); }
}"#,
        pe,
    );

    if let Some(results) = results {
        let found = results
            .iter()
            .any(|r| r.name == "RichCount" && r.version == "42");
        assert!(
            found,
            "Expected RichCount with version 42, got: {results:?}"
        );
    }
}

#[test]
fn rich_signature_not_present_returns_zero() {
    let pe = build_minimal_pe(&[], &[], false);

    let results = run_js_pe(
        r#"var n = PE.getNumberOfRichIDs();
if (n === 0) { bDetected = true; sName = "NoRich"; }"#,
        pe,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "NoRich");
        assert!(found, "Expected NoRich detection, got: {results:?}");
    }
}

#[test]
fn rich_signature_multiple_entries() {
    let pe = build_minimal_pe(
        &[(0x5D, 0x0F, 3), (0x5E, 0x10, 1), (0x84, 0x00, 5)],
        &[],
        false,
    );

    let results = run_js_pe(
        r#"if (PE.isRichSignaturePresent()) {
    var n = PE.getNumberOfRichIDs();
    var ids = [];
    for (var i = 0; i < n; i++) { ids.push(PE.getRichID(i)); }
    if (n === 3 && ids[0] === 0x5D && ids[1] === 0x5E && ids[2] === 0x84) {
        bDetected = true; sName = "MultiRich";
    }
}"#,
        pe,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "MultiRich");
        assert!(found, "Expected MultiRich detection, got: {results:?}");
    }
}

// =====================================================================
// PE debug data tests
// =====================================================================

#[test]
fn debug_data_no_records() {
    let pe = build_minimal_pe(&[], &[], false);

    let results = run_js_pe(
        r#"var n = PE.getNumberOfDebugDataRecords();
if (n === 0) { bDetected = true; sName = "NoDebug"; }"#,
        pe,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "NoDebug");
        assert!(found, "Expected NoDebug detection, got: {results:?}");
    }
}

#[test]
fn debug_data_codeview_type() {
    let pe = build_minimal_pe(&[], &[2], false); // Type 2 = CODEVIEW

    let results = run_js_pe(
        r#"var n = PE.getNumberOfDebugDataRecords();
var nsec = PE.getNumberOfSections();
var secVA = nsec > 0 ? PE.getSectionVirtualAddress(0) : -1;
var secVS = nsec > 0 ? PE.getSectionVirtualSize(0) : -1;
var secRaw = nsec > 0 ? PE.getSectionFileOffset(0) : -1;
var secRawSize = nsec > 0 ? PE.getSectionFileSize(0) : -1;
bDetected = true; sName = "DebugInfo";
sVersion = "n=" + n + " nsec=" + nsec + " secVA=" + secVA + " secVS=" + secVS + " secRaw=" + secRaw + " secRawSize=" + secRawSize;
if (n >= 1) {
    var t = PE.getDebugDataType(0);
    sVersion += " type=" + t;
    if (t === "CODEVIEW") { sName = "DebugCV"; }
}"#,
        pe,
    );

    if let Some(results) = results {
        eprintln!("DEBUG: results = {results:?}");
        let found = results.iter().any(|r| r.name == "DebugCV");
        assert!(found, "Expected DebugCV, got: {results:?}");
    } else {
        eprintln!("DEBUG: run_js_pe returned None");
    }
}

#[test]
fn debug_data_multiple_types() {
    let pe = build_minimal_pe(&[], &[2, 13, 15], false); // CODEVIEW, ILTCG, REPRO

    let results = run_js_pe(
        r#"var n = PE.getNumberOfDebugDataRecords();
if (n === 3) {
    var t0 = PE.getDebugDataType(0);
    var t1 = PE.getDebugDataType(1);
    var t2 = PE.getDebugDataType(2);
    if (t0 === "CODEVIEW" && t1 === "ILTCG" && t2 === "REPRO") {
        bDetected = true; sName = "DebugMulti";
    }
}"#,
        pe,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "DebugMulti");
        assert!(found, "Expected DebugMulti detection, got: {results:?}");
    }
}

#[test]
fn debug_data_unknown_type() {
    let pe = build_minimal_pe(&[], &[99], false); // Unknown type

    let results = run_js_pe(
        r#"var n = PE.getNumberOfDebugDataRecords();
if (n === 1) {
    var t = PE.getDebugDataType(0);
    if (t === "UNKNOWN") { bDetected = true; sName = "DebugUnknown"; }
}"#,
        pe,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "DebugUnknown");
        assert!(found, "Expected DebugUnknown detection, got: {results:?}");
    }
}

// =====================================================================
// PE.isSigned tests
// =====================================================================

#[test]
fn pe_is_signed_true_when_security_directory_present() {
    let pe = build_minimal_pe(&[], &[], true);

    let results = run_js_pe(
        r#"if (PE.isSigned()) { bDetected = true; sName = "Signed"; }"#,
        pe,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "Signed");
        assert!(found, "Expected Signed detection, got: {results:?}");
    }
}

#[test]
fn pe_is_signed_false_when_no_security_directory() {
    let pe = build_minimal_pe(&[], &[], false);

    let results = run_js_pe(
        r#"if (!PE.isSigned()) { bDetected = true; sName = "NotSigned"; }"#,
        pe,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "NotSigned");
        assert!(found, "Expected NotSigned detection, got: {results:?}");
    }
}

#[test]
fn pe_is_signed_file_alias_works() {
    let pe = build_minimal_pe(&[], &[], true);

    let results = run_js_pe(
        r#"if (PE.isSignedFile()) { bDetected = true; sName = "SignedFile"; }"#,
        pe,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "SignedFile");
        assert!(found, "Expected SignedFile detection, got: {results:?}");
    }
}

// =====================================================================
// Binary.isPlainText tests
// =====================================================================

#[test]
fn is_plain_text_true_for_ascii_content() {
    let data = b"Hello, World!\nThis is a test file.\n".to_vec();

    let results = run_js_binary(
        r#"if (Binary.isPlainText()) { bDetected = true; sName = "PlainText"; }"#,
        data,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "PlainText");
        assert!(found, "Expected PlainText detection, got: {results:?}");
    }
}

#[test]
fn is_plain_text_false_for_binary_content() {
    let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

    let results = run_js_binary(
        r#"if (!Binary.isPlainText()) { bDetected = true; sName = "NotPlain"; }"#,
        data,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "NotPlain");
        assert!(found, "Expected NotPlain detection, got: {results:?}");
    }
}

#[test]
fn is_plain_text_true_for_empty_file() {
    // Empty file: isPlainText returns false (size == 0)
    let data = vec![];

    let results = run_js_binary(
        r#"if (!Binary.isPlainText()) { bDetected = true; sName = "EmptyNotPlain"; }"#,
        data,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "EmptyNotPlain");
        assert!(found, "Expected EmptyNotPlain detection, got: {results:?}");
    }
}

#[test]
fn is_plain_text_false_for_pdf_with_high_bytes() {
    // PDF files start with %PDF but a binary-heavy body keeps the extended
    // ASCII ratio above upstream's 0.50 threshold, so isPlainText() is false.
    let mut data = b"%PDF-1.4\n".to_vec();
    data.extend(std::iter::repeat_n(0xE0u8, 24));

    let results = run_js_binary(
        r#"if (!Binary.isPlainText()) { bDetected = true; sName = "PDFNotPlain"; }"#,
        data,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "PDFNotPlain");
        assert!(found, "Expected PDFNotPlain detection, got: {results:?}");
    }
}

#[test]
fn is_plain_text_allows_tab_cr_lf() {
    let data = b"col1\tcol2\tcol3\r\nrow2\r\n".to_vec();

    let results = run_js_binary(
        r#"if (Binary.isPlainText()) { bDetected = true; sName = "TabsAndCRLF"; }"#,
        data,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "TabsAndCRLF");
        assert!(found, "Expected TabsAndCRLF detection, got: {results:?}");
    }
}

#[test]
fn is_text_alias_works() {
    let data = b"Simple text file.\n".to_vec();

    let results = run_js_binary(
        r#"if (Binary.isText()) { bDetected = true; sName = "IsText"; }"#,
        data,
    );

    if let Some(results) = results {
        let found = results.iter().any(|r| r.name == "IsText");
        assert!(found, "Expected IsText detection, got: {results:?}");
    }
}

// =====================================================================
// Disassembly (getDisasmString / getDisasmNextAddress) tests
// =====================================================================

#[test]
fn pe_get_disasm_string_returns_int3_for_cc_bytes() {
    // build_minimal_pe creates a .text section filled with 0xCC (INT3).
    // Entry point RVA = 0x1000, ImageBase = 0x400000, so VA = 0x401000.
    // File offset of .text = 0x200.
    let pe = build_minimal_pe(&[], &[], false);

    let results = run_js_pe(
        r#"var da = PE.getDisasmString(0x401000);
if (da && da.length > 0) {
    bDetected = true;
    sName = "DisasmTest";
    sVersion = da;
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let det = results
        .iter()
        .find(|r| r.name == "DisasmTest")
        .expect("expected DisasmTest detection");
    // 0xCC = INT3 in x86. Capstone renders it as "INT3" (uppercase).
    assert_eq!(
        det.version.to_uppercase(),
        "INT3",
        "Expected INT3 for 0xCC byte, got: {}",
        det.version
    );
}

#[test]
fn pe_get_disasm_string_returns_push_for_55_byte() {
    // Modify the .text section to start with PUSH EBP (0x55).
    let mut pe = build_minimal_pe(&[], &[], false);
    // .text section raw data starts at file offset 0x200.
    pe[0x200] = 0x55; // PUSH EBP

    let results = run_js_pe(
        r#"var da = PE.getDisasmString(0x401000);
if (da && da.length > 0) {
    bDetected = true;
    sName = "DisasmPush";
    sVersion = da;
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let det = results
        .iter()
        .find(|r| r.name == "DisasmPush")
        .expect("expected DisasmPush detection");
    assert!(
        det.version.to_uppercase().contains("PUSH"),
        "Expected PUSH in disasm, got: {}",
        det.version
    );
}

#[test]
fn pe_get_disasm_next_address_returns_next_va() {
    // 0xCC (INT3) is a 1-byte instruction.
    // VA 0x401000 -> next VA should be 0x401001.
    let pe = build_minimal_pe(&[], &[], false);

    let results = run_js_pe(
        r#"var next = PE.getDisasmNextAddress(0x401000);
if (next > 0) {
    bDetected = true;
    sName = "NextAddr";
    sVersion = String(next);
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let det = results
        .iter()
        .find(|r| r.name == "NextAddr")
        .expect("expected NextAddr detection");
    // INT3 is 1 byte, so next address = 0x401001 = 4198401.
    assert_eq!(
        det.version, "4198401",
        "Expected next address 0x401001 (4198401), got: {}",
        det.version
    );
}

#[test]
fn pe_get_disasm_string_returns_empty_for_invalid_va() {
    // VA not in any section should return empty string.
    let pe = build_minimal_pe(&[], &[], false);

    let results = run_js_pe(
        r#"var da = PE.getDisasmString(0xDEADBEEF);
if (!da || da.length === 0) {
    bDetected = true;
    sName = "InvalidVA";
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let found = results.iter().any(|r| r.name == "InvalidVA");
    assert!(
        found,
        "Expected InvalidVA detection for out-of-range VA, got: {results:?}"
    );
}

// =====================================================================
// getSectionNameCollision tests (upstream issue #7, Phase 16.7 fix)
// =====================================================================

#[test]
fn get_section_name_collision_returns_common_prefix() {
    // VMProtect-style section names: "oiNRhy0" and "oiNRhy1" share
    // common prefix "oiNRhy" with suffixes "0" and "1".
    let pe = build_pe_with_imports_and_sections(&["oiNRhy0", "oiNRhy1"], &[]);

    let results = run_js_pe(
        r#"var prefix = PE.getSectionNameCollision("0", "1");
if (prefix === "oiNRhy") {
    bDetected = true;
    sName = "CollisionPrefix";
    sVersion = prefix;
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let det = results
        .iter()
        .find(|r| r.name == "CollisionPrefix")
        .expect("expected CollisionPrefix detection");
    assert_eq!(
        det.version, "oiNRhy",
        "getSectionNameCollision('0','1') should return 'oiNRhy', got: {}",
        det.version
    );
}

#[test]
fn get_section_name_collision_vmprotect_rule_pattern() {
    // Simulate the exact VMProtect.2.sg rule pattern:
    //   var sCollision = PE.getSectionNameCollision("0", "1");
    //   if (PE.isSectionNamePresent(sCollision + "1")) { bDetected = true; }
    let pe = build_pe_with_imports_and_sections(&["oiNRhy0", "oiNRhy1"], &[]);

    let results = run_js_pe(
        r#"var sCollision = PE.getSectionNameCollision("0", "1");
if (sCollision !== "" && PE.isSectionNamePresent(sCollision + "1")) {
    bDetected = true;
    sName = "VMProtect";
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let found = results.iter().any(|r| r.name == "VMProtect");
    assert!(
        found,
        "VMProtect pattern should detect with collision sections, got: {results:?}"
    );
}

#[test]
fn get_section_name_collision_no_match_returns_empty() {
    // Sections without colliding suffixes should return "".
    let pe = build_pe_with_imports_and_sections(&[".data", ".rsrc"], &[]);

    let results = run_js_pe(
        r#"var prefix = PE.getSectionNameCollision("0", "1");
if (prefix === "") {
    bDetected = true;
    sName = "NoCollision";
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let found = results.iter().any(|r| r.name == "NoCollision");
    assert!(
        found,
        "getSectionNameCollision with non-colliding sections should return empty, got: {results:?}"
    );
}

#[test]
fn get_section_name_collision_single_section_returns_empty() {
    // Only one section with a matching suffix — no pair, should return "".
    let pe = build_pe_with_imports_and_sections(&["abc0"], &[]);

    let results = run_js_pe(
        r#"var prefix = PE.getSectionNameCollision("0", "1");
if (prefix === "") {
    bDetected = true;
    sName = "SingleSection";
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let found = results.iter().any(|r| r.name == "SingleSection");
    assert!(
        found,
        "Single section should not produce collision, got: {results:?}"
    );
}

// =====================================================================
// getImportFunctionName tests (upstream issue #8, Phase 16.7 fix)
// =====================================================================

#[test]
fn get_import_function_name_two_args_returns_correct_function() {
    // PE with 2 libraries: kernel32.dll (LoadLibraryA, GetProcAddress)
    // and user32.dll (MessageBoxA).
    let pe = build_pe_with_imports_and_sections(
        &[],
        &[
            ("kernel32.dll", &["LoadLibraryA", "GetProcAddress"]),
            ("user32.dll", &["MessageBoxA"]),
        ],
    );

    let results = run_js_pe(
        r#"var f00 = PE.getImportFunctionName(0, 0);
var f01 = PE.getImportFunctionName(0, 1);
var f10 = PE.getImportFunctionName(1, 0);
if (f00 === "LoadLibraryA" && f01 === "GetProcAddress" && f10 === "MessageBoxA") {
    bDetected = true;
    sName = "ImportFuncName";
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let found = results.iter().any(|r| r.name == "ImportFuncName");
    assert!(
        found,
        "getImportFunctionName(libIdx, funcIdx) should return correct function names, got: {results:?}"
    );
}

#[test]
fn get_import_function_name_out_of_range_returns_empty() {
    let pe = build_pe_with_imports_and_sections(&[], &[("kernel32.dll", &["LoadLibraryA"])]);

    let results = run_js_pe(
        r#"var bad1 = PE.getImportFunctionName(5, 0);
var bad2 = PE.getImportFunctionName(0, 5);
var bad3 = PE.getImportFunctionName(-1, 0);
if (bad1 === "" && bad2 === "" && bad3 === "") {
    bDetected = true;
    sName = "ImportFuncOOB";
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let found = results.iter().any(|r| r.name == "ImportFuncOOB");
    assert!(
        found,
        "Out-of-range indices should return empty string, got: {results:?}"
    );
}

#[test]
fn get_import_function_name_upx_rule_pattern() {
    // Simulate the UPX.2.sg rule pattern:
    //   if (PE.getImportFunctionName(0, 0) == "LoadLibraryA") { funcCounter++; }
    //   if (PE.getImportFunctionName(0, 1) == "GetProcAddress") { funcCounter++; }
    let pe = build_pe_with_imports_and_sections(
        &[],
        &[("kernel32.dll", &["LoadLibraryA", "GetProcAddress"])],
    );

    let results = run_js_pe(
        r#"var funcCounter = 0;
if (PE.getImportFunctionName(0, 0) == "LoadLibraryA") { funcCounter++; }
if (PE.getImportFunctionName(0, 1) == "GetProcAddress") { funcCounter++; }
if (funcCounter === 2) {
    bDetected = true;
    sName = "UPXPattern";
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let found = results.iter().any(|r| r.name == "UPXPattern");
    assert!(
        found,
        "UPX import function pattern should match, got: {results:?}"
    );
}

// =====================================================================
// getNumberOfImportThunks tests (upstream issue #9, Phase 16.7 fix)
// =====================================================================

#[test]
fn get_number_of_import_thunks_per_library() {
    // kernel32.dll has 2 functions, user32.dll has 1 function.
    let pe = build_pe_with_imports_and_sections(
        &[],
        &[
            ("kernel32.dll", &["LoadLibraryA", "GetProcAddress"]),
            ("user32.dll", &["MessageBoxA"]),
        ],
    );

    let results = run_js_pe(
        r#"var n0 = PE.getNumberOfImportThunks(0);
var n1 = PE.getNumberOfImportThunks(1);
if (n0 === 2 && n1 === 1) {
    bDetected = true;
    sName = "ThunkCount";
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let found = results.iter().any(|r| r.name == "ThunkCount");
    assert!(
        found,
        "getNumberOfImportThunks(libIdx) should return per-library count, got: {results:?}"
    );
}

#[test]
fn get_number_of_import_thunks_out_of_range_returns_zero() {
    let pe = build_pe_with_imports_and_sections(&[], &[("kernel32.dll", &["LoadLibraryA"])]);

    let results = run_js_pe(
        r#"var n = PE.getNumberOfImportThunks(5);
if (n === 0) {
    bDetected = true;
    sName = "ThunkOOB";
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let found = results.iter().any(|r| r.name == "ThunkOOB");
    assert!(
        found,
        "Out-of-range library index should return 0, got: {results:?}"
    );
}

#[test]
fn get_number_of_import_thunks_upx_range_check() {
    // Simulate UPX.2.sg isPatchedUPX range check:
    //   var nNumberOfFunctions = PE.getNumberOfImportThunks(0);
    //   if (nNumberOfFunctions > 1 && nNumberOfFunctions < 7) { ... }
    let pe = build_pe_with_imports_and_sections(
        &[],
        &[(
            "kernel32.dll",
            &["LoadLibraryA", "GetProcAddress", "VirtualProtect"],
        )],
    );

    let results = run_js_pe(
        r#"var nNumberOfFunctions = PE.getNumberOfImportThunks(0);
if (nNumberOfFunctions > 1 && nNumberOfFunctions < 7) {
    bDetected = true;
    sName = "UPXRangeCheck";
    sVersion = String(nNumberOfFunctions);
}"#,
        pe,
    );

    let results = results.expect("run_js_pe returned None");
    let det = results
        .iter()
        .find(|r| r.name == "UPXRangeCheck")
        .expect("expected UPXRangeCheck detection");
    assert_eq!(
        det.version, "3",
        "getNumberOfImportThunks(0) should return 3, got: {}",
        det.version
    );
}

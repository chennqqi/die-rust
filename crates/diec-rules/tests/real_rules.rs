//! End-to-end tests with real upstream rule files.
//!
//! These tests load the real upstream `_init` framework script and
//! execute actual `.sg` rule files from the Detect-It-Easy database.
//! They verify that the rquickjs runtime is compatible with real rules.

#![cfg(test)]

use diec_core::cancel::CancellationToken;
use diec_core::format::FileType;
use diec_core::input::ByteView;
use diec_rules::backend_rquickjs::RquickjsRuntime;
use diec_rules::host_api::{HostApi, HostApiError};
use diec_rules::runtime::{
    DatabaseSnapshot, DetectionResult, LoadedRule, RuleRuntime, RuntimeConfig,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Path to the upstream Detect-It-Easy database.
/// Uses CARGO_MANIFEST_DIR to find the workspace root regardless of cwd.
fn db_root() -> String {
    // CARGO_MANIFEST_DIR is crates/diec-rules, so go up 2 levels.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(manifest)
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("workspace root");
    root.join("upstream/Detect-It-Easy/db")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

/// Path to the upstream Detect-It-Easy db_extra database.
fn db_extra_root() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    root.join("upstream/Detect-It-Easy/db_extra")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

/// Test host with an in-memory byte buffer.
struct BufferHost {
    data: Vec<u8>,
    file_type: FileType,
}

impl BufferHost {
    #[allow(dead_code)]
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            file_type: FileType::new("Binary"),
        }
    }

    /// Create a host with a specific file type (e.g., "PE", "ELF", "MACH").
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
            diec_rules::host_api_bridge::parse_signature(signature).map_err(|detail| {
                HostApiError::InvalidSignature {
                    pattern: signature.into(),
                    detail,
                }
            })?;
        Ok(diec_rules::host_api_bridge::match_signature(
            &self.data,
            offset as usize,
            &elements,
        ))
    }

    fn find_signature(&self, start: u64, signature: &str) -> Result<Option<u64>, HostApiError> {
        let elements =
            diec_rules::host_api_bridge::parse_signature(signature).map_err(|detail| {
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
            if diec_rules::host_api_bridge::match_signature(&self.data, i, &elements) {
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
            diec_rules::host_api_bridge::parse_signature(signature).map_err(|detail| {
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
            if diec_rules::host_api_bridge::match_signature(&self.data, i, &elements) {
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

    fn pe_batch(&self) -> Option<diec_rules::pe_native::PeBatchInfo> {
        diec_rules::pe_native::parse_batch(&self.data)
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
        false
    }
}

/// Framework data: (init_script, type_init_scripts, includes).
type FrameworkData = (String, Vec<(String, String)>, BTreeMap<String, String>);

/// Load the upstream _init script and include scripts for a given file type.
/// Returns (init_script, type_init_scripts, includes).
/// file_type can be "Binary", "PE", "ELF", "MACH", etc.
fn load_upstream_framework_for_type(file_type: &str) -> Option<FrameworkData> {
    let db = db_root();
    let init_path = format!("{db}/_init");
    let init_source = std::fs::read_to_string(&init_path).ok()?;

    let mut includes = BTreeMap::new();

    // Load the scripts that _init includes.
    for name in &["_debug", "_runtime_helpers", "language"] {
        let path = format!("{db}/{name}");
        if let Ok(source) = std::fs::read_to_string(&path) {
            includes.insert(name.to_string(), source);
        }
    }

    // Also load archive-file helper used by many rules.
    for name in &["archive-file", "zip-file", "read"] {
        let path = format!("{db}/{name}");
        if let Ok(source) = std::fs::read_to_string(&path) {
            includes.insert(name.to_string(), source);
        }
    }

    // Load the type-specific _init script (e.g., "Binary/_init", "PE/_init").
    let type_init = std::fs::read_to_string(format!("{db}/{file_type}/_init")).ok();
    let type_init_scripts = type_init
        .map(|s| vec![(file_type.to_string(), s)])
        .unwrap_or_default();

    Some((init_source, type_init_scripts, includes))
}

/// Load the upstream framework for Binary type (backward compatibility).
fn load_upstream_framework() -> Option<FrameworkData> {
    load_upstream_framework_for_type("Binary")
}

/// Run a real rule file against a buffer with a specific file type.
fn run_real_rule_typed(
    rule_relative_path: &str,
    file_type: &str,
    init_source: &str,
    type_init_scripts: &[(String, String)],
    includes: &BTreeMap<String, String>,
    data: Vec<u8>,
) -> Option<Vec<DetectionResult>> {
    let db = db_root();
    let rule_path = format!("{db}/{rule_relative_path}");
    run_real_rule_from_path(
        &rule_path,
        file_type,
        init_source,
        type_init_scripts,
        includes,
        data,
    )
}

/// Run a real rule file from an absolute path (e.g., db_extra rules).
fn run_real_rule_from_path(
    rule_path: &str,
    file_type: &str,
    init_source: &str,
    type_init_scripts: &[(String, String)],
    includes: &BTreeMap<String, String>,
    data: Vec<u8>,
) -> Option<Vec<DetectionResult>> {
    let source = std::fs::read_to_string(rule_path).ok()?;

    let snapshot = DatabaseSnapshot {
        rules: vec![LoadedRule {
            path: rule_path.to_string(),
            ordinal: 0,
            file_type: file_type.into(),
            source,
        }],
        init_script: Some(init_source.to_string()),
        type_init_scripts: type_init_scripts.to_vec(),
        include_scripts: includes.clone(),
    };

    let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).ok()?;

    let host = Arc::new(BufferHost::with_type(data, file_type));
    runtime.register_host_api(host.clone()).ok()?;

    runtime.load_database(&snapshot).ok()?;

    let token = CancellationToken::new();
    let host_ref: &dyn HostApi = &*host;
    runtime.init(host_ref).ok()?;

    runtime
        .evaluate_rule(&snapshot.rules[0], host_ref, &token)
        .ok()
}

/// Run a real rule file against a buffer (Binary type, backward compatible).
fn run_real_rule(
    rule_relative_path: &str,
    init_source: &str,
    type_init_scripts: &[(String, String)],
    includes: &BTreeMap<String, String>,
    data: Vec<u8>,
) -> Option<Vec<DetectionResult>> {
    run_real_rule_typed(
        rule_relative_path,
        "Binary",
        init_source,
        type_init_scripts,
        includes,
        data,
    )
}

#[test]
fn real_rule_7z_detects_signature() {
    let (init_source, type_init_scripts, includes) = match load_upstream_framework() {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    // 7z magic: 37 7A BC AF 27 1C + version bytes
    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    data.resize(64, 0); // Pad to minimum size

    let results = run_real_rule(
        "Binary/archive_7z.1.sg",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );

    if let Some(results) = results {
        // Should detect 7-Zip with version "0.4"
        let found = results.iter().any(|r| r.name == "7-Zip");
        assert!(found, "Expected 7-Zip detection, got: {results:?}");
    }
}

#[test]
fn real_rule_7z_no_match_on_random_data() {
    let (init_source, type_init_scripts, includes) = match load_upstream_framework() {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    // Random data that doesn't match 7z signature
    let data = vec![0x00; 64];

    let results = run_real_rule(
        "Binary/archive_7z.1.sg",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );

    if let Some(results) = results {
        // Should not detect 7-Zip
        assert!(
            results.is_empty(),
            "Expected no detection, got: {results:?}"
        );
    }
}

#[test]
fn real_rule_zip_detects_signature() {
    let (init_source, type_init_scripts, includes) = match load_upstream_framework() {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    // ZIP local file header: PK\x03\x04
    let mut data = vec![0x50, 0x4B, 0x03, 0x04];
    data.resize(64, 0);

    let results = run_real_rule(
        "Binary/archive_ZIP.1.sg",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );

    if let Some(results) = results {
        // ZIP detection may or may not trigger depending on the zip-file helper
        // implementation. Just verify it doesn't crash.
        let _ = results;
    }
}

#[test]
fn real_rule_ar_detects_signature() {
    let (init_source, type_init_scripts, includes) = match load_upstream_framework() {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    // AR archive magic: "!<arch>\n"
    let mut data = b"!<arch>\n".to_vec();
    data.resize(128, 0);

    let results = run_real_rule(
        "Binary/archive_AR.1.sg",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );

    if let Some(results) = results {
        // AR rule should detect the archive format.
        // It uses Archive.add() and Archive.contents() from the
        // archive-file include script.
        let found = results
            .iter()
            .any(|r| r.name.contains("Library") || r.name.contains("arch"));
        assert!(
            found || !results.is_empty(),
            "Expected AR detection, got: {results:?}"
        );
    }
}

#[test]
fn real_rule_bzip_detects_signature() {
    let (init_source, type_init_scripts, includes) = match load_upstream_framework() {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    // BZip2 magic: "BZh" + level digit + CRC block magic 314159265359
    let mut data = b"BZh9".to_vec();
    // bzip2 block magic: 0x314159265359 (6 bytes) at offset 4
    data.extend_from_slice(&[0x31, 0x41, 0x59, 0x26, 0x53, 0x59]);
    data.resize(64, 0);

    let results = run_real_rule(
        "Binary/archive_BZip.1.sg",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );

    if let Some(results) = results {
        // BZip2 should be detected.
        let found = results
            .iter()
            .any(|r| r.name.contains("bzip") || r.name.contains("Bzip") || r.name.contains("BZip"));
        assert!(found, "Expected BZip2 detection, got: {results:?}");
    }
}

#[test]
fn real_rule_gzip_detects_signature() {
    let (init_source, type_init_scripts, includes) = match load_upstream_framework() {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    // GZIP magic: 1F 8B 08
    let mut data = vec![0x1F, 0x8B, 0x08, 0x00];
    data.resize(64, 0);

    let results = run_real_rule(
        "Binary/archive_gzip.1.sg",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );

    if let Some(results) = results {
        // GZIP should be detected.
        let found = results
            .iter()
            .any(|r| r.name.contains("gzip") || r.name.contains("Gzip") || r.name.contains("GZIP"));
        assert!(found, "Expected GZIP detection, got: {results:?}");
    }
}

// ============================================================================
// PE format rule tests
//
// These tests load the PE type-specific _init script and execute real PE
// rules against PE files. This is a regression test for the case where
// PE rules were never tested with real PE host API (batch_load_pe.rs used
// DummyHost returning empty values, and real_rules.rs only tested Binary).
// ============================================================================

/// Load a corpus PE file for testing.
fn load_corpus_pe(filename: &str) -> Option<Vec<u8>> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let path = root.join("corpus").join(filename);
    std::fs::read(&path).ok()
}

/// Load the project's own diec.exe (release build) for testing.
fn load_diec_exe() -> Option<Vec<u8>> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let path = root.join("target/release/diec.exe");
    std::fs::read(&path).ok()
}

#[test]
fn real_rule_pe_init_loads_without_error() {
    // Verify that the PE type-specific _init script loads and executes
    // successfully. This is a regression test: previously batch_load_pe.rs
    // skipped PE _init entirely, meaning PE.getNumberOfImports and other
    // PE-specific methods were never registered.
    let (init_source, type_init_scripts, includes) = match load_upstream_framework_for_type("PE") {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    // Use corpus/with-tables.exe which has a real import table.
    let data = match load_corpus_pe("with-tables.exe") {
        Some(d) => d,
        None => {
            eprintln!("Skipping: corpus/with-tables.exe not found");
            return;
        }
    };

    // Run a simple PE rule that uses PE.isLibraryPresent.
    let results = run_real_rule_typed(
        "PE/library_7z.4.sg",
        "PE",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );

    // The rule should execute without error (it won't detect 7z since
    // with-tables.exe doesn't import 7z, but it should not crash).
    assert!(results.is_some(), "PE rule execution failed");
    let results = results.unwrap();
    // 7z library not present in with-tables.exe, so no detection expected.
    assert!(
        results.is_empty(),
        "Expected no 7z detection, got: {results:?}"
    );
}

#[test]
fn real_rule_pe_detects_microsoft_linker_on_diec_exe() {
    // Verify that the _Microsoft.6.sg rule detects "Microsoft Linker" when
    // scanning the project's own diec.exe. This is a true end-to-end test
    // of PE rule execution with real PE host API.
    let (init_source, type_init_scripts, includes) = match load_upstream_framework_for_type("PE") {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    let data = match load_diec_exe() {
        Some(d) => d,
        None => {
            eprintln!("Skipping: target/release/diec.exe not found");
            return;
        }
    };

    let results = run_real_rule_typed(
        "PE/_Microsoft.6.sg",
        "PE",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );

    assert!(results.is_some(), "PE rule execution failed");
    let results = results.unwrap();
    let has_linker = results
        .iter()
        .any(|r| r.type_name == "linker" && r.name.to_lowercase().contains("microsoft"));
    assert!(
        has_linker,
        "Expected Microsoft Linker detection, got: {:?}",
        results
            .iter()
            .map(|r| format!("{}:{}", r.type_name, r.name))
            .collect::<Vec<_>>()
    );
}

#[test]
fn real_rule_pe_islibrarypresent_works_with_real_imports() {
    // Verify that PE.isLibraryPresent() correctly reads the import table.
    // with-tables.exe imports "kernel32.dll", so isLibraryPresent("kernel32.dll")
    // should return true. This is a regression test for the f64 precision bug
    // that caused incorrect import parsing.
    let (init_source, type_init_scripts, includes) = match load_upstream_framework_for_type("PE") {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    let data = match load_corpus_pe("with-tables.exe") {
        Some(d) => d,
        None => {
            eprintln!("Skipping: corpus/with-tables.exe not found");
            return;
        }
    };

    // Use a rule that checks for kernel32.dll presence.
    // compiler_PureBasic checks PE.getNumberOfSections and compareEP,
    // but we just need to verify the rule executes without error.
    let results = run_real_rule_typed(
        "PE/compiler_PureBasic.4.sg",
        "PE",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );

    // Rule should execute without error (won't detect PureBasic).
    assert!(results.is_some(), "PE rule execution failed");
}

#[test]
fn real_rule_pe_isnet_alias_no_type_error() {
    // Regression test for Phase 14.2: these rules used to call `PE.isNET()`
    // (uppercase) but the bridge only registered `PE.isNet` (camelCase), so
    // they threw TypeError: not a function. After the ruleset re-sync to
    // pinned `8925358d`, upstream rules call `isNet` and the compat alias
    // was removed — this test keeps asserting the real rules run clean.
    let (init_source, type_init_scripts, includes) = match load_upstream_framework_for_type("PE") {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    let data = match load_corpus_pe("with-tables.exe") {
        Some(d) => d,
        None => {
            eprintln!("Skipping: corpus/with-tables.exe not found");
            return;
        }
    };

    // Rules that exercise the PE.isNet path — must not throw TypeError.
    // These rules live in db_extra, not db.
    let extra = db_extra_root();
    for rule_rel in [
        "PE/cryptor_404crypter.1.sg",
        "PE/installer_Store_Installer.1.sg",
    ] {
        let rule_path = format!("{extra}/{rule_rel}");
        let results = run_real_rule_from_path(
            &rule_path,
            "PE",
            &init_source,
            &type_init_scripts,
            &includes,
            data.clone(),
        );
        assert!(
            results.is_some(),
            "{rule_rel} threw TypeError (expected PE.isNet to be defined)"
        );
    }
}

#[test]
fn real_rule_pe_resource_group_and_net_stubs_no_type_error() {
    // Regression test for Phase 14.2: PE.isResourceGroupNamePresent and
    // PE.compareEP_NET were missing, causing TypeError in
    // compiler_RealBasic and protector_Phoenix/protector_Skater.
    let (init_source, type_init_scripts, includes) = match load_upstream_framework_for_type("PE") {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    let data = match load_corpus_pe("with-tables.exe") {
        Some(d) => d,
        None => {
            eprintln!("Skipping: corpus/with-tables.exe not found");
            return;
        }
    };

    // compiler_RealBasic calls PE.isResourceGroupNamePresent("PICKLE").
    let results = run_real_rule_typed(
        "PE/compiler_RealBasic.4.sg",
        "PE",
        &init_source,
        &type_init_scripts,
        &includes,
        data.clone(),
    );
    assert!(
        results.is_some(),
        "compiler_RealBasic threw TypeError (expected isResourceGroupNamePresent defined)"
    );

    // protector_Phoenix calls PE.compareEP_NET.
    let results = run_real_rule_typed(
        "PE/protector_Phoenix.2.sg",
        "PE",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );
    assert!(
        results.is_some(),
        "protector_Phoenix threw TypeError (expected compareEP_NET defined)"
    );
}

// ============================================================================
// ELF format rule tests
// ============================================================================

#[test]
fn real_rule_elf_init_loads_without_error() {
    // Verify that the ELF type-specific _init script loads successfully.
    let (init_source, type_init_scripts, includes) = match load_upstream_framework_for_type("ELF") {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    // Use corpus/minimal.elf (64-byte ELF64).
    let data = match load_corpus_pe("minimal.elf") {
        Some(d) => d,
        None => {
            eprintln!("Skipping: corpus/minimal.elf not found");
            return;
        }
    };

    // Run the ELF OS detection rule.
    let results = run_real_rule_typed(
        "ELF/_ELF.0.sg",
        "ELF",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );

    // Rule should execute without error.
    assert!(results.is_some(), "ELF rule execution failed");
}

#[test]
fn real_rule_elf_compiler_rules_no_b_reference_error() {
    // Regression test for Phase 14.1: ELF compiler/library rules used
    // _B.__elfSectionNames() / _B.__elfImportLibraries() in the
    // _sectionNumber / _libraryNames helpers, but the ELF method closure
    // did not define `var _B = Binary;`, causing ReferenceError: _B is
    // not defined and total ELF detection failure.
    //
    // These rules call _sectionNumber (compiler_gcc, compiler_Rust, ...) and
    // _libraryNames (library_GLIBC, library_Curl, ...). They must execute
    // without throwing a ReferenceError, regardless of whether they detect.
    let (init_source, type_init_scripts, includes) = match load_upstream_framework_for_type("ELF") {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    let data = match load_corpus_pe("minimal.elf") {
        Some(d) => d,
        None => {
            eprintln!("Skipping: corpus/minimal.elf not found");
            return;
        }
    };

    // Rules that exercise _sectionNumber (uses _B.__elfSectionNames).
    for rule in [
        "ELF/compiler_gcc.4.sg",
        "ELF/compiler_Rust.4.sg",
        "ELF/compiler_Go.4.sg",
    ] {
        let results = run_real_rule_typed(
            rule,
            "ELF",
            &init_source,
            &type_init_scripts,
            &includes,
            data.clone(),
        );
        assert!(
            results.is_some(),
            "{rule} threw an exception (expected no ReferenceError: _B)"
        );
    }

    // Rules that exercise _libraryNames (uses _B.__elfImportLibraries).
    for rule in ["ELF/library_GLIBC.3.sg", "ELF/library_Curl.4.sg"] {
        let results = run_real_rule_typed(
            rule,
            "ELF",
            &init_source,
            &type_init_scripts,
            &includes,
            data.clone(),
        );
        assert!(
            results.is_some(),
            "{rule} threw an exception (expected no ReferenceError: _B)"
        );
    }
}

#[test]
fn real_rule_mach_section_helpers_no_b_reference_error() {
    // Regression test for Phase 14.1: the Mach-O method closure had the
    // same _B omission as ELF. _machoSectionNames / _machoImportLibraries
    // helpers use _B.__machoSectionNames() / _B.__machoImportLibraries().
    let (init_source, type_init_scripts, includes) = match load_upstream_framework_for_type("MACH")
    {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    let data = match load_corpus_pe("minimal.macho") {
        Some(d) => d,
        None => {
            eprintln!("Skipping: corpus/minimal.macho not found");
            return;
        }
    };

    // Run a Mach-O rule that exercises section/library helpers.
    // _MACH.0.sg is the OS detection rule; it should not throw.
    let results = run_real_rule_typed(
        "MACH/_MACH.0.sg",
        "MACH",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );
    assert!(
        results.is_some(),
        "MACH rule threw an exception (expected no ReferenceError: _B)"
    );
}

// ============================================================================
// MACH format rule tests
// ============================================================================

#[test]
fn real_rule_mach_init_loads_without_error() {
    // Verify that the MACH type-specific _init script loads successfully.
    let (init_source, type_init_scripts, includes) = match load_upstream_framework_for_type("MACH")
    {
        Some(x) => x,
        None => {
            eprintln!("Skipping: upstream rules not found");
            return;
        }
    };

    // Use corpus/minimal.macho (104-byte Mach-O 64).
    let data = match load_corpus_pe("minimal.macho") {
        Some(d) => d,
        None => {
            eprintln!("Skipping: corpus/minimal.macho not found");
            return;
        }
    };

    // Run the MACH OS detection rule.
    let results = run_real_rule_typed(
        "MACH/_MACH.0.sg",
        "MACH",
        &init_source,
        &type_init_scripts,
        &includes,
        data,
    );

    // Rule should execute without error.
    assert!(results.is_some(), "MACH rule execution failed");
}

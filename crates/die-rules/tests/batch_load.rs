//! Batch load test: load all Binary rules and report failures.
//!
//! This test loads every .sg file in the Binary rules directory to
//! identify which rules fail to load and why. It helps find missing
//! host API methods and syntax incompatibilities.

#![cfg(test)]

use die_core::format::FileType;
use die_core::input::ByteView;
use die_rules::backend_rquickjs::RquickjsRuntime;
use die_rules::host_api::{HostApi, HostApiError};
use die_rules::runtime::{DatabaseSnapshot, LoadedRule, RuleRuntime, RuntimeConfig};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Dummy host that returns empty/zero values for all methods.
/// Used for batch load testing where we only test rule loading, not detection.
struct DummyHost {
    file_type: FileType,
}

impl DummyHost {
    fn new() -> Self {
        Self {
            file_type: FileType::new("Binary"),
        }
    }
}

impl HostApi for DummyHost {
    fn file_type(&self) -> &FileType {
        &self.file_type
    }

    fn view(&self) -> &ByteView<'_> {
        unimplemented!()
    }

    fn read_u8(&self, _offset: u64) -> Result<u8, HostApiError> {
        Ok(0)
    }
    fn read_u16_le(&self, _offset: u64) -> Result<u16, HostApiError> {
        Ok(0)
    }
    fn read_u16_be(&self, _offset: u64) -> Result<u16, HostApiError> {
        Ok(0)
    }
    fn read_u24_le(&self, _offset: u64) -> Result<u32, HostApiError> {
        Ok(0)
    }
    fn read_u24_be(&self, _offset: u64) -> Result<u32, HostApiError> {
        Ok(0)
    }
    fn read_u32_le(&self, _offset: u64) -> Result<u32, HostApiError> {
        Ok(0)
    }
    fn read_u32_be(&self, _offset: u64) -> Result<u32, HostApiError> {
        Ok(0)
    }
    fn read_u64_le(&self, _offset: u64) -> Result<u64, HostApiError> {
        Ok(0)
    }
    fn read_u64_be(&self, _offset: u64) -> Result<u64, HostApiError> {
        Ok(0)
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
        0
    }
    fn check_signature(&self, _offset: u64, _signature: &str) -> Result<bool, HostApiError> {
        Ok(false)
    }
    fn find_signature(&self, _start: u64, _signature: &str) -> Result<Option<u64>, HostApiError> {
        Ok(None)
    }
    fn find_signature_in_range(
        &self,
        _start: u64,
        _end: u64,
        _signature: &str,
    ) -> Result<Option<u64>, HostApiError> {
        Ok(None)
    }
    fn read_string(&self, _offset: u64, _max_len: u64) -> Result<String, HostApiError> {
        Ok(String::new())
    }
    fn file_name(&self) -> &str {
        "dummy.bin"
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
    fn entropy(&self, _offset: u64, _size: u64) -> Result<f64, HostApiError> {
        Ok(0.0)
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
        None
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

fn db_root() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    root.join("upstream/Detect-It-Easy/db")
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

fn load_all_include_scripts(db: &str) -> BTreeMap<String, String> {
    let mut includes = BTreeMap::new();

    // Load all files in db root that don't have .sg extension (init scripts).
    if let Ok(entries) = std::fs::read_dir(db) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && path.extension().is_none()
                && let Some(name) = path.file_name().and_then(|n| n.to_str())
                && let Ok(source) = std::fs::read_to_string(&path)
            {
                includes.insert(name.to_string(), source);
            }
        }
    }

    // Load files in subdirectories: db/<dir>/<file> and db/<dir>/<dir>
    // The upstream include system resolves includeScript("name") by looking
    // for db/<name> (file) or db/<name>/<name> (file in directory).
    if let Ok(entries) = std::fs::read_dir(db) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir()
                && let Some(dir_name) = path.file_name().and_then(|n| n.to_str())
            {
                // Try db/<dir>/<dir> (file with same name as directory)
                let inner = path.join(dir_name);
                if inner.is_file()
                    && !includes.contains_key(dir_name)
                    && let Ok(source) = std::fs::read_to_string(&inner)
                {
                    includes.insert(dir_name.to_string(), source);
                }

                // Also load other files without .sg extension in subdirectories.
                if let Ok(sub_entries) = std::fs::read_dir(&path) {
                    for sub_entry in sub_entries.flatten() {
                        let sub_path = sub_entry.path();
                        if sub_path.is_file()
                            && sub_path.extension().is_none()
                            && let Some(name) = sub_path.file_name().and_then(|n| n.to_str())
                            && !includes.contains_key(name)
                            && let Ok(source) = std::fs::read_to_string(&sub_path)
                        {
                            includes.insert(name.to_string(), source);
                        }
                    }
                }
            }
        }
    }

    includes
}

fn load_init_script(db: &str) -> Option<String> {
    std::fs::read_to_string(format!("{db}/_init")).ok()
}

#[test]
fn batch_load_all_binary_rules() {
    let db = db_root();
    let binary_dir = format!("{db}/Binary");

    let init_script = load_init_script(&db);
    let includes = load_all_include_scripts(&db);

    // Collect all .sg files in Binary directory.
    let mut rules = Vec::new();
    let mut ordinal = 0u64;

    if let Ok(entries) = std::fs::read_dir(&binary_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("sg")
                && let Ok(source) = std::fs::read_to_string(&path)
            {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                rules.push(LoadedRule {
                    path: format!("Binary/{name}"),
                    ordinal,
                    file_type: "Binary".into(),
                    source,
                });
                ordinal += 1;
            }
        }
    }

    if rules.is_empty() {
        eprintln!("Skipping: no Binary rules found");
        return;
    }

    eprintln!("Found {} Binary rules", rules.len());

    // Load the Binary type-specific _init script.
    let binary_init = std::fs::read_to_string(format!("{db}/Binary/_init")).ok();

    // Try loading each rule individually to identify failures.
    let mut success_count = 0;
    let mut fail_count = 0;
    let mut failures = Vec::new();

    for rule in &rules {
        let type_init = binary_init
            .as_ref()
            .map(|s| vec![("Binary".to_string(), s.clone())])
            .unwrap_or_default();

        let snapshot = DatabaseSnapshot {
            rules: vec![rule.clone()],
            init_script: init_script.clone(),
            type_init_scripts: type_init,
            include_scripts: includes.clone(),
        };

        let mut runtime = match RquickjsRuntime::new(RuntimeConfig::default()) {
            Ok(rt) => rt,
            Err(e) => {
                fail_count += 1;
                failures.push((rule.path.clone(), format!("runtime create: {e}")));
                continue;
            }
        };

        // Register a dummy host before loading so that include scripts
        // which reference `Binary` at top level (e.g. shell-script) work.
        let dummy_host = Arc::new(DummyHost::new());
        if let Err(e) = runtime.register_host_api(dummy_host.clone()) {
            fail_count += 1;
            failures.push((rule.path.clone(), format!("register_host_api: {e}")));
            continue;
        }

        // Load database (evaluates _init and rule sources).
        match runtime.load_database(&snapshot) {
            Ok(()) => {
                // Run init to execute type init scripts (Binary/_init sets
                // X=Binary and includes "read").
                let host_ref: &dyn HostApi = &*dummy_host;
                if let Err(e) = runtime.init(host_ref) {
                    fail_count += 1;
                    failures.push((rule.path.clone(), format!("init: {e}")));
                    continue;
                }
                success_count += 1;
            }
            Err(e) => {
                fail_count += 1;
                failures.push((rule.path.clone(), format!("{e}")));
            }
        }
    }

    eprintln!("Success: {success_count}, Fail: {fail_count}");

    // Print first 20 failures for analysis.
    let show = failures.len().min(20);
    for (path, error) in failures.iter().take(show) {
        eprintln!("FAIL: {path} -> {error}");
    }

    // We expect at least 50% of rules to load successfully at this stage.
    // Many failures are expected due to missing PE/ELF-specific methods,
    // Archive object, and other format-specific APIs.
    let success_ratio = success_count as f64 / rules.len() as f64;
    eprintln!("Success ratio: {:.1}%", success_ratio * 100.0);

    assert!(
        success_ratio >= 0.99,
        "Expected at least 99% of Binary rules to load, got {:.1}% ({}/{})",
        success_ratio * 100.0,
        success_count,
        rules.len()
    );
}

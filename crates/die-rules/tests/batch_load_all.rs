//! Batch load test for all format types (ELF, MACH, MACHOFAT, etc.).
//!
//! These format-specific rules require their own host API objects
//! (ELF, MACH, etc.) which are not yet implemented. This test verifies
//! that rules can be parsed without the format-specific methods.

#![cfg(test)]

use die_core::format::FileType;
use die_core::input::ByteView;
use die_rules::backend_rquickjs::RquickjsRuntime;
use die_rules::host_api::{HostApi, HostApiError};
use die_rules::runtime::{DatabaseSnapshot, LoadedRule, RuleRuntime, RuntimeConfig};
use std::collections::BTreeMap;
use std::sync::Arc;

struct DummyHost {
    file_type: FileType,
}

impl DummyHost {
    fn new(ft: &str) -> Self {
        Self {
            file_type: FileType::new(ft),
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
    fn read_u8(&self, _o: u64) -> Result<u8, HostApiError> {
        Ok(0)
    }
    fn read_u16_le(&self, _o: u64) -> Result<u16, HostApiError> {
        Ok(0)
    }
    fn read_u16_be(&self, _o: u64) -> Result<u16, HostApiError> {
        Ok(0)
    }
    fn read_u24_le(&self, _o: u64) -> Result<u32, HostApiError> {
        Ok(0)
    }
    fn read_u24_be(&self, _o: u64) -> Result<u32, HostApiError> {
        Ok(0)
    }
    fn read_u32_le(&self, _o: u64) -> Result<u32, HostApiError> {
        Ok(0)
    }
    fn read_u32_be(&self, _o: u64) -> Result<u32, HostApiError> {
        Ok(0)
    }
    fn read_u64_le(&self, _o: u64) -> Result<u64, HostApiError> {
        Ok(0)
    }
    fn read_u64_be(&self, _o: u64) -> Result<u64, HostApiError> {
        Ok(0)
    }
    fn read_i8(&self, o: u64) -> Result<i8, HostApiError> {
        self.read_u8(o).map(|v| v as i8)
    }
    fn read_i16_le(&self, o: u64) -> Result<i16, HostApiError> {
        self.read_u16_le(o).map(|v| v as i16)
    }
    fn read_i32_le(&self, o: u64) -> Result<i32, HostApiError> {
        self.read_u32_le(o).map(|v| v as i32)
    }
    fn read_i64_le(&self, o: u64) -> Result<i64, HostApiError> {
        self.read_u64_le(o).map(|v| v as i64)
    }
    fn file_size(&self) -> u64 {
        0
    }
    fn check_signature(&self, _o: u64, _s: &str) -> Result<bool, HostApiError> {
        Ok(false)
    }
    fn find_signature(&self, _o: u64, _s: &str) -> Result<Option<u64>, HostApiError> {
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
    fn read_string(&self, _o: u64, _m: u64) -> Result<String, HostApiError> {
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
    fn entropy(&self, _o: u64, _s: u64) -> Result<f64, HostApiError> {
        Ok(0.0)
    }
    fn md5(&self, _o: u64, _s: u64) -> Result<String, HostApiError> {
        Err(HostApiError::NotImplemented {
            method: "md5".into(),
        })
    }
    fn crc32(&self, _o: u64, _s: u64) -> Result<u32, HostApiError> {
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
    if let Ok(entries) = std::fs::read_dir(db) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir()
                && let Some(dir_name) = path.file_name().and_then(|n| n.to_str())
            {
                let inner = path.join(dir_name);
                if inner.is_file()
                    && !includes.contains_key(dir_name)
                    && let Ok(source) = std::fs::read_to_string(&inner)
                {
                    includes.insert(dir_name.to_string(), source);
                }
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

/// Test loading all rules for a given format type.
fn test_format_loading(format: &str, min_success_ratio: f64) {
    let db = db_root();
    let format_dir = format!("{db}/{format}");
    let init_script = std::fs::read_to_string(format!("{db}/_init")).ok();
    let includes = load_all_include_scripts(&db);

    let mut rules = Vec::new();
    let mut ordinal = 0u64;

    if let Ok(entries) = std::fs::read_dir(&format_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("sg")
                && let Ok(source) = std::fs::read_to_string(&path)
            {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                rules.push(LoadedRule {
                    path: format!("{format}/{name}"),
                    ordinal,
                    file_type: format.into(),
                    source,
                });
                ordinal += 1;
            }
        }
    }

    if rules.is_empty() {
        eprintln!("Skipping: no {format} rules found");
        return;
    }

    eprintln!("Found {format} rules: {}", rules.len());

    let mut success_count = 0;
    let mut fail_count = 0;
    let mut failures = Vec::new();

    for rule in &rules {
        let snapshot = DatabaseSnapshot {
            rules: vec![rule.clone()],
            init_script: init_script.clone(),
            type_init_scripts: Vec::new(),
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

        let dummy_host = Arc::new(DummyHost::new(format));
        if let Err(e) = runtime.register_host_api(dummy_host) {
            fail_count += 1;
            failures.push((rule.path.clone(), format!("register_host_api: {e}")));
            continue;
        }

        match runtime.load_database(&snapshot) {
            Ok(()) => success_count += 1,
            Err(e) => {
                fail_count += 1;
                failures.push((rule.path.clone(), format!("{e}")));
            }
        }
    }

    eprintln!("{format}: Success: {success_count}, Fail: {fail_count}");

    let show = failures.len().min(10);
    for (path, error) in failures.iter().take(show) {
        eprintln!("  FAIL: {path} -> {error}");
    }

    let success_ratio = success_count as f64 / rules.len() as f64;
    eprintln!("{format} success ratio: {:.1}%", success_ratio * 100.0);

    assert!(
        success_ratio >= min_success_ratio,
        "{format}: expected at least {:.0}% load success, got {:.1}% ({}/{})",
        min_success_ratio * 100.0,
        success_ratio * 100.0,
        success_count,
        rules.len()
    );
}

#[test]
fn batch_load_elf_rules() {
    test_format_loading("ELF", 0.80);
}

#[test]
fn batch_load_mach_rules() {
    test_format_loading("MACH", 0.80);
}

#[test]
fn batch_load_machofat_rules() {
    test_format_loading("MACHOFAT", 0.50);
}

#[test]
fn batch_load_all_formats_summary() {
    // Summary test that prints a combined report.
    let formats = [
        ("Binary", 0.99),
        ("PE", 0.99),
        ("ELF", 0.80),
        ("MACH", 0.80),
        ("MACHOFAT", 0.50),
    ];

    let db = db_root();
    let init_script = std::fs::read_to_string(format!("{db}/_init")).ok();
    let includes = load_all_include_scripts(&db);

    let mut total_rules = 0;
    let mut total_success = 0;

    for (format, _min_ratio) in &formats {
        let format_dir = format!("{db}/{format}");
        let mut rules = Vec::new();
        let mut ordinal = 0u64;

        if let Ok(entries) = std::fs::read_dir(&format_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("sg")
                    && let Ok(source) = std::fs::read_to_string(&path)
                {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                    rules.push(LoadedRule {
                        path: format!("{format}/{name}"),
                        ordinal,
                        file_type: format.to_string(),
                        source,
                    });
                    ordinal += 1;
                }
            }
        }

        let mut success_count = 0;
        for rule in &rules {
            let snapshot = DatabaseSnapshot {
                rules: vec![rule.clone()],
                init_script: init_script.clone(),
                type_init_scripts: Vec::new(),
                include_scripts: includes.clone(),
            };

            let Ok(mut runtime) = RquickjsRuntime::new(RuntimeConfig::default()) else {
                continue;
            };

            let dummy_host = Arc::new(DummyHost::new(format));
            if runtime.register_host_api(dummy_host).is_err() {
                continue;
            }

            if runtime.load_database(&snapshot).is_ok() {
                success_count += 1;
            }
        }

        total_rules += rules.len();
        total_success += success_count;
        eprintln!(
            "{format}: {success_count}/{} ({:.1}%)",
            rules.len(),
            if rules.is_empty() {
                100.0
            } else {
                success_count as f64 / rules.len() as f64 * 100.0
            }
        );
    }

    eprintln!("Total: {total_success}/{total_rules}");
    let overall_ratio = if total_rules > 0 {
        total_success as f64 / total_rules as f64
    } else {
        0.0
    };
    eprintln!("Overall success ratio: {:.1}%", overall_ratio * 100.0);

    assert!(
        overall_ratio >= 0.95,
        "Expected at least 95% overall load success, got {:.1}%",
        overall_ratio * 100.0
    );
}

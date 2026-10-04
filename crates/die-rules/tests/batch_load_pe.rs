//! Batch load test for PE rules.
//!
//! PE rules require a PE-specific host API (PE_Script) which is not
//! yet implemented. This test verifies that PE rules can be loaded
//! (parsed) without the PE-specific methods, identifying which rules
//! have syntax errors or use unsupported features.

#![cfg(test)]

use die_core::cancel::CancellationToken;
use die_core::format::FileType;
use die_core::input::ByteView;
use die_rules::backend_rquickjs::RquickjsRuntime;
use die_rules::host_api::{HostApi, HostApiError};
use die_rules::runtime::{DatabaseSnapshot, LoadedRule, RuleRuntime, RuntimeConfig};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Dummy host that returns empty/zero values for all methods.
struct DummyHost {
    file_type: FileType,
}

impl DummyHost {
    fn new() -> Self {
        Self {
            file_type: FileType::new("PE"),
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
        "dummy.exe"
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
    // Load files in subdirectories: db/<dir>/<dir>
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

#[test]
fn batch_load_pe_rules() {
    let db = db_root();
    let pe_dir = format!("{db}/PE");

    let init_script = std::fs::read_to_string(format!("{db}/_init")).ok();

    // PE _init requires PE-specific host API methods (getNumberOfSections, etc.)
    // which are not yet implemented. We skip it for now and only test rule parsing.
    let includes = load_all_include_scripts(&db);

    // Collect all .sg files in PE directory.
    let mut rules = Vec::new();
    let mut ordinal = 0u64;

    if let Ok(entries) = std::fs::read_dir(&pe_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("sg")
                && let Ok(source) = std::fs::read_to_string(&path)
            {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                rules.push(LoadedRule {
                    path: format!("PE/{name}"),
                    ordinal,
                    file_type: "PE".into(),
                    source,
                });
                ordinal += 1;
            }
        }
    }

    if rules.is_empty() {
        eprintln!("Skipping: no PE rules found");
        return;
    }

    eprintln!("Found {} PE rules", rules.len());

    let mut success_count = 0;
    let mut fail_count = 0;
    let mut failures = Vec::new();

    for rule in &rules {
        let snapshot = DatabaseSnapshot {
            rules: vec![rule.clone()],
            init_script: init_script.clone(),
            type_init_scripts: Vec::new(), // No PE _init yet
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

        // Register dummy host (provides Binary but not PE-specific methods).
        let dummy_host = Arc::new(DummyHost::new());
        if let Err(e) = runtime.register_host_api(dummy_host.clone()) {
            fail_count += 1;
            failures.push((rule.path.clone(), format!("register_host_api: {e}")));
            continue;
        }

        match runtime.load_database(&snapshot) {
            Ok(()) => {
                success_count += 1;
            }
            Err(e) => {
                fail_count += 1;
                failures.push((rule.path.clone(), format!("{e}")));
            }
        }
    }

    eprintln!("Success: {success_count}, Fail: {fail_count}");

    let show = failures.len().min(20);
    for (path, error) in failures.iter().take(show) {
        eprintln!("FAIL: {path} -> {error}");
    }

    let success_ratio = success_count as f64 / rules.len() as f64;
    eprintln!("Success ratio: {:.1}%", success_ratio * 100.0);

    // PE rules use PE-specific methods at the top level (outside detect()),
    // so many will fail. We expect at least 50% to parse successfully.
    assert!(
        success_ratio >= 0.50,
        "Expected at least 50% of PE rules to load, got {:.1}% ({}/{})",
        success_ratio * 100.0,
        success_count,
        rules.len()
    );
}

/// Minimal PE import table parser for test purposes.
/// Returns library names from the import directory.
fn parse_pe_imports(data: &[u8]) -> Vec<String> {
    if data.len() < 0x40 {
        return Vec::new();
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Vec::new();
    }
    let coff_off = e_lfanew + 4;
    let opt_hdr_size = u16::from_le_bytes([data[coff_off + 16], data[coff_off + 17]]) as usize;
    let opt_off = coff_off + 20;
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let is_64 = magic == 0x020B;
    let dd_off = opt_off + 96;
    if dd_off + 16 > data.len() {
        return Vec::new();
    }
    let import_rva = u32::from_le_bytes([
        data[dd_off + 8],
        data[dd_off + 9],
        data[dd_off + 10],
        data[dd_off + 11],
    ]);
    if import_rva == 0 {
        return Vec::new();
    }
    // Parse section headers to convert RVA to file offset.
    let sect_off = opt_off + opt_hdr_size;
    let num_sections = u16::from_le_bytes([data[coff_off + 2], data[coff_off + 3]]) as usize;
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let s = sect_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let va = u32::from_le_bytes([data[s + 12], data[s + 13], data[s + 14], data[s + 15]]);
        let vs = u32::from_le_bytes([data[s + 8], data[s + 9], data[s + 10], data[s + 11]]);
        let rs = u32::from_le_bytes([data[s + 16], data[s + 17], data[s + 18], data[s + 19]]);
        let ro = u32::from_le_bytes([data[s + 20], data[s + 21], data[s + 22], data[s + 23]]);
        sections.push((va, vs.max(rs), ro));
    }
    let rva_to_offset = |rva: u32| -> Option<usize> {
        for &(va, size, ro) in &sections {
            if rva >= va && rva < va + size {
                return Some(ro as usize + (rva - va) as usize);
            }
        }
        None
    };
    let import_off = match rva_to_offset(import_rva) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let mut libs = Vec::new();
    let mut desc_off = import_off;
    loop {
        if desc_off + 20 > data.len() {
            break;
        }
        let name_rva = u32::from_le_bytes([
            data[desc_off + 12],
            data[desc_off + 13],
            data[desc_off + 14],
            data[desc_off + 15],
        ]);
        if name_rva == 0 {
            break; // Terminator
        }
        if let Some(name_off) = rva_to_offset(name_rva) {
            let mut name = Vec::new();
            for &b in &data[name_off..data.len().min(name_off + 256)] {
                if b == 0 {
                    break;
                }
                name.push(b);
            }
            if let Ok(s) = String::from_utf8(name) {
                libs.push(s);
            }
        }
        desc_off += 20;
    }
    let _ = is_64; // Suppress unused warning
    libs
}

/// Minimal PE export table parser for test purposes.
/// Returns export function names.
fn parse_pe_exports(data: &[u8]) -> Vec<String> {
    if data.len() < 0x40 {
        return Vec::new();
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Vec::new();
    }
    let coff_off = e_lfanew + 4;
    let opt_hdr_size = u16::from_le_bytes([data[coff_off + 16], data[coff_off + 17]]) as usize;
    let opt_off = coff_off + 20;
    let dd_off = opt_off + 96;
    if dd_off + 8 > data.len() {
        return Vec::new();
    }
    let export_rva = u32::from_le_bytes([
        data[dd_off],
        data[dd_off + 1],
        data[dd_off + 2],
        data[dd_off + 3],
    ]);
    if export_rva == 0 {
        return Vec::new();
    }
    // Parse section headers.
    let sect_off = opt_off + opt_hdr_size;
    let num_sections = u16::from_le_bytes([data[coff_off + 2], data[coff_off + 3]]) as usize;
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let s = sect_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let va = u32::from_le_bytes([data[s + 12], data[s + 13], data[s + 14], data[s + 15]]);
        let vs = u32::from_le_bytes([data[s + 8], data[s + 9], data[s + 10], data[s + 11]]);
        let rs = u32::from_le_bytes([data[s + 16], data[s + 17], data[s + 18], data[s + 19]]);
        let ro = u32::from_le_bytes([data[s + 20], data[s + 21], data[s + 22], data[s + 23]]);
        sections.push((va, vs.max(rs), ro));
    }
    let rva_to_offset = |rva: u32| -> Option<usize> {
        for &(va, size, ro) in &sections {
            if rva >= va && rva < va + size {
                return Some(ro as usize + (rva - va) as usize);
            }
        }
        None
    };
    let export_off = match rva_to_offset(export_rva) {
        Some(o) => o,
        None => return Vec::new(),
    };
    if export_off + 40 > data.len() {
        return Vec::new();
    }
    let num_names = u32::from_le_bytes([
        data[export_off + 24],
        data[export_off + 25],
        data[export_off + 26],
        data[export_off + 27],
    ]);
    let names_rva = u32::from_le_bytes([
        data[export_off + 32],
        data[export_off + 33],
        data[export_off + 34],
        data[export_off + 35],
    ]);
    if num_names == 0 || names_rva == 0 {
        return Vec::new();
    }
    let names_off = match rva_to_offset(names_rva) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let mut result = Vec::new();
    for i in 0..num_names as usize {
        let ptr_off = names_off + i * 4;
        if ptr_off + 4 > data.len() {
            break;
        }
        let name_rva = u32::from_le_bytes([
            data[ptr_off],
            data[ptr_off + 1],
            data[ptr_off + 2],
            data[ptr_off + 3],
        ]);
        if let Some(name_off) = rva_to_offset(name_rva) {
            let mut name = Vec::new();
            for &b in &data[name_off..data.len().min(name_off + 256)] {
                if b == 0 {
                    break;
                }
                name.push(b);
            }
            if let Ok(s) = String::from_utf8(name) {
                result.push(s);
            }
        }
    }
    result
}

/// Real PE host that wraps actual PE file data and delegates to the
/// Rust-side PE parser for import/export table queries.
struct RealPeHost {
    data: Vec<u8>,
    file_type: FileType,
    file_name: String,
}

impl RealPeHost {
    fn new(data: Vec<u8>, file_name: &str) -> Self {
        Self {
            data,
            file_type: FileType::new("PE"),
            file_name: file_name.to_string(),
        }
    }
}

impl HostApi for RealPeHost {
    fn file_type(&self) -> &FileType {
        &self.file_type
    }
    fn view(&self) -> &ByteView<'_> {
        unimplemented!()
    }
    fn read_u8(&self, o: u64) -> Result<u8, HostApiError> {
        let i = o as usize;
        if i >= self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset: o,
                file_size: self.data.len() as u64,
            });
        }
        Ok(self.data[i])
    }
    fn read_u16_le(&self, o: u64) -> Result<u16, HostApiError> {
        let i = o as usize;
        if i + 2 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset: o,
                file_size: self.data.len() as u64,
            });
        }
        Ok(u16::from_le_bytes([self.data[i], self.data[i + 1]]))
    }
    fn read_u16_be(&self, o: u64) -> Result<u16, HostApiError> {
        let i = o as usize;
        if i + 2 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset: o,
                file_size: self.data.len() as u64,
            });
        }
        Ok(u16::from_be_bytes([self.data[i], self.data[i + 1]]))
    }
    fn read_u24_le(&self, o: u64) -> Result<u32, HostApiError> {
        let i = o as usize;
        if i + 3 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset: o,
                file_size: self.data.len() as u64,
            });
        }
        Ok(u32::from_le_bytes([
            self.data[i],
            self.data[i + 1],
            self.data[i + 2],
            0,
        ]))
    }
    fn read_u24_be(&self, o: u64) -> Result<u32, HostApiError> {
        let i = o as usize;
        if i + 3 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset: o,
                file_size: self.data.len() as u64,
            });
        }
        Ok(u32::from_be_bytes([
            self.data[i],
            self.data[i + 1],
            self.data[i + 2],
            0,
        ]))
    }
    fn read_u32_le(&self, o: u64) -> Result<u32, HostApiError> {
        let i = o as usize;
        if i + 4 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset: o,
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
    fn read_u32_be(&self, o: u64) -> Result<u32, HostApiError> {
        let i = o as usize;
        if i + 4 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset: o,
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
    fn read_u64_le(&self, o: u64) -> Result<u64, HostApiError> {
        let i = o as usize;
        if i + 8 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset: o,
                file_size: self.data.len() as u64,
            });
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[i..i + 8]);
        Ok(u64::from_le_bytes(buf))
    }
    fn read_u64_be(&self, o: u64) -> Result<u64, HostApiError> {
        let i = o as usize;
        if i + 8 > self.data.len() {
            return Err(HostApiError::OutOfBounds {
                offset: o,
                file_size: self.data.len() as u64,
            });
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[i..i + 8]);
        Ok(u64::from_be_bytes(buf))
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
        self.data.len() as u64
    }
    fn check_signature(&self, o: u64, sig: &str) -> Result<bool, HostApiError> {
        let sig = sig.trim_matches('\'');
        let bytes: Result<Vec<u8>, _> = (0..sig.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig[i..i + 2], 16))
            .collect();
        let sig_bytes = bytes.map_err(|e| HostApiError::InvalidSignature {
            pattern: sig.into(),
            detail: e.to_string(),
        })?;
        let start = o as usize;
        if start + sig_bytes.len() > self.data.len() {
            return Ok(false);
        }
        Ok(&self.data[start..start + sig_bytes.len()] == sig_bytes.as_slice())
    }
    fn find_signature(&self, start: u64, sig: &str) -> Result<Option<u64>, HostApiError> {
        let s = sig.trim_matches('\'');
        let bytes: Result<Vec<u8>, _> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect();
        let sig_bytes = bytes.map_err(|e| HostApiError::InvalidSignature {
            pattern: sig.into(),
            detail: e.to_string(),
        })?;
        let start = start as usize;
        if sig_bytes.is_empty() || start + sig_bytes.len() > self.data.len() {
            return Ok(None);
        }
        for i in start..=self.data.len() - sig_bytes.len() {
            if &self.data[i..i + sig_bytes.len()] == sig_bytes.as_slice() {
                return Ok(Some(i as u64));
            }
        }
        Ok(None)
    }
    fn find_signature_in_range(
        &self,
        start: u64,
        end: u64,
        sig: &str,
    ) -> Result<Option<u64>, HostApiError> {
        let s = sig.trim_matches('\'');
        let bytes: Result<Vec<u8>, _> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect();
        let sig_bytes = bytes.map_err(|e| HostApiError::InvalidSignature {
            pattern: sig.into(),
            detail: e.to_string(),
        })?;
        let start = start as usize;
        let end = (end as usize).min(self.data.len());
        if sig_bytes.is_empty() || start >= end || end < sig_bytes.len() {
            return Ok(None);
        }
        for i in start..=end - sig_bytes.len() {
            if &self.data[i..i + sig_bytes.len()] == sig_bytes.as_slice() {
                return Ok(Some(i as u64));
            }
        }
        Ok(None)
    }
    fn read_string(&self, o: u64, max_len: u64) -> Result<String, HostApiError> {
        let start = o as usize;
        let end = (start + max_len as usize).min(self.data.len());
        if start >= self.data.len() {
            return Ok(String::new());
        }
        let bytes = &self.data[start..end];
        let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..nul]).into_owned())
    }
    fn file_name(&self) -> &str {
        &self.file_name
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
    fn entropy(&self, o: u64, sz: u64) -> Result<f64, HostApiError> {
        let start = o as usize;
        let end = (start + sz as usize).min(self.data.len());
        if start >= end {
            return Ok(0.0);
        }
        let mut counts = [0u32; 256];
        for &b in &self.data[start..end] {
            counts[b as usize] += 1;
        }
        let total = (end - start) as f64;
        let mut e = 0.0;
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / total;
                e -= p * p.log2();
            }
        }
        Ok(e)
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
        die_rules::pe_native::parse_batch(&self.data)
    }
    fn pe_import_libraries(&self) -> Vec<String> {
        parse_pe_imports(&self.data)
    }
    fn pe_import_functions(&self) -> Vec<String> {
        Vec::new()
    }
    fn pe_export_names(&self) -> Vec<String> {
        parse_pe_exports(&self.data)
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

/// Load the corpus/with-tables.exe PE sample for testing.
fn load_test_pe() -> Option<Vec<u8>> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let path = root.join("corpus/with-tables.exe");
    std::fs::read(&path).ok()
}

#[test]
fn batch_load_pe_rules_with_real_host_and_init() {
    // Regression test: previously batch_load_pe.rs used DummyHost and
    // skipped PE _init, meaning PE rules were never tested with real
    // PE host API. This test loads PE _init and executes rules with
    // a real PE file (corpus/with-tables.exe).
    let db = db_root();
    let pe_dir = format!("{db}/PE");

    let test_pe = match load_test_pe() {
        Some(d) => d,
        None => {
            eprintln!("SKIP: corpus/with-tables.exe not found");
            return;
        }
    };

    let init_script = std::fs::read_to_string(format!("{db}/_init")).ok();
    let pe_init = std::fs::read_to_string(format!("{db}/PE/_init")).ok();
    let includes = load_all_include_scripts(&db);

    let type_init_scripts = pe_init
        .map(|s| vec![("PE".to_string(), s)])
        .unwrap_or_default();

    // Collect all .sg files in PE directory.
    let mut rules = Vec::new();
    let mut ordinal = 0u64;

    if let Ok(entries) = std::fs::read_dir(&pe_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("sg")
                && let Ok(source) = std::fs::read_to_string(&path)
            {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                rules.push(LoadedRule {
                    path: format!("PE/{name}"),
                    ordinal,
                    file_type: "PE".into(),
                    source,
                });
                ordinal += 1;
            }
        }
    }

    if rules.is_empty() {
        eprintln!("SKIP: no PE rules found");
        return;
    }

    eprintln!(
        "Testing {} PE rules with RealPeHost + PE _init",
        rules.len()
    );

    let mut success_count = 0;
    let mut fail_count = 0;
    let mut execute_success = 0;
    let mut execute_fail = 0;
    let mut failures = Vec::new();

    for rule in &rules {
        let snapshot = DatabaseSnapshot {
            rules: vec![rule.clone()],
            init_script: init_script.clone(),
            type_init_scripts: type_init_scripts.clone(),
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

        let host = Arc::new(RealPeHost::new(test_pe.clone(), "with-tables.exe"));
        if let Err(e) = runtime.register_host_api(host.clone()) {
            fail_count += 1;
            failures.push((rule.path.clone(), format!("register_host_api: {e}")));
            continue;
        }

        // Load database (includes PE _init execution).
        match runtime.load_database(&snapshot) {
            Ok(()) => {
                success_count += 1;
            }
            Err(e) => {
                fail_count += 1;
                failures.push((rule.path.clone(), format!("load_database: {e}")));
                continue;
            }
        }

        // Also try to execute the rule's detect() function.
        let token = CancellationToken::new();
        let host_ref: &dyn HostApi = &*host;
        match runtime.init(host_ref) {
            Ok(()) => {}
            Err(e) => {
                failures.push((rule.path.clone(), format!("init: {e}")));
                continue;
            }
        }
        match runtime.evaluate_rule(&snapshot.rules[0], host_ref, &token) {
            Ok(_) => execute_success += 1,
            Err(e) => {
                execute_fail += 1;
                if execute_fail <= 10 {
                    failures.push((rule.path.clone(), format!("evaluate: {e}")));
                }
            }
        }
    }

    eprintln!(
        "Load: {success_count} ok, {fail_count} fail. Execute: {execute_success} ok, {execute_fail} fail."
    );

    let show = failures.len().min(20);
    for (path, error) in failures.iter().take(show) {
        eprintln!("FAIL: {path} -> {error}");
    }

    let load_ratio = success_count as f64 / rules.len() as f64;
    eprintln!("Load ratio: {:.1}%", load_ratio * 100.0);

    // With PE _init and real host, we expect at least 50% to load.
    // (Some rules may fail due to unimplemented PE methods like isConsole,
    // getManifest, etc., but the core parsing should work.)
    assert!(
        load_ratio >= 0.50,
        "Expected at least 50% of PE rules to load with real host + PE _init, got {:.1}% ({}/{})",
        load_ratio * 100.0,
        success_count,
        rules.len()
    );

    // At least some rules should execute successfully.
    assert!(
        execute_success > 0,
        "Expected at least 1 PE rule to execute successfully, got 0"
    );
}

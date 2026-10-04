//! Rule loading and host API conformance tests.
//!
//! These tests verify that the rquickjs runtime correctly loads and
//! executes rule scripts that use the upstream DIE rule syntax patterns.
//! They serve as regression tests for the rule compatibility layer.

#![cfg(test)]

use diec_core::cancel::CancellationToken;
use diec_core::format::FileType;
use diec_core::input::ByteView;
use diec_rules::backend_rquickjs::{RquickjsRuntime, RquickjsRuntimeFactory};
use diec_rules::error::RuleError;
use diec_rules::host_api::{HostApi, HostApiError};
use diec_rules::runtime::{
    DatabaseSnapshot, DetectionResult, LoadedRule, RuleRuntime, RuleRuntimeFactory, RuntimeConfig,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Test host with an in-memory byte buffer.
struct BufferHost {
    data: Vec<u8>,
    file_type: FileType,
    deep: bool,
    heuristic: bool,
    aggressive: bool,
    recursive: bool,
}

impl BufferHost {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            file_type: FileType::new("Binary"),
            deep: false,
            heuristic: false,
            aggressive: false,
            recursive: false,
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
        let sig = signature.trim_matches('\'');
        if !sig.len().is_multiple_of(2) {
            return Err(HostApiError::InvalidSignature {
                pattern: signature.into(),
                detail: "odd number of hex digits".into(),
            });
        }
        let bytes: Result<Vec<u8>, _> = (0..sig.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig[i..i + 2], 16))
            .collect();
        let sig_bytes = bytes.map_err(|e| HostApiError::InvalidSignature {
            pattern: signature.into(),
            detail: e.to_string(),
        })?;
        let start = offset as usize;
        if start + sig_bytes.len() > self.data.len() {
            return Ok(false);
        }
        Ok(&self.data[start..start + sig_bytes.len()] == sig_bytes.as_slice())
    }

    fn find_signature(&self, start: u64, signature: &str) -> Result<Option<u64>, HostApiError> {
        let sig = signature.trim_matches('\'');
        let bytes: Result<Vec<u8>, _> = (0..sig.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig[i..i + 2], 16))
            .collect();
        let sig_bytes = bytes.map_err(|e| HostApiError::InvalidSignature {
            pattern: signature.into(),
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
        signature: &str,
    ) -> Result<Option<u64>, HostApiError> {
        let sig = signature.trim_matches('\'');
        let bytes: Result<Vec<u8>, _> = (0..sig.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig[i..i + 2], 16))
            .collect();
        let sig_bytes = bytes.map_err(|e| HostApiError::InvalidSignature {
            pattern: signature.into(),
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
        self.deep
    }

    fn is_heuristic(&self) -> bool {
        self.heuristic
    }

    fn is_aggressive(&self) -> bool {
        self.aggressive
    }

    fn is_verbose(&self) -> bool {
        false
    }

    fn is_recursive(&self) -> bool {
        self.recursive
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

/// Helper to create a simple rule snapshot with one rule.
fn make_snapshot(source: &str) -> DatabaseSnapshot {
    DatabaseSnapshot {
        rules: vec![LoadedRule {
            path: "test.sg".into(),
            ordinal: 0,
            file_type: "Binary".into(),
            source: source.to_string(),
        }],
        init_script: None,
        type_init_scripts: Vec::new(),
        include_scripts: BTreeMap::new(),
    }
}

/// Helper to create a snapshot with include scripts.
fn make_snapshot_with_includes(source: &str, includes: &[(&str, &str)]) -> DatabaseSnapshot {
    let mut map = BTreeMap::new();
    for (name, src) in includes {
        map.insert(name.to_string(), src.to_string());
    }
    DatabaseSnapshot {
        rules: vec![LoadedRule {
            path: "test.sg".into(),
            ordinal: 0,
            file_type: "Binary".into(),
            source: source.to_string(),
        }],
        init_script: None,
        type_init_scripts: Vec::new(),
        include_scripts: map,
    }
}

/// Helper to run a rule against a buffer and return results.
fn run_rule(snapshot: &DatabaseSnapshot, data: Vec<u8>) -> Vec<DetectionResult> {
    let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
    runtime.load_database(snapshot).unwrap();

    // Register the host API bridge.
    let host = Arc::new(BufferHost::new(data));
    runtime.register_host_api(host.clone()).unwrap();

    let token = CancellationToken::new();
    let host_ref: &dyn HostApi = &*host;
    runtime.init(host_ref).unwrap();

    runtime
        .evaluate_rule(&snapshot.rules[0], host_ref, &token)
        .unwrap()
}

// === Rule loading conformance tests ===

#[test]
fn rule_with_meta_and_detect_loads() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "TestFormat");
        function detect() {
            _setResult("info", "TestFormat", "1.0", "");
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x00]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].type_name, "info");
    assert_eq!(results[0].name, "TestFormat");
}

#[test]
fn rule_with_multiple_results() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "Multi");
        function detect() {
            _setResult("info", "Result1", "1.0", "");
            _setResult("info", "Result2", "2.0", "");
            _setResult("info", "Result3", "3.0", "");
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x00]);
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].name, "Result1");
    assert_eq!(results[1].name, "Result2");
    assert_eq!(results[2].name, "Result3");
}

#[test]
fn rule_with_set_lang() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "LangTest");
        function detect() {
            _setResult("info", "LangTest", "1.0", "");
            _setLang("C++", "17");
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x00]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].lang, "C++");
    assert_eq!(results[0].lang_version, "17");
}

#[test]
fn rule_with_no_detect_function() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "NoDetect");
        "#,
    );
    let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
    runtime.load_database(&snapshot).unwrap();

    let token = CancellationToken::new();
    let host = BufferHost::new(vec![0x00]);
    runtime.init(&host).unwrap();

    // evaluate_rule should succeed with empty results (no detect function
    // means no detections, which is not an error).
    let result = runtime.evaluate_rule(&snapshot.rules[0], &host, &token);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn rule_with_signature_check() {
    // MZ header (PE file)
    let snapshot = make_snapshot(
        r#"
        meta("info", "PECheck");
        function detect() {
            if (Binary.compare("4D5A", 0)) {
                _setResult("info", "PECheck", "1.0", "");
            }
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x4D, 0x5A, 0x90, 0x00]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "PECheck");
}

#[test]
fn rule_with_signature_check_no_match() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "PECheck");
        function detect() {
            if (Binary.compare("4D5A", 0)) {
                _setResult("info", "PECheck", "1.0", "");
            }
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x00, 0x00, 0x00, 0x00]);
    assert_eq!(results.len(), 0);
}

#[test]
fn rule_with_find_signature() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "FindTest");
        function detect() {
            var offset = Binary.findSignature(0, "4D5A");
            if (offset >= 0) {
                _setResult("info", "FindTest", String(offset), "");
            }
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x00, 0x00, 0x4D, 0x5A]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].version, "2");
}

#[test]
fn rule_with_read_byte() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "ByteTest");
        function detect() {
            var b = Binary.readByte(0);
            _setResult("info", "ByteTest", String(b), "");
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x42]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].version, "66"); // 0x42 = 66
}

#[test]
fn rule_with_read_word_le() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "WordTest");
        function detect() {
            var w = Binary.readWord(0);
            _setResult("info", "WordTest", String(w), "");
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x78, 0x56]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].version, "22136"); // 0x5678
}

#[test]
fn rule_with_get_size() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "SizeTest");
        function detect() {
            var size = Binary.getSize();
            _setResult("info", "SizeTest", String(size), "");
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x00; 100]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].version, "100");
}

#[test]
fn rule_with_entropy_check() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "EntropyTest");
        function detect() {
            var e = Binary.calculateEntropy(0, 100);
            _setResult("info", "EntropyTest", String(e), "");
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x00; 100]);
    assert_eq!(results.len(), 1);
    // All zeros -> entropy 0
    assert_eq!(results[0].version, "0");
}

#[test]
fn rule_with_is_deep_scan() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "DeepTest");
        function detect() {
            if (Binary.isDeepScan()) {
                _setResult("info", "DeepTest", "deep", "");
            } else {
                _setResult("info", "DeepTest", "shallow", "");
            }
        }
        "#,
    );

    // Non-deep scan
    let results = run_rule(&snapshot, vec![0x00]);
    assert_eq!(results[0].version, "shallow");
}

#[test]
fn rule_with_include_script() {
    let snapshot = make_snapshot_with_includes(
        r#"
        meta("info", "IncludeTest");
        includeScript("helpers");
        function detect() {
            _setResult("info", "IncludeTest", helperFunc(), "");
        }
        "#,
        &[("helpers", r#"function helperFunc() { return "helped"; }"#)],
    );
    let results = run_rule(&snapshot, vec![0x00]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].version, "helped");
}

#[test]
fn rule_with_get_engine_version() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "VersionTest");
        function detect() {
            var v = _getEngineVersion();
            _setResult("info", "VersionTest", v, "");
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x00]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].version, "3.10");
}

#[test]
fn rule_with_get_os() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "OSTest");
        function detect() {
            var os = _getOS();
            _setResult("info", "OSTest", os, "");
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x00]);
    assert_eq!(results.len(), 1);
    // Should return the current OS name (non-empty).
    assert!(!results[0].version.is_empty());
}

#[test]
fn rule_factory_creates_working_runtime() {
    let factory = RquickjsRuntimeFactory;
    let mut rt = factory.create(RuntimeConfig::default()).unwrap();
    let snapshot = make_snapshot(
        r#"
        meta("info", "FactoryTest");
        function detect() {
            _setResult("info", "FactoryTest", "1.0", "");
        }
        "#,
    );
    rt.load_database(&snapshot).unwrap();

    let token = CancellationToken::new();
    let host = BufferHost::new(vec![0x00]);
    rt.init(&host).unwrap();

    let results = rt.evaluate_rule(&snapshot.rules[0], &host, &token).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "FactoryTest");
}

#[test]
fn rule_with_shutdown_resets_state() {
    let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
    let snapshot = make_snapshot(
        r#"
        meta("info", "ShutdownTest");
        function detect() {
            _setResult("info", "ShutdownTest", "1.0", "");
        }
        "#,
    );
    runtime.load_database(&snapshot).unwrap();

    let token = CancellationToken::new();
    let host = BufferHost::new(vec![0x00]);
    runtime.init(&host).unwrap();

    let results = runtime
        .evaluate_rule(&snapshot.rules[0], &host, &token)
        .unwrap();
    assert_eq!(results.len(), 1);

    runtime.shutdown();

    // After shutdown, evaluate_rule should fail.
    let result = runtime.evaluate_rule(&snapshot.rules[0], &host, &token);
    assert!(result.is_err());
}

#[test]
fn rule_with_cancellation() {
    let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
    let snapshot = make_snapshot(
        r#"
        meta("info", "CancelTest");
        function detect() {
            _setResult("info", "CancelTest", "1.0", "");
        }
        "#,
    );
    runtime.load_database(&snapshot).unwrap();

    let host = BufferHost::new(vec![0x00]);
    runtime.init(&host).unwrap();

    // Create a cancelled token.
    let token = CancellationToken::new();
    token.cancel();

    let result = runtime.evaluate_rule(&snapshot.rules[0], &host, &token);
    assert!(result.is_err());
    match result.unwrap_err() {
        RuleError::Cancelled => {}
        other => panic!("expected Cancelled, got {other:?}"),
    }
}

#[test]
fn rule_with_u8_alias() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "U8Test");
        function detect() {
            var v = X.U8(0);
            _setResult("info", "U8Test", String(v), "");
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0xFF]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].version, "255");
}

#[test]
fn rule_with_u32_alias() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "U32Test");
        function detect() {
            var v = X.U32(0);
            _setResult("info", "U32Test", String(v), "");
        }
        "#,
    );
    let results = run_rule(&snapshot, vec![0x78, 0x56, 0x34, 0x12]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].version, "305419896"); // 0x12345678
}

#[test]
fn rule_with_get_string() {
    let snapshot = make_snapshot(
        r#"
        meta("info", "StringTest");
        function detect() {
            var s = Binary.getString(0, 5);
            _setResult("info", "StringTest", s, "");
        }
        "#,
    );
    let results = run_rule(&snapshot, b"Hello\0World".to_vec());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].version, "Hello");
}

#[test]
fn rule_with_multiple_rules_in_snapshot() {
    let snapshot = DatabaseSnapshot {
        rules: vec![
            LoadedRule {
                path: "rule1.sg".into(),
                ordinal: 0,
                file_type: "Binary".into(),
                source: r#"
                    meta("info", "Rule1");
                    function detect() {
                        _setResult("info", "Rule1", "1.0", "");
                    }
                "#
                .to_string(),
            },
            LoadedRule {
                path: "rule2.sg".into(),
                ordinal: 1,
                file_type: "Binary".into(),
                source: r#"
                    meta("info", "Rule2");
                    function detect() {
                        _setResult("info", "Rule2", "2.0", "");
                    }
                "#
                .to_string(),
            },
        ],
        init_script: None,
        type_init_scripts: Vec::new(),
        include_scripts: BTreeMap::new(),
    };

    let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
    runtime.load_database(&snapshot).unwrap();

    let host = BufferHost::new(vec![0x00]);
    let token = CancellationToken::new();
    runtime.init(&host).unwrap();

    // Evaluate the second rule — since rules share the global scope,
    // the last-defined detect() wins. This is expected behavior in
    // the current simple implementation.
    let results = runtime
        .evaluate_rule(&snapshot.rules[1], &host, &token)
        .unwrap();
    assert_eq!(results.len(), 1);
}

/// `PE.isNET` was removed upstream (@2550d2d) and the vendored ruleset was
/// re-synced to pinned `8925358d`, which has no `PE.isNET()` callers. The
/// compatibility alias was dropped for exact parity: `isNET` must be
/// `undefined` while the canonical `isNet` remains a function.
#[test]
fn rule_pe_isnet_alias_absent_isnet_present() {
    let snapshot = DatabaseSnapshot {
        rules: vec![LoadedRule {
            path: "test.sg".into(),
            ordinal: 0,
            file_type: "PE".into(),
            source: r#"
                meta("info", "IsNetSurface");
                function detect() {
                    if (typeof PE.isNET === "undefined" &&
                        typeof PE.isNet === "function") {
                        _setResult("info", "IsNetSurface", "1.0", "");
                    }
                }
            "#
            .to_string(),
        }],
        init_script: None,
        type_init_scripts: Vec::new(),
        include_scripts: BTreeMap::new(),
    };
    let results = run_rule(&snapshot, vec![0x4D, 0x5A]);
    assert_eq!(results.len(), 1, "PE.isNET alias must be absent (parity)");
}

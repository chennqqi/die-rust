//! `diec-output` renders scan results into canonical JSON and
//! human-readable text output.
//!
//! It only performs presentation conversion and never duplicates detection,
//! nesting, ordering or diagnostic logic. Canonical JSON is the stable data
//! plane shared by the library, FFI and modern CLI.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod delimited;
mod json;
pub mod struct_formatter;
mod text;
mod xml;

pub use delimited::{render_csv, render_tsv};
pub use json::{render_json, render_json_upstream};
pub use struct_formatter::{
    render_struct_csv, render_struct_json, render_struct_text, render_struct_tsv, render_struct_xml,
};
pub use text::{render_text, render_text_formatted};
pub use xml::render_xml;

#[cfg(test)]
mod tests {
    use super::*;
    use diec_engine::ScanDetection;

    fn sample_result() -> diec_engine::ScanResult {
        diec_engine::ScanResult {
            path: "test.7z".into(),
            detections: vec![ScanDetection {
                file_type: "Binary".into(),
                type_name: "archive".into(),
                name: "7-Zip".into(),
                version: Some("0.4".into()),
                options: None,
                signature_path: None,
                id: None,
                parent_id: None,
                file_part: None,
                offset: None,
                size: None,
                is_heuristic: None,
                is_a_heuristic: None,
                original_name: None,
                engine: None,
            }],
            diagnostics: vec![],
            structured_diagnostics: vec![],
            profiling: vec![],
        }
    }

    #[test]
    fn json_contains_detection() {
        let result = sample_result();
        let json = render_json(&result);
        assert!(json.contains("7-Zip"));
        assert!(json.contains("archive"));
        assert!(json.contains("0.4"));
        assert!(json.contains("test.7z"));
    }

    #[test]
    fn json_upstream_contains_detection() {
        let result = sample_result();
        let json = render_json_upstream(&result);
        // Upstream format: array of objects with fileType/name/string/version.
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        assert!(json.contains("\"fileType\":\"Binary\""));
        assert!(json.contains("\"name\":\"7-Zip\""));
        assert!(json.contains("\"string\":\"archive\""));
        assert!(json.contains("\"version\":\"0.4\""));
        // Must NOT contain canonical-format field names.
        assert!(!json.contains("\"file_type\""));
        assert!(!json.contains("\"type_name\""));
        assert!(!json.contains("\"detections\""));
    }

    #[test]
    fn json_upstream_empty_result() {
        let result = diec_engine::ScanResult {
            path: "empty.bin".into(),
            detections: vec![],
            diagnostics: vec![],
            structured_diagnostics: vec![],
            profiling: vec![],
        };
        let json = render_json_upstream(&result);
        assert_eq!(json, "[]");
    }

    #[test]
    fn json_upstream_offset_as_hex() {
        let result = diec_engine::ScanResult {
            path: "test.bin".into(),
            detections: vec![ScanDetection {
                file_type: "PE".into(),
                type_name: "compiler".into(),
                name: "TestCompiler".into(),
                version: Some("1.0".into()),
                options: Some("console".into()),
                signature_path: None,
                id: None,
                parent_id: None,
                file_part: None,
                offset: Some(0x260),
                size: None,
                is_heuristic: None,
                is_a_heuristic: None,
                original_name: None,
                engine: None,
            }],
            diagnostics: vec![],
            structured_diagnostics: vec![],
            profiling: vec![],
        };
        let json = render_json_upstream(&result);
        assert!(json.contains("\"offset\":\"0x260\""));
        assert!(json.contains("\"info\":\"console\""));
        assert!(json.contains("\"version\":\"1.0\""));
    }

    #[test]
    fn text_contains_detection() {
        let result = sample_result();
        let text = render_text(&result);
        assert!(text.contains("7-Zip"));
        assert!(text.contains("test.7z"));
    }

    #[test]
    fn json_is_valid_json() {
        let result = sample_result();
        let json = render_json(&result);
        // Verify it starts and ends with JSON object delimiters.
        assert!(json.trim_start().starts_with('{'));
        assert!(json.trim_end().ends_with('}'));
    }

    #[test]
    fn empty_result_renders() {
        let result = diec_engine::ScanResult {
            path: "empty.bin".into(),
            detections: vec![],
            diagnostics: vec![],
            structured_diagnostics: vec![],
            profiling: vec![],
        };
        let json = render_json(&result);
        assert!(json.contains("empty.bin"));
        assert!(json.contains("\"detections\""));
        let text = render_text(&result);
        assert!(text.contains("empty.bin"));
    }

    /// Verify that Optional fields with `None` values do not appear in JSON
    /// output. This is the compatibility guarantee: existing CLI JSON output
    /// must remain byte-identical when no new fields are populated.
    #[test]
    fn json_none_fields_omitted() {
        let result = sample_result();
        let json = render_json(&result);
        // None fields must not appear in the JSON output.
        assert!(!json.contains("\"id\""));
        assert!(!json.contains("\"parent_id\""));
        assert!(!json.contains("\"file_part\""));
        assert!(!json.contains("\"offset\""));
        assert!(!json.contains("\"size\""));
        assert!(!json.contains("\"is_heuristic\""));
        assert!(!json.contains("\"is_a_heuristic\""));
        assert!(!json.contains("\"original_name\""));
    }

    /// Verify that Optional fields with `Some` values do appear in JSON output.
    #[test]
    fn json_some_fields_present() {
        let result = diec_engine::ScanResult {
            path: "test.bin".into(),
            detections: vec![ScanDetection {
                file_type: "PE".into(),
                type_name: "compiler".into(),
                name: "TestCompiler".into(),
                version: None,
                options: None,
                signature_path: None,
                id: Some("abc-123".into()),
                parent_id: None,
                file_part: Some("Resource".into()),
                offset: Some(0x260),
                size: Some(0x14),
                is_heuristic: Some(true),
                is_a_heuristic: None,
                original_name: None,
                engine: None,
            }],
            diagnostics: vec![],
            structured_diagnostics: vec![],
            profiling: vec![],
        };
        let json = render_json(&result);
        assert!(json.contains("\"id\":\"abc-123\""));
        assert!(json.contains("\"file_part\":\"Resource\""));
        assert!(json.contains("\"offset\":608"));
        assert!(json.contains("\"size\":20"));
        assert!(json.contains("\"is_heuristic\":true"));
        // None fields must still be omitted.
        assert!(!json.contains("\"parent_id\""));
        assert!(!json.contains("\"is_a_heuristic\""));
        assert!(!json.contains("\"original_name\""));
    }
}

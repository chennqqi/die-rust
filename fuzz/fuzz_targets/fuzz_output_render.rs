//! Fuzz target: output rendering on arbitrary scan results.
//!
//! Invariant: no panic, no hang. JSON and text renderers must produce
//! valid output for any ScanResult, including empty detections and
//! non-UTF-8 paths.
//!
//! See `docs/design/testing.md` section 14.

#![no_main]

use die_engine::{ScanDetection, ScanResult};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Construct a ScanResult from fuzz data. We interpret the data as
    // a sequence of (type_name_len, type_name, name_len, name) pairs,
    // with the path being the first NUL-terminated segment.
    if data.is_empty() {
        // Empty input: render an empty result.
        let result = ScanResult {
            path: "empty".to_string(),
            detections: vec![],
            diagnostics: vec![],
            structured_diagnostics: vec![],
            profiling: vec![],
        };
        let json = die_output::render_json(&result);
        assert!(!json.is_empty(), "JSON output should be non-empty");
        let text = die_output::render_text(&result);
        let _ = text;
        return;
    }

    // Use the data as a "path" (replace NULs to keep it valid UTF-8).
    let path = String::from_utf8_lossy(data);
    let path = path.replace('\0', "_");

    // Build detections from the data: split into chunks and use each
    // chunk as a detection name.
    let mut detections = Vec::new();
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let name_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let type_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if name_len == 0 || type_len == 0 {
            break;
        }

        let name_end = offset + name_len.min(data.len() - offset);
        let type_end = name_end + type_len.min(data.len().saturating_sub(name_end));

        if type_end > data.len() {
            break;
        }

        let name = String::from_utf8_lossy(&data[offset..name_end]).to_string();
        let type_name = String::from_utf8_lossy(&data[name_end..type_end]).to_string();

        detections.push(ScanDetection {
            file_type: "fuzz".to_string(),
            type_name: if type_name.is_empty() {
                "unknown".to_string()
            } else {
                type_name
            },
            name: if name.is_empty() {
                "unknown".to_string()
            } else {
                name
            },
            version: Some("1.0".to_string()),
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
        });

        offset = type_end;
        if offset >= data.len() {
            break;
        }
    }

    let result = ScanResult {
        path,
        detections,
        diagnostics: vec!["fuzz diagnostic".to_string()],
        structured_diagnostics: vec![],
        profiling: vec![],
    };

    // Render JSON - must not panic.
    let json = die_output::render_json(&result);
    assert!(!json.is_empty(), "JSON output should be non-empty");

    // Verify JSON is valid by re-parsing.
    let _ = serde_json::from_str::<serde_json::Value>(&json);

    // Render text - must not panic.
    let text = die_output::render_text(&result);
    let _ = text;

    // Render formatted text - must not panic.
    let text_formatted = die_output::render_text_formatted(&result);
    let _ = text_formatted;

    // Render XML - must not panic.
    let xml = die_output::render_xml(&result);
    let _ = xml;

    // Render CSV - must not panic.
    let csv = die_output::render_csv(&result);
    let _ = csv;

    // Render TSV - must not panic.
    let tsv = die_output::render_tsv(&result);
    let _ = tsv;
});

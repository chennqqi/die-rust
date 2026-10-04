//! Canonical JSON renderer for scan results.
//!
//! Produces a stable, single-document JSON object with deterministic
//! field ordering. No external JSON library is used to avoid adding
//! a workspace dependency.

use die_engine::ScanResult;

/// Escape a string for JSON output.
fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Render a scan result as upstream DIE-engine compatible JSON.
///
/// Upstream `diec --json` outputs a JSON array of detection objects, each
/// with fields: `fileType`, `name`, `string`, `info`, `version`, `offset`.
/// This renderer matches that structure for tooling compatibility.
///
/// Field mapping:
/// - `fileType` <- `file_type` (e.g., "PE", "ELF", "Binary")
/// - `name` <- `name` (detection name, e.g., "Microsoft Linker")
/// - `string` <- `type_name` (detection type, e.g., "compiler", "linker")
/// - `info` <- `options` (additional info, if present)
/// - `version` <- `version` (version string, if present)
/// - `offset` <- `offset` (hex string, if present)
pub fn render_json_upstream(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push('[');
    for (i, det) in result.detections.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        out.push_str("\"fileType\":\"");
        out.push_str(&escape_json(&det.file_type));
        out.push_str("\",");
        out.push_str("\"name\":\"");
        out.push_str(&escape_json(&det.name));
        out.push_str("\",");
        out.push_str("\"string\":\"");
        out.push_str(&escape_json(&det.type_name));
        out.push('"');
        if let Some(info) = &det.options {
            out.push_str(",\"info\":\"");
            out.push_str(&escape_json(info));
            out.push('"');
        }
        if let Some(v) = &det.version {
            out.push_str(",\"version\":\"");
            out.push_str(&escape_json(v));
            out.push('"');
        }
        if let Some(off) = det.offset {
            out.push_str(",\"offset\":\"0x");
            out.push_str(&format!("{:x}", off));
            out.push('"');
        }
        out.push('}');
    }
    out.push(']');
    out
}

/// Render a scan result as canonical JSON.
pub fn render_json(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str("\"path\":\"");
    out.push_str(&escape_json(&result.path));
    out.push_str("\",");

    out.push_str("\"detections\":[");
    for (i, det) in result.detections.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        out.push_str("\"file_type\":\"");
        out.push_str(&escape_json(&det.file_type));
        out.push_str("\",");
        out.push_str("\"type\":\"");
        out.push_str(&escape_json(&det.type_name));
        out.push_str("\",");
        out.push_str("\"name\":\"");
        out.push_str(&escape_json(&det.name));
        out.push('"');
        if let Some(v) = &det.version {
            out.push_str(",\"version\":\"");
            out.push_str(&escape_json(v));
            out.push('"');
        }
        if let Some(o) = &det.options {
            out.push_str(",\"options\":\"");
            out.push_str(&escape_json(o));
            out.push('"');
        }
        if let Some(id) = &det.id {
            out.push_str(",\"id\":\"");
            out.push_str(&escape_json(id));
            out.push('"');
        }
        if let Some(pid) = &det.parent_id {
            out.push_str(",\"parent_id\":\"");
            out.push_str(&escape_json(pid));
            out.push('"');
        }
        if let Some(fp) = &det.file_part {
            out.push_str(",\"file_part\":\"");
            out.push_str(&escape_json(fp));
            out.push('"');
        }
        if let Some(off) = det.offset {
            out.push_str(",\"offset\":");
            out.push_str(&off.to_string());
        }
        if let Some(sz) = det.size {
            out.push_str(",\"size\":");
            out.push_str(&sz.to_string());
        }
        if let Some(h) = det.is_heuristic {
            out.push_str(",\"is_heuristic\":");
            out.push_str(if h { "true" } else { "false" });
        }
        if let Some(ah) = det.is_a_heuristic {
            out.push_str(",\"is_a_heuristic\":");
            out.push_str(if ah { "true" } else { "false" });
        }
        if let Some(on) = &det.original_name {
            out.push_str(",\"original_name\":\"");
            out.push_str(&escape_json(on));
            out.push('"');
        }
        if let Some(eng) = &det.engine {
            out.push_str(",\"engine\":\"");
            out.push_str(&escape_json(eng));
            out.push('"');
        }
        out.push('}');
    }
    out.push(']');

    if !result.diagnostics.is_empty() {
        out.push_str(",\"diagnostics\":[");
        for (i, diag) in result.diagnostics.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(&escape_json(diag));
            out.push('"');
        }
        out.push(']');
    }

    if !result.structured_diagnostics.is_empty() {
        out.push_str(",\"structured_diagnostics\":[");
        for (i, diag) in result.structured_diagnostics.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"file\":\"");
            out.push_str(&escape_json(&diag.file));
            out.push_str("\",\"message\":\"");
            out.push_str(&escape_json(&diag.message));
            out.push_str("\",\"kind\":\"");
            out.push_str(&escape_json(&diag.kind));
            out.push('"');
            if let Some(line) = diag.line {
                out.push_str(&format!(",\"line\":{}", line));
            }
            out.push('}');
        }
        out.push(']');
    }

    if !result.profiling.is_empty() {
        out.push_str(",\"profiling\":[");
        for (i, prof) in result.profiling.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"file\":\"");
            out.push_str(&escape_json(&prof.file));
            out.push_str(&format!("\",\"elapsed_ms\":{}}}", prof.elapsed_ms));
        }
        out.push(']');
    }

    out.push('}');
    out
}

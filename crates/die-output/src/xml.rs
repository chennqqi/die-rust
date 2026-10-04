//! XML renderer for scan results.
//!
//! Produces a simple XML document matching the upstream DIE-engine
//! XML output structure. No external XML library is used.

use die_engine::ScanResult;

/// Escape a string for XML output.
fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {
                out.push_str(&format!("&#x{:x};", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Render a scan result as XML.
pub fn render_xml(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<Result>\n");
    out.push_str("  <Path>");
    out.push_str(&escape_xml(&result.path));
    out.push_str("</Path>\n");

    out.push_str("  <Detections>\n");
    for det in &result.detections {
        out.push_str("    <Detection>\n");
        out.push_str("      <FileType>");
        out.push_str(&escape_xml(&det.file_type));
        out.push_str("</FileType>\n");
        out.push_str("      <Type>");
        out.push_str(&escape_xml(&det.type_name));
        out.push_str("</Type>\n");
        out.push_str("      <Name>");
        out.push_str(&escape_xml(&det.name));
        out.push_str("</Name>\n");
        if let Some(v) = &det.version {
            out.push_str("      <Version>");
            out.push_str(&escape_xml(v));
            out.push_str("</Version>\n");
        }
        if let Some(o) = &det.options {
            out.push_str("      <Options>");
            out.push_str(&escape_xml(o));
            out.push_str("</Options>\n");
        }
        if let Some(id) = &det.id {
            out.push_str("      <Id>");
            out.push_str(&escape_xml(id));
            out.push_str("</Id>\n");
        }
        if let Some(pid) = &det.parent_id {
            out.push_str("      <ParentId>");
            out.push_str(&escape_xml(pid));
            out.push_str("</ParentId>\n");
        }
        if let Some(fp) = &det.file_part {
            out.push_str("      <FilePart>");
            out.push_str(&escape_xml(fp));
            out.push_str("</FilePart>\n");
        }
        if let Some(off) = det.offset {
            out.push_str("      <Offset>");
            out.push_str(&off.to_string());
            out.push_str("</Offset>\n");
        }
        if let Some(sz) = det.size {
            out.push_str("      <Size>");
            out.push_str(&sz.to_string());
            out.push_str("</Size>\n");
        }
        if let Some(h) = det.is_heuristic {
            out.push_str("      <IsHeuristic>");
            out.push_str(if h { "true" } else { "false" });
            out.push_str("</IsHeuristic>\n");
        }
        if let Some(ah) = det.is_a_heuristic {
            out.push_str("      <IsAHeuristic>");
            out.push_str(if ah { "true" } else { "false" });
            out.push_str("</IsAHeuristic>\n");
        }
        if let Some(on) = &det.original_name {
            out.push_str("      <OriginalName>");
            out.push_str(&escape_xml(on));
            out.push_str("</OriginalName>\n");
        }
        out.push_str("    </Detection>\n");
    }
    out.push_str("  </Detections>\n");

    if !result.diagnostics.is_empty() {
        out.push_str("  <Diagnostics>\n");
        for diag in &result.diagnostics {
            out.push_str("    <Diagnostic>");
            out.push_str(&escape_xml(diag));
            out.push_str("</Diagnostic>\n");
        }
        out.push_str("  </Diagnostics>\n");
    }

    if !result.structured_diagnostics.is_empty() {
        out.push_str("  <StructuredDiagnostics>\n");
        for diag in &result.structured_diagnostics {
            out.push_str("    <DiagnosticEntry");
            out.push_str(" file=\"");
            out.push_str(&escape_xml(&diag.file));
            out.push_str("\" kind=\"");
            out.push_str(&escape_xml(&diag.kind));
            out.push('"');
            if let Some(line) = diag.line {
                out.push_str(&format!(" line=\"{}\"", line));
            }
            out.push('>');
            out.push_str(&escape_xml(&diag.message));
            out.push_str("</DiagnosticEntry>\n");
        }
        out.push_str("  </StructuredDiagnostics>\n");
    }

    if !result.profiling.is_empty() {
        out.push_str("  <Profiling>\n");
        for prof in &result.profiling {
            out.push_str("    <Signature file=\"");
            out.push_str(&escape_xml(&prof.file));
            out.push_str(&format!("\" elapsed_ms=\"{}\"/>\n", prof.elapsed_ms));
        }
        out.push_str("  </Profiling>\n");
    }

    out.push_str("</Result>\n");
    out
}

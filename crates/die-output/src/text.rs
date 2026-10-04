//! Human-readable text renderer for scan results.
//!
//! Produces a simple, color-free text output suitable for terminal
//! display. Each detection is shown on its own line with the file
//! path, type, name, version and options.

use die_engine::ScanResult;

/// Render a scan result as human-readable text.
///
/// Only detections are shown by default. Diagnostics are suppressed
/// in text mode to keep output clean; they are available in JSON mode.
pub fn render_text(result: &ScanResult) -> String {
    let mut out = String::new();

    if result.detections.is_empty() {
        out.push_str(&format!("{}: no detections\n", result.path));
    } else {
        for det in &result.detections {
            out.push_str(&format!("{}: ", result.path));
            out.push_str(&det.type_name);
            out.push_str(": ");
            out.push_str(&det.name);
            if let Some(v) = &det.version
                && !v.is_empty()
            {
                out.push_str(" (");
                out.push_str(v);
                out.push(')');
            }
            if let Some(o) = &det.options
                && !o.is_empty()
            {
                out.push_str(" [");
                out.push_str(o);
                out.push(']');
            }
            out.push('\n');
        }
    }

    out
}

/// Render a scan result as formatted text (--format flag).
///
/// Upstream `--format` adds extra spacing around separators for
/// improved readability. The display strings have additional spaces
/// around the type separator and version/option brackets.
pub fn render_text_formatted(result: &ScanResult) -> String {
    let mut out = String::new();

    if result.detections.is_empty() {
        out.push_str(&format!("{}: no detections\n", result.path));
    } else {
        for det in &result.detections {
            out.push_str(&format!("{}:  ", result.path));
            out.push_str(&det.type_name);
            out.push_str(" :  ");
            out.push_str(&det.name);
            if let Some(v) = &det.version
                && !v.is_empty()
            {
                out.push_str("  (");
                out.push_str(v);
                out.push_str(") ");
            }
            if let Some(o) = &det.options
                && !o.is_empty()
            {
                out.push_str("  [");
                out.push_str(o);
                out.push_str("] ");
            }
            out.push('\n');
        }
    }

    out
}

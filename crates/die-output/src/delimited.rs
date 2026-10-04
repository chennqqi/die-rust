//! CSV and TSV renderers for scan results.
//!
//! Produces tabular output with one row per detection.
//! CSV uses comma separation, TSV uses tab separation.

use die_engine::ScanResult;

/// Escape a field for CSV output (RFC 4180).
fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

/// Render a scan result as CSV.
pub fn render_csv(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str("path,file_type,type,name,version,options\n");
    for det in &result.detections {
        out.push_str(&escape_csv(&result.path));
        out.push(',');
        out.push_str(&escape_csv(&det.file_type));
        out.push(',');
        out.push_str(&escape_csv(&det.type_name));
        out.push(',');
        out.push_str(&escape_csv(&det.name));
        out.push(',');
        out.push_str(&escape_csv(det.version.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&escape_csv(det.options.as_deref().unwrap_or("")));
        out.push('\n');
    }
    out
}

/// Render a scan result as TSV.
pub fn render_tsv(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str("path\tfile_type\ttype\tname\tversion\toptions\n");
    for det in &result.detections {
        out.push_str(&result.path);
        out.push('\t');
        out.push_str(&det.file_type);
        out.push('\t');
        out.push_str(&det.type_name);
        out.push('\t');
        out.push_str(&det.name);
        out.push('\t');
        out.push_str(det.version.as_deref().unwrap_or(""));
        out.push('\t');
        out.push_str(det.options.as_deref().unwrap_or(""));
        out.push('\n');
    }
    out
}

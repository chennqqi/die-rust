//! Struct mode output formatters for `--struct <value>` mode.
//!
//! Implements 5 output formats matching upstream `XFileInfo` struct output:
//! - JSON: top-level `data` object, leaf values as strings
//! - XML: recursive `record` elements, leaf values in `value` attribute
//! - CSV: no header, parent nodes as name-only rows
//! - TSV: same as CSV with tab delimiter
//! - Text: `key: value` with hierarchical indentation
//!
//! Output format priority (specialized modes): JSON > XML > CSV > TSV > text.

use die_engine::StructNode;

/// Render a struct node tree as JSON.
///
/// Top-level object has a `data` key. Leaf values are serialized as strings.
/// Parent nodes have nested objects.
pub fn render_struct_json(node: &StructNode) -> String {
    let mut out = String::from("{\"data\":");
    render_struct_json_node(node, &mut out);
    out.push('}');
    out
}

/// Recursively render a struct node as JSON.
fn render_struct_json_node(node: &StructNode, out: &mut String) {
    if node.children.is_empty()
        && let Some(ref val) = node.value
    {
        // Leaf node: serialize value as string.
        out.push('"');
        json_escape_string(&node.name, out);
        out.push_str("\":\"");
        json_escape_string(val, out);
        out.push('"');
    } else if node.children.is_empty() {
        // Empty parent: empty string value.
        out.push('"');
        json_escape_string(&node.name, out);
        out.push_str("\":\"\"");
    } else {
        // Parent node: nested object.
        out.push('"');
        json_escape_string(&node.name, out);
        out.push_str("\":{");
        for (i, child) in node.children.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            render_struct_json_node(child, out);
        }
        out.push('}');
    }
}

/// Escape a string for JSON output.
fn json_escape_string(s: &str, out: &mut String) {
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
}

/// Render a struct node tree as XML.
///
/// Uses recursive `record` elements. Leaf values are in the `value` attribute.
/// Parent nodes contain child `record` elements.
pub fn render_struct_xml(node: &StructNode) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<data>");
    render_struct_xml_node(node, &mut out, 0);
    out.push_str("</data>\n");
    out
}

/// Recursively render a struct node as XML.
fn render_struct_xml_node(node: &StructNode, out: &mut String, indent: usize) {
    let prefix = "  ".repeat(indent);
    if node.children.is_empty()
        && let Some(ref val) = node.value
    {
        // Leaf node: value in attribute.
        out.push_str(&format!(
            "{prefix}<record name=\"{}\" value=\"{}\"/>\n",
            escape_xml(&node.name),
            escape_xml(val)
        ));
    } else if node.children.is_empty() {
        // Empty parent.
        out.push_str(&format!(
            "{prefix}<record name=\"{}\"/>\n",
            escape_xml(&node.name)
        ));
    } else {
        // Parent node.
        out.push_str(&format!(
            "{prefix}<record name=\"{}\">\n",
            escape_xml(&node.name)
        ));
        for child in &node.children {
            render_struct_xml_node(child, out, indent + 1);
        }
        out.push_str(&format!("{prefix}</record>\n"));
    }
}

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

/// Render a struct node tree as CSV.
///
/// No header row. Parent nodes output as name-only rows (empty value).
/// Leaf nodes output as `name,value` rows.
pub fn render_struct_csv(node: &StructNode) -> String {
    let mut out = String::new();
    render_struct_delimited(node, &mut out, ',');
    out
}

/// Render a struct node tree as TSV.
///
/// Same as CSV but with tab delimiter.
pub fn render_struct_tsv(node: &StructNode) -> String {
    let mut out = String::new();
    render_struct_delimited(node, &mut out, '\t');
    out
}

/// Render a struct node tree as delimited text (CSV or TSV).
fn render_struct_delimited(node: &StructNode, out: &mut String, delim: char) {
    if node.children.is_empty()
        && let Some(ref val) = node.value
    {
        // Leaf node: name,value.
        out.push_str(&node.name);
        out.push(delim);
        out.push_str(val);
        out.push('\n');
    } else if node.children.is_empty() {
        // Empty parent: name only (empty value).
        out.push_str(&node.name);
        out.push(delim);
        out.push('\n');
    } else {
        // Parent node: output name with empty value, then children.
        out.push_str(&node.name);
        out.push(delim);
        out.push('\n');
        for child in &node.children {
            render_struct_delimited(child, out, delim);
        }
    }
}

/// Render a struct node tree as text.
///
/// Uses `key: value` with hierarchical indentation.
pub fn render_struct_text(node: &StructNode) -> String {
    render_struct_text_inner(node, 0)
}

/// Recursively render a struct node as text.
fn render_struct_text_inner(node: &StructNode, indent: usize) -> String {
    let mut out = String::new();
    let prefix = "  ".repeat(indent);
    if let Some(ref val) = node.value {
        out.push_str(&format!("{prefix}{}: {val}\n", node.name));
    } else if node.children.is_empty() {
        out.push_str(&format!("{prefix}{}:\n", node.name));
    } else {
        out.push_str(&format!("{prefix}{}:\n", node.name));
        for child in &node.children {
            out.push_str(&render_struct_text_inner(child, indent + 1));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tree() -> StructNode {
        StructNode::parent(
            "Hash",
            vec![
                StructNode::leaf("MD5", "d41d8cd98f00b204e9800998ecf8427e"),
                StructNode::leaf("SHA256", "e3b0c44298fc1c149afbf4c8996fb924"),
            ],
        )
    }

    #[test]
    fn json_has_data_key() {
        let node = sample_tree();
        let json = render_struct_json(&node);
        assert!(json.contains("\"data\""));
        assert!(json.contains("\"Hash\""));
        assert!(json.contains("\"MD5\""));
        assert!(json.contains("d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn json_leaf_value_is_string() {
        let node = StructNode::leaf("MD5", "abc123");
        let json = render_struct_json(&node);
        // Leaf at top level: {"data":"MD5":"abc123"}}
        assert!(json.contains("\"MD5\":\"abc123\""));
    }

    #[test]
    fn xml_has_record_elements() {
        let node = sample_tree();
        let xml = render_struct_xml(&node);
        assert!(xml.contains("<data>"));
        assert!(xml.contains("record"));
        assert!(xml.contains("Hash"));
        assert!(xml.contains("d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn csv_has_no_header() {
        let node = sample_tree();
        let csv = render_struct_csv(&node);
        // First line should be "Hash," (parent with empty value).
        assert!(csv.starts_with("Hash,"));
        assert!(csv.contains("MD5,d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn tsv_uses_tabs() {
        let node = StructNode::leaf("MD5", "abc123");
        let tsv = render_struct_tsv(&node);
        assert!(tsv.contains("MD5\tabc123"));
    }

    #[test]
    fn text_uses_indentation() {
        let node = sample_tree();
        let text = render_struct_text(&node);
        assert!(text.contains("Hash:"));
        assert!(text.contains("  MD5: d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn empty_parent_renders_correctly() {
        let node = StructNode::empty_parent("NoSuch");
        let json = render_struct_json(&node);
        assert!(json.contains("\"NoSuch\":\"\""));
        let text = render_struct_text(&node);
        assert!(text.contains("NoSuch:"));
    }
}

//! Rule inventory and metadata extraction.
//!
//! At database build time, each `.sg` rule file is scanned to extract:
//! - The `meta()` call arguments (type, name).
//! - Literal `includeScript("name")` calls for the include graph.
//! - Whether a `detect()` function is defined.
//!
//! This is a lightweight static scan, not a full JavaScript parse. It uses
//! simple pattern matching to extract the metadata without executing the
//! script. Unknown syntax is not flagged here — that is the runtime's job
//! during `load_database`.
//!
//! See `docs/research/rule-compatibility.md` for the rule file structure.

use std::collections::BTreeMap;

/// Metadata extracted from a single rule file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMetadata {
    /// Relative path of the rule file (e.g. "db/Binary/ELF.1.sg").
    pub path: String,
    /// File size in bytes.
    pub size: u64,
    /// Detection type from `meta()` (e.g. "info", "packer", "compiler").
    pub type_name: String,
    /// Detection name from `meta()` (e.g. "UPX", "ELF").
    pub name: String,
    /// Scripts included via literal `includeScript("name")` calls.
    pub includes: Vec<String>,
    /// Whether the file defines a `detect()` function.
    pub has_detect: bool,
    /// Whether the file defines a `result()` function.
    pub has_result: bool,
}

/// Extract metadata from a rule file's source text.
///
/// This performs a simple static scan:
/// - Looks for `meta("type", "name"` pattern.
/// - Looks for `includeScript("name")` patterns.
/// - Looks for `function detect()` pattern.
/// - Looks for `function result()` pattern.
///
/// Returns `None` if the file does not appear to be a valid rule file
/// (e.g. no `meta()` call found).
pub fn extract_metadata(path: &str, source: &str) -> Option<RuleMetadata> {
    let (type_name, name) = extract_meta_call(source)?;
    let includes = extract_includes(source);
    let has_detect = source.contains("function detect(") || source.contains("function detect (");
    let has_result = source.contains("function result(") || source.contains("function result (");

    Some(RuleMetadata {
        path: path.to_string(),
        size: source.len() as u64,
        type_name,
        name,
        includes,
        has_detect,
        has_result,
    })
}

/// Extract the `meta("type", "name")` call arguments.
///
/// The upstream pattern is:
/// ```javascript
/// meta("type", "name");
/// ```
/// or with single quotes:
/// ```javascript
/// meta('type', 'name');
/// ```
///
/// Returns `None` if no `meta()` call is found.
fn extract_meta_call(source: &str) -> Option<(String, String)> {
    let meta_idx = source.find("meta(")?;
    let after_meta = &source[meta_idx + 5..];

    // Find the first string argument.
    let type_name = extract_first_string(after_meta)?;
    let after_type = skip_string_and_comma(after_meta)?;

    // Find the second string argument (may be empty).
    let name = extract_first_string(after_type).unwrap_or_default();

    Some((type_name, name))
}

/// Extract all literal `includeScript("name")` calls.
fn extract_includes(source: &str) -> Vec<String> {
    let mut includes = Vec::new();
    let mut search_from = 0;

    while let Some(idx) = source[search_from..].find("includeScript(") {
        let abs_idx = search_from + idx;
        let after = &source[abs_idx + "includeScript(".len()..];

        if let Some(name) = extract_first_string(after)
            && !includes.contains(&name)
        {
            includes.push(name);
        }

        search_from = abs_idx + "includeScript(".len();
    }

    includes
}

/// Extract the first quoted string from the source.
///
/// Handles both single and double quotes. Returns the string content
/// without quotes, or `None` if no string is found.
fn extract_first_string(source: &str) -> Option<String> {
    let bytes = source.as_bytes();
    let mut i = 0;

    // Skip whitespace.
    while i < bytes.len()
        && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
    {
        i += 1;
    }

    if i >= bytes.len() {
        return None;
    }

    let quote = bytes[i];
    if quote != b'"' && quote != b'\'' {
        return None;
    }

    i += 1;
    let start = i;

    while i < bytes.len() && bytes[i] != quote {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
        } else {
            i += 1;
        }
    }

    if i >= bytes.len() {
        return None;
    }

    let content = &source[start..i];
    Some(unescape_string(content))
}

/// Skip past a string literal and the following comma/whitespace.
fn skip_string_and_comma(source: &str) -> Option<&str> {
    let bytes = source.as_bytes();
    let mut i = 0;

    while i < bytes.len()
        && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
    {
        i += 1;
    }

    if i >= bytes.len() {
        return None;
    }

    let quote = bytes[i];
    if quote != b'"' && quote != b'\'' {
        return None;
    }

    i += 1;
    while i < bytes.len() && bytes[i] != quote {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
        } else {
            i += 1;
        }
    }

    if i >= bytes.len() {
        return None;
    }

    i += 1; // skip closing quote

    // Skip whitespace and comma.
    while i < bytes.len()
        && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
    {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b',' {
        i += 1;
    }

    Some(&source[i..])
}

/// Unescape basic JavaScript string escapes.
fn unescape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('\'') => result.push('\''),
                Some('0') => result.push('\0'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Build a map of rule path -> metadata from a set of rule files.
pub fn build_inventory(files: &[(String, String)]) -> BTreeMap<String, RuleMetadata> {
    let mut inventory = BTreeMap::new();
    for (path, source) in files {
        if let Some(meta) = extract_metadata(path, source) {
            inventory.insert(path.clone(), meta);
        }
    }
    inventory
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_simple_meta() {
        let source = r#"meta("audio", "");
function detect() {
    // ...
}"#;
        let meta = extract_metadata("db/Binary/audio.1.sg", source).unwrap();
        assert_eq!(meta.type_name, "audio");
        assert_eq!(meta.name, "");
        assert!(meta.has_detect);
        assert!(!meta.has_result);
    }

    #[test]
    fn extract_meta_with_name() {
        let source = r#"meta("info", "ELF");
function detect() { }
function result() { }"#;
        let meta = extract_metadata("db/Binary/ELF.1.sg", source).unwrap();
        assert_eq!(meta.type_name, "info");
        assert_eq!(meta.name, "ELF");
        assert!(meta.has_detect);
        assert!(meta.has_result);
    }

    #[test]
    fn extract_meta_single_quotes() {
        let source = r#"meta('packer', 'UPX');
function detect() { }"#;
        let meta = extract_metadata("db/PE/UPX.1.sg", source).unwrap();
        assert_eq!(meta.type_name, "packer");
        assert_eq!(meta.name, "UPX");
    }

    #[test]
    fn extract_includes_from_source() {
        let source = r#"meta("audio", "");
includeScript("chunkparsers");
includeScript("soundchips");
includeScript("bytecodeparsers");
function detect() { }"#;
        let meta = extract_metadata("db/Binary/audio.1.sg", source).unwrap();
        assert_eq!(meta.includes.len(), 3);
        assert_eq!(meta.includes[0], "chunkparsers");
        assert_eq!(meta.includes[1], "soundchips");
        assert_eq!(meta.includes[2], "bytecodeparsers");
    }

    #[test]
    fn extract_includes_deduplicates() {
        let source = r#"meta("audio", "");
includeScript("chunkparsers");
includeScript("chunkparsers");
function detect() { }"#;
        let meta = extract_metadata("db/Binary/audio.1.sg", source).unwrap();
        assert_eq!(meta.includes.len(), 1);
    }

    #[test]
    fn no_meta_returns_none() {
        let source = "var x = 1;";
        assert!(extract_metadata("test.sg", source).is_none());
    }

    #[test]
    fn empty_source_returns_none() {
        assert!(extract_metadata("test.sg", "").is_none());
    }

    #[test]
    fn detect_with_space_paren_detected() {
        let source = r#"meta("info", "test");
function detect () { }"#;
        let meta = extract_metadata("test.sg", source).unwrap();
        assert!(meta.has_detect);
    }

    #[test]
    fn build_inventory_multiple_files() {
        let files = vec![
            (
                "db/Binary/a.sg".to_string(),
                r#"meta("info", "A");
function detect() { }"#
                    .to_string(),
            ),
            (
                "db/Binary/b.sg".to_string(),
                r#"meta("info", "B");
includeScript("helpers");
function detect() { }"#
                    .to_string(),
            ),
        ];
        let inv = build_inventory(&files);
        assert_eq!(inv.len(), 2);
        assert_eq!(inv["db/Binary/a.sg"].name, "A");
        assert_eq!(inv["db/Binary/b.sg"].includes, vec!["helpers"]);
    }

    #[test]
    fn extract_meta_with_escaped_quote() {
        let source = r#"meta("info", "Shiru\'s module");
function detect() { }"#;
        let meta = extract_metadata("test.sg", source).unwrap();
        assert_eq!(meta.name, "Shiru's module");
    }

    #[test]
    fn extract_meta_empty_name() {
        let source = r#"meta("audio", "");
function detect() { }"#;
        let meta = extract_metadata("test.sg", source).unwrap();
        assert_eq!(meta.type_name, "audio");
        assert_eq!(meta.name, "");
    }

    #[test]
    fn unescape_basic_escapes() {
        assert_eq!(unescape_string("hello\\nworld"), "hello\nworld");
        assert_eq!(unescape_string("tab\\there"), "tab\there");
        assert_eq!(unescape_string("back\\\\slash"), "back\\slash");
        assert_eq!(unescape_string("quote\\\"end"), "quote\"end");
    }
}

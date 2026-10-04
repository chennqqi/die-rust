//! String extraction and search: ASCII, UTF-16LE, and filtered strings.
//!
//! Extracts printable strings from binary files with offset tracking.
//! Supports minimum length filter and search query.

use serde::{Deserialize, Serialize};

/// A single extracted string entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    /// File offset of the string start.
    pub offset: u64,
    /// The extracted string content.
    pub text: String,
    /// String encoding type.
    pub encoding: StringEncoding,
}

/// String encoding type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    /// ASCII / UTF-8 printable.
    Ascii,
    /// UTF-16 little-endian (Windows wide strings).
    Utf16Le,
}

/// String filter mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FilterMode {
    /// Case-insensitive substring match (default).
    #[default]
    Substring,
    /// Regular expression match.
    Regexp,
    /// Only strings that look like URLs/links (http://, https://, ftp://, file://).
    Links,
}

/// Map mode for address mapping in string search results.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum StringMapMode {
    /// File offsets (default).
    #[default]
    File,
    /// Virtual addresses (mapped via PE/ELF/Mach-O sections).
    Virtual,
    /// Physical addresses (same as file for most formats).
    Physical,
}

/// File type selection for string search.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum StringFileType {
    /// Auto-detect from file content.
    #[default]
    Auto,
    /// PE format.
    Pe,
    /// ELF format.
    Elf,
    /// Mach-O format.
    Macho,
    /// DEX format.
    Dex,
    /// Raw binary (no mapping).
    Raw,
}

/// Parameters for string extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringExtractParams {
    /// Minimum string length (default 5, matching upstream).
    pub min_length: usize,
    /// Whether to extract ASCII strings.
    pub extract_ascii: bool,
    /// Whether to extract UTF-16LE strings.
    pub extract_utf16: bool,
    /// Optional search filter (case-insensitive substring match).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    /// Maximum number of results to return (0 = unlimited).
    pub max_results: usize,
    /// Whether to only extract null-terminated strings (strings must end with 0x00).
    #[serde(default)]
    pub null_terminated_only: bool,
    /// Filter mode (substring, regexp, or links).
    #[serde(default)]
    pub filter_mode: FilterMode,
    /// Map mode for address mapping (file, virtual, physical).
    #[serde(default)]
    pub map_mode: StringMapMode,
    /// File type for address mapping (auto, pe, elf, macho, dex, etc.).
    #[serde(default)]
    pub file_type: StringFileType,
}

impl Default for StringExtractParams {
    fn default() -> Self {
        Self {
            min_length: 5,
            extract_ascii: true,
            extract_utf16: true,
            filter: None,
            max_results: 0,
            null_terminated_only: false,
            filter_mode: FilterMode::default(),
            map_mode: StringMapMode::default(),
            file_type: StringFileType::default(),
        }
    }
}

/// Extract strings from binary data according to the given parameters.
pub fn extract_strings(data: &[u8], params: &StringExtractParams) -> Vec<StringEntry> {
    let mut results = Vec::new();

    // Build the filter matcher based on filter_mode.
    let matcher = build_matcher(params);

    if params.extract_ascii {
        extract_ascii_strings(
            data,
            params.min_length,
            &matcher,
            params.null_terminated_only,
            &mut results,
        );
    }
    if params.extract_utf16 {
        extract_utf16le_strings(
            data,
            params.min_length,
            &matcher,
            params.null_terminated_only,
            &mut results,
        );
    }

    // Sort by offset.
    results.sort_by_key(|e| e.offset);

    // Apply max_results limit.
    if params.max_results > 0 && results.len() > params.max_results {
        results.truncate(params.max_results);
    }

    results
}

/// Build a matcher closure based on the filter mode.
type Matcher = Box<dyn Fn(&str) -> bool>;

fn build_matcher(params: &StringExtractParams) -> Matcher {
    match params.filter_mode {
        FilterMode::Substring => {
            let filter_lower = params.filter.as_ref().map(|f| f.to_lowercase());
            Box::new(move |text: &str| {
                if let Some(ref fl) = filter_lower {
                    text.to_lowercase().contains(fl)
                } else {
                    true
                }
            })
        }
        FilterMode::Regexp => {
            // Simple regexp: use the filter as a pattern, match with regex crate if available.
            // For now, fall back to substring if regex is not available.
            let filter = params.filter.clone();
            Box::new(move |text: &str| {
                if let Some(ref pattern) = filter {
                    simple_regex_match(text, pattern)
                } else {
                    true
                }
            })
        }
        FilterMode::Links => Box::new(move |text: &str| is_link(text)),
    }
}

/// Check if a string looks like a URL/link.
fn is_link(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("file://")
        || lower.starts_with("www.")
        || lower.starts_with("mailto:")
}

/// Simple regex-like matching (supports . and * wildcards).
/// For full regex support, the `regex` crate would be needed.
fn simple_regex_match(text: &str, pattern: &str) -> bool {
    // Convert simple glob-like pattern to substring check.
    // Supports: * (any chars), ? (single char), literal chars.
    // For now, use a basic implementation.
    if pattern.is_empty() {
        return true;
    }
    // If pattern has no wildcards, do substring match.
    if !pattern.contains('*') && !pattern.contains('?') {
        return text.to_lowercase().contains(&pattern.to_lowercase());
    }
    // Simple wildcard matching.
    wildcard_match(&text.to_lowercase(), &pattern.to_lowercase())
}

/// Simple wildcard match with * and ? support.
fn wildcard_match(text: &str, pattern: &str) -> bool {
    let text_bytes = text.as_bytes();
    let pat_bytes = pattern.as_bytes();
    let mut ti = 0;
    let mut pi = 0;
    let mut star_pi = None;
    let mut star_ti = 0;

    while ti < text_bytes.len() {
        if pi < pat_bytes.len() && (pat_bytes[pi] == b'?' || pat_bytes[pi] == text_bytes[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < pat_bytes.len() && pat_bytes[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pat_bytes.len() && pat_bytes[pi] == b'*' {
        pi += 1;
    }
    pi == pat_bytes.len()
}

/// Extract ASCII printable strings.
fn extract_ascii_strings(
    data: &[u8],
    min_length: usize,
    matcher: &Matcher,
    null_terminated_only: bool,
    results: &mut Vec<StringEntry>,
) {
    let mut start = 0;
    let mut len = 0;

    for (i, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            if len == 0 {
                start = i;
            }
            len += 1;
        } else {
            // Check null-termination: the byte after the string must be 0x00.
            let is_null_terminated = data.get(start + len) == Some(&0);
            if len >= min_length && (!null_terminated_only || is_null_terminated) {
                push_string(
                    results,
                    start as u64,
                    &data[start..start + len],
                    StringEncoding::Ascii,
                    matcher,
                );
            }
            len = 0;
        }
    }
    // Handle trailing string.
    if len >= min_length {
        let is_null_terminated = data.get(start + len) == Some(&0);
        if !null_terminated_only || is_null_terminated {
            push_string(
                results,
                start as u64,
                &data[start..start + len],
                StringEncoding::Ascii,
                matcher,
            );
        }
    }
}

/// Extract UTF-16LE printable strings.
fn extract_utf16le_strings(
    data: &[u8],
    min_length: usize,
    matcher: &Matcher,
    null_terminated_only: bool,
    results: &mut Vec<StringEntry>,
) {
    let mut start = 0;
    let mut len = 0; // length in UTF-16 code units

    let mut i = 0;
    while i + 1 < data.len() {
        let lo = data[i];
        let hi = data[i + 1];
        if hi == 0 && is_printable_ascii(lo) {
            if len == 0 {
                start = i;
            }
            len += 1;
            i += 2;
        } else {
            if len >= min_length {
                let bytes = &data[start..start + len * 2];
                // Check null-termination: two zero bytes after the string.
                let is_null_terminated = data.get(start + len * 2) == Some(&0)
                    && data.get(start + len * 2 + 1) == Some(&0);
                if !null_terminated_only || is_null_terminated {
                    push_utf16_string(results, start as u64, bytes, matcher);
                }
            }
            len = 0;
            i += 1;
        }
    }
    // Handle trailing string.
    if len >= min_length {
        let bytes = &data[start..start + len * 2];
        let is_null_terminated =
            data.get(start + len * 2) == Some(&0) && data.get(start + len * 2 + 1) == Some(&0);
        if !null_terminated_only || is_null_terminated {
            push_utf16_string(results, start as u64, bytes, matcher);
        }
    }
}

/// Push an ASCII string entry if it passes the filter.
fn push_string(
    results: &mut Vec<StringEntry>,
    offset: u64,
    bytes: &[u8],
    encoding: StringEncoding,
    matcher: &Matcher,
) {
    let text = String::from_utf8_lossy(bytes).to_string();
    if matcher(&text) {
        results.push(StringEntry {
            offset,
            text,
            encoding,
        });
    }
}

/// Push a UTF-16LE string entry if it passes the filter.
fn push_utf16_string(results: &mut Vec<StringEntry>, offset: u64, bytes: &[u8], matcher: &Matcher) {
    // Convert UTF-16LE bytes to String.
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    let text = String::from_utf16_lossy(&units);
    if matcher(&text) {
        results.push(StringEntry {
            offset,
            text,
            encoding: StringEncoding::Utf16Le,
        });
    }
}

/// Check if a byte is printable ASCII (0x20-0x7E plus tab/newline).
fn is_printable_ascii(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte) || byte == b'\t' || byte == b'\n' || byte == b'\r'
}

/// Edit a string at a given file offset.
/// Writes the new value (encoded as ASCII or UTF-16LE) at the specified offset.
/// Creates a .bak backup of the original file before modifying.
pub fn edit_string_at_offset(
    path: &str,
    offset: usize,
    new_value: &str,
    is_utf16: bool,
) -> Result<(), String> {
    let mut data = std::fs::read(path).map_err(|e| e.to_string())?;
    if offset >= data.len() {
        return Err("Offset out of bounds".into());
    }
    // Encode the new value.
    let encoded: Vec<u8> = if is_utf16 {
        new_value
            .encode_utf16()
            .flat_map(|w| w.to_le_bytes())
            .collect()
    } else {
        new_value.as_bytes().to_vec()
    };
    // Find the end of the existing string (null terminator).
    let old_end = if is_utf16 {
        let mut p = offset;
        while p + 1 < data.len() {
            if data[p] == 0 && data[p + 1] == 0 {
                break;
            }
            p += 2;
        }
        p
    } else {
        data[offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| offset + p)
            .unwrap_or(data.len())
    };
    let old_len = old_end - offset;
    // Check if new value fits in the old slot (including null terminator).
    if encoded.len() > old_len {
        return Err(format!(
            "New value ({} bytes) is longer than old string slot ({} bytes)",
            encoded.len(),
            old_len
        ));
    }
    // Backup.
    let backup = format!("{}.bak", path);
    std::fs::copy(path, &backup).map_err(|e| e.to_string())?;
    // Write new value.
    data[offset..offset + encoded.len()].copy_from_slice(&encoded);
    // Pad remaining bytes with zeros.
    for b in data.iter_mut().take(old_end).skip(offset + encoded.len()) {
        *b = 0;
    }
    std::fs::write(path, &data).map_err(|e| e.to_string())?;
    Ok(())
}

/// Maximum bytes writable in a single hex-edit call (defensive bound).
const MAX_EDIT_BYTES: usize = 1 << 20; // 1 MiB

/// Edit raw bytes at a given file offset (hex-viewer edit entry).
///
/// Creates a `.bak` backup before modifying; refuses out-of-bounds or
/// oversized writes. Mirrors upstream hex edit semantics loosely —
/// write is in-place, never extends the file.
pub fn edit_bytes_at_offset(path: &str, offset: usize, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("Nothing to write".into());
    }
    if bytes.len() > MAX_EDIT_BYTES {
        return Err(format!("Edit too large: {} bytes", bytes.len()));
    }
    let mut data = std::fs::read(path).map_err(|e| e.to_string())?;
    if offset >= data.len() {
        return Err("Offset out of bounds".into());
    }
    let end = offset + bytes.len();
    if end > data.len() {
        return Err("Write would exceed file size".into());
    }
    let backup = format!("{}.bak", path);
    std::fs::copy(path, &backup).map_err(|e| e.to_string())?;
    data[offset..end].copy_from_slice(bytes);
    std::fs::write(path, &data).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edit_bytes_at_offset() {
        let dir = std::env::temp_dir().join(format!("die_edit_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.bin");
        std::fs::write(&p, [0u8; 16]).unwrap();
        edit_bytes_at_offset(p.to_str().unwrap(), 4, &[0xAA, 0xBB]).unwrap();
        let data = std::fs::read(&p).unwrap();
        assert_eq!(&data[4..6], &[0xAA, 0xBB]);
        assert!(dir.join("t.bin.bak").exists());
        // Out-of-bounds and oversized writes must fail without panic.
        assert!(edit_bytes_at_offset(p.to_str().unwrap(), 14, &[1, 2, 3]).is_err());
        assert!(edit_bytes_at_offset(p.to_str().unwrap(), 100, &[1]).is_err());
        assert!(edit_bytes_at_offset(p.to_str().unwrap(), 0, &[]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_extract_ascii_basic() {
        let data = b"Hello\x00World\x00Foo";
        let params = StringExtractParams {
            min_length: 3,
            extract_ascii: true,
            extract_utf16: false,
            ..Default::default()
        };
        let strings = extract_strings(data, &params);
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[1].text, "World");
        assert_eq!(strings[1].offset, 6);
    }

    #[test]
    fn test_extract_min_length() {
        let data = b"Hi\x00Hello\x00X\x00World";
        let params = StringExtractParams {
            min_length: 4,
            extract_ascii: true,
            extract_utf16: false,
            ..Default::default()
        };
        let strings = extract_strings(data, &params);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[1].text, "World");
    }

    #[test]
    fn test_extract_utf16le() {
        // "Hi" in UTF-16LE: H\x00i\x00
        let data = [
            b'H', 0x00, b'i', 0x00, 0x00, 0x00, b'W', 0x00, b'o', 0x00, b'r', 0x00,
        ];
        let params = StringExtractParams {
            min_length: 2,
            extract_ascii: false,
            extract_utf16: true,
            ..Default::default()
        };
        let strings = extract_strings(&data, &params);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hi");
        assert_eq!(strings[0].encoding, StringEncoding::Utf16Le);
        assert_eq!(strings[1].text, "Wor");
    }

    #[test]
    fn test_extract_with_filter() {
        let data = b"Hello\x00World\x00Help";
        let params = StringExtractParams {
            min_length: 3,
            extract_ascii: true,
            extract_utf16: false,
            filter: Some("hel".to_string()),
            ..Default::default()
        };
        let strings = extract_strings(data, &params);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[1].text, "Help");
    }

    #[test]
    fn test_extract_max_results() {
        let data = b"AAA\x00BBB\x00CCC\x00DDD";
        let params = StringExtractParams {
            min_length: 3,
            extract_ascii: true,
            extract_utf16: false,
            max_results: 2,
            ..Default::default()
        };
        let strings = extract_strings(data, &params);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "AAA");
        assert_eq!(strings[1].text, "BBB");
    }

    #[test]
    fn test_extract_empty_data() {
        let data = b"";
        let params = StringExtractParams::default();
        let strings = extract_strings(data, &params);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_no_strings() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let params = StringExtractParams::default();
        let strings = extract_strings(&data, &params);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b' '));
        assert!(is_printable_ascii(b'~'));
        assert!(!is_printable_ascii(0x1F));
        assert!(!is_printable_ascii(0x7F));
        assert!(!is_printable_ascii(0x80));
    }

    #[test]
    fn test_null_terminated_only() {
        // "Hello" is null-terminated, "World" is not (followed by 'X')
        let data = b"Hello\x00WorldX";
        let params = StringExtractParams {
            min_length: 3,
            extract_ascii: true,
            extract_utf16: false,
            null_terminated_only: true,
            ..Default::default()
        };
        let strings = extract_strings(data, &params);
        // Only "Hello" should be extracted (null-terminated)
        // "World" is followed by 'X', not null
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Hello");
    }

    #[test]
    fn test_links_filter() {
        let data = b"http://example.com\x00Hello World\x00https://test.org";
        let params = StringExtractParams {
            min_length: 4,
            extract_ascii: true,
            extract_utf16: false,
            filter_mode: FilterMode::Links,
            ..Default::default()
        };
        let strings = extract_strings(data, &params);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "http://example.com");
        assert_eq!(strings[1].text, "https://test.org");
    }

    #[test]
    fn test_regexp_wildcard_filter() {
        let data = b"Hello\x00World\x00Help";
        let params = StringExtractParams {
            min_length: 3,
            extract_ascii: true,
            extract_utf16: false,
            filter: Some("Hel*".to_string()),
            filter_mode: FilterMode::Regexp,
            ..Default::default()
        };
        let strings = extract_strings(data, &params);
        // "Hello" and "Help" match "Hel*" wildcard
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[1].text, "Help");
    }

    #[test]
    fn test_wildcard_match() {
        assert!(wildcard_match("hello", "h*"));
        assert!(wildcard_match("hello", "*o"));
        assert!(wildcard_match("hello", "h?llo"));
        assert!(wildcard_match("hello", "*"));
        assert!(!wildcard_match("hello", "h?"));
        assert!(wildcard_match("hello world", "hello*world"));
    }

    #[test]
    fn test_is_link() {
        assert!(is_link("http://example.com"));
        assert!(is_link("https://test.org"));
        assert!(is_link("ftp://ftp.example.com"));
        assert!(is_link("www.example.com"));
        assert!(is_link("mailto:test@example.com"));
        assert!(!is_link("Hello World"));
        assert!(!is_link("C:\\Windows\\System32"));
    }

    #[test]
    fn test_string_map_mode_default() {
        assert_eq!(StringMapMode::default(), StringMapMode::File);
    }

    #[test]
    fn test_string_file_type_default() {
        assert_eq!(StringFileType::default(), StringFileType::Auto);
    }

    #[test]
    fn test_string_params_default_min_length() {
        let params = StringExtractParams::default();
        assert_eq!(params.min_length, 5);
    }

    #[test]
    fn test_extract_with_map_mode_file() {
        let data = b"Hello\x00World\x00".to_vec();
        let params = StringExtractParams {
            min_length: 5,
            extract_ascii: true,
            extract_utf16: false,
            map_mode: StringMapMode::File,
            file_type: StringFileType::Auto,
            ..Default::default()
        };
        let result = extract_strings(&data, &params);
        assert!(result.iter().any(|s| s.text == "Hello"));
        assert!(result.iter().any(|s| s.text == "World"));
    }
}

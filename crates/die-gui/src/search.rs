//! Advanced search: byte signatures, integer values, and static unpacking.
//!
//! Mirrors upstream DIE-engine search functionality:
//! - Signature search: hex pattern with wildcards (?? for any byte).
//! - Value search: integer values in u8/u16/u32/u64, LE/BE.
//! - Static unpacking: detect and extract common packer stubs.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

/// Search hit (offset of a match).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    /// File offset of the match.
    pub offset: u64,
    /// Matched bytes (hex string).
    pub matched: String,
}

/// Search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// File size.
    pub file_size: u64,
    /// Search hits.
    pub hits: Vec<SearchHit>,
}

/// Value search type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    /// 8-bit unsigned integer.
    U8,
    /// 16-bit unsigned integer (little-endian).
    U16Le,
    /// 16-bit unsigned integer (big-endian).
    U16Be,
    /// 32-bit unsigned integer (little-endian).
    U32Le,
    /// 32-bit unsigned integer (big-endian).
    U32Be,
    /// 64-bit unsigned integer (little-endian).
    U64Le,
    /// 64-bit unsigned integer (big-endian).
    U64Be,
}

/// Search for a hex signature pattern with wildcard support.
///
/// Pattern format: hex bytes separated by spaces, `??` for wildcard.
/// Example: "DE AD BE EF" or "DE ?? ?? EF"
pub fn search_signature(
    path: &str,
    pattern: &str,
    start_offset: u64,
    max_hits: usize,
) -> Result<SearchResult, String> {
    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    let file_size = metadata.len();

    let needle = parse_signature_pattern(pattern)?;
    if needle.is_empty() {
        return Ok(SearchResult {
            file_size,
            hits: Vec::new(),
        });
    }

    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let chunk_size: usize = 65536;
    let overlap = needle.len() - 1;
    let mut buf = vec![0u8; chunk_size + overlap];
    let mut pos = start_offset;
    let mut hits = Vec::new();

    file.seek(SeekFrom::Start(start_offset))
        .map_err(|e| e.to_string())?;

    loop {
        if pos >= file_size || hits.len() >= max_hits {
            break;
        }
        let to_read = std::cmp::min(buf.len() as u64, file_size - pos) as usize;
        let n = file.read(&mut buf[..to_read]).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }

        let data = &buf[..n];
        let mut search_start = 0;
        while search_start + needle.len() <= data.len() {
            if let Some(idx) = match_signature(&data[search_start..], &needle) {
                let abs_offset = pos + search_start as u64 + idx as u64;
                let matched = data[search_start + idx..search_start + idx + needle.len()]
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                hits.push(SearchHit {
                    offset: abs_offset,
                    matched,
                });
                if hits.len() >= max_hits {
                    break;
                }
                search_start += idx + 1;
            } else {
                break;
            }
        }

        pos += n as u64 - overlap as u64;
        file.seek(SeekFrom::Start(pos)).map_err(|e| e.to_string())?;
    }

    Ok(SearchResult { file_size, hits })
}

/// Search for an integer value in the file.
pub fn search_value(
    path: &str,
    value: u64,
    value_type: ValueType,
    start_offset: u64,
    max_hits: usize,
) -> Result<SearchResult, String> {
    let needle = match value_type {
        ValueType::U8 => vec![value as u8],
        ValueType::U16Le => (value as u16).to_le_bytes().to_vec(),
        ValueType::U16Be => (value as u16).to_be_bytes().to_vec(),
        ValueType::U32Le => (value as u32).to_le_bytes().to_vec(),
        ValueType::U32Be => (value as u32).to_be_bytes().to_vec(),
        ValueType::U64Le => value.to_le_bytes().to_vec(),
        ValueType::U64Be => value.to_be_bytes().to_vec(),
    };
    let pattern = needle
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");
    search_signature(path, &pattern, start_offset, max_hits)
}

/// Parse a signature pattern with wildcards.
/// Returns a vector of Option<u8> where None = wildcard.
fn parse_signature_pattern(pattern: &str) -> Result<Vec<Option<u8>>, String> {
    let cleaned: String = pattern.split_whitespace().collect();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err("Pattern must have an even number of hex digits".into());
    }
    let mut result = Vec::new();
    for chunk in cleaned.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        if s.eq_ignore_ascii_case("??") {
            result.push(None);
        } else {
            let val = u8::from_str_radix(s, 16).map_err(|e| e.to_string())?;
            result.push(Some(val));
        }
    }
    Ok(result)
}

/// Match a signature pattern against data, returning the index of the first match.
fn match_signature(data: &[u8], needle: &[Option<u8>]) -> Option<usize> {
    if needle.len() > data.len() {
        return None;
    }
    'outer: for i in 0..=data.len() - needle.len() {
        for (j, pat) in needle.iter().enumerate() {
            if let Some(expected) = pat
                && data[i + j] != *expected
            {
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}

/// Packer detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerInfo {
    /// Packer name (e.g. "UPX", "PECompact", "ASPack").
    pub name: String,
    /// Packer version (if detected).
    pub version: Option<String>,
    /// Section name where the packer stub was found.
    pub section_name: Option<String>,
    /// Entry point section (if known).
    pub entry_section: Option<String>,
}

/// Detect common packers in a PE file.
pub fn detect_packers(path: &str) -> Result<Vec<PackerInfo>, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let mut packers = Vec::new();

    // Try PE format.
    if let Some(view) = crate::pe_viewer::parse_pe_view(&data) {
        // Check section names for known packers.
        for sec in &view.section_details {
            let name = sec.name.to_uppercase();
            if name.starts_with("UPX") {
                packers.push(PackerInfo {
                    name: "UPX".into(),
                    version: None,
                    section_name: Some(sec.name.clone()),
                    entry_section: None,
                });
            } else if name.starts_with(".MPRESS") {
                packers.push(PackerInfo {
                    name: "MPRESS".into(),
                    version: None,
                    section_name: Some(sec.name.clone()),
                    entry_section: None,
                });
            } else if name.starts_with(".PECOMPACT") || name.starts_with("PEC2") {
                packers.push(PackerInfo {
                    name: "PECompact".into(),
                    version: None,
                    section_name: Some(sec.name.clone()),
                    entry_section: None,
                });
            } else if name.starts_with(".ASPACK") || name.starts_with("ASPack") {
                packers.push(PackerInfo {
                    name: "ASPack".into(),
                    version: None,
                    section_name: Some(sec.name.clone()),
                    entry_section: None,
                });
            } else if name.starts_with(".PETITE") {
                packers.push(PackerInfo {
                    name: "Petite".into(),
                    version: None,
                    section_name: Some(sec.name.clone()),
                    entry_section: None,
                });
            } else if name.starts_with(".THEMIDA") || name.starts_with(".WinLicen") {
                packers.push(PackerInfo {
                    name: "Themida/WinLicense".into(),
                    version: None,
                    section_name: Some(sec.name.clone()),
                    entry_section: None,
                });
            } else if name.starts_with(".VMProtect") {
                packers.push(PackerInfo {
                    name: "VMProtect".into(),
                    version: None,
                    section_name: Some(sec.name.clone()),
                    entry_section: None,
                });
            } else if name.starts_with(".ENIGMA") {
                packers.push(PackerInfo {
                    name: "Enigma Protector".into(),
                    version: None,
                    section_name: Some(sec.name.clone()),
                    entry_section: None,
                });
            } else if name == ".PACKMAN" {
                packers.push(PackerInfo {
                    name: "Packman".into(),
                    version: None,
                    section_name: Some(sec.name.clone()),
                    entry_section: None,
                });
            }
        }

        // Check for UPX magic in the file.
        if data.windows(3).any(|w| w == b"UPX") && !packers.iter().any(|p| p.name == "UPX") {
            packers.push(PackerInfo {
                name: "UPX".into(),
                version: None,
                section_name: None,
                entry_section: None,
            });
        }
    }

    Ok(packers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signature_pattern_basic() {
        let pat = parse_signature_pattern("DE AD BE EF").unwrap();
        assert_eq!(pat, vec![Some(0xDE), Some(0xAD), Some(0xBE), Some(0xEF)]);
    }

    #[test]
    fn test_parse_signature_pattern_wildcards() {
        let pat = parse_signature_pattern("DE ?? ?? EF").unwrap();
        assert_eq!(pat, vec![Some(0xDE), None, None, Some(0xEF)]);
    }

    #[test]
    fn test_parse_signature_pattern_empty() {
        let pat = parse_signature_pattern("").unwrap();
        assert!(pat.is_empty());
    }

    #[test]
    fn test_parse_signature_pattern_odd() {
        let result = parse_signature_pattern("DEA");
        assert!(result.is_err());
    }

    #[test]
    fn test_match_signature_exact() {
        let needle = vec![Some(0xDE), Some(0xAD), Some(0xBE), Some(0xEF)];
        assert_eq!(
            match_signature(&[0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00], &needle),
            Some(1)
        );
    }

    #[test]
    fn test_match_signature_wildcard() {
        let needle = vec![Some(0xDE), None, None, Some(0xEF)];
        assert_eq!(
            match_signature(&[0x00, 0xDE, 0x01, 0x02, 0xEF, 0x00], &needle),
            Some(1)
        );
        assert_eq!(
            match_signature(&[0x00, 0xDE, 0xFF, 0xEE, 0xEF, 0x00], &needle),
            Some(1)
        );
    }

    #[test]
    fn test_match_signature_no_match() {
        let needle = vec![Some(0xDE), Some(0xAD)];
        assert_eq!(match_signature(&[0x00, 0x01, 0x02], &needle), None);
    }

    #[test]
    fn test_search_signature_file_not_found() {
        let result = search_signature("/nonexistent", "DE AD", 0, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_packers_file_not_found() {
        let result = detect_packers("/nonexistent");
        assert!(result.is_err());
    }
}

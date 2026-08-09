//! File extractor: extracts overlay, resources, sections, and arbitrary byte ranges.
//!
//! Mirrors upstream `XExtractorWidget` which supports two modes:
//! - RAW mode: extract arbitrary byte ranges by offset and size.
//! - FORMAT mode: extract PE/ELF/Mach-O sections, overlay, resources by name.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

/// Extraction mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum ExtractMode {
    /// Raw byte range extraction.
    Raw,
    /// Format-aware extraction (sections, overlay, resources).
    Format,
    /// Heuristic extraction (scan for embedded file magic signatures).
    Heuristic,
}

/// Extractable item (section, overlay, resource, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractItem {
    /// Item name (e.g. ".text", "overlay", "resource_0").
    pub name: String,
    /// Item type (section, overlay, resource, raw).
    pub item_type: String,
    /// File offset.
    pub offset: u64,
    /// Size in bytes.
    pub size: u64,
    /// Optional description.
    pub description: Option<String>,
}

/// List of extractable items in a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractItemList {
    /// File path.
    pub file_path: String,
    /// File size.
    pub file_size: u64,
    /// List of extractable items.
    pub items: Vec<ExtractItem>,
}

/// Get list of extractable items from a file.
pub fn list_extractable(path: &str) -> Result<ExtractItemList, String> {
    let metadata =
        std::fs::metadata(path).map_err(|e| format!("Failed to read metadata: {}", e))?;
    let file_size = metadata.len();
    let mut items = Vec::new();

    // Try PE.
    if let Ok(data) = std::fs::read(path) {
        if let Some(view) = crate::pe_viewer::parse_pe_view(&data) {
            // Sections.
            for sec in &view.section_details {
                if sec.size_of_raw_data > 0 {
                    items.push(ExtractItem {
                        name: sec.name.clone(),
                        item_type: "section".into(),
                        offset: sec.pointer_to_raw_data as u64,
                        size: sec.size_of_raw_data as u64,
                        description: Some(format!("Entropy: {:.2}", sec.entropy.unwrap_or(0.0))),
                    });
                }
            }
            // Overlay.
            if view.overlay_size > 0 {
                items.push(ExtractItem {
                    name: "overlay".into(),
                    item_type: "overlay".into(),
                    offset: view.overlay_offset,
                    size: view.overlay_size,
                    description: Some("Data after last section".into()),
                });
            }
            // Resources (flatten the tree to find leaf resources).
            collect_pe_resources(&view.resources, "", &mut items);
        } else if let Some(view) = crate::elf_viewer::parse_elf_view(&data) {
            // ELF sections.
            for sec in &view.section_headers {
                if sec.sh_size > 0 && sec.sh_type != "SHT_NOBITS" {
                    items.push(ExtractItem {
                        name: sec.sh_name.clone(),
                        item_type: "section".into(),
                        offset: sec.sh_offset,
                        size: sec.sh_size,
                        description: Some(sec.sh_type.clone()),
                    });
                }
            }
        } else if let Some(view) = crate::macho_viewer::parse_macho_view(&data) {
            // Mach-O segments.
            for seg in &view.segments {
                if seg.filesize > 0 {
                    items.push(ExtractItem {
                        name: seg.name.clone(),
                        item_type: "segment".into(),
                        offset: seg.fileoff,
                        size: seg.filesize,
                        description: None,
                    });
                }
            }
            // Mach-O sections.
            for sec in &view.sections {
                if sec.size > 0 && sec.offset > 0 {
                    items.push(ExtractItem {
                        name: format!("{},{}", sec.segname, sec.sectname),
                        item_type: "section".into(),
                        offset: sec.offset as u64,
                        size: sec.size,
                        description: None,
                    });
                }
            }
        }
    }

    Ok(ExtractItemList {
        file_path: path.to_string(),
        file_size,
        items,
    })
}

/// Recursively collect PE resource leaves.
fn collect_pe_resources(
    nodes: &[crate::pe_viewer::PeResourceNode],
    parent_path: &str,
    items: &mut Vec<ExtractItem>,
) {
    for node in nodes {
        let full_name = if parent_path.is_empty() {
            node.name.clone()
        } else {
            format!("{}/{}", parent_path, node.name)
        };
        // Leaf node: has data_size but no children.
        if node.children.is_empty()
            && let Some(size) = node.data_size
        {
            items.push(ExtractItem {
                name: full_name.clone(),
                item_type: "resource".into(),
                offset: 0, // Resource offset requires RVA-to-file-offset mapping; placeholder.
                size: size as u64,
                description: Some(format!("Resource: {}", full_name)),
            });
        }
        if !node.children.is_empty() {
            collect_pe_resources(&node.children, &full_name, items);
        }
    }
}

/// Extract a byte range from a file to an output directory.
///
/// Returns the path of the extracted file.
pub fn extract_range(
    input_path: &str,
    offset: u64,
    size: u64,
    output_dir: &str,
    output_name: &str,
) -> Result<String, String> {
    let mut input = File::open(input_path).map_err(|e| format!("Failed to open input: {}", e))?;

    // Seek to offset.
    use std::io::Seek;
    input
        .seek(std::io::SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek: {}", e))?;

    // Create output directory if it doesn't exist.
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create output dir: {}", e))?;

    let output_path = PathBuf::from(output_dir).join(output_name);
    let mut output =
        File::create(&output_path).map_err(|e| format!("Failed to create output: {}", e))?;

    // Copy bytes.
    let mut remaining = size;
    let mut buf = vec![0u8; 65536];
    while remaining > 0 {
        let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
        let n = input
            .read(&mut buf[..to_read])
            .map_err(|e| format!("Failed to read: {}", e))?;
        if n == 0 {
            break;
        }
        output
            .write_all(&buf[..n])
            .map_err(|e| format!("Failed to write: {}", e))?;
        remaining -= n as u64;
    }

    Ok(output_path.to_string_lossy().to_string())
}

/// Extract an item by name from a file.
pub fn extract_item(input_path: &str, item_name: &str, output_dir: &str) -> Result<String, String> {
    let list = list_extractable(input_path)?;
    let item = list
        .items
        .iter()
        .find(|i| i.name == item_name)
        .ok_or_else(|| format!("Item '{}' not found", item_name))?;

    // Sanitize the output filename.
    let safe_name = item_name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    let output_name = format!("{}.bin", safe_name);

    extract_range(input_path, item.offset, item.size, output_dir, &output_name)
}

/// Heuristic extraction: scan for embedded file magic signatures.
/// Returns a list of embedded files found by scanning for known magic bytes.
/// If deep_scan is true, scans the entire file; otherwise only scans the first 1MB.
pub fn extract_heuristic(input_path: &str, deep_scan: bool) -> Result<Vec<ExtractItem>, String> {
    let data = std::fs::read(input_path).map_err(|e| e.to_string())?;
    let scan_end = if deep_scan {
        data.len()
    } else {
        std::cmp::min(data.len(), 1024 * 1024)
    };
    let mut items = Vec::new();
    // Known magic signatures: (magic bytes, type name, typical max size).
    let signatures: &[(&[u8], &str, usize)] = &[
        (b"MZ", "PE", 1024 * 1024 * 10),
        (b"\x7fELF", "ELF", 1024 * 1024 * 10),
        (b"\xcf\xfa\xed\xfe", "Mach-O 64 LE", 1024 * 1024 * 10),
        (b"\xfe\xed\xfa\xcf", "Mach-O 32 BE", 1024 * 1024 * 10),
        (b"\xca\xfe\xba\xbe", "Mach-O Universal", 1024 * 1024 * 10),
        (b"dex\n", "DEX", 1024 * 1024 * 10),
        (b"PK\x03\x04", "ZIP/JAR", 1024 * 1024 * 100),
        (b"\x1f\x8b", "GZIP", 1024 * 1024),
        (b"BZh", "BZIP2", 1024 * 1024),
        (b"\xfd7zXZ\x00", "XZ", 1024 * 1024),
        (b"Rar!", "RAR", 1024 * 1024 * 100),
        (b"\x89PNG\r\n\x1a\n", "PNG", 1024 * 1024),
        (b"\xff\xd8\xff", "JPEG", 1024 * 1024 * 10),
        (b"GIF8", "GIF", 1024 * 1024),
        (b"BM", "BMP", 1024 * 1024),
        (b"%PDF", "PDF", 1024 * 1024 * 100),
        (b"RIFF", "RIFF", 1024 * 1024 * 10),
        (b"OggS", "OGG", 1024 * 1024),
        (b"ID3", "MP3", 1024 * 1024 * 10),
        (b"\x00\x00\x01\x00", "ICO", 1024 * 1024),
        (b"SQLite format 3\x00", "SQLite", 1024 * 1024 * 100),
    ];
    for i in 0..scan_end {
        for (magic, type_name, max_size) in signatures {
            if i + magic.len() > scan_end {
                continue;
            }
            if &data[i..i + magic.len()] == *magic {
                // Skip if this is the file's own header (offset 0).
                if i == 0 {
                    continue;
                }
                let size = std::cmp::min(*max_size, data.len() - i);
                items.push(ExtractItem {
                    name: format!("embedded_{}_0x{:x}", type_name, i),
                    item_type: type_name.to_string(),
                    offset: i as u64,
                    size: size as u64,
                    description: Some(format!("Embedded {} at offset 0x{:x}", type_name, i)),
                });
            }
        }
    }
    // Limit to 100 items.
    items.truncate(100);
    Ok(items)
}

/// Analyze an extractable item: identify format, compute entropy.
pub fn analyze_item(input_path: &str, offset: u64, size: u64) -> Result<AnalyzeResult, String> {
    let data = std::fs::read(input_path).map_err(|e| e.to_string())?;
    let off = offset as usize;
    let sz = size as usize;
    if off + sz > data.len() {
        return Err("Offset+size out of bounds".into());
    }
    let chunk = &data[off..off + sz];
    let file_type = detect_format_from_magic(chunk);
    let entropy = calc_entropy(chunk);
    Ok(AnalyzeResult {
        file_type,
        size,
        entropy,
    })
}

/// Analysis result for an extractable item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeResult {
    /// Detected file type string.
    pub file_type: String,
    /// Size in bytes.
    pub size: u64,
    /// Shannon entropy (0.0-8.0).
    pub entropy: f64,
}

/// Detect file format from magic bytes.
fn detect_format_from_magic(data: &[u8]) -> String {
    if data.len() >= 2 && &data[..2] == b"MZ" {
        return "PE".into();
    }
    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        return "ELF".into();
    }
    if data.len() >= 4 && &data[..4] == b"\xcf\xfa\xed\xfe" {
        return "Mach-O 64 LE".into();
    }
    if data.len() >= 4 && &data[..4] == b"\xfe\xed\xfa\xcf" {
        return "Mach-O 32 BE".into();
    }
    if data.len() >= 4 && &data[..4] == b"dex\n" {
        return "DEX".into();
    }
    if data.len() >= 4 && &data[..4] == b"PK\x03\x04" {
        return "ZIP/JAR".into();
    }
    if data.len() >= 8 && &data[..8] == b"\x89PNG\r\n\x1a\n" {
        return "PNG".into();
    }
    if data.len() >= 3 && &data[..3] == b"\xff\xd8\xff" {
        return "JPEG".into();
    }
    if data.len() >= 5 && &data[..5] == b"%PDF-" {
        return "PDF".into();
    }
    if data.len() >= 16 && &data[..16] == b"SQLite format 3\x00" {
        return "SQLite".into();
    }
    "Unknown".into()
}

/// Calculate Shannon entropy of a byte slice.
fn calc_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_extractable_not_found() {
        let result = list_extractable("/nonexistent/file");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_range_not_found() {
        let result = extract_range("/nonexistent/file", 0, 100, "/tmp", "test.bin");
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_format_from_magic() {
        assert_eq!(detect_format_from_magic(b"MZ\x00\x00"), "PE");
        assert_eq!(detect_format_from_magic(b"\x7fELF"), "ELF");
        assert_eq!(detect_format_from_magic(b"PK\x03\x04"), "ZIP/JAR");
        assert_eq!(detect_format_from_magic(b"Unknown"), "Unknown");
    }

    #[test]
    fn test_calc_entropy() {
        assert_eq!(calc_entropy(&[]), 0.0);
        // All same bytes = 0 entropy.
        assert_eq!(calc_entropy(&[0; 100]), 0.0);
        // Two distinct bytes = 1.0 entropy.
        let mixed: Vec<u8> = (0..100).map(|i| (i % 2) as u8).collect();
        let e = calc_entropy(&mixed);
        assert!((e - 1.0).abs() < 0.01);
    }
}

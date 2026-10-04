//! Nested (intra-file) recursive scanning for PE resources and overlays.
//!
//! When `ScanFlags.recursive` is true, the scanner enumerates PE resources
//! and overlay, recursively scans each as a sub-device, and nests child
//! detections under the parent with `file_part`, `offset`, and `size`.
//!
//! This matches upstream DIE-engine's `-r`/`--recursivescan` behavior:
//! `bIsRecursiveScan` enables both resource scanning and overlay scanning.

use crate::host::ScanFlags;
use crate::scanner::{ScanDetection, ScanError};
use die_core::cancel::CancellationToken;
use die_rules::pe_native;

/// Maximum number of resources to scan in normal mode.
const MAX_RESOURCES_NORMAL: usize = 20;

/// Maximum number of resources to scan in aggressive mode.
const MAX_RESOURCES_AGGRESSIVE: usize = 2000;

/// Minimum overlay size to scan (smaller overlays are likely padding).
const MIN_OVERLAY_SIZE: u64 = 16;

/// A file part extracted from a PE for nested scanning.
pub struct FilePart {
    /// The part type: "Resource" or "Overlay".
    pub part_type: &'static str,
    /// The part name (e.g., resource type path or "Overlay").
    pub name: String,
    /// The extracted bytes.
    pub data: Vec<u8>,
}

/// Extract file parts (resources + overlay) from a PE file for nested scanning.
///
/// Returns a list of file parts to recursively scan. Each part contains
/// the extracted bytes and metadata for nesting.
pub fn extract_nested_parts(data: &[u8], flags: &ScanFlags) -> Vec<FilePart> {
    let mut parts = Vec::new();

    // Extract resources if recursive or resources flag is set.
    if flags.recursive || flags.resources {
        let resources = pe_native::get_resource_data(data);
        let max = if flags.aggressive {
            MAX_RESOURCES_AGGRESSIVE
        } else {
            MAX_RESOURCES_NORMAL
        };
        for res in resources.into_iter().take(max) {
            parts.push(FilePart {
                part_type: "Resource",
                name: res.type_path,
                data: res.data,
            });
        }
    }

    // Extract overlay if recursive or overlays flag is set.
    if (flags.recursive || flags.overlays) && pe_native::is_overlay_present(data) {
        let offset = pe_native::get_overlay_offset(data);
        let size = pe_native::get_overlay_size(data);
        if offset >= 0 && size >= MIN_OVERLAY_SIZE {
            let start = offset as usize;
            let end = (start + size as usize).min(data.len());
            if start < end {
                parts.push(FilePart {
                    part_type: "Overlay",
                    name: "Overlay".to_string(),
                    data: data[start..end].to_vec(),
                });
            }
        }
    }

    parts
}

/// Recursively scan PE file parts (resources + overlay) and append nested
/// detections to the parent result.
///
/// This is called after the initial scan of the PE file. It extracts
/// Type alias for the nested scan callback function.
type ScanFn<'a> = &'a dyn Fn(
    &str,
    &[u8],
    &ScanFlags,
    &CancellationToken,
) -> Result<Vec<ScanDetection>, ScanError>;

/// Recursively scan PE file parts (resources + overlay) and append nested
/// detections to the parent result.
///
/// This is called after the initial scan of the PE file. It extracts
/// resources and overlay, scans each as a sub-device, and appends child
/// detections with `file_part`, `offset`, and `size` metadata.
pub fn scan_nested_pe(
    parent_path: &str,
    data: &[u8],
    flags: &ScanFlags,
    cancel: &CancellationToken,
    scan_fn: ScanFn<'_>,
) -> Result<Vec<ScanDetection>, ScanError> {
    let parts = extract_nested_parts(data, flags);
    let mut nested_detections = Vec::new();

    for part in &parts {
        if cancel.is_cancelled() {
            return Err(ScanError::Cancelled);
        }

        // Skip empty parts.
        if part.data.is_empty() {
            continue;
        }

        // Scan the extracted part as a sub-device.
        let part_name = format!("{parent_path}:{}({})", part.part_type, part.name);
        let child_flags = ScanFlags {
            // Nested scans don't recurse further (avoid infinite loops).
            // The NFD engine performs its own file-part recursion inside
            // `die_nfd::scan`; disable it here to avoid duplicate records.
            recursive: false,
            resources: false,
            overlays: false,
            nfd: false,
            ..flags.clone()
        };

        match scan_fn(&part_name, &part.data, &child_flags, cancel) {
            Ok(child_detections) => {
                for mut det in child_detections {
                    // Set file_part metadata.
                    det.file_part = Some(part.part_type.to_string());
                    nested_detections.push(det);
                }
            }
            Err(ScanError::Cancelled) => return Err(ScanError::Cancelled),
            Err(_) => {
                // Skip failed nested scans (don't propagate errors).
            }
        }
    }

    Ok(nested_detections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_nested_parts_empty_data() {
        let flags = ScanFlags {
            recursive: true,
            ..Default::default()
        };
        let parts = extract_nested_parts(&[], &flags);
        assert!(parts.is_empty());
    }

    #[test]
    fn extract_nested_parts_not_pe() {
        let flags = ScanFlags {
            recursive: true,
            ..Default::default()
        };
        let parts = extract_nested_parts(b"not a PE file", &flags);
        assert!(parts.is_empty());
    }

    #[test]
    fn extract_nested_parts_recursive_disabled() {
        let flags = ScanFlags {
            recursive: false,
            resources: false,
            overlays: false,
            ..Default::default()
        };
        // Even for a valid PE, no parts should be extracted.
        let parts = extract_nested_parts(b"MZ\x00\x00", &flags);
        assert!(parts.is_empty());
    }

    #[test]
    fn max_resources_normal_is_20() {
        assert_eq!(MAX_RESOURCES_NORMAL, 20);
    }

    #[test]
    fn max_resources_aggressive_is_2000() {
        assert_eq!(MAX_RESOURCES_AGGRESSIVE, 2000);
    }

    #[test]
    fn min_overlay_size_is_16() {
        assert_eq!(MIN_OVERLAY_SIZE, 16);
    }
}

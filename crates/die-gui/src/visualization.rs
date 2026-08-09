//! 2D file visualization: renders file bytes as a color-coded grid.
//!
//! Mirrors upstream `XVisualizationWidget` which supports multiple
//! rendering methods (Entropy, Gradient, Zero bytes, Text) and
//! region coloring based on PE/ELF sections.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

/// Visualization rendering method.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VizMethod {
    /// Entropy-based coloring (Shannon entropy per block).
    Entropy,
    /// Gradient coloring (byte value → grayscale).
    Gradient,
    /// Zero-byte highlighting (black = 0x00, white = non-zero).
    ZeroBytes,
    /// Text highlighting (printable ASCII = white, non-printable = black).
    Text,
    /// Zero-byte gradient (rate of zero-byte changes per block).
    ZerosGradient,
    /// Text gradient (rate of printable text changes per block).
    TextGradient,
}

/// Visualization region (PE section or ELF segment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VizRegion {
    /// Region name (e.g. ".text", "__TEXT").
    pub name: String,
    /// File offset of the region.
    pub offset: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// RGBA color for the region border (hex string like "#FF0000").
    pub color: String,
}

/// 2D visualization data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizationData {
    /// Number of columns in the grid.
    pub width: u32,
    /// Number of rows in the grid.
    pub height: u32,
    /// Block size in bytes per cell.
    pub block_size: u32,
    /// Total file size.
    pub file_size: u64,
    /// Grid data: one value per cell (0-255 for color mapping).
    pub grid: Vec<u8>,
    /// Regions (PE sections or ELF segments) for overlay coloring.
    pub regions: Vec<VizRegion>,
    /// Rendering method used.
    pub method: VizMethod,
}

/// Default block size for visualization.
const DEFAULT_BLOCK_SIZE: u32 = 256;

/// Default grid width (columns).
const DEFAULT_WIDTH: u32 = 256;

/// Generate 2D visualization data for a file.
///
/// Reads the file in blocks and computes a color value for each block
/// based on the selected rendering method.
pub fn generate_visualization(
    path: &str,
    method: VizMethod,
    block_size: Option<u32>,
    width: Option<u32>,
) -> Result<VisualizationData, String> {
    let block_size = block_size.unwrap_or(DEFAULT_BLOCK_SIZE);
    let width = width.unwrap_or(DEFAULT_WIDTH);

    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to read metadata: {}", e))?;
    let file_size = metadata.len();

    let total_blocks = if block_size > 0 {
        file_size.div_ceil(block_size as u64)
    } else {
        0
    };
    let height = if width > 0 {
        total_blocks.div_ceil(width as u64) as u32
    } else {
        0
    };

    let mut grid = Vec::with_capacity(total_blocks as usize);
    let mut buf = vec![0u8; block_size as usize];

    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        if n == 0 {
            break;
        }
        let value = compute_block_value(&buf[..n], method);
        grid.push(value);
    }

    // Pad grid to fill the last row.
    let expected_cells = (width as u64 * height as u64) as usize;
    while grid.len() < expected_cells {
        grid.push(0);
    }

    // Parse regions (PE sections or ELF segments).
    let regions = parse_regions(path);

    Ok(VisualizationData {
        width,
        height,
        block_size,
        file_size,
        grid,
        regions,
        method,
    })
}

/// Compute a color value (0-255) for a block of bytes.
fn compute_block_value(data: &[u8], method: VizMethod) -> u8 {
    match method {
        VizMethod::Entropy => {
            // Shannon entropy scaled to 0-255.
            let entropy = shannon_entropy(data);
            // Entropy ranges from 0 to 8; scale to 0-255.
            ((entropy / 8.0) * 255.0).clamp(0.0, 255.0) as u8
        }
        VizMethod::Gradient => {
            // Average byte value.
            if data.is_empty() {
                0
            } else {
                let sum: u64 = data.iter().map(|&b| b as u64).sum();
                (sum / data.len() as u64) as u8
            }
        }
        VizMethod::ZeroBytes => {
            // Count zero bytes; more zeros = darker.
            let zeros = data.iter().filter(|&&b| b == 0).count();
            if data.is_empty() {
                0
            } else {
                // Non-zero ratio: 0 = all zeros (black), 255 = no zeros (white).
                (255.0 * (1.0 - zeros as f64 / data.len() as f64)) as u8
            }
        }
        VizMethod::Text => {
            // Count printable ASCII bytes; more printable = brighter.
            let printable = data.iter().filter(|&&b| (0x20..=0x7e).contains(&b)).count();
            if data.is_empty() {
                0
            } else {
                (255.0 * (printable as f64 / data.len() as f64)) as u8
            }
        }
        VizMethod::ZerosGradient => {
            // Rate of zero-byte changes: count transitions between zero and non-zero.
            if data.len() < 2 {
                return 0;
            }
            let mut transitions = 0u64;
            for i in 1..data.len() {
                let prev_zero = data[i - 1] == 0;
                let curr_zero = data[i] == 0;
                if prev_zero != curr_zero {
                    transitions += 1;
                }
            }
            // Normalize: max transitions = len-1.
            (255.0 * (transitions as f64 / (data.len() - 1) as f64)) as u8
        }
        VizMethod::TextGradient => {
            // Rate of text/non-text changes: count transitions between printable and non-printable.
            if data.len() < 2 {
                return 0;
            }
            let is_printable = |b: u8| (0x20..=0x7e).contains(&b);
            let mut transitions = 0u64;
            for i in 1..data.len() {
                if is_printable(data[i - 1]) != is_printable(data[i]) {
                    transitions += 1;
                }
            }
            (255.0 * (transitions as f64 / (data.len() - 1) as f64)) as u8
        }
    }
}

/// Calculate Shannon entropy of a byte slice.
fn shannon_entropy(data: &[u8]) -> f64 {
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

/// Parse PE sections or ELF segments as regions for visualization overlay.
fn parse_regions(path: &str) -> Vec<VizRegion> {
    // Try PE first, then ELF, then Mach-O.
    if let Ok(data) = std::fs::read(path) {
        if let Some(view) = crate::pe_viewer::parse_pe_view(&data) {
            return view
                .section_details
                .iter()
                .map(|s| VizRegion {
                    name: s.name.clone(),
                    offset: s.pointer_to_raw_data as u64,
                    size: s.size_of_raw_data as u64,
                    color: section_color(&s.name),
                })
                .collect();
        }
        if let Some(view) = crate::elf_viewer::parse_elf_view(&data) {
            return view
                .section_headers
                .iter()
                .map(|s| VizRegion {
                    name: s.sh_name.clone(),
                    offset: s.sh_offset,
                    size: s.sh_size,
                    color: section_color(&s.sh_name),
                })
                .collect();
        }
        if let Some(view) = crate::macho_viewer::parse_macho_view(&data) {
            return view
                .segments
                .iter()
                .map(|s| VizRegion {
                    name: s.name.clone(),
                    offset: s.fileoff,
                    size: s.filesize,
                    color: section_color(&s.name),
                })
                .collect();
        }
    }
    Vec::new()
}

/// Assign a color to a section/segment based on its name.
fn section_color(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.contains("text") || lower.contains("code") {
        "#FF6B6B".into() // red
    } else if lower.contains("data") {
        "#4ECDC4".into() // teal
    } else if lower.contains("rdata") || lower.contains("rodata") {
        "#45B7D1".into() // blue
    } else if lower.contains("bss") {
        "#96CEB4".into() // green
    } else if lower.contains("rsrc") || lower.contains("resource") {
        "#FFEAA7".into() // yellow
    } else if lower.contains("rdata") {
        "#DDA0DD".into() // plum
    } else if lower.contains("linkedit") {
        "#A0A0A0".into() // gray
    } else {
        "#CCCCCC".into() // light gray
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_block_value_entropy() {
        let data = vec![0u8; 256];
        let val = compute_block_value(&data, VizMethod::Entropy);
        assert_eq!(val, 0); // All zeros → entropy 0

        let data = vec![0u8; 128];
        let val = compute_block_value(&data, VizMethod::Entropy);
        assert_eq!(val, 0); // All same byte → entropy 0
    }

    #[test]
    fn test_compute_block_value_gradient() {
        let data = vec![128u8; 256];
        let val = compute_block_value(&data, VizMethod::Gradient);
        assert_eq!(val, 128);
    }

    #[test]
    fn test_compute_block_value_zero_bytes() {
        let data = vec![0u8; 256];
        let val = compute_block_value(&data, VizMethod::ZeroBytes);
        assert_eq!(val, 0); // All zeros → black

        let data = vec![0xFFu8; 256];
        let val = compute_block_value(&data, VizMethod::ZeroBytes);
        assert_eq!(val, 255); // No zeros → white
    }

    #[test]
    fn test_compute_block_value_text() {
        let data = b"Hello, World! This is a test string.   ".to_vec();
        let val = compute_block_value(&data, VizMethod::Text);
        assert!(val > 200); // Mostly printable → bright
    }

    #[test]
    fn test_section_color() {
        assert_eq!(section_color(".text"), "#FF6B6B");
        assert_eq!(section_color(".data"), "#4ECDC4");
        assert_eq!(section_color("__TEXT"), "#FF6B6B");
    }

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        assert_eq!(shannon_entropy(&[0u8; 100]), 0.0);
    }

    #[test]
    fn test_compute_block_value_zeros_gradient() {
        // All same bytes → no transitions → 0.
        let data = vec![0u8; 256];
        let val = compute_block_value(&data, VizMethod::ZerosGradient);
        assert_eq!(val, 0);

        // Alternating zero/non-zero → max transitions.
        let data: Vec<u8> = (0..256).map(|i| (i % 2) as u8 * 0xFF).collect();
        let val = compute_block_value(&data, VizMethod::ZerosGradient);
        assert!(val > 200);
    }

    #[test]
    fn test_compute_block_value_text_gradient() {
        // All printable → no transitions → 0.
        let data = b"Hello, World! This is a test string.   ".to_vec();
        let val = compute_block_value(&data, VizMethod::TextGradient);
        assert_eq!(val, 0);

        // Alternating printable/non-printable → high transitions.
        let data: Vec<u8> = (0..256)
            .map(|i| if i % 2 == 0 { 0x41 } else { 0x01 })
            .collect();
        let val = compute_block_value(&data, VizMethod::TextGradient);
        assert!(val > 200);
    }
}

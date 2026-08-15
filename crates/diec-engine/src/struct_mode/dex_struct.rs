//! DEX format-specific struct methods for `--struct` mode.
//!
//! Implements the 1 DEX-specific method matching upstream
//! `XFileInfo::getMethodNames()` for DEX files:
//! - `Header`

use super::{StructNode, StructSelector};

/// DEX magic bytes: "dex\n" followed by version.
const DEX_MAGIC: [u8; 4] = [0x64, 0x65, 0x78, 0x0A]; // "dex\n"

/// Check if data starts with DEX magic.
fn is_dex(data: &[u8]) -> bool {
    data.len() >= 8 && data[0..4] == DEX_MAGIC
}

/// Build DEX-specific struct method nodes filtered by the selector.
pub fn dex_struct_nodes(data: &[u8], selector: &StructSelector) -> Vec<StructNode> {
    if !is_dex(data) {
        return vec![];
    }

    let mut nodes = Vec::new();

    if selector.matches(0, "Header") {
        nodes.push(build_header(data));
    }

    nodes
}

/// Build DEX header fields.
///
/// DEX header layout (112 bytes):
/// - 0x00: magic[8] — "dex\n" + version (3 bytes) + "\0"
/// - 0x08: checksum (u32, adler32 of rest of file)
/// - 0x0C: signature[20] (SHA-1 hash of rest of file)
/// - 0x20: file_size (u32)
/// - 0x24: header_size (u32, always 0x70 = 112)
/// - 0x28: endian_tag (u32, always 0x12345678)
/// - 0x2C: link_size (u32)
/// - 0x30: link_off (u32)
/// - 0x34: map_off (u32)
/// - 0x38: string_ids_size (u32)
/// - 0x3C: string_ids_off (u32)
fn build_header(data: &[u8]) -> StructNode {
    let mut children = Vec::new();

    if data.len() >= 8 {
        // Magic (8 bytes: "dex\n" + 3 version chars + "\0").
        let version = String::from_utf8_lossy(&data[4..7]).to_string();
        children.push(StructNode::leaf("magic", "dex"));
        children.push(StructNode::leaf("version", version));
    }

    if data.len() >= 12 {
        let checksum = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        children.push(StructNode::leaf("checksum", format!("0x{checksum:08X}")));
    }

    if data.len() >= 0x20 {
        let file_size = u32::from_le_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]);
        children.push(StructNode::leaf("file_size", file_size.to_string()));
    }

    if data.len() >= 0x24 {
        let header_size = u32::from_le_bytes([data[0x24], data[0x25], data[0x26], data[0x27]]);
        children.push(StructNode::leaf(
            "header_size",
            format!("0x{header_size:X}"),
        ));
    }

    if data.len() >= 0x28 {
        let endian_tag = u32::from_le_bytes([data[0x28], data[0x29], data[0x2A], data[0x2B]]);
        children.push(StructNode::leaf(
            "endian_tag",
            format!("0x{endian_tag:08X}"),
        ));
    }

    if data.len() >= 0x30 {
        let link_size = u32::from_le_bytes([data[0x2C], data[0x2D], data[0x2E], data[0x2F]]);
        children.push(StructNode::leaf("link_size", link_size.to_string()));

        let link_off = u32::from_le_bytes([data[0x30], data[0x31], data[0x32], data[0x33]]);
        children.push(StructNode::leaf("link_off", format!("0x{link_off:08X}")));
    }

    if data.len() >= 0x34 {
        let map_off = u32::from_le_bytes([data[0x34], data[0x35], data[0x36], data[0x37]]);
        children.push(StructNode::leaf("map_off", format!("0x{map_off:08X}")));
    }

    if data.len() >= 0x3C {
        let string_ids_size = u32::from_le_bytes([data[0x38], data[0x39], data[0x3A], data[0x3B]]);
        children.push(StructNode::leaf(
            "string_ids_size",
            string_ids_size.to_string(),
        ));

        let string_ids_off = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
        children.push(StructNode::leaf(
            "string_ids_off",
            format!("0x{string_ids_off:08X}"),
        ));
    }

    StructNode::parent("Header", children)
}

/// Return the list of DEX-specific struct method names.
#[allow(dead_code)]
pub fn dex_method_names() -> &'static [&'static str] {
    &["Header"]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal DEX binary (header only).
    fn minimal_dex() -> Vec<u8> {
        let mut data = vec![0u8; 112];
        // Magic: "dex\n035\0".
        data[0..4].copy_from_slice(&DEX_MAGIC);
        data[4..7].copy_from_slice(b"035");
        data[7] = 0;
        // header_size = 0x70 (112).
        data[0x24] = 0x70;
        data[0x25] = 0x00;
        data[0x26] = 0x00;
        data[0x27] = 0x00;
        // endian_tag = 0x12345678.
        data[0x28] = 0x78;
        data[0x29] = 0x56;
        data[0x2A] = 0x34;
        data[0x2B] = 0x12;
        data
    }

    #[test]
    fn dex_header() {
        let data = minimal_dex();
        let selector = StructSelector::parse("Header").unwrap();
        let nodes = dex_struct_nodes(&data, &selector);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Header");
        let names: Vec<_> = nodes[0].children.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"magic"));
        assert!(names.contains(&"version"));
        assert!(names.contains(&"header_size"));
        assert!(names.contains(&"endian_tag"));
    }

    #[test]
    fn dex_not_dex_returns_empty() {
        let data = b"not a DEX file";
        let selector = StructSelector::parse("Header").unwrap();
        let nodes = dex_struct_nodes(data, &selector);
        assert!(nodes.is_empty());
    }

    #[test]
    fn dex_method_names_has_one() {
        assert_eq!(dex_method_names().len(), 1);
    }
}

//! PE32 format-specific struct methods for `--struct` mode.
//!
//! Implements the 6 PE-specific methods matching upstream
//! `XFileInfo::getMethodNames()` for PE files:
//! - `Entry point`
//! - `IMAGE_DOS_HEADER`
//! - `IMAGE_NT_HEADERS`
//! - `IMAGE_SECTION_HEADER`
//! - `IMAGE_RESOURCE_DIRECTORY`
//! - `IMAGE_EXPORT_DIRECTORY`

use super::{StructNode, StructSelector};
use die_rules::pe_native;

/// Build PE-specific struct method nodes filtered by the selector.
///
/// Returns child nodes for the matched PE methods.
pub fn pe_struct_nodes(data: &[u8], selector: &StructSelector) -> Vec<StructNode> {
    if !pe_native::is_pe(data) {
        return vec![];
    }

    let mut nodes = Vec::new();

    if selector.matches(0, "Entry point") {
        let ep = pe_native::get_entry_point(data);
        nodes.push(StructNode::leaf("Entry point", format!("0x{ep:X}")));
    }

    if selector.matches(0, "IMAGE_DOS_HEADER") {
        nodes.push(build_dos_header(data));
    }

    if selector.matches(0, "IMAGE_NT_HEADERS") {
        nodes.push(build_nt_headers(data));
    }

    if selector.matches(0, "IMAGE_SECTION_HEADER") {
        nodes.push(build_section_headers(data));
    }

    if selector.matches(0, "IMAGE_RESOURCE_DIRECTORY") {
        nodes.push(build_resource_directory(data));
    }

    if selector.matches(0, "IMAGE_EXPORT_DIRECTORY") {
        nodes.push(build_export_directory(data));
    }

    nodes
}

/// Build IMAGE_DOS_HEADER fields.
fn build_dos_header(data: &[u8]) -> StructNode {
    let mut children = Vec::new();

    if data.len() >= 2 {
        let magic = format!("0x{:02X}{:02X}", data[1], data[0]);
        children.push(StructNode::leaf("e_magic", magic));
    }
    if data.len() >= 64 {
        let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);
        children.push(StructNode::leaf("e_lfanew", format!("0x{e_lfanew:X}")));
    }

    StructNode::parent("IMAGE_DOS_HEADER", children)
}

/// Build IMAGE_NT_HEADERS fields.
fn build_nt_headers(data: &[u8]) -> StructNode {
    let mut children = Vec::new();

    if data.len() >= 64 {
        let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

        if e_lfanew + 4 <= data.len() {
            let signature = u32::from_le_bytes([
                data[e_lfanew],
                data[e_lfanew + 1],
                data[e_lfanew + 2],
                data[e_lfanew + 3],
            ]);
            children.push(StructNode::leaf("Signature", format!("0x{signature:08X}")));
        }

        // Machine field at e_lfanew + 4.
        if e_lfanew + 6 <= data.len() {
            let machine = u16::from_le_bytes([data[e_lfanew + 4], data[e_lfanew + 5]]);
            children.push(StructNode::leaf("Machine", format!("0x{machine:04X}")));
        }

        // Entry point.
        let entry = pe_native::get_entry_point(data);
        children.push(StructNode::leaf(
            "AddressOfEntryPoint",
            format!("0x{entry:X}"),
        ));

        // Image base.
        let image_base = pe_native::get_image_base(data);
        children.push(StructNode::leaf("ImageBase", format!("0x{image_base:X}")));
    }

    StructNode::parent("IMAGE_NT_HEADERS", children)
}

/// Build IMAGE_SECTION_HEADER list.
fn build_section_headers(data: &[u8]) -> StructNode {
    let num_sections = pe_native::get_number_of_sections(data);
    let mut children = Vec::new();

    for i in 0..num_sections.min(64) {
        let name = pe_native::get_section_name(data, i);
        let offset = pe_native::get_section_file_offset(data, i);
        let size = pe_native::get_section_file_size(data, i);
        let vaddr = pe_native::get_section_virtual_address(data, i);
        let vsize = pe_native::get_section_virtual_size(data, i);

        children.push(StructNode::parent(
            name,
            vec![
                StructNode::leaf("PointerToRawData", format!("0x{offset:X}")),
                StructNode::leaf("SizeOfRawData", format!("0x{size:X}")),
                StructNode::leaf("VirtualAddress", format!("0x{vaddr:X}")),
                StructNode::leaf("VirtualSize", format!("0x{vsize:X}")),
            ],
        ));
    }

    StructNode::parent("IMAGE_SECTION_HEADER", children)
}

/// Build IMAGE_RESOURCE_DIRECTORY summary.
fn build_resource_directory(data: &[u8]) -> StructNode {
    let num_resources = pe_native::get_number_of_resources(data);
    let mut children = Vec::new();

    children.push(StructNode::leaf(
        "NumberOfResources",
        num_resources.to_string(),
    ));

    if pe_native::is_resources_present(data) {
        children.push(StructNode::leaf("Present", "true"));
    } else {
        children.push(StructNode::leaf("Present", "false"));
    }

    StructNode::parent("IMAGE_RESOURCE_DIRECTORY", children)
}

/// Build IMAGE_EXPORT_DIRECTORY summary.
fn build_export_directory(data: &[u8]) -> StructNode {
    let mut children = Vec::new();

    if pe_native::is_export_present(data) {
        let exports = pe_native::get_export_names(data);
        children.push(StructNode::leaf(
            "NumberOfFunctions",
            exports.len().to_string(),
        ));
        children.push(StructNode::leaf("Present", "true"));
    } else {
        children.push(StructNode::leaf("NumberOfFunctions", "0"));
        children.push(StructNode::leaf("Present", "false"));
    }

    StructNode::parent("IMAGE_EXPORT_DIRECTORY", children)
}

/// Return the list of PE-specific struct method names.
#[allow(dead_code)]
pub fn pe_method_names() -> &'static [&'static str] {
    &[
        "Entry point",
        "IMAGE_DOS_HEADER",
        "IMAGE_NT_HEADERS",
        "IMAGE_SECTION_HEADER",
        "IMAGE_RESOURCE_DIRECTORY",
        "IMAGE_EXPORT_DIRECTORY",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Load a real PE32 from the test corpus.
    fn corpus_pe32() -> Option<Vec<u8>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("minimal.exe");
        std::fs::read(&path).ok()
    }

    #[test]
    fn pe_entry_point() {
        let data = match corpus_pe32() {
            Some(d) => d,
            None => {
                eprintln!("Skipping: corpus/minimal.exe not found");
                return;
            }
        };
        let selector = StructSelector::parse("Entry point").unwrap();
        let nodes = pe_struct_nodes(&data, &selector);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Entry point");
    }

    #[test]
    fn pe_dos_header() {
        let data = match corpus_pe32() {
            Some(d) => d,
            None => {
                eprintln!("Skipping: corpus/minimal.exe not found");
                return;
            }
        };
        let selector = StructSelector::parse("IMAGE_DOS_HEADER").unwrap();
        let nodes = pe_struct_nodes(&data, &selector);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "IMAGE_DOS_HEADER");
        let names: Vec<_> = nodes[0].children.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"e_magic"));
        assert!(names.contains(&"e_lfanew"));
    }

    #[test]
    fn pe_nt_headers() {
        let data = match corpus_pe32() {
            Some(d) => d,
            None => {
                eprintln!("Skipping: corpus/minimal.exe not found");
                return;
            }
        };
        let selector = StructSelector::parse("IMAGE_NT_HEADERS").unwrap();
        let nodes = pe_struct_nodes(&data, &selector);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "IMAGE_NT_HEADERS");
    }

    #[test]
    fn pe_not_pe_returns_empty() {
        let data = b"not a PE file";
        let selector = StructSelector::parse("Entry point").unwrap();
        let nodes = pe_struct_nodes(data, &selector);
        assert!(nodes.is_empty());
    }

    #[test]
    fn pe_method_names_has_six() {
        assert_eq!(pe_method_names().len(), 6);
    }
}

//! Mach-O 64 format-specific struct methods for `--struct` mode.
//!
//! Implements the 2 Mach-O-specific methods matching upstream
//! `XFileInfo::getMethodNames()` for Mach-O files:
//! - `Entry point`
//! - `Header`

use super::{StructNode, StructSelector};
use diec_rules::macho_native;

/// Build Mach-O-specific struct method nodes filtered by the selector.
pub fn macho_struct_nodes(data: &[u8], selector: &StructSelector) -> Vec<StructNode> {
    if !macho_native::is_macho(data) {
        return vec![];
    }

    let mut nodes = Vec::new();

    if selector.matches(0, "Entry point") {
        let ep = macho_native::get_entry_point(data);
        nodes.push(StructNode::leaf("Entry point", format!("0x{ep:X}")));
    }

    if selector.matches(0, "Header") {
        nodes.push(build_header(data));
    }

    nodes
}

/// Build Mach-O header fields.
fn build_header(data: &[u8]) -> StructNode {
    let mut children = Vec::new();

    if data.len() >= 4 {
        // Magic number.
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        children.push(StructNode::leaf("magic", format!("0x{magic:08X}")));
    }

    // CPU type.
    let cpu_type = macho_native::get_cpu_type(data);
    children.push(StructNode::leaf("cputype", format!("0x{cpu_type:X}")));

    // File type.
    let file_type = macho_native::get_file_type(data);
    children.push(StructNode::leaf("filetype", format!("0x{file_type:X}")));

    // Number of load commands.
    let ncmds = macho_native::get_ncmds(data);
    children.push(StructNode::leaf("ncmds", ncmds.to_string()));

    // Number of sections.
    let num_sections = macho_native::get_number_of_sections(data);
    children.push(StructNode::leaf(
        "NumberOfSections",
        num_sections.to_string(),
    ));

    // Number of segments.
    let num_segments = macho_native::get_number_of_segments(data);
    children.push(StructNode::leaf(
        "NumberOfSegments",
        num_segments.to_string(),
    ));

    // Entry point.
    let entry = macho_native::get_entry_point(data);
    children.push(StructNode::leaf("EntryPoint", format!("0x{entry:X}")));

    StructNode::parent("Header", children)
}

/// Return the list of Mach-O-specific struct method names.
#[allow(dead_code)]
pub fn macho_method_names() -> &'static [&'static str] {
    &["Entry point", "Header"]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Load a real Mach-O 64 from the test corpus.
    fn corpus_macho64() -> Option<Vec<u8>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("minimal.macho");
        std::fs::read(&path).ok()
    }

    #[test]
    fn macho_entry_point() {
        let data = match corpus_macho64() {
            Some(d) => d,
            None => {
                eprintln!("Skipping: corpus/minimal.macho not found");
                return;
            }
        };
        let selector = StructSelector::parse("Entry point").unwrap();
        let nodes = macho_struct_nodes(&data, &selector);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Entry point");
    }

    #[test]
    fn macho_header() {
        let data = match corpus_macho64() {
            Some(d) => d,
            None => {
                eprintln!("Skipping: corpus/minimal.macho not found");
                return;
            }
        };
        let selector = StructSelector::parse("Header").unwrap();
        let nodes = macho_struct_nodes(&data, &selector);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Header");
        let names: Vec<_> = nodes[0].children.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"magic"));
        assert!(names.contains(&"cputype"));
    }

    #[test]
    fn macho_not_macho_returns_empty() {
        let data = b"not a Mach-O file";
        let selector = StructSelector::parse("Entry point").unwrap();
        let nodes = macho_struct_nodes(data, &selector);
        assert!(nodes.is_empty());
    }

    #[test]
    fn macho_method_names_has_two() {
        assert_eq!(macho_method_names().len(), 2);
    }
}

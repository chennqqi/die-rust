//! ELF64 format-specific struct methods for `--struct` mode.
//!
//! Implements the 2 ELF-specific methods matching upstream
//! `XFileInfo::getMethodNames()` for ELF files:
//! - `Entry point`
//! - `Elf_Ehdr`

use super::{StructNode, StructSelector};
use diec_rules::elf_native;

/// Build ELF-specific struct method nodes filtered by the selector.
pub fn elf_struct_nodes(data: &[u8], selector: &StructSelector) -> Vec<StructNode> {
    if !elf_native::is_elf(data) {
        return vec![];
    }

    let mut nodes = Vec::new();

    if selector.matches(0, "Entry point") {
        let ep = elf_native::get_entry_point(data);
        nodes.push(StructNode::leaf("Entry point", format!("0x{ep:X}")));
    }

    if selector.matches(0, "Elf_Ehdr") {
        nodes.push(build_ehdr(data));
    }

    nodes
}

/// Build Elf_Ehdr (ELF header) fields.
fn build_ehdr(data: &[u8]) -> StructNode {
    let mut children = Vec::new();

    if data.len() >= 16 {
        // e_ident magic.
        let magic = format!(
            "0x{:02X}{:02X}{:02X}{:02X}",
            data[0], data[1], data[2], data[3]
        );
        children.push(StructNode::leaf("e_ident", magic));

        // EI_CLASS at offset 4.
        let class = if data[4] == 2 { "ELF64" } else { "ELF32" };
        children.push(StructNode::leaf("EI_CLASS", class));

        // EI_DATA at offset 5.
        let endian = if data[5] == 1 {
            "Little endian"
        } else {
            "Big endian"
        };
        children.push(StructNode::leaf("EI_DATA", endian));
    }

    // e_type.
    let type_name = elf_native::get_type_name(data);
    children.push(StructNode::leaf("e_type", type_name));

    // e_machine.
    let machine_name = elf_native::get_machine_name(data);
    children.push(StructNode::leaf("e_machine", machine_name));

    // e_entry.
    let entry = elf_native::get_entry_point(data);
    children.push(StructNode::leaf("e_entry", format!("0x{entry:X}")));

    // Number of sections and programs.
    let num_sections = elf_native::get_number_of_sections(data);
    children.push(StructNode::leaf("e_shnum", num_sections.to_string()));

    let num_programs = elf_native::get_number_of_programs(data);
    children.push(StructNode::leaf("e_phnum", num_programs.to_string()));

    StructNode::parent("Elf_Ehdr", children)
}

/// Return the list of ELF-specific struct method names.
#[allow(dead_code)]
pub fn elf_method_names() -> &'static [&'static str] {
    &["Entry point", "Elf_Ehdr"]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Load a real ELF64 from the test corpus.
    fn corpus_elf64() -> Option<Vec<u8>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("minimal.elf");
        std::fs::read(&path).ok()
    }

    #[test]
    fn elf_entry_point() {
        let data = match corpus_elf64() {
            Some(d) => d,
            None => {
                eprintln!("Skipping: corpus/minimal.elf not found");
                return;
            }
        };
        let selector = StructSelector::parse("Entry point").unwrap();
        let nodes = elf_struct_nodes(&data, &selector);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Entry point");
    }

    #[test]
    fn elf_ehdr() {
        let data = match corpus_elf64() {
            Some(d) => d,
            None => {
                eprintln!("Skipping: corpus/minimal.elf not found");
                return;
            }
        };
        let selector = StructSelector::parse("Elf_Ehdr").unwrap();
        let nodes = elf_struct_nodes(&data, &selector);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Elf_Ehdr");
        let names: Vec<_> = nodes[0].children.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"e_ident"));
        assert!(names.contains(&"EI_CLASS"));
        assert!(names.contains(&"e_entry"));
    }

    #[test]
    fn elf_not_elf_returns_empty() {
        let data = b"not an ELF file";
        let selector = StructSelector::parse("Entry point").unwrap();
        let nodes = elf_struct_nodes(data, &selector);
        assert!(nodes.is_empty());
    }

    #[test]
    fn elf_method_names_has_two() {
        assert_eq!(elf_method_names().len(), 2);
    }
}

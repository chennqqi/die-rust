//! Native ELF host API methods backed by the `goblin` crate.
//!
//! This module replaces the hand-written JavaScript ELF parsing code in
//! `host_api_bridge.rs` with native Rust implementations using `goblin`.
//! The methods are registered as JavaScript functions on the `ELF` object.
//!
//! Benefits over the JS implementation:
//! - Battle-tested ELF parsing (goblin is widely used and fuzzed)
//! - Better performance (no per-byte JS->Rust FFI round-trips)
//! - Correctness guarantees from goblin's validation

use goblin::elf::Elf;

/// ELF magic bytes: 0x7F 'E' 'L' 'F'.
const ELF_MAGIC: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];

/// Check if the data starts with the ELF magic.
pub fn is_elf(data: &[u8]) -> bool {
    data.len() >= 64 && data[..4] == ELF_MAGIC
}

/// Safely parse an ELF file, catching panics from goblin's unsafe code.
///
/// Returns `None` if the data is not a valid ELF or if parsing panics.
fn elf_from_bytes(data: &[u8]) -> Option<Elf<'_>> {
    if !is_elf(data) {
        return None;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Elf::parse(data)))
        .ok()
        .and_then(|r| r.ok())
}

/// Get the ELF import library names (DT_NEEDED entries).
///
/// Returns an empty vector if not a valid ELF or no imports.
pub fn get_import_libraries(data: &[u8]) -> Vec<String> {
    elf_from_bytes(data)
        .map(|elf| elf.libraries.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

/// Get the ELF entry point address.
///
/// Returns 0 if not a valid ELF.
pub fn get_entry_point(data: &[u8]) -> u64 {
    elf_from_bytes(data).map(|elf| elf.entry).unwrap_or(0)
}

/// Get the ELF machine type (e_machine field).
///
/// Returns 0 if not a valid ELF.
pub fn get_machine(data: &[u8]) -> u16 {
    elf_from_bytes(data)
        .map(|elf| elf.header.e_machine)
        .unwrap_or(0)
}

/// Get the ELF type (e_type field).
///
/// Returns 0 if not a valid ELF.
pub fn get_elf_type(data: &[u8]) -> u16 {
    elf_from_bytes(data)
        .map(|elf| elf.header.e_type)
        .unwrap_or(0)
}

/// Check if the ELF file is 64-bit.
///
/// Returns false if not a valid ELF.
pub fn is_64bit(data: &[u8]) -> bool {
    elf_from_bytes(data).map(|elf| elf.is_64).unwrap_or(false)
}

/// Check if the ELF file is little-endian.
///
/// Returns false if not a valid ELF.
pub fn is_little_endian(data: &[u8]) -> bool {
    elf_from_bytes(data)
        .map(|elf| elf.little_endian)
        .unwrap_or(false)
}

/// Get the number of section headers.
///
/// Returns 0 if not a valid ELF.
pub fn get_number_of_sections(data: &[u8]) -> u16 {
    elf_from_bytes(data)
        .map(|elf| elf.header.e_shnum)
        .unwrap_or(0)
}

/// Get the number of program headers.
///
/// Returns 0 if not a valid ELF.
pub fn get_number_of_programs(data: &[u8]) -> u16 {
    elf_from_bytes(data)
        .map(|elf| elf.header.e_phnum)
        .unwrap_or(0)
}

/// Get the image base (lowest p_vaddr among PT_LOAD segments).
///
/// Returns 0 if not a valid ELF or no PT_LOAD segments.
pub fn get_image_base(data: &[u8]) -> u64 {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return 0;
    };
    let mut base: Option<u64> = None;
    for phdr in &elf.program_headers {
        if phdr.p_type == goblin::elf::program_header::PT_LOAD {
            let vaddr = phdr.p_vaddr;
            if base.is_none() || vaddr < base.unwrap() {
                base = Some(vaddr);
            }
        }
    }
    base.unwrap_or(0)
}

/// Get section names.
///
/// Returns an empty vector if not a valid ELF or no sections.
pub fn get_section_names(data: &[u8]) -> Vec<String> {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return Vec::new();
    };
    elf.section_headers
        .iter()
        .filter_map(|shdr| elf.shdr_strtab.get_at(shdr.sh_name).map(|s| s.to_string()))
        .collect()
}

/// Check if a section name is present.
///
/// Returns false if not a valid ELF or section not found.
pub fn is_section_name_present(data: &[u8], name: &str) -> bool {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return false;
    };
    elf.section_headers
        .iter()
        .any(|shdr| elf.shdr_strtab.get_at(shdr.sh_name) == Some(name))
}

/// Get the section index by name.
///
/// Returns -1 if not found or not a valid ELF.
pub fn get_section_number(data: &[u8], name: &str) -> i64 {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return -1;
    };
    for (i, shdr) in elf.section_headers.iter().enumerate() {
        if elf.shdr_strtab.get_at(shdr.sh_name) == Some(name) {
            return i as i64;
        }
    }
    -1
}

/// Get the file offset of a section by index.
///
/// Returns 0 if not a valid ELF or index out of bounds.
pub fn get_section_file_offset(data: &[u8], index: usize) -> u64 {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return 0;
    };
    elf.section_headers
        .get(index)
        .map(|shdr| shdr.sh_offset)
        .unwrap_or(0)
}

/// Get the file size of a section by index.
///
/// Returns 0 if not a valid ELF or index out of bounds.
pub fn get_section_file_size(data: &[u8], index: usize) -> u64 {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return 0;
    };
    elf.section_headers
        .get(index)
        .map(|shdr| shdr.sh_size)
        .unwrap_or(0)
}

/// Get the file offset of a program header by index.
///
/// Returns 0 if not a valid ELF or index out of bounds.
pub fn get_program_file_offset(data: &[u8], index: usize) -> u64 {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return 0;
    };
    elf.program_headers
        .get(index)
        .map(|phdr| phdr.p_offset)
        .unwrap_or(0)
}

/// Get the file size of a program header by index.
///
/// Returns 0 if not a valid ELF or index out of bounds.
pub fn get_program_file_size(data: &[u8], index: usize) -> u64 {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return 0;
    };
    elf.program_headers
        .get(index)
        .map(|phdr| phdr.p_filesz)
        .unwrap_or(0)
}

/// Get the overlay offset (data after the last segment's file data).
///
/// Returns -1 if no overlay or not a valid ELF.
pub fn get_overlay_offset(data: &[u8]) -> i64 {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return -1;
    };
    let mut max_end: u64 = 0;
    for phdr in &elf.program_headers {
        let end = phdr.p_offset.saturating_add(phdr.p_filesz);
        if end > max_end {
            max_end = end;
        }
    }
    if max_end >= data.len() as u64 {
        return -1;
    }
    max_end as i64
}

/// Get the string table offset (first SHT_STRTAB section).
///
/// Returns 0 if not found or not a valid ELF.
pub fn get_string_table_offset(data: &[u8]) -> u64 {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return 0;
    };
    let sht_strtab = goblin::elf::section_header::SHT_STRTAB;
    for shdr in &elf.section_headers {
        if shdr.sh_type == sht_strtab {
            return shdr.sh_offset;
        }
    }
    0
}

/// Get the symbol table offset (first SHT_SYMTAB section).
///
/// Returns 0 if not found or not a valid ELF.
pub fn get_symbol_table_offset(data: &[u8]) -> u64 {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return 0;
    };
    let sht_symtab = goblin::elf::section_header::SHT_SYMTAB;
    for shdr in &elf.section_headers {
        if shdr.sh_type == sht_symtab {
            return shdr.sh_offset;
        }
    }
    0
}

/// Get the relocation table offset (first SHT_REL or SHT_RELA section).
///
/// Returns 0 if not found or not a valid ELF.
pub fn get_relocation_table_offset(data: &[u8]) -> u64 {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return 0;
    };
    let sht_rel = goblin::elf::section_header::SHT_REL;
    let sht_rela = goblin::elf::section_header::SHT_RELA;
    for shdr in &elf.section_headers {
        if shdr.sh_type == sht_rel || shdr.sh_type == sht_rela {
            return shdr.sh_offset;
        }
    }
    0
}

/// ELF type names mapping.
fn elf_type_name(e_type: u16) -> String {
    use goblin::elf::header::*;
    match e_type {
        ET_NONE => "NONE".to_string(),
        ET_REL => "REL".to_string(),
        ET_EXEC => "EXEC".to_string(),
        ET_DYN => "DYN".to_string(),
        ET_CORE => "CORE".to_string(),
        _ => format!("type{e_type}"),
    }
}

/// ELF machine names mapping (subset matching the JS implementation).
fn elf_machine_name(e_machine: u16) -> String {
    use goblin::elf::header::*;
    match e_machine {
        EM_NONE => "None".to_string(),
        EM_386 => "x86".to_string(),
        EM_ARM => "ARM".to_string(),
        EM_X86_64 => "x86-64".to_string(),
        EM_AARCH64 => "AArch64".to_string(),
        EM_RISCV => "RISC-V".to_string(),
        _ => format!("machine{e_machine}"),
    }
}

/// Get the ELF type name.
///
/// Returns empty string if not a valid ELF.
pub fn get_type_name(data: &[u8]) -> String {
    elf_from_bytes(data)
        .map(|elf| elf_type_name(elf.header.e_type))
        .unwrap_or_default()
}

/// Get the ELF machine name.
///
/// Returns empty string if not a valid ELF.
pub fn get_machine_name(data: &[u8]) -> String {
    elf_from_bytes(data)
        .map(|elf| elf_machine_name(elf.header.e_machine))
        .unwrap_or_default()
}

/// Get the general options string (type + machine + bits).
///
/// Returns empty string if not a valid ELF.
pub fn get_general_options(data: &[u8]) -> String {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return String::new();
    };
    let t = elf_type_name(elf.header.e_type);
    let m = elf_machine_name(elf.header.e_machine);
    let b = if elf.is_64 { "64" } else { "32" };
    format!("{t} {m}-{b}")
}

/// Get the OS ABI name.
///
/// Returns empty string if not a valid ELF.
pub fn get_osabi_name(data: &[u8]) -> String {
    let elf = elf_from_bytes(data);
    let Some(elf) = elf else {
        return String::new();
    };
    // goblin stores OS/ABI in header.e_ident[7] (EI_OSABI).
    let osabi = elf.header.e_ident[7];
    match osabi {
        0 => "UNIX - System V".to_string(),
        1 => "HP-UX".to_string(),
        2 => "NetBSD".to_string(),
        3 => "Linux".to_string(),
        6 => "Solaris".to_string(),
        7 => "AIX".to_string(),
        8 => "IRIX".to_string(),
        9 => "FreeBSD".to_string(),
        10 => "Compaq Tru64".to_string(),
        11 => "Novell Modesto".to_string(),
        12 => "OpenBSD".to_string(),
        64 => "ARM EABI".to_string(),
        97 => "ARM".to_string(),
        255 => "Standalone".to_string(),
        _ => String::new(),
    }
}

/// Check if a library is present in the DT_NEEDED entries.
///
/// Returns false if not a valid ELF or library not found.
pub fn is_library_present(data: &[u8], name: &str) -> bool {
    get_import_libraries(data).iter().any(|lib| lib == name)
}

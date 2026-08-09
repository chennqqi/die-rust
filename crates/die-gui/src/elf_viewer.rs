//! ELF-specific views: program headers, section headers, dynamic entries,
//! libraries, interpreter, notes, and symbol table.
//!
//! Uses `goblin` for ELF parsing (ELF32 and ELF64). Mirrors upstream
//! `FormatWidgets/ELF/elfwidget.cpp` sub-views.

use serde::{Deserialize, Serialize};

/// ELF program header entry (Elf_Phdr).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfProgramHeader {
    /// Program header type (PT_LOAD, PT_DYNAMIC, etc.).
    pub p_type: String,
    /// Program header type raw value.
    pub p_type_val: u32,
    /// Program header flags (PF_R/PF_W/PF_X).
    pub p_flags: String,
    /// Segment offset in file.
    pub p_offset: u64,
    /// Segment virtual address.
    pub p_vaddr: u64,
    /// Segment physical address (usually same as vaddr).
    pub p_paddr: u64,
    /// Segment size in file.
    pub p_filesz: u64,
    /// Segment size in memory.
    pub p_memsz: u64,
    /// Segment alignment.
    pub p_align: u64,
    /// Flags raw value.
    pub p_flags_val: u32,
}

/// ELF section header entry (Elf_Shdr).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSectionHeader {
    /// Section name.
    pub sh_name: String,
    /// Section type (SHT_PROGBITS, SHT_STRTAB, etc.).
    pub sh_type: String,
    /// Section type raw value.
    pub sh_type_val: u32,
    /// Section flags (SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR, etc.).
    pub sh_flags: String,
    /// Section flags raw value.
    pub sh_flags_val: u64,
    /// Section virtual address.
    pub sh_addr: u64,
    /// Section offset in file.
    pub sh_offset: u64,
    /// Section size.
    pub sh_size: u64,
    /// Link field (section header index).
    pub sh_link: u32,
    /// Info field (section-specific).
    pub sh_info: u32,
    /// Address alignment.
    pub sh_addralign: u64,
    /// Entry size (for tables).
    pub sh_entsize: u64,
}

/// ELF dynamic entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfDynamicEntry {
    /// Tag name (DT_NEEDED, DT_PLTGOT, etc.).
    pub d_tag: String,
    /// Tag raw value.
    pub d_tag_val: u64,
    /// Value (offset or address).
    pub d_val: u64,
}

/// ELF library (from DT_NEEDED entries).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfLibrary {
    /// Library name (e.g. "libc.so.6").
    pub name: String,
}

/// ELF note entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfNote {
    /// Note name.
    pub name: String,
    /// Note type.
    pub n_type: String,
    /// Note type raw value.
    pub n_type_val: u32,
    /// Note description (hex).
    pub desc: String,
}

/// ELF symbol table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSymbol {
    /// Symbol name.
    pub name: String,
    /// Symbol value (address or offset).
    pub value: u64,
    /// Symbol size.
    pub size: u64,
    /// Binding (LOCAL, GLOBAL, WEAK).
    pub binding: String,
    /// Symbol type (NOTYPE, OBJECT, FUNC, etc.).
    pub sym_type: String,
    /// Visibility (DEFAULT, HIDDEN, PROTECTED).
    pub visibility: String,
    /// Section index (or special value like SHN_UNDEF).
    pub shndx: String,
}

/// ELF relocation entry (Rela or Rel).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfRelocation {
    /// Offset where the relocation applies.
    pub r_offset: u64,
    /// Relocation info (symbol index + type).
    pub r_info: u64,
    /// Addend (0 for Rel, non-zero for Rela).
    pub r_addend: i64,
    /// Symbol index extracted from r_info.
    pub r_sym: u32,
    /// Relocation type extracted from r_info.
    pub r_type: u32,
    /// Whether this is a Rela (has addend) or Rel.
    pub is_rela: bool,
}

/// Complete ELF view data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ElfView {
    /// Program headers (PT_PHDR entries).
    pub program_headers: Vec<ElfProgramHeader>,
    /// Section headers.
    pub section_headers: Vec<ElfSectionHeader>,
    /// Dynamic entries.
    pub dynamic_entries: Vec<ElfDynamicEntry>,
    /// Required libraries (DT_NEEDED).
    pub libraries: Vec<ElfLibrary>,
    /// Interpreter (PT_INTERP path).
    pub interpreter: Option<String>,
    /// Notes (PT_NOTE entries).
    pub notes: Vec<ElfNote>,
    /// Symbol table entries.
    pub symbols: Vec<ElfSymbol>,
    /// Runpath (DT_RUNPATH).
    pub runpath: Option<String>,
    /// Is 64-bit.
    pub is64: bool,
    /// Is little-endian.
    pub is_le: bool,
    /// Machine type string.
    pub machine: String,
    /// File type string (ET_EXEC, ET_DYN, etc.).
    pub e_type: String,
    /// Entry point address.
    pub entry: u64,
    /// Relocation entries (Rela and Rel).
    pub relocations: Vec<ElfRelocation>,
    /// String table entries (from .strtab / .shstrtab sections).
    pub string_table: Vec<ElfStringTableEntry>,
}

/// ELF string table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfStringTableEntry {
    /// String offset within the string table section.
    pub offset: u32,
    /// String value.
    pub value: String,
    /// Section name from which this entry was extracted.
    pub section: String,
}

/// Parse ELF view data from raw bytes.
///
/// Returns `None` if the data is not a valid ELF file.
pub fn parse_elf_view(data: &[u8]) -> Option<ElfView> {
    let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(data) else {
        return None;
    };

    let header = &elf.header;
    let is64 = header.e_ident[goblin::elf::header::EI_CLASS] == goblin::elf::header::ELFCLASS64;
    let is_le = header.e_ident[goblin::elf::header::EI_DATA] == goblin::elf::header::ELFDATA2LSB;
    let machine = elf_machine_name(header.e_machine);
    let e_type = elf_type_name(header.e_type);

    // Parse program headers.
    let program_headers: Vec<ElfProgramHeader> = elf
        .program_headers
        .iter()
        .map(|ph| ElfProgramHeader {
            p_type: ph_type_name(ph.p_type),
            p_type_val: ph.p_type,
            p_flags: ph_flags_string(ph.p_flags),
            p_offset: ph.p_offset,
            p_vaddr: ph.p_vaddr,
            p_paddr: ph.p_paddr,
            p_filesz: ph.p_filesz,
            p_memsz: ph.p_memsz,
            p_align: ph.p_align,
            p_flags_val: ph.p_flags,
        })
        .collect();

    // Parse section headers.
    let section_headers: Vec<ElfSectionHeader> = elf
        .section_headers
        .iter()
        .map(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
            ElfSectionHeader {
                sh_name: name,
                sh_type: sh_type_name(sh.sh_type),
                sh_type_val: sh.sh_type,
                sh_flags: sh_flags_string(sh.sh_flags),
                sh_flags_val: sh.sh_flags,
                sh_addr: sh.sh_addr,
                sh_offset: sh.sh_offset,
                sh_size: sh.sh_size,
                sh_link: sh.sh_link,
                sh_info: sh.sh_info,
                sh_addralign: sh.sh_addralign,
                sh_entsize: sh.sh_entsize,
            }
        })
        .collect();

    // Parse dynamic entries and libraries.
    let mut dynamic_entries = Vec::new();
    let mut libraries = Vec::new();
    let mut runpath = None;

    if let Some(dynamic) = &elf.dynamic {
        for d in &dynamic.dyns {
            let tag_name = dt_tag_name(d.d_tag);
            dynamic_entries.push(ElfDynamicEntry {
                d_tag: tag_name.clone(),
                d_tag_val: d.d_tag,
                d_val: d.d_val,
            });

            if d.d_tag == goblin::elf::dynamic::DT_NEEDED
                && let Some(name) = elf.dynstrtab.get_at(d.d_val as usize)
            {
                libraries.push(ElfLibrary {
                    name: name.to_string(),
                });
            }
            if d.d_tag == goblin::elf::dynamic::DT_RUNPATH
                && let Some(path) = elf.dynstrtab.get_at(d.d_val as usize)
            {
                runpath = Some(path.to_string());
            }
        }
    }

    // Parse interpreter from PT_INTERP.
    let interpreter = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == goblin::elf::program_header::PT_INTERP)
        .and_then(|ph| {
            let start = ph.p_offset as usize;
            let end = (ph.p_offset + ph.p_filesz) as usize;
            if end <= data.len() {
                let interp_bytes = &data[start..end];
                let interp = interp_bytes
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect::<String>();
                if !interp.is_empty() {
                    return Some(interp);
                }
            }
            None
        });

    // Parse notes from PT_NOTE.
    let notes = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == goblin::elf::program_header::PT_NOTE)
        .flat_map(|ph| {
            let start = ph.p_offset as usize;
            let end = (ph.p_offset + ph.p_filesz) as usize;
            if end > data.len() {
                return Vec::new();
            }
            parse_elf_notes(&data[start..end])
        })
        .collect();

    // Parse symbols.
    let symbols = elf
        .syms
        .iter()
        .map(|sym| {
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();
            ElfSymbol {
                name,
                value: sym.st_value,
                size: sym.st_size,
                binding: sym_binding_name(sym.st_bind()),
                sym_type: sym_type_name(sym.st_type()),
                visibility: sym_visibility_name(sym.st_visibility()),
                shndx: sym_shndx_name(sym.st_shndx),
            }
        })
        .collect();

    // Parse relocations from rela and rel sections.
    let relocations = parse_elf_relocations(&elf, data, is64);

    // Parse string table entries from .strtab and .shstrtab sections.
    let string_table = parse_elf_string_table(&elf, data);

    Some(ElfView {
        program_headers,
        section_headers,
        dynamic_entries,
        libraries,
        interpreter,
        notes,
        symbols,
        runpath,
        is64,
        is_le,
        machine,
        e_type,
        entry: header.e_entry,
        relocations,
        string_table,
    })
}

/// Parse string table entries from .strtab and .shstrtab sections.
fn parse_elf_string_table(elf: &goblin::elf::Elf, data: &[u8]) -> Vec<ElfStringTableEntry> {
    let mut result = Vec::new();
    for sec in &elf.section_headers {
        let sh_type = sec.sh_type;
        let sh_name = elf
            .shdr_strtab
            .get_at(sec.sh_name)
            .unwrap_or("")
            .to_string();
        // SHT_STRTAB = 3 (covers .strtab, .shstrtab, .dynstr)
        if sh_type == goblin::elf::section_header::SHT_STRTAB {
            let offset = sec.sh_offset as usize;
            let size = sec.sh_size as usize;
            if offset + size > data.len() || size == 0 {
                continue;
            }
            let raw = &data[offset..offset + size];
            let mut pos = 0;
            while pos < raw.len() {
                let end = raw[pos..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(raw.len() - pos);
                if end > 0 {
                    let value = String::from_utf8_lossy(&raw[pos..pos + end]).to_string();
                    result.push(ElfStringTableEntry {
                        offset: pos as u32,
                        value,
                        section: sh_name.clone(),
                    });
                }
                pos += end + 1;
            }
        }
    }
    // Limit to 5000 entries.
    result.truncate(5000);
    result
}

/// Parse ELF relocations from SHT_RELA and SHT_REL sections.
fn parse_elf_relocations(
    elf: &goblin::elf::Elf<'_>,
    data: &[u8],
    is64: bool,
) -> Vec<ElfRelocation> {
    let mut relocs = Vec::new();
    for section in &elf.section_headers {
        let sh_type = section.sh_type;
        if sh_type != goblin::elf::section_header::SHT_RELA
            && sh_type != goblin::elf::section_header::SHT_REL
        {
            continue;
        }
        let is_rela = sh_type == goblin::elf::section_header::SHT_RELA;
        let offset = section.sh_offset as usize;
        let size = section.sh_size as usize;
        let entsize = section.sh_entsize as usize;
        if offset + size > data.len() || entsize == 0 {
            continue;
        }
        let section_data = &data[offset..offset + size];
        for chunk in section_data.chunks(entsize) {
            if is64 {
                if is_rela && chunk.len() >= 24 {
                    let r_offset = u64::from_le_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                        chunk[7],
                    ]);
                    let r_info = u64::from_le_bytes([
                        chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14],
                        chunk[15],
                    ]);
                    let r_addend = i64::from_le_bytes([
                        chunk[16], chunk[17], chunk[18], chunk[19], chunk[20], chunk[21],
                        chunk[22], chunk[23],
                    ]);
                    relocs.push(ElfRelocation {
                        r_offset,
                        r_info,
                        r_addend,
                        r_sym: (r_info >> 32) as u32,
                        r_type: (r_info & 0xffffffff) as u32,
                        is_rela,
                    });
                } else if !is_rela && chunk.len() >= 16 {
                    let r_offset = u64::from_le_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                        chunk[7],
                    ]);
                    let r_info = u64::from_le_bytes([
                        chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14],
                        chunk[15],
                    ]);
                    relocs.push(ElfRelocation {
                        r_offset,
                        r_info,
                        r_addend: 0,
                        r_sym: (r_info >> 32) as u32,
                        r_type: (r_info & 0xffffffff) as u32,
                        is_rela,
                    });
                }
            } else {
                if is_rela && chunk.len() >= 12 {
                    let r_offset =
                        u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
                    let r_info =
                        u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) as u64;
                    let r_addend =
                        i32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]) as i64;
                    relocs.push(ElfRelocation {
                        r_offset,
                        r_info,
                        r_addend,
                        r_sym: (r_info >> 8) as u32,
                        r_type: (r_info & 0xff) as u32,
                        is_rela,
                    });
                } else if !is_rela && chunk.len() >= 8 {
                    let r_offset =
                        u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
                    let r_info =
                        u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) as u64;
                    relocs.push(ElfRelocation {
                        r_offset,
                        r_info,
                        r_addend: 0,
                        r_sym: (r_info >> 8) as u32,
                        r_type: (r_info & 0xff) as u32,
                        is_rela,
                    });
                }
            }
        }
    }
    relocs
}

/// Parse ELF notes from a PT_NOTE segment.
fn parse_elf_notes(data: &[u8]) -> Vec<ElfNote> {
    let mut notes = Vec::new();
    let mut offset = 0usize;

    while offset + 12 <= data.len() {
        let n_namesz = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let n_descsz = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let n_type = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]);

        let name_start = offset + 12;
        let name_end = name_start + n_namesz as usize;
        if name_end > data.len() {
            break;
        }
        let name = data[name_start..name_end]
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect::<String>();

        let desc_start = (name_end + 3) & !3; // Align to 4 bytes
        let desc_end = desc_start + n_descsz as usize;
        if desc_end > data.len() {
            break;
        }
        let desc = data[desc_start..desc_end]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        notes.push(ElfNote {
            name,
            n_type: note_type_name(n_type),
            n_type_val: n_type,
            desc,
        });

        offset = (desc_end + 3) & !3; // Align to 4 bytes
    }

    notes
}

/// Convert ELF machine type to human-readable name.
fn elf_machine_name(e_machine: u16) -> String {
    use goblin::elf::header::*;
    match e_machine {
        EM_NONE => "NONE".to_string(),
        EM_386 => "x86".to_string(),
        EM_X86_64 => "x86_64".to_string(),
        EM_ARM => "ARM".to_string(),
        EM_AARCH64 => "AArch64".to_string(),
        EM_MIPS => "MIPS".to_string(),
        EM_PPC => "PowerPC".to_string(),
        EM_PPC64 => "PowerPC64".to_string(),
        EM_RISCV => "RISC-V".to_string(),
        EM_S390 => "S390".to_string(),
        _ => format!("0x{:04x}", e_machine),
    }
}

/// Convert ELF file type to human-readable name.
fn elf_type_name(e_type: u16) -> String {
    use goblin::elf::header::*;
    match e_type {
        ET_NONE => "NONE".to_string(),
        ET_REL => "REL (relocatable)".to_string(),
        ET_EXEC => "EXEC (executable)".to_string(),
        ET_DYN => "DYN (shared object)".to_string(),
        ET_CORE => "CORE (core dump)".to_string(),
        _ => format!("0x{:04x}", e_type),
    }
}

/// Convert program header type to name.
fn ph_type_name(p_type: u32) -> String {
    use goblin::elf::program_header::*;
    match p_type {
        PT_NULL => "NULL".to_string(),
        PT_LOAD => "LOAD".to_string(),
        PT_DYNAMIC => "DYNAMIC".to_string(),
        PT_INTERP => "INTERP".to_string(),
        PT_NOTE => "NOTE".to_string(),
        PT_SHLIB => "SHLIB".to_string(),
        PT_PHDR => "PHDR".to_string(),
        PT_TLS => "TLS".to_string(),
        PT_GNU_EH_FRAME => "GNU_EH_FRAME".to_string(),
        PT_GNU_STACK => "GNU_STACK".to_string(),
        PT_GNU_RELRO => "GNU_RELRO".to_string(),
        PT_GNU_PROPERTY => "GNU_PROPERTY".to_string(),
        _ => {
            if (PT_LOOS..=PT_HIOS).contains(&p_type) {
                format!("LOOS-0x{:08x}", p_type)
            } else if (PT_LOPROC..=PT_HIPROC).contains(&p_type) {
                format!("LOPROC-0x{:08x}", p_type)
            } else {
                format!("0x{:08x}", p_type)
            }
        }
    }
}

/// Format program header flags as string (e.g. "R", "RW", "RWE").
fn ph_flags_string(p_flags: u32) -> String {
    let mut s = String::new();
    if p_flags & 4 != 0 {
        s.push('R');
    }
    if p_flags & 2 != 0 {
        s.push('W');
    }
    if p_flags & 1 != 0 {
        s.push('E');
    }
    if s.is_empty() {
        s.push_str("---");
    }
    s
}

/// Convert section header type to name.
fn sh_type_name(sh_type: u32) -> String {
    use goblin::elf::section_header::*;
    match sh_type {
        SHT_NULL => "NULL".to_string(),
        SHT_PROGBITS => "PROGBITS".to_string(),
        SHT_SYMTAB => "SYMTAB".to_string(),
        SHT_STRTAB => "STRTAB".to_string(),
        SHT_RELA => "RELA".to_string(),
        SHT_HASH => "HASH".to_string(),
        SHT_DYNAMIC => "DYNAMIC".to_string(),
        SHT_NOTE => "NOTE".to_string(),
        SHT_NOBITS => "NOBITS".to_string(),
        SHT_REL => "REL".to_string(),
        SHT_SHLIB => "SHLIB".to_string(),
        SHT_DYNSYM => "DYNSYM".to_string(),
        SHT_INIT_ARRAY => "INIT_ARRAY".to_string(),
        SHT_FINI_ARRAY => "FINI_ARRAY".to_string(),
        SHT_PREINIT_ARRAY => "PREINIT_ARRAY".to_string(),
        SHT_GROUP => "GROUP".to_string(),
        SHT_SYMTAB_SHNDX => "SYMTAB_SHNDX".to_string(),
        SHT_GNU_HASH => "GNU_HASH".to_string(),
        SHT_GNU_VERDEF => "GNU_VERDEF".to_string(),
        SHT_GNU_VERNEED => "GNU_VERNEED".to_string(),
        SHT_GNU_VERSYM => "GNU_VERSYM".to_string(),
        _ => format!("0x{:08x}", sh_type),
    }
}

/// Format section header flags as string.
fn sh_flags_string(sh_flags: u64) -> String {
    let mut parts = Vec::new();
    if sh_flags & 0x1 != 0 {
        parts.push("W");
    }
    if sh_flags & 0x2 != 0 {
        parts.push("A");
    }
    if sh_flags & 0x4 != 0 {
        parts.push("X");
    }
    if sh_flags & 0x10 != 0 {
        parts.push("M");
    }
    if sh_flags & 0x20 != 0 {
        parts.push("S");
    }
    if sh_flags & 0x40 != 0 {
        parts.push("I");
    }
    if sh_flags & 0x80 != 0 {
        parts.push("L");
    }
    parts.join("|")
}

/// Convert dynamic tag to name.
fn dt_tag_name(d_tag: u64) -> String {
    use goblin::elf::dynamic::*;
    match d_tag {
        DT_NULL => "NULL".to_string(),
        DT_NEEDED => "NEEDED".to_string(),
        DT_PLTRELSZ => "PLTRELSZ".to_string(),
        DT_PLTGOT => "PLTGOT".to_string(),
        DT_HASH => "HASH".to_string(),
        DT_STRTAB => "STRTAB".to_string(),
        DT_SYMTAB => "SYMTAB".to_string(),
        DT_RELA => "RELA".to_string(),
        DT_RELASZ => "RELASZ".to_string(),
        DT_RELAENT => "RELAENT".to_string(),
        DT_STRSZ => "STRSZ".to_string(),
        DT_SYMENT => "SYMENT".to_string(),
        DT_INIT => "INIT".to_string(),
        DT_FINI => "FINI".to_string(),
        DT_SONAME => "SONAME".to_string(),
        DT_RPATH => "RPATH".to_string(),
        DT_SYMBOLIC => "SYMBOLIC".to_string(),
        DT_REL => "REL".to_string(),
        DT_RELSZ => "RELSZ".to_string(),
        DT_RELENT => "RELENT".to_string(),
        DT_PLTREL => "PLTREL".to_string(),
        DT_DEBUG => "DEBUG".to_string(),
        DT_TEXTREL => "TEXTREL".to_string(),
        DT_JMPREL => "JMPREL".to_string(),
        DT_BIND_NOW => "BIND_NOW".to_string(),
        DT_INIT_ARRAY => "INIT_ARRAY".to_string(),
        DT_FINI_ARRAY => "FINI_ARRAY".to_string(),
        DT_RUNPATH => "RUNPATH".to_string(),
        DT_FLAGS => "FLAGS".to_string(),
        DT_GNU_HASH => "GNU_HASH".to_string(),
        DT_VERSYM => "VERSYM".to_string(),
        DT_VERDEF => "VERDEF".to_string(),
        DT_VERNEED => "VERNEED".to_string(),
        _ => format!("0x{:x}", d_tag),
    }
}

/// Convert symbol binding to name.
fn sym_binding_name(st_bind: u8) -> String {
    match st_bind {
        0 => "LOCAL".to_string(),
        1 => "GLOBAL".to_string(),
        2 => "WEAK".to_string(),
        10 => "LOOS".to_string(),
        _ => format!("0x{:02x}", st_bind),
    }
}

/// Convert symbol type to name.
fn sym_type_name(st_type: u8) -> String {
    match st_type {
        0 => "NOTYPE".to_string(),
        1 => "OBJECT".to_string(),
        2 => "FUNC".to_string(),
        3 => "SECTION".to_string(),
        4 => "FILE".to_string(),
        5 => "COMMON".to_string(),
        6 => "TLS".to_string(),
        _ => format!("0x{:02x}", st_type),
    }
}

/// Convert symbol visibility to name.
fn sym_visibility_name(st_visibility: u8) -> String {
    match st_visibility {
        0 => "DEFAULT".to_string(),
        1 => "INTERNAL".to_string(),
        2 => "HIDDEN".to_string(),
        3 => "PROTECTED".to_string(),
        _ => format!("0x{:02x}", st_visibility),
    }
}

/// Convert section index to name.
fn sym_shndx_name(st_shndx: usize) -> String {
    match st_shndx {
        0 => "UND".to_string(),
        0xfff1 => "ABS".to_string(),
        0xfff2 => "COMMON".to_string(),
        0xffff => "XINDEX".to_string(),
        _ => st_shndx.to_string(),
    }
}

/// Convert note type to name (common values).
fn note_type_name(n_type: u32) -> String {
    match n_type {
        1 => "NT_VERSION".to_string(),
        2 => "NT_ARCH".to_string(),
        3 => "NT_GNU_BUILD_ID".to_string(),
        4 => "NT_GNU_GOLD_VERSION".to_string(),
        5 => "NT_GNU_PROPERTY_TYPE_0".to_string(),
        _ => format!("0x{:08x}", n_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_elf_view_not_elf() {
        let data = vec![0u8; 64];
        assert!(parse_elf_view(&data).is_none());
    }

    #[test]
    fn test_ph_flags_string() {
        assert_eq!(ph_flags_string(4), "R");
        assert_eq!(ph_flags_string(6), "RW");
        assert_eq!(ph_flags_string(7), "RWE");
        assert_eq!(ph_flags_string(0), "---");
    }

    #[test]
    fn test_sh_flags_string() {
        assert_eq!(sh_flags_string(0x2), "A");
        assert_eq!(sh_flags_string(0x3), "W|A");
        assert_eq!(sh_flags_string(0x7), "W|A|X");
    }

    #[test]
    fn test_elf_string_table_entry_serialization() {
        let entry = ElfStringTableEntry {
            offset: 42,
            value: "printf".to_string(),
            section: ".strtab".to_string(),
        };
        assert_eq!(entry.offset, 42);
        assert_eq!(entry.value, "printf");
        assert_eq!(entry.section, ".strtab");
    }

    #[test]
    fn test_elf_string_table_extraction_logic() {
        // Simulate raw string table bytes: "\0printf\0scanf\0malloc\0"
        let raw: Vec<u8> = b"\0printf\0scanf\0malloc\0".to_vec();
        let mut entries = Vec::new();
        let mut pos = 0;
        while pos < raw.len() {
            let end = raw[pos..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(raw.len() - pos);
            if end > 0 {
                let value = String::from_utf8_lossy(&raw[pos..pos + end]).to_string();
                entries.push(value);
            }
            pos += end + 1;
        }
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], "printf");
        assert_eq!(entries[1], "scanf");
        assert_eq!(entries[2], "malloc");
    }
}

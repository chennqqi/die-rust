//! Mach-O-specific views: header, load commands, segments, sections,
//! and libraries.
//!
//! Uses `goblin` for Mach-O parsing (32-bit, 64-bit, and FAT). Mirrors
//! upstream `FormatWidgets/MACH/machwidget.cpp` sub-views.

use goblin::mach::load_command::CommandVariant;
use serde::{Deserialize, Serialize};

/// Mach-O load command entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachLoadCommand {
    /// Command name (LC_SEGMENT, LC_LOAD_DYLIB, etc.).
    pub cmd: String,
    /// Command raw value.
    pub cmd_val: u32,
    /// Command size in bytes.
    pub cmdsize: u32,
    /// Additional info (e.g. library name, segment name).
    pub info: String,
}

/// Mach-O segment entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachSegment {
    /// Segment name (e.g. "__TEXT", "__DATA").
    pub name: String,
    /// VM address.
    pub vmaddr: u64,
    /// VM size.
    pub vmsize: u64,
    /// File offset.
    pub fileoff: u64,
    /// File size.
    pub filesize: u64,
    /// Maximum VM protection.
    pub maxprot: String,
    /// Initial VM protection.
    pub initprot: String,
    /// Number of sections.
    pub nsects: u32,
    /// Flags.
    pub flags: u32,
}

/// Mach-O section entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachSection {
    /// Section name (e.g. "__text", "__data").
    pub sectname: String,
    /// Segment name.
    pub segname: String,
    /// VM address.
    pub addr: u64,
    /// Size.
    pub size: u64,
    /// File offset.
    pub offset: u32,
    /// Alignment (power of 2).
    pub align: u32,
    /// Relocation offset.
    pub reloff: u32,
    /// Number of relocations.
    pub nreloc: u32,
    /// Flags.
    pub flags: u32,
}

/// Mach-O library entry (from LC_LOAD_DYLIB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachLibrary {
    /// Library path (e.g. "/usr/lib/libSystem.B.dylib").
    pub name: String,
    /// Current version.
    pub current_version: u32,
    /// Compatibility version.
    pub compatibility_version: u32,
}

/// Mach-O UUID info (from LC_UUID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachUuid {
    /// UUID as hex string (e.g. "A1B2C3D4-...").
    pub uuid: String,
}

/// Mach-O symtab info (from LC_SYMTAB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachSymtab {
    /// Symbol table offset.
    pub symoff: u32,
    /// Number of symbols.
    pub nsyms: u32,
    /// String table offset.
    pub stroff: u32,
    /// String table size.
    pub strsize: u32,
}

/// Mach-O dysymtab info (from LC_DYSYMTAB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachDysymtab {
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

/// Mach-O dyld info (from LC_DYLD_INFO / LC_DYLD_INFO_ONLY).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachDyldInfo {
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

/// Mach-O version min (from LC_VERSION_MIN_*).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachVersionMin {
    /// Platform name (macosx/iphoneos/tvos/watchos).
    pub platform: String,
    /// Version as X.Y.Z string.
    pub version: String,
    /// SDK version as X.Y.Z string.
    pub sdk: String,
}

/// Mach-O build version (from LC_BUILD_VERSION).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachBuildVersion {
    /// Platform name.
    pub platform: String,
    /// Min OS version as X.Y.Z string.
    pub minos: String,
    /// SDK version as X.Y.Z string.
    pub sdk: String,
    /// Number of tool entries.
    pub ntools: u32,
}

/// Mach-O rpath entry (from LC_RPATH).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachRpath {
    /// Rpath string.
    pub path: String,
}

/// Mach-O source version (from LC_SOURCE_VERSION).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachSourceVersion {
    /// Version as A.B.C.D.E string.
    pub version: String,
}

/// Mach-O dylinker info (from LC_LOAD_DYLINKER / LC_ID_DYLINKER).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachDylinker {
    /// Dylinker path.
    pub name: String,
}

/// Mach-O linkedit data (from LC_CODE_SIGNATURE, LC_FUNCTION_STARTS, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachLinkeditData {
    /// Command name.
    pub cmd: String,
    /// Data offset.
    pub dataoff: u32,
    /// Data size.
    pub datasize: u32,
}

/// Mach-O encryption info (from LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachEncryptionInfo {
    /// Encrypted range offset.
    pub cryptoff: u32,
    /// Encrypted range size.
    pub cryptsize: u32,
    /// Encryption system ID (0 = not encrypted).
    pub cryptid: u32,
}

/// Mach-O entry point info (from LC_MAIN).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachEntryPoint {
    /// File offset of main.
    pub entryoff: u64,
    /// Initial stack size (0 if not specified).
    pub stacksize: u64,
}

/// Mach-O weak library entry (from LC_LOAD_WEAK_DYLIB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachWeakLibrary {
    /// Library name (dylib path).
    pub name: String,
    /// Current version.
    pub current_version: u32,
    /// Compatibility version.
    pub compatibility_version: u32,
}

/// Mach-O ID library (from LC_ID_DYLIB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachIdLibrary {
    /// Library name (dylib path).
    pub name: String,
    /// Current version.
    pub current_version: u32,
    /// Compatibility version.
    pub compatibility_version: u32,
}

/// Mach-O FVMLIB entry (from LC_LOADFVMLIB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachFvmlib {
    /// File offset to the name string.
    pub name: String,
    /// Minor version number.
    pub minor_version: u32,
    /// Header address.
    pub header_addr: u32,
}

/// Mach-O IDFVMLIB entry (from LC_IDFVMLIB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachIdFvmlib {
    /// File offset to the name string.
    pub name: String,
    /// Minor version number.
    pub minor_version: u32,
    /// Header address.
    pub header_addr: u32,
}

/// Mach-O function start entry (from LC_FUNCTION_STARTS, ULEB128 decoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachFunctionStart {
    /// Function start address (virtual address).
    pub address: u64,
}

/// Mach-O data-in-code entry (from LC_DATA_IN_CODE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachDataInCodeEntry {
    /// Offset from the start of the file.
    pub offset: u32,
    /// Length of the data region.
    pub length: u16,
    /// Kind of data (1=DATA, 2=JUMP_TABLE, 3=SYMBOL_TRAMPOLINES).
    pub kind: u16,
    /// Kind name string.
    pub kind_name: String,
}

/// Mach-O code signature info (from LC_CODE_SIGNATURE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachCodeSignature {
    /// Magic value (0xfade0cc0 for embedded signature).
    pub magic: u32,
    /// Total length of the blob.
    pub length: u32,
    /// Number of code slots.
    pub count: u32,
    /// Code slot entries (type + offset).
    pub slots: Vec<MachCodeSlot>,
}

/// Mach-O code signature slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachCodeSlot {
    /// Slot type (e.g. 0=CODE_DIRECTORY, 2=requirements, 3=requirements set).
    pub type_val: u32,
    /// Slot type name.
    pub type_name: String,
    /// Offset within the SuperBlob.
    pub offset: u32,
}

/// Mach-O SuperBlob info (embedded signature wrapper).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachSuperBlob {
    /// Magic value.
    pub magic: u32,
    /// Total length.
    pub length: u32,
    /// Number of blob entries.
    pub count: u32,
    /// Blob index entries.
    pub entries: Vec<MachSuperBlobEntry>,
}

/// Mach-O SuperBlob entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachSuperBlobEntry {
    /// Slot type.
    pub type_val: u32,
    /// Slot type name.
    pub type_name: String,
    /// Offset within the SuperBlob.
    pub offset: u32,
}

/// Mach-O Unix Thread entry (from LC_UNIXTHREAD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachUnixThread {
    /// CPU type string.
    pub cputype: String,
    /// Entry point address.
    pub entry: u64,
}

/// Mach-O Dyld chained fixups info (from LC_DYLD_CHAINED_FIXUPS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachDyldChainedFixups {
    /// Data offset in file.
    pub dataoff: u32,
    /// Data size.
    pub datasize: u32,
    /// Fixups version (parsed from header, 0 if unparseable).
    pub fixups_version: u32,
    /// Starts offset (parsed from header, 0 if unparseable).
    pub starts_offset: u32,
    /// Image base (parsed from header, 0 if unparseable).
    pub image_base: u64,
}

/// Mach-O Dyld exports trie info (from LC_DYLD_EXPORTS_TRIE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachDyldExportsTrie {
    /// Data offset in file.
    pub dataoff: u32,
    /// Data size.
    pub datasize: u32,
    /// Number of exported symbols (parsed from trie, 0 if unparseable).
    pub export_count: u32,
}

/// Mach-O string table entry (from LC_SYMTAB stroff/strsize).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachStringTableEntry {
    /// String offset within the string table.
    pub offset: u32,
    /// String value.
    pub value: String,
}

/// Complete Mach-O view data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MachView {
    /// Load commands.
    pub load_commands: Vec<MachLoadCommand>,
    /// Segments.
    pub segments: Vec<MachSegment>,
    /// Sections.
    pub sections: Vec<MachSection>,
    /// Libraries.
    pub libraries: Vec<MachLibrary>,
    /// Is 64-bit.
    pub is64: bool,
    /// Magic value.
    pub magic: u32,
    /// CPU type string.
    pub cputype: String,
    /// CPU subtype.
    pub cpusubtype: u32,
    /// File type string.
    pub filetype: String,
    /// Number of load commands.
    pub ncmds: u32,
    /// Size of load commands.
    pub sizeofcmds: u32,
    /// Entry point (from LC_MAIN or LC_UNIXTHREAD).
    pub entry: Option<u64>,
    /// UUID (from LC_UUID).
    pub uuid: Option<MachUuid>,
    /// Symbol table (from LC_SYMTAB).
    pub symtab: Option<MachSymtab>,
    /// Dynamic symbol table (from LC_DYSYMTAB).
    pub dysymtab: Option<MachDysymtab>,
    /// Dyld info (from LC_DYLD_INFO / LC_DYLD_INFO_ONLY).
    pub dyld_info: Option<MachDyldInfo>,
    /// Version min (from LC_VERSION_MIN_*).
    pub version_min: Option<MachVersionMin>,
    /// Build version (from LC_BUILD_VERSION).
    pub build_version: Option<MachBuildVersion>,
    /// Rpaths (from LC_RPATH).
    pub rpaths: Vec<MachRpath>,
    /// Source version (from LC_SOURCE_VERSION).
    pub source_version: Option<MachSourceVersion>,
    /// Dylinker (from LC_LOAD_DYLINKER).
    pub dylinker: Option<MachDylinker>,
    /// Linkedit data entries (code signature, function starts, data in code, etc.).
    pub linkedit_data: Vec<MachLinkeditData>,
    /// Encryption info (from LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64).
    pub encryption_info: Option<MachEncryptionInfo>,
    /// Entry point detail (from LC_MAIN).
    pub entry_point: Option<MachEntryPoint>,
    /// Weak libraries (from LC_LOAD_WEAK_DYLIB).
    pub weak_libraries: Vec<MachWeakLibrary>,
    /// ID library (from LC_ID_DYLIB).
    pub id_library: Option<MachIdLibrary>,
    /// FVMLIB entries (from LC_LOADFVMLIB).
    pub fvmlibs: Vec<MachFvmlib>,
    /// IDFVMLIB entries (from LC_IDFVMLIB).
    pub id_fvmlibs: Vec<MachIdFvmlib>,
    /// Function starts (from LC_FUNCTION_STARTS, ULEB128 decoded).
    pub function_starts: Vec<MachFunctionStart>,
    /// Data in code entries (from LC_DATA_IN_CODE).
    pub data_in_code: Vec<MachDataInCodeEntry>,
    /// Code signature (from LC_CODE_SIGNATURE, parsed SuperBlob).
    pub code_signature: Option<MachCodeSignature>,
    /// SuperBlob entries (detailed blob index).
    pub superblob: Option<MachSuperBlob>,
    /// Unix thread (from LC_UNIXTHREAD).
    pub unix_thread: Option<MachUnixThread>,
    /// Dyld chained fixups (from LC_DYLD_CHAINED_FIXUPS).
    pub dyld_chained_fixups: Option<MachDyldChainedFixups>,
    /// Dyld exports trie (from LC_DYLD_EXPORTS_TRIE).
    pub dyld_exports_trie: Option<MachDyldExportsTrie>,
    /// String table entries (from LC_SYMTAB stroff/strsize).
    pub string_table: Vec<MachStringTableEntry>,
}

/// Parse Mach-O view data from raw bytes.
///
/// Returns `None` if the data is not a valid Mach-O file.
pub fn parse_macho_view(data: &[u8]) -> Option<MachView> {
    use goblin::mach::MachO;

    let macho = MachO::parse(data, 0).ok()?;

    let header = &macho.header;
    let is64 = macho.is_64;
    let cputype = macho_cputype_name(header.cputype);
    let filetype = macho_filetype_name(header.filetype);

    // Parse load commands.
    let mut load_commands = Vec::new();
    let mut libraries = Vec::new();
    let mut uuid = None;
    let mut symtab = None;
    let mut dysymtab = None;
    let mut dyld_info = None;
    let mut version_min = None;
    let mut build_version = None;
    let mut rpaths = Vec::new();
    let mut source_version = None;
    let mut dylinker = None;
    let mut linkedit_data = Vec::new();
    let mut encryption_info = None;
    let mut entry_point = None;
    let mut weak_libraries = Vec::new();
    let mut id_library = None;
    let mut fvmlibs = Vec::new();
    let mut id_fvmlibs = Vec::new();
    let mut function_starts_raw = None;
    let mut data_in_code_raw = None;
    let mut code_signature_raw = None;
    let mut unix_thread_entry = None;
    let mut dyld_chained_fixups_raw = None;
    let mut dyld_exports_trie_raw = None;

    for lc in &macho.load_commands {
        let cmd_val = lc.command.cmd();
        let cmdsize = lc.command.cmdsize() as u32;
        let cmd_name = lc_name(cmd_val);
        let info = lc_info(&lc.command);

        load_commands.push(MachLoadCommand {
            cmd: cmd_name.clone(),
            cmd_val,
            cmdsize,
            info,
        });

        // Extract detailed info from specific load commands.
        match &lc.command {
            CommandVariant::LoadDylib(d)
            | CommandVariant::ReexportDylib(d)
            | CommandVariant::LazyLoadDylib(d)
            | CommandVariant::LoadUpwardDylib(d) => {
                if let Ok(name) = lc_str_to_string(data, lc.offset, d.dylib.name) {
                    libraries.push(MachLibrary {
                        name,
                        current_version: d.dylib.current_version,
                        compatibility_version: d.dylib.compatibility_version,
                    });
                }
            }
            CommandVariant::LoadWeakDylib(d) => {
                if let Ok(name) = lc_str_to_string(data, lc.offset, d.dylib.name) {
                    weak_libraries.push(MachWeakLibrary {
                        name: name.clone(),
                        current_version: d.dylib.current_version,
                        compatibility_version: d.dylib.compatibility_version,
                    });
                    libraries.push(MachLibrary {
                        name,
                        current_version: d.dylib.current_version,
                        compatibility_version: d.dylib.compatibility_version,
                    });
                }
            }
            CommandVariant::IdDylib(d) => {
                if let Ok(name) = lc_str_to_string(data, lc.offset, d.dylib.name) {
                    id_library = Some(MachIdLibrary {
                        name,
                        current_version: d.dylib.current_version,
                        compatibility_version: d.dylib.compatibility_version,
                    });
                }
            }
            CommandVariant::Uuid(u) => {
                uuid = Some(MachUuid {
                    uuid: format_uuid(&u.uuid),
                });
            }
            CommandVariant::Symtab(s) => {
                symtab = Some(MachSymtab {
                    symoff: s.symoff,
                    nsyms: s.nsyms,
                    stroff: s.stroff,
                    strsize: s.strsize,
                });
            }
            CommandVariant::Dysymtab(d) => {
                dysymtab = Some(MachDysymtab {
                    ilocalsym: d.ilocalsym,
                    nlocalsym: d.nlocalsym,
                    iextdefsym: d.iextdefsym,
                    nextdefsym: d.nextdefsym,
                    iundefsym: d.iundefsym,
                    nundefsym: d.nundefsym,
                    tocoff: d.tocoff,
                    ntoc: d.ntoc,
                    modtaboff: d.modtaboff,
                    nmodtab: d.nmodtab,
                    extrefsymoff: d.extrefsymoff,
                    nextrefsyms: d.nextrefsyms,
                    indirectsymoff: d.indirectsymoff,
                    nindirectsyms: d.nindirectsyms,
                    extreloff: d.extreloff,
                    nextrel: d.nextrel,
                    locreloff: d.locreloff,
                    nlocrel: d.nlocrel,
                });
            }
            CommandVariant::DyldInfo(d) | CommandVariant::DyldInfoOnly(d) => {
                dyld_info = Some(MachDyldInfo {
                    rebase_off: d.rebase_off,
                    rebase_size: d.rebase_size,
                    bind_off: d.bind_off,
                    bind_size: d.bind_size,
                    weak_bind_off: d.weak_bind_off,
                    weak_bind_size: d.weak_bind_size,
                    lazy_bind_off: d.lazy_bind_off,
                    lazy_bind_size: d.lazy_bind_size,
                    export_off: d.export_off,
                    export_size: d.export_size,
                });
            }
            CommandVariant::VersionMinMacosx(v)
            | CommandVariant::VersionMinIphoneos(v)
            | CommandVariant::VersionMinTvos(v)
            | CommandVariant::VersionMinWatchos(v) => {
                version_min = Some(MachVersionMin {
                    platform: version_min_platform_name(cmd_val),
                    version: decode_version(v.version),
                    sdk: decode_version(v.sdk),
                });
            }
            CommandVariant::BuildVersion(b) => {
                build_version = Some(MachBuildVersion {
                    platform: build_platform_name(b.platform),
                    minos: decode_version(b.minos),
                    sdk: decode_version(b.sdk),
                    ntools: b.ntools,
                });
            }
            CommandVariant::Rpath(r) => {
                if let Ok(path) = lc_str_to_string(data, lc.offset, r.path) {
                    rpaths.push(MachRpath { path });
                }
            }
            CommandVariant::SourceVersion(s) => {
                source_version = Some(MachSourceVersion {
                    version: decode_source_version(s.version),
                });
            }
            CommandVariant::LoadDylinker(d) | CommandVariant::IdDylinker(d) => {
                if let Ok(name) = lc_str_to_string(data, lc.offset, d.name) {
                    dylinker = Some(MachDylinker { name });
                }
            }
            CommandVariant::CodeSignature(l) => {
                code_signature_raw = Some((l.dataoff, l.datasize));
                linkedit_data.push(MachLinkeditData {
                    cmd: cmd_name.clone(),
                    dataoff: l.dataoff,
                    datasize: l.datasize,
                });
            }
            CommandVariant::FunctionStarts(l) => {
                function_starts_raw = Some((l.dataoff, l.datasize));
                linkedit_data.push(MachLinkeditData {
                    cmd: cmd_name.clone(),
                    dataoff: l.dataoff,
                    datasize: l.datasize,
                });
            }
            CommandVariant::DataInCode(l) => {
                data_in_code_raw = Some((l.dataoff, l.datasize));
                linkedit_data.push(MachLinkeditData {
                    cmd: cmd_name.clone(),
                    dataoff: l.dataoff,
                    datasize: l.datasize,
                });
            }
            CommandVariant::DyldChainedFixups(l) => {
                dyld_chained_fixups_raw = Some((l.dataoff, l.datasize));
                linkedit_data.push(MachLinkeditData {
                    cmd: cmd_name.clone(),
                    dataoff: l.dataoff,
                    datasize: l.datasize,
                });
            }
            CommandVariant::DyldExportsTrie(l) => {
                dyld_exports_trie_raw = Some((l.dataoff, l.datasize));
                linkedit_data.push(MachLinkeditData {
                    cmd: cmd_name.clone(),
                    dataoff: l.dataoff,
                    datasize: l.datasize,
                });
            }
            CommandVariant::SegmentSplitInfo(l)
            | CommandVariant::DylibCodeSignDrs(l)
            | CommandVariant::LinkerOption(l)
            | CommandVariant::LinkerOptimizationHint(l) => {
                linkedit_data.push(MachLinkeditData {
                    cmd: cmd_name.clone(),
                    dataoff: l.dataoff,
                    datasize: l.datasize,
                });
            }
            CommandVariant::EncryptionInfo32(e) => {
                encryption_info = Some(MachEncryptionInfo {
                    cryptoff: e.cryptoff,
                    cryptsize: e.cryptsize,
                    cryptid: e.cryptid,
                });
            }
            CommandVariant::EncryptionInfo64(e) => {
                encryption_info = Some(MachEncryptionInfo {
                    cryptoff: e.cryptoff,
                    cryptsize: e.cryptsize,
                    cryptid: e.cryptid,
                });
            }
            CommandVariant::Main(m) => {
                entry_point = Some(MachEntryPoint {
                    entryoff: m.entryoff,
                    stacksize: m.stacksize,
                });
            }
            _ => {
                // Handle LC_UNIXTHREAD manually (goblin doesn't expose it as a variant).
                if cmd_val == goblin::mach::load_command::LC_UNIXTHREAD && macho.entry != 0 {
                    unix_thread_entry = Some(MachUnixThread {
                        cputype: cputype.clone(),
                        entry: macho.entry,
                    });
                }
                // Handle LC_LOADFVMLIB and LC_IDFVMLIB manually (old NeXTSTEP format).
                if cmd_val == goblin::mach::load_command::LC_LOADFVMLIB
                    || cmd_val == goblin::mach::load_command::LC_IDFVMLIB
                {
                    let lc_off = lc.offset;
                    if lc_off + 20 <= data.len() {
                        let name_off = u32::from_le_bytes([
                            data[lc_off + 8],
                            data[lc_off + 9],
                            data[lc_off + 10],
                            data[lc_off + 11],
                        ]) as usize;
                        let minor_version = u32::from_le_bytes([
                            data[lc_off + 12],
                            data[lc_off + 13],
                            data[lc_off + 14],
                            data[lc_off + 15],
                        ]);
                        let header_addr = u32::from_le_bytes([
                            data[lc_off + 16],
                            data[lc_off + 17],
                            data[lc_off + 18],
                            data[lc_off + 19],
                        ]);
                        let name_abs = lc_off + name_off;
                        if name_abs < data.len() {
                            let name_end =
                                data[name_abs..].iter().position(|&b| b == 0).unwrap_or(0);
                            let name =
                                String::from_utf8_lossy(&data[name_abs..name_abs + name_end])
                                    .to_string();
                            if cmd_val == goblin::mach::load_command::LC_LOADFVMLIB {
                                fvmlibs.push(MachFvmlib {
                                    name,
                                    minor_version,
                                    header_addr,
                                });
                            } else {
                                id_fvmlibs.push(MachIdFvmlib {
                                    name,
                                    minor_version,
                                    header_addr,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Parse segments from the Segments collection.
    let mut segments = Vec::new();
    let mut sections = Vec::new();

    for seg in macho.segments.iter() {
        let seg_name = seg.name().unwrap_or("").to_string();
        segments.push(MachSegment {
            name: seg_name.clone(),
            vmaddr: seg.vmaddr,
            vmsize: seg.vmsize,
            fileoff: seg.fileoff,
            filesize: seg.filesize,
            maxprot: prot_string(seg.maxprot),
            initprot: prot_string(seg.initprot),
            nsects: seg.nsects,
            flags: seg.flags,
        });

        // Extract sections from this segment.
        if let Ok(secs) = seg.sections() {
            for (section, _data) in secs {
                sections.push(MachSection {
                    sectname: bytes_to_string(&section.sectname),
                    segname: bytes_to_string(&section.segname),
                    addr: section.addr,
                    size: section.size,
                    offset: section.offset,
                    align: section.align,
                    reloff: section.reloff,
                    nreloc: section.nreloc,
                    flags: section.flags,
                });
            }
        }
    }

    // Entry point.
    let entry = if macho.entry != 0 {
        Some(macho.entry)
    } else {
        None
    };

    // Parse function starts (ULEB128 encoded deltas from image base).
    let function_starts = function_starts_raw
        .and_then(|(off, size)| parse_function_starts(data, off as usize, size as usize, &segments))
        .unwrap_or_default();

    // Parse data in code entries.
    let data_in_code = data_in_code_raw
        .and_then(|(off, size)| parse_data_in_code(data, off as usize, size as usize))
        .unwrap_or_default();

    // Parse code signature SuperBlob.
    let (code_signature, superblob) = code_signature_raw
        .and_then(|(off, size)| parse_code_signature(data, off as usize, size as usize))
        .unwrap_or((None, None));

    // Parse dyld chained fixups header.
    let dyld_chained_fixups = dyld_chained_fixups_raw
        .and_then(|(off, size)| parse_dyld_chained_fixups(data, off as usize, size as usize))
        .map(|(dataoff, datasize, fv, so, ib)| MachDyldChainedFixups {
            dataoff,
            datasize,
            fixups_version: fv,
            starts_offset: so,
            image_base: ib,
        });

    // Parse dyld exports trie.
    let dyld_exports_trie = dyld_exports_trie_raw
        .map(|(off, size)| parse_dyld_exports_trie(data, off as usize, size as usize));

    // Parse string table from symtab.
    let string_table = symtab
        .as_ref()
        .and_then(|s| parse_string_table(data, s.stroff as usize, s.strsize as usize))
        .unwrap_or_default();

    Some(MachView {
        load_commands,
        segments,
        sections,
        libraries,
        is64,
        magic: header.magic,
        cputype,
        cpusubtype: header.cpusubtype,
        filetype,
        ncmds: header.ncmds as u32,
        sizeofcmds: header.sizeofcmds,
        entry,
        uuid,
        symtab,
        dysymtab,
        dyld_info,
        version_min,
        build_version,
        rpaths,
        source_version,
        dylinker,
        linkedit_data,
        encryption_info,
        entry_point,
        weak_libraries,
        id_library,
        fvmlibs,
        id_fvmlibs,
        function_starts,
        data_in_code,
        code_signature,
        superblob,
        unix_thread: unix_thread_entry,
        dyld_chained_fixups,
        dyld_exports_trie,
        string_table,
    })
}

/// Parse function starts from ULEB128 encoded data.
/// Each entry is a delta from the previous address (or from the segment start for the first).
fn parse_function_starts(
    data: &[u8],
    off: usize,
    size: usize,
    segments: &[MachSegment],
) -> Option<Vec<MachFunctionStart>> {
    if off + size > data.len() || size == 0 {
        return None;
    }
    let raw = &data[off..off + size];
    // Find the base address from the first text segment.
    let base = segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .map(|s| s.vmaddr)
        .unwrap_or(0);

    let mut result = Vec::new();
    let mut current = base;
    let mut pos = 0;
    while pos < raw.len() {
        let (delta, consumed) = read_uleb128(&raw[pos..]);
        if consumed == 0 {
            break;
        }
        if delta != 0 {
            current += delta;
            result.push(MachFunctionStart { address: current });
        }
        pos += consumed;
    }
    // Limit to 10000 entries.
    result.truncate(10000);
    Some(result)
}

/// Read a ULEB128 value from a byte slice. Returns (value, bytes_consumed).
fn read_uleb128(data: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &b) in data.iter().enumerate() {
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return (result, i + 1);
        }
        shift += 7;
        if shift >= 64 {
            return (0, 0); // Overflow
        }
    }
    (0, 0) // Incomplete
}

/// Parse data in code entries (each entry is 8 bytes: offset(4) + length(2) + kind(2)).
fn parse_data_in_code(data: &[u8], off: usize, size: usize) -> Option<Vec<MachDataInCodeEntry>> {
    if off + size > data.len() || size == 0 {
        return None;
    }
    let raw = &data[off..off + size];
    let mut result = Vec::new();
    for chunk in raw.chunks_exact(8) {
        let offset = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let length = u16::from_le_bytes([chunk[4], chunk[5]]);
        let kind = u16::from_le_bytes([chunk[6], chunk[7]]);
        result.push(MachDataInCodeEntry {
            offset,
            length,
            kind,
            kind_name: data_in_code_kind_name(kind),
        });
    }
    Some(result)
}

/// Get data-in-code kind name.
fn data_in_code_kind_name(kind: u16) -> String {
    match kind {
        0 => "DATA".into(),
        1 => "JUMP_TABLE(8)".into(),
        2 => "JUMP_TABLE(4)".into(),
        3 => "JUMP_TABLE(2)".into(),
        4 => "SYMBOL_TRAMPOLINES".into(),
        _ => format!("Unknown(0x{:04x})", kind),
    }
}

/// Parse code signature SuperBlob from raw data.
/// Returns (code_signature, superblob) tuple.
fn parse_code_signature(
    data: &[u8],
    off: usize,
    size: usize,
) -> Option<(Option<MachCodeSignature>, Option<MachSuperBlob>)> {
    if off + 12 > data.len() || size < 12 {
        return None;
    }
    let raw = &data[off..off + std::cmp::min(size, data.len() - off)];
    let magic = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let length = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let count = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);

    // Parse blob index entries (each 8 bytes: type(4) + offset(4)).
    let mut slots = Vec::new();
    let mut entries = Vec::new();
    for i in 0..count as usize {
        let entry_off = 12 + i * 8;
        if entry_off + 8 > raw.len() {
            break;
        }
        let type_val = u32::from_le_bytes([
            raw[entry_off],
            raw[entry_off + 1],
            raw[entry_off + 2],
            raw[entry_off + 3],
        ]);
        let blob_off = u32::from_le_bytes([
            raw[entry_off + 4],
            raw[entry_off + 5],
            raw[entry_off + 6],
            raw[entry_off + 7],
        ]);
        let type_name = code_slot_type_name(type_val);
        slots.push(MachCodeSlot {
            type_val,
            type_name: type_name.clone(),
            offset: blob_off,
        });
        entries.push(MachSuperBlobEntry {
            type_val,
            type_name,
            offset: blob_off,
        });
    }

    let cs = Some(MachCodeSignature {
        magic,
        length,
        count,
        slots,
    });
    let sb = Some(MachSuperBlob {
        magic,
        length,
        count,
        entries,
    });
    Some((cs, sb))
}

/// Get code slot type name.
fn code_slot_type_name(type_val: u32) -> String {
    match type_val {
        0 => "CODE_DIRECTORY".into(),
        2 => "REQUIREMENTS".into(),
        3 => "REQUIREMENTS_SET".into(),
        4 => "ENTITLEMENTS".into(),
        5 => "ALTERNATE_CODE_DIRECTORY".into(),
        6 => "SIGNATURE".into(),
        0xfade0c01 => "CSSLOT_CODEDIRECTORY".into(),
        0xfade0c02 => "CSSLOT_REQUIREMENTS".into(),
        0xfade0c03 => "CSSLOT_REQUIREMENTS_SET".into(),
        0xfade0c05 => "CSSLOT_ALTERNATE_CODEDIRECTORY".into(),
        0xfade0c06 => "CSSLOT_SIGNATURE".into(),
        _ => format!("0x{:08x}", type_val),
    }
}

/// Parse dyld chained fixups header from raw data.
/// Returns (dataoff, datasize, fixups_version, starts_offset, image_base).
fn parse_dyld_chained_fixups(
    data: &[u8],
    off: usize,
    size: usize,
) -> Option<(u32, u32, u32, u32, u64)> {
    if off + size > data.len() || size < 20 {
        return None;
    }
    let raw = &data[off..off + size];
    // header: fixups_version(4) + starts_offset(4) + starts_count(4) + image_base(8)
    let fixups_version = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let starts_offset = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let _starts_count = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let image_base = u64::from_le_bytes([
        raw[12], raw[13], raw[14], raw[15], raw[16], raw[17], raw[18], raw[19],
    ]);
    Some((
        off as u32,
        size as u32,
        fixups_version,
        starts_offset,
        image_base,
    ))
}

/// Parse dyld exports trie from raw data.
/// Counts the number of exported symbols by walking the trie.
fn parse_dyld_exports_trie(data: &[u8], off: usize, size: usize) -> MachDyldExportsTrie {
    let export_count = if off + size <= data.len() && size > 0 {
        let raw = &data[off..off + size];
        count_exports_in_trie(raw)
    } else {
        0
    };
    MachDyldExportsTrie {
        dataoff: off as u32,
        datasize: size as u32,
        export_count,
    }
}

/// Count exported symbols in a trie by walking all terminal nodes.
fn count_exports_in_trie(trie: &[u8]) -> u32 {
    let mut count = 0;
    walk_trie(trie, 0, &mut count);
    count
}

/// Recursively walk the exports trie to count terminal nodes.
fn walk_trie(trie: &[u8], pos: usize, count: &mut u32) {
    if pos >= trie.len() {
        return;
    }
    // Read terminal size (ULEB128).
    let (term_size, consumed) = read_uleb128(&trie[pos..]);
    let term_end = pos + consumed + term_size as usize;
    if term_size > 0 {
        *count += 1;
    }
    // Read child count.
    let child_pos = term_end;
    if child_pos >= trie.len() {
        return;
    }
    let (child_count, cc_consumed) = read_uleb128(&trie[child_pos..]);
    let mut p = child_pos + cc_consumed;
    for _ in 0..child_count {
        if p >= trie.len() {
            break;
        }
        // Skip edge string (null-terminated).
        while p < trie.len() && trie[p] != 0 {
            p += 1;
        }
        p += 1; // Skip null terminator.
        // Read child offset (ULEB128).
        let (child_off, off_consumed) = read_uleb128(&trie[p..]);
        p += off_consumed;
        if child_off > 0 && (child_off as usize) < trie.len() {
            walk_trie(trie, child_off as usize, count);
        }
    }
}

/// Parse string table entries from raw data.
fn parse_string_table(data: &[u8], off: usize, size: usize) -> Option<Vec<MachStringTableEntry>> {
    if off + size > data.len() || size == 0 {
        return None;
    }
    let raw = &data[off..off + size];
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < raw.len() {
        let end = raw[pos..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(raw.len() - pos);
        if end > 0 {
            let value = String::from_utf8_lossy(&raw[pos..pos + end]).to_string();
            result.push(MachStringTableEntry {
                offset: pos as u32,
                value,
            });
        }
        pos += end + 1;
    }
    // Limit to 5000 entries.
    result.truncate(5000);
    Some(result)
}

/// Convert a byte array (C string) to a Rust string, trimming null bytes.
fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string()
}

/// Read an LcStr (a u32 offset) from the load command data.
///
/// `lc_offset` is the offset of the load command in the file.
/// `name_offset` is the LcStr value (offset relative to the load command start).
fn lc_str_to_string(data: &[u8], lc_offset: usize, name_offset: u32) -> Result<String, ()> {
    // The offset in LcStr is relative to the start of the load command.
    let abs_offset = lc_offset + name_offset as usize;
    if abs_offset >= data.len() {
        return Err(());
    }
    let rest = &data[abs_offset..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Ok(String::from_utf8_lossy(&rest[..end]).to_string())
}

/// Convert CPU type to human-readable name.
fn macho_cputype_name(cputype: u32) -> String {
    match cputype {
        0x07 => "x86".to_string(),
        0x01000007 => "x86_64".to_string(),
        0x0c => "ARM".to_string(),
        0x0100000c => "ARM64".to_string(),
        0x12 => "PPC".to_string(),
        0x01000012 => "PPC64".to_string(),
        _ => format!("0x{:08x}", cputype),
    }
}

/// Convert file type to human-readable name.
fn macho_filetype_name(filetype: u32) -> String {
    match filetype {
        0x01 => "OBJECT".to_string(),
        0x02 => "EXECUTE".to_string(),
        0x04 => "FVMLIB".to_string(),
        0x05 => "CORE".to_string(),
        0x06 => "PRELOAD".to_string(),
        0x07 => "DYLIB".to_string(),
        0x08 => "DYLINKER".to_string(),
        0x09 => "BUNDLE".to_string(),
        0x0a => "DSYM".to_string(),
        _ => format!("0x{:08x}", filetype),
    }
}

/// Convert load command type to name.
fn lc_name(cmd: u32) -> String {
    use goblin::mach::load_command::*;
    match cmd {
        LC_SEGMENT => "LC_SEGMENT".to_string(),
        LC_SYMTAB => "LC_SYMTAB".to_string(),
        LC_SYMSEG => "LC_SYMSEG".to_string(),
        LC_THREAD => "LC_THREAD".to_string(),
        LC_UNIXTHREAD => "LC_UNIXTHREAD".to_string(),
        LC_LOADFVMLIB => "LC_LOADFVMLIB".to_string(),
        LC_IDFVMLIB => "LC_IDFVMLIB".to_string(),
        LC_IDENT => "LC_IDENT".to_string(),
        LC_FVMFILE => "LC_FVMFILE".to_string(),
        LC_PREPAGE => "LC_PREPAGE".to_string(),
        LC_DYSYMTAB => "LC_DYSYMTAB".to_string(),
        LC_LOAD_DYLIB => "LC_LOAD_DYLIB".to_string(),
        LC_ID_DYLIB => "LC_ID_DYLIB".to_string(),
        LC_LOAD_DYLINKER => "LC_LOAD_DYLINKER".to_string(),
        LC_ID_DYLINKER => "LC_ID_DYLINKER".to_string(),
        LC_PREBOUND_DYLIB => "LC_PREBOUND_DYLIB".to_string(),
        LC_ROUTINES => "LC_ROUTINES".to_string(),
        LC_SUB_FRAMEWORK => "LC_SUB_FRAMEWORK".to_string(),
        LC_SUB_UMBRELLA => "LC_SUB_UMBRELLA".to_string(),
        LC_SUB_CLIENT => "LC_SUB_CLIENT".to_string(),
        LC_SUB_LIBRARY => "LC_SUB_LIBRARY".to_string(),
        LC_TWOLEVEL_HINTS => "LC_TWOLEVEL_HINTS".to_string(),
        LC_PREBIND_CKSUM => "LC_PREBIND_CKSUM".to_string(),
        LC_SEGMENT_64 => "LC_SEGMENT_64".to_string(),
        LC_ROUTINES_64 => "LC_ROUTINES_64".to_string(),
        LC_UUID => "LC_UUID".to_string(),
        LC_RPATH => "LC_RPATH".to_string(),
        LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE".to_string(),
        LC_SEGMENT_SPLIT_INFO => "LC_SEGMENT_SPLIT_INFO".to_string(),
        LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB".to_string(),
        LC_LAZY_LOAD_DYLIB => "LC_LAZY_LOAD_DYLIB".to_string(),
        LC_ENCRYPTION_INFO => "LC_ENCRYPTION_INFO".to_string(),
        LC_DYLD_INFO => "LC_DYLD_INFO".to_string(),
        LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY".to_string(),
        LC_LOAD_UPWARD_DYLIB => "LC_LOAD_UPWARD_DYLIB".to_string(),
        LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX".to_string(),
        LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS".to_string(),
        LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS".to_string(),
        LC_DYLD_ENVIRONMENT => "LC_DYLD_ENVIRONMENT".to_string(),
        LC_MAIN => "LC_MAIN".to_string(),
        LC_DATA_IN_CODE => "LC_DATA_IN_CODE".to_string(),
        LC_SOURCE_VERSION => "LC_SOURCE_VERSION".to_string(),
        LC_DYLIB_CODE_SIGN_DRS => "LC_DYLIB_CODE_SIGN_DRS".to_string(),
        LC_ENCRYPTION_INFO_64 => "LC_ENCRYPTION_INFO_64".to_string(),
        LC_LINKER_OPTION => "LC_LINKER_OPTION".to_string(),
        LC_LINKER_OPTIMIZATION_HINT => "LC_LINKER_OPTIMIZATION_HINT".to_string(),
        LC_VERSION_MIN_TVOS => "LC_VERSION_MIN_TVOS".to_string(),
        LC_VERSION_MIN_WATCHOS => "LC_VERSION_MIN_WATCHOS".to_string(),
        LC_NOTE => "LC_NOTE".to_string(),
        LC_BUILD_VERSION => "LC_BUILD_VERSION".to_string(),
        LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE".to_string(),
        LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS".to_string(),
        LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB".to_string(),
        _ => format!("0x{:08x}", cmd),
    }
}

/// Extract additional info from a CommandVariant (segment name, library name, etc.).
fn lc_info(variant: &CommandVariant) -> String {
    match variant {
        CommandVariant::Segment32(s) => bytes_to_string(&s.segname),
        CommandVariant::Segment64(s) => bytes_to_string(&s.segname),
        _ => String::new(),
    }
}

/// Format VM protection as string (rwx).
fn prot_string(prot: u32) -> String {
    let mut s = String::new();
    if prot & 0x01 != 0 {
        s.push('r');
    } else {
        s.push('-');
    }
    if prot & 0x02 != 0 {
        s.push('w');
    } else {
        s.push('-');
    }
    if prot & 0x04 != 0 {
        s.push('x');
    } else {
        s.push('-');
    }
    s
}

/// Format a 16-byte UUID as a standard UUID string.
fn format_uuid(uuid: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15]
    )
}

/// Decode a Mach-O packed version (xxxx.yy.zz) to X.Y.Z string.
fn decode_version(v: u32) -> String {
    let major = (v >> 16) & 0xffff;
    let minor = (v >> 8) & 0xff;
    let patch = v & 0xff;
    format!("{}.{}.{}", major, minor, patch)
}

/// Decode a Mach-O source version (A.B.C.D.E packed as a24.b10.c10.d10.e10).
fn decode_source_version(v: u64) -> String {
    let a = (v >> 40) & 0xffffff;
    let b = (v >> 30) & 0x3ff;
    let c = (v >> 20) & 0x3ff;
    let d = (v >> 10) & 0x3ff;
    let e = v & 0x3ff;
    format!("{}.{}.{}.{}.{}", a, b, c, d, e)
}

/// Get platform name for LC_VERSION_MIN_* commands.
fn version_min_platform_name(cmd: u32) -> String {
    match cmd {
        0x24 => "macosx".into(),
        0x25 => "iphoneos".into(),
        0x2f => "tvos".into(),
        0x30 => "watchos".into(),
        _ => format!("0x{:08x}", cmd),
    }
}

/// Get platform name for LC_BUILD_VERSION platform field.
fn build_platform_name(platform: u32) -> String {
    match platform {
        1 => "macOS".into(),
        2 => "iOS".into(),
        3 => "tvOS".into(),
        4 => "watchOS".into(),
        5 => "bridgeOS".into(),
        6 => "macCatalyst".into(),
        7 => "iOS Simulator".into(),
        8 => "tvOS Simulator".into(),
        9 => "watchOS Simulator".into(),
        10 => "driverKit".into(),
        _ => format!("0x{:08x}", platform),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_macho_view_not_macho() {
        let data = vec![0u8; 64];
        assert!(parse_macho_view(&data).is_none());
    }

    #[test]
    fn test_prot_string() {
        assert_eq!(prot_string(0x07), "rwx");
        assert_eq!(prot_string(0x05), "r-x");
        assert_eq!(prot_string(0x03), "rw-");
        assert_eq!(prot_string(0x00), "---");
    }

    #[test]
    fn test_macho_cputype_name() {
        assert_eq!(macho_cputype_name(0x01000007), "x86_64");
        assert_eq!(macho_cputype_name(0x0100000c), "ARM64");
    }

    #[test]
    fn test_bytes_to_string() {
        assert_eq!(bytes_to_string(b"__TEXT\0\0\0"), "__TEXT");
        assert_eq!(bytes_to_string(b"hello"), "hello");
        assert_eq!(bytes_to_string(b""), "");
    }

    #[test]
    fn test_read_uleb128() {
        // Single byte (0 = value 0).
        assert_eq!(read_uleb128(&[0]), (0, 1));
        // Single byte (7 = value 7).
        assert_eq!(read_uleb128(&[7]), (7, 1));
        // Two bytes: 0x80 | 0x05, 0x01 → value = (1 << 7) | 5 = 133.
        assert_eq!(read_uleb128(&[0x85, 0x01]), (133, 2));
        // Empty data.
        assert_eq!(read_uleb128(&[]), (0, 0));
    }

    #[test]
    fn test_data_in_code_kind_name() {
        assert_eq!(data_in_code_kind_name(0), "DATA");
        assert_eq!(data_in_code_kind_name(1), "JUMP_TABLE(8)");
        assert_eq!(data_in_code_kind_name(4), "SYMBOL_TRAMPOLINES");
        assert!(data_in_code_kind_name(99).contains("Unknown"));
    }

    #[test]
    fn test_code_slot_type_name() {
        assert_eq!(code_slot_type_name(0), "CODE_DIRECTORY");
        assert_eq!(code_slot_type_name(2), "REQUIREMENTS");
        assert_eq!(code_slot_type_name(6), "SIGNATURE");
    }

    #[test]
    fn test_count_exports_in_trie() {
        // Empty trie → 0 exports.
        assert_eq!(count_exports_in_trie(&[]), 0);
        // Single terminal node: terminal_size=1, no children.
        let trie = [0x01, 0x00];
        assert_eq!(count_exports_in_trie(&trie), 1);
    }

    #[test]
    fn test_parse_string_table() {
        let data = b"\0hello\0world\0".to_vec();
        let entries = parse_string_table(&data, 0, data.len()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].value, "hello");
        assert_eq!(entries[0].offset, 1);
        assert_eq!(entries[1].value, "world");
        assert_eq!(entries[1].offset, 7);
    }
}

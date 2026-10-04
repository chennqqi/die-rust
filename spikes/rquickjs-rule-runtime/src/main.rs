#![recursion_limit = "256"]

mod tracking_allocator;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use die_signature_parser_spike::{
    Endian, FileType, MemoryMap, MemoryRecord, NATIVE_CHECKPOINT_INTERVAL, Pattern,
};

use rquickjs::{
    CatchResultExt, Context, Error, Function, Object, Runtime, context::EvalOptions, function::Opt,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracking_allocator::{TrackingAllocatorStats, TrackingLimitAllocator};

const HOST_SHIM: &[u8] = br#"
    var included = [];
    function meta(type, name) {
        globalThis.metaType = type;
        globalThis.metaName = name;
    }
    function includeScript(name) { included.push(name); }
    var __hostStub;
    __hostStub = new Proxy(function () { return __hostStub; }, {
        apply: function () { return __hostStub; },
        get: function (_target, property) {
            if (property === "length") return 0;
            if (property === Symbol.toPrimitive) return function () { return 0; };
            return __hostStub;
        },
        set: function () { return true; }
    });
    var APK = __hostStub, Amiga = __hostStub, Archive = __hostStub;
    var AtariST = __hostStub, Binary = __hostStub, CFBF = __hostStub;
    var COM = __hostStub, DEX = __hostStub, DOS16M = __hostStub;
    var DOS4G = __hostStub, ELF = __hostStub, IPA = __hostStub;
    var ISO9660 = __hostStub, Image = __hostStub, JAR = __hostStub;
    var JavaClass = __hostStub, Jpeg = __hostStub, LE = __hostStub;
    var LX = __hostStub, MACH = __hostStub, MACHOFAT = __hostStub;
    var MSDOS = __hostStub, NE = __hostStub, NPM = __hostStub;
    var PDF = __hostStub, PE = __hostStub, PNG = __hostStub;
    var PYC = __hostStub, RAR = __hostStub, ZIP = __hostStub;
    var bBorlandC = 0;
"#;

const HOST_FALLBACK_SHIM: &[u8] = br#"
    globalThis.__fallbackCalls = [];
    function __makeFallback(path) {
        var stub;
        stub = new Proxy(function () {
            __fallbackCalls.push(path);
            return stub;
        }, {
            get: function (_target, property) {
                if (property === Symbol.toPrimitive) return function () { return 0; };
                return __makeFallback(path + "." + String(property));
            }
        });
        return stub;
    }
    Binary = new Proxy(Binary, {
        get: function (target, property) {
            if (property in target) return target[property];
            return __makeFallback("Binary." + String(property));
        }
    });
    X = Binary;
    Util = new Proxy(Util, {
        get: function (target, property) {
            if (property in target) return target[property];
            return __makeFallback("Util." + String(property));
        }
    });
"#;

const DIAGNOSTIC_HOST_FALLBACK_SHIM: &[u8] = br#"
    globalThis.__fallbackCalls = [];
    globalThis.__fallbackTotal = 0;
    function __makeDiagnosticFallback(path) {
        var stub;
        stub = new Proxy(function () {
            __fallbackTotal++;
            if (__fallbackCalls.length < 256) __fallbackCalls.push(path);
            return stub;
        }, {
            get: function (_target, property) {
                if (property === Symbol.toPrimitive) return function () { return 0; };
                return __makeDiagnosticFallback(path + "." + String(property));
            }
        });
        return stub;
    }
    Binary = new Proxy(Binary, {
        get: function (target, property) {
            if (property in target) return target[property];
            return __makeDiagnosticFallback("Binary." + String(property));
        }
    });
    X = Binary;
    Util = new Proxy(Util, {
        get: function (target, property) {
            if (property in target) return target[property];
            return __makeDiagnosticFallback("Util." + String(property));
        }
    });
"#;

const NINTENDO_RULE_SUFFIX: &str = "Binary/format_bin.Nintendo-certified-file.1.sg";
const NINTENDO_RULE_BYTES: usize = 1_994;
const NINTENDO_RULE_SHA256: &str =
    "1f7485b8b0c9c211932fdcc31529ea37588c176e46a1ff06230fc376df5ad0f5";
const NINTENDO_VAR_DECLARATION: &[u8] = b"        var tp, e;";
const NINTENDO_COMPAT_DECLARATION: &[u8] = b"        var     e;";
const AUDIO_RULE_SUFFIX: &str = "Binary/audio.1.sg";
const AUDIO_RULE_BYTES: usize = 603_640;
const AUDIO_RULE_SHA256: &str = "998c2476ddc07a88c83598192faf1ffb4b35d60c4b2d6c1fafcfa4b153a9892f";
const AUDIO_CONST_DEBUG_DECLARATION: &[u8] = b"const debug = 0;";
const AUDIO_COMPAT_DEBUG_DECLARATION: &[u8] = b"var   debug = 0;";
const EXTENSIONS_RULE_SUFFIX: &str = "Binary/__MiniExtensionsHeuristic_By_DosX.7.sg";
const EXTENSIONS_RULE_BYTES: usize = 21_958;
const EXTENSIONS_RULE_SHA256: &str =
    "e8eac22087d7814bdb6c80fd3626b1dbad721c16a5ce4ab290b9eedcc165c12d";
const EXTENSIONS_CONST_DETECT_DECLARATION: &[u8] = b"const detect = main;";
const EXTENSIONS_COMPAT_DETECT_DECLARATION: &[u8] = b"var   detect = main;";
const UPSTREAM_COMMIT: &str = "74eaf505c250ab47e709024e9dc41657cd8f2254";
const XSCANENGINE_COMMIT: &str = "dfe4a419e4f491bb23688ba03c5a5bf39e34da83";
const RULES_COMMIT: &str = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6";
const LINUX_QT5_BINARY_ORDER_SHA256: &str =
    "27138d68ed788dd2609b7c533fecf540593fa2e4ddb7195adc26b1a9ff0e1ff3";
const INCLUDE_GRAPH_SIZING_SHA256: &str =
    "b957d8d672b1cf3c746180661918e16954f3428a57941b7783d82e693f8aede1";
const NINTENDO_CORPUS_MANIFEST_SHA256: &str =
    "eac3ad62c7f21d5112ee1ca73fbb6cc4e5306b6004357aeaf86144fa3ef51a03";
const NINTENDO_BASELINE_SHA256: &str =
    "683d2d85abc7053321785f53224842cd2047427d4d8ce6d591248453e2f29503";
const BINARY_SIGNATURE_COUNT: usize = 292;
const TRACKED_RULE_RUNTIME_LIMIT_BYTES: usize = 32 * 1024 * 1024;
const PE_RULE_SUFFIX: &str = "PE/compiler_Cygwin32.4.sg";
const PE_RULE_BYTES: usize = 240;
const PE_RULE_SHA256: &str = "de563e3333c54b966efb7aa3d678acd56ca5fa9b83a7b8356b3a4e71e47dc4cd";
const PE_FIXTURE_SHA256: &str = "102eacfa044f838fb51992c65a2cf7e90cd346a493bffc77b08f4ec02f5159e1";
const PE_QT5_BASELINE_SHA256: &str =
    "645fc9b13d500f1eda3203df90439cb5234f8eb850d820de119962b4778be03a";
const ELF_RULE_SUFFIX: &str = "ELF/protector_Burneye.2.sg";
const ELF_RULE_BYTES: usize = 282;
const ELF_RULE_SHA256: &str = "35461b495f056d98de9af44eda91df3c6412d22555b182834af9b6a68842d44c";
const ELF_FIXTURE_SHA256: &str = "b3547482b2013a993a36262860f82dbda69b1588898cd2a8020124c6b9aad5b4";
const ELF_QT5_BASELINE_SHA256: &str =
    "edf2d32cde44c8fcf010190e48cc33076dcb1dc0ea81830996eeab7a57f89410";
const MACHO_RULE_SUFFIX: &str = "MACH/compiler_Rust.4.sg";
const MACHO_RULE_BYTES: usize = 1_331;
const MACHO_RULE_SHA256: &str = "70fec4e86cd1a1a5b3e7663521cb45e3c4ce85d1e1f8ed80cf1d80f6d8268d84";
const MACHO_FIXTURE_SHA256: &str =
    "d1e691bcd72942916dcabb75177f6e411b7d78483bdd0d1635c4a0c89619188d";
const MACHO_QT5_BASELINE_SHA256: &str =
    "ec6b9f373d598f41cf7d51550eae020307c2a41b27f569135c022aeda54045f4";
const DEX_RULE_SUFFIX: &str = "DEX/protector_QDBH.2.sg";
const DEX_RULE_BYTES: usize = 273;
const DEX_RULE_SHA256: &str = "5280ae0425f47c03ca037002b29964fe59eb898e871a00ad266475856f0e7ba7";
const DEX_FIXTURE_SHA256: &str = "7c312742257d365a49f399036e9ce62784e819f13a27831acfadd7625025cbc8";
const DEX_QT5_BASELINE_SHA256: &str =
    "881988e4c85686489fcf05235b686656ea3dcfaa487cbd7b36259f98614b7bf5";
const XDEX_COMMIT: &str = "035c61966d3a9018edf80cd0013083ee32626e71";
const APK_RULE_SUFFIX: &str = "APK/protector_QDBH.2.sg";
const APK_RULE_BYTES: usize = 283;
const APK_RULE_SHA256: &str = "cc20faadf1aec677679151a1997ea95184b265db2dbb1d4fcf56f0b62cead752";
const APK_FIXTURE_SHA256: &str = "531112ec3a4af5a9736c11774c7df6c26819165a6962b5a168bfd70f47c5ee94";
const APK_QT5_BASELINE_SHA256: &str =
    "41d75dae86b0f4a57b0159a3cc92fa0ad4cae1ca1117bc5620da68faa98fc00c";
const ARCHIVE_RULE_SUFFIX: &str = "Archive/_Archive.0.sg";
const ARCHIVE_RULE_BYTES: usize = 421;
const ARCHIVE_RULE_SHA256: &str =
    "97202e19118514bcd33ef40c2dea69822249406092eddcb61f56e3410278ec86";
const ARCHIVE_FIXTURE_SHA256: &str =
    "04ee27fe5741ad9b65098722213d67058f748416e7075256dacf26a3be4d6b6b";
const ARCHIVE_QT5_BASELINE_SHA256: &str =
    "92d33c5982fcb457c0a07b30dbe1ef262ac5ccf36ca00fa5151c7b2e3f10c97c";
const PDF_RULE_SUFFIX: &str = "PDF/format_Tools.2.sg";
const PDF_RULE_BYTES: usize = 557;
const PDF_RULE_SHA256: &str = "982869432394292415be6c3c2ef9408ac1943c4d7571e19f767ffe87314c23da";
const PDF_FIXTURE_SHA256: &str = "28ae4bbe1b02c0ba303ad08fd075a7f01ff0ca7f9ec5fbf77f8b751c7d8c1f65";
const PDF_QT5_BASELINE_SHA256: &str =
    "af31dc57c04974af5fb74b0a4dea42b01ac0aa9460f541b70d60a107d370dbd8";
const XPDF_COMMIT: &str = "cdcee54dce97f566f2c023f400a457f4e6278de2";
const XARCHIVE_COMMIT: &str = "0fcd4e8d3e9933baac3b12246d82ac026557ffd0";
const FORMATS_COMMIT: &str = "1151e7254fdee3c0294ff7095edbdd7bfccf8201";
const FORMAT_RESULT_SHIM: &[u8] = br#"
    var bDetected, sType, sName, sVersion, sOptions;
    function meta(type, name, version, options) {
        sType = type;
        sName = name ? name : String();
        sVersion = version ? version : String();
        sOptions = options ? options : String();
        bDetected = false;
    }
    function _error(message) { throw new Error(String(message)); }
    function result() {
        if (bDetected) {
            sVersion = sVersion ? sVersion : String();
            sOptions = sOptions ? sOptions : String();
            if (!sName) _error("No input detection name.");
            _setResult(sType, sName, sVersion, sOptions);
        }
        sName = sVersion = sOptions = "";
        var value = bDetected;
        bDetected = false;
        return value;
    }
"#;

type Detection = (String, String, String, String);
type DetectionTriple = (String, String, String);
type NintendoLifecycleResult = (Vec<Detection>, Vec<String>, usize, Vec<String>);
type SharedDetections = Arc<Mutex<Vec<Detection>>>;
type SharedHostTrace = Arc<HostTrace>;

#[derive(Default)]
struct HostTrace {
    calls: AtomicUsize,
    compare_native_checkpoints: AtomicUsize,
    fast_paths: AtomicUsize,
    generic_paths: AtomicUsize,
    quirks: AtomicUsize,
    errors: AtomicUsize,
    unique_quirks: Mutex<BTreeSet<String>>,
    unique_errors: Mutex<BTreeSet<String>>,
    search_calls: AtomicUsize,
    search_native_checkpoints: AtomicUsize,
    find_signature_calls: AtomicUsize,
    f_sig_calls: AtomicUsize,
    is_signature_present_calls: AtomicUsize,
    search_matches: AtomicUsize,
    search_quirks: AtomicUsize,
    search_errors: AtomicUsize,
    search_unique_quirks: Mutex<BTreeSet<String>>,
    search_unique_errors: Mutex<BTreeSet<String>>,
    is_overlay_calls: AtomicUsize,
    get_overlay_offset_calls: AtomicUsize,
    get_overlay_size_calls: AtomicUsize,
    is_overlay_present_calls: AtomicUsize,
    get_file_suffix_calls: AtomicUsize,
    get_header_string_calls: AtomicUsize,
    is_plain_text_calls: AtomicUsize,
    is_utf8_text_calls: AtomicUsize,
    is_unicode_text_calls: AtomicUsize,
    is_text_calls: AtomicUsize,
    get_scan_id_calls: AtomicUsize,
    is_resource_calls: AtomicUsize,
    is_debug_data_calls: AtomicUsize,
    is_file_part_calls: AtomicUsize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostFilePart {
    Header,
    Overlay,
    Resource,
    DebugData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BinaryHostContext {
    file_part: HostFilePart,
    overlay_offset: i64,
    overlay_size: i64,
    scan_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PeRuleContext {
    entry_point_offset: Option<usize>,
    memory_map: MemoryMap,
    aliased_out_of_bounds_sections: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ElfRuleContext {
    elf_class: u8,
    entry_point_offset: Option<usize>,
    memory_map: MemoryMap,
    out_of_bounds_loads: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MachoRuleContext {
    is_64: bool,
    cpu_type: u32,
    entry_point_offset: Option<usize>,
    memory_map: MemoryMap,
    out_of_bounds_segments: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DexRuleContext {
    version: u32,
    map_item_count: usize,
    strings: Vec<String>,
    out_of_bounds_string_offsets: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApkRuleContext {
    archive_record_names: Vec<String>,
    local_header_signature_mismatches: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArchiveRuleContext {
    is_verbose: bool,
    file_format_name: String,
    file_format_version: String,
    file_format_options: String,
    local_header_signature_mismatches: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PdfObjectContext {
    id: u64,
    offset: usize,
    tokens: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PdfRuleContext {
    objects: Vec<PdfObjectContext>,
    creator_values: Vec<String>,
    producer_values: Vec<String>,
    header_comment_hex: String,
}

#[derive(Default)]
struct EntryPointHostTrace {
    compare_ep_calls: AtomicUsize,
    fast_paths: AtomicUsize,
    generic_paths: AtomicUsize,
    errors: AtomicUsize,
}

#[derive(Default)]
struct DexHostTrace {
    is_dex_string_present_calls: AtomicUsize,
}

#[derive(Default)]
struct ApkHostTrace {
    is_archive_record_present_calls: AtomicUsize,
}

#[derive(Default)]
struct ArchiveHostTrace {
    is_verbose_calls: AtomicUsize,
    get_file_format_name_calls: AtomicUsize,
    get_file_format_version_calls: AtomicUsize,
    get_file_format_options_calls: AtomicUsize,
}

#[derive(Default)]
struct PdfHostTrace {
    get_string_values_by_key_calls: AtomicUsize,
    get_header_comment_as_hex_calls: AtomicUsize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TextUnicodeType {
    None,
    Little,
    Big,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BinaryStringContext {
    file_suffix: String,
    header_string: String,
    is_plain_text: bool,
    is_utf8_text: bool,
    unicode_type: TextUnicodeType,
}

impl BinaryStringContext {
    fn from_file_name(data: &[u8], file_name: &str) -> Self {
        let is_plain_text = is_plain_text_type(data);
        let is_utf8_text = is_utf8_text_type(data);
        let unicode_type = detect_unicode_type(data);
        let header_string = match unicode_type {
            TextUnicodeType::Little => read_utf16_header(data, false),
            TextUnicodeType::Big => read_utf16_header(data, true),
            TextUnicodeType::None if is_utf8_text => read_utf8_header(data),
            TextUnicodeType::None if is_plain_text => read_latin1_header(data),
            TextUnicodeType::None => String::new(),
        };
        Self {
            file_suffix: qt_file_suffix(file_name),
            header_string,
            is_plain_text,
            is_utf8_text,
            unicode_type,
        }
    }

    fn is_unicode_text(&self) -> bool {
        self.unicode_type != TextUnicodeType::None
    }

    fn is_text(&self) -> bool {
        self.is_plain_text || self.is_utf8_text || self.is_unicode_text()
    }
}

impl BinaryHostContext {
    fn new(
        file_part: HostFilePart,
        overlay_offset: i64,
        overlay_size: i64,
    ) -> Result<Self, String> {
        if overlay_size < 0 {
            return Err("Binary overlay size must be non-negative".to_owned());
        }
        Ok(Self {
            file_part,
            overlay_offset,
            overlay_size,
            scan_id: String::new(),
        })
    }

    fn with_scan_id(mut self, scan_id: impl Into<String>) -> Self {
        self.scan_id = scan_id.into();
        self
    }

    fn identity_header(data_len: usize) -> Result<Self, String> {
        Self::new(
            HostFilePart::Header,
            i64::try_from(data_len)
                .map_err(|_| "Binary input length does not fit qint64".to_owned())?,
            0,
        )
        .map(|context| context.with_scan_id(""))
    }

    fn is_overlay(&self) -> bool {
        self.file_part == HostFilePart::Overlay
    }

    fn is_overlay_present(&self) -> bool {
        self.overlay_size != 0
    }

    fn is_resource(&self) -> bool {
        self.file_part == HostFilePart::Resource
    }

    fn is_debug_data(&self) -> bool {
        self.file_part == HostFilePart::DebugData
    }

    fn is_file_part(&self) -> bool {
        self.file_part != HostFilePart::Header
    }
}

fn pe_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn pe_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn pe_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn pe_field(base: usize, relative: usize, name: &str) -> Result<usize, String> {
    base.checked_add(relative)
        .ok_or_else(|| format!("PE {name} offset overflow"))
}

impl PeRuleContext {
    fn parse(data: &[u8]) -> Result<Self, String> {
        if data.get(0..2) != Some(b"MZ") {
            return Err("PE DOS signature is missing".to_owned());
        }
        let pe_offset = usize::try_from(
            pe_u32(data, 0x3c).ok_or_else(|| "PE e_lfanew is truncated".to_owned())?,
        )
        .map_err(|_| "PE e_lfanew does not fit usize".to_owned())?;
        let signature_end = pe_field(pe_offset, 4, "signature end")?;
        if data.get(pe_offset..signature_end) != Some(b"PE\0\0") {
            return Err("PE signature is missing or truncated".to_owned());
        }
        let coff = signature_end;
        let section_count = usize::from(
            pe_u16(data, pe_field(coff, 2, "section count")?)
                .ok_or_else(|| "PE COFF header is truncated".to_owned())?,
        );
        if section_count > 96 {
            return Err(format!(
                "PE section count {section_count} exceeds spike limit 96"
            ));
        }
        let optional_size = usize::from(
            pe_u16(data, pe_field(coff, 16, "optional header size")?)
                .ok_or_else(|| "PE COFF header is truncated".to_owned())?,
        );
        let optional = pe_field(coff, 20, "optional header")?;
        let optional_end = optional
            .checked_add(optional_size)
            .ok_or_else(|| "PE optional header size overflow".to_owned())?;
        if optional_end > data.len() {
            return Err("PE optional header is truncated".to_owned());
        }
        let magic =
            pe_u16(data, optional).ok_or_else(|| "PE optional magic is truncated".to_owned())?;
        let image_base = match magic {
            0x10b => u64::from(
                pe_u32(data, pe_field(optional, 28, "PE32 image base")?)
                    .ok_or_else(|| "PE32 image base is truncated".to_owned())?,
            ),
            0x20b => pe_u64(data, pe_field(optional, 24, "PE32+ image base")?)
                .ok_or_else(|| "PE32+ image base is truncated".to_owned())?,
            other => {
                return Err(format!(
                    "unsupported PE optional header magic 0x{other:04x}"
                ));
            }
        };
        let entry_rva = u64::from(
            pe_u32(data, pe_field(optional, 16, "entry point RVA")?)
                .ok_or_else(|| "PE entry point RVA is truncated".to_owned())?,
        );
        let size_of_headers = u64::from(
            pe_u32(data, pe_field(optional, 60, "SizeOfHeaders")?)
                .ok_or_else(|| "PE SizeOfHeaders is truncated".to_owned())?,
        );
        let section_table_size = section_count
            .checked_mul(40)
            .ok_or_else(|| "PE section table size overflow".to_owned())?;
        let section_table_end = optional_end
            .checked_add(section_table_size)
            .ok_or_else(|| "PE section table offset overflow".to_owned())?;
        if section_table_end > data.len() {
            return Err("PE section table is truncated".to_owned());
        }

        let mut records = Vec::with_capacity(section_count.saturating_add(1));
        let mut aliased_out_of_bounds_sections = 0_usize;
        let header_size = usize::try_from(size_of_headers)
            .unwrap_or(usize::MAX)
            .min(data.len());
        if header_size != 0 {
            records.push(MemoryRecord {
                offset: 0,
                address: image_base,
                size: header_size as u64,
            });
        }
        let mut entry_point_offset = (entry_rva < size_of_headers)
            .then(|| usize::try_from(entry_rva).ok())
            .flatten()
            .filter(|offset| *offset < data.len());
        for index in 0..section_count {
            let section = optional_end
                .checked_add(
                    index
                        .checked_mul(40)
                        .ok_or_else(|| "PE section offset overflow".to_owned())?,
                )
                .ok_or_else(|| "PE section offset overflow".to_owned())?;
            let virtual_size = u64::from(
                pe_u32(data, pe_field(section, 8, "section virtual size")?)
                    .ok_or_else(|| "PE section header is truncated".to_owned())?,
            );
            let virtual_address = u64::from(
                pe_u32(data, pe_field(section, 12, "section virtual address")?)
                    .ok_or_else(|| "PE section header is truncated".to_owned())?,
            );
            let raw_size = u64::from(
                pe_u32(data, pe_field(section, 16, "section raw size")?)
                    .ok_or_else(|| "PE section header is truncated".to_owned())?,
            );
            let raw_offset = u64::from(
                pe_u32(data, pe_field(section, 20, "section raw offset")?)
                    .ok_or_else(|| "PE section header is truncated".to_owned())?,
            );
            let address = image_base
                .checked_add(virtual_address)
                .ok_or_else(|| "PE section address overflow".to_owned())?;
            let physical_offset = usize::try_from(raw_offset).ok().map(|offset| {
                if offset > data.len() {
                    aliased_out_of_bounds_sections += 1;
                    0
                } else {
                    offset
                }
            });
            let available_size = physical_offset.map_or(0, |offset| {
                if offset == data.len() {
                    0
                } else {
                    usize::try_from(raw_size)
                        .unwrap_or(usize::MAX)
                        .min(data.len() - offset)
                }
            });
            if available_size != 0 {
                records.push(MemoryRecord {
                    offset: physical_offset.unwrap_or(0) as u64,
                    address,
                    size: available_size as u64,
                });
            }
            if entry_point_offset.is_none() {
                let mapped_size = virtual_size.max(raw_size);
                let section_end = virtual_address.checked_add(mapped_size);
                if section_end.is_some_and(|end| virtual_address <= entry_rva && entry_rva < end) {
                    let delta = entry_rva - virtual_address;
                    entry_point_offset = raw_offset
                        .checked_add(delta)
                        .and_then(|offset| usize::try_from(offset).ok())
                        .filter(|offset| {
                            delta < raw_size
                                && *offset < data.len()
                                && usize::try_from(raw_offset)
                                    .ok()
                                    .is_some_and(|raw| *offset >= raw)
                        });
                }
            }
        }
        Ok(Self {
            entry_point_offset,
            aliased_out_of_bounds_sections,
            memory_map: MemoryMap {
                file_type: FileType::Pe,
                endian: Endian::Little,
                code_base: 0,
                start_load_offset: 0,
                records,
            },
        })
    }
}

fn elf_u16(data: &[u8], offset: usize, endian: Endian) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u16::from_le_bytes(bytes),
        Endian::Big => u16::from_be_bytes(bytes),
    })
}

fn elf_u32(data: &[u8], offset: usize, endian: Endian) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u32::from_le_bytes(bytes),
        Endian::Big => u32::from_be_bytes(bytes),
    })
}

fn elf_u64(data: &[u8], offset: usize, endian: Endian) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u64::from_le_bytes(bytes),
        Endian::Big => u64::from_be_bytes(bytes),
    })
}

fn elf_field(base: usize, relative: usize, name: &str) -> Result<usize, String> {
    base.checked_add(relative)
        .ok_or_else(|| format!("ELF {name} offset overflow"))
}

impl ElfRuleContext {
    fn parse(data: &[u8]) -> Result<Self, String> {
        if data.get(0..4) != Some(b"\x7fELF") {
            return Err("ELF signature is missing".to_owned());
        }
        let elf_class = *data
            .get(4)
            .ok_or_else(|| "ELF class is truncated".to_owned())?;
        let endian = match data
            .get(5)
            .copied()
            .ok_or_else(|| "ELF data encoding is truncated".to_owned())?
        {
            1 => Endian::Little,
            2 => Endian::Big,
            other => return Err(format!("unsupported ELF data encoding {other}")),
        };
        if data.get(6) != Some(&1) {
            return Err("unsupported or truncated ELF identification version".to_owned());
        }
        let (header_size, program_header_size, entry, program_offset, entry_size, entry_count) =
            match elf_class {
                1 => (
                    52_usize,
                    32_usize,
                    u64::from(
                        elf_u32(data, 24, endian)
                            .ok_or_else(|| "ELF32 entry point is truncated".to_owned())?,
                    ),
                    u64::from(
                        elf_u32(data, 28, endian)
                            .ok_or_else(|| "ELF32 program table offset is truncated".to_owned())?,
                    ),
                    elf_u16(data, 42, endian)
                        .ok_or_else(|| "ELF32 program entry size is truncated".to_owned())?,
                    elf_u16(data, 44, endian)
                        .ok_or_else(|| "ELF32 program entry count is truncated".to_owned())?,
                ),
                2 => (
                    64_usize,
                    56_usize,
                    elf_u64(data, 24, endian)
                        .ok_or_else(|| "ELF64 entry point is truncated".to_owned())?,
                    elf_u64(data, 32, endian)
                        .ok_or_else(|| "ELF64 program table offset is truncated".to_owned())?,
                    elf_u16(data, 54, endian)
                        .ok_or_else(|| "ELF64 program entry size is truncated".to_owned())?,
                    elf_u16(data, 56, endian)
                        .ok_or_else(|| "ELF64 program entry count is truncated".to_owned())?,
                ),
                other => return Err(format!("unsupported ELF class {other}")),
            };
        let declared_header_size = usize::from(
            elf_u16(data, if elf_class == 1 { 40 } else { 52 }, endian)
                .ok_or_else(|| "ELF header size is truncated".to_owned())?,
        );
        if declared_header_size < header_size || data.len() < header_size {
            return Err(format!(
                "ELF header is truncated or smaller than class minimum {header_size}"
            ));
        }
        let entry_size = usize::from(entry_size);
        if entry_size < program_header_size {
            return Err(format!(
                "ELF program entry size {entry_size} is smaller than {program_header_size}"
            ));
        }
        let entry_count = usize::from(entry_count);
        if entry_count > 1024 {
            return Err(format!(
                "ELF program entry count {entry_count} exceeds spike limit 1024"
            ));
        }
        let program_offset = usize::try_from(program_offset)
            .map_err(|_| "ELF program table offset does not fit usize".to_owned())?;
        let table_size = entry_count
            .checked_mul(entry_size)
            .ok_or_else(|| "ELF program table size overflow".to_owned())?;
        let table_end = program_offset
            .checked_add(table_size)
            .ok_or_else(|| "ELF program table end overflow".to_owned())?;
        if table_end > data.len() {
            return Err("ELF program table is truncated".to_owned());
        }

        let mut loads = Vec::new();
        for index in 0..entry_count {
            let header = program_offset
                .checked_add(
                    index
                        .checked_mul(entry_size)
                        .ok_or_else(|| "ELF program entry offset overflow".to_owned())?,
                )
                .ok_or_else(|| "ELF program entry offset overflow".to_owned())?;
            let segment_type = elf_u32(data, header, endian)
                .ok_or_else(|| "ELF program entry type is truncated".to_owned())?;
            if segment_type != 1 {
                continue;
            }
            let (offset, address, file_size) = if elf_class == 1 {
                (
                    u64::from(
                        elf_u32(data, elf_field(header, 4, "ELF32 segment offset")?, endian)
                            .ok_or_else(|| "ELF32 segment offset is truncated".to_owned())?,
                    ),
                    u64::from(
                        elf_u32(data, elf_field(header, 8, "ELF32 segment address")?, endian)
                            .ok_or_else(|| "ELF32 segment address is truncated".to_owned())?,
                    ),
                    u64::from(
                        elf_u32(data, elf_field(header, 16, "ELF32 file size")?, endian)
                            .ok_or_else(|| "ELF32 file size is truncated".to_owned())?,
                    ),
                )
            } else {
                (
                    elf_u64(data, elf_field(header, 8, "ELF64 segment offset")?, endian)
                        .ok_or_else(|| "ELF64 segment offset is truncated".to_owned())?,
                    elf_u64(
                        data,
                        elf_field(header, 16, "ELF64 segment address")?,
                        endian,
                    )
                    .ok_or_else(|| "ELF64 segment address is truncated".to_owned())?,
                    elf_u64(data, elf_field(header, 32, "ELF64 file size")?, endian)
                        .ok_or_else(|| "ELF64 file size is truncated".to_owned())?,
                )
            };
            if file_size != 0 {
                loads.push((offset, address, file_size));
            }
        }
        let image_base = loads
            .iter()
            .map(|(_, address, _)| *address)
            .min()
            .ok_or_else(|| "ELF contains no non-empty PT_LOAD segment".to_owned())?;
        let mut entry_point_offset = None;
        let mut records = Vec::with_capacity(loads.len());
        let mut out_of_bounds_loads = 0_usize;
        let data_len = u64::try_from(data.len())
            .map_err(|_| "ELF input length does not fit u64".to_owned())?;
        for (offset, address, size) in loads {
            let normalized_address = address
                .checked_sub(image_base)
                .ok_or_else(|| "ELF normalized segment address underflow".to_owned())?;
            let segment_end = offset
                .checked_add(size)
                .ok_or_else(|| "ELF segment file range overflow".to_owned())?;
            if segment_end > data_len {
                out_of_bounds_loads += 1;
            }
            if entry_point_offset.is_none() {
                let address_end = address
                    .checked_add(size)
                    .ok_or_else(|| "ELF segment address range overflow".to_owned())?;
                if address <= entry && entry < address_end {
                    entry_point_offset = offset
                        .checked_add(entry - address)
                        .and_then(|value| usize::try_from(value).ok());
                }
            }
            records.push(MemoryRecord {
                offset,
                address: normalized_address,
                size,
            });
        }
        Ok(Self {
            elf_class,
            entry_point_offset,
            out_of_bounds_loads,
            memory_map: MemoryMap {
                file_type: FileType::Elf,
                endian,
                code_base: 0,
                start_load_offset: 0,
                records,
            },
        })
    }
}

fn macho_u32(data: &[u8], offset: usize, endian: Endian) -> Option<u32> {
    elf_u32(data, offset, endian)
}

fn macho_u64(data: &[u8], offset: usize, endian: Endian) -> Option<u64> {
    elf_u64(data, offset, endian)
}

fn macho_field(base: usize, relative: usize, name: &str) -> Result<usize, String> {
    base.checked_add(relative)
        .ok_or_else(|| format!("Mach-O {name} offset overflow"))
}

impl MachoRuleContext {
    fn parse(data: &[u8]) -> Result<Self, String> {
        let (is_64, endian) = match data.get(0..4) {
            Some(b"\xce\xfa\xed\xfe") => (false, Endian::Little),
            Some(b"\xcf\xfa\xed\xfe") => (true, Endian::Little),
            Some(b"\xfe\xed\xfa\xce") => (false, Endian::Big),
            Some(b"\xfe\xed\xfa\xcf") => (true, Endian::Big),
            _ => return Err("Mach-O signature is missing or unsupported".to_owned()),
        };
        let header_size = if is_64 { 32_usize } else { 28_usize };
        if data.len() < header_size {
            return Err("Mach-O header is truncated".to_owned());
        }
        let cpu_type =
            macho_u32(data, 4, endian).ok_or_else(|| "Mach-O CPU type is truncated".to_owned())?;
        let command_count = usize::try_from(
            macho_u32(data, 16, endian)
                .ok_or_else(|| "Mach-O command count is truncated".to_owned())?,
        )
        .map_err(|_| "Mach-O command count does not fit usize".to_owned())?;
        if command_count > 1024 {
            return Err(format!(
                "Mach-O command count {command_count} exceeds spike limit 1024"
            ));
        }
        let command_bytes = usize::try_from(
            macho_u32(data, 20, endian)
                .ok_or_else(|| "Mach-O command byte size is truncated".to_owned())?,
        )
        .map_err(|_| "Mach-O command byte size does not fit usize".to_owned())?;
        let commands_end = header_size
            .checked_add(command_bytes)
            .ok_or_else(|| "Mach-O command range overflow".to_owned())?;
        if commands_end > data.len() {
            return Err("Mach-O load commands are truncated".to_owned());
        }

        let mut cursor = header_size;
        let mut segments = Vec::new();
        let mut main_entry_offset = None;
        for _ in 0..command_count {
            let command = macho_u32(data, cursor, endian)
                .ok_or_else(|| "Mach-O load command is truncated".to_owned())?;
            let size = usize::try_from(
                macho_u32(data, macho_field(cursor, 4, "command size")?, endian)
                    .ok_or_else(|| "Mach-O load command size is truncated".to_owned())?,
            )
            .map_err(|_| "Mach-O command size does not fit usize".to_owned())?;
            if size < 8 {
                return Err(format!("Mach-O load command size {size} is smaller than 8"));
            }
            let next = cursor
                .checked_add(size)
                .ok_or_else(|| "Mach-O load command range overflow".to_owned())?;
            if next > commands_end {
                return Err("Mach-O load command exceeds declared command range".to_owned());
            }
            if command == 0x19 {
                if size < 72 {
                    return Err("Mach-O64 segment command is smaller than 72".to_owned());
                }
                let address = macho_u64(data, macho_field(cursor, 24, "segment address")?, endian)
                    .ok_or_else(|| "Mach-O64 segment address is truncated".to_owned())?;
                let offset = macho_u64(data, macho_field(cursor, 40, "segment offset")?, endian)
                    .ok_or_else(|| "Mach-O64 segment offset is truncated".to_owned())?;
                let file_size =
                    macho_u64(data, macho_field(cursor, 48, "segment file size")?, endian)
                        .ok_or_else(|| "Mach-O64 segment file size is truncated".to_owned())?;
                if file_size != 0 {
                    segments.push((offset, address, file_size));
                }
            } else if command == 0x1 {
                if size < 56 {
                    return Err("Mach-O32 segment command is smaller than 56".to_owned());
                }
                let address = u64::from(
                    macho_u32(data, macho_field(cursor, 24, "segment address")?, endian)
                        .ok_or_else(|| "Mach-O32 segment address is truncated".to_owned())?,
                );
                let offset = u64::from(
                    macho_u32(data, macho_field(cursor, 32, "segment offset")?, endian)
                        .ok_or_else(|| "Mach-O32 segment offset is truncated".to_owned())?,
                );
                let file_size = u64::from(
                    macho_u32(data, macho_field(cursor, 36, "segment file size")?, endian)
                        .ok_or_else(|| "Mach-O32 segment file size is truncated".to_owned())?,
                );
                if file_size != 0 {
                    segments.push((offset, address, file_size));
                }
            } else if command == 0x8000_0028 {
                if size < 24 {
                    return Err("Mach-O LC_MAIN command is smaller than 24".to_owned());
                }
                main_entry_offset = Some(
                    macho_u64(
                        data,
                        macho_field(cursor, 8, "LC_MAIN entry offset")?,
                        endian,
                    )
                    .ok_or_else(|| "Mach-O LC_MAIN entry offset is truncated".to_owned())?,
                );
            }
            cursor = next;
        }
        if cursor != commands_end {
            return Err("Mach-O load command sizes do not consume sizeofcmds".to_owned());
        }
        if segments.is_empty() {
            return Err("Mach-O contains no non-empty segment".to_owned());
        }
        let data_len = u64::try_from(data.len())
            .map_err(|_| "Mach-O input length does not fit u64".to_owned())?;
        let mut out_of_bounds_segments = 0_usize;
        let mut records = Vec::with_capacity(segments.len());
        for (offset, address, size) in segments {
            let end = offset
                .checked_add(size)
                .ok_or_else(|| "Mach-O segment file range overflow".to_owned())?;
            address
                .checked_add(size)
                .ok_or_else(|| "Mach-O segment address range overflow".to_owned())?;
            if end > data_len {
                out_of_bounds_segments += 1;
            }
            records.push(MemoryRecord {
                offset,
                address,
                size,
            });
        }
        let entry_point_offset = main_entry_offset
            .filter(|entry| {
                records.iter().any(|record| {
                    record
                        .offset
                        .checked_add(record.size)
                        .is_some_and(|end| record.offset <= *entry && *entry < end)
                })
            })
            .and_then(|entry| usize::try_from(entry).ok());
        Ok(Self {
            is_64,
            cpu_type,
            entry_point_offset,
            out_of_bounds_segments,
            memory_map: MemoryMap {
                file_type: FileType::MachO,
                endian,
                code_base: 0,
                start_load_offset: 0,
                records,
            },
        })
    }
}

fn dex_u16(data: &[u8], offset: usize, endian: Endian) -> Option<u16> {
    elf_u16(data, offset, endian)
}

fn dex_u32(data: &[u8], offset: usize, endian: Endian) -> Option<u32> {
    elf_u32(data, offset, endian)
}

fn dex_field(base: usize, relative: usize, name: &str) -> Result<usize, String> {
    base.checked_add(relative)
        .ok_or_else(|| format!("DEX {name} offset overflow"))
}

fn dex_uleb128(data: &[u8]) -> Result<(usize, usize), String> {
    let mut value = 0_usize;
    for (index, byte) in data.iter().copied().take(5).enumerate() {
        let shift = index * 7;
        value |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    if data.is_empty() {
        Ok((0, 0))
    } else {
        Err("DEX string ULEB128 is unterminated or exceeds 5 bytes".to_owned())
    }
}

impl DexRuleContext {
    fn parse(data: &[u8]) -> Result<Self, String> {
        const HEADER_SIZE: usize = 0x70;
        const MAP_ITEM_SIZE: usize = 12;
        const MAX_MAP_ITEMS: usize = 0x1_0000;
        const MAX_STRINGS: usize = 0x1_0000;
        const TYPE_STRING_ID_ITEM: u16 = 0x0001;

        if data.get(0..4) != Some(b"dex\n") || data.get(7) != Some(&0) {
            return Err("DEX signature is missing or unsupported".to_owned());
        }
        let version = std::str::from_utf8(
            data.get(4..7)
                .ok_or_else(|| "DEX version is truncated".to_owned())?,
        )
        .map_err(|_| "DEX version is not ASCII".to_owned())?
        .parse::<u32>()
        .map_err(|_| "DEX version is not numeric".to_owned())?;
        if version < 35 {
            return Err(format!("unsupported DEX version {version:03}"));
        }
        if data.len() < HEADER_SIZE {
            return Err("DEX header is truncated".to_owned());
        }
        let endian = match data.get(40..44) {
            Some(b"\x78\x56\x34\x12") => Endian::Little,
            Some(b"\x12\x34\x56\x78") => Endian::Big,
            _ => return Err("DEX endian tag is invalid".to_owned()),
        };
        let data_size = usize::try_from(
            dex_u32(data, 104, endian).ok_or_else(|| "DEX data size is truncated".to_owned())?,
        )
        .map_err(|_| "DEX data size does not fit usize".to_owned())?;
        let data_offset = usize::try_from(
            dex_u32(data, 108, endian).ok_or_else(|| "DEX data offset is truncated".to_owned())?,
        )
        .map_err(|_| "DEX data offset does not fit usize".to_owned())?;
        let declared_data_end = data_offset
            .checked_add(data_size)
            .ok_or_else(|| "DEX data range overflow".to_owned())?;
        let data_end = declared_data_end.min(data.len());

        let map_offset = usize::try_from(
            dex_u32(data, 52, endian).ok_or_else(|| "DEX map offset is truncated".to_owned())?,
        )
        .map_err(|_| "DEX map offset does not fit usize".to_owned())?;
        if map_offset == 0 {
            return Ok(Self {
                version,
                map_item_count: 0,
                strings: Vec::new(),
                out_of_bounds_string_offsets: 0,
            });
        }
        let Some(declared_map_items) = dex_u32(data, map_offset, endian) else {
            return Ok(Self {
                version,
                map_item_count: 0,
                strings: Vec::new(),
                out_of_bounds_string_offsets: 0,
            });
        };
        let entries_offset = dex_field(map_offset, 4, "map entries")?;
        let available = data.len().saturating_sub(entries_offset);
        let map_item_count = usize::try_from(declared_map_items)
            .unwrap_or(usize::MAX)
            .min(available / MAP_ITEM_SIZE)
            .min(MAX_MAP_ITEMS);
        let mut string_ids = None;
        for index in 0..map_item_count {
            let item = entries_offset
                .checked_add(
                    index
                        .checked_mul(MAP_ITEM_SIZE)
                        .ok_or_else(|| "DEX map item offset overflow".to_owned())?,
                )
                .ok_or_else(|| "DEX map item offset overflow".to_owned())?;
            let item_type = dex_u16(data, item, endian)
                .ok_or_else(|| "DEX map item type is truncated".to_owned())?;
            if item_type == TYPE_STRING_ID_ITEM && string_ids.is_none() {
                let count = usize::try_from(
                    dex_u32(data, dex_field(item, 4, "string-id count")?, endian)
                        .ok_or_else(|| "DEX string-id count is truncated".to_owned())?,
                )
                .map_err(|_| "DEX string-id count does not fit usize".to_owned())?;
                if count > MAX_STRINGS {
                    return Err(format!(
                        "DEX string count {count} exceeds spike limit {MAX_STRINGS}"
                    ));
                }
                let offset = usize::try_from(
                    dex_u32(data, dex_field(item, 8, "string-id table")?, endian)
                        .ok_or_else(|| "DEX string-id offset is truncated".to_owned())?,
                )
                .map_err(|_| "DEX string-id offset does not fit usize".to_owned())?;
                string_ids = Some((count, offset));
            }
        }

        let Some((string_count, string_ids_offset)) = string_ids else {
            return Ok(Self {
                version,
                map_item_count,
                strings: Vec::new(),
                out_of_bounds_string_offsets: 0,
            });
        };
        let mut strings = Vec::with_capacity(string_count);
        let mut out_of_bounds_string_offsets = 0_usize;
        for index in 0..string_count {
            let id_offset = string_ids_offset
                .checked_add(
                    index
                        .checked_mul(4)
                        .ok_or_else(|| "DEX string-id entry offset overflow".to_owned())?,
                )
                .ok_or_else(|| "DEX string-id entry offset overflow".to_owned())?;
            let string_offset =
                dex_u32(data, id_offset, endian).and_then(|offset| usize::try_from(offset).ok());
            let Some(string_offset) =
                string_offset.filter(|offset| data_offset <= *offset && *offset < data_end)
            else {
                out_of_bounds_string_offsets += 1;
                strings.push(String::new());
                continue;
            };
            let source = &data[string_offset..data_end];
            let (declared_length, prefix_size) = dex_uleb128(source)?;
            let payload = source.get(prefix_size..).unwrap_or_default();
            let actual_length = declared_length.min(payload.len());
            strings.push(String::from_utf8_lossy(&payload[..actual_length]).into_owned());
        }
        Ok(Self {
            version,
            map_item_count,
            strings,
            out_of_bounds_string_offsets,
        })
    }
}

fn zip_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn zip_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn zip_field(base: usize, relative: usize, name: &str) -> Result<usize, String> {
    base.checked_add(relative)
        .ok_or_else(|| format!("ZIP {name} offset overflow"))
}

fn find_zip_eocd(data: &[u8]) -> Option<usize> {
    const EOCD_SIZE: usize = 22;
    const EOCD_SIGNATURE: u32 = 0x0605_4b50;
    const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;

    if data.len() < EOCD_SIZE {
        return None;
    }
    let start = data.len().saturating_sub(0x1000);
    let mut result = None;
    for offset in start..=data.len().saturating_sub(4) {
        if zip_u32(data, offset) != Some(EOCD_SIGNATURE) {
            continue;
        }
        let Some(central_field) = offset.checked_add(16) else {
            continue;
        };
        let Some(central_offset) =
            zip_u32(data, central_field).and_then(|value| usize::try_from(value).ok())
        else {
            continue;
        };
        if central_offset >= offset {
            continue;
        }
        if zip_u32(data, central_offset) == Some(CENTRAL_SIGNATURE) {
            result = Some(offset);
        }
    }
    result
}

impl ApkRuleContext {
    fn parse(data: &[u8]) -> Result<Self, String> {
        const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
        const EOCD_SIGNATURE: u32 = 0x0605_4b50;
        const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
        const CENTRAL_HEADER_SIZE: usize = 46;
        const SCRIPT_RECORD_LIMIT: usize = 20_000;
        const APK_PROBE_LIMIT: usize = 10_000;

        if !matches!(
            zip_u32(data, 0),
            Some(LOCAL_SIGNATURE) | Some(EOCD_SIGNATURE)
        ) {
            return Err("ZIP signature is missing or unsupported".to_owned());
        }
        let eocd = find_zip_eocd(data)
            .ok_or_else(|| "ZIP end of central directory is missing".to_owned())?;
        let total_records = usize::from(
            zip_u16(data, zip_field(eocd, 10, "EOCD record count")?)
                .ok_or_else(|| "ZIP EOCD record count is truncated".to_owned())?,
        );
        let mut cursor = usize::try_from(
            zip_u32(data, zip_field(eocd, 16, "central directory")?)
                .ok_or_else(|| "ZIP central directory offset is truncated".to_owned())?,
        )
        .map_err(|_| "ZIP central directory offset does not fit usize".to_owned())?;
        let record_count = total_records.min(SCRIPT_RECORD_LIMIT);
        let mut archive_record_names = Vec::with_capacity(record_count);
        let mut local_header_signature_mismatches = 0_usize;
        for index in 0..record_count {
            let header_end = cursor
                .checked_add(CENTRAL_HEADER_SIZE)
                .ok_or_else(|| "ZIP central header range overflow".to_owned())?;
            if header_end > data.len() {
                return Err(format!("ZIP central header {index} is truncated"));
            }
            if zip_u32(data, cursor) != Some(CENTRAL_SIGNATURE) {
                return Err(format!("ZIP central header {index} signature is invalid"));
            }
            let name_length = usize::from(
                zip_u16(data, zip_field(cursor, 28, "file name length")?)
                    .ok_or_else(|| "ZIP file name length is truncated".to_owned())?,
            );
            let extra_length = usize::from(
                zip_u16(data, zip_field(cursor, 30, "extra length")?)
                    .ok_or_else(|| "ZIP extra length is truncated".to_owned())?,
            );
            let comment_length = usize::from(
                zip_u16(data, zip_field(cursor, 32, "comment length")?)
                    .ok_or_else(|| "ZIP comment length is truncated".to_owned())?,
            );
            let local_offset = usize::try_from(
                zip_u32(data, zip_field(cursor, 42, "local header")?)
                    .ok_or_else(|| "ZIP local header offset is truncated".to_owned())?,
            )
            .map_err(|_| "ZIP local header offset does not fit usize".to_owned())?;
            if zip_u32(data, local_offset) != Some(LOCAL_SIGNATURE) {
                local_header_signature_mismatches += 1;
            }
            let name_end = header_end
                .checked_add(name_length)
                .ok_or_else(|| "ZIP file name range overflow".to_owned())?;
            let next = name_end
                .checked_add(extra_length)
                .and_then(|value| value.checked_add(comment_length))
                .ok_or_else(|| "ZIP central entry range overflow".to_owned())?;
            let name = data
                .get(header_end..name_end)
                .ok_or_else(|| format!("ZIP central header {index} file name is truncated"))?
                .iter()
                .copied()
                .map(char::from)
                .collect();
            if next > data.len() {
                return Err(format!("ZIP central entry {index} is truncated"));
            }
            archive_record_names.push(name);
            cursor = next;
        }
        if !archive_record_names
            .iter()
            .take(APK_PROBE_LIMIT)
            .any(|name| name == "classes.dex" || name == "AndroidManifest.xml")
        {
            return Err("ZIP central directory does not identify an APK".to_owned());
        }
        Ok(Self {
            archive_record_names,
            local_header_signature_mismatches,
        })
    }
}

impl ArchiveRuleContext {
    fn parse(data: &[u8], is_verbose: bool) -> Result<Self, String> {
        const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
        const EOCD_SIGNATURE: u32 = 0x0605_4b50;
        const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
        const CENTRAL_HEADER_SIZE: usize = 46;
        const METADATA_RECORD_LIMIT: usize = 20;

        if data.is_empty()
            || !matches!(
                zip_u32(data, 0),
                Some(LOCAL_SIGNATURE) | Some(EOCD_SIGNATURE)
            )
        {
            return Err("ZIP signature is missing or unsupported".to_owned());
        }
        let eocd = find_zip_eocd(data)
            .ok_or_else(|| "ZIP end of central directory is missing".to_owned())?;
        let total_records = usize::from(
            zip_u16(data, zip_field(eocd, 10, "EOCD record count")?)
                .ok_or_else(|| "ZIP EOCD record count is truncated".to_owned())?,
        );
        let central_offset = usize::try_from(
            zip_u32(data, zip_field(eocd, 16, "central directory")?)
                .ok_or_else(|| "ZIP central directory offset is truncated".to_owned())?,
        )
        .map_err(|_| "ZIP central directory offset does not fit usize".to_owned())?;
        if zip_u32(data, central_offset) != Some(CENTRAL_SIGNATURE) {
            return Err("ZIP first central header signature is invalid".to_owned());
        }

        let central_version_offset = zip_field(central_offset, 4, "central version")?;
        let local_version_offset = zip_field(0, 4, "local minimum version")?;
        let mut version = data.get(central_version_offset).copied().unwrap_or(0);
        if version == 0 {
            version = data.get(local_version_offset).copied().unwrap_or(0);
        }
        let file_format_version = if version == 0 {
            String::new()
        } else {
            format!("{}.{:01}", version / 10, version % 10)
        };

        let first_flags = zip_u16(data, zip_field(central_offset, 8, "central flags")?)
            .ok_or_else(|| "ZIP central flags are truncated".to_owned())?;
        let encrypted = first_flags & 1 != 0;
        let mut cursor = central_offset;
        let mut compression_methods = BTreeSet::new();
        let mut local_header_signature_mismatches = 0_usize;
        for index in 0..total_records.min(METADATA_RECORD_LIMIT) {
            let header_end = cursor
                .checked_add(CENTRAL_HEADER_SIZE)
                .ok_or_else(|| "ZIP central header range overflow".to_owned())?;
            if header_end > data.len() {
                return Err(format!("ZIP central header {index} is truncated"));
            }
            if zip_u32(data, cursor) != Some(CENTRAL_SIGNATURE) {
                return Err(format!("ZIP central header {index} signature is invalid"));
            }
            let flags = zip_u16(data, zip_field(cursor, 8, "central flags")?)
                .ok_or_else(|| "ZIP central flags are truncated".to_owned())?;
            let method = zip_u16(data, zip_field(cursor, 10, "compression method")?)
                .ok_or_else(|| "ZIP compression method is truncated".to_owned())?;
            let uncompressed_size = zip_u32(data, zip_field(cursor, 24, "uncompressed size")?)
                .ok_or_else(|| "ZIP uncompressed size is truncated".to_owned())?;
            if uncompressed_size != 0 {
                match (method, flags & 1 != 0) {
                    (0, false) => {
                        compression_methods.insert("Store");
                    }
                    (method, encrypted) => {
                        return Err(format!(
                            "unsupported ZIP metadata method {method}, encrypted={encrypted}"
                        ));
                    }
                }
            }
            let name_length = usize::from(
                zip_u16(data, zip_field(cursor, 28, "file name length")?)
                    .ok_or_else(|| "ZIP file name length is truncated".to_owned())?,
            );
            let extra_length = usize::from(
                zip_u16(data, zip_field(cursor, 30, "extra length")?)
                    .ok_or_else(|| "ZIP extra length is truncated".to_owned())?,
            );
            let comment_length = usize::from(
                zip_u16(data, zip_field(cursor, 32, "comment length")?)
                    .ok_or_else(|| "ZIP comment length is truncated".to_owned())?,
            );
            let local_offset = usize::try_from(
                zip_u32(data, zip_field(cursor, 42, "local header")?)
                    .ok_or_else(|| "ZIP local header offset is truncated".to_owned())?,
            )
            .map_err(|_| "ZIP local header offset does not fit usize".to_owned())?;
            if zip_u32(data, local_offset) != Some(LOCAL_SIGNATURE) {
                local_header_signature_mismatches += 1;
            }
            cursor = header_end
                .checked_add(name_length)
                .and_then(|value| value.checked_add(extra_length))
                .and_then(|value| value.checked_add(comment_length))
                .ok_or_else(|| "ZIP central entry range overflow".to_owned())?;
            if cursor > data.len() {
                return Err(format!("ZIP central entry {index} is truncated"));
            }
        }
        if compression_methods.len() > 1 {
            return Err(
                "multiple ZIP compression-method ordering is not covered by this spike".to_owned(),
            );
        }
        let mut options = Vec::new();
        if encrypted {
            options.push("Encrypted");
        }
        options.extend(compression_methods);
        Ok(Self {
            is_verbose,
            file_format_name: "ZIP".to_owned(),
            file_format_version,
            file_format_options: options.join(", "),
            local_header_signature_mismatches,
        })
    }
}

fn pdf_is_line_ending(byte: u8) -> bool {
    byte == b'\n' || byte == b'\r'
}

fn pdf_skip_space_then_endings(data: &[u8], mut offset: usize) -> usize {
    while data.get(offset) == Some(&b' ') {
        offset += 1;
    }
    while let Some(byte) = data.get(offset) {
        if *byte == b'\n' {
            offset += 1;
        } else if *byte == b'\r' {
            offset += 1;
            if data.get(offset) == Some(&b'\n') {
                offset += 1;
            }
        } else {
            break;
        }
    }
    offset
}

fn pdf_latin1(bytes: &[u8]) -> String {
    bytes.iter().copied().map(char::from).collect()
}

fn pdf_read_line(data: &[u8], offset: usize) -> Result<(String, usize), String> {
    if offset >= data.len() {
        return Ok((String::new(), offset));
    }
    let mut end = offset;
    while let Some(byte) = data.get(end) {
        if *byte == 0 {
            return Err("PDF NUL line termination is not covered by this spike".to_owned());
        }
        if pdf_is_line_ending(*byte) {
            break;
        }
        end += 1;
    }
    Ok((
        pdf_latin1(&data[offset..end]),
        pdf_skip_space_then_endings(data, end),
    ))
}

fn pdf_is_structural_delimiter(byte: u8) -> bool {
    matches!(byte, b'[' | b']' | b'<' | b'>')
}

fn pdf_read_token(data: &[u8], offset: usize) -> Result<(String, usize), String> {
    let first = *data
        .get(offset)
        .ok_or_else(|| "PDF token offset is at EOF".to_owned())?;
    let mut end = offset;
    let token = match first {
        b'/' => {
            end += 1;
            while let Some(byte) = data.get(end) {
                if *byte == 0
                    || pdf_is_line_ending(*byte)
                    || pdf_is_structural_delimiter(*byte)
                    || *byte == b' '
                    || *byte == b'('
                    || *byte == b'/'
                {
                    break;
                }
                end += 1;
            }
            pdf_latin1(&data[offset..end])
        }
        b'(' => {
            let mut output = String::from("(");
            end += 1;
            let mut escaped = false;
            while let Some(byte) = data.get(end).copied() {
                if byte == 0 || pdf_is_line_ending(byte) {
                    break;
                }
                if byte == b')' && !escaped {
                    output.push(')');
                    end += 1;
                    break;
                }
                if byte == b'\\' {
                    escaped = true;
                    end += 1;
                    continue;
                }
                output.push(char::from(byte));
                escaped = false;
                end += 1;
            }
            output
        }
        b'<' if data.get(offset + 1) == Some(&b'<') => {
            end += 2;
            "<<".to_owned()
        }
        b'<' => {
            end += 1;
            while let Some(byte) = data.get(end) {
                end += 1;
                if *byte == b'>' {
                    break;
                }
            }
            pdf_latin1(&data[offset..end])
        }
        b'>' if data.get(offset + 1) == Some(&b'>') => {
            end += 2;
            ">>".to_owned()
        }
        b'[' | b']' => {
            end += 1;
            char::from(first).to_string()
        }
        b'>' => return Err("single PDF '>' token is unsupported".to_owned()),
        _ => {
            while let Some(byte) = data.get(end) {
                if *byte == 0
                    || pdf_is_line_ending(*byte)
                    || pdf_is_structural_delimiter(*byte)
                    || *byte == b'/'
                {
                    break;
                }
                if *byte == b' ' {
                    break;
                }
                end += 1;
            }
            pdf_latin1(&data[offset..end])
        }
    };
    if end == offset {
        return Err("PDF tokenizer made no progress".to_owned());
    }
    Ok((token, pdf_skip_space_then_endings(data, end)))
}

fn pdf_is_object_line(line: &str) -> bool {
    let trimmed = line.trim_end_matches(' ');
    let Some(prefix) = trimmed.strip_suffix("obj") else {
        return false;
    };
    prefix.is_empty() || prefix.ends_with(' ')
}

fn pdf_object_id(line: &str) -> u64 {
    line.split_ascii_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn pdf_string_values_by_key(objects: &[PdfObjectContext], key: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    for object in objects {
        for pair in object.tokens.windows(2) {
            if pair[0] != key {
                continue;
            }
            let value = &pair[1];
            if value.len() >= 2 && value.starts_with('(') && value.ends_with(')') {
                let string = value[1..value.len() - 1].to_owned();
                if seen.insert(string.clone()) {
                    values.push(string);
                }
            }
        }
    }
    values
}

impl PdfRuleContext {
    fn parse(data: &[u8]) -> Result<Self, String> {
        const OBJECT_LIMIT: usize = 4_096;
        const PART_LIMIT: usize = 20;

        if data.len() <= 4 || data.get(0..4) != Some(b"%PDF") {
            return Err("PDF signature is missing or input is too short".to_owned());
        }
        let (_, mut header_end) = pdf_read_line(data, 0)?;
        let header_comment_hex = if data.get(header_end) == Some(&b'%') {
            header_end += 1;
            let comment_end = data.len().min(header_end.saturating_add(40));
            let mut end = header_end;
            while end < comment_end {
                let byte = data[end];
                if byte == 0 || pdf_is_line_ending(byte) {
                    break;
                }
                end += 1;
            }
            data[header_end..end]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join("")
        } else {
            String::new()
        };

        let mut objects = Vec::new();
        let mut cursor = 0_usize;
        while cursor < data.len() {
            if objects.len() >= OBJECT_LIMIT {
                return Err(format!(
                    "PDF object count exceeds spike limit {OBJECT_LIMIT}"
                ));
            }
            let object_offset = cursor;
            let (line, next) = pdf_read_line(data, cursor)?;
            if pdf_is_object_line(&line) {
                let search = &data[next..];
                let Some(relative_endobj) = search
                    .windows(b"endobj".len())
                    .position(|window| window == b"endobj")
                else {
                    break;
                };
                let endobj_offset = next
                    .checked_add(relative_endobj)
                    .ok_or_else(|| "PDF endobj offset overflow".to_owned())?;
                let (endobj, after_endobj) = pdf_read_line(data, endobj_offset)?;
                if endobj.trim() != "endobj" {
                    break;
                }

                let mut token_cursor = next;
                let mut tokens = Vec::new();
                let mut dictionary_depth = 0_i32;
                let mut array_depth = 0_i32;
                while token_cursor < endobj_offset && tokens.len() < PART_LIMIT {
                    let (token, token_next) = pdf_read_token(data, token_cursor)?;
                    match token.as_str() {
                        "<<" => dictionary_depth += 1,
                        ">>" => dictionary_depth -= 1,
                        "[" => array_depth += 1,
                        "]" => array_depth -= 1,
                        _ => {}
                    }
                    tokens.push(token);
                    token_cursor = token_next;
                    if dictionary_depth == 0 && array_depth == 0 {
                        break;
                    }
                    if dictionary_depth < 0 || array_depth < 0 {
                        return Err("PDF dictionary/array nesting underflow".to_owned());
                    }
                }
                objects.push(PdfObjectContext {
                    id: pdf_object_id(&line),
                    offset: object_offset,
                    tokens,
                });
                cursor = after_endobj;
            } else if line.starts_with('%') {
                cursor = next;
            } else {
                break;
            }
        }
        let creator_values = pdf_string_values_by_key(&objects, "/Creator");
        let producer_values = pdf_string_values_by_key(&objects, "/Producer");
        Ok(Self {
            objects,
            creator_values,
            producer_values,
            header_comment_hex,
        })
    }
}

fn collect_rule_files(root: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        fs::read_dir(root).map_err(|error| format!("cannot read {}: {error}", root.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("cannot enumerate {}: {error}", root.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_rule_files(&path, output)?;
        } else if file_type.is_file()
            && (path.extension().is_none()
                || path.extension().is_some_and(|extension| extension == "sg"))
        {
            output.push(path);
        }
    }
    Ok(())
}

fn normalized_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn apply_compatibility_overlay(path: &Path, source: &[u8]) -> Result<(Vec<u8>, bool), String> {
    let normalized = normalized_path(path);
    if !normalized.ends_with(NINTENDO_RULE_SUFFIX) {
        return Ok((source.to_vec(), false));
    }
    if source.len() != NINTENDO_RULE_BYTES {
        return Err(format!(
            "refusing Nintendo compatibility overlay: expected {NINTENDO_RULE_BYTES} bytes, got {}",
            source.len()
        ));
    }
    let matches = source
        .windows(NINTENDO_VAR_DECLARATION.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == NINTENDO_VAR_DECLARATION).then_some(offset))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "refusing Nintendo compatibility overlay: expected one declaration, got {}",
            matches.len()
        ));
    }
    debug_assert_eq!(
        NINTENDO_VAR_DECLARATION.len(),
        NINTENDO_COMPAT_DECLARATION.len()
    );
    let mut transformed = source.to_vec();
    let start = matches[0];
    let end = start + NINTENDO_VAR_DECLARATION.len();
    transformed[start..end].copy_from_slice(NINTENDO_COMPAT_DECLARATION);
    Ok((transformed, true))
}

fn apply_exact_lifecycle_overlay(
    path: &Path,
    source: &[u8],
    suffix: &str,
    expected_bytes: usize,
    declaration: &[u8],
    replacement: &[u8],
    id: &'static str,
) -> Result<(Vec<u8>, Option<&'static str>), String> {
    if !normalized_path(path).ends_with(suffix) {
        return Ok((source.to_vec(), None));
    }
    if source.len() != expected_bytes {
        return Err(format!(
            "refusing {id} overlay: expected {expected_bytes} bytes, got {}",
            source.len()
        ));
    }
    if declaration.len() != replacement.len() {
        return Err(format!("invalid {id} overlay: replacement length differs"));
    }
    let matches = source
        .windows(declaration.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == declaration).then_some(offset))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "refusing {id} overlay: expected one declaration, got {}",
            matches.len()
        ));
    }
    let mut transformed = source.to_vec();
    let start = matches[0];
    transformed[start..start + declaration.len()].copy_from_slice(replacement);
    Ok((transformed, Some(id)))
}

fn apply_binary_lifecycle_overlay(
    path: &Path,
    source: &[u8],
) -> Result<(Vec<u8>, Option<&'static str>), String> {
    let (transformed, nintendo_applied) = apply_compatibility_overlay(path, source)?;
    if nintendo_applied {
        return Ok((transformed, Some("nintendo-unused-var-tp-v1")));
    }
    let (transformed, audio_id) = apply_exact_lifecycle_overlay(
        path,
        source,
        AUDIO_RULE_SUFFIX,
        AUDIO_RULE_BYTES,
        AUDIO_CONST_DEBUG_DECLARATION,
        AUDIO_COMPAT_DEBUG_DECLARATION,
        "audio-global-const-debug-v1",
    )?;
    if audio_id.is_some() {
        return Ok((transformed, audio_id));
    }
    apply_exact_lifecycle_overlay(
        path,
        source,
        EXTENSIONS_RULE_SUFFIX,
        EXTENSIONS_RULE_BYTES,
        EXTENSIONS_CONST_DETECT_DECLARATION,
        EXTENSIONS_COMPAT_DETECT_DECLARATION,
        "extensions-global-const-detect-v1",
    )
}

fn new_runtime() -> Result<Runtime, String> {
    Runtime::new().map_err(|error| error.to_string())
}

fn new_tracking_runtime(
    maximum_live_bytes: usize,
) -> Result<(Runtime, Arc<TrackingAllocatorStats>), String> {
    let (allocator, stats) = TrackingLimitAllocator::new(maximum_live_bytes);
    Runtime::new_with_alloc(allocator)
        .map(|runtime| (runtime, stats))
        .map_err(|error| error.to_string())
}

#[derive(Clone, Copy)]
struct RuntimeMemorySnapshot {
    malloc_size: u64,
    memory_used_size: u64,
    malloc_count: u64,
    memory_used_count: u64,
    atom_count: u64,
    object_count: u64,
    js_function_count: u64,
    js_function_code_size: u64,
    binary_object_count: u64,
    binary_object_size: u64,
}

impl RuntimeMemorySnapshot {
    fn to_json(self) -> Value {
        json!({
            "malloc_size": self.malloc_size,
            "memory_used_size": self.memory_used_size,
            "malloc_count": self.malloc_count,
            "memory_used_count": self.memory_used_count,
            "atom_count": self.atom_count,
            "object_count": self.object_count,
            "js_function_count": self.js_function_count,
            "js_function_code_size": self.js_function_code_size,
            "binary_object_count": self.binary_object_count,
            "binary_object_size": self.binary_object_size,
        })
    }
}

fn runtime_memory_snapshot(runtime: &Runtime) -> Result<RuntimeMemorySnapshot, String> {
    let usage = runtime.memory_usage();
    let nonnegative = |name: &str, value: i64| {
        u64::try_from(value)
            .map_err(|_| format!("runtime memory field {name} is negative: {value}"))
    };
    Ok(RuntimeMemorySnapshot {
        malloc_size: nonnegative("malloc_size", usage.malloc_size)?,
        memory_used_size: nonnegative("memory_used_size", usage.memory_used_size)?,
        malloc_count: nonnegative("malloc_count", usage.malloc_count)?,
        memory_used_count: nonnegative("memory_used_count", usage.memory_used_count)?,
        atom_count: nonnegative("atom_count", usage.atom_count)?,
        object_count: nonnegative("obj_count", usage.obj_count)?,
        js_function_count: nonnegative("js_func_count", usage.js_func_count)?,
        js_function_code_size: nonnegative("js_func_code_size", usage.js_func_code_size)?,
        binary_object_count: nonnegative("binary_object_count", usage.binary_object_count)?,
        binary_object_size: nonnegative("binary_object_size", usage.binary_object_size)?,
    })
}

struct RuleCaseRuntimeProbe {
    interrupt_calls: Arc<AtomicUsize>,
    runtime_created: RuntimeMemorySnapshot,
    tracking: Option<(usize, Arc<TrackingAllocatorStats>)>,
}

impl RuleCaseRuntimeProbe {
    fn finish(
        self,
        runtime: Runtime,
        context: Context,
        initialized: RuntimeMemorySnapshot,
    ) -> Result<Value, String> {
        let after_rule = runtime_memory_snapshot(&runtime)?;
        let checkpoints = [
            ("runtime_created", self.runtime_created),
            ("initialized", initialized),
            ("after_rule", after_rule),
        ];
        let maximum_malloc = checkpoints
            .iter()
            .max_by_key(|(_, snapshot)| snapshot.malloc_size)
            .ok_or_else(|| "rule runtime malloc checkpoints are empty".to_owned())?;
        let maximum_memory_used = checkpoints
            .iter()
            .max_by_key(|(_, snapshot)| snapshot.memory_used_size)
            .ok_or_else(|| "rule runtime memory-used checkpoints are empty".to_owned())?;
        let mut report = json!({
            "interrupt": {
                "handler_semantics":
                    "one QuickJS-NG interrupt callback invocation over one isolated rule-case runtime",
                "handler_call_total": self.interrupt_calls.load(Ordering::Relaxed),
            },
            "memory": {
                "api": "rquickjs Runtime::memory_usage / QuickJS-NG JS_ComputeMemoryUsage",
                "scope":
                    "three post-operation lifecycle checkpoints; transient in-eval allocator high-water is not observed",
                "checkpoint_count": checkpoints.len(),
                "runtime_created": self.runtime_created.to_json(),
                "initialized": initialized.to_json(),
                "after_rule": after_rule.to_json(),
                "maximum_observed_malloc_size": {
                    "bytes": maximum_malloc.1.malloc_size,
                    "stage": maximum_malloc.0,
                },
                "maximum_observed_memory_used_size": {
                    "bytes": maximum_memory_used.1.memory_used_size,
                    "stage": maximum_memory_used.0,
                },
                "transient_high_water_measured": false,
            },
        });
        let tracking_before_drop = self.tracking.as_ref().map(|(_, stats)| {
            (
                stats.live_bytes(),
                stats.high_water_bytes(),
                stats.denied_allocation_count(),
            )
        });
        drop(context);
        drop(runtime);
        if let (Some((limit_bytes, stats)), Some((live_before_drop, high_water, denied))) =
            (self.tracking, tracking_before_drop)
        {
            let live_after_drop = stats.live_bytes();
            if live_before_drop == 0
                || high_water < live_before_drop
                || high_water > limit_bytes
                || denied != 0
                || live_after_drop != 0
            {
                return Err(format!(
                    "tracked rule runtime invariant failed: limit={limit_bytes} \
                     live_before_drop={live_before_drop} high_water={high_water} \
                     denied={denied} live_after_drop={live_after_drop}"
                ));
            }
            report["memory"]["scope"] = json!(
                "three post-operation lifecycle checkpoints plus allocator-observed transient live-byte high-water"
            );
            report["memory"]["transient_high_water_measured"] = json!(true);
            report["memory"]["tracking_allocator"] = json!({
                "backend": "rquickjs RustAllocator wrapped by TrackingLimitAllocator",
                "limit_bytes": limit_bytes,
                "set_memory_limit_used": false,
                "accounting": "RustAllocator allocation Layout bytes: aligned payload plus internal header",
                "live_bytes_before_drop": live_before_drop,
                "high_water_bytes": high_water,
                "denied_allocation_count": denied,
                "live_bytes_after_drop": live_after_drop,
            });
        }
        Ok(report)
    }
}

fn new_rule_case_runtime_with_tracking(
    tracking_limit_bytes: Option<usize>,
) -> Result<(Runtime, RuleCaseRuntimeProbe), String> {
    let (runtime, tracking) = if let Some(limit) = tracking_limit_bytes {
        let (runtime, stats) = new_tracking_runtime(limit)?;
        (runtime, Some((limit, stats)))
    } else {
        (new_runtime()?, None)
    };
    let runtime_created = runtime_memory_snapshot(&runtime)?;
    let interrupt_calls = Arc::new(AtomicUsize::new(0));
    let interrupt_calls_for_handler = Arc::clone(&interrupt_calls);
    runtime.set_interrupt_handler(Some(Box::new(move || {
        interrupt_calls_for_handler.fetch_add(1, Ordering::Relaxed);
        false
    })));
    Ok((
        runtime,
        RuleCaseRuntimeProbe {
            interrupt_calls,
            runtime_created,
            tracking,
        },
    ))
}

fn new_context(runtime: &Runtime) -> Result<Context, String> {
    Context::full(runtime).map_err(|error| error.to_string())
}

fn eval_unit(context: &Context, source: &[u8]) -> Result<(), String> {
    context.with(|ctx| {
        let mut options = EvalOptions::default();
        options.strict = false;
        ctx.eval_with_options::<(), _>(source.to_vec(), options)
            .catch(&ctx)
            .map_err(|error| error.to_string())
    })
}

fn install_host_shim(context: &Context) -> Result<(), String> {
    eval_unit(context, HOST_SHIM)
}

fn install_host_fallbacks(context: &Context) -> Result<(), String> {
    eval_unit(context, HOST_FALLBACK_SHIM)
}

fn install_diagnostic_host_fallbacks(context: &Context) -> Result<(), String> {
    eval_unit(context, DIAGNOSTIC_HOST_FALLBACK_SHIM)
}

fn install_selected_host_trace(context: &Context) -> Result<(), String> {
    eval_unit(
        context,
        br#"
        globalThis.__selectedHostTrace = [];
        ["c", "U8", "U16", "U32", "U64", "SA", "Sz", "isDeepScan", "isHeuristicScan", "isVerbose"]
            .forEach(function (name) {
                var original = X[name];
                X[name] = function () {
                    var args = Array.prototype.slice.call(arguments);
                    var value = original.apply(X, args);
                    __selectedHostTrace.push([name, args, value]);
                    return value;
                };
            });
        "#,
    )
}

fn eval_string(context: &Context, source: &[u8]) -> Result<String, String> {
    context.with(|ctx| {
        let mut options = EvalOptions::default();
        options.strict = false;
        ctx.eval_with_options::<String, _>(source.to_vec(), options)
            .catch(&ctx)
            .map_err(|error| error.to_string())
    })
}

fn eval_rule_lexical(
    context: &Context,
    source: &[u8],
    invoke_detect: bool,
) -> Result<String, String> {
    let suffix = if invoke_detect {
        b"\nreturn typeof detect === 'function' ? String(detect()) : 'not-function';\n}).call(globalThis)\n"
            .as_slice()
    } else {
        b"\nreturn typeof detect;\n}).call(globalThis)\n".as_slice()
    };
    let prefix = b"(function () {\n";
    let capacity = prefix
        .len()
        .checked_add(source.len())
        .and_then(|size| size.checked_add(suffix.len()))
        .ok_or_else(|| "lexical wrapper size overflow".to_owned())?;
    let mut wrapped = Vec::with_capacity(capacity);
    wrapped.extend_from_slice(prefix);
    wrapped.extend_from_slice(source);
    wrapped.extend_from_slice(suffix);
    eval_string(context, &wrapped)
}

fn read_unsigned_bits(data: &[u8], offset: usize, width: usize, big_endian: bool) -> u64 {
    let Some(bytes) = data.get(offset..offset.saturating_add(width)) else {
        return 0;
    };
    if big_endian {
        bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
    } else {
        bytes
            .iter()
            .rev()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
    }
}

fn read_unsigned(data: &[u8], offset: usize, width: usize, big_endian: bool) -> f64 {
    read_unsigned_bits(data, offset, width, big_endian) as f64
}

fn read_signed(data: &[u8], offset: usize, width: usize, big_endian: bool) -> f64 {
    let unsigned = read_unsigned_bits(data, offset, width, big_endian);
    let shift = 64_u32.saturating_sub((width as u32).saturating_mul(8));
    ((unsigned << shift) as i64 >> shift) as f64
}

fn shift_right_unsigned(value: f64, bits: u32) -> rquickjs::Result<f64> {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > MAX_SAFE_INTEGER {
        return Err(Error::new_from_js_message(
            "number",
            "quint64",
            "shru64 spike accepts only non-negative safe integers",
        ));
    }
    if bits >= 64 {
        return Err(Error::new_from_js_message(
            "number",
            "quint64 shift",
            "shru64 shift must be less than 64",
        ));
    }
    Ok(((value as u64) >> bits) as f64)
}

fn nonnegative_index(value: i64) -> Option<usize> {
    usize::try_from(value).ok()
}

fn read_ascii(data: &[u8], offset: usize, size: usize) -> String {
    let Some(bytes) = read_byte_slice(data, offset, size) else {
        return String::new();
    };
    bytes
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| char::from(*byte))
        .collect()
}

fn read_byte_slice(data: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    if offset > data.len() {
        return None;
    }
    let end = offset.saturating_add(size).min(data.len());
    data.get(offset..end)
}

fn percentage_at_least(value: usize, total: usize, percent: usize) -> bool {
    (value as u128) * 100 >= (total as u128) * (percent as u128)
}

fn percentage_at_most(value: usize, total: usize, percent: usize) -> bool {
    (value as u128) * 100 <= (total as u128) * (percent as u128)
}

fn is_plain_text_type(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(0x8000)];
    if sample.is_empty()
        || sample.starts_with(&[0xef, 0xbb, 0xbf])
        || sample.starts_with(&[0xff, 0xfe])
        || sample.starts_with(&[0xfe, 0xff])
    {
        return false;
    }

    let mut control = 0_usize;
    let mut printable = 0_usize;
    let mut extended = 0_usize;
    for byte in sample {
        match *byte {
            0 => return false,
            1..=8 => control += 1,
            9 | 10 | 13 | 0x20..=0x7e => printable += 1,
            0x80..=0xff => extended += 1,
            _ => control += 1,
        }
    }
    percentage_at_least(printable + extended, sample.len(), 85)
        && percentage_at_most(control, sample.len(), 5)
        && percentage_at_most(extended, sample.len(), 50)
}

fn is_utf8_text_type(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(0x2000)];
    if sample.is_empty() {
        return false;
    }
    let has_bom = sample.starts_with(&[0xef, 0xbb, 0xbf]);
    let mut index = usize::from(has_bom) * 3;
    let mut valid_chars = 0_usize;
    let mut multibyte_chars = 0_usize;
    let mut printable_chars = 0_usize;
    while index < sample.len() {
        let byte = sample[index];
        if byte == 0 {
            return false;
        }
        if byte < 0x80 {
            printable_chars += usize::from(byte >= 0x20 || matches!(byte, 9 | 10 | 13));
            valid_chars += 1;
            index += 1;
            continue;
        }
        if byte & 0xe0 == 0xc0 {
            if index + 1 >= sample.len() || sample[index + 1] & 0xc0 != 0x80 || byte < 0xc2 {
                return false;
            }
            multibyte_chars += 1;
            valid_chars += 1;
            index += 2;
            continue;
        }
        if byte & 0xf0 == 0xe0 {
            if index + 2 >= sample.len()
                || sample[index + 1] & 0xc0 != 0x80
                || sample[index + 2] & 0xc0 != 0x80
                || (byte == 0xe0 && sample[index + 1] < 0xa0)
            {
                return false;
            }
            multibyte_chars += 1;
            valid_chars += 1;
            index += 3;
            continue;
        }
        if byte & 0xf8 == 0xf0 {
            if index + 3 >= sample.len()
                || sample[index + 1] & 0xc0 != 0x80
                || sample[index + 2] & 0xc0 != 0x80
                || sample[index + 3] & 0xc0 != 0x80
                || (byte == 0xf0 && sample[index + 1] < 0x90)
                || byte > 0xf4
                || (byte == 0xf4 && sample[index + 1] > 0x8f)
            {
                return false;
            }
            multibyte_chars += 1;
            valid_chars += 1;
            index += 4;
            continue;
        }
        return false;
    }

    if has_bom {
        valid_chars != 0
    } else {
        valid_chars != 0
            && (multibyte_chars as u128) * 100 > (valid_chars as u128) * 5
            && percentage_at_least(printable_chars, valid_chars, 70)
    }
}

fn detect_unicode_type(data: &[u8]) -> TextUnicodeType {
    let sample = &data[..data.len().min(0x1000)];
    if sample.starts_with(&[0xff, 0xfe]) {
        return TextUnicodeType::Little;
    }
    if sample.starts_with(&[0xfe, 0xff]) {
        return TextUnicodeType::Big;
    }
    if sample.len() < 4 {
        return TextUnicodeType::None;
    }

    let analyzed = &sample[..sample.len().min(512)];
    let mut nulls = 0_usize;
    let mut even_nulls = 0_usize;
    let mut odd_nulls = 0_usize;
    let mut printable = 0_usize;
    for (index, byte) in analyzed.iter().enumerate() {
        if *byte == 0 {
            nulls += 1;
            if index % 2 == 0 {
                even_nulls += 1;
            } else {
                odd_nulls += 1;
            }
        } else if (0x20..=0x7e).contains(byte) {
            printable += 1;
        }
    }
    if nulls == 0
        || analyzed.len() <= 4
        || !percentage_at_least(nulls, analyzed.len(), 30)
        || !percentage_at_least(printable, analyzed.len(), 30)
    {
        return TextUnicodeType::None;
    }
    if even_nulls > odd_nulls.saturating_mul(2) {
        return TextUnicodeType::Little;
    }
    if odd_nulls > even_nulls.saturating_mul(2) {
        return TextUnicodeType::Big;
    }

    let mut little_pairs = 0_usize;
    let mut big_pairs = 0_usize;
    for pair in analyzed.chunks_exact(2) {
        let little = u16::from_le_bytes([pair[0], pair[1]]);
        if little & 0xff00 == 0 && (0x20..=0x7e).contains(&(little & 0xff)) {
            little_pairs += 1;
        }
        let big = u16::from_be_bytes([pair[0], pair[1]]);
        if big & 0xff00 == 0 && (0x20..=0x7e).contains(&(big & 0xff)) {
            big_pairs += 1;
        }
    }
    if little_pairs > big_pairs {
        TextUnicodeType::Little
    } else if big_pairs > little_pairs {
        TextUnicodeType::Big
    } else {
        TextUnicodeType::None
    }
}

fn nul_terminated(bytes: &[u8]) -> &[u8] {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..length]
}

fn read_latin1_header(data: &[u8]) -> String {
    nul_terminated(&data[..data.len().min(0x1000)])
        .iter()
        .map(|byte| char::from(*byte))
        .collect()
}

fn read_utf8_header(data: &[u8]) -> String {
    let max_size = data.len().min(0x1000);
    let bytes = data
        .get(3..3_usize.saturating_add(max_size).min(data.len()))
        .unwrap_or_default();
    String::from_utf8_lossy(nul_terminated(bytes)).into_owned()
}

fn read_utf16_header(data: &[u8], big_endian: bool) -> String {
    let max_words = data.len().min(0x1000);
    let bytes = data.get(2..).unwrap_or_default();
    let mut words = Vec::with_capacity((bytes.len() / 2).min(max_words));
    for pair in bytes.chunks_exact(2).take(max_words) {
        let word = if big_endian {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        };
        if word == 0 {
            break;
        }
        words.push(word);
    }
    String::from_utf16_lossy(&words)
}

fn qt_file_suffix(file_name: &str) -> String {
    if file_name.is_empty() {
        return String::new();
    }
    #[cfg(windows)]
    let base_name = file_name.rsplit(['/', '\\']).next().unwrap_or(file_name);
    #[cfg(not(windows))]
    let base_name = file_name.rsplit('/').next().unwrap_or(file_name);
    base_name
        .rfind('.')
        .map_or_else(String::new, |dot| base_name[dot + 1..].to_owned())
}

fn read_byte_array(data: &[u8], offset: i64, size: i64, replace_zero: bool) -> Vec<u8> {
    let Some((offset, size)) = nonnegative_index(offset).zip(nonnegative_index(size)) else {
        return Vec::new();
    };
    read_byte_slice(data, offset, size)
        .unwrap_or_default()
        .iter()
        .map(|byte| {
            if replace_zero && *byte == 0 {
                b' '
            } else {
                *byte
            }
        })
        .collect()
}

fn search_signature(
    data: &[u8],
    trace: &HostTrace,
    host_name: &'static str,
    offset: i64,
    size: i64,
    pattern: &str,
) -> rquickjs::Result<Option<usize>> {
    trace.search_calls.fetch_add(1, Ordering::Relaxed);
    let mut checkpoint = || {
        trace
            .search_native_checkpoints
            .fetch_add(1, Ordering::Relaxed);
        true
    };
    match Pattern::find_binary_wrapper_with_checkpoint(pattern, data, offset, size, &mut checkpoint)
    {
        Ok(report) => {
            trace
                .search_matches
                .fetch_add(usize::from(report.found.is_some()), Ordering::Relaxed);
            trace
                .search_quirks
                .fetch_add(report.quirks.len(), Ordering::Relaxed);
            if !report.quirks.is_empty() {
                trace
                    .search_unique_quirks
                    .lock()
                    .map_err(|_| {
                        Error::new_from_js_message(
                            host_name,
                            "signature search result",
                            "signature search quirk mutex poisoned",
                        )
                    })?
                    .extend(report.quirks.iter().map(|quirk| format!("{quirk:?}")));
            }
            Ok(report.found.map(|found| found.offset))
        }
        Err(error) => {
            trace.search_errors.fetch_add(1, Ordering::Relaxed);
            let message = error.to_string();
            trace
                .search_unique_errors
                .lock()
                .map_err(|_| {
                    Error::new_from_js_message(
                        host_name,
                        "signature search result",
                        "signature search error mutex poisoned",
                    )
                })?
                .insert(message.clone());
            Err(Error::new_from_js_message(
                host_name,
                "signature search result",
                message,
            ))
        }
    }
}

fn install_entry_point_host(
    context: &Context,
    receiver_name: &'static str,
    data: Arc<Vec<u8>>,
    entry_point_offset: Option<usize>,
    memory_map: MemoryMap,
) -> Result<Arc<EntryPointHostTrace>, String> {
    let trace = Arc::new(EntryPointHostTrace::default());
    let trace_for_context = Arc::clone(&trace);
    let compare_api = match receiver_name {
        "PE" => "PE.compareEP",
        "ELF" => "ELF.compareEP",
        "MACH" => "MACH.compareEP",
        _ => "format.compareEP",
    };
    context.with(|ctx| {
        let receiver = Object::new(ctx.clone()).map_err(|error| error.to_string())?;
        let compare_data = Arc::clone(&data);
        let compare_memory_map = memory_map.clone();
        receiver
            .set(
                "compareEP",
                Function::new(ctx.clone(), move |pattern: String, offset: Opt<i64>| {
                    trace_for_context
                        .compare_ep_calls
                        .fetch_add(1, Ordering::Relaxed);
                    match Pattern::compare_entry_point_wrapper(
                        &pattern,
                        &compare_data,
                        entry_point_offset,
                        offset.0.unwrap_or(0),
                        &compare_memory_map,
                    ) {
                        Ok(report) => {
                            if report.header_fast_path {
                                trace_for_context.fast_paths.fetch_add(1, Ordering::Relaxed);
                            } else {
                                trace_for_context
                                    .generic_paths
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(report.matched)
                        }
                        Err(error) => {
                            trace_for_context.errors.fetch_add(1, Ordering::Relaxed);
                            Err(Error::new_from_js_message(
                                compare_api,
                                "boolean",
                                error.to_string(),
                            ))
                        }
                    }
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        ctx.globals()
            .set(receiver_name, receiver)
            .map_err(|error| error.to_string())
    })?;
    Ok(trace)
}

fn install_pe_host(
    context: &Context,
    data: Arc<Vec<u8>>,
    pe_context: PeRuleContext,
) -> Result<Arc<EntryPointHostTrace>, String> {
    install_entry_point_host(
        context,
        "PE",
        data,
        pe_context.entry_point_offset,
        pe_context.memory_map,
    )
}

fn install_elf_host(
    context: &Context,
    data: Arc<Vec<u8>>,
    elf_context: ElfRuleContext,
) -> Result<Arc<EntryPointHostTrace>, String> {
    install_entry_point_host(
        context,
        "ELF",
        data,
        elf_context.entry_point_offset,
        elf_context.memory_map,
    )
}

fn install_macho_host(
    context: &Context,
    data: Arc<Vec<u8>>,
    macho_context: MachoRuleContext,
) -> Result<Arc<EntryPointHostTrace>, String> {
    install_entry_point_host(
        context,
        "MACH",
        data,
        macho_context.entry_point_offset,
        macho_context.memory_map,
    )
}

fn install_dex_host(
    context: &Context,
    dex_context: DexRuleContext,
) -> Result<Arc<DexHostTrace>, String> {
    let trace = Arc::new(DexHostTrace::default());
    let trace_for_context = Arc::clone(&trace);
    context.with(|ctx| {
        let receiver = Object::new(ctx.clone()).map_err(|error| error.to_string())?;
        receiver
            .set(
                "isDexStringPresent",
                Function::new(ctx.clone(), move |query: String| {
                    trace_for_context
                        .is_dex_string_present_calls
                        .fetch_add(1, Ordering::Relaxed);
                    dex_context.strings.iter().any(|value| value == &query)
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        ctx.globals()
            .set("DEX", receiver)
            .map_err(|error| error.to_string())
    })?;
    Ok(trace)
}

fn install_apk_host(
    context: &Context,
    apk_context: ApkRuleContext,
) -> Result<Arc<ApkHostTrace>, String> {
    let trace = Arc::new(ApkHostTrace::default());
    let trace_for_context = Arc::clone(&trace);
    context.with(|ctx| {
        let receiver = Object::new(ctx.clone()).map_err(|error| error.to_string())?;
        receiver
            .set(
                "isArchiveRecordPresent",
                Function::new(ctx.clone(), move |query: String| {
                    trace_for_context
                        .is_archive_record_present_calls
                        .fetch_add(1, Ordering::Relaxed);
                    apk_context
                        .archive_record_names
                        .iter()
                        .any(|value| value == &query)
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        ctx.globals()
            .set("APK", receiver)
            .map_err(|error| error.to_string())
    })?;
    Ok(trace)
}

fn install_archive_host(
    context: &Context,
    archive_context: ArchiveRuleContext,
) -> Result<Arc<ArchiveHostTrace>, String> {
    let trace = Arc::new(ArchiveHostTrace::default());
    let archive_context = Arc::new(archive_context);
    context.with(|ctx| {
        let receiver = Object::new(ctx.clone()).map_err(|error| error.to_string())?;

        let context_for_verbose = Arc::clone(&archive_context);
        let trace_for_verbose = Arc::clone(&trace);
        receiver
            .set(
                "isVerbose",
                Function::new(ctx.clone(), move || {
                    trace_for_verbose
                        .is_verbose_calls
                        .fetch_add(1, Ordering::Relaxed);
                    context_for_verbose.is_verbose
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;

        let context_for_name = Arc::clone(&archive_context);
        let trace_for_name = Arc::clone(&trace);
        receiver
            .set(
                "getFileFormatName",
                Function::new(ctx.clone(), move || {
                    trace_for_name
                        .get_file_format_name_calls
                        .fetch_add(1, Ordering::Relaxed);
                    context_for_name.file_format_name.clone()
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;

        let context_for_version = Arc::clone(&archive_context);
        let trace_for_version = Arc::clone(&trace);
        receiver
            .set(
                "getFileFormatVersion",
                Function::new(ctx.clone(), move || {
                    trace_for_version
                        .get_file_format_version_calls
                        .fetch_add(1, Ordering::Relaxed);
                    context_for_version.file_format_version.clone()
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;

        let context_for_options = Arc::clone(&archive_context);
        let trace_for_options = Arc::clone(&trace);
        receiver
            .set(
                "getFileFormatOptions",
                Function::new(ctx.clone(), move || {
                    trace_for_options
                        .get_file_format_options_calls
                        .fetch_add(1, Ordering::Relaxed);
                    context_for_options.file_format_options.clone()
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;

        ctx.globals()
            .set("Archive", receiver)
            .map_err(|error| error.to_string())
    })?;
    Ok(trace)
}

fn install_pdf_host(
    context: &Context,
    pdf_context: PdfRuleContext,
) -> Result<Arc<PdfHostTrace>, String> {
    let trace = Arc::new(PdfHostTrace::default());
    let pdf_context = Arc::new(pdf_context);
    context.with(|ctx| {
        let receiver = Object::new(ctx.clone()).map_err(|error| error.to_string())?;

        let context_for_values = Arc::clone(&pdf_context);
        let trace_for_values = Arc::clone(&trace);
        receiver
            .set(
                "getStringValuesByKey",
                Function::new(ctx.clone(), move |key: String| {
                    trace_for_values
                        .get_string_values_by_key_calls
                        .fetch_add(1, Ordering::Relaxed);
                    match key.as_str() {
                        "/Creator" => context_for_values.creator_values.clone(),
                        "/Producer" => context_for_values.producer_values.clone(),
                        _ => Vec::new(),
                    }
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;

        let context_for_header = Arc::clone(&pdf_context);
        let trace_for_header = Arc::clone(&trace);
        receiver
            .set(
                "getHeaderCommentAsHex",
                Function::new(ctx.clone(), move || {
                    trace_for_header
                        .get_header_comment_as_hex_calls
                        .fetch_add(1, Ordering::Relaxed);
                    context_for_header.header_comment_hex.clone()
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;

        ctx.globals()
            .set("PDF", receiver)
            .map_err(|error| error.to_string())
    })?;
    Ok(trace)
}

fn install_nintendo_host(
    context: &Context,
    data: Arc<Vec<u8>>,
    detections: SharedDetections,
) -> Result<SharedHostTrace, String> {
    let host_context = BinaryHostContext::identity_header(data.len())?;
    let string_context = BinaryStringContext::from_file_name(&data, "");
    install_nintendo_host_with_context_and_strings(
        context,
        data,
        detections,
        host_context,
        string_context,
    )
}

fn install_nintendo_host_for_path(
    context: &Context,
    data: Arc<Vec<u8>>,
    detections: SharedDetections,
    input_path: &Path,
) -> Result<SharedHostTrace, String> {
    let host_context = BinaryHostContext::identity_header(data.len())?;
    let file_name = input_path.as_os_str().to_string_lossy();
    let string_context = BinaryStringContext::from_file_name(&data, &file_name);
    install_nintendo_host_with_context_and_strings(
        context,
        data,
        detections,
        host_context,
        string_context,
    )
}

#[cfg(test)]
fn install_nintendo_host_with_context(
    context: &Context,
    data: Arc<Vec<u8>>,
    detections: SharedDetections,
    host_context: BinaryHostContext,
) -> Result<SharedHostTrace, String> {
    let string_context = BinaryStringContext::from_file_name(&data, "");
    install_nintendo_host_with_context_and_strings(
        context,
        data,
        detections,
        host_context,
        string_context,
    )
}

fn install_nintendo_host_with_context_and_strings(
    context: &Context,
    data: Arc<Vec<u8>>,
    detections: SharedDetections,
    host_context: BinaryHostContext,
    string_context: BinaryStringContext,
) -> Result<SharedHostTrace, String> {
    let signature_trace = Arc::new(HostTrace::default());
    let signature_trace_for_context = Arc::clone(&signature_trace);
    let is_overlay = host_context.is_overlay();
    let overlay_offset = host_context.overlay_offset;
    let overlay_size = host_context.overlay_size;
    let is_overlay_present = host_context.is_overlay_present();
    let scan_id = host_context.scan_id.clone();
    let is_resource = host_context.is_resource();
    let is_debug_data = host_context.is_debug_data();
    let is_file_part = host_context.is_file_part();
    context.with(|ctx| {
        let globals = ctx.globals();
        let x = Object::new(ctx.clone()).map_err(|error| error.to_string())?;

        for name in ["c", "compare"] {
            let compare_data = Arc::clone(&data);
            let compare_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                name,
                Function::new(ctx.clone(), move |pattern: String, offset: Opt<i64>| {
                    compare_trace.calls.fetch_add(1, Ordering::Relaxed);
                    let mut checkpoint = || {
                        compare_trace
                            .compare_native_checkpoints
                            .fetch_add(1, Ordering::Relaxed);
                        true
                    };
                    match Pattern::compare_binary_wrapper_with_checkpoint(
                        &pattern,
                        &compare_data,
                        offset.0.unwrap_or(0),
                        &mut checkpoint,
                    ) {
                        Ok(report) => {
                            if report.header_fast_path {
                                compare_trace.fast_paths.fetch_add(1, Ordering::Relaxed);
                            } else {
                                compare_trace.generic_paths.fetch_add(1, Ordering::Relaxed);
                            }
                            compare_trace
                                .quirks
                                .fetch_add(report.quirks.len(), Ordering::Relaxed);
                            if !report.quirks.is_empty() {
                                let mut unique =
                                    compare_trace.unique_quirks.lock().map_err(|_| {
                                        Error::new_from_js_message(
                                            "Binary.compare",
                                            "boolean",
                                            "signature quirk mutex poisoned",
                                        )
                                    })?;
                                unique
                                    .extend(report.quirks.iter().map(|quirk| format!("{quirk:?}")));
                            }
                            Ok(report.matched)
                        }
                        Err(error) => {
                            compare_trace.errors.fetch_add(1, Ordering::Relaxed);
                            let message = error.to_string();
                            compare_trace
                                .unique_errors
                                .lock()
                                .map_err(|_| {
                                    Error::new_from_js_message(
                                        "Binary.compare",
                                        "boolean",
                                        "signature error mutex poisoned",
                                    )
                                })?
                                .insert(message.clone());
                            Err(Error::new_from_js_message(
                                "Binary.compare",
                                "boolean",
                                message,
                            ))
                        }
                    }
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }

        {
            let search_data = Arc::clone(&data);
            let search_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "findSignature",
                Function::new(
                    ctx.clone(),
                    move |offset: i64, size: i64, pattern: String| {
                        search_trace
                            .find_signature_calls
                            .fetch_add(1, Ordering::Relaxed);
                        search_signature(
                            &search_data,
                            &search_trace,
                            "Binary.findSignature",
                            offset,
                            size,
                            &pattern,
                        )
                        .map(|found| {
                            found
                                .and_then(|offset| i64::try_from(offset).ok())
                                .unwrap_or(-1)
                        })
                    },
                )
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let search_data = Arc::clone(&data);
            let search_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "fSig",
                Function::new(
                    ctx.clone(),
                    move |offset: i64, size: i64, pattern: String| {
                        search_trace.f_sig_calls.fetch_add(1, Ordering::Relaxed);
                        search_signature(
                            &search_data,
                            &search_trace,
                            "Binary.fSig",
                            offset,
                            size,
                            &pattern,
                        )
                        .map(|found| {
                            found
                                .and_then(|offset| i64::try_from(offset).ok())
                                .unwrap_or(-1)
                        })
                    },
                )
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let search_data = Arc::clone(&data);
            let search_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "isSignaturePresent",
                Function::new(
                    ctx.clone(),
                    move |offset: i64, size: i64, pattern: String| {
                        search_trace
                            .is_signature_present_calls
                            .fetch_add(1, Ordering::Relaxed);
                        search_signature(
                            &search_data,
                            &search_trace,
                            "Binary.isSignaturePresent",
                            offset,
                            size,
                            &pattern,
                        )
                        .map(|found| found.is_some())
                    },
                )
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }

        {
            let overlay_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "isOverlay",
                Function::new(ctx.clone(), move || {
                    overlay_trace
                        .is_overlay_calls
                        .fetch_add(1, Ordering::Relaxed);
                    is_overlay
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let overlay_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "getOverlayOffset",
                Function::new(ctx.clone(), move || {
                    overlay_trace
                        .get_overlay_offset_calls
                        .fetch_add(1, Ordering::Relaxed);
                    overlay_offset
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let overlay_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "getOverlaySize",
                Function::new(ctx.clone(), move || {
                    overlay_trace
                        .get_overlay_size_calls
                        .fetch_add(1, Ordering::Relaxed);
                    overlay_size
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let overlay_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "isOverlayPresent",
                Function::new(ctx.clone(), move || {
                    overlay_trace
                        .is_overlay_present_calls
                        .fetch_add(1, Ordering::Relaxed);
                    is_overlay_present
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let value = string_context.file_suffix.clone();
            let string_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "getFileSuffix",
                Function::new(ctx.clone(), move || {
                    string_trace
                        .get_file_suffix_calls
                        .fetch_add(1, Ordering::Relaxed);
                    value.clone()
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let value = string_context.header_string.clone();
            let string_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "getHeaderString",
                Function::new(ctx.clone(), move || {
                    string_trace
                        .get_header_string_calls
                        .fetch_add(1, Ordering::Relaxed);
                    value.clone()
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let value = string_context.is_plain_text;
            let string_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "isPlainText",
                Function::new(ctx.clone(), move || {
                    string_trace
                        .is_plain_text_calls
                        .fetch_add(1, Ordering::Relaxed);
                    value
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let value = string_context.is_utf8_text;
            let string_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "isUTF8Text",
                Function::new(ctx.clone(), move || {
                    string_trace
                        .is_utf8_text_calls
                        .fetch_add(1, Ordering::Relaxed);
                    value
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let value = string_context.is_unicode_text();
            let string_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "isUnicodeText",
                Function::new(ctx.clone(), move || {
                    string_trace
                        .is_unicode_text_calls
                        .fetch_add(1, Ordering::Relaxed);
                    value
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let value = string_context.is_text();
            let string_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "isText",
                Function::new(ctx.clone(), move || {
                    string_trace.is_text_calls.fetch_add(1, Ordering::Relaxed);
                    value
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let context_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "getScanID",
                Function::new(ctx.clone(), move || {
                    context_trace
                        .get_scan_id_calls
                        .fetch_add(1, Ordering::Relaxed);
                    scan_id.clone()
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let context_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "isResource",
                Function::new(ctx.clone(), move || {
                    context_trace
                        .is_resource_calls
                        .fetch_add(1, Ordering::Relaxed);
                    is_resource
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let context_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "isDebugData",
                Function::new(ctx.clone(), move || {
                    context_trace
                        .is_debug_data_calls
                        .fetch_add(1, Ordering::Relaxed);
                    is_debug_data
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        {
            let context_trace = Arc::clone(&signature_trace_for_context);
            x.set(
                "isFilePart",
                Function::new(ctx.clone(), move || {
                    context_trace
                        .is_file_part_calls
                        .fetch_add(1, Ordering::Relaxed);
                    is_file_part
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }

        for (name, width) in [
            ("U16", 2_usize),
            ("readWord", 2),
            ("read_uint16", 2),
            ("U24", 3),
            ("read_uint24", 3),
            ("U32", 4),
            ("readDword", 4),
            ("read_uint32", 4),
            ("U64", 8),
            ("readQword", 8),
            ("read_uint64", 8),
        ] {
            let integer_data = Arc::clone(&data);
            x.set(
                name,
                Function::new(ctx.clone(), move |offset: i64, big_endian: Opt<bool>| {
                    nonnegative_index(offset).map_or(0.0, |offset| {
                        read_unsigned(&integer_data, offset, width, big_endian.0.unwrap_or(false))
                    })
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        for name in ["U8", "readByte", "read_uint8"] {
            let byte_data = Arc::clone(&data);
            x.set(
                name,
                Function::new(ctx.clone(), move |offset: i64| {
                    nonnegative_index(offset)
                        .and_then(|offset| byte_data.get(offset))
                        .copied()
                        .unwrap_or(0)
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        for (name, width) in [
            ("I8", 1_usize),
            ("readSByte", 1),
            ("read_int8", 1),
            ("I16", 2),
            ("readSWord", 2),
            ("read_int16", 2),
            ("I32", 4),
            ("readSDword", 4),
            ("read_int32", 4),
            ("I64", 8),
            ("readSQword", 8),
            ("read_int64", 8),
        ] {
            let integer_data = Arc::clone(&data);
            x.set(
                name,
                Function::new(ctx.clone(), move |offset: i64, big_endian: Opt<bool>| {
                    nonnegative_index(offset).map_or(0.0, |offset| {
                        read_signed(&integer_data, offset, width, big_endian.0.unwrap_or(false))
                    })
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        for name in ["SA", "getString", "read_ansiString"] {
            let string_data = Arc::clone(&data);
            x.set(
                name,
                Function::new(ctx.clone(), move |offset: i64, size: Opt<i64>| {
                    nonnegative_index(offset)
                        .zip(nonnegative_index(size.0.unwrap_or(50)))
                        .map_or_else(String::new, |(offset, size)| {
                            read_ascii(&string_data, offset, size)
                        })
                })
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        for name in ["readBytes", "BA"] {
            let array_data = Arc::clone(&data);
            x.set(
                name,
                Function::new(
                    ctx.clone(),
                    move |offset: i64, size: i64, replace_zero: Opt<bool>| {
                        read_byte_array(&array_data, offset, size, replace_zero.0.unwrap_or(false))
                    },
                )
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }

        let size = data.len() as f64;
        for name in ["Sz", "getSize"] {
            x.set(
                name,
                Function::new(ctx.clone(), move || size).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        x.set(
            "isHeuristicScan",
            Function::new(ctx.clone(), || false).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        x.set(
            "isDeepScan",
            Function::new(ctx.clone(), || false).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        x.set(
            "isVerbose",
            Function::new(ctx.clone(), || false).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        globals
            .set("Binary", x.clone())
            .map_err(|error| error.to_string())?;
        globals.set("X", x).map_err(|error| error.to_string())?;
        let util = Object::new(ctx.clone()).map_err(|error| error.to_string())?;
        util.set(
            "shlu64",
            Function::new(ctx.clone(), |value: f64, bits: u32| {
                value * 2_f64.powi(i32::try_from(bits).unwrap_or(i32::MAX))
            })
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        util.set(
            "shru64",
            Function::new(ctx.clone(), shift_right_unsigned).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        util.set(
            "div64",
            Function::new(ctx.clone(), |dividend: i64, divisor: i64| {
                if divisor == 0 {
                    -1
                } else {
                    dividend.overflowing_div(divisor).0
                }
            })
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        globals
            .set("Util", util)
            .map_err(|error| error.to_string())?;
        globals
            .set(
                "_log",
                Function::new(ctx.clone(), |_message: String| {})
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        globals
            .set(
                "_isResultPresent",
                Function::new(ctx.clone(), |_kind: String, _name: String| false)
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        globals
            .set(
                "_getNumberOfResults",
                Function::new(ctx.clone(), |_kind: Opt<String>| 0_i32)
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        globals
            .set(
                "_removeResult",
                Function::new(ctx.clone(), |_kind: String, _name: String| {})
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        globals
            .set(
                "_setLang",
                Function::new(ctx.clone(), |_language: String, _version: Opt<String>| {})
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        let result_detections = Arc::clone(&detections);
        globals
            .set(
                "_setResult",
                Function::new(
                    ctx.clone(),
                    move |kind: String, name: String, version: String, info: String| {
                        result_detections
                            .lock()
                            .expect("Nintendo fixture result mutex poisoned")
                            .push((kind, name, version, info));
                    },
                )
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        Ok::<(), String>(())
    })?;
    Ok(signature_trace)
}

fn install_main_include_registry(context: &Context, rule_root: &Path) -> Result<(), String> {
    let mut helpers = serde_json::Map::new();
    let entries = fs::read_dir(rule_root)
        .map_err(|error| format!("cannot read {}: {error}", rule_root.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("cannot enumerate {}: {error}", rule_root.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if !file_type.is_file()
            || !(path.extension().is_none()
                || path.extension().is_some_and(|extension| extension == "sg"))
        {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("non-UTF-8 helper name: {}", path.display()))?
            .to_uppercase();
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        helpers.entry(name).or_insert(Value::String(source));
    }
    let registry = serde_json::to_string(&helpers)
        .map_err(|error| format!("cannot serialize include registry: {error}"))?;
    let program = format!(
        r#"
        globalThis.__helperSources = {registry};
        globalThis.__includeTrace = [];
        function includeScript(name) {{
            var key = String(name).toUpperCase();
            if (!Object.prototype.hasOwnProperty.call(__helperSources, key)) {{
                throw new Error("Cannot find: " + name);
            }}
            __includeTrace.push(String(name));
            (0, eval)(__helperSources[key]);
        }}
        "#
    );
    eval_unit(context, program.as_bytes())
}

fn parse_binary_order(document: &Value) -> Result<Vec<String>, String> {
    if document.get("upstream_commit").and_then(Value::as_str) != Some(UPSTREAM_COMMIT) {
        return Err("Binary order upstream commit mismatch".to_owned());
    }
    if document.get("rules_commit").and_then(Value::as_str) != Some(RULES_COMMIT) {
        return Err("Binary order rules commit mismatch".to_owned());
    }
    if document.get("order_sha256").and_then(Value::as_str) != Some(LINUX_QT5_BINARY_ORDER_SHA256) {
        return Err("Binary order SHA-256 mismatch".to_owned());
    }
    let order = document
        .get("order")
        .and_then(Value::as_array)
        .ok_or_else(|| "Binary order array is missing".to_owned())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "Binary order contains a non-string".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if order.len() != BINARY_SIGNATURE_COUNT {
        return Err(format!(
            "expected {BINARY_SIGNATURE_COUNT} Binary signatures, got {}",
            order.len()
        ));
    }
    let mut unique = order.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != order.len() {
        return Err("Binary order contains duplicate names".to_owned());
    }
    for name in &order {
        let path = Path::new(name);
        if path.file_name().and_then(|value| value.to_str()) != Some(name.as_str()) {
            return Err(format!("invalid Binary signature name: {name}"));
        }
    }
    let mut canonical = Vec::new();
    for name in &order {
        canonical.extend_from_slice(name.as_bytes());
        canonical.push(b'\n');
    }
    if sha256_hex(&canonical) != LINUX_QT5_BINARY_ORDER_SHA256 {
        return Err("Binary canonical order SHA-256 mismatch".to_owned());
    }
    Ok(order)
}

fn run_binary_lifecycle(
    rule_root: &Path,
    order_path: &Path,
    compatibility_overlays: bool,
    lexical_wrapper: bool,
) -> Result<bool, String> {
    let order_document: Value = serde_json::from_slice(
        &fs::read(order_path)
            .map_err(|error| format!("cannot read {}: {error}", order_path.display()))?,
    )
    .map_err(|error| format!("cannot parse {}: {error}", order_path.display()))?;
    let order = parse_binary_order(&order_document)?;
    let started = Instant::now();
    let runtime = new_runtime()?;
    let interrupt_ticks = Arc::new(AtomicUsize::new(0));
    let interrupt_ticks_for_handler = Arc::clone(&interrupt_ticks);
    runtime.set_interrupt_handler(Some(Box::new(move || {
        interrupt_ticks_for_handler.fetch_add(1, Ordering::Relaxed) >= 1_000_000
    })));
    let context = new_context(&runtime)?;
    install_host_shim(&context)?;
    install_main_include_registry(&context, rule_root)?;

    for relative in ["_init", "Binary/_init"] {
        let path = rule_root.join(relative);
        let source =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        eval_unit(&context, &source)
            .map_err(|error| format!("cannot eval {}: {error}", path.display()))?;
    }

    let mut errors = Vec::new();
    let mut non_function_detects = Vec::new();
    let mut total_bytes = 0_u64;
    let mut overlay_paths = Vec::new();
    for (index, name) in order.iter().enumerate() {
        let path = rule_root.join("Binary").join(name);
        let source =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        total_bytes = total_bytes
            .checked_add(source.len() as u64)
            .ok_or_else(|| "Binary rule byte count overflow".to_owned())?;
        let (evaluated, overlay_id) = if lexical_wrapper {
            let (evaluated, applied) = apply_compatibility_overlay(&path, &source)?;
            (evaluated, applied.then_some("nintendo-unused-var-tp-v1"))
        } else if compatibility_overlays {
            apply_binary_lifecycle_overlay(&path, &source)?
        } else {
            (source, None)
        };
        if let Some(id) = overlay_id {
            overlay_paths.push(json!({
                "id": id,
                "path": normalized_path(&path),
            }));
        }
        interrupt_ticks.store(0, Ordering::Relaxed);
        let eval_result = if lexical_wrapper {
            eval_rule_lexical(&context, &evaluated, false).map(|detect_type| {
                if detect_type != "function" {
                    non_function_detects.push(json!({
                        "index": index,
                        "name": name,
                        "type": detect_type,
                    }));
                }
            })
        } else {
            eval_unit(&context, &evaluated)
        };
        if let Err(error) = eval_result {
            errors.push(json!({"index": index, "name": name, "error": error}));
        }
    }
    let include_trace_text = eval_string(&context, b"JSON.stringify(__includeTrace)")?;
    let include_trace: Value = serde_json::from_str(&include_trace_text)
        .map_err(|error| format!("cannot parse include trace: {error}"))?;
    let overlay_ok = if lexical_wrapper {
        overlay_paths.len() == 1 && overlay_paths[0]["id"] == "nintendo-unused-var-tp-v1"
    } else if compatibility_overlays {
        overlay_paths.len() == 3
            && overlay_paths[0]["id"] == "audio-global-const-debug-v1"
            && overlay_paths[1]["id"] == "nintendo-unused-var-tp-v1"
            && overlay_paths[2]["id"] == "extensions-global-const-detect-v1"
    } else {
        overlay_paths.is_empty()
    };
    let passed = errors.is_empty() && non_function_detects.is_empty() && overlay_ok;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation": if lexical_wrapper {
                "fixed Linux Qt5 Binary lifecycle eval with per-rule lexical wrapper and Nintendo overlay"
            } else if compatibility_overlays {
                "fixed Linux Qt5 Binary top-level lifecycle eval with compatibility overlays"
            } else {
                "fixed Linux Qt5 Binary top-level lifecycle eval without compatibility overlays"
            },
            "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
            "upstream_commit": UPSTREAM_COMMIT,
            "rules_commit": RULES_COMMIT,
            "order_manifest": normalized_path(order_path),
            "order_sha256": LINUX_QT5_BINARY_ORDER_SHA256,
            "init_sequence": ["_init", "Binary/_init"],
            "include_trace": include_trace,
            "files": order.len(),
            "bytes": total_bytes,
            "compatibility_overlay": {
                "enabled": compatibility_overlays || lexical_wrapper,
                "applied_paths": overlay_paths,
                "expected_count": if lexical_wrapper {
                    1
                } else if compatibility_overlays {
                    3
                } else {
                    0
                },
                "applied_exactly": overlay_ok,
                "source_sha256": {
                    "audio-global-const-debug-v1": AUDIO_RULE_SHA256,
                    "nintendo-unused-var-tp-v1": NINTENDO_RULE_SHA256,
                    "extensions-global-const-detect-v1": EXTENSIONS_RULE_SHA256,
                },
            },
            "eval_errors": errors,
            "eval_error_count": errors.len(),
            "detect_function_count": order.len() - non_function_detects.len(),
            "non_function_detects": non_function_detects,
            "elapsed_ms": started.elapsed().as_millis(),
            "passed": passed,
            "scope": if lexical_wrapper {
                "per-rule function lexical wrapper; detect is resolved but not called"
            } else {
                "top-level eval only; detect functions are not called"
            },
        }))
        .map_err(|error| format!("cannot serialize report: {error}"))?
    );
    Ok(passed)
}

fn parse_scope_fixture_order(document: &Value) -> Result<Vec<String>, String> {
    let generator = document.get("generator").and_then(Value::as_str);
    if !matches!(
        generator,
        Some(
            "tools/corpus/generate_script_scope_fixture.py"
                | "tools/corpus/generate_script_state_fixture.py"
        )
    ) {
        return Err("unexpected script semantics fixture generator".to_owned());
    }
    let order = document
        .get("rule_order")
        .and_then(Value::as_array)
        .ok_or_else(|| "script-scope rule_order is missing".to_owned())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "script-scope rule_order contains a non-string".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if order.len() != 7 {
        return Err(format!(
            "expected 7 script-scope rules, got {}",
            order.len()
        ));
    }
    for name in &order {
        let path = Path::new(name);
        if path.file_name().and_then(|value| value.to_str()) != Some(name.as_str()) {
            return Err(format!("invalid script-scope rule name: {name}"));
        }
    }
    Ok(order)
}

fn parse_scope_detections(document: &Value) -> Result<Vec<Detection>, String> {
    document
        .get("detections")
        .and_then(Value::as_array)
        .ok_or_else(|| "Qt5 script-scope detections are missing".to_owned())?
        .iter()
        .map(|detection| {
            let field = |name| {
                detection
                    .get(name)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| format!("Qt5 script-scope detection field is missing: {name}"))
            };
            Ok((
                field("type")?,
                field("name")?,
                field("version")?,
                field("info")?,
            ))
        })
        .collect()
}

fn run_scope_fixture(
    fixture_root: &Path,
    manifest_path: &Path,
    qt5_baseline_path: &Path,
    lexical_wrapper: bool,
) -> Result<bool, String> {
    let manifest: Value = serde_json::from_slice(
        &fs::read(manifest_path)
            .map_err(|error| format!("cannot read {}: {error}", manifest_path.display()))?,
    )
    .map_err(|error| format!("cannot parse {}: {error}", manifest_path.display()))?;
    let order = parse_scope_fixture_order(&manifest)?;
    let qt5_baseline: Value = serde_json::from_slice(
        &fs::read(qt5_baseline_path)
            .map_err(|error| format!("cannot read {}: {error}", qt5_baseline_path.display()))?,
    )
    .map_err(|error| format!("cannot parse {}: {error}", qt5_baseline_path.display()))?;
    let qt5_detections = parse_scope_detections(&qt5_baseline)?;
    let runtime = new_runtime()?;
    let context = new_context(&runtime)?;
    let detections = Arc::new(Mutex::new(Vec::new()));
    install_nintendo_host(&context, Arc::new(Vec::new()), Arc::clone(&detections))?;

    let mut observations = Vec::new();
    for name in &order {
        let path = fixture_root.join("main").join("Binary").join(name);
        let source =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let before = detections
            .lock()
            .map_err(|_| "script-scope result mutex poisoned".to_owned())?
            .len();
        let lexical_result = if lexical_wrapper {
            Some(eval_rule_lexical(&context, &source, true))
        } else {
            None
        };
        let eval_result = if lexical_wrapper {
            lexical_result
                .as_ref()
                .expect("lexical result should be present")
                .as_ref()
                .map(|_| ())
                .map_err(Clone::clone)
        } else {
            eval_unit(&context, &source)
        };
        let detect_result = if lexical_wrapper {
            lexical_result
        } else if eval_result.is_ok() {
            Some(eval_string(
                &context,
                b"typeof detect === 'function' ? String(detect()) : 'not-function'",
            ))
        } else {
            None
        };
        let emitted = detections
            .lock()
            .map_err(|_| "script-scope result mutex poisoned".to_owned())?[before..]
            .to_vec();
        observations.push(json!({
            "name": name,
            "eval_accepted": eval_result.is_ok(),
            "eval_error": eval_result.err(),
            "detect_result": detect_result.map(|result| match result {
                Ok(value) => json!({"accepted": true, "value": value}),
                Err(error) => json!({"accepted": false, "error": error}),
            }),
            "detections": emitted,
        }));
    }

    let all_detections = detections
        .lock()
        .map_err(|_| "script-scope result mutex poisoned".to_owned())?
        .clone();
    let errors = observations
        .iter()
        .filter(|observation| observation["eval_accepted"] == false)
        .count();
    let matches_qt5_oracle = all_detections == qt5_detections;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation": if lexical_wrapper {
                "shared host/global context with per-rule lexical wrapper and immediate detect invocation"
            } else {
                "shared-context sequential sloppy eval and detect invocation"
            },
            "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
            "fixture_manifest": normalized_path(manifest_path),
            "qt5_baseline": normalized_path(qt5_baseline_path),
            "rule_order": order,
            "observations": observations,
            "eval_error_count": errors,
            "detections": all_detections,
            "matches_qt5_oracle": matches_qt5_oracle,
            "passed": true,
        }))
        .map_err(|error| format!("cannot serialize report: {error}"))?
    );
    Ok(true)
}

fn run_nintendo_rule(rule_root: &Path, data: Vec<u8>) -> Result<Vec<Detection>, String> {
    let runtime = new_runtime()?;
    let context = new_context(&runtime)?;
    let detections = Arc::new(Mutex::new(Vec::new()));
    install_nintendo_host(&context, Arc::new(data), Arc::clone(&detections))?;
    install_main_include_registry(&context, rule_root)?;

    for relative in ["_init", "Binary/_init"] {
        let path = rule_root.join(relative);
        let bytes =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        eval_unit(&context, &bytes)
            .map_err(|error| format!("cannot eval {}: {error}", path.display()))?;
    }
    let include_trace = eval_string(&context, b"JSON.stringify(__includeTrace)")?;
    if include_trace != r#"["_debug","_runtime_helpers","language","read"]"# {
        return Err(format!("unexpected init include trace: {include_trace}"));
    }

    let rule_path = rule_root
        .join("Binary")
        .join("format_bin.Nintendo-certified-file.1.sg");
    let source = fs::read(&rule_path)
        .map_err(|error| format!("cannot read {}: {error}", rule_path.display()))?;
    let (transformed, applied) = apply_compatibility_overlay(&rule_path, &source)?;
    if !applied {
        return Err("Nintendo compatibility overlay was not applied".to_owned());
    }
    eval_unit(&context, &transformed)?;
    let detected = eval_string(&context, b"String(detect())")?;
    if detected != "true" {
        let probe = eval_string(
            &context,
            br#"JSON.stringify([
                X.c("'SCE'00"),
                X.U16(8, X.c("0000 0002", 4) ? _BE : _LE),
                X.U16(0xA, X.c("0000 0002", 4) ? _BE : _LE),
                X.U64(0x10, X.c("0000 0002", 4) ? _BE : _LE),
                X.Sz()
            ])"#,
        )?;
        return Err(format!(
            "Nintendo detect returned {detected}; probe={probe}"
        ));
    }

    let result = detections
        .lock()
        .map_err(|_| "Nintendo fixture result mutex poisoned".to_owned())?
        .clone();
    Ok(result)
}

fn run_nintendo_corpus(
    rule_root: &Path,
    corpus_root: &Path,
    baseline_path: &Path,
) -> Result<bool, String> {
    let baseline: Value = serde_json::from_slice(
        &fs::read(baseline_path)
            .map_err(|error| format!("cannot read {}: {error}", baseline_path.display()))?,
    )
    .map_err(|error| format!("cannot parse {}: {error}", baseline_path.display()))?;
    let samples = baseline
        .get("samples")
        .and_then(Value::as_object)
        .ok_or_else(|| "Nintendo baseline has no samples object".to_owned())?;
    let mut names = samples.keys().cloned().collect::<Vec<_>>();
    names.sort();
    let mut reports = Vec::new();
    let mut all_match = true;

    for name in names {
        let sample = &samples[&name];
        let expected = sample
            .get("detections")
            .and_then(Value::as_array)
            .and_then(|detections| detections.first())
            .and_then(Value::as_array)
            .ok_or_else(|| format!("Nintendo baseline sample {name} has no detection"))?;
        let expected_tuple = (
            expected[0].as_str().unwrap_or_default().to_owned(),
            expected[1].as_str().unwrap_or_default().to_owned(),
            expected[2].as_str().unwrap_or_default().to_owned(),
            "fSELF".to_owned(),
        );
        let input_path = corpus_root.join(&name);
        let actual = run_nintendo_rule(
            rule_root,
            fs::read(&input_path)
                .map_err(|error| format!("cannot read {}: {error}", input_path.display()))?,
        )
        .map_err(|error| format!("{name}: {error}"))?;
        let matches = actual == [expected_tuple.clone()];
        all_match &= matches;
        reports.push(json!({
            "name": name,
            "expected": expected_tuple,
            "actual": actual,
            "matches": matches,
        }));
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation": "Nintendo rule detect with Rust byte HostApi",
            "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
            "compatibility_overlay": "nintendo-unused-var-tp-v1",
            "init_sequence": ["_init", "Binary/_init"],
            "include_trace": ["_debug", "_runtime_helpers", "language", "read"],
            "host_methods": [
                "X.c", "X.U16", "X.U32", "X.U64", "X.Sz",
                "X.isHeuristicScan", "X.isVerbose", "_setResult"
            ],
            "samples": reports,
            "sample_count": samples.len(),
            "matched_count": reports.iter().filter(|item| item["matches"] == true).count(),
            "all_match": all_match,
        }))
        .map_err(|error| format!("cannot serialize report: {error}"))?
    );
    Ok(all_match)
}

fn run_nintendo_lifecycle_rule(
    rule_root: &Path,
    order: &[String],
    data: Vec<u8>,
) -> Result<NintendoLifecycleResult, String> {
    let expect_ea_xa = data.get(4..8) == Some(b"\x03\0\0\0");
    let runtime = new_runtime()?;
    let context = new_context(&runtime)?;
    let detections = Arc::new(Mutex::new(Vec::new()));
    install_nintendo_host(&context, Arc::new(data), Arc::clone(&detections))?;
    install_host_fallbacks(&context)?;
    install_main_include_registry(&context, rule_root)?;
    for relative in ["_init", "Binary/_init"] {
        let path = rule_root.join(relative);
        let source =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        eval_unit(&context, &source)
            .map_err(|error| format!("cannot eval {}: {error}", path.display()))?;
    }
    install_selected_host_trace(&context)?;

    let selected = [
        "archive_DEFLATE.1.sg",
        "audio_EXA.1.sg",
        "format_bin.Nintendo-certified-file.1.sg",
    ];
    let mut invoked = Vec::new();
    let mut overlay_count = 0;
    for name in order {
        let path = rule_root.join("Binary").join(name);
        let source =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let (evaluated, applied) = apply_compatibility_overlay(&path, &source)?;
        overlay_count += usize::from(applied);
        let invoke = selected.contains(&name.as_str());
        let fallback_before = if invoke {
            eval_unit(&context, b"__selectedHostTrace = [];")?;
            Some(eval_string(&context, b"String(__fallbackCalls.length)")?)
        } else {
            None
        };
        let detect_result = eval_rule_lexical(&context, &evaluated, invoke)
            .map_err(|error| format!("cannot eval {name}: {error}"))?;
        if invoke {
            let fallback_after = eval_string(&context, b"String(__fallbackCalls.length)")?;
            if fallback_before.as_deref() != Some(fallback_after.as_str()) {
                let calls = eval_string(&context, b"JSON.stringify(__fallbackCalls)")?;
                return Err(format!(
                    "{name}: selected detect used fallback HostApi: {calls}"
                ));
            }
            if name == "audio_EXA.1.sg" && (detect_result == "true") != expect_ea_xa {
                let trace = eval_string(&context, b"JSON.stringify(__selectedHostTrace)")?;
                return Err(format!(
                    "{name}: expected detect={expect_ea_xa}, got {detect_result}; trace={trace}"
                ));
            }
            invoked.push(name.clone());
        }
    }
    if invoked != selected {
        return Err(format!("unexpected selected rule order: {invoked:?}"));
    }
    let include_trace_text = eval_string(&context, b"JSON.stringify(__includeTrace)")?;
    let include_trace: Vec<String> = serde_json::from_str(&include_trace_text)
        .map_err(|error| format!("cannot parse include trace: {error}"))?;
    let result = detections
        .lock()
        .map_err(|_| "Nintendo lifecycle result mutex poisoned".to_owned())?
        .clone();
    let fallback_calls_text = eval_string(&context, b"JSON.stringify(__fallbackCalls)")?;
    let fallback_calls = serde_json::from_str(&fallback_calls_text)
        .map_err(|error| format!("cannot parse fallback calls: {error}"))?;
    Ok((result, include_trace, overlay_count, fallback_calls))
}

fn run_nintendo_lifecycle_corpus(
    rule_root: &Path,
    corpus_root: &Path,
    baseline_path: &Path,
    order_path: &Path,
) -> Result<bool, String> {
    let baseline: Value = serde_json::from_slice(
        &fs::read(baseline_path)
            .map_err(|error| format!("cannot read {}: {error}", baseline_path.display()))?,
    )
    .map_err(|error| format!("cannot parse {}: {error}", baseline_path.display()))?;
    let order_document: Value = serde_json::from_slice(
        &fs::read(order_path)
            .map_err(|error| format!("cannot read {}: {error}", order_path.display()))?,
    )
    .map_err(|error| format!("cannot parse {}: {error}", order_path.display()))?;
    let order = parse_binary_order(&order_document)?;
    let samples = baseline
        .get("samples")
        .and_then(Value::as_object)
        .ok_or_else(|| "Nintendo baseline has no samples object".to_owned())?;
    let mut names = samples.keys().cloned().collect::<Vec<_>>();
    names.sort();
    let mut reports = Vec::new();
    let mut all_match = true;
    let mut common_include_trace: Option<Vec<String>> = None;

    for name in names {
        let expected = samples[&name]
            .get("detections")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("Nintendo baseline sample {name} has no detections"))?
            .iter()
            .map(|detection| {
                let fields = detection
                    .as_array()
                    .ok_or_else(|| format!("invalid baseline detection for {name}"))?;
                Ok((
                    fields[0].as_str().unwrap_or_default().to_owned(),
                    fields[1].as_str().unwrap_or_default().to_owned(),
                    fields[2].as_str().unwrap_or_default().to_owned(),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let input_path = corpus_root.join(&name);
        let (actual, include_trace, overlay_count, fallback_calls) = run_nintendo_lifecycle_rule(
            rule_root,
            &order,
            fs::read(&input_path)
                .map_err(|error| format!("cannot read {}: {error}", input_path.display()))?,
        )
        .map_err(|error| format!("{name}: {error}"))?;
        if include_trace.len() != 30 {
            return Err(format!(
                "{name}: expected 30 includes, got {}",
                include_trace.len()
            ));
        }
        if let Some(common) = &common_include_trace {
            if common != &include_trace {
                return Err(format!("{name}: include trace differs between samples"));
            }
        } else {
            common_include_trace = Some(include_trace);
        }
        if overlay_count != 1 {
            return Err(format!(
                "{name}: expected one Nintendo overlay, got {overlay_count}"
            ));
        }
        let execution_order = actual
            .iter()
            .map(|(kind, detection_name, version, _)| {
                (kind.clone(), detection_name.clone(), version.clone())
            })
            .collect::<Vec<_>>();
        let mut output_order = execution_order.clone();
        output_order.sort_by_key(|(kind, _, _)| match kind.as_str() {
            "format" => 0,
            "audio" => 1,
            _ => 2,
        });
        let nintendo_info_ok = actual
            .iter()
            .filter(|(kind, _, _, _)| kind == "format")
            .all(|(_, _, _, info)| info == "fSELF");
        let matches = output_order == expected && nintendo_info_ok;
        all_match &= matches;
        reports.push(json!({
            "name": name,
            "expected_output_order": expected,
            "actual_execution_order": execution_order,
            "actual_output_order": output_order,
            "nintendo_info_ok": nintendo_info_ok,
            "non_target_top_level_fallback_calls": fallback_calls,
            "matches": matches,
        }));
    }
    let include_trace = common_include_trace.unwrap_or_default();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation": "fixed 292-rule Binary load with selected shared-state, EA-XA, and Nintendo detect invocation",
            "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
            "compatibility_overlay": "nintendo-unused-var-tp-v1",
            "order_manifest": normalized_path(order_path),
            "order_sha256": LINUX_QT5_BINARY_ORDER_SHA256,
            "rule_count": order.len(),
            "selected_rules": [
                "archive_DEFLATE.1.sg",
                "audio_EXA.1.sg",
                "format_bin.Nintendo-certified-file.1.sg"
            ],
            "include_trace": include_trace,
            "include_call_count": include_trace.len(),
            "output_projection": "target-only type order: format, audio",
            "samples": reports,
            "sample_count": samples.len(),
            "matched_count": reports.iter().filter(|item| item["matches"] == true).count(),
            "all_match": all_match,
        }))
        .map_err(|error| format!("cannot serialize report: {error}"))?
    );
    Ok(all_match)
}

fn trace_binary_detects_report_with_data(
    rule_root: &Path,
    input_path: &Path,
    order_path: &Path,
    data: Vec<u8>,
) -> Result<Value, String> {
    trace_binary_detects_report_with_data_and_tracking(
        rule_root, input_path, order_path, data, None,
    )
}

fn trace_binary_detects_report_with_data_and_tracking(
    rule_root: &Path,
    input_path: &Path,
    order_path: &Path,
    data: Vec<u8>,
    tracking_limit_bytes: Option<usize>,
) -> Result<Value, String> {
    let order_document: Value = serde_json::from_slice(
        &fs::read(order_path)
            .map_err(|error| format!("cannot read {}: {error}", order_path.display()))?,
    )
    .map_err(|error| format!("cannot parse {}: {error}", order_path.display()))?;
    let order = parse_binary_order(&order_document)?;
    let input_size = data.len();
    let (runtime, tracking_stats) = if let Some(limit) = tracking_limit_bytes {
        let (runtime, stats) = new_tracking_runtime(limit)?;
        (runtime, Some(stats))
    } else {
        (new_runtime()?, None)
    };
    let runtime_created_memory = runtime_memory_snapshot(&runtime)?;
    let interrupt_ticks_per_rule = Arc::new(AtomicUsize::new(0));
    let interrupt_ticks_per_rule_for_handler = Arc::clone(&interrupt_ticks_per_rule);
    let interrupt_ticks_total = Arc::new(AtomicUsize::new(0));
    let interrupt_ticks_total_for_handler = Arc::clone(&interrupt_ticks_total);
    runtime.set_interrupt_handler(Some(Box::new(move || {
        interrupt_ticks_total_for_handler.fetch_add(1, Ordering::Relaxed);
        interrupt_ticks_per_rule_for_handler.fetch_add(1, Ordering::Relaxed) >= 1_000_000
    })));
    let context = new_context(&runtime)?;
    let detections = Arc::new(Mutex::new(Vec::new()));
    let signature_trace = install_nintendo_host_for_path(
        &context,
        Arc::new(data),
        Arc::clone(&detections),
        input_path,
    )?;
    install_diagnostic_host_fallbacks(&context)?;
    install_main_include_registry(&context, rule_root)?;
    for relative in ["_init", "Binary/_init"] {
        let path = rule_root.join(relative);
        let source =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        eval_unit(&context, &source)
            .map_err(|error| format!("cannot eval {}: {error}", path.display()))?;
    }
    let initialized_memory = runtime_memory_snapshot(&runtime)?;
    let mut maximum_malloc_size = runtime_created_memory.malloc_size;
    let mut maximum_malloc_size_stage = "runtime_created".to_owned();
    let mut maximum_memory_used_size = runtime_created_memory.memory_used_size;
    let mut maximum_memory_used_size_stage = "runtime_created".to_owned();
    if initialized_memory.malloc_size > maximum_malloc_size {
        maximum_malloc_size = initialized_memory.malloc_size;
        maximum_malloc_size_stage = "initialized".to_owned();
    }
    if initialized_memory.memory_used_size > maximum_memory_used_size {
        maximum_memory_used_size = initialized_memory.memory_used_size;
        maximum_memory_used_size_stage = "initialized".to_owned();
    }
    let mut memory_checkpoint_count = 2_u64;

    let started = Instant::now();
    let mut observations = Vec::with_capacity(order.len());
    let mut overlay_count = 0;
    let mut error_count = 0;
    let mut fallback_rule_count = 0;
    let mut fallback_call_total = 0_u64;
    let mut fallback_paths = BTreeSet::new();
    let mut detect_interrupt_handler_call_sum = 0_u64;
    let mut maximum_interrupt_handler_calls_per_rule = 0_u64;
    for (index, name) in order.iter().enumerate() {
        let path = rule_root.join("Binary").join(name);
        let source =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let (evaluated, applied) = apply_compatibility_overlay(&path, &source)?;
        overlay_count += usize::from(applied);
        eval_unit(&context, b"__fallbackCalls = []; __fallbackTotal = 0;")?;
        let detections_before = detections
            .lock()
            .map_err(|_| "Binary trace result mutex poisoned".to_owned())?
            .len();
        let signature_calls_before = signature_trace.calls.load(Ordering::Relaxed);
        let compare_native_checkpoints_before = signature_trace
            .compare_native_checkpoints
            .load(Ordering::Relaxed);
        let signature_fast_paths_before = signature_trace.fast_paths.load(Ordering::Relaxed);
        let signature_generic_paths_before = signature_trace.generic_paths.load(Ordering::Relaxed);
        let signature_quirks_before = signature_trace.quirks.load(Ordering::Relaxed);
        let signature_errors_before = signature_trace.errors.load(Ordering::Relaxed);
        let signature_search_calls_before = signature_trace.search_calls.load(Ordering::Relaxed);
        let search_native_checkpoints_before = signature_trace
            .search_native_checkpoints
            .load(Ordering::Relaxed);
        let signature_find_signature_calls_before =
            signature_trace.find_signature_calls.load(Ordering::Relaxed);
        let signature_f_sig_calls_before = signature_trace.f_sig_calls.load(Ordering::Relaxed);
        let signature_is_signature_present_calls_before = signature_trace
            .is_signature_present_calls
            .load(Ordering::Relaxed);
        let signature_search_matches_before =
            signature_trace.search_matches.load(Ordering::Relaxed);
        let signature_search_quirks_before = signature_trace.search_quirks.load(Ordering::Relaxed);
        let signature_search_errors_before = signature_trace.search_errors.load(Ordering::Relaxed);
        let is_overlay_calls_before = signature_trace.is_overlay_calls.load(Ordering::Relaxed);
        let get_overlay_offset_calls_before = signature_trace
            .get_overlay_offset_calls
            .load(Ordering::Relaxed);
        let get_overlay_size_calls_before = signature_trace
            .get_overlay_size_calls
            .load(Ordering::Relaxed);
        let is_overlay_present_calls_before = signature_trace
            .is_overlay_present_calls
            .load(Ordering::Relaxed);
        let get_file_suffix_calls_before = signature_trace
            .get_file_suffix_calls
            .load(Ordering::Relaxed);
        let get_header_string_calls_before = signature_trace
            .get_header_string_calls
            .load(Ordering::Relaxed);
        let is_plain_text_calls_before =
            signature_trace.is_plain_text_calls.load(Ordering::Relaxed);
        let is_utf8_text_calls_before = signature_trace.is_utf8_text_calls.load(Ordering::Relaxed);
        let is_unicode_text_calls_before = signature_trace
            .is_unicode_text_calls
            .load(Ordering::Relaxed);
        let is_text_calls_before = signature_trace.is_text_calls.load(Ordering::Relaxed);
        let get_scan_id_calls_before = signature_trace.get_scan_id_calls.load(Ordering::Relaxed);
        let is_resource_calls_before = signature_trace.is_resource_calls.load(Ordering::Relaxed);
        let is_debug_data_calls_before =
            signature_trace.is_debug_data_calls.load(Ordering::Relaxed);
        let is_file_part_calls_before = signature_trace.is_file_part_calls.load(Ordering::Relaxed);
        interrupt_ticks_per_rule.store(0, Ordering::Relaxed);
        let detect_result = eval_rule_lexical(&context, &evaluated, true);
        let signature_call_count = signature_trace
            .calls
            .load(Ordering::Relaxed)
            .saturating_sub(signature_calls_before);
        let compare_native_checkpoint_count = signature_trace
            .compare_native_checkpoints
            .load(Ordering::Relaxed)
            .saturating_sub(compare_native_checkpoints_before);
        let signature_fast_path_count = signature_trace
            .fast_paths
            .load(Ordering::Relaxed)
            .saturating_sub(signature_fast_paths_before);
        let signature_generic_path_count = signature_trace
            .generic_paths
            .load(Ordering::Relaxed)
            .saturating_sub(signature_generic_paths_before);
        let signature_quirk_count = signature_trace
            .quirks
            .load(Ordering::Relaxed)
            .saturating_sub(signature_quirks_before);
        let signature_error_count = signature_trace
            .errors
            .load(Ordering::Relaxed)
            .saturating_sub(signature_errors_before);
        let signature_search_call_count = signature_trace
            .search_calls
            .load(Ordering::Relaxed)
            .saturating_sub(signature_search_calls_before);
        let search_native_checkpoint_count = signature_trace
            .search_native_checkpoints
            .load(Ordering::Relaxed)
            .saturating_sub(search_native_checkpoints_before);
        let signature_find_signature_call_count = signature_trace
            .find_signature_calls
            .load(Ordering::Relaxed)
            .saturating_sub(signature_find_signature_calls_before);
        let signature_f_sig_call_count = signature_trace
            .f_sig_calls
            .load(Ordering::Relaxed)
            .saturating_sub(signature_f_sig_calls_before);
        let signature_is_signature_present_call_count = signature_trace
            .is_signature_present_calls
            .load(Ordering::Relaxed)
            .saturating_sub(signature_is_signature_present_calls_before);
        let signature_search_match_count = signature_trace
            .search_matches
            .load(Ordering::Relaxed)
            .saturating_sub(signature_search_matches_before);
        let signature_search_quirk_count = signature_trace
            .search_quirks
            .load(Ordering::Relaxed)
            .saturating_sub(signature_search_quirks_before);
        let signature_search_error_count = signature_trace
            .search_errors
            .load(Ordering::Relaxed)
            .saturating_sub(signature_search_errors_before);
        let is_overlay_call_count = signature_trace
            .is_overlay_calls
            .load(Ordering::Relaxed)
            .saturating_sub(is_overlay_calls_before);
        let get_overlay_offset_call_count = signature_trace
            .get_overlay_offset_calls
            .load(Ordering::Relaxed)
            .saturating_sub(get_overlay_offset_calls_before);
        let get_overlay_size_call_count = signature_trace
            .get_overlay_size_calls
            .load(Ordering::Relaxed)
            .saturating_sub(get_overlay_size_calls_before);
        let is_overlay_present_call_count = signature_trace
            .is_overlay_present_calls
            .load(Ordering::Relaxed)
            .saturating_sub(is_overlay_present_calls_before);
        let get_file_suffix_call_count = signature_trace
            .get_file_suffix_calls
            .load(Ordering::Relaxed)
            .saturating_sub(get_file_suffix_calls_before);
        let get_header_string_call_count = signature_trace
            .get_header_string_calls
            .load(Ordering::Relaxed)
            .saturating_sub(get_header_string_calls_before);
        let is_plain_text_call_count = signature_trace
            .is_plain_text_calls
            .load(Ordering::Relaxed)
            .saturating_sub(is_plain_text_calls_before);
        let is_utf8_text_call_count = signature_trace
            .is_utf8_text_calls
            .load(Ordering::Relaxed)
            .saturating_sub(is_utf8_text_calls_before);
        let is_unicode_text_call_count = signature_trace
            .is_unicode_text_calls
            .load(Ordering::Relaxed)
            .saturating_sub(is_unicode_text_calls_before);
        let is_text_call_count = signature_trace
            .is_text_calls
            .load(Ordering::Relaxed)
            .saturating_sub(is_text_calls_before);
        let get_scan_id_call_count = signature_trace
            .get_scan_id_calls
            .load(Ordering::Relaxed)
            .saturating_sub(get_scan_id_calls_before);
        let is_resource_call_count = signature_trace
            .is_resource_calls
            .load(Ordering::Relaxed)
            .saturating_sub(is_resource_calls_before);
        let is_debug_data_call_count = signature_trace
            .is_debug_data_calls
            .load(Ordering::Relaxed)
            .saturating_sub(is_debug_data_calls_before);
        let is_file_part_call_count = signature_trace
            .is_file_part_calls
            .load(Ordering::Relaxed)
            .saturating_sub(is_file_part_calls_before);
        let interrupt_handler_calls =
            u64::try_from(interrupt_ticks_per_rule.load(Ordering::Relaxed))
                .map_err(|_| "per-rule interrupt handler count exceeds u64".to_owned())?;
        detect_interrupt_handler_call_sum = detect_interrupt_handler_call_sum
            .checked_add(interrupt_handler_calls)
            .ok_or_else(|| "detect interrupt handler call sum overflow".to_owned())?;
        maximum_interrupt_handler_calls_per_rule =
            maximum_interrupt_handler_calls_per_rule.max(interrupt_handler_calls);
        let fallback_text = eval_string(
            &context,
            b"JSON.stringify({calls: __fallbackCalls, total: __fallbackTotal})",
        )?;
        let fallback: Value = serde_json::from_str(&fallback_text)
            .map_err(|error| format!("cannot parse fallback report for {name}: {error}"))?;
        let memory_after_rule = runtime_memory_snapshot(&runtime)?;
        memory_checkpoint_count = memory_checkpoint_count
            .checked_add(1)
            .ok_or_else(|| "runtime memory checkpoint count overflow".to_owned())?;
        let memory_stage = format!("after_rule:{index}:{name}");
        if memory_after_rule.malloc_size > maximum_malloc_size {
            maximum_malloc_size = memory_after_rule.malloc_size;
            maximum_malloc_size_stage = memory_stage.clone();
        }
        if memory_after_rule.memory_used_size > maximum_memory_used_size {
            maximum_memory_used_size = memory_after_rule.memory_used_size;
            maximum_memory_used_size_stage = memory_stage;
        }
        let fallback_total = fallback
            .get("total")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("fallback total is missing for {name}"))?;
        let calls = fallback
            .get("calls")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("fallback calls are missing for {name}"))?;
        for call in calls {
            if let Some(path) = call.as_str() {
                fallback_paths.insert(path.to_owned());
            }
        }
        fallback_call_total = fallback_call_total
            .checked_add(fallback_total)
            .ok_or_else(|| "fallback call total overflow".to_owned())?;
        fallback_rule_count += usize::from(fallback_total != 0);
        let detect_accepted = detect_result.is_ok();
        error_count += usize::from(!detect_accepted);
        let (detect_value, detect_error) = match detect_result {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error)),
        };
        let emitted = detections
            .lock()
            .map_err(|_| "Binary trace result mutex poisoned".to_owned())?[detections_before..]
            .to_vec();
        observations.push(json!({
            "index": index,
            "name": name,
            "accepted": detect_accepted,
            "detect_result": detect_value,
            "error": detect_error,
            "fallback_call_count": fallback_total,
            "fallback_calls": calls,
            "fallback_calls_truncated": fallback_total > calls.len() as u64,
            "signature_compare_call_count": signature_call_count,
            "signature_compare_native_checkpoint_count":
                compare_native_checkpoint_count,
            "signature_compare_fast_path_count": signature_fast_path_count,
            "signature_compare_generic_path_count": signature_generic_path_count,
            "signature_compare_quirk_count": signature_quirk_count,
            "signature_compare_error_count": signature_error_count,
            "signature_search_call_count": signature_search_call_count,
            "signature_search_native_checkpoint_count":
                search_native_checkpoint_count,
            "signature_find_signature_call_count": signature_find_signature_call_count,
            "signature_f_sig_call_count": signature_f_sig_call_count,
            "signature_is_signature_present_call_count":
                signature_is_signature_present_call_count,
            "signature_search_match_count": signature_search_match_count,
            "signature_search_quirk_count": signature_search_quirk_count,
            "signature_search_error_count": signature_search_error_count,
            "overlay_host_calls": {
                "is_overlay": is_overlay_call_count,
                "get_overlay_offset": get_overlay_offset_call_count,
                "get_overlay_size": get_overlay_size_call_count,
                "is_overlay_present": is_overlay_present_call_count,
            },
            "string_host_calls": {
                "get_file_suffix": get_file_suffix_call_count,
                "get_header_string": get_header_string_call_count,
                "is_plain_text": is_plain_text_call_count,
                "is_utf8_text": is_utf8_text_call_count,
                "is_unicode_text": is_unicode_text_call_count,
                "is_text": is_text_call_count,
            },
            "context_host_calls": {
                "get_scan_id": get_scan_id_call_count,
                "is_resource": is_resource_call_count,
                "is_debug_data": is_debug_data_call_count,
                "is_file_part": is_file_part_call_count,
            },
            "interrupt_handler_calls": interrupt_handler_calls,
            "runtime_memory_after_rule": memory_after_rule.to_json(),
            "detections": emitted,
        }));
    }
    let all_detections = detections
        .lock()
        .map_err(|_| "Binary trace result mutex poisoned".to_owned())?
        .clone();
    let include_trace_text = eval_string(&context, b"JSON.stringify(__includeTrace)")?;
    let include_trace: Value = serde_json::from_str(&include_trace_text)
        .map_err(|error| format!("cannot parse include trace: {error}"))?;
    let final_memory = runtime_memory_snapshot(&runtime)?;
    memory_checkpoint_count = memory_checkpoint_count
        .checked_add(1)
        .ok_or_else(|| "runtime memory checkpoint count overflow".to_owned())?;
    if final_memory.malloc_size > maximum_malloc_size {
        maximum_malloc_size = final_memory.malloc_size;
        maximum_malloc_size_stage = "after_final_reporting".to_owned();
    }
    if final_memory.memory_used_size > maximum_memory_used_size {
        maximum_memory_used_size = final_memory.memory_used_size;
        maximum_memory_used_size_stage = "after_final_reporting".to_owned();
    }
    let interrupt_handler_call_total = u64::try_from(interrupt_ticks_total.load(Ordering::Relaxed))
        .map_err(|_| "total interrupt handler count exceeds u64".to_owned())?;
    let interrupt_handler_calls_outside_detects = interrupt_handler_call_total
        .checked_sub(detect_interrupt_handler_call_sum)
        .ok_or_else(|| "interrupt handler call partition underflow".to_owned())?;
    let include_call_count = include_trace.as_array().map_or(0, Vec::len);
    let signature_unique_quirks = signature_trace
        .unique_quirks
        .lock()
        .map_err(|_| "signature quirk mutex poisoned".to_owned())?
        .clone();
    let signature_unique_errors = signature_trace
        .unique_errors
        .lock()
        .map_err(|_| "signature error mutex poisoned".to_owned())?
        .clone();
    let signature_search_unique_quirks = signature_trace
        .search_unique_quirks
        .lock()
        .map_err(|_| "signature search quirk mutex poisoned".to_owned())?
        .clone();
    let signature_search_unique_errors = signature_trace
        .search_unique_errors
        .lock()
        .map_err(|_| "signature search error mutex poisoned".to_owned())?
        .clone();
    let overlay_host_call_totals = json!({
        "is_overlay": signature_trace.is_overlay_calls.load(Ordering::Relaxed),
        "get_overlay_offset": signature_trace.get_overlay_offset_calls.load(Ordering::Relaxed),
        "get_overlay_size": signature_trace.get_overlay_size_calls.load(Ordering::Relaxed),
        "is_overlay_present": signature_trace.is_overlay_present_calls.load(Ordering::Relaxed),
    });
    let string_host_call_totals = json!({
        "get_file_suffix": signature_trace.get_file_suffix_calls.load(Ordering::Relaxed),
        "get_header_string": signature_trace.get_header_string_calls.load(Ordering::Relaxed),
        "is_plain_text": signature_trace.is_plain_text_calls.load(Ordering::Relaxed),
        "is_utf8_text": signature_trace.is_utf8_text_calls.load(Ordering::Relaxed),
        "is_unicode_text": signature_trace.is_unicode_text_calls.load(Ordering::Relaxed),
        "is_text": signature_trace.is_text_calls.load(Ordering::Relaxed),
    });
    let context_host_call_totals = json!({
        "get_scan_id": signature_trace.get_scan_id_calls.load(Ordering::Relaxed),
        "is_resource": signature_trace.is_resource_calls.load(Ordering::Relaxed),
        "is_debug_data": signature_trace.is_debug_data_calls.load(Ordering::Relaxed),
        "is_file_part": signature_trace.is_file_part_calls.load(Ordering::Relaxed),
    });
    let compare_native_checkpoint_total = signature_trace
        .compare_native_checkpoints
        .load(Ordering::Relaxed);
    let search_native_checkpoint_total = signature_trace
        .search_native_checkpoints
        .load(Ordering::Relaxed);
    let native_checkpoint_total = compare_native_checkpoint_total
        .checked_add(search_native_checkpoint_total)
        .ok_or_else(|| "native checkpoint total overflow".to_owned())?;
    let mut report = json!({
        "schema_version": 1,
        "operation": "diagnostic invocation of all fixed-order Binary detect functions",
        "scope": "fallback-tolerant gap inventory; detections are not compatibility evidence",
        "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
        "input": {
            "path": normalized_path(input_path),
            "bytes": input_size,
        },
        "order_manifest": normalized_path(order_path),
        "order_sha256": LINUX_QT5_BINARY_ORDER_SHA256,
        "rule_count": order.len(),
        "attempted_detect_count": observations.len(),
        "accepted_detect_count": observations.len() - error_count,
        "detect_error_count": error_count,
        "compatibility_overlay_count": overlay_count,
        "include_trace": include_trace,
        "include_call_count": include_call_count,
        "fallback_rule_count": fallback_rule_count,
        "fallback_call_total": fallback_call_total,
        "fallback_paths": fallback_paths,
        "signature_compare_call_total": signature_trace.calls.load(Ordering::Relaxed),
        "signature_compare_native_checkpoint_total":
            compare_native_checkpoint_total,
        "signature_compare_fast_path_total":
            signature_trace.fast_paths.load(Ordering::Relaxed),
        "signature_compare_generic_path_total":
            signature_trace.generic_paths.load(Ordering::Relaxed),
        "signature_compare_quirk_total": signature_trace.quirks.load(Ordering::Relaxed),
        "signature_compare_error_total": signature_trace.errors.load(Ordering::Relaxed),
        "signature_compare_unique_quirks": signature_unique_quirks,
        "signature_compare_unique_errors": signature_unique_errors,
        "signature_search_call_total": signature_trace.search_calls.load(Ordering::Relaxed),
        "signature_search_native_checkpoint_total":
            search_native_checkpoint_total,
        "signature_find_signature_call_total":
            signature_trace.find_signature_calls.load(Ordering::Relaxed),
        "signature_f_sig_call_total": signature_trace.f_sig_calls.load(Ordering::Relaxed),
        "signature_is_signature_present_call_total":
            signature_trace.is_signature_present_calls.load(Ordering::Relaxed),
        "signature_search_match_total":
            signature_trace.search_matches.load(Ordering::Relaxed),
        "signature_search_quirk_total":
            signature_trace.search_quirks.load(Ordering::Relaxed),
        "signature_search_error_total":
            signature_trace.search_errors.load(Ordering::Relaxed),
        "signature_search_unique_quirks": signature_search_unique_quirks,
        "signature_search_unique_errors": signature_search_unique_errors,
        "overlay_host_call_totals": overlay_host_call_totals,
        "string_host_call_totals": string_host_call_totals,
        "context_host_call_totals": context_host_call_totals,
        "detection_count": all_detections.len(),
        "detections": all_detections,
        "observations": observations,
        "interrupt_handler_call_limit_per_rule": 1_000_000,
        "runtime_measurement": {
            "native_checkpoint": {
                "semantics":
                    "one callback at each Binary signature compare/search entry and then before every 4096th searched candidate position within the same native call",
                "candidate_interval": NATIVE_CHECKPOINT_INTERVAL,
                "call_total": native_checkpoint_total,
                "compare_call_total": compare_native_checkpoint_total,
                "search_call_total": search_native_checkpoint_total,
                "can_interrupt_single_native_call": true,
            },
            "interrupt": {
                "handler_semantics":
                    "one QuickJS-NG interrupt callback invocation; counter is monotonic for the sample runtime",
                "handler_call_total": interrupt_handler_call_total,
                "detect_handler_call_sum": detect_interrupt_handler_call_sum,
                "handler_calls_outside_detects": interrupt_handler_calls_outside_detects,
                "maximum_handler_calls_per_rule":
                    maximum_interrupt_handler_calls_per_rule,
            },
            "memory": {
                "api": "rquickjs Runtime::memory_usage / QuickJS-NG JS_ComputeMemoryUsage",
                "scope":
                    "post-operation lifecycle checkpoints; transient in-eval allocator high-water is not observed",
                "checkpoint_count": memory_checkpoint_count,
                "runtime_created": runtime_created_memory.to_json(),
                "initialized": initialized_memory.to_json(),
                "after_final_reporting": final_memory.to_json(),
                "maximum_observed_malloc_size": {
                    "bytes": maximum_malloc_size,
                    "stage": maximum_malloc_size_stage,
                },
                "maximum_observed_memory_used_size": {
                    "bytes": maximum_memory_used_size,
                    "stage": maximum_memory_used_size_stage,
                },
                "transient_high_water_measured": false,
            },
        },
        "elapsed_ms": started.elapsed().as_millis(),
        "completed": true,
    });
    let tracking_before_drop = tracking_stats.as_ref().map(|stats| {
        (
            stats.live_bytes(),
            stats.high_water_bytes(),
            stats.denied_allocation_count(),
        )
    });
    drop(context);
    drop(runtime);
    if let (Some(limit_bytes), Some(stats), Some((live_before_drop, high_water_bytes, denied))) =
        (tracking_limit_bytes, tracking_stats, tracking_before_drop)
    {
        let live_after_drop = stats.live_bytes();
        report["runtime_measurement"]["memory"]["scope"] = json!(
            "post-operation lifecycle checkpoints plus allocator-observed transient live-byte high-water"
        );
        report["runtime_measurement"]["memory"]["transient_high_water_measured"] = json!(true);
        report["runtime_measurement"]["memory"]["tracking_allocator"] = json!({
            "backend": "rquickjs RustAllocator wrapped by TrackingLimitAllocator",
            "limit_bytes": limit_bytes,
            "set_memory_limit_used": false,
            "accounting": "RustAllocator allocation Layout bytes: aligned payload plus internal header",
            "live_bytes_before_drop": live_before_drop,
            "high_water_bytes": high_water_bytes,
            "denied_allocation_count": denied,
            "live_bytes_after_drop": live_after_drop,
        });
    }
    Ok(report)
}

fn trace_binary_detects_report(
    rule_root: &Path,
    input_path: &Path,
    order_path: &Path,
) -> Result<Value, String> {
    let data = fs::read(input_path)
        .map_err(|error| format!("cannot read {}: {error}", input_path.display()))?;
    trace_binary_detects_report_with_data(rule_root, input_path, order_path, data)
}

fn trace_binary_detects(
    rule_root: &Path,
    input_path: &Path,
    order_path: &Path,
) -> Result<bool, String> {
    let report = trace_binary_detects_report(rule_root, input_path, order_path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot serialize report: {error}"))?
    );
    Ok(true)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn decode_hex_string(value: &str, field: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err(format!("{field} has an odd number of hex digits"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|error| format!("{field} is not ASCII: {error}"))?;
            u8::from_str_radix(text, 16)
                .map_err(|error| format!("{field} contains invalid hex: {error}"))
        })
        .collect()
}

fn pe_physical_map_projection(context: &PeRuleContext) -> Value {
    json!({
        "file_type": "pe",
        "endian": "little",
        "code_base": context.memory_map.code_base.to_string(),
        "start_load_offset": context.memory_map.start_load_offset.to_string(),
        "records": context
            .memory_map
            .records
            .iter()
            .map(|record| json!({
                "offset": record.offset.to_string(),
                "address": record.address.to_string(),
                "size": record.size.to_string(),
            }))
            .collect::<Vec<_>>(),
    })
}

fn qt5_pe_physical_map_projection(value: &Value) -> Result<Value, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Qt5 PE memory map must be an object".to_owned())?;
    let records = object
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| "Qt5 PE memory map records are missing".to_owned())?
        .iter()
        .filter_map(|record| {
            let object = record.as_object()?;
            let is_virtual = object.get("virtual")?.as_bool()?;
            let size = object.get("size")?.as_str()?;
            (!is_virtual && size != "0").then(|| {
                json!({
                    "offset": object.get("offset"),
                    "address": object.get("address"),
                    "size": size,
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "file_type": object.get("file_type"),
        "endian": object.get("endian"),
        "code_base": object.get("code_base"),
        "start_load_offset": object.get("start_load_offset"),
        "records": records,
    }))
}

fn elf_matcher_map_projection(context: &ElfRuleContext) -> Value {
    let endian = match context.memory_map.endian {
        Endian::Little => "little",
        Endian::Big => "big",
    };
    json!({
        "file_type": "elf",
        "endian": endian,
        "code_base": context.memory_map.code_base.to_string(),
        "start_load_offset": context.memory_map.start_load_offset.to_string(),
        "records": context
            .memory_map
            .records
            .iter()
            .map(|record| json!({
                "offset": record.offset.to_string(),
                "address": record.address.to_string(),
                "size": record.size.to_string(),
            }))
            .collect::<Vec<_>>(),
    })
}

fn macho_matcher_map_projection(context: &MachoRuleContext) -> Value {
    let endian = match context.memory_map.endian {
        Endian::Little => "little",
        Endian::Big => "big",
    };
    json!({
        "file_type": "macho",
        "endian": endian,
        "code_base": context.memory_map.code_base.to_string(),
        "start_load_offset": context.memory_map.start_load_offset.to_string(),
        "records": context
            .memory_map
            .records
            .iter()
            .map(|record| json!({
                "offset": record.offset.to_string(),
                "address": record.address.to_string(),
                "size": record.size.to_string(),
            }))
            .collect::<Vec<_>>(),
    })
}

#[derive(Debug, Eq, PartialEq)]
struct Qt5MatcherMapProjection {
    matcher_map: Value,
    discarded_virtual_records: usize,
    discarded_nonpositive_size_records: usize,
    discarded_negative_offset_records: usize,
    discarded_overlay_sentinel_records: usize,
}

fn parse_qt5_i128(value: Option<&Value>, field: &str) -> Result<i128, String> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Qt5 memory record {field} is missing"))?
        .parse::<i128>()
        .map_err(|error| format!("Qt5 memory record {field} is invalid: {error}"))
}

fn qt5_matcher_map_projection(value: &Value) -> Result<Qt5MatcherMapProjection, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Qt5 memory map must be an object".to_owned())?;
    let source_records = object
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| "Qt5 memory map records are missing".to_owned())?;
    let mut records = Vec::new();
    let mut discarded_virtual_records = 0_usize;
    let mut discarded_nonpositive_size_records = 0_usize;
    let mut discarded_negative_offset_records = 0_usize;
    let mut discarded_overlay_sentinel_records = 0_usize;
    for record in source_records {
        let record = record
            .as_object()
            .ok_or_else(|| "Qt5 memory map record must be an object".to_owned())?;
        if record.get("virtual").and_then(Value::as_bool) != Some(false) {
            discarded_virtual_records += 1;
            continue;
        }
        let size = parse_qt5_i128(record.get("size"), "size")?;
        if size <= 0 {
            discarded_nonpositive_size_records += 1;
            continue;
        }
        let offset = parse_qt5_i128(record.get("offset"), "offset")?;
        if offset < 0 {
            discarded_negative_offset_records += 1;
            continue;
        }
        let address = parse_qt5_i128(record.get("address"), "address")?;
        if address == i128::from(u64::MAX) {
            discarded_overlay_sentinel_records += 1;
            continue;
        }
        records.push(json!({
            "offset": offset.to_string(),
            "address": address.to_string(),
            "size": size.to_string(),
        }));
    }
    Ok(Qt5MatcherMapProjection {
        matcher_map: json!({
            "file_type": object.get("file_type"),
            "endian": object.get("endian"),
            "code_base": object.get("code_base"),
            "start_load_offset": object.get("start_load_offset"),
            "records": records,
        }),
        discarded_virtual_records,
        discarded_nonpositive_size_records,
        discarded_negative_offset_records,
        discarded_overlay_sentinel_records,
    })
}

fn verify_pe_rule(
    rule_root: &Path,
    fixture_path: &Path,
    baseline_path: &Path,
    tracking_limit_bytes: Option<usize>,
) -> Result<bool, String> {
    let fixture_bytes = fs::read(fixture_path)
        .map_err(|error| format!("cannot read {}: {error}", fixture_path.display()))?;
    let baseline_bytes = fs::read(baseline_path)
        .map_err(|error| format!("cannot read {}: {error}", baseline_path.display()))?;
    if sha256_hex(&fixture_bytes) != PE_FIXTURE_SHA256 {
        return Err(format!(
            "fixed PE fixture hash mismatch: {}",
            fixture_path.display()
        ));
    }
    if sha256_hex(&baseline_bytes) != PE_QT5_BASELINE_SHA256 {
        return Err(format!(
            "fixed Qt5 PE baseline hash mismatch: {}",
            baseline_path.display()
        ));
    }
    let rule_path = rule_root.join(PE_RULE_SUFFIX);
    let rule_source = fs::read(&rule_path)
        .map_err(|error| format!("cannot read {}: {error}", rule_path.display()))?;
    if rule_source.len() != PE_RULE_BYTES || sha256_hex(&rule_source) != PE_RULE_SHA256 {
        return Err(format!("fixed PE rule mismatch: {}", rule_path.display()));
    }
    let fixture: Value = serde_json::from_slice(&fixture_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", fixture_path.display()))?;
    let baseline: Value = serde_json::from_slice(&baseline_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", baseline_path.display()))?;
    for (document_name, document) in [("fixture", &fixture), ("baseline", &baseline)] {
        if document["upstream_commit"] != UPSTREAM_COMMIT
            || document["xscanengine_commit"] != XSCANENGINE_COMMIT
            || document["rules_commit"] != RULES_COMMIT
            || document["case_count"] != 3
        {
            return Err(format!("{document_name} PE metadata mismatch"));
        }
    }
    if fixture["formats_commit"] != baseline["formats_commit"]
        || fixture["rule"]["path"] != PE_RULE_SUFFIX
        || fixture["rule"]["sha256"] != PE_RULE_SHA256
        || baseline["rule_sha256"] != PE_RULE_SHA256
        || baseline["qt_version"] != "5.15.13"
        || baseline["engine"] != "QScriptEngine"
    {
        return Err("fixed PE fixture/baseline contract mismatch".to_owned());
    }
    let fixture_cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| "PE fixture cases are missing".to_owned())?;
    let baseline_cases = baseline["cases"]
        .as_array()
        .ok_or_else(|| "Qt5 PE baseline cases are missing".to_owned())?;
    if fixture_cases.len() != 3 || baseline_cases.len() != 3 {
        return Err("fixed PE case count mismatch".to_owned());
    }

    let mut reports = Vec::with_capacity(fixture_cases.len());
    let mut all_match = true;
    for fixture_case in fixture_cases {
        let id = fixture_case["id"]
            .as_str()
            .ok_or_else(|| "PE fixture case id is missing".to_owned())?;
        let baseline_case = baseline_cases
            .iter()
            .find(|case| case["id"] == id)
            .ok_or_else(|| format!("Qt5 PE baseline case is missing: {id}"))?;
        if fixture_case["data_hex"] != baseline_case["data_hex"]
            || fixture_case["data_sha256"] != baseline_case["data_sha256"]
        {
            return Err(format!("{id}: fixture and Qt5 input evidence differ"));
        }
        let data_hex = fixture_case["data_hex"]
            .as_str()
            .ok_or_else(|| format!("{id}: data_hex is missing"))?;
        let data = decode_hex_string(data_hex, &format!("{id}.data_hex"))?;
        if sha256_hex(&data) != fixture_case["data_sha256"] {
            return Err(format!("{id}: decoded input hash mismatch"));
        }
        let pe_context = PeRuleContext::parse(&data).map_err(|error| format!("{id}: {error}"))?;
        let expected_entry_point = baseline_case["entry_point_offset"]
            .as_i64()
            .ok_or_else(|| format!("{id}: Qt5 entry point offset is missing"))?;
        let actual_entry_point = pe_context
            .entry_point_offset
            .and_then(|offset| i64::try_from(offset).ok())
            .unwrap_or(-1);
        let actual_map = pe_physical_map_projection(&pe_context);
        let expected_map = qt5_pe_physical_map_projection(&baseline_case["memory_map"])?;

        let (runtime, runtime_probe) = new_rule_case_runtime_with_tracking(tracking_limit_bytes)?;
        let context = new_context(&runtime)?;
        let detections = Arc::new(Mutex::new(Vec::new()));
        install_nintendo_host(&context, Arc::new(data.clone()), Arc::clone(&detections))?;
        let pe_trace = install_pe_host(&context, Arc::new(data), pe_context.clone())?;
        eval_unit(&context, FORMAT_RESULT_SHIM)?;
        let initialized_memory = runtime_memory_snapshot(&runtime)?;
        let detect_result = eval_rule_lexical(&context, &rule_source, true)
            .map_err(|error| format!("{id}: fixed PE rule failed: {error}"))?;
        let actual_detections = detections
            .lock()
            .map_err(|_| "PE detection result mutex poisoned".to_owned())?
            .clone();
        let expected_detections: Vec<Detection> =
            serde_json::from_value(baseline_case["detections"].clone())
                .map_err(|error| format!("{id}: invalid Qt5 detections: {error}"))?;
        let expected_detect_result = baseline_case["detect_result"]
            .as_bool()
            .ok_or_else(|| format!("{id}: Qt5 detect result is missing"))?;
        let compare_ep_calls = pe_trace.compare_ep_calls.load(Ordering::Relaxed);
        let fast_paths = pe_trace.fast_paths.load(Ordering::Relaxed);
        let generic_paths = pe_trace.generic_paths.load(Ordering::Relaxed);
        let errors = pe_trace.errors.load(Ordering::Relaxed);
        let entry_point_matches = actual_entry_point == expected_entry_point;
        let memory_map_matches = actual_map == expected_map;
        let matches = entry_point_matches
            && memory_map_matches
            && detect_result == expected_detect_result.to_string()
            && actual_detections == expected_detections
            && compare_ep_calls == 1
            && fast_paths + generic_paths == 1
            && errors == 0;
        all_match &= matches;
        let runtime_measurement = runtime_probe.finish(runtime, context, initialized_memory)?;
        reports.push(json!({
            "id": id,
            "input_sha256": fixture_case["data_sha256"],
            "input_bytes": data_hex.len() / 2,
            "parser_valid": true,
            "entry_point_offset": {
                "qt5": expected_entry_point,
                "rust": actual_entry_point,
                "matches": entry_point_matches,
            },
            "physical_memory_map": {
                "qt5": expected_map,
                "rust": actual_map,
                "matches": memory_map_matches,
                "bounded_upstream_alias_count":
                    pe_context.aliased_out_of_bounds_sections,
            },
            "detect_result": {
                "qt5": expected_detect_result,
                "rust": detect_result,
            },
            "detections": {
                "qt5": expected_detections,
                "rust": actual_detections,
            },
            "pe_compare_ep_calls": compare_ep_calls,
            "pe_compare_ep_fast_paths": fast_paths,
            "pe_compare_ep_generic_paths": generic_paths,
            "pe_compare_ep_errors": errors,
            "runtime_measurement": runtime_measurement,
            "matches": matches,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation": "byte-identical fixed PE rule with Rust PE context and PE.compareEP",
            "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
            "upstream_commit": UPSTREAM_COMMIT,
            "xscanengine_commit": XSCANENGINE_COMMIT,
            "rules_commit": RULES_COMMIT,
            "rule": {
                "path": normalized_path(&rule_path),
                "bytes": rule_source.len(),
                "sha256": PE_RULE_SHA256,
            },
            "fixture": {
                "path": normalized_path(fixture_path),
                "sha256": PE_FIXTURE_SHA256,
            },
            "qt5_baseline": {
                "path": normalized_path(baseline_path),
                "sha256": PE_QT5_BASELINE_SHA256,
            },
            "case_count": reports.len(),
            "matched_count": reports.iter().filter(|case| case["matches"] == true).count(),
            "cases": reports,
            "all_match": all_match,
        }))
        .map_err(|error| format!("cannot serialize PE rule report: {error}"))?
    );
    Ok(all_match)
}

fn verify_elf_rule(
    rule_root: &Path,
    fixture_path: &Path,
    baseline_path: &Path,
    tracking_limit_bytes: Option<usize>,
) -> Result<bool, String> {
    let fixture_bytes = fs::read(fixture_path)
        .map_err(|error| format!("cannot read {}: {error}", fixture_path.display()))?;
    let baseline_bytes = fs::read(baseline_path)
        .map_err(|error| format!("cannot read {}: {error}", baseline_path.display()))?;
    if sha256_hex(&fixture_bytes) != ELF_FIXTURE_SHA256 {
        return Err(format!(
            "fixed ELF fixture hash mismatch: {}",
            fixture_path.display()
        ));
    }
    if sha256_hex(&baseline_bytes) != ELF_QT5_BASELINE_SHA256 {
        return Err(format!(
            "fixed Qt5 ELF baseline hash mismatch: {}",
            baseline_path.display()
        ));
    }
    let rule_path = rule_root.join(ELF_RULE_SUFFIX);
    let rule_source = fs::read(&rule_path)
        .map_err(|error| format!("cannot read {}: {error}", rule_path.display()))?;
    if rule_source.len() != ELF_RULE_BYTES || sha256_hex(&rule_source) != ELF_RULE_SHA256 {
        return Err(format!("fixed ELF rule mismatch: {}", rule_path.display()));
    }
    let fixture: Value = serde_json::from_slice(&fixture_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", fixture_path.display()))?;
    let baseline: Value = serde_json::from_slice(&baseline_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", baseline_path.display()))?;
    for (document_name, document) in [("fixture", &fixture), ("baseline", &baseline)] {
        if document["upstream_commit"] != UPSTREAM_COMMIT
            || document["formats_commit"] != FORMATS_COMMIT
            || document["xscanengine_commit"] != XSCANENGINE_COMMIT
            || document["rules_commit"] != RULES_COMMIT
            || document["case_count"] != 6
        {
            return Err(format!("{document_name} ELF metadata mismatch"));
        }
    }
    if fixture["rule"]["path"] != ELF_RULE_SUFFIX
        || fixture["rule"]["sha256"] != ELF_RULE_SHA256
        || baseline["rule_path"] != format!("/opt/die-source/Detect-It-Easy/db/{ELF_RULE_SUFFIX}")
        || baseline["rule_sha256"] != ELF_RULE_SHA256
        || baseline["qt_version"] != "5.15.13"
        || baseline["engine"] != "QScriptEngine"
    {
        return Err("fixed ELF fixture/baseline contract mismatch".to_owned());
    }
    let fixture_cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| "ELF fixture cases are missing".to_owned())?;
    let baseline_cases = baseline["cases"]
        .as_array()
        .ok_or_else(|| "Qt5 ELF baseline cases are missing".to_owned())?;
    if fixture_cases.len() != 6 || baseline_cases.len() != 6 {
        return Err("fixed ELF case count mismatch".to_owned());
    }

    let mut reports = Vec::with_capacity(fixture_cases.len());
    let mut all_match = true;
    for fixture_case in fixture_cases {
        let id = fixture_case["id"]
            .as_str()
            .ok_or_else(|| "ELF fixture case id is missing".to_owned())?;
        let baseline_case = baseline_cases
            .iter()
            .find(|case| case["id"] == id)
            .ok_or_else(|| format!("Qt5 ELF baseline case is missing: {id}"))?;
        if fixture_case["data_hex"] != baseline_case["data_hex"]
            || fixture_case["data_sha256"] != baseline_case["data_sha256"]
            || fixture_case["elf_class"] != baseline_case["elf_class"]
        {
            return Err(format!("{id}: fixture and Qt5 input evidence differ"));
        }
        if baseline_case["parser_valid"] != true || baseline_case["elf_script_error"] != "" {
            return Err(format!("{id}: Qt5 ELF parser/script evidence is not valid"));
        }
        let data_hex = fixture_case["data_hex"]
            .as_str()
            .ok_or_else(|| format!("{id}: data_hex is missing"))?;
        let data = decode_hex_string(data_hex, &format!("{id}.data_hex"))?;
        if sha256_hex(&data) != fixture_case["data_sha256"] {
            return Err(format!("{id}: decoded input hash mismatch"));
        }
        let elf_context = ElfRuleContext::parse(&data).map_err(|error| format!("{id}: {error}"))?;
        let expected_class = baseline_case["elf_class"]
            .as_u64()
            .ok_or_else(|| format!("{id}: Qt5 ELF class is missing"))?;
        let actual_class = u64::from(elf_context.elf_class) * 32;
        let expected_entry_point = baseline_case["entry_point_offset"]
            .as_i64()
            .ok_or_else(|| format!("{id}: Qt5 entry point offset is missing"))?;
        let actual_entry_point = elf_context
            .entry_point_offset
            .and_then(|offset| i64::try_from(offset).ok())
            .unwrap_or(-1);
        let actual_map = elf_matcher_map_projection(&elf_context);
        let expected_projection = qt5_matcher_map_projection(&baseline_case["memory_map"])?;
        let memory_map_matches = actual_map == expected_projection.matcher_map;

        let (runtime, runtime_probe) = new_rule_case_runtime_with_tracking(tracking_limit_bytes)?;
        let context = new_context(&runtime)?;
        let detections = Arc::new(Mutex::new(Vec::new()));
        install_nintendo_host(&context, Arc::new(data.clone()), Arc::clone(&detections))?;
        let elf_trace = install_elf_host(&context, Arc::new(data), elf_context.clone())?;
        eval_unit(&context, FORMAT_RESULT_SHIM)?;
        let initialized_memory = runtime_memory_snapshot(&runtime)?;
        let detect_result = eval_rule_lexical(&context, &rule_source, true)
            .map_err(|error| format!("{id}: fixed ELF rule failed: {error}"))?;
        let actual_detections = detections
            .lock()
            .map_err(|_| "ELF detection result mutex poisoned".to_owned())?
            .clone();
        let expected_detections: Vec<Detection> =
            serde_json::from_value(baseline_case["detections"].clone())
                .map_err(|error| format!("{id}: invalid Qt5 detections: {error}"))?;
        let expected_detect_result = baseline_case["detect_result"]
            .as_bool()
            .ok_or_else(|| format!("{id}: Qt5 detect result is missing"))?;
        let compare_ep_calls = elf_trace.compare_ep_calls.load(Ordering::Relaxed);
        let fast_paths = elf_trace.fast_paths.load(Ordering::Relaxed);
        let generic_paths = elf_trace.generic_paths.load(Ordering::Relaxed);
        let errors = elf_trace.errors.load(Ordering::Relaxed);
        let class_matches = actual_class == expected_class;
        let entry_point_matches = actual_entry_point == expected_entry_point;
        let matches = class_matches
            && entry_point_matches
            && memory_map_matches
            && detect_result == expected_detect_result.to_string()
            && actual_detections == expected_detections
            && compare_ep_calls == 1
            && fast_paths + generic_paths == 1
            && errors == 0;
        all_match &= matches;
        let runtime_measurement = runtime_probe.finish(runtime, context, initialized_memory)?;
        reports.push(json!({
            "id": id,
            "input_sha256": fixture_case["data_sha256"],
            "input_bytes": data_hex.len() / 2,
            "parser_valid": true,
            "elf_class": {
                "qt5": expected_class,
                "rust": actual_class,
                "matches": class_matches,
            },
            "entry_point_offset": {
                "qt5": expected_entry_point,
                "rust": actual_entry_point,
                "matches": entry_point_matches,
            },
            "matcher_memory_map": {
                "qt5_safe_projection": expected_projection.matcher_map,
                "rust": actual_map,
                "matches": memory_map_matches,
                "qt5_discarded_records": {
                    "virtual": expected_projection.discarded_virtual_records,
                    "nonpositive_size":
                        expected_projection.discarded_nonpositive_size_records,
                    "negative_offset":
                        expected_projection.discarded_negative_offset_records,
                    "overlay_sentinel":
                        expected_projection.discarded_overlay_sentinel_records,
                },
                "rust_declared_out_of_bounds_loads": elf_context.out_of_bounds_loads,
            },
            "detect_result": {
                "qt5": expected_detect_result,
                "rust": detect_result,
            },
            "detections": {
                "qt5": expected_detections,
                "rust": actual_detections,
            },
            "elf_compare_ep_calls": compare_ep_calls,
            "elf_compare_ep_fast_paths": fast_paths,
            "elf_compare_ep_generic_paths": generic_paths,
            "elf_compare_ep_errors": errors,
            "runtime_measurement": runtime_measurement,
            "matches": matches,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation": "byte-identical fixed ELF rule with Rust ELF context and ELF.compareEP",
            "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
            "upstream_commit": UPSTREAM_COMMIT,
            "formats_commit": FORMATS_COMMIT,
            "xscanengine_commit": XSCANENGINE_COMMIT,
            "rules_commit": RULES_COMMIT,
            "rule": {
                "path": normalized_path(&rule_path),
                "bytes": rule_source.len(),
                "sha256": ELF_RULE_SHA256,
            },
            "fixture": {
                "path": normalized_path(fixture_path),
                "sha256": ELF_FIXTURE_SHA256,
            },
            "qt5_baseline": {
                "path": normalized_path(baseline_path),
                "sha256": ELF_QT5_BASELINE_SHA256,
            },
            "case_count": reports.len(),
            "matched_count": reports.iter().filter(|case| case["matches"] == true).count(),
            "cases": reports,
            "all_match": all_match,
        }))
        .map_err(|error| format!("cannot serialize ELF rule report: {error}"))?
    );
    Ok(all_match)
}

fn verify_macho_rule(
    rule_root: &Path,
    fixture_path: &Path,
    baseline_path: &Path,
    tracking_limit_bytes: Option<usize>,
) -> Result<bool, String> {
    let fixture_bytes = fs::read(fixture_path)
        .map_err(|error| format!("cannot read {}: {error}", fixture_path.display()))?;
    let baseline_bytes = fs::read(baseline_path)
        .map_err(|error| format!("cannot read {}: {error}", baseline_path.display()))?;
    if sha256_hex(&fixture_bytes) != MACHO_FIXTURE_SHA256 {
        return Err(format!(
            "fixed Mach-O fixture hash mismatch: {}",
            fixture_path.display()
        ));
    }
    if sha256_hex(&baseline_bytes) != MACHO_QT5_BASELINE_SHA256 {
        return Err(format!(
            "fixed Qt5 Mach-O baseline hash mismatch: {}",
            baseline_path.display()
        ));
    }
    let rule_path = rule_root.join(MACHO_RULE_SUFFIX);
    let rule_source = fs::read(&rule_path)
        .map_err(|error| format!("cannot read {}: {error}", rule_path.display()))?;
    if rule_source.len() != MACHO_RULE_BYTES || sha256_hex(&rule_source) != MACHO_RULE_SHA256 {
        return Err(format!(
            "fixed Mach-O rule mismatch: {}",
            rule_path.display()
        ));
    }
    let fixture: Value = serde_json::from_slice(&fixture_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", fixture_path.display()))?;
    let baseline: Value = serde_json::from_slice(&baseline_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", baseline_path.display()))?;
    for (document_name, document) in [("fixture", &fixture), ("baseline", &baseline)] {
        if document["upstream_commit"] != UPSTREAM_COMMIT
            || document["formats_commit"] != FORMATS_COMMIT
            || document["xscanengine_commit"] != XSCANENGINE_COMMIT
            || document["rules_commit"] != RULES_COMMIT
            || document["case_count"] != 4
        {
            return Err(format!("{document_name} Mach-O metadata mismatch"));
        }
    }
    if fixture["rule"]["path"] != MACHO_RULE_SUFFIX
        || fixture["rule"]["sha256"] != MACHO_RULE_SHA256
        || baseline["rule_path"] != format!("/opt/die-source/Detect-It-Easy/db/{MACHO_RULE_SUFFIX}")
        || baseline["rule_sha256"] != MACHO_RULE_SHA256
        || baseline["qt_version"] != "5.15.13"
        || baseline["engine"] != "QScriptEngine"
    {
        return Err("fixed Mach-O fixture/baseline contract mismatch".to_owned());
    }
    let fixture_cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| "Mach-O fixture cases are missing".to_owned())?;
    let baseline_cases = baseline["cases"]
        .as_array()
        .ok_or_else(|| "Qt5 Mach-O baseline cases are missing".to_owned())?;
    if fixture_cases.len() != 4 || baseline_cases.len() != 4 {
        return Err("fixed Mach-O case count mismatch".to_owned());
    }

    let mut reports = Vec::with_capacity(fixture_cases.len());
    let mut all_match = true;
    for fixture_case in fixture_cases {
        let id = fixture_case["id"]
            .as_str()
            .ok_or_else(|| "Mach-O fixture case id is missing".to_owned())?;
        let baseline_case = baseline_cases
            .iter()
            .find(|case| case["id"] == id)
            .ok_or_else(|| format!("Qt5 Mach-O baseline case is missing: {id}"))?;
        for field in ["architecture", "cpu_type", "data_hex", "data_sha256"] {
            if fixture_case[field] != baseline_case[field] {
                return Err(format!("{id}: fixture and Qt5 {field} evidence differ"));
            }
        }
        if baseline_case["parser_valid"] != true || baseline_case["mach_script_error"] != "" {
            return Err(format!(
                "{id}: Qt5 Mach-O parser/script evidence is not valid"
            ));
        }
        let data_hex = fixture_case["data_hex"]
            .as_str()
            .ok_or_else(|| format!("{id}: data_hex is missing"))?;
        let data = decode_hex_string(data_hex, &format!("{id}.data_hex"))?;
        if sha256_hex(&data) != fixture_case["data_sha256"] {
            return Err(format!("{id}: decoded input hash mismatch"));
        }
        let macho_context =
            MachoRuleContext::parse(&data).map_err(|error| format!("{id}: {error}"))?;
        let expected_cpu_type = baseline_case["cpu_type"]
            .as_u64()
            .ok_or_else(|| format!("{id}: Qt5 CPU type is missing"))?;
        let actual_cpu_type = u64::from(macho_context.cpu_type);
        let expected_entry_point = baseline_case["entry_point_offset"]
            .as_i64()
            .ok_or_else(|| format!("{id}: Qt5 entry point offset is missing"))?;
        let actual_entry_point = macho_context
            .entry_point_offset
            .and_then(|offset| i64::try_from(offset).ok())
            .unwrap_or(-1);
        let actual_map = macho_matcher_map_projection(&macho_context);
        let expected_projection = qt5_matcher_map_projection(&baseline_case["memory_map"])?;
        let memory_map_matches = actual_map == expected_projection.matcher_map;

        let (runtime, runtime_probe) = new_rule_case_runtime_with_tracking(tracking_limit_bytes)?;
        let context = new_context(&runtime)?;
        let detections = Arc::new(Mutex::new(Vec::new()));
        install_nintendo_host(&context, Arc::new(data.clone()), Arc::clone(&detections))?;
        let macho_trace = install_macho_host(&context, Arc::new(data), macho_context.clone())?;
        eval_unit(&context, FORMAT_RESULT_SHIM)?;
        let initialized_memory = runtime_memory_snapshot(&runtime)?;
        let detect_result = eval_rule_lexical(&context, &rule_source, true)
            .map_err(|error| format!("{id}: fixed Mach-O rule failed: {error}"))?;
        let actual_detections = detections
            .lock()
            .map_err(|_| "Mach-O detection result mutex poisoned".to_owned())?
            .clone();
        let expected_detections: Vec<Detection> =
            serde_json::from_value(baseline_case["detections"].clone())
                .map_err(|error| format!("{id}: invalid Qt5 detections: {error}"))?;
        let expected_detect_result = baseline_case["detect_result"]
            .as_bool()
            .ok_or_else(|| format!("{id}: Qt5 detect result is missing"))?;
        let expected_calls = match id {
            "rust_macho64_x86_64_entry_point_match" => 5,
            "rust_macho64_arm64_entry_point_match" => 6,
            "rust_macho64_x86_64_entry_point_mismatch"
            | "rust_macho64_x86_64_entry_point_truncated" => 9,
            _ => return Err(format!("{id}: unexpected fixed Mach-O case")),
        };
        let expected_fast_paths = if id.ends_with("_truncated") {
            0
        } else {
            expected_calls
        };
        let expected_generic_paths = expected_calls - expected_fast_paths;
        let compare_ep_calls = macho_trace.compare_ep_calls.load(Ordering::Relaxed);
        let fast_paths = macho_trace.fast_paths.load(Ordering::Relaxed);
        let generic_paths = macho_trace.generic_paths.load(Ordering::Relaxed);
        let errors = macho_trace.errors.load(Ordering::Relaxed);
        let cpu_type_matches = actual_cpu_type == expected_cpu_type;
        let entry_point_matches = actual_entry_point == expected_entry_point;
        let matches = macho_context.is_64
            && cpu_type_matches
            && entry_point_matches
            && memory_map_matches
            && detect_result == expected_detect_result.to_string()
            && actual_detections == expected_detections
            && compare_ep_calls == expected_calls
            && fast_paths == expected_fast_paths
            && generic_paths == expected_generic_paths
            && errors == 0;
        all_match &= matches;
        let runtime_measurement = runtime_probe.finish(runtime, context, initialized_memory)?;
        reports.push(json!({
            "id": id,
            "architecture": fixture_case["architecture"],
            "input_sha256": fixture_case["data_sha256"],
            "input_bytes": data_hex.len() / 2,
            "parser_valid": true,
            "is_64": macho_context.is_64,
            "cpu_type": {
                "qt5": expected_cpu_type,
                "rust": actual_cpu_type,
                "matches": cpu_type_matches,
            },
            "entry_point_offset": {
                "qt5": expected_entry_point,
                "rust": actual_entry_point,
                "matches": entry_point_matches,
            },
            "matcher_memory_map": {
                "qt5_safe_projection": expected_projection.matcher_map,
                "rust": actual_map,
                "matches": memory_map_matches,
                "qt5_discarded_records": {
                    "virtual": expected_projection.discarded_virtual_records,
                    "nonpositive_size":
                        expected_projection.discarded_nonpositive_size_records,
                    "negative_offset":
                        expected_projection.discarded_negative_offset_records,
                    "overlay_sentinel":
                        expected_projection.discarded_overlay_sentinel_records,
                },
                "rust_declared_out_of_bounds_segments":
                    macho_context.out_of_bounds_segments,
            },
            "detect_result": {
                "qt5": expected_detect_result,
                "rust": detect_result,
            },
            "detections": {
                "qt5": expected_detections,
                "rust": actual_detections,
            },
            "macho_compare_ep_calls": compare_ep_calls,
            "macho_compare_ep_fast_paths": fast_paths,
            "macho_compare_ep_generic_paths": generic_paths,
            "macho_compare_ep_errors": errors,
            "runtime_measurement": runtime_measurement,
            "matches": matches,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation":
                "byte-identical fixed Mach-O rule with Rust Mach-O context and MACH.compareEP",
            "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
            "upstream_commit": UPSTREAM_COMMIT,
            "formats_commit": FORMATS_COMMIT,
            "xscanengine_commit": XSCANENGINE_COMMIT,
            "rules_commit": RULES_COMMIT,
            "rule": {
                "path": normalized_path(&rule_path),
                "bytes": rule_source.len(),
                "sha256": MACHO_RULE_SHA256,
            },
            "fixture": {
                "path": normalized_path(fixture_path),
                "sha256": MACHO_FIXTURE_SHA256,
            },
            "qt5_baseline": {
                "path": normalized_path(baseline_path),
                "sha256": MACHO_QT5_BASELINE_SHA256,
            },
            "case_count": reports.len(),
            "matched_count": reports.iter().filter(|case| case["matches"] == true).count(),
            "cases": reports,
            "all_match": all_match,
        }))
        .map_err(|error| format!("cannot serialize Mach-O rule report: {error}"))?
    );
    Ok(all_match)
}

fn verify_dex_rule(
    rule_root: &Path,
    fixture_path: &Path,
    baseline_path: &Path,
    tracking_limit_bytes: Option<usize>,
) -> Result<bool, String> {
    let fixture_bytes = fs::read(fixture_path)
        .map_err(|error| format!("cannot read {}: {error}", fixture_path.display()))?;
    let baseline_bytes = fs::read(baseline_path)
        .map_err(|error| format!("cannot read {}: {error}", baseline_path.display()))?;
    if sha256_hex(&fixture_bytes) != DEX_FIXTURE_SHA256 {
        return Err(format!(
            "fixed DEX fixture hash mismatch: {}",
            fixture_path.display()
        ));
    }
    if sha256_hex(&baseline_bytes) != DEX_QT5_BASELINE_SHA256 {
        return Err(format!(
            "fixed Qt5 DEX baseline hash mismatch: {}",
            baseline_path.display()
        ));
    }
    let rule_path = rule_root.join(DEX_RULE_SUFFIX);
    let rule_source = fs::read(&rule_path)
        .map_err(|error| format!("cannot read {}: {error}", rule_path.display()))?;
    if rule_source.len() != DEX_RULE_BYTES || sha256_hex(&rule_source) != DEX_RULE_SHA256 {
        return Err(format!("fixed DEX rule mismatch: {}", rule_path.display()));
    }
    let fixture: Value = serde_json::from_slice(&fixture_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", fixture_path.display()))?;
    let baseline: Value = serde_json::from_slice(&baseline_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", baseline_path.display()))?;
    for (document_name, document) in [("fixture", &fixture), ("baseline", &baseline)] {
        if document["upstream_commit"] != UPSTREAM_COMMIT
            || document["xdex_commit"] != XDEX_COMMIT
            || document["xscanengine_commit"] != XSCANENGINE_COMMIT
            || document["rules_commit"] != RULES_COMMIT
            || document["case_count"] != 3
        {
            return Err(format!("{document_name} DEX metadata mismatch"));
        }
    }
    if fixture["rule"]["path"] != DEX_RULE_SUFFIX
        || fixture["rule"]["sha256"] != DEX_RULE_SHA256
        || baseline["rule_path"] != format!("/opt/die-source/Detect-It-Easy/db/{DEX_RULE_SUFFIX}")
        || baseline["rule_sha256"] != DEX_RULE_SHA256
        || baseline["qt_version"] != "5.15.13"
        || baseline["engine"] != "QScriptEngine"
    {
        return Err("fixed DEX fixture/baseline contract mismatch".to_owned());
    }
    let fixture_cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| "DEX fixture cases are missing".to_owned())?;
    let baseline_cases = baseline["cases"]
        .as_array()
        .ok_or_else(|| "Qt5 DEX baseline cases are missing".to_owned())?;
    if fixture_cases.len() != 3 || baseline_cases.len() != 3 {
        return Err("fixed DEX case count mismatch".to_owned());
    }

    let mut reports = Vec::with_capacity(fixture_cases.len());
    let mut all_match = true;
    for fixture_case in fixture_cases {
        let id = fixture_case["id"]
            .as_str()
            .ok_or_else(|| "DEX fixture case id is missing".to_owned())?;
        let baseline_case = baseline_cases
            .iter()
            .find(|case| case["id"] == id)
            .ok_or_else(|| format!("Qt5 DEX baseline case is missing: {id}"))?;
        for field in ["data_hex", "data_sha256"] {
            if fixture_case[field] != baseline_case[field] {
                return Err(format!("{id}: fixture and Qt5 {field} evidence differ"));
            }
        }
        if baseline_case["parser_valid"] != true || baseline_case["dex_script_error"] != "" {
            return Err(format!("{id}: Qt5 DEX parser/script evidence is not valid"));
        }
        let data_hex = fixture_case["data_hex"]
            .as_str()
            .ok_or_else(|| format!("{id}: data_hex is missing"))?;
        let data = decode_hex_string(data_hex, &format!("{id}.data_hex"))?;
        if sha256_hex(&data) != fixture_case["data_sha256"] {
            return Err(format!("{id}: decoded input hash mismatch"));
        }
        let dex_context = DexRuleContext::parse(&data).map_err(|error| format!("{id}: {error}"))?;
        let expected_strings: Vec<String> =
            serde_json::from_value(baseline_case["parsed_strings"].clone())
                .map_err(|error| format!("{id}: invalid Qt5 parsed strings: {error}"))?;
        let expected_map_item_count = baseline_case["map_item_count"]
            .as_u64()
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| format!("{id}: Qt5 map item count is missing"))?;
        let expected_native_present = baseline_case["native_qdbh_present"]
            .as_bool()
            .ok_or_else(|| format!("{id}: Qt5 native result is missing"))?;
        let rust_native_present = dex_context.strings.iter().any(|value| value == "/qdbh");

        let (runtime, runtime_probe) = new_rule_case_runtime_with_tracking(tracking_limit_bytes)?;
        let context = new_context(&runtime)?;
        let detections = Arc::new(Mutex::new(Vec::new()));
        install_nintendo_host(&context, Arc::new(data), Arc::clone(&detections))?;
        let dex_trace = install_dex_host(&context, dex_context.clone())?;
        eval_unit(&context, FORMAT_RESULT_SHIM)?;
        let initialized_memory = runtime_memory_snapshot(&runtime)?;
        let detect_result = eval_rule_lexical(&context, &rule_source, true)
            .map_err(|error| format!("{id}: fixed DEX rule failed: {error}"))?;
        let actual_detections = detections
            .lock()
            .map_err(|_| "DEX detection result mutex poisoned".to_owned())?
            .clone();
        let expected_detections: Vec<Detection> =
            serde_json::from_value(baseline_case["detections"].clone())
                .map_err(|error| format!("{id}: invalid Qt5 detections: {error}"))?;
        let expected_detect_result = baseline_case["detect_result"]
            .as_bool()
            .ok_or_else(|| format!("{id}: Qt5 detect result is missing"))?;
        let calls = dex_trace
            .is_dex_string_present_calls
            .load(Ordering::Relaxed);
        let expected_out_of_bounds = usize::from(id == "qdbh_string_data_truncated");
        let strings_match = dex_context.strings == expected_strings;
        let map_matches = dex_context.map_item_count == expected_map_item_count;
        let native_matches = rust_native_present == expected_native_present;
        let matches = dex_context.version == 35
            && map_matches
            && strings_match
            && native_matches
            && dex_context.out_of_bounds_string_offsets == expected_out_of_bounds
            && detect_result == expected_detect_result.to_string()
            && actual_detections == expected_detections
            && calls == 1;
        all_match &= matches;
        let runtime_measurement = runtime_probe.finish(runtime, context, initialized_memory)?;
        reports.push(json!({
            "id": id,
            "input_sha256": fixture_case["data_sha256"],
            "input_bytes": data_hex.len() / 2,
            "parser_valid": true,
            "version": dex_context.version,
            "map_item_count": {
                "qt5": expected_map_item_count,
                "rust": dex_context.map_item_count,
                "matches": map_matches,
            },
            "parsed_strings": {
                "qt5": expected_strings,
                "rust": dex_context.strings,
                "matches": strings_match,
            },
            "native_qdbh_present": {
                "qt5": expected_native_present,
                "rust": rust_native_present,
                "matches": native_matches,
            },
            "rust_out_of_bounds_string_offsets":
                dex_context.out_of_bounds_string_offsets,
            "detect_result": {
                "qt5": expected_detect_result,
                "rust": detect_result,
            },
            "detections": {
                "qt5": expected_detections,
                "rust": actual_detections,
            },
            "dex_is_string_present_calls": calls,
            "runtime_measurement": runtime_measurement,
            "matches": matches,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation":
                "byte-identical fixed DEX rule with Rust DEX context and DEX.isDexStringPresent",
            "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
            "upstream_commit": UPSTREAM_COMMIT,
            "xdex_commit": XDEX_COMMIT,
            "xscanengine_commit": XSCANENGINE_COMMIT,
            "rules_commit": RULES_COMMIT,
            "rule": {
                "path": normalized_path(&rule_path),
                "bytes": rule_source.len(),
                "sha256": DEX_RULE_SHA256,
            },
            "fixture": {
                "path": normalized_path(fixture_path),
                "sha256": DEX_FIXTURE_SHA256,
            },
            "qt5_baseline": {
                "path": normalized_path(baseline_path),
                "sha256": DEX_QT5_BASELINE_SHA256,
            },
            "case_count": reports.len(),
            "matched_count": reports.iter().filter(|case| case["matches"] == true).count(),
            "cases": reports,
            "all_match": all_match,
        }))
        .map_err(|error| format!("cannot serialize DEX rule report: {error}"))?
    );
    Ok(all_match)
}

fn verify_apk_rule(
    rule_root: &Path,
    fixture_path: &Path,
    baseline_path: &Path,
    tracking_limit_bytes: Option<usize>,
) -> Result<bool, String> {
    let fixture_bytes = fs::read(fixture_path)
        .map_err(|error| format!("cannot read {}: {error}", fixture_path.display()))?;
    let baseline_bytes = fs::read(baseline_path)
        .map_err(|error| format!("cannot read {}: {error}", baseline_path.display()))?;
    if sha256_hex(&fixture_bytes) != APK_FIXTURE_SHA256 {
        return Err(format!(
            "fixed APK fixture hash mismatch: {}",
            fixture_path.display()
        ));
    }
    if sha256_hex(&baseline_bytes) != APK_QT5_BASELINE_SHA256 {
        return Err(format!(
            "fixed Qt5 APK baseline hash mismatch: {}",
            baseline_path.display()
        ));
    }
    let rule_path = rule_root.join(APK_RULE_SUFFIX);
    let rule_source = fs::read(&rule_path)
        .map_err(|error| format!("cannot read {}: {error}", rule_path.display()))?;
    if rule_source.len() != APK_RULE_BYTES || sha256_hex(&rule_source) != APK_RULE_SHA256 {
        return Err(format!("fixed APK rule mismatch: {}", rule_path.display()));
    }
    let fixture: Value = serde_json::from_slice(&fixture_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", fixture_path.display()))?;
    let baseline: Value = serde_json::from_slice(&baseline_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", baseline_path.display()))?;
    for (document_name, document) in [("fixture", &fixture), ("baseline", &baseline)] {
        if document["upstream_commit"] != UPSTREAM_COMMIT
            || document["xarchive_commit"] != XARCHIVE_COMMIT
            || document["xscanengine_commit"] != XSCANENGINE_COMMIT
            || document["rules_commit"] != RULES_COMMIT
            || document["case_count"] != 3
        {
            return Err(format!("{document_name} APK metadata mismatch"));
        }
    }
    if fixture["rule"]["path"] != APK_RULE_SUFFIX
        || fixture["rule"]["sha256"] != APK_RULE_SHA256
        || baseline["rule_path"] != format!("/opt/die-source/Detect-It-Easy/db/{APK_RULE_SUFFIX}")
        || baseline["rule_sha256"] != APK_RULE_SHA256
        || baseline["qt_version"] != "5.15.13"
        || baseline["engine"] != "QScriptEngine"
    {
        return Err("fixed APK fixture/baseline contract mismatch".to_owned());
    }
    let fixture_cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| "APK fixture cases are missing".to_owned())?;
    let baseline_cases = baseline["cases"]
        .as_array()
        .ok_or_else(|| "Qt5 APK baseline cases are missing".to_owned())?;
    if fixture_cases.len() != 3 || baseline_cases.len() != 3 {
        return Err("fixed APK case count mismatch".to_owned());
    }

    let mut reports = Vec::with_capacity(fixture_cases.len());
    let mut all_match = true;
    for fixture_case in fixture_cases {
        let id = fixture_case["id"]
            .as_str()
            .ok_or_else(|| "APK fixture case id is missing".to_owned())?;
        let baseline_case = baseline_cases
            .iter()
            .find(|case| case["id"] == id)
            .ok_or_else(|| format!("Qt5 APK baseline case is missing: {id}"))?;
        for field in ["data_hex", "data_sha256"] {
            if fixture_case[field] != baseline_case[field] {
                return Err(format!("{id}: fixture and Qt5 {field} evidence differ"));
            }
        }
        if baseline_case["parser_valid"] != true || baseline_case["apk_script_error"] != "" {
            return Err(format!("{id}: Qt5 APK parser/script evidence is not valid"));
        }
        let data_hex = fixture_case["data_hex"]
            .as_str()
            .ok_or_else(|| format!("{id}: data_hex is missing"))?;
        let data = decode_hex_string(data_hex, &format!("{id}.data_hex"))?;
        if sha256_hex(&data) != fixture_case["data_sha256"] {
            return Err(format!("{id}: decoded input hash mismatch"));
        }
        let apk_context = ApkRuleContext::parse(&data).map_err(|error| format!("{id}: {error}"))?;
        let expected_names: Vec<String> =
            serde_json::from_value(baseline_case["archive_record_names"].clone())
                .map_err(|error| format!("{id}: invalid Qt5 archive record names: {error}"))?;
        let expected_record_count = baseline_case["archive_record_count"]
            .as_u64()
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(|| format!("{id}: Qt5 archive record count is missing"))?;
        let expected_native_present = baseline_case["native_qdbh_present"]
            .as_bool()
            .ok_or_else(|| format!("{id}: Qt5 native result is missing"))?;
        let rust_native_present = apk_context
            .archive_record_names
            .iter()
            .any(|value| value == "assets/qdbh");

        let (runtime, runtime_probe) = new_rule_case_runtime_with_tracking(tracking_limit_bytes)?;
        let context = new_context(&runtime)?;
        let detections = Arc::new(Mutex::new(Vec::new()));
        install_nintendo_host(&context, Arc::new(data), Arc::clone(&detections))?;
        let apk_trace = install_apk_host(&context, apk_context.clone())?;
        eval_unit(&context, FORMAT_RESULT_SHIM)?;
        let initialized_memory = runtime_memory_snapshot(&runtime)?;
        let detect_result = eval_rule_lexical(&context, &rule_source, true)
            .map_err(|error| format!("{id}: fixed APK rule failed: {error}"))?;
        let actual_detections = detections
            .lock()
            .map_err(|_| "APK detection result mutex poisoned".to_owned())?
            .clone();
        let expected_detections: Vec<Detection> =
            serde_json::from_value(baseline_case["detections"].clone())
                .map_err(|error| format!("{id}: invalid Qt5 detections: {error}"))?;
        let expected_detect_result = baseline_case["detect_result"]
            .as_bool()
            .ok_or_else(|| format!("{id}: Qt5 detect result is missing"))?;
        let calls = apk_trace
            .is_archive_record_present_calls
            .load(Ordering::Relaxed);
        let expected_local_mismatches = if id == "qdbh_local_records_truncated" {
            2
        } else {
            0
        };
        let names_match = apk_context.archive_record_names == expected_names;
        let record_count_matches = apk_context.archive_record_names.len() == expected_record_count;
        let native_matches = rust_native_present == expected_native_present;
        let matches = names_match
            && record_count_matches
            && native_matches
            && apk_context.local_header_signature_mismatches == expected_local_mismatches
            && detect_result == expected_detect_result.to_string()
            && actual_detections == expected_detections
            && calls == 1;
        all_match &= matches;
        let runtime_measurement = runtime_probe.finish(runtime, context, initialized_memory)?;
        reports.push(json!({
            "id": id,
            "input_sha256": fixture_case["data_sha256"],
            "input_bytes": data_hex.len() / 2,
            "parser_valid": true,
            "archive_record_count": {
                "qt5": expected_record_count,
                "rust": apk_context.archive_record_names.len(),
                "matches": record_count_matches,
            },
            "archive_record_names": {
                "qt5": expected_names,
                "rust": apk_context.archive_record_names,
                "matches": names_match,
            },
            "native_qdbh_present": {
                "qt5": expected_native_present,
                "rust": rust_native_present,
                "matches": native_matches,
            },
            "rust_local_header_signature_mismatches":
                apk_context.local_header_signature_mismatches,
            "detect_result": {
                "qt5": expected_detect_result,
                "rust": detect_result,
            },
            "detections": {
                "qt5": expected_detections,
                "rust": actual_detections,
            },
            "apk_is_archive_record_present_calls": calls,
            "runtime_measurement": runtime_measurement,
            "matches": matches,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation":
                "byte-identical fixed APK rule with Rust ZIP context and APK.isArchiveRecordPresent",
            "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
            "upstream_commit": UPSTREAM_COMMIT,
            "xarchive_commit": XARCHIVE_COMMIT,
            "xscanengine_commit": XSCANENGINE_COMMIT,
            "rules_commit": RULES_COMMIT,
            "rule": {
                "path": normalized_path(&rule_path),
                "bytes": rule_source.len(),
                "sha256": APK_RULE_SHA256,
            },
            "fixture": {
                "path": normalized_path(fixture_path),
                "sha256": APK_FIXTURE_SHA256,
            },
            "qt5_baseline": {
                "path": normalized_path(baseline_path),
                "sha256": APK_QT5_BASELINE_SHA256,
            },
            "case_count": reports.len(),
            "matched_count": reports.iter().filter(|case| case["matches"] == true).count(),
            "cases": reports,
            "all_match": all_match,
        }))
        .map_err(|error| format!("cannot serialize APK rule report: {error}"))?
    );
    Ok(all_match)
}

fn verify_archive_rule(
    rule_root: &Path,
    fixture_path: &Path,
    baseline_path: &Path,
    tracking_limit_bytes: Option<usize>,
) -> Result<bool, String> {
    let fixture_bytes = fs::read(fixture_path)
        .map_err(|error| format!("cannot read {}: {error}", fixture_path.display()))?;
    let baseline_bytes = fs::read(baseline_path)
        .map_err(|error| format!("cannot read {}: {error}", baseline_path.display()))?;
    if sha256_hex(&fixture_bytes) != ARCHIVE_FIXTURE_SHA256 {
        return Err(format!(
            "fixed Archive fixture hash mismatch: {}",
            fixture_path.display()
        ));
    }
    if sha256_hex(&baseline_bytes) != ARCHIVE_QT5_BASELINE_SHA256 {
        return Err(format!(
            "fixed Qt5 Archive baseline hash mismatch: {}",
            baseline_path.display()
        ));
    }
    let rule_path = rule_root.join(ARCHIVE_RULE_SUFFIX);
    let rule_source = fs::read(&rule_path)
        .map_err(|error| format!("cannot read {}: {error}", rule_path.display()))?;
    if rule_source.len() != ARCHIVE_RULE_BYTES || sha256_hex(&rule_source) != ARCHIVE_RULE_SHA256 {
        return Err(format!(
            "fixed Archive rule mismatch: {}",
            rule_path.display()
        ));
    }
    let fixture: Value = serde_json::from_slice(&fixture_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", fixture_path.display()))?;
    let baseline: Value = serde_json::from_slice(&baseline_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", baseline_path.display()))?;
    for (document_name, document) in [("fixture", &fixture), ("baseline", &baseline)] {
        if document["upstream_commit"] != UPSTREAM_COMMIT
            || document["xarchive_commit"] != XARCHIVE_COMMIT
            || document["xscanengine_commit"] != XSCANENGINE_COMMIT
            || document["rules_commit"] != RULES_COMMIT
            || document["case_count"] != 3
        {
            return Err(format!("{document_name} Archive metadata mismatch"));
        }
    }
    if fixture["rule"]["path"] != ARCHIVE_RULE_SUFFIX
        || fixture["rule"]["sha256"] != ARCHIVE_RULE_SHA256
        || baseline["rule_path"]
            != format!("/opt/die-source/Detect-It-Easy/db/{ARCHIVE_RULE_SUFFIX}")
        || baseline["rule_sha256"] != ARCHIVE_RULE_SHA256
        || baseline["qt_version"] != "5.15.13"
        || baseline["engine"] != "QScriptEngine"
    {
        return Err("fixed Archive fixture/baseline contract mismatch".to_owned());
    }
    let fixture_cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| "Archive fixture cases are missing".to_owned())?;
    let baseline_cases = baseline["cases"]
        .as_array()
        .ok_or_else(|| "Qt5 Archive baseline cases are missing".to_owned())?;
    if fixture_cases.len() != 3 || baseline_cases.len() != 3 {
        return Err("fixed Archive case count mismatch".to_owned());
    }

    let mut reports = Vec::with_capacity(fixture_cases.len());
    let mut all_match = true;
    for fixture_case in fixture_cases {
        let id = fixture_case["id"]
            .as_str()
            .ok_or_else(|| "Archive fixture case id is missing".to_owned())?;
        let baseline_case = baseline_cases
            .iter()
            .find(|case| case["id"] == id)
            .ok_or_else(|| format!("Qt5 Archive baseline case is missing: {id}"))?;
        for field in ["verbose", "data_hex", "data_sha256"] {
            if fixture_case[field] != baseline_case[field] {
                return Err(format!("{id}: fixture and Qt5 {field} evidence differ"));
            }
        }
        if baseline_case["parser_valid"] != true || baseline_case["archive_script_error"] != "" {
            return Err(format!(
                "{id}: Qt5 Archive parser/script evidence is not valid"
            ));
        }
        let verbose = fixture_case["verbose"]
            .as_bool()
            .ok_or_else(|| format!("{id}: verbose flag is missing"))?;
        let data_hex = fixture_case["data_hex"]
            .as_str()
            .ok_or_else(|| format!("{id}: data_hex is missing"))?;
        let data = decode_hex_string(data_hex, &format!("{id}.data_hex"))?;
        if sha256_hex(&data) != fixture_case["data_sha256"] {
            return Err(format!("{id}: decoded input hash mismatch"));
        }
        let archive_context =
            ArchiveRuleContext::parse(&data, verbose).map_err(|error| format!("{id}: {error}"))?;
        let native_matches = archive_context.is_verbose == baseline_case["native_is_verbose"]
            && archive_context.file_format_name == baseline_case["native_format_name"]
            && archive_context.file_format_version == baseline_case["native_format_version"]
            && archive_context.file_format_options == baseline_case["native_format_options"];

        let (runtime, runtime_probe) = new_rule_case_runtime_with_tracking(tracking_limit_bytes)?;
        let context = new_context(&runtime)?;
        let detections = Arc::new(Mutex::new(Vec::new()));
        install_nintendo_host(&context, Arc::new(data), Arc::clone(&detections))?;
        let archive_trace = install_archive_host(&context, archive_context.clone())?;
        eval_unit(&context, FORMAT_RESULT_SHIM)?;
        let initialized_memory = runtime_memory_snapshot(&runtime)?;
        let detect_result = eval_rule_lexical(&context, &rule_source, true)
            .map_err(|error| format!("{id}: fixed Archive rule failed: {error}"))?;
        let actual_detections = detections
            .lock()
            .map_err(|_| "Archive detection result mutex poisoned".to_owned())?
            .clone();
        let expected_detections: Vec<Detection> =
            serde_json::from_value(baseline_case["detections"].clone())
                .map_err(|error| format!("{id}: invalid Qt5 detections: {error}"))?;
        let expected_detect_result = baseline_case["detect_result"]
            .as_bool()
            .ok_or_else(|| format!("{id}: Qt5 detect result is missing"))?;
        let calls = [
            archive_trace.is_verbose_calls.load(Ordering::Relaxed),
            archive_trace
                .get_file_format_name_calls
                .load(Ordering::Relaxed),
            archive_trace
                .get_file_format_version_calls
                .load(Ordering::Relaxed),
            archive_trace
                .get_file_format_options_calls
                .load(Ordering::Relaxed),
        ];
        let expected_calls = if verbose { [1, 1, 1, 1] } else { [1, 0, 0, 0] };
        let expected_local_mismatches = if id == "verbose_central_directory_only" {
            1
        } else {
            0
        };
        let matches = native_matches
            && archive_context.local_header_signature_mismatches == expected_local_mismatches
            && detect_result == expected_detect_result.to_string()
            && actual_detections == expected_detections
            && calls == expected_calls;
        all_match &= matches;
        let runtime_measurement = runtime_probe.finish(runtime, context, initialized_memory)?;
        reports.push(json!({
            "id": id,
            "input_sha256": fixture_case["data_sha256"],
            "input_bytes": data_hex.len() / 2,
            "parser_valid": true,
            "verbose": verbose,
            "native": {
                "qt5": {
                    "is_verbose": baseline_case["native_is_verbose"],
                    "file_format_name": baseline_case["native_format_name"],
                    "file_format_version": baseline_case["native_format_version"],
                    "file_format_options": baseline_case["native_format_options"],
                },
                "rust": {
                    "is_verbose": archive_context.is_verbose,
                    "file_format_name": archive_context.file_format_name,
                    "file_format_version": archive_context.file_format_version,
                    "file_format_options": archive_context.file_format_options,
                },
                "matches": native_matches,
            },
            "rust_local_header_signature_mismatches":
                archive_context.local_header_signature_mismatches,
            "detect_result": {
                "qt5": expected_detect_result,
                "rust": detect_result,
            },
            "detections": {
                "qt5": expected_detections,
                "rust": actual_detections,
            },
            "archive_host_calls": {
                "is_verbose": calls[0],
                "get_file_format_name": calls[1],
                "get_file_format_version": calls[2],
                "get_file_format_options": calls[3],
            },
            "runtime_measurement": runtime_measurement,
            "matches": matches,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation":
                "byte-identical fixed Archive rule with Rust ZIP metadata context",
            "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
            "upstream_commit": UPSTREAM_COMMIT,
            "xarchive_commit": XARCHIVE_COMMIT,
            "xscanengine_commit": XSCANENGINE_COMMIT,
            "rules_commit": RULES_COMMIT,
            "rule": {
                "path": normalized_path(&rule_path),
                "bytes": rule_source.len(),
                "sha256": ARCHIVE_RULE_SHA256,
            },
            "fixture": {
                "path": normalized_path(fixture_path),
                "sha256": ARCHIVE_FIXTURE_SHA256,
            },
            "qt5_baseline": {
                "path": normalized_path(baseline_path),
                "sha256": ARCHIVE_QT5_BASELINE_SHA256,
            },
            "case_count": reports.len(),
            "matched_count": reports.iter().filter(|case| case["matches"] == true).count(),
            "cases": reports,
            "all_match": all_match,
        }))
        .map_err(|error| format!("cannot serialize Archive rule report: {error}"))?
    );
    Ok(all_match)
}

fn verify_pdf_rule(
    rule_root: &Path,
    fixture_path: &Path,
    baseline_path: &Path,
    tracking_limit_bytes: Option<usize>,
) -> Result<bool, String> {
    let fixture_bytes = fs::read(fixture_path)
        .map_err(|error| format!("cannot read {}: {error}", fixture_path.display()))?;
    let baseline_bytes = fs::read(baseline_path)
        .map_err(|error| format!("cannot read {}: {error}", baseline_path.display()))?;
    if sha256_hex(&fixture_bytes) != PDF_FIXTURE_SHA256 {
        return Err(format!(
            "fixed PDF fixture hash mismatch: {}",
            fixture_path.display()
        ));
    }
    if sha256_hex(&baseline_bytes) != PDF_QT5_BASELINE_SHA256 {
        return Err(format!(
            "fixed Qt5 PDF baseline hash mismatch: {}",
            baseline_path.display()
        ));
    }
    let rule_path = rule_root.join(PDF_RULE_SUFFIX);
    let rule_source = fs::read(&rule_path)
        .map_err(|error| format!("cannot read {}: {error}", rule_path.display()))?;
    if rule_source.len() != PDF_RULE_BYTES || sha256_hex(&rule_source) != PDF_RULE_SHA256 {
        return Err(format!("fixed PDF rule mismatch: {}", rule_path.display()));
    }
    let fixture: Value = serde_json::from_slice(&fixture_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", fixture_path.display()))?;
    let baseline: Value = serde_json::from_slice(&baseline_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", baseline_path.display()))?;
    for (document_name, document) in [("fixture", &fixture), ("baseline", &baseline)] {
        if document["upstream_commit"] != UPSTREAM_COMMIT
            || document["xpdf_commit"] != XPDF_COMMIT
            || document["xscanengine_commit"] != XSCANENGINE_COMMIT
            || document["rules_commit"] != RULES_COMMIT
            || document["case_count"] != 3
        {
            return Err(format!("{document_name} PDF metadata mismatch"));
        }
    }
    if fixture["rule"]["path"] != PDF_RULE_SUFFIX
        || fixture["rule"]["sha256"] != PDF_RULE_SHA256
        || baseline["rule_path"] != format!("/opt/die-source/Detect-It-Easy/db/{PDF_RULE_SUFFIX}")
        || baseline["rule_sha256"] != PDF_RULE_SHA256
        || baseline["qt_version"] != "5.15.13"
        || baseline["engine"] != "QScriptEngine"
    {
        return Err("fixed PDF fixture/baseline contract mismatch".to_owned());
    }
    let fixture_cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| "PDF fixture cases are missing".to_owned())?;
    let baseline_cases = baseline["cases"]
        .as_array()
        .ok_or_else(|| "Qt5 PDF baseline cases are missing".to_owned())?;
    if fixture_cases.len() != 3 || baseline_cases.len() != 3 {
        return Err("fixed PDF case count mismatch".to_owned());
    }

    let mut reports = Vec::with_capacity(fixture_cases.len());
    let mut all_match = true;
    for fixture_case in fixture_cases {
        let id = fixture_case["id"]
            .as_str()
            .ok_or_else(|| "PDF fixture case id is missing".to_owned())?;
        let baseline_case = baseline_cases
            .iter()
            .find(|case| case["id"] == id)
            .ok_or_else(|| format!("Qt5 PDF baseline case is missing: {id}"))?;
        for field in ["data_hex", "data_sha256"] {
            if fixture_case[field] != baseline_case[field] {
                return Err(format!("{id}: fixture and Qt5 {field} evidence differ"));
            }
        }
        if baseline_case["parser_valid"] != true || baseline_case["pdf_script_error"] != "" {
            return Err(format!("{id}: Qt5 PDF parser/script evidence is not valid"));
        }
        let data_hex = fixture_case["data_hex"]
            .as_str()
            .ok_or_else(|| format!("{id}: data_hex is missing"))?;
        let data = decode_hex_string(data_hex, &format!("{id}.data_hex"))?;
        if sha256_hex(&data) != fixture_case["data_sha256"] {
            return Err(format!("{id}: decoded input hash mismatch"));
        }
        let pdf_context = PdfRuleContext::parse(&data).map_err(|error| format!("{id}: {error}"))?;
        let actual_parts = Value::Array(
            pdf_context
                .objects
                .iter()
                .map(|object| {
                    json!({
                        "id": object.id,
                        "offset": object.offset,
                        "tokens": object.tokens,
                    })
                })
                .collect(),
        );
        let expected_creators: Vec<String> =
            serde_json::from_value(baseline_case["native_creator_values"].clone())
                .map_err(|error| format!("{id}: invalid Qt5 creator values: {error}"))?;
        let expected_producers: Vec<String> =
            serde_json::from_value(baseline_case["native_producer_values"].clone())
                .map_err(|error| format!("{id}: invalid Qt5 producer values: {error}"))?;
        let expected_header = baseline_case["native_header_comment_hex"]
            .as_str()
            .ok_or_else(|| format!("{id}: Qt5 header comment is missing"))?;
        let object_parts_match = actual_parts == baseline_case["object_parts"];
        let native_matches = pdf_context.creator_values == expected_creators
            && pdf_context.producer_values == expected_producers
            && pdf_context.header_comment_hex == expected_header;

        let (runtime, runtime_probe) = new_rule_case_runtime_with_tracking(tracking_limit_bytes)?;
        let context = new_context(&runtime)?;
        let detections = Arc::new(Mutex::new(Vec::new()));
        install_nintendo_host(&context, Arc::new(data), Arc::clone(&detections))?;
        let pdf_trace = install_pdf_host(&context, pdf_context.clone())?;
        eval_unit(&context, FORMAT_RESULT_SHIM)?;
        let initialized_memory = runtime_memory_snapshot(&runtime)?;
        let detect_result = eval_rule_lexical(&context, &rule_source, true)
            .map_err(|error| format!("{id}: fixed PDF rule failed: {error}"))?;
        let actual_detections = detections
            .lock()
            .map_err(|_| "PDF detection result mutex poisoned".to_owned())?
            .clone();
        let expected_detections: Vec<Detection> =
            serde_json::from_value(baseline_case["detections"].clone())
                .map_err(|error| format!("{id}: invalid Qt5 detections: {error}"))?;
        let values_calls = pdf_trace
            .get_string_values_by_key_calls
            .load(Ordering::Relaxed);
        let header_calls = pdf_trace
            .get_header_comment_as_hex_calls
            .load(Ordering::Relaxed);
        let expected_header_calls = expected_creators.len() + expected_producers.len();
        let matches = object_parts_match
            && pdf_context.objects.len()
                == baseline_case["object_count"]
                    .as_u64()
                    .and_then(|count| usize::try_from(count).ok())
                    .ok_or_else(|| format!("{id}: Qt5 object count is missing"))?
            && native_matches
            && detect_result == "undefined"
            && baseline_case["detect_is_undefined"] == true
            && actual_detections == expected_detections
            && values_calls == 2
            && header_calls == expected_header_calls;
        all_match &= matches;
        let runtime_measurement = runtime_probe.finish(runtime, context, initialized_memory)?;
        reports.push(json!({
            "id": id,
            "input_sha256": fixture_case["data_sha256"],
            "input_bytes": data_hex.len() / 2,
            "parser_valid": true,
            "object_count": pdf_context.objects.len(),
            "object_parts": {
                "qt5": baseline_case["object_parts"],
                "rust": actual_parts,
                "matches": object_parts_match,
            },
            "creator_values": {
                "qt5": expected_creators,
                "rust": pdf_context.creator_values,
            },
            "producer_values": {
                "qt5": expected_producers,
                "rust": pdf_context.producer_values,
            },
            "header_comment_hex": {
                "qt5": expected_header,
                "rust": pdf_context.header_comment_hex,
            },
            "detect_result": {
                "qt5_is_undefined": true,
                "rust": detect_result,
            },
            "detections": {
                "qt5": expected_detections,
                "rust": actual_detections,
            },
            "pdf_host_calls": {
                "get_string_values_by_key": values_calls,
                "get_header_comment_as_hex": header_calls,
            },
            "runtime_measurement": runtime_measurement,
            "matches": matches,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation":
                "byte-identical fixed PDF Tools rule with Rust object/string context",
            "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
            "upstream_commit": UPSTREAM_COMMIT,
            "xpdf_commit": XPDF_COMMIT,
            "xscanengine_commit": XSCANENGINE_COMMIT,
            "rules_commit": RULES_COMMIT,
            "rule": {
                "path": normalized_path(&rule_path),
                "bytes": rule_source.len(),
                "sha256": PDF_RULE_SHA256,
            },
            "fixture": {
                "path": normalized_path(fixture_path),
                "sha256": PDF_FIXTURE_SHA256,
            },
            "qt5_baseline": {
                "path": normalized_path(baseline_path),
                "sha256": PDF_QT5_BASELINE_SHA256,
            },
            "case_count": reports.len(),
            "matched_count": reports.iter().filter(|case| case["matches"] == true).count(),
            "cases": reports,
            "all_match": all_match,
        }))
        .map_err(|error| format!("cannot serialize PDF rule report: {error}"))?
    );
    Ok(all_match)
}

fn upstream_type_priority(kind: &str) -> i32 {
    let normalized = kind.to_lowercase().replace(['~', '!'], "");
    match normalized.as_str() {
        "operation system" | "virtual machine" => 10,
        "format" => 12,
        "platform" | "dos extender" => 14,
        "linker" => 20,
        "compiler" => 30,
        "language" => 40,
        "library" => 50,
        "tool" | "pe tool" | "sign tool" | "apk tool" => 60,
        "protector" | "cryptor" | "crypter" => 70,
        ".net obfuscator" | "apk obfuscator" | "jar obfuscator" => 80,
        "dongle protection" | "protection" => 90,
        "packer" | ".net compressor" => 100,
        "joiner" => 110,
        "sfx" | "installer" => 120,
        "virus" | "malware" | "trojan" | "corrupted data" | "personal data" | "author" => 70,
        "debug data" => 200,
        _ => 1000,
    }
}

fn parse_detection_triples(
    value: &Value,
    sample_name: &str,
) -> Result<Vec<DetectionTriple>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("baseline detections for {sample_name} are not an array"))?
        .iter()
        .enumerate()
        .map(|(index, detection)| {
            let fields = detection.as_array().ok_or_else(|| {
                format!("baseline detection {index} for {sample_name} is not an array")
            })?;
            if fields.len() != 3 {
                return Err(format!(
                    "baseline detection {index} for {sample_name} has {} fields, expected 3",
                    fields.len()
                ));
            }
            Ok((
                fields[0]
                    .as_str()
                    .ok_or_else(|| {
                        format!("baseline detection {index} type for {sample_name} is not a string")
                    })?
                    .to_owned(),
                fields[1]
                    .as_str()
                    .ok_or_else(|| {
                        format!("baseline detection {index} name for {sample_name} is not a string")
                    })?
                    .to_owned(),
                fields[2]
                    .as_str()
                    .ok_or_else(|| {
                        format!(
                            "baseline detection {index} version for {sample_name} is not a string"
                        )
                    })?
                    .to_owned(),
            ))
        })
        .collect()
}

fn parse_runtime_detections(report: &Value, sample_name: &str) -> Result<Vec<Detection>, String> {
    report
        .get("detections")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("runtime detections for {sample_name} are missing"))?
        .iter()
        .enumerate()
        .map(|(index, detection)| {
            let fields = detection.as_array().ok_or_else(|| {
                format!("runtime detection {index} for {sample_name} is not an array")
            })?;
            if fields.len() != 4 {
                return Err(format!(
                    "runtime detection {index} for {sample_name} has {} fields, expected 4",
                    fields.len()
                ));
            }
            let field = |field_index: usize, label: &str| {
                fields[field_index]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        format!(
                            "runtime detection {index} {label} for {sample_name} is not a string"
                        )
                    })
            };
            Ok((
                field(0, "type")?,
                field(1, "name")?,
                field(2, "version")?,
                field(3, "info")?,
            ))
        })
        .collect()
}

fn sorted_detection_projection(detections: &[Detection]) -> (Vec<DetectionTriple>, bool) {
    let mut priority_counts = BTreeMap::new();
    for (kind, _, _, _) in detections {
        *priority_counts
            .entry(upstream_type_priority(kind))
            .or_insert(0_usize) += 1;
    }
    let priorities_unambiguous = priority_counts.values().all(|count| *count == 1);
    let mut sorted = detections.to_vec();
    sorted.sort_by_key(|(kind, _, _, _)| upstream_type_priority(kind));
    (
        sorted
            .into_iter()
            .map(|(kind, name, version, _)| (kind, name, version))
            .collect(),
        priorities_unambiguous,
    )
}

fn report_u64(report: &Value, field: &str, sample_name: &str) -> Result<u64, String> {
    report
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{sample_name}: runtime report field {field} is missing"))
}

fn report_nested_u64(report: &Value, path: &[&str], sample_name: &str) -> Result<u64, String> {
    let mut value = report;
    for field in path {
        value = value.get(*field).ok_or_else(|| {
            format!(
                "{sample_name}: runtime report field {} is missing",
                path.join(".")
            )
        })?;
    }
    value.as_u64().ok_or_else(|| {
        format!(
            "{sample_name}: runtime report field {} is not an unsigned integer",
            path.join(".")
        )
    })
}

fn verify_binary_corpus(
    rule_root: &Path,
    corpus_root: &Path,
    corpus_manifest_path: &Path,
    baseline_path: &Path,
    order_path: &Path,
) -> Result<bool, String> {
    verify_binary_corpus_with_tracking(
        rule_root,
        corpus_root,
        corpus_manifest_path,
        baseline_path,
        order_path,
        None,
    )
}

fn verify_binary_corpus_with_tracking(
    rule_root: &Path,
    corpus_root: &Path,
    corpus_manifest_path: &Path,
    baseline_path: &Path,
    order_path: &Path,
    tracking_limit_bytes: Option<usize>,
) -> Result<bool, String> {
    let corpus_manifest_bytes = fs::read(corpus_manifest_path).map_err(|error| {
        format!(
            "cannot read corpus manifest {}: {error}",
            corpus_manifest_path.display()
        )
    })?;
    if sha256_hex(&corpus_manifest_bytes) != NINTENDO_CORPUS_MANIFEST_SHA256 {
        return Err("Nintendo corpus manifest SHA-256 mismatch".to_owned());
    }
    let corpus_manifest: Value =
        serde_json::from_slice(&corpus_manifest_bytes).map_err(|error| {
            format!(
                "cannot parse corpus manifest {}: {error}",
                corpus_manifest_path.display()
            )
        })?;
    if corpus_manifest
        .get("schema_version")
        .and_then(Value::as_u64)
        != Some(1)
        || corpus_manifest.get("generator").and_then(Value::as_str)
            != Some("tools/corpus/generate_nintendo_certified_corpus.py")
    {
        return Err("unexpected Nintendo corpus manifest identity".to_owned());
    }
    let mut manifest_samples = BTreeMap::new();
    for sample in corpus_manifest
        .get("samples")
        .and_then(Value::as_array)
        .ok_or_else(|| "Nintendo corpus manifest samples are missing".to_owned())?
    {
        let name = sample
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "Nintendo corpus manifest sample name is missing".to_owned())?
            .to_owned();
        let size = sample
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("Nintendo corpus manifest size is missing for {name}"))?;
        let sha256 = sample
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Nintendo corpus manifest SHA-256 is missing for {name}"))?
            .to_owned();
        if manifest_samples
            .insert(name.clone(), (size, sha256))
            .is_some()
        {
            return Err(format!("duplicate Nintendo corpus manifest sample: {name}"));
        }
    }

    let baseline_bytes = fs::read(baseline_path)
        .map_err(|error| format!("cannot read {}: {error}", baseline_path.display()))?;
    if sha256_hex(&baseline_bytes) != NINTENDO_BASELINE_SHA256 {
        return Err("Nintendo oracle baseline SHA-256 mismatch".to_owned());
    }
    let baseline: Value = serde_json::from_slice(&baseline_bytes)
        .map_err(|error| format!("cannot parse {}: {error}", baseline_path.display()))?;
    if baseline.get("schema_version").and_then(Value::as_u64) != Some(1)
        || baseline.get("expected_revision").and_then(Value::as_str) != Some(UPSTREAM_COMMIT)
        || baseline.get("rules_commit").and_then(Value::as_str) != Some(RULES_COMMIT)
    {
        return Err("unexpected Nintendo oracle baseline identity".to_owned());
    }
    let baseline_samples = baseline
        .get("samples")
        .and_then(Value::as_object)
        .ok_or_else(|| "Nintendo oracle baseline samples are missing".to_owned())?;
    let manifest_names = manifest_samples.keys().collect::<BTreeSet<_>>();
    let baseline_names = baseline_samples.keys().collect::<BTreeSet<_>>();
    if manifest_names != baseline_names {
        return Err("Nintendo corpus manifest and oracle baseline sample sets differ".to_owned());
    }

    let mut sample_reports = Vec::with_capacity(baseline_samples.len());
    let mut all_match = true;
    let mut signature_compare_call_total = 0_u64;
    let mut signature_search_call_total = 0_u64;
    let mut native_checkpoint_total = 0_u64;
    let mut compare_native_checkpoint_total = 0_u64;
    let mut search_native_checkpoint_total = 0_u64;
    let mut attempted_detect_count = 0_u64;
    let mut accepted_detect_count = 0_u64;
    let mut detect_error_count = 0_u64;
    let mut fallback_call_total = 0_u64;
    let mut signature_compare_error_total = 0_u64;
    let mut signature_search_error_total = 0_u64;
    let mut detection_count = 0_u64;
    let mut unambiguous_priority_sample_count = 0_usize;
    let mut nintendo_info_matched_count = 0_usize;
    let mut elapsed_ms = 0_u64;
    let mut interrupt_handler_call_total = 0_u64;
    let mut detect_interrupt_handler_call_sum = 0_u64;
    let mut interrupt_handler_calls_outside_detects = 0_u64;
    let mut maximum_interrupt_handler_calls_per_rule = 0_u64;
    let mut memory_checkpoint_count = 0_u64;
    let mut maximum_observed_malloc_size = 0_u64;
    let mut maximum_observed_malloc_size_sample = String::new();
    let mut maximum_observed_memory_used_size = 0_u64;
    let mut maximum_observed_memory_used_size_sample = String::new();
    let mut maximum_tracked_high_water_bytes = 0_u64;
    let mut maximum_tracked_high_water_sample = String::new();
    let mut tracking_denied_allocation_count = 0_u64;
    for (name, baseline_sample) in baseline_samples {
        let expected = parse_detection_triples(
            baseline_sample
                .get("detections")
                .ok_or_else(|| format!("baseline detections are missing for {name}"))?,
            name,
        )?;
        let (expected_size, expected_sha256) = &manifest_samples[name];
        let input_path = corpus_root.join(name);
        let input = fs::read(&input_path)
            .map_err(|error| format!("cannot read {}: {error}", input_path.display()))?;
        let input_size = input.len();
        let input_size_matches = input_size as u64 == *expected_size;
        let actual_sha256 = sha256_hex(&input);
        let input_sha256_matches = actual_sha256 == *expected_sha256;
        if !input_size_matches || !input_sha256_matches {
            return Err(format!(
                "{name}: generated input identity mismatch: size={} sha256={actual_sha256}",
                input.len()
            ));
        }

        let trace = trace_binary_detects_report_with_data_and_tracking(
            rule_root,
            &input_path,
            order_path,
            input,
            tracking_limit_bytes,
        )
        .map_err(|error| format!("{name}: {error}"))?;
        let actual = parse_runtime_detections(&trace, name)?;
        let execution_order = actual
            .iter()
            .map(|(kind, detection_name, version, _)| {
                (kind.clone(), detection_name.clone(), version.clone())
            })
            .collect::<Vec<_>>();
        let (output_order, output_priorities_unambiguous) = sorted_detection_projection(&actual);
        let nintendo_detections = actual
            .iter()
            .filter(|(_, detection_name, _, _)| detection_name.starts_with("Nintendō "))
            .collect::<Vec<_>>();
        let nintendo_info_ok =
            nintendo_detections.len() == 1 && nintendo_detections[0].3 == "fSELF";

        let attempted = report_u64(&trace, "attempted_detect_count", name)?;
        let accepted = report_u64(&trace, "accepted_detect_count", name)?;
        let errors = report_u64(&trace, "detect_error_count", name)?;
        let overlays = report_u64(&trace, "compatibility_overlay_count", name)?;
        let fallbacks = report_u64(&trace, "fallback_call_total", name)?;
        let include_calls = report_u64(&trace, "include_call_count", name)?;
        let compare_errors = report_u64(&trace, "signature_compare_error_total", name)?;
        let search_errors = report_u64(&trace, "signature_search_error_total", name)?;
        let sample_native_checkpoint_total = report_nested_u64(
            &trace,
            &["runtime_measurement", "native_checkpoint", "call_total"],
            name,
        )?;
        let sample_compare_native_checkpoint_total = report_nested_u64(
            &trace,
            &[
                "runtime_measurement",
                "native_checkpoint",
                "compare_call_total",
            ],
            name,
        )?;
        let sample_search_native_checkpoint_total = report_nested_u64(
            &trace,
            &[
                "runtime_measurement",
                "native_checkpoint",
                "search_call_total",
            ],
            name,
        )?;
        let sample_native_checkpoint_interval = report_nested_u64(
            &trace,
            &[
                "runtime_measurement",
                "native_checkpoint",
                "candidate_interval",
            ],
            name,
        )?;
        let sample_native_checkpoint_can_interrupt = trace
            .pointer("/runtime_measurement/native_checkpoint/can_interrupt_single_native_call")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("{name}: native checkpoint interrupt capability is missing"))?;
        let sample_interrupt_total = report_nested_u64(
            &trace,
            &["runtime_measurement", "interrupt", "handler_call_total"],
            name,
        )?;
        let sample_detect_interrupt_sum = report_nested_u64(
            &trace,
            &[
                "runtime_measurement",
                "interrupt",
                "detect_handler_call_sum",
            ],
            name,
        )?;
        let sample_interrupt_outside_detects = report_nested_u64(
            &trace,
            &[
                "runtime_measurement",
                "interrupt",
                "handler_calls_outside_detects",
            ],
            name,
        )?;
        let sample_maximum_interrupt_per_rule = report_nested_u64(
            &trace,
            &[
                "runtime_measurement",
                "interrupt",
                "maximum_handler_calls_per_rule",
            ],
            name,
        )?;
        let sample_memory_checkpoint_count = report_nested_u64(
            &trace,
            &["runtime_measurement", "memory", "checkpoint_count"],
            name,
        )?;
        let sample_maximum_malloc_size = report_nested_u64(
            &trace,
            &[
                "runtime_measurement",
                "memory",
                "maximum_observed_malloc_size",
                "bytes",
            ],
            name,
        )?;
        let sample_maximum_memory_used_size = report_nested_u64(
            &trace,
            &[
                "runtime_measurement",
                "memory",
                "maximum_observed_memory_used_size",
                "bytes",
            ],
            name,
        )?;
        let sample_transient_high_water_measured = trace
            .pointer("/runtime_measurement/memory/transient_high_water_measured")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                format!("{name}: runtime memory transient high-water boundary is missing")
            })?;
        let sample_tracking = if let Some(expected_limit) = tracking_limit_bytes {
            let prefix = "/runtime_measurement/memory/tracking_allocator";
            let limit = trace
                .pointer(&format!("{prefix}/limit_bytes"))
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("{name}: tracking allocator limit is missing"))?;
            let live_before_drop = trace
                .pointer(&format!("{prefix}/live_bytes_before_drop"))
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    format!("{name}: tracking allocator live-before-drop value is missing")
                })?;
            let high_water = trace
                .pointer(&format!("{prefix}/high_water_bytes"))
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("{name}: tracking allocator high-water value is missing"))?;
            let denied = trace
                .pointer(&format!("{prefix}/denied_allocation_count"))
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    format!("{name}: tracking allocator denied-allocation count is missing")
                })?;
            let live_after_drop = trace
                .pointer(&format!("{prefix}/live_bytes_after_drop"))
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    format!("{name}: tracking allocator live-after-drop value is missing")
                })?;
            let set_memory_limit_used = trace
                .pointer(&format!("{prefix}/set_memory_limit_used"))
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    format!("{name}: tracking allocator set-memory-limit marker is missing")
                })?;
            Some((
                limit,
                live_before_drop,
                high_water,
                denied,
                live_after_drop,
                set_memory_limit_used,
                expected_limit as u64,
            ))
        } else {
            None
        };
        let tracking_measurement_ok = match sample_tracking {
            Some((
                limit,
                live_before_drop,
                high_water,
                denied,
                live_after_drop,
                set_memory_limit_used,
                expected_limit,
            )) => {
                sample_transient_high_water_measured
                    && limit == expected_limit
                    && live_before_drop > 0
                    && live_before_drop <= high_water
                    && high_water <= limit
                    && denied == 0
                    && live_after_drop == 0
                    && !set_memory_limit_used
            }
            None => {
                !sample_transient_high_water_measured
                    && trace
                        .pointer("/runtime_measurement/memory/tracking_allocator")
                        .is_none()
            }
        };
        let completed = trace.get("completed").and_then(Value::as_bool) == Some(true);
        let runtime_measurement_ok = sample_detect_interrupt_sum
            .checked_add(sample_interrupt_outside_detects)
            == Some(sample_interrupt_total)
            && sample_compare_native_checkpoint_total
                >= report_u64(&trace, "signature_compare_call_total", name)?
            && sample_search_native_checkpoint_total
                >= report_u64(&trace, "signature_search_call_total", name)?
            && sample_compare_native_checkpoint_total
                .checked_add(sample_search_native_checkpoint_total)
                == Some(sample_native_checkpoint_total)
            && sample_native_checkpoint_interval == NATIVE_CHECKPOINT_INTERVAL as u64
            && sample_native_checkpoint_can_interrupt
            && sample_memory_checkpoint_count == (BINARY_SIGNATURE_COUNT as u64 + 3)
            && sample_maximum_malloc_size > 0
            && sample_maximum_memory_used_size > 0
            && tracking_measurement_ok;
        let lifecycle_ok = attempted == BINARY_SIGNATURE_COUNT as u64
            && accepted == BINARY_SIGNATURE_COUNT as u64
            && errors == 0
            && overlays == 1
            && fallbacks == 0
            && include_calls == 30
            && compare_errors == 0
            && search_errors == 0
            && runtime_measurement_ok
            && completed;
        let matches = lifecycle_ok
            && output_priorities_unambiguous
            && output_order == expected
            && nintendo_info_ok;
        all_match &= matches;
        unambiguous_priority_sample_count += usize::from(output_priorities_unambiguous);
        nintendo_info_matched_count += usize::from(nintendo_info_ok);

        signature_compare_call_total = signature_compare_call_total
            .checked_add(report_u64(&trace, "signature_compare_call_total", name)?)
            .ok_or_else(|| "signature compare aggregate overflow".to_owned())?;
        signature_search_call_total = signature_search_call_total
            .checked_add(report_u64(&trace, "signature_search_call_total", name)?)
            .ok_or_else(|| "signature search aggregate overflow".to_owned())?;
        native_checkpoint_total = native_checkpoint_total
            .checked_add(sample_native_checkpoint_total)
            .ok_or_else(|| "native checkpoint aggregate overflow".to_owned())?;
        compare_native_checkpoint_total = compare_native_checkpoint_total
            .checked_add(sample_compare_native_checkpoint_total)
            .ok_or_else(|| "compare native checkpoint aggregate overflow".to_owned())?;
        search_native_checkpoint_total = search_native_checkpoint_total
            .checked_add(sample_search_native_checkpoint_total)
            .ok_or_else(|| "search native checkpoint aggregate overflow".to_owned())?;
        elapsed_ms = elapsed_ms
            .checked_add(report_u64(&trace, "elapsed_ms", name)?)
            .ok_or_else(|| "elapsed millisecond aggregate overflow".to_owned())?;
        attempted_detect_count = attempted_detect_count
            .checked_add(attempted)
            .ok_or_else(|| "attempted detect aggregate overflow".to_owned())?;
        accepted_detect_count = accepted_detect_count
            .checked_add(accepted)
            .ok_or_else(|| "accepted detect aggregate overflow".to_owned())?;
        detect_error_count = detect_error_count
            .checked_add(errors)
            .ok_or_else(|| "detect error aggregate overflow".to_owned())?;
        fallback_call_total = fallback_call_total
            .checked_add(fallbacks)
            .ok_or_else(|| "fallback call aggregate overflow".to_owned())?;
        signature_compare_error_total =
            signature_compare_error_total
                .checked_add(compare_errors)
                .ok_or_else(|| "signature compare error aggregate overflow".to_owned())?;
        signature_search_error_total = signature_search_error_total
            .checked_add(search_errors)
            .ok_or_else(|| "signature search error aggregate overflow".to_owned())?;
        detection_count = detection_count
            .checked_add(actual.len() as u64)
            .ok_or_else(|| "detection aggregate overflow".to_owned())?;
        interrupt_handler_call_total = interrupt_handler_call_total
            .checked_add(sample_interrupt_total)
            .ok_or_else(|| "interrupt handler aggregate overflow".to_owned())?;
        detect_interrupt_handler_call_sum = detect_interrupt_handler_call_sum
            .checked_add(sample_detect_interrupt_sum)
            .ok_or_else(|| "detect interrupt aggregate overflow".to_owned())?;
        interrupt_handler_calls_outside_detects = interrupt_handler_calls_outside_detects
            .checked_add(sample_interrupt_outside_detects)
            .ok_or_else(|| "outside-detect interrupt aggregate overflow".to_owned())?;
        maximum_interrupt_handler_calls_per_rule =
            maximum_interrupt_handler_calls_per_rule.max(sample_maximum_interrupt_per_rule);
        memory_checkpoint_count = memory_checkpoint_count
            .checked_add(sample_memory_checkpoint_count)
            .ok_or_else(|| "memory checkpoint aggregate overflow".to_owned())?;
        if sample_maximum_malloc_size > maximum_observed_malloc_size {
            maximum_observed_malloc_size = sample_maximum_malloc_size;
            maximum_observed_malloc_size_sample = name.clone();
        }
        if sample_maximum_memory_used_size > maximum_observed_memory_used_size {
            maximum_observed_memory_used_size = sample_maximum_memory_used_size;
            maximum_observed_memory_used_size_sample = name.clone();
        }
        if let Some((_, _, high_water, denied, _, _, _)) = sample_tracking {
            tracking_denied_allocation_count = tracking_denied_allocation_count
                .checked_add(denied)
                .ok_or_else(|| "tracking denied-allocation aggregate overflow".to_owned())?;
            if high_water > maximum_tracked_high_water_bytes {
                maximum_tracked_high_water_bytes = high_water;
                maximum_tracked_high_water_sample = name.clone();
            }
        }

        sample_reports.push(json!({
            "name": name,
            "input": {
                "bytes": input_size,
                "sha256": actual_sha256,
            },
            "expected_output_order": expected,
            "actual_execution_order": execution_order,
            "actual_output_order": output_order,
            "actual_detection_details": actual,
            "output_priorities_unambiguous": output_priorities_unambiguous,
            "nintendo_info_ok": nintendo_info_ok,
            "lifecycle": {
                "attempted_detect_count": attempted,
                "accepted_detect_count": accepted,
                "detect_error_count": errors,
                "compatibility_overlay_count": overlays,
                "fallback_call_total": fallbacks,
                "include_call_count": include_calls,
                "signature_compare_error_total": compare_errors,
                "signature_search_error_total": search_errors,
                "runtime_measurement_ok": runtime_measurement_ok,
                "completed": completed,
                "matches": lifecycle_ok,
            },
            "runtime_measurement": trace["runtime_measurement"],
            "matches": matches,
        }));
    }

    let mut runtime_measurement = json!({
        "sample_runtime_count": sample_reports.len(),
        "native_checkpoint": {
            "semantics":
                "one callback at each Binary signature compare/search entry and then before every 4096th searched candidate position within the same native call",
            "candidate_interval": NATIVE_CHECKPOINT_INTERVAL,
            "call_total": native_checkpoint_total,
            "compare_call_total": compare_native_checkpoint_total,
            "search_call_total": search_native_checkpoint_total,
            "can_interrupt_single_native_call": true,
        },
        "interrupt": {
            "handler_semantics":
                "one QuickJS-NG interrupt callback invocation; each sample uses one monotonic runtime counter",
            "handler_call_total": interrupt_handler_call_total,
            "detect_handler_call_sum": detect_interrupt_handler_call_sum,
            "handler_calls_outside_detects":
                interrupt_handler_calls_outside_detects,
            "maximum_handler_calls_per_rule":
                maximum_interrupt_handler_calls_per_rule,
        },
        "memory": {
            "api": "rquickjs Runtime::memory_usage / QuickJS-NG JS_ComputeMemoryUsage",
            "scope":
                "post-operation lifecycle checkpoints over all 14 sample runtimes; transient in-eval allocator high-water is not observed",
            "checkpoint_count": memory_checkpoint_count,
            "maximum_observed_malloc_size": {
                "bytes": maximum_observed_malloc_size,
                "sample": maximum_observed_malloc_size_sample,
            },
            "maximum_observed_memory_used_size": {
                "bytes": maximum_observed_memory_used_size,
                "sample": maximum_observed_memory_used_size_sample,
            },
            "transient_high_water_measured": false,
        },
    });
    if let Some(limit_bytes) = tracking_limit_bytes {
        runtime_measurement["memory"]["scope"] = json!(
            "post-operation lifecycle checkpoints plus allocator-observed transient live-byte high-water over all 14 sample runtimes"
        );
        runtime_measurement["memory"]["transient_high_water_measured"] = json!(true);
        runtime_measurement["memory"]["tracking_allocator"] = json!({
            "backend": "rquickjs RustAllocator wrapped by TrackingLimitAllocator",
            "limit_bytes_per_sample_runtime": limit_bytes,
            "set_memory_limit_used": false,
            "accounting": "RustAllocator allocation Layout bytes: aligned payload plus internal header",
            "maximum_high_water_bytes": maximum_tracked_high_water_bytes,
            "maximum_high_water_sample": maximum_tracked_high_water_sample,
            "denied_allocation_count": tracking_denied_allocation_count,
            "all_runtimes_released_to_zero": true,
        });
    }
    let sample_measurements = sample_reports
        .iter()
        .map(|sample| {
            json!({
                "name": sample["name"],
                "runtime_measurement": sample["runtime_measurement"],
            })
        })
        .collect::<Vec<_>>();
    let stable_projection = json!({
        "all_match": all_match,
        "matched_count":
            sample_reports.iter().filter(|sample| sample["matches"] == true).count(),
        "attempted_detect_count": attempted_detect_count,
        "accepted_detect_count": accepted_detect_count,
        "detect_error_count": detect_error_count,
        "fallback_call_total": fallback_call_total,
        "signature_compare_call_total": signature_compare_call_total,
        "signature_search_call_total": signature_search_call_total,
        "runtime_measurement": runtime_measurement,
        "sample_measurements": sample_measurements,
    });
    let stable_projection_sha256 = sha256_hex(
        &serde_json::to_vec(&stable_projection)
            .map_err(|error| format!("cannot serialize stable runtime projection: {error}"))?,
    );
    let report = json!({
        "schema_version": 1,
        "operation": "all fixed-order Binary detect functions over the generated Nintendo corpus",
        "scope": "14 generated Binary header samples; exact ordered type/name/version oracle plus Nintendo info invariant",
        "runtime": "rquickjs 0.12.1 / QuickJS-NG 0.15.1",
        "upstream_commit": UPSTREAM_COMMIT,
        "rules_commit": RULES_COMMIT,
        "compatibility_overlay": "nintendo-unused-var-tp-v1",
        "corpus_manifest": normalized_path(corpus_manifest_path),
        "corpus_manifest_sha256": sha256_hex(&corpus_manifest_bytes),
        "baseline": normalized_path(baseline_path),
        "baseline_sha256": sha256_hex(&baseline_bytes),
        "order_manifest": normalized_path(order_path),
        "order_sha256": LINUX_QT5_BINARY_ORDER_SHA256,
        "result_sort_oracle": {
            "component": "XScanEngine@dfe4a419e4f491bb23688ba03c5a5bf39e34da83",
            "source": "xscanengine.cpp::_sortItems, sortRecords, typeToPrio",
            "comparison": "ascending numeric nPrio",
            "equal_priority_limitation": "upstream std::sort has no stable tie-order contract; every multi-detection sample in this corpus has distinct priorities",
        },
        "rule_count_per_sample": BINARY_SIGNATURE_COUNT,
        "sample_count": sample_reports.len(),
        "matched_count": sample_reports.iter().filter(|sample| sample["matches"] == true).count(),
        "attempted_detect_count": attempted_detect_count,
        "accepted_detect_count": accepted_detect_count,
        "detect_error_count": detect_error_count,
        "fallback_call_total": fallback_call_total,
        "signature_compare_error_total": signature_compare_error_total,
        "signature_search_error_total": signature_search_error_total,
        "detection_count": detection_count,
        "unambiguous_priority_sample_count": unambiguous_priority_sample_count,
        "nintendo_info_matched_count": nintendo_info_matched_count,
        "signature_compare_call_total": signature_compare_call_total,
        "signature_search_call_total": signature_search_call_total,
        "runtime_measurement": runtime_measurement,
        "stable_projection_sha256": stable_projection_sha256,
        "elapsed_ms": elapsed_ms,
        "samples": sample_reports,
        "all_match": all_match,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot serialize corpus report: {error}"))?
    );
    Ok(all_match)
}

fn evaluate_corpus(
    roots: &[PathBuf],
    shared_realm: bool,
    compatibility_overlay: bool,
    tracking_limit_bytes: Option<usize>,
) -> Result<bool, String> {
    let mut files = Vec::new();
    for root in roots {
        collect_rule_files(root, &mut files)?;
    }
    files.sort_by_key(|path| normalized_path(path));

    let started = Instant::now();
    let (runtime, tracking) = if let Some(limit) = tracking_limit_bytes {
        let (runtime, stats) = new_tracking_runtime(limit)?;
        (runtime, Some((limit, stats)))
    } else {
        (new_runtime()?, None)
    };
    let interrupt_ticks = Arc::new(AtomicUsize::new(0));
    let interrupt_ticks_for_handler = Arc::clone(&interrupt_ticks);
    runtime.set_interrupt_handler(Some(Box::new(move || {
        interrupt_ticks_for_handler.fetch_add(1, Ordering::Relaxed) >= 1_000_000
    })));
    let shared_context = if shared_realm {
        let context = new_context(&runtime)?;
        install_host_shim(&context)?;
        Some(context)
    } else {
        None
    };
    let mut errors = Vec::new();
    let mut overlays_applied = Vec::new();
    let mut total_bytes = 0_u64;

    for path in &files {
        let original_bytes =
            fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        total_bytes = total_bytes
            .checked_add(original_bytes.len() as u64)
            .ok_or_else(|| "rule byte count overflow".to_owned())?;
        let (evaluated_bytes, overlay_applied) = if compatibility_overlay {
            apply_compatibility_overlay(path, &original_bytes)?
        } else {
            (original_bytes, false)
        };
        if overlay_applied {
            overlays_applied.push(normalized_path(path));
        }
        interrupt_ticks.store(0, Ordering::Relaxed);
        let isolated_context;
        let context = if let Some(context) = &shared_context {
            context
        } else {
            isolated_context = new_context(&runtime)?;
            install_host_shim(&isolated_context)?;
            &isolated_context
        };
        if let Err(error) = eval_unit(context, &evaluated_bytes) {
            errors.push(json!({
                "path": normalized_path(path),
                "error": error,
            }));
        }
    }

    let tracking_before_drop = tracking.as_ref().map(|(_, stats)| {
        (
            stats.live_bytes(),
            stats.high_water_bytes(),
            stats.denied_allocation_count(),
        )
    });
    drop(shared_context);
    drop(runtime);
    let tracking_report = if let (
        Some((limit_bytes, stats)),
        Some((live_before_drop, high_water_bytes, denied_allocation_count)),
    ) = (tracking, tracking_before_drop)
    {
        let live_after_drop = stats.live_bytes();
        if live_before_drop == 0
            || high_water_bytes < live_before_drop
            || high_water_bytes > limit_bytes
            || denied_allocation_count != 0
            || live_after_drop != 0
        {
            return Err(format!(
                "tracked corpus runtime invariant failed: limit={limit_bytes} \
                 live_before_drop={live_before_drop} high_water={high_water_bytes} \
                 denied={denied_allocation_count} live_after_drop={live_after_drop}"
            ));
        }
        Some(json!({
            "backend": "rquickjs RustAllocator wrapped by TrackingLimitAllocator",
            "limit_bytes": limit_bytes,
            "set_memory_limit_used": false,
            "accounting":
                "RustAllocator allocation Layout bytes: aligned payload plus internal header",
            "live_bytes_before_drop": live_before_drop,
            "high_water_bytes": high_water_bytes,
            "denied_allocation_count": denied_allocation_count,
            "live_bytes_after_drop": live_after_drop,
        }))
    } else {
        None
    };
    let mut report = json!({
        "schema_version": 1,
        "runtime": {
            "crate": "rquickjs",
            "version": "0.12.1",
            "default_features": false,
            "features": ["std"],
            "engine": "QuickJS-NG",
        },
        "realm_mode": if shared_realm { "shared" } else { "isolated" },
        "operation": if compatibility_overlay {
            "sloppy eval with explicit host proxy and manifest-pinned compatibility overlay"
        } else {
            "sloppy eval with explicit host proxy"
        },
        "compatibility_overlay": {
            "enabled": compatibility_overlay,
            "id": "nintendo-unused-var-tp-v1",
            "expected_source_sha256": NINTENDO_RULE_SHA256,
            "expected_source_bytes": NINTENDO_RULE_BYTES,
            "preserves_source_file": true,
            "preserves_evaluated_length": true,
            "applied_paths": overlays_applied,
        },
        "interrupt_handler_call_limit_per_file": 1_000_000,
        "selection": "recursive files with .sg or no extension",
        "roots": roots
            .iter()
            .map(|path| normalized_path(path))
            .collect::<Vec<_>>(),
        "files": files.len(),
        "bytes": total_bytes,
        "eval_errors": errors,
        "eval_error_count": errors.len(),
        "elapsed_ms": started.elapsed().as_millis(),
    });
    if let Some(tracking_report) = tracking_report {
        let stable_projection = json!({
            "schema_version": 1,
            "upstream_commit": UPSTREAM_COMMIT,
            "rules_commit": RULES_COMMIT,
            "realm_mode": "isolated",
            "selection": "recursive files with .sg or no extension",
            "files": files.len(),
            "bytes": total_bytes,
            "eval_error_count": errors.len(),
            "compatibility_overlay": {
                "id": "nintendo-unused-var-tp-v1",
                "applied_count": overlays_applied.len(),
            },
            "tracking_allocator": tracking_report.clone(),
        });
        let stable_projection_bytes = serde_json::to_vec(&stable_projection)
            .map_err(|error| format!("cannot serialize tracked corpus projection: {error}"))?;
        report["stable_projection_sha256"] = json!(sha256_hex(&stable_projection_bytes));
        report["stable_projection"] = stable_projection;
        report["tracking_allocator"] = tracking_report;
        report["scope"] = json!(
            "all fixed rule programs parsed and evaluated at top level in isolated realms \
             within one custom-allocator runtime; detect functions are not called and this \
             is not default-allocator or cross-platform evidence"
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot serialize report: {error}"))?
    );
    Ok(errors.is_empty())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IsolatedRuleHeapObservation {
    logical_path: String,
    source_bytes: u64,
    high_water_bytes: u64,
    live_bytes_before_drop: u64,
    interrupt_calls: u64,
}

fn rule_logical_path(roots: &[PathBuf], path: &Path) -> Result<String, String> {
    for root in roots {
        if let Ok(relative) = path.strip_prefix(root) {
            let root_name = root
                .file_name()
                .ok_or_else(|| format!("rule root has no file name: {}", root.display()))?;
            return Ok(format!(
                "{}/{}",
                root_name.to_string_lossy(),
                normalized_path(relative)
            ));
        }
    }
    Err(format!(
        "rule path is outside configured roots: {}",
        path.display()
    ))
}

fn rule_logical_scope(logical_path: &str) -> String {
    let mut components = logical_path.split('/');
    let root = components.next().unwrap_or("_unknown");
    let relative_head = components.next().unwrap_or("_root");
    let scope = if components.next().is_some() {
        relative_head
    } else {
        "_root"
    };
    format!("{root}/{scope}")
}

fn nearest_rank_percentile(sorted_values: &[u64], percentile: usize) -> Result<u64, String> {
    if sorted_values.is_empty() {
        return Err("cannot calculate a percentile from no observations".to_owned());
    }
    if !(1..=100).contains(&percentile) {
        return Err(format!("percentile must be in 1..=100, got {percentile}"));
    }
    let numerator = sorted_values
        .len()
        .checked_mul(percentile)
        .ok_or_else(|| "percentile rank overflow".to_owned())?;
    let rank = numerator
        .checked_add(99)
        .ok_or_else(|| "percentile rank rounding overflow".to_owned())?
        / 100;
    Ok(sorted_values[rank - 1])
}

fn measure_rule_corpus_isolated_heap(roots: &[PathBuf]) -> Result<bool, String> {
    let mut files = Vec::new();
    for root in roots {
        collect_rule_files(root, &mut files)?;
    }
    files.sort_by_key(|path| normalized_path(path));

    let started = Instant::now();
    let mut observations = Vec::with_capacity(files.len());
    let mut errors = Vec::new();
    let mut total_bytes = 0_u64;
    let mut overlay_paths = Vec::new();

    for path in &files {
        let original_bytes =
            fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let source_bytes = u64::try_from(original_bytes.len())
            .map_err(|_| format!("rule size does not fit u64: {}", path.display()))?;
        total_bytes = total_bytes
            .checked_add(source_bytes)
            .ok_or_else(|| "rule byte count overflow".to_owned())?;
        let (evaluated_bytes, overlay_applied) =
            apply_compatibility_overlay(path, &original_bytes)?;
        let logical_path = rule_logical_path(roots, path)?;
        if overlay_applied {
            overlay_paths.push(logical_path.clone());
        }

        let (runtime, probe) =
            new_rule_case_runtime_with_tracking(Some(TRACKED_RULE_RUNTIME_LIMIT_BYTES))?;
        let context = new_context(&runtime)?;
        install_host_shim(&context)?;
        let initialized = runtime_memory_snapshot(&runtime)?;
        let eval_error = eval_unit(&context, &evaluated_bytes).err();
        let measurement = probe.finish(runtime, context, initialized)?;
        if let Some(error) = eval_error {
            errors.push(json!({
                "path": logical_path,
                "error": error,
            }));
        }
        let tracking = &measurement["memory"]["tracking_allocator"];
        let high_water_bytes = tracking["high_water_bytes"]
            .as_u64()
            .ok_or_else(|| "tracked rule high-water is missing".to_owned())?;
        let live_bytes_before_drop = tracking["live_bytes_before_drop"]
            .as_u64()
            .ok_or_else(|| "tracked rule live-before-drop is missing".to_owned())?;
        let interrupt_calls = measurement["interrupt"]["handler_call_total"]
            .as_u64()
            .ok_or_else(|| "tracked rule interrupt count is missing".to_owned())?;
        observations.push(IsolatedRuleHeapObservation {
            logical_path,
            source_bytes,
            high_water_bytes,
            live_bytes_before_drop,
            interrupt_calls,
        });
    }

    if observations.is_empty() {
        return Err("tracked rule corpus is empty".to_owned());
    }

    let mut heap_values = observations
        .iter()
        .map(|observation| observation.high_water_bytes)
        .collect::<Vec<_>>();
    heap_values.sort_unstable();
    let mut ranked = observations.clone();
    ranked.sort_by(|left, right| {
        right
            .high_water_bytes
            .cmp(&left.high_water_bytes)
            .then_with(|| left.logical_path.cmp(&right.logical_path))
    });
    let maximum = ranked
        .first()
        .ok_or_else(|| "tracked rule corpus maximum is missing".to_owned())?;
    let maximum_interrupt = observations
        .iter()
        .max_by(|left, right| {
            left.interrupt_calls
                .cmp(&right.interrupt_calls)
                .then_with(|| right.logical_path.cmp(&left.logical_path))
        })
        .ok_or_else(|| "tracked rule interrupt maximum is missing".to_owned())?;
    let total_interrupt_calls = observations.iter().try_fold(0_u64, |total, observation| {
        total
            .checked_add(observation.interrupt_calls)
            .ok_or_else(|| "tracked rule interrupt total overflow".to_owned())
    })?;

    let mut scopes = BTreeMap::<String, Vec<&IsolatedRuleHeapObservation>>::new();
    for observation in &observations {
        scopes
            .entry(rule_logical_scope(&observation.logical_path))
            .or_default()
            .push(observation);
    }
    let scope_projection = scopes
        .into_iter()
        .map(|(scope, members)| {
            let maximum = members
                .iter()
                .copied()
                .max_by(|left, right| {
                    left.high_water_bytes
                        .cmp(&right.high_water_bytes)
                        .then_with(|| right.logical_path.cmp(&left.logical_path))
                })
                .ok_or_else(|| format!("tracked rule scope {scope} is empty"))?;
            Ok((
                scope,
                json!({
                    "rule_count": members.len(),
                    "maximum_high_water_bytes": maximum.high_water_bytes,
                    "maximum_rule": maximum.logical_path,
                }),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let top_rules = ranked
        .iter()
        .take(20)
        .map(|observation| {
            json!({
                "path": observation.logical_path,
                "source_bytes": observation.source_bytes,
                "high_water_bytes": observation.high_water_bytes,
                "live_bytes_before_drop": observation.live_bytes_before_drop,
                "interrupt_calls": observation.interrupt_calls,
            })
        })
        .collect::<Vec<_>>();
    let scope_projection_bytes = serde_json::to_vec(&scope_projection)
        .map_err(|error| format!("cannot serialize isolated rule heap scopes: {error}"))?;
    let top_rules_bytes = serde_json::to_vec(&top_rules)
        .map_err(|error| format!("cannot serialize isolated rule heap ranking: {error}"))?;
    let stable_projection = json!({
        "schema_version": 1,
        "upstream_commit": UPSTREAM_COMMIT,
        "rules_commit": RULES_COMMIT,
        "runtime_isolation": "one custom-allocator runtime and realm per rule",
        "selection": "recursive files with .sg or no extension",
        "files": observations.len(),
        "bytes": total_bytes,
        "eval_error_count": errors.len(),
        "compatibility_overlay": {
            "id": "nintendo-unused-var-tp-v1",
            "applied_paths": overlay_paths,
        },
        "tracking_allocator": {
            "backend": "rquickjs RustAllocator wrapped by TrackingLimitAllocator",
            "limit_bytes_per_rule_runtime": TRACKED_RULE_RUNTIME_LIMIT_BYTES,
            "set_memory_limit_used": false,
            "accounting":
                "RustAllocator allocation Layout bytes: aligned payload plus internal header",
            "denied_allocation_count": 0,
            "all_rule_runtimes_released_to_zero": true,
        },
        "heap_distribution_bytes": {
            "minimum": heap_values[0],
            "p50_nearest_rank": nearest_rank_percentile(&heap_values, 50)?,
            "p95_nearest_rank": nearest_rank_percentile(&heap_values, 95)?,
            "p99_nearest_rank": nearest_rank_percentile(&heap_values, 99)?,
            "maximum": maximum.high_water_bytes,
            "maximum_rule": maximum.logical_path,
            "maximum_rule_source_bytes": maximum.source_bytes,
        },
        "interrupt": {
            "handler_call_total": total_interrupt_calls,
            "maximum_handler_calls_per_rule": maximum_interrupt.interrupt_calls,
            "maximum_rule": maximum_interrupt.logical_path,
        },
        "scope_maxima": {
            "scope_count": scope_projection.len(),
            "sha256": sha256_hex(&scope_projection_bytes),
        },
        "top_rules_by_high_water": {
            "rule_count": top_rules.len(),
            "sha256": sha256_hex(&top_rules_bytes),
        },
    });
    let stable_projection_bytes = serde_json::to_vec(&stable_projection)
        .map_err(|error| format!("cannot serialize isolated rule heap projection: {error}"))?;
    let report = json!({
        "schema_version": 1,
        "operation": "isolated per-rule top-level parse/eval with custom allocator",
        "stable_projection_sha256": sha256_hex(&stable_projection_bytes),
        "stable_projection": stable_projection,
        "scope_maxima": scope_projection,
        "top_rules_by_high_water": top_rules,
        "eval_errors": errors,
        "elapsed_ms": started.elapsed().as_millis(),
        "scope":
            "all fixed rule programs evaluated separately; detect functions are not called and \
             this is not upstream lifecycle, default-allocator, or cross-platform evidence",
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot serialize isolated rule heap report: {error}"))?
    );
    Ok(errors.is_empty())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScopeInitExpectation {
    scope: String,
    selected_init: String,
    program_file_count: u64,
    transitive_include_evaluation_count: u64,
    maximum_active_include_depth: u64,
}

fn parse_scope_init_expectations(
    manifest_path: &Path,
) -> Result<Vec<ScopeInitExpectation>, String> {
    let bytes = fs::read(manifest_path)
        .map_err(|error| format!("cannot read {}: {error}", manifest_path.display()))?;
    if sha256_hex(&bytes) != INCLUDE_GRAPH_SIZING_SHA256 {
        return Err("include graph sizing SHA-256 mismatch".to_owned());
    }
    let document: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse {}: {error}", manifest_path.display()))?;
    if document.get("upstream_commit").and_then(Value::as_str) != Some(UPSTREAM_COMMIT) {
        return Err("include graph sizing upstream commit mismatch".to_owned());
    }
    if document.get("rules_commit").and_then(Value::as_str) != Some(RULES_COMMIT) {
        return Err("include graph sizing rules commit mismatch".to_owned());
    }
    let sizing = document
        .get("sizing")
        .and_then(Value::as_object)
        .ok_or_else(|| "include graph sizing object is missing".to_owned())?;
    if sizing.get("scope_count").and_then(Value::as_u64) != Some(30)
        || sizing
            .get("maximum_transitive_include_evaluations")
            .and_then(Value::as_u64)
            != Some(30)
        || sizing
            .get("maximum_active_include_depth")
            .and_then(Value::as_u64)
            != Some(2)
    {
        return Err("include graph sizing summary drift".to_owned());
    }
    let records = sizing
        .get("scopes")
        .and_then(Value::as_array)
        .ok_or_else(|| "include graph sizing scopes are missing".to_owned())?;
    let mut expectations = Vec::with_capacity(records.len());
    for record in records {
        let scope = record
            .get("scope")
            .and_then(Value::as_str)
            .ok_or_else(|| "include graph scope name is missing".to_owned())?;
        if scope.is_empty()
            || !scope
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(format!("invalid include graph scope name: {scope}"));
        }
        let selected_init = record
            .get("selected_init")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("selected init is missing for scope {scope}"))?;
        if selected_init != format!("db/{scope}/_init") {
            return Err(format!(
                "unexpected selected init for scope {scope}: {selected_init}"
            ));
        }
        let program_file_count = record
            .get("program_file_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("program file count is missing for scope {scope}"))?;
        let transitive_include_evaluation_count = record
            .get("transitive_include_evaluation_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("include evaluation count is missing for scope {scope}"))?;
        let maximum_active_include_depth = record
            .get("maximum_active_include_depth")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("include depth is missing for scope {scope}"))?;
        if program_file_count == 0
            || transitive_include_evaluation_count == 0
            || maximum_active_include_depth == 0
        {
            return Err(format!("zero include sizing value for scope {scope}"));
        }
        expectations.push(ScopeInitExpectation {
            scope: scope.to_owned(),
            selected_init: selected_init.to_owned(),
            program_file_count,
            transitive_include_evaluation_count,
            maximum_active_include_depth,
        });
    }
    expectations.sort_by(|left, right| left.scope.cmp(&right.scope));
    if expectations.len() != 30
        || expectations
            .windows(2)
            .any(|pair| pair[0].scope == pair[1].scope)
    {
        return Err("include graph scope inventory is incomplete or duplicated".to_owned());
    }
    Ok(expectations)
}

fn install_scope_include_probe(context: &Context, rule_root: &Path) -> Result<(), String> {
    install_main_include_registry(context, rule_root)?;
    eval_unit(
        context,
        br#"
        globalThis.__includeDepth = 0;
        globalThis.__includeMaximumDepth = 0;
        globalThis.__includeRegistryEval = includeScript;
        includeScript = function (name) {
            __includeDepth++;
            if (__includeDepth > __includeMaximumDepth) {
                __includeMaximumDepth = __includeDepth;
            }
            try {
                return __includeRegistryEval(name);
            } finally {
                __includeDepth--;
            }
        };
        "#,
    )
}

fn verify_scope_lifecycles_tracked_heap(
    rule_root: &Path,
    extra_rule_root: &Path,
    manifest_path: &Path,
) -> Result<bool, String> {
    let expectations = parse_scope_init_expectations(manifest_path)?;
    let global_init_path = rule_root.join("_init");
    let global_init = fs::read(&global_init_path)
        .map_err(|error| format!("cannot read {}: {error}", global_init_path.display()))?;
    let started = Instant::now();
    let mut scope_results = Vec::with_capacity(expectations.len());
    let mut heap_values = Vec::with_capacity(expectations.len());
    let mut total_program_files = 0_u64;
    let mut total_include_evaluations = 0_u64;
    let mut total_interrupt_calls = 0_u64;
    let mut total_compatibility_overlays = 0_u64;

    for expectation in &expectations {
        let relative_init = expectation
            .selected_init
            .strip_prefix("db/")
            .ok_or_else(|| format!("selected init is outside db: {}", expectation.selected_init))?;
        let type_init_path = rule_root.join(relative_init);
        let type_init = fs::read(&type_init_path)
            .map_err(|error| format!("cannot read {}: {error}", type_init_path.display()))?;
        let (runtime, probe) =
            new_rule_case_runtime_with_tracking(Some(TRACKED_RULE_RUNTIME_LIMIT_BYTES))?;
        let context = new_context(&runtime)?;
        install_host_shim(&context)?;
        install_scope_include_probe(&context, rule_root)?;
        eval_unit(&context, &global_init)
            .map_err(|error| format!("cannot eval {}: {error}", global_init_path.display()))?;
        let initialized = runtime_memory_snapshot(&runtime)?;
        eval_unit(&context, &type_init)
            .map_err(|error| format!("cannot eval {}: {error}", type_init_path.display()))?;
        let mut scope_rule_files = Vec::new();
        for layer_root in [rule_root, extra_rule_root] {
            let scope_root = layer_root.join(&expectation.scope);
            if !scope_root.is_dir() {
                continue;
            }
            let entries = fs::read_dir(&scope_root)
                .map_err(|error| format!("cannot read {}: {error}", scope_root.display()))?;
            let mut layer_files = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|error| {
                    format!("cannot enumerate {}: {error}", scope_root.display())
                })?;
                let path = entry.path();
                let file_type = entry
                    .file_type()
                    .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
                if file_type.is_file()
                    && path.file_name().and_then(|name| name.to_str()) != Some("_init")
                    && (path.extension().is_none()
                        || path.extension().is_some_and(|extension| extension == "sg"))
                {
                    layer_files.push(path);
                }
            }
            layer_files.sort_by_key(|path| normalized_path(path));
            scope_rule_files.extend(layer_files);
        }
        let observed_program_count = u64::try_from(scope_rule_files.len())
            .map_err(|_| format!("{} rule count overflow", expectation.scope))?
            .checked_add(1)
            .ok_or_else(|| format!("{} program count overflow", expectation.scope))?;
        if observed_program_count != expectation.program_file_count {
            return Err(format!(
                "{} program count mismatch: {observed_program_count}/{}",
                expectation.scope, expectation.program_file_count
            ));
        }
        let mut scope_overlay_count = 0_u64;
        let mut non_function_detects = Vec::new();
        for path in &scope_rule_files {
            let source = fs::read(path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            let (evaluated, overlay_applied) = apply_compatibility_overlay(path, &source)?;
            if overlay_applied {
                scope_overlay_count = scope_overlay_count
                    .checked_add(1)
                    .ok_or_else(|| "scope overlay count overflow".to_owned())?;
            }
            let detect_type = eval_rule_lexical(&context, &evaluated, false)
                .map_err(|error| format!("cannot eval {}: {error}", path.display()))?;
            if detect_type != "function" {
                non_function_detects.push(normalized_path(path));
            }
        }
        if !non_function_detects.is_empty() {
            return Err(format!(
                "{} contains non-function detect bindings: {}",
                expectation.scope,
                non_function_detects.join(", ")
            ));
        }
        let trace_text = eval_string(&context, b"JSON.stringify(__includeTrace)")?;
        let trace: Value = serde_json::from_str(&trace_text).map_err(|error| {
            format!("cannot parse {} include trace: {error}", expectation.scope)
        })?;
        let trace_values = trace
            .as_array()
            .ok_or_else(|| format!("{} include trace is not an array", expectation.scope))?;
        let include_evaluation_count = u64::try_from(trace_values.len())
            .map_err(|_| format!("{} include trace count overflow", expectation.scope))?;
        let maximum_depth = eval_string(&context, b"String(__includeMaximumDepth)")?
            .parse::<u64>()
            .map_err(|error| {
                format!("cannot parse {} include depth: {error}", expectation.scope)
            })?;
        if include_evaluation_count != expectation.transitive_include_evaluation_count
            || maximum_depth != expectation.maximum_active_include_depth
        {
            return Err(format!(
                "{} include trace mismatch: evaluations={include_evaluation_count}/{} \
                 depth={maximum_depth}/{}",
                expectation.scope,
                expectation.transitive_include_evaluation_count,
                expectation.maximum_active_include_depth
            ));
        }
        let trace_bytes = serde_json::to_vec(&trace).map_err(|error| {
            format!(
                "cannot serialize {} include trace: {error}",
                expectation.scope
            )
        })?;
        let measurement = probe.finish(runtime, context, initialized)?;
        let tracking = &measurement["memory"]["tracking_allocator"];
        let high_water_bytes = tracking["high_water_bytes"]
            .as_u64()
            .ok_or_else(|| format!("{} high-water is missing", expectation.scope))?;
        let live_bytes_before_drop = tracking["live_bytes_before_drop"]
            .as_u64()
            .ok_or_else(|| format!("{} live-before-drop is missing", expectation.scope))?;
        let interrupt_calls = measurement["interrupt"]["handler_call_total"]
            .as_u64()
            .ok_or_else(|| format!("{} interrupt count is missing", expectation.scope))?;
        heap_values.push(high_water_bytes);
        total_program_files = total_program_files
            .checked_add(expectation.program_file_count)
            .ok_or_else(|| "scope program file total overflow".to_owned())?;
        total_include_evaluations = total_include_evaluations
            .checked_add(include_evaluation_count)
            .ok_or_else(|| "scope include evaluation total overflow".to_owned())?;
        total_interrupt_calls = total_interrupt_calls
            .checked_add(interrupt_calls)
            .ok_or_else(|| "scope interrupt total overflow".to_owned())?;
        total_compatibility_overlays = total_compatibility_overlays
            .checked_add(scope_overlay_count)
            .ok_or_else(|| "scope compatibility overlay total overflow".to_owned())?;
        scope_results.push(json!({
            "scope": expectation.scope,
            "selected_init": expectation.selected_init,
            "program_file_count": expectation.program_file_count,
            "ordinary_rule_evaluation_count": scope_rule_files.len(),
            "compatibility_overlay_count": scope_overlay_count,
            "include_evaluation_count": include_evaluation_count,
            "maximum_active_include_depth": maximum_depth,
            "include_trace_sha256": sha256_hex(&trace_bytes),
            "high_water_bytes": high_water_bytes,
            "live_bytes_before_drop": live_bytes_before_drop,
            "interrupt_calls": interrupt_calls,
        }));
    }

    heap_values.sort_unstable();
    let maximum_scope = scope_results
        .iter()
        .max_by(|left, right| {
            left["high_water_bytes"]
                .as_u64()
                .cmp(&right["high_water_bytes"].as_u64())
                .then_with(|| right["scope"].as_str().cmp(&left["scope"].as_str()))
        })
        .ok_or_else(|| "scope heap maximum is missing".to_owned())?;
    let scope_results_bytes = serde_json::to_vec(&scope_results)
        .map_err(|error| format!("cannot serialize scope init results: {error}"))?;
    let stable_projection = json!({
        "schema_version": 1,
        "upstream_commit": UPSTREAM_COMMIT,
        "rules_commit": RULES_COMMIT,
        "include_graph_sizing_sha256": INCLUDE_GRAPH_SIZING_SHA256,
        "scope_count": expectations.len(),
        "program_file_count": total_program_files,
        "global_init": "db/_init",
        "type_init_count": expectations.len(),
        "ordinary_rule_evaluation_count": total_program_files - expectations.len() as u64,
        "compatibility_overlay_count": total_compatibility_overlays,
        "layer_order": "db normalized path, then db_extra normalized path",
        "layer_order_is_upstream_equivalent": false,
        "include_evaluation_count": total_include_evaluations,
        "maximum_active_include_depth": 2,
        "scope_results": {
            "count": scope_results.len(),
            "sha256": sha256_hex(&scope_results_bytes),
        },
        "heap_distribution_bytes": {
            "minimum": heap_values[0],
            "p50_nearest_rank": nearest_rank_percentile(&heap_values, 50)?,
            "p95_nearest_rank": nearest_rank_percentile(&heap_values, 95)?,
            "maximum": maximum_scope["high_water_bytes"],
            "maximum_scope": maximum_scope["scope"],
        },
        "interrupt_handler_call_total": total_interrupt_calls,
        "tracking_allocator": {
            "backend": "rquickjs RustAllocator wrapped by TrackingLimitAllocator",
            "limit_bytes_per_scope_runtime": TRACKED_RULE_RUNTIME_LIMIT_BYTES,
            "set_memory_limit_used": false,
            "accounting":
                "RustAllocator allocation Layout bytes: aligned payload plus internal header",
            "denied_allocation_count": 0,
            "all_scope_runtimes_released_to_zero": true,
        },
    });
    let stable_projection_bytes = serde_json::to_vec(&stable_projection)
        .map_err(|error| format!("cannot serialize scope init projection: {error}"))?;
    let report = json!({
        "schema_version": 1,
        "operation":
            "one tracked runtime per fixed file-type scope: global init, type init, normalized-path lexical rule eval, recursive includes",
        "stable_projection_sha256": sha256_hex(&stable_projection_bytes),
        "stable_projection": stable_projection,
        "scope_results": scope_results,
        "elapsed_ms": started.elapsed().as_millis(),
        "passed": true,
        "scope":
            "all 30 fixed scope top-level/include lifecycles under an explicit diagnostic rule \
             order; detect functions are not called, the order is not claimed as upstream \
             equivalent, and this is not default-allocator or cross-platform evidence",
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot serialize scope init report: {error}"))?
    );
    Ok(true)
}

fn run_fixture(rule_root: &Path) -> Result<bool, String> {
    let started = Instant::now();
    let runtime = new_runtime()?;
    let context = new_context(&runtime)?;
    context.with(|ctx| {
        let host_add = Function::new(ctx.clone(), |left: i32, right: i32| {
            left.saturating_add(right)
        })
        .map_err(|error| error.to_string())?;
        ctx.globals()
            .set("hostAdd", host_add)
            .map_err(|error| error.to_string())
    })?;
    let host_result = eval_string(&context, br#"String(hostAdd(20, 22))"#)?;

    let helper_path = rule_root.join("_runtime_helpers");
    let helper_bytes = fs::read(&helper_path)
        .map_err(|error| format!("cannot read {}: {error}", helper_path.display()))?;
    eval_unit(&context, &helper_bytes)?;
    let helper_result = eval_string(
        &context,
        br#""a".append("b").appendS("c", "/") + "|" + (7).padStart(3, "0")"#,
    )?;

    let audio_runtime = new_runtime()?;
    let audio_context = new_context(&audio_runtime)?;
    install_host_shim(&audio_context)?;
    let audio_path = rule_root.join("Binary").join("audio.1.sg");
    let audio_bytes = fs::read(&audio_path)
        .map_err(|error| format!("cannot read {}: {error}", audio_path.display()))?;
    let audio_eval = eval_unit(&audio_context, &audio_bytes);
    let audio_result = if audio_eval.is_ok() {
        eval_string(
            &audio_context,
            br#"metaType + "|" + metaName + "|" + included.join(",") + "|" + typeof detect"#,
        )?
    } else {
        String::new()
    };

    let redeclaration_runtime = new_runtime()?;
    let redeclaration_context = new_context(&redeclaration_runtime)?;
    let invalid_redeclaration = eval_unit(
        &redeclaration_context,
        b"function detect() { var value, other; const first = 1, value = 2; }",
    );

    let shared_runtime = new_runtime()?;
    let shared_context = new_context(&shared_runtime)?;
    eval_unit(&shared_context, b"const sharedName = 1;")?;
    let shared_lexical_redeclaration = eval_unit(&shared_context, b"const sharedName = 2;");

    let nintendo_runtime = new_runtime()?;
    let nintendo_context = new_context(&nintendo_runtime)?;
    install_host_shim(&nintendo_context)?;
    let nintendo_path = rule_root
        .join("Binary")
        .join("format_bin.Nintendo-certified-file.1.sg");
    let nintendo_bytes = fs::read(&nintendo_path)
        .map_err(|error| format!("cannot read {}: {error}", nintendo_path.display()))?;
    let nintendo_eval = eval_unit(&nintendo_context, &nintendo_bytes);
    let (nintendo_compat_bytes, nintendo_overlay_applied) =
        apply_compatibility_overlay(&nintendo_path, &nintendo_bytes)?;
    let nintendo_compat_runtime = new_runtime()?;
    let nintendo_compat_context = new_context(&nintendo_compat_runtime)?;
    install_host_shim(&nintendo_compat_context)?;
    let nintendo_compat_eval = eval_unit(&nintendo_compat_context, &nintendo_compat_bytes);

    let interrupt_count = Arc::new(AtomicUsize::new(0));
    let interrupt_count_for_handler = Arc::clone(&interrupt_count);
    let limited_runtime = new_runtime()?;
    limited_runtime.set_interrupt_handler(Some(Box::new(move || {
        interrupt_count_for_handler.fetch_add(1, Ordering::Relaxed) >= 16
    })));
    let limited_context = new_context(&limited_runtime)?;
    let interrupt_error = eval_unit(&limited_context, b"for (;;) {}").err();

    const EXTERNAL_CANCEL_HARD_STOP_CALLS: usize = 1_000_000;
    let cancel_requested = Arc::new(AtomicBool::new(false));
    let cancel_handler_seen = Arc::new(AtomicBool::new(false));
    let cancel_handler_calls = Arc::new(AtomicUsize::new(0));
    let cancel_requested_for_handler = Arc::clone(&cancel_requested);
    let cancel_handler_seen_for_handler = Arc::clone(&cancel_handler_seen);
    let cancel_handler_calls_for_handler = Arc::clone(&cancel_handler_calls);
    let cancel_runtime = new_runtime()?;
    cancel_runtime.set_interrupt_handler(Some(Box::new(move || {
        let calls = cancel_handler_calls_for_handler.fetch_add(1, Ordering::Relaxed) + 1;
        cancel_handler_seen_for_handler.store(true, Ordering::Release);
        cancel_requested_for_handler.load(Ordering::Acquire)
            || calls >= EXTERNAL_CANCEL_HARD_STOP_CALLS
    })));
    let cancel_context = new_context(&cancel_runtime)?;
    let cancel_requested_for_worker = Arc::clone(&cancel_requested);
    let cancel_handler_seen_for_worker = Arc::clone(&cancel_handler_seen);
    let cancel_worker = thread::spawn(move || {
        while !cancel_handler_seen_for_worker.load(Ordering::Acquire) {
            thread::yield_now();
        }
        cancel_requested_for_worker.store(true, Ordering::Release);
    });
    let external_cancel_error = eval_unit(&cancel_context, b"for (;;) {}").err();
    cancel_worker
        .join()
        .map_err(|_| "external cancellation worker panicked".to_owned())?;
    let external_cancel_requested = cancel_requested.load(Ordering::Acquire);
    let external_cancel_handler_calls = cancel_handler_calls.load(Ordering::Relaxed);
    let external_cancel_hard_stop_reached =
        external_cancel_handler_calls >= EXTERNAL_CANCEL_HARD_STOP_CALLS;
    cancel_requested.store(false, Ordering::Release);
    cancel_handler_calls.store(0, Ordering::Relaxed);
    let external_cancel_recovery = eval_string(&cancel_context, b"String(40 + 2)");
    let external_cancel_recovered = external_cancel_recovery.as_deref() == Ok("42");

    const NATIVE_CANCEL_HARD_STOP_ITERATIONS: i32 = 1_000_000;
    let native_cancel_requested = Arc::new(AtomicBool::new(false));
    let native_host_entered = Arc::new(AtomicBool::new(false));
    let native_host_finished = Arc::new(AtomicBool::new(false));
    let native_cancel_requested_for_host = Arc::clone(&native_cancel_requested);
    let native_host_entered_for_host = Arc::clone(&native_host_entered);
    let native_cancel_runtime = new_runtime()?;
    let native_cancel_context = new_context(&native_cancel_runtime)?;
    native_cancel_context.with(|ctx| {
        let cooperative_host_loop = Function::new(ctx.clone(), move || {
            native_host_entered_for_host.store(true, Ordering::Release);
            let mut iterations = 0;
            loop {
                iterations += 1;
                if native_cancel_requested_for_host.load(Ordering::Acquire)
                    || iterations >= NATIVE_CANCEL_HARD_STOP_ITERATIONS
                {
                    return iterations;
                }
                thread::yield_now();
            }
        })
        .map_err(|error| error.to_string())?;
        ctx.globals()
            .set("cooperativeHostLoop", cooperative_host_loop)
            .map_err(|error| error.to_string())
    })?;
    let native_cancel_requested_for_worker = Arc::clone(&native_cancel_requested);
    let native_host_entered_for_worker = Arc::clone(&native_host_entered);
    let native_host_finished_for_worker = Arc::clone(&native_host_finished);
    let native_cancel_worker = thread::spawn(move || {
        while !native_host_entered_for_worker.load(Ordering::Acquire)
            && !native_host_finished_for_worker.load(Ordering::Acquire)
        {
            thread::yield_now();
        }
        if native_host_entered_for_worker.load(Ordering::Acquire) {
            native_cancel_requested_for_worker.store(true, Ordering::Release);
        }
    });
    let native_cancel_result =
        eval_string(&native_cancel_context, b"String(cooperativeHostLoop())");
    native_host_finished.store(true, Ordering::Release);
    native_cancel_worker
        .join()
        .map_err(|_| "native cancellation worker panicked".to_owned())?;
    let native_cancel_requested_observed = native_cancel_requested.load(Ordering::Acquire);
    let native_cancel_iterations = native_cancel_result
        .as_deref()
        .ok()
        .and_then(|value| value.parse::<i32>().ok());
    let native_cancel_hard_stop_reached =
        native_cancel_iterations == Some(NATIVE_CANCEL_HARD_STOP_ITERATIONS);

    const WALL_CLOCK_DEADLINE_MS: u64 = 25;
    const WALL_CLOCK_DEADLINE_HARD_STOP_CALLS: usize = 1_000_000;
    let wall_clock_deadline_started = Arc::new(Mutex::new(None::<Instant>));
    let wall_clock_deadline_calls = Arc::new(AtomicUsize::new(0));
    let wall_clock_deadline_started_for_handler = Arc::clone(&wall_clock_deadline_started);
    let wall_clock_deadline_calls_for_handler = Arc::clone(&wall_clock_deadline_calls);
    let wall_clock_deadline_runtime = new_runtime()?;
    wall_clock_deadline_runtime.set_interrupt_handler(Some(Box::new(move || {
        let calls = wall_clock_deadline_calls_for_handler.fetch_add(1, Ordering::Relaxed) + 1;
        let now = Instant::now();
        let expired = match wall_clock_deadline_started_for_handler.lock() {
            Ok(mut started) => {
                let started = *started.get_or_insert(now);
                now.duration_since(started) >= Duration::from_millis(WALL_CLOCK_DEADLINE_MS)
            }
            Err(_) => true,
        };
        expired || calls >= WALL_CLOCK_DEADLINE_HARD_STOP_CALLS
    })));
    let wall_clock_deadline_context = new_context(&wall_clock_deadline_runtime)?;
    let wall_clock_deadline_error = eval_unit(&wall_clock_deadline_context, b"for (;;) {}").err();
    let wall_clock_deadline_calls_observed = wall_clock_deadline_calls.load(Ordering::Relaxed);
    let wall_clock_deadline_hard_stop_reached =
        wall_clock_deadline_calls_observed >= WALL_CLOCK_DEADLINE_HARD_STOP_CALLS;
    let wall_clock_deadline_expired = wall_clock_deadline_started
        .lock()
        .map_err(|_| "wall-clock deadline state mutex poisoned".to_owned())?
        .is_some_and(|started| started.elapsed() >= Duration::from_millis(WALL_CLOCK_DEADLINE_MS));
    wall_clock_deadline_runtime.set_interrupt_handler(None);
    let wall_clock_deadline_recovery = eval_string(&wall_clock_deadline_context, b"String(21 * 2)");

    const NATIVE_DEADLINE_HARD_STOP_ITERATIONS: i32 = 10_000_000;
    let native_deadline = Arc::new(Mutex::new(None::<Instant>));
    let native_deadline_for_host = Arc::clone(&native_deadline);
    let native_deadline_runtime = new_runtime()?;
    let native_deadline_context = new_context(&native_deadline_runtime)?;
    native_deadline_context.with(|ctx| {
        let deadline_host_loop = Function::new(ctx.clone(), move || {
            let deadline = native_deadline_for_host
                .lock()
                .ok()
                .and_then(|deadline| *deadline);
            let Some(deadline) = deadline else {
                return -1;
            };
            let mut iterations = 0;
            loop {
                iterations += 1;
                if Instant::now() >= deadline || iterations >= NATIVE_DEADLINE_HARD_STOP_ITERATIONS
                {
                    return iterations;
                }
                thread::yield_now();
            }
        })
        .map_err(|error| error.to_string())?;
        ctx.globals()
            .set("deadlineHostLoop", deadline_host_loop)
            .map_err(|error| error.to_string())
    })?;
    let native_deadline_at = Instant::now() + Duration::from_millis(WALL_CLOCK_DEADLINE_MS);
    *native_deadline
        .lock()
        .map_err(|_| "native deadline state mutex poisoned".to_owned())? = Some(native_deadline_at);
    let native_deadline_result =
        eval_string(&native_deadline_context, b"String(deadlineHostLoop())");
    let native_deadline_iterations = native_deadline_result
        .as_deref()
        .ok()
        .and_then(|value| value.parse::<i32>().ok());
    let native_deadline_expired = Instant::now() >= native_deadline_at;
    let native_deadline_hard_stop_reached =
        native_deadline_iterations == Some(NATIVE_DEADLINE_HARD_STOP_ITERATIONS);
    let native_deadline_recovery = eval_string(&native_deadline_context, b"String(21 * 2)");

    let numeric_runtime = new_runtime()?;
    let numeric_context = new_context(&numeric_runtime)?;
    install_nintendo_host(
        &numeric_context,
        Arc::new(vec![b'A', b'B', b'C', 0, 0x12, 0x34, 0x56]),
        Arc::new(Mutex::new(Vec::new())),
    )?;
    let numeric_result_text = eval_string(
        &numeric_context,
        br#"JSON.stringify([
            X.U24(4),
            X.U24(4, true),
            X.read_uint24(4, true),
            Util.shru64(4294967295, 0),
            Util.shru64(4294967295, 4),
            Util.shru64(4294967295, 32)
        ])"#,
    )?;
    let numeric_result: Value = serde_json::from_str(&numeric_result_text)
        .map_err(|error| format!("cannot parse numeric HostApi fixture: {error}"))?;
    let numeric_expected = json!([
        0x563412_u64,
        0x123456_u64,
        0x123456_u64,
        0xFFFFFFFF_u64,
        0x0FFFFFFF_u64,
        0_u64,
    ]);

    let memory_runtime = new_runtime()?;
    memory_runtime.set_memory_limit(4 * 1024 * 1024);
    let memory_context = new_context(&memory_runtime)?;
    let memory_limit_error = eval_unit(
        &memory_context,
        b"globalThis.large = new ArrayBuffer(16 * 1024 * 1024);",
    )
    .err();
    let memory_limit_recovery = eval_string(&memory_context, b"String(6 * 7)");

    const TRACKING_ALLOCATOR_LIMIT_BYTES: usize = 4 * 1024 * 1024;
    let (tracking_runtime, tracking_stats) = new_tracking_runtime(TRACKING_ALLOCATOR_LIMIT_BYTES)?;
    let tracking_context = new_context(&tracking_runtime)?;
    let tracking_limit_error = eval_unit(
        &tracking_context,
        b"globalThis.large = new ArrayBuffer(16 * 1024 * 1024);",
    )
    .err();
    let tracking_limit_recovery = eval_string(&tracking_context, b"String(6 * 7)");
    let tracking_live_bytes_before_drop = tracking_stats.live_bytes();
    let tracking_high_water_bytes = tracking_stats.high_water_bytes();
    let tracking_denied_allocation_count = tracking_stats.denied_allocation_count();
    drop(tracking_context);
    drop(tracking_runtime);
    let tracking_live_bytes_after_drop = tracking_stats.live_bytes();

    const STACK_LIMIT_BYTES: usize = 128 * 1024;
    let stack_runtime = new_runtime()?;
    stack_runtime.set_max_stack_size(STACK_LIMIT_BYTES);
    let stack_context = new_context(&stack_runtime)?;
    let stack_limit_error = eval_unit(
        &stack_context,
        b"function recurse() { return 1 + recurse(); } recurse();",
    )
    .err();
    let stack_limit_recovery = eval_string(&stack_context, b"String(6 * 7)");

    const PANIC_SENTINEL: &str = "die-rquickjs-native-panic-sentinel";
    let panic_runtime = new_runtime()?;
    let panic_context = new_context(&panic_runtime)?;
    panic_context.with(|ctx| {
        let panic_host = Function::new(ctx.clone(), move || -> i32 {
            panic!("{PANIC_SENTINEL}");
        })
        .map_err(|error| error.to_string())?;
        ctx.globals()
            .set("panicHost", panic_host)
            .map_err(|error| error.to_string())
    })?;
    let previous_panic_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let native_panic_result = panic::catch_unwind(AssertUnwindSafe(|| {
        eval_unit(&panic_context, b"panicHost();")
    }));
    panic::set_hook(previous_panic_hook);
    let native_panic_payload = native_panic_result.as_ref().err().and_then(|payload| {
        payload
            .downcast_ref::<&str>()
            .map(|value| (*value).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
    });
    let native_panic_recovery = eval_string(&panic_context, b"String(6 * 7)");

    let passed = host_result == "42"
        && helper_result == "a, b/c|007"
        && audio_eval.is_ok()
        && audio_result == "audio||chunkparsers,soundchips,bytecodeparsers|function"
        && invalid_redeclaration.is_err()
        && shared_lexical_redeclaration.is_err()
        && nintendo_eval.is_err()
        && nintendo_overlay_applied
        && nintendo_compat_eval.is_ok()
        && interrupt_error.is_some()
        && external_cancel_error.is_some()
        && external_cancel_requested
        && !external_cancel_hard_stop_reached
        && external_cancel_recovered
        && native_cancel_requested_observed
        && native_cancel_iterations.is_some_and(|iterations| {
            (1..NATIVE_CANCEL_HARD_STOP_ITERATIONS).contains(&iterations)
        })
        && !native_cancel_hard_stop_reached
        && wall_clock_deadline_error.is_some()
        && wall_clock_deadline_expired
        && !wall_clock_deadline_hard_stop_reached
        && wall_clock_deadline_recovery.as_deref() == Ok("42")
        && native_deadline_iterations.is_some_and(|iterations| {
            (1..NATIVE_DEADLINE_HARD_STOP_ITERATIONS).contains(&iterations)
        })
        && native_deadline_expired
        && !native_deadline_hard_stop_reached
        && native_deadline_recovery.as_deref() == Ok("42")
        && numeric_result == numeric_expected
        && memory_limit_error.is_some()
        && memory_limit_recovery.as_deref() == Ok("42")
        && tracking_limit_error.is_some()
        && tracking_limit_recovery.as_deref() == Ok("42")
        && tracking_denied_allocation_count > 0
        && tracking_live_bytes_before_drop <= TRACKING_ALLOCATOR_LIMIT_BYTES
        && tracking_high_water_bytes <= TRACKING_ALLOCATOR_LIMIT_BYTES
        && tracking_live_bytes_after_drop == 0
        && stack_limit_error.is_some()
        && stack_limit_recovery.as_deref() == Ok("42")
        && native_panic_payload.as_deref() == Some(PANIC_SENTINEL)
        && native_panic_recovery.as_deref() == Ok("42");
    let compatible = nintendo_eval.is_ok();
    let report = json!({
        "schema_version": 1,
        "runtime": {
            "crate": "rquickjs",
            "version": "0.12.1",
            "default_features": false,
            "features": ["std"],
            "engine": "QuickJS-NG",
        },
        "host_function_result": host_result,
        "runtime_helpers_result": helper_result,
        "audio_rule": {
            "path": normalized_path(&audio_path),
            "bytes": audio_bytes.len(),
            "eval_accepted": audio_eval.is_ok(),
            "eval_error": audio_eval.err(),
            "result": audio_result,
        },
        "invalid_var_const_redeclaration": {
            "eval_accepted": invalid_redeclaration.is_ok(),
            "eval_error": invalid_redeclaration.err(),
        },
        "shared_const_redeclaration": {
            "second_eval_accepted": shared_lexical_redeclaration.is_ok(),
            "second_eval_error": shared_lexical_redeclaration.err(),
        },
        "nintendo_rule": {
            "path": normalized_path(&nintendo_path),
            "bytes": fs::metadata(&nintendo_path)
                .map_err(|error| error.to_string())?
                .len(),
            "eval_accepted": nintendo_eval.is_ok(),
            "eval_error": nintendo_eval.err(),
            "source_sha256": NINTENDO_RULE_SHA256,
            "compatibility_overlay": {
                "id": "nintendo-unused-var-tp-v1",
                "applied": nintendo_overlay_applied,
                "evaluated_length_unchanged": nintendo_compat_bytes.len() == nintendo_bytes.len(),
                "eval_accepted": nintendo_compat_eval.is_ok(),
                "eval_error": nintendo_compat_eval.err(),
            },
        },
        "interrupt": {
            "handler_calls": interrupt_count.load(Ordering::Relaxed),
            "error": interrupt_error,
        },
        "external_cancel": {
            "requested": external_cancel_requested,
            "handler_calls": external_cancel_handler_calls,
            "hard_stop_handler_call_limit": EXTERNAL_CANCEL_HARD_STOP_CALLS,
            "hard_stop_reached": external_cancel_hard_stop_reached,
            "error": external_cancel_error,
            "same_context_recovery": {
                "accepted": external_cancel_recovery.is_ok(),
                "result": external_cancel_recovery.as_deref().ok(),
                "error": external_cancel_recovery.as_ref().err(),
            },
        },
        "native_host_cooperative_cancel": {
            "requested": native_cancel_requested_observed,
            "result": native_cancel_result.as_deref().ok(),
            "error": native_cancel_result.as_ref().err(),
            "iterations": native_cancel_iterations,
            "hard_stop_iteration_limit": NATIVE_CANCEL_HARD_STOP_ITERATIONS,
            "hard_stop_reached": native_cancel_hard_stop_reached,
        },
        "wall_clock_deadline": {
            "milliseconds": WALL_CLOCK_DEADLINE_MS,
            "handler_calls": wall_clock_deadline_calls_observed,
            "expired": wall_clock_deadline_expired,
            "hard_stop_handler_call_limit": WALL_CLOCK_DEADLINE_HARD_STOP_CALLS,
            "hard_stop_reached": wall_clock_deadline_hard_stop_reached,
            "error": wall_clock_deadline_error,
            "same_context_recovery": {
                "result": wall_clock_deadline_recovery.as_deref().ok(),
                "error": wall_clock_deadline_recovery.as_ref().err(),
            },
        },
        "native_host_cooperative_deadline": {
            "milliseconds": WALL_CLOCK_DEADLINE_MS,
            "expired": native_deadline_expired,
            "result": native_deadline_result.as_deref().ok(),
            "error": native_deadline_result.as_ref().err(),
            "iterations": native_deadline_iterations,
            "hard_stop_iteration_limit": NATIVE_DEADLINE_HARD_STOP_ITERATIONS,
            "hard_stop_reached": native_deadline_hard_stop_reached,
            "same_context_recovery": {
                "result": native_deadline_recovery.as_deref().ok(),
                "error": native_deadline_recovery.as_ref().err(),
            },
        },
        "numeric_host_api": {
            "methods": ["X.U24", "X.read_uint24", "Util.shru64"],
            "result": numeric_result,
            "expected": numeric_expected,
            "matches_qt5_qt6_oracle": numeric_result == numeric_expected,
        },
        "memory_limit": {
            "bytes": 4 * 1024 * 1024,
            "error": memory_limit_error,
            "same_context_recovery": {
                "result": memory_limit_recovery.as_deref().ok(),
                "error": memory_limit_recovery.as_ref().err(),
            },
        },
        "tracking_allocator": {
            "limit_bytes": TRACKING_ALLOCATOR_LIMIT_BYTES,
            "accounting": "RustAllocator allocation Layout bytes: aligned payload plus internal header",
            "error": tracking_limit_error,
            "denied_allocation_count": tracking_denied_allocation_count,
            "live_bytes_before_drop": tracking_live_bytes_before_drop,
            "high_water_bytes": tracking_high_water_bytes,
            "live_bytes_after_drop": tracking_live_bytes_after_drop,
            "same_context_recovery": {
                "result": tracking_limit_recovery.as_deref().ok(),
                "error": tracking_limit_recovery.as_ref().err(),
            },
            "set_memory_limit_used": false,
        },
        "stack_limit": {
            "bytes": STACK_LIMIT_BYTES,
            "error": stack_limit_error,
            "same_context_recovery": {
                "result": stack_limit_recovery.as_deref().ok(),
                "error": stack_limit_recovery.as_ref().err(),
            },
        },
        "native_host_panic": {
            "caught_at_rust_eval_boundary": native_panic_result.is_err(),
            "payload_matches_sentinel": native_panic_payload.as_deref() == Some(PANIC_SENTINEL),
            "eval_returned_without_panic": native_panic_result.is_ok(),
            "same_context_recovery": {
                "result": native_panic_recovery.as_deref().ok(),
                "error": native_panic_recovery.as_ref().err(),
            },
        },
        "elapsed_ms": started.elapsed().as_millis(),
        "candidate_compatible_with_fixed_rules": compatible,
        "passed": passed,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot serialize report: {error}"))?
    );
    Ok(passed)
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: die-rquickjs-rule-runtime-spike \
         <eval-isolated|eval-isolated-compat|eval-shared> <rule-root>...\n       \
         die-rquickjs-rule-runtime-spike \
         eval-isolated-compat-tracked-heap <rule-root>...\n       \
         die-rquickjs-rule-runtime-spike \
         measure-rule-corpus-isolated-heap <rule-root>...\n       \
         die-rquickjs-rule-runtime-spike \
         verify-scope-lifecycles-tracked-heap \
         <main-rule-root> <extra-rule-root> <include-graph-sizing-json>\n       \
         die-rquickjs-rule-runtime-spike fixture <main-rule-root>\n       \
         die-rquickjs-rule-runtime-spike \
         <eval-binary-lifecycle|eval-binary-lifecycle-raw|eval-binary-lifecycle-lexical> \
         <main-rule-root> <binary-order-json>\n       \
         die-rquickjs-rule-runtime-spike \
         <eval-scope-fixture|eval-scope-fixture-lexical> \
         <fixture-root> <fixture-manifest-json> <qt5-baseline-json>\n       \
         die-rquickjs-rule-runtime-spike detect-nintendo \
         <main-rule-root> <corpus-dir> <baseline-json>\n       \
         die-rquickjs-rule-runtime-spike detect-nintendo-lifecycle \
         <main-rule-root> <corpus-dir> <baseline-json> <binary-order-json>\n       \
         die-rquickjs-rule-runtime-spike trace-binary-detects \
         <main-rule-root> <input-file> <binary-order-json>\n       \
         die-rquickjs-rule-runtime-spike verify-binary-corpus \
         <main-rule-root> <corpus-dir> <corpus-manifest-json> \
         <baseline-json> <binary-order-json>\n       \
         die-rquickjs-rule-runtime-spike verify-binary-corpus-tracked-heap \
         <main-rule-root> <corpus-dir> <corpus-manifest-json> \
         <baseline-json> <binary-order-json>\n       \
         die-rquickjs-rule-runtime-spike \
         <verify-pe-rule|verify-pe-rule-tracked-heap> \
         <main-rule-root> <pe-fixture-json> <qt5-baseline-json>\n       \
         die-rquickjs-rule-runtime-spike \
         <verify-elf-rule|verify-elf-rule-tracked-heap> \
         <main-rule-root> <elf-fixture-json> <qt5-baseline-json>\n       \
         die-rquickjs-rule-runtime-spike \
         <verify-macho-rule|verify-macho-rule-tracked-heap> \
         <main-rule-root> <macho-fixture-json> <qt5-baseline-json>\n       \
         die-rquickjs-rule-runtime-spike \
         <verify-dex-rule|verify-dex-rule-tracked-heap> \
         <main-rule-root> <dex-fixture-json> <qt5-baseline-json>\n       \
         die-rquickjs-rule-runtime-spike \
         <verify-apk-rule|verify-apk-rule-tracked-heap> \
         <main-rule-root> <apk-fixture-json> <qt5-baseline-json>\n       \
         die-rquickjs-rule-runtime-spike \
         <verify-archive-rule|verify-archive-rule-tracked-heap> \
         <main-rule-root> <archive-fixture-json> <qt5-baseline-json>\n       \
         die-rquickjs-rule-runtime-spike \
         <verify-pdf-rule|verify-pdf-rule-tracked-heap> \
         <main-rule-root> <pdf-fixture-json> <qt5-baseline-json>"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        return usage();
    };
    let roots = arguments.map(PathBuf::from).collect::<Vec<_>>();
    if roots.is_empty() {
        return usage();
    }

    let result = if command == "eval-isolated" {
        evaluate_corpus(&roots, false, false, None)
    } else if command == "eval-isolated-compat" {
        evaluate_corpus(&roots, false, true, None)
    } else if command == "eval-isolated-compat-tracked-heap" {
        evaluate_corpus(&roots, false, true, Some(TRACKED_RULE_RUNTIME_LIMIT_BYTES))
    } else if command == "measure-rule-corpus-isolated-heap" {
        measure_rule_corpus_isolated_heap(&roots)
    } else if command == "verify-scope-lifecycles-tracked-heap" && roots.len() == 3 {
        verify_scope_lifecycles_tracked_heap(&roots[0], &roots[1], &roots[2])
    } else if command == "eval-shared" {
        evaluate_corpus(&roots, true, false, None)
    } else if command == "fixture" && roots.len() == 1 {
        run_fixture(&roots[0])
    } else if command == "eval-binary-lifecycle" && roots.len() == 2 {
        run_binary_lifecycle(&roots[0], &roots[1], true, false)
    } else if command == "eval-binary-lifecycle-raw" && roots.len() == 2 {
        run_binary_lifecycle(&roots[0], &roots[1], false, false)
    } else if command == "eval-binary-lifecycle-lexical" && roots.len() == 2 {
        run_binary_lifecycle(&roots[0], &roots[1], false, true)
    } else if command == "eval-scope-fixture" && roots.len() == 3 {
        run_scope_fixture(&roots[0], &roots[1], &roots[2], false)
    } else if command == "eval-scope-fixture-lexical" && roots.len() == 3 {
        run_scope_fixture(&roots[0], &roots[1], &roots[2], true)
    } else if command == "detect-nintendo" && roots.len() == 3 {
        run_nintendo_corpus(&roots[0], &roots[1], &roots[2])
    } else if command == "detect-nintendo-lifecycle" && roots.len() == 4 {
        run_nintendo_lifecycle_corpus(&roots[0], &roots[1], &roots[2], &roots[3])
    } else if command == "trace-binary-detects" && roots.len() == 3 {
        trace_binary_detects(&roots[0], &roots[1], &roots[2])
    } else if command == "verify-binary-corpus" && roots.len() == 5 {
        verify_binary_corpus(&roots[0], &roots[1], &roots[2], &roots[3], &roots[4])
    } else if command == "verify-binary-corpus-tracked-heap" && roots.len() == 5 {
        verify_binary_corpus_with_tracking(
            &roots[0],
            &roots[1],
            &roots[2],
            &roots[3],
            &roots[4],
            Some(TRACKED_RULE_RUNTIME_LIMIT_BYTES),
        )
    } else if command == "verify-pe-rule" && roots.len() == 3 {
        verify_pe_rule(&roots[0], &roots[1], &roots[2], None)
    } else if command == "verify-pe-rule-tracked-heap" && roots.len() == 3 {
        verify_pe_rule(
            &roots[0],
            &roots[1],
            &roots[2],
            Some(TRACKED_RULE_RUNTIME_LIMIT_BYTES),
        )
    } else if command == "verify-elf-rule" && roots.len() == 3 {
        verify_elf_rule(&roots[0], &roots[1], &roots[2], None)
    } else if command == "verify-elf-rule-tracked-heap" && roots.len() == 3 {
        verify_elf_rule(
            &roots[0],
            &roots[1],
            &roots[2],
            Some(TRACKED_RULE_RUNTIME_LIMIT_BYTES),
        )
    } else if command == "verify-macho-rule" && roots.len() == 3 {
        verify_macho_rule(&roots[0], &roots[1], &roots[2], None)
    } else if command == "verify-macho-rule-tracked-heap" && roots.len() == 3 {
        verify_macho_rule(
            &roots[0],
            &roots[1],
            &roots[2],
            Some(TRACKED_RULE_RUNTIME_LIMIT_BYTES),
        )
    } else if command == "verify-dex-rule" && roots.len() == 3 {
        verify_dex_rule(&roots[0], &roots[1], &roots[2], None)
    } else if command == "verify-dex-rule-tracked-heap" && roots.len() == 3 {
        verify_dex_rule(
            &roots[0],
            &roots[1],
            &roots[2],
            Some(TRACKED_RULE_RUNTIME_LIMIT_BYTES),
        )
    } else if command == "verify-apk-rule" && roots.len() == 3 {
        verify_apk_rule(&roots[0], &roots[1], &roots[2], None)
    } else if command == "verify-apk-rule-tracked-heap" && roots.len() == 3 {
        verify_apk_rule(
            &roots[0],
            &roots[1],
            &roots[2],
            Some(TRACKED_RULE_RUNTIME_LIMIT_BYTES),
        )
    } else if command == "verify-archive-rule" && roots.len() == 3 {
        verify_archive_rule(&roots[0], &roots[1], &roots[2], None)
    } else if command == "verify-archive-rule-tracked-heap" && roots.len() == 3 {
        verify_archive_rule(
            &roots[0],
            &roots[1],
            &roots[2],
            Some(TRACKED_RULE_RUNTIME_LIMIT_BYTES),
        )
    } else if command == "verify-pdf-rule" && roots.len() == 3 {
        verify_pdf_rule(&roots[0], &roots[1], &roots[2], None)
    } else if command == "verify-pdf-rule-tracked-heap" && roots.len() == 3 {
        verify_pdf_rule(
            &roots[0],
            &roots[1],
            &roots[2],
            Some(TRACKED_RULE_RUNTIME_LIMIT_BYTES),
        )
    } else {
        return usage();
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApkRuleContext, ArchiveRuleContext, BinaryHostContext, BinaryStringContext, DexRuleContext,
        ElfRuleContext, HostFilePart, MachoRuleContext, NINTENDO_COMPAT_DECLARATION,
        NINTENDO_RULE_BYTES, NINTENDO_VAR_DECLARATION, PdfRuleContext, PeRuleContext,
        TextUnicodeType, apply_compatibility_overlay, apply_exact_lifecycle_overlay,
        collect_rule_files, elf_matcher_map_projection, eval_rule_lexical, eval_string, eval_unit,
        install_diagnostic_host_fallbacks, install_host_shim, install_nintendo_host,
        install_nintendo_host_with_context, install_nintendo_host_with_context_and_strings,
        install_scope_include_probe, macho_matcher_map_projection, nearest_rank_percentile,
        new_context, new_rule_case_runtime_with_tracking, new_runtime, new_tracking_runtime,
        nonnegative_index, normalized_path, parse_detection_triples, parse_scope_detections,
        parse_scope_fixture_order, parse_scope_init_expectations, pe_physical_map_projection,
        qt5_matcher_map_projection, qt5_pe_physical_map_projection, read_ascii, read_byte_array,
        read_signed, read_unsigned, rule_logical_path, rule_logical_scope, runtime_memory_snapshot,
        sha256_hex, shift_right_unsigned, sorted_detection_projection, upstream_type_priority,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should follow Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "die-rquickjs-spike-{}-{nonce}",
            std::process::id()
        ))
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "hex fixture must have complete bytes");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("hex fixture must be ASCII");
                u8::from_str_radix(text, 16).expect("hex fixture must contain digits")
            })
            .collect()
    }

    #[test]
    fn nearest_rank_percentile_checks_boundaries_and_rounds_up() {
        let values = [10, 20, 30, 40];
        assert_eq!(nearest_rank_percentile(&values, 1).unwrap(), 10);
        assert_eq!(nearest_rank_percentile(&values, 50).unwrap(), 20);
        assert_eq!(nearest_rank_percentile(&values, 51).unwrap(), 30);
        assert_eq!(nearest_rank_percentile(&values, 100).unwrap(), 40);
        assert!(nearest_rank_percentile(&[], 50).is_err());
        assert!(nearest_rank_percentile(&values, 0).is_err());
        assert!(nearest_rank_percentile(&values, 101).is_err());
    }

    #[test]
    fn rule_logical_identity_is_root_relative_and_scope_stable() {
        let root = PathBuf::from("rules").join("db");
        let path = root.join("PE").join("compiler.sg");
        let logical = rule_logical_path(std::slice::from_ref(&root), &path).unwrap();
        assert_eq!(logical, "db/PE/compiler.sg");
        assert_eq!(rule_logical_scope(&logical), "db/PE");
        assert_eq!(rule_logical_scope("db/_init"), "db/_root");
        assert!(rule_logical_path(&[root], Path::new("outside/rule.sg")).is_err());
    }

    #[test]
    fn scope_init_manifest_is_pinned_and_complete() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/research/data/include-graph-sizing.json");
        let expectations =
            parse_scope_init_expectations(&path).expect("fixed include sizing should parse");
        assert_eq!(expectations.len(), 30);
        assert_eq!(
            expectations
                .iter()
                .map(|record| record.program_file_count)
                .sum::<u64>(),
            2205
        );
        assert_eq!(
            expectations
                .iter()
                .map(|record| record.transitive_include_evaluation_count)
                .sum::<u64>(),
            151
        );
        assert_eq!(
            expectations
                .iter()
                .filter(|record| record.maximum_active_include_depth == 2)
                .map(|record| record.scope.as_str())
                .collect::<Vec<_>>(),
            ["Binary", "MSDOS", "PE"]
        );
    }

    #[test]
    fn scope_include_probe_counts_nested_depth_and_duplicate_evaluations() {
        let root = temporary_directory();
        fs::create_dir_all(&root).expect("temporary include root should be created");
        fs::write(root.join("first"), "includeScript('second');")
            .expect("first helper should be written");
        fs::write(root.join("second"), "globalThis.includeValue = 42;")
            .expect("second helper should be written");

        let runtime = new_runtime().expect("runtime should be created");
        let context = new_context(&runtime).expect("context should be created");
        install_host_shim(&context).expect("host shim should be installed");
        install_scope_include_probe(&context, &root).expect("include probe should be installed");
        eval_unit(&context, b"includeScript('first'); includeScript('first');")
            .expect("nested duplicate includes should evaluate");
        assert_eq!(
            eval_string(
                &context,
                b"JSON.stringify([__includeTrace, __includeMaximumDepth, includeValue])",
            )
            .expect("include trace should serialize"),
            r#"[["first","second","first","second"],2,42]"#
        );

        drop(context);
        drop(runtime);
        fs::remove_dir_all(&root).expect("temporary include root should be removed");
    }

    #[test]
    fn isolated_rule_case_runtime_probe_records_three_bounded_checkpoints() {
        let (runtime, probe) =
            new_rule_case_runtime_with_tracking(None).expect("measured runtime should be created");
        let context = new_context(&runtime).expect("measured context should be created");
        eval_unit(&context, b"globalThis.fixtureValue = 41;")
            .expect("fixture initialization should succeed");
        let initialized =
            runtime_memory_snapshot(&runtime).expect("initialized memory should be readable");
        eval_unit(&context, b"fixtureValue += 1;").expect("fixture rule evaluation should succeed");
        let measurement = probe
            .finish(runtime, context, initialized)
            .expect("runtime measurement should finish");
        assert_eq!(
            measurement.pointer("/memory/checkpoint_count"),
            Some(&serde_json::json!(3))
        );
        assert_eq!(
            measurement.pointer("/memory/transient_high_water_measured"),
            Some(&serde_json::json!(false))
        );
        assert!(
            measurement
                .pointer("/memory/maximum_observed_malloc_size/bytes")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|bytes| bytes > 0)
        );
        assert!(
            measurement
                .pointer("/memory/maximum_observed_memory_used_size/bytes")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|bytes| bytes > 0)
        );
        assert!(
            measurement
                .pointer("/interrupt/handler_call_total")
                .and_then(serde_json::Value::as_u64)
                .is_some()
        );
    }

    #[test]
    fn tracked_rule_case_runtime_probe_records_high_water_and_releases_to_zero() {
        let (runtime, probe) = new_rule_case_runtime_with_tracking(Some(1024 * 1024))
            .expect("tracked runtime should be created");
        let context = new_context(&runtime).expect("tracked context should be created");
        eval_unit(&context, b"globalThis.fixtureValue = new Uint8Array(4096);")
            .expect("tracked fixture initialization should succeed");
        let initialized =
            runtime_memory_snapshot(&runtime).expect("initialized memory should be readable");
        eval_unit(&context, b"fixtureValue[0] = 42;")
            .expect("tracked fixture evaluation should succeed");
        let measurement = probe
            .finish(runtime, context, initialized)
            .expect("tracked runtime measurement should finish");
        assert_eq!(
            measurement.pointer("/memory/transient_high_water_measured"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            measurement.pointer("/memory/tracking_allocator/limit_bytes"),
            Some(&serde_json::json!(1024 * 1024))
        );
        assert_eq!(
            measurement.pointer("/memory/tracking_allocator/denied_allocation_count"),
            Some(&serde_json::json!(0))
        );
        assert_eq!(
            measurement.pointer("/memory/tracking_allocator/live_bytes_after_drop"),
            Some(&serde_json::json!(0))
        );
        assert!(
            measurement
                .pointer("/memory/tracking_allocator/high_water_bytes")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|bytes| bytes > 0)
        );
    }

    #[test]
    fn tracking_allocator_enforces_limit_recovers_and_releases_all_live_bytes() {
        const LIMIT: usize = 1024 * 1024;
        let (runtime, stats) =
            new_tracking_runtime(LIMIT).expect("tracking runtime should be created");
        let context = new_context(&runtime).expect("tracking context should be created");
        let error = eval_unit(
            &context,
            b"globalThis.large = new ArrayBuffer(16 * 1024 * 1024);",
        )
        .expect_err("tracking allocator should reject oversized live heap");
        assert!(!error.is_empty());
        assert!(stats.denied_allocation_count() > 0);
        assert!(stats.live_bytes() <= LIMIT);
        assert!(stats.high_water_bytes() <= LIMIT);
        assert_eq!(
            eval_string(&context, b"String(6 * 7)")
                .expect("same context should recover after allocator OOM"),
            "42"
        );
        drop(context);
        drop(runtime);
        assert_eq!(stats.live_bytes(), 0);
    }

    #[test]
    fn upstream_result_priority_matches_fixed_xscanengine_mapping() {
        let cases = [
            ("operation system", 10),
            ("virtual machine", 10),
            ("format", 12),
            ("platform", 14),
            ("dos extender", 14),
            ("linker", 20),
            ("compiler", 30),
            ("language", 40),
            ("library", 50),
            ("tool", 60),
            ("pe tool", 60),
            ("sign tool", 60),
            ("apk tool", 60),
            ("protector", 70),
            ("cryptor", 70),
            ("crypter", 70),
            (".net obfuscator", 80),
            ("apk obfuscator", 80),
            ("jar obfuscator", 80),
            ("dongle protection", 90),
            ("protection", 90),
            ("packer", 100),
            (".net compressor", 100),
            ("joiner", 110),
            ("sfx", 120),
            ("installer", 120),
            ("virus", 70),
            ("malware", 70),
            ("trojan", 70),
            ("corrupted data", 70),
            ("personal data", 70),
            ("author", 70),
            ("debug data", 200),
            ("audio", 1000),
        ];
        for (kind, expected) in cases {
            assert_eq!(upstream_type_priority(kind), expected, "{kind}");
        }
        assert_eq!(upstream_type_priority("~!FORMAT"), 12);
    }

    #[test]
    fn pe_context_matches_fixed_qt5_entry_points_and_physical_maps() {
        let baseline: serde_json::Value =
            serde_json::from_str(include_str!("../../../docs/research/data/pe-rule-qt5.json"))
                .expect("fixed Qt5 PE rule baseline should be valid JSON");
        let cases = baseline["cases"]
            .as_array()
            .expect("fixed Qt5 PE baseline should have cases");
        assert_eq!(cases.len(), 3);
        for case in cases {
            assert_eq!(case["parser_valid"], true);
            let id = case["id"].as_str().expect("case should have an id");
            let data = decode_hex(case["data_hex"].as_str().expect("case should contain data"));
            let context = PeRuleContext::parse(&data)
                .unwrap_or_else(|error| panic!("{id}: PE context should parse: {error}"));
            let entry_point = context
                .entry_point_offset
                .and_then(|offset| i64::try_from(offset).ok())
                .unwrap_or(-1);
            assert_eq!(entry_point, case["entry_point_offset"].as_i64().unwrap());
            assert_eq!(
                pe_physical_map_projection(&context),
                qt5_pe_physical_map_projection(&case["memory_map"])
                    .expect("Qt5 map should project")
            );
            assert_eq!(
                context.aliased_out_of_bounds_sections,
                usize::from(id == "cygwin32_entry_point_truncated")
            );
        }
    }

    #[test]
    fn elf_context_matches_fixed_qt5_entry_points_and_safe_matcher_maps() {
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/elf-rule-qt5.json"
        ))
        .expect("fixed Qt5 ELF rule baseline should be valid JSON");
        let cases = baseline["cases"]
            .as_array()
            .expect("fixed Qt5 ELF baseline should have cases");
        assert_eq!(cases.len(), 6);
        for case in cases {
            assert_eq!(case["parser_valid"], true);
            let id = case["id"].as_str().expect("case should have an id");
            let data = decode_hex(case["data_hex"].as_str().expect("case should contain data"));
            let context = ElfRuleContext::parse(&data)
                .unwrap_or_else(|error| panic!("{id}: ELF context should parse: {error}"));
            assert_eq!(
                u64::from(context.elf_class) * 32,
                case["elf_class"].as_u64().unwrap()
            );
            let entry_point = context
                .entry_point_offset
                .and_then(|offset| i64::try_from(offset).ok())
                .unwrap_or(-1);
            assert_eq!(entry_point, case["entry_point_offset"].as_i64().unwrap());
            let expected = qt5_matcher_map_projection(&case["memory_map"])
                .expect("Qt5 ELF map should safely project");
            assert_eq!(elf_matcher_map_projection(&context), expected.matcher_map);
            if id.ends_with("_truncated") {
                assert_eq!(context.out_of_bounds_loads, 2);
                assert_eq!(expected.discarded_virtual_records, 2);
                assert_eq!(expected.discarded_nonpositive_size_records, 2);
                assert_eq!(expected.discarded_overlay_sentinel_records, 0);
            } else {
                assert_eq!(context.out_of_bounds_loads, 0);
                assert_eq!(expected.discarded_virtual_records, 0);
                assert_eq!(expected.discarded_nonpositive_size_records, 0);
                assert_eq!(expected.discarded_overlay_sentinel_records, 1);
            }
            assert_eq!(expected.discarded_negative_offset_records, 0);
        }
    }

    #[test]
    fn elf_context_rejects_malformed_counts_ranges_and_missing_loads() {
        assert!(ElfRuleContext::parse(&[]).is_err());
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/elf-rule-qt5.json"
        ))
        .expect("fixed Qt5 ELF rule baseline should be valid JSON");
        let mut data = decode_hex(
            baseline["cases"][3]["data_hex"]
                .as_str()
                .expect("ELF64 case should contain data"),
        );

        let mut short_entry = data.clone();
        short_entry[54..56].copy_from_slice(&0_u16.to_le_bytes());
        assert!(
            ElfRuleContext::parse(&short_entry)
                .expect_err("undersized program entry must fail")
                .contains("smaller")
        );

        let mut excessive_count = data.clone();
        excessive_count[56..58].copy_from_slice(&1025_u16.to_le_bytes());
        assert!(
            ElfRuleContext::parse(&excessive_count)
                .expect_err("excessive program entry count must fail")
                .contains("limit 1024")
        );

        data[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            ElfRuleContext::parse(&data)
                .expect_err("overflowing segment range must fail")
                .contains("range overflow")
        );

        let mut no_loads = decode_hex(
            baseline["cases"][3]["data_hex"]
                .as_str()
                .expect("ELF64 case should contain data"),
        );
        no_loads[64..68].copy_from_slice(&0_u32.to_le_bytes());
        no_loads[120..124].copy_from_slice(&0_u32.to_le_bytes());
        assert!(
            ElfRuleContext::parse(&no_loads)
                .expect_err("missing PT_LOAD must fail")
                .contains("no non-empty PT_LOAD")
        );
    }

    #[test]
    fn macho_context_matches_fixed_qt5_entry_points_and_safe_matcher_maps() {
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/macho-rule-qt5.json"
        ))
        .expect("fixed Qt5 Mach-O rule baseline should be valid JSON");
        let cases = baseline["cases"]
            .as_array()
            .expect("fixed Qt5 Mach-O baseline should have cases");
        assert_eq!(cases.len(), 4);
        for case in cases {
            assert_eq!(case["parser_valid"], true);
            let id = case["id"].as_str().expect("case should have an id");
            let data = decode_hex(case["data_hex"].as_str().expect("case should contain data"));
            let context = MachoRuleContext::parse(&data)
                .unwrap_or_else(|error| panic!("{id}: Mach-O context should parse: {error}"));
            assert!(context.is_64);
            assert_eq!(
                u64::from(context.cpu_type),
                case["cpu_type"].as_u64().unwrap()
            );
            let entry_point = context
                .entry_point_offset
                .and_then(|offset| i64::try_from(offset).ok())
                .unwrap_or(-1);
            assert_eq!(entry_point, case["entry_point_offset"].as_i64().unwrap());
            let expected = qt5_matcher_map_projection(&case["memory_map"])
                .expect("Qt5 Mach-O map should safely project");
            assert_eq!(macho_matcher_map_projection(&context), expected.matcher_map);
            if id.ends_with("_truncated") {
                assert_eq!(context.out_of_bounds_segments, 1);
                assert_eq!(expected.discarded_overlay_sentinel_records, 0);
            } else {
                assert_eq!(context.out_of_bounds_segments, 0);
                assert_eq!(expected.discarded_overlay_sentinel_records, 1);
            }
            assert_eq!(expected.discarded_virtual_records, 0);
            assert_eq!(expected.discarded_nonpositive_size_records, 0);
            assert_eq!(expected.discarded_negative_offset_records, 0);
        }
    }

    #[test]
    fn macho_context_rejects_malformed_commands_ranges_and_missing_segments() {
        assert!(MachoRuleContext::parse(&[]).is_err());
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/macho-rule-qt5.json"
        ))
        .expect("fixed Qt5 Mach-O rule baseline should be valid JSON");
        let data = decode_hex(
            baseline["cases"][0]["data_hex"]
                .as_str()
                .expect("Mach-O64 case should contain data"),
        );

        let mut excessive_count = data.clone();
        excessive_count[16..20].copy_from_slice(&1025_u32.to_le_bytes());
        assert!(
            MachoRuleContext::parse(&excessive_count)
                .expect_err("excessive load command count must fail")
                .contains("limit 1024")
        );

        let mut short_command = data.clone();
        short_command[36..40].copy_from_slice(&0_u32.to_le_bytes());
        assert!(
            MachoRuleContext::parse(&short_command)
                .expect_err("undersized load command must fail")
                .contains("smaller than 8")
        );

        let mut overflowing_segment = data.clone();
        overflowing_segment[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            MachoRuleContext::parse(&overflowing_segment)
                .expect_err("overflowing segment file range must fail")
                .contains("range overflow")
        );

        let mut no_segments = data;
        no_segments[32..36].copy_from_slice(&0_u32.to_le_bytes());
        assert!(
            MachoRuleContext::parse(&no_segments)
                .expect_err("missing segment must fail")
                .contains("no non-empty segment")
        );
    }

    #[test]
    fn dex_context_matches_fixed_qt5_string_table_and_truncation() {
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/dex-rule-qt5.json"
        ))
        .expect("fixed Qt5 DEX rule baseline should be valid JSON");
        let cases = baseline["cases"]
            .as_array()
            .expect("fixed Qt5 DEX baseline should have cases");
        assert_eq!(cases.len(), 3);
        for case in cases {
            assert_eq!(case["parser_valid"], true);
            let id = case["id"].as_str().expect("case should have an id");
            let data = decode_hex(case["data_hex"].as_str().expect("case should contain data"));
            let context = DexRuleContext::parse(&data)
                .unwrap_or_else(|error| panic!("{id}: DEX context should parse: {error}"));
            let expected_strings: Vec<String> =
                serde_json::from_value(case["parsed_strings"].clone())
                    .expect("Qt5 parsed strings should deserialize");
            assert_eq!(context.version, 35);
            assert_eq!(context.map_item_count, 3);
            assert_eq!(context.strings, expected_strings);
            assert_eq!(
                context.strings.iter().any(|value| value == "/qdbh"),
                case["native_qdbh_present"].as_bool().unwrap()
            );
            assert_eq!(
                context.out_of_bounds_string_offsets,
                usize::from(id == "qdbh_string_data_truncated")
            );
        }
    }

    #[test]
    fn dex_context_rejects_malformed_counts_and_uleb128() {
        assert!(DexRuleContext::parse(&[]).is_err());
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/dex-rule-qt5.json"
        ))
        .expect("fixed Qt5 DEX rule baseline should be valid JSON");
        let data = decode_hex(
            baseline["cases"][0]["data_hex"]
                .as_str()
                .expect("DEX case should contain data"),
        );

        let mut invalid_endian = data.clone();
        invalid_endian[40..44].fill(0);
        assert!(
            DexRuleContext::parse(&invalid_endian)
                .expect_err("invalid endian tag must fail")
                .contains("endian tag")
        );

        let mut excessive_strings = data.clone();
        excessive_strings[0x88..0x8c].copy_from_slice(&65_537_u32.to_le_bytes());
        assert!(
            DexRuleContext::parse(&excessive_strings)
                .expect_err("excessive string count must fail")
                .contains("limit 65536")
        );

        let mut unterminated_uleb128 = data;
        unterminated_uleb128[0xa8..0xad].fill(0x80);
        assert!(
            DexRuleContext::parse(&unterminated_uleb128)
                .expect_err("unterminated ULEB128 must fail")
                .contains("ULEB128")
        );
    }

    #[test]
    fn apk_context_matches_fixed_qt5_records_case_and_local_truncation() {
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/apk-rule-qt5.json"
        ))
        .expect("fixed Qt5 APK rule baseline should be valid JSON");
        let cases = baseline["cases"]
            .as_array()
            .expect("fixed Qt5 APK baseline should have cases");
        assert_eq!(cases.len(), 3);
        for case in cases {
            assert_eq!(case["parser_valid"], true);
            let id = case["id"].as_str().expect("case should have an id");
            let data = decode_hex(case["data_hex"].as_str().expect("case should contain data"));
            let context = ApkRuleContext::parse(&data)
                .unwrap_or_else(|error| panic!("{id}: APK context should parse: {error}"));
            let expected_names: Vec<String> =
                serde_json::from_value(case["archive_record_names"].clone())
                    .expect("Qt5 archive record names should deserialize");
            assert_eq!(context.archive_record_names, expected_names);
            assert_eq!(
                context
                    .archive_record_names
                    .iter()
                    .any(|value| value == "assets/qdbh"),
                case["native_qdbh_present"].as_bool().unwrap()
            );
            assert_eq!(
                context.local_header_signature_mismatches,
                if id == "qdbh_local_records_truncated" {
                    2
                } else {
                    0
                }
            );
        }
    }

    #[test]
    fn apk_context_rejects_malformed_central_ranges_and_non_apk() {
        assert!(ApkRuleContext::parse(&[]).is_err());
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/apk-rule-qt5.json"
        ))
        .expect("fixed Qt5 APK rule baseline should be valid JSON");
        let data = decode_hex(
            baseline["cases"][0]["data_hex"]
                .as_str()
                .expect("APK case should contain data"),
        );
        let eocd = data.len() - 22;
        let central_offset =
            u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().unwrap()) as usize;

        let mut invalid_signature = data.clone();
        invalid_signature[0..4].fill(0);
        assert!(
            ApkRuleContext::parse(&invalid_signature)
                .expect_err("invalid leading ZIP signature must fail")
                .contains("signature")
        );

        let mut oversized_name = data.clone();
        oversized_name[central_offset + 28..central_offset + 30]
            .copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(
            ApkRuleContext::parse(&oversized_name)
                .expect_err("oversized central name must fail")
                .contains("truncated")
        );

        let mut non_apk = data;
        let class_name = non_apk[central_offset + 46..central_offset + 57].to_vec();
        assert_eq!(class_name, b"classes.dex");
        non_apk[central_offset + 46..central_offset + 57].copy_from_slice(b"not-app.bin");
        assert!(
            ApkRuleContext::parse(&non_apk)
                .expect_err("ZIP without APK marker must fail")
                .contains("does not identify an APK")
        );
    }

    #[test]
    fn archive_context_matches_fixed_qt5_metadata_verbose_gate_and_truncation() {
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/archive-rule-qt5.json"
        ))
        .expect("fixed Qt5 Archive rule baseline should be valid JSON");
        let cases = baseline["cases"]
            .as_array()
            .expect("fixed Qt5 Archive baseline should have cases");
        assert_eq!(cases.len(), 3);
        for case in cases {
            assert_eq!(case["parser_valid"], true);
            let id = case["id"].as_str().expect("case should have an id");
            let data = decode_hex(case["data_hex"].as_str().expect("case should contain data"));
            let verbose = case["verbose"]
                .as_bool()
                .expect("case should contain verbose");
            let context = ArchiveRuleContext::parse(&data, verbose)
                .unwrap_or_else(|error| panic!("{id}: Archive context should parse: {error}"));
            assert_eq!(context.is_verbose, case["native_is_verbose"]);
            assert_eq!(
                context.file_format_name,
                case["native_format_name"].as_str().unwrap()
            );
            assert_eq!(
                context.file_format_version,
                case["native_format_version"].as_str().unwrap()
            );
            assert_eq!(
                context.file_format_options,
                case["native_format_options"].as_str().unwrap()
            );
            assert_eq!(
                context.local_header_signature_mismatches,
                usize::from(id == "verbose_central_directory_only")
            );
        }
    }

    #[test]
    fn archive_context_rejects_malformed_ranges_and_uncovered_methods() {
        assert!(ArchiveRuleContext::parse(&[], true).is_err());
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/archive-rule-qt5.json"
        ))
        .expect("fixed Qt5 Archive rule baseline should be valid JSON");
        let data = decode_hex(
            baseline["cases"][0]["data_hex"]
                .as_str()
                .expect("Archive case should contain data"),
        );
        let eocd = data.len() - 22;
        let central_offset =
            u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().unwrap()) as usize;

        let mut invalid_signature = data.clone();
        invalid_signature[0..4].fill(0);
        assert!(
            ArchiveRuleContext::parse(&invalid_signature, true)
                .expect_err("invalid leading ZIP signature must fail")
                .contains("signature")
        );

        let mut oversized_name = data.clone();
        oversized_name[central_offset + 28..central_offset + 30]
            .copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(
            ArchiveRuleContext::parse(&oversized_name, true)
                .expect_err("oversized central name must fail")
                .contains("truncated")
        );

        let mut deflate = data;
        deflate[central_offset + 10..central_offset + 12].copy_from_slice(&8_u16.to_le_bytes());
        assert!(
            ArchiveRuleContext::parse(&deflate, true)
                .expect_err("uncovered compression method must fail explicitly")
                .contains("unsupported ZIP metadata method")
        );
    }

    #[test]
    fn pdf_context_matches_fixed_qt5_objects_strings_and_truncation() {
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/pdf-rule-qt5.json"
        ))
        .expect("fixed Qt5 PDF rule baseline should be valid JSON");
        let cases = baseline["cases"]
            .as_array()
            .expect("fixed Qt5 PDF baseline should have cases");
        assert_eq!(cases.len(), 3);
        for case in cases {
            assert_eq!(case["parser_valid"], true);
            let id = case["id"].as_str().expect("case should have an id");
            let data = decode_hex(case["data_hex"].as_str().expect("case should contain data"));
            let context = PdfRuleContext::parse(&data)
                .unwrap_or_else(|error| panic!("{id}: PDF context should parse: {error}"));
            assert_eq!(
                context.objects.len(),
                case["object_count"].as_u64().unwrap() as usize
            );
            let object_parts = serde_json::Value::Array(
                context
                    .objects
                    .iter()
                    .map(|object| {
                        serde_json::json!({
                            "id": object.id,
                            "offset": object.offset,
                            "tokens": object.tokens,
                        })
                    })
                    .collect(),
            );
            assert_eq!(object_parts, case["object_parts"]);
            let expected_creators: Vec<String> =
                serde_json::from_value(case["native_creator_values"].clone()).unwrap();
            let expected_producers: Vec<String> =
                serde_json::from_value(case["native_producer_values"].clone()).unwrap();
            assert_eq!(context.creator_values, expected_creators);
            assert_eq!(context.producer_values, expected_producers);
            assert_eq!(
                context.header_comment_hex,
                case["native_header_comment_hex"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn pdf_context_rejects_malformed_tokens_without_unbounded_scanning() {
        assert!(PdfRuleContext::parse(&[]).is_err());
        let baseline: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/pdf-rule-qt5.json"
        ))
        .expect("fixed Qt5 PDF rule baseline should be valid JSON");
        let data = decode_hex(
            baseline["cases"][0]["data_hex"]
                .as_str()
                .expect("PDF case should contain data"),
        );

        let mut nul_line = data.clone();
        nul_line[4] = 0;
        assert!(
            PdfRuleContext::parse(&nul_line)
                .expect_err("NUL line termination must fail explicitly")
                .contains("NUL")
        );

        let dictionary_offset = data
            .windows(2)
            .position(|window| window == b"<<")
            .expect("fixed PDF should contain a dictionary");
        let mut nesting_underflow = data;
        nesting_underflow[dictionary_offset..dictionary_offset + 2].copy_from_slice(b">>");
        assert!(
            PdfRuleContext::parse(&nesting_underflow)
                .expect_err("dictionary nesting underflow must fail")
                .contains("underflow")
        );
    }

    #[test]
    fn output_projection_sorts_distinct_priorities_and_rejects_tie_evidence() {
        let distinct = vec![
            (
                "audio".to_owned(),
                "audio-name".to_owned(),
                "audio-version".to_owned(),
                String::new(),
            ),
            (
                "platform".to_owned(),
                "platform-name".to_owned(),
                "platform-version".to_owned(),
                String::new(),
            ),
            (
                "format".to_owned(),
                "format-name".to_owned(),
                "format-version".to_owned(),
                "format-info".to_owned(),
            ),
        ];
        let (projection, unambiguous) = sorted_detection_projection(&distinct);
        assert!(unambiguous);
        assert_eq!(
            projection,
            [
                (
                    "format".to_owned(),
                    "format-name".to_owned(),
                    "format-version".to_owned(),
                ),
                (
                    "platform".to_owned(),
                    "platform-name".to_owned(),
                    "platform-version".to_owned(),
                ),
                (
                    "audio".to_owned(),
                    "audio-name".to_owned(),
                    "audio-version".to_owned(),
                ),
            ]
        );

        let tied = vec![
            (
                "audio".to_owned(),
                "first".to_owned(),
                String::new(),
                String::new(),
            ),
            (
                "unknown".to_owned(),
                "second".to_owned(),
                String::new(),
                String::new(),
            ),
        ];
        assert!(!sorted_detection_projection(&tied).1);
    }

    #[test]
    fn corpus_oracle_helpers_hash_and_strictly_parse_triples() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let detections = serde_json::json!([["format", "name", "version"]]);
        assert_eq!(
            parse_detection_triples(&detections, "sample").expect("valid triple"),
            [("format".to_owned(), "name".to_owned(), "version".to_owned())]
        );
        let invalid = serde_json::json!([["format", "name", "version", "info"]]);
        assert!(parse_detection_triples(&invalid, "sample").is_err());
    }

    #[test]
    fn corpus_selection_keeps_sg_and_extensionless_files_only() {
        let root = temporary_directory();
        let nested = root.join("PE");
        fs::create_dir_all(&nested).expect("temporary tree should be created");
        fs::write(root.join("_init"), b"init").expect("helper should be written");
        fs::write(nested.join("rule.sg"), b"rule").expect("rule should be written");
        fs::write(nested.join("notes.txt"), b"notes").expect("non-rule should be written");

        let mut files = Vec::new();
        collect_rule_files(&root, &mut files).expect("tree should be readable");
        files.sort();
        let relative = files
            .iter()
            .map(|path| {
                normalized_path(
                    path.strip_prefix(&root)
                        .expect("selected path should remain under root"),
                )
            })
            .collect::<Vec<_>>();

        fs::remove_dir_all(&root).expect("temporary tree should be removed");
        assert_eq!(relative, ["PE/rule.sg", "_init"]);
    }

    #[test]
    fn path_normalization_uses_forward_slashes() {
        assert_eq!(
            normalized_path(&PathBuf::from(r"db\Binary\audio.1.sg")),
            "db/Binary/audio.1.sg"
        );
    }

    #[test]
    fn compatibility_overlay_is_exact_and_length_preserving() {
        let mut source = vec![b' '; NINTENDO_RULE_BYTES];
        let offset = 100;
        source[offset..offset + NINTENDO_VAR_DECLARATION.len()]
            .copy_from_slice(NINTENDO_VAR_DECLARATION);
        let path = PathBuf::from("db/Binary/format_bin.Nintendo-certified-file.1.sg");
        let (transformed, applied) =
            apply_compatibility_overlay(&path, &source).expect("known rule shape should transform");
        assert!(applied);
        assert_eq!(transformed.len(), source.len());
        assert_eq!(
            &transformed[offset..offset + NINTENDO_COMPAT_DECLARATION.len()],
            NINTENDO_COMPAT_DECLARATION
        );
        assert_eq!(
            &transformed[..offset],
            &source[..offset],
            "prefix must remain byte-identical"
        );
    }

    #[test]
    fn compatibility_overlay_refuses_drift() {
        let path = PathBuf::from("db/Binary/format_bin.Nintendo-certified-file.1.sg");
        let error = apply_compatibility_overlay(&path, b"var tp, e;")
            .expect_err("unexpected source identity must be rejected");
        assert!(error.contains("expected 1994 bytes"));
    }

    #[test]
    fn exact_lifecycle_overlay_is_path_size_and_declaration_guarded() {
        let path = PathBuf::from("db/Binary/example.sg");
        let source = b"const value = 1;";
        let (transformed, id) = apply_exact_lifecycle_overlay(
            &path,
            source,
            "Binary/example.sg",
            source.len(),
            b"const",
            b"var  ",
            "example-v1",
        )
        .expect("exact overlay should apply");
        assert_eq!(id, Some("example-v1"));
        assert_eq!(transformed, b"var   value = 1;");

        let error = apply_exact_lifecycle_overlay(
            &path,
            source,
            "Binary/example.sg",
            source.len() + 1,
            b"const",
            b"var  ",
            "example-v1",
        )
        .expect_err("size drift must be rejected");
        assert!(error.contains("expected 17 bytes"));
    }

    #[test]
    fn nintendo_host_reads_both_endiannesses() {
        let bytes = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(read_unsigned(&bytes, 0, 2, true), 0x1234 as f64);
        assert_eq!(read_unsigned(&bytes, 0, 2, false), 0x3412 as f64);
        assert_eq!(read_unsigned(&bytes, 0, 3, true), 0x123456 as f64);
        assert_eq!(read_unsigned(&bytes, 0, 3, false), 0x563412 as f64);
        assert_eq!(read_unsigned(&bytes, 0, 4, true), 0x12345678 as f64);
        assert_eq!(read_unsigned(&bytes, 3, 2, true), 0.0);
    }

    #[test]
    fn unsigned_shift_accepts_defined_safe_integer_range() {
        assert_eq!(
            shift_right_unsigned(0xFFFFFFFF_u64 as f64, 0).expect("zero shift should succeed"),
            0xFFFFFFFF_u64 as f64
        );
        assert_eq!(
            shift_right_unsigned(0xFFFFFFFF_u64 as f64, 4).expect("four-bit shift should succeed"),
            0x0FFFFFFF_u64 as f64
        );
        assert_eq!(
            shift_right_unsigned(0xFFFFFFFF_u64 as f64, 32).expect("32-bit shift should succeed"),
            0.0
        );
        assert!(shift_right_unsigned(-1.0, 1).is_err());
        assert!(shift_right_unsigned(1.5, 1).is_err());
        assert!(shift_right_unsigned(f64::NAN, 1).is_err());
        assert!(shift_right_unsigned(1.0, 64).is_err());
    }

    #[test]
    fn signature_adapter_exposes_compare_search_and_explicit_diagnostics() {
        let runtime = new_runtime().expect("runtime should be created");
        let context = new_context(&runtime).expect("context should be created");
        let mut bytes = vec![0_u8; 300];
        bytes[0..8].copy_from_slice(b"SCE\0\0\0\0\x02");
        bytes[16..23].copy_from_slice(b"\x7fELF\0\0\x01");
        bytes[253] = b'A';
        let trace =
            install_nintendo_host(&context, Arc::new(bytes), Arc::new(Mutex::new(Vec::new())))
                .expect("host should be installed");

        assert_eq!(
            eval_string(
                &context,
                br#"String(X.c("'SCE'00", 0)) + "|" +
                    String(Binary.compare("41x", 253)) + "|" +
                    String(Binary.findSignature(0, -1, "'SCE'")) + "|" +
                    String(X.fSig(1, 10, "4345")) + "|" +
                    String(Binary.isSignaturePresent(0, 8, "'ELF'"))"#,
            )
            .expect("supported signatures should be evaluated"),
            "true|true|0|1|false"
        );
        eval_unit(&context, b"Binary.compare('unsupported', 253)")
            .expect_err("unknown syntax must be an explicit diagnostic");
        eval_unit(&context, b"Binary.findSignature(0, -1, 'unsupported')")
            .expect_err("unknown search syntax must be an explicit diagnostic");
        assert_eq!(trace.calls.load(Ordering::Relaxed), 3);
        assert_eq!(trace.compare_native_checkpoints.load(Ordering::Relaxed), 3);
        assert_eq!(trace.fast_paths.load(Ordering::Relaxed), 1);
        assert_eq!(trace.generic_paths.load(Ordering::Relaxed), 1);
        assert_eq!(trace.quirks.load(Ordering::Relaxed), 1);
        assert_eq!(trace.errors.load(Ordering::Relaxed), 1);
        assert_eq!(trace.search_calls.load(Ordering::Relaxed), 4);
        assert_eq!(trace.search_native_checkpoints.load(Ordering::Relaxed), 4);
        assert_eq!(trace.find_signature_calls.load(Ordering::Relaxed), 2);
        assert_eq!(trace.f_sig_calls.load(Ordering::Relaxed), 1);
        assert_eq!(trace.is_signature_present_calls.load(Ordering::Relaxed), 1);
        assert_eq!(trace.search_matches.load(Ordering::Relaxed), 2);
        assert_eq!(trace.search_quirks.load(Ordering::Relaxed), 0);
        assert_eq!(trace.search_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn overlay_host_context_keeps_file_part_and_nested_overlay_independent() {
        let cases = [
            (
                vec![0_u8; 256],
                BinaryHostContext::new(HostFilePart::Header, 256, 0)
                    .expect("fixed context should be valid"),
                "false|256|0|false",
            ),
            (
                vec![0_u8; 1],
                BinaryHostContext::new(HostFilePart::Overlay, 1, 0)
                    .expect("fixed context should be valid"),
                "true|1|0|false",
            ),
            (
                vec![0_u8; 2048],
                BinaryHostContext::new(HostFilePart::Header, 1536, 512)
                    .expect("fixed context should be valid"),
                "false|1536|512|true",
            ),
        ];
        for (bytes, host_context, expected) in cases {
            let runtime = new_runtime().expect("runtime should be created");
            let context = new_context(&runtime).expect("context should be created");
            let trace = install_nintendo_host_with_context(
                &context,
                Arc::new(bytes),
                Arc::new(Mutex::new(Vec::new())),
                host_context,
            )
            .expect("host should be installed");
            assert_eq!(
                eval_string(
                    &context,
                    br#"String(Binary.isOverlay()) + "|" +
                        String(Binary.getOverlayOffset()) + "|" +
                        String(Binary.getOverlaySize()) + "|" +
                        String(Binary.isOverlayPresent())"#,
                )
                .expect("overlay HostApi should be callable"),
                expected
            );
            assert_eq!(trace.is_overlay_calls.load(Ordering::Relaxed), 1);
            assert_eq!(trace.get_overlay_offset_calls.load(Ordering::Relaxed), 1);
            assert_eq!(trace.get_overlay_size_calls.load(Ordering::Relaxed), 1);
            assert_eq!(trace.is_overlay_present_calls.load(Ordering::Relaxed), 1);
        }
        assert!(BinaryHostContext::new(HostFilePart::Header, 0, -1).is_err());
    }

    #[test]
    fn scan_and_file_part_context_matches_pinned_qt5_oracle() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/signature-oracle-qt5.json"
        ))
        .expect("Qt5 signature oracle should be valid JSON");
        let cases = oracle["cases"]
            .as_array()
            .expect("Qt5 signature oracle should contain cases");
        let mut checked = 0_usize;
        for case in cases {
            let Some(file_part_name) = case["binary_script_file_part"].as_str() else {
                continue;
            };
            let Some(scan_id) = case["binary_script_scan_id"].as_str() else {
                continue;
            };
            checked += 1;
            let file_part = match file_part_name {
                "header" => HostFilePart::Header,
                "resource" => HostFilePart::Resource,
                "debugdata" => HostFilePart::DebugData,
                other => panic!("unexpected oracle file part: {other}"),
            };
            let actual = BinaryHostContext::new(file_part, 0, 0)
                .expect("oracle context should be valid")
                .with_scan_id(scan_id);
            assert_eq!(
                actual.scan_id,
                case["binary_script_get_scan_id_result"]
                    .as_str()
                    .expect("oracle scan ID should be a string")
            );
            assert_eq!(
                actual.is_resource(),
                case["binary_script_is_resource_result"]
                    .as_bool()
                    .expect("oracle resource flag should be a bool")
            );
            assert_eq!(
                actual.is_debug_data(),
                case["binary_script_is_debug_data_result"]
                    .as_bool()
                    .expect("oracle debug-data flag should be a bool")
            );
            assert_eq!(
                actual.is_file_part(),
                case["binary_script_is_file_part_result"]
                    .as_bool()
                    .expect("oracle file-part flag should be a bool")
            );
        }
        assert_eq!(checked, 3);
    }

    #[test]
    fn text_context_is_deterministic_across_upstream_prefill_states() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/signature-oracle-qt5.json"
        ))
        .expect("Qt5 signature oracle should be valid JSON");
        let cases = oracle["cases"]
            .as_array()
            .expect("Qt5 signature oracle should contain cases");
        let find = |id: &str| {
            cases
                .iter()
                .find(|case| case["id"].as_str() == Some(id))
                .unwrap_or_else(|| panic!("missing oracle case {id}"))
        };
        let nontext_zero = find("binary_script_nontext_prefill_zero");
        let nontext_one = find("binary_script_nontext_prefill_one");
        assert_eq!(
            nontext_zero["binary_script_prefill_is_text_result"].as_bool(),
            Some(false)
        );
        assert_eq!(
            nontext_one["binary_script_prefill_is_text_result"].as_bool(),
            Some(true),
            "fixed upstream result must expose the uninitialized-state divergence"
        );
        let nontext = BinaryStringContext::from_file_name(&decode_hex("00010203"), "");
        assert!(!nontext.is_unicode_text());
        assert!(!nontext.is_text());

        for id in [
            "binary_script_unicode_prefill_zero",
            "binary_script_unicode_prefill_one",
        ] {
            let case = find(id);
            assert_eq!(
                case["binary_script_prefill_is_unicode_text_result"].as_bool(),
                Some(true)
            );
            assert_eq!(
                case["binary_script_prefill_is_text_result"].as_bool(),
                Some(true)
            );
        }
        let unicode = BinaryStringContext::from_file_name(&decode_hex("fffe4100"), "");
        assert!(unicode.is_unicode_text());
        assert!(unicode.is_text());
    }

    #[test]
    fn fixed_context_rules_match_pinned_qt5_oracle_end_to_end() {
        const RESULT_SHIM: &[u8] = br#"
            var bDetected, sType, sName, sVersion, sOptions;
            function meta(type, name, version, options) {
                sType = type;
                sName = name ? name : String();
                sVersion = version ? version : String();
                sOptions = options ? options : String();
                bDetected = false;
            }
            function _error(message) { throw new Error(String(message)); }
            function result() {
                if (bDetected) {
                    sVersion = sVersion ? sVersion : String();
                    sOptions = sOptions ? sOptions : String();
                    if (!sName) _error("No input detection name.");
                    _setResult(sType, sName, sVersion, sOptions);
                }
                sName = sVersion = sOptions = "";
                var value = bDetected;
                bDetected = false;
                return value;
            }
        "#;

        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/context-rule-qt5.json"
        ))
        .expect("Qt5 context-rule oracle should be valid JSON");
        let cases = oracle["cases"]
            .as_array()
            .expect("Qt5 context-rule oracle should contain cases");
        let rule_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../upstream/Detect-It-Easy/db/Binary");
        assert_eq!(cases.len(), 8);

        for case in cases {
            let id = case["id"].as_str().expect("oracle case should have an id");
            let data = decode_hex(
                case["data_hex"]
                    .as_str()
                    .expect("oracle case should have data"),
            );
            let file_part = match case["file_part"]
                .as_str()
                .expect("oracle case should have a file part")
            {
                "header" => HostFilePart::Header,
                "resource" => HostFilePart::Resource,
                "debugdata" => HostFilePart::DebugData,
                other => panic!("unexpected context-rule file part: {other}"),
            };
            let scan_id = case["scan_id"]
                .as_str()
                .expect("oracle case should have a scan ID");
            let file_name = case["file_name"]
                .as_str()
                .expect("oracle case should have a file name");
            let rule_name = Path::new(
                case["rule_path"]
                    .as_str()
                    .expect("oracle case should have a rule path"),
            )
            .file_name()
            .expect("oracle rule path should have a file name");
            let rule_path = rule_root.join(rule_name);
            let source = fs::read(&rule_path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", rule_path.display()));

            let runtime = new_runtime().expect("runtime should be created");
            let context = new_context(&runtime).expect("context should be created");
            let detections = Arc::new(Mutex::new(Vec::new()));
            let bytes = Arc::new(data);
            let host_context = BinaryHostContext::new(
                file_part,
                i64::try_from(bytes.len()).expect("fixture size should fit qint64"),
                0,
            )
            .expect("fixed context should be valid")
            .with_scan_id(scan_id);
            let string_context = BinaryStringContext::from_file_name(&bytes, file_name);
            install_nintendo_host_with_context_and_strings(
                &context,
                bytes,
                Arc::clone(&detections),
                host_context,
                string_context,
            )
            .expect("host should be installed");
            eval_unit(&context, RESULT_SHIM).expect("result shim should evaluate");
            let detect_result = eval_rule_lexical(&context, &source, true)
                .unwrap_or_else(|error| panic!("{id} should evaluate: {error}"));
            assert_eq!(
                detect_result,
                if case["detect_result"].as_bool() == Some(true) {
                    "true"
                } else {
                    "false"
                },
                "detect result mismatch for {id}"
            );
            let actual_detections = detections
                .lock()
                .expect("fixture result mutex should not be poisoned")
                .clone();
            assert_eq!(
                serde_json::to_value(actual_detections).expect("detections should serialize"),
                case["detections"],
                "detection mismatch for {id}"
            );
        }
    }

    #[test]
    fn string_context_matches_pinned_qt5_oracle() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/research/data/signature-oracle-qt5.json"
        ))
        .expect("Qt5 signature oracle should be valid JSON");
        let cases = oracle["cases"]
            .as_array()
            .expect("Qt5 signature oracle should contain cases");
        let mut checked = 0_usize;
        for case in cases {
            if case["binary_script_string_info"].as_bool() != Some(true) {
                continue;
            }
            checked += 1;
            let id = case["id"].as_str().expect("oracle case should have an id");
            let data = decode_hex(
                case["data_hex"]
                    .as_str()
                    .expect("oracle case should have data"),
            );
            let file_name = case["file_name"].as_str().unwrap_or("");
            let actual = BinaryStringContext::from_file_name(&data, file_name);
            assert_eq!(
                actual.file_suffix,
                case["binary_script_get_file_suffix_result"]
                    .as_str()
                    .expect("oracle suffix should be a string"),
                "suffix mismatch for {id}"
            );
            assert_eq!(
                actual.header_string,
                case["binary_script_get_header_string_result"]
                    .as_str()
                    .expect("oracle header should be a string"),
                "header mismatch for {id}"
            );
            assert_eq!(
                actual.is_plain_text,
                case["binary_script_is_plain_text_result"]
                    .as_bool()
                    .expect("oracle plain-text flag should be a bool"),
                "plain-text mismatch for {id}"
            );
            assert_eq!(
                actual.is_utf8_text,
                case["binary_script_is_utf8_text_result"]
                    .as_bool()
                    .expect("oracle UTF-8 flag should be a bool"),
                "UTF-8 mismatch for {id}"
            );
            let expected_unicode = match case["x_binary_unicode_type_result"]
                .as_str()
                .expect("oracle Unicode type should be a string")
            {
                "none" => TextUnicodeType::None,
                "little" => TextUnicodeType::Little,
                "big" => TextUnicodeType::Big,
                other => panic!("unexpected oracle Unicode type: {other}"),
            };
            assert_eq!(
                actual.unicode_type, expected_unicode,
                "Unicode type mismatch for {id}"
            );
        }
        assert_eq!(checked, 15);
    }

    #[test]
    fn string_context_is_exposed_as_native_host_api() {
        let runtime = new_runtime().expect("runtime should be created");
        let context = new_context(&runtime).expect("context should be created");
        let bytes = Arc::new(b"function test() {}\n".to_vec());
        let host_context =
            BinaryHostContext::identity_header(bytes.len()).expect("fixed context should be valid");
        let string_context = BinaryStringContext::from_file_name(&bytes, "sample.C");
        let trace = install_nintendo_host_with_context_and_strings(
            &context,
            bytes,
            Arc::new(Mutex::new(Vec::new())),
            host_context,
            string_context,
        )
        .expect("host should be installed");
        assert_eq!(
            eval_string(
                &context,
                br#"Binary.getFileSuffix() + "|" +
                    Binary.getHeaderString() + "|" +
                    String(Binary.isPlainText()) + "|" +
                    String(Binary.isUTF8Text()) + "|" +
                    String(Binary.isUnicodeText()) + "|" +
                    String(Binary.isText())"#,
            )
            .expect("string HostApi should be callable"),
            "C|function test() {}\n|true|false|false|true"
        );
        assert_eq!(trace.get_file_suffix_calls.load(Ordering::Relaxed), 1);
        assert_eq!(trace.get_header_string_calls.load(Ordering::Relaxed), 1);
        assert_eq!(trace.is_plain_text_calls.load(Ordering::Relaxed), 1);
        assert_eq!(trace.is_utf8_text_calls.load(Ordering::Relaxed), 1);
        assert_eq!(trace.is_unicode_text_calls.load(Ordering::Relaxed), 1);
        assert_eq!(trace.is_text_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn scan_and_file_part_context_is_exposed_as_native_host_api() {
        let runtime = new_runtime().expect("runtime should be created");
        let context = new_context(&runtime).expect("context should be created");
        let bytes = Arc::new(vec![0x41]);
        let host_context = BinaryHostContext::new(HostFilePart::Resource, 1, 0)
            .expect("fixed context should be valid")
            .with_scan_id("24");
        let string_context = BinaryStringContext::from_file_name(&bytes, "");
        let trace = install_nintendo_host_with_context_and_strings(
            &context,
            bytes,
            Arc::new(Mutex::new(Vec::new())),
            host_context,
            string_context,
        )
        .expect("host should be installed");
        assert_eq!(
            eval_string(
                &context,
                br#"Binary.getScanID() + "|" +
                    String(Binary.isResource()) + "|" +
                    String(Binary.isDebugData()) + "|" +
                    String(Binary.isFilePart())"#,
            )
            .expect("scan and file-part HostApi should be callable"),
            "24|true|false|true"
        );
        assert_eq!(trace.get_scan_id_calls.load(Ordering::Relaxed), 1);
        assert_eq!(trace.is_resource_calls.load(Ordering::Relaxed), 1);
        assert_eq!(trace.is_debug_data_calls.load(Ordering::Relaxed), 1);
        assert_eq!(trace.is_file_part_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn ascii_host_read_is_nul_terminated_and_bounds_checked() {
        let bytes = b"SC\0trailing";
        assert_eq!(read_ascii(bytes, 0, bytes.len()), "SC");
        assert_eq!(read_ascii(bytes, 3, 4), "trai");
        assert_eq!(read_ascii(b"abc", 1, 50), "bc");
        assert_eq!(read_ascii(bytes, bytes.len(), 1), "");
    }

    #[test]
    fn signed_and_byte_array_host_reads_are_bounded() {
        assert_eq!(read_signed(&[0xff], 0, 1, false), -1.0);
        assert_eq!(read_signed(&[0x80, 0x00], 0, 2, true), -32768.0);
        assert_eq!(read_signed(&[0x80], 1, 1, false), 0.0);
        assert_eq!(read_byte_array(b"a\0b", 0, 20, false), b"a\0b");
        assert_eq!(read_byte_array(b"a\0b", 0, 20, true), b"a b");
        assert!(read_byte_array(b"abc", -1, 1, false).is_empty());
        assert!(read_byte_array(b"abc", 0, -1, false).is_empty());
    }

    #[test]
    fn host_offsets_reject_negative_values_without_conversion_errors() {
        assert_eq!(nonnegative_index(-1), None);
        assert_eq!(nonnegative_index(0), Some(0));
        assert_eq!(nonnegative_index(128), Some(128));
    }

    #[test]
    fn diagnostic_fallback_counts_all_calls_and_caps_captured_paths() {
        let runtime = new_runtime().expect("runtime should be created");
        let context = new_context(&runtime).expect("context should be created");
        eval_unit(
            &context,
            b"var Binary = { c: function () { return false; } }; var Util = {};",
        )
        .expect("fallback globals should be initialized");
        install_diagnostic_host_fallbacks(&context).expect("fallback should be installed");
        eval_unit(&context, b"for (var i = 0; i < 300; i++) Binary.missing();")
            .expect("fallback calls should complete");
        assert_eq!(
            eval_string(
                &context,
                b"String(__fallbackTotal) + '|' + String(__fallbackCalls.length)",
            )
            .expect("fallback counters should be readable"),
            "300|256"
        );
    }

    #[test]
    fn scope_fixture_order_rejects_wrong_inventory() {
        let document = serde_json::json!({
            "generator": "tools/corpus/generate_script_scope_fixture.py",
            "rule_order": ["only-one.sg"],
        });
        let error = parse_scope_fixture_order(&document)
            .expect_err("incomplete scope fixture must be rejected");
        assert!(error.contains("expected 7"));
    }

    #[test]
    fn scope_detections_parse_qt5_shape() {
        let document = serde_json::json!({
            "detections": [{
                "type": "format",
                "name": "Scope",
                "version": "2",
                "info": "",
            }],
        });
        assert_eq!(
            parse_scope_detections(&document).expect("fixed shape should parse"),
            [(
                "format".to_owned(),
                "Scope".to_owned(),
                "2".to_owned(),
                String::new(),
            )]
        );
    }

    #[test]
    fn lexical_wrapper_isolates_rule_bindings_and_returns_detect() {
        let runtime = new_runtime().expect("runtime should be created");
        let context = new_context(&runtime).expect("context should be created");
        assert_eq!(
            eval_rule_lexical(
                &context,
                b"const value = 1; function detect() { return value; }",
                true,
            )
            .expect("first rule should evaluate"),
            "1"
        );
        assert_eq!(
            eval_rule_lexical(
                &context,
                b"value = 2; function detect() { return value; }",
                true,
            )
            .expect("prior const must not make this assignment read-only"),
            "2"
        );
        assert_eq!(
            eval_rule_lexical(&context, b"function detect() { return 'function'; }", true,)
                .expect("function detect should evaluate"),
            "function"
        );
        assert_eq!(
            eval_rule_lexical(
                &context,
                b"const detect = main; function main() { return 'const'; }",
                true,
            )
            .expect("const detect must not conflict with the prior rule"),
            "const"
        );
    }
}

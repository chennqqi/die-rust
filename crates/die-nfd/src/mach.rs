//! `NFD_MACH` semantic handlers — Mach-O load-command driven detection:
//! OS/SDK/Xcode/clang/Swift/ld version chain, libraries, protectors
//! (`handle_Tools`, `handle_Protection`, `handle_FixDetects`).

use crate::mach_tables as mt;
use crate::parse::{self, rd_u32_be_le};
use crate::scans::{EmitTarget, ResultMaps};
use crate::{gen_names::name as n, gen_names::rtype as rt};

fn emit(map: &mut impl EmitTarget, ft: u16, rtype: u8, name: u16, ver: &str, info: &str) {
    crate::scans::push(map, ft, rtype, name, ver, info, None, None);
}

/// Parsed Mach-O load-command summary.
#[derive(Debug, Default)]
pub struct MachInfo {
    /// MH_CIGAM*.
    pub big: bool,
    /// `cputype`.
    pub cputype: u32,
    /// `cpusubtype` (low 24 bits).
    pub cpusubtype: u32,
    /// 64-bit magic (`MH_MAGIC_64`/`MH_CIGAM_64`).
    pub is64: bool,
    /// `filetype` header field (`MH_*`).
    pub filetype: u32,
    /// Load commands as `(cmd, file offset)`.
    pub commands: Vec<(u32, usize)>,
    /// LC_LOAD_DYLIB records: `(basename, current_version)`.
    pub libraries: Vec<(String, u32)>,
    /// Segment names.
    pub segments: Vec<String>,
    /// Section records: `(name, file offset, size)`.
    pub sections: Vec<(String, usize, usize)>,
}

/// Parse Mach-O header + load commands (`XMACH::getCommandRecords` et
/// al.). Thin/fat-universal is not split here — the caller sniffs
/// `FT_MACHO32/64` first.
pub fn mach_info(d: &[u8]) -> Option<MachInfo> {
    let magic = parse::rd_u32(d, 0)?;
    let (is64, big) = match magic {
        0xFEEDFACE => (false, false), // MH_MAGIC (read LE → magic bytes as stored)
        0xCEFAEDFE => (false, true),  // MH_CIGAM
        0xFEEDFACF => (true, false),  // MH_MAGIC_64
        0xCFFAEDFE => (true, true),   // MH_CIGAM_64
        _ => return None,
    };
    let ru32 = |o: usize| rd_u32_be_le(d, o, big);
    let mut info = MachInfo {
        big,
        cputype: ru32(4)?,
        cpusubtype: ru32(8)? & 0xFF_FFFF,
        is64,
        filetype: ru32(12)?,
        ..Default::default()
    };
    let ncmds = ru32(16)? as usize;
    let mut p = if is64 { 32usize } else { 28usize };
    for _ in 0..ncmds.min(4096) {
        let (Some(cmd), Some(cmdsize)) = (ru32(p), ru32(p + 4)) else {
            break;
        };
        if cmdsize < 8 || p.checked_add(cmdsize as usize)? > d.len() {
            break;
        }
        let cs = cmdsize as usize;
        info.commands.push((cmd, p));
        match cmd {
            // LC_SEGMENT / LC_SEGMENT_64 — segname + embedded sections.
            0x1 | 0x19 => {
                let (seg_at, sec_at, sec_sz, nsec_at) = if is64 {
                    (p + 8, p + 72, 80usize, p + 64)
                } else {
                    (p + 8, p + 56, 68usize, p + 48)
                };
                let seg = parse::read_ansi_string(d, seg_at).unwrap_or_default();
                if !seg.is_empty() {
                    info.segments.push(seg);
                }
                let nsec = ru32(nsec_at).unwrap_or(0) as usize;
                for i in 0..nsec.min(256) {
                    let s_off = sec_at + i * sec_sz;
                    if s_off + sec_sz > d.len() {
                        break;
                    }
                    let name = parse::read_ansi_string(d, s_off).unwrap_or_default();
                    let (off, size) = if is64 {
                        (
                            ru32(s_off + 48).unwrap_or(0) as usize,
                            ru32(s_off + 40).unwrap_or(0) as usize,
                        )
                    } else {
                        (
                            ru32(s_off + 36).unwrap_or(0) as usize,
                            ru32(s_off + 32).unwrap_or(0) as usize,
                        )
                    };
                    info.sections.push((name, off, size));
                }
            }
            // LC_LOAD_DYLIB — name (rel offset), current_version.
            0xC => {
                if cs >= 24
                    && let Some(name_off) = ru32(p + 8).map(|v| v as usize)
                    && let Some(full) = p
                        .checked_add(name_off)
                        .and_then(|o| parse::read_ansi_string(d, o))
                {
                    let base = full.rsplit('/').next().unwrap_or(&full).to_string();
                    let cur = ru32(p + 16).unwrap_or(0);
                    info.libraries.push((base, cur));
                }
            }
            _ => {}
        }
        p += cs;
    }
    Some(info)
}

fn cmd_present(e: &MachInfo, cmd: u32) -> bool {
    e.commands.iter().any(|(c, _)| *c == cmd)
}

fn cmd_offset(e: &MachInfo, cmd: u32) -> Option<usize> {
    e.commands.iter().find(|(c, _)| *c == cmd).map(|(_, o)| *o)
}

fn lib_present(e: &MachInfo, name: &str) -> bool {
    e.libraries.iter().any(|(nm, _)| nm == name)
}

fn lib_version(e: &MachInfo, name: &str) -> u32 {
    e.libraries
        .iter()
        .find(|(nm, _)| nm == name)
        .map(|(_, v)| *v)
        .unwrap_or(0)
}

fn sec_present(e: &MachInfo, name: &str) -> bool {
    e.sections.iter().any(|(nm, _, _)| nm == name)
}

/// `XBinary::get_uint32_full_version` — `major16.minor8.patch8`.
fn full_ver(v: u32) -> String {
    format!("{}.{}.{}", (v >> 16) & 0xFFFF, (v >> 8) & 0xFF, v & 0xFF)
}

fn s_full(maj: u32, min: u32, pat: u32) -> u32 {
    (maj << 16) | (min << 8) | pat
}

// OSNAME ids carried as RECORD_NAME ids directly (the names coincide).
const OSX: u16 = n::RECORD_NAME_OS_X;
const MACOSX: u16 = n::RECORD_NAME_MAC_OS_X;
const MACOS: u16 = n::RECORD_NAME_MACOS;
const IPHONEOS: u16 = n::RECORD_NAME_IPHONEOS;
const IOS: u16 = n::RECORD_NAME_IOS;
const IPADOS: u16 = n::RECORD_NAME_IPADOS;
const TVOS: u16 = n::RECORD_NAME_TVOS;
const WATCHOS: u16 = n::RECORD_NAME_WATCHOS;

/// `XMACH::getFileFormatInfo` OS identification: CPU-type defaults,
/// LC_VERSION_MIN/LC_BUILD_VERSION overrides, Foundation refinement.
fn mach_os(d: &[u8], e: &MachInfo, big: bool) -> (u16, String) {
    let (mut os, mut osver) = match e.cputype {
        6 => (n::RECORD_NAME_MAC_OS, "1.0-8.1".to_string()), // MC680x0
        0x12 => (n::RECORD_NAME_MAC_OS, "7.1.2-9.22".to_string()), // POWERPC
        0x0100_0012 => (MACOSX, "10.4-10.6".to_string()),    // POWERPC64
        7 | 0x0100_0007 => (MACOSX, "10.4-10.14".to_string()), // I386/X86_64
        0x0C | 0x0100_000C => {
            // ARM/ARM64
            match e.cpusubtype {
                6 => (IPHONEOS, "1.0-4.2.1".to_string()),
                9 => (IPHONEOS, "3.0-10.3.4".to_string()),
                _ if e.cputype == 0x0100_000C => (IOS, "7.0-16.0".to_string()),
                _ => (IOS, String::new()),
            }
        }
        _ => (n::RECORD_NAME_MAC_OS, String::new()),
    };

    // LC_BUILD_VERSION wins over LC_VERSION_MIN_*.
    let mut build_off = None;
    let mut vmin_off = None;
    if cmd_present(e, 0x32) {
        build_off = cmd_offset(e, 0x32);
    } else if cmd_present(e, 0x25) {
        vmin_off = cmd_offset(e, 0x25);
        os = IOS;
    } else if cmd_present(e, 0x24) {
        vmin_off = cmd_offset(e, 0x24);
        os = MACOS;
    } else if cmd_present(e, 0x2F) {
        vmin_off = cmd_offset(e, 0x2F);
        os = TVOS;
    } else if cmd_present(e, 0x30) {
        vmin_off = cmd_offset(e, 0x30);
        os = WATCHOS;
    }
    if let Some(off) = build_off {
        let platform = rd_u32_be_le(d, off + 8, big).unwrap_or(0);
        let minos = rd_u32_be_le(d, off + 12, big).unwrap_or(0);
        os = match platform {
            1 => MACOS,
            2 | 7 => IOS,
            3 | 8 => TVOS,
            4 | 9 => WATCHOS,
            5 => n::RECORD_NAME_BRIDGEOS,
            6 => n::RECORD_NAME_MACCATALYST,
            10 => n::RECORD_NAME_MACDRIVERKIT,
            13 => n::RECORD_NAME_MACFIRMWARE,
            14 => n::RECORD_NAME_SEPOS,
            _ => os,
        };
        if minos != 0 {
            osver = full_ver(minos);
        }
    } else if let Some(off) = vmin_off {
        let version = rd_u32_be_le(d, off + 8, big).unwrap_or(0);
        if version != 0 {
            osver = full_ver(version);
        }
    }

    // Foundation-version refinement (`getFileFormatInfo` tail).
    if lib_present(e, "Foundation") {
        let v = lib_version(e, "Foundation");
        if os == MACOSX || os == OSX || os == MACOS {
            let new_ver: &str = if (s_full(397, 40, 0)..s_full(425, 0, 0)).contains(&v) {
                "10.0.0"
            } else if v < s_full(567, 0, 0) {
                "10.3.0"
            } else if v < s_full(677, 0, 0) {
                "10.4.0"
            } else if v < s_full(677, 24, 0) {
                "10.5.0"
            } else if v < s_full(751, 0, 0) {
                "10.5.7"
            } else if v < s_full(833, 10, 0) {
                "10.6.0"
            } else if v < s_full(833, 25, 0) {
                "10.7.0"
            } else if v < s_full(945, 18, 0) {
                "10.7.4"
            } else if v < s_full(1151, 16, 0) {
                "10.8.4"
            } else if v < s_full(1200, 0, 0) {
                "10.10.0"
            } else {
                return (os, osver);
            };
            osver = new_ver.to_string();
            if v < s_full(833, 10, 0) {
                os = MACOSX;
            }
        } else if os == IPHONEOS || os == IOS || os == IPADOS {
            let new_ver: &str = if v < s_full(678, 24, 0) {
                "1.0.0"
            } else if v < s_full(678, 26, 0) {
                "2.0.0"
            } else if v < s_full(678, 29, 0) {
                "2.1.0"
            } else if v < s_full(678, 47, 0) {
                "2.2.0"
            } else if v < s_full(678, 51, 0) {
                "3.0.0"
            } else if v < s_full(678, 60, 0) {
                "3.1.0"
            } else if v < s_full(751, 32, 0) {
                "3.2.0"
            } else if v < s_full(751, 37, 0) {
                "4.0.0"
            } else if v < s_full(751, 49, 0) {
                "4.1.0"
            } else if v < s_full(881, 0, 0) {
                "4.2.0"
            } else if v < s_full(890, 10, 0) {
                "5.0.0"
            } else if v < s_full(992, 0, 0) {
                "5.1.0"
            } else if v < s_full(993, 0, 0) {
                "6.0.0"
            } else if v < s_full(1047, 20, 0) {
                "6.1.0"
            } else if v < s_full(1047, 25, 0) {
                "7.0.0"
            } else if v < s_full(1140, 11, 0) {
                "7.1.0"
            } else if v < s_full(1141, 1, 0) {
                "8.0.0"
            } else if v < s_full(1142, 14, 0) {
                "8.1.0"
            } else if v < s_full(1144, 17, 0) {
                "8.2.0"
            } else if v < s_full(1200, 0, 0) {
                "8.3.0"
            } else {
                return (os, osver);
            };
            osver = new_ver.to_string();
            os = if v < s_full(751, 32, 0) {
                IPHONEOS
            } else {
                IOS
            };
        }
    }
    (os, osver)
}

/// `XMACH::getSDKVersionFromFoundation` — first table entry whose
/// threshold exceeds the Foundation version.
fn sdk_from_foundation(v: u32, os: u16) -> String {
    let macos = matches!(os, MACOS | OSX | MACOSX);
    let ios = matches!(os, IPHONEOS | IOS | IPADOS);
    if macos {
        for &(a, b, c, s) in mt::FOUNDATION_VERSIONS {
            if v < s_full(a, b, c) {
                return s.to_string();
            }
        }
    } else if ios {
        for &(a, b, c, s) in mt::IOS_FOUNDATION_VERSIONS {
            if v < s_full(a, b, c) {
                return s.to_string();
            }
        }
    }
    String::new()
}

/// `XMACH::getExactOSName` — macOS/OS X/iPhoneOS naming evolution.
fn exact_os(os: u16, ver: &str) -> u16 {
    let parts: Vec<u32> = ver.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    let major = parts.first().copied().unwrap_or(0);
    let minor = parts.get(1).copied().unwrap_or(0);
    if matches!(os, MACOS | OSX | MACOSX) {
        if major == 10 {
            if minor <= 7 {
                MACOSX
            } else if minor <= 11 {
                OSX
            } else {
                MACOS
            }
        } else if major >= 11 {
            MACOS
        } else {
            os
        }
    } else if matches!(os, IPHONEOS | IOS | IPADOS) {
        if major <= 3 {
            IPHONEOS
        } else if major >= 13 && os == IPADOS {
            IPADOS
        } else {
            IOS
        }
    } else {
        os
    }
}

/// Normalize an SDK version: strip trailing `.0` components while more
/// than one component remains (`getXcodeVersionFromSDK` normalization).
fn norm_sdk(v: &str) -> &str {
    let mut s = v;
    while s.ends_with(".0") && s.matches('.').count() > 0 {
        s = &s[..s.len() - 2];
    }
    s
}

/// `XMACH::getXcodeVersionFromSDK` — normalized SDK→Xcode lookup over
/// the OS-appropriate column (0=macOS, 1=iOS, 2=watchOS, 3=tvOS).
fn xcode_from_sdk(sdk: &str, os: u16) -> &'static str {
    let col = match os {
        x if x == MACOS || x == OSX || x == MACOSX => 0usize,
        x if x == IPHONEOS || x == IOS || x == IPADOS => 1,
        x if x == WATCHOS => 2,
        x if x == TVOS => 3,
        _ => return "",
    };
    // Table columns: [version, date, min_macos, macos_sdk, ios_sdk,
    // watchos_sdk, tvos_sdk, visionos_sdk] → sdk column index = 3+col.
    let want = norm_sdk(sdk);
    for r in mt::XCODE_VERSIONS {
        if norm_sdk(r[3 + col]) == want && !want.is_empty() {
            return r[0];
        }
    }
    ""
}

/// `getClangVersionFromSDK` / `getSwiftVersionFromSDK` — Xcode version →
/// toolchain table lookup (col 4 = clang, col 5 = swift).
fn toolchain_from_sdk(sdk: &str, os: u16, col: usize) -> &'static str {
    let xv = xcode_from_sdk(sdk, os);
    if xv.is_empty() {
        return "";
    }
    for r in mt::XCODE_TOOLCHAINS {
        if r[0] == xv {
            return r[col];
        }
    }
    ""
}

/// `XMACH::_getArch` — CPU-type table (the ARM/MC680x0 subtype
/// refinements are not needed by any current caller).
fn mach_arch(cputype: u32, _cpusubtype: u32) -> &'static str {
    match cputype {
        1 => "VAX",
        2 => "ROMP",
        4 => "NS32032",
        5 => "NS32332",
        6 => "MC680x0",
        7 => "I386",
        0x0100_0007 => "X86_64",
        8 => "MIPS",
        9 => "NS32532",
        0xB => "HPPA",
        0xC => "ARM",
        0x0100_000C => "ARM64",
        0x0200_000C => "ARM64_32",
        0xD => "MC88000",
        0xE => "SPARC",
        0xF => "I860",
        0x10 => "I860_LITTLE",
        0x11 => "RS6000",
        0x12 => "POWERPC",
        0x0100_0012 => "POWERPC64",
        255 => "VEO",
        _ => "Unknown",
    }
}

/// `XMACH::typeIdToString(XMACH::getType)` — `MH_*` file type names.
fn mach_type(filetype: u32) -> &'static str {
    match filetype {
        1 => "OBJECT",
        2 => "EXECUTE",
        3 => "FVMLIB",
        4 => "CORE",
        5 => "PRELOAD",
        6 => "DYLIB",
        7 => "DYLINKER",
        8 => "BUNDLE",
        9 => "DYLIB_STUB",
        10 => "DSYM",
        11 => "KEXT_BUNDLE",
        12 => "FILESET",
        0xD..=0xF => "Unknown",
        _ => "Unknown",
    }
}

/// Full `NFD_MACH::getInfo` semantic path (fat binaries are sniffed
/// FT_MACHOFAT upstream and have no dedicated handler).
pub fn mach_semantic_scan(data: &[u8], ft: u16, misc: &mut ResultMaps) {
    let Some(e) = mach_info(data) else {
        return;
    };
    let big = e.big;

    // OS record emitted first (before Foundation exact-name fixup).
    // `getOperationSystemScansStruct` info: "<arch>, <mode>, <type>".
    let (os, osver) = mach_os(data, &e, big);
    let info = format!(
        "{}, {}, {}",
        mach_arch(e.cputype, e.cpusubtype),
        if e.is64 { "64-bit" } else { "32-bit" },
        mach_type(e.filetype),
    );
    emit(misc, ft, rt::RECORD_TYPE_OPERATIONSYSTEM, os, &osver, &info);

    // recordSDK/recordXcode/recordGCC/recordCLANG/recordSwift state.
    let mut sdk_name: u16 = n::RECORD_NAME_UNKNOWN;
    let mut sdk_ver = String::new();
    let mut gcc: Option<u16> = None;
    let mut clang: Option<u16> = None;
    let mut clang_ver = String::new();
    let mut swift: Option<u16> = None;
    let mut swift_ver = String::new();
    let mut objc_info = false;

    if cmd_present(&e, 0x1D) {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_SIGNTOOL,
            n::RECORD_NAME_CODESIGN,
            "",
            "",
        );
    }

    // Foundation library + SDK version.
    if lib_present(&e, "Foundation") {
        let v = lib_version(&e, "Foundation");
        let mut os2 = os;
        if matches!(os, MACOSX | OSX | MACOS) {
            sdk_name = n::RECORD_NAME_MACOSSDK;
            sdk_ver = sdk_from_foundation(v, os);
            if !sdk_ver.is_empty() {
                os2 = exact_os(os, &sdk_ver);
            }
        } else if matches!(os, IPHONEOS | IOS | IPADOS) {
            sdk_name = n::RECORD_NAME_IOSSDK;
            sdk_ver = sdk_from_foundation(v, os);
            if !sdk_ver.is_empty() {
                os2 = exact_os(os, &sdk_ver);
            }
        }
        let _ = os2; // upstream patches fileFormatInfo after the OS record
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_FOUNDATION,
            &full_ver(v),
            "",
        );
    }

    if lib_present(&e, "libgcc_s.1.dylib") {
        gcc = Some(n::RECORD_NAME_GCC);
    }
    if sec_present(&e, "__swift5_proto")
        || sec_present(&e, "__swift5_types")
        || sec_present(&e, "__swift2_proto")
        || lib_present(&e, "libswiftCore.dylib")
    {
        swift = Some(n::RECORD_NAME_SWIFT);
    }
    if sec_present(&e, "__objc_selrefs")
        || e.segments.iter().any(|s| s == "__OBJC")
        || lib_present(&e, "libobjc.A.dylib")
    {
        objc_info = true;
    }

    // LC_BUILD_VERSION / LC_VERSION_MIN_* → SDK name+version, tools.
    let mut tools: Vec<(u32, u32)> = Vec::new();
    if let Some(off) = cmd_offset(&e, 0x32) {
        if let (Some(platform), Some(sdk), Some(cmdsize), Some(ntools)) = (
            rd_u32_be_le(data, off + 8, big),
            rd_u32_be_le(data, off + 16, big),
            rd_u32_be_le(data, off + 4, big),
            rd_u32_be_le(data, off + 20, big),
        ) {
            sdk_name = match platform {
                1 => n::RECORD_NAME_MACOSSDK,
                5 => n::RECORD_NAME_BRIDGEOS,
                2 | 7 => n::RECORD_NAME_IOSSDK,
                3 | 8 => n::RECORD_NAME_TVOSSDK,
                4 | 9 => n::RECORD_NAME_WATCHOSSDK,
                _ => sdk_name,
            };
            if sdk != 0 {
                sdk_ver = full_ver(sdk);
            }
            // Tool entries start at off+24, 8 bytes each.
            let count = ((cmdsize as usize).saturating_sub(24) / 8)
                .min(ntools as usize)
                .min(64);
            for i in 0..count {
                if let (Some(tool), Some(ver)) = (
                    rd_u32_be_le(data, off + 24 + i * 8, big),
                    rd_u32_be_le(data, off + 28 + i * 8, big),
                ) {
                    tools.push((tool, ver));
                }
            }
        }
    } else {
        for (cmd, sdk_nm) in [
            (0x25u32, n::RECORD_NAME_IOSSDK),
            (0x24, n::RECORD_NAME_MACOSSDK),
            (0x2F, n::RECORD_NAME_TVOSSDK),
            (0x30, n::RECORD_NAME_WATCHOSSDK),
        ] {
            if let Some(off) = cmd_offset(&e, cmd) {
                sdk_name = sdk_nm;
                if let Some(sdk) = rd_u32_be_le(data, off + 12, big).filter(|v| *v != 0) {
                    sdk_ver = full_ver(sdk);
                }
                break;
            }
        }
    }

    // SDK → Xcode/clang/Swift inference.
    let mut xcode_ver = String::new();
    if sdk_name != n::RECORD_NAME_UNKNOWN && !sdk_ver.is_empty() {
        let xv = xcode_from_sdk(&sdk_ver, os);
        if !xv.is_empty() {
            xcode_ver = xv.to_string();
        }
        let cv = toolchain_from_sdk(&sdk_ver, os, 4);
        if !cv.is_empty() {
            clang = Some(n::RECORD_NAME_CLANG);
            clang_ver = cv.to_string();
        }
        let sv = toolchain_from_sdk(&sdk_ver, os, 5);
        if !sv.is_empty() {
            swift = Some(n::RECORD_NAME_SWIFT);
            swift_ver = sv.to_string();
        }
    }

    // Qt / Carbon / Cocoa libraries.
    if lib_present(&e, "QtCore") {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_QT,
            &full_ver(lib_version(&e, "QtCore")),
            "",
        );
    } else if sec_present(&e, ".qtmimedatabase") {
        emit(misc, ft, rt::RECORD_TYPE_LIBRARY, n::RECORD_NAME_QT, "", "");
    }
    if lib_present(&e, "Carbon") {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_CARBON,
            "",
            "",
        );
    }
    if lib_present(&e, "Cocoa") {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_COCOA,
            "",
            "",
        );
    }

    // Zig: ZIG_DEBUG_COLOR / ZIG_PROGRESS string inside __cstring.
    if let Some((_, off, size)) = e.sections.iter().find(|(nm, _, _)| nm == "__cstring") {
        let sz = (*size).min(1 << 20);
        let hit = parse::find_ansi(data, *off, sz, b"ZIG_DEBUG_COLOR").is_some()
            || parse::find_ansi(data, *off, sz, b"ZIG_PROGRESS").is_some();
        if hit {
            emit(
                misc,
                ft,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_ZIG,
                "",
                "",
            );
        }
    }

    // LC_BUILD_VERSION tools override SDK-derived versions.
    let mut ld_ver = String::new();
    for (tool, ver) in &tools {
        match *tool {
            2 => {
                swift = Some(n::RECORD_NAME_SWIFT);
                swift_ver = full_ver(*ver);
            }
            1 => {
                clang = Some(n::RECORD_NAME_CLANG);
                clang_ver = full_ver(*ver);
            }
            3 => {
                ld_ver = full_ver(*ver);
            }
            _ => {}
        }
    }
    if !ld_ver.is_empty() {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_LINKER,
            n::RECORD_NAME_XCODELINKER,
            &ld_ver,
            "",
        );
    }

    // Default: emit clang when neither gcc nor clang identified.
    if gcc.is_none() && clang.is_none() {
        clang = Some(n::RECORD_NAME_CLANG);
    }
    let info = if objc_info { "Objective-C" } else { "" };
    if let Some(nm) = gcc {
        emit(misc, ft, rt::RECORD_TYPE_COMPILER, nm, "", info);
    }
    if let Some(nm) = clang {
        emit(misc, ft, rt::RECORD_TYPE_COMPILER, nm, &clang_ver, info);
    }
    if let Some(nm) = swift {
        emit(misc, ft, rt::RECORD_TYPE_COMPILER, nm, &swift_ver, "");
    }
    if sdk_name != n::RECORD_NAME_UNKNOWN {
        emit(misc, ft, rt::RECORD_TYPE_TOOL, sdk_name, &sdk_ver, "");
    }
    if !xcode_ver.is_empty() {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_XCODE,
            &xcode_ver,
            "",
        );
    }

    // handle_Protection.
    if lib_present(&e, "libVMProtectSDK.dylib") {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_PROTECTOR,
            n::RECORD_NAME_VMPROTECT,
            "",
            "",
        );
    }

    // handle_FixDetects: upstream suppresses CCPP when OBJECTIVEC is
    // present; our merged map holds no LANGUAGE records (upstream
    // Mach-O never emits them either — the rule is a no-op upstream),
    // applied for structural parity.
    if misc.contains_key(&n::RECORD_NAME_OBJECTIVEC) || misc.contains_key(&n::RECORD_NAME_CCPP) {
        misc.remove(&n::RECORD_NAME_CCPP);
    }
}

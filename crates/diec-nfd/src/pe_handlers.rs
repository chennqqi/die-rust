//! PE semantic handlers — bounded port of `NFD_PE::handle_*` slices that
//! do not depend on the Rich-description table:
//! `handle_OperationSystem`, `handle_import`, `handle_DebugData`, and the
//! non-Rich portion of `handle_Microsoft` (MFC/VB/linker-version/
//! Visual-Studio version chain). Rich-derived linker/compiler version
//! enrichment remains deferred.

use crate::pe::{PeInfo, SectionExtent};
use crate::pe_tables::{MSVC_BUILD_VS, MSVC_LINKER_VS};
use crate::scans::{DetectMap, ScanRecord};
use crate::{gen_names::ft, gen_names::name as n, gen_names::rtype as rt};

fn emit(map: &mut DetectMap, ft_id: u16, rtype: u8, name: u16, ver: &str, info: &str) {
    map.entry(name).or_insert_with(|| ScanRecord {
        name,
        rtype,
        ft: ft_id,
        variant: 0,
        version: ver.to_string(),
        info: info.to_string(),
        heuristic: false,
        unknown: false,
    });
}

/// Case-insensitive import-library presence
/// (`XPE::isImportLibraryPresentI`).
fn has_lib(pe: &PeInfo, name: &str) -> bool {
    let want = name.to_ascii_uppercase();
    pe.import_headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case(name) || h.name.to_ascii_uppercase() == want)
}

/// `getNormalCodeSection`: among the first two sections prefer a
/// `CODE`/`.text` section with masked characteristics `0x60000020` and
/// non-zero raw size; otherwise section 0 when it has raw data.
pub fn normal_code_section(pe: &PeInfo) -> Option<&SectionExtent> {
    let it = pe.extents.iter().take(2).find(|s| {
        (s.name == "CODE" || s.name == ".text")
            && (s.flags & 0xFF00_00FF) == 0x6000_0020
            && s.size != 0
    });
    if let Some(s) = it {
        return Some(s);
    }
    pe.extents.first().filter(|s| s.size != 0)
}

/// `getNormalDataSection`: first section after index 0 named
/// `DATA`/`.data` with masked characteristics `0xC0000040`, not the
/// import section; otherwise the first later section with raw data that
/// is not code (`0x60000020`) or uninitialized (`0x40000040`).
pub fn normal_data_section(pe: &PeInfo) -> Option<&SectionExtent> {
    for (i, s) in pe.extents.iter().enumerate().skip(1) {
        // Raw-name compare upstream; our parser uppercases names.
        if (s.name.eq_ignore_ascii_case("DATA") || s.name.eq_ignore_ascii_case(".data"))
            && (s.flags & 0xFF00_00FF) == 0xC000_0040
            && s.size != 0
            && pe.import_section != i as i32
        {
            return Some(s);
        }
    }
    pe.extents.iter().enumerate().skip(1).find_map(|(i, s)| {
        if s.size != 0
            && pe.import_section != i as i32
            && s.flags != 0x6000_0020
            && s.flags != 0x4000_0040
        {
            Some(s)
        } else {
            None
        }
    })
}

/// `XPE::getArch` subset for `handle_OperationSystem` info strings.
fn arch_name(machine: u16) -> &'static str {
    // Machine after `_getMachine` normalization.
    let m = if machine == (0x7B79u16 ^ 0x8664) {
        0x8664
    } else {
        machine
    };
    match m {
        0x014C => "I386",
        0x8664 => "AMD64",
        0x01C0 => "ARM",
        0x01C4 => "ARMNT",
        0xAA64 => "ARM64",
        0x0200 => "IA64",
        0x0166 | 0x0168 | 0x0266 => "MIPS",
        0x01F0 => "POWERPC",
        0x5064 => "RISCV64",
        0x5032 => "RISCV32",
        _ => "Unknown",
    }
}

/// `XPE::getType`/`typeIdToString` subset used in the OS record info.
fn type_name(pe: &PeInfo) -> &'static str {
    let t = match pe.subsystem {
        1 | 8 => {
            if pe
                .import_headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("ntdll.dll"))
            {
                "Native"
            } else {
                "Driver"
            }
        }
        3 | 5 | 7 => "Console",
        2 => "GUI",
        9 => "CE GUI",
        14 => "XBOX Application",
        10 => "EFI Application",
        12 => "EFI Runtime driver",
        11 => "EFI Boot service driver",
        _ => "Application",
    };
    if t != "Driver" && pe.characteristics & 0x2000 != 0 {
        return "DLL";
    }
    t
}

/// `handle_OperationSystem` — `XPE::getFileFormatInfo` OS resolution:
/// subsystem → OS family, Linux native-override machine check, and the
/// Windows version table with the 64-bit >=5.02 floor.
pub fn operation_system(pe: &PeInfo, ftpe: u16, misc: &mut DetectMap) {
    let (os_name, show_ver) = match pe.subsystem {
        2 | 3 | 8 | 16 => (n::RECORD_NAME_WINDOWS, true),
        10..=13 => (n::RECORD_NAME_UNKNOWN, false), // UEFI
        14 | 17 => (n::RECORD_NAME_XBOX, false),
        5 => (n::RECORD_NAME_OS2, false),
        7 => (n::RECORD_NAME_POSIX, false),
        9 => (n::RECORD_NAME_WINDOWSCE, false),
        _ => (n::RECORD_NAME_WINDOWS, true),
    };
    let mut os_name = os_name;
    let mut show_ver = show_ver;
    if pe.machine == (0x7B79u16 ^ 0x8664) {
        os_name = n::RECORD_NAME_LINUX;
        show_ver = false;
    }
    let version = if !show_ver {
        String::new()
    } else {
        let mut v = pe.os_version;
        if pe.is64 && v < 0x0005_0002 {
            v = 0x0005_0002;
        }
        let s = match v {
            0x0003_000A => "NT 3.1",
            0x0003_0032 => "NT 3.5",
            0x0003_0033 => "NT 3.51",
            0x0004_0000 => "95",
            0x0004_0001 => "98",
            0x0004_0009 => "Millenium",
            0x0005_0000 => "2000",
            0x0005_0001 => "XP",
            0x0005_0002 => "Server 2003",
            0x0006_0000 => "Vista",
            0x0006_0001 => "7",
            0x0006_0002 => "8",
            0x0006_0003 => "8.1",
            0x000A_0000 => "10",
            _ => "",
        };
        if s.is_empty() {
            if pe.is64 {
                "Server 2003".to_string()
            } else {
                "XP".to_string()
            }
        } else {
            s.to_string()
        }
    };
    let mode = if pe.is64 { "64-bit" } else { "32-bit" };
    let info = format!("{}, {}, {}", arch_name(pe.machine), mode, type_name(pe));
    emit(
        misc,
        ftpe,
        rt::RECORD_TYPE_OPERATIONSYSTEM,
        os_name,
        &version,
        &info,
    );
}

/// `handle_import` — ordered-import pattern detections feeding
/// `mapImportDetects` (ZProtect, PESpin 1.0-1.2/1.3X, Alloy).
pub fn import_heuristics(pe: &PeInfo, ftpe: u16, imports: &mut DetectMap) {
    let ih = &pe.import_headers;
    let pos = |i: usize, j: usize| -> &str {
        ih.get(i)
            .and_then(|h| h.positions.get(j))
            .map(String::as_str)
            .unwrap_or("")
    };
    let lib_eq = |i: usize, n: &str| ih.get(i).is_some_and(|h| h.name.eq_ignore_ascii_case(n));
    let cnt = |i: usize| ih.get(i).map(|h| h.positions.len()).unwrap_or(0);
    let total = ih.len();

    let mut d_zprotect = false;
    let mut d_user_pina = false;
    let mut d_user_pin = false;
    let mut d_ctl_pina = false;
    let mut d_ctl_pin = false;
    let mut d_k32_pinx = false;
    let mut d_k32_pin = false;
    let mut d_alloy0 = false;
    let mut d_alloy2 = false;

    if total >= 1 {
        if lib_eq(0, "KERNEL32.DLL") {
            if cnt(0) == 2 && pos(0, 0) == "GetProcAddress" && pos(0, 1) == "LoadLibraryA" {
                d_zprotect = true;
            } else if cnt(0) == 13
                && pos(0, 0) == "LoadLibraryA"
                && pos(0, 1) == "GetProcAddress"
                && pos(0, 2) == "VirtualAlloc"
                && pos(0, 3) == "VirtualFree"
                && pos(0, 4) == "ExitProcess"
                && pos(0, 5) == "CreateFileA"
                && pos(0, 6) == "CloseHandle"
                && pos(0, 7) == "WriteFile"
                && pos(0, 8) == "GetSystemDirectoryA"
                && pos(0, 9) == "GetFileTime"
                && pos(0, 10) == "SetFileTime"
                && pos(0, 11) == "GetWindowsDirectoryA"
                && pos(0, 12) == "lstrcatA"
            {
                if total == 1 {
                    d_alloy0 = true;
                }
            } else if cnt(0) == 15
                && pos(0, 0) == "LoadLibraryA"
                && pos(0, 1) == "GetProcAddress"
                && pos(0, 2) == "VirtualAlloc"
                && pos(0, 3) == "VirtualFree"
                && pos(0, 4) == "ExitProcess"
                && pos(0, 5) == "CreateFileA"
                && pos(0, 6) == "CloseHandle"
                && pos(0, 7) == "WriteFile"
                && pos(0, 8) == "GetSystemDirectoryA"
                && pos(0, 9) == "GetFileTime"
                && pos(0, 10) == "SetFileTime"
                && pos(0, 11) == "GetWindowsDirectoryA"
                && pos(0, 14) == "GetTempPathA"
            {
                d_alloy2 = true;
            }
        } else if lib_eq(0, "USER32.DLL") && cnt(0) == 1 && pos(0, 0) == "MessageBoxA" {
            if total == 2 {
                d_user_pina = true;
            }
            if total == 3 {
                d_user_pin = true;
            }
        }
        // KERNEL32 ordinal-1 arm (`kernel32_yzpack_b`) has no downstream
        // record upstream — not replicated.
    }
    if total >= 2 && lib_eq(1, "COMCTL32.DLL") && cnt(1) == 1 && pos(1, 0) == "InitCommonControls" {
        if total == 2 {
            d_ctl_pina = true;
        }
        if total == 3 {
            d_ctl_pin = true;
        }
    }
    if total >= 3 && lib_eq(2, "KERNEL32.DLL") {
        if cnt(2) == 2 && pos(2, 0) == "LoadLibraryA" && pos(2, 1) == "GetProcAddress" && total == 3
        {
            d_k32_pinx = true;
        } else if cnt(2) == 4
            && pos(2, 0) == "LoadLibraryA"
            && pos(2, 1) == "GetProcAddress"
            && pos(2, 2) == "VirtualAlloc"
            && pos(2, 3) == "VirtualFree"
            && total == 3
        {
            d_k32_pin = true;
        }
    }

    let ft32 = if pe.is64 { ft::FT_PE64 } else { ft::FT_PE32 };
    if d_zprotect {
        emit(
            imports,
            ft32,
            rt::RECORD_TYPE_PROTECTOR,
            n::RECORD_NAME_ZPROTECT,
            "",
            "",
        );
    }
    if d_user_pina && d_ctl_pina {
        emit(
            imports,
            ftpe,
            rt::RECORD_TYPE_PROTECTOR,
            n::RECORD_NAME_PESPIN,
            "1.0-1.2",
            "",
        );
    }
    if d_user_pin && d_ctl_pin && d_k32_pin {
        emit(
            imports,
            ftpe,
            rt::RECORD_TYPE_PROTECTOR,
            n::RECORD_NAME_PESPIN,
            "",
            "",
        );
    }
    if d_user_pin && d_ctl_pin && d_k32_pinx {
        emit(
            imports,
            ftpe,
            rt::RECORD_TYPE_PROTECTOR,
            n::RECORD_NAME_PESPIN,
            "1.3X",
            "",
        );
    }
    if d_alloy0 || d_alloy2 {
        emit(
            imports,
            ft32,
            rt::RECORD_TYPE_PROTECTOR,
            n::RECORD_NAME_ALLOY,
            "4.X",
            "",
        );
    }
}

/// `handle_DebugData` — `.stab`/`.stabstr` → Stabs record; `.debug_info`
/// → DWARF version (u16 at +4, 0..=7 → "v.0").
pub fn debug_data(data: &[u8], pe: &PeInfo, ftpe: u16, misc: &mut DetectMap) {
    let names: Vec<&str> = pe.section_names.iter().map(String::as_str).collect();
    if names.contains(&".stab") && names.contains(&".stabstr") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_DEBUGDATA,
            n::RECORD_NAME_STABSDEBUGINFO,
            "",
            "",
        );
    }
    if let Some(dbg) = pe
        .extents
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(".debug_info"))
        && dbg.size > 8
        && let Some(v) = crate::parse::rd_u32(data, dbg.off + 4).map(|x| x as u16)
        && v <= 7
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_DEBUGDATA,
            n::RECORD_NAME_DWARFDEBUGINFO,
            &format!("{v}.0"),
            "",
        );
    }
}

/// Version map: linker/MFC major version → compiler major
/// (`mapVersions` in `handle_Microsoft`).
fn map_versions(major: &str) -> &'static str {
    match major {
        "1" => "8",
        "2" => "9",
        "4" => "10",
        "5" => "11",
        "6" => "12",
        "7" => "13",
        "8" => "14",
        "9" => "15",
        "10" => "16",
        "11" => "17",
        "12" => "18",
        "14" => "19",
        _ => "",
    }
}

/// The non-Rich subset of `handle_Microsoft`: MFC import/deep-scan
/// library detection, VB4/5/6 compiler + P-Code flag, linker version
/// fallback, compiler CPP version derivation, Visual Studio version
/// (build table then linker-major table), MASM32 combo and .NET
/// library/compiler records.
pub fn microsoft(
    data: &[u8],
    pe: &PeInfo,
    deep: bool,
    ftpe: u16,
    header: &DetectMap,
    entrypoint: &DetectMap,
    misc: &mut DetectMap,
) {
    // ssLinker initial state.
    let has_mslinker = header.contains_key(&n::RECORD_NAME_MICROSOFTLINKER);
    let has_generic = header.contains_key(&n::RECORD_NAME_GENERICLINKER);
    let mut linker: Option<(u16, String)> = None;
    let mut compiler_dot: Option<(u16, String)> = None;
    if has_mslinker && !has_generic {
        linker = Some((n::RECORD_NAME_MICROSOFTLINKER, String::new()));
    } else if has_generic && pe.is_dotnet {
        linker = Some((n::RECORD_NAME_MICROSOFTLINKER, String::new()));
        compiler_dot = Some((n::RECORD_NAME_VISUALCSHARP, String::new()));
    }

    // ssMFC: imports ^MFC → version = digits/10 ("%.2f"), U.DLL →
    // Unicode; deep scan: "CMFCComObject" in the data section → Static.
    let mut mfc: Option<(String, String)> = None;
    if deep && let Some(ds) = normal_data_section(pe) {
        let sz = ds.size.min(1 << 22);
        if crate::parse::find_ansi(data, ds.off, sz, b"CMFCComObject").is_some() {
            mfc = Some((String::new(), "Static".to_string()));
        }
    }
    for h in &pe.import_headers {
        let up = h.name.to_ascii_uppercase();
        if up.starts_with("MFC") {
            let digits: String = up
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(dv) = digits.parse::<f64>() {
                let dv = dv / 10.0;
                if dv != 0.0 {
                    let info = if up.contains("U.DLL") { "Unicode" } else { "" };
                    mfc = Some((format!("{dv:.2}"), info.to_string()));
                }
            }
            break;
        }
    }

    // VB compiler (non-.NET images only).
    let mut compiler_vb: Option<(u16, String, String)> = None;
    let mut net: Option<(String, String)> = None;
    if !pe.is_dotnet {
        let mut vb_new = false;
        let mut rec: Option<(u16, &'static str)> = None;
        if has_lib(pe, "VB40032.DLL") {
            rec = Some((n::RECORD_NAME_VISUALBASIC, "4.0"));
        } else if has_lib(pe, "MSVBVM50.DLL") {
            rec = Some((n::RECORD_NAME_VISUALBASIC, "5.0"));
            vb_new = true;
        }
        if has_lib(pe, "MSVBVM60.DLL") {
            rec = Some((n::RECORD_NAME_VISUALBASIC, "6.0"));
            vb_new = true;
        }
        let mut info = String::new();
        if vb_new
            && deep
            && let Some(cs) = normal_code_section(pe)
            && let Some(layout) = crate::pe::collect_layout(data)
        {
            // Options block signature: u32 0x21354256 / 0x21364256 in the
            // code section; flag read via RVA indirection (the u32 at
            // section+0x30 is an RVA; flag = u32 at that offset + 0x20).
            let sz = cs.size.min(1 << 22);
            let hit = find_u32_le(data, cs.off, sz, 0x2135_4256)
                .or_else(|| find_u32_le(data, cs.off, sz, 0x2136_4256));
            if hit.is_some()
                && let Some(rva) = crate::parse::rd_u32(data, cs.off + 0x30)
                && let Some(o) = crate::pe::rva_to_off_pub(&layout, rva)
                && let Some(v) = crate::parse::rd_u32(data, o + 0x20)
            {
                info = if v != 0 { "P-Code" } else { "Native" }.to_string();
            }
        }
        if let Some((nm, ver)) = rec {
            compiler_vb = Some((nm, ver.to_string(), info));
        }
    } else {
        net = Some((pe.dotnet_version.clone(), String::new()));
        compiler_dot.get_or_insert((n::RECORD_NAME_VISUALCSHARP, String::new()));
    }

    // Cross-derivations.
    let mut compiler_cpp: Option<(u16, String)> = if mfc.is_some() {
        Some((n::RECORD_NAME_VISUALCCPP, String::new()))
    } else {
        None
    };
    if let Some((ver, _)) = &mfc
        && let Some((_, cver)) = compiler_cpp.as_mut()
        && cver.is_empty()
    {
        let parts: Vec<&str> = ver.split('.').collect();
        let mv = map_versions(parts.first().copied().unwrap_or(""));
        // Upstream concatenates unconditionally — a missing map entry
        // yields a leading-dot version like ".20" (recorded quirk).
        *cver = format!("{}.{}", mv, parts.get(1).copied().unwrap_or(""));
    }
    if compiler_cpp.is_none()
        && let Some(ep) = entrypoint.get(&n::RECORD_NAME_VISUALCCPP)
    {
        compiler_cpp = Some((n::RECORD_NAME_VISUALCCPP, ep.version.clone()));
    }
    if let Some((ver, _)) = &mut mfc
        && ver.is_empty()
        && compiler_cpp.is_some()
        && let Some((_, lv)) = &linker
        && !lv.is_empty()
    {
        let sec: Vec<&str> = lv.split('.').collect();
        *ver = sec[..sec.len().min(2)].join(".");
    }
    if mfc.is_some() && !matches!(linker, Some((n::RECORD_NAME_MICROSOFTLINKER, _))) {
        linker = Some((n::RECORD_NAME_MICROSOFTLINKER, String::new()));
    }
    if matches!(compiler_cpp, Some((n::RECORD_NAME_VISUALCCPP, _)))
        && !matches!(linker, Some((n::RECORD_NAME_MICROSOFTLINKER, _)))
    {
        linker = Some((n::RECORD_NAME_MICROSOFTLINKER, String::new()));
    }
    if let Some((_, lv)) = &mut linker
        && lv.is_empty()
    {
        *lv = format!("{}.{:02}", pe.major_linker, pe.minor_linker);
    }
    if let Some((mver, _)) = &mfc
        && let Some((_, lv)) = &mut linker
        && lv.is_empty()
        && pe.minor_linker != 10
    {
        *lv = mver.clone();
    }
    if matches!(linker, Some((n::RECORD_NAME_MICROSOFTLINKER, _)))
        && matches!(compiler_cpp.as_ref(), Some((n::RECORD_NAME_VISUALCCPP, _)))
        && let Some((_, cv)) = &mut compiler_cpp
        && cv.is_empty()
        && let Some((_, lv)) = &linker
    {
        // Upstream keys mapVersions on `linker.section(".", 0, 1)` —
        // "major.minor" — not the bare major.
        let major2: String = lv.split('.').take(2).collect::<Vec<_>>().join(".");
        let mv = map_versions(&major2);
        if !mv.is_empty() {
            *cv = mv.to_string();
        }
    }

    // ssTool: Visual Studio — build-version table via the compiler's
    // 3rd version component, else linker major.minor table.
    let mut tool: Option<String> = None;
    if let Some((nm, cver)) = &compiler_cpp
        && *nm == n::RECORD_NAME_VISUALCCPP
    {
        let build: String = cver.split('.').nth(2).unwrap_or("").to_string();
        if let Ok(bn) = build.parse::<u32>()
            && let Some((_, v)) = MSVC_BUILD_VS.iter().find(|(b, _)| *b == bn)
        {
            tool = Some(v.to_string());
        }
        if tool.is_none()
            && let Some((_, lv)) = &linker
        {
            let lm: String = lv.split('.').take(2).collect::<Vec<_>>().join(".");
            if let Some((_, v)) = MSVC_LINKER_VS.iter().find(|(b, _)| *b == lm) {
                tool = Some(v.to_string());
            }
        }
    }

    // Emit (upstream order: linker → compilers → tool → MFC → NET).
    if let Some((nm, ver)) = linker {
        emit(misc, ftpe, rt::RECORD_TYPE_LINKER, nm, &ver, "");
    }
    if let Some((nm, ver)) = compiler_cpp {
        emit(misc, ftpe, rt::RECORD_TYPE_COMPILER, nm, &ver, "");
    }
    if let Some((nm, ver, info)) = compiler_vb {
        emit(misc, ftpe, rt::RECORD_TYPE_COMPILER, nm, &ver, &info);
    }
    if let Some((nm, ver)) = compiler_dot {
        emit(misc, ftpe, rt::RECORD_TYPE_COMPILER, nm, &ver, "");
    }
    if let Some(ver) = tool {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_MICROSOFTVISUALSTUDIO,
            &ver,
            "",
        );
    }
    if let Some((ver, info)) = mfc {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_MFC,
            &ver,
            &info,
        );
    }
    if let Some((ver, info)) = net {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_DOTNET,
            &ver,
            &info,
        );
    }
}

/// Find a little-endian u32 inside `[off, off+size)`.
fn find_u32_le(d: &[u8], off: usize, size: usize, val: u32) -> Option<usize> {
    let needle = val.to_le_bytes();
    let end = off.checked_add(size)?.min(d.len());
    d.get(off..end)?
        .windows(4)
        .position(|w| w == needle)
        .map(|i| off + i)
}

/// `getConstDataSection` — first `.rdata` section (index ≥1) with
/// masked characteristics `0x40000040` and non-zero raw size.
fn const_data_section(pe: &PeInfo) -> Option<&SectionExtent> {
    // Upstream compares the raw name against ".rdata"; our parser
    // uppercases names, so compare case-insensitively.
    pe.extents.iter().skip(1).find(|s| {
        s.name.eq_ignore_ascii_case(".rdata")
            && (s.flags & 0xFF00_00FF) == 0x4000_0040
            && s.size != 0
    })
}

/// First ANSI string at a section offset (`read_ansiString` at the
/// section base) — the `sDllLib` input of `handle_GCC`.
fn first_ansi(data: &[u8], off: usize) -> String {
    crate::parse::read_ansi_string(data, off).unwrap_or_default()
}

/// `get_GCC_vi1`: find "GCC:" inside `[off, off+size)` and parse the
/// version string (copied `SpecAbstract::_get_GCC_string` semantics).
fn gcc_vi1(data: &[u8], off: usize, size: usize) -> (String, String) {
    let Some(hit) = crate::parse::find_ansi(data, off, size, b"GCC:") else {
        return (String::new(), String::new());
    };
    let s = crate::parse::read_ansi_string(data, hit).unwrap_or_default();
    if !s.contains("GCC:") {
        return (String::new(), String::new());
    }
    let info = if s.contains("MinGW") {
        "MinGW"
    } else if s.contains("MSYS2") {
        "MSYS2"
    } else if s.contains("Cygwin") {
        "Cygwin"
    } else {
        ""
    };
    let words: Vec<&str> = s.split(' ').collect();
    let version = if s.contains("(experimental)") || s.contains("(prerelease)") {
        words
            .iter()
            .rev()
            .take(3)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    } else if let Some(i) = s.find("(GNU) c ") {
        s[i + 8..].split(' ').collect::<Vec<_>>().join(" ")
    } else if s.contains("GNU") {
        words.iter().skip(2).cloned().collect::<Vec<_>>().join(" ")
    } else if s.contains("Rev1, Built by MSYS2 project") {
        words
            .iter()
            .rev()
            .take(2)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    } else if s.contains("(Ubuntu ") {
        s.rsplit(") ")
            .next()
            .and_then(|t| t.split(' ').next())
            .unwrap_or("")
            .to_string()
    } else if s.contains("StartOS)") {
        s.rsplit(')')
            .next()
            .and_then(|t| t.split(' ').next())
            .unwrap_or("")
            .to_string()
    } else if let Some(i) = s.find("GCC: (c) ") {
        s[i + 9..].split(' ').next().unwrap_or("").to_string()
    } else {
        words.last().copied().unwrap_or("").to_string()
    };
    (version, info.to_string())
}

/// `get_GCC_vi2`: find "gcc-" and take `section("-",1,1).section("/",0,0)`.
fn gcc_vi2(data: &[u8], off: usize, size: usize) -> String {
    let Some(hit) = crate::parse::find_ansi(data, off, size, b"gcc-") else {
        return String::new();
    };
    let s = crate::parse::read_ansi_string(data, hit).unwrap_or_default();
    s.split('-')
        .nth(1)
        .and_then(|t| t.split('/').next())
        .unwrap_or("")
        .to_string()
}

/// `handle_GCC` — GCC/MinGW/MSYS/MSYS2/Cygwin chain: const-data "GCC:"
/// version string, Cygwin DLL version, `.stabstr` GCC path markers,
/// GNU linker version fill, MinGW linker-minor→GCC version table.
#[allow(clippy::too_many_arguments)]
pub fn gcc(
    data: &[u8],
    pe: &PeInfo,
    deep: bool,
    ftpe: u16,
    header: &DetectMap,
    overlay: &DetectMap,
    entrypoint: &DetectMap,
    misc: &mut DetectMap,
) {
    if pe.is_dotnet {
        return;
    }
    let has_generic = header.contains_key(&n::RECORD_NAME_GENERICLINKER);
    let mut heur = false;
    if has_generic && pe.major_linker == 2 {
        heur = matches!(pe.minor_linker, 22..=36 | 56);
    }

    // sDllLib — first ANSI string of the const-data section (deep scan).
    let cd = if deep { const_data_section(pe) } else { None };
    let dll_lib = cd.map(|s| first_ansi(data, s.off)).unwrap_or_default();

    let mut tool: Option<(u16, String)> = None;
    let mut compiler: Option<(u16, String)> = None;
    let mut linker: Option<(u16, String)> = None;

    if has_lib(pe, "msys-1.0.dll") || dll_lib.contains("msys-") {
        tool = Some((n::RECORD_NAME_MSYS, "1.0".to_string()));
    }

    let detect = dll_lib.contains("gcc")
        || dll_lib.contains("libgcj")
        || dll_lib.contains("cyggcj")
        || dll_lib == "_set_invalid_parameter_handler"
        || has_lib(pe, "libgcc_s_dw2-1.dll")
        || overlay.contains_key(&n::RECORD_NAME_MINGW)
        || entrypoint.contains_key(&n::RECORD_NAME_GCC);

    if detect || heur {
        if let Some(cs) = cd {
            let sz = cs.size.min(1 << 22);
            let (ver, info) = gcc_vi1(data, cs.off, sz);
            let mut cver = ver;
            if info == "MinGW" {
                tool = Some((n::RECORD_NAME_MINGW, String::new()));
            } else if info == "MSYS2" {
                tool = Some((n::RECORD_NAME_MSYS2, String::new()));
            } else if info == "Cygwin" {
                tool = Some((n::RECORD_NAME_CYGWIN, String::new()));
            }
            if cver.is_empty() {
                cver = gcc_vi2(data, cs.off, sz);
            }
            if cver.is_empty()
                && let Some(ds) = normal_data_section(pe)
            {
                cver = gcc_vi2(data, ds.off, ds.size.min(1 << 22));
            }
            if tool.is_none()
                && let Some(ep) = entrypoint.get(&n::RECORD_NAME_GCC)
                && ep.info.contains("MinGW")
            {
                tool = Some((n::RECORD_NAME_MINGW, String::new()));
            }
            if !cver.is_empty() {
                compiler = Some((n::RECORD_NAME_GCC, cver));
            }
            if !detect && let Some(cs2) = cd {
                let sz2 = cs2.size.min(1 << 22);
                if crate::parse::find_ansi(data, cs2.off, sz2, b"Mingw-w64 runtime failure:")
                    .is_some()
                {
                    tool = Some((n::RECORD_NAME_MINGW, String::new()));
                }
            }
        }
        if detect && compiler.is_none() {
            compiler = Some((n::RECORD_NAME_GCC, String::new()));
        }
        // Cygwin DLL version: import name ^CYGWIN → digits → "%.2f".
        for h in &pe.import_headers {
            let up = h.name.to_ascii_uppercase();
            if up.starts_with("CYGWIN") {
                let digits: String = up.chars().filter(|c| c.is_ascii_digit()).collect();
                if let Ok(dv) = digits.parse::<f64>()
                    && dv != 0.0
                {
                    tool = Some((n::RECORD_NAME_CYGWIN, format!("{dv:.2}")));
                }
                if tool.is_none() {
                    tool = Some((n::RECORD_NAME_CYGWIN, String::new()));
                }
            }
        }
        // .stabstr GCC path markers when no compiler identified yet.
        if compiler.is_none()
            && let Some(sr) = pe
                .extents
                .iter()
                .find(|s| s.name.eq_ignore_ascii_case(".stabstr"))
        {
            let sz = sr.size.min(1 << 22);
            if crate::parse::find_ansi(data, sr.off, sz, b"/gcc/mingw32/").is_some() {
                tool = Some((n::RECORD_NAME_MINGW, String::new()));
            } else if crate::parse::find_ansi(data, sr.off, sz, b"/gcc/i686-pc-cygwin/").is_some() {
                tool = Some((n::RECORD_NAME_CYGWIN, String::new()));
            }
        }
        if compiler.is_none()
            && matches!(
                tool.as_ref().map(|t| t.0),
                Some(n::RECORD_NAME_MINGW)
                    | Some(n::RECORD_NAME_MSYS)
                    | Some(n::RECORD_NAME_MSYS2)
                    | Some(n::RECORD_NAME_CYGWIN)
            )
        {
            compiler = Some((n::RECORD_NAME_GCC, String::new()));
        }
        if matches!(compiler, Some((n::RECORD_NAME_GCC, _))) && tool.is_none() {
            tool = Some((n::RECORD_NAME_MINGW, String::new()));
        }
        if matches!(compiler, Some((n::RECORD_NAME_GCC, _))) && has_generic {
            linker = Some((
                n::RECORD_NAME_GNULINKER,
                format!("{}.{}", pe.major_linker, pe.minor_linker),
            ));
        }
        if let Some((nm, ver)) = &mut tool
            && *nm == n::RECORD_NAME_MINGW
            && ver.is_empty()
            && pe.major_linker == 2
        {
            *ver = match pe.minor_linker {
                23 => "4.7.0-4.8.0",
                24 => "4.8.2-4.9.2",
                25 => "5.3.0",
                29 | 30 => "7.3.0",
                _ => "",
            }
            .to_string();
        }
    }

    if let Some((nm, ver)) = linker {
        emit(misc, ftpe, rt::RECORD_TYPE_LINKER, nm, &ver, "");
    }
    if let Some((nm, ver)) = compiler {
        emit(misc, ftpe, rt::RECORD_TYPE_COMPILER, nm, &ver, "");
    }
    if let Some((nm, ver)) = tool {
        emit(misc, ftpe, rt::RECORD_TYPE_TOOL, nm, &ver, "");
    }
}

/// `handle_Watcom` — WATCOMLINKER header detect + EP WATCOMCCPP +
/// `get_Watcom_vi` strings near the entry point ("Open Watcom"/"WATCOM"
/// with ` 2002-`/`. 1988-` version extraction).
pub fn watcom(
    data: &[u8],
    pe: &PeInfo,
    ftpe: u16,
    header: &DetectMap,
    entrypoint: &DetectMap,
    misc: &mut DetectMap,
) {
    let mut linker: Option<(String, String)> = None;
    let mut compiler: Option<(u16, String, String)> = None;

    if let Some(rec) = header.get(&n::RECORD_NAME_WATCOMLINKER) {
        linker = Some((
            String::new(),
            format!("{}.{:02}", pe.major_linker, pe.minor_linker),
        ));
        let _ = rec;
    }
    if let Some(rec) = entrypoint.get(&n::RECORD_NAME_WATCOMCCPP) {
        compiler = Some((
            n::RECORD_NAME_WATCOMCCPP,
            rec.version.clone(),
            rec.info.clone(),
        ));
    }

    // get_Watcom_vi over [EP, EP+0x100).
    if pe.entry_point_offset >= 0 {
        let off = pe.entry_point_offset as usize;
        let sz = 0x100usize;
        if let Some(hit) = crate::parse::find_ansi(data, off, sz, b"Open Watcom") {
            let _ = hit;
            let ver = crate::parse::find_ansi(data, off, sz, b" 2002-")
                .and_then(|o| crate::parse::read_ansi_string_len(data, o + 6, 4))
                .unwrap_or_else(|| "2002".to_string());
            compiler = Some((n::RECORD_NAME_OPENWATCOMCCPP, ver, String::new()));
        } else if crate::parse::find_ansi(data, off, sz, b"WATCOM").is_some() {
            let ver = crate::parse::find_ansi(data, off, sz, b". 1988-")
                .and_then(|o| crate::parse::read_ansi_string_len(data, o + 7, 4))
                .unwrap_or_else(|| "1988".to_string());
            compiler = Some((n::RECORD_NAME_WATCOMCCPP, ver, String::new()));
        }
    }
    if linker.is_some() && compiler.is_none() {
        compiler = Some((n::RECORD_NAME_WATCOMCCPP, String::new(), String::new()));
    }
    if linker.is_none() && compiler.is_some() {
        linker = Some((String::new(), String::new()));
    }

    if let Some((_, ver)) = linker {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_LINKER,
            n::RECORD_NAME_WATCOMLINKER,
            &ver,
            "",
        );
    }
    if let Some((nm, ver, info)) = compiler {
        emit(misc, ftpe, rt::RECORD_TYPE_COMPILER, nm, &ver, &info);
    }
}

/// `handle_Signtools` — security-directory first cert with
/// `wRevision=0x200`/`wCertificateType=2` → WINAUTH "2.0"/"PKCS #7".
pub fn signtools(data: &[u8], pe: &PeInfo, ftpe: u16, misc: &mut DetectMap) {
    if pe.cert_offset == 0 || pe.cert_size == 0 {
        return;
    }
    let off = pe.cert_offset;
    if off + 8 > data.len() {
        return;
    }
    // First WIN_CERTIFICATE: dwLength @0, wRevision @4, wCertType @6.
    let (Some(rev), Some(cty)) = (
        crate::parse::rd_u16(data, off + 4),
        crate::parse::rd_u16(data, off + 6),
    ) else {
        return;
    };
    if rev == 0x200 && cty == 2 {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_SIGNTOOL,
            n::RECORD_NAME_WINAUTH,
            "2.0",
            "PKCS #7",
        );
    }
}

/// `handle_DongleProtection` — single `NOVEX*` import → Guardian
/// Stealth dongle record (emitted via the SFX map upstream; we use misc).
pub fn dongle(pe: &PeInfo, ftpe: u16, misc: &mut DetectMap) {
    if pe.import_headers.len() == 1
        && pe.import_headers[0]
            .name
            .to_ascii_uppercase()
            .starts_with("NOVEX")
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_DONGLEPROTECTION,
            n::RECORD_NAME_GUARDIANSTEALTH,
            "",
            "",
        );
    }
}

/// `handle_NeoLite` — EP section contains "NeoLite Executable File
/// Compressor" (deep scan, EP not in section 0).
pub fn neolite(data: &[u8], pe: &PeInfo, deep: bool, ftpe: u16, misc: &mut DetectMap) {
    if pe.is_dotnet || pe.entrypoint_section_index() == 0 || !deep {
        return;
    }
    if let Some((off, size)) = pe.entrypoint_section_extent(data) {
        let sz = size.min(1 << 22);
        if crate::parse::find_ansi(data, off, sz, b"NeoLite Executable File Compressor").is_some() {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_PACKER,
                n::RECORD_NAME_NEOLITE,
                "1.0",
                "",
            );
        }
    }
}

/// `handle_PETools` — section-name detects VMUNPACKER/XVOLKOLAK/HOODLUM
/// are re-emitted as PETools records.
pub fn petools(section_names: &DetectMap, ftpe: u16, misc: &mut DetectMap) {
    for nm in [
        n::RECORD_NAME_VMUNPACKER,
        n::RECORD_NAME_XVOLKOLAK,
        n::RECORD_NAME_HOODLUM,
    ] {
        if let Some(rec) = section_names.get(&nm) {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_PETOOL,
                nm,
                &rec.version,
                &rec.info,
            );
        }
    }
}

/// `handle_Joiners` — BladeJoiner/ExeJoiner (import+EP detects + overlay
/// present), Celesty File Binder and NJoiner (import detect + named
/// resources).
#[allow(clippy::too_many_arguments)]
pub fn joiners(
    data: &[u8],
    pe: &PeInfo,
    ftpe: u16,
    imports: &DetectMap,
    entrypoint: &DetectMap,
    misc: &mut DetectMap,
) {
    let overlay_size = if pe.overlay_offset >= 0 {
        data.len().saturating_sub(pe.overlay_offset as usize)
    } else {
        0
    };
    for nm in [n::RECORD_NAME_BLADEJOINER, n::RECORD_NAME_EXEJOINER] {
        if imports.contains_key(&nm)
            && entrypoint.contains_key(&nm)
            && overlay_size != 0
            && let Some(rec) = entrypoint.get(&nm)
        {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_JOINER,
                nm,
                &rec.version,
                &rec.info,
            );
        }
    }
    let res = crate::pe::collect_resources(data);
    let has_res = |name: &str| res.iter().any(|r| r.name2.as_deref() == Some(name));
    if imports.contains_key(&n::RECORD_NAME_CELESTYFILEBINDER)
        && has_res("RBIND")
        && let Some(rec) = imports.get(&n::RECORD_NAME_CELESTYFILEBINDER)
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_JOINER,
            n::RECORD_NAME_CELESTYFILEBINDER,
            &rec.version,
            &rec.info,
        );
    }
    if imports.contains_key(&n::RECORD_NAME_NJOINER)
        && (has_res("NJ") || has_res("NJOY"))
        && let Some(rec) = imports.get(&n::RECORD_NAME_NJOINER)
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_JOINER,
            n::RECORD_NAME_NJOINER,
            &rec.version,
            &rec.info,
        );
    }
}

/// `get_TurboLinker_vi`: byte@0x1E == 0xFB → version = byte@0x1F/16.0
/// formatted "%.1f" (Turbo Linker version stored in the MZ header).
fn turbo_linker_vi(data: &[u8]) -> Option<String> {
    if !data.is_empty() && *data.get(0x1E)? == 0xFB {
        let v = *data.get(0x1F)? as f64 / 16.0;
        Some(format!("{v:.1}"))
    } else {
        None
    }
}

/// `getVCLstruct`: scan `[off, off+size)` for `\x07\x08"TControl"`;
/// the dword at +10 is a VA pointer — resolve via `va_to_off`, then walk
/// back ≤20 `addr_size` slots for the first value ≤0xFFFF. Returns
/// `(nOffset, nValue)` of each hit.
fn vcl_structs(data: &[u8], pe: &PeInfo, off: usize, size: usize, is64: bool) -> Vec<(u32, u32)> {
    let pat: &[u8] = b"\x07\x08TControl";
    let addr_size: u32 = if is64 { 8 } else { 4 };
    let mut out = Vec::new();
    let mut cur = off;
    let mut rem = size;
    while rem > pat.len() && out.len() < 64 {
        let Some(hit) = crate::parse::find_ansi(data, cur, rem, pat) else {
            break;
        };
        // `find_array` is a raw byte scan; find_ansi suffices (pattern
        // contains no NUL terminators semantics).
        if let Some(dw) = crate::parse::rd_u32(data, hit + 10)
            && let Some(co2) = pe.va_to_off(dw)
        {
            for i in 0..20u32 {
                let back = addr_size * (i + 1);
                let Some(v) = co2
                    .checked_sub(back as usize)
                    .and_then(|o| crate::parse::rd_u32(data, o))
                else {
                    break;
                };
                if v <= 0xFFFF {
                    out.push((back, v));
                    break;
                }
            }
        }
        let delta = (hit - cur) + 1;
        cur += delta;
        rem = rem.saturating_sub(delta);
    }
    out
}

/// `getVCLPackageInfo` subset: PACKAGEINFO resource (type 10) →
/// `(flags, modules_count)`; used only for the producer-bit override
/// (`(flags >> 26) & 3`: 2=C++, 3=Pascal) gated on `modules > 0`.
fn vcl_package_info(data: &[u8], res: &[crate::scans::ResourceEntry]) -> (u32, usize) {
    let Some(pkg) = res
        .iter()
        .find(|r| r.id1 == 10 && r.name2.as_deref() == Some("PACKAGEINFO") && r.data_size != 0)
    else {
        return (0, 0);
    };
    let mut off = pkg.data_off;
    let Some(flags) = crate::parse::rd_u32(data, off) else {
        return (0, 0);
    };
    if flags & 0xFF00 != 0 {
        return (0, 0);
    }
    off += 4;
    let Some(unknown) = crate::parse::rd_u32(data, off) else {
        return (flags, 0);
    };
    let mut count = 0usize;
    let mut requires = 0u32;
    if unknown == 0 {
        off += 4;
        requires = crate::parse::rd_u32(data, off).unwrap_or(0);
        off += 4;
    } else {
        off += 3;
    }
    let limit = if requires != 0 {
        requires as usize
    } else {
        1000
    };
    for _ in 0..limit.min(4096) {
        if off.saturating_sub(pkg.data_off) > pkg.data_size {
            break;
        }
        let Some(flags8) = data.get(off) else { break };
        let _ = flags8;
        off += 2; // module flags + hashcode
        let Some(name) = crate::parse::read_ansi_string(data, off) else {
            break;
        };
        off += name.len() + 1;
        count += 1;
    }
    (flags, count)
}

/// `_get_DelphiVersionFromCompiler`: first word → Delphi release name;
/// any non-empty unknown value maps to "12.x Athens++" (upstream default).
fn delphi_version_from_compiler(s: &str) -> Option<&'static str> {
    let word = s.split(' ').next().unwrap_or("");
    if word.is_empty() {
        return None;
    }
    Some(match word {
        "28.0" => "XE7",
        "29.0" => "XE8",
        "30.0" => "10 Seattle",
        "31.0" => "10.1 Berlin",
        "32.0" => "10.2 Tokyo",
        "33.0" => "10.3 Rio",
        "34.0" => "10.4 Sydney",
        "35.0" => "11.0 Alexandria",
        "36.0" => "12.0 Athens",
        _ => "12.x Athens++",
    })
}

/// `handle_Borland` — Turbo Linker header vi, Delphi/C++Builder
/// detection via `.text` Pascal-metadata arrays (`TObject`/`Boolean`/
/// `string`/`String`), VCL TControl back-pointer fingerprint,
/// PACKAGEINFO producer override, C++ copyright strings in the data
/// section, `__CPPdebugHook` exports, PACKAGEINFO/DVCLAL resources and
/// EP BORLANDCPP records.
#[allow(clippy::too_many_arguments)]
pub fn borland(
    data: &[u8],
    pe: &PeInfo,
    deep: bool,
    ftpe: u16,
    header: &DetectMap,
    entrypoint: &DetectMap,
    dot_ansi: &DetectMap,
    misc: &mut DetectMap,
) {
    #[derive(Clone, Copy, PartialEq)]
    enum Company {
        Borland,
        Codegear,
        Embarcadero,
    }

    let mut linker: Option<(u16, String)> = None;
    let mut compiler: Option<(u16, String)> = None;
    let mut tool: Option<(u16, String)> = None;
    let mut vcl: Option<(u16, String)> = None;

    if let Some(rec) = header.get(&n::RECORD_NAME_TURBOLINKER) {
        let ver = turbo_linker_vi(data)
            .unwrap_or_else(|| format!("{}.{:02}", pe.major_linker, pe.minor_linker));
        linker = Some((rec.name, ver));
    }

    if !pe.is_dotnet {
        let (mut t_object, mut string_l, mut string_u) = (false, false, false);
        let (mut borland_cpp, mut codegear_cpp, mut emb_old, mut emb_new) =
            (false, false, false, false);
        let mut vcl_list: Vec<(u32, u32)> = Vec::new();

        let cpp_export = pe
            .export_names
            .iter()
            .any(|s| s == "__CPPdebugHook" || s == "___CPPdebugHook");

        if deep && let Some((off, size)) = pe.code_section_extent(data) {
            let sz = size.min(1 << 22);
            t_object = crate::parse::find_ansi(data, off, sz, b"\x07TObject").is_some();
            if t_object {
                let boolean_s = crate::parse::find_ansi(data, off, sz, b"\x07Boolean").is_some();
                string_l = crate::parse::find_ansi(data, off, sz, b"\x06string").is_some();
                if boolean_s || string_l {
                    if !string_l {
                        string_u = crate::parse::find_ansi(data, off, sz, b"\x06String").is_some();
                    }
                    vcl_list = vcl_structs(data, pe, off, sz, pe.is64);
                }
            }
        }
        if deep && let Some(ds) = normal_data_section(pe) {
            let (off, sz) = (ds.off, ds.size.min(1 << 22));
            borland_cpp =
                crate::parse::find_ansi(data, off, sz, b"Borland C++ - Copyright ").is_some();
            if !borland_cpp {
                codegear_cpp =
                    crate::parse::find_ansi(data, off, sz, b"CodeGear C++ - Copyright ").is_some();
                if !codegear_cpp {
                    emb_old = crate::parse::find_ansi(
                        data,
                        off,
                        sz,
                        b"Embarcadero RAD Studio - Copyright ",
                    )
                    .is_some();
                    if !emb_old {
                        emb_new = crate::parse::find_ansi(
                            data,
                            off,
                            sz,
                            b"Embarcadero RAD Studio 27.0 - Copyright 2020 Embarcadero Technologies, Inc.",
                        )
                        .is_some();
                    }
                }
            }
        }

        let res = crate::pe::collect_resources(data);
        let pkg = res
            .iter()
            .any(|r| r.id1 == 10 && r.name2.as_deref() == Some("PACKAGEINFO"));
        let dvcal = res
            .iter()
            .any(|r| r.id1 == 10 && r.name2.as_deref() == Some("DVCLAL"));
        let ep_bcpp = entrypoint.contains_key(&n::RECORD_NAME_BORLANDCPP);

        if pkg
            || dvcal
            || ep_bcpp
            || t_object
            || borland_cpp
            || codegear_cpp
            || emb_old
            || emb_new
            || cpp_export
        {
            let mut cpp = false;
            let mut vcl_b = pkg;
            let mut delphi_ver = String::new();

            let mut objpas_ver = String::new();
            let mut cpp_ver = String::new();
            let mut new_version = false;
            let mut company = Company::Borland;

            if ep_bcpp || borland_cpp || codegear_cpp || emb_old || emb_new || cpp_export {
                cpp = true;
                company = if borland_cpp {
                    Company::Borland
                } else if codegear_cpp {
                    Company::Codegear
                } else {
                    Company::Embarcadero
                };
            }
            if t_object {
                if string_l {
                    if dvcal || pkg {
                        delphi_ver = "2005+".to_string();
                        new_version = true;
                    } else {
                        delphi_ver = "2".to_string();
                        objpas_ver = "9.0".to_string();
                    }
                } else if string_u {
                    company = Company::Borland;
                    delphi_ver = "3-7".to_string();
                }
            }
            if pkg {
                let (flags, modules) = vcl_package_info(data, &res);
                if modules > 0 {
                    match (flags >> 26) & 0x3 {
                        2 => cpp = true,
                        3 => cpp = false,
                        _ => {}
                    }
                }
            }
            // Copyright-string version reads (fixed tail offsets).
            if borland_cpp {
                if let Some(ds) = normal_data_section(pe)
                    && let Some(h) = crate::parse::find_ansi(
                        data,
                        ds.off,
                        ds.size.min(1 << 22),
                        b"Borland C++ - Copyright ",
                    )
                {
                    cpp_ver =
                        crate::parse::read_ansi_string_len(data, h + 24, 4).unwrap_or_default();
                }
            } else if codegear_cpp {
                if let Some(ds) = normal_data_section(pe)
                    && let Some(h) = crate::parse::find_ansi(
                        data,
                        ds.off,
                        ds.size.min(1 << 22),
                        b"CodeGear C++ - Copyright ",
                    )
                {
                    cpp_ver =
                        crate::parse::read_ansi_string_len(data, h + 25, 4).unwrap_or_default();
                }
            } else if emb_old {
                if let Some(ds) = normal_data_section(pe)
                    && let Some(h) = crate::parse::find_ansi(
                        data,
                        ds.off,
                        ds.size.min(1 << 22),
                        b"Embarcadero RAD Studio - Copyright ",
                    )
                {
                    cpp_ver =
                        crate::parse::read_ansi_string_len(data, h + 35, 4).unwrap_or_default();
                }
            } else if emb_new
                && let Some(ds) = normal_data_section(pe)
                && let Some(h) = crate::parse::find_ansi(
                    data,
                    ds.off,
                    ds.size.min(1 << 22),
                    b"Embarcadero RAD Studio 27.0 - Copyright 2020 Embarcadero Technologies, Inc.",
                )
            {
                cpp_ver = crate::parse::read_ansi_string_len(data, h + 40, 4).unwrap_or_default();
            }
            let builder_ver: String = match cpp_ver.as_str() {
                "2009" => "2009",
                "2015" => "2015",
                "2020" => "10.4",
                _ => "",
            }
            .to_string();

            if let Some(&(n_off, n_val)) = vcl_list.first() {
                vcl_b = true;
                for (o, v, comp, dv, ov, nv) in [
                    (24u32, 168u32, Company::Borland, "2", "9.0", false),
                    (28, 180, Company::Borland, "3", "10.0", false),
                    (40, 276, Company::Borland, "4", "12.0", false),
                    (40, 288, Company::Borland, "5", "13.0", false),
                    (40, 296, Company::Borland, "6 CLX", "14.0", false),
                    (40, 300, Company::Borland, "7 CLX", "15.0", false),
                    (40, 348, Company::Borland, "6-7", "14.0-15.0", false),
                    (40, 356, Company::Borland, "2005", "17.0", false),
                    (40, 400, Company::Borland, "2006", "18.0", false),
                    (52, 420, Company::Embarcadero, "2009", "20.0", false),
                    (52, 428, Company::Embarcadero, "2010-XE", "21.0-22.0", false),
                    (52, 436, Company::Embarcadero, "XE2-XE4", "23.0-25.0", true),
                    (52, 444, Company::Embarcadero, "XE2-XE8", "23.0-29.0", true),
                    (104, 760, Company::Embarcadero, "XE2", "23.0", true),
                    (
                        128,
                        776,
                        Company::Embarcadero,
                        "XE8-10 Seattle",
                        "30.0",
                        true,
                    ),
                ] {
                    if n_off == o && n_val == v {
                        company = comp;
                        delphi_ver = dv.to_string();
                        objpas_ver = ov.to_string();
                        new_version = nv;
                        break;
                    }
                }
            }
            if new_version
                && deep
                && let Some(cs) = const_data_section(pe)
            {
                let sz = cs.size.min(1 << 22);
                let needle: &[u8] = if pe.is64 {
                    b"Embarcadero Delphi for Win64 compiler version "
                } else {
                    b"Embarcadero Delphi for Win32 compiler version "
                };
                if let Some(h) = crate::parse::find_ansi(data, cs.off, sz, needle) {
                    company = Company::Embarcadero;
                    objpas_ver = crate::parse::read_ansi_string(data, h + 46).unwrap_or_default();
                    delphi_ver = delphi_version_from_compiler(&objpas_ver)
                        .unwrap_or("")
                        .to_string();
                }
            }

            // Record selection.
            if !cpp {
                let (cn, tn) = match company {
                    Company::Borland => (
                        n::RECORD_NAME_BORLANDOBJECTPASCALDELPHI,
                        n::RECORD_NAME_BORLANDDELPHI,
                    ),
                    Company::Codegear => (
                        n::RECORD_NAME_CODEGEAROBJECTPASCALDELPHI,
                        n::RECORD_NAME_CODEGEARDELPHI,
                    ),
                    Company::Embarcadero => (
                        n::RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI,
                        n::RECORD_NAME_EMBARCADERODELPHI,
                    ),
                };
                compiler = Some((cn, objpas_ver));
                tool = Some((tn, delphi_ver));
            } else {
                let (cn, tn) = match company {
                    Company::Borland => {
                        (n::RECORD_NAME_BORLANDCPP, n::RECORD_NAME_BORLANDCPPBUILDER)
                    }
                    Company::Codegear => (
                        n::RECORD_NAME_CODEGEARCPP,
                        n::RECORD_NAME_CODEGEARCPPBUILDER,
                    ),
                    Company::Embarcadero => (
                        n::RECORD_NAME_EMBARCADEROCPP,
                        n::RECORD_NAME_EMBARCADEROCPPBUILDER,
                    ),
                };
                compiler = Some((cn, cpp_ver));
                tool = Some((tn, builder_ver));
            }
            if vcl_b {
                // Upstream quirk: sVCLVersion assignments are all
                // commented out — VCL records carry an empty version.
                vcl = Some((n::RECORD_NAME_VCL, String::new()));
            }
            if linker.is_none() {
                linker = Some((n::RECORD_NAME_TURBOLINKER, String::new()));
            }
        }
    } else {
        // Delphi.NET: dotAnsi heap hits (Borland.Studio.Delphi →
        // "XE*", Borland.Vcl.Types → "8") promote to the tool record.
        if let Some(r) = dot_ansi.get(&n::RECORD_NAME_EMBARCADERODELPHIDOTNET) {
            tool = Some((r.name, r.version.clone()));
        }
    }

    if let Some((nm, ver)) = linker {
        emit(misc, ftpe, rt::RECORD_TYPE_LINKER, nm, &ver, "");
    }
    if let Some((nm, ver)) = compiler {
        emit(misc, ftpe, rt::RECORD_TYPE_COMPILER, nm, &ver, "");
    }
    if let Some((nm, ver)) = vcl {
        emit(misc, ftpe, rt::RECORD_TYPE_LIBRARY, nm, &ver, "");
    }
    if let Some((nm, ver)) = tool {
        emit(misc, ftpe, rt::RECORD_TYPE_TOOL, nm, &ver, "");
    }
}

/// UTF-16LE substring search (`find_unicodeString` with bIsBigEndian=0).
fn find_utf16le(data: &[u8], off: usize, size: usize, needle: &str) -> Option<usize> {
    let mut pat = Vec::with_capacity(needle.len() * 2);
    for c in needle.encode_utf16() {
        pat.extend(c.to_le_bytes());
    }
    crate::parse::find_ansi(data, off, size, &pat)
}

/// `XBinary::getVersionString`: trim a string to its version-shaped
/// prefix (`[\d.]`-ish words, e.g. "1.20.5 windows/amd64" → "1.20.5").
fn version_string(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() || c == '.' {
            out.push(c);
        } else if !out.is_empty() {
            break;
        }
    }
    while out.ends_with('.') {
        out.pop();
    }
    out
}

/// `XBinary::getVersionIntValue` — pack a dotted version for ordering.
fn version_value(s: &str) -> u64 {
    let mut v = 0u64;
    for (i, p) in s.split('.').take(4).enumerate() {
        let n: u64 = p.parse().unwrap_or(0).min(0xFFFF);
        v |= n << (48 - i * 16);
    }
    v
}

/// `get_Go_vi`: scan for "go1." strings, keep the max `go1.x[.y]`.
fn go_vi(data: &[u8], off: usize, size: usize) -> Option<(String, String)> {
    let mut cur = off;
    let mut rem = size;
    let mut best = (0u64, String::new());
    while rem > 4 {
        let Some(hit) = crate::parse::find_ansi(data, cur, rem, b"go1.") else {
            break;
        };
        let s = crate::parse::read_ansi_string_len(data, hit + 2, 10).unwrap_or_default();
        let ver = version_string(&s);
        let val = version_value(&ver);
        if val > best.0 {
            best = (val, ver);
        }
        let delta = (hit - cur) + 1;
        cur += delta;
        rem = rem.saturating_sub(delta);
    }
    if best.0 == 0 {
        None
    } else {
        Some((best.1, String::new()))
    }
}

/// `handle_Tools` — tool/compiler/library heuristics that do not fit
/// other buckets: Rust/Go/Zig/Nim compilers, AutoIt, TinyC section
/// shape, Crashpad/ExcelsiorJET/Qt/FPC/Lazarus/Python/Perl/FlexLM and
/// linker-detect→record chains (FASM, GoLink, UNILINK, DMD32, …).
///
/// Deferred upstream sub-branches: version-resource lookups
/// (`getResourcesVersionValue`/`getFileVersionMS` for AutoIt 2.XX) and
/// `mapDotAnsiStringsDetects`-gated paths.
#[allow(clippy::too_many_arguments)]
pub fn tools(
    data: &[u8],
    pe: &PeInfo,
    deep: bool,
    ftpe: u16,
    header: &DetectMap,
    overlay: &DetectMap,
    entrypoint: &DetectMap,
    section_names: &DetectMap,
    code_section: &DetectMap,
    misc: &mut DetectMap,
) {
    let _ = overlay;
    let cd = if deep { const_data_section(pe) } else { None };
    let cd_rng = cd.map(|s| (s.off, s.size.min(1 << 22)));

    // Rust: TLS dir + EP RUST record + "Local\RustBacktraceMutex".
    if pe.tls_present
        && let Some(rec) = entrypoint.get(&n::RECORD_NAME_RUST)
        && let Some((off, sz)) = cd_rng
        && crate::parse::find_ansi(data, off, sz, b"Local\\RustBacktraceMutex").is_some()
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_RUST,
            "",
            &rec.info,
        );
    }

    // AutoIt 3.x: RT_RCDATA "SCRIPT" resource.
    let res = crate::pe::collect_resources(data);
    let has_rcdata = |nm: &str| {
        res.iter()
            .any(|r| r.id1 == 10 && r.name2.as_deref() == Some(nm))
    };
    if has_rcdata("SCRIPT") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_AUTOIT,
            "3.XX",
            "",
        );
    }
    // (AutoIt 2.XX FileDescription/version-resource branch deferred.)

    // TinyC: msvcrt.dll import + linker 6.0 + exact section shapes.
    if has_lib(pe, "msvcrt.dll") && pe.major_linker == 6 && pe.minor_linker == 0 {
        let names: Vec<&str> = pe.extents.iter().map(|s| s.name.as_str()).collect();
        let nsec = names.len();
        let (mut detected, mut debug) = (false, false);
        if pe.is64 {
            if (nsec == 3 || nsec == 5)
                && names.first() == Some(&".TEXT")
                && names.get(1) == Some(&".DATA")
                && names.get(2) == Some(&".PDATA")
            {
                if nsec == 3 {
                    detected = true;
                } else if names.get(3) == Some(&".STAB") && names.get(4) == Some(&".STABSTR") {
                    debug = true;
                    detected = true;
                }
            }
        } else if (nsec == 2 || nsec == 4)
            && names.first() == Some(&".TEXT")
            && names.get(1) == Some(&".DATA")
        {
            if nsec == 2 {
                detected = true;
            } else if names.get(2) == Some(&".STAB") && names.get(3) == Some(&".STABSTR") {
                debug = true;
                detected = true;
            }
        }
        if detected {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_TINYC,
                "",
                if debug { "debug" } else { "" },
            );
        }
    }

    // Chromium Crashpad: CPADinfo section, signature 0x43506164.
    if section_names.contains_key(&n::RECORD_NAME_CHROMIUMCRASHPAD)
        && let Some(sec) = pe
            .extents
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("CPADinfo"))
        && crate::parse::rd_u32(data, sec.off) == Some(0x4350_6164)
    {
        let v = crate::parse::rd_u32(data, sec.off + 8).unwrap_or(0);
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_CHROMIUMCRASHPAD,
            &format!("{v}.0"),
            "",
        );
    }

    // Excelsior JET: section-name detect → Java(Native) lib + compiler.
    if section_names.contains_key(&n::RECORD_NAME_EXCELSIORJET) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_JAVA,
            "",
            "Native",
        );
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_EXCELSIORJET,
            "",
            "",
        );
    }

    // Go compiler.
    if section_names.contains_key(&n::RECORD_NAME_GO)
        || code_section.contains_key(&n::RECORD_NAME_GO)
    {
        let mut ver = "1.X".to_string();
        if let Some((off, sz)) = cd_rng
            && let Some((v, _)) = go_vi(data, off, sz)
        {
            ver = v;
        }
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_GO,
            &ver,
            "",
        );
    }

    // Visual Objects: DOS stub carries a distinctive banner @0x312.
    if data.len() > 0x312
        && crate::parse::find_ansi(
            data,
            0x312,
            data.len() - 0x312,
            b"This Visual Objects application cannot be run in DOS mode",
        ) == Some(0x312)
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_VISUALOBJECTS,
            "2.XX",
            "",
        );
    }

    // FASM header detect → linker-version fill.
    if header.contains_key(&n::RECORD_NAME_FASM) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_FASM,
            &format!("{}.{}", pe.major_linker, pe.minor_linker),
            "",
        );
    }

    // IExpress SFX marker in const data.
    if let Some((off, sz)) = cd_rng
        && crate::parse::find_ansi(data, off, sz, b"POSTRUNPROGRAM").is_some()
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_SFX,
            n::RECORD_NAME_IEXPRESS,
            "",
            "",
        );
    }

    // LLD linker: ".buildid" section or "LLD PDB." in const data.
    let b_lld = pe
        .extents
        .iter()
        .any(|s| s.name.eq_ignore_ascii_case(".buildid"))
        || cd_rng
            .is_some_and(|(off, sz)| crate::parse::find_ansi(data, off, sz, b"LLD PDB.").is_some());
    if b_lld {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_LINKER,
            n::RECORD_NAME_LLD,
            &format!("{}.{}", pe.major_linker, pe.minor_linker),
            "",
        );
    }

    // Zig: GENERICLINKER variant 1 + ZIG_* marker strings.
    if let Some(rec) = header.get(&n::RECORD_NAME_GENERICLINKER)
        && rec.variant == 1
        && let Some((off, sz)) = cd_rng
        && (crate::parse::find_ansi(data, off, sz, b"ZIG_DEBUG_COLOR").is_some()
            || crate::parse::find_ansi(data, off, sz, b"ZIG_PROGRESS").is_some()
            || find_utf16le(data, off, sz, "ZIG_DEBUG_COLOR").is_some()
            || find_utf16le(data, off, sz, "ZIG_PROGRESS").is_some())
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_ZIG,
            "",
            "",
        );
    }

    // Nim: io.nim/fatal.nim strings in const data.
    if let Some((off, sz)) = cd_rng
        && (crate::parse::find_ansi(data, off, sz, b"io.nim").is_some()
            || crate::parse::find_ansi(data, off, sz, b"fatal.nim").is_some())
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_NIM,
            "",
            "",
        );
    }

    // Header-detect → record chains.
    if header.contains_key(&n::RECORD_NAME_VALVE) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_STUB,
            n::RECORD_NAME_VALVE,
            "",
            "",
        );
    }
    if header.contains_key(&n::RECORD_NAME_UNILINK) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_LINKER,
            n::RECORD_NAME_UNILINK,
            "",
            "",
        );
    }
    if header.contains_key(&n::RECORD_NAME_DMD32) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_DMD32,
            "",
            "",
        );
    }
    if header.contains_key(&n::RECORD_NAME_GOLINK) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_LINKER,
            n::RECORD_NAME_GOLINK,
            &format!("{}.{}", pe.major_linker, pe.minor_linker),
            "",
        );
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_GOASM,
            "",
            "",
        );
    }
    if header.contains_key(&n::RECORD_NAME_LAYHEYFORTRAN90)
        && crate::parse::read_ansi_string(data, 0x200).as_deref()
            == Some(
                "This program must be run under Windows 95, NT, or Win32s\r\nPress any key to exit.$",
            )
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_LAYHEYFORTRAN90,
            "",
            "",
        );
    }

    // FLEXlm/FlexNet licensing strings in the data section.
    if deep && let Some(ds) = normal_data_section(pe) {
        let (off, sz) = (ds.off, ds.size.min(1 << 22));
        if let Some(h) = crate::parse::find_ansi(data, off, sz, b"@(#) FLEXlm ") {
            let mut v = crate::parse::read_ansi_string_len(data, h + 12, 50).unwrap_or_default();
            v = v.split(' ').next().unwrap_or("").to_string();
            if let Some(stripped) = v.strip_prefix('v') {
                v = stripped.to_string();
            }
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_LIBRARY,
                n::RECORD_NAME_FLEXLM,
                &v,
                "",
            );
        } else {
            let h = crate::parse::find_ansi(data, off, sz, b"@(#) FLEXnet Licensing v")
                .or_else(|| crate::parse::find_ansi(data, off, sz, b"@(#) FlexNet Licensing v"));
            if let Some(h) = h {
                let mut v =
                    crate::parse::read_ansi_string_len(data, h + 24, 50).unwrap_or_default();
                v = if v.contains("build") {
                    v.split(' ').take(3).collect::<Vec<_>>().join(" ")
                } else {
                    v.split(' ').next().unwrap_or("").to_string()
                };
                emit(
                    misc,
                    ftpe,
                    rt::RECORD_TYPE_LIBRARY,
                    n::RECORD_NAME_FLEXNET,
                    &v,
                    "",
                );
            }
        }
    }

    if !pe.is_dotnet {
        // Qt runtime libraries.
        for (lib, ver, dbg) in [
            ("QtCore4.dll", "4.X", ""),
            ("QtCored4.dll", "4.X", "Debug"),
            ("Qt5Core.dll", "5.X", ""),
            ("Qt5Cored.dll", "5.X", "Debug"),
            ("Qt6Core.dll", "6.X", ""),
            ("Qt6Cored.dll", "6.X", "Debug"),
        ] {
            if pe
                .import_headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case(lib))
            {
                emit(
                    misc,
                    ftpe,
                    rt::RECORD_TYPE_LIBRARY,
                    n::RECORD_NAME_QT,
                    ver,
                    dbg,
                );
                break;
            }
        }
        if !misc.contains_key(&n::RECORD_NAME_QT)
            && let Some(rec) = section_names.get(&n::RECORD_NAME_QT)
        {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_LIBRARY,
                n::RECORD_NAME_QT,
                &rec.version,
                &rec.info,
            );
        }

        // Free Pascal + Lazarus.
        if let Some(ds) = normal_data_section(pe).filter(|_| deep) {
            let (off, sz) = (ds.off, ds.size.min(1 << 22));
            if let Some(h) = crate::parse::find_ansi(data, off, sz, b"FPC ") {
                let s = crate::parse::read_ansi_string(data, h).unwrap_or_default();
                // section(" ",1,-1).section(" - ",0,0)
                let ver = s
                    .split(' ')
                    .skip(1)
                    .collect::<Vec<_>>()
                    .join(" ")
                    .split(" - ")
                    .next()
                    .unwrap_or("")
                    .to_string();
                emit(
                    misc,
                    ftpe,
                    rt::RECORD_TYPE_COMPILER,
                    n::RECORD_NAME_FPC,
                    &ver,
                    "",
                );
                let laz = crate::parse::find_ansi(data, off, sz, b"Lazarus LCL: ").or_else(|| {
                    cd_rng.and_then(|(co, cs)| {
                        crate::parse::find_ansi(data, co, cs, b"Lazarus LCL: ")
                    })
                });
                if let Some(lh) = laz {
                    let lv = crate::parse::read_ansi_string(data, lh + 13)
                        .unwrap_or_default()
                        .split(' ')
                        .next()
                        .unwrap_or("")
                        .to_string();
                    emit(
                        misc,
                        ftpe,
                        rt::RECORD_TYPE_TOOL,
                        n::RECORD_NAME_LAZARUS,
                        &lv,
                        "",
                    );
                }
            } else if crate::parse::find_ansi(data, off, sz, b"\x0eRuntime error ").is_some() {
                emit(
                    misc,
                    ftpe,
                    rt::RECORD_TYPE_COMPILER,
                    n::RECORD_NAME_FPC,
                    "",
                    "",
                );
            }
        }

        // Python/Perl runtime DLLs → library versions.
        for ih in &pe.import_headers {
            let up = ih.name.to_ascii_uppercase();
            if up.starts_with("PYTHON") {
                let digits: String = up.chars().filter(|c| c.is_ascii_digit()).collect();
                if let Ok(dv) = digits.parse::<f64>()
                    && dv != 0.0
                {
                    emit(
                        misc,
                        ftpe,
                        rt::RECORD_TYPE_LIBRARY,
                        n::RECORD_NAME_PYTHON,
                        &format!("{:.1}", dv / 10.0),
                        "",
                    );
                }
            } else if up.starts_with("LIBPYTHON") {
                // (\d.\d) → direct version, e.g. LIBPYTHON3.9 → "3.9".
                if let Some(v) = python_dot_version(&up) {
                    emit(
                        misc,
                        ftpe,
                        rt::RECORD_TYPE_LIBRARY,
                        n::RECORD_NAME_PYTHON,
                        &v,
                        "",
                    );
                }
            } else if up.starts_with("PERL") {
                let digits: String = up.chars().filter(|c| c.is_ascii_digit()).collect();
                if let Ok(dv) = digits.parse::<f64>()
                    && dv != 0.0
                {
                    emit(
                        misc,
                        ftpe,
                        rt::RECORD_TYPE_LIBRARY,
                        n::RECORD_NAME_PERL,
                        &format!("{:.2}", dv / 100.0),
                        "",
                    );
                }
            }
        }

        // Virtual Pascal / PowerBASIC strings, PureBasic/LCC-Win32 EP.
        if let Some(ds) = normal_data_section(pe).filter(|_| deep)
            && crate::parse::find_ansi(
                data,
                ds.off,
                ds.size.min(1 << 22),
                b"Virtual Pascal - Copyright (C) ",
            )
            .is_some()
        {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_VIRTUALPASCAL,
                &format!("{}.{}", pe.major_linker, pe.minor_linker),
                "",
            );
        }
        if deep
            && let Some((off, sz)) = pe.code_section_extent(data)
            && crate::parse::find_ansi(data, off, sz.min(1 << 22), b"PowerBASIC").is_some()
        {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_POWERBASIC,
                "",
                "",
            );
        }
        if let Some(rec) = entrypoint.get(&n::RECORD_NAME_PUREBASIC) {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_PUREBASIC,
                &rec.version,
                &rec.info,
            );
        }
        if let Some(rec) = entrypoint.get(&n::RECORD_NAME_LCCWIN) {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_LCCWIN,
                &rec.version,
                &rec.info,
            );
            if header.contains_key(&n::RECORD_NAME_GENERICLINKER) {
                emit(
                    misc,
                    ftpe,
                    rt::RECORD_TYPE_LINKER,
                    n::RECORD_NAME_LCCLNK,
                    &format!("{}.{}", pe.major_linker, pe.minor_linker),
                    "",
                );
            }
        }
    }
}

/// Extract a `d.d`-shaped version from a `LIBPYTHON…` library name.
fn python_dot_version(up: &str) -> Option<String> {
    let idx = up.find(|c: char| c.is_ascii_digit())?;
    let tail = &up[idx..];
    let mut it = tail.split(|c: char| !(c.is_ascii_digit() || c == '.'));
    let v = it.next()?;
    if v.chars().filter(|&c| c == '.').count() >= 1 && v.chars().next().unwrap().is_ascii_digit() {
        Some(v.trim_end_matches('.').to_string())
    } else {
        None
    }
}

/// `XBinary::appendComma` — build ", "-separated info strings.
fn append_comma(s: &mut String, add: &str) {
    if add.is_empty() {
        return;
    }
    if !s.is_empty() {
        s.push_str(", ");
    }
    s.push_str(add);
}

/// Region bounds guard mirroring `checkOffsetSize` + deep-scan gating
/// used before every `find_ansiString` call in the installer handlers.
fn region(d: &[u8], e: Option<&SectionExtent>, deep: bool) -> Option<(usize, usize)> {
    let e = e?;
    if !deep || e.off == 0 || e.off >= d.len() {
        return None;
    }
    Some((e.off, e.size.min(d.len() - e.off)))
}

/// `NFD_Binary::get_WindowsInstaller_vi` — find "Windows Installer" in
/// the region, capture `(...)` as version; "xml" (case-insensitive)
/// marks info="XML".
fn windows_installer_vi(d: &[u8], off: usize, size: usize) -> (String, String, bool) {
    let Some(pos) = crate::parse::find_ansi(
        d,
        off,
        size.min(d.len().saturating_sub(off)),
        b"Windows Installer",
    ) else {
        return (String::new(), String::new(), false);
    };
    let s = crate::parse::read_ansi_string(d, pos).unwrap_or_default();
    let mut info = String::new();
    if s.to_ascii_lowercase().contains("xml") {
        info = "XML".to_string();
    }
    let ver = crate::scans::reg_exp(r"\((.*?)\)", &s, 1);
    (ver, info, true)
}

/// `handle_Installers` (non-.NET branch, `nfd_pe.cpp` 3717..4278):
/// overlay/header/section-name gated installer detections driven by
/// version-resource fields, the manifest string and export names.
#[allow(clippy::too_many_arguments)]
pub fn installers(
    d: &[u8],
    pe: &PeInfo,
    deep: bool,
    ftpe: u16,
    overlay: &DetectMap,
    header: &DetectMap,
    section_names: &DetectMap,
    misc: &mut DetectMap,
) {
    use crate::gen_names::name as n;
    use crate::gen_names::rtype as rt;
    use crate::scans::reg_exp;
    if pe.is_dotnet {
        return;
    }
    let rv = &pe.res_version;
    let manifest = &pe.manifest;

    // ---- Inno Setup ----
    if overlay.contains_key(&n::RECORD_NAME_INNOSETUP)
        || header.contains_key(&n::RECORD_NAME_INNOSETUP)
    {
        let mut ver = String::new();
        let mut info = String::new();
        if crate::parse::rd_u32(d, 0x30) == Some(0x6E55_6E49) {
            // "InUn" — Uninstall stub.
            info = "Uninstall".to_string();
            if let Some((off, size)) = region(d, normal_code_section(pe), deep)
                && let Some(pos) =
                    crate::parse::find_ansi(d, off, size, b"Setup version: Inno Setup version ")
            {
                let vs = crate::parse::read_ansi_string(d, pos + 34).unwrap_or_default();
                ver = vs.split(' ').next().unwrap_or("").to_string();
                match vs.split(' ').nth(1) {
                    Some("(a)") => append_comma(&mut info, "ANSI"),
                    Some("(u)") => append_comma(&mut info, "Unicode"),
                    _ => {}
                }
            }
        } else if overlay
            .get(&n::RECORD_NAME_INNOSETUP)
            .map(|r| r.info.as_str())
            == Some("Uninstall")
        {
            info = "Uninstall".to_string();
            if pe.overlay_offset >= 0 {
                let (oo, osz) = (pe.overlay_offset as usize, pe.overlay_size);
                if let Some(pos) = crate::parse::find_ansi(d, oo, osz, b"Inno Setup Messages (") {
                    let vs = crate::parse::read_ansi_string(d, pos + 21).unwrap_or_default();
                    ver = vs.split(' ').next().unwrap_or("").replace(')', "");
                    match vs.split(' ').nth(1) {
                        Some("(a))") => append_comma(&mut info, "ANSI"),
                        Some("(u))") => append_comma(&mut info, "Unicode"),
                        _ => {}
                    }
                }
            }
        } else {
            let mut ldr_off: i64 = -1;
            if crate::parse::rd_u32(d, 0x30) == Some(0x6F6E_6E49) {
                // "Inno" — 1.XX-5.1.X layout.
                ver = "1.XX-5.1.X".to_string();
                info = "Install".to_string();
                ldr_off = crate::parse::rd_u32(d, 0x34)
                    .map(|v| v as i64)
                    .unwrap_or(-1);
            } else if let Some((o, _)) =
                crate::pe::resource_record(&pe.resources, 10 /* RT_RCDATA */, 11111)
            {
                ldr_off = o as i64;
                ver = "5.1.X-X.X.X".to_string();
                info = "Install".to_string();
            }
            if ldr_off >= 0 {
                let lo = ldr_off as usize;
                if crate::signature::get_signature(d, lo, 12)[..12] == *"72446C507453" {
                    // rDlPtS — loader table.
                    let mut setup = crate::parse::rd_u32(d, lo + 32)
                        .and_then(|o| crate::parse::read_ansi_string(d, o as usize))
                        .unwrap_or_default();
                    if !setup.contains('(') {
                        setup = crate::parse::rd_u32(d, lo + 36)
                            .and_then(|o| crate::parse::read_ansi_string(d, o as usize))
                            .unwrap_or_default();
                    }
                    let v = reg_exp(r"\((.*?)\)", &setup, 1);
                    if !v.is_empty() {
                        ver = v;
                    }
                    match reg_exp(r"\) \((.*?)\)", &setup, 1).as_str() {
                        "a" => append_comma(&mut info, "ANSI"),
                        "u" => append_comma(&mut info, "Unicode"),
                        _ => {}
                    }
                }
            }
        }
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_INNOSETUP,
            &ver,
            &info,
        );
    }

    // ---- WiX toolset (CAB overlay + .wixburn section) ----
    if overlay.contains_key(&n::RECORD_NAME_CAB) && pe.has_section_name(".wixburn") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_WIXTOOLSET,
            "3.X",
            "",
        );
    }
    if overlay.contains_key(&n::RECORD_NAME_NOSINSTALLER)
        && section_names.contains_key(&n::RECORD_NAME_NOSINSTALLER)
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_NOSINSTALLER,
            "",
            "",
        );
    }

    // ---- sfxcab.exe manifest → CAB SFX w/ embedded version ----
    if manifest.contains("sfxcab.exe") {
        let mut ver = String::new();
        if deep
            && pe.resources_section >= 0
            && let Some(e) = pe.extents.get(pe.resources_section as usize)
        {
            let end = e.off + e.vsize.min(e.size as u32) as usize;
            let base = end.saturating_sub(0x600).min(d.len());
            let sz = (end.min(d.len())).saturating_sub(base);
            if let Some(p) = crate::parse::find_ansi(
                d,
                base,
                sz,
                &[0xBD, 0x04, 0xEF, 0xFE, 0x00, 0x00, 0x01, 0x00],
            ) {
                // BD04EFFE sig → version dwords at +16.
                let (a, b, c, dd) = (
                    crate::parse::rd_u16(d, p + 18).unwrap_or(0),
                    crate::parse::rd_u16(d, p + 16).unwrap_or(0),
                    crate::parse::rd_u16(d, p + 22).unwrap_or(0),
                    crate::parse::rd_u16(d, p + 20).unwrap_or(0),
                );
                ver = format!("{a}.{b}.{c}.{dd}");
            }
        }
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_SFX,
            n::RECORD_NAME_CAB,
            &ver,
            "",
        );
    }

    // ---- InstallAnywhere ----
    if overlay.contains_key(&n::RECORD_NAME_INSTALLANYWHERE)
        && rv.value("ProductName") == "InstallAnywhere"
    {
        let v = rv.value("ProductVersion").to_string();
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_INSTALLANYWHERE,
            &v,
            "",
        );
    }
    if overlay.contains_key(&n::RECORD_NAME_GHOSTINSTALLER) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_GHOSTINSTALLER,
            "1.0",
            "",
        );
    }
    if overlay.contains_key(&n::RECORD_NAME_QTINSTALLER) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_QTINSTALLER,
            "",
            "",
        );
    }
    if overlay.contains_key(&n::RECORD_NAME_INSTALL4J) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_INSTALL4J,
            "",
            "",
        );
    }
    if overlay.contains_key(&n::RECORD_NAME_SMARTINSTALLMAKER) {
        // Version = overlay signature bytes 23..30 as hex.
        let sig = if pe.overlay_offset >= 0 {
            crate::signature::get_signature(d, pe.overlay_offset as usize, 150)
        } else {
            String::new()
        };
        let v = if sig.len() >= 60 {
            // mid(46,14) hex chars → raw ASCII bytes 23..30.
            let hex = &sig[46..60];
            (0..7)
                .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
                .map(|b| b as char)
                .collect::<String>()
        } else {
            String::new()
        };
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_SMARTINSTALLMAKER,
            &v,
            "",
        );
    }
    if overlay.contains_key(&n::RECORD_NAME_TARMAINSTALLER) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_TARMAINSTALLER,
            "",
            "",
        );
    }
    if overlay.contains_key(&n::RECORD_NAME_CLICKTEAM) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_CLICKTEAM,
            "",
            "",
        );
    }

    // ---- NSIS ----
    if overlay.contains_key(&n::RECORD_NAME_NSIS) || manifest.contains("Nullsoft.NSIS") {
        let mut info = overlay
            .get(&n::RECORD_NAME_NSIS)
            .map(|r| r.info.clone())
            .unwrap_or_default();
        if info.is_empty() {
            info = String::new();
        }
        let ver = reg_exp("Null[sS]oft Install System v?(.*?)<", manifest, 1);
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_NSIS,
            &ver,
            &info,
        );
    }

    // ---- InstallShield chain ----
    if rv.value("ProductName").contains("InstallShield") {
        let mut v = rv.value("FileVersion").trim().to_string();
        v = v.replace(", ", ".");
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_INSTALLSHIELD,
            &v,
            "",
        );
    } else if manifest.contains("InstallShield") {
        let mut ver = String::new();
        if let Some((off, size)) = region(d, normal_data_section(pe), deep)
            && let Some(pos) = crate::parse::find_ansi(d, off, size, b"SOFTWARE\\InstallShield\\1")
        {
            let s = crate::parse::read_ansi_string(d, pos).unwrap_or_default();
            ver = s.split('\\').nth(2).unwrap_or("").to_string();
        }
        if ver.is_empty() {
            ver = rv.value("ISInternalVersion").to_string();
        }
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_INSTALLSHIELD,
            &ver,
            "",
        );
    } else if overlay.contains_key(&n::RECORD_NAME_INSTALLSHIELD) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_INSTALLSHIELD,
            "",
            "PackageForTheWeb",
        );
    } else if rv.value("CompanyName").contains("InstallShield") {
        let mut v = rv.value("FileVersion").to_string();
        let mut info = "";
        if rv.value("CompanyName").contains("PackageForTheWeb") {
            info = "PackageForTheWeb";
        }
        v = v.trim().to_string();
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_INSTALLSHIELD,
            &v,
            info,
        );
    }

    if manifest.contains("name=\"InstallSimple\"")
        || overlay.contains_key(&n::RECORD_NAME_INSTALLSIMPLE)
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_INSTALLSIMPLE,
            "",
            "",
        );
    }
    if manifest.contains("AdvancedInstallerSetup") {
        let mut ver = String::new();
        if deep
            && pe.overlay_offset >= 0
            && pe.overlay_size > 0
            && let Some(pos) = crate::parse::find_ansi(
                d,
                pe.overlay_offset as usize,
                pe.overlay_size,
                b"Advanced Installer ",
            )
        {
            let s = crate::parse::read_ansi_string(d, pos).unwrap_or_default();
            ver = s.split(' ').nth(2).unwrap_or("").to_string();
        }
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_ADVANCEDINSTALLER,
            &ver,
            "",
        );
    }
    if manifest.contains("Illustrate.Spoon.Installer") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_SPOONINSTALLER,
            "",
            "",
        );
    }
    if manifest.contains("DeployMaster Installer") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_DEPLOYMASTER,
            "",
            "",
        );
    }
    if manifest.contains("Gentee.Installer.Install")
        || manifest.contains("name=\"gentee\"")
        || (section_names.contains_key(&n::RECORD_NAME_GENTEEINSTALLER)
            && crate::pe::resource_present(&pe.resources, 10, Some("SETUP_TEMP"), None))
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_GENTEEINSTALLER,
            "",
            "",
        );
    }
    if manifest.contains("BitRock Installer") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_BITROCKINSTALLER,
            "",
            "",
        );
    }

    // ---- version-resource driven installers ----
    let file_ver = rv.value("FileVersion").trim().replace(", ", ".");
    let fd = rv.value("FileDescription");
    let pn = rv.value("ProductName");
    let cm = rv.value("Comments");
    let iname = rv.value("InternalName");

    if fd.contains("GP-Install") && fd.contains("TASPro6-Install") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_GPINSTALL,
            &file_ver,
            "",
        );
    }
    if fd.contains("Total Commander Installer") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_TOTALCOMMANDERINSTALLER,
            &file_ver,
            "",
        );
    }
    if cm.contains("Actual Installer") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_ACTUALINSTALLER,
            &file_ver,
            "",
        );
    }
    if cm.contains("Avast Antivirus") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_AVASTANTIVIRUS,
            &file_ver,
            "",
        );
    }
    if pn.contains("Opera Installer") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_OPERA,
            &file_ver,
            "",
        );
    }
    if pn.contains("Yandex Installer") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_YANDEX,
            &file_ver,
            "",
        );
    }
    if pn.contains("Google Update") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_GOOGLE,
            &file_ver,
            "",
        );
    }
    if fd.contains("Visual Studio Installer") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_MICROSOFTVISUALSTUDIO,
            &file_ver,
            "",
        );
    }
    if iname.contains("Dropbox Update Setup") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_DROPBOX,
            &file_ver,
            "",
        );
    }
    if pn.contains("VeraCrypt") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_VERACRYPT,
            &file_ver,
            "",
        );
    }
    if fd.contains("Microsoft .NET Framework") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_MICROSOFTDOTNETFRAMEWORK,
            &file_ver,
            "",
        );
    }
    if rv.value("LegalTrademarks").contains("Setup Factory") {
        let mut v = rv.value("ProductVersion").trim().to_string();
        if v.contains(',') {
            v = v.replace(' ', "").replace(',', ".");
        }
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_SETUPFACTORY,
            &v,
            "",
        );
    }
    if cm.contains("This installation was built with InstallAware") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_INSTALLAWARE,
            &file_ver,
            "",
        );
    }
    if fd.contains("Microsoft Office") && iname.contains("Bootstrapper.exe") {
        let mut v = rv.value("ProductVersion").trim().to_string();
        if v.contains(',') {
            v = v.replace(' ', "").replace(',', ".");
        }
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_MICROSOFTOFFICE,
            &v,
            "",
        );
    }
    let squirrel = rv.value("SquirrelAwareVersion").trim();
    if !squirrel.is_empty() {
        let v = if squirrel == "1" {
            "1.0.0-1.9.1"
        } else {
            squirrel
        };
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_SQUIRRELINSTALLER,
            v,
            "",
        );
    }
    if fd.contains("Java") && iname.contains("Setup Launcher") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_JAVA,
            &file_ver,
            "",
        );
    }
    if overlay.contains_key(&n::RECORD_NAME_VMWARE) || fd.contains("VMware installation") {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_VMWARE,
            &file_ver,
            "",
        );
    }

    // ---- Windows Installer (MSI overlay / embedded CFBF) ----
    if overlay.contains_key(&n::RECORD_NAME_MICROSOFTCOMPOUND) && pe.overlay_offset >= 0 {
        let (v, inf, ok) = windows_installer_vi(d, pe.overlay_offset as usize, pe.overlay_size);
        if ok && !v.is_empty() || ok && !inf.is_empty() {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_INSTALLER,
                n::RECORD_NAME_WINDOWSINSTALLER,
                &v,
                &inf,
            );
        } else if ok && v.is_empty() {
            // upstream emits only when sVersion non-empty.
            let _ = inf;
        }
    }
    if !misc.contains_key(&n::RECORD_NAME_WINDOWSINSTALLER) {
        for r in &pe.resources {
            if r.data_off == 0 || r.data_size == 0 {
                continue;
            }
            let sig = crate::signature::get_signature(d, r.data_off, 8.min(r.data_size));
            if sig == "D0CF11E0A1B11AE1" {
                let (v, inf, ok) = windows_installer_vi(d, r.data_off, r.data_size);
                if ok && !v.is_empty() {
                    emit(
                        misc,
                        ftpe,
                        rt::RECORD_TYPE_INSTALLER,
                        n::RECORD_NAME_WINDOWSINSTALLER,
                        &v,
                        &inf,
                    );
                    break;
                }
            }
        }
    }

    // ---- WISE (STUB32.EXE export signature) ----
    if pe.export_dll_name == "STUB32.EXE" {
        let names = &pe.export_names;
        let is_wise = (names.len() == 2
            && (names.first().map(|s| s.as_str()) == Some("_MainWndProc@16")
                || names.get(1).map(|s| s.as_str()) == Some("_StubFileWrite@12")))
            || (names.len() == 6
                && [
                    "_LanguageDlg@16",
                    "_PasswordDlg@16",
                    "_ProgressDlg@16",
                    "_UpdateCRC@8",
                    "_t1@40",
                    "_t2@12",
                ]
                .iter()
                .enumerate()
                .any(|(i, w)| names.get(i).map(|s| s.as_str()) == Some(w)));
        if is_wise {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_INSTALLER,
                n::RECORD_NAME_WISE,
                "",
                "",
            );
        }
    }
}

/// `handle_SFX` (`nfd_pe.cpp` 4280..4501): non-.NET branch, SFX
/// detections driven by overlay map + manifest + version resources.
pub fn sfx(
    d: &[u8],
    pe: &PeInfo,
    deep: bool,
    ftpe: u16,
    overlay: &DetectMap,
    misc: &mut DetectMap,
) {
    use crate::gen_names::name as n;
    use crate::gen_names::rtype as rt;
    if pe.is_dotnet {
        return;
    }
    let rv = &pe.res_version;
    let manifest = &pe.manifest;

    if overlay.contains_key(&n::RECORD_NAME_RAR)
        && crate::pe::resource_present(
            &pe.resources,
            5, /* RT_DIALOG */
            Some("STARTDLG"),
            None,
        )
        && crate::pe::resource_present(&pe.resources, 5, Some("LICENSEDLG"), None)
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_SFX,
            n::RECORD_NAME_WINRAR,
            "",
            "",
        );
    }
    if (overlay.contains_key(&n::RECORD_NAME_WINRAR) || overlay.contains_key(&n::RECORD_NAME_ZIP))
        && manifest.contains("WinRAR")
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_SFX,
            n::RECORD_NAME_WINRAR,
            "",
            "",
        );
    }
    if overlay.contains_key(&n::RECORD_NAME_ZIP)
        && let Some((off, size)) = region(d, normal_data_section(pe), deep)
        && crate::parse::find_ansi(d, off, size, b"ZIP self-extractor").is_some()
    {
        emit(misc, ftpe, rt::RECORD_TYPE_SFX, n::RECORD_NAME_ZIP, "", "");
    }
    if rv.value("ProductName").contains("7-Zip") {
        let v = rv.value("ProductVersion").to_string();
        emit(misc, ftpe, rt::RECORD_TYPE_SFX, n::RECORD_NAME_7Z, &v, "");
    }
    if !misc.contains_key(&n::RECORD_NAME_7Z) && overlay.contains_key(&n::RECORD_NAME_7Z) {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_SFX,
            n::RECORD_NAME_7Z,
            "",
            "Modified",
        );
    }
    if overlay.contains_key(&n::RECORD_NAME_SQUEEZSFX) && rv.value("ProductName").contains("Squeez")
    {
        // Upstream tags the type INSTALLER but inserts into mapResultSFX.
        let v = rv.value("FileVersion").trim().to_string();
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_INSTALLER,
            n::RECORD_NAME_SQUEEZSFX,
            &v,
            "",
        );
    }
    let iname = rv.value("InternalName");
    if iname.contains("WinACE") || iname.contains("WinAce") || iname.contains("UNACE") {
        let v = rv.value("ProductVersion").to_string();
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_SFX,
            n::RECORD_NAME_WINACE,
            &v,
            "",
        );
    }
    if manifest.contains("WinZipComputing.WinZip") || pe.has_section_name("_winzip_") {
        let seg = manifest.split("assemblyIdentity").nth(1).unwrap_or("");
        let v = crate::scans::reg_exp("version=\"(.*?)\"", seg, 1);
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_SFX,
            n::RECORD_NAME_WINZIP,
            &v,
            "",
        );
    }
    if rv
        .value("FileDescription")
        .contains("Self-Extracting Cabinet")
    {
        let v = rv.value("FileVersion").to_string();
        emit(misc, ftpe, rt::RECORD_TYPE_SFX, n::RECORD_NAME_CAB, &v, "");
    }
    if rv.value("ProductName").contains("GkSetup Self extractor") {
        let v = rv.value("ProductVersion").to_string();
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_SFX,
            n::RECORD_NAME_GKSETUPSFX,
            &v,
            "",
        );
    }
}

/// `handle_wxWidgets` (`nfd_pe.cpp` 7159..7246): `^WX*` import DLL →
/// dynamic version, `WXWINDOWMENU` menu resource → static; deep-scan
/// const-data version strings refine the version.
pub fn wx_widgets(d: &[u8], pe: &PeInfo, deep: bool, ftpe: u16, misc: &mut DetectMap) {
    use crate::gen_names::name as n;
    use crate::gen_names::rtype as rt;
    if pe.is_dotnet {
        return;
    }
    let mut dynamic = false;
    let mut statik = false;
    let mut version = String::new();
    let mut info = String::new();
    for h in &pe.import_headers {
        if crate::scans::reg_exp_present("^WX", &h.name.to_uppercase()) {
            let dv = crate::scans::reg_exp("(\\d+)", &h.name.to_uppercase(), 0);
            if let Ok(v) = dv.parse::<f64>()
                && v != 0.0
            {
                if v < 100.0 {
                    version = format!("{:.1}", v / 10.0);
                } else if v < 1000.0 {
                    version = format!("{:.2}", v / 100.0);
                }
                dynamic = true;
            }
            break;
        }
    }
    if !dynamic
        && crate::pe::resource_present(
            &pe.resources,
            4, /* RT_MENU */
            Some("WXWINDOWMENU"),
            None,
        )
    {
        statik = true;
    }
    if (dynamic || statik)
        && deep
        && let Some((off, size)) = region(d, const_data_section(pe), true)
    {
        for (pat, ver, inf) in [
            (
                "3.1.1 (wchar_t,Visual C++ 1900,wx containers)",
                "3.1.1",
                "Visual C++ 1900",
            ),
            (
                "3.1.2 (wchar_t,Visual C++ 1900,wx containers,compatible with 3.0)",
                "3.1.2",
                "Visual C++ 1900",
            ),
        ] {
            if crate::parse::find_ansi(d, off, size, pat.as_bytes()).is_some() {
                version = ver.to_string();
                info = inf.to_string();
                break;
            }
        }
    }
    if dynamic || statik {
        let mut inf = String::new();
        if statik {
            inf = "Static".to_string();
        }
        append_comma(&mut inf, &info);
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_WXWIDGETS,
            &version,
            &inf,
        );
    }
}

/// `get_DeepSea_vi` — "DeepSeaObfuscator" banner → version "4.X",
/// "Evaluation" in the following string marks info.
fn deepsea_vi(d: &[u8], off: usize, size: usize) -> Option<(String, String)> {
    let pos = crate::parse::find_ansi(d, off, size, b"DeepSeaObfuscator")?;
    let full = crate::parse::read_ansi_string(d, pos + 18).unwrap_or_default();
    let info = if full.contains("Evaluation") {
        "Evaluation"
    } else {
        ""
    };
    Some(("4.X".to_string(), info.to_string()))
}

/// `get_Enigma_vi` — `\0\0\0ENIGMA` marker + version fields, or the
/// ` *** Enigma protector v` banner fallback.
fn enigma_vi(d: &[u8], off: usize, size: usize) -> Option<(String, String)> {
    let sz = size.min(d.len().saturating_sub(off));
    if let Some(pos) = crate::parse::find_ansi(d, off, sz, b"\x00\x00\x00ENIGMA") {
        let r8 = |o: usize| d.get(o).copied().unwrap_or(0);
        let r16 = |o: usize| crate::parse::rd_u16(d, o).unwrap_or(0);
        let v = format!(
            "{}.{:02} build {:04}.{:02}.{:02} {:02}:{:02}:{:02}",
            r8(pos + 9),
            r8(pos + 10),
            r16(pos + 11),
            r16(pos + 13),
            r16(pos + 15),
            r16(pos + 17),
            r16(pos + 19),
            r16(pos + 21),
        );
        return Some((v, String::new()));
    }
    let pos = crate::parse::find_ansi(d, off, sz, b" *** Enigma protector v")?;
    let v = crate::parse::read_ansi_string(d, pos + 22).unwrap_or_default();
    Some((v, String::new()))
}

/// `get_SmartAssembly_vi` — "Powered by SmartAssembly " + version.
fn smartassembly_vi(d: &[u8], off: usize, size: usize) -> Option<(String, String)> {
    let pos = crate::parse::find_ansi(
        d,
        off,
        size.min(d.len().saturating_sub(off)),
        b"Powered by SmartAssembly ",
    )?;
    let v = crate::parse::read_ansi_string(d, pos + 25).unwrap_or_default();
    Some((v, String::new()))
}

/// `handle_NETProtection` (`nfd_pe.cpp` 5228..5561): .NET protector /
/// obfuscator promotion driven by the `dot_ansi`/`dot_unicode` heap
/// scans plus code-section memory scans. Emitted into `misc`
/// (upstream fans out to mapResultNETObfuscators/Protectors/Packers/
/// NETCompressors — our output keeps the record's own type).
#[allow(clippy::too_many_arguments)]
pub fn net_protection(
    d: &[u8],
    pe: &PeInfo,
    deep: bool,
    ftpe: u16,
    dot_ansi: &DetectMap,
    dot_unicode: &DetectMap,
    code_section: &DetectMap,
    overlay: &DetectMap,
    imports: &DetectMap,
    entrypoint: &DetectMap,
    misc: &mut DetectMap,
) {
    // bIsNetPresent ≈ cliInfo.bValid || isNETPresent&&deep — both mean
    // "CLI dir present" here.
    if !pe.is_dotnet {
        return;
    }
    /// Copy a scan record into misc (upstream `scansToScan`).
    fn take(src: &DetectMap, name: u16, misc: &mut DetectMap) {
        if let Some(r) = src.get(&name) {
            misc.entry(name).or_insert_with(|| r.clone());
        }
    }
    let code_region = region(d, normal_code_section(pe), deep);

    // Enigma (.NET variant) — banner in the code section.
    if let Some((off, size)) = code_region
        && let Some((v, inf)) = enigma_vi(d, off, size)
    {
        let e = misc
            .entry(n::RECORD_NAME_ENIGMA)
            .or_insert_with(|| ScanRecord {
                name: n::RECORD_NAME_ENIGMA,
                rtype: rt::RECORD_TYPE_PROTECTOR,
                ft: ftpe,
                variant: 0,
                version: v,
                info: inf,
                heuristic: false,
                unknown: false,
            });
        let _ = e;
    }
    // DotNetReactor — fixed signature in section 1 (deep only).
    if deep && pe.extents.len() >= 2 {
        let e = &pe.extents[1];
        let sz = e.size.min(d.len().saturating_sub(e.off));
        let sig = [
            0x52, 0x66, 0x68, 0x6E, 0x20, 0x4D, 0x18, 0x22, 0x76, 0xB5, 0x33, 0x11, 0x12, 0x33,
            0x0C, 0x6D, 0x0A, 0x20, 0x4D, 0x18, 0x22, 0x9E, 0xA1, 0x29, 0x61, 0x1C, 0x76, 0xB5,
            0x05, 0x19, 0x01, 0x58,
        ];
        if crate::parse::find_ansi(d, e.off, sz, &sig).is_some() {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_DOTNETREACTOR,
                "4.8-4.9",
                "",
            );
        }
    }

    for name in [
        n::RECORD_NAME_YANO,
        n::RECORD_NAME_DOTFUSCATOR,
        n::RECORD_NAME_AGILENET,
        n::RECORD_NAME_BABELNET,
        n::RECORD_NAME_GOLIATHNET,
        n::RECORD_NAME_SPICESNET,
        n::RECORD_NAME_OBFUSCATORNET2009,
        n::RECORD_NAME_CLISECURE,
        n::RECORD_NAME_DNGUARD,
        n::RECORD_NAME_MAXTOCODE,
        n::RECORD_NAME_PHOENIXPROTECTOR,
        n::RECORD_NAME_XENOCODEPOSTBUILD,
    ] {
        take(dot_ansi, name, misc);
    }
    take(code_section, n::RECORD_NAME_SKATER, misc);
    take(dot_ansi, n::RECORD_NAME_NSPACK, misc);

    // DeepSea: ansi then code-section, with vi refinement.
    let mut ds = dot_ansi
        .get(&n::RECORD_NAME_DEEPSEA)
        .or_else(|| code_section.get(&n::RECORD_NAME_DEEPSEA))
        .cloned();
    if let Some(ref mut r) = ds {
        if let Some((off, size)) = code_region
            && let Some((v, inf)) = deepsea_vi(d, off, size)
        {
            r.version = v;
            r.info = inf;
        }
        misc.insert(n::RECORD_NAME_DEEPSEA, r.clone());
    }

    // CliSecure: ansi hit, else unicode "CliSecure" in exec section 1.
    if !dot_ansi.contains_key(&n::RECORD_NAME_CLISECURE)
        && pe.extents.len() >= 2
        && pe.extents[1].flags & 0x2000_0000 != 0
    {
        let e = &pe.extents[1];
        let sz = e.size.min(d.len().saturating_sub(e.off));
        if find_utf16le(d, e.off, sz, "CliSecure").is_some() {
            emit(
                misc,
                ftpe,
                rt::RECORD_TYPE_NETOBFUSCATOR,
                n::RECORD_NAME_CLISECURE,
                "4.X",
                "",
            );
        }
    }
    if overlay.contains_key(&n::RECORD_NAME_FISHNET)
        || code_section.contains_key(&n::RECORD_NAME_FISHNET)
    {
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_NETOBFUSCATOR,
            n::RECORD_NAME_FISHNET,
            "1.X",
            "",
        );
    }
    if !dot_ansi.contains_key(&n::RECORD_NAME_DOTNETZ) {
        take(code_section, n::RECORD_NAME_DOTNETZ, misc);
    } else {
        take(dot_ansi, n::RECORD_NAME_DOTNETZ, misc);
    }

    // SmartAssembly: ansi/code-section hit + vi version.
    let mut sa = dot_ansi
        .get(&n::RECORD_NAME_SMARTASSEMBLY)
        .or_else(|| code_section.get(&n::RECORD_NAME_SMARTASSEMBLY))
        .cloned();
    if let Some(ref mut r) = sa {
        if let Some((off, size)) = code_region
            && let Some((v, inf)) = smartassembly_vi(d, off, size)
        {
            r.version = v;
            r.info = inf;
        }
        misc.insert(n::RECORD_NAME_SMARTASSEMBLY, r.clone());
    }

    // Confuser / ConfuserEx — ansi hit then banner version in code.
    if let Some(r) = dot_ansi.get(&n::RECORD_NAME_CONFUSER).cloned() {
        let mut r = r;
        if let Some((off, size)) = code_region {
            if let Some(pos) = crate::parse::find_ansi(d, off, size, b"Confuser v") {
                r.version = crate::parse::read_ansi_string(d, pos + 10).unwrap_or_default();
            } else if let Some(pos) = crate::parse::find_ansi(d, off, size, b"ConfuserEx v") {
                r.name = n::RECORD_NAME_CONFUSEREX;
                r.version = crate::parse::read_ansi_string(d, pos + 12).unwrap_or_default();
            }
        }
        misc.insert(r.name, r);
    }

    // CodeVeil — ansi, else unicode heap.
    if !dot_ansi.contains_key(&n::RECORD_NAME_CODEVEIL) {
        take(dot_unicode, n::RECORD_NAME_CODEVEIL, misc);
    } else {
        take(dot_ansi, n::RECORD_NAME_CODEVEIL, misc);
    }
    take(code_section, n::RECORD_NAME_CODEWALL, misc);
    take(code_section, n::RECORD_NAME_CRYPTOOBFUSCATORFORNET, misc);
    take(code_section, n::RECORD_NAME_EAZFUSCATOR, misc);
    if !code_section.contains_key(&n::RECORD_NAME_EAZFUSCATOR) {
        take(dot_ansi, n::RECORD_NAME_EAZFUSCATOR, misc);
    }
    take(code_section, n::RECORD_NAME_OBFUSCAR, misc);
    if !dot_ansi.contains_key(&n::RECORD_NAME_DOTNETSPIDER) {
        take(code_section, n::RECORD_NAME_DOTNETSPIDER, misc);
    } else {
        take(dot_ansi, n::RECORD_NAME_DOTNETSPIDER, misc);
    }
    take(code_section, n::RECORD_NAME_PHOENIXPROTECTOR, misc);
    if !dot_ansi.contains_key(&n::RECORD_NAME_SIXXPACK) {
        take(code_section, n::RECORD_NAME_SIXXPACK, misc);
    } else {
        take(dot_ansi, n::RECORD_NAME_SIXXPACK, misc);
    }
    take(code_section, n::RECORD_NAME_RENETPACK, misc);
    take(code_section, n::RECORD_NAME_DOTNETSHRINK, misc);

    // Xenocode Postbuild via version-resource Packager field.
    let packager = pe.res_version.value("Packager");
    if packager.contains("Xenocode Postbuild 2009 for .NET") {
        let v = pe.res_version.value("PackagerVersion").trim().to_string();
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_NETOBFUSCATOR,
            n::RECORD_NAME_XENOCODEPOSTBUILD2009FORDOTNET,
            &v,
            "",
        );
    }
    if packager.contains("Xenocode Postbuild 2010 for .NET") {
        let v = pe.res_version.value("PackagerVersion").trim().to_string();
        emit(
            misc,
            ftpe,
            rt::RECORD_TYPE_PROTECTOR,
            n::RECORD_NAME_XENOCODEPOSTBUILD2010FORDOTNET,
            &v,
            "",
        );
    }
    if !misc.contains_key(&n::RECORD_NAME_DOTNETREACTOR)
        && imports.contains_key(&n::RECORD_NAME_DOTNETREACTOR)
        && crate::pe::resource_present(&pe.resources, 10, Some("__"), None)
    {
        take(imports, n::RECORD_NAME_DOTNETREACTOR, misc);
    }
    if !misc.contains_key(&n::RECORD_NAME_CODEVEIL)
        && imports.contains_key(&n::RECORD_NAME_CODEVEIL)
        && entrypoint.contains_key(&n::RECORD_NAME_CODEVEIL)
    {
        take(entrypoint, n::RECORD_NAME_CODEVEIL, misc);
    }
}

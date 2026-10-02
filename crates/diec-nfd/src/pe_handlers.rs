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
        if (s.name == "DATA" || s.name == ".data")
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
    if let Some(dbg) = pe.extents.iter().find(|s| s.name == ".debug_info")
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

//! NE/LE/LX semantic handlers — the post-scan fixups of
//! `NFD_NE::getInfo` and `NFD_LE::getInfo`: EP-detect promotion
//! (Borland C++/Turbo Pascal/PK-SFX), deep-scan banner heuristics,
//! exetyp-derived OS records, TurboLinker trailer vi, and the Watcom
//! entry-point banner scan.

use crate::parse;
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

/// `get_TurboLinker_vi` — byte 0xFB at 0x1E marks a Turbo-Linker-stamped
/// image; version is the byte at 0x1F divided by 16 (`'f',1`).
fn turbo_linker_vi(d: &[u8]) -> Option<String> {
    if d.get(0x1E) == Some(&0xFB) {
        let b = f64::from(d.get(0x1F).copied().unwrap_or(0));
        return Some(format!("{:.1}", b / 16.0));
    }
    None
}

/// NE `ne_exetyp` (u8 at header+0x36) -> (os name, version, arch).
fn ne_os(ne: u8) -> (u16, &'static str, &'static str) {
    match ne {
        1 => (n::RECORD_NAME_OS2, "", "286"),
        2 => (n::RECORD_NAME_WINDOWS, "", "286"),
        3 => (n::RECORD_NAME_MSDOS, "4.x", "286"),
        4 => (n::RECORD_NAME_WINDOWS, "", "386"),
        5 => (n::RECORD_NAME_BORLANDOSSERVICES, "", "386"),
        0x81 => (n::RECORD_NAME_OS2, "PharLap Dos Extender", "286"),
        0x82 => (n::RECORD_NAME_WINDOWS, "PharLap Dos Extender", "286"),
        _ => (n::RECORD_NAME_UNKNOWN, "", "286"),
    }
}

/// LE/LX `e32_os` (u16 at header+0x0A) -> (os name, version).
fn le_os(v: u16) -> (u16, &'static str) {
    match v {
        1 => (n::RECORD_NAME_OS2, ""),
        2 => (n::RECORD_NAME_WINDOWS, ""),
        3 => (n::RECORD_NAME_MSDOS, "4.X"),
        4 => (n::RECORD_NAME_WINDOWS, "386"),
        _ => (n::RECORD_NAME_UNKNOWN, ""),
    }
}

/// `XLE::getImageLECpusS` — cpu field -> arch string.
fn le_arch(cpu: u16) -> &'static str {
    match cpu {
        0x01 => "80286",
        0x02 => "80386",
        0x03 => "80486",
        0x04 => "80586",
        0x20 => "i860",
        0x21 => "N11",
        0x40 => "R2000",
        0x41 => "R6000",
        0x42 => "R4000",
        _ => "Unknown",
    }
}

/// `NFD_NE::getInfo` post-scan block.
pub fn ne_semantic_scan(data: &[u8], deep: bool, ft: u16, ep: &DetectMap, misc: &mut DetectMap) {
    let Some(ne_off) = parse::rd_u32(data, 0x3C).map(|v| v as usize) else {
        return;
    };
    if data.get(ne_off..ne_off + 2) != Some(b"NE") {
        return;
    }
    // Entry-point detect promotions.
    for (name, rty) in [
        (n::RECORD_NAME_BORLANDCPP, rt::RECORD_TYPE_COMPILER),
        (n::RECORD_NAME_TURBOPASCAL, rt::RECORD_TYPE_COMPILER),
        (n::RECORD_NAME_PKSFX, rt::RECORD_TYPE_SFX),
    ] {
        if let Some(r) = ep.get(&name) {
            let mut r = r.clone();
            r.rtype = rty;
            misc.insert(name, r);
        }
    }
    // Deep-scan banners bounded by the overlay offset.
    if deep {
        let end = parse::ne_overlay_offset(data).unwrap_or(data.len());
        if !misc.contains_key(&n::RECORD_NAME_BORLANDCPP)
            && parse::find_ansi(data, 0, end, b"Borland C++ - Copyright 1995 Borland Intl.")
                .is_some()
        {
            emit(
                misc,
                ft,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_BORLANDCPP,
                "1995",
                "",
            );
        }
        if parse::find_ansi(data, 0, end, b"Ginkel").is_some() {
            emit(
                misc,
                ft,
                rt::RECORD_TYPE_INSTALLER,
                n::RECORD_NAME_SETUPSPECIALIST,
                "",
                "",
            );
        }
    }
    // OS record — `getOperationSystemScansStruct(XNE::getFileFormatInfo)`;
    // upstream `typeIdToString` is a dead switch returning "Unknown".
    let exetyp = data.get(ne_off + 0x36).copied().unwrap_or(0);
    let (os, osver, arch) = ne_os(exetyp);
    emit(
        misc,
        ft,
        rt::RECORD_TYPE_OPERATIONSYSTEM,
        os,
        osver,
        &format!("{arch}, 16SEG, Unknown"),
    );
    // TurboLinker trailer.
    if let Some(ver) = turbo_linker_vi(data) {
        emit(
            misc,
            ft::FT_MSDOS,
            rt::RECORD_TYPE_LINKER,
            n::RECORD_NAME_TURBOLINKER,
            &ver,
            "",
        );
    }
    // Watcom banner over [EP, EP+0x100).
    if let Some(ep_off) = parse::ne_entry_offset(data)
        && let Some((nm, ver)) = crate::pe_handlers::watcom_vi(data, ep_off, 0x100)
    {
        emit(misc, ft::FT_MSDOS, rt::RECORD_TYPE_COMPILER, nm, &ver, "");
        emit(
            misc,
            ft::FT_MSDOS,
            rt::RECORD_TYPE_LINKER,
            n::RECORD_NAME_WATCOMLINKER,
            "",
            "",
        );
    }
}

/// `NFD_LE::getInfo` post-scan block (shared by LE and LX).
pub fn le_semantic_scan(data: &[u8], ft: u16, misc: &mut DetectMap) {
    let Some(le_off) = parse::rd_u32(data, 0x3C).map(|v| v as usize) else {
        return;
    };
    let Some(sig) = data.get(le_off..le_off + 2) else {
        return;
    };
    let mode = if sig == b"LX" { "32-bit" } else { "16SEG" };
    let os_v = parse::rd_u16(data, le_off + 0x0A).unwrap_or(0);
    let cpu = parse::rd_u16(data, le_off + 0x08).unwrap_or(0);
    let (os, osver) = le_os(os_v);
    emit(
        misc,
        ft,
        rt::RECORD_TYPE_OPERATIONSYSTEM,
        os,
        osver,
        &format!("{}, {}, Unknown", le_arch(cpu), mode),
    );
    if let Some(ver) = turbo_linker_vi(data) {
        emit(
            misc,
            ft::FT_LX,
            rt::RECORD_TYPE_LINKER,
            n::RECORD_NAME_TURBOLINKER,
            &ver,
            "",
        );
    }
    if let Some(ep_off) = parse::le_entry_offset(data)
        && let Some((nm, ver)) = crate::pe_handlers::watcom_vi(data, ep_off, 0x100)
    {
        emit(misc, ft::FT_LX, rt::RECORD_TYPE_COMPILER, nm, &ver, "");
        emit(
            misc,
            ft::FT_LX,
            rt::RECORD_TYPE_LINKER,
            n::RECORD_NAME_WATCOMLINKER,
            "",
            "",
        );
    }
}

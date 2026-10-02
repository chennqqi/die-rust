//! `NFD_ELF` semantic handlers — OS identification, `.comment`
//! toolchain strings, GCC/debug-data/tools fixups
//! (`handle_OperationSystem`, `handle_CommentSection`, `handle_GCC`,
//! `handle_DebugData`, `handle_Tools`).

use crate::scans::{DetectMap, ScanRecord};
use crate::{gen_names::name as n, gen_names::rtype as rt, parse, vi};

fn rec(ft: u16, rtype: u8, name: u16, ver: &str, info: &str) -> ScanRecord {
    ScanRecord {
        name,
        rtype,
        ft,
        variant: 0,
        version: ver.to_string(),
        info: info.to_string(),
        heuristic: false,
        unknown: false,
    }
}

fn emit(map: &mut DetectMap, ft: u16, rtype: u8, name: u16, ver: &str, info: &str) {
    map.entry(name)
        .or_insert_with(|| rec(ft, rtype, name, ver, info));
}

/// OSABI value → `RECORD_NAME` (`XELF::getFileFormatInfo` osabi map).
fn osabi_name(osabi: u8) -> Option<u16> {
    Some(match osabi {
        1 => n::RECORD_NAME_HPUX,
        2 => n::RECORD_NAME_NETBSD,
        3 => n::RECORD_NAME_LINUX,
        6 => n::RECORD_NAME_SOLARIS,
        7 => n::RECORD_NAME_AIX,
        8 => n::RECORD_NAME_IRIX,
        9 => n::RECORD_NAME_FREEBSD,
        10 => n::RECORD_NAME_TRU64,
        11 => n::RECORD_NAME_MODESTO,
        12 => n::RECORD_NAME_OPENBSD,
        13 => n::RECORD_NAME_OPENVMS,
        14 => n::RECORD_NAME_NSK,
        15 => n::RECORD_NAME_AROS,
        16 => n::RECORD_NAME_FENIXOS,
        18 => n::RECORD_NAME_OPENVOS,
        _ => return None,
    })
}

/// `e_machine` → `getMachinesS` string (prefix `EM_`).
fn machine_str(m: u16) -> &'static str {
    match m {
        0 => "EM_NONE",
        1 => "EM_M32",
        2 => "EM_SPARC",
        3 => "EM_386",
        4 => "EM_68K",
        5 => "EM_88K",
        7 => "EM_860",
        8 => "EM_MIPS",
        15 => "EM_PARISC",
        18 => "EM_SPARC32PLUS",
        20 => "EM_PPC",
        21 => "EM_PPC64",
        22 => "EM_S390",
        40 => "EM_ARM",
        41 => "EM_ALPHA",
        42 => "EM_SH",
        43 => "EM_SPARCV9",
        50 => "EM_IA_64",
        62 => "EM_AMD64",
        83 => "EM_AVR",
        87 => "EM_V850",
        88 => "EM_M32R",
        89 => "EM_MN10300",
        92 => "EM_OPENRISC",
        94 => "EM_XTENSA",
        106 => "EM_BLACKFIN",
        113 => "EM_ALTERA_NIOS2",
        140 => "EM_TI_C6000",
        183 => "EM_AARCH64",
        243 => "EM_RISC_V",
        258 => "EM_LOONGARCH",
        _ => "Unknown",
    }
}

/// `XBinary::getAndroidVersionFromApi`.
fn android_ver(api: u32) -> &'static str {
    match api {
        1 => "1.0",
        2 => "1.1",
        3 => "1.5",
        4 => "1.6",
        5 => "2.0",
        6 => "2.0.1",
        7 => "2.1",
        8 => "2.2.X",
        9 => "2.3-2.3.2",
        10 => "2.3.3-2.3.7",
        11 => "3.0",
        12 => "3.1",
        13 => "3.2.X",
        14 => "4.0.1-4.0.2",
        15 => "4.0.3-4.0.4",
        16 => "4.1.X",
        17 => "4.2.X",
        18 => "4.3.X",
        19 => "4.4-4.4.4",
        20 => "4.4W",
        21 => "5.0",
        22 => "5.1",
        23 => "6.0",
        24 => "7.0",
        25 => "7.1",
        26 => "8.0",
        27 => "8.1",
        28 => "9.0",
        29 => "10.0",
        30 => "11.0",
        31 => "12.0",
        32 => "12.1",
        33 => "13.0",
        34 => "14.0",
        35 => "15.0",
        36 => "16.0",
        _ => "",
    }
}

fn u32_of(e: &parse::ElfInfo, b: &[u8], off: usize) -> Option<u32> {
    let w = b.get(off..off + 4)?;
    Some(if e.big_endian {
        u32::from_be_bytes([w[0], w[1], w[2], w[3]])
    } else {
        u32::from_le_bytes([w[0], w[1], w[2], w[3]])
    })
}

/// Ordered `.comment` extractor entry: function, record type, record
/// name (`NFD_ELF::handle_CommentSection` chain order).
type Extractor = (fn(&str) -> vi::Vi, u8, u16);

/// Run the full `NFD_ELF` semantic handler set over parsed ELF info.
pub fn elf_semantic_scan(data: &[u8], ft: u16, misc: &mut DetectMap) {
    let Some(e) = parse::elf_info(data) else {
        return;
    };

    // ---- handle_OperationSystem (XELF::getFileFormatInfo) ----
    let mut os = osabi_name(e.osabi).unwrap_or(n::RECORD_NAME_UNIX);
    let mut osver = String::new();
    if os == n::RECORD_NAME_UNIX && e.interp.contains("ld-elf.so") {
        os = n::RECORD_NAME_FREEBSD;
    }
    if os == n::RECORD_NAME_UNIX && e.interp.contains("linux") {
        os = n::RECORD_NAME_LINUX;
    }
    if os == n::RECORD_NAME_UNIX && e.interp.contains("ldqnx") {
        os = n::RECORD_NAME_QNX;
    }
    if os == n::RECORD_NAME_UNIX && e.interp.contains("uClibc") {
        os = n::RECORD_NAME_MCLINUX;
    }
    if os == n::RECORD_NAME_UNIX || os == n::RECORD_NAME_LINUX {
        for c in &e.comments {
            let found = if c.contains("Ubuntu") || c.contains("ubuntu") {
                os = n::RECORD_NAME_UBUNTULINUX;
                if c.contains("ubuntu1~") {
                    osver = vi::section(&vi::section(c, "ubuntu1~", 1, -1), ")", 0, 0);
                }
                true
            } else if c.contains("Debian") || c.contains("debian") {
                os = n::RECORD_NAME_DEBIANLINUX;
                true
            } else if c.contains("StartOS") {
                os = n::RECORD_NAME_STARTOSLINUX;
                true
            } else if c.contains("Gentoo") {
                os = n::RECORD_NAME_GENTOOLINUX;
                true
            } else if c.contains("Alpine") {
                os = n::RECORD_NAME_ALPINELINUX;
                true
            } else if c.contains("Wind River Linux") {
                os = n::RECORD_NAME_WINDRIVERLINUX;
                true
            } else if c.contains("SuSE") || c.contains("SUSE Linux") {
                os = n::RECORD_NAME_SUSELINUX;
                true
            } else if c.contains("Mandrakelinux")
                || c.contains("Linux-Mandrake")
                || c.contains("Mandrake Linux")
            {
                os = n::RECORD_NAME_MANDRAKELINUX;
                true
            } else if c.contains("ASPLinux") {
                os = n::RECORD_NAME_ASPLINUX;
                true
            } else if c.contains("Red Hat") {
                os = n::RECORD_NAME_REDHATLINUX;
                true
            } else if c.contains("Hancom Linux") {
                os = n::RECORD_NAME_HANCOMLINUX;
                true
            } else if c.contains("TurboLinux") {
                os = n::RECORD_NAME_TURBOLINUX;
                true
            } else if c.contains("Vine Linux") {
                os = n::RECORD_NAME_VINELINUX;
                true
            } else {
                false
            };
            if os != n::RECORD_NAME_LINUX && c.contains("SunOS") {
                os = n::RECORD_NAME_SUNOS;
                if c.contains("@(#)SunOS ") {
                    osver = vi::section(c, "@(#)SunOS ", 1, -1);
                }
            }
            if found {
                break;
            }
        }
    }
    if os == n::RECORD_NAME_FREEBSD {
        for c in &e.comments {
            if c.contains("FreeBSD: release/") {
                osver = vi::section(&vi::section(c, "FreeBSD: release/", 1, -1), "/", 0, 0);
            }
        }
    }
    if os == n::RECORD_NAME_UNIX {
        if let Some(note) = e.notes.iter().find(|(nm, _)| nm == "Android") {
            os = n::RECORD_NAME_ANDROID;
            if let Some(sdk) = u32_of(&e, &note.1, 0) {
                osver = android_ver(sdk).to_string();
            }
        } else if e.needed.iter().any(|l| l == "liblog.so")
            || e.interp == "system/bin/linker"
            || e.interp == "system/bin/linker64"
        {
            os = n::RECORD_NAME_ANDROID;
        }
    }
    // GNU ABI tag note (type 1, name "GNU").
    if let Some((_, desc)) = e.notes.iter().find(|(nm, _)| nm == "GNU")
        && desc.len() >= 16
    {
        let nos = u32_of(&e, desc, 0).unwrap_or(0);
        if os == n::RECORD_NAME_UNIX {
            os = match nos {
                0 => n::RECORD_NAME_LINUX,
                2 => n::RECORD_NAME_SOLARIS,
                3 => n::RECORD_NAME_FREEBSD,
                4 => n::RECORD_NAME_NETBSD,
                5 => n::RECORD_NAME_SYLLABLE,
                _ => os,
            };
        }
        let abi = format!(
            "ABI: {}.{}.{}",
            u32_of(&e, desc, 4).unwrap_or(0),
            u32_of(&e, desc, 8).unwrap_or(0),
            u32_of(&e, desc, 12).unwrap_or(0)
        );
        osver = if osver.is_empty() {
            abi
        } else {
            format!("{osver}, {abi}")
        };
    }
    if os == n::RECORD_NAME_UNIX {
        let sec_present = |s: &str| e.sections.iter().any(|x| x.name == s);
        if sec_present(".note.android.ident") {
            os = n::RECORD_NAME_ANDROID;
        } else if sec_present(".note.minix.ident") {
            os = n::RECORD_NAME_MINIX;
        } else if sec_present(".note.netbsd.ident") {
            os = n::RECORD_NAME_NETBSD;
        } else if sec_present(".note.openbsd.ident") {
            os = n::RECORD_NAME_OPENBSD;
        }
    }
    if os == n::RECORD_NAME_UNIX {
        osver = format!("{}", e.osabi);
    }
    // sInfo = "arch, mode, type" (+ ", big" for BE).
    let machine = crate::parse::rd_u16_be_le(data, 0x12, e.big_endian);
    let etype = crate::parse::rd_u16_be_le(data, 0x10, e.big_endian).unwrap_or(0);
    let type_str = match etype {
        1 => "REL",
        2 => "EXEC",
        3 => "DYN",
        4 => "CORE",
        _ => "Unknown",
    };
    let mut info = format!(
        "{}, {}, {}",
        machine_str(machine.unwrap_or(0)),
        if e.is64 { "64-bit" } else { "32-bit" },
        type_str
    );
    if e.big_endian {
        info.push_str(", big");
    }
    emit(misc, ft, rt::RECORD_TYPE_OPERATIONSYSTEM, os, &osver, &info);

    // ---- handle_CommentSection — ordered extractor chain ----
    let mut comment_detects = DetectMap::new();
    for c in &e.comments {
        let chain: &[Extractor] = &[
            (
                vi::byteguard,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_BYTEGUARD,
            ),
            (vi::gcc, rt::RECORD_TYPE_COMPILER, n::RECORD_NAME_GCC),
            (
                vi::apple_llvm,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_APPLELLVM,
            ),
            (
                vi::android_clang,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_ANDROIDCLANG,
            ),
            (
                vi::alipay_clang,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_ALIPAYCLANG,
            ),
            (
                vi::alpine_clang,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_ALPINECLANG,
            ),
            (
                vi::alibaba_clang,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_ALIBABACLANG,
            ),
            (
                vi::plex_clang,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_PLEXCLANG,
            ),
            (
                vi::ubuntu_clang,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_UBUNTUCLANG,
            ),
            (
                vi::debian_clang,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_DEBIANCLANG,
            ),
            (
                vi::apportable_clang,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_APPORTABLECLANG,
            ),
            (
                vi::arm_assembler,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_ARMASSEMBLER,
            ),
            (
                vi::arm_linker,
                rt::RECORD_TYPE_LINKER,
                n::RECORD_NAME_ARMLINKER,
            ),
            (vi::arm_c, rt::RECORD_TYPE_COMPILER, n::RECORD_NAME_ARMC),
            (
                vi::arm_ccpp,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_ARMCCPP,
            ),
            (
                vi::arm_neon_ccpp,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_ARMNEONCCPP,
            ),
            (
                vi::arm_thumb_ccpp,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_ARMTHUMBCCPP,
            ),
            (
                vi::arm_thumb_macro_assembler,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_ARMTHUMBMACROASSEMBLER,
            ),
            (vi::thumb_c, rt::RECORD_TYPE_COMPILER, n::RECORD_NAME_THUMBC),
            (vi::clang, rt::RECORD_TYPE_COMPILER, n::RECORD_NAME_CLANG),
            (vi::dynasm, rt::RECORD_TYPE_COMPILER, n::RECORD_NAME_DYNASM),
            (
                vi::delphi,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI,
            ),
            (vi::lld, rt::RECORD_TYPE_LINKER, n::RECORD_NAME_LLD),
            (vi::mold, rt::RECORD_TYPE_LINKER, n::RECORD_NAME_MOLD),
            (
                vi::oracle_solaris,
                rt::RECORD_TYPE_LINKER,
                n::RECORD_NAME_ORACLESOLARISLINKEDITORS,
            ),
            (
                vi::sun_workshop,
                rt::RECORD_TYPE_TOOL,
                n::RECORD_NAME_SUNWORKSHOP,
            ),
            (
                vi::sun_workshop_compilers,
                rt::RECORD_TYPE_TOOL,
                n::RECORD_NAME_SUNWORKSHOPCOMPILERS,
            ),
            (
                vi::snapdragon_llvm_arm,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_SNAPDRAGONLLVMARM,
            ),
            (vi::nasm, rt::RECORD_TYPE_COMPILER, n::RECORD_NAME_NASM),
            (
                vi::tencent_legu,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_TENCENTLEGU,
            ),
            (
                vi::alipay_obfuscator,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_ALIPAYOBFUSCATOR,
            ),
            (
                vi::wangzehua_llvm,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_WANGZEHUALLVM,
            ),
            (
                vi::obfuscator_llvm,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_OBFUSCATORLLVM,
            ),
            (
                vi::nagain_llvm,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_NAGAINLLVM,
            ),
            (
                vi::ijiami,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_IJIAMILLVM,
            ),
            (
                vi::safeengine_llvm,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_SAFEENGINELLVM,
            ),
            (
                vi::tencent_obfuscation,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_TENCENTPROTECTION,
            ),
            (vi::appimage, rt::RECORD_TYPE_TOOL, n::RECORD_NAME_APPIMAGE),
            (
                vi::hikari,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_HIKARIOBFUSCATOR,
            ),
            (
                vi::snap_protect,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_SNAPPROTECT,
            ),
            (
                vi::bytedance_sec,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_BYTEDANCESECCOMPILER,
            ),
            (
                vi::dingbaozeng,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR,
            ),
            (
                vi::ollvm_tll,
                rt::RECORD_TYPE_PROTECTOR,
                n::RECORD_NAME_OLLVMTLL,
            ),
        ];
        let mut matched = false;
        for (f, rt_id, name_id) in chain {
            if matched {
                break;
            }
            let v = f(c);
            if v.valid {
                emit(
                    &mut comment_detects,
                    ft,
                    *rt_id,
                    *name_id,
                    &v.version,
                    &v.info,
                );
                matched = true;
            }
        }
        // Sourcery CodeBench + Rust run unconditionally.
        let (v, lite) = vi::sourcery_codebench(c);
        if v.valid {
            let nm = if lite {
                n::RECORD_NAME_SOURCERYCODEBENCHLITE
            } else {
                n::RECORD_NAME_SOURCERYCODEBENCH
            };
            emit(
                &mut comment_detects,
                ft,
                rt::RECORD_TYPE_TOOL,
                nm,
                &v.version,
                "",
            );
        }
        let v = vi::rust(c);
        if v.valid {
            emit(
                &mut comment_detects,
                ft,
                rt::RECORD_TYPE_COMPILER,
                n::RECORD_NAME_RUST,
                &v.version,
                "",
            );
        }
    }

    // handle_Tools moves comment detects into the result categories;
    // keep them grouped by their RECORD_TYPE when draining.
    for r in comment_detects.values() {
        misc.entry(r.name).or_insert_with(|| r.clone());
    }

    // ---- handle_GCC — .gcc_except_table fallback ----
    if !misc.contains_key(&n::RECORD_NAME_GCC)
        && e.sections.iter().any(|s| s.name == ".gcc_except_table")
    {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_GCC,
            "",
            "",
        );
    }

    // ---- handle_DebugData ----
    if let Some(sym) = e.sections.iter().find(|s| s.typ == 2) {
        // SHT_SYMTAB
        if let Some(count) = sym.size.checked_div(sym.entsize.max(1))
            && count > 0
        {
            emit(
                misc,
                ft,
                rt::RECORD_TYPE_DEBUGDATA,
                n::RECORD_NAME_SYMBOLTABLE,
                "",
                &format!("{}, {} symbols", sym.name, count),
            );
        }
    }
    let has = |s: &str| e.sections.iter().any(|x| x.name == s);
    if has(".stab") && has(".stabstr") {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_DEBUGDATA,
            n::RECORD_NAME_STABSDEBUGINFO,
            "",
            "",
        );
    }
    if let Some(dbg) = e.sections.iter().find(|s| s.name == ".debug_info")
        && dbg.size > 8
        && let Some(v) = crate::parse::rd_u16_be_le(data, dbg.off + 4, e.big_endian)
        && v <= 7
    {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_DEBUGDATA,
            n::RECORD_NAME_DWARFDEBUGINFO,
            &format!("{v}.0"),
            "",
        );
    }

    // ---- handle_Tools ----
    // Qt: .qtversion (u32/u64 version field) else .qtplugin string else
    // DT_NEEDED lib names.
    if let Some(qt) = e.sections.iter().find(|s| s.name == ".qtversion") {
        let mut ver = String::new();
        let v = if e.is64 && qt.size == 16 {
            crate::parse::rd_u64_be_le(data, qt.off + 8, e.big_endian)
        } else if !e.is64 && qt.size == 8 {
            crate::parse::rd_u32_be_le(data, qt.off + 4, e.big_endian).map(|x| x as u64)
        } else {
            None
        };
        if let Some(v) = v.filter(|v| *v != 0) {
            let lo = (v & 0xFFFF_FFFF) as u32;
            ver = if e.is64 {
                format!(
                    "{}.{}.{}.{}.{}.{}",
                    (v >> 48) & 0xFFFF,
                    (v >> 40) & 0xFF,
                    (v >> 32) & 0xFF,
                    (v >> 16) & 0xFFFF,
                    (v >> 8) & 0xFF,
                    v & 0xFF
                )
            } else {
                format!("{}.{}.{}", (lo >> 16) & 0xFFFF, (lo >> 8) & 0xFF, lo & 0xFF)
            };
        }
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_QT,
            &ver,
            "",
        );
    } else if let Some(qp) = e.sections.iter().find(|s| s.name == ".qtplugin") {
        let mut ver = String::new();
        if let Some(s) = parse::read_ansi_string(data, qp.off) {
            // regExp("version=(.*?)\\\n") → substring between "version=" and "\n"
            if let Some(pos) = s.find("version=") {
                let rest = &s[pos + 8..];
                ver = rest.split('\n').next().unwrap_or("").to_string();
            }
        }
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_QT,
            &ver,
            "",
        );
    } else if e.needed.iter().any(|l| l == "libQt5Core.so.5") {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_QT,
            "5.X",
            "",
        );
    } else if e
        .needed
        .iter()
        .any(|l| l == "libQt6Core_x86.so" || l == "libQt6Core.so.6")
    {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_LIBRARY,
            n::RECORD_NAME_QT,
            "6.X",
            "",
        );
    }
    // Android SDK/NDK from the "Android" note.
    if let Some((_, desc)) = e.notes.iter().find(|(nm, _)| nm == "Android") {
        let mut sdk_ver = String::new();
        if let Some(sdk) = u32_of(&e, desc, 0) {
            sdk_ver = format!("API {}(Android {})", sdk, android_ver(sdk));
        }
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_ANDROIDSDK,
            &sdk_ver,
            "",
        );
        let mut ndk_ver = String::new();
        if desc.len() >= 4 + 128 {
            let ndk = parse::read_ansi_string(&desc.clone(), 4).unwrap_or_default();
            let build = parse::read_ansi_string(&desc.clone(), 4 + 64).unwrap_or_default();
            ndk_ver = format!("{ndk}({build})");
        }
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_TOOL,
            n::RECORD_NAME_ANDROIDNDK,
            &ndk_ver,
            "",
        );
    }
    // Go note.
    if e.notes.iter().any(|(nm, _)| nm == "Go") {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_COMPILER,
            n::RECORD_NAME_GO,
            "",
            "",
        );
    }
    // gold linker via .note.gnu.gold-version section ("gold X.Y" string).
    if let Some(g) = e
        .sections
        .iter()
        .find(|s| s.name == ".note.gnu.gold-version")
    {
        let mut ver = String::new();
        if let Some(off) = parse::find_ansi(data, g.off, g.size.min(4096), b"gold ")
            && let Some(s) = parse::read_ansi_string(data, off)
        {
            ver = vi::section(&s, " ", 1, 1);
        }
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_LINKER,
            n::RECORD_NAME_GOLD,
            &ver,
            "",
        );
    }
    // .NET Core self-contained deployment marker.
    if e.runpath == "$ORIGIN/netcoredeps" {
        emit(
            misc,
            ft,
            rt::RECORD_TYPE_LOADER,
            n::RECORD_NAME_DOTNET,
            "",
            "",
        );
    }
}

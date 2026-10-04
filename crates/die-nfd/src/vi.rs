//! `VI_STRUCT` string extractors ported from
//! `NFD_Binary::_get_*_string` (SpecAbstract `nfd_binary.cpp`).

/// Version+info pair (`NFD_Binary::VI_STRUCT`).
#[derive(Debug, Default, Clone)]
pub struct Vi {
    /// Extraction succeeded.
    pub valid: bool,
    /// Version string.
    pub version: String,
    /// Info string.
    pub info: String,
}

/// `QString::section(sep, start, end)`: split on `sep`, index range
/// `[start, end]`; negative indices count from the end. Empty fields
/// are kept, mirroring `QString::SectionDefault` (without
/// `SectionSkipEmpty`).
pub fn section(s: &str, sep: &str, start: i64, end: i64) -> String {
    let fields: Vec<&str> = s.split(sep).collect();
    let n = fields.len() as i64;
    let a = if start < 0 { n + start } else { start };
    let b = if end < 0 { n + end } else { end };
    if a < 0 || a >= n || b < a {
        return String::new();
    }
    fields[a as usize..=(b.min(n - 1)) as usize].join(sep)
}

fn vi(version: String) -> Vi {
    Vi {
        valid: true,
        version,
        info: String::new(),
    }
}

fn vi_full(version: String, info: String) -> Vi {
    Vi {
        valid: true,
        version,
        info,
    }
}

fn none() -> Vi {
    Vi::default()
}

/// `_get_GCC_string`.
pub fn gcc(s: &str) -> Vi {
    if !s.contains("GCC:") {
        return none();
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
    let version = if s.contains("(experimental)") || s.contains("(prerelease)") {
        section(s, " ", -3, -1)
    } else if s.contains("(GNU) c ") {
        section(s, "(GNU) c ", 1, -1)
    } else if s.contains("GNU") {
        section(s, " ", 2, -1)
    } else if s.contains("Rev1, Built by MSYS2 project") {
        section(s, " ", -2, -1)
    } else if s.contains("(Ubuntu ") {
        section(&section(s, ") ", 1, 1), " ", 0, 0)
    } else if s.contains("StartOS)") {
        section(&section(s, ")", 1, 1), " ", 0, 0)
    } else if s.contains("GCC: (c) ") {
        section(s, "GCC: (c) ", 1, 1)
    } else {
        section(s, " ", -1, -1)
    };
    vi_full(version, info.to_string())
}

/// `_get_ByteGuard_string`.
pub fn byteguard(s: &str) -> Vi {
    for pat in ["ByteGuard ", "Byteguard "] {
        if s.contains(pat) {
            return vi(section(
                &section(&section(s, pat, 1, 1), "-", 0, 0),
                ")",
                0,
                0,
            ));
        }
    }
    none()
}

/// `_get_AppleLLVM_string`.
pub fn apple_llvm(s: &str) -> Vi {
    if s.contains("Apple LLVM version") {
        vi(section(&section(s, "Apple LLVM version ", 1, 1), " ", 0, 0))
    } else {
        none()
    }
}

/// `_get_AndroidClang_string`.
pub fn android_clang(s: &str) -> Vi {
    if s.contains("Android clang") {
        vi(section(s, " ", 3, 3))
    } else if s.contains("Android (") && s.contains(" clang version ") {
        vi(section(&section(s, " clang version ", 1, 1), " ", 0, 0))
    } else {
        none()
    }
}

/// `_get_AlipayClang_string`.
pub fn alipay_clang(s: &str) -> Vi {
    if s.contains("Alipay clang") {
        vi(section(s, " ", 3, 3))
    } else {
        none()
    }
}

/// `_get_AlpineClang_string`.
pub fn alpine_clang(s: &str) -> Vi {
    if s.contains("Alpine clang") {
        vi(section(s, " ", 3, 3))
    } else {
        none()
    }
}

/// `_get_AlibabaClang_string`.
pub fn alibaba_clang(s: &str) -> Vi {
    if s.contains("Alibaba clang") {
        vi(section(s, " ", 3, 3))
    } else {
        none()
    }
}

/// `_get_PlexClang_string`.
pub fn plex_clang(s: &str) -> Vi {
    if s.contains("Plex clang") {
        vi(section(s, " ", 3, 3))
    } else {
        none()
    }
}

/// `_get_UbuntuClang_string`.
pub fn ubuntu_clang(s: &str) -> Vi {
    if s.contains("Ubuntu clang") {
        vi(section(s, " ", 3, 3))
    } else {
        none()
    }
}

/// `_get_DebianClang_string`.
pub fn debian_clang(s: &str) -> Vi {
    if s.contains("Debian clang") {
        vi(section(s, " ", 3, 3))
    } else {
        none()
    }
}

/// `_get_ApportableClang_string`.
pub fn apportable_clang(s: &str) -> Vi {
    if s.contains("Apportable clang version") {
        vi(section(s, " ", 3, 3))
    } else {
        none()
    }
}

/// `_get_ARMAssembler_string`.
pub fn arm_assembler(s: &str) -> Vi {
    if s.contains("ARM Assembler,") {
        vi(section(s, ", ", 1, -1))
    } else {
        none()
    }
}

/// `_get_ARMLinker_string`.
pub fn arm_linker(s: &str) -> Vi {
    if s.contains("ARM Linker,") {
        vi(format!("{}]", section(&section(s, ", ", 1, -1), "]", 0, 0)))
    } else {
        none()
    }
}

/// `_get_ARMC_string`.
pub fn arm_c(s: &str) -> Vi {
    if s.contains("ARM C Compiler,") {
        vi(section(s, ", ", 1, -1))
    } else {
        none()
    }
}

/// `_get_ARMCCPP_string`.
pub fn arm_ccpp(s: &str) -> Vi {
    if s.contains("ARM C/C++ Compiler,") {
        vi(section(s, ", ", 1, -1))
    } else {
        none()
    }
}

/// `_get_ARMNEONCCPP_string`.
pub fn arm_neon_ccpp(s: &str) -> Vi {
    if s.contains("ARM NEON C/C++ Compiler,") {
        vi(section(s, ", ", 1, -1))
    } else {
        none()
    }
}

/// `_get_ARMThumbCCPP_string`.
pub fn arm_thumb_ccpp(s: &str) -> Vi {
    if s.contains("ARM/Thumb C/C++ Compiler,") {
        vi(section(s, ", ", 1, -1))
    } else {
        none()
    }
}

/// `_get_ARMThumbMacroAssembler_string`.
pub fn arm_thumb_macro_assembler(s: &str) -> Vi {
    if !s.contains("ARM/Thumb Macro Assembler") {
        return none();
    }
    if s.contains("vsn ") {
        vi(section(s, "vsn ", 1, -1))
    } else {
        vi(section(s, ", ", 1, -1))
    }
}

/// `_get_ThumbC_string`.
pub fn thumb_c(s: &str) -> Vi {
    if s.contains("Thumb C Compiler,") {
        vi(section(s, ", ", 1, -1))
    } else {
        none()
    }
}

/// `_get_clang_string` (`^clang version`).
pub fn clang(s: &str) -> Vi {
    if s.starts_with("clang version") {
        vi(section(s, " ", 2, 2))
    } else {
        none()
    }
}

/// `_get_DynASM_string`.
pub fn dynasm(s: &str) -> Vi {
    if s.contains("DynASM") {
        vi(section(s, " ", 1, 1))
    } else {
        none()
    }
}

/// `_get_Delphi_string` (`^Embarcadero Delphi for`).
pub fn delphi(s: &str) -> Vi {
    if s.starts_with("Embarcadero Delphi for") {
        vi(section(s, "version ", 1, 1))
    } else {
        none()
    }
}

/// `_get_LLD_string` (`^Linker: LLD`).
pub fn lld(s: &str) -> Vi {
    if s.starts_with("Linker: LLD") {
        vi(section(&section(s, "Linker: LLD ", 1, 1), "(", 0, 0))
    } else {
        none()
    }
}

/// `_get_mold_string` (`^mold `).
pub fn mold(s: &str) -> Vi {
    if s.starts_with("mold ") {
        vi(String::new())
    } else {
        none()
    }
}

/// `_get_OracleSolarisLinkEditors_string`.
pub fn oracle_solaris(s: &str) -> Vi {
    if s.starts_with("ld: Software Generation Utilities - Solaris Link Editors:") {
        vi(section(s, "Solaris Link Editors: ", 1, 1))
    } else {
        none()
    }
}

/// `_get_SunWorkShop_string`.
pub fn sun_workshop(s: &str) -> Vi {
    if s.contains("Sun WorkShop") {
        let v = section(&section(s, "Sun WorkShop ", 1, 1), " ", 0, 1);
        vi(section(&section(&v, "\r", 0, 0), "\n", 0, 0))
    } else {
        none()
    }
}

/// `_get_SunWorkShopCompilers_string`.
pub fn sun_workshop_compilers(s: &str) -> Vi {
    if s.contains("WorkShop Compilers") {
        let v = section(s, "WorkShop Compilers ", 1, 1);
        vi(section(&section(&v, "\r", 0, 0), "\n", 0, 0))
    } else {
        none()
    }
}

/// `_get_SnapdragonLLVMARM_string`.
pub fn snapdragon_llvm_arm(s: &str) -> Vi {
    if s.starts_with("Snapdragon LLVM ARM Compiler") {
        vi(section(s, " ", 4, 4))
    } else {
        none()
    }
}

/// `_get_NASM_string` (`^The Netwide Assembler`).
pub fn nasm(s: &str) -> Vi {
    if s.starts_with("The Netwide Assembler") {
        vi(section(s, "The Netwide Assembler ", 1, 1))
    } else {
        none()
    }
}

/// `_get_TencentLegu_string` (`^legu`).
pub fn tencent_legu(s: &str) -> Vi {
    if s.starts_with("legu") {
        vi(String::new())
    } else {
        none()
    }
}

/// `_get_AlipayObfuscator_string`.
pub fn alipay_obfuscator(s: &str) -> Vi {
    if s.contains("Alipay") {
        let mut v = vi(section(s, " ", 3, 3));
        if s.contains("Trial") {
            v.info = "Trial".to_string();
        }
        v
    } else {
        none()
    }
}

/// `_get_wangzehuaLLVM_string`.
pub fn wangzehua_llvm(s: &str) -> Vi {
    if s.contains("wangzehua  clang version") {
        vi(section(s, "wangzehua  clang version", 1, 1))
    } else {
        none()
    }
}

/// `_get_ObfuscatorLLVM_string`.
pub fn obfuscator_llvm(s: &str) -> Vi {
    if s.contains("Obfuscator-clang version")
        || s.contains("Obfuscator- clang version")
        || s.contains("Obfuscator-LLVM clang version")
    {
        let v = section(&section(s, "version ", 1, 1), "(", 0, 0);
        vi(section(&v, " ", 0, 0))
    } else {
        none()
    }
}

/// `_get_NagainLLVM_string`.
pub fn nagain_llvm(s: &str) -> Vi {
    if s.contains("Nagain-LLVM clang version") {
        vi(section(s, " ", 3, 3))
    } else {
        none()
    }
}

/// `_get_iJiami_string`.
pub fn ijiami(s: &str) -> Vi {
    if s.contains("ijiami LLVM Compiler- clang version") {
        vi(section(s, " ", 5, 5))
    } else {
        none()
    }
}

/// `_get_SafeengineLLVM_string`.
pub fn safeengine_llvm(s: &str) -> Vi {
    if s.contains("Safengine clang version") {
        vi(section(s, " ", 3, 3))
    } else {
        none()
    }
}

/// `_get_TencentObfuscation_string`.
pub fn tencent_obfuscation(s: &str) -> Vi {
    if s.contains("Tencent-Obfuscation Compiler") {
        vi(String::new())
    } else {
        none()
    }
}

/// `_get_AppImage_string`.
pub fn appimage(s: &str) -> Vi {
    if s.contains("AppImage") {
        vi(String::new())
    } else {
        none()
    }
}

/// `_get_HikariObfuscator_string`.
pub fn hikari(s: &str) -> Vi {
    if s.contains("HikariObfuscator") || s.contains("_Hikari") || s.contains("Hikari.git") {
        vi(String::new())
    } else {
        none()
    }
}

/// `_get_SnapProtect_string`.
pub fn snap_protect(s: &str) -> Vi {
    if s.contains("snap.protect version ") {
        vi(section(
            &section(s, "snap.protect version ", 1, 1),
            " ",
            0,
            0,
        ))
    } else {
        none()
    }
}

/// `_get_ByteDanceSecCompiler_string`.
pub fn bytedance_sec(s: &str) -> Vi {
    if s.contains("ByteDance-SecCompiler") {
        vi(String::new())
    } else {
        none()
    }
}

/// `_get_DingbaozengNativeObfuscator_string`.
pub fn dingbaozeng(s: &str) -> Vi {
    if s.contains("dingbaozeng/native_obfuscator.git") {
        vi(String::new())
    } else {
        none()
    }
}

/// `_get_OllvmTll_string`.
pub fn ollvm_tll(s: &str) -> Vi {
    if s.contains("ollvm-tll.git") {
        vi(String::new())
    } else {
        none()
    }
}

/// `_get_SourceryCodeBench_string` (runs unconditionally upstream).
pub fn sourcery_codebench(s: &str) -> (Vi, bool) {
    if s.contains("Sourcery CodeBench Lite ") {
        let v = section(&section(s, "Sourcery CodeBench Lite ", 1, 1), ")", 0, 0);
        (vi(v), true)
    } else if s.contains("Sourcery CodeBench ") {
        let v = section(&section(s, "Sourcery CodeBench ", 1, 1), ")", 0, 0);
        (vi(v), false)
    } else {
        (none(), false)
    }
}

/// `_get_Rust_string` (`^rustc `, runs unconditionally upstream).
pub fn rust(s: &str) -> Vi {
    if s.starts_with("rustc ") {
        vi(section(&section(s, "rustc version ", 1, 1), " ", 0, 0))
    } else {
        none()
    }
}

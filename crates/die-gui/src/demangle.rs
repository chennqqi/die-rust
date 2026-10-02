//! Demangle backend for die-gui (upstream `XDemangle` alignment, Phase 17.A).
//!
//! Upstream `XDemangle` supports 20 `MODE_*` values (see
//! `docs/research/gui-gap-analysis-v4.md` V4-10). This module implements a
//! subset with faithful `detectMode` porting and per-mode dispatch:
//!
//! | Mode            | Backend                              |
//! |-----------------|--------------------------------------|
//! | MSVC*           | `msvc-demangler` crate               |
//! | GNU_V3/GCC_*/BORLAND64 | `cpp_demangle` (Itanium ABI)  |
//! | RUST            | `rustc-demangle`                     |
//! | DLANG           | built-in simplified D decoder        |
//! | JAVA            | built-in JNI-style decoder           |
//! | BORLAND32       | built-in simplified `@`-segment decoder |
//! | WATCOM          | built-in simplified `W?` decoder     |
//! | GNU_V2/GNAT/SWIFT/GO/HASKELL/OCAML/TRU64/SUN | built-in simplified decoders (Phase 18.A) |

use serde::{Deserialize, Serialize};

/// Demangle mode, mirrors the subset of upstream `XDemangle::MODE` that is
/// implemented. Names match upstream enum names (lowercased).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DemangleMode {
    /// Automatic detection via `detect_mode` (upstream `MODE_AUTO`).
    Auto,
    /// Generic MSVC (`?...@@` scheme).
    Msvc,
    /// MSVC x86.
    Msvc32,
    /// MSVC x64.
    Msvc64,
    /// MSVC ARM32.
    MsvcArm32,
    /// MSVC ARM64.
    MsvcArm64,
    /// Itanium ABI (GCC v3+, `_Z` prefix).
    GnuV3,
    /// Itanium with Windows `@` decorations (`@_Z..` / `_Z..@N`).
    GccWin,
    /// Itanium with Mach-O `__Z` prefix.
    GccMac,
    /// Borland 32-bit (`@...$q` scheme) — simplified decoder.
    Borland32,
    /// Borland 64-bit (Itanium ABI).
    Borland64,
    /// Watcom (`W?...` scheme) — simplified decoder.
    Watcom,
    /// Rust (legacy `ZN`/`_R` and v0 `_R` schemes).
    Rust,
    /// GNAT/Ada (`_ada_` prefix) — simplified decoder.
    Gnat,
    /// D language (`_D` prefix) — simplified decoder.
    Dlang,
    /// Swift (`$s`/`_$s` prefix) — simplified decoder.
    Swift,
    /// Go symbol conventions — escape/separator normalizer.
    Go,
    /// Haskell (`zi` + `_closure`/`_info`/`_entry`) — z-encoding decoder.
    Haskell,
    /// OCaml (`caml` prefix) — simplified decoder.
    Ocaml,
    /// DEC/Compaq Tru64 (`__X` marker) — simplified decoder.
    Tru64,
    /// SunPro / Sun Studio (`__1c` scheme) — simplified decoder.
    Sun,
    /// GNU v2 (`__vt_`/`__F`/`__Q` style) — simplified decoder.
    GnuV2,
    /// Java / JNI (`Java_` prefix) — simplified decoder.
    Java,
    /// Unrecognized symbol.
    Unknown,
}

impl DemangleMode {
    /// Parse a mode name (case-insensitive). Accepts upstream enum spellings
    /// plus legacy aliases kept for backward compatibility:
    /// `"cpp"`/`"itanium"` -> `GnuV3`, `"d"` -> `Dlang`, `"borland"` ->
    /// `Borland32`.
    pub fn parse(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "auto" => Self::Auto,
            "msvc" => Self::Msvc,
            "msvc32" => Self::Msvc32,
            "msvc64" => Self::Msvc64,
            "msvcarm32" | "msvc_arm32" => Self::MsvcArm32,
            "msvcarm64" | "msvc_arm64" => Self::MsvcArm64,
            "gnuv3" | "gnu_v3" | "cpp" | "itanium" | "c++" => Self::GnuV3,
            "gccwin" | "gcc_win" => Self::GccWin,
            "gccmac" | "gcc_mac" => Self::GccMac,
            "borland32" | "borland" => Self::Borland32,
            "borland64" => Self::Borland64,
            "watcom" => Self::Watcom,
            "rust" => Self::Rust,
            "gnat" | "ada" => Self::Gnat,
            "dlang" | "d" => Self::Dlang,
            "swift" => Self::Swift,
            "go" | "golang" => Self::Go,
            "haskell" => Self::Haskell,
            "ocaml" => Self::Ocaml,
            "tru64" => Self::Tru64,
            "sun" | "sunpro" => Self::Sun,
            "gnuv2" | "gnu_v2" => Self::GnuV2,
            "java" | "jni" => Self::Java,
            _ => Self::Unknown,
        }
    }
}

/// Detect the demangle mode of a symbol, faithful port of upstream
/// `XDemangle::detectMode` (xdemangle.cpp, commit 16165988).
pub fn detect_mode(s: &str) -> DemangleMode {
    if (s.starts_with('?') || s.starts_with(".?")) && s.contains('@') {
        return DemangleMode::Msvc;
    }
    if s.starts_with("W?") {
        return DemangleMode::Watcom;
    }
    if s.starts_with('@') && (s.contains("$q") || s.contains("$b")) {
        return DemangleMode::Borland32;
    }
    if s.starts_with("_R") || s.starts_with("__R") {
        return DemangleMode::Rust;
    }
    // Legacy Rust and C++ both use _ZN. A terminal Rust hash identifies the
    // Rust form; otherwise retain the ordinary Itanium interpretation.
    if (s.starts_with("_ZN") || s.starts_with("__ZN"))
        && let Some(n_hash) = s.rfind("17h")
        && n_hash + 20 == s.len()
        && s.ends_with('E')
    {
        let b_hex = s[n_hash + 3..n_hash + 19]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
        if b_hex {
            return DemangleMode::Rust;
        }
    }
    if s.starts_with("@_Z") {
        return DemangleMode::GccWin;
    }
    if s.starts_with("CXX$_Z") {
        return DemangleMode::GnuV3;
    }
    if s.starts_with("_Z") {
        let b_bytes = s
            .rfind('@')
            .map(|n_at| n_at + 1 < s.len() && s[n_at + 1..].bytes().all(|c| c.is_ascii_digit()))
            .unwrap_or(false);
        return if b_bytes {
            DemangleMode::GccWin
        } else {
            DemangleMode::GnuV3
        };
    }
    if s.starts_with("__Z") {
        return DemangleMode::GccMac;
    }
    if s == "_Dmain"
        || s.starts_with("_D__T")
        || s.starts_with("_D__U")
        || (s.starts_with("_D") && s.as_bytes().get(2).is_some_and(u8::is_ascii_digit))
    {
        return DemangleMode::Dlang;
    }
    if s.starts_with("$s") || s.starts_with("_$s") || s.starts_with("$S") || s.starts_with("_$S") {
        return DemangleMode::Swift;
    }
    if s.starts_with("_ada_") {
        return DemangleMode::Gnat;
    }
    if s.starts_with("caml") && s.as_bytes().get(4).is_some_and(u8::is_ascii_uppercase) {
        return DemangleMode::Ocaml;
    }
    if s.starts_with("__1c") {
        return DemangleMode::Sun;
    }
    if s.find("__X").is_some_and(|i| i > 0) {
        return DemangleMode::Tru64;
    }
    if s.starts_with("__vt_")
        || s.starts_with("_vt$")
        || s.starts_with("_vt.")
        || s.starts_with("_$_")
        || s.starts_with("_._")
        || s.starts_with("__ti")
        || s.starts_with("__tf")
        || s.starts_with("_GLOBAL_$I$")
        || s.starts_with("_GLOBAL_$D$")
        || s.starts_with("_GLOBAL_.I.")
        || s.starts_with("_GLOBAL_.D.")
    {
        return DemangleMode::GnuV2;
    }
    let mut idx = s.find("__");
    while let Some(n_sep) = idx {
        match s.as_bytes().get(n_sep + 2) {
            Some(b'F' | b'Q' | b'C' | b'V' | b't') | Some(b'0'..=b'9') => {
                return DemangleMode::GnuV2;
            }
            _ => {}
        }
        idx = s[n_sep + 2..].find("__").map(|i| n_sep + 2 + i);
    }
    if s.contains("zi")
        && (s.ends_with("_closure") || s.ends_with("_info") || s.ends_with("_entry"))
    {
        return DemangleMode::Haskell;
    }
    if s.starts_with("main.")
        || s.starts_with("runtime.")
        || s.starts_with("go.")
        || s.contains('\u{00b7}')
        || s.contains('\u{2215}')
    {
        return DemangleMode::Go;
    }
    DemangleMode::Unknown
}

/// Demangle a mangled symbol string.
///
/// `compiler` is a mode name accepted by [`DemangleMode::parse`] (upstream
/// mode names plus `cpp`/`rust`/`d` aliases). `"auto"` runs
/// [`detect_mode`]. Returns the original string if the detected/selected
/// mode is unimplemented or decoding fails — same fallback as upstream.
pub fn demangle_symbol(symbol: &str, compiler: &str) -> String {
    let mode = DemangleMode::parse(compiler);
    demangle_with_mode(symbol, mode)
}

/// Demangle with an explicit [`DemangleMode`]. `Auto` detects via
/// [`detect_mode`]; unimplemented modes and decode failures return the
/// input unchanged (upstream `sResult == "" -> sResult = _sString`).
pub fn demangle_with_mode(symbol: &str, mode: DemangleMode) -> String {
    let mode = match mode {
        DemangleMode::Auto => detect_mode(symbol),
        m => m,
    };
    let out = match mode {
        DemangleMode::Msvc
        | DemangleMode::Msvc32
        | DemangleMode::Msvc64
        | DemangleMode::MsvcArm32
        | DemangleMode::MsvcArm64 => {
            msvc_demangler::demangle(symbol, msvc_demangler::DemangleFlags::llvm()).ok()
        }
        DemangleMode::GnuV3 | DemangleMode::Borland64 => demangle_itanium(symbol),
        DemangleMode::GccWin => {
            // Windows Itanium: leading '@' and/or trailing '@<digits>' stdcall
            // decoration wrapped around a normal '_Z' name.
            let s = symbol.strip_prefix('@').unwrap_or(symbol);
            let s = match s.rfind('@') {
                Some(i) if s[i + 1..].bytes().all(|c| c.is_ascii_digit()) => &s[..i],
                _ => s,
            };
            demangle_itanium(s)
        }
        DemangleMode::GccMac => {
            // Mach-O prepends an extra '_' to the Itanium '_Z' prefix.
            symbol
                .strip_prefix("__Z")
                .and_then(|s| demangle_itanium(&format!("_{}", s)))
                .or_else(|| demangle_itanium(symbol))
        }
        DemangleMode::Rust => rustc_demangle::try_demangle(symbol)
            .ok()
            .map(|d| format!("{}", d)),
        DemangleMode::Dlang => demangle_dlang(symbol),
        DemangleMode::Java => demangle_java(symbol),
        DemangleMode::Borland32 => demangle_borland32(symbol),
        DemangleMode::Watcom => demangle_watcom(symbol),
        DemangleMode::Swift => demangle_swift(symbol),
        DemangleMode::Go => Some(demangle_go(symbol)),
        DemangleMode::Gnat => demangle_gnat(symbol),
        DemangleMode::Haskell => demangle_haskell(symbol),
        DemangleMode::Ocaml => demangle_ocaml(symbol),
        DemangleMode::Tru64 => demangle_tru64(symbol),
        DemangleMode::Sun => demangle_sun(symbol),
        DemangleMode::GnuV2 => demangle_gnuv2(symbol),
        _ => None,
    };
    out.unwrap_or_else(|| symbol.to_string())
}

/// Itanium ABI demangle via `cpp_demangle`; returns `None` on failure.
fn demangle_itanium(symbol: &str) -> Option<String> {
    let sym = cpp_demangle::Symbol::new(symbol).ok()?;
    sym.demangle(&cpp_demangle::DemangleOptions::default()).ok()
}

/// Simplified D ABI decoder (`_D` prefix, length-prefixed identifiers,
/// `F...Z<ret>` function signature). Covers the common
/// `_D<qualified><type-seq>` shape; exotic D encodings fall back to raw.
fn demangle_dlang(s: &str) -> Option<String> {
    let rest = s.strip_prefix("_D")?;
    if rest == "main" {
        return Some("D main".to_string());
    }
    // Length-prefixed qualified name segments until a non-digit byte.
    let b = rest.as_bytes();
    let mut i = 0usize;
    let mut parts: Vec<String> = Vec::new();
    while i < b.len() && b[i].is_ascii_digit() {
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let n: usize = rest[start..i].parse().ok()?;
        if n == 0 || i + n > rest.len() {
            return None;
        }
        parts.push(rest[i..i + n].to_string());
        i += n;
    }
    if parts.is_empty() {
        return None;
    }
    let mut out = parts.join(".");
    // Function signature: 'F' .. 'Z' <return type>.
    let tail = &rest[i..];
    if let Some(sig) = tail.strip_prefix('F')
        && let Some(zpos) = sig.find('Z')
    {
        let params = &sig[..zpos];
        let ret = &sig[zpos + 1..];
        let args = parse_dlang_args(params);
        let ret_s = ret.chars().next().map(dlang_type).unwrap_or_default();
        out = if ret_s.is_empty() {
            format!("{}({})", out, args)
        } else {
            format!("{} {}({})", ret_s, out, args)
        };
    }
    Some(out)
}

/// Decode a D parameter type sequence into a comma-separated list.
fn parse_dlang_args(sig: &str) -> String {
    sig.chars().map(dlang_type).collect::<Vec<_>>().join(", ")
}

/// Map a single D type-code character to its type name.
fn dlang_type(c: char) -> &'static str {
    match c {
        'v' => "void",
        'b' => "bool",
        'g' => "byte",
        'h' => "ubyte",
        's' => "short",
        't' => "ushort",
        'i' => "int",
        'k' => "uint",
        'l' => "long",
        'm' => "ulong",
        'n' => "cent",
        'u' => "ucent",
        'f' => "float",
        'd' => "double",
        'e' => "real",
        'o' => "ifloat",
        'p' => "idouble",
        'j' => "ireal",
        'a' => "char",
        'w' => "wchar",
        'x' => "const",
        'y' => "immutable",
        'P' => "*",
        'A' => "[]",
        'G' => "static-array",
        'H' => "assoc-array",
        'C' => "class",
        'S' => "struct",
        'E' => "enum",
        'T' => "typedef",
        _ => "?",
    }
}

/// Simplified Java/JNI decoder: `Java_<pkg>_<class>_<method>` →
/// `pkg.class.method`. Non-JNI input falls back to `None`.
fn demangle_java(s: &str) -> Option<String> {
    let rest = s.strip_prefix("Java_")?;
    let mut parts: Vec<String> = Vec::new();
    for seg in rest.split('_') {
        if seg.is_empty() {
            return None;
        }
        parts.push(seg.to_string());
    }
    (parts.len() >= 2).then(|| parts.join("."))
}

/// Simplified Borland32 decoder (`@`-delimited unit/class/method segments
/// with a `$q<params>` or `$b<kind>` tail marker). Decodes the qualified
/// name; parameter encodings are shown loosely (upstream uses a full
/// BORLAND syntax tree — documented as partial in COMPATIBILITY.md).
fn demangle_borland32(s: &str) -> Option<String> {
    let rest = s.strip_prefix('@')?;
    // Strip the '$q...' / '$b...' trailing encoding.
    let name_part = rest.split('$').next().unwrap_or(rest);
    let segs: Vec<&str> = name_part.split('@').filter(|x| !x.is_empty()).collect();
    if segs.len() < 2 {
        return None;
    }
    Some(segs.join("."))
}

/// Simplified Watcom decoder (`W?<name>$<sig>` scheme). Extracts the
/// identifier part between `W?` and the first `$` or `:` marker.
fn demangle_watcom(s: &str) -> Option<String> {
    let rest = s.strip_prefix("W?")?;
    let name: String = rest
        .chars()
        .take_while(|c| *c != '$' && *c != ':')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Shared legacy type-letter map for Sun/Tru64/GNU v2 signatures.
/// These ABIs use single-letter codes similar to but simpler than Itanium.
fn legacy_type_letter(c: char) -> &'static str {
    match c {
        'v' => "void",
        'c' => "char",
        'w' => "wchar_t",
        'b' => "bool",
        's' => "short",
        'i' => "int",
        'l' => "long",
        'f' => "float",
        'd' => "double",
        'r' => "long double",
        'e' => "...",
        'x' => "long long",
        'j' => "unsigned int",
        _ => "?",
    }
}

/// Decode a legacy single-letter parameter sequence into a joined list.
fn legacy_params(sig: &str) -> String {
    // Trim a trailing return-type segment after '_' if present is the
    // caller's job; here we map each leading type letter.
    sig.chars()
        .filter(|c| *c != '_')
        .map(legacy_type_letter)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Simplified Swift decoder: `$s`/`_$s` prefix, length-prefixed
/// identifiers (`4main`), then an optional function signature tail.
/// Handles the common `$s<mod><name>y?<types>F`/`...F` shape; exotic
/// substitutions (std shorthands, generics) fall back to raw segments.
fn demangle_swift(s: &str) -> Option<String> {
    let s = s.strip_prefix('_').unwrap_or(s);
    let rest = s.strip_prefix("$s").or_else(|| s.strip_prefix("$S"))?;
    let b = rest.as_bytes();
    let mut i = 0usize;
    let mut parts: Vec<String> = Vec::new();
    // Skip well-known entity markers.
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let n: usize = rest[start..i].parse().ok()?;
            if n == 0 || i + n > rest.len() {
                return Some(if parts.is_empty() {
                    s.to_string()
                } else {
                    parts.join(".")
                });
            }
            parts.push(rest[i..i + n].to_string());
            i += n;
        } else if b[i] == b's' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            // 's' std-module shorthand: treat like a length-prefixed name
            // already handled by the digit branch on the next byte.
            i += 1;
        } else {
            break;
        }
    }
    if parts.is_empty() {
        return None;
    }
    let tail = &rest[i..];
    let mut out = parts.join(".");
    // Function signature tail: 'y<ret>F' / '<params>F' / bare 'F'.
    if tail.contains('F') {
        let params = tail.trim_end_matches('F').trim_start_matches('y');
        if params.is_empty() {
            out.push_str("()");
        } else {
            out.push_str(&format!("({})", legacy_params_swift(params)));
        }
    }
    Some(out)
}

/// Map a subset of Swift type-letter codes to names.
fn legacy_params_swift(sig: &str) -> String {
    sig.chars()
        .map(|c| match c {
            'i' => "Int",
            'd' => "Double",
            'f' => "Float",
            'S' => "String",
            'b' => "Bool",
            _ => "?",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Simplified Go symbol normalizer: Go linker symbols are already mostly
/// readable (`main.main`, `runtime.goexit`); the decoder decodes `%NN`
/// percent escapes and normalizes mid-dot separators to `.`.
fn demangle_go(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v as char);
            i += 3;
            continue;
        }
        // Push the full (possibly multi-byte) char, not a raw byte.
        let c = s[i..].chars().next().unwrap();
        out.push(c);
        i += c.len_utf8();
    }
    out.replace(['\u{00b7}', '\u{2215}'], ".")
}

/// Simplified GNAT/Ada decoder: strip `_ada_`, split library levels on
/// `__`, and decode common `O<op>` operator encodings.
fn demangle_gnat(s: &str) -> Option<String> {
    let rest = s.strip_prefix("_ada_")?;
    let parts: Vec<String> = rest.split("__").map(gnat_op).collect();
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("."))
}

/// Decode a GNAT operator token (`Oadd` -> `"+"`, etc.); non-operator
/// segments pass through unchanged.
fn gnat_op(seg: &str) -> String {
    let table = [
        ("Oadd", "+"),
        ("Ominus", "-"),
        ("Omult", "*"),
        ("Odivide", "/"),
        ("Omod", "mod"),
        ("Orem", "rem"),
        ("Oand", "and"),
        ("Oor", "or"),
        ("Oxor", "xor"),
        ("Olt", "<"),
        ("Ole", "<="),
        ("Ogt", ">"),
        ("Oge", ">="),
        ("Oeq", "="),
        ("One", "/="),
        ("Oabs", "abs"),
        ("Onot", "not"),
        ("Oppow", "**"),
    ];
    for (enc, op) in table {
        if seg == enc {
            return format!("\"{}\"", op);
        }
    }
    seg.to_string()
}

/// Simplified Haskell (GHC z-encoding) decoder: decode `z`-escape pairs
/// and keep the `_closure`/`_info`/`_entry` kind as a suffix note.
fn demangle_haskell(s: &str) -> Option<String> {
    let (kind, base) = ["_closure", "_info", "_entry"]
        .iter()
        .find_map(|k| s.strip_suffix(k).map(|b| (*k, b)))
        .unwrap_or(("", s));
    if !base.contains("zi") && !base.contains("zt") && !base.contains("zz") {
        return None;
    }
    Some(format!("{}{}", z_decode(base), kind_suffix(kind)))
}

/// Decode GHC z-encoding escapes (`zi`=':' `zt`='*' `zz`='z' …).
fn z_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'z' && i + 1 < b.len() {
            let decoded = match b[i + 1] {
                b'a' => '&',
                b'b' => '|',
                b'c' => ':',
                b'd' => '$',
                b'e' => '=',
                b'f' => '?',
                b'g' => '>',
                b'h' => '#',
                b'i' => ':',
                b'j' => '.',
                b'l' => '<',
                b'm' => '(',
                b'n' => ')',
                b'o' => '[',
                b'p' => ']',
                b'q' => '\'',
                b'r' => ')',
                b's' => '-',
                b't' => '*',
                b'u' => '_',
                b'v' => 'v',
                b'z' => 'z',
                _ => {
                    out.push('z');
                    i += 1;
                    continue;
                }
            };
            out.push(decoded);
            i += 2;
            continue;
        }
        if b[i] == b'Z' && i + 1 < b.len() && b[i + 1].is_ascii_uppercase() {
            out.push((b[i + 1] - b'A' + b'a') as char);
            i += 2;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// Render a Haskell symbol-kind suffix as a readable note.
fn kind_suffix(kind: &str) -> &'static str {
    match kind {
        "_closure" => " [closure]",
        "_info" => " [info]",
        "_entry" => " [entry]",
        _ => "",
    }
}

/// Simplified OCaml decoder: `caml<Module>__<name>_<stamp>` →
/// `Module.name`; `caml<Module>.<field>` globals decode to `Module.field`.
fn demangle_ocaml(s: &str) -> Option<String> {
    let rest = s.strip_prefix("caml")?;
    if rest.is_empty() || !rest.as_bytes()[0].is_ascii_uppercase() {
        return None;
    }
    if let Some((module, tail)) = rest.split_once("__") {
        // Drop the trailing numeric stamp (_<digits>).
        let name = match tail.rfind('_') {
            Some(i) if tail[i + 1..].bytes().all(|c| c.is_ascii_digit()) => &tail[..i],
            _ => tail,
        };
        return Some(format!("{}.{}", module, name.replace("__", ".")));
    }
    if let Some((module, field)) = rest.split_once('.') {
        return Some(format!("{}.{}", module, field));
    }
    Some(rest.to_string())
}

/// Simplified Tru64 (Compaq C++) decoder: `name__X<params>` →
/// `name(<params>)`; `__vtbl__<name>` → `vtable for <name>`.
fn demangle_tru64(s: &str) -> Option<String> {
    if let Some(vt) = s.strip_prefix("__vtbl__") {
        return Some(format!("vtable for {}", vt));
    }
    let pos = s.find("__X").filter(|&i| i > 0)?;
    let name = &s[..pos];
    let params = &s[pos + 3..];
    Some(format!("{}({})", name, legacy_params(params)))
}

/// Simplified SunPro (Sun Studio) decoder: `__1c<L><name>6F_<sig>_`
/// where `<L>` is `'A'+name_len`, `6F` marks a function, and the
/// signature tail encodes return/parameter type letters.
fn demangle_sun(s: &str) -> Option<String> {
    let rest = s.strip_prefix("__1c")?;
    let b = rest.as_bytes();
    if b.is_empty() {
        return None;
    }
    // Length char: 'A' encodes 0, 'B' encodes 1, … (SunPro scheme).
    let len = (b[0] as usize).checked_sub(b'A' as usize)?;
    if len > 26 || 1 + len > rest.len() {
        return None;
    }
    let name = &rest[1..1 + len];
    let tail = &rest[1 + len..];
    let mut out = name.to_string();
    if let Some(sig) = tail.strip_prefix("6F") {
        let sig = sig.trim_matches('_');
        let (ret, params) = if sig.len() > 1 {
            (sig.chars().last(), &sig[..sig.len() - 1])
        } else {
            (sig.chars().next(), "")
        };
        let args = if params.is_empty() || params == "v" {
            String::new()
        } else {
            legacy_params(params)
        };
        if let Some(r) = ret {
            return Some(format!("{} {}({})", legacy_type_letter(r), out, args));
        }
        out.push_str(&format!("({})", args));
    }
    Some(out)
}

/// Simplified GNU v2 (g++ 2.x) decoder covering:
/// `__vt_<class>` vtables, `_$_<class>` destructors, `name__F<params>`
/// free functions, and `name__<class-spec>F<params>` members where
/// class-spec is `<len><name>` or `Q<n>_<len><name>...`.
fn demangle_gnuv2(s: &str) -> Option<String> {
    if let Some(rest) = s.strip_prefix("__vt_") {
        return parse_gnuv2_name(rest).map(|n| format!("vtable for {}", n));
    }
    if let Some(rest) = s.strip_prefix("_$_") {
        return parse_gnuv2_name(rest)
            .map(|n| format!("{}::~{}", n, n.rsplit("::").next().unwrap_or(&n)));
    }
    let pos = s.find("__").filter(|&i| i > 0)?;
    let name = &s[..pos];
    let tail = &s[pos + 2..];
    if let Some(sig) = tail.strip_prefix('F') {
        return Some(format!("{}({})", name, legacy_params(sig)));
    }
    // Member form: `<class-spec>F<params>` — consume the class spec first
    // so an 'F' inside the class name is not mistaken for the marker.
    let (class, used) = gnuv2_class_prefix(tail)?;
    let params = tail[used..].strip_prefix('F')?;
    Some(format!("{}::{}({})", class, name, legacy_params(params)))
}

/// Parse a GNU v2 class spec prefix: `<len><name>` or `Q<n>_<len><name>…`.
/// Returns the dotted class path and the number of bytes consumed.
fn gnuv2_class_prefix(spec: &str) -> Option<(String, usize)> {
    if let Some(q) = spec.strip_prefix('Q') {
        let n: usize = q.chars().next()?.to_digit(10)? as usize;
        let body = q[1..].strip_prefix('_').unwrap_or(&q[1..]);
        let mut parts = Vec::new();
        let mut i = 0usize;
        let b = body.as_bytes();
        while i < b.len() && parts.len() < n {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if start == i {
                return None;
            }
            let len: usize = body[start..i].parse().ok()?;
            if i + len > body.len() {
                return None;
            }
            parts.push(&body[i..i + len]);
            i += len;
        }
        if parts.len() == n {
            // consumed = 'Q' + digit + optional '_' + i bytes of body
            let sep = if q[1..].starts_with('_') { 1 } else { 0 };
            return Some((parts.join("::"), 1 + 1 + sep + i));
        }
        return None;
    }
    // `<len><name>` form.
    let digits: String = spec.chars().take_while(|c| c.is_ascii_digit()).collect();
    let len: usize = digits.parse().ok()?;
    spec.get(digits.len()..digits.len() + len)
        .map(|n| (n.to_string(), digits.len() + len))
}

/// Parse a GNU v2 length-prefixed name used by `__vt_`/`_$_` forms.
fn parse_gnuv2_name(spec: &str) -> Option<String> {
    gnuv2_class_prefix(spec)
        .map(|(n, _)| n)
        .or_else(|| Some(spec.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- detect_mode: mirrors upstream detectMode ordering --

    #[test]
    fn detect_msvc() {
        assert_eq!(detect_mode("?foo@@YAHXZ"), DemangleMode::Msvc);
        assert_eq!(detect_mode(".?AVFoo@@"), DemangleMode::Msvc);
    }

    #[test]
    fn detect_watcom() {
        assert_eq!(detect_mode("W?main$_n_"), DemangleMode::Watcom);
    }

    #[test]
    fn detect_borland32() {
        assert_eq!(detect_mode("@Unit1@Foo$qpv"), DemangleMode::Borland32);
    }

    #[test]
    fn detect_rust() {
        // Terminal 17h<16-hex> hash + trailing E => Rust legacy.
        assert_eq!(
            detect_mode("_ZN4test4test17h0123456789abcdefE"),
            DemangleMode::Rust
        );
        // Plain Itanium _ZN without hash stays GnuV3.
        assert_eq!(detect_mode("_ZN3foo3barEv"), DemangleMode::GnuV3);
    }

    #[test]
    fn detect_itanium_family() {
        assert_eq!(detect_mode("@_Z3foov"), DemangleMode::GccWin);
        assert_eq!(detect_mode("CXX$_Z3foov"), DemangleMode::GnuV3);
        assert_eq!(detect_mode("_Z3foov"), DemangleMode::GnuV3);
        assert_eq!(detect_mode("_Z3foov@12"), DemangleMode::GccWin);
        assert_eq!(detect_mode("__Z3foov"), DemangleMode::GccMac);
    }

    #[test]
    fn detect_dlang() {
        assert_eq!(detect_mode("_Dmain"), DemangleMode::Dlang);
        assert_eq!(detect_mode("_D3foo3barFZv"), DemangleMode::Dlang);
    }

    #[test]
    fn detect_phase18a_modes() {
        assert_eq!(detect_mode("$s4test4testyF"), DemangleMode::Swift);
        assert_eq!(detect_mode("_ada_foo"), DemangleMode::Gnat);
        assert_eq!(detect_mode("camlFoo"), DemangleMode::Ocaml);
        assert_eq!(detect_mode("__1cGfoo6F_v_"), DemangleMode::Sun);
        assert_eq!(detect_mode("foo__Xbar"), DemangleMode::Tru64);
        assert_eq!(detect_mode("__vt_3foo"), DemangleMode::GnuV2);
        assert_eq!(detect_mode("main.main"), DemangleMode::Go);
        assert_eq!(detect_mode("plain_symbol"), DemangleMode::Unknown);
    }

    // -- per-mode demangling --

    #[test]
    fn demangle_msvc_simple_function() {
        // ?foo@@YAHXZ -> int __cdecl foo(void)
        let out = demangle_symbol("?foo@@YAHXZ", "auto");
        assert!(out.contains("foo"), "got: {}", out);
        assert!(out.contains("int"), "got: {}", out);
    }

    #[test]
    fn demangle_msvc_modes() {
        for m in ["msvc", "msvc32", "msvc64", "msvcarm32", "msvcarm64"] {
            let out = demangle_symbol("?foo@@YAHXZ", m);
            assert!(out.contains("foo"), "{}: got {}", m, out);
        }
    }

    #[test]
    fn demangle_itanium() {
        let out = demangle_symbol("_ZN3foo3barEv", "cpp");
        assert_eq!(out, "foo::bar()");
    }

    #[test]
    fn demangle_gccwin_stdcall_suffix() {
        let out = demangle_symbol("_Z3foov@0", "auto");
        assert!(out.contains("foo"), "got: {}", out);
    }

    #[test]
    fn demangle_rust() {
        let out = demangle_symbol("_ZN4test4test17h0123456789abcdefE", "auto");
        assert!(out.contains("test"), "got: {}", out);
    }

    #[test]
    fn demangle_dlang_function() {
        assert_eq!(demangle_symbol("_D3foo3barFZv", "auto"), "void foo.bar()");
        assert_eq!(demangle_symbol("_Dmain", "auto"), "D main");
    }

    #[test]
    fn demangle_java_jni() {
        assert_eq!(
            demangle_symbol("Java_com_example_Foo_bar", "java"),
            "com.example.Foo.bar"
        );
    }

    #[test]
    fn demangle_borland32_qualified() {
        assert_eq!(
            demangle_symbol("@Unit1@TForm1@Foo$qpv", "auto"),
            "Unit1.TForm1.Foo"
        );
    }

    #[test]
    fn demangle_watcom_name() {
        assert_eq!(demangle_symbol("W?main$_n_", "watcom"), "main");
    }

    #[test]
    fn demangle_unknown_passthrough() {
        assert_eq!(demangle_symbol("plain_symbol", "auto"), "plain_symbol");
    }

    // -- Phase 18.A: previously-deferred modes --

    #[test]
    fn demangle_swift_function() {
        // $s<mod-len><mod><name-len><name>y?..F form.
        assert_eq!(demangle_symbol("$s4test5helloyF", "auto"), "test.hello()");
        let out = demangle_symbol("_$s7MyClass8callbackySiF", "swift");
        assert!(out.contains("MyClass.callback"), "got: {}", out);
        assert!(out.contains("Int"), "got: {}", out);
    }

    #[test]
    fn demangle_go_separators() {
        assert_eq!(demangle_symbol("main.main", "go"), "main.main");
        // Mid-dot / division-slash used in generic Go symbol names.
        assert_eq!(demangle_symbol("main\u{00b7}main", "go"), "main.main");
        // Percent escapes (Go linker encodes '.'/'/'/'%' in package paths).
        assert_eq!(
            demangle_symbol("foo%2ecom%2fbar%2eBaz", "go"),
            "foo.com/bar.Baz"
        );
    }

    #[test]
    fn demangle_gnat_ada() {
        assert_eq!(demangle_symbol("_ada_pack__proc", "gnat"), "pack.proc");
        assert_eq!(demangle_symbol("_ada_foo__Oadd", "gnat"), "foo.\"+\"");
    }

    #[test]
    fn demangle_haskell_z_encoding() {
        // 'zi' -> ':' inside identifiers.
        let out = demangle_symbol("base_GHCziIO_zdws_info", "haskell");
        assert!(out.contains(':'), "got: {}", out);
        assert!(out.ends_with("[info]"), "got: {}", out);
        // '_closure' suffix.
        let out = demangle_symbol("Main_zimain_closure", "haskell");
        assert!(out.ends_with("[closure]"), "got: {}", out);
    }

    #[test]
    fn demangle_ocaml_module() {
        assert_eq!(demangle_symbol("camlList__map_1008", "auto"), "List.map");
        assert_eq!(
            demangle_symbol("camlPrintf.printf", "ocaml"),
            "Printf.printf"
        );
    }

    #[test]
    fn demangle_tru64_function() {
        assert_eq!(demangle_symbol("foo__Xi", "auto"), "foo(int)");
        assert_eq!(demangle_symbol("__vtbl__3Bar", "tru64"), "vtable for 3Bar");
    }

    #[test]
    fn demangle_sun_function() {
        // __1cD put 6F _v_  -> void put()
        assert_eq!(demangle_symbol("__1cDput6F_v_", "auto"), "void put()");
    }

    #[test]
    fn demangle_gnuv2_forms() {
        assert_eq!(demangle_symbol("__vt_3Foo", "auto"), "vtable for Foo");
        assert_eq!(demangle_symbol("_$_3Foo", "gnuv2"), "Foo::~Foo");
        assert_eq!(demangle_symbol("bar__3FooFi", "gnuv2"), "Foo::bar(int)");
        assert_eq!(demangle_symbol("baz__Fi", "gnuv2"), "baz(int)");
    }
}

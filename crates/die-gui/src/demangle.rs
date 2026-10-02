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
//! | GNU_V2/GNAT/SWIFT/GO/HASKELL/OCAML/TRU64/SUN | not implemented (raw passthrough) |

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
    /// GNAT/Ada (`_ada_` prefix) — not implemented.
    Gnat,
    /// D language (`_D` prefix) — simplified decoder.
    Dlang,
    /// Swift (`$s`/`_$s` prefix) — not implemented.
    Swift,
    /// Go symbol conventions — not implemented.
    Go,
    /// Haskell (`zi` + `_closure`/`_info`/`_entry`) — not implemented.
    Haskell,
    /// OCaml (`caml` prefix) — not implemented.
    Ocaml,
    /// DEC/Compaq Tru64 (`__X` marker) — not implemented.
    Tru64,
    /// SunPro / Sun Studio (`__1c` scheme) — not implemented.
    Sun,
    /// GNU v2 (`__vt_`/`__F`/`__Q` style) — not implemented.
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
    fn detect_unimplemented_modes() {
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
    fn demangle_unimplemented_passthrough() {
        assert_eq!(demangle_symbol("$s4test4testyF", "auto"), "$s4test4testyF");
        assert_eq!(demangle_symbol("plain_symbol", "auto"), "plain_symbol");
    }
}

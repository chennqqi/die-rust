//! Demangle backend for die-gui (upstream `XDemangle` alignment, Phase 17.A).
//!
//! Upstream `XDemangle` supports 20 `MODE_*` values (see
//! `docs/research/gui-gap-analysis-v4.md` V4-10). All modes are
//! implemented; Phase 44 replaced the Phase-18.A simplified decoders
//! with faithful ports of the upstream parsers (oracle-verified
//! against `tools/demangle-oracle` snapshots in `corpus/demangle/`):
//!
//! | Mode            | Backend                              |
//! |-----------------|--------------------------------------|
//! | MSVC*           | `msvc-demangler` crate + per-mode convention fix-ups |
//! | GNU_V3/GCC_*/BORLAND64 | `cpp_demangle` (Itanium ABI) + thunk/substitution fix-ups |
//! | RUST            | `rustc-demangle` + legacy-hash strip   |
//! | DLANG           | upstream `dlang_*` port              |
//! | JAVA            | Itanium + upstream MODE_JAVA rendering |
//! | BORLAND32       | upstream `borland_*` port            |
//! | WATCOM          | upstream `watcom_*` port             |
//! | SWIFT           | upstream `swift_*` node-stack port   |
//! | GNU_V2/TRU64    | upstream `gnu2_*` port (Tru64 `__X`) |
//! | GNAT/GO/HASKELL/OCAML/SUN | upstream decoder ports   |

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
    /// Borland 32-bit (`@...$q` scheme) — upstream `borland_*` port.
    Borland32,
    /// Borland 64-bit (Itanium ABI).
    Borland64,
    /// Watcom (`W?...` scheme) — upstream `watcom_*` port.
    Watcom,
    /// Rust (legacy `ZN`/`_R` and v0 `_R` schemes).
    Rust,
    /// GNAT/Ada (`_ada_` prefix) — upstream decoder port.
    Gnat,
    /// D language (`_D` prefix) — upstream `dlang_*` port.
    Dlang,
    /// Swift (`$s`/`_$s` prefix) — upstream `swift_*` port.
    Swift,
    /// Go symbol conventions — escape/separator normalizer.
    Go,
    /// Haskell (`zi` + `_closure`/`_info`/`_entry`) — z-encoding decoder.
    Haskell,
    /// OCaml (`caml` prefix) — upstream decoder port.
    Ocaml,
    /// DEC/Compaq Tru64 (`__X` marker) — GNU v2 engine, `X` allowed.
    Tru64,
    /// SunPro / Sun Studio (`__1c` scheme) — upstream decoder port.
    Sun,
    /// GNU v2 (`__vt_`/`__F`/`__Q` style) — upstream `gnu2_*` port.
    GnuV2,
    /// Java mode — Itanium parse with upstream MODE_JAVA rendering.
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
        | DemangleMode::MsvcArm64 => demangle_msvc(symbol, mode),
        DemangleMode::GnuV3 | DemangleMode::Borland64 => demangle_itanium(symbol),
        DemangleMode::GccWin => {
            // Upstream: only the '@_Z...@<digits>' fastcall form is a
            // GCC_WIN symbol; the convention is rendered as
            // '__fastcall '. '__Z'/'_Z' with '@' digits and bare
            // '@'-less forms are not accepted (raw passthrough).
            symbol.strip_prefix("@_Z").and_then(|rest| {
                let body = match rest.rfind('@') {
                    Some(i) if rest[i + 1..].bytes().all(|c| c.is_ascii_digit()) => &rest[..i],
                    _ => rest,
                };
                demangle_itanium(&format!("_Z{}", body)).map(|s| format!("__fastcall {}", s))
            })
        }
        DemangleMode::GccMac => {
            // Mach-O prepends an extra '_' to the Itanium '_Z' prefix.
            symbol
                .strip_prefix("__Z")
                .and_then(|s| demangle_itanium(&format!("_{}", s)))
                .or_else(|| demangle_itanium(symbol))
        }
        DemangleMode::Rust => rustc_demangle::try_demangle(symbol).ok().map(|d| {
            let s = format!("{}", d);
            // Upstream drops the trailing legacy hash
            // ('17h' + 16 hex) when not in verbose mode.
            match s.rfind("::h") {
                Some(i)
                    if s[i + 3..].len() == 16
                        && s[i + 3..].bytes().all(|b| b.is_ascii_hexdigit()) =>
                {
                    s[..i].to_string()
                }
                _ => s,
            }
        }),
        DemangleMode::Dlang => demangle_dlang(symbol),
        DemangleMode::Java => demangle_java(symbol),
        DemangleMode::Borland32 => demangle_borland32(symbol),
        DemangleMode::Watcom => demangle_watcom(symbol),
        DemangleMode::Swift => demangle_swift(symbol),
        DemangleMode::Go => demangle_go(symbol),
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

/// Itanium ABI demangle via `cpp_demangle` with upstream `XDemangle`
/// semantic fix-ups layered on top:
///
/// - `Th`/`Tv` thunk prefixes render as `non-virtual thunk to X` /
///   `virtual thunk to X` (upstream drops the offsets entirely).
/// - Ref-qualified nested names (`NR`/`NO` after the cv-qual run) are
///   not supported by the upstream parser → raw passthrough.
/// - When `cpp_demangle` fails, `<template-param>` substitutions
///   (`T_`/`T<n>_`) referencing the enclosing `I<args>E` list are
///   expanded textually and the symbol is retried — this covers
///   forms like `_ZN3FooIidE3barET0_T_` that the crate cannot parse.
///
/// Returns `None` on failure.
fn demangle_itanium(symbol: &str) -> Option<String> {
    if itanium_nested_refqual(symbol) {
        return None;
    }
    if let Some((virt, target)) = itanium_thunk_target(symbol) {
        let inner = demangle_itanium(&format!("_Z{}", target))?;
        return Some(format!(
            "{} thunk to {}",
            if virt { "virtual" } else { "non-virtual" },
            inner
        ));
    }
    let b = symbol.as_bytes();
    // Upstream lacks `TC`/`GTt`/`GR` handling; `TV`/`TT`/`TI`/`TS`/`GV`
    // decode via the cpp_demangle output below.
    if symbol.starts_with("_ZTC") || symbol.starts_with("_ZGT") || symbol.starts_with("_ZGR") {
        return None;
    }
    let tokens = itanium_external_t_tokens(b);
    if !tokens.is_empty() {
        // Upstream resolves T<n>_ against the most recent I<args>E
        // list; cpp_demangle resolves differently, so take the
        // expansion path first and fail closed like upstream does.
        return demangle_itanium_texpanded(b, &tokens);
    }
    let sym = cpp_demangle::Symbol::new(symbol).ok()?;
    let mut s = sym
        .demangle(&cpp_demangle::DemangleOptions::default())
        .ok()?;
    // cpp_demangle wraps vtable/VTT specials in braces; upstream
    // renders `vtable for X` / `VTT for X`.
    if symbol.starts_with("_ZTV")
        && let Some(inner) = s
            .strip_prefix("{vtable(")
            .and_then(|x| x.strip_suffix(")}"))
    {
        s = format!("vtable for {}", inner);
    } else if symbol.starts_with("_ZTT")
        && let Some(inner) = s.strip_prefix("{vtt(").and_then(|x| x.strip_suffix(")}"))
    {
        s = format!("VTT for {}", inner);
    }
    Some(s)
}

/// Collect `T_`/`T<n>_` template-parameter tokens that lie outside
/// `I<args>E` regions. Tokens inside arg lists resolve against the
/// argument's own context and are left to `cpp_demangle`.
fn itanium_external_t_tokens(b: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut tokens = Vec::new();
    let mut i = 2;
    while i + 1 < b.len() {
        if b[i] == b'I' {
            if let Some((_, end)) = itanium_split_targs(b, i) {
                i = end;
                continue;
            }
            i += 1;
            continue;
        }
        if b[i] == b'T' {
            let mut j = i + 1;
            while b.get(j).is_some_and(|c| c.is_ascii_digit()) {
                j += 1;
            }
            if b.get(j) == Some(&b'_') {
                // T_ is index 0; T<n>_ is seq-id n = index n+1.
                let Some(idx) = (if j == i + 1 {
                    Some(0usize)
                } else {
                    std::str::from_utf8(&b[i + 1..j])
                        .ok()
                        .and_then(|d| d.parse::<usize>().ok())
                        .and_then(|n| n.checked_add(1))
                }) else {
                    return Vec::new();
                };
                tokens.push((i, j + 1, idx));
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    tokens
}

/// Detect a ref-qualified nested name upstream cannot parse:
/// `_ZN` [cv-quals] (`R` lvalue | `O` rvalue).
fn itanium_nested_refqual(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 4 || !s.starts_with("_Z") {
        return false;
    }
    if b[2] != b'N' {
        return false;
    }
    let mut j = 3;
    while matches!(b.get(j), Some(b'K') | Some(b'V') | Some(b'r')) {
        j += 1;
    }
    matches!(b.get(j), Some(b'R') | Some(b'O'))
}

/// Parse `_ZTh<nv-off>_` / `_ZTv<v-off>_<nv-off>_` thunk prefixes.
/// Returns `(is_virtual, remaining-encoding)`.
fn itanium_thunk_target(s: &str) -> Option<(bool, &str)> {
    let b = s.as_bytes();
    if b.len() < 5 || !s.starts_with("_ZT") {
        return None;
    }
    /// `<nv-offset>`: optional 'n' sign then digits then '_'.
    fn nv_offset(b: &[u8], mut p: usize) -> Option<usize> {
        if b.get(p) == Some(&b'n') {
            p += 1;
        }
        let start = p;
        while b.get(p).is_some_and(|c| c.is_ascii_digit()) {
            p += 1;
        }
        if p == start || b.get(p) != Some(&b'_') {
            return None;
        }
        Some(p + 1)
    }
    match b[3] {
        b'h' => nv_offset(b, 4).map(|p| (false, &s[p..])),
        b'v' => {
            // <v-offset> then <nv-offset>: both are `[n]<digits>_`.
            let p = nv_offset(b, 4)?;
            nv_offset(b, p).map(|p| (true, &s[p..]))
        }
        _ => None,
    }
}

/// `T_`/`T<n>_` template-parameter expansion: locate the last
/// `I<args>E` list ending before the first token (upstream resolves
/// against the most recent template-argument list), substitute each
/// token with its raw argument fragment, and re-demangle.
fn demangle_itanium_texpanded(b: &[u8], tokens: &[(usize, usize, usize)]) -> Option<String> {
    if tokens.len() > 64 {
        return None;
    }
    // Last `I<args>E` ending before the first token.
    let first = tokens[0].0;
    let mut args: Option<Vec<String>> = None;
    let mut p = 2;
    while p < first {
        if b[p] == b'I' {
            if let Some((a, end)) = itanium_split_targs(b, p) {
                if end <= first {
                    args = Some(a);
                }
                p = end;
                continue;
            }
            return None;
        }
        p += 1;
    }
    let args = args?;
    if args.len() > 1024 {
        return None;
    }
    // Substitute right-to-left to keep offsets valid.
    let mut out = String::from_utf8_lossy(b).into_owned();
    for (start, end, idx) in tokens.iter().rev() {
        let frag = args.get(*idx)?;
        out.replace_range(*start..*end, frag);
    }
    let sym = cpp_demangle::Symbol::new(&out).ok()?;
    sym.demangle(&cpp_demangle::DemangleOptions::default()).ok()
}

/// Split `I<arg>...E` at `pos` into raw argument fragments.
/// Returns `(args, end-pos)` or `None` on unsupported syntax.
fn itanium_split_targs(b: &[u8], pos: usize) -> Option<(Vec<String>, usize)> {
    if b.get(pos) != Some(&b'I') {
        return None;
    }
    let mut args = Vec::new();
    let mut p = pos + 1;
    let mut steps = 0u32;
    while p < b.len() && b[p] != b'E' {
        steps += 1;
        if steps > 200_000 || args.len() >= 1024 {
            return None;
        }
        let end = itanium_skip_type(b, p)?;
        if end <= p {
            return None;
        }
        args.push(std::str::from_utf8(&b[p..end]).ok()?.to_string());
        p = end;
    }
    if p >= b.len() {
        return None;
    }
    Some((args, p + 1))
}

/// Skip one Itanium `<type>`/`<name>` production starting at `pos`.
/// Subset sufficient for template-argument splitting; returns the end
/// offset or `None` on syntax outside the subset.
fn itanium_skip_type(b: &[u8], pos: usize) -> Option<usize> {
    let c = *b.get(pos)?;
    match c {
        // cv-quals, pointers/references, complex/imaginary prefixes.
        b'K' | b'V' | b'r' | b'P' | b'R' | b'O' | b'C' | b'G' => itanium_skip_type(b, pos + 1),
        // <type> <type>: pointer-to-member.
        b'M' => itanium_skip_type(b, itanium_skip_type(b, pos + 1)?),
        // Function type: F [Y] <type>* E.
        b'F' => {
            let mut p = pos + 1;
            if b.get(p) == Some(&b'Y') {
                p += 1;
            }
            let mut steps = 0u32;
            while p < b.len() && b[p] != b'E' {
                steps += 1;
                if steps > 200_000 {
                    return None;
                }
                p = itanium_skip_type(b, p)?;
            }
            (p < b.len()).then_some(p + 1)
        }
        // Array: A [<n>] _ <type> / A <expr> _ <type> (subset: decimal n).
        b'A' => {
            let mut p = pos + 1;
            while b.get(p).is_some_and(|c| c.is_ascii_digit()) {
                p += 1;
            }
            if b.get(p) != Some(&b'_') {
                return None;
            }
            itanium_skip_type(b, p + 1)
        }
        // Nested name: scan structurally to the matching 'E'.
        b'N' => itanium_skip_nested(b, pos + 1),
        // <template-param>: T <seqid> _ (seqid = base-36, empty = 0).
        b'T' => {
            let mut p = pos + 1;
            while b.get(p).is_some_and(|c| c.is_ascii_alphanumeric()) {
                p += 1;
            }
            (b.get(p) == Some(&b'_')).then_some(p + 1)
        }
        // Substitutions: S_ / St / Sa / Sb / Ss / Si / So / Sd / S<seqid>_.
        b'S' => {
            let n = *b.get(pos + 1)?;
            if matches!(n, b'_' | b't' | b'a' | b'b' | b's' | b'i' | b'o' | b'd') {
                Some(pos + 2)
            } else {
                let mut p = pos + 1;
                while b.get(p).is_some_and(|c| c.is_ascii_alphanumeric()) {
                    p += 1;
                }
                (b.get(p) == Some(&b'_')).then_some(p + 1)
            }
        }
        // decltype(nullptr) is atomic; other D-forms bail.
        b'D' => (b.get(pos + 1) == Some(&b'n')).then_some(pos + 2),
        // Vendor extended type: u <source-name>.
        b'u' => {
            let (len, end) = itanium_source_len(b, pos + 1)?;
            (b.len() - end >= len).then_some(end + len)
        }
        // Source name.
        _ if c.is_ascii_digit() => {
            let (len, end) = itanium_source_len(b, pos)?;
            (b.len() - end >= len).then_some(end + len)
        }
        // Builtin types are single letters.
        _ if c.is_ascii_alphabetic() => Some(pos + 1),
        _ => None,
    }
}

/// Skip an `N...`-body to its matching `E` (called after the 'N').
/// Returns the offset just past `E`.
fn itanium_skip_nested(b: &[u8], mut p: usize) -> Option<usize> {
    while matches!(b.get(p), Some(b'K') | Some(b'V') | Some(b'r')) {
        p += 1;
    }
    if matches!(b.get(p), Some(b'R') | Some(b'O')) {
        p += 1;
    }
    let mut steps = 0u32;
    loop {
        steps += 1;
        if steps > 200_000 {
            return None;
        }
        let c = *b.get(p)?;
        match c {
            b'E' => return Some(p + 1),
            b'I' => {
                // Template args: types until 'E'.
                p += 1;
                loop {
                    let a = *b.get(p)?;
                    if a == b'E' {
                        p += 1;
                        break;
                    }
                    p = itanium_skip_type(b, p)?;
                }
            }
            b'C' | b'D' => {
                // C1/C2/C3 ctors, D0/D1/D2/D5 dtors (+ 't'/'i' variants).
                p += 1;
                if matches!(b.get(p), Some(b't') | Some(b'i')) {
                    p += 1;
                }
                if b.get(p).is_some_and(|c| c.is_ascii_digit()) {
                    p += 1;
                }
            }
            b'S' => {
                p = itanium_skip_type(b, p)?;
            }
            b'T' => {
                p = itanium_skip_type(b, p)?;
            }
            b'L' => {
                // <local-name> 'Z' or <unnamed-type> 'Ut'/'UL' — bail.
                return None;
            }
            b'G' | b'J' | b'U' | b'B' => return None,
            _ if c.is_ascii_digit() => {
                let (len, end) = itanium_source_len(b, p)?;
                if b.len() - end < len {
                    return None;
                }
                p = end + len;
            }
            _ => return None,
        }
    }
}

/// Parse a `<source-name>` length prefix; returns `(len, pos-after-digits)`.
fn itanium_source_len(b: &[u8], pos: usize) -> Option<(usize, usize)> {
    if !b.get(pos).is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut p = pos;
    let mut n: usize = 0;
    while let Some(&d) = b.get(p) {
        if !d.is_ascii_digit() {
            break;
        }
        n = n.checked_mul(10)?.checked_add((d - b'0') as usize)?;
        if n > 1_048_576 {
            return None;
        }
        p += 1;
    }
    Some((n, p))
}

/// MSVC demangle via `msvc-demangler` (LLVM undname port) with
/// upstream `XDemangle` semantic fix-ups layered on top:
///
/// - `??_R0`/`??_R1` RTTI encodings are not handled upstream → invalid
///   → raw passthrough.
/// - Calling-convention code validity is per-mode: `A` means `__cdecl`
///   for MSVC32, `__fastcall` for MSVC64, and (upstream quirk) falls
///   through to the reference qualifier `&` for ARM modes. `I` is only
///   a convention char for MSVC32; elsewhere the symbol is invalid.
///   `O`/`P`/`S` map to the literal conv word `Unknown`.
/// - Nested-template output collapses `> >` into `>>`.
/// - `scalar/vector deleting destructor` renders as `... dtor` upstream.
fn demangle_msvc(symbol: &str, mode: DemangleMode) -> Option<String> {
    if symbol.starts_with("??_R0") || symbol.starts_with("??_R1") {
        return None;
    }
    let convs = msvc_conv_chars(symbol);
    let is32 = matches!(mode, DemangleMode::Msvc | DemangleMode::Msvc32);
    let is64 = mode == DemangleMode::Msvc64;
    let is_arm = matches!(mode, DemangleMode::MsvcArm32 | DemangleMode::MsvcArm64);
    const COMMON: &[u8] = b"BCDEFGHJMNOPQS";
    for &c in &convs {
        let ok = COMMON.contains(&c)
            || (is32 && (c == b'A' || c == b'I'))
            || (is64 && c == b'A')
            || (is_arm && c == b'A');
        if !ok {
            return None;
        }
    }
    let mut s = msvc_demangler::demangle(symbol, msvc_demangler::DemangleFlags::llvm()).ok()?;
    // Convention-word substitutions the LLVM renderer gets "wrong"
    // relative to upstream's per-mode table.
    if let Some(&outer) = convs.first() {
        if is64 && outer == b'A' {
            if convs.iter().all(|&c| c == b'A') {
                s = s.replace("__cdecl", "__fastcall");
            } else {
                s = s.replacen(" __cdecl ", " __fastcall ", 1);
            }
        } else if is_arm && outer == b'A' {
            // Upstream renders the stray 'A' as a reference qualifier '&'.
            if convs.iter().all(|&c| c == b'A') {
                s = s.replace("__cdecl * ", "*& ");
                s = s.replace(" __cdecl ", " & ");
            } else {
                s = s.replacen(" __cdecl ", " & ", 1);
            }
        }
    }
    let n_unknown = convs
        .iter()
        .filter(|&&c| matches!(c, b'O' | b'P' | b'S'))
        .count();
    for _ in 0..n_unknown {
        // FC_EABI / FC_SWIFT render as literal 'Unknown' upstream.
        let mut done = false;
        for w in [
            "__cdecl",
            "__fastcall",
            "__stdcall",
            "__thiscall",
            "__vectorcall",
            "__clrcall",
            "__pascal",
            "__swift_2",
        ] {
            if s.contains(w) {
                s = s.replacen(w, "Unknown", 1);
                done = true;
                break;
            }
        }
        if !done {
            break;
        }
    }
    s = s.replace("`scalar deleting destructor'", "`scalar deleting dtor'");
    s = s.replace("`vector deleting destructor'", "`vector deleting dtor'");
    while s.contains("> >") {
        s = s.replace("> >", ">>");
    }
    Some(s)
}

/// Extract MSVC calling-convention code characters: the outer function
/// convention (after the access/qualifier run) plus inner `?6?`/`?8?`
/// pointer-to-function conventions. Non-convention contexts yield no
/// entries.
fn msvc_conv_chars(symbol: &str) -> Vec<u8> {
    let b = symbol.as_bytes();
    let mut out = Vec::new();
    if let Some(at) = symbol.find("@@") {
        let mut i = at + 2;
        while b.get(i) == Some(&b'$') && b.get(i + 1) == Some(&b'$') && b.get(i + 2) == Some(&b'J')
        {
            i += 3;
            while b.get(i).is_some_and(|c| c.is_ascii_digit()) {
                i += 1;
            }
        }
        match b.get(i) {
            Some(&c) if (b'A'..=b'V').contains(&c) => {
                // Member access. Static members (C/D/K/L/S/T) take the
                // calling convention directly; non-static members parse
                // ext-quals (E/I/F), ref-qual (G/H) and one member-qualifier
                // char first (upstream `ms_demangle_FunctionType` bThisQual).
                let mut j = i + 1;
                if !matches!(c, b'C' | b'D' | b'K' | b'L' | b'S' | b'T') {
                    while matches!(b.get(j), Some(b'E') | Some(b'I') | Some(b'F')) {
                        j += 1;
                    }
                    if matches!(b.get(j), Some(b'G') | Some(b'H')) {
                        j += 1;
                    }
                    if matches!(
                        b.get(j),
                        Some(b'A')
                            | Some(b'B')
                            | Some(b'C')
                            | Some(b'D')
                            | Some(b'Q')
                            | Some(b'R')
                            | Some(b'S')
                            | Some(b'T')
                    ) {
                        j += 1;
                    }
                }
                if let Some(&c) = b.get(j) {
                    out.push(c);
                }
            }
            Some(b'Y') | Some(b'Z') => {
                if let Some(&c) = b.get(i + 1) {
                    out.push(c);
                }
            }
            _ => {}
        }
    }
    // Inner pointer-to-function conventions: `[PQRSTUVW][68]<conv>`.
    for w in b.windows(3) {
        if matches!(w[0], b'P' | b'Q' | b'R' | b'S' | b'T' | b'U' | b'V' | b'W')
            && matches!(w[1], b'6' | b'8')
        {
            out.push(w[2]);
        }
    }
    out
}

/// D language demangler — faithful port of upstream `dlang_demangle`
/// (itself a port of dmd `core.demangle`). `_D` + qualified name,
/// nested-function signatures, type modifiers, `N`-attributes,
/// delegates/function pointers, tuples, `__T`/`__U` templates,
/// `Q` back-references and value arguments are all covered. Any
/// parse failure or trailing byte returns `None` → raw passthrough.
fn demangle_dlang(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if b.len() < 2 || b[0] != b'_' || b[1] != b'D' {
        return None;
    }
    if s == "_Dmain" {
        return Some("D main".to_string());
    }
    let mut p = DParser {
        s,
        last_backref: s.len(),
        depth: 0,
        steps: 0,
    };
    let mut decl = String::new();
    let pos = p.parse_mangle(&mut decl, 0)?;
    (pos == s.len()).then_some(decl)
}

/// Recursive-descent state for the D demangler (mirrors upstream
/// `DLANGINFO` — bounded depth/steps, last-type-backref position).
struct DParser<'a> {
    s: &'a str,
    last_backref: usize,
    depth: u32,
    steps: u32,
}

impl<'a> DParser<'a> {
    /// Byte at `pos` or NUL.
    fn at(&self, pos: usize) -> u8 {
        *self.s.as_bytes().get(pos).unwrap_or(&0)
    }

    /// Bounded-recursion guard (upstream `XDemangleDlangScope`):
    /// wraps a parse step, holding the depth for the call duration.
    fn guarded<T>(&mut self, f: impl FnOnce(&mut Self) -> Option<T>) -> Option<T> {
        if self.depth >= 128 || self.steps >= 200_000 {
            return None;
        }
        self.depth += 1;
        self.steps += 1;
        let r = f(self);
        self.depth -= 1;
        r
    }

    /// `_D` prefix + qualified name + trailing type/Z marker.
    fn parse_mangle(&mut self, decl: &mut String, mut pos: usize) -> Option<usize> {
        pos += 2;
        pos = self.parse_qualified(decl, pos, true)?;
        if self.at(pos) == b'Z' {
            return Some(pos + 1);
        }
        let mut dump = String::new();
        self.ty(&mut dump, pos)
    }

    /// Qualified-name chain with optional nested function signatures
    /// and `M`-suffix modifiers (ported from `dlang_parse_qualified`).
    fn parse_qualified(
        &mut self,
        decl: &mut String,
        pos: usize,
        suffix_mods: bool,
    ) -> Option<usize> {
        self.guarded(|s| s.parse_qualified_inner(decl, pos, suffix_mods))
    }

    fn parse_qualified_inner(
        &mut self,
        decl: &mut String,
        mut pos: usize,
        suffix_mods: bool,
    ) -> Option<usize> {
        let mut n = 0;
        loop {
            if n != 0 {
                decl.push('.');
            }
            n += 1;
            while self.at(pos) == b'0' {
                pos += 1; // anonymous symbols
            }
            pos = self.identifier(decl, pos)?;
            if self.at(pos) == b'M'
                || matches!(self.at(pos), b'F' | b'U' | b'V' | b'W' | b'R' | b'Y')
            {
                let start_fn = pos;
                let saved_len = decl.len();
                let mut mods = String::new();
                if self.at(pos) == b'M' {
                    pos += 1;
                    match self.type_modifiers(&mut mods, pos) {
                        Some(np) => {
                            pos = np;
                            if decl.len() > saved_len {
                                decl.truncate(saved_len);
                            }
                        }
                        None => pos = usize::MAX,
                    }
                }
                if pos != usize::MAX {
                    match self.function_type_noreturn(decl, None, None, pos) {
                        Some(np) => pos = np,
                        None => pos = usize::MAX,
                    }
                }
                if pos != usize::MAX && suffix_mods {
                    decl.push_str(&mods);
                }
                if pos == usize::MAX || self.at(pos) == 0 {
                    // Not a nested function - backtrack.
                    pos = start_fn;
                    if decl.len() > saved_len {
                        decl.truncate(saved_len);
                    }
                }
            }
            if !self.symbol_name_p(pos) {
                break;
            }
        }
        Some(pos)
    }

    /// Identifier: `Q` symbol backref, `__T`/`__U` template, or an
    /// LName (length-prefixed name incl. `__ctor`/`__dtor` specials).
    fn identifier(&mut self, decl: &mut String, pos: usize) -> Option<usize> {
        self.guarded(|s| s.identifier_inner(decl, pos))
    }

    fn identifier_inner(&mut self, decl: &mut String, pos: usize) -> Option<usize> {
        if self.at(pos) == 0 {
            return None;
        }
        if self.at(pos) == b'Q' {
            return self.symbol_backref(decl, pos);
        }
        if self.at(pos) == b'_'
            && self.at(pos + 1) == b'_'
            && matches!(self.at(pos + 2), b'T' | b'U')
        {
            return self.parse_template(decl, pos, u32::MAX);
        }
        let (len, end) = self.number(pos)?;
        if len == 0 || self.s.len() - end < len as usize {
            return None;
        }
        let pos = end;
        if len >= 5
            && self.at(pos) == b'_'
            && self.at(pos + 1) == b'_'
            && matches!(self.at(pos + 2), b'T' | b'U')
        {
            return self.parse_template(decl, pos, len);
        }
        self.lname(decl, pos, len)
    }

    /// LName with upstream's special-name table (ctor/dtor/init/vtbl/
    /// class/interface/module-info/postblit), else the raw text.
    fn lname(&mut self, decl: &mut String, pos: usize, len: u32) -> Option<usize> {
        let m = &self.s[pos..];
        if len == 6 {
            if m.starts_with("__ctor") {
                decl.push_str("this");
                return Some(pos + 6);
            }
            if m.starts_with("__dtor") {
                decl.push_str("~this");
                return Some(pos + 6);
            }
            if m.starts_with("__initZ") {
                decl.insert_str(0, "initializer for ");
                if !decl.is_empty() {
                    decl.pop();
                }
                return Some(pos + 6);
            }
            if m.starts_with("__vtblZ") {
                decl.insert_str(0, "vtable for ");
                if !decl.is_empty() {
                    decl.pop();
                }
                return Some(pos + 6);
            }
        } else if len == 7 && m.starts_with("__ClassZ") {
            decl.insert_str(0, "ClassInfo for ");
            if !decl.is_empty() {
                decl.pop();
            }
            return Some(pos + 7);
        } else if len == 10 && m.starts_with("__postblitMFZ") {
            decl.push_str("this(this)");
            return Some(pos + 13);
        } else if len == 11 && m.starts_with("__InterfaceZ") {
            decl.insert_str(0, "Interface for ");
            if !decl.is_empty() {
                decl.pop();
            }
            return Some(pos + 11);
        } else if len == 12 && m.starts_with("__ModuleInfoZ") {
            decl.insert_str(0, "ModuleInfo for ");
            if !decl.is_empty() {
                decl.pop();
            }
            return Some(pos + 12);
        }
        decl.push_str(&self.s[pos..pos + len as usize]);
        Some(pos + len as usize)
    }

    /// `dlang_symbol_name_p` — digit, `__T`/`__U`, or `Q` backref to a
    /// digit position.
    fn symbol_name_p(&mut self, pos: usize) -> bool {
        let c = self.at(pos);
        if c.is_ascii_digit() {
            return true;
        }
        if c == b'_' && self.at(pos + 1) == b'_' && matches!(self.at(pos + 2), b'T' | b'U') {
            return true;
        }
        if c != b'Q' {
            return false;
        }
        match self.decode_backref(pos + 1) {
            Some((ret, _)) if ret <= pos as u64 => self.at(pos - ret as usize).is_ascii_digit(),
            _ => false,
        }
    }

    /// `dlang_number` — decimal run followed by more input.
    fn number(&self, pos: usize) -> Option<(u32, usize)> {
        if !self.at(pos).is_ascii_digit() {
            return None;
        }
        let mut val: u32 = 0;
        let mut p = pos;
        while self.at(p).is_ascii_digit() {
            let d = (self.at(p) - b'0') as u32;
            if val > (u32::MAX - d) / 10 {
                return None;
            }
            val = val * 10 + d;
            p += 1;
        }
        if self.at(p) == 0 {
            return None;
        }
        Some((val, p))
    }

    /// `dlang_decode_backref` — base-26 run terminated by a lowercase
    /// letter.
    fn decode_backref(&self, mut pos: usize) -> Option<(u64, usize)> {
        let mut val: u64 = 0;
        loop {
            let c = self.at(pos);
            if !c.is_ascii_alphabetic() {
                return None;
            }
            if val > (u64::MAX - 25) / 26 {
                return None;
            }
            val *= 26;
            if c.is_ascii_lowercase() {
                val += (c - b'a') as u64;
                if val as i64 <= 0 {
                    return None;
                }
                return Some((val, pos + 1));
            }
            val += (c - b'A') as u64;
            pos += 1;
        }
    }

    /// `Q<backref>` → target position.
    fn backref(&self, pos: usize) -> Option<(usize, usize)> {
        if self.at(pos) != b'Q' {
            return None;
        }
        let (r, after) = self.decode_backref(pos + 1)?;
        if r > pos as u64 {
            return None;
        }
        Some((pos - r as usize, after))
    }

    /// Symbol backref: re-parse the target LName into `decl`.
    fn symbol_backref(&mut self, decl: &mut String, pos: usize) -> Option<usize> {
        let (target, after) = self.backref(pos)?;
        let (len, p) = self.number(target)?;
        self.lname(decl, p, len)?;
        Some(after)
    }

    /// Type backref: re-parse the target type; must point strictly
    /// before the previous type backref.
    fn type_backref(&mut self, decl: &mut String, pos: usize, is_fn: bool) -> Option<usize> {
        if pos >= self.last_backref {
            return None;
        }
        let save = self.last_backref;
        self.last_backref = pos;
        let parsed = self.backref(pos).and_then(|(target, after)| {
            let r = if is_fn {
                self.function_type(decl, target)
            } else {
                self.ty(decl, target)
            };
            r.map(|_| after)
        });
        self.last_backref = save;
        parsed
    }

    /// `dlang_call_convention` — writes `extern(...)` text into `call`.
    fn call_convention(&mut self, call: &mut String, pos: usize) -> Option<usize> {
        let c = self.at(pos);
        let t = match c {
            b'F' => "",
            b'U' => "extern(C) ",
            b'W' => "extern(Windows) ",
            b'V' => "extern(Pascal) ",
            b'R' => "extern(C++) ",
            b'Y' => "extern(Objective-C) ",
            _ => return None,
        };
        call.push_str(t);
        Some(pos + 1)
    }

    /// `dlang_type_modifiers` — `x`/`y`/`O`/`Ng` suffix text.
    fn type_modifiers(&mut self, out: &mut String, pos: usize) -> Option<usize> {
        self.guarded(|s| s.type_modifiers_inner(out, pos))
    }

    fn type_modifiers_inner(&mut self, out: &mut String, pos: usize) -> Option<usize> {
        match self.at(pos) {
            0 => None,
            b'x' => {
                out.push_str(" const");
                Some(pos + 1)
            }
            b'y' => {
                out.push_str(" immutable");
                Some(pos + 1)
            }
            b'O' => {
                out.push_str(" shared");
                self.type_modifiers(out, pos + 1)
            }
            b'N' if self.at(pos + 1) == b'g' => {
                out.push_str(" inout");
                self.type_modifiers(out, pos + 2)
            }
            b'N' => None,
            _ => Some(pos),
        }
    }

    /// `dlang_attributes` — `N`-letter function attributes.
    fn attributes(&mut self, attr: &mut String, mut pos: usize) -> Option<usize> {
        while self.at(pos) == b'N' {
            let (t, adv) = match self.at(pos + 1) {
                b'a' => ("pure ", 2),
                b'b' => ("nothrow ", 2),
                b'c' => ("ref ", 2),
                b'd' => ("@property ", 2),
                b'e' => ("@trusted ", 2),
                b'f' => ("@safe ", 2),
                b'i' => ("@nogc ", 2),
                b'j' => ("return ", 2),
                b'l' => ("scope ", 2),
                b'm' => ("@live ", 2),
                b'g' | b'h' | b'k' => break,
                _ => return None,
            };
            attr.push_str(t);
            pos += adv;
        }
        Some(pos)
    }

    /// `dlang_function_type_noreturn` — convention + attributes +
    /// `(args)`; `call`/`attr` may be discarded.
    fn function_type_noreturn(
        &mut self,
        args: &mut String,
        mut call: Option<&mut String>,
        mut attr: Option<&mut String>,
        pos: usize,
    ) -> Option<usize> {
        let mut dump = String::new();
        let mut pos = self.call_convention(call.as_deref_mut().unwrap_or(&mut dump), pos)?;
        pos = self.attributes(attr.as_deref_mut().unwrap_or(&mut dump), pos)?;
        if call.is_some() || attr.is_some() {
            // when caller supplies buffers, args go into `args` (psArgs)
        }
        args.push('(');
        let pos = self.function_args(args, pos)?;
        args.push(')');
        Some(pos)
    }

    /// `dlang_function_type` — `{conv}{ret}({args}) {attr}` assembly.
    fn function_type(&mut self, decl: &mut String, pos: usize) -> Option<usize> {
        if self.at(pos) == 0 {
            return None;
        }
        let mut attr = String::new();
        let mut args = String::new();
        let mut ty = String::new();
        let pos = self.function_type_noreturn(&mut args, Some(decl), Some(&mut attr), pos)?;
        let pos = self.ty(&mut ty, pos)?;
        decl.push_str(&ty);
        decl.push_str(&args);
        decl.push(' ');
        decl.push_str(&attr);
        Some(pos)
    }

    /// `dlang_function_args` — arg list through `Z`, `X`/`Y` varargs,
    /// `M`/`Nk`/`I`/`J`/`K`/`L` storage classes.
    fn function_args(&mut self, decl: &mut String, mut pos: usize) -> Option<usize> {
        let mut n = 0;
        while self.at(pos) != 0 {
            match self.at(pos) {
                b'X' => {
                    decl.push_str("...");
                    return Some(pos + 1);
                }
                b'Y' => {
                    if n != 0 {
                        decl.push_str(", ");
                    }
                    decl.push_str("...");
                    return Some(pos + 1);
                }
                b'Z' => return Some(pos + 1),
                _ => {}
            }
            if n != 0 {
                decl.push_str(", ");
            }
            n += 1;
            if self.at(pos) == b'M' {
                pos += 1;
                decl.push_str("scope ");
            }
            if self.at(pos) == b'N' && self.at(pos + 1) == b'k' {
                pos += 2;
                decl.push_str("return ");
            }
            match self.at(pos) {
                b'I' => {
                    pos += 1;
                    decl.push_str("in ");
                    if self.at(pos) == b'K' {
                        pos += 1;
                        decl.push_str("ref ");
                    }
                }
                b'J' => {
                    pos += 1;
                    decl.push_str("out ");
                }
                b'K' => {
                    pos += 1;
                    decl.push_str("ref ");
                }
                b'L' => {
                    pos += 1;
                    decl.push_str("lazy ");
                }
                _ => {}
            }
            pos = self.ty(decl, pos)?;
        }
        Some(pos)
    }

    /// `dlang_type` — the full D type grammar.
    fn ty(&mut self, decl: &mut String, pos: usize) -> Option<usize> {
        self.guarded(|s| s.ty_inner(decl, pos))
    }

    fn ty_inner(&mut self, decl: &mut String, pos: usize) -> Option<usize> {
        let c = self.at(pos);
        if c == 0 {
            return None;
        }
        match c {
            b'O' | b'x' | b'y' => {
                let tag = match c {
                    b'O' => "shared(",
                    b'x' => "const(",
                    _ => "immutable(",
                };
                decl.push_str(tag);
                let pos = self.ty(decl, pos + 1)?;
                decl.push(')');
                Some(pos)
            }
            b'N' => {
                let (tag, pos) = match self.at(pos + 1) {
                    b'g' => ("inout(", pos + 2),
                    b'h' => ("__vector(", pos + 2),
                    _ => return None,
                };
                decl.push_str(tag);
                let pos = self.ty(decl, pos)?;
                decl.push(')');
                Some(pos)
            }
            b'A' => {
                let pos = self.ty(decl, pos + 1)?;
                decl.push_str("[]");
                Some(pos)
            }
            b'G' => {
                let mut num = String::new();
                let mut p = pos + 1;
                while self.at(p).is_ascii_digit() {
                    num.push(self.at(p) as char);
                    p += 1;
                }
                if num.is_empty() {
                    return None;
                }
                let pos = self.ty(decl, p)?;
                decl.push('[');
                decl.push_str(&num);
                decl.push(']');
                Some(pos)
            }
            b'H' => {
                let mut key = String::new();
                let pos = self.ty(&mut key, pos + 1)?;
                let pos = self.ty(decl, pos)?;
                decl.push('[');
                decl.push_str(&key);
                decl.push(']');
                Some(pos)
            }
            b'P' => {
                if matches!(self.at(pos + 1), b'F' | b'U' | b'V' | b'W' | b'R' | b'Y') {
                    let pos = self.function_type(decl, pos + 1)?;
                    decl.push_str("function");
                    return Some(pos);
                }
                let pos = self.ty(decl, pos + 1)?;
                decl.push('*');
                Some(pos)
            }
            b'F' | b'U' | b'W' | b'V' | b'R' | b'Y' => {
                let pos = self.function_type(decl, pos)?;
                decl.push_str("function");
                Some(pos)
            }
            b'C' | b'S' | b'E' | b'T' => self.parse_qualified(decl, pos + 1, false),
            b'D' => {
                let mut mods = String::new();
                let pos = self.type_modifiers(&mut mods, pos + 1)?;
                let pos = if self.at(pos) == b'Q' {
                    self.type_backref(decl, pos, true)?
                } else {
                    self.function_type(decl, pos)?
                };
                decl.push_str("delegate");
                decl.push_str(&mods);
                Some(pos)
            }
            b'B' => self.parse_tuple(decl, pos + 1),
            b'Q' => self.type_backref(decl, pos, false),
            b'z' => match self.at(pos + 1) {
                b'i' => {
                    decl.push_str("cent");
                    Some(pos + 2)
                }
                b'k' => {
                    decl.push_str("ucent");
                    Some(pos + 2)
                }
                _ => None,
            },
            _ => {
                let t = match c {
                    b'n' => "none",
                    b'v' => "void",
                    b'g' => "byte",
                    b'h' => "ubyte",
                    b's' => "short",
                    b't' => "ushort",
                    b'i' => "int",
                    b'k' => "uint",
                    b'l' => "long",
                    b'm' => "ulong",
                    b'f' => "float",
                    b'd' => "double",
                    b'e' => "real",
                    b'o' => "ifloat",
                    b'p' => "idouble",
                    b'j' => "ireal",
                    b'q' => "cfloat",
                    b'r' => "cdouble",
                    b'c' => "creal",
                    b'b' => "bool",
                    b'a' => "char",
                    b'u' => "wchar",
                    b'w' => "dchar",
                    _ => return None,
                };
                decl.push_str(t);
                Some(pos + 1)
            }
        }
    }

    /// `dlang_parse_tuple` — `B<n><types>` → `Tuple!(...)`.
    fn parse_tuple(&mut self, decl: &mut String, pos: usize) -> Option<usize> {
        let (mut n, mut pos) = self.number(pos)?;
        decl.push_str("Tuple!(");
        while n != 0 {
            pos = self.ty(decl, pos)?;
            n -= 1;
            if n != 0 {
                decl.push_str(", ");
            }
        }
        decl.push(')');
        Some(pos)
    }

    /// `dlang_parse_template` — `__T`/`__U` template instance.
    fn parse_template(&mut self, decl: &mut String, pos: usize, len: u32) -> Option<usize> {
        self.guarded(|s| s.parse_template_inner(decl, pos, len))
    }

    fn parse_template_inner(&mut self, decl: &mut String, pos: usize, len: u32) -> Option<usize> {
        let start = pos;
        if !self.symbol_name_p(pos + 3) || self.at(pos + 3) == b'0' {
            return None;
        }
        let mut pos = self.identifier(decl, pos + 3)?;
        let mut args = String::new();
        pos = self.template_args(&mut args, pos)?;
        decl.push_str("!(");
        decl.push_str(&args);
        decl.push(')');
        if len != u32::MAX && (pos - start) as u32 != len {
            return None;
        }
        Some(pos)
    }

    /// `dlang_template_args` — `S`/`T`/`V`/`X` arguments through `Z`.
    fn template_args(&mut self, decl: &mut String, mut pos: usize) -> Option<usize> {
        let mut n = 0;
        while self.at(pos) != 0 {
            if self.at(pos) == b'Z' {
                return Some(pos + 1);
            }
            if n != 0 {
                decl.push_str(", ");
            }
            n += 1;
            if self.at(pos) == b'H' {
                pos += 1;
            }
            match self.at(pos) {
                b'S' => {
                    pos = self.template_symbol_param(decl, pos + 1)?;
                }
                b'T' => {
                    pos = self.ty(decl, pos + 1)?;
                }
                b'V' => {
                    pos += 1;
                    let mut ctype = self.at(pos);
                    if ctype == b'Q' {
                        let (target, after) = self.backref(pos)?;
                        let _ = after;
                        ctype = self.at(target);
                    }
                    let mut name = String::new();
                    pos = self.ty(&mut name, pos)?;
                    pos = self.value(decl, pos, &name, ctype)?;
                }
                b'X' => {
                    pos += 1;
                    let (len, end) = self.number(pos)?;
                    if self.s.len() - end < len as usize {
                        return None;
                    }
                    decl.push_str(&self.s[end..end + len as usize]);
                    pos = end + len as usize;
                }
                _ => return None,
            }
        }
        None
    }

    /// `dlang_template_symbol_param` — with the <=2.076 ambiguous-length
    /// retry loop.
    fn template_symbol_param(&mut self, decl: &mut String, pos: usize) -> Option<usize> {
        self.guarded(|s| s.template_symbol_param_inner(decl, pos))
    }

    fn template_symbol_param_inner(&mut self, decl: &mut String, pos: usize) -> Option<usize> {
        if self.s[pos..].starts_with("_D") && self.symbol_name_p(pos + 2) {
            return self.parse_mangle(decl, pos);
        }
        if self.at(pos) == b'Q' {
            return self.parse_qualified(decl, pos, false);
        }
        let (len, endptr) = self.number(pos)?;
        if len == 0 {
            return None;
        }
        let mut psize = len;
        let saved = decl.len();
        let mut pend = endptr;
        let mut endptr_valid = true;
        loop {
            let mut nmangled = pend;
            if psize == 0 {
                psize = len;
                pend = endptr;
                endptr_valid = false;
                nmangled = pend;
            }
            let mut r = None;
            if self.symbol_name_p(nmangled) {
                r = self.parse_qualified(decl, nmangled, false);
            } else if self.s[nmangled.min(self.s.len())..].starts_with("_D")
                && self.symbol_name_p(nmangled + 2)
            {
                r = self.parse_mangle(decl, nmangled);
            }
            if let Some(r) = r
                && (!endptr_valid || (r - pend) as u32 == psize)
            {
                return Some(r);
            }
            if !endptr_valid {
                return None;
            }
            psize /= 10;
            if decl.len() > saved {
                decl.truncate(saved);
            }
        }
    }

    /// `dlang_value` — template value argument rendering.
    fn value(&mut self, decl: &mut String, pos: usize, name: &str, ctype: u8) -> Option<usize> {
        self.guarded(|s| s.value_inner(decl, pos, name, ctype))
    }

    fn value_inner(
        &mut self,
        decl: &mut String,
        pos: usize,
        name: &str,
        ctype: u8,
    ) -> Option<usize> {
        match self.at(pos) {
            0 => None,
            b'n' => {
                decl.push_str("null");
                Some(pos + 1)
            }
            b'N' => {
                decl.push('-');
                self.parse_integer(decl, pos + 1, ctype)
            }
            b'i' => self.parse_integer(decl, pos + 1, ctype),
            b'0'..=b'9' => self.parse_integer(decl, pos, ctype),
            b'e' => self.parse_real(decl, pos + 1),
            b'c' => {
                let pos = self.parse_real(decl, pos + 1)?;
                decl.push('+');
                if self.at(pos) != b'c' {
                    return None;
                }
                let pos = self.parse_real(decl, pos + 1)?;
                decl.push('i');
                Some(pos)
            }
            b'a' | b'w' | b'd' => self.parse_string(decl, pos),
            b'A' => {
                if ctype == b'H' {
                    self.parse_assocarray(decl, pos + 1)
                } else {
                    self.parse_arrayliteral(decl, pos + 1)
                }
            }
            b'S' => self.parse_structlit(decl, pos + 1, name),
            _ => None,
        }
    }

    /// `dlang_parse_integer` — char literals `'x'`/escapes, bools,
    /// and plain integers with `u`/`L`/`uL` suffixes.
    fn parse_integer(&mut self, decl: &mut String, pos: usize, ctype: u8) -> Option<usize> {
        if matches!(ctype, b'a' | b'u' | b'w') {
            let (val, pos) = self.number(pos)?;
            decl.push('\'');
            if ctype == b'a' && (0x20..0x7f).contains(&val) {
                decl.push(val as u8 as char);
            } else {
                let (esc, width) = match ctype {
                    b'a' => ("\\x", 2),
                    b'u' => ("\\u", 4),
                    _ => ("\\U", 8),
                };
                decl.push_str(esc);
                decl.push_str(&format!("{:0width$x}", val, width = width));
            }
            decl.push('\'');
            return Some(pos);
        }
        if ctype == b'b' {
            let (val, pos) = self.number(pos)?;
            decl.push_str(if val != 0 { "true" } else { "false" });
            return Some(pos);
        }
        if !self.at(pos).is_ascii_digit() {
            return None;
        }
        let mut p = pos;
        while self.at(p).is_ascii_digit() {
            decl.push(self.at(p) as char);
            p += 1;
        }
        match ctype {
            b'h' | b't' | b'k' => decl.push('u'),
            b'l' => decl.push('L'),
            b'm' => decl.push_str("uL"),
            _ => {}
        }
        Some(p)
    }

    /// `dlang_parse_real` — NAN/INF/NINF and `0xH.HHHp[N]exp` forms.
    fn parse_real(&mut self, decl: &mut String, mut pos: usize) -> Option<usize> {
        let m = &self.s[pos.min(self.s.len())..];
        if m.starts_with("NAN") {
            decl.push_str("NaN");
            return Some(pos + 3);
        }
        if m.starts_with("INF") {
            decl.push_str("Inf");
            return Some(pos + 3);
        }
        if m.starts_with("NINF") {
            decl.push_str("-Inf");
            return Some(pos + 4);
        }
        if self.at(pos) == b'N' {
            decl.push('-');
            pos += 1;
        }
        if !self.at(pos).is_ascii_hexdigit() {
            return None;
        }
        decl.push_str("0x");
        decl.push(self.at(pos) as char);
        pos += 1;
        decl.push('.');
        while self.at(pos).is_ascii_hexdigit() {
            decl.push(self.at(pos) as char);
            pos += 1;
        }
        if self.at(pos) != b'P' {
            return None;
        }
        decl.push('p');
        pos += 1;
        if self.at(pos) == b'N' {
            decl.push('-');
            pos += 1;
        }
        let start = pos;
        while self.at(pos).is_ascii_digit() {
            decl.push(self.at(pos) as char);
            pos += 1;
        }
        if pos == start {
            return None;
        }
        Some(pos)
    }

    /// `dlang_parse_string` — `<a|w|d><len>_<hex-pairs>` string literal.
    fn parse_string(&mut self, decl: &mut String, pos: usize) -> Option<usize> {
        let ctype = self.at(pos);
        let (len, mut pos) = self.number(pos + 1)?;
        if self.at(pos) != b'_' {
            return None;
        }
        pos += 1;
        decl.push('"');
        for _ in 0..len {
            let start = pos;
            let hi = hexdig(self.at(pos))?;
            let lo = hexdig(self.at(pos + 1))?;
            let val = (hi << 4) | lo;
            pos += 2;
            match val {
                b'\t' => decl.push_str("\\t"),
                b'\n' => decl.push_str("\\n"),
                b'\r' => decl.push_str("\\r"),
                0x0c => decl.push_str("\\f"),
                0x0b => decl.push_str("\\v"),
                0x20..=0x7e => decl.push(val as char),
                _ => {
                    decl.push_str("\\x");
                    decl.push_str(&self.s[start..start + 2]);
                }
            }
        }
        decl.push('"');
        if ctype != b'a' {
            decl.push(ctype as char);
        }
        Some(pos)
    }

    /// `dlang_parse_arrayliteral` — `<n><value>*` → `[v, v]`.
    fn parse_arrayliteral(&mut self, decl: &mut String, mut pos: usize) -> Option<usize> {
        let (mut n, p) = self.number(pos)?;
        pos = p;
        decl.push('[');
        while n != 0 {
            pos = self.value(decl, pos, "", 0)?;
            n -= 1;
            if n != 0 {
                decl.push_str(", ");
            }
        }
        decl.push(']');
        Some(pos)
    }

    /// `dlang_parse_assocarray` — `<n>(<value>:<value>)*` → `[k:v]`.
    fn parse_assocarray(&mut self, decl: &mut String, mut pos: usize) -> Option<usize> {
        let (mut n, p) = self.number(pos)?;
        pos = p;
        decl.push('[');
        while n != 0 {
            pos = self.value(decl, pos, "", 0)?;
            decl.push(':');
            pos = self.value(decl, pos, "", 0)?;
            n -= 1;
            if n != 0 {
                decl.push_str(", ");
            }
        }
        decl.push(']');
        Some(pos)
    }

    /// `dlang_parse_structlit` — `<n><value>*` → `Name(v, v)`.
    fn parse_structlit(&mut self, decl: &mut String, pos: usize, name: &str) -> Option<usize> {
        let (mut n, mut pos) = self.number(pos)?;
        decl.push_str(name);
        decl.push('(');
        while n != 0 {
            pos = self.value(decl, pos, "", 0)?;
            n -= 1;
            if n != 0 {
                decl.push_str(", ");
            }
        }
        decl.push(')');
        Some(pos)
    }
}

/// Hex-digit value for `0-9A-Fa-f`, else `None`.
fn hexdig(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Java mode — upstream `MODE_JAVA` runs the same Itanium parser as
/// GNU_V3 but joins nested names with '.' instead of '::'
/// (`xdemangle.cpp` `itanium_getSymbol` + `_nameToString` MODE_JAVA
/// branch). JNI `Java_*` symbols are NOT decoded upstream and pass
/// through raw.
fn demangle_java(s: &str) -> Option<String> {
    let base = demangle_itanium(s)?;
    // Upstream MODE_JAVA drops the entire pointer string
    // (`itanium_parameterToString` ST_POINTER branch): `P`/`R`/`O`
    // declarators render as the pointee type.
    let mut s = base.replace("::", ".");
    s = s.replace(['*', '&'], "");
    while s.contains("  ") {
        s = s.replace("  ", " ");
    }
    for pat in [" )", " ,", "( ", "< ", " >"] {
        if s.contains(pat) {
            let rep = pat.trim();
            s = s.replace(pat, rep);
        }
    }
    Some(s)
}

/// Borland32 demangler — faithful port of upstream
/// `borland_getSymbol`/`borland_demangle_Encoding`/`NameScope`/`Type`.
///
/// Grammar: `@seg(@seg)*` name scope where a segment may be `@$b<op>`
/// (constructor/destructor/operator encodings), followed by `$q<conv>`
/// and a run of parameter types. `qr`/`qs` select `__fastcall` /
/// `__stdcall`. Each of `z u p r x w` prefixes one qualifier layer;
/// base types come from the BORLAND type table. The whole symbol must
/// be consumed, otherwise the input passes through raw.
fn demangle_borland32(s: &str) -> Option<String> {
    /// One parsed name-scope segment.
    enum Seg {
        /// Plain identifier.
        Name(String),
        /// Borland `$b` operator key mapped to its display text.
        Op(&'static str),
        /// Constructor: renders the enclosing class name.
        Ctor,
        /// Destructor: renders `~` + enclosing class name.
        Dtor,
    }
    /// Borland `$b` operator table (upstream `getOperators` BORLAND).
    /// `xor` maps to OP_BITWISEXOR — the second `QMap::insert` wins.
    const OPS: &[(&str, &str)] = &[
        ("arow", "operator->"),
        ("arwm", "operator->*"),
        ("land", "operator&&"),
        ("coma", "operator,"),
        ("call", "operator()"),
        ("dele", "operator delete"),
        ("dla", "operator delete[]"),
        ("rmul", "operator*="),
        ("rplu", "operator+="),
        ("rmin", "operator-="),
        ("rdiv", "operator/="),
        ("rmod", "operator%="),
        ("rrsh", "operator>>="),
        ("rlsh", "operator<<="),
        ("rand", "operator&="),
        ("rxor", "operator^="),
        ("ror", "operator|="),
        ("nwa", "operator new[]"),
        ("new", "operator new"),
        ("asg", "operator="),
        ("rsh", "operator>>"),
        ("lsh", "operator<<"),
        ("not", "operator!"),
        ("eql", "operator=="),
        ("neq", "operator!="),
        ("xor", "operator^"),
        ("ind", "operator*"),
        ("adr", "operator&"),
        ("inc", "operator++"),
        ("dec", "operator--"),
        ("sub", "operator-"),
        ("add", "operator+"),
        ("and", "operator&"),
        ("mul", "operator*"),
        ("div", "operator/"),
        ("mod", "operator%"),
        ("lss", "operator<"),
        ("leq", "operator<="),
        ("gtr", "operator>"),
        ("geq", "operator>="),
        ("cmp", "operator~"),
        ("lor", "operator||"),
        ("ctr", ""),
        ("dtr", "~"),
    ];
    let b = s.as_bytes();
    let mut pos = 0usize;
    let mut segs: Vec<Seg> = Vec::new();
    // Name scope: '@' segment or '@$b<op>' operator entries.
    while b.get(pos) == Some(&b'@') {
        if s[pos..].starts_with("@$b") {
            let rest = &s[pos + 3..];
            let op = OPS
                .iter()
                .filter(|(k, _)| rest.starts_with(k))
                .max_by_key(|(k, _)| k.len());
            match op {
                Some(&(k, v)) => {
                    pos += 3 + k.len();
                    segs.push(match k {
                        "ctr" => Seg::Ctor,
                        "dtr" => Seg::Dtor,
                        _ => Seg::Op(v),
                    });
                }
                None => return None,
            }
        } else {
            pos += 1;
            let start = pos;
            while pos < b.len() && b[pos] != b'@' && b[pos] != b'$' {
                pos += 1;
            }
            if pos == start {
                break;
            }
            segs.push(Seg::Name(s[start..pos].to_string()));
        }
    }
    if segs.is_empty() {
        return None;
    }
    // Function marker: optional '$' then required 'q'.
    if b.get(pos) == Some(&b'$') {
        pos += 1;
    }
    if b.get(pos) != Some(&b'q') {
        return None;
    }
    pos += 1;
    let conv = if s[pos..].starts_with("qr") {
        pos += 2;
        "__fastcall "
    } else if s[pos..].starts_with("qs") {
        pos += 2;
        "__stdcall "
    } else {
        ""
    };
    let mut params: Vec<String> = Vec::new();
    while pos < b.len() {
        let (t, n) = borland_type(&s[pos..])?;
        params.push(t);
        pos += n;
    }
    if pos != b.len() || params.is_empty() {
        return None;
    }
    // Render the name scope; ctor/dtor reuse the previous segment.
    let mut name = String::new();
    for (i, seg) in segs.iter().enumerate() {
        if i > 0 {
            name.push_str("::");
        }
        match seg {
            Seg::Name(n) => name.push_str(n),
            Seg::Op(o) => name.push_str(o),
            Seg::Ctor | Seg::Dtor => {
                if matches!(seg, Seg::Dtor) {
                    name.push('~');
                }
                if i > 0
                    && let Seg::Name(n) = &segs[i - 1]
                {
                    name.push_str(n);
                }
            }
        }
    }
    // Upstream quirk: a void param terminates the list mid-join, so a
    // trailing separator may remain (e.g. `qiv` -> `foo(int, )`).
    let mut plist = String::new();
    for (i, p) in params.iter().enumerate() {
        if p == "void" {
            break;
        }
        plist.push_str(p);
        if i != params.len() - 1 {
            plist.push_str(", ");
        }
    }
    Some(format!("{}{}({})", conv, name, plist))
}

/// Parse one Borland parameter type starting at `s`; returns the
/// rendered text and consumed byte count, or `None` when the encoding
/// is incomplete/unknown.
fn borland_type(s: &str) -> Option<(String, usize)> {
    const BASE: &[(&str, &str)] = &[
        ("Cs", "char16_t"),
        ("Ci", "char32_t"),
        ("v", "void"),
        ("c", "char"),
        ("s", "short"),
        ("i", "int"),
        ("j", "__int64"),
        ("l", "long"),
        ("f", "float"),
        ("d", "double"),
        ("g", "long double"),
        ("e", "..."),
        ("o", "bool"),
        ("b", "wchar_t"),
    ];
    const QUAL: &[(u8, &str)] = &[
        (b'p', "*"),
        (b'r', "&"),
        (b'x', "const"),
        (b'w', "volatile"),
        (b'z', "signed"),
        (b'u', "unsigned"),
    ];
    let b = s.as_bytes();
    let mut pos = 0usize;
    let mut layers: Vec<&'static str> = Vec::new();
    while let Some(&c) = b.get(pos) {
        match QUAL.iter().find(|(k, _)| *k == c) {
            Some(&(_, q)) => {
                layers.push(q);
                pos += 1;
            }
            None => break,
        }
    }
    let (base, n) = BASE
        .iter()
        .filter(|(k, _)| s[pos..].starts_with(k))
        .max_by_key(|(k, _)| k.len())
        .map(|&(k, v)| (v, k.len()))?;
    pos += n;
    // Inner qualifier layers prepend (upstream borland_getPointerString).
    let mut out = String::new();
    for q in layers {
        out = format!("{}{}", q, out);
    }
    if !(out.ends_with('*') || out.ends_with('&') || out.ends_with('_') || out.is_empty()) {
        out.push(' ');
    }
    out.push_str(base);
    Some((out, pos))
}

/// Watcom demangler — faithful port of upstream `watcom_getSymbol` +
/// `watcom_parseScopedName`/`watcom_parseName`/`watcom_parseType`
/// (`xdemangle.cpp`). `W?` prefix, `$`-terminated names with `:` scope
/// chains and `::` template args, `0`-`9` back-references, `$`-operator
/// encodings, and a declarator-style type tail covering pointers with
/// `n`/`f`/`g`/`h` memory models, `x`/`y` cv-qualifiers, arrays,
/// functions and `$name$` class types. Full consumption is required.
fn demangle_watcom(s: &str) -> Option<String> {
    if !s.starts_with("W?") {
        return None;
    }
    let mut p = WatParser {
        s,
        pos: 2,
        refs: Vec::new(),
        depth: 0,
    };
    let name = p.parse_scoped_name(true)?;
    let out = p.parse_type(&name)?;
    (p.pos == s.len()).then_some(out)
}

/// Recursive-descent state for the Watcom decoder.
struct WatParser<'a> {
    s: &'a str,
    pos: usize,
    /// Name back-reference table (`0`-`9` replicate indices).
    refs: Vec<String>,
    /// Recursion bound (upstream `XDemangleParseDepthGuard`).
    depth: u32,
}

/// Watcom base types (upstream `getTypes` WATCOM, longest first).
const WATCOM_TYPES: &[(&str, &str)] = &[
    ("uc", "unsigned char"),
    ("us", "unsigned short"),
    ("ui", "unsigned int"),
    ("ul", "unsigned long"),
    ("uz", "unsigned __int64"),
    ("a", "char"),
    ("c", "signed char"),
    ("s", "short"),
    ("i", "int"),
    ("l", "long"),
    ("z", "__int64"),
    ("b", "float"),
    ("d", "double"),
    ("t", "long double"),
    ("q", "bool"),
    ("w", "wchar_t"),
    ("e", "..."),
    ("v", "void"),
];

/// Watcom `$`-operators (upstream `getOperators` WATCOM).
const WATCOM_OPS: &[(&str, &str)] = &[
    ("$ct", ""),
    ("$dt", "~"),
    ("$nw", "operator new"),
    ("$dl", "operator delete"),
    ("$na", "operator new[]"),
    ("$da", "operator delete[]"),
    ("$oa", "operator>>"),
    ("$ob", "operator<<"),
    ("$oc", "operator!"),
    ("$od", "operator[]"),
    ("$oe", "operator->"),
    ("$of", "operator*"),
    ("$og", "operator++"),
    ("$oh", "operator--"),
    ("$oi", "operator-"),
    ("$oj", "operator+"),
    ("$ok", "operator&"),
    ("$ol", "operator->*"),
    ("$om", "operator/"),
    ("$on", "operator%"),
    ("$oo", "operator,"),
    ("$op", "operator()"),
    ("$oq", "operator~"),
    ("$or", "operator^"),
    ("$os", "operator|"),
    ("$ot", "operator&&"),
    ("$ou", "operator||"),
    ("$ra", "operator=="),
    ("$rb", "operator!="),
    ("$rc", "operator<"),
    ("$rd", "operator<="),
    ("$re", "operator>"),
    ("$rf", "operator>="),
];

impl<'a> WatParser<'a> {
    /// Char at `pos + n` or NUL (upstream `watcom_charAt`).
    fn at(&self, n: usize) -> u8 {
        *self.s.as_bytes().get(self.pos + n).unwrap_or(&0)
    }

    /// `[A-Za-z0-9_]` (upstream `watcom_isIdentifierChar`).
    fn is_ident(c: u8) -> bool {
        c.is_ascii_alphanumeric() || c == b'_'
    }

    /// `watcom_charToDigit` — base-36 style digit value.
    fn char_to_digit(c: u8) -> Option<i64> {
        match c {
            b'0'..=b'9' => Some((c - b'0') as i64),
            b'A'..=b'Z' => Some((c - b'A' + 10) as i64),
            b'a'..=b'z' => Some((c - b'a' + 10) as i64),
            _ => None,
        }
    }

    /// `watcom_parseName` — identifier + `$`, or `0`-`9` backref.
    fn parse_name(&mut self) -> Option<String> {
        let c = self.at(0);
        if c.is_ascii_digit() {
            let idx = Self::char_to_digit(c)?;
            self.pos += 1;
            return self.refs.get(idx as usize).cloned();
        }
        let start = self.pos;
        while Self::is_ident(self.at(0)) {
            self.pos += 1;
        }
        if self.pos > start && self.at(0) == b'$' {
            let name = self.s[start..self.pos].to_string();
            self.pos += 1;
            self.refs.push(name.clone());
            return Some(name);
        }
        self.pos = start;
        None
    }

    /// `watcom_parseScopedName` — `:`-separated scope chain, `::`
    /// template args, `$`-operator head (when allowed).
    fn parse_scoped_name(&mut self, allow_op: bool) -> Option<String> {
        if self.depth >= 128 {
            return None;
        }
        self.depth += 1;
        let r = self.parse_scoped_name_inner(allow_op);
        self.depth -= 1;
        r
    }

    /// Inner of `parse_scoped_name` (depth-guarded by the wrapper).
    fn parse_scoped_name_inner(&mut self, allow_op: bool) -> Option<String> {
        let mut chain: Vec<String> = Vec::new();
        let mut op: Option<&'static str> = None;
        let mut op_like = false;
        if allow_op && self.at(0) == b'$' {
            let rest = &self.s[self.pos..];
            let m = WATCOM_OPS
                .iter()
                .filter(|(k, _)| rest.starts_with(k))
                .max_by_key(|(k, _)| k.len());
            match m {
                Some(&(k, v)) => {
                    self.pos += k.len();
                    op = Some(v);
                    op_like = true;
                    chain.push(String::new());
                }
                None => return None,
            }
        } else {
            chain.push(self.parse_name()?);
        }
        while self.at(0) == b':' {
            self.pos += 1;
            match self.at(0) {
                b':' => {
                    self.pos += 1;
                    let t = self.parse_template_args()?;
                    if let Some(last) = chain.last_mut() {
                        last.push_str(&t);
                    }
                }
                b'?' => return None,
                _ => chain.push(self.parse_name()?),
            }
        }
        if op_like {
            let class = chain
                .get(1)
                .map(|c| c.split('<').next().unwrap_or(c).to_string())
                .unwrap_or_default();
            let name = match op {
                Some("") => class,
                Some("~") => format!("~{}", class),
                Some(o) => o.to_string(),
                None => String::new(),
            };
            chain[0] = name;
        }
        // Render: scopes outermost-first, own name last.
        let mut out = String::new();
        for i in (1..chain.len()).rev() {
            out.push_str(&chain[i]);
            out.push_str("::");
        }
        if let Some(first) = chain.first() {
            out.push_str(first);
        }
        Some(out)
    }

    /// `watcom_parseTemplateArgs` — `1<type>` / `0<base32>[zy]` args.
    fn parse_template_args(&mut self) -> Option<String> {
        let mut args: Vec<String> = Vec::new();
        loop {
            match self.at(0) {
                b'1' => {
                    self.pos += 1;
                    args.push(self.parse_type("")?);
                }
                b'0' => {
                    self.pos += 1;
                    let v = self.parse_base32()?;
                    match self.at(0) {
                        b'z' => {
                            self.pos += 1;
                            args.push(v.to_string());
                        }
                        b'y' => {
                            self.pos += 1;
                            args.push((-v).to_string());
                        }
                        _ => return None,
                    }
                }
                _ => break,
            }
        }
        Some(format!("<{}>", args.join(", ")))
    }

    /// `watcom_parseBase32` — base-32 digit run, `-1` on empty/overflow.
    fn parse_base32(&mut self) -> Option<i64> {
        let mut val: i64 = 0;
        let start = self.pos;
        while let Some(d) = Self::char_to_digit(self.at(0)).filter(|d| *d < 32) {
            if val > (i64::MAX - d) / 32 {
                return None;
            }
            val = val * 32 + d;
            self.pos += 1;
        }
        (self.pos != start).then_some(val)
    }

    /// `watcom_parseBase10` — decimal digit run for array dims.
    fn parse_base10(&mut self) -> Option<i64> {
        let mut val: i64 = 0;
        let start = self.pos;
        while self.at(0).is_ascii_digit() {
            let d = (self.at(0) - b'0') as i64;
            if val > (i64::MAX - d) / 10 {
                return None;
            }
            val = val * 10 + d;
            self.pos += 1;
        }
        (self.pos != start).then_some(val)
    }

    /// `watcom_pointeeNeedsParen` — pointer to array/function needs
    /// `(...)` around the declarator.
    fn pointee_needs_paren(&self) -> bool {
        let mut i = 0usize;
        let mut c = self.at(i);
        while matches!(c, b'n' | b'f' | b'g' | b'h' | b'x' | b'y') {
            i += 1;
            c = self.at(i);
        }
        c == b'[' || c == b'('
    }

    /// `watcom_memoryModelString` — `n`/`f`/`g`/`h` storage classes.
    fn memory_model(c: u8) -> &'static str {
        match c {
            b'f' | b'g' => "__far ",
            b'h' => "__huge ",
            _ => "",
        }
    }

    /// `watcom_parseType` — declarator-style recursive type parse.
    fn parse_type(&mut self, core: &str) -> Option<String> {
        if self.depth >= 128 {
            return None;
        }
        self.depth += 1;
        let r = self.parse_type_inner(core);
        self.depth -= 1;
        r
    }

    /// Inner of `parse_type` (depth-guarded by the wrapper).
    fn parse_type_inner(&mut self, core: &str) -> Option<String> {
        let c = self.at(0);
        if c == 0 {
            return None;
        }
        // Pointer / reference with optional pointer memory model.
        if matches!(c, b'p' | b'r') {
            self.pos += 1;
            let sym = if c == b'r' { "&" } else { "*" };
            let mem = if matches!(self.at(0), b'n' | b'f' | b'g' | b'h') {
                let m = Self::memory_model(self.at(0));
                self.pos += 1;
                m
            } else {
                ""
            };
            let mut new_core = format!("{}{}{}", mem, sym, core);
            if self.pointee_needs_paren() {
                new_core = format!("({})", new_core);
            }
            return self.parse_type(&new_core);
        }
        // Arrays: `[<n>]` dims (leading dimension may be omitted).
        if c == b'[' {
            let mut dims = String::new();
            while self.at(0) == b'[' {
                self.pos += 1;
                let mut dim = String::new();
                if self.at(0) != b']' {
                    dim = self.parse_base10()?.to_string();
                }
                if self.at(0) == b']' {
                    self.pos += 1;
                } else {
                    return None;
                }
                dims.push('[');
                dims.push_str(&dim);
                dims.push(']');
            }
            return self.parse_type(&format!("{}{}", core, dims));
        }
        // cv-qualifiers prepend to the whole inner result.
        if matches!(c, b'x' | b'y') {
            self.pos += 1;
            let qual = if c == b'x' { "const " } else { "volatile " };
            let inner = self.parse_type(core)?;
            return Some(format!("{}{}", qual, inner));
        }
        // Object memory model.
        if matches!(c, b'n' | b'f' | b'g' | b'h') {
            let mem = Self::memory_model(c);
            self.pos += 1;
            let inner = self.parse_type(core)?;
            return Some(format!("{}{}", mem, inner));
        }
        // Function: `(` params `)` return-type.
        if c == b'(' {
            self.pos += 1;
            let mut params: Vec<String> = Vec::new();
            while self.at(0) != b')' {
                let prev = self.pos;
                params.push(self.parse_type("")?);
                if self.pos == prev {
                    return None;
                }
                if self.at(0) == 0 {
                    return None;
                }
            }
            self.pos += 1;
            let core2 = format!("{}({})", core, params.join(", "));
            return self.parse_type(&core2);
        }
        // `$name$` class type.
        if c == b'$' {
            self.pos += 1;
            let name = self.parse_scoped_name(false)?;
            if self.at(0) == b'$' {
                self.pos += 1;
            } else {
                return None;
            }
            return Some(if core.is_empty() {
                name
            } else {
                format!("{} {}", name, core)
            });
        }
        // `_` — no type (ctor/dtor placeholder).
        if c == b'_' {
            self.pos += 1;
            return Some(core.to_string());
        }
        // Base types (longest match).
        let rest = &self.s[self.pos..];
        let t = WATCOM_TYPES
            .iter()
            .filter(|(k, _)| rest.starts_with(k))
            .max_by_key(|(k, _)| k.len());
        match t {
            Some(&(k, v)) => {
                self.pos += k.len();
                Some(if core.is_empty() {
                    v.to_string()
                } else {
                    format!("{} {}", v, core)
                })
            }
            None => None,
        }
    }
}

/// Swift demangler — faithful port of upstream `swift_demangle`
/// (`xdemangle.cpp`), itself a subset port of libswiftDemangling:
/// `$s`/`_$s`/`$S`/`_$S` prefix, post-order node stack, all-or-nothing
/// (anything unmodeled yields the raw symbol).
fn demangle_swift(s: &str) -> Option<String> {
    let body = s
        .strip_prefix("_$s")
        .or_else(|| s.strip_prefix("$s"))
        .or_else(|| s.strip_prefix("_$S"))
        .or_else(|| s.strip_prefix("$S"))?;
    let mut info = SwiftInfo {
        sym: body,
        pos: 0,
        errored: false,
        stack: Vec::new(),
        substs: Vec::new(),
    };
    while info.pos < body.len() && !info.errored {
        info.demangle_top();
    }
    if info.errored || info.pos != body.len() || info.stack.len() != 1 {
        return None;
    }
    Some(info.stack.pop()?.text)
}

/// Node kinds of the Swift demangler stack (upstream `SWK_*`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Swk {
    /// Identifier text (module / decl name / label).
    Ident,
    /// Rendered type or entity.
    Type,
    /// List markers `y` (empty) and `_` (first element).
    ListMark,
    /// Postfix effects ` async` / ` throws`.
    Effect,
    /// Prefix attributes `@Sendable ` etc.
    Attr,
    /// Generic parameter count list (before `l` terminator).
    Count,
    /// Where-clause requirement node.
    Req,
    /// Generic parameter pack marker (`each`-candidate).
    PackMark,
    /// Assembled generic signature `<...>`.
    GenericSig,
}

/// One demangler stack node (upstream `SWNODE`).
#[derive(Clone)]
struct Swnode {
    kind: Swk,
    text: String,
    /// Tuple element type texts (for function-param re-labeling).
    items: Vec<String>,
    /// Function-type `[effects] -> result` tail.
    aux: String,
    /// Nominal kind letter (C=class, V=struct, O=enum, ...).
    ckind: u8,
    /// True for tuple nodes (text already parenthesized).
    tuple: bool,
    /// True for function-type nodes (parens under `?`).
    func: bool,
}

impl Swnode {
    /// Construct a minimal node.
    fn new(kind: Swk, text: impl Into<String>) -> Self {
        Swnode {
            kind,
            text: text.into(),
            items: Vec::new(),
            aux: String::new(),
            ckind: 0,
            tuple: false,
            func: false,
        }
    }
}

/// Demangler state (upstream `SWIFTINFO`).
struct SwiftInfo<'a> {
    sym: &'a str,
    pos: usize,
    errored: bool,
    stack: Vec<Swnode>,
    substs: Vec<Swnode>,
}

/// Swift known-type table (standard library `S<letter>` forms).
const SWIFT_KNOWN: &[(u8, &str)] = &[
    (b'A', "AutoreleasingUnsafeMutablePointer"),
    (b'a', "Swift.Array"),
    (b'B', "Swift.BinaryFloatingPoint"),
    (b'b', "Swift.Bool"),
    (b'D', "Swift.Dictionary"),
    (b'd', "Swift.Double"),
    (b'E', "Swift.Encodable"),
    (b'e', "Swift.Decodable"),
    (b'F', "Swift.FloatingPoint"),
    (b'f', "Swift.Float"),
    (b'G', "Swift.RandomNumberGenerator"),
    (b'H', "Swift.Hashable"),
    (b'h', "Swift.Set"),
    (b'I', "Swift.DefaultIndices"),
    (b'i', "Swift.Int"),
    (b'J', "Swift.Character"),
    (b'j', "Swift.Numeric"),
    (b'K', "Swift.BidirectionalCollection"),
    (b'k', "Swift.RandomAccessCollection"),
    (b'L', "Swift.Comparable"),
    (b'l', "Swift.Collection"),
    (b'M', "Swift.MutableCollection"),
    (b'm', "Swift.RangeReplaceableCollection"),
    (b'N', "Swift.ClosedRange"),
    (b'n', "Swift.Range"),
    (b'O', "Swift.ObjectIdentifier"),
    (b'P', "Swift.UnsafePointer"),
    (b'p', "Swift.UnsafeMutablePointer"),
    (b'Q', "Swift.Equatable"),
    (b'q', "Swift.Optional"),
    (b'R', "Swift.UnsafeBufferPointer"),
    (b'r', "Swift.UnsafeMutableBufferPointer"),
    (b'S', "Swift.String"),
    (b's', "Swift.Substring"),
    (b'T', "Swift.Sequence"),
    (b't', "Swift.IteratorProtocol"),
    (b'U', "Swift.UnsignedInteger"),
    (b'u', "Swift.UInt"),
    (b'V', "Swift.UnsafeRawPointer"),
    (b'v', "Swift.UnsafeMutableRawPointer"),
    (b'W', "Swift.UnsafeRawBufferPointer"),
    (b'w', "Swift.UnsafeMutableRawBufferPointer"),
    (b'X', "Swift.RangeExpression"),
    (b'x', "Swift.Strideable"),
    (b'Y', "Swift.RawRepresentable"),
    (b'y', "Swift.StringProtocol"),
    (b'Z', "Swift.SignedInteger"),
    (b'z', "Swift.BinaryInteger"),
];

/// Swift concurrency known-type table (`Sc<letter>` forms).
const SWIFT_CONC: &[(u8, &str)] = &[
    (b'A', "Swift.Actor"),
    (b'C', "Swift.CheckedContinuation"),
    (b'c', "Swift.UnsafeContinuation"),
    (b'E', "Swift.CancellationError"),
    (b'e', "Swift.UnownedSerialExecutor"),
    (b'F', "Swift.Executor"),
    (b'f', "Swift.SerialExecutor"),
    (b'G', "Swift.TaskGroup"),
    (b'g', "Swift.ThrowingTaskGroup"),
    (b'I', "Swift.AsyncIteratorProtocol"),
    (b'i', "Swift.AsyncSequence"),
    (b'J', "Swift.UnownedJob"),
    (b'M', "Swift.MainActor"),
    (b'P', "Swift.TaskPriority"),
    (b'S', "Swift.AsyncStream"),
    (b's', "Swift.AsyncThrowingStream"),
    (b'T', "Swift.Task"),
    (b't', "Swift.UnsafeCurrentTask"),
];

/// Generic parameter name (upstream `swift_genericParamName`):
/// index → base-26 letters LSB-first, depth as decimal suffix.
fn swift_generic_param_name(depth: i64, index: i64) -> String {
    let mut idx = if index < 0 { 0u64 } else { index as u64 };
    let mut out = String::new();
    loop {
        out.push((b'A' + (idx % 26) as u8) as char);
        idx /= 26;
        if idx == 0 {
            break;
        }
    }
    if depth > 0 {
        out.push_str(&depth.to_string());
    }
    out
}

/// Layout-constraint display name (upstream `swift_layoutName`).
fn swift_layout_name(c: u8) -> &'static str {
    match c {
        b'C' => "AnyObject",
        b'D' => "_NativeClass",
        b'N' => "_NativeRefCountedObject",
        b'R' => "_RefCountedObject",
        b'T' => "_Trivial",
        b'U' => "_UnknownLayout",
        b'B' => "_BridgeObject",
        _ => "",
    }
}

/// Accessor suffix for `v`/`i` entities; `None` means unmodeled → raw.
fn swift_accessor_suffix(c: u8) -> Option<&'static str> {
    Some(match c {
        b'g' | b'G' => ".getter",
        b's' => ".setter",
        b'm' => ".materializeForSet",
        b'w' => ".willset",
        b'W' => ".didset",
        b'r' => ".read",
        b'M' => ".modify",
        b'x' => ".modify2",
        b'p' => "",
        _ => return None,
    })
}

impl<'a> SwiftInfo<'a> {
    /// Current char or NUL.
    fn peek(&self) -> u8 {
        *self.sym.as_bytes().get(self.pos).unwrap_or(&0)
    }

    /// Char at `pos + n` or NUL.
    fn peek_at(&self, n: usize) -> u8 {
        *self.sym.as_bytes().get(self.pos + n).unwrap_or(&0)
    }

    /// Consume and return the current char (NUL sets errored).
    fn nextc(&mut self) -> u8 {
        let c = self.peek();
        if c == 0 {
            self.errored = true;
        } else {
            self.pos += 1;
        }
        c
    }

    /// Consume `c` if present.
    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == c {
            self.pos += 1;
            return true;
        }
        false
    }

    /// `swift_parseNatural` — nonzero-led decimal.
    fn parse_natural(&mut self) -> Option<i64> {
        if !(b'1'..=b'9').contains(&self.peek()) {
            return None;
        }
        let mut n: i64 = 0;
        while self.peek().is_ascii_digit() {
            let d = (self.peek() - b'0') as i64;
            if n > (i64::MAX - d) / 10 {
                return None;
            }
            n = n * 10 + d;
            self.pos += 1;
        }
        Some(n)
    }

    /// `swift_parseIndex` — `_`(0) or `<digits>_`(n+1).
    fn parse_index(&mut self) -> Option<i64> {
        if self.eat(b'_') {
            return Some(0);
        }
        if !self.peek().is_ascii_digit() {
            return None;
        }
        let mut n: i64 = 0;
        while self.peek().is_ascii_digit() {
            let d = (self.peek() - b'0') as i64;
            if n > (i64::MAX - 2 - d) / 10 {
                return None;
            }
            n = n * 10 + d;
            self.pos += 1;
        }
        if !self.eat(b'_') {
            return None;
        }
        Some(n + 1)
    }

    /// Push a plain node.
    fn push(&mut self, kind: Swk, text: impl Into<String>) {
        self.stack.push(Swnode::new(kind, text));
    }

    /// Push a node and register it as a substitution.
    fn push_subst(&mut self, kind: Swk, text: impl Into<String>) {
        let node = Swnode::new(kind, text);
        self.stack.push(node.clone());
        self.substs.push(node);
    }

    /// Pop a node; empty stack is an error.
    fn pop(&mut self) -> Option<Swnode> {
        match self.stack.pop() {
            Some(n) => Some(n),
            None => {
                self.errored = true;
                None
            }
        }
    }

    /// `swift_readIdentifier` — `<natural><bytes>`.
    fn read_identifier(&mut self) -> Option<String> {
        let len = self.parse_natural()?;
        if len < 0 || len > (self.sym.len() - self.pos) as i64 {
            return None;
        }
        let s = &self.sym[self.pos..self.pos + len as usize];
        self.pos += len as usize;
        Some(s.to_string())
    }

    /// `swift_popTypeList` — pop back to and including a list marker.
    fn pop_type_list(&mut self) -> Vec<Swnode> {
        let mut out = Vec::new();
        while let Some(n) = self.stack.pop() {
            if n.kind == Swk::ListMark {
                break;
            }
            out.insert(0, n);
        }
        out
    }

    /// Pop a pending generic-signature node or "".
    fn take_generic_sig(&mut self) -> String {
        if self.stack.last().is_some_and(|n| n.kind == Swk::GenericSig) {
            return self.stack.pop().map(|n| n.text).unwrap_or_default();
        }
        String::new()
    }

    /// `swift_parseGPIName` — absolute generic-param name.
    fn parse_gpi_name(&mut self) -> Option<String> {
        match self.peek() {
            b'z' => {
                self.pos += 1;
                Some(swift_generic_param_name(0, 0))
            }
            b'd' => {
                self.pos += 1;
                let depth = self.parse_index()?;
                let index = self.parse_index()?;
                Some(swift_generic_param_name(depth + 1, index))
            }
            b's' => None,
            _ => Some(swift_generic_param_name(0, self.parse_index()? + 1)),
        }
    }

    /// `swift_demangleTop` — dispatch one mangled item.
    fn demangle_top(&mut self) {
        let c = self.peek();
        if c.is_ascii_digit() {
            match self.read_identifier() {
                Some(id) => self.push_subst(Swk::Ident, id),
                None => self.errored = true,
            }
            return;
        }
        match c {
            b'S' => {
                let d = self.peek_at(1);
                if d == b'C' {
                    self.pos += 2;
                    self.push(Swk::Ident, "__C_Synthesized");
                } else if d == b'o' {
                    self.pos += 2;
                    self.push(Swk::Ident, "__C");
                } else {
                    self.pos += 1;
                    self.demangle_known_type();
                }
            }
            b's' => {
                self.pos += 1;
                self.push(Swk::Ident, "Swift");
            }
            b'B' => {
                self.pos += 1;
                self.demangle_builtin();
            }
            b'C' | b'V' | b'O' | b'a' | b'P' => {
                self.pos += 1;
                self.demangle_nominal(c);
            }
            b'y' => {
                self.pos += 1;
                self.push(Swk::ListMark, "y");
            }
            b'_' => {
                self.pos += 1;
                self.push(Swk::ListMark, "_");
            }
            b'G' => {
                self.pos += 1;
                self.demangle_bound_generic();
            }
            b't' => {
                self.pos += 1;
                self.demangle_tuple();
            }
            b'D' => self.pos += 1,
            b'F' => {
                self.pos += 1;
                self.demangle_function();
            }
            b'A' => {
                self.pos += 1;
                self.demangle_substitution();
            }
            b'x' => {
                self.pos += 1;
                self.push(Swk::Type, swift_generic_param_name(0, 0));
            }
            b'q' => {
                self.pos += 1;
                if self.eat(b'd') {
                    match (self.parse_index(), self.parse_index()) {
                        (Some(d), Some(i)) => {
                            self.push(Swk::Type, swift_generic_param_name(d + 1, i))
                        }
                        _ => self.errored = true,
                    }
                } else {
                    match self.parse_index() {
                        Some(i) => self.push(Swk::Type, swift_generic_param_name(0, i + 1)),
                        None => self.errored = true,
                    }
                }
            }
            b'm' => {
                self.pos += 1;
                if let Some(inner) = self.pop() {
                    self.push(Swk::Type, format!("{}.Type", inner.text));
                }
            }
            b'Y' => {
                self.pos += 1;
                self.demangle_y();
            }
            b'z' | b'n' | b'h' => {
                self.pos += 1;
                match self.stack.last_mut() {
                    Some(n) if n.kind == Swk::Type => {
                        let pre = match c {
                            b'z' => "inout ",
                            b'n' => "__owned ",
                            _ => "__shared ",
                        };
                        n.text = format!("{}{}", pre, n.text);
                    }
                    _ => self.errored = true,
                }
            }
            b'd' => {
                self.pos += 1;
                match self.stack.last_mut() {
                    Some(n) if n.kind == Swk::Type => n.text.push_str("..."),
                    _ => self.errored = true,
                }
            }
            b'K' => {
                self.pos += 1;
                self.push(Swk::Effect, " throws");
            }
            b'c' | b'X' => {
                self.pos += 1;
                self.demangle_fn_type(c);
            }
            b'p' => {
                self.pos += 1;
                self.demangle_existential();
            }
            b'E' => {
                self.pos += 1;
                self.demangle_extension();
            }
            b'Q' => {
                self.demangle_assoc_type();
            }
            b'R' => {
                self.pos += 1;
                self.demangle_requirement();
            }
            b'r' => {
                self.pos += 1;
                self.demangle_param_counts();
            }
            b'l' => {
                self.pos += 1;
                self.finish_generic_sig();
            }
            b'v' => {
                self.pos += 1;
                self.demangle_variable();
            }
            b'i' => {
                self.pos += 1;
                self.demangle_subscript();
            }
            b'f' => {
                self.pos += 1;
                self.demangle_f_entity();
            }
            b'Z' => {
                self.pos += 1;
                match self.stack.last_mut() {
                    Some(n) => n.text = format!("static {}", n.text),
                    None => self.errored = true,
                }
            }
            b'T' => {
                self.pos += 1;
                self.demangle_thunk();
            }
            b'M' => {
                self.pos += 1;
                self.demangle_metadata();
            }
            b'W' => {
                self.pos += 1;
                self.demangle_witness();
            }
            _ => self.errored = true,
        }
    }

    /// `Y`-effect continuation (upstream's per-element `t`/`k`/`i`
    /// list-type attributes and `a`/`b`/`j` effects).
    fn demangle_y(&mut self) {
        let d = self.nextc();
        if self.errored {
            return;
        }
        match d {
            b'a' => self.push(Swk::Effect, " async"),
            b'b' => self.push(Swk::Attr, "@Sendable "),
            b'j' => match self.nextc() {
                b'f' => self.push(Swk::Attr, "@differentiable(_forward) "),
                b'r' => self.push(Swk::Attr, "@differentiable(reverse) "),
                b'd' => self.push(Swk::Attr, "@differentiable "),
                b'l' => self.push(Swk::Attr, "@differentiable(_linear) "),
                _ => self.errored = true,
            },
            b't' | b'k' | b'i' => {
                let pre = match d {
                    b't' => "_const ",
                    b'k' => "@noDerivative ",
                    _ => "isolated ",
                };
                match self.stack.last_mut() {
                    Some(n) if n.kind == Swk::Type => n.text = format!("{}{}", pre, n.text),
                    _ => self.errored = true,
                }
            }
            _ => self.errored = true,
        }
    }

    /// `S` known-type forms (repeat counts, `Sg` sugar, `Sc` concurrency,
    /// single-letter table).
    fn demangle_known_type(&mut self) {
        let c = self.peek();
        if c.is_ascii_digit() {
            let rep = match self.parse_natural() {
                Some(n) if n <= 4096 => n,
                _ => {
                    self.errored = true;
                    return;
                }
            };
            let letter = self.nextc();
            if self.errored {
                return;
            }
            let t = match SWIFT_KNOWN.iter().find(|(k, _)| *k == letter) {
                Some(&(_, t)) => t,
                None => {
                    self.errored = true;
                    return;
                }
            };
            for _ in 0..rep {
                self.push(Swk::Type, t);
            }
            return;
        }
        if c == b'g' {
            self.pos += 1;
            let inner = match self.pop() {
                Some(n) => n,
                None => return,
            };
            let text = if inner.func {
                format!("({})?", inner.text)
            } else {
                format!("{}?", inner.text)
            };
            self.push_subst(Swk::Type, text);
            return;
        }
        if c == b'c' {
            self.pos += 1;
            let d = self.nextc();
            if self.errored {
                return;
            }
            match SWIFT_CONC.iter().find(|(k, _)| *k == d) {
                Some(&(_, t)) => self.push(Swk::Type, t),
                None => self.errored = true,
            }
            return;
        }
        let letter = self.nextc();
        if self.errored {
            return;
        }
        match SWIFT_KNOWN.iter().find(|(k, _)| *k == letter) {
            Some(&(_, t)) => self.push(Swk::Type, t),
            None => self.errored = true,
        }
    }

    /// `B` builtin types.
    fn demangle_builtin(&mut self) {
        let c = self.nextc();
        if self.errored {
            return;
        }
        match c {
            b'p' => self.push(Swk::Type, "Builtin.RawPointer"),
            b'o' => self.push(Swk::Type, "Builtin.NativeObject"),
            b'O' => self.push(Swk::Type, "Builtin.UnknownObject"),
            b'b' => self.push(Swk::Type, "Builtin.BridgeObject"),
            b't' => self.push(Swk::Type, "Builtin.SILToken"),
            b'w' => self.push(Swk::Type, "Builtin.Word"),
            b'i' | b'f' => {
                let n = self.parse_natural();
                let ok = n.is_some() && self.eat(b'_');
                if !ok {
                    self.errored = true;
                    return;
                }
                let n = n.unwrap_or(0);
                if c == b'i' {
                    self.push(Swk::Type, format!("Builtin.Int{}", n));
                } else {
                    self.push(Swk::Type, format!("Builtin.FPIEEE{}", n));
                }
            }
            b'v' => {
                let n = self.parse_natural();
                let ok = n.is_some() && self.eat(b'_');
                if !ok {
                    self.errored = true;
                    return;
                }
                let elem = match self.pop() {
                    Some(e) => e,
                    None => return,
                };
                let e = elem.text.strip_prefix("Builtin.").unwrap_or(&elem.text);
                self.push(Swk::Type, format!("Builtin.Vec{}x{}", n.unwrap_or(0), e));
            }
            _ => self.errored = true,
        }
    }

    /// `C`/`V`/`O`/`a`/`P` nominal: context + name → `ctx.name`.
    fn demangle_nominal(&mut self, ckind: u8) {
        let name = match self.pop() {
            Some(n) => n,
            None => return,
        };
        let context = match self.pop() {
            Some(n) => n,
            None => return,
        };
        if name.kind != Swk::Ident || context.text.contains(" : ") || context.text.contains(" -> ")
        {
            self.errored = true;
            return;
        }
        let mut node = Swnode::new(Swk::Type, format!("{}.{}", context.text, name.text));
        node.ckind = ckind;
        self.stack.push(node.clone());
        self.substs.push(node);
    }

    /// `G` bound generic: sugar for Array/Dictionary/Optional else
    /// `base<args>`.
    fn demangle_bound_generic(&mut self) {
        let args = self.pop_type_list();
        let base = match self.pop() {
            Some(n) => n,
            None => return,
        };
        if args.is_empty() {
            self.errored = true;
            return;
        }
        let names: Vec<&str> = args.iter().map(|a| a.text.as_str()).collect();
        let result = match (base.text.as_str(), names.as_slice()) {
            ("Swift.Array", [a]) => format!("[{}]", a),
            ("Swift.Optional", [a]) => {
                let inner = if args[0].func {
                    format!("({})", a)
                } else {
                    a.to_string()
                };
                format!("{}?", inner)
            }
            ("Swift.Dictionary", [k, v]) => format!("[{} : {}]", k, v),
            _ => format!("{}<{}>", base.text, names.join(", ")),
        };
        self.push_subst(Swk::Type, result);
    }

    /// `t` tuple: optional labels, `_` first-element marker.
    fn demangle_tuple(&mut self) {
        let mut above: Vec<Swnode> = Vec::new();
        let mut marker = String::new();
        while let Some(n) = self.stack.pop() {
            if n.kind == Swk::ListMark {
                marker = n.text;
                break;
            }
            above.insert(0, n);
        }
        let mut elems: Vec<Swnode> = Vec::new();
        if marker == "_" {
            let top = match self.pop() {
                Some(n) => n,
                None => return,
            };
            if top.kind == Swk::Ident {
                let ty = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                if ty.kind != Swk::Type {
                    self.errored = true;
                    return;
                }
                elems.push(ty);
                elems.push(top);
            } else if top.kind == Swk::Type {
                elems.push(top);
            } else {
                self.errored = true;
                return;
            }
        }
        elems.extend(above);
        let mut display: Vec<String> = Vec::new();
        let mut bare: Vec<String> = Vec::new();
        let mut i = 0;
        while i < elems.len() {
            if elems[i].kind != Swk::Type {
                self.errored = true;
                return;
            }
            let ty = elems[i].text.clone();
            i += 1;
            if i < elems.len() && elems[i].kind == Swk::Ident {
                display.push(format!("{}: {}", elems[i].text, ty));
                i += 1;
            } else {
                display.push(ty.clone());
            }
            bare.push(ty);
        }
        let mut node = Swnode::new(Swk::Type, format!("({})", display.join(", ")));
        node.items = bare;
        node.tuple = true;
        self.stack.push(node);
    }

    /// `A` multi-substitution run.
    fn demangle_substitution(&mut self) {
        let mut repeat: i64 = -1;
        loop {
            let c = self.peek();
            if c.is_ascii_lowercase() {
                let idx = (c - b'a') as usize;
                match self.substs.get(idx) {
                    Some(node) => {
                        let node = node.clone();
                        let copies = if repeat > 1 { repeat } else { 1 };
                        for _ in 0..copies {
                            self.stack.push(node.clone());
                        }
                        repeat = -1;
                        self.pos += 1;
                    }
                    None => {
                        self.errored = true;
                        return;
                    }
                }
                continue;
            }
            if c.is_ascii_uppercase() {
                let idx = (c - b'A') as usize;
                match self.substs.get(idx) {
                    Some(node) => {
                        let node = node.clone();
                        let copies = if repeat > 1 { repeat } else { 1 };
                        for _ in 0..copies {
                            self.stack.push(node.clone());
                        }
                        self.pos += 1;
                        return;
                    }
                    None => {
                        self.errored = true;
                        return;
                    }
                }
            }
            if c == b'_' {
                self.pos += 1;
                let idx = (if repeat < 0 { 0 } else { repeat + 1 }) as usize + 26;
                match self.substs.get(idx) {
                    Some(node) => {
                        let node = node.clone();
                        self.stack.push(node);
                        return;
                    }
                    None => {
                        self.errored = true;
                        return;
                    }
                }
            }
            if c.is_ascii_digit() {
                match self.parse_natural() {
                    Some(n) if n <= 4096 => {
                        repeat = n;
                    }
                    _ => {
                        self.errored = true;
                        return;
                    }
                }
                continue;
            }
            self.errored = true;
            return;
        }
    }

    /// `c`/`X` function type: params, result, prefix attrs, effects.
    fn demangle_fn_type(&mut self, c: u8) {
        let mut conv = "";
        if c == b'X' {
            let k = self.nextc();
            if self.errored {
                return;
            }
            conv = match k {
                b'E' => "",
                b'f' => "@convention(thin) ",
                b'C' => "@convention(c) ",
                b'B' => "@convention(block) ",
                _ => {
                    self.errored = true;
                    return;
                }
            };
        }
        let mut prefix = String::new();
        let mut effects = String::new();
        while self
            .stack
            .last()
            .is_some_and(|n| matches!(n.kind, Swk::Effect | Swk::Attr))
        {
            let e = self
                .stack
                .pop()
                .unwrap_or_else(|| Swnode::new(Swk::Type, ""));
            if e.kind == Swk::Attr {
                prefix.push_str(&e.text);
            } else {
                effects.insert_str(0, &e.text);
            }
        }
        let params = match self.pop() {
            Some(n) => n,
            None => return,
        };
        let result = match self.pop() {
            Some(n) => n,
            None => return,
        };
        let sp = if params.kind == Swk::ListMark || params.text.is_empty() {
            "()".to_string()
        } else if params.tuple {
            params.text.clone()
        } else {
            format!("({})", params.text)
        };
        let sr = if result.kind == Swk::ListMark || result.text.is_empty() {
            "()".to_string()
        } else {
            result.text.clone()
        };
        let mut node = Swnode::new(
            Swk::Type,
            format!("{}{}{}{} -> {}", prefix, conv, sp, effects, sr),
        );
        node.items = params.items.clone();
        node.aux = format!("{} -> {}", effects, sr);
        node.func = true;
        self.stack.push(node);
    }

    /// `F` function entity: context.name[sig](labels)effects -> result.
    fn demangle_function(&mut self) {
        let generic_sig = self.take_generic_sig();
        let mut effects = String::new();
        while self.stack.last().is_some_and(|n| n.kind == Swk::Effect) {
            let e = self
                .stack
                .pop()
                .unwrap_or_else(|| Swnode::new(Swk::Type, ""));
            effects.insert_str(0, &e.text);
        }
        let params = match self.pop() {
            Some(n) => n,
            None => return,
        };
        let result = match self.pop() {
            Some(n) => n,
            None => return,
        };
        let nparams = if params.tuple {
            params.items.len()
        } else if params.kind == Swk::ListMark || params.text.is_empty() {
            0
        } else {
            1
        };
        let mut labels: Vec<String> = Vec::new();
        let mut labeled = false;
        if self
            .stack
            .last()
            .is_some_and(|n| n.kind == Swk::ListMark && n.text == "y")
        {
            self.stack.pop();
        } else if nparams > 0 {
            for _ in 0..nparams {
                match self.stack.last() {
                    Some(l) if l.kind == Swk::Ident => {
                        labels.insert(0, l.text.clone());
                        self.stack.pop();
                    }
                    Some(l) if l.kind == Swk::ListMark && l.text == "_" => {
                        labels.insert(0, "_".to_string());
                        self.stack.pop();
                    }
                    _ => {
                        self.errored = true;
                        return;
                    }
                }
            }
            labeled = true;
        }
        let name = match self.pop() {
            Some(n) => n,
            None => return,
        };
        let context = match self.pop() {
            Some(n) => n,
            None => return,
        };
        if name.kind != Swk::Ident {
            self.errored = true;
            return;
        }
        let sparams = if labeled {
            let types: Vec<String> = if params.tuple {
                params.items.clone()
            } else {
                vec![params.text.clone()]
            };
            let parts: Vec<String> = types
                .iter()
                .enumerate()
                .map(|(i, t)| match labels.get(i) {
                    Some(l) if !l.is_empty() => format!("{}: {}", l, t),
                    _ => t.clone(),
                })
                .collect();
            format!("({})", parts.join(", "))
        } else if params.kind == Swk::ListMark || params.text.is_empty() {
            "()".to_string()
        } else if params.tuple {
            params.text.clone()
        } else {
            format!("({})", params.text)
        };
        let sresult = if result.kind == Swk::ListMark || result.text.is_empty() {
            "()"
        } else {
            &result.text
        };
        self.push(
            Swk::Type,
            format!(
                "{}.{}{}{}{} -> {}",
                context.text, name.text, generic_sig, sparams, effects, sresult
            ),
        );
    }

    /// `p` existential: protocol list or `Any`.
    fn demangle_existential(&mut self) {
        if self
            .stack
            .last()
            .is_some_and(|n| n.kind == Swk::ListMark && n.text == "y")
        {
            self.stack.pop();
            self.push(Swk::Type, "Any");
            return;
        }
        let mut prots: Vec<String> = Vec::new();
        let mut marker = String::new();
        while let Some(n) = self.stack.pop() {
            if n.kind == Swk::ListMark {
                marker = n.text;
                break;
            }
            let ctx = match self.pop() {
                Some(c) => c,
                None => return,
            };
            if n.kind != Swk::Ident {
                self.errored = true;
                return;
            }
            prots.insert(0, format!("{}.{}", ctx.text, n.text));
        }
        if marker == "_" {
            let nm = match self.pop() {
                Some(n) => n,
                None => return,
            };
            let ctx = match self.pop() {
                Some(c) => c,
                None => return,
            };
            if nm.kind != Swk::Ident {
                self.errored = true;
                return;
            }
            prots.insert(0, format!("{}.{}", ctx.text, nm.text));
        }
        if prots.is_empty() {
            self.errored = true;
            return;
        }
        self.push(Swk::Type, prots.join(" & "));
    }

    /// `E` extension context: `(extension in mod):type[sig]`.
    fn demangle_extension(&mut self) {
        let gensig = self.take_generic_sig();
        let module = match self.pop() {
            Some(n) => n,
            None => return,
        };
        let ty = match self.pop() {
            Some(n) => n,
            None => return,
        };
        if module.kind != Swk::Ident {
            self.errored = true;
            return;
        }
        let mut node = Swnode::new(
            Swk::Type,
            format!("(extension in {}):{}{}", module.text, ty.text, gensig),
        );
        node.ckind = ty.ckind;
        self.stack.push(node);
    }

    /// `Q` associated-type forms (`Qp` pack expansion, `Qz`/`Qy` GPI).
    fn demangle_assoc_type(&mut self) {
        let d = self.peek_at(1);
        if d == b'p' {
            self.pos += 2;
            let _count = match self.pop() {
                Some(n) => n,
                None => return,
            };
            let pattern = match self.pop() {
                Some(n) => n,
                None => return,
            };
            self.push(Swk::Type, format!("repeat {}", pattern.text));
            return;
        }
        if d == b'z' {
            self.pos += 2;
            let assoc = match self.pop() {
                Some(n) => n,
                None => return,
            };
            if assoc.kind != Swk::Ident {
                self.errored = true;
                return;
            }
            self.push_subst(
                Swk::Type,
                format!("{}.{}", swift_generic_param_name(0, 0), assoc.text),
            );
            return;
        }
        if d == b'y' {
            self.pos += 2;
            let name = self.parse_gpi_name();
            let assoc = match self.pop() {
                Some(n) => n,
                None => return,
            };
            match name {
                Some(n) if assoc.kind == Swk::Ident => {
                    self.push_subst(Swk::Type, format!("{}.{}", n, assoc.text))
                }
                _ => self.errored = true,
            }
            return;
        }
        self.errored = true;
    }

    /// `R` requirement forms.
    fn demangle_requirement(&mut self) {
        let d = self.peek();
        if d == b'v' {
            self.pos += 1;
            match self.parse_gpi_name() {
                Some(n) => self.push(Swk::PackMark, n),
                None => self.errored = true,
            }
            return;
        }
        if d == b'i' || d == b'j' {
            self.errored = true;
            return;
        }
        if matches!(d, b'z' | b'd' | b'_') || d.is_ascii_digit() {
            let subj = match self.parse_gpi_name() {
                Some(n) => n,
                None => {
                    self.errored = true;
                    return;
                }
            };
            let proto = match self.pop() {
                Some(n) => n,
                None => return,
            };
            let sproto = if proto.kind == Swk::Ident {
                let ctx = match self.pop() {
                    Some(c) => c,
                    None => return,
                };
                format!("{}.{}", ctx.text, proto.text)
            } else {
                proto.text
            };
            self.push(Swk::Req, format!("{}: {}", subj, sproto));
            return;
        }
        self.pos += 1;
        match d {
            b'p' => {
                let subj = self.parse_gpi_name();
                let assoc = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                let proto = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                let sproto = if proto.kind == Swk::Ident {
                    let ctx = match self.pop() {
                        Some(c) => c,
                        None => return,
                    };
                    format!("{}.{}", ctx.text, proto.text)
                } else {
                    proto.text
                };
                match subj {
                    Some(s) if assoc.kind == Swk::Ident => {
                        let dep = format!("{}.{}", s, assoc.text);
                        self.substs.push(Swnode::new(Swk::Type, dep.clone()));
                        self.push(Swk::Req, format!("{}: {}", dep, sproto));
                    }
                    _ => self.errored = true,
                }
            }
            b'b' => {
                let subj = self.parse_gpi_name();
                let ty = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                match subj {
                    Some(s) => self.push(Swk::Req, format!("{}: {}", s, ty.text)),
                    None => self.errored = true,
                }
            }
            b'c' => {
                let subj = self.parse_gpi_name();
                let assoc = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                let ty = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                match subj {
                    Some(s) if assoc.kind == Swk::Ident => {
                        let dep = format!("{}.{}", s, assoc.text);
                        self.substs.push(Swnode::new(Swk::Type, dep.clone()));
                        self.push(Swk::Req, format!("{}: {}", dep, ty.text));
                    }
                    _ => self.errored = true,
                }
            }
            b's' => {
                let subj = self.parse_gpi_name();
                let ty = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                match subj {
                    Some(s) => self.push(Swk::Req, format!("{} == {}", s, ty.text)),
                    None => self.errored = true,
                }
            }
            b't' => {
                let subj = self.parse_gpi_name();
                let assoc = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                let ty = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                match subj {
                    Some(s) if assoc.kind == Swk::Ident => {
                        let dep = format!("{}.{}", s, assoc.text);
                        self.substs.push(Swnode::new(Swk::Type, dep.clone()));
                        self.push(Swk::Req, format!("{} == {}", dep, ty.text));
                    }
                    _ => self.errored = true,
                }
            }
            b'Q' => {
                let subj = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                let proto = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                let sproto = if proto.kind == Swk::Ident {
                    let ctx = match self.pop() {
                        Some(c) => c,
                        None => return,
                    };
                    format!("{}.{}", ctx.text, proto.text)
                } else {
                    proto.text
                };
                self.push(Swk::Req, format!("{}: {}", subj.text, sproto));
            }
            b'l' => {
                let subj = self.parse_gpi_name();
                let cl = self.nextc();
                if self.errored {
                    return;
                }
                match (subj, swift_layout_name(cl)) {
                    (Some(s), lay) if !lay.is_empty() => {
                        self.push(Swk::Req, format!("{}: {}", s, lay))
                    }
                    _ => self.errored = true,
                }
            }
            _ => self.errored = true,
        }
    }

    /// `r` generic-parameter counts through `l`.
    fn demangle_param_counts(&mut self) {
        let mut counts: Vec<String> = Vec::new();
        loop {
            let c = self.peek();
            if c == b'l' {
                break;
            }
            if c == b'z' {
                self.pos += 1;
                counts.push("0".to_string());
                continue;
            }
            if c == b'_' || c.is_ascii_digit() {
                match self.parse_index() {
                    Some(n) => {
                        counts.push((n + 1).to_string());
                    }
                    None => {
                        self.errored = true;
                        return;
                    }
                }
                continue;
            }
            self.errored = true;
            return;
        }
        let mut node = Swnode::new(Swk::Count, "");
        node.items = counts;
        self.stack.push(node);
    }

    /// `l` generic-signature terminator → `<params where reqs>`.
    fn finish_generic_sig(&mut self) {
        let mut nparams: i64 = 1;
        if self.stack.last().is_some_and(|n| n.kind == Swk::Count) {
            let cnt = self
                .stack
                .pop()
                .unwrap_or_else(|| Swnode::new(Swk::Type, ""));
            if cnt.items.len() >= 2 {
                self.errored = true;
                return;
            }
            if cnt.items.is_empty() {
                nparams = 0;
            } else {
                match cnt.items.last().and_then(|s| s.parse::<i64>().ok()) {
                    Some(n) => nparams = n,
                    None => {
                        self.errored = true;
                        return;
                    }
                }
            }
        }
        let mut packs: Vec<String> = Vec::new();
        let mut reqs: Vec<String> = Vec::new();
        while self
            .stack
            .last()
            .is_some_and(|n| matches!(n.kind, Swk::PackMark | Swk::Req))
        {
            let n = self
                .stack
                .pop()
                .unwrap_or_else(|| Swnode::new(Swk::Type, ""));
            if n.kind == Swk::PackMark {
                packs.push(n.text);
            } else {
                reqs.insert(0, n.text);
            }
        }
        if !(0..=64).contains(&nparams) {
            self.errored = true;
            return;
        }
        let params: Vec<String> = (0..nparams)
            .map(|i| {
                let nm = swift_generic_param_name(0, i);
                if packs.contains(&nm) {
                    format!("each {}", nm)
                } else {
                    nm
                }
            })
            .collect();
        let mut sig = format!("<{}", params.join(", "));
        if !reqs.is_empty() {
            sig.push_str(" where ");
            sig.push_str(&reqs.join(", "));
        }
        sig.push('>');
        self.push(Swk::GenericSig, sig);
    }

    /// `v` variable: `ctx.name[suffix] : type`.
    fn demangle_variable(&mut self) {
        let acc = self.nextc();
        if self.errored {
            return;
        }
        let suffix = match swift_accessor_suffix(acc) {
            Some(s) => s,
            None => {
                self.errored = true;
                return;
            }
        };
        let ty = match self.pop() {
            Some(n) => n,
            None => return,
        };
        if self.stack.last().is_some_and(|n| n.kind == Swk::ListMark) {
            self.stack.pop();
        }
        let name = match self.pop() {
            Some(n) => n,
            None => return,
        };
        let context = match self.pop() {
            Some(n) => n,
            None => return,
        };
        if name.kind != Swk::Ident {
            self.errored = true;
            return;
        }
        self.push(
            Swk::Type,
            format!("{}.{}{} : {}", context.text, name.text, suffix, ty.text),
        );
    }

    /// `i` subscript entity.
    fn demangle_subscript(&mut self) {
        let acc = self.nextc();
        if self.errored {
            return;
        }
        let suffix = match swift_accessor_suffix(acc) {
            Some(s) => s,
            None => {
                self.errored = true;
                return;
            }
        };
        let ty = match self.pop() {
            Some(n) => n,
            None => return,
        };
        let mut labels: Vec<String> = Vec::new();
        let mut labeled = false;
        if self
            .stack
            .last()
            .is_some_and(|n| n.kind == Swk::ListMark && n.text == "y")
        {
            self.stack.pop();
        } else if ty.func {
            for _ in 0..ty.items.len() {
                match self.stack.last() {
                    Some(l) if l.kind == Swk::Ident => {
                        labels.insert(0, l.text.clone());
                        self.stack.pop();
                    }
                    Some(l) if l.kind == Swk::ListMark && l.text == "_" => {
                        labels.insert(0, "_".to_string());
                        self.stack.pop();
                    }
                    _ => {
                        self.errored = true;
                        return;
                    }
                }
            }
            labeled = true;
        }
        let context = match self.pop() {
            Some(n) => n,
            None => return,
        };
        let tstr = if labeled {
            let parts: Vec<String> = ty
                .items
                .iter()
                .enumerate()
                .map(|(k, t)| match labels.get(k) {
                    Some(l) if !l.is_empty() => format!("{}: {}", l, t),
                    _ => t.clone(),
                })
                .collect();
            format!("({}){}", parts.join(", "), ty.aux)
        } else {
            ty.text.clone()
        };
        if acc == b'p' && ty.func {
            self.push(Swk::Type, format!("{}.subscript{}", context.text, tstr));
        } else {
            self.push(
                Swk::Type,
                format!("{}.subscript{} : {}", context.text, suffix, tstr),
            );
        }
    }

    /// `f` ctor/dtor/init/default-arg entities.
    fn demangle_f_entity(&mut self) {
        let d = self.nextc();
        if self.errored {
            return;
        }
        match d {
            b'C' | b'c' => {
                let ty = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                let mut labels: Vec<String> = Vec::new();
                for _ in 0..ty.items.len() {
                    match self.stack.last() {
                        Some(l) if l.kind == Swk::Ident => {
                            labels.insert(0, l.text.clone());
                            self.stack.pop();
                        }
                        Some(l) if l.kind == Swk::ListMark && l.text == "_" => {
                            labels.insert(0, "_".to_string());
                            self.stack.pop();
                        }
                        _ => {
                            self.errored = true;
                            return;
                        }
                    }
                }
                let context = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                let name = if d == b'C' && context.ckind == b'C' {
                    "__allocating_init"
                } else {
                    "init"
                };
                let parts: Vec<String> = ty
                    .items
                    .iter()
                    .enumerate()
                    .map(|(k, t)| match labels.get(k) {
                        Some(l) if !l.is_empty() => format!("{}: {}", l, t),
                        _ => t.clone(),
                    })
                    .collect();
                let tail = if ty.aux.is_empty() {
                    " -> ()"
                } else {
                    ty.aux.as_str()
                };
                self.push(
                    Swk::Type,
                    format!("{}.{}({}){}", context.text, name, parts.join(", "), tail),
                );
            }
            b'D' => {
                let context = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                self.push(Swk::Type, format!("{}.__deallocating_deinit", context.text));
            }
            b'd' => {
                let context = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                self.push(Swk::Type, format!("{}.deinit", context.text));
            }
            b'i' => {
                let inner = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                self.push(
                    Swk::Type,
                    format!("variable initialization expression of {}", inner.text),
                );
            }
            b'A' => {
                let idx = match self.parse_index() {
                    Some(n) => n,
                    None => {
                        self.errored = true;
                        return;
                    }
                };
                let inner = match self.pop() {
                    Some(n) => n,
                    None => return,
                };
                self.push(
                    Swk::Type,
                    format!("default argument {} of {}", idx, inner.text),
                );
            }
            _ => self.errored = true,
        }
    }

    /// `T` thunk wrappers.
    fn demangle_thunk(&mut self) {
        let d = self.nextc();
        if self.errored {
            return;
        }
        let prefix = match d {
            b'o' => "@objc ",
            b'O' => "@nonobjc ",
            b'm' => "merged ",
            b'j' => "dispatch thunk of ",
            b'q' => "method descriptor for ",
            _ => {
                self.errored = true;
                return;
            }
        };
        let inner = match self.pop() {
            Some(n) => n,
            None => return,
        };
        self.push(Swk::Type, format!("{}{}", prefix, inner.text));
    }

    /// `M` metadata/descriptor accessors.
    fn demangle_metadata(&mut self) {
        let d = self.nextc();
        if self.errored {
            return;
        }
        let desc = match d {
            b'a' => "type metadata accessor for ",
            b'n' => "nominal type descriptor for ",
            b'p' => "protocol descriptor for ",
            b'o' => "class metadata base offset for ",
            b'u' => "method lookup function for ",
            b'V' => "property descriptor for ",
            b'f' => "full type metadata for ",
            b'm' => "metaclass for ",
            b'F' => "reflection metadata field descriptor ",
            _ => {
                self.errored = true;
                return;
            }
        };
        let inner = match self.pop() {
            Some(n) => n,
            None => return,
        };
        if inner.kind != Swk::Type {
            self.errored = true;
            return;
        }
        self.push(Swk::Type, format!("{}{}", desc, inner.text));
    }

    /// `W` witness tables (`WV` only).
    fn demangle_witness(&mut self) {
        let d = self.nextc();
        if self.errored {
            return;
        }
        if d == b'V' {
            let inner = match self.pop() {
                Some(n) => n,
                None => return,
            };
            if inner.kind != Swk::Type {
                self.errored = true;
                return;
            }
            self.push(Swk::Type, format!("value witness table for {}", inner.text));
            return;
        }
        self.errored = true;
    }
}

/// Go symbol decoder — faithful port of upstream
/// `XDemangle::go_demangle` (xdemangle.cpp): U+00B7 -> '.',
/// U+2215 -> '/', and runs of %XX decode as UTF-8 (invalid UTF-8
/// or embedded NUL aborts the whole decode to the raw fallback).
fn demangle_go(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '\u{00b7}' {
            out.push('.');
            i += 1;
        } else if c == '\u{2215}' {
            out.push('/');
            i += 1;
        } else if c == '%' && i + 2 < chars.len() {
            let mut bytes: Vec<u8> = Vec::new();
            while i + 2 < chars.len() && chars[i] == '%' {
                let hi = chars[i + 1].to_digit(16);
                let lo = chars[i + 2].to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) if h < 16 && l < 16 => {
                        bytes.push(((h << 4) | l) as u8);
                        i += 3;
                    }
                    _ => break,
                }
            }
            if bytes.is_empty() {
                out.push(c);
                i += 1;
            } else {
                let decoded = String::from_utf8(bytes);
                match decoded {
                    Ok(d) if !d.contains('\0') => out.push_str(&d),
                    _ => return None,
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    Some(out)
}

/// GNAT/Ada decoder — faithful port of upstream
/// `XDemangle::gnat_demangle` + `gnat_demangleName`
/// (xdemangle.cpp). Lowercase identifiers, `__` scope separators,
/// `O<op>` operator names, TK__ inner-task segments, `X[n|b]` body
/// nesting, stream ops `S<letter>_`, controlled ops `DF`/`DA`,
/// `_E`/`_B` entry bodies and `_<digits>` overload stamps.
fn demangle_gnat(s: &str) -> Option<String> {
    let mangled = s.strip_prefix("_ada_").unwrap_or(s);
    gnat_demangle_name(mangled).or_else(|| Some(format!("<{}>", mangled)))
}

/// True for ASCII lowercase (upstream `gnat_isLower`).
fn gnat_is_lower(c: char) -> bool {
    c.is_ascii_lowercase()
}

/// True for ASCII digit (upstream `gnat_isDigit`).
fn gnat_is_digit(c: char) -> bool {
    c.is_ascii_digit()
}

/// Safe char access mirroring upstream `watcom_charAt`: out-of-range
/// reads yield '\0'.
fn char_at(s: &str, pos: usize) -> char {
    s.chars().nth(pos).unwrap_or('\0')
}

/// Port of upstream `gnat_demangleName`.
fn gnat_demangle_name(mangled: &str) -> Option<String> {
    const OPERATORS: &[(&str, &str)] = &[
        ("Oabs", "abs"),
        ("Oand", "and"),
        ("Omod", "mod"),
        ("Onot", "not"),
        ("Oor", "or"),
        ("Orem", "rem"),
        ("Oxor", "xor"),
        ("Oeq", "="),
        ("One", "/="),
        ("Olt", "<"),
        ("Ole", "<="),
        ("Ogt", ">"),
        ("Oge", ">="),
        ("Oadd", "+"),
        ("Osubtract", "-"),
        ("Oconcat", "&"),
        ("Omultiply", "*"),
        ("Odivide", "/"),
        ("Oexpon", "**"),
    ];
    const SPECIAL: &[(&str, &str)] = &[
        ("_elabb", "'Elab_Body"),
        ("_elabs", "'Elab_Spec"),
        ("_size", "'Size"),
        ("_alignment", "'Alignment"),
        ("_assign", ".\":=\""),
    ];

    let n = mangled.chars().count();
    let mut d = String::new();
    let mut p = 0usize;

    if !gnat_is_lower(char_at(mangled, 0)) {
        return None;
    }

    loop {
        let c = char_at(mangled, p);

        if gnat_is_lower(c) {
            loop {
                d.push(char_at(mangled, p));
                p += 1;
                let nc = char_at(mangled, p);
                if !(gnat_is_lower(nc)
                    || gnat_is_digit(nc)
                    || (nc == '_'
                        && (gnat_is_lower(char_at(mangled, p + 1))
                            || gnat_is_digit(char_at(mangled, p + 1)))))
                {
                    break;
                }
            }
        } else if c == 'O' {
            let rest: String = mangled.chars().skip(p).collect();
            let mut found = false;
            for (enc, op) in OPERATORS {
                if rest.starts_with(enc) {
                    p += enc.len();
                    d.push('"');
                    d.push_str(op);
                    d.push('"');
                    found = true;
                    break;
                }
            }
            if !found {
                return None;
            }
        } else {
            return None;
        }

        if char_at(mangled, p) == 'T' && char_at(mangled, p + 1) == 'K' {
            if char_at(mangled, p + 2) == 'B' && p + 3 >= n {
                break; // subprogram for task body
            } else if char_at(mangled, p + 2) == '_' && char_at(mangled, p + 3) == '_' {
                p += 4;
                d.push('.');
                continue;
            } else {
                return None;
            }
        }

        if char_at(mangled, p) == 'E' && p + 1 >= n {
            return None; // exception name
        }

        if matches!(char_at(mangled, p), 'P' | 'N') && p + 1 >= n {
            break; // protected type subprogram
        }

        if matches!(char_at(mangled, p), 'N' | 'S') && p + 1 >= n {
            return None; // enumerated type name table
        }

        if char_at(mangled, p) == 'X' {
            p += 1;
            while matches!(char_at(mangled, p), 'n' | 'b') {
                p += 1;
            }
        }

        if char_at(mangled, p) == 'S' && p + 1 < n && (char_at(mangled, p + 2) == '_' || p + 2 >= n)
        {
            let sname = match char_at(mangled, p + 1) {
                'R' => "'Read",
                'W' => "'Write",
                'I' => "'Input",
                'O' => "'Output",
                _ => return None,
            };
            p += 2;
            d.push_str(sname);
        } else if char_at(mangled, p) == 'D' {
            let sname = match char_at(mangled, p + 1) {
                'F' => ".Finalize",
                'A' => ".Adjust",
                _ => return None,
            };
            if p + 2 < n {
                return None;
            }
            d.push_str(sname);
            break;
        }

        if char_at(mangled, p) == '_' {
            let cnext = char_at(mangled, p + 1);
            if cnext == '_' {
                p += 2;
                if gnat_is_digit(char_at(mangled, p)) {
                    loop {
                        p += 1;
                        let nc = char_at(mangled, p);
                        if !(gnat_is_digit(nc)
                            || (nc == '_' && gnat_is_digit(char_at(mangled, p + 1))))
                        {
                            break;
                        }
                    }
                    if char_at(mangled, p) == 'X' {
                        p += 1;
                        while matches!(char_at(mangled, p), 'n' | 'b') {
                            p += 1;
                        }
                    }
                } else if char_at(mangled, p) == '_' && char_at(mangled, p + 1) != '_' {
                    let rest: String = mangled.chars().skip(p).collect();
                    let mut found = false;
                    for (enc, sp) in SPECIAL {
                        if rest == *enc {
                            d.push_str(sp);
                            found = true;
                            break;
                        }
                    }
                    if found {
                        break;
                    }
                    return None;
                } else {
                    d.push('.');
                    continue;
                }
            } else if matches!(cnext, 'B' | 'E') {
                p += 2;
                while gnat_is_digit(char_at(mangled, p)) {
                    p += 1;
                }
                if char_at(mangled, p) == 's' && p + 1 >= n {
                    break;
                }
                return None;
            } else {
                return None;
            }
        }

        if char_at(mangled, p) == '.' && gnat_is_digit(char_at(mangled, p + 1)) {
            p += 2;
            while gnat_is_digit(char_at(mangled, p)) {
                p += 1;
            }
        }

        if p >= n {
            break;
        }
        return None;
    }

    Some(d)
}

/// Haskell (GHC Z-encoding) decoder — faithful port of upstream
/// `XDemangle::haskell_demangle` (xdemangle.cpp): `Z`-escapes
/// (`ZL`=`(`, `Z<n>T`=n-tuple, `Z<n>H`=unboxed tuple) and `z`-escapes
/// (`zi`=`.`, `zh`=`#`, `z<hex>U`=code point). Invalid scalar values
/// or tuple-width overflow abort the decode (raw fallback).
fn demangle_haskell(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;

    while i < n {
        let c = chars[i];

        if c == 'Z' && i + 1 < n {
            let d = chars[i + 1];
            if d.is_ascii_digit() {
                let mut j = i + 1;
                let mut num: u64 = 0;
                while j < n && chars[j].is_ascii_digit() {
                    let dig = (chars[j] as u64) - ('0' as u64);
                    if num > (4096 - dig) / 10 {
                        return None; // bound tuple expansion, reject overflow
                    }
                    num = num * 10 + dig;
                    j += 1;
                }
                if j < n && chars[j] == 'T' {
                    if num == 0 {
                        out.push_str("()");
                    } else {
                        out.push('(');
                        for _ in 0..num - 1 {
                            out.push(',');
                        }
                        out.push(')');
                    }
                    i = j + 1;
                } else if j < n && chars[j] == 'H' {
                    if num == 1 {
                        out.push_str("(# #)");
                    } else {
                        out.push_str("(#");
                        for _ in 0..num - 1 {
                            out.push(',');
                        }
                        out.push_str("#)");
                    }
                    i = j + 1;
                } else {
                    out.push(c);
                    i += 1;
                }
            } else {
                let r = match d {
                    'L' => '(',
                    'R' => ')',
                    'M' => '[',
                    'N' => ']',
                    'C' => ':',
                    'Z' => 'Z',
                    _ => d,
                };
                out.push(r);
                i += 2;
            }
        } else if c == 'z' && i + 1 < n {
            let d = chars[i + 1];
            if d.is_ascii_digit() {
                // Numeric escape: z<hex>U
                let mut j = i + 1;
                let mut num: u64 = 0;
                while j < n {
                    let hv = chars[j].to_digit(16);
                    match hv {
                        Some(v) if v < 16 => {
                            if num > (0x10FFFF - v as u64) / 16 {
                                return None;
                            }
                            num = num * 16 + v as u64;
                            j += 1;
                        }
                        _ => break,
                    }
                }
                if j < n && chars[j] == 'U' {
                    if num == 0 || (0xD800..=0xDFFF).contains(&num) {
                        return None; // not a printable Unicode scalar
                    }
                    out.push(char::from_u32(num as u32)?);
                    i = j + 1;
                } else {
                    out.push(c);
                    i += 1;
                }
            } else {
                let r = match d {
                    'z' => 'z',
                    'a' => '&',
                    'b' => '|',
                    'c' => '^',
                    'd' => '$',
                    'e' => '=',
                    'g' => '>',
                    'h' => '#',
                    'i' => '.',
                    'l' => '<',
                    'm' => '-',
                    'n' => '!',
                    'p' => '+',
                    'q' => '\'',
                    'r' => '\\',
                    's' => '/',
                    't' => '*',
                    'u' => '_',
                    'v' => '%',
                    _ => d,
                };
                out.push(r);
                i += 2;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }

    Some(out)
}

/// OCaml decoder — faithful port of upstream
/// `XDemangle::ocaml_demangle` (xdemangle.cpp): strip `caml`,
/// decode `$XX` hex escapes, drop a trailing `_<digits>` stamp and
/// turn `__` into `.`. Non-`caml` input returns None (raw fallback).
fn demangle_ocaml(s: &str) -> Option<String> {
    let rest = s.strip_prefix("caml")?;
    let chars: Vec<char> = rest.chars().collect();
    let mut decoded = String::with_capacity(rest.len());
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '$' && i + 2 < chars.len() {
            let hi = chars[i + 1].to_digit(16);
            let lo = chars[i + 2].to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                decoded.push(char::from_u32((h << 4) | l).unwrap_or(c));
                i += 3;
                continue;
            }
        }
        decoded.push(c);
        i += 1;
    }
    // Drop a trailing _<digits> compilation stamp.
    if let Some(pos) = decoded.rfind('_') {
        let tail = &decoded[pos + 1..];
        if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            decoded.truncate(pos);
        }
    }
    Some(decoded.replace("__", "."))
}

/// Tru64 (Compaq C++) decoder — delegates to the GNU v2 machinery
/// with the `__X` ARM-mode marker allowed (upstream
/// `demangle(..., MODE_TRU64)` calls `gnu2_demangle(s, true)`).
fn demangle_tru64(s: &str) -> Option<String> {
    demangle_gnuv2_x(s, true)
}

/// GNU v2 entry point shared by `GnuV2` and `Tru64` modes.
/// `allow_x_marker` enables the ARM-style `__X` signature marker
/// (upstream `gnu2_demangle`'s `bAllowXMarker`).
fn demangle_gnuv2_x(s: &str, allow_x_marker: bool) -> Option<String> {
    gnu2_demangle(s, allow_x_marker)
}

/// SunPro (Sun Studio) decoder — faithful port of upstream
/// `XDemangle::sun_demangle` (xdemangle.cpp):
/// `__1c` (`<len-letter><name>`)+ `6F` <arg-type>* `_` <ret-type> `_`
/// where `<len-letter>` encodes length 1..25 as 'B'..'Z'.
/// All-or-nothing: the whole symbol must be consumed.
fn demangle_sun(s: &str) -> Option<String> {
    let rest = s.strip_prefix("__1c")?;
    let chars: Vec<char> = rest.chars().collect();
    let mut pos = 0usize;

    let mut names: Vec<String> = Vec::new();
    loop {
        let c = char_at(rest, pos);
        if ('B'..='Z').contains(&c) {
            let len = (c as usize) - ('A' as usize);
            pos += 1;
            if pos + len > chars.len() {
                return None;
            }
            names.push(chars[pos..pos + len].iter().collect());
            pos += len;
        } else {
            break;
        }
    }
    if names.is_empty() {
        return None;
    }

    if char_at(rest, pos) != '6' || char_at(rest, pos + 1) != 'F' {
        return None;
    }
    pos += 2;

    let mut args: Vec<&'static str> = Vec::new();
    while char_at(rest, pos) != '_' {
        if pos >= chars.len() {
            return None;
        }
        args.push(sun_builtin(char_at(rest, pos))?);
        pos += 1;
    }
    pos += 1;
    // 'void' denotes an empty argument list and cannot accompany others.
    if args.contains(&"void") && args.len() != 1 {
        return None;
    }

    let ret = sun_builtin(char_at(rest, pos))?;
    pos += 1;
    if char_at(rest, pos) != '_' {
        return None;
    }
    pos += 1;
    if pos != chars.len() {
        return None;
    }

    let args_str = if args.is_empty() {
        "void".to_string()
    } else {
        args.join(", ")
    };
    Some(format!("{} {}({})", ret, names.join("::"), args_str))
}

/// Sun builtin type letter -> C type name (upstream `sun_builtin`).
fn sun_builtin(c: char) -> Option<&'static str> {
    match c {
        'v' => Some("void"),
        'b' => Some("bool"),
        'c' => Some("char"),
        's' => Some("short"),
        'i' => Some("int"),
        'l' => Some("long"),
        'f' => Some("float"),
        'd' => Some("double"),
        _ => None,
    }
}

/// GNU v2 (g++ 2.x / ARM-era) demangler — faithful port of upstream
/// `gnu2_demangle` (`xdemangle.cpp`), itself derived from libiberty
/// cplus-dem. Covers `__ti`/`__tf` type-info, `_GLOBAL_` forms,
/// `_$_`/`_._` destructors, `__vt_`/`_vt$` vtables, `_<class>$<var>`
/// statics, `__<class>` constructors, `__<op>` operators, and the
/// general `name__<sig>` function form with the run-splitting
/// backtrack. Tru64 mode passes `allow_x_marker` for `__X` signatures.
fn demangle_gnuv2(s: &str) -> Option<String> {
    gnu2_demangle(s, false)
}

/// Shared GNU v2 entry point (upstream `gnu2_demangle`).
fn gnu2_demangle(s: &str, allow_x: bool) -> Option<String> {
    if s.len() > 65536 {
        return None;
    }
    if let Some(r) = gnu2_special(s) {
        return (r.len() <= 1_048_576).then_some(r);
    }
    if !s.contains("__") || s.contains("_GLOBAL_") {
        return None;
    }
    if let Some(rest) = s.strip_prefix("__") {
        let c2 = rest.as_bytes().first().copied().unwrap_or(0);
        if c2.is_ascii_digit() || c2 == b'Q' || c2 == b't' {
            return gnu2_try_function(s, 2, "", true, allow_x);
        }
        let nn = rest.find("__")?;
        let code = &rest[..nn];
        let func_name = if let Some(t) = code.strip_prefix("op") {
            let mut info = Gnu2Info::new(t);
            let ty = info.ty()?;
            if info.pos != t.len() {
                return None;
            }
            format!("operator {}", ty)
        } else {
            gnu2_operator_name(code)?
        };
        return gnu2_try_function(s, nn + 4, &func_name, false, allow_x);
    }
    // Plain function: try every "__" run, splitting at the LAST pair
    // of each run, first successful full parse wins.
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i..].starts_with(b"__") {
            let mut scan = i;
            while scan + 2 < b.len() && b[scan + 2] == b'_' {
                scan += 1;
            }
            let name_end = scan;
            let sig_start = scan + 2;
            if name_end > 0
                && let Some(r) = gnu2_try_function(s, sig_start, &s[..name_end], false, allow_x)
            {
                return Some(r);
            }
            i = scan + 2;
            while i < b.len() && b[i] == b'_' {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    None
}

/// GNU v2 parser state (upstream `GNU2INFO`).
struct Gnu2Info<'a> {
    m: &'a str,
    pos: usize,
    depth: u32,
    steps: u32,
    errored: bool,
    /// Remembered arg types (`T<n>`/`N<r><n>` backrefs).
    remembered: Vec<String>,
    /// Template-function args (`X<idx>` backrefs).
    tmpl_args: Vec<String>,
    /// Template functions encode a return type after the args.
    expect_return: bool,
}

impl<'a> Gnu2Info<'a> {
    /// Fresh state on a mangled string.
    fn new(m: &'a str) -> Self {
        Gnu2Info {
            m,
            pos: 0,
            depth: 0,
            steps: 0,
            errored: false,
            remembered: Vec::new(),
            tmpl_args: Vec::new(),
            expect_return: false,
        }
    }

    /// Char at `pos + n` or NUL.
    fn at(&self, n: usize) -> u8 {
        *self.m.as_bytes().get(self.pos + n).unwrap_or(&0)
    }

    /// Bounded recursion (upstream `XDemangleGNU2Scope`).
    fn guarded<T>(&mut self, f: impl FnOnce(&mut Self) -> Option<T>) -> Option<T> {
        if self.errored || self.depth >= 128 || self.steps >= 200_000 {
            self.errored = true;
            return None;
        }
        self.depth += 1;
        self.steps += 1;
        let r = f(self);
        self.depth -= 1;
        r
    }

    /// `gnu2_consumeCount` — decimal run.
    fn consume_count(&mut self) -> Option<i64> {
        if !self.at(0).is_ascii_digit() {
            return None;
        }
        let mut n: i64 = 0;
        while self.at(0).is_ascii_digit() {
            let d = (self.at(0) - b'0') as i64;
            if n > (i64::MAX - d) / 10 {
                return None;
            }
            n = n * 10 + d;
            self.pos += 1;
        }
        Some(n)
    }

    /// `gnu2_getCount` — single digit, or full count if `_`-terminated.
    fn get_count(&mut self) -> Option<i64> {
        if !self.at(0).is_ascii_digit() {
            return None;
        }
        let save = self.pos;
        let n = self.consume_count()?;
        if self.at(0) == b'_' {
            self.pos += 1;
            return Some(n);
        }
        self.pos = save + 1;
        Some((self.m.as_bytes()[save] - b'0') as i64)
    }

    /// `gnu2_args` — `(...)` arg list through `_` or end; `T`/`N`
    /// backrefs, `e` ellipsis, empty → `(void)`.
    fn args(&mut self) -> Option<String> {
        self.guarded(|s| s.args_inner())
    }

    /// Inner of `args`.
    fn args_inner(&mut self) -> Option<String> {
        let mut list: Vec<String> = Vec::new();
        let mut length: i64 = 0;
        let mut ellipsis = false;
        loop {
            let c = self.at(0);
            if c == 0 || c == b'_' {
                break;
            }
            if c == b'e' {
                self.pos += 1;
                ellipsis = true;
                break;
            }
            if c == b'N' {
                self.pos += 1;
                let rep = self.get_count()?;
                if rep <= 0 || rep > 1024 {
                    return None;
                }
                let idx = self.get_count()?;
                let ty = self.remembered.get(idx as usize)?.clone();
                for _ in 0..rep {
                    if !append_bounded(&mut list, &ty, &mut length) {
                        return None;
                    }
                }
                continue;
            }
            if c == b'T' {
                self.pos += 1;
                let idx = self.get_count()?;
                let ty = self.remembered.get(idx as usize)?.clone();
                if !append_bounded(&mut list, &ty, &mut length) {
                    return None;
                }
                continue;
            }
            let before = self.pos;
            let ty = self.ty()?;
            if self.pos == before {
                return None;
            }
            self.remembered.push(ty.clone());
            if !append_bounded(&mut list, &ty, &mut length) {
                return None;
            }
        }
        let mut inner = list.join(", ");
        if ellipsis {
            inner += if inner.is_empty() { "..." } else { ",..." };
        } else if list.is_empty() {
            inner = "void".to_string();
        }
        Some(format!("({})", inner))
    }

    /// `gnu2_type` — declarator prefixes (`P`/`p`/`R`/`O`, cv-quals,
    /// `F` function, `T` backref, `M` member-pointer) then the base.
    fn ty(&mut self) -> Option<String> {
        self.guarded(|s| s.ty_inner())
    }

    /// Inner of `ty`.
    fn ty_inner(&mut self) -> Option<String> {
        let mut decl = String::new();
        let mut result;
        loop {
            if decl.len() > 1_048_576 {
                return None;
            }
            match self.at(0) {
                b'P' | b'p' => {
                    self.pos += 1;
                    decl.insert(0, '*');
                }
                b'R' => {
                    self.pos += 1;
                    decl.insert(0, '&');
                }
                b'O' => {
                    self.pos += 1;
                    decl.insert_str(0, "&&");
                }
                b'C' | b'V' | b'u' => {
                    let q = match self.at(0) {
                        b'C' => "const",
                        b'V' => "volatile",
                        _ => "__restrict",
                    };
                    if !decl.is_empty() {
                        decl.insert(0, ' ');
                    }
                    decl.insert_str(0, q);
                    self.pos += 1;
                }
                b'F' => {
                    self.pos += 1;
                    if !decl.is_empty() && (decl.starts_with('*') || decl.starts_with('&')) {
                        decl.insert(0, '(');
                        decl.push(')');
                    }
                    let saved = std::mem::take(&mut self.remembered);
                    let a = self.args();
                    self.remembered = saved;
                    decl.push_str(&a?);
                    if self.at(0) == b'_' {
                        self.pos += 1;
                    }
                }
                b'T' => {
                    self.pos += 1;
                    let n = self.get_count()?;
                    let mut out = self.remembered.get(n as usize)?.clone();
                    if !decl.is_empty() {
                        out.push(' ');
                        out.push_str(&decl);
                    }
                    return (out.len() <= 1_048_576).then_some(out);
                }
                b'M' => {
                    self.pos += 1;
                    let cc = self.at(0);
                    let cls = if cc.is_ascii_digit() {
                        let n = self.consume_count()?;
                        if n <= 0 || n > (self.m.len() - self.pos) as i64 {
                            return None;
                        }
                        let s = self.m[self.pos..self.pos + n as usize].to_string();
                        self.pos += n as usize;
                        s
                    } else if cc == b'Q' {
                        self.qualified()?.0
                    } else if cc == b't' {
                        self.template()?.0
                    } else {
                        return None;
                    };
                    decl = format!("({}::{})", cls, decl);
                    let cq = self.at(0);
                    if matches!(cq, b'C' | b'V' | b'u') {
                        self.pos += 1;
                    }
                    if self.at(0) == b'F' {
                        self.pos += 1;
                        let saved = std::mem::take(&mut self.remembered);
                        let a = self.args();
                        self.remembered = saved;
                        decl.push_str(&a?);
                        if self.at(0) == b'_' {
                            self.pos += 1;
                        }
                    }
                }
                b'G' => self.pos += 1,
                _ => break,
            }
        }
        let c = self.at(0);
        result = if c == b'Q' || c == b'K' {
            self.qualified()?.0
        } else if c == b'X' || c == b'Y' {
            self.pos += 1;
            let mut idx: i64 = -1;
            for which in 0..2 {
                let d = self.at(0);
                let val = if d == b'_' {
                    self.pos += 1;
                    let v = self.consume_count()?;
                    if self.at(0) != b'_' {
                        return None;
                    }
                    self.pos += 1;
                    v
                } else if d.is_ascii_digit() {
                    self.pos += 1;
                    (d - b'0') as i64
                } else {
                    return None;
                };
                if which == 0 {
                    idx = val;
                }
            }
            if idx < 0 {
                return None;
            }
            self.tmpl_args.get(idx as usize)?.clone()
        } else {
            self.fund_type()?
        };
        if !decl.is_empty() {
            result.push(' ');
            result.push_str(&decl);
        }
        (result.len() <= 1_048_576).then_some(result)
    }

    /// `gnu2_fundType` — qualifier prefixes then a fundamental /
    /// explicit-length class name / template type.
    fn fund_type(&mut self) -> Option<String> {
        self.guarded(|s| s.fund_type_inner())
    }

    /// Inner of `fund_type`.
    fn fund_type_inner(&mut self) -> Option<String> {
        let mut result = String::new();
        loop {
            match self.at(0) {
                b'C' | b'V' | b'u' => {
                    let q = match self.at(0) {
                        b'C' => "const",
                        b'V' => "volatile",
                        _ => "__restrict",
                    };
                    if !result.is_empty() {
                        result.insert(0, ' ');
                    }
                    result.insert_str(0, q);
                    self.pos += 1;
                }
                b'U' => {
                    self.pos += 1;
                    if !result.is_empty() {
                        result.push(' ');
                    }
                    result.push_str("unsigned");
                }
                b'S' => {
                    self.pos += 1;
                    if !result.is_empty() {
                        result.push(' ');
                    }
                    result.push_str("signed");
                }
                b'J' => {
                    self.pos += 1;
                    if !result.is_empty() {
                        result.push(' ');
                    }
                    result.push_str("__complex");
                }
                _ => break,
            }
        }
        let c = self.at(0);
        let word = match c {
            b'v' => "void",
            b'x' => "long long",
            b'l' => "long",
            b'i' => "int",
            b's' => "short",
            b'b' => "bool",
            b'c' => "char",
            b'w' => "wchar_t",
            b'r' => "long double",
            b'd' => "double",
            b'f' => "float",
            _ => "",
        };
        if !word.is_empty() {
            self.pos += 1;
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str(word);
            return Some(result);
        }
        if c.is_ascii_digit() {
            let n = self.consume_count()?;
            if n <= 0 || n > (self.m.len() - self.pos) as i64 {
                return None;
            }
            let name = &self.m[self.pos..self.pos + n as usize];
            self.pos += n as usize;
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str(name);
            return Some(result);
        }
        if c == b't' {
            let (tmpl, _bare) = self.template()?;
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str(&tmpl);
            return Some(result);
        }
        None
    }

    /// `gnu2_template` — `t<len><name><nargs><args>` → `name<a, b>`.
    /// Returns `(rendered, bare-name)`.
    fn template(&mut self) -> Option<(String, String)> {
        self.guarded(|s| s.template_inner())
    }

    /// Inner of `template`.
    fn template_inner(&mut self) -> Option<(String, String)> {
        if self.at(0) != b't' {
            return None;
        }
        self.pos += 1;
        let n = self.consume_count()?;
        if n <= 0 || n > (self.m.len() - self.pos) as i64 {
            return None;
        }
        let name = self.m[self.pos..self.pos + n as usize].to_string();
        self.pos += n as usize;
        let nargs = self.get_count()?;
        if !(0..=1024).contains(&nargs) {
            return None;
        }
        let mut args: Vec<String> = Vec::new();
        let mut length: i64 = 0;
        for _ in 0..nargs {
            if self.at(0) == b'Z' {
                self.pos += 1;
                let t = self.ty()?;
                if !append_bounded(&mut args, &t, &mut length) {
                    return None;
                }
            } else {
                let _t = self.ty()?;
                let v = self.integral_value()?;
                if !append_bounded(&mut args, &v, &mut length) {
                    return None;
                }
            }
        }
        let joined = args.join(", ");
        let space = if joined.ends_with('>') { " " } else { "" };
        if name.len() + joined.len() + space.len() + 2 > 1_048_576 {
            return None;
        }
        Some((format!("{}<{}{}>", name, joined, space), name))
    }

    /// `gnu2_qualified` — `Q[<n> | _<count>_]<len><name|t...>` chain.
    /// Returns `(a::b::c, last-name)`.
    fn qualified(&mut self) -> Option<(String, String)> {
        self.guarded(|s| s.qualified_inner())
    }

    /// Inner of `qualified`.
    fn qualified_inner(&mut self) -> Option<(String, String)> {
        if self.at(0) != b'Q' {
            return None;
        }
        self.pos += 1;
        let count = if self.at(0) == b'_' {
            self.pos += 1;
            let n = self.consume_count()?;
            if self.at(0) != b'_' {
                return None;
            }
            self.pos += 1;
            n
        } else if self.at(0).is_ascii_digit() {
            let n = (self.at(0) - b'0') as i64;
            self.pos += 1;
            n
        } else {
            return None;
        };
        if !(1..=1024).contains(&count) {
            return None;
        }
        let mut parts: Vec<String> = Vec::new();
        let mut length: i64 = 0;
        let mut last = String::new();
        for _ in 0..count {
            let c = self.at(0);
            if c == b't' {
                let (tmpl, bare) = self.template()?;
                if !append_bounded(&mut parts, &tmpl, &mut length) {
                    return None;
                }
                last = bare;
            } else if c.is_ascii_digit() {
                let n = self.consume_count()?;
                if n <= 0 || n > (self.m.len() - self.pos) as i64 {
                    return None;
                }
                let name = self.m[self.pos..self.pos + n as usize].to_string();
                self.pos += n as usize;
                if !append_bounded(&mut parts, &name, &mut length) {
                    return None;
                }
                last = name;
            } else {
                return None;
            }
        }
        Some((parts.join("::"), last))
    }

    /// `gnu2_integralValue` — template value argument.
    fn integral_value(&mut self) -> Option<String> {
        let c = self.at(0);
        if c == b'E' {
            return None;
        }
        if c == b'Q' || c == b'K' {
            return Some(self.qualified()?.0);
        }
        let mut s = String::new();
        let mut multidigit = false;
        let mut leave_underscore = false;
        if c == b'_' {
            if self.at(1) == b'm' {
                multidigit = true;
                s.push('-');
                self.pos += 2;
            } else {
                leave_underscore = true;
            }
        } else {
            if c == b'm' {
                s.push('-');
                self.pos += 1;
            }
            multidigit = true;
            leave_underscore = true;
        }
        let value = if multidigit {
            self.consume_count()?
        } else if self.at(0) == b'_' {
            self.pos += 1;
            let v = self.consume_count()?;
            if self.at(0) != b'_' {
                return None;
            }
            self.pos += 1;
            v
        } else {
            let d = self.at(0);
            if !d.is_ascii_digit() {
                return None;
            }
            self.pos += 1;
            (d - b'0') as i64
        };
        s.push_str(&value.to_string());
        if (value > 9 || multidigit) && !leave_underscore && self.at(0) == b'_' {
            self.pos += 1;
        }
        Some(s)
    }
}

/// `gnu2_appendBounded` — list append with size accounting.
fn append_bounded(list: &mut Vec<String>, value: &str, length: &mut i64) -> bool {
    let added = value.len() as i64 + if list.is_empty() { 0 } else { 2 };
    if list.len() >= 1024 || added > 1_048_576 - *length {
        return false;
    }
    list.push(value.to_string());
    *length += added;
    true
}

/// `gnu2_operatorName` — GNU v2 two-letter operator table.
fn gnu2_operator_name(code: &str) -> Option<String> {
    const OPS: &[(&str, &str)] = &[
        ("nw", " new"),
        ("dl", " delete"),
        ("vn", " new []"),
        ("vd", " delete []"),
        ("as", "="),
        ("ne", "!="),
        ("eq", "=="),
        ("ge", ">="),
        ("gt", ">"),
        ("le", "<="),
        ("lt", "<"),
        ("pl", "+"),
        ("apl", "+="),
        ("mi", "-"),
        ("ami", "-="),
        ("ml", "*"),
        ("amu", "*="),
        ("aml", "*="),
        ("md", "%"),
        ("amd", "%="),
        ("dv", "/"),
        ("adv", "/="),
        ("aa", "&&"),
        ("oo", "||"),
        ("nt", "!"),
        ("pp", "++"),
        ("mm", "--"),
        ("or", "|"),
        ("aor", "|="),
        ("er", "^"),
        ("aer", "^="),
        ("ad", "&"),
        ("aad", "&="),
        ("co", "~"),
        ("cl", "()"),
        ("ls", "<<"),
        ("als", "<<="),
        ("rs", ">>"),
        ("ars", ">>="),
        ("rf", "->"),
        ("vc", "[]"),
        ("cm", ", "),
        ("cn", "?:"),
        ("mx", ">?"),
        ("mn", "<?"),
        ("rm", "->*"),
        ("sz", "sizeof "),
    ];
    OPS.iter()
        .find(|(k, _)| *k == code)
        .map(|(_, v)| format!("operator{}", v))
}

/// `gnu2_special` — `__ti`/`__tf`, `_GLOBAL_`, `_$_`/`_._`,
/// `__vt_`/`_vt$`/`_vt.`, `_<class>$<var>` forms.
fn gnu2_special(s: &str) -> Option<String> {
    if s.starts_with("__ti") || s.starts_with("__tf") {
        let mut info = Gnu2Info::new(s);
        info.pos = 4;
        let ty = info.ty()?;
        if info.pos != s.len() {
            return None;
        }
        let suffix = if s.starts_with("__ti") {
            " type_info node"
        } else {
            " type_info function"
        };
        return Some(format!("{}{}", ty, suffix));
    }
    if let Some(g) = s.find("_GLOBAL_") {
        let p = g + 8;
        let b = s.as_bytes();
        let m1 = b.get(p).copied().unwrap_or(0);
        let kind = b.get(p + 1).copied().unwrap_or(0);
        let m2 = b.get(p + 2).copied().unwrap_or(0);
        if matches!(m1, b'$' | b'.') && matches!(m2, b'$' | b'.') {
            if kind == b'I' {
                return Some(format!("global constructors keyed to {}", &s[p + 3..]));
            }
            if kind == b'D' {
                return Some(format!("global destructors keyed to {}", &s[p + 3..]));
            }
            if kind == b'N' {
                let last = s.rfind(['$', '.']);
                let var = last.map(|i| &s[i + 1..]).unwrap_or("");
                return Some(format!("{{anonymous}}::{}", var));
            }
        }
        return None;
    }
    if s.starts_with("_$_") || s.starts_with("_._") {
        let mut info = Gnu2Info::new(s);
        info.pos = 3;
        let c = info.at(0);
        let (class, bare) = if c == b'Q' {
            info.qualified()?
        } else if c == b't' {
            info.template()?
        } else if c.is_ascii_digit() {
            let n = info.consume_count()?;
            if n <= 0 || n > (s.len() - info.pos) as i64 {
                return None;
            }
            let name = s[info.pos..info.pos + n as usize].to_string();
            info.pos += n as usize;
            (name.clone(), name)
        } else {
            return None;
        };
        let args = info.args()?;
        if info.pos != s.len() {
            return None;
        }
        return Some(format!("{}::~{}{}", class, bare, args));
    }
    if let Some(rest) = s.strip_prefix("__vt_") {
        let mut info = Gnu2Info::new(s);
        info.pos = 5;
        let c = info.at(0);
        let name = if c == b'Q' {
            info.qualified()?.0
        } else if c.is_ascii_digit() {
            let n = info.consume_count()?;
            if n <= 0 || n > (s.len() - info.pos) as i64 {
                return None;
            }
            let name = s[info.pos..info.pos + n as usize].to_string();
            info.pos += n as usize;
            name
        } else {
            return None;
        };
        if info.pos != s.len() {
            return None;
        }
        let _ = rest;
        return Some(format!("{} virtual table", name));
    }
    if s.starts_with("_vt$") || s.starts_with("_vt.") {
        let rest = &s[4..];
        let cur = rest.replace('.', "$");
        let mut parts: Vec<String> = Vec::new();
        let mut length: i64 = 0;
        for part in cur.split('$') {
            let pb = part.as_bytes();
            if pb.first() == Some(&b't') && pb.get(1).is_some_and(|c| c.is_ascii_digit()) {
                let mut info = Gnu2Info::new(part);
                if let Some((tmpl, _)) = info.template()
                    && info.pos == part.len()
                {
                    if !append_bounded(&mut parts, &tmpl, &mut length) {
                        return None;
                    }
                    continue;
                }
            }
            if !append_bounded(&mut parts, part, &mut length) {
                return None;
            }
        }
        return Some(format!("{} virtual table", parts.join("::")));
    }
    if s.starts_with('_') && !s.starts_with("__") {
        let c = s.as_bytes().get(1).copied().unwrap_or(0);
        if c.is_ascii_digit() || c == b'Q' || c == b't' {
            let mut info = Gnu2Info::new(s);
            info.pos = 1;
            let (class, _bare) = if c == b'Q' {
                info.qualified()?
            } else if c == b't' {
                info.template()?
            } else {
                let n = info.consume_count()?;
                if n <= 0 || n > (s.len() - info.pos) as i64 {
                    return None;
                }
                let name = s[info.pos..info.pos + n as usize].to_string();
                info.pos += n as usize;
                (name.clone(), name)
            };
            let sep = info.at(0);
            if sep != b'$' && sep != b'.' {
                return None;
            }
            info.pos += 1;
            let var = &s[info.pos..];
            if var.is_empty() {
                return None;
            }
            return Some(format!("{}::{}", class, var));
        }
    }
    None
}

/// `gnu2_tryFunction` — parse `<sig>` at `sig_start` as a function
/// (member quals, class spec, `S` static, `H` template, `F`/`X`
/// marker, args, optional template return). All-or-nothing.
fn gnu2_try_function(
    s: &str,
    sig_start: usize,
    func_name: &str,
    ctor: bool,
    allow_x: bool,
) -> Option<String> {
    let mut info = Gnu2Info::new(s);
    info.pos = sig_start;
    let mut quals = String::new();
    loop {
        match info.at(0) {
            b'C' => {
                if !quals.is_empty() {
                    quals.push(' ');
                }
                quals.push_str("const");
                info.pos += 1;
            }
            b'V' => {
                if !quals.is_empty() {
                    quals.push(' ');
                }
                quals.push_str("volatile");
                info.pos += 1;
            }
            _ => break,
        }
    }
    let c = info.at(0);
    let mut class = String::new();
    let mut bare_class = String::new();
    if c.is_ascii_digit() {
        let n = info.consume_count()?;
        if n <= 0 || n > (s.len() - info.pos) as i64 {
            return None;
        }
        class = s[info.pos..info.pos + n as usize].to_string();
        info.pos += n as usize;
        bare_class = class.clone();
        info.remembered.push(class.clone());
    } else if c == b'Q' {
        let (cl, bare) = info.qualified()?;
        class = cl;
        bare_class = bare;
        info.remembered.push(class.clone());
    } else if c == b't' {
        let (cl, bare) = info.template()?;
        class = cl;
        bare_class = bare;
        info.remembered.push(class.clone());
    }
    if info.at(0) == b'S' {
        info.pos += 1;
    }
    let mut tmpl_args_str = String::new();
    if info.at(0) == b'H' {
        info.pos += 1;
        info.expect_return = true;
        let nt = info.get_count()?;
        if !(0..=1024).contains(&nt) {
            return None;
        }
        let mut list: Vec<String> = Vec::new();
        let mut length: i64 = 0;
        for _ in 0..nt {
            if info.at(0) == b'Z' {
                info.pos += 1;
                let t = info.ty()?;
                info.tmpl_args.push(t.clone());
                if !append_bounded(&mut list, &t, &mut length) {
                    return None;
                }
            } else {
                return None;
            }
        }
        let joined = list.join(", ");
        tmpl_args_str = format!(
            "<{}{}>",
            joined,
            if joined.ends_with('>') { " " } else { "" }
        );
        if info.at(0) == b'_' {
            info.pos += 1;
        }
    }
    // Tru64 ARM-mode uses '__X' where GNU uses '__F'; the X form is
    // rejected for template functions (H-form), whose args may begin
    // with an `X<idx>` back-reference.
    if info.at(0) == b'F' || (allow_x && !info.expect_return && info.at(0) == b'X') {
        info.pos += 1;
    }
    let args = info.args()?;
    let mut ret = String::new();
    if info.expect_return {
        if info.at(0) == b'_' {
            info.pos += 1;
        }
        ret = info.ty()?;
    }
    if info.pos != s.len() {
        return None;
    }
    let mut func = if ctor {
        bare_class
    } else {
        func_name.to_string()
    };
    func.push_str(&tmpl_args_str);
    let mut full = if !class.is_empty() {
        format!("{}::{}", class, func)
    } else {
        func
    };
    full.push_str(&args);
    if !quals.is_empty() {
        full.push(' ');
        full.push_str(&quals);
    }
    if !ret.is_empty() {
        full = format!("{} {}", ret, full);
    }
    (full.len() <= 1_048_576).then_some(full)
}

#[cfg(test)]
mod tests {
    /// Differential test: every `(mode, symbol)` pair in
    /// `corpus/demangle/pairs.txt` must demangle byte-identically to the
    /// upstream `XDemangle::demangle` snapshot in `oracle.txt`
    /// (generated by `tools/demangle-oracle`).
    #[test]
    fn demangle_matches_upstream_oracle() {
        let pairs = std::fs::read_to_string("../../corpus/demangle/pairs.txt").unwrap();
        let oracle = std::fs::read_to_string("../../corpus/demangle/oracle.txt").unwrap();
        let expected: std::collections::HashMap<(String, String), String> = oracle
            .lines()
            .filter(|l| !l.is_empty())
            .map(|line| {
                let mut it = line.splitn(3, '\t');
                let mode = it.next().unwrap().to_string();
                let sym = it.next().unwrap().to_string();
                let out = it.next().unwrap_or("").to_string();
                ((mode, sym), out)
            })
            .collect();
        let mut failures = Vec::new();
        for line in pairs.lines() {
            if line.is_empty() {
                continue;
            }
            let (mode_name, sym) = line.split_once('\t').unwrap();
            let mode = super::DemangleMode::parse(mode_name);
            let out = super::demangle_with_mode(sym, mode);
            let want = expected
                .get(&(mode_name.to_string(), sym.to_string()))
                .unwrap_or_else(|| panic!("no oracle row for {mode_name}\t{sym}"));
            if &out != want {
                failures.push(format!("{mode_name}\t{sym}\n  want: {want}\n  got:  {out}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} demangle mismatches:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

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
        assert_eq!(demangle_symbol("_D3foo3barFZv", "auto"), "foo.bar()");
        assert_eq!(demangle_symbol("_Dmain", "auto"), "D main");
    }

    #[test]
    fn demangle_java_jni() {
        // Upstream MODE_JAVA does not decode JNI `Java_*` names.
        assert_eq!(
            demangle_symbol("Java_com_example_Foo_bar", "java"),
            "Java_com_example_Foo_bar"
        );
    }

    #[test]
    fn demangle_borland32_qualified() {
        assert_eq!(
            demangle_symbol("@Unit1@TForm1@Foo$qpv", "auto"),
            "Unit1::TForm1::Foo(*void)"
        );
    }

    #[test]
    fn demangle_watcom_name() {
        // `_n_` is not a valid upstream Watcom signature -> raw.
        assert_eq!(demangle_symbol("W?main$_n_", "watcom"), "W?main$_n_");
    }

    #[test]
    fn demangle_unknown_passthrough() {
        assert_eq!(demangle_symbol("plain_symbol", "auto"), "plain_symbol");
    }

    // -- Phase 18.A: previously-deferred modes --

    #[test]
    fn demangle_swift_function() {
        // `yF` is a ()-returning function but upstream's all-or-nothing
        // parser rejects this bare identifier form -> raw passthrough.
        assert_eq!(
            demangle_symbol("$s4test5helloyF", "auto"),
            "$s4test5helloyF"
        );
        let out = demangle_symbol("_$s7MyClass8callbackySiF", "swift");
        assert_eq!(out, "_$s7MyClass8callbackySiF");
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
        assert_eq!(out, "base_GHC.IO_$ws_info");
        let out = demangle_symbol("Main_zimain_closure", "haskell");
        assert_eq!(out, "Main_.main_closure");
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
        // `__vtbl__` is not an upstream Tru64 form -> raw.
        assert_eq!(demangle_symbol("__vtbl__3Bar", "tru64"), "__vtbl__3Bar");
    }

    #[test]
    fn demangle_sun_function() {
        // __1cD put 6F _v_  -> void put(void)
        assert_eq!(demangle_symbol("__1cDput6F_v_", "auto"), "void put(void)");
    }

    #[test]
    fn demangle_gnuv2_forms() {
        assert_eq!(demangle_symbol("__vt_3Foo", "auto"), "Foo virtual table");
        assert_eq!(demangle_symbol("_$_3Foo", "gnuv2"), "Foo::~Foo(void)");
        assert_eq!(demangle_symbol("bar__3FooFi", "gnuv2"), "Foo::bar(int)");
        assert_eq!(demangle_symbol("baz__Fi", "gnuv2"), "baz(int)");
    }
}

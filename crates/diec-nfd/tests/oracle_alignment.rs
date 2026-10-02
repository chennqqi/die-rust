//! Phase 23 regression tests: behaviors pinned against the upstream
//! DIE-engine oracle (`tools/nfd-oracle`). Each test mirrors a diff that
//! was observed and fixed during the differential-convergence pass.

use diec_nfd::{Detection, ScanOptions, scan, sniff_ft};

fn corpus(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Options matching the oracle harness: deep + heuristic + verbose +
/// recursive + archives + overlay, non-aggressive, non-all-types.
fn oracle_opts() -> ScanOptions {
    ScanOptions {
        deep_scan: true,
        heuristic_scan: true,
        verbose: true,
        all_types: false,
        archives_scan: true,
        recursive_scan: true,
        resources_scan: true,
        overlay_scan: true,
        aggressive_scan: false,
    }
}

fn run(name: &str) -> Vec<Detection> {
    let d = corpus(name);
    let ft = sniff_ft(&d);
    scan(&d, ft, oracle_opts())
}

fn has(out: &[Detection], rtype: &str, name_part: &str) -> bool {
    out.iter()
        .any(|r| r.record_type == rtype && r.record_name.contains(name_part))
}

/// UPX-packed PE: the MinGW/GCC chain is detected through the
/// FT_BINARY overlay signature scan, and `getLanguage` folds GCC +
/// MinGW into `C/C++` (upstream `NFD_Binary::getLanguage`).
#[test]
fn upx_packed_emits_mingw_gcc_and_cpp_language() {
    let out = run("upx-pe32-nrv2b.exe");
    assert!(has(&out, "Packer", "UPX"), "{out:?}");
    assert!(has(&out, "Compiler", "GCC"), "{out:?}");
    assert!(has(&out, "Tool", "MinGW"), "{out:?}");
    assert!(has(&out, "Linker", "GNU ld"), "{out:?}");
    assert!(
        out.iter()
            .any(|r| r.record_type == "Language" && r.record_name == "C/C++"),
        "{out:?}"
    );
    // Nested scans must not leak synthetic Unknown records upward.
    assert!(!out.iter().any(|r| r.record_name == "Unknown"), "{out:?}");
}

/// Unpacked MinGW PE: `.debug_info` section name lives in the COFF
/// string table (`/N` references) — resolving it yields DWARF 5.0.
#[test]
fn unpacked_mingw_pe_resolves_coff_strtab_dwarf() {
    let out = run("upx-pe32-lzma.unpacked.exe");
    assert!(
        out.iter().any(|r| r.record_type == "Debug data"
            && r.record_name.contains("DWARF")
            && r.version == "5.0"),
        "{out:?}"
    );
    assert!(has(&out, "Debug data", "MinGW"), "{out:?}");
}

/// Bare EOCD (empty archive): upstream `XZip::isValid` accepts it, so
/// `handle_Container` emits "0 records inspected" with no
/// "central/local headers verified" suffix (that suffix is only added
/// by the strict `handle_ContainerHeader` fallback).
#[test]
fn empty_zip_eocd_is_plain_container_record() {
    let out = run("edge/empty-zip-eocd.bin");
    assert_eq!(out.len(), 1, "{out:?}");
    let r = &out[0];
    assert_eq!(r.record_type, "Format");
    assert_eq!(r.record_name, "ZIP");
    assert_eq!(r.info, "0 records inspected");
}

/// Mach-O: `clang` compiler records map to the `C/C++` language in
/// upstream `getLanguage` (Clang family → CCPP unless Objective-C).
#[test]
fn macho_clang_maps_to_cpp_language() {
    let out = run("minimal.macho");
    assert!(
        out.iter()
            .any(|r| r.record_type == "Language" && r.record_name == "C/C++"),
        "{out:?}"
    );
}

/// Nested ZIP: the ELF member scan (58-byte truncated ELF) must emit
/// the Unix OS record — upstream `read_*` returns zeroes for missing
/// trailing fields rather than rejecting the whole format. Child scans
/// must not leak a synthetic `Unknown` either.
#[test]
fn nested_zip_elf_member_os_record() {
    let out = run("nested-zip-with-pe.zip");
    assert!(
        out.iter()
            .any(|r| r.record_type == "Operation system" && r.record_name == "Unix"),
        "{out:?}"
    );
    assert!(!out.iter().any(|r| r.record_name == "Unknown"), "{out:?}");
}

/// Malformed/minimal NE: upstream enumerates the overlay file part and
/// the overlay sub-scan falls back to a bare `Unknown` record.
#[test]
fn minimal_ne_overlay_unknown() {
    let out = run("minimal-ne.exe");
    assert!(out.iter().any(|r| r.record_name == "Unknown"), "{out:?}");
}

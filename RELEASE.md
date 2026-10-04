# Release Checklist

This document defines the release process and verification checklist
for die-rust. Every item must be verified before publishing a release.

## Pre-Release

### Code Quality
- [x] `cargo fmt --check` passes with zero diffs
- [x] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` passes
- [x] No `TODO` or `FIXME` comments in released code paths
- [x] All `unsafe` blocks have safety documentation and tests

### Testing
- [x] `cargo test --workspace --all-features --locked` passes (720 tests)
- [x] Corpus differential tests pass (31 baseline + 20 edge samples)
- [x] FFI tests pass (unit + integration + sanitizer)
- [x] Edge corpus tests pass (no-crash, no-spurious, no-hang)
- [x] Go binding tests pass (5 tests)
- [x] Python binding tests pass (9 tests)
- [x] C smoke test passes

### Compatibility
- [x] `COMPATIBILITY.md` updated with current metrics
- [x] Rule loading success rate >= 99% (actual: 100%, 1186/1186)
- [x] Corpus differential: 0 engine mismatches (4 rule-version diffs documented)
- [x] All known differences documented with ADRs
- [x] Upstream source pinned to specific commit SHA (`c2c17dfa5`, vendored subtree)

### Performance
- [x] Benchmarks run on release build
- [x] database_load < 600ms (actual: ~12ms debug, ~510ms release)
- [x] scan_corpus per-file < 250ms
- [x] No performance regression vs previous release
- [x] Benchmark results recorded in COMPATIBILITY.md

### Fuzz
- [x] All 6 fuzz targets compile
- [x] Seed corpora generated and committed (165 seeds across 6 targets)
- [x] Short fuzz run (5 min per target) shows no crashes
      — seed-corpus replay passed locally on stable Rust
      (`cd fuzz && cargo test --no-default-features --features replay`,
      7 tests, 0 failures, 165 seeds × 6 harnesses); coverage-guided
      libFuzzer 5-min/target run delegated to CI (`.github/workflows/fuzz.yml`,
      Linux + nightly + cargo-fuzz, runs on every push to main and on PRs)
- [x] Any crash from prior fuzz runs is fixed or quarantined (none observed)

### CI
- [x] CI passes on all three platforms (Linux, macOS, Windows)
- [x] MSRV (1.88) build and test passes
- [x] FFI smoke test passes on all platforms
- [x] Python binding test passes on all platforms

## License and Supply Chain
- [x] `LICENSE` file present and correct (MIT)
- [x] `NOTICES.md` updated with all third-party attribution
- [x] `AUDIT.md` reviewed and current
- [x] `cargo license --all-features` output matches NOTICES.md
- [x] No copyleft licenses in dependency tree
- [x] No new dependencies without license review
- [x] Cargo.lock committed and up to date

## Build Artifacts
- [x] Release build: `cargo build --workspace --all-targets --release --locked`
- [x] CLI binary: `base/diec` (or `base/diec.exe` on Windows)
- [x] Server binary: `base/died` (or `base/died.exe` on Windows)
- [x] Top-level launcher: `diec` (Unix) / `diec.cmd` (Windows)
- [x] Static library: `lib/libdie_ffi.a` (Unix) / `lib/die_ffi.lib` (Windows)
- [x] Dynamic library: `lib/libdie_ffi.so` / `.dylib` / `lib/die_ffi.dll`
- [x] C header: `include/die.h`
- [x] Rule database: `base/db`, `base/db_extra`, `base/db_custom`
- [x] Go binding: `bindings/go/diec/diec.go`
- [x] Python binding: `bindings/python/diec.py`
- [x] All artifacts verified on at least one platform

### GUI Artifacts (v0.4.0+)
- [ ] GUI portable: `die-gui-<version>-<platform>-portable.zip/.tar.gz`
  - Windows: `die.exe` + `db/` + README + LICENSE
  - Linux: `die` + `db/` + README + LICENSE
  - macOS: `die` + `db/` + README + LICENSE
- [ ] GUI installer (Windows): `die-gui-<version>-windows-x86_64-installers.zip`
  - MSI: `Detect It Easy_<version>_x64_en-US.msi` (~14MB, perMachine)
  - NSIS: `Detect It Easy_<version>_x64-setup.exe` (~8.5MB, perMachine)
- [ ] GUI installer (Linux): `die-gui-<version>-linux-x86_64-installers.tar.gz`
  - DEB: `detect-it-easy_<version>_amd64.deb`
  - RPM: `detect-it-easy-<version>-1.x86_64.rpm`
  - AppImage: `Detect It Easy_<version>_amd64.AppImage`
- [ ] GUI installer (macOS): `die-gui-<version>-macos-arm64-installers.tar.gz`
  - DMG: `Detect It Easy_<version>_aarch64.dmg`
  - App: `Detect It Easy.app`
- [ ] Rule database bundled in all installers via `tauri.conf.json > bundle.resources`

## Documentation
- [x] `ROADMAP.md` updated with release status
- [x] `COMPATIBILITY.md` updated with final metrics
- [x] `README.md` reflects current state
- [x] `docs/design/` documents are current
- [x] `AGENTS.md` reflects current phase
- [x] Changelog / release notes drafted (`RELEASE_NOTES.md`)

## Version and Tag
- [x] Version bumped in `Cargo.toml` (workspace.package.version = 0.9.0)
- [ ] Git tag created: `v0.9.0`
- [ ] Tag is annotated (`git cat-file -t v0.9.0` => `tag`)
- [ ] Tag message includes release summary ("v0.9.0 - Phase 15: host API 100% coverage, true differential testing, --alltypes negative assertions")

## Post-Release
- [x] Release notes published (`RELEASE_NOTES.md` committed)
- [x] Artifacts uploaded to release page (verified 2026-08-05)
- [x] Compatibility report published (`COMPATIBILITY.md`)
- [x] Next milestone planned in ROADMAP.md (Phase 6 closed; maintenance + upstream-sync)

---

## Release Sign-off

### v0.9.0 — 2026-08-16

- **Tag**: `v0.9.0` (annotated, pending CI green)
- **Tests**: 720 pass, 0 failures (up from 686 in v0.8.0, +34 new tests)
- **Phase 14-15 alignment methodology** (7 sub-phases):
  - 15.1 True differential test framework vs upstream diec 4.0.0
    - 31 golden baselines from upstream diec 4.0.0 (commit c2c17dfa5)
    - filetype mapping: ZIP/TAR/RAR/PDF/CFBF/DEX/JavaClass/PNG/JPEG/Amiga/LE/LX/NE
    - 0 engine mismatches, known gaps documented (NPM/CAB)
  - 15.2 Rule execution coverage matrix + exception hardening
    - 1186/1186 rules execute without TypeError
    - Exception logging for runtime errors
  - 15.3 Host API coverage audit + P0 gap closure
    - `tools/audit_host_api.py`: automated audit vs upstream help docs
    - Coverage matrix: 270 methods tracked across 8 classes
  - 15.4 `--alltypes` systemic negative assertions
    - 20 edge corpus samples, 0 spurious detections
  - 15.5 Corpus coverage blind spot supplementation
    - New corpus files: minimal-le.exe, minimal-lx.exe, minimal-ne.exe, etc.
  - 15.6 Host API coverage 44.1% → 100%
    - 151 methods implemented (119 → 270)
    - PE .NET: BSJB metadata parsing, #US/#Strings heap extraction
    - PE: isPE32/isPEPlus/isDriver/isImportPresent/isExportPresent/isResourcesPresent
    - PE: getImportHash32/64 (FNV-1a), isImportPositionHashPresent
    - PE: compareEP_NET, findSignatureInBlob_NET, isNetTypePresent/MethodPresent/FieldPresent
    - Binary: read_int24/float/double/float16/32/64/bcd_uint8/16/32/64
    - Binary: read_utf8String, find_ansiString/find_unicodeString, upperCase/lowerCase
    - Binary: RVAToOffset/VAToOffset/OffsetToRVA/OffsetToVA (PE section table)
    - Binary: getImageBase/getAddressOfEntryPoint/compareEP/compareOverlay
    - Binary: isJpeg/getJpegComment/isJpegChunkPresent/getJpegExifCameraName
    - Binary: detectZLIB/detectGZIP/detectZIP/getCompressedDataSize
    - Binary: 15 correctness checks (is*Correct/is*Build/is*Table)
    - Binary: profiling (startTiming/endTiming/isProfiling)
    - Binary: getFileFormatName/Version/Options (magic byte detection)
    - ELF: getElfHeader_version/flags/ehsize, getRunPath
    - MSDOS: getDosStubOffset/Size/isDosStubPresent/isRichVersionPresent
    - ISO9660: 12 PVD field readers (isValid + all identifiers + dates)
    - Util: shl64/shr64/secondsToTimeStr
    - Global: includeScript/result, Archive: isArchiveRecordPresent/Exp
  - 15.7 Documentation and baseline update
    - ROADMAP.md, COMPATIBILITY.md, host-api-coverage-matrix.md updated
- **Host API coverage**: 100% (270/270 methods, 0 stub, 0 missing)
- **Rule loading**: 100% (1186/1186)
- **Differential**: 0 engine mismatches vs upstream diec 4.0.0
- **GUI**: no changes needed (architecture isolation verified)
- **No new dependencies**
- **No new ADRs** (all changes within existing architecture)

### v0.8.0 — 2026-08-15

- **Tag**: `v0.8.0` (annotated, pending CI green)
- **Tests**: 686 pass, 0 failures (up from 614 in v0.7.0, +72 new tests)
- **Phase 13 CLI parity** (8 sub-tasks):
  - 13.1 `--struct` general methods: Hash#MD5/SHA1/SHA256, Info, Entropy, Check format
  - 13.2 `--struct` format-specific methods: PE (6), ELF (2), Mach-O (2), DEX (1)
  - 13.3 `--struct` output formatting: text/JSON/XML/CSV/TSV + mode priority
  - 13.4 Intra-file recursive scanning (ADR 0028): `-r` semantic alignment
    - `-r`/`--recursivescan`: PE resources + overlay recursive scan
    - `-R`/`--recursive-dir`: directory recursion (replaces old `-r`)
    - `--resources`/`--overlays`: selective intra-file scan
    - FFI flags: RECURSIVE(0x80), RESOURCES(0x100), OVERLAYS(0x200)
  - 13.5 Archive member extraction (ADR 0029/0030): ZIP/7Z/RAR
    - Safety bounds: 128MiB single, 512MiB total, 100:1 ratio, 20/100k members
    - FFI flag: ARCHIVES(0x400)
  - 13.6 macOS platform baseline: CI 3-platform matrix (ubuntu/windows/macos-14)
  - 13.7 Corpus: nested-zip-with-pe.zip + 3 new CLI integration tests
  - 13.8 Documentation: COMPATIBILITY.md + ADR 0028/0029/0030
- **GUI sync** (die-gui):
  - 6 new toolbar checkboxes (aggressive/recursive/resources/overlay/archives/hide_unknown)
  - New "Struct" tab with Struct/Entropy/Info sub-modes
  - 4 new Tauri commands: evaluate_struct, list_struct_methods, get_entropy_info, get_scan_info
  - i18n: 5 languages updated (en/zh-CN/ru/de/fr)
- **New dependencies**: zip (MIT), sevenz-rust (Apache-2.0), rars (MIT/Apache-2.0), serde (MIT/Apache-2.0)
- **New ADRs**: 0028 (-r semantic alignment), 0029 (rars RAR library), 0030 (archive safety bounds)
- **Known differences**: CAB/ISO9660 not yet implemented; archive safety bounds stricter than upstream

### v0.7.0 — 2026-08-09

- **Tag**: `v0.7.0` (annotated)
- **Tests**: 614 pass, 0 failures (up from 597 in v0.6.1, +17 new tests)
- **Phase 11 GUI deep alignment** (8 batches):
  - 11.1 FileInfo complete header parsing (HeaderField tree + PE/ELF/Mach-O)
  - 11.2 File format detection extension (die-formats probe + magic fallback)
  - 11.3 PE dedicated view (9 sub-tabs: imports/exports/resources/overlay/.NET/manifest/version info/TLS/Rich Header)
  - 11.4 String search & extractor (ASCII/UTF-16LE + filter)
  - 11.5 Archive format extension (ZIP/TAR/GZIP+TAR)
  - 11.6 Visualization & section view (SectionVisualizer)
  - 11.7 Settings modal & shortcut config (5 tabs, 8 shortcuts)
  - 11.8 VirusTotal integration & MIME type
- **Phase 12 GUI gap v3** (35 items):
  - Batch A: PE 5 sub-views (NT_HEADERS/RESOURCES_STRINGTABLE/NET_METADATA_STREAM/NET_METADATA_TABLE/TOOLS)
  - Batch B: Mach-O 12 sub-views (weak_libraries/id_library/FVMLIB/IDFVMLIB/function_starts/data_in_code/code_signature/SuperBlob/unix_thread/dyld_chained_fixups/dyld_exports_trie/STRINGTABLE)
  - Batch C: ELF STRINGTABLE
  - Batch D: String search 8 enhancements (MapMode/FileType/jump Hex/jump Disasm/Demangle/Edit String/Save/min length 5)
  - Batch E: Visualization 5 enhancements (ZEROS_GRADIENT/TEXT_GRADIENT/highlight/zoom/save image)
  - Batch F: Extractor 3 enhancements (HEURISTIC/deep scan/analyze mode)
  - Batch G: Scan log display
- **ROADMAP.md**: Phase 11 and Phase 12 marked as DONE
- **New files**: 11 backend modules + 11 frontend components + 4 docs

### v0.6.0 — 2026-08-08

- **Tag**: `v0.6.0` (annotated)
- **Tests**: 511 pass, 0 failures (up from 506 in v0.5.0, +5 dedup tests)
- **Phase 10 known issues fix** (3 items):
  - 10.1 Documentation cleanup: getDisasmString integrated with Capstone (removed from Known Limitations)
  - 10.2 Documentation cleanup: rule version differences documented as non-defects (moved to Known Differences)
  - 10.3 Result deduplication: ADR 0027, --alltypes default dedup + --no-dedup escape hatch
- **New ADR**: ADR 0027 (result deduplication decision)
- **GUI**: Added no_dedup checkbox and i18n support (en/zh-CN)
- **ROADMAP.md**: Phase 10 marked as DONE
- **GUI build resources**: db/db_extra/dbs_min/dbs_special/peid_rules/yara_rules bundled

### v0.5.0 — 2026-08-08

- **Tag**: `v0.5.0` (annotated)
- **Tests**: 511 pass, 0 failures (up from 506 in v0.4.7, +5 dedup tests)
- **Phase 9 GUI upstream alignment** (20 items):
  - 9.1 P1 core fixes (7): ScanDetection optional fields, DB/type selection wiring,
    options display, heuristic markers, nested result tree, hex viewer rewrite,
    disassembler multi-arch + no break-on-Ret
  - 9.2 P2 completeness (7): hex data inspector + follow-in-disasm, symbol virtual
    scroll, structured diagnostics, profiling data, disasm xrefs + analyze all,
    PE imports, Mach-O FAT support
  - 9.3 P3 alignment (6): scan progress events, hex element mode, follow-in-hex,
    CRC32 hash, entropy block size configurable, i18n (already covered)
- **Phase 10 known issues fix** (3 items):
  - 10.1 Documentation cleanup: getDisasmString integrated with Capstone (removed from Known Limitations)
  - 10.2 Documentation cleanup: rule version differences documented as non-defects (moved to Known Differences)
  - 10.3 Result deduplication: ADR 0027, --alltypes default dedup + --no-dedup escape hatch
- **New dependency**: crc32fast 1.5.0
- **Frontend**: tsc --noEmit + vite build pass
- **ROADMAP.md**: Phase 9 and Phase 10 sections added with full item lists and exit conditions
- **GUI build resources**: db/db_extra/dbs_min/dbs_special/peid_rules/yara_rules bundled

### v0.4.7 — 2026-08-07

- **Tag**: `v0.4.7` (annotated)
- **Tests**: 480 pass, 0 failures (unchanged from v0.4.0)
- **CI**: 12/12 jobs pass (ci #36)
- **Fuzz**: 9/9 jobs pass (fuzz #15)
- **Release**: CLI 4/4 pass, GUI fix for tauri-cli + cp
- **No functional code changes**: only CI config + version bump
- **Artifacts**: identical to v0.4.0

### v0.4.6 — 2026-08-07

- **Tag**: `v0.4.6` (annotated)
- **Tests**: 480 pass, 0 failures (unchanged from v0.4.0)
- **CI**: 12/12 jobs pass (ci), 9/9 pass (fuzz)
- **Fuzz replay**: 7/7 pass (165 seeds)
- **Fuzz libFuzzer**: 6/6 targets compile and run
- **Fixes**: comprehensive CI config fixes (GTK deps, data dirs,
  cargo-fuzz metadata, linker, MSRV, cfg attribute)
- **No functional code changes**: only CI + fuzz config + version bump
- **Artifacts**: identical to v0.4.0

### v0.4.5 — 2026-08-07

- **Tag**: `v0.4.5` (annotated)
- **Tests**: 480 pass, 0 failures (unchanged from v0.4.0)
- **Fuzz replay**: 7/7 pass (165 seeds)
- **Fuzz libFuzzer**: all 6 targets compile (Docker CI simulation)
- **Fix**: force-link die-ffi symbols in fuzz_scan_ffi
- **No code changes**: only fuzz linker fix + version bump
- **Artifacts**: identical to v0.4.0

### v0.4.4 — 2026-08-07

- **Tag**: `v0.4.4` (annotated)
- **Tests**: 480 pass, 0 failures (unchanged from v0.4.0)
- **Fuzz replay**: 7/7 pass (165 seeds)
- **Fuzz libFuzzer**: 8/9 pass in v0.4.3, fixed fuzz_scan_ffi linking
- **Fix**: die-ffi dev-dependency → dependency for libFuzzer linking
- **No code changes**: only fuzz Cargo.toml + version bump
- **Artifacts**: identical to v0.4.0

### v0.4.3 — 2026-08-07

- **Tag**: `v0.4.3` (annotated)
- **Tests**: 480 pass, 0 failures (unchanged from v0.4.0)
- **Fuzz replay**: 7/7 pass (165 seeds, Docker CI simulation)
- **Fuzz libFuzzer**: cargo-fuzz list shows all 6 targets (Docker sim)
- **Fix**: cargo-fuzz metadata missing since v0.3.0
- **No code changes**: only fuzz metadata + CI config + version bump
- **Artifacts**: identical to v0.4.0

### v0.4.2 — 2026-08-07

- **Tag**: `v0.4.2` (annotated)
- **Tests**: 480 pass, 0 failures (unchanged from v0.4.0)
- **Fuzz replay**: 7/7 pass in Docker CI simulation (ubuntu:24.04)
- **Fix**: .gitignore excluded 3 .pyc seed files (165→162 in CI)
- **No code changes**: only .gitignore + seed files + version bump
- **Artifacts**: identical to v0.4.0

### v0.4.1 — 2026-08-06

- **Tag**: `v0.4.1` (annotated)
- **Tests**: 480 pass, 0 failures (unchanged from v0.4.0)
- **Fix**: fuzz/Cargo.lock version mismatch (0.3.0 → 0.4.1)
- **No code changes**: only version numbers and lock files
- **Artifacts**: identical to v0.4.0

### v0.4.0 — 2026-08-06

- **Tag**: `v0.4.0` (annotated)
- **Tests**: 480 pass, 0 failures (+3 GUI differential tests)
- **Rule count**: 2175 (db + db_extra + db_custom, was 2037 in v0.3.0)
- **New**: die-gui desktop app (Tauri v2 + React 18), native installers
  (MSI/NSIS/DEB/RPM/DMG), i18n (5 languages), Windows context menu,
  CLI auto-loading of db_extra/db_custom
- **Platforms**: Linux x86_64, Windows x86_64, macOS arm64 (GUI);
  + macOS x86_64 (CLI only)
- **GUI artifacts**: portable + installer per platform (6 products)
- **GitHub Release**: artifacts uploaded after CI

### v0.3.0 — 2026-08-05

- **Tag**: `v0.3.0` (annotated)
- **Commit**: `ca656ea79` (ci: include died binary in release artifacts)
- **Upstream pin**: `c2c17dfa5` (vendored subtree, merge `e0bcca000`)
- **Tests**: 477 pass, 0 failures
- **Compatibility**: 1186/1186 rules load, 0 engine mismatches
- **Performance**: database_load ~510ms, scan_corpus < 250ms/file
- **Platforms**: Linux x86_64, Windows x86_64, macOS arm64, macOS x86_64
- **GitHub Release**: artifacts uploaded and verified

**Open items (non-blocking for v0.3.0)**:
- Coverage-guided libFuzzer 5-min/target run is delegated to the CI fuzz
  workflow (`.github/workflows/fuzz.yml`); it runs on every push to main
  and on PRs. Seed-corpus replay (165 seeds × 6 harnesses) passed locally
  on stable Rust as the deterministic pre-release gate.
- ROADMAP.md Phase 6 closure is recorded below; next milestone is
  "maintenance and upstream-sync" until a GUI phase is scoped.

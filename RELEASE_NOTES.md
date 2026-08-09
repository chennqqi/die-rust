# Release Notes

## diec-rust v0.7.0

Phase 11 + Phase 12 GUI deep alignment release — 43 items achieving
full feature parity with upstream DIE-engine Qt GUI.

### Phase 11: GUI Deep Alignment — Complete Header Parsing & Missing Modules (8 batches)

- **11.1 FileInfo complete header parsing (P0)**: HeaderField tree structure +
  PE/ELF/Mach-O complete header parsing (pelite + goblin); FileHeaderTree
  recursive tree component + FileInfoPanel sub-tabs
- **11.2 File format detection extension (P0)**: Integrated diec-formats probe
  table (20+ format detection); hand-written magic bytes as fallback
  (PE32/PE32+ subtype distinction)
- **11.3 PE dedicated view (P1)**: pe_viewer.rs with imports/exports/resources/
  overlay/.NET/manifest/version info/TLS/Rich Header; PeViewPanel.tsx with
  9 sub-tabs
- **11.4 String search & extractor (P1)**: string_extractor.rs with ASCII/UTF-16LE
  extraction + filter search; StringExtractor.tsx with real-time search +
  encoding filter
- **11.5 Archive format extension (P1)**: list_archive extended for ZIP/TAR/
  GZIP+TAR (tar + flate2 dependencies)
- **11.6 Visualization & section view (P2)**: SectionVisualizer.tsx with
  color-coded section layout + entropy coloring + overlay markers
- **11.7 Settings modal & shortcut config (P2)**: SettingsModal.tsx with
  5-tab modal (View/Scan/Database/Engine/Shortcuts); 8 configurable shortcuts
- **11.8 VirusTotal integration & MIME type (P2)**: FileInfo mime_type field +
  detect_mime_type function; OnlineTools refactored with SHA256 + VirusTotal
  jump (matching upstream Qt behavior)

### Phase 12: GUI Gap v3 — 35 Remaining Items Complete Alignment

- **Batch A: PE missing sub-views (5)**: IMAGE_NT_HEADERS overview,
  RESOURCES_STRINGTABLE, .NET_METADATA_STREAM, .NET_METADATA_TABLE,
  PE TOOLS (DosStub/Overlay dump/remove/add with .bak backup)
- **Batch B: Mach-O missing sub-views (12)**: weak_libraries, id_library,
  FVMLIB, IDFVMLIB, function_starts (ULEB128 decode), data_in_code,
  code_signature (SuperBlob), SuperBlob, unix_thread, dyld_chained_fixups,
  dyld_exports_trie (trie traversal), STRINGTABLE
- **Batch C: ELF STRINGTABLE (1)**: SHT_STRTAB section string table parsing
- **Batch D: String search enhancements (8)**: MapMode (file/virtual/physical),
  FileType (auto/pe/elf/macho/dex/raw), right-click menu (Follow in Hex/Disasm/
  Demangle/Edit String), Save results (CSV/JSON), default min length 4→5
- **Batch E: Visualization enhancements (5)**: ZEROS_GRADIENT, TEXT_GRADIENT
  methods, highlight feature, zoom slider (1-10px), save image (PNG)
- **Batch F: Extractor enhancements (3)**: HEURISTIC mode (21 magic signatures),
  deep scan toggle, analyze mode (format detection + entropy calculation)
- **Batch G: Scan log (1)**: ScanResultDto scan_log field + frontend collapsible
  display

### Testing & Verification

- **Tests**: 614 pass, 0 failures (up from 597 in v0.6.1, +17 new tests)
- **cargo fmt --check**: PASS
- **cargo clippy --workspace --all-targets --all-features -- -D warnings**: PASS
- **npx tsc --noEmit**: PASS (zero TypeScript errors)
- **New unit tests**: visualization (ZerosGradient/TextGradient), macho
  (read_uleb128/data_in_code_kind_name/code_slot_type_name/count_exports_in_trie/
  parse_string_table), pe (pe_subsystem_name/pe_machine_name/parse_nt_headers),
  elf (string_table_entry_serialization/extraction_logic), string_extractor
  (map_mode_default/file_type_default/params_default_min_length/
  extract_with_map_mode_file)

### Documentation Updates

- **ROADMAP.md**: Phase 11 and Phase 12 marked as DONE with completion summaries
- **docs/research/gui-gap-analysis-v2.md**: Phase 11 gap analysis
- **docs/research/gui-gap-analysis-v3.md**: Phase 12 gap analysis (35 items)
- **docs/design/phase11-gui-parity.md**: Phase 11 design document
- **doc/requirements.md**: Requirements summary appended
- **doc/requirements-analysis.md**: Analysis process appended

## diec-rust v0.6.0

Phase 10 known issues fix and documentation cleanup release —
3 items fixing known limitations and cleaning up documentation.

### Phase 10 Known Issues Fix (3 items)

- **Documentation cleanup (getDisasmString)**: Removed getDisasmString from
  "Known Limitations" — Capstone 0.14.0 integration completed in Phase 6,
  fully functional with thread-local caching and VA→file offset conversion
- **Documentation cleanup (rule version differences)**: Moved rule version
  differences from "Known Limitations" to new "Known Differences (Non-Defects)"
  section; 4 corpus samples detect more due to newer vendored rules (NOT engine bugs)
- **Result deduplication**: ADR 0027 accepted; `--alltypes` mode now deduplicates
  results by default using key `(type_name, name, version, options, offset, size)`;
  `--no-dedup` flag provides escape hatch for upstream-exact differential testing;
  propagated through all 6 layers (ScanFlags → scanner → CLI → FFI → server → GUI);
  5 new dedup tests added (511 total tests)

### GUI Enhancements

- **no_dedup checkbox**: Added to Advanced Toolbar with i18n support (en/zh-CN)
- **ScanFlagsDto**: Added no_dedup field and From impl mapping
- **Settings**: Added no_dedup field to AppSettings with default false

### Documentation Updates

- **ROADMAP.md**: Phase 10 marked as DONE with completion summary
- **AGENTS.md**: Updated current phase description to include Phase 10
- **README.md**: Cleaned up Known Limitations, added Known Differences section
- **docs/design/decisions/README.md**: Added ADR 0027 reference

## diec-rust v0.5.0

Phase 9 GUI upstream alignment release — 20 items aligning die-gui with
the upstream DIE-engine Qt GUI, based on `docs/research/gui-upstream-diff.md`.

### Phase 9.1 P1 Core Fixes (7 items)

- **ScanDetection optional fields**: Added id, parentId, file_part, offset,
  size, is_heuristic, is_a_heuristic, original_name across the full stack
  (scanner → runtime → backend → JSON/XML → server → GUI → frontend)
- **Database selection wiring**: scan_file accepts database_paths parameter;
  new list_database_paths IPC command; frontend Databases dropdown is live
- **File type override wiring**: scan_file accepts file_type override;
  frontend Type dropdown is live
- **Options direct display**: Detection tree shows options string directly
  instead of just a count
- **Heuristic markers**: Detection names show `(Heur)` / `(A-Heur)` markers
- **Nested result tree**: Built from id/parentId, showing file_part/offset/size
- **Hex viewer rewrite**: Virtual scrolling, hex/ASCII pattern search,
  jump-to-offset, copy. New search_bytes + read_hex_range functions (+9 tests)
- **Disassembler fix**: Removed break-on-Ret, multi-arch support (x86/x64 via
  iced-x86 instr_info, ARM/ARM64 via yaxpeax), arch parameter, default
  max_bytes raised to 4096, label/comment/jump_target fields (+8 tests)

### Phase 9.2 P2 Completeness Enhancements (7 items)

- **Hex data inspector + Follow in Disasm**: Click hex line → 32-byte inspector
  panel (uint8/16/32/64, int8/16/32/64, float32/64, ASCII); "Follow in Disasm"
  button jumps to disassembly tab at selected offset
- **Symbol table virtual scrolling**: Removed .slice(0, 500) limit; scrollable
  container with sticky header, shows total symbol count
- **Structured diagnostics**: New Diagnostic struct (file/line/message/kind);
  JSON/XML output includes structured_diagnostics; frontend table display
- **Profiling data**: New SignatureProfile struct (file/elapsed_ms); per-rule
  timing via Instant::now(); JSON/XML/frontend display
- **Disasm cross-references + Analyze All**: Jump/call comments clickable to
  follow target; xref summary shows counts for labeled addresses; "Analyze All"
  button disassembles 64KB range
- **PE imports**: parse_pe_sections now extracts imports via goblin pe.imports;
  import symbols shown as "DLL.function" with kind="import"
- **Mach-O FAT support**: detect_format recognizes 0xCAFEBABE / 0xBEBAFECA
  magic; returns "Mach-O FAT" for universal binaries (+7 format detection tests)

### Phase 9.3 P3 Alignment Extensions (6 items)

- **Scan progress events**: scan_file/scan_bytes_cmd emit "scan_progress" Tauri
  events (loading_database → scanning → complete); frontend shows phase-specific
  progress text
- **Hex element mode**: Dropdown to switch byte grouping (Byte/Word/DWord/QWord);
  formatHexByMode re-groups bytes in little-endian multi-byte elements
- **Disasm Follow in Hex**: "Follow in Hex" button in Disassembler; HexViewer
  accepts initialOffset and scrolls to line; bidirectional Hex ↔ Disasm navigation
- **CRC32 hash**: Added crc32fast dependency; FileHashes includes crc32 field
  (8-digit uppercase hex)
- **Entropy block size configurable**: EntropyView dropdown (64B–4KB); re-fetches
  entropy graph on block size change
- **Multi-language**: Already covered by Phase 8 i18n (en/zh-CN/ru/de/fr)

### Stats

| Metric | v0.4.7 | v0.5.0 |
| --- | --- | --- |
| Tests | 480 | 506 (+26) |
| Phase 9 items | 0 | 20/20 |
| New dependencies | — | crc32fast 1.5.0 |

### Compatibility

- Rule loading: 1186/1186 = 100% (unchanged)
- GUI-CLI differential: 2/2 pass, 0 mismatches (unchanged)
- cargo fmt/clippy: clean
- Frontend: tsc --noEmit + vite build pass

## diec-rust v0.4.7

Patch release fixing release workflow GUI build jobs.

### Fixes (since v0.4.6)

- **tauri-cli install**: Added `cargo install tauri-cli` step to
  build-gui job. Without it, `cargo tauri build` failed with
  "no such command: tauri".
- **cp empty dirs**: Fixed `cp -r ... /*` failing when data
  directories exist but are empty (e.g. db_custom). Changed to
  `cp -r .../.` with `2>/dev/null || true`.

### CI Status

| Workflow | Jobs | Status |
| --- | --- | --- |
| ci | 12 | ✅ all pass (#36) |
| fuzz | 9 | ✅ all pass (#15) |
| release | 8 | ✅ (expected, CLI 4/4 pass in #19) |

### No Functional Code Changes

Only release.yml CI config + version bump.
All features identical to v0.4.0.

## diec-rust v0.4.6

Patch release with comprehensive CI fixes. All three workflows
(ci, fuzz, release) now pass on all platforms.

### CI Fixes (since v0.4.0)

- **fuzz cargo-fuzz metadata**: Added `[package.metadata] cargo-fuzz = true`
  to fuzz/Cargo.toml. Without it, cargo-fuzz searched for
  `fuzz/fuzz/Cargo.toml` and failed.
- **fuzz_scan_ffi linker**: Added `const _: ()` block to force-link
  diec-ffi's `#[no_mangle]` symbols, preventing dead code elimination.
- **fuzz LeakSanitizer**: Set `ASAN_OPTIONS=detect_leaks=0` for libFuzzer
  jobs (OnceLock cached resources are by design, not leaks).
- **ci Linux GTK deps**: Added `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
  `libglib2.0-dev` etc. to default and msrv jobs.
- **ci data dirs**: Added "Copy data directories" step before die-gui
  build (Tauri checks resource paths exist).
- **ci is_context_menu_installed**: Fixed `cfg!(windows) &&` runtime
  check to compile-time `#[cfg(windows)]` / `#[cfg(not(windows))]`.
- **ci MSRV exclude die-gui**: MSRV 1.88 job excludes die-gui (Tauri
  deps wasmtime 43, yara-x 1.19 require rustc 1.91+). Core crates
  MSRV remains 1.88 per ADR 0011.
- **release CLI job**: Excluded die-gui from `build` job (GUI built
  separately in `build-gui` job with GTK deps).

### CI Status

| Workflow | Jobs | Status |
| --- | --- | --- |
| ci | 12 | ✅ all pass |
| fuzz | 9 | ✅ all pass |
| release | 8 | ✅ (expected) |

### No Functional Code Changes

Only CI config + fuzz linker fix + version bump.
All features identical to v0.4.0.

## diec-rust v0.4.5

Patch release fixing the last libFuzzer CI job (fuzz_scan_ffi)
that failed due to dead code elimination removing diec-ffi's
#[no_mangle] symbols from the rlib.

### Fixes

- **Force-link diec-ffi symbols**: fuzz_scan_ffi.rs uses `extern "C"`
  to declare diec-ffi's C ABI functions, but the Rust linker removes
  unreferenced `#[no_mangle]` symbols during dead code elimination.
  Added a `const _: ()` block that references `diec_ffi::scan::`
  functions to force the linker to retain them, allowing the
  `extern "C"` declarations to resolve at link time.

### CI Status (v0.4.4 → v0.4.5)

| Job | v0.4.4 | v0.4.5 (expected) |
| --- | --- | --- |
| seed replay (all 3 platforms) | ✅ | ✅ |
| libFuzzer (5 other targets) | ✅ | ✅ |
| libFuzzer (fuzz_scan_ffi) | ❌ undefined symbol | ✅ (fixed) |

### Verification (Docker CI simulation)

- ubuntu:24.04 + nightly Rust + cargo-fuzz v0.13.2
- `cargo +nightly fuzz build fuzz_scan_ffi`: compiles successfully
- Seed replay: 7/7 pass (165 seeds)

### No Functional Code Changes

Only fuzz_scan_ffi.rs linker fix + version bump.
All features identical to v0.4.0.

## diec-rust v0.4.4

Patch release fixing the last libFuzzer CI job (fuzz_scan_ffi)
that failed due to diec-ffi not being linked as a regular dependency.

### Fixes

- **diec-ffi linking**: Moved `diec-ffi` from `[dev-dependencies]` to
  `[dependencies]` in fuzz/Cargo.toml. The `fuzz_scan_ffi` target uses
  `extern "C"` declarations referencing diec-ffi symbols, but
  dev-dependencies are not linked into binary targets during
  cargo-fuzz builds, causing "undefined symbol" linker errors.

### CI Status (v0.4.3 → v0.4.4)

| Job | v0.4.3 | v0.4.4 (expected) |
| --- | --- | --- |
| seed replay (ubuntu) | ✅ | ✅ |
| seed replay (windows) | ✅ | ✅ |
| seed replay (macos) | ✅ | ✅ |
| libFuzzer (fuzz_byte_source) | ✅ | ✅ |
| libFuzzer (fuzz_byte_view_subview) | ✅ | ✅ |
| libFuzzer (fuzz_format_probe) | ✅ | ✅ |
| libFuzzer (fuzz_output_render) | ✅ | ✅ |
| libFuzzer (fuzz_scan_engine) | ✅ | ✅ |
| libFuzzer (fuzz_scan_ffi) | ❌ undefined symbol | ✅ (fixed) |

### No Functional Code Changes

Only fuzz/Cargo.toml dependency placement + version bump.
All features identical to v0.4.0.

## diec-rust v0.4.3

Patch release fixing libFuzzer CI jobs that had been failing since
v0.3.0 due to missing cargo-fuzz metadata.

### Fixes

- **cargo-fuzz metadata**: Added `[package.metadata] cargo-fuzz = true`
  to fuzz/Cargo.toml. Without this, cargo-fuzz searched for
  `fuzz/fuzz/Cargo.toml` (double nesting) and failed with
  "No such file or directory".
- **fuzz.yml path fix**: Run cargo-fuzz from repo root instead of
  `cd fuzz` first, since cargo-fuzz auto-discovers the fuzz/ directory
  via the metadata marker.
- **Independent workspace**: Added `[workspace] members = ["."]` to
  fuzz/Cargo.toml for proper independent workspace declaration.

### Verification (Docker CI simulation)

- ubuntu:24.04 + nightly Rust + cargo-fuzz v0.13.2
- `cargo fuzz list` correctly shows all 6 targets:
  fuzz_byte_source, fuzz_byte_view_subview, fuzz_format_probe,
  fuzz_output_render, fuzz_scan_engine, fuzz_scan_ffi
- Seed replay: 7/7 pass (165 seeds)

### No Functional Code Changes

Only fuzz/Cargo.toml metadata + fuzz.yml CI config + version bump.
All features identical to v0.4.0.

## diec-rust v0.4.2

Patch release fixing fuzz CI failure caused by .gitignore excluding
.pyc seed files from the repository.

### Fixes

- **Track .pyc fuzz seed files**: The `.gitignore` rule `*.py[cod]`
  was matching `fuzz/corpus/*/minimal.pyc` seed files, causing them
  to be excluded from git. CI fresh checkout got only 162 seeds
  instead of 165, failing `replay_seed_count_matches_release`.
  Added negation rule `!fuzz/corpus/**/*.pyc` and committed the 3
  missing .pyc files (format_probe, scan_engine, scan_ffi).

### Verification (Docker CI simulation)

- ubuntu:24.04 + stable Rust + clean git archive checkout
- Seed count: 165 (was 162 in v0.4.0/v0.4.1 CI)
- `cargo test --no-default-features --features replay`: 7/7 pass
- `replay_seed_count_matches_release`: ok

### No Functional Code Changes

Only .gitignore fix + 3 seed files + version bump.
All features identical to v0.4.0.

## diec-rust v0.4.1

Patch release fixing fuzz/Cargo.lock version mismatch that caused
CI fuzz workflow to fail on v0.4.0 tag.

### Fixes

- **fuzz/Cargo.lock updated to 0.4.1**: The fuzz workspace Cargo.lock
  was not updated when the workspace version was bumped, causing all
  9 fuzz CI jobs (3 replay + 6 libFuzzer) to fail with exit code 101.
  All 6 diec-* entries updated to match the workspace version.

### No Code Changes

No functional code changes — only version numbers and lock files.
All features and artifacts are identical to v0.4.0.

## diec-rust v0.4.0

Minor release adding the **die-gui** desktop application (Tauri v2 + React 18)
with full feature parity to the upstream DIE GUI, plus native installer
packages and CLI auto-loading of extra rule databases.

### New Features

- **die-gui desktop application** (ADR 0018):
  - Tauri v2 + React 18 + TypeScript GUI with dark/light theme
  - Full feature parity to upstream `die` GUI:
    - 7A core: file/dir scan, drag-drop, stop, settings persistence,
      recent files, fullscreen, keyboard shortcuts
    - 7B advanced: hex viewer, disassembler (Intel/GAS/NASM),
      C++/Rust demangle, signature browser with source view/edit/run/debug
    - 7C extensions: YARA scanner, PEID scanner, online lookup,
      archive viewer, data converter, file info panel (hashes/entropy/
      sections/symbols), memory map viewer
  - Internationalization (i18n): English, Chinese (Simplified), Russian,
    German, French — all UI strings externalized via react-i18next
  - Windows Explorer context menu integration: one-click add/remove
    "Scan with DIE" from Settings panel (HKCU registry, no admin needed)
  - Single-instance support: launching from context menu focuses existing
    window and auto-loads the right-clicked file

- **Native installer packages** (MSI/NSIS/DEB/RPM/DMG):
  - Windows: MSI (WiX, perMachine, ~14MB) + NSIS (~9.3MB)
  - Linux: DEB + RPM + AppImage
  - macOS: DMG + .app bundle
  - All installers bundle the complete rule database (7 data directories)
  - Portable archives (zip/tar.gz) also provided for each platform

- **CLI auto-loading of db_extra/db_custom**:
  - CLI now auto-discovers `db_extra/` and `db_custom/` alongside the
    main `db/` directory, matching upstream DIE-engine behavior
  - Rule count: 2037 → 2175 (+138 from db_extra)
  - Users can still override with `--extradb`/`--customdb`

- **Complete data directory bundling**:
  - All 7 upstream data directories packaged: `db/`, `db_extra/`,
    `db_custom/`, `dbs_min/`, `dbs_special/`, `peid_rules/`, `yara_rules/`
  - GUI auto-loads db + db_extra + db_custom for scanning
  - PEID scanner auto-loads `peid_rules/PE/userdb.txt`
  - YARA scanner provides dropdown to load built-in `yara_rules/*.yar`

- **GUI vs CLI differential tests**:
  - `gui_cli_differential.rs`: 2 tests verifying GUI `scan_once` matches
    CLI `scan_bytes` on 32 corpus files + flag combination consistency

### Improvements

- Test count: 480 tests (up from 477, +3 GUI differential tests)
- Rule count: 2175 rules loaded (up from 2037, includes db_extra)
- New crate: `die-gui` (Tauri v2 GUI adapter, no core-layer dependency)
- Tri-platform GUI CI: Linux (webkit2gtk-4.1), macOS (arm64), Windows
- ADR 0018 (Tauri v2 GUI framework), ADR 0019 (auto-update deferred)

### Artifacts

**CLI** (4 platforms, unchanged from v0.3.0):
- `diec` / `diec.exe` — CLI binary
- `died` / `died.exe` — HTTP/JSON scan service
- `libdiec_ffi.*` — static and dynamic libraries
- `include/diec.h` — C header
- `db/` + `db_extra/` + `db_custom/` — rule databases
- `bindings/python/diec.py` + `bindings/go/diec/diec.go`

**GUI** (3 platforms, new in v0.4.0):
- Portable: `die-gui-<version>-<platform>-portable.zip/.tar.gz`
- Windows installers: MSI + NSIS exe
- Linux installers: DEB + RPM + AppImage
- macOS installers: DMG + .app bundle

### Documentation

- [docs/design/phase8-gui.md](docs/design/phase8-gui.md) — Phase 8 GUI design
- ADR 0018 (Tauri v2 framework selection) — Accepted
- ADR 0019 (auto-update deferred) — Accepted
- NOTICES.md updated with die-gui dependencies (tauri, iced-x86,
  cpp_demangle, yara-x, winreg, react, etc.)

### Testing

480 tests, 6 fuzz targets, 0 failures. Tri-platform GUI CI.

### License

MIT — see [LICENSE](LICENSE) and [NOTICES.md](NOTICES.md)

## diec-rust v0.3.0

Minor release adding the died (die daemon) HTTP/JSON scan service and
runtime reuse optimization for batch scanning.

### New Features

- **died (die daemon) HTTP/JSON service** (ADR 0017):
  - `GET /health` — service status and version info
  - `POST /scan/path` — scan local file by path
  - `POST /scan/bytes` — scan uploaded file content
  - Security: `--allow-root` path restriction, `--max-file-size`,
    `--max-request-size`, `--scan-timeout`
  - Windows service support: `died install` / `died uninstall` via `sc.exe`
  - Linux systemd unit template generation
  - Packaging: DEB (cargo-deb), RPM (spec), MSI (cargo-wix)
  - API documentation with curl/PowerShell/Python/Go client examples
    ([docs/died-api.md](docs/died-api.md))

- **Scanner runtime reuse** (ADR 0016):
  - `diec_engine::Scanner` — stateful scanner that reuses QuickJS
    runtimes across files of the same file type
  - `RquickjsRuntime::reinit()` — clears results and re-runs type init
    scripts to update host aliases for a new file
  - Differential verification: reuse vs no-reuse 0 mismatches
  - BudgetExceeded error evicts the runtime for fresh creation

- **Database::version()** (ADR 0017):
  - Loads commit/synced_at from `rule-source-manifest.json`
  - Fallback to `DatabaseVersion::unknown(rule_count)` when manifest
    is not available

### Improvements

- Rule count: 2037 rules loaded (up from 1186 — includes db_extra)
- Test count: 477 tests (up from 459)
- New crate: `diec-server` (thin adapter over `diec-engine`, no core
  layer dependency on CLI or FFI)

### Artifacts

Each platform archive now also includes:
- `bin/died` — HTTP/JSON scan service daemon
- `bin/died.exe` (Windows) — with Windows service support

### Documentation

- [docs/died-api.md](docs/died-api.md) — full API reference with client
  examples in curl, PowerShell, Python, and Go
- [crates/diec-server/packaging/README.md](crates/diec-server/packaging/README.md)
  — DEB/RPM/MSI packaging guide
- ADR 0016 (runtime reuse) and ADR 0017 (scan service layer) — Accepted

### Testing

477 tests, 6 fuzz targets, 0 failures.

### License

MIT — see [LICENSE](LICENSE) and [NOTICES.md](NOTICES.md)

## diec-rust v0.2.2

Patch release that fixes the v0.2.1 release build failure.

### Bug Fixes

- **Cargo.lock sync**: The v0.2.1 release commit bumped
  `workspace.package.version` in `Cargo.toml` from 0.2.0 to 0.2.1 but
  forgot to regenerate and commit `Cargo.lock`. Because the release
  workflow builds with `--locked`, every build job failed with
  "cannot update the lock file because --locked was passed". The lock
  file is now regenerated and committed alongside the version bump.

### No Code Changes

No runtime, CLI, FFI, or rule changes versus v0.2.1 — this release
exists solely to produce working artifacts that v0.2.1 could not.

## diec-rust v0.2.0

First public release of diec-rust, a Rust reimplementation of Detect It Easy.

### Features

- **Format detection**: 20 format probes (PE, ELF, Mach-O, DEX, Java
  class, ZIP, tar, PDF, PNG, JPEG, BMP, WAV, ISO 9660, CFBF, and more)
- **Rule compatibility**: 1186/1186 upstream rules loaded (100%)
- **Native binary parsing**: pelite (PE) and goblin (ELF/Mach-O) replace
  hand-written JavaScript parsing for imports, exports, resources,
  manifest, version info, .NET CLR detection, and Authenticode
- **CLI**: full-featured with JSON/XML/CSV/TSV output, recursive scan,
  entropy analysis, profiling, custom databases
- **C ABI**: stable versioned C ABI with opaque handles
- **Language bindings**: Go/cgo and Python ctypes
- **Cross-platform**: Linux, macOS (arm64 + x86_64), Windows

### Performance

- Database load: ~510ms (parallel I/O)
- Format probe: sub-microsecond
- PE32 scan: ~89ms (native pelite + batch cache)
- ELF64 scan: ~15ms (native goblin)
- Mach-O 64 scan: ~14ms (native goblin)

### Artifacts

Each platform archive contains:
- `bin/diec` — CLI binary
- `lib/libdiec_ffi.*` — static and dynamic libraries
- `include/diec.h` — C header
- `db/` — pinned rule database (MIT licensed)
- `bindings/python/diec.py` — Python binding
- `bindings/go/diec/diec.go` — Go binding

### Rule Database

Rules are bundled from the upstream Detect-It-Easy repository at a
fixed commit (c2c17dfa). To use a different or updated database:

```sh
diec --customdb /path/to/rules/ file.exe
```

Or set the `DIEC_DB_PATH` environment variable.

### Compatibility

- Rule loading: 1186/1186 (100%)
- Corpus differential: 31 baseline + 20 edge samples, 0 mismatches
- Known differences: 4 rule version diffs (archive:Zip vs format:ZIP),
  all documented in [COMPATIBILITY.md](COMPATIBILITY.md)

### Testing

459 tests, 6 fuzz targets, 0 failures.

### License

MIT — see [LICENSE](LICENSE) and [NOTICES.md](NOTICES.md)

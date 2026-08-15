# Compatibility Report

This document tracks compatibility between diec-rust and the upstream
DIE-engine project. It is updated with each release.

Last updated: 2026-08-15

## Baseline

- **Upstream**: https://github.com/horsicq/DIE-engine
- **Fixed commit**: `c2c17dfa5` (recorded at the squashed subtree merge
  `e0bcca000` on 2026-07-25; `upstream/Detect-It-Easy` is a vendored
  subtree, not a git submodule — there is no `.gitmodules` entry)
- **Rule database**: loaded verbatim from upstream, no modifications

## Rule Loading Compatibility

| Metric | Result |
|--------|--------|
| Total rules in database | 1186 |
| Successfully loaded | 1186 |
| Failed to load | 0 |
| Load success rate | 100.0% |

### Known Load Failures

All 1186 upstream rules load and execute successfully.

Previously, 2 rules failed to load:
1. `Binary/format_bin.Nintendo-certified-file.1.sg` — upstream rule bug
   (`const tp` redeclares `var tp` in same scope). Fixed by preprocessing
   `const` → `var` in `eval_script` to match Qt Script behavior (see
   `docs/research/upstream-bug-const-redeclaration-nintendo-certified-file.md`).
2. PE rule requiring PE-specific host API — fixed by implementing full PE
   host API (imports, exports, resources, manifest, version info, .NET,
   Authenticode) via native `pelite` parsing.

## Format Detection Compatibility

### Corpus Differential Test

| Category | Samples | Matched | Mismatched | Notes |
|----------|---------|---------|------------|-------|
| Executable (ELF) | 4 | 4 | 0 | 2 minimal + 2 with DT_NEEDED deps |
| Executable (PE) | 5 | 5 | 0 | 2 minimal + with-tables + resources + .NET |
| Executable (Mach-O) | 4 | 4 | 0 | FAT binary detected as lipo; +1 with LC_LOAD_DYLIB |
| Bytecode | 3 | 3 | 0 | Java Class, DEX, PYC (PYC is rule version diff) |
| Archive | 7 | 4 | 3 | APK/JAR/ZIP: archive:Zip (rule version diff) |
| Document | 2 | 2 | 0 | PDF, CFBF (Microsoft Office) |
| Image | 3 | 3 | 0 | PNG, JPEG, BMP |
| Audio | 1 | 1 | 0 | WAV |
| Other | 5 | 5 | 0 | empty, text, RAR, GZIP, manifest |
| **Total** | **31** | **27** | **4** | All mismatches are rule version diffs |

### Mismatch Details (Rule Version Differences)

All 4 mismatches are due to differences between the submodule rule
database (newer version) and the upstream DIE 3.21 bundled rules.
These are NOT engine bugs:

| File | Our detection | Upstream 3.21 | Cause |
|------|---------------|---------------|-------|
| minimal.apk | archive:Zip:2.0 | (none) | New rule detects archive |
| minimal.jar | archive:Zip:2.0 | (none) | New rule detects archive |
| payload.zip | archive:Zip:2.0 | (none) | New rule detects archive |
| minimal.pyc | Python bytecode | (none) | New rule detects PYC |

### Edge-Case Robustness

| Category | Samples | No crash | No spurious | No hang |
|----------|---------|----------|-------------|---------|
| Truncated headers | 10 | 10 | N/A | 10 |
| Malformed structures | 2 | 2 | 2 | 2 |
| Oversized fields | 1 | 1 | 1 | 1 |
| Empty containers | 2 | 2 | N/A | 2 |
| No-match inputs | 5 | 5 | 5 | 5 |
| **Total** | **20** | **20** | **7** | **20** |

## CLI Compatibility

| Feature | Status | Notes |
|---------|--------|-------|
| Basic scan | ✅ | |
| --database / --db | ✅ | |
| --recursive / -r | ✅ | |
| --deepscan / -d | ✅ | |
| --heuristicscan | ✅ | |
| --verbose | ✅ | |
| --aggressivescan / -a | ✅ | |
| --alltypes | ✅ | |
| --hideunknown | ✅ | |
| --output | ✅ | accepts: text, json, xml, csv, tsv, plaintext |
| --json / --xml / --csv / --tsv / --plaintext | ✅ | upstream-style independent format switches |
| --format | ✅ | |
| --profiling | ✅ | |
| --messages | ✅ | |
| --entropy | ✅ | |
| --info | ✅ | |
| --extradatabase / --extradb | ✅ | |
| --customdatabase / --customdb | ✅ | |
| --showdatabase | ✅ | |
| --showmethods / --showstructs | ✅ | |
| --version / -v / -V | ✅ | |
| --help / -h | ✅ | |

## C ABI Compatibility

| Feature | Status | Notes |
|---------|--------|-------|
| ABI version negotiation | ✅ | v1.0 |
| Opaque handles | ✅ | 6 handle types |
| Database builder | ✅ | |
| One-shot scan | ✅ | bytes + path |
| Reusable scanner | ✅ | bytes + path |
| Cancel token | ✅ | |
| Error handle | ✅ | |
| Panic containment | ✅ | catch_unwind |
| Double-free safety | ✅ | all handle types |
| Go/cgo binding | ✅ | 5 tests |
| Python ctypes binding | ✅ | 9 tests |
| C smoke test | ✅ | |

## Host API Compatibility

| Feature | Status | Notes |
|---------|--------|-------|
| Binary (read, compare, find) | ✅ | Full implementation |
| PE (header, sections, imports) | ✅ | Native pelite-backed |
| PE.getDisasmString | ✅ | Capstone-based, Intel syntax |
| PE.getDisasmNextAddress | ✅ | Capstone-based |
| PE Rich signature | ✅ | |
| PE debug data | ✅ | |
| PE.isSigned | ✅ | Native pelite security directory check |
| PE validation (is*Correct) | ✅ | 8 methods for heuristic scan |
| PE overlay | ✅ | getOverlayOffset/Size/compareOverlay |
| PE.isNet | ✅ | Native pelite CLR header detection |
| PE.getManifest | ✅ | Native pelite resource directory |
| PE version info | ✅ | getFileVersion/getProductVersion/getVersionStringInfo (VS_FIXEDFILEINFO + StringFileInfo) |
| PE resources | ✅ | getNumberOfResources/isResourceNamePresent (native pelite) |
| ELF | ✅ | Native goblin-backed |
| ELF overlay | ✅ | getOverlayOffset/Size |
| ELF.getImageBase | ✅ | Lowest PT_LOAD p_vaddr |
| ELF table offsets | ✅ | String/Symbol/Relocation table |
| Mach-O | ✅ | Native goblin-backed |
| Mach-O overlay | ✅ | getOverlayOffset/Size |
| Mach-O.getImageBase | ✅ | Lowest LC_SEGMENT vmaddr |
| PDF (version, header comment) | ✅ | |
| JPEG (version from JFIF) | ✅ | |
| DEX (version from header) | ✅ | |
| CFBF (version from header) | ✅ | major.minor format |
| Java Class (version from header) | ✅ | Java SE version mapping |
| Binary.isPlainText | ✅ | |
| Archive (isVerbose, format) | ✅ | `isVerbose()` returns false, matching upstream DIE 3.21 (decision recorded in ROADMAP.md "后续改进项") |

## Known Differences

| ID | Description | ADR | Impact |
|----|-------------|-----|--------|
| D001 | Rule version differences (submodule vs 3.21) | N/A | Detection name/version diffs |
| D002 | Format-specific rules exclude Binary rules | N/A | Eliminates duplicate detections |
| D003 | JavaClass no longer runs Binary rules | N/A | Host API now complete |

## Performance Baseline

| Benchmark | Time (release) | Notes |
|-----------|----------------|-------|
| scan_corpus/ELF64 | ~15ms | minimal ELF (native goblin) |
| scan_corpus/PE32 | ~89ms | minimal PE (native pelite + batch cache) |
| scan_corpus/Mach-O 64 | ~14ms | minimal Mach-O (native goblin) |
| scan_corpus/Zip | ~176ms | payload.zip |
| scan_corpus/tar | ~154ms | payload.tar |
| scan_corpus/PDF | ~12ms | minimal PDF |
| scan_corpus/PNG | ~13ms | pixel.png |
| scan_corpus/Java class | ~12ms | Minimal.class |
| scan_corpus/DEX | ~12ms | minimal DEX |
| scan_flags/default | ~187ms | payload.zip |
| scan_flags/heuristic | ~175ms | payload.zip |
| scan_flags/all_types | ~509ms | payload.zip |
| scan_flags/deep | ~170ms | payload.zip |
| database_load | ~510ms | full database |
| probe_corpus/ELF64 | ~345ns | format probe only |
| probe_corpus/Zip | ~950ns | format probe only |

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Unit tests | 251 | ✅ all pass |
| Integration tests | 182 | ✅ all pass (+14 Scanner/Database version/Server) |
| FFI tests | 35 | ✅ all pass |
| Edge corpus tests | 3 | ✅ all pass |
| GUI differential tests | 2 | ✅ all pass (v0.4.0) |
| Fuzz targets | 6 | ✅ compile |
| **Total** | **684** | ✅ 0 failures |

## Phase 13: CLI Parity & Nested Scanning (2026-08-15)

### `--struct` Mode (13.1-13.3)

The `--struct`/`-S` CLI option is now fully implemented, matching upstream
DIE-engine's structure inspection mode:

- **General methods**: Hash#MD5, Hash#SHA1, Hash#SHA256, Info, Entropy,
  Check format
- **Format-specific methods**: PE (6 methods), ELF (2), Mach-O (2), DEX (1)
- **Output formats**: text, JSON, XML, CSV, TSV
- **Mode priority**: `--struct` > `--entropy`/`--info` > normal scan

### Intra-file Recursive Scanning (13.4, ADR 0028)

The `-r`/`--recursivescan` flag now matches upstream semantics:

- **`-r`/`--recursivescan`**: Intra-file recursive scan (PE resources +
  overlay). Extracts PE resources and overlay, scans each as a sub-device.
- **`-R`/`--recursive-dir`**: Directory-level recursion (replaces old `-r`
  directory behavior). `--recursive` retained as alias for backward
  compatibility.
- **`--resources`**: Scan only PE resources.
- **`--overlays`**: Scan only PE overlay.
- **FFI flags**: `DIEC_SCAN_FLAG_RECURSIVE` (0x80),
  `DIEC_SCAN_FLAG_RESOURCES` (0x100), `DIEC_SCAN_FLAG_OVERLAYS` (0x200).

### Archive Member Extraction (13.5, ADR 0029/0030)

The `--archives` flag enables archive member extraction and recursive
scanning:

- **Supported formats**: ZIP, 7Z, RAR (CAB and ISO9660 deferred)
- **Safety bounds** (ADR 0030, stricter than upstream):
  - Single-member limit: 128 MiB
  - Total decompressed limit: 512 MiB
  - Compression ratio limit: 100:1
  - Member count: 20 (default), 100000 (aggressive)
- **RAR library**: `rars` 0.6.0 (MIT/Apache-2.0, pure Rust)
- **FFI flag**: `DIEC_SCAN_FLAG_ARCHIVES` (0x400)

### Known Differences from Upstream

1. **Archive safety bounds**: diec-rust enforces stricter limits than
   upstream (which has no size/ratio limits). Highly compressed archives
   (ratio > 100:1) or very large members (> 128 MiB) are skipped. This is
   an intentional safety improvement (ADR 0030).

2. **CAB and ISO9660**: Not yet implemented. Upstream supports all 5
   archive formats; diec-rust currently supports 3 (ZIP/7Z/RAR).

3. **`--recursive` backward compatibility**: `--recursive` is retained as
   an alias for `--recursive-dir` to avoid breaking existing scripts.

# Third-Party Notices

This file lists third-party software, licenses, and attribution used by
diec-rust. It is maintained manually and verified via `cargo license`.

## Upstream Project

- **DIE-engine** by horsicq: https://github.com/horsicq/DIE-engine
  - License: MIT
  - Used as: compatibility baseline, rule database source, submodule
  - Fixed commit SHA recorded in `upstream/Detect-It-Easy` submodule
  - Rules are loaded verbatim; no modifications

## Rust Dependencies

### Core Dependencies (runtime)

| Crate | License | Purpose |
|-------|---------|---------|
| rquickjs | MIT | JavaScript runtime for rule execution |
| rquickjs-core | MIT | QuickJS bindings core |
| rquickjs-sys | MIT | QuickJS FFI system bindings |
| pelite | MIT | Native PE binary parsing |
| pelite-macros | MIT | Procedural macros for pelite |
| goblin | MIT | Native ELF/Mach-O binary parsing |
| scroll | MIT | Byte-level parsing primitives for goblin |
| scroll_derive | MIT | Derive macros for scroll |
| capstone | MIT | Disassembly engine (x86/x64/ARM) |
| capstone-sys | MIT | FFI bindings for Capstone |
| serde | Apache-2.0 OR MIT | Serialization framework |
| serde_json | Apache-2.0 OR MIT | JSON serialization |
| sha2 | Apache-2.0 OR MIT | SHA-256 hashing |
| regex | Apache-2.0 OR MIT | Regular expressions |
| walkdir | MIT OR Unlicense | Directory traversal |
| memchr | MIT OR Unlicense | Fast byte search |
| aho-corasick | MIT OR Unlicense | Multi-pattern search |
| libc | Apache-2.0 OR MIT | C library bindings |
| slab | MIT | Slab allocator |
| plain | Apache-2.0 OR MIT | Plain old data traits |
| dataview | MIT | Byte view helpers for pelite |
| derive_pod | MIT | Plain old data derive for pelite |
| no-std-compat | MIT | no_std compatibility for pelite |
| log | Apache-2.0 OR MIT | Logging facade |

### GUI Dependencies (die-gui crate, v0.4.0+)

| Crate | License | Purpose |
|-------|---------|---------|
| tauri | Apache-2.0 OR MIT | Tauri v2 application framework |
| tauri-plugin-dialog | Apache-2.0 OR MIT | Native file dialog plugin |
| tauri-plugin-fs | Apache-2.0 OR MIT | File system access plugin |
| tauri-plugin-single-instance | Apache-2.0 OR MIT | Single instance enforcement |
| tauri-plugin-store | Apache-2.0 OR MIT | Key-value store plugin |
| iced-x86 | MIT | x86/x64 disassembler (Intel/GAS/NASM) |
| cpp_demangle | Apache-2.0 OR MIT | C++ symbol demangling (Itanium ABI) |
| rustc-demangle | Apache-2.0 OR MIT | Rust symbol demangling |
| yara-x | BSD-3-Clause | YARA rule engine (Rust) |
| sha1 | Apache-2.0 OR MIT | SHA-1 hashing |
| md-5 | Apache-2.0 OR MIT | MD5 hashing |
| hex | Apache-2.0 OR MIT | Hex encoding/decoding |
| zip | MIT | ZIP archive reading |
| sevenz-rust | Apache-2.0 | 7Z archive extraction (ADR 0029) |
| rars | MIT OR Apache-2.0 | RAR archive extraction (ADR 0029) |
| serde | MIT OR Apache-2.0 | Serialization for IPC |
| winreg | MIT | Windows registry access (context menu) |

### GUI Frontend Dependencies (npm)

| Package | License | Purpose |
|---------|---------|---------|
| react | MIT | UI framework |
| react-dom | MIT | React DOM renderer |
| react-i18next | MIT | i18n integration for React |
| i18next | MIT | Internationalization framework |
| @tauri-apps/api | Apache-2.0 OR MIT | Tauri JavaScript API |
| @tauri-apps/plugin-dialog | Apache-2.0 OR MIT | Dialog plugin JS bindings |
| @tauri-apps/plugin-fs | Apache-2.0 OR MIT | FS plugin JS bindings |
| lucide-react | ISC | Icon library |
| iced-x86 | MIT | x86 disassembler (WASM/JS) |
| typescript | Apache-2.0 | TypeScript compiler |
| vite | MIT | Build tool |
| tailwindcss | MIT | CSS framework |

### Development Dependencies (build/test/bench only)

| Crate | License | Purpose |
|-------|---------|---------|
| criterion | Apache-2.0 OR MIT | Benchmarking |
| clap | Apache-2.0 OR MIT | CLI argument parsing |
| rayon | Apache-2.0 OR MIT | Parallelism |
| crossbeam | Apache-2.0 OR MIT | Concurrency primitives |
| plotters | MIT | Criterion plotting |
| oorandom | MIT | Simple PRNG for tests |
| ciborium | Apache-2.0 | CBOR encoding for fuzz |
| generic-array | MIT | Type-level array |

### Transitive Dependencies

All transitive dependencies use permissive licenses (MIT, Apache-2.0,
BSD-2-Clause, BSL-1.0, Zlib, Unicode-3.0). No GPL, AGPL, or copyleft
licenses are present in the dependency tree.

## QuickJS

- **QuickJS** by Bellard: https://bellard.org/quickjs/
  - License: MIT
  - Bundled via `rquickjs-sys` crate
  - Used as: JavaScript engine for rule script execution

## Capstone

- **Capstone** by aquynh: https://www.capstone-engine.org/
  - License: MIT (Rust crate), BSD-3-Clause (upstream C library)
  - Bundled via `capstone-sys` crate
  - Used as: disassembly engine for PE.getDisasmString/getDisasmNextAddress

## pelite

- **pelite** by caspern: https://github.com/caspern/pelite
  - License: MIT
  - Used as: native PE32/PE64 binary parser (imports, exports, resources, manifest, version info)

## goblin

- **goblin** by m4b: https://github.com/m4b/goblin
  - License: MIT
  - Used as: native ELF and Mach-O binary parser (imports, sections, segments)

## Corpus

All corpus samples in `corpus/` and `corpus/edge/` are project-generated.
No third-party sample bytes are included. See:
- `tools/corpus/generate_baseline_corpus.py`
- `tools/corpus/generate_edge_corpus.py`

## Verification

To verify the license inventory:

```sh
cargo install cargo-license
cargo license --all-features
```

The output should match the dependencies listed above. Any new dependency
must be checked for license compatibility before merging.

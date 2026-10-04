# die-rust

A Rust rewrite of [Detect It Easy](https://github.com/horsicq/DIE-engine) (DIE).

[中文文档](README.zh-CN.md)

> **⚠️ Work in Progress — Not Production Ready**
>
> This project is under active development. Detection coverage, API
> stability, and output formats may change between commits. Some PE
> protector/packer rules that rely on disassembly (Capstone) are not
> yet supported. Do not use in production environments.

## Why

Aim for compatibility with upstream DIE — same detection capabilities,
same rule semantics, same output formats — with Rust's memory safety and
multi-language bindings.

## Project Principles

- **AI-developed, AI-tested**: this project is built and tested by AI.
  No manual testing is promised; bug reports are welcome.
- **Best-effort compatibility**: 1:1 behavioral parity with upstream DIE
  is not guaranteed, but compatibility is a primary goal.
- **Selective PRs**: pull requests are not guaranteed to be accepted; by
  default only changes that align the project with upstream features
  are merged.

## Key Points

- **DIE compatibility**: loads upstream rules verbatim via the rquickjs
  runtime; PE/ELF/MACH host API bridge implements most commonly used
  methods
- **Rust safety**: zero `unsafe` in core, panic containment at FFI
  boundary, no crashes on malformed input
- **Performance**: parallel database loading (3x faster than sequential),
  sub-microsecond format probing
- **Multi-language bindings**: C ABI + Go/cgo + Python ctypes

## Known Limitations

None at this time.

## Known Differences (Non-Defects)

- **Rule version differences**: 4 corpus samples detect more than upstream
  DIE 3.21 because the vendored rule database is newer. See
  `COMPATIBILITY.md` § Mismatch Details. These are NOT engine bugs.
- **Result deduplication**: `--alltypes` mode deduplicates results by default
  (upstream does not). Use `--no-dedup` to match upstream behavior. See
  ADR 0027.
- **RAR archive extraction**: Upstream XArchive's RAR decoder is a near-verbatim
  translation of UnRAR source code (94.21% token coverage across 17 UnRAR
  files) but is labeled MIT without retaining the UnRAR license notice or
  acknowledgments required for modified-source redistribution. For license
  compliance, die-rust does NOT copy, translate, or derive from the upstream
  RAR decoder. Instead, RAR member extraction uses `rars` (WTFPL), an
  independent pure-Rust RAR implementation. Due to the independent
  implementation, RAR extraction behavior may differ from upstream on edge
  cases (e.g., CAB LZX/Quantum methods, encrypted archives, corrupted
  headers). See `docs/research/rar-decoder-provenance.md` for the upstream
  source audit and ADR 0029 for the `rars` selection decision.

## Benchmark

Database load: **160ms** (parallel) vs **480ms** (sequential before
optimization) — **300% improvement**. Format probing: **60-407ns** per file.

Test method and raw data: [tools/benchmark/](tools/benchmark/) ·
[benchmark_results.json](tools/benchmark/results/benchmark_results.json)

Reproduce:
```sh
python tools/benchmark/run_benchmarks.py --quick
```

## Compatibility

**477 tests pass**, upstream rules loaded, 28 baseline + 20 edge-case
corpus files verified — no crashes, no spurious detections, no hangs.

Differential testing against upstream DIE 3.21:
- diec.exe self-detection: **5/5 match** (linker, compiler, tool,
  debug data, C/C++ runtime)
- 6 large system DLLs (0.5-61MB): **6/6 match**
- 28-file corpus: 17/28 match (remaining differences are rule version
  differences and format-type deduplication behavior)

Test method and raw data: [tools/benchmark/](tools/benchmark/) ·
[compatibility_results.json](tools/benchmark/results/compatibility_results.json)

Reproduce:
```sh
python tools/benchmark/run_compatibility.py
python tools/compat/compare_upstream.py
```

## Quick Start

```sh
git clone https://github.com/chennqqi/die-rust.git
cd die-rust && cargo build --workspace --release
./target/release/diec --alltypes file.exe
```

Python / Go / C bindings: see [README.zh-CN.md](README.zh-CN.md) or
[bindings/](bindings/).

### Linux Platform Requirements

The pre-built release binaries and the Rust standard library (since Rust
1.88) require **glibc 2.34+** (Ubuntu 22.04+, Debian 12+, RHEL 9+, Fedora 35+).
This is a constraint of the Rust toolchain's pre-compiled `std`, not a
project choice.

To run on older distributions (glibc < 2.34, e.g. Ubuntu 20.04, CentOS 7):

1. **Build from source on the target system** with a compatible Rust
   toolchain. Use `rustup default 1.87` (the last stable before glibc 2.34
   became the baseline), then `cargo build --workspace --release`.
2. **Use the Docker image** which ships a compatible glibc:
   ```sh
   docker run --rm -v "$PWD:/work" -w /work ghcr.io/chennqqi/die-rust:latest \
       diec --alltypes file.exe
   ```
3. **Static linking** (advanced): build with `RUSTFLAGS='-C target-feature=+crt-static'`
   to produce a fully static binary with no glibc dependency.

## died (Scan Service)

died (die daemon) is an HTTP/JSON scan service for batch file
identification. It loads the rule database once and reuses it across
requests, avoiding the 160ms per-process database load overhead.

```sh
# Build and start the server
cargo build --release --package die-server
./target/release/died --db upstream/Detect-It-Easy/db --bind 127.0.0.1:18080
```

Client examples (curl, PowerShell, Python, Go) and full API reference:
[docs/died-api.md](docs/died-api.md).

Windows service installation, Linux systemd setup, and DEB/RPM/MSI
packaging: [crates/die-server/packaging/README.md](crates/die-server/packaging/README.md).

## License

MIT — same as upstream. See [NOTICES.md](NOTICES.md).


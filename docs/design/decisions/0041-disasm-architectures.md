# ADR 0041: Additional Disassembly Architectures — Deferred

**Date**: 2026-10-05
**Status**: Deferred

## Context

Upstream disassembly is XCapstone (~15 architectures: x86, ARM, MIPS,
PPC, SPARC, RISC-V, WASM, M68K, ...). die-gui currently decodes x86
(iced-x86, 3 syntaxes) and ARM (yaxpeax-arm). Phase 18.D evaluated the
gap (V4-17):

| Architecture | Pure-Rust option | Maturity |
|--------------|------------------|----------|
| MIPS | `yaxpeax-mips` 0.1.0 | dormant since 2021, 8.6k downloads |
| PPC | none on crates.io | no viable pure-Rust decoder |
| RISC-V | `rvdasm` 0.3.0, `riscv-decode` 0.2.3 | young/thin; `rvdasm` 6k downloads |
| SPARC/M68K/etc | none maintained | — |
| all | `capstone` 0.14.0 native binding | mature, but C FFI + native build on every target |

## Decision

Keep x86 + ARM only; defer additional architectures.

## Rationale

- **Semantic parity argument favours capstone**: upstream *is* capstone —
  only the native binding reproduces its instruction semantics, aliases,
  and operand formatting exactly. But it adds a C toolchain dependency
  and FFI surface to every build target.
- **Pure-Rust coverage is incomplete**: there is no PPC decoder at all,
  RISC-V options are immature, and `yaxpeax-mips` has been dormant since
  2021. Half-coverage via disjoint decoder families would produce three
  different operand/notation styles — worse than a clean gap.
- **Demand**: MIPS/PPC/RISC-V disassembly matters mainly for firmware/IoT
  ELF files, which are a minority of the differential corpus.

## Re-evaluation triggers

- Differential corpus gains meaningful MIPS/PPC/RISC-V ELF samples, or
- a maintainer decision to accept the `capstone` native dependency — the
  only path that achieves genuine upstream parity across all ~15
  architectures in one stroke.

# ADR 0041: Additional Disassembly Architectures — Deferred

**Date**: 2026-10-05
**Status**: Deferred (re-evaluated 2026-10-03, Phase 30 — decision upheld)

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

## 2026-10-03 re-evaluation (Phase 30)

Both triggers checked; neither is met. **Decision upheld.**

| Trigger | Evidence |
|---------|----------|
| Corpus demand | 0 of 109 corpus files are MIPS/PPC/RISC-V/SPARC; all 3 ELFs are x86/x86-64 |
| Crate landscape | Unchanged since original ADR: `yaxpeax-mips` still 0.1.0 (dormant 2021), no `yaxpeax-ppc` crate exists, `rvdasm` 0.3.0/`riscv-decode` 0.2.3 unchanged, `capstone` 0.14.0 unchanged |
| Build environment | C toolchain (gcc/clang) present — capstone is *feasible*, but feasibility alone does not justify a native dependency with zero demand signal |

Partial pure-Rust coverage (MIPS via dormant yaxpeax + thin RISC-V,
no PPC at all) would still produce three disjoint operand notations —
the original rationale stands unchanged.

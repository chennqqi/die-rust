# ADR 0039: Fuzzy Hashes (SSDeep / TLSH) — Deferred

**Date**: 2026-10-05
**Status**: Deferred (SSDeep effectively rejected on license)

## Context

Upstream `XHashWidget` offers SSDeep and TLSH alongside cryptographic
hashes. Phase 18.C evaluated Rust-side options:

| Option | Status | License | Notes |
|--------|--------|---------|-------|
| `ssdeep` crate 0.7.0 | native binding to libfuzzy | **GPL-2.0** | libfuzzy/ssdeep is GPL — linking infects the binary distribution; incompatible with the project's dependency policy |
| Pure-Rust SSDeep port | none mature | — | fuzzy hashing rolling-hash algorithm is implementable but no maintained crate exists |
| `tlsh` crate 0.1.0 | pure Rust port, dormant since 2021 | Apache-2.0/BSD | 18k downloads, unmaintained; algorithm version skew risk vs upstream libtlsh (TrendMicro, C++) |
| `libtlsh` native | C++ library | BSD | native build burden on all platforms for a niche hash |

## Decision

- **SSDeep: rejected** — GPL-2.0 license of libfuzzy is incompatible; no
  maintained pure-Rust implementation exists. Re-evaluate only if a
  permissively-licensed maintained implementation appears.
- **TLSH: deferred** — the pure-Rust `tlsh` port is unmaintained since
  2021; the native libtlsh adds C++ build burden for a low-value widget
  feature. Revisit when analyst demand appears.

## Consequences

- The hash widget covers 17 cryptographic/checksum algorithms (Phase 17.C);
  fuzzy-hash columns remain absent vs upstream.
- No native or GPL dependencies are introduced.
- Re-evaluation trigger: maintained pure-Rust SSDeep/TLSH crate, or
  documented analyst workflow requiring fuzzy-hash triage.

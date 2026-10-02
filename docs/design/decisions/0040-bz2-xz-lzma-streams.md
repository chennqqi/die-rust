# ADR 0040: BZ2/XZ/LZMA Decompression via Pure-Rust Codecs

**Date**: 2026-10-05
**Status**: Accepted (implemented in Phase 18.C)

## Context

Upstream `XArchive` handles `.bz2`, `.xz`, and `.lzma` files as
single-member archives (one decompressed record). Phase 18.C evaluated:

| Option | Status | Notes |
|--------|--------|-------|
| `bzip2` 0.6 | native libbz2 binding | mature but native dep |
| `bzip2-rs` 0.1.2 | pure Rust, decode-only, dormant since 2021 | BZ2 format is frozen; decode-only is sufficient for an unpacker |
| `xz2` 0.1.7 / `liblzma-sys` | native liblzma | CVE-2024-3094 supply-chain incident; heavy build |
| `lzma-rs` 0.3.0 | pure Rust LZMA/LZMA2/XZ | 40M+ downloads, actively vendored by the 7z ecosystem |
| `lzma-rust` 0.1.7 | already in dep tree via `sevenz-rust` | exposes raw LZMA2 readers only — no `.xz` container parsing |

## Decision

- **BZ2**: `bzip2-rs` (decode-only, pure Rust).
- **XZ / LZMA-Alone**: `lzma-rs` (`xz_decompress` / `lzma_decompress`).
- Single-stream formats expose exactly one pseudo-member named `data`,
  matching upstream's one-record listing model.
- All output bounded by `MAX_SINGLE_MEMBER_BYTES`; overflow returns
  nothing rather than a truncated stream.
- LZMA has no magic bytes: detection is a strict header heuristic
  (props < 225, sane dict size, plausible size field); decode failures
  still return empty, so false positives are contained.

## Consequences

- `is_archive`/`extract_archive`/`list_archive_members`/`extract_member`
  now cover BZ2, XZ, and LZMA-Alone streams; the GUI archive view and
  nested-scan path pick them up with no adapter changes.
- No native dependencies added; `xz2`/`bzip2` (libbz2-sys) explicitly
  rejected.
- `bzip2-rs` dormancy is acceptable: the BZ2 bitstream is stable, and
  the decoder is exercised by roundtrip tests against `bzip2`-produced
  fixtures.

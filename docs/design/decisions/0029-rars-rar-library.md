# ADR 0029: `rars` (WTFPL) RAR Extraction Library Selection

**Date**: 2026-08-15
**Status**: Accepted

## Context

Phase 13 sub-task 13.5 implements archive member extraction for 5 formats:
ZIP, 7Z, RAR, CAB, ISO9660. The RAR format requires a decoder that supports
RAR 1.5/2.x/3.x/5.x decompression methods (LZ, PPMd, Store) and AES encryption.

**Upstream XArchive RAR decoder license problem**:

The upstream XArchive `xrardecoder.cpp`/`.h` is a near-verbatim translation of
UnRAR 7.13 source code:
- 94.21% token coverage (12-token shingle) across 17 UnRAR source files
- 74.21% token coverage (64-token shingle)
- Covers RAR 1.5/2.x/3.x/5.x unpack, PPM model, RAR VM, suballocator, bit reader
- Labeled horsicq MIT, but missing UnRAR license notice and `acknow.txt`
  attributions (PPM/AES/SHA public-domain, Intel BSD)

UnRAR license requires:
1. Modified source distribution must include the license paragraph in license,
   documentation, or source code comments.
2. Source code may not be used to develop RAR-compatible archiver or recreate
   the proprietary RAR compression algorithm.

die-rust has explicitly decided NOT to copy, translate, or derive from
XArchive's RAR decoder (see `docs/research/rar-decoder-provenance.md`).

**Pure Rust RAR library survey** (2026-08-15):

| Library | License | Pure Rust | Compatibility | Notes |
| --- | --- | --- | --- | --- |
| `rars` (bitplane) | WTFPL + "don't blame me" | Yes | Permissive, MIT-compatible | 407 commits, 69 stars, RAR 1.5-7 |
| `weaver-unrar` (scryer-media) | GPL-3.0-or-later | Yes | Copyleft, conflicts with AUDIT.md | Contains UnRAR license text |
| `unrar` crate | UnRAR license (C++ wrapper) | No | Requires native dependency | Conflicts with "pure Rust" principle |

## Decision

Select `rars` (WTFPL) as the RAR extraction library for die-rust.

**Rationale**:

1. **Pure Rust**: No native C/C++ dependency, consistent with the project's
   "prefer pure Rust, cross-platform dependencies" principle (AGENTS.md
   § Architecture & Security).

2. **License compatibility**: WTFPL is a permissive license that allows
   commercial use, modification, and distribution without copyleft
   restrictions. It is compatible with the project's MIT license. The
   "don't blame me" clause is a disclaimer, not a restriction.

3. **Non-standard SPDX**: WTFPL is not a standard SPDX identifier. This ADR
   documents the selection decision. `cargo license` and `NOTICES.md` must
   list WTFPL with a reference to this ADR.

4. **Coverage**: `rars` covers the full RAR lineage (RAR 1.5 through RAR 7),
   matching the upstream XArchive decoder's coverage.

5. **Independence**: `rars` is an independent implementation, not derived from
   UnRAR source code. This avoids the UnRAR license notice and attribution
   requirements entirely.

## Alternatives Considered

1. **`weaver-unrar` (GPL-3.0-or-later)**: Rejected. GPL-3.0 is a copyleft
   license that conflicts with the project's `AUDIT.md` requirement of "no
   copyleft licenses" (`cargo license --all-features` verification).

2. **`unrar` crate (UnRAR C++ wrapper)**: Rejected. Requires a native C++
   dependency (UnRAR source code), conflicting with the "prefer pure Rust"
   principle. Also introduces the UnRAR license notice compliance burden.

3. **Exclude RAR, implement only ZIP/7Z/CAB/ISO9660**: Rejected. The user
   explicitly decided to include all 5 formats for 100% upstream engine
   capability alignment. RAR is one of the 5 archive formats upstream
   supports.

4. **Implement RAR decoder from scratch**: Rejected. RAR decompression
   algorithms (LZ, PPMd) are complex and proprietary. Implementing from
   scratch would be a massive effort with high risk of incompatibility.
   The `rars` library already provides a working independent implementation.

5. **Defer RAR entirely**: Rejected by user decision. The user chose to use
   `rars` after reviewing the license survey.

## Consequences

- `rars` (WTFPL) is added as a dependency of the `die-unpack` crate (or
  `die-formats` extension).
- `NOTICES.md` must list `rars` with its WTFPL license and a reference to
  this ADR.
- `AUDIT.md` must document WTFPL as a permissive (non-copyleft) license.
- `cargo license --all-features` must continue to show no copyleft licenses.
- RAR extraction behavior may differ from upstream on edge cases due to the
  independent implementation. These differences must be documented in
  `COMPATIBILITY.md` and tested with differential testing.
- The `rars` library's WTFPL license is not a standard SPDX identifier.
  `cargo deny` configuration may need a waiver entry for WTFPL.

## Evidence

- `docs/research/rar-decoder-provenance.md`: upstream XArchive RAR decoder
  source audit (94.21% UnRAR token coverage, missing notice)
- `https://github.com/bitplane/rars`: `rars` repository (407 commits, 69 stars)
- `https://raw.githubusercontent.com/bitplane/rars/master/COPYING`: WTFPL +
  "don't blame me" license text
- `https://raw.githubusercontent.com/bitplane/rars/master/README.md`: RAR
  1.5-7 coverage, pure Rust, no native dependencies
- `https://raw.githubusercontent.com/scryer-media/rarpar/main/Cargo.toml`:
  `weaver-unrar` is GPL-3.0-or-later
- `https://docs.rs/weaver-unrar/latest/weaver_unrar/`: `weaver-unrar` docs
  contain UnRAR license paragraph
- `AUDIT.md`: project supply chain audit requires no copyleft licenses
- `AGENTS.md` § Architecture & Security: "prefer pure Rust, cross-platform
  dependencies"

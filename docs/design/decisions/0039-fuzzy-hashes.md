# ADR 0039: Fuzzy Hashes (SSDeep / TLSH) — Accepted (SSDeep), Superseded TLSH

**Date**: 2026-10-05 (v1), revised 2026-10-05 (v2, Phase 38)
**Status**: Accepted — SSDeep implemented clean-room; v1 "rejected" status superseded

## Context

v1 evaluated SSDeep as "upstream offers it via XHashWidget" and rejected it
on license grounds (libfuzzy is GPL-2.0; no maintained pure-Rust port).
Phase 38 re-investigated the pinned baseline directly:

- `XHashWidget` submodule at pinned `291e3ef6` contains **no fuzzy-hash
  code** — it is a thin wrapper over `XBinary::getHashMethodsAsList()`.
- `XBinary::HASH` at pinned DIE-engine `23fec32` lists only
  MD4/MD5/SHA1/SHA2-family entries. **Upstream at the pin ships no
  SSDeep implementation at all**, so there is no upstream oracle and the
  earlier "upstream implementation deviates" rationale was incorrect.

Phase 29 already set a precedent of extending the hash panel beyond the
pinned list (GOST/Tiger/Whirlpool/TLSH via `tlsh2`), so adding SSDeep is
consistent — provided the GPL license blocker is removed.

## Decision

- **SSDeep: implemented** as a clean-room Rust port
  (`crates/die-gui/src/ssdeep.rs`). Written against the published CTPH /
  SpamSum algorithm description — not translated from GPL `fuzzy.c` — so
  no copyleft is introduced. Output is byte-compatible with libfuzzy.
- Oracle: `ppdeep` 20260221 (Apache-2.0 pure-Python port of spamsum)
  generated reference digests stored in `corpus/ssdeep-vectors.json`;
  payloads are reconstructed by a shared deterministic LCG recipe, and the
  unit test asserts digest parity including the block-size halving retry
  and rolling-hash tail semantics.
- **TLSH**: unchanged — provided by the `tlsh2` pure-Rust crate since
  Phase 29.
- The `ssdeep` native crate (libfuzzy binding) remains rejected: native
  dependency + GPL linkage.

## Consequences

- `SSDEEP` is selectable in the GUI hash panel (`HASH_ALGORITHMS`) and
  `compute_named_hash`; output format is the canonical
  `blocksize:digest1:digest2`.
- This is a documented **extension** over the pinned upstream, not an
  alignment gap — no differential-against-upstream test can exist.
- Re-evaluation trigger: upstream adds a fuzzy hash to `XBinary::HASH`
  with a different algorithm version (e.g. ssdeep v3 digests); then the
  oracle target changes.

# ADR 0036: Defer Static Unpacker (XStaticUnpacker) Porting

**Date**: 2026-10-02  
**Status**: Deferred

## Context

Upstream ships `XStaticUnpacker` — a collection of per-packer static
unpackers (UPX, ASPack, PECompact, etc.) exposed through the GUI `Unpack`
tool button (`on_toolButtonUnpack_clicked`). Phase 17 analysis lists it
as fully missing (V4-06).

Each packer unpacker is a bespoke transform: stub identification,
OEP discovery, section reconstruction, import repair. UPX alone is
well-understood, but upstream supports a long tail of packers whose
implementations are individually non-trivial.

## Decision

Defer static unpacking. No stub or placeholder UI is added for the
`Unpack` tool button.

## Rationale

- Per-packer correctness requires packer-specific test corpora;
  partial ports (e.g. UPX only) risk silently wrong output on malformed
  or variant samples, which violates the "no silent unsupported
  behavior" rule.
- Archive extraction (17.B) already covers the container-unpacking use
  case that matters for the engine's nested-scan pipeline.
- A future port should proceed one packer at a time, starting with UPX,
  each with real-sample differential tests against upstream output.

## Consequences

- Packed binaries are reported as packed by DIE signatures but not
  unpacked for display; users can use archive extraction or external
  unpackers.
- Re-evaluation trigger: dedicated phase with per-packer corpus and
  upstream differential fixtures.

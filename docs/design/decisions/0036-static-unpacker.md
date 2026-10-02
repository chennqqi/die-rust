# ADR 0036: Defer Static Unpacker (XStaticUnpacker) Porting

**Date**: 2026-10-02  
**Status**: Accepted (UPX scope; other packers remain deferred)

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

## Resolution (Phase 20, 2026-10-07)

UPX was implemented per the "one packer at a time" exit condition:

- `diec-engine::unpack` module: `UPX!` pack-header parsing aligned with
  `XUPX::_read_packheader` (version-sensitive header sizes, filter/CTO/MRU),
  UCL NRV2B/2D/2E decompression (all 9 bit-reader variants, ported from
  UCL source), LZMA and raw DEFLATE dispatch, UPX PE call/jmp filter
  restoration (little-endian, matching `_read_uint32` defaults), and PE
  reconstruction matching `XUPX::_unpackPE` (headers, sections, imports,
  relocations, exports, resources, overlay).
- Differential tests compare section-level bytes against `upx -d` output
  on a generated corpus (PE32 × NRV2B/NRV2E/LZMA, PE64 × NRV2B).
- CLI `--unpack` and GUI `unpack_file`/`detect_upx` commands added.
- Other packers (ASPack, PECompact, …) remain deferred under the same
  per-packer corpus requirement.

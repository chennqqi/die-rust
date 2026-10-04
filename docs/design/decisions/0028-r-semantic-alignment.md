# ADR 0028: `-r`/`--recursivescan` Semantic Alignment with Upstream

**Date**: 2026-08-15
**Status**: Accepted

## Context

The upstream DIE-engine release `diec` CLI uses `-r`/`--recursivescan` to enable
**intra-file recursive scanning** of PE resources and overlays, NOT directory
recursion. Specifically:

- `bIsRecursiveScan` enables PE resource scanning (`bIsResourcesScan ||
  bIsRecursiveScan`) and overlay scanning (`bIsOverlayScan ||
  bIsRecursiveScan`).
- The release CLI (`src/console/main_console.cpp`) does NOT register
  `bIsArchivesScan`, `bIsResourcesScan`, or `bIsOverlayScan` as independent
  options; `-r` is the only way to reach resource/overlay recursive scanning.
- Directory enumeration is unconditional (depth-first) and does not depend on
  `-r`.

die-rust's current `-r`/`--recursive` does **directory-level recursion**
(`expand_target` in `main.rs` L53-65), which is semantically different from
upstream. This means:

1. die-rust cannot produce nested resource/overlay detections (e.g., PE → PDF
   Resource, PE → PDF Overlay) that upstream produces with `-r`.
2. die-rust's `-r` on a directory silently does something upstream does not
   gate on `-r` at all.

This is a **breaking change**: existing users who run `diec -r directory` must
switch to `diec --recursive-dir directory`.

## Decision

Align `-r`/`--recursivescan` with upstream semantics:

1. **`-r`/`--recursivescan`**: Enable intra-file resource/overlay recursive
   scanning (maps to `flags.recursive = true` in `ScanFlags`). When scanning a
   PE file with `-r`, the scanner enumerates PE resources (up to 20, or 2000
   with `--aggressivescan`) and overlay, recursively scans each as a subdevice,
   and nests child detections under the parent with `file_part`, `offset`, and
   `size`.

2. **`--recursive-dir`/`-R`** (new option): Directory-level recursion. Replaces
   the old `-r` directory behavior. This is the equivalent of upstream's
   unconditional directory enumeration.

3. **`--help` and documentation**: Clearly document that `-r` enables
   intra-file recursive scanning (matching upstream), and `--recursive-dir`
   enables directory recursion.

4. **ScanFlags extension**: Add `recursive: bool`, `resources: bool`,
   `overlays: bool` fields to `ScanFlags`. The `is_recursive()` host API
   method returns `flags.recursive || flags.resources || flags.overlays`
   (currently hardcoded to `false`).

5. **FFI/server/GUI propagation**: The new flags propagate through all layers:
   `ScanFlags` (engine) → `--recursivescan`/`--recursive-dir` (CLI) →
   FFI scan options → server `ScanFlagsRequest` → GUI `ScanFlagsDto`.

## Alternatives Considered

1. **Keep `-r` as directory recursion, add `--nested` for intra-file
   recursion**: Rejected. This would leave die-rust's `-r` semantically
   incompatible with upstream, defeating the goal of 100% CLI alignment.
   Differential testing of `-r` behavior would always show mismatches.

2. **`-r` does both directory and intra-file recursion**: Rejected. Mixed
   semantics are confusing. Upstream's `-r` on a directory does NOT enable
   intra-file recursion per-file — it's the same flag but the directory
   enumeration is unconditional. Conflating the two would produce unexpected
   nested detections when users only want directory traversal.

3. **Keep `-r` as directory recursion, do not implement intra-file
   recursion**: Rejected. This leaves G3 (resource/overlay recursive scanning)
   unimplemented, which is a core upstream capability.

## Consequences

- **Breaking change**: `diec -r directory` must become
  `diec --recursive-dir directory`. Users of FFI/server/GUI APIs that set
  `recursive = true` for directory scanning must switch to the new
  directory-recursion flag.
- The `ScanFlags` struct gains 3 new `bool` fields (`recursive`, `resources`,
  `overlays`). Since `ScanFlags` is a Rust struct (not C ABI), this is a
  source-level change. All callers use `#[derive(Default)]` which initializes
  to `false`.
- The FFI `DieScanOptions` struct may need new bit flags for
  `DIE_SCAN_FLAG_RECURSIVE` and `DIE_SCAN_FLAG_RECURSIVE_DIR`. These use
  available bits (0x80 and beyond), maintaining ABI backward compatibility.
- Differential testing of `-r` on the 8 nested corpus samples will now match
  upstream output.
- Release notes must prominently document the `-r` semantic change.

## Evidence

- `docs/research/nested-scan-behavior.md` L9-19: upstream `-r` enables
  resource/overlay intra-file recursion, not directory enumeration
- `docs/research/nested-scan-behavior.md` L78-80: three-layer capability
  table showing release CLI exposes `-r` for resource/overlay, archive
  unreachable
- `docs/research/nested-scan-behavior.md` L183-212: 8 nested corpus samples
  × 4 modes with fixed stdout SHA-256
- `crates/die-cli/src/main.rs` L33, L142-144, L53-65: current `-r` does
  directory recursion only
- `crates/die-engine/src/host.rs` L22-45: `ScanFlags` has no
  resource/overlay/recursive fields
- `crates/die-engine/src/host.rs` L415-417: `is_recursive()` hardcoded to
  `false`
- `crates/die-core/src/request.rs` L64-71: `NestingOptions` defined but
  unused by engine
- `crates/die-engine/src/scanner.rs` L279-313: `ScanDetection` has
  `parent_id`/`file_part`/`offset`/`size` fields, always `None`

# ADR 0027: Result-Level Deduplication for --alltypes

**Date**: 2026-08-08  
**Status**: Accepted

## Context

The `--alltypes` flag runs all 18 file_type rule groups (PE, ELF, MACH, MSDOS,
Binary, APK, JAR, ZIP, RAR, DEX, PDF, CFBF, ISO9660, JPEG, PNG, PYC, NPM,
JavaClass) regardless of the detected format. This causes cross-group
duplicate detections: for example, a PE file also matches MSDOS rules, and
both groups output "MS-DOS" as a format detection.

Upstream DIE-engine has no result-level deduplication — it relies on
`bIsAllTypesScan` to control which rule groups run, but does not filter
duplicate results across groups.

The free function `scan_bytes` (scanner.rs L385-516) and the stateful
`Scanner::scan_bytes` (scanner.rs L603-747) both aggregate detections from
all rule groups into a single `Vec<ScanDetection>` without any dedup step.

## Decision

Add result-level deduplication **enabled by default**, with a `--no-dedup`
opt-out flag to preserve upstream behavior for differential testing.

**Dedup key**: `(type_name, name, version, options, offset, size)`

- **Excludes `file_type`**: The core problem is cross-file_type duplicates
  (e.g., PE and MSDOS both output "MS-DOS"). Including `file_type` in the key
  would prevent cross-group dedup, defeating the purpose.
- **Excludes `signature_path`**: Different rule files can produce the same
  detection; the signature source is not part of detection identity.
- **Excludes `id`/`parent_id`/`file_part`/`is_heuristic`/`is_a_heuristic`/
  `original_name`**: These are metadata fields that don't change the
  semantic identity of a detection.

**Keep policy**: Retain the first occurrence, discard subsequent duplicates.
Rules execute in BTreeMap dictionary order by file_type, so the first
occurrence comes from the more specific format group (e.g., "MSDOS" before
"Binary"), which is the more precise detection.

**Flag propagation**: The `no_dedup` flag is propagated through all 6 layers:
`ScanFlags` (engine) → `dedup_detections` (scanner) → `--no-dedup` (CLI) →
`DIE_SCAN_FLAG_NO_DEDUP = 0x40` (FFI C ABI) → `ScanFlagsRequest.no_dedup`
(server) → `ScanFlagsDto.no_dedup` (GUI).

## Alternatives Considered

1. **No dedup (match upstream exactly)**: Rejected. Cross-group duplicates
   are user-visible noise. The `--alltypes` mode is specifically for
   exhaustive scanning, and duplicate entries add no information.

2. **Dedup including `file_type` in key**: Rejected. This would not solve
   the core problem — PE "MS-DOS" and MSDOS "MS-DOS" have different
   `file_type` values and would both be kept.

3. **Dedup always, no opt-out**: Rejected. Differential testing against
   upstream requires the ability to reproduce upstream's non-deduplicated
   output. The `--no-dedup` flag provides this escape hatch.

4. **Dedup off by default, `--dedup` opt-in**: Rejected. The default
   behavior should be the higher-quality output. Users who need
   upstream-exact output are a minority (primarily differential testing).

## Consequences

- Default `--alltypes` output has fewer entries than upstream (dedup removes
  cross-group duplicates). This is an intentional quality improvement.
- `--no-dedup` preserves upstream behavior for differential testing.
- The FFI `DIE_SCAN_FLAG_NO_DEDUP = 0x40` uses bit 7 (bits 1-6 are already
  allocated: 0x01-0x20). This does not change `DieScanOptions` struct layout
  or `struct_size`, maintaining ABI backward compatibility.
- The `ScanFlags` struct gains a new `no_dedup: bool` field. Since `ScanFlags`
  is a Rust struct (not a C ABI struct), this is a source-level change with
  no ABI impact. All callers use `#[derive(Default)]` which initializes
  `no_dedup` to `false` (dedup on).

## Evidence

- `crates/die-engine/src/scanner.rs` L385-516: `scan_bytes` free function,
  no dedup before returning `ScanResult`
- `crates/die-engine/src/scanner.rs` L603-747: `Scanner::scan_bytes`,
  same pattern
- `crates/die-engine/src/scanner.rs` L224-246: `all_rule_types()` returns
  18 file types for `--alltypes` mode
- `crates/die-engine/src/scanner.rs` L248-284: `ScanDetection` struct with
  14 fields
- `crates/die-engine/src/host.rs` L22-39: `ScanFlags` struct (6 fields
  before change)
- `include/die.h` L51-58: `DIE_SCAN_FLAG_*` macros, bits 0x01-0x20 used
- `crates/die-ffi/src/scan.rs` L136-159: `options_to_flags` bit mapping

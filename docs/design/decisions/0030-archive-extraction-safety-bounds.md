# ADR 0030: Archive Member Extraction Safety Bounds

**Date**: 2026-08-15
**Status**: Accepted

## Context

Phase 13 sub-task 13.5 implements archive member extraction and recursive
scanning for ZIP, 7Z, RAR, CAB, and ISO9660 formats. The upstream DIE-engine
has **no total decompressed byte limit, no single-member size limit, and no
compression ratio limit** (see `docs/research/nested-scan-behavior.md`
§ Archive 分支). This creates a compression bomb (zip bomb) risk:

- A 42KB ZIP file can decompress to 4.5 PB (petabytes) with a 1:10^8 ratio.
- Upstream's only limit is the member count: 20 (default) or 100000
  (aggressive), and a loop hard cap of `i < 100000`.
- Upstream allocates the full declared uncompressed size as a buffer before
  decompression, with no cap on individual member size.

die-rust's core principle (AGENTS.md § Architecture & Security): "All binary
input is untrusted. Offsets, lengths, integer arithmetic, and allocations must
be bounded; malformed input must not cause panics, out-of-bounds, infinite
loops, or unbounded allocations."

The existing `die-core/src/limits.rs` already defines a framework:
- `max_archive_entries: u64` (default 4096)
- `max_total_decompressed_bytes: u64` (default 512 MiB)
- `max_depth: u32` (default 32)
- `max_single_allocation_bytes: u64` (default 128 MiB)

However, these limits are not yet enforced in any extraction path.

## Decision

Enforce safety bounds on archive member extraction that are **stricter than
upstream** but sufficient for real-world archives:

1. **Single-member decompressed size limit**: `max_single_allocation_bytes`
   (default 128 MiB). If a member's declared uncompressed size exceeds this,
   skip the member and emit a diagnostic. Do NOT allocate the buffer.

2. **Total decompressed bytes limit**: `max_total_decompressed_bytes`
   (default 512 MiB). Track cumulative decompressed bytes across all members
   in a single scan. If exceeded, stop extracting further members and emit a
   diagnostic.

3. **Compression ratio limit**: If `declared_uncompressed_size /
   compressed_size > 100`, skip the member and emit a diagnostic. This catches
   classic zip bombs (typical real-world ratios are 1:3 to 1:10; even highly
   compressible data rarely exceeds 1:50).

4. **Member count limit**: Match upstream: 20 (default), 100000 (aggressive).
   The loop hard cap is 100000.

5. **Recursion depth limit**: `max_depth` (default 32). Nested archives
   (archive within archive) are recursively scanned; depth is tracked and
   enforced. Upstream has no independent depth limit (termination depends on
   structure not producing more file parts).

6. **Memory allocation**: Allocate extraction buffers lazily (only when the
   member is actually scanned, not when declared size is read). Use
   `max_single_allocation_bytes` as the allocation cap.

7. **Timeout**: Respect the existing `CancellationToken` and `ScanLimits`
   deadline. Long-running extraction must be cancellable.

**Divergence from upstream**: These limits are stricter than upstream. Some
legitimate but highly compressed archives (ratio > 100) may not be fully
extracted. This is an intentional safety improvement, documented as a known
difference. The limits are configurable via `ScanLimits` for users who need
higher thresholds.

## Alternatives Considered

1. **Match upstream (no limits)**: Rejected. Violates the project's core
   security principle. A malicious archive could exhaust memory or cause
   unbounded allocation.

2. **Ratio limit only (no total/single size limits)**: Rejected. A malicious
   archive could use many small members with moderate ratios to exhaust
   memory cumulatively.

3. **Very high limits (e.g., 4 GiB single, 16 GiB total)**: Rejected. These
   limits are too high to effectively prevent memory exhaustion on typical
   systems. The 128 MiB / 512 MiB defaults are sufficient for real-world
   archives (the largest legitimate test archive in the corpus is ~1 MB).

4. **Configurable limits only, no defaults**: Rejected. Default-unlimited
   would leave the common case unsafe. The defaults must be safe; users can
   raise them if needed.

## Consequences

- Archive extraction is **safer than upstream** but may not extract some
  edge-case archives (very large members, very high compression ratios).
  This is documented as a known difference in `COMPATIBILITY.md`.
- The `max_total_decompressed_bytes` and `max_single_allocation_bytes` fields
  in `die-core/src/limits.rs` are now actively enforced in the extraction
  path.
- The compression ratio limit (100:1) is a new safety check not present in
  the existing `limits.rs` framework. It should be added as a new field
  (e.g., `max_compression_ratio: u32`, default 100).
- Differential testing against upstream may show differences on adversarial
  archives (zip bombs). These are expected and documented, not bugs.
- The `ScanLimits` struct gains a `max_compression_ratio` field. Since it's a
  Rust struct with `#[derive(Default)]`, this is a source-level change.
- FFI `DieScanOptions` may need an extension mechanism for custom limits;
  current design uses `struct_size` for additive extension.

## Evidence

- `docs/research/nested-scan-behavior.md` L103-123: upstream archive
  extraction flow, no total/single size/ratio limits
- `docs/research/nested-scan-behavior.md` L121: "分配发生在成员类型过滤之前，
  且按 archive 声明的解压后大小创建 buffer" (allocation by declared size)
- `crates/die-core/src/limits.rs` L29-30, L76-77, L86-89: existing limit
  framework (`max_archive_entries`, `max_total_decompressed_bytes`,
  `max_depth`, `max_single_allocation_bytes`)
- `AGENTS.md` § Architecture & Security: "All binary input is untrusted...
  malformed input must not cause panics, out-of-bounds, infinite loops, or
  unbounded allocations."
- `docs/research/archive-adversarial-behavior.md`: ZIP deflate/ZipCrypto,
  high compression ratio, CRC/compression stream malformed inputs

## Amendment (2026-10-12): bounds are now host-configurable

All constants moved into `diec_engine::archive_unpack::ArchiveLimits`
(`members_normal`, `members_aggressive`, `single_member_bytes`,
`total_decompressed_bytes`, `compression_ratio`, `member_names`,
`member_string_bytes`, `iso_max_depth`). `Default` reproduces the
original values byte-for-byte, so the safe-default policy is unchanged;
hosts may now override per invocation:

- Engine: `ScanFlags::archive_limits`
- CLI: `--archive-max-member/--archive-max-total/--archive-max-ratio/
  --archive-max-members` (plain integers, K/M/G suffixes)
- Server: `ScanFlagsRequest.archive_limits` (JSON body field on
  `/scan/path`; the scalar `/scan/bytes` query keeps defaults)
- GUI: `ScanFlagDefaults.archive_limits` (persisted settings) +
  `ScanFlagsDto.archive_limits` per-scan override + settings-panel
  numeric inputs
- Record-level APIs (`list_archive_members`, `extract_member`,
  `zip_member_*`) take `&ArchiveLimits` explicitly

Detection heuristics (`is_lzma`) keep the default bound so loosened
extraction limits never widen the detection surface.

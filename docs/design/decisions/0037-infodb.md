# ADR 0037: Defer InfoDB (Bookmarks/Annotations) Infrastructure

**Date**: 2026-10-02  
**Status**: Deferred

## Context

Upstream `XInfoDB` provides per-file persistent annotations: bookmarks,
comments on offsets/addresses, and symbol overlays used by the hex and
disassembly views. Phase 17 analysis lists it as fully missing (V4-07)
and notes it also blocks upstream-style disasm annotations.

Implementing it requires: a storage format (upstream uses a device-id
keyed SQLite store), a mutation API across views, and invalidation on
file change — plus UI affordances in every view that displays offsets.

## Decision

Defer InfoDB. Bookmarks/comments are not implemented; no schema is
reserved.

## Rationale

- InfoDB is infrastructure, not a view feature: it touches storage,
  IPC surface, and every offset-bearing widget.
- The GUI's primary use (scan + inspect) is complete without
  annotation persistence; annotations are an analyst-workflow
  enhancement.
- Committing to a schema now without the annotation UX design risks a
  migration burden; deferring keeps options open (SQLite via
  `tauri-plugin-sql` vs. sidecar JSON).

## Consequences

- No bookmark/comment persistence; disassembly shows no user labels.
- Re-evaluation trigger: when analyst-workflow features (commenting,
  session save/restore) are scheduled; the schema decision should be
  revisited then.

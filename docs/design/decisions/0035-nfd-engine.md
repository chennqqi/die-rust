# ADR 0035: Defer NFD (SpecAbstract) Engine Porting

**Date**: 2026-10-02  
**Status**: Deferred

## Context

Upstream `DIE-engine` integrates `nfd_widget` backed by the SpecAbstract
(NFD) signature engine — a second static scanner beside DIE signatures,
covering compilers/linkers/installers for binary identification.
The Phase 17 gap analysis (`gui-gap-analysis-v4.md`, V4-05) lists NFD as
fully missing: the GUI has only a `nfd_enabled` setting stub with no
backend.

Porting SpecAbstract means re-implementing a signature engine of
comparable scope to the DIE engine itself (its own rule format, scanning
pipeline, and host bindings) plus its `specabstract` database, which is
licensed separately from DIE rules.

## Decision

Defer NFD engine porting indefinitely. The `nfd_enabled` setting stub is
removed from the GUI until a backend exists.

## Rationale

- NFD is a second engine, not an incremental feature; effort is
  comparable to the core DIE engine already ported.
- The SpecAbstract database license and redistribution terms have not
  been audited; importing rules requires provenance review per project
  rules.
- DIE signatures already cover the dominant detection surface; NFD adds
  incremental identification, not new capability classes.
- The scan-engine selector UX can remain per-tab until NFD exists.

## Consequences

- GUI scan-engine selector stays as separate tabs (DIE/YARA/PEiD).
- Re-evaluation trigger: a dedicated phase if downstream users request
  NFD-level identification coverage, or if SpecAbstract licensing is
  confirmed compatible and a porting budget is approved.

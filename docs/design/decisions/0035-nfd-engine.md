# ADR 0035: Defer NFD (SpecAbstract) Engine Porting

**Date**: 2026-10-02  
**Status**: Accepted (partial) — superseded 2026-10-07

> **Update (Phase 21, 2026-10-07)**: the license gate cleared (SpecAbstract
> is MIT) and a bounded port shipped. `crates/die-nfd` re-implements the
> matching core in pure Rust; signature tables are generated from the C
> arrays by `tools/nfd_codegen.py` (35 tables / 1730 records @ 5188e047,
> MIT attribution in generated headers). Ported dispatch: BINARY
> header/archive scans, MSDOS, PE32/PE64 (header, entry-point chain
> incl. NOP/JZ/E9-follow, import hashes, resources, section names, Rich
> records, deep section scans). Integration: `ScanFlags::nfd` /
> CLI `--nfd` / GUI engine checkbox; records carry `engine="nfd"`.
> Later slices added: COM (header + exp), NE (linker header + CS:IP
> entrypoint), LE/LX (linker header), ELF32/64 (`elf.rs` — OSABI/
> interpreter/note/comment chain + debug-data + libraries + tool
> metadata), DEX (string/type scans), APK (member-name scans, signing
> block v2/v3/Walle/GooglePlay, Kotlin/Java, Android OS), ZIP container
> info, PDF version fixup, MSDOS extender/vintage banners, and Mach-O
> 32/64 (`mach.rs` + `mach_tables.rs` — LC_* command driven OS/SDK/
> Xcode/clang/Swift/ld version chain, Foundation/codesign/Qt/Carbon/
> Cocoa/VMProtect/Zig records; CAFEBABE FAT-vs-JavaClass
> disambiguation follows the upstream field-validity walk).
> Still deferred: heuristic `handle_*` version enrichment, per-format
> regex heuristics, and JavaClass/PDF/JPEG/CFBF/Amiga/JAR/MACHOFAT
> `getInfo` bodies (generic binary fallback).

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

# ADR 0038: Incremental i18n Coverage, No Bulk .ts Conversion

**Date**: 2026-10-02  
**Status**: Accepted

## Context

Upstream ships 22 Qt `.ts` translation catalogs (`die_*.ts`); the GUI
ships 5 i18next JSON catalogs (en, zh-CN, ru, de, fr) — a gap of 17
languages (V4-15).

Upstream `.ts` files are XML with Qt-specific context grouping and
plural forms; our strings are a different key space (i18next JSON), so
upstream catalogs cannot be converted mechanically — every upstream
keyed string maps to a Qt UI string, not to our keys.

## Decision

Do not bulk-convert upstream `.ts` files. Add languages incrementally on
demand, keyed off our own catalog; accept community/user-provided
translations per language.

## Rationale

- The key spaces are disjoint: upstream `.ts` covers Qt widget text that
  mostly does not exist verbatim in our UI; conversion would produce
  near-empty or misleadingly-filled catalogs.
- Machine translation of our own catalogs is possible but produces
  low-quality domain terms (packer names, format jargon); better to add
  languages when a reviewer can validate them.
- The 5 existing languages cover the current user base per issue
  feedback; new languages are a low-risk incremental add (drop a JSON
  file into `frontend/src/i18n/` and register it).

## Consequences

- Language count stays at 5 until contributors provide validated
  translations.
- If demand arises, the path is: `frontend/src/i18n/<lang>.json`
  mirroring the English key set, then a settings option — no engine
  work required.

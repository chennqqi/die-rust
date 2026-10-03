# ADR 0042: Intentional Deviation Governance and Conditional Phases

**Date**: 2026-10-12
**Status**: Accepted

## Context

After Phases 41–44 eliminated all remaining schedulable alignment
gaps, the
delta between diec-rust and the pinned upstream baseline consists
entirely of intentional deviations, blocked items, and deferred items.
Previously these were recorded across several ADRs (0019, 0030,
0035–0039) plus scattered ROADMAP/COMPATIBILITY notes with inconsistent
status wording ("deferred", "不立项", "permanent", "stub") and no
explicit revisit triggers.

This ADR establishes a single classification and disposition for every
intentional deviation, so each item is either (a) permanently
intentional, (b) scheduled as a future phase, or (c) blocked with an
explicit unblocking condition.

## Decision

### Classification taxonomy

| Disposition | Meaning |
|---|---|
| **Permanent** | Deliberate product/platform/safety difference. No upstream parity goal. Revisit only via a new ADR. |
| **Scheduled** | Committed to a future phase (Phase 45+). Upstream source and oracle path exist in the pinned baseline. |
| **Conditional** | Implementation gated on an explicit external prerequisite (infrastructure, corpus, demand). Recorded trigger required. |
| **Blocked** | Not implementable from the pinned baseline (missing upstream source). Revisit only if an independent pinned source + oracle become available. |
| **Parity** | Previously listed as a deviation but verified identical to upstream behavior. |

### Inventory and dispositions

| # | Item | Current Rust behavior | Upstream behavior | Disposition | Trigger / unblocking condition |
|---|---|---|---|---|---|
| 1 | Archive safety bounds (ADR 0030) | 128 MiB member / 512 MiB total / 100:1 ratio / 20-or-100000 members / depth 32, fail-closed | No size/ratio limits; member-count and loop caps only | **Permanent** (safety hardening) | Only via a new ADR introducing an explicit opt-out flag; safe defaults must remain |
| 2 | XStyles theme ecosystem | CSS-variable themes: light/dark/system | Qt QSS style sheets (XStyles submodule, pinned `948dd85`, not checked out) | **Permanent** platform difference; **Conditional** phase for a Tauri-native theme set | User/distribution demand for additional themes → Phase 49 |
| 3 | i18n coverage (ADR 0038) | 5 validated locales × 269 keys (en, zh-CN, ru, de, fr) | 22 Qt `.ts` catalogs + 24 XTranslation `.po` terminology dictionaries | **Scheduled** → Phase 45 (terminology-anchored drafts + validation tooling) | — |
| 4 | InstallSimple static unpacker | Not implemented | `xinstallsimple.cpp` wholly inside `#ifdef USE_XEMULATOR`; XEmulator absent from pin | **Blocked** | Pin horsicq/XEmulator at a fixed SHA as an external oracle source + reproducible build + security review of the sandboxed-execution semantics |
| 5 | Tauri auto-update (ADR 0019) | Not implemented | Upstream XUpdate/XOnlineTools unchecked-out Qt components; not on the diec console path | **Conditional** → Phase 48 | Release-infrastructure decision: Ed25519 signing key pair, private-key CI storage, update-manifest endpoint |
| 6 | RNC old-variant / encrypted-stream corpora | Decoders fully ported (Phase 24); only synthetic oracle-verified fixtures exist | Same code path; upstream also lacks bundled samples | **Conditional** → Phase 47 | Generator producing oracle-accepted old-variant streams, or real ProPack samples via hash manifest (never commit binaries) |
| 7 | Windows shell context menu | `add_context_menu`/`remove_context_menu`/`get_context_menu_status`, Windows registry only | `XOptions::registerContext` is `#ifdef Q_OS_WIN` — Windows-only upstream | **Parity** (was misclassified as a gap). No action. | If Linux/macOS shell integration is ever requested it is a new product feature, not a parity item |
| 8 | NFD/SpecAbstract remaining scope (ADR 0035) | All `getInfo` drivers and nearly all `handle_*` chains ported (Phases 21–23). Residual: `handle_PolyMorph` (nfd_pe.cpp:8283 call site) and ZIP-family member handlers `handle_Metainfos`/`handle_Microsoftoffice`/`handle_OpenOffice`/`handle_JAR`/`handle_IPA` (`promote.rs` "Phase 23.C pending"). `handle_AnslymPacker` is commented-out dead code upstream — parity, not a gap | Full SpecAbstract (pinned `5188e04`, checked out) | **Scheduled** → Phase 46 | — |
| 9 | XStaticUnpacker packers (ADR 0036) | All non-emulator modules ported with oracle-verified parity: UPX (Phase 20), MEW/Petite/yoda/ASPack/NsPack (Phases 26–27), AutoIt/EnigmaVB/BoxedApp (Phase 28) | 10 modules; XEmulator needed only by xinstallsimple and the emulator fallback branches of xaspack/xpetite | **Complete** except: InstallSimple + ASPack/Petite emulator branches → **Blocked** (same XEmulator condition as item 4) | — |
| 10 | InfoDB storage format (ADR 0037) | Sidecar JSON `<file>.diec.json` (Phase 19) | SQLite InfoDB | **Permanent** product difference (functionally delivered; no SQLite dependency) | — |
| 11 | TLSH (ADR 0039) | SSDeep implemented clean-room (Phase 38, ppdeep oracle); TLSH not implemented | Pin baseline has neither (XHashWidget `291e3ef6` lacks both) | **Conditional** | A maintained pure-Rust TLSH implementation or an in-tree port with an independent oracle |
| 12 | Vendored rule DB vs upstream submodule drift | Vendored `db/`/`db_extra/` snapshot; 10 rules still call upstream-removed `PE.isNET` (alias added to keep them working) | Upstream `db` submodule at a newer pin | **Conditional** maintenance task | Re-sync vendored DB to the pinned submodule SHA, then remove the `PE.isNET` compat alias |

### Scheduled phases (Phase 45–47)

- **Phase 45**: i18n terminology-anchored bulk drafts + validation
  tooling (item 3).
- **Phase 46**: NFD residual handlers (item 8) — **DONE 2026-10-12**:
  audit showed only `handle_Microsoftoffice`/`handle_OpenOffice` emit
  records (ported); `handle_PolyMorph`, `handle_Metainfos`,
  `handle_JAR`, `handle_IPA` and ZIP `handle_FixDetects` are
  comment-only no-ops upstream; `handle_AnslymPacker` is commented-out
  dead code. Oracle-verified over 10 synthetic ZIP fixtures; NFD
  differential 332 files / 0 diffs.
- **Phase 47**: RNC old-variant / encrypted-stream corpus generator
  or hash-manifest sample acquisition (item 6).

Each phase follows the established acceptance protocol: independent
upstream oracle, negative/fail-closed tests, regression tests,
`cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace
--all-features`, NFD differential where applicable. Qt remains confined
to `tools/` oracle harnesses — never a Rust crate dependency.

### Conditional phases (Phase 48–49)

- **Phase 48**: Tauri auto-update (item 5) — requires the release/
  signing infrastructure decision in ADR 0019's implementation plan.
- **Phase 49**: Tauri-native theme set derived from XStyles (item 2) —
  requires theme demand; XStyles pin `948dd85` must be fetched on
  demand since the submodule is not checked out.

Recorded with triggers so they are not silently dropped; they produce
no code until the prerequisite is met.

## Consequences

- `COMPATIBILITY.md` statuses must use the taxonomy above; "deferred"
  without a trigger or phase number is no longer an acceptable status.
- Items 1, 2, 7, 10 are closed decisions — listed so they are not
  re-litigated.
- Item 4 stays blocked: no half-port of `xinstallsimple.cpp` without
  the emulator source, and no fabricated oracle output.
- Item 12 is a small housekeeping task folded into the next
  rules-touching phase rather than its own phase.

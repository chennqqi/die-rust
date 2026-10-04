# ADR 0042: Intentional Deviation Governance and Conditional Phases

**Date**: 2026-10-12
**Status**: Accepted

## Context

After Phases 41–44 eliminated all remaining schedulable alignment
gaps, the
delta between die-rust and the pinned upstream baseline consists
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
| 1 | Archive safety bounds (ADR 0030) | `ArchiveLimits` struct (member/total/ratio/members/names/string/depth), fail-closed; **defaults unchanged**, host-tunable via `ScanFlags::archive_limits`, CLI `--archive-max-*`, server `ScanFlagsRequest.archive_limits`, GUI settings | No size/ratio limits; member-count and loop caps only | **Permanent** safe-default policy, now host-configurable (delivered 2026-10-12) | Tuning is per-scan/host opt-in; compiled-in defaults remain the safe values |
| 2 | XStyles theme ecosystem | CSS-variable themes: light/dark/system + 6 XStyles-derived palettes + custom overrides | Qt QSS style sheets (XStyles pin `948dd85`) | **Permanent** platform difference; Tauri-native theme set delivered → Phase 49 ✅ | Delivered 2026-10-12: representative palettes only, not QSS-selector equivalence |
| 3 | i18n coverage (ADR 0038) | 5 validated locales × 269 keys (en, zh-CN, ru, de, fr) | 22 Qt `.ts` catalogs + 24 XTranslation `.po` terminology dictionaries | **Scheduled** → Phase 45 (terminology-anchored drafts + validation tooling) | — |
| 4 | InstallSimple static unpacker | Not implemented | `xinstallsimple.cpp` wholly inside `#ifdef USE_XEMULATOR`; XEmulator is a horsicq source library (not an app) referenced as sibling checkout, absent from pin | **DONE** → Phase 50 | XEmulator pin `655e6da` at `dep/XEmulator` (tools-only); bounded x86 core (491/491 oracle diff) + full `xinstallsimple.cpp` port; 6 real-world samples verified — all `init_unpack:false` identically on both sides (upstream lacks these stub variants too); emulator-success path remains synthetic-verified |
| 5 | Tauri auto-update (ADR 0019) | Implemented (`tauri-plugin-updater` + production minisign keypair) | Upstream XUpdate/XOnlineTools unchecked-out Qt components; not on the diec console path | **DONE** — production signing pipeline wired in `release.yml` (preflight secret/pubkey guard → signed updater artifacts → generated `latest.json`); private key in GitHub secret under maintainer control | Dev fixture keys in `corpus/updater` must never sign releases (preflight enforces) |
| 6 | RNC old-variant / encrypted-stream corpora | Generators emit oracle-accepted old-variant and locked streams (Phase 47) | Same code path; upstream also lacks bundled samples | **DONE** → Phase 47 | — |
| 7 | Windows shell context menu | `add_context_menu`/`remove_context_menu`/`get_context_menu_status`, Windows registry only | `XOptions::registerContext` is `#ifdef Q_OS_WIN` — Windows-only upstream | **Parity** (was misclassified as a gap). No action. | If Linux/macOS shell integration is ever requested it is a new product feature, not a parity item |
| 8 | NFD/SpecAbstract remaining scope (ADR 0035) | All `getInfo` drivers and nearly all `handle_*` chains ported (Phases 21–23). Residual: `handle_PolyMorph` (nfd_pe.cpp:8283 call site) and ZIP-family member handlers `handle_Metainfos`/`handle_Microsoftoffice`/`handle_OpenOffice`/`handle_JAR`/`handle_IPA` (`promote.rs` "Phase 23.C pending"). `handle_AnslymPacker` is commented-out dead code upstream — parity, not a gap | Full SpecAbstract (pinned `5188e04`, checked out) | **Scheduled** → Phase 46 | — |
| 9 | XStaticUnpacker packers (ADR 0036) | All non-emulator modules ported with oracle-verified parity: UPX (Phase 20), MEW/Petite/yoda/ASPack/NsPack (Phases 26–27), AutoIt/EnigmaVB/BoxedApp (Phase 28) | 10 modules; XEmulator needed only by xinstallsimple and the emulator fallback branches of xaspack/xpetite | **Complete** — InstallSimple + ASPack/Petite emulator branches delivered → Phase 50 ✅ | — |
| 10 | InfoDB storage format (ADR 0037) | Sidecar JSON `<file>.diec.json` (Phase 19) | SQLite InfoDB | **Permanent** product difference (functionally delivered; no SQLite dependency) | — |
| 11 | TLSH (ADR 0039) | ✅ `tlsh2` pure-Rust port since Phase 29; reference-impl oracle vectors added 2026-10-12 (trendmicro/tlsh `ebdec8fd`, 7 digests + 3 fail-closed cases) | Pin baseline has neither (XHashWidget `291e3ef6` lacks both) | **DONE** | — |
| 12 | Vendored rule DB vs upstream submodule drift | ✅ Vendored tree verified against `rule-source-manifest.json` (commit `8925358d`, 4,698 files, 0 hash mismatches) and byte-identical to the pinned submodule checkout; no rule calls `PE.isNET()` — alias removed 2026-10-12 | Upstream `db` submodule at pin `8925358d` | **DONE** | Re-sync future vendor updates to the submodule pin via `xtask sync-rules` + manifest regen; re-verify zero `PE.isNET()` callers before any alias change |

### Scheduled phases (Phase 45–47, Phase 50)

- **Phase 50** ✅: XEmulator x86-core subset port + InstallSimple +
  ASPack 2.11/Petite emulator branches (items 4, 9) — scheduled
  2026-10-12 after confirming XEmulator is a source library in the
  horsicq component family, not a standalone app. Delivered:
  (a) XEmulator pinned at `655e6da` under
  `upstream/DIE-engine/dep/XEmulator`; tools-only Qt oracle
  `tools/xemulator-oracle` (micro + unpack modes) drives all three
  call sites; (b) bounded x86 core ported (`decode`/`exec`/`fpu`/
  `mmx`/`memory`/`regs`, mapped-memory only, upstream step caps
  mirrored, fail-closed) — 491/491 oracle instruction cases match;
  `xinstallsimple.cpp` fully ported with shared 100 M step budget,
  allocator trap, strict manifest grammar and record/output bounds;
  the two ASPack 2.11 layout rows (`decrypt_stub_head`) and the
  xpetite embedded-decoder branches wired in; (c) synthetic
  InstallSimple fixture verified end to end against the upstream
  oracle (byte-identical member report), 9 + 5 regression tests.

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
  or hash-manifest sample acquisition (item 6) — **DONE 2026-10-12**:
  `tools/gen_p47_corpus.py` emits RNC1-old / RNC2-old / locked-RNC1-new
  streams (known-key, unique-key GF(2) recovery, and an underdetermined-
  key negative) that the pinned oracle decodes byte-identically; NFD
  differential 337 files / 0 diffs. Real ProPack samples were not needed
  — the generator path was oracle-accepted, so the hash-manifest
  fallback stays dormant.

Each phase follows the established acceptance protocol: independent
upstream oracle, negative/fail-closed tests, regression tests,
`cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace
--all-features`, NFD differential where applicable. Qt remains confined
to `tools/` oracle harnesses — never a Rust crate dependency.

### Conditional phases (Phase 48–49) — delivered 2026-10-12

- **Phase 48 ✅**: Tauri auto-update (item 5) — `tauri-plugin-updater`
  v2.12.0, `updater.rs` IPC commands, settings-page update UI,
  `corpus/updater` dev Ed25519 fixtures, `updater_flow.rs` 5
  integration tests (valid signature, tampered signature, offline
  endpoint, downgrade, version mismatch). Production signing
  key/endpoint/CI pipeline remains a deployment decision (ADR 0019).
- **Phase 49 ✅**: Tauri-native theme set derived from XStyles
  pin `948dd85` (item 2) — six representative palettes as CSS
  variable classes, `custom_theme` whitelist-validated overrides,
  both settings UIs synchronized.

## Consequences

- `COMPATIBILITY.md` statuses must use the taxonomy above; "deferred"
  without a trigger or phase number is no longer an acceptable status.
- Items 1, 2, 7, 10 are closed decisions — listed so they are not
  re-litigated.
- Item 4 was reclassified Blocked → Scheduled (Phase 50, 2026-10-12)
  after verifying XEmulator is a horsicq library component — the same
  category as the other pinned `dep/` sources — not a standalone app:
  the needed subset is the x86 core only (~6.9 kLOC: `xemux86`,
  `xemumemorymanager`, `xemuregisters`), the OS/syscall layers are
  unused by XStaticUnpacker, and upstream call sites already bound
  execution (`pnStepsRemaining`, `IS_CANCEL_CHECK_STEPS`,
  `STEP_HALT` trap addresses). Still no half-port and no fabricated
  oracle output.
- Item 12 is a small housekeeping task folded into the next
  rules-touching phase rather than its own phase.

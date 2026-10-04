# ADR 0019: Defer GUI Auto-Update to Post-Phase-8

**Date**: 2026-08-06  
**Status**: Accepted — **fully delivered**: code in Phase 48 (2026-10-12),
production signing pipeline wired 2026-10-12 (user decision: auto-update
enabled, private key held in GitHub secret under maintainer control).

## Revision (2026-10-12, production pipeline)

The deployment prerequisites listed below are now satisfied:

1. **Production Ed25519 keypair** — generated with
   `tauri signer generate` (`@tauri-apps/cli` v2), stored outside the
   repo on the maintainer's machine; the base64-encoded secret file goes
   into GitHub secret `TAURI_SIGNING_PRIVATE_KEY`
   (password: `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, empty). The public
   key is embedded in `plugins.updater.pubkey`.
2. **Production endpoint** — `plugins.updater.endpoints` points at
   `releases/latest/download/latest.json` on this repository.
3. **CI signing pipeline** — `release.yml` now:
   - `preflight` job: fails fast if `TAURI_SIGNING_PRIVATE_KEY` is unset
     or `tauri.conf.json` still carries the dev fixture pubkey
   - `build-gui`: `cargo tauri build` runs with the signing env so the
     bundler emits updater artifacts (`*.app.tar.gz`,
     `*.AppImage.tar.gz`, NSIS `*-setup.exe`/`*.nsis.zip`) + `.sig`
     sidecars, collected raw as `die-gui-updater-<os>` artifacts
   - `release`: `tools/updater/gen_latest_json.py` builds `latest.json`
     (signature = base64 of the entire `.sig` file text, the format
     `tauri-plugin-updater` parses) and uploads it as a release asset
   - `bundle.createUpdaterArtifacts: true` set in `tauri.conf.json`

The `corpus/updater` dev keypair remains for tests only — the preflight
guard hard-fails if the dev pubkey ever lands in `tauri.conf.json`.

## Revision (2026-10-12, Phase 48)

The code-side plan below was executed: `tauri-plugin-updater`
v2.12.0, `plugins.updater` config, `src/updater.rs` IPC commands,
settings-page update UI, and `tests/updater_flow.rs` covering
signature verification, tampered signatures, offline endpoints,
downgrade rejection, and version-mismatch rejection.

The configured public key and `corpus/updater` keypair are
**development fixtures only** — they must never sign a release.
Before any release build enables updates, the deployment must supply:

1. A production Ed25519 keypair (private key in CI secret storage,
   never committed)
2. A production update-manifest endpoint over HTTPS
3. A CI step that signs release bundles and publishes manifests

Until then the feature is verified code awaiting infrastructure —
exactly the split this ADR anticipated.

## Context

Phase 8 ROADMAP lists "自动更新：tauri-plugin-updater，GitHub Releases 签名更新"
under 7B advanced features. The `tauri-plugin-updater` requires:

1. A signing key pair (private key for CI, public key embedded in app)
2. GitHub Releases integration with update manifest JSON
3. A `tauri-plugin-updater` dependency and IPC command wiring
4. CI workflow changes to sign and upload update bundles

The Phase 8 exit condition states "7C 扩展功能可 deferred 到后续 Phase".
Auto-update is a distribution/operations feature, not a core GUI functionality
feature. It does not affect scanning, detection, or user interaction with the
application.

## Decision

Defer `tauri-plugin-updater` auto-update to a post-Phase-8 improvement.

**Rationale**:
- Auto-update is a release infrastructure concern, not a GUI feature
- It requires signing key management which is an operational decision
- Users can manually download new versions from GitHub Releases
- Phase 8 exit condition explicitly allows deferring non-core features
- Implementing it now would block Phase 8 closure on an operational dependency

## Consequences

- Users must manually check for updates via GitHub Releases
- The `tauri-plugin-updater` integration will be implemented in a future
  phase when signing infrastructure is established
- This ADR serves as the formal deferral record required by the ROADMAP

## Implementation Plan (Future)

1. Generate Ed25519 signing key pair
2. Add `tauri-plugin-updater` dependency
3. Configure updater in `tauri.conf.json` with public key
4. Add "Check for Updates" menu item
5. Update CI to sign bundles and generate update manifests
6. Test update flow on all three platforms

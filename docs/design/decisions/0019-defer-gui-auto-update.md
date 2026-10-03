# ADR 0019: Defer GUI Auto-Update to Post-Phase-8

**Date**: 2026-08-06  
**Status**: Accepted — **code delivered in Phase 48 (2026-10-12)**;
production release infrastructure remains a deployment decision.

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

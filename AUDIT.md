# Supply Chain Audit

This document records the supply chain security audit for diec-rust.

Last updated: 2026-08-15

## Dependency Policy

1. **License compatibility**: All dependencies must use permissive licenses
   (MIT, Apache-2.0, BSD, Zlib, Unicode-3.0, BSL-1.0). No GPL/AGPL/copyleft.
2. **Minimum release age**: New dependencies must be published at least 7
   days before adoption. Newly published versions are not vetted.
3. **No floating ranges**: Dependencies use pinned versions in Cargo.lock.
   No `latest`, `*`, or unbounded `>=` ranges.
4. **Audit trail**: All dependencies are listed in `NOTICES.md` with
   license and purpose.

## Audit Checklist

- [x] `cargo license` output reviewed — all permissive licenses
- [x] No GPL/AGPL/copyleft licenses in dependency tree
- [x] All direct dependencies identified with purpose
- [x] QuickJS (via rquickjs-sys) is MIT licensed
- [x] Upstream DIE-engine is MIT licensed
- [x] Corpus is project-generated (no third-party bytes)
- [x] No secrets, API keys, or credentials in repository
- [x] CI uses pinned action major versions (e.g. `actions/checkout@v5`)
- [x] `Cargo.lock` is committed and verified with `--locked`

## CI Security

- GitHub Actions are pinned to major-version tags (e.g.
  `actions/checkout@v5`, `actions/upload-artifact@v5`,
  `actions/download-artifact@v5`). They are NOT pinned to full commit
  SHAs; this is a tracked deviation from the original "SHA-pinned"
  statement and should be revisited if stricter pinning is required.
- `persist-credentials: false` on all checkout steps
- `permissions: contents: read` (minimal scope; `contents: write` only
  on the release workflow's release-creation job)
- Concurrency group prevents redundant CI runs

## Upstream Source Security

- `upstream/Detect-It-Easy` is a vendored subtree (squashed merge at
  `e0bcca000` on 2026-07-25), NOT a git submodule — there is no
  `.gitmodules` entry. The upstream content is pinned to upstream
  commit `c2c17dfa5`.
- Rules are loaded verbatim; no modifications to upstream files.

## Known Risks

1. **rquickjs-sys builds QuickJS from source**: The QuickJS C source is
   bundled in the crate and compiled via `cc`. This is inherent to the
   rule execution approach. Risk is mitigated by:
   - Using the published `rquickjs` crate (not vendored QuickJS)
   - QuickJS is MIT licensed and widely used
   - The build is reproducible with `--locked`

2. **JavaScript runtime in scan path**: Rule execution involves a JS VM.
   Risk is mitigated by:
   - All inputs are untrusted and validated before reaching the VM
   - The VM has fuel/timeout limits (see scan options)
   - Panic containment at the FFI boundary

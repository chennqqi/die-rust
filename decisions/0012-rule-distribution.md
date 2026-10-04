# ADR 0012: Rule Database Distribution Strategy

Date: 2026-08-01

## Status

Accepted

## Context

diec-rust requires the upstream Detect-It-Easy rule database to perform
detection. The database is 2.7 MB containing 2037 `.sg` rule files,
licensed under MIT (same as diec-rust).

Two distribution options were considered:

1. **Bundle in release artifacts**: Include the rule database in
   release tarballs/zip files.
2. **Download from official repository**: Fetch rules at runtime or
   build time from the upstream GitHub repository.

## Decision

**Use a hybrid approach: bundle a pinned snapshot in release artifacts,
with optional override via `--extradb`/`--customdb`.**

### Rationale

- **Reproducibility**: Bundling a pinned snapshot ensures that every
  user gets identical detection results. Downloading "latest" would
  make results non-deterministic across versions.
- **Offline operation**: Security analysts often work in air-gapped
  environments. Bundled rules work without network access.
- **Small size**: 2.7 MB is negligible compared to the binary itself.
  No need for lazy download optimization.
- **License compatibility**: MIT license allows redistribution.
- **Upstream stability**: The upstream repo is actively maintained.
  A pinned snapshot protects against breaking changes.
- **Override capability**: `--extradb` and `--customdb` flags already
  exist for users who want to use a different or updated database.

### Implementation

1. Release artifacts include a `db/` directory containing the pinned
   rule snapshot (from `upstream/Detect-It-Easy/db` at the fixed
   commit).
2. The CLI searches for the database in this order:
   a. `--database` flag (explicit path)
   b. `DIE_DB_PATH` environment variable
   c. `db/` directory adjacent to the executable
   d. System-wide install path (e.g., `/usr/share/die/db`)
   e. Fallback: bundled `db/` in the release archive
3. Users can update rules by:
   - Downloading a newer release (recommended)
   - Using `--customdb` to point at a self-managed database
   - Setting `DIE_DB_PATH` to override the default

### Alternatives Considered

**Download at runtime**: Rejected because:
- Adds network dependency for a security tool
- Non-deterministic results across users/versions
- Privacy concerns (tool "calling home")
- More complex error handling

**Download at install time**: Rejected because:
- Still requires network during installation
- Version drift between install time and run time
- Harder to audit and reproduce

## Consequences

- Release artifacts are ~2.7 MB larger
- Users get deterministic results out of the box
- Rule updates require a new release (acceptable for a security tool)
- Custom database override is available for advanced users

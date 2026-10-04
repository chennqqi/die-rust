# Boa rule runtime spike

This is an isolated Phase 0 research program, not part of the future
`die-rust` Cargo workspace or public API.

It evaluates whether a pinned pure-Rust Boa release can parse the fixed
Detect-It-Easy rule corpus and support the host/runtime semantics required by
the upstream Qt JavaScript environment. Findings belong in
`docs/research/rule-runtime-spike.md`; this directory only contains the
reproducible experiment.

The spike must not modify or normalize any upstream rule bytes.

# Testing Discipline Rules

> These rules are mandatory. Violating them is a critical process error,
> regardless of whether the code compiles or tests pass.

## Rule 1: "Tests pass" ≠ "Feature correct"

`cargo test` passing only means **already-written tests** did not fail.
It does NOT mean the feature works correctly. Before claiming a feature
is correct or a bug is fixed, you MUST verify that the test suite
actually covers the changed behavior.

### Required checks before claiming "fixed" or "correct"

1. **Coverage check**: Does at least one test exercise the specific code
   path you changed? If not, write one first (TDD: write failing test →
   fix → test passes).

2. **Edge case check**: Does the test cover boundary inputs (empty,
   truncated, malformed, maximum size, zero values)?

3. **Regression check**: If you fixed a bug, is there a test that would
   fail if the bug regressed?

4. **Never claim a feature is correct based solely on existing tests
   passing if those tests were not designed to cover that feature.**

## Rule 2: No "it works" without evidence

When reporting results, distinguish between:
- **Observed**: "diec.exe produced 3 detections" — this is an observation
- **Verified**: "diec.exe produced the same 3 detections as upstream DIE
  commit abc123" — this is verified evidence

Only **verified** evidence supports claims of correctness or compatibility.

### Forbidden without evidence

- "1:1 compatible with upstream" — requires differential test output
- "All PE files detected correctly" — requires test matrix covering
  PE32/PE64, with/without imports, with/without exports, various sizes
- "Performance is good" — requires benchmark numbers against a threshold
- "No regressions" — requires running the full test suite AND confirming
  the test suite covers the changed area

### Required for correctness claims

- Differential testing: run both die-rust and upstream DIE on the same
  files, compare outputs
- Test matrix: cover all relevant file types, sizes, and feature combinations
- Performance threshold: define explicit thresholds (e.g., "<10MB files
  must scan in <2s") and assert them in tests

## Rule 3: Test-first for bug fixes (TDD)

When fixing a bug:

1. **Write a test that reproduces the bug** — it must FAIL before the fix
2. **Fix the code** — the test now passes
3. **Check sibling features** — if the bug is in PE import parsing,
   check PE export parsing, ELF import parsing, etc. for similar bugs
4. **Add regression test** — the test from step 1 stays as a regression guard

Never skip step 1. "I can see the bug in the code, I'll just fix it" is
not acceptable — without a reproducing test, you cannot verify the fix
is complete or prevent regression.

## Rule 4: Audit test suite before trusting it

Before relying on "all tests pass" as evidence of correctness, audit
the test suite's coverage of the area you changed:

### Questions to ask

- Does any test actually execute the code path I changed?
- Does any test use realistic input data (not just minimal/dummy data)?
- Does any test verify the output matches expected values (not just
  "no crash" or "no error")?
- Does any test cover performance (not just correctness)?
- Are there test helpers that silently bypass the feature being tested
  (e.g., DummyHost returning empty values, skipping _init scripts)?

### Red flags

- Tests use stub/mock hosts that return empty/zero for the methods
  being tested
- Tests skip initialization scripts that are required for the feature
- Test corpus contains only minimal synthetic files (e.g., 512-byte PE
  with no import/export tables)
- Tests only check "no crash" or "no panic" without verifying output
- Performance tests have overly generous thresholds (e.g., 5s for
  files that should complete in <1s)

If any red flag is found, fix the test suite BEFORE claiming the
feature is correct.

## Rule 5: One bug often means a class of bugs

When you find and fix a bug, immediately check for similar bugs in
related code:

- If PE import parsing has a precision bug → check PE export parsing,
  ELF parsing, MACH parsing
- If `findSignature` 3-arg form ignores the size parameter → check
  `isSignaturePresent`, `fSig`, all other functions with similar
  signatures
- If one host API method returns wrong values → audit all host API
  methods that use similar logic

Document the audit result. "I checked X, Y, Z and found no similar
issues" is valuable. "I fixed X and assumed Y, Z are fine" is not.

## Rule 6: Never claim "ready for release" without explicit gate review

"Ready for release" requires ALL of the following:

1. **Differential testing**: die-rust output matches upstream DIE output
   on a representative corpus (at least 20 files across all supported
   formats)
2. **Test coverage audit**: every implemented feature has at least one
   test that verifies its correctness (not just "no crash")
3. **Performance benchmark**: all file types and size ranges meet
   defined thresholds, with regression tests
4. **Edge case testing**: malformed/truncated/large/empty inputs tested
   for no-crash and no-hang
5. **User confirmation**: the user has reviewed and confirmed the
   release readiness

Never declare "ready for release" based solely on "all tests pass"
and "it looks like it works". The absence of known bugs is not the
presence of correctness.

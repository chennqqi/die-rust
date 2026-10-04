# Claim and Conclusion Discipline

> These rules constrain what conclusions you can draw and what claims
> you can make. Overclaiming is a process violation.

## Rule 1: Distinguish observation from verification

Every statement about system behavior must be labeled:

- **"Observed"** = I ran something and saw an output. This is raw data.
  Example: "Observed: diec.exe scan produced 3 detections in 0.5s"

- **"Verified"** = I compared against a known-correct reference.
  Example: "Verified: diec.exe output matches upstream DIE commit abc123
  for all 24 corpus files"

Only **verified** statements can support conclusions like "correct",
"compatible", "fixed", "no regression".

## Rule 2: Forbidden claims without required evidence

| Claim | Required evidence |
|-------|-------------------|
| "1:1 compatible with upstream" | Differential test output comparing die-rust vs upstream DIE on ≥20 files |
| "Feature X works correctly" | At least 1 test that verifies X's output against expected values (not just "no crash") |
| "Bug X is fixed" | Test that reproduces X, fails before fix, passes after fix |
| "No regressions" | Full test suite passes AND test suite covers the changed area |
| "Performance is good/optimized" | Benchmark numbers against defined thresholds, with regression test |
| "Ready for release" | All 5 gates in testing-discipline.md Rule 6 passed + user confirmation |
| "All file types supported" | Test matrix covering each claimed file type with real samples |

Making any of these claims without the required evidence is a violation.

## Rule 3: Required hedging when evidence is incomplete

When evidence is incomplete, use hedged language:

- ❌ "PE detection is correct" → ✅ "PE detection produces output for
  tested files; correctness vs upstream not yet verified"
- ❌ "Performance issue is resolved" → ✅ "Tested files complete within
  2s; untested file types/sizes not yet benchmarked"
- ❌ "No regressions" → ✅ "All 430 tests pass; test suite coverage of
  changed area has not been audited"

## Rule 4: Report what was NOT tested

Every status report must include a "Not tested" section listing:

- File types/formats not tested
- Feature combinations not tested
- Input size ranges not tested
- Edge cases not tested
- Performance scenarios not tested

Example:
```
## Not tested
- ELF/MACH rule end-to-end execution (only Binary rules tested)
- PE64 import table parsing (only PE32 tested)
- Files >10MB (only files <2MB tested)
- Differential comparison with upstream DIE output
```

Omitting "what was not tested" gives a false sense of completeness.

## Rule 5: Sibling audit after every bug fix

After fixing a bug, the report MUST include:

```
## Sibling audit
- Bug was in: PE import thunk parsing (f64 precision)
- Checked PE export parsing: [no similar issue found / similar bug found and fixed]
- Checked ELF import parsing: [not applicable / similar bug found and fixed]
- Checked MACH parsing: [not applicable / similar bug found and fixed]
```

Never fix one bug and silently assume siblings are fine.

## Rule 6: Test suite audit before "all tests pass" claims

Before reporting "all tests pass" as evidence of correctness, include:

```
## Test suite coverage audit
- Changed area: PE import/export table parsing
- Tests covering this area: pe_table_parsing.rs (10 tests), batch_load_pe.rs (2 tests)
- Coverage gaps: PE64 import thunks not tested, ordinal imports not tested
- Red flags found: [none / list]
```

If coverage gaps or red flags exist, "all tests pass" does NOT support
a correctness claim for the changed area.

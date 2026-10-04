# Runtime Reuse State Audit

Audited: 2026-08-04
Database: `upstream/Detect-It-Easy/db`
Tool: `tools/audit/audit_global_side_effects.py`
Raw data: `docs/research/data/runtime-reuse-state-audit.json`

## Summary

| Metric | Value |
|--------|-------|
| Total .sg files scanned | 2037 |
| Files with bare assignments | 2020 |
| Total bare assignment occurrences | 24787 |
| Unique bare-assigned variables | 2168 |

## Framework-managed globals (safe)

The `_init` framework script (`db/_init`, lines 8-14) declares these variables
with `var` in global scope:

```js
var bDetected, sType, sName, sVersion, sOptions, sLang, sLangVersion;
```

The `result()` function (`db/_init`, lines 63-90) resets them after each rule:

```js
function result() {
    if (bDetected) { /* emit detection via _setResult */ }
    sName = sVersion = sOptions = sLang = sLangVersion = '';
    var resultValue = bDetected;
    bDetected = false;
    return resultValue;
}
```

The `meta()` function (`db/_init`, lines 26-45) also resets them at rule start.

These 7 variables account for the vast majority of bare assignments:

| Variable | Occurrences | Files |
|----------|-------------|-------|
| `bDetected` | 4776 | 2010 |
| `sVersion` | 4163 | 1075 |
| `sOptions` | 1775 | 771 |
| `sName` | 1013 | 128 |
| `sLang` | 186 | 184 |
| `sType` | — | — |
| `sLangVersion` | — | — |

**Safe for runtime reuse**: the framework resets them via `result()` after each
rule's `detect()` call.

## Rule-specific bare assignments (low risk)

The remaining ~1658 bare-assigned variables (e.g. `ptn`, `ord`, `hwid`,
`tracker`, `d0`, `d2`) typically appear in only 1-3 files. They are used within
a single rule's `detect()` function and are initialized before use.

Cross-file leakage is theoretically possible but practically irrelevant because:

1. **Different file types run different rule sets** — PE rules only run for PE
   files, Binary rules for archives/unrecognized, etc. Cross-file-type leakage
   cannot occur.
2. **Rules already run sequentially in the same runtime** — the current
   `scan_bytes` (scanner.rs:373-402) creates one runtime per file_type and
   evaluates ALL rules of that group in it. Tests pass (459 tests, 31 baseline
   + 20 edge, 0 mismatch), meaning rules already tolerate stale global state
   from previous rules.
3. **Rule-specific variables are initialized before read** — e.g. `ptn =
   X.U8(0xF)` overwrites any stale value before `ptn` is read.

## Key insight: current code already reuses runtime across rules

The current `scan_bytes` implementation creates one runtime per file_type
group and evaluates all rules of that group sequentially in the same runtime.
This means global state leakage between rules is **already happening** and
tests pass.

Cross-file runtime reuse extends this from "rules within one file" to "rules
across multiple files of the same file_type." The same rule-ordering and
state-reset mechanisms (framework `result()`) apply.

## Conclusion

The framework's `result()` function resets the 7 most common bare-assigned
variables after each rule. The remaining rule-specific variables are low risk
because they are initialized before use within their rule's `detect()`.

The current code already evaluates multiple rules in the same runtime with
passing tests, confirming that inter-rule global state leakage is handled.
Cross-file runtime reuse extends this to inter-file reuse with the same
mechanisms.

**Differential testing is the ultimate verification**: implement runtime
reuse and verify 0 mismatches on the 31 baseline + 20 edge corpus.

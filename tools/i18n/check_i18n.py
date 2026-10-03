#!/usr/bin/env python3
"""i18n catalog validator — Phase 45 gate.

Checks every locale JSON under frontend/src/i18n/locales/:
  1. Key parity: identical dotted-path set as en.json.
  2. Placeholder parity: every {{var}} in the en value appears in the
     locale value (no dropped/renamed interpolation variables).
  3. Format-specifier sanity: %-style specifiers preserved verbatim.
  4. Draft accounting: values still equal to English must be listed in
     <lang>.draft.json, and draft lists must not contain translated
     entries (stale draft marks fail the check).

Exits non-zero on any violation. Mirrors what the Rust-side
tests/i18n_parity.rs asserts for the cargo gate.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LOCALES = REPO / "crates/die-gui/frontend/src/i18n/locales"

VAR_RE = re.compile(r"\{\{\s*(\w+)\s*\}\}")
FMT_RE = re.compile(r"%[-+0-9.]*[sdifuxX%]")


def flatten(obj: dict, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in obj.items():
        p = k if not prefix else f"{prefix}.{k}"
        if isinstance(v, dict):
            out.update(flatten(v, p))
        else:
            out[p] = v
    return out


def main() -> int:
    en = flatten(json.loads((LOCALES / "en.json").read_text("utf-8")))
    failures: list[str] = []

    catalogs = sorted(p for p in LOCALES.glob("*.json") if not p.name.endswith(".draft.json"))
    for cat in catalogs:
        code = cat.stem
        flat = flatten(json.loads(cat.read_text("utf-8")))
        missing = set(en) - set(flat)
        extra = set(flat) - set(en)
        if missing or extra:
            failures.append(
                f"{code}: key mismatch missing={sorted(missing)[:5]} extra={sorted(extra)[:5]}")
        for path, enval in en.items():
            val = flat.get(path)
            if val is None:
                continue
            env, lv = set(VAR_RE.findall(enval)), set(VAR_RE.findall(val))
            if env != lv:
                failures.append(f"{code}:{path}: placeholder mismatch {env} vs {lv}")
            enf, lf = FMT_RE.findall(enval), FMT_RE.findall(val)
            if enf != lf:
                failures.append(f"{code}:{path}: format specifiers {enf} vs {lf}")

        draft_file = cat.with_suffix(".draft.json")
        untranslated = {p for p, v in flat.items() if en.get(p) == v}
        if draft_file.exists():
            manifest = json.loads(draft_file.read_text("utf-8"))
            drafts = set(manifest.get("drafts", []))
            same = set(manifest.get("same", []))
            stale = drafts - untranslated
            unmarked = untranslated - drafts - same
            translated_in_same = same - untranslated
            if stale:
                failures.append(f"{code}: {len(stale)} stale draft marks (translated but marked), e.g. {sorted(stale)[:3]}")
            if unmarked:
                failures.append(f"{code}: {len(unmarked)} unmarked untranslated keys, e.g. {sorted(unmarked)[:3]}")
            if translated_in_same:
                failures.append(f"{code}: {len(translated_in_same)} keys in `same` but not English-identical, e.g. {sorted(translated_in_same)[:3]}")
        elif untranslated and code != "en":
            failures.append(f"{code}: {len(untranslated)} untranslated keys without draft manifest")

    if failures:
        for f in failures:
            print(f"FAIL {f}")
        return 1
    print(f"i18n check OK: {len(catalogs)} catalogs × {len(en)} keys")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""NFD differential harness: upstream SpecAbstract oracle vs diec-nfd.

Runs `nfd-oracle` (Qt build of pinned upstream SpecAbstract) and
`diec --nfd --json` over the same files, normalizes both sides to
(type, name, version, info) tuples, and reports the three diff classes
from AGENTS.md lesson 11: missing (upstream-only), extra (ours-only),
and version mismatches.

Usage:
    tools/nfd_diff.py <file-or-dir> [...]
    ORACLE=tools/nfd-oracle/build/nfd-oracle DIEC=./diec tools/nfd_diff.py corpus/
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORACLE = os.environ.get("ORACLE", str(ROOT / "tools/nfd-oracle/build/nfd-oracle"))
ORACLE_LIB = str(ROOT / "tools/nfd-oracle/rpms/usr/lib64")
DIEC = os.environ.get("DIEC", str(ROOT / "target/debug/diec"))


def norm_type(t: str) -> str:
    return t.strip().lower().replace(" ", "")


def oracle_records(path: str) -> list[tuple[str, str, str, str]]:
    env = dict(os.environ, LD_LIBRARY_PATH=ORACLE_LIB)
    out = subprocess.run([ORACLE, path], capture_output=True, text=True, env=env)
    recs = []
    for f in json.loads(out.stdout or "[]"):
        for r in f["records"]:
            name = r.get("sname") or r["name"]
            rtype = r.get("stype") or r["type"]
            recs.append((norm_type(rtype), name, r["version"], r["info"]))
    return recs


def rust_records(path: str) -> list[tuple[str, str, str, str]]:
    out = subprocess.run(
        [
            DIEC,
            "--nfd",
            "--deepscan",
            "--heuristicscan",
            "--verbose",
            "--archives",
            "--recursivescan",
            "--json",
            path,
        ],
        capture_output=True,
        text=True,
    )
    recs = []
    payload = json.loads(out.stdout or "{}")
    if isinstance(payload, dict):
        payload = [payload]
    for f in payload:
        for r in f.get("detections", []):
            if r.get("engine") != "nfd":
                continue
            recs.append(
                (
                    norm_type(r["type"]),
                    r["name"],
                    r.get("version", ""),
                    r.get("options", ""),
                )
            )
    return recs


def diff(path: str) -> int:
    oracle = oracle_records(path)
    rust = rust_records(path)
    oset = {(t, n, v, i) for t, n, v, i in oracle}
    rset = {(t, n, v, i) for t, n, v, i in rust}
    missing = oset - rset
    extra = rset - oset
    # Name-keyed version diffs when name+type match but payload differs.
    o_by_key = {(t, n): (v, i) for t, n, v, i in oracle}
    r_by_key = {(t, n): (v, i) for t, n, v, i in rust}
    verdiff = [
        (t, n, r_by_key[(t, n)], o_by_key[(t, n)])
        for (t, n) in o_by_key.keys() & r_by_key.keys()
        if (t, n, *r_by_key[(t, n)]) not in oset
        and (t, n, *o_by_key[(t, n)]) not in rset
    ]
    if not (missing or extra or verdiff):
        return 0
    print(f"== {path}")
    for t, n, v, i in sorted(missing):
        print(f"  MISS   {t}: {n} {v} [{i}]")
    for t, n, v, i in sorted(extra):
        print(f"  EXTRA  {t}: {n} {v} [{i}]")
    for t, n, (rv, ri), (ov, oi) in sorted(verdiff):
        print(f"  VERDIF {t}: {n}  rust={rv!r}[{ri}] oracle={ov!r}[{oi}]")
    return 1


def main() -> int:
    paths: list[str] = []
    for arg in sys.argv[1:]:
        p = Path(arg)
        if p.is_dir():
            paths.extend(str(c) for c in sorted(p.rglob("*")) if c.is_file())
        else:
            paths.append(str(p))
    bad = 0
    for p in paths:
        try:
            bad += diff(p)
        except Exception as e:  # noqa: BLE001 - report and continue
            print(f"== {p}\n  ERROR {e}")
            bad += 1
    print(f"-- {len(paths)} files, {bad} with diffs")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

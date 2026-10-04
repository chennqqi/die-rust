#!/usr/bin/env python3
"""XEmulator micro-differential: upstream xemulator-oracle vs diec-engine.

Runs `xemulator-oracle micro <hex>` (Qt build of pinned upstream
XEmulator@655e6da) and `emu_micro` (cargo example driving the Rust port)
over the shared case list, then compares the JSON reports field-by-field
including per-region FNV-1a memory checksums.

Usage:
    python3 tools/emu_diff.py [--steps N] [--cases FILE]
        [--oracle PATH] [--rust PATH] [--snapshot DIR] [-v]

`--snapshot DIR` writes one `<idx>.json` oracle dump per case for
offline replay by crates/diec-engine/tests/x86_oracle.rs.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_CASES = REPO / "corpus" / "xemulator" / "cases.txt"
DEFAULT_ORACLE = REPO / "tools" / "xemulator-oracle" / "build" / "xemulator-oracle"


def load_cases(path: Path) -> list[tuple[int, str, str]]:
    """Return (line_no, hex, comment) triples."""
    cases = []
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        comment = raw.split("#", 1)[1].strip() if "#" in raw else ""
        cases.append((lineno, line, comment))
    return cases


def run_oracle(oracle: Path, hexs: str, steps: int) -> dict | None:
    try:
        proc = subprocess.run(
            [str(oracle), "micro", hexs, str(steps)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def run_rust(rust: Path, hexs: str, steps: int) -> dict | None:
    try:
        proc = subprocess.run(
            [str(rust), hexs, str(steps)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def diff_reports(oracle: dict, rust: dict) -> list[str]:
    """Return human-readable field differences."""
    diffs = []
    for key in sorted(set(oracle) | set(rust)):
        ov, rv = oracle.get(key), rust.get(key)
        if ov == rv:
            continue
        if key in ("regions", "gpr"):
            if len(ov or []) != len(rv or []):
                diffs.append(f"{key}: len oracle={len(ov or [])} rust={len(rv or [])}")
                continue
            for i, (o, r) in enumerate(zip(ov, rv)):
                if o != r:
                    diffs.append(f"{key}[{i}]: oracle={o} rust={r}")
            continue
        diffs.append(f"{key}: oracle={ov!r} rust={rv!r}")
    return diffs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--steps", type=int, default=64)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument(
        "--rust",
        type=Path,
        default=REPO / "target" / "debug" / "examples" / "emu_micro",
    )
    parser.add_argument("--snapshot", type=Path, default=None)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not args.oracle.exists():
        print(f"oracle not found: {args.oracle}", file=sys.stderr)
        return 2
    if not args.rust.exists():
        print(f"rust harness not found: {args.rust}", file=sys.stderr)
        print("build with: cargo build -p diec-engine --example emu_micro", file=sys.stderr)
        return 2

    cases = load_cases(args.cases)
    if args.snapshot:
        args.snapshot.mkdir(parents=True, exist_ok=True)

    matched = 0
    failed = []
    for idx, (lineno, hexs, comment) in enumerate(cases):
        oracle = run_oracle(args.oracle, hexs, args.steps)
        if oracle is None:
            failed.append((lineno, hexs, comment, ["oracle failed"]))
            continue
        if args.snapshot:
            (args.snapshot / f"case_{idx:04d}.json").write_text(
                json.dumps({"line": lineno, "hex": hexs, "comment": comment, "oracle": oracle})
            )
        rust = run_rust(args.rust, hexs, args.steps)
        if rust is None:
            failed.append((lineno, hexs, comment, ["rust failed"]))
            continue
        diffs = diff_reports(oracle, rust)
        if diffs:
            failed.append((lineno, hexs, comment, diffs))
        else:
            matched += 1
            if args.verbose:
                print(f"OK   {lineno:4d} {hexs:<60} {comment}")

    print(f"\n{matched}/{len(cases)} cases match")
    for lineno, hexs, comment, diffs in failed:
        print(f"DIFF {lineno:4d} {hexs}")
        if comment:
            print(f"      # {comment}")
        for d in diffs[:8]:
            print(f"      {d}")
        if len(diffs) > 8:
            print(f"      ... {len(diffs) - 8} more")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

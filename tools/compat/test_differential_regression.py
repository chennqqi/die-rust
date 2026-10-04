#!/usr/bin/env python3
"""Differential regression test: compare current die-rust output against baseline.

This script runs die-rust on the corpus and compares the output against
a previously collected baseline. Any difference in detections or
diagnostics is reported as a regression.

Usage:
    python tools/compat/test_differential_regression.py [--diec PATH] [--baseline FILE]

Exit code: 0 if no regressions, 1 if regressions found.
"""

import argparse
import json
import os
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description="Differential regression test")
    parser.add_argument("--diec", default=None, help="Path to diec executable")
    parser.add_argument("--baseline", default=None, help="Path to baseline JSON file")
    args = parser.parse_args()

    # Find diec
    diec_path = args.diec
    if not diec_path:
        for c in ["target/release/diec", "target/release/diec.exe"]:
            if os.path.isfile(c):
                diec_path = os.path.abspath(c)
                break
    if not diec_path:
        print("ERROR: diec executable not found")
        sys.exit(1)

    # Find baseline
    script_dir = os.path.dirname(os.path.abspath(__file__))
    workspace_root = os.path.dirname(os.path.dirname(script_dir))
    baseline_path = args.baseline or os.path.join(script_dir, "differential-baseline.json")

    if not os.path.isfile(baseline_path):
        print(f"ERROR: baseline file not found: {baseline_path}")
        print("Run collect_differential_baseline.py first to create it.")
        sys.exit(1)

    with open(baseline_path, "r", encoding="utf-8") as f:
        baseline = json.load(f)

    corpus_dir = baseline["corpus_dir"]
    if not os.path.isdir(corpus_dir):
        # Try relative to workspace
        corpus_dir = os.path.join(workspace_root, "corpus")

    baseline_results = {r["file"]: r for r in baseline["results"]}

    # Scan each file and compare
    regressions = []
    checked = 0

    for name, base in baseline_results.items():
        path = os.path.join(corpus_dir, name)
        if not os.path.isfile(path):
            regressions.append(f"{name}: file missing from corpus")
            continue

        try:
            result = subprocess.run(
                [diec_path, "--output", "json", path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                regressions.append(f"{name}: diec exit code {result.returncode}")
                continue

            data = json.loads(result.stdout)
        except Exception as e:
            regressions.append(f"{name}: error: {e}")
            continue

        checked += 1

        # Compare detections
        base_dets = {(d["type"], d["name"]) for d in base.get("detections", [])}
        curr_dets = {(d["type"], d["name"]) for d in data.get("detections", [])}

        if base_dets != curr_dets:
            added = curr_dets - base_dets
            removed = base_dets - curr_dets
            parts = []
            if added:
                parts.append(f"added: {sorted(added)}")
            if removed:
                parts.append(f"removed: {sorted(removed)}")
            regressions.append(f"{name}: detection mismatch ({', '.join(parts)})")

        # Compare diagnostics count (not exact text, as stack traces may vary)
        base_diag_count = len(base.get("diagnostics", []))
        curr_diag_count = len(data.get("diagnostics", []))
        if base_diag_count != curr_diag_count:
            regressions.append(
                f"{name}: diagnostic count changed {base_diag_count} -> {curr_diag_count}"
            )

    print(f"Checked {checked} files against baseline: {baseline_path}")
    if regressions:
        print(f"\nREGRESSIONS FOUND ({len(regressions)}):")
        for r in regressions:
            print(f"  - {r}")
        sys.exit(1)
    else:
        print("No regressions found.")
        sys.exit(0)


if __name__ == "__main__":
    main()

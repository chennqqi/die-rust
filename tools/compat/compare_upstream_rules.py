#!/usr/bin/env python3
"""Differential comparison using upstream 3.21 rules for both sides.

Runs die-rust with upstream 3.21's rule database and compares against
upstream DIE 3.21 with its own rules. This isolates engine differences
from rule version differences.
"""

import json
import os
import subprocess
import sys


def run_rust_with_db(diec_path, db_path, file_path):
    """Run die-rust with a specific database directory."""
    try:
        result = subprocess.run(
            [diec_path, "--db", db_path, "--output", "json", file_path],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            return set(), f"exit {result.returncode}: {result.stderr[:200]}"
        data = json.loads(result.stdout)
        dets = set()
        for d in data.get("detections", []):
            dets.add((d.get("type", ""), d.get("name", ""), d.get("version", "")))
        return dets, None
    except Exception as e:
        return set(), str(e)


def run_upstream(diec_path, file_path):
    """Run upstream DIE."""
    try:
        result = subprocess.run(
            [diec_path, "-j", file_path],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            return set(), f"exit {result.returncode}"
        data = json.loads(result.stdout)
        dets = set()
        for det in data.get("detects", []):
            for v in det.get("values", []):
                dets.add((v.get("type", ""), v.get("name", ""), v.get("version", "")))
        return dets, None
    except Exception as e:
        return set(), str(e)


def main():
    rust_path = "target/release/diec.exe"
    upstream_path = "tools/upstream-die/die/diec.exe"
    upstream_db = "tools/upstream-die/die/db"

    if not os.path.isfile(rust_path):
        print(f"ERROR: rust diec not found: {rust_path}")
        sys.exit(1)

    workspace = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    corpus_dir = os.path.join(workspace, "corpus")

    files = sorted(
        os.path.join(corpus_dir, f)
        for f in os.listdir(corpus_dir)
        if os.path.isfile(os.path.join(corpus_dir, f)) and not f.startswith(".")
    )

    print(f"Comparing {len(files)} files (using upstream 3.21 rules for both)")
    print(f"  Rust:     {rust_path}")
    print(f"  Upstream: {upstream_path}")
    print(f"  DB:       {upstream_db}")
    print()

    total_matches = 0
    total_mismatches = 0

    for fpath in files:
        fname = os.path.basename(fpath)
        rust_dets, rust_err = run_rust_with_db(rust_path, upstream_db, fpath)
        up_dets, up_err = run_upstream(upstream_path, fpath)

        if rust_err and up_err:
            print(f"  ERROR  {fname}: rust={rust_err}, upstream={up_err}")
            continue
        if rust_err:
            print(f"  ERROR  {fname}: rust error: {rust_err}")
            continue
        if up_err:
            print(f"  ERROR  {fname}: upstream error: {up_err}")
            continue

        # Filter Unknown
        up_real = {d for d in up_dets if d[1] != "Unknown"}
        rust_real = {d for d in rust_dets if d[1] != "Unknown"}

        missing = up_real - rust_real
        extra = rust_real - up_real

        if not missing and not extra:
            total_matches += 1
            print(f"  MATCH  {fname}: {len(rust_real)} detections")
        else:
            total_mismatches += 1
            parts = []
            if missing:
                parts.append(f"missing {len(missing)}: {sorted(missing)[:5]}")
            if extra:
                parts.append(f"extra {len(extra)}: {sorted(extra)[:5]}")
            print(f"  DIFF   {fname}: rust={len(rust_real)}, upstream={len(up_real)}, {', '.join(parts)}")

    print()
    print(f"Summary: {total_matches} matches, {total_mismatches} mismatches")
    if total_mismatches > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

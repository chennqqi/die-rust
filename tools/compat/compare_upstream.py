#!/usr/bin/env python3
"""Differential comparison between die-rust and upstream DIE.

Runs both die-rust and upstream DIE on the same files and compares
detections. Reports mismatches in detections found/missing and version
info.

Usage:
    python tools/compat/compare_upstream.py [--rust PATH] [--upstream PATH] [--corpus DIR]
"""

import argparse
import json
import os
import subprocess
import sys


def run_rust(diec_path, file_path):
    """Run die-rust and return set of (type, name, version) tuples."""
    try:
        result = subprocess.run(
            [diec_path, "--output", "json", file_path],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            return set(), f"exit {result.returncode}"
        data = json.loads(result.stdout)
        dets = set()
        for d in data.get("detections", []):
            dets.add((d.get("type", ""), d.get("name", ""), d.get("version", "")))
        return dets, None
    except Exception as e:
        return set(), str(e)


def run_upstream(diec_path, file_path):
    """Run upstream DIE and return set of (type, name, version) tuples."""
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
    parser = argparse.ArgumentParser(description="Compare die-rust vs upstream DIE")
    parser.add_argument("--rust", default="target/release/diec.exe")
    parser.add_argument("--upstream", default="tools/upstream-die/die/diec.exe")
    parser.add_argument("--corpus", default=None)
    parser.add_argument("--files", nargs="*", default=None, help="Specific files to compare")
    args = parser.parse_args()

    rust_path = args.rust
    upstream_path = args.upstream

    if not os.path.isfile(rust_path):
        print(f"ERROR: rust diec not found: {rust_path}")
        sys.exit(1)
    if not os.path.isfile(upstream_path):
        print(f"ERROR: upstream diec not found: {upstream_path}")
        sys.exit(1)

    # Collect files
    if args.files:
        files = args.files
    else:
        corpus_dir = args.corpus or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "corpus",
        )
        if not os.path.isdir(corpus_dir):
            print(f"ERROR: corpus not found: {corpus_dir}")
            sys.exit(1)
        files = sorted(
            os.path.join(corpus_dir, f)
            for f in os.listdir(corpus_dir)
            if os.path.isfile(os.path.join(corpus_dir, f)) and not f.startswith(".")
        )

    print(f"Comparing {len(files)} files")
    print(f"  Rust:     {rust_path}")
    print(f"  Upstream: {upstream_path}")
    print()

    total_matches = 0
    total_mismatches = 0
    total_missing = 0
    total_extra = 0

    for fpath in files:
        fname = os.path.basename(fpath)
        rust_dets, rust_err = run_rust(rust_path, fpath)
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

        # Filter out "Unknown" detections - upstream outputs Unknown for
        # unrecognized files, we don't. This is a format difference, not
        # a detection defect.
        up_dets_real = {d for d in up_dets if d[1] != "Unknown"}
        rust_dets_real = {d for d in rust_dets if d[1] != "Unknown"}

        missing = up_dets_real - rust_dets_real
        extra = rust_dets_real - up_dets_real

        if not missing and not extra:
            total_matches += 1
            print(f"  MATCH  {fname}: {len(rust_dets)} detections")
        else:
            total_mismatches += 1
            total_missing += len(missing)
            total_extra += len(extra)
            parts = []
            if missing:
                parts.append(f"missing {len(missing)}: {sorted(missing)[:5]}")
            if extra:
                parts.append(f"extra {len(extra)}: {sorted(extra)[:5]}")
            print(f"  DIFF   {fname}: rust={len(rust_dets)}, upstream={len(up_dets)}, {', '.join(parts)}")

    print()
    print(f"Summary: {total_matches} matches, {total_mismatches} mismatches")
    print(f"  Total missing (in rust but not upstream): {total_missing}")
    print(f"  Total extra (in rust but not upstream):   {total_extra}")

    if total_mismatches > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

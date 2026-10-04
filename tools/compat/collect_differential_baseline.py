#!/usr/bin/env python3
"""Differential test baseline collector for die-rust.

This script runs die-rust on all corpus files and produces a JSON
baseline file that records the exact detections and diagnostics for
each file. This baseline can then be compared against:

1. Future die-rust runs (regression detection)
2. Upstream DIE-engine output (compatibility verification)

Usage:
    python tools/compat/collect_differential_baseline.py [--diec PATH] [--corpus DIR] [--output FILE]

Output format:
{
    "tool": "die-rust",
    "version": "<version>",
    "collected_at": "<ISO timestamp>",
    "corpus_dir": "<path>",
    "results": [
        {
            "file": "minimal.exe",
            "size": 512,
            "detections": [{"type": "linker", "name": "Microsoft Linker", "version": ""}],
            "diagnostics": [],
            "elapsed_ms": 123
        }
    ]
}

This is NOT a substitute for upstream DIE comparison. It is a regression
guard: if the baseline changes, something has changed in detection behavior.
To verify upstream compatibility, run upstream DIE on the same corpus and
compare outputs.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone


def find_diec():
    """Find the diec executable."""
    # Check common locations
    candidates = [
        "target/release/diec",
        "target/release/diec.exe",
        "target/debug/diec",
        "target/debug/diec.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    return None


def scan_file(diec_path, file_path):
    """Run diec on a single file and parse the JSON output."""
    try:
        start = time.monotonic()
        result = subprocess.run(
            [diec_path, "--output", "json", file_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        elapsed = (time.monotonic() - start) * 1000

        if result.returncode != 0:
            return {
                "error": f"exit code {result.returncode}",
                "stderr": result.stderr[:500],
                "elapsed_ms": round(elapsed, 1),
            }

        data = json.loads(result.stdout)
        return {
            "detections": data.get("detections", []),
            "diagnostics": data.get("diagnostics", []),
            "elapsed_ms": round(elapsed, 1),
        }
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "elapsed_ms": 30000}
    except json.JSONDecodeError as e:
        return {"error": f"json parse: {e}", "elapsed_ms": 0}
    except Exception as e:
        return {"error": str(e), "elapsed_ms": 0}


def main():
    parser = argparse.ArgumentParser(description="Collect differential test baseline")
    parser.add_argument("--diec", default=None, help="Path to diec executable")
    parser.add_argument("--corpus", default=None, help="Path to corpus directory")
    parser.add_argument("--output", default=None, help="Output baseline file path")
    args = parser.parse_args()

    diec_path = args.diec or find_diec()
    if not diec_path:
        print("ERROR: diec executable not found. Build with 'cargo build --release' first.")
        sys.exit(1)

    # Find corpus directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    workspace_root = os.path.dirname(os.path.dirname(script_dir))
    corpus_dir = args.corpus or os.path.join(workspace_root, "corpus")

    if not os.path.isdir(corpus_dir):
        print(f"ERROR: corpus directory not found: {corpus_dir}")
        sys.exit(1)

    # Collect all files in corpus (not in subdirectories like edge/)
    files = []
    for name in sorted(os.listdir(corpus_dir)):
        path = os.path.join(corpus_dir, name)
        if os.path.isfile(path) and not name.startswith("."):
            files.append(name)

    print(f"Scanning {len(files)} files from {corpus_dir}")
    print(f"Using diec: {diec_path}")
    print()

    results = []
    for name in files:
        path = os.path.join(corpus_dir, name)
        size = os.path.getsize(path)
        scan_result = scan_file(diec_path, path)

        entry = {
            "file": name,
            "size": size,
            **scan_result,
        }
        results.append(entry)

        if "error" in scan_result:
            print(f"  ERROR  {name:30s} {size:>8} bytes  {scan_result['error']}")
        else:
            dets = scan_result.get("detections", [])
            diags = scan_result.get("diagnostics", [])
            ms = scan_result.get("elapsed_ms", 0)
            det_str = ", ".join(f"{d['type']}:{d['name']}" for d in dets)
            print(f"  {'OK' if not diags else 'WARN'}  {name:30s} {size:>8} bytes  {ms:>7.1f}ms  {len(dets)} dets  {len(diags)} diags  {det_str}")

    # Get diec version
    try:
        version_result = subprocess.run(
            [diec_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = version_result.stdout.strip()
    except Exception:
        version = "unknown"

    baseline = {
        "tool": "die-rust",
        "version": version,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "corpus_dir": os.path.abspath(corpus_dir),
        "file_count": len(files),
        "results": results,
    }

    output_path = args.output or os.path.join(workspace_root, "tools", "compat", "differential-baseline.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2, ensure_ascii=False)

    print(f"\nBaseline written to: {output_path}")
    print(f"Total files: {len(files)}")

    # Summary
    errors = sum(1 for r in results if "error" in r)
    with_diags = sum(1 for r in results if "diagnostics" in r and r["diagnostics"])
    with_dets = sum(1 for r in results if "detections" in r and r["detections"])
    print(f"Errors: {errors}, Files with diagnostics: {with_diags}, Files with detections: {with_dets}")


if __name__ == "__main__":
    main()

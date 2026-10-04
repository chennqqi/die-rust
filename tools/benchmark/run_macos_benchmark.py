#!/usr/bin/env python3
"""Run macOS Qt5 upstream benchmark plans and collect results."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


WORK_DIR = Path(__file__).resolve().parents[3]
PLANS_PATH = WORK_DIR / "die-rust" / "tools" / "benchmark" / "upstream-benchmark-macos-qt5-plans.json"
RUNNER_PATH = WORK_DIR / "die-rust" / "tools" / "benchmark" / "run_process_benchmark.py"
BENCH_DIR = WORK_DIR / "bench"
OUTPUT_DIR = WORK_DIR / "evidence" / "macos-benchmark"
VENV_PYTHON = WORK_DIR / "venv" / "bin" / "python3"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    plans_container = json.loads(PLANS_PATH.read_bytes())
    plans = plans_container["plans"]
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    case_reports: dict[str, Any] = {}
    for plan in plans:
        benchmark_id = plan["benchmark_id"]
        print(f"running {benchmark_id}...", flush=True)
        plan_path = OUTPUT_DIR / f"{benchmark_id}.plan.json"
        plan_path.write_text(
            json.dumps(plan, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        output_path = OUTPUT_DIR / f"{benchmark_id}.report.json"
        result = subprocess.run(
            [
                str(VENV_PYTHON),
                str(RUNNER_PATH),
                "--plan",
                str(plan_path),
                "--output",
                str(output_path),
                "--repo-root",
                str(BENCH_DIR),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"  FAILED: {result.stderr}", file=sys.stderr)
            return result.returncode
        if not output_path.exists():
            print(f"  no output file produced", file=sys.stderr)
            return 1
        report = json.loads(output_path.read_bytes())
        case_reports[benchmark_id] = report
        timing = report.get("execution", {}).get("timing", {})
        median_ms = timing.get("median_ms", "n/a")
        peak_rss = report.get("execution", {}).get("peak_rss_bytes", "n/a")
        print(f"  median={median_ms}ms peak_rss={peak_rss}")

    # Build combined report
    combined = {
        "baseline_scope": "descriptive_upstream_only",
        "case_reports": case_reports,
        "plans_identity": {
            "path": str(PLANS_PATH),
            "sha256": sha256_file(PLANS_PATH),
        },
        "runner_identity": {
            "path": str(RUNNER_PATH),
            "sha256": sha256_file(RUNNER_PATH),
        },
    }
    combined_path = OUTPUT_DIR / "upstream-benchmark-macos-qt5.json"
    combined_path.write_text(
        json.dumps(combined, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"\nwrote combined report: {combined_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

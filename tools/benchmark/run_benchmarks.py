#!/usr/bin/env python3
"""Run die-rust benchmarks and collect results.

This script runs the criterion benchmarks in release mode and collects
the timing results into a JSON file for documentation.

Usage:
    python tools/benchmark/run_benchmarks.py [--quick]

Output:
    tools/benchmark/results/benchmark_results.json
"""

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

WORKSPACE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RESULTS_DIR = os.path.join(WORKSPACE, "tools", "benchmark", "results")


def run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    """Run a command and return (exit_code, output)."""
    try:
        result = subprocess.run(
            cmd,
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return 1, "TIMEOUT"
    except Exception as e:
        return 1, str(e)


def parse_criterion_output(output: str) -> list[dict]:
    """Parse criterion benchmark output to extract timing data."""
    results = []
    # Pattern: "benchmark_name time: [lower estimate upper]"
    pattern = re.compile(
        r"^(.*?)\s+time:\s+\[\s*([\d.]+)\s+(\w+)\s+([\d.]+)\s+(\w+)\s+([\d.]+)\s+(\w+)\s*\]",
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        name = m.group(1).strip()
        # Convert all values to nanoseconds
        def to_ns(val: str, unit: str) -> float:
            v = float(val)
            if unit == "ns":
                return v
            elif unit == "µs" or unit == "us":
                return v * 1000
            elif unit == "ms":
                return v * 1_000_000
            elif unit == "s":
                return v * 1_000_000_000
            return v

        lower = to_ns(m.group(2), m.group(3))
        point = to_ns(m.group(4), m.group(5))
        upper = to_ns(m.group(6), m.group(7))

        results.append({
            "benchmark": name,
            "lower_ns": round(lower, 1),
            "point_ns": round(point, 1),
            "upper_ns": round(upper, 1),
            "point_human": f"{m.group(4)} {m.group(5)}",
        })
    return results


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="Quick run (shorter measurement)")
    args = parser.parse_args()

    os.makedirs(RESULTS_DIR, exist_ok=True)

    all_results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "quick": args.quick,
        "benchmarks": {},
    }

    # 1. die-engine scan benchmarks
    print("=== Running die-engine scan benchmarks ===")
    cmd = ["cargo", "bench", "-p", "die-engine", "--bench", "scan", "--"]
    if args.quick:
        cmd += ["--quick", "--warm-up-time", "1", "--measurement-time", "2"]
    else:
        cmd += ["--warm-up-time", "3", "--measurement-time", "5"]

    code, output = run_cmd(cmd, timeout=600)
    if code == 0:
        all_results["benchmarks"]["diec_engine_scan"] = parse_criterion_output(output)
        print(f"  Parsed {len(all_results['benchmarks']['diec_engine_scan'])} results")
    else:
        print(f"  FAILED (exit {code})")
        all_results["benchmarks"]["diec_engine_scan"] = {"error": output[-500:]}

    # 2. die-formats probe benchmarks
    print("=== Running die-formats probe benchmarks ===")
    cmd = ["cargo", "bench", "-p", "die-formats", "--bench", "probe", "--"]
    if args.quick:
        cmd += ["--quick", "--warm-up-time", "1", "--measurement-time", "2"]
    else:
        cmd += ["--warm-up-time", "3", "--measurement-time", "5"]

    code, output = run_cmd(cmd, timeout=600)
    if code == 0:
        all_results["benchmarks"]["diec_formats_probe"] = parse_criterion_output(output)
        print(f"  Parsed {len(all_results['benchmarks']['diec_formats_probe'])} results")
    else:
        print(f"  FAILED (exit {code})")
        all_results["benchmarks"]["diec_formats_probe"] = {"error": output[-500:]}

    # 3. Database load timing (separate measurement)
    print("=== Measuring database load time ===")
    load_times = []
    for i in range(5):
        start = time.perf_counter()
        code, _ = run_cmd(
            ["cargo", "run", "--release", "-p", "die-cli", "--", "--showdatabase"],
            timeout=30,
        )
        elapsed = time.perf_counter() - start
        if code == 0:
            load_times.append(round(elapsed * 1000, 1))
            print(f"  Run {i+1}: {elapsed*1000:.1f}ms")

    if load_times:
        all_results["benchmarks"]["database_load_cli"] = {
            "runs_ms": load_times,
            "avg_ms": round(sum(load_times) / len(load_times), 1),
            "min_ms": min(load_times),
            "max_ms": max(load_times),
        }

    # Save results
    output_path = os.path.join(RESULTS_DIR, "benchmark_results.json")
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nResults saved to {output_path}")

    # Print summary
    print("\n=== Summary ===")
    for category, data in all_results["benchmarks"].items():
        if isinstance(data, list):
            print(f"\n{category}:")
            for r in data:
                print(f"  {r['benchmark']}: {r['point_human']}")
        elif isinstance(data, dict) and "avg_ms" in data:
            print(f"\n{category}: avg={data['avg_ms']}ms")

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Run compatibility tests and collect results.

This script runs the full test suite and corpus differential tests,
then collects the results into a JSON file for documentation.

Usage:
    python tools/benchmark/run_compatibility.py

Output:
    tools/benchmark/results/compatibility_results.json
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

WORKSPACE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RESULTS_DIR = os.path.join(WORKSPACE, "tools", "benchmark", "results")
CORPUS_DIR = os.path.join(WORKSPACE, "corpus")
EDGE_DIR = os.path.join(CORPUS_DIR, "edge")
DB_PATH = os.path.join(WORKSPACE, "upstream", "Detect-It-Easy", "db")


def run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    """Run a command and return (exit_code, combined output)."""
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


def run_cmd_stdout(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    """Run a command and return (exit_code, stdout only)."""
    try:
        result = subprocess.run(
            cmd,
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired:
        return 1, "TIMEOUT"
    except Exception as e:
        return 1, str(e)


def parse_test_output(output: str) -> dict:
    """Parse cargo test output to extract pass/fail counts."""
    results = {"total_passed": 0, "total_failed": 0, "suites": []}

    # Match lines like: "test result: ok. 5 passed; 0 failed; 0 ignored"
    pattern = re.compile(
        r"test result: (ok|FAILED)\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored"
    )
    for m in pattern.finditer(output):
        status = m.group(1)
        passed = int(m.group(2))
        failed = int(m.group(3))
        ignored = int(m.group(4))
        results["suites"].append({
            "status": status,
            "passed": passed,
            "failed": failed,
            "ignored": ignored,
        })
        results["total_passed"] += passed
        results["total_failed"] += failed

    return results


def count_rules(db_path: str) -> dict:
    """Count rule files in the database directory."""
    counts = {"total_sg": 0, "by_type": {}}
    if not os.path.isdir(db_path):
        return counts

    for entry in os.listdir(db_path):
        type_dir = os.path.join(db_path, entry)
        if os.path.isdir(type_dir):
            sg_count = 0
            for f in os.listdir(type_dir):
                if f.endswith(".sg"):
                    sg_count += 1
            if sg_count > 0:
                counts["by_type"][entry] = sg_count
                counts["total_sg"] += sg_count

    return counts


def count_corpus_samples() -> dict:
    """Count corpus samples and their sizes."""
    counts = {"baseline": 0, "edge": 0, "total_bytes": 0}

    if os.path.isdir(CORPUS_DIR):
        for f in os.listdir(CORPUS_DIR):
            path = os.path.join(CORPUS_DIR, f)
            if os.path.isfile(path):
                counts["baseline"] += 1
                counts["total_bytes"] += os.path.getsize(path)

    if os.path.isdir(EDGE_DIR):
        for f in os.listdir(EDGE_DIR):
            path = os.path.join(EDGE_DIR, f)
            if os.path.isfile(path):
                counts["edge"] += 1
                counts["total_bytes"] += os.path.getsize(path)

    return counts


def scan_file_with_cli(filepath: str) -> dict:
    """Scan a single file with the CLI and return detections."""
    cmd = [
        "cargo", "run", "--release", "-p", "die-cli", "--",
        "--output", "json", "--alltypes", filepath,
    ]
    code, output = run_cmd_stdout(cmd, timeout=30)
    if code != 0:
        return {"error": output[-200:], "exit_code": code}

    # Try to parse JSON output
    try:
        data = json.loads(output.strip().split("\n")[-1] if output else "{}")
        detections = data.get("detections", [])
        return {
            "file": os.path.basename(filepath),
            "detection_count": len(detections),
            "detections": [
                {"type": d.get("type", ""), "name": d.get("name", "")}
                for d in detections
            ],
        }
    except (json.JSONDecodeError, IndexError):
        return {"file": os.path.basename(filepath), "raw_output": output[-200:]}


def main() -> int:
    os.makedirs(RESULTS_DIR, exist_ok=True)

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db_path": DB_PATH,
        "db_exists": os.path.isdir(DB_PATH),
    }

    # 1. Rule database statistics
    print("=== Counting rules in database ===")
    rule_counts = count_rules(DB_PATH)
    results["rule_database"] = rule_counts
    print(f"  Total .sg files: {rule_counts['total_sg']}")
    for ft, count in sorted(rule_counts["by_type"].items()):
        print(f"    {ft}: {count}")

    # 2. Corpus statistics
    print("\n=== Counting corpus samples ===")
    corpus_counts = count_corpus_samples()
    results["corpus"] = corpus_counts
    print(f"  Baseline: {corpus_counts['baseline']} files")
    print(f"  Edge: {corpus_counts['edge']} files")

    # 3. Run full test suite
    print("\n=== Running cargo test --workspace --all-features --locked ===")
    code, output = run_cmd(
        ["cargo", "test", "--workspace", "--all-features", "--locked"],
        timeout=600,
    )
    test_results = parse_test_output(output)
    test_results["exit_code"] = code
    results["tests"] = test_results
    print(f"  Total: {test_results['total_passed']} passed, {test_results['total_failed']} failed")
    for suite in test_results["suites"]:
        print(f"    {suite['status']}: {suite['passed']} passed, {suite['failed']} failed")

    # 4. Run clippy
    print("\n=== Running cargo clippy ===")
    code, output = run_cmd(
        ["cargo", "clippy", "--workspace", "--all-targets", "--all-features",
         "--locked", "--", "-D", "warnings"],
        timeout=300,
    )
    results["clippy"] = {
        "exit_code": code,
        "passed": code == 0,
        "warnings": 0 if code == 0 else 1,
    }
    print(f"  {'PASS' if code == 0 else 'FAIL'} (exit {code})")

    # 5. Scan each corpus file and record detections
    print("\n=== Scanning corpus files ===")
    scan_results = []
    if os.path.isdir(CORPUS_DIR):
        for f in sorted(os.listdir(CORPUS_DIR)):
            path = os.path.join(CORPUS_DIR, f)
            if os.path.isfile(path) and f != "manifest.json":
                print(f"  Scanning {f}...", end=" ")
                result = scan_file_with_cli(path)
                scan_results.append(result)
                det_count = result.get("detection_count", 0)
                print(f"{det_count} detections")

    results["corpus_scans"] = scan_results

    # 6. Scan edge corpus files
    print("\n=== Scanning edge corpus files ===")
    edge_scan_results = []
    if os.path.isdir(EDGE_DIR):
        for f in sorted(os.listdir(EDGE_DIR)):
            path = os.path.join(EDGE_DIR, f)
            if os.path.isfile(path) and f != "manifest.json":
                print(f"  Scanning {f}...", end=" ")
                result = scan_file_with_cli(path)
                edge_scan_results.append(result)
                det_count = result.get("detection_count", 0)
                print(f"{det_count} detections")

    results["edge_corpus_scans"] = edge_scan_results

    # Save results
    output_path = os.path.join(RESULTS_DIR, "compatibility_results.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to {output_path}")
    return 0 if test_results["total_failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

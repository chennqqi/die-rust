#!/usr/bin/env python3
"""Build Rust paired benchmark plans for macOS Qt5 comparison."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
WORK_DIR = Path(__file__).resolve().parents[3]
RUST_CLI = str(WORK_DIR / "die-rust-src" / "target" / "release" / "diec")
DB = str(WORK_DIR / "DIE-engine-src" / "Detect-It-Easy" / "db")
BENCH = WORK_DIR / "bench"
ENVIRONMENT = {
    "LC_ALL": "C",
    "TZ": "UTC",
}
PRODUCER = {
    "implementation": "die-rust Rust implementation (Phase 3)",
    "source_commit": "9bb97c611f559dbebf805e4dd607c04aafa54468",
    "rules_commit": "c2c17dfa5ea4e078ba31eab55d87430c96622fb6",
    "build_profile": "cargo release",
    "toolchain": "rustc 1.96.1 stable x86_64-apple-darwin",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def artifact(prefix: str, sample: dict[str, Any]) -> dict[str, Any]:
    return {
        "bytes": sample["size"],
        "path": f"{prefix}/{sample['name']}",
        "sha256": sample["sha256"],
    }


def base_plan(
    benchmark_id: str,
    command: list[str],
    input_artifacts: list[dict[str, Any]],
    work_bytes: int,
    work_definition: str,
    measured_runs: int = 15,
    warmup_runs: int = 3,
    timeout_ms: int = 30000,
    max_stdout_bytes: int = 4194304,
) -> dict[str, Any]:
    return {
        "benchmark_id": benchmark_id,
        "benchmark_plan_schema": SCHEMA_VERSION,
        "cache_state": "warm",
        "command": command,
        "environment": ENVIRONMENT,
        "inherit_environment": True,
        "input_artifacts": input_artifacts,
        "max_stderr_bytes": 65536,
        "max_stdout_bytes": max_stdout_bytes,
        "measured_runs": measured_runs,
        "notes": [
            "runner executes on the pinned macOS host",
            "Rust implementation paired with upstream Qt5 benchmark",
            "OS cache is warmed but not forcibly controlled",
            "script exceptions are expected (Phase 3 runtime incomplete)",
        ],
        "producer": PRODUCER,
        "require_deterministic_output": False,
        "require_peak_rss": True,
        "timeout_ms": timeout_ms,
        "warmup_runs": warmup_runs,
        "work_bytes": work_bytes,
        "work_definition": work_definition,
        "working_directory": ".",
    }


def build_plans() -> dict[str, Any]:
    baseline_manifest = json.loads(
        (BENCH / "baseline" / "manifest.json").read_bytes()
    )
    baseline_samples = baseline_manifest["samples"]

    plans: list[dict[str, Any]] = []

    # 1. Rust CLI PE32 JSON
    pe32_sample = next(
        s for s in baseline_samples if s["name"] == "minimal.exe"
    )
    plans.append(
        base_plan(
            "rust.macos-cli-pe32-json.v1",
            [RUST_CLI, "--db", DB, "--output", "json", str(BENCH / "baseline" / "minimal.exe")],
            [artifact("baseline", pe32_sample)],
            pe32_sample["size"],
            "minimal PE32 input bytes scanned once with JSON rendering (Rust)",
        )
    )

    # 2. Rust CLI baseline batch JSON
    total_bytes = sum(s["size"] for s in baseline_samples)
    plans.append(
        base_plan(
            "rust.macos-cli-baseline-batch-json.v1",
            [RUST_CLI, "--db", DB, "--output", "json", "--recursive", str(BENCH / "baseline")],
            [artifact("baseline", s) for s in baseline_samples],
            total_bytes,
            "all files in generated baseline directory scanned once with JSON rendering (Rust)",
        )
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "baseline_manifest_sha256": sha256_file(BENCH / "baseline" / "manifest.json"),
        "plans": plans,
    }


def main() -> None:
    report = build_plans()
    output = Path(__file__).resolve().parent / "rust-benchmark-macos-plans.json"
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {output} with {len(report['plans'])} plans")


if __name__ == "__main__":
    main()

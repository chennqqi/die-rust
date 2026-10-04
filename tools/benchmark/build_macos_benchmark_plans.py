#!/usr/bin/env python3
"""Build strict process benchmark plans for the pinned macOS Qt5 oracle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
WORK_DIR = Path(__file__).resolve().parents[3]
CLI = str(WORK_DIR / "DIE-engine-src" / "build" / "release" / "diec")
HARNESS = str(
    WORK_DIR
    / "DIE-engine-src"
    / "build"
    / "release"
    / "die-upstream-benchmark-harness"
)
DB = str(WORK_DIR / "DIE-engine-src" / "Detect-It-Easy" / "db")
DB_EXTRA = str(WORK_DIR / "DIE-engine-src" / "Detect-It-Easy" / "db_extra")
DB_CUSTOM = str(WORK_DIR / "DIE-engine-src" / "Detect-It-Easy" / "db_custom")
BENCH = WORK_DIR / "bench"
QT_LIB = str(WORK_DIR / "qt" / "5.15.2" / "clang_64" / "lib")
ENVIRONMENT = {
    "LC_ALL": "C",
    "QT_HASH_SEED": "0",
    "TZ": "UTC",
    "DYLD_FRAMEWORK_PATH": QT_LIB,
}
PRODUCER = {
    "implementation": "DIE-engine macOS Qt5 qmake oracle",
    "source_commit": UPSTREAM_COMMIT,
    "rules_commit": RULES_COMMIT,
    "build_profile": "Release -O3 -DNDEBUG",
    "toolchain": "Apple clang 14.0.0; Qt 5.15.2; qmake 3.1",
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
    timeout_ms: int = 10000,
    max_stdout_bytes: int = 1048576,
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
            "each sample is a fresh direct upstream process",
            "OS cache is warmed but not forcibly controlled",
        ],
        "producer": PRODUCER,
        "require_deterministic_output": True,
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
    archive_manifest = json.loads(
        (BENCH / "archive" / "manifest.json").read_bytes()
    )
    archive_samples = archive_manifest["samples"]
    depth16 = next(
        s for s in archive_samples if s["name"] == "depth-16.zip"
    )

    database_args = [
        "--database",
        DB,
        "--extradatabase",
        DB_EXTRA,
        "--customdatabase",
        DB_CUSTOM,
    ]

    plans: list[dict[str, Any]] = []

    # 1. Process control (noop)
    plans.append(
        base_plan(
            "upstream.macos-qt-process-control.v1",
            [HARNESS, "--noop"],
            [],
            1,
            "one QCoreApplication process startup; throughput is not interpreted",
            measured_runs=30,
            warmup_runs=5,
            max_stdout_bytes=4096,
        )
    )

    # 2. Database load
    plans.append(
        base_plan(
            "upstream.macos-database-load.v1",
            [HARNESS, "--database-only"],
            [],
            1,
            "one full pinned main/extra/custom database load; throughput is not interpreted",
            max_stdout_bytes=4096,
        )
    )

    # 3. CLI PE32 JSON
    pe32_sample = next(
        s for s in baseline_samples if s["name"] == "minimal.exe"
    )
    plans.append(
        base_plan(
            "upstream.macos-cli-pe32-json.v1",
            [CLI, "--json", *database_args, str(BENCH / "baseline" / "minimal.exe")],
            [artifact("baseline", pe32_sample)],
            pe32_sample["size"],
            "minimal PE32 input bytes scanned once with JSON rendering",
        )
    )

    # 4. CLI baseline batch JSON
    total_bytes = sum(s["size"] for s in baseline_samples)
    plans.append(
        base_plan(
            "upstream.macos-cli-baseline-batch-json.v1",
            [CLI, "--json", *database_args, str(BENCH / "baseline")],
            [artifact("baseline", s) for s in baseline_samples],
            total_bytes,
            "all files in generated baseline directory, including manifest.json, scanned once with JSON rendering",
            max_stdout_bytes=4194304,
        )
    )

    # 5. Archive depth-16
    plans.append(
        base_plan(
            "upstream.macos-archive-depth16.v1",
            [HARNESS, "--archive", str(BENCH / "archive" / "depth-16.zip")],
            [artifact("archive", depth16)],
            depth16["cumulative_expanded_bytes"],
            "cumulative uncompressed member bytes traversed through a single-member 16-level store-only ZIP chain",
            max_stdout_bytes=4096,
        )
    )

    baseline_manifest_sha = sha256_file(BENCH / "baseline" / "manifest.json")
    archive_manifest_sha = sha256_file(BENCH / "archive" / "manifest.json")

    return {
        "schema_version": SCHEMA_VERSION,
        "upstream_commit": UPSTREAM_COMMIT,
        "baseline_manifest_sha256": baseline_manifest_sha,
        "archive_manifest_sha256": archive_manifest_sha,
        "plans": plans,
    }


def main() -> None:
    report = build_plans()
    output = Path(__file__).resolve().parent / "upstream-benchmark-macos-qt5-plans.json"
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {output} with {len(report['plans'])} plans")


if __name__ == "__main__":
    main()

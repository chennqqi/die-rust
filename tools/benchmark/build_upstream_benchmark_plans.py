#!/usr/bin/env python3
"""Build strict process benchmark plans for the pinned Linux Qt5 oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
DATABASE_ARGS = [
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
]
CLI = "/opt/die-build/src/console/diec"
HARNESS = (
    "/opt/die-build/src/console/"
    "die-upstream-benchmark-harness"
)
ENVIRONMENT = {
    "LC_ALL": "C",
    "MALLOC_ARENA_MAX": "1",
    "QT_HASH_SEED": "0",
    "TZ": "UTC",
}
PRODUCER = {
    "implementation": "DIE-engine Linux Qt5 CMake oracle",
    "source_commit": UPSTREAM_COMMIT,
    "rules_commit": RULES_COMMIT,
    "build_profile": "Release -O3 -DNDEBUG",
    "toolchain": "GCC 13.3.0; Qt 5.15.13; CMake 3.28.3",
}


class PlanError(ValueError):
    """Benchmark plan inputs are invalid or inconsistent."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlanError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PlanError(f"invalid manifest JSON: {error}") from error
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise PlanError("unsupported manifest")
    samples = value.get("samples")
    if not isinstance(samples, list) or not samples:
        raise PlanError("manifest samples must be non-empty")
    return value, raw


def artifact(prefix: str, sample: dict[str, Any]) -> dict[str, Any]:
    return {
        "bytes": sample["size"],
        "path": f"{prefix}/{sample['name']}",
        "sha256": sample["sha256"],
    }


def base_plan(
    benchmark_id: str,
    command: list[str],
    artifacts: list[dict[str, Any]],
    *,
    work_bytes: int,
    work_definition: str,
    warmup_runs: int = 3,
    measured_runs: int = 15,
    max_stdout_bytes: int = 1_048_576,
) -> dict[str, Any]:
    return {
        "benchmark_id": benchmark_id,
        "benchmark_plan_schema": 1,
        "cache_state": "warm",
        "command": command,
        "environment": ENVIRONMENT,
        "inherit_environment": True,
        "input_artifacts": artifacts,
        "max_stderr_bytes": 65_536,
        "max_stdout_bytes": max_stdout_bytes,
        "measured_runs": measured_runs,
        "notes": [
            "runner executes inside the pinned container",
            "each sample is a fresh direct upstream process",
            "OS cache is warmed but not forcibly controlled",
        ],
        "producer": PRODUCER,
        "require_deterministic_output": True,
        "require_peak_rss": True,
        "timeout_ms": 10_000,
        "warmup_runs": warmup_runs,
        "work_bytes": work_bytes,
        "work_definition": work_definition,
        "working_directory": ".",
    }


def build_plans(
    baseline: dict[str, Any],
    baseline_raw: bytes,
    archive: dict[str, Any],
    archive_raw: bytes,
) -> dict[str, Any]:
    if baseline.get("generator") != (
        "tools/corpus/generate_baseline_corpus.py"
    ):
        raise PlanError("unexpected baseline generator")
    if archive.get("generator") != (
        "tools/corpus/generate_archive_limit_fixture.py"
    ):
        raise PlanError("unexpected archive generator")

    baseline_by_name = {
        sample["name"]: sample for sample in baseline["samples"]
    }
    archive_by_name = {
        sample["name"]: sample for sample in archive["samples"]
    }
    pe = baseline_by_name["minimal.exe"]
    depth16 = archive_by_name["depth-16.zip"]
    batch_artifacts = [
        artifact("baseline", sample)
        for sample in baseline["samples"]
    ]
    batch_artifacts.append(
        {
            "bytes": len(baseline_raw),
            "path": "baseline/manifest.json",
            "sha256": hashlib.sha256(baseline_raw).hexdigest(),
        }
    )
    batch_bytes = sum(item["bytes"] for item in batch_artifacts)

    plans = [
        base_plan(
            "upstream.qt-process-control.v1",
            [HARNESS, "--noop"],
            [],
            work_bytes=1,
            work_definition=(
                "one QCoreApplication process startup; throughput is not "
                "interpreted"
            ),
            warmup_runs=5,
            measured_runs=30,
            max_stdout_bytes=4096,
        ),
        base_plan(
            "upstream.database-load.v1",
            [HARNESS, "--database-only"],
            [],
            work_bytes=1,
            work_definition=(
                "one full pinned main/extra/custom database load; "
                "throughput is not interpreted"
            ),
            max_stdout_bytes=4096,
        ),
        base_plan(
            "upstream.cli-pe32-json.v1",
            [
                CLI,
                "--json",
                *DATABASE_ARGS,
                "/bench/baseline/minimal.exe",
            ],
            [artifact("baseline", pe)],
            work_bytes=pe["size"],
            work_definition=(
                "minimal PE32 input bytes scanned once with JSON rendering"
            ),
        ),
        base_plan(
            "upstream.cli-baseline-batch-json.v1",
            [
                CLI,
                "--json",
                *DATABASE_ARGS,
                "/bench/baseline",
            ],
            batch_artifacts,
            work_bytes=batch_bytes,
            work_definition=(
                "all files in generated baseline directory, including "
                "manifest.json, scanned once with JSON rendering"
            ),
            max_stdout_bytes=4 * 1024 * 1024,
        ),
        base_plan(
            "upstream.archive-depth16.v1",
            [
                HARNESS,
                "--archive",
                "/bench/archive/depth-16.zip",
            ],
            [artifact("archive", depth16)],
            work_bytes=depth16["cumulative_expanded_bytes"],
            work_definition=(
                "cumulative uncompressed member bytes traversed through "
                "a single-member 16-level store-only ZIP chain"
            ),
            max_stdout_bytes=4096,
        ),
    ]
    return {
        "archive_manifest_sha256": hashlib.sha256(
            archive_raw
        ).hexdigest(),
        "baseline_manifest_sha256": hashlib.sha256(
            baseline_raw
        ).hexdigest(),
        "container_limits": {
            "cpus": "1",
            "memory": "512m",
            "network": "none",
            "pids": 128,
        },
        "plans": plans,
        "schema_version": SCHEMA_VERSION,
        "upstream_commit": UPSTREAM_COMMIT,
    }


def serialize(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline-manifest",
        type=Path,
        default=(
            root / "docs" / "research" / "data" / "baseline-corpus.json"
        ),
    )
    parser.add_argument(
        "--archive-manifest",
        type=Path,
        default=(
            root
            / "tools"
            / "benchmark"
            / "upstream-benchmark-archive-corpus-v1.json"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            root
            / "docs"
            / "research"
            / "data"
            / "upstream-benchmark-plans.json"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    baseline, baseline_raw = load_manifest(args.baseline_manifest)
    archive, archive_raw = load_manifest(args.archive_manifest)
    result = build_plans(
        baseline,
        baseline_raw,
        archive,
        archive_raw,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(serialize(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

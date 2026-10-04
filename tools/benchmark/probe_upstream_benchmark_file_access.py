#!/usr/bin/env python3
"""Audit repeated successful regular-file access for pinned benchmarks."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
EXPECTED_REVISION = "74eaf505c250ab47e709024e9dc41657cd8f2254"
EXPECTED_IMAGE = "die-rust/upstream-benchmark-qt5:74eaf505"
EXPECTED_IMAGE_ID = (
    "sha256:9f1d70a8d4513404cdc457074e00dec"
    "4a9b8a6f043a572ffc17465bbe699eb09"
)
EXPECTED_PLAN_SHA256 = (
    "f93672c9603db16050047095f15d5f5e"
    "a6d9d58663b4574ed901f819f0106e1a"
)
EXPECTED_CPU = "0"
TRACE_REPETITIONS = 2
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
GENERATOR = (
    "tools/benchmark/probe_upstream_benchmark_file_access.py"
)
TRACER = "tools/benchmark/trace_linux_file_access.py"
CONTAINER_TRACER = "/opt/die-benchmark/trace_linux_file_access.py"
CONTAINER_RULE_ROOT = "/opt/die-source/Detect-It-Easy"
RULE_TREES = ("db", "db_extra", "db_custom")


class AccessProbeError(ValueError):
    """The traced file-access closure is incomplete or incomparable."""


def reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AccessProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise AccessProbeError(f"non-finite JSON constant: {value}")


def parse_json(raw: bytes, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AccessProbeError(
            f"invalid {description} JSON: {error}"
        ) from error
    if not isinstance(value, dict):
        raise AccessProbeError(
            f"{description} root must be an object"
        )
    return value


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def serialize(value: object) -> bytes:
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


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AccessProbeError(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_inputs(
    repo: Path,
    plans_path: Path,
    baseline_path: Path,
) -> tuple[Any, dict[str, Any], dict[str, Any], bytes]:
    probe = load_module(
        "probe_upstream_benchmark_for_file_access",
        repo / "tools/benchmark/probe_upstream_benchmark.py",
    )
    plans, plans_raw = probe.load_plans(plans_path)
    if sha256(plans_raw) != EXPECTED_PLAN_SHA256:
        raise AccessProbeError("plan suite SHA-256 mismatch")
    baseline_raw = baseline_path.read_bytes()
    baseline = parse_json(baseline_raw, "affinity baseline")
    if probe.evaluate_report(baseline):
        raise AccessProbeError("affinity baseline verifier failed")
    if (
        baseline["environment"]["image_identity"]["id"]
        != EXPECTED_IMAGE_ID
        or baseline["environment"]["cgroup"]["cpuset_effective"]
        != EXPECTED_CPU
        or baseline["plan_suite"] != plans
    ):
        raise AccessProbeError("affinity baseline identity mismatch")
    return probe, plans, baseline, baseline_raw


def run_trace(
    repo: Path,
    image: str,
    limits: dict[str, Any],
    tracer_path: Path,
    plan: dict[str, Any],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        exchange = Path(directory)
        output = exchange / "trace.json"
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            str(limits["network"]),
            "--cpus",
            str(limits["cpus"]),
            "--cpuset-cpus",
            EXPECTED_CPU,
            "--memory",
            str(limits["memory"]),
            "--pids-limit",
            str(limits["pids"]),
            "--mount",
            (
                f"type=bind,source={tracer_path.resolve()},"
                f"target={CONTAINER_TRACER},readonly"
            ),
            "--mount",
            (
                f"type=bind,source={exchange.resolve()},"
                "target=/io"
            ),
        ]
        environment = plan["environment"]
        for key in sorted(environment):
            command.extend(["--env", f"{key}={environment[key]}"])
        command.extend(
            [
                "--entrypoint",
                "/usr/bin/python3",
                image,
                CONTAINER_TRACER,
                "--output",
                "/io/trace.json",
                "--working-directory",
                "/bench",
                "--timeout-ms",
                "120000",
                "--",
                *plan["command"],
            ]
        )
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=180,
            cwd=repo,
        )
        if completed.returncode != 0:
            raise AccessProbeError(
                f"{plan['benchmark_id']} tracer exited "
                f"{completed.returncode}: "
                f"{completed.stderr.decode(errors='replace')}"
            )
        if completed.stdout or completed.stderr:
            raise AccessProbeError(
                f"{plan['benchmark_id']} tracer emitted output"
            )
        raw = output.read_bytes()
    return parse_json(raw, f"{plan['benchmark_id']} trace")


def validate_trace(
    trace: dict[str, Any],
    tracer_sha256: str,
    plan: dict[str, Any],
    baseline_case: dict[str, Any],
) -> None:
    if (
        trace.get("schema_version") != 1
        or trace.get("generator_sha256") != tracer_sha256
        or trace.get("command") != plan["command"]
        or trace.get("working_directory") != "/bench"
        or trace.get("exit_code") != 0
        or trace.get("stderr")
        != {"bytes": 0, "sha256": EMPTY_SHA256}
        or trace.get("stdout", {}).get("sha256")
        not in baseline_case["summary"]["stdout_unique_sha256"]
        or trace.get("stdout", {}).get("bytes")
        != baseline_case["runs"][0]["stdout"]["bytes"]
    ):
        raise AccessProbeError(
            f"{plan['benchmark_id']} trace identity mismatch"
        )
    scope = trace.get("scope", {})
    if (
        scope.get(
            "successful_open_openat_openat2_execve_and_exec_mappings_only"
        )
        is not True
        or scope.get("performance_measurement") is not False
        or scope.get("cold_cache_claimed") is not False
    ):
        raise AccessProbeError(
            f"{plan['benchmark_id']} trace scope mismatch"
        )
    records = trace.get("successful_regular_files")
    if not isinstance(records, list) or not records:
        raise AccessProbeError(
            f"{plan['benchmark_id']} trace has no records"
        )
    paths = [record.get("path") for record in records]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise AccessProbeError(
            f"{plan['benchmark_id']} trace paths drift"
        )
    for record in records:
        if (
            set(record)
            != {
                "bytes",
                "mode",
                "open_count",
                "path",
                "sha256",
                "syscalls",
            }
            or not isinstance(record["bytes"], int)
            or record["bytes"] < 0
            or not isinstance(record["open_count"], int)
            or record["open_count"] < 0
            or len(record["sha256"]) != 64
        ):
            raise AccessProbeError(
                f"{plan['benchmark_id']} invalid trace record"
            )


def route(path: str) -> str:
    for tree in RULE_TREES:
        prefix = f"{CONTAINER_RULE_ROOT}/{tree}/"
        if path.startswith(prefix):
            return f"rules/{tree}"
    if path.startswith("/opt/die-build/"):
        return "build"
    if path.startswith("/bench/"):
        return "corpus"
    if path == "/etc/ld.so.cache":
        return "loader_cache"
    if path.startswith(("/usr/lib/", "/lib/")):
        return "system_library"
    return "other"


def case_summary(
    traces: list[dict[str, Any]],
) -> dict[str, Any]:
    first_records = traces[0]["successful_regular_files"]
    if any(
        trace["successful_regular_files"] != first_records
        for trace in traces[1:]
    ):
        raise AccessProbeError(
            "repeated successful file closures differ"
        )
    first_volatile = traces[0]["volatile_regular_paths"]
    if any(
        trace["volatile_regular_paths"] != first_volatile
        for trace in traces[1:]
    ):
        raise AccessProbeError("repeated volatile paths differ")
    routes: dict[str, dict[str, int]] = {}
    for record in first_records:
        item = routes.setdefault(
            route(record["path"]),
            {"file_count": 0, "bytes": 0},
        )
        item["file_count"] += 1
        item["bytes"] += record["bytes"]
    return {
        "trace_repetitions": len(traces),
        "successful_regular_file_count": len(first_records),
        "successful_regular_file_bytes": sum(
            record["bytes"] for record in first_records
        ),
        "records_sha256": sha256(canonical_json(first_records)),
        "route_summary": {
            name: routes[name] for name in sorted(routes)
        },
        "volatile_regular_paths": first_volatile,
        "repeated_records_identical": True,
    }


def rule_inventory(repo: Path) -> dict[str, dict[str, Any]]:
    result = {}
    for tree in RULE_TREES:
        root = repo / f"upstream/Detect-It-Easy/{tree}"
        files = sorted(
            (path for path in root.rglob("*") if path.is_file()),
            key=lambda path: path.relative_to(root)
            .as_posix()
            .encode("utf-8"),
        )
        records = [
            {
                "path": (
                    f"{CONTAINER_RULE_ROOT}/{tree}/"
                    f"{path.relative_to(root).as_posix()}"
                ),
                "bytes": path.stat().st_size,
                "sha256": file_sha256(path),
            }
            for path in files
        ]
        result[tree] = {
            "file_count": len(records),
            "bytes": sum(record["bytes"] for record in records),
            "records": records,
            "records_sha256": sha256(canonical_json(records)),
        }
    return result


def build_report(
    repo: Path,
    image: str,
    plans_path: Path,
    baseline_path: Path,
) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    tracer_path = repo / TRACER
    tracer_sha256 = file_sha256(tracer_path)
    probe, plans, baseline, baseline_raw = load_inputs(
        repo,
        plans_path,
        baseline_path,
    )
    image_identity = probe.docker_inspect(image)
    if image_identity["id"] != EXPECTED_IMAGE_ID:
        raise AccessProbeError("benchmark image ID mismatch")
    limits = plans["container_limits"]
    cgroup = probe.observe_cgroup(
        image,
        limits,
        cpuset_cpu=EXPECTED_CPU,
    )
    traces_by_case = {}
    cases = {}
    for plan in plans["plans"]:
        benchmark_id = plan["benchmark_id"]
        baseline_case = baseline["case_reports"][benchmark_id][
            "report"
        ]
        traces = []
        for _ in range(TRACE_REPETITIONS):
            trace = run_trace(
                repo,
                image,
                limits,
                tracer_path,
                plan,
            )
            validate_trace(
                trace,
                tracer_sha256,
                plan,
                baseline_case,
            )
            traces.append(trace)
        traces_by_case[benchmark_id] = traces
        cases[benchmark_id] = case_summary(traces)

    union: dict[str, dict[str, Any]] = {}
    for benchmark_id, traces in traces_by_case.items():
        for record in traces[0]["successful_regular_files"]:
            item = union.setdefault(
                record["path"],
                {
                    "path": record["path"],
                    "bytes": record["bytes"],
                    "mode": record["mode"],
                    "sha256": record["sha256"],
                    "cases": [],
                    "syscalls": set(),
                },
            )
            if (
                item["bytes"] != record["bytes"]
                or item["mode"] != record["mode"]
                or item["sha256"] != record["sha256"]
            ):
                raise AccessProbeError(
                    f"file identity differs across cases: "
                    f"{record['path']}"
                )
            item["cases"].append(benchmark_id)
            item["syscalls"].update(record["syscalls"])
    union_records = [
        {
            **{
                key: value
                for key, value in union[path].items()
                if key != "syscalls"
            },
            "cases": sorted(union[path]["cases"]),
            "syscalls": sorted(union[path]["syscalls"]),
            "route": route(path),
        }
        for path in sorted(union)
    ]
    accessed_rule_paths = {
        record["path"]
        for record in union_records
        if record["route"].startswith("rules/")
    }
    inventory = rule_inventory(repo)
    rule_access = {}
    for tree in RULE_TREES:
        source = inventory[tree]
        accessed = [
            record
            for record in source["records"]
            if record["path"] in accessed_rule_paths
        ]
        missing = [
            record
            for record in source["records"]
            if record["path"] not in accessed_rule_paths
        ]
        rule_access[tree] = {
            "asset_file_count": source["file_count"],
            "asset_bytes": source["bytes"],
            "asset_records_sha256": source["records_sha256"],
            "successfully_opened_file_count": len(accessed),
            "successfully_opened_bytes": sum(
                record["bytes"] for record in accessed
            ),
            "missing_file_count": len(missing),
            "missing_bytes": sum(
                record["bytes"] for record in missing
            ),
            "missing_records": missing,
            "missing_records_sha256": sha256(
                canonical_json(missing)
            ),
        }
    relationships = {
        "all_cases_match_affinity_baseline_outputs": True,
        "all_case_closures_repeat_identically": all(
            case["repeated_records_identical"]
            for case in cases.values()
        ),
        "all_union_files_have_stable_identity": True,
        "rule_access_is_a_strict_subset_of_assets": (
            sum(
                item["successfully_opened_file_count"]
                for item in rule_access.values()
            )
            < sum(
                item["asset_file_count"]
                for item in rule_access.values()
            )
        ),
        "cold_cache_is_not_claimed": True,
    }
    if not all(relationships.values()):
        raise AccessProbeError("file-access relationships failed")
    generator_raw = Path(__file__).read_bytes()
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": GENERATOR,
        "generator_sha256": sha256(generator_raw),
        "tracer": {
            "path": TRACER,
            "sha256": tracer_sha256,
            "scope": (
                "successful open/openat/openat2 regular files plus "
                "the execve executable and kernel exec mappings"
            ),
        },
        "upstream_commit": EXPECTED_REVISION,
        "environment": {
            "network": "none",
            "image": image,
            "image_identity": image_identity,
            "container_limits": limits,
            "cgroup": cgroup,
            "cpu_affinity": {
                "requested_cpuset_cpu": EXPECTED_CPU,
                "scope": "linux_vcpu",
            },
        },
        "plan_suite": {
            "path": plans_path.relative_to(repo).as_posix(),
            "sha256": EXPECTED_PLAN_SHA256,
        },
        "affinity_baseline": {
            "path": baseline_path.relative_to(repo).as_posix(),
            "bytes": len(baseline_raw),
            "sha256": sha256(baseline_raw),
        },
        "trace_repetitions_per_case": TRACE_REPETITIONS,
        "cases": {name: cases[name] for name in sorted(cases)},
        "successful_regular_file_union": {
            "file_count": len(union_records),
            "bytes": sum(
                record["bytes"] for record in union_records
            ),
            "records_sha256": sha256(
                canonical_json(union_records)
            ),
            "records": union_records,
        },
        "rule_asset_access": rule_access,
        "relationships": relationships,
        "scope": {
            "platform": "Linux x86_64",
            "successful_regular_file_access_closure": True,
            "failed_lookup_closure": False,
            "directory_and_metadata_cache_closure": False,
            "descendant_process_access_closure": False,
            "page_residency_observed": False,
            "posix_fadvise_executed": False,
            "cold_cache_controlled": False,
            "cold_benchmark_collected": False,
            "performance_timings_from_ptrace": False,
        },
        "limitations": [
            "ptrace records only successful open/openat/openat2 regular files, the execve executable, and kernel exec mappings; failed lookups, directories, dentry/inode cache, and untraced descendants are outside this closure",
            "the repeated traces validate closure stability and output identity but ptrace timings are intentionally discarded",
            "the union is a candidate regular-file set for a future advisory eviction controller, not proof that page-cache residency can be fully cleared",
            "cold cache and cold benchmark claims remain false until residency observation, controlled eviction, and the non-file cache boundaries are designed and validated",
        ],
    }


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=root)
    parser.add_argument("--image", default=EXPECTED_IMAGE)
    parser.add_argument(
        "--plans",
        type=Path,
        default=(
            root
            / "docs/research/data/upstream-benchmark-plans.json"
        ),
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=(
            root
            / "docs/research/data/"
            "upstream-benchmark-linux-qt5-affinity.json"
        ),
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = build_report(
            args.repo,
            args.image,
            args.plans,
            args.baseline,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(serialize(report))
    except (
        AccessProbeError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"file-access probe error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

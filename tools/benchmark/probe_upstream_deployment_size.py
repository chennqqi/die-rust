#!/usr/bin/env python3
"""Capture and verify the pinned Linux Qt5 upstream deployment size."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


SCHEMA_VERSION = 1
EXPECTED_REVISION = "74eaf505c250ab47e709024e9dc41657cd8f2254"
EXPECTED_CLI_SHA256 = (
    "da1fab49f7ba5970d1fc1c7fe3d4f380c"
    "f5e8775dd8097207e7b3c30f08236cf"
)
EXPECTED_DIRECT_NEEDED = [
    "libQt5Script.so.5",
    "libQt5Core.so.5",
    "libstdc++.so.6",
    "libm.so.6",
    "libgcc_s.so.1",
    "libc.so.6",
]
EXPECTED_RULE_IDENTITY = {
    "bytes": 2_909_316,
    "combined_tree_sha256": (
        "20f2b74effc2bdaf069e3b2e13060432b"
        "8890d38364511f5cde56a337348bfda"
    ),
    "commit": "c2c17dfa5ea4e078ba31eab55d87430c96622fb6",
    "file_count": 2_268,
}
EXPECTED_DEPENDENCY_CLOSURE_SHA256 = (
    "96e11fd18f8f1d289a345ecacc10f328b"
    "d7b3e2148dcfca29a04824d6e2189b2"
)
INSPECTOR_PATH = "/opt/die-size/inspect_upstream_deployment.py"


class ProbeError(ValueError):
    """The deployment-size evidence is incomplete or ambiguous."""


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(raw: bytes, description: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError(f"invalid {description} JSON: {error}") from error
    if not isinstance(value, dict):
        raise ProbeError(f"{description} root must be an object")
    return value


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


def docker_inspect(image: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        capture_output=True,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, list) or len(value) != 1:
        raise ProbeError("unexpected docker image inspect result")
    inspected = value[0]
    labels = inspected.get("Config", {}).get("Labels", {})
    revision = labels.get("org.opencontainers.image.revision")
    if revision != EXPECTED_REVISION:
        raise ProbeError(f"image revision mismatch: {revision!r}")
    return {
        "id": inspected["Id"],
        "repo_digests": sorted(inspected.get("RepoDigests") or []),
        "revision": revision,
    }


def run_container(image: str, arguments: list[str]) -> bytes:
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            image,
            *arguments,
        ],
        capture_output=True,
        timeout=120,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")
        raise ProbeError(
            f"container exited {completed.returncode}: {stderr}"
        )
    if completed.stderr:
        raise ProbeError("container emitted stderr")
    return completed.stdout


def load_rule_identity(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    report = parse_json(raw, "runtime rule asset report")
    inventory = report["inventory"]
    return {
        "bytes": inventory["byte_count"],
        "combined_tree_sha256": report["identity"][
            "combined_tree_sha256"
        ],
        "commit": report["scope"]["commit"],
        "file_count": inventory["file_count"],
        "trees": [
            {
                "bytes": tree["byte_count"],
                "file_count": tree["file_count"],
                "path": tree["path"],
                "tree_sha256": tree["tree_sha256"],
            }
            for tree in inventory["trees"]
        ],
    }, raw


def evaluate_report(report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if report.get("schema_version") != SCHEMA_VERSION:
        failures.append("schema_version")
    if report.get("upstream_commit") != EXPECTED_REVISION:
        failures.append("upstream_commit")
    if report.get("baseline_scope") != "descriptive_upstream_only":
        failures.append("baseline_scope")
    if report.get("targets_frozen") is not False:
        failures.append("targets_frozen")
    environment = report.get("environment", {})
    if (
        environment.get("image_identity", {}).get("revision")
        != EXPECTED_REVISION
    ):
        failures.append("image_revision")
    analyzer = report.get("analyzer", {})
    if analyzer.get("image_sha256") != analyzer.get("repository_sha256"):
        failures.append("analyzer_sha256")
    measurement = report.get("measurement", {})
    if measurement.get("schema_version") != 1:
        failures.append("measurement_schema")
        return failures
    if report.get("measurement_sha256") != sha256(serialize(measurement)):
        failures.append("measurement_sha256")
    binary = measurement.get("binary", {})
    if binary.get("sha256") != EXPECTED_CLI_SHA256:
        failures.append("binary.sha256")
    if binary.get("direct_needed") != EXPECTED_DIRECT_NEEDED:
        failures.append("binary.direct_needed")
    if binary.get("bytes", 0) <= 0:
        failures.append("binary.bytes")

    dependencies = measurement.get(
        "dynamic_dependencies", {}
    ).get("dependencies", [])
    real_paths = [item.get("real_path") for item in dependencies]
    if not dependencies:
        failures.append("dependencies.empty")
    if len(real_paths) != len(set(real_paths)):
        failures.append("dependencies.real_path_unique")
    for index, item in enumerate(dependencies):
        if item.get("bytes", 0) <= 0:
            failures.append(f"dependencies.{index}.bytes")
        digest = item.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            failures.append(f"dependencies.{index}.sha256")
        requested_names = item.get("requested_names")
        resolved_paths = item.get("resolved_paths")
        if (
            not isinstance(requested_names, list)
            or not requested_names
            or requested_names != sorted(set(requested_names))
        ):
            failures.append(f"dependencies.{index}.requested_names")
        if (
            not isinstance(resolved_paths, list)
            or not resolved_paths
            or resolved_paths != sorted(set(resolved_paths))
            or any(
                not isinstance(path, str) or not path.startswith("/")
                for path in resolved_paths
            )
        ):
            failures.append(f"dependencies.{index}.resolved_paths")
        if (
            not isinstance(item.get("real_path"), str)
            or not item["real_path"].startswith("/")
        ):
            failures.append(f"dependencies.{index}.real_path")
    direct_names = {
        name
        for item in dependencies
        if item.get("direct") is True
        for name in item.get("requested_names", [])
    }
    if direct_names != set(EXPECTED_DIRECT_NEEDED):
        failures.append("dependencies.direct_set")
    dependency_summary = measurement.get("dynamic_dependencies", {})
    if (
        dependency_summary.get("closure_sha256")
        != EXPECTED_DEPENDENCY_CLOSURE_SHA256
    ):
        failures.append("dependencies.closure_sha256")
    dependency_bytes = sum(item.get("bytes", 0) for item in dependencies)
    if dependency_summary.get("file_count") != len(dependencies):
        failures.append("dependencies.file_count")
    if dependency_summary.get("total_bytes") != dependency_bytes:
        failures.append("dependencies.total_bytes")

    rules = measurement.get("rules", {})
    expected_rules = report.get("rule_asset_identity", {})
    for field, expected in EXPECTED_RULE_IDENTITY.items():
        if expected_rules.get(field) != expected:
            failures.append(f"rule_asset_identity.{field}")
    for field in ("bytes", "combined_tree_sha256", "file_count", "trees"):
        if rules.get(field) != expected_rules.get(field):
            failures.append(f"rules.{field}")

    totals = measurement.get("totals", {})
    binary_bytes = binary.get("bytes", 0)
    rules_bytes = rules.get("bytes", 0)
    expected_totals = {
        "binary_and_dependencies_bytes": binary_bytes + dependency_bytes,
        "binary_and_rules_bytes": binary_bytes + rules_bytes,
        "full_closure_and_rules_bytes": (
            binary_bytes + dependency_bytes + rules_bytes
        ),
    }
    if totals != expected_totals:
        failures.append("totals")
    host = measurement.get("host", {})
    if host.get("system") != "Linux":
        failures.append("host.system")
    if host.get("machine") != "x86_64":
        failures.append("host.machine")
    contract = report.get("comparison_contract", {})
    if contract.get("primary_metrics") != [
        "binary_and_rules_bytes",
        "full_closure_and_rules_bytes",
    ]:
        failures.append("comparison_contract.primary_metrics")
    return failures


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument(
        "--rule-assets-report",
        type=Path,
        default=(
            root
            / "docs"
            / "research"
            / "data"
            / "runtime-rule-assets-license.json"
        ),
    )
    parser.add_argument(
        "--inspector",
        type=Path,
        default=(
            root
            / "tools"
            / "benchmark"
            / "inspect_upstream_deployment.py"
        ),
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    image_identity = docker_inspect(args.image)
    local_inspector = args.inspector.read_bytes()
    image_inspector = run_container(
        args.image,
        ["cat", INSPECTOR_PATH],
    )
    measurement_raw = run_container(
        args.image,
        ["python3", INSPECTOR_PATH],
    )
    measurement = parse_json(measurement_raw, "deployment measurement")
    rule_identity, raw_rule_report = load_rule_identity(
        args.rule_assets_report
    )
    report: dict[str, Any] = {
        "analyzer": {
            "image_path": INSPECTOR_PATH,
            "image_sha256": sha256(image_inspector),
            "repository_path": (
                "tools/benchmark/inspect_upstream_deployment.py"
            ),
            "repository_sha256": sha256(local_inspector),
        },
        "baseline_scope": "descriptive_upstream_only",
        "comparison_contract": {
            "limitations": [
                "binary bytes alone omit dynamic libraries and runtime rules",
                "full closure includes OS libraries that a package manager may supply",
                "a release bundle may add metadata, licenses, launchers, or compression",
                "this Linux x86_64 result cannot represent other target platforms",
            ],
            "primary_metrics": [
                "binary_and_rules_bytes",
                "full_closure_and_rules_bytes",
            ],
        },
        "environment": {
            "image": args.image,
            "image_identity": image_identity,
            "network": "none",
        },
        "measurement": measurement,
        "measurement_sha256": sha256(serialize(measurement)),
        "rule_asset_identity": rule_identity,
        "rule_asset_report": {
            "path": "docs/research/data/runtime-rule-assets-license.json",
            "sha256": sha256(raw_rule_report),
        },
        "schema_version": SCHEMA_VERSION,
        "targets_frozen": False,
        "upstream_commit": EXPECTED_REVISION,
    }
    failures = evaluate_report(report)
    report["failures"] = failures
    report["passed"] = not failures
    raw = serialize(report)
    if args.output is None:
        sys.stdout.buffer.write(raw)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(raw)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

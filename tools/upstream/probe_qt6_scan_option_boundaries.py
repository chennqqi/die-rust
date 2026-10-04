#!/usr/bin/env python3
"""Compare fixed Qt6 scan-option boundaries with the committed Qt5 oracle."""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys
from typing import Any


QT6_WARNING = b"Unimplemented code.\n" * 4
QT6_ORACLE_NAME = "linux-qt6-cmake"
QT6_IMAGE = "die-rust/upstream-oracle-cmake-qt6:74eaf505"
QT6_BINARY = "/opt/die-build/src/console/diec"
REPETITIONS = 2


def _load_qt5_probe():
    module_path = pathlib.Path(__file__).with_name(
        "probe_scan_option_boundaries.py"
    )
    spec = importlib.util.spec_from_file_location(
        "_diec_qt5_scan_option_boundaries",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Qt5 scan-option probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BASE = _load_qt5_probe()
QT6_ORACLE = BASE.Oracle(QT6_ORACLE_NAME, QT6_IMAGE, QT6_BINARY)


def qt5_reference(
    report_path: pathlib.Path,
    manifest_sha256: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, str], str]:
    report_bytes = report_path.read_bytes()
    report = BASE.strict_json(report_bytes)
    if not isinstance(report, dict):
        raise ValueError("Qt5 report must be an object")
    if (
        report.get("schema_version") != 1
        or report.get("upstream_commit") != BASE.UPSTREAM_COMMIT
        or report.get("platform") != "linux-x86_64-qt5"
        or report.get("passed") is not True
        or report.get("failures") != []
    ):
        raise ValueError("Qt5 reference identity changed")
    if report["fixture_manifest"]["sha256"] != manifest_sha256:
        raise ValueError("Qt5 reference fixture differs")
    oracle = report["observations"]["linux-qt5-cmake"]
    summaries = {
        case.name: oracle["cases"][case.name]["summary"]
        for case in BASE.CASES
    }
    identity = {
        "resource_source_sha256": oracle["resource_source_sha256"],
        "console_source_sha256": oracle["console_source_sha256"],
        "pe_source_sha256": oracle["pe_source_sha256"],
    }
    return summaries, identity, BASE.sha256(report_bytes)


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
    qt5_report_path: pathlib.Path,
) -> dict[str, Any]:
    manifest, manifest_sha256 = BASE.load_fixture(
        fixture_dir,
        manifest_path,
    )
    qt5_summaries, qt5_sources, qt5_report_sha256 = qt5_reference(
        qt5_report_path,
        manifest_sha256,
    )
    identity = BASE.inspect_image(QT6_ORACLE)
    qt6_sources = {
        key: identity[key]
        for key in (
            "resource_source_sha256",
            "console_source_sha256",
            "pe_source_sha256",
        )
    }
    if qt6_sources != qt5_sources:
        raise ValueError("Qt5 and Qt6 upstream source identities differ")

    raw_artifacts: dict[str, dict[str, Any]] = {}
    cases: dict[str, Any] = {}
    qt6_summaries: dict[str, dict[str, Any]] = {}
    warning_cases: list[str] = []
    for case in BASE.CASES:
        executions = []
        raw_pairs: list[tuple[bytes, bytes]] = []
        summaries = []
        for _ in range(REPETITIONS):
            process = BASE.observe(QT6_ORACLE, fixture_dir, case)
            if process.returncode != 0:
                raise ValueError(f"Qt6 execution failed: {case.name}")
            if process.stderr not in (b"", QT6_WARNING):
                raise ValueError(
                    f"unclassified Qt6 stderr: {case.name}"
                )
            document = BASE.strict_json(process.stdout)
            summary = BASE.summarize_document(document)
            summaries.append(summary)
            raw_pairs.append((process.stdout, process.stderr))
            executions.append(
                {
                    "exit_code": process.returncode,
                    "stdout": BASE.raw_stream(
                        process.stdout,
                        raw_artifacts,
                    ),
                    "stderr": BASE.raw_stream(
                        process.stderr,
                        raw_artifacts,
                    ),
                }
            )
        if raw_pairs[0] != raw_pairs[1]:
            raise ValueError(f"Qt6 raw output is unstable: {case.name}")
        if summaries[0] != summaries[1]:
            raise ValueError(
                f"Qt6 normalized output is unstable: {case.name}"
            )
        if raw_pairs[0][1] == QT6_WARNING:
            warning_cases.append(case.name)
        qt6_summaries[case.name] = summaries[0]
        cases[case.name] = {
            "sample": case.sample,
            "arguments": list(BASE.arguments(case)),
            "summary": summaries[0],
            "executions": executions,
        }

    BASE.validate_summaries(qt6_summaries)
    if qt6_summaries != qt5_summaries:
        raise ValueError("Qt5 and Qt6 normalized boundary outputs differ")

    facts = {
        "qt6_two_repetitions_are_raw_equal": True,
        "qt5_qt6_normalized_outputs_are_equal": True,
        "qt5_qt6_upstream_sources_are_equal": True,
        "default_scanable_resource_limit_is_inclusive_21": True,
        "aggressive_resource_limit_is_inclusive_2001": True,
        "resource_children_preserve_enumeration_order": True,
        "qt6_stderr_is_empty_or_known_four_line_diagnostic": True,
    }
    repo = pathlib.Path(__file__).resolve().parents[2]
    return {
        "schema_version": 1,
        "generator": (
            "tools/upstream/probe_qt6_scan_option_boundaries.py"
        ),
        "generator_sha256": BASE.sha256(
            pathlib.Path(__file__).read_bytes()
        ),
        "upstream_commit": BASE.UPSTREAM_COMMIT,
        "platform": "linux-x86_64-qt6",
        "resource_limits": {
            "network": "none",
            "cpus": 1,
            "memory_bytes": 512 * 1024 * 1024,
            "pids": 128,
            "timeout_seconds_per_execution": 180,
            "fixture_mount": "read-only",
            "container_root": "read-only",
        },
        "fixture_manifest": {
            "path": (
                "docs/research/data/"
                "scan-option-boundary-fixture.json"
            ),
            "sha256": manifest_sha256,
            "entry_count": len(manifest["entries"]),
        },
        "qt5_reference": {
            "path": (
                "docs/research/data/"
                "scan-option-boundaries-linux-qt5.json"
            ),
            "sha256": qt5_report_sha256,
            "oracle": "linux-qt5-cmake",
        },
        "local_sources": {
            "qt6_probe": {
                "path": (
                    "tools/upstream/"
                    "probe_qt6_scan_option_boundaries.py"
                ),
                "sha256": BASE.sha256(
                    pathlib.Path(__file__).read_bytes()
                ),
            },
            "qt5_probe": {
                "path": (
                    "tools/upstream/"
                    "probe_scan_option_boundaries.py"
                ),
                "sha256": BASE.sha256(
                    pathlib.Path(BASE.__file__).read_bytes()
                ),
            },
            "fixture_generator": {
                "path": BASE.FIXTURE_GENERATOR,
                "sha256": BASE.sha256(
                    (
                        repo
                        / "tools"
                        / "corpus"
                        / "generate_scan_option_boundary_fixture.py"
                    ).read_bytes()
                ),
            },
        },
        "source_audit": BASE.source_audit(QT6_IMAGE),
        "observation": {
            **identity,
            "image": QT6_IMAGE,
            "binary": QT6_BINARY,
            "repetitions": REPETITIONS,
            "cases": cases,
        },
        "known_qt6_diagnostic": {
            "stderr_bytes_per_affected_execution": len(QT6_WARNING),
            "stderr_sha256_per_affected_execution": BASE.sha256(
                QT6_WARNING
            ),
            "affected_cases": warning_cases,
            "raw_streams_retained": True,
        },
        "raw_artifacts": raw_artifacts,
        "facts": facts,
        "passed": all(facts.values()),
        "failures": [],
        "closed_capability": "CAP-NEST-004",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    repo = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument("--fixture-dir", required=True, type=pathlib.Path)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=(
            repo
            / "docs"
            / "research"
            / "data"
            / "scan-option-boundary-fixture.json"
        ),
    )
    parser.add_argument(
        "--qt5-report",
        type=pathlib.Path,
        default=(
            repo
            / "docs"
            / "research"
            / "data"
            / "scan-option-boundaries-linux-qt5.json"
        ),
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    report = build_report(
        args.fixture_dir.resolve(),
        args.manifest.resolve(),
        args.qt5_report.resolve(),
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

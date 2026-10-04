#!/usr/bin/env python3
"""Compare pinned Qt5/Qt6 nested archive depth and byte observations."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
CAPABILITY = "CAP-NEST-009"
PROBE_PATH = "tools/upstream/probe_archive_limits_harness.py"
QT5_REPORT_PATH = "docs/research/data/archive-limit-engine-qt5.json"
CORPUS_PATH = "docs/research/data/archive-limit-corpus.json"
QT6_IMAGE = (
    "die-rust/upstream-archive-limits-harness-qt6:74eaf505"
)
QT6_BINARY = "/opt/die-build/src/console/die-archive-limits-harness"
LOCAL_SOURCES = (
    "tools/upstream/Dockerfile.archive-limits-harness-qt6",
    "tools/upstream/archive_limits_harness_main.cpp",
    PROBE_PATH,
)
SUPPORTING_REPORTS = {
    "archive_family_and_qt5_limit_closure": (
        "docs/research/data/archive-gap-closure.json"
    ),
    "archive_iteration_boundary": (
        "docs/research/data/"
        "archive-iteration-boundary-engine-qt6.json"
    ),
    "archive_option_and_internal_recursion_gate": (
        "docs/research/data/archive-option-engine-qt5-qt6.json"
    ),
    "archive_private_and_public_dispatch": (
        "docs/research/data/archive-dispatch-linux-qt5-qt6.json"
    ),
    "cli_recursion_gate": (
        "docs/research/data/"
        "cli-scan-nested-matrix-linux-qt5-qt6.json"
    ),
    "resource_context_and_subdevice_gate": (
        "docs/research/data/resource-context-chain-qt6.json"
    ),
    "resource_record_count_boundary": (
        "docs/research/data/"
        "scan-option-boundaries-linux-qt6.json"
    ),
}
STABLE_HARNESS_FIELDS = (
    "callback_calls",
    "cancel_after_callbacks",
    "cyclic_node_count",
    "debug_record_count",
    "deepest_pdf_depth",
    "error_count",
    "handler_count",
    "max_depth",
    "max_stream_depth",
    "node_count",
    "pdf_node_count",
    "pd_stopped",
    "record_count",
    "stream_node_count",
)


class ProbeError(ValueError):
    """The fixed archive-limit oracle or comparison changed."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(data: bytes, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ProbeError(f"non-finite JSON token: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError(f"invalid {description}: {error}") from error
    if not isinstance(value, dict):
        raise ProbeError(f"{description} root must be an object")
    return value


def load_probe(root: Path) -> ModuleType:
    path = root / PROBE_PATH
    spec = importlib.util.spec_from_file_location(
        "diec_archive_limits_qt6_base",
        path,
    )
    if spec is None or spec.loader is None:
        raise ProbeError(f"cannot load archive-limit probe: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def case_projection(case: dict[str, Any]) -> dict[str, Any]:
    harness = case.get("harness")
    if not isinstance(harness, dict):
        raise ProbeError(f"missing harness result: {case.get('case')}")
    return {
        "arguments": case.get("arguments"),
        "case": case.get("case"),
        "exit_code": case.get("exit_code"),
        "harness": {
            field: harness.get(field)
            for field in STABLE_HARNESS_FIELDS
        },
        "possible_oom_exit_137": case.get("possible_oom_exit_137"),
        "sample": case.get("sample"),
        "stderr": case.get("stderr"),
        "stderr_sha256": case.get("stderr_sha256"),
        "timed_out": case.get("timed_out"),
    }


def behavior_projection(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "assertions": report.get("assertions"),
        "cancellation_case": case_projection(
            report["cancellation_case"]
        ),
        "corpus": report.get("corpus"),
        "corpus_manifest_sha256": report.get(
            "corpus_manifest_sha256"
        ),
        "normal_cases": [
            case_projection(case)
            for case in report.get("normal_cases", [])
        ],
        "source_contract": report.get("source_contract"),
        "upstream_commit": report.get("upstream_commit"),
        "xscanengine_commit": report.get("xscanengine_commit"),
    }


def projection_sha256(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def validate_supporting_reports(
    root: Path,
) -> dict[str, dict[str, str]]:
    result = {}
    for role, relative_path in SUPPORTING_REPORTS.items():
        raw = (root / relative_path).read_bytes()
        report = strict_json(raw, relative_path)
        revision = (
            report.get("upstream_commit")
            or report.get("expected_revision")
        )
        if revision != UPSTREAM_COMMIT:
            raise ProbeError(f"supporting report revision drift: {role}")
        result[role] = {
            "path": relative_path,
            "sha256": sha256(raw),
        }

    archive_gap = strict_json(
        (
            root
            / SUPPORTING_REPORTS[
                "archive_family_and_qt5_limit_closure"
            ]
        ).read_bytes(),
        "archive gap closure",
    )
    limits = archive_gap.get("depth_and_total_observation", {})
    if (
        archive_gap.get("result") != "closed"
        or limits.get("maximum_observed_depth") != 64
        or limits.get(
            "maximum_observed_cumulative_expanded_bytes"
        )
        != 33_554_546
        or limits.get(
            "source_has_no_independent_depth_or_total_token"
        )
        is not True
    ):
        raise ProbeError("Qt5 archive-limit closure reference drift")
    return result


def build_report(root: Path, corpus_dir: Path) -> dict[str, Any]:
    base = load_probe(root)
    qt5_raw = (root / QT5_REPORT_PATH).read_bytes()
    qt5 = strict_json(qt5_raw, "Qt5 archive-limit report")
    if (
        qt5.get("passed") is not True
        or qt5.get("failures") != []
        or qt5.get("upstream_commit") != UPSTREAM_COMMIT
    ):
        raise ProbeError("Qt5 archive-limit baseline drift")

    qt6 = base.build_report(
        image_name=QT6_IMAGE,
        binary_path=QT6_BINARY,
        corpus_dir=corpus_dir,
        reference_manifest=root / CORPUS_PATH,
        platform="linux-x86_64-qt6",
    )
    if qt6.get("passed") is not True or qt6.get("failures") != []:
        raise ProbeError("Qt6 archive-limit assertions failed")

    qt5_projection = behavior_projection(qt5)
    qt6_projection = behavior_projection(qt6)
    projection_equal = qt5_projection == qt6_projection
    if not projection_equal:
        raise ProbeError("Qt5/Qt6 archive-limit behavior differs")

    deepest = max(
        qt6["corpus"]["samples"],
        key=lambda sample: sample["depth"],
    )
    largest = max(
        qt6["corpus"]["samples"],
        key=lambda sample: sample["cumulative_expanded_bytes"],
    )
    supporting = validate_supporting_reports(root)
    local_sources = {
        path: sha256((root / path).read_bytes())
        for path in LOCAL_SOURCES
    }
    facts = {
        "cancellation_partial_prefix_is_equal": (
            qt5_projection["cancellation_case"]
            == qt6_projection["cancellation_case"]
        ),
        "depth_64_is_reached_on_both_qt_versions": (
            deepest["depth"] == 64
            and next(
                case
                for case in qt6_projection["normal_cases"]
                if case["sample"] == deepest["name"]
            )["harness"]["deepest_pdf_depth"]
            == 64
        ),
        "expanded_33554546_bytes_is_reached_on_both_qt_versions": (
            largest["cumulative_expanded_bytes"] == 33_554_546
            and next(
                case
                for case in qt6_projection["normal_cases"]
                if case["sample"] == largest["name"]
            )["harness"]["deepest_pdf_depth"]
            == 2
        ),
        "full_stable_behavior_projection_is_equal": projection_equal,
        "raw_qt6_stdout_stderr_are_retained": all(
            isinstance(case.get("stdout"), str)
            and isinstance(case.get("stderr"), str)
            for case in [
                *qt6["normal_cases"],
                qt6["cancellation_case"],
            ]
        ),
        "source_contract_is_equal": (
            qt5["source_contract"] == qt6["source_contract"]
        ),
        "local_probe_sources_are_hash_bound": (
            set(local_sources) == set(LOCAL_SOURCES)
        ),
        "supporting_nested_boundaries_are_hash_bound": (
            set(supporting) == set(SUPPORTING_REPORTS)
        ),
    }
    driver = Path(__file__)
    return {
        "capability": CAPABILITY,
        "comparison": {
            "behavior_projection_equal": projection_equal,
            "behavior_projection_sha256": projection_sha256(
                qt5_projection
            ),
            "stable_harness_fields": list(STABLE_HARNESS_FIELDS),
        },
        "facts": facts,
        "failures": [],
        "generator": f"tools/upstream/{driver.name}",
        "generator_sha256": sha256(driver.read_bytes()),
        "local_sources": local_sources,
        "passed": all(facts.values()),
        "platform": "linux-x86_64-qt5-qt6",
        "qt5_reference": {
            "path": QT5_REPORT_PATH,
            "sha256": sha256(qt5_raw),
        },
        "qt6": qt6,
        "schema_version": 1,
        "supporting_reports": supporting,
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


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = build_report(root, args.corpus_dir.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(serialize(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

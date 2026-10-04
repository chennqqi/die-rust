#!/usr/bin/env python3
"""Run the five fixed result-model harnesses on the Qt6 oracle."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any


GENERATOR = "tools/upstream/probe_qt6_result_model.py"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
PROFILES = {
    "metadata": {
        "probe": "tools/upstream/probe_result_metadata_harness.py",
        "image": "die-rust/result-metadata-harness-qt6:74eaf505",
        "qt5_report": (
            "docs/research/data/result-metadata-engine-qt5.json"
        ),
    },
    "lists": {
        "probe": "tools/upstream/probe_result_lists_harness.py",
        "image": "die-rust/result-lists-harness-qt6:74eaf505",
        "qt5_report": "docs/research/data/result-lists-engine-qt5.json",
    },
    "ids": {
        "probe": "tools/upstream/probe_result_ids_harness.py",
        "image": "die-rust/result-ids-harness-qt6:74eaf505",
        "qt5_report": "docs/research/data/result-ids-engine-qt5.json",
    },
    "flags": {
        "probe": "tools/upstream/probe_result_flags_harness.py",
        "image": "die-rust/result-flags-harness-qt6:74eaf505",
        "qt5_report": "docs/research/data/result-flags-engine-qt5.json",
    },
    "enums": {
        "probe": "tools/upstream/probe_result_enums_harness.py",
        "image": "die-rust/result-enums-harness-qt6:74eaf505",
        "qt5_report": "docs/research/data/result-enums-engine-qt5.json",
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_probe(root: Path, profile: str) -> Any:
    path = root / str(PROFILES[profile]["probe"])
    spec = importlib.util.spec_from_file_location(
        f"_diec_qt6_result_{profile}_underlying", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load result-{profile} probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.IMAGE = PROFILES[profile]["image"]
    return module


def scalar_differences(
    left: Any, right: Any, path: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    if type(left) is not type(right):
        return [{"path": "/".join(path), "qt5": left, "qt6": right}]
    if isinstance(left, dict):
        differences = []
        for key in sorted(set(left) | set(right)):
            child_path = (*path, str(key))
            if key not in left or key not in right:
                differences.append(
                    {
                        "path": "/".join(child_path),
                        "qt5": left.get(key, "<missing>"),
                        "qt6": right.get(key, "<missing>"),
                    }
                )
            else:
                differences.extend(
                    scalar_differences(
                        left[key],
                        right[key],
                        child_path,
                    )
                )
        return differences
    if isinstance(left, list):
        if len(left) != len(right):
            return [
                {
                    "path": "/".join((*path, "length")),
                    "qt5": len(left),
                    "qt6": len(right),
                }
            ]
        differences = []
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            differences.extend(
                scalar_differences(
                    left_item,
                    right_item,
                    (*path, str(index)),
                )
            )
        return differences
    if left == right:
        return []
    return [{"path": "/".join(path), "qt5": left, "qt6": right}]


def differences_are_classified(
    profile: str, differences: list[dict[str, Any]]
) -> bool:
    paths = {item["path"] for item in differences}
    if profile == "metadata":
        return all(path.endswith("/nScanTime") for path in paths)
    if profile == "ids":
        return all(path.endswith("/uuid") for path in paths)
    if profile == "lists":
        return differences == [
            {
                "path": "cases/1/errors/1/message",
                "qt5": (
                    "Binary/d_parse_error.1.sg: 1: "
                    "SyntaxError: Parse error"
                ),
                "qt6": (
                    "Binary/d_parse_error.1.sg: 2: "
                    "SyntaxError: Expected token `}'"
                ),
            }
        ]
    return not differences


def collect_result_records(
    value: Any, path: tuple[str, ...] = ()
) -> dict[str, dict[str, Any]]:
    records = {}
    if isinstance(value, dict):
        if {"type", "name", "version", "info", "priority"} <= set(value):
            records["/".join(path)] = value
        for key, child in value.items():
            records.update(
                collect_result_records(child, (*path, str(key)))
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            records.update(
                collect_result_records(child, (*path, str(index)))
            )
    return records


def build_record_metadata_comparison(root: Path) -> dict[str, Any]:
    qt5_path = (
        root / "docs" / "research" / "data" / "global-host-api-qt5.json"
    )
    qt6_path = (
        root / "docs" / "research" / "data" / "global-host-api-qt6.json"
    )
    engine_path = (
        root
        / "docs"
        / "research"
        / "data"
        / "engine-contract-linux-qt6.json"
    )
    qt5_bytes = qt5_path.read_bytes()
    qt6_bytes = qt6_path.read_bytes()
    engine_bytes = engine_path.read_bytes()
    qt5 = json.loads(qt5_bytes)
    qt6 = json.loads(qt6_bytes)
    engine = json.loads(engine_bytes)
    qt5_records = collect_result_records(qt5["observation"])
    qt6_records = collect_result_records(qt6["observation"])
    common_paths = set(qt5_records) & set(qt6_records)
    qt5_only = sorted(set(qt5_records) - set(qt6_records))
    qt6_only = sorted(set(qt6_records) - set(qt5_records))
    expected_qt5_only = [
        (
            "isolated_query_conversions/cyclic_array_count/"
            "observation/final_records/0"
        ),
        "missing_arguments/count/records/0",
        "missing_arguments/is_present/records/0",
        "missing_arguments/set_result/records/0",
    ]
    common_equal = all(
        qt5_records[path] == qt6_records[path] for path in common_paths
    )
    common_values = [qt6_records[path] for path in sorted(common_paths)]

    engine_records = collect_result_records(engine["harness_output"])
    rule_records = [
        record
        for record in engine_records.values()
        if record.get("signature") and record.get("signature_file")
    ]
    facts = {
        "common_hostapi_records_equal": common_equal,
        "runtime_specific_record_difference_is_exact": (
            qt5_only == expected_qt5_only and not qt6_only
        ),
        "nonempty_version_and_info_are_observed": any(
            record["version"] and record["info"]
            for record in common_values
        ),
        "hostapi_priorities_cover_multiple_types": (
            {30, 70, 90}
            <= {record["priority"] for record in common_values}
        ),
        "engine_rule_name_and_path_are_observed": bool(rule_records),
        "engine_rule_priorities_are_observed": (
            {12, 30, 100}
            <= {record["priority"] for record in rule_records}
        ),
    }
    if not all(facts.values()):
        raise ValueError("result record metadata comparison failed")
    return {
        "sources": {
            "docs/research/data/global-host-api-qt5.json": sha256(
                qt5_bytes
            ),
            "docs/research/data/global-host-api-qt6.json": sha256(
                qt6_bytes
            ),
            "docs/research/data/engine-contract-linux-qt6.json": sha256(
                engine_bytes
            ),
        },
        "common_record_count": len(common_paths),
        "qt5_only_record_paths": qt5_only,
        "qt6_only_record_paths": qt6_only,
        "facts": facts,
    }


def build_report(
    list_fixture: Path,
    id_corpus: Path,
    flag_fixture: Path,
    enum_fixture: Path,
    raw_dir: Path,
) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    raw_dir.mkdir(parents=True, exist_ok=True)
    modules = {
        profile: load_probe(root, profile) for profile in PROFILES
    }
    reports = {
        "metadata": modules["metadata"].build_report(
            raw_dir / "metadata"
        ),
        "lists": modules["lists"].build_report(
            list_fixture,
            root
            / "docs"
            / "research"
            / "data"
            / "result-list-fixture.json",
            raw_dir / "lists",
        ),
        "ids": modules["ids"].build_report(
            id_corpus,
            root / "docs" / "research" / "data" / "nested-corpus.json",
            raw_dir / "ids",
        ),
        "flags": modules["flags"].build_report(
            flag_fixture,
            root
            / "docs"
            / "research"
            / "data"
            / "result-flag-fixture.json",
            raw_dir / "flags",
        ),
        "enums": modules["enums"].build_report(
            enum_fixture,
            root
            / "docs"
            / "research"
            / "data"
            / "result-enum-fixture.json",
            raw_dir / "enums",
        ),
    }
    for report in reports.values():
        report["platform"] = "linux-amd64-qt6"

    sources = {}
    comparisons = {}
    for profile, specification in PROFILES.items():
        path = root / str(specification["probe"])
        sources[str(specification["probe"])] = sha256(path.read_bytes())
        qt5_path = root / str(specification["qt5_report"])
        qt5_bytes = qt5_path.read_bytes()
        qt5 = json.loads(qt5_bytes)
        differences = scalar_differences(
            qt5["harness_output"],
            reports[profile]["harness_output"],
        )
        comparison = {
            "qt5_report": str(specification["qt5_report"]),
            "qt5_report_sha256": sha256(qt5_bytes),
            "relationships_equal": (
                qt5["relationships"] == reports[profile]["relationships"]
            ),
            "fixture_equal": (
                qt5.get("fixture") == reports[profile].get("fixture")
            ),
            "harness_output_differences": differences,
            "differences_classified": differences_are_classified(
                profile, differences
            ),
        }
        if (
            not comparison["relationships_equal"]
            or not comparison["fixture_equal"]
            or not comparison["differences_classified"]
        ):
            raise ValueError(
                f"unclassified Qt5/Qt6 result-{profile} difference"
            )
        comparisons[profile] = comparison
    return {
        "schema_version": 1,
        "generator": GENERATOR,
        "generator_sha256": sha256(Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "platform": "linux-amd64-qt6",
        "result": "observed",
        "capability_scope": [
            "CAP-RESULT-001",
            "CAP-RESULT-002",
            "CAP-RESULT-003",
            "CAP-RESULT-004",
            "CAP-RESULT-005",
            "CAP-RESULT-006",
        ],
        "underlying_probes": sources,
        "reports": reports,
        "comparisons": comparisons,
        "record_metadata_comparison": build_record_metadata_comparison(
            root
        ),
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir"
        },
        "limitations": [
            "scan times, debug elapsed times, and UUID values are nondeterministic",
            "Qt5 comparison and field-specific normalization are performed by the closure synthesis",
            "the five harnesses cover Linux amd64 and the fixed fixture revisions only",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-fixture", type=Path, required=True)
    parser.add_argument("--id-corpus", type=Path, required=True)
    parser.add_argument("--flag-fixture", type=Path, required=True)
    parser.add_argument("--enum-fixture", type=Path, required=True)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(
        args.list_fixture.resolve(),
        args.id_corpus.resolve(),
        args.flag_fixture.resolve(),
        args.enum_fixture.resolve(),
        args.raw_dir.resolve(),
    )
    args.output.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Replay the complete pinned Linux Qt5 path boundary on the Qt6 oracle."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys
from types import ModuleType
from typing import Any, Callable


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
QT6_IMAGE = "die-rust/upstream-oracle-cmake-qt6:74eaf505"
QT6_BINARY = "/opt/die-build/src/console/diec"
DATA_DIR = "docs/research/data"
PROBE_DIR = "tools/upstream"
RUNTIME_FIELDS = {
    "host_wall_elapsed_ms",
    "usage",
    "wall_elapsed_ms",
}
COMPARISON_VOLATILE_FIELDS = RUNTIME_FIELDS | {"device", "inode"}

SUITES = (
    {
        "id": "special_path",
        "module": "probe_special_path_behavior.py",
        "baseline": "special-path-engine-qt5.json",
    },
    {
        "id": "filesystem",
        "module": "probe_path_filesystem_behavior.py",
        "baseline": "path-filesystem-engine-qt5.json",
    },
    {
        "id": "large_directory",
        "module": "probe_large_path_behavior.py",
        "baseline": "large-path-engine-qt5.json",
    },
    {
        "id": "toctou",
        "module": "probe_path_toctou_behavior.py",
        "baseline": "path-toctou-engine-qt5.json",
    },
    {
        "id": "locale_filesystem",
        "module": "probe_path_locale_filesystem_behavior.py",
        "baseline": "path-locale-filesystem-engine-qt5.json",
    },
)


class ProbeError(ValueError):
    """The fixed input, oracle, or path behavior changed."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProbeError(f"non-finite JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError(f"invalid JSON: {error}") from error


def load_module(path: pathlib.Path, suite_id: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        f"diec_qt6_path_{suite_id}", path
    )
    if spec is None or spec.loader is None:
        raise ProbeError(f"cannot load probe module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def strip_fields(value: Any, excluded: set[str]) -> Any:
    if isinstance(value, dict):
        return {
            key: strip_fields(child, excluded)
            for key, child in value.items()
            if key not in excluded
        }
    if isinstance(value, list):
        return [strip_fields(child, excluded) for child in value]
    return value


def behavior_projection(report: dict[str, Any]) -> dict[str, Any]:
    admitted = (
        "cases",
        "facts",
        "fixture",
        "locale_inventory",
        "matrix",
        "output_equivalence",
        "raw_artifacts",
        "source_contract",
        "upstream_commit",
    )
    return strip_fields(
        {key: report[key] for key in admitted if key in report},
        COMPARISON_VOLATILE_FIELDS,
    )


def projection_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(encoded)


def rename_repetitions(value: Any) -> Any:
    if isinstance(value, list):
        return [rename_repetitions(child) for child in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"cmake", "qmake"}:
        first = rename_repetitions(value["qmake"])
        second = rename_repetitions(value["cmake"])
        return {
            "repetition_1": first,
            "repetition_2": second,
        }
    return {
        key: rename_repetitions(child)
        for key, child in value.items()
    }


def prepare_qt6_report(report: dict[str, Any]) -> dict[str, Any]:
    stable = strip_fields(copy.deepcopy(report), RUNTIME_FIELDS)
    images = stable.pop("images")
    binaries = stable.pop("binaries")
    if images["qmake"] != images["cmake"]:
        raise ProbeError("Qt6 repetition image identities differ")
    if binaries["qmake"] != binaries["cmake"]:
        raise ProbeError("Qt6 repetition binary identities differ")
    stable["qt6_oracle"] = images["qmake"]
    stable["qt6_binary"] = binaries["qmake"]
    stable["platform"] = "linux-x86_64-qt6"
    stable.pop("remaining_gap", None)
    facts = stable.get("facts")
    if isinstance(facts, dict):
        if facts.pop("qmake_and_cmake_outputs_are_byte_equal", None) is True:
            facts["qt6_repetitions_are_byte_equal"] = True
    return rename_repetitions(stable)


def invoke_suite(
    *,
    root: pathlib.Path,
    suite: dict[str, str],
    special_fixture_dir: pathlib.Path,
    filesystem_fixture_dir: pathlib.Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    module_path = root / PROBE_DIR / suite["module"]
    module = load_module(module_path, suite["id"])
    module.ORACLES = {
        "qmake": {"image": QT6_IMAGE, "binary": QT6_BINARY},
        "cmake": {"image": QT6_IMAGE, "binary": QT6_BINARY},
    }
    manifest = root / module.FIXTURE_MANIFEST
    builders: dict[str, Callable[[], dict[str, Any]]] = {
        "special_path": lambda: module.build_report(
            special_fixture_dir, manifest
        ),
        "filesystem": lambda: module.build_report(
            filesystem_fixture_dir, manifest
        ),
        "large_directory": lambda: module.build_report(manifest),
        "toctou": lambda: module.build_report(manifest),
        "locale_filesystem": lambda: module.build_report(manifest),
    }
    raw_qt6 = builders[suite["id"]]()
    baseline_path = root / DATA_DIR / suite["baseline"]
    baseline_raw = baseline_path.read_bytes()
    baseline = strict_json(baseline_raw)
    if not isinstance(baseline, dict) or not isinstance(raw_qt6, dict):
        raise ProbeError(f"invalid report root: {suite['id']}")
    qt5_projection = behavior_projection(baseline)
    qt6_projection = behavior_projection(raw_qt6)
    if qt6_projection != qt5_projection:
        raise ProbeError(f"Qt5/Qt6 behavior differs: {suite['id']}")
    comparison = {
        "behavior_projection_equal": True,
        "behavior_projection_sha256": projection_sha256(qt5_projection),
        "qt5_report_path": f"{DATA_DIR}/{suite['baseline']}",
        "qt5_report_sha256": sha256(baseline_raw),
    }
    return prepare_qt6_report(raw_qt6), comparison


def build_report(
    *,
    root: pathlib.Path,
    special_fixture_dir: pathlib.Path,
    filesystem_fixture_dir: pathlib.Path,
) -> dict[str, Any]:
    suites: dict[str, Any] = {}
    for suite in SUITES:
        qt6_report, comparison = invoke_suite(
            root=root,
            suite=suite,
            special_fixture_dir=special_fixture_dir,
            filesystem_fixture_dir=filesystem_fixture_dir,
        )
        suites[suite["id"]] = {
            "comparison": comparison,
            "qt6": qt6_report,
        }
    driver_path = pathlib.Path(__file__)
    facts = {
        "all_five_qt5_boundaries_replayed": len(suites) == 5,
        "all_qt6_repetitions_are_equal": all(
            suite["qt6"]["facts"]["qt6_repetitions_are_byte_equal"]
            for suite in suites.values()
        ),
        "all_qt6_results_equal_qt5": all(
            suite["comparison"]["behavior_projection_equal"]
            for suite in suites.values()
        ),
    }
    return {
        "capability": "CAP-CLI-IN-003",
        "facts": facts,
        "failures": [],
        "generator": f"{PROBE_DIR}/{driver_path.name}",
        "generator_sha256": sha256(driver_path.read_bytes()),
        "passed": all(facts.values()),
        "platform": "linux-x86_64-qt5-qt6",
        "qt6_binary": QT6_BINARY,
        "qt6_image": QT6_IMAGE,
        "schema_version": 1,
        "suite_order": [suite["id"] for suite in SUITES],
        "suites": suites,
        "upstream_commit": UPSTREAM_COMMIT,
    }


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--special-fixture-dir",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--filesystem-fixture-dir",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    report = build_report(
        root=root,
        special_fixture_dir=args.special_fixture_dir.resolve(),
        filesystem_fixture_dir=args.filesystem_fixture_dir.resolve(),
    )
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

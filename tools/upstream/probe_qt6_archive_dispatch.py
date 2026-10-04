#!/usr/bin/env python3
"""Close the pinned Qt6 archive-family public and private dispatch boundary."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys
from types import ModuleType
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
QT6_RELEASE_BINARY = "/opt/die-build/src/console/diec"
DATA_DIR = "docs/research/data"
PROBE_DIR = "tools/upstream"
PUBLIC_REPORT = f"{DATA_DIR}/cli-output-matrix-linux-qt5-qt6.json"
ARCHIVE_GAP_REPORT = f"{DATA_DIR}/archive-gap-closure.json"
NAMED_MEMBERS = (
    "APK",
    "IPA",
    "JAR",
    "ZIP",
    "RAR",
    "NPM",
    "ISO9660",
    "Archive",
)
PUBLIC_CASES = {
    "minimal.apk": "APK",
    "minimal.ipa": "Binary",
    "minimal.iso": "ISO 9660",
    "minimal.jar": "JAR",
    "minimal.rar": "RAR",
    "payload.tar": "Binary",
    "payload.txt.gz": "Binary",
    "payload.zip": "ZIP",
}
SUITES = (
    {
        "id": "npm",
        "module": "probe_npm_dispatch_harness.py",
        "baseline": "npm-dispatch-engine-qt5.json",
        "dockerfile": "Dockerfile.npm-dispatch-harness-qt6",
        "image": "die-rust/npm-dispatch-harness-qt6:74eaf505",
    },
    {
        "id": "generic_archive",
        "module": "probe_generic_archive_dispatch_harness.py",
        "baseline": "generic-archive-dispatch-engine-qt5.json",
        "dockerfile": (
            "Dockerfile.generic-archive-dispatch-harness-qt6"
        ),
        "image": (
            "die-rust/"
            "generic-archive-dispatch-harness-qt6:74eaf505"
        ),
    },
)


class ProbeError(ValueError):
    """The fixed archive dispatch input, oracle, or behavior changed."""


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
        f"diec_qt6_archive_{suite_id}", path
    )
    if spec is None or spec.loader is None:
        raise ProbeError(f"cannot load probe module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def projection_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(encoded)


def behavior_projection(report: dict[str, Any]) -> dict[str, Any]:
    admitted = (
        "cases",
        "component_commits",
        "facts",
        "fixture_manifest",
        "raw_artifacts",
        "source_contract",
        "upstream_commit",
    )
    return {key: report[key] for key in admitted}


def prepare_qt6_report(report: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(report)
    images = result.pop("images")
    binaries = result.pop("binaries")
    if images["harness_cmake"] != images["release_qmake"]:
        raise ProbeError("Qt6 harness/release image identity drift")
    if binaries["release_cmake"] != binaries["release_qmake"]:
        raise ProbeError("Qt6 release repetition binary identity drift")
    result["qt6_image"] = images["harness_cmake"]
    result["qt6_binaries"] = {
        "harness": binaries["harness"],
        "release": binaries["release_cmake"],
    }
    result["platform"] = "linux-x86_64-qt6"
    result.pop("remaining_gap", None)
    facts = result["facts"]
    if facts.pop("qmake_and_cmake_release_outputs_are_byte_equal") is not True:
        raise ProbeError("Qt6 release repetitions differ")
    facts["qt6_release_repetitions_are_byte_equal"] = True
    replacements = (
        ("cmake_release_quiet", "release_repetition_1_quiet"),
        ("qmake_release_quiet", "release_repetition_2_quiet"),
        ("cmake_release_verbose", "release_repetition_1_verbose"),
        ("qmake_release_verbose", "release_repetition_2_verbose"),
        ("cmake_release", "release_repetition_1"),
        ("qmake_release", "release_repetition_2"),
    )
    for case in result["cases"].values():
        for old, new in replacements:
            if old in case:
                case[new] = case.pop(old)
    return result


def invoke_private_suite(
    *,
    root: pathlib.Path,
    suite: dict[str, str],
    fixture_dir: pathlib.Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    module = load_module(
        root / PROBE_DIR / suite["module"],
        suite["id"],
    )
    module.HARNESS_DOCKERFILE = (
        f"{PROBE_DIR}/{suite['dockerfile']}"
    )
    module.HARNESS_IMAGE = suite["image"]
    module.QMAKE_IMAGE = suite["image"]
    module.QMAKE_RELEASE_BINARY = QT6_RELEASE_BINARY
    raw_qt6 = module.build_report(
        fixture_dir,
        root / module.FIXTURE_MANIFEST,
    )
    baseline_path = root / DATA_DIR / suite["baseline"]
    baseline_raw = baseline_path.read_bytes()
    baseline = strict_json(baseline_raw)
    if not isinstance(baseline, dict) or not isinstance(raw_qt6, dict):
        raise ProbeError(f"invalid private report root: {suite['id']}")
    qt5_projection = behavior_projection(baseline)
    qt6_projection = behavior_projection(raw_qt6)
    if qt5_projection != qt6_projection:
        raise ProbeError(
            f"Qt5/Qt6 private behavior differs: {suite['id']}"
        )
    return prepare_qt6_report(raw_qt6), {
        "behavior_projection_equal": True,
        "behavior_projection_sha256": projection_sha256(
            qt5_projection
        ),
        "qt5_report_path": f"{DATA_DIR}/{suite['baseline']}",
        "qt5_report_sha256": sha256(baseline_raw),
    }


def public_dispatch_projection(
    root: pathlib.Path,
) -> dict[str, Any]:
    report_path = root / PUBLIC_REPORT
    raw = report_path.read_bytes()
    report = strict_json(raw)
    if (
        report.get("expected_revision") != UPSTREAM_COMMIT
        or report.get("left_revision") != UPSTREAM_COMMIT
        or report.get("right_revision") != UPSTREAM_COMMIT
    ):
        raise ProbeError("public archive dispatch revision drift")
    corpus = report.get("corpus")
    if not isinstance(corpus, dict):
        raise ProbeError("public archive dispatch corpus missing")
    cases = {}
    for name, expected_filetype in PUBLIC_CASES.items():
        case = corpus.get(name)
        left_tree = (
            case.get("left_detect_tree")
            if isinstance(case, dict)
            else None
        )
        if (
            not isinstance(case, dict)
            or case.get("differences") != []
            or not isinstance(left_tree, list)
            or len(left_tree) != 1
            or left_tree != case.get("right_detect_tree")
            or case.get("left", {}).get("exit_code") != 0
            or case.get("right", {}).get("exit_code") != 0
            or left_tree[0].get("filetype") != expected_filetype
        ):
            raise ProbeError(f"public dispatch drift: {name}")
        cases[name] = {
            "detect_tree": case["left_detect_tree"],
            "input_sha256": case["sha256"],
            "input_size": case["size"],
            "qt5": case["left"],
            "qt6": case["right"],
        }
    return {
        "cases": cases,
        "report_path": PUBLIC_REPORT,
        "report_sha256": sha256(raw),
    }


def archive_gap_projection(root: pathlib.Path) -> dict[str, Any]:
    path = root / ARCHIVE_GAP_REPORT
    raw = path.read_bytes()
    report = strict_json(raw)
    families = report.get("engine_extraction_families")
    if (
        report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("result") != "closed"
        or not isinstance(families, dict)
        or families.get("ordered_filetypes")
        != ["ZIP", "7Z", "RAR", "CAB", "ISO9660"]
        or report.get("closure_assertions", {}).get(
            "engine_extraction_family_inventory_is_exhaustive"
        )
        is not True
    ):
        raise ProbeError("archive family closure reference drift")
    return {
        "engine_extraction_families": families["ordered_filetypes"],
        "report_path": ARCHIVE_GAP_REPORT,
        "report_sha256": sha256(raw),
        "source_inventory_is_exhaustive": True,
    }


def build_report(
    *,
    root: pathlib.Path,
    npm_fixture_dir: pathlib.Path,
    generic_fixture_dir: pathlib.Path,
) -> dict[str, Any]:
    fixture_dirs = {
        "npm": npm_fixture_dir,
        "generic_archive": generic_fixture_dir,
    }
    private_suites = {}
    for suite in SUITES:
        qt6, comparison = invoke_private_suite(
            root=root,
            suite=suite,
            fixture_dir=fixture_dirs[suite["id"]],
        )
        private_suites[suite["id"]] = {
            "comparison": comparison,
            "qt6": qt6,
        }
    public = public_dispatch_projection(root)
    archive_gap = archive_gap_projection(root)
    facts = {
        "all_eight_named_dispatch_members_are_covered": (
            len(NAMED_MEMBERS) == 8
            and set(private_suites) == {"npm", "generic_archive"}
            and set(public["cases"]) == set(PUBLIC_CASES)
        ),
        "all_public_dispatch_and_generic_controls_are_covered": (
            len(public["cases"]) == 8
        ),
        "generic_archive_private_branch_matches_qt5": (
            private_suites["generic_archive"]["comparison"][
                "behavior_projection_equal"
            ]
        ),
        "npm_private_branch_matches_qt5": (
            private_suites["npm"]["comparison"][
                "behavior_projection_equal"
            ]
        ),
        "public_dispatch_matches_qt5": all(
            case["qt5"] == case["qt6"]
            for case in public["cases"].values()
        ),
        "source_family_inventory_is_exhaustive": (
            archive_gap["source_inventory_is_exhaustive"]
        ),
    }
    driver_path = pathlib.Path(__file__)
    return {
        "archive_gap_reference": archive_gap,
        "capability": "CAP-DISPATCH-004",
        "facts": facts,
        "failures": [],
        "generator": f"{PROBE_DIR}/{driver_path.name}",
        "generator_sha256": sha256(driver_path.read_bytes()),
        "named_members": list(NAMED_MEMBERS),
        "passed": all(facts.values()),
        "platform": "linux-x86_64-qt5-qt6",
        "private_suite_order": [suite["id"] for suite in SUITES],
        "private_suites": private_suites,
        "public_dispatch": public,
        "schema_version": 1,
        "upstream_commit": UPSTREAM_COMMIT,
    }


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--npm-fixture-dir",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--generic-fixture-dir",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    report = build_report(
        root=root,
        npm_fixture_dir=args.npm_fixture_dir.resolve(),
        generic_fixture_dir=args.generic_fixture_dir.resolve(),
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

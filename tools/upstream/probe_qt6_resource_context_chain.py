#!/usr/bin/env python3
"""Capture the pinned Qt6 resource-context chain and compare it with Qt5."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


GENERATOR = "tools/upstream/probe_qt6_resource_context_chain.py"
UNDERLYING_PROBE = "tools/upstream/probe_resource_context_chain.py"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
IMAGE = "die-rust/upstream-oracle-cmake-qt6:74eaf505"
BINARY = "/opt/die-build/src/console/diec"
QT6_IMAGE_ID = (
    "sha256:e015495c313d0715f0b80f395da983a113a439f2a135eb637e9f0638c225200b"
)
QT6_WARNING = b"Unimplemented code.\n" * 4


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_underlying(root: Path) -> Any:
    path = root / UNDERLYING_PROBE
    spec = importlib.util.spec_from_file_location(
        "_diec_qt6_resource_context_underlying", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load resource-context probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def inspect_image_id(image: str, docker_context: str) -> str:
    process = subprocess.run(
        [
            "docker",
            f"--context={docker_context}",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            image,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return process.stdout.strip()


def validate_qt5_baseline(
    underlying: Any,
    baseline: dict[str, Any],
) -> None:
    if baseline.get("schema_version") != 1:
        raise ValueError("unsupported Qt5 resource-context baseline schema")
    if baseline.get("upstream_commit") != UPSTREAM_COMMIT:
        raise ValueError("Qt5 resource-context revision drift")
    if set(baseline.get("cases", {})) != {
        case.name for case in underlying.CASES
    }:
        raise ValueError("Qt5 resource-context case catalog drift")
    for case_name, case in baseline["cases"].items():
        stdout = case.get("raw_stdout", "").encode("utf-8")
        try:
            stderr = bytes.fromhex(case.get("raw_stderr_hex", ""))
        except ValueError as error:
            raise ValueError(
                f"invalid Qt5 resource-context stderr: {case_name}"
            ) from error
        if (
            sha256(stdout) != case.get("raw_stdout_sha256")
            or sha256(stderr) != case.get("raw_stderr_sha256")
        ):
            raise ValueError(
                f"Qt5 resource-context raw identity drift: {case_name}"
            )
        if stderr:
            raise ValueError(
                f"unexpected Qt5 resource-context stderr: {case_name}"
            )


def build_report(
    corpus_dir: Path,
    qt5_baseline_path: Path,
    docker_context: str,
) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    underlying = load_underlying(root)
    try:
        qt5_baseline_source = qt5_baseline_path.relative_to(root).as_posix()
    except ValueError as error:
        raise ValueError(
            "Qt5 resource-context baseline must be inside the repository"
        ) from error
    qt5_baseline = underlying.load_object(qt5_baseline_path)
    validate_qt5_baseline(underlying, qt5_baseline)

    revision = underlying.inspect_revision(IMAGE, docker_context)
    if revision != UPSTREAM_COMMIT:
        raise ValueError("Qt6 resource-context image revision drift")
    image_id = inspect_image_id(IMAGE, docker_context)
    if image_id != QT6_IMAGE_ID:
        raise ValueError("Qt6 resource-context image identity drift")

    sample = underlying.load_sample(corpus_dir)
    binary_hash = underlying.binary_sha256(
        IMAGE,
        BINARY,
        docker_context,
    )
    cases: dict[str, Any] = {}
    for case in underlying.CASES:
        observation = underlying.observe(
            IMAGE,
            BINARY,
            case.arguments,
            corpus_dir,
            docker_context,
        )
        if observation.exit_code != 0:
            raise ValueError(
                f"Qt6 resource-context exit-code drift: {case.name}"
            )
        if observation.stderr != QT6_WARNING:
            raise ValueError(
                f"unexpected Qt6 resource-context stderr: {case.name}"
            )
        tree = underlying.SHARED.json_detect_tree(observation.stdout)
        if tree != underlying.EXPECTED_TREES[case.name]:
            raise ValueError(
                f"Qt6 resource-context detection drift: {case.name}"
            )
        qt5_case = qt5_baseline["cases"][case.name]
        if observation.stdout.decode("utf-8") != qt5_case["raw_stdout"]:
            raise ValueError(
                f"Qt6 resource-context stdout differs: {case.name}"
            )
        if tree != qt5_case["normalized_detect_tree"]:
            raise ValueError(
                f"Qt6 resource-context tree differs: {case.name}"
            )
        if observation.exit_code != qt5_case["exit_code"]:
            raise ValueError(
                f"Qt6 resource-context exit code differs: {case.name}"
            )
        cases[case.name] = {
            "arguments": [
                *case.arguments,
                f"/corpus/{underlying.SAMPLE_NAME}",
            ],
            "exit_code": observation.exit_code,
            "raw_stdout": observation.stdout.decode("utf-8"),
            "raw_stdout_sha256": sha256(observation.stdout),
            "raw_stderr_hex": observation.stderr.hex(),
            "raw_stderr_sha256": sha256(observation.stderr),
            "normalized_detect_tree": tree,
            "comparison_to_qt5": {
                "exit_code_equal": True,
                "stdout_equal": True,
                "normalized_detect_tree_equal": True,
                "stderr_difference": "known_qt6_pe_warning",
            },
        }

    resource_child = cases["recursive_aggressive"][
        "normalized_detect_tree"
    ][0]["values"][1]
    relationships = {
        "all_exit_codes_match_qt5": all(
            case["comparison_to_qt5"]["exit_code_equal"]
            for case in cases.values()
        ),
        "all_stdout_streams_match_qt5": all(
            case["comparison_to_qt5"]["stdout_equal"]
            for case in cases.values()
        ),
        "all_detection_trees_match_qt5": all(
            case["comparison_to_qt5"]["normalized_detect_tree_equal"]
            for case in cases.values()
        ),
        "default_omits_resource_child": (
            cases["default"]["normalized_detect_tree"]
            == underlying.ROOT_TREE
        ),
        "recursive_alone_omits_unclassified_resource": (
            cases["recursive"]["normalized_detect_tree"]
            == underlying.ROOT_TREE
        ),
        "aggressive_alone_omits_resource_child": (
            cases["aggressive"]["normalized_detect_tree"]
            == underlying.ROOT_TREE
        ),
        "recursive_and_aggressive_reaches_resource_child": (
            cases["recursive_aggressive"]["normalized_detect_tree"]
            == underlying.RESOURCE_TREE
        ),
        "resource_context_is_propagated": (
            resource_child["parentfilepart"] == "Resource"
            and resource_child["offset"] == "608"
            and resource_child["size"] == "20"
            and resource_child["filetype"] == "Binary"
        ),
        "manifest_rule_observes_original_resource_type": (
            resource_child["values"]
            == [{"name": "Manifest", "type": "format", "version": ""}]
        ),
    }
    if not all(relationships.values()):
        raise ValueError("Qt6 resource-context relationship drift")

    return {
        "schema_version": 1,
        "generator": GENERATOR,
        "generator_sha256": sha256(Path(__file__).read_bytes()),
        "underlying_probe": {
            "path": UNDERLYING_PROBE,
            "sha256": sha256((root / UNDERLYING_PROBE).read_bytes()),
        },
        "platform": "linux-amd64-qt6",
        "upstream_commit": UPSTREAM_COMMIT,
        "rules_commit": RULES_COMMIT,
        "result": "observed",
        "oracle": {
            "image": IMAGE,
            "image_id": image_id,
            "image_revision": revision,
            "binary": BINARY,
            "binary_sha256": binary_hash,
        },
        "qt5_baseline": {
            "path": qt5_baseline_source,
            "sha256": sha256(qt5_baseline_path.read_bytes()),
        },
        "sample": sample,
        "cases": cases,
        "relationships": relationships,
        "known_difference": {
            "scope": "PE rule runtime warning in each CLI invocation",
            "case_count": len(cases),
            "stderr_bytes_per_case": len(QT6_WARNING),
            "stderr_sha256_per_case": sha256(QT6_WARNING),
            "lines_per_case": 4,
            "semantic_output_equal_to_qt5": True,
        },
        "limitations": [
            "the experiment covers one fixed RT_MANIFEST resource payload",
            "the four CLI modes isolate recursive and aggressive gate interaction",
            "the Qt6 PE warning is retained verbatim before classification",
        ],
    }


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nested-corpus-dir", type=Path, required=True)
    parser.add_argument(
        "--qt5-baseline",
        type=Path,
        default=(
            root
            / "docs"
            / "research"
            / "data"
            / "resource-context-chain-qt5.json"
        ),
    )
    parser.add_argument("--docker-context", default="default")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(
        args.nested_corpus_dir.resolve(),
        args.qt5_baseline.resolve(),
        args.docker_context,
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

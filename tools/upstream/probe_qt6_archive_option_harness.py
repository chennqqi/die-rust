#!/usr/bin/env python3
"""Compare the fixed Qt5/Qt6 engine-only archive option with raw streams."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


GENERATOR = "tools/upstream/probe_qt6_archive_option_harness.py"
UNDERLYING_PROBE = "tools/upstream/probe_archive_harness.py"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
HARNESS_BINARY = "/opt/die-build/src/console/die-archive-harness"
RELEASE_BINARY = "/opt/die-build/src/console/diec"
QT6_WARNING = b"Unimplemented code.\n" * 4
ORACLES = {
    "qt5": {
        "harness_image": "die-rust/upstream-archive-harness:74eaf505",
        "harness_image_id": (
            "sha256:771b9094a2ad6ab4f6250dd89307ab727c07a1aae885a894695abfa959bab5dc"
        ),
        "harness_binary_sha256": (
            "b7ea9b151b58b630c017e9989333fa035b7d86ffab366a5d3a1f74bab9f1e96e"
        ),
        "release_image": "die-rust/upstream-oracle-cmake:74eaf505",
        "release_image_id": (
            "sha256:466102628c3a94b7ab1048f0c24261b1920e61a40029b128763cf79370255040"
        ),
        "release_binary_sha256": (
            "da1fab49f7ba5970d1fc1c7fe3d4f380cf5e8775dd8097207e7b3c30f08236cf"
        ),
    },
    "qt6": {
        "harness_image": (
            "die-rust/upstream-archive-harness-qt6:74eaf505"
        ),
        "harness_image_id": (
            "sha256:2e46aa3e3d2fa731e92bd57c11f905bc3ff4a4064106d020314ad05a422c4488"
        ),
        "harness_binary_sha256": (
            "6fed831d6c11b67e0a9e0ea0aa57b2a9e380a5a6f53dd46f426122aec3839d76"
        ),
        "release_image": (
            "die-rust/upstream-oracle-cmake-qt6:74eaf505"
        ),
        "release_image_id": (
            "sha256:e015495c313d0715f0b80f395da983a113a439f2a135eb637e9f0638c225200b"
        ),
        "release_binary_sha256": (
            "e3321105af0349b29195325e79d5d2c7cc25ead2f28f84e242e3835b98f7283e"
        ),
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_underlying(root: Path) -> Any:
    path = root / UNDERLYING_PROBE
    spec = importlib.util.spec_from_file_location(
        "_diec_qt6_archive_option_underlying", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load archive-option probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def inspect_image(image: str, docker_context: str) -> tuple[str, str]:
    process = subprocess.run(
        [
            "docker",
            f"--context={docker_context}",
            "image",
            "inspect",
            "--format",
            '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}',
            image,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    values = process.stdout.strip().split()
    if len(values) != 2:
        raise ValueError(f"invalid image identity: {image}")
    return values[0], values[1]


def binary_sha256(
    image: str,
    binary: str,
    docker_context: str,
) -> str:
    process = subprocess.run(
        [
            "docker",
            f"--context={docker_context}",
            "run",
            "--rm",
            "--network=none",
            "--memory=512m",
            "--cpus=1",
            "--pids-limit=128",
            "--entrypoint",
            "sha256sum",
            image,
            binary,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return process.stdout.split()[0]


def observation_record(
    underlying: Any,
    observation: Any,
    raw_streams: dict[str, Any],
    detection_trees: dict[str, Any],
) -> dict[str, Any]:
    tree = underlying.SHARED.json_detect_tree(observation.stdout)
    if tree is None:
        raise ValueError("archive-option output is not a JSON detection tree")
    stdout_hash = sha256(observation.stdout)
    stderr_hash = sha256(observation.stderr)
    for stream_hash, stream in (
        (stdout_hash, observation.stdout),
        (stderr_hash, observation.stderr),
    ):
        encoded = {
            "bytes": len(stream),
            "base64": base64.b64encode(stream).decode("ascii"),
        }
        existing = raw_streams.setdefault(stream_hash, encoded)
        if existing != encoded:
            raise ValueError("archive-option raw stream hash collision")
    tree_bytes = json.dumps(
        tree,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    tree_hash = sha256(tree_bytes)
    existing_tree = detection_trees.setdefault(tree_hash, tree)
    if existing_tree != tree:
        raise ValueError("archive-option detection tree hash collision")
    return {
        "exit_code": observation.exit_code,
        "stdout_bytes": len(observation.stdout),
        "stdout_sha256": stdout_hash,
        "stderr_bytes": len(observation.stderr),
        "stderr_sha256": stderr_hash,
        "detect_tree_sha256": tree_hash,
        "stream_count": underlying.count_file_parts(tree, "Stream"),
        "resource_count": underlying.count_file_parts(tree, "Resource"),
        "overlay_count": underlying.count_file_parts(tree, "Overlay"),
    }


def validate_stderr(
    oracle_name: str,
    sample_name: str,
    stderr: bytes,
) -> None:
    expected = (
        QT6_WARNING
        if oracle_name == "qt6" and sample_name.startswith("pe-")
        else b""
    )
    if stderr != expected:
        raise ValueError(
            f"unexpected {oracle_name} archive-option stderr: {sample_name}"
        )


def build_report(
    corpus_dir: Path,
    docker_context: str,
) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    underlying = load_underlying(root)
    samples = underlying.SHARED.load_nested_corpus(corpus_dir)
    if len(samples) != 8:
        raise ValueError("archive-option fixture catalog drift")

    oracle_report: dict[str, Any] = {}
    for oracle_name, oracle in ORACLES.items():
        identity: dict[str, Any] = {}
        for kind, binary in (
            ("harness", HARNESS_BINARY),
            ("release", RELEASE_BINARY),
        ):
            image = oracle[f"{kind}_image"]
            image_id, revision = inspect_image(image, docker_context)
            observed_binary_hash = binary_sha256(
                image,
                binary,
                docker_context,
            )
            if (
                image_id != oracle[f"{kind}_image_id"]
                or revision != UPSTREAM_COMMIT
                or observed_binary_hash
                != oracle[f"{kind}_binary_sha256"]
            ):
                raise ValueError(
                    f"{oracle_name} {kind} oracle identity drift"
                )
            identity[kind] = {
                "image": image,
                "image_id": image_id,
                "revision": revision,
                "binary": binary,
                "binary_sha256": observed_binary_hash,
            }
        oracle_report[oracle_name] = identity

    raw_streams: dict[str, Any] = {}
    detection_trees: dict[str, Any] = {}
    cases: dict[str, Any] = {}
    for sample in samples:
        sample_name = str(sample["name"])
        sample_cases: dict[str, Any] = {}
        cases[sample_name] = sample_cases
        for case in underlying.HARNESS_MATRIX:
            arguments = (*case.arguments, f"/nested/{sample_name}")
            entry: dict[str, Any] = {
                "arguments": list(arguments),
                "observations": {},
            }
            sample_cases[case.name] = entry
            observations: dict[str, Any] = entry["observations"]
            for oracle_name, oracle in ORACLES.items():
                observation = underlying.SHARED.observe(
                    oracle["harness_image"],
                    HARNESS_BINARY,
                    arguments,
                    corpus_dir,
                    "/nested",
                )
                if observation.exit_code != 0:
                    raise ValueError(
                        f"{oracle_name} harness exit-code drift: "
                        f"{sample_name}.{case.name}"
                    )
                validate_stderr(
                    oracle_name,
                    sample_name,
                    observation.stderr,
                )
                observations[oracle_name] = observation_record(
                    underlying,
                    observation,
                    raw_streams,
                    detection_trees,
                )
            qt5 = observations["qt5"]
            qt6 = observations["qt6"]
            if (
                qt5["exit_code"] != qt6["exit_code"]
                or qt5["stdout_sha256"] != qt6["stdout_sha256"]
                or qt5["detect_tree_sha256"]
                != qt6["detect_tree_sha256"]
            ):
                raise ValueError(
                    f"Qt5/Qt6 archive-option semantic drift: "
                    f"{sample_name}.{case.name}"
                )
            entry["comparison"] = {
                "exit_code_equal": True,
                "stdout_equal": True,
                "detect_tree_equal": True,
                "stderr_classification": (
                    "known_qt6_pe_warning"
                    if sample_name.startswith("pe-")
                    else "equal_empty"
                ),
            }

            release_prefix = underlying.RELEASE_EQUIVALENTS.get(case.name)
            if release_prefix is not None:
                release_arguments = (
                    *release_prefix,
                    f"/nested/{sample_name}",
                )
                releases: dict[str, Any] = {}
                for oracle_name, oracle in ORACLES.items():
                    release = underlying.SHARED.observe(
                        oracle["release_image"],
                        RELEASE_BINARY,
                        release_arguments,
                        corpus_dir,
                        "/nested",
                    )
                    validate_stderr(
                        oracle_name,
                        sample_name,
                        release.stderr,
                    )
                    release_record = observation_record(
                        underlying,
                        release,
                        raw_streams,
                        detection_trees,
                    )
                    releases[oracle_name] = release_record
                    harness_record = observations[oracle_name]
                    if (
                        release.exit_code != 0
                        or release_record["stdout_sha256"]
                        != harness_record["stdout_sha256"]
                        or release_record["stderr_sha256"]
                        != harness_record["stderr_sha256"]
                        or release_record["detect_tree_sha256"]
                        != harness_record["detect_tree_sha256"]
                    ):
                        raise ValueError(
                            f"{oracle_name} release equivalence drift: "
                            f"{sample_name}.{case.name}"
                        )
                entry["release_control"] = {
                    "arguments": list(release_arguments),
                    "observations": releases,
                    "harness_equal": {"qt5": True, "qt6": True},
                }

    archive_samples = {
        "pdf-member.zip",
        "nested-zip.zip",
        "many-pdf-members.zip",
    }
    without_archive = {
        case.name
        for case in underlying.HARNESS_MATRIX
        if "--archive" not in case.arguments
    }
    with_archive = {
        case.name
        for case in underlying.HARNESS_MATRIX
        if "--archive" in case.arguments
    }
    relationships = {
        "all_64_harness_exit_codes_match": all(
            case["comparison"]["exit_code_equal"]
            for sample_cases in cases.values()
            for case in sample_cases.values()
        ),
        "all_64_harness_stdout_streams_match": all(
            case["comparison"]["stdout_equal"]
            for sample_cases in cases.values()
            for case in sample_cases.values()
        ),
        "all_64_harness_detection_trees_match": all(
            case["comparison"]["detect_tree_equal"]
            for sample_cases in cases.values()
            for case in sample_cases.values()
        ),
        "all_32_no_archive_harness_runs_match_release_cli": all(
            all(case["release_control"]["harness_equal"].values())
            for sample_cases in cases.values()
            for case_name, case in sample_cases.items()
            if case_name in without_archive
        ),
        "archive_samples_have_no_stream_without_archive_option": all(
            cases[sample_name][case_name]["observations"]["qt6"][
                "stream_count"
            ]
            == 0
            for sample_name in archive_samples
            for case_name in without_archive
        ),
        "archive_samples_have_streams_with_archive_option": all(
            cases[sample_name][case_name]["observations"]["qt6"][
                "stream_count"
            ]
            > 0
            for sample_name in archive_samples
            for case_name in with_archive
        ),
        "nested_archive_option_propagates_to_inner_zip": (
            cases["nested-zip.zip"]["archive"]["observations"]["qt6"][
                "stream_count"
            ]
            == 2
        ),
        "default_archive_member_limit_matches_qt5": (
            cases["many-pdf-members.zip"]["archive"]["observations"]["qt6"][
                "stream_count"
            ]
            == 21
        ),
        "aggressive_archive_member_control_reaches_all_22": (
            cases["many-pdf-members.zip"]["archive_aggressive"][
                "observations"
            ]["qt6"]["stream_count"]
            == 22
        ),
        "default_resource_limit_matches_qt5": (
            cases["pe-many-pdf-resources.exe"]["recursive"][
                "observations"
            ]["qt6"]["resource_count"]
            == 21
        ),
        "aggressive_resource_control_reaches_all_22": (
            cases["pe-many-pdf-resources.exe"]["recursive_aggressive"][
                "observations"
            ]["qt6"]["resource_count"]
            == 22
        ),
    }
    if not all(relationships.values()):
        raise ValueError("Qt6 archive-option relationship drift")

    manifest_path = corpus_dir / "manifest.json"
    return {
        "schema_version": 1,
        "generator": GENERATOR,
        "generator_sha256": sha256(Path(__file__).read_bytes()),
        "underlying_probe": {
            "path": UNDERLYING_PROBE,
            "sha256": sha256((root / UNDERLYING_PROBE).read_bytes()),
        },
        "capability": "CAP-NEST-003",
        "platform": "linux-amd64-qt5-qt6",
        "upstream_commit": UPSTREAM_COMMIT,
        "rules_commit": RULES_COMMIT,
        "result": "observed",
        "fixture": {
            "manifest": "docs/research/data/nested-corpus.json",
            "manifest_sha256": sha256(manifest_path.read_bytes()),
            "samples": samples,
        },
        "oracles": oracle_report,
        "case_count": sum(len(value) for value in cases.values()),
        "release_control_count": sum(
            "release_control" in case
            for sample_cases in cases.values()
            for case in sample_cases.values()
        ),
        "raw_streams": raw_streams,
        "detection_trees": detection_trees,
        "cases": cases,
        "relationships": relationships,
        "known_difference": {
            "scope": "Qt6 PE rule runtime warning",
            "affected_samples": sorted(
                sample["name"]
                for sample in samples
                if str(sample["name"]).startswith("pe-")
            ),
            "harness_invocations": 40,
            "release_invocations": 20,
            "stderr_bytes_per_invocation": len(QT6_WARNING),
            "stderr_sha256_per_invocation": sha256(QT6_WARNING),
            "lines_per_invocation": 4,
            "all_stdout_equal": True,
        },
        "limitations": [
            "the matrix covers the eight project-generated nested fixtures",
            "count observations stop at 22 and do not close the 100000 iteration boundary",
            "depth and cumulative expanded-byte limits require the separate limit harness",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nested-corpus-dir", type=Path, required=True)
    parser.add_argument("--docker-context", default="default")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(
        args.nested_corpus_dir.resolve(),
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

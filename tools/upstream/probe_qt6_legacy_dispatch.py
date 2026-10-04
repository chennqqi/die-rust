#!/usr/bin/env python3
"""Compare Amiga Hunk and Atari ST dispatch on pinned Qt5/Qt6 CLIs."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import zlib
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
FORMATS_COMMIT = "1151e7254fdee3c0294ff7095edbdd7bfccf8201"
QT5_REPORT_SHA256 = (
    "9dd1d4de3535fc035d4624205a24405d05d1b9a9589ca89b4a1e0a4cfdace5fc"
)
QT6_IMAGE = "die-rust/upstream-oracle-cmake-qt6:74eaf505"
QT6_BINARY = "/opt/die-build/src/console/diec"
REPETITIONS = 2
SOURCE_PATHS = (
    "/opt/die-source/Formats/exec/xamigahunk.cpp",
    "/opt/die-source/Formats/exec/xatarist.cpp",
    "/opt/die-source/Formats/xformats.cpp",
    "/opt/die-source/XScanEngine/xscanengine.cpp",
)


def _load_base_probe():
    path = pathlib.Path(__file__).with_name("probe_legacy_dispatch.py")
    spec = importlib.util.spec_from_file_location(
        "_diec_qt5_legacy_dispatch",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Qt5 legacy dispatch probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BASE = _load_base_probe()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(data: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(
        data.decode("utf-8"),
        parse_constant=reject_constant,
        object_pairs_hook=closed_pairs,
    )


def inspect_qt6_image() -> dict[str, Any]:
    process = subprocess.run(
        ["docker", "image", "inspect", QT6_IMAGE],
        check=True,
        capture_output=True,
    )
    document = strict_json(process.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision",
        "",
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError("Qt6 image revision mismatch")
    paths = (QT6_BINARY, *SOURCE_PATHS)
    hashes = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            QT6_IMAGE,
            "sha256sum",
            *paths,
        ],
        check=True,
        capture_output=True,
    )
    parsed = {}
    for line in hashes.stdout.decode("ascii").splitlines():
        digest, path = line.split(maxsplit=1)
        parsed[path] = digest
    if set(parsed) != set(paths):
        raise ValueError("Qt6 container hash inventory mismatch")
    return {
        "image": QT6_IMAGE,
        "image_id": document["Id"],
        "revision": revision,
        "binary": QT6_BINARY,
        "binary_sha256": parsed[QT6_BINARY],
        "source_sha256": {
            path: parsed[path] for path in SOURCE_PATHS
        },
    }


def observe(
    corpus_dir: pathlib.Path,
    arguments: tuple[str, ...],
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cpus",
            "1",
            "--memory",
            "512m",
            "--pids-limit",
            "128",
            "--read-only",
            "--mount",
            f"type=bind,src={corpus_dir},dst=/corpus,readonly",
            QT6_IMAGE,
            QT6_BINARY,
            *arguments,
        ],
        check=False,
        capture_output=True,
        timeout=60,
    )


def raw_stream(
    data: bytes,
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    digest = sha256(data)
    compressed = zlib.compress(data, level=9)
    artifact = {
        "bytes": len(data),
        "encoding": "zlib+base64",
        "compressed_bytes": len(compressed),
        "base64": base64.b64encode(compressed).decode("ascii"),
    }
    previous = artifacts.setdefault(digest, artifact)
    if previous != artifact:
        raise ValueError("raw artifact digest collision")
    return {
        "bytes": len(data),
        "sha256": digest,
        "artifact_sha256": digest,
    }


def load_qt5_reference(
    path: pathlib.Path,
    manifest_sha256: str,
) -> tuple[dict[str, Any], str]:
    report_bytes = path.read_bytes()
    digest = sha256(report_bytes)
    report = strict_json(report_bytes)
    if (
        digest != QT5_REPORT_SHA256
        or report.get("schema_version") != 1
        or report.get("result") != "pass"
        or report.get("failures") != []
        or report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("rules_commit") != RULES_COMMIT
        or report.get("formats_commit") != FORMATS_COMMIT
        or report.get("platform") != "linux-amd64-qt5"
        or report.get("capability") != "CAP-DISPATCH-003"
        or report.get("corpus_manifest", {}).get("sha256")
        != manifest_sha256
    ):
        raise ValueError("Qt5 legacy dispatch reference drift")
    return report, digest


def build_report(
    corpus_dir: pathlib.Path,
    qt5_report_path: pathlib.Path,
) -> dict[str, Any]:
    manifest, samples, manifest_bytes = BASE.load_fixture(
        ROOT,
        corpus_dir,
    )
    manifest_sha256 = sha256(manifest_bytes)
    qt5, qt5_sha256 = load_qt5_reference(
        qt5_report_path,
        manifest_sha256,
    )
    identity = inspect_qt6_image()
    raw_artifacts: dict[str, dict[str, Any]] = {}
    cases = {}
    known_differences = []
    qt5_cases = qt5["cases"]

    for sample in samples:
        name = sample["name"]
        scan_arguments = (
            "--json",
            *BASE.SHARED.DATABASE_ARGS,
            f"/corpus/{name}",
        )
        info_arguments = (
            "--info",
            "--json",
            f"/corpus/{name}",
        )
        executions = []
        raw_pairs = []
        semantic_pairs = []
        for _ in range(REPETITIONS):
            scan = observe(corpus_dir, scan_arguments)
            info = observe(corpus_dir, info_arguments)
            if scan.returncode != 0 or info.returncode != 0:
                raise ValueError(f"Qt6 legacy dispatch failed: {name}")
            scan_tree = BASE.SHARED.json_detect_tree(scan.stdout)
            observed_info = BASE.info_filetype(info.stdout)
            failures = BASE.expectation_failures(
                f"cases.{name}.qt6",
                scan_tree,
                sample["expected_dispatch"],
            )
            if (
                failures
                or observed_info
                != sample["expected_dispatch"]["info_filetype"]
            ):
                raise ValueError(
                    f"Qt6 legacy dispatch expectation failed: {name}"
                )
            raw_pairs.append(
                (
                    scan.stdout,
                    scan.stderr,
                    info.stdout,
                    info.stderr,
                )
            )
            semantic_pairs.append((scan_tree, observed_info))
            executions.append(
                {
                    "scan": {
                        "arguments": list(scan_arguments),
                        "exit_code": scan.returncode,
                        "stdout": raw_stream(
                            scan.stdout,
                            raw_artifacts,
                        ),
                        "stderr": raw_stream(
                            scan.stderr,
                            raw_artifacts,
                        ),
                        "detect_tree": scan_tree,
                    },
                    "detector_info": {
                        "arguments": list(info_arguments),
                        "exit_code": info.returncode,
                        "stdout": raw_stream(
                            info.stdout,
                            raw_artifacts,
                        ),
                        "stderr": raw_stream(
                            info.stderr,
                            raw_artifacts,
                        ),
                        "filetype": observed_info,
                    },
                }
            )
        if raw_pairs[0] != raw_pairs[1]:
            raise ValueError(f"Qt6 raw output is unstable: {name}")
        if semantic_pairs[0] != semantic_pairs[1]:
            raise ValueError(f"Qt6 semantic output is unstable: {name}")

        qt5_case = qt5_cases[name]["oracles"]["linux-qt5-cmake"]
        if (
            semantic_pairs[0][0] != qt5_case["scan"]["detect_tree"]
            or semantic_pairs[0][1]
            != qt5_case["detector_info"]["filetype"]
        ):
            raise ValueError(
                f"Qt5/Qt6 legacy dispatch semantics differ: {name}"
            )
        differences = []
        for mode in ("scan", "detector_info"):
            qt5_mode = qt5_case[mode]
            qt6_mode = executions[0][mode]
            if qt5_mode["stdout_sha256"] != qt6_mode["stdout"]["sha256"]:
                differences.append(f"{mode}.stdout")
            if qt5_mode["stderr_sha256"] != qt6_mode["stderr"]["sha256"]:
                differences.append(f"{mode}.stderr")
        if differences:
            known_differences.append(
                {
                    "case": name,
                    "streams": differences,
                    "semantic_dispatch_equal": True,
                }
            )
        cases[name] = {
            "case_kind": sample["case_kind"],
            "target_filetype": sample["target_filetype"],
            "expected_dispatch": sample["expected_dispatch"],
            "size": sample["size"],
            "sha256": sample["sha256"],
            "qt5_cmake": {
                "scan": {
                    key: qt5_case["scan"][key]
                    for key in (
                        "exit_code",
                        "stdout_bytes",
                        "stdout_sha256",
                        "stderr_bytes",
                        "stderr_sha256",
                        "detect_tree",
                    )
                },
                "detector_info": {
                    key: qt5_case["detector_info"][key]
                    for key in (
                        "exit_code",
                        "stdout_bytes",
                        "stdout_sha256",
                        "stderr_bytes",
                        "stderr_sha256",
                        "filetype",
                    )
                },
            },
            "qt6_executions": executions,
            "comparison": {
                "semantic_dispatch_equal": True,
                "raw_stream_differences": differences,
            },
        }

    relationships = {
        "amiga_positive_detector_is_amiga_hunk": True,
        "amiga_positive_scanner_dispatches_amiga_hunk": True,
        "atari_positive_detector_is_atari_st": True,
        "atari_positive_scanner_falls_back_to_binary": True,
        "six_boundary_controls_remain_binary": True,
        "qt6_two_repetitions_are_raw_equal": True,
        "qt5_qt6_semantic_dispatch_is_equal": True,
        "all_raw_differences_are_retained": True,
    }
    return {
        "schema_version": 1,
        "generator": (
            "tools/upstream/probe_qt6_legacy_dispatch.py"
        ),
        "generator_sha256": sha256(
            pathlib.Path(__file__).read_bytes()
        ),
        "result": "pass",
        "upstream_commit": UPSTREAM_COMMIT,
        "rules_commit": RULES_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "platform": "linux-amd64-qt5-qt6",
        "capability": "CAP-DISPATCH-003",
        "corpus_manifest": {
            "path": (
                "docs/research/data/legacy-dispatch-corpus.json"
            ),
            "sha256": manifest_sha256,
            "sample_count": len(manifest["samples"]),
        },
        "qt5_reference": {
            "path": (
                "docs/research/data/legacy-dispatch-linux-qt5.json"
            ),
            "sha256": qt5_sha256,
            "oracle": "linux-qt5-cmake",
        },
        "qt6_oracle": identity,
        "resource_limits": {
            "network": "none",
            "cpus": 1,
            "memory_bytes": 512 * 1024 * 1024,
            "pids": 128,
            "timeout_seconds_per_execution": 60,
            "fixture_mount": "read-only",
            "container_root": "read-only",
        },
        "repetitions": REPETITIONS,
        "cases": cases,
        "known_differences": known_differences,
        "raw_artifacts": raw_artifacts,
        "relationships": relationships,
        "failures": [],
        "closed_capability": "CAP-DISPATCH-003",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-dir", required=True, type=pathlib.Path)
    parser.add_argument(
        "--qt5-report",
        type=pathlib.Path,
        default=(
            ROOT
            / "docs"
            / "research"
            / "data"
            / "legacy-dispatch-linux-qt5.json"
        ),
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    report = build_report(
        args.corpus_dir.resolve(),
        args.qt5_report.resolve(),
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

#!/usr/bin/env python3
"""Compare the branch-only BW DOS16M harness on pinned Qt5 and Qt6."""

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
FORMATS_COMMIT = "1151e7254fdee3c0294ff7095edbdd7bfccf8201"
XSCANENGINE_COMMIT = "dfe4a419e4f491bb23688ba03c5a5bf39e34da83"
QT5_REPORT_SHA256 = (
    "ab24ede4c85ab856e77639ad27f31ee47154c0d3e1885d88f9e0f6f8f4bfede8"
)
IMAGE = "die-rust/bw-dispatch-harness-qt6:74eaf505"
BINARY = "/opt/die-build/src/console/die-bw-dispatch-harness"
DOCKERFILE = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.bw-dispatch-harness-qt6"
)
REPETITIONS = 2


def _load_base():
    path = pathlib.Path(__file__).with_name(
        "probe_bw_dispatch_harness.py"
    )
    spec = importlib.util.spec_from_file_location(
        "_diec_qt5_bw_dispatch",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Qt5 BW dispatch probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BASE = _load_base()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(data: bytes) -> Any:
    def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=closed_pairs,
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
        raise ValueError("BW raw artifact digest collision")
    return {
        "bytes": len(data),
        "sha256": digest,
        "artifact_sha256": digest,
    }


def inspect_image() -> dict[str, str]:
    process = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        check=True,
        capture_output=True,
    )
    document = strict_json(process.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision",
        "",
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError("Qt6 BW image revision mismatch")
    hash_process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            IMAGE,
            "sha256sum",
            BINARY,
        ],
        check=True,
        capture_output=True,
    )
    binary_sha256, path = hash_process.stdout.decode("ascii").split()
    if path != BINARY:
        raise ValueError("Qt6 BW binary hash path mismatch")
    return {
        "image": IMAGE,
        "image_id": document["Id"],
        "revision": revision,
        "binary": BINARY,
        "binary_sha256": binary_sha256,
    }


def observe() -> subprocess.CompletedProcess[bytes]:
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
            "--entrypoint",
            BINARY,
            IMAGE,
        ],
        check=False,
        capture_output=True,
        timeout=60,
    )


def load_qt5_reference(path: pathlib.Path) -> tuple[dict[str, Any], str]:
    report_bytes = path.read_bytes()
    digest = sha256(report_bytes)
    report = strict_json(report_bytes)
    if (
        digest != QT5_REPORT_SHA256
        or report.get("schema_version") != 1
        or report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("formats_commit") != FORMATS_COMMIT
        or report.get("xscanengine_commit") != XSCANENGINE_COMMIT
        or report.get("platform") != "linux-amd64-qt5"
        or report.get("capability") != "CAP-DISPATCH-002"
        or not all(report.get("relationships", {}).values())
    ):
        raise ValueError("Qt5 BW dispatch reference drift")
    return report, digest


def build_report(qt5_report_path: pathlib.Path) -> dict[str, Any]:
    qt5, qt5_sha256 = load_qt5_reference(qt5_report_path)
    identity = inspect_image()
    artifacts: dict[str, dict[str, Any]] = {}
    executions = []
    raw_pairs = []
    documents = []
    for _ in range(REPETITIONS):
        process = observe()
        if process.returncode != 0 or process.stderr:
            raise ValueError("Qt6 BW harness execution failed")
        document = strict_json(process.stdout)
        relationships = BASE.validate(document)
        raw_pairs.append((process.stdout, process.stderr))
        documents.append(document)
        executions.append(
            {
                "exit_code": process.returncode,
                "stdout": raw_stream(process.stdout, artifacts),
                "stderr": raw_stream(process.stderr, artifacts),
            }
        )
    if raw_pairs[0] != raw_pairs[1] or documents[0] != documents[1]:
        raise ValueError("Qt6 BW harness output is unstable")
    if documents[0] != qt5["harness_output"]:
        raise ValueError("Qt5/Qt6 BW harness semantics differ")
    qt5_oracle = qt5["oracle"]
    differences = []
    if executions[0]["stdout"]["sha256"] != qt5_oracle[
        "raw_stdout_sha256"
    ]:
        differences.append("stdout")
    if executions[0]["stderr"]["sha256"] != qt5_oracle[
        "raw_stderr_sha256"
    ]:
        differences.append("stderr")
    if differences:
        raise ValueError(f"Qt5/Qt6 BW raw difference: {differences}")

    return {
        "schema_version": 1,
        "generator": (
            "tools/upstream/probe_qt6_bw_dispatch_harness.py"
        ),
        "generator_sha256": sha256(
            pathlib.Path(__file__).read_bytes()
        ),
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "platform": "linux-amd64-qt5-qt6",
        "capability": "CAP-DISPATCH-002",
        "harness": {
            "source": "tools/upstream/bw_dispatch_harness_main.cpp",
            "source_sha256": sha256(BASE.HARNESS_SOURCE.read_bytes()),
            "qt6_dockerfile": (
                "tools/upstream/"
                "Dockerfile.bw-dispatch-harness-qt6"
            ),
            "qt6_dockerfile_sha256": sha256(DOCKERFILE.read_bytes()),
        },
        "qt5_reference": {
            "path": (
                "docs/research/data/"
                "bw-dispatch-engine-qt5.json"
            ),
            "sha256": qt5_sha256,
        },
        "qt6_oracle": identity,
        "resource_limits": {
            "network": "none",
            "cpus": 1,
            "memory_bytes": 512 * 1024 * 1024,
            "pids": 128,
            "timeout_seconds_per_execution": 60,
            "container_root": "read-only",
        },
        "repetitions": REPETITIONS,
        "executions": executions,
        "raw_artifacts": artifacts,
        "relationships": relationships,
        "harness_output": documents[0],
        "comparison": {
            "semantic_output_equal": True,
            "raw_stream_differences": differences,
        },
        "failures": [],
        "closed_capability_part": "BW DOS16M property-only branch",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--qt5-report",
        type=pathlib.Path,
        default=(
            ROOT
            / "docs"
            / "research"
            / "data"
            / "bw-dispatch-engine-qt5.json"
        ),
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    report = build_report(args.qt5_report.resolve())
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

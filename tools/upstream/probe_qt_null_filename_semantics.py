#!/usr/bin/env python3
"""Compare the pinned Qt5/Qt6 NUL filename string semantics."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any


GENERATOR = "tools/upstream/probe_qt_null_filename_semantics.py"
SOURCE = "tools/upstream/qt_null_filename_probe.cpp"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
ORACLES = {
    "qt5": {
        "image": (
            "die-rust/upstream-archive-iteration-boundary-harness:74eaf505"
        ),
        "image_id": (
            "sha256:6cfc6dfb568e1287103bbe92f31e75864153b6bf5f196a744178d9c86ae19392"
        ),
        "expected": {
            "equals_c_string": True,
            "equals_explicit_null": False,
            "first_code_unit": -1,
            "qt_version": "5.15.13",
            "string_size": 0,
        },
    },
    "qt6": {
        "image": (
            "die-rust/archive-iteration-boundary-harness-qt6:74eaf505"
        ),
        "image_id": (
            "sha256:a51310e8e03ada9fb907d6ea3d3d3b0a5d0c1917a3aaef971f3a07683486508f"
        ),
        "expected": {
            "equals_c_string": False,
            "equals_explicit_null": True,
            "first_code_unit": 0,
            "qt_version": "6.4.2",
            "string_size": 1,
        },
    },
}
COMPILE_SCRIPT = r"""
set -eu
object_dir=/opt/die-build/src/console/CMakeFiles/diec.dir
cd /opt/die-build/src/console
harness_defines="$(sed -n 's/^CXX_DEFINES = //p' "${object_dir}/flags.make")"
harness_includes="$(sed -n 's/^CXX_INCLUDES = //p' "${object_dir}/flags.make")"
harness_flags="$(sed -n 's/^CXX_FLAGS = //p' "${object_dir}/flags.make")"
/usr/bin/c++ ${harness_defines} ${harness_includes} ${harness_flags} \
    -c /probe/qt_null_filename_probe.cpp -o /tmp/qt_null_filename_probe.o
sed \
    -e 's#CMakeFiles/diec.dir/main_console.cpp.o#/tmp/qt_null_filename_probe.o#' \
    -e 's# -o diec # -o qt-null-filename-probe #' \
    "${object_dir}/link.txt" > /tmp/link-qt-null-filename-probe.sh
sh /tmp/link-qt-null-filename-probe.sh
/opt/die-build/src/console/qt-null-filename-probe
"""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def observe(
    image: str,
    source: Path,
    docker_context: str,
) -> tuple[dict[str, Any], bytes, bytes]:
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
            "--mount",
            (
                f"type=bind,source={source.parent},"
                "target=/probe,readonly"
            ),
            "--entrypoint",
            "sh",
            image,
            "-c",
            COMPILE_SCRIPT,
        ],
        check=False,
        capture_output=True,
    )
    if process.returncode != 0 or process.stderr:
        raise ValueError("Qt NUL filename probe compile/run failed")
    try:
        result = json.loads(process.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid Qt NUL filename probe output") from error
    if not isinstance(result, dict):
        raise ValueError("Qt NUL filename probe output must be an object")
    return result, process.stdout, process.stderr


def build_report(docker_context: str) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    source = root / SOURCE
    observations: dict[str, Any] = {}
    for oracle_name, oracle in ORACLES.items():
        image_id, revision = inspect_image(
            oracle["image"],
            docker_context,
        )
        if (
            image_id != oracle["image_id"]
            or revision != UPSTREAM_COMMIT
        ):
            raise ValueError(f"{oracle_name} image identity drift")
        result, stdout, stderr = observe(
            oracle["image"],
            source,
            docker_context,
        )
        if result != oracle["expected"]:
            raise ValueError(
                f"{oracle_name} Qt string semantics drift: {result!r}"
            )
        observations[oracle_name] = {
            "image": oracle["image"],
            "image_id": image_id,
            "revision": revision,
            "exit_code": 0,
            "stdout": stdout.decode("utf-8"),
            "stdout_sha256": sha256(stdout),
            "stderr": stderr.decode("utf-8"),
            "stderr_sha256": sha256(stderr),
            "result": result,
        }

    relationships = {
        "qt5_from_latin1_truncates_at_nul": (
            observations["qt5"]["result"]["string_size"] == 0
            and observations["qt5"]["result"]["first_code_unit"] == -1
            and observations["qt5"]["result"][
                "equals_explicit_null"
            ]
            is False
        ),
        "qt6_from_latin1_preserves_one_nul_code_unit": (
            observations["qt6"]["result"]["string_size"] == 1
            and observations["qt6"]["result"]["first_code_unit"] == 0
            and observations["qt6"]["result"][
                "equals_explicit_null"
            ]
            is True
        ),
        "qt5_nul_string_equals_nul_c_string": (
            observations["qt5"]["result"]["equals_c_string"] is True
        ),
        "qt6_nul_string_does_not_equal_nul_c_string": (
            observations["qt6"]["result"]["equals_c_string"] is False
        ),
        "iso_dot_filter_expression_changes_across_qt_versions": (
            observations["qt5"]["result"]["equals_c_string"]
            != observations["qt6"]["result"]["equals_c_string"]
        ),
    }
    if not all(relationships.values()):
        raise ValueError("Qt NUL filename relationships drift")
    return {
        "schema_version": 1,
        "generator": GENERATOR,
        "generator_sha256": sha256(Path(__file__).read_bytes()),
        "source": {
            "path": SOURCE,
            "sha256": sha256(source.read_bytes()),
        },
        "upstream_commit": UPSTREAM_COMMIT,
        "platform": "linux-x86_64-qt5-qt6",
        "result": "observed",
        "observations": observations,
        "relationships": relationships,
        "relevance": {
            "component": "XArchive/xiso9660.cpp",
            "expression": (
                'sFileName == "\\x00" in the dot-entry filter'
            ),
            "qt6_effect": (
                "the one-NUL dot entry is retained before real ISO records"
            ),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-context", default="default")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args.docker_context)
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

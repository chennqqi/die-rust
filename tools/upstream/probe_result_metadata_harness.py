#!/usr/bin/env python3
"""Probe SCAN_RESULT scalar metadata across all public scan entry points."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
FORMATS_COMMIT = "1151e7254fdee3c0294ff7095edbdd7bfccf8201"
XSCANENGINE_COMMIT = "dfe4a419e4f491bb23688ba03c5a5bf39e34da83"
IMAGE = "die-rust/result-metadata-harness-qt5:74eaf505"
BINARY = "/opt/die-build/src/console/die-result-metadata-harness"
INPUT_SIZE = 0x80
FILE_PATH = "/tmp/die-result-metadata-input.exe"
DEVICE_NAME = "named-device.exe"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_image() -> tuple[str, str]:
    process = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        check=True,
        capture_output=True,
    )
    document = json.loads(process.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision", ""
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError("result metadata image revision mismatch")
    return document["Id"], revision


def docker_bytes(entrypoint: str, *arguments: str) -> bytes:
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            entrypoint,
            IMAGE,
            *arguments,
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError(f"{entrypoint} wrote stderr")
    return process.stdout


def case_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cases = document.get("cases")
    if not isinstance(cases, list):
        raise ValueError("result metadata cases must be an array")
    if document.get("case_count") != len(cases):
        raise ValueError("result metadata case count mismatch")
    result = {str(case["id"]): case for case in cases}
    if len(result) != len(cases):
        raise ValueError("duplicate result metadata case id")
    return result


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate(document: dict[str, Any]) -> dict[str, bool]:
    if document.get("schema_version") != 1:
        raise ValueError("unsupported result metadata schema")
    if document.get("upstream_commit") != UPSTREAM_COMMIT:
        raise ValueError("result metadata upstream commit mismatch")
    if document.get("formats_commit") != FORMATS_COMMIT:
        raise ValueError("result metadata Formats commit mismatch")
    if document.get("xscanengine_commit") != XSCANENGINE_COMMIT:
        raise ValueError("result metadata XScanEngine commit mismatch")
    if document.get("input_size") != INPUT_SIZE:
        raise ValueError("result metadata input size mismatch")
    if document.get("file_path") != FILE_PATH:
        raise ValueError("result metadata file path mismatch")
    if document.get("device_name") != DEVICE_NAME:
        raise ValueError("result metadata device name mismatch")
    input_hex = document.get("input_hex")
    if not isinstance(input_hex, str) or len(input_hex) != INPUT_SIZE * 2:
        raise ValueError("result metadata input hex mismatch")

    cases = case_map(document)
    if set(cases) != {"file", "memory", "device", "subdevice"}:
        raise ValueError("unexpected result metadata case inventory")

    scalar_fields_present = all(
        all(
            field in case
            for field in (
                "nScanTime",
                "sFileName",
                "nSize",
                "ftInit",
                "ftInit_string",
            )
        )
        for case in cases.values()
    )
    scan_time_typed_nonnegative = all(
        _is_integer(case["nScanTime"]) and case["nScanTime"] >= 0
        for case in cases.values()
    )
    sizes_match_identical_input = all(
        case["nSize"] == INPUT_SIZE for case in cases.values()
    )
    filetype_is_consistent_msdos = (
        all(
            _is_integer(case["ftInit"])
            and case["ftInit_string"] == "MSDOS"
            for case in cases.values()
        )
        and len({case["ftInit"] for case in cases.values()}) == 1
    )
    filenames_follow_entrypoint = (
        cases["file"]["sFileName"] == FILE_PATH
        and cases["device"]["sFileName"] == DEVICE_NAME
        and cases["memory"]["sFileName"] == ""
        and cases["subdevice"]["sFileName"] == ""
    )
    scans_complete_without_errors = all(
        case["scan_success"]
        and case["error_count"] == 0
        and "harness_error" not in case
        for case in cases.values()
    )
    relationships = {
        "scalar_fields_present": scalar_fields_present,
        "scan_time_typed_nonnegative": scan_time_typed_nonnegative,
        "sizes_match_identical_input": sizes_match_identical_input,
        "filetype_is_consistent_msdos": filetype_is_consistent_msdos,
        "filenames_follow_entrypoint": filenames_follow_entrypoint,
        "scans_complete_without_errors": scans_complete_without_errors,
    }
    failed = [name for name, passed in relationships.items() if not passed]
    if failed:
        raise ValueError(
            f"result metadata relationships failed: {failed}"
        )
    return relationships


def build_report(raw_dir: pathlib.Path) -> dict[str, Any]:
    image_id, revision = inspect_image()
    binary_digest = docker_bytes("/usr/bin/sha256sum", BINARY).split()[0]
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            BINARY,
            IMAGE,
        ],
        check=False,
        capture_output=True,
    )
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "result-metadata.stdout").write_bytes(process.stdout)
    (raw_dir / "result-metadata.stderr").write_bytes(process.stderr)
    if process.returncode != 0 or process.stderr:
        raise ValueError("result metadata harness process failed")
    document = json.loads(process.stdout)
    relationships = validate(document)
    return {
        "schema_version": 1,
        "generator": (
            "tools/upstream/probe_result_metadata_harness.py"
        ),
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "platform": "linux-amd64-qt5",
        "capability": "CAP-RESULT-001",
        "oracle": {
            "image": IMAGE,
            "image_id": image_id,
            "revision": revision,
            "binary": BINARY,
            "binary_sha256": binary_digest.decode("ascii"),
            "exit_code": process.returncode,
            "raw_stdout_bytes": len(process.stdout),
            "raw_stdout_sha256": sha256(process.stdout),
            "raw_stderr_bytes": len(process.stderr),
            "raw_stderr_sha256": sha256(process.stderr),
        },
        "raw_artifacts": {
            "storage": (
                "untracked external directory selected by --raw-dir"
            )
        },
        "relationships": relationships,
        "harness_output": document,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = build_report(args.raw_dir.resolve())
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

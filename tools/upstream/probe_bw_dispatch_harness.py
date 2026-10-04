#!/usr/bin/env python3
"""Probe automatic versus forced-property BW DOS16M dispatch."""

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
IMAGE = "die-rust/bw-dispatch-harness-qt5:74eaf505"
BINARY = "/opt/die-build/src/console/die-bw-dispatch-harness"
INPUT_HEX = "42570000000000000000"
ROOT = pathlib.Path(__file__).resolve().parents[2]
HARNESS_SOURCE = ROOT / "tools" / "upstream" / "bw_dispatch_harness_main.cpp"
DOCKERFILE = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.bw-dispatch-harness-qt5"
)


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
        raise ValueError("BW harness image revision mismatch")
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
        raise ValueError("BW harness cases must be an array")
    if document.get("case_count") != len(cases):
        raise ValueError("BW harness case count mismatch")
    result = {str(case["id"]): case for case in cases}
    if len(result) != len(cases):
        raise ValueError("duplicate BW harness case id")
    return result


def validate(document: dict[str, Any]) -> dict[str, bool]:
    if document.get("schema_version") != 1:
        raise ValueError("unsupported BW harness schema")
    if document.get("upstream_commit") != UPSTREAM_COMMIT:
        raise ValueError("BW harness upstream commit mismatch")
    if document.get("formats_commit") != FORMATS_COMMIT:
        raise ValueError("BW harness Formats commit mismatch")
    if document.get("xscanengine_commit") != XSCANENGINE_COMMIT:
        raise ValueError("BW harness XScanEngine commit mismatch")
    if document.get("input_hex") != INPUT_HEX:
        raise ValueError("BW harness input mismatch")

    cases = case_map(document)
    if set(cases) != {"automatic_detection", "forced_property"}:
        raise ValueError("unexpected BW harness case inventory")
    automatic = cases["automatic_detection"]
    forced = cases["forced_property"]
    relationships = {
        "automatic_detector_does_not_emit_bw": (
            "BWDOS16M"
            not in automatic["detected_filetypes"].split("|")
        ),
        "automatic_scan_does_not_initialize_bw": (
            automatic["initial_filetype"] != "BW DOS16M"
        ),
        "forced_property_is_exact": (
            forced["property"] == "BWDOS16M"
            and forced["detected_filetypes"] == "BWDOS16M"
        ),
        "forced_scan_reaches_bw_branch": (
            forced["initial_filetype"] == "BW DOS16M"
            and any(
                record["filetype"] == "BW DOS16M"
                for record in forced["records"]
            )
        ),
        "forced_fallback_is_explicit_unknown": (
            len(forced["records"]) == 1
            and forced["records"][0]["unknown"]
            and forced["records"][0]["name"] == "Unknown"
        ),
        "both_scans_complete_without_errors": (
            automatic["error_count"] == 0
            and forced["error_count"] == 0
            and automatic["scan_success"]
            and forced["scan_success"]
        ),
    }
    failed = [name for name, passed in relationships.items() if not passed]
    if failed:
        raise ValueError(f"BW harness relationships failed: {failed}")
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
    (raw_dir / "bw-dispatch.stdout").write_bytes(process.stdout)
    (raw_dir / "bw-dispatch.stderr").write_bytes(process.stderr)
    if process.returncode != 0 or process.stderr:
        raise ValueError("BW dispatch harness process failed")
    document = json.loads(process.stdout)
    relationships = validate(document)
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_bw_dispatch_harness.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "platform": "linux-amd64-qt5",
        "capability": "CAP-DISPATCH-002",
        "harness": {
            "source": "tools/upstream/bw_dispatch_harness_main.cpp",
            "source_sha256": sha256(HARNESS_SOURCE.read_bytes()),
            "dockerfile": (
                "tools/upstream/Dockerfile.bw-dispatch-harness-qt5"
            ),
            "dockerfile_sha256": sha256(DOCKERFILE.read_bytes()),
        },
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
            "storage": "untracked external directory selected by --raw-dir"
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

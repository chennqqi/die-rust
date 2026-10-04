#!/usr/bin/env python3
"""Probe SCANSTRUCT heuristic and unknown flags with fixed benign rules."""

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
DIE_SCRIPT_COMMIT = "5d82316c110abf0eb863b50bc679d330e05067b6"
IMAGE = "die-rust/result-flags-harness-qt5:74eaf505"
BINARY = "/opt/die-build/src/console/die-result-flags-harness"
INPUT_SHA256 = (
    "28aa71cff9d35029534ce01a6c64d944e910f9b0232b9519679c79abf2288b87"
)
EXPECTED_CASES = {
    "normal": {
        "database": "main",
        "signature": "normal.1.sg",
        "heuristic_scan": False,
        "type": "format",
        "name": "Normal",
        "heuristic": False,
        "advanced_heuristic": False,
        "unknown": False,
    },
    "heuristic": {
        "database": "main",
        "signature": "HEUR.heuristic.2.sg",
        "heuristic_scan": True,
        "type": "~format",
        "name": "Heuristic",
        "heuristic": True,
        "advanced_heuristic": False,
        "unknown": False,
    },
    "advanced_heuristic": {
        "database": "main",
        "signature": "HEUR.advanced.3.sg",
        "heuristic_scan": True,
        "type": "!format",
        "name": "Advanced",
        "heuristic": False,
        "advanced_heuristic": True,
        "unknown": False,
    },
    "unknown": {
        "database": "empty-main",
        "signature": "",
        "heuristic_scan": False,
        "type": "Unknown",
        "name": "Unknown",
        "heuristic": False,
        "advanced_heuristic": False,
        "unknown": True,
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def verify_fixture(
    fixture_dir: pathlib.Path,
    committed_manifest: pathlib.Path,
) -> tuple[dict[str, Any], str]:
    manifest_path = fixture_dir / "manifest.json"
    if manifest_path.read_bytes() != committed_manifest.read_bytes():
        raise ValueError("result-flag fixture manifest differs from committed")
    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported result-flag fixture schema")
    if (
        manifest.get("generator")
        != "tools/corpus/generate_result_flag_fixture.py"
    ):
        raise ValueError("result-flag fixture generator mismatch")
    if manifest.get("capability") != "CAP-RESULT-003":
        raise ValueError("result-flag fixture capability mismatch")
    if manifest.get("cases") != {
        case_id: {
            field: expected[field]
            for field in ("database", "signature", "heuristic_scan")
        }
        for case_id, expected in EXPECTED_CASES.items()
    }:
        raise ValueError("result-flag fixture case inventory mismatch")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("result-flag fixture entries must be non-empty")
    for entry in entries:
        path = fixture_dir / pathlib.PurePosixPath(entry["path"])
        data = path.read_bytes()
        if len(data) != entry["size"]:
            raise ValueError(f"fixture size mismatch: {entry['path']}")
        if sha256(data) != entry["sha256"]:
            raise ValueError(f"fixture hash mismatch: {entry['path']}")
    input_entries = [
        entry for entry in entries if entry["path"] == "input/probe.bin"
    ]
    if (
        len(input_entries) != 1
        or input_entries[0]["sha256"] != INPUT_SHA256
    ):
        raise ValueError("result-flag fixture input identity mismatch")
    return manifest, sha256(manifest_path.read_bytes())


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
        raise ValueError("result-flag image revision mismatch")
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
        raise ValueError("result-flag cases must be an array")
    if document.get("case_count") != len(cases):
        raise ValueError("result-flag case count mismatch")
    result = {str(case["id"]): case for case in cases}
    if len(result) != len(cases):
        raise ValueError("duplicate result-flag case id")
    return result


def validate(document: dict[str, Any]) -> dict[str, bool]:
    identities = {
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "input_sha256": INPUT_SHA256,
    }
    if document.get("schema_version") != 1:
        raise ValueError("unsupported result-flag harness schema")
    for field, expected in identities.items():
        if document.get(field) != expected:
            raise ValueError(f"result-flag {field} mismatch")

    cases = case_map(document)
    if set(cases) != set(EXPECTED_CASES):
        raise ValueError("unexpected result-flag case inventory")

    single_record_per_case = all(
        len(case.get("records", [])) == 1
        for case in cases.values()
    )
    metadata_matches_fixture = all(
        cases[case_id]["database"] == expected["database"]
        and cases[case_id]["signature"] == expected["signature"]
        and cases[case_id]["heuristic_scan"]
        is expected["heuristic_scan"]
        for case_id, expected in EXPECTED_CASES.items()
    )
    raw_types_and_names_preserved = all(
        cases[case_id]["records"][0]["type"] == expected["type"]
        and cases[case_id]["records"][0]["name"] == expected["name"]
        for case_id, expected in EXPECTED_CASES.items()
    )
    flags_match_independently = all(
        all(
            cases[case_id]["records"][0][field] is expected[field]
            for field in (
                "heuristic",
                "advanced_heuristic",
                "unknown",
            )
        )
        for case_id, expected in EXPECTED_CASES.items()
    )
    positive_flags_are_mutually_exclusive = all(
        sum(
            bool(cases[case_id]["records"][0][field])
            for field in (
                "heuristic",
                "advanced_heuristic",
                "unknown",
            )
        )
        == (0 if case_id == "normal" else 1)
        for case_id in EXPECTED_CASES
    )
    scans_loaded_without_errors = all(
        case["database_loaded"]
        and case["load_not_canceled"]
        and case["scan_not_canceled"]
        and case["error_count"] == 0
        for case in cases.values()
    )
    relationships = {
        "single_record_per_case": single_record_per_case,
        "metadata_matches_fixture": metadata_matches_fixture,
        "raw_types_and_names_preserved": raw_types_and_names_preserved,
        "flags_match_independently": flags_match_independently,
        "positive_flags_are_mutually_exclusive": (
            positive_flags_are_mutually_exclusive
        ),
        "scans_loaded_without_errors": scans_loaded_without_errors,
    }
    failed = [name for name, passed in relationships.items() if not passed]
    if failed:
        raise ValueError(f"result-flag relationships failed: {failed}")
    return relationships


def build_report(
    fixture_dir: pathlib.Path,
    committed_manifest: pathlib.Path,
    raw_dir: pathlib.Path,
) -> dict[str, Any]:
    fixture_manifest, fixture_manifest_sha256 = verify_fixture(
        fixture_dir,
        committed_manifest,
    )
    image_id, revision = inspect_image()
    binary_digest = docker_bytes("/usr/bin/sha256sum", BINARY).split()[0]
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--mount",
            f"type=bind,src={fixture_dir},dst=/fixture,readonly",
            "--entrypoint",
            BINARY,
            IMAGE,
            "/fixture",
        ],
        check=False,
        capture_output=True,
    )
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "result-flags.stdout").write_bytes(process.stdout)
    (raw_dir / "result-flags.stderr").write_bytes(process.stderr)
    if process.returncode != 0 or process.stderr:
        raise ValueError("result-flag harness process failed")
    document = json.loads(process.stdout)
    relationships = validate(document)
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_result_flags_harness.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "platform": "linux-amd64-qt5",
        "capability": "CAP-RESULT-003",
        "fixture": {
            "manifest": (
                "docs/research/data/result-flag-fixture.json"
            ),
            "manifest_sha256": fixture_manifest_sha256,
            "entry_count": len(fixture_manifest["entries"]),
            "license": fixture_manifest["license"],
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
            "storage": (
                "untracked external directory selected by --raw-dir"
            )
        },
        "relationships": relationships,
        "harness_output": document,
    }


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument(
        "--committed-manifest",
        type=pathlib.Path,
        default=(
            root
            / "docs"
            / "research"
            / "data"
            / "result-flag-fixture.json"
        ),
    )
    args = parser.parse_args()
    report = build_report(
        args.fixture_dir.resolve(),
        args.committed_manifest.resolve(),
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

#!/usr/bin/env python3
"""Probe the pinned engine's private signature-file path filter."""

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
IMAGE = "die-rust/signature-path-harness-qt5:74eaf505"
BINARY = "/opt/die-build/src/console/die-signature-path-harness"
INPUT_SHA256 = (
    "ec19bc91132237e7293ac3a67caab394c86acad9e7f6dec4a403bfee42d95f8e"
)
CASE_METADATA = {
    "empty_filter": {
        "filter": "",
        "expected_names": ["main-path", "extra-path"],
    },
    "exact_main": {
        "filter": "main/Binary/shared.1.sg",
        "expected_names": ["main-path"],
    },
    "exact_extra": {
        "filter": "extra/Binary/shared.1.sg",
        "expected_names": ["extra-path"],
    },
    "missing": {
        "filter": "main/Binary/missing.1.sg",
        "expected_names": [],
    },
    "case_mismatch": {
        "filter": "main/Binary/SHARED.1.SG",
        "expected_names": [],
    },
    "dot_segment": {
        "filter": "main/Binary/../Binary/shared.1.sg",
        "expected_names": [],
    },
    "basename_only": {
        "filter": "shared.1.sg",
        "expected_names": [],
    },
}
ROOT = pathlib.Path(__file__).resolve().parents[2]
HARNESS_SOURCE = (
    ROOT / "tools" / "upstream" / "signature_path_harness_main.cpp"
)
DOCKERFILE = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.signature-path-harness-qt5"
)


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
        raise ValueError("signature-path fixture differs from committed")
    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported signature-path fixture schema")
    if (
        manifest.get("generator")
        != "tools/corpus/generate_signature_path_fixture.py"
    ):
        raise ValueError("signature-path fixture generator mismatch")
    if manifest.get("capability") != "CAP-RULE-007":
        raise ValueError("signature-path fixture capability mismatch")
    if manifest.get("cases") != CASE_METADATA:
        raise ValueError("signature-path fixture case inventory mismatch")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != 3:
        raise ValueError("signature-path fixture entries mismatch")
    for entry in entries:
        path = fixture_dir / pathlib.PurePosixPath(entry["path"])
        data = path.read_bytes()
        if len(data) != entry["size"]:
            raise ValueError(f"fixture size mismatch: {entry['path']}")
        if sha256(data) != entry["sha256"]:
            raise ValueError(f"fixture hash mismatch: {entry['path']}")
    inputs = [
        entry for entry in entries if entry["path"] == "input/probe.bin"
    ]
    if len(inputs) != 1 or inputs[0]["sha256"] != INPUT_SHA256:
        raise ValueError("signature-path fixture input identity mismatch")
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
        raise ValueError("signature-path image revision mismatch")
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
        raise ValueError("signature-path cases must be an array")
    if document.get("case_count") != len(cases):
        raise ValueError("signature-path case count mismatch")
    result = {str(case["id"]): case for case in cases}
    if len(result) != len(cases):
        raise ValueError("duplicate signature-path case id")
    return result


def record_names(case: dict[str, Any]) -> list[str]:
    return [str(record["name"]) for record in case["records"]]


def validate(document: dict[str, Any]) -> dict[str, bool]:
    identities = {
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "input_sha256": INPUT_SHA256,
        "fixture_root": "/fixture",
    }
    if document.get("schema_version") != 1:
        raise ValueError("unsupported signature-path harness schema")
    for field, expected in identities.items():
        if document.get(field) != expected:
            raise ValueError(f"signature-path {field} mismatch")

    cases = case_map(document)
    if set(cases) != set(CASE_METADATA):
        raise ValueError("unexpected signature-path case inventory")
    if any(
        case.get("record_count") != len(case.get("records", []))
        for case in cases.values()
    ):
        raise ValueError("signature-path record count mismatch")

    main_path = "/fixture/main/Binary/shared.1.sg"
    extra_path = "/fixture/extra/Binary/shared.1.sg"
    expected_filters = {
        case_id: (
            ""
            if metadata["filter"] == ""
            else (
                metadata["filter"]
                if case_id == "basename_only"
                else f"/fixture/{metadata['filter']}"
            )
        )
        for case_id, metadata in CASE_METADATA.items()
    }
    filters_are_passed_verbatim = all(
        cases[case_id]["filter"] == expected
        for case_id, expected in expected_filters.items()
    )
    empty_records = cases["empty_filter"]["records"]
    empty_filter_executes_both_layers = (
        set(record_names(cases["empty_filter"]))
        == {"main-path", "extra-path"}
        and {record["signature_path"] for record in empty_records}
        == {main_path, extra_path}
    )
    exact_main_selects_only_main = (
        record_names(cases["exact_main"]) == ["main-path"]
        and cases["exact_main"]["records"][0]["signature_path"]
        == main_path
    )
    exact_extra_selects_only_extra = (
        record_names(cases["exact_extra"]) == ["extra-path"]
        and cases["exact_extra"]["records"][0]["signature_path"]
        == extra_path
    )
    nonexistent_path_matches_nothing = (
        cases["missing"]["record_count"] == 0
    )
    comparison_is_case_sensitive = (
        cases["case_mismatch"]["record_count"] == 0
    )
    comparison_does_not_clean_dot_segments = (
        cases["dot_segment"]["record_count"] == 0
    )
    basename_is_not_a_path_match = (
        cases["basename_only"]["record_count"] == 0
    )
    same_basename_does_not_conflate_layers = (
        len(empty_records) == 2
        and {record["signature"] for record in empty_records}
        == {"shared.1.sg"}
        and len({record["signature_path"] for record in empty_records})
        == 2
    )
    loaded = document.get("loaded_signatures")
    both_fixture_rules_loaded_with_absolute_paths = (
        isinstance(loaded, list)
        and len(loaded) == 2
        and {item["name"] for item in loaded} == {"shared.1.sg"}
        and {item["file_path"] for item in loaded}
        == {main_path, extra_path}
        and {item["database_type"] for item in loaded} == {0, 1}
    )
    all_runs_complete_without_errors = (
        document.get("database_loaded") is True
        and document.get("load_not_canceled") is True
        and all(
            case["scan_not_canceled"]
            and case["error_count"] == 0
            for case in cases.values()
        )
    )
    relationships = {
        "filters_are_passed_verbatim": filters_are_passed_verbatim,
        "empty_filter_executes_both_layers": (
            empty_filter_executes_both_layers
        ),
        "exact_main_selects_only_main": exact_main_selects_only_main,
        "exact_extra_selects_only_extra": exact_extra_selects_only_extra,
        "nonexistent_path_matches_nothing": (
            nonexistent_path_matches_nothing
        ),
        "comparison_is_case_sensitive": comparison_is_case_sensitive,
        "comparison_does_not_clean_dot_segments": (
            comparison_does_not_clean_dot_segments
        ),
        "basename_is_not_a_path_match": basename_is_not_a_path_match,
        "same_basename_does_not_conflate_layers": (
            same_basename_does_not_conflate_layers
        ),
        "both_fixture_rules_loaded_with_absolute_paths": (
            both_fixture_rules_loaded_with_absolute_paths
        ),
        "all_runs_complete_without_errors": (
            all_runs_complete_without_errors
        ),
    }
    failed = [name for name, passed in relationships.items() if not passed]
    if failed:
        raise ValueError(
            f"signature-path relationships failed: {failed}"
        )
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
    (raw_dir / "signature-path.stdout").write_bytes(process.stdout)
    (raw_dir / "signature-path.stderr").write_bytes(process.stderr)
    if process.returncode != 0 or process.stderr:
        raise ValueError("signature-path harness process failed")
    document = json.loads(process.stdout)
    relationships = validate(document)
    return {
        "schema_version": 1,
        "generator": (
            "tools/upstream/probe_signature_path_harness.py"
        ),
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "platform": "linux-amd64-qt5",
        "capability": "CAP-RULE-007",
        "fixture": {
            "manifest": (
                "docs/research/data/signature-path-fixture.json"
            ),
            "manifest_sha256": fixture_manifest_sha256,
            "license": fixture_manifest["license"],
            "entry_count": len(fixture_manifest["entries"]),
        },
        "harness": {
            "source": (
                "tools/upstream/signature_path_harness_main.cpp"
            ),
            "source_sha256": sha256(HARNESS_SOURCE.read_bytes()),
            "dockerfile": (
                "tools/upstream/"
                "Dockerfile.signature-path-harness-qt5"
            ),
            "dockerfile_sha256": sha256(DOCKERFILE.read_bytes()),
            "access_method": (
                "translation-unit-only private-to-public macro; "
                "pinned engine objects are unmodified"
            ),
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
    parser.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    parser.add_argument(
        "--committed-manifest",
        type=pathlib.Path,
        required=True,
    )
    parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
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

#!/usr/bin/env python3
"""Probe all four SCAN_RESULT list fields with fixed benign rules."""

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
IMAGE = "die-rust/result-lists-harness-qt5:74eaf505"
BINARY = "/opt/die-build/src/console/die-result-lists-harness"
INPUT_SHA256 = (
    "789b791f239520d2244dfa30bcec3dbf5b77db407d8cbca4aba64b29e99c8b54"
)
COLLECTION_ROOT = "/tmp/die-result-list-collection"
EXPECTED_SCRIPTS = [
    "a_first.1.sg",
    "b_second.1.sg",
    "c_runtime_error.1.sg",
    "d_parse_error.1.sg",
]


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
        raise ValueError("result-list fixture manifest differs from committed")
    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported result-list fixture schema")
    if (
        manifest.get("generator")
        != "tools/corpus/generate_result_list_fixture.py"
    ):
        raise ValueError("result-list fixture generator mismatch")
    if manifest.get("capability") != "CAP-RESULT-002":
        raise ValueError("result-list fixture capability mismatch")
    if manifest.get("expected_signature_order") != EXPECTED_SCRIPTS:
        raise ValueError("result-list fixture signature order mismatch")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("result-list fixture entries must be non-empty")
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
        raise ValueError("result-list fixture input identity mismatch")
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
        raise ValueError("result-list image revision mismatch")
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
        raise ValueError("result-list cases must be an array")
    if document.get("case_count") != len(cases):
        raise ValueError("result-list case count mismatch")
    result = {str(case["id"]): case for case in cases}
    if len(result) != len(cases):
        raise ValueError("duplicate result-list case id")
    return result


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate(document: dict[str, Any]) -> dict[str, bool]:
    identities = {
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "input_sha256": INPUT_SHA256,
        "collection_root": COLLECTION_ROOT,
    }
    if document.get("schema_version") != 1:
        raise ValueError("unsupported result-list harness schema")
    for field, expected in identities.items():
        if document.get(field) != expected:
            raise ValueError(f"result-list {field} mismatch")

    cases = case_map(document)
    if set(cases) != {"default_success", "all_lists"}:
        raise ValueError("unexpected result-list case inventory")
    default = cases["default_success"]
    complete = cases["all_lists"]
    fields = ("records", "errors", "debug_records", "handlers")
    lists_serialized_independently = all(
        isinstance(case.get(field), list)
        for case in cases.values()
        for field in fields
    )
    default_has_only_record_list = (
        len(default["records"]) == 1
        and default["records"][0]["name"] == "Duplicate"
        and default["errors"] == []
        and default["debug_records"] == []
        and default["handlers"] == []
    )
    duplicate_records_preserved_in_order = (
        len(complete["records"]) == 2
        and [
            record["name"] for record in complete["records"]
        ] == ["Duplicate", "Duplicate"]
        and [
            record["signature"] for record in complete["records"]
        ] == ["a_first.1.sg", "b_second.1.sg"]
    )
    errors_preserved_separately_in_order = (
        len(complete["errors"]) == 2
        and [
            error["script"] for error in complete["errors"]
        ] == EXPECTED_SCRIPTS[2:]
        and all(error["message"] for error in complete["errors"])
    )
    debug_records_cover_every_rule_in_order = (
        [
            record["script"] for record in complete["debug_records"]
        ] == EXPECTED_SCRIPTS
        and all(
            _is_integer(record["elapsed_ms"])
            and record["elapsed_ms"] >= 0
            for record in complete["debug_records"]
        )
    )
    duplicate_handlers_preserved_in_order = (
        len(complete["handlers"]) == 2
        and complete["handlers"][0] == complete["handlers"][1]
        and complete["handlers"][0]["kind"] == 2
        and complete["handlers"][0]["source"]
        == "/fixture/input/probe.bin"
        and complete["handlers"][0]["destination"]
        == (
            COLLECTION_ROOT
            + "/files/duplicate.bin"
        )
    )
    scans_loaded_and_completed = all(
        case["database_loaded"]
        and case["load_not_canceled"]
        and case["scan_not_canceled"]
        for case in cases.values()
    )
    relationships = {
        "lists_serialized_independently": lists_serialized_independently,
        "default_has_only_record_list": default_has_only_record_list,
        "duplicate_records_preserved_in_order": (
            duplicate_records_preserved_in_order
        ),
        "errors_preserved_separately_in_order": (
            errors_preserved_separately_in_order
        ),
        "debug_records_cover_every_rule_in_order": (
            debug_records_cover_every_rule_in_order
        ),
        "duplicate_handlers_preserved_in_order": (
            duplicate_handlers_preserved_in_order
        ),
        "scans_loaded_and_completed": scans_loaded_and_completed,
    }
    failed = [name for name, passed in relationships.items() if not passed]
    if failed:
        raise ValueError(f"result-list relationships failed: {failed}")
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
    (raw_dir / "result-lists.stdout").write_bytes(process.stdout)
    (raw_dir / "result-lists.stderr").write_bytes(process.stderr)
    if process.returncode != 0 or process.stderr:
        raise ValueError("result-list harness process failed")
    document = json.loads(process.stdout)
    relationships = validate(document)
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_result_lists_harness.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "platform": "linux-amd64-qt5",
        "capability": "CAP-RESULT-002",
        "fixture": {
            "manifest": (
                "docs/research/data/result-list-fixture.json"
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
            / "result-list-fixture.json"
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

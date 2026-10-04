#!/usr/bin/env python3
"""Probe SCANSTRUCT id and parentId relationships on a PE resource."""

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
IMAGE = "die-rust/result-ids-harness-qt5:74eaf505"
BINARY = "/opt/die-build/src/console/die-result-ids-harness"
SAMPLE_NAME = "pe-manifest-resource.exe"
SAMPLE_SIZE = 1024
SAMPLE_SHA256 = (
    "0a973cbde2f520bdbd6e1b75304e4a412462113d4de9a8139cdf997af16641ee"
)
RESOURCE_OFFSET = 608
RESOURCE_SIZE = 20
ID_FIELDS = {
    "uuid",
    "filetype",
    "filetype_string",
    "filepart",
    "filepart_string",
    "version",
    "info",
    "size",
    "offset",
    "original_name",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def verify_corpus(
    corpus_dir: pathlib.Path,
    committed_manifest: pathlib.Path,
) -> tuple[dict[str, Any], str]:
    manifest_path = corpus_dir / "manifest.json"
    if manifest_path.read_bytes() != committed_manifest.read_bytes():
        raise ValueError("nested corpus manifest differs from committed")
    manifest = load_json(manifest_path)
    if (
        manifest.get("generator")
        != "tools/corpus/generate_nested_corpus.py"
    ):
        raise ValueError("nested corpus generator mismatch")
    samples = manifest.get("samples")
    if not isinstance(samples, list):
        raise ValueError("nested corpus samples must be an array")
    matches = [
        sample for sample in samples if sample["name"] == SAMPLE_NAME
    ]
    if len(matches) != 1:
        raise ValueError("nested resource sample inventory mismatch")
    sample = matches[0]
    data = (corpus_dir / SAMPLE_NAME).read_bytes()
    if (
        sample["size"] != SAMPLE_SIZE
        or sample["sha256"] != SAMPLE_SHA256
        or len(data) != SAMPLE_SIZE
        or sha256(data) != SAMPLE_SHA256
    ):
        raise ValueError("nested resource sample identity mismatch")
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
        raise ValueError("result-id image revision mismatch")
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


def _id_shape(value: Any) -> bool:
    return isinstance(value, dict) and set(value) == ID_FIELDS


def validate(document: dict[str, Any]) -> dict[str, bool]:
    identities = {
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "sample_name": SAMPLE_NAME,
        "sample_size": SAMPLE_SIZE,
        "sample_sha256": SAMPLE_SHA256,
    }
    if document.get("schema_version") != 1:
        raise ValueError("unsupported result-id harness schema")
    for field, expected in identities.items():
        if document.get(field) != expected:
            raise ValueError(f"result-id {field} mismatch")
    records = document.get("records")
    if (
        not isinstance(records, list)
        or document.get("record_count") != len(records)
        or len(records) != 2
    ):
        raise ValueError("result-id record inventory mismatch")
    root, child = records

    full_id_shape_is_preserved = all(
        _id_shape(record.get(field))
        for record in records
        for field in ("id", "parent_id")
    )
    both_records_are_explicit_unknown = all(
        record["type"] == "Unknown"
        and record["name"] == "Unknown"
        and record["unknown"]
        for record in records
    )
    uuids_are_nonempty_and_distinct = (
        isinstance(root["id"]["uuid"], str)
        and isinstance(child["id"]["uuid"], str)
        and bool(root["id"]["uuid"])
        and bool(child["id"]["uuid"])
        and root["id"]["uuid"] != child["id"]["uuid"]
    )
    root_id_describes_whole_pe = (
        root["id"]["filetype_string"] == "PE32"
        and root["id"]["filepart_string"] == "Header"
        and root["id"]["offset"] == 0
        and root["id"]["size"] == SAMPLE_SIZE
        and root["parent_id"]["uuid"] == ""
        and root["parent_id"]["filetype_string"] == "Unknown"
        and root["parent_id"]["filepart_string"] == "Header"
    )
    child_id_describes_resource_binary = (
        child["id"]["filetype_string"] == "Binary"
        and child["id"]["filepart_string"] == "Resource"
        and child["id"]["offset"] == RESOURCE_OFFSET
        and child["id"]["size"] == RESOURCE_SIZE
    )
    child_parent_uuid_anchors_root = (
        child["parent_id"]["uuid"] == root["id"]["uuid"]
        and child["parent_id"]["filetype"] == root["id"]["filetype"]
        and child["parent_id"]["filetype_string"]
        == root["id"]["filetype_string"]
    )
    child_parent_carries_edge_metadata = (
        child["parent_id"]["filepart_string"] == "Resource"
        and child["parent_id"]["offset"] == RESOURCE_OFFSET
        and child["parent_id"]["size"] == RESOURCE_SIZE
        and child["parent_id"] != root["id"]
    )
    scans_complete_without_errors = (
        document.get("error_count") == 0
        and document.get("scan_not_canceled") is True
    )
    relationships = {
        "full_id_shape_is_preserved": full_id_shape_is_preserved,
        "both_records_are_explicit_unknown": (
            both_records_are_explicit_unknown
        ),
        "uuids_are_nonempty_and_distinct": (
            uuids_are_nonempty_and_distinct
        ),
        "root_id_describes_whole_pe": root_id_describes_whole_pe,
        "child_id_describes_resource_binary": (
            child_id_describes_resource_binary
        ),
        "child_parent_uuid_anchors_root": (
            child_parent_uuid_anchors_root
        ),
        "child_parent_carries_edge_metadata": (
            child_parent_carries_edge_metadata
        ),
        "scans_complete_without_errors": scans_complete_without_errors,
    }
    failed = [name for name, passed in relationships.items() if not passed]
    if failed:
        raise ValueError(f"result-id relationships failed: {failed}")
    return relationships


def build_report(
    corpus_dir: pathlib.Path,
    committed_manifest: pathlib.Path,
    raw_dir: pathlib.Path,
) -> dict[str, Any]:
    manifest, manifest_sha256 = verify_corpus(
        corpus_dir,
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
            f"type=bind,src={corpus_dir},dst=/corpus,readonly",
            "--entrypoint",
            BINARY,
            IMAGE,
            "/corpus",
        ],
        check=False,
        capture_output=True,
    )
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "result-ids.stdout").write_bytes(process.stdout)
    (raw_dir / "result-ids.stderr").write_bytes(process.stderr)
    if process.returncode != 0 or process.stderr:
        raise ValueError("result-id harness process failed")
    document = json.loads(process.stdout)
    relationships = validate(document)
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_result_ids_harness.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "platform": "linux-amd64-qt5",
        "capability": "CAP-RESULT-004",
        "fixture": {
            "manifest": "docs/research/data/nested-corpus.json",
            "manifest_sha256": manifest_sha256,
            "sample_count": len(manifest["samples"]),
            "selected_sample": SAMPLE_NAME,
            "license": manifest["license"],
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
    parser.add_argument("--corpus-dir", type=pathlib.Path, required=True)
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
            / "nested-corpus.json"
        ),
    )
    args = parser.parse_args()
    report = build_report(
        args.corpus_dir.resolve(),
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

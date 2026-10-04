#!/usr/bin/env python3
"""Probe debug-data enumeration, direct detection, and scanner omission."""

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
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
SAMPLE_NAME = "pe-resource-debug.exe"
SAMPLE_SIZE = 1536
SAMPLE_SHA256 = (
    "58e2b8e73ba187977564e719d39022079b8fb9172c5bcdf40c495ed825b38ea1"
)
RESOURCE_SHA256 = (
    "96f63fca235e4a359900fa17b076d2cb3d16945855b25fcb3c391eb49215428b"
)
DEBUG_SHA256 = (
    "f4062413bf0504b8eb9b30dc76d27a576f75827f0b13822a43eea00706709e5f"
)
RESOURCE_RULE_SHA256 = (
    "2fdad41d666d32467cabe83dae7d16625ade5935e3061c58dfefeb1fb7b99db7"
)
DEBUG_RULE_SHA256 = (
    "381b6259b239f2633b92fbd84fd0d99b972751e20cab12b6e09139a260f1f47d"
)
DEBUG_RULE_NAME = "debug_data_debugData.1.sg"
IMAGE = "die-rust/debug-dispatch-harness-qt5:74eaf505"
BINARY = "/opt/die-build/src/console/die-debug-dispatch-harness"
ROOT = pathlib.Path(__file__).resolve().parents[2]
HARNESS_SOURCE = (
    ROOT / "tools" / "upstream" / "debug_dispatch_harness_main.cpp"
)
DOCKERFILE = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.debug-dispatch-harness-qt5"
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
        raise ValueError("debug-dispatch fixture differs from committed")
    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported debug-dispatch fixture schema")
    if (
        manifest.get("generator")
        != "tools/corpus/generate_debug_dispatch_fixture.py"
    ):
        raise ValueError("debug-dispatch fixture generator mismatch")
    if manifest.get("capability") != "CAP-NEST-007":
        raise ValueError("debug-dispatch fixture capability mismatch")
    sample = manifest.get("sample")
    if not isinstance(sample, dict):
        raise ValueError("debug-dispatch sample metadata missing")
    if (
        sample.get("name") != SAMPLE_NAME
        or sample.get("size") != SAMPLE_SIZE
        or sample.get("sha256") != SAMPLE_SHA256
    ):
        raise ValueError("debug-dispatch sample identity mismatch")
    data = (fixture_dir / SAMPLE_NAME).read_bytes()
    if len(data) != SAMPLE_SIZE or sha256(data) != SAMPLE_SHA256:
        raise ValueError("debug-dispatch sample bytes mismatch")
    resource = sample.get("resource")
    debug = sample.get("debug_data")
    if not isinstance(resource, dict) or not isinstance(debug, dict):
        raise ValueError("debug-dispatch part metadata missing")
    resource_bytes = data[
        resource["offset"] : resource["offset"] + resource["size"]
    ]
    debug_bytes = data[
        debug["offset"] : debug["offset"] + debug["size"]
    ]
    if sha256(resource_bytes) != RESOURCE_SHA256:
        raise ValueError("debug-dispatch resource bytes mismatch")
    if (
        sha256(debug_bytes) != DEBUG_SHA256
        or not debug_bytes.startswith(b"RSDS")
    ):
        raise ValueError("debug-dispatch debug bytes mismatch")
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
        raise ValueError("debug-dispatch image revision mismatch")
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


def part_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    parts = document.get("enumerated_parts")
    if not isinstance(parts, list):
        raise ValueError("debug-dispatch parts must be an array")
    if document.get("enumerated_part_count") != len(parts):
        raise ValueError("debug-dispatch part count mismatch")
    result = {str(part["filepart_string"]): part for part in parts}
    if len(result) != len(parts):
        raise ValueError("duplicate debug-dispatch file part")
    return result


def validate(document: dict[str, Any]) -> dict[str, bool]:
    identities = {
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "rules_commit": RULES_COMMIT,
        "sample_name": SAMPLE_NAME,
        "sample_size": SAMPLE_SIZE,
        "sample_sha256": SAMPLE_SHA256,
        "resource_rule_sha256": RESOURCE_RULE_SHA256,
        "debug_rule_sha256": DEBUG_RULE_SHA256,
        "format_filetype": "PE32",
    }
    if document.get("schema_version") != 1:
        raise ValueError("unsupported debug-dispatch harness schema")
    for field, expected in identities.items():
        if document.get(field) != expected:
            raise ValueError(f"debug-dispatch {field} mismatch")

    parts = part_map(document)
    if set(parts) != {"Resource", "Debug data"}:
        raise ValueError("unexpected debug-dispatch part inventory")
    resource = parts["Resource"]
    debug = parts["Debug data"]
    format_layer_enumerates_resource = (
        resource["filepart"] == 64
        and resource["offset"] == 608
        and resource["size"] == 20
        and resource["resource_id"] == "24"
        and resource["sha256"] == RESOURCE_SHA256
    )
    format_layer_enumerates_debug_data = (
        debug["filepart"] == 128
        and debug["offset"] == 1088
        and debug["size"] == 38
        and debug["name"] == "2"
        and debug["sha256"] == DEBUG_SHA256
    )

    public = document.get("public_recursive_scan")
    direct = document.get("direct_debug_scan")
    if not isinstance(public, dict) or not isinstance(direct, dict):
        raise ValueError("debug-dispatch scan output missing")
    public_records = public.get("records")
    direct_records = direct.get("records")
    if not isinstance(public_records, list):
        raise ValueError("public recursive records must be an array")
    if not isinstance(direct_records, list):
        raise ValueError("direct debug records must be an array")
    if public.get("record_count") != len(public_records):
        raise ValueError("public recursive record count mismatch")
    if direct.get("record_count") != len(direct_records):
        raise ValueError("direct debug record count mismatch")

    parent_debug_metadata_is_header_record = any(
        record["type"] == "debug data"
        and record["name"] == "Records"
        and record["info"] == "CodeView"
        and record["id"]["filepart_string"] == "Header"
        and record["signature"] == "_debug_data.5.sg"
        for record in public_records
    )
    recursive_resource_is_positive_control = any(
        record["type"] == "format"
        and record["name"] == "Manifest"
        and record["info"] == "Resources"
        and record["id"]["filepart_string"] == "Resource"
        and record["parent_id"]["filepart_string"] == "Resource"
        and record["parent_id"]["offset"] == resource["offset"]
        and record["signature"] == "win_resources.1.sg"
        for record in public_records
    )
    public_scanner_omits_debug_data_child = (
        all(
            record["id"]["filepart_string"] != "Debug data"
            and record["parent_id"]["filepart_string"] != "Debug data"
            for record in public_records
        )
        and all(record["name"] != "PDB file link" for record in public_records)
    )
    direct_debug_uses_enumerated_part = (
        direct.get("source_part") == debug
        and direct.get("signature_filter") == DEBUG_RULE_NAME
    )
    direct_debug_rule_detects_rsds = (
        len(direct_records) == 1
        and direct_records[0]["type"] == "debug data"
        and direct_records[0]["name"] == "PDB file link"
        and direct_records[0]["version"] == "7.0"
        and direct_records[0]["signature"] == DEBUG_RULE_NAME
        and direct_records[0]["id"]["filepart_string"] == "Debug data"
        and direct_records[0]["parent_id"]["filepart_string"]
        == "Debug data"
        and direct_records[0]["parent_id"]["offset"] == debug["offset"]
        and direct_records[0]["parent_id"]["size"] == debug["size"]
    )
    public_mode_is_recursive_and_aggressive = (
        public.get("recursive") is True
        and public.get("aggressive") is True
        and public.get("initial_filetype") == "PE32"
    )
    all_operations_complete_without_errors = (
        document.get("database_loaded") is True
        and document.get("enumeration_not_canceled") is True
        and document.get("load_not_canceled") is True
        and public.get("error_count") == 0
        and public.get("scan_not_canceled") is True
        and direct.get("error_count") == 0
        and direct.get("scan_not_canceled") is True
    )
    relationships = {
        "format_layer_enumerates_resource": (
            format_layer_enumerates_resource
        ),
        "format_layer_enumerates_debug_data": (
            format_layer_enumerates_debug_data
        ),
        "parent_debug_metadata_is_header_record": (
            parent_debug_metadata_is_header_record
        ),
        "recursive_resource_is_positive_control": (
            recursive_resource_is_positive_control
        ),
        "public_scanner_omits_debug_data_child": (
            public_scanner_omits_debug_data_child
        ),
        "direct_debug_uses_enumerated_part": (
            direct_debug_uses_enumerated_part
        ),
        "direct_debug_rule_detects_rsds": (
            direct_debug_rule_detects_rsds
        ),
        "public_mode_is_recursive_and_aggressive": (
            public_mode_is_recursive_and_aggressive
        ),
        "all_operations_complete_without_errors": (
            all_operations_complete_without_errors
        ),
    }
    failed = [name for name, passed in relationships.items() if not passed]
    if failed:
        raise ValueError(
            f"debug-dispatch relationships failed: {failed}"
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
            "--memory=512m",
            "--cpus=1",
            "--pids-limit=128",
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
    (raw_dir / "debug-dispatch.stdout").write_bytes(process.stdout)
    (raw_dir / "debug-dispatch.stderr").write_bytes(process.stderr)
    if process.returncode != 0 or process.stderr:
        raise ValueError("debug-dispatch harness process failed")
    document = json.loads(process.stdout)
    relationships = validate(document)
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_debug_dispatch_harness.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "rules_commit": RULES_COMMIT,
        "platform": "linux-amd64-qt5",
        "capability": "CAP-NEST-007",
        "fixture": {
            "manifest": (
                "docs/research/data/debug-dispatch-fixture.json"
            ),
            "manifest_sha256": fixture_manifest_sha256,
            "license": fixture_manifest["license"],
            "sample": fixture_manifest["sample"]["name"],
        },
        "harness": {
            "source": (
                "tools/upstream/debug_dispatch_harness_main.cpp"
            ),
            "source_sha256": sha256(HARNESS_SOURCE.read_bytes()),
            "dockerfile": (
                "tools/upstream/"
                "Dockerfile.debug-dispatch-harness-qt5"
            ),
            "dockerfile_sha256": sha256(DOCKERFILE.read_bytes()),
            "access_method": (
                "public scanner plus direct private rule executor; "
                "pinned engine and rule bytes are unmodified"
            ),
        },
        "oracle": {
            "image": IMAGE,
            "image_id": image_id,
            "revision": revision,
            "binary": BINARY,
            "binary_sha256": binary_digest.decode("ascii"),
            "exit_code": process.returncode,
            "limits": {
                "network": "none",
                "memory": "512m",
                "cpus": 1,
                "pids": 128,
            },
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

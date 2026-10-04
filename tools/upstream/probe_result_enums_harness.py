#!/usr/bin/env python3
"""Probe SCANSTRUCT type/name enums beside raw string representations."""

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
IMAGE = "die-rust/result-enums-harness-qt5:74eaf505"
BINARY = "/opt/die-build/src/console/die-result-enums-harness"
INPUT_SHA256 = (
    "1effe084564a199b007fbfdeb2cbe1095bd5b5e87303147a515fefcd3e1cb7b5"
)
CASE_METADATA = {
    "known_alias": {
        "database": "main",
        "signature": "known_alias.1.sg",
        "heuristic_scan": False,
    },
    "heuristic_prefix": {
        "database": "main",
        "signature": "HEUR.heuristic.2.sg",
        "heuristic_scan": True,
    },
    "custom_raw": {
        "database": "main",
        "signature": "custom.3.sg",
        "heuristic_scan": False,
    },
    "unknown_fallback": {
        "database": "empty-main",
        "signature": "",
        "heuristic_scan": False,
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
        raise ValueError("result-enum fixture manifest differs from committed")
    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported result-enum fixture schema")
    if (
        manifest.get("generator")
        != "tools/corpus/generate_result_enum_fixture.py"
    ):
        raise ValueError("result-enum fixture generator mismatch")
    if manifest.get("capability") != "CAP-RESULT-005":
        raise ValueError("result-enum fixture capability mismatch")
    if manifest.get("cases") != CASE_METADATA:
        raise ValueError("result-enum fixture case inventory mismatch")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("result-enum fixture entries must be non-empty")
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
        raise ValueError("result-enum fixture input identity mismatch")
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
        raise ValueError("result-enum image revision mismatch")
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
        raise ValueError("result-enum cases must be an array")
    if document.get("case_count") != len(cases):
        raise ValueError("result-enum case count mismatch")
    result = {str(case["id"]): case for case in cases}
    if len(result) != len(cases):
        raise ValueError("duplicate result-enum case id")
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
        raise ValueError("unsupported result-enum harness schema")
    for field, expected in identities.items():
        if document.get(field) != expected:
            raise ValueError(f"result-enum {field} mismatch")
    cases = case_map(document)
    if set(cases) != set(CASE_METADATA):
        raise ValueError("unexpected result-enum case inventory")
    if any(len(case.get("records", [])) != 1 for case in cases.values()):
        raise ValueError("result-enum cases must have one record each")
    records = {
        case_id: case["records"][0] for case_id, case in cases.items()
    }

    raw_and_numeric_are_emitted_together = all(
        {
            "raw_type",
            "raw_name",
            "type_value",
            "type_canonical",
            "name_value",
            "name_canonical",
        }
        <= set(record)
        for record in records.values()
    )
    known_alias_maps_to_canonical_enums = (
        records["known_alias"]["raw_type"] == "PE-Tool"
        and records["known_alias"]["type_value"] > 0
        and records["known_alias"]["type_canonical"] == "PE Tool"
        and records["known_alias"]["raw_name"] == "7 ZIP"
        and records["known_alias"]["name_value"] > 0
        and records["known_alias"]["name_canonical"] == "7-Zip"
    )
    heuristic_prefix_keeps_raw_but_maps_format = (
        records["heuristic_prefix"]["raw_type"] == "~format"
        and records["heuristic_prefix"]["type_value"] > 0
        and records["heuristic_prefix"]["type_canonical"] == "Format"
        and records["heuristic_prefix"]["name_value"]
        == records["known_alias"]["name_value"]
    )
    custom_raw_is_retained_beside_unknown_enums = (
        records["custom_raw"]["raw_type"] == "Vendor-Custom"
        and records["custom_raw"]["raw_name"] == "Project/Custom"
        and records["custom_raw"]["type_value"] == 0
        and records["custom_raw"]["type_canonical"] == "Unknown"
        and records["custom_raw"]["name_value"] == 0
        and records["custom_raw"]["name_canonical"] == "Unknown"
        and records["custom_raw"]["unknown"] is False
    )
    fallback_has_unknown_text_enum_and_flag = (
        records["unknown_fallback"]["raw_type"] == "Unknown"
        and records["unknown_fallback"]["raw_name"] == "Unknown"
        and records["unknown_fallback"]["type_value"] == 0
        and records["unknown_fallback"]["name_value"] == 0
        and records["unknown_fallback"]["unknown"] is True
    )

    type_mappings = document.get("type_mappings")
    name_mappings = document.get("name_mappings")
    canonicalization_aliases_are_equal = (
        isinstance(type_mappings, list)
        and len(type_mappings) == 5
        and len({item["value"] for item in type_mappings}) == 1
        and type_mappings[0]["value"] > 0
        and {item["canonical"] for item in type_mappings} == {"PE Tool"}
        and isinstance(name_mappings, list)
        and len(name_mappings) == 3
        and len({item["value"] for item in name_mappings}) == 1
        and name_mappings[0]["value"] > 0
        and {item["canonical"] for item in name_mappings} == {"7-Zip"}
    )

    aliases = document.get("reserved_name_aliases")
    fallbacks = document.get("fallbacks")
    reserved_unknown_aliases_are_distinct = (
        isinstance(aliases, list)
        and len(aliases) == 10
        and len({item["value"] for item in aliases}) == 10
        and all(
            next_item["value"] == item["value"] + 1
            for item, next_item in zip(aliases, aliases[1:])
        )
        and {item["canonical"] for item in aliases} == {"_Unknown"}
        and fallbacks["reserved_alias_first_value"]
        == aliases[0]["value"]
        and fallbacks["reserved_alias_last_value"]
        == aliases[-1]["value"]
        and fallbacks["reserved_alias_input"]["value"]
        == aliases[0]["value"]
        and fallbacks["reserved_alias_input"]["canonical"] == "_Unknown"
    )
    unknown_and_out_of_range_are_explicit = (
        fallbacks["unknown_type_input"]["value"] == 0
        and fallbacks["unknown_type_input"]["canonical"] == "Unknown"
        and fallbacks["unknown_name_input"]["value"] == 0
        and fallbacks["unknown_name_input"]["canonical"] == "Unknown"
        and fallbacks["out_of_range_type_value"] > 0
        and fallbacks["out_of_range_type_string"] == "Unknown"
        and fallbacks["out_of_range_name_value"]
        > fallbacks["reserved_alias_last_value"]
        and fallbacks["out_of_range_name_string"] == "Unknown"
    )
    scans_loaded_without_errors = all(
        case["database_loaded"]
        and case["load_not_canceled"]
        and case["scan_not_canceled"]
        and case["error_count"] == 0
        for case in cases.values()
    )
    relationships = {
        "raw_and_numeric_are_emitted_together": (
            raw_and_numeric_are_emitted_together
        ),
        "known_alias_maps_to_canonical_enums": (
            known_alias_maps_to_canonical_enums
        ),
        "heuristic_prefix_keeps_raw_but_maps_format": (
            heuristic_prefix_keeps_raw_but_maps_format
        ),
        "custom_raw_is_retained_beside_unknown_enums": (
            custom_raw_is_retained_beside_unknown_enums
        ),
        "fallback_has_unknown_text_enum_and_flag": (
            fallback_has_unknown_text_enum_and_flag
        ),
        "canonicalization_aliases_are_equal": (
            canonicalization_aliases_are_equal
        ),
        "reserved_unknown_aliases_are_distinct": (
            reserved_unknown_aliases_are_distinct
        ),
        "unknown_and_out_of_range_are_explicit": (
            unknown_and_out_of_range_are_explicit
        ),
        "scans_loaded_without_errors": scans_loaded_without_errors,
    }
    failed = [name for name, passed in relationships.items() if not passed]
    if failed:
        raise ValueError(f"result-enum relationships failed: {failed}")
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
    (raw_dir / "result-enums.stdout").write_bytes(process.stdout)
    (raw_dir / "result-enums.stderr").write_bytes(process.stderr)
    if process.returncode != 0 or process.stderr:
        raise ValueError("result-enum harness process failed")
    document = json.loads(process.stdout)
    relationships = validate(document)
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_result_enums_harness.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "platform": "linux-amd64-qt5",
        "capability": "CAP-RESULT-005",
        "fixture": {
            "manifest": (
                "docs/research/data/result-enum-fixture.json"
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
            / "result-enum-fixture.json"
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

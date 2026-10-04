#!/usr/bin/env python3
"""Probe pinned DIE against audited external compressed RAR fixtures."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import sys
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
FIXTURE_SOURCE_COMMIT = (
    "16b785c2b1b504e99fc307676e5369a26d3ce060"
)
FIXTURE_SOURCE_REMOTE = (
    "https://github.com/ssokolow/rar-test-files.git"
)
IMAGE = "die-rust/upstream-sevenzip-password-harness:74eaf505"
EXPECTED_IMAGE_ID = (
    "sha256:adf8e09f3ed7c15a54f3486c482599e1bcb122"
    "308a0b27396de1baf2ee634daf"
)
HARNESS_BINARY = "/opt/die-build/src/console/die-archive-harness"
HARNESS_SOURCE = "tools/upstream/archive_harness_main.cpp"
HARNESS_DOCKERFILE = "tools/upstream/Dockerfile.archive-harness-qt5"
FIXTURE_REPORT = (
    "docs/research/data/rar-compressed-fixture-source.json"
)
FIXTURE_AUDITOR = (
    "tools/corpus/audit_rar_compressed_fixture_source.py"
)
REPEATS = 2
SOURCE_HASHES = {
    "/opt/die-source/XScanEngine/xscanengine.cpp": (
        "e088bebb7c8345ce5832cc51de712c05a8b239873d7f092"
        "db3ae5566a761b498"
    ),
    "/opt/die-source/XArchive/xrar.cpp": (
        "23721187a6118edce8b9511680f34c404727f831ec8c7ed6"
        "6e0ed0868260ccb8"
    ),
    "/opt/die-source/XArchive/xdecompress.cpp": (
        "4f52eefa06674ea5b7e3f7e1b989502147be84d83e32e808"
        "6a7087839ed2728d"
    ),
    "/opt/die-source/XArchive/Algos/xrardecoder.cpp": (
        "55f36d7b0188f5093ffad5723637fedafae32321b1fde3cf"
        "2f81ff5983e94026"
    ),
    "/opt/die-source/XArchive/Algos/xrardecoder.h": (
        "29e0f4e1091df88f992f2cf5688df044bfbb46e607cb6536"
        "cbd5b4e234665540"
    ),
}
EXPECTED_CASES = {
    "rar3_method35_single": {
        "fixture": "build/testfile.rar3.rar",
        "default_children": [],
        "aggressive_children": [("Binary", 12)],
    },
    "rar3_method35_solid_pair": {
        "fixture": "build/testfile.rar3.solid.cbr",
        "default_children": [],
        "aggressive_children": [("PNG", 87), ("JPEG", 220)],
    },
    "rar5_method5_mixed_pair": {
        "fixture": "build/testfile.rar5.cbr",
        "default_children": [],
        "aggressive_children": [("JPEG", 220), ("PNG", 87)],
    },
    "rar5_method5_solid_pair": {
        "fixture": "build/testfile.rar5.solid.cbr",
        "default_children": [],
        "aggressive_children": [("JPEG", 220), ("PNG", 87)],
    },
}


class RarProbeError(ValueError):
    """The probe cannot produce trustworthy oracle evidence."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_git(path: pathlib.Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(path), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    if process.stderr:
        raise RarProbeError(f"git wrote stderr: {' '.join(arguments)}")
    return process.stdout.strip()


def verify_fixture_root(
    fixture_root: pathlib.Path,
    fixture_report: dict[str, Any],
) -> dict[str, Any]:
    if run_git(fixture_root, "rev-parse", "HEAD") != FIXTURE_SOURCE_COMMIT:
        raise RarProbeError("fixture source commit mismatch")
    if run_git(fixture_root, "status", "--porcelain"):
        raise RarProbeError("fixture source checkout is dirty")
    remote = run_git(fixture_root, "remote", "get-url", "origin")
    if remote.rstrip("/") != FIXTURE_SOURCE_REMOTE.rstrip("/"):
        raise RarProbeError("fixture source remote mismatch")
    samples = {
        sample["path"]: sample
        for sample in fixture_report["selection"]["samples"]
    }
    expected_paths = {
        case["fixture"] for case in EXPECTED_CASES.values()
    }
    if set(samples) != expected_paths:
        raise RarProbeError("fixture report selection changed")
    for relative, sample in samples.items():
        data = (fixture_root / relative).read_bytes()
        if len(data) != sample["bytes"] or sha256(data) != sample["sha256"]:
            raise RarProbeError(f"fixture identity mismatch: {relative}")
    return samples


def inspect_image() -> dict[str, str]:
    process = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        check=True,
        capture_output=True,
    )
    document = json.loads(process.stdout)[0]
    image_id = document["Id"]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision", ""
    )
    if image_id != EXPECTED_IMAGE_ID:
        raise RarProbeError("RAR probe image ID mismatch")
    if revision != UPSTREAM_COMMIT:
        raise RarProbeError("RAR probe image revision mismatch")
    return {
        "image": IMAGE,
        "image_id": image_id,
        "revision": revision,
        "network": "none",
        "fixture_mount": "readonly",
    }


def verify_image_sources() -> list[dict[str, str]]:
    paths = list(SOURCE_HASHES)
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            "/usr/bin/sha256sum",
            IMAGE,
            *paths,
            HARNESS_BINARY,
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise RarProbeError("source hash command wrote stderr")
    records = []
    observed = {}
    for line in process.stdout.decode("ascii").splitlines():
        digest, path = line.split("  ", 1)
        observed[path] = digest
    if {
        path: observed.get(path) for path in SOURCE_HASHES
    } != SOURCE_HASHES:
        raise RarProbeError("fixed RAR source hashes changed")
    for path in paths:
        records.append({"path": path, "sha256": observed[path]})
    return records + [
        {
            "path": HARNESS_BINARY,
            "sha256": observed[HARNESS_BINARY],
        }
    ]


def project_file_record(
    repo: pathlib.Path, relative: str
) -> dict[str, Any]:
    data = (repo / relative).read_bytes()
    return {
        "path": relative,
        "bytes": len(data),
        "sha256": sha256(data),
    }


def result_projection(document: dict[str, Any]) -> dict[str, Any]:
    if set(document) != {"detects"}:
        raise RarProbeError("unexpected result root")
    detects = document["detects"]
    if not isinstance(detects, list) or len(detects) != 1:
        raise RarProbeError("expected one RAR root")
    root = detects[0]
    if root.get("filetype") != "RAR":
        raise RarProbeError("result root is not RAR")
    values = root.get("values")
    if not isinstance(values, list) or not values:
        raise RarProbeError("RAR root values are missing")
    first = values[0]
    if first.get("string") != "Unknown: Unknown":
        raise RarProbeError("RAR root marker changed")
    children = []
    for value in values[1:]:
        if value.get("parentfilepart") != "Stream":
            raise RarProbeError("RAR child is not a stream")
        children.append(
            {
                "filetype": value["filetype"],
                "size": int(value["size"]),
            }
        )
    return {
        "root_filetype": root["filetype"],
        "root_size": int(root["size"]),
        "children": children,
    }


def run_case(
    fixture_root: pathlib.Path,
    fixture: str,
    *,
    aggressive: bool,
) -> dict[str, Any]:
    arguments = [
        HARNESS_BINARY,
        "--archive",
    ]
    if aggressive:
        arguments.append("--aggressive")
    arguments.append(f"/fixtures/{fixture}")
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--mount",
            (
                f"type=bind,source={fixture_root},"
                "target=/fixtures,readonly"
            ),
            IMAGE,
            *arguments,
        ],
        capture_output=True,
    )
    if process.returncode != 0:
        raise RarProbeError(
            f"RAR harness failed for {fixture}: {process.returncode}"
        )
    if process.stderr:
        raise RarProbeError(f"RAR harness wrote stderr for {fixture}")
    try:
        document = json.loads(process.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RarProbeError("RAR harness output is not JSON") from error
    return {
        "command": arguments,
        "exit_code": process.returncode,
        "stdout_base64": base64.b64encode(process.stdout).decode("ascii"),
        "stdout_sha256": sha256(process.stdout),
        "stderr_base64": "",
        "stderr_sha256": sha256(process.stderr),
        "projection": result_projection(document),
    }


def build_report(
    repo: pathlib.Path,
    fixture_root: pathlib.Path,
) -> dict[str, Any]:
    fixture_report_path = repo / FIXTURE_REPORT
    fixture_report_bytes = fixture_report_path.read_bytes()
    fixture_report = json.loads(fixture_report_bytes)
    if fixture_report["source"]["commit"] != FIXTURE_SOURCE_COMMIT:
        raise RarProbeError("fixture report commit mismatch")
    samples = verify_fixture_root(fixture_root, fixture_report)
    image = inspect_image()
    image_sources = verify_image_sources()
    cases = []
    for case_id, expected in EXPECTED_CASES.items():
        for mode, aggressive in (
            ("default", False),
            ("aggressive", True),
        ):
            runs = [
                run_case(
                    fixture_root,
                    expected["fixture"],
                    aggressive=aggressive,
                )
                for _ in range(REPEATS)
            ]
            if len({run["stdout_sha256"] for run in runs}) != 1:
                raise RarProbeError(
                    f"nondeterministic RAR output: {case_id}/{mode}"
                )
            expected_children = [
                {"filetype": filetype, "size": size}
                for filetype, size in expected[f"{mode}_children"]
            ]
            if runs[0]["projection"]["children"] != expected_children:
                raise RarProbeError(
                    f"unexpected RAR children: {case_id}/{mode}"
                )
            fixture_sample = samples[expected["fixture"]]
            if (
                runs[0]["projection"]["root_size"]
                != fixture_sample["bytes"]
            ):
                raise RarProbeError("RAR root size mismatch")
            cases.append(
                {
                    "id": case_id,
                    "mode": mode,
                    "fixture": expected["fixture"],
                    "fixture_sha256": fixture_sample["sha256"],
                    "runs": runs,
                    "deterministic": True,
                }
            )

    relationships = {
        "eight_mode_cases_are_present": len(cases) == 8,
        "all_cases_are_two_run_deterministic": all(
            case["deterministic"] and len(case["runs"]) == REPEATS
            for case in cases
        ),
        "default_mode_has_no_children": all(
            not case["runs"][0]["projection"]["children"]
            for case in cases
            if case["mode"] == "default"
        ),
        "aggressive_mode_expands_all_expected_members": (
            sum(
                len(case["runs"][0]["projection"]["children"])
                for case in cases
                if case["mode"] == "aggressive"
            )
            == 7
        ),
        "rar3_and_rar5_solid_following_members_expand": all(
            len(case["runs"][0]["projection"]["children"]) == 2
            for case in cases
            if case["mode"] == "aggressive"
            and "solid_pair" in case["id"]
        ),
        "fixture_binaries_remain_external": (
            fixture_report["selection"]["external_storage"]
            and not fixture_report["selection"][
                "binary_files_committed_to_project"
            ]
        ),
        "fixture_redistribution_review_remains_open": (
            not fixture_report["redistribution_review"][
                "project_legal_review_complete"
            ]
            and not fixture_report["redistribution_review"][
                "project_redistribution_approved"
            ]
        ),
    }
    if not all(relationships.values()):
        raise RarProbeError("RAR probe relationships failed")
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_rar_compressed_harness.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "fixture_source_commit": FIXTURE_SOURCE_COMMIT,
        "fixture_report": {
            "path": FIXTURE_REPORT,
            "sha256": sha256(fixture_report_bytes),
        },
        "fixture_auditor": project_file_record(
            repo, FIXTURE_AUDITOR
        ),
        "harness": {
            "source": project_file_record(repo, HARNESS_SOURCE),
            "dockerfile": project_file_record(
                repo, HARNESS_DOCKERFILE
            ),
            "binary": next(
                record
                for record in image_sources
                if record["path"] == HARNESS_BINARY
            ),
        },
        "source_image": image,
        "source_files": [
            record
            for record in image_sources
            if record["path"] != HARNESS_BINARY
        ],
        "repeat_count": REPEATS,
        "cases": cases,
        "relationships": relationships,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fixture-root", type=pathlib.Path, required=True
    )
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    repo = pathlib.Path(__file__).resolve().parents[2]
    report = build_report(repo, args.fixture_root.resolve())
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(serialized)
    else:
        args.output.write_text(
            serialized, encoding="utf-8", newline="\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

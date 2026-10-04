#!/usr/bin/env python3
"""Audit pinned DIE-engine component license files from a fixed source image."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tomllib
from typing import Any


IMAGE = "die-rust/upstream-oracle-cmake:74eaf505"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
LICENSE_PREFIXES = ("license", "copying", "notice", "copyright")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_license_candidate(path: pathlib.Path) -> bool:
    name = path.name.casefold()
    return any(name.startswith(prefix) for prefix in LICENSE_PREFIXES)


def first_nonempty_line(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        value = line.strip()
        if value:
            return value[:200]
    return ""


def license_record(path: pathlib.Path, component_root: pathlib.Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(component_root).as_posix(),
        "bytes": len(data),
        "sha256": sha256(data),
        "first_nonempty_line": first_nonempty_line(data),
    }


def git_head(path: pathlib.Path) -> str:
    process = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    if process.stderr:
        raise ValueError(f"git rev-parse wrote stderr: {path}")
    return process.stdout.strip()


def inventory_component(
    source_root: pathlib.Path, name: str, expected_commit: str
) -> dict[str, Any]:
    root = source_root / name
    if not root.is_dir():
        raise ValueError(f"component directory is missing: {name}")
    actual_commit = git_head(root)
    if actual_commit != expected_commit:
        raise ValueError(
            f"component commit mismatch: {name}: "
            f"{actual_commit} != {expected_commit}"
        )

    candidates = sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file()
            and ".git" not in path.relative_to(root).parts
            and is_license_candidate(path)
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    root_candidates = [path for path in candidates if path.parent == root]
    nested_gitmodules = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob(".gitmodules")
        if path.is_file() and ".git" not in path.relative_to(root).parts
    )
    records = [license_record(path, root) for path in candidates]
    root_records = [
        record for record in records if "/" not in record["path"]
    ]
    return {
        "name": name,
        "expected_commit": expected_commit,
        "actual_commit": actual_commit,
        "root_license_count": len(root_candidates),
        "root_license_is_mit": any(
            record["first_nonempty_line"] == "MIT License"
            for record in root_records
        ),
        "nested_gitmodules": nested_gitmodules,
        "license_file_count": len(records),
        "license_files": records,
    }


def build_inside_report(
    source_root: pathlib.Path, lock_path: pathlib.Path
) -> dict[str, Any]:
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    gitlinks = lock["gitlink"]
    baseline = lock["baseline"]
    if len(gitlinks) != 58:
        raise ValueError("expected exactly 58 direct gitlinks")
    if baseline["commit"] != UPSTREAM_COMMIT:
        raise ValueError("component lock baseline mismatch")
    if git_head(source_root) != UPSTREAM_COMMIT:
        raise ValueError("source image root commit mismatch")

    components = [
        inventory_component(
            source_root, name, str(metadata["commit"])
        )
        for name, metadata in sorted(gitlinks.items())
    ]
    root_license_path = source_root / "LICENSE"
    root_license = license_record(root_license_path, source_root)
    relationships = {
        "all_58_component_directories_present": len(components) == 58,
        "all_component_commits_match_lock": all(
            item["actual_commit"] == item["expected_commit"]
            for item in components
        ),
        "no_component_has_nested_gitmodules": all(
            not item["nested_gitmodules"] for item in components
        ),
        "all_components_have_exactly_one_root_license": all(
            item["root_license_count"] == 1 for item in components
        ),
        "all_component_root_licenses_identify_mit": all(
            item["root_license_is_mit"] for item in components
        ),
    }
    return {
        "schema_version": 1,
        "generator": "tools/upstream/audit_component_licenses.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "component_lock": {
            "path": "upstream/components.lock.toml",
            "sha256": sha256(lock_bytes),
        },
        "source_root_license": root_license,
        "component_count": len(components),
        "license_file_count": sum(
            item["license_file_count"] for item in components
        ),
        "relationships": relationships,
        "components": components,
    }


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
        raise ValueError("license audit image revision mismatch")
    return document["Id"], revision


def run_in_fixed_image(repo: pathlib.Path) -> dict[str, Any]:
    image_id, revision = inspect_image()
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--mount",
            f"type=bind,source={repo},target=/repo,readonly",
            "--entrypoint",
            "/usr/bin/python3",
            IMAGE,
            "/repo/tools/upstream/audit_component_licenses.py",
            "--inside",
            "--source-root",
            "/opt/die-source",
            "--lock",
            "/repo/upstream/components.lock.toml",
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError("inside license audit wrote stderr")
    report = json.loads(process.stdout)
    report["source_image"] = {
        "image": IMAGE,
        "image_id": image_id,
        "revision": revision,
        "network": "none",
        "repository_mount": "readonly",
    }
    if not all(report["relationships"].values()):
        raise ValueError("component license relationships are incomplete")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--source-root", type=pathlib.Path)
    parser.add_argument("--lock", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.inside:
        if args.source_root is None or args.lock is None:
            parser.error("--inside requires --source-root and --lock")
        report = build_inside_report(args.source_root, args.lock)
    else:
        if args.output is None:
            parser.error("host mode requires --output")
        repo = pathlib.Path(__file__).resolve().parents[2]
        report = run_in_fixed_image(repo)

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

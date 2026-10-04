#!/usr/bin/env python3
"""Inventory XArchive files compiled or included by the fixed Linux diec build."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shlex
import subprocess
import sys
import tomllib
from typing import Any


IMAGE = "die-rust/upstream-oracle-cmake:74eaf505"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
DIRECT_OBJECT_PREFIX = "CMakeFiles/diec.dir/__/__/XArchive/"
EXPECTED_ARCHIVES = {
    "../XArchive/3rdparty/bzip2/libbzip2.a": 8,
    "../XArchive/3rdparty/lzma/liblzma.a": 2,
    "../XArchive/3rdparty/ppmd/libppmd.a": 4,
    "../XArchive/3rdparty/zlib/libzlib.a": 8,
}
LICENSE_MARKERS = {
    "mit-permission": b"permission is hereby granted, free of charge",
    "public-domain": b"public domain",
    "bzip2-copyright": b"julian seward",
    "zlib-notice": b"jean-loup gailly",
    "apache-2.0": b"apache license, version 2.0",
    "bsd-redistribution": b"redistribution and use in source and binary forms",
}
ORIGIN_MARKERS = {
    "brotli": b"brotli",
    "lzma-7zip": b"igor pavlov",
    "ppmd": b"ppmd",
    "zstandard": b"zstd",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def find_markers(data: bytes, markers: dict[str, bytes]) -> list[str]:
    folded = data.lower()
    return sorted(
        name
        for name, marker in markers.items()
        if marker.lower() in folded
    )


def file_record(path: pathlib.Path, root: pathlib.Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "bytes": len(data),
        "sha256": sha256(data),
        "license_markers": find_markers(data, LICENSE_MARKERS),
        "origin_markers": find_markers(data, ORIGIN_MARKERS),
    }


def parse_dependency_file(path: pathlib.Path) -> list[pathlib.Path]:
    text = path.read_text(encoding="utf-8", errors="replace")
    flattened = text.replace("\\\n", " ")
    if ":" not in flattened:
        raise ValueError(f"invalid dependency file: {path}")
    dependencies = flattened.split(":", 1)[1]
    return [pathlib.Path(value) for value in shlex.split(dependencies)]


def direct_compile_units(
    link_tokens: list[str],
    link_directory: pathlib.Path,
    component_root: pathlib.Path,
) -> list[tuple[pathlib.Path, pathlib.Path, str]]:
    units = []
    for token in link_tokens:
        if not token.startswith(DIRECT_OBJECT_PREFIX) or not token.endswith(".o"):
            continue
        relative_source = token[len(DIRECT_OBJECT_PREFIX) : -2]
        source = component_root / relative_source
        dependency_file = link_directory / f"{token}.d"
        units.append((source, dependency_file, "die-direct"))
    return units


def archive_compile_units(
    link_tokens: list[str],
    link_directory: pathlib.Path,
    component_root: pathlib.Path,
) -> tuple[list[tuple[pathlib.Path, pathlib.Path, str]], dict[str, int]]:
    units: list[tuple[pathlib.Path, pathlib.Path, str]] = []
    counts: dict[str, int] = {}
    for archive, expected_count in sorted(EXPECTED_ARCHIVES.items()):
        if archive not in link_tokens:
            raise ValueError(f"required XArchive library is not linked: {archive}")
        archive_path = (link_directory / archive).resolve()
        target = archive_path.stem.removeprefix("lib")
        dependency_root = archive_path.parent / "CMakeFiles" / f"{target}.dir"
        dependency_files = sorted(dependency_root.rglob("*.o.d"))
        counts[archive] = len(dependency_files)
        if len(dependency_files) != expected_count:
            raise ValueError(
                f"unexpected object count for {archive}: "
                f"{len(dependency_files)} != {expected_count}"
            )
        source_root = (
            component_root
            / "3rdparty"
            / archive_path.parent.name
        )
        for dependency_file in dependency_files:
            relative = dependency_file.relative_to(dependency_root).as_posix()
            source = source_root / relative.removesuffix(".o.d")
            units.append((source, dependency_file, archive))
    return units, counts


def build_inside_report(
    source_root: pathlib.Path,
    build_root: pathlib.Path,
    lock_path: pathlib.Path,
) -> dict[str, Any]:
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    xarchive_commit = str(lock["gitlink"]["XArchive"]["commit"])
    component_root = source_root / "XArchive"
    if lock["baseline"]["commit"] != UPSTREAM_COMMIT:
        raise ValueError("component lock baseline mismatch")
    if git_head(source_root) != UPSTREAM_COMMIT:
        raise ValueError("source image root commit mismatch")
    if git_head(component_root) != xarchive_commit:
        raise ValueError("XArchive commit mismatch")

    link_path = build_root / "src/console/CMakeFiles/diec.dir/link.txt"
    link_bytes = link_path.read_bytes()
    link_tokens = shlex.split(link_bytes.decode("utf-8"))
    link_directory = build_root / "src/console"
    direct_units = direct_compile_units(
        link_tokens, link_directory, component_root
    )
    archive_units, archive_counts = archive_compile_units(
        link_tokens, link_directory, component_root
    )
    if len(direct_units) != 84:
        raise ValueError(
            f"unexpected direct XArchive object count: {len(direct_units)}"
        )

    all_units = direct_units + archive_units
    missing_sources = [
        str(source) for source, _, _ in all_units if not source.is_file()
    ]
    missing_dependencies = [
        str(path) for _, path, _ in all_units if not path.is_file()
    ]
    if missing_sources or missing_dependencies:
        raise ValueError("XArchive build closure contains missing files")

    dependency_paths: set[pathlib.Path] = set()
    for _, dependency_file, _ in all_units:
        for dependency in parse_dependency_file(dependency_file):
            try:
                dependency.relative_to(component_root)
            except ValueError:
                continue
            if dependency.is_file():
                dependency_paths.add(dependency)

    source_paths = {source for source, _, _ in all_units}
    closure_paths = source_paths | dependency_paths
    records = [
        file_record(path, component_root)
        for path in sorted(
            closure_paths,
            key=lambda value: value.relative_to(component_root).as_posix(),
        )
    ]
    no_license_marker_origins = sorted(
        record["path"]
        for record in records
        if record["origin_markers"] and not record["license_markers"]
    )
    linked_xarchive_archives = sorted(
        token
        for token in link_tokens
        if token.startswith("../XArchive/") and token.endswith(".a")
    )
    relationships = {
        "direct_xarchive_object_count_is_84": len(direct_units) == 84,
        "linked_archive_object_count_is_22": len(archive_units) == 22,
        "four_expected_xarchive_archives_are_linked": (
            linked_xarchive_archives == sorted(EXPECTED_ARCHIVES)
        ),
        "xyara_is_not_linked_into_diec": not any(
            "XYara" in token for token in link_tokens
        ),
        "all_compile_units_and_dependency_files_exist": (
            not missing_sources and not missing_dependencies
        ),
    }
    if not all(relationships.values()):
        raise ValueError("XArchive build relationships are incomplete")

    compile_units = [
        {
            "source": source.relative_to(component_root).as_posix(),
            "linkage": linkage,
            "dependency_file": dependency_file.relative_to(
                build_root
            ).as_posix(),
        }
        for source, dependency_file, linkage in sorted(
            all_units,
            key=lambda unit: unit[0].relative_to(
                component_root
            ).as_posix(),
        )
    ]
    evidence_paths = [
        component_root / "LICENSE",
        component_root / "3rdparty/bzip2/src/LICENSE",
        component_root / "3rdparty/lzma/src/LzmaDec.c",
        component_root / "3rdparty/ppmd/src/Ppmd7.c",
        component_root / "3rdparty/zlib/src/zlib.h",
    ]

    return {
        "schema_version": 1,
        "generator": "tools/upstream/audit_xarchive_license_closure.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "xarchive_commit": xarchive_commit,
        "component_lock": {
            "path": "upstream/components.lock.toml",
            "sha256": sha256(lock_bytes),
        },
        "build": {
            "link_path": "src/console/CMakeFiles/diec.dir/link.txt",
            "link_sha256": sha256(link_bytes),
            "direct_object_count": len(direct_units),
            "archive_object_count": len(archive_units),
            "archive_object_counts": archive_counts,
            "linked_xarchive_archives": linked_xarchive_archives,
        },
        "closure_file_count": len(records),
        "compile_source_count": len(source_paths),
        "relationships": relationships,
        "origin_files_without_license_markers": no_license_marker_origins,
        "license_evidence_files": [
            file_record(path, component_root) for path in evidence_paths
        ],
        "compile_units": compile_units,
        "files": records,
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
        raise ValueError("XArchive audit image revision mismatch")
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
            "/repo/tools/upstream/audit_xarchive_license_closure.py",
            "--inside",
            "--source-root",
            "/opt/die-source",
            "--build-root",
            "/opt/die-build",
            "--lock",
            "/repo/upstream/components.lock.toml",
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError("inside XArchive audit wrote stderr")
    report = json.loads(process.stdout)
    report["source_image"] = {
        "image": IMAGE,
        "image_id": image_id,
        "revision": revision,
        "network": "none",
        "repository_mount": "readonly",
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--source-root", type=pathlib.Path)
    parser.add_argument("--build-root", type=pathlib.Path)
    parser.add_argument("--lock", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.inside:
        if (
            args.source_root is None
            or args.build_root is None
            or args.lock is None
        ):
            parser.error(
                "--inside requires --source-root, --build-root and --lock"
            )
        report = build_inside_report(
            args.source_root, args.build_root, args.lock
        )
    else:
        if args.output is None:
            parser.error("host mode requires --output")
        repo = pathlib.Path(__file__).resolve().parents[2]
        report = run_in_fixed_image(repo)

    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(serialized)
    else:
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Inventory Formats/xsimd files that contribute to the fixed Linux diec ELF."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shlex
import subprocess
import sys
import tempfile
import tomllib
from typing import Any


IMAGE = "die-rust/upstream-oracle-cmake:74eaf505"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
ARCHIVES = {
    "../XSIMD/libxsimd.a": {
        "member": "xsimd.c.o",
        "source": "xsimd/src/xsimd.c",
        "dependency_file": (
            "src/XSIMD/CMakeFiles/xsimd.dir/src/xsimd.c.o.d"
        ),
    },
    "../XSIMD/libxsimd_avx2.a": {
        "member": "xsimd_avx2.c.o",
        "source": "xsimd/src/xsimd_avx2.c",
        "dependency_file": (
            "src/XSIMD/CMakeFiles/xsimd_avx2.dir/src/"
            "xsimd_avx2.c.o.d"
        ),
    },
    "../XSIMD/libxsimd_sse2.a": {
        "member": "xsimd_sse2.c.o",
        "source": "xsimd/src/xsimd_sse2.c",
        "dependency_file": (
            "src/XSIMD/CMakeFiles/xsimd_sse2.dir/src/"
            "xsimd_sse2.c.o.d"
        ),
    },
}
LICENSE_MARKERS = {
    "mit-permission": b"permission is hereby granted, free of charge",
    "hors-copyright": b"hors<horsicq@gmail.com>",
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


def parse_dependency_file(path: pathlib.Path) -> list[pathlib.Path]:
    text = path.read_text(encoding="utf-8", errors="replace")
    flattened = text.replace("\\\n", " ")
    if ":" not in flattened:
        raise ValueError(f"invalid dependency file: {path}")
    return [
        pathlib.Path(value)
        for value in shlex.split(flattened.split(":", 1)[1])
    ]


def parse_nm_defined_symbols(text: str) -> set[str]:
    symbols = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        symbol_type = fields[-2]
        if (
            len(symbol_type) != 1
            or not symbol_type.isupper()
            or symbol_type == "U"
        ):
            continue
        symbols.add(fields[-1])
    return symbols


def defined_symbols(path: pathlib.Path) -> set[str]:
    process = subprocess.run(
        ["nm", "-g", "--defined-only", str(path)],
        check=True,
        capture_output=True,
        text=True,
        errors="replace",
    )
    if process.stderr:
        raise ValueError(f"nm wrote stderr: {path}")
    return parse_nm_defined_symbols(process.stdout)


def archive_members(path: pathlib.Path) -> list[str]:
    process = subprocess.run(
        ["ar", "t", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    if process.stderr:
        raise ValueError(f"ar member listing wrote stderr: {path}")
    return process.stdout.splitlines()


def member_defined_symbols(
    archive: pathlib.Path,
    member: str,
) -> set[str]:
    process = subprocess.run(
        ["ar", "p", str(archive), member],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError(f"ar member extraction wrote stderr: {member}")
    with tempfile.NamedTemporaryFile(suffix=".o") as temporary:
        temporary.write(process.stdout)
        temporary.flush()
        return defined_symbols(pathlib.Path(temporary.name))


def markers(data: bytes) -> list[str]:
    folded = data.lower()
    return sorted(
        name
        for name, marker in LICENSE_MARKERS.items()
        if marker.lower() in folded
    )


def file_record(
    path: pathlib.Path,
    component_root: pathlib.Path,
) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(component_root).as_posix(),
        "bytes": len(data),
        "sha256": sha256(data),
        "license_markers": markers(data),
    }


def component_dependencies(
    dependency_file: pathlib.Path,
    component_root: pathlib.Path,
) -> set[pathlib.Path]:
    result = set()
    for dependency in parse_dependency_file(dependency_file):
        resolved = dependency.resolve()
        try:
            resolved.relative_to(component_root)
        except ValueError:
            continue
        if resolved.is_file():
            result.add(resolved)
    return result


def build_inside_report(
    source_root: pathlib.Path,
    build_root: pathlib.Path,
    lock_path: pathlib.Path,
) -> dict[str, Any]:
    source_root = source_root.resolve()
    build_root = build_root.resolve()
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    formats_root = (source_root / "Formats").resolve()
    formats_commit = str(lock["gitlink"]["Formats"]["commit"])
    if lock["baseline"]["commit"] != UPSTREAM_COMMIT:
        raise ValueError("component lock baseline mismatch")
    if git_head(source_root) != UPSTREAM_COMMIT:
        raise ValueError("source image root commit mismatch")
    if git_head(formats_root) != formats_commit:
        raise ValueError("Formats commit mismatch")

    link_path = build_root / "src/console/CMakeFiles/diec.dir/link.txt"
    link_bytes = link_path.read_bytes()
    link_tokens = shlex.split(link_bytes.decode("utf-8"))
    for archive_token in ARCHIVES:
        if link_tokens.count(archive_token) != 1:
            raise ValueError(f"XSIMD link identity drift: {archive_token}")

    artifact = build_root / "src/console/diec"
    artifact_bytes = artifact.read_bytes()
    final_symbols = defined_symbols(artifact)
    link_directory = build_root / "src/console"
    closure_paths: set[pathlib.Path] = set()
    archive_records = []
    compile_units = []
    for archive_token, expected in sorted(ARCHIVES.items()):
        archive_path = (link_directory / archive_token).resolve()
        members = archive_members(archive_path)
        if members != [expected["member"]]:
            raise ValueError(f"XSIMD archive member drift: {archive_token}")
        member_symbols = member_defined_symbols(
            archive_path, expected["member"]
        )
        witnesses = sorted(member_symbols & final_symbols)
        if not witnesses:
            raise ValueError(
                f"XSIMD member lacks final ELF witness: {archive_token}"
            )
        dependency_file = build_root / expected["dependency_file"]
        dependencies = component_dependencies(
            dependency_file, formats_root
        )
        source = formats_root / expected["source"]
        if source not in dependencies:
            raise ValueError(f"XSIMD source missing from .o.d: {source}")
        closure_paths.update(dependencies)
        record = {
            "archive": archive_token,
            "archive_sha256": sha256(archive_path.read_bytes()),
            "member": expected["member"],
            "source": expected["source"],
            "dependency_file": expected["dependency_file"],
            "defined_global_symbols": sorted(member_symbols),
            "final_elf_symbol_witnesses": witnesses,
            "extracted_into_final_elf": True,
        }
        archive_records.append(record)
        compile_units.append(
            {
                "source": expected["source"],
                "linkage": archive_token,
                "dependency_file": expected["dependency_file"],
                "symbol_witnesses": witnesses,
            }
        )

    files = [
        file_record(path, formats_root)
        for path in sorted(
            closure_paths,
            key=lambda item: item.relative_to(formats_root).as_posix(),
        )
    ]
    source_paths = {unit["source"] for unit in compile_units}
    cuda_paths = {
        "xsimd/src/xsimd_cuda.cu",
        "xsimd/src/xsimd_cuda.h",
    }
    root_license = formats_root / "LICENSE"
    marker_counts = {
        marker: sum(
            marker in record["license_markers"] for record in files
        )
        for marker in sorted(LICENSE_MARKERS)
    }
    relationships = {
        "three_xsimd_archives_are_linked_once": all(
            link_tokens.count(token) == 1 for token in ARCHIVES
        ),
        "each_archive_contains_exactly_one_expected_member": (
            len(archive_records) == 3
        ),
        "all_three_members_have_final_elf_symbol_witnesses": all(
            record["final_elf_symbol_witnesses"]
            for record in archive_records
        ),
        "compile_source_count_is_3": len(source_paths) == 3,
        "component_dependency_closure_has_6_files": len(files) == 6,
        "all_closure_files_have_mit_and_hors_markers": all(
            set(record["license_markers"])
            == {"hors-copyright", "mit-permission"}
            for record in files
        ),
        "cuda_sources_are_excluded_from_linux_qt5_closure": (
            cuda_paths.isdisjoint(
                {record["path"] for record in files}
            )
        ),
        "formats_root_license_exists_outside_compiler_dependencies": (
            root_license.is_file() and root_license not in closure_paths
        ),
    }
    if not all(relationships.values()):
        raise ValueError("XSIMD build relationships are incomplete")

    return {
        "schema_version": 1,
        "generator": "tools/upstream/audit_xsimd_license_closure.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": formats_commit,
        "component_lock": {
            "path": "upstream/components.lock.toml",
            "sha256": sha256(lock_bytes),
        },
        "build": {
            "link_path": "src/console/CMakeFiles/diec.dir/link.txt",
            "link_sha256": sha256(link_bytes),
            "artifact_path": "src/console/diec",
            "artifact_sha256": sha256(artifact_bytes),
            "linked_archives": sorted(ARCHIVES),
            "archive_count": len(archive_records),
            "extracted_archive_member_count": sum(
                record["extracted_into_final_elf"]
                for record in archive_records
            ),
        },
        "compile_source_count": len(source_paths),
        "closure_file_count": len(files),
        "marker_counts": marker_counts,
        "relationships": relationships,
        "archives": archive_records,
        "compile_units": sorted(
            compile_units, key=lambda unit: unit["source"]
        ),
        "files": files,
        "license_evidence_files": [
            file_record(root_license, formats_root)
        ],
        "distribution_requirements": [
            (
                "retain the Formats root MIT text and the hors copyright "
                "notice for the six contributing xsimd source/header files"
            ),
        ],
        "limitations": [
            (
                "symbol intersection proves archive member contribution "
                "for this non-stripped ELF, not instruction-level reachability"
            ),
            (
                "the report covers fixed Linux x86_64 Qt5 CMake Release "
                "diec only; CUDA, Windows, macOS, qmake, and Qt6 are outside "
                "this report"
            ),
            (
                "license markers and retained text are technical evidence, "
                "not legal approval"
            ),
        ],
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
        raise ValueError("XSIMD audit image revision mismatch")
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
            "/repo/tools/upstream/audit_xsimd_license_closure.py",
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
        raise ValueError("inside XSIMD audit wrote stderr")
    report = json.loads(process.stdout)
    report["source_image"] = {
        "image": IMAGE,
        "image_id": image_id,
        "revision": revision,
        "network": "none",
        "repository_mount": "readonly",
    }
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--source-root", type=pathlib.Path)
    parser.add_argument("--build-root", type=pathlib.Path)
    parser.add_argument("--lock", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.inside:
        if (
            args.source_root is None
            or args.build_root is None
            or args.lock is None
        ):
            raise ValueError(
                "--inside requires source root, build root, and lock"
            )
        report = build_inside_report(
            args.source_root, args.build_root, args.lock
        )
    else:
        if args.output is None:
            raise ValueError("host mode requires --output")
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

#!/usr/bin/env python3
"""Inventory XCapstone files that contribute to the fixed Linux diec ELF."""

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
DIRECT_OBJECT = "CMakeFiles/diec.dir/__/__/XCapstone/xcapstone.cpp.o"
ARCHIVE_TOKEN = "../XCapstone_86/libcapstone_x86.a"
EXPECTED_ARCHIVE_MEMBERS = {
    "MCInst.c.o",
    "MCInstrDesc.c.o",
    "MCRegisterInfo.c.o",
    "SStream.c.o",
    "X86Disassembler.c.o",
    "X86DisassemblerDecoder.c.o",
    "X86IntelInstPrinter.c.o",
    "X86Mapping.c.o",
    "X86Module.c.o",
    "cs.c.o",
    "utils.c.o",
}
LICENSE_MARKERS = {
    "bsd-redistribution": (
        b"redistribution and use in source and binary forms"
    ),
    "capstone-origin": b"capstone disassembly",
    "llvm-ncsa-attribution": b"university of illinois",
    "mit-permission": b"permission is hereby granted, free of charge",
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


def find_markers(data: bytes) -> list[str]:
    folded = data.lower()
    return sorted(
        name
        for name, marker in LICENSE_MARKERS.items()
        if marker in folded
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
        "license_markers": find_markers(data),
    }


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


def archive_member_bytes(
    archive: pathlib.Path,
    member: str,
) -> bytes:
    process = subprocess.run(
        ["ar", "p", str(archive), member],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError(f"ar wrote stderr for member: {member}")
    return process.stdout


def archive_members(archive: pathlib.Path) -> list[str]:
    process = subprocess.run(
        ["ar", "t", str(archive)],
        check=True,
        capture_output=True,
        text=True,
    )
    if process.stderr:
        raise ValueError("ar member listing wrote stderr")
    return process.stdout.splitlines()


def member_symbol_witnesses(
    archive: pathlib.Path,
    member: str,
    final_symbols: set[str],
) -> tuple[list[str], list[str]]:
    data = archive_member_bytes(archive, member)
    with tempfile.NamedTemporaryFile(suffix=".o") as temporary:
        temporary.write(data)
        temporary.flush()
        member_symbols = defined_symbols(pathlib.Path(temporary.name))
    return sorted(member_symbols), sorted(member_symbols & final_symbols)


def first_component_source(
    dependencies: list[pathlib.Path],
    component_root: pathlib.Path,
) -> pathlib.Path:
    for dependency in dependencies:
        resolved = dependency.resolve()
        try:
            resolved.relative_to(component_root)
        except ValueError:
            continue
        if resolved.suffix.lower() in {".c", ".cpp"} and resolved.is_file():
            return resolved
    raise ValueError("dependency file has no XCapstone compile source")


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
    component_root = (source_root / "XCapstone").resolve()
    xcapstone_commit = str(lock["gitlink"]["XCapstone"]["commit"])
    if lock["baseline"]["commit"] != UPSTREAM_COMMIT:
        raise ValueError("component lock baseline mismatch")
    if git_head(source_root) != UPSTREAM_COMMIT:
        raise ValueError("source image root commit mismatch")
    if git_head(component_root) != xcapstone_commit:
        raise ValueError("XCapstone commit mismatch")

    link_path = build_root / "src/console/CMakeFiles/diec.dir/link.txt"
    link_bytes = link_path.read_bytes()
    link_tokens = shlex.split(link_bytes.decode("utf-8"))
    if link_tokens.count(DIRECT_OBJECT) != 1:
        raise ValueError("direct XCapstone object link identity drift")
    if link_tokens.count(ARCHIVE_TOKEN) != 1:
        raise ValueError("capstone_x86 archive link identity drift")

    link_directory = build_root / "src/console"
    direct_dependency = link_directory / f"{DIRECT_OBJECT}.d"
    direct_dependencies = parse_dependency_file(direct_dependency)
    direct_source = first_component_source(
        direct_dependencies, component_root
    )
    if direct_source.relative_to(component_root).as_posix() != "xcapstone.cpp":
        raise ValueError("direct XCapstone source drift")

    archive_path = (link_directory / ARCHIVE_TOKEN).resolve()
    members = archive_members(archive_path)
    if set(members) != EXPECTED_ARCHIVE_MEMBERS or len(members) != 11:
        raise ValueError("capstone_x86 archive member set drift")
    dependency_root = (
        build_root
        / "src/XCapstone_86/CMakeFiles/capstone_x86.dir"
    )
    dependency_files = sorted(dependency_root.rglob("*.o.d"))
    dependency_by_member = {
        path.name.removesuffix(".o.d"): path
        for path in dependency_files
    }
    if set(dependency_by_member) != {
        member.removesuffix(".o") for member in members
    }:
        raise ValueError("capstone_x86 dependency member set drift")

    artifact = build_root / "src/console/diec"
    artifact_bytes = artifact.read_bytes()
    final_symbols = defined_symbols(artifact)
    member_records = []
    extracted_members = []
    unextracted_members = []
    closure_paths = component_dependencies(
        direct_dependency, component_root
    )
    compile_units = [
        {
            "source": "xcapstone.cpp",
            "linkage": "die-direct",
            "dependency_file": direct_dependency.relative_to(
                build_root
            ).as_posix(),
            "symbol_witnesses": None,
        }
    ]
    for member in members:
        defined, witnesses = member_symbol_witnesses(
            archive_path, member, final_symbols
        )
        dependency_file = dependency_by_member[
            member.removesuffix(".o")
        ]
        dependencies = parse_dependency_file(dependency_file)
        source = first_component_source(dependencies, component_root)
        record = {
            "member": member,
            "source": source.relative_to(component_root).as_posix(),
            "dependency_file": dependency_file.relative_to(
                build_root
            ).as_posix(),
            "defined_global_symbols": defined,
            "final_elf_symbol_witnesses": witnesses,
            "extracted_into_final_elf": bool(witnesses),
        }
        member_records.append(record)
        if witnesses:
            extracted_members.append(member)
            closure_paths.update(
                component_dependencies(dependency_file, component_root)
            )
            compile_units.append(
                {
                    "source": record["source"],
                    "linkage": ARCHIVE_TOKEN,
                    "dependency_file": record["dependency_file"],
                    "symbol_witnesses": witnesses,
                }
            )
        else:
            unextracted_members.append(member)

    source_paths = {
        component_root / unit["source"] for unit in compile_units
    }
    records = [
        file_record(path, component_root)
        for path in sorted(
            closure_paths,
            key=lambda item: item.relative_to(
                component_root
            ).as_posix(),
        )
    ]
    evidence_paths = [
        component_root / "LICENSE",
        component_root / "3rdparty/Capstone/src/LICENSE.TXT",
        component_root / "3rdparty/Capstone/src/LICENSE_LLVM.TXT",
    ]
    marker_counts = {
        marker: sum(
            marker in record["license_markers"] for record in records
        )
        for marker in sorted(LICENSE_MARKERS)
    }
    relationships = {
        "direct_xcapstone_object_is_linked_once": (
            link_tokens.count(DIRECT_OBJECT) == 1
        ),
        "capstone_x86_archive_is_linked_once": (
            link_tokens.count(ARCHIVE_TOKEN) == 1
        ),
        "archive_build_contains_11_members": len(members) == 11,
        "ten_archive_members_have_final_elf_symbol_witnesses": (
            len(extracted_members) == 10
        ),
        "mcinstrdesc_is_the_only_unextracted_archive_member": (
            unextracted_members == ["MCInstrDesc.c.o"]
        ),
        "final_compile_source_count_is_11": len(source_paths) == 11,
        "final_component_dependency_closure_has_71_files": (
            len(records) == 71
        ),
        "all_extracted_members_have_symbol_witnesses": all(
            record["final_elf_symbol_witnesses"]
            for record in member_records
            if record["extracted_into_final_elf"]
        ),
        "all_required_license_texts_exist_outside_compiler_dependencies": (
            all(path.is_file() for path in evidence_paths)
            and all(path not in closure_paths for path in evidence_paths)
        ),
    }
    if not all(relationships.values()):
        raise ValueError("XCapstone build relationships are incomplete")

    return {
        "schema_version": 1,
        "generator": (
            "tools/upstream/audit_xcapstone_license_closure.py"
        ),
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "xcapstone_commit": xcapstone_commit,
        "component_lock": {
            "path": "upstream/components.lock.toml",
            "sha256": sha256(lock_bytes),
        },
        "build": {
            "link_path": "src/console/CMakeFiles/diec.dir/link.txt",
            "link_sha256": sha256(link_bytes),
            "artifact_path": "src/console/diec",
            "artifact_sha256": sha256(artifact_bytes),
            "direct_object": DIRECT_OBJECT,
            "linked_archive": ARCHIVE_TOKEN,
            "archive_member_count": len(members),
            "extracted_archive_member_count": len(extracted_members),
            "unextracted_archive_members": unextracted_members,
        },
        "compile_source_count": len(source_paths),
        "closure_file_count": len(records),
        "marker_counts": marker_counts,
        "relationships": relationships,
        "archive_members": member_records,
        "compile_units": sorted(
            compile_units,
            key=lambda unit: unit["source"],
        ),
        "files": records,
        "license_evidence_files": [
            file_record(path, component_root) for path in evidence_paths
        ],
        "distribution_requirements": [
            (
                "retain XCapstone root MIT text for the direct wrapper "
                "source"
            ),
            (
                "reproduce Capstone BSD conditions and disclaimer in "
                "binary distribution documentation or other materials"
            ),
            (
                "reproduce the LLVM University of Illinois/NCSA notice "
                "and disclaimers for the 11 contributing LLVM-derived files"
            ),
        ],
        "limitations": [
            (
                "symbol intersection proves archive member contribution "
                "for this non-stripped ELF, not instruction-level reachability"
            ),
            (
                "the report covers fixed Linux Qt5 CMake Release diec only"
            ),
            (
                "license markers and retained texts are technical evidence, "
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
        raise ValueError("XCapstone audit image revision mismatch")
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
            (
                "/repo/tools/upstream/"
                "audit_xcapstone_license_closure.py"
            ),
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
        raise ValueError("inside XCapstone audit wrote stderr")
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
            args.source_root,
            args.build_root,
            args.lock,
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
            serialized,
            encoding="utf-8",
            newline="\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

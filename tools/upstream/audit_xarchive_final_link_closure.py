#!/usr/bin/env python3
"""Audit XArchive static-library member extraction in the fixed Linux diec ELF."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import tomllib
from typing import Any


IMAGE = "die-rust/upstream-oracle-cmake:74eaf505"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
PRIOR_REPORT = (
    "docs/research/data/xarchive-license-closure-linux.json"
)
DIRECT_OBJECT_PREFIX = "CMakeFiles/diec.dir/__/__/XArchive/"
EXPECTED_ARCHIVES = {
    "../XArchive/3rdparty/bzip2/libbzip2.a": {
        "blocksort.c.o",
        "bzip2.c.o",
        "bzlib.c.o",
        "compress.c.o",
        "crctable.c.o",
        "decompress.c.o",
        "huffman.c.o",
        "randtable.c.o",
    },
    "../XArchive/3rdparty/lzma/liblzma.a": {
        "Lzma2Dec.c.o",
        "LzmaDec.c.o",
    },
    "../XArchive/3rdparty/ppmd/libppmd.a": {
        "Ppmd7.c.o",
        "Ppmd7Dec.c.o",
        "Ppmd8.c.o",
        "Ppmd8Dec.c.o",
    },
    "../XArchive/3rdparty/zlib/libzlib.a": {
        "adler32.c.o",
        "crc32.c.o",
        "deflate.c.o",
        "inflate.c.o",
        "inffast.c.o",
        "inftrees.c.o",
        "trees.c.o",
        "zutil.c.o",
    },
}
EXPECTED_INCLUDED = {
    (
        "../XArchive/3rdparty/lzma/liblzma.a",
        "LzmaDec.c.o",
    ): (
        "CMakeFiles/diec.dir/__/__/XStaticUnpacker/xnsis.cpp.o "
        "(LzmaDec_Init)"
    ),
}
LICENSE_MARKERS = {
    "mit-permission": b"permission is hereby granted, free of charge",
    "public-domain": b"public domain",
    "igor-pavlov": b"igor pavlov",
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


def dependency_by_member(
    archive_path: pathlib.Path,
) -> dict[str, pathlib.Path]:
    target = archive_path.stem.removeprefix("lib")
    dependency_root = (
        archive_path.parent / "CMakeFiles" / f"{target}.dir"
    )
    result = {}
    for path in sorted(dependency_root.rglob("*.o.d")):
        member = path.name.removesuffix(".d")
        if member in result:
            raise ValueError(f"duplicate archive member dependency: {member}")
        result[member] = path
    return result


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
    raise ValueError("dependency file has no XArchive compile source")


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


def file_record(
    path: pathlib.Path,
    component_root: pathlib.Path,
) -> dict[str, Any]:
    data = path.read_bytes()
    folded = data.lower()
    return {
        "path": path.relative_to(component_root).as_posix(),
        "bytes": len(data),
        "sha256": sha256(data),
        "license_markers": sorted(
            name
            for name, marker in LICENSE_MARKERS.items()
            if marker in folded
        ),
    }


def replay_link_with_map(
    link_tokens: list[str],
    link_directory: pathlib.Path,
) -> tuple[bytes, bytes]:
    if link_tokens.count("-o") != 1:
        raise ValueError("link command output option drift")
    output_index = link_tokens.index("-o") + 1
    replay_tokens = list(link_tokens)
    replay_tokens[output_index] = "/tmp/die-xarchive-final-link"
    replay_tokens.insert(
        output_index - 1,
        "-Wl,-Map,/tmp/die-xarchive-final-link.map",
    )
    process = subprocess.run(
        replay_tokens,
        cwd=link_directory,
        check=True,
        capture_output=True,
    )
    if process.stdout or process.stderr:
        raise ValueError("replayed link command wrote output")
    artifact = pathlib.Path("/tmp/die-xarchive-final-link").read_bytes()
    link_map = pathlib.Path(
        "/tmp/die-xarchive-final-link.map"
    ).read_bytes()
    return artifact, link_map


def parse_archive_inclusions(
    link_map: str,
) -> dict[tuple[str, str], str]:
    header, separator, _ = link_map.partition(
        "\n\nMerging program properties"
    )
    if not separator:
        raise ValueError("GNU ld map inclusion header is missing")
    lines = header.splitlines()
    result = {}
    pattern = re.compile(
        r"^(\.\./XArchive/3rdparty/(?:bzip2|lzma|ppmd|zlib)/"
        r"lib[^()]+\.a)\(([^()]+)\)$"
    )
    for index, line in enumerate(lines):
        match = pattern.fullmatch(line)
        if match is None:
            continue
        if index + 1 >= len(lines):
            raise ValueError("archive inclusion lacks a reason line")
        key = (match.group(1), match.group(2))
        if key in result:
            raise ValueError(f"duplicate archive inclusion: {key}")
        result[key] = lines[index + 1].strip()
    return result


def build_inside_report(
    source_root: pathlib.Path,
    build_root: pathlib.Path,
    lock_path: pathlib.Path,
    prior_report_path: pathlib.Path,
) -> dict[str, Any]:
    source_root = source_root.resolve()
    build_root = build_root.resolve()
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    component_root = (source_root / "XArchive").resolve()
    xarchive_commit = str(lock["gitlink"]["XArchive"]["commit"])
    if lock["baseline"]["commit"] != UPSTREAM_COMMIT:
        raise ValueError("component lock baseline mismatch")
    if git_head(source_root) != UPSTREAM_COMMIT:
        raise ValueError("source image root commit mismatch")
    if git_head(component_root) != xarchive_commit:
        raise ValueError("XArchive commit mismatch")

    prior_bytes = prior_report_path.read_bytes()
    prior = json.loads(prior_bytes)
    if (
        prior["upstream_commit"] != UPSTREAM_COMMIT
        or prior["xarchive_commit"] != xarchive_commit
        or prior["build"]["direct_object_count"] != 84
        or prior["build"]["archive_object_count"] != 22
        or not all(prior["relationships"].values())
    ):
        raise ValueError("prior XArchive build closure report drift")

    link_path = build_root / "src/console/CMakeFiles/diec.dir/link.txt"
    link_bytes = link_path.read_bytes()
    if sha256(link_bytes) != prior["build"]["link_sha256"]:
        raise ValueError("prior XArchive link identity drift")
    link_tokens = shlex.split(link_bytes.decode("utf-8"))
    direct_objects = sorted(
        token
        for token in link_tokens
        if token.startswith(DIRECT_OBJECT_PREFIX) and token.endswith(".o")
    )
    if len(direct_objects) != 84:
        raise ValueError("direct XArchive object count drift")
    for archive_token in EXPECTED_ARCHIVES:
        if link_tokens.count(archive_token) != 1:
            raise ValueError(f"XArchive link identity drift: {archive_token}")

    original_artifact = build_root / "src/console/diec"
    original_bytes = original_artifact.read_bytes()
    replay_bytes, map_bytes = replay_link_with_map(
        link_tokens, build_root / "src/console"
    )
    if replay_bytes != original_bytes:
        raise ValueError("map replay changed final ELF bytes")
    inclusions = parse_archive_inclusions(
        map_bytes.decode("utf-8", errors="strict")
    )
    if inclusions != EXPECTED_INCLUDED:
        raise ValueError("XArchive archive inclusion set drift")

    final_symbols = defined_symbols(original_artifact)
    member_records = []
    included_dependencies: set[pathlib.Path] = set()
    archive_records = []
    for archive_token, expected_members in sorted(
        EXPECTED_ARCHIVES.items()
    ):
        archive_path = (
            build_root / "src/console" / archive_token
        ).resolve()
        members = archive_members(archive_path)
        if set(members) != expected_members:
            raise ValueError(f"XArchive archive member set drift: {archive_token}")
        dependencies = dependency_by_member(archive_path)
        if set(dependencies) != expected_members:
            raise ValueError(
                f"XArchive dependency member set drift: {archive_token}"
            )
        archive_records.append(
            {
                "archive": archive_token,
                "sha256": sha256(archive_path.read_bytes()),
                "built_member_count": len(members),
                "included_member_count": sum(
                    (archive_token, member) in inclusions
                    for member in members
                ),
            }
        )
        for member in members:
            dependency_file = dependencies[member]
            dependency_paths = parse_dependency_file(dependency_file)
            source = first_component_source(
                dependency_paths, component_root
            )
            member_symbols = member_defined_symbols(archive_path, member)
            intersections = sorted(member_symbols & final_symbols)
            included = (archive_token, member) in inclusions
            if included:
                included_dependencies.update(
                    component_dependencies(
                        dependency_file, component_root
                    )
                )
            member_records.append(
                {
                    "archive": archive_token,
                    "member": member,
                    "source": source.relative_to(
                        component_root
                    ).as_posix(),
                    "dependency_file": dependency_file.relative_to(
                        build_root
                    ).as_posix(),
                    "included_by_link_map": included,
                    "inclusion_reason": inclusions.get(
                        (archive_token, member)
                    ),
                    "defined_global_symbols": sorted(member_symbols),
                    "final_elf_symbol_name_intersections": intersections,
                }
            )

    included_records = [
        record
        for record in member_records
        if record["included_by_link_map"]
    ]
    excluded_with_intersections = [
        record
        for record in member_records
        if (
            not record["included_by_link_map"]
            and record["final_elf_symbol_name_intersections"]
        )
    ]
    dependency_records = [
        file_record(path, component_root)
        for path in sorted(
            included_dependencies,
            key=lambda item: item.relative_to(
                component_root
            ).as_posix(),
        )
    ]
    relationships = {
        "prior_report_proves_84_direct_and_22_built_archive_units": (
            prior["build"]["direct_object_count"] == 84
            and prior["build"]["archive_object_count"] == 22
        ),
        "four_expected_archives_are_linked_once": all(
            link_tokens.count(token) == 1 for token in EXPECTED_ARCHIVES
        ),
        "archive_build_contains_22_members": len(member_records) == 22,
        "replayed_link_is_byte_identical": replay_bytes == original_bytes,
        "link_map_includes_only_lzmadec": (
            inclusions == EXPECTED_INCLUDED
        ),
        "one_of_22_archive_members_is_included": (
            len(included_records) == 1
        ),
        "twenty_one_archive_members_are_not_included": (
            len(member_records) - len(included_records) == 21
        ),
        "eight_excluded_members_have_misleading_symbol_intersections": (
            len(excluded_with_intersections) == 8
        ),
        "final_xarchive_compile_source_count_is_85": (
            len(direct_objects) + len(included_records) == 85
        ),
    }
    if not all(relationships.values()):
        raise ValueError("XArchive final link relationships are incomplete")

    return {
        "schema_version": 1,
        "generator": (
            "tools/upstream/audit_xarchive_final_link_closure.py"
        ),
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "xarchive_commit": xarchive_commit,
        "component_lock": {
            "path": "upstream/components.lock.toml",
            "sha256": sha256(lock_bytes),
        },
        "prior_build_closure": {
            "path": PRIOR_REPORT,
            "sha256": sha256(prior_bytes),
            "direct_compile_source_count": 84,
            "built_archive_member_count": 22,
        },
        "build": {
            "link_path": "src/console/CMakeFiles/diec.dir/link.txt",
            "link_sha256": sha256(link_bytes),
            "artifact_path": "src/console/diec",
            "artifact_sha256": sha256(original_bytes),
            "replayed_artifact_sha256": sha256(replay_bytes),
            "link_map_sha256": sha256(map_bytes),
            "direct_xarchive_object_count": len(direct_objects),
            "built_archive_member_count": len(member_records),
            "included_archive_member_count": len(included_records),
            "excluded_archive_member_count": (
                len(member_records) - len(included_records)
            ),
            "final_xarchive_compile_source_count": (
                len(direct_objects) + len(included_records)
            ),
        },
        "relationships": relationships,
        "archives": archive_records,
        "members": sorted(
            member_records,
            key=lambda record: (
                record["archive"], record["member"]
            ),
        ),
        "included_member_dependency_file_count": len(
            dependency_records
        ),
        "included_member_dependency_files": dependency_records,
        "symbol_intersection_boundary": {
            "excluded_members_with_nonempty_intersections": len(
                excluded_with_intersections
            ),
            "interpretation": (
                "global symbol-name intersection is not proof of archive "
                "member extraction because another object or library can "
                "provide the same symbol; GNU ld inclusion map is authoritative"
            ),
        },
        "distribution_requirements": [
            (
                "the fixed final ELF extracts only LzmaDec.c.o from these "
                "four XArchive archives; retain its public-domain/origin "
                "evidence in addition to the XArchive root MIT text"
            ),
            (
                "do not classify the other 21 built members as final ELF "
                "contributors for this configuration solely because their "
                "archives occur on the link line"
            ),
        ],
        "limitations": [
            (
                "the 84 directly linked XArchive objects remain contributors "
                "and retain the separate RAR/Brotli/Zstandard review findings"
            ),
            (
                "the report covers fixed Linux x86_64 Qt5 CMake Release "
                "diec only; other platforms/build systems/features can extract "
                "different members"
            ),
            (
                "license markers and link evidence are technical evidence, "
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
        raise ValueError("XArchive final-link image revision mismatch")
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
                "audit_xarchive_final_link_closure.py"
            ),
            "--inside",
            "--source-root",
            "/opt/die-source",
            "--build-root",
            "/opt/die-build",
            "--lock",
            "/repo/upstream/components.lock.toml",
            "--prior-report",
            f"/repo/{PRIOR_REPORT}",
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError("inside XArchive final-link audit wrote stderr")
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
    parser.add_argument("--prior-report", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.inside:
        if (
            args.source_root is None
            or args.build_root is None
            or args.lock is None
            or args.prior_report is None
        ):
            raise ValueError(
                "--inside requires source root, build root, lock, and "
                "prior report"
            )
        report = build_inside_report(
            args.source_root,
            args.build_root,
            args.lock,
            args.prior_report,
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

#!/usr/bin/env python3
"""Audit the YARA target embedded in the fixed XYara Linux build."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shlex
import subprocess
import sys
import tomllib
from typing import Any


IMAGE = "die-rust/upstream-oracle-cmake:74eaf505"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
XYARA_COMMIT = "34a733e9c733669ad8dcaf4588d51197a08545e3"
YARA_COMMIT = "688268d83983a0d61bb68ef3d8dfd28102b7d1b4"
YARA_REPOSITORY = "https://github.com/VirusTotal/yara.git"
YARA_TLSHC_IMPORT = "19ac2efeb89b88f938fd64234791149ec7edf00f"
YARA_TLSHC_FORMAT = "22fde83d7aa7dd208ee756e3c56d565575d1a7b0"
YARA_TLSHC_HISTORY = {
    YARA_TLSHC_IMPORT,
    YARA_TLSHC_FORMAT,
    "b2612f51362439abbc03311f58fcc452de258f91",
    "94e884f999734e72301eb4c0cc340e7acbaa5009",
    "17ae552539cfa09470c40b1e35187ba3c998c64e",
    "bdd398039353279c67d4541aacf7c1875d69a22b",
}
TLSHC_COMMIT = "bb91fef822a21d480a6bee2a8d693965b5bca16e"
TLSHC_REPOSITORY = "https://github.com/avast/tlshc.git"
EXPECTED_OBJECT_COUNT = 51
EXPECTED_ARCHIVE_SHA256 = (
    "2a7db6ee2b0191a6092afe3c27640e98702d2b363d01d93e33afe7d2a29d85c9"
)
LICENSE_MARKERS = {
    "avast-mit": b"copyright (c) 2021 avast software",
    "bison-gpl3": b"either version 3 of the license",
    "bison-special-exception": b"as a special exception",
    "mit-permission": b"permission is hereby granted, free of charge",
    "yara-bsd": b"redistribution and use in source and binary forms",
}
TLSHC_PATHS = {
    "src/include/tlshc/tlsh.h": "include/tlshc/tlsh.h",
    "src/tlshc/tlsh.c": "src/tlsh.c",
    "src/tlshc/tlsh_impl.c": "src/tlsh_impl.c",
    "src/tlshc/tlsh_impl.h": "src/tlsh_impl.h",
    "src/tlshc/tlsh_util.c": "src/tlsh_util.c",
    "src/tlshc/tlsh_util.h": "src/tlsh_util.h",
}
GENERATED_PARSER_PATHS = {
    "src/grammar.c",
    "src/grammar.h",
    "src/hex_grammar.c",
    "src/hex_grammar.h",
    "src/re_grammar.c",
    "src/re_grammar.h",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(
    command: list[str],
    *,
    check: bool = True,
    text: bool = False,
) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        command,
        check=check,
        capture_output=True,
        text=text,
    )


def git_output(path: pathlib.Path, *args: str) -> str:
    process = run(
        ["git", "-C", str(path), *args],
        text=True,
    )
    if process.stderr:
        raise ValueError(f"git wrote stderr for {path}: {process.stderr}")
    return process.stdout.strip()


def validate_checkout(
    path: pathlib.Path,
    *,
    commit: str,
    repository: str,
) -> None:
    if git_output(path, "rev-parse", "HEAD") != commit:
        raise ValueError(f"checkout commit mismatch: {path}")
    if git_output(path, "status", "--porcelain"):
        raise ValueError(f"checkout is dirty: {path}")
    remote = git_output(path, "remote", "get-url", "origin")
    if remote.rstrip("/").removesuffix(".git").lower() != (
        repository.rstrip("/").removesuffix(".git").lower()
    ):
        raise ValueError(f"checkout remote mismatch: {path}")


def find_markers(data: bytes) -> list[str]:
    folded = data.lower()
    return sorted(
        name
        for name, marker in LICENSE_MARKERS.items()
        if marker in folded
    )


def file_record(
    path: pathlib.Path,
    root: pathlib.Path,
) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "bytes": len(data),
        "sha256": sha256(data),
        "license_markers": find_markers(data),
    }


def evidence_record(label: str, path: pathlib.Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "label": label,
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


def relative_files(root: pathlib.Path) -> dict[str, pathlib.Path]:
    return {
        path.relative_to(root).as_posix(): path
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def official_yara_path(vendored_path: str) -> str:
    if vendored_path == "_hash.c":
        return "hash.c"
    return vendored_path


def git_blob(
    checkout: pathlib.Path,
    commit: str,
    path: str,
) -> bytes:
    return run(
        ["git", "-C", str(checkout), "show", f"{commit}:{path}"]
    ).stdout


def parse_version(libyara_header: pathlib.Path) -> str:
    text = libyara_header.read_text(encoding="utf-8")
    parts = []
    for name in ("MAJOR", "MINOR", "MICRO"):
        match = re.search(
            rf"^#define YR_{name}_VERSION\s+(\d+)$",
            text,
            flags=re.MULTILINE,
        )
        if match is None:
            raise ValueError(f"missing YARA {name} version")
        parts.append(match.group(1))
    return ".".join(parts)


def normalize_build_stderr(
    stderr: str,
    source_root: pathlib.Path,
) -> str:
    normalized = stderr.replace(
        source_root.as_posix(),
        "$YARA_SOURCE",
    )
    return normalized.replace("\r\n", "\n")


def warning_records(stderr: str) -> list[dict[str, Any]]:
    pattern = re.compile(
        r"^\$YARA_SOURCE/src/([^:]+):(\d+):\d+: warning: "
        r"(.*) \[(-W[^\]]+)\]$"
    )
    records = []
    for line in stderr.splitlines():
        match = pattern.match(line)
        if match is None:
            continue
        records.append(
            {
                "path": f"src/{match.group(1)}",
                "line": int(match.group(2)),
                "message": match.group(3),
                "option": match.group(4),
            }
        )
    return records


def compare_official_yara(
    vendored_source: pathlib.Path,
    official_yara: pathlib.Path,
) -> dict[str, Any]:
    vendored = relative_files(vendored_source)
    official_root = official_yara / "libyara"
    official = relative_files(official_root)
    mappings = []
    mapped_official = set()
    for path, source in sorted(vendored.items()):
        official_path = official_yara_path(path)
        target = official.get(official_path)
        if target is None:
            raise ValueError(f"vendored YARA file has no official map: {path}")
        source_hash = sha256(source.read_bytes())
        official_hash = sha256(target.read_bytes())
        mappings.append(
            {
                "vendored_path": path,
                "official_path": official_path,
                "vendored_sha256": source_hash,
                "official_sha256": official_hash,
                "exact": source_hash == official_hash,
            }
        )
        mapped_official.add(official_path)

    modified = [
        record for record in mappings if not record["exact"]
    ]
    official_only = sorted(set(official) - mapped_official)
    if len(vendored) != 132 or len(official) != 139:
        raise ValueError("unexpected vendored or official YARA file count")
    if len(mappings) != 132 or sum(r["exact"] for r in mappings) != 129:
        raise ValueError("unexpected YARA source identity coverage")
    if [record["vendored_path"] for record in modified] != [
        "include/yara/unaligned.h",
        "simple_str.c",
        "strutils.c",
    ]:
        raise ValueError("unexpected XYara modifications to YARA")
    if official_only != [
        "grammar.y",
        "hex_grammar.y",
        "hex_lexer.l",
        "lexer.l",
        "re_grammar.y",
        "re_lexer.l",
        "stino.settings",
    ]:
        raise ValueError("unexpected official-only YARA sources")

    return {
        "vendored_file_count": len(vendored),
        "official_file_count": len(official),
        "mapped_file_count": len(mappings),
        "exact_file_count": sum(r["exact"] for r in mappings),
        "modified_files": modified,
        "official_only_files": official_only,
        "renamed_exact_files": [
            record
            for record in mappings
            if record["vendored_path"] != record["official_path"]
        ],
    }


def trace_tlshc(
    vendored_yara: pathlib.Path,
    official_yara: pathlib.Path,
    official_tlshc: pathlib.Path,
) -> dict[str, Any]:
    ancestry = run(
        [
            "git",
            "-C",
            str(official_yara),
            "merge-base",
            "--is-ancestor",
            YARA_TLSHC_IMPORT,
            YARA_COMMIT,
        ],
        check=False,
    )
    if ancestry.returncode != 0:
        raise ValueError("YARA TLSH import is not an ancestor of v4.5.2")

    records = []
    histories: set[str] = set()
    for vendored_path, tlshc_path in sorted(TLSHC_PATHS.items()):
        official_path = f"libyara/{vendored_path.removeprefix('src/')}"
        vendored_bytes = (vendored_yara / vendored_path).read_bytes()
        current_bytes = (official_yara / official_path).read_bytes()
        import_bytes = git_blob(
            official_yara,
            YARA_TLSHC_IMPORT,
            official_path,
        )
        source_bytes = (official_tlshc / tlshc_path).read_bytes()
        history = git_output(
            official_yara,
            "log",
            "--format=%H",
            "--",
            official_path,
        ).splitlines()
        histories.update(history)
        record = {
            "vendored_path": vendored_path,
            "official_yara_path": official_path,
            "official_tlshc_path": tlshc_path,
            "vendored_sha256": sha256(vendored_bytes),
            "official_yara_sha256": sha256(current_bytes),
            "yara_import_sha256": sha256(import_bytes),
            "official_tlshc_sha256": sha256(source_bytes),
            "yara_history": history,
            "vendored_equals_yara_v4_5_2": vendored_bytes
            == current_bytes,
            "yara_import_equals_tlshc": import_bytes == source_bytes,
            "inline_license_markers": find_markers(vendored_bytes),
        }
        if not record["vendored_equals_yara_v4_5_2"]:
            raise ValueError("vendored TLSH differs from official YARA")
        if not record["yara_import_equals_tlshc"]:
            raise ValueError("YARA TLSH import differs from avast/tlshc")
        if record["inline_license_markers"]:
            raise ValueError("unexpected inline license in TLSH source")
        records.append(record)

    if histories != YARA_TLSHC_HISTORY:
        raise ValueError("unexpected YARA TLSH history")
    return {
        "license_expression": "Apache-2.0 OR BSD-3-Clause",
        "yara_import_commit": YARA_TLSHC_IMPORT,
        "yara_format_commit": YARA_TLSHC_FORMAT,
        "yara_history_commits": sorted(histories),
        "files": records,
        "license_evidence": [
            evidence_record(
                "avast/tlshc LICENSE",
                official_tlshc / "LICENSE",
            ),
            evidence_record(
                "avast/tlshc NOTICE.txt",
                official_tlshc / "NOTICE.txt",
            ),
        ],
    }


def build_inside_report(
    source_root: pathlib.Path,
    build_root: pathlib.Path,
    lock_path: pathlib.Path,
    official_yara: pathlib.Path,
    official_tlshc: pathlib.Path,
) -> dict[str, Any]:
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    if lock["baseline"]["commit"] != UPSTREAM_COMMIT:
        raise ValueError("component lock baseline mismatch")
    if lock["gitlink"]["XYara"]["commit"] != XYARA_COMMIT:
        raise ValueError("component lock XYara mismatch")
    if git_output(source_root, "rev-parse", "HEAD") != UPSTREAM_COMMIT:
        raise ValueError("source image root commit mismatch")

    xyara_root = source_root / "XYara"
    if git_output(xyara_root, "rev-parse", "HEAD") != XYARA_COMMIT:
        raise ValueError("XYara commit mismatch")
    validate_checkout(
        official_yara,
        commit=YARA_COMMIT,
        repository=YARA_REPOSITORY,
    )
    validate_checkout(
        official_tlshc,
        commit=TLSHC_COMMIT,
        repository=TLSHC_REPOSITORY,
    )

    yara_root = xyara_root / "3rdparty/yara"
    vendored_source = yara_root / "src"
    target_root = build_root / "src/XYara/3rdparty/yara"
    build = run(
        [
            "cmake",
            "--build",
            str(build_root),
            "--target",
            "yara",
            "--parallel",
            "2",
        ],
        check=False,
        text=True,
    )
    if build.returncode != 0:
        raise ValueError(f"YARA build failed:\n{build.stderr}")

    archive_path = target_root / "libyara.a"
    archive_bytes = archive_path.read_bytes()
    archive_members = run(
        ["ar", "t", str(archive_path)],
        text=True,
    ).stdout.splitlines()
    dependency_root = target_root / "CMakeFiles/yara.dir"
    dependency_files = sorted(dependency_root.rglob("*.o.d"))
    if (
        len(archive_members) != EXPECTED_OBJECT_COUNT
        or len(dependency_files) != EXPECTED_OBJECT_COUNT
    ):
        raise ValueError("unexpected YARA object or dependency count")

    compile_units = []
    closure_paths: set[pathlib.Path] = set()
    source_paths: set[pathlib.Path] = set()
    for dependency_file in dependency_files:
        dependencies = parse_dependency_file(dependency_file)
        vendored_dependencies = []
        for dependency in dependencies:
            try:
                dependency.relative_to(yara_root)
            except ValueError:
                continue
            if dependency.is_file():
                vendored_dependencies.append(dependency)
                closure_paths.add(dependency)
        candidates = [
            path
            for path in vendored_dependencies
            if path.suffix == ".c" and path.is_relative_to(vendored_source)
        ]
        if len(candidates) != 1:
            raise ValueError(
                f"dependency file has {len(candidates)} C sources: "
                f"{dependency_file}"
            )
        source = candidates[0]
        source_paths.add(source)
        compile_units.append(
            {
                "source": source.relative_to(yara_root).as_posix(),
                "dependency_file": dependency_file.relative_to(
                    build_root
                ).as_posix(),
                "dependency_count": len(vendored_dependencies),
            }
        )
    compile_units.sort(key=lambda record: record["source"])
    if len(source_paths) != EXPECTED_OBJECT_COUNT:
        raise ValueError("YARA compile source count mismatch")

    records = [
        file_record(path, yara_root)
        for path in sorted(
            closure_paths,
            key=lambda item: item.relative_to(yara_root).as_posix(),
        )
    ]
    closure_names = {record["path"] for record in records}
    generated_records = [
        record
        for record in records
        if record["path"] in GENERATED_PARSER_PATHS
    ]
    if {record["path"] for record in generated_records} != (
        GENERATED_PARSER_PATHS
    ):
        raise ValueError("generated Bison parser closure mismatch")

    authenticode_paths = sorted(
        path
        for path in vendored_source.rglob("*")
        if path.is_file() and "authenticode" in path.as_posix()
    )
    authenticode_records = [
        file_record(path, yara_root) for path in authenticode_paths
    ]
    if len(authenticode_records) != 10:
        raise ValueError("unexpected Authenticode parser inventory")
    if any(
        record["license_markers"] != ["avast-mit", "mit-permission"]
        for record in authenticode_records
    ):
        raise ValueError("Authenticode parser license header mismatch")

    flags_path = dependency_root / "flags.make"
    flags_bytes = flags_path.read_bytes()
    flags_text = flags_bytes.decode("utf-8")
    link_path = build_root / "src/console/CMakeFiles/diec.dir/link.txt"
    link_bytes = link_path.read_bytes()
    normalized_stderr = normalize_build_stderr(
        build.stderr,
        yara_root,
    )
    warnings = warning_records(normalized_stderr)
    if len(warnings) != 12:
        raise ValueError("unexpected YARA compiler warning count")

    source_comparison = compare_official_yara(
        vendored_source,
        official_yara,
    )
    tlshc = trace_tlshc(
        yara_root,
        official_yara,
        official_tlshc,
    )
    bundled_license_candidates = sorted(
        path.relative_to(yara_root).as_posix()
        for path in yara_root.rglob("*")
        if path.is_file()
        and path.name.upper().startswith(
            ("LICENSE", "COPYING", "NOTICE", "COPYRIGHT")
        )
    )
    relationships = {
        "archive_has_51_objects": len(archive_members)
        == EXPECTED_OBJECT_COUNT,
        "dependency_graph_has_51_compile_units": len(compile_units)
        == EXPECTED_OBJECT_COUNT,
        "archive_hash_is_reproducible": sha256(archive_bytes)
        == EXPECTED_ARCHIVE_SHA256,
        "vendored_yara_maps_to_official_v4_5_2": (
            source_comparison["mapped_file_count"] == 132
        ),
        "all_tlshc_files_have_fixed_provenance": all(
            record["vendored_equals_yara_v4_5_2"]
            and record["yara_import_equals_tlshc"]
            for record in tlshc["files"]
        ),
        "generated_bison_parsers_are_in_closure": (
            {record["path"] for record in generated_records}
            == GENERATED_PARSER_PATHS
        ),
        "authenticode_parser_is_not_in_linux_closure": not any(
            record["path"] in closure_names
            for record in authenticode_records
        ),
        "libcrypto_is_disabled": "HAVE_LIBCRYPTO" not in flags_text,
        "yara_is_not_linked_into_diec": not re.search(
            r"(?i)(xyara|libyara|/yara)",
            link_bytes.decode("utf-8"),
        ),
        "bundled_yara_has_no_license_candidate": not (
            bundled_license_candidates
        ),
    }
    if not all(relationships.values()):
        raise ValueError("YARA build relationships are incomplete")

    return {
        "schema_version": 1,
        "generator": "tools/upstream/audit_yara_license_closure.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "xyara_commit": XYARA_COMMIT,
        "official_yara": {
            "repository": YARA_REPOSITORY,
            "commit": YARA_COMMIT,
            "version": parse_version(
                vendored_source / "include/yara/libyara.h"
            ),
            "copying": evidence_record(
                "VirusTotal/yara COPYING",
                official_yara / "COPYING",
            ),
        },
        "official_tlshc": {
            "repository": TLSHC_REPOSITORY,
            "commit": TLSHC_COMMIT,
        },
        "component_lock": {
            "path": "upstream/components.lock.toml",
            "sha256": sha256(lock_bytes),
        },
        "build": {
            "target": "yara",
            "archive_path": (
                "src/XYara/3rdparty/yara/libyara.a"
            ),
            "archive_sha256": sha256(archive_bytes),
            "object_count": len(archive_members),
            "archive_members": archive_members,
            "flags_path": flags_path.relative_to(build_root).as_posix(),
            "flags_sha256": sha256(flags_bytes),
            "compile_definitions": re.search(
                r"^C_DEFINES = (.*)$",
                flags_text,
                flags=re.MULTILINE,
            ).group(1).split(),
            "compile_flags": re.search(
                r"^C_FLAGS = (.*)$",
                flags_text,
                flags=re.MULTILINE,
            ).group(1).split(),
            "normalized_stderr_sha256": sha256(
                normalized_stderr.encode("utf-8")
            ),
            "warnings": warnings,
        },
        "compile_source_count": len(source_paths),
        "closure_file_count": len(records),
        "compile_units": compile_units,
        "files": records,
        "generated_bison_parsers": generated_records,
        "authenticode_parser": {
            "license_expression": "MIT",
            "vendored_file_count": len(authenticode_records),
            "compiled_or_included_file_count": sum(
                record["path"] in closure_names
                for record in authenticode_records
            ),
            "files": authenticode_records,
        },
        "source_comparison": source_comparison,
        "tlshc_provenance": tlshc,
        "bundled_license_candidates": bundled_license_candidates,
        "relationships": relationships,
    }


def inspect_image() -> tuple[str, str]:
    process = run(["docker", "image", "inspect", IMAGE])
    document = json.loads(process.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision",
        "",
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError("YARA audit image revision mismatch")
    return document["Id"], revision


def run_in_fixed_image(
    repo: pathlib.Path,
    official_yara: pathlib.Path,
    official_tlshc: pathlib.Path,
) -> dict[str, Any]:
    validate_checkout(
        official_yara,
        commit=YARA_COMMIT,
        repository=YARA_REPOSITORY,
    )
    validate_checkout(
        official_tlshc,
        commit=TLSHC_COMMIT,
        repository=TLSHC_REPOSITORY,
    )
    image_id, revision = inspect_image()
    process = run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--cpus=2",
            "--memory=2g",
            "--mount",
            f"type=bind,source={repo},target=/repo,readonly",
            "--mount",
            (
                f"type=bind,source={official_yara},"
                "target=/official/yara,readonly"
            ),
            "--mount",
            (
                f"type=bind,source={official_tlshc},"
                "target=/official/tlshc,readonly"
            ),
            "--entrypoint",
            "/usr/bin/python3",
            IMAGE,
            "/repo/tools/upstream/audit_yara_license_closure.py",
            "--inside",
            "--source-root",
            "/opt/die-source",
            "--build-root",
            "/opt/die-build",
            "--lock",
            "/repo/upstream/components.lock.toml",
            "--official-yara-root",
            "/official/yara",
            "--official-tlshc-root",
            "/official/tlshc",
        ],
        check=False,
    )
    if process.returncode != 0:
        raise ValueError(
            "inside YARA audit failed:\n"
            + process.stderr.decode("utf-8", errors="replace")
        )
    if process.stderr:
        raise ValueError(
            "inside YARA audit wrote stderr:\n"
            + process.stderr.decode("utf-8", errors="replace")
        )
    report = json.loads(process.stdout)
    report["source_image"] = {
        "image": IMAGE,
        "image_id": image_id,
        "revision": revision,
        "network": "none",
        "repository_mount": "readonly",
        "official_mounts": "readonly",
        "cpu_limit": 2,
        "memory_limit": "2g",
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--source-root", type=pathlib.Path)
    parser.add_argument("--build-root", type=pathlib.Path)
    parser.add_argument("--lock", type=pathlib.Path)
    parser.add_argument("--official-yara-root", type=pathlib.Path)
    parser.add_argument("--official-tlshc-root", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.inside:
        required = (
            args.source_root,
            args.build_root,
            args.lock,
            args.official_yara_root,
            args.official_tlshc_root,
        )
        if any(value is None for value in required):
            parser.error("inside mode requires all source arguments")
        report = build_inside_report(
            args.source_root,
            args.build_root,
            args.lock,
            args.official_yara_root,
            args.official_tlshc_root,
        )
    else:
        if (
            args.output is None
            or args.official_yara_root is None
            or args.official_tlshc_root is None
        ):
            parser.error(
                "host mode requires --output, --official-yara-root "
                "and --official-tlshc-root"
            )
        repo = pathlib.Path(__file__).resolve().parents[2]
        report = run_in_fixed_image(
            repo,
            args.official_yara_root.resolve(),
            args.official_tlshc_root.resolve(),
        )

    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(serialized)
    else:
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build the fixed Linux diec product-level compile-source closure."""

from __future__ import annotations

import argparse
import collections
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
DIRECT_PREFIX = "CMakeFiles/diec.dir/"
COMPONENT_DIRECT_PREFIX = f"{DIRECT_PREFIX}__/__/"
EXPECTED_COMPONENT_DIRECT_COUNTS = {
    "Formats": 37,
    "SpecAbstract": 30,
    "XArchive": 84,
    "XCapstone": 1,
    "XDEX": 2,
    "XDisasmCore": 5,
    "XEntropyWidget": 1,
    "XFileInfo": 4,
    "XOptions": 5,
    "XPDF": 1,
    "XScanEngine": 34,
    "XStaticUnpacker": 11,
    "die_script": 5,
}
EXPECTED_ROOT_OBJECTS = {
    "CMakeFiles/diec.dir/consoleoutput.cpp.o",
    "CMakeFiles/diec.dir/main_console.cpp.o",
}
GENERATED_OBJECT = (
    "CMakeFiles/diec.dir/diec_autogen/mocs_compilation.cpp.o"
)
EXPECTED_ARCHIVES = {
    "../XArchive/3rdparty/bzip2/libbzip2.a": {
        "component": "XArchive",
        "members": {
            "blocksort.c.o",
            "bzip2.c.o",
            "bzlib.c.o",
            "compress.c.o",
            "crctable.c.o",
            "decompress.c.o",
            "huffman.c.o",
            "randtable.c.o",
        },
        "included": set(),
    },
    "../XArchive/3rdparty/lzma/liblzma.a": {
        "component": "XArchive",
        "members": {"Lzma2Dec.c.o", "LzmaDec.c.o"},
        "included": {"LzmaDec.c.o"},
    },
    "../XArchive/3rdparty/ppmd/libppmd.a": {
        "component": "XArchive",
        "members": {
            "Ppmd7.c.o",
            "Ppmd7Dec.c.o",
            "Ppmd8.c.o",
            "Ppmd8Dec.c.o",
        },
        "included": set(),
    },
    "../XArchive/3rdparty/zlib/libzlib.a": {
        "component": "XArchive",
        "members": {
            "adler32.c.o",
            "crc32.c.o",
            "deflate.c.o",
            "inflate.c.o",
            "inffast.c.o",
            "inftrees.c.o",
            "trees.c.o",
            "zutil.c.o",
        },
        "included": set(),
    },
    "../XCapstone_86/libcapstone_x86.a": {
        "component": "XCapstone",
        "members": {
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
        },
        "included": {
            "MCInst.c.o",
            "MCRegisterInfo.c.o",
            "SStream.c.o",
            "X86Disassembler.c.o",
            "X86DisassemblerDecoder.c.o",
            "X86IntelInstPrinter.c.o",
            "X86Mapping.c.o",
            "X86Module.c.o",
            "cs.c.o",
            "utils.c.o",
        },
    },
    "../XSIMD/libxsimd.a": {
        "component": "Formats",
        "members": {"xsimd.c.o"},
        "included": {"xsimd.c.o"},
    },
    "../XSIMD/libxsimd_avx2.a": {
        "component": "Formats",
        "members": {"xsimd_avx2.c.o"},
        "included": {"xsimd_avx2.c.o"},
    },
    "../XSIMD/libxsimd_sse2.a": {
        "component": "Formats",
        "members": {"xsimd_sse2.c.o"},
        "included": {"xsimd_sse2.c.o"},
    },
}
EXPECTED_COMPILE_SOURCE_COUNTS = {
    "DIE-engine": 2,
    "Formats": 40,
    "SpecAbstract": 30,
    "XArchive": 85,
    "XCapstone": 11,
    "XDEX": 2,
    "XDisasmCore": 5,
    "XEntropyWidget": 1,
    "XFileInfo": 4,
    "XOptions": 5,
    "XPDF": 1,
    "XScanEngine": 34,
    "XStaticUnpacker": 11,
    "die_script": 5,
    "generated": 1,
}
EXPECTED_GENERATED_ORIGINS = {
    "Formats",
    "SpecAbstract",
    "XArchive",
    "XCapstone",
    "XDEX",
    "XDisasmCore",
    "XEntropyWidget",
    "XFileInfo",
    "XOptions",
    "XPDF",
    "XScanEngine",
    "XStaticUnpacker",
    "die_script",
}
PRIOR_REPORTS = {
    "xarchive_final_link": (
        "docs/research/data/xarchive-final-link-closure-linux.json"
    ),
    "xcapstone": (
        "docs/research/data/xcapstone-license-closure-linux.json"
    ),
    "xsimd": "docs/research/data/xsimd-license-closure-linux.json",
}
LICENSE_MARKERS = {
    "mit-permission": b"permission is hereby granted, free of charge",
    "public-domain": b"public domain",
    "bsd-redistribution": (
        b"redistribution and use in source and binary forms"
    ),
    "llvm-ncsa": b"university of illinois",
    "unrar": b"unrar",
    "gpl": b"gnu general public license",
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


def markers(data: bytes) -> list[str]:
    folded = data.lower()
    return sorted(
        name
        for name, marker in LICENSE_MARKERS.items()
        if marker in folded
    )


def source_record(
    path: pathlib.Path,
    relative_path: str,
    component: str,
    linkage: str,
    dependency_file: str,
    source_kind: str,
    inclusion_reason: str | None = None,
) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "component": component,
        "source": relative_path,
        "source_kind": source_kind,
        "linkage": linkage,
        "dependency_file": dependency_file,
        "bytes": len(data),
        "sha256": sha256(data),
        "license_markers": markers(data),
        "inclusion_reason": inclusion_reason,
    }


def first_source(
    dependencies: list[pathlib.Path],
    root: pathlib.Path,
) -> pathlib.Path:
    for dependency in dependencies:
        resolved = dependency.resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        if resolved.suffix.lower() in {".c", ".cc", ".cpp"}:
            if resolved.is_file():
                return resolved
    raise ValueError(f"dependency list has no compile source under {root}")


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


def archive_dependency_files(
    archive_token: str,
    archive_path: pathlib.Path,
    build_root: pathlib.Path,
) -> dict[str, pathlib.Path]:
    if archive_token.startswith("../XArchive/"):
        target = archive_path.stem.removeprefix("lib")
        dependency_root = (
            archive_path.parent / "CMakeFiles" / f"{target}.dir"
        )
    elif archive_token == "../XCapstone_86/libcapstone_x86.a":
        dependency_root = (
            build_root
            / "src/XCapstone_86/CMakeFiles/capstone_x86.dir"
        )
    elif archive_token.startswith("../XSIMD/"):
        target = archive_path.stem.removeprefix("lib")
        dependency_root = (
            build_root / "src/XSIMD/CMakeFiles" / f"{target}.dir"
        )
    else:
        raise ValueError(f"unknown project archive: {archive_token}")
    result = {}
    for path in sorted(dependency_root.rglob("*.o.d")):
        member = path.name.removesuffix(".d")
        if member in result:
            raise ValueError(f"duplicate dependency member: {member}")
        result[member] = path
    return result


def replay_link_with_map(
    link_tokens: list[str],
    link_directory: pathlib.Path,
) -> tuple[bytes, bytes]:
    if link_tokens.count("-o") != 1:
        raise ValueError("link output option drift")
    output_index = link_tokens.index("-o") + 1
    replay = list(link_tokens)
    replay[output_index] = "/tmp/die-product-source-closure"
    replay.insert(
        output_index - 1,
        "-Wl,-Map,/tmp/die-product-source-closure.map",
    )
    process = subprocess.run(
        replay,
        cwd=link_directory,
        check=True,
        capture_output=True,
    )
    if process.stdout or process.stderr:
        raise ValueError("replayed product link wrote output")
    return (
        pathlib.Path("/tmp/die-product-source-closure").read_bytes(),
        pathlib.Path(
            "/tmp/die-product-source-closure.map"
        ).read_bytes(),
    )


def parse_project_archive_inclusions(
    link_map: str,
) -> dict[tuple[str, str], str]:
    header, separator, _ = link_map.partition(
        "\n\nMerging program properties"
    )
    if not separator:
        raise ValueError("GNU ld map inclusion header is missing")
    archive_pattern = re.compile(r"^(\.\./[^()]+\.a)\(([^()]+)\)$")
    result = {}
    lines = header.splitlines()
    for index, line in enumerate(lines):
        match = archive_pattern.fullmatch(line)
        if match is None or match.group(1) not in EXPECTED_ARCHIVES:
            continue
        if index + 1 >= len(lines):
            raise ValueError("project archive inclusion lacks reason")
        key = (match.group(1), match.group(2))
        if key in result:
            raise ValueError(f"duplicate project archive inclusion: {key}")
        result[key] = lines[index + 1].strip()
    return result


def component_from_source(
    source: pathlib.Path,
    source_root: pathlib.Path,
) -> tuple[str, str]:
    relative = source.relative_to(source_root).as_posix()
    first = relative.split("/", 1)[0]
    if first == "src":
        return "DIE-engine", relative
    return first, relative


def validate_prior_reports(
    repo_root: pathlib.Path,
    link_sha: str,
    artifact_sha: str,
) -> dict[str, dict[str, Any]]:
    result = {}
    for name, relative in PRIOR_REPORTS.items():
        path = repo_root / relative
        data = path.read_bytes()
        report = json.loads(data)
        if (
            report["upstream_commit"] != UPSTREAM_COMMIT
            or report["build"]["link_sha256"] != link_sha
            or report["build"]["artifact_sha256"] != artifact_sha
            or not all(report["relationships"].values())
        ):
            raise ValueError(f"prior report drift: {name}")
        result[name] = {
            "path": relative,
            "sha256": sha256(data),
        }
    return result


def build_inside_report(
    source_root: pathlib.Path,
    build_root: pathlib.Path,
    lock_path: pathlib.Path,
    repo_root: pathlib.Path,
) -> dict[str, Any]:
    source_root = source_root.resolve()
    build_root = build_root.resolve()
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    if lock["baseline"]["commit"] != UPSTREAM_COMMIT:
        raise ValueError("component lock baseline mismatch")
    if git_head(source_root) != UPSTREAM_COMMIT:
        raise ValueError("source image root commit mismatch")
    for component in EXPECTED_COMPONENT_DIRECT_COUNTS:
        expected = str(lock["gitlink"][component]["commit"])
        if git_head(source_root / component) != expected:
            raise ValueError(f"component commit mismatch: {component}")

    link_directory = build_root / "src/console"
    link_path = link_directory / "CMakeFiles/diec.dir/link.txt"
    link_bytes = link_path.read_bytes()
    link_tokens = shlex.split(link_bytes.decode("utf-8"))
    original_path = link_directory / "diec"
    original_bytes = original_path.read_bytes()
    prior_reports = validate_prior_reports(
        repo_root, sha256(link_bytes), sha256(original_bytes)
    )

    direct_objects = sorted(
        token
        for token in link_tokens
        if token.startswith(DIRECT_PREFIX) and token.endswith(".o")
    )
    if len(direct_objects) != 223:
        raise ValueError("direct object count drift")
    component_object_counts = collections.Counter()
    root_objects = set()
    generated_objects = set()
    for token in direct_objects:
        if token.startswith(COMPONENT_DIRECT_PREFIX):
            remainder = token[len(COMPONENT_DIRECT_PREFIX) :]
            component_object_counts[remainder.split("/", 1)[0]] += 1
        elif token == GENERATED_OBJECT:
            generated_objects.add(token)
        else:
            root_objects.add(token)
    if dict(component_object_counts) != EXPECTED_COMPONENT_DIRECT_COUNTS:
        raise ValueError("component direct object counts drift")
    if root_objects != EXPECTED_ROOT_OBJECTS:
        raise ValueError("root direct object set drift")
    if generated_objects != {GENERATED_OBJECT}:
        raise ValueError("generated direct object set drift")

    replay_bytes, map_bytes = replay_link_with_map(
        link_tokens, link_directory
    )
    if replay_bytes != original_bytes:
        raise ValueError("product link replay changed ELF bytes")
    inclusions = parse_project_archive_inclusions(
        map_bytes.decode("utf-8", errors="strict")
    )
    expected_inclusions = {
        (archive, member)
        for archive, config in EXPECTED_ARCHIVES.items()
        for member in config["included"]
    }
    if set(inclusions) != expected_inclusions:
        raise ValueError("project archive inclusion set drift")

    compile_sources = []
    generated_origin_components = set()
    for token in direct_objects:
        dependency_file = link_directory / f"{token}.d"
        dependencies = parse_dependency_file(dependency_file)
        if token == GENERATED_OBJECT:
            source = (
                link_directory / "diec_autogen/mocs_compilation.cpp"
            ).resolve()
            if source not in {path.resolve() for path in dependencies}:
                raise ValueError("generated source missing from dependency file")
            for dependency in dependencies:
                resolved = dependency.resolve()
                try:
                    relative = resolved.relative_to(source_root).as_posix()
                except ValueError:
                    continue
                first = relative.split("/", 1)[0]
                if first in EXPECTED_COMPONENT_DIRECT_COUNTS:
                    generated_origin_components.add(first)
            compile_sources.append(
                source_record(
                    source,
                    "@build/src/console/diec_autogen/"
                    "mocs_compilation.cpp",
                    "generated",
                    "direct-object",
                    dependency_file.relative_to(build_root).as_posix(),
                    "cmake-automoc-generated",
                )
            )
            continue
        source = first_source(dependencies, source_root)
        component, relative = component_from_source(
            source, source_root
        )
        compile_sources.append(
            source_record(
                source,
                relative,
                component,
                "direct-object",
                dependency_file.relative_to(build_root).as_posix(),
                "upstream-source",
            )
        )
    if generated_origin_components != EXPECTED_GENERATED_ORIGINS:
        raise ValueError(
            "AUTOMOC origin component set drift: "
            f"{sorted(generated_origin_components)}"
        )

    archive_records = []
    for archive_token, config in sorted(EXPECTED_ARCHIVES.items()):
        if link_tokens.count(archive_token) != 1:
            raise ValueError(f"archive link identity drift: {archive_token}")
        archive_path = (link_directory / archive_token).resolve()
        members = archive_members(archive_path)
        if set(members) != config["members"]:
            raise ValueError(f"archive member set drift: {archive_token}")
        dependency_files = archive_dependency_files(
            archive_token, archive_path, build_root
        )
        if set(dependency_files) != config["members"]:
            raise ValueError(
                f"archive dependency member set drift: {archive_token}"
            )
        archive_records.append(
            {
                "archive": archive_token,
                "sha256": sha256(archive_path.read_bytes()),
                "component": config["component"],
                "built_member_count": len(members),
                "included_member_count": len(config["included"]),
                "excluded_members": sorted(
                    config["members"] - config["included"]
                ),
            }
        )
        component_root = source_root / config["component"]
        for member in sorted(config["included"]):
            dependency_file = dependency_files[member]
            source = first_source(
                parse_dependency_file(dependency_file),
                component_root,
            )
            compile_sources.append(
                source_record(
                    source,
                    source.relative_to(source_root).as_posix(),
                    config["component"],
                    f"{archive_token}({member})",
                    dependency_file.relative_to(build_root).as_posix(),
                    "upstream-source",
                    inclusions[(archive_token, member)],
                )
            )

    source_identities = {
        (record["component"], record["source"], record["linkage"])
        for record in compile_sources
    }
    if len(source_identities) != len(compile_sources):
        raise ValueError("duplicate compile-source identity")
    compile_counts = collections.Counter(
        record["component"] for record in compile_sources
    )
    if dict(compile_counts) != EXPECTED_COMPILE_SOURCE_COUNTS:
        raise ValueError("final compile-source counts drift")

    license_records = []
    root_license = source_root / "LICENSE"
    license_records.append(
        source_record(
            root_license,
            "LICENSE",
            "DIE-engine",
            "license-evidence",
            "",
            "license-text",
        )
    )
    for component in EXPECTED_COMPONENT_DIRECT_COUNTS:
        path = source_root / component / "LICENSE"
        license_records.append(
            source_record(
                path,
                f"{component}/LICENSE",
                component,
                "license-evidence",
                "",
                "license-text",
            )
        )
    marker_counts = collections.Counter(
        marker
        for record in compile_sources
        for marker in record["license_markers"]
    )
    gpl_marker_sources = [
        record
        for record in compile_sources
        if "gpl" in record["license_markers"]
    ]
    xucl_path = source_root / "XArchive/Algos/xucldecoder.cpp"
    xucl_lines = xucl_path.read_text(
        encoding="utf-8", errors="strict"
    ).splitlines()
    xucl_gpl_lines = [
        index
        for index, line in enumerate(xucl_lines, start=1)
        if "GNU General Public License" in line
    ]
    acc_license_paths = sorted(
        path.relative_to(source_root / "XArchive").as_posix()
        for path in (source_root / "XArchive").rglob("*")
        if path.is_file() and path.name.upper() == "ACC_LICENSE"
    )
    relationships = {
        "direct_object_count_is_223": len(direct_objects) == 223,
        "thirteen_components_contribute_220_direct_objects": (
            sum(component_object_counts.values()) == 220
            and len(component_object_counts) == 13
        ),
        "root_contributes_two_direct_objects": len(root_objects) == 2,
        "automoc_contributes_one_generated_direct_object": (
            len(generated_objects) == 1
        ),
        "eight_project_archives_are_linked_once": all(
            link_tokens.count(token) == 1 for token in EXPECTED_ARCHIVES
        ),
        "project_archives_build_36_members": (
            sum(
                len(config["members"])
                for config in EXPECTED_ARCHIVES.values()
            )
            == 36
        ),
        "link_map_includes_14_project_archive_members": (
            len(inclusions) == 14
        ),
        "twenty_two_project_archive_members_are_not_included": (
            36 - len(inclusions) == 22
        ),
        "product_compile_source_count_is_237": (
            len(compile_sources) == 237
        ),
        "compile_source_component_counts_are_exact": (
            dict(compile_counts) == EXPECTED_COMPILE_SOURCE_COUNTS
        ),
        "automoc_origin_component_set_is_exact": (
            generated_origin_components == EXPECTED_GENERATED_ORIGINS
        ),
        "replayed_link_is_byte_identical": replay_bytes == original_bytes,
        "all_contributing_component_root_licenses_exist": (
            len(license_records) == 14
            and all(record["bytes"] > 0 for record in license_records)
        ),
        "compile_source_marker_counts_are_exact": (
            dict(marker_counts)
            == {
                "gpl": 1,
                "llvm-ncsa": 4,
                "mit-permission": 212,
                "public-domain": 3,
            }
        ),
        "xucl_is_the_only_gpl_marker_compile_source": (
            len(gpl_marker_sources) == 1
            and gpl_marker_sources[0]["source"]
            == "XArchive/Algos/xucldecoder.cpp"
        ),
        "xucl_references_missing_acc_license_at_line_842": (
            xucl_gpl_lines == [842] and not acc_license_paths
        ),
        "three_prior_member_reports_are_bound": len(prior_reports) == 3,
    }
    if not all(relationships.values()):
        raise ValueError("product source closure relationships are incomplete")

    return {
        "schema_version": 1,
        "generator": "tools/upstream/audit_product_source_closure.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "component_lock": {
            "path": "upstream/components.lock.toml",
            "sha256": sha256(lock_bytes),
        },
        "prior_reports": prior_reports,
        "build": {
            "link_path": "src/console/CMakeFiles/diec.dir/link.txt",
            "link_sha256": sha256(link_bytes),
            "artifact_path": "src/console/diec",
            "artifact_sha256": sha256(original_bytes),
            "replayed_artifact_sha256": sha256(replay_bytes),
            "link_map_sha256": sha256(map_bytes),
            "direct_object_count": len(direct_objects),
            "project_archive_count": len(EXPECTED_ARCHIVES),
            "built_project_archive_member_count": 36,
            "included_project_archive_member_count": len(inclusions),
            "excluded_project_archive_member_count": 36 - len(inclusions),
            "compile_source_count": len(compile_sources),
        },
        "relationships": relationships,
        "direct_object_counts": {
            "components": dict(sorted(component_object_counts.items())),
            "root": len(root_objects),
            "generated": len(generated_objects),
        },
        "compile_source_counts": dict(sorted(compile_counts.items())),
        "generated_automoc": {
            "source": (
                "@build/src/console/diec_autogen/mocs_compilation.cpp"
            ),
            "origin_components": sorted(generated_origin_components),
        },
        "marker_counts": dict(sorted(marker_counts.items())),
        "archives": archive_records,
        "compile_sources": sorted(
            compile_sources,
            key=lambda record: (
                record["component"],
                record["source"],
                record["linkage"],
            ),
        ),
        "root_license_evidence": sorted(
            license_records, key=lambda record: record["component"]
        ),
        "notable_license_findings": [
            {
                "id": "PRODUCT-LICENSE-GAP-001",
                "component": "XArchive",
                "source": "XArchive/Algos/xucldecoder.cpp",
                "source_sha256": sha256(xucl_path.read_bytes()),
                "linkage": "direct-object",
                "gpl_marker_lines": xucl_gpl_lines,
                "referenced_license_file": "ACC_LICENSE",
                "matching_license_paths_in_component": acc_license_paths,
                "classification": "release-legal-review-required",
                "boundary": (
                    "the source's GPL statement and missing referenced "
                    "license are technical evidence; this report does not "
                    "select a GPL version or provide a legal conclusion"
                ),
            }
        ],
        "scope_classification": {
            "compiled_product_sources": 237,
            "runtime_rule_assets": (
                "separate 2268-file closure; not compile sources"
            ),
            "build_only_targets": (
                "XYara/YARA and XCppfilt are absent from the diec link"
            ),
            "dynamic_system_dependencies": (
                "separate deployment-size and runtime dependency closure"
            ),
        },
        "limitations": [
            (
                "the report covers the fixed Linux x86_64 Qt5 CMake Release "
                "diec product only"
            ),
            (
                "compile-source contribution is not function- or section-level "
                "runtime reachability and does not waive source attribution"
            ),
            (
                "component root MIT files do not override the separately "
                "documented XArchive and XCapstone bundled-code terms"
            ),
            (
                "license markers and source/link identities are technical "
                "evidence, not legal approval"
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
        raise ValueError("product source closure image revision mismatch")
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
            "/repo/tools/upstream/audit_product_source_closure.py",
            "--inside",
            "--source-root",
            "/opt/die-source",
            "--build-root",
            "/opt/die-build",
            "--lock",
            "/repo/upstream/components.lock.toml",
            "--repo-root",
            "/repo",
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError("inside product source closure wrote stderr")
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
    parser.add_argument("--repo-root", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.inside:
        if (
            args.source_root is None
            or args.build_root is None
            or args.lock is None
            or args.repo_root is None
        ):
            raise ValueError(
                "--inside requires source root, build root, lock, and "
                "repo root"
            )
        report = build_inside_report(
            args.source_root,
            args.build_root,
            args.lock,
            args.repo_root,
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

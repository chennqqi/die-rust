#!/usr/bin/env python3
"""Audit pinned YARA, PEiD, and binary-signature data assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tomllib
from typing import Any


IMAGE = "die-rust/upstream-oracle-cmake:74eaf505"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
DETECT_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
XYARA_COMMIT = "34a733e9c733669ad8dcaf4588d51197a08545e3"
XPEID_COMMIT = "15c2e2951ab2443c7794e8f88c9fc5c65b217f28"
SIGNATURES_COMMIT = "5d80fb2863d02e9366aee7b3ade6abb7d6598dbb"

XYARA_REPOSITORY = "https://github.com/horsicq/XYara.git"
XPEID_REPOSITORY = "https://github.com/horsicq/XPEID.git"
SIGNATURES_REPOSITORY = "https://github.com/horsicq/signatures.git"

YARA_RULE_RE = re.compile(
    rb"(?m)^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+"
)
PEID_SECTION_RE = re.compile(
    rb"(?m)^[ \t]*\[[^\r\n]+\][ \t]*\r?$"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(
    command: list[str], *, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        check=check,
        capture_output=True,
    )


def git(root: pathlib.Path, *arguments: str) -> bytes:
    process = run(
        [
            "git",
            "-c",
            "safe.directory=*",
            "-C",
            str(root),
            *arguments,
        ]
    )
    if process.stderr:
        raise ValueError(
            f"git wrote stderr for {root}: "
            + process.stderr.decode("utf-8", errors="replace")
        )
    return process.stdout


def normalize_repository(value: str) -> str:
    normalized = value.strip().rstrip("/").casefold()
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized


def validate_checkout(
    root: pathlib.Path, *, commit: str, repository: str
) -> None:
    if not root.is_dir():
        raise ValueError(f"checkout is missing: {root}")
    actual_commit = git(root, "rev-parse", "HEAD").decode().strip()
    if actual_commit != commit:
        raise ValueError(
            f"checkout commit mismatch: {actual_commit} != {commit}"
        )
    status = git(root, "status", "--porcelain=v1")
    if status:
        raise ValueError(f"checkout is dirty: {root}")
    actual_repository = git(
        root, "remote", "get-url", "origin"
    ).decode().strip()
    if normalize_repository(actual_repository) != normalize_repository(
        repository
    ):
        raise ValueError(
            f"checkout repository mismatch: {actual_repository}"
        )


def tracked_paths(
    root: pathlib.Path, prefix: str, *, suffix: str | None = None
) -> list[pathlib.Path]:
    output = git(root, "ls-files", "-z", "--", prefix)
    values = [
        pathlib.Path(value.decode("utf-8"))
        for value in output.split(b"\0")
        if value
    ]
    if suffix is not None:
        values = [
            path for path in values if path.suffix.casefold() == suffix
        ]
    return sorted(values, key=lambda path: path.as_posix())


def history_record(root: pathlib.Path, path: pathlib.Path) -> dict[str, Any]:
    output = git(
        root,
        "log",
        "--follow",
        "--format=%H%x09%cI",
        "--reverse",
        "--",
        path.as_posix(),
    ).decode("utf-8")
    entries = []
    for line in output.splitlines():
        if not line:
            continue
        commit, committed_at = line.split("\t", 1)
        entries.append(
            {"commit": commit, "committed_at": committed_at}
        )
    if not entries:
        raise ValueError(f"no git history for {path.as_posix()}")
    return {
        "first": entries[0],
        "last": entries[-1],
        "commit_count": len(entries),
    }


def visible_markers(path: pathlib.Path, data: bytes) -> list[str]:
    text = data.decode("utf-8", errors="replace")
    lowered = text.casefold()
    markers: list[str] = []
    if "gnu-gplv2 license" in lowered:
        markers.append("explicit-gpl-v2")
    if "please retain the copyright information" in lowered:
        markers.append("retain-copyright-request")
    if re.search(r"(?im)^[ \t]*(?://|/\*|\*)?[ \t]*author(?:s)?\s*[:=]", text):
        markers.append("author-metadata")
    if "yara rules generated with ./peid2yara.py" in lowered:
        markers.append("peid2yara-generated")
    if "raw.githubusercontent.com" in lowered and path.suffix == ".yar":
        markers.append("upstream-database-urls")
    if data.startswith(b"; PEiD signature database - "):
        markers.append("peid-category-header")
    if re.search(rb"(?i)[a-z]:\\tmp_build\\", data):
        markers.append("absolute-local-build-path")
    return sorted(markers)


def first_nonempty_line(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        value = line.strip()
        if value:
            return value[:240]
    return ""


def newline_style(data: bytes) -> str:
    crlf_count = data.count(b"\r\n")
    lf_count = data.count(b"\n")
    bare_lf_count = lf_count - crlf_count
    if crlf_count and bare_lf_count:
        return "mixed"
    if crlf_count:
        return "crlf"
    if bare_lf_count:
        return "lf"
    return "none"


def file_record(
    root: pathlib.Path,
    path: pathlib.Path,
    *,
    base: pathlib.Path,
    include_history: bool,
) -> dict[str, Any]:
    full_path = root / path
    data = full_path.read_bytes()
    relative = path.relative_to(base)
    record: dict[str, Any] = {
        "path": relative.as_posix(),
        "bytes": len(data),
        "sha256": sha256(data),
        "first_nonempty_line": first_nonempty_line(data),
        "visible_markers": visible_markers(path, data),
        "line_count": len(data.splitlines()),
        "newline_style": newline_style(data),
        "yara_rule_count": len(YARA_RULE_RE.findall(data)),
        "peid_section_count": len(PEID_SECTION_RE.findall(data)),
    }
    if include_history:
        record["history"] = history_record(root, path)
    return record


def tree_sha256(records: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for record in records:
        digest.update(record["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(record["bytes"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(record["sha256"].encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def inventory(
    *,
    name: str,
    repository: str,
    commit: str,
    root: pathlib.Path,
    base: pathlib.Path,
    paths: list[pathlib.Path],
    include_history: bool,
) -> dict[str, Any]:
    records = [
        file_record(
            root,
            path,
            base=base,
            include_history=include_history,
        )
        for path in paths
    ]
    return {
        "name": name,
        "repository": repository,
        "commit": commit,
        "source_path": base.as_posix(),
        "file_count": len(records),
        "byte_count": sum(record["bytes"] for record in records),
        "tree_sha256": tree_sha256(records),
        "yara_rule_count": sum(
            record["yara_rule_count"] for record in records
        ),
        "peid_section_count": sum(
            record["peid_section_count"] for record in records
        ),
        "files": records,
    }


def compare_inventories(
    left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    left_files = {record["path"]: record for record in left["files"]}
    right_files = {record["path"]: record for record in right["files"]}
    common = sorted(left_files.keys() & right_files.keys())
    exact = [
        path
        for path in common
        if left_files[path]["sha256"] == right_files[path]["sha256"]
    ]
    return {
        "left": left["name"],
        "right": right["name"],
        "common_path_count": len(common),
        "byte_exact_count": len(exact),
        "byte_exact_paths": exact,
        "modified_common_paths": [
            path for path in common if path not in exact
        ],
        "left_only_paths": sorted(left_files.keys() - right_files.keys()),
        "right_only_paths": sorted(right_files.keys() - left_files.keys()),
    }


def license_record(root: pathlib.Path) -> dict[str, Any]:
    data = (root / "LICENSE").read_bytes()
    return {
        "path": "LICENSE",
        "bytes": len(data),
        "sha256": sha256(data),
        "first_nonempty_line": first_nonempty_line(data),
    }


def source_evidence(
    source_root: pathlib.Path, build_root: pathlib.Path
) -> dict[str, Any]:
    paths = {
        "console_main": source_root / "src/console/main_console.cpp",
        "console_cmake": source_root / "src/console/CMakeLists.txt",
        "console_link": (
            build_root / "src/console/CMakeFiles/diec.dir/link.txt"
        ),
        "gui_cmake": source_root / "src/gui/CMakeLists.txt",
        "gui_qmake_sources": source_root / "gui_source/gui_source_tr.pro",
        "scan_console": source_root / "XScanEngine/xscanengineconsole.cpp",
        "signature_options": (
            source_root
            / "FormatWidgets/SearchSignatures/"
            "searchsignaturesoptionswidget.cpp"
        ),
        "signature_cmake": (
            source_root
            / "FormatWidgets/SearchSignatures/"
            "searchsignatureswidget.cmake"
        ),
        "xpeid_cmake": source_root / "XPEID/xpeid.cmake",
        "portable_packaging": (
            source_root / "build_linux_portable.sh"
        ),
        "generic_install": source_root / "install.sh",
        "appimage_packaging": source_root / "create_appimage.sh",
    }
    data = {
        name: path.read_bytes() for name, path in paths.items()
    }
    text = {
        name: value.decode("utf-8", errors="replace")
        for name, value in data.items()
    }
    forbidden_cli_tokens = (
        "XYara",
        "XPEID",
        "FormatWidgets",
        "yara_rules",
        "peid_rules",
        "crypto.db",
        "$data/yara",
        "$data/peid",
        "$data/signatures",
    )
    cli_combined = (
        text["console_main"]
        + "\n"
        + text["console_cmake"]
        + "\n"
        + text["console_link"]
    )
    relationships = {
        "console_constructs_die_script": (
            "DiE_Script die_script" in text["console_main"]
        ),
        "console_exposes_only_die_database_paths": all(
            token in text["console_main"]
            for token in (
                "$data/db",
                "$data/db_extra",
                "$data/db_custom",
            )
        ),
        "console_has_no_auxiliary_asset_path": not any(
            token in cli_combined for token in forbidden_cli_tokens
        ),
        "console_link_has_no_auxiliary_engine": not re.search(
            r"(?i)(xyara|xpeid|formatwidgets|libyara|signatures)",
            text["console_link"],
        ),
        "gui_cmake_enables_and_links_yara": all(
            token in text["gui_cmake"]
            for token in (
                'option(WITH_YARA "Use Yara" ON)',
                "add_definitions(-DUSE_YARA)",
                "target_link_libraries(${DIE_GUI_TARGET} PRIVATE yara)",
                "../../XYara/yara_rules",
            )
        ),
        "qmake_gui_collects_xyara_and_xpeid": all(
            token in text["gui_qmake_sources"]
            for token in ("../XYara/xyara.cpp", "../XPEID/xpeid.cpp")
        ),
        "alternative_console_has_yara_and_peid_paths": all(
            token in text["scan_console"]
            for token in ("$data/peid", "$data/yara")
        ),
        "signature_widget_defaults_to_signature_path": (
            "$data/signatures" in text["signature_options"]
        ),
        "signature_widget_includes_signature_assets": (
            "signatures/signatures.cmake" in text["signature_cmake"]
        ),
        "xpeid_component_installs_peid_assets": (
            "DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/peid"
            in text["xpeid_cmake"]
        ),
        "portable_package_copies_yara_and_signatures": all(
            token in text["portable_packaging"]
            for token in (
                "XYara/yara_rules/",
                "signatures/crypto.db",
            )
        ),
        "generic_install_copies_all_auxiliary_assets": all(
            token in text["generic_install"]
            for token in (
                "XYara/yara_rules/",
                "XPEID/peid/",
                "signatures/crypto.db",
            )
        ),
        "appimage_copies_all_auxiliary_assets": all(
            token in text["appimage_packaging"]
            for token in (
                "XYara/yara_rules/",
                "XPEID/peid/",
                "signatures/crypto.db",
            )
        ),
    }
    if not all(relationships.values()):
        failed = [
            name for name, value in relationships.items() if not value
        ]
        raise ValueError(
            "asset reachability relationships failed: "
            + ", ".join(failed)
        )
    return {
        "files": {
            name: {
                "path": path.relative_to(source_root).as_posix()
                if path.is_relative_to(source_root)
                else path.relative_to(build_root).as_posix(),
                "sha256": sha256(data[name]),
            }
            for name, path in paths.items()
        },
        "relationships": relationships,
        "current_die_cli_loads": [
            "Detect-It-Easy/db",
            "Detect-It-Easy/db_extra",
            "Detect-It-Easy/db_custom",
        ],
        "current_die_cli_does_not_load": [
            "Detect-It-Easy/yara_rules",
            "Detect-It-Easy/peid_rules",
            "XYara/yara_rules",
            "XPEID/peid",
            "signatures/*.db",
        ],
    }


def build_inside_report(
    *,
    source_root: pathlib.Path,
    build_root: pathlib.Path,
    repo_root: pathlib.Path,
    lock_path: pathlib.Path,
    xyara_root: pathlib.Path,
    xpeid_root: pathlib.Path,
    signatures_root: pathlib.Path,
) -> dict[str, Any]:
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    expected = {
        "Detect-It-Easy": DETECT_COMMIT,
        "XYara": XYARA_COMMIT,
        "XPEID": XPEID_COMMIT,
        "signatures": SIGNATURES_COMMIT,
    }
    if lock["baseline"]["commit"] != UPSTREAM_COMMIT:
        raise ValueError("component lock baseline mismatch")
    for name, commit in expected.items():
        if lock["gitlink"][name]["commit"] != commit:
            raise ValueError(f"component lock mismatch: {name}")
        actual = git(source_root / name, "rev-parse", "HEAD").decode().strip()
        if actual != commit:
            raise ValueError(f"source image commit mismatch: {name}")

    detect_root = source_root / "Detect-It-Easy"
    release_yara_paths = tracked_paths(
        detect_root, "yara_rules", suffix=".yar"
    )
    release_peid_paths = tracked_paths(detect_root, "peid_rules")
    component_yara_paths = tracked_paths(xyara_root, "yara_rules")
    component_peid_paths = tracked_paths(xpeid_root, "peid")
    signature_paths = tracked_paths(
        signatures_root, ".", suffix=".db"
    )

    release_yara = inventory(
        name="detect-release-yara",
        repository=lock["gitlink"]["Detect-It-Easy"]["repository"],
        commit=DETECT_COMMIT,
        root=detect_root,
        base=pathlib.Path("yara_rules"),
        paths=release_yara_paths,
        include_history=False,
    )
    release_peid = inventory(
        name="detect-release-peid",
        repository=lock["gitlink"]["Detect-It-Easy"]["repository"],
        commit=DETECT_COMMIT,
        root=detect_root,
        base=pathlib.Path("peid_rules"),
        paths=release_peid_paths,
        include_history=False,
    )
    component_yara = inventory(
        name="xyara-component-yara",
        repository=XYARA_REPOSITORY,
        commit=XYARA_COMMIT,
        root=xyara_root,
        base=pathlib.Path("yara_rules"),
        paths=component_yara_paths,
        include_history=True,
    )
    component_peid = inventory(
        name="xpeid-component-peid",
        repository=XPEID_REPOSITORY,
        commit=XPEID_COMMIT,
        root=xpeid_root,
        base=pathlib.Path("peid"),
        paths=component_peid_paths,
        include_history=True,
    )
    signatures = inventory(
        name="signatures-component-data",
        repository=SIGNATURES_REPOSITORY,
        commit=SIGNATURES_COMMIT,
        root=signatures_root,
        base=pathlib.Path("."),
        paths=signature_paths,
        include_history=True,
    )
    inventories = [
        release_yara,
        release_peid,
        component_yara,
        component_peid,
        signatures,
    ]

    local_detect = repo_root / "upstream/Detect-It-Easy"
    local_release_yara = inventory(
        name="local-detect-release-yara",
        repository="local-subtree",
        commit=DETECT_COMMIT,
        root=local_detect,
        base=pathlib.Path("yara_rules"),
        paths=[
            path.relative_to(local_detect)
            for path in sorted(
                (local_detect / "yara_rules").glob("*.yar")
            )
        ],
        include_history=False,
    )
    local_release_peid = inventory(
        name="local-detect-release-peid",
        repository="local-subtree",
        commit=DETECT_COMMIT,
        root=local_detect,
        base=pathlib.Path("peid_rules"),
        paths=[
            path.relative_to(local_detect)
            for path in sorted(
                path
                for path in (local_detect / "peid_rules").rglob("*")
                if path.is_file()
            )
        ],
        include_history=False,
    )

    root_licenses = {
        "Detect-It-Easy": license_record(detect_root),
        "XYara": license_record(xyara_root),
        "XPEID": license_record(xpeid_root),
        "signatures": license_record(signatures_root),
    }
    relationships = {
        "all_component_commits_match_lock_and_image": True,
        "local_release_yara_matches_fixed_image": (
            local_release_yara["tree_sha256"]
            == release_yara["tree_sha256"]
        ),
        "local_release_peid_matches_fixed_image": (
            local_release_peid["tree_sha256"]
            == release_peid["tree_sha256"]
        ),
        "all_root_license_candidates_identify_mit": all(
            record["first_nonempty_line"] == "MIT License"
            for record in root_licenses.values()
        ),
        "release_and_component_yara_are_not_byte_mirrors": (
            release_yara["tree_sha256"] != component_yara["tree_sha256"]
        ),
        "release_and_component_peid_are_not_byte_mirrors": (
            release_peid["tree_sha256"] != component_peid["tree_sha256"]
        ),
        "root_and_structured_crypto_databases_are_identical": (
            {
                record["path"]: record["sha256"]
                for record in signatures["files"]
            }["crypto.db"]
            == {
                record["path"]: record["sha256"]
                for record in signatures["files"]
            }["signatures/generic/crypto.db"]
        ),
        "legacy_and_structured_junk_databases_are_distinct": (
            {
                record["path"]: record["sha256"]
                for record in signatures["files"]
            }["Junks/x86.db"]
            != {
                record["path"]: record["sha256"]
                for record in signatures["files"]
            }["signatures/x86/junks.db"]
        ),
    }
    if not all(relationships.values()):
        raise ValueError("asset inventory relationships failed")

    return {
        "schema_version": 1,
        "generator": "tools/upstream/audit_rule_assets.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "component_lock": {
            "path": "upstream/components.lock.toml",
            "sha256": sha256(lock_bytes),
        },
        "asset_sets": inventories,
        "comparisons": {
            "yara_release_vs_component": compare_inventories(
                release_yara, component_yara
            ),
            "peid_release_vs_component": compare_inventories(
                release_peid, component_peid
            ),
        },
        "root_license_evidence": root_licenses,
        "reachability": source_evidence(source_root, build_root),
        "relationships": relationships,
    }


def inspect_image() -> tuple[str, str]:
    process = run(["docker", "image", "inspect", IMAGE])
    document = json.loads(process.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision", ""
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError("asset audit image revision mismatch")
    return document["Id"], revision


def run_in_fixed_image(
    repo: pathlib.Path,
    xyara_root: pathlib.Path,
    xpeid_root: pathlib.Path,
    signatures_root: pathlib.Path,
) -> dict[str, Any]:
    validate_checkout(
        xyara_root,
        commit=XYARA_COMMIT,
        repository=XYARA_REPOSITORY,
    )
    validate_checkout(
        xpeid_root,
        commit=XPEID_COMMIT,
        repository=XPEID_REPOSITORY,
    )
    validate_checkout(
        signatures_root,
        commit=SIGNATURES_COMMIT,
        repository=SIGNATURES_REPOSITORY,
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
            f"type=bind,source={xyara_root},target=/assets/xyara,readonly",
            "--mount",
            f"type=bind,source={xpeid_root},target=/assets/xpeid,readonly",
            "--mount",
            (
                f"type=bind,source={signatures_root},"
                "target=/assets/signatures,readonly"
            ),
            "--entrypoint",
            "/usr/bin/python3",
            IMAGE,
            "/repo/tools/upstream/audit_rule_assets.py",
            "--inside",
            "--source-root",
            "/opt/die-source",
            "--build-root",
            "/opt/die-build",
            "--repo-root",
            "/repo",
            "--lock",
            "/repo/upstream/components.lock.toml",
            "--xyara-root",
            "/assets/xyara",
            "--xpeid-root",
            "/assets/xpeid",
            "--signatures-root",
            "/assets/signatures",
        ],
        check=False,
    )
    if process.returncode != 0:
        raise ValueError(
            "inside asset audit failed:\n"
            + process.stderr.decode("utf-8", errors="replace")
        )
    if process.stderr:
        raise ValueError(
            "inside asset audit wrote stderr:\n"
            + process.stderr.decode("utf-8", errors="replace")
        )
    report = json.loads(process.stdout)
    report["source_image"] = {
        "image": IMAGE,
        "image_id": image_id,
        "revision": revision,
        "network": "none",
        "repository_mount": "readonly",
        "asset_mounts": "readonly",
        "cpu_limit": 2,
        "memory_limit": "2g",
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--source-root", type=pathlib.Path)
    parser.add_argument("--build-root", type=pathlib.Path)
    parser.add_argument("--repo-root", type=pathlib.Path)
    parser.add_argument("--lock", type=pathlib.Path)
    parser.add_argument("--xyara-root", type=pathlib.Path)
    parser.add_argument("--xpeid-root", type=pathlib.Path)
    parser.add_argument("--signatures-root", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.inside:
        required = (
            args.source_root,
            args.build_root,
            args.repo_root,
            args.lock,
            args.xyara_root,
            args.xpeid_root,
            args.signatures_root,
        )
        if any(value is None for value in required):
            parser.error("inside mode requires all source arguments")
        report = build_inside_report(
            source_root=args.source_root,
            build_root=args.build_root,
            repo_root=args.repo_root,
            lock_path=args.lock,
            xyara_root=args.xyara_root,
            xpeid_root=args.xpeid_root,
            signatures_root=args.signatures_root,
        )
    else:
        required = (
            args.output,
            args.xyara_root,
            args.xpeid_root,
            args.signatures_root,
        )
        if any(value is None for value in required):
            parser.error(
                "host mode requires --output and all asset roots"
            )
        repo = pathlib.Path(__file__).resolve().parents[2]
        report = run_in_fixed_image(
            repo,
            args.xyara_root.resolve(),
            args.xpeid_root.resolve(),
            args.signatures_root.resolve(),
        )

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

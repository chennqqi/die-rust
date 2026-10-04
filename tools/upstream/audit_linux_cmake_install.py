#!/usr/bin/env python3
"""Audit the fixed Linux Qt5 CMake install staging tree."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
BASE_IMAGE = "die-rust/upstream-oracle-cmake:74eaf505"
BASE_IMAGE_ID = (
    "sha256:466102628c3a94b7ab1048f0c24261b"
    "1920e61a40029b128763cf79370255040"
)
FULL_IMAGE = "die-rust/upstream-install-qt5:74eaf505"
INSIDE_SCRIPT = "/opt/die-install/audit_linux_cmake_install.py"
DOCKERFILE = "tools/upstream/Dockerfile.upstream-install-qt5"
SOURCE_ROOT = Path("/opt/die-source")
BUILD_ROOT = Path("/opt/die-build")
INSTALL_PREFIX = "/usr"
LICENSE_NAMES = ("license", "copying", "notice", "copyright")
EXPECTED_BINARIES = {
    "usr/bin/die",
    "usr/bin/diec",
    "usr/bin/diel",
}
EXPECTED_CLI_SHA256 = (
    "da1fab49f7ba5970d1fc1c7fe3d4f380c"
    "f5e8775dd8097207e7b3c30f08236cf"
)
EXPECTED_RUNTIME_RULES = {
    "bytes": 2_909_316,
    "combined_tree_sha256": (
        "20f2b74effc2bdaf069e3b2e13060432b"
        "8890d38364511f5cde56a337348bfda"
    ),
    "file_count": 2_268,
}
PRIOR_REPORTS = {
    "product_source_closure":
        "docs/research/data/product-source-closure-linux-qt5.json",
    "rule_assets": "docs/research/data/rule-assets.json",
    "runtime_rule_assets":
        "docs/research/data/runtime-rule-assets-license.json",
}


class AuditError(ValueError):
    """The install-tree evidence is incomplete or ambiguous."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def serialize(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def git_head(root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    if completed.stderr:
        raise AuditError("git rev-parse emitted stderr")
    return completed.stdout.strip()


def iter_regular_files(root: Path) -> list[Path]:
    result = []
    for directory, names, files in os.walk(root):
        names[:] = sorted(name for name in names if name != ".git")
        for name in sorted(files):
            path = Path(directory) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if stat.S_ISREG(metadata.st_mode):
                result.append(path)
    return result


def candidate_index(
    root: Path,
    required_sizes: set[int],
) -> dict[tuple[int, str], list[str]]:
    result: dict[tuple[int, str], list[str]] = collections.defaultdict(list)
    for path in iter_regular_files(root):
        size = path.stat().st_size
        if size not in required_sizes:
            continue
        key = (size, file_sha256(path))
        result[key].append(path.relative_to(root).as_posix())
    for paths in result.values():
        paths.sort(key=lambda value: value.encode("utf-8"))
    return result


def route(path: str) -> str:
    parts = PurePosixPath(path).parts
    if len(parts) >= 3 and parts[:2] == ("usr", "lib"):
        return "/".join(parts[:3])
    if len(parts) >= 3 and parts[:2] == ("usr", "share"):
        return "/".join(parts[:3])
    if len(parts) >= 2:
        return "/".join(parts[:2])
    return parts[0]


def tree_sha256(records: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for record in records:
        digest.update(record["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(record["bytes"].to_bytes(8, "big"))
        digest.update(bytes.fromhex(record["sha256"]))
        digest.update(record["mode"].to_bytes(4, "big"))
    return digest.hexdigest()


def content_tree_sha256(root: Path, files: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(relative)
        digest.update(b"\0")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        digest.update(bytes.fromhex(sha256(data)))
    return digest.hexdigest()


def subtree_identity(
    records: list[dict[str, Any]],
    prefix: str,
) -> dict[str, Any]:
    selected = []
    marker = prefix.rstrip("/") + "/"
    for record in records:
        if not record["path"].startswith(marker):
            continue
        relative = record["path"].removeprefix(marker)
        selected.append(
            {
                "path": relative,
                "bytes": record["bytes"],
                "sha256": record["sha256"],
                "mode": record["mode"],
            }
        )
    selected.sort(key=lambda item: item["path"].encode("utf-8"))
    return {
        "prefix": prefix,
        "file_count": len(selected),
        "bytes": sum(item["bytes"] for item in selected),
        "tree_sha256": tree_sha256(selected),
    }


def bounded_list(values: list[Any], limit: int = 20) -> dict[str, Any]:
    return {
        "count": len(values),
        "entries_sha256": sha256(canonical_json(values)),
        "sample": values[:limit],
        "sample_truncated": len(values) > limit,
    }


def inspect_install_components() -> dict[str, Any]:
    scripts = sorted(
        BUILD_ROOT.rglob("cmake_install.cmake"),
        key=lambda path: path.relative_to(BUILD_ROOT)
        .as_posix()
        .encode("utf-8"),
    )
    if not scripts:
        raise AuditError("no generated CMake install scripts")
    components = set()
    records = []
    pattern = re.compile(
        r'CMAKE_INSTALL_COMPONENT STREQUAL "([^"]+)"'
    )
    for path in scripts:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
        components.update(pattern.findall(text))
        records.append(
            {
                "path": path.relative_to(BUILD_ROOT).as_posix(),
                "bytes": len(raw),
                "sha256": sha256(raw),
            }
        )
    if not components:
        raise AuditError("generated install component set is empty")
    return {
        "script_count": len(records),
        "scripts_sha256": sha256(canonical_json(records)),
        "components": sorted(
            components, key=lambda value: value.encode("utf-8")
        ),
    }


def inspect_stage(stage: Path) -> dict[str, Any]:
    paths = []
    symlinks = []
    for path in sorted(
        stage.rglob("*"),
        key=lambda item: item.relative_to(stage).as_posix().encode("utf-8"),
    ):
        relative = path.relative_to(stage).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            symlinks.append(
                {
                    "path": relative,
                    "target": os.readlink(path),
                }
            )
        elif stat.S_ISREG(metadata.st_mode):
            paths.append(path)
    required_sizes = {path.stat().st_size for path in paths}
    source_index = candidate_index(SOURCE_ROOT, required_sizes)
    build_index = candidate_index(BUILD_ROOT, required_sizes)

    records = []
    unmatched = []
    for path in paths:
        relative = path.relative_to(stage).as_posix()
        metadata = path.stat()
        digest = file_sha256(path)
        key = (metadata.st_size, digest)
        source_candidates = source_index.get(key, [])
        build_candidates = build_index.get(key, [])
        candidates = source_candidates or build_candidates
        origin_kind = (
            "source"
            if source_candidates
            else "build"
            if build_candidates
            else "unmatched"
        )
        if not candidates:
            unmatched.append(relative)
        records.append(
            {
                "path": relative,
                "bytes": metadata.st_size,
                "sha256": digest,
                "mode": stat.S_IMODE(metadata.st_mode),
                "route": route(relative),
                "origin": {
                    "kind": origin_kind,
                    "candidate_count": len(candidates),
                    "candidates_sha256": sha256(canonical_json(candidates)),
                    "candidate_paths": candidates[:20],
                    "candidate_paths_truncated": len(candidates) > 20,
                },
            }
        )

    groups: dict[str, dict[str, Any]] = {}
    origin_groups: dict[str, dict[str, int]] = {}
    for record in records:
        item = groups.setdefault(
            record["route"],
            {"file_count": 0, "bytes": 0},
        )
        item["file_count"] += 1
        item["bytes"] += record["bytes"]
        origin = origin_groups.setdefault(
            record["origin"]["kind"],
            {"file_count": 0, "bytes": 0},
        )
        origin["file_count"] += 1
        origin["bytes"] += record["bytes"]
    by_hash: dict[tuple[int, str], list[str]] = collections.defaultdict(list)
    for record in records:
        by_hash[(record["bytes"], record["sha256"])].append(record["path"])
    duplicate_groups = [
        {
            "bytes_each": size,
            "sha256": digest,
            "path_count": len(duplicate_paths),
            "paths": sorted(
                duplicate_paths, key=lambda value: value.encode("utf-8")
            ),
        }
        for (size, digest), duplicate_paths in sorted(by_hash.items())
        if len(duplicate_paths) > 1
    ]
    duplicate_groups.sort(
        key=lambda item: (
            -(item["bytes_each"] * (item["path_count"] - 1)),
            item["sha256"],
        )
    )
    license_paths = [
        record["path"]
        for record in records
        if PurePosixPath(record["path"]).name.lower().startswith(
            LICENSE_NAMES
        )
    ]
    mirror_pairs = []
    for name in ("db", "info", "yara_rules"):
        detect = subtree_identity(
            records, f"usr/lib/DetectItEasy/{name}"
        )
        die = subtree_identity(records, f"usr/lib/die/{name}")
        mirror_pairs.append(
            {
                "name": name,
                "detect_it_easy": detect,
                "die": die,
                "identical": (
                    detect["file_count"] == die["file_count"]
                    and detect["bytes"] == die["bytes"]
                    and detect["tree_sha256"] == die["tree_sha256"]
                ),
            }
        )
    detect_root = stage / "usr/lib/DetectItEasy"
    runtime_files = []
    runtime_trees = []
    for name in ("db", "db_extra", "db_custom"):
        tree_root = detect_root / name
        selected = sorted(
            (
                path
                for path in tree_root.rglob("*")
                if path.is_file() and not path.is_symlink()
            ),
            key=lambda path: path.relative_to(detect_root)
            .as_posix()
            .encode("utf-8"),
        )
        runtime_files.extend(selected)
        runtime_trees.append(
            {
                "path": name,
                "file_count": len(selected),
                "bytes": sum(path.stat().st_size for path in selected),
                "tree_sha256": content_tree_sha256(
                    detect_root, selected
                ),
            }
        )
    return {
        "file_count": len(records),
        "bytes": sum(record["bytes"] for record in records),
        "tree_sha256": tree_sha256(records),
        "records_sha256": sha256(canonical_json(records)),
        "symlinks": bounded_list(symlinks),
        "route_summary": [
            {"route": name, **values}
            for name, values in sorted(groups.items())
        ],
        "origin_summary": [
            {"kind": name, **values}
            for name, values in sorted(origin_groups.items())
        ],
        "usr_bin_paths": [
            record["path"]
            for record in records
            if record["path"].startswith("usr/bin/")
        ],
        "license_candidate_paths": license_paths,
        "unmatched_origins": bounded_list(unmatched),
        "duplicate_content": {
            "group_count": len(duplicate_groups),
            "path_count": sum(
                item["path_count"] for item in duplicate_groups
            ),
            "redundant_bytes": sum(
                item["bytes_each"] * (item["path_count"] - 1)
                for item in duplicate_groups
            ),
            "groups_sha256": sha256(canonical_json(duplicate_groups)),
            "largest_groups": duplicate_groups[:20],
            "largest_groups_truncated": len(duplicate_groups) > 20,
        },
        "mirrored_subtrees": mirror_pairs,
        "runtime_rules": {
            "file_count": len(runtime_files),
            "bytes": sum(path.stat().st_size for path in runtime_files),
            "combined_tree_sha256": content_tree_sha256(
                detect_root, runtime_files
            ),
            "trees": runtime_trees,
        },
        "_records": records,
    }


def inside_report() -> dict[str, Any]:
    if git_head(SOURCE_ROOT) != UPSTREAM_COMMIT:
        raise AuditError("source commit mismatch")
    for path in (
        BUILD_ROOT / "src/gui/die",
        BUILD_ROOT / "src/console/diec",
        BUILD_ROOT / "src/lite/diel",
    ):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise AuditError(f"missing built executable: {path}")
    with tempfile.TemporaryDirectory(prefix="die-install-") as directory:
        stage = Path(directory)
        environment = dict(os.environ)
        environment["DESTDIR"] = str(stage)
        completed = subprocess.run(
            [
                "cmake",
                "--install",
                str(BUILD_ROOT),
                "--prefix",
                INSTALL_PREFIX,
                "--config",
                "Release",
            ],
            env=environment,
            capture_output=True,
        )
        if completed.returncode != 0:
            raise AuditError(
                "full CMake install failed: "
                + completed.stderr.decode("utf-8", errors="replace")
            )
        if completed.stderr:
            raise AuditError("full CMake install emitted stderr")
        inventory = inspect_stage(stage)
        manifest_path = BUILD_ROOT / "install_manifest.txt"
        manifest_entries = manifest_path.read_text(
            encoding="utf-8"
        ).splitlines()
        if not manifest_entries or any(
            not entry.startswith(f"{INSTALL_PREFIX}/")
            for entry in manifest_entries
        ):
            raise AuditError("install manifest path scope drift")
        normalized_manifest = [
            entry.removeprefix("/") for entry in manifest_entries
        ]
        manifest_counts = collections.Counter(normalized_manifest)
        manifest_unique = sorted(
            manifest_counts, key=lambda value: value.encode("utf-8")
        )
        installed_paths = [
            record["path"] for record in inventory["_records"]
        ]
        if set(manifest_unique) != set(installed_paths):
            raise AuditError("install manifest and staging tree differ")
        manifest_duplicates = [
            {"path": path, "entry_count": count}
            for path, count in sorted(manifest_counts.items())
            if count > 1
        ]
        normalized_stdout = completed.stdout.replace(
            str(stage).encode("utf-8"), b"<DESTDIR>"
        )
    records = inventory.pop("_records")
    binaries = {
        record["path"]: record
        for record in records
        if record["path"] in EXPECTED_BINARIES
    }
    manifest_duplicates.sort(
        key=lambda item: (-item["entry_count"], item["path"])
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "upstream_commit": UPSTREAM_COMMIT,
        "install": {
            "configuration": "Release",
            "prefix": INSTALL_PREFIX,
            "destdir_is_ephemeral": True,
            "components": inspect_install_components(),
            "stdout_bytes": len(normalized_stdout),
            "stdout_sha256": sha256(normalized_stdout),
            "stdout_paths_normalized": True,
            "stderr_bytes": len(completed.stderr),
            "manifest": {
                "entry_count": len(normalized_manifest),
                "unique_path_count": len(manifest_unique),
                "duplicate_entry_count": (
                    len(normalized_manifest) - len(manifest_unique)
                ),
                "duplicate_path_count": len(manifest_duplicates),
                "duplicate_paths_sha256": sha256(
                    canonical_json(manifest_duplicates)
                ),
                "highest_multiplicity_paths": manifest_duplicates[:20],
                "highest_multiplicity_paths_truncated": (
                    len(manifest_duplicates) > 20
                ),
                "normalized_entries_sha256": sha256(
                    canonical_json(normalized_manifest)
                ),
                "unique_paths_sha256": sha256(
                    canonical_json(manifest_unique)
                ),
            },
        },
        "binaries": binaries,
        "inventory": inventory,
    }


def inspect_image(image: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        capture_output=True,
    )
    values = json.loads(completed.stdout)
    if not isinstance(values, list) or len(values) != 1:
        raise AuditError("unexpected image inspect result")
    value = values[0]
    revision = value.get("Config", {}).get("Labels", {}).get(
        "org.opencontainers.image.revision"
    )
    if revision != UPSTREAM_COMMIT:
        raise AuditError(f"image revision mismatch: {image}")
    return {
        "image": image,
        "id": value["Id"],
        "revision": revision,
        "repo_digests": sorted(value.get("RepoDigests") or []),
    }


def base_install_failure() -> dict[str, Any]:
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            "/bin/sh",
            BASE_IMAGE,
            "-c",
            (
                "set -u; rm -rf /tmp/die-stage; "
                "DESTDIR=/tmp/die-stage cmake --install /opt/die-build "
                "--prefix /usr --config Release >/dev/null; "
                "code=$?; "
                "find /tmp/die-stage -type f -printf '%s\\n' | "
                "awk '{count += 1; bytes += $1} "
                "END {printf \"%d %d\\n\", count, bytes}'; "
                "exit $code"
            ),
        ],
        capture_output=True,
        timeout=180,
    )
    stderr = completed.stderr.decode("utf-8", errors="strict")
    if (
        completed.returncode == 0
        or 'cannot find "/opt/die-build/src/gui/die"' not in stderr
    ):
        raise AuditError("CLI-only base image install failure drift")
    try:
        partial_file_count, partial_bytes = (
            int(value) for value in completed.stdout.split()
        )
    except (TypeError, ValueError) as error:
        raise AuditError("invalid partial install summary") from error
    if partial_file_count <= 0 or partial_bytes <= 0:
        raise AuditError("base install did not leave a partial tree")
    return {
        "return_code": completed.returncode,
        "stdout_bytes": len(completed.stdout),
        "stderr_bytes": len(completed.stderr),
        "stderr_sha256": sha256(completed.stderr),
        "missing_path": "src/gui/die",
        "partial_tree": {
            "file_count": partial_file_count,
            "bytes": partial_bytes,
        },
        "copied_partial_tree_before_failure": True,
    }


def host_report(repo: Path) -> dict[str, Any]:
    base = inspect_image(BASE_IMAGE)
    if base["id"] != BASE_IMAGE_ID:
        raise AuditError("base image ID mismatch")
    full = inspect_image(FULL_IMAGE)
    image_script = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            "/bin/cat",
            FULL_IMAGE,
            INSIDE_SCRIPT,
        ],
        check=True,
        capture_output=True,
    ).stdout
    local_script = Path(__file__).read_bytes()
    dockerfile = (repo / DOCKERFILE).read_bytes()
    if image_script != local_script:
        raise AuditError("image audit script differs from repository")
    completed = subprocess.run(
        ["docker", "run", "--rm", "--network=none", FULL_IMAGE],
        check=True,
        capture_output=True,
        timeout=300,
    )
    if completed.stderr:
        raise AuditError("full install audit emitted stderr")
    inside = json.loads(completed.stdout)
    inventory = inside["inventory"]
    installed_bin_paths = set(inventory["usr_bin_paths"])
    base_failure = base_install_failure()
    prior_reports = {}
    prior_valid = True
    for name, relative in PRIOR_REPORTS.items():
        raw = (repo / relative).read_bytes()
        report = json.loads(raw)
        relationships = report.get("relationships")
        if relationships is not None and not all(relationships.values()):
            prior_valid = False
        prior_reports[name] = {
            "path": relative,
            "sha256": sha256(raw),
        }
    relationships = {
        "cli_base_install_copies_partial_tree_then_fails_on_missing_gui": (
            base_failure["return_code"] != 0
            and base_failure["missing_path"] == "src/gui/die"
            and base_failure["copied_partial_tree_before_failure"]
        ),
        "full_image_install_succeeds_without_stderr": (
            inside["install"]["stderr_bytes"] == 0
        ),
        "generated_install_has_only_unspecified_component": (
            inside["install"]["components"]["components"]
            == ["Unspecified"]
        ),
        "install_manifest_unique_paths_equal_staging_tree": (
            inside["install"]["manifest"]["unique_path_count"]
            == inventory["file_count"]
        ),
        "usr_bin_contains_exactly_three_product_binaries": (
            set(inside["binaries"]) == EXPECTED_BINARIES
            and installed_bin_paths == EXPECTED_BINARIES
            and all(
                record["mode"] & 0o111
                for record in inside["binaries"].values()
            )
        ),
        "installed_cli_matches_fixed_product_binary": (
            inside["binaries"]["usr/bin/diec"]["sha256"]
            == EXPECTED_CLI_SHA256
        ),
        "install_tree_has_no_symlinks": inventory["symlinks"]["count"] == 0,
        "every_installed_file_has_source_or_build_origin": (
            inventory["unmatched_origins"]["count"] == 0
        ),
        "db_info_and_yara_are_duplicated_between_two_prefixes": all(
            item["identical"] and item["detect_it_easy"]["file_count"] > 0
            for item in inventory["mirrored_subtrees"]
        ),
        "only_one_license_candidate_is_installed": (
            inventory["license_candidate_paths"]
            == [
                "usr/share/doc/DetectItEasy/detect-it-easy/LICENSE"
            ]
        ),
        "installed_runtime_rules_match_prior_identity": (
            all(
                inventory["runtime_rules"][field] == expected
                for field, expected in EXPECTED_RUNTIME_RULES.items()
            )
        ),
        "prior_asset_and_source_reports_are_valid": prior_valid,
    }
    if not all(relationships.values()):
        failed = sorted(
            name for name, value in relationships.items() if not value
        )
        raise AuditError(f"install relationships failed: {failed}")
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": "tools/upstream/audit_linux_cmake_install.py",
        "generator_sha256": sha256(local_script),
        "upstream_commit": UPSTREAM_COMMIT,
        "environment": {
            "network": "none",
            "base_image": base,
            "full_image": full,
            "inside_script": {
                "image_path": INSIDE_SCRIPT,
                "image_sha256": sha256(image_script),
                "repository_sha256": sha256(local_script),
            },
            "dockerfile": {
                "path": DOCKERFILE,
                "sha256": sha256(dockerfile),
            },
        },
        "cli_only_install_attempt": base_failure,
        "full_install": inside,
        "prior_reports": prior_reports,
        "relationships": relationships,
        "scope": {
            "platform": "Linux x86_64",
            "qt": "5",
            "build_system": "CMake",
            "kind": "cmake-install-staging-tree-not-compressed-package",
            "image_rebuild_reproducibility_verified": False,
            "legal_review_complete": False,
            "release_approved": False,
        },
        "limitations": [
            "this is the CMake install staging tree, not an AppImage, DEB, RPM, or archive",
            "system dynamic libraries are not copied into the staging tree",
            "the full default install includes GUI and lite products outside the current Rust deliverable",
            "the GUI binary is bound to the exact full image ID; independent image rebuild reproducibility is not claimed",
            "technical file and origin closure is not legal approval",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = inside_report() if args.inside else host_report(args.repo)
    raw = serialize(report)
    if args.output is None:
        sys.stdout.buffer.write(raw)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

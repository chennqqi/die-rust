#!/usr/bin/env python3
"""Audit fixed Linux portable and pre-linuxdeploy AppImage trees."""

from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any


SCHEMA_VERSION = 1
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
BUILD_TOOLS_COMMIT = "5dd5bcc8abf3b178d9ed47100f6f37ebecceb23e"
BASE_IMAGE = "die-rust/upstream-install-qt5:74eaf505"
BASE_IMAGE_ID = (
    "sha256:6f7a378ea1c5a07745d45083c0e59643"
    "0fefc6526273528366a7dc7e11230368"
)
RELEASE_IMAGE = "die-rust/upstream-release-trees-qt5:74eaf505"
INSIDE_SCRIPT = "/opt/die-release/audit_linux_release_trees.py"
DOCKERFILE = "tools/upstream/Dockerfile.upstream-release-trees-qt5"
SOURCE_ROOT = Path("/opt/die-source")
BUILD_ROOT = Path("/opt/die-build")
APPIMAGE_SCRIPT = SOURCE_ROOT / "create_appimage.sh"
PORTABLE_SCRIPT = SOURCE_ROOT / "build_linux_portable.sh"
LINUX_HELPER = SOURCE_ROOT / "build_tools/linux.sh"
RELEASE_VERSION_PATH = SOURCE_ROOT / "release_version.txt"
QT_LIB_ROOT = Path("/usr/lib/x86_64-linux-gnu")
QT_PLUGIN_ROOT = QT_LIB_ROOT / "qt5/plugins"
QT_LIBS = (
    "libQt5Core",
    "libQt5Gui",
    "libQt5Widgets",
    "libQt5Svg",
    "libQt5Sql",
    "libQt5Network",
    "libQt5OpenGL",
    "libQt5DBus",
    "libQt5XcbQpa",
    "libQt5Script",
    "libQt5ScriptTools",
    "libQt5Concurrent",
    "libQt5PrintSupport",
)
EXPECTED_RUNTIME_RULES = {
    "bytes": 2_909_316,
    "combined_tree_sha256": (
        "20f2b74effc2bdaf069e3b2e13060432b"
        "8890d38364511f5cde56a337348bfda"
    ),
    "file_count": 2_268,
}
PRIOR_REPORT = (
    "docs/research/data/linux-cmake-install-tree.json"
)
LICENSE_NAMES = ("license", "copying", "notice", "copyright")


class AuditError(ValueError):
    """The release-tree replay is incomplete or ambiguous."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def compressed_stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with gzip.open(path, "rb") as stream:
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


def route(path: str) -> str:
    parts = PurePosixPath(path).parts
    if parts[0] == "base" and len(parts) >= 2:
        return "/".join(parts[:2])
    if len(parts) >= 3 and parts[:2] == ("usr", "lib"):
        return "/".join(parts[:3])
    if len(parts) >= 3 and parts[:2] == ("usr", "share"):
        return "/".join(parts[:3])
    if len(parts) >= 2:
        return "/".join(parts[:2])
    return "<root>"


def register_copy(
    source: Path,
    destination: Path,
    root: Path,
    provenance: dict[str, dict[str, str]],
    kind: str,
    origin: str,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination, follow_symlinks=True)
    relative = destination.relative_to(root).as_posix()
    provenance[relative] = {"kind": kind, "path": origin}


def register_tree(
    source: Path,
    destination: Path,
    root: Path,
    provenance: dict[str, dict[str, str]],
    kind: str,
    origin_prefix: str,
) -> None:
    if not source.is_dir():
        raise AuditError(f"missing source directory: {source}")
    shutil.copytree(
        source,
        destination,
        dirs_exist_ok=True,
        copy_function=shutil.copy2,
    )
    for path in sorted(
        (item for item in source.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(source)
        .as_posix()
        .encode("utf-8"),
    ):
        relative = path.relative_to(source)
        target = destination / relative
        key = target.relative_to(root).as_posix()
        origin = PurePosixPath(origin_prefix, relative.as_posix())
        provenance[key] = {"kind": kind, "path": origin.as_posix()}


def register_generated(
    destination: Path,
    root: Path,
    provenance: dict[str, dict[str, str]],
    data: bytes,
    origin: str,
    mode: int,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    destination.chmod(mode)
    relative = destination.relative_to(root).as_posix()
    provenance[relative] = {"kind": "generated", "path": origin}


def tree_identity(root: Path, relative: str) -> dict[str, Any]:
    tree = root / relative
    files = sorted(
        (
            path
            for path in tree.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        if tree.is_dir()
        else [],
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )
    return {
        "path": relative,
        "present": tree.is_dir(),
        "file_count": len(files),
        "bytes": sum(path.stat().st_size for path in files),
        "tree_sha256": content_tree_sha256(root, files),
    }


def directory_content_identity(root: Path) -> dict[str, Any]:
    files = sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink()
        ),
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )
    return {
        "file_count": len(files),
        "bytes": sum(path.stat().st_size for path in files),
        "tree_sha256": content_tree_sha256(root, files),
    }


def inspect_tree(
    root: Path,
    provenance: dict[str, dict[str, str]],
) -> dict[str, Any]:
    files = []
    directories = []
    symlinks = []
    for path in sorted(
        root.rglob("*"),
        key=lambda item: item.relative_to(root).as_posix().encode("utf-8"),
    ):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            symlinks.append(
                {"path": relative, "target": os.readlink(path)}
            )
        elif stat.S_ISDIR(metadata.st_mode):
            directories.append(
                {
                    "path": relative,
                    "mode": stat.S_IMODE(metadata.st_mode),
                }
            )
        elif stat.S_ISREG(metadata.st_mode):
            origin = provenance.get(relative)
            if origin is None:
                raise AuditError(f"missing provenance: {relative}")
            files.append(
                {
                    "path": relative,
                    "bytes": metadata.st_size,
                    "sha256": file_sha256(path),
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "route": route(relative),
                    "origin": origin,
                }
            )
    if set(provenance) != {item["path"] for item in files}:
        raise AuditError("provenance contains paths outside package tree")
    route_summary: dict[str, dict[str, int]] = collections.defaultdict(
        lambda: {"file_count": 0, "bytes": 0}
    )
    origin_summary: dict[str, dict[str, int]] = collections.defaultdict(
        lambda: {"file_count": 0, "bytes": 0}
    )
    for record in files:
        route_item = route_summary[record["route"]]
        route_item["file_count"] += 1
        route_item["bytes"] += record["bytes"]
        origin_item = origin_summary[record["origin"]["kind"]]
        origin_item["file_count"] += 1
        origin_item["bytes"] += record["bytes"]
    license_paths = [
        record["path"]
        for record in files
        if PurePosixPath(record["path"]).name.lower().startswith(
            LICENSE_NAMES
        )
    ]
    binary_paths = [
        record["path"]
        for record in files
        if (
            record["path"].startswith("usr/bin/")
            or record["path"] in {"base/die", "base/diec", "base/diel"}
        )
    ]
    binary_records = {
        record["path"]: record
        for record in files
        if record["path"] in binary_paths
    }
    return {
        "file_count": len(files),
        "bytes": sum(item["bytes"] for item in files),
        "directory_count": len(directories),
        "symlinks": symlinks,
        "records_sha256": sha256(
            canonical_json(
                {
                    "directories": directories,
                    "files": files,
                    "symlinks": symlinks,
                }
            )
        ),
        "route_summary": [
            {"route": name, **values}
            for name, values in sorted(route_summary.items())
        ],
        "origin_summary": [
            {"kind": name, **values}
            for name, values in sorted(origin_summary.items())
        ],
        "license_candidate_paths": license_paths,
        "binaries": binary_records,
    }


def make_appimage_pre_tree(root: Path) -> dict[str, Any]:
    provenance: dict[str, dict[str, str]] = {}
    for relative in (
        "usr/bin",
        "usr/lib/die/lang",
        "usr/share/applications",
        "usr/share/icons",
        "usr/share/metainfo",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    register_copy(
        BUILD_ROOT / "src/gui/die",
        root / "usr/bin/die",
        root,
        provenance,
        "build",
        "src/gui/die",
    )
    register_copy(
        SOURCE_ROOT
        / "LINUX/io.github.horsicq.detect-it-easy.desktop",
        root
        / "usr/share/applications/io.github.horsicq.detect-it-easy.desktop",
        root,
        provenance,
        "source",
        "LINUX/io.github.horsicq.detect-it-easy.desktop",
    )
    register_tree(
        SOURCE_ROOT / "LINUX/hicolor",
        root / "usr/share/icons/hicolor",
        root,
        provenance,
        "source",
        "LINUX/hicolor",
    )
    register_copy(
        SOURCE_ROOT
        / "LINUX/io.github.horsicq.detect-it-easy.metainfo.xml",
        root
        / "usr/share/metainfo/io.github.horsicq.detect-it-easy.metainfo.xml",
        root,
        provenance,
        "source",
        "LINUX/io.github.horsicq.detect-it-easy.metainfo.xml",
    )
    for source_relative, target_name in (
        ("images", "images"),
        ("XStyles/qss", "qss"),
        ("XInfoDB/info", "info"),
        ("Detect-It-Easy/db", "db"),
        ("Detect-It-Easy/db_custom", "db_custom"),
        ("Detect-It-Easy/db_extra", "db_extra"),
        ("XYara/yara_rules", "yara_rules"),
        ("XPEID/peid", "peid"),
    ):
        register_tree(
            SOURCE_ROOT / source_relative,
            root / f"usr/lib/die/{target_name}",
            root,
            provenance,
            "source",
            source_relative,
        )
    register_copy(
        SOURCE_ROOT / "signatures/crypto.db",
        root / "usr/lib/die/signatures/crypto.db",
        root,
        provenance,
        "source",
        "signatures/crypto.db",
    )
    for source, relative in (
        (
            QT_PLUGIN_ROOT / "platforms/libqxcb.so",
            "usr/lib/qt5/plugins/platforms/libqxcb.so",
        ),
        (
            QT_PLUGIN_ROOT / "imageformats/libqjpeg.so",
            "usr/lib/qt5/plugins/imageformats/libqjpeg.so",
        ),
        (
            QT_PLUGIN_ROOT / "printsupport/libcupsprintersupport.so",
            "usr/lib/qt5/plugins/printsupport/libcupsprintersupport.so",
        ),
    ):
        register_copy(
            source,
            root / relative,
            root,
            provenance,
            "system",
            source.as_posix().removeprefix("/"),
        )
    inventory = inspect_tree(root, provenance)
    runtime = {
        name: tree_identity(root / "usr/lib/die", name)
        for name in ("db", "db_extra", "db_custom")
    }
    runtime_files = []
    for name in ("db", "db_extra", "db_custom"):
        runtime_files.extend(
            sorted(
                (
                    path
                    for path in (root / f"usr/lib/die/{name}").rglob(
                        "*"
                    )
                    if path.is_file() and not path.is_symlink()
                ),
                key=lambda path: path.relative_to(root / "usr/lib/die")
                .as_posix()
                .encode("utf-8"),
            )
        )
    return {
        "kind": "pre-linuxdeploy-appdir",
        "binary_replay": (
            "fixed CMake gui binary substitutes for "
            "create_appimage.sh build/release/die"
        ),
        "linuxdeploy_available": shutil.which("linuxdeploy") is not None,
        "inventory": inventory,
        "data_trees": {
            name: tree_identity(root / "usr/lib/die", name)
            for name in (
                "qss",
                "info",
                "images",
                "yara_rules",
                "peid",
                "signatures",
            )
        },
        "runtime_rules": {
            "trees": runtime,
            "file_count": len(runtime_files),
            "bytes": sum(path.stat().st_size for path in runtime_files),
            "combined_tree_sha256": content_tree_sha256(
                root / "usr/lib/die", runtime_files
            ),
        },
    }


def install_stage(root: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "cmake",
            "--install",
            str(BUILD_ROOT),
            "--prefix",
            str(root),
            "--config",
            "Release",
        ],
        capture_output=True,
    )
    if completed.returncode != 0 or completed.stderr:
        raise AuditError("portable CMake install staging failed")
    normalized = completed.stdout.replace(
        str(root).encode("utf-8"), b"<STAGE>"
    )
    return {
        "stdout_bytes": len(normalized),
        "stdout_sha256": sha256(normalized),
        "stderr_bytes": len(completed.stderr),
    }


def portable_launcher(name: str) -> bytes:
    return (
        "#!/bin/sh\n"
        "CWD=$(dirname $0)\n"
        'export LD_LIBRARY_PATH="$CWD/base:$LD_LIBRARY_PATH"\n'
        f'"$CWD/base/{name}" "$@"\n'
    ).encode("utf-8")


def make_portable_tree(
    root: Path,
    stage: Path,
    qt_prefix: Path | None,
) -> dict[str, Any]:
    provenance: dict[str, dict[str, str]] = {}
    for relative in ("base/platforms", "base/sqldrivers"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    for name in ("die", "diec", "diel"):
        register_copy(
            stage / f"bin/{name}",
            root / f"base/{name}",
            root,
            provenance,
            "build",
            f"src/{'gui' if name == 'die' else 'console' if name == 'diec' else 'lite'}/{name}",
        )
    bundled_qt = []
    if qt_prefix is not None:
        qt_lib_root = qt_prefix / "lib"
        qt_plugin_root = qt_prefix / "plugins"
        for name in QT_LIBS:
            matches = sorted(qt_lib_root.glob(f"{name}.so.5"))
            if len(matches) > 1:
                raise AuditError(f"Qt library match drift: {name}")
            if not matches:
                continue
            source = matches[0]
            destination = root / f"base/{source.name}"
            register_copy(
                source,
                destination,
                root,
                provenance,
                "system",
                source.as_posix().removeprefix("/"),
            )
            bundled_qt.append(destination.relative_to(root).as_posix())
        for source, relative in (
            (
                qt_plugin_root / "platforms/libqxcb.so",
                "base/platforms/libqxcb.so",
            ),
            (
                qt_plugin_root / "sqldrivers/libqsqlite.so",
                "base/sqldrivers/libqsqlite.so",
            ),
        ):
            if not source.is_file():
                continue
            register_copy(
                source,
                root / relative,
                root,
                provenance,
                "system",
                source.as_posix().removeprefix("/"),
            )
            bundled_qt.append(relative)
    stage_data = stage / "lib/die"
    expected = {
        "db": "Detect-It-Easy/db",
        "images": "images",
        "info": "XInfoDB/info",
        "qss": "XStyles/qss",
        "yara_rules": "XYara/yara_rules",
    }
    if {path.name for path in stage_data.iterdir()} != set(expected):
        raise AuditError("portable staged data subtree set drift")
    for name, source_relative in expected.items():
        staged = stage_data / name
        source = SOURCE_ROOT / source_relative
        if directory_content_identity(
            staged
        ) != directory_content_identity(source):
            raise AuditError(f"portable staged data differs: {name}")
        register_tree(
            staged,
            root / f"base/{name}",
            root,
            provenance,
            "source",
            source_relative,
        )
    register_copy(
        SOURCE_ROOT / "signatures/crypto.db",
        root / "base/signatures/crypto.db",
        root,
        provenance,
        "source",
        "signatures/crypto.db",
    )
    for name in ("die", "diec", "diel"):
        register_generated(
            root / f"{name}.sh",
            root,
            provenance,
            portable_launcher(name),
            f"build_linux_portable.sh:{name}.sh",
            0o755,
        )
    inventory = inspect_tree(root, provenance)
    runtime = {
        name: tree_identity(root / "base", name)
        for name in ("db", "db_extra", "db_custom")
    }
    runtime_files = sorted(
        (
            path
            for path in (root / "base/db").rglob("*")
            if path.is_file() and not path.is_symlink()
        ),
        key=lambda path: path.relative_to(root / "base")
        .as_posix()
        .encode("utf-8"),
    )
    return {
        "kind": (
            "portable-tree-with-qmake-qt-prefix"
            if qt_prefix is not None
            else "portable-tree-with-system-qt"
        ),
        "build_replay": (
            "fixed complete CMake build substitutes for the script's "
            "fresh configure and build"
        ),
        "qt_prefix_argument": (
            qt_prefix.as_posix() if qt_prefix is not None else None
        ),
        "bundled_qt_files": bundled_qt,
        "inventory": inventory,
        "data_trees": {
            name: tree_identity(root / "base", name)
            for name in (
                "qss",
                "info",
                "images",
                "yara_rules",
                "peid",
                "signatures",
            )
        },
        "runtime_rules": {
            "trees": runtime,
            "file_count": len(runtime_files),
            "bytes": sum(path.stat().st_size for path in runtime_files),
            "combined_tree_sha256": content_tree_sha256(
                root / "base", runtime_files
            ),
        },
        "launchers": {
            name: {
                "path": f"{name}.sh",
                "sha256": sha256(portable_launcher(name)),
                "mode": 0o755,
            }
            for name in ("die", "diec", "diel")
        },
    }


def tar_inventory(path: Path) -> dict[str, Any]:
    records = []
    mtimes = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            payload_sha256 = None
            if member.isreg():
                stream = archive.extractfile(member)
                if stream is None:
                    raise AuditError(
                        f"tar regular member has no payload: {member.name}"
                    )
                digest = hashlib.sha256()
                while block := stream.read(1024 * 1024):
                    digest.update(block)
                payload_sha256 = digest.hexdigest()
            records.append(
                {
                    "path": member.name,
                    "type": member.type.hex(),
                    "mode": member.mode,
                    "uid": member.uid,
                    "gid": member.gid,
                    "uname": member.uname,
                    "gname": member.gname,
                    "size": member.size,
                    "linkname": member.linkname,
                    "devmajor": member.devmajor,
                    "devminor": member.devminor,
                    "payload_sha256": payload_sha256,
                }
            )
            mtimes[member.name] = member.mtime
    return {
        "member_count": len(records),
        "records": records,
        "records_sha256": sha256(canonical_json(records)),
        "mtimes": mtimes,
    }


def create_normalized_portable_archive(
    parent: Path,
    package_name: str,
) -> dict[str, Any]:
    tar_path = parent / f"{package_name}.normalized.tar"
    archive_path = parent / f"{package_name}.normalized.tar.gz"
    tar_command = [
        "tar",
        "--sort=name",
        "--mtime=@0",
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        "--format=gnu",
        "-cf",
        str(tar_path),
        package_name,
    ]
    completed = subprocess.run(
        tar_command,
        cwd=parent,
        capture_output=True,
    )
    if (
        completed.returncode != 0
        or completed.stdout
        or completed.stderr
        or not tar_path.is_file()
        or tar_path.stat().st_size == 0
    ):
        raise AuditError("normalized portable tar creation failed")
    gzip_command = ["gzip", "-n", "-9", "-c", str(tar_path)]
    with archive_path.open("wb") as output:
        completed = subprocess.run(
            gzip_command,
            stdout=output,
            stderr=subprocess.PIPE,
        )
    if (
        completed.returncode != 0
        or completed.stderr
        or not archive_path.is_file()
        or archive_path.stat().st_size == 0
    ):
        raise AuditError("normalized portable gzip creation failed")
    return {
        "tar_command": [
            *tar_command[:-2],
            "<TAR>",
            package_name,
        ],
        "gzip_command": [
            "gzip",
            "-n",
            "-9",
            "-c",
            "<TAR>",
        ],
        "archive_bytes": archive_path.stat().st_size,
        "archive_sha256": file_sha256(archive_path),
        "uncompressed_tar_sha256": file_sha256(tar_path),
        "tar": tar_inventory(archive_path),
    }


def create_portable_archive_replay(
    temporary: Path,
    stage: Path,
) -> dict[str, Any]:
    package_name = "die_4.0.0_portable"
    runs = []
    minimum_delay_seconds = 1.1
    for number in (1, 2):
        parent = temporary / f"archive-run-{number}"
        package_root = parent / package_name
        parent.mkdir()
        tree = make_portable_tree(package_root, stage, None)
        archive_path = parent / f"{package_name}.tar.gz"
        completed = subprocess.run(
            ["tar", "-czf", str(archive_path), package_name],
            cwd=parent,
            capture_output=True,
        )
        if (
            completed.returncode != 0
            or completed.stdout
            or completed.stderr
            or not archive_path.is_file()
            or archive_path.stat().st_size == 0
        ):
            raise AuditError(
                f"portable archive replay failed on run {number}"
            )
        runs.append(
            {
                "tree_records_sha256": tree["inventory"][
                    "records_sha256"
                ],
                "archive_sha256": file_sha256(archive_path),
                "uncompressed_tar_sha256": compressed_stream_sha256(
                    archive_path
                ),
                "tar": tar_inventory(archive_path),
                "normalized": create_normalized_portable_archive(
                    parent,
                    package_name,
                ),
            }
        )
        if number == 1:
            time.sleep(minimum_delay_seconds)

    first, second = runs
    if first["tar"]["records"] != second["tar"]["records"]:
        raise AuditError("portable tar semantic records differ")
    first_mtimes = first["tar"]["mtimes"]
    second_mtimes = second["tar"]["mtimes"]
    if set(first_mtimes) != set(second_mtimes):
        raise AuditError("portable tar member path sets differ")
    differing_mtime_paths = sorted(
        path
        for path in first_mtimes
        if first_mtimes[path] != second_mtimes[path]
    )
    first_normalized = first["normalized"]
    second_normalized = second["normalized"]
    if (
        first_normalized["tar"]["records"]
        != second_normalized["tar"]["records"]
    ):
        raise AuditError("normalized tar semantic records differ")
    normalized_metadata = first_normalized["tar"]
    normalized_metadata_is_fixed = all(
        set(run["normalized"]["tar"]["mtimes"].values()) == {0}
        and all(
            record["uid"] == 0
            and record["gid"] == 0
            and not record["uname"]
            and not record["gname"]
            for record in run["normalized"]["tar"]["records"]
        )
        for run in (first, second)
    )
    return {
        "command": ["tar", "-czf", "<ARCHIVE>", package_name],
        "run_count": 2,
        "minimum_inter_run_delay_seconds": minimum_delay_seconds,
        "archives_nonempty": True,
        "archive_hashes_intentionally_omitted": True,
        "tree_records_identical": (
            first["tree_records_sha256"]
            == second["tree_records_sha256"]
        ),
        "tar_member_count": first["tar"]["member_count"],
        "tar_semantic_records_sha256": first["tar"][
            "records_sha256"
        ],
        "tar_semantic_records_identical": True,
        "differing_mtime_path_count": len(differing_mtime_paths),
        "differing_mtime_paths_sha256": sha256(
            canonical_json(differing_mtime_paths)
        ),
        "differing_mtime_path_sample": differing_mtime_paths[:20],
        "differing_mtime_path_sample_truncated": (
            len(differing_mtime_paths) > 20
        ),
        "uncompressed_tar_byte_identical": (
            first["uncompressed_tar_sha256"]
            == second["uncompressed_tar_sha256"]
        ),
        "compressed_tar_gz_byte_identical": (
            first["archive_sha256"] == second["archive_sha256"]
        ),
        "normalized_control": {
            "tar_command": first_normalized["tar_command"],
            "gzip_command": first_normalized["gzip_command"],
            "run_count": 2,
            "metadata_is_fixed": normalized_metadata_is_fixed,
            "tar_member_count": normalized_metadata["member_count"],
            "tar_semantic_records_identical": True,
            "tar_semantic_records_sha256": normalized_metadata[
                "records_sha256"
            ],
            "uncompressed_tar_byte_identical": (
                first_normalized["uncompressed_tar_sha256"]
                == second_normalized["uncompressed_tar_sha256"]
            ),
            "uncompressed_tar_sha256": first_normalized[
                "uncompressed_tar_sha256"
            ],
            "compressed_tar_gz_byte_identical": (
                first_normalized["archive_sha256"]
                == second_normalized["archive_sha256"]
            ),
            "archive_bytes": first_normalized["archive_bytes"],
            "archive_sha256": first_normalized["archive_sha256"],
        },
    }


def validate_script_contracts() -> dict[str, Any]:
    appimage = APPIMAGE_SCRIPT.read_bytes()
    portable = PORTABLE_SCRIPT.read_bytes()
    helper = LINUX_HELPER.read_bytes()
    app_text = appimage.decode("utf-8")
    portable_text = portable.decode("utf-8")
    required_app = (
        "create_image_app_dir die",
        "cp -f $X_SOURCE_PATH/build/release/die ",
        "#cp -f $X_SOURCE_PATH/build/release/diec ",
        "#cp -f $X_SOURCE_PATH/build/release/diel ",
        "linuxdeploy ",
        "--executable $X_SOURCE_PATH/release/appDir/usr/bin/die",
    )
    required_portable = (
        'cp -f "$STAGE_DIR/bin/die"',
        'cp -f "$STAGE_DIR/bin/diec"',
        'cp -f "$STAGE_DIR/bin/diel"',
        '[ -d "$STAGE_DIR/lib/die/" ]',
        '[ ! -d "$PACKAGE_DIR/base/db" ]',
        "tar -czf",
    )
    if not all(value in app_text for value in required_app):
        raise AuditError("AppImage script contract drift")
    if not all(value in portable_text for value in required_portable):
        raise AuditError("portable script contract drift")
    if "db_extra" in portable_text or "db_custom" in portable_text:
        raise AuditError("portable runtime rule fallback changed")
    return {
        "create_appimage": {
            "path": "create_appimage.sh",
            "bytes": len(appimage),
            "sha256": sha256(appimage),
        },
        "build_linux_portable": {
            "path": "build_linux_portable.sh",
            "bytes": len(portable),
            "sha256": sha256(portable),
        },
        "build_tools_linux": {
            "path": "build_tools/linux.sh",
            "commit": git_head(SOURCE_ROOT / "build_tools"),
            "bytes": len(helper),
            "sha256": sha256(helper),
        },
        "derived_findings": {
            "appimage_copies_gui_only_before_linuxdeploy": True,
            "appimage_cli_and_lite_copy_commands_are_commented": True,
            "portable_copies_all_three_products": True,
            "portable_uses_lib_die_staging_data": True,
            "portable_has_no_db_extra_or_db_custom_copy": True,
            "portable_tar_metadata_is_not_normalized": (
                "--sort=" not in portable_text
                and "--mtime=" not in portable_text
                and "SOURCE_DATE_EPOCH" not in portable_text
            ),
        },
    }


def qmake_query(field: str) -> str:
    completed = subprocess.run(
        ["qmake", "-query", field],
        check=True,
        capture_output=True,
        text=True,
    )
    if completed.stderr:
        raise AuditError(f"qmake query emitted stderr: {field}")
    value = completed.stdout.strip()
    if not value.startswith("/"):
        raise AuditError(f"qmake query is not absolute: {field}")
    return value


def inside_report() -> dict[str, Any]:
    if git_head(SOURCE_ROOT) != UPSTREAM_COMMIT:
        raise AuditError("source commit mismatch")
    if git_head(SOURCE_ROOT / "build_tools") != BUILD_TOOLS_COMMIT:
        raise AuditError("build_tools commit mismatch")
    version = RELEASE_VERSION_PATH.read_text(encoding="utf-8").strip()
    if version != "4.0.0":
        raise AuditError("release version drift")
    scripts = validate_script_contracts()
    qt_layout = {
        "prefix": qmake_query("QT_INSTALL_PREFIX"),
        "libraries": qmake_query("QT_INSTALL_LIBS"),
        "plugins": qmake_query("QT_INSTALL_PLUGINS"),
    }
    with tempfile.TemporaryDirectory(
        prefix="die-release-tree-"
    ) as directory:
        temporary = Path(directory)
        stage = temporary / "cmake-stage"
        stage.mkdir()
        install = install_stage(stage)
        appimage = make_appimage_pre_tree(temporary / "appimage")
        portable_system = make_portable_tree(
            temporary / "portable-system", stage, None
        )
        portable_qt = make_portable_tree(
            temporary / "portable-qt",
            stage,
            Path(qt_layout["prefix"]),
        )
        portable_archive = create_portable_archive_replay(
            temporary,
            stage,
        )
    relationships = {
        "appimage_pre_tree_has_only_gui_product": (
            set(appimage["inventory"]["binaries"]) == {"usr/bin/die"}
        ),
        "appimage_final_artifact_is_unavailable_without_linuxdeploy": (
            not appimage["linuxdeploy_available"]
        ),
        "appimage_pre_tree_contains_complete_runtime_rules": all(
            appimage["runtime_rules"][field] == expected
            for field, expected in EXPECTED_RUNTIME_RULES.items()
        ),
        "portable_variants_have_exactly_three_products": all(
            set(variant["inventory"]["binaries"])
            == {"base/die", "base/diec", "base/diel"}
            for variant in (portable_system, portable_qt)
        ),
        "portable_variants_omit_extra_and_custom_rules": all(
            not variant["runtime_rules"]["trees"][name]["present"]
            for variant in (portable_system, portable_qt)
            for name in ("db_extra", "db_custom")
        ),
        "portable_variants_contain_exact_main_rule_tree": all(
            variant["runtime_rules"]["file_count"] == 2_124
            and variant["runtime_rules"]["bytes"] == 2_832_469
            and variant["runtime_rules"]["combined_tree_sha256"]
            == (
                "8000138ce96a6a892aaa3cba8dee60960"
                "694c42dcfa24b3787f02c25858f1650"
            )
            for variant in (portable_system, portable_qt)
        ),
        "portable_default_bundles_no_qt_files": (
            not portable_system["bundled_qt_files"]
        ),
        "portable_qmake_prefix_bundles_no_qt_on_multiarch_image": (
            not portable_qt["bundled_qt_files"]
            and portable_qt["inventory"]["records_sha256"]
            == portable_system["inventory"]["records_sha256"]
            and qt_layout["prefix"] == "/usr"
            and qt_layout["libraries"] != "/usr/lib"
            and qt_layout["plugins"] != "/usr/plugins"
        ),
        "all_replayed_trees_have_no_license_candidate": all(
            not variant["inventory"]["license_candidate_paths"]
            for variant in (appimage, portable_system, portable_qt)
        ),
        "all_replayed_trees_have_no_symlinks": all(
            not variant["inventory"]["symlinks"]
            for variant in (appimage, portable_system, portable_qt)
        ),
        "script_findings_are_true": all(
            scripts["derived_findings"].values()
        ),
        "appimage_includes_yara_peid_and_signature_data": all(
            appimage["data_trees"][name]["present"]
            and appimage["data_trees"][name]["file_count"] > 0
            for name in ("yara_rules", "peid", "signatures")
        ),
        "portable_includes_yara_and_signatures_but_not_peid": all(
            variant["data_trees"]["yara_rules"]["present"]
            and variant["data_trees"]["signatures"]["present"]
            and not variant["data_trees"]["peid"]["present"]
            for variant in (portable_system, portable_qt)
        ),
        "portable_tar_replay_proves_metadata_nondeterminism": (
            portable_archive["tree_records_identical"]
            and portable_archive["tar_semantic_records_identical"]
            and portable_archive["differing_mtime_path_count"] > 0
            and not portable_archive["uncompressed_tar_byte_identical"]
            and not portable_archive["compressed_tar_gz_byte_identical"]
        ),
        "normalized_portable_archive_control_is_byte_reproducible": (
            portable_archive["normalized_control"][
                "metadata_is_fixed"
            ]
            and portable_archive["normalized_control"][
                "tar_semantic_records_identical"
            ]
            and portable_archive["normalized_control"][
                "uncompressed_tar_byte_identical"
            ]
            and portable_archive["normalized_control"][
                "compressed_tar_gz_byte_identical"
            ]
        ),
    }
    if not all(relationships.values()):
        failed = sorted(
            name for name, value in relationships.items() if not value
        )
        raise AuditError(
            "release-tree relationships failed: "
            f"{failed}; appimage_runtime={appimage['runtime_rules']}"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "upstream_commit": UPSTREAM_COMMIT,
        "build_tools_commit": BUILD_TOOLS_COMMIT,
        "release_version": version,
        "qt_layout": qt_layout,
        "scripts": scripts,
        "cmake_stage": install,
        "variants": {
            "appimage_pre_linuxdeploy": appimage,
            "portable_system_qt": portable_system,
            "portable_qmake_prefix": portable_qt,
        },
        "portable_archive_replay": portable_archive,
        "relationships": relationships,
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


def host_report(repo: Path) -> dict[str, Any]:
    base = inspect_image(BASE_IMAGE)
    if base["id"] != BASE_IMAGE_ID:
        raise AuditError("base image ID mismatch")
    release = inspect_image(RELEASE_IMAGE)
    image_script = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            "/bin/cat",
            RELEASE_IMAGE,
            INSIDE_SCRIPT,
        ],
        check=True,
        capture_output=True,
    ).stdout
    local_script = Path(__file__).read_bytes()
    if image_script != local_script:
        raise AuditError("image audit script differs from repository")
    completed = subprocess.run(
        ["docker", "run", "--rm", "--network=none", RELEASE_IMAGE],
        check=True,
        capture_output=True,
        timeout=300,
    )
    if completed.stderr:
        raise AuditError("release-tree audit emitted stderr")
    inside = json.loads(completed.stdout)
    prior_raw = (repo / PRIOR_REPORT).read_bytes()
    prior = json.loads(prior_raw)
    prior_valid = all(prior["relationships"].values())
    relationships = dict(inside["relationships"])
    relationships["prior_cmake_install_report_is_valid"] = prior_valid
    if not all(relationships.values()):
        raise AuditError("host release-tree relationships failed")
    dockerfile = (repo / DOCKERFILE).read_bytes()
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": "tools/upstream/audit_linux_release_trees.py",
        "generator_sha256": sha256(local_script),
        "upstream_commit": UPSTREAM_COMMIT,
        "environment": {
            "network": "none",
            "base_image": base,
            "release_image": release,
            "inside_script": {
                "path": INSIDE_SCRIPT,
                "image_sha256": sha256(image_script),
                "repository_sha256": sha256(local_script),
            },
            "dockerfile": {
                "path": DOCKERFILE,
                "sha256": sha256(dockerfile),
            },
        },
        "prior_report": {
            "path": PRIOR_REPORT,
            "sha256": sha256(prior_raw),
        },
        "release": inside,
        "relationships": relationships,
        "scope": {
            "platform": "Linux x86_64",
            "qt": "5",
            "kind": "post-build-release-tree-replay",
            "original_scripts_executed_end_to_end": False,
            "final_appimage_available": False,
            "compressed_portable_archive_generated": True,
            "portable_archive_byte_reproducible": False,
            "normalized_portable_archive_control_generated": True,
            "normalized_portable_archive_control_byte_reproducible": (
                True
            ),
            "legal_review_complete": False,
            "release_approved": False,
        },
        "limitations": [
            "the replay uses fixed built executables and reproduces script copy/layout semantics instead of reconfiguring and rebuilding",
            "the AppImage pre-tree uses the fixed CMake GUI executable as a surrogate for create_appimage.sh build/release/die; an actual qmake-workflow binary is not claimed",
            "linuxdeploy is absent, so the final AppImage dependency closure and mutations are not observed",
            "two portable tar.gz replays use the original tar command and prove mtime-driven byte differences; their unstable archive hashes are intentionally omitted",
            "the byte-reproducible normalized archive is a post-build control over the upstream portable tree, not an upstream artifact, clean-build proof, or approved Rust release manifest",
            "technical content and provenance closure is not legal approval",
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

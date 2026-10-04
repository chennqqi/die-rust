#!/usr/bin/env python3
"""Probe pinned Linux Qt5 symlink, permission, and path-depth behavior."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import pathlib
import re
import subprocess
import time
from typing import Any
import zlib


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
FIXTURE_GENERATOR = "tools/corpus/generate_path_filesystem_fixture.py"
FIXTURE_MANIFEST = "docs/research/data/path-filesystem-fixture.json"
ARCHIVE_NAME = "path-filesystem-fixture.tar"
DATABASE_ARGS = (
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
)
ORACLES = {
    "qmake": {
        "image": "die-rust/upstream-oracle:74eaf505-repro",
        "binary": "/opt/die-source/build/release/diec",
    },
    "cmake": {
        "image": "die-rust/upstream-oracle-cmake:74eaf505",
        "binary": "/opt/die-build/src/console/diec",
    },
}
SOURCE_PATH = "/opt/die-source/Formats/xbinary.cpp"
SOURCE_PATTERNS = (
    "QFileInfoList eil = dir.entryInfoList();",
    "findFiles(eil.at(i).absoluteFilePath(), pListFileNames, pPdStruct);",
)


@dataclass(frozen=True)
class Case:
    name: str
    path: str
    user: str = "root"
    timeout_seconds: int = 30


CASES = (
    Case("direct_control", "/work/paths/symlink/target.pdf"),
    Case("file_symlink", "/work/paths/symlink/file-link.pdf"),
    Case("directory_symlink", "/work/paths/symlink/dir-link"),
    Case("symlink_tree", "/work/paths/symlink"),
    Case("dangling_symlink", "/work/paths/symlink/dangling.pdf"),
    Case("deep_64", "/work/paths/deep"),
    Case("denied_as_root", "/work/paths/denied"),
    Case("denied_as_nobody", "/work/paths/denied", user="nobody"),
    Case("self_cycle", "/work/paths/cycle", timeout_seconds=10),
)
EMPTY_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855"
)
PDF_STDOUT_SHA256 = (
    "5a475aa450326d3096db01352fe524bbd"
    "a579173a645f0f502a74bba27a32e35"
)
EXPECTED_CASES = {
    "dangling_symlink": {
        "exit_code": 1,
        "stdout_sha256": (
            "48b5671e6aa7f34d80f0fe5cb435162d"
            "57e0b66264665fb23fb82ff725bac75a"
        ),
        "summary": {
            "cannot_find_count": 1,
            "filename_prefix_count": 0,
            "pdf_root_count": 0,
        },
    },
    "deep_64": {
        "exit_code": 0,
        "stdout_sha256": PDF_STDOUT_SHA256,
        "summary": {
            "cannot_find_count": 0,
            "filename_prefix_count": 0,
            "pdf_root_count": 1,
        },
    },
    "denied_as_nobody": {
        "exit_code": 0,
        "stdout_sha256": EMPTY_SHA256,
        "summary": {
            "cannot_find_count": 0,
            "filename_prefix_count": 0,
            "pdf_root_count": 0,
        },
    },
    "denied_as_root": {
        "exit_code": 0,
        "stdout_sha256": PDF_STDOUT_SHA256,
        "summary": {
            "cannot_find_count": 0,
            "filename_prefix_count": 0,
            "pdf_root_count": 1,
        },
    },
    "direct_control": {
        "exit_code": 0,
        "stdout_sha256": PDF_STDOUT_SHA256,
        "summary": {
            "cannot_find_count": 0,
            "filename_prefix_count": 0,
            "pdf_root_count": 1,
        },
    },
    "directory_symlink": {
        "exit_code": 0,
        "stdout_sha256": PDF_STDOUT_SHA256,
        "summary": {
            "cannot_find_count": 0,
            "filename_prefix_count": 0,
            "pdf_root_count": 1,
        },
    },
    "file_symlink": {
        "exit_code": 0,
        "stdout_sha256": PDF_STDOUT_SHA256,
        "summary": {
            "cannot_find_count": 0,
            "filename_prefix_count": 0,
            "pdf_root_count": 1,
        },
    },
    "self_cycle": {
        "exit_code": 0,
        "stdout_sha256": (
            "66f7fb7535dcdd248ff2ee053bcd528a0"
            "09c277f598044540e3c86506b0b8bf6"
        ),
        "summary": {
            "cannot_find_count": 0,
            "filename_prefix_count": 41,
            "pdf_root_count": 41,
        },
    },
    "symlink_tree": {
        "exit_code": 0,
        "stdout_sha256": (
            "79d30fa46318c587e501b67afea273647"
            "10cae5ac10f09dd1b4eda33c5792617"
        ),
        "summary": {
            "cannot_find_count": 0,
            "filename_prefix_count": 4,
            "pdf_root_count": 4,
        },
    },
}


class ProbeError(ValueError):
    """The fixture, fixed oracle, or observed filesystem behavior is invalid."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProbeError(f"non-finite JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError(f"invalid JSON: {error}") from error


def load_fixture(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
) -> tuple[dict[str, Any], bytes]:
    raw = manifest_path.read_bytes()
    manifest = strict_json(raw)
    if not isinstance(manifest, dict) or set(manifest) != {
        "archive",
        "deep_levels",
        "entries",
        "generator",
        "license",
        "payload",
        "schema_version",
    }:
        raise ProbeError("fixture manifest fields changed")
    if manifest["schema_version"] != 1:
        raise ProbeError("unsupported fixture schema")
    if manifest["generator"] != FIXTURE_GENERATOR:
        raise ProbeError("unexpected fixture generator")
    if manifest["deep_levels"] != 64:
        raise ProbeError("deep fixture level changed")
    archive_record = manifest["archive"]
    if (
        not isinstance(archive_record, dict)
        or set(archive_record)
        != {"format", "name", "sha256", "size"}
        or archive_record["name"] != ARCHIVE_NAME
        or archive_record["format"] != "gnu"
    ):
        raise ProbeError("fixture archive identity changed")
    archive_path = fixture_dir / ARCHIVE_NAME
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ProbeError("fixture archive is missing or symlinked")
    archive = archive_path.read_bytes()
    if (
        len(archive) != archive_record["size"]
        or sha256(archive) != archive_record["sha256"]
    ):
        raise ProbeError("fixture archive bytes changed")
    entries = manifest["entries"]
    if not isinstance(entries, list) or len(entries) != 79:
        raise ProbeError("fixture entry inventory changed")
    paths = [entry.get("path") for entry in entries]
    if len(paths) != len(set(paths)):
        raise ProbeError("duplicate fixture path")
    required = {
        "paths/symlink/file-link.pdf",
        "paths/symlink/dir-link",
        "paths/symlink/dangling.pdf",
        "paths/cycle/loop",
        "paths/denied/",
    }
    if not required.issubset(set(paths)):
        raise ProbeError("fixture matrix changed")
    return manifest, raw


def inspect_image(name: str, image: str) -> dict[str, Any]:
    process = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        capture_output=True,
    )
    documents = strict_json(process.stdout)
    if not isinstance(documents, list) or len(documents) != 1:
        raise ProbeError(f"unexpected image inspection shape: {name}")
    document = documents[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision",
        "",
    )
    if revision != UPSTREAM_COMMIT:
        raise ProbeError(f"oracle revision changed: {name}")
    return {
        "binary": ORACLES[name]["binary"],
        "id": document["Id"],
        "image": image,
        "repo_digests": sorted(document.get("RepoDigests") or []),
        "revision": revision,
    }


def read_container_files(
    image: str, paths: tuple[str, ...]
) -> dict[str, bytes]:
    script = (
        "import base64,json,pathlib;"
        f"paths={paths!r};"
        "print(json.dumps({p:base64.b64encode("
        "pathlib.Path(p).read_bytes()).decode('ascii') for p in paths},"
        "sort_keys=True))"
    )
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            image,
            "python3",
            "-c",
            script,
        ],
        check=True,
        capture_output=True,
    )
    encoded = strict_json(process.stdout)
    if not isinstance(encoded, dict) or set(encoded) != set(paths):
        raise ProbeError("container file inventory changed")
    return {
        path: base64.b64decode(value, validate=True)
        for path, value in encoded.items()
    }


def docker_prefix(
    image: str, fixture_dir: pathlib.Path
) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cpus",
        "1",
        "--memory",
        "512m",
        "--pids-limit",
        "128",
        "--read-only",
        "--ulimit",
        "core=0",
        "--tmpfs",
        "/work:rw,nosuid,nodev,size=64m",
        "--mount",
        f"type=bind,src={fixture_dir},dst=/fixture,readonly",
        image,
    ]


def run_case(
    *,
    image: str,
    binary: str,
    fixture_dir: pathlib.Path,
    case: Case,
) -> tuple[subprocess.CompletedProcess[bytes], int]:
    shell = (
        "tar -xf /fixture/path-filesystem-fixture.tar -C /work"
        ' && binary="$1" && user="$2" && seconds="$3" && path="$4"'
        ' && if [ "$user" = nobody ]; then'
        ' exec timeout -s KILL "$seconds"'
        ' runuser -u nobody -- "$binary" --json "$5" "$6"'
        ' "$7" "$8" "$9" "${10}" "$path";'
        " else"
        ' exec timeout -s KILL "$seconds" "$binary" --json'
        ' "$5" "$6" "$7" "$8" "$9" "${10}" "$path";'
        " fi"
    )
    command = [
        *docker_prefix(image, fixture_dir),
        "sh",
        "-c",
        shell,
        "sh",
        binary,
        case.user,
        str(case.timeout_seconds),
        case.path,
        *DATABASE_ARGS,
    ]
    started = time.monotonic()
    process = subprocess.run(
        command,
        capture_output=True,
        timeout=case.timeout_seconds + 20,
        check=False,
    )
    return process, round((time.monotonic() - started) * 1000)


def inspect_extracted_fixture(
    image: str, fixture_dir: pathlib.Path
) -> dict[str, Any]:
    script = (
        "import json,os,pathlib,stat;"
        "base=pathlib.Path('/work/paths');"
        "deep=list((base/'deep').glob('level-*'));"
        "leaf=next((base/'deep').rglob('leaf.pdf'));"
        "result={"
        "'file_link':os.readlink(base/'symlink/file-link.pdf'),"
        "'dir_link':os.readlink(base/'symlink/dir-link'),"
        "'dangling_link':os.readlink(base/'symlink/dangling.pdf'),"
        "'cycle_link':os.readlink(base/'cycle/loop'),"
        "'denied_mode':stat.S_IMODE(os.lstat(base/'denied').st_mode),"
        "'deep_leaf':str(leaf),"
        "'deep_component_count':sum("
        "part.startswith('level-') for part in leaf.parts),"
        "'file_link_is_symlink':(base/'symlink/file-link.pdf').is_symlink(),"
        "'dir_link_is_symlink':(base/'symlink/dir-link').is_symlink(),"
        "'cycle_link_is_symlink':(base/'cycle/loop').is_symlink()};"
        "print(json.dumps(result,sort_keys=True))"
    )
    process = subprocess.run(
        [
            *docker_prefix(image, fixture_dir),
            "sh",
            "-c",
            (
                "tar -xf /fixture/path-filesystem-fixture.tar -C /work"
                ' && exec python3 -c "$1"'
            ),
            "sh",
            script,
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    if process.returncode != 0 or process.stderr:
        raise ProbeError("fixture extraction preflight failed")
    result = strict_json(process.stdout)
    expected = {
        "cycle_link": ".",
        "cycle_link_is_symlink": True,
        "dangling_link": "missing.pdf",
        "deep_component_count": 64,
        "dir_link": "dir-target",
        "dir_link_is_symlink": True,
        "file_link": "target.pdf",
        "file_link_is_symlink": True,
        "denied_mode": 0,
    }
    for key, value in expected.items():
        if result.get(key) != value:
            raise ProbeError(f"fixture preflight changed: {key}")
    if not str(result.get("deep_leaf", "")).endswith("/leaf.pdf"):
        raise ProbeError("deep leaf preflight changed")
    return result


def raw_ref(
    data: bytes,
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    digest = sha256(data)
    compressed = zlib.compress(data, 9)
    artifact = {
        "base64": base64.b64encode(compressed).decode("ascii"),
        "bytes": len(data),
        "compressed_bytes": len(compressed),
        "encoding": "zlib+base64",
    }
    previous = artifacts.setdefault(digest, artifact)
    if previous != artifact:
        raise ProbeError("raw artifact digest collision")
    return {
        "artifact_sha256": digest,
        "bytes": len(data),
        "sha256": digest,
    }


def stdout_summary(data: bytes) -> dict[str, Any]:
    return {
        "cannot_find_count": data.count(b"Cannot find:"),
        "filename_prefix_count": data.count(b".pdf:\n"),
        "pdf_root_count": (
            data.count(b'"filetype":"PDF"')
            + data.count(b'"filetype": "PDF"')
        ),
    }


def filename_prefixes(data: bytes) -> list[str]:
    return [
        value.decode("utf-8")
        for value in re.findall(rb"(?m)^(/work/.*\.pdf):$", data)
    ]


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
) -> dict[str, Any]:
    manifest, manifest_raw = load_fixture(fixture_dir, manifest_path)
    artifacts: dict[str, dict[str, Any]] = {}
    images = {
        name: inspect_image(name, oracle["image"])
        for name, oracle in ORACLES.items()
    }
    cmake_files = read_container_files(
        ORACLES["cmake"]["image"],
        (ORACLES["cmake"]["binary"], SOURCE_PATH),
    )
    qmake_files = read_container_files(
        ORACLES["qmake"]["image"],
        (ORACLES["qmake"]["binary"],),
    )
    source_text = cmake_files[SOURCE_PATH].decode("utf-8")
    pattern_counts = {
        pattern: source_text.count(pattern)
        for pattern in SOURCE_PATTERNS
    }
    if any(count < 1 for count in pattern_counts.values()):
        raise ProbeError("findFiles source contract changed")

    cases: dict[str, Any] = {}
    for case in CASES:
        observations = {}
        exact: tuple[int, bytes, bytes] | None = None
        for oracle_name, oracle in ORACLES.items():
            process, elapsed_ms = run_case(
                image=oracle["image"],
                binary=oracle["binary"],
                fixture_dir=fixture_dir,
                case=case,
            )
            current = (
                process.returncode,
                process.stdout,
                process.stderr,
            )
            if exact is None:
                exact = current
            elif current != exact:
                raise ProbeError(f"qmake/CMake drift: {case.name}")
            observations[oracle_name] = {
                "exit_code": process.returncode,
                "stderr": raw_ref(process.stderr, artifacts),
                "stdout": raw_ref(process.stdout, artifacts),
                "wall_elapsed_ms": elapsed_ms,
            }
        assert exact is not None
        expected = EXPECTED_CASES[case.name]
        summary = stdout_summary(exact[1])
        if exact[0] != expected["exit_code"]:
            raise ProbeError(f"exit changed: {case.name}")
        if exact[2] != b"":
            raise ProbeError(f"stderr changed: {case.name}")
        if sha256(exact[1]) != expected["stdout_sha256"]:
            raise ProbeError(f"stdout changed: {case.name}")
        if summary != expected["summary"]:
            raise ProbeError(f"stdout summary changed: {case.name}")
        prefixes = filename_prefixes(exact[1])
        prefix_summary: dict[str, Any] = {}
        if case.name == "symlink_tree":
            expected_prefixes = [
                "/work/paths/symlink/dir-link/child.pdf",
                "/work/paths/symlink/dir-target/child.pdf",
                "/work/paths/symlink/file-link.pdf",
                "/work/paths/symlink/target.pdf",
            ]
            if prefixes != expected_prefixes:
                raise ProbeError("symlink tree order changed")
            prefix_summary["paths"] = prefixes
        elif case.name == "self_cycle":
            loop_depths = [path.count("/loop") for path in prefixes]
            if loop_depths != list(range(40, -1, -1)):
                raise ProbeError("self-cycle depth sequence changed")
            prefix_summary = {
                "first_path": prefixes[0],
                "last_path": prefixes[-1],
                "loop_depths": loop_depths,
            }
        elif prefixes:
            raise ProbeError(f"unexpected filename prefixes: {case.name}")
        cases[case.name] = {
            "path": case.path,
            "prefix_summary": prefix_summary,
            "summary": summary,
            "timeout_seconds": case.timeout_seconds,
            "user": case.user,
            "observations": observations,
        }

    facts = {
        "dangling_symlink_is_reported_missing": True,
        "deep_64_directory_reaches_leaf": True,
        "denied_directory_is_silently_empty_for_nobody": True,
        "directory_symlink_is_followed": True,
        "file_symlink_is_followed": True,
        "fixture_preflight_passed": True,
        "qmake_and_cmake_outputs_are_byte_equal": True,
        "self_cycle_duplicates_pdf_at_depths_40_through_0": True,
        "symlink_tree_duplicates_file_and_directory_targets": True,
    }
    root = pathlib.Path(__file__).resolve().parents[2]
    return {
        "binaries": {
            "cmake": {
                "path": ORACLES["cmake"]["binary"],
                "sha256": sha256(
                    cmake_files[ORACLES["cmake"]["binary"]]
                ),
                "size": len(
                    cmake_files[ORACLES["cmake"]["binary"]]
                ),
            },
            "qmake": {
                "path": ORACLES["qmake"]["binary"],
                "sha256": sha256(
                    qmake_files[ORACLES["qmake"]["binary"]]
                ),
                "size": len(
                    qmake_files[ORACLES["qmake"]["binary"]]
                ),
            },
        },
        "cases": cases,
        "facts": facts,
        "failures": [],
        "fixture": {
            "archive_sha256": manifest["archive"]["sha256"],
            "archive_size": manifest["archive"]["size"],
            "entry_count": len(manifest["entries"]),
            "extraction_preflight": inspect_extracted_fixture(
                ORACLES["cmake"]["image"], fixture_dir
            ),
            "manifest_path": FIXTURE_MANIFEST,
            "manifest_sha256": sha256(manifest_raw),
        },
        "generator": "tools/upstream/probe_path_filesystem_behavior.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "images": images,
        "local_sources": {
            "baseline_generator": {
                "path": "tools/corpus/generate_baseline_corpus.py",
                "sha256": sha256(
                    (
                        root
                        / "tools"
                        / "corpus"
                        / "generate_baseline_corpus.py"
                    ).read_bytes()
                ),
            },
            "fixture_generator": {
                "path": FIXTURE_GENERATOR,
                "sha256": sha256(
                    (root / FIXTURE_GENERATOR).read_bytes()
                ),
            },
        },
        "passed": all(facts.values()),
        "platform": "linux-x86_64-qt5",
        "raw_artifacts": artifacts,
        "remaining_gap": (
            "CAP-GAP-003: locale/filesystem and cross-platform behavior"
        ),
        "resource_limits": {
            "container_root": "read-only",
            "core_bytes": 0,
            "cpus": 1,
            "fixture_mount": "read-only",
            "memory_bytes": 512 * 1024 * 1024,
            "network": "none",
            "pids": 128,
            "timeout_seconds_default": 30,
            "timeout_seconds_self_cycle": 10,
            "work_tmpfs_bytes": 64 * 1024 * 1024,
        },
        "schema_version": 1,
        "source_contract": {
            "path": SOURCE_PATH,
            "required_patterns": pattern_counts,
            "sha256": sha256(cmake_files[SOURCE_PATH]),
        },
        "upstream_commit": UPSTREAM_COMMIT,
    }


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", required=True, type=pathlib.Path)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=root / FIXTURE_MANIFEST,
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    report = build_report(
        args.fixture_dir.resolve(),
        args.manifest.resolve(),
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

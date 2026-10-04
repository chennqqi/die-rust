#!/usr/bin/env python3
"""Probe pinned Linux Qt5 large-directory enumeration behavior."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import re
import subprocess
import time
from typing import Any
import zlib


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
FIXTURE_GENERATOR = "tools/corpus/generate_large_path_fixture.py"
FIXTURE_MANIFEST = "docs/research/data/large-path-fixture.json"
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
SOURCE_PATHS = (
    "/opt/die-source/Formats/xbinary.cpp",
    "/opt/die-source/Formats/xbinary.h",
    "/opt/die-source/src/console/main_console.cpp",
)
SOURCE_PATTERNS = {
    SOURCE_PATHS[0]: (
        (
            "for (qint32 i = 0; (i < nNumberOfFiles) && "
            "isPdStructNotCanceled(pPdStruct); i++)"
        ),
        (
            "findFiles(eil.at(i).absoluteFilePath(), "
            "pListFileNames, pPdStruct);"
        ),
        "if (pPdStruct) {",
        "if (pPdStruct->bIsStop) {",
    ),
    SOURCE_PATHS[1]: (
        (
            "static void findFiles(const QString &sDirectoryName, "
            "QList<QString> *pListFileNames, "
            "PDSTRUCT *pPdStruct = nullptr);"
        ),
    ),
    SOURCE_PATHS[2]: (
        "XBinary::findFiles(sFileName, &listFileNames);",
    ),
}
CASE_TIMEOUT_SECONDS = 60
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

# Filled from one exploratory run, then enforced by strict report generation.
EXPECTED_STDOUT_SHA256 = {
    "empty_0": EMPTY_SHA256,
    "single_1": (
        "dfffd893cea0ad3d9d925824f634b5ce"
        "aae92cb12bbbadad904e2e329cc9dc87"
    ),
    "flat_256": (
        "ecfda4bbb2774c5a9a4d8b053b89a265"
        "374c9dc994c0f308f7a48b1564fbd901"
    ),
    "flat_4096": (
        "0f4ca62f93978f859199b45bb5177cb1"
        "6da46b26332f52470b44f434613e838a"
    ),
    "nested_4096": (
        "13dd85e56d883e96c46a386b9aa7663e"
        "a93b20e0db26c57f9e38aadd65d77072"
    ),
}


class ProbeError(ValueError):
    """The fixture, fixed Oracle, or observed behavior is invalid."""


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


def load_fixture(path: pathlib.Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    manifest = strict_json(raw)
    if not isinstance(manifest, dict) or set(manifest) != {
        "cases",
        "generator",
        "license",
        "materialization",
        "schema_version",
    }:
        raise ProbeError("fixture manifest fields changed")
    if manifest["schema_version"] != 1:
        raise ProbeError("unsupported fixture schema")
    if manifest["generator"] != FIXTURE_GENERATOR:
        raise ProbeError("unexpected fixture generator")
    materialization = manifest["materialization"]
    if materialization != {
        "bucket_name_pattern": "bucket-{index:03d}",
        "creation_order": "descending",
        "file_name_pattern": "item-{index:06d}.empty",
        "payload_sha256": EMPTY_SHA256,
        "payload_size": 0,
    }:
        raise ProbeError("fixture materialization changed")
    expected_cases = {
        "empty_0": ("flat", 0, 0, 0),
        "single_1": ("flat", 1, 0, 0),
        "flat_256": ("flat", 256, 0, 0),
        "flat_4096": ("flat", 4096, 0, 0),
        "nested_4096": ("nested", 4096, 16, 256),
    }
    cases = manifest["cases"]
    if not isinstance(cases, list):
        raise ProbeError("fixture cases must be a list")
    observed_names = [case.get("name") for case in cases]
    if observed_names != list(expected_cases):
        raise ProbeError("fixture case order changed")
    for case in cases:
        expected = expected_cases[case["name"]]
        actual = (
            case.get("layout"),
            case.get("file_count"),
            case.get("bucket_count"),
            case.get("files_per_bucket"),
        )
        if actual != expected:
            raise ProbeError(f"fixture case changed: {case['name']}")
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


WRAPPER = r"""
import base64
import json
import pathlib
import resource
import subprocess
import sys
import time
import zlib

binary = sys.argv[1]
layout = sys.argv[2]
count = int(sys.argv[3])
bucket_count = int(sys.argv[4])
files_per_bucket = int(sys.argv[5])
root = pathlib.Path("/work/case")
root.mkdir()

if layout == "flat":
    for index in range(count - 1, -1, -1):
        (root / f"item-{index:06d}.empty").touch()
elif layout == "nested":
    for bucket in range(bucket_count - 1, -1, -1):
        directory = root / f"bucket-{bucket:03d}"
        directory.mkdir()
        for index in range(files_per_bucket - 1, -1, -1):
            (directory / f"item-{index:06d}.empty").touch()
else:
    raise SystemExit("unknown layout")

files = sorted(path for path in root.rglob("*") if path.is_file())
root_entries = sorted(path.name for path in root.iterdir())
command = [
    binary,
    "--entropy",
    "--json",
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
    str(root),
]
started = time.monotonic_ns()
process = subprocess.run(
    command,
    capture_output=True,
    check=False,
    timeout=60,
)
elapsed_ns = time.monotonic_ns() - started
usage = resource.getrusage(resource.RUSAGE_CHILDREN)

def encoded(value):
    compressed = zlib.compress(value, 9)
    return {
        "base64": base64.b64encode(compressed).decode("ascii"),
        "bytes": len(value),
        "encoding": "zlib+base64",
    }

print(json.dumps({
    "exit_code": process.returncode,
    "stdout": encoded(process.stdout),
    "stderr": encoded(process.stderr),
    "preflight": {
        "first_file": str(files[0]) if files else None,
        "last_file": str(files[-1]) if files else None,
        "recursive_file_count": len(files),
        "root_entries": root_entries,
        "root_entry_count": len(root_entries),
    },
    "usage": {
        "major_page_faults": usage.ru_majflt,
        "max_rss_kib": usage.ru_maxrss,
        "system_cpu_ns": round(usage.ru_stime * 1000000000),
        "user_cpu_ns": round(usage.ru_utime * 1000000000),
        "wall_elapsed_ns": elapsed_ns,
    },
}, sort_keys=True))
"""


def docker_prefix(image: str) -> list[str]:
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
        image,
    ]


def decode_stream(record: Any) -> bytes:
    if (
        not isinstance(record, dict)
        or set(record) != {"base64", "bytes", "encoding"}
        or record["encoding"] != "zlib+base64"
        or not isinstance(record["bytes"], int)
        or record["bytes"] < 0
    ):
        raise ProbeError("wrapper stream record changed")
    try:
        compressed = base64.b64decode(record["base64"], validate=True)
        raw = zlib.decompress(compressed)
    except (ValueError, zlib.error) as error:
        raise ProbeError("invalid wrapper stream encoding") from error
    if len(raw) != record["bytes"]:
        raise ProbeError("wrapper stream size changed")
    return raw


def run_case(
    *,
    image: str,
    binary: str,
    case: dict[str, Any],
) -> dict[str, Any]:
    command = [
        *docker_prefix(image),
        "python3",
        "-c",
        WRAPPER,
        binary,
        case["layout"],
        str(case["file_count"]),
        str(case["bucket_count"]),
        str(case["files_per_bucket"]),
    ]
    started = time.monotonic()
    process = subprocess.run(
        command,
        capture_output=True,
        timeout=CASE_TIMEOUT_SECONDS + 30,
        check=False,
    )
    host_elapsed_ms = round((time.monotonic() - started) * 1000)
    if process.returncode != 0:
        raise ProbeError(
            f"wrapper failed for {case['name']}: "
            f"exit={process.returncode}, stderr={process.stderr!r}"
        )
    if process.stderr:
        raise ProbeError(f"wrapper stderr changed: {case['name']}")
    result = strict_json(process.stdout)
    if not isinstance(result, dict) or set(result) != {
        "exit_code",
        "preflight",
        "stderr",
        "stdout",
        "usage",
    }:
        raise ProbeError(f"wrapper result fields changed: {case['name']}")
    result["stdout_raw"] = decode_stream(result.pop("stdout"))
    result["stderr_raw"] = decode_stream(result.pop("stderr"))
    result["host_wall_elapsed_ms"] = host_elapsed_ms
    return result


def expected_prefixes(case: dict[str, Any]) -> list[str]:
    count = case["file_count"]
    if count <= 1:
        return []
    if case["layout"] == "flat":
        return [
            f"/work/case/item-{index:06d}.empty"
            for index in range(count)
        ]
    return [
        (
            f"/work/case/bucket-{bucket:03d}/"
            f"item-{index:06d}.empty"
        )
        for bucket in range(case["bucket_count"])
        for index in range(case["files_per_bucket"])
    ]


def filename_prefixes(stdout: bytes) -> list[str]:
    return [
        value.decode("utf-8")
        for value in re.findall(
            rb"(?m)^(/work/case/.*\.empty):$",
            stdout,
        )
    ]


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


def source_contract(files: dict[str, bytes]) -> dict[str, Any]:
    result = {}
    for path, patterns in SOURCE_PATTERNS.items():
        raw = files[path]
        text = raw.decode("utf-8")
        records = {}
        for pattern in patterns:
            lines = [
                index
                for index, line in enumerate(text.splitlines(), start=1)
                if pattern in line
            ]
            if not lines:
                raise ProbeError(f"source contract changed: {path}: {pattern}")
            records[pattern] = {
                "count": len(lines),
                "lines": lines,
            }
        result[path] = {
            "required_patterns": records,
            "sha256": sha256(raw),
            "size": len(raw),
        }
    return result


def validate_preflight(case: dict[str, Any], value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "first_file",
        "last_file",
        "recursive_file_count",
        "root_entries",
        "root_entry_count",
    }:
        raise ProbeError(f"preflight fields changed: {case['name']}")
    if value["recursive_file_count"] != case["file_count"]:
        raise ProbeError(f"preflight file count changed: {case['name']}")
    if case["layout"] == "flat":
        if value["root_entry_count"] != case["file_count"]:
            raise ProbeError(f"flat root count changed: {case['name']}")
    else:
        if value["root_entry_count"] != case["bucket_count"]:
            raise ProbeError(f"nested root count changed: {case['name']}")
    if case["file_count"] == 0:
        if value["first_file"] is not None or value["last_file"] is not None:
            raise ProbeError("empty preflight contains files")
    elif case["layout"] == "flat":
        if value["first_file"] != "/work/case/item-000000.empty":
            raise ProbeError(f"flat first file changed: {case['name']}")
        if value["last_file"] != (
            f"/work/case/item-{case['file_count'] - 1:06d}.empty"
        ):
            raise ProbeError(f"flat last file changed: {case['name']}")
    else:
        if value["first_file"] != (
            "/work/case/bucket-000/item-000000.empty"
        ):
            raise ProbeError("nested first file changed")
        if value["last_file"] != (
            "/work/case/bucket-015/item-000255.empty"
        ):
            raise ProbeError("nested last file changed")


def build_report(
    manifest_path: pathlib.Path,
    *,
    strict_expected_hashes: bool = True,
) -> dict[str, Any]:
    manifest, manifest_raw = load_fixture(manifest_path)
    if strict_expected_hashes and set(EXPECTED_STDOUT_SHA256) != {
        case["name"] for case in manifest["cases"]
    }:
        raise ProbeError("expected stdout hash inventory is incomplete")

    images = {
        name: inspect_image(name, oracle["image"])
        for name, oracle in ORACLES.items()
    }
    cmake_files = read_container_files(
        ORACLES["cmake"]["image"],
        (ORACLES["cmake"]["binary"], *SOURCE_PATHS),
    )
    qmake_files = read_container_files(
        ORACLES["qmake"]["image"],
        (ORACLES["qmake"]["binary"],),
    )
    sources = source_contract(cmake_files)
    artifacts: dict[str, dict[str, Any]] = {}
    cases: dict[str, Any] = {}
    for case in manifest["cases"]:
        observations = {}
        exact: tuple[int, bytes, bytes] | None = None
        shared_preflight = None
        for oracle_name, oracle in ORACLES.items():
            run = run_case(
                image=oracle["image"],
                binary=oracle["binary"],
                case=case,
            )
            validate_preflight(case, run["preflight"])
            if shared_preflight is None:
                shared_preflight = run["preflight"]
            elif run["preflight"] != shared_preflight:
                raise ProbeError(f"preflight oracle drift: {case['name']}")
            current = (
                run["exit_code"],
                run["stdout_raw"],
                run["stderr_raw"],
            )
            if exact is None:
                exact = current
            elif current != exact:
                raise ProbeError(f"qmake/CMake output drift: {case['name']}")
            observations[oracle_name] = {
                "exit_code": run["exit_code"],
                "host_wall_elapsed_ms": run["host_wall_elapsed_ms"],
                "stderr": raw_ref(run["stderr_raw"], artifacts),
                "stdout": raw_ref(run["stdout_raw"], artifacts),
                "usage": run["usage"],
            }
        assert exact is not None
        if exact[0] != 0 or exact[2] != b"":
            raise ProbeError(f"case did not cleanly succeed: {case['name']}")
        prefixes = filename_prefixes(exact[1])
        expected = expected_prefixes(case)
        if prefixes != expected:
            raise ProbeError(f"enumeration order changed: {case['name']}")
        entropy_document_count = exact[1].count(b'"total": 0')
        if entropy_document_count != case["file_count"]:
            raise ProbeError(f"file result count changed: {case['name']}")
        digest = sha256(exact[1])
        if (
            strict_expected_hashes
            and digest != EXPECTED_STDOUT_SHA256[case["name"]]
        ):
            raise ProbeError(f"stdout hash changed: {case['name']}")
        cases[case["name"]] = {
            "bucket_count": case["bucket_count"],
            "entropy_document_count": entropy_document_count,
            "file_count": case["file_count"],
            "files_per_bucket": case["files_per_bucket"],
            "first_prefix": prefixes[0] if prefixes else None,
            "last_prefix": prefixes[-1] if prefixes else None,
            "layout": case["layout"],
            "observations": observations,
            "prefix_count": len(prefixes),
            "prefixes_sha256": sha256(
                ("\n".join(prefixes) + ("\n" if prefixes else "")).encode()
            ),
            "preflight": shared_preflight,
            "stdout_sha256": digest,
        }

    facts = {
        "all_4096_flat_files_are_emitted": (
            cases["flat_4096"]["entropy_document_count"] == 4096
        ),
        "all_4096_nested_files_are_emitted": (
            cases["nested_4096"]["entropy_document_count"] == 4096
        ),
        "creation_order_does_not_override_qdir_name_order": True,
        "cli_find_files_uses_default_null_pdstruct": True,
        "cli_target_expansion_has_no_wired_cooperative_cancel": True,
        "find_files_optional_pdstruct_supports_cancel_checks": True,
        "qmake_and_cmake_outputs_are_byte_equal": True,
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
            "manifest_path": FIXTURE_MANIFEST,
            "manifest_sha256": sha256(manifest_raw),
            "materialization": manifest["materialization"],
        },
        "generator": "tools/upstream/probe_large_path_behavior.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "images": images,
        "local_sources": {
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
            "CAP-GAP-003: TOCTOU and remaining Linux "
            "locale/filesystem behavior"
        ),
        "resource_limits": {
            "container_root": "read-only",
            "core_bytes": 0,
            "cpus": 1,
            "memory_bytes": 512 * 1024 * 1024,
            "network": "none",
            "pids": 128,
            "timeout_seconds": CASE_TIMEOUT_SECONDS,
            "work_tmpfs_bytes": 64 * 1024 * 1024,
        },
        "schema_version": 1,
        "source_contract": sources,
        "upstream_commit": UPSTREAM_COMMIT,
    }


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=root / FIXTURE_MANIFEST,
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--explore",
        action="store_true",
        help="permit missing frozen stdout hashes for initial investigation",
    )
    args = parser.parse_args()
    report = build_report(
        args.manifest.resolve(),
        strict_expected_hashes=not args.explore,
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

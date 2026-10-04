#!/usr/bin/env python3
"""Probe pinned Linux Qt5 path ordering across locale and filesystems."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import time
from typing import Any
import zlib


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
FIXTURE_GENERATOR = "tools/corpus/generate_path_locale_fixture.py"
FIXTURE_MANIFEST = "docs/research/data/path-locale-fixture.json"
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
    "/opt/die-source/src/console/main_console.cpp",
)
SOURCE_PATTERNS = {
    SOURCE_PATHS[0]: (
        "QFileInfoList eil = dir.entryInfoList();",
        (
            "findFiles(eil.at(i).absoluteFilePath(), "
            "pListFileNames, pPdStruct);"
        ),
    ),
    SOURCE_PATHS[1]: (
        "XBinary::findFiles(sFileName, &listFileNames);",
    ),
}
DATABASE_ARGS = (
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
)
LOCALES = ("C", "C.utf8", "POSIX")
FILESYSTEMS = {
    "tmpfs": {
        "docker_mount": "tmpfs",
        "expected_type": "tmpfs",
    },
    "volume": {
        "docker_mount": "anonymous-volume",
        "expected_type": "ext2/ext3",
    },
}
CASE_TIMEOUT_SECONDS = 60
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

# Filled from the exploratory run and enforced for normal report generation.
TMPFS_STDOUT_SHA256 = (
    "a1e9b785a9537df7db272c6105d78f34"
    "fdcfd52ffefad441cc93de58bbe47d4b"
)
VOLUME_STDOUT_SHA256 = (
    "6f69fc47642575a28b3e2210a7b390d8"
    "21caba9421b98645089455a78e6e4191"
)
TMPFS_PREFIXES = (
    "/work/case/ leading-space.empty",
    "/work/case/--leading-dash.empty",
    "/work/case/00-digit.empty",
    "/work/case/_underscore.empty",
    "/work/case/a-case.empty",
    "/work/case/A-case.empty",
    "/work/case/emoji-\U0001f600.empty",
    "/work/case/e\u0301-nfd.empty",
    "/work/case/I-ascii.empty",
    "/work/case/i-ascii.empty",
    "/work/case/\u0130-turkish-capital.empty",
    "/work/case/z-last.empty",
    "/work/case/\u00e4-german.empty",
    "/work/case/\u00e5-swedish.empty",
    "/work/case/\u00e9-nfc.empty",
    "/work/case/\u0131-turkish-small.empty",
    "/work/case/\u4e2d\u6587.empty",
)
VOLUME_PREFIXES = (
    *TMPFS_PREFIXES[:4],
    "/work/case/A-case.empty",
    "/work/case/a-case.empty",
    *TMPFS_PREFIXES[6:],
)
EXPECTED_STDOUT_SHA256 = {
    f"{locale_name}/tmpfs": TMPFS_STDOUT_SHA256
    for locale_name in LOCALES
} | {
    f"{locale_name}/volume": VOLUME_STDOUT_SHA256
    for locale_name in LOCALES
}
EXPECTED_PREFIXES = {
    f"{locale_name}/tmpfs": TMPFS_PREFIXES
    for locale_name in LOCALES
} | {
    f"{locale_name}/volume": VOLUME_PREFIXES
    for locale_name in LOCALES
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
    required = {
        "filesystems",
        "generator",
        "license",
        "locales",
        "materialization",
        "names",
        "schema_version",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ProbeError("fixture manifest fields changed")
    if manifest["schema_version"] != 1:
        raise ProbeError("unsupported fixture schema")
    if manifest["generator"] != FIXTURE_GENERATOR:
        raise ProbeError("unexpected fixture generator")
    if manifest["locales"] != list(LOCALES):
        raise ProbeError("locale matrix changed")
    if manifest["filesystems"] != [
        {"name": name, **record}
        for name, record in FILESYSTEMS.items()
    ]:
        raise ProbeError("filesystem matrix changed")
    if manifest["materialization"] != {
        "creation_order": "reverse-manifest",
        "payload_sha256": EMPTY_SHA256,
        "payload_size": 0,
    }:
        raise ProbeError("fixture materialization changed")
    names = manifest["names"]
    if not isinstance(names, list) or len(names) != 21:
        raise ProbeError("raw-name matrix changed")
    ids: set[str] = set()
    raw_names: set[bytes] = set()
    valid_count = invalid_count = hidden_count = 0
    for record in names:
        if not isinstance(record, dict) or set(record) != {
            "hidden",
            "id",
            "path_bytes_hex",
            "utf8",
            "valid_utf8",
        }:
            raise ProbeError("raw-name record fields changed")
        if record["id"] in ids:
            raise ProbeError("duplicate raw-name id")
        ids.add(record["id"])
        try:
            name = bytes.fromhex(record["path_bytes_hex"])
        except (TypeError, ValueError) as error:
            raise ProbeError("invalid raw-name hex") from error
        if name in raw_names or b"/" in name or b"\x00" in name:
            raise ProbeError("unsafe or duplicate raw name")
        raw_names.add(name)
        try:
            decoded = name.decode("utf-8")
        except UnicodeDecodeError:
            decoded = None
        if record["valid_utf8"]:
            valid_count += 1
            if decoded != record["utf8"]:
                raise ProbeError("valid UTF-8 record changed")
        else:
            invalid_count += 1
            if decoded is not None or record["utf8"] is not None:
                raise ProbeError("invalid UTF-8 record changed")
        hidden_count += int(record["hidden"])
    if (valid_count, invalid_count, hidden_count) != (18, 3, 1):
        raise ProbeError("raw-name category counts changed")
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


def available_locales(image: str) -> list[str]:
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            image,
            "locale",
            "-a",
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ProbeError("locale inventory emitted stderr")
    return process.stdout.decode("ascii").splitlines()


WRAPPER = r"""
import base64
import json
import os
import resource
import subprocess
import sys
import time
import zlib

binary = sys.argv[1]
locale_name = sys.argv[2]
name_hex = json.loads(sys.argv[3])
root = b"/work/case"
os.mkdir(root)
for value in reversed(name_hex):
    path = root + b"/" + bytes.fromhex(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)

entries = sorted(value.hex() for value in os.listdir(root))
environment = os.environ.copy()
environment["LC_ALL"] = locale_name
environment["LANG"] = locale_name
charmap = subprocess.run(
    ["locale", "charmap"],
    env=environment,
    check=True,
    capture_output=True,
).stdout.decode("ascii").strip()
filesystem_type = subprocess.run(
    ["stat", "-f", "-c", "%T", "/work"],
    check=True,
    capture_output=True,
).stdout.decode("ascii").strip()
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
    "/work/case",
]
started = time.monotonic_ns()
process = subprocess.run(
    command,
    env=environment,
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
        "charmap": charmap,
        "filesystem_type": filesystem_type,
        "name_hex": entries,
        "name_count": len(entries),
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


def docker_prefix(image: str, filesystem: str) -> list[str]:
    command = [
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
    ]
    if filesystem == "tmpfs":
        command.extend(
            ["--tmpfs", "/work:rw,noexec,nosuid,nodev,size=16m"]
        )
    elif filesystem == "volume":
        command.extend(
            [
                "--mount",
                "type=volume,dst=/work,volume-nocopy",
            ]
        )
    else:
        raise ProbeError(f"unknown filesystem: {filesystem}")
    command.append(image)
    return command


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
    filesystem: str,
    locale_name: str,
    name_hex: list[str],
) -> dict[str, Any]:
    command = [
        *docker_prefix(image, filesystem),
        "python3",
        "-c",
        WRAPPER,
        binary,
        locale_name,
        json.dumps(name_hex, separators=(",", ":")),
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
            f"wrapper failed for {locale_name}/{filesystem}: "
            f"exit={process.returncode}, stderr={process.stderr!r}"
        )
    if process.stderr:
        raise ProbeError(
            f"wrapper stderr changed: {locale_name}/{filesystem}"
        )
    result = strict_json(process.stdout)
    if not isinstance(result, dict) or set(result) != {
        "exit_code",
        "preflight",
        "stderr",
        "stdout",
        "usage",
    }:
        raise ProbeError("wrapper result fields changed")
    result["stdout_raw"] = decode_stream(result.pop("stdout"))
    result["stderr_raw"] = decode_stream(result.pop("stderr"))
    result["host_wall_elapsed_ms"] = host_elapsed_ms
    return result


def filename_prefixes(stdout: bytes) -> list[str]:
    values: list[str] = []
    for line in stdout.splitlines():
        if line.startswith(b"/work/case/") and line.endswith(b":"):
            try:
                values.append(line[:-1].decode("utf-8"))
            except UnicodeDecodeError as error:
                raise ProbeError("filename prefix is not UTF-8") from error
    return values


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
            records[pattern] = {"count": len(lines), "lines": lines}
        result[path] = {
            "required_patterns": records,
            "sha256": sha256(raw),
            "size": len(raw),
        }
    return result


def validate_preflight(
    *,
    value: Any,
    expected_names: list[str],
    filesystem: str,
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "charmap",
        "filesystem_type",
        "name_count",
        "name_hex",
    }:
        raise ProbeError("preflight fields changed")
    if value["name_count"] != len(expected_names):
        raise ProbeError("preflight name count changed")
    if value["name_hex"] != sorted(expected_names):
        raise ProbeError("preflight raw-name inventory changed")
    if value["filesystem_type"] != FILESYSTEMS[filesystem]["expected_type"]:
        raise ProbeError("mounted filesystem type changed")
    if not isinstance(value["charmap"], str) or not value["charmap"]:
        raise ProbeError("locale charmap missing")


def build_report(
    manifest_path: pathlib.Path,
    *,
    strict_expected_hashes: bool = True,
) -> dict[str, Any]:
    manifest, manifest_raw = load_fixture(manifest_path)
    matrix_keys = {
        f"{locale_name}/{filesystem}"
        for locale_name in LOCALES
        for filesystem in FILESYSTEMS
    }
    if (
        strict_expected_hashes
        and (
            set(EXPECTED_STDOUT_SHA256) != matrix_keys
            or set(EXPECTED_PREFIXES) != matrix_keys
        )
    ):
        raise ProbeError("expected output inventory is incomplete")
    images = {
        name: inspect_image(name, oracle["image"])
        for name, oracle in ORACLES.items()
    }
    locale_inventory = {
        name: available_locales(oracle["image"])
        for name, oracle in ORACLES.items()
    }
    for name, values in locale_inventory.items():
        if values != list(LOCALES):
            raise ProbeError(f"available locale inventory changed: {name}")
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
    observations: dict[str, Any] = {}
    name_hex = [record["path_bytes_hex"] for record in manifest["names"]]
    visible_valid_count = sum(
        record["valid_utf8"] and not record["hidden"]
        for record in manifest["names"]
    )
    matrix_outputs: dict[str, bytes] = {}
    matrix_prefixes: dict[str, list[str]] = {}
    for locale_name in LOCALES:
        for filesystem in FILESYSTEMS:
            key = f"{locale_name}/{filesystem}"
            oracle_records = {}
            pair_output: tuple[int, bytes, bytes] | None = None
            pair_preflight = None
            for oracle_name, oracle in ORACLES.items():
                run = run_case(
                    image=oracle["image"],
                    binary=oracle["binary"],
                    filesystem=filesystem,
                    locale_name=locale_name,
                    name_hex=name_hex,
                )
                validate_preflight(
                    value=run["preflight"],
                    expected_names=name_hex,
                    filesystem=filesystem,
                )
                if pair_preflight is None:
                    pair_preflight = run["preflight"]
                elif run["preflight"] != pair_preflight:
                    raise ProbeError(f"preflight oracle drift: {key}")
                current = (
                    run["exit_code"],
                    run["stdout_raw"],
                    run["stderr_raw"],
                )
                if pair_output is None:
                    pair_output = current
                elif current != pair_output:
                    raise ProbeError(f"qmake/CMake output drift: {key}")
                oracle_records[oracle_name] = {
                    "exit_code": run["exit_code"],
                    "host_wall_elapsed_ms": run["host_wall_elapsed_ms"],
                    "stderr": raw_ref(run["stderr_raw"], artifacts),
                    "stdout": raw_ref(run["stdout_raw"], artifacts),
                    "usage": run["usage"],
                }
            assert pair_output is not None
            if pair_output[0] != 0 or pair_output[2] != b"":
                raise ProbeError(f"case did not cleanly succeed: {key}")
            prefixes = filename_prefixes(pair_output[1])
            if len(prefixes) != visible_valid_count:
                raise ProbeError(f"visible file count changed: {key}")
            if strict_expected_hashes:
                if sha256(pair_output[1]) != EXPECTED_STDOUT_SHA256[key]:
                    raise ProbeError(f"stdout hash changed: {key}")
                if tuple(prefixes) != EXPECTED_PREFIXES[key]:
                    raise ProbeError(f"prefix order changed: {key}")
            matrix_outputs[key] = pair_output[1]
            matrix_prefixes[key] = prefixes
            observations[key] = {
                "filesystem": filesystem,
                "locale": locale_name,
                "observations": oracle_records,
                "prefix_count": len(prefixes),
                "prefixes": prefixes,
                "prefixes_sha256": sha256(
                    ("\n".join(prefixes) + "\n").encode("utf-8")
                ),
                "preflight": pair_preflight,
                "stdout_sha256": sha256(pair_output[1]),
            }
    hidden_names = {
        record["utf8"]
        for record in manifest["names"]
        if record["hidden"] and record["utf8"] is not None
    }
    emitted_by_case = {
        key: {
            value.removeprefix("/work/case/") for value in prefixes
        }
        for key, prefixes in matrix_prefixes.items()
    }
    reverse_creation_prefixes = [
        "/work/case/" + record["utf8"]
        for record in reversed(manifest["names"])
        if record["valid_utf8"] and not record["hidden"]
    ]
    all_matrix_stdout_byte_equal = len(set(matrix_outputs.values())) == 1
    locale_stdout_byte_equal_within_filesystem = all(
        len(
            {
                matrix_outputs[f"{locale_name}/{filesystem}"]
                for locale_name in LOCALES
            }
        )
        == 1
        for filesystem in FILESYSTEMS
    )
    filesystem_stdout_byte_equal_within_locale = all(
        len(
            {
                matrix_outputs[f"{locale_name}/{filesystem}"]
                for filesystem in FILESYSTEMS
            }
        )
        == 1
        for locale_name in LOCALES
    )
    facts = {
        "all_installed_locales_are_covered": True,
        "creation_order_does_not_override_qdir_order": all(
            prefixes != reverse_creation_prefixes
            for prefixes in matrix_prefixes.values()
        ),
        "filesystem_output_profiles_are_characterized": (
            set(matrix_outputs) == matrix_keys
        ),
        "hidden_names_are_filtered": all(
            emitted.isdisjoint(hidden_names)
            for emitted in emitted_by_case.values()
        ),
        "invalid_utf8_names_are_filtered": all(
            len(prefixes) == visible_valid_count
            for prefixes in matrix_prefixes.values()
        ),
        "locale_output_profiles_are_characterized": (
            set(matrix_outputs) == matrix_keys
        ),
        "qmake_and_cmake_outputs_are_byte_equal": True,
        "tmpfs_and_volume_types_are_distinct": (
            FILESYSTEMS["tmpfs"]["expected_type"]
            != FILESYSTEMS["volume"]["expected_type"]
        ),
    }
    root = pathlib.Path(__file__).resolve().parents[2]
    return {
        "binaries": {
            "cmake": {
                "path": ORACLES["cmake"]["binary"],
                "sha256": sha256(
                    cmake_files[ORACLES["cmake"]["binary"]]
                ),
                "size": len(cmake_files[ORACLES["cmake"]["binary"]]),
            },
            "qmake": {
                "path": ORACLES["qmake"]["binary"],
                "sha256": sha256(
                    qmake_files[ORACLES["qmake"]["binary"]]
                ),
                "size": len(qmake_files[ORACLES["qmake"]["binary"]]),
            },
        },
        "facts": facts,
        "failures": [],
        "fixture": {
            "manifest_path": FIXTURE_MANIFEST,
            "manifest_sha256": sha256(manifest_raw),
            "materialization": manifest["materialization"],
        },
        "generator": (
            "tools/upstream/probe_path_locale_filesystem_behavior.py"
        ),
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "images": images,
        "local_sources": {
            "fixture_generator": {
                "path": FIXTURE_GENERATOR,
                "sha256": sha256((root / FIXTURE_GENERATOR).read_bytes()),
            },
        },
        "locale_inventory": locale_inventory,
        "matrix": observations,
        "output_equivalence": {
            "all_matrix_stdout_byte_equal": (
                all_matrix_stdout_byte_equal
            ),
            "filesystem_stdout_byte_equal_within_locale": (
                filesystem_stdout_byte_equal_within_locale
            ),
            "locale_stdout_byte_equal_within_filesystem": (
                locale_stdout_byte_equal_within_filesystem
            ),
        },
        "passed": all(facts.values()),
        "platform": "linux-x86_64-qt5",
        "raw_artifacts": artifacts,
        "remaining_gap": None,
        "resource_limits": {
            "container_root": "read-only",
            "core_bytes": 0,
            "cpus": 1,
            "memory_bytes": 512 * 1024 * 1024,
            "network": "none",
            "pids": 128,
            "timeout_seconds": CASE_TIMEOUT_SECONDS,
            "tmpfs_bytes": 16 * 1024 * 1024,
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
        help="permit missing frozen hashes for initial investigation",
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

#!/usr/bin/env python3
"""Probe pinned Linux Qt5 enumeration/open path TOCTOU behavior."""

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
FIXTURE_GENERATOR = "tools/corpus/generate_path_toctou_fixture.py"
FIXTURE_MANIFEST = "docs/research/data/path-toctou-fixture.json"
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
STDBUF_PATH = "/usr/bin/stdbuf"
SOURCE_PATTERNS = {
    SOURCE_PATHS[0]: (
        "pListFileNames->append(fi.absoluteFilePath());",
    ),
    SOURCE_PATHS[1]: (
        "XBinary::findFiles(sFileName, &listFileNames);",
        "qint32 nNumberOfFiles = listFileNames.count();",
        "QString sFileName = listFileNames.at(i);",
        (
            'printf("%s:\\n", '
            "QDir().toNativeSeparators(sFileName).toUtf8().data());"
        ),
        (
            "EntropyProcess::DATA epData = "
            "EntropyProcess::processRegionsFile(sFileName);"
        ),
    ),
}
CASE_TIMEOUT_SECONDS = 30
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

# Filled from one exploratory run, then enforced for committed evidence.
EXPECTED_STDOUT_SHA256 = {
    "stable_old": (
        "d2bdb2d9ad473838d3529143c33278ab"
        "5d09991f9c0b7755b3bf092f128f2d4c"
    ),
    "stable_new": (
        "49f59670345f16c63d0d1143e8fd219a"
        "1081659da30c5e8d7150ca260a2b4f57"
    ),
    "swap_old_to_new": (
        "49f59670345f16c63d0d1143e8fd219a"
        "1081659da30c5e8d7150ca260a2b4f57"
    ),
    "remove_old_after_enumeration": (
        "31dfa241dfb8647d9949db4fe2a405e8"
        "64c1c298184da4254b4572fa03e948f0"
    ),
}
EXPECTED_BLOCKER_DOCUMENT = {
    "records": [
        {
            "entropy": 0,
            "name": "Data",
            "offset": 0,
            "size": 32 * 1024 * 1024,
            "status": "not packed",
        }
    ],
    "status": "not packed",
    "total": 0,
}
EXPECTED_LINK_DOCUMENTS = {
    "old": {
        "records": [
            {
                "entropy": 0,
                "name": "Data",
                "offset": 0,
                "size": 0,
                "status": "not packed",
            }
        ],
        "status": "not packed",
        "total": 0,
    },
    "new": {
        "records": [
            {
                "entropy": 8,
                "name": "Data",
                "offset": 0,
                "size": 4096,
                "status": "packed",
            }
        ],
        "status": "packed",
        "total": 8,
    },
    "missing": {
        "records": [],
        "status": "",
        "total": 0,
    },
}


class ProbeError(ValueError):
    """The fixture, synchronization, source, or Oracle behavior is invalid."""


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
        "synchronization",
    }:
        raise ProbeError("fixture manifest fields changed")
    if manifest["schema_version"] != 1:
        raise ProbeError("unsupported fixture schema")
    if manifest["generator"] != FIXTURE_GENERATOR:
        raise ProbeError("unexpected fixture generator")
    materialization = manifest["materialization"]
    if (
        materialization["blocker"]["size"] != 32 * 1024 * 1024
        or materialization["old_target"]["size"] != 0
        or materialization["new_target"]["size"] != 4096
        or materialization["link"]["path"] != "/work/case/z-link.bin"
    ):
        raise ProbeError("fixture materialization changed")
    synchronization = manifest["synchronization"]
    if synchronization != {
        "mutation": "after waitpid(WUNTRACED), before SIGCONT",
        "resume_signal": "SIGCONT",
        "stdout": "stdbuf -oL",
        "stop_after_line": "/work/case/a-blocker.bin:",
        "stop_signal": "SIGSTOP",
    }:
        raise ProbeError("fixture synchronization changed")
    expected_cases = {
        "stable_old": ("../targets/old.bin", "none", "old"),
        "stable_new": ("../targets/new.bin", "none", "new"),
        "swap_old_to_new": (
            "../targets/old.bin",
            "replace_symlink_with_new_target",
            "new",
        ),
        "remove_old_after_enumeration": (
            "../targets/old.bin",
            "unlink_symlink",
            "missing",
        ),
    }
    cases = manifest["cases"]
    if [case.get("name") for case in cases] != list(expected_cases):
        raise ProbeError("fixture case order changed")
    for case in cases:
        actual = (
            case.get("initial_target"),
            case.get("action"),
            case.get("expected_open_target"),
        )
        if actual != expected_cases[case["name"]]:
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
import hashlib
import json
import os
import pathlib
import resource
import select
import signal
import subprocess
import sys
import time
import zlib

binary = sys.argv[1]
initial_target = sys.argv[2]
action = sys.argv[3]
case_dir = pathlib.Path("/work/case")
targets = pathlib.Path("/work/targets")
case_dir.mkdir()
targets.mkdir()
blocker = case_dir / "a-blocker.bin"
with blocker.open("wb") as stream:
    stream.truncate(32 * 1024 * 1024)
old_target = targets / "old.bin"
old_target.touch()
new_target = targets / "new.bin"
new_target.write_bytes(bytes(range(256)) * 16)
link = case_dir / "z-link.bin"
link.symlink_to(initial_target)

def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()

def identity(path, follow):
    try:
        stat = path.stat() if follow else path.lstat()
    except FileNotFoundError:
        return None
    return {
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "mode": stat.st_mode,
        "size": stat.st_size,
    }

before = {
    "link_identity": identity(link, False),
    "link_target": os.readlink(link),
    "target_identity": identity(link, True),
}
preflight = {
    "blocker_sha256": file_sha256(blocker),
    "blocker_size": blocker.stat().st_size,
    "new_sha256": file_sha256(new_target),
    "new_size": new_target.stat().st_size,
    "old_sha256": file_sha256(old_target),
    "old_size": old_target.stat().st_size,
}
command = [
    "/usr/bin/stdbuf",
    "-oL",
    binary,
    "--entropy",
    "--json",
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
    str(case_dir),
]
started = time.monotonic_ns()
process = subprocess.Popen(
    command,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    bufsize=0,
)
stopped = False
try:
    ready, _, _ = select.select([process.stdout], [], [], 10)
    if not ready:
        raise RuntimeError("first prefix timeout")
    first_line = process.stdout.readline()
    if first_line != b"/work/case/a-blocker.bin:\n":
        raise RuntimeError(f"unexpected first line: {first_line!r}")
    os.kill(process.pid, signal.SIGSTOP)
    waited_pid, wait_status = os.waitpid(process.pid, os.WUNTRACED)
    if waited_pid != process.pid or not os.WIFSTOPPED(wait_status):
        raise RuntimeError("child did not enter stopped state")
    if os.WSTOPSIG(wait_status) != signal.SIGSTOP:
        raise RuntimeError("child stopped by unexpected signal")
    stopped = True

    if action == "replace_symlink_with_new_target":
        replacement = case_dir / ".replacement-link"
        replacement.symlink_to("../targets/new.bin")
        os.replace(replacement, link)
    elif action == "unlink_symlink":
        link.unlink()
    elif action != "none":
        raise RuntimeError("unknown action")

    after = {
        "link_identity": identity(link, False),
        "link_target": os.readlink(link) if link.is_symlink() else None,
        "target_identity": identity(link, True),
    }
    os.kill(process.pid, signal.SIGCONT)
    stopped = False
    remaining_stdout, stderr = process.communicate(timeout=30)
    stdout = first_line + remaining_stdout
finally:
    if process.poll() is None:
        if stopped:
            os.kill(process.pid, signal.SIGCONT)
        process.kill()
        process.wait()

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
    "after": after,
    "before": before,
    "exit_code": process.returncode,
    "preflight": preflight,
    "stderr": encoded(stderr),
    "stdout": encoded(stdout),
    "synchronization": {
        "first_line": first_line.decode("utf-8").rstrip("\n"),
        "mutation_while_stopped": True,
        "stop_signal": signal.SIGSTOP,
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
        case["initial_target"],
        case["action"],
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
        "after",
        "before",
        "exit_code",
        "preflight",
        "stderr",
        "stdout",
        "synchronization",
        "usage",
    }:
        raise ProbeError(f"wrapper result fields changed: {case['name']}")
    result["stdout_raw"] = decode_stream(result.pop("stdout"))
    result["stderr_raw"] = decode_stream(result.pop("stderr"))
    result["host_wall_elapsed_ms"] = host_elapsed_ms
    return result


def parse_documents(stdout: bytes) -> list[dict[str, Any]]:
    matches = list(
        re.finditer(rb"(?m)^(/work/case/[^:\r\n]+):\n", stdout)
    )
    paths = [match.group(1).decode("utf-8") for match in matches]
    if paths != [
        "/work/case/a-blocker.bin",
        "/work/case/z-link.bin",
    ]:
        raise ProbeError("filename prefix sequence changed")
    documents = []
    for index, match in enumerate(matches):
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(stdout)
        )
        value = strict_json(stdout[match.end() : end])
        if not isinstance(value, dict):
            raise ProbeError("entropy document is not an object")
        documents.append(value)
    return documents


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


def validate_preflight(
    manifest: dict[str, Any],
    case: dict[str, Any],
    run: dict[str, Any],
) -> None:
    materialization = manifest["materialization"]
    expected = {
        "blocker_sha256": materialization["blocker"]["sha256"],
        "blocker_size": materialization["blocker"]["size"],
        "new_sha256": materialization["new_target"]["sha256"],
        "new_size": materialization["new_target"]["size"],
        "old_sha256": materialization["old_target"]["sha256"],
        "old_size": materialization["old_target"]["size"],
    }
    if run["preflight"] != expected:
        raise ProbeError(f"materialization preflight changed: {case['name']}")
    sync = run["synchronization"]
    if (
        sync["first_line"] != "/work/case/a-blocker.bin:"
        or not sync["mutation_while_stopped"]
        or sync["stop_signal"] != 19
    ):
        raise ProbeError(f"synchronization changed: {case['name']}")
    before = run["before"]
    after = run["after"]
    if before["link_target"] != case["initial_target"]:
        raise ProbeError(f"initial link target changed: {case['name']}")
    if before["link_identity"] is None or before["target_identity"] is None:
        raise ProbeError(f"initial identity missing: {case['name']}")
    if case["action"] == "none":
        if after != before:
            raise ProbeError(f"stable identity changed: {case['name']}")
    elif case["action"] == "replace_symlink_with_new_target":
        if (
            after["link_target"] != "../targets/new.bin"
            or after["link_identity"] is None
            or after["target_identity"] is None
            or after["link_identity"]["inode"]
            == before["link_identity"]["inode"]
            or after["target_identity"]["inode"]
            == before["target_identity"]["inode"]
        ):
            raise ProbeError("symlink replacement evidence changed")
    elif case["action"] == "unlink_symlink":
        if after != {
            "link_identity": None,
            "link_target": None,
            "target_identity": None,
        }:
            raise ProbeError("unlink evidence changed")


def build_report(
    manifest_path: pathlib.Path,
    *,
    strict_expected_hashes: bool = True,
) -> dict[str, Any]:
    manifest, manifest_raw = load_fixture(manifest_path)
    case_names = {case["name"] for case in manifest["cases"]}
    if (
        strict_expected_hashes
        and set(EXPECTED_STDOUT_SHA256) != case_names
    ):
        raise ProbeError("expected stdout hash inventory is incomplete")

    images = {
        name: inspect_image(name, oracle["image"])
        for name, oracle in ORACLES.items()
    }
    files_by_oracle = {
        name: read_container_files(
            oracle["image"],
            (oracle["binary"], STDBUF_PATH, *SOURCE_PATHS),
        )
        for name, oracle in ORACLES.items()
    }
    if any(
        files_by_oracle["qmake"][path]
        != files_by_oracle["cmake"][path]
        for path in (*SOURCE_PATHS, STDBUF_PATH)
    ):
        raise ProbeError("qmake/CMake source or stdbuf bytes drift")
    sources = source_contract(files_by_oracle["cmake"])
    artifacts: dict[str, dict[str, Any]] = {}
    cases: dict[str, Any] = {}
    for case in manifest["cases"]:
        observations = {}
        exact: tuple[int, bytes, bytes] | None = None
        shared_mutation = None
        shared_preflight = None
        for oracle_name, oracle in ORACLES.items():
            run = run_case(
                image=oracle["image"],
                binary=oracle["binary"],
                case=case,
            )
            validate_preflight(manifest, case, run)
            mutation = {
                "after": run["after"],
                "before": run["before"],
                "synchronization": run["synchronization"],
            }
            if shared_mutation is None:
                shared_mutation = mutation
                shared_preflight = run["preflight"]
            else:
                # Device/inode values are container-run specific. Compare
                # semantic shape separately; preserve each raw observation.
                if (
                    mutation["before"]["link_target"]
                    != shared_mutation["before"]["link_target"]
                    or mutation["after"]["link_target"]
                    != shared_mutation["after"]["link_target"]
                    or mutation["synchronization"]
                    != shared_mutation["synchronization"]
                ):
                    raise ProbeError(f"mutation oracle drift: {case['name']}")
                if run["preflight"] != shared_preflight:
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
                "after": run["after"],
                "before": run["before"],
                "exit_code": run["exit_code"],
                "host_wall_elapsed_ms": run["host_wall_elapsed_ms"],
                "stderr": raw_ref(run["stderr_raw"], artifacts),
                "stdout": raw_ref(run["stdout_raw"], artifacts),
                "synchronization": run["synchronization"],
                "usage": run["usage"],
            }
        assert exact is not None
        if exact[0] != 0 or exact[2] != b"":
            raise ProbeError(f"case did not cleanly succeed: {case['name']}")
        documents = parse_documents(exact[1])
        if documents[0] != EXPECTED_BLOCKER_DOCUMENT:
            raise ProbeError(f"blocker result changed: {case['name']}")
        if documents[1] != EXPECTED_LINK_DOCUMENTS[
            case["expected_open_target"]
        ]:
            raise ProbeError(f"link result changed: {case['name']}")
        digest = sha256(exact[1])
        if (
            strict_expected_hashes
            and digest != EXPECTED_STDOUT_SHA256[case["name"]]
        ):
            raise ProbeError(f"stdout hash changed: {case['name']}")
        cases[case["name"]] = {
            "action": case["action"],
            "blocker_document": documents[0],
            "expected_open_target": case["expected_open_target"],
            "initial_target": case["initial_target"],
            "link_document": documents[1],
            "link_document_sha256": sha256(
                (
                    json.dumps(
                        documents[1],
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode()
            ),
            "observations": observations,
            "stdout_sha256": digest,
        }

    stable_old = cases["stable_old"]
    stable_new = cases["stable_new"]
    swapped = cases["swap_old_to_new"]
    removed = cases["remove_old_after_enumeration"]
    facts = {
        "logical_symlink_path_prefix_is_preserved": True,
        "qmake_and_cmake_outputs_are_byte_equal": True,
        "remove_after_enumeration_still_scans_stored_path": (
            removed["link_document"] == EXPECTED_LINK_DOCUMENTS["missing"]
            and removed["stdout_sha256"]
            == EXPECTED_STDOUT_SHA256[
                "remove_old_after_enumeration"
            ]
        ),
        "stable_controls_are_distinct": (
            stable_old["link_document"] != stable_new["link_document"]
        ),
        "swap_happens_after_full_enumeration_sync_point": True,
        "swap_old_to_new_matches_stable_new": (
            swapped["link_document"] == stable_new["link_document"]
        ),
        "swap_old_to_new_no_longer_matches_stable_old": (
            swapped["link_document"] != stable_old["link_document"]
        ),
        "unlink_result_matches_observed_missing_open": (
            removed["link_document"] == EXPECTED_LINK_DOCUMENTS["missing"]
            and removed["link_document"] != stable_old["link_document"]
        ),
    }
    root = pathlib.Path(__file__).resolve().parents[2]
    return {
        "binaries": {
            name: {
                "path": oracle["binary"],
                "sha256": sha256(
                    files_by_oracle[name][oracle["binary"]]
                ),
                "size": len(
                    files_by_oracle[name][oracle["binary"]]
                ),
            }
            for name, oracle in ORACLES.items()
        },
        "cases": cases,
        "facts": facts,
        "failures": [],
        "fixture": {
            "manifest_path": FIXTURE_MANIFEST,
            "manifest_sha256": sha256(manifest_raw),
            "materialization": manifest["materialization"],
            "synchronization": manifest["synchronization"],
        },
        "generator": "tools/upstream/probe_path_toctou_behavior.py",
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
            "CAP-GAP-003: remaining Linux locale/filesystem behavior"
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
        "stdbuf": {
            "path": STDBUF_PATH,
            "sha256": sha256(
                files_by_oracle["cmake"][STDBUF_PATH]
            ),
            "size": len(files_by_oracle["cmake"][STDBUF_PATH]),
        },
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

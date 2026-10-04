#!/usr/bin/env python3
"""Collect the final native-Windows Qt5 directory-enumeration profiles."""

from __future__ import annotations

import argparse
import base64
import csv
import ctypes
import hashlib
import importlib.util
import io
import json
import ntpath
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_DIR = ROOT / "tools/upstream"
DATA_DIR = ROOT / "docs/research/data"
FIXTURE_GENERATOR = (
    ROOT / "tools/corpus/generate_windows_path_closure_fixture.py"
)
FIXTURE_MANIFEST = (
    DATA_DIR / "windows-path-closure-fixture.json"
)
LARGE_MANIFEST = DATA_DIR / "large-path-fixture.json"
LARGE_LINUX_REPORT = DATA_DIR / "large-path-engine-qt5.json"
TOCTOU_LINUX_REPORT = DATA_DIR / "path-toctou-engine-qt5.json"
WINDOWS_BASELINE = DATA_DIR / "baseline-corpus-windows-qt5.json"
EXPECTED_CLI_SHA256 = (
    "e8579a6ed0d2536ea14af154bcbeeaaea6967c0c7559a595"
    "fb3fe52206ac635e"
)
EXPECTED_XBINARY_SHA256 = (
    "d82bd21326bb7ba07eb343020d50af0ae2cf7e8e534d8e08d07ffa8129913c34"
)
EXPECTED_CONSOLE_SHA256 = (
    "ebb82a94fdd0f54722ea36589d6a35694ec4022bc9179030dae6a85e7a9d7e8f"
)
EXPECTED_LARGE_MANIFEST_SHA256 = (
    "67a29846d009f10b6448021f651d6b7e8bed0c16124f16c2b07f55085e2dd26a"
)
EXPECTED_LARGE_REPORT_SHA256 = (
    "100562d79fa661055fd79e0efe6ce8f58a31b8e4faebedf410f80f51e817883b"
)
EXPECTED_TOCTOU_REPORT_SHA256 = (
    "733b136667c39f46e2d32bfb6a15c7da7077eee98232d7ff3a06a812f6913cf9"
)
EXPECTED_WINDOWS_BASELINE_SHA256 = (
    "6beba732e88d90ed1414dd2584a4a783eac24dec70103fc54e6214eb12cca998"
)
WSL_ROOT = "/tmp/die-rust-windows-path-closure-74eaf505-evidence"
MULTI_DOCUMENT_PREFIX = re.compile(r"(?m)^(.+):\r?\n(?=\{)")


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load helper module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


baseline = load_module(
    "collect_windows_path_closure_baseline",
    UPSTREAM_DIR / "collect_windows_cli_baseline.py",
)
fixture_generator = load_module(
    "collect_windows_path_closure_fixture",
    FIXTURE_GENERATOR,
)
ProbeError = baseline.BaselineError


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def strict_json(data: bytes, description: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProbeError(
                    f"non-finite JSON in {description}: {value}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError(
            f"invalid JSON in {description}: {error}"
        ) from error


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def validate_input_reports() -> dict[str, Any]:
    fixture_raw = FIXTURE_MANIFEST.read_bytes()
    fixture = strict_json(fixture_raw, "path closure fixture")
    if (
        fixture_raw
        != fixture_generator.serialize(
            fixture_generator.build_manifest()
        )
        or fixture.get("capability") != "CAP-CLI-IN-003"
    ):
        raise ProbeError("path closure fixture manifest differs")

    large_raw = LARGE_MANIFEST.read_bytes()
    large = strict_json(large_raw, "large path fixture")
    large_report_raw = LARGE_LINUX_REPORT.read_bytes()
    large_report = strict_json(
        large_report_raw,
        "Linux large path report",
    )
    toctou_raw = TOCTOU_LINUX_REPORT.read_bytes()
    toctou_report = strict_json(
        toctou_raw,
        "Linux TOCTOU report",
    )
    baseline_raw = WINDOWS_BASELINE.read_bytes()
    windows_baseline = strict_json(
        baseline_raw,
        "Windows baseline",
    )
    if (
        sha256(large_raw) != EXPECTED_LARGE_MANIFEST_SHA256
        or sha256(large_report_raw)
        != EXPECTED_LARGE_REPORT_SHA256
        or sha256(toctou_raw) != EXPECTED_TOCTOU_REPORT_SHA256
        or sha256(baseline_raw)
        != EXPECTED_WINDOWS_BASELINE_SHA256
        or large.get("cases") is None
        or large_report.get("passed") is not True
        or not all(large_report.get("facts", {}).values())
        or toctou_report.get("passed") is not True
        or not all(toctou_report.get("facts", {}).values())
        or windows_baseline.get("binary", {}).get("sha256")
        != EXPECTED_CLI_SHA256
    ):
        raise ProbeError("path closure reference report differs")
    return {
        "fixture": fixture,
        "fixture_raw": fixture_raw,
        "large": large,
        "large_raw": large_raw,
        "large_report_raw": large_report_raw,
        "toctou_report_raw": toctou_raw,
        "windows_baseline": windows_baseline,
        "windows_baseline_raw": baseline_raw,
    }


def observe_source(source_dir: Path) -> dict[str, Any]:
    paths = {
        "xbinary": source_dir / "Formats/xbinary.cpp",
        "console": source_dir / "src/console/main_console.cpp",
    }
    raw = {name: path.read_bytes() for name, path in paths.items()}
    hashes = {name: sha256(data) for name, data in raw.items()}
    if hashes != {
        "xbinary": EXPECTED_XBINARY_SHA256,
        "console": EXPECTED_CONSOLE_SHA256,
    }:
        raise ProbeError("Windows path source identity differs")
    text = {
        name: data.decode("utf-8") for name, data in raw.items()
    }
    required = {
        "find_files_entry_list": (
            text["xbinary"].count(
                "QFileInfoList eil = dir.entryInfoList();"
            )
        ),
        "find_files_recursive_call": (
            text["xbinary"].count(
                "findFiles(eil.at(i).absoluteFilePath(), "
                "pListFileNames, pPdStruct);"
            )
        ),
        "find_files_append": (
            text["xbinary"].count(
                "pListFileNames->append(fi.absoluteFilePath());"
            )
        ),
        "cli_freezes_file_count": (
            text["console"].count(
                "qint32 nNumberOfFiles = listFileNames.count();"
            )
        ),
        "cli_opens_frozen_path": (
            text["console"].count(
                "EntropyProcess::processRegionsFile(sFileName);"
            )
        ),
    }
    if any(count < 1 for count in required.values()):
        raise ProbeError("Windows path source contract differs")
    start = text["xbinary"].index(
        "void XBinary::findFiles("
        "const QString &sDirectoryName, "
        "QList<QString> *pListFileNames, "
        "PDSTRUCT *pPdStruct)"
    )
    end = text["xbinary"].index(
        "void XBinary::findFiles(",
        start + 1,
    )
    console_start = text["console"].index(
        "XOptions::CR ScanFiles("
    )
    console_end = text["console"].index(
        "\nint main(",
        console_start + 1,
    )
    contract = (
        text["xbinary"][start:end]
        + text["console"][console_start:console_end]
    ).lower()
    negative = {
        token: len(
            re.findall(
                rf"\b{re.escape(token)}\b",
                contract,
            )
        )
        for token in (
            "acl",
            "domain",
            "reparse",
            "securitydescriptor",
            "unc",
        )
    }
    if any(negative.values()):
        raise ProbeError("platform-specific path branch appeared")
    return {
        "paths": {
            "xbinary": "<source>/Formats/xbinary.cpp",
            "console": "<source>/src/console/main_console.cpp",
        },
        "sha256": hashes,
        "required_pattern_counts": required,
        "negative_platform_token_counts": negative,
        "find_files_start_line": (
            text["xbinary"][:start].count("\n") + 1
        ),
        "find_files_end_line": (
            text["xbinary"][:end].count("\n") + 1
        ),
        "scan_files_start_line": (
            text["console"][:console_start].count("\n") + 1
        ),
        "scan_files_end_line": (
            text["console"][:console_end].count("\n") + 1
        ),
    }


def database_arguments(source_dir: Path) -> list[str]:
    return [
        "--database",
        str(source_dir / "Detect-It-Easy/db"),
        "--extradatabase",
        str(source_dir / "Detect-It-Easy/db_extra"),
        "--customdatabase",
        str(source_dir / "Detect-It-Easy/db_custom"),
    ]


def peak_working_set_kib(process: subprocess.Popen[Any]) -> int:
    counters = PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(counters)
    ok = ctypes.windll.psapi.GetProcessMemoryInfo(
        int(process._handle),  # type: ignore[attr-defined]
        ctypes.byref(counters),
        ctypes.sizeof(counters),
    )
    return (
        int(counters.PeakWorkingSetSize // 1024)
        if ok
        else -1
    )


def run_to_files(
    *,
    binary: Path,
    arguments: list[str],
    cwd: Path,
    qt_dir: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: int,
    sync_threshold: int | None = None,
    on_sync: Callable[[], None] | None = None,
) -> dict[str, Any]:
    environment = os.environ.copy()
    path_key = next(
        (key for key in environment if key.upper() == "PATH"),
        "PATH",
    )
    environment[path_key] = (
        str(qt_dir / "bin")
        + os.pathsep
        + environment.get(path_key, "")
    )
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    synchronized = False
    timed_out = False
    peak_kib = -1
    with (
        stdout_path.open("wb") as stdout_file,
        stderr_path.open("wb") as stderr_file,
    ):
        process = subprocess.Popen(
            [binary.name, *arguments],
            executable=str(binary),
            cwd=cwd,
            env=environment,
            stdout=stdout_file,
            stderr=stderr_file,
        )
        while process.poll() is None:
            peak_kib = max(peak_kib, peak_working_set_kib(process))
            if (
                not synchronized
                and sync_threshold is not None
                and stdout_path.stat().st_size >= sync_threshold
            ):
                if on_sync is not None:
                    on_sync()
                synchronized = True
            if time.monotonic() - started >= timeout_seconds:
                timed_out = True
                process.kill()
                break
            time.sleep(0.005)
        process.wait()
        peak_kib = max(peak_kib, peak_working_set_kib(process))
    elapsed_ms = round((time.monotonic() - started) * 1000)
    stdout = stdout_path.read_bytes()
    stderr = stderr_path.read_bytes()
    return {
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "wall_elapsed_ms": elapsed_ms,
        "peak_working_set_kib": peak_kib,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": sha256(stdout),
        "stderr_sha256": sha256(stderr),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "sync_threshold_reached": (
            synchronized if sync_threshold is not None else None
        ),
    }


def public_observation(
    observation: dict[str, Any],
    *,
    stdout_name: str,
    stderr_name: str,
) -> dict[str, Any]:
    return {
        key: value
        for key, value in observation.items()
        if key not in {"stdout", "stderr"}
    } | {
        "raw_stdout": stdout_name,
        "raw_stderr": stderr_name,
    }


def parse_documents(data: bytes) -> list[dict[str, Any]]:
    if not data.strip():
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProbeError("CLI stdout is not UTF-8") from error
    matches = list(MULTI_DOCUMENT_PREFIX.finditer(text))
    if not matches:
        document = strict_json(data, "single CLI document")
        if not isinstance(document, dict):
            raise ProbeError("single CLI document is not an object")
        return [{"path": None, "document": document}]
    if text[: matches[0].start()].strip():
        raise ProbeError("unexpected text before first CLI prefix")
    result = []
    for index, match in enumerate(matches):
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(text)
        )
        raw_document = text[match.end() : end].strip().encode("utf-8")
        document = strict_json(raw_document, "multi CLI document")
        if not isinstance(document, dict):
            raise ProbeError("multi CLI document is not an object")
        result.append(
            {
                "path": match.group(1),
                "document": document,
            }
        )
    return result


def expected_entropy(size: int, entropy: float) -> dict[str, Any]:
    return {
        "records": [
            {
                "entropy": entropy,
                "name": "Data",
                "offset": 0,
                "size": size,
                "status": (
                    "packed" if entropy == 8 else "not packed"
                ),
            }
        ],
        "status": "packed" if entropy == 8 else "not packed",
        "total": entropy,
    }


def expected_missing_entropy() -> dict[str, Any]:
    return {"records": [], "status": "", "total": 0}


def relative_windows_path(path: str, root: Path) -> str:
    value = ntpath.relpath(path, str(root))
    if value == ".." or value.startswith("..\\"):
        raise ProbeError(f"CLI prefix escaped fixture root: {path}")
    return value.replace("\\", "/")


def materialize_large(
    root: Path,
    manifest: dict[str, Any],
) -> None:
    root.mkdir(parents=True, exist_ok=False)
    for case in manifest["cases"]:
        case_root = root / case["name"]
        case_root.mkdir()
        count = case["file_count"]
        if case["layout"] == "flat":
            for index in range(count - 1, -1, -1):
                (case_root / f"item-{index:06d}.empty").touch()
        else:
            per_bucket = case["files_per_bucket"]
            for bucket in range(case["bucket_count"] - 1, -1, -1):
                bucket_root = case_root / f"bucket-{bucket:03d}"
                bucket_root.mkdir()
                for item in range(per_bucket - 1, -1, -1):
                    index = bucket * per_bucket + item
                    (bucket_root / f"item-{index:06d}.empty").touch()


def expected_large_paths(case: dict[str, Any]) -> list[str]:
    if case["layout"] == "flat":
        return [
            f"item-{index:06d}.empty"
            for index in range(case["file_count"])
        ]
    return [
        f"bucket-{bucket:03d}/item-{bucket * case['files_per_bucket'] + item:06d}.empty"
        for bucket in range(case["bucket_count"])
        for item in range(case["files_per_bucket"])
    ]


def create_junction(link: Path, target: Path) -> None:
    if os.path.lexists(link):
        raise ProbeError(f"junction path already exists: {link}")
    result = subprocess.run(
        [
            "cmd.exe",
            "/d",
            "/c",
            "mklink",
            "/J",
            str(link),
            str(target),
        ],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise ProbeError(f"cannot create junction: {link}")


def remove_junction(link: Path) -> None:
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", "rmdir", str(link)],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0 or os.path.lexists(link):
        raise ProbeError(f"cannot remove junction: {link}")


def observe_large_cases(
    *,
    binary: Path,
    source_dir: Path,
    qt_dir: Path,
    root: Path,
    raw_dir: Path,
    manifest: dict[str, Any],
    repetitions: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    cases: dict[str, Any] = {}
    empty_document = expected_entropy(0, 0)
    for case in manifest["cases"]:
        name = case["name"]
        expected_paths = expected_large_paths(case)
        expected_path_hash = canonical_hash(expected_paths)
        runs = []
        semantic = []
        for repetition in range(1, repetitions + 1):
            stem = f"large.{name}.run-{repetition}"
            stdout_name = stem + ".stdout"
            stderr_name = stem + ".stderr"
            observation = run_to_files(
                binary=binary,
                arguments=[
                    "--entropy",
                    "--json",
                    *database_arguments(source_dir),
                    str(root / name),
                ],
                cwd=source_dir,
                qt_dir=qt_dir,
                stdout_path=raw_dir / stdout_name,
                stderr_path=raw_dir / stderr_name,
                timeout_seconds=timeout_seconds,
            )
            if (
                observation["exit_code"] != 0
                or observation["timed_out"]
                or observation["stderr"]
            ):
                raise ProbeError(f"large path run failed: {stem}")
            documents = parse_documents(observation["stdout"])
            paths = [
                relative_windows_path(item["path"], root / name)
                for item in documents
                if item["path"] is not None
            ]
            if len(documents) != case["file_count"]:
                raise ProbeError(f"large document count differs: {stem}")
            if (
                case["file_count"] > 1 and paths != expected_paths
            ):
                raise ProbeError(f"large path order differs: {stem}")
            if any(
                item["document"] != empty_document
                for item in documents
            ):
                raise ProbeError(f"large entropy document differs: {stem}")
            projection = {
                "document_count": len(documents),
                "prefix_count": len(paths),
                "relative_prefixes_sha256": canonical_hash(paths),
                "expected_relative_prefixes_sha256": expected_path_hash,
                "complete_expected_order": (
                    paths == expected_paths
                    if case["file_count"] > 1
                    else True
                ),
                "first_prefix": paths[0] if paths else None,
                "last_prefix": paths[-1] if paths else None,
            }
            semantic.append(projection)
            runs.append(
                {
                    **public_observation(
                        observation,
                        stdout_name=stdout_name,
                        stderr_name=stderr_name,
                    ),
                    "projection": projection,
                }
            )
        cases[name] = {
            "layout": case["layout"],
            "file_count": case["file_count"],
            "runs": runs,
            "semantic_deterministic": all(
                value == semantic[0] for value in semantic[1:]
            ),
        }
    return cases


def observe_reparse_cases(
    *,
    binary: Path,
    source_dir: Path,
    qt_dir: Path,
    root: Path,
    raw_dir: Path,
    payload: bytes,
    reference_tree: Any,
    repetitions: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=False)
    dangling_parent = root / "dangling"
    dangling_parent.mkdir()
    dangling_target = root / "dangling-target"
    dangling_target.mkdir()
    dangling_link = dangling_parent / "link"
    create_junction(dangling_link, dangling_target)
    dangling_target.rmdir()

    cycle_root = root / "cycle"
    cycle_a = cycle_root / "a"
    cycle_b = cycle_root / "b"
    cycle_a.mkdir(parents=True)
    cycle_b.mkdir()
    (cycle_a / "payload.pdf").write_bytes(payload)
    (cycle_b / "payload.pdf").write_bytes(payload)
    cycle_ab = cycle_a / "to-b"
    cycle_ba = cycle_b / "to-a"
    create_junction(cycle_ab, cycle_b)
    create_junction(cycle_ba, cycle_a)

    definitions = {
        "dangling_explicit": (dangling_link, timeout_seconds),
        "dangling_parent": (dangling_parent, timeout_seconds),
        "two_node_cycle": (cycle_a, min(timeout_seconds, 5)),
    }
    result: dict[str, Any] = {}
    try:
        for name, (argument, case_timeout) in definitions.items():
            runs = []
            semantic = []
            for repetition in range(1, repetitions + 1):
                stem = f"reparse.{name}.run-{repetition}"
                stdout_name = stem + ".stdout"
                stderr_name = stem + ".stderr"
                observation = run_to_files(
                    binary=binary,
                    arguments=[
                        "--json",
                        *database_arguments(source_dir),
                        str(argument),
                    ],
                    cwd=source_dir,
                    qt_dir=qt_dir,
                    stdout_path=raw_dir / stdout_name,
                    stderr_path=raw_dir / stderr_name,
                    timeout_seconds=case_timeout,
                )
                normalized_stdout = (
                    observation["stdout"]
                    .decode("utf-8", errors="replace")
                    .replace(str(root), "<reparse>")
                )
                cycle_projection = {
                    "document_count": None,
                    "relative_prefixes_sha256": None,
                    "max_prefix_code_units": None,
                    "all_documents_match_minimal_pdf": None,
                }
                if (
                    name == "two_node_cycle"
                    and not observation["timed_out"]
                    and observation["exit_code"] == 0
                ):
                    documents = parse_documents(
                        observation["stdout"]
                    )
                    relative_paths = [
                        relative_windows_path(
                            item["path"],
                            cycle_root,
                        )
                        for item in documents
                        if item["path"] is not None
                    ]
                    document_trees = [
                        baseline.json_detect_tree(
                            (
                                json.dumps(item["document"])
                                + "\n"
                            ).encode("utf-8")
                        )
                        for item in documents
                    ]
                    cycle_projection = {
                        "document_count": len(documents),
                        "relative_prefixes_sha256": canonical_hash(
                            relative_paths
                        ),
                        "max_prefix_code_units": max(
                            (len(path) for path in relative_paths),
                            default=0,
                        ),
                        "all_documents_match_minimal_pdf": all(
                            tree == reference_tree
                            for tree in document_trees
                        ),
                    }
                projection = {
                    "exit_code": observation["exit_code"],
                    "timed_out": observation["timed_out"],
                    "normalized_stdout_sha256": sha256(
                        normalized_stdout.encode("utf-8")
                    ),
                    "stderr_sha256": observation["stderr_sha256"],
                    "stdout_bytes": observation["stdout_bytes"],
                    "stderr_bytes": observation["stderr_bytes"],
                    **cycle_projection,
                }
                semantic.append(projection)
                runs.append(
                    {
                        **public_observation(
                            observation,
                            stdout_name=stdout_name,
                            stderr_name=stderr_name,
                        ),
                        "projection": projection,
                    }
                )
            result[name] = {
                "runs": runs,
                "semantic_deterministic": all(
                    value == semantic[0]
                    for value in semantic[1:]
                ),
                "externally_bounded": all(
                    run["wall_elapsed_ms"]
                    <= (case_timeout * 1000 + 1000)
                    for run in runs
                ),
            }
    finally:
        remove_junction(cycle_ab)
        remove_junction(cycle_ba)
        remove_junction(dangling_link)
    return result


def materialize_toctou(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    blocker_payload = bytes(range(256)) * 4096
    payload_path = root / "blocker-payload.bin"
    payload_path.write_bytes(blocker_payload)
    case_root = root / "case"
    case_root.mkdir()
    for index in range(fixture_generator.TOCTOU_BLOCKER_COUNT):
        os.link(
            payload_path,
            case_root / f"a-blocker-{index:03d}.bin",
        )
    targets = root / "targets"
    old = targets / "old"
    new = targets / "new"
    old.mkdir(parents=True)
    new.mkdir()
    (old / "payload.bin").write_bytes(b"")
    (new / "payload.bin").write_bytes(
        fixture_generator.TOCTOU_NEW_PAYLOAD
    )


def observe_toctou_cases(
    *,
    binary: Path,
    source_dir: Path,
    qt_dir: Path,
    root: Path,
    raw_dir: Path,
    manifest: dict[str, Any],
    repetitions: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    case_root = root / "case"
    old_target = root / "targets/old"
    new_target = root / "targets/new"
    link = case_root / "z-link"
    expected_documents = {
        "old": expected_entropy(0, 0),
        "new": expected_entropy(4096, 8),
        "missing": expected_missing_entropy(),
    }
    result: dict[str, Any] = {}
    for case in manifest["cases"]:
        name = case["name"]
        runs = []
        semantic = []
        for repetition in range(1, repetitions + 1):
            initial = (
                new_target if name == "stable_new" else old_target
            )
            create_junction(link, initial)

            def mutate() -> None:
                remove_junction(link)
                if case["action"] == "replace_junction_with_new_target":
                    create_junction(link, new_target)

            stem = f"toctou.{name}.run-{repetition}"
            stdout_name = stem + ".stdout"
            stderr_name = stem + ".stderr"
            action = case["action"]
            try:
                observation = run_to_files(
                    binary=binary,
                    arguments=[
                        "--entropy",
                        "--json",
                        *database_arguments(source_dir),
                        str(case_root),
                    ],
                    cwd=source_dir,
                    qt_dir=qt_dir,
                    stdout_path=raw_dir / stdout_name,
                    stderr_path=raw_dir / stderr_name,
                    timeout_seconds=timeout_seconds,
                    sync_threshold=(
                        manifest["stdout_sync_threshold_bytes"]
                        if action != "none"
                        else None
                    ),
                    on_sync=mutate if action != "none" else None,
                )
            finally:
                if os.path.lexists(link):
                    remove_junction(link)
            if (
                observation["exit_code"] != 0
                or observation["timed_out"]
                or observation["stderr"]
                or (
                    action != "none"
                    and not observation["sync_threshold_reached"]
                )
            ):
                raise ProbeError(f"TOCTOU run failed: {stem}")
            documents = parse_documents(observation["stdout"])
            relative = [
                (
                    relative_windows_path(item["path"], case_root),
                    item["document"],
                )
                for item in documents
                if item["path"] is not None
            ]
            link_documents = [
                document
                for path, document in relative
                if path == "z-link/payload.bin"
            ]
            blocker_paths = [
                path
                for path, _ in relative
                if path.startswith("a-blocker-")
            ]
            expected_target = case["expected_open_target"]
            if (
                len(documents) != 129
                or len(blocker_paths) != 128
                or len(link_documents) != 1
                or link_documents[0]
                != expected_documents[expected_target]
            ):
                raise ProbeError(f"TOCTOU projection differs: {stem}")
            projection = {
                "document_count": len(documents),
                "blocker_prefix_count": len(blocker_paths),
                "link_prefix": "z-link/payload.bin",
                "link_document": link_documents[0],
                "observed_open_target": expected_target,
                "sync_threshold_reached": observation[
                    "sync_threshold_reached"
                ],
            }
            semantic.append(projection)
            runs.append(
                {
                    **public_observation(
                        observation,
                        stdout_name=stdout_name,
                        stderr_name=stderr_name,
                    ),
                    "projection": projection,
                }
            )
        result[name] = {
            "action": action,
            "expected_open_target": case["expected_open_target"],
            "runs": runs,
            "semantic_deterministic": all(
                value == semantic[0] for value in semantic[1:]
            ),
        }
    return result


def run_checked(
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    process = subprocess.run(
        arguments,
        input=input_bytes,
        check=False,
        capture_output=True,
    )
    if process.returncode != 0:
        raise ProbeError(f"command failed: {arguments[0]}")
    return process.stdout


def prepare_wsl_fixture(distro: str, payload: bytes) -> None:
    script = r"""
import base64, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
if root.exists():
    raise SystemExit("WSL fixture root already exists")
payload = base64.b64decode(sys.argv[2], validate=True)
(root / "allowed").mkdir(parents=True)
(root / "directory").mkdir()
(root / "mixed" / "denied").mkdir(parents=True)
(root / "denied-directory").mkdir()
(root / "allowed" / "minimal.pdf").write_bytes(payload)
(root / "directory" / "minimal.pdf").write_bytes(payload)
(root / "mixed" / "visible.pdf").write_bytes(payload)
(root / "mixed" / "denied" / "secret.pdf").write_bytes(payload)
(root / "denied-file.pdf").write_bytes(payload)
(root / "denied-directory" / "secret.pdf").write_bytes(payload)
os.chmod(root / "denied-file.pdf", 0)
os.chmod(root / "denied-directory", 0)
os.chmod(root / "mixed" / "denied", 0)
"""
    run_checked(
        [
            "wsl.exe",
            "-d",
            distro,
            "--exec",
            "python3",
            "-c",
            script,
            WSL_ROOT,
            base64.b64encode(payload).decode("ascii"),
        ]
    )


def cleanup_wsl_fixture(distro: str) -> None:
    script = r"""
import os, pathlib, shutil, sys
root = pathlib.Path(sys.argv[1])
for path in (
    root / "denied-file.pdf",
    root / "denied-directory",
    root / "mixed" / "denied",
):
    if path.exists():
        os.chmod(path, 0o700)
shutil.rmtree(root)
"""
    run_checked(
        [
            "wsl.exe",
            "-d",
            distro,
            "--exec",
            "python3",
            "-c",
            script,
            WSL_ROOT,
        ]
    )


def extended_unc(path: str) -> str:
    if not path.startswith("\\\\"):
        raise ProbeError("UNC path must start with two backslashes")
    return "\\\\?\\UNC\\" + path[2:]


def detection_projection(
    stdout: bytes,
    reference_tree: Any,
) -> dict[str, Any]:
    try:
        document = strict_json(stdout, "detection projection")
        valid_json = isinstance(document, dict)
        tree = (
            baseline.json_detect_tree(stdout)
            if valid_json
            else None
        )
    except ProbeError:
        tree = None
        valid_json = False
    return {
        "valid_json": valid_json,
        "detect_tree": tree,
        "minimal_pdf_equal": valid_json and tree == reference_tree,
    }


def observe_unc_cases(
    *,
    binary: Path,
    source_dir: Path,
    qt_dir: Path,
    raw_dir: Path,
    distro: str,
    payload: bytes,
    reference_tree: Any,
    repetitions: int,
    timeout_seconds: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    prepare_wsl_fixture(distro, payload)
    unc_root = (
        rf"\\wsl.localhost\{distro}"
        + WSL_ROOT.replace("/", "\\")
    )
    allowed_file = unc_root + r"\allowed\minimal.pdf"
    definitions = {
        "unc_file": allowed_file,
        "unc_directory": unc_root + r"\directory",
        "extended_unc_file": extended_unc(allowed_file),
        "extended_unc_directory": extended_unc(
            unc_root + r"\directory"
        ),
        "unc_missing": unc_root + r"\missing.pdf",
        "unc_denied_file": unc_root + r"\denied-file.pdf",
        "unc_denied_directory": unc_root + r"\denied-directory",
        "unc_directory_with_denied_child": unc_root + r"\mixed",
    }
    environment = {
        "distro": distro,
        "provider": "WSL UNC redirector",
        "ordinary_prefix": rf"\\wsl.localhost\{distro}\<fixture>",
        "extended_prefix": (
            rf"\\?\UNC\wsl.localhost\{distro}\<fixture>"
        ),
        "allowed_payload_readable_from_windows": (
            Path(allowed_file).read_bytes() == payload
        ),
    }
    result: dict[str, Any] = {}
    try:
        for name, argument in definitions.items():
            runs = []
            semantic = []
            for repetition in range(1, repetitions + 1):
                stem = f"unc.{name}.run-{repetition}"
                stdout_name = stem + ".stdout"
                stderr_name = stem + ".stderr"
                observation = run_to_files(
                    binary=binary,
                    arguments=[
                        "--json",
                        *database_arguments(source_dir),
                        argument,
                    ],
                    cwd=source_dir,
                    qt_dir=qt_dir,
                    stdout_path=raw_dir / stdout_name,
                    stderr_path=raw_dir / stderr_name,
                    timeout_seconds=timeout_seconds,
                )
                normalized_stdout = (
                    observation["stdout"]
                    .decode("utf-8", errors="replace")
                    .replace(unc_root, "<unc-fixture>")
                    .replace(
                        extended_unc(unc_root),
                        "<extended-unc-fixture>",
                    )
                )
                detection = detection_projection(
                    observation["stdout"],
                    reference_tree,
                )
                projection = {
                    "exit_code": observation["exit_code"],
                    "timed_out": observation["timed_out"],
                    "normalized_stdout_sha256": sha256(
                        normalized_stdout.encode("utf-8")
                    ),
                    "stderr_sha256": observation["stderr_sha256"],
                    **detection,
                }
                semantic.append(projection)
                runs.append(
                    {
                        **public_observation(
                            observation,
                            stdout_name=stdout_name,
                            stderr_name=stderr_name,
                        ),
                        "projection": projection,
                    }
                )
            result[name] = {
                "runs": runs,
                "semantic_deterministic": all(
                    value == semantic[0]
                    for value in semantic[1:]
                ),
            }
    finally:
        cleanup_wsl_fixture(distro)
    return result, environment


def current_user_identity() -> dict[str, Any]:
    raw = run_checked(
        ["whoami.exe", "/user", "/fo", "csv", "/nh"]
    )
    row = next(
        csv.reader(
            io.StringIO(
                raw.decode(
                    "utf-8",
                    errors="replace",
                ).strip()
            )
        )
    )
    account = row[0]
    sid = row[1]
    machine = platform.node()
    prefix = account.split("\\", 1)[0] if "\\" in account else ""
    return {
        "account": account,
        "sid": sid,
        "machine_name": machine,
        "account_prefix_equals_machine": (
            prefix.casefold() == machine.casefold()
        ),
        "classification": (
            "local-account"
            if prefix.casefold() == machine.casefold()
            else "domain-or-external-account"
        ),
    }


def apply_acl_deny(path: Path, sid: str) -> None:
    process = subprocess.run(
        [
            "icacls.exe",
            str(path),
            "/inheritance:r",
            "/deny",
            f"*{sid}:(OI)(CI)F",
        ],
        check=False,
        capture_output=True,
    )
    if process.returncode != 0:
        raise ProbeError("cannot apply disposable DACL deny")


def recover_acl(path: Path, sid: str) -> None:
    remove = subprocess.run(
        [
            "icacls.exe",
            str(path),
            "/remove:d",
            f"*{sid}",
        ],
        check=False,
        capture_output=True,
    )
    reset = subprocess.run(
        ["icacls.exe", str(path), "/reset"],
        check=False,
        capture_output=True,
    )
    if remove.returncode != 0 or reset.returncode != 0:
        raise ProbeError("cannot recover disposable DACL")


def observe_acl_cases(
    *,
    binary: Path,
    source_dir: Path,
    qt_dir: Path,
    root: Path,
    raw_dir: Path,
    payload: bytes,
    reference_tree: Any,
    user: dict[str, Any],
    repetitions: int,
    timeout_seconds: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    root.mkdir(parents=True, exist_ok=False)
    (root / "visible.pdf").write_bytes(payload)
    denied = root / "denied"
    denied.mkdir()
    secret = denied / "secret.pdf"
    secret.write_bytes(payload)
    apply_acl_deny(denied, user["sid"])
    python_access_denied = False
    try:
        try:
            list(denied.iterdir())
        except PermissionError:
            python_access_denied = True
        definitions = {
            "local_denied_file": secret,
            "local_denied_directory": denied,
            "local_directory_with_denied_child": root,
        }
        result: dict[str, Any] = {}
        for name, argument in definitions.items():
            runs = []
            semantic = []
            for repetition in range(1, repetitions + 1):
                stem = f"acl.{name}.run-{repetition}"
                stdout_name = stem + ".stdout"
                stderr_name = stem + ".stderr"
                observation = run_to_files(
                    binary=binary,
                    arguments=[
                        "--json",
                        *database_arguments(source_dir),
                        str(argument),
                    ],
                    cwd=source_dir,
                    qt_dir=qt_dir,
                    stdout_path=raw_dir / stdout_name,
                    stderr_path=raw_dir / stderr_name,
                    timeout_seconds=timeout_seconds,
                )
                normalized_stdout = (
                    observation["stdout"]
                    .decode("utf-8", errors="replace")
                    .replace(str(root), "<acl-fixture>")
                )
                detection = detection_projection(
                    observation["stdout"],
                    reference_tree,
                )
                projection = {
                    "exit_code": observation["exit_code"],
                    "timed_out": observation["timed_out"],
                    "normalized_stdout_sha256": sha256(
                        normalized_stdout.encode("utf-8")
                    ),
                    "stderr_sha256": observation["stderr_sha256"],
                    **detection,
                }
                semantic.append(projection)
                runs.append(
                    {
                        **public_observation(
                            observation,
                            stdout_name=stdout_name,
                            stderr_name=stderr_name,
                        ),
                        "projection": projection,
                    }
                )
            result[name] = {
                "runs": runs,
                "semantic_deterministic": all(
                    value == semantic[0]
                    for value in semantic[1:]
                ),
            }
    finally:
        recover_acl(denied, user["sid"])
    if not secret.is_file() or secret.read_bytes() != payload:
        raise ProbeError("DACL recovery did not restore fixture")
    environment = {
        "provider": "NTFS DACL",
        "ace": "explicit deny (OI)(CI)F",
        "current_sid_sha256": sha256(user["sid"].encode("utf-8")),
        "python_access_denied_while_ace_active": python_access_denied,
        "recovery_verified": True,
    }
    return result, environment


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--qt-dir", type=Path, required=True)
    parser.add_argument("--baseline-fixture-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--wsl-distro", default="Ubuntu")
    parser.add_argument("--repetitions", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.name != "nt":
        raise ProbeError("Windows path closure requires native Windows")
    if args.repetitions < 2 or args.repetitions > 5:
        raise ProbeError("repetitions must be in 2..5")
    if args.timeout_seconds < 5 or args.timeout_seconds > 600:
        raise ProbeError("timeout-seconds must be in 5..600")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.wsl_distro):
        raise ProbeError("unsafe WSL distro name")

    binary = args.binary.resolve(strict=True)
    source_dir = args.source_dir.resolve(strict=True)
    qt_dir = args.qt_dir.resolve(strict=True)
    baseline_fixture = args.baseline_fixture_dir.resolve(strict=True)
    work_dir = args.work_dir.resolve()
    raw_dir = args.raw_dir.resolve()
    if work_dir.exists() and any(work_dir.iterdir()):
        raise ProbeError("work-dir must be absent or empty")
    work_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    if raw_dir == work_dir or work_dir in raw_dir.parents:
        pass
    elif raw_dir.exists() and any(raw_dir.iterdir()):
        raise ProbeError("raw-dir must be empty or inside work-dir")

    expected_binary = (
        source_dir / "build/release/diec.exe"
    ).resolve(strict=True)
    if binary != expected_binary:
        raise ProbeError("binary must be fixed source release CLI")
    if baseline.sha256_file(binary) != EXPECTED_CLI_SHA256:
        raise ProbeError("fixed Windows CLI SHA-256 differs")
    source_identity = baseline.validate_source(source_dir)
    qt_identity = baseline.validate_qt(qt_dir)
    references = validate_input_reports()
    source_contract = observe_source(source_dir)

    baseline_manifest = strict_json(
        (baseline_fixture / "manifest.json").read_bytes(),
        "baseline fixture",
    )
    pdf = (baseline_fixture / "minimal.pdf").read_bytes()
    if (
        len(pdf) != references["fixture"]["payload"]["size"]
        or sha256(pdf)
        != references["fixture"]["payload"]["sha256"]
        or not any(
            sample.get("name") == "minimal.pdf"
            and sample.get("sha256") == sha256(pdf)
            for sample in baseline_manifest.get("samples", [])
        )
    ):
        raise ProbeError("baseline minimal PDF identity differs")
    reference_tree = references["windows_baseline"]["corpus"][
        "minimal.pdf"
    ]["first_detect_tree"]
    user = current_user_identity()

    large_root = work_dir / "large"
    materialize_large(large_root, references["large"])
    large_cases = observe_large_cases(
        binary=binary,
        source_dir=source_dir,
        qt_dir=qt_dir,
        root=large_root,
        raw_dir=raw_dir,
        manifest=references["large"],
        repetitions=args.repetitions,
        timeout_seconds=args.timeout_seconds,
    )
    reparse_cases = observe_reparse_cases(
        binary=binary,
        source_dir=source_dir,
        qt_dir=qt_dir,
        root=work_dir / "reparse",
        raw_dir=raw_dir,
        payload=pdf,
        reference_tree=reference_tree,
        repetitions=args.repetitions,
        timeout_seconds=args.timeout_seconds,
    )
    toctou_root = work_dir / "toctou"
    materialize_toctou(toctou_root)
    toctou_cases = observe_toctou_cases(
        binary=binary,
        source_dir=source_dir,
        qt_dir=qt_dir,
        root=toctou_root,
        raw_dir=raw_dir,
        manifest=references["fixture"]["toctou"],
        repetitions=args.repetitions,
        timeout_seconds=args.timeout_seconds,
    )
    unc_cases, unc_environment = observe_unc_cases(
        binary=binary,
        source_dir=source_dir,
        qt_dir=qt_dir,
        raw_dir=raw_dir,
        distro=args.wsl_distro,
        payload=pdf,
        reference_tree=reference_tree,
        repetitions=args.repetitions,
        timeout_seconds=args.timeout_seconds,
    )
    acl_cases, acl_environment = observe_acl_cases(
        binary=binary,
        source_dir=source_dir,
        qt_dir=qt_dir,
        root=work_dir / "acl",
        raw_dir=raw_dir,
        payload=pdf,
        reference_tree=reference_tree,
        user=user,
        repetitions=args.repetitions,
        timeout_seconds=args.timeout_seconds,
    )

    unc_ordinary_success_names = (
        "unc_file",
        "unc_directory",
    )
    unc_extended_names = (
        "extended_unc_file",
        "extended_unc_directory",
    )
    unc_denied_names = (
        "unc_denied_file",
        "unc_denied_directory",
    )
    acl_denied_names = (
        "local_denied_file",
        "local_denied_directory",
    )
    relationships = {
        "large_all_cases_are_semantically_deterministic": all(
            case["semantic_deterministic"]
            for case in large_cases.values()
        ),
        "large_flat_4096_is_complete_and_ordered": (
            large_cases["flat_4096"]["runs"][0]["projection"][
                "document_count"
            ]
            == 4096
            and large_cases["flat_4096"]["runs"][0]["projection"][
                "complete_expected_order"
            ]
        ),
        "large_nested_4096_is_complete_and_ordered": (
            large_cases["nested_4096"]["runs"][0]["projection"][
                "document_count"
            ]
            == 4096
            and large_cases["nested_4096"]["runs"][0]["projection"][
                "complete_expected_order"
            ]
        ),
        "reparse_all_cases_are_semantically_deterministic": all(
            case["semantic_deterministic"]
            for case in reparse_cases.values()
        ),
        "reparse_cycle_is_bounded_and_repeats_without_deduplication": (
            reparse_cases["two_node_cycle"]["externally_bounded"]
            and reparse_cases["two_node_cycle"]["runs"][0][
                "projection"
            ]["document_count"]
            > 2
            and reparse_cases["two_node_cycle"]["runs"][0][
                "projection"
            ]["all_documents_match_minimal_pdf"]
        ),
        "toctou_all_cases_are_semantically_deterministic": all(
            case["semantic_deterministic"]
            for case in toctou_cases.values()
        ),
        "toctou_swap_opens_new_target": toctou_cases[
            "swap_old_to_new"
        ]["runs"][0]["projection"]["observed_open_target"]
        == "new",
        "toctou_remove_retains_missing_result_shape": toctou_cases[
            "remove_after_enumeration"
        ]["runs"][0]["projection"]["observed_open_target"]
        == "missing",
        "unc_provider_is_readable": unc_environment[
            "allowed_payload_readable_from_windows"
        ],
        "unc_ordinary_succeeds_and_extended_is_rejected": (
            all(
            unc_cases[name]["runs"][0]["projection"][
                "minimal_pdf_equal"
            ]
                for name in unc_ordinary_success_names
            )
            and all(
                unc_cases[name]["runs"][0]["projection"][
                    "exit_code"
                ]
                == 1
                and not unc_cases[name]["runs"][0]["projection"][
                    "minimal_pdf_equal"
                ]
                for name in unc_extended_names
            )
        ),
        "unc_missing_is_not_reported_as_pdf": not unc_cases[
            "unc_missing"
        ]["runs"][0]["projection"]["minimal_pdf_equal"],
        "unc_permission_denials_do_not_expose_pdf": all(
            not unc_cases[name]["runs"][0]["projection"][
                "minimal_pdf_equal"
            ]
            for name in unc_denied_names
        ),
        "unc_mixed_directory_retains_visible_pdf": unc_cases[
            "unc_directory_with_denied_child"
        ]["runs"][0]["projection"]["minimal_pdf_equal"],
        "unc_all_cases_are_semantically_deterministic": all(
            case["semantic_deterministic"]
            for case in unc_cases.values()
        ),
        "local_acl_is_denied_to_current_process": acl_environment[
            "python_access_denied_while_ace_active"
        ],
        "local_acl_denials_do_not_expose_pdf": all(
            not acl_cases[name]["runs"][0]["projection"][
                "minimal_pdf_equal"
            ]
            for name in acl_denied_names
        ),
        "local_acl_mixed_directory_retains_visible_pdf": acl_cases[
            "local_directory_with_denied_child"
        ]["runs"][0]["projection"]["minimal_pdf_equal"],
        "local_acl_all_cases_are_semantically_deterministic": all(
            case["semantic_deterministic"]
            for case in acl_cases.values()
        ),
        "local_acl_recovery_is_verified": acl_environment[
            "recovery_verified"
        ],
        "source_freezes_list_before_open": all(
            count >= 1
            for count in source_contract[
                "required_pattern_counts"
            ].values()
        ),
        "source_has_no_platform_specific_path_branch": not any(
            source_contract[
                "negative_platform_token_counts"
            ].values()
        ),
    }
    if len(relationships) != 21 or not all(relationships.values()):
        failed = [
            name
            for name, value in relationships.items()
            if not value
        ]
        raise ProbeError(f"Windows path relationships differ: {failed}")

    execution_count = (
        len(large_cases)
        + len(reparse_cases)
        + len(toctou_cases)
        + len(unc_cases)
        + len(acl_cases)
    ) * args.repetitions
    report = {
        "schema_version": 1,
        "generator": (
            "tools/upstream/collect_windows_path_closure.py"
        ),
        "generator_sha256": baseline.sha256_file(Path(__file__)),
        "platform": "windows-x86_64-qt5",
        "capability": "CAP-CLI-IN-003",
        "source": source_identity,
        "qt": qt_identity,
        "binary": {
            "relative_path": "build/release/diec.exe",
            "size": binary.stat().st_size,
            "sha256": EXPECTED_CLI_SHA256,
        },
        "host": {
            "os_build": platform.version(),
            "architecture": platform.machine(),
            "user": {
                "account_sha256": sha256(
                    user["account"].encode("utf-8")
                ),
                "sid_sha256": sha256(
                    user["sid"].encode("utf-8")
                ),
                "account_prefix_equals_machine": user[
                    "account_prefix_equals_machine"
                ],
                "classification": user["classification"],
            },
            "unc": unc_environment,
            "acl": acl_environment,
        },
        "source_contract": source_contract,
        "fixture": {
            "path": (
                "docs/research/data/"
                "windows-path-closure-fixture.json"
            ),
            "sha256": sha256(references["fixture_raw"]),
            "identity": references["fixture"],
        },
        "references": {
            "large_manifest": {
                "path": "docs/research/data/large-path-fixture.json",
                "sha256": sha256(references["large_raw"]),
            },
            "linux_qt5_large": {
                "path": "docs/research/data/large-path-engine-qt5.json",
                "sha256": sha256(references["large_report_raw"]),
            },
            "linux_qt5_toctou": {
                "path": "docs/research/data/path-toctou-engine-qt5.json",
                "sha256": sha256(references["toctou_report_raw"]),
            },
            "windows_default": {
                "path": (
                    "docs/research/data/"
                    "baseline-corpus-windows-qt5.json"
                ),
                "sha256": sha256(
                    references["windows_baseline_raw"]
                ),
                "sample": "minimal.pdf",
            },
        },
        "repetitions": args.repetitions,
        "case_count": execution_count // args.repetitions,
        "execution_count": execution_count,
        "case_observation_count": execution_count,
        "large_directory_cases": large_cases,
        "reparse_cases": reparse_cases,
        "toctou_cases": toctou_cases,
        "unc_cases": unc_cases,
        "acl_cases": acl_cases,
        "relationships": relationships,
        "failures": [],
        "passed": True,
        "raw_artifacts": {
            "retained_externally": True,
            "directory_role": (
                "native CLI stdout/stderr, excluded from repository"
            ),
            "file_count": execution_count * 2,
        },
        "limitations": [
            (
                "successful UNC cases use the installed WSL redirector; "
                "no machine SMB share is created or modified"
            ),
            (
                "the WSL redirector accepts ordinary UNC but the fixed "
                "Qt5 CLI rejects the corresponding extended UNC form"
            ),
            (
                "ACL behavior is exercised with the current local SID "
                "and WSL Unix modes; Active Directory identity is not "
                "an independent branch in the fixed source"
            ),
            (
                "the reparse cycle is bounded by the collector wall "
                "timeout if upstream does not terminate first"
            ),
            (
                "4096 entries and the tested path/resource bounds do "
                "not justify an unbounded Rust default"
            ),
        ],
    }
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "case_count": report["case_count"],
                "execution_count": execution_count,
                "output": str(output),
                "passed": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

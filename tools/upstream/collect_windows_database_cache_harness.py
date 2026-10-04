#!/usr/bin/env python3
"""Collect the native-Windows Qt5 DIE engine database-cache matrix."""

from __future__ import annotations

import argparse
import copy
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Sequence


ROOT = Path(__file__).resolve().parents[2]
BASELINE_SCRIPT = (
    ROOT / "tools/upstream/collect_windows_cli_baseline.py"
)
SHARED_HELPER = ROOT / "tools/upstream/compare_cli_oracles.py"
LINUX_PROBE = (
    ROOT / "tools/upstream/probe_database_cache_harness.py"
)
SHARED_HARNESS = (
    ROOT / "tools/upstream/database_cache_harness_main.cpp"
)
WINDOWS_BUILDER = (
    ROOT / "tools/upstream/build_windows_database_cache_harness.ps1"
)
WINDOWS_ADAPTER = (
    ROOT / "tools/upstream/database_cache_harness_windows_adapter.cpp"
)
WINDOWS_COMPAT = (
    ROOT
    / "tools/upstream/windows_database_cache_compat/unistd.h"
)
FIXTURE_GENERATOR = (
    ROOT / "tools/corpus/generate_database_fixture.py"
)


def load_module(name: str, path: Path) -> object:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load helper module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


baseline = load_module(
    "collect_windows_cli_baseline_cache_helper",
    BASELINE_SCRIPT,
)
shared = load_module(
    "compare_cli_oracles_windows_cache_helper",
    SHARED_HELPER,
)
sys.modules["compare_cli_oracles"] = shared
linux_probe = load_module(
    "probe_database_cache_harness_windows_reference",
    LINUX_PROBE,
)
HarnessError = baseline.BaselineError


class TokenElevation(ctypes.Structure):
    _fields_ = [("TokenIsElevated", wintypes.DWORD)]


def process_token_is_elevated() -> bool:
    token_query = 0x0008
    token_elevation = 20
    token = wintypes.HANDLE()
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        token_query,
        ctypes.byref(token),
    ):
        raise HarnessError("OpenProcessToken failed")
    try:
        elevation = TokenElevation()
        returned = wintypes.DWORD()
        if not advapi32.GetTokenInformation(
            token,
            token_elevation,
            ctypes.byref(elevation),
            ctypes.sizeof(elevation),
            ctypes.byref(returned),
        ):
            raise HarnessError("GetTokenInformation(TokenElevation) failed")
        return bool(elevation.TokenIsElevated)
    finally:
        kernel32.CloseHandle(token)


def read_json(path: Path) -> tuple[dict[str, object], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise HarnessError(f"JSON document is not an object: {path}")
    return value, raw


def validate_build_manifest(
    build: dict[str, object],
    binary: Path,
) -> None:
    expected_source_hashes = {
        "builder": baseline.sha256_file(WINDOWS_BUILDER),
        "shared_harness": baseline.sha256_file(SHARED_HARNESS),
        "windows_adapter": baseline.sha256_file(WINDOWS_ADAPTER),
        "windows_compat_header": baseline.sha256_file(WINDOWS_COMPAT),
    }
    expected_baseline = {
        "repository": "https://github.com/horsicq/DIE-engine",
        "commit": baseline.UPSTREAM_COMMIT,
        "recursive_submodule_count": baseline.EXPECTED_SUBMODULE_COUNT,
        "rules_commit": baseline.RULES_COMMIT,
        "cli_sha256": (
            "e8579a6ed0d2536ea14af154bcbeeaaea6967c0c7559a595"
            "fb3fe52206ac635e"
        ),
    }
    if build.get("schema_version") != 1:
        raise HarnessError("unsupported Windows harness build manifest")
    if build.get("baseline") != expected_baseline:
        raise HarnessError("Windows harness build baseline differs")
    if build.get("source_hashes") != expected_source_hashes:
        raise HarnessError("Windows harness source hashes differ")
    artifact = build.get("artifact")
    if not isinstance(artifact, dict):
        raise HarnessError("Windows harness build has no artifact")
    if artifact.get("filename") != binary.name:
        raise HarnessError("Windows harness artifact filename differs")
    if artifact.get("size") != binary.stat().st_size:
        raise HarnessError("Windows harness artifact size differs")
    if artifact.get("sha256") != baseline.sha256_file(binary):
        raise HarnessError("Windows harness artifact hash differs")


def validate_linux_reference(
    report: dict[str, object],
    fixture_sha256: str,
) -> dict[str, object]:
    expected = {
        "schema_version": 1,
        "generator": "tools/upstream/probe_database_cache_harness.py",
        "generator_sha256": baseline.sha256_file(LINUX_PROBE),
        "expected_revision": baseline.UPSTREAM_COMMIT,
        "image_revision": baseline.UPSTREAM_COMMIT,
        "fixture_manifest_sha256": fixture_sha256,
        "passed": True,
        "failures": [],
        "raw_outputs_equal": True,
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise HarnessError(
                f"Linux cache reference {key!r} differs"
            )
    source_hashes = report.get("source_hashes")
    if not isinstance(source_hashes, dict):
        raise HarnessError("Linux cache reference has no source hashes")
    if source_hashes.get("harness") != baseline.sha256_file(
        SHARED_HARNESS
    ):
        raise HarnessError("Linux cache reference harness hash differs")
    observation = report.get("observation")
    if not isinstance(observation, dict):
        raise HarnessError("Linux cache reference has no observation")
    linux_probe.index_cases(observation)
    return observation


def observe(
    binary: Path,
    qt_dir: Path,
    fixture_dir: Path,
    working_dir: Path,
    timeout_seconds: int,
) -> object:
    environment = os.environ.copy()
    environment["PATH"] = (
        str(qt_dir / "bin")
        + os.pathsep
        + environment.get("PATH", "")
    )
    result = subprocess.run(
        [str(binary), str(fixture_dir)],
        cwd=working_dir,
        env=environment,
        check=False,
        capture_output=True,
        timeout=timeout_seconds,
    )
    return shared.Observation(
        result.returncode,
        result.stdout,
        result.stderr,
    )


def normalize_observation(
    observation: dict[str, object],
) -> dict[str, object]:
    result = copy.deepcopy(observation)
    if result.get("upstream_commit") != baseline.UPSTREAM_COMMIT:
        raise HarnessError("harness output upstream commit differs")
    if result.get("xscanengine_commit") != (
        "dfe4a419e4f491bb23688ba03c5a5bf39e34da83"
    ):
        raise HarnessError("harness output XScanEngine commit differs")
    if result.get("effective_uid") != -1:
        raise HarnessError("Windows UID sentinel differs")
    if result.get("effective_gid") != -1:
        raise HarnessError("Windows GID sentinel differs")
    if result.get("database_path") != (
        "/tmp/die-database-cache-harness/database"
    ):
        raise HarnessError("Windows harness database path differs")
    if result.get("rule_path") != (
        "/tmp/die-database-cache-harness/database/Binary/fixture.1.sg"
    ):
        raise HarnessError("Windows harness rule path differs")

    cache_path = result.get("cache_path")
    if not isinstance(cache_path, str):
        raise HarnessError("Windows harness cache path is invalid")
    normalized_cache = cache_path.replace("\\", "/")
    cache_marker = "/NTInfo/die/db_cache/"
    marker_index = normalized_cache.casefold().rfind(
        cache_marker.casefold()
    )
    cache_root = normalized_cache[:marker_index]
    if (
        marker_index <= 0
        or "/qttest" not in cache_root.casefold()
        or not Path(cache_path).is_absolute()
    ):
        raise HarnessError("Windows harness did not use Qt test APPDATA")
    result["database_path"] = "<work>/database"
    result["rule_path"] = "<work>/database/Binary/fixture.1.sg"
    result["cache_path"] = (
        "<qt-test-appdata>" + normalized_cache[marker_index:]
    )
    linux_probe.index_cases(result)
    return result


def semantic_case_projection(case: dict[str, object]) -> dict[str, object]:
    cache = case.get("cache")
    if not isinstance(cache, dict):
        raise HarnessError("cache harness case has no cache snapshot")
    return {
        "loaded": case.get("loaded"),
        "stop_before_load": case.get("stop_before_load"),
        "load_pd_not_canceled": case.get("load_pd_not_canceled"),
        "binary_signature_count": case.get("binary_signature_count"),
        "scan_names": case.get("scan_names"),
        "scan_errors": case.get("scan_errors"),
        "cache_exists": cache.get("exists"),
    }


def compare_linux_cases(
    windows: dict[str, object],
    linux: dict[str, object],
) -> tuple[list[str], dict[str, int]]:
    windows_cases = linux_probe.index_cases(windows)
    linux_cases = linux_probe.index_cases(linux)
    projection_differences = []
    cache_size_deltas = {}
    for case_id in linux_probe.EXPECTED_CASE_IDS:
        windows_case = windows_cases[case_id]
        linux_case = linux_cases[case_id]
        if semantic_case_projection(
            windows_case
        ) != semantic_case_projection(linux_case):
            projection_differences.append(case_id)
        windows_cache = windows_case["cache"]
        linux_cache = linux_case["cache"]
        if windows_cache["exists"] and linux_cache["exists"]:
            cache_size_deltas[case_id] = (
                windows_cache["size"] - linux_cache["size"]
            )
    return projection_differences, cache_size_deltas


def raw_summary(observation: object) -> dict[str, object]:
    return observation.summary()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--qt-dir", type=Path, required=True)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--build-manifest", type=Path, required=True)
    parser.add_argument("--working-dir", type=Path, required=True)
    parser.add_argument(
        "--fixture-manifest",
        type=Path,
        default=ROOT / "docs/research/data/database-fixture.json",
    )
    parser.add_argument(
        "--linux-reference",
        type=Path,
        default=ROOT / "docs/research/data/database-cache-engine-qt5.json",
    )
    parser.add_argument("--repetitions", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.name != "nt":
        raise HarnessError("native Windows cache harness requires Windows")
    if args.repetitions < 2 or args.repetitions > 20:
        raise HarnessError("repetitions must be in 2..20")
    if args.timeout_seconds < 1 or args.timeout_seconds > 3600:
        raise HarnessError("timeout-seconds must be in 1..3600")
    if process_token_is_elevated():
        raise HarnessError(
            "run the Windows permission matrix with a non-elevated token"
        )

    binary = args.binary.resolve(strict=True)
    source_dir = args.source_dir.resolve(strict=True)
    qt_dir = args.qt_dir.resolve(strict=True)
    fixture_dir = args.fixture_dir.resolve(strict=True)
    working_dir = args.working_dir.resolve(strict=True)
    source_identity = baseline.validate_source(source_dir)
    qt_identity = baseline.validate_qt(qt_dir)

    build_manifest_path = args.build_manifest.resolve(strict=True)
    build_manifest, build_manifest_raw = read_json(build_manifest_path)
    validate_build_manifest(build_manifest, binary)

    fixture_manifest_path = args.fixture_manifest.resolve(strict=True)
    fixture_raw = (fixture_dir / "manifest.json").read_bytes()
    if fixture_raw != fixture_manifest_path.read_bytes():
        raise HarnessError("database fixture manifest differs")
    shared.load_database_fixture(fixture_dir)
    fixture_sha256 = hashlib.sha256(fixture_raw).hexdigest()

    linux_reference_path = args.linux_reference.resolve(strict=True)
    linux_report, linux_raw = read_json(linux_reference_path)
    linux_observation = validate_linux_reference(
        linux_report,
        fixture_sha256,
    )

    runs = []
    normalized_observations = []
    failures = []
    for index in range(args.repetitions):
        observation = observe(
            binary,
            qt_dir,
            fixture_dir,
            working_dir,
            args.timeout_seconds,
        )
        runs.append(raw_summary(observation))
        if observation.exit_code != 0:
            failures.append(f"run_{index}.exit_code")
            continue
        if observation.stderr:
            failures.append(f"run_{index}.stderr")
        try:
            parsed = json.loads(observation.stdout)
            if not isinstance(parsed, dict):
                raise HarnessError("harness output is not an object")
            normalized_observations.append(
                normalize_observation(parsed)
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ):
            failures.append(f"run_{index}.stdout")

    raw_outputs_equal = (
        len({run["stdout_sha256"] for run in runs}) == 1
        and len({run["stderr_sha256"] for run in runs}) == 1
    )
    normalized_outputs_equal = (
        len(normalized_observations) == args.repetitions
        and all(
            observation == normalized_observations[0]
            for observation in normalized_observations[1:]
        )
    )
    if not raw_outputs_equal:
        failures.append("raw_outputs_equal")
    if not normalized_outputs_equal:
        failures.append("normalized_outputs_equal")

    normalized = (
        normalized_observations[0]
        if normalized_observations
        else None
    )
    relationships = {}
    projection_differences = []
    cache_size_deltas = {}
    if normalized is not None:
        relationships = linux_probe.derive_relationships(normalized)
        relationships.pop("harness_runs_without_root_privileges", None)
        projection_differences, cache_size_deltas = compare_linux_cases(
            normalized,
            linux_observation,
        )

    report = {
        "schema_version": 1,
        "generator": (
            "tools/upstream/collect_windows_database_cache_harness.py"
        ),
        "generator_sha256": baseline.sha256_file(Path(__file__)),
        "platform": "windows-x86_64-qt5",
        "host": {
            "os_build": platform.version(),
            "architecture": platform.machine(),
            "token_elevated": False,
        },
        "source": source_identity,
        "qt": qt_identity,
        "binary": {
            "filename": binary.name,
            "size": binary.stat().st_size,
            "sha256": baseline.sha256_file(binary),
        },
        "build_manifest": {
            "sha256": hashlib.sha256(build_manifest_raw).hexdigest(),
            "identity": build_manifest,
        },
        "fixture": {
            "manifest": "docs/research/data/database-fixture.json",
            "sha256": fixture_sha256,
        },
        "linux_qt5_reference": {
            "path": "docs/research/data/database-cache-engine-qt5.json",
            "sha256": hashlib.sha256(linux_raw).hexdigest(),
        },
        "source_hashes": {
            "shared_helper": baseline.sha256_file(SHARED_HELPER),
            "linux_probe": baseline.sha256_file(LINUX_PROBE),
            "fixture_generator": baseline.sha256_file(
                FIXTURE_GENERATOR
            ),
        },
        "repetitions": args.repetitions,
        "runs": runs,
        "raw_outputs_equal": raw_outputs_equal,
        "normalized_outputs_equal": normalized_outputs_equal,
        "observation": normalized,
        "relationships": relationships,
        "linux_qt5_comparison": {
            "case_projection_differences": projection_differences,
            "cache_size_deltas": cache_size_deltas,
            "all_named_relationships_hold": (
                bool(relationships) and all(relationships.values())
            ),
        },
        "normalization": {
            "operations": [
                "replace fixed harness database/rule paths with <work>",
                (
                    "replace verified Qt test-mode APPDATA prefix with "
                    "<qt-test-appdata>"
                ),
                "convert cache_path backslashes to forward slashes",
            ],
            "not_performed": [
                "case removal or reordering",
                "cache hash/size rewriting",
                "scan result or error rewriting",
                "raw stdout/stderr hash rewriting",
            ],
        },
        "limitations": [
            (
                "the adapter maps POSIX chmod cases to explicit current-user "
                "Windows DACL deny/restore operations"
            ),
            (
                "QStandardPaths test mode isolates the harness from the "
                "ordinary user application-data namespace"
            ),
            (
                "the report covers a non-elevated local token and local "
                "NTFS paths; domain ACLs, network shares, EFS and alternate "
                "integrity levels are not covered"
            ),
            (
                "the Windows harness links Advapi32 only for research DACL "
                "setup; the unmodified engine object set is reused"
            ),
        ],
        "failures": failures,
        "passed": not failures,
    }
    serialized = (
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(serialized)
    print(serialized.decode("utf-8"), end="")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

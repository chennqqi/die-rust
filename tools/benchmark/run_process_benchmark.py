#!/usr/bin/env python3
"""Run hash-bound warm v1 or Linux file-content-controlled v2 benchmarks."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import statistics
import subprocess
import sys
import threading
import time
from typing import Any


PLAN_SCHEMA_VERSIONS = {1, 2}
REPORT_SCHEMA_VERSION = 2
RUNNER = {"name": "die-process-benchmark", "version": 2}
WARM = "warm"
FILE_CONTENT = "file-content-nonresident-metadata-warm"
FILE_CONTENT_CONTROLLER_KIND = "linux-file-content-v1"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
MAX_RUNS = 100
MAX_WARMUPS = 20
MAX_TIMEOUT_MS = 600_000
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
POLL_SECONDS = 0.002
INITIAL_RSS_ATTEMPTS = 16


class BenchmarkError(ValueError):
    """The benchmark plan, execution, or evidence is not trustworthy."""


def duplicate_key_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise BenchmarkError(f"non-finite JSON constant is not allowed: {value}")


def load_json(path: Path) -> tuple[object, bytes]:
    data = path.read_bytes()
    try:
        value = json.loads(
            data,
            object_pairs_hook=duplicate_key_rejector,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"invalid benchmark plan JSON: {error}") from error
    return value, data


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def require_object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{field} must be an object")
    return value


def require_list(value: object, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise BenchmarkError(f"{field} must be an array")
    return value


def require_exact_keys(
    value: dict[str, Any],
    required: set[str],
    optional: set[str],
    field: str,
) -> None:
    missing = sorted(required - value.keys())
    extra = sorted(value.keys() - required - optional)
    if missing:
        raise BenchmarkError(f"{field} missing fields: {', '.join(missing)}")
    if extra:
        raise BenchmarkError(f"{field} unknown fields: {', '.join(extra)}")


def require_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise BenchmarkError(f"{field} must be a non-empty NUL-free string")
    return value


def require_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise BenchmarkError(f"{field} must be a boolean")
    return value


def require_int(
    value: object,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise BenchmarkError(
            f"{field} must be an integer in {minimum}..{maximum}"
        )
    return value


def validate_relative_path(value: object, field: str) -> str:
    text = require_string(value, field)
    if "\\" in text:
        raise BenchmarkError(f"{field} must use '/' separators")
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise BenchmarkError(f"{field} must be a normalized relative path")
    return path.as_posix()


def validate_working_directory(value: object, field: str) -> str:
    text = require_string(value, field)
    if text == ".":
        return text
    return validate_relative_path(text, field)


def validate_producer(value: object) -> dict[str, str]:
    producer = require_object(value, "plan.producer")
    require_exact_keys(
        producer,
        {
            "implementation",
            "source_commit",
            "rules_commit",
            "build_profile",
            "toolchain",
        },
        set(),
        "plan.producer",
    )
    source_commit = require_string(
        producer["source_commit"],
        "plan.producer.source_commit",
    )
    rules_commit = require_string(
        producer["rules_commit"],
        "plan.producer.rules_commit",
    )
    if not HEX_40.fullmatch(source_commit):
        raise BenchmarkError("plan.producer.source_commit must be 40-hex")
    if not HEX_40.fullmatch(rules_commit):
        raise BenchmarkError("plan.producer.rules_commit must be 40-hex")
    return {
        "implementation": require_string(
            producer["implementation"],
            "plan.producer.implementation",
        ),
        "source_commit": source_commit,
        "rules_commit": rules_commit,
        "build_profile": require_string(
            producer["build_profile"],
            "plan.producer.build_profile",
        ),
        "toolchain": require_string(
            producer["toolchain"],
            "plan.producer.toolchain",
        ),
    }


def validate_artifact(value: object, index: int) -> dict[str, object]:
    field = f"plan.input_artifacts[{index}]"
    artifact = require_object(value, field)
    require_exact_keys(artifact, {"path", "bytes", "sha256"}, set(), field)
    digest = require_string(artifact["sha256"], f"{field}.sha256")
    if not HEX_64.fullmatch(digest):
        raise BenchmarkError(f"{field}.sha256 must be lowercase 64-hex")
    return {
        "path": validate_relative_path(artifact["path"], f"{field}.path"),
        "bytes": require_int(
            artifact["bytes"],
            f"{field}.bytes",
            0,
            (1 << 63) - 1,
        ),
        "sha256": digest,
    }


def validate_controller_artifact(
    value: object,
    field: str,
) -> dict[str, object]:
    artifact = require_object(value, field)
    require_exact_keys(
        artifact,
        {"path", "bytes", "sha256"},
        set(),
        field,
    )
    path = require_string(artifact["path"], f"{field}.path")
    pure = PurePosixPath(path)
    if (
        not pure.is_absolute()
        or "\\" in path
        or path != pure.as_posix()
        or any(part in {"", ".", ".."} for part in pure.parts[1:])
    ):
        raise BenchmarkError(
            f"{field}.path must be a normalized absolute POSIX path"
        )
    digest = require_string(artifact["sha256"], f"{field}.sha256")
    if not HEX_64.fullmatch(digest):
        raise BenchmarkError(
            f"{field}.sha256 must be lowercase 64-hex"
        )
    return {
        "path": path,
        "bytes": require_int(
            artifact["bytes"],
            f"{field}.bytes",
            1,
            (1 << 63) - 1,
        ),
        "sha256": digest,
    }


def validate_cache_controller(value: object) -> dict[str, object]:
    field = "plan.cache_controller"
    controller = require_object(value, field)
    require_exact_keys(
        controller,
        {
            "kind",
            "binary",
            "manifest",
            "page_size",
            "file_count",
            "logical_pages",
            "working_directory",
        },
        set(),
        field,
    )
    kind = require_string(controller["kind"], f"{field}.kind")
    if kind != FILE_CONTENT_CONTROLLER_KIND:
        raise BenchmarkError(
            "plan.cache_controller.kind is unsupported"
        )
    working_directory = require_string(
        controller["working_directory"],
        f"{field}.working_directory",
    )
    if working_directory != "/bench":
        raise BenchmarkError(
            "linux-file-content-v1 requires working_directory=/bench"
        )
    return {
        "kind": kind,
        "binary": validate_controller_artifact(
            controller["binary"],
            f"{field}.binary",
        ),
        "manifest": validate_controller_artifact(
            controller["manifest"],
            f"{field}.manifest",
        ),
        "page_size": require_int(
            controller["page_size"],
            f"{field}.page_size",
            4096,
            4096,
        ),
        "file_count": require_int(
            controller["file_count"],
            f"{field}.file_count",
            1,
            1_000_000,
        ),
        "logical_pages": require_int(
            controller["logical_pages"],
            f"{field}.logical_pages",
            1,
            (1 << 63) - 1,
        ),
        "working_directory": working_directory,
    }


def validate_plan(value: object) -> dict[str, object]:
    plan = require_object(value, "plan")
    schema = plan.get("benchmark_plan_schema")
    if (
        not isinstance(schema, int)
        or isinstance(schema, bool)
        or schema not in PLAN_SCHEMA_VERSIONS
    ):
        raise BenchmarkError("unsupported benchmark_plan_schema")
    optional = {"cache_controller"} if schema == 2 else set()
    require_exact_keys(
        plan,
        {
            "benchmark_plan_schema",
            "benchmark_id",
            "command",
            "working_directory",
            "environment",
            "inherit_environment",
            "producer",
            "input_artifacts",
            "cache_state",
            "warmup_runs",
            "measured_runs",
            "timeout_ms",
            "max_stdout_bytes",
            "max_stderr_bytes",
            "work_bytes",
            "work_definition",
            "require_deterministic_output",
            "require_peak_rss",
            "notes",
        },
        optional,
        "plan",
    )
    benchmark_id = require_string(plan["benchmark_id"], "plan.benchmark_id")
    if not ID.fullmatch(benchmark_id):
        raise BenchmarkError("plan.benchmark_id must be one exact ID")
    command_values = require_list(plan["command"], "plan.command")
    if not 1 <= len(command_values) <= 128:
        raise BenchmarkError("plan.command must contain 1..128 argv items")
    command = [
        require_string(item, f"plan.command[{index}]")
        for index, item in enumerate(command_values)
    ]
    environment_value = require_object(plan["environment"], "plan.environment")
    environment: dict[str, str] = {}
    for key, item in environment_value.items():
        name = require_string(key, "plan.environment key")
        if "=" in name:
            raise BenchmarkError("plan.environment keys must not contain '='")
        environment[name] = require_string(
            item,
            f"plan.environment[{name!r}]",
        )
    artifacts = [
        validate_artifact(item, index)
        for index, item in enumerate(
            require_list(plan["input_artifacts"], "plan.input_artifacts")
        )
    ]
    artifact_paths = [str(item["path"]) for item in artifacts]
    if len(artifact_paths) != len(set(artifact_paths)):
        raise BenchmarkError("plan.input_artifacts paths must be unique")
    cache_state = require_string(plan["cache_state"], "plan.cache_state")
    cache_controller = None
    if schema == 1 and cache_state != WARM:
        raise BenchmarkError(
            "only explicit warm cache_state is supported; cold cache "
            "requires a platform-specific controller"
        )
    if schema == 2:
        if cache_state not in {WARM, FILE_CONTENT}:
            raise BenchmarkError(
                "schema v2 cache_state must be warm or "
                "file-content-nonresident-metadata-warm"
            )
        if "cache_controller" not in plan:
            raise BenchmarkError(
                "schema v2 requires plan.cache_controller"
            )
        cache_controller = validate_cache_controller(
            plan["cache_controller"]
        )
        if plan["timeout_ms"] != 120_000:
            raise BenchmarkError(
                "linux-file-content-v1 requires timeout_ms=120000"
            )
        if plan["warmup_runs"] != 0 or plan["measured_runs"] != 1:
            raise BenchmarkError(
                "linux-file-content-v1 requires warmup_runs=0 and "
                "measured_runs=1; pairing belongs to the suite"
            )
    notes = [
        require_string(item, f"plan.notes[{index}]")
        for index, item in enumerate(require_list(plan["notes"], "plan.notes"))
    ]
    return {
        "benchmark_plan_schema": schema,
        "benchmark_id": benchmark_id,
        "command": command,
        "working_directory": validate_working_directory(
            plan["working_directory"],
            "plan.working_directory",
        ),
        "environment": dict(sorted(environment.items())),
        "inherit_environment": require_bool(
            plan["inherit_environment"],
            "plan.inherit_environment",
        ),
        "producer": validate_producer(plan["producer"]),
        "input_artifacts": artifacts,
        "cache_state": cache_state,
        "warmup_runs": require_int(
            plan["warmup_runs"],
            "plan.warmup_runs",
            0,
            MAX_WARMUPS,
        ),
        "measured_runs": require_int(
            plan["measured_runs"],
            "plan.measured_runs",
            1 if schema == 2 else 3,
            MAX_RUNS,
        ),
        "timeout_ms": require_int(
            plan["timeout_ms"],
            "plan.timeout_ms",
            1,
            MAX_TIMEOUT_MS,
        ),
        "max_stdout_bytes": require_int(
            plan["max_stdout_bytes"],
            "plan.max_stdout_bytes",
            0,
            MAX_CAPTURE_BYTES,
        ),
        "max_stderr_bytes": require_int(
            plan["max_stderr_bytes"],
            "plan.max_stderr_bytes",
            0,
            MAX_CAPTURE_BYTES,
        ),
        "work_bytes": require_int(
            plan["work_bytes"],
            "plan.work_bytes",
            1,
            (1 << 63) - 1,
        ),
        "work_definition": require_string(
            plan["work_definition"],
            "plan.work_definition",
        ),
        "require_deterministic_output": require_bool(
            plan["require_deterministic_output"],
            "plan.require_deterministic_output",
        ),
        "require_peak_rss": require_bool(
            plan["require_peak_rss"],
            "plan.require_peak_rss",
        ),
        "notes": notes,
        **(
            {"cache_controller": cache_controller}
            if cache_controller is not None
            else {}
        ),
    }


def is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def resolve_below_root(root: Path, relative: str, field: str) -> Path:
    candidate = root
    try:
        for part in PurePosixPath(relative).parts:
            candidate = candidate / part
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or is_reparse_point(metadata):
                raise BenchmarkError(
                    f"{field} contains a symlink/reparse component"
                )
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except BenchmarkError:
        raise
    except (OSError, ValueError) as error:
        raise BenchmarkError(f"{field} escapes repository root") from error
    return resolved


def resolve_executable(command: list[str], cwd: Path) -> Path:
    raw = command[0]
    if "/" in raw or "\\" in raw or Path(raw).is_absolute():
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = cwd / candidate
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise BenchmarkError(f"cannot resolve executable: {error}") from error
    else:
        found = shutil.which(raw)
        if found is None:
            raise BenchmarkError(f"executable not found on PATH: {raw}")
        resolved = Path(found).resolve(strict=True)
    if not resolved.is_file():
        raise BenchmarkError("command executable must be a regular file")
    return resolved


def validate_inputs(
    root: Path,
    artifacts: list[dict[str, object]],
) -> list[dict[str, object]]:
    result = []
    for index, artifact in enumerate(artifacts):
        path = resolve_below_root(
            root,
            str(artifact["path"]),
            f"input artifact {index}",
        )
        metadata = path.stat()
        if not path.is_file():
            raise BenchmarkError(f"input artifact {index} is not a file")
        if metadata.st_size != artifact["bytes"]:
            raise BenchmarkError(f"input artifact {index} byte count mismatch")
        digest = sha256_file(path)
        if digest != artifact["sha256"]:
            raise BenchmarkError(f"input artifact {index} SHA-256 mismatch")
        result.append(dict(artifact))
    return result


def resolve_controller_artifact(
    artifact: dict[str, object],
    field: str,
    *,
    executable: bool,
) -> tuple[Path, dict[str, object]]:
    path = Path(str(artifact["path"]))
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or is_reparse_point(metadata):
            raise BenchmarkError(f"{field} must not be a symlink/reparse point")
        resolved = path.resolve(strict=True)
    except BenchmarkError:
        raise
    except OSError as error:
        raise BenchmarkError(f"cannot resolve {field}: {error}") from error
    if not resolved.is_file():
        raise BenchmarkError(f"{field} must be a regular file")
    if executable and not os.access(resolved, os.X_OK):
        raise BenchmarkError(f"{field} must be executable")
    identity = {
        "path": str(artifact["path"]),
        "bytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }
    if (
        identity["bytes"] != artifact["bytes"]
        or identity["sha256"] != artifact["sha256"]
    ):
        raise BenchmarkError(f"{field} identity mismatch")
    return resolved, identity


def parse_controller_tsv(raw: bytes) -> dict[str, str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise BenchmarkError(
            f"cache controller output is not UTF-8: {error}"
        ) from error
    result: dict[str, str] = {}
    for line in lines:
        name, separator, value = line.partition("\t")
        if not separator or not name or name in result:
            raise BenchmarkError(
                "invalid or duplicate cache controller field"
            )
        result[name] = value
    expected = {
        "schema_version",
        "cache_state",
        "fadvise_executed",
        "page_size",
        "file_count",
        "logical_pages",
        "resident_pages_after_warm",
        "resident_pages_before_run",
        "before_run_page_state_verified",
        "duration_ns",
        "peak_rss_bytes",
        "exit_code",
        "timed_out",
    }
    if set(result) != expected:
        raise BenchmarkError("cache controller fields changed")
    return result


def parse_controller_measurement(
    raw: bytes,
    cache_state: str,
    controller: dict[str, object],
) -> dict[str, object]:
    fields = parse_controller_tsv(raw)
    integers: dict[str, int] = {}
    for name, value in fields.items():
        if name == "cache_state":
            continue
        if not value.isascii() or not value.isdecimal():
            raise BenchmarkError(
                f"cache controller {name} is not an unsigned integer"
            )
        integers[name] = int(value)
    logical_pages = int(controller["logical_pages"])
    expected_before = logical_pages if cache_state == WARM else 0
    if (
        fields["cache_state"] != cache_state
        or integers["schema_version"] != 1
        or integers["fadvise_executed"]
        != (0 if cache_state == WARM else 1)
        or integers["page_size"] != controller["page_size"]
        or integers["file_count"] != controller["file_count"]
        or integers["logical_pages"] != logical_pages
        or integers["resident_pages_after_warm"] != logical_pages
        or integers["resident_pages_before_run"] != expected_before
        or integers["before_run_page_state_verified"] != 1
        or integers["duration_ns"] <= 0
        or integers["peak_rss_bytes"] <= 0
        or integers["exit_code"] != 0
        or integers["timed_out"] != 0
    ):
        raise BenchmarkError("cache controller measurement invariant failed")
    return {
        "duration_ns": integers["duration_ns"],
        "peak_rss_bytes": integers["peak_rss_bytes"],
        "exit_code": 0,
        "cache_controller_evidence": {
            "kind": controller["kind"],
            "before_run_page_state_verified": True,
            "fadvise_executed": (
                integers["fadvise_executed"] == 1
            ),
            "page_size": integers["page_size"],
            "file_count": integers["file_count"],
            "logical_pages": logical_pages,
            "resident_pages_after_warm": logical_pages,
            "resident_pages_before_run": expected_before,
        },
    }


def windows_rss_bytes(pid: int) -> int | None:
    if os.name != "nt":
        return None

    class ProcessMemoryCounters(ctypes.Structure):
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

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.argtypes = [
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    psapi.GetProcessMemoryInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    handle = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
    if not handle:
        return None
    try:
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(
            handle,
            ctypes.byref(counters),
            counters.cb,
        ):
            return None
        return int(counters.PeakWorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


def linux_rss_bytes(pid: int) -> int | None:
    if not sys.platform.startswith("linux"):
        return None
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    except OSError:
        return None
    for field in ("VmHWM:", "VmRSS:"):
        for line in text.splitlines():
            if line.startswith(field):
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1]) * 1024
    return None


def darwin_rss_bytes(pid: int) -> int | None:
    if sys.platform != "darwin":
        return None

    class RusageInfoV2(ctypes.Structure):
        _fields_ = [
            ("ri_uuid", ctypes.c_ubyte * 16),
            ("ri_user_time", ctypes.c_uint64),
            ("ri_system_time", ctypes.c_uint64),
            ("ri_pkg_idle_wkups", ctypes.c_uint64),
            ("ri_interrupt_wkups", ctypes.c_uint64),
            ("ri_pageins", ctypes.c_uint64),
            ("ri_wired_size", ctypes.c_uint64),
            ("ri_resident_size", ctypes.c_uint64),
            ("ri_phys_footprint", ctypes.c_uint64),
            ("ri_proc_start_abstime", ctypes.c_uint64),
            ("ri_proc_exit_abstime", ctypes.c_uint64),
            ("ri_child_user_time", ctypes.c_uint64),
            ("ri_child_system_time", ctypes.c_uint64),
            ("ri_child_pkg_idle_wkups", ctypes.c_uint64),
            ("ri_child_interrupt_wkups", ctypes.c_uint64),
            ("ri_child_pageins", ctypes.c_uint64),
            ("ri_child_elapsed_abstime", ctypes.c_uint64),
            ("ri_diskio_bytesread", ctypes.c_uint64),
            ("ri_diskio_byteswritten", ctypes.c_uint64),
        ]

    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
        info = RusageInfoV2()
        result = libproc.proc_pid_rusage(pid, 2, ctypes.byref(info))
    except (OSError, AttributeError):
        return None
    return int(info.ri_resident_size) if result == 0 else None


def sample_rss_bytes(pid: int) -> int | None:
    if os.name == "nt":
        return windows_rss_bytes(pid)
    if sys.platform.startswith("linux"):
        return linux_rss_bytes(pid)
    if sys.platform == "darwin":
        return darwin_rss_bytes(pid)
    return None


def rss_method() -> str:
    if os.name == "nt":
        return "GetProcessMemoryInfo.PeakWorkingSetSize"
    if sys.platform.startswith("linux"):
        return "/proc/PID/status VmHWM/VmRSS polling"
    if sys.platform == "darwin":
        return "proc_pid_rusage resident_size polling"
    return "unsupported"


def build_environment(plan: dict[str, object]) -> dict[str, str]:
    inherit = bool(plan["inherit_environment"])
    environment = dict(os.environ) if inherit else {}
    overrides = plan["environment"]
    assert isinstance(overrides, dict)
    environment.update({str(key): str(value) for key, value in overrides.items()})
    return environment


def run_once(
    *,
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
    timeout_ms: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    expected_exit_code: int = 0,
) -> dict[str, object]:
    started = time.perf_counter_ns()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stop = threading.Event()
    observed_peak: list[int] = []
    for attempt in range(INITIAL_RSS_ATTEMPTS):
        initial_rss = sample_rss_bytes(process.pid)
        if initial_rss is not None:
            observed_peak.append(initial_rss)
            break
        if process.poll() is not None:
            break
        if attempt + 1 < INITIAL_RSS_ATTEMPTS:
            time.sleep(0)
    output_results: dict[str, dict[str, object]] = {}
    output_limit_exceeded: list[str] = []
    output_lock = threading.Lock()

    def monitor() -> None:
        while not stop.is_set():
            value = sample_rss_bytes(process.pid)
            if value is not None:
                observed_peak.append(value)
            stop.wait(POLL_SECONDS)

    def drain_output(stream: Any, name: str, limit: int) -> None:
        digest = hashlib.sha256()
        byte_count = 0
        while block := stream.read(65_536):
            byte_count += len(block)
            digest.update(block)
            if byte_count > limit:
                with output_lock:
                    if name not in output_limit_exceeded:
                        output_limit_exceeded.append(name)
                try:
                    process.kill()
                except OSError:
                    pass
        output_results[name] = {
            "bytes": byte_count,
            "sha256": digest.hexdigest(),
        }

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    stdout_thread = threading.Thread(
        target=drain_output,
        args=(process.stdout, "stdout", max_stdout_bytes),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain_output,
        args=(process.stderr, "stderr", max_stderr_bytes),
        daemon=True,
    )
    monitor_thread.start()
    stdout_thread.start()
    stderr_thread.start()
    try:
        exit_code = process.wait(timeout=timeout_ms / 1000)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        raise BenchmarkError(
            f"benchmark command timed out after {timeout_ms} ms"
        ) from error
    finally:
        stdout_thread.join()
        stderr_thread.join()
        process.stdout.close()
        process.stderr.close()
        final_rss = sample_rss_bytes(process.pid)
        if final_rss is not None:
            observed_peak.append(final_rss)
        stop.set()
        monitor_thread.join(timeout=1)
    finished = time.perf_counter_ns()
    if output_limit_exceeded:
        names = ", ".join(sorted(output_limit_exceeded))
        raise BenchmarkError(f"{names} exceeded configured byte limit")
    if exit_code != expected_exit_code:
        raise BenchmarkError(
            f"benchmark command exited {exit_code}, expected "
            f"{expected_exit_code}"
        )
    return {
        "duration_ns": finished - started,
        "peak_rss_bytes": max(observed_peak) if observed_peak else None,
        "exit_code": exit_code,
        "stdout": output_results["stdout"],
        "stderr": output_results["stderr"],
    }


def bounded_file_identity(
    path: Path,
    field: str,
    limit: int,
) -> dict[str, object]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise BenchmarkError(f"cannot read controlled {field}: {error}") from error
    if size > limit:
        raise BenchmarkError(
            f"{field} exceeded configured byte limit"
        )
    return {
        "bytes": size,
        "sha256": sha256_file(path),
    }


def percentile_nearest_rank(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def summarize_runs(
    runs: list[dict[str, object]],
    work_bytes: int,
) -> dict[str, object]:
    durations = [int(run["duration_ns"]) for run in runs]
    peaks = [
        int(run["peak_rss_bytes"])
        for run in runs
        if run["peak_rss_bytes"] is not None
    ]
    median_ns = int(statistics.median(durations))
    mad_ns = int(
        statistics.median(abs(value - median_ns) for value in durations)
    )
    return {
        "sample_count": len(runs),
        "duration_ns": {
            "min": min(durations),
            "median": median_ns,
            "p95_nearest_rank": percentile_nearest_rank(durations, 0.95),
            "max": max(durations),
            "mad": mad_ns,
        },
        "throughput_bytes_per_second_at_median": (
            work_bytes * 1_000_000_000 / median_ns
        ),
        "peak_rss_bytes": (
            {
                "sample_count": len(peaks),
                "median": int(statistics.median(peaks)),
                "max": max(peaks),
            }
            if peaks
            else None
        ),
        "stdout_unique_sha256": sorted(
            {str(run["stdout"]["sha256"]) for run in runs}
        ),
        "stderr_unique_sha256": sorted(
            {str(run["stderr"]["sha256"]) for run in runs}
        ),
    }


def total_memory_bytes() -> int | None:
    if os.name == "nt":
        class MemoryStatusEx(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatusEx()
        status.dwLength = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullTotalPhys)
        return None
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
        except OSError:
            return None
    if sys.platform == "darwin":
        size = ctypes.c_size_t(ctypes.sizeof(ctypes.c_uint64))
        value = ctypes.c_uint64()
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        if libc.sysctlbyname(
            b"hw.memsize",
            ctypes.byref(value),
            ctypes.byref(size),
            None,
            0,
        ) == 0:
            return int(value.value)
    return None


def cpu_model() -> str:
    if os.name == "nt":
        return os.environ.get("PROCESSOR_IDENTIFIER", "") or platform.processor()
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith(("model name", "hardware")):
                    return line.split(":", 1)[1].strip()
        except (OSError, IndexError):
            pass
    return platform.processor() or "unavailable"


def windows_filesystem(path: Path) -> str | None:
    if os.name != "nt":
        return None
    root = Path(path.anchor)
    buffer = ctypes.create_unicode_buffer(64)
    if ctypes.windll.kernel32.GetVolumeInformationW(
        str(root),
        None,
        0,
        None,
        None,
        None,
        buffer,
        len(buffer),
    ):
        return buffer.value
    return None


def linux_filesystem(path: Path) -> str | None:
    if not sys.platform.startswith("linux"):
        return None
    try:
        target = path.resolve().as_posix()
        candidates: list[tuple[int, str]] = []
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            left, right = line.split(" - ", 1)
            mount_point = left.split()[4].replace("\\040", " ")
            file_system = right.split()[0]
            if target == mount_point or target.startswith(mount_point.rstrip("/") + "/"):
                candidates.append((len(mount_point), file_system))
        return max(candidates)[1] if candidates else None
    except (OSError, ValueError, IndexError):
        return None


def host_identity(cwd: Path) -> dict[str, object]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "cpu_model": cpu_model(),
        "logical_cpu_count": os.cpu_count(),
        "total_memory_bytes": total_memory_bytes(),
        "filesystem": (
            windows_filesystem(cwd)
            or linux_filesystem(cwd)
            or "unavailable"
        ),
        "python": platform.python_version(),
        "rss_method": rss_method(),
        "clock": "time.perf_counter_ns",
    }


def exact_file_identity(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise BenchmarkError(f"identity target is not a file: {path}")
    return {
        "path": str(resolved),
        "bytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def controlled_exchange_paths(output: Path) -> dict[str, Path]:
    return {
        "measurement": output.with_name(
            output.name + ".measurement.tsv"
        ),
        "stdout": output.with_name(output.name + ".stdout.bin"),
        "stderr": output.with_name(output.name + ".stderr.bin"),
        "preflight": output.with_name(
            output.name + ".preflight.json"
        ),
    }


def exec_controlled_benchmark(
    raw_plan: object,
    raw_plan_bytes: bytes,
    repo_root: Path,
    plan_path: Path,
    output: Path,
) -> None:
    plan = validate_plan(raw_plan)
    if plan["benchmark_plan_schema"] != 2:
        raise BenchmarkError(
            "controlled exec requires benchmark_plan_schema=2"
        )
    output = output.resolve()
    controller = plan["cache_controller"]
    assert isinstance(controller, dict)
    if (
        not sys.platform.startswith("linux")
        or platform.machine() != "x86_64"
    ):
        raise BenchmarkError(
            "linux-file-content-v1 requires Linux x86_64"
        )
    repo_root = repo_root.resolve(strict=True)
    cwd = resolve_below_root(
        repo_root,
        str(plan["working_directory"]),
        "working directory",
    )
    if (
        not cwd.is_dir()
        or cwd.as_posix() != controller["working_directory"]
    ):
        raise BenchmarkError(
            "cache controller working directory does not match plan"
        )
    command = list(plan["command"])
    if not Path(command[0]).is_absolute():
        raise BenchmarkError(
            "controlled benchmark command[0] must be absolute"
        )
    executable = resolve_executable(command, cwd)
    artifacts = plan["input_artifacts"]
    assert isinstance(artifacts, list)
    frozen_artifacts = validate_inputs(repo_root, artifacts)
    binary_artifact = controller["binary"]
    manifest_artifact = controller["manifest"]
    assert isinstance(binary_artifact, dict)
    assert isinstance(manifest_artifact, dict)
    controller_binary, binary_identity = resolve_controller_artifact(
        binary_artifact,
        "cache controller binary",
        executable=True,
    )
    controller_manifest, manifest_identity = (
        resolve_controller_artifact(
            manifest_artifact,
            "cache controller manifest",
            executable=False,
        )
    )
    runner_source = Path(__file__).resolve(strict=True)
    finalizer_python = Path(sys.executable).resolve(strict=True)
    paths = controlled_exchange_paths(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    preflight = {
        "schema_version": 1,
        "plan_artifact": {
            "sha256": sha256_bytes(raw_plan_bytes),
            "canonical_sha256": sha256_bytes(
                canonical_json(raw_plan)
            ),
        },
        "runner_source": exact_file_identity(runner_source),
        "finalizer_python": exact_file_identity(finalizer_python),
        "host": host_identity(cwd),
        "working_directory": str(cwd),
        "executable": exact_file_identity(executable),
        "input_artifacts": frozen_artifacts,
        "cache_controller": {
            "binary": binary_identity,
            "manifest": manifest_identity,
        },
    }
    paths["preflight"].write_bytes(serialize_report(preflight))
    environment = build_environment(plan)
    controller_command = [
        str(controller_binary),
        "--cache-state",
        str(plan["cache_state"]),
        "--manifest",
        str(controller_manifest),
        "--output",
        str(paths["measurement"]),
        "--stdout",
        str(paths["stdout"]),
        "--stderr",
        str(paths["stderr"]),
        "--finalizer-python",
        str(finalizer_python),
        "--finalizer-script",
        str(runner_source),
        "--final-report",
        str(output),
        "--plan",
        str(plan_path.resolve(strict=True)),
        "--preflight",
        str(paths["preflight"]),
        "--repo-root",
        str(repo_root),
        "--",
        *command,
    ]
    os.execve(
        str(controller_binary),
        controller_command,
        environment,
    )


def require_preflight(
    value: object,
) -> dict[str, Any]:
    preflight = require_object(value, "preflight")
    require_exact_keys(
        preflight,
        {
            "schema_version",
            "plan_artifact",
            "runner_source",
            "finalizer_python",
            "host",
            "working_directory",
            "executable",
            "input_artifacts",
            "cache_controller",
        },
        set(),
        "preflight",
    )
    if preflight["schema_version"] != 1:
        raise BenchmarkError("unsupported controlled preflight schema")
    return preflight


def finalize_controlled_benchmark(
    raw_plan: object,
    raw_plan_bytes: bytes,
    repo_root: Path,
    preflight_value: object,
    measurement_path: Path,
    stdout_path: Path,
    stderr_path: Path,
) -> dict[str, object]:
    plan = validate_plan(raw_plan)
    if plan["benchmark_plan_schema"] != 2:
        raise BenchmarkError(
            "controlled finalizer requires benchmark_plan_schema=2"
        )
    preflight = require_preflight(preflight_value)
    expected_plan_artifact = {
        "sha256": sha256_bytes(raw_plan_bytes),
        "canonical_sha256": sha256_bytes(canonical_json(raw_plan)),
    }
    if preflight["plan_artifact"] != expected_plan_artifact:
        raise BenchmarkError("controlled preflight plan identity mismatch")
    repo_root = repo_root.resolve(strict=True)
    cwd = resolve_below_root(
        repo_root,
        str(plan["working_directory"]),
        "working directory",
    )
    if str(cwd) != preflight["working_directory"]:
        raise BenchmarkError(
            "controlled preflight working directory changed"
        )
    command = list(plan["command"])
    executable = resolve_executable(command, cwd)
    if exact_file_identity(executable) != preflight["executable"]:
        raise BenchmarkError(
            "controlled executable changed during benchmark"
        )
    artifacts = plan["input_artifacts"]
    assert isinstance(artifacts, list)
    if validate_inputs(repo_root, artifacts) != preflight["input_artifacts"]:
        raise BenchmarkError(
            "controlled input artifact changed during benchmark"
        )
    controller = plan["cache_controller"]
    assert isinstance(controller, dict)
    binary_artifact = controller["binary"]
    manifest_artifact = controller["manifest"]
    assert isinstance(binary_artifact, dict)
    assert isinstance(manifest_artifact, dict)
    _, binary_identity = resolve_controller_artifact(
        binary_artifact,
        "cache controller binary",
        executable=True,
    )
    _, manifest_identity = resolve_controller_artifact(
        manifest_artifact,
        "cache controller manifest",
        executable=False,
    )
    if preflight["cache_controller"] != {
        "binary": binary_identity,
        "manifest": manifest_identity,
    }:
        raise BenchmarkError(
            "cache controller artifact changed during benchmark"
        )
    runner_identity = exact_file_identity(Path(__file__))
    python_identity = exact_file_identity(Path(sys.executable))
    if (
        runner_identity != preflight["runner_source"]
        or python_identity != preflight["finalizer_python"]
    ):
        raise BenchmarkError(
            "controlled finalizer identity changed"
        )
    measurement_raw = measurement_path.read_bytes()
    if len(measurement_raw) > 16_384:
        raise BenchmarkError(
            "cache controller measurement exceeded byte limit"
        )
    run = parse_controller_measurement(
        measurement_raw,
        str(plan["cache_state"]),
        controller,
    )
    run["stdout"] = bounded_file_identity(
        stdout_path,
        "stdout",
        int(plan["max_stdout_bytes"]),
    )
    run["stderr"] = bounded_file_identity(
        stderr_path,
        "stderr",
        int(plan["max_stderr_bytes"]),
    )
    runs = [run]
    summary = summarize_runs(runs, int(plan["work_bytes"]))
    if (
        plan["require_deterministic_output"]
        and (
            len(summary["stdout_unique_sha256"]) != 1
            or len(summary["stderr_unique_sha256"]) != 1
        )
    ):
        raise BenchmarkError(
            "controlled stdout/stderr are not deterministic"
        )
    if plan["require_peak_rss"] and summary["peak_rss_bytes"] is None:
        raise BenchmarkError(
            "controlled peak RSS measurement is unavailable"
        )
    environment_value = plan["environment"]
    assert isinstance(environment_value, dict)
    return {
        "benchmark_report_schema": REPORT_SCHEMA_VERSION,
        "runner": RUNNER,
        "runner_source": runner_identity,
        "finalizer_python": python_identity,
        "result": "pass",
        "benchmark_id": plan["benchmark_id"],
        "plan_artifact": expected_plan_artifact,
        "producer": plan["producer"],
        "execution": {
            "command": command,
            "working_directory": plan["working_directory"],
            "environment_policy": (
                "inherit_with_overrides"
                if plan["inherit_environment"]
                else "explicit_only"
            ),
            "environment_override_keys": sorted(environment_value),
            "environment_overrides_sha256": sha256_bytes(
                canonical_json(environment_value)
            ),
            "cache_state": plan["cache_state"],
            "warmup_runs": 0,
            "measured_runs": 1,
            "timeout_ms": plan["timeout_ms"],
            "work_bytes": plan["work_bytes"],
            "work_definition": plan["work_definition"],
            "notes": plan["notes"],
            "measurement": {
                "clock": "clock_gettime(CLOCK_MONOTONIC)",
                "peak_rss_method": (
                    "wait4 child rusage.ru_maxrss * 1024"
                ),
                "timed_process_scope": "direct child",
            },
        },
        "host": preflight["host"],
        "executable": preflight["executable"],
        "input_artifacts": preflight["input_artifacts"],
        "cache_controller": {
            "kind": controller["kind"],
            "binary": binary_identity,
            "manifest": manifest_identity,
            "page_size": controller["page_size"],
            "file_count": controller["file_count"],
            "logical_pages": controller["logical_pages"],
            "working_directory": controller["working_directory"],
            "clock": "clock_gettime(CLOCK_MONOTONIC)",
            "peak_rss_method": (
                "wait4 child rusage.ru_maxrss * 1024"
            ),
            "timed_process_scope": "direct child",
        },
        "warmup_validation": {
            "run_count": 0,
            "stdout_unique_sha256": [],
            "stderr_unique_sha256": [],
        },
        "runs": runs,
        "summary": summary,
        "limitations": [
            (
                "candidate content-page residency is controlled, but "
                "pathname, dentry, inode, and failed-lookup metadata "
                "are not system-cold"
            ),
            (
                "peak RSS is wait4 direct-child ru_maxrss, not "
                "controller, descendant-tree, or filesystem-cache memory"
            ),
            (
                "thread scheduling, physical-core topology, power "
                "governor, and background load are not controlled"
            ),
            (
                "linux-file-content-v1 is Linux x86_64 and /bench "
                "specific; other platforms require reviewed controllers"
            ),
            (
                "this report is a process-level benchmark, not a "
                "component profiler or system-cold result"
            ),
        ],
    }


def run_benchmark(
    raw_plan: object,
    repo_root: Path,
    raw_plan_bytes: bytes | None = None,
) -> dict[str, object]:
    plan = validate_plan(raw_plan)
    if plan["benchmark_plan_schema"] == 2:
        raise BenchmarkError(
            "schema v2 requires the CLI preflight/exec/finalize chain"
        )
    repo_root = repo_root.resolve(strict=True)
    cwd = resolve_below_root(
        repo_root,
        str(plan["working_directory"]),
        "working directory",
    )
    if not cwd.is_dir():
        raise BenchmarkError("working directory must be a directory")
    command = list(plan["command"])
    executable = resolve_executable(command, cwd)
    executable_before = {
        "path": str(executable),
        "bytes": executable.stat().st_size,
        "sha256": sha256_file(executable),
    }
    artifacts = plan["input_artifacts"]
    assert isinstance(artifacts, list)
    frozen_artifacts = validate_inputs(repo_root, artifacts)
    environment = build_environment(plan)
    environment_value = plan["environment"]
    assert isinstance(environment_value, dict)

    run_arguments = {
        "command": command,
        "cwd": cwd,
        "environment": environment,
        "timeout_ms": int(plan["timeout_ms"]),
        "max_stdout_bytes": int(plan["max_stdout_bytes"]),
        "max_stderr_bytes": int(plan["max_stderr_bytes"]),
    }
    warmups = [
        run_once(**run_arguments)
        for _ in range(int(plan["warmup_runs"]))
    ]
    runs = [
        run_once(**run_arguments)
        for _ in range(int(plan["measured_runs"]))
    ]
    executable_after = {
        "path": str(executable),
        "bytes": executable.stat().st_size,
        "sha256": sha256_file(executable),
    }
    if executable_after != executable_before:
        raise BenchmarkError("executable changed during benchmark")
    validate_inputs(repo_root, artifacts)
    summary = summarize_runs(runs, int(plan["work_bytes"]))
    if (
        plan["require_deterministic_output"]
        and (
            len(summary["stdout_unique_sha256"]) != 1
            or len(summary["stderr_unique_sha256"]) != 1
        )
    ):
        raise BenchmarkError("measured stdout/stderr are not deterministic")
    if plan["require_peak_rss"] and summary["peak_rss_bytes"] is None:
        raise BenchmarkError("peak RSS measurement is required but unavailable")
    plan_bytes = raw_plan_bytes or canonical_json(raw_plan)
    return {
        "benchmark_report_schema": 1,
        "runner": RUNNER,
        "result": "pass",
        "benchmark_id": plan["benchmark_id"],
        "plan_artifact": {
            "sha256": sha256_bytes(plan_bytes),
            "canonical_sha256": sha256_bytes(canonical_json(raw_plan)),
        },
        "producer": plan["producer"],
        "execution": {
            "command": command,
            "working_directory": plan["working_directory"],
            "environment_policy": (
                "inherit_with_overrides"
                if plan["inherit_environment"]
                else "explicit_only"
            ),
            "environment_override_keys": sorted(environment_value),
            "environment_overrides_sha256": sha256_bytes(
                canonical_json(environment_value)
            ),
            "cache_state": plan["cache_state"],
            "warmup_runs": plan["warmup_runs"],
            "measured_runs": plan["measured_runs"],
            "timeout_ms": plan["timeout_ms"],
            "work_bytes": plan["work_bytes"],
            "work_definition": plan["work_definition"],
            "notes": plan["notes"],
            "measurement": {
                "clock": "time.perf_counter_ns",
                "peak_rss_method": rss_method(),
                "timed_process_scope": "direct process",
            },
        },
        "host": host_identity(cwd),
        "executable": executable_before,
        "input_artifacts": frozen_artifacts,
        "warmup_validation": {
            "run_count": len(warmups),
            "stdout_unique_sha256": sorted(
                {str(run["stdout"]["sha256"]) for run in warmups}
            ),
            "stderr_unique_sha256": sorted(
                {str(run["stderr"]["sha256"]) for run in warmups}
            ),
        },
        "runs": runs,
        "summary": summary,
        "limitations": [
            "warm cache state is declared but the OS cache is not forcibly controlled",
            "peak RSS is sampled for the direct process, not an arbitrary descendant tree",
            "thread scheduling, CPU affinity, power governor, and background load are not controlled",
            "this report is a process-level benchmark, not a component profiler",
            "timeouts terminate only the direct process; commands must not leave persistent descendants",
        ],
    }


def serialize_report(report: dict[str, object]) -> bytes:
    return (
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    script_parents = Path(__file__).resolve().parents
    default_root = (
        script_parents[2]
        if len(script_parents) > 2
        else Path.cwd()
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--finalize-controlled",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--measurement",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--stdout",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--stderr",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--preflight",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=default_root,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        plan, raw_plan = load_json(args.plan)
        if args.finalize_controlled:
            if any(
                path is None
                for path in (
                    args.measurement,
                    args.stdout,
                    args.stderr,
                    args.preflight,
                )
            ):
                raise BenchmarkError(
                    "controlled finalizer paths are required"
                )
            preflight, _ = load_json(args.preflight)
            report = finalize_controlled_benchmark(
                plan,
                raw_plan,
                args.repo_root,
                preflight,
                args.measurement,
                args.stdout,
                args.stderr,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(serialize_report(report))
        elif (
            isinstance(plan, dict)
            and plan.get("benchmark_plan_schema") == 2
        ):
            exec_controlled_benchmark(
                plan,
                raw_plan,
                args.repo_root,
                args.plan,
                args.output,
            )
            raise BenchmarkError(
                "controlled exec unexpectedly returned"
            )
        else:
            report = run_benchmark(plan, args.repo_root, raw_plan)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(serialize_report(report))
    except (BenchmarkError, OSError, subprocess.SubprocessError) as error:
        print(f"benchmark error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

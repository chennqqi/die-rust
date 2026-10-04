#!/usr/bin/env python3
"""Collect a raw execution record from the Rust diec binary.

Run the ``diec`` CLI with the given arguments in an isolated temporary
directory, capture stdout/stderr/exit code/timing, write content-addressed
byte artifacts, and emit a ``raw-execution-v1`` compliant JSON record that
``verify_raw_execution.py`` can audit.

This is the Rust producer adapter for the differential framework. It never
participates in generating upstream expected values; it only captures the
Rust side's observable behaviour. See ``docs/design/testing.md`` section 7
and ``docs/design/schemas/raw-execution-v1.schema.json``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import time
from typing import Any

import verify_raw_execution as raw_verifier


COLLECTOR_NAME = "die-rust-execution-collector"
COLLECTOR_VERSION = 1
HASH_CHUNK_BYTES = 1024 * 1024
MAX_STDOUT_BYTES = 64 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 30
HEX_40 = re.compile(r"^[0-9a-f]{40}$")


class CollectorError(ValueError):
    """The collector inputs or captured execution are not valid."""


def sha256_bytes(data: bytes) -> str:
    """Compute the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    """Compute the SHA-256 hex digest of a file by streaming."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def detect_platform() -> str:
    """Return a ``raw-execution-v1`` platform string like ``linux-x86_64``."""
    os_name = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        machine = "x86_64"
    elif machine in ("aarch64", "arm64"):
        machine = "aarch64"
    return f"{os_name}-{machine}"


def git_revision(repo: pathlib.Path) -> str:
    """Return the 40-hex git revision of *repo*, or ``0``*40 on error."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        rev = result.stdout.strip()
        if HEX_40.match(rev):
            return rev
    except (OSError, subprocess.SubprocessError):
        pass
    return "0" * 40


def write_artifact(
    artifact_root: pathlib.Path,
    role: str,
    data: bytes,
) -> dict[str, Any]:
    """Write *data* as a content-addressed artifact and return its reference.

    Artifacts are stored under ``artifact_root/sha256/<digest>`` so that the
    manifest only carries digests and sizes, never absolute paths.
    """
    digest = sha256_bytes(data)
    shard_dir = artifact_root / "sha256"
    shard_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = shard_dir / digest
    if not artifact_path.exists():
        artifact_path.write_bytes(data)
    return {"sha256": digest, "size": len(data)}


def collect(
    executable: pathlib.Path,
    argv: list[str],
    *,
    case_id: str,
    case_manifest_sha256: str,
    producer_profile: str,
    producer_revision: str,
    artifact_root: pathlib.Path,
    timeout_seconds: float,
    environment: dict[str, str] | None,
    logical_cwd: pathlib.Path,
) -> dict[str, Any]:
    """Run *executable* with *argv* and return a ``raw-execution-v1`` record."""
    if not executable.is_file():
        raise CollectorError(f"executable not found: {executable}")
    executable_sha = sha256_file(executable)

    env: dict[str, str] = dict(os.environ)
    if environment is not None:
        env = {**env, **environment}

    full_argv = [str(executable)] + argv
    start = time.perf_counter_ns()
    try:
        proc = subprocess.run(
            full_argv,
            capture_output=True,
            cwd=str(logical_cwd),
            env=env,
            timeout=timeout_seconds,
        )
        wall_ns = time.perf_counter_ns() - start
        stdout = proc.stdout[:MAX_STDOUT_BYTES]
        stderr = proc.stderr[:MAX_STDERR_BYTES]
        termination: dict[str, Any] = {
            "kind": "exit",
            "code": proc.returncode,
        }
    except subprocess.TimeoutExpired as exc:
        wall_ns = time.perf_counter_ns() - start
        stdout = (exc.stdout or b"")[:MAX_STDOUT_BYTES] if exc.stdout else b""
        stderr = (exc.stderr or b"")[:MAX_STDERR_BYTES] if exc.stderr else b""
        termination = {
            "kind": "timeout",
            "limit_ms": int(timeout_seconds * 1000),
        }

    stdout_ref = write_artifact(artifact_root, "stdout", stdout)
    stderr_ref = write_artifact(artifact_root, "stderr", stderr)

    return {
        "execution_schema": 1,
        "run_identity": {
            "case_id": case_id,
            "side": "rust",
            "platform": detect_platform(),
            "producer_profile": producer_profile,
            "producer_revision": producer_revision,
            "case_manifest_sha256": case_manifest_sha256,
            "executable_sha256": executable_sha,
        },
        "argv": full_argv,
        "environment": environment or {},
        "logical_cwd": str(logical_cwd),
        "termination": termination,
        "wall_time_ns": wall_ns,
        "resource_usage": {
            "cpu_time_ns": None,
            "peak_memory_bytes": None,
            "budget_counters": {},
        },
        "artifacts": {
            "stdout": stdout_ref,
            "stderr": stderr_ref,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect a raw execution record from the Rust diec binary.",
    )
    parser.add_argument(
        "--executable",
        type=pathlib.Path,
        required=True,
        help="Path to the diec binary.",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        required=True,
        help="Path to write the raw-execution-v1 JSON record.",
    )
    parser.add_argument(
        "--artifact-root",
        type=pathlib.Path,
        required=True,
        help="Root directory for content-addressed byte artifacts.",
    )
    parser.add_argument(
        "--case-id",
        required=True,
        help="Stable case identifier.",
    )
    parser.add_argument(
        "--case-manifest-sha256",
        required=True,
        help="SHA-256 of the case manifest.",
    )
    parser.add_argument(
        "--producer-profile",
        default="rust-cli",
        help="Producer profile name (default: rust-cli).",
    )
    parser.add_argument(
        "--producer-revision",
        default=None,
        help="40-hex git revision. Auto-detected if omitted.",
    )
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=None,
        help="Repository root for git revision auto-detection.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Timeout in seconds (default: 30).",
    )
    parser.add_argument(
        "--cwd",
        type=pathlib.Path,
        default=None,
        help="Logical working directory for the subprocess.",
    )
    parser.add_argument(
        "--env",
        nargs="*",
        default=None,
        help="Environment variables as KEY=VALUE pairs.",
    )
    parser.add_argument(
        "diec_args",
        nargs=argparse.REMAINDER,
        help="Arguments to pass to diec (after --).",
    )
    args = parser.parse_args(argv)

    environment: dict[str, str] | None = None
    if args.env is not None:
        environment = {}
        for pair in args.env:
            if "=" not in pair:
                raise CollectorError(f"env pair must be KEY=VALUE: {pair}")
            key, value = pair.split("=", 1)
            environment[key] = value

    producer_revision = args.producer_revision
    if producer_revision is None:
        repo = args.repo_root or pathlib.Path.cwd()
        producer_revision = git_revision(repo)

    logical_cwd = args.cwd or pathlib.Path.cwd()

    diec_args = args.diec_args
    if diec_args and diec_args[0] == "--":
        diec_args = diec_args[1:]

    record = collect(
        args.executable,
        diec_args,
        case_id=args.case_id,
        case_manifest_sha256=args.case_manifest_sha256,
        producer_profile=args.producer_profile,
        producer_revision=producer_revision,
        artifact_root=args.artifact_root,
        timeout_seconds=args.timeout,
        environment=environment,
        logical_cwd=logical_cwd,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"collected: {args.output}")
    print(f"  case_id: {record['run_identity']['case_id']}")
    print(f"  termination: {record['termination']}")
    print(f"  stdout: {record['artifacts']['stdout']['sha256'][:16]}... ({record['artifacts']['stdout']['size']} bytes)")
    print(f"  stderr: {record['artifacts']['stderr']['sha256'][:16]}... ({record['artifacts']['stderr']['size']} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

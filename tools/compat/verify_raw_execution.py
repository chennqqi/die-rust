#!/usr/bin/env python3
"""Verify a raw execution record and its content-addressed byte streams."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any


EXECUTION_SCHEMA_VERSION = 1
VERIFICATION_SCHEMA_VERSION = 1
VERIFIER_NAME = "die-raw-execution-verifier"
VERIFIER_VERSION = 1
DEFAULT_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
MAX_U64 = (1 << 64) - 1

HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
PLATFORM_PATTERN = re.compile(r"^[a-z0-9]+-[a-z0-9][a-z0-9_]*$")
PROFILE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
ENVIRONMENT_NAME_PATTERN = re.compile(r"^[^=\x00]+$")
ERROR_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
BUDGET_COUNTER_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")
ARTIFACT_ROLES = ("stdout", "stderr", "runtime_log")
REQUIRED_ARTIFACT_ROLES = {"stdout", "stderr"}


class VerificationError(ValueError):
    """The execution record or referenced bytes are not trustworthy."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    try:
        serialized = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise VerificationError(
            "execution values must be finite JSON values"
        ) from error
    return serialized.encode("utf-8")


def reject_constant(value: str) -> object:
    raise VerificationError(f"non-finite JSON constant is forbidden: {value}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_bytes(data: bytes, field: str) -> object:
    if len(data) > MAX_MANIFEST_BYTES:
        raise VerificationError(
            f"{field} exceeds {MAX_MANIFEST_BYTES} bytes"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"{field} must be UTF-8 JSON") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as error:
        raise VerificationError(
            f"{field} is invalid JSON at line {error.lineno}, "
            f"column {error.colno}"
        ) from error


def require_object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{field} must be an object")
    return value


def require_list(value: object, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{field} must be an array")
    return value


def require_string(
    value: object,
    field: str,
    *,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise VerificationError(f"{field} must be a string")
    if not allow_empty and not value:
        raise VerificationError(f"{field} must be a non-empty string")
    if "\x00" in value:
        raise VerificationError(f"{field} must not contain NUL")
    return value


def require_int_range(
    value: object,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise VerificationError(
            f"{field} must be an integer in {minimum}..{maximum}"
        )
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
        raise VerificationError(
            f"{field} is missing fields: {', '.join(missing)}"
        )
    if extra:
        raise VerificationError(
            f"{field} has unknown fields: {', '.join(extra)}"
        )


def validate_sha256(value: object, field: str) -> str:
    digest = require_string(value, field)
    if not HEX_64.fullmatch(digest):
        raise VerificationError(
            f"{field} must be a lowercase SHA-256"
        )
    return digest


def validate_identity(value: object) -> dict[str, object]:
    field = "execution.run_identity"
    identity = require_object(value, field)
    require_exact_keys(
        identity,
        {
            "case_id",
            "side",
            "platform",
            "producer_profile",
            "producer_revision",
            "case_manifest_sha256",
            "executable_sha256",
        },
        set(),
        field,
    )
    case_id = require_string(identity["case_id"], f"{field}.case_id")
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise VerificationError(
            f"{field}.case_id must be one exact case ID"
        )
    side = require_string(identity["side"], f"{field}.side")
    if side not in {"upstream", "rust"}:
        raise VerificationError(
            f"{field}.side must be upstream or rust"
        )
    platform = require_string(identity["platform"], f"{field}.platform")
    if not PLATFORM_PATTERN.fullmatch(platform):
        raise VerificationError(
            f"{field}.platform must name one exact OS-architecture pair"
        )
    profile = require_string(
        identity["producer_profile"],
        f"{field}.producer_profile",
    )
    if not PROFILE_PATTERN.fullmatch(profile):
        raise VerificationError(
            f"{field}.producer_profile must name one exact profile"
        )
    revision = require_string(
        identity["producer_revision"],
        f"{field}.producer_revision",
    )
    if not HEX_40.fullmatch(revision):
        raise VerificationError(
            f"{field}.producer_revision must be a lowercase 40-hex SHA"
        )
    return {
        "case_id": case_id,
        "side": side,
        "platform": platform,
        "producer_profile": profile,
        "producer_revision": revision,
        "case_manifest_sha256": validate_sha256(
            identity["case_manifest_sha256"],
            f"{field}.case_manifest_sha256",
        ),
        "executable_sha256": validate_sha256(
            identity["executable_sha256"],
            f"{field}.executable_sha256",
        ),
    }


def validate_termination(value: object) -> dict[str, object]:
    field = "execution.termination"
    termination = require_object(value, field)
    kind = require_string(termination.get("kind"), f"{field}.kind")
    if kind == "exit":
        require_exact_keys(termination, {"kind", "code"}, set(), field)
        return {
            "kind": kind,
            "code": require_int_range(
                termination["code"],
                f"{field}.code",
                -(1 << 31),
                (1 << 32) - 1,
            ),
        }
    if kind == "signal":
        require_exact_keys(termination, {"kind", "signal"}, set(), field)
        return {
            "kind": kind,
            "signal": require_int_range(
                termination["signal"],
                f"{field}.signal",
                1,
                (1 << 31) - 1,
            ),
        }
    if kind == "timeout":
        require_exact_keys(termination, {"kind", "limit_ms"}, set(), field)
        return {
            "kind": kind,
            "limit_ms": require_int_range(
                termination["limit_ms"],
                f"{field}.limit_ms",
                1,
                MAX_U64,
            ),
        }
    if kind == "spawn_error":
        require_exact_keys(
            termination,
            {"kind", "error_code"},
            set(),
            field,
        )
        error_code = require_string(
            termination["error_code"],
            f"{field}.error_code",
        )
        if not ERROR_CODE_PATTERN.fullmatch(error_code):
            raise VerificationError(
                f"{field}.error_code must be a stable uppercase code"
            )
        return {"kind": kind, "error_code": error_code}
    raise VerificationError(f"{field}.kind is unsupported")


def validate_artifact_reference(
    value: object,
    role: str,
) -> dict[str, object]:
    field = f"execution.artifacts.{role}"
    reference = require_object(value, field)
    require_exact_keys(reference, {"sha256", "size"}, set(), field)
    return {
        "sha256": validate_sha256(
            reference["sha256"],
            f"{field}.sha256",
        ),
        "size": require_int_range(
            reference["size"],
            f"{field}.size",
            0,
            MAX_U64,
        ),
    }


def validate_resource_usage(value: object) -> dict[str, object]:
    field = "execution.resource_usage"
    usage = require_object(value, field)
    require_exact_keys(
        usage,
        {"cpu_time_ns", "peak_memory_bytes", "budget_counters"},
        set(),
        field,
    )

    nullable_values: dict[str, int | None] = {}
    for name in ("cpu_time_ns", "peak_memory_bytes"):
        raw_value = usage[name]
        nullable_values[name] = (
            None
            if raw_value is None
            else require_int_range(
                raw_value,
                f"{field}.{name}",
                0,
                MAX_U64,
            )
        )

    raw_counters = require_object(
        usage["budget_counters"],
        f"{field}.budget_counters",
    )
    counters: dict[str, int] = {}
    for name, raw_value in raw_counters.items():
        if not BUDGET_COUNTER_PATTERN.fullmatch(name):
            raise VerificationError(
                f"{field}.budget_counters key is invalid: {name!r}"
            )
        counters[name] = require_int_range(
            raw_value,
            f"{field}.budget_counters.{name}",
            0,
            MAX_U64,
        )
    return {
        "cpu_time_ns": nullable_values["cpu_time_ns"],
        "peak_memory_bytes": nullable_values["peak_memory_bytes"],
        "budget_counters": counters,
    }


def validate_execution(value: object) -> dict[str, object]:
    execution = require_object(value, "execution")
    require_exact_keys(
        execution,
        {
            "execution_schema",
            "run_identity",
            "argv",
            "environment",
            "logical_cwd",
            "termination",
            "wall_time_ns",
            "resource_usage",
            "artifacts",
        },
        set(),
        "execution",
    )
    if (
        not isinstance(execution["execution_schema"], int)
        or isinstance(execution["execution_schema"], bool)
        or execution["execution_schema"] != EXECUTION_SCHEMA_VERSION
    ):
        raise VerificationError("unsupported execution_schema")

    argv_values = require_list(execution["argv"], "execution.argv")
    if not argv_values:
        raise VerificationError("execution.argv must not be empty")
    argv = [
        require_string(value, f"execution.argv[{index}]")
        for index, value in enumerate(argv_values)
    ]

    environment_value = require_object(
        execution["environment"],
        "execution.environment",
    )
    environment: dict[str, str] = {}
    for name, raw_value in environment_value.items():
        if not ENVIRONMENT_NAME_PATTERN.fullmatch(name):
            raise VerificationError(
                f"execution.environment key is invalid: {name!r}"
            )
        environment[name] = require_string(
            raw_value,
            f"execution.environment.{name}",
            allow_empty=True,
        )

    artifacts_value = require_object(
        execution["artifacts"],
        "execution.artifacts",
    )
    unknown_roles = sorted(set(artifacts_value) - set(ARTIFACT_ROLES))
    missing_roles = sorted(
        REQUIRED_ARTIFACT_ROLES - set(artifacts_value)
    )
    if missing_roles:
        raise VerificationError(
            "execution.artifacts is missing roles: "
            + ", ".join(missing_roles)
        )
    if unknown_roles:
        raise VerificationError(
            "execution.artifacts has unknown roles: "
            + ", ".join(unknown_roles)
        )
    artifacts = {
        role: validate_artifact_reference(artifacts_value[role], role)
        for role in ARTIFACT_ROLES
        if role in artifacts_value
    }

    normalized = {
        "execution_schema": EXECUTION_SCHEMA_VERSION,
        "run_identity": validate_identity(execution["run_identity"]),
        "argv": argv,
        "environment": environment,
        "logical_cwd": require_string(
            execution["logical_cwd"],
            "execution.logical_cwd",
        ),
        "termination": validate_termination(execution["termination"]),
        "wall_time_ns": require_int_range(
            execution["wall_time_ns"],
            "execution.wall_time_ns",
            0,
            MAX_U64,
        ),
        "resource_usage": validate_resource_usage(
            execution["resource_usage"]
        ),
        "artifacts": artifacts,
    }
    canonical_json(normalized)
    return normalized


def is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def read_stable_manifest(path: pathlib.Path) -> bytes:
    relative = str(path)
    before_path = path.lstat()
    if (
        not stat.S_ISREG(before_path.st_mode)
        or is_reparse_point(before_path)
    ):
        raise VerificationError(
            "execution manifest must be a regular non-reparse file"
        )
    if before_path.st_size > MAX_MANIFEST_BYTES:
        raise VerificationError(
            f"execution manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )

    chunks: list[bytes] = []
    bytes_read = 0
    open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        open_flags |= os.O_NOFOLLOW
    descriptor = os.open(path, open_flags)
    try:
        before_open = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_open.st_mode)
            or file_identity(before_open) != file_identity(before_path)
        ):
            raise VerificationError(
                "execution manifest changed before reading"
            )
        while True:
            chunk = os.read(descriptor, HASH_CHUNK_BYTES)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > MAX_MANIFEST_BYTES:
                raise VerificationError(
                    "execution manifest exceeded its read budget"
                )
            chunks.append(chunk)
        after_open = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    after_path = path.lstat()
    if (
        file_identity(before_open) != file_identity(after_open)
        or file_identity(after_open) != file_identity(after_path)
        or not stat.S_ISREG(after_path.st_mode)
        or is_reparse_point(after_path)
    ):
        raise VerificationError(
            "execution manifest changed while reading"
        )
    if bytes_read != before_path.st_size:
        raise VerificationError(
            f"execution manifest byte count changed: {relative}"
        )
    return b"".join(chunks)


def artifact_relative_path(digest: str) -> pathlib.PurePosixPath:
    return pathlib.PurePosixPath("sha256", digest)


def resolve_artifact_root(artifact_root: pathlib.Path) -> pathlib.Path:
    root_metadata = artifact_root.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or is_reparse_point(root_metadata)
    ):
        raise VerificationError(
            "artifact root must be a real directory, not a symlink"
        )
    return artifact_root.resolve(strict=True)


def resolve_artifact_path(
    artifact_root: pathlib.Path,
    digest: str,
) -> pathlib.Path:
    sha_directory = artifact_root / "sha256"
    try:
        sha_metadata = sha_directory.lstat()
    except FileNotFoundError as error:
        raise VerificationError(
            "artifact sha256 directory is missing"
        ) from error
    if (
        not stat.S_ISDIR(sha_metadata.st_mode)
        or is_reparse_point(sha_metadata)
    ):
        raise VerificationError(
            "artifact sha256 directory must be a real directory"
        )
    candidate = sha_directory / digest
    try:
        metadata = candidate.lstat()
    except FileNotFoundError as error:
        raise VerificationError(
            f"artifact is missing: sha256/{digest}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or is_reparse_point(metadata):
        raise VerificationError(
            f"artifact must not be a symlink/reparse point: sha256/{digest}"
        )
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(artifact_root)
    except (OSError, ValueError) as error:
        raise VerificationError(
            f"artifact escapes its root: sha256/{digest}"
        ) from error
    return resolved


def _verify_artifact_content(
    path: pathlib.Path,
    expected_digest: str,
    expected_size: int,
    max_artifact_bytes: int,
    capture: bool,
) -> bytes | None:
    relative = str(artifact_relative_path(expected_digest))
    before_path = path.lstat()
    if (
        not stat.S_ISREG(before_path.st_mode)
        or is_reparse_point(before_path)
    ):
        raise VerificationError(
            f"artifact must be a regular file: {relative}"
        )
    if before_path.st_size != expected_size:
        raise VerificationError(
            f"artifact size mismatch for {relative}: "
            f"expected {expected_size}, observed {before_path.st_size}"
        )
    if expected_size > max_artifact_bytes:
        raise VerificationError(
            f"artifact exceeds verification budget: {relative}"
        )

    digest = hashlib.sha256()
    chunks: list[bytes] = []
    bytes_read = 0
    open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        open_flags |= os.O_NOFOLLOW
    descriptor = os.open(path, open_flags)
    try:
        before_open = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_open.st_mode)
            or file_identity(before_open) != file_identity(before_path)
        ):
            raise VerificationError(
                f"artifact changed before hashing: {relative}"
            )
        while True:
            chunk = os.read(descriptor, HASH_CHUNK_BYTES)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > expected_size:
                raise VerificationError(
                    f"artifact grew while hashing: {relative}"
                )
            digest.update(chunk)
            if capture:
                chunks.append(chunk)
        after_open = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    after_path = path.lstat()
    if (
        file_identity(before_open) != file_identity(after_open)
        or file_identity(after_open) != file_identity(after_path)
        or not stat.S_ISREG(after_path.st_mode)
        or is_reparse_point(after_path)
    ):
        raise VerificationError(
            f"artifact changed while hashing: {relative}"
        )
    if bytes_read != expected_size:
        raise VerificationError(
            f"artifact byte count mismatch for {relative}"
        )
    observed_digest = digest.hexdigest()
    if observed_digest != expected_digest:
        raise VerificationError(
            f"artifact SHA-256 mismatch for {relative}"
        )
    return b"".join(chunks) if capture else None


def read_verified_artifact(
    path: pathlib.Path,
    expected_digest: str,
    expected_size: int,
    max_artifact_bytes: int,
) -> bytes:
    content = _verify_artifact_content(
        path,
        expected_digest,
        expected_size,
        max_artifact_bytes,
        True,
    )
    assert content is not None
    return content


def hash_artifact(
    path: pathlib.Path,
    expected_digest: str,
    expected_size: int,
    max_artifact_bytes: int,
) -> dict[str, object]:
    relative = str(artifact_relative_path(expected_digest))
    _verify_artifact_content(
        path,
        expected_digest,
        expected_size,
        max_artifact_bytes,
        False,
    )
    return {
        "relative_path": relative,
        "sha256": expected_digest,
        "size": expected_size,
    }


def validate_artifact_budget(
    artifacts: dict[str, dict[str, object]],
    max_artifact_bytes: int,
) -> int:
    if (
        not isinstance(max_artifact_bytes, int)
        or isinstance(max_artifact_bytes, bool)
        or max_artifact_bytes < 1
        or max_artifact_bytes > MAX_U64
    ):
        raise VerificationError(
            "max_artifact_bytes must be a positive u64 integer"
        )
    declared_total = sum(
        int(reference["size"])
        for reference in artifacts.values()
    )
    if declared_total > max_artifact_bytes:
        raise VerificationError(
            "declared artifact total exceeds verification budget"
        )
    return declared_total


def verify_execution(
    execution: dict[str, object],
    manifest_file_sha256: str,
    artifact_root: pathlib.Path,
    max_artifact_bytes: int,
) -> dict[str, object]:
    artifacts = execution["artifacts"]
    assert isinstance(artifacts, dict)
    declared_total = validate_artifact_budget(
        artifacts,
        max_artifact_bytes,
    )

    verified: dict[str, dict[str, object]] = {}
    for role in ARTIFACT_ROLES:
        if role not in artifacts:
            continue
        reference = artifacts[role]
        digest = str(reference["sha256"])
        path = resolve_artifact_path(artifact_root, digest)
        verified[role] = hash_artifact(
            path,
            digest,
            int(reference["size"]),
            max_artifact_bytes,
        )

    return {
        "verification_schema": VERIFICATION_SCHEMA_VERSION,
        "verifier": {
            "name": VERIFIER_NAME,
            "version": VERIFIER_VERSION,
        },
        "result": "pass",
        "run_identity": execution["run_identity"],
        "manifest_artifact": {
            "sha256": manifest_file_sha256,
            "canonical_execution_sha256": sha256_bytes(
                canonical_json(execution)
            ),
        },
        "verification_budget_bytes": max_artifact_bytes,
        "verified_total_bytes": declared_total,
        "artifacts": verified,
    }


def serialize_verification(verification: dict[str, object]) -> bytes:
    return (
        json.dumps(
            verification,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def verify_files(
    manifest_path: pathlib.Path,
    artifact_root: pathlib.Path,
    output_path: pathlib.Path,
    max_artifact_bytes: int,
) -> dict[str, object]:
    manifest_metadata = manifest_path.lstat()
    if (
        not stat.S_ISREG(manifest_metadata.st_mode)
        or is_reparse_point(manifest_metadata)
    ):
        raise VerificationError(
            "execution manifest must be a regular non-reparse file"
        )
    resolved_manifest = manifest_path.resolve(strict=True)
    resolved_root = resolve_artifact_root(artifact_root)
    resolved_output = output_path.resolve()
    if resolved_output == resolved_manifest:
        raise VerificationError("output must not overwrite the manifest")

    manifest_bytes = read_stable_manifest(manifest_path)
    execution = validate_execution(
        load_json_bytes(manifest_bytes, "execution manifest")
    )
    artifacts = execution["artifacts"]
    assert isinstance(artifacts, dict)
    validate_artifact_budget(artifacts, max_artifact_bytes)
    artifact_paths = {
        resolve_artifact_path(
            resolved_root,
            str(reference["sha256"]),
        )
        for reference in artifacts.values()
    }
    if resolved_output in artifact_paths:
        raise VerificationError("output must not overwrite an artifact")

    verification = verify_execution(
        execution,
        sha256_bytes(manifest_bytes),
        resolved_root,
        max_artifact_bytes,
    )
    if read_stable_manifest(manifest_path) != manifest_bytes:
        raise VerificationError(
            "execution manifest changed during verification"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(serialize_verification(verification))
    return verification


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify one raw execution manifest and content-addressed streams."
        )
    )
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--artifact-root", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--max-artifact-bytes",
        type=int,
        default=DEFAULT_MAX_ARTIFACT_BYTES,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        verify_files(
            args.manifest,
            args.artifact_root,
            args.output,
            args.max_artifact_bytes,
        )
    except (VerificationError, OSError) as error:
        print(f"verification error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

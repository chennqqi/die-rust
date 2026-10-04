#!/usr/bin/env python3
"""Project verified stdout into lossless raw/JSON byte segments."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

import verify_raw_execution as raw_verifier


FRAMING_SCHEMA_VERSION = 1
PROJECTOR_NAME = "die-raw-framing-projector"
PROJECTOR_VERSION = 1
MAX_JSON_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_JSON_DOCUMENTS = 4096
MAX_JSON_NESTING = 256
LIMIT_REASON_ORDER = (
    "document_bytes",
    "document_count",
    "nesting",
)


class FramingError(ValueError):
    """Verified bytes cannot be projected without violating the contract."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json_document(data: bytes) -> object:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FramingError("JSON candidate is not UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=raw_verifier.unique_object,
            parse_constant=raw_verifier.reject_constant,
        )
    except (
        json.JSONDecodeError,
        raw_verifier.VerificationError,
        RecursionError,
    ) as error:
        raise FramingError("JSON candidate is not strict JSON") from error
    if not isinstance(value, (dict, list)):
        raise FramingError("JSON candidate root is not object or array")
    try:
        raw_verifier.canonical_json(value)
    except (
        raw_verifier.VerificationError,
        RecursionError,
        UnicodeEncodeError,
    ) as error:
        raise FramingError(
            "JSON candidate cannot be represented canonically"
        ) from error
    return value


def scan_balanced_document(
    data: bytes,
    start: int,
) -> tuple[int | None, int, str | None]:
    opening = data[start]
    if opening not in (ord("{"), ord("[")):
        raise FramingError("candidate must start with object or array")
    stack = [ord("}") if opening == ord("{") else ord("]")]
    in_string = False
    escaped = False
    position = start + 1
    while position < len(data):
        byte = data[position]
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            position += 1
            continue
        if byte == ord('"'):
            in_string = True
        elif byte == ord("{"):
            stack.append(ord("}"))
            if len(stack) > MAX_JSON_NESTING:
                return None, len(data), "nesting"
        elif byte == ord("["):
            stack.append(ord("]"))
            if len(stack) > MAX_JSON_NESTING:
                return None, len(data), "nesting"
        elif byte in (ord("}"), ord("]")):
            if not stack or stack[-1] != byte:
                return None, position + 1, None
            stack.pop()
            if not stack:
                end = position + 1
                return end, end, None
        position += 1
    return None, len(data), None


def next_candidate(data: bytes, position: int) -> int | None:
    while position < len(data):
        object_offset = data.find(b"{", position)
        array_offset = data.find(b"[", position)
        offsets = [
            offset
            for offset in (object_offset, array_offset)
            if offset >= 0
        ]
        if not offsets:
            return None
        candidate = min(offsets)
        if candidate == 0 or data[candidate - 1] == ord("\n"):
            return candidate
        position = candidate + 1
    return None


def raw_segment(index: int, offset: int, content: bytes) -> dict[str, object]:
    return {
        "index": index,
        "kind": "raw",
        "offset": offset,
        "size": len(content),
        "sha256": sha256_bytes(content),
    }


def json_segment(
    index: int,
    offset: int,
    content: bytes,
    value: object,
) -> dict[str, object]:
    return {
        "index": index,
        "kind": "json_document",
        "offset": offset,
        "size": len(content),
        "sha256": sha256_bytes(content),
        "root_kind": "object" if isinstance(value, dict) else "array",
        "canonical_json_sha256": sha256_bytes(
            raw_verifier.canonical_json(value)
        ),
        "value": value,
    }


def project_segments_with_limits(
    data: bytes,
) -> tuple[list[dict[str, object]], list[str]]:
    segments: list[dict[str, object]] = []
    limit_reasons: set[str] = set()
    document_count = 0
    consumed = 0
    search_position = 0
    while True:
        start = next_candidate(data, search_position)
        if start is None:
            break
        end, resume, scan_limit = scan_balanced_document(data, start)
        if scan_limit is not None:
            limit_reasons.add(scan_limit)
            break
        if end is None:
            search_position = resume
            continue
        candidate = data[start:end]
        if len(candidate) > MAX_JSON_DOCUMENT_BYTES:
            limit_reasons.add("document_bytes")
            search_position = end
            continue
        if document_count >= MAX_JSON_DOCUMENTS:
            limit_reasons.add("document_count")
            break
        try:
            value = strict_json_document(candidate)
        except FramingError:
            search_position = end
            continue
        if start > consumed:
            segments.append(
                raw_segment(
                    len(segments),
                    consumed,
                    data[consumed:start],
                )
            )
        segments.append(
            json_segment(
                len(segments),
                start,
                candidate,
                value,
            )
        )
        document_count += 1
        consumed = end
        search_position = end
    if consumed < len(data):
        segments.append(
            raw_segment(
                len(segments),
                consumed,
                data[consumed:],
            )
        )
    validate_coverage(segments, len(data))
    ordered_reasons = [
        reason
        for reason in LIMIT_REASON_ORDER
        if reason in limit_reasons
    ]
    return segments, ordered_reasons


def project_segments(data: bytes) -> list[dict[str, object]]:
    segments, _ = project_segments_with_limits(data)
    return segments


def validate_coverage(
    segments: list[dict[str, object]],
    expected_size: int,
) -> None:
    next_offset = 0
    for index, segment in enumerate(segments):
        if segment["index"] != index:
            raise FramingError("segment indexes are not contiguous")
        if segment["offset"] != next_offset:
            raise FramingError("segment byte ranges are not contiguous")
        size = segment["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise FramingError("segments must have positive byte lengths")
        next_offset += size
    if next_offset != expected_size:
        raise FramingError("segments do not cover the complete stream")


def build_projection(
    execution: dict[str, object],
    verification: dict[str, object],
    stdout: bytes,
) -> dict[str, object]:
    artifacts = execution["artifacts"]
    assert isinstance(artifacts, dict)
    stdout_reference = artifacts["stdout"]
    segments, limit_reasons = project_segments_with_limits(stdout)
    document_count = sum(
        segment["kind"] == "json_document"
        for segment in segments
    )
    raw_count = len(segments) - document_count
    verification_bytes = raw_verifier.serialize_verification(verification)
    return {
        "framing_schema": FRAMING_SCHEMA_VERSION,
        "projector": {
            "name": PROJECTOR_NAME,
            "version": PROJECTOR_VERSION,
        },
        "result": (
            "projection_limit_reached"
            if limit_reasons
            else (
                "documents_found"
                if document_count
                else "no_json_document"
            )
        ),
        "run_identity": execution["run_identity"],
        "execution_verification": verification,
        "execution_verification_sha256": sha256_bytes(
            verification_bytes
        ),
        "stream": {
            "role": "stdout",
            "relative_path": str(
                raw_verifier.artifact_relative_path(
                    str(stdout_reference["sha256"])
                )
            ),
            "sha256": stdout_reference["sha256"],
            "size": stdout_reference["size"],
        },
        "coverage": {
            "bytes": len(stdout),
            "segment_count": len(segments),
            "raw_segment_count": raw_count,
            "json_document_count": document_count,
        },
        "limits": {
            "max_json_document_bytes": MAX_JSON_DOCUMENT_BYTES,
            "max_json_documents": MAX_JSON_DOCUMENTS,
            "max_json_nesting": MAX_JSON_NESTING,
            "limit_reached": bool(limit_reasons),
            "reasons": limit_reasons,
        },
        "segments_sha256": sha256_bytes(
            raw_verifier.canonical_json(segments)
        ),
        "segments": segments,
    }


def serialize_projection(projection: dict[str, object]) -> bytes:
    return (
        json.dumps(
            projection,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def project_files(
    manifest_path: pathlib.Path,
    artifact_root: pathlib.Path,
    output_path: pathlib.Path,
    max_artifact_bytes: int,
) -> dict[str, object]:
    resolved_manifest = manifest_path.resolve(strict=True)
    resolved_root = raw_verifier.resolve_artifact_root(artifact_root)
    resolved_output = output_path.resolve()
    if resolved_output == resolved_manifest:
        raise FramingError("output must not overwrite the manifest")

    manifest_bytes = raw_verifier.read_stable_manifest(manifest_path)
    execution = raw_verifier.validate_execution(
        raw_verifier.load_json_bytes(
            manifest_bytes,
            "execution manifest",
        )
    )
    artifacts = execution["artifacts"]
    assert isinstance(artifacts, dict)
    raw_verifier.validate_artifact_budget(
        artifacts,
        max_artifact_bytes,
    )
    artifact_paths = {
        raw_verifier.resolve_artifact_path(
            resolved_root,
            str(reference["sha256"]),
        )
        for reference in artifacts.values()
    }
    if resolved_output in artifact_paths:
        raise FramingError("output must not overwrite an artifact")

    verification = raw_verifier.verify_execution(
        execution,
        raw_verifier.sha256_bytes(manifest_bytes),
        resolved_root,
        max_artifact_bytes,
    )
    stdout_reference = artifacts["stdout"]
    stdout_path = raw_verifier.resolve_artifact_path(
        resolved_root,
        str(stdout_reference["sha256"]),
    )
    stdout = raw_verifier.read_verified_artifact(
        stdout_path,
        str(stdout_reference["sha256"]),
        int(stdout_reference["size"]),
        max_artifact_bytes,
    )
    projection = build_projection(execution, verification, stdout)
    if raw_verifier.read_stable_manifest(manifest_path) != manifest_bytes:
        raise FramingError(
            "execution manifest changed during framing projection"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(serialize_projection(projection))
    return projection


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Project verified stdout into lossless raw/JSON byte segments."
        )
    )
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--artifact-root", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--max-artifact-bytes",
        type=int,
        default=raw_verifier.DEFAULT_MAX_ARTIFACT_BYTES,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        project_files(
            args.manifest,
            args.artifact_root,
            args.output,
            args.max_artifact_bytes,
        )
    except (
        FramingError,
        raw_verifier.VerificationError,
        OSError,
    ) as error:
        print(f"framing error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

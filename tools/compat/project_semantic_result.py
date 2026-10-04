#!/usr/bin/env python3
"""Project verified DIE CLI output into a strict semantic result model."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import math
import pathlib
import re
import sys
from typing import Any

import project_raw_framing as framing
import verify_raw_execution as raw_verifier


SEMANTIC_MODEL_SCHEMA_VERSION = 1
SEMANTIC_PROJECTION_SCHEMA_VERSION = 1
SEMANTIC_CONTRACT_SCHEMA_VERSION = 1
PROJECTOR_NAME = "die-semantic-result-projector"
PROJECTOR_VERSION = 1

OUTPUT_KINDS = (
    "normal_scan_json",
    "entropy_json",
    "info_json",
    "struct_json",
    "raw",
)
MAX_EXPECTED_DOCUMENTS = framing.MAX_JSON_DOCUMENTS
HEX_40 = re.compile(r"^[0-9a-f]{40}$")


class SemanticProjectionError(ValueError):
    """Input evidence or projection contract violates the strict contract."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_exact_keys(
    value: dict[str, Any],
    required: set[str],
    optional: set[str],
    field: str,
) -> None:
    raw_verifier.require_exact_keys(value, required, optional, field)


def require_string(
    value: object,
    field: str,
    *,
    allow_empty: bool = False,
) -> str:
    return raw_verifier.require_string(
        value,
        field,
        allow_empty=allow_empty,
    )


def require_semantic_string(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise SemanticProjectionError(f"{field} must be a string")
    return value


def validate_contract(value: object) -> dict[str, object]:
    field = "semantic projection contract"
    contract = raw_verifier.require_object(value, field)
    require_exact_keys(
        contract,
        {
            "contract_schema",
            "case_id",
            "platform",
            "oracle_profile",
            "upstream_commit",
            "case_manifest_sha256",
            "semantic_schema",
            "output",
        },
        set(),
        field,
    )
    if (
        not isinstance(contract["contract_schema"], int)
        or isinstance(contract["contract_schema"], bool)
        or contract["contract_schema"]
        != SEMANTIC_CONTRACT_SCHEMA_VERSION
    ):
        raise SemanticProjectionError("unsupported contract_schema")

    case_id = require_string(contract["case_id"], f"{field}.case_id")
    if not raw_verifier.CASE_ID_PATTERN.fullmatch(case_id):
        raise SemanticProjectionError(
            f"{field}.case_id must be one exact case ID"
        )
    platform = require_string(contract["platform"], f"{field}.platform")
    if not raw_verifier.PLATFORM_PATTERN.fullmatch(platform):
        raise SemanticProjectionError(
            f"{field}.platform must name one OS-architecture pair"
        )
    oracle_profile = require_string(
        contract["oracle_profile"],
        f"{field}.oracle_profile",
    )
    if not raw_verifier.PROFILE_PATTERN.fullmatch(oracle_profile):
        raise SemanticProjectionError(
            f"{field}.oracle_profile is invalid"
        )
    upstream_commit = require_string(
        contract["upstream_commit"],
        f"{field}.upstream_commit",
    )
    if not HEX_40.fullmatch(upstream_commit):
        raise SemanticProjectionError(
            f"{field}.upstream_commit must be lowercase 40-hex"
        )
    case_manifest_sha256 = raw_verifier.validate_sha256(
        contract["case_manifest_sha256"],
        f"{field}.case_manifest_sha256",
    )
    semantic_schema = raw_verifier.require_int_range(
        contract["semantic_schema"],
        f"{field}.semantic_schema",
        1,
        (1 << 31) - 1,
    )
    if semantic_schema != SEMANTIC_MODEL_SCHEMA_VERSION:
        raise SemanticProjectionError("unsupported semantic_schema")

    output_field = f"{field}.output"
    output = raw_verifier.require_object(
        contract["output"],
        output_field,
    )
    require_exact_keys(
        output,
        {"kind", "expected_json_documents"},
        set(),
        output_field,
    )
    kind = require_string(output["kind"], f"{output_field}.kind")
    if kind not in OUTPUT_KINDS:
        raise SemanticProjectionError(
            f"{output_field}.kind is unsupported"
        )
    expected_documents = raw_verifier.require_int_range(
        output["expected_json_documents"],
        f"{output_field}.expected_json_documents",
        0,
        MAX_EXPECTED_DOCUMENTS,
    )
    if kind == "raw" and expected_documents != 0:
        raise SemanticProjectionError(
            "raw output must expect zero JSON documents"
        )

    normalized = {
        "contract_schema": SEMANTIC_CONTRACT_SCHEMA_VERSION,
        "case_id": case_id,
        "platform": platform,
        "oracle_profile": oracle_profile,
        "upstream_commit": upstream_commit,
        "case_manifest_sha256": case_manifest_sha256,
        "semantic_schema": semantic_schema,
        "output": {
            "kind": kind,
            "expected_json_documents": expected_documents,
        },
    }
    raw_verifier.canonical_json(normalized)
    return normalized


def validate_contract_identity(
    contract: dict[str, object],
    execution: dict[str, object],
) -> None:
    identity = execution["run_identity"]
    assert isinstance(identity, dict)
    matches = (
        ("case_id", "case_id"),
        ("platform", "platform"),
        ("case_manifest_sha256", "case_manifest_sha256"),
    )
    for contract_name, identity_name in matches:
        if contract[contract_name] != identity[identity_name]:
            raise SemanticProjectionError(
                f"contract {contract_name} does not match execution identity"
            )
    if (
        identity["side"] == "upstream"
        and identity["producer_revision"] != contract["upstream_commit"]
    ):
        raise SemanticProjectionError(
            "upstream producer revision does not match compatibility target"
        )


def encode_bytes(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {
            "encoding": "base64",
            "base64": base64.b64encode(data).decode("ascii"),
        }
    return {"encoding": "utf8", "text": text}


def project_raw_records(
    data: bytes,
    base_offset: int = 0,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    start = 0
    while start < len(data):
        newline = data.find(b"\n", start)
        if newline == -1:
            body_end = len(data)
            record_end = len(data)
            line_ending = "none"
        else:
            record_end = newline + 1
            if newline > start and data[newline - 1] == ord("\r"):
                body_end = newline - 1
                line_ending = "crlf"
            else:
                body_end = newline
                line_ending = "lf"
        record_bytes = data[start:record_end]
        records.append(
            {
                "source": {
                    "offset": base_offset + start,
                    "size": len(record_bytes),
                    "sha256": sha256_bytes(record_bytes),
                },
                "body": encode_bytes(data[start:body_end]),
                "line_ending": line_ending,
            }
        )
        start = record_end
    return records


def comparison_records(
    records: list[dict[str, object]],
) -> list[dict[str, object]]:
    return [
        {
            "body": copy.deepcopy(record["body"]),
            "line_ending": record["line_ending"],
        }
        for record in records
    ]


def record_sources(
    records: list[dict[str, object]],
) -> list[dict[str, object]]:
    return [copy.deepcopy(record["source"]) for record in records]


def require_object_exact(
    value: object,
    required: set[str],
    field: str,
) -> dict[str, Any]:
    result = raw_verifier.require_object(value, field)
    require_exact_keys(result, required, set(), field)
    return result


def require_nonnegative_decimal(value: object, field: str) -> int:
    text = require_string(value, field, allow_empty=True)
    if not text or not text.isascii() or not text.isdecimal():
        raise SemanticProjectionError(
            f"{field} must be a non-negative decimal string"
        )
    number = int(text, 10)
    if number > raw_verifier.MAX_U64:
        raise SemanticProjectionError(f"{field} exceeds u64")
    return number


def require_finite_number(value: object, field: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SemanticProjectionError(f"{field} must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise SemanticProjectionError(f"{field} must be finite")
    return value


def project_detection_leaf(
    value: object,
    field: str,
) -> dict[str, object]:
    leaf = require_object_exact(
        value,
        {"info", "name", "string", "type", "version"},
        field,
    )
    detection_type = require_semantic_string(
        leaf["type"],
        f"{field}.type",
    )
    name = require_semantic_string(leaf["name"], f"{field}.name")
    display = require_semantic_string(
        leaf["string"],
        f"{field}.string",
    )
    version = require_semantic_string(
        leaf["version"],
        f"{field}.version",
    )
    info = require_semantic_string(
        leaf["info"],
        f"{field}.info",
    )
    return {
        "kind": "detection",
        "type": detection_type,
        "name": name,
        "version": version,
        "info": info,
        "display": display,
        "heuristic": (
            detection_type.startswith("~")
            or display.startswith("(Heur)")
        ),
        "unknown": (
            detection_type == "Unknown"
            or (
                not detection_type
                and not name
                and not version
                and not info
                and bool(display)
            )
        ),
        "rule_identity": None,
        "priority": None,
    }


def project_scan_node(
    value: object,
    field: str,
    depth: int,
) -> dict[str, object]:
    if depth > framing.MAX_JSON_NESTING:
        raise SemanticProjectionError(
            f"{field} exceeds semantic nesting limit"
        )
    node = require_object_exact(
        value,
        {
            "filetype",
            "info",
            "offset",
            "parentfilepart",
            "size",
            "values",
        },
        field,
    )
    values = raw_verifier.require_list(node["values"], f"{field}.values")
    projected_values: list[dict[str, object]] = []
    for index, child in enumerate(values):
        child_field = f"{field}.values[{index}]"
        if isinstance(child, dict) and "filetype" in child:
            projected_values.append(
                project_scan_node(child, child_field, depth + 1)
            )
        else:
            projected_values.append(
                project_detection_leaf(child, child_field)
            )
    return {
        "kind": "scan_node",
        "file_type": require_semantic_string(
            node["filetype"],
            f"{field}.filetype",
        ),
        "info": require_semantic_string(
            node["info"],
            f"{field}.info",
        ),
        "offset": require_nonnegative_decimal(
            node["offset"],
            f"{field}.offset",
        ),
        "offset_text": node["offset"],
        "size": require_nonnegative_decimal(
            node["size"],
            f"{field}.size",
        ),
        "size_text": node["size"],
        "parent_file_part": require_semantic_string(
            node["parentfilepart"],
            f"{field}.parentfilepart",
        ),
        "values": projected_values,
    }


def project_normal_scan(value: object) -> dict[str, object]:
    root = require_object_exact(value, {"detects"}, "document")
    detects = raw_verifier.require_list(
        root["detects"],
        "document.detects",
    )
    items: list[dict[str, object]] = []
    format_candidates: list[str] = []
    for index, item in enumerate(detects):
        field = f"document.detects[{index}]"
        if isinstance(item, dict) and "filetype" in item:
            projected = project_scan_node(item, field, 1)
            format_candidates.append(str(projected["file_type"]))
        else:
            projected = project_detection_leaf(item, field)
            format_candidates.append(str(projected["display"]))
        items.append(projected)
    return {
        "kind": "normal_scan",
        "format_candidates": format_candidates,
        "items": items,
    }


def project_entropy(value: object) -> dict[str, object]:
    root = require_object_exact(
        value,
        {"total", "status", "records"},
        "document",
    )
    records = raw_verifier.require_list(
        root["records"],
        "document.records",
    )
    projected_records = []
    for index, raw_record in enumerate(records):
        field = f"document.records[{index}]"
        record = require_object_exact(
            raw_record,
            {"name", "offset", "size", "entropy", "status"},
            field,
        )
        projected_records.append(
            {
                "name": require_semantic_string(
                    record["name"],
                    f"{field}.name",
                ),
                "offset": raw_verifier.require_int_range(
                    record["offset"],
                    f"{field}.offset",
                    0,
                    raw_verifier.MAX_U64,
                ),
                "size": raw_verifier.require_int_range(
                    record["size"],
                    f"{field}.size",
                    0,
                    raw_verifier.MAX_U64,
                ),
                "entropy": require_finite_number(
                    record["entropy"],
                    f"{field}.entropy",
                ),
                "status": require_semantic_string(
                    record["status"],
                    f"{field}.status",
                ),
            }
        )
    return {
        "kind": "entropy",
        "total": require_finite_number(
            root["total"],
            "document.total",
        ),
        "status": require_semantic_string(
            root["status"],
            "document.status",
        ),
        "records": projected_records,
    }


def project_info_value(
    value: object,
    field: str,
    depth: int,
) -> dict[str, object]:
    if depth > framing.MAX_JSON_NESTING:
        raise SemanticProjectionError(
            f"{field} exceeds semantic nesting limit"
        )
    if isinstance(value, str):
        return {"kind": "string", "value": value}
    if not isinstance(value, dict):
        raise SemanticProjectionError(
            f"{field} must be a string or object"
        )
    entries = []
    for name, child in value.items():
        require_semantic_string(name, f"{field} key")
        entries.append(
            {
                "name": name,
                "value": project_info_value(
                    child,
                    f"{field}.{name}",
                    depth + 1,
                ),
            }
        )
    return {"kind": "object", "entries": entries}


def project_info(value: object, kind: str) -> dict[str, object]:
    root = require_object_exact(value, {"data"}, "document")
    return {
        "kind": kind,
        "data": project_info_value(root["data"], "document.data", 1),
    }


def project_document(value: object, output_kind: str) -> dict[str, object]:
    if output_kind == "normal_scan_json":
        if (
            isinstance(value, dict)
            and set(value) == {"error"}
            and isinstance(value["error"], str)
        ):
            return {
                "kind": "cli_error",
                "message": require_semantic_string(
                    value["error"],
                    "document.error",
                ),
            }
        return project_normal_scan(value)
    if output_kind == "entropy_json":
        return project_entropy(value)
    if output_kind == "info_json":
        return project_info(value, "info")
    if output_kind == "struct_json":
        return project_info(value, "struct")
    raise SemanticProjectionError(
        "JSON document is not permitted for raw output"
    )


def source_segment(segment: dict[str, object]) -> dict[str, object]:
    result = {
        "index": segment["index"],
        "offset": segment["offset"],
        "size": segment["size"],
        "sha256": segment["sha256"],
    }
    if segment["kind"] == "json_document":
        result["canonical_json_sha256"] = segment[
            "canonical_json_sha256"
        ]
    return result


def build_semantic_segments(
    stdout: bytes,
    framing_projection: dict[str, object],
    output_kind: str,
) -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    segments = framing_projection["segments"]
    assert isinstance(segments, list)
    projected: list[dict[str, object]] = []
    source_maps: list[dict[str, object]] = []
    issues: list[dict[str, object]] = []
    for segment in segments:
        assert isinstance(segment, dict)
        source = source_segment(segment)
        if segment["kind"] == "raw":
            offset = int(segment["offset"])
            size = int(segment["size"])
            records = project_raw_records(
                stdout[offset : offset + size],
                offset,
            )
            projected.append(
                {
                    "kind": "raw",
                    "records": comparison_records(records),
                }
            )
            source_maps.append(
                {
                    "kind": "raw",
                    "source": source,
                    "records": record_sources(records),
                }
            )
            continue
        try:
            document = project_document(segment["value"], output_kind)
        except (
            SemanticProjectionError,
            raw_verifier.VerificationError,
        ) as error:
            reason = str(error)
            document = {
                "kind": "unclassified",
                "reason": reason,
                "value": copy.deepcopy(segment["value"]),
            }
            issues.append(
                {
                    "code": (
                        "unexpected_json_document"
                        if output_kind == "raw"
                        else "document_schema_mismatch"
                    ),
                    "segment_index": segment["index"],
                    "message": reason,
                }
            )
        projected.append(
            {
                "kind": "document",
                "document": document,
            }
        )
        source_maps.append(
            {
                "kind": "document",
                "source": source,
            }
        )
    return projected, source_maps, issues


def build_projection(
    contract: dict[str, object],
    contract_bytes: bytes,
    execution: dict[str, object],
    verification: dict[str, object],
    framing_projection: dict[str, object],
    artifacts: dict[str, bytes],
) -> dict[str, object]:
    output = contract["output"]
    assert isinstance(output, dict)
    stdout = artifacts["stdout"]
    semantic_segments, stdout_source_maps, issues = build_semantic_segments(
        stdout,
        framing_projection,
        str(output["kind"]),
    )

    coverage = framing_projection["coverage"]
    limits = framing_projection["limits"]
    assert isinstance(coverage, dict)
    assert isinstance(limits, dict)
    actual_documents = int(coverage["json_document_count"])
    expected_documents = int(output["expected_json_documents"])
    if actual_documents != expected_documents:
        issues.append(
            {
                "code": "document_count_mismatch",
                "segment_index": None,
                "message": (
                    f"expected {expected_documents} JSON document(s), "
                    f"observed {actual_documents}"
                ),
            }
        )
    if bool(limits["limit_reached"]):
        issues.append(
            {
                "code": "framing_limit_reached",
                "segment_index": None,
                "message": (
                    "raw framing limit reached: "
                    + ", ".join(str(item) for item in limits["reasons"])
                ),
            }
        )

    identity = execution["run_identity"]
    artifact_references = execution["artifacts"]
    assert isinstance(identity, dict)
    assert isinstance(artifact_references, dict)
    stderr_records = project_raw_records(artifacts["stderr"])
    streams: dict[str, object] = {
        "stdout": {
            "segments": semantic_segments,
        },
        "stderr": {
            "records": comparison_records(stderr_records),
        },
    }
    raw_streams: dict[str, object] = {
        "stdout": {
            "sha256": artifact_references["stdout"]["sha256"],
            "size": artifact_references["stdout"]["size"],
            "segments": stdout_source_maps,
        },
        "stderr": {
            "sha256": artifact_references["stderr"]["sha256"],
            "size": artifact_references["stderr"]["size"],
            "records": record_sources(stderr_records),
        },
    }
    if "runtime_log" in artifacts:
        runtime_records = project_raw_records(artifacts["runtime_log"])
        streams["runtime_log"] = {
            "records": comparison_records(runtime_records),
        }
        raw_streams["runtime_log"] = {
            "sha256": artifact_references["runtime_log"]["sha256"],
            "size": artifact_references["runtime_log"]["size"],
            "records": record_sources(runtime_records),
        }

    semantic = {
        "model_schema": SEMANTIC_MODEL_SCHEMA_VERSION,
        "result": "pass" if not issues else "projection_failure",
        "issues": issues,
        "producer": {
            "side": identity["side"],
            "profile": identity["producer_profile"],
            "revision": identity["producer_revision"],
            "executable_sha256": identity["executable_sha256"],
        },
        "evidence": {
            "contract_artifact_sha256": sha256_bytes(contract_bytes),
            "canonical_contract_sha256": sha256_bytes(
                raw_verifier.canonical_json(contract)
            ),
            "execution_verification_sha256": sha256_bytes(
                raw_verifier.serialize_verification(verification)
            ),
            "canonical_framing_projection_sha256": sha256_bytes(
                raw_verifier.canonical_json(framing_projection)
            ),
            "framing_segments_sha256": framing_projection[
                "segments_sha256"
            ],
            "raw_streams": raw_streams,
        },
        "comparison": {
            "output": copy.deepcopy(output),
            "termination": copy.deepcopy(execution["termination"]),
            "streams": streams,
        },
    }
    raw_verifier.canonical_json(semantic)
    return {
        "projection_schema": SEMANTIC_PROJECTION_SCHEMA_VERSION,
        "run_identity": {
            "platform": contract["platform"],
            "oracle_profile": contract["oracle_profile"],
            "upstream_commit": contract["upstream_commit"],
            "semantic_schema": contract["semantic_schema"],
        },
        "case_id": contract["case_id"],
        "semantic": semantic,
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


def read_contract(path: pathlib.Path) -> tuple[bytes, dict[str, object]]:
    try:
        data = raw_verifier.read_stable_manifest(path)
        value = raw_verifier.load_json_bytes(
            data,
            "semantic projection contract",
        )
    except raw_verifier.VerificationError as error:
        raise SemanticProjectionError(str(error)) from error
    return data, validate_contract(value)


def project_files(
    contract_path: pathlib.Path,
    manifest_path: pathlib.Path,
    artifact_root: pathlib.Path,
    output_path: pathlib.Path,
    max_artifact_bytes: int,
) -> dict[str, object]:
    resolved_contract = contract_path.resolve(strict=True)
    resolved_manifest = manifest_path.resolve(strict=True)
    resolved_output = output_path.resolve()
    if resolved_output in {resolved_contract, resolved_manifest}:
        raise SemanticProjectionError(
            "output must not overwrite an input file"
        )

    contract_bytes, contract = read_contract(contract_path)
    manifest_bytes = raw_verifier.read_stable_manifest(manifest_path)
    execution = raw_verifier.validate_execution(
        raw_verifier.load_json_bytes(
            manifest_bytes,
            "execution manifest",
        )
    )
    validate_contract_identity(contract, execution)
    resolved_root = raw_verifier.resolve_artifact_root(artifact_root)
    artifact_references = execution["artifacts"]
    assert isinstance(artifact_references, dict)
    raw_verifier.validate_artifact_budget(
        artifact_references,
        max_artifact_bytes,
    )
    artifact_paths = {
        role: raw_verifier.resolve_artifact_path(
            resolved_root,
            str(reference["sha256"]),
        )
        for role, reference in artifact_references.items()
    }
    if resolved_output in set(artifact_paths.values()):
        raise SemanticProjectionError(
            "output must not overwrite an artifact"
        )

    verification = raw_verifier.verify_execution(
        execution,
        sha256_bytes(manifest_bytes),
        resolved_root,
        max_artifact_bytes,
    )
    artifacts = {
        role: raw_verifier.read_verified_artifact(
            artifact_paths[role],
            str(reference["sha256"]),
            int(reference["size"]),
            max_artifact_bytes,
        )
        for role, reference in artifact_references.items()
    }
    framing_projection = framing.build_projection(
        execution,
        verification,
        artifacts["stdout"],
    )
    projection = build_projection(
        contract,
        contract_bytes,
        execution,
        verification,
        framing_projection,
        artifacts,
    )

    if raw_verifier.read_stable_manifest(manifest_path) != manifest_bytes:
        raise SemanticProjectionError(
            "execution manifest changed during projection"
        )
    latest_contract_bytes, _ = read_contract(contract_path)
    if latest_contract_bytes != contract_bytes:
        raise SemanticProjectionError(
            "semantic projection contract changed during projection"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(serialize_projection(projection))
    return projection


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Project verified DIE CLI output into semantic result v1."
        )
    )
    parser.add_argument("--contract", required=True, type=pathlib.Path)
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
        projection = project_files(
            args.contract,
            args.manifest,
            args.artifact_root,
            args.output,
            args.max_artifact_bytes,
        )
    except (
        SemanticProjectionError,
        raw_verifier.VerificationError,
        framing.FramingError,
        OSError,
    ) as error:
        print(f"semantic projection error: {error}", file=sys.stderr)
        return 2
    semantic = projection["semantic"]
    assert isinstance(semantic, dict)
    return 0 if semantic["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

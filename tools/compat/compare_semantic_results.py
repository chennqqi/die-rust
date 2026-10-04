#!/usr/bin/env python3
"""Compare two verified DIE semantic projections with exact provenance."""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys
from typing import Any

import normalize_semantic_projection as normalizer
import project_raw_framing as framing
import project_semantic_result as projector
import validate_difference_waivers as waiver_validator
import verify_raw_execution as raw_verifier


COMPARISON_CONTRACT_SCHEMA_VERSION = 1
COMPARISON_SCHEMA_VERSION = 1
COMPARATOR_NAME = "die-semantic-comparator"
COMPARATOR_VERSION = 1
DIFFERENCE_REPORT_SCHEMA_VERSION = 1
BLOCKED_DIFFERENCE_SCHEMA_VERSION = 1
MAX_DIFFERENCES = 10_000
MISSING = object()


class ComparisonError(ValueError):
    """Comparison inputs or derived state violate the strict contract."""


class DifferenceLimitReached(ComparisonError):
    """The complete semantic difference set exceeds the frozen budget."""


def sha256_bytes(data: bytes) -> str:
    return raw_verifier.sha256_bytes(data)


def canonical_json(value: object) -> bytes:
    return raw_verifier.canonical_json(value)


def require_exact_keys(
    value: dict[str, Any],
    required: set[str],
    optional: set[str],
    field: str,
) -> None:
    raw_verifier.require_exact_keys(value, required, optional, field)


def validate_comparison_contract(value: object) -> dict[str, object]:
    field = "semantic comparison contract"
    contract = raw_verifier.require_object(value, field)
    require_exact_keys(
        contract,
        {
            "comparison_contract_schema",
            "projection_contract_sha256",
            "normalization_policy_sha256",
            "required_equivalence",
            "max_differences",
        },
        set(),
        field,
    )
    if (
        not isinstance(contract["comparison_contract_schema"], int)
        or isinstance(contract["comparison_contract_schema"], bool)
        or contract["comparison_contract_schema"]
        != COMPARISON_CONTRACT_SCHEMA_VERSION
    ):
        raise ComparisonError("unsupported comparison_contract_schema")
    required_equivalence = raw_verifier.require_string(
        contract["required_equivalence"],
        f"{field}.required_equivalence",
    )
    if required_equivalence not in {"exact", "semantic"}:
        raise ComparisonError(
            f"{field}.required_equivalence is unsupported"
        )
    policy_digest = contract["normalization_policy_sha256"]
    if policy_digest is not None:
        policy_digest = raw_verifier.validate_sha256(
            policy_digest,
            f"{field}.normalization_policy_sha256",
        )
    max_differences = raw_verifier.require_int_range(
        contract["max_differences"],
        f"{field}.max_differences",
        1,
        MAX_DIFFERENCES,
    )
    if max_differences != MAX_DIFFERENCES:
        raise ComparisonError(
            f"{field}.max_differences must be {MAX_DIFFERENCES}"
        )
    normalized = {
        "comparison_contract_schema": (
            COMPARISON_CONTRACT_SCHEMA_VERSION
        ),
        "projection_contract_sha256": raw_verifier.validate_sha256(
            contract["projection_contract_sha256"],
            f"{field}.projection_contract_sha256",
        ),
        "normalization_policy_sha256": policy_digest,
        "required_equivalence": required_equivalence,
        "max_differences": MAX_DIFFERENCES,
    }
    canonical_json(normalized)
    return normalized


def read_contract(
    path: pathlib.Path,
    field: str,
) -> tuple[bytes, dict[str, object]]:
    try:
        data = raw_verifier.read_stable_manifest(path)
        value = raw_verifier.load_json_bytes(data, field)
    except raw_verifier.VerificationError as error:
        raise ComparisonError(str(error)) from error
    return data, validate_comparison_contract(value)


def json_kind(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise ComparisonError(
        f"comparison contains non-JSON value: {type(value).__name__}"
    )


def escape_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def child_pointer(pointer: str, token: str) -> str:
    return f"{pointer}/{escape_pointer_token(token)}"


def presence(value: object) -> dict[str, object]:
    if value is MISSING:
        return {"state": "missing"}
    canonical_json(value)
    return {"state": "present", "value": copy.deepcopy(value)}


def append_difference(
    differences: list[dict[str, object]],
    pointer: str,
    upstream_value: object,
    rust_value: object,
    case_id: str,
    upstream_raw_sha256: str,
    rust_raw_sha256: str,
    max_differences: int,
) -> None:
    if not pointer:
        raise ComparisonError(
            "semantic comparison roots have incompatible JSON kinds"
        )
    if len(differences) >= max_differences:
        raise DifferenceLimitReached(
            f"semantic differences exceed {max_differences}"
        )
    difference = {
        "id": f"D-{len(differences) + 1:04d}",
        "case_id": case_id,
        "json_pointer": pointer,
        "classification": "Semantic",
        "failure_kind": "semantic_mismatch",
        "left_raw_sha256": upstream_raw_sha256,
        "right_raw_sha256": rust_raw_sha256,
        "upstream_value": presence(upstream_value),
        "rust_value": presence(rust_value),
    }
    difference["diff_fingerprint"] = (
        waiver_validator.difference_fingerprint(difference)
    )
    differences.append(difference)


def compare_values(
    upstream_value: object,
    rust_value: object,
    pointer: str,
    differences: list[dict[str, object]],
    case_id: str,
    upstream_raw_sha256: str,
    rust_raw_sha256: str,
    max_differences: int = MAX_DIFFERENCES,
) -> None:
    upstream_kind = json_kind(upstream_value)
    rust_kind = json_kind(rust_value)
    if upstream_kind != rust_kind:
        append_difference(
            differences,
            pointer,
            upstream_value,
            rust_value,
            case_id,
            upstream_raw_sha256,
            rust_raw_sha256,
            max_differences,
        )
        return
    if upstream_kind == "object":
        assert isinstance(upstream_value, dict)
        assert isinstance(rust_value, dict)
        for key in sorted(set(upstream_value) | set(rust_value)):
            child = child_pointer(pointer, key)
            if key not in upstream_value:
                append_difference(
                    differences,
                    child,
                    MISSING,
                    rust_value[key],
                    case_id,
                    upstream_raw_sha256,
                    rust_raw_sha256,
                    max_differences,
                )
            elif key not in rust_value:
                append_difference(
                    differences,
                    child,
                    upstream_value[key],
                    MISSING,
                    case_id,
                    upstream_raw_sha256,
                    rust_raw_sha256,
                    max_differences,
                )
            else:
                compare_values(
                    upstream_value[key],
                    rust_value[key],
                    child,
                    differences,
                    case_id,
                    upstream_raw_sha256,
                    rust_raw_sha256,
                    max_differences,
                )
        return
    if upstream_kind == "array":
        assert isinstance(upstream_value, list)
        assert isinstance(rust_value, list)
        shared_length = min(len(upstream_value), len(rust_value))
        for index in range(shared_length):
            compare_values(
                upstream_value[index],
                rust_value[index],
                child_pointer(pointer, str(index)),
                differences,
                case_id,
                upstream_raw_sha256,
                rust_raw_sha256,
                max_differences,
            )
        for index in range(shared_length, len(upstream_value)):
            append_difference(
                differences,
                child_pointer(pointer, str(index)),
                upstream_value[index],
                MISSING,
                case_id,
                upstream_raw_sha256,
                rust_raw_sha256,
                max_differences,
            )
        for index in range(shared_length, len(rust_value)):
            append_difference(
                differences,
                child_pointer(pointer, str(index)),
                MISSING,
                rust_value[index],
                case_id,
                upstream_raw_sha256,
                rust_raw_sha256,
                max_differences,
            )
        return
    if upstream_value != rust_value:
        append_difference(
            differences,
            pointer,
            upstream_value,
            rust_value,
            case_id,
            upstream_raw_sha256,
            rust_raw_sha256,
            max_differences,
        )


def stream_references(
    semantic: dict[str, object],
) -> dict[str, dict[str, object]]:
    evidence = semantic["evidence"]
    assert isinstance(evidence, dict)
    raw_streams = evidence["raw_streams"]
    assert isinstance(raw_streams, dict)
    result: dict[str, dict[str, object]] = {}
    for role in ("stdout", "stderr", "runtime_log"):
        if role not in raw_streams:
            continue
        stream = raw_streams[role]
        assert isinstance(stream, dict)
        result[role] = {
            "sha256": stream["sha256"],
            "size": stream["size"],
        }
    return result


def raw_observation_sha256(
    semantic: dict[str, object],
) -> str:
    comparison = semantic["comparison"]
    assert isinstance(comparison, dict)
    return sha256_bytes(
        canonical_json(
            {
                "termination": comparison["termination"],
                "streams": stream_references(semantic),
            }
        )
    )


def normalization_summary(
    output: dict[str, object] | None,
    output_bytes: bytes | None,
    skipped_projection_failure: bool,
) -> dict[str, object]:
    if skipped_projection_failure:
        if output is not None or output_bytes is not None:
            raise ComparisonError(
                "skipped normalization must not have an output"
            )
        return {
            "kind": "skipped",
            "reason": "projection_failure",
        }
    if output is None:
        return {"kind": "none"}
    assert output_bytes is not None
    return {
        "kind": "applied",
        "output_artifact_sha256": sha256_bytes(output_bytes),
        "normalized_projection_sha256": output[
            "normalized_projection_sha256"
        ],
        "policy_artifact": copy.deepcopy(output["policy_artifact"]),
        "rules_applied": copy.deepcopy(output["rules_applied"]),
    }


def side_summary(
    projection: dict[str, object],
    projection_bytes: bytes,
    normalization_output: dict[str, object] | None,
    normalization_bytes: bytes | None,
    normalization_skipped: bool,
) -> tuple[dict[str, object], dict[str, object]]:
    source_semantic = projection["semantic"]
    assert isinstance(source_semantic, dict)
    selected_semantic = (
        source_semantic
        if normalization_output is None
        else normalization_output["semantic"]
    )
    assert isinstance(selected_semantic, dict)
    comparison = selected_semantic["comparison"]
    assert isinstance(comparison, dict)
    summary = {
        "producer": copy.deepcopy(source_semantic["producer"]),
        "projection": {
            "artifact_sha256": sha256_bytes(projection_bytes),
            "canonical_projection_sha256": sha256_bytes(
                canonical_json(projection)
            ),
            "result": source_semantic["result"],
            "issues": copy.deepcopy(source_semantic["issues"]),
        },
        "raw_streams": stream_references(source_semantic),
        "raw_observation_sha256": raw_observation_sha256(
            source_semantic
        ),
        "normalization": normalization_summary(
            normalization_output,
            normalization_bytes,
            normalization_skipped,
        ),
        "comparison_sha256": sha256_bytes(canonical_json(comparison)),
    }
    return summary, comparison


def raw_equality(
    upstream_semantic: dict[str, object],
    rust_semantic: dict[str, object],
) -> dict[str, bool]:
    upstream_comparison = upstream_semantic["comparison"]
    rust_comparison = rust_semantic["comparison"]
    assert isinstance(upstream_comparison, dict)
    assert isinstance(rust_comparison, dict)
    upstream_streams = stream_references(upstream_semantic)
    rust_streams = stream_references(rust_semantic)
    result = {
        "termination": (
            upstream_comparison["termination"]
            == rust_comparison["termination"]
        ),
        "stdout": (
            upstream_streams.get("stdout")
            == rust_streams.get("stdout")
        ),
        "stderr": (
            upstream_streams.get("stderr")
            == rust_streams.get("stderr")
        ),
        "runtime_log": (
            upstream_streams.get("runtime_log")
            == rust_streams.get("runtime_log")
        ),
    }
    result["all"] = all(result.values())
    return result


def build_difference_report(
    run_identity: dict[str, object],
    case_id: str,
    differences: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "report_schema": DIFFERENCE_REPORT_SCHEMA_VERSION,
        "run_identity": {
            "platform": run_identity["platform"],
            "upstream_commit": run_identity["upstream_commit"],
            "rust_schema": run_identity["semantic_schema"],
        },
        "executed_case_ids": [case_id],
        "differences": differences,
    }


def build_blocked_difference_output(
    run_identity: dict[str, object],
    case_id: str,
    reason: str,
) -> dict[str, object]:
    return {
        "blocked_schema": BLOCKED_DIFFERENCE_SCHEMA_VERSION,
        "result": "blocked",
        "reason": reason,
        "run_identity": {
            "platform": run_identity["platform"],
            "upstream_commit": run_identity["upstream_commit"],
            "rust_schema": run_identity["semantic_schema"],
        },
        "case_id": case_id,
    }


def serialize_json(value: dict[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def requirement_met(result: str, required_equivalence: str) -> bool:
    if required_equivalence == "exact":
        return result == "exact"
    return result in {"exact", "semantic_equal"}


def build_report(
    comparison_contract: dict[str, object],
    comparison_contract_bytes: bytes,
    projection_contract_bytes: bytes,
    upstream_projection: dict[str, object],
    upstream_projection_bytes: bytes,
    rust_projection: dict[str, object],
    rust_projection_bytes: bytes,
    upstream_normalization: dict[str, object] | None,
    upstream_normalization_bytes: bytes | None,
    rust_normalization: dict[str, object] | None,
    rust_normalization_bytes: bytes | None,
    normalization_skipped: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    if upstream_projection["run_identity"] != rust_projection["run_identity"]:
        raise ComparisonError("projection run identities do not match")
    if upstream_projection["case_id"] != rust_projection["case_id"]:
        raise ComparisonError("projection case IDs do not match")
    run_identity = upstream_projection["run_identity"]
    case_id = str(upstream_projection["case_id"])
    assert isinstance(run_identity, dict)

    upstream_summary, upstream_comparison = side_summary(
        upstream_projection,
        upstream_projection_bytes,
        upstream_normalization,
        upstream_normalization_bytes,
        normalization_skipped,
    )
    rust_summary, rust_comparison = side_summary(
        rust_projection,
        rust_projection_bytes,
        rust_normalization,
        rust_normalization_bytes,
        normalization_skipped,
    )
    upstream_producer = upstream_summary["producer"]
    rust_producer = rust_summary["producer"]
    assert isinstance(upstream_producer, dict)
    assert isinstance(rust_producer, dict)
    if upstream_producer["side"] != "upstream":
        raise ComparisonError("left producer side must be upstream")
    if rust_producer["side"] != "rust":
        raise ComparisonError("right producer side must be rust")

    source_upstream_semantic = upstream_projection["semantic"]
    source_rust_semantic = rust_projection["semantic"]
    assert isinstance(source_upstream_semantic, dict)
    assert isinstance(source_rust_semantic, dict)
    raw_equal = raw_equality(
        source_upstream_semantic,
        source_rust_semantic,
    )
    projection_failed = (
        source_upstream_semantic["result"] != "pass"
        or source_rust_semantic["result"] != "pass"
    )

    differences: list[dict[str, object]] = []
    difference_report: dict[str, object] | None = None
    limit_error: str | None = None
    if projection_failed:
        result = "projection_failure"
    else:
        try:
            compare_values(
                upstream_comparison,
                rust_comparison,
                "/comparison",
                differences,
                case_id,
                str(upstream_summary["raw_observation_sha256"]),
                str(rust_summary["raw_observation_sha256"]),
                int(comparison_contract["max_differences"]),
            )
        except DifferenceLimitReached as error:
            limit_error = str(error)
        if limit_error is not None:
            result = "comparison_limit_reached"
        elif differences:
            result = "different"
        elif raw_equal["all"]:
            result = "exact"
        else:
            result = "semantic_equal"
        if limit_error is None:
            difference_report = build_difference_report(
                run_identity,
                case_id,
                differences,
            )

    difference_output: dict[str, object]
    if difference_report is not None:
        difference_output = difference_report
        difference_bytes = serialize_json(difference_output)
        difference_artifact = {
            "kind": "report",
            "sha256": sha256_bytes(difference_bytes),
            "canonical_report_sha256": sha256_bytes(
                canonical_json(difference_output)
            ),
            "difference_count": len(differences),
        }
    else:
        difference_output = build_blocked_difference_output(
            run_identity,
            case_id,
            result,
        )
        difference_bytes = serialize_json(difference_output)
        difference_artifact = {
            "kind": "blocked",
            "sha256": sha256_bytes(difference_bytes),
            "canonical_blocked_sha256": sha256_bytes(
                canonical_json(difference_output)
            ),
            "reason": result,
        }

    report = {
        "comparison_schema": COMPARISON_SCHEMA_VERSION,
        "comparator": {
            "name": COMPARATOR_NAME,
            "version": COMPARATOR_VERSION,
        },
        "result": result,
        "requirement": {
            "required_equivalence": comparison_contract[
                "required_equivalence"
            ],
            "met": requirement_met(
                result,
                str(comparison_contract["required_equivalence"]),
            ),
        },
        "run_identity": copy.deepcopy(run_identity),
        "case_id": case_id,
        "contracts": {
            "comparison": {
                "artifact_sha256": sha256_bytes(
                    comparison_contract_bytes
                ),
                "canonical_contract_sha256": sha256_bytes(
                    canonical_json(comparison_contract)
                ),
            },
            "projection": {
                "artifact_sha256": sha256_bytes(
                    projection_contract_bytes
                ),
            },
        },
        "inputs": {
            "upstream": upstream_summary,
            "rust": rust_summary,
        },
        "raw_equality": raw_equal,
        "difference_report_artifact": difference_artifact,
        "limit_error": limit_error,
    }
    canonical_json(report)
    return report, difference_output


def ensure_output_paths(
    outputs: list[pathlib.Path],
    inputs: list[pathlib.Path],
    artifact_roots: list[pathlib.Path],
) -> None:
    resolved_outputs = [path.resolve() for path in outputs]
    if len(resolved_outputs) != len(set(resolved_outputs)):
        raise ComparisonError("all output paths must be distinct")
    resolved_inputs = {path.resolve(strict=True) for path in inputs}
    if any(path in resolved_inputs for path in resolved_outputs):
        raise ComparisonError("output must not overwrite an input")
    resolved_roots = [
        raw_verifier.resolve_artifact_root(path)
        for path in artifact_roots
    ]
    for output in resolved_outputs:
        if any(
            output == root or output.is_relative_to(root)
            for root in resolved_roots
        ):
            raise ComparisonError(
                "outputs must not be inside an artifact root"
            )


def compare_files(
    comparison_contract_path: pathlib.Path,
    projection_contract_path: pathlib.Path,
    upstream_manifest_path: pathlib.Path,
    upstream_artifact_root: pathlib.Path,
    rust_manifest_path: pathlib.Path,
    rust_artifact_root: pathlib.Path,
    upstream_projection_output: pathlib.Path,
    rust_projection_output: pathlib.Path,
    normalization_policy_path: pathlib.Path | None,
    upstream_normalization_output: pathlib.Path | None,
    rust_normalization_output: pathlib.Path | None,
    comparison_output: pathlib.Path,
    difference_report_output: pathlib.Path,
    max_artifact_bytes: int,
    repo_root: pathlib.Path,
) -> tuple[dict[str, object], dict[str, object]]:
    outputs = [
        upstream_projection_output,
        rust_projection_output,
        comparison_output,
        difference_report_output,
    ]
    inputs = [
        comparison_contract_path,
        projection_contract_path,
        upstream_manifest_path,
        rust_manifest_path,
    ]
    if normalization_policy_path is None:
        if (
            upstream_normalization_output is not None
            or rust_normalization_output is not None
        ):
            raise ComparisonError(
                "normalization outputs require a normalization policy"
            )
    else:
        if (
            upstream_normalization_output is None
            or rust_normalization_output is None
        ):
            raise ComparisonError(
                "a normalization policy requires both output paths"
            )
        inputs.append(normalization_policy_path)
        outputs.extend(
            [
                upstream_normalization_output,
                rust_normalization_output,
            ]
        )
    ensure_output_paths(
        outputs,
        inputs,
        [upstream_artifact_root, rust_artifact_root],
    )

    comparison_contract_bytes, comparison_contract = read_contract(
        comparison_contract_path,
        "semantic comparison contract",
    )
    projection_contract_bytes = raw_verifier.read_stable_manifest(
        projection_contract_path
    )
    expected_projection_digest = comparison_contract[
        "projection_contract_sha256"
    ]
    if sha256_bytes(projection_contract_bytes) != expected_projection_digest:
        raise ComparisonError(
            "projection contract hash does not match comparison contract"
        )

    policy_bytes: bytes | None = None
    expected_policy_digest = comparison_contract[
        "normalization_policy_sha256"
    ]
    if normalization_policy_path is None:
        if expected_policy_digest is not None:
            raise ComparisonError(
                "comparison contract requires a normalization policy"
            )
    else:
        policy_bytes = raw_verifier.read_stable_manifest(
            normalization_policy_path
        )
        if sha256_bytes(policy_bytes) != expected_policy_digest:
            raise ComparisonError(
                "normalization policy hash does not match comparison contract"
            )

    upstream_projection = projector.project_files(
        projection_contract_path,
        upstream_manifest_path,
        upstream_artifact_root,
        upstream_projection_output,
        max_artifact_bytes,
    )
    rust_projection = projector.project_files(
        projection_contract_path,
        rust_manifest_path,
        rust_artifact_root,
        rust_projection_output,
        max_artifact_bytes,
    )
    upstream_projection_bytes = upstream_projection_output.read_bytes()
    rust_projection_bytes = rust_projection_output.read_bytes()
    upstream_projection_semantic = upstream_projection["semantic"]
    rust_projection_semantic = rust_projection["semantic"]
    assert isinstance(upstream_projection_semantic, dict)
    assert isinstance(rust_projection_semantic, dict)
    projection_failed = (
        upstream_projection_semantic["result"] != "pass"
        or rust_projection_semantic["result"] != "pass"
    )

    upstream_normalization = None
    rust_normalization = None
    upstream_normalization_bytes = None
    rust_normalization_bytes = None
    if normalization_policy_path is not None and not projection_failed:
        assert upstream_normalization_output is not None
        assert rust_normalization_output is not None
        upstream_normalization = normalizer.normalize_files(
            upstream_projection_output,
            normalization_policy_path,
            upstream_normalization_output,
            repo_root,
        )
        rust_normalization = normalizer.normalize_files(
            rust_projection_output,
            normalization_policy_path,
            rust_normalization_output,
            repo_root,
        )
        upstream_normalization_bytes = (
            upstream_normalization_output.read_bytes()
        )
        rust_normalization_bytes = rust_normalization_output.read_bytes()

    report, difference_output = build_report(
        comparison_contract,
        comparison_contract_bytes,
        projection_contract_bytes,
        upstream_projection,
        upstream_projection_bytes,
        rust_projection,
        rust_projection_bytes,
        upstream_normalization,
        upstream_normalization_bytes,
        rust_normalization,
        rust_normalization_bytes,
        normalization_skipped=(
            normalization_policy_path is not None and projection_failed
        ),
    )

    if (
        raw_verifier.read_stable_manifest(comparison_contract_path)
        != comparison_contract_bytes
    ):
        raise ComparisonError(
            "semantic comparison contract changed during comparison"
        )
    if (
        raw_verifier.read_stable_manifest(projection_contract_path)
        != projection_contract_bytes
    ):
        raise ComparisonError(
            "semantic projection contract changed during comparison"
        )
    if normalization_policy_path is not None:
        assert policy_bytes is not None
        if (
            raw_verifier.read_stable_manifest(normalization_policy_path)
            != policy_bytes
        ):
            raise ComparisonError(
                "normalization policy changed during comparison"
            )

    comparison_output.parent.mkdir(parents=True, exist_ok=True)
    comparison_output.write_bytes(serialize_json(report))
    difference_report_output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    difference_report_output.write_bytes(
        serialize_json(difference_output)
    )
    return report, difference_output


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Project, optionally normalize, and compare upstream/Rust "
            "DIE semantic results."
        )
    )
    parser.add_argument(
        "--comparison-contract",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--projection-contract",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--upstream-manifest",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--upstream-artifact-root",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--rust-manifest",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--rust-artifact-root",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--upstream-projection-output",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--rust-projection-output",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--normalization-policy",
        type=pathlib.Path,
    )
    parser.add_argument(
        "--upstream-normalization-output",
        type=pathlib.Path,
    )
    parser.add_argument(
        "--rust-normalization-output",
        type=pathlib.Path,
    )
    parser.add_argument(
        "--comparison-output",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--difference-report-output",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--max-artifact-bytes",
        type=int,
        default=raw_verifier.DEFAULT_MAX_ARTIFACT_BYTES,
    )
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[2],
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report, _ = compare_files(
            args.comparison_contract,
            args.projection_contract,
            args.upstream_manifest,
            args.upstream_artifact_root,
            args.rust_manifest,
            args.rust_artifact_root,
            args.upstream_projection_output,
            args.rust_projection_output,
            args.normalization_policy,
            args.upstream_normalization_output,
            args.rust_normalization_output,
            args.comparison_output,
            args.difference_report_output,
            args.max_artifact_bytes,
            args.repo_root,
        )
    except (
        ComparisonError,
        framing.FramingError,
        normalizer.NormalizationError,
        projector.SemanticProjectionError,
        raw_verifier.VerificationError,
        waiver_validator.ValidationError,
        OSError,
    ) as error:
        print(f"semantic comparison error: {error}", file=sys.stderr)
        return 2
    if report["result"] in {
        "projection_failure",
        "comparison_limit_reached",
    }:
        return 2
    requirement = report["requirement"]
    assert isinstance(requirement, dict)
    return 0 if requirement["met"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

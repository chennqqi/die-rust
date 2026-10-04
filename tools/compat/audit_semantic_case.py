#!/usr/bin/env python3
"""Run one authoritative semantic comparison and exact waiver audit."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

import compare_semantic_results as comparator
import validate_difference_waivers as waivers


CASE_AUDIT_SCHEMA_VERSION = 1
AUDITOR = {
    "name": "die-semantic-case-auditor",
    "version": 1,
}


def serialize_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def write_json(path: pathlib.Path, value: dict[str, object]) -> bytes:
    data = serialize_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def artifact_reference(
    value: object,
    data: bytes,
) -> dict[str, str]:
    return {
        "sha256": waivers.sha256_bytes(data),
        "canonical_sha256": waivers.sha256_bytes(
            waivers.canonical_json(value)
        ),
    }


def empty_artifacts() -> dict[str, object]:
    return {
        "comparison": None,
        "difference_report": None,
        "waiver_registry": None,
        "waiver_audit": None,
    }


def infrastructure_waiver_audit(
    as_of: object,
    error: str,
) -> dict[str, object]:
    return {
        "audit_schema": waivers.AUDIT_SCHEMA_VERSION,
        "as_of": as_of,
        "errors": [error],
        "result": "infrastructure_error",
    }


def build_case_audit(
    *,
    as_of: object,
    result: str,
    reason: str,
    artifacts: dict[str, object],
    comparison: dict[str, object] | None,
    waiver_audit: dict[str, object] | None,
    errors: list[str],
) -> dict[str, object]:
    return {
        "case_audit_schema": CASE_AUDIT_SCHEMA_VERSION,
        "auditor": AUDITOR,
        "as_of": as_of,
        "result": result,
        "reason": reason,
        "run_identity": (
            None if comparison is None else comparison["run_identity"]
        ),
        "case_id": None if comparison is None else comparison["case_id"],
        "artifacts": artifacts,
        "comparison": comparison,
        "waiver_audit": waiver_audit,
        "input_files_unchanged": result != "infrastructure_error",
        "errors": errors,
    }


def audit_files(
    *,
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
    waiver_registry_path: pathlib.Path,
    waiver_audit_output: pathlib.Path,
    case_audit_output: pathlib.Path,
    as_of_text: str,
    max_artifact_bytes: int,
    repo_root: pathlib.Path,
) -> dict[str, object]:
    outputs = [
        upstream_projection_output,
        rust_projection_output,
        comparison_output,
        difference_report_output,
        waiver_audit_output,
        case_audit_output,
    ]
    inputs = [
        comparison_contract_path,
        projection_contract_path,
        upstream_manifest_path,
        rust_manifest_path,
        waiver_registry_path,
    ]
    if normalization_policy_path is not None:
        inputs.append(normalization_policy_path)
    if upstream_normalization_output is not None:
        outputs.append(upstream_normalization_output)
    if rust_normalization_output is not None:
        outputs.append(rust_normalization_output)
    comparator.ensure_output_paths(
        outputs,
        inputs,
        [upstream_artifact_root, rust_artifact_root],
    )

    artifacts = empty_artifacts()
    comparison: dict[str, object] | None = None
    waiver_audit: dict[str, object] | None = None
    parsed_as_of = None
    registry_bytes: bytes | None = None
    try:
        parsed_as_of = waivers.parse_date(as_of_text, "--as-of")
        registry_value, registry_bytes = waivers.load_json_bytes(
            waiver_registry_path,
            "waiver registry",
        )
        registry = waivers.validate_registry(
            registry_value,
            repo_root.resolve(),
            parsed_as_of,
        )
        artifacts["waiver_registry"] = artifact_reference(
            registry_value,
            registry_bytes,
        )

        comparison, difference_output = comparator.compare_files(
            comparison_contract_path,
            projection_contract_path,
            upstream_manifest_path,
            upstream_artifact_root,
            rust_manifest_path,
            rust_artifact_root,
            upstream_projection_output,
            rust_projection_output,
            normalization_policy_path,
            upstream_normalization_output,
            rust_normalization_output,
            comparison_output,
            difference_report_output,
            max_artifact_bytes,
            repo_root,
        )
        comparison_value, comparison_bytes = waivers.load_json_bytes(
            comparison_output,
            "semantic comparison output",
        )
        difference_value, difference_bytes = waivers.load_json_bytes(
            difference_report_output,
            "semantic difference output",
        )
        if comparison_value != comparison:
            raise waivers.ValidationError(
                "semantic comparison output changed after generation"
            )
        if difference_value != difference_output:
            raise waivers.ValidationError(
                "semantic difference output changed after generation"
            )
        artifacts["comparison"] = artifact_reference(
            comparison_value,
            comparison_bytes,
        )
        artifacts["difference_report"] = artifact_reference(
            difference_value,
            difference_bytes,
        )

        if comparison["result"] in {
            "projection_failure",
            "comparison_limit_reached",
        }:
            error = f"semantic comparison blocked: {comparison['result']}"
            waiver_audit = infrastructure_waiver_audit(
                parsed_as_of.isoformat(),
                error,
            )
            waiver_bytes = write_json(
                waiver_audit_output,
                waiver_audit,
            )
            artifacts["waiver_audit"] = artifact_reference(
                waiver_audit,
                waiver_bytes,
            )
            case_audit = build_case_audit(
                as_of=parsed_as_of.isoformat(),
                result="infrastructure_error",
                reason="comparison_blocked",
                artifacts=artifacts,
                comparison=comparison,
                waiver_audit=waiver_audit,
                errors=[error],
            )
            write_json(case_audit_output, case_audit)
            return case_audit

        report = waivers.validate_report(difference_value)
        if waiver_registry_path.read_bytes() != registry_bytes:
            raise waivers.ValidationError(
                "waiver registry changed during case audit"
            )
        waiver_audit = waivers.audit_waivers(
            registry,
            report,
            parsed_as_of,
            waivers.sha256_bytes(registry_bytes),
            waivers.sha256_bytes(difference_bytes),
        )
        waiver_bytes = write_json(waiver_audit_output, waiver_audit)
        artifacts["waiver_audit"] = artifact_reference(
            waiver_audit,
            waiver_bytes,
        )

        stable_files = (
            (comparison_output, comparison_bytes, "comparison output"),
            (
                difference_report_output,
                difference_bytes,
                "difference output",
            ),
            (waiver_registry_path, registry_bytes, "waiver registry"),
            (waiver_audit_output, waiver_bytes, "waiver audit output"),
        )
        for path, expected, field in stable_files:
            if path.read_bytes() != expected:
                raise waivers.ValidationError(
                    f"{field} changed during case audit"
                )

        requirement = comparison["requirement"]
        assert isinstance(requirement, dict)
        if waiver_audit["result"] != "pass":
            result = "fail"
            reason = "waiver_audit_failed"
        elif comparison["result"] == "different":
            result = "pass"
            reason = "approved_semantic_differences"
        elif requirement["met"]:
            result = "pass"
            reason = "required_equivalence_met"
        else:
            result = "fail"
            reason = "raw_only_mismatch_unwaivable"
        case_audit = build_case_audit(
            as_of=parsed_as_of.isoformat(),
            result=result,
            reason=reason,
            artifacts=artifacts,
            comparison=comparison,
            waiver_audit=waiver_audit,
            errors=[],
        )
        write_json(case_audit_output, case_audit)
        return case_audit
    except (
        comparator.ComparisonError,
        comparator.framing.FramingError,
        comparator.normalizer.NormalizationError,
        comparator.projector.SemanticProjectionError,
        comparator.raw_verifier.VerificationError,
        waivers.ValidationError,
        OSError,
    ) as caught:
        error = str(caught)
        as_of = (
            None
            if parsed_as_of is None
            else parsed_as_of.isoformat()
        )
        waiver_audit = infrastructure_waiver_audit(as_of, error)
        waiver_bytes = write_json(waiver_audit_output, waiver_audit)
        artifacts["waiver_audit"] = artifact_reference(
            waiver_audit,
            waiver_bytes,
        )
        case_audit = build_case_audit(
            as_of=as_of,
            result="infrastructure_error",
            reason="infrastructure_error",
            artifacts=artifacts,
            comparison=comparison,
            waiver_audit=waiver_audit,
            errors=[error],
        )
        write_json(case_audit_output, case_audit)
        return case_audit


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run one audited upstream/Rust semantic comparison and exact "
            "difference-waiver decision."
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
    parser.add_argument("--normalization-policy", type=pathlib.Path)
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
        "--waiver-registry",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--waiver-audit-output",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--case-audit-output",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--as-of",
        required=True,
        help="Deterministic audit date in YYYY-MM-DD form",
    )
    parser.add_argument(
        "--max-artifact-bytes",
        type=int,
        default=comparator.raw_verifier.DEFAULT_MAX_ARTIFACT_BYTES,
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
        audit = audit_files(
            comparison_contract_path=args.comparison_contract,
            projection_contract_path=args.projection_contract,
            upstream_manifest_path=args.upstream_manifest,
            upstream_artifact_root=args.upstream_artifact_root,
            rust_manifest_path=args.rust_manifest,
            rust_artifact_root=args.rust_artifact_root,
            upstream_projection_output=args.upstream_projection_output,
            rust_projection_output=args.rust_projection_output,
            normalization_policy_path=args.normalization_policy,
            upstream_normalization_output=(
                args.upstream_normalization_output
            ),
            rust_normalization_output=args.rust_normalization_output,
            comparison_output=args.comparison_output,
            difference_report_output=args.difference_report_output,
            waiver_registry_path=args.waiver_registry,
            waiver_audit_output=args.waiver_audit_output,
            case_audit_output=args.case_audit_output,
            as_of_text=args.as_of,
            max_artifact_bytes=args.max_artifact_bytes,
            repo_root=args.repo_root,
        )
    except (
        comparator.ComparisonError,
        comparator.raw_verifier.VerificationError,
        OSError,
    ) as error:
        print(f"semantic case audit error: {error}", file=sys.stderr)
        return 2
    if audit["result"] == "infrastructure_error":
        return 2
    return 0 if audit["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

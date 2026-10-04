#!/usr/bin/env python3
"""Run and aggregate a complete planned typed-legacy compatibility suite."""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import stat
import sys
from typing import Any

import audit_semantic_case as case_auditor


PLAN_SCHEMA_VERSION = 1
REPORT_SCHEMA_VERSION = 1
RUNNER = {
    "name": "die-compatibility-suite-runner",
    "version": 1,
}
MAX_CASES = 10_000
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
PROFILE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
RAW = case_auditor.comparator.raw_verifier
WAIVERS = case_auditor.waivers


class SuiteError(ValueError):
    """The suite plan, filesystem, or derived result is not trustworthy."""


def require_object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SuiteError(f"{field} must be an object")
    return value


def require_list(value: object, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise SuiteError(f"{field} must be an array")
    return value


def require_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise SuiteError(f"{field} must be a non-empty string")
    if "\x00" in value:
        raise SuiteError(f"{field} must not contain NUL")
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
        raise SuiteError(
            f"{field} is missing fields: {', '.join(missing)}"
        )
    if extra:
        raise SuiteError(
            f"{field} has unknown fields: {', '.join(extra)}"
        )


def require_positive_int(
    value: object,
    field: str,
    maximum: int,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > maximum
    ):
        raise SuiteError(
            f"{field} must be an integer in 1..{maximum}"
        )
    return value


def validate_id(value: object, field: str) -> str:
    text = require_string(value, field)
    if not ID_PATTERN.fullmatch(text):
        raise SuiteError(f"{field} must be one exact ID")
    return text


def validate_profile(value: object, field: str) -> str:
    text = require_string(value, field)
    if not PROFILE_PATTERN.fullmatch(text):
        raise SuiteError(f"{field} must be one exact profile")
    return text


def validate_relative_path(value: object, field: str) -> str:
    text = require_string(value, field)
    if "\\" in text:
        raise SuiteError(f"{field} must use '/' separators")
    relative = pathlib.PurePosixPath(text)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise SuiteError(
            f"{field} must be a normalized relative path"
        )
    return relative.as_posix()


def validate_input_artifact(
    value: object,
    field: str,
) -> dict[str, str]:
    artifact = require_object(value, field)
    require_exact_keys(artifact, {"path", "sha256"}, set(), field)
    digest = require_string(artifact["sha256"], f"{field}.sha256")
    if not RAW.HEX_64.fullmatch(digest):
        raise SuiteError(
            f"{field}.sha256 must be a lowercase SHA-256"
        )
    return {
        "path": validate_relative_path(
            artifact["path"],
            f"{field}.path",
        ),
        "sha256": digest,
    }


def validate_case(value: object, index: int) -> dict[str, object]:
    field = f"plan.cases[{index}]"
    item = require_object(value, field)
    required = {
        "case_id",
        "capability",
        "platform",
        "oracle_profile",
        "comparison_contract",
        "projection_contract",
        "upstream_manifest",
        "upstream_artifact_root",
        "rust_manifest",
        "rust_artifact_root",
        "normalization_policy",
        "waiver_registry",
    }
    require_exact_keys(item, required, set(), field)
    platform = require_string(item["platform"], f"{field}.platform")
    if not RAW.PLATFORM_PATTERN.fullmatch(platform):
        raise SuiteError(
            f"{field}.platform must name one exact platform"
        )
    policy = item["normalization_policy"]
    return {
        "case_id": validate_id(item["case_id"], f"{field}.case_id"),
        "capability": validate_id(
            item["capability"],
            f"{field}.capability",
        ),
        "platform": platform,
        "oracle_profile": validate_profile(
            item["oracle_profile"],
            f"{field}.oracle_profile",
        ),
        "comparison_contract": validate_input_artifact(
            item["comparison_contract"],
            f"{field}.comparison_contract",
        ),
        "projection_contract": validate_input_artifact(
            item["projection_contract"],
            f"{field}.projection_contract",
        ),
        "upstream_manifest": validate_input_artifact(
            item["upstream_manifest"],
            f"{field}.upstream_manifest",
        ),
        "upstream_artifact_root": validate_relative_path(
            item["upstream_artifact_root"],
            f"{field}.upstream_artifact_root",
        ),
        "rust_manifest": validate_input_artifact(
            item["rust_manifest"],
            f"{field}.rust_manifest",
        ),
        "rust_artifact_root": validate_relative_path(
            item["rust_artifact_root"],
            f"{field}.rust_artifact_root",
        ),
        "normalization_policy": (
            None
            if policy is None
            else validate_input_artifact(
                policy,
                f"{field}.normalization_policy",
            )
        ),
        "waiver_registry": validate_input_artifact(
            item["waiver_registry"],
            f"{field}.waiver_registry",
        ),
    }


def validate_plan(value: object) -> dict[str, object]:
    plan = require_object(value, "plan")
    require_exact_keys(
        plan,
        {
            "suite_plan_schema",
            "suite_id",
            "as_of",
            "upstream_commit",
            "semantic_schema",
            "max_artifact_bytes",
            "cases",
        },
        set(),
        "plan",
    )
    if plan["suite_plan_schema"] != PLAN_SCHEMA_VERSION:
        raise SuiteError("unsupported suite_plan_schema")
    upstream_commit = require_string(
        plan["upstream_commit"],
        "plan.upstream_commit",
    )
    if not RAW.HEX_40.fullmatch(upstream_commit):
        raise SuiteError(
            "plan.upstream_commit must be a lowercase 40-hex SHA"
        )
    cases_value = require_list(plan["cases"], "plan.cases")
    if not 1 <= len(cases_value) <= MAX_CASES:
        raise SuiteError(
            f"plan.cases must contain 1..{MAX_CASES} entries"
        )
    cases = [
        validate_case(item, index)
        for index, item in enumerate(cases_value)
    ]
    identities = [
        (
            item["platform"],
            item["oracle_profile"],
            item["case_id"],
        )
        for item in cases
    ]
    if len(identities) != len(set(identities)):
        raise SuiteError(
            "plan case platform/oracle_profile/case_id identities "
            "must be unique"
        )
    try:
        as_of = WAIVERS.parse_date(plan["as_of"], "plan.as_of")
    except WAIVERS.ValidationError as error:
        raise SuiteError(str(error)) from error
    return {
        "suite_plan_schema": PLAN_SCHEMA_VERSION,
        "suite_id": validate_id(plan["suite_id"], "plan.suite_id"),
        "as_of": as_of.isoformat(),
        "upstream_commit": upstream_commit,
        "semantic_schema": require_positive_int(
            plan["semantic_schema"],
            "plan.semantic_schema",
            (1 << 31) - 1,
        ),
        "max_artifact_bytes": require_positive_int(
            plan["max_artifact_bytes"],
            "plan.max_artifact_bytes",
            MAX_ARTIFACT_BYTES,
        ),
        "cases": cases,
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


def artifact_reference(
    value: object,
    data: bytes,
) -> dict[str, str]:
    return {
        "sha256": RAW.sha256_bytes(data),
        "canonical_sha256": RAW.sha256_bytes(
            RAW.canonical_json(value)
        ),
    }


def resolve_real_directory(
    path: pathlib.Path,
    field: str,
) -> pathlib.Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SuiteError(f"cannot inspect {field}: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or RAW.is_reparse_point(metadata)
    ):
        raise SuiteError(f"{field} must be a real directory")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise SuiteError(f"cannot resolve {field}: {error}") from error


def prepare_roots(
    input_root: pathlib.Path,
    output_root: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path]:
    resolved_input = resolve_real_directory(input_root, "input root")
    try:
        prospective_output = output_root.resolve(strict=False)
    except OSError as error:
        raise SuiteError(f"cannot resolve output root: {error}") from error
    if (
        prospective_output == resolved_input
        or prospective_output.is_relative_to(resolved_input)
        or resolved_input.is_relative_to(prospective_output)
    ):
        raise SuiteError(
            "input root and output root must be disjoint"
        )
    try:
        output_root.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise SuiteError(f"cannot create output root: {error}") from error
    resolved_output = resolve_real_directory(output_root, "output root")
    if (
        resolved_output == resolved_input
        or resolved_output.is_relative_to(resolved_input)
        or resolved_input.is_relative_to(resolved_output)
    ):
        raise SuiteError(
            "input root and output root must be disjoint"
        )
    try:
        if next(resolved_output.iterdir(), None) is not None:
            raise SuiteError("output root must be empty")
    except OSError as error:
        raise SuiteError(f"cannot inspect output root: {error}") from error
    return resolved_input, resolved_output


def resolve_below_root(
    root: pathlib.Path,
    relative: str,
    field: str,
) -> pathlib.Path:
    candidate = root
    try:
        for part in pathlib.PurePosixPath(relative).parts:
            candidate = candidate / part
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or RAW.is_reparse_point(
                metadata
            ):
                raise SuiteError(
                    f"{field} contains a symlink/reparse component"
                )
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except SuiteError:
        raise
    except (OSError, ValueError) as error:
        raise SuiteError(f"{field} escapes input root") from error
    return resolved


def freeze_input_file(
    root: pathlib.Path,
    artifact: dict[str, str],
    field: str,
    frozen: dict[pathlib.Path, bytes],
) -> pathlib.Path:
    path = resolve_below_root(root, artifact["path"], field)
    try:
        data = RAW.read_stable_manifest(path)
    except (OSError, RAW.VerificationError) as error:
        raise SuiteError(f"cannot read {field}: {error}") from error
    digest = RAW.sha256_bytes(data)
    if digest != artifact["sha256"]:
        raise SuiteError(
            f"{field} SHA-256 mismatch: expected "
            f"{artifact['sha256']}, observed {digest}"
        )
    previous = frozen.get(path)
    if previous is not None and previous != data:
        raise SuiteError(f"{field} changed while freezing suite inputs")
    frozen[path] = data
    return path


def resolve_case_inputs(
    plan_case: dict[str, object],
    input_root: pathlib.Path,
    frozen: dict[pathlib.Path, bytes],
) -> dict[str, object]:
    result = dict(plan_case)
    for name in (
        "comparison_contract",
        "projection_contract",
        "upstream_manifest",
        "rust_manifest",
        "waiver_registry",
    ):
        artifact = plan_case[name]
        assert isinstance(artifact, dict)
        result[name] = freeze_input_file(
            input_root,
            artifact,
            f"case {plan_case['case_id']} {name}",
            frozen,
        )
    policy = plan_case["normalization_policy"]
    if policy is not None:
        assert isinstance(policy, dict)
        result["normalization_policy"] = freeze_input_file(
            input_root,
            policy,
            f"case {plan_case['case_id']} normalization_policy",
            frozen,
        )
    for name in ("upstream_artifact_root", "rust_artifact_root"):
        relative = plan_case[name]
        assert isinstance(relative, str)
        candidate = resolve_below_root(
            input_root,
            relative,
            f"case {plan_case['case_id']} {name}",
        )
        try:
            result[name] = RAW.resolve_artifact_root(candidate)
        except (OSError, RAW.VerificationError) as error:
            raise SuiteError(
                f"invalid case {plan_case['case_id']} {name}: {error}"
            ) from error
    return result


def case_output_paths(
    output_root: pathlib.Path,
    index: int,
    normalized: bool,
) -> dict[str, pathlib.Path | None]:
    root = output_root / "cases" / f"{index:06d}"
    return {
        "upstream_projection": root / "upstream-projection.json",
        "rust_projection": root / "rust-projection.json",
        "comparison": root / "comparison.json",
        "differences": root / "differences.json",
        "waiver_audit": root / "waiver-audit.json",
        "case_audit": root / "case-audit.json",
        "upstream_normalization": (
            root / "upstream-normalization.json" if normalized else None
        ),
        "rust_normalization": (
            root / "rust-normalization.json" if normalized else None
        ),
    }


def empty_result_counts() -> dict[str, int]:
    return {
        "total": 0,
        "pass": 0,
        "fail": 0,
        "infrastructure_error": 0,
    }


def empty_classification_counts() -> dict[str, int]:
    return {
        "Semantic": 0,
        "SafetyDeviation": 0,
        "Unsupported": 0,
    }


def empty_difference_counts() -> dict[str, object]:
    return {
        "total": 0,
        "applied": 0,
        "unmatched": 0,
        "by_classification": empty_classification_counts(),
    }


def empty_summary() -> dict[str, object]:
    return {
        "case_results": empty_result_counts(),
        "comparison_results": {
            "exact": 0,
            "semantic_equal": 0,
            "different": 0,
            "projection_failure": 0,
            "comparison_limit_reached": 0,
            "unavailable": 0,
        },
        "differences": empty_difference_counts(),
        "normalization_applied_cases": 0,
        "waived_cases": 0,
    }


def add_difference_counts(
    target: dict[str, object],
    source: dict[str, object],
) -> None:
    for field in ("total", "applied", "unmatched"):
        target[field] = int(target[field]) + int(source[field])
    target_classes = target["by_classification"]
    source_classes = source["by_classification"]
    assert isinstance(target_classes, dict)
    assert isinstance(source_classes, dict)
    for name in empty_classification_counts():
        target_classes[name] = (
            int(target_classes[name]) + int(source_classes[name])
        )


def result_counts(cases: list[dict[str, object]]) -> dict[str, int]:
    counts = empty_result_counts()
    counts["total"] = len(cases)
    for item in cases:
        result = str(item["result"])
        counts[result] += 1
    return counts


def aggregate_result(cases: list[dict[str, object]]) -> str:
    results = {str(item["result"]) for item in cases}
    if "infrastructure_error" in results:
        return "infrastructure_error"
    if "fail" in results:
        return "fail"
    return "pass"


def build_case_result(
    *,
    index: int,
    plan_case: dict[str, object],
    audit: dict[str, object],
    audit_bytes: bytes,
    difference_value: object | None,
    orchestration_errors: list[str],
) -> dict[str, object]:
    comparison = audit["comparison"]
    comparison_result = None
    raw_equal = None
    normalization_applied = None
    if isinstance(comparison, dict):
        comparison_result = comparison["result"]
        raw_equality = comparison["raw_equality"]
        assert isinstance(raw_equality, dict)
        raw_equal = raw_equality["all"]
        inputs = comparison["inputs"]
        assert isinstance(inputs, dict)
        normalization_applied = any(
            isinstance(inputs[side], dict)
            and isinstance(inputs[side]["normalization"], dict)
            and inputs[side]["normalization"]["kind"] == "applied"
            for side in ("upstream", "rust")
        )

    differences = None
    if isinstance(difference_value, dict) and (
        difference_value.get("report_schema") == 1
    ):
        raw_differences = difference_value.get("differences")
        if isinstance(raw_differences, list):
            classifications = empty_classification_counts()
            for difference in raw_differences:
                if isinstance(difference, dict):
                    classification = difference.get("classification")
                    if classification in classifications:
                        classifications[str(classification)] += 1
            waiver_audit = audit["waiver_audit"]
            applied = []
            unmatched = []
            if isinstance(waiver_audit, dict):
                if isinstance(waiver_audit.get("applied"), list):
                    applied = waiver_audit["applied"]
                if isinstance(
                    waiver_audit.get("unmatched_differences"),
                    list,
                ):
                    unmatched = waiver_audit[
                        "unmatched_differences"
                    ]
            differences = {
                "total": len(raw_differences),
                "applied": len(applied),
                "unmatched": len(unmatched),
                "by_classification": classifications,
            }

    errors = list(audit["errors"])
    errors.extend(orchestration_errors)
    result = str(audit["result"])
    reason = str(audit["reason"])
    if orchestration_errors:
        result = "infrastructure_error"
        reason = "suite_case_identity_mismatch"
    return {
        "index": index,
        "identity": {
            "case_id": plan_case["case_id"],
            "capability": plan_case["capability"],
            "platform": plan_case["platform"],
            "oracle_profile": plan_case["oracle_profile"],
        },
        "result": result,
        "reason": reason,
        "comparison_result": comparison_result,
        "raw_equal": raw_equal,
        "normalization_applied": normalization_applied,
        "differences": differences,
        "audit_path": f"cases/{index:06d}/case-audit.json",
        "audit_artifact": artifact_reference(audit, audit_bytes),
        "errors": errors,
    }


def validate_case_identity(
    audit: dict[str, object],
    plan: dict[str, object],
    plan_case: dict[str, object],
) -> list[str]:
    errors = []
    if audit.get("as_of") != plan["as_of"]:
        errors.append("case audit date does not match suite plan")
    comparison = audit.get("comparison")
    if not isinstance(comparison, dict):
        if audit.get("result") != "infrastructure_error":
            errors.append(
                "non-infrastructure case audit has no comparison"
            )
        return errors
    expected_identity = {
        "platform": plan_case["platform"],
        "oracle_profile": plan_case["oracle_profile"],
        "upstream_commit": plan["upstream_commit"],
        "semantic_schema": plan["semantic_schema"],
    }
    if comparison.get("run_identity") != expected_identity:
        errors.append(
            "comparison run identity does not match suite plan"
        )
    if comparison.get("case_id") != plan_case["case_id"]:
        errors.append("comparison case ID does not match suite plan")
    if audit.get("case_id") != plan_case["case_id"]:
        errors.append("case audit case ID does not match suite plan")
    return errors


def build_summary(
    cases: list[dict[str, object]],
) -> tuple[
    dict[str, object],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    summary = empty_summary()
    summary["case_results"] = result_counts(cases)
    comparison_counts = summary["comparison_results"]
    differences = summary["differences"]
    assert isinstance(comparison_counts, dict)
    assert isinstance(differences, dict)
    for item in cases:
        comparison_result = item["comparison_result"]
        if comparison_result is None:
            comparison_counts["unavailable"] += 1
        else:
            comparison_counts[str(comparison_result)] += 1
        item_differences = item["differences"]
        if isinstance(item_differences, dict):
            add_difference_counts(differences, item_differences)
        if item["normalization_applied"] is True:
            summary["normalization_applied_cases"] += 1
        if item["reason"] == "approved_semantic_differences":
            summary["waived_cases"] += 1

    platform_groups: dict[
        tuple[str, str],
        list[dict[str, object]],
    ] = collections.defaultdict(list)
    capability_groups: dict[str, list[dict[str, object]]] = (
        collections.defaultdict(list)
    )
    for item in cases:
        identity = item["identity"]
        assert isinstance(identity, dict)
        platform_groups[
            (str(identity["platform"]), str(identity["oracle_profile"]))
        ].append(item)
        capability_groups[str(identity["capability"])].append(item)

    platforms = [
        {
            "platform": platform,
            "oracle_profile": profile,
            "case_results": result_counts(items),
        }
        for (platform, profile), items in sorted(platform_groups.items())
    ]
    capabilities = []
    for capability, items in sorted(capability_groups.items()):
        capability_differences = empty_difference_counts()
        for item in items:
            item_differences = item["differences"]
            if isinstance(item_differences, dict):
                add_difference_counts(
                    capability_differences,
                    item_differences,
                )
        capabilities.append(
            {
                "capability": capability,
                "case_results": result_counts(items),
                "differences": capability_differences,
            }
        )
    return summary, platforms, capabilities


def minimal_report(error: str) -> dict[str, object]:
    return {
        "compatibility_report_schema": REPORT_SCHEMA_VERSION,
        "aggregator": RUNNER,
        "suite_id": None,
        "as_of": None,
        "run_identity": None,
        "plan_artifact": None,
        "result": "infrastructure_error",
        "summary": empty_summary(),
        "platforms": [],
        "capabilities": [],
        "cases": [],
        "input_files_unchanged": None,
        "errors": [error],
    }


def write_report(
    output_root: pathlib.Path,
    report: dict[str, object],
) -> None:
    path = output_root / "compatibility-report.json"
    path.write_bytes(serialize_json(report))


def run_suite(
    plan_path: pathlib.Path,
    input_root: pathlib.Path,
    output_root: pathlib.Path,
    repo_root: pathlib.Path,
) -> dict[str, object]:
    resolved_input, resolved_output = prepare_roots(
        input_root,
        output_root,
    )
    try:
        resolved_plan = plan_path.resolve(strict=True)
        resolved_plan.relative_to(resolved_input)
    except (OSError, ValueError) as error:
        report = minimal_report("suite plan must be below input root")
        write_report(resolved_output, report)
        return report

    plan_value: object | None = None
    plan_bytes: bytes | None = None
    try:
        plan_bytes = RAW.read_stable_manifest(resolved_plan)
        plan_value = RAW.load_json_bytes(plan_bytes, "suite plan")
        plan = validate_plan(plan_value)
        frozen = {resolved_plan: plan_bytes}
        raw_cases = plan["cases"]
        assert isinstance(raw_cases, list)
        cases = [
            resolve_case_inputs(item, resolved_input, frozen)
            for item in raw_cases
        ]

        all_outputs = [resolved_output / "compatibility-report.json"]
        all_inputs = list(frozen)
        artifact_roots = []
        output_sets = []
        for index, item in enumerate(cases, start=1):
            normalized = item["normalization_policy"] is not None
            outputs = case_output_paths(
                resolved_output,
                index,
                normalized,
            )
            output_sets.append(outputs)
            all_outputs.extend(
                path
                for path in outputs.values()
                if isinstance(path, pathlib.Path)
            )
            artifact_roots.extend(
                [
                    item["upstream_artifact_root"],
                    item["rust_artifact_root"],
                ]
            )
        case_auditor.comparator.ensure_output_paths(
            all_outputs,
            all_inputs,
            artifact_roots,
        )

        case_results = []
        suite_errors = []
        derived_files: dict[pathlib.Path, bytes] = {}
        for index, (item, outputs) in enumerate(
            zip(cases, output_sets, strict=True),
            start=1,
        ):
            try:
                audit = case_auditor.audit_files(
                    comparison_contract_path=item[
                        "comparison_contract"
                    ],
                    projection_contract_path=item[
                        "projection_contract"
                    ],
                    upstream_manifest_path=item["upstream_manifest"],
                    upstream_artifact_root=item[
                        "upstream_artifact_root"
                    ],
                    rust_manifest_path=item["rust_manifest"],
                    rust_artifact_root=item["rust_artifact_root"],
                    upstream_projection_output=outputs[
                        "upstream_projection"
                    ],
                    rust_projection_output=outputs["rust_projection"],
                    normalization_policy_path=item[
                        "normalization_policy"
                    ],
                    upstream_normalization_output=outputs[
                        "upstream_normalization"
                    ],
                    rust_normalization_output=outputs[
                        "rust_normalization"
                    ],
                    comparison_output=outputs["comparison"],
                    difference_report_output=outputs["differences"],
                    waiver_registry_path=item["waiver_registry"],
                    waiver_audit_output=outputs["waiver_audit"],
                    case_audit_output=outputs["case_audit"],
                    as_of_text=plan["as_of"],
                    max_artifact_bytes=plan["max_artifact_bytes"],
                    repo_root=repo_root,
                )
                audit_path = outputs["case_audit"]
                difference_path = outputs["differences"]
                assert isinstance(audit_path, pathlib.Path)
                assert isinstance(difference_path, pathlib.Path)
                audit_bytes = RAW.read_stable_manifest(audit_path)
                if audit_bytes != case_auditor.serialize_json(audit):
                    raise SuiteError(
                        "case audit output changed after generation"
                    )
                derived_files[audit_path] = audit_bytes
                difference_value = None
                if difference_path.is_file():
                    difference_bytes = RAW.read_stable_manifest(
                        difference_path
                    )
                    comparison = audit.get("comparison")
                    if not isinstance(comparison, dict):
                        raise SuiteError(
                            "case difference output has no comparison"
                        )
                    difference_artifact = comparison.get(
                        "difference_report_artifact"
                    )
                    if not isinstance(difference_artifact, dict) or (
                        difference_artifact.get("sha256")
                        != RAW.sha256_bytes(difference_bytes)
                    ):
                        raise SuiteError(
                            "case difference output hash does not match "
                            "case audit"
                        )
                    derived_files[difference_path] = difference_bytes
                    difference_value = RAW.load_json_bytes(
                        difference_bytes,
                        "case difference report",
                    )
                identity_errors = validate_case_identity(
                    audit,
                    plan,
                    item,
                )
                case_result = build_case_result(
                    index=index,
                    plan_case=item,
                    audit=audit,
                    audit_bytes=audit_bytes,
                    difference_value=difference_value,
                    orchestration_errors=identity_errors,
                )
            except (
                SuiteError,
                OSError,
                RAW.VerificationError,
                case_auditor.comparator.ComparisonError,
            ) as error:
                message = str(error)
                case_result = {
                    "index": index,
                    "identity": {
                        "case_id": item["case_id"],
                        "capability": item["capability"],
                        "platform": item["platform"],
                        "oracle_profile": item["oracle_profile"],
                    },
                    "result": "infrastructure_error",
                    "reason": "suite_case_infrastructure_error",
                    "comparison_result": None,
                    "raw_equal": None,
                    "normalization_applied": None,
                    "differences": None,
                    "audit_path": (
                        f"cases/{index:06d}/case-audit.json"
                    ),
                    "audit_artifact": None,
                    "errors": [message],
                }
            case_results.append(case_result)
            if case_result["result"] == "infrastructure_error":
                errors = case_result["errors"]
                assert isinstance(errors, list)
                detail = "; ".join(str(error) for error in errors)
                suite_errors.append(
                    f"case {index} ({item['case_id']}): "
                    + (detail or str(case_result["reason"]))
                )

        input_files_unchanged = True
        for path, expected in frozen.items():
            try:
                observed = RAW.read_stable_manifest(path)
            except (OSError, RAW.VerificationError) as error:
                input_files_unchanged = False
                suite_errors.append(
                    f"input changed or became unreadable: {path}: {error}"
                )
                continue
            if observed != expected:
                input_files_unchanged = False
                suite_errors.append(
                    f"input changed during suite execution: {path}"
                )

        for path, expected in derived_files.items():
            try:
                observed = RAW.read_stable_manifest(path)
            except (OSError, RAW.VerificationError) as error:
                suite_errors.append(
                    f"derived case artifact changed or became unreadable: "
                    f"{path}: {error}"
                )
                continue
            if observed != expected:
                suite_errors.append(
                    f"derived case artifact changed during aggregation: "
                    f"{path}"
                )

        summary, platforms, capabilities = build_summary(case_results)
        result = aggregate_result(case_results)
        if not input_files_unchanged or suite_errors:
            result = "infrastructure_error"
        report = {
            "compatibility_report_schema": REPORT_SCHEMA_VERSION,
            "aggregator": RUNNER,
            "suite_id": plan["suite_id"],
            "as_of": plan["as_of"],
            "run_identity": {
                "upstream_commit": plan["upstream_commit"],
                "semantic_schema": plan["semantic_schema"],
            },
            "plan_artifact": artifact_reference(
                plan_value,
                plan_bytes,
            ),
            "result": result,
            "summary": summary,
            "platforms": platforms,
            "capabilities": capabilities,
            "cases": case_results,
            "input_files_unchanged": input_files_unchanged,
            "errors": suite_errors,
        }
    except (
        SuiteError,
        OSError,
        RAW.VerificationError,
        WAIVERS.ValidationError,
        case_auditor.comparator.ComparisonError,
    ) as error:
        report = minimal_report(str(error))
        if plan_value is not None and plan_bytes is not None:
            report["plan_artifact"] = artifact_reference(
                plan_value,
                plan_bytes,
            )
    write_report(resolved_output, report)
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a hash-bound typed-legacy compatibility suite and "
            "produce one deterministic aggregate report."
        )
    )
    parser.add_argument("--plan", required=True, type=pathlib.Path)
    parser.add_argument(
        "--input-root",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--output-root",
        required=True,
        type=pathlib.Path,
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
        report = run_suite(
            args.plan,
            args.input_root,
            args.output_root,
            args.repo_root.resolve(),
        )
    except (SuiteError, OSError) as error:
        print(f"compatibility suite error: {error}", file=sys.stderr)
        return 2
    if report["result"] == "infrastructure_error":
        return 2
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

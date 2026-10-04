#!/usr/bin/env python3
"""Create an audited semantic projection using only approved transforms."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import re
import sys
from typing import Any, Callable


INPUT_SCHEMA_VERSION = 1
POLICY_SCHEMA_VERSION = 1
OUTPUT_SCHEMA_VERSION = 1
NORMALIZER_NAME = "die-semantic-normalizer"
NORMALIZER_VERSION = 1

HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
PLATFORM_PATTERN = re.compile(r"^[a-z0-9]+-[a-z0-9][a-z0-9_]*$")
PROFILE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
RULE_ID_PATTERN = re.compile(r"^NORM-[0-9]{4,}$")
QOBJECT_ADDRESS_PATTERN = re.compile(
    r"([A-Za-z_][A-Za-z0-9_:]*)\(0x[0-9a-fA-F]+\)"
)
PROFILING_ELAPSED_PATTERN = re.compile(
    r"^(?P<label>[^\r\n]+): \[(?P<elapsed>[0-9]+) ms\]$"
)


class NormalizationError(ValueError):
    """An input, policy, or transform is not trustworthy."""


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
        raise NormalizationError(
            "semantic values must be finite JSON values"
        ) from error
    return serialized.encode("utf-8")


def reject_constant(value: str) -> object:
    raise NormalizationError(f"non-finite JSON constant is forbidden: {value}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NormalizationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_bytes(data: bytes, field: str) -> object:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise NormalizationError(f"{field} must be UTF-8 JSON") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as error:
        raise NormalizationError(
            f"{field} is invalid JSON at line {error.lineno}, "
            f"column {error.colno}"
        ) from error


def require_object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NormalizationError(f"{field} must be an object")
    return value


def require_list(value: object, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise NormalizationError(f"{field} must be an array")
    return value


def require_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NormalizationError(f"{field} must be a non-empty string")
    return value


def require_positive_int(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
    ):
        raise NormalizationError(f"{field} must be a positive integer")
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
        raise NormalizationError(
            f"{field} is missing fields: {', '.join(missing)}"
        )
    if extra:
        raise NormalizationError(
            f"{field} has unknown fields: {', '.join(extra)}"
        )


def validate_case_id(value: object, field: str) -> str:
    case_id = require_string(value, field)
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise NormalizationError(f"{field} must be one exact case ID")
    return case_id


def validate_identity(value: object, field: str) -> dict[str, object]:
    identity = require_object(value, field)
    require_exact_keys(
        identity,
        {
            "platform",
            "oracle_profile",
            "upstream_commit",
            "semantic_schema",
        },
        set(),
        field,
    )
    platform = require_string(identity["platform"], f"{field}.platform")
    if not PLATFORM_PATTERN.fullmatch(platform):
        raise NormalizationError(
            f"{field}.platform must name one exact OS-architecture pair"
        )
    profile = require_string(
        identity["oracle_profile"],
        f"{field}.oracle_profile",
    )
    if not PROFILE_PATTERN.fullmatch(profile):
        raise NormalizationError(
            f"{field}.oracle_profile must name one exact profile"
        )
    upstream_commit = require_string(
        identity["upstream_commit"],
        f"{field}.upstream_commit",
    )
    if not HEX_40.fullmatch(upstream_commit):
        raise NormalizationError(
            f"{field}.upstream_commit must be a lowercase 40-hex SHA"
        )
    semantic_schema = require_positive_int(
        identity["semantic_schema"],
        f"{field}.semantic_schema",
    )
    return {
        "platform": platform,
        "oracle_profile": profile,
        "upstream_commit": upstream_commit,
        "semantic_schema": semantic_schema,
    }


def validate_reference(
    value: object,
    field: str,
    repo_root: pathlib.Path,
    prefix: str,
) -> str:
    reference = require_string(value, field)
    if "\\" in reference:
        raise NormalizationError(f"{field} must use repository '/' paths")
    relative = pathlib.PurePosixPath(reference)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or not relative.parts
        or not reference.startswith(prefix)
    ):
        raise NormalizationError(
            f"{field} must be a safe repository path under {prefix}"
        )
    resolved = repo_root.joinpath(*relative.parts).resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError as error:
        raise NormalizationError(f"{field} escapes the repository") from error
    if not resolved.is_file():
        raise NormalizationError(f"{field} does not exist: {reference}")
    return reference


def decode_pointer(pointer: str, field: str) -> list[str]:
    if not pointer.startswith("/") or pointer == "/":
        raise NormalizationError(
            f"{field} must be one non-root JSON Pointer"
        )
    tokens: list[str] = []
    for raw_token in pointer[1:].split("/"):
        if not raw_token:
            raise NormalizationError(f"{field} contains an empty token")
        token: list[str] = []
        index = 0
        while index < len(raw_token):
            character = raw_token[index]
            if character != "~":
                token.append(character)
                index += 1
                continue
            if (
                index + 1 >= len(raw_token)
                or raw_token[index + 1] not in {"0", "1"}
            ):
                raise NormalizationError(
                    f"{field} has an invalid JSON Pointer escape"
                )
            token.append("~" if raw_token[index + 1] == "0" else "/")
            index += 2
        decoded = "".join(token)
        if any(character in decoded for character in "*?[]"):
            raise NormalizationError(
                f"{field} must not contain wildcard tokens"
            )
        tokens.append(decoded)
    return tokens


def resolve_pointer(
    document: object,
    pointer: str,
    field: str,
) -> tuple[object, str | int]:
    tokens = decode_pointer(pointer, field)
    current = document
    for index, token in enumerate(tokens):
        last = index == len(tokens) - 1
        if isinstance(current, dict):
            if token not in current:
                raise NormalizationError(
                    f"{field} target does not exist at {token!r}"
                )
            if last:
                return current, token
            current = current[token]
            continue
        if isinstance(current, list):
            if not token.isdigit() or (
                len(token) > 1 and token.startswith("0")
            ):
                raise NormalizationError(
                    f"{field} array token must be a canonical index"
                )
            item_index = int(token)
            if item_index >= len(current):
                raise NormalizationError(
                    f"{field} array index is out of range"
                )
            if last:
                return current, item_index
            current = current[item_index]
            continue
        raise NormalizationError(
            f"{field} traverses a non-container value"
        )
    raise AssertionError("a validated pointer always has a token")


def normalize_qobject_address(value: str) -> tuple[str, int]:
    return QOBJECT_ADDRESS_PATTERN.subn(r"\1(<address>)", value)


def normalize_profiling_elapsed(value: str) -> tuple[str, int]:
    match = PROFILING_ELAPSED_PATTERN.fullmatch(value)
    if match is None:
        return value, 0
    return f"{match.group('label')}: [<elapsed> ms]", 1


TRANSFORMS: dict[str, Callable[[str], tuple[str, int]]] = {
    "qobject_address_v1": normalize_qobject_address,
    "profiling_elapsed_ms_v1": normalize_profiling_elapsed,
}


def validate_input(value: object) -> dict[str, object]:
    projection = require_object(value, "projection")
    require_exact_keys(
        projection,
        {"projection_schema", "run_identity", "case_id", "semantic"},
        set(),
        "projection",
    )
    if projection["projection_schema"] != INPUT_SCHEMA_VERSION:
        raise NormalizationError("unsupported projection_schema")
    semantic = projection["semantic"]
    canonical_json(semantic)
    return {
        "projection_schema": INPUT_SCHEMA_VERSION,
        "run_identity": validate_identity(
            projection["run_identity"],
            "projection.run_identity",
        ),
        "case_id": validate_case_id(
            projection["case_id"],
            "projection.case_id",
        ),
        "semantic": semantic,
    }


def validate_rule(
    value: object,
    index: int,
    repo_root: pathlib.Path,
) -> dict[str, object]:
    field = f"policy.rules[{index}]"
    rule = require_object(value, field)
    require_exact_keys(
        rule,
        {
            "id",
            "json_pointer",
            "transform",
            "expected_replacements",
            "expected_normalized_value",
            "evidence",
            "contract",
        },
        set(),
        field,
    )
    rule_id = require_string(rule["id"], f"{field}.id")
    if not RULE_ID_PATTERN.fullmatch(rule_id):
        raise NormalizationError(
            f"{field}.id must match NORM- followed by at least 4 digits"
        )
    pointer = require_string(
        rule["json_pointer"],
        f"{field}.json_pointer",
    )
    decode_pointer(pointer, f"{field}.json_pointer")
    transform = require_string(rule["transform"], f"{field}.transform")
    if transform not in TRANSFORMS:
        raise NormalizationError(f"{field}.transform is not approved")
    expected_value = rule["expected_normalized_value"]
    if not isinstance(expected_value, str):
        raise NormalizationError(
            f"{field}.expected_normalized_value must be a string"
        )
    return {
        "id": rule_id,
        "json_pointer": pointer,
        "transform": transform,
        "expected_replacements": require_positive_int(
            rule["expected_replacements"],
            f"{field}.expected_replacements",
        ),
        "expected_normalized_value": expected_value,
        "evidence": validate_reference(
            rule["evidence"],
            f"{field}.evidence",
            repo_root,
            "docs/research/",
        ),
        "contract": validate_reference(
            rule["contract"],
            f"{field}.contract",
            repo_root,
            "docs/design/",
        ),
    }


def validate_policy(
    value: object,
    repo_root: pathlib.Path,
) -> dict[str, object]:
    policy = require_object(value, "policy")
    require_exact_keys(
        policy,
        {"policy_schema", "policy_identity", "case_id", "rules"},
        set(),
        "policy",
    )
    if policy["policy_schema"] != POLICY_SCHEMA_VERSION:
        raise NormalizationError("unsupported policy_schema")
    rules = [
        validate_rule(item, index, repo_root)
        for index, item in enumerate(
            require_list(policy["rules"], "policy.rules")
        )
    ]
    if not rules:
        raise NormalizationError("policy.rules must not be empty")
    ids = [rule["id"] for rule in rules]
    if len(ids) != len(set(ids)):
        raise NormalizationError("normalization rule IDs must be unique")
    pointers = [rule["json_pointer"] for rule in rules]
    if len(pointers) != len(set(pointers)):
        raise NormalizationError(
            "each JSON Pointer may have only one normalization rule"
        )
    return {
        "policy_schema": POLICY_SCHEMA_VERSION,
        "policy_identity": validate_identity(
            policy["policy_identity"],
            "policy.policy_identity",
        ),
        "case_id": validate_case_id(
            policy["case_id"],
            "policy.case_id",
        ),
        "rules": rules,
    }


def normalize_projection(
    projection: dict[str, object],
    policy: dict[str, object],
    input_file_sha256: str,
    policy_file_sha256: str,
) -> dict[str, object]:
    if projection["run_identity"] != policy["policy_identity"]:
        raise NormalizationError(
            "policy identity does not match projection identity"
        )
    if projection["case_id"] != policy["case_id"]:
        raise NormalizationError(
            "policy case_id does not match projection case_id"
        )

    semantic = copy.deepcopy(projection["semantic"])
    applied: list[dict[str, object]] = []
    for index, rule in enumerate(policy["rules"]):
        pointer = str(rule["json_pointer"])
        field = f"policy.rules[{index}].json_pointer"
        parent, key = resolve_pointer(semantic, pointer, field)
        original = parent[key]  # type: ignore[index]
        if not isinstance(original, str):
            raise NormalizationError(
                f"{field} must target a string value"
            )
        transform = TRANSFORMS[str(rule["transform"])]
        normalized, replacements = transform(original)
        if replacements != rule["expected_replacements"]:
            raise NormalizationError(
                f"{field} expected {rule['expected_replacements']} "
                f"replacement(s), observed {replacements}"
            )
        if normalized != rule["expected_normalized_value"]:
            raise NormalizationError(
                f"{field} normalized value does not match policy"
            )
        parent[key] = normalized  # type: ignore[index]
        applied.append(
            {
                "id": rule["id"],
                "json_pointer": pointer,
                "transform": rule["transform"],
                "replacements": replacements,
                "input_value_sha256": sha256_bytes(
                    canonical_json(original)
                ),
                "output_value_sha256": sha256_bytes(
                    canonical_json(normalized)
                ),
                "evidence": rule["evidence"],
                "contract": rule["contract"],
            }
        )

    normalized_projection = {
        "projection_schema": INPUT_SCHEMA_VERSION,
        "run_identity": projection["run_identity"],
        "case_id": projection["case_id"],
        "semantic": semantic,
    }
    return {
        "normalization_schema": OUTPUT_SCHEMA_VERSION,
        "normalizer": {
            "name": NORMALIZER_NAME,
            "version": NORMALIZER_VERSION,
        },
        "run_identity": projection["run_identity"],
        "case_id": projection["case_id"],
        "input_artifact": {
            "sha256": input_file_sha256,
            "canonical_projection_sha256": sha256_bytes(
                canonical_json(projection)
            ),
        },
        "policy_artifact": {
            "sha256": policy_file_sha256,
            "canonical_policy_sha256": sha256_bytes(
                canonical_json(policy)
            ),
        },
        "rules_applied": applied,
        "normalized_projection_sha256": sha256_bytes(
            canonical_json(normalized_projection)
        ),
        "semantic": semantic,
    }


def serialize_output(output: dict[str, object]) -> str:
    return (
        json.dumps(
            output,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    )


def normalize_files(
    input_path: pathlib.Path,
    policy_path: pathlib.Path,
    output_path: pathlib.Path,
    repo_root: pathlib.Path,
) -> dict[str, object]:
    resolved_input = input_path.resolve()
    resolved_policy = policy_path.resolve()
    resolved_output = output_path.resolve()
    if resolved_output in {resolved_input, resolved_policy}:
        raise NormalizationError(
            "output must not overwrite the input or policy artifact"
        )
    input_bytes = input_path.read_bytes()
    policy_bytes = policy_path.read_bytes()
    projection = validate_input(load_json_bytes(input_bytes, "input"))
    policy = validate_policy(
        load_json_bytes(policy_bytes, "policy"),
        repo_root.resolve(),
    )
    output = normalize_projection(
        projection,
        policy,
        sha256_bytes(input_bytes),
        sha256_bytes(policy_bytes),
    )
    if input_path.read_bytes() != input_bytes:
        raise NormalizationError("input artifact changed during normalization")
    if policy_path.read_bytes() != policy_bytes:
        raise NormalizationError(
            "policy artifact changed during normalization"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(serialize_output(output).encode("utf-8"))
    return output


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an audited, normalized semantic projection."
    )
    parser.add_argument("--input", required=True, type=pathlib.Path)
    parser.add_argument("--policy", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[2],
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        normalize_files(
            args.input,
            args.policy,
            args.output,
            args.repo_root,
        )
    except (NormalizationError, OSError) as error:
        print(f"normalization error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Collect the five native-Windows Qt5 result-model harnesses."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BASELINE_SCRIPT = ROOT / "tools/upstream/collect_windows_cli_baseline.py"
BUILDER = ROOT / "tools/upstream/build_windows_result_model_harnesses.ps1"
ENGINE_REPORT = (
    ROOT / "docs/research/data/engine-contract-windows-qt5.json"
)
EXPECTED_MAKEFILE_SHA256 = (
    "e6f7710cd32be5050e10234f3282d2512b58d28170d5de14f96c30478ac03725"
)
EXPECTED_MAIN_OBJECT_SHA256 = (
    "ff736a313b4d8d53747a7b113fff5a310c31c4218555ffbf1570537af15dd6be"
)
EXPECTED_DIE_SCRIPT_OBJECT_SHA256 = (
    "f74138c8acbf6a7427c90761c7bfbf7715c3dfda6e1c4def3715d348ac159a19"
)
PROFILES = {
    "metadata": {
        "binary": "die-result-metadata-harness.exe",
        "source": "result_metadata_harness_main.cpp",
        "probe": "probe_result_metadata_harness.py",
        "reference": "result-metadata-engine-qt5.json",
        "case_count": 4,
        "fixture": None,
    },
    "lists": {
        "binary": "die-result-lists-harness.exe",
        "source": "result_lists_harness_main.cpp",
        "probe": "probe_result_lists_harness.py",
        "reference": "result-lists-engine-qt5.json",
        "case_count": 2,
        "fixture": "list",
        "manifest": "result-list-fixture.json",
    },
    "flags": {
        "binary": "die-result-flags-harness.exe",
        "source": "result_flags_harness_main.cpp",
        "probe": "probe_result_flags_harness.py",
        "reference": "result-flags-engine-qt5.json",
        "case_count": 4,
        "fixture": "flag",
        "manifest": "result-flag-fixture.json",
    },
    "ids": {
        "binary": "die-result-ids-harness.exe",
        "source": "result_ids_harness_main.cpp",
        "probe": "probe_result_ids_harness.py",
        "reference": "result-ids-engine-qt5.json",
        "case_count": 1,
        "fixture": "id",
        "manifest": "nested-corpus.json",
    },
    "enums": {
        "binary": "die-result-enums-harness.exe",
        "source": "result_enums_harness_main.cpp",
        "probe": "probe_result_enums_harness.py",
        "reference": "result-enums-engine-qt5.json",
        "case_count": 4,
        "fixture": "enum",
        "manifest": "result-enum-fixture.json",
    },
}


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load helper module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


baseline = load_module(
    "collect_windows_cli_baseline_result_model_helper",
    BASELINE_SCRIPT,
)
HarnessError = baseline.BaselineError
PROBE_MODULES = {
    profile: load_module(
        f"collect_windows_result_model_{profile}_probe",
        ROOT / "tools/upstream" / str(specification["probe"]),
    )
    for profile, specification in PROFILES.items()
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise HarnessError(f"JSON root must be an object: {path}")
    return value, raw


def validate_build_manifest(
    manifest: dict[str, Any],
    binary_dir: Path,
) -> None:
    identity = manifest.get("baseline", {})
    qt = manifest.get("qt", {})
    build = manifest.get("build", {})
    source_hashes = manifest.get("source_hashes", {})
    artifacts = manifest.get("artifacts", {})
    expected_cli = (
        "e8579a6ed0d2536ea14af154bcbeeaaea6967c0c7559a595"
        "fb3fe52206ac635e"
    )
    if (
        manifest.get("schema_version") != 1
        or identity.get("commit") != baseline.UPSTREAM_COMMIT
        or identity.get("rules_commit") != baseline.RULES_COMMIT
        or identity.get("recursive_submodule_count") != 58
        or identity.get("cli_sha256") != expected_cli
        or qt.get("version") != "5.15.2"
        or qt.get("qmake_spec") != "win32-msvc"
        or build.get("system") != "patched-qmake-release-makefile"
        or build.get("tool") != "nmake"
        or build.get("target_architecture") != "amd64"
        or build.get("host_architecture") != "amd64"
        or build.get("original_makefile_sha256")
        != EXPECTED_MAKEFILE_SHA256
        or build.get("original_main_object_sha256")
        != EXPECTED_MAIN_OBJECT_SHA256
        or build.get("original_die_script_object_sha256")
        != EXPECTED_DIE_SCRIPT_OBJECT_SHA256
        or build.get("replaced_object") != "release/main_console.obj"
        or build.get("harness_count") != 5
        or source_hashes.get("builder") != baseline.sha256_file(BUILDER)
    ):
        raise HarnessError("Windows result-model build identity differs")

    harness_hashes = source_hashes.get("harnesses", {})
    if set(harness_hashes) != set(PROFILES) or set(artifacts) != set(
        PROFILES
    ):
        raise HarnessError("Windows result-model artifact inventory differs")
    for profile, specification in PROFILES.items():
        source = ROOT / "tools/upstream" / str(specification["source"])
        binary = binary_dir / str(specification["binary"])
        artifact = artifacts[profile]
        if (
            not binary.is_file()
            or harness_hashes.get(profile) != baseline.sha256_file(source)
            or artifact.get("filename") != binary.name
            or artifact.get("size") != binary.stat().st_size
            or artifact.get("sha256") != baseline.sha256_file(binary)
        ):
            raise HarnessError(
                f"Windows result-{profile} artifact identity differs"
            )


def verify_fixtures(
    fixture_dirs: dict[str, Path],
) -> dict[str, dict[str, Any]]:
    evidence = {}
    for profile in ("lists", "flags", "ids", "enums"):
        specification = PROFILES[profile]
        fixture = fixture_dirs[str(specification["fixture"])]
        manifest_path = (
            ROOT
            / "docs/research/data"
            / str(specification["manifest"])
        )
        if profile == "ids":
            manifest, digest = PROBE_MODULES[profile].verify_corpus(
                fixture,
                manifest_path,
            )
        else:
            manifest, digest = PROBE_MODULES[profile].verify_fixture(
                fixture,
                manifest_path,
            )
        evidence[profile] = {
            "manifest": (
                "docs/research/data/" + str(specification["manifest"])
            ),
            "manifest_sha256": digest,
            "entry_count": len(
                manifest.get("entries", manifest.get("samples", []))
            ),
        }
    return evidence


def replace_fixture_paths(
    value: Any,
    fixture_dir: Path | None,
) -> Any:
    if isinstance(value, dict):
        return {
            key: replace_fixture_paths(item, fixture_dir)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            replace_fixture_paths(item, fixture_dir) for item in value
        ]
    if not isinstance(value, str):
        return value

    if fixture_dir is not None:
        normalized = value.replace("\\", "/")
        prefix = fixture_dir.as_posix().rstrip("/")
        if normalized.casefold() == prefix.casefold():
            return "/fixture"
        marker = prefix + "/"
        if normalized.casefold().startswith(marker.casefold()):
            return "/fixture/" + normalized[len(marker) :]

    collection = "/tmp/die-result-list-collection"
    if value.startswith(collection):
        return value.replace("\\", "/")
    return value


def normalize_nondeterministic(
    profile: str,
    document: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized = copy.deepcopy(document)
    observed: dict[str, Any] = {}
    if profile == "metadata":
        observed["scan_times"] = [
            case["nScanTime"] for case in normalized["cases"]
        ]
        for case in normalized["cases"]:
            case["nScanTime"] = 0
    elif profile == "lists":
        elapsed = [
            record["elapsed_ms"]
            for case in normalized["cases"]
            for record in case["debug_records"]
        ]
        observed["debug_elapsed_ms"] = elapsed
        for case in normalized["cases"]:
            for record in case["debug_records"]:
                record["elapsed_ms"] = 0
    elif profile == "ids":
        uuid_map: dict[str, str] = {}
        observed_values = []
        for record in normalized["records"]:
            for key in ("id", "parent_id"):
                uuid = record[key]["uuid"]
                if not uuid:
                    continue
                if uuid not in uuid_map:
                    uuid_map[uuid] = f"<uuid-{len(uuid_map) + 1}>"
                    observed_values.append(uuid)
                record[key]["uuid"] = uuid_map[uuid]
        observed["uuids"] = observed_values
    return normalized, observed


def observe(
    binary: Path,
    qt_dir: Path,
    working_dir: Path,
    fixture_dir: Path | None,
    timeout_seconds: int,
) -> Any:
    environment = os.environ.copy()
    path_key = next(
        (key for key in environment if key.upper() == "PATH"),
        "PATH",
    )
    environment[path_key] = (
        str(qt_dir / "bin")
        + os.pathsep
        + environment.get(path_key, "")
    )
    arguments = [binary.name]
    if fixture_dir is not None:
        arguments.append(fixture_dir.as_posix())
    process = subprocess.run(
        arguments,
        executable=str(binary),
        cwd=working_dir,
        env=environment,
        check=False,
        capture_output=True,
        timeout=timeout_seconds,
    )
    return baseline.Observation(
        process.returncode,
        process.stdout,
        process.stderr,
    )


def parse_document(stdout: bytes) -> dict[str, Any]:
    try:
        document = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarnessError("Windows result-model stdout is not JSON") from error
    if not isinstance(document, dict):
        raise HarnessError("Windows result-model output is not an object")
    return document


def normalized_document(
    profile: str,
    document: dict[str, Any],
    fixture_dir: Path | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, bool]]:
    path_normalized = replace_fixture_paths(document, fixture_dir)
    relationships = PROBE_MODULES[profile].validate(
        copy.deepcopy(path_normalized)
    )
    normalized, observed = normalize_nondeterministic(
        profile,
        path_normalized,
    )
    return normalized, observed, relationships


def collect_result_records(value: Any) -> list[dict[str, Any]]:
    records = []
    if isinstance(value, dict):
        if {"type", "name", "version", "info", "priority"} <= set(value):
            records.append(value)
        for child in value.values():
            records.extend(collect_result_records(child))
    elif isinstance(value, list):
        for child in value:
            records.extend(collect_result_records(child))
    return records


def result_field_facts(
    lists_document: dict[str, Any],
    engine_report: dict[str, Any],
) -> dict[str, bool]:
    list_records = [
        record
        for case in lists_document["cases"]
        for record in case["records"]
    ]
    engine_records = collect_result_records(engine_report["observation"])
    rule_records = [
        record
        for record in engine_records
        if record.get("signature") and record.get("signature_file")
    ]
    return {
        "nonempty_version_observed": any(
            record["version"] for record in list_records
        ),
        "nonempty_info_observed": any(
            record["info"] for record in list_records
        ),
        "rule_name_and_path_observed": bool(rule_records),
        "rule_priorities_cover_fixed_values": (
            {12, 30, 100}
            <= {record["priority"] for record in rule_records}
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--qt-dir", type=Path, required=True)
    parser.add_argument("--list-fixture", type=Path, required=True)
    parser.add_argument("--id-corpus", type=Path, required=True)
    parser.add_argument("--flag-fixture", type=Path, required=True)
    parser.add_argument("--enum-fixture", type=Path, required=True)
    parser.add_argument("--working-dir", type=Path, required=True)
    parser.add_argument("--build-manifest", type=Path, required=True)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.name != "nt":
        raise HarnessError(
            "native Windows result-model collector requires Windows"
        )
    if args.repetitions < 2 or args.repetitions > 20:
        raise HarnessError("repetitions must be in 2..20")
    if args.timeout_seconds < 1 or args.timeout_seconds > 3600:
        raise HarnessError("timeout-seconds must be in 1..3600")

    source_dir = args.source_dir.resolve(strict=True)
    qt_dir = args.qt_dir.resolve(strict=True)
    binary_dir = args.binary_dir.resolve(strict=True)
    working_dir = args.working_dir.resolve(strict=True)
    raw_dir = args.raw_dir.resolve()
    raw_dir.mkdir(parents=True, exist_ok=True)
    fixture_dirs = {
        "list": args.list_fixture.resolve(strict=True),
        "id": args.id_corpus.resolve(strict=True),
        "flag": args.flag_fixture.resolve(strict=True),
        "enum": args.enum_fixture.resolve(strict=True),
    }

    source_identity = baseline.validate_source(source_dir)
    qt_identity = baseline.validate_qt(qt_dir)
    build_path = args.build_manifest.resolve(strict=True)
    build_manifest, build_raw = read_json(build_path)
    validate_build_manifest(build_manifest, binary_dir)
    fixture_evidence = verify_fixtures(fixture_dirs)
    engine_report, engine_raw = read_json(ENGINE_REPORT)

    reports = {}
    execution_count = 0
    case_observation_count = 0
    for profile, specification in PROFILES.items():
        binary = binary_dir / str(specification["binary"])
        fixture_key = specification["fixture"]
        fixture_dir = (
            fixture_dirs[str(fixture_key)]
            if fixture_key is not None
            else None
        )
        reference_path = (
            ROOT
            / "docs/research/data"
            / str(specification["reference"])
        )
        reference, reference_raw = read_json(reference_path)
        reference_normalized, _, reference_relationships = (
            normalized_document(
                profile,
                reference["harness_output"],
                None,
            )
        )
        if reference_relationships != reference["relationships"]:
            raise HarnessError(
                f"Linux result-{profile} relationships differ"
            )

        runs = []
        normalized_runs = []
        observed_fields = []
        relationship_runs = []
        profile_raw_dir = raw_dir / profile
        profile_raw_dir.mkdir(parents=True, exist_ok=True)
        for index in range(args.repetitions):
            observation = observe(
                binary,
                qt_dir,
                working_dir,
                fixture_dir,
                args.timeout_seconds,
            )
            (profile_raw_dir / f"run-{index + 1}.stdout").write_bytes(
                observation.stdout
            )
            (profile_raw_dir / f"run-{index + 1}.stderr").write_bytes(
                observation.stderr
            )
            if observation.exit_code != 0 or observation.stderr:
                raise HarnessError(
                    f"Windows result-{profile} run {index + 1} failed"
                )
            document = parse_document(observation.stdout)
            normalized, observed, relationships = normalized_document(
                profile,
                document,
                fixture_dir,
            )
            runs.append(observation.summary())
            normalized_runs.append(normalized)
            observed_fields.append(observed)
            relationship_runs.append(relationships)

        normalized_equal = all(
            item == normalized_runs[0] for item in normalized_runs[1:]
        )
        relationships_equal = all(
            item == reference_relationships for item in relationship_runs
        )
        linux_equal = normalized_runs[0] == reference_normalized
        if not normalized_equal or not relationships_equal or not linux_equal:
            raise HarnessError(
                f"Windows result-{profile} semantic comparison differs"
            )
        raw_equal = (
            len({run["stdout_sha256"] for run in runs}) == 1
            and len({run["stderr_sha256"] for run in runs}) == 1
        )
        reports[profile] = {
            "binary": {
                "filename": binary.name,
                "size": binary.stat().st_size,
                "sha256": baseline.sha256_file(binary),
            },
            "fixture": fixture_evidence.get(profile),
            "linux_qt5_reference": {
                "path": (
                    "docs/research/data/" + str(specification["reference"])
                ),
                "sha256": sha256_bytes(reference_raw),
            },
            "case_count": specification["case_count"],
            "repetitions": args.repetitions,
            "execution_count": args.repetitions,
            "case_observation_count": (
                int(specification["case_count"]) * args.repetitions
            ),
            "runs": runs,
            "raw_outputs_equal": raw_equal,
            "normalized_outputs_equal": normalized_equal,
            "observed_nondeterministic_fields": observed_fields,
            "relationships": reference_relationships,
            "relationships_equal": relationships_equal,
            "harness_output": normalized_runs[0],
            "linux_qt5_semantic_document_equal": linux_equal,
        }
        execution_count += args.repetitions
        case_observation_count += (
            int(specification["case_count"]) * args.repetitions
        )

    field_facts = result_field_facts(
        reports["lists"]["harness_output"],
        engine_report,
    )
    if not all(field_facts.values()):
        raise HarnessError("Windows result field facts differ")

    report = {
        "schema_version": 1,
        "generator": (
            "tools/upstream/collect_windows_result_model_harnesses.py"
        ),
        "generator_sha256": baseline.sha256_file(Path(__file__)),
        "platform": "windows-x86_64-qt5",
        "capability_scope": [
            "CAP-RESULT-001",
            "CAP-RESULT-002",
            "CAP-RESULT-003",
            "CAP-RESULT-004",
            "CAP-RESULT-005",
            "CAP-RESULT-006",
        ],
        "host": {
            "os_build": platform.version(),
            "architecture": platform.machine(),
        },
        "source": source_identity,
        "qt": qt_identity,
        "build_manifest": {
            "sha256": sha256_bytes(build_raw),
            "identity": build_manifest,
        },
        "repetitions": args.repetitions,
        "execution_count": execution_count,
        "case_observation_count": case_observation_count,
        "reports": reports,
        "record_metadata_evidence": {
            "engine_contract": {
                "path": (
                    "docs/research/data/"
                    "engine-contract-windows-qt5.json"
                ),
                "sha256": sha256_bytes(engine_raw),
            },
            "facts": field_facts,
        },
        "normalization": {
            "operations": [
                (
                    "replace only each verified fixture-root prefix in "
                    "structured strings with /fixture"
                ),
                (
                    "convert separators only inside replaced fixture "
                    "paths and the fixed collection destination"
                ),
                (
                    "set scan time and debug elapsed milliseconds to zero "
                    "after retaining each observed value"
                ),
                (
                    "map nonempty UUIDs by first occurrence while "
                    "preserving equality links and retaining raw values"
                ),
            ],
            "not_performed": [
                "case or record removal/reordering",
                "error text rewriting",
                "type/name/flag/enum/value rewriting",
                "raw stdout/stderr hash rewriting",
            ],
        },
        "raw_artifacts": {
            "storage": (
                "untracked external directory selected by --raw-dir"
            ),
            "profile_count": len(PROFILES),
        },
        "failures": [],
        "passed": True,
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

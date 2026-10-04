#!/usr/bin/env python3
"""Collect native-Windows Qt5 legacy and archive dispatch behavior."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_DIR = ROOT / "tools/upstream"
DATA_DIR = ROOT / "docs/research/data"
BUILDER = UPSTREAM_DIR / "build_windows_dispatch_harnesses.ps1"
EXPECTED_CLI_SHA256 = (
    "e8579a6ed0d2536ea14af154bcbeeaaea6967c0c7559a595"
    "fb3fe52206ac635e"
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
    "bw": {
        "binary": "die-bw-dispatch-harness.exe",
        "source": "bw_dispatch_harness_main.cpp",
        "reference": "bw-dispatch-engine-qt5.json",
        "fixture": None,
        "case_count": 2,
    },
    "npm": {
        "binary": "die-npm-dispatch-harness.exe",
        "source": "npm_dispatch_harness_main.cpp",
        "reference": "npm-dispatch-engine-qt5.json",
        "fixture": "npm",
        "case_count": 4,
    },
    "generic_archive": {
        "binary": "die-generic-archive-dispatch-harness.exe",
        "source": "generic_archive_dispatch_harness_main.cpp",
        "reference": "generic-archive-dispatch-engine-qt5.json",
        "fixture": "generic",
        "case_count": 3,
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
    "collect_windows_dispatch_baseline",
    UPSTREAM_DIR / "collect_windows_cli_baseline.py",
)
dos_probe = load_module(
    "collect_windows_dispatch_dos",
    UPSTREAM_DIR / "probe_dos_dispatch.py",
)
legacy_probe = load_module(
    "collect_windows_dispatch_legacy",
    UPSTREAM_DIR / "probe_legacy_dispatch.py",
)
bw_probe = load_module(
    "collect_windows_dispatch_bw",
    UPSTREAM_DIR / "probe_bw_dispatch_harness.py",
)
npm_probe = load_module(
    "collect_windows_dispatch_npm",
    UPSTREAM_DIR / "probe_npm_dispatch_harness.py",
)
generic_probe = load_module(
    "collect_windows_dispatch_generic",
    UPSTREAM_DIR / "probe_generic_archive_dispatch_harness.py",
)
HarnessError = baseline.BaselineError


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarnessError(f"invalid JSON: {path}") from error
    if not isinstance(value, dict):
        raise HarnessError(f"JSON root must be an object: {path}")
    return value, raw


def validate_binary(binary: Path, source_dir: Path) -> dict[str, Any]:
    expected = (source_dir / "build/release/diec.exe").resolve(strict=True)
    if binary != expected:
        raise HarnessError("binary must be <source>/build/release/diec.exe")
    digest = baseline.sha256_file(binary)
    if digest != EXPECTED_CLI_SHA256:
        raise HarnessError("fixed Windows CLI SHA-256 differs")
    return {
        "filename": binary.name,
        "size": binary.stat().st_size,
        "sha256": digest,
    }


def expected_adapted_source(
    source: Path,
    replacements: list[dict[str, Any]],
) -> str:
    text = source.read_text(encoding="utf-8")
    for replacement in replacements:
        if (
            set(replacement) != {"from", "to", "count"}
            or replacement["count"] != 1
            or text.count(replacement["from"]) != 1
        ):
            raise HarnessError("invalid database-path adaptation record")
        text = text.replace(replacement["from"], replacement["to"])
    return sha256_bytes(text.encode("utf-8"))


def validate_build_manifest(
    manifest: dict[str, Any],
    binary_dir: Path,
    source_dir: Path,
) -> None:
    identity = manifest.get("baseline", {})
    qt = manifest.get("qt", {})
    build = manifest.get("build", {})
    sources = manifest.get("source_hashes", {})
    artifacts = manifest.get("artifacts", {})
    database_root = "Detect-It-Easy"
    if (
        manifest.get("schema_version") != 1
        or identity.get("commit") != baseline.UPSTREAM_COMMIT
        or identity.get("rules_commit") != baseline.RULES_COMMIT
        or identity.get("recursive_submodule_count") != 58
        or identity.get("cli_sha256") != EXPECTED_CLI_SHA256
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
        or build.get("harness_count") != 3
        or build.get("database_root")
        != "<working-directory>/Detect-It-Easy"
        or build.get("runtime_working_directory_contract")
        != "verified-source-root"
        or build.get("engine_objects_modified") is not False
        or sources.get("builder") != baseline.sha256_file(BUILDER)
        or set(sources.get("harnesses", {})) != set(PROFILES)
        or set(artifacts) != set(PROFILES)
    ):
        raise HarnessError("Windows dispatch build identity differs")

    for name, specification in PROFILES.items():
        source = UPSTREAM_DIR / str(specification["source"])
        binary = binary_dir / str(specification["binary"])
        source_record = sources["harnesses"][name]
        artifact = artifacts[name]
        replacements = source_record.get("database_path_replacements")
        expected_replacement_count = 0 if name == "bw" else 3
        if (
            source_record.get("path")
            != "tools/upstream/" + str(specification["source"])
            or source_record.get("original_sha256")
            != baseline.sha256_file(source)
            or not isinstance(replacements, list)
            or len(replacements) != expected_replacement_count
            or source_record.get("adapted_sha256")
            != expected_adapted_source(source, replacements)
            or not binary.is_file()
            or artifact.get("filename") != binary.name
            or artifact.get("size") != binary.stat().st_size
            or artifact.get("sha256") != baseline.sha256_file(binary)
        ):
            raise HarnessError(f"Windows {name} harness identity differs")
        for replacement in replacements:
            if (
                not replacement["from"].startswith(
                    "/opt/die-source/Detect-It-Easy/db"
                )
                or not replacement["to"].startswith(database_root + "/db")
            ):
                raise HarnessError("database adaptation escaped fixed roots")


def observe(
    binary: Path,
    qt_dir: Path,
    working_dir: Path,
    arguments: Sequence[str],
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
    process = subprocess.run(
        [binary.name, *arguments],
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


def raw_summary(
    observation: Any,
    stdout_path: Path,
    stderr_path: Path,
    report_stdout: str,
    report_stderr: str,
) -> dict[str, Any]:
    stdout_path.write_bytes(observation.stdout)
    stderr_path.write_bytes(observation.stderr)
    return {
        **observation.summary(),
        "raw_stdout": report_stdout,
        "raw_stderr": report_stderr,
    }


def validate_linux_cli_reference(
    report: dict[str, Any],
    *,
    capability: str,
    manifest_sha256: str,
    expected_cases: set[str],
) -> None:
    if (
        report.get("schema_version") != 1
        or report.get("result") != "pass"
        or report.get("upstream_commit") != baseline.UPSTREAM_COMMIT
        or report.get("rules_commit") != baseline.RULES_COMMIT
        or report.get("platform") != "linux-amd64-qt5"
        or report.get("capability") != capability
        or report.get("corpus_manifest", {}).get("sha256")
        != manifest_sha256
        or report.get("failures") != []
        or set(report.get("cases", {})) != expected_cases
    ):
        raise HarnessError(f"Linux {capability} CLI reference differs")


def collect_cli_suite(
    *,
    name: str,
    samples: list[dict[str, Any]],
    fixture_dir: Path,
    binary: Path,
    qt_dir: Path,
    working_dir: Path,
    source_dir: Path,
    raw_dir: Path,
    repetitions: int,
    timeout_seconds: int,
    linux_report: dict[str, Any],
    include_info: bool,
) -> tuple[dict[str, Any], int, int]:
    database_arguments = (
        "--database",
        (source_dir / "Detect-It-Easy/db").as_posix(),
        "--extradatabase",
        (source_dir / "Detect-It-Easy/db_extra").as_posix(),
        "--customdatabase",
        (source_dir / "Detect-It-Easy/db_custom").as_posix(),
    )
    suite_raw = raw_dir / name
    suite_raw.mkdir(parents=True, exist_ok=True)
    cases = {}
    execution_count = 0
    observation_count = 0
    for sample in samples:
        sample_name = str(sample["name"])
        actual_path = (fixture_dir / sample_name).resolve(strict=True)
        scan_arguments = (
            "--json",
            *database_arguments,
            actual_path.as_posix(),
        )
        info_arguments = ("--info", "--json", actual_path.as_posix())
        reference = linux_report["cases"][sample_name]["oracles"][
            "linux-qt5-cmake"
        ]
        expected_tree = (
            reference["scan"]["detect_tree"]
            if include_info
            else reference["detect_tree"]
        )
        expected_info = (
            reference["detector_info"]["filetype"]
            if include_info
            else None
        )
        runs = []
        semantic_runs = []
        for index in range(repetitions):
            run_number = index + 1
            scan = observe(
                binary,
                qt_dir,
                working_dir,
                scan_arguments,
                timeout_seconds,
            )
            scan_stdout = f"{name}/{sample_name}.run-{run_number}.scan.stdout"
            scan_stderr = f"{name}/{sample_name}.run-{run_number}.scan.stderr"
            scan_record = raw_summary(
                scan,
                raw_dir / scan_stdout,
                raw_dir / scan_stderr,
                scan_stdout,
                scan_stderr,
            )
            tree = baseline.json_detect_tree(scan.stdout)
            if scan.exit_code != 0 or scan.stderr or tree is None:
                raise HarnessError(f"{name} scan failed: {sample_name}")
            failures = legacy_probe.expectation_failures(
                f"{name}.{sample_name}",
                tree,
                sample["expected_dispatch"],
            )
            if failures:
                raise HarnessError(f"{name} expectation failed: {failures}")
            run = {
                "scan": scan_record,
                "detect_tree": tree,
            }
            semantic: dict[str, Any] = {"detect_tree": tree}
            execution_count += 1
            if include_info:
                info = observe(
                    binary,
                    qt_dir,
                    working_dir,
                    info_arguments,
                    timeout_seconds,
                )
                info_stdout = (
                    f"{name}/{sample_name}.run-{run_number}.info.stdout"
                )
                info_stderr = (
                    f"{name}/{sample_name}.run-{run_number}.info.stderr"
                )
                info_record = raw_summary(
                    info,
                    raw_dir / info_stdout,
                    raw_dir / info_stderr,
                    info_stdout,
                    info_stderr,
                )
                filetype = legacy_probe.info_filetype(info.stdout)
                if (
                    info.exit_code != 0
                    or info.stderr
                    or filetype
                    != sample["expected_dispatch"]["info_filetype"]
                ):
                    raise HarnessError(
                        f"{name} detector info failed: {sample_name}"
                    )
                run["detector_info"] = {
                    **info_record,
                    "filetype": filetype,
                }
                semantic["info_filetype"] = filetype
                execution_count += 1
            runs.append(run)
            semantic_runs.append(semantic)
            observation_count += 1

        semantic_equal = all(
            item == semantic_runs[0] for item in semantic_runs[1:]
        )
        linux_equal = (
            semantic_runs[0]["detect_tree"] == expected_tree
            and (
                not include_info
                or semantic_runs[0]["info_filetype"] == expected_info
            )
        )
        raw_equal = all(
            run["scan"]["stdout_sha256"]
            == runs[0]["scan"]["stdout_sha256"]
            and run["scan"]["stderr_sha256"]
            == runs[0]["scan"]["stderr_sha256"]
            and (
                not include_info
                or (
                    run["detector_info"]["stdout_sha256"]
                    == runs[0]["detector_info"]["stdout_sha256"]
                    and run["detector_info"]["stderr_sha256"]
                    == runs[0]["detector_info"]["stderr_sha256"]
                )
            )
            for run in runs[1:]
        )
        if not semantic_equal or not linux_equal:
            raise HarnessError(
                f"{name} semantic comparison differs: {sample_name}"
            )
        cases[sample_name] = {
            "case_kind": sample["case_kind"],
            "target_filetype": sample["target_filetype"],
            "size": sample["size"],
            "sha256": sample["sha256"],
            "expected_dispatch": sample["expected_dispatch"],
            "repetitions": repetitions,
            "runs": runs,
            "raw_outputs_equal": raw_equal,
            "semantic_outputs_equal": semantic_equal,
            "linux_qt5_semantic_projection_equal": linux_equal,
            "semantic_projection": semantic_runs[0],
        }
    return {
        "case_count": len(samples),
        "repetitions": repetitions,
        "execution_count": execution_count,
        "case_observation_count": observation_count,
        "cases": cases,
        "all_semantic_outputs_equal": all(
            case["semantic_outputs_equal"] for case in cases.values()
        ),
        "all_linux_qt5_semantic_projections_equal": all(
            case["linux_qt5_semantic_projection_equal"]
            for case in cases.values()
        ),
    }, execution_count, observation_count


def parse_harness_document(stdout: bytes, profile: str) -> dict[str, Any]:
    try:
        document = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarnessError(f"{profile} harness stdout is not JSON") from error
    if not isinstance(document, dict):
        raise HarnessError(f"{profile} harness output is not an object")
    return document


def collect_harnesses(
    *,
    binary_dir: Path,
    qt_dir: Path,
    working_dir: Path,
    fixture_dirs: dict[str, Path],
    raw_dir: Path,
    repetitions: int,
    timeout_seconds: int,
) -> tuple[dict[str, Any], int, int]:
    modules = {
        "bw": bw_probe,
        "npm": npm_probe,
        "generic_archive": generic_probe,
    }
    manifests: dict[str, tuple[dict[str, Any], str]] = {
        "npm": npm_probe.load_fixture(
            fixture_dirs["npm"],
            DATA_DIR / "npm-dispatch-fixture.json",
        ),
        "generic_archive": generic_probe.load_fixture(
            fixture_dirs["generic"],
            DATA_DIR / "generic-archive-dispatch-fixture.json",
        ),
    }
    sample_maps = {
        name: {sample["name"]: sample for sample in manifest[0]["samples"]}
        for name, manifest in manifests.items()
    }
    reports = {}
    execution_count = 0
    observation_count = 0
    for profile, specification in PROFILES.items():
        binary = binary_dir / str(specification["binary"])
        reference_path = DATA_DIR / str(specification["reference"])
        reference, reference_raw = read_json(reference_path)
        expected_documents = (
            {"bw": reference["harness_output"]}
            if profile == "bw"
            else {
                case: value["harness"]["output"]
                for case, value in reference["cases"].items()
            }
        )
        case_names = (
            ["bw"]
            if profile == "bw"
            else list(sample_maps[profile])
        )
        profile_raw = raw_dir / profile
        profile_raw.mkdir(parents=True, exist_ok=True)
        cases = {}
        for case_name in case_names:
            arguments: tuple[str, ...] = ()
            if profile != "bw":
                arguments = (
                    (
                        fixture_dirs[
                            str(specification["fixture"])
                        ]
                        / case_name
                    )
                    .resolve(strict=True)
                    .as_posix(),
                )
            runs = []
            documents = []
            relationships = None
            for index in range(repetitions):
                observation = observe(
                    binary,
                    qt_dir,
                    working_dir,
                    arguments,
                    timeout_seconds,
                )
                stdout_name = (
                    f"{profile}/{case_name}.run-{index + 1}.stdout"
                )
                stderr_name = (
                    f"{profile}/{case_name}.run-{index + 1}.stderr"
                )
                run = raw_summary(
                    observation,
                    raw_dir / stdout_name,
                    raw_dir / stderr_name,
                    stdout_name,
                    stderr_name,
                )
                if observation.exit_code != 0 or observation.stderr:
                    raise HarnessError(
                        f"{profile} harness failed: {case_name}"
                    )
                document = parse_harness_document(
                    observation.stdout,
                    profile,
                )
                if profile == "bw":
                    current_relationships = modules[profile].validate(
                        document
                    )
                    if relationships is None:
                        relationships = current_relationships
                    elif relationships != current_relationships:
                        raise HarnessError("BW relationships are unstable")
                else:
                    modules[profile].validate_harness(
                        document,
                        sample_maps[profile][case_name],
                    )
                runs.append(run)
                documents.append(document)
                execution_count += 1
                observation_count += int(specification["case_count"]) if (
                    profile == "bw"
                ) else 1
            document_equal = all(
                document == documents[0] for document in documents[1:]
            )
            linux_equal = documents[0] == expected_documents[case_name]
            raw_equal = all(
                run["stdout_sha256"] == runs[0]["stdout_sha256"]
                and run["stderr_sha256"] == runs[0]["stderr_sha256"]
                for run in runs[1:]
            )
            if not document_equal or not linux_equal:
                raise HarnessError(
                    f"{profile} semantic document differs: {case_name}"
                )
            cases[case_name] = {
                "repetitions": repetitions,
                "runs": runs,
                "raw_outputs_equal": raw_equal,
                "semantic_documents_equal": document_equal,
                "linux_qt5_full_document_equal": linux_equal,
                "harness_output": documents[0],
            }
            if relationships is not None:
                cases[case_name]["relationships"] = relationships

        reports[profile] = {
            "binary": {
                "filename": binary.name,
                "size": binary.stat().st_size,
                "sha256": baseline.sha256_file(binary),
            },
            "fixture": (
                None
                if profile == "bw"
                else {
                    "path": (
                        "docs/research/data/"
                        + (
                            "npm-dispatch-fixture.json"
                            if profile == "npm"
                            else "generic-archive-dispatch-fixture.json"
                        )
                    ),
                    "sha256": manifests[profile][1],
                    "sample_count": len(sample_maps[profile]),
                }
            ),
            "linux_qt5_reference": {
                "path": (
                    "docs/research/data/"
                    + str(specification["reference"])
                ),
                "sha256": sha256_bytes(reference_raw),
            },
            "input_case_count": len(case_names),
            "semantic_case_count_per_execution": specification["case_count"],
            "repetitions": repetitions,
            "execution_count": len(case_names) * repetitions,
            "case_observation_count": (
                int(specification["case_count"]) * repetitions
                if profile == "bw"
                else len(case_names) * repetitions
            ),
            "cases": cases,
            "all_full_documents_equal_linux_qt5": all(
                case["linux_qt5_full_document_equal"]
                for case in cases.values()
            ),
        }
    return reports, execution_count, observation_count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--qt-dir", type=Path, required=True)
    parser.add_argument("--dos-fixture", type=Path, required=True)
    parser.add_argument("--legacy-fixture", type=Path, required=True)
    parser.add_argument("--npm-fixture", type=Path, required=True)
    parser.add_argument("--generic-fixture", type=Path, required=True)
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
        raise HarnessError("native Windows dispatch collector requires Windows")
    if args.repetitions < 2 or args.repetitions > 20:
        raise HarnessError("repetitions must be in 2..20")
    if args.timeout_seconds < 1 or args.timeout_seconds > 3600:
        raise HarnessError("timeout-seconds must be in 1..3600")

    source_dir = args.source_dir.resolve(strict=True)
    qt_dir = args.qt_dir.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    binary_dir = args.binary_dir.resolve(strict=True)
    working_dir = args.working_dir.resolve(strict=True)
    fixture_dirs = {
        "dos": args.dos_fixture.resolve(strict=True),
        "legacy": args.legacy_fixture.resolve(strict=True),
        "npm": args.npm_fixture.resolve(strict=True),
        "generic": args.generic_fixture.resolve(strict=True),
    }
    raw_dir = args.raw_dir.resolve()
    raw_dir.mkdir(parents=True, exist_ok=True)

    source_identity = baseline.validate_source(source_dir)
    qt_identity = baseline.validate_qt(qt_dir)
    binary_identity = validate_binary(binary, source_dir)
    build_manifest, build_raw = read_json(
        args.build_manifest.resolve(strict=True)
    )
    validate_build_manifest(build_manifest, binary_dir, source_dir)

    dos_manifest, dos_samples, dos_manifest_raw = dos_probe.load_fixture(
        ROOT,
        fixture_dirs["dos"],
    )
    legacy_manifest, legacy_samples, legacy_manifest_raw = (
        legacy_probe.load_fixture(ROOT, fixture_dirs["legacy"])
    )
    dos_reference_path = DATA_DIR / "dos-dispatch-linux-qt5.json"
    legacy_reference_path = DATA_DIR / "legacy-dispatch-linux-qt5.json"
    dos_reference, dos_reference_raw = read_json(dos_reference_path)
    legacy_reference, legacy_reference_raw = read_json(legacy_reference_path)
    validate_linux_cli_reference(
        dos_reference,
        capability="CAP-DISPATCH-002",
        manifest_sha256=sha256_bytes(dos_manifest_raw),
        expected_cases={str(sample["name"]) for sample in dos_samples},
    )
    validate_linux_cli_reference(
        legacy_reference,
        capability="CAP-DISPATCH-003",
        manifest_sha256=sha256_bytes(legacy_manifest_raw),
        expected_cases={str(sample["name"]) for sample in legacy_samples},
    )

    dos_report, dos_executions, dos_observations = collect_cli_suite(
        name="dos",
        samples=dos_samples,
        fixture_dir=fixture_dirs["dos"],
        binary=binary,
        qt_dir=qt_dir,
        working_dir=working_dir,
        source_dir=source_dir,
        raw_dir=raw_dir,
        repetitions=args.repetitions,
        timeout_seconds=args.timeout_seconds,
        linux_report=dos_reference,
        include_info=False,
    )
    legacy_report, legacy_executions, legacy_observations = (
        collect_cli_suite(
            name="legacy",
            samples=legacy_samples,
            fixture_dir=fixture_dirs["legacy"],
            binary=binary,
            qt_dir=qt_dir,
            working_dir=working_dir,
            source_dir=source_dir,
            raw_dir=raw_dir,
            repetitions=args.repetitions,
            timeout_seconds=args.timeout_seconds,
            linux_report=legacy_reference,
            include_info=True,
        )
    )
    harness_reports, harness_executions, harness_observations = (
        collect_harnesses(
            binary_dir=binary_dir,
            qt_dir=qt_dir,
            working_dir=source_dir,
            fixture_dirs=fixture_dirs,
            raw_dir=raw_dir,
            repetitions=args.repetitions,
            timeout_seconds=args.timeout_seconds,
        )
    )
    execution_count = (
        dos_executions + legacy_executions + harness_executions
    )
    observation_count = (
        dos_observations + legacy_observations + harness_observations
    )
    relationships = {
        "dos_public_dispatch_matches_linux_qt5": (
            dos_report["all_linux_qt5_semantic_projections_equal"]
        ),
        "bw_property_only_dispatch_matches_linux_qt5": (
            harness_reports["bw"]["all_full_documents_equal_linux_qt5"]
        ),
        "amiga_and_atari_dispatch_matches_linux_qt5": (
            legacy_report["all_linux_qt5_semantic_projections_equal"]
        ),
        "npm_property_dispatch_matches_linux_qt5": (
            harness_reports["npm"]["all_full_documents_equal_linux_qt5"]
        ),
        "generic_archive_property_dispatch_matches_linux_qt5": (
            harness_reports["generic_archive"][
                "all_full_documents_equal_linux_qt5"
            ]
        ),
        "all_repetitions_are_semantically_stable": (
            dos_report["all_semantic_outputs_equal"]
            and legacy_report["all_semantic_outputs_equal"]
            and all(
                all(
                    case["semantic_documents_equal"]
                    for case in report["cases"].values()
                )
                for report in harness_reports.values()
            )
        ),
        "all_harness_documents_are_full_document_equal": all(
            report["all_full_documents_equal_linux_qt5"]
            for report in harness_reports.values()
        ),
        "all_raw_outputs_are_retained_externally": True,
        "engine_objects_are_unmodified": (
            build_manifest["build"]["engine_objects_modified"] is False
        ),
    }
    if not all(relationships.values()):
        raise HarnessError("derived Windows dispatch relationships failed")

    report = {
        "schema_version": 1,
        "generator": "tools/upstream/collect_windows_dispatch.py",
        "generator_sha256": baseline.sha256_file(Path(__file__)),
        "platform": "windows-x86_64-qt5",
        "capability_scope": [
            "CAP-DISPATCH-002",
            "CAP-DISPATCH-003",
            "CAP-DISPATCH-004",
        ],
        "host": {
            "os_build": platform.version(),
            "architecture": platform.machine(),
        },
        "source": source_identity,
        "qt": qt_identity,
        "cli": binary_identity,
        "build_manifest": {
            "sha256": sha256_bytes(build_raw),
            "identity": build_manifest,
        },
        "repetitions": args.repetitions,
        "execution_count": execution_count,
        "case_observation_count": observation_count,
        "public_cli": {
            "dos": {
                **dos_report,
                "fixture": {
                    "path": "docs/research/data/dos-dispatch-corpus.json",
                    "sha256": sha256_bytes(dos_manifest_raw),
                    "sample_count": len(dos_manifest["samples"]),
                },
                "linux_qt5_reference": {
                    "path": (
                        "docs/research/data/dos-dispatch-linux-qt5.json"
                    ),
                    "sha256": sha256_bytes(dos_reference_raw),
                },
            },
            "legacy": {
                **legacy_report,
                "fixture": {
                    "path": (
                        "docs/research/data/legacy-dispatch-corpus.json"
                    ),
                    "sha256": sha256_bytes(legacy_manifest_raw),
                    "sample_count": len(legacy_manifest["samples"]),
                },
                "linux_qt5_reference": {
                    "path": (
                        "docs/research/data/"
                        "legacy-dispatch-linux-qt5.json"
                    ),
                    "sha256": sha256_bytes(legacy_reference_raw),
                },
            },
        },
        "private_harnesses": harness_reports,
        "relationships": relationships,
        "normalization": {
            "public_cli": (
                "parse JSON into the existing detect-tree projection; "
                "parse detector --info File type; retain raw streams"
            ),
            "private_harnesses": (
                "none: compare the complete parsed JSON document"
            ),
            "build_manifest": (
                "none: the build uses fixed relative Detect-It-Easy/db* "
                "strings and executes harnesses from the verified source root"
            ),
            "not_performed": [
                "case, record, or field removal/reordering",
                "filetype, detection, rule, or error text rewriting",
                "raw stdout/stderr hash rewriting",
            ],
        },
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir",
            "stdout_and_stderr_retained_for_every_execution": True,
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

import errno
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / "tools/upstream/build_macos_qt5_oracle.sh"
VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_qt5_oracle_report.py"
)
PLAN_SCRIPT = ROOT / "tools/research/build_macos_qt5_oracle_plan.py"
PLAN_PATH = ROOT / "docs/research/data/macos-qt5-oracle-plan.json"
WORKFLOW_PATH = (
    ROOT / ".github/workflows/macos-qt5-oracle-candidate.yml"
)
CLI_COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_baseline.py"
)
CLI_VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_baseline.py"
)
MATRIX_COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_matrix.py"
)
MATRIX_VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_matrix.py"
)
REMAINING_COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_remaining.py"
)
REMAINING_VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_remaining.py"
)
DATABASE_COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_database.py"
)
DATABASE_VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_database.py"
)
PATH_NESTED_COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_path_nested.py"
)
PATH_NESTED_VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_path_nested.py"
)
DATABASE_ARCHIVE_COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_database_archives.py"
)
DATABASE_ARCHIVE_VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_database_archives.py"
)
SPECIAL_PATH_COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_special_paths.py"
)
SPECIAL_PATH_VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_special_paths.py"
)
FILESYSTEM_COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_filesystem.py"
)
FILESYSTEM_VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_filesystem.py"
)
LARGE_DIRECTORY_COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_large_directory.py"
)
LARGE_DIRECTORY_VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_large_directory.py"
)
LONG_PATH_FIXTURE_GENERATOR_PATH = (
    ROOT / "tools/corpus/generate_macos_long_path_fixture.py"
)
LONG_PATH_FIXTURE_VALIDATOR_PATH = (
    ROOT / "tools/corpus/validate_macos_long_path_fixture.py"
)
LONG_PATH_COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_long_paths.py"
)
LONG_PATH_VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_long_paths.py"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VALIDATOR = load_module("validate_macos_qt5_oracle_report", VALIDATOR_PATH)
PLAN = load_module("build_macos_qt5_oracle_plan", PLAN_SCRIPT)
CLI_COLLECTOR = load_module(
    "collect_macos_cli_baseline", CLI_COLLECTOR_PATH
)
CLI_VALIDATOR = load_module(
    "validate_macos_cli_baseline", CLI_VALIDATOR_PATH
)
CLI_COMMON = load_module(
    "collect_windows_cli_baseline_for_macos_test",
    ROOT / "tools/upstream/collect_windows_cli_baseline.py",
)
MATRIX_COLLECTOR = load_module(
    "collect_macos_cli_matrix", MATRIX_COLLECTOR_PATH
)
MATRIX_VALIDATOR = load_module(
    "validate_macos_cli_matrix", MATRIX_VALIDATOR_PATH
)
MATRIX_HELPER = load_module(
    "collect_windows_cli_matrix_for_macos_test",
    ROOT / "tools/upstream/collect_windows_cli_matrix.py",
)
MATRIX_DEFINITIONS = load_module(
    "compare_cli_oracles_for_macos_test",
    ROOT / "tools/upstream/compare_cli_oracles.py",
)
REMAINING_COLLECTOR = load_module(
    "collect_macos_cli_remaining", REMAINING_COLLECTOR_PATH
)
REMAINING_VALIDATOR = load_module(
    "validate_macos_cli_remaining", REMAINING_VALIDATOR_PATH
)
REMAINING_OUTPUT_HELPER = load_module(
    "collect_windows_cli_output_remaining_for_macos_test",
    ROOT / "tools/upstream/collect_windows_cli_output_remaining.py",
)
REMAINING_SPECIAL_HELPER = load_module(
    "collect_windows_cli_special_remaining_for_macos_test",
    ROOT / "tools/upstream/collect_windows_cli_special_remaining.py",
)
DATABASE_COLLECTOR = load_module(
    "collect_macos_cli_database", DATABASE_COLLECTOR_PATH
)
DATABASE_VALIDATOR = load_module(
    "validate_macos_cli_database", DATABASE_VALIDATOR_PATH
)
DATABASE_HELPER = load_module(
    "collect_windows_cli_database_for_macos_test",
    ROOT / "tools/upstream/collect_windows_cli_database.py",
)
PATH_NESTED_COLLECTOR = load_module(
    "collect_macos_cli_path_nested", PATH_NESTED_COLLECTOR_PATH
)
PATH_NESTED_VALIDATOR = load_module(
    "validate_macos_cli_path_nested", PATH_NESTED_VALIDATOR_PATH
)
PATH_NESTED_HELPER = load_module(
    "collect_windows_cli_path_nested_for_macos_test",
    ROOT / "tools/upstream/collect_windows_cli_path_nested.py",
)
DATABASE_ARCHIVE_COLLECTOR = load_module(
    "collect_macos_cli_database_archives",
    DATABASE_ARCHIVE_COLLECTOR_PATH,
)
DATABASE_ARCHIVE_VALIDATOR = load_module(
    "validate_macos_cli_database_archives",
    DATABASE_ARCHIVE_VALIDATOR_PATH,
)
DATABASE_ARCHIVE_HELPER = load_module(
    "collect_windows_cli_database_archives_for_macos_test",
    ROOT / "tools/upstream/collect_windows_cli_database_archives.py",
)
SPECIAL_PATH_COLLECTOR = load_module(
    "collect_macos_cli_special_paths", SPECIAL_PATH_COLLECTOR_PATH
)
SPECIAL_PATH_VALIDATOR = load_module(
    "validate_macos_cli_special_paths", SPECIAL_PATH_VALIDATOR_PATH
)
SPECIAL_FIXTURE_GENERATOR = load_module(
    "generate_macos_special_path_fixture_for_cli_test",
    ROOT / "tools/corpus/generate_macos_special_path_fixture.py",
)
SPECIAL_FIXTURE_VALIDATOR = load_module(
    "validate_macos_special_path_fixture_for_cli_test",
    ROOT / "tools/corpus/validate_macos_special_path_fixture.py",
)
FILESYSTEM_COLLECTOR = load_module(
    "collect_macos_cli_filesystem", FILESYSTEM_COLLECTOR_PATH
)
FILESYSTEM_VALIDATOR = load_module(
    "validate_macos_cli_filesystem", FILESYSTEM_VALIDATOR_PATH
)
LARGE_DIRECTORY_COLLECTOR = load_module(
    "collect_macos_cli_large_directory",
    LARGE_DIRECTORY_COLLECTOR_PATH,
)
LARGE_DIRECTORY_VALIDATOR = load_module(
    "validate_macos_cli_large_directory",
    LARGE_DIRECTORY_VALIDATOR_PATH,
)
LARGE_DIRECTORY_MATERIALIZER = load_module(
    "materialize_large_path_fixture_for_macos_test",
    ROOT / "tools/corpus/materialize_large_path_fixture.py",
)
LONG_PATH_FIXTURE_GENERATOR = load_module(
    "generate_macos_long_path_fixture_for_cli_test",
    LONG_PATH_FIXTURE_GENERATOR_PATH,
)
LONG_PATH_FIXTURE_VALIDATOR = load_module(
    "validate_macos_long_path_fixture_for_cli_test",
    LONG_PATH_FIXTURE_VALIDATOR_PATH,
)
LONG_PATH_COLLECTOR = load_module(
    "collect_macos_cli_long_paths", LONG_PATH_COLLECTOR_PATH
)
LONG_PATH_VALIDATOR = load_module(
    "validate_macos_cli_long_paths", LONG_PATH_VALIDATOR_PATH
)
BASELINE_CORPUS_GENERATOR = load_module(
    "generate_baseline_corpus_for_long_path_cli_test",
    ROOT / "tools/corpus/generate_baseline_corpus.py",
)


def candidate_report() -> dict:
    digest = "0" * 64
    return {
        "schema_version": 1,
        "result": "candidate",
        "platform": "macos-x86_64-qt5",
        "source": {
            "repository": "https://github.com/horsicq/DIE-engine",
            "commit": VALIDATOR.UPSTREAM_COMMIT,
            "rules_commit": VALIDATOR.RULES_COMMIT,
            "recursive_submodule_count": 58,
            "tracked_files_clean_before_and_after": True,
        },
        "source_files": {
            path: digest for path in VALIDATOR.EXPECTED_SOURCE_FILES
        },
        "host": {
            "sw_vers": ["ProductName:\tmacOS", "ProductVersion:\t15.0"],
            "uname": "Darwin host 24.0.0 x86_64",
            "cpu_brand": "Intel test CPU",
            "logical_cpu_count": 4,
            "xcode_version": ["Xcode 16.0", "Build version 16A1"],
            "clang_version": ["Apple clang version 16.0.0"],
            "cmake_version": "cmake version 3.30.0",
        },
        "qt": {
            "version": "5.15.2",
            "qmake_spec": "macx-clang",
            "qmake_version": [
                "QMake version 3.1",
                "Using Qt version 5.15.2",
            ],
            "qmake_sha256": digest,
            "qtcore_sha256": digest,
            "qtscript_sha256": digest,
        },
        "build": {
            "system": "qmake",
            "configuration": "release",
            "jobs": 4,
            "targets": [
                "sub-build_libs-make_first",
                "sub-console_source-make_first",
            ],
            "elapsed_seconds": 60,
        },
        "artifact": {
            "size": 1,
            "sha256": digest,
            "architectures": ["x86_64"],
            "file_description": "Mach-O 64-bit executable x86_64",
            "otool_l": [
                "diec:",
                "\tQtCore.framework/Versions/5/QtCore",
            ],
            "version_stdout": "die 4.0.0",
            "version_exit_code": 0,
        },
        "admission": {
            "platform_admitted": False,
            "reason": "runtime capability evidence is missing",
        },
        "local_paths": {
            "source_dir": "/private/tmp/source",
            "qt_dir": "/Users/runner/Qt/5.15.2/clang_64",
            "build_dir": "/private/tmp/build",
            "artifact": "/private/tmp/source/build/release/diec",
        },
    }


def write_cli_candidate_bundle(directory: Path) -> Path:
    oracle = candidate_report()
    oracle_path = directory / "oracle-candidate.json"
    oracle_path.write_text(
        json.dumps(oracle, sort_keys=True), encoding="utf-8"
    )
    manifest_raw = (
        ROOT / "docs/research/data/baseline-corpus.json"
    ).read_bytes()
    manifest = json.loads(manifest_raw)
    linux_raw = (
        ROOT / "docs/research/data/baseline-corpus-linux-qt5.json"
    ).read_bytes()
    linux = json.loads(linux_raw)

    cases = {}
    for case in CLI_COLLECTOR.expected_cases(CLI_COMMON):
        observation = CLI_COMMON.Observation(0, b"stable", b"")
        pair = CLI_COLLECTOR.pair_report(
            CLI_COMMON,
            directory,
            f"cli-baseline/cases/{case.name}",
            observation,
            observation,
        )
        pair["arguments"] = list(case.report_arguments)
        cases[case.name] = pair

    database_args = [
        "--database",
        "<source>/Detect-It-Easy/db",
        "--extradatabase",
        "<source>/Detect-It-Easy/db_extra",
        "--customdatabase",
        "<source>/Detect-It-Easy/db_custom",
    ]
    corpus = {}
    for sample in manifest["samples"]:
        name = sample["name"]
        linux_item = linux["corpus"][name]
        linux_tree = linux_item["left_detect_tree"]
        stdout = (
            b""
            if linux_tree is None
            else json.dumps(
                {"detects": linux_tree},
                separators=(",", ":"),
            ).encode("utf-8")
        )
        observation = CLI_COMMON.Observation(
            linux_item["left"]["exit_code"], stdout, b""
        )
        pair = CLI_COLLECTOR.pair_report(
            CLI_COMMON,
            directory,
            f"cli-baseline/corpus/{name}",
            observation,
            observation,
        )
        projected = CLI_COMMON.json_detect_tree(stdout)
        pair.update(
            {
                "arguments": [
                    "--json",
                    *database_args,
                    f"<corpus>/{name}",
                ],
                "intended_format": sample["intended_format"],
                "sample_sha256": sample["sha256"],
                "first_detect_tree": projected,
                "second_detect_tree": projected,
                "linux_qt5_detect_tree": linux_tree,
                "linux_projection_equal": projected == linux_tree,
                "linux_exit_code_equal": True,
            }
        )
        corpus[name] = pair

    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": CLI_VALIDATOR.PLATFORM,
        "generator": {
            "path": CLI_VALIDATOR.COLLECTOR,
            "sha256": hashlib.sha256(
                CLI_COLLECTOR_PATH.read_bytes()
            ).hexdigest(),
            "shared_collector_path": (
                CLI_VALIDATOR.SHARED_COLLECTOR
            ),
            "shared_collector_sha256": hashlib.sha256(
                (
                    ROOT
                    / CLI_VALIDATOR.SHARED_COLLECTOR
                ).read_bytes()
            ).hexdigest(),
            "validator_path": (
                "tools/upstream/validate_macos_cli_baseline.py"
            ),
            "validator_sha256": hashlib.sha256(
                CLI_VALIDATOR_PATH.read_bytes()
            ).hexdigest(),
        },
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                oracle_path.read_bytes()
            ).hexdigest(),
        },
        "source": {
            "repository": "https://github.com/horsicq/DIE-engine",
            "commit": VALIDATOR.UPSTREAM_COMMIT,
            "recursive_submodule_count": 58,
            "rules_commit": VALIDATOR.RULES_COMMIT,
            "tracked_files_clean_before_and_after": True,
        },
        "qt": {
            "version": oracle["qt"]["version"],
            "qmake_spec": oracle["qt"]["qmake_spec"],
            "qmake_sha256": oracle["qt"]["qmake_sha256"],
            "qtcore_sha256": oracle["qt"]["qtcore_sha256"],
            "qtscript_sha256": oracle["qt"]["qtscript_sha256"],
        },
        "binary": {
            "size": oracle["artifact"]["size"],
            "sha256": oracle["artifact"]["sha256"],
            "relative_path": "build/release/diec",
        },
        "corpus_manifest": {
            "path": CLI_VALIDATOR.BASELINE_MANIFEST,
            "sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "sample_count": len(manifest["samples"]),
        },
        "linux_qt5_reference": {
            "path": CLI_VALIDATOR.LINUX_REFERENCE,
            "sha256": hashlib.sha256(linux_raw).hexdigest(),
        },
        "cases": cases,
        "corpus": corpus,
        "summary": {
            "case_count": len(cases),
            "corpus_count": len(corpus),
            "execution_count": 2 * (len(cases) + len(corpus)),
            "determinism_failures": [],
            "linux_projection_failures": [],
            "deterministic": True,
            "linux_projection_equal": True,
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": CLI_VALIDATOR.EXPECTED_ADMISSION_REASON,
        },
        "limitations": CLI_VALIDATOR.EXPECTED_LIMITATIONS,
    }
    report_path = directory / "cli-baseline-candidate.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path


def write_cli_matrix_candidate_bundle(
    directory: Path,
    baseline_path: Path,
) -> Path:
    baseline = CLI_VALIDATOR.load_json(baseline_path)[0]
    oracle_path = directory / "oracle-candidate.json"
    manifest = json.loads(
        (
            ROOT / "docs/research/data/baseline-corpus.json"
        ).read_bytes()
    )
    sample_names = [sample["name"] for sample in manifest["samples"]]
    cases_by_kind = {
        "output": MATRIX_DEFINITIONS.OUTPUT_MATRIX,
        "scan": MATRIX_DEFINITIONS.SCAN_MATRIX,
        "special": MATRIX_DEFINITIONS.SPECIAL_MATRIX,
    }
    selection = {
        "output": list(MATRIX_COLLECTOR.OUTPUT_SAMPLES),
        "scan": sample_names,
        "special": list(MATRIX_COLLECTOR.SPECIAL_SAMPLES),
    }
    linux_reports = {}
    linux_bindings = {}
    for kind, relative in MATRIX_COLLECTOR.LINUX_REFERENCES.items():
        raw = (ROOT / relative).read_bytes()
        linux_reports[kind] = json.loads(raw)
        linux_bindings[kind] = {
            "path": relative,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

    matrix = {}
    for kind in ("output", "scan", "special"):
        for sample_name in selection[kind]:
            kind_report = matrix.setdefault(sample_name, {}).setdefault(
                kind, {}
            )
            baseline_entry = baseline["corpus"][sample_name]
            baseline_observations = {}
            for side in ("first", "second"):
                item = baseline_entry[side]
                baseline_observations[side] = CLI_COMMON.Observation(
                    item["exit_code"],
                    (directory / item["stdout_path"]).read_bytes(),
                    (directory / item["stderr_path"]).read_bytes(),
                )
            observations = {}
            for case in cases_by_kind[kind]:
                if kind == "scan":
                    stdout = baseline_observations["first"].stdout
                    stderr = baseline_observations["first"].stderr
                    exit_code = baseline_observations["first"].exit_code
                else:
                    stdout = b"stable"
                    stderr = b""
                    exit_code = 0
                if sample_name in MATRIX_COLLECTOR.OUTPUT_SAMPLES:
                    exit_code = linux_reports[kind]["matrix"][
                        sample_name
                    ][kind][case.name]["left"]["exit_code"]
                observation = CLI_COMMON.Observation(
                    exit_code, stdout, stderr
                )
                observations[case.name] = (
                    observation,
                    observation,
                )
                pair = CLI_COLLECTOR.pair_report(
                    CLI_COMMON,
                    directory,
                    (
                        "cli-matrix/"
                        f"{sample_name}/{kind}/{case.name}"
                    ),
                    observation,
                    observation,
                )
                pair["arguments"] = [
                    *MATRIX_HELPER.translate_arguments(
                        case.arguments,
                        Path("<source>"),
                        report=True,
                    ),
                    f"<corpus>/{sample_name}",
                ]
                if kind == "scan":
                    tree = CLI_COMMON.json_detect_tree(stdout)
                    pair["first_detect_tree"] = tree
                    pair["second_detect_tree"] = tree
                if sample_name in MATRIX_COLLECTOR.OUTPUT_SAMPLES:
                    pair["linux_qt5_exit_code"] = exit_code
                    pair["linux_qt5_exit_code_equal"] = True
                kind_report[case.name] = pair

            if kind == "scan":
                default_first, default_second = observations["default"]
                default = kind_report["default"]
                reference_equal = (
                    default_first.summary()
                    == MATRIX_COLLECTOR.observation_identity(
                        baseline_entry["first"]
                    )
                    and default_second.summary()
                    == MATRIX_COLLECTOR.observation_identity(
                        baseline_entry["second"]
                    )
                    and default["first_detect_tree"]
                    == baseline_entry["first_detect_tree"]
                    and default["second_detect_tree"]
                    == baseline_entry["second_detect_tree"]
                )
                default["cli_baseline_reference_equal"] = reference_equal
                for case_name, (first, second) in observations.items():
                    entry = kind_report[case_name]
                    entry["first_changes_from_default"] = (
                        MATRIX_HELPER.observation_differences(
                            default_first, first
                        )
                    )
                    entry["second_changes_from_default"] = (
                        MATRIX_HELPER.observation_differences(
                            default_second, second
                        )
                    )

    case_counts = {
        kind: len(selection[kind]) * len(cases_by_kind[kind])
        for kind in selection
    }
    case_count = sum(case_counts.values())
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": MATRIX_COLLECTOR.PLATFORM,
        "generator": {
            "path": MATRIX_VALIDATOR.COLLECTOR,
            "sha256": hashlib.sha256(
                MATRIX_COLLECTOR_PATH.read_bytes()
            ).hexdigest(),
            "validator_path": (
                "tools/upstream/validate_macos_cli_matrix.py"
            ),
            "validator_sha256": hashlib.sha256(
                MATRIX_VALIDATOR_PATH.read_bytes()
            ).hexdigest(),
            "baseline_collector_path": (
                MATRIX_VALIDATOR.BASELINE_COLLECTOR
            ),
            "baseline_collector_sha256": hashlib.sha256(
                CLI_COLLECTOR_PATH.read_bytes()
            ).hexdigest(),
            "baseline_validator_path": (
                MATRIX_VALIDATOR.BASELINE_VALIDATOR
            ),
            "baseline_validator_sha256": hashlib.sha256(
                CLI_VALIDATOR_PATH.read_bytes()
            ).hexdigest(),
            "windows_matrix_helper_path": (
                MATRIX_VALIDATOR.WINDOWS_MATRIX_HELPER
            ),
            "windows_matrix_helper_sha256": hashlib.sha256(
                (
                    ROOT
                    / MATRIX_VALIDATOR.WINDOWS_MATRIX_HELPER
                ).read_bytes()
            ).hexdigest(),
            "matrix_definitions_path": (
                MATRIX_VALIDATOR.MATRIX_DEFINITIONS
            ),
            "matrix_definitions_sha256": hashlib.sha256(
                (
                    ROOT / MATRIX_VALIDATOR.MATRIX_DEFINITIONS
                ).read_bytes()
            ).hexdigest(),
        },
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                oracle_path.read_bytes()
            ).hexdigest(),
        },
        "cli_baseline_report": {
            "path": "cli-baseline-candidate.json",
            "sha256": hashlib.sha256(
                baseline_path.read_bytes()
            ).hexdigest(),
        },
        "source": baseline["source"],
        "qt": baseline["qt"],
        "binary": baseline["binary"],
        "corpus_manifest": baseline["corpus_manifest"],
        "linux_qt5_references": linux_bindings,
        "selection": selection,
        "matrix": matrix,
        "summary": {
            "sample_count": len(sample_names),
            "case_counts": case_counts,
            "case_count": case_count,
            "execution_count": 2 * case_count,
            "raw_stream_count": 4 * case_count,
            "determinism_failures": [],
            "default_reference_failures": [],
            "linux_exit_code_failures": [],
            "deterministic": True,
            "default_reference_equal": True,
            "linux_exit_codes_equal": True,
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": MATRIX_COLLECTOR.ADMISSION_REASON,
        },
        "limitations": MATRIX_COLLECTOR.LIMITATIONS,
    }
    report_path = directory / "cli-matrix-candidate.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path


def write_cli_remaining_candidate_bundle(
    directory: Path,
    baseline_path: Path,
    primary_path: Path,
) -> Path:
    baseline = CLI_VALIDATOR.load_json(baseline_path)[0]
    manifest = json.loads(
        (
            ROOT / "docs/research/data/baseline-corpus.json"
        ).read_bytes()
    )
    covered = set(
        REMAINING_OUTPUT_HELPER.ALREADY_COVERED
    )
    selection = [
        sample["name"]
        for sample in manifest["samples"]
        if sample["name"] not in covered
    ]
    cases_by_kind = {
        "output": MATRIX_DEFINITIONS.OUTPUT_MATRIX,
        "special": MATRIX_DEFINITIONS.SPECIAL_MATRIX,
    }
    matrix = {}
    for sample_name in selection:
        sample_report = matrix.setdefault(sample_name, {})
        for kind in ("output", "special"):
            kind_report = sample_report.setdefault(kind, {})
            observations = {}
            for case in cases_by_kind[kind]:
                if kind == "output" and case.name == "json":
                    baseline_entry = baseline["corpus"][sample_name]
                    pair_observations = tuple(
                        CLI_COMMON.Observation(
                            baseline_entry[side]["exit_code"],
                            (
                                directory
                                / baseline_entry[side]["stdout_path"]
                            ).read_bytes(),
                            (
                                directory
                                / baseline_entry[side]["stderr_path"]
                            ).read_bytes(),
                        )
                        for side in ("first", "second")
                    )
                else:
                    if kind == "output":
                        stdout = (
                            b"<invalid"
                            if (
                                case.name == "xml"
                                and sample_name
                                in REMAINING_OUTPUT_HELPER.EXPECTED_INVALID_XML
                            )
                            else (
                                b"<root/>"
                                if case.name == "xml"
                                else b"text"
                            )
                        )
                    elif case.name in {
                        "info_json",
                        "info_all_output_flags",
                    }:
                        stdout = json.dumps(
                            {
                                "data": {
                                    "Info": {
                                        "File name": (
                                            "/tmp/corpus/"
                                            f"{sample_name}"
                                        )
                                    }
                                }
                            },
                            separators=(",", ":"),
                        ).encode("utf-8")
                    elif (
                        case.name
                        in REMAINING_SPECIAL_HELPER.JSON_CASES
                    ):
                        stdout = b"{}"
                    elif (
                        case.name
                        in REMAINING_SPECIAL_HELPER.XML_CASES
                    ):
                        stdout = b"<root/>"
                    else:
                        stdout = b"text"
                    observation = CLI_COMMON.Observation(
                        0, stdout, b""
                    )
                    pair_observations = (
                        observation,
                        observation,
                    )
                first, second = pair_observations
                observations[case.name] = pair_observations
                entry = CLI_COLLECTOR.pair_report(
                    CLI_COMMON,
                    directory,
                    (
                        "cli-remaining/"
                        f"{sample_name}/{kind}/{case.name}"
                    ),
                    first,
                    second,
                )
                entry.update(
                    {
                        "arguments": [
                            *MATRIX_HELPER.translate_arguments(
                                case.arguments,
                                Path("<source>"),
                                report=True,
                            ),
                            f"<corpus>/{sample_name}",
                        ],
                        "expected_exit_code": 0,
                        "expected_exit_code_equal": True,
                        "expected_empty_stderr": True,
                        "first_stderr_empty": True,
                        "second_stderr_empty": True,
                    }
                )
                if kind == "output":
                    expected_valid = not (
                        case.name == "xml"
                        and sample_name
                        in REMAINING_OUTPUT_HELPER.EXPECTED_INVALID_XML
                    )
                    first_valid = (
                        REMAINING_OUTPUT_HELPER.output_validity(
                            case.name, first.stdout
                        )
                    )
                    second_valid = (
                        REMAINING_OUTPUT_HELPER.output_validity(
                            case.name, second.stdout
                        )
                    )
                    entry.update(
                        {
                            "first_output_valid": first_valid,
                            "second_output_valid": second_valid,
                            "expected_output_valid": expected_valid,
                            "output_validity_expected_equal": True,
                        }
                    )
                    if case.name == "json":
                        first_tree = CLI_COMMON.json_detect_tree(
                            first.stdout
                        )
                        second_tree = CLI_COMMON.json_detect_tree(
                            second.stdout
                        )
                        entry.update(
                            {
                                "first_detect_tree": first_tree,
                                "second_detect_tree": second_tree,
                                "cli_baseline_reference_equal": True,
                            }
                        )
                else:
                    first_valid, first_projection = (
                        REMAINING_SPECIAL_HELPER.parse_output(
                            case.name, first.stdout
                        )
                    )
                    second_valid, second_projection = (
                        REMAINING_SPECIAL_HELPER.parse_output(
                            case.name, second.stdout
                        )
                    )
                    first_projection = (
                        REMAINING_SPECIAL_HELPER.normalize_projection(
                            case.name,
                            first_projection,
                            sample_name,
                        )
                    )
                    second_projection = (
                        REMAINING_SPECIAL_HELPER.normalize_projection(
                            case.name,
                            second_projection,
                            sample_name,
                        )
                    )
                    entry.update(
                        {
                            "first_output_valid": first_valid,
                            "second_output_valid": second_valid,
                        }
                    )
                    if (
                        case.name
                        in REMAINING_SPECIAL_HELPER.JSON_CASES
                        or case.name
                        in REMAINING_SPECIAL_HELPER.XML_CASES
                    ):
                        entry.update(
                            {
                                "first_projection": first_projection,
                                "second_projection": second_projection,
                            }
                        )
                kind_report[case.name] = entry

            if kind == "output":
                kind_report["all_output_flags"][
                    "csv_priority_reference_equal"
                ] = (
                    observations["all_output_flags"]
                    == observations["csv"]
                )
            else:
                for case_name, reference_name in (
                    REMAINING_SPECIAL_HELPER.PRIORITY_REFERENCES.items()
                ):
                    entry = kind_report[case_name]
                    entry["priority_reference_case"] = reference_name
                    entry["priority_reference_equal"] = (
                        observations[case_name]
                        == observations[reference_name]
                    )

    case_counts = {
        kind: len(selection) * len(cases)
        for kind, cases in cases_by_kind.items()
    }
    case_count = sum(case_counts.values())
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": REMAINING_COLLECTOR.PLATFORM,
        "generator": REMAINING_COLLECTOR._generator_bindings(ROOT),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                (directory / "oracle-candidate.json").read_bytes()
            ).hexdigest(),
        },
        "cli_baseline_report": {
            "path": "cli-baseline-candidate.json",
            "sha256": hashlib.sha256(
                baseline_path.read_bytes()
            ).hexdigest(),
        },
        "cli_primary_matrix_report": {
            "path": "cli-matrix-candidate.json",
            "sha256": hashlib.sha256(
                primary_path.read_bytes()
            ).hexdigest(),
        },
        "source": baseline["source"],
        "qt": baseline["qt"],
        "binary": baseline["binary"],
        "corpus_manifest": baseline["corpus_manifest"],
        "selection": selection,
        "cases": {
            kind: [case.name for case in cases]
            for kind, cases in cases_by_kind.items()
        },
        "output_classification": {
            "expected_invalid_xml_samples": list(
                REMAINING_OUTPUT_HELPER.EXPECTED_INVALID_XML
            ),
            "special_json": list(
                REMAINING_SPECIAL_HELPER.JSON_CASES
            ),
            "special_xml": list(
                REMAINING_SPECIAL_HELPER.XML_CASES
            ),
        },
        "priority_references": {
            "output_all_flags": "csv",
            "special": (
                REMAINING_SPECIAL_HELPER.PRIORITY_REFERENCES
            ),
        },
        "matrix": matrix,
        "summary": {
            "sample_count": len(selection),
            "case_counts": case_counts,
            "case_count": case_count,
            "execution_count": 2 * case_count,
            "raw_stream_count": 4 * case_count,
            "determinism_failures": [],
            "expected_exit_failures": [],
            "stderr_failures": [],
            "validity_failures": [],
            "json_reference_failures": [],
            "priority_failures": [],
            "deterministic": True,
            "expected_exits_equal": True,
            "stderr_empty": True,
            "outputs_valid_as_expected": True,
            "json_baseline_references_equal": True,
            "priority_references_equal": True,
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": REMAINING_COLLECTOR.ADMISSION_REASON,
        },
        "limitations": REMAINING_COLLECTOR.LIMITATIONS,
    }
    report_path = directory / "cli-remaining-candidate.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path


def write_cli_database_candidate_bundle(directory: Path) -> Path:
    oracle_path = directory / "oracle-candidate.json"
    oracle = json.loads(oracle_path.read_bytes())
    fixture_raw = (
        ROOT / DATABASE_COLLECTOR.FIXTURE_MANIFEST
    ).read_bytes()
    fixture = json.loads(fixture_raw)
    linux_raw = (
        ROOT / DATABASE_COLLECTOR.LINUX_REFERENCE
    ).read_bytes()
    linux = json.loads(linux_raw)
    linux_cases = DATABASE_HELPER.validate_linux_reference(linux)
    source_dir = PurePosixPath(oracle["local_paths"]["source_dir"])
    fixture_dir = PurePosixPath("/private/tmp/database-fixture")

    cases = {}
    determinism_failures = []
    exit_failures = []
    load_error_failures = []
    validity_failures = []
    normalized_failures = []
    for case in MATRIX_DEFINITIONS.DATABASE_CASES:
        actual_arguments = DATABASE_HELPER.translate_arguments(
            case.arguments,
            source_dir,
            fixture_dir,
            report=False,
        )
        report_arguments = DATABASE_HELPER.translate_arguments(
            case.arguments,
            source_dir,
            fixture_dir,
            report=True,
        )
        linux_case = linux_cases[case.name]
        if "malformed" in case.name:
            stdout = b"SyntaxError: Parse error"
        elif "throwing" in case.name:
            stdout = b"Error: database fixture"
        elif linux_case["left_reports_load_error"]:
            database_index = actual_arguments.index("--database") + 1
            stdout = (
                b"Cannot load database: "
                + actual_arguments[database_index].encode("utf-8")
            )
        elif case.name.endswith("_json"):
            stdout = b"{}"
        else:
            stdout = b"text"
        observation = CLI_COMMON.Observation(
            linux_case["left"]["exit_code"],
            stdout,
            b"",
        )
        entry = CLI_COLLECTOR.pair_report(
            CLI_COMMON,
            directory,
            f"cli-database/{case.name}",
            observation,
            observation,
        )
        first_load_error = b"Cannot load database:" in stdout
        linux_load_error = linux_case["left_reports_load_error"]
        normalized = (
            DATABASE_HELPER.normalize_windows_stdout_for_linux(
                stdout,
                actual_arguments,
                case.arguments,
            )
        )
        normalized_sha256 = hashlib.sha256(normalized).hexdigest()
        normalized_equal = (
            normalized_sha256
            == linux_case["left"]["stdout_sha256"]
        )
        entry.update(
            {
                "arguments": list(report_arguments),
                "first_reports_load_error": first_load_error,
                "second_reports_load_error": first_load_error,
                "linux_qt5_reports_load_error": linux_load_error,
                "linux_qt5_reports_load_error_equal": (
                    first_load_error == linux_load_error
                ),
                "reports_parse_error": (
                    b"SyntaxError: Parse error" in stdout
                ),
                "reports_runtime_error": (
                    b"Error: database fixture" in stdout
                ),
                "linux_qt5_raw_differences": (
                    DATABASE_COLLECTOR._raw_differences(
                        observation.summary(),
                        linux_case["left"],
                    )
                ),
                "linux_normalized_stdout_sha256": normalized_sha256,
                "linux_qt5_normalized_stdout_equal": normalized_equal,
            }
        )
        if case.name.endswith("_json"):
            valid = MATRIX_DEFINITIONS.document_is_valid(
                stdout, "json"
            )
            linux_valid = linux_case["left_valid_json"]
            entry.update(
                {
                    "first_valid_json": valid,
                    "second_valid_json": valid,
                    "linux_qt5_valid_json": linux_valid,
                    "linux_qt5_valid_json_equal": valid == linux_valid,
                }
            )
            if valid != linux_valid:
                validity_failures.append(case.name)
        cases[case.name] = entry
        if entry["determinism_differences"]:
            determinism_failures.append(case.name)
        if observation.exit_code != linux_case["left"]["exit_code"]:
            exit_failures.append(case.name)
        if first_load_error != linux_load_error:
            load_error_failures.append(case.name)
        if not normalized_equal:
            normalized_failures.append(case.name)

    case_count = len(MATRIX_DEFINITIONS.DATABASE_CASES)
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": DATABASE_COLLECTOR.PLATFORM,
        "generator": DATABASE_COLLECTOR._generator_bindings(ROOT),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                oracle_path.read_bytes()
            ).hexdigest(),
        },
        "source": {
            "repository": (
                "https://github.com/horsicq/DIE-engine"
            ),
            "commit": VALIDATOR.UPSTREAM_COMMIT,
            "recursive_submodule_count": 58,
            "rules_commit": VALIDATOR.RULES_COMMIT,
            "tracked_files_clean_before_and_after": True,
        },
        "qt": {
            "version": oracle["qt"]["version"],
            "qmake_spec": oracle["qt"]["qmake_spec"],
            "qmake_sha256": oracle["qt"]["qmake_sha256"],
            "qtcore_sha256": oracle["qt"]["qtcore_sha256"],
            "qtscript_sha256": oracle["qt"]["qtscript_sha256"],
        },
        "binary": {
            "size": oracle["artifact"]["size"],
            "sha256": oracle["artifact"]["sha256"],
            "relative_path": "build/release/diec",
        },
        "fixture": {
            "manifest": DATABASE_COLLECTOR.FIXTURE_MANIFEST,
            "sha256": hashlib.sha256(fixture_raw).hexdigest(),
            "directories": fixture["directories"],
            "entries": fixture["entries"],
        },
        "linux_qt5_reference": {
            "path": DATABASE_COLLECTOR.LINUX_REFERENCE,
            "sha256": hashlib.sha256(linux_raw).hexdigest(),
        },
        "local_paths": {
            "fixture_dir": str(fixture_dir),
        },
        "cases": cases,
        "summary": {
            "case_count": case_count,
            "execution_count": 2 * case_count,
            "raw_stream_count": 4 * case_count,
            "determinism_failures": determinism_failures,
            "linux_exit_code_failures": exit_failures,
            "linux_load_error_failures": load_error_failures,
            "linux_document_validity_failures": validity_failures,
            "linux_normalized_stdout_failures": normalized_failures,
            "deterministic": not determinism_failures,
            "linux_exit_codes_equal": not exit_failures,
            "linux_load_errors_equal": not load_error_failures,
            "linux_document_validity_equal": not validity_failures,
            "linux_normalized_stdout_equal": not normalized_failures,
        },
        "normalization": DATABASE_COLLECTOR.NORMALIZATION,
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": DATABASE_COLLECTOR.ADMISSION_REASON,
        },
        "limitations": DATABASE_COLLECTOR.LIMITATIONS,
    }
    report_path = directory / "cli-database-candidate.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path


def write_cli_path_nested_candidate_bundle(directory: Path) -> Path:
    oracle_path = directory / "oracle-candidate.json"
    oracle = json.loads(oracle_path.read_bytes())
    path_manifest_raw = (
        ROOT / PATH_NESTED_COLLECTOR.PATH_MANIFEST
    ).read_bytes()
    path_manifest = json.loads(path_manifest_raw)
    nested_manifest_raw = (
        ROOT / PATH_NESTED_COLLECTOR.NESTED_MANIFEST
    ).read_bytes()
    nested_manifest = json.loads(nested_manifest_raw)
    path_reference_raw = (
        ROOT / PATH_NESTED_COLLECTOR.LINUX_PATH_REFERENCE
    ).read_bytes()
    path_reference = json.loads(path_reference_raw)
    nested_reference_raw = (
        ROOT / PATH_NESTED_COLLECTOR.LINUX_NESTED_REFERENCE
    ).read_bytes()
    nested_reference = json.loads(nested_reference_raw)
    linux_path_cases = path_reference["path_corpus"]["cases"]
    linux_nested_cases = nested_reference["nested_corpus"]["cases"]
    source_dir = PurePosixPath(
        oracle["local_paths"]["source_dir"]
    )
    path_corpus_dir = PurePosixPath("/private/tmp/path-corpus")
    nested_corpus_dir = PurePosixPath(
        "/private/tmp/nested-corpus"
    )

    path_cases = {}
    path_observations = {}
    determinism_failures = []
    exit_failures = []
    path_prefix_failures = []
    nested_projection_failures = []
    for case in MATRIX_DEFINITIONS.PATH_CASES:
        linux_case = linux_path_cases[case.name]
        linux_prefixes = (
            PATH_NESTED_HELPER.normalized_linux_prefixes(
                linux_case["left_filename_prefixes"]
            )
        )
        prefix_bytes = b"".join(
            (
                str(path_corpus_dir)
                + prefix.removeprefix("<paths>")
                + ":\n"
            ).encode("utf-8")
            for prefix in linux_prefixes
        )
        if case.name.endswith("_json"):
            body = b"{}"
        elif case.name.endswith("_xml"):
            body = b"<root/>"
        else:
            body = b"text"
        observation = CLI_COMMON.Observation(
            linux_case["left"]["exit_code"],
            prefix_bytes + body,
            b"",
        )
        path_observations[case.name] = (
            observation,
            observation,
        )
        entry = CLI_COLLECTOR.pair_report(
            CLI_COMMON,
            directory,
            f"cli-path-nested/path/{case.name}",
            observation,
            observation,
        )
        report_arguments = PATH_NESTED_HELPER.translate_arguments(
            case.arguments,
            source_dir,
            path_corpus_dir,
            nested_corpus_dir,
            report=True,
        )
        first_prefixes = (
            PATH_NESTED_HELPER.relative_filename_prefixes(
                observation.stdout, path_corpus_dir
            )
        )
        entry.update(
            {
                "arguments": list(report_arguments),
                "first_filename_prefixes": first_prefixes,
                "second_filename_prefixes": first_prefixes,
                "linux_qt5_filename_prefixes": linux_prefixes,
                "linux_qt5_filename_prefixes_equal": (
                    first_prefixes == linux_prefixes
                ),
                "linux_qt5_raw_differences": (
                    PATH_NESTED_HELPER.raw_differences(
                        observation.summary(),
                        linux_case["left"],
                    )
                ),
            }
        )
        if case.name.endswith("_json"):
            valid = MATRIX_DEFINITIONS.document_is_valid(
                observation.stdout, "json"
            )
            entry.update(
                {
                    "first_valid_json": valid,
                    "second_valid_json": valid,
                    "linux_qt5_valid_json": (
                        linux_case["left_valid_json"]
                    ),
                }
            )
        elif case.name.endswith("_xml"):
            valid = MATRIX_DEFINITIONS.document_is_valid(
                observation.stdout, "xml"
            )
            entry.update(
                {
                    "first_valid_xml": valid,
                    "second_valid_xml": valid,
                    "linux_qt5_valid_xml": (
                        linux_case["left_valid_xml"]
                    ),
                }
            )
        path_cases[case.name] = entry
        if entry["determinism_differences"]:
            determinism_failures.append(f"path.{case.name}")
        if observation.exit_code != linux_case["left"]["exit_code"]:
            exit_failures.append(f"path.{case.name}")
        if first_prefixes != linux_prefixes:
            path_prefix_failures.append(case.name)

    tree = path_observations["tree_json"]
    recursive = path_observations["tree_recursive_json"]
    recursive_entry = path_cases["tree_recursive_json"]
    recursive_entry["first_changes_from_tree_json"] = (
        PATH_NESTED_HELPER.observation_differences(
            tree[0], recursive[0]
        )
    )
    recursive_entry["second_changes_from_tree_json"] = (
        PATH_NESTED_HELPER.observation_differences(
            tree[1], recursive[1]
        )
    )

    nested_cases = {}
    for sample in nested_manifest["samples"]:
        sample_name = sample["name"]
        sample_cases = {}
        nested_cases[sample_name] = sample_cases
        observations = {}
        for case in MATRIX_DEFINITIONS.NESTED_MATRIX:
            linux_case = linux_nested_cases[sample_name][case.name]
            tree = linux_case["left_detect_tree"]
            stdout = json.dumps(
                {"detects": tree},
                separators=(",", ":"),
            ).encode("utf-8")
            observation = CLI_COMMON.Observation(
                linux_case["left"]["exit_code"], stdout, b""
            )
            observations[case.name] = (
                observation,
                observation,
            )
            entry = CLI_COLLECTOR.pair_report(
                CLI_COMMON,
                directory,
                (
                    "cli-path-nested/nested/"
                    f"{sample_name}/{case.name}"
                ),
                observation,
                observation,
            )
            arguments = (
                *case.arguments,
                f"/nested/{sample_name}",
            )
            report_arguments = (
                PATH_NESTED_HELPER.translate_arguments(
                    arguments,
                    source_dir,
                    path_corpus_dir,
                    nested_corpus_dir,
                    report=True,
                )
            )
            projected = CLI_COMMON.json_detect_tree(stdout)
            entry.update(
                {
                    "arguments": list(report_arguments),
                    "first_detect_tree": projected,
                    "second_detect_tree": projected,
                    "linux_qt5_detect_tree": tree,
                    "linux_qt5_detect_tree_equal": projected == tree,
                    "linux_qt5_raw_differences": (
                        PATH_NESTED_HELPER.raw_differences(
                            observation.summary(),
                            linux_case["left"],
                        )
                    ),
                }
            )
            sample_cases[case.name] = entry
            identity = f"nested.{sample_name}.{case.name}"
            if entry["determinism_differences"]:
                determinism_failures.append(identity)
            if observation.exit_code != linux_case["left"]["exit_code"]:
                exit_failures.append(identity)
            if projected != tree:
                nested_projection_failures.append(identity)
        default = observations["default"]
        for case_name, observation_pair in observations.items():
            entry = sample_cases[case_name]
            entry["first_changes_from_default"] = (
                PATH_NESTED_HELPER.observation_differences(
                    default[0], observation_pair[0]
                )
            )
            entry["second_changes_from_default"] = (
                PATH_NESTED_HELPER.observation_differences(
                    default[1], observation_pair[1]
                )
            )

    path_case_count = len(MATRIX_DEFINITIONS.PATH_CASES)
    nested_case_count = len(nested_manifest["samples"]) * len(
        MATRIX_DEFINITIONS.NESTED_MATRIX
    )
    case_count = path_case_count + nested_case_count
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": PATH_NESTED_COLLECTOR.PLATFORM,
        "generator": PATH_NESTED_COLLECTOR._generator_bindings(
            ROOT
        ),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                oracle_path.read_bytes()
            ).hexdigest(),
        },
        "source": {
            "repository": (
                "https://github.com/horsicq/DIE-engine"
            ),
            "commit": VALIDATOR.UPSTREAM_COMMIT,
            "recursive_submodule_count": 58,
            "rules_commit": VALIDATOR.RULES_COMMIT,
            "tracked_files_clean_before_and_after": True,
        },
        "qt": {
            "version": oracle["qt"]["version"],
            "qmake_spec": oracle["qt"]["qmake_spec"],
            "qmake_sha256": oracle["qt"]["qmake_sha256"],
            "qtcore_sha256": oracle["qt"]["qtcore_sha256"],
            "qtscript_sha256": oracle["qt"]["qtscript_sha256"],
        },
        "binary": {
            "size": oracle["artifact"]["size"],
            "sha256": oracle["artifact"]["sha256"],
            "relative_path": "build/release/diec",
        },
        "fixtures": {
            "path": {
                "manifest": PATH_NESTED_COLLECTOR.PATH_MANIFEST,
                "sha256": hashlib.sha256(
                    path_manifest_raw
                ).hexdigest(),
                "directories": path_manifest["directories"],
                "entries": path_manifest["entries"],
            },
            "nested": {
                "manifest": PATH_NESTED_COLLECTOR.NESTED_MANIFEST,
                "sha256": hashlib.sha256(
                    nested_manifest_raw
                ).hexdigest(),
                "samples": nested_manifest["samples"],
            },
        },
        "linux_qt5_references": {
            "path": {
                "path": (
                    PATH_NESTED_COLLECTOR.LINUX_PATH_REFERENCE
                ),
                "sha256": hashlib.sha256(
                    path_reference_raw
                ).hexdigest(),
            },
            "nested": {
                "path": (
                    PATH_NESTED_COLLECTOR.LINUX_NESTED_REFERENCE
                ),
                "sha256": hashlib.sha256(
                    nested_reference_raw
                ).hexdigest(),
            },
        },
        "local_paths": {
            "path_corpus_dir": str(path_corpus_dir),
            "nested_corpus_dir": str(nested_corpus_dir),
        },
        "path": {"cases": path_cases},
        "nested": {"cases": nested_cases},
        "summary": {
            "path_case_count": path_case_count,
            "nested_sample_count": len(
                nested_manifest["samples"]
            ),
            "nested_case_count": nested_case_count,
            "case_count": case_count,
            "execution_count": 2 * case_count,
            "raw_stream_count": 4 * case_count,
            "determinism_failures": determinism_failures,
            "linux_exit_code_failures": exit_failures,
            "path_prefix_failures": path_prefix_failures,
            "nested_projection_failures": (
                nested_projection_failures
            ),
            "deterministic": not determinism_failures,
            "linux_exit_codes_equal": not exit_failures,
            "path_prefixes_equal": not path_prefix_failures,
            "nested_projections_equal": (
                not nested_projection_failures
            ),
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": PATH_NESTED_COLLECTOR.ADMISSION_REASON,
        },
        "limitations": PATH_NESTED_COLLECTOR.LIMITATIONS,
    }
    report_path = directory / "cli-path-nested-candidate.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path


def write_cli_database_archive_candidate_bundle(
    directory: Path,
) -> Path:
    oracle_path = directory / "oracle-candidate.json"
    oracle = json.loads(oracle_path.read_bytes())
    fixture_raw = (
        ROOT / DATABASE_ARCHIVE_COLLECTOR.FIXTURE_MANIFEST
    ).read_bytes()
    fixture = json.loads(fixture_raw)
    fixture_sha256 = hashlib.sha256(fixture_raw).hexdigest()
    linux_raw = (
        ROOT / DATABASE_ARCHIVE_COLLECTOR.LINUX_REFERENCE
    ).read_bytes()
    linux = json.loads(linux_raw)
    linux_cases = (
        DATABASE_ARCHIVE_HELPER.validate_linux_reference(
            linux, fixture_sha256
        )
    )
    database_helper = DATABASE_ARCHIVE_HELPER.windows_database
    definitions = DATABASE_ARCHIVE_HELPER.archive_definitions
    source_dir = PurePosixPath(
        oracle["local_paths"]["source_dir"]
    )
    fixture_dir = PurePosixPath("/private/tmp/database-fixture")

    cases = {}
    determinism_failures = []
    exit_failures = []
    stderr_failures = []
    validity_failures = []
    normalized_failures = []
    for case in definitions.ARCHIVE_CASES:
        actual_arguments = database_helper.translate_arguments(
            case.arguments,
            source_dir,
            fixture_dir,
            report=False,
        )
        report_arguments = database_helper.translate_arguments(
            case.arguments,
            source_dir,
            fixture_dir,
            report=True,
        )
        linux_case = linux_cases[case.name]
        if "payload_structure_truncated" in case.name:
            stdout = b"SyntaxError: Parse error"
        elif case.name.endswith("_json"):
            stdout = b"{}"
        else:
            stdout = b"text"
        observation = CLI_COMMON.Observation(
            linux_case["left"]["exit_code"], stdout, b""
        )
        entry = CLI_COLLECTOR.pair_report(
            CLI_COMMON,
            directory,
            f"cli-database-archive/{case.name}",
            observation,
            observation,
        )
        normalized = (
            database_helper.normalize_windows_stdout_for_linux(
                stdout,
                actual_arguments,
                case.arguments,
            )
        )
        normalized_sha256 = hashlib.sha256(normalized).hexdigest()
        normalized_equal = (
            normalized_sha256
            == linux_case["left"]["stdout_sha256"]
        )
        stderr_equal = (
            observation.summary()["stderr_sha256"]
            == linux_case["left"]["stderr_sha256"]
        )
        entry.update(
            {
                "arguments": list(report_arguments),
                "reports_parse_error": (
                    b"SyntaxError: Parse error" in stdout
                ),
                "linux_qt5_raw_differences": (
                    database_helper.raw_differences(
                        observation.summary(),
                        linux_case["left"],
                    )
                ),
                "linux_normalized_stdout_sha256": normalized_sha256,
                "linux_qt5_normalized_stdout_equal": normalized_equal,
                "linux_qt5_stderr_equal": stderr_equal,
            }
        )
        if case.name.endswith("_json"):
            valid = (
                database_helper.matrix_definitions.document_is_valid(
                    stdout, "json"
                )
            )
            linux_valid = linux_case["left_valid_json"]
            entry.update(
                {
                    "first_valid_json": valid,
                    "second_valid_json": valid,
                    "linux_qt5_valid_json": linux_valid,
                    "linux_qt5_valid_json_equal": (
                        valid == linux_valid
                    ),
                }
            )
            if valid != linux_valid:
                validity_failures.append(case.name)
        cases[case.name] = entry
        if entry["determinism_differences"]:
            determinism_failures.append(case.name)
        if observation.exit_code != linux_case["left"]["exit_code"]:
            exit_failures.append(case.name)
        if not stderr_equal:
            stderr_failures.append(case.name)
        if not normalized_equal:
            normalized_failures.append(case.name)

    case_count = len(definitions.ARCHIVE_CASES)
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": DATABASE_ARCHIVE_COLLECTOR.PLATFORM,
        "generator": (
            DATABASE_ARCHIVE_COLLECTOR._generator_bindings(ROOT)
        ),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                oracle_path.read_bytes()
            ).hexdigest(),
        },
        "source": {
            "repository": (
                "https://github.com/horsicq/DIE-engine"
            ),
            "commit": VALIDATOR.UPSTREAM_COMMIT,
            "recursive_submodule_count": 58,
            "rules_commit": VALIDATOR.RULES_COMMIT,
            "tracked_files_clean_before_and_after": True,
        },
        "qt": {
            "version": oracle["qt"]["version"],
            "qmake_spec": oracle["qt"]["qmake_spec"],
            "qmake_sha256": oracle["qt"]["qmake_sha256"],
            "qtcore_sha256": oracle["qt"]["qtcore_sha256"],
            "qtscript_sha256": oracle["qt"]["qtscript_sha256"],
        },
        "binary": {
            "size": oracle["artifact"]["size"],
            "sha256": oracle["artifact"]["sha256"],
            "relative_path": "build/release/diec",
        },
        "fixture": {
            "manifest": (
                DATABASE_ARCHIVE_COLLECTOR.FIXTURE_MANIFEST
            ),
            "sha256": fixture_sha256,
            "directories": fixture["directories"],
            "entries": fixture["entries"],
        },
        "linux_qt5_reference": {
            "path": DATABASE_ARCHIVE_COLLECTOR.LINUX_REFERENCE,
            "sha256": hashlib.sha256(linux_raw).hexdigest(),
        },
        "local_paths": {
            "fixture_dir": str(fixture_dir),
        },
        "cases": cases,
        "summary": {
            "case_count": case_count,
            "execution_count": 2 * case_count,
            "raw_stream_count": 4 * case_count,
            "determinism_failures": determinism_failures,
            "linux_exit_code_failures": exit_failures,
            "linux_stderr_failures": stderr_failures,
            "linux_document_validity_failures": validity_failures,
            "linux_normalized_stdout_failures": normalized_failures,
            "deterministic": not determinism_failures,
            "linux_exit_codes_equal": not exit_failures,
            "linux_stderr_equal": not stderr_failures,
            "linux_document_validity_equal": not validity_failures,
            "linux_normalized_stdout_equal": not normalized_failures,
        },
        "normalization": DATABASE_ARCHIVE_COLLECTOR.NORMALIZATION,
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": DATABASE_ARCHIVE_COLLECTOR.ADMISSION_REASON,
        },
        "limitations": DATABASE_ARCHIVE_COLLECTOR.LIMITATIONS,
    }
    report_path = (
        directory / "cli-database-archive-candidate.json"
    )
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path


def write_special_path_fixture_candidate_bundle(
    directory: Path,
) -> Path:
    manifest_raw = (
        ROOT / SPECIAL_FIXTURE_GENERATOR.BASELINE_MANIFEST
    ).read_bytes()
    manifest = json.loads(manifest_raw)
    sample = next(
        item
        for item in manifest["samples"]
        if item["name"] == SPECIAL_FIXTURE_GENERATOR.SOURCE_NAME
    )
    entries = []
    inventory = {
        name: [] for name in SPECIAL_FIXTURE_GENERATOR.DIRECTORIES
    }
    for case_id, relative in (
        SPECIAL_FIXTURE_GENERATOR.STABLE_ENTRIES
    ):
        parent, name = relative.rsplit("/", 1)
        name_hex = name.encode().hex()
        entries.append(
            {
                "id": case_id,
                "path": relative,
                "directory_name_bytes_hex": name_hex,
                "size": sample["size"],
                "sha256": sample["sha256"],
            }
        )
        inventory[parent].append(name_hex)
    raw_attempts = []
    for name in SPECIAL_FIXTURE_GENERATOR.RAW_NAMES:
        item = {
            "name_bytes_hex": name.hex(),
            "created": True,
            "errno": None,
            "size": sample["size"],
            "sha256": sample["sha256"],
        }
        raw_attempts.append(item)
        inventory["nonutf8"].append(item["name_bytes_hex"])
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": SPECIAL_FIXTURE_GENERATOR.PLATFORM,
        "generator": {
            "path": SPECIAL_FIXTURE_GENERATOR.GENERATOR,
            "sha256": hashlib.sha256(
                (
                    ROOT
                    / SPECIAL_FIXTURE_GENERATOR.GENERATOR
                ).read_bytes()
            ).hexdigest(),
            "validator_path": SPECIAL_FIXTURE_GENERATOR.VALIDATOR,
            "validator_sha256": hashlib.sha256(
                (
                    ROOT
                    / SPECIAL_FIXTURE_GENERATOR.VALIDATOR
                ).read_bytes()
            ).hexdigest(),
        },
        "source": {
            "manifest": (
                SPECIAL_FIXTURE_GENERATOR.BASELINE_MANIFEST
            ),
            "manifest_sha256": hashlib.sha256(
                manifest_raw
            ).hexdigest(),
            "sample": SPECIAL_FIXTURE_GENERATOR.SOURCE_NAME,
            "size": sample["size"],
            "sha256": sample["sha256"],
        },
        "fixture": {
            "local_path": "/private/tmp/macos-special-path",
            "directories": list(
                SPECIAL_FIXTURE_GENERATOR.DIRECTORIES
            ),
            "entries": entries,
            "raw_attempts": raw_attempts,
            "directory_inventory_name_bytes_hex": inventory,
        },
        "filesystem_observations": {
            "lowercase_alias_exists_after_upper_create": True,
            "lowercase_alias_is_same_file": True,
            "case_distinct_names_materialized": False,
            "nfd_alias_exists_after_nfc_create": True,
            "nfd_alias_is_same_file": True,
            "nfc_nfd_distinct_names_materialized": False,
        },
        "admission": {
            "fixture_admitted": False,
            "capability_rows_admitted": 0,
            "reason": SPECIAL_FIXTURE_GENERATOR.ADMISSION_REASON,
        },
        "limitations": SPECIAL_FIXTURE_GENERATOR.LIMITATIONS,
    }
    report_path = directory / "special-path-fixture-candidate.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path


def write_cli_special_path_candidate_bundle(
    directory: Path,
    baseline_path: Path,
    fixture_path: Path,
) -> Path:
    baseline = CLI_VALIDATOR.load_json(baseline_path)[0]
    fixture_report = SPECIAL_FIXTURE_VALIDATOR.load_json(
        fixture_path
    )[0]
    oracle_path = directory / "oracle-candidate.json"
    source_dir = PurePosixPath(
        "/private/tmp/source"
    )
    fixture_dir = PurePosixPath(
        fixture_report["fixture"]["local_path"]
    )
    binary_dir = PurePosixPath(
        "/private/tmp/source/build/release"
    )
    case_contracts = SPECIAL_PATH_COLLECTOR.build_cases(
        source_dir=source_dir,
        fixture_dir=fixture_dir,
        binary_dir=binary_dir,
        fixture_generator=SPECIAL_FIXTURE_GENERATOR,
    )
    reference_tree = baseline["corpus"]["minimal.pdf"][
        "first_detect_tree"
    ]
    entries_by_id = {
        entry["id"]: entry
        for entry in fixture_report["fixture"]["entries"]
    }
    raw_tokens = [
        f"raw:{attempt['name_bytes_hex']}"
        for attempt in fixture_report["fixture"]["raw_attempts"]
        if attempt["created"]
    ]

    def prefix_line(token: str) -> bytes:
        if token.startswith("raw:"):
            name = bytes.fromhex(token.removeprefix("raw:"))
            parent = str(fixture_dir / "nonutf8").encode()
        else:
            entry = entries_by_id[token]
            relative = entry["path"]
            parent_name = relative.rsplit("/", 1)[0]
            parent = str(
                fixture_dir.joinpath(*parent_name.split("/"))
            ).encode()
            name = bytes.fromhex(
                entry["directory_name_bytes_hex"]
            )
        return parent + b"/" + name + b":\n"

    special_sequence = [
        entry["id"]
        for entry in fixture_report["fixture"]["entries"]
        if entry["path"].startswith("special/")
    ]
    reports = {}
    determinism_failures = []
    exit_failures = []
    projection_failures = []
    for case in case_contracts:
        if case.name == "directory_special":
            tokens = special_sequence
            stdout = b"".join(prefix_line(token) for token in tokens)
        elif case.name == "directory_nonutf8":
            tokens = raw_tokens
            stdout = b"".join(prefix_line(token) for token in tokens)
        elif case.name == "explicit_order":
            tokens = ["emoji", "nfc", "ascii"]
            stdout = b"".join(prefix_line(token) for token in tokens)
        elif case.name == "leading_dash_relative_unescaped":
            tokens = []
            stdout = b""
        else:
            tokens = []
            stdout = json.dumps(
                {"detects": reference_tree},
                separators=(",", ":"),
            ).encode()
        observation = CLI_COMMON.Observation(
            case.expected_exit, stdout, b""
        )
        entry = CLI_COLLECTOR.pair_report(
            CLI_COMMON,
            directory,
            f"cli-special-path/{case.name}",
            observation,
            observation,
        )
        tree = CLI_COMMON.json_detect_tree(stdout)
        projection_equal = (
            tree == reference_tree
            if case.reference_projection_applies
            else None
        )
        entry.update(
            {
                "cwd": case.report_cwd,
                "arguments": list(case.report_arguments),
                "expected_exit_code": case.expected_exit,
                "expected_exit_code_equal": True,
                "first_valid_json": (
                    SPECIAL_PATH_COLLECTOR.valid_json(stdout)
                ),
                "second_valid_json": (
                    SPECIAL_PATH_COLLECTOR.valid_json(stdout)
                ),
                "first_detect_tree": tree,
                "second_detect_tree": tree,
                "reference_projection_applies": (
                    case.reference_projection_applies
                ),
                "minimal_pdf_detect_tree_equal": projection_equal,
                "first_prefix_tokens": tokens,
                "second_prefix_tokens": tokens,
            }
        )
        reports[case.name] = entry
        if entry["determinism_differences"]:
            determinism_failures.append(case.name)
        if observation.exit_code != case.expected_exit:
            exit_failures.append(case.name)
        if (
            case.reference_projection_applies
            and tree != reference_tree
        ):
            projection_failures.append(case.name)

    logical = SPECIAL_PATH_COLLECTOR.logical_entries(
        SPECIAL_FIXTURE_GENERATOR
    )
    case_count = len(case_contracts)
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": SPECIAL_PATH_COLLECTOR.PLATFORM,
        "generator": SPECIAL_PATH_COLLECTOR._generator_bindings(
            ROOT
        ),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                oracle_path.read_bytes()
            ).hexdigest(),
        },
        "cli_baseline_report": {
            "path": "cli-baseline-candidate.json",
            "sha256": hashlib.sha256(
                baseline_path.read_bytes()
            ).hexdigest(),
        },
        "fixture_report": {
            "path": "special-path-fixture-candidate.json",
            "sha256": hashlib.sha256(
                fixture_path.read_bytes()
            ).hexdigest(),
        },
        "source": baseline["source"],
        "qt": baseline["qt"],
        "binary": baseline["binary"],
        "selection": {
            "logical_entries": [
                {"id": case_id, "path": relative}
                for case_id, relative in logical
            ],
            "case_names": [case.name for case in case_contracts],
        },
        "cases": reports,
        "findings": {
            "logical_single_case_count": len(logical),
            "directory_special_sequence": special_sequence,
            "directory_nonutf8_sequence": raw_tokens,
            "explicit_target_sequence": [
                "emoji",
                "nfc",
                "ascii",
            ],
            "explicit_target_order_is_preserved": True,
            "case_alias_same_file": True,
            "unicode_alias_same_file": True,
            "created_raw_name_count": len(raw_tokens),
            (
                "leading_dash_requires_option_terminator_when_relative"
            ): True,
        },
        "summary": {
            "case_count": case_count,
            "execution_count": 2 * case_count,
            "raw_stream_count": 4 * case_count,
            "determinism_failures": determinism_failures,
            "expected_exit_failures": exit_failures,
            "reference_projection_failures": projection_failures,
            "deterministic": not determinism_failures,
            "expected_exits_equal": not exit_failures,
            "reference_projections_equal": not projection_failures,
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": SPECIAL_PATH_COLLECTOR.ADMISSION_REASON,
        },
        "limitations": SPECIAL_PATH_COLLECTOR.LIMITATIONS,
    }
    report_path = directory / "cli-special-path-candidate.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path


def write_cli_filesystem_candidate_bundle(
    directory: Path, baseline_path: Path
) -> Path:
    oracle_path = directory / "oracle-candidate.json"
    baseline = CLI_VALIDATOR.load_json(baseline_path)[0]
    fixture_raw = (
        ROOT / FILESYSTEM_COLLECTOR.FIXTURE_MANIFEST
    ).read_bytes()
    fixture = json.loads(fixture_raw)
    linux_raw = (
        ROOT / FILESYSTEM_COLLECTOR.LINUX_REFERENCE
    ).read_bytes()
    linux = json.loads(linux_raw)
    fixture_dir = PurePosixPath("/private/tmp/filesystem-fixture")
    reference_tree = baseline["corpus"]["minimal.pdf"][
        "first_detect_tree"
    ]
    body = json.dumps(
        {"detects": reference_tree}, separators=(",", ":")
    ).encode("utf-8")

    def observation_for(case):
        projection = FILESYSTEM_COLLECTOR._linux_projection(
            linux, case.linux_case
        )
        if case.name == "dangling_symlink":
            stdout = b"Cannot find: fixture\n"
        elif case.name == "denied_as_runner":
            stdout = b""
        elif case.name == "symlink_tree":
            relative_paths = [
                "paths/symlink/dir-link/child.pdf",
                "paths/symlink/dir-target/child.pdf",
                "paths/symlink/file-link.pdf",
                "paths/symlink/target.pdf",
            ]
            stdout = b"".join(
                (
                    str(fixture_dir / relative).encode("utf-8")
                    + b":\n"
                    + body
                    + b"\n"
                )
                for relative in relative_paths
            )
        elif case.name == "self_cycle":
            stdout = b"".join(
                (
                    str(
                        fixture_dir
                        / "paths"
                        / "cycle"
                        / Path(*(["loop"] * depth))
                        / "root.pdf"
                    ).encode("utf-8")
                    + b":\n"
                    + body
                    + b"\n"
                )
                for depth in range(40, -1, -1)
            )
        else:
            stdout = body
        observation = CLI_COMMON.Observation(
            projection["exit_code"], stdout, b""
        )
        assert (
            FILESYSTEM_COLLECTOR.stdout_summary(stdout)
            == projection["stdout_summary"]
        )
        return observation

    report_db = FILESYSTEM_COLLECTOR.database_arguments(
        Path("<source>"), report=True
    )
    cases = {}
    for case in FILESYSTEM_COLLECTOR.CASES:
        observation = observation_for(case)
        entry = CLI_COLLECTOR.pair_report(
            CLI_COMMON,
            directory,
            f"cli-filesystem/{case.name}",
            observation,
            observation,
        )
        tree = CLI_COMMON.json_detect_tree(observation.stdout)
        projection = FILESYSTEM_COLLECTOR._linux_projection(
            linux, case.linux_case
        )
        summary = FILESYSTEM_COLLECTOR.stdout_summary(
            observation.stdout
        )
        entry.update(
            {
                "arguments": [
                    "--json",
                    *report_db,
                    f"<fixture>/{case.relative}",
                ],
                "timeout_seconds": (
                    case.timeout_cap_seconds or 120
                ),
                "first_timed_out": False,
                "second_timed_out": False,
                "first_stdout_summary": summary,
                "second_stdout_summary": summary,
                "first_prefix_paths": (
                    FILESYSTEM_COLLECTOR.prefix_paths(
                        observation.stdout, fixture_dir
                    )
                ),
                "second_prefix_paths": (
                    FILESYSTEM_COLLECTOR.prefix_paths(
                        observation.stdout, fixture_dir
                    )
                ),
                "first_detect_tree": tree,
                "second_detect_tree": tree,
                "reference_tree_applies": (
                    case.reference_tree_applies
                ),
                "minimal_pdf_detect_tree_equal": (
                    tree == reference_tree
                    if case.reference_tree_applies
                    else None
                ),
                "linux_case": case.linux_case,
                "linux_qt5_projection": projection,
                "linux_qt5_semantic_equal": True,
            }
        )
        cases[case.name] = entry

    count = len(FILESYSTEM_COLLECTOR.CASES)
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": FILESYSTEM_COLLECTOR.PLATFORM,
        "generator": FILESYSTEM_COLLECTOR._generator_bindings(ROOT),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                oracle_path.read_bytes()
            ).hexdigest(),
        },
        "cli_baseline_report": {
            "path": "cli-baseline-candidate.json",
            "sha256": hashlib.sha256(
                baseline_path.read_bytes()
            ).hexdigest(),
        },
        "source": baseline["source"],
        "qt": baseline["qt"],
        "binary": baseline["binary"],
        "fixture": {
            "manifest": FILESYSTEM_COLLECTOR.FIXTURE_MANIFEST,
            "manifest_sha256": hashlib.sha256(
                fixture_raw
            ).hexdigest(),
            "archive_sha256": fixture["archive"]["sha256"],
            "archive_size": fixture["archive"]["size"],
            "entry_count": len(fixture["entries"]),
            "live_preflight": {
                "effective_uid": 501,
                "effective_gid": 20,
                "denied_mode": 0,
                "denied_read_execute_access": False,
                "deep_component_count": 64,
                "symlink_targets": {
                    "file_link": "target.pdf",
                    "directory_link": "dir-target",
                    "dangling_link": "missing.pdf",
                    "cycle_link": ".",
                },
            },
        },
        "linux_qt5_reference": {
            "path": FILESYSTEM_COLLECTOR.LINUX_REFERENCE,
            "sha256": hashlib.sha256(linux_raw).hexdigest(),
        },
        "local_paths": {"fixture_dir": str(fixture_dir)},
        "selection": {
            "case_names": [
                case.name for case in FILESYSTEM_COLLECTOR.CASES
            ],
            "minimum_repetitions_per_case": 2,
        },
        "cases": cases,
        "summary": {
            "case_count": count,
            "execution_count": 2 * count,
            "raw_stream_count": 4 * count,
            "determinism_failures": [],
            "timeout_cases": [],
            "linux_semantic_failures": [],
            "reference_projection_failures": [],
            "deterministic": True,
            "linux_semantics_equal": True,
            "reference_projections_equal": True,
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": FILESYSTEM_COLLECTOR.ADMISSION_REASON,
        },
        "limitations": FILESYSTEM_COLLECTOR.LIMITATIONS,
    }
    report_path = directory / "cli-filesystem-candidate.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path


def write_cli_large_directory_candidate_bundle(
    directory: Path, baseline_path: Path
) -> Path:
    oracle_path = directory / "oracle-candidate.json"
    baseline = CLI_VALIDATOR.load_json(baseline_path)[0]
    fixture_raw = (
        ROOT / LARGE_DIRECTORY_COLLECTOR.FIXTURE_MANIFEST
    ).read_bytes()
    fixture = json.loads(fixture_raw)
    linux_raw = (
        ROOT / LARGE_DIRECTORY_COLLECTOR.LINUX_REFERENCE
    ).read_bytes()
    linux = json.loads(linux_raw)
    fixture_dir = PurePosixPath(
        "/private/tmp/large-directory-fixture"
    )
    body = b'{"total": 0}'
    report_db = LARGE_DIRECTORY_COLLECTOR.database_arguments(
        Path("<source>"), report=True
    )
    cases = {}
    for case in fixture["cases"]:
        name = case["name"]
        expected = LARGE_DIRECTORY_COLLECTOR.expected_prefixes(
            LARGE_DIRECTORY_MATERIALIZER, case
        )
        if not expected and case["file_count"] == 0:
            stdout = b""
        elif not expected:
            stdout = body
        else:
            case_dir = fixture_dir / name
            stdout = b"".join(
                (
                    str(case_dir / relative).encode("utf-8")
                    + b":\n"
                    + body
                    + b"\n"
                )
                for relative in expected
            )
        observation = CLI_COMMON.Observation(0, stdout, b"")
        entry = CLI_COLLECTOR.pair_report(
            CLI_COMMON,
            directory,
            f"cli-large-directory/{name}",
            observation,
            observation,
        )
        prefixes = LARGE_DIRECTORY_COLLECTOR.prefix_relatives(
            stdout, fixture_dir / name
        )
        documents = (
            LARGE_DIRECTORY_COLLECTOR.entropy_document_count(
                stdout
            )
        )
        projection = LARGE_DIRECTORY_COLLECTOR.linux_projection(
            linux, name
        )
        entry.update(
            {
                "arguments": [
                    "--entropy",
                    "--json",
                    *report_db,
                    f"<fixture>/{name}",
                ],
                "timeout_seconds": 60,
                "first_timed_out": False,
                "second_timed_out": False,
                "first_entropy_document_count": documents,
                "second_entropy_document_count": documents,
                "first_prefix_count": len(prefixes),
                "second_prefix_count": len(prefixes),
                "first_prefix": (
                    prefixes[0] if prefixes else None
                ),
                "last_prefix": (
                    prefixes[-1] if prefixes else None
                ),
                "first_prefixes_sha256": (
                    LARGE_DIRECTORY_COLLECTOR.sequence_sha256(
                        prefixes
                    )
                ),
                "second_prefixes_sha256": (
                    LARGE_DIRECTORY_COLLECTOR.sequence_sha256(
                        prefixes
                    )
                ),
                "expected_name_order_sha256": (
                    LARGE_DIRECTORY_COLLECTOR.sequence_sha256(
                        expected
                    )
                ),
                "complete_name_order_equal": prefixes == expected,
                "linux_qt5_projection": projection,
                "linux_qt5_semantic_equal": (
                    observation.exit_code
                    == projection["exit_code"]
                    and documents
                    == projection["entropy_document_count"]
                    and len(prefixes) == projection["prefix_count"]
                ),
            }
        )
        cases[name] = entry

    preflight = {
        case["name"]: LARGE_DIRECTORY_MATERIALIZER.preflight(case)
        for case in fixture["cases"]
    }
    count = len(fixture["cases"])
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": LARGE_DIRECTORY_COLLECTOR.PLATFORM,
        "generator": LARGE_DIRECTORY_COLLECTOR._generator_bindings(
            ROOT
        ),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                oracle_path.read_bytes()
            ).hexdigest(),
        },
        "cli_baseline_report": {
            "path": "cli-baseline-candidate.json",
            "sha256": hashlib.sha256(
                baseline_path.read_bytes()
            ).hexdigest(),
        },
        "source": baseline["source"],
        "qt": baseline["qt"],
        "binary": baseline["binary"],
        "fixture": {
            "manifest": LARGE_DIRECTORY_COLLECTOR.FIXTURE_MANIFEST,
            "manifest_sha256": hashlib.sha256(
                fixture_raw
            ).hexdigest(),
            "materializer": (
                LARGE_DIRECTORY_COLLECTOR.FIXTURE_MATERIALIZER
            ),
            "case_count": count,
            "planned_file_count": sum(
                case["file_count"] for case in fixture["cases"]
            ),
            "live_preflight": preflight,
        },
        "linux_qt5_reference": {
            "path": LARGE_DIRECTORY_COLLECTOR.LINUX_REFERENCE,
            "sha256": hashlib.sha256(linux_raw).hexdigest(),
        },
        "local_paths": {"fixture_dir": str(fixture_dir)},
        "selection": {
            "case_names": [
                case["name"] for case in fixture["cases"]
            ],
            "minimum_repetitions_per_case": 2,
        },
        "cases": cases,
        "summary": {
            "case_count": count,
            "execution_count": 2 * count,
            "raw_stream_count": 4 * count,
            "determinism_failures": [],
            "timeout_cases": [],
            "linux_semantic_failures": [],
            "name_order_failures": [],
            "deterministic": True,
            "linux_semantics_equal": True,
            "complete_name_order_equal": True,
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": LARGE_DIRECTORY_COLLECTOR.ADMISSION_REASON,
        },
        "limitations": LARGE_DIRECTORY_COLLECTOR.LIMITATIONS,
    }
    report_path = (
        directory / "cli-large-directory-candidate.json"
    )
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path


def write_long_path_fixture_candidate_bundle(
    directory: Path,
) -> Path:
    generator = LONG_PATH_FIXTURE_GENERATOR
    base = PurePosixPath("/private/tmp/die-macos-long-path")
    payload = BASELINE_CORPUS_GENERATOR.make_pdf()
    cases = []

    def append(
        case_id,
        kind,
        relative,
        boundary,
        target,
        *,
        created=True,
    ):
        attempt = (
            {"created": True, "errno": None, "errno_name": None}
            if created
            else {
                "created": False,
                "errno": errno.ENAMETOOLONG,
                "errno_name": "ENAMETOOLONG",
            }
        )
        cases.append(
            generator._case_record(
                case_id=case_id,
                kind=kind,
                fixture_dir=base,
                relative=relative,
                attempt=attempt,
                payload=payload,
                target_boundary=boundary,
                target_bytes=target,
            )
        )

    control = "control/target.pdf"
    append(
        "control",
        "control",
        control,
        "control",
        len(f"{base}/{control}".encode("ascii")),
    )
    for boundary, value in (
        ("path_max", generator.XNU_PATH_MAX),
        ("max_long_path", generator.XNU_MAXLONGPATHLEN),
    ):
        for delta in generator.FULL_PATH_DELTAS:
            target = value + delta
            append(
                f"{boundary}_{delta:+d}",
                "full_path",
                generator.build_full_relative_path(base, target),
                boundary,
                target,
            )
    for delta in generator.COMPONENT_DELTAS:
        target = generator.XNU_NAME_MAX + delta
        append(
            f"name_max_{delta:+d}",
            "component",
            (
                "components/"
                + generator.build_component_name(target)
            ),
            "name_max",
            target,
            created=delta <= 0,
        )
    baseline_raw = (
        ROOT / generator.BASELINE_MANIFEST
    ).read_bytes()
    report = {
        "schema_version": generator.SCHEMA_VERSION,
        "result": "candidate",
        "platform": generator.PLATFORM,
        "generator": generator.generator_binding(ROOT),
        "xnu_reference": {
            "repository": (
                "https://github.com/apple-oss-distributions/xnu"
            ),
            "commit": generator.XNU_COMMIT,
            "source": generator.XNU_SOURCE,
            "source_url": generator.XNU_SOURCE_URL,
            "source_sha256": generator.XNU_SOURCE_SHA256,
            "name_max": generator.XNU_NAME_MAX,
            "path_max": generator.XNU_PATH_MAX,
            "kernel_private_max_long_path": (
                generator.XNU_MAXLONGPATHLEN
            ),
        },
        "baseline": {
            "manifest": generator.BASELINE_MANIFEST,
            "manifest_sha256": hashlib.sha256(
                baseline_raw
            ).hexdigest(),
            "sample": generator.SOURCE_NAME,
            "payload_size": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        },
        "filesystem_limits": {
            "pathconf_name_max": generator.XNU_NAME_MAX,
            "pathconf_path_max": generator.XNU_PATH_MAX,
        },
        "fixture": {
            "local_path": str(base),
            "local_path_bytes": len(str(base).encode("ascii")),
            "case_ids": [case["id"] for case in cases],
            "cases": cases,
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": generator.ADMISSION_REASON,
        },
        "limitations": generator.LIMITATIONS,
    }
    path = directory / "long-path-fixture-candidate.json"
    path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return path


def write_cli_long_path_candidate_bundle(
    directory: Path,
    baseline_path: Path,
    fixture_path: Path,
) -> Path:
    baseline = CLI_VALIDATOR.load_json(baseline_path)[0]
    oracle_path = directory / "oracle-candidate.json"
    fixture = LONG_PATH_FIXTURE_VALIDATOR.load_json(
        fixture_path
    )[0]
    reference_tree = baseline["corpus"]["minimal.pdf"][
        "first_detect_tree"
    ]
    body = json.dumps(
        {"detects": reference_tree}, separators=(",", ":")
    ).encode("utf-8")
    report_db = LONG_PATH_COLLECTOR.database_arguments(
        Path("<source>"), report=True
    )
    fixture_records = {
        case["id"]: case for case in fixture["fixture"]["cases"]
    }
    cases = {}
    for case in LONG_PATH_COLLECTOR.build_cases(fixture):
        if case.mode == "component_directory":
            created = [
                record
                for record in fixture_records.values()
                if record["kind"] == "component"
                and record["attempt"]["created"]
            ]
            stdout = b"".join(
                (
                    record["absolute_path"].encode("ascii")
                    + b":\n"
                    + body
                    + b"\n"
                )
                for record in created
            )
            exit_code = 0
        elif case.reference_projection_applies:
            stdout = body
            exit_code = 0
        else:
            stdout = b"Cannot find: fixture\n"
            exit_code = 1
        observation = CLI_COMMON.Observation(
            exit_code, stdout, b""
        )
        entry = CLI_COLLECTOR.pair_report(
            CLI_COMMON,
            directory,
            f"cli-long-path/{case.name}",
            observation,
            observation,
        )
        tree = CLI_COMMON.json_detect_tree(stdout)
        reference_equal = (
            tree == reference_tree
            if case.reference_projection_applies
            else None
        )
        entry.update(
            {
                "arguments": [
                    "--json",
                    *report_db,
                    case.report_target,
                ],
                "mode": case.mode,
                "fixture_case_id": case.fixture_case_id,
                "reference_projection_applies": (
                    case.reference_projection_applies
                ),
                "timeout_seconds": 120,
                "first_timed_out": False,
                "second_timed_out": False,
                "first_valid_json": (
                    LONG_PATH_COLLECTOR.valid_json(stdout)
                ),
                "second_valid_json": (
                    LONG_PATH_COLLECTOR.valid_json(stdout)
                ),
                "first_detect_tree": tree,
                "second_detect_tree": tree,
                "minimal_pdf_detect_tree_equal": reference_equal,
                "first_prefix_case_ids": (
                    LONG_PATH_COLLECTOR.prefix_case_ids(
                        stdout, fixture
                    )
                ),
                "second_prefix_case_ids": (
                    LONG_PATH_COLLECTOR.prefix_case_ids(
                        stdout, fixture
                    )
                ),
            }
        )
        cases[case.name] = entry
    count = len(cases)
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": LONG_PATH_COLLECTOR.PLATFORM,
        "generator": LONG_PATH_COLLECTOR._generator_bindings(ROOT),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                oracle_path.read_bytes()
            ).hexdigest(),
        },
        "cli_baseline_report": {
            "path": "cli-baseline-candidate.json",
            "sha256": hashlib.sha256(
                baseline_path.read_bytes()
            ).hexdigest(),
        },
        "fixture_report": {
            "path": "long-path-fixture-candidate.json",
            "sha256": hashlib.sha256(
                fixture_path.read_bytes()
            ).hexdigest(),
        },
        "source": baseline["source"],
        "qt": baseline["qt"],
        "binary": baseline["binary"],
        "selection": {
            "case_names": list(cases),
            "minimum_repetitions_per_case": 2,
        },
        "cases": cases,
        "summary": {
            "case_count": count,
            "execution_count": 2 * count,
            "raw_stream_count": 4 * count,
            "determinism_failures": [],
            "timeout_cases": [],
            "reference_projection_failures": [],
            "deterministic": True,
            "reference_projections_equal": True,
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": LONG_PATH_COLLECTOR.ADMISSION_REASON,
        },
        "limitations": LONG_PATH_COLLECTOR.LIMITATIONS,
    }
    path = directory / "cli-long-path-candidate.json"
    path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return path


class MacosQt5OracleBootstrapTests(unittest.TestCase):
    def test_plan_is_exact_generator_output_and_source_bound(self):
        report = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
        expected = PLAN.build_plan(ROOT)
        self.assertEqual(report, expected)
        self.assertEqual(PLAN_PATH.read_bytes(), PLAN.serialize(expected))
        for relative, digest in report["sources"].items():
            with self.subTest(path=relative):
                self.assertEqual(
                    hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                    digest,
                )

    def test_plan_keeps_runtime_and_platform_admission_open(self):
        report = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            report["result"],
            "infrastructure_ready_runtime_missing",
        )
        self.assertFalse(report["admission"]["platform_admitted"])
        self.assertEqual(
            report["admission"]["coverage_status"],
            "platform_missing",
        )
        self.assertEqual(
            report["runtime_closure"]["required_capability_count"],
            68,
        )
        self.assertEqual(
            report["runtime_closure"]["minimum_repetitions_per_case"],
            2,
        )

    def test_shell_builder_is_fail_closed_and_cli_only(self):
        text = BUILD_SCRIPT.read_text(encoding="utf-8")
        for required in (
            VALIDATOR.UPSTREAM_COMMIT,
            VALIDATOR.RULES_COMMIT,
            'EXPECTED_SUBMODULE_COUNT=58',
            'EXPECTED_QT_VERSION="5.15.2"',
            'EXPECTED_QMAKE_SPEC="macx-clang"',
            'EXPECTED_ARCH="x86_64"',
            'git -C "$source_dir" submodule status --recursive',
            'build directory must be empty',
            'sub-build_libs-make_first',
            'sub-console_source-make_first',
            'tracked_files_clean_before_and_after',
            'platform_admitted": False',
            'validate_macos_qt5_oracle_report.py',
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        self.assertNotIn("rm -rf", text)
        self.assertNotIn("gui_source", text)
        self.assertNotIn("lite_source", text)

    def test_dispatch_workflow_is_manual_pinned_and_non_admitting(self):
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        for required in (
            "workflow_dispatch:",
            "runs-on: macos-15-intel",
            "contents: read",
            "persist-credentials: false",
            "aqtinstall==${AQTINSTALL_VERSION}",
            "mac desktop 5.15.2 clang_64",
            "--modules qtscript",
            VALIDATOR.UPSTREAM_COMMIT,
            "submodule update",
            "--init --recursive --depth=1 --jobs 4",
            "build_macos_qt5_oracle.sh",
            "validate_macos_qt5_oracle_report.py",
            "collect_macos_cache_state_candidate.py",
            "validate_macos_cache_state_candidate.py",
            "generate_baseline_corpus.py",
            "collect_macos_cli_baseline.py",
            "validate_macos_cli_baseline.py",
            "collect_macos_cli_matrix.py",
            "validate_macos_cli_matrix.py",
            "collect_macos_cli_remaining.py",
            "validate_macos_cli_remaining.py",
            "generate_database_fixture.py",
            "collect_macos_cli_database.py",
            "validate_macos_cli_database.py",
            "generate_path_corpus.py",
            "generate_nested_corpus.py",
            "generate_macos_special_path_fixture.py",
            "generate_path_filesystem_fixture.py",
            "materialize_large_path_fixture.py",
            "generate_macos_long_path_fixture.py",
            "validate_macos_long_path_fixture.py",
            "validate_macos_special_path_fixture.py",
            "collect_macos_cli_path_nested.py",
            "validate_macos_cli_path_nested.py",
            "collect_macos_cli_database_archives.py",
            "validate_macos_cli_database_archives.py",
            "collect_macos_cli_special_paths.py",
            "validate_macos_cli_special_paths.py",
            "collect_macos_cli_filesystem.py",
            "validate_macos_cli_filesystem.py",
            "collect_macos_cli_privilege_paths.py",
            "validate_macos_cli_privilege_paths.py",
            "collect_macos_cli_large_directory.py",
            "validate_macos_cli_large_directory.py",
            "collect_macos_cli_long_paths.py",
            "validate_macos_cli_long_paths.py",
            "collect_macos_cli_toctou.py",
            "validate_macos_cli_toctou.py",
            "build_macos_database_cache_harness.py",
            "validate_macos_database_cache_harness_build.py",
            "collect_macos_database_cache_harness.py",
            "validate_macos_database_cache_harness.py",
            "database-cache-harness-build-candidate.json",
            "database-cache-harness-candidate",
            "database-cache-engine-candidate.json",
            "die-macos-candidate-evidence/build-input",
            "cli-baseline-candidate.json",
            "cli-matrix-candidate.json",
            "cli-remaining-candidate.json",
            "cli-database-candidate.json",
            "cli-path-nested-candidate.json",
            "cli-database-archive-candidate.json",
            "special-path-fixture-candidate.json",
            "cli-special-path-candidate.json",
            "cli-filesystem-candidate.json",
            "cli-privilege-path-candidate.json",
            "cli-large-directory-candidate.json",
            "long-path-fixture-candidate.json",
            "cli-long-path-candidate.json",
            "cli-toctou-candidate.json",
            "database-cache-harness-build-candidate.json",
            "database-cache-engine-candidate.json",
            "die-macos-candidate-evidence/raw",
            (
                "actions/checkout@"
                "de0fac2e4500dabe0009e67214ff5f5447ce83dd"
            ),
            (
                "actions/upload-artifact@"
                "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
            ),
            "retention-days: 14",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        for forbidden in (
            "macos-latest",
            "pull_request:",
            "push:",
            "@v4",
            "@v5",
            "@v6",
            "@v7",
            "platform_admitted",
            "cache_state_admitted",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

        report = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
        workflow = report["dispatch_workflow"]
        self.assertEqual(workflow["trigger"], "workflow_dispatch")
        self.assertEqual(workflow["runner"], "macos-15-intel")
        self.assertFalse(workflow["automatically_admits_evidence"])
        self.assertTrue(workflow["raw_cli_streams_retained"])
        self.assertEqual(
            workflow["candidate_reports"],
            [
                "oracle-candidate.json",
                "cache-state-candidate.json",
                "cli-baseline-candidate.json",
                "cli-matrix-candidate.json",
                "cli-remaining-candidate.json",
                "cli-database-candidate.json",
                "cli-path-nested-candidate.json",
                "cli-database-archive-candidate.json",
                "special-path-fixture-candidate.json",
                "cli-special-path-candidate.json",
                "cli-filesystem-candidate.json",
                "cli-privilege-path-candidate.json",
                "cli-large-directory-candidate.json",
                "long-path-fixture-candidate.json",
                "cli-long-path-candidate.json",
                "cli-toctou-candidate.json",
                "database-cache-harness-build-candidate.json",
                "database-cache-engine-candidate.json",
            ],
        )
        self.assertTrue(workflow["special_path_fixture_candidate"])
        self.assertTrue(
            workflow["filesystem_path_fixture_candidate"]
        )
        self.assertTrue(workflow["privilege_path_cli_candidate"])
        self.assertTrue(
            workflow["large_directory_fixture_candidate"]
        )
        self.assertTrue(workflow["long_path_fixture_candidate"])
        self.assertTrue(workflow["toctou_cli_candidate"])
        self.assertTrue(
            workflow["database_cache_engine_candidate"]
        )
        self.assertEqual(
            workflow["remaining_cli_execution_count"], 1092
        )
        self.assertEqual(
            workflow["database_cli_execution_count"], 36
        )
        self.assertEqual(
            workflow["path_nested_cli_execution_count"], 92
        )
        self.assertEqual(
            workflow["database_archive_cli_execution_count"], 34
        )
        self.assertEqual(
            workflow["special_path_cli_execution_count"], 46
        )
        self.assertEqual(
            workflow["filesystem_cli_execution_count"], 16
        )
        self.assertEqual(
            workflow["privilege_path_cli_execution_count"], 24
        )
        self.assertEqual(
            workflow["large_directory_cli_execution_count"], 10
        )
        self.assertEqual(
            workflow["long_path_cli_execution_count"], 34
        )
        self.assertEqual(
            workflow["toctou_cli_execution_count"], 8
        )
        self.assertEqual(
            workflow["general_cli_execution_count"], 2132
        )
        self.assertEqual(
            workflow["general_cli_raw_stream_count"], 4264
        )
        self.assertEqual(
            workflow["engine_cache_execution_count"], 2
        )
        self.assertEqual(
            workflow["engine_cache_raw_stream_count"], 4
        )
        self.assertEqual(workflow["build_raw_stream_count"], 2)
        self.assertEqual(
            workflow["candidate_runtime_execution_count"], 2134
        )
        self.assertEqual(
            workflow["candidate_runtime_raw_stream_count"], 4268
        )

    def test_cli_candidate_tools_are_bound_and_fail_closed(self):
        collector = CLI_COLLECTOR_PATH.read_text(encoding="utf-8")
        validator = CLI_VALIDATOR_PATH.read_text(encoding="utf-8")
        for required in (
            "native Darwin x86_64",
            "oracle-candidate.json",
            "baseline-corpus-linux-qt5.json",
            "platform_admitted",
            "capability_rows_admitted",
            "write_observation",
            "determinism_failures",
            "linux_projection_failures",
        ):
            with self.subTest(required=required):
                self.assertIn(required, collector)
        for required in (
            "bundle-local oracle-candidate.json",
            "raw file inventory differs from report",
            "raw path escaped bundle",
            "candidate must not admit capability evidence",
            "determinism projection drift",
            "corpus projection drift",
        ):
            with self.subTest(required=required):
                self.assertIn(required, validator)
        self.assertEqual(
            CLI_COLLECTOR.ADMISSION_REASON,
            CLI_VALIDATOR.EXPECTED_ADMISSION_REASON,
        )
        self.assertEqual(
            CLI_COLLECTOR.LIMITATIONS,
            CLI_VALIDATOR.EXPECTED_LIMITATIONS,
        )

    def test_cli_candidate_validator_recomputes_raw_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report_path = write_cli_candidate_bundle(directory)
            report = CLI_VALIDATOR.load_json(report_path)[0]
            oracle_path = directory / "oracle-candidate.json"
            CLI_VALIDATOR.validate_report(
                report,
                report_path=report_path,
                oracle_path=oracle_path,
                root=ROOT,
            )

            raw_path = directory / report["cases"]["help"]["first"][
                "stdout_path"
            ]
            raw_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                CLI_VALIDATOR.ReportError,
                "raw stream identity mismatch",
            ):
                CLI_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )

    def test_cli_candidate_validator_rejects_admission_and_extra_raw(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report_path = write_cli_candidate_bundle(directory)
            report = CLI_VALIDATOR.load_json(report_path)[0]
            oracle_path = directory / "oracle-candidate.json"

            report["admission"]["platform_admitted"] = True
            with self.assertRaisesRegex(
                CLI_VALIDATOR.ReportError,
                "must not admit",
            ):
                CLI_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )
            report["admission"]["platform_admitted"] = False
            (
                directory
                / "raw"
                / "cli-baseline"
                / "undeclared"
            ).write_bytes(b"x")
            with self.assertRaisesRegex(
                CLI_VALIDATOR.ReportError,
                "raw file inventory",
            ):
                CLI_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )

    def test_cli_matrix_validator_recomputes_full_raw_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            baseline_path = write_cli_candidate_bundle(directory)
            matrix_path = write_cli_matrix_candidate_bundle(
                directory, baseline_path
            )
            report = CLI_VALIDATOR.load_json(matrix_path)[0]
            oracle_path = directory / "oracle-candidate.json"
            MATRIX_VALIDATOR.validate_report(
                report,
                report_path=matrix_path,
                oracle_path=oracle_path,
                baseline_path=baseline_path,
                root=ROOT,
            )
            self.assertEqual(report["summary"]["case_count"], 338)
            self.assertEqual(
                report["summary"]["execution_count"], 676
            )
            self.assertEqual(
                report["summary"]["raw_stream_count"], 1352
            )

            first = report["matrix"]["empty.bin"]["output"][
                "json"
            ]["first"]
            raw_path = directory / first["stdout_path"]
            original = raw_path.read_bytes()
            raw_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                MATRIX_VALIDATOR.ReportError,
                "raw stream identity mismatch",
            ):
                MATRIX_VALIDATOR.validate_report(
                    report,
                    report_path=matrix_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    root=ROOT,
                )
            raw_path.write_bytes(original)

            report["admission"]["platform_admitted"] = True
            with self.assertRaisesRegex(
                MATRIX_VALIDATOR.ReportError,
                "must not admit",
            ):
                MATRIX_VALIDATOR.validate_report(
                    report,
                    report_path=matrix_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    root=ROOT,
                )
            report["admission"]["platform_admitted"] = False

            extra = (
                directory
                / "raw"
                / "cli-matrix"
                / "undeclared"
            )
            extra.write_bytes(b"x")
            with self.assertRaisesRegex(
                MATRIX_VALIDATOR.ReportError,
                "raw file inventory",
            ):
                MATRIX_VALIDATOR.validate_report(
                    report,
                    report_path=matrix_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    root=ROOT,
                )

    def test_cli_remaining_validator_recomputes_full_raw_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            baseline_path = write_cli_candidate_bundle(directory)
            primary_path = write_cli_matrix_candidate_bundle(
                directory, baseline_path
            )
            report_path = write_cli_remaining_candidate_bundle(
                directory, baseline_path, primary_path
            )
            report = CLI_VALIDATOR.load_json(report_path)[0]
            oracle_path = directory / "oracle-candidate.json"
            REMAINING_VALIDATOR.validate_report(
                report,
                report_path=report_path,
                oracle_path=oracle_path,
                baseline_path=baseline_path,
                primary_path=primary_path,
                root=ROOT,
            )
            self.assertEqual(report["summary"]["case_count"], 546)
            self.assertEqual(
                report["summary"]["execution_count"], 1092
            )
            self.assertEqual(
                report["summary"]["raw_stream_count"], 2184
            )

            first = report["matrix"]["Minimal.class"]["output"][
                "json"
            ]["first"]
            raw_path = directory / first["stdout_path"]
            original = raw_path.read_bytes()
            raw_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                REMAINING_VALIDATOR.ReportError,
                "raw stream identity mismatch",
            ):
                REMAINING_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    primary_path=primary_path,
                    root=ROOT,
                )
            raw_path.write_bytes(original)

            report["admission"]["platform_admitted"] = True
            with self.assertRaisesRegex(
                REMAINING_VALIDATOR.ReportError,
                "must not admit",
            ):
                REMAINING_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    primary_path=primary_path,
                    root=ROOT,
                )
            report["admission"]["platform_admitted"] = False

            extra = (
                directory
                / "raw"
                / "cli-remaining"
                / "undeclared"
            )
            extra.write_bytes(b"x")
            with self.assertRaisesRegex(
                REMAINING_VALIDATOR.ReportError,
                "raw file inventory",
            ):
                REMAINING_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    primary_path=primary_path,
                    root=ROOT,
                )

    def test_cli_database_validator_recomputes_full_raw_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            oracle_path = directory / "oracle-candidate.json"
            oracle_path.write_text(
                json.dumps(candidate_report(), sort_keys=True),
                encoding="utf-8",
            )
            report_path = write_cli_database_candidate_bundle(
                directory
            )
            report = CLI_VALIDATOR.load_json(report_path)[0]
            DATABASE_VALIDATOR.validate_report(
                report,
                report_path=report_path,
                oracle_path=oracle_path,
                root=ROOT,
            )
            self.assertEqual(report["summary"]["case_count"], 18)
            self.assertEqual(
                report["summary"]["execution_count"], 36
            )
            self.assertEqual(
                report["summary"]["raw_stream_count"], 72
            )

            first = report["cases"][
                "scan_malformed_main_json"
            ]["first"]
            raw_path = directory / first["stdout_path"]
            original = raw_path.read_bytes()
            raw_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                DATABASE_VALIDATOR.ReportError,
                "raw stream identity mismatch",
            ):
                DATABASE_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )
            raw_path.write_bytes(original)

            report["admission"]["platform_admitted"] = True
            with self.assertRaisesRegex(
                DATABASE_VALIDATOR.ReportError,
                "must not admit",
            ):
                DATABASE_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )
            report["admission"]["platform_admitted"] = False

            extra = (
                directory
                / "raw"
                / "cli-database"
                / "undeclared"
            )
            extra.write_bytes(b"x")
            with self.assertRaisesRegex(
                DATABASE_VALIDATOR.ReportError,
                "raw file inventory",
            ):
                DATABASE_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )

    def test_cli_path_nested_validator_recomputes_full_raw_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            oracle_path = directory / "oracle-candidate.json"
            oracle_path.write_text(
                json.dumps(candidate_report(), sort_keys=True),
                encoding="utf-8",
            )
            report_path = write_cli_path_nested_candidate_bundle(
                directory
            )
            report = CLI_VALIDATOR.load_json(report_path)[0]
            PATH_NESTED_VALIDATOR.validate_report(
                report,
                report_path=report_path,
                oracle_path=oracle_path,
                root=ROOT,
            )
            self.assertEqual(report["summary"]["case_count"], 46)
            self.assertEqual(
                report["summary"]["execution_count"], 92
            )
            self.assertEqual(
                report["summary"]["raw_stream_count"], 184
            )

            first = report["nested"]["cases"][
                "pdf-member.zip"
            ]["recursive"]["first"]
            raw_path = directory / first["stdout_path"]
            original = raw_path.read_bytes()
            raw_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                PATH_NESTED_VALIDATOR.ReportError,
                "raw stream identity mismatch",
            ):
                PATH_NESTED_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )
            raw_path.write_bytes(original)

            report["admission"]["platform_admitted"] = True
            with self.assertRaisesRegex(
                PATH_NESTED_VALIDATOR.ReportError,
                "must not admit",
            ):
                PATH_NESTED_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )
            report["admission"]["platform_admitted"] = False

            extra = (
                directory
                / "raw"
                / "cli-path-nested"
                / "undeclared"
            )
            extra.write_bytes(b"x")
            with self.assertRaisesRegex(
                PATH_NESTED_VALIDATOR.ReportError,
                "raw file inventory",
            ):
                PATH_NESTED_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )

    def test_cli_database_archive_validator_recomputes_raw_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            oracle_path = directory / "oracle-candidate.json"
            oracle_path.write_text(
                json.dumps(candidate_report(), sort_keys=True),
                encoding="utf-8",
            )
            report_path = (
                write_cli_database_archive_candidate_bundle(
                    directory
                )
            )
            report = CLI_VALIDATOR.load_json(report_path)[0]
            DATABASE_ARCHIVE_VALIDATOR.validate_report(
                report,
                report_path=report_path,
                oracle_path=oracle_path,
                root=ROOT,
            )
            self.assertEqual(report["summary"]["case_count"], 17)
            self.assertEqual(
                report["summary"]["execution_count"], 34
            )
            self.assertEqual(
                report["summary"]["raw_stream_count"], 68
            )

            first = report["cases"][
                "scan_payload_structure_truncated_archive_json"
            ]["first"]
            raw_path = directory / first["stdout_path"]
            original = raw_path.read_bytes()
            raw_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                DATABASE_ARCHIVE_VALIDATOR.ReportError,
                "raw stream identity mismatch",
            ):
                DATABASE_ARCHIVE_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )
            raw_path.write_bytes(original)

            report["admission"]["platform_admitted"] = True
            with self.assertRaisesRegex(
                DATABASE_ARCHIVE_VALIDATOR.ReportError,
                "must not admit",
            ):
                DATABASE_ARCHIVE_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )
            report["admission"]["platform_admitted"] = False

            extra = (
                directory
                / "raw"
                / "cli-database-archive"
                / "undeclared"
            )
            extra.write_bytes(b"x")
            with self.assertRaisesRegex(
                DATABASE_ARCHIVE_VALIDATOR.ReportError,
                "raw file inventory",
            ):
                DATABASE_ARCHIVE_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    root=ROOT,
                )

    def test_cli_special_path_validator_recomputes_raw_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            baseline_path = write_cli_candidate_bundle(directory)
            fixture_path = (
                write_special_path_fixture_candidate_bundle(
                    directory
                )
            )
            report_path = write_cli_special_path_candidate_bundle(
                directory, baseline_path, fixture_path
            )
            report = CLI_VALIDATOR.load_json(report_path)[0]
            oracle_path = directory / "oracle-candidate.json"
            SPECIAL_PATH_VALIDATOR.validate_report(
                report,
                report_path=report_path,
                oracle_path=oracle_path,
                baseline_path=baseline_path,
                fixture_report_path=fixture_path,
                root=ROOT,
            )
            self.assertEqual(report["summary"]["case_count"], 23)
            self.assertEqual(
                report["summary"]["execution_count"], 46
            )
            self.assertEqual(
                report["summary"]["raw_stream_count"], 92
            )

            first = report["cases"]["directory_nonutf8"][
                "first"
            ]
            raw_path = directory / first["stdout_path"]
            original = raw_path.read_bytes()
            raw_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                SPECIAL_PATH_VALIDATOR.ReportError,
                "raw stream identity mismatch",
            ):
                SPECIAL_PATH_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    fixture_report_path=fixture_path,
                    root=ROOT,
                )
            raw_path.write_bytes(original)

            report["admission"]["platform_admitted"] = True
            with self.assertRaisesRegex(
                SPECIAL_PATH_VALIDATOR.ReportError,
                "must not admit",
            ):
                SPECIAL_PATH_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    fixture_report_path=fixture_path,
                    root=ROOT,
                )
            report["admission"]["platform_admitted"] = False

            extra = (
                directory
                / "raw"
                / "cli-special-path"
                / "undeclared"
            )
            extra.write_bytes(b"x")
            with self.assertRaisesRegex(
                SPECIAL_PATH_VALIDATOR.ReportError,
                "raw file inventory",
            ):
                SPECIAL_PATH_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    fixture_report_path=fixture_path,
                    root=ROOT,
                )

    def test_cli_filesystem_validator_recomputes_raw_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            baseline_path = write_cli_candidate_bundle(directory)
            report_path = write_cli_filesystem_candidate_bundle(
                directory, baseline_path
            )
            report = CLI_VALIDATOR.load_json(report_path)[0]
            oracle_path = directory / "oracle-candidate.json"
            FILESYSTEM_VALIDATOR.validate_report(
                report,
                report_path=report_path,
                oracle_path=oracle_path,
                baseline_path=baseline_path,
                root=ROOT,
            )
            self.assertEqual(report["summary"]["case_count"], 8)
            self.assertEqual(
                report["summary"]["execution_count"], 16
            )
            self.assertEqual(
                report["summary"]["raw_stream_count"], 32
            )
            self.assertEqual(
                len(
                    report["cases"]["self_cycle"][
                        "first_prefix_paths"
                    ]
                ),
                41,
            )

            first = report["cases"]["self_cycle"]["first"]
            raw_path = directory / first["stdout_path"]
            original = raw_path.read_bytes()
            raw_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                FILESYSTEM_VALIDATOR.ReportError,
                "raw stream identity mismatch",
            ):
                FILESYSTEM_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    root=ROOT,
                )
            raw_path.write_bytes(original)

            report["admission"]["platform_admitted"] = True
            with self.assertRaisesRegex(
                FILESYSTEM_VALIDATOR.ReportError,
                "must not admit",
            ):
                FILESYSTEM_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    root=ROOT,
                )
            report["admission"]["platform_admitted"] = False

            extra = (
                directory
                / "raw"
                / "cli-filesystem"
                / "undeclared"
            )
            extra.write_bytes(b"x")
            with self.assertRaisesRegex(
                FILESYSTEM_VALIDATOR.ReportError,
                "raw file inventory",
            ):
                FILESYSTEM_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    root=ROOT,
                )

    def test_cli_large_directory_validator_recomputes_raw_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            baseline_path = write_cli_candidate_bundle(directory)
            report_path = write_cli_large_directory_candidate_bundle(
                directory, baseline_path
            )
            report = CLI_VALIDATOR.load_json(report_path)[0]
            oracle_path = directory / "oracle-candidate.json"
            LARGE_DIRECTORY_VALIDATOR.validate_report(
                report,
                report_path=report_path,
                oracle_path=oracle_path,
                baseline_path=baseline_path,
                root=ROOT,
            )
            self.assertEqual(report["summary"]["case_count"], 5)
            self.assertEqual(
                report["summary"]["execution_count"], 10
            )
            self.assertEqual(
                report["summary"]["raw_stream_count"], 20
            )
            self.assertEqual(
                report["cases"]["flat_4096"][
                    "first_prefix_count"
                ],
                4096,
            )

            first = report["cases"]["flat_4096"]["first"]
            raw_path = directory / first["stdout_path"]
            original = raw_path.read_bytes()
            raw_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                LARGE_DIRECTORY_VALIDATOR.ReportError,
                "raw stream identity mismatch",
            ):
                LARGE_DIRECTORY_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    root=ROOT,
                )
            raw_path.write_bytes(original)

            report["admission"]["platform_admitted"] = True
            with self.assertRaisesRegex(
                LARGE_DIRECTORY_VALIDATOR.ReportError,
                "must not admit",
            ):
                LARGE_DIRECTORY_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    root=ROOT,
                )
            report["admission"]["platform_admitted"] = False

            extra = (
                directory
                / "raw"
                / "cli-large-directory"
                / "undeclared"
            )
            extra.write_bytes(b"x")
            with self.assertRaisesRegex(
                LARGE_DIRECTORY_VALIDATOR.ReportError,
                "raw file inventory",
            ):
                LARGE_DIRECTORY_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    root=ROOT,
                )

    def test_cli_long_path_validator_recomputes_raw_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            baseline_path = write_cli_candidate_bundle(directory)
            fixture_path = write_long_path_fixture_candidate_bundle(
                directory
            )
            report_path = write_cli_long_path_candidate_bundle(
                directory, baseline_path, fixture_path
            )
            report = CLI_VALIDATOR.load_json(report_path)[0]
            oracle_path = directory / "oracle-candidate.json"
            LONG_PATH_VALIDATOR.validate_report(
                report,
                report_path=report_path,
                oracle_path=oracle_path,
                baseline_path=baseline_path,
                fixture_report_path=fixture_path,
                root=ROOT,
            )
            self.assertEqual(report["summary"]["case_count"], 17)
            self.assertEqual(
                report["summary"]["execution_count"], 34
            )
            self.assertEqual(
                report["summary"]["raw_stream_count"], 68
            )
            self.assertEqual(
                report["cases"]["component_directory"][
                    "first_prefix_case_ids"
                ],
                ["name_max_-1", "name_max_+0"],
            )

            first = report["cases"]["path_max_+0_explicit"][
                "first"
            ]
            raw_path = directory / first["stdout_path"]
            original = raw_path.read_bytes()
            raw_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                LONG_PATH_VALIDATOR.ReportError,
                "raw stream identity mismatch",
            ):
                LONG_PATH_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    fixture_report_path=fixture_path,
                    root=ROOT,
                )
            raw_path.write_bytes(original)

            report["admission"]["platform_admitted"] = True
            with self.assertRaisesRegex(
                LONG_PATH_VALIDATOR.ReportError,
                "must not admit",
            ):
                LONG_PATH_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    fixture_report_path=fixture_path,
                    root=ROOT,
                )
            report["admission"]["platform_admitted"] = False

            extra = (
                directory
                / "raw"
                / "cli-long-path"
                / "undeclared"
            )
            extra.write_bytes(b"x")
            with self.assertRaisesRegex(
                LONG_PATH_VALIDATOR.ReportError,
                "raw file inventory",
            ):
                LONG_PATH_VALIDATOR.validate_report(
                    report,
                    report_path=report_path,
                    oracle_path=oracle_path,
                    baseline_path=baseline_path,
                    fixture_report_path=fixture_path,
                    root=ROOT,
                )

    def test_candidate_validator_accepts_complete_report(self):
        VALIDATOR.validate_report(candidate_report())

    def test_candidate_validator_rejects_identity_and_admission_drift(self):
        changed = candidate_report()
        changed["source"]["commit"] = "f" * 40
        with self.assertRaisesRegex(
            VALIDATOR.ReportError,
            "source identity",
        ):
            VALIDATOR.validate_report(changed)

        changed = candidate_report()
        changed["admission"]["platform_admitted"] = True
        with self.assertRaisesRegex(
            VALIDATOR.ReportError,
            "must not admit",
        ):
            VALIDATOR.validate_report(changed)

        changed = candidate_report()
        changed["artifact"]["architectures"] = ["arm64"]
        with self.assertRaisesRegex(
            VALIDATOR.ReportError,
            "artifact identity",
        ):
            VALIDATOR.validate_report(changed)

        changed = candidate_report()
        changed["qt"] = []
        with self.assertRaisesRegex(
            VALIDATOR.ReportError,
            "expected object: qt",
        ):
            VALIDATOR.validate_report(changed)

    def test_loader_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaisesRegex(
                VALIDATOR.ReportError,
                "duplicate JSON key",
            ):
                VALIDATOR.load_report(path)


if __name__ == "__main__":
    unittest.main()

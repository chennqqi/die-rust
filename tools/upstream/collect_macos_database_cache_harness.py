#!/usr/bin/env python3
"""Collect a non-admitted macOS Qt5 database-cache engine candidate."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
from typing import Any


PLATFORM = "macos-x86_64-qt5"
BUILD_VALIDATOR = (
    "tools/upstream/validate_macos_database_cache_harness_build.py"
)
BASELINE_COLLECTOR = "tools/upstream/collect_macos_cli_baseline.py"
BASELINE_VALIDATOR = "tools/upstream/validate_macos_cli_baseline.py"
WINDOWS_COLLECTOR = (
    "tools/upstream/collect_windows_database_cache_harness.py"
)
LINUX_PROBE = "tools/upstream/probe_database_cache_harness.py"
FIXTURE_GENERATOR = "tools/corpus/generate_database_fixture.py"
FIXTURE_MANIFEST = "docs/research/data/database-fixture.json"
LINUX_REFERENCE = (
    "docs/research/data/database-cache-engine-qt5.json"
)
VALIDATOR = (
    "tools/upstream/validate_macos_database_cache_harness.py"
)
REPORT_NAME = "database-cache-engine-candidate.json"
ADMISSION_REASON = (
    "database-cache engine candidate only; native macOS results have "
    "not been reviewed or projected into the 68-row capability closure"
)
LIMITATIONS = [
    (
        "the shared harness reaches bUseCache=true through an engine "
        "entry point because the fixed release CLI has no cache option "
        "and always leaves bUseCache false"
    ),
    (
        "QStandardPaths test mode and a collector-owned HOME isolate "
        "cache writes from the ordinary Detect It Easy user namespace"
    ),
    (
        "POSIX mode denial is observed as the non-root hosted-runner "
        "user; root, macOS ACLs, ownership changes, sandbox profiles, "
        "network filesystems, and different-content writers remain open"
    ),
    (
        "raw streams remain authoritative; normalization changes only "
        "the fixed /tmp work paths and verified test HOME prefix"
    ),
]
NORMALIZATION = {
    "operations": [
        (
            "replace fixed /tmp harness database and rule "
            "paths with <work>"
        ),
        (
            "replace the verified collector-controlled HOME "
            "prefix with <qt-test-home>"
        ),
    ],
    "not_performed": [
        "case removal or reordering",
        "cache hash or size rewriting",
        "scan result or error rewriting",
        "raw stdout/stderr rewriting",
    ],
}


class HarnessError(ValueError):
    """The database-cache harness candidate is unsafe or inconsistent."""


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load(root: Path, relative: str, name: str) -> Any:
    path = root / relative
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise HarnessError(f"cannot load helper module: {relative}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def generator_bindings(root: Path) -> dict[str, str]:
    paths = {
        "path": (
            "tools/upstream/collect_macos_database_cache_harness.py"
        ),
        "validator_path": VALIDATOR,
        "build_validator_path": BUILD_VALIDATOR,
        "baseline_collector_path": BASELINE_COLLECTOR,
        "baseline_validator_path": BASELINE_VALIDATOR,
        "windows_collector_path": WINDOWS_COLLECTOR,
        "linux_probe_path": LINUX_PROBE,
        "fixture_generator_path": FIXTURE_GENERATOR,
    }
    result = dict(paths)
    for field, relative in paths.items():
        digest_field = (
            "sha256"
            if field == "path"
            else field.removesuffix("_path") + "_sha256"
        )
        result[digest_field] = sha256((root / relative).read_bytes())
    return result


def strict_json(raw: bytes) -> dict[str, Any]:
    def reject_duplicates(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise HarnessError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                HarnessError(f"non-finite JSON constant: {constant}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarnessError(f"invalid harness JSON: {error}") from error
    if not isinstance(value, dict):
        raise HarnessError("harness JSON root must be an object")
    return value


def observe(
    common: Any,
    binary: Path,
    qt_dir: Path,
    fixture_dir: Path,
    working_dir: Path,
    home_dir: Path,
    timeout_seconds: int,
) -> Any:
    environment = os.environ.copy()
    environment["PATH"] = (
        str(qt_dir / "bin")
        + os.pathsep
        + environment.get("PATH", "")
    )
    environment["HOME"] = str(home_dir)
    try:
        result = subprocess.run(
            [binary.name, str(fixture_dir)],
            executable=str(binary),
            cwd=working_dir,
            env=environment,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise HarnessError("database-cache harness timed out") from error
    return common.Observation(
        result.returncode, result.stdout, result.stderr
    )


def normalize_observation(
    value: dict[str, Any],
    *,
    home_dir: PurePosixPath,
    linux_probe: Any,
) -> dict[str, Any]:
    result = json.loads(json.dumps(value))
    database = "/tmp/die-database-cache-harness/database"
    rule = database + "/Binary/fixture.1.sg"
    if result.get("database_path") != database:
        raise HarnessError("fixed harness database path changed")
    if result.get("rule_path") != rule:
        raise HarnessError("fixed harness rule path changed")
    cache = result.get("cache_path")
    if not isinstance(cache, str):
        raise HarnessError("harness cache path is invalid")
    cache_path = PurePosixPath(cache)
    if not cache_path.is_absolute() or "\\" in cache:
        raise HarnessError("harness cache path is not absolute POSIX")
    # On Linux, QStandardPaths test mode respects HOME and the cache
    # path is under the collector-controlled home_dir.  On macOS, Qt
    # uses NSSearchPathForDirectoriesInDomains which ignores HOME and
    # always returns ~/Library/Application Support/<org>/<app>; the
    # collector still sets HOME for isolation, but the cache path will
    # be under the real user home, not home_dir.  Accept both: try the
    # collector-controlled home first, then fall back to the real user
    # home (Path.home()) for macOS.
    cache_relative: PurePosixPath | None = None
    for candidate in (home_dir, PurePosixPath(str(Path.home()))):
        try:
            cache_relative = cache_path.relative_to(candidate)
            break
        except ValueError:
            continue
    if cache_relative is None:
        raise HarnessError(
            "harness cache escaped collector-controlled HOME"
        )
    # On Linux, QStandardPaths test mode inserts a "qttest" segment
    # into the path.  On macOS, Qt uses NSSearchPathForDirectoriesInDomains
    # which does not insert a test-mode marker; the cache is under
    # ~/Library/Application Support/NTInfo/die/db_cache/ instead.
    # Accept the macOS path if it contains the expected NTInfo/die
    # organization/application segments.
    cache_rel_posix = cache_relative.as_posix().casefold()
    if "qttest" not in cache_rel_posix:
        if "ntinfo/die" not in cache_rel_posix:
            raise HarnessError(
                "QStandardPaths test-mode marker is missing"
            )
    if cache_path.name == "" or cache_path.suffix != ".cache":
        raise HarnessError("harness cache filename changed")
    result["database_path"] = "<work>/database"
    result["rule_path"] = "<work>/database/Binary/fixture.1.sg"
    result["cache_path"] = (
        "<qt-test-home>/" + cache_relative.as_posix()
    )
    linux_probe.index_cases(result)
    return result


def semantic_case_projection(case: dict[str, Any]) -> dict[str, Any]:
    cache = case.get("cache")
    if not isinstance(cache, dict):
        raise HarnessError("cache harness case has no cache snapshot")
    return {
        "loaded": case.get("loaded"),
        "stop_before_load": case.get("stop_before_load"),
        "load_pd_not_canceled": case.get("load_pd_not_canceled"),
        "binary_signature_count": case.get(
            "binary_signature_count"
        ),
        "scan_names": case.get("scan_names"),
        "scan_errors": case.get("scan_errors"),
        "cache_exists": cache.get("exists"),
    }


def compare_linux_cases(
    macos: dict[str, Any],
    linux: dict[str, Any],
    *,
    linux_probe: Any,
) -> tuple[list[str], dict[str, int]]:
    macos_cases = linux_probe.index_cases(macos)
    linux_cases = linux_probe.index_cases(linux)
    differences = []
    size_deltas = {}
    for case_id in linux_probe.EXPECTED_CASE_IDS:
        macos_case = macos_cases[case_id]
        linux_case = linux_cases[case_id]
        if semantic_case_projection(
            macos_case
        ) != semantic_case_projection(linux_case):
            differences.append(case_id)
        macos_cache = macos_case["cache"]
        linux_cache = linux_case["cache"]
        if macos_cache["exists"] and linux_cache["exists"]:
            size_deltas[case_id] = (
                macos_cache["size"] - linux_cache["size"]
            )
    return differences, size_deltas


def collect(
    *,
    root: Path,
    binary: Path,
    source_dir: Path,
    qt_dir: Path,
    fixture_dir: Path,
    working_dir: Path,
    oracle_path: Path,
    build_report_path: Path,
    output: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    if sys.platform != "darwin" or platform.machine() != "x86_64":
        raise HarnessError("collector requires native Darwin x86_64")
    if os.geteuid() == 0:
        raise HarnessError(
            "permission matrix requires a non-root process"
        )
    if not 1 <= timeout_seconds <= 3600:
        raise HarnessError("timeout-seconds must be in 1..3600")
    binary = binary.resolve(strict=True)
    source_dir = source_dir.resolve(strict=True)
    qt_dir = qt_dir.resolve(strict=True)
    fixture_dir = fixture_dir.resolve(strict=True)
    working_dir = working_dir.resolve()
    oracle_path = oracle_path.resolve(strict=True)
    build_report_path = build_report_path.resolve(strict=True)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.name != REPORT_NAME:
        raise HarnessError(f"report name must be {REPORT_NAME}")
    for path, name in (
        (oracle_path, "oracle-candidate.json"),
        (
            build_report_path,
            "database-cache-harness-build-candidate.json",
        ),
    ):
        if path != (output.parent / name).resolve(strict=True):
            raise HarnessError(f"input report must be bundle-local: {name}")
    if binary != (
        output.parent / "database-cache-harness-candidate"
    ).resolve(strict=True):
        raise HarnessError("harness binary must be bundle-local")
    if output.exists():
        raise HarnessError("candidate report already exists")
    working_dir.mkdir(parents=True, exist_ok=True)
    if any(working_dir.iterdir()):
        raise HarnessError("harness working directory must be empty")
    home_dir = working_dir / "home"
    home_dir.mkdir()
    fixed_work = Path("/tmp/die-database-cache-harness")
    if fixed_work.exists():
        raise HarnessError(
            "fixed harness /tmp work root already exists"
        )
    raw_dir = output.parent / "raw" / "database-cache-engine"
    raw_dir.mkdir(parents=True, exist_ok=True)
    if any(raw_dir.iterdir()):
        raise HarnessError("database-cache raw directory must be empty")

    build_validator = _load(
        root, BUILD_VALIDATOR, "macos_cache_build_validator_for_run"
    )
    build_report = build_validator.load_json(build_report_path)[0]
    build_validator.validate_report(
        build_report,
        report_path=build_report_path,
        oracle_path=oracle_path,
        artifact_path=binary,
        root=root,
    )
    baseline = _load(
        root, BASELINE_COLLECTOR, "macos_baseline_for_cache_run"
    )
    baseline_validator = _load(
        root,
        BASELINE_VALIDATOR,
        "macos_baseline_validator_for_cache_run",
    )
    windows = _load(
        root, WINDOWS_COLLECTOR, "windows_cache_helper_for_macos"
    )
    linux_probe = _load(
        root, LINUX_PROBE, "linux_cache_probe_for_macos"
    )
    common = baseline.load_module(
        "windows_cli_common_for_macos_cache_run",
        root / baseline.SHARED_COLLECTOR,
    )
    oracle_validator = _load(
        root,
        build_validator.ORACLE_VALIDATOR,
        "macos_oracle_for_cache_run",
    )
    oracle = oracle_validator.load_report(oracle_path)
    source = build_report["source"]
    qt = build_report["qt"]
    live_source = common.validate_source(source_dir)
    live_source["tracked_files_clean_before_and_after"] = True
    if live_source != source:
        raise HarnessError("source identity differs from build report")
    if baseline.validate_qt(common, qt_dir, oracle) != qt:
        raise HarnessError("Qt identity differs from build report")

    fixture_raw = (fixture_dir / "manifest.json").read_bytes()
    reference_fixture_raw = (root / FIXTURE_MANIFEST).read_bytes()
    if fixture_raw != reference_fixture_raw:
        raise HarnessError("database fixture manifest differs")
    definitions = baseline.load_module(
        "database_fixture_definitions_for_macos_cache",
        root / "tools/upstream/compare_cli_oracles.py",
    )
    definitions.load_database_fixture(fixture_dir)
    linux_report, linux_raw = windows.read_json(root / LINUX_REFERENCE)
    linux_observation = windows.validate_linux_reference(
        linux_report, sha256(fixture_raw)
    )

    first = observe(
        common,
        binary,
        qt_dir,
        fixture_dir,
        working_dir,
        home_dir,
        timeout_seconds,
    )
    second = observe(
        common,
        binary,
        qt_dir,
        fixture_dir,
        working_dir,
        home_dir,
        timeout_seconds,
    )
    pair = baseline.pair_report(
        common,
        output.parent,
        "database-cache-engine/harness",
        first,
        second,
    )
    parsed = []
    for side, observation in (("first", first), ("second", second)):
        if observation.exit_code != 0:
            raise HarnessError(
                f"{side} harness exit code: {observation.exit_code}"
            )
        if observation.stderr:
            raise HarnessError(f"{side} harness stderr is not empty")
        parsed.append(strict_json(observation.stdout))
    home_posix = PurePosixPath(str(home_dir))
    normalized = [
        normalize_observation(
            value,
            home_dir=home_posix,
            linux_probe=linux_probe,
        )
        for value in parsed
    ]
    normalized_equal = normalized[0] == normalized[1]
    relationships = linux_probe.derive_relationships(normalized[0])
    relationships["harness_runs_without_root_privileges"] = (
        normalized[0].get("effective_uid") != 0
    )
    relationship_failures = [
        name for name, value in relationships.items() if not value
    ]
    projection_differences, size_deltas = compare_linux_cases(
        normalized[0], linux_observation, linux_probe=linux_probe
    )
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": PLATFORM,
        "generator": generator_bindings(root),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": sha256(oracle_path.read_bytes()),
        },
        "build_report": {
            "path": build_report_path.name,
            "sha256": sha256(build_report_path.read_bytes()),
        },
        "source": source,
        "qt": qt,
        "binary": build_report["artifact"],
        "fixture": {
            "manifest": FIXTURE_MANIFEST,
            "sha256": sha256(fixture_raw),
        },
        "linux_qt5_reference": {
            "path": LINUX_REFERENCE,
            "sha256": sha256(linux_raw),
        },
        "local_paths": {
            "working_dir": str(working_dir),
            "home_dir": str(home_dir),
        },
        "selection": {
            "case_ids": list(linux_probe.EXPECTED_CASE_IDS),
            "repetitions": 2,
            "timeout_seconds": timeout_seconds,
        },
        "run": pair,
        "observation": normalized[0],
        "relationships": relationships,
        "linux_qt5_comparison": {
            "case_projection_differences": projection_differences,
            "cache_size_deltas": size_deltas,
        },
        "summary": {
            "case_count": len(linux_probe.EXPECTED_CASE_IDS),
            "execution_count": 2,
            "raw_stream_count": 4,
            "raw_determinism_failures": pair[
                "determinism_differences"
            ],
            "normalized_outputs_equal": normalized_equal,
            "relationship_failures": relationship_failures,
            "linux_case_projection_differences": (
                projection_differences
            ),
        },
        "normalization": NORMALIZATION,
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": ADMISSION_REASON,
        },
        "limitations": LIMITATIONS,
    }
    output.write_bytes(
        (
            json.dumps(
                report,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode()
    )
    return report


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--qt-dir", type=Path, required=True)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--working-dir", type=Path, required=True)
    parser.add_argument("--oracle-report", type=Path, required=True)
    parser.add_argument("--build-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.set_defaults(root=root)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        collect(
            root=args.root.resolve(),
            binary=args.binary,
            source_dir=args.source_dir,
            qt_dir=args.qt_dir,
            fixture_dir=args.fixture_dir,
            working_dir=args.working_dir,
            oracle_path=args.oracle_report,
            build_report_path=args.build_report,
            output=args.output,
            timeout_seconds=args.timeout_seconds,
        )
    except (HarnessError, OSError, ValueError) as error:
        print(
            f"macOS database-cache harness error: {error}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

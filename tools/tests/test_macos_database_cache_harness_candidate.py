import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILD_TEST = load_module(
    "macos_cache_build_test_helpers_for_runtime",
    ROOT / "tools/tests/test_macos_database_cache_harness_build.py",
)
COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_database_cache_harness.py"
)
VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_database_cache_harness.py"
)
COLLECTOR = load_module(
    "macos_cache_harness_collector_test", COLLECTOR_PATH
)
VALIDATOR = load_module(
    "macos_cache_harness_validator_test", VALIDATOR_PATH
)
BASELINE = BUILD_TEST.BOOTSTRAP.CLI_COLLECTOR
COMMON = BUILD_TEST.BOOTSTRAP.CLI_COMMON
LINUX_PROBE = load_module(
    "linux_cache_probe_for_macos_candidate_test",
    ROOT / COLLECTOR.LINUX_PROBE,
)


def write_candidate(bundle: Path):
    (
        build_report_path,
        oracle_path,
        binary_path,
        build_report,
    ) = BUILD_TEST.write_candidate(bundle)
    fixture_raw = (ROOT / COLLECTOR.FIXTURE_MANIFEST).read_bytes()
    linux_raw = (ROOT / COLLECTOR.LINUX_REFERENCE).read_bytes()
    linux = json.loads(linux_raw)
    observation = copy.deepcopy(linux["observation"])
    working = PurePosixPath(
        "/private/tmp/die-macos-cache-working"
    )
    home = working / "home"
    observation["effective_uid"] = 501
    observation["effective_gid"] = 20
    observation["database_path"] = (
        "/tmp/die-database-cache-harness/database"
    )
    observation["rule_path"] = (
        "/tmp/die-database-cache-harness/database/"
        "Binary/fixture.1.sg"
    )
    observation["cache_path"] = str(
        home
        / "Library/Application Support/qttest/NTInfo/die/"
        "db_cache/0123456789abcdef.cache"
    )
    stdout = (
        json.dumps(observation, indent=2, sort_keys=True) + "\n"
    ).encode()
    raw = COMMON.Observation(0, stdout, b"")
    run = BASELINE.pair_report(
        COMMON,
        bundle,
        "database-cache-engine/harness",
        raw,
        raw,
    )
    normalized = COLLECTOR.normalize_observation(
        observation,
        home_dir=home,
        linux_probe=LINUX_PROBE,
    )
    relationships = LINUX_PROBE.derive_relationships(normalized)
    relationships["harness_runs_without_root_privileges"] = True
    projection_differences, size_deltas = (
        COLLECTOR.compare_linux_cases(
            normalized,
            linux["observation"],
            linux_probe=LINUX_PROBE,
        )
    )
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": COLLECTOR.PLATFORM,
        "generator": COLLECTOR.generator_bindings(ROOT),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                oracle_path.read_bytes()
            ).hexdigest(),
        },
        "build_report": {
            "path": build_report_path.name,
            "sha256": hashlib.sha256(
                build_report_path.read_bytes()
            ).hexdigest(),
        },
        "source": build_report["source"],
        "qt": build_report["qt"],
        "binary": build_report["artifact"],
        "fixture": {
            "manifest": COLLECTOR.FIXTURE_MANIFEST,
            "sha256": hashlib.sha256(fixture_raw).hexdigest(),
        },
        "linux_qt5_reference": {
            "path": COLLECTOR.LINUX_REFERENCE,
            "sha256": hashlib.sha256(linux_raw).hexdigest(),
        },
        "local_paths": {
            "working_dir": str(working),
            "home_dir": str(home),
        },
        "selection": {
            "case_ids": list(LINUX_PROBE.EXPECTED_CASE_IDS),
            "repetitions": 2,
            "timeout_seconds": 120,
        },
        "run": run,
        "observation": normalized,
        "relationships": relationships,
        "linux_qt5_comparison": {
            "case_projection_differences": projection_differences,
            "cache_size_deltas": size_deltas,
        },
        "summary": {
            "case_count": len(LINUX_PROBE.EXPECTED_CASE_IDS),
            "execution_count": 2,
            "raw_stream_count": 4,
            "raw_determinism_failures": [],
            "normalized_outputs_equal": True,
            "relationship_failures": [],
            "linux_case_projection_differences": (
                projection_differences
            ),
        },
        "normalization": COLLECTOR.NORMALIZATION,
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": COLLECTOR.ADMISSION_REASON,
        },
        "limitations": COLLECTOR.LIMITATIONS,
    }
    report_path = bundle / COLLECTOR.REPORT_NAME
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return (
        report_path,
        oracle_path,
        build_report_path,
        binary_path,
        report,
    )


class MacosDatabaseCacheHarnessCandidateTest(unittest.TestCase):
    def validate(
        self,
        report_path,
        oracle_path,
        build_report_path,
        binary_path,
    ):
        report = json.loads(report_path.read_bytes())
        VALIDATOR.validate_report(
            report,
            report_path=report_path.resolve(strict=True),
            oracle_path=oracle_path.resolve(strict=True),
            build_report_path=build_report_path.resolve(strict=True),
            binary_path=binary_path.resolve(strict=True),
            root=ROOT,
        )

    def test_validator_replays_19_cases_from_raw_streams(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            values = write_candidate(bundle)
            self.validate(*values[:4])
            report = values[4]
            self.assertEqual(report["summary"]["case_count"], 19)
            self.assertEqual(report["summary"]["execution_count"], 2)
            self.assertEqual(report["summary"]["raw_stream_count"], 4)
            self.assertEqual(
                report["summary"][
                    "linux_case_projection_differences"
                ],
                [],
            )

    def test_validator_rejects_raw_projection_admission_and_inventory_drift(
        self,
    ):
        for mutation in ("raw", "projection", "admission", "inventory"):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    bundle = Path(temporary)
                    values = write_candidate(bundle)
                    (
                        report_path,
                        oracle_path,
                        build_report_path,
                        binary_path,
                        report,
                    ) = values
                    if mutation == "raw":
                        path = bundle / report["run"]["first"][
                            "stdout_path"
                        ]
                        path.write_bytes(path.read_bytes() + b"x")
                    elif mutation == "projection":
                        changed = copy.deepcopy(report)
                        changed["observation"]["effective_uid"] = 0
                        report_path.write_text(
                            json.dumps(changed), encoding="utf-8"
                        )
                    elif mutation == "admission":
                        changed = copy.deepcopy(report)
                        changed["admission"][
                            "platform_admitted"
                        ] = True
                        report_path.write_text(
                            json.dumps(changed), encoding="utf-8"
                        )
                    else:
                        extra = (
                            bundle
                            / "raw"
                            / "database-cache-engine"
                            / "undeclared"
                        )
                        extra.write_bytes(b"x")
                    with self.assertRaises(
                        (VALIDATOR.ReportError, ValueError)
                    ):
                        self.validate(
                            report_path,
                            oracle_path,
                            build_report_path,
                            binary_path,
                        )

    def test_normalizer_rejects_cache_outside_test_home(self):
        linux = json.loads(
            (ROOT / COLLECTOR.LINUX_REFERENCE).read_bytes()
        )
        value = copy.deepcopy(linux["observation"])
        value["database_path"] = (
            "/tmp/die-database-cache-harness/database"
        )
        value["rule_path"] = (
            "/tmp/die-database-cache-harness/database/"
            "Binary/fixture.1.sg"
        )
        value["cache_path"] = "/Users/runner/real/cache.cache"
        with self.assertRaises(COLLECTOR.HarnessError):
            COLLECTOR.normalize_observation(
                value,
                home_dir=PurePosixPath("/private/tmp/test-home"),
                linux_probe=LINUX_PROBE,
            )


if __name__ == "__main__":
    unittest.main()

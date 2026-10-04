import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT / "tools/upstream/collect_windows_database_cache_harness.py"
)
BUILDER = (
    ROOT / "tools/upstream/build_windows_database_cache_harness.ps1"
)
SHARED_HARNESS = (
    ROOT / "tools/upstream/database_cache_harness_main.cpp"
)
ADAPTER = (
    ROOT / "tools/upstream/database_cache_harness_windows_adapter.cpp"
)
COMPAT = (
    ROOT / "tools/upstream/windows_database_cache_compat/unistd.h"
)
REPORT = (
    ROOT / "docs/research/data/database-cache-engine-windows-qt5.json"
)
LINUX_REFERENCE = (
    ROOT / "docs/research/data/database-cache-engine-qt5.json"
)
FIXTURE_MANIFEST = ROOT / "docs/research/data/database-fixture.json"
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_database_cache_harness",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsDatabaseCacheHarnessTests(unittest.TestCase):
    def test_expected_case_inventory_is_reused_from_linux_probe(self):
        self.assertEqual(len(MODULE.linux_probe.EXPECTED_CASE_IDS), 19)
        self.assertEqual(
            MODULE.linux_probe.EXPECTED_CASE_IDS[0],
            "initial_miss",
        )
        self.assertEqual(
            MODULE.linux_probe.EXPECTED_CASE_IDS[-1],
            "poisoned_empty_cache_hit",
        )

    def test_semantic_projection_excludes_platform_cache_bytes(self):
        case = {
            "loaded": True,
            "stop_before_load": False,
            "load_pd_not_canceled": True,
            "binary_signature_count": 1,
            "scan_names": ["Fixture"],
            "scan_errors": [],
            "cache": {
                "exists": True,
                "size": 403,
                "sha256": "platform-specific",
            },
        }
        projection = MODULE.semantic_case_projection(case)
        self.assertTrue(projection["cache_exists"])
        self.assertNotIn("size", projection)
        self.assertNotIn("sha256", projection)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_is_identity_bound_and_complete(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        build = json.loads(WINDOWS_BUILD.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["platform"], "windows-x86_64-qt5")
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )
        source_hashes = report["build_manifest"]["identity"][
            "source_hashes"
        ]
        for key, path in (
            ("builder", BUILDER),
            ("shared_harness", SHARED_HARNESS),
            ("windows_adapter", ADAPTER),
            ("windows_compat_header", COMPAT),
        ):
            with self.subTest(key=key):
                self.assertEqual(
                    source_hashes[key],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
        self.assertEqual(
            report["fixture"]["sha256"],
            hashlib.sha256(FIXTURE_MANIFEST.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["linux_qt5_reference"]["sha256"],
            hashlib.sha256(LINUX_REFERENCE.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            build["windows_engine_database_cache"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["repetitions"], 2)
        self.assertEqual(len(report["observation"]["cases"]), 19)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_two_runs_are_raw_and_normalized_deterministic(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["passed"])
        self.assertEqual(report["failures"], [])
        self.assertTrue(report["raw_outputs_equal"])
        self.assertTrue(report["normalized_outputs_equal"])
        self.assertEqual(len(report["runs"]), 2)
        self.assertEqual(report["runs"][0], report["runs"][1])

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_all_linux_semantic_projections_and_relationships_hold(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        comparison = report["linux_qt5_comparison"]
        self.assertEqual(comparison["case_projection_differences"], [])
        self.assertTrue(comparison["all_named_relationships_hold"])
        self.assertTrue(all(report["relationships"].values()))

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_windows_dacl_permission_cases_are_effective(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        cases = {
            case["id"]: case for case in report["observation"]["cases"]
        }
        write_denied = cases["cache_write_denied"]
        denied_directory = cases[
            "database_directory_permission_denied"
        ]
        denied_file = cases["database_file_permission_denied"]
        self.assertFalse(write_denied["cache"]["exists"])
        self.assertEqual(
            denied_directory["binary_signature_count"],
            0,
        )
        self.assertEqual(denied_directory["scan_names"], ["Unknown"])
        self.assertFalse(denied_file["loaded"])

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_cache_size_difference_is_preserved(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        deltas = report["linux_qt5_comparison"]["cache_size_deltas"]
        self.assertEqual(deltas["initial_miss"], 4)
        self.assertEqual(deltas["canceled_cache_miss"], 0)
        self.assertEqual(
            report["observation"]["cases"][0]["cache"]["size"],
            403,
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_identity_or_absolute_path(self):
        text = REPORT.read_text(encoding="utf-8")
        for forbidden in (
            "C:/Users",
            "C:\\\\Users",
            "I:/tmp",
            "I:\\\\tmp",
            "worker",
            "die-windows-script-source",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        self.assertIn("<work>/database", text)
        self.assertIn(
            "<qt-test-appdata>/NTInfo/die/db_cache/",
            text,
        )


if __name__ == "__main__":
    unittest.main()

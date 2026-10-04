import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_windows_cli_long_paths.py"
FIXTURE_SCRIPT = (
    ROOT / "tools/corpus/generate_windows_long_path_fixture.py"
)
MANIFEST = ROOT / "docs/research/data/windows-long-path-fixture.json"
REPORT = ROOT / "docs/research/data/windows-qt5-cli-long-paths.json"
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_long_paths",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliLongPathsTests(unittest.TestCase):
    def test_case_builder_covers_explicit_and_discovered_long_paths(self):
        files = [
            {"id": "control", "path": "control/target.pdf"},
            {
                "id": "explicit",
                "path": MODULE.fixture_generator.EXPLICIT_PATH,
            },
            {
                "id": "discovery",
                "path": MODULE.fixture_generator.DISCOVERY_PATH,
            },
        ]
        cases = MODULE.build_cases(Path("C:/fixture"), files)
        self.assertEqual(len(cases), 7)
        self.assertEqual(
            {case.name for case in cases},
            {
                "control_file",
                "long_file_ordinary",
                "long_file_extended",
                "long_directory_ordinary",
                "long_directory_extended",
                "short_discovery_root",
                "extended_discovery_root",
            },
        )
        self.assertTrue(
            all(
                case.target.startswith("\\\\?\\")
                for case in cases
                if "extended" in case.name
            )
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_committed_report_is_bound_and_complete(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        build = json.loads(WINDOWS_BUILD.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["platform"], "windows-x86_64-qt5")
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["fixture_generator"]["sha256"],
            hashlib.sha256(FIXTURE_SCRIPT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["fixture"]["sha256"],
            hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            build["windows_cli_long_paths"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["summary"]["case_count"], 7)
        self.assertEqual(report["summary"]["execution_count"], 14)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_all_long_path_modes_match_control(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["summary"]["deterministic"])
        self.assertTrue(report["summary"]["expected_exits_equal"])
        self.assertTrue(report["summary"]["all_json_valid"])
        self.assertTrue(
            report["summary"]["reference_projections_equal"]
        )
        self.assertTrue(
            all(report["findings"].values())
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\tmp", text)
        self.assertNotIn("die-windows-script-source", text)
        self.assertNotIn("die-windows-long-path-", text)
        self.assertIn("<extended-fixture>/", text)
        self.assertIn("<source>/Detect-It-Easy/db", text)


if __name__ == "__main__":
    unittest.main()

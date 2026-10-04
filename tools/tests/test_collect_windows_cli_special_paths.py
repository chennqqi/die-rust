import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_windows_cli_special_paths.py"
FIXTURE_SCRIPT = (
    ROOT / "tools/corpus/generate_windows_special_path_fixture.py"
)
MANIFEST = (
    ROOT / "docs/research/data/windows-special-path-fixture.json"
)
REPORT = (
    ROOT / "docs/research/data/windows-qt5-cli-special-paths.json"
)
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_special_paths",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliSpecialPathsTests(unittest.TestCase):
    def test_case_builder_covers_each_entry_and_boundary_case(self):
        entries = [
            {"id": case_id, "path": path}
            for case_id, path, _ in MODULE.fixture_generator.ENTRIES
        ]
        cases = MODULE.build_cases(
            Path("C:/source"),
            Path("C:/fixture"),
            entries,
            Path("C:/binary"),
        )
        self.assertEqual(len(cases), 17)
        self.assertEqual(
            {case.name for case in cases if case.name.startswith("single_")},
            {f"single_{entry['id']}" for entry in entries},
        )

    def test_prefix_parser_preserves_declared_order_not_line_order(self):
        entries = [
            {"id": "emoji", "path": "special/emoji-😀.pdf"},
            {"id": "space", "path": "special/space name.pdf"},
        ]
        fixture = Path("I:/fixture")
        data = (
            str(fixture / "special" / "space name.pdf").encode()
            + b":\r\n{}\r\n"
            + str(fixture / "special" / "emoji-😀.pdf").encode()
            + b":\r\n{}\r\n"
        )
        self.assertEqual(
            MODULE.prefix_ids(data, fixture, entries),
            ["space", "emoji"],
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
            build["windows_cli_special_paths"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["summary"]["case_count"], 17)
        self.assertEqual(report["summary"]["execution_count"], 34)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_all_cases_are_stable_and_keep_pdf_projection(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["summary"]["deterministic"])
        self.assertTrue(report["summary"]["expected_exits_equal"])
        self.assertTrue(
            report["summary"]["reference_projections_equal"]
        )
        self.assertEqual(report["summary"]["determinism_failures"], [])
        self.assertEqual(report["summary"]["expected_exit_failures"], [])
        self.assertEqual(
            report["summary"]["reference_projection_failures"],
            [],
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_windows_hidden_and_order_findings_are_fixed(self):
        findings = json.loads(REPORT.read_text(encoding="utf-8"))[
            "findings"
        ]
        self.assertTrue(findings["dot_file_is_enumerated"])
        self.assertTrue(findings["hidden_attribute_file_is_excluded"])
        self.assertTrue(findings["nfc_nfd_are_distinct_and_enumerated"])
        self.assertTrue(findings["explicit_target_order_is_preserved"])
        self.assertTrue(
            findings["common_directory_order_matches_linux_qt5"]
        )
        self.assertTrue(
            findings[
                "leading_dash_requires_option_terminator_when_relative"
            ]
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\tmp", text)
        self.assertNotIn("die-windows-script-source", text)
        self.assertNotIn("die-windows-special-path", text)
        self.assertIn("<fixture>/special", text)
        self.assertIn("<source>/Detect-It-Easy/db", text)


if __name__ == "__main__":
    unittest.main()

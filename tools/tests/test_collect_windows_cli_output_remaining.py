import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT / "tools/upstream/collect_windows_cli_output_remaining.py"
)
DEFINITIONS = ROOT / "tools/upstream/compare_cli_oracles.py"
PRIMARY_COLLECTOR = (
    ROOT / "tools/upstream/collect_windows_cli_matrix.py"
)
REPORT = (
    ROOT / "docs/research/data/windows-qt5-cli-output-remaining.json"
)
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
PRIMARY_REPORT = (
    ROOT / "docs/research/data/windows-qt5-cli-matrix.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_output_remaining",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliOutputRemainingTests(unittest.TestCase):
    def test_partition_and_cases_are_fixed(self):
        self.assertEqual(len(MODULE.ALREADY_COVERED), 5)
        self.assertEqual(
            set(MODULE.EXPECTED_INVALID_XML),
            {
                "minimal-fat.macho",
                "Minimal.class",
                "minimal.pyc",
                "minimal.iso",
            },
        )
        self.assertEqual(
            [case.name for case in MODULE.matrix_definitions.OUTPUT_MATRIX],
            [
                "text",
                "plaintext",
                "json",
                "xml",
                "csv",
                "tsv",
                "all_output_flags",
            ],
        )

    def test_output_validity_parses_documents_and_text(self):
        self.assertTrue(MODULE.output_validity("json", b'{"x": 1}'))
        self.assertFalse(MODULE.output_validity("json", b"{"))
        self.assertTrue(MODULE.output_validity("xml", b"<Result/>"))
        self.assertFalse(MODULE.output_validity("xml", b"<Result>"))
        self.assertTrue(MODULE.output_validity("csv", b"a;b\r\n"))
        self.assertFalse(MODULE.output_validity("tsv", b""))
        self.assertFalse(MODULE.output_validity("text", b"\xff"))

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_committed_report_is_bound_and_complete(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        build = json.loads(WINDOWS_BUILD.read_text(encoding="utf-8"))
        primary = json.loads(PRIMARY_REPORT.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["platform"], "windows-x86_64-qt5")
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["helpers"]["matrix_definitions"]["sha256"],
            hashlib.sha256(DEFINITIONS.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["helpers"]["primary_collector"]["sha256"],
            hashlib.sha256(PRIMARY_COLLECTOR.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["primary_windows_matrix"]["sha256"],
            hashlib.sha256(PRIMARY_REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["primary_windows_matrix"]["covered_samples"],
            primary["selection"]["output"],
        )
        self.assertEqual(
            build["windows_cli_output_remaining"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["summary"]["sample_count"], 21)
        self.assertEqual(report["summary"]["case_count"], 147)
        self.assertEqual(report["summary"]["execution_count"], 294)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_all_remaining_outputs_are_stable_and_valid(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        for field in (
            "deterministic",
            "expected_exits_equal",
            "stderr_empty",
            "output_validity_matches_expected",
            "json_default_references_equal",
            "csv_priority_equal",
        ):
            with self.subTest(field=field):
                self.assertTrue(report["summary"][field])
        self.assertEqual(
            set(report["summary"]["expected_invalid_xml_samples"]),
            set(MODULE.EXPECTED_INVALID_XML),
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\tmp", text)
        self.assertNotIn("die-windows-script-source", text)
        self.assertIn("<source>/Detect-It-Easy/db", text)
        self.assertIn("<corpus>/minimal-pe64.exe", text)


if __name__ == "__main__":
    unittest.main()

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_windows_cli_special_remaining.py"
DEFINITIONS = ROOT / "tools/upstream/compare_cli_oracles.py"
PRIMARY_SCRIPT = ROOT / "tools/upstream/collect_windows_cli_matrix.py"
REPORT = (
    ROOT
    / "docs/research/data/windows-qt5-cli-special-remaining.json"
)
PRIMARY_REPORT = ROOT / "docs/research/data/windows-qt5-cli-matrix.json"
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
MANIFEST = ROOT / "docs/research/data/baseline-corpus.json"
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_special_remaining",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliSpecialRemainingTests(unittest.TestCase):
    def test_special_matrix_and_output_classification_are_complete(self):
        names = [
            case.name for case in MODULE.matrix_definitions.SPECIAL_MATRIX
        ]
        self.assertEqual(len(names), 19)
        classified = (
            set(MODULE.JSON_CASES)
            | set(MODULE.XML_CASES)
            | {
                name
                for name in names
                if name not in MODULE.JSON_CASES
                and name not in MODULE.XML_CASES
            }
        )
        self.assertEqual(classified, set(names))
        self.assertEqual(
            MODULE.PRIORITY_REFERENCES,
            {
                "entropy_all_output_flags": "entropy_json",
                "info_all_output_flags": "info_json",
                "entropy_over_info_struct_json": "entropy_json",
                "struct_over_info_json": "struct_hash_json",
            },
        )

    def test_parse_output_validates_structured_and_text_modes(self):
        self.assertEqual(
            MODULE.parse_output("entropy_json", b'{"entropy": 0}'),
            (True, {"entropy": 0}),
        )
        self.assertEqual(
            MODULE.parse_output("entropy_json", b"{"),
            (False, None),
        )
        self.assertEqual(
            MODULE.parse_output("info_xml", b"<info/>"),
            (True, {"root_tag": "info"}),
        )
        self.assertEqual(
            MODULE.parse_output("info_xml", b"<info>"),
            (False, None),
        )
        self.assertEqual(
            MODULE.parse_output("entropy_csv", b"value"),
            (True, None),
        )
        self.assertEqual(
            MODULE.parse_output("entropy_csv", b""),
            (False, None),
        )

    def test_info_projection_normalizes_only_verified_file_name(self):
        projection = {
            "data": {
                "Info": {
                    "File name": "I:/private/corpus/minimal.elf",
                    "File size": "64 bytes",
                }
            }
        }
        self.assertEqual(
            MODULE.normalize_projection(
                "info_json",
                projection,
                "minimal.elf",
            ),
            {
                "data": {
                    "Info": {
                        "File name": "<corpus>/minimal.elf",
                        "File size": "64 bytes",
                    }
                }
            },
        )
        self.assertEqual(
            projection["data"]["Info"]["File name"],
            "I:/private/corpus/minimal.elf",
        )
        self.assertIs(
            MODULE.normalize_projection(
                "entropy_json",
                projection,
                "minimal.elf",
            ),
            projection,
        )
        with self.assertRaises(MODULE.ProbeError):
            MODULE.normalize_projection(
                "info_json",
                projection,
                "another.elf",
            )

    @unittest.skipUnless(REPORT.exists(), "Windows special matrix not collected")
    def test_committed_report_is_bound_and_complete(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        primary = json.loads(PRIMARY_REPORT.read_text(encoding="utf-8"))
        build = json.loads(WINDOWS_BUILD.read_text(encoding="utf-8"))
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
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
            hashlib.sha256(PRIMARY_SCRIPT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["primary_windows_matrix"]["sha256"],
            hashlib.sha256(PRIMARY_REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["source"], primary["source"])
        self.assertEqual(report["qt"], primary["qt"])
        self.assertEqual(report["binary"], primary["binary"])
        self.assertEqual(
            build["windows_cli_special_remaining"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            build["windows_cli_special_remaining"]["execution_count"],
            report["summary"]["execution_count"],
        )
        self.assertEqual(
            report["corpus_manifest"]["sample_count"],
            len(manifest["samples"]),
        )
        self.assertEqual(report["summary"]["sample_count"], 21)
        self.assertEqual(report["summary"]["case_count"], 399)
        self.assertEqual(report["summary"]["execution_count"], 798)

    @unittest.skipUnless(REPORT.exists(), "Windows special matrix not collected")
    def test_committed_report_has_no_observed_failures(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["summary"]["deterministic"])
        self.assertTrue(report["summary"]["expected_exits_equal"])
        self.assertTrue(report["summary"]["stderr_empty"])
        self.assertTrue(report["summary"]["outputs_valid"])
        self.assertTrue(report["summary"]["priority_references_equal"])
        for key in (
            "determinism_failures",
            "expected_exit_failures",
            "stderr_failures",
            "validity_failures",
            "priority_failures",
        ):
            self.assertEqual(report["summary"][key], [])

    @unittest.skipUnless(REPORT.exists(), "Windows special matrix not collected")
    def test_every_case_is_deterministic_and_structured_modes_parse(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        for sample_name, cases in report["matrix"].items():
            for case_name, case in cases.items():
                with self.subTest(sample=sample_name, case=case_name):
                    self.assertEqual(case["determinism_differences"], [])
                    self.assertEqual(case["first"], case["second"])
                    self.assertTrue(case["first_output_valid"])
                    self.assertTrue(case["second_output_valid"])
                    if (
                        case_name in MODULE.JSON_CASES
                        or case_name in MODULE.XML_CASES
                    ):
                        self.assertEqual(
                            case["first_projection"],
                            case["second_projection"],
                        )

    @unittest.skipUnless(REPORT.exists(), "Windows special matrix not collected")
    def test_priority_cases_equal_their_reference_modes(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        for sample_name, cases in report["matrix"].items():
            for case_name, reference in MODULE.PRIORITY_REFERENCES.items():
                with self.subTest(sample=sample_name, case=case_name):
                    case = cases[case_name]
                    self.assertEqual(
                        case["priority_reference_case"],
                        reference,
                    )
                    self.assertTrue(case["priority_reference_equal"])
                    self.assertEqual(case["first"], cases[reference]["first"])
                    self.assertEqual(case["second"], cases[reference]["second"])

    @unittest.skipUnless(REPORT.exists(), "Windows special matrix not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\tmp", text)
        self.assertNotIn("I:/tmp", text)
        self.assertNotIn("die-windows-script-source", text)
        self.assertNotIn("die-windows-corpus", text)
        self.assertIn("<source>/Detect-It-Easy/db", text)
        self.assertIn("<corpus>/minimal.elf", text)


if __name__ == "__main__":
    unittest.main()

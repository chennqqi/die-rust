import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_linux_cli_output_remaining.py"
DEFINITIONS = ROOT / "tools/upstream/compare_cli_oracles.py"
LINUX_HELPER = (
    ROOT / "tools/upstream/collect_linux_cli_special_remaining.py"
)
WINDOWS_COLLECTOR = (
    ROOT / "tools/upstream/collect_windows_cli_output_remaining.py"
)
WINDOWS_REPORT = (
    ROOT
    / "docs/research/data/windows-qt5-cli-output-remaining.json"
)
REPORT = (
    ROOT
    / "docs/research/data/linux-qt5-qt6-cli-output-remaining.json"
)
MANIFEST = ROOT / "docs/research/data/baseline-corpus.json"
SPEC = importlib.util.spec_from_file_location(
    "collect_linux_cli_output_remaining",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectLinuxCliOutputRemainingTests(unittest.TestCase):
    def test_expected_difference_set_is_only_pe64_stderr(self):
        self.assertEqual(len(MODULE.EXPECTED_RAW_DIFFERENCES), 7)
        self.assertEqual(
            set(MODULE.EXPECTED_RAW_DIFFERENCES),
            {
                f"matrix.minimal-pe64.exe.{case.name}"
                for case in MODULE.matrix.OUTPUT_MATRIX
            },
        )
        self.assertTrue(
            all(
                value == ("stderr",)
                for value in MODULE.EXPECTED_RAW_DIFFERENCES.values()
            )
        )
        observed = dict(MODULE.EXPECTED_RAW_DIFFERENCES)
        self.assertEqual(
            set(MODULE.EXPECTED_RAW_DIFFERENCES) - set(observed),
            set(),
        )

    @unittest.skipUnless(REPORT.exists(), "Linux output matrix not collected")
    def test_committed_report_is_bound_and_complete(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        windows = json.loads(WINDOWS_REPORT.read_text(encoding="utf-8"))
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["matrix_definitions"]["sha256"],
            hashlib.sha256(DEFINITIONS.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["linux_identity_helper"]["sha256"],
            hashlib.sha256(LINUX_HELPER.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["windows_collector"]["sha256"],
            hashlib.sha256(WINDOWS_COLLECTOR.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["windows_reference"]["sha256"],
            hashlib.sha256(WINDOWS_REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["platforms"]["linux-x86_64-qt5"]["id"],
            MODULE.linux_helper.QT5_IMAGE_ID,
        )
        self.assertEqual(
            report["platforms"]["linux-x86_64-qt6"]["id"],
            MODULE.linux_helper.QT6_IMAGE_ID,
        )
        self.assertEqual(
            report["corpus_manifest"]["sample_count"],
            len(manifest["samples"]),
        )
        self.assertEqual(report["selection"], windows["selection"])
        self.assertEqual(report["cases"], windows["cases"])
        self.assertEqual(report["summary"]["sample_count"], 21)
        self.assertEqual(report["summary"]["case_count"], 147)
        self.assertEqual(report["summary"]["execution_count"], 294)

    @unittest.skipUnless(REPORT.exists(), "Linux output matrix not collected")
    def test_committed_report_has_only_expected_differences(self):
        summary = json.loads(
            REPORT.read_text(encoding="utf-8")
        )["summary"]
        for key in (
            "raw_differences_match_expected",
            "all_exits_zero",
            "stderr_contract_matches",
            "output_validity_matches_expected",
            "qt_json_projections_equal",
            "windows_linux_qt5_json_projections_equal",
            "priority_references_equal",
        ):
            self.assertTrue(summary[key], key)
        for key in (
            "unexpected_raw_difference_failures",
            "missing_expected_raw_differences",
            "exit_failures",
            "stderr_contract_failures",
            "validity_failures",
            "qt_json_projection_failures",
            "windows_json_projection_failures",
            "priority_failures",
        ):
            self.assertEqual(summary[key], [], key)
        self.assertEqual(summary["expected_raw_difference_count"], 7)
        self.assertEqual(
            set(summary["observed_raw_differences"]),
            set(MODULE.EXPECTED_RAW_DIFFERENCES),
        )
        self.assertTrue(
            all(
                value == ["stderr"]
                for value in summary[
                    "observed_raw_differences"
                ].values()
            )
        )

    @unittest.skipUnless(REPORT.exists(), "Linux output matrix not collected")
    def test_json_trees_match_three_oracles(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        for sample_name, cases in report["matrix"].items():
            case = cases["json"]
            with self.subTest(sample=sample_name):
                self.assertTrue(case["qt5_qt6_json_projection_equal"])
                self.assertTrue(
                    case["windows_linux_qt5_json_projection_equal"]
                )
                self.assertEqual(
                    case["qt5_json_detect_tree"],
                    case["qt6_json_detect_tree"],
                )
                self.assertEqual(
                    case["qt5_json_detect_tree"],
                    case["windows_qt5_json_detect_tree"],
                )

    @unittest.skipUnless(REPORT.exists(), "Linux output matrix not collected")
    def test_validity_and_priority_are_frozen_per_sample(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        invalid_xml = set(
            report["summary"]["expected_invalid_xml_samples"]
        )
        self.assertEqual(
            invalid_xml,
            set(MODULE.windows_collector.EXPECTED_INVALID_XML),
        )
        for sample_name, cases in report["matrix"].items():
            for case_name, case in cases.items():
                with self.subTest(sample=sample_name, case=case_name):
                    self.assertTrue(
                        case["output_validity_expected_equal"]
                    )
            all_flags = cases["all_output_flags"]
            for platform in ("qt5", "qt6"):
                self.assertTrue(
                    all_flags[
                        f"{platform}_priority_reference_equal"
                    ]
                )
                self.assertEqual(
                    all_flags[platform],
                    cases["csv"][platform],
                )

    @unittest.skipUnless(REPORT.exists(), "Linux output matrix not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\", text)
        self.assertNotIn("I:/", text)
        self.assertNotIn("die-windows-corpus", text)
        self.assertIn("/corpus/minimal.elf", text)


if __name__ == "__main__":
    unittest.main()

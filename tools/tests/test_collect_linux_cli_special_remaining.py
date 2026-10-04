import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_linux_cli_special_remaining.py"
DEFINITIONS = ROOT / "tools/upstream/compare_cli_oracles.py"
WINDOWS_COLLECTOR = (
    ROOT / "tools/upstream/collect_windows_cli_special_remaining.py"
)
WINDOWS_REPORT = (
    ROOT
    / "docs/research/data/windows-qt5-cli-special-remaining.json"
)
REPORT = (
    ROOT
    / "docs/research/data/linux-qt5-qt6-cli-special-remaining.json"
)
MANIFEST = ROOT / "docs/research/data/baseline-corpus.json"
SPEC = importlib.util.spec_from_file_location(
    "collect_linux_cli_special_remaining",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectLinuxCliSpecialRemainingTests(unittest.TestCase):
    def test_pinned_images_and_matrix_are_explicit(self):
        self.assertEqual(
            MODULE.UPSTREAM_COMMIT,
            "74eaf505c250ab47e709024e9dc41657cd8f2254",
        )
        self.assertEqual(
            MODULE.QT5_IMAGE_ID,
            "sha256:"
            "466102628c3a94b7ab1048f0c24261b1920e61a40029b128763cf79370255040",
        )
        self.assertEqual(
            MODULE.QT6_IMAGE_ID,
            "sha256:"
            "e015495c313d0715f0b80f395da983a113a439f2a135eb637e9f0638c225200b",
        )
        self.assertEqual(len(MODULE.matrix.SPECIAL_MATRIX), 19)
        self.assertEqual(
            set(MODULE.windows_collector.JSON_CASES)
            | set(MODULE.windows_collector.XML_CASES),
            {
                "entropy_json",
                "entropy_xml",
                "entropy_all_output_flags",
                "info_json",
                "info_xml",
                "info_all_output_flags",
                "struct_hash_json",
                "struct_hash_md5_json",
                "struct_unknown_json",
                "entropy_over_info_struct_json",
                "struct_over_info_json",
            },
        )

    @unittest.skipUnless(REPORT.exists(), "Linux special matrix not collected")
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
            report["windows_collector"]["sha256"],
            hashlib.sha256(WINDOWS_COLLECTOR.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["windows_reference"]["sha256"],
            hashlib.sha256(WINDOWS_REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["platforms"]["linux-x86_64-qt5"]["id"],
            MODULE.QT5_IMAGE_ID,
        )
        self.assertEqual(
            report["platforms"]["linux-x86_64-qt6"]["id"],
            MODULE.QT6_IMAGE_ID,
        )
        self.assertEqual(
            report["corpus_manifest"]["sample_count"],
            len(manifest["samples"]),
        )
        self.assertEqual(report["selection"], windows["selection"])
        self.assertEqual(report["cases"], windows["cases"])
        self.assertEqual(report["summary"]["sample_count"], 21)
        self.assertEqual(report["summary"]["case_count"], 399)
        self.assertEqual(report["summary"]["execution_count"], 798)
        self.assertEqual(
            report["summary"]["structured_case_count"],
            231,
        )

    @unittest.skipUnless(REPORT.exists(), "Linux special matrix not collected")
    def test_committed_report_has_no_observed_failures(self):
        summary = json.loads(
            REPORT.read_text(encoding="utf-8")
        )["summary"]
        for key in (
            "raw_equal",
            "all_exits_zero",
            "all_stderr_empty",
            "all_outputs_valid",
            "qt_structured_projections_equal",
            "windows_linux_qt5_structured_projections_equal",
            "priority_references_equal",
        ):
            self.assertTrue(summary[key], key)
        for key in (
            "raw_difference_failures",
            "exit_failures",
            "stderr_failures",
            "validity_failures",
            "qt_projection_failures",
            "windows_projection_failures",
            "priority_failures",
        ):
            self.assertEqual(summary[key], [], key)

    @unittest.skipUnless(REPORT.exists(), "Linux special matrix not collected")
    def test_structured_projections_match_three_oracles(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        structured = set(MODULE.windows_collector.JSON_CASES) | set(
            MODULE.windows_collector.XML_CASES
        )
        for sample_name, cases in report["matrix"].items():
            for case_name in structured:
                with self.subTest(sample=sample_name, case=case_name):
                    case = cases[case_name]
                    self.assertTrue(case["qt5_qt6_projection_equal"])
                    self.assertTrue(
                        case["windows_linux_qt5_projection_equal"]
                    )
                    self.assertEqual(
                        case["qt5_projection"],
                        case["qt6_projection"],
                    )
                    self.assertEqual(
                        case["qt5_projection"],
                        case["windows_qt5_projection"],
                    )

    @unittest.skipUnless(REPORT.exists(), "Linux special matrix not collected")
    def test_priority_references_are_raw_equal_on_both_qt_versions(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        for sample_name, cases in report["matrix"].items():
            for case_name, reference in (
                MODULE.windows_collector.PRIORITY_REFERENCES.items()
            ):
                for platform in ("qt5", "qt6"):
                    with self.subTest(
                        sample=sample_name,
                        case=case_name,
                        platform=platform,
                    ):
                        case = cases[case_name]
                        self.assertEqual(
                            case[f"{platform}_priority_reference_case"],
                            reference,
                        )
                        self.assertTrue(
                            case[f"{platform}_priority_reference_equal"]
                        )
                        self.assertEqual(
                            case[platform],
                            cases[reference][platform],
                        )

    @unittest.skipUnless(REPORT.exists(), "Linux special matrix not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\", text)
        self.assertNotIn("I:/", text)
        self.assertNotIn("die-windows-corpus", text)
        self.assertIn("/corpus/minimal.elf", text)
        self.assertIn("<corpus>/minimal.elf", text)


if __name__ == "__main__":
    unittest.main()

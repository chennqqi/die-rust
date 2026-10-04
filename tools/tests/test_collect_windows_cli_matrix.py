import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_windows_cli_matrix.py"
DEFINITIONS = ROOT / "tools/upstream/compare_cli_oracles.py"
REPORT = ROOT / "docs/research/data/windows-qt5-cli-matrix.json"
BASELINE_REPORT = (
    ROOT / "docs/research/data/baseline-corpus-windows-qt5.json"
)
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
MANIFEST = ROOT / "docs/research/data/baseline-corpus.json"
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_matrix",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliMatrixTests(unittest.TestCase):
    def test_matrix_definitions_are_reused_without_copying(self):
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
        self.assertEqual(
            len(MODULE.matrix_definitions.SCAN_MATRIX),
            8,
        )
        self.assertEqual(
            len(MODULE.matrix_definitions.SPECIAL_MATRIX),
            19,
        )

    def test_translate_arguments_replaces_only_pinned_database_paths(self):
        source = Path("C:/source")
        actual = MODULE.translate_arguments(
            MODULE.matrix_definitions.SCAN_MATRIX[0].arguments,
            source,
            report=False,
        )
        reported = MODULE.translate_arguments(
            MODULE.matrix_definitions.SCAN_MATRIX[0].arguments,
            source,
            report=True,
        )
        self.assertIn(str(source / "Detect-It-Easy" / "db"), actual)
        self.assertIn("<source>/Detect-It-Easy/db", reported)
        self.assertFalse(
            any(item.startswith("/opt/die-source") for item in actual)
        )

    def test_observation_differences_preserves_raw_dimensions(self):
        first = MODULE.baseline.Observation(0, b"first", b"")
        second = MODULE.baseline.Observation(1, b"second", b"error")
        self.assertEqual(
            MODULE.observation_differences(first, second),
            ["exit_code", "stdout", "stderr"],
        )

    @unittest.skipUnless(REPORT.exists(), "Windows matrix not collected")
    def test_committed_report_is_bound_and_complete(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        baseline = json.loads(BASELINE_REPORT.read_text(encoding="utf-8"))
        build = json.loads(WINDOWS_BUILD.read_text(encoding="utf-8"))
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["platform"], "windows-x86_64-qt5")
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["matrix_definitions"]["sha256"],
            hashlib.sha256(DEFINITIONS.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["source"], baseline["source"])
        self.assertEqual(report["qt"], baseline["qt"])
        self.assertEqual(
            report["binary"]["sha256"],
            baseline["binary"]["sha256"],
        )
        self.assertEqual(
            report["windows_default_reference"]["sha256"],
            hashlib.sha256(BASELINE_REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            build["windows_cli_matrix"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            build["windows_cli_matrix"]["execution_count"],
            report["summary"]["execution_count"],
        )
        self.assertEqual(
            report["corpus_manifest"]["sample_count"],
            len(manifest["samples"]),
        )
        self.assertEqual(
            report["summary"]["case_counts"],
            {"output": 35, "scan": 208, "special": 95},
        )
        self.assertEqual(report["summary"]["case_count"], 338)
        self.assertEqual(report["summary"]["execution_count"], 676)

    @unittest.skipUnless(REPORT.exists(), "Windows matrix not collected")
    def test_committed_report_has_no_observed_failures(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["summary"]["deterministic"])
        self.assertTrue(report["summary"]["default_reference_equal"])
        self.assertTrue(report["summary"]["linux_exit_codes_equal"])
        self.assertEqual(report["summary"]["determinism_failures"], [])
        self.assertEqual(
            report["summary"]["default_reference_failures"],
            [],
        )
        self.assertEqual(
            report["summary"]["linux_exit_code_failures"],
            [],
        )

    @unittest.skipUnless(REPORT.exists(), "Windows matrix not collected")
    def test_scan_default_matches_committed_windows_baseline(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        baseline = json.loads(BASELINE_REPORT.read_text(encoding="utf-8"))
        self.assertEqual(
            set(report["selection"]["scan"]),
            set(baseline["corpus"]),
        )
        for name in report["selection"]["scan"]:
            with self.subTest(sample=name):
                observed = report["matrix"][name]["scan"]["default"]
                reference = baseline["corpus"][name]
                self.assertTrue(
                    observed["windows_default_reference_equal"]
                )
                self.assertEqual(
                    observed["first_detect_tree"],
                    reference["first_detect_tree"],
                )
                self.assertEqual(
                    observed["second_detect_tree"],
                    reference["second_detect_tree"],
                )

    @unittest.skipUnless(REPORT.exists(), "Windows matrix not collected")
    def test_every_matrix_case_was_run_twice_without_drift(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        for name, sample in report["matrix"].items():
            for kind, cases in sample.items():
                for case_name, case in cases.items():
                    with self.subTest(
                        sample=name,
                        kind=kind,
                        case=case_name,
                    ):
                        self.assertEqual(
                            case["determinism_differences"],
                            [],
                        )
                        self.assertEqual(
                            case["first"],
                            case["second"],
                        )

    @unittest.skipUnless(REPORT.exists(), "Windows matrix not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\tmp", text)
        self.assertNotIn("die-windows-script-source", text)
        self.assertIn("<source>/Detect-It-Easy/db", text)
        self.assertIn("<corpus>/minimal.exe", text)


if __name__ == "__main__":
    unittest.main()

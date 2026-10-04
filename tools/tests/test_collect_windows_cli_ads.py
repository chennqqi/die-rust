import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_windows_cli_ads.py"
FIXTURE_SCRIPT = ROOT / "tools/corpus/generate_windows_ads_fixture.py"
MANIFEST = ROOT / "docs/research/data/windows-ads-fixture.json"
REPORT = ROOT / "docs/research/data/windows-qt5-cli-ads.json"
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_ads",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliAdsTests(unittest.TestCase):
    def test_case_builder_separates_stream_and_enumeration_controls(self):
        cases = MODULE.build_cases(
            Path("C:/fixture"),
            Path("C:/corpus"),
        )
        self.assertEqual(len(cases), 5)
        self.assertEqual(
            {case.name for case in cases},
            {
                "pdf_control",
                "carrier_default_stream",
                "named_pdf_stream",
                "extended_named_pdf_stream",
                "directory_enumeration",
            },
        )
        references = {
            case.name: case.reference_sample for case in cases
        }
        self.assertEqual(references["named_pdf_stream"], "minimal.pdf")
        self.assertEqual(
            references["directory_enumeration"],
            "plain.txt",
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
            build["windows_cli_ads"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["summary"]["case_count"], 5)
        self.assertEqual(report["summary"]["execution_count"], 10)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_named_stream_and_directory_findings_are_fixed(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["summary"]["deterministic"])
        self.assertTrue(report["summary"]["expected_exits_equal"])
        self.assertTrue(report["summary"]["all_json_valid"])
        self.assertTrue(
            report["summary"]["reference_projections_equal"]
        )
        self.assertTrue(all(report["findings"].values()))

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\tmp", text)
        self.assertNotIn("die-windows-script-source", text)
        self.assertNotIn("die-windows-ads-", text)
        self.assertIn("<extended-fixture>/ads/carrier.bin:payload.pdf", text)
        self.assertIn("<source>/Detect-It-Easy/db", text)


if __name__ == "__main__":
    unittest.main()

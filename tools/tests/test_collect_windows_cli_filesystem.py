import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_windows_cli_filesystem.py"
FIXTURE_SCRIPT = (
    ROOT / "tools/corpus/generate_windows_filesystem_fixture.py"
)
MANIFEST = ROOT / "docs/research/data/windows-filesystem-fixture.json"
REPORT = ROOT / "docs/research/data/windows-qt5-cli-filesystem.json"
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_filesystem",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliFilesystemTests(unittest.TestCase):
    def test_case_builder_covers_junction_chain_and_extended_namespace(self):
        cases = MODULE.build_cases(
            Path("C:/source"),
            Path("C:/fixture"),
        )
        self.assertEqual(len(cases), 8)
        self.assertEqual(
            {case.name for case in cases},
            {
                "single_real_file",
                "single_file_through_junction",
                "directory_real",
                "directory_junction",
                "directory_junction_chain",
                "tree_real_and_junction",
                "extended_single_real_file",
                "extended_directory_junction",
            },
        )
        extended = [
            case
            for case in cases
            if case.name.startswith("extended_")
        ]
        self.assertTrue(
            all(
                case.arguments[-1].startswith("\\\\?\\")
                for case in extended
            )
        )

    def test_prefix_parser_preserves_output_order(self):
        paths = {
            "real": Path("I:/fixture/tree/real/child.pdf"),
            "alias": Path("I:/fixture/tree/alias/child.pdf"),
        }
        data = (
            str(paths["alias"]).encode()
            + b":\r\n{}\r\n"
            + str(paths["real"]).encode()
            + b":\r\n{}\r\n"
        )
        self.assertEqual(
            MODULE.prefix_ids(data, paths),
            ["alias", "real"],
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
            build["windows_cli_filesystem"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["summary"]["case_count"], 8)
        self.assertEqual(report["summary"]["execution_count"], 16)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_junction_and_extended_cases_are_stable(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["summary"]["deterministic"])
        self.assertTrue(report["summary"]["expected_exits_equal"])
        self.assertTrue(
            report["summary"]["reference_projections_equal"]
        )
        findings = report["findings"]
        self.assertTrue(
            findings["explicit_file_through_junction_is_scanned"]
        )
        self.assertTrue(
            findings["explicit_junction_directory_is_scanned"]
        )
        self.assertTrue(
            findings["finite_two_junction_chain_is_scanned"]
        )
        self.assertEqual(
            findings["enumerated_tree_prefix_ids"],
            ["tree_alias", "tree_real"],
        )
        self.assertFalse(
            findings["enumerated_tree_is_single_valid_json"]
        )
        self.assertTrue(
            findings["extended_file_matches_ordinary_raw_stdout"]
        )
        self.assertTrue(
            findings[
                "extended_junction_matches_ordinary_raw_stdout"
            ]
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\tmp", text)
        self.assertNotIn("die-windows-script-source", text)
        self.assertNotIn("die-windows-filesystem-", text)
        self.assertIn("<extended-fixture>/", text)
        self.assertIn("<source>/Detect-It-Easy/db", text)


if __name__ == "__main__":
    unittest.main()

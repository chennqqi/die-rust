import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_windows_cli_path_nested.py"
DEFINITIONS = ROOT / "tools/upstream/compare_cli_oracles.py"
REPORT = (
    ROOT / "docs/research/data/windows-qt5-cli-path-nested.json"
)
PATH_MANIFEST = ROOT / "docs/research/data/path-corpus.json"
NESTED_MANIFEST = ROOT / "docs/research/data/nested-corpus.json"
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_path_nested",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliPathNestedTests(unittest.TestCase):
    def test_matrix_definitions_are_reused_without_copying(self):
        self.assertEqual(
            [case.name for case in MODULE.matrix_definitions.NESTED_MATRIX],
            [
                "default",
                "recursive",
                "aggressive",
                "recursive_aggressive",
            ],
        )
        self.assertEqual(
            len(MODULE.matrix_definitions.PATH_CASES),
            14,
        )

    def test_translation_maps_posix_fixture_paths_to_windows(self):
        translated = MODULE.translate_arguments(
            (
                "--json",
                "/paths/tree/a-first.pdf",
                "/nested/pdf-member.zip",
            ),
            Path("C:/source"),
            Path("C:/fixtures/path"),
            Path("C:/fixtures/nested"),
            report=False,
        )
        self.assertEqual(
            translated,
            (
                "--json",
                str(Path("C:/fixtures/path/tree/a-first.pdf")),
                str(Path("C:/fixtures/nested/pdf-member.zip")),
            ),
        )
        reported = MODULE.translate_arguments(
            translated[:1]
            + (
                "/paths/tree/a-first.pdf",
                "/nested/pdf-member.zip",
            ),
            Path("C:/source"),
            Path("C:/fixtures/path"),
            Path("C:/fixtures/nested"),
            report=True,
        )
        self.assertEqual(
            reported,
            (
                "--json",
                "<paths>/tree/a-first.pdf",
                "<nested>/pdf-member.zip",
            ),
        )

    def test_relative_prefixes_remove_case_insensitive_windows_root(self):
        data = (
            b"I:\\fixtures\\path\\tree\\z-last.txt:\r\n"
            b"I:\\FIXTURES\\PATH\\tree\\a-first.pdf:\r\n"
            b'{"detects":[]}\r\n'
        )
        self.assertEqual(
            MODULE.relative_filename_prefixes(
                data,
                Path("I:/fixtures/path"),
            ),
            [
                "<paths>/tree/z-last.txt",
                "<paths>/tree/a-first.pdf",
            ],
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_committed_report_is_identity_bound_and_complete(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        build = json.loads(WINDOWS_BUILD.read_text(encoding="utf-8"))
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
        self.assertEqual(
            report["fixtures"]["path"]["sha256"],
            hashlib.sha256(PATH_MANIFEST.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["fixtures"]["nested"]["sha256"],
            hashlib.sha256(NESTED_MANIFEST.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            build["windows_cli_path_nested"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["summary"]["path_case_count"], 14)
        self.assertEqual(report["summary"]["nested_sample_count"], 8)
        self.assertEqual(report["summary"]["nested_case_count"], 32)
        self.assertEqual(report["summary"]["case_count"], 46)
        self.assertEqual(report["summary"]["execution_count"], 92)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_every_case_is_deterministic(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["summary"]["deterministic"])
        self.assertEqual(report["summary"]["determinism_failures"], [])
        for case_name, case in report["path"]["cases"].items():
            with self.subTest(kind="path", case=case_name):
                self.assertEqual(case["determinism_differences"], [])
                self.assertEqual(case["first"], case["second"])
        for sample_name, cases in report["nested"]["cases"].items():
            for case_name, case in cases.items():
                with self.subTest(
                    kind="nested",
                    sample=sample_name,
                    case=case_name,
                ):
                    self.assertEqual(
                        case["determinism_differences"],
                        [],
                    )
                    self.assertEqual(case["first"], case["second"])

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_cross_platform_semantic_projections_are_explicit(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["summary"]["linux_exit_codes_equal"])
        self.assertTrue(report["summary"]["path_prefixes_equal"])
        self.assertTrue(report["summary"]["nested_projections_equal"])
        self.assertEqual(
            report["summary"]["linux_exit_code_failures"],
            [],
        )
        self.assertEqual(report["summary"]["path_prefix_failures"], [])
        self.assertEqual(
            report["summary"]["nested_projection_failures"],
            [],
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\tmp", text)
        self.assertNotIn("die-windows-script-source", text)
        self.assertNotIn("die-windows-path", text)
        self.assertNotIn("die-windows-nested", text)
        self.assertIn("<paths>/tree/a-first.pdf", text)
        self.assertIn("<nested>/pdf-member.zip", text)


if __name__ == "__main__":
    unittest.main()

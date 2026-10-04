import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_windows_cli_database.py"
DEFINITIONS = ROOT / "tools/upstream/compare_cli_oracles.py"
REPORT = ROOT / "docs/research/data/windows-qt5-cli-database.json"
FIXTURE_MANIFEST = ROOT / "docs/research/data/database-fixture.json"
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_database",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliDatabaseTests(unittest.TestCase):
    def test_database_cases_are_reused_without_copying(self):
        self.assertEqual(
            len(MODULE.matrix_definitions.DATABASE_CASES),
            18,
        )
        self.assertEqual(
            [case.name for case in MODULE.matrix_definitions.DATABASE_CASES][
                :3
            ],
            [
                "show_database_missing_main",
                "show_database_missing_main_messages",
                "show_database_empty_main",
            ],
        )

    def test_translation_maps_fixture_and_source_paths(self):
        arguments = (
            "--database",
            "/opt/die-source/Detect-It-Easy/db",
            "--extradatabase",
            "/dbfx/empty-extra",
        )
        actual = MODULE.translate_arguments(
            arguments,
            Path("C:/source"),
            Path("C:/fixture"),
            report=False,
        )
        reported = MODULE.translate_arguments(
            arguments,
            Path("C:/source"),
            Path("C:/fixture"),
            report=True,
        )
        self.assertEqual(
            actual,
            (
                "--database",
                str(Path("C:/source/Detect-It-Easy/db")),
                "--extradatabase",
                str(Path("C:/fixture/empty-extra")),
            ),
        )
        self.assertEqual(
            reported,
            (
                "--database",
                "<source>/Detect-It-Easy/db",
                "--extradatabase",
                "<dbfx>/empty-extra",
            ),
        )

    def test_linux_normalizer_is_limited_to_arguments_and_crlf(self):
        actual = (
            "--database",
            r"I:\fixture\missing-main",
            r"I:\fixture\input\plain.txt",
        )
        linux = (
            "--database",
            "/dbfx/missing-main",
            "/dbfx/input/plain.txt",
        )
        data = (
            b"Cannot load database: I:\\fixture\\missing-main\r\n"
            b"I:/fixture/input/plain.txt\r\n"
            b'{"message":"do not rewrite"}\r\n'
        )
        self.assertEqual(
            MODULE.normalize_windows_stdout_for_linux(
                data,
                actual,
                linux,
            ),
            (
                b"Cannot load database: /dbfx/missing-main\n"
                b"/dbfx/input/plain.txt\n"
                b'{"message":"do not rewrite"}\n'
            ),
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
            report["fixture"]["sha256"],
            hashlib.sha256(FIXTURE_MANIFEST.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            build["windows_cli_database"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["summary"]["case_count"], 18)
        self.assertEqual(report["summary"]["execution_count"], 36)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_all_cases_are_deterministic(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["summary"]["deterministic"])
        self.assertEqual(report["summary"]["determinism_failures"], [])
        for name, case in report["cases"].items():
            with self.subTest(case=name):
                self.assertEqual(case["determinism_differences"], [])
                self.assertEqual(case["first"], case["second"])

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_named_cross_platform_contract_is_explicit(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["summary"]["linux_exit_codes_equal"])
        self.assertTrue(report["summary"]["linux_load_errors_equal"])
        self.assertTrue(
            report["summary"]["linux_document_validity_equal"]
        )
        self.assertTrue(
            report["summary"]["linux_normalized_stdout_equal"]
        )
        for key in (
            "linux_exit_code_failures",
            "linux_load_error_failures",
            "linux_document_validity_failures",
            "linux_normalized_stdout_failures",
        ):
            self.assertEqual(report["summary"][key], [])

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_rule_error_markers_remain_visible(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        malformed = report["cases"]["scan_malformed_main_json"]
        throwing = report["cases"]["scan_throwing_main_json"]
        self.assertTrue(malformed["reports_parse_error"])
        self.assertFalse(malformed["first_valid_json"])
        self.assertTrue(throwing["reports_runtime_error"])
        self.assertFalse(throwing["first_valid_json"])

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\tmp", text)
        self.assertNotIn("die-windows-script-source", text)
        self.assertNotIn("die-windows-database", text)
        self.assertIn("<dbfx>/missing-main", text)
        self.assertIn("<source>/Detect-It-Easy/db", text)


if __name__ == "__main__":
    unittest.main()

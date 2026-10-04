import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT / "tools/upstream/collect_windows_cli_database_archives.py"
)
WINDOWS_HELPER = (
    ROOT / "tools/upstream/collect_windows_cli_database.py"
)
ARCHIVE_DEFINITIONS = (
    ROOT / "tools/upstream/probe_database_archives.py"
)
REPORT = (
    ROOT
    / "docs/research/data/windows-qt5-cli-database-archive.json"
)
LINUX_REFERENCE = (
    ROOT / "docs/research/data/database-archive-linux-qt5.json"
)
FIXTURE_MANIFEST = ROOT / "docs/research/data/database-fixture.json"
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_database_archives",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliDatabaseArchivesTests(unittest.TestCase):
    def test_archive_cases_are_reused_without_copying(self):
        cases = MODULE.archive_definitions.ARCHIVE_CASES
        self.assertEqual(len(cases), 17)
        self.assertEqual(
            [case.name for case in cases[:3]],
            [
                "show_database_valid_archive",
                "show_database_empty_archive",
                "show_database_truncated_archive",
            ],
        )
        self.assertEqual(
            cases[-1].name,
            "scan_prefixed_archive_json",
        )

    def test_translation_uses_existing_narrow_contract(self):
        arguments = (
            "--database",
            "/dbfx/valid-main.zip",
            "/dbfx/input/plain.txt",
        )
        self.assertEqual(
            MODULE.windows_database.translate_arguments(
                arguments,
                Path("C:/source"),
                Path("C:/fixture"),
                report=True,
            ),
            (
                "--database",
                "<dbfx>/valid-main.zip",
                "<dbfx>/input/plain.txt",
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
            report["windows_database_helper"]["sha256"],
            hashlib.sha256(WINDOWS_HELPER.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["archive_definitions"]["sha256"],
            hashlib.sha256(ARCHIVE_DEFINITIONS.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["fixture"]["sha256"],
            hashlib.sha256(FIXTURE_MANIFEST.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["linux_qt5_reference"]["sha256"],
            hashlib.sha256(LINUX_REFERENCE.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            build["windows_cli_database_archive"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["summary"]["case_count"], 17)
        self.assertEqual(report["summary"]["execution_count"], 34)

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
    def test_cross_platform_contract_is_explicit(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        for field in (
            "linux_exit_codes_equal",
            "linux_stderr_equal",
            "linux_document_validity_equal",
            "linux_normalized_stdout_equal",
        ):
            self.assertTrue(report["summary"][field])
        for field in (
            "linux_exit_code_failures",
            "linux_stderr_failures",
            "linux_document_validity_failures",
            "linux_normalized_stdout_failures",
        ):
            self.assertEqual(report["summary"][field], [])

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_parse_error_and_zip_entry_semantics_remain_visible(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        malformed = report["cases"][
            "scan_payload_structure_truncated_archive_json"
        ]
        duplicate = report["cases"]["scan_duplicate_archive_json"]
        traversal = report["cases"]["scan_traversal_archive_json"]
        self.assertTrue(malformed["reports_parse_error"])
        self.assertFalse(malformed["first_valid_json"])
        self.assertTrue(duplicate["first_valid_json"])
        self.assertTrue(traversal["first_valid_json"])

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\tmp", text)
        self.assertNotIn("I:/tmp", text)
        self.assertNotIn("die-windows-script-source", text)
        self.assertNotIn("die-windows-database", text)
        self.assertIn("<dbfx>/valid-main.zip", text)


if __name__ == "__main__":
    unittest.main()

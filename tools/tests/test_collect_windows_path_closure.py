import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_windows_path_closure.py"
REPORT = (
    ROOT / "docs/research/data/windows-path-closure-qt5.json"
)


class CollectWindowsPathClosureTests(unittest.TestCase):
    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_formal_report_closes_all_named_path_profiles(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["passed"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["capability"], "CAP-CLI-IN-003")
        self.assertEqual(report["repetitions"], 2)
        self.assertEqual(report["case_count"], 23)
        self.assertEqual(report["execution_count"], 46)
        self.assertEqual(report["case_observation_count"], 46)
        self.assertEqual(len(report["relationships"]), 21)
        self.assertTrue(all(report["relationships"].values()))
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_covers_each_profile_group(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(len(report["large_directory_cases"]), 5)
        self.assertEqual(len(report["reparse_cases"]), 3)
        self.assertEqual(len(report["toctou_cases"]), 4)
        self.assertEqual(len(report["unc_cases"]), 8)
        self.assertEqual(len(report["acl_cases"]), 3)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_absolute_path(self):
        text = REPORT.read_text(encoding="utf-8")
        for forbidden in (
            "C:/Users",
            "C:\\\\Users",
            "I:/tmp",
            "I:\\\\tmp",
            "worker",
            WSL_LOCAL_ROOT,
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)


WSL_LOCAL_ROOT = (
    "die-rust-windows-path-closure-74eaf505-evidence"
)


if __name__ == "__main__":
    unittest.main()

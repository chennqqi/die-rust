import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT / "tools/upstream/collect_windows_result_model_harnesses.py"
)
REPORT = (
    ROOT / "docs/research/data/result-model-engine-windows-qt5.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_result_model_harnesses",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsResultModelHarnessesTests(unittest.TestCase):
    def test_fixture_replacement_is_prefix_scoped(self):
        value = {
            "root": "I:/controlled/fixture",
            "child": "I:\\controlled\\fixture\\main\\rule.sg",
            "similar": "I:/controlled/fixture-like/rule.sg",
            "collection": (
                "/tmp/die-result-list-collection\\files\\item.bin"
            ),
        }
        normalized = MODULE.replace_fixture_paths(
            value,
            Path("I:/controlled/fixture"),
        )
        self.assertEqual(normalized["root"], "/fixture")
        self.assertEqual(
            normalized["child"],
            "/fixture/main/rule.sg",
        )
        self.assertEqual(
            normalized["similar"],
            "I:/controlled/fixture-like/rule.sg",
        )
        self.assertEqual(
            normalized["collection"],
            "/tmp/die-result-list-collection/files/item.bin",
        )

    def test_uuid_normalization_preserves_parent_link(self):
        document = {
            "records": [
                {
                    "id": {"uuid": "first"},
                    "parent_id": {"uuid": ""},
                },
                {
                    "id": {"uuid": "second"},
                    "parent_id": {"uuid": "first"},
                },
            ]
        }
        normalized, observed = MODULE.normalize_nondeterministic(
            "ids",
            document,
        )
        self.assertEqual(observed["uuids"], ["first", "second"])
        self.assertEqual(
            normalized["records"][0]["id"]["uuid"],
            "<uuid-1>",
        )
        self.assertEqual(
            normalized["records"][1]["parent_id"]["uuid"],
            "<uuid-1>",
        )
        self.assertEqual(
            normalized["records"][1]["id"]["uuid"],
            "<uuid-2>",
        )

    def test_all_linux_references_remain_valid(self):
        for profile, specification in MODULE.PROFILES.items():
            with self.subTest(profile=profile):
                path = (
                    ROOT
                    / "docs/research/data"
                    / str(specification["reference"])
                )
                report = json.loads(path.read_text(encoding="utf-8"))
                normalized, _, relationships = (
                    MODULE.normalized_document(
                        profile,
                        copy.deepcopy(report["harness_output"]),
                        None,
                    )
                )
                self.assertTrue(normalized)
                self.assertEqual(
                    relationships,
                    report["relationships"],
                )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_formal_report_closes_all_six_capabilities(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["passed"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["repetitions"], 2)
        self.assertEqual(report["execution_count"], 10)
        self.assertEqual(report["case_observation_count"], 30)
        self.assertEqual(
            report["capability_scope"],
            [f"CAP-RESULT-00{index}" for index in range(1, 7)],
        )
        self.assertEqual(set(report["reports"]), set(MODULE.PROFILES))
        self.assertTrue(
            all(
                report["record_metadata_evidence"]["facts"].values()
            )
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_each_profile_matches_linux_after_narrow_normalization(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        for profile, profile_report in report["reports"].items():
            with self.subTest(profile=profile):
                self.assertEqual(profile_report["repetitions"], 2)
                self.assertTrue(
                    profile_report["normalized_outputs_equal"]
                )
                self.assertTrue(profile_report["relationships_equal"])
                self.assertTrue(
                    profile_report[
                        "linux_qt5_semantic_document_equal"
                    ]
                )
                self.assertTrue(
                    all(profile_report["relationships"].values())
                )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_path(self):
        text = REPORT.read_text(encoding="utf-8")
        for forbidden in (
            "C:/Users",
            "C:\\\\Users",
            "I:/tmp",
            "I:\\\\tmp",
            "worker",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()

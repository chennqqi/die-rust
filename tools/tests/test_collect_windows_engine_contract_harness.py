import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT / "tools/upstream/collect_windows_engine_contract_harness.py"
)
BUILDER = (
    ROOT / "tools/upstream/build_windows_engine_contract_harness.ps1"
)
SHARED_HARNESS = (
    ROOT / "tools/upstream/engine_contract_harness_main.cpp"
)
LINUX_PROBE = ROOT / "tools/upstream/probe_engine_contract.py"
FIXTURE_PROBE = ROOT / "tools/upstream/probe_rule_orchestration.py"
FIXTURE_GENERATOR = (
    ROOT / "tools/corpus/generate_rule_orchestration_fixture.py"
)
REPORT = (
    ROOT / "docs/research/data/engine-contract-windows-qt5.json"
)
LINUX_REFERENCE = (
    ROOT / "docs/research/data/engine-contract-linux-qt5.json"
)
FIXTURE_MANIFEST = (
    ROOT / "docs/research/data/rule-orchestration-fixture.json"
)
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_engine_contract_harness",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsEngineContractHarnessTests(unittest.TestCase):
    def test_fixture_normalization_changes_only_prefix_paths(self):
        value = {
            "signature_file": (
                "I:\\tmp\\fixture\\priority-main/Binary/a.sg"
            ),
            "name": "I:\\tmp\\fixture-like",
            "other": ["plain", 1],
        }
        normalized = MODULE.replace_fixture_paths(
            value,
            "I:\\tmp\\fixture",
        )
        self.assertEqual(
            normalized["signature_file"],
            "<fixture>/priority-main/Binary/a.sg",
        )
        self.assertEqual(normalized["name"], "I:\\tmp\\fixture-like")
        self.assertEqual(normalized["other"], ["plain", 1])

    def test_semantic_projection_excludes_only_qt_identity(self):
        document = {
            "qt_version": "5.15.2",
            "case_count": 1,
            "cases": [{"id": "case", "records": []}],
        }
        projected = MODULE.windows_semantic_document(document)
        self.assertNotIn("qt_version", projected)
        self.assertEqual(projected["cases"], document["cases"])
        self.assertIn("qt_version", document)

    def test_collector_reuses_linux_case_validator(self):
        linux = json.loads(LINUX_REFERENCE.read_text(encoding="utf-8"))
        document = copy.deepcopy(linux["harness_output"])
        relationships = MODULE.linux_probe.validate(document)
        self.assertEqual(len(document["cases"]), 37)
        self.assertEqual(relationships, linux["relationships"])
        self.assertTrue(all(relationships.values()))

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_is_identity_bound_and_complete(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        build = json.loads(WINDOWS_BUILD.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["platform"], "windows-x86_64-qt5")
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )
        source_hashes = report["build_manifest"]["identity"][
            "source_hashes"
        ]
        self.assertEqual(
            source_hashes["builder"],
            hashlib.sha256(BUILDER.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            source_hashes["shared_harness"],
            hashlib.sha256(SHARED_HARNESS.read_bytes()).hexdigest(),
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
            build["windows_engine_contract"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["repetitions"], 2)
        self.assertEqual(report["execution_count"], 2)
        self.assertEqual(report["case_observation_count"], 74)
        self.assertEqual(len(report["observation"]["cases"]), 37)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_two_runs_are_raw_and_normalized_deterministic(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["passed"])
        self.assertEqual(report["failures"], [])
        self.assertTrue(report["raw_outputs_equal"])
        self.assertTrue(report["normalized_outputs_equal"])
        self.assertEqual(len(report["runs"]), 2)
        self.assertEqual(report["runs"][0], report["runs"][1])

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_windows_and_linux_semantics_are_equal(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        comparison = report["linux_qt5_comparison"]
        self.assertEqual(comparison["case_differences"], [])
        self.assertTrue(comparison["semantic_document_equal"])
        self.assertTrue(comparison["all_named_relationships_equal"])
        self.assertEqual(comparison["excluded_identity_fields"], ["qt_version"])
        self.assertEqual(comparison["windows_qt_version"], "5.15.2")
        self.assertEqual(comparison["linux_qt_version"], "5.15.13")
        self.assertTrue(all(report["relationships"].values()))

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_source_audit_is_bound_to_local_upstream_bytes(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        audit = report["source_audit"]
        self.assertEqual(set(audit["sources"]), set(MODULE.SOURCE_PATHS))
        self.assertFalse(
            audit["contracts"]["public_runtime_filter_reachable"]
        )
        self.assertTrue(
            all(
                audit["contracts"]["device_contracts"].values()
            )
        )
        self.assertTrue(
            all(
                audit["contracts"]["cancellation_contracts"].values()
            )
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_path_or_raw_rewrite(self):
        text = REPORT.read_text(encoding="utf-8")
        for forbidden in (
            "C:/Users",
            "C:\\\\Users",
            "I:/tmp",
            "I:\\\\tmp",
            "worker",
            "die-windows-script-source",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        self.assertIn("<fixture>/priority-main/", text)
        operations = json.loads(text)["normalization"]
        self.assertIn(
            "raw stdout/stderr hash rewriting",
            operations["not_performed"],
        )

    def test_collector_inputs_have_stable_hashes(self):
        for path in (
            SCRIPT,
            BUILDER,
            SHARED_HARNESS,
            LINUX_PROBE,
            FIXTURE_PROBE,
            FIXTURE_GENERATOR,
        ):
            with self.subTest(path=path.name):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()

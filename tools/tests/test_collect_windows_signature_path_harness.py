import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT / "tools/upstream/collect_windows_signature_path_harness.py"
)
BUILDER = (
    ROOT / "tools/upstream/build_windows_signature_path_harness.ps1"
)
HARNESS = ROOT / "tools/upstream/signature_path_harness_main.cpp"
LINUX_PROBE = ROOT / "tools/upstream/probe_signature_path_harness.py"
FIXTURE_MANIFEST = (
    ROOT / "docs/research/data/signature-path-fixture.json"
)
LINUX_REFERENCE = (
    ROOT / "docs/research/data/signature-path-engine-qt5.json"
)
WINDOWS_REPORT = (
    ROOT
    / "docs/research/data/signature-path-engine-windows-qt5.json"
)
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_signature_path_harness",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsSignaturePathHarnessTests(unittest.TestCase):
    def test_fixture_path_replacement_changes_only_prefix(self):
        value = {
            "fixture_root": "I:\\controlled\\fixture",
            "path": (
                "I:\\controlled\\fixture\\main/Binary/shared.1.sg"
            ),
            "dot": (
                "I:\\controlled\\fixture/main/Binary/../"
                "Binary/shared.1.sg"
            ),
            "similar": "I:\\controlled\\fixture-like\\shared.1.sg",
            "basename": "shared.1.sg",
        }
        normalized = MODULE.replace_fixture_paths(
            value,
            Path("I:/controlled/fixture"),
        )
        self.assertEqual(normalized["fixture_root"], "/fixture")
        self.assertEqual(
            normalized["path"],
            "/fixture/main/Binary/shared.1.sg",
        )
        self.assertEqual(
            normalized["dot"],
            "/fixture/main/Binary/../Binary/shared.1.sg",
        )
        self.assertEqual(
            normalized["similar"],
            "I:\\controlled\\fixture-like\\shared.1.sg",
        )
        self.assertEqual(normalized["basename"], "shared.1.sg")

    def test_fixture_argument_uses_qt_path_spelling(self):
        self.assertEqual(
            MODULE.qt_path_argument(
                Path("I:/controlled/fixture")
            ),
            "I:/controlled/fixture",
        )
        self.assertNotIn(
            "\\",
            MODULE.qt_path_argument(
                Path("I:/controlled/fixture")
            ),
        )

    def test_linux_reference_remains_valid(self):
        report = json.loads(
            LINUX_REFERENCE.read_text(encoding="utf-8")
        )
        document = MODULE.validate_linux_reference(
            copy.deepcopy(report),
            hashlib.sha256(FIXTURE_MANIFEST.read_bytes()).hexdigest(),
        )
        relationships = MODULE.linux_probe.validate(document)
        self.assertEqual(relationships, report["relationships"])
        self.assertEqual(len(relationships), 11)

    @unittest.skipUnless(
        WINDOWS_REPORT.exists(),
        "Windows signature-path report not collected",
    )
    def test_report_is_identity_bound_and_complete(self):
        report = json.loads(
            WINDOWS_REPORT.read_text(encoding="utf-8")
        )
        build = json.loads(WINDOWS_BUILD.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["platform"], "windows-x86_64-qt5")
        self.assertEqual(report["capability"], "CAP-RULE-007")
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
            hashlib.sha256(HARNESS.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["fixture"]["manifest_sha256"],
            hashlib.sha256(FIXTURE_MANIFEST.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["linux_qt5_reference"]["sha256"],
            hashlib.sha256(LINUX_REFERENCE.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            build["windows_signature_path"]["sha256"],
            hashlib.sha256(WINDOWS_REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["repetitions"], 2)
        self.assertEqual(report["execution_count"], 2)
        self.assertEqual(report["case_observation_count"], 14)

    @unittest.skipUnless(
        WINDOWS_REPORT.exists(),
        "Windows signature-path report not collected",
    )
    def test_two_runs_are_raw_and_normalized_deterministic(self):
        report = json.loads(
            WINDOWS_REPORT.read_text(encoding="utf-8")
        )
        self.assertTrue(report["passed"])
        self.assertEqual(report["failures"], [])
        self.assertTrue(report["raw_outputs_equal"])
        self.assertTrue(report["normalized_outputs_equal"])
        self.assertEqual(len(report["runs"]), 2)
        self.assertEqual(report["runs"][0], report["runs"][1])

    @unittest.skipUnless(
        WINDOWS_REPORT.exists(),
        "Windows signature-path report not collected",
    )
    def test_windows_matches_linux_after_prefix_mapping(self):
        report = json.loads(
            WINDOWS_REPORT.read_text(encoding="utf-8")
        )
        linux = json.loads(
            LINUX_REFERENCE.read_text(encoding="utf-8")
        )
        comparison = report["linux_qt5_comparison"]
        self.assertTrue(comparison["semantic_document_equal"])
        self.assertTrue(comparison["relationships_equal"])
        self.assertTrue(comparison["path_normalization_only"])
        self.assertEqual(
            report["harness_output"],
            linux["harness_output"],
        )
        self.assertEqual(report["relationships"], linux["relationships"])
        self.assertEqual(len(report["relationships"]), 11)
        self.assertTrue(all(report["relationships"].values()))

    @unittest.skipUnless(
        WINDOWS_REPORT.exists(),
        "Windows signature-path report not collected",
    )
    def test_msvc_access_alias_is_explicit_and_engine_is_unmodified(self):
        report = json.loads(
            WINDOWS_REPORT.read_text(encoding="utf-8")
        )
        access = report["access_method"]
        self.assertFalse(access["engine_objects_modified"])
        alias = report["build_manifest"]["identity"]["build"][
            "msvc_access_symbol_alias"
        ]
        self.assertTrue(
            alias["from_public_declaration"].startswith(
                "?processDetect@DiE_Script@@QEAAX"
            )
        )
        self.assertTrue(
            alias["to_private_definition"].startswith(
                "?processDetect@DiE_Script@@AEAAX"
            )
        )

    @unittest.skipUnless(
        WINDOWS_REPORT.exists(),
        "Windows signature-path report not collected",
    )
    def test_report_contains_no_local_path_or_semantic_rewrite(self):
        text = WINDOWS_REPORT.read_text(encoding="utf-8")
        for forbidden in (
            "C:/Users",
            "C:\\\\Users",
            "I:/tmp",
            "I:\\\\tmp",
            "worker",
            "die-windows-clean",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        report = json.loads(text)
        self.assertIn(
            "path canonicalization or dot-segment cleanup",
            report["normalization"]["not_performed"],
        )
        self.assertIn(
            "/fixture/main/Binary/../Binary/shared.1.sg",
            text,
        )

    def test_collector_inputs_have_stable_hashes(self):
        for path in (
            SCRIPT,
            BUILDER,
            HARNESS,
            LINUX_PROBE,
            FIXTURE_MANIFEST,
            LINUX_REFERENCE,
        ):
            with self.subTest(path=path.name):
                self.assertEqual(
                    len(hashlib.sha256(path.read_bytes()).hexdigest()),
                    64,
                )


if __name__ == "__main__":
    unittest.main()

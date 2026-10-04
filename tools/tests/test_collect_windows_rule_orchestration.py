import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT / "tools/upstream/collect_windows_rule_orchestration.py"
)
LINUX_PROBE = ROOT / "tools/upstream/probe_rule_orchestration.py"
FIXTURE_GENERATOR = (
    ROOT / "tools/corpus/generate_rule_orchestration_fixture.py"
)
FIXTURE_MANIFEST = (
    ROOT / "docs/research/data/rule-orchestration-fixture.json"
)
LINUX_REFERENCE = (
    ROOT / "docs/research/data/rule-orchestration-linux-qt5.json"
)
WINDOWS_REPORT = (
    ROOT / "docs/research/data/rule-orchestration-windows-qt5.json"
)
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_rule_orchestration",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsRuleOrchestrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(
            FIXTURE_MANIFEST.read_text(encoding="utf-8")
        )
        cls.linux = json.loads(
            LINUX_REFERENCE.read_text(encoding="utf-8")
        )

    def test_linux_reference_is_identity_bound_and_valid(self):
        MODULE.validate_linux_reference(
            copy.deepcopy(self.linux),
            copy.deepcopy(self.manifest),
            hashlib.sha256(FIXTURE_MANIFEST.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            set(self.linux["canonical_cases"]),
            set(MODULE.case_names(self.manifest)),
        )

    def test_materialize_arguments_replaces_only_fixture_prefix(self):
        fixture = Path("I:/controlled/rules")
        arguments = (
            "/fixture",
            "/fixture/main",
            "/fixture-like/main",
            "--json",
        )
        result = MODULE.materialize_arguments(arguments, fixture)
        self.assertEqual(result[0], str(fixture))
        self.assertEqual(result[1], str(fixture / "main"))
        self.assertEqual(result[2], "/fixture-like/main")
        self.assertEqual(result[3], "--json")

    def test_case_inventory_matches_linux_reference(self):
        cases = MODULE.build_cases(
            Path("I:/controlled/rules"),
            copy.deepcopy(self.manifest),
        )
        self.assertEqual(len(cases), 10)
        self.assertEqual(
            {case.name for case in cases},
            set(self.linux["canonical_cases"]),
        )
        self.assertTrue(
            all(
                argument.startswith("/fixture")
                or not argument.startswith("I:")
                for case in cases
                for argument in case.report_arguments
            )
        )

    def test_relationships_are_derived_from_canonical_cases(self):
        relationships = MODULE.calculate_relationships(
            copy.deepcopy(self.linux["canonical_cases"]),
            copy.deepcopy(self.manifest),
        )
        self.assertEqual(relationships, self.linux["relationships"])
        self.assertEqual(len(relationships), 14)
        self.assertTrue(all(relationships.values()))

        changed = copy.deepcopy(self.linux["canonical_cases"])
        changed["combined"]["execution_order"].append("decoy.0.sg")
        self.assertFalse(
            MODULE.calculate_relationships(
                changed,
                copy.deepcopy(self.manifest),
            )["wrong_file_type_rule_never_executes"]
        )

    def test_observe_uses_the_explicit_working_directory(self):
        completed = mock.Mock(
            returncode=0,
            stdout=b"stdout",
            stderr=b"",
        )
        with mock.patch.object(
            MODULE.subprocess,
            "run",
            return_value=completed,
        ) as run:
            observation = MODULE.observe(
                Path("I:/oracle/diec.exe"),
                Path("I:/qt"),
                Path("I:/controlled-work"),
                ("--json", "I:/fixture/probe.bin"),
                30,
            )
        self.assertEqual(observation.exit_code, 0)
        self.assertEqual(observation.stdout, b"stdout")
        self.assertEqual(
            run.call_args.kwargs["cwd"],
            Path("I:/controlled-work"),
        )
        environment = run.call_args.kwargs["env"]
        path_key = next(
            key for key in environment if key.upper() == "PATH"
        )
        self.assertTrue(
            environment[path_key].startswith(str(Path("I:/qt/bin")))
        )

    @unittest.skipUnless(
        WINDOWS_REPORT.exists(),
        "Windows rule-orchestration report not collected",
    )
    def test_report_is_identity_bound_and_complete(self):
        report = json.loads(
            WINDOWS_REPORT.read_text(encoding="utf-8")
        )
        build = json.loads(WINDOWS_BUILD.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["platform"], "windows-x86_64-qt5")
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
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
            report["binary"]["sha256"],
            build["clean_qmake_build"]["artifact"]["sha256"],
        )
        self.assertEqual(
            build["windows_rule_orchestration"]["sha256"],
            hashlib.sha256(WINDOWS_REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["repetitions"], 2)
        self.assertEqual(report["case_count"], 10)
        self.assertEqual(report["execution_count"], 20)

    @unittest.skipUnless(
        WINDOWS_REPORT.exists(),
        "Windows rule-orchestration report not collected",
    )
    def test_all_cases_are_semantically_deterministic(self):
        report = json.loads(
            WINDOWS_REPORT.read_text(encoding="utf-8")
        )
        self.assertTrue(report["passed"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(
            report["determinism"]["semantic_case_failures"],
            [],
        )
        self.assertEqual(len(report["cases"]), 10)
        for name, case in report["cases"].items():
            with self.subTest(case=name):
                self.assertEqual(len(case["runs"]), 2)
                self.assertTrue(case["semantic_runs_equal"])
                self.assertTrue(case["raw_stderr_equal"])

    @unittest.skipUnless(
        WINDOWS_REPORT.exists(),
        "Windows rule-orchestration report not collected",
    )
    def test_windows_matches_linux_exact_semantic_projection(self):
        report = json.loads(
            WINDOWS_REPORT.read_text(encoding="utf-8")
        )
        comparison = report["linux_qt5_comparison"]
        self.assertEqual(comparison["case_differences"], [])
        self.assertTrue(comparison["canonical_cases_equal"])
        self.assertTrue(comparison["relationships_equal"])
        self.assertEqual(
            comparison["platform_difference_classification"],
            "none_observed_in_semantic_projection",
        )
        self.assertEqual(
            report["canonical_cases"],
            self.linux["canonical_cases"],
        )
        self.assertEqual(
            report["relationships"],
            self.linux["relationships"],
        )

    @unittest.skipUnless(
        WINDOWS_REPORT.exists(),
        "Windows rule-orchestration report not collected",
    )
    def test_report_contains_no_local_path_or_elapsed_rewrite(self):
        text = WINDOWS_REPORT.read_text(encoding="utf-8")
        for forbidden in (
            "C:/Users",
            "C:\\\\Users",
            "I:/tmp",
            "I:\\\\tmp",
            "worker",
            "die-windows-source",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        report = json.loads(text)
        self.assertIn(
            "profiling elapsed-time rewriting",
            report["normalization"]["not_performed"],
        )
        self.assertIn("/fixture/main", text)

    def test_collector_inputs_have_stable_hashes(self):
        for path in (
            SCRIPT,
            LINUX_PROBE,
            FIXTURE_GENERATOR,
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

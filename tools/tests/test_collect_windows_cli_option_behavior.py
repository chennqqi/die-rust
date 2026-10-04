import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT / "tools/upstream/collect_windows_cli_option_behavior.py"
)
REPORT = (
    ROOT / "docs/research/data/windows-qt5-cli-option-behavior.json"
)
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
BASELINE_MANIFEST = ROOT / "docs/research/data/baseline-corpus.json"
NINTENDO_MANIFEST = (
    ROOT / "docs/research/data/nintendo-certified-corpus.json"
)
LIFECYCLE = ROOT / "docs/research/data/binary-rule-lifecycle.json"
LINUX_OPTION = (
    ROOT / "docs/research/data/cli-option-behavior-linux.json"
)
LINUX_ORDER = (
    ROOT / "docs/research/data/binary-rule-order-linux-qt5.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_option_behavior",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliOptionBehaviorTests(unittest.TestCase):
    def test_normalization_is_limited_to_crlf_and_exact_paths(self):
        data = (
            b"C:\\fixture\\minimal.elf\r\n"
            b"C:\\fixture-like\\minimal.elf\r\n"
        )
        normalized = MODULE.normalize_text(
            data,
            [("C:\\fixture\\minimal.elf", "<sample>")],
        )
        self.assertEqual(
            normalized,
            "<sample>\nC:\\fixture-like\\minimal.elf\n",
        )

    def test_linux_references_retain_expected_contracts(self):
        option = json.loads(LINUX_OPTION.read_text(encoding="utf-8"))
        MODULE.validate_linux_option_reference(copy.deepcopy(option))
        order = json.loads(LINUX_ORDER.read_text(encoding="utf-8"))
        expected_names, lifecycle_hash = (
            MODULE.order_probe.load_expected_names(LIFECYCLE)
        )
        manifest = json.loads(
            NINTENDO_MANIFEST.read_text(encoding="utf-8")
        )
        sample = next(
            item
            for item in manifest["samples"]
            if item["name"] == "ps3-type-1-elf.self"
        )
        result = MODULE.validate_order_reference(
            copy.deepcopy(order),
            lifecycle_hash,
            sample,
        )
        self.assertEqual(len(result), 292)
        self.assertEqual(set(result), expected_names)

    def test_parse_values_retains_only_semantic_verbose_fields(self):
        raw = json.dumps(
            {
                "detects": [
                    {
                        "values": [
                            {
                                "type": "operation system",
                                "name": "Unix",
                                "version": "",
                                "info": "AMD64, 64-bit",
                                "string": "presentation",
                            }
                        ]
                    }
                ]
            }
        ).encode()
        self.assertEqual(
            MODULE.parse_values(raw),
            [
                {
                    "type": "operation system",
                    "name": "Unix",
                    "version": "",
                    "info": "AMD64, 64-bit",
                }
            ],
        )

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
        self.assertEqual(
            report["binary"]["sha256"],
            build["clean_qmake_build"]["artifact"]["sha256"],
        )
        self.assertEqual(
            build["windows_cli_option_behavior"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        for key, path in (
            ("baseline_manifest", BASELINE_MANIFEST),
            ("nintendo_manifest", NINTENDO_MANIFEST),
            ("binary_lifecycle", LIFECYCLE),
        ):
            with self.subTest(key=key):
                self.assertEqual(
                    report["fixtures"][key]["sha256"],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
        self.assertEqual(report["repetitions"], 2)
        self.assertEqual(report["summary"]["case_count"], 10)
        self.assertEqual(report["summary"]["execution_count"], 20)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_nine_option_cases_are_raw_deterministic(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(len(report["cases"]), 9)
        for name, case in report["cases"].items():
            with self.subTest(case=name):
                self.assertEqual(
                    case["raw_determinism_differences"],
                    [],
                )
                self.assertTrue(case["normalized_outputs_equal"])
                self.assertEqual(case["runs"][0], case["runs"][1])

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_all_option_relationships_hold(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(report["passed"])
        self.assertEqual(report["failures"], [])
        relationships = report["relationships"]
        self.assertTrue(
            relationships["test_directory_value_is_unvalidated"]
        )
        self.assertTrue(
            relationships[
                "createtest_complete_only_prints_announcement"
            ]
        )
        self.assertEqual(
            relationships["createtest_missing_positionals_exit_code"],
            4,
        )
        self.assertTrue(
            relationships[
                "profiling_without_messages_equals_default"
            ]
        )
        self.assertEqual(
            relationships["verbose_added_values"],
            [
                {
                    "type": "operation system",
                    "name": "Unix",
                    "version": "",
                    "info": "AMD64, 64-bit",
                }
            ],
        )
        self.assertEqual(
            relationships["verbose_removed_values"],
            [
                {
                    "type": "Unknown",
                    "name": "Unknown",
                    "version": "",
                    "info": "",
                }
            ],
        )
        controls = report["linux_references"]["same_sample_control"]
        self.assertEqual(controls["execution_count"], 3)
        self.assertTrue(
            all(
                case["windows_semantic_equal"]
                for case in controls["cases"].values()
            )
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_profiling_order_is_exactly_linux_qt5_order(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        profiling = report["profiling_order"]
        linux = json.loads(LINUX_ORDER.read_text(encoding="utf-8"))
        self.assertTrue(profiling["order_runs_equal"])
        self.assertFalse(profiling["order_matches_linux_qt5"])
        self.assertEqual(profiling["order_count"], 292)
        self.assertEqual(set(profiling["order"]), set(linux["order"]))
        difference = profiling["linux_qt5_difference"]
        self.assertEqual(
            difference["classification"],
            "single_rule_moved_to_end",
        )
        self.assertEqual(difference["moved_rule"], "image_ICNS.sg")
        self.assertEqual(difference["linux_index"], 248)
        self.assertEqual(difference["windows_index"], 291)
        self.assertEqual(difference["differing_position_count"], 44)
        self.assertEqual(
            difference["compatibility_status"],
            "platform_difference_retained_as_defect",
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_contains_no_local_path_or_elapsed_rewrite(self):
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
        normalization = json.loads(text)["normalization"]
        self.assertIn(
            "profiling elapsed-time rewriting",
            normalization["not_performed"],
        )
        self.assertIn("<baseline-corpus>/minimal.elf", text)
        self.assertIn(
            "<nintendo-corpus>/ps3-type-1-elf.self",
            text,
        )

    def test_collector_inputs_have_stable_hashes(self):
        for path in (
            SCRIPT,
            BASELINE_MANIFEST,
            NINTENDO_MANIFEST,
            LIFECYCLE,
            LINUX_OPTION,
            LINUX_ORDER,
        ):
            with self.subTest(path=path.name):
                self.assertEqual(
                    len(hashlib.sha256(path.read_bytes()).hexdigest()),
                    64,
                )


if __name__ == "__main__":
    unittest.main()

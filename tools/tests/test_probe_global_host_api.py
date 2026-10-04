import hashlib
import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/upstream/probe_global_host_api.py"
SPEC = importlib.util.spec_from_file_location(
    "probe_global_host_api", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class GlobalHostApiProbeTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "docs/research/data/global-host-api-qt5.json"
        self.report = json.loads(path.read_text(encoding="utf-8"))
        self.observation = self.report["observation"]
        qt6_path = ROOT / "docs/research/data/global-host-api-qt6.json"
        self.qt6_report = json.loads(qt6_path.read_text(encoding="utf-8"))
        self.qt6_observation = self.qt6_report["observation"]

    def test_committed_observation_satisfies_oracle_contract(self):
        MODULE.validate_observation(self.observation)
        MODULE.validate_observation(self.qt6_observation, "qt6")
        MODULE.validate_streams(
            self.report["streams"],
            self.observation,
            "qt5",
        )
        MODULE.validate_streams(
            self.qt6_report["streams"],
            self.qt6_observation,
            "qt6",
        )

    def test_committed_source_identities_are_current(self):
        for report in (self.report, self.qt6_report):
            for relative, identity in report["sources"].items():
                data = (ROOT / relative).read_bytes()
                self.assertEqual(len(data), identity["bytes"])
                self.assertEqual(MODULE.sha256(data), identity["sha256"])

    def test_research_document_binds_report_and_artifact_identities(self):
        document = (
            ROOT / "docs/research/global-host-api-runtime-differential.md"
        ).read_text(encoding="utf-8")
        for name in (
            "global-host-api-qt5.json",
            "global-host-api-qt6.json",
            "global-host-api-qt5-qt6.json",
        ):
            data = (ROOT / "docs/research/data" / name).read_bytes()
            self.assertIn(hashlib.sha256(data).hexdigest(), document)
        for report in (self.report, self.qt6_report):
            self.assertIn(report["image"]["id"], document)
            self.assertIn(report["binary"]["sha256"], document)

    def test_qt6_missing_arguments_are_exact_errors(self):
        expected = {
            "_log()",
            "_setResult()",
            "_isResultPresent()",
            "_getNumberOfResults()",
        }
        observed = set()

        def visit(value):
            if isinstance(value, dict):
                if value.get("is_error") is True:
                    observed.add(value["source"])
                    self.assertEqual(
                        value["error_message"],
                        "Insufficient arguments",
                    )
                    self.assertEqual(value["error_line"], 1)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(self.qt6_observation)
        self.assertEqual(observed, expected)

    def test_qt6_runtime_specific_contract(self):
        methods = self.qt6_observation["surface"]["methods"]
        self.assertEqual(
            methods["_getQtVersion"]["type"]["string"],
            "function",
        )
        self.assertEqual(
            self.qt6_observation["modes"]["qt_version"]["string"],
            "6.4.2",
        )
        info = self.qt6_observation["info"]
        self.assertEqual(info["log_messages"], ["", "42"])
        self.assertEqual(info["encoding_message_count"], 0)
        self.assertTrue(
            info["encoding_call"]["evaluation"]["is_undefined"]
        )
        conversions = self.qt6_observation["query_conversions"][
            "evaluations"
        ]
        self.assertEqual(conversions["undefined_count"]["number"], 17)
        self.assertEqual(conversions["null_count"]["number"], 17)
        self.assertEqual(
            conversions["throwing_object_count"]["number"],
            0,
        )
        self.assertEqual(self.qt6_report["streams"]["stderr"]["bytes"], 176)

    def test_qt5_query_conversion_error_and_surrogate_are_preserved(self):
        conversions = self.observation["query_conversions"]
        evaluations = conversions["evaluations"]
        self.assertEqual(evaluations["undefined_count"]["number"], 0)
        self.assertEqual(evaluations["null_count"]["number"], 0)
        throwing = evaluations["throwing_object_count"]
        self.assertTrue(throwing["is_error"])
        self.assertEqual(throwing["error_message"], "conversion-boom")
        self.assertEqual(
            [
                record["type"]
                for record in conversions["final_records"][-6:]
            ],
            [
                "\ud800",
                "\udc00",
                "\ud800\ud800",
                "\udc00\udc00",
                "\udc00\ud800",
                "\U00010000",
            ],
        )

    def test_isolated_query_conversions_preserve_qt6_crash(self):
        qt5 = self.observation["isolated_query_conversions"]
        qt6 = self.qt6_observation["isolated_query_conversions"]
        self.assertEqual(
            qt5["cyclic_array_count"]["observation"]["evaluation"]["number"],
            1,
        )
        qt6_cycle = qt6["cyclic_array_count"]
        self.assertEqual(qt6_cycle["exit_status"], "crash")
        self.assertEqual(qt6_cycle["exit_code"], 11)
        self.assertEqual(qt6_cycle["process_error_code"], 1)
        self.assertNotIn("observation", qt6_cycle)
        self.assertEqual(qt6_cycle["stdout"]["bytes"], 0)
        self.assertEqual(
            qt5["proxy_object_count"]["observation"]["evaluation"]["number"],
            -1,
        )
        self.assertEqual(
            qt6["proxy_object_count"]["observation"]["evaluation"]["number"],
            1,
        )
        self.assertEqual(
            qt5["symbol_count"]["observation"]["evaluation"]["number"],
            -1,
        )
        self.assertEqual(
            qt6["symbol_count"]["observation"]["evaluation"]["number"],
            1,
        )
        for observations in (qt5, qt6):
            self.assertEqual(
                observations["bigint_count"]["observation"]["evaluation"][
                    "number"
                ],
                -1,
            )

    def test_empty_argv0_reaches_library_mode_in_both_runtimes(self):
        for observation in (self.observation, self.qt6_observation):
            regular = observation["modes"]["empty_requested"]
            self.assertEqual(
                regular["application_name"],
                "die-global-host-api-harness",
            )
            self.assertFalse(regular["library"]["boolean"])

            process = observation["modes"]["empty_argv0_process"]
            self.assertEqual(process["exit_status"], "normal")
            self.assertEqual(process["stderr"]["bytes"], 0)
            embedded = process["observation"]
            self.assertEqual(embedded["application_name"], "")
            self.assertFalse(embedded["console"]["boolean"])
            self.assertFalse(embedded["gui"]["boolean"])
            self.assertFalse(embedded["lite"]["boolean"])
            self.assertTrue(embedded["library"]["boolean"])

    def test_include_errors_and_pdstruct_side_effects_are_preserved(self):
        qt5_include = self.observation["include"]
        qt6_include = self.qt6_observation["include"]
        self.assertTrue(
            qt5_include["parse_error"]["evaluation"]["is_error"]
        )
        self.assertTrue(
            qt5_include["runtime_error"]["evaluation"]["is_error"]
        )
        self.assertTrue(
            qt6_include["parse_error"]["evaluation"]["is_undefined"]
        )
        self.assertTrue(
            qt6_include["runtime_error"]["evaluation"]["is_undefined"]
        )
        for include in (qt5_include, qt6_include):
            self.assertEqual(
                include["parse_visibility"]["evaluation"]["string"],
                "undefined",
            )
            self.assertEqual(
                include["runtime_before_visibility"]["evaluation"]["string"],
                "number",
            )
            self.assertEqual(
                include["runtime_after_visibility"]["evaluation"]["string"],
                "undefined",
            )
        self.assertEqual(
            [
                self.observation["info"]["pd_info_after_missing"],
                self.observation["info"]["pd_info_after_null"],
                self.observation["info"]["pd_info_after_number"],
                self.observation["info"]["pd_info_after_encoding"],
            ],
            ["undefined", "null", "42", "42"],
        )
        self.assertEqual(
            [
                self.qt6_observation["info"]["pd_info_after_missing"],
                self.qt6_observation["info"]["pd_info_after_null"],
                self.qt6_observation["info"]["pd_info_after_number"],
                self.qt6_observation["info"]["pd_info_after_encoding"],
            ],
            ["", "", "42", "42"],
        )

    def test_raw_stream_drift_is_rejected(self):
        changed = json.loads(json.dumps(self.report["streams"]))
        changed["stdout"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "stdout stream identity"):
            MODULE.validate_streams(changed, self.observation, "qt5")

    def test_isolated_query_stream_and_crash_drift_are_rejected(self):
        changed = json.loads(json.dumps(self.observation))
        changed["isolated_query_conversions"]["proxy_object_count"][
            "stdout"
        ]["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            ValueError,
            "proxy_object_count stdout byte identity",
        ):
            MODULE.validate_observation(changed, "qt5")

        changed = json.loads(json.dumps(self.qt6_observation))
        changed["isolated_query_conversions"]["cyclic_array_count"][
            "exit_code"
        ] = 0
        with self.assertRaisesRegex(
            ValueError,
            "cyclic array crash behavior",
        ):
            MODULE.validate_observation(changed, "qt6")

    def test_empty_argv0_raw_stream_drift_is_rejected(self):
        changed = json.loads(json.dumps(self.observation))
        changed["modes"]["empty_argv0_process"]["stdout"]["sha256"] = (
            "0" * 64
        )
        with self.assertRaisesRegex(
            ValueError,
            r"empty argv\[0\] stdout byte identity",
        ):
            MODULE.validate_observation(changed, "qt5")

    def test_qt6_unexpected_error_is_rejected(self):
        changed = json.loads(json.dumps(self.qt6_observation))
        changed["modes"]["os"]["is_error"] = True
        with self.assertRaisesRegex(ValueError, "unexpected JavaScript"):
            MODULE.validate_observation(changed, "qt6")

    def test_array_removal_change_is_rejected(self):
        changed = json.loads(json.dumps(self.observation))
        changed["array_removal"]["removal"]["records"].pop()
        with self.assertRaisesRegex(ValueError, "array removeResult"):
            MODULE.validate_observation(changed)

    def test_nonempty_version_info_and_type_priority_are_observed(self):
        first = self.observation["results"]["steps"][0]
        self.assertEqual(
            first["evaluation"]["source"],
            "_setResult('compiler','Rust','1.0','first')",
        )
        self.assertEqual(
            first["records"],
            [
                {
                    "info": "first",
                    "is_advanced_heuristic": False,
                    "is_heuristic": False,
                    "name": "Rust",
                    "priority": 30,
                    "type": "compiler",
                    "version": "1.0",
                }
            ],
        )

    def test_stop_state_conflation_is_rejected(self):
        changed = json.loads(json.dumps(self.observation))
        changed["stop"]["js_stop_before_break"]["evaluation"][
            "boolean"
        ] = True
        with self.assertRaisesRegex(ValueError, "internal wrapper stop"):
            MODULE.validate_observation(changed)

    def test_parser_rejects_diagnostics(self):
        data = json.dumps(self.observation).encode()
        with self.assertRaisesRegex(ValueError, "stderr"):
            MODULE.parse_observation(data, b"warning", 0)
        with self.assertRaisesRegex(ValueError, "trailing"):
            MODULE.parse_observation(data + b"\nwarning", b"", 0)

    def test_qt6_dockerfile_uses_fixed_qt6_base(self):
        source = (
            ROOT
            / "tools/upstream/Dockerfile.global-host-api-harness-qt6"
        ).read_text(encoding="utf-8")
        self.assertIn(
            (
                "ARG BASE_IMAGE="
                "die-rust/upstream-oracle-cmake-qt6:74eaf505"
            ),
            source,
        )
        self.assertIn(
            "Research-only Qt 6 native global HostApi oracle harness",
            source,
        )
        self.assertIn(
            "CMakeFiles/diec.dir/main_console.cpp.o",
            source,
        )


if __name__ == "__main__":
    unittest.main()

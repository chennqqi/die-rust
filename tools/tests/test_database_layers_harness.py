import base64
import hashlib
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[2]
REPORT_PATH = (
    ROOT / "docs" / "research" / "data"
    / "database-layers-engine-qt5.json"
)
FIXTURE_PATH = (
    ROOT / "docs" / "research" / "data"
    / "database-layer-fixture.json"
)
DOCUMENT_PATH = (
    ROOT / "docs" / "research" / "database-layer-behavior.md"
)
HARNESS_PATH = (
    ROOT / "tools" / "upstream"
    / "database_layers_harness_main.cpp"
)
DOCKERFILE_PATH = (
    ROOT / "tools" / "upstream"
    / "Dockerfile.database-layers-harness-qt5"
)


class DatabaseLayersHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        cls.fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        observation = cls.report["observation"]
        cls.loads = {
            case["id"]: case
            for case in observation["load_cases"]
        }
        cls.scans = {
            case["id"]: case
            for case in observation["scan_cases"]
        }

    def raw_stream(self, run, stream):
        data = base64.b64decode(run[f"{stream}_base64"])
        self.assertEqual(len(data), run[f"{stream}_bytes"])
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            run[f"{stream}_sha256"],
        )
        return data

    def test_report_is_bound_to_sources_fixture_image_and_revision(self):
        report = self.report
        revision = "74eaf505c250ab47e709024e9dc41657cd8f2254"
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(
            report["generator"],
            "tools/upstream/probe_database_layers.py",
        )
        self.assertEqual(report["expected_revision"], revision)
        self.assertEqual(report["image_revision"], revision)
        self.assertEqual(
            report["image_id"],
            (
                "sha256:"
                "0b5f10b2e0fad5fbfaa14601afd2635032426008da96a92"
                "cdc3cb1fc95137468"
            ),
        )
        self.assertEqual(
            report["binary"],
            "/opt/die-build/src/console/die-database-layers-harness",
        )
        self.assertEqual(report["repetitions"], 2)
        self.assertTrue(report["passed"])
        self.assertEqual(report["failures"], [])

        source_paths = {
            "harness": HARNESS_PATH,
            "dockerfile": DOCKERFILE_PATH,
            "shared_helper": (
                ROOT / "tools" / "upstream" / "compare_cli_oracles.py"
            ),
            "fixture_generator": (
                ROOT / "tools" / "corpus"
                / "generate_database_layer_fixture.py"
            ),
        }
        generator = ROOT / report["generator"]
        self.assertEqual(
            hashlib.sha256(generator.read_bytes()).hexdigest(),
            report["generator_sha256"],
        )
        for name, path in source_paths.items():
            with self.subTest(source=name):
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    report["source_hashes"][name],
                )
        self.assertEqual(
            hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest(),
            report["fixture_manifest_sha256"],
        )

    def test_fixture_has_only_project_generated_layer_rules(self):
        self.assertEqual(
            self.fixture["license"],
            "project-generated; no third-party sample or rule bytes",
        )
        self.assertEqual(
            self.fixture["layers"],
            ["main", "extra", "custom"],
        )
        self.assertEqual(
            self.fixture["rule_filenames"],
            [
                "layer-low.1.sg",
                "shared.5.sg",
                "layer-high.9.sg",
            ],
        )
        self.assertEqual(len(self.fixture["entries"]), 10)
        self.assertTrue(
            all(
                entry["source"] == "project-generated"
                for entry in self.fixture["entries"]
            )
        )

    def test_both_runs_preserve_identical_raw_json_and_empty_stderr(self):
        self.assertTrue(self.report["raw_outputs_equal"])
        self.assertEqual(len(self.report["runs"]), 2)
        first_stdout = None
        for index, run in enumerate(self.report["runs"]):
            with self.subTest(run=index):
                self.assertEqual(run["exit_code"], 0)
                stdout = self.raw_stream(run, "stdout")
                stderr = self.raw_stream(run, "stderr")
                self.assertEqual(stderr, b"")
                self.assertEqual(
                    json.loads(stdout),
                    self.report["observation"],
                )
                if first_stdout is None:
                    first_stdout = stdout
                else:
                    self.assertEqual(stdout, first_stdout)

    def test_load_flags_control_materialized_layer_blocks(self):
        expected = {
            "main_only": (3, ["main"] * 3),
            "main_extra": (6, ["main"] * 3 + ["extra"] * 3),
            "main_custom": (
                6,
                ["main"] * 3 + ["custom"] * 3,
            ),
            "all_layers": (
                9,
                ["main"] * 3
                + ["extra"] * 3
                + ["custom"] * 3,
            ),
        }
        self.assertEqual(list(self.loads), list(expected))
        for case_id, (count, layers) in expected.items():
            with self.subTest(case=case_id):
                case = self.loads[case_id]
                self.assertTrue(case["loaded"])
                self.assertTrue(case["load_pd_not_canceled"])
                self.assertEqual(case["signature_count"], count)
                self.assertEqual(
                    [
                        record["database_type"]
                        for record in case["signatures"]
                    ],
                    layers,
                )

    def test_same_names_survive_in_main_extra_custom_order(self):
        records = self.report["observation"]["all_loaded_signatures"]
        self.assertEqual(
            [
                (
                    record["database_type"],
                    record["database_type_value"],
                    record["name"],
                )
                for record in records
            ],
            [
                ("main", 0, "layer-low.1.sg"),
                ("main", 0, "shared.5.sg"),
                ("main", 0, "layer-high.9.sg"),
                ("extra", 1, "layer-low.1.sg"),
                ("extra", 1, "shared.5.sg"),
                ("extra", 1, "layer-high.9.sg"),
                ("custom", 2, "layer-low.1.sg"),
                ("custom", 2, "shared.5.sg"),
                ("custom", 2, "layer-high.9.sg"),
            ],
        )
        self.assertEqual(
            sum(record["name"] == "shared.5.sg" for record in records),
            3,
        )
        self.assertTrue(
            all(record["file_type_value"] == 4 for record in records)
        )

    def test_runtime_flags_filter_already_loaded_records(self):
        main = ["MainLow", "MainShared", "MainHigh"]
        extra = ["ExtraLow", "ExtraShared", "ExtraHigh"]
        custom = ["CustomLow", "CustomShared", "CustomHigh"]
        expected = {
            "all_unsorted": main + extra + custom,
            "main_only_unsorted": main,
            "main_extra_unsorted": main + extra,
            "main_custom_unsorted": main + custom,
            "all_sorted": main + extra + custom,
        }
        self.assertEqual(list(self.scans), list(expected))
        for case_id, names in expected.items():
            with self.subTest(case=case_id):
                case = self.scans[case_id]
                self.assertEqual(case["names"], names)
                self.assertEqual(case["errors"], [])
                self.assertTrue(case["scan_pd_not_canceled"])

    def test_all_derived_relationships_are_true(self):
        self.assertEqual(len(self.report["relationships"]), 8)
        self.assertTrue(all(self.report["relationships"].values()))

    def test_harness_and_container_keep_layer_controls_explicit(self):
        harness = HARNESS_PATH.read_text(encoding="utf-8")
        for token in (
            "options.bUseExtraDatabase = useExtra",
            "options.bUseCustomDatabase = useCustom",
            "options.bUseCache = false",
            "engine->getSignatures()",
            '"all_unsorted"',
            '"all_sorted"',
        ):
            with self.subTest(token=token):
                self.assertIn(token, harness)

        dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "die-rust/upstream-oracle-cmake:74eaf505",
            dockerfile,
        )
        self.assertIn(
            "74eaf505c250ab47e709024e9dc41657cd8f2254",
            dockerfile,
        )
        self.assertIn("die-database-layers-harness", dockerfile)

    def test_document_and_index_link_machine_evidence(self):
        document = DOCUMENT_PATH.read_text(encoding="utf-8")
        index = (
            ROOT / "docs" / "research" / "README.md"
        ).read_text(encoding="utf-8")
        for filename in (REPORT_PATH.name, FIXTURE_PATH.name):
            self.assertIn(filename, document)
            self.assertIn(filename, index)
        for text in (
            "main → extra → custom",
            "shared.5.sg",
            "不覆盖",
        ):
            self.assertIn(text, document)


if __name__ == "__main__":
    unittest.main()

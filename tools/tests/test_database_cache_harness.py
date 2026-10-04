import base64
import hashlib
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[2]
REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "database-cache-engine-qt5.json"
)
FIXTURE_PATH = (
    ROOT / "docs" / "research" / "data" / "database-fixture.json"
)
DOCUMENT_PATH = (
    ROOT / "docs" / "research" / "database-archive-cache.md"
)
HARNESS_PATH = (
    ROOT / "tools" / "upstream" / "database_cache_harness_main.cpp"
)
DOCKERFILE_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.database-cache-harness-qt5"
)


class DatabaseCacheHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        cls.fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        cls.cases = {
            case["id"]: case
            for case in cls.report["observation"]["cases"]
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
            "tools/upstream/probe_database_cache_harness.py",
        )
        self.assertEqual(report["expected_revision"], revision)
        self.assertEqual(report["image_revision"], revision)
        self.assertEqual(
            report["image_id"],
            (
                "sha256:"
                "17f7bd0514e973df9da8ff06967cb73ddff906cb568d1d0"
                "7d75f3b09c7146fc9"
            ),
        )
        self.assertEqual(
            report["binary"],
            "/opt/die-build/src/console/die-database-cache-harness",
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
                / "generate_database_fixture.py"
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

    def test_resource_limits_and_fixed_harness_identity_are_explicit(self):
        self.assertEqual(
            self.report["resource_limits"],
            {
                "network": "none",
                "cpus": 2,
                "memory_bytes": 1073741824,
                "pids": 256,
                "fixture_mount": "read-only",
                "xdg_data_home": "/tmp/xdg",
                "uid_gid": "65534:65534",
            },
        )
        observation = self.report["observation"]
        self.assertEqual(observation["schema_version"], 1)
        self.assertEqual(
            observation["upstream_commit"],
            self.report["expected_revision"],
        )
        self.assertEqual(
            observation["xscanengine_commit"],
            "dfe4a419e4f491bb23688ba03c5a5bf39e34da83",
        )
        self.assertEqual(observation["effective_uid"], 65534)
        self.assertEqual(observation["effective_gid"], 65534)
        self.assertEqual(
            observation["database_path"],
            "/tmp/die-database-cache-harness/database",
        )
        self.assertEqual(observation["fixed_mtime_seconds"], 1700000000)
        self.assertEqual(observation["fixed_mtime_nanoseconds"], 123000000)

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

    def test_case_order_and_exact_observations_are_fixed(self):
        case_ids = [
            case["id"]
            for case in self.report["observation"]["cases"]
        ]
        self.assertEqual(
            case_ids,
            [
                "initial_miss",
                "unchanged_hit",
                "same_stats_stale_hit",
                "stats_changed_rebuild",
                "bad_magic_fallback",
                "bad_version_fallback",
                "empty_cache_fallback",
                "magic_only_fallback",
                "magic_version_only_fallback",
                "truncated_record_fallback",
                "record_tail_truncated_fallback",
                "cache_write_denied",
                "cache_write_recovery",
                "concurrent_identical_writers",
                "database_directory_permission_denied",
                "database_file_permission_denied",
                "canceled_cache_hit",
                "canceled_cache_miss",
                "poisoned_empty_cache_hit",
            ],
        )

        expected = {
            "initial_miss": (1, ["Fixture"], 399),
            "unchanged_hit": (1, ["Fixture"], 399),
            "same_stats_stale_hit": (1, ["Fixture"], 399),
            "stats_changed_rebuild": (1, ["Changed"], 399),
            "bad_magic_fallback": (1, ["Changed"], 399),
            "bad_version_fallback": (1, ["Changed"], 399),
            "empty_cache_fallback": (1, ["Changed"], 399),
            "magic_only_fallback": (1, ["Changed"], 399),
            "magic_version_only_fallback": (1, ["Changed"], 399),
            "truncated_record_fallback": (2, ["Changed"], 399),
            "record_tail_truncated_fallback": (
                2,
                ["Changed", "Changed"],
                399,
            ),
            "cache_write_denied": (1, ["Changed"], 0),
            "cache_write_recovery": (1, ["Changed"], 399),
            "concurrent_identical_writers": (1, ["Changed"], 399),
            "database_directory_permission_denied": (0, ["Unknown"], 42),
            "database_file_permission_denied": (0, ["Unknown"], 0),
            "canceled_cache_hit": (0, ["Unknown"], 399),
            "canceled_cache_miss": (0, ["Unknown"], 42),
            "poisoned_empty_cache_hit": (0, ["Unknown"], 42),
        }
        for case_id, (
            signature_count,
            scan_names,
            cache_size,
        ) in expected.items():
            with self.subTest(case=case_id):
                case = self.cases[case_id]
                self.assertEqual(
                    case["loaded"],
                    case_id != "database_file_permission_denied",
                )
                self.assertEqual(
                    case["binary_signature_count"],
                    signature_count,
                )
                self.assertEqual(case["scan_names"], scan_names)
                self.assertEqual(case["scan_errors"], [])
                self.assertEqual(
                    case["cache"]["exists"],
                    case_id
                    not in {
                        "cache_write_denied",
                        "database_file_permission_denied",
                    },
                )
                self.assertEqual(case["cache"]["size"], cache_size)

    def test_cache_hash_transitions_and_cancellation_are_fixed(self):
        original_hash = (
            "1c80b4ef70e0ce7075179e971a38336319a5e3957a79ce9"
            "efe4d28037c494801"
        )
        rebuilt_hash = (
            "28675cca1c62e30f218613394656b74fd34bd12517a64be"
            "414b63163eef05595"
        )
        poisoned_hash = (
            "9c6d8e481a2b89dcffc604dba21d08b6cad4e1731f0b7c"
            "6b76cbc70e21d4ffd2"
        )
        for case_id in (
            "initial_miss",
            "unchanged_hit",
            "same_stats_stale_hit",
        ):
            self.assertEqual(
                self.cases[case_id]["cache"]["sha256"],
                original_hash,
            )
        for case_id in (
            "stats_changed_rebuild",
            "bad_magic_fallback",
            "bad_version_fallback",
            "empty_cache_fallback",
            "magic_only_fallback",
            "magic_version_only_fallback",
            "truncated_record_fallback",
            "record_tail_truncated_fallback",
            "cache_write_recovery",
            "concurrent_identical_writers",
            "canceled_cache_hit",
        ):
            self.assertEqual(
                self.cases[case_id]["cache"]["sha256"],
                rebuilt_hash,
            )
        for case_id in (
            "canceled_cache_miss",
            "poisoned_empty_cache_hit",
        ):
            self.assertEqual(
                self.cases[case_id]["cache"]["sha256"],
                poisoned_hash,
            )

        for case_id in ("canceled_cache_hit", "canceled_cache_miss"):
            case = self.cases[case_id]
            self.assertTrue(case["stop_before_load"])
            self.assertFalse(case["load_pd_not_canceled"])
        self.assertFalse(
            self.cases["poisoned_empty_cache_hit"]["stop_before_load"]
        )
        self.assertTrue(
            self.cases["poisoned_empty_cache_hit"][
                "load_pd_not_canceled"
            ]
        )

    def test_all_derived_relationships_are_true(self):
        self.assertEqual(
            set(self.report["relationships"]),
            {
                "all_scan_error_lists_are_empty",
                "bad_magic_falls_back_and_rewrites",
                "bad_version_falls_back_and_rewrites",
                "cache_write_failure_is_silent_and_nonfatal",
                "cache_write_recovers_after_permission_restore",
                "canceled_cache_hit_reports_success_with_zero_records",
                "canceled_miss_saves_empty_cache",
                "concurrent_identical_writers_finish_with_valid_cache",
                "header_truncations_fall_back_without_partial_records",
                "harness_runs_without_root_privileges",
                "initial_load_creates_one_record_cache",
                "mtime_change_rebuilds_changed_rule",
                "permission_denied_directory_is_silent_empty_success",
                "permission_denied_file_is_silent_failure",
                "same_size_mtime_content_change_is_stale_hit",
                "record_truncation_injects_partial_record_before_fallback",
                "tail_truncation_injects_partial_record_before_fallback",
                "uncanceled_load_reuses_poisoned_empty_cache",
                "unchanged_load_reuses_identical_cache",
            },
        )
        self.assertTrue(all(self.report["relationships"].values()))

    def test_harness_and_container_keep_compatibility_controls(self):
        harness = HARNESS_PATH.read_text(encoding="utf-8")
        for token in (
            "options.bUseCache = true",
            "setPdStructStopped",
            "writeCachePrefix",
            "writeBadVersionCache",
            "observeConcurrentWriters",
            "cache_write_denied",
            "database_directory_permission_denied",
            "geteuid",
            "getegid",
            "replaceRulePreservingStats",
            "/tmp/die-database-cache-harness",
            "1700000000",
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
        self.assertIn("die-database-cache-harness", dockerfile)

    def test_document_and_index_link_machine_evidence(self):
        document = DOCUMENT_PATH.read_text(encoding="utf-8")
        index = (
            ROOT / "docs" / "research" / "README.md"
        ).read_text(encoding="utf-8")
        for text in (
            REPORT_PATH.name,
            "same_stats_stale_hit",
            "truncated_record_fallback",
            "cache_write_denied",
            "concurrent_identical_writers",
            "database_file_permission_denied",
            "poisoned_empty_cache_hit",
        ):
            self.assertIn(text, document)
        self.assertIn(REPORT_PATH.name, index)


if __name__ == "__main__":
    unittest.main()

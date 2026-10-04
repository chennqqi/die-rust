import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    ROOT / "tools" / "upstream" / "probe_archive_limits_harness.py"
)
REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "archive-limit-engine-qt5.json"
)
MANIFEST_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "archive-limit-corpus.json"
)
DOCKERFILE_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.archive-limits-harness-qt5"
)
QT6_DOCKERFILE_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.archive-limits-harness-qt6"
)
HARNESS_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "archive_limits_harness_main.cpp"
)
SPEC = importlib.util.spec_from_file_location(
    "probe_archive_limits_harness", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
GENERATOR_PATH = (
    ROOT / "tools" / "corpus" / "generate_archive_limit_fixture.py"
)
GENERATOR_SPEC = importlib.util.spec_from_file_location(
    "generate_archive_limit_fixture_for_probe_test",
    GENERATOR_PATH,
)
assert (
    GENERATOR_SPEC is not None
    and GENERATOR_SPEC.loader is not None
)
GENERATOR = importlib.util.module_from_spec(GENERATOR_SPEC)
sys.modules[GENERATOR_SPEC.name] = GENERATOR
GENERATOR_SPEC.loader.exec_module(GENERATOR)


class ProbeArchiveLimitsHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        cls.manifest = json.loads(
            MANIFEST_PATH.read_text(encoding="utf-8")
        )

    def test_committed_report_passes_all_semantic_assertions(self):
        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report["failures"], [])
        self.assertEqual(MODULE.evaluate_report(self.report), [])
        self.assertTrue(all(self.report["assertions"].values()))

    def test_report_binds_exact_upstream_source_image_and_binary(self):
        self.assertEqual(
            self.report["upstream_commit"],
            MODULE.EXPECTED_REVISION,
        )
        self.assertEqual(
            self.report["xscanengine_commit"],
            MODULE.EXPECTED_XSCANENGINE_COMMIT,
        )
        source = self.report["source_contract"]
        self.assertEqual(source["sha256"], MODULE.EXPECTED_SOURCE_SHA256)
        self.assertTrue(
            all(
                count >= 1
                for count in source[
                    "required_pattern_counts"
                ].values()
            )
        )
        self.assertFalse(
            any(source["negative_token_counts"].values())
        )
        self.assertRegex(
            self.report["environment"]["image_identity"]["id"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertRegex(
            self.report["harness_binary"]["sha256"],
            r"^[0-9a-f]{64}$",
        )

    def test_report_embeds_exact_hash_bound_manifest(self):
        self.assertEqual(self.report["corpus"], self.manifest)
        self.assertEqual(
            self.report["corpus_manifest_sha256"],
            hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
        )

    def test_raw_observations_match_hashes_and_resource_limits(self):
        cases = [
            *self.report["normal_cases"],
            self.report["cancellation_case"],
        ]
        for case in cases:
            with self.subTest(case=case["case"]):
                stdout = case["stdout"].encode("utf-8")
                stderr = case["stderr"].encode("utf-8")
                self.assertEqual(
                    hashlib.sha256(stdout).hexdigest(),
                    case["stdout_sha256"],
                )
                self.assertEqual(
                    hashlib.sha256(stderr).hexdigest(),
                    case["stderr_sha256"],
                )
                self.assertEqual(
                    json.loads(case["stdout"]),
                    case["harness"],
                )
        self.assertEqual(
            self.report["environment"]["resource_limits"],
            MODULE.RESOURCE_LIMITS,
        )
        self.assertEqual(
            self.report["environment"]["container_network"],
            "none",
        )

    def test_cancellation_is_a_nonempty_strict_prefix_control(self):
        cancellation_case = self.report["cancellation_case"]
        cancellation = cancellation_case["harness"]
        full = next(
            case["harness"]
            for case in self.report["normal_cases"]
            if case["sample"] == cancellation_case["sample"]
        )
        self.assertEqual(cancellation_case["sample"], "depth-64.zip")
        self.assertTrue(cancellation["pd_stopped"])
        self.assertGreater(cancellation["record_count"], 0)
        self.assertLess(
            cancellation["record_count"],
            full["record_count"],
        )
        self.assertLess(
            cancellation["max_stream_depth"],
            full["max_stream_depth"],
        )

    def test_manifest_verifier_rejects_extra_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            GENERATOR.generate(root)
            (root / "extra.bin").write_bytes(b"extra")
            with self.assertRaisesRegex(
                MODULE.ProbeError,
                "extra files",
            ):
                MODULE.load_and_verify_corpus(root, MANIFEST_PATH)

    def test_dockerfile_relinks_only_the_console_main(self):
        dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
        harness = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "ARG BASE_IMAGE=die-rust/upstream-oracle-cmake:74eaf505",
            dockerfile,
        )
        self.assertIn(
            "CMakeFiles/diec.dir/main_console.cpp.o",
            dockerfile,
        )
        self.assertIn(
            "/tmp/archive_limits_harness_main.cpp.o",
            dockerfile,
        )
        self.assertIn(
            'org.opencontainers.image.revision="74eaf505',
            dockerfile,
        )
        self.assertIn("engine.scanFile", harness)
        self.assertIn("getrusage(RUSAGE_SELF", harness)
        self.assertIn("XBinary::setPdStructStopped", harness)

    def test_qt6_dockerfile_relinks_the_same_console_main(self):
        dockerfile = QT6_DOCKERFILE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "ARG BASE_IMAGE="
            "die-rust/upstream-oracle-cmake-qt6:74eaf505",
            dockerfile,
        )
        self.assertIn(
            "CMakeFiles/diec.dir/main_console.cpp.o",
            dockerfile,
        )
        self.assertIn(
            "/tmp/archive_limits_harness_main.cpp.o",
            dockerfile,
        )
        self.assertIn(
            'org.opencontainers.image.revision="74eaf505',
            dockerfile,
        )


if __name__ == "__main__":
    unittest.main()

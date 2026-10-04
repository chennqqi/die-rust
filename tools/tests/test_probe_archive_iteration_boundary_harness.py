import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "probe_archive_iteration_boundary_harness.py"
)
REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "archive-iteration-boundary-engine-qt5.json"
)
MANIFEST_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "archive-iteration-boundary-corpus.json"
)
DOCKERFILE_PATHS = {
    "qt5": (
        ROOT
        / "tools"
        / "upstream"
        / "Dockerfile.archive-iteration-boundary-harness-qt5"
    ),
    "qt6": (
        ROOT
        / "tools"
        / "upstream"
        / "Dockerfile.archive-iteration-boundary-harness-qt6"
    ),
}
HARNESS_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "archive_iteration_boundary_harness_main.cpp"
)
DOCUMENT_PATH = (
    ROOT / "docs" / "research" / "archive-iteration-boundary.md"
)
SPEC = importlib.util.spec_from_file_location(
    "probe_archive_iteration_boundary_harness",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
GENERATOR_PATH = (
    ROOT
    / "tools"
    / "corpus"
    / "generate_archive_iteration_boundary_fixture.py"
)
GENERATOR_SPEC = importlib.util.spec_from_file_location(
    "generate_archive_iteration_boundary_fixture_for_probe_test",
    GENERATOR_PATH,
)
assert (
    GENERATOR_SPEC is not None
    and GENERATOR_SPEC.loader is not None
)
GENERATOR = importlib.util.module_from_spec(GENERATOR_SPEC)
sys.modules[GENERATOR_SPEC.name] = GENERATOR
GENERATOR_SPEC.loader.exec_module(GENERATOR)


class ProbeArchiveIterationBoundaryHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = json.loads(
            REPORT_PATH.read_text(encoding="utf-8")
        )
        cls.manifest = json.loads(
            MANIFEST_PATH.read_text(encoding="utf-8")
        )

    def test_committed_report_passes_all_semantic_assertions(self):
        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report["failures"], [])
        self.assertEqual(MODULE.evaluate_report(self.report), [])
        self.assertTrue(all(self.report["assertions"].values()))

    def test_exact_boundary_is_100000_inclusive(self):
        by_sample = {
            case["sample"]: case["harness"]
            for case in self.report["cases"]
        }
        self.assertEqual(
            by_sample["sentinel-099999.iso"]["pdf_node_count"],
            1,
        )
        self.assertEqual(
            by_sample["sentinel-100000.iso"]["pdf_node_count"],
            1,
        )
        self.assertEqual(
            by_sample["sentinel-100001.iso"]["pdf_node_count"],
            0,
        )
        self.assertEqual(
            by_sample["sentinel-100001.iso"][
                "stream_node_count"
            ],
            0,
        )

    def test_report_binds_source_image_binary_and_manifest(self):
        self.assertEqual(
            self.report["upstream_commit"],
            MODULE.EXPECTED_REVISION,
        )
        self.assertEqual(
            self.report["xscanengine_commit"],
            MODULE.EXPECTED_XSCANENGINE_COMMIT,
        )
        self.assertEqual(
            self.report["source_contract"]["sha256"],
            MODULE.EXPECTED_SOURCE_SHA256,
        )
        self.assertTrue(
            self.report["source_contract"][
                "source_order_verified"
            ]
        )
        self.assertRegex(
            self.report["environment"]["image_identity"]["id"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertRegex(
            self.report["harness_binary"]["sha256"],
            r"^[0-9a-f]{64}$",
        )
        self.assertEqual(self.report["corpus"], self.manifest)
        self.assertEqual(
            self.report["corpus_manifest_sha256"],
            hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
        )

    def test_raw_observations_match_hashes_and_limits(self):
        for case in self.report["cases"]:
            with self.subTest(sample=case["sample"]):
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
                self.assertFalse(case["timed_out"])
                self.assertFalse(case["possible_oom_exit_137"])
        self.assertEqual(
            self.report["environment"]["resource_limits"],
            MODULE.RESOURCE_LIMITS,
        )
        self.assertEqual(
            self.report["environment"]["fault_injection"],
            MODULE.FAULT_INJECTION,
        )
        self.assertEqual(
            self.report["environment"]["container_network"],
            "none",
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
                MODULE.load_and_verify_corpus(
                    root,
                    MANIFEST_PATH,
                )

    def test_harness_and_dockerfile_enable_aggressive_scan(self):
        dockerfiles = {
            name: path.read_text(encoding="utf-8")
            for name, path in DOCKERFILE_PATHS.items()
        }
        harness = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "ARG BASE_IMAGE=die-rust/upstream-oracle-cmake:74eaf505",
            dockerfiles["qt5"],
        )
        self.assertIn(
            "ARG BASE_IMAGE="
            "die-rust/upstream-oracle-cmake-qt6:74eaf505",
            dockerfiles["qt6"],
        )
        for name, dockerfile in dockerfiles.items():
            with self.subTest(variant=name):
                self.assertIn(
                    "CMakeFiles/diec.dir/main_console.cpp.o",
                    dockerfile,
                )
                self.assertIn(
                    "/tmp/archive_iteration_boundary_harness_main.cpp.o",
                    dockerfile,
                )
                self.assertIn(
                    'org.opencontainers.image.revision="74eaf505',
                    dockerfile,
                )
        self.assertIn("options.bIsAggressiveScan = true", harness)
        self.assertIn("options.bIsArchivesScan = true", harness)
        self.assertIn("getrusage(RUSAGE_SELF", harness)

    def test_research_document_records_fault_injection_and_boundary(self):
        document = DOCUMENT_PATH.read_text(encoding="utf-8")
        self.assertIn("第 100000 条可达", document)
        self.assertIn("第 100001 条不可达", document)
        self.assertIn("TMPDIR=/proc", document)
        self.assertIn("CAP-GAP-006", document)


if __name__ == "__main__":
    unittest.main()

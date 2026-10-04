import base64
import hashlib
import importlib.util
import json
import pathlib
import sys
import unittest
import zlib


ROOT = pathlib.Path(__file__).resolve().parents[2]
REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "bw-dispatch-engine-qt5-qt6.json"
)
QT5_REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "bw-dispatch-engine-qt5.json"
)
PROBE_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "probe_qt6_bw_dispatch_harness.py"
)
HARNESS_PATH = (
    ROOT / "tools" / "upstream" / "bw_dispatch_harness_main.cpp"
)
DOCKERFILE_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.bw-dispatch-harness-qt6"
)
DOCUMENT_PATH = (
    ROOT / "docs" / "research" / "dos-dispatch-reachability.md"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_probe():
    spec = importlib.util.spec_from_file_location(
        "_test_qt6_bw_dispatch",
        PROBE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Qt6 BW dispatch probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PROBE = load_probe()


class Qt6BwDispatchHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report_bytes = REPORT_PATH.read_bytes()
        cls.report = json.loads(cls.report_bytes)
        cls.qt5 = json.loads(QT5_REPORT_PATH.read_bytes())

    def test_report_and_harness_identity_are_exact(self):
        report = self.report
        self.assertEqual(
            sha256(self.report_bytes),
            "8bf95a3f81855e751880dd54d2747c2aac6c8458378c5a80c411561080143a6a",
        )
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["capability"], "CAP-DISPATCH-002")
        self.assertEqual(report["repetitions"], 2)
        self.assertEqual(
            report["generator_sha256"],
            sha256(PROBE_PATH.read_bytes()),
        )
        self.assertEqual(
            report["harness"]["source_sha256"],
            sha256(HARNESS_PATH.read_bytes()),
        )
        self.assertEqual(
            report["harness"]["qt6_dockerfile_sha256"],
            sha256(DOCKERFILE_PATH.read_bytes()),
        )
        self.assertEqual(
            report["qt5_reference"]["sha256"],
            sha256(QT5_REPORT_PATH.read_bytes()),
        )

    def test_qt6_oracle_is_exact(self):
        oracle = self.report["qt6_oracle"]
        self.assertEqual(
            oracle["image_id"],
            "sha256:f71568facffa71c29420f9f0701e58bce15db54ee1cb12603938bc19804f893e",
        )
        self.assertEqual(
            oracle["binary_sha256"],
            "556c8ff8ed0b2f3a534305aa15184fd7ad33408068cdd6be1f3992de92c23f32",
        )
        self.assertEqual(
            oracle["revision"],
            "74eaf505c250ab47e709024e9dc41657cd8f2254",
        )

    def test_raw_artifacts_and_repetitions_are_equal(self):
        artifacts = self.report["raw_artifacts"]
        self.assertEqual(len(artifacts), 2)
        for digest, artifact in artifacts.items():
            compressed = base64.b64decode(
                artifact["base64"],
                validate=True,
            )
            data = zlib.decompress(compressed)
            self.assertEqual(len(data), artifact["bytes"])
            self.assertEqual(sha256(data), digest)
        executions = self.report["executions"]
        self.assertEqual(executions[0], executions[1])
        for execution in executions:
            self.assertEqual(execution["exit_code"], 0)
            for stream in ("stdout", "stderr"):
                reference = execution[stream]
                self.assertIn(reference["sha256"], artifacts)
                self.assertEqual(
                    reference["sha256"],
                    reference["artifact_sha256"],
                )

    def test_semantics_and_raw_streams_match_qt5(self):
        self.assertEqual(
            self.report["harness_output"],
            self.qt5["harness_output"],
        )
        self.assertEqual(
            self.report["comparison"],
            {
                "raw_stream_differences": [],
                "semantic_output_equal": True,
            },
        )
        self.assertTrue(all(self.report["relationships"].values()))
        cases = PROBE.BASE.case_map(self.report["harness_output"])
        automatic = cases["automatic_detection"]
        forced = cases["forced_property"]
        self.assertNotIn(
            "BWDOS16M",
            automatic["detected_filetypes"].split("|"),
        )
        self.assertEqual(automatic["initial_filetype"], "Binary")
        self.assertEqual(forced["property"], "BWDOS16M")
        self.assertEqual(forced["initial_filetype"], "BW DOS16M")
        self.assertEqual(forced["records"][0]["filetype"], "BW DOS16M")
        self.assertTrue(forced["records"][0]["unknown"])

    def test_qt6_dockerfile_replaces_only_console_main(self):
        text = DOCKERFILE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "ARG BASE_IMAGE=die-rust/"
            "upstream-oracle-cmake-qt6:74eaf505",
            text,
        )
        self.assertIn(
            "CMakeFiles/diec.dir/main_console.cpp.o",
            text,
        )
        self.assertIn(
            "/tmp/bw_dispatch_harness_main.cpp.o",
            text,
        )
        self.assertIn(
            'org.opencontainers.image.description="Research-only Qt 6',
            text,
        )

    def test_document_binds_bw_report(self):
        document = DOCUMENT_PATH.read_text(encoding="utf-8")
        self.assertIn(REPORT_PATH.name, document)
        self.assertIn(sha256(self.report_bytes), document)


if __name__ == "__main__":
    unittest.main()

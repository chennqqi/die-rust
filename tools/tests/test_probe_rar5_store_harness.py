import base64
import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
import zlib


ROOT = pathlib.Path(__file__).resolve().parents[2]
PROBE_PATH = (
    ROOT / "tools" / "upstream" / "probe_rar5_store_harness.py"
)
GENERATOR_PATH = (
    ROOT / "tools" / "corpus" / "generate_rar5_store_fixture.py"
)
MANIFEST_PATH = (
    ROOT / "docs" / "research" / "data" / "rar5-store-corpus.json"
)
REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "rar5-store-engine-qt5.json"
)
DOCUMENT_PATH = (
    ROOT / "docs" / "research" / "archive-rar5-store-behavior.md"
)


def load_module(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PROBE = load_module(PROBE_PATH, "probe_rar5_store_harness_test")
GENERATOR = load_module(
    GENERATOR_PATH,
    "generate_rar5_store_fixture_for_probe_test",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ProbeRar5StoreHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report_bytes = REPORT_PATH.read_bytes()
        cls.report = json.loads(cls.report_bytes)
        cls.manifest = json.loads(MANIFEST_PATH.read_bytes())

    def test_report_identity_scope_and_hash_are_exact(self):
        self.assertEqual(
            sha256(self.report_bytes),
            "788100fd4bb2d2009b9a4531c7b8880c1a0369bacca2ed1adf8700983ce4d264",
        )
        self.assertEqual(self.report["schema_version"], 1)
        self.assertEqual(
            self.report["upstream_commit"],
            "74eaf505c250ab47e709024e9dc41657cd8f2254",
        )
        self.assertEqual(
            self.report["platform"],
            "linux-x86_64-qt5",
        )
        self.assertEqual(self.report["execution_count"], 8)
        self.assertEqual(self.report["remaining_gap"], "CAP-GAP-006")
        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report["failures"], [])
        self.assertTrue(all(self.report["facts"].values()))
        self.assertEqual(
            self.report["generator_sha256"],
            sha256(PROBE_PATH.read_bytes()),
        )

    def test_fixture_image_binaries_and_sources_are_exact(self):
        self.assertEqual(
            self.report["fixture_manifest"],
            {
                "path": "docs/research/data/rar5-store-corpus.json",
                "sample_count": 2,
                "sha256": sha256(MANIFEST_PATH.read_bytes()),
            },
        )
        self.assertEqual(
            self.report["image"],
            {
                "id": (
                    "sha256:771b9094a2ad6ab4f6250dd89307ab727c07a1aa"
                    "e885a894695abfa959bab5dc"
                ),
                "name": (
                    "die-rust/upstream-archive-harness:74eaf505"
                ),
                "repo_digests": [
                    "die-rust/upstream-archive-harness@sha256:"
                    "771b9094a2ad6ab4f6250dd89307ab727c07a1aa"
                    "e885a894695abfa959bab5dc"
                ],
                "revision": (
                    "74eaf505c250ab47e709024e9dc41657cd8f2254"
                ),
            },
        )
        self.assertEqual(
            self.report["binaries"],
            {
                "harness": {
                    "path": (
                        "/opt/die-build/src/console/"
                        "die-archive-harness"
                    ),
                    "sha256": (
                        "b7ea9b151b58b630c017e9989333fa035b7d86ffa"
                        "b366a5d3a1f74bab9f1e96e"
                    ),
                    "size": 8233888,
                },
                "release": {
                    "path": "/opt/die-build/src/console/diec",
                    "sha256": (
                        "da1fab49f7ba5970d1fc1c7fe3d4f380cf5e8775"
                        "dd8097207e7b3c30f08236cf"
                    ),
                    "size": 8248008,
                },
            },
        )
        expected_source_hashes = {
            "engine_archive_gate": (
                "e088bebb7c8345ce5832cc51de712c05a8b239873d7f092db3ae5566a761b498"
            ),
            "rar5_solid_index": (
                "23721187a6118edce8b9511680f34c404727f831ec8c7ed66e0ed0868260ccb8"
            ),
            "rar5_store_mapping": (
                "23721187a6118edce8b9511680f34c404727f831ec8c7ed66e0ed0868260ccb8"
            ),
            "rar_solid_store_dispatch": (
                "4f52eefa06674ea5b7e3f7e1b989502147be84d83e32e8086a7087839ed2728d"
            ),
            "rar_unpack": (
                "23721187a6118edce8b9511680f34c404727f831ec8c7ed66e0ed0868260ccb8"
            ),
        }
        self.assertEqual(
            {
                name: source["sha256"]
                for name, source in self.report[
                    "source_contract"
                ].items()
            },
            expected_source_hashes,
        )
        self.assertTrue(
            all(
                source["required_pattern_count"] >= 1
                for source in self.report[
                    "source_contract"
                ].values()
            )
        )

    def test_modes_preserve_exact_rar5_store_results(self):
        self.assertEqual(
            set(self.report["cases"]),
            {"rar5-store-single.rar", "rar5-store-solid-pair.rar"},
        )
        expected_pdf = {
            "detection_names": ["PDF", "HeaderComment"],
            "filetype": "PDF",
            "size": "331",
        }
        for sample_name, cases in self.report["cases"].items():
            self.assertEqual(
                set(cases),
                {
                    "archive",
                    "archive_aggressive",
                    "default",
                    "release_default",
                },
            )
            for mode, case in cases.items():
                with self.subTest(sample=sample_name, mode=mode):
                    summary = case["summary"]
                    self.assertEqual(summary["root_filetype"], "RAR")
                    self.assertEqual(
                        summary["root_detection_names"],
                        ["Unknown"],
                    )
                    count = (
                        0
                        if mode in {"default", "release_default"}
                        else (
                            1
                            if sample_name == "rar5-store-single.rar"
                            else 2
                        )
                    )
                    self.assertEqual(summary["stream_count"], count)
                    self.assertEqual(
                        summary["streams"],
                        [expected_pdf] * count,
                    )
            self.assertEqual(
                cases["default"]["stdout"],
                cases["release_default"]["stdout"],
            )
            self.assertEqual(
                cases["archive"]["stdout"],
                cases["archive_aggressive"]["stdout"],
            )

    def test_raw_artifacts_reconstruct_every_execution(self):
        artifacts = self.report["raw_artifacts"]
        self.assertEqual(len(artifacts), 5)
        for digest, artifact in artifacts.items():
            with self.subTest(digest=digest):
                self.assertEqual(
                    artifact["encoding"],
                    "zlib+base64",
                )
                compressed = base64.b64decode(
                    artifact["base64"],
                    validate=True,
                )
                self.assertEqual(
                    len(compressed),
                    artifact["compressed_bytes"],
                )
                data = zlib.decompress(compressed)
                self.assertEqual(len(data), artifact["bytes"])
                self.assertEqual(sha256(data), digest)
        references = []
        for cases in self.report["cases"].values():
            for case in cases.values():
                references.extend((case["stdout"], case["stderr"]))
        self.assertEqual(len(references), 16)
        for reference in references:
            self.assertIn(reference["artifact_sha256"], artifacts)
            self.assertEqual(
                reference["sha256"],
                reference["artifact_sha256"],
            )

    def test_report_is_exactly_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture_dir = pathlib.Path(temporary) / "fixture"
            GENERATOR.generate(fixture_dir)
            report = PROBE.build_report(
                fixture_dir,
                MANIFEST_PATH,
            )
            actual = (
                json.dumps(report, indent=2, sort_keys=True) + "\n"
            ).encode()
        self.assertEqual(actual, self.report_bytes)

    def test_research_document_binds_report_and_later_gap_closure(self):
        document = DOCUMENT_PATH.read_text(encoding="utf-8")
        for token in (
            "Status: Draft",
            "74eaf505c250ab47e709024e9dc41657cd8f2254",
            "788100fd4bb2d2009b9a4531c7b8880c1a0369bacca2ed1adf8700983ce4d264",
            "rar5-store-single.rar",
            "rar5-store-solid-pair.rar",
            "RAR5 Store",
            "solid",
            "8",
            "CAP-GAP-006",
            "本实验单独没有关闭",
            "archive-gap-closure.md",
            "后续关闭",
            "不包含专有压缩算法",
        ):
            with self.subTest(token=token):
                self.assertIn(token, document)


if __name__ == "__main__":
    unittest.main()

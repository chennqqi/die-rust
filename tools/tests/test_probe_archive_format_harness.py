import base64
import hashlib
import json
import pathlib
import unittest
import zlib


ROOT = pathlib.Path(__file__).resolve().parents[2]
REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "archive-format-engine-qt5.json"
)
MANIFEST_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "archive-format-corpus.json"
)
PROBE_PATH = (
    ROOT / "tools" / "upstream" / "probe_archive_format_harness.py"
)
DOCUMENT_PATH = (
    ROOT / "docs" / "research" / "archive-format-behavior.md"
)
BASE_AES_ARCHIVES = (
    "pdf-member-copy-aes.7z",
    "pdf-member-lzma-aes.7z",
    "pdf-member-ppmd7-aes.7z",
    "pdf-member-bzip2-aes.7z",
    "pdf-member-deflate-aes.7z",
    "pdf-member-deflate64-aes.7z",
)
BASE_AES_PREFIXES = (
    "copy",
    "lzma",
    "ppmd7",
    "bzip2",
    "deflate",
    "deflate64",
)
FILTER_BASE_AES_CASES = tuple(
    (
        f"pdf-member-{filter_slug}-{method_slug}-aes.7z",
        f"{filter_slug}_{method_slug}",
    )
    for filter_slug in ("bcj", "arm64")
    for method_slug in (
        "copy",
        "lzma",
        "ppmd7",
        "bzip2",
        "deflate",
        "deflate64",
    )
)
FILTER_BASE_AES_ARCHIVES = tuple(
    archive_name for archive_name, _ in FILTER_BASE_AES_CASES
)
FILTER_BASE_AES_PREFIXES = tuple(
    prefix for _, prefix in FILTER_BASE_AES_CASES
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ArchiveFormatHarnessProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report_bytes = REPORT_PATH.read_bytes()
        cls.report = json.loads(cls.report_bytes)

    def test_report_identity_and_scope_are_exact(self):
        report = self.report
        self.assertEqual(
            sha256(self.report_bytes),
            "d27ee4aa9c03be0939d495e6b9ab062f669f123eeff36ccfac16062d3089a784",
        )
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(
            report["upstream_commit"],
            "74eaf505c250ab47e709024e9dc41657cd8f2254",
        )
        self.assertEqual(report["platform"], "linux-x86_64-qt5")
        self.assertEqual(
            report["generator_sha256"],
            sha256(PROBE_PATH.read_bytes()),
        )
        self.assertEqual(report["remaining_gap"], "CAP-GAP-006")
        self.assertTrue(report["passed"])
        self.assertEqual(report["failures"], [])

    def test_fixture_and_local_sources_are_hash_bound(self):
        report = self.report
        self.assertEqual(
            report["fixture_manifest"],
            {
                "path": "docs/research/data/archive-format-corpus.json",
                "sample_count": 41,
                "sha256": sha256(MANIFEST_PATH.read_bytes()),
            },
        )
        self.assertEqual(
            set(report["local_sources"]),
            {
                "baseline_generator",
                "direct_password_dockerfile",
                "direct_password_source",
                "fixture_generator",
                "fixture_requirements",
                "harness_dockerfile",
                "harness_source",
            },
        )
        for source in report["local_sources"].values():
            with self.subTest(source=source["path"]):
                self.assertEqual(
                    source["sha256"],
                    sha256((ROOT / source["path"]).read_bytes()),
                )

    def test_oracle_image_binaries_and_sources_are_exact(self):
        report = self.report
        self.assertEqual(
            report["image"],
            {
                "id": (
                    "sha256:adf8e09f3ed7c15a54f3486c482599e1bcb12230"
                    "8a0b27396de1baf2ee634daf"
                ),
                "name": (
                    "die-rust/upstream-sevenzip-password-harness:"
                    "74eaf505"
                ),
                "repo_digests": [
                    "die-rust/upstream-sevenzip-password-harness@sha256:"
                    "adf8e09f3ed7c15a54f3486c482599e1bcb12230"
                    "8a0b27396de1baf2ee634daf"
                ],
                "revision": "74eaf505c250ab47e709024e9dc41657cd8f2254",
            },
        )
        self.assertEqual(
            report["binaries"],
            {
                "direct_password_harness": {
                    "path": (
                        "/opt/die-build/src/console/"
                        "die-sevenzip-password-harness"
                    ),
                    "sha256": (
                        "af3566c9c3a554f0769a3c582ebc2eb116e74560"
                        "cbd6f3f3b03e4d006cc98baa"
                    ),
                    "size": 8238080,
                },
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
        expected_sources = {
            "bcj2_decoder": "254d9773c5f709e4700d917815afba07f87325300bfbd0c14ee314a501b3018a",
            "bcj2_dispatch": "4f52eefa06674ea5b7e3f7e1b989502147be84d83e32e8086a7087839ed2728d",
            "cab": "a0ce130f4d81ba3aeb018e485a3ee8c046d4cbb570d6318f7aa8817aff28035b",
            "cab_decompress_dispatch": "4f52eefa06674ea5b7e3f7e1b989502147be84d83e32e8086a7087839ed2728d",
            "cab_lzx_method": "a0ce130f4d81ba3aeb018e485a3ee8c046d4cbb570d6318f7aa8817aff28035b",
            "cab_unknown_method": "a0ce130f4d81ba3aeb018e485a3ee8c046d4cbb570d6318f7aa8817aff28035b",
            "decompress_dispatch": "4f52eefa06674ea5b7e3f7e1b989502147be84d83e32e8086a7087839ed2728d",
            "deflate_decoder": "cb74b248ded89fea38940ee2ea8135f77a6a4d3b11bc1edd5dea1eb49e5627a6",
            "engine": "e088bebb7c8345ce5832cc51de712c05a8b239873d7f092db3ae5566a761b498",
            "engine_empty_unpack_properties": "e088bebb7c8345ce5832cc51de712c05a8b239873d7f092db3ae5566a761b498",
            "iso9660": "d6e97c4ff2395b812b65da5ab480e937c6b365e6e6e8b0288ddf48b8fd398fb1",
            "rar": "23721187a6118edce8b9511680f34c404727f831ec8c7ed66e0ed0868260ccb8",
            "sevenzip": "d8da44bdcd1dfab07f1403ae19a0113238fd54620ef9b4307410097d7d8e5554",
            "sevenzip_aes_decompress": "4f52eefa06674ea5b7e3f7e1b989502147be84d83e32e8086a7087839ed2728d",
            "sevenzip_aes_method": "d8da44bdcd1dfab07f1403ae19a0113238fd54620ef9b4307410097d7d8e5554",
            "sevenzip_aes_sequences": "d8da44bdcd1dfab07f1403ae19a0113238fd54620ef9b4307410097d7d8e5554",
            "sevenzip_bcj2_graph": "d8da44bdcd1dfab07f1403ae19a0113238fd54620ef9b4307410097d7d8e5554",
            "sevenzip_filters": "d8da44bdcd1dfab07f1403ae19a0113238fd54620ef9b4307410097d7d8e5554",
            "sevenzip_methods": "d8da44bdcd1dfab07f1403ae19a0113238fd54620ef9b4307410097d7d8e5554",
        }
        self.assertEqual(
            {
                name: source["sha256"]
                for name, source in report["source_contract"].items()
            },
            expected_sources,
        )
        self.assertTrue(
            all(
                source["required_pattern_count"] >= 1
                for source in report["source_contract"].values()
            )
        )

    def test_raw_artifacts_reconstruct_every_execution(self):
        report = self.report
        artifacts = report["raw_artifacts"]
        self.assertEqual(len(artifacts), 51)
        for digest, artifact in artifacts.items():
            with self.subTest(digest=digest):
                self.assertEqual(artifact["encoding"], "zlib+base64")
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
        for sample in report["cases"].values():
            for case in sample.values():
                for stream in ("stdout", "stderr"):
                    reference = case[stream]
                    artifact = artifacts[reference["artifact_sha256"]]
                    self.assertEqual(
                        reference["sha256"],
                        reference["artifact_sha256"],
                    )
                    self.assertEqual(reference["bytes"], artifact["bytes"])
        for case in report["direct_password_cases"].values():
            for stream in ("stdout", "stderr"):
                reference = case[stream]
                artifact = artifacts[reference["artifact_sha256"]]
                self.assertEqual(
                    reference["sha256"],
                    reference["artifact_sha256"],
                )
                self.assertEqual(reference["bytes"], artifact["bytes"])

    def test_modes_preserve_exact_roots_and_unpack_one_pdf(self):
        expected_roots = {
            "pdf-member.7z": ("Binary", ["7-Zip"]),
            "pdf-member-bzip2.7z": ("Binary", ["7-Zip"]),
            "pdf-member-deflate.7z": ("Binary", ["7-Zip"]),
            "pdf-member-deflate64.7z": ("Binary", ["7-Zip"]),
            "pdf-member-bcj-lzma2.7z": ("Binary", ["7-Zip"]),
            "pdf-member-bcj2-lzma2.7z": ("Binary", ["7-Zip"]),
            "pdf-member-bcj2-e8-lzma2.7z": (
                "Binary",
                ["7-Zip"],
            ),
            "pdf-member-bcj2-e9-lzma2.7z": (
                "Binary",
                ["7-Zip"],
            ),
            "pdf-member-bcj2-jcc-lzma2.7z": (
                "Binary",
                ["7-Zip"],
            ),
            "pdf-member-arm64-bcj-lzma2.7z": (
                "Binary",
                ["7-Zip"],
            ),
            "pdf-member-lzma.7z": ("Binary", ["7-Zip"]),
            "pdf-member-lzma2.7z": ("Binary", ["7-Zip"]),
            "pdf-member-lzma2-aes.7z": ("Binary", ["7-Zip"]),
            "pdf-member-bcj2-lzma2-aes.7z": (
                "Binary",
                ["7-Zip"],
            ),
            "pdf-member-bcj-lzma2-aes.7z": (
                "Binary",
                ["7-Zip"],
            ),
            "pdf-member-arm64-lzma2-aes.7z": (
                "Binary",
                ["7-Zip"],
            ),
            "pdf-member-ppmd7.7z": ("Binary", ["7-Zip"]),
            "pdf-member.cab": ("Binary", ["CAB"]),
            "pdf-member-mszip.cab": ("Binary", ["CAB"]),
            "pdf-member-lzx.cab": ("Binary", ["CAB"]),
            "text-member-quantum.cab": ("Binary", ["CAB"]),
            "pdf-member.iso": ("ISO 9660", ["Unknown"]),
            "pdf-member.rar": ("RAR", ["Unknown"]),
        }
        expected_roots.update(
            {
                name: ("Binary", ["7-Zip"])
                for name in (
                    *BASE_AES_ARCHIVES,
                    *FILTER_BASE_AES_ARCHIVES,
                )
            }
        )
        for sample_name, (filetype, names) in expected_roots.items():
            cases = self.report["cases"][sample_name]
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
                    self.assertEqual(summary["root_filetype"], filetype)
                    self.assertEqual(
                        summary["root_detection_names"],
                        names,
                    )
                    if mode in {"default", "release_default"} or (
                        sample_name
                        in {
                            "pdf-member-lzx.cab",
                            "text-member-quantum.cab",
                        }
                        and mode == "archive"
                    ) or (
                        sample_name
                        in {
                            "pdf-member-lzma2-aes.7z",
                            "pdf-member-bcj2-lzma2-aes.7z",
                            "pdf-member-bcj-lzma2-aes.7z",
                            "pdf-member-arm64-lzma2-aes.7z",
                            *BASE_AES_ARCHIVES,
                            *FILTER_BASE_AES_ARCHIVES,
                        }
                    ):
                        self.assertEqual(summary["stream_count"], 0)
                    elif sample_name in {
                        "pdf-member-lzx.cab",
                        "text-member-quantum.cab",
                    }:
                        self.assertEqual(summary["stream_count"], 1)
                        self.assertEqual(
                            summary["stream_filetypes"],
                            ["Binary"],
                        )
                        self.assertEqual(
                            summary["stream_detection_names"],
                            ["Unknown"],
                        )
                        self.assertEqual(
                            summary["stream_sizes"],
                            [
                                {
                                    "pdf-member-lzx.cab": "331",
                                    "text-member-quantum.cab": "59",
                                }[sample_name]
                            ],
                        )
                    else:
                        self.assertEqual(summary["stream_count"], 1)
                        self.assertEqual(
                            summary["stream_filetypes"],
                            ["PDF"],
                        )
                        self.assertEqual(
                            summary["stream_detection_names"],
                            ["PDF", "HeaderComment"],
                        )
                        self.assertEqual(
                            summary["stream_sizes"],
                            [{
                                "pdf-member-arm64-bcj-lzma2.7z": "4100",
                                "pdf-member-deflate64.7z": "32772",
                                "pdf-member-bcj2-e8-lzma2.7z": "336",
                                "pdf-member-bcj2-e9-lzma2.7z": "336",
                                "pdf-member-bcj2-jcc-lzma2.7z": "337",
                            }.get(sample_name, "331")],
                        )
            self.assertEqual(
                cases["default"]["stdout"],
                cases["release_default"]["stdout"],
            )
            if sample_name in {
                "pdf-member-lzx.cab",
                "text-member-quantum.cab",
            }:
                self.assertNotEqual(
                    cases["archive"]["stdout"],
                    cases["archive_aggressive"]["stdout"],
                )
            else:
                self.assertEqual(
                    cases["archive"]["stdout"],
                    cases["archive_aggressive"]["stdout"],
                )
            if sample_name in {
                "pdf-member-lzma2-aes.7z",
                "pdf-member-bcj2-lzma2-aes.7z",
                "pdf-member-bcj-lzma2-aes.7z",
                "pdf-member-arm64-lzma2-aes.7z",
                *BASE_AES_ARCHIVES,
                *FILTER_BASE_AES_ARCHIVES,
            }:
                warning_sha256 = (
                    "003e45244a40755beaf48f2a2b30bb756"
                    "344488874b4d6f23caa50b7b3bf011c"
                )
                self.assertEqual(
                    cases["archive"]["stderr"]["sha256"],
                    warning_sha256,
                )
                self.assertEqual(
                    cases["archive_aggressive"]["stderr"]["sha256"],
                    warning_sha256,
                )

    def test_direct_sevenzip_password_contract_is_exact(self):
        cases = self.report["direct_password_cases"]
        expected_case_names = {
                "bcj2_correct_password",
                "bcj2_missing_password",
                "bcj2_wrong_password",
                "bcj_correct_password",
                "bcj_missing_password",
                "bcj_wrong_password",
                "arm64_correct_password",
                "arm64_missing_password",
                "arm64_wrong_password",
                "lzma2_correct_password",
                "lzma2_missing_password",
                "lzma2_wrong_password",
        }
        expected_case_names.update(
            f"{prefix}_{state}"
            for prefix in (
                *BASE_AES_PREFIXES,
                *FILTER_BASE_AES_PREFIXES,
            )
            for state in (
                "correct_password",
                "missing_password",
                "wrong_password",
            )
        )
        self.assertEqual(set(cases), expected_case_names)
        empty_sha256 = (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )
        pdf_sha256 = (
            "47bd96bd99d3fd9d9edf09151f7c6299"
            "9aaf71ed599bd975db9e46c4d6ef5d92"
        )
        expected = {
            "lzma2_correct_password": (
                True,
                True,
                331,
                pdf_sha256,
                0,
            ),
            "lzma2_missing_password": (
                False,
                False,
                0,
                empty_sha256,
                54,
            ),
            "lzma2_wrong_password": (
                True,
                False,
                0,
                empty_sha256,
                0,
            ),
            "bcj2_correct_password": (
                True,
                False,
                0,
                empty_sha256,
                54,
            ),
            "bcj2_missing_password": (
                False,
                False,
                0,
                empty_sha256,
                54,
            ),
            "bcj2_wrong_password": (
                True,
                False,
                0,
                empty_sha256,
                0,
            ),
            "bcj_correct_password": (
                True,
                True,
                331,
                pdf_sha256,
                0,
            ),
            "bcj_missing_password": (
                False,
                False,
                0,
                empty_sha256,
                54,
            ),
            "bcj_wrong_password": (
                True,
                False,
                0,
                empty_sha256,
                0,
            ),
            "arm64_correct_password": (
                True,
                True,
                331,
                pdf_sha256,
                0,
            ),
            "arm64_missing_password": (
                False,
                False,
                0,
                empty_sha256,
                54,
            ),
            "arm64_wrong_password": (
                True,
                False,
                0,
                empty_sha256,
                0,
            ),
        }
        for prefix in (
            *BASE_AES_PREFIXES,
            *FILTER_BASE_AES_PREFIXES,
        ):
            expected[f"{prefix}_correct_password"] = (
                True,
                True,
                331,
                pdf_sha256,
                0,
            )
            expected[f"{prefix}_missing_password"] = (
                False,
                False,
                0,
                empty_sha256,
                54,
            )
            expected[f"{prefix}_wrong_password"] = (
                True,
                False,
                0,
                empty_sha256,
                0,
            )
        expected["copy_wrong_password"] = (
            True,
            False,
            331,
            (
                "d427e6be98806d608c527a2a0b1065ae"
                "dcfcf29f8bfba42b33f064b806fb0274"
            ),
            0,
        )
        expected["ppmd7_wrong_password"] = (
            True,
            False,
            331,
            (
                "3404ad646903d0c1ae7521b82f606b13"
                "a88fd595496255217f6e4a250076f042"
            ),
            0,
        )
        for prefix, output_sha256 in {
            "arm64_copy": (
                "730eb17ce3f4240b11303a14041e952a"
                "8acff6463ad59d3f60d723fa500d2dfd"
            ),
            "arm64_ppmd7": (
                "3404ad646903d0c1ae7521b82f606b13"
                "a88fd595496255217f6e4a250076f042"
            ),
            "bcj_copy": (
                "e4b808e14457a016c55f09633c0351c7"
                "bb29d1b785427e7a5dc775f009fc6a43"
            ),
            "bcj_ppmd7": (
                "3404ad646903d0c1ae7521b82f606b13"
                "a88fd595496255217f6e4a250076f042"
            ),
        }.items():
            expected[f"{prefix}_wrong_password"] = (
                True,
                False,
                331,
                output_sha256,
                0,
            )
        for name, (
            password_supplied,
            unpacked,
            output_size,
            output_sha256,
            stderr_bytes,
        ) in expected.items():
            with self.subTest(name=name):
                case = cases[name]
                self.assertEqual(case["exit_code"], 0)
                self.assertEqual(
                    case["result"],
                    {
                        "archive_valid": True,
                        "declared_size": 331,
                        "initialized": True,
                        "member_name": "payload.pdf",
                        "output_opened": True,
                        "output_sha256": output_sha256,
                        "output_size": output_size,
                        "password_supplied": password_supplied,
                        "record_count": 1,
                        "unpacked": unpacked,
                    },
                )
                self.assertEqual(
                    case["stderr"]["bytes"],
                    stderr_bytes,
                )

    def test_limits_facts_and_document_are_explicit(self):
        self.assertEqual(
            self.report["resource_limits"],
            {
                "container_root": "read-only",
                "cpus": 1,
                "fixture_mount": "read-only",
                "memory_bytes": 536870912,
                "network": "none",
                "pids": 128,
                "timeout_seconds_per_execution": 60,
            },
        )
        self.assertTrue(all(self.report["facts"].values()))
        document = DOCUMENT_PATH.read_text(encoding="utf-8")
        for fact in self.report["facts"]:
            self.assertIn(fact, document)
        self.assertIn("CAP-GAP-006", document)
        self.assertIn("archive-format-engine-qt5.json", document)
        self.assertIn(
            "d27ee4aa9c03be0939d495e6b9ab062f669f123eeff36ccfac16062d3089a784",
            document,
        )


if __name__ == "__main__":
    unittest.main()

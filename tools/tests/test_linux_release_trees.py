import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = (
    ROOT / "tools" / "upstream" / "audit_linux_release_trees.py"
)
DOCKERFILE_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.upstream-release-trees-qt5"
)
REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "linux-release-trees.json"
)
PRIOR_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "linux-cmake-install-tree.json"
)
DOCUMENT_PATH = (
    ROOT / "docs" / "research" / "linux-release-trees.md"
)
INDEX_PATH = ROOT / "docs" / "research" / "README.md"
GATE_PATH = ROOT / "docs" / "design" / "phase-0-gate-review.md"
GATE_DATA_PATH = (
    ROOT / "docs" / "design" / "data" / "phase-0-gate-review.json"
)
RISK_PATH = ROOT / "docs" / "design" / "risks.md"
TESTING_PATH = ROOT / "docs" / "design" / "testing.md"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MODULE = load_module("audit_linux_release_trees_for_test", TOOL_PATH)


class LinuxReleaseTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report_raw = REPORT_PATH.read_bytes()
        cls.report = json.loads(cls.report_raw)
        cls.release = cls.report["release"]

    def test_helpers_bind_routes_launchers_and_tree_content(self):
        self.assertEqual(MODULE.route("base/db/PE/_init"), "base/db")
        self.assertEqual(
            MODULE.route("usr/lib/die/db/read"), "usr/lib/die"
        )
        launcher = MODULE.portable_launcher("diec")
        self.assertEqual(
            launcher,
            (
                "#!/bin/sh\n"
                "CWD=$(dirname $0)\n"
                'export LD_LIBRARY_PATH="$CWD/base:$LD_LIBRARY_PATH"\n'
                '"$CWD/base/diec" "$@"\n'
            ).encode(),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "b").write_bytes(b"two")
            (root / "a").write_bytes(b"one")
            identity = MODULE.directory_content_identity(root)
        self.assertEqual(identity["file_count"], 2)
        self.assertEqual(identity["bytes"], 6)
        self.assertRegex(identity["tree_sha256"], r"^[0-9a-f]{64}$")

    def test_dockerfile_is_bound_to_exact_install_image(self):
        text = DOCKERFILE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "ARG BASE_IMAGE=die-rust/upstream-install-qt5:74eaf505"
            "@sha256:6f7a378ea1c5a07745d45083c0e596430fefc652"
            "6273528366a7dc7e11230368",
            text,
        )
        self.assertIn(
            "COPY upstream/audit_linux_release_trees.py",
            text,
        )
        self.assertIn(MODULE.UPSTREAM_COMMIT, text)

    def test_report_binds_generator_images_dockerfile_and_prior(self):
        report = self.report
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(
            report["generator"],
            "tools/upstream/audit_linux_release_trees.py",
        )
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(TOOL_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["environment"]["base_image"]["id"],
            MODULE.BASE_IMAGE_ID,
        )
        self.assertEqual(
            report["environment"]["inside_script"]["image_sha256"],
            report["generator_sha256"],
        )
        self.assertEqual(
            report["environment"]["inside_script"][
                "repository_sha256"
            ],
            report["generator_sha256"],
        )
        self.assertEqual(
            report["environment"]["dockerfile"],
            {
                "path": MODULE.DOCKERFILE,
                "sha256": hashlib.sha256(
                    DOCKERFILE_PATH.read_bytes()
                ).hexdigest(),
            },
        )
        self.assertEqual(
            report["prior_report"],
            {
                "path": MODULE.PRIOR_REPORT,
                "sha256": hashlib.sha256(
                    PRIOR_PATH.read_bytes()
                ).hexdigest(),
            },
        )
        self.assertEqual(
            report["upstream_commit"], MODULE.UPSTREAM_COMMIT
        )

    def test_scripts_release_version_and_qt_layout_are_exact(self):
        self.assertEqual(self.release["release_version"], "4.0.0")
        self.assertEqual(
            self.release["build_tools_commit"],
            MODULE.BUILD_TOOLS_COMMIT,
        )
        scripts = self.release["scripts"]
        expected = {
            "create_appimage": (
                2415,
                (
                    "3b4cfc5b8118eda8bfbbe199001520bc"
                    "022858955667d0ed8f851f82a2646075"
                ),
            ),
            "build_linux_portable": (
                3218,
                (
                    "91fb88e2f7841362b927b3471bbcb473"
                    "c663ea9421859f2ec8ceae9d2b35052a"
                ),
            ),
            "build_tools_linux": (
                5272,
                (
                    "81d8c06a40b94ac73951a92a94c6db7"
                    "d1da87bd20ca7e3dd937ee019794850a3"
                ),
            ),
        }
        for name, (size, digest) in expected.items():
            self.assertEqual(scripts[name]["bytes"], size)
            self.assertEqual(scripts[name]["sha256"], digest)
        self.assertTrue(all(scripts["derived_findings"].values()))
        self.assertEqual(
            self.release["qt_layout"],
            {
                "libraries": "/usr/lib/x86_64-linux-gnu",
                "plugins": "/usr/lib/x86_64-linux-gnu/qt5/plugins",
                "prefix": "/usr",
            },
        )

    def test_all_relationships_and_scope_remain_fail_closed(self):
        self.assertTrue(all(self.report["relationships"].values()))
        self.assertTrue(
            all(self.release["relationships"].values())
        )
        scope = self.report["scope"]
        self.assertEqual(scope["kind"], "post-build-release-tree-replay")
        for field in (
            "original_scripts_executed_end_to_end",
            "final_appimage_available",
            "portable_archive_byte_reproducible",
            "legal_review_complete",
            "release_approved",
        ):
            self.assertFalse(scope[field])
        self.assertTrue(scope["compressed_portable_archive_generated"])
        self.assertTrue(
            scope["normalized_portable_archive_control_generated"]
        )
        self.assertTrue(
            scope[
                "normalized_portable_archive_control_byte_reproducible"
            ]
        )
        limitations = "\n".join(self.report["limitations"])
        for text in (
            "surrogate",
            "linuxdeploy",
            "tar.gz",
            "post-build control",
            "legal",
        ):
            self.assertIn(text, limitations)

    def test_appimage_pre_tree_identity_and_content_are_exact(self):
        variant = self.release["variants"]["appimage_pre_linuxdeploy"]
        inventory = variant["inventory"]
        self.assertEqual(inventory["file_count"], 2640)
        self.assertEqual(inventory["bytes"], 38_920_508)
        self.assertEqual(inventory["directory_count"], 83)
        self.assertEqual(
            inventory["records_sha256"],
            (
                "795314ec3393e6e4abfcc81c3ea3de61"
                "a1e825f5c3f9402bc6873a60d191f039"
            ),
        )
        self.assertEqual(set(inventory["binaries"]), {"usr/bin/die"})
        self.assertEqual(inventory["license_candidate_paths"], [])
        self.assertEqual(inventory["symlinks"], [])
        self.assertEqual(
            inventory["origin_summary"],
            [
                {
                    "bytes": 25_293_840,
                    "file_count": 1,
                    "kind": "build",
                },
                {
                    "bytes": 13_469_084,
                    "file_count": 2636,
                    "kind": "source",
                },
                {
                    "bytes": 157_584,
                    "file_count": 3,
                    "kind": "system",
                },
            ],
        )
        self.assertEqual(
            {
                name: (
                    item["file_count"],
                    item["bytes"],
                    item["present"],
                )
                for name, item in variant["data_trees"].items()
            },
            {
                "images": (202, 2_180_397, True),
                "info": (118, 122_340, True),
                "peid": (14, 1_157_703, True),
                "qss": (15, 79_018, True),
                "signatures": (1, 3_085_459, True),
                "yara_rules": (10, 3_900_619, True),
            },
        )
        runtime = variant["runtime_rules"]
        for field, expected in MODULE.EXPECTED_RUNTIME_RULES.items():
            self.assertEqual(runtime[field], expected)

    def test_portable_variants_are_identical_and_incomplete(self):
        variants = self.release["variants"]
        system = variants["portable_system_qt"]
        prefix = variants["portable_qmake_prefix"]
        for variant in (system, prefix):
            inventory = variant["inventory"]
            self.assertEqual(inventory["file_count"], 2476)
            self.assertEqual(inventory["bytes"], 52_751_519)
            self.assertEqual(inventory["directory_count"], 45)
            self.assertEqual(
                inventory["records_sha256"],
                (
                    "fa9938f9456d6a3b92a6e5537f9da47"
                    "ec6d7f5a00d4727eaed9f3e3005ae20b5"
                ),
            )
            self.assertEqual(
                set(inventory["binaries"]),
                {"base/die", "base/diec", "base/diel"},
            )
            self.assertEqual(variant["bundled_qt_files"], [])
            self.assertEqual(inventory["license_candidate_paths"], [])
            self.assertEqual(inventory["symlinks"], [])
            runtime = variant["runtime_rules"]
            self.assertEqual(runtime["file_count"], 2124)
            self.assertEqual(runtime["bytes"], 2_832_469)
            self.assertEqual(
                runtime["combined_tree_sha256"],
                (
                    "8000138ce96a6a892aaa3cba8dee60960"
                    "694c42dcfa24b3787f02c25858f1650"
                ),
            )
            self.assertFalse(runtime["trees"]["db_extra"]["present"])
            self.assertFalse(runtime["trees"]["db_custom"]["present"])
            self.assertFalse(variant["data_trees"]["peid"]["present"])
            self.assertTrue(variant["data_trees"]["yara_rules"]["present"])
            self.assertTrue(variant["data_trees"]["signatures"]["present"])
        self.assertIsNone(system["qt_prefix_argument"])
        self.assertEqual(prefix["qt_prefix_argument"], "/usr")
        self.assertEqual(system["inventory"], prefix["inventory"])

    def test_portable_archive_replay_proves_mtime_nondeterminism(self):
        replay = self.release["portable_archive_replay"]
        self.assertEqual(
            replay["command"],
            [
                "tar",
                "-czf",
                "<ARCHIVE>",
                "die_4.0.0_portable",
            ],
        )
        self.assertEqual(replay["run_count"], 2)
        self.assertEqual(
            replay["minimum_inter_run_delay_seconds"],
            1.1,
        )
        self.assertTrue(replay["archives_nonempty"])
        self.assertTrue(
            replay["archive_hashes_intentionally_omitted"]
        )
        self.assertTrue(replay["tree_records_identical"])
        self.assertTrue(replay["tar_semantic_records_identical"])
        self.assertEqual(replay["tar_member_count"], 2522)
        self.assertEqual(replay["differing_mtime_path_count"], 8)
        self.assertEqual(
            replay["differing_mtime_path_sample"],
            [
                "die_4.0.0_portable",
                "die_4.0.0_portable/base",
                "die_4.0.0_portable/base/platforms",
                "die_4.0.0_portable/base/signatures",
                "die_4.0.0_portable/base/sqldrivers",
                "die_4.0.0_portable/die.sh",
                "die_4.0.0_portable/diec.sh",
                "die_4.0.0_portable/diel.sh",
            ],
        )
        self.assertFalse(
            replay["differing_mtime_path_sample_truncated"]
        )
        self.assertEqual(
            replay["differing_mtime_paths_sha256"],
            (
                "ea384a2e43e9f0d15a9d55eb68ce8c9"
                "122a27d573c2e5b4164692adcd3733c86"
            ),
        )
        self.assertEqual(
            replay["tar_semantic_records_sha256"],
            (
                "27d38544770412dbf8a080ad16d94d43"
                "07f4eac3a5415ba0c7a422fdcc040376"
            ),
        )
        self.assertFalse(replay["uncompressed_tar_byte_identical"])
        self.assertFalse(replay["compressed_tar_gz_byte_identical"])

        normalized = replay["normalized_control"]
        self.assertEqual(
            normalized["tar_command"],
            [
                "tar",
                "--sort=name",
                "--mtime=@0",
                "--owner=0",
                "--group=0",
                "--numeric-owner",
                "--format=gnu",
                "-cf",
                "<TAR>",
                "die_4.0.0_portable",
            ],
        )
        self.assertEqual(
            normalized["gzip_command"],
            ["gzip", "-n", "-9", "-c", "<TAR>"],
        )
        self.assertEqual(normalized["run_count"], 2)
        self.assertTrue(normalized["metadata_is_fixed"])
        self.assertEqual(normalized["tar_member_count"], 2522)
        self.assertTrue(
            normalized["tar_semantic_records_identical"]
        )
        self.assertEqual(
            normalized["tar_semantic_records_sha256"],
            (
                "b142b9f01493d11fe8ce5c42d3741536"
                "101591943cac487e7cfe67a5feb2e3a7"
            ),
        )
        self.assertTrue(
            normalized["uncompressed_tar_byte_identical"]
        )
        self.assertEqual(
            normalized["uncompressed_tar_sha256"],
            (
                "355c1e1883cee7158fb6e75d28c1912b"
                "9d557c1a372ef8d6e2309d58c20c8227"
            ),
        )
        self.assertTrue(
            normalized["compressed_tar_gz_byte_identical"]
        )
        self.assertEqual(normalized["archive_bytes"], 17_463_573)
        self.assertEqual(
            normalized["archive_sha256"],
            (
                "7a0ed887eec767590393f8994229f97b"
                "2a0de04b9d41bc7e3cdb8addaf366fbc"
            ),
        )

    def test_binary_and_launcher_identities_are_exact(self):
        variants = self.release["variants"]
        portable = variants["portable_system_qt"]
        expected_binaries = {
            "base/die": (
                25_293_840,
                (
                    "28a28aabeb6e942060e5bf9333b09374"
                    "c96944aed4d5e2c99a8a78fa958be2d3"
                ),
            ),
            "base/diec": (
                8_248_008,
                (
                    "da1fab49f7ba5970d1fc1c7fe3d4f380c"
                    "f5e8775dd8097207e7b3c30f08236cf"
                ),
            ),
            "base/diel": (
                7_009_064,
                (
                    "69facb4d8de1b61856ed749f469c2956"
                    "623e6c6f9663c1b66be43470de4253da"
                ),
            ),
        }
        for path, (size, digest) in expected_binaries.items():
            record = portable["inventory"]["binaries"][path]
            self.assertEqual(record["bytes"], size)
            self.assertEqual(record["sha256"], digest)
            self.assertEqual(record["mode"], 0o755)
        for name, record in portable["launchers"].items():
            self.assertEqual(record["path"], f"{name}.sh")
            self.assertEqual(record["mode"], 0o755)
            self.assertEqual(
                record["sha256"],
                hashlib.sha256(
                    MODULE.portable_launcher(name)
                ).hexdigest(),
            )

    def test_report_and_documents_preserve_replay_boundaries(self):
        raw = self.report_raw.decode("utf-8")
        for text in ("I:\\\\", "die-release-tree-", "<STAGE>"):
            self.assertNotIn(text, raw)
        document = DOCUMENT_PATH.read_text(encoding="utf-8")
        for text in (
            "2,640",
            "38,920,508",
            "2,476",
            "52,751,519",
            "144 files",
            "76,847 bytes",
            "original_scripts_executed_end_to_end=false",
            "final_appimage_available=false",
            "compressed_portable_archive_generated=true",
            "portable_archive_byte_reproducible=false",
            "normalized_portable_archive_control_generated=true",
            (
                "normalized_portable_archive_control_"
                "byte_reproducible=true"
            ),
        ):
            self.assertIn(text, document)
        for path in (INDEX_PATH, GATE_PATH, GATE_DATA_PATH):
            self.assertIn(
                "linux-release-trees",
                path.read_text(encoding="utf-8"),
            )
        self.assertIn(
            "linux-release-trees.md",
            RISK_PATH.read_text(encoding="utf-8"),
        )
        self.assertIn(
            "linux-release-trees.md",
            TESTING_PATH.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = (
    ROOT / "tools" / "upstream" / "audit_linux_cmake_install.py"
)
DOCKERFILE_PATH = (
    ROOT / "tools" / "upstream" / "Dockerfile.upstream-install-qt5"
)
REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "linux-cmake-install-tree.json"
)
DOCUMENT_PATH = (
    ROOT / "docs" / "research" / "linux-cmake-install-tree.md"
)
INDEX_PATH = ROOT / "docs" / "research" / "README.md"
GATE_PATH = ROOT / "docs" / "design" / "phase-0-gate-review.md"
GATE_DATA_PATH = (
    ROOT / "docs" / "design" / "data" / "phase-0-gate-review.json"
)
TESTING_PATH = ROOT / "docs" / "design" / "testing.md"
RISK_PATH = ROOT / "docs" / "design" / "risks.md"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MODULE = load_module("audit_linux_cmake_install_for_test", TOOL_PATH)


class LinuxCmakeInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report_raw = REPORT_PATH.read_bytes()
        cls.report = json.loads(cls.report_raw)

    def test_helpers_are_deterministic_and_fail_closed(self):
        self.assertEqual(
            MODULE.route("usr/lib/die/db/read"),
            "usr/lib/die",
        )
        self.assertEqual(
            MODULE.route("usr/share/doc/project/LICENSE"),
            "usr/share/doc",
        )
        values = [{"path": f"p{index}"} for index in range(25)]
        bounded = MODULE.bounded_list(values)
        self.assertEqual(bounded["count"], 25)
        self.assertEqual(bounded["sample"], values[:20])
        self.assertTrue(bounded["sample_truncated"])
        self.assertEqual(
            bounded["entries_sha256"],
            hashlib.sha256(MODULE.canonical_json(values)).hexdigest(),
        )
        records = [
            {
                "path": "b",
                "bytes": 1,
                "sha256": hashlib.sha256(b"x").hexdigest(),
                "mode": 0o644,
            }
        ]
        changed = [dict(records[0], mode=0o755)]
        self.assertNotEqual(
            MODULE.tree_sha256(records),
            MODULE.tree_sha256(changed),
        )

    def test_candidate_index_ignores_git_and_binds_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            (root / "nested" / "same.bin").write_bytes(b"abc")
            (root / ".git").mkdir()
            (root / ".git" / "ignored.bin").write_bytes(b"abc")
            index = MODULE.candidate_index(root, {3})
        self.assertEqual(
            index,
            {
                (
                    3,
                    hashlib.sha256(b"abc").hexdigest(),
                ): ["nested/same.bin"]
            },
        )

    def test_dockerfile_is_pinned_and_keeps_build_cache_independent(self):
        text = DOCKERFILE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "ARG BASE_IMAGE=die-rust/upstream-oracle-cmake:74eaf505"
            "@sha256:466102628c3a94b7ab1048f0c24261b1920e61a"
            "40029b128763cf79370255040",
            text,
        )
        self.assertLess(
            text.index("RUN set -eux"),
            text.index("COPY upstream/audit_linux_cmake_install.py"),
        )
        for path in (
            "/opt/die-build/src/gui/die",
            "/opt/die-build/src/console/diec",
            "/opt/die-build/src/lite/diel",
        ):
            self.assertIn(f"test -x {path}", text)
        self.assertIn(MODULE.UPSTREAM_COMMIT, text)

    def test_report_binds_generator_images_dockerfile_and_priors(self):
        report = self.report
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(
            report["generator"],
            "tools/upstream/audit_linux_cmake_install.py",
        )
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(TOOL_PATH.read_bytes()).hexdigest(),
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
            report["environment"]["full_image"]["revision"],
            MODULE.UPSTREAM_COMMIT,
        )
        self.assertEqual(
            report["upstream_commit"], MODULE.UPSTREAM_COMMIT
        )
        self.assertEqual(
            set(report["prior_reports"]), set(MODULE.PRIOR_REPORTS)
        )
        for name, relative in MODULE.PRIOR_REPORTS.items():
            self.assertEqual(
                report["prior_reports"][name],
                {
                    "path": relative,
                    "sha256": hashlib.sha256(
                        (ROOT / relative).read_bytes()
                    ).hexdigest(),
                },
            )

    def test_all_relationships_and_scope_are_fail_closed(self):
        self.assertTrue(all(self.report["relationships"].values()))
        scope = self.report["scope"]
        self.assertEqual(scope["platform"], "Linux x86_64")
        self.assertEqual(scope["qt"], "5")
        self.assertEqual(
            scope["kind"],
            "cmake-install-staging-tree-not-compressed-package",
        )
        self.assertFalse(scope["legal_review_complete"])
        self.assertFalse(scope["release_approved"])
        self.assertFalse(
            scope["image_rebuild_reproducibility_verified"]
        )
        limitations = "\n".join(self.report["limitations"])
        for value in (
            "AppImage",
            "system dynamic libraries",
            "GUI",
            "reproducibility is not claimed",
        ):
            self.assertIn(value, limitations)

    def test_cli_only_install_fails_after_a_nonempty_partial_copy(self):
        attempt = self.report["cli_only_install_attempt"]
        self.assertEqual(attempt["return_code"], 1)
        self.assertEqual(attempt["missing_path"], "src/gui/die")
        self.assertTrue(attempt["copied_partial_tree_before_failure"])
        self.assertEqual(
            attempt["partial_tree"],
            {"bytes": 11_178_908, "file_count": 2434},
        )
        self.assertEqual(attempt["stdout_bytes"], 14)
        self.assertEqual(attempt["stderr_bytes"], 300)
        self.assertEqual(
            attempt["stderr_sha256"],
            (
                "c6ba054d5af6193e336ab477fd520a28c"
                "5b79ad7ac7ef40f5f98d82e16ecfa64"
            ),
        )

    def test_inventory_identity_routes_and_origins_are_exact(self):
        inventory = self.report["full_install"]["inventory"]
        self.assertEqual(inventory["file_count"], 4916)
        self.assertEqual(inventory["bytes"], 60_881_050)
        self.assertEqual(
            inventory["tree_sha256"],
            (
                "c5860284e27d6048f69f065d494ac7e9"
                "19da263a8be43833a755df2d6e8806b4"
            ),
        )
        self.assertEqual(
            inventory["records_sha256"],
            (
                "b89d8ac4d6f901ec5bf91d5be1e07bc"
                "8f18aa363a4a1f8ca11850ca60ddd4906"
            ),
        )
        self.assertEqual(
            inventory["usr_bin_paths"],
            ["usr/bin/die", "usr/bin/diec", "usr/bin/diel"],
        )
        self.assertEqual(inventory["symlinks"]["count"], 0)
        self.assertEqual(inventory["unmatched_origins"]["count"], 0)
        self.assertEqual(
            inventory["origin_summary"],
            [
                {
                    "bytes": 40_554_609,
                    "file_count": 26,
                    "kind": "build",
                },
                {
                    "bytes": 20_326_441,
                    "file_count": 4890,
                    "kind": "source",
                },
            ],
        )
        self.assertEqual(
            {
                item["route"]: (
                    item["file_count"],
                    item["bytes"],
                )
                for item in inventory["route_summary"]
            },
            {
                "usr/bin": (3, 40_550_912),
                "usr/lang": (22, 3430),
                "usr/lib/DetectItEasy": (2412, 11_175_478),
                "usr/lib/die": (2469, 9_114_843),
                "usr/share/applications": (1, 267),
                "usr/share/doc": (2, 2114),
                "usr/share/icons": (6, 31_561),
                "usr/share/metainfo": (1, 2445),
            },
        )

    def test_manifest_binaries_rules_and_duplicates_are_exact(self):
        full = self.report["full_install"]
        self.assertEqual(
            full["install"]["components"],
            {
                "components": ["Unspecified"],
                "script_count": 16,
                "scripts_sha256": (
                    "39fffae274be48257910e165c988a3ff"
                    "30a485079c1f29137346a6feb066509d"
                ),
            },
        )
        manifest = full["install"]["manifest"]
        self.assertEqual(manifest["entry_count"], 7364)
        self.assertEqual(manifest["unique_path_count"], 4916)
        self.assertEqual(manifest["duplicate_entry_count"], 2448)
        self.assertEqual(manifest["duplicate_path_count"], 2278)
        self.assertEqual(
            manifest["normalized_entries_sha256"],
            (
                "87ffdd9ddaa0e6b19085628505fc8f63"
                "cdbbcbf6b96469bad69e1ef5dcfdcfa9"
            ),
        )
        self.assertEqual(
            manifest["unique_paths_sha256"],
            (
                "61f82aaa2813653d93d8faddd8bb4395"
                "90d825ad88ce71eb0f4df4c0efe914bd"
            ),
        )
        self.assertEqual(
            {
                path: (
                    record["bytes"],
                    record["sha256"],
                    record["mode"],
                )
                for path, record in full["binaries"].items()
            },
            {
                "usr/bin/die": (
                    25_293_840,
                    (
                        "28a28aabeb6e942060e5bf9333b09374"
                        "c96944aed4d5e2c99a8a78fa958be2d3"
                    ),
                    0o755,
                ),
                "usr/bin/diec": (
                    8_248_008,
                    MODULE.EXPECTED_CLI_SHA256,
                    0o755,
                ),
                "usr/bin/diel": (
                    7_009_064,
                    (
                        "69facb4d8de1b61856ed749f469c2956"
                        "623e6c6f9663c1b66be43470de4253da"
                    ),
                    0o755,
                ),
            },
        )
        inventory = full["inventory"]
        duplicate = inventory["duplicate_content"]
        self.assertEqual(duplicate["group_count"], 2247)
        self.assertEqual(duplicate["path_count"], 4509)
        self.assertEqual(duplicate["redundant_bytes"], 6_857_345)
        self.assertEqual(
            duplicate["groups_sha256"],
            (
                "3456ce174011a19d60ef9771c4c72cb4"
                "cdc00d703d522c55a1b8a00c98b05282"
            ),
        )
        self.assertEqual(
            [
                (
                    item["name"],
                    item["detect_it_easy"]["file_count"],
                    item["detect_it_easy"]["bytes"],
                    item["detect_it_easy"]["tree_sha256"],
                    item["identical"],
                )
                for item in inventory["mirrored_subtrees"]
            ],
            [
                (
                    "db",
                    2124,
                    2_832_469,
                    (
                        "006c6789e364f2a31c2ab2a18e374c34"
                        "d548c60405f9c4128d1b8ea31aca6a7a"
                    ),
                    True,
                ),
                (
                    "info",
                    118,
                    122_340,
                    (
                        "42db9c7018459af1499ad8da59c61245"
                        "4f9f6056543a96e1df9193ea2afca843"
                    ),
                    True,
                ),
                (
                    "yara_rules",
                    10,
                    3_900_619,
                    (
                        "190872d30fec728e99a3b19056ef86bb"
                        "319ec6d7f17708414c3c66f95932cead"
                    ),
                    True,
                ),
            ],
        )
        self.assertEqual(
            inventory["runtime_rules"],
            {
                "bytes": MODULE.EXPECTED_RUNTIME_RULES["bytes"],
                "combined_tree_sha256": MODULE.EXPECTED_RUNTIME_RULES[
                    "combined_tree_sha256"
                ],
                "file_count": MODULE.EXPECTED_RUNTIME_RULES[
                    "file_count"
                ],
                "trees": [
                    {
                        "bytes": 2_832_469,
                        "file_count": 2124,
                        "path": "db",
                        "tree_sha256": (
                            "8000138ce96a6a892aaa3cba8dee6096"
                            "0694c42dcfa24b3787f02c25858f1650"
                        ),
                    },
                    {
                        "bytes": 76_651,
                        "file_count": 142,
                        "path": "db_extra",
                        "tree_sha256": (
                            "77c4e0da796baa9a71ec1a699a37e61"
                            "ed73783c0d3dc5d49044185dc80a38ec1"
                        ),
                    },
                    {
                        "bytes": 196,
                        "file_count": 2,
                        "path": "db_custom",
                        "tree_sha256": (
                            "36c10cd4d87826c78f07a0c801c1ae3"
                            "74f4b6364936056d44a045e9150ba5815"
                        ),
                    },
                ],
            },
        )
        self.assertEqual(
            inventory["license_candidate_paths"],
            ["usr/share/doc/DetectItEasy/detect-it-easy/LICENSE"],
        )

    def test_report_and_documents_preserve_scope_and_exact_values(self):
        raw = self.report_raw.decode("utf-8")
        for value in (
            "I:\\\\",
            "/opt/die-source",
            "/opt/die-build",
            "die-install-",
        ):
            self.assertNotIn(value, raw)
        document = DOCUMENT_PATH.read_text(encoding="utf-8")
        for value in (
            "4,916",
            "60,881,050",
            "2,448",
            "6,857,345",
            "legal_review_complete=false",
            "release_approved=false",
            "cmake-install-staging-tree-not-compressed-package",
        ):
            self.assertIn(value, document)
        for path in (INDEX_PATH, GATE_PATH, GATE_DATA_PATH):
            self.assertIn(
                "linux-cmake-install-tree",
                path.read_text(encoding="utf-8"),
            )
        self.assertIn(
            "linux-cmake-install-tree.md",
            TESTING_PATH.read_text(encoding="utf-8"),
        )
        self.assertIn(
            "4,916",
            RISK_PATH.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()

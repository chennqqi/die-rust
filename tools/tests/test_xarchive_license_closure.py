import collections
import hashlib
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
REPORT_PATH = (
    ROOT / "docs/research/data/xarchive-license-closure-linux.json"
)
TOOL_PATH = (
    ROOT / "tools/upstream/audit_xarchive_license_closure.py"
)
LOCK_PATH = ROOT / "upstream/components.lock.toml"


class XArchiveLicenseClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_report_is_bound_to_generator_lock_and_image(self):
        self.assertEqual(self.report["schema_version"], 1)
        self.assertEqual(
            self.report["generator"],
            "tools/upstream/audit_xarchive_license_closure.py",
        )
        self.assertEqual(
            self.report["generator_sha256"],
            hashlib.sha256(TOOL_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            self.report["component_lock"]["sha256"],
            hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            self.report["upstream_commit"],
            "74eaf505c250ab47e709024e9dc41657cd8f2254",
        )
        self.assertEqual(
            self.report["xarchive_commit"],
            "0fcd4e8d3e9933baac3b12246d82ac026557ffd0",
        )
        self.assertEqual(
            self.report["source_image"]["revision"],
            self.report["upstream_commit"],
        )

    def test_link_and_compile_closure_is_exact(self):
        self.assertTrue(all(self.report["relationships"].values()))
        self.assertEqual(self.report["compile_source_count"], 106)
        self.assertEqual(len(self.report["compile_units"]), 106)
        self.assertEqual(
            len({unit["source"] for unit in self.report["compile_units"]}),
            106,
        )
        counts = collections.Counter(
            unit["linkage"] for unit in self.report["compile_units"]
        )
        self.assertEqual(
            counts,
            {
                "die-direct": 84,
                "../XArchive/3rdparty/bzip2/libbzip2.a": 8,
                "../XArchive/3rdparty/lzma/liblzma.a": 2,
                "../XArchive/3rdparty/ppmd/libppmd.a": 4,
                "../XArchive/3rdparty/zlib/libzlib.a": 8,
            },
        )

    def test_dependency_closure_and_markers_are_auditable(self):
        self.assertEqual(self.report["closure_file_count"], 217)
        marker_counts = collections.Counter(
            marker
            for record in self.report["files"]
            for marker in record["license_markers"]
        )
        self.assertEqual(
            marker_counts,
            {
                "bzip2-copyright": 12,
                "mit-permission": 167,
                "public-domain": 23,
                "zlib-notice": 9,
            },
        )
        evidence = {
            record["path"]: record["license_markers"]
            for record in self.report["license_evidence_files"]
        }
        self.assertEqual(
            evidence,
            {
                "LICENSE": ["mit-permission"],
                "3rdparty/bzip2/src/LICENSE": [
                    "bsd-redistribution",
                    "bzip2-copyright",
                ],
                "3rdparty/lzma/src/LzmaDec.c": ["public-domain"],
                "3rdparty/ppmd/src/Ppmd7.c": ["public-domain"],
                "3rdparty/zlib/src/zlib.h": ["zlib-notice"],
            },
        )

    def test_unattributed_embedded_origins_remain_explicit(self):
        self.assertEqual(
            self.report["origin_files_without_license_markers"],
            [
                "Algos/brotlideclib.cpp",
                "Algos/zstddeclib.cpp",
            ],
        )


if __name__ == "__main__":
    unittest.main()

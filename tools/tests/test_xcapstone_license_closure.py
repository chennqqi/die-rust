import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = (
    ROOT / "docs/research/data/xcapstone-license-closure-linux.json"
)
TOOL_PATH = (
    ROOT / "tools/upstream/audit_xcapstone_license_closure.py"
)
LOCK_PATH = ROOT / "upstream/components.lock.toml"
SPEC = importlib.util.spec_from_file_location(
    "audit_xcapstone_license_closure",
    TOOL_PATH,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class XCapstoneLicenseClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(
            REPORT_PATH.read_text(encoding="utf-8")
        )

    def test_report_is_bound_to_generator_lock_component_and_image(self):
        report = self.report
        lock = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(
            report["generator"],
            "tools/upstream/audit_xcapstone_license_closure.py",
        )
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(TOOL_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["component_lock"]["sha256"],
            hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["upstream_commit"],
            MODULE.UPSTREAM_COMMIT,
        )
        self.assertEqual(
            report["xcapstone_commit"],
            lock["gitlink"]["XCapstone"]["commit"],
        )
        self.assertEqual(
            report["source_image"]["revision"],
            MODULE.UPSTREAM_COMMIT,
        )
        self.assertEqual(report["source_image"]["network"], "none")
        self.assertEqual(
            report["source_image"]["repository_mount"],
            "readonly",
        )

    def test_final_elf_contribution_is_member_exact(self):
        report = self.report
        self.assertTrue(all(report["relationships"].values()))
        self.assertEqual(report["build"]["archive_member_count"], 11)
        self.assertEqual(
            report["build"]["extracted_archive_member_count"],
            10,
        )
        self.assertEqual(
            report["build"]["unextracted_archive_members"],
            ["MCInstrDesc.c.o"],
        )
        members = report["archive_members"]
        self.assertEqual(
            {member["member"] for member in members},
            MODULE.EXPECTED_ARCHIVE_MEMBERS,
        )
        extracted = [
            member
            for member in members
            if member["extracted_into_final_elf"]
        ]
        unextracted = [
            member
            for member in members
            if not member["extracted_into_final_elf"]
        ]
        self.assertEqual(len(extracted), 10)
        self.assertEqual(
            [member["member"] for member in unextracted],
            ["MCInstrDesc.c.o"],
        )
        self.assertTrue(
            all(member["final_elf_symbol_witnesses"] for member in extracted)
        )
        self.assertEqual(
            unextracted[0]["final_elf_symbol_witnesses"],
            [],
        )

    def test_compile_and_dependency_closure_is_exact(self):
        report = self.report
        self.assertEqual(report["compile_source_count"], 11)
        self.assertEqual(report["closure_file_count"], 71)
        self.assertEqual(len(report["compile_units"]), 11)
        self.assertEqual(
            len({unit["source"] for unit in report["compile_units"]}),
            11,
        )
        linkage_counts = collections.Counter(
            unit["linkage"] for unit in report["compile_units"]
        )
        self.assertEqual(
            linkage_counts,
            {
                "die-direct": 1,
                MODULE.ARCHIVE_TOKEN: 10,
            },
        )
        files = report["files"]
        self.assertEqual(len(files), 71)
        self.assertEqual(len({record["path"] for record in files}), 71)
        for record in files:
            self.assertRegex(record["sha256"], r"^[0-9a-f]{64}$")

    def test_license_markers_and_retained_texts_are_exact(self):
        self.assertEqual(
            self.report["marker_counts"],
            {
                "bsd-redistribution": 0,
                "capstone-origin": 67,
                "llvm-ncsa-attribution": 11,
                "mit-permission": 2,
            },
        )
        evidence = {
            record["path"]: {
                "sha256": record["sha256"],
                "markers": record["license_markers"],
            }
            for record in self.report["license_evidence_files"]
        }
        self.assertEqual(
            evidence,
            {
                "LICENSE": {
                    "sha256": (
                        "abdeb212f229d2b93a5c315763df4d720"
                        "1c7d74f580ad9dc77d77dec7cbc6c69"
                    ),
                    "markers": ["mit-permission"],
                },
                "3rdparty/Capstone/src/LICENSE.TXT": {
                    "sha256": (
                        "404bd0cb0137ffb797258f844f53e527"
                        "3f9b6d5781a1a359a2880411f49a4f30"
                    ),
                    "markers": [
                        "bsd-redistribution",
                        "capstone-origin",
                    ],
                },
                "3rdparty/Capstone/src/LICENSE_LLVM.TXT": {
                    "sha256": (
                        "d4cc2005623614495b43508021c85d1d2"
                        "ff21d8766287605ac41fee47f499bf9"
                    ),
                    "markers": [
                        "llvm-ncsa-attribution",
                        "mit-permission",
                    ],
                },
            },
        )
        self.assertEqual(len(self.report["distribution_requirements"]), 3)

    def test_report_has_no_container_or_workspace_paths(self):
        serialized = REPORT_PATH.read_text(encoding="utf-8")
        self.assertNotIn("/opt/die-source", serialized)
        self.assertNotIn("/opt/die-build", serialized)
        self.assertNotIn(str(ROOT), serialized)

    def test_dependency_and_nm_parsers_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.o.d"
            path.write_text(
                "sample.o: /src/sample.c \\\n /src/sample.h\n",
                encoding="utf-8",
            )
            self.assertEqual(
                MODULE.parse_dependency_file(path),
                [
                    Path("/src/sample.c"),
                    Path("/src/sample.h"),
                ],
            )
        self.assertEqual(
            MODULE.parse_nm_defined_symbols(
                "00000000 T alpha\n"
                "         U external\n"
                "00000010 t local_symbol\n"
            ),
            {"alpha"},
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.o.d"
            path.write_text("no dependency separator")
            with self.assertRaisesRegex(
                ValueError,
                "invalid dependency file",
            ):
                MODULE.parse_dependency_file(path)


if __name__ == "__main__":
    unittest.main()

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSPECTOR_PATH = (
    ROOT / "tools" / "benchmark" / "inspect_upstream_deployment.py"
)
PROBE_PATH = (
    ROOT / "tools" / "benchmark" / "probe_upstream_deployment_size.py"
)
REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "upstream-deployment-size-linux-qt5.json"
)
RULE_REPORT_PATH = (
    ROOT
    / "docs"
    / "research"
    / "data"
    / "runtime-rule-assets-license.json"
)
DOCKERFILE_PATH = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.upstream-size-qt5"
)
DOCUMENT_PATH = (
    ROOT / "docs" / "research" / "upstream-deployment-size.md"
)
GATE_PATH = ROOT / "docs" / "design" / "phase-0-gate-review.md"
TESTING_PATH = ROOT / "docs" / "design" / "testing.md"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


INSPECTOR = load_module(
    "inspect_upstream_deployment_for_test",
    INSPECTOR_PATH,
)
PROBE = load_module(
    "probe_upstream_deployment_size_for_test",
    PROBE_PATH,
)


class UpstreamDeploymentSizeTests(unittest.TestCase):
    def test_parse_ldd_excludes_vdso_and_retains_loader(self):
        raw = b"""\
\tlinux-vdso.so.1 (0x00007ffc00000000)
\tlibQt5Core.so.5 => /lib/libQt5Core.so.5 (0x00007f0000000000)
\t/lib64/ld-linux-x86-64.so.2 (0x00007f0000001000)
"""
        self.assertEqual(
            INSPECTOR.parse_ldd(raw),
            [
                {
                    "requested_name": "libQt5Core.so.5",
                    "resolved_path": "/lib/libQt5Core.so.5",
                },
                {
                    "requested_name": "ld-linux-x86-64.so.2",
                    "resolved_path": "/lib64/ld-linux-x86-64.so.2",
                },
            ],
        )

    def test_parse_ldd_rejects_missing_and_unknown_lines(self):
        with self.assertRaisesRegex(
            INSPECTOR.InspectionError,
            "unresolved dependency",
        ):
            INSPECTOR.parse_ldd(b"libmissing.so => not found\n")
        with self.assertRaisesRegex(
            INSPECTOR.InspectionError,
            "unsupported ldd output",
        ):
            INSPECTOR.parse_ldd(b"surprising output\n")

    def test_rule_digest_matches_runtime_asset_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = []
            for tree, name, content in (
                ("db", "a.sg", b"a"),
                ("db_extra", "b.sg", b"bc"),
                ("db_custom", "empty.txt", b""),
            ):
                path = root / tree / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                files.append(path)
            expected = hashlib.sha256()
            for path in files:
                relative = path.relative_to(root).as_posix().encode()
                data = path.read_bytes()
                expected.update(relative)
                expected.update(b"\0")
                expected.update(len(data).to_bytes(8, "big"))
                expected.update(data)
                expected.update(hashlib.sha256(data).digest())
            inventory = INSPECTOR.rule_inventory(root)
            self.assertEqual(
                inventory["combined_tree_sha256"],
                expected.hexdigest(),
            )
            self.assertEqual(inventory["file_count"], 3)
            self.assertEqual(inventory["bytes"], 3)

    def test_dockerfile_derives_from_fixed_benchmark_image(self):
        text = DOCKERFILE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "ARG BASE_IMAGE=die-rust/upstream-benchmark-qt5:74eaf505"
            "@sha256:a5b33708eb148591d127041b6a54d05d68f8dd24"
            "bea7855e95ea88715d0bf8c5",
            text,
        )
        self.assertIn(
            "COPY benchmark/inspect_upstream_deployment.py",
            text,
        )
        self.assertIn(PROBE.EXPECTED_REVISION, text)

    def test_committed_report_is_strictly_verified(self):
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        self.assertTrue(report["passed"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(PROBE.evaluate_report(report), [])
        self.assertFalse(report["targets_frozen"])

    def test_report_binds_analyzer_rules_and_exact_totals(self):
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        rules = json.loads(RULE_REPORT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            report["analyzer"]["repository_sha256"],
            hashlib.sha256(INSPECTOR_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["rule_asset_report"]["sha256"],
            hashlib.sha256(RULE_REPORT_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["measurement"]["rules"]["combined_tree_sha256"],
            rules["identity"]["combined_tree_sha256"],
        )
        measurement = report["measurement"]
        dependency_bytes = sum(
            item["bytes"]
            for item in measurement["dynamic_dependencies"][
                "dependencies"
            ]
        )
        self.assertEqual(
            measurement["totals"]["full_closure_and_rules_bytes"],
            measurement["binary"]["bytes"]
            + dependency_bytes
            + measurement["rules"]["bytes"],
        )
        self.assertEqual(
            measurement["dynamic_dependencies"]["closure_sha256"],
            PROBE.EXPECTED_DEPENDENCY_CLOSURE_SHA256,
        )

    def test_report_and_documents_preserve_scope_and_exact_values(self):
        raw_report = REPORT_PATH.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\", raw_report)
        document = DOCUMENT_PATH.read_text(encoding="utf-8")
        for value in (
            "8,248,008",
            "2,909,316",
            "54,100,576",
            "11,157,324",
            "65,257,900",
            "targets_frozen=false",
            "4d8c83178ae3a6ddc96e5bfc96fb4324f0ef1d16372b7e74ef9c2d92b958bef5",
            "93d09f465d005b61309fb99ba6f6546c7333dce75b7d7f5e1bd0e080a7216310",
            PROBE.EXPECTED_DEPENDENCY_CLOSURE_SHA256,
        ):
            self.assertIn(value, document)
        self.assertIn(
            "upstream-deployment-size.md",
            GATE_PATH.read_text(encoding="utf-8"),
        )
        self.assertIn(
            "upstream-deployment-size.md",
            TESTING_PATH.read_text(encoding="utf-8"),
        )

    def test_verifier_rejects_measurement_and_rule_identity_tampering(self):
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        changed = copy.deepcopy(report)
        changed["measurement"]["binary"]["bytes"] += 1
        self.assertIn(
            "measurement_sha256",
            PROBE.evaluate_report(changed),
        )
        changed = copy.deepcopy(report)
        changed["rule_asset_identity"]["commit"] = "0" * 40
        self.assertIn(
            "rule_asset_identity.commit",
            PROBE.evaluate_report(changed),
        )


if __name__ == "__main__":
    unittest.main()

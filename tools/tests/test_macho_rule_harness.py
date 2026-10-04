import copy
import hashlib
import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[2]


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


GENERATOR = load_module(
    "generate_macho_rule_fixture",
    ROOT / "tools" / "corpus" / "generate_macho_rule_fixture.py",
)
PROBE = load_module(
    "probe_macho_rule_harness",
    ROOT / "tools" / "upstream" / "probe_macho_rule_harness.py",
)
FIXTURE_PATH = ROOT / "docs" / "research" / "data" / "macho-rule-fixture.json"
BASELINE_PATH = ROOT / "docs" / "research" / "data" / "macho-rule-qt5.json"
RULE_PATH = (
    ROOT
    / "upstream"
    / "Detect-It-Easy"
    / "db"
    / "MACH"
    / "compiler_Rust.4.sg"
)


class MachoRuleHarnessTests(unittest.TestCase):
    def test_checked_in_fixture_is_exact_generator_output(self):
        checked_in = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(checked_in, GENERATOR.manifest())
        self.assertEqual(
            [case["id"] for case in checked_in["cases"]],
            PROBE.EXPECTED_IDS,
        )
        self.assertEqual(
            [len(bytes.fromhex(case["data_hex"])) for case in checked_in["cases"]],
            [0x200, 0x200, 0x200, 0x100],
        )

    def test_rule_is_byte_identical_and_hash_pinned(self):
        self.assertEqual(
            hashlib.sha256(RULE_PATH.read_bytes()).hexdigest(),
            GENERATOR.RULE_SHA256,
        )
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(fixture["rule"]["sha256"], GENERATOR.RULE_SHA256)
        self.assertEqual(
            fixture["rule"]["preservation"],
            "loaded byte-for-byte from the pinned rules subtree",
        )

    def test_probe_accepts_checked_in_qt5_oracle(self):
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            PROBE.validate(fixture, baseline, GENERATOR.UPSTREAM_COMMIT),
            [],
        )

    def test_probe_rejects_detection_input_and_entry_point_drift(self):
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        drifted = copy.deepcopy(baseline)
        drifted["cases"][0]["detections"] = []
        drifted["cases"][1]["data_sha256"] = "0" * 64
        drifted["cases"][3]["entry_point_offset"] = -1
        failures = PROBE.validate(
            fixture,
            drifted,
            GENERATOR.UPSTREAM_COMMIT,
        )
        self.assertIn(
            "rust_macho64_x86_64_entry_point_match.detections",
            failures,
        )
        self.assertIn(
            "rust_macho64_arm64_entry_point_match.data_sha256",
            failures,
        )
        self.assertIn(
            "rust_macho64_x86_64_entry_point_truncated.entry_point_offset",
            failures,
        )

    def test_harness_container_is_pinned_and_network_independent(self):
        dockerfile = (
            ROOT
            / "tools"
            / "upstream"
            / "Dockerfile.macho-rule-harness-qt5"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "die-rust/upstream-oracle-cmake:74eaf505",
            dockerfile,
        )
        self.assertNotIn("apt-get", dockerfile)
        self.assertNotIn("git clone", dockerfile)


if __name__ == "__main__":
    unittest.main()

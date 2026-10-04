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
    "generate_dex_rule_fixture",
    ROOT / "tools" / "corpus" / "generate_dex_rule_fixture.py",
)
PROBE = load_module(
    "probe_dex_rule_harness",
    ROOT / "tools" / "upstream" / "probe_dex_rule_harness.py",
)
FIXTURE_PATH = ROOT / "docs" / "research" / "data" / "dex-rule-fixture.json"
BASELINE_PATH = ROOT / "docs" / "research" / "data" / "dex-rule-qt5.json"
RULE_PATH = (
    ROOT
    / "upstream"
    / "Detect-It-Easy"
    / "db"
    / "DEX"
    / "protector_QDBH.2.sg"
)


class DexRuleHarnessTests(unittest.TestCase):
    def test_checked_in_fixture_is_exact_generator_output(self):
        checked_in = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(checked_in, GENERATOR.manifest())
        self.assertEqual(
            [case["id"] for case in checked_in["cases"]],
            PROBE.EXPECTED_IDS,
        )
        self.assertEqual(
            [len(bytes.fromhex(case["data_hex"])) for case in checked_in["cases"]],
            [0xAF, 0xAF, 0xA8],
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

    def test_probe_rejects_parser_string_and_detection_drift(self):
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        drifted = copy.deepcopy(baseline)
        drifted["cases"][0]["detections"] = []
        drifted["cases"][1]["parsed_strings"] = []
        drifted["cases"][2]["native_qdbh_present"] = True
        failures = PROBE.validate(
            fixture,
            drifted,
            GENERATOR.UPSTREAM_COMMIT,
        )
        self.assertIn("qdbh_string_match.detections", failures)
        self.assertIn("qdbh_string_mismatch.parsed_strings", failures)
        self.assertIn(
            "qdbh_string_data_truncated.native_qdbh_present",
            failures,
        )

    def test_harness_container_is_pinned_and_network_independent(self):
        dockerfile = (
            ROOT
            / "tools"
            / "upstream"
            / "Dockerfile.dex-rule-harness-qt5"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "die-rust/upstream-oracle-cmake:74eaf505",
            dockerfile,
        )
        self.assertNotIn("apt-get", dockerfile)
        self.assertNotIn("git clone", dockerfile)


if __name__ == "__main__":
    unittest.main()

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
    "generate_pdf_rule_fixture",
    ROOT / "tools" / "corpus" / "generate_pdf_rule_fixture.py",
)
PROBE = load_module(
    "probe_pdf_rule_harness",
    ROOT / "tools" / "upstream" / "probe_pdf_rule_harness.py",
)
FIXTURE_PATH = ROOT / "docs" / "research" / "data" / "pdf-rule-fixture.json"
BASELINE_PATH = ROOT / "docs" / "research" / "data" / "pdf-rule-qt5.json"
RULE_PATH = (
    ROOT
    / "upstream"
    / "Detect-It-Easy"
    / "db"
    / "PDF"
    / "format_Tools.2.sg"
)


class PdfRuleHarnessTests(unittest.TestCase):
    def test_checked_in_fixture_is_exact_generator_output(self):
        checked_in = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(checked_in, GENERATOR.manifest())
        self.assertEqual(
            [case["id"] for case in checked_in["cases"]],
            PROBE.EXPECTED_IDS,
        )
        lengths = [
            len(bytes.fromhex(case["data_hex"])) for case in checked_in["cases"]
        ]
        self.assertEqual(lengths, [152, 82, 69])

    def test_rule_is_byte_identical_and_hash_pinned(self):
        self.assertEqual(
            hashlib.sha256(RULE_PATH.read_bytes()).hexdigest(),
            GENERATOR.RULE_SHA256,
        )
        self.assertEqual(RULE_PATH.stat().st_size, 557)
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

    def test_probe_rejects_token_value_and_detection_drift(self):
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        drifted = copy.deepcopy(baseline)
        drifted["cases"][0]["native_creator_values"] = ["Tool A"]
        drifted["cases"][1]["object_parts"][0]["tokens"][2] = "(Tool)"
        drifted["cases"][2]["detections"] = [
            ["tool", "Creator", "fffe", "Hidden"]
        ]
        failures = PROBE.validate(
            fixture,
            drifted,
            GENERATOR.UPSTREAM_COMMIT,
        )
        self.assertIn(
            "tools_string_values.native_creator_values",
            failures,
        )
        self.assertIn("tools_non_string_values.object_parts", failures)
        self.assertIn("tools_missing_endobj.detections", failures)

    def test_harness_container_is_pinned_and_network_independent(self):
        dockerfile = (
            ROOT
            / "tools"
            / "upstream"
            / "Dockerfile.pdf-rule-harness-qt5"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "die-rust/upstream-oracle-cmake:74eaf505",
            dockerfile,
        )
        self.assertNotIn("apt-get", dockerfile)
        self.assertNotIn("git clone", dockerfile)


if __name__ == "__main__":
    unittest.main()

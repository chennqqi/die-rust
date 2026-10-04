import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/upstream/probe_host_api_arity.py"
SPEC = importlib.util.spec_from_file_location("probe_host_api_arity", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class HostApiArityProbeTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "docs/research/data/host-api-arity-qt5.json"
        self.report = json.loads(path.read_text(encoding="utf-8"))
        self.observation = self.report["observation"]
        qt6_path = ROOT / "docs/research/data/host-api-arity-qt6.json"
        self.qt6_report = json.loads(qt6_path.read_text(encoding="utf-8"))
        self.qt6_observation = self.qt6_report["observation"]

    def test_committed_observation_satisfies_oracle_contract(self):
        MODULE.validate_observation(self.observation)
        MODULE.validate_observation(self.qt6_observation, "qt6")

    def test_committed_source_identities_are_current(self):
        for report in (self.report, self.qt6_report):
            for relative, identity in report["sources"].items():
                data = (ROOT / relative).read_bytes()
                self.assertEqual(len(data), identity["bytes"])
                self.assertEqual(MODULE.sha256(data), identity["sha256"])

    def test_runtime_specific_qint64_conversion_is_exact(self):
        qt5 = self.observation["binary"]
        qt6 = self.qt6_observation["binary"]
        for key in ("u8_string", "u8_boolean"):
            self.assertEqual(qt5[key]["number"], 65)
            self.assertEqual(qt6[key]["number"], 65)
        for key in ("u8_null", "u8_undefined"):
            self.assertEqual(qt5[key]["number"], 65)
            self.assertEqual(qt6[key]["error_name"], "TypeError")
            self.assertIn(
                "incompatible arguments",
                qt6[key]["error_message"],
            )

    def test_required_and_default_arity_behavior_is_exact(self):
        qt5 = self.observation["binary"]
        qt6 = self.qt6_observation["binary"]
        self.assertEqual(qt5["sa_missing"]["string"], "ABC")
        self.assertEqual(qt6["sa_missing"]["string"], "ABC")
        for key in ("sc_default_one", "sc_default_two"):
            self.assertEqual(qt5[key]["string"], "")
            self.assertEqual(qt6[key]["string"], "")
        self.assertEqual(qt5["u8_missing"]["error_name"], "SyntaxError")
        self.assertEqual(qt6["u8_missing"]["error_name"], "Error")

    def test_u24_and_unsigned_shift_match_both_runtimes(self):
        for observation in (self.observation, self.qt6_observation):
            binary = observation["binary"]
            self.assertEqual(
                binary["u24_little_endian"]["number"],
                0x563412,
            )
            for key in (
                "u24_big_endian",
                "read_uint24_big_endian",
                "u24_extra",
            ):
                self.assertEqual(binary[key]["number"], 0x123456)

            util = observation["util"]
            self.assertEqual(util["shru64_zero"]["number"], 0xFFFFFFFF)
            self.assertEqual(util["shru64_four"]["number"], 0x0FFFFFFF)
            self.assertEqual(util["shru64_thirty_two"]["number"], 0)
            self.assertEqual(
                util["shru64_extra"]["number"],
                0x0FFFFFFF,
            )

    def test_qt6_extra_arguments_emit_exact_stderr(self):
        self.assertEqual(
            self.qt6_report["stderr"],
            {
                "bytes": len(MODULE.QT6_STDERR),
                "sha256": MODULE.sha256(MODULE.QT6_STDERR),
                "utf8_lines": (
                    MODULE.QT6_STDERR.decode("utf-8").splitlines()
                ),
            },
        )
        self.assertEqual(self.report["stderr"]["bytes"], 0)

    def test_qt6_object_address_is_explicitly_normalized(self):
        error = self.qt6_observation["pe"][
            "get_ep_signature_call"
        ]
        self.assertIn("PE_Script(<address>)", error["error_message"])
        self.assertNotIn("0x", error["error_message"])

    def test_extra_argument_change_is_rejected(self):
        changed = json.loads(json.dumps(self.observation))
        changed["binary"]["u8_extra"]["number"] = 66
        with self.assertRaisesRegex(ValueError, "extra arguments"):
            MODULE.validate_observation(changed)

    def test_missing_method_alias_is_rejected(self):
        changed = json.loads(json.dumps(self.observation))
        changed["pe"]["get_ep_signature_type_after_init"]["string"] = "function"
        with self.assertRaisesRegex(ValueError, "method type"):
            MODULE.validate_observation(changed)

    def test_parser_rejects_diagnostics(self):
        data = json.dumps(self.observation).encode()
        with self.assertRaisesRegex(ValueError, "stderr"):
            MODULE.parse_observation(data, b"warning", 0)
        with self.assertRaisesRegex(ValueError, "trailing"):
            MODULE.parse_observation(data + b"\nwarning", b"", 0)

    def test_qt6_dockerfile_uses_fixed_qt6_base(self):
        source = (
            ROOT / "tools/upstream/Dockerfile.host-api-arity-harness-qt6"
        ).read_text(encoding="utf-8")
        self.assertIn(
            (
                "ARG BASE_IMAGE="
                "die-rust/upstream-oracle-cmake-qt6:74eaf505"
            ),
            source,
        )
        self.assertIn(
            "Research-only Qt 6 HostApi arity oracle harness",
            source,
        )


if __name__ == "__main__":
    unittest.main()

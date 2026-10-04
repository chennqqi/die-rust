import hashlib
import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).parents[2]
SPIKE = ROOT / "spikes" / "c-static-link"
REFERENCE = (
    ROOT / "docs" / "research" / "data" / "c-static-link.json"
)


class CStaticLinkSpikeTests(unittest.TestCase):
    def setUp(self):
        self.reference = json.loads(REFERENCE.read_text(encoding="utf-8"))

    def test_reference_matches_all_experiment_inputs(self):
        for relative, expected in self.reference["experiment"][
            "hashes"
        ].items():
            with self.subTest(path=relative):
                actual = hashlib.sha256(
                    (SPIKE / relative).read_bytes()
                ).hexdigest()
                self.assertEqual(actual, expected)

    def test_header_constants_match_machine_baseline(self):
        header = (SPIKE / "include" / "die_spike.h").read_text(
            encoding="utf-8"
        )
        expected = {
            "DIE_SPIKE_ABI_VERSION": self.reference["abi"]["version"],
            "DIE_SPIKE_STATUS_OK": self.reference["abi"][
                "status_codes"
            ]["ok"],
            "DIE_SPIKE_STATUS_INVALID_ARGUMENT": self.reference[
                "abi"
            ]["status_codes"]["invalid_argument"],
            "DIE_SPIKE_STATUS_INPUT_TOO_LARGE": self.reference[
                "abi"
            ]["status_codes"]["input_too_large"],
            "DIE_SPIKE_STATUS_PANIC": self.reference["abi"][
                "status_codes"
            ]["panic"],
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                match = re.search(
                    rf"#define {name} UINT32_C\((\d+)\)",
                    header,
                )
                self.assertIsNotNone(match)
                self.assertEqual(int(match.group(1)), value)

        max_input = re.search(
            r"#define DIE_SPIKE_MAX_INPUT_BYTES UINT64_C\((\d+)\)",
            header,
        )
        self.assertIsNotNone(max_input)
        self.assertEqual(
            int(max_input.group(1)),
            self.reference["abi"]["max_input_bytes"],
        )

    def test_exports_exist_in_header_and_rust_source(self):
        header = (SPIKE / "include" / "die_spike.h").read_text(
            encoding="utf-8"
        )
        rust = (SPIKE / "src" / "lib.rs").read_text(encoding="utf-8")
        for symbol in self.reference["abi"]["exports"]:
            with self.subTest(symbol=symbol):
                self.assertIn(symbol, header)
                self.assertIn(f"fn {symbol}", rust)

    def test_three_native_smoke_paths_are_recorded(self):
        windows = self.reference["windows_msvc"]
        linux = self.reference["linux_gnu"]
        self.assertEqual(windows["dynamic_crt"]["smoke_exit_code"], 0)
        self.assertEqual(windows["static_crt"]["smoke_exit_code"], 0)
        self.assertEqual(linux["smoke_exit_code"], 0)
        self.assertTrue(self.reference["fixture"]["panic_contained"])
        self.assertEqual(
            self.reference["fixture"]["lifecycle_iterations"],
            1000,
        )


if __name__ == "__main__":
    unittest.main()

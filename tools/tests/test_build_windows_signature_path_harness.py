from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
BUILDER = (
    ROOT / "tools/upstream/build_windows_signature_path_harness.ps1"
)
HARNESS = ROOT / "tools/upstream/signature_path_harness_main.cpp"


class BuildWindowsSignaturePathHarnessTests(unittest.TestCase):
    def test_builder_is_identity_bound_and_uses_amd64_environment(self):
        text = BUILDER.read_text(encoding="utf-8")
        for expected in (
            "74eaf505c250ab47e709024e9dc41657cd8f2254",
            "c2c17dfa5ea4e078ba31eab55d87430c96622fb6",
            "e8579a6ed0d2536ea14af154bcbeeaaea6967c0c7559a595"
            "fb3fe52206ac635e",
            "e873ad3a689a0628c3037a6440221dcd2e426395edf14ffa6"
            "379612dede26d36",
            "-arch=amd64 -host_arch=amd64",
            "submodule status --recursive",
            "status --porcelain=v1 --untracked-files=no",
            "/alternatename:",
            "?processDetect@DiE_Script@@QEAAX",
            "?processDetect@DiE_Script@@AEAAX",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)

    def test_builder_replaces_only_console_main_contract(self):
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn(
            '$HarnessTarget = "die-signature-path-harness.exe"',
            text,
        )
        self.assertIn(
            '$HarnessObjectName = '
            '"release\\signature_path_harness_main.obj"',
            text,
        )
        self.assertIn(
            '"Makefile.SignaturePath.Release"',
            text,
        )
        self.assertIn(
            '"signature_path_harness_main.cpp"',
            text,
        )
        self.assertNotIn("engine_contract_harness_main", text)

    def test_harness_access_shim_remains_minimal(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertEqual(source.count("#define private public"), 1)
        self.assertEqual(source.count("#undef private"), 1)
        self.assertIn("engine->processDetect(", source)


if __name__ == "__main__":
    unittest.main()

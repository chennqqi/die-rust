import gzip
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest


ROOT = pathlib.Path(__file__).parents[2]
GENERATOR_PATH = (
    ROOT / "tools" / "corpus" / "generate_npm_dispatch_fixture.py"
)
MANIFEST_PATH = (
    ROOT / "docs" / "research" / "data" / "npm-dispatch-fixture.json"
)
SPEC = importlib.util.spec_from_file_location(
    "generate_npm_dispatch_fixture",
    GENERATOR_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class GenerateNpmDispatchFixtureTests(unittest.TestCase):
    def test_generation_matches_committed_manifest_and_is_reproducible(self):
        expected = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as first_dir:
            with tempfile.TemporaryDirectory() as second_dir:
                first = pathlib.Path(first_dir)
                second = pathlib.Path(second_dir)
                self.assertEqual(MODULE.generate(first), expected)
                self.assertEqual(MODULE.generate(second), expected)
                self.assertEqual(
                    (first / "manifest.json").read_bytes(),
                    MANIFEST_PATH.read_bytes(),
                )
                for sample in expected["samples"]:
                    first_data = (first / sample["name"]).read_bytes()
                    second_data = (second / sample["name"]).read_bytes()
                    self.assertEqual(first_data, second_data)
                    self.assertEqual(len(first_data), sample["size"])
                    self.assertEqual(sha256(first_data), sample["sha256"])

    def test_samples_are_valid_deterministic_ustar_gzip_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest = MODULE.generate(root)
            for sample in manifest["samples"]:
                with self.subTest(sample=sample["name"]):
                    data = (root / sample["name"]).read_bytes()
                    self.assertEqual(data[:10], bytes.fromhex(
                        "1f8b08000000000000ff"
                    ))
                    tar_data = gzip.decompress(data)
                    self.assertTrue(tar_data.endswith(bytes(1024)))
                    with tarfile.open(
                        fileobj=io.BytesIO(tar_data),
                        mode="r:",
                    ) as archive:
                        self.assertEqual(
                            archive.getnames(),
                            sample["entries"],
                        )
                        for member in archive.getmembers():
                            self.assertEqual(member.mtime, 0)
                            self.assertEqual(member.uid, 0)
                            self.assertEqual(member.gid, 0)
                            self.assertEqual(member.uname, "die-rust")
                            self.assertEqual(member.gname, "die-rust")

    def test_detector_controls_differ_only_as_declared(self):
        cases = {case["name"]: case for case in MODULE.CASES}
        self.assertEqual(
            {
                name: case["expected_npm"]
                for name, case in cases.items()
            },
            {
                "case-package-json.tgz": False,
                "npm-invalid-json.tgz": True,
                "npm-valid.tgz": True,
                "root-package-json.tgz": False,
            },
        )
        self.assertEqual(
            cases["npm-valid.tgz"]["entries"][0][0],
            "package/package.json",
        )
        self.assertEqual(
            cases["npm-invalid-json.tgz"]["entries"][0][0],
            "package/package.json",
        )
        self.assertEqual(
            cases["root-package-json.tgz"]["entries"][0][0],
            "package.json",
        )
        self.assertEqual(
            cases["case-package-json.tgz"]["entries"][0][0],
            "package/Package.json",
        )
        self.assertEqual(
            json.loads(MODULE.VALID_PACKAGE_JSON),
            {"name": "die-fixture", "version": "1.2.3"},
        )
        with self.assertRaises(json.JSONDecodeError):
            json.loads(MODULE.INVALID_PACKAGE_JSON)


if __name__ == "__main__":
    unittest.main()

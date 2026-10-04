import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[2]
DOCKERFILES = {
    "qt5": (
        ROOT
        / "tools"
        / "upstream"
        / "Dockerfile.engine-contract-harness-qt5"
    ),
    "qt6": (
        ROOT
        / "tools"
        / "upstream"
        / "Dockerfile.engine-contract-harness-qt6"
    ),
}


class EngineContractHarnessDockerfileTests(unittest.TestCase):
    def test_builds_from_pinned_cmake_oracle_without_network(self):
        expected_bases = {
            "qt5": "die-rust/upstream-oracle-cmake:74eaf505",
            "qt6": "die-rust/upstream-oracle-cmake-qt6:74eaf505",
        }
        for profile, dockerfile in DOCKERFILES.items():
            with self.subTest(profile=profile):
                text = dockerfile.read_text(encoding="utf-8")
                self.assertIn(
                    f"ARG BASE_IMAGE={expected_bases[profile]}",
                    text,
                )
                self.assertIn("engine_contract_harness_main.cpp", text)
                self.assertIn("die-engine-contract-harness", text)
                self.assertNotIn("apt-get", text)
                self.assertNotIn("git clone", text)

    def test_labels_exact_upstream_revision(self):
        for profile, dockerfile in DOCKERFILES.items():
            with self.subTest(profile=profile):
                text = dockerfile.read_text(encoding="utf-8")
                self.assertIn(
                    (
                        'org.opencontainers.image.revision="'
                        "74eaf505c250ab47e709024e9dc41657cd8f2254"
                        '"'
                    ),
                    text,
                )


if __name__ == "__main__":
    unittest.main()

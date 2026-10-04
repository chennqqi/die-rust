import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[2]
DOCKERFILE = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.result-metadata-harness-qt5"
)


class ResultMetadataHarnessDockerfileTests(unittest.TestCase):
    def test_builds_from_pinned_cmake_oracle_without_network(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn(
            "ARG BASE_IMAGE=die-rust/upstream-oracle-cmake:74eaf505",
            text,
        )
        self.assertIn("result_metadata_harness_main.cpp", text)
        self.assertIn("die-result-metadata-harness", text)
        self.assertNotIn("apt-get", text)
        self.assertNotIn("git clone", text)

    def test_labels_exact_upstream_revision(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
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

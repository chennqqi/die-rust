import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[2]
DOCKERFILES = {
    "qt5": (
        ROOT
        / "tools"
        / "upstream"
        / "Dockerfile.bw-dispatch-harness-qt5"
    ),
    "qt6": (
        ROOT
        / "tools"
        / "upstream"
        / "Dockerfile.bw-dispatch-harness-qt6"
    ),
}


class BwDispatchHarnessDockerfileTests(unittest.TestCase):
    def test_builds_from_pinned_cmake_oracle_without_network(self):
        for platform, dockerfile in DOCKERFILES.items():
            with self.subTest(platform=platform):
                text = dockerfile.read_text(encoding="utf-8")
                suffix = "-qt6" if platform == "qt6" else ""
                self.assertIn(
                    "ARG BASE_IMAGE=die-rust/"
                    f"upstream-oracle-cmake{suffix}:74eaf505",
                    text,
                )
                self.assertIn("bw_dispatch_harness_main.cpp", text)
                self.assertIn("die-bw-dispatch-harness", text)
                self.assertNotIn("apt-get", text)
                self.assertNotIn("git clone", text)

    def test_labels_exact_upstream_revision(self):
        for platform, dockerfile in DOCKERFILES.items():
            with self.subTest(platform=platform):
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

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILES = {
    "qt5": ROOT / "tools" / "upstream" / "Dockerfile.archive-harness-qt5",
    "qt6": ROOT / "tools" / "upstream" / "Dockerfile.archive-harness-qt6",
}


class ArchiveHarnessDockerfilesTest(unittest.TestCase):
    def test_both_variants_use_the_same_harness_and_link_replacement(self):
        contents = {
            name: path.read_text(encoding="utf-8")
            for name, path in DOCKERFILES.items()
        }
        for name, content in contents.items():
            with self.subTest(variant=name):
                self.assertIn(
                    "COPY archive_harness_main.cpp /tmp/archive_harness_main.cpp",
                    content,
                )
                self.assertIn(
                    "CMakeFiles/diec.dir/main_console.cpp.o#"
                    "/tmp/archive_harness_main.cpp.o",
                    content,
                )
                self.assertIn(
                    "/opt/die-build/src/console/die-archive-harness",
                    content,
                )
                self.assertIn(
                    'org.opencontainers.image.revision="'
                    "74eaf505c250ab47e709024e9dc41657cd8f2254"
                    '"',
                    content,
                )

    def test_variants_are_pinned_to_the_expected_oracle_images(self):
        self.assertIn(
            "ARG BASE_IMAGE=die-rust/upstream-oracle-cmake:74eaf505",
            DOCKERFILES["qt5"].read_text(encoding="utf-8"),
        )
        self.assertIn(
            "ARG BASE_IMAGE="
            "die-rust/upstream-oracle-cmake-qt6:74eaf505",
            DOCKERFILES["qt6"].read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROFILES = {
    "metadata": "result_metadata_harness_main.cpp",
    "lists": "result_lists_harness_main.cpp",
    "ids": "result_ids_harness_main.cpp",
    "flags": "result_flags_harness_main.cpp",
    "enums": "result_enums_harness_main.cpp",
}


class ResultModelHarnessDockerfilesQt6Test(unittest.TestCase):
    def test_all_profiles_use_the_pinned_qt6_oracle_without_network(self):
        for profile, source in PROFILES.items():
            with self.subTest(profile=profile):
                path = (
                    ROOT
                    / "tools"
                    / "upstream"
                    / f"Dockerfile.result-{profile}-harness-qt6"
                )
                text = path.read_text(encoding="utf-8")
                self.assertIn(
                    "ARG BASE_IMAGE="
                    "die-rust/upstream-oracle-cmake-qt6:74eaf505",
                    text,
                )
                self.assertIn(source, text)
                self.assertIn(
                    f"die-result-{profile}-harness",
                    text,
                )
                self.assertNotIn("apt-get", text)
                self.assertNotIn("git clone", text)

    def test_all_profiles_label_the_exact_upstream_revision(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                path = (
                    ROOT
                    / "tools"
                    / "upstream"
                    / f"Dockerfile.result-{profile}-harness-qt6"
                )
                text = path.read_text(encoding="utf-8")
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

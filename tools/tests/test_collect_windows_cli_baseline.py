import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/upstream/collect_windows_cli_baseline.py"
REPORT = ROOT / "docs/research/data/baseline-corpus-windows-qt5.json"
MANIFEST = ROOT / "docs/research/data/baseline-corpus.json"
LINUX_REFERENCE = (
    ROOT / "docs/research/data/baseline-corpus-linux-qt5.json"
)
WINDOWS_BUILD = (
    ROOT / "docs/research/data/windows-qt5-build-baseline.json"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_windows_cli_baseline",
    SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CollectWindowsCliBaselineTests(unittest.TestCase):
    def test_checked_command_preserves_git_status_prefix(self):
        result = mock.Mock(returncode=0, stdout=" abc123 path\r\n")
        with mock.patch.object(MODULE.subprocess, "run", return_value=result):
            self.assertEqual(
                MODULE.run_checked(["git", "submodule", "status"]),
                " abc123 path",
            )

    def test_observation_summary_hashes_raw_crlf_bytes(self):
        observation = MODULE.Observation(1, b"out\r\n", b"error\r\n")
        self.assertEqual(
            observation.summary(),
            {
                "exit_code": 1,
                "stdout_bytes": 5,
                "stdout_sha256": hashlib.sha256(b"out\r\n").hexdigest(),
                "stderr_bytes": 7,
                "stderr_sha256": hashlib.sha256(b"error\r\n").hexdigest(),
            },
        )

    def test_observe_uses_absolute_executable_with_stable_argv0(self):
        completed = mock.Mock(
            returncode=0,
            stdout=b"output",
            stderr=b"",
        )
        binary = Path("C:/oracle/diec.exe")
        qt_dir = Path("C:/Qt")
        with mock.patch.object(
            MODULE.subprocess,
            "run",
            return_value=completed,
        ) as run:
            observation = MODULE.observe(
                binary,
                qt_dir,
                ("--version",),
                timeout_seconds=10,
            )
        self.assertEqual(observation.stdout, b"output")
        arguments, keywords = run.call_args
        self.assertEqual(arguments[0], ["diec.exe", "--version"])
        self.assertEqual(keywords["executable"], str(binary))
        self.assertEqual(keywords["cwd"], binary.parent)

    def test_pair_report_preserves_each_determinism_dimension(self):
        first = MODULE.Observation(0, b"first", b"")
        second = MODULE.Observation(1, b"second", b"error")
        paired = MODULE.pair_report(first, second)
        self.assertEqual(
            paired["determinism_differences"],
            ["exit_code", "stdout", "stderr"],
        )

    def test_json_projection_matches_existing_contract(self):
        data = json.dumps(
            {
                "detects": [
                    {
                        "filetype": "PE64",
                        "offset": "0",
                        "parentfilepart": "Header",
                        "size": "512",
                        "info": "ignored",
                        "values": [
                            {
                                "name": "Unknown",
                                "type": "Unknown",
                                "version": "",
                                "string": "ignored",
                            }
                        ],
                    }
                ]
            }
        ).encode()
        self.assertEqual(
            MODULE.json_detect_tree(data),
            [
                {
                    "filetype": "PE64",
                    "offset": "0",
                    "parentfilepart": "Header",
                    "size": "512",
                    "values": [
                        {
                            "name": "Unknown",
                            "type": "Unknown",
                            "version": "",
                        }
                    ],
                }
            ],
        )

    def test_corpus_loader_rejects_manifest_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory)
            (corpus / "manifest.json").write_text(
                '{"schema_version": 1, "samples": []}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                MODULE.BaselineError,
                "differs from the committed reference",
            ):
                MODULE.load_corpus(corpus, MANIFEST)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_committed_report_is_identity_bound_and_deterministic(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        build = json.loads(WINDOWS_BUILD.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["platform"], "windows-x86_64-qt5")
        self.assertEqual(
            report["generator_sha256"],
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["source"]["commit"], MODULE.UPSTREAM_COMMIT
        )
        self.assertEqual(
            report["source"]["rules_commit"], MODULE.RULES_COMMIT
        )
        self.assertEqual(
            report["binary"]["sha256"],
            build["clean_qmake_build"]["artifact"]["sha256"],
        )
        self.assertEqual(
            build["windows_cli_baseline"]["sha256"],
            hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            build["windows_cli_baseline"]["execution_count"],
            report["summary"]["execution_count"],
        )
        self.assertEqual(
            report["corpus_manifest"]["sha256"],
            hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["linux_qt5_reference"]["sha256"],
            hashlib.sha256(LINUX_REFERENCE.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["summary"]["case_count"], 6)
        self.assertEqual(report["summary"]["corpus_count"], 26)
        self.assertEqual(report["summary"]["execution_count"], 64)
        self.assertTrue(report["summary"]["deterministic"])
        self.assertEqual(
            report["summary"]["determinism_failures"],
            [],
        )
        self.assertTrue(report["summary"]["linux_projection_equal"])
        self.assertEqual(
            report["summary"]["linux_projection_failures"],
            [],
        )

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_all_corpus_projections_match_linux_qt5(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        for name, case in report["corpus"].items():
            with self.subTest(sample=name):
                self.assertEqual(
                    case["first_detect_tree"],
                    case["second_detect_tree"],
                )
                self.assertEqual(
                    case["first_detect_tree"],
                    case["linux_qt5_detect_tree"],
                )
                self.assertTrue(case["linux_projection_equal"])
                self.assertTrue(case["linux_exit_code_equal"])
                self.assertEqual(case["determinism_differences"], [])

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_report_has_no_local_absolute_paths(self):
        text = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("I:\\\\tmp", text)
        self.assertNotIn("die-windows-script-source", text)
        self.assertIn("<source>/Detect-It-Easy/db", text)
        self.assertIn("<corpus>/minimal-pe64.exe", text)

    @unittest.skipUnless(REPORT.exists(), "Windows report not collected")
    def test_windows_raw_line_endings_remain_observable(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(report["cases"]["version"]["first"]["stdout_bytes"], 11)
        linux = json.loads(LINUX_REFERENCE.read_text(encoding="utf-8"))
        self.assertEqual(linux["cases"]["version"]["left"]["stdout_bytes"], 10)
        self.assertNotEqual(
            report["cases"]["version"]["first"]["stdout_sha256"],
            linux["cases"]["version"]["left"]["stdout_sha256"],
        )


if __name__ == "__main__":
    unittest.main()

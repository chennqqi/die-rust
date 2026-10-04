import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BOOTSTRAP = load_module(
    "macos_bootstrap_helpers_for_toctou",
    ROOT / "tools/tests/test_macos_qt5_oracle_bootstrap.py",
)
COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_toctou.py"
)
VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_toctou.py"
)
COLLECTOR = load_module("macos_cli_toctou_collector_test", COLLECTOR_PATH)
VALIDATOR = load_module("macos_cli_toctou_validator_test", VALIDATOR_PATH)
MANIFEST_PATH = ROOT / COLLECTOR.FIXTURE_MANIFEST
LINUX_PATH = ROOT / COLLECTOR.LINUX_REFERENCE


def identity(inode: int, size: int, *, symlink: bool = False):
    return {
        "device": 1,
        "inode": inode,
        "mode": 0o120777 if symlink else 0o100644,
        "size": size,
    }


def attempt_for(case, fixture_dir: PurePosixPath):
    initial_is_new = case["initial_target"].endswith("new.bin")
    before = {
        "link_identity": identity(10, 18, symlink=True),
        "link_target": case["initial_target"],
        "target_identity": identity(
            21 if initial_is_new else 20,
            len(COLLECTOR.NEW_PAYLOAD) if initial_is_new else 0,
        ),
    }
    action = case["action"]
    if action == "none":
        after = copy.deepcopy(before)
    elif action == "replace_symlink_with_new_target":
        after = {
            "link_identity": identity(11, 18, symlink=True),
            "link_target": "../targets/new.bin",
            "target_identity": identity(
                21, len(COLLECTOR.NEW_PAYLOAD)
            ),
        }
    else:
        after = {
            "link_identity": None,
            "link_target": None,
            "target_identity": None,
        }
    return {
        "before": before,
        "after": after,
        "synchronization": {
            "transport": "pty-with-oPOST-disabled",
            "first_line": (
                str(fixture_dir / "case" / "a-blocker.bin") + ":"
            ),
            "child_confirmed_stopped": True,
            "mutation_while_stopped": True,
            "second_prefix_seen_before_mutation": False,
            "stop_signal": VALIDATOR.DARWIN_SIGSTOP,
            "resume_signal": VALIDATOR.DARWIN_SIGCONT,
        },
    }


def write_candidate(directory: Path):
    baseline_path = BOOTSTRAP.write_cli_candidate_bundle(directory)
    oracle_path = directory / "oracle-candidate.json"
    baseline = json.loads(baseline_path.read_bytes())
    manifest_raw = MANIFEST_PATH.read_bytes()
    manifest = json.loads(manifest_raw)
    linux_raw = LINUX_PATH.read_bytes()
    linux = json.loads(linux_raw)
    fixture_dir = PurePosixPath("/private/tmp/die-macos-toctou")
    report_db = COLLECTOR.database_arguments(
        Path("<source>"), report=True
    )
    cases = {}
    for case in manifest["cases"]:
        name = case["name"]
        linux_case = linux["cases"][name]
        projection = {
            "action": linux_case["action"],
            "expected_open_target": linux_case[
                "expected_open_target"
            ],
            "blocker_document": linux_case["blocker_document"],
            "link_document": linux_case["link_document"],
        }
        prefix = str(fixture_dir / "case")
        stdout = (
            f"{prefix}/a-blocker.bin:\n".encode()
            + json.dumps(
                projection["blocker_document"],
                separators=(",", ":"),
            ).encode()
            + b"\n"
            + f"{prefix}/z-link.bin:\n".encode()
            + json.dumps(
                projection["link_document"],
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )
        observation = BOOTSTRAP.CLI_COMMON.Observation(0, stdout, b"")
        entry = BOOTSTRAP.CLI_COLLECTOR.pair_report(
            BOOTSTRAP.CLI_COMMON,
            directory,
            f"cli-toctou/{name}",
            observation,
            observation,
        )
        documents = COLLECTOR.parse_documents(
            stdout, Path(str(fixture_dir / "case"))
        )
        attempt = attempt_for(case, fixture_dir)
        entry.update(
            {
                "arguments": [
                    "--entropy",
                    "--json",
                    *report_db,
                    "<fixture>/case",
                ],
                "timeout_seconds": 60,
                "initial_target": case["initial_target"],
                "action": case["action"],
                "expected_open_target": case[
                    "expected_open_target"
                ],
                "attempts": {
                    "first": copy.deepcopy(attempt),
                    "second": copy.deepcopy(attempt),
                },
                "first_documents": documents,
                "second_documents": documents,
                "synchronization_valid": True,
                "state_transitions_valid": True,
                "linux_qt5_projection": projection,
                "linux_qt5_semantic_equal": True,
            }
        )
        cases[name] = entry

    materialization = manifest["materialization"]
    preflight = {
        "blocker_size": materialization["blocker"]["size"],
        "blocker_sha256": materialization["blocker"]["sha256"],
        "old_size": materialization["old_target"]["size"],
        "old_sha256": materialization["old_target"]["sha256"],
        "new_size": materialization["new_target"]["size"],
        "new_sha256": materialization["new_target"]["sha256"],
    }
    count = len(manifest["cases"])
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": COLLECTOR.PLATFORM,
        "generator": COLLECTOR._generator_bindings(ROOT),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": hashlib.sha256(
                oracle_path.read_bytes()
            ).hexdigest(),
        },
        "cli_baseline_report": {
            "path": "cli-baseline-candidate.json",
            "sha256": hashlib.sha256(
                baseline_path.read_bytes()
            ).hexdigest(),
        },
        "source": baseline["source"],
        "qt": baseline["qt"],
        "binary": baseline["binary"],
        "fixture": {
            "manifest": COLLECTOR.FIXTURE_MANIFEST,
            "manifest_sha256": hashlib.sha256(
                manifest_raw
            ).hexdigest(),
            "case_count": count,
            "live_preflight": preflight,
        },
        "linux_qt5_reference": {
            "path": COLLECTOR.LINUX_REFERENCE,
            "sha256": hashlib.sha256(linux_raw).hexdigest(),
        },
        "local_paths": {"fixture_dir": str(fixture_dir)},
        "selection": {
            "case_names": [
                case["name"] for case in manifest["cases"]
            ],
            "minimum_repetitions_per_case": 2,
        },
        "cases": cases,
        "summary": {
            "case_count": count,
            "execution_count": count * 2,
            "raw_stream_count": count * 4,
            "determinism_failures": [],
            "synchronization_failures": [],
            "state_transition_failures": [],
            "linux_semantic_failures": [],
            "deterministic": True,
            "synchronization_valid": True,
            "state_transitions_valid": True,
            "linux_semantics_equal": True,
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": COLLECTOR.ADMISSION_REASON,
        },
        "limitations": COLLECTOR.LIMITATIONS,
    }
    report_path = directory / "cli-toctou-candidate.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path, oracle_path, baseline_path, report


class MacosCliToctouCandidateTest(unittest.TestCase):
    def validate(self, report_path, oracle_path, baseline_path):
        report = json.loads(report_path.read_bytes())
        VALIDATOR.validate_report(
            report,
            report_path=report_path.resolve(strict=True),
            oracle_path=oracle_path.resolve(strict=True),
            baseline_path=baseline_path.resolve(strict=True),
            root=ROOT,
        )

    def test_validator_replays_all_raw_documents_and_transitions(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report_path, oracle_path, baseline_path, report = (
                write_candidate(directory)
            )
            self.validate(report_path, oracle_path, baseline_path)
            self.assertEqual(report["summary"]["execution_count"], 8)
            self.assertEqual(report["summary"]["raw_stream_count"], 16)
            swapped = report["cases"]["swap_old_to_new"]
            self.assertNotEqual(
                swapped["attempts"]["first"]["before"][
                    "link_identity"
                ]["inode"],
                swapped["attempts"]["first"]["after"][
                    "link_identity"
                ]["inode"],
            )

    def test_validator_rejects_raw_sync_admission_and_inventory_drift(self):
        mutations = (
            "raw",
            "sync",
            "consistent_sync_failure",
            "admission",
            "inventory",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    directory = Path(temporary)
                    report_path, oracle_path, baseline_path, report = (
                        write_candidate(directory)
                    )
                    if mutation == "raw":
                        raw = (
                            directory
                            / report["cases"]["stable_old"]["first"][
                                "stdout_path"
                            ]
                        )
                        raw.write_bytes(raw.read_bytes() + b"x")
                    elif mutation == "sync":
                        report["cases"]["stable_old"]["attempts"][
                            "first"
                        ]["synchronization"]["stop_signal"] = 9
                        report_path.write_text(
                            json.dumps(report), encoding="utf-8"
                        )
                    elif mutation == "consistent_sync_failure":
                        report["cases"]["stable_old"]["attempts"][
                            "first"
                        ]["synchronization"]["stop_signal"] = 9
                        report["cases"]["stable_old"][
                            "synchronization_valid"
                        ] = False
                        report["summary"][
                            "synchronization_failures"
                        ] = ["stable_old"]
                        report["summary"][
                            "synchronization_valid"
                        ] = False
                        report_path.write_text(
                            json.dumps(report), encoding="utf-8"
                        )
                    elif mutation == "admission":
                        report["admission"]["platform_admitted"] = True
                        report_path.write_text(
                            json.dumps(report), encoding="utf-8"
                        )
                    else:
                        extra = (
                            directory
                            / "raw"
                            / "cli-toctou"
                            / "undeclared"
                        )
                        extra.write_bytes(b"x")
                    with self.assertRaises((VALIDATOR.ReportError, ValueError)):
                        self.validate(
                            report_path, oracle_path, baseline_path
                        )

    def test_document_parser_rejects_duplicate_and_non_finite_json(self):
        case_dir = Path("/private/tmp/die-macos-toctou/case")
        prefix = str(PurePosixPath(str(case_dir).replace("\\", "/")))
        for body in (
            b'{"total":0,"total":1}',
            b'{"total":NaN}',
        ):
            stdout = (
                f"{prefix}/a-blocker.bin:\n".encode()
                + body
                + b"\n"
                + f"{prefix}/z-link.bin:\n".encode()
                + b'{"total":0}\n'
            )
            with self.subTest(body=body):
                with self.assertRaises(COLLECTOR.ToctouError):
                    COLLECTOR.parse_documents(stdout, case_dir)


if __name__ == "__main__":
    unittest.main()

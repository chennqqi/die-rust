import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BOOTSTRAP = load_module(
    "macos_bootstrap_helpers_for_privilege_path",
    ROOT / "tools/tests/test_macos_qt5_oracle_bootstrap.py",
)
COLLECTOR_PATH = (
    ROOT / "tools/upstream/collect_macos_cli_privilege_paths.py"
)
VALIDATOR_PATH = (
    ROOT / "tools/upstream/validate_macos_cli_privilege_paths.py"
)
COLLECTOR = load_module(
    "macos_cli_privilege_path_collector_test", COLLECTOR_PATH
)
VALIDATOR = load_module(
    "macos_cli_privilege_path_validator_test", VALIDATOR_PATH
)
ROOT_EXEC = load_module(
    "macos_privilege_root_exec_test",
    ROOT / COLLECTOR.ROOT_EXEC_HELPER,
)


def command_record(stdout: str = "", stderr: str = ""):
    return {"exit_code": 0, "stdout": stdout, "stderr": stderr}


def snapshot(target, payload_size: int):
    uid = 0 if target.owner == "root" else 501
    gid = 0 if target.owner == "root" else 20
    acl = ""
    if target.acl_kind is not None:
        entry = COLLECTOR.acl_entry("runner", target.acl_kind)
        acl = f"0: {entry}\n"
    return {
        "relative_path": target.relative,
        "kind": target.kind,
        "owner": target.owner,
        "uid": uid,
        "gid": gid,
        "mode": f"{target.mode:04o}",
        "size": payload_size if target.kind == "file" else 96,
        "acl_kind": target.acl_kind,
        "acl_listing": acl,
    }


def write_candidate(directory: Path):
    baseline_path = BOOTSTRAP.write_cli_candidate_bundle(directory)
    oracle_path = directory / "oracle-candidate.json"
    baseline = json.loads(baseline_path.read_bytes())
    manifest_raw = (ROOT / COLLECTOR.BASELINE_MANIFEST).read_bytes()
    manifest = json.loads(manifest_raw)
    payload = next(
        item
        for item in manifest["samples"]
        if item["name"] == COLLECTOR.MINIMAL_PDF
    )
    reference_tree = baseline["corpus"][COLLECTOR.MINIMAL_PDF][
        "first_detect_tree"
    ]
    fixture_dir = PurePosixPath(
        "/private/tmp/die-macos-privilege-path"
    )
    report_db = COLLECTOR.database_arguments(Path("."), report=True)
    snapshots = {
        target.name: snapshot(target, payload["size"])
        for target in COLLECTOR.TARGETS
    }
    cases = {}
    for target in COLLECTOR.TARGETS:
        for identity in COLLECTOR.IDENTITIES:
            name = COLLECTOR._case_name(target, identity)
            succeeds = (
                identity in target.expected_reference_identities
                or (
                    identity == "root"
                    and target.acl_kind is not None
                )
            )
            stdout = (
                json.dumps(
                    {"detects": reference_tree}, separators=(",", ":")
                ).encode()
                if succeeds
                else b""
            )
            observation = BOOTSTRAP.CLI_COMMON.Observation(
                0, stdout, b""
            )
            entry = BOOTSTRAP.CLI_COLLECTOR.pair_report(
                BOOTSTRAP.CLI_COMMON,
                directory,
                f"{COLLECTOR.RAW_SUBDIR}/{name}",
                observation,
                observation,
            )
            tree = BOOTSTRAP.CLI_COMMON.json_detect_tree(stdout)
            item_snapshot = copy.deepcopy(snapshots[target.name])
            entry.update(
                {
                    "target": target.name,
                    "execution_identity": identity,
                    "command_prefix": (
                        []
                        if identity == "runner"
                        else [
                            "sudo",
                            "-n",
                            "--",
                            "python3",
                            "-I",
                            "-S",
                            "root-exec-helper",
                        ]
                    ),
                    "runtime_environment": {
                        "HOME": (
                            "<fixture>/"
                            + COLLECTOR.RUNTIME_DIRECTORIES[identity][
                                "home"
                            ]
                        ),
                        "TMPDIR": (
                            "<fixture>/"
                            + COLLECTOR.RUNTIME_DIRECTORIES[identity][
                                "tmp"
                            ]
                        ),
                        "root_umask": (
                            "0000" if identity == "root" else None
                        ),
                    },
                    "arguments": [
                        "--json",
                        *report_db,
                        f"<fixture>/{target.relative}",
                    ],
                    "timeout_seconds": 120,
                    "first_timed_out": False,
                    "second_timed_out": False,
                    "first_fixture_snapshot": copy.deepcopy(
                        item_snapshot
                    ),
                    "second_fixture_snapshot": copy.deepcopy(
                        item_snapshot
                    ),
                    "first_stdout_summary": COLLECTOR.stdout_summary(
                        stdout
                    ),
                    "second_stdout_summary": COLLECTOR.stdout_summary(
                        stdout
                    ),
                    "first_prefix_paths": [],
                    "second_prefix_paths": [],
                    "first_detect_tree": tree,
                    "second_detect_tree": tree,
                    "reference_tree_expected": (
                        identity
                        in target.expected_reference_identities
                    ),
                    "minimal_pdf_detect_tree_equal": (
                        tree == reference_tree
                        if target.kind == "file"
                        else None
                    ),
                }
            )
            cases[name] = entry

    mutations = []
    for target in COLLECTOR.TARGETS:
        if target.owner == "root":
            mutations.append(
                {
                    "target": target.name,
                    "operation": "chown_root",
                    **command_record(),
                }
            )
        if target.acl_kind is not None:
            mutations.append(
                {
                    "target": target.name,
                    "operation": "add_acl",
                    "entry": COLLECTOR.acl_entry(
                        "runner", target.acl_kind
                    ),
                    **command_record(),
                }
            )
    cleanup_operations = [
        {
            "target": target.name,
            "operation": "remove_acl",
            **command_record(),
        }
        for target in COLLECTOR.TARGETS
        if target.acl_kind is not None
    ]
    count = len(cases)
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
            "manifest": COLLECTOR.BASELINE_MANIFEST,
            "manifest_sha256": hashlib.sha256(
                manifest_raw
            ).hexdigest(),
            "payload": payload,
            "runner": {
                "uid": 501,
                "gid": 20,
                "username": "runner",
            },
            "tool_paths": {
                "sudo": str(COLLECTOR.SUDO),
                "id": str(COLLECTOR.ID),
                "chmod": str(COLLECTOR.CHMOD),
                "chown": str(COLLECTOR.CHOWN),
                "ls": str(COLLECTOR.LS),
                "python": "/usr/bin/python3",
                "root_exec_helper": COLLECTOR.ROOT_EXEC_HELPER,
            },
            "sudo_probe": command_record("0\n"),
            "mutations": mutations,
            "targets": snapshots,
            "database_archives": [
                {
                    "name": name,
                    "path": (
                        f"{COLLECTOR.DATABASE_ARCHIVE_DIRECTORY}/"
                        f"{name}.zip"
                    ),
                    "member_count": 1,
                    "size": 128,
                    "sha256": hashlib.sha256(name.encode()).hexdigest(),
                    "format": (
                        "ZIP_STORED; lexicographic POSIX member order; "
                        "1980-01-01T00:00:00; mode 0100644"
                    ),
                }
                for name in COLLECTOR.DATABASE_DIRECTORIES
            ],
            "runtime_directories": COLLECTOR.RUNTIME_DIRECTORIES,
            "runtime_artifacts": [
                {
                    "path": relative,
                    "kind": "directory",
                    "uid": 501,
                    "gid": 20,
                    "mode": "0700",
                    "size": 96,
                }
                for relative in sorted(
                    value
                    for identity in COLLECTOR.IDENTITIES
                    for value in COLLECTOR.RUNTIME_DIRECTORIES[
                        identity
                    ].values()
                )
            ],
            "cleanup": {
                "fixture_removed": True,
                "operations": cleanup_operations,
            },
        },
        "local_paths": {"fixture_dir": str(fixture_dir)},
        "selection": {
            "target_names": [
                target.name for target in COLLECTOR.TARGETS
            ],
            "execution_identities": list(COLLECTOR.IDENTITIES),
            "minimum_repetitions_per_case": 2,
        },
        "cases": cases,
        "relationships": COLLECTOR.derive_relationships(cases),
        "summary": {
            "case_count": count,
            "execution_count": 2 * count,
            "raw_stream_count": 4 * count,
            "determinism_failures": [],
            "timeout_cases": [],
            "expected_reference_failures": [],
            "deterministic": True,
            "expected_references_equal": True,
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": COLLECTOR.ADMISSION_REASON,
        },
        "limitations": COLLECTOR.LIMITATIONS,
    }
    report_path = directory / COLLECTOR.REPORT_NAME
    report_path.write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8"
    )
    return report_path, oracle_path, baseline_path, report


class MacosCliPrivilegePathCandidateTest(unittest.TestCase):
    def validate(self, report_path, oracle_path, baseline_path):
        report = json.loads(report_path.read_bytes())
        VALIDATOR.validate_report(
            report,
            report_path=report_path.resolve(strict=True),
            oracle_path=oracle_path.resolve(strict=True),
            baseline_path=baseline_path.resolve(strict=True),
            root=ROOT,
        )

    def test_validator_replays_12_cases_and_raw_streams(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            values = write_candidate(directory)
            self.validate(*values[:3])
            report = values[3]
            self.assertEqual(report["summary"]["case_count"], 12)
            self.assertEqual(report["summary"]["execution_count"], 24)
            self.assertEqual(report["summary"]["raw_stream_count"], 48)
            self.assertFalse(
                report["relationships"]["acl_deny_read_file"][
                    "runner_matches_minimal_pdf"
                ]
            )
            self.assertTrue(
                report["relationships"]["acl_deny_read_file"][
                    "root_matches_minimal_pdf"
                ]
            )

    def test_validator_rejects_raw_state_relationship_and_admission_drift(
        self,
    ):
        mutations = (
            "raw",
            "snapshot",
            "relationship",
            "runtime",
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
                    case = report["cases"][
                        "owner_public_file__as_runner"
                    ]
                    if mutation == "raw":
                        raw = directory / case["first"]["stdout_path"]
                        raw.write_bytes(raw.read_bytes() + b"x")
                    elif mutation == "snapshot":
                        case["first_fixture_snapshot"]["mode"] = "0600"
                        report_path.write_text(
                            json.dumps(report), encoding="utf-8"
                        )
                    elif mutation == "relationship":
                        report["relationships"]["mode_000_file"][
                            "root_matches_minimal_pdf"
                        ] = False
                        report_path.write_text(
                            json.dumps(report), encoding="utf-8"
                        )
                    elif mutation == "runtime":
                        report["fixture"]["runtime_artifacts"][0][
                            "path"
                        ] = "../escape"
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
                            / COLLECTOR.RAW_SUBDIR
                            / "undeclared"
                        )
                        extra.write_bytes(b"x")
                    with self.assertRaises(
                        (VALIDATOR.ReportError, ValueError)
                    ):
                        self.validate(
                            report_path, oracle_path, baseline_path
                        )

    def test_fixture_path_must_be_new_direct_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            valid = parent / "fixture"
            self.assertEqual(
                COLLECTOR.validate_fixture_path(valid),
                valid.resolve(),
            )
            valid.mkdir()
            with self.assertRaises(COLLECTOR.PrivilegePathError):
                COLLECTOR.validate_fixture_path(valid)
            nested = parent / "missing" / "fixture"
            with self.assertRaises(OSError):
                COLLECTOR.validate_fixture_path(nested)

    def test_acl_entries_bind_darwin_rights(self):
        self.assertEqual(
            COLLECTOR.database_arguments(Path("."), report=True),
            (
                "--database",
                "<fixture>/.database/db.zip",
                "--extradatabase",
                "<fixture>/.database/db_extra.zip",
                "--customdatabase",
                "<fixture>/.database/db_custom.zip",
            ),
        )
        self.assertEqual(
            COLLECTOR.acl_entry("runner", "deny_read"),
            "user:runner deny read",
        )
        self.assertEqual(
            COLLECTOR.acl_entry("runner", "deny_search"),
            "user:runner deny list,search",
        )

    def test_database_archives_are_deterministic_and_cache_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            fixture_a = root / "fixture-a"
            fixture_b = root / "fixture-b"
            fixture_a.mkdir()
            fixture_b.mkdir()
            for name in COLLECTOR.DATABASE_DIRECTORIES:
                database = source / "Detect-It-Easy" / name
                (database / "Binary").mkdir(parents=True)
                (database / "Binary" / "z.1.sg").write_bytes(b"z\n")
                (database / "Binary" / "a.1.sg").write_bytes(b"a\n")
            first = COLLECTOR.materialize_database_archives(
                source,
                fixture_a,
            )
            second = COLLECTOR.materialize_database_archives(
                source,
                fixture_b,
            )
            self.assertEqual(first, second)
            for record in first:
                archive_path = fixture_a / record["path"]
                with zipfile.ZipFile(archive_path) as archive:
                    self.assertEqual(
                        archive.namelist(),
                        ["Binary/a.1.sg", "Binary/z.1.sg"],
                    )
                    self.assertTrue(
                        all(
                            item.compress_type == zipfile.ZIP_STORED
                            for item in archive.infolist()
                        )
                    )

    def test_root_exec_parser_requires_contained_absolute_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            home = runtime / "home"
            temp = runtime / "tmp"
            binary = runtime / "diec"
            home.mkdir()
            temp.mkdir()
            binary.write_bytes(b"binary")
            parsed = ROOT_EXEC.parse_invocation(
                [
                    "--home",
                    str(home),
                    "--tmp",
                    str(temp),
                    "--path",
                    "/qt/bin:/usr/bin",
                    "--",
                    str(binary),
                    "--json",
                ]
            )
            self.assertEqual(parsed[0], home.resolve())
            self.assertEqual(parsed[1], temp.resolve())
            self.assertEqual(parsed[3], binary.resolve())
            with self.assertRaises(ROOT_EXEC.ExecError):
                ROOT_EXEC.parse_invocation(
                    [
                        "--home",
                        str(home),
                        "--tmp",
                        "relative",
                        "--path",
                        "/usr/bin",
                        "--",
                        str(binary),
                        "--json",
                    ]
                )


if __name__ == "__main__":
    unittest.main()

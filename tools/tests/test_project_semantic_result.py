import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPAT = ROOT / "tools" / "compat"
MODULE_PATH = COMPAT / "project_semantic_result.py"
sys.path.insert(0, str(COMPAT))
import normalize_semantic_projection as NORMALIZER


SPEC = importlib.util.spec_from_file_location(
    "project_semantic_result",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
RAW = MODULE.raw_verifier
FRAMING = MODULE.framing
UPSTREAM = "74eaf505c250ab47e709024e9dc41657cd8f2254"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def base_contract(kind="normal_scan_json", documents=1):
    return {
        "contract_schema": 1,
        "case_id": "synthetic.semantic",
        "platform": "linux-x86_64",
        "oracle_profile": "cmake-qt5",
        "upstream_commit": UPSTREAM,
        "case_manifest_sha256": "0" * 64,
        "semantic_schema": 1,
        "output": {
            "kind": kind,
            "expected_json_documents": documents,
        },
    }


def base_execution(stdout, stderr=b"", side="upstream"):
    revision = UPSTREAM if side == "upstream" else "2" * 40
    return {
        "execution_schema": 1,
        "run_identity": {
            "case_id": "synthetic.semantic",
            "side": side,
            "platform": "linux-x86_64",
            "producer_profile": (
                "cmake-qt5" if side == "upstream" else "rust-debug"
            ),
            "producer_revision": revision,
            "case_manifest_sha256": "0" * 64,
            "executable_sha256": "1" * 64,
        },
        "argv": ["diec", "--json", "/corpus/input"],
        "environment": {"LC_ALL": "C", "TZ": "UTC"},
        "logical_cwd": "/work",
        "termination": {"kind": "exit", "code": 0},
        "wall_time_ns": 123,
        "resource_usage": {
            "cpu_time_ns": None,
            "peak_memory_bytes": None,
            "budget_counters": {},
        },
        "artifacts": {
            "stdout": {"sha256": sha256(stdout), "size": len(stdout)},
            "stderr": {"sha256": sha256(stderr), "size": len(stderr)},
        },
    }


def verification(execution):
    artifacts = {
        role: {
            "relative_path": f"sha256/{reference['sha256']}",
            "sha256": reference["sha256"],
            "size": reference["size"],
        }
        for role, reference in execution["artifacts"].items()
    }
    return {
        "verification_schema": 1,
        "verifier": {
            "name": RAW.VERIFIER_NAME,
            "version": RAW.VERIFIER_VERSION,
        },
        "result": "pass",
        "run_identity": execution["run_identity"],
        "manifest_artifact": {
            "sha256": "3" * 64,
            "canonical_execution_sha256": sha256(
                RAW.canonical_json(execution)
            ),
        },
        "verification_budget_bytes": 4096,
        "verified_total_bytes": sum(
            item["size"] for item in execution["artifacts"].values()
        ),
        "artifacts": artifacts,
    }


def project(stdout, contract=None, stderr=b"", side="upstream"):
    raw_contract = contract or base_contract()
    normalized_contract = MODULE.validate_contract(raw_contract)
    execution = RAW.validate_execution(
        base_execution(stdout, stderr, side)
    )
    audit = verification(execution)
    framing_projection = FRAMING.build_projection(
        execution,
        audit,
        stdout,
    )
    return MODULE.build_projection(
        normalized_contract,
        RAW.canonical_json(normalized_contract),
        execution,
        audit,
        framing_projection,
        {"stdout": stdout, "stderr": stderr},
    )


def write_case(directory, stdout, stderr=b"", contract=None):
    execution = base_execution(stdout, stderr)
    artifact_root = directory / "artifacts"
    sha_root = artifact_root / "sha256"
    sha_root.mkdir(parents=True)
    for content in (stdout, stderr):
        (sha_root / sha256(content)).write_bytes(content)
    manifest = directory / "execution.json"
    manifest.write_text(json.dumps(execution), encoding="utf-8")
    contract_path = directory / "contract.json"
    contract_path.write_text(
        json.dumps(contract or base_contract()),
        encoding="utf-8",
    )
    return contract_path, manifest, artifact_root, execution


class SemanticResultProjectionTests(unittest.TestCase):
    def test_projects_ordered_nested_scan_tree_without_losing_strings(self):
        document = {
            "detects": [
                {
                    "filetype": "PE32",
                    "info": "",
                    "offset": "0",
                    "parentfilepart": "Header",
                    "size": "1024",
                    "values": [
                        {
                            "info": "",
                            "name": "Generic",
                            "string": "(Heur)Protection: Generic",
                            "type": "~protection",
                            "version": "",
                        },
                        {
                            "filetype": "Binary",
                            "info": "",
                            "offset": "608",
                            "parentfilepart": "Resource",
                            "size": "20",
                            "values": [
                                {
                                    "info": "Resources",
                                    "name": "Manifest",
                                    "string": (
                                        "Format: Manifest[Resources]"
                                    ),
                                    "type": "format",
                                    "version": "",
                                }
                            ],
                        },
                    ],
                }
            ]
        }
        stdout = json.dumps(document, separators=(",", ":")).encode()
        semantic = project(stdout)["semantic"]

        self.assertEqual(semantic["result"], "pass")
        typed = semantic["comparison"]["streams"]["stdout"]["segments"][0][
            "document"
        ]
        self.assertEqual(typed["format_candidates"], ["PE32"])
        root = typed["items"][0]
        self.assertEqual(root["offset"], 0)
        self.assertEqual(root["offset_text"], "0")
        self.assertEqual(root["values"][0]["type"], "~protection")
        self.assertTrue(root["values"][0]["heuristic"])
        child = root["values"][1]
        self.assertEqual(child["parent_file_part"], "Resource")
        self.assertEqual(child["values"][0]["display"], (
            "Format: Manifest[Resources]"
        ))

    def test_projects_unknown_and_hideunknown_semantics_explicitly(self):
        unknown = {
            "info": "",
            "name": "Unknown",
            "string": "Unknown: Unknown",
            "type": "Unknown",
            "version": "",
        }
        regular = {
            "detects": [
                {
                    "filetype": "ELF64",
                    "info": "",
                    "offset": "0",
                    "parentfilepart": "Header",
                    "size": "64",
                    "values": [unknown],
                }
            ]
        }
        regular_output = project(json.dumps(regular).encode())
        regular_leaf = regular_output["semantic"]["comparison"]["streams"][
            "stdout"
        ]["segments"][0]["document"]["items"][0]["values"][0]
        self.assertTrue(regular_leaf["unknown"])

        hidden = {
            "detects": [
                {
                    "info": "",
                    "name": "",
                    "string": "ELF64",
                    "type": "",
                    "version": "",
                }
            ]
        }
        hidden_output = project(json.dumps(hidden).encode())
        hidden_document = hidden_output["semantic"]["comparison"]["streams"][
            "stdout"
        ]["segments"][0]["document"]
        self.assertEqual(hidden_document["format_candidates"], ["ELF64"])
        self.assertEqual(hidden_document["items"][0]["kind"], "detection")
        self.assertTrue(hidden_document["items"][0]["unknown"])

    def test_projects_entropy_numbers_and_record_order(self):
        contract = base_contract("entropy_json")
        value = {
            "total": 1.5,
            "status": "not packed",
            "records": [
                {
                    "name": "Header",
                    "offset": 0,
                    "size": 64,
                    "entropy": 1.25,
                    "status": "not packed",
                },
                {
                    "name": "Data",
                    "offset": 64,
                    "size": 2,
                    "entropy": 0,
                    "status": "",
                },
            ],
        }
        output = project(json.dumps(value).encode(), contract)
        document = output["semantic"]["comparison"]["streams"]["stdout"][
            "segments"
        ][0]["document"]
        self.assertEqual(document["kind"], "entropy")
        self.assertEqual(
            [record["name"] for record in document["records"]],
            ["Header", "Data"],
        )

    def test_info_and_struct_convert_object_keys_to_ordered_entries(self):
        value = {
            "data": {
                "Info": {
                    "File name": "sample.exe",
                    "Size": "64",
                }
            }
        }
        for output_kind, document_kind in (
            ("info_json", "info"),
            ("struct_json", "struct"),
        ):
            with self.subTest(output_kind=output_kind):
                output = project(
                    json.dumps(value).encode(),
                    base_contract(output_kind),
                )
                document = output["semantic"]["comparison"]["streams"][
                    "stdout"
                ]["segments"][0]["document"]
                self.assertEqual(document["kind"], document_kind)
                info = document["data"]["entries"][0]
                self.assertEqual(info["name"], "Info")
                self.assertEqual(
                    [item["name"] for item in info["value"]["entries"]],
                    ["File name", "Size"],
                )

        empty_struct = project(
            b'{"data":""}',
            base_contract("struct_json"),
        )
        data = empty_struct["semantic"]["comparison"]["streams"]["stdout"][
            "segments"
        ][0]["document"]["data"]
        self.assertEqual(data, {"kind": "string", "value": ""})

    def test_normal_scan_cli_error_is_not_silently_empty(self):
        output = project(b'{"error":"Cannot open file"}')
        document = output["semantic"]["comparison"]["streams"]["stdout"][
            "segments"
        ][0]["document"]
        self.assertEqual(
            document,
            {"kind": "cli_error", "message": "Cannot open file"},
        )

    def test_valid_json_nul_in_observable_string_is_preserved(self):
        document = {
            "detects": [
                {
                    "filetype": "Binary",
                    "info": "",
                    "offset": "0",
                    "parentfilepart": "Header",
                    "size": "1",
                    "values": [
                        {
                            "info": "A\x00B",
                            "name": "Embedded",
                            "string": "Format: Embedded[A\x00B]",
                            "type": "format",
                            "version": "",
                        }
                    ],
                }
            ]
        }
        output = project(json.dumps(document).encode())
        leaf = output["semantic"]["comparison"]["streams"]["stdout"][
            "segments"
        ][0]["document"]["items"][0]["values"][0]
        self.assertEqual(leaf["info"], "A\x00B")
        self.assertEqual(leaf["display"], "Format: Embedded[A\x00B]")

    def test_unrecognized_shape_is_explicit_failure_and_preserves_value(self):
        output = project(b'{"detects":[],"extra":true}')
        semantic = output["semantic"]
        self.assertEqual(semantic["result"], "projection_failure")
        self.assertEqual(
            semantic["issues"][0]["code"],
            "document_schema_mismatch",
        )
        document = semantic["comparison"]["streams"]["stdout"]["segments"][
            0
        ]["document"]
        self.assertEqual(document["kind"], "unclassified")
        self.assertEqual(
            document["value"],
            {"detects": [], "extra": True},
        )

    def test_raw_output_and_binary_diagnostics_remain_lossless(self):
        stdout = b"\xffdiagnostic\n"
        output = project(
            stdout,
            base_contract("raw", 0),
            stderr=b"\xfe",
        )
        semantic = output["semantic"]
        self.assertEqual(semantic["result"], "pass")
        raw_segment = semantic["comparison"]["streams"]["stdout"]["segments"][
            0
        ]
        record = raw_segment["records"][0]
        self.assertEqual(record["body"]["encoding"], "base64")
        self.assertEqual(record["body"]["base64"], "/2RpYWdub3N0aWM=")
        self.assertEqual(record["line_ending"], "lf")
        self.assertEqual(
            semantic["comparison"]["streams"]["stderr"]["records"][0][
                "body"
            ],
            {"encoding": "base64", "base64": "/g=="},
        )

    def test_raw_records_split_body_from_exact_line_endings(self):
        output = project(
            b"one.1.sg\r\none.1.sg: [12 ms]\ntrailing",
            base_contract("raw", 0),
        )
        records = output["semantic"]["comparison"]["streams"]["stdout"][
            "segments"
        ][0]["records"]
        self.assertEqual(
            [record["body"]["text"] for record in records],
            ["one.1.sg", "one.1.sg: [12 ms]", "trailing"],
        )
        self.assertEqual(
            [record["line_ending"] for record in records],
            ["crlf", "lf", "none"],
        )
        sources = output["semantic"]["evidence"]["raw_streams"]["stdout"][
            "segments"
        ][0]["records"]
        self.assertEqual(sources[0]["offset"], 0)
        self.assertEqual(sources[1]["offset"], 10)

    def test_comparison_and_evidence_reconstruct_raw_segment_exactly(self):
        stdout = b"\xfffirst\r\nsecond\nlast"
        output = project(stdout, base_contract("raw", 0))
        semantic = output["semantic"]
        comparison = semantic["comparison"]["streams"]["stdout"][
            "segments"
        ][0]
        evidence = semantic["evidence"]["raw_streams"]["stdout"][
            "segments"
        ][0]
        rebuilt = bytearray()
        endings = {"none": b"", "lf": b"\n", "crlf": b"\r\n"}
        for record, source in zip(
            comparison["records"],
            evidence["records"],
            strict=True,
        ):
            body = record["body"]
            if body["encoding"] == "utf8":
                body_bytes = body["text"].encode("utf-8")
            else:
                body_bytes = base64.b64decode(body["base64"])
            raw_record = body_bytes + endings[record["line_ending"]]
            self.assertEqual(len(raw_record), source["size"])
            self.assertEqual(sha256(raw_record), source["sha256"])
            rebuilt.extend(raw_record)
        self.assertEqual(bytes(rebuilt), stdout)
        self.assertEqual(sha256(rebuilt), evidence["source"]["sha256"])

    def test_profiling_line_is_directly_normalizer_addressable(self):
        projection = project(
            b"one.1.sg\none.1.sg: [12 ms]\n",
            base_contract("raw", 0),
        )
        pointer = (
            "/comparison/streams/stdout/segments/0/records/1/body/text"
        )
        policy = {
            "policy_schema": 1,
            "policy_identity": copy.deepcopy(
                projection["run_identity"]
            ),
            "case_id": projection["case_id"],
            "rules": [
                {
                    "id": "NORM-9001",
                    "json_pointer": pointer,
                    "transform": "profiling_elapsed_ms_v1",
                    "expected_replacements": 1,
                    "expected_normalized_value": (
                        "one.1.sg: [<elapsed> ms]"
                    ),
                    "evidence": (
                        "docs/research/cli-option-behavior.md"
                    ),
                    "contract": "docs/design/testing.md",
                }
            ],
        }
        normalized = NORMALIZER.normalize_projection(
            projection,
            policy,
            "1" * 64,
            "2" * 64,
        )
        self.assertEqual(
            normalized["semantic"]["comparison"]["streams"]["stdout"][
                "segments"
            ][0]["records"][1]["body"]["text"],
            "one.1.sg: [<elapsed> ms]",
        )

    def test_normalized_comparison_excludes_side_specific_raw_evidence(self):
        left = project(
            b"one.1.sg: [9 ms]\nnext\n",
            base_contract("raw", 0),
        )
        right = project(
            b"one.1.sg: [123 ms]\nnext\n",
            base_contract("raw", 0),
        )
        pointer = (
            "/comparison/streams/stdout/segments/0/records/0/body/text"
        )

        def normalize(projection, marker):
            policy = {
                "policy_schema": 1,
                "policy_identity": copy.deepcopy(
                    projection["run_identity"]
                ),
                "case_id": projection["case_id"],
                "rules": [
                    {
                        "id": "NORM-9002",
                        "json_pointer": pointer,
                        "transform": "profiling_elapsed_ms_v1",
                        "expected_replacements": 1,
                        "expected_normalized_value": (
                            "one.1.sg: [<elapsed> ms]"
                        ),
                        "evidence": (
                            "docs/research/cli-option-behavior.md"
                        ),
                        "contract": "docs/design/testing.md",
                    }
                ],
            }
            return NORMALIZER.normalize_projection(
                projection,
                policy,
                marker * 64,
                "3" * 64,
            )

        normalized_left = normalize(left, "1")
        normalized_right = normalize(right, "2")
        self.assertEqual(
            normalized_left["semantic"]["comparison"],
            normalized_right["semantic"]["comparison"],
        )
        self.assertNotEqual(
            normalized_left["semantic"]["evidence"],
            normalized_right["semantic"]["evidence"],
        )

    def test_raw_contract_rejects_unexpected_json_document(self):
        output = project(b'{"detects":[]}', base_contract("raw", 0))
        semantic = output["semantic"]
        self.assertEqual(semantic["result"], "projection_failure")
        self.assertEqual(
            [issue["code"] for issue in semantic["issues"]],
            [
                "unexpected_json_document",
                "document_count_mismatch",
            ],
        )

    def test_document_count_and_framing_limit_are_projection_failures(self):
        output = project(
            b'{"detects":[]}',
            base_contract("normal_scan_json", 2),
        )
        self.assertEqual(
            output["semantic"]["issues"][0]["code"],
            "document_count_mismatch",
        )

        stdout = b'{"detects":[]}'
        contract = MODULE.validate_contract(base_contract())
        execution = RAW.validate_execution(base_execution(stdout))
        audit = verification(execution)
        framing_projection = FRAMING.build_projection(
            execution,
            audit,
            stdout,
        )
        framing_projection["result"] = "projection_limit_reached"
        framing_projection["limits"]["limit_reached"] = True
        framing_projection["limits"]["reasons"] = ["document_bytes"]
        limited = MODULE.build_projection(
            contract,
            RAW.canonical_json(contract),
            execution,
            audit,
            framing_projection,
            {"stdout": stdout, "stderr": b""},
        )
        self.assertEqual(
            limited["semantic"]["issues"][0]["code"],
            "framing_limit_reached",
        )

    def test_contract_rejects_unknowns_raw_documents_and_identity_drift(self):
        mutations = (
            ({"unknown": True}, "unknown fields"),
            ({"contract_schema": True}, "unsupported contract_schema"),
            ({"semantic_schema": 2}, "unsupported semantic_schema"),
            (
                {
                    "output": {
                        "kind": "raw",
                        "expected_json_documents": 1,
                    }
                },
                "must expect zero",
            ),
        )
        for change, message in mutations:
            contract = base_contract()
            contract.update(change)
            with self.subTest(change=change):
                with self.assertRaisesRegex(
                    (MODULE.SemanticProjectionError, RAW.VerificationError),
                    message,
                ):
                    MODULE.validate_contract(contract)

        stdout = b'{"detects":[]}'
        execution = RAW.validate_execution(base_execution(stdout))
        contract = MODULE.validate_contract(base_contract())
        for key, value in (
            ("case_id", "different.case"),
            ("platform", "windows-x86_64"),
            ("case_manifest_sha256", "9" * 64),
            ("upstream_commit", "8" * 40),
        ):
            drifted = copy.deepcopy(contract)
            drifted[key] = value
            with self.subTest(key=key):
                with self.assertRaisesRegex(
                    MODULE.SemanticProjectionError,
                    "does not match",
                ):
                    MODULE.validate_contract_identity(
                        drifted,
                        execution,
                    )

    def test_rust_producer_revision_stays_distinct_from_upstream_target(self):
        stdout = b'{"detects":[]}'
        contract = MODULE.validate_contract(base_contract())
        execution = RAW.validate_execution(
            base_execution(stdout, side="rust")
        )
        MODULE.validate_contract_identity(contract, execution)
        output = project(stdout, side="rust")
        self.assertEqual(
            output["run_identity"]["upstream_commit"],
            UPSTREAM,
        )
        self.assertEqual(
            output["semantic"]["producer"]["revision"],
            "2" * 40,
        )

    def test_project_files_verifies_before_reading_or_projecting(self):
        stdout = b'{"detects":[]}'
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            contract, manifest, artifact_root, _ = write_case(
                directory,
                stdout,
            )
            with mock.patch.object(
                RAW,
                "verify_execution",
                side_effect=RAW.VerificationError("verification stopped"),
            ), mock.patch.object(
                RAW,
                "read_verified_artifact",
            ) as reader:
                with self.assertRaisesRegex(
                    RAW.VerificationError,
                    "verification stopped",
                ):
                    MODULE.project_files(
                        contract,
                        manifest,
                        artifact_root,
                        directory / "output.json",
                        1024,
                    )
                reader.assert_not_called()

    def test_project_files_rejects_overwrite_and_artifact_mutation(self):
        stdout = b'{"detects":[]}'
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            contract, manifest, artifact_root, execution = write_case(
                directory,
                stdout,
            )
            for output in (contract, manifest):
                with self.subTest(output=output):
                    with self.assertRaisesRegex(
                        MODULE.SemanticProjectionError,
                        "must not overwrite",
                    ):
                        MODULE.project_files(
                            contract,
                            manifest,
                            artifact_root,
                            output,
                            1024,
                        )
            stdout_path = (
                artifact_root
                / "sha256"
                / execution["artifacts"]["stdout"]["sha256"]
            )
            stdout_path.write_bytes(b'{"detects":[1]}')
            with self.assertRaisesRegex(
                RAW.VerificationError,
                "size mismatch|SHA-256 mismatch",
            ):
                MODULE.project_files(
                    contract,
                    manifest,
                    artifact_root,
                    directory / "output.json",
                    1024,
                )

    def test_cli_is_deterministic_and_returns_one_for_projection_failure(self):
        stdout = b'{"detects":[]}'
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            contract, manifest, artifact_root, _ = write_case(
                directory,
                stdout,
            )
            output = directory / "output.json"
            command = [
                sys.executable,
                str(MODULE_PATH),
                "--contract",
                str(contract),
                "--manifest",
                str(manifest),
                "--artifact-root",
                str(artifact_root),
                "--max-artifact-bytes",
                "1024",
                "--output",
                str(output),
            ]
            first = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            first_bytes = output.read_bytes()
            output.unlink()
            second = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(output.read_bytes(), first_bytes)
            self.assertNotIn(b"\r\n", first_bytes)

            bad_contract = base_contract("entropy_json")
            contract.write_text(
                json.dumps(bad_contract),
                encoding="utf-8",
            )
            output.unlink()
            failed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(failed.returncode, 1, failed.stderr)
            self.assertEqual(
                json.loads(output.read_text())["semantic"]["result"],
                "projection_failure",
            )

    def test_documentation_example_reproduces_golden(self):
        examples = ROOT / "docs" / "design" / "schemas" / "examples"
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "projection.json"
            projection = MODULE.project_files(
                examples / "semantic-projection-contract-v1.example.json",
                examples / "raw-framing-execution-v1.example.json",
                examples / "raw-artifacts",
                output,
                1024,
            )
            expected = (
                examples
                / "semantic-result-projection-v1.example.json"
            ).read_bytes()
            self.assertEqual(
                MODULE.serialize_projection(projection),
                expected,
            )

    def test_schemas_parse_and_bind_legacy_cli_model(self):
        schemas = ROOT / "docs" / "design" / "schemas"
        contract = json.loads(
            (schemas / "semantic-projection-contract-v1.schema.json")
            .read_text(encoding="utf-8")
        )
        model = json.loads(
            (schemas / "semantic-result-v1.schema.json")
            .read_text(encoding="utf-8")
        )
        projection = json.loads(
            (schemas / "semantic-result-projection-v1.schema.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(contract["properties"]["semantic_schema"], {
            "const": 1
        })
        self.assertIn("normalScan", model["$defs"])
        self.assertIn("entropy", model["$defs"])
        self.assertIn("infoValue", model["$defs"])
        self.assertEqual(
            projection["properties"]["semantic"]["$ref"],
            (
                "https://die-rust.invalid/schemas/"
                "semantic-result-v1.schema.json"
            ),
        )

    def test_documents_link_tool_schemas_inventory_and_remaining_scope(self):
        testing = (
            ROOT / "docs" / "design" / "testing.md"
        ).read_text(encoding="utf-8")
        schema_index = (
            ROOT / "docs" / "design" / "schemas" / "README.md"
        ).read_text(encoding="utf-8")
        compat = (
            ROOT / "tools" / "compat" / "README.md"
        ).read_text(encoding="utf-8")
        research = (
            ROOT / "docs" / "research" / "cli-json-schema-inventory.md"
        ).read_text(encoding="utf-8")
        for name in (
            MODULE_PATH.name,
            "semantic-projection-contract-v1.schema.json",
            "semantic-result-v1.schema.json",
            "semantic-result-projection-v1.schema.json",
        ):
            self.assertIn(name, testing)
            self.assertIn(name, schema_index)
            self.assertIn(name, compat)
        self.assertIn(UPSTREAM, research)
        self.assertIn("scan-node | detection", research)
        self.assertIn("engine-only", testing)
        self.assertIn("双侧 comparator", testing)
        self.assertIn("run_compatibility_suite.py", testing)


if __name__ == "__main__":
    unittest.main()

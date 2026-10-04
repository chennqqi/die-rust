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
MODULE_PATH = COMPAT / "project_raw_framing.py"
sys.path.insert(0, str(COMPAT))
SPEC = importlib.util.spec_from_file_location(
    "project_raw_framing",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
RAW = MODULE.raw_verifier


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def base_execution(stdout, stderr=b""):
    return {
        "execution_schema": 1,
        "run_identity": {
            "case_id": "synthetic.raw-framing",
            "side": "upstream",
            "platform": "linux-x86_64",
            "producer_profile": "cmake-qt5",
            "producer_revision": (
                "74eaf505c250ab47e709024e9dc41657cd8f2254"
            ),
            "case_manifest_sha256": "0" * 64,
            "executable_sha256": "1" * 64,
        },
        "argv": ["diec", "--messages", "--json", "/corpus/input"],
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


def write_case(directory, stdout, stderr=b""):
    execution = base_execution(stdout, stderr)
    artifact_root = directory / "artifacts"
    sha_root = artifact_root / "sha256"
    sha_root.mkdir(parents=True)
    for content in (stdout, stderr):
        (sha_root / sha256(content)).write_bytes(content)
    manifest = directory / "execution.json"
    manifest.write_text(json.dumps(execution), encoding="utf-8")
    return manifest, artifact_root, execution


def assert_segment_hashes(test_case, data, segments):
    offset = 0
    for index, segment in enumerate(segments):
        test_case.assertEqual(segment["index"], index)
        test_case.assertEqual(segment["offset"], offset)
        content = data[offset : offset + segment["size"]]
        test_case.assertEqual(segment["sha256"], sha256(content))
        offset += segment["size"]
    test_case.assertEqual(offset, len(data))


class RawFramingProjectionTests(unittest.TestCase):
    def test_preserves_prefix_document_and_trailing_diagnostic(self):
        prefix = b"one.1.sg\none.1.sg: [12 ms]\n"
        document = b'{"detects":[]}'
        trailing = b"\nthrow.1.sg: ReferenceError\n"
        data = prefix + document + trailing
        segments = MODULE.project_segments(data)

        self.assertEqual(
            [segment["kind"] for segment in segments],
            ["raw", "json_document", "raw"],
        )
        self.assertEqual(
            [(segment["offset"], segment["size"]) for segment in segments],
            [
                (0, len(prefix)),
                (len(prefix), len(document)),
                (len(prefix) + len(document), len(trailing)),
            ],
        )
        self.assertEqual(segments[1]["value"], {"detects": []})
        assert_segment_hashes(self, data, segments)

    def test_balancer_ignores_structural_bytes_inside_strings(self):
        data = (
            b'{"text":"{ [ ] } \\\\ \\\"","nested":[{"v":1}]}'
            b"\ntrailing"
        )
        segments = MODULE.project_segments(data)
        self.assertEqual(
            [segment["kind"] for segment in segments],
            ["json_document", "raw"],
        )
        self.assertEqual(
            segments[0]["value"]["text"],
            '{ [ ] } \\ "',
        )
        assert_segment_hashes(self, data, segments)

    def test_enumerates_multiple_documents_without_dropping_separator(self):
        first = b'{"first":1}'
        separator = b"\nmessage\n"
        second = b'[{"second":2}]'
        data = first + separator + second
        segments = MODULE.project_segments(data)
        self.assertEqual(
            [segment["kind"] for segment in segments],
            ["json_document", "raw", "json_document"],
        )
        self.assertEqual(segments[0]["root_kind"], "object")
        self.assertEqual(segments[2]["root_kind"], "array")
        assert_segment_hashes(self, data, segments)

    def test_embedded_json_text_is_raw_but_next_line_document_is_found(self):
        prefix = b'warning contains {"not":"a document"}\n'
        document = b'{"real":true}'
        data = prefix + document
        segments = MODULE.project_segments(data)
        self.assertEqual(
            [segment["kind"] for segment in segments],
            ["raw", "json_document"],
        )
        self.assertEqual(segments[0]["size"], len(prefix))
        self.assertEqual(segments[1]["value"], {"real": True})

    def test_invalid_balanced_candidate_is_not_mined_for_inner_json(self):
        invalid = b'{invalid: {"inner":1}}\n'
        valid = b'{"outer":2}'
        segments = MODULE.project_segments(invalid + valid)
        self.assertEqual(
            [segment["kind"] for segment in segments],
            ["raw", "json_document"],
        )
        self.assertEqual(segments[0]["size"], len(invalid))
        self.assertEqual(segments[1]["value"], {"outer": 2})

    def test_unterminated_candidates_advance_to_eof_once(self):
        data = b"{\n" * 1000
        with mock.patch.object(
            MODULE,
            "scan_balanced_document",
            wraps=MODULE.scan_balanced_document,
        ) as scanner:
            segments = MODULE.project_segments(data)
        self.assertEqual(scanner.call_count, 1)
        self.assertEqual(segments[0]["kind"], "raw")
        self.assertEqual(segments[0]["size"], len(data))

    def test_projection_limits_preserve_remainder_as_raw(self):
        with mock.patch.object(MODULE, "MAX_JSON_NESTING", 2):
            data = b'[[[{"deep":true}]]]'
            segments, reasons = MODULE.project_segments_with_limits(data)
            self.assertEqual(reasons, ["nesting"])
            self.assertEqual(segments[0]["kind"], "raw")
            self.assertEqual(segments[0]["size"], len(data))

        with mock.patch.object(MODULE, "MAX_JSON_DOCUMENT_BYTES", 5):
            data = b'{"too":"large"}\n{"ok":1}'
            segments, reasons = MODULE.project_segments_with_limits(data)
            self.assertEqual(reasons, ["document_bytes"])
            self.assertEqual(
                [segment["kind"] for segment in segments],
                ["raw"],
            )
            self.assertEqual(segments[0]["size"], len(data))

        with mock.patch.object(MODULE, "MAX_JSON_DOCUMENTS", 1):
            data = b'{"first":1}\n{"second":2}'
            segments, reasons = MODULE.project_segments_with_limits(data)
            self.assertEqual(reasons, ["document_count"])
            self.assertEqual(
                [segment["kind"] for segment in segments],
                ["json_document", "raw"],
            )
            assert_segment_hashes(self, data, segments)

    def test_parser_recursion_failure_remains_raw(self):
        data = b'{"value":[]}'
        with mock.patch.object(
            MODULE.json,
            "loads",
            side_effect=RecursionError,
        ):
            segments = MODULE.project_segments(data)
        self.assertEqual(segments[0]["kind"], "raw")
        self.assertEqual(segments[0]["size"], len(data))

    def test_duplicate_nonfinite_scalar_and_invalid_utf8_remain_raw(self):
        cases = (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b"123",
            b"\xff{\"a\":1}",
            b'{"unterminated":',
        )
        for data in cases:
            with self.subTest(data=data):
                segments = MODULE.project_segments(data)
                self.assertEqual(len(segments), 1)
                self.assertEqual(segments[0]["kind"], "raw")
                self.assertEqual(segments[0]["size"], len(data))

    def test_empty_stream_has_empty_lossless_projection(self):
        self.assertEqual(MODULE.project_segments(b""), [])
        MODULE.validate_coverage([], 0)

    def test_coverage_validator_rejects_gap_overlap_and_zero_size(self):
        base = [
            {
                "index": 0,
                "kind": "raw",
                "offset": 0,
                "size": 2,
                "sha256": "0" * 64,
            }
        ]
        mutations = (
            ({"index": 1}, "indexes"),
            ({"offset": 1}, "ranges"),
            ({"size": 0}, "positive"),
        )
        for change, message in mutations:
            segments = copy.deepcopy(base)
            segments[0].update(change)
            with self.subTest(change=change):
                with self.assertRaisesRegex(
                    MODULE.FramingError,
                    message,
                ):
                    MODULE.validate_coverage(segments, 2)
        with self.assertRaisesRegex(
            MODULE.FramingError,
            "complete stream",
        ):
            MODULE.validate_coverage(base, 3)

    def test_build_projection_binds_verification_and_segment_hashes(self):
        stdout = b'prefix\n{"value":1}\n'
        execution = RAW.validate_execution(base_execution(stdout))
        verification = {
            "verification_schema": 1,
            "verifier": {
                "name": RAW.VERIFIER_NAME,
                "version": RAW.VERIFIER_VERSION,
            },
            "result": "pass",
            "run_identity": execution["run_identity"],
            "manifest_artifact": {
                "sha256": "2" * 64,
                "canonical_execution_sha256": "3" * 64,
            },
            "verification_budget_bytes": 1024,
            "verified_total_bytes": len(stdout),
            "artifacts": {
                "stdout": {
                    "relative_path": (
                        f"sha256/{sha256(stdout)}"
                    ),
                    "sha256": sha256(stdout),
                    "size": len(stdout),
                },
                "stderr": {
                    "relative_path": (
                        f"sha256/{sha256(b'')}"
                    ),
                    "sha256": sha256(b""),
                    "size": 0,
                },
            },
        }
        projection = MODULE.build_projection(
            execution,
            verification,
            stdout,
        )
        self.assertEqual(projection["result"], "documents_found")
        self.assertEqual(
            projection["execution_verification_sha256"],
            sha256(RAW.serialize_verification(verification)),
        )
        self.assertEqual(
            projection["segments_sha256"],
            sha256(RAW.canonical_json(projection["segments"])),
        )
        self.assertEqual(
            projection["coverage"],
            {
                "bytes": len(stdout),
                "segment_count": 3,
                "raw_segment_count": 2,
                "json_document_count": 1,
            },
        )
        self.assertEqual(
            projection["limits"],
            {
                "max_json_document_bytes": (
                    MODULE.MAX_JSON_DOCUMENT_BYTES
                ),
                "max_json_documents": MODULE.MAX_JSON_DOCUMENTS,
                "max_json_nesting": MODULE.MAX_JSON_NESTING,
                "limit_reached": False,
                "reasons": [],
            },
        )

    def test_no_document_is_explicit_not_empty_success(self):
        stdout = b"diagnostic only\n"
        execution = RAW.validate_execution(base_execution(stdout))
        verification = {
            "verification_schema": 1,
            "verifier": {
                "name": RAW.VERIFIER_NAME,
                "version": RAW.VERIFIER_VERSION,
            },
            "result": "pass",
            "run_identity": execution["run_identity"],
            "manifest_artifact": {
                "sha256": "2" * 64,
                "canonical_execution_sha256": "3" * 64,
            },
            "verification_budget_bytes": 1024,
            "verified_total_bytes": len(stdout),
            "artifacts": {},
        }
        projection = MODULE.build_projection(
            execution,
            verification,
            stdout,
        )
        self.assertEqual(projection["result"], "no_json_document")
        self.assertEqual(projection["coverage"]["raw_segment_count"], 1)
        self.assertEqual(projection["coverage"]["json_document_count"], 0)

    def test_build_projection_reports_limits_as_non_success(self):
        stdout = b'{"first":1}\n{"second":2}'
        execution = RAW.validate_execution(base_execution(stdout))
        verification = {
            "verification_schema": 1,
            "verifier": {
                "name": RAW.VERIFIER_NAME,
                "version": RAW.VERIFIER_VERSION,
            },
            "result": "pass",
            "run_identity": execution["run_identity"],
            "manifest_artifact": {
                "sha256": "2" * 64,
                "canonical_execution_sha256": "3" * 64,
            },
            "verification_budget_bytes": 1024,
            "verified_total_bytes": len(stdout),
            "artifacts": {},
        }
        with mock.patch.object(MODULE, "MAX_JSON_DOCUMENTS", 1):
            projection = MODULE.build_projection(
                execution,
                verification,
                stdout,
            )
        self.assertEqual(
            projection["result"],
            "projection_limit_reached",
        )
        self.assertTrue(projection["limits"]["limit_reached"])
        self.assertEqual(
            projection["limits"]["reasons"],
            ["document_count"],
        )

    def test_project_files_rehashes_before_reading_stdout(self):
        stdout = b'{"value":1}\n'
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            manifest, artifact_root, _ = write_case(directory, stdout)
            failure = RAW.VerificationError("verification stopped")
            with mock.patch.object(
                RAW,
                "verify_execution",
                side_effect=failure,
            ), mock.patch.object(
                RAW,
                "read_verified_artifact",
            ) as reader:
                with self.assertRaisesRegex(
                    RAW.VerificationError,
                    "verification stopped",
                ):
                    MODULE.project_files(
                        manifest,
                        artifact_root,
                        directory / "projection.json",
                        1024,
                    )
                reader.assert_not_called()

    def test_project_files_rejects_hash_mismatch_and_source_overwrite(self):
        stdout = b'{"value":1}\n'
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            manifest, artifact_root, execution = write_case(
                directory,
                stdout,
            )
            stdout_path = (
                artifact_root
                / "sha256"
                / execution["artifacts"]["stdout"]["sha256"]
            )
            stdout_path.write_bytes(b'{"value":2}\n')
            with self.assertRaisesRegex(
                RAW.VerificationError,
                "SHA-256 mismatch",
            ):
                MODULE.project_files(
                    manifest,
                    artifact_root,
                    directory / "projection.json",
                    1024,
                )

        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            manifest, artifact_root, execution = write_case(
                directory,
                stdout,
            )
            stdout_path = (
                artifact_root
                / "sha256"
                / execution["artifacts"]["stdout"]["sha256"]
            )
            for output in (manifest, stdout_path):
                with self.subTest(output=output):
                    with self.assertRaisesRegex(
                        MODULE.FramingError,
                        "must not overwrite",
                    ):
                        MODULE.project_files(
                            manifest,
                            artifact_root,
                            output,
                            1024,
                        )

    def test_cli_writes_deterministic_projection_and_preserves_sources(self):
        stdout = b'prefix\n{"value":1}\ntrailing\n'
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            manifest, artifact_root, execution = write_case(
                directory,
                stdout,
            )
            output = directory / "projection.json"
            stdout_path = (
                artifact_root
                / "sha256"
                / execution["artifacts"]["stdout"]["sha256"]
            )
            manifest_bytes = manifest.read_bytes()
            stdout_bytes = stdout_path.read_bytes()
            process = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--manifest",
                    str(manifest),
                    "--artifact-root",
                    str(artifact_root),
                    "--output",
                    str(output),
                    "--max-artifact-bytes",
                    "1024",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(manifest.read_bytes(), manifest_bytes)
            self.assertEqual(stdout_path.read_bytes(), stdout_bytes)
            self.assertNotIn(b"\r\n", output.read_bytes())
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["result"],
                "documents_found",
            )

    def test_schema_parses_and_references_raw_verification_contract(self):
        schema_path = (
            ROOT
            / "docs"
            / "design"
            / "schemas"
            / "raw-framing-projection-v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(
            schema["properties"]["execution_verification"]["$ref"],
            (
                "https://die-rust.invalid/schemas/"
                "raw-execution-verification-v1.schema.json"
            ),
        )
        self.assertEqual(
            schema["properties"]["result"]["enum"],
            [
                "documents_found",
                "no_json_document",
                "projection_limit_reached",
            ],
        )

    def test_documentation_example_reproduces_golden_projection(self):
        examples = ROOT / "docs" / "design" / "schemas" / "examples"
        manifest = examples / "raw-framing-execution-v1.example.json"
        artifact_root = examples / "raw-artifacts"
        expected = examples / "raw-framing-projection-v1.example.json"
        manifest_bytes = RAW.read_stable_manifest(manifest)
        execution = RAW.validate_execution(
            RAW.load_json_bytes(manifest_bytes, "manifest")
        )
        verification = RAW.verify_execution(
            execution,
            RAW.sha256_bytes(manifest_bytes),
            artifact_root.resolve(),
            1024,
        )
        reference = execution["artifacts"]["stdout"]
        stdout = RAW.read_verified_artifact(
            RAW.resolve_artifact_path(
                artifact_root.resolve(),
                reference["sha256"],
            ),
            reference["sha256"],
            reference["size"],
            1024,
        )
        projection = MODULE.build_projection(
            execution,
            verification,
            stdout,
        )
        self.assertEqual(
            MODULE.serialize_projection(projection),
            expected.read_bytes(),
        )

    def test_documents_link_projector_schema_and_remaining_scope(self):
        testing = (
            ROOT / "docs" / "design" / "testing.md"
        ).read_text(encoding="utf-8")
        index = (
            ROOT / "docs" / "design" / "schemas" / "README.md"
        ).read_text(encoding="utf-8")
        compat = (
            ROOT / "tools" / "compat" / "README.md"
        ).read_text(encoding="utf-8")
        for name in (
            MODULE_PATH.name,
            "raw-framing-projection-v1.schema.json",
        ):
            self.assertIn(name, testing)
            self.assertIn(name, index)
            self.assertIn(name, compat)
        self.assertIn("完整 semantic model", testing)
        self.assertIn("run_compatibility_suite.py", testing)


if __name__ == "__main__":
    unittest.main()

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
MODULE_PATH = COMPAT / "compare_semantic_results.py"
sys.path.insert(0, str(COMPAT))
SPEC = importlib.util.spec_from_file_location(
    "compare_semantic_results",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
RAW = MODULE.raw_verifier
WAIVERS = MODULE.waiver_validator
UPSTREAM = "74eaf505c250ab47e709024e9dc41657cd8f2254"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def projection_contract():
    return {
        "contract_schema": 1,
        "case_id": "synthetic.compare",
        "platform": "linux-x86_64",
        "oracle_profile": "cmake-qt5",
        "upstream_commit": UPSTREAM,
        "case_manifest_sha256": "0" * 64,
        "semantic_schema": 1,
        "output": {
            "kind": "normal_scan_json",
            "expected_json_documents": 1,
        },
    }


def execution(stdout, side, stderr=b""):
    return {
        "execution_schema": 1,
        "run_identity": {
            "case_id": "synthetic.compare",
            "side": side,
            "platform": "linux-x86_64",
            "producer_profile": (
                "cmake-qt5" if side == "upstream" else "rust-debug"
            ),
            "producer_revision": (
                UPSTREAM if side == "upstream" else "2" * 40
            ),
            "case_manifest_sha256": "0" * 64,
            "executable_sha256": (
                "1" * 64 if side == "upstream" else "2" * 64
            ),
        },
        "argv": ["diec", "--json", "/corpus/input"],
        "environment": {"LC_ALL": "C", "TZ": "UTC"},
        "logical_cwd": "/work",
        "termination": {"kind": "exit", "code": 0},
        "wall_time_ns": 1,
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


def write_execution(directory, stdout, side, stderr=b""):
    directory.mkdir()
    artifact_root = directory / "artifacts"
    sha_root = artifact_root / "sha256"
    sha_root.mkdir(parents=True)
    for content in (stdout, stderr):
        (sha_root / sha256(content)).write_bytes(content)
    manifest = directory / "execution.json"
    manifest.write_text(
        json.dumps(execution(stdout, side, stderr)),
        encoding="utf-8",
    )
    return manifest, artifact_root


def normalization_policy():
    return {
        "policy_schema": 1,
        "policy_identity": {
            "platform": "linux-x86_64",
            "oracle_profile": "cmake-qt5",
            "upstream_commit": UPSTREAM,
            "semantic_schema": 1,
        },
        "case_id": "synthetic.compare",
        "rules": [
            {
                "id": "NORM-9001",
                "json_pointer": (
                    "/comparison/streams/stdout/segments/0/"
                    "records/0/body/text"
                ),
                "transform": "profiling_elapsed_ms_v1",
                "expected_replacements": 1,
                "expected_normalized_value": "sig: [<elapsed> ms]",
                "evidence": "docs/research/cli-option-behavior.md",
                "contract": "docs/design/testing.md",
            }
        ],
    }


def write_json(path, value):
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path.read_bytes()


def prepare_case(
    directory,
    upstream_stdout,
    rust_stdout,
    *,
    required="exact",
    policy=None,
    upstream_stderr=b"",
    rust_stderr=b"",
):
    directory = pathlib.Path(directory)
    projection_path = directory / "projection-contract.json"
    projection_bytes = write_json(
        projection_path,
        projection_contract(),
    )
    policy_path = None
    policy_bytes = None
    if policy is not None:
        policy_path = directory / "normalization-policy.json"
        policy_bytes = write_json(policy_path, policy)
    comparison_path = directory / "comparison-contract.json"
    comparison_contract = {
        "comparison_contract_schema": 1,
        "projection_contract_sha256": sha256(projection_bytes),
        "normalization_policy_sha256": (
            None if policy_bytes is None else sha256(policy_bytes)
        ),
        "required_equivalence": required,
        "max_differences": MODULE.MAX_DIFFERENCES,
    }
    write_json(comparison_path, comparison_contract)
    upstream_manifest, upstream_root = write_execution(
        directory / "upstream",
        upstream_stdout,
        "upstream",
        upstream_stderr,
    )
    rust_manifest, rust_root = write_execution(
        directory / "rust",
        rust_stdout,
        "rust",
        rust_stderr,
    )
    outputs = {
        "upstream_projection": directory / "upstream-projection.json",
        "rust_projection": directory / "rust-projection.json",
        "comparison": directory / "comparison.json",
        "differences": directory / "differences.json",
        "upstream_normalization": (
            None
            if policy is None
            else directory / "upstream-normalization.json"
        ),
        "rust_normalization": (
            None
            if policy is None
            else directory / "rust-normalization.json"
        ),
    }
    return {
        "comparison_contract": comparison_path,
        "projection_contract": projection_path,
        "policy": policy_path,
        "upstream_manifest": upstream_manifest,
        "upstream_root": upstream_root,
        "rust_manifest": rust_manifest,
        "rust_root": rust_root,
        "outputs": outputs,
    }


def compare_prepared(prepared):
    outputs = prepared["outputs"]
    return MODULE.compare_files(
        prepared["comparison_contract"],
        prepared["projection_contract"],
        prepared["upstream_manifest"],
        prepared["upstream_root"],
        prepared["rust_manifest"],
        prepared["rust_root"],
        outputs["upstream_projection"],
        outputs["rust_projection"],
        prepared["policy"],
        outputs["upstream_normalization"],
        outputs["rust_normalization"],
        outputs["comparison"],
        outputs["differences"],
        4096,
        ROOT,
    )


class SemanticComparisonTests(unittest.TestCase):
    def test_contract_is_closed_and_binds_policy_and_limit(self):
        valid = {
            "comparison_contract_schema": 1,
            "projection_contract_sha256": "1" * 64,
            "normalization_policy_sha256": None,
            "required_equivalence": "exact",
            "max_differences": MODULE.MAX_DIFFERENCES,
        }
        self.assertEqual(
            MODULE.validate_comparison_contract(valid),
            valid,
        )
        mutations = (
            ({"unknown": True}, "unknown fields"),
            (
                {"comparison_contract_schema": True},
                "unsupported comparison_contract_schema",
            ),
            ({"required_equivalence": "close"}, "unsupported"),
            ({"max_differences": 9999}, "must be 10000"),
            (
                {"normalization_policy_sha256": "ABC"},
                "lowercase SHA-256",
            ),
        )
        for change, message in mutations:
            value = copy.deepcopy(valid)
            value.update(change)
            with self.subTest(change=change):
                with self.assertRaisesRegex(
                    (
                        MODULE.ComparisonError,
                        RAW.VerificationError,
                    ),
                    message,
                ):
                    MODULE.validate_comparison_contract(value)

    def test_json_diff_is_ordered_pointer_exact_and_presence_aware(self):
        upstream = {
            "b": [True, "old", "upstream-only"],
            "a/b~c": {"value": 1},
        }
        rust = {
            "b": [1, "new"],
            "a/b~c": {"value": 2},
            "rust-only": None,
        }
        differences = []
        MODULE.compare_values(
            upstream,
            rust,
            "",
            differences,
            "synthetic.compare",
            "1" * 64,
            "2" * 64,
        )
        self.assertEqual(
            [item["json_pointer"] for item in differences],
            [
                "/a~1b~0c/value",
                "/b/0",
                "/b/1",
                "/b/2",
                "/rust-only",
            ],
        )
        self.assertEqual(
            differences[-2]["rust_value"],
            {"state": "missing"},
        )
        self.assertEqual(
            differences[-1]["upstream_value"],
            {"state": "missing"},
        )
        for item in differences:
            self.assertEqual(
                item["diff_fingerprint"],
                WAIVERS.difference_fingerprint(item),
            )

    def test_json_diff_treats_numeric_forms_equal_but_bool_distinct(self):
        differences = []
        MODULE.compare_values(
            {"number": 1, "boolean": True},
            {"number": 1.0, "boolean": 1},
            "",
            differences,
            "synthetic.compare",
            "1" * 64,
            "2" * 64,
        )
        self.assertEqual(
            [item["json_pointer"] for item in differences],
            ["/boolean"],
        )

    def test_difference_limit_never_returns_a_partial_success(self):
        differences = []
        with self.assertRaisesRegex(
            MODULE.DifferenceLimitReached,
            "exceed",
        ):
            MODULE.compare_values(
                [1, 2],
                [3, 4],
                "/items",
                differences,
                "synthetic.compare",
                "1" * 64,
                "2" * 64,
                max_differences=1,
            )
        self.assertEqual(len(differences), 1)

    def test_exact_raw_and_semantic_results_pass_exact_requirement(self):
        stdout = b'{"detects":[]}'
        with tempfile.TemporaryDirectory() as temporary:
            prepared = prepare_case(
                temporary,
                stdout,
                stdout,
            )
            report, difference_report = compare_prepared(prepared)
            self.assertEqual(report["result"], "exact")
            self.assertTrue(report["requirement"]["met"])
            self.assertTrue(report["raw_equality"]["all"])
            self.assertEqual(difference_report["differences"], [])
            self.assertNotEqual(
                report["inputs"]["upstream"]["projection"][
                    "artifact_sha256"
                ],
                report["inputs"]["rust"]["projection"][
                    "artifact_sha256"
                ],
            )
            self.assertEqual(
                report["inputs"]["upstream"]["comparison_sha256"],
                report["inputs"]["rust"]["comparison_sha256"],
            )

    def test_semantic_equal_raw_formatting_fails_exact_requirement(self):
        upstream = b'{"detects":[]}'
        rust = b'{\n  "detects": []\n}'
        with tempfile.TemporaryDirectory() as temporary:
            prepared = prepare_case(temporary, upstream, rust)
            report, difference_report = compare_prepared(prepared)
            self.assertEqual(report["result"], "semantic_equal")
            self.assertFalse(report["requirement"]["met"])
            self.assertFalse(report["raw_equality"]["stdout"])
            self.assertEqual(difference_report["differences"], [])

    def test_semantic_requirement_accepts_audited_normalization(self):
        upstream = b'sig: [9 ms]\n{"detects":[]}'
        rust = b'sig: [123 ms]\n{"detects":[]}'
        with tempfile.TemporaryDirectory() as temporary:
            prepared = prepare_case(
                temporary,
                upstream,
                rust,
                required="semantic",
                policy=normalization_policy(),
            )
            report, difference_report = compare_prepared(prepared)
            self.assertEqual(report["result"], "semantic_equal")
            self.assertTrue(report["requirement"]["met"])
            self.assertFalse(report["raw_equality"]["stdout"])
            self.assertEqual(difference_report["differences"], [])
            for side in ("upstream", "rust"):
                normalization = report["inputs"][side]["normalization"]
                self.assertEqual(normalization["kind"], "applied")
                self.assertEqual(
                    normalization["rules_applied"][0]["id"],
                    "NORM-9001",
                )
                self.assertTrue(
                    prepared["outputs"][
                        f"{side}_normalization"
                    ].is_file()
                )

    def test_semantic_mismatch_emits_waiver_compatible_report(self):
        upstream = (
            b'{"detects":[{"filetype":"Binary","info":"",'
            b'"offset":"0","parentfilepart":"Header","size":"1",'
            b'"values":[{"info":"","name":"A","string":"Format: A",'
            b'"type":"format","version":""}]}]}'
        )
        rust = upstream.replace(
            b'"name":"A"',
            b'"name":"B"',
        ).replace(
            b'"string":"Format: A"',
            b'"string":"Format: B"',
        )
        with tempfile.TemporaryDirectory() as temporary:
            prepared = prepare_case(temporary, upstream, rust)
            report, difference_report = compare_prepared(prepared)
            self.assertEqual(report["result"], "different")
            self.assertFalse(report["requirement"]["met"])
            self.assertEqual(
                [
                    item["json_pointer"]
                    for item in difference_report["differences"]
                ],
                [
                    (
                        "/comparison/streams/stdout/segments/0/document/"
                        "items/0/values/0/display"
                    ),
                    (
                        "/comparison/streams/stdout/segments/0/document/"
                        "items/0/values/0/name"
                    ),
                ],
            )
            validated = WAIVERS.validate_report(difference_report)
            self.assertEqual(
                len(validated["differences"]),
                2,
            )
            self.assertEqual(
                report["difference_report_artifact"]["sha256"],
                sha256(
                    prepared["outputs"]["differences"].read_bytes()
                ),
            )

    def test_projection_failure_is_not_a_waivable_empty_report(self):
        invalid_shape = b'{"unexpected":true}'
        with tempfile.TemporaryDirectory() as temporary:
            prepared = prepare_case(
                temporary,
                invalid_shape,
                invalid_shape,
            )
            report, difference_report = compare_prepared(prepared)
            self.assertEqual(report["result"], "projection_failure")
            self.assertFalse(report["requirement"]["met"])
            self.assertEqual(difference_report["result"], "blocked")
            self.assertEqual(
                difference_report["reason"],
                "projection_failure",
            )
            self.assertEqual(
                report["difference_report_artifact"]["kind"],
                "blocked",
            )
            self.assertTrue(prepared["outputs"]["differences"].is_file())
            with self.assertRaises(WAIVERS.ValidationError):
                WAIVERS.validate_report(difference_report)

    def test_projection_failure_skips_configured_normalization(self):
        invalid_shape = b'{"unexpected":true}'
        with tempfile.TemporaryDirectory() as temporary:
            prepared = prepare_case(
                temporary,
                invalid_shape,
                invalid_shape,
                policy=normalization_policy(),
            )
            report, difference_report = compare_prepared(prepared)
            self.assertEqual(report["result"], "projection_failure")
            self.assertEqual(difference_report["result"], "blocked")
            for side in ("upstream", "rust"):
                self.assertEqual(
                    report["inputs"][side]["normalization"],
                    {
                        "kind": "skipped",
                        "reason": "projection_failure",
                    },
                )
                self.assertFalse(
                    prepared["outputs"][
                        f"{side}_normalization"
                    ].exists()
                )

    def test_contract_hashes_and_normalization_arguments_are_mandatory(self):
        stdout = b'{"detects":[]}'
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            prepared = prepare_case(directory, stdout, stdout)
            contract = json.loads(
                prepared["comparison_contract"].read_text()
            )
            contract["projection_contract_sha256"] = "9" * 64
            write_json(prepared["comparison_contract"], contract)
            with self.assertRaisesRegex(
                MODULE.ComparisonError,
                "projection contract hash",
            ):
                compare_prepared(prepared)

        with tempfile.TemporaryDirectory() as temporary:
            prepared = prepare_case(
                temporary,
                stdout,
                stdout,
                policy=normalization_policy(),
            )
            prepared["policy"] = None
            with self.assertRaisesRegex(
                MODULE.ComparisonError,
                "require a normalization policy",
            ):
                compare_prepared(prepared)

    def test_outputs_cannot_collide_or_enter_artifact_roots(self):
        stdout = b'{"detects":[]}'
        with tempfile.TemporaryDirectory() as temporary:
            prepared = prepare_case(temporary, stdout, stdout)
            prepared["outputs"]["comparison"] = prepared[
                "projection_contract"
            ]
            with self.assertRaisesRegex(
                MODULE.ComparisonError,
                "overwrite",
            ):
                compare_prepared(prepared)

        with tempfile.TemporaryDirectory() as temporary:
            prepared = prepare_case(temporary, stdout, stdout)
            prepared["outputs"]["comparison"] = (
                prepared["upstream_root"] / "comparison.json"
            )
            with self.assertRaisesRegex(
                MODULE.ComparisonError,
                "artifact root",
            ):
                compare_prepared(prepared)

    def test_verification_failure_stops_before_rust_projection(self):
        stdout = b'{"detects":[]}'
        with tempfile.TemporaryDirectory() as temporary:
            prepared = prepare_case(temporary, stdout, stdout)
            with mock.patch.object(
                MODULE.projector,
                "project_files",
                side_effect=RAW.VerificationError("rehash failed"),
            ) as project_files:
                with self.assertRaisesRegex(
                    RAW.VerificationError,
                    "rehash failed",
                ):
                    compare_prepared(prepared)
                self.assertEqual(project_files.call_count, 1)

    def test_cli_exit_codes_distinguish_requirement_and_infrastructure(self):
        upstream = b'{"detects":[]}'
        rust = b'{\n"detects":[]\n}'
        with tempfile.TemporaryDirectory() as temporary:
            prepared = prepare_case(temporary, upstream, rust)
            outputs = prepared["outputs"]
            command = [
                sys.executable,
                str(MODULE_PATH),
                "--comparison-contract",
                str(prepared["comparison_contract"]),
                "--projection-contract",
                str(prepared["projection_contract"]),
                "--upstream-manifest",
                str(prepared["upstream_manifest"]),
                "--upstream-artifact-root",
                str(prepared["upstream_root"]),
                "--rust-manifest",
                str(prepared["rust_manifest"]),
                "--rust-artifact-root",
                str(prepared["rust_root"]),
                "--upstream-projection-output",
                str(outputs["upstream_projection"]),
                "--rust-projection-output",
                str(outputs["rust_projection"]),
                "--comparison-output",
                str(outputs["comparison"]),
                "--difference-report-output",
                str(outputs["differences"]),
                "--max-artifact-bytes",
                "4096",
            ]
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(process.returncode, 1, process.stderr)

            contract = json.loads(
                prepared["comparison_contract"].read_text()
            )
            contract["projection_contract_sha256"] = "9" * 64
            write_json(prepared["comparison_contract"], contract)
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(process.returncode, 2)
            self.assertIn("semantic comparison error", process.stderr)

    def test_documentation_example_reproduces_all_four_golden_outputs(self):
        examples = ROOT / "docs" / "design" / "schemas" / "examples"
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            outputs = {
                "upstream": directory / "upstream.json",
                "rust": directory / "rust.json",
                "comparison": directory / "comparison.json",
                "differences": directory / "differences.json",
            }
            MODULE.compare_files(
                examples / "semantic-comparison-contract-v1.example.json",
                examples / "semantic-projection-contract-v1.example.json",
                examples / "raw-framing-execution-v1.example.json",
                examples / "raw-artifacts",
                (
                    examples
                    / "semantic-comparison-rust-execution-v1.example.json"
                ),
                examples / "raw-artifacts",
                outputs["upstream"],
                outputs["rust"],
                None,
                None,
                None,
                outputs["comparison"],
                outputs["differences"],
                1024,
                ROOT,
            )
            expected_names = {
                "upstream": (
                    "semantic-comparison-upstream-projection-v1."
                    "example.json"
                ),
                "rust": (
                    "semantic-comparison-rust-projection-v1.example.json"
                ),
                "comparison": "semantic-comparison-v1.example.json",
                "differences": (
                    "semantic-comparison-difference-report-v1.example.json"
                ),
            }
            for key, expected_name in expected_names.items():
                with self.subTest(key=key):
                    self.assertEqual(
                        outputs[key].read_bytes(),
                        (examples / expected_name).read_bytes(),
                    )

    def test_schemas_parse_and_bind_existing_pipeline_contracts(self):
        schemas = ROOT / "docs" / "design" / "schemas"
        contract = json.loads(
            (schemas / "semantic-comparison-contract-v1.schema.json")
            .read_text(encoding="utf-8")
        )
        report = json.loads(
            (schemas / "semantic-comparison-v1.schema.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            contract["properties"]["max_differences"],
            {"const": MODULE.MAX_DIFFERENCES},
        )
        self.assertEqual(
            report["properties"]["run_identity"]["$ref"],
            (
                "https://die-rust.invalid/schemas/"
                "semantic-projection-v1.schema.json#/$defs/runIdentity"
            ),
        )
        self.assertIn("normalization", report["$defs"])
        self.assertIn("differenceArtifact", report["$defs"])
        self.assertIn("blockedDifferenceArtifact", report["$defs"])
        blocked = json.loads(
            (schemas / "semantic-difference-blocked-v1.schema.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            blocked["properties"]["blocked_schema"],
            {"const": MODULE.BLOCKED_DIFFERENCE_SCHEMA_VERSION},
        )


if __name__ == "__main__":
    unittest.main()

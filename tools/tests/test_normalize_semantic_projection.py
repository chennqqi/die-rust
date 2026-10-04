import copy
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "compat" / "normalize_semantic_projection.py"
SPEC = importlib.util.spec_from_file_location(
    "normalize_semantic_projection",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

IDENTITY = {
    "platform": "linux-x86_64",
    "oracle_profile": "cmake-qt5",
    "upstream_commit": "74eaf505c250ab47e709024e9dc41657cd8f2254",
    "semantic_schema": 1,
}


def base_projection():
    return {
        "projection_schema": 1,
        "run_identity": copy.deepcopy(IDENTITY),
        "case_id": "synthetic.normalization",
        "semantic": {
            "diagnostics": [
                {
                    "message": (
                        "PE_Script(0x7ffABC): ReferenceError"
                    )
                }
            ],
            "profiling": ["one.1.sg: [12 ms]"],
            "detections": [
                {"name": "First", "offset": 16},
                {"name": "Second", "offset": 8},
            ],
        },
    }


def base_policy():
    return {
        "policy_schema": 1,
        "policy_identity": copy.deepcopy(IDENTITY),
        "case_id": "synthetic.normalization",
        "rules": [
            {
                "id": "NORM-0001",
                "json_pointer": "/diagnostics/0/message",
                "transform": "qobject_address_v1",
                "expected_replacements": 1,
                "expected_normalized_value": (
                    "PE_Script(<address>): ReferenceError"
                ),
                "evidence": (
                    "docs/research/"
                    "format-host-api-runtime-differential.md"
                ),
                "contract": "docs/design/testing.md",
            },
            {
                "id": "NORM-0002",
                "json_pointer": "/profiling/0",
                "transform": "profiling_elapsed_ms_v1",
                "expected_replacements": 1,
                "expected_normalized_value": (
                    "one.1.sg: [<elapsed> ms]"
                ),
                "evidence": "docs/research/cli-option-behavior.md",
                "contract": "docs/design/testing.md",
            },
        ],
    }


class SemanticNormalizationTests(unittest.TestCase):
    def normalize(self, projection=None, policy=None):
        projection = projection or base_projection()
        policy = policy or base_policy()
        validated_projection = MODULE.validate_input(projection)
        validated_policy = MODULE.validate_policy(policy, ROOT)
        return MODULE.normalize_projection(
            validated_projection,
            validated_policy,
            "1" * 64,
            "2" * 64,
        )

    def test_applies_only_two_approved_transforms(self):
        projection = base_projection()
        original = copy.deepcopy(projection)
        output = self.normalize(projection)

        self.assertEqual(
            output["semantic"]["diagnostics"][0]["message"],
            "PE_Script(<address>): ReferenceError",
        )
        self.assertEqual(
            output["semantic"]["profiling"][0],
            "one.1.sg: [<elapsed> ms]",
        )
        self.assertEqual(
            output["semantic"]["detections"],
            original["semantic"]["detections"],
        )
        self.assertEqual(projection, original)
        self.assertEqual(
            [rule["transform"] for rule in output["rules_applied"]],
            [
                "qobject_address_v1",
                "profiling_elapsed_ms_v1",
            ],
        )

    def test_qobject_transform_preserves_surrounding_text_and_colons(self):
        value = (
            "prefix NS::PE_Script(0xA0) and "
            "Other_2(0x0f) suffix"
        )
        normalized, replacements = MODULE.normalize_qobject_address(value)
        self.assertEqual(replacements, 2)
        self.assertEqual(
            normalized,
            (
                "prefix NS::PE_Script(<address>) and "
                "Other_2(<address>) suffix"
            ),
        )

    def test_profiling_transform_requires_one_complete_line(self):
        self.assertEqual(
            MODULE.normalize_profiling_elapsed("one.1.sg: [0 ms]"),
            ("one.1.sg: [<elapsed> ms]", 1),
        )
        for value in (
            "one.1.sg [0 ms]",
            "one.1.sg: [-1 ms]",
            "one.1.sg: [0.1 ms]",
            "one.1.sg: [0 ms]\ntrailing",
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    MODULE.normalize_profiling_elapsed(value),
                    (value, 0),
                )

    def test_rejects_replacement_count_drift(self):
        policy = base_policy()
        policy["rules"][0]["expected_replacements"] = 2
        with self.assertRaisesRegex(
            MODULE.NormalizationError,
            "expected 2 replacement",
        ):
            self.normalize(policy=policy)

    def test_rejects_normalized_text_drift(self):
        projection = base_projection()
        projection["semantic"]["diagnostics"][0]["message"] += " changed"
        with self.assertRaisesRegex(
            MODULE.NormalizationError,
            "normalized value does not match policy",
        ):
            self.normalize(projection=projection)

    def test_rejects_unknown_transform_and_fields(self):
        policy = base_policy()
        policy["rules"][0]["transform"] = "regex_replace"
        with self.assertRaisesRegex(
            MODULE.NormalizationError,
            "not approved",
        ):
            MODULE.validate_policy(policy, ROOT)

        policy = base_policy()
        policy["rules"][0]["pattern"] = ".*"
        with self.assertRaisesRegex(
            MODULE.NormalizationError,
            "unknown fields: pattern",
        ):
            MODULE.validate_policy(policy, ROOT)

    def test_rejects_duplicate_ids_and_targets(self):
        policy = base_policy()
        policy["rules"][1]["id"] = "NORM-0001"
        with self.assertRaisesRegex(
            MODULE.NormalizationError,
            "IDs must be unique",
        ):
            MODULE.validate_policy(policy, ROOT)

        policy = base_policy()
        policy["rules"][1]["json_pointer"] = (
            "/diagnostics/0/message"
        )
        with self.assertRaisesRegex(
            MODULE.NormalizationError,
            "only one normalization rule",
        ):
            MODULE.validate_policy(policy, ROOT)

    def test_rejects_identity_and_case_drift(self):
        policy = base_policy()
        policy["policy_identity"]["oracle_profile"] = "cmake-qt6"
        with self.assertRaisesRegex(
            MODULE.NormalizationError,
            "identity does not match",
        ):
            self.normalize(policy=policy)

        policy = base_policy()
        policy["case_id"] = "different.case"
        with self.assertRaisesRegex(
            MODULE.NormalizationError,
            "case_id does not match",
        ):
            self.normalize(policy=policy)

    def test_rejects_missing_non_string_and_ambiguous_pointer_targets(self):
        for pointer, message in (
            ("/diagnostics/2/message", "out of range"),
            ("/diagnostics/00/message", "canonical index"),
            ("/diagnostics/*/message", "wildcard"),
            ("/diagnostics//message", "empty token"),
            ("/diagnostics/0/missing", "does not exist"),
        ):
            policy = base_policy()
            policy["rules"][0]["json_pointer"] = pointer
            with self.subTest(pointer=pointer):
                with self.assertRaisesRegex(
                    MODULE.NormalizationError,
                    message,
                ):
                    self.normalize(policy=policy)

        policy = base_policy()
        policy["rules"][0]["json_pointer"] = (
            "/detections/0/offset"
        )
        with self.assertRaisesRegex(
            MODULE.NormalizationError,
            "target a string",
        ):
            self.normalize(policy=policy)

    def test_json_pointer_decodes_standard_escapes(self):
        projection = base_projection()
        projection["semantic"]["escaped/key"] = {
            "~message": "PE_Script(0x1)"
        }
        policy = base_policy()
        policy["rules"] = [policy["rules"][0]]
        policy["rules"][0]["json_pointer"] = (
            "/escaped~1key/~0message"
        )
        policy["rules"][0]["expected_normalized_value"] = (
            "PE_Script(<address>)"
        )
        output = self.normalize(projection, policy)
        self.assertEqual(
            output["semantic"]["escaped/key"]["~message"],
            "PE_Script(<address>)",
        )

    def test_strict_json_rejects_duplicates_nan_and_invalid_utf8(self):
        for data, message in (
            (b'{"a":1,"a":2}', "duplicate JSON key"),
            (b'{"a":NaN}', "non-finite JSON constant"),
            (b"\xff", "UTF-8 JSON"),
        ):
            with self.subTest(data=data):
                with self.assertRaisesRegex(
                    MODULE.NormalizationError,
                    message,
                ):
                    MODULE.load_json_bytes(data, "input")

    def test_output_hashes_cover_raw_and_canonical_artifacts(self):
        projection = base_projection()
        policy = base_policy()
        input_bytes = json.dumps(projection, indent=2).encode()
        policy_bytes = json.dumps(policy, indent=2).encode()
        output = MODULE.normalize_projection(
            MODULE.validate_input(projection),
            MODULE.validate_policy(policy, ROOT),
            hashlib.sha256(input_bytes).hexdigest(),
            hashlib.sha256(policy_bytes).hexdigest(),
        )
        self.assertEqual(
            output["input_artifact"]["sha256"],
            hashlib.sha256(input_bytes).hexdigest(),
        )
        self.assertEqual(
            output["policy_artifact"]["sha256"],
            hashlib.sha256(policy_bytes).hexdigest(),
        )
        reconstructed = {
            "projection_schema": 1,
            "run_identity": output["run_identity"],
            "case_id": output["case_id"],
            "semantic": output["semantic"],
        }
        self.assertEqual(
            output["normalized_projection_sha256"],
            MODULE.sha256_bytes(MODULE.canonical_json(reconstructed)),
        )

    def test_cli_writes_derived_output_without_modifying_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            input_path = directory / "input.json"
            policy_path = directory / "policy.json"
            output_path = directory / "output.json"
            input_path.write_text(
                json.dumps(base_projection()),
                encoding="utf-8",
            )
            policy_path.write_text(
                json.dumps(base_policy()),
                encoding="utf-8",
            )
            original_input = input_path.read_bytes()
            original_policy = policy_path.read_bytes()
            process = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--input",
                    str(input_path),
                    "--policy",
                    str(policy_path),
                    "--output",
                    str(output_path),
                    "--repo-root",
                    str(ROOT),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(input_path.read_bytes(), original_input)
            self.assertEqual(policy_path.read_bytes(), original_policy)
            self.assertNotIn(b"\r\n", output_path.read_bytes())
            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8"))[
                    "normalizer"
                ],
                {"name": "die-semantic-normalizer", "version": 1},
            )

    def test_refuses_to_overwrite_input_or_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            input_path = directory / "input.json"
            policy_path = directory / "policy.json"
            input_path.write_text(
                json.dumps(base_projection()),
                encoding="utf-8",
            )
            policy_path.write_text(
                json.dumps(base_policy()),
                encoding="utf-8",
            )
            for output_path in (input_path, policy_path):
                with self.subTest(output_path=output_path):
                    with self.assertRaisesRegex(
                        MODULE.NormalizationError,
                        "must not overwrite",
                    ):
                        MODULE.normalize_files(
                            input_path,
                            policy_path,
                            output_path,
                            ROOT,
                        )

    def test_schemas_are_parseable_and_transform_enum_is_closed(self):
        schemas = ROOT / "docs" / "design" / "schemas"
        for name in (
            "semantic-projection-v1.schema.json",
            "semantic-normalization-policy-v1.schema.json",
            "semantic-normalization-output-v1.schema.json",
        ):
            with self.subTest(name=name):
                json.loads((schemas / name).read_text(encoding="utf-8"))
        policy_schema = json.loads(
            (
                schemas
                / "semantic-normalization-policy-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(
                policy_schema["$defs"]["rule"]["properties"][
                    "transform"
                ]["enum"]
            ),
            set(MODULE.TRANSFORMS),
        )

    def test_documentation_examples_reproduce_golden_output(self):
        examples = ROOT / "docs" / "design" / "schemas" / "examples"
        input_path = examples / "semantic-projection-v1.example.json"
        policy_path = (
            examples / "semantic-normalization-policy-v1.example.json"
        )
        expected_path = (
            examples / "semantic-normalization-output-v1.example.json"
        )
        input_bytes = input_path.read_bytes()
        policy_bytes = policy_path.read_bytes()
        projection = MODULE.validate_input(
            MODULE.load_json_bytes(input_bytes, "input")
        )
        policy = MODULE.validate_policy(
            MODULE.load_json_bytes(policy_bytes, "policy"),
            ROOT,
        )
        output = MODULE.normalize_projection(
            projection,
            policy,
            MODULE.sha256_bytes(input_bytes),
            MODULE.sha256_bytes(policy_bytes),
        )
        self.assertEqual(
            MODULE.serialize_output(output).encode("utf-8"),
            expected_path.read_bytes(),
        )

    def test_design_documents_link_tool_and_schemas(self):
        testing = (
            ROOT / "docs" / "design" / "testing.md"
        ).read_text(encoding="utf-8")
        index = (
            ROOT / "docs" / "design" / "schemas" / "README.md"
        ).read_text(encoding="utf-8")
        for name in (
            MODULE_PATH.name,
            "semantic-projection-v1.schema.json",
            "semantic-normalization-policy-v1.schema.json",
            "semantic-normalization-output-v1.schema.json",
        ):
            self.assertIn(name, testing)
            self.assertIn(name, index)
        self.assertIn("不等于完整 semantic model", testing)
        self.assertIn("compare_semantic_results.py", testing)
        self.assertIn(
            "真实跨平台/release integration",
            testing,
        )


if __name__ == "__main__":
    unittest.main()

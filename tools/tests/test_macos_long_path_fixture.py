import errno
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
GENERATOR_PATH = (
    ROOT / "tools/corpus/generate_macos_long_path_fixture.py"
)
VALIDATOR_PATH = (
    ROOT / "tools/corpus/validate_macos_long_path_fixture.py"
)
BASELINE_GENERATOR_PATH = (
    ROOT / "tools/corpus/generate_baseline_corpus.py"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = load_module(
    "generate_macos_long_path_fixture_test", GENERATOR_PATH
)
VALIDATOR = load_module(
    "validate_macos_long_path_fixture_test", VALIDATOR_PATH
)
BASELINE = load_module(
    "generate_baseline_corpus_long_path_test",
    BASELINE_GENERATOR_PATH,
)


def synthetic_report(local_path: str) -> dict:
    base = PurePosixPath(local_path)
    payload = BASELINE.make_pdf()
    cases = []

    def append(
        case_id: str,
        kind: str,
        relative: str,
        boundary: str,
        target: int,
        created: bool = True,
    ) -> None:
        attempt = (
            {"created": True, "errno": None, "errno_name": None}
            if created
            else {
                "created": False,
                "errno": errno.ENAMETOOLONG,
                "errno_name": "ENAMETOOLONG",
            }
        )
        cases.append(
            GENERATOR._case_record(
                case_id=case_id,
                kind=kind,
                fixture_dir=base,
                relative=relative,
                attempt=attempt,
                payload=payload,
                target_boundary=boundary,
                target_bytes=target,
            )
        )

    control = "control/target.pdf"
    append(
        "control",
        "control",
        control,
        "control",
        len(f"{base}/{control}".encode("ascii")),
    )
    for boundary, value in (
        ("path_max", GENERATOR.XNU_PATH_MAX),
        ("max_long_path", GENERATOR.XNU_MAXLONGPATHLEN),
    ):
        for delta in GENERATOR.FULL_PATH_DELTAS:
            target = value + delta
            append(
                f"{boundary}_{delta:+d}",
                "full_path",
                GENERATOR.build_full_relative_path(base, target),
                boundary,
                target,
            )
    for delta in GENERATOR.COMPONENT_DELTAS:
        target = GENERATOR.XNU_NAME_MAX + delta
        append(
            f"name_max_{delta:+d}",
            "component",
            (
                "components/"
                + GENERATOR.build_component_name(target)
            ),
            "name_max",
            target,
            created=delta <= 0,
        )
    baseline_raw = (
        ROOT / GENERATOR.BASELINE_MANIFEST
    ).read_bytes()
    return {
        "schema_version": GENERATOR.SCHEMA_VERSION,
        "result": "candidate",
        "platform": GENERATOR.PLATFORM,
        "generator": GENERATOR.generator_binding(ROOT),
        "xnu_reference": {
            "repository": (
                "https://github.com/apple-oss-distributions/xnu"
            ),
            "commit": GENERATOR.XNU_COMMIT,
            "source": GENERATOR.XNU_SOURCE,
            "source_url": GENERATOR.XNU_SOURCE_URL,
            "source_sha256": GENERATOR.XNU_SOURCE_SHA256,
            "name_max": GENERATOR.XNU_NAME_MAX,
            "path_max": GENERATOR.XNU_PATH_MAX,
            "kernel_private_max_long_path": (
                GENERATOR.XNU_MAXLONGPATHLEN
            ),
        },
        "baseline": {
            "manifest": GENERATOR.BASELINE_MANIFEST,
            "manifest_sha256": GENERATOR.sha256(baseline_raw),
            "sample": GENERATOR.SOURCE_NAME,
            "payload_size": len(payload),
            "payload_sha256": GENERATOR.sha256(payload),
        },
        "filesystem_limits": {
            "pathconf_name_max": GENERATOR.XNU_NAME_MAX,
            "pathconf_path_max": GENERATOR.XNU_PATH_MAX,
        },
        "fixture": {
            "local_path": local_path,
            "local_path_bytes": len(local_path.encode("ascii")),
            "case_ids": [case["id"] for case in cases],
            "cases": cases,
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": GENERATOR.ADMISSION_REASON,
        },
        "limitations": GENERATOR.LIMITATIONS,
    }


class MacosLongPathFixtureTest(unittest.TestCase):
    def test_exact_full_path_and_component_boundaries(self) -> None:
        base = PurePosixPath("/private/tmp/die-macos-long-path")
        discovery_roots = set()
        for target in (1023, 1024, 1025, 8191, 8192, 8193):
            relative = GENERATOR.build_full_relative_path(
                base, target
            )
            discovery_roots.add(relative.split("/", 1)[0])
            absolute = f"{base}/{relative}"
            self.assertEqual(len(absolute.encode("ascii")), target)
            self.assertTrue(
                all(
                    len(part.encode("ascii")) <= 120
                    for part in relative.split("/")[:-1]
                )
            )
        self.assertEqual(len(discovery_roots), 6)
        for target in (254, 255, 256):
            name = GENERATOR.build_component_name(target)
            self.assertEqual(len(name.encode("ascii")), target)

    def test_validator_accepts_complete_synthetic_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = (
                Path(temporary)
                / "long-path-fixture-candidate.json"
            )
            report = synthetic_report(
                "/private/tmp/die-macos-long-path"
            )
            path.write_text(
                json.dumps(report, sort_keys=True), encoding="utf-8"
            )
            VALIDATOR.validate_report(
                report,
                report_path=path.resolve(strict=True),
                root=ROOT,
            )

            report["fixture"]["cases"][1]["absolute_bytes"] += 1
            with self.assertRaisesRegex(
                VALIDATOR.ReportError, "projection drift"
            ):
                VALIDATOR.validate_report(
                    report,
                    report_path=path.resolve(strict=True),
                    root=ROOT,
                )

    def test_validator_rejects_admission_and_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = (
                Path(temporary)
                / "long-path-fixture-candidate.json"
            )
            report = synthetic_report(
                "/private/tmp/die-macos-long-path"
            )
            path.write_text(
                json.dumps(report, sort_keys=True), encoding="utf-8"
            )
            report["admission"]["platform_admitted"] = True
            with self.assertRaisesRegex(
                VALIDATOR.ReportError, "must not admit"
            ):
                VALIDATOR.validate_report(
                    report,
                    report_path=path.resolve(strict=True),
                    root=ROOT,
                )

            duplicate = Path(temporary) / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VALIDATOR.ReportError, "duplicate JSON key"
            ):
                VALIDATOR.load_json(duplicate)


if __name__ == "__main__":
    unittest.main()

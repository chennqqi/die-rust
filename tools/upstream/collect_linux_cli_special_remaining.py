#!/usr/bin/env python3
"""Collect Linux Qt5/Qt6 special modes omitted by the primary matrix."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
MATRIX_SCRIPT = ROOT / "tools/upstream/compare_cli_oracles.py"
WINDOWS_COLLECTOR_SCRIPT = (
    ROOT / "tools/upstream/collect_windows_cli_special_remaining.py"
)
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
QT5_IMAGE = "die-rust/upstream-oracle-cmake:74eaf505"
QT5_IMAGE_ID = (
    "sha256:466102628c3a94b7ab1048f0c24261b1920e61a40029b128763cf79370255040"
)
QT6_IMAGE = "die-rust/upstream-oracle-cmake-qt6:74eaf505"
QT6_IMAGE_ID = (
    "sha256:e015495c313d0715f0b80f395da983a113a439f2a135eb637e9f0638c225200b"
)
ORACLE_BINARY = "/opt/die-build/src/console/diec"
ALREADY_COVERED = (
    "empty.bin",
    "minimal.exe",
    "minimal.pdf",
    "payload.zip",
    "plain.txt",
)


def load_module(name: str, path: Path) -> object:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load helper module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


matrix = load_module(
    "compare_cli_oracles_linux_special_remaining_helper",
    MATRIX_SCRIPT,
)
windows_collector = load_module(
    "collect_windows_cli_special_remaining_linux_helper",
    WINDOWS_COLLECTOR_SCRIPT,
)


class CollectionError(RuntimeError):
    """Raised when a pinned input identity or report contract drifts."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--qt5-image", default=QT5_IMAGE)
    parser.add_argument("--qt5-image-id", default=QT5_IMAGE_ID)
    parser.add_argument("--qt6-image", default=QT6_IMAGE)
    parser.add_argument("--qt6-image-id", default=QT6_IMAGE_ID)
    parser.add_argument("--qt5-binary", default=ORACLE_BINARY)
    parser.add_argument("--qt6-binary", default=ORACLE_BINARY)
    parser.add_argument("--expected-revision", default=UPSTREAM_COMMIT)
    parser.add_argument(
        "--reference-manifest",
        type=Path,
        default=ROOT / "docs/research/data/baseline-corpus.json",
    )
    parser.add_argument(
        "--windows-reference",
        type=Path,
        default=ROOT
        / "docs/research/data/windows-qt5-cli-special-remaining.json",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_image(
    image: str,
    expected_id: str,
    expected_revision: str,
) -> dict[str, object]:
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        capture_output=True,
        text=True,
    )
    documents = json.loads(result.stdout)
    if not isinstance(documents, list) or len(documents) != 1:
        raise CollectionError(f"unexpected image inspect result: {image}")
    document = documents[0]
    image_id = document.get("Id")
    labels = document.get("Config", {}).get("Labels", {})
    revision = labels.get("org.opencontainers.image.revision")
    if image_id != expected_id:
        raise CollectionError(f"image ID mismatch: {image}")
    if revision != expected_revision:
        raise CollectionError(f"image revision mismatch: {image}")
    return {
        "name": image,
        "id": image_id,
        "revision": revision,
        "binary": None,
    }


def validate_report_binding(
    windows_report: dict[str, object],
    selected_samples: list[str],
    case_names: list[str],
) -> None:
    if windows_report.get("platform") != "windows-x86_64-qt5":
        raise CollectionError("unexpected Windows report platform")
    if windows_report.get("selection") != selected_samples:
        raise CollectionError("Windows special selection differs")
    if windows_report.get("cases") != case_names:
        raise CollectionError("Windows special cases differ")
    if windows_report.get("generator_sha256") != sha256_file(
        WINDOWS_COLLECTOR_SCRIPT
    ):
        raise CollectionError("Windows collector binding differs")
    helper = windows_report.get("helpers", {}).get(
        "matrix_definitions",
        {},
    )
    if helper.get("sha256") != sha256_file(MATRIX_SCRIPT):
        raise CollectionError("Windows matrix definition binding differs")


def main() -> int:
    args = parse_args()
    corpus_dir = args.corpus_dir.resolve(strict=True)
    reference_path = args.reference_manifest.resolve(strict=True)
    corpus_manifest_path = corpus_dir / "manifest.json"
    if corpus_manifest_path.read_bytes() != reference_path.read_bytes():
        raise CollectionError("generated corpus manifest differs from reference")
    samples = matrix.load_corpus(corpus_dir)
    sample_names = [str(sample["name"]) for sample in samples]
    if not set(ALREADY_COVERED).issubset(sample_names):
        raise CollectionError("primary special selection is absent from corpus")
    selected_samples = [
        name for name in sample_names if name not in ALREADY_COVERED
    ]
    if len(sample_names) != 26 or len(selected_samples) != 21:
        raise CollectionError("Linux special sample partition changed")

    cases = matrix.SPECIAL_MATRIX
    case_names = [case.name for case in cases]
    if case_names != [
        case.name for case in windows_collector.matrix_definitions.SPECIAL_MATRIX
    ]:
        raise CollectionError("special matrix helper definitions differ")

    windows_path = args.windows_reference.resolve(strict=True)
    windows_raw = windows_path.read_bytes()
    windows_report = json.loads(windows_raw)
    validate_report_binding(windows_report, selected_samples, case_names)

    qt5_identity = inspect_image(
        args.qt5_image,
        args.qt5_image_id,
        args.expected_revision,
    )
    qt6_identity = inspect_image(
        args.qt6_image,
        args.qt6_image_id,
        args.expected_revision,
    )
    qt5_identity["binary"] = args.qt5_binary
    qt6_identity["binary"] = args.qt6_binary

    reports = {}
    raw_difference_failures = []
    exit_failures = []
    stderr_failures = []
    validity_failures = []
    qt_projection_failures = []
    windows_projection_failures = []
    priority_failures = []
    structured_cases = set(windows_collector.JSON_CASES) | set(
        windows_collector.XML_CASES
    )
    for sample_name in selected_samples:
        case_reports = {}
        reports[sample_name] = case_reports
        observations = {"qt5": {}, "qt6": {}}
        for case in cases:
            arguments = (*case.arguments, f"/corpus/{sample_name}")
            qt5 = matrix.observe(
                args.qt5_image,
                args.qt5_binary,
                arguments,
                corpus_dir,
            )
            qt6 = matrix.observe(
                args.qt6_image,
                args.qt6_binary,
                arguments,
                corpus_dir,
            )
            observations["qt5"][case.name] = qt5
            observations["qt6"][case.name] = qt6
            differences = matrix.compare_observations(qt5, qt6)
            qt5_valid, qt5_projection = windows_collector.parse_output(
                case.name,
                qt5.stdout,
            )
            qt6_valid, qt6_projection = windows_collector.parse_output(
                case.name,
                qt6.stdout,
            )
            qt5_projection = windows_collector.normalize_projection(
                case.name,
                qt5_projection,
                sample_name,
            )
            qt6_projection = windows_collector.normalize_projection(
                case.name,
                qt6_projection,
                sample_name,
            )
            windows_case = windows_report["matrix"][sample_name][case.name]
            windows_projection = windows_case.get("first_projection")
            qt_projection_equal = (
                qt5_projection == qt6_projection
                if case.name in structured_cases
                else None
            )
            windows_projection_equal = (
                qt5_projection == windows_projection
                if case.name in structured_cases
                else None
            )
            case_reports[case.name] = {
                "arguments": list(arguments),
                "qt5": qt5.summary(),
                "qt6": qt6.summary(),
                "raw_differences": differences,
                "qt5_output_valid": qt5_valid,
                "qt6_output_valid": qt6_valid,
                "qt5_projection": qt5_projection,
                "qt6_projection": qt6_projection,
                "qt5_qt6_projection_equal": qt_projection_equal,
                "windows_qt5_projection": windows_projection,
                "windows_linux_qt5_projection_equal": (
                    windows_projection_equal
                ),
            }
            prefix = f"matrix.{sample_name}.{case.name}"
            if differences:
                raw_difference_failures.append(
                    {"case": prefix, "dimensions": differences}
                )
            if qt5.exit_code != 0 or qt6.exit_code != 0:
                exit_failures.append(prefix)
            if qt5.stderr != b"" or qt6.stderr != b"":
                stderr_failures.append(prefix)
            if not qt5_valid or not qt6_valid:
                validity_failures.append(prefix)
            if qt_projection_equal is False:
                qt_projection_failures.append(prefix)
            if windows_projection_equal is False:
                windows_projection_failures.append(prefix)

        for platform in ("qt5", "qt6"):
            for case_name, reference_name in (
                windows_collector.PRIORITY_REFERENCES.items()
            ):
                equal = (
                    observations[platform][case_name]
                    == observations[platform][reference_name]
                )
                case_reports[case_name][
                    f"{platform}_priority_reference_case"
                ] = reference_name
                case_reports[case_name][
                    f"{platform}_priority_reference_equal"
                ] = equal
                if not equal:
                    priority_failures.append(
                        f"matrix.{sample_name}.{case_name}.{platform}"
                    )

    case_count = len(selected_samples) * len(cases)
    report = {
        "schema_version": 1,
        "generator": (
            "tools/upstream/collect_linux_cli_special_remaining.py"
        ),
        "generator_sha256": sha256_file(Path(__file__)),
        "matrix_definitions": {
            "path": "tools/upstream/compare_cli_oracles.py",
            "sha256": sha256_file(MATRIX_SCRIPT),
        },
        "windows_collector": {
            "path": (
                "tools/upstream/"
                "collect_windows_cli_special_remaining.py"
            ),
            "sha256": sha256_file(WINDOWS_COLLECTOR_SCRIPT),
        },
        "platforms": {
            "linux-x86_64-qt5": qt5_identity,
            "linux-x86_64-qt6": qt6_identity,
        },
        "corpus_manifest": {
            "path": "docs/research/data/baseline-corpus.json",
            "sha256": sha256_file(reference_path),
            "sample_count": len(samples),
        },
        "windows_reference": {
            "path": (
                "docs/research/data/"
                "windows-qt5-cli-special-remaining.json"
            ),
            "sha256": hashlib.sha256(windows_raw).hexdigest(),
        },
        "selection": selected_samples,
        "cases": case_names,
        "matrix": reports,
        "summary": {
            "sample_count": len(selected_samples),
            "case_count": case_count,
            "execution_count": 2 * case_count,
            "structured_case_count": (
                len(selected_samples) * len(structured_cases)
            ),
            "raw_difference_failures": raw_difference_failures,
            "exit_failures": exit_failures,
            "stderr_failures": stderr_failures,
            "validity_failures": validity_failures,
            "qt_projection_failures": qt_projection_failures,
            "windows_projection_failures": windows_projection_failures,
            "priority_failures": priority_failures,
            "raw_equal": not raw_difference_failures,
            "all_exits_zero": not exit_failures,
            "all_stderr_empty": not stderr_failures,
            "all_outputs_valid": not validity_failures,
            "qt_structured_projections_equal": (
                not qt_projection_failures
            ),
            "windows_linux_qt5_structured_projections_equal": (
                not windows_projection_failures
            ),
            "priority_references_equal": not priority_failures,
        },
        "limitations": [
            (
                "Linux Qt5 and Qt6 are each executed once per case; the "
                "Windows reference retains two-run determinism evidence"
            ),
            (
                "Windows comparison is exact for parsed JSON values and XML "
                "root tags; Windows raw stream bytes are not retained"
            ),
            (
                "non-structured Windows text/CSV/TSV streams cannot be "
                "compared from hash-only evidence across CRLF/LF platforms"
            ),
            (
                "structure coverage remains limited to Hash, Hash#MD5, and "
                "an unknown method in this baseline extension"
            ),
        ],
    }
    serialized = (
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(serialized)
    sys.stdout.buffer.write(serialized)
    failures = (
        raw_difference_failures
        or exit_failures
        or stderr_failures
        or validity_failures
        or qt_projection_failures
        or windows_projection_failures
        or priority_failures
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

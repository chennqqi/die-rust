#!/usr/bin/env python3
"""Capture the Qt5/Qt6 --alltypes trailing-diagnostic difference."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any


SCHEMA_VERSION = 1
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
GENERATOR = "tools/upstream/probe_qt6_alltypes_diagnostics.py"
FIXTURE_GENERATOR = "tools/corpus/generate_baseline_corpus.py"
SAMPLE_NAME = "minimal.exe"
SAMPLE_SHA256 = (
    "afb1bcd812caa45095075a60ff49599c7d5e767c7732226c3e0007708cb198a2"
)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
QT6_WARNING = b"Unimplemented code.\n" * 4
DATABASE_ARGS = (
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
)
ORACLES = {
    "qt5": {
        "image": "die-rust/upstream-oracle-cmake:74eaf505",
        "binary": "/opt/die-build/src/console/diec",
    },
    "qt6": {
        "image": "die-rust/upstream-oracle-cmake-qt6:74eaf505",
        "binary": "/opt/die-build/src/console/diec",
    },
}
CASES = {
    "alltypes": ("--json", "--alltypes"),
    "combined": (
        "--json",
        "--deepscan",
        "--heuristicscan",
        "--aggressivecscan",
        "--alltypes",
    ),
}
ADDRESS_PATTERN = re.compile(r"0x[0-9a-fA-F]+")
EXPECTED_DIAGNOSTICS = (
    '_init: MSDOS/_init: 41: TypeError: Cannot assign to read-only property '
    '"getEntryPointOffset"\n'
    "extender_DOS4G.0a.sg: MSDOS/extender_DOS4G.0a.sg: 10: TypeError: "
    "Property 'getNEOffset' of object MSDOS_Script(<address>) is not a "
    "function\n\n"
)


class ProbeError(ValueError):
    """The focused alltypes probe could not validate its evidence."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_image(image: str) -> dict[str, str]:
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        capture_output=True,
        text=True,
    )
    document = json.loads(result.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision", ""
    )
    if revision != UPSTREAM_COMMIT:
        raise ProbeError(f"oracle revision mismatch: {image}")
    return {"image": image, "image_id": document["Id"], "revision": revision}


def image_file_sha256(image: str, path: str) -> str:
    result = subprocess.run(
        ["docker", "run", "--rm", image, "sha256sum", path],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.split()[0]


def load_fixture(fixture_dir: Path, manifest_path: Path) -> dict[str, Any]:
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw)
    if (
        manifest.get("schema_version") != 1
        or manifest.get("generator") != FIXTURE_GENERATOR
    ):
        raise ProbeError("unexpected baseline fixture manifest")
    matches = [
        sample
        for sample in manifest.get("samples", [])
        if sample.get("name") == SAMPLE_NAME
    ]
    if len(matches) != 1 or matches[0].get("sha256") != SAMPLE_SHA256:
        raise ProbeError("minimal.exe fixture identity drift")
    sample = fixture_dir / SAMPLE_NAME
    data = sample.read_bytes()
    if sha256(data) != SAMPLE_SHA256 or len(data) != matches[0].get("size"):
        raise ProbeError("minimal.exe fixture content drift")
    return {
        "manifest": manifest,
        "manifest_sha256": sha256(manifest_raw),
        "sample_size": len(data),
    }


def observe(
    image: str,
    binary: str,
    fixture_dir: Path,
    arguments: tuple[str, ...],
) -> subprocess.CompletedProcess[bytes]:
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cpus",
        "1",
        "--memory",
        "512m",
        "--pids-limit",
        "128",
        "--mount",
        (
            f"type=bind,source={fixture_dir},"
            "target=/fixture,readonly"
        ),
        image,
        binary,
        *arguments,
        *DATABASE_ARGS,
        f"/fixture/{SAMPLE_NAME}",
    ]
    return subprocess.run(command, check=False, capture_output=True)


def split_json_and_diagnostics(stdout: bytes) -> tuple[Any, str]:
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProbeError("stdout is not UTF-8") from error
    decoder = json.JSONDecoder()
    try:
        document, end = decoder.raw_decode(text)
    except json.JSONDecodeError as error:
        raise ProbeError("stdout does not start with JSON") from error
    diagnostics = text[end:].lstrip("\r\n")
    return document, diagnostics


def serialize_observation(
    result: subprocess.CompletedProcess[bytes],
) -> dict[str, Any]:
    document, diagnostics = split_json_and_diagnostics(result.stdout)
    normalized = ADDRESS_PATTERN.sub("<address>", diagnostics)
    return {
        "exit_code": result.returncode,
        "stdout_base64": base64.b64encode(result.stdout).decode("ascii"),
        "stdout_bytes": len(result.stdout),
        "stdout_sha256": sha256(result.stdout),
        "stderr_base64": base64.b64encode(result.stderr).decode("ascii"),
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": sha256(result.stderr),
        "json_document": document,
        "diagnostics": diagnostics,
        "normalized_diagnostics": normalized,
    }


def build_report(
    fixture_dir: Path,
    manifest_path: Path,
    repetitions: int,
) -> dict[str, Any]:
    if repetitions < 2:
        raise ProbeError("at least two repetitions are required")
    fixture = load_fixture(fixture_dir, manifest_path)
    oracle_metadata = {}
    for name, oracle in ORACLES.items():
        metadata = inspect_image(oracle["image"])
        metadata["binary"] = oracle["binary"]
        metadata["binary_sha256"] = image_file_sha256(
            oracle["image"], oracle["binary"]
        )
        oracle_metadata[name] = metadata

    cases = {}
    for case_name, arguments in CASES.items():
        observations = {}
        for oracle_name, oracle in ORACLES.items():
            observations[oracle_name] = [
                serialize_observation(
                    observe(
                        oracle["image"],
                        oracle["binary"],
                        fixture_dir,
                        arguments,
                    )
                )
                for _ in range(repetitions)
            ]
        cases[case_name] = {
            "arguments": [*arguments, *DATABASE_ARGS, f"/fixture/{SAMPLE_NAME}"],
            "observations": observations,
        }

    facts: dict[str, Any] = {}
    for case_name, case in cases.items():
        qt5 = case["observations"]["qt5"]
        qt6 = case["observations"]["qt6"]
        facts[f"{case_name}_all_exit_zero"] = all(
            item["exit_code"] == 0 for item in [*qt5, *qt6]
        )
        facts[f"{case_name}_json_equal_across_oracles"] = all(
            item["json_document"] == qt5[0]["json_document"]
            for item in [*qt5, *qt6]
        )
        facts[f"{case_name}_qt5_has_no_diagnostics"] = all(
            item["diagnostics"] == "" for item in qt5
        )
        facts[f"{case_name}_qt6_diagnostics_normalize_exactly"] = all(
            item["normalized_diagnostics"] == EXPECTED_DIAGNOSTICS
            for item in qt6
        )
        facts[f"{case_name}_qt5_stderr_is_empty"] = all(
            item["stderr_sha256"] == EMPTY_SHA256 for item in qt5
        )
        facts[f"{case_name}_qt6_stderr_is_known_warning"] = all(
            base64.b64decode(item["stderr_base64"]) == QT6_WARNING
            for item in qt6
        )
        facts[f"{case_name}_qt6_raw_diagnostics_contain_address"] = all(
            ADDRESS_PATTERN.search(item["diagnostics"]) is not None
            for item in qt6
        )
        case["qt6_raw_diagnostic_variant_count"] = len(
            {item["diagnostics"] for item in qt6}
        )

    passed = all(value is True for value in facts.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": GENERATOR,
        "generator_sha256": sha256(Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "platform": "linux-amd64-qt5-qt6",
        "resource_limits": {
            "network": "none",
            "cpus": 1,
            "memory_bytes": 536870912,
            "pids": 128,
            "fixture_mount": "/fixture",
            "mount_mode": "read-only",
        },
        "fixture": {
            "generator": FIXTURE_GENERATOR,
            "manifest_path": "docs/research/data/baseline-corpus.json",
            "manifest_sha256": fixture["manifest_sha256"],
            "sample": SAMPLE_NAME,
            "sample_sha256": SAMPLE_SHA256,
            "sample_size": fixture["sample_size"],
        },
        "repetitions": repetitions,
        "oracles": oracle_metadata,
        "cases": cases,
        "expected_normalized_diagnostics": EXPECTED_DIAGNOSTICS,
        "facts": facts,
        "passed": passed,
        "limitations": [
            "raw Qt6 diagnostic object addresses are process-specific",
            "address normalization is applied only after raw streams are retained",
            "this probe covers the alltypes and combined option vectors on minimal.exe",
        ],
    }


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=root / "docs" / "research" / "data" / "baseline-corpus.json",
    )
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(
        args.fixture_dir.resolve(),
        args.manifest.resolve(),
        args.repetitions,
    )
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

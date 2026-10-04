#!/usr/bin/env python3
"""Capture Qt5/Qt6 malformed and runtime database diagnostics."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any


SCHEMA_VERSION = 1
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
GENERATOR = "tools/upstream/probe_qt6_database_diagnostics.py"
FIXTURE_GENERATOR = "tools/corpus/generate_database_fixture.py"
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
    "malformed": "/dbfx/malformed-main",
    "throwing": "/dbfx/throwing-main",
}
EXPECTED_DIAGNOSTICS = {
    "malformed": {
        "qt5": (
            "broken.1.sg: Binary/broken.1.sg: 1: "
            "SyntaxError: Parse error\n\n"
        ),
        "qt6": (
            "broken.1.sg: Binary/broken.1.sg: 2: "
            "SyntaxError: Expected token `}'\n\n"
        ),
    },
    "throwing": {
        "qt5": (
            "throw.1.sg: Binary/throw.1.sg: 2: "
            "Error: database fixture\n\n"
        ),
        "qt6": (
            "throw.1.sg: Binary/throw.1.sg: 2: "
            "Error: database fixture\n\n"
        ),
    },
}


class ProbeError(ValueError):
    """The database diagnostic evidence did not meet its contract."""


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
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    if (
        manifest.get("schema_version") != 1
        or manifest.get("generator") != FIXTURE_GENERATOR
    ):
        raise ProbeError("unexpected database fixture manifest")
    required = {
        "input/plain.txt",
        "malformed-main/Binary/broken.1.sg",
        "throwing-main/Binary/throw.1.sg",
    }
    entries = {
        entry.get("path"): entry for entry in manifest.get("entries", [])
    }
    if not required <= set(entries):
        raise ProbeError("database diagnostic fixture entries are missing")
    for relative_path in required:
        entry = entries[relative_path]
        data = (fixture_dir / relative_path).read_bytes()
        if (
            len(data) != entry.get("size")
            or sha256(data) != entry.get("sha256")
        ):
            raise ProbeError(f"database fixture drift: {relative_path}")
    return {
        "manifest_sha256": sha256(raw),
        "entries": [entries[path] for path in sorted(required)],
    }


def observe(
    image: str,
    binary: str,
    fixture_dir: Path,
    database: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
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
                "target=/dbfx,readonly"
            ),
            image,
            binary,
            "--json",
            "--database",
            database,
            "--extradatabase",
            "/dbfx/empty-extra",
            "--customdatabase",
            "/dbfx/empty-custom",
            "/dbfx/input/plain.txt",
        ],
        check=False,
        capture_output=True,
    )


def split_json_and_diagnostics(stdout: bytes) -> tuple[Any, str]:
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProbeError("database diagnostic stdout is not UTF-8") from error
    try:
        document, end = json.JSONDecoder().raw_decode(text)
    except json.JSONDecodeError as error:
        raise ProbeError(
            "database diagnostic stdout does not start with JSON"
        ) from error
    return document, text[end:].lstrip("\r\n")


def serialize_observation(
    result: subprocess.CompletedProcess[bytes],
) -> dict[str, Any]:
    document, diagnostics = split_json_and_diagnostics(result.stdout)
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
    facts = {}
    for case_name, database in CASES.items():
        observations = {}
        for oracle_name, oracle in ORACLES.items():
            observations[oracle_name] = [
                serialize_observation(
                    observe(
                        oracle["image"],
                        oracle["binary"],
                        fixture_dir,
                        database,
                    )
                )
                for _ in range(repetitions)
            ]
        cases[case_name] = {
            "database": database,
            "observations": observations,
        }
        all_items = [
            *observations["qt5"],
            *observations["qt6"],
        ]
        facts[f"{case_name}_all_exit_zero"] = all(
            item["exit_code"] == 0 for item in all_items
        )
        facts[f"{case_name}_all_stderr_empty"] = all(
            item["stderr_bytes"] == 0 for item in all_items
        )
        facts[f"{case_name}_json_equal_across_oracles"] = all(
            item["json_document"] == all_items[0]["json_document"]
            for item in all_items
        )
        for oracle_name in ORACLES:
            items = observations[oracle_name]
            facts[
                f"{case_name}_{oracle_name}_diagnostic_exact"
            ] = all(
                item["diagnostics"]
                == EXPECTED_DIAGNOSTICS[case_name][oracle_name]
                for item in items
            )
            facts[
                f"{case_name}_{oracle_name}_raw_stable"
            ] = len({item["stdout_sha256"] for item in items}) == 1

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
            "fixture_mount": "/dbfx",
            "mount_mode": "read-only",
        },
        "fixture": {
            "generator": FIXTURE_GENERATOR,
            "manifest_path": "docs/research/data/database-fixture.json",
            **fixture,
        },
        "repetitions": repetitions,
        "oracles": oracle_metadata,
        "cases": cases,
        "expected_diagnostics": EXPECTED_DIAGNOSTICS,
        "facts": facts,
        "passed": all(value is True for value in facts.values()),
        "limitations": [
            "the focused probe covers one parse error and one runtime error",
            "raw streams are retained before diagnostic classification",
            "database layer ordering and engine cache behavior are separate harness concerns",
        ],
    }


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=root
        / "docs"
        / "research"
        / "data"
        / "database-fixture.json",
    )
    parser.add_argument("--repetitions", type=int, default=2)
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

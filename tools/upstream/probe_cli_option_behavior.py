#!/usr/bin/env python3
"""Capture deterministic legacy CLI option behavior from pinned oracles."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
from dataclasses import dataclass
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
DATABASE_ARGS = (
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
)
MISSING_DATABASE_ARGS = (
    "--database",
    "/does-not-exist",
    "--extradatabase",
    "/does-not-exist-extra",
    "--customdatabase",
    "/does-not-exist-custom",
)


@dataclass(frozen=True)
class Oracle:
    name: str
    image: str
    binary: str


@dataclass(frozen=True)
class Case:
    name: str
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class Observation:
    exit_code: int
    stdout: bytes
    stderr: bytes


ORACLES = (
    Oracle(
        "linux-qt5-qmake",
        "die-rust/upstream-oracle:74eaf505-repro",
        "/opt/die-source/build/release/diec",
    ),
    Oracle(
        "linux-qt5-cmake",
        "die-rust/upstream-oracle-cmake:74eaf505",
        "/opt/die-build/src/console/diec",
    ),
)

CASES = (
    Case("test_existing_directory", ("--test", "/tmp", *DATABASE_ARGS)),
    Case(
        "test_missing_directory",
        ("--test", "/does-not-exist", *DATABASE_ARGS),
    ),
    Case(
        "createtest_missing_positionals",
        ("--createtest", "/usr/bin/true", *DATABASE_ARGS),
    ),
    Case(
        "createtest_complete",
        (
            "--createtest",
            "/usr/bin/true",
            *DATABASE_ARGS,
            "Detect String",
            "/tmp",
        ),
    ),
    Case(
        "scan_default_json",
        ("--json", *DATABASE_ARGS, "/usr/bin/true"),
    ),
    Case(
        "scan_verbose_json",
        ("--json", "--verbose", *DATABASE_ARGS, "/usr/bin/true"),
    ),
    Case(
        "scan_profiling_without_messages_json",
        ("--json", "--profiling", *DATABASE_ARGS, "/usr/bin/true"),
    ),
    Case(
        "showdatabase_missing_without_messages",
        ("--showdatabase", *MISSING_DATABASE_ARGS),
    ),
    Case(
        "showdatabase_missing_with_messages",
        ("--showdatabase", "--messages", *MISSING_DATABASE_ARGS),
    ),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_image(image: str) -> tuple[str, str]:
    process = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        capture_output=True,
    )
    document = json.loads(process.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision", ""
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError(f"oracle image revision mismatch: {image}")
    return document["Id"], revision


def sample_sha256(oracle: Oracle) -> str:
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            "sha256sum",
            oracle.image,
            "/usr/bin/true",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return process.stdout.split()[0]


def observe(oracle: Oracle, arguments: tuple[str, ...]) -> Observation:
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            oracle.binary,
            oracle.image,
            *arguments,
        ],
        check=False,
        capture_output=True,
    )
    return Observation(process.returncode, process.stdout, process.stderr)


def observation_summary(observation: Observation) -> dict[str, Any]:
    return {
        "exit_code": observation.exit_code,
        "stdout_bytes": len(observation.stdout),
        "stdout_sha256": sha256(observation.stdout),
        "stderr_bytes": len(observation.stderr),
        "stderr_sha256": sha256(observation.stderr),
    }


def canonical_output(observation: Observation) -> dict[str, Any]:
    try:
        stdout = observation.stdout.decode("utf-8")
        stderr = observation.stderr.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("CLI output is not UTF-8") from error
    return {
        **observation_summary(observation),
        "stdout_utf8": stdout,
        "stderr_utf8": stderr,
    }


def scan_values(stdout: bytes) -> list[dict[str, str]]:
    document = json.loads(stdout)
    detects = document.get("detects")
    if not isinstance(detects, list) or len(detects) != 1:
        raise ValueError("expected one top-level detect record")
    values = detects[0].get("values")
    if not isinstance(values, list):
        raise ValueError("detect record has no values")
    return [
        {
            key: value.get(key, "")
            for key in ("type", "name", "version", "info")
        }
        for value in values
    ]


def validate_relationships(
    observations: dict[str, Observation],
) -> dict[str, Any]:
    empty = b""
    test_existing = observations["test_existing_directory"]
    test_missing = observations["test_missing_directory"]
    if test_existing != Observation(0, empty, empty):
        raise ValueError("--test existing-directory behavior drifted")
    if test_missing != test_existing:
        raise ValueError("--test unexpectedly validates its directory")

    create_missing = observations["createtest_missing_positionals"]
    expected_missing = (
        b"Error: --addtest requires <filename> <detect_string> <directory>\n"
    )
    if create_missing != Observation(4, expected_missing, empty):
        raise ValueError("--createtest missing-argument behavior drifted")

    create_complete = observations["createtest_complete"]
    expected_complete = (
        b"Adding test for file '/usr/bin/true' with detect string "
        b"'Detect String' in directory '/tmp'\n"
    )
    if create_complete != Observation(0, expected_complete, empty):
        raise ValueError("--createtest complete behavior drifted")

    default = observations["scan_default_json"]
    verbose = observations["scan_verbose_json"]
    profiling = observations["scan_profiling_without_messages_json"]
    if default.exit_code != 0 or default.stderr:
        raise ValueError("default scan failed")
    if verbose.exit_code != 0 or verbose.stderr:
        raise ValueError("verbose scan failed")
    if profiling != default:
        raise ValueError("--profiling changed output without --messages")

    default_values = scan_values(default.stdout)
    verbose_values = scan_values(verbose.stdout)
    added_values = [
        value for value in verbose_values if value not in default_values
    ]
    removed_values = [
        value for value in default_values if value not in verbose_values
    ]
    expected_added = [
        {
            "type": "operation system",
            "name": "Linux",
            "version": "ABI: 3.2.0",
            "info": "AMD64, 64-bit",
        }
    ]
    if added_values != expected_added or removed_values:
        raise ValueError("unexpected --verbose scan delta")

    missing_quiet = observations["showdatabase_missing_without_messages"]
    missing_messages = observations["showdatabase_missing_with_messages"]
    quiet_output = (
        b"Main database: /does-not-exist\n"
        b"Extra database: /does-not-exist-extra\n"
        b"Custom database: /does-not-exist-custom\n"
    )
    message = b"Cannot load database: /does-not-exist\n"
    if missing_quiet != Observation(3, quiet_output, empty):
        raise ValueError("quiet missing-database behavior drifted")
    if missing_messages != Observation(3, message + quiet_output, empty):
        raise ValueError("--messages missing-database behavior drifted")

    return {
        "test_directory_value_is_unvalidated": True,
        "createtest_complete_only_prints_announcement": True,
        "createtest_missing_positionals_exit_code": 4,
        "createtest_missing_positionals_uses_addtest_name": True,
        "verbose_added_values": added_values,
        "verbose_removed_values": removed_values,
        "profiling_without_messages_equals_default": True,
        "messages_added_stdout_lines": [
            message.decode("utf-8").rstrip("\n")
        ],
        "messages_change_exit_code": False,
        "all_stderr_empty": True,
    }


def build_report(raw_dir: pathlib.Path) -> dict[str, Any]:
    raw_dir.mkdir(parents=True, exist_ok=True)
    oracle_metadata = []
    sample_hashes = set()
    observations_by_oracle: dict[str, dict[str, Observation]] = {}

    for oracle in ORACLES:
        image_id, revision = inspect_image(oracle.image)
        sample_hash = sample_sha256(oracle)
        sample_hashes.add(sample_hash)
        oracle_metadata.append(
            {
                "name": oracle.name,
                "image": oracle.image,
                "image_id": image_id,
                "revision": revision,
                "binary": oracle.binary,
                "sample_sha256": sample_hash,
            }
        )
        case_observations = {}
        observations_by_oracle[oracle.name] = case_observations
        for case in CASES:
            observation = observe(oracle, case.arguments)
            case_observations[case.name] = observation
            (raw_dir / f"{oracle.name}-{case.name}.stdout").write_bytes(
                observation.stdout
            )
            (raw_dir / f"{oracle.name}-{case.name}.stderr").write_bytes(
                observation.stderr
            )

    if len(sample_hashes) != 1:
        raise ValueError("oracle /usr/bin/true sample hashes differ")

    cases = {}
    canonical_observations = {}
    first_oracle = ORACLES[0].name
    for case in CASES:
        canonical = observations_by_oracle[first_oracle][case.name]
        canonical_observations[case.name] = canonical
        oracle_summaries = []
        for oracle in ORACLES:
            observation = observations_by_oracle[oracle.name][case.name]
            if observation != canonical:
                raise ValueError(
                    f"oracle output mismatch for case {case.name}"
                )
            oracle_summaries.append(
                {
                    "name": oracle.name,
                    **observation_summary(observation),
                }
            )
        cases[case.name] = {
            "arguments": list(case.arguments),
            "all_oracles_equal": True,
            "canonical": canonical_output(canonical),
            "oracles": oracle_summaries,
        }

    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_cli_option_behavior.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "platform": "linux-amd64-qt5",
        "sample": {
            "path": "/usr/bin/true",
            "sha256": next(iter(sample_hashes)),
        },
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir",
            "stdout_and_stderr_preserved_per_oracle_and_case": True,
        },
        "oracles": oracle_metadata,
        "cases": cases,
        "relationships": validate_relationships(canonical_observations),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = build_report(args.raw_dir.resolve())
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

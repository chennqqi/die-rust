#!/usr/bin/env python3
"""Probe fixed Qt5 include cycles and include error propagation."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
from dataclasses import dataclass
from typing import Any

from compare_cli_oracles import load_path_corpus


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
GENERATOR = "tools/corpus/generate_include_fixture.py"
DATABASE_ARGS = ("--messages", "--json")


@dataclass(frozen=True)
class Oracle:
    name: str
    image: str
    binary: str


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
CASES = {
    "self-cycle": "After self cycle",
    "two-cycle": "After two cycle",
    "parse-error": "After parse error",
    "missing": "After missing include",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_image(oracle: Oracle) -> tuple[str, str]:
    process = subprocess.run(
        ["docker", "image", "inspect", oracle.image],
        check=True,
        capture_output=True,
    )
    document = json.loads(process.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision", ""
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError(f"{oracle.name} revision mismatch")
    return document["Id"], revision


def binary_sha256(oracle: Oracle) -> str:
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            "/usr/bin/sha256sum",
            oracle.image,
            oracle.binary,
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError(f"{oracle.name} sha256sum wrote stderr")
    return process.stdout.split()[0].decode("ascii")


def observe(
    oracle: Oracle, fixture_dir: pathlib.Path, case_name: str
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--memory=256m",
            "--pids-limit=64",
            "--mount",
            f"type=bind,source={fixture_dir},target=/fixture,readonly",
            "--entrypoint",
            oracle.binary,
            oracle.image,
            *DATABASE_ARGS,
            "--database",
            f"/fixture/{case_name}-main",
            "--extradatabase",
            f"/fixture/{case_name}-extra",
            "--customdatabase",
            f"/fixture/{case_name}-custom",
            "/fixture/input/probe.bin",
        ],
        check=False,
        capture_output=True,
        timeout=10,
    )


def parse_stdout(stdout: bytes) -> dict[str, Any]:
    text = stdout.decode("utf-8")
    json_start = text.find("{")
    if json_start == -1:
        raise ValueError("include observation contains no JSON")
    document, json_length = json.JSONDecoder().raw_decode(text[json_start:])
    json_end = json_start + json_length
    prefix = [
        line for line in text[:json_start].splitlines() if line.strip()
    ]
    suffix = [
        line for line in text[json_end:].splitlines() if line.strip()
    ]
    values = [
        value
        for detect in document.get("detects", [])
        for value in detect.get("values", [])
    ]
    return {
        "prefix_lines": prefix,
        "document": document,
        "suffix_lines": suffix,
        "detection_names": [value.get("name", "") for value in values],
    }


def validate_case(case_name: str, parsed: dict[str, Any]) -> None:
    if parsed["detection_names"] != [CASES[case_name]]:
        raise ValueError(f"{case_name} did not continue to detection")
    prefix = parsed["prefix_lines"]
    suffix = parsed["suffix_lines"]
    if case_name == "self-cycle":
        if (
            len(prefix) != 28
            or not all(
                line.startswith("includeScript self:")
                and "RangeError: Maximum call stack size exceeded." in line
                for line in prefix
            )
            or suffix
            != [
                "_init: Unknown/_init: 1: RangeError: "
                "Maximum call stack size exceeded."
            ]
        ):
            raise ValueError("self-cycle diagnostics changed")
    elif case_name == "two-cycle":
        if (
            len(prefix) != 28
            or not all(
                line.startswith(
                    ("includeScript cycle-a:", "includeScript cycle-b:")
                )
                and "RangeError: Maximum call stack size exceeded." in line
                for line in prefix
            )
            or suffix
            != [
                "_init: Unknown/_init: 1: RangeError: "
                "Maximum call stack size exceeded."
            ]
        ):
            raise ValueError("two-cycle diagnostics changed")
    elif case_name == "parse-error":
        expected = (
            "includeScript broken-helper: 1: SyntaxError: Parse error"
        )
        if prefix != [expected, expected] or suffix != [
            "_init: Unknown/_init: 1: SyntaxError: Parse error"
        ]:
            raise ValueError("include parse-error diagnostics changed")
    elif case_name == "missing":
        if prefix != [
            "Cannot find: not-present",
            "Cannot find: not-present",
        ] or suffix:
            raise ValueError("missing include diagnostics changed")


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
    raw_dir: pathlib.Path,
) -> dict[str, Any]:
    manifest = load_path_corpus(fixture_dir)
    if manifest.get("generator") != GENERATOR:
        raise ValueError("unexpected include fixture generator")
    manifest_bytes = manifest_path.read_bytes()
    if json.loads(manifest_bytes) != manifest:
        raise ValueError("fixture manifest path differs from mounted manifest")

    raw_dir.mkdir(parents=True, exist_ok=True)
    oracle_reports = []
    normalized = []
    for oracle in ORACLES:
        image_id, revision = inspect_image(oracle)
        cases = {}
        normalized_cases = {}
        for case_name in CASES:
            try:
                process = observe(oracle, fixture_dir, case_name)
            except subprocess.TimeoutExpired as error:
                raise ValueError(
                    f"{oracle.name}/{case_name} timed out"
                ) from error
            stdout_path = raw_dir / f"{oracle.name}-{case_name}.stdout"
            stderr_path = raw_dir / f"{oracle.name}-{case_name}.stderr"
            stdout_path.write_bytes(process.stdout)
            stderr_path.write_bytes(process.stderr)
            if process.returncode != 0 or process.stderr:
                raise ValueError(
                    f"{oracle.name}/{case_name} failed: "
                    f"exit={process.returncode}"
                )
            parsed = parse_stdout(process.stdout)
            validate_case(case_name, parsed)
            normalized_cases[case_name] = parsed
            cases[case_name] = {
                "exit_code": process.returncode,
                "stdout_bytes": len(process.stdout),
                "stdout_sha256": sha256(process.stdout),
                "stderr_bytes": len(process.stderr),
                "stderr_sha256": sha256(process.stderr),
                **parsed,
            }
        normalized.append(normalized_cases)
        oracle_reports.append(
            {
                "name": oracle.name,
                "image": oracle.image,
                "image_id": image_id,
                "revision": revision,
                "binary": oracle.binary,
                "binary_sha256": binary_sha256(oracle),
                "cases": cases,
            }
        )

    equal = normalized[0] == normalized[1]
    if not equal:
        raise ValueError("qmake/CMake include observations differ")
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_include_lifecycle.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "platform": "linux-amd64-qt5",
        "resource_limits": {
            "network": "none",
            "memory": "256m",
            "pids": 64,
            "timeout_seconds_per_case": 10,
            "fixture_mount": "readonly",
        },
        "fixture_manifest": {
            "path": "docs/research/data/include-fixture.json",
            "sha256": sha256(manifest_bytes),
        },
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir"
        },
        "oracles": oracle_reports,
        "normalized_outputs_equal": equal,
        "relationships": {
            "cycles_hit_qtscript_stack_limit_without_process_failure": True,
            "include_failure_does_not_stop_later_rule": True,
            "missing_include_is_signal_only": True,
            "included_parse_error_is_signal_and_init_error": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    repo = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=repo / "docs/research/data/include-fixture.json",
    )
    parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = build_report(
        args.fixture_dir.resolve(),
        args.manifest.resolve(),
        args.raw_dir.resolve(),
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

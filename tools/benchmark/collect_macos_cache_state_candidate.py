#!/usr/bin/env python3
"""Collect a Darwin-only temporary-file cache-state candidate report."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import platform
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
XNU_COMMIT = "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea"
XNU_FCNTL_SHA256 = (
    "0f93c8918a70ffafe20bfe9c72e671fde67438cbee9f9de8c2f87b5c704c9a9e"
)
XNU_KERN_DESCRIP_SHA256 = (
    "480cfed4e987be874bd71fb6933c254adf9fb1f36de8496dee8f351b18da13b1"
)
PROBE_PATH = "tools/benchmark/probe_macos_file_content_cache.c"
VALIDATOR_PATH = (
    "tools/benchmark/validate_macos_cache_state_candidate.py"
)
COMPILER_ARGUMENTS = [
    "-std=c11",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
]


class CollectionError(ValueError):
    """The Darwin candidate experiment is incomplete or unsafe."""


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def run_text(arguments: list[str], description: str) -> str:
    completed = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise CollectionError(
            f"{description} failed with exit {completed.returncode}: "
            f"{completed.stderr.decode('utf-8', errors='replace')}"
        )
    return completed.stdout.decode("utf-8").strip()


def parse_observation(raw: str) -> dict[str, int]:
    expected = {
        "schema_version",
        "page_size",
        "fixture_bytes",
        "logical_pages",
        "warm_resident_pages",
        "after_f_nocache_resident_pages",
        "msync_flags",
        "after_msync_invalidate_resident_pages",
        "checksum",
        "temporary_fixture_unlinked_before_probe",
        "benchmark_files_touched",
        "system_cache_flush_executed",
    }
    result = {}
    for line in raw.splitlines():
        name, separator, value = line.partition("\t")
        if not separator or not name or name in result:
            raise CollectionError("probe emitted malformed or duplicate TSV")
        if not value.isascii() or not value.isdecimal():
            raise CollectionError(f"probe field is not decimal: {name}")
        result[name] = int(value)
    if set(result) != expected:
        raise CollectionError("probe TSV field set drift")
    return result


def load_validator(root: Path) -> Any:
    path = root / VALIDATOR_PATH
    spec = importlib.util.spec_from_file_location(
        "macos_cache_state_candidate_validator", path
    )
    if spec is None or spec.loader is None:
        raise CollectionError("cannot load candidate validator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_report(root: Path) -> dict[str, Any]:
    if sys.platform != "darwin" or platform.machine() != "x86_64":
        raise CollectionError("collector requires native Darwin x86_64")
    source = root / PROBE_PATH
    if not source.is_file():
        raise CollectionError("cache-state probe source is missing")

    with tempfile.TemporaryDirectory(
        prefix="die-macos-cache-candidate-"
    ) as temporary:
        directory = Path(temporary)
        binary = directory / "cache-state-probe"
        run_text(
            [
                "clang",
                *COMPILER_ARGUMENTS,
                str(source),
                "-o",
                str(binary),
            ],
            "compile cache-state probe",
        )
        binary_raw = binary.read_bytes()
        observations = []
        for index in range(2):
            run_directory = directory / f"run-{index}"
            run_directory.mkdir()
            raw = run_text(
                [
                    str(binary),
                    "--temporary-directory",
                    str(run_directory),
                ],
                f"cache-state observation {index}",
            )
            observations.append(parse_observation(raw))
        temporary_filesystem = run_text(
            ["stat", "-f", "%T", str(directory)],
            "observe temporary filesystem",
        )
        clang_version = run_text(
            ["clang", "--version"], "observe clang version"
        ).splitlines()

    if observations[0] != observations[1]:
        raise CollectionError("repeated cache-state observations differ")
    zero_after_msync = all(
        item["after_msync_invalidate_resident_pages"] == 0
        for item in observations
    )
    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": "macos-x86_64-cache-state",
        "generated_at": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "upstream_commit": UPSTREAM_COMMIT,
        "darwin_source": {
            "xnu_commit": XNU_COMMIT,
            "fcntl_header_sha256": XNU_FCNTL_SHA256,
            "kern_descrip_sha256": XNU_KERN_DESCRIP_SHA256,
        },
        "probe": {
            "source_sha256": sha256(source.read_bytes()),
            "binary_sha256": sha256(binary_raw),
            "collector_sha256": sha256(
                Path(__file__).resolve().read_bytes()
            ),
            "validator_sha256": sha256(
                (root / VALIDATOR_PATH).read_bytes()
            ),
            "compiler_arguments": COMPILER_ARGUMENTS,
        },
        "host": {
            "machine": platform.machine(),
            "macos_product_version": run_text(
                ["sw_vers", "-productVersion"], "observe macOS version"
            ),
            "macos_build_version": run_text(
                ["sw_vers", "-buildVersion"], "observe macOS build"
            ),
            "darwin_release": platform.release(),
            "temporary_filesystem": temporary_filesystem,
            "clang_version": clang_version,
        },
        "observations": observations,
        "relationships": {
            "two_observations_identical": True,
            "all_pages_warm_before_control": all(
                item["warm_resident_pages"] == item["logical_pages"]
                for item in observations
            ),
            "f_nocache_toggle_alone_evicted_all_pages": all(
                item["after_f_nocache_resident_pages"] == 0
                for item in observations
            ),
            "msync_invalidate_produced_zero_resident_pages": (
                zero_after_msync
            ),
            "linux_file_content_semantic_candidate": zero_after_msync,
        },
        "admission": {
            "cache_state_admitted": False,
            "reason": (
                "temporary-file capability candidate only; the fixed "
                "benchmark closure, controller identity, direct-child "
                "measurement, output invariants, and review are missing"
            ),
        },
        "scope": {
            "temporary_unlinked_fixture_only": True,
            "benchmark_files_touched": False,
            "system_cache_flush_executed": False,
            "performance_baseline": False,
            "runtime_candidate_only": True,
        },
    }
    load_validator(root).validate_report(report)
    return report


def serialize(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="external candidate report path",
    )
    return parser.parse_args()


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    args = parse_args()
    try:
        report = build_report(root)
        args.output.write_bytes(serialize(report))
    except (CollectionError, OSError, ValueError) as error:
        print(
            f"macOS cache-state collection error: {error}",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

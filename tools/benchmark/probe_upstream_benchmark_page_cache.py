#!/usr/bin/env python3
"""Probe page residency around advisory eviction for pinned benchmarks."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
EXPECTED_REVISION = "74eaf505c250ab47e709024e9dc41657cd8f2254"
EXPECTED_IMAGE = "die-rust/upstream-benchmark-qt5:74eaf505"
EXPECTED_IMAGE_ID = (
    "sha256:9f1d70a8d4513404cdc457074e00dec"
    "4a9b8a6f043a572ffc17465bbe699eb09"
)
EXPECTED_PLAN_SHA256 = (
    "f93672c9603db16050047095f15d5f5e"
    "a6d9d58663b4574ed901f819f0106e1a"
)
EXPECTED_AFFINITY_SHA256 = (
    "67e6d594a5b93e1b791c11ef89bdb12"
    "e85399964cea9bee87baf591047f5d7de"
)
EXPECTED_ACCESS_SHA256 = (
    "4edfe49fc68861bbfbb04f7b3a8309b6"
    "5eb4f6eba884985b4fe08e5f5ed3f922"
)
EXPECTED_CPU = "0"
EXPECTED_PAGE_SIZE = 4096
REPETITIONS = 2
GENERATOR = "tools/benchmark/probe_upstream_benchmark_page_cache.py"
CONTROLLER_SOURCE = "tools/benchmark/control_linux_page_cache.c"


class PageCacheProbeError(ValueError):
    """The page-cache observation is incomplete or incomparable."""


def reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PageCacheProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise PageCacheProbeError(f"non-finite JSON constant: {value}")


def parse_json(raw: bytes, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PageCacheProbeError(
            f"invalid {description} JSON: {error}"
        ) from error
    if not isinstance(value, dict):
        raise PageCacheProbeError(
            f"{description} root must be an object"
        )
    return value


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


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


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise PageCacheProbeError(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def require_file(
    path: Path,
    expected_sha256: str,
    description: str,
) -> bytes:
    raw = path.read_bytes()
    observed = sha256(raw)
    if observed != expected_sha256:
        raise PageCacheProbeError(
            f"{description} SHA-256 mismatch: {observed}"
        )
    return raw


def resource_arguments(limits: dict[str, Any]) -> list[str]:
    return [
        "--network",
        str(limits["network"]),
        "--cpus",
        str(limits["cpus"]),
        "--cpuset-cpus",
        EXPECTED_CPU,
        "--memory",
        str(limits["memory"]),
        "--pids-limit",
        str(limits["pids"]),
    ]


def validate_static_elf(raw: bytes) -> dict[str, Any]:
    if (
        len(raw) < 64
        or raw[:4] != b"\x7fELF"
        or raw[4] != 2
        or raw[5] != 1
    ):
        raise PageCacheProbeError(
            "controller is not ELF64 little-endian"
        )
    machine = struct.unpack_from("<H", raw, 18)[0]
    program_offset = struct.unpack_from("<Q", raw, 32)[0]
    entry_size = struct.unpack_from("<H", raw, 54)[0]
    entry_count = struct.unpack_from("<H", raw, 56)[0]
    if machine != 62 or entry_size < 56 or entry_count == 0:
        raise PageCacheProbeError(
            "controller ELF header is not Linux x86_64"
        )
    end = program_offset + entry_size * entry_count
    if end > len(raw):
        raise PageCacheProbeError(
            "controller program headers are truncated"
        )
    types = [
        struct.unpack_from(
            "<I",
            raw,
            program_offset + index * entry_size,
        )[0]
        for index in range(entry_count)
    ]
    if 2 in types or 3 in types:
        raise PageCacheProbeError(
            "controller contains PT_DYNAMIC or PT_INTERP"
        )
    return {
        "elf_class": "ELF64",
        "machine": "x86_64",
        "program_header_count": entry_count,
        "pt_dynamic_present": False,
        "pt_interp_present": False,
        "statically_linked": True,
    }


def compile_controller(
    image: str,
    limits: dict[str, Any],
    source: Path,
    exchange: Path,
) -> tuple[Path, dict[str, Any]]:
    binary = exchange / "page-cache-controller"
    command = [
        "docker",
        "run",
        "--rm",
        *resource_arguments(limits),
        "--mount",
        (
            f"type=bind,source={source.resolve()},"
            "target=/src/controller.c,readonly"
        ),
        "--mount",
        (
            f"type=bind,source={exchange.resolve()},"
            "target=/io"
        ),
        "--entrypoint",
        "/usr/bin/cc",
        image,
        "-static",
        "-O2",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "/src/controller.c",
        "-o",
        "/io/page-cache-controller",
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        timeout=120,
    )
    if (
        completed.returncode != 0
        or completed.stdout
        or completed.stderr
    ):
        raise PageCacheProbeError(
            "static controller compilation failed: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    raw = binary.read_bytes()
    elf = validate_static_elf(raw)
    version = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            *resource_arguments(limits),
            "--entrypoint",
            "/usr/bin/cc",
            image,
            "--version",
        ],
        capture_output=True,
        timeout=30,
    )
    if (
        version.returncode != 0
        or not version.stdout
        or version.stderr
    ):
        raise PageCacheProbeError("cannot identify controller compiler")
    version_text = version.stdout.decode("utf-8")
    return binary, {
        "source": CONTROLLER_SOURCE,
        "source_sha256": sha256(source.read_bytes()),
        "compile_arguments": command[
            command.index("-static") :
        ],
        "compiler_version_first_line": version_text.splitlines()[0],
        "compiler_version_sha256": sha256(version.stdout),
        "binary_bytes": len(raw),
        "binary_sha256": sha256(raw),
        **elf,
    }


def case_records(
    access: dict[str, Any],
    benchmark_id: str,
) -> list[dict[str, Any]]:
    records = [
        record
        for record in access["successful_regular_file_union"][
            "records"
        ]
        if benchmark_id in record["cases"]
    ]
    records.sort(key=lambda record: record["path"])
    summary = access["cases"][benchmark_id]
    if (
        len(records) != summary["successful_regular_file_count"]
        or sum(record["bytes"] for record in records)
        != summary["successful_regular_file_bytes"]
    ):
        raise PageCacheProbeError(
            f"{benchmark_id} closure projection mismatch"
        )
    return records


def write_manifest(
    path: Path,
    records: list[dict[str, Any]],
) -> bytes:
    lines = []
    for record in records:
        name = record["path"]
        if (
            not name.startswith("/")
            or "\t" in name
            or "\r" in name
            or "\n" in name
        ):
            raise PageCacheProbeError(
                f"unsafe controller path: {name!r}"
            )
        lines.append(f"{name}\t{record['bytes']}\n")
    raw = "".join(lines).encode("utf-8")
    path.write_bytes(raw)
    return raw


def parse_controller_output(
    raw: bytes,
    expected: list[dict[str, Any]],
) -> dict[str, Any]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise PageCacheProbeError(
            f"controller output is not UTF-8: {error}"
        ) from error
    if len(lines) != len(expected) + 2:
        raise PageCacheProbeError(
            "controller output record count mismatch"
        )
    if lines[0] != f"page_size\t{EXPECTED_PAGE_SIZE}":
        raise PageCacheProbeError(
            "controller page size mismatch"
        )
    if lines[1] != "exit_code\t0":
        raise PageCacheProbeError(
            "benchmark command did not exit successfully"
        )
    records = []
    identities = set()
    for line, source in zip(lines[2:], expected, strict=True):
        fields = line.split("\t")
        if len(fields) != 9 or fields[0] != "file":
            raise PageCacheProbeError(
                "invalid controller file record"
            )
        try:
            (
                size,
                pages,
                after_warm,
                after_evict,
                after_run,
                device,
                inode,
            ) = (int(value) for value in fields[2:])
        except ValueError as error:
            raise PageCacheProbeError(
                "controller file record contains a non-integer"
            ) from error
        expected_pages = math.ceil(
            source["bytes"] / EXPECTED_PAGE_SIZE
        )
        if (
            fields[1] != source["path"]
            or size != source["bytes"]
            or pages != expected_pages
            or after_warm != pages
            or after_evict != 0
            or not 0 <= after_run <= pages
            or device < 0
            or inode <= 0
        ):
            raise PageCacheProbeError(
                f"page residency invariant failed: {source['path']}"
            )
        identities.add((device, inode))
        records.append(
            {
                "path": source["path"],
                "pages": pages,
                "resident_pages_after_run": after_run,
            }
        )
    return {
        "file_count": len(records),
        "unique_device_inode_count": len(identities),
        "logical_pages": sum(
            record["pages"] for record in records
        ),
        "resident_pages_after_warm": sum(
            int(line.split("\t")[4]) for line in lines[2:]
        ),
        "resident_pages_after_evict": sum(
            int(line.split("\t")[5]) for line in lines[2:]
        ),
        "resident_pages_after_run": sum(
            record["resident_pages_after_run"]
            for record in records
        ),
        "post_run_records": records,
        "post_run_records_sha256": sha256(
            canonical_json(records)
        ),
    }


def run_case(
    image: str,
    limits: dict[str, Any],
    exchange: Path,
    binary: Path,
    plan: dict[str, Any],
    records: list[dict[str, Any]],
    baseline_case: dict[str, Any],
    repetition: int,
) -> dict[str, Any]:
    prefix = f"case-{plan['benchmark_id'].replace('.', '-')}-{repetition}"
    manifest = exchange / f"{prefix}.manifest"
    result = exchange / f"{prefix}.tsv"
    stdout_path = exchange / f"{prefix}.stdout"
    stderr_path = exchange / f"{prefix}.stderr"
    manifest_raw = write_manifest(manifest, records)
    command = [
        "docker",
        "run",
        "--rm",
        *resource_arguments(limits),
        "--mount",
        (
            f"type=bind,source={exchange.resolve()},"
            "target=/io"
        ),
    ]
    for key in sorted(plan["environment"]):
        command.extend(
            ["--env", f"{key}={plan['environment'][key]}"]
        )
    command.extend(
        [
            "--entrypoint",
            f"/io/{binary.name}",
            image,
            "--manifest",
            f"/io/{manifest.name}",
            "--output",
            f"/io/{result.name}",
            "--stdout",
            f"/io/{stdout_path.name}",
            "--stderr",
            f"/io/{stderr_path.name}",
            "--",
            *plan["command"],
        ]
    )
    completed = subprocess.run(
        command,
        capture_output=True,
        timeout=180,
    )
    if completed.returncode != 0:
        raise PageCacheProbeError(
            f"{plan['benchmark_id']} controller failed: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    if completed.stdout or completed.stderr:
        raise PageCacheProbeError(
            f"{plan['benchmark_id']} controller emitted output"
        )
    stdout_raw = stdout_path.read_bytes()
    stderr_raw = stderr_path.read_bytes()
    if (
        stderr_raw
        or len(stdout_raw)
        != baseline_case["runs"][0]["stdout"]["bytes"]
        or sha256(stdout_raw)
        not in baseline_case["summary"]["stdout_unique_sha256"]
    ):
        raise PageCacheProbeError(
            f"{plan['benchmark_id']} output identity mismatch"
        )
    parsed = parse_controller_output(
        result.read_bytes(),
        records,
    )
    parsed.update(
        {
            "manifest_bytes": len(manifest_raw),
            "manifest_sha256": sha256(manifest_raw),
            "stdout": {
                "bytes": len(stdout_raw),
                "sha256": sha256(stdout_raw),
            },
            "stderr": {
                "bytes": 0,
                "sha256": sha256(b""),
            },
        }
    )
    return parsed


def summarize_case(
    runs: list[dict[str, Any]],
    expected_bytes: int,
) -> dict[str, Any]:
    first = runs[0]
    stable_fields = (
        "file_count",
        "logical_pages",
        "manifest_bytes",
        "manifest_sha256",
        "post_run_records",
        "post_run_records_sha256",
        "resident_pages_after_evict",
        "resident_pages_after_run",
        "resident_pages_after_warm",
        "stderr",
        "stdout",
        "unique_device_inode_count",
    )
    if any(
        any(run[field] != first[field] for field in stable_fields)
        for run in runs[1:]
    ):
        raise PageCacheProbeError(
            "repeated page-cache observations differ"
        )
    if (
        first["unique_device_inode_count"] != first["file_count"]
        or first["resident_pages_after_warm"]
        != first["logical_pages"]
        or first["resident_pages_after_evict"] != 0
    ):
        raise PageCacheProbeError(
            "page-cache controller did not establish invariants"
        )
    return {
        "repetitions": len(runs),
        "repeated_observations_identical": True,
        "file_count": first["file_count"],
        "file_bytes": expected_bytes,
        "unique_device_inode_count": first[
            "unique_device_inode_count"
        ],
        "logical_pages": first["logical_pages"],
        "resident_pages_after_warm": first[
            "resident_pages_after_warm"
        ],
        "resident_pages_after_evict": 0,
        "resident_pages_after_run": first[
            "resident_pages_after_run"
        ],
        "manifest_bytes": first["manifest_bytes"],
        "manifest_sha256": first["manifest_sha256"],
        "post_run_records": first["post_run_records"],
        "post_run_records_sha256": first[
            "post_run_records_sha256"
        ],
        "stdout": first["stdout"],
        "stderr": first["stderr"],
    }


def build_report(
    repo: Path,
    image: str,
    plans_path: Path,
    affinity_path: Path,
    access_path: Path,
) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    benchmark_probe = load_module(
        "probe_upstream_benchmark_for_page_cache",
        repo / "tools/benchmark/probe_upstream_benchmark.py",
    )
    plans, plans_raw = benchmark_probe.load_plans(plans_path)
    if sha256(plans_raw) != EXPECTED_PLAN_SHA256:
        raise PageCacheProbeError("plan suite SHA-256 mismatch")
    affinity_raw = require_file(
        affinity_path,
        EXPECTED_AFFINITY_SHA256,
        "affinity baseline",
    )
    affinity = parse_json(affinity_raw, "affinity baseline")
    if benchmark_probe.evaluate_report(affinity):
        raise PageCacheProbeError(
            "affinity baseline verifier failed"
        )
    access_raw = require_file(
        access_path,
        EXPECTED_ACCESS_SHA256,
        "file-access report",
    )
    access = parse_json(access_raw, "file-access report")
    image_identity = benchmark_probe.docker_inspect(image)
    if (
        image_identity["id"] != EXPECTED_IMAGE_ID
        or access["environment"]["image_identity"] != image_identity
        or access["upstream_commit"] != EXPECTED_REVISION
    ):
        raise PageCacheProbeError(
            "image or upstream identity mismatch"
        )
    limits = plans["container_limits"]
    cgroup = benchmark_probe.observe_cgroup(
        image,
        limits,
        cpuset_cpu=EXPECTED_CPU,
    )
    source = repo / CONTROLLER_SOURCE
    with tempfile.TemporaryDirectory() as directory:
        exchange = Path(directory)
        binary, controller = compile_controller(
            image,
            limits,
            source,
            exchange,
        )
        cases = {}
        for plan in plans["plans"]:
            benchmark_id = plan["benchmark_id"]
            records = case_records(access, benchmark_id)
            baseline_case = affinity["case_reports"][benchmark_id][
                "report"
            ]
            runs = [
                run_case(
                    image,
                    limits,
                    exchange,
                    binary,
                    plan,
                    records,
                    baseline_case,
                    repetition,
                )
                for repetition in range(REPETITIONS)
            ]
            cases[benchmark_id] = summarize_case(
                runs,
                sum(record["bytes"] for record in records),
            )
    relationships = {
        "all_case_outputs_match_affinity_baseline": True,
        "all_case_manifests_project_fixed_access_closure": True,
        "all_files_resident_after_explicit_warm_read": all(
            case["resident_pages_after_warm"]
            == case["logical_pages"]
            for case in cases.values()
        ),
        "all_candidate_pages_nonresident_after_fadvise": all(
            case["resident_pages_after_evict"] == 0
            for case in cases.values()
        ),
        "all_repeated_observations_identical": all(
            case["repeated_observations_identical"]
            for case in cases.values()
        ),
        "cold_cache_is_not_claimed": True,
    }
    if not all(relationships.values()):
        raise PageCacheProbeError(
            "page-cache relationships failed"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": GENERATOR,
        "generator_sha256": sha256(Path(__file__).read_bytes()),
        "upstream_commit": EXPECTED_REVISION,
        "environment": {
            "network": "none",
            "image": image,
            "image_identity": image_identity,
            "container_limits": limits,
            "cgroup": cgroup,
            "cpu_affinity": {
                "requested_cpuset_cpu": EXPECTED_CPU,
                "scope": "linux_vcpu",
            },
            "page_size": EXPECTED_PAGE_SIZE,
        },
        "controller": controller,
        "plan_suite": {
            "path": plans_path.relative_to(repo).as_posix(),
            "sha256": EXPECTED_PLAN_SHA256,
        },
        "affinity_baseline": {
            "path": affinity_path.relative_to(repo).as_posix(),
            "bytes": len(affinity_raw),
            "sha256": EXPECTED_AFFINITY_SHA256,
        },
        "successful_file_access": {
            "path": access_path.relative_to(repo).as_posix(),
            "bytes": len(access_raw),
            "sha256": EXPECTED_ACCESS_SHA256,
            "union_records_sha256": access[
                "successful_regular_file_union"
            ]["records_sha256"],
        },
        "repetitions_per_case": REPETITIONS,
        "cases": {name: cases[name] for name in sorted(cases)},
        "relationships": relationships,
        "scope": {
            "platform": "Linux x86_64",
            "successful_regular_file_page_residency_observed": True,
            "posix_fadvise_dontneed_executed": True,
            "all_candidate_pages_observed_nonresident_before_run": True,
            "directory_and_metadata_cache_controlled": False,
            "failed_lookup_cache_controlled": False,
            "overlayfs_host_cache_isolation_proven": False,
            "cold_cache_controlled": False,
            "cold_benchmark_collected": False,
            "performance_timings_collected": False,
        },
        "limitations": [
            "mincore observes only the successful persistent regular-file paths fixed by the access report",
            "the static controller avoids retaining the benchmark dynamic loader and shared libraries while observing or advising their pages",
            "POSIX_FADV_DONTNEED is advisory; this report validates its observed effect on candidate pages immediately before each command rather than treating the call alone as proof",
            "directory entries, inodes, failed path lookups, overlayfs internals, and host page-cache isolation are not controlled",
            "no latency or RSS value from the controller is retained and the result is not labeled a cold benchmark",
        ],
    }


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=root)
    parser.add_argument("--image", default=EXPECTED_IMAGE)
    parser.add_argument(
        "--plans",
        type=Path,
        default=(
            root
            / "docs/research/data/upstream-benchmark-plans.json"
        ),
    )
    parser.add_argument(
        "--affinity-baseline",
        type=Path,
        default=(
            root
            / "docs/research/data/"
            "upstream-benchmark-linux-qt5-affinity.json"
        ),
    )
    parser.add_argument(
        "--file-access",
        type=Path,
        default=(
            root
            / "docs/research/data/"
            "upstream-benchmark-linux-qt5-file-access.json"
        ),
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = build_report(
            args.repo,
            args.image,
            args.plans,
            args.affinity_baseline,
            args.file_access,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(serialize(report))
    except (
        PageCacheProbeError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"page-cache probe error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

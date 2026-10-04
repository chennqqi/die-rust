#!/usr/bin/env python3
"""Probe pinned DIE archive depth and expanded-byte behavior under limits."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


SCHEMA_VERSION = 1
CAPABILITY = "CAP-NEST-009"
EXPECTED_REVISION = "74eaf505c250ab47e709024e9dc41657cd8f2254"
EXPECTED_XSCANENGINE_COMMIT = "dfe4a419e4f491bb23688ba03c5a5bf39e34da83"
EXPECTED_SOURCE_SHA256 = (
    "e088bebb7c8345ce5832cc51de712c05"
    "a8b239873d7f092db3ae5566a761b498"
)
SOURCE_PATH = "/opt/die-source/XScanEngine/xscanengine.cpp"
CORPUS_GENERATOR = "tools/corpus/generate_archive_limit_fixture.py"
DEFAULT_BINARY = (
    "/opt/die-build/src/console/die-archive-limits-harness"
)
RESOURCE_LIMITS = {
    "cpus": "1",
    "memory": "256m",
    "pids": 128,
    "wall_timeout_seconds": 30,
}
SOURCE_PATTERNS = {
    "archive_option_guard": (
        "if (pScanOptions->bIsArchivesScan) {"
    ),
    "default_per_level_limit": "qint32 nLimit = 20;",
    "aggressive_per_level_limit": "nLimit = 100000;",
    "hard_iteration_guard": "(i < 100000)",
    "declared_size_allocation": (
        "XBinary::createFileBuffer("
        "archiveRecord.mapProperties.value("
        "XBinary::FPART_PROP_UNCOMPRESSEDSIZE).toLongLong(), "
        "pPdStruct)"
    ),
    "recursive_scan_call": (
        "scanProcess(pArchiveRecord, "
        "&scanResultArchiveRecord, scanIdSub, &_options, "
        "false, pPdStruct);"
    ),
}


class ProbeError(ValueError):
    """The archive-limit experiment or its evidence is invalid."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(raw: bytes, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError(f"invalid {description} JSON: {error}") from error
    if not isinstance(value, dict):
        raise ProbeError(f"{description} root must be an object")
    return value


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_and_verify_corpus(
    corpus_dir: Path,
    reference_manifest: Path,
) -> tuple[dict[str, Any], bytes]:
    reference_raw = reference_manifest.read_bytes()
    reference = parse_json(reference_raw, "reference manifest")
    generated_raw = (corpus_dir / "manifest.json").read_bytes()
    generated = parse_json(generated_raw, "generated manifest")
    if generated_raw != reference_raw or generated != reference:
        raise ProbeError("generated corpus manifest differs from reference")
    if generated.get("schema_version") != 1:
        raise ProbeError("unsupported corpus schema")
    if generated.get("capability") != CAPABILITY:
        raise ProbeError("corpus capability mismatch")
    if generated.get("generator") != CORPUS_GENERATOR:
        raise ProbeError("corpus generator mismatch")

    samples = generated.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ProbeError("corpus samples must be a non-empty array")
    names = set()
    for sample in samples:
        if not isinstance(sample, dict):
            raise ProbeError("corpus sample must be an object")
        name = sample.get("name")
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or name in names
        ):
            raise ProbeError(f"invalid or duplicate sample name: {name!r}")
        names.add(name)
        data = (corpus_dir / name).read_bytes()
        if len(data) != sample.get("size"):
            raise ProbeError(f"sample size mismatch: {name}")
        if sha256(data) != sample.get("sha256"):
            raise ProbeError(f"sample SHA-256 mismatch: {name}")

    actual_files = {
        path.name
        for path in corpus_dir.iterdir()
        if path.is_file()
    }
    if actual_files != names | {"manifest.json"}:
        raise ProbeError("corpus directory contains missing or extra files")
    return generated, reference_raw


def docker_inspect(image: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        capture_output=True,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, list) or len(value) != 1:
        raise ProbeError("docker image inspect returned unexpected shape")
    inspected = value[0]
    revision = (
        inspected.get("Config", {})
        .get("Labels", {})
        .get("org.opencontainers.image.revision")
    )
    if revision != EXPECTED_REVISION:
        raise ProbeError(
            f"image revision mismatch: {revision!r}"
        )
    return {
        "id": inspected["Id"],
        "repo_digests": sorted(inspected.get("RepoDigests") or []),
        "revision": revision,
    }


def read_image_file(image: str, path: str) -> bytes:
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            image,
            "cat",
            path,
        ],
        check=True,
        capture_output=True,
    )
    if completed.stderr:
        raise ProbeError(f"unexpected stderr while reading {path}")
    return completed.stdout


def observe_source(image: str) -> dict[str, Any]:
    source = read_image_file(image, SOURCE_PATH)
    source_hash = sha256(source)
    if source_hash != EXPECTED_SOURCE_SHA256:
        raise ProbeError(
            f"XScanEngine source SHA-256 mismatch: {source_hash}"
        )
    text = source.decode("utf-8")
    counts = {
        name: text.count(pattern)
        for name, pattern in SOURCE_PATTERNS.items()
    }
    if any(count < 1 for count in counts.values()):
        raise ProbeError(f"required source pattern missing: {counts}")

    start = text.index(SOURCE_PATTERNS["archive_option_guard"])
    end = text.index(
        "QList<XBinary::FPART> listFileParts;",
        start,
    )
    archive_block = text[start:end]
    negative_tokens = {
        token: archive_block.lower().count(token)
        for token in (
            "depth",
            "cumulative",
            "totalextracted",
            "totaldecompressed",
        )
    }
    if any(negative_tokens.values()):
        raise ProbeError(
            "unexpected independent-limit token in archive block"
        )
    return {
        "archive_block_end_line": text[:end].count("\n") + 1,
        "archive_block_start_line": text[:start].count("\n") + 1,
        "component_commit": EXPECTED_XSCANENGINE_COMMIT,
        "negative_token_counts": negative_tokens,
        "path": SOURCE_PATH,
        "required_pattern_counts": counts,
        "sha256": source_hash,
    }


def observe_binary(image: str, binary: str) -> dict[str, Any]:
    data = read_image_file(image, binary)
    return {
        "path": binary,
        "sha256": sha256(data),
        "size": len(data),
    }


def run_case(
    *,
    image: str,
    binary: str,
    corpus_dir: Path,
    sample_name: str,
    case_name: str,
    extra_arguments: tuple[str, ...] = (),
) -> dict[str, Any]:
    logical_arguments = [
        *extra_arguments,
        f"/corpus/{sample_name}",
    ]
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--memory",
        RESOURCE_LIMITS["memory"],
        "--cpus",
        RESOURCE_LIMITS["cpus"],
        "--pids-limit",
        str(RESOURCE_LIMITS["pids"]),
        "-v",
        f"{corpus_dir}:/corpus:ro",
        image,
        binary,
        *logical_arguments,
    ]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=RESOURCE_LIMITS["wall_timeout_seconds"],
        )
    except subprocess.TimeoutExpired as error:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        return {
            "arguments": logical_arguments,
            "case": case_name,
            "exit_code": None,
            "harness": None,
            "possible_oom_exit_137": False,
            "stderr": stderr.decode("utf-8", errors="replace"),
            "stderr_sha256": sha256(stderr),
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stdout_sha256": sha256(stdout),
            "timed_out": True,
            "wall_elapsed_ms": elapsed_ms,
        }

    elapsed_ms = round((time.monotonic() - started) * 1000)
    harness = None
    if completed.returncode == 0:
        harness = parse_json(completed.stdout, f"{case_name} harness")
    return {
        "arguments": logical_arguments,
        "case": case_name,
        "exit_code": completed.returncode,
        "harness": harness,
        "possible_oom_exit_137": completed.returncode == 137,
        "stderr": completed.stderr.decode("utf-8", errors="replace"),
        "stderr_sha256": sha256(completed.stderr),
        "stdout": completed.stdout.decode("utf-8", errors="replace"),
        "stdout_sha256": sha256(completed.stdout),
        "timed_out": False,
        "wall_elapsed_ms": elapsed_ms,
    }


def evaluate_report(report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    samples = report["corpus"]["samples"]
    normal = report["normal_cases"]
    by_name = {case["sample"]: case for case in normal}

    for sample in samples:
        name = sample["name"]
        case = by_name.get(name)
        if case is None:
            failures.append(f"{name}.missing_case")
            continue
        if case["exit_code"] != 0:
            failures.append(f"{name}.exit_code")
        if case["timed_out"]:
            failures.append(f"{name}.timed_out")
        if case["possible_oom_exit_137"]:
            failures.append(f"{name}.possible_oom")
        if case["stderr"]:
            failures.append(f"{name}.stderr")
        harness = case.get("harness")
        if not isinstance(harness, dict):
            failures.append(f"{name}.harness")
            continue
        expected_depth = sample["depth"]
        expected_values = {
            "cyclic_node_count": 0,
            "deepest_pdf_depth": expected_depth,
            "error_count": 0,
            "max_stream_depth": expected_depth,
            "pdf_node_count": 1,
            "pd_stopped": False,
            "stream_node_count": expected_depth,
        }
        for field, expected in expected_values.items():
            if harness.get(field) != expected:
                failures.append(f"{name}.{field}")
        if harness.get("callback_calls", 0) < 1:
            failures.append(f"{name}.callback_calls")
        if harness.get("peak_rss_before_kib", 0) <= 0:
            failures.append(f"{name}.peak_rss_before_kib")
        if (
            harness.get("peak_rss_after_kib", 0)
            < harness.get("peak_rss_before_kib", 0)
        ):
            failures.append(f"{name}.peak_rss_after_kib")
        if harness.get("elapsed_ms", -1) < 0:
            failures.append(f"{name}.elapsed_ms")

    depth_samples = [
        sample for sample in samples if sample["series"] == "depth"
    ]
    if not depth_samples:
        failures.append("depth_series.empty")
    elif any(
        sample["member_count_per_level"] != 1
        for sample in depth_samples
    ):
        failures.append("depth_series.member_count_per_level")
    elif [
        sample["depth"] for sample in depth_samples
    ] != sorted(sample["depth"] for sample in depth_samples):
        failures.append("depth_series.not_monotonic")

    expanded_samples = [
        sample
        for sample in samples
        if sample["series"] == "expanded_bytes"
    ]
    if not expanded_samples:
        failures.append("expanded_series.empty")
    elif len({sample["depth"] for sample in expanded_samples}) != 1:
        failures.append("expanded_series.depth_not_fixed")
    elif [
        sample["cumulative_expanded_bytes"]
        for sample in expanded_samples
    ] != sorted(
        sample["cumulative_expanded_bytes"]
        for sample in expanded_samples
    ):
        failures.append("expanded_series.not_monotonic")

    cancellation = report["cancellation_case"]
    full = by_name.get(cancellation["sample"])
    canceled = cancellation.get("harness")
    if cancellation["exit_code"] != 0:
        failures.append("cancellation.exit_code")
    if cancellation["timed_out"]:
        failures.append("cancellation.timed_out")
    if cancellation["stderr"]:
        failures.append("cancellation.stderr")
    if not isinstance(canceled, dict):
        failures.append("cancellation.harness")
    elif full is None or not isinstance(full.get("harness"), dict):
        failures.append("cancellation.full_control")
    else:
        full_harness = full["harness"]
        if not canceled.get("pd_stopped"):
            failures.append("cancellation.pd_stopped")
        if canceled.get("callback_calls") != 1:
            failures.append("cancellation.callback_calls")
        if canceled.get("record_count", 0) < 1:
            failures.append("cancellation.no_partial_result")
        if (
            canceled.get("record_count", 0)
            >= full_harness.get("record_count", 0)
        ):
            failures.append("cancellation.not_partial")
        if (
            canceled.get("max_stream_depth", 0)
            >= full_harness.get("max_stream_depth", 0)
        ):
            failures.append("cancellation.depth_not_reduced")

    source = report["source_contract"]
    if source["sha256"] != EXPECTED_SOURCE_SHA256:
        failures.append("source.sha256")
    if any(source["negative_token_counts"].values()):
        failures.append("source.independent_limit_token")
    if any(
        count < 1
        for count in source["required_pattern_counts"].values()
    ):
        failures.append("source.required_pattern")
    return failures


def serialize(value: dict[str, Any]) -> bytes:
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
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    parser.add_argument("--corpus-dir", required=True, type=Path)
    parser.add_argument(
        "--reference-manifest",
        type=Path,
        default=(
            root
            / "docs"
            / "research"
            / "data"
            / "archive-limit-corpus.json"
        ),
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def build_report(
    *,
    image_name: str,
    binary_path: str,
    corpus_dir: Path,
    reference_manifest: Path,
    platform: str,
) -> dict[str, Any]:
    corpus, manifest_raw = load_and_verify_corpus(
        corpus_dir,
        reference_manifest,
    )
    image = docker_inspect(image_name)
    source = observe_source(image_name)
    binary = observe_binary(image_name, binary_path)

    normal_cases = []
    for sample in corpus["samples"]:
        observation = run_case(
            image=image_name,
            binary=binary_path,
            corpus_dir=corpus_dir,
            sample_name=sample["name"],
            case_name=f"normal.{sample['name']}",
        )
        observation["sample"] = sample["name"]
        normal_cases.append(observation)

    deepest = max(
        (
            sample
            for sample in corpus["samples"]
            if sample["series"] == "depth"
        ),
        key=lambda sample: sample["depth"],
    )
    cancellation = run_case(
        image=image_name,
        binary=binary_path,
        corpus_dir=corpus_dir,
        sample_name=deepest["name"],
        case_name="cancel_after_first_progress_callback",
        extra_arguments=("--cancel-after-callbacks", "1"),
    )
    cancellation["sample"] = deepest["name"]

    report: dict[str, Any] = {
        "capability": CAPABILITY,
        "cancellation_case": cancellation,
        "corpus": corpus,
        "corpus_manifest_sha256": sha256(manifest_raw),
        "environment": {
            "container_network": "none",
            "image": image_name,
            "image_identity": image,
            "platform": platform,
            "resource_limits": RESOURCE_LIMITS,
        },
        "harness_binary": binary,
        "normal_cases": normal_cases,
        "schema_version": SCHEMA_VERSION,
        "source_contract": source,
        "upstream_commit": EXPECTED_REVISION,
        "xscanengine_commit": EXPECTED_XSCANENGINE_COMMIT,
    }
    failures = evaluate_report(report)
    report["assertions"] = {
        "cancellation_retains_partial_result": not any(
            failure.startswith("cancellation.")
            for failure in failures
        ),
        "depth_reaches_maximum_tested": not any(
            failure.startswith("depth-")
            or failure.startswith("depth_series.")
            for failure in failures
        ),
        "expanded_bytes_reach_maximum_tested": not any(
            failure.startswith("expanded-")
            or failure.startswith("expanded_series.")
            for failure in failures
        ),
        "source_has_no_independent_depth_or_total_token": not any(
            failure.startswith("source.")
            for failure in failures
        ),
    }
    report["failures"] = failures
    report["passed"] = not failures
    return report


def main() -> int:
    args = parse_args()
    report = build_report(
        image_name=args.image,
        binary_path=args.binary,
        corpus_dir=args.corpus_dir.resolve(),
        reference_manifest=args.reference_manifest.resolve(),
        platform="linux-x86_64-qt5",
    )
    raw_report = serialize(report)
    if args.output is None:
        sys.stdout.buffer.write(raw_report)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(raw_report)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

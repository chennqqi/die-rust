#!/usr/bin/env python3
"""Run pinned upstream benchmark plans inside the Linux Qt5 container."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
EXPECTED_REVISION = "74eaf505c250ab47e709024e9dc41657cd8f2254"
EXPECTED_CLI_SHA256 = (
    "da1fab49f7ba5970d1fc1c7fe3d4f380c"
    "f5e8775dd8097207e7b3c30f08236cf"
)
RUNNER_PATH = "/opt/die-benchmark/run_process_benchmark.py"
BENCH_ROOT = "/bench"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
NOISE_GUARDRAILS = {
    "control_mad_over_median_max": 0.50,
    "control_p95_over_median_max": 3.00,
    "minimum_regression_case_median_ms": 50,
}


class ProbeError(ValueError):
    """The benchmark environment or evidence is not trustworthy."""


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


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


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


def load_plans(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    plans = parse_json(raw, "benchmark plans")
    required = {
        "archive_manifest_sha256",
        "baseline_manifest_sha256",
        "container_limits",
        "plans",
        "schema_version",
        "upstream_commit",
    }
    if set(plans) != required:
        raise ProbeError("benchmark suite fields changed")
    if plans["schema_version"] != 1:
        raise ProbeError("unsupported benchmark suite schema")
    if plans["upstream_commit"] != EXPECTED_REVISION:
        raise ProbeError("benchmark suite revision mismatch")
    entries = plans["plans"]
    if not isinstance(entries, list) or len(entries) != 5:
        raise ProbeError("benchmark suite must contain five plans")
    ids = [entry.get("benchmark_id") for entry in entries]
    if len(ids) != len(set(ids)):
        raise ProbeError("benchmark IDs must be unique")
    return plans, raw


def docker_inspect(image: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        capture_output=True,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, list) or len(value) != 1:
        raise ProbeError("unexpected docker image inspect result")
    inspected = value[0]
    revision = (
        inspected.get("Config", {})
        .get("Labels", {})
        .get("org.opencontainers.image.revision")
    )
    if revision != EXPECTED_REVISION:
        raise ProbeError(f"image revision mismatch: {revision!r}")
    return {
        "id": inspected["Id"],
        "repo_digests": sorted(inspected.get("RepoDigests") or []),
        "revision": revision,
    }


def parse_single_cpu(value: str) -> str:
    if not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError(
            "cpuset CPU must be one non-negative decimal integer"
        )
    cpu = int(value)
    if cpu > 2**31 - 1:
        raise argparse.ArgumentTypeError("cpuset CPU is out of range")
    return str(cpu)


def resource_arguments(
    limits: dict[str, Any],
    cpuset_cpu: str | None = None,
) -> list[str]:
    arguments = [
        "--network",
        str(limits["network"]),
        "--cpus",
        str(limits["cpus"]),
        "--memory",
        str(limits["memory"]),
        "--pids-limit",
        str(limits["pids"]),
    ]
    if cpuset_cpu is not None:
        arguments.extend(["--cpuset-cpus", cpuset_cpu])
    return arguments


def run_container(
    image: str,
    limits: dict[str, Any],
    arguments: list[str],
    *,
    cpuset_cpu: str | None = None,
    mount: Path | None = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess[bytes]:
    command = [
        "docker",
        "run",
        "--rm",
        *resource_arguments(limits, cpuset_cpu),
    ]
    if mount is not None:
        command.extend(["-v", f"{mount.resolve()}:/io"])
    command.extend([image, *arguments])
    return subprocess.run(
        command,
        capture_output=True,
        timeout=timeout,
    )


def read_image_file(
    image: str,
    limits: dict[str, Any],
    path: str,
    *,
    cpuset_cpu: str | None = None,
) -> bytes:
    completed = run_container(
        image,
        limits,
        ["cat", path],
        cpuset_cpu=cpuset_cpu,
        timeout=30,
    )
    if completed.returncode != 0 or completed.stderr:
        raise ProbeError(f"cannot read image file {path}")
    return completed.stdout


def observe_cgroup(
    image: str,
    limits: dict[str, Any],
    *,
    cpuset_cpu: str | None = None,
) -> dict[str, Any]:
    program = (
        "import json,pathlib;"
        "paths={"
        "'cpu_max':'/sys/fs/cgroup/cpu.max',"
        "'cpuset_effective':'/sys/fs/cgroup/cpuset.cpus.effective',"
        "'memory_max':'/sys/fs/cgroup/memory.max',"
        "'pids_max':'/sys/fs/cgroup/pids.max'};"
        "print(json.dumps({k:pathlib.Path(v).read_text().strip() "
        "for k,v in paths.items()},sort_keys=True))"
    )
    completed = run_container(
        image,
        limits,
        ["python3", "-c", program],
        cpuset_cpu=cpuset_cpu,
        timeout=30,
    )
    if completed.returncode != 0 or completed.stderr:
        raise ProbeError("cannot observe benchmark cgroup")
    observed = parse_json(completed.stdout, "cgroup observation")
    expected = {
        "cpu_max": "100000 100000",
        "memory_max": str(512 * 1024 * 1024),
        "pids_max": "128",
    }
    for field, value in expected.items():
        if observed.get(field) != value:
            raise ProbeError(
                f"cgroup {field} mismatch: {observed.get(field)!r}"
            )
    if (
        cpuset_cpu is not None
        and observed.get("cpuset_effective") != cpuset_cpu
    ):
        raise ProbeError(
            "cgroup cpuset_effective mismatch: "
            f"{observed.get('cpuset_effective')!r}"
        )
    return observed


def verify_image_corpora(
    image: str,
    limits: dict[str, Any],
    plans: dict[str, Any],
    *,
    cpuset_cpu: str | None = None,
) -> dict[str, Any]:
    result = {}
    for name, path, expected in (
        (
            "baseline",
            "/bench/baseline/manifest.json",
            plans["baseline_manifest_sha256"],
        ),
        (
            "archive",
            "/bench/archive/manifest.json",
            plans["archive_manifest_sha256"],
        ),
    ):
        raw = read_image_file(
            image,
            limits,
            path,
            cpuset_cpu=cpuset_cpu,
        )
        actual = sha256(raw)
        if actual != expected:
            raise ProbeError(f"{name} manifest SHA-256 mismatch")
        result[name] = {
            "path": path,
            "sha256": actual,
            "size": len(raw),
        }
    return result


def run_plan(
    image: str,
    limits: dict[str, Any],
    plan: dict[str, Any],
    *,
    cpuset_cpu: str | None = None,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        exchange = Path(directory)
        plan_path = exchange / "plan.json"
        report_path = exchange / "report.json"
        plan_path.write_bytes(serialize(plan))
        completed = run_container(
            image,
            limits,
            [
                "python3",
                RUNNER_PATH,
                "--plan",
                "/io/plan.json",
                "--output",
                "/io/report.json",
                "--repo-root",
                BENCH_ROOT,
            ],
            cpuset_cpu=cpuset_cpu,
            mount=exchange,
        )
        if completed.returncode != 0:
            raise ProbeError(
                f"{plan['benchmark_id']} runner exited "
                f"{completed.returncode}: "
                f"{completed.stderr.decode(errors='replace')}"
            )
        if completed.stdout or completed.stderr:
            raise ProbeError(
                f"{plan['benchmark_id']} runner emitted output"
            )
        raw_report = report_path.read_bytes()
        report = parse_json(
            raw_report,
            f"{plan['benchmark_id']} report",
        )
    return {
        "report": report,
        "report_sha256": sha256(raw_report),
        "report_size": len(raw_report),
    }


def noise_summary(report: dict[str, Any]) -> dict[str, Any]:
    duration = report["summary"]["duration_ns"]
    median = duration["median"]
    return {
        "mad_over_median": duration["mad"] / median,
        "max_minus_min_over_median": (
            duration["max"] - duration["min"]
        )
        / median,
        "p95_over_median": duration["p95_nearest_rank"] / median,
    }


def evaluate_report(report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    environment = report.get("environment", {})
    affinity_enabled = environment.get("cpu_affinity") is not None
    if report.get("upstream_commit") != EXPECTED_REVISION:
        failures.append("upstream_commit")
    if report.get("baseline_scope") != "descriptive_upstream_only":
        failures.append("baseline_scope")
    if report.get("targets_frozen") is not False:
        failures.append("targets_frozen")
    if (
        sha256(serialize(report["plan_suite"]))
        != report.get("plan_suite_sha256")
    ):
        failures.append("plan_suite_sha256")
    image_identity = report["environment"]["image_identity"]
    if image_identity.get("revision") != EXPECTED_REVISION:
        failures.append("image_revision")
    if (
        report["environment"]["container_limits"]
        != report["plan_suite"]["container_limits"]
    ):
        failures.append("container_limits")
    for name in ("baseline", "archive"):
        if (
            report["image_corpora"][name]["sha256"]
            != report["plan_suite"][f"{name}_manifest_sha256"]
        ):
            failures.append(f"image_corpora.{name}")

    suite_plans = {
        plan["benchmark_id"]: plan
        for plan in report["plan_suite"]["plans"]
    }
    case_reports = report["case_reports"]
    if set(case_reports) != set(suite_plans):
        failures.append("case_set")
        return failures

    executable_hashes: dict[str, str] = {}
    hosts = []
    for benchmark_id, wrapped in case_reports.items():
        plan = suite_plans[benchmark_id]
        item = wrapped["report"]
        prefix = benchmark_id
        raw_item = serialize(item)
        if sha256(raw_item) != wrapped.get("report_sha256"):
            failures.append(f"{prefix}.report_sha256")
        if len(raw_item) != wrapped.get("report_size"):
            failures.append(f"{prefix}.report_size")
        if item.get("result") != "pass":
            failures.append(f"{prefix}.result")
        if item.get("benchmark_id") != benchmark_id:
            failures.append(f"{prefix}.benchmark_id")
        if item.get("producer") != plan["producer"]:
            failures.append(f"{prefix}.producer")
        if item.get("input_artifacts") != plan["input_artifacts"]:
            failures.append(f"{prefix}.input_artifacts")
        execution = item.get("execution", {})
        for field in (
            "warmup_runs",
            "measured_runs",
            "work_bytes",
            "work_definition",
        ):
            if execution.get(field) != plan[field]:
                failures.append(f"{prefix}.execution.{field}")
        runs = item.get("runs", [])
        if len(runs) != plan["measured_runs"]:
            failures.append(f"{prefix}.run_count")
        if any(run.get("exit_code") != 0 for run in runs):
            failures.append(f"{prefix}.exit_code")
        peak_samples = [
            run.get("peak_rss_bytes")
            for run in runs
            if run.get("peak_rss_bytes") is not None
        ]
        if len(peak_samples) != len(runs):
            partial_control_rss = (
                affinity_enabled
                and benchmark_id == "upstream.qt-process-control.v1"
                and len(peak_samples) >= 3
            )
            if not partial_control_rss:
                failures.append(f"{prefix}.peak_rss")
        if any(run.get("stdout", {}).get("bytes", 0) <= 0 for run in runs):
            failures.append(f"{prefix}.stdout_empty")
        if any(
            run.get("stderr", {}).get("sha256") != EMPTY_SHA256
            for run in runs
        ):
            failures.append(f"{prefix}.stderr")
        summary = item.get("summary", {})
        peak_summary = summary.get("peak_rss_bytes")
        if not isinstance(peak_summary, dict):
            failures.append(f"{prefix}.peak_rss_summary")
        elif peak_summary.get("sample_count") != len(peak_samples):
            failures.append(f"{prefix}.peak_rss_sample_count")
        if len(summary.get("stdout_unique_sha256", [])) != 1:
            failures.append(f"{prefix}.stdout_determinism")
        if summary.get("stderr_unique_sha256") != [EMPTY_SHA256]:
            failures.append(f"{prefix}.stderr_determinism")
        duration = summary.get("duration_ns", {})
        if not (
            0 < duration.get("min", 0)
            <= duration.get("median", 0)
            <= duration.get("p95_nearest_rank", 0)
            <= duration.get("max", 0)
        ):
            failures.append(f"{prefix}.duration_order")
        if (
            not isinstance(peak_summary, dict)
            or peak_summary.get("max", 0) <= 0
        ):
            failures.append(f"{prefix}.peak_rss_summary")
        executable_hashes[
            item["executable"]["path"]
        ] = item["executable"]["sha256"]
        hosts.append(item["host"])

    if executable_hashes.get(
        "/opt/die-build/src/console/diec"
    ) != EXPECTED_CLI_SHA256:
        failures.append("cli_sha256")
    if any(host.get("system") != "Linux" for host in hosts):
        failures.append("host_system")
    if any(host.get("machine") != "x86_64" for host in hosts):
        failures.append("host_machine")
    if any(
        host.get("rss_method")
        != "/proc/PID/status VmHWM/VmRSS polling"
        for host in hosts
    ):
        failures.append("rss_method")

    cgroup = environment["cgroup"]
    if cgroup.get("cpu_max") != "100000 100000":
        failures.append("cgroup.cpu_max")
    if cgroup.get("memory_max") != str(512 * 1024 * 1024):
        failures.append("cgroup.memory_max")
    if cgroup.get("pids_max") != "128":
        failures.append("cgroup.pids_max")
    affinity = environment.get("cpu_affinity")
    if affinity is not None:
        if set(affinity) != {
            "requested_cpuset_cpu",
            "scope",
        }:
            failures.append("cpu_affinity.fields")
        requested_cpu = affinity.get("requested_cpuset_cpu")
        if affinity.get("scope") != "linux_vcpu":
            failures.append("cpu_affinity.scope")
        if cgroup.get("cpuset_effective") != requested_cpu:
            failures.append("cgroup.cpuset_effective")

    control = report["noise"][
        "upstream.qt-process-control.v1"
    ]
    if (
        control["mad_over_median"]
        > NOISE_GUARDRAILS["control_mad_over_median_max"]
    ):
        failures.append("noise.control_mad")
    if (
        control["p95_over_median"]
        > NOISE_GUARDRAILS["control_p95_over_median_max"]
    ):
        failures.append("noise.control_p95")
    return failures


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument(
        "--plans",
        type=Path,
        default=(
            root
            / "docs"
            / "research"
            / "data"
            / "upstream-benchmark-plans.json"
        ),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--cpuset-cpus",
        dest="cpuset_cpu",
        metavar="CPU",
        type=parse_single_cpu,
        help=(
            "pin every probe container to one Linux CPU and verify "
            "cpuset.cpus.effective"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    plans, raw_plans = load_plans(args.plans)
    limits = plans["container_limits"]
    image = docker_inspect(args.image)
    cgroup = observe_cgroup(
        args.image,
        limits,
        cpuset_cpu=args.cpuset_cpu,
    )
    corpora = verify_image_corpora(
        args.image,
        limits,
        plans,
        cpuset_cpu=args.cpuset_cpu,
    )

    case_reports = {}
    for plan in plans["plans"]:
        case_reports[plan["benchmark_id"]] = run_plan(
            args.image,
            limits,
            plan,
            cpuset_cpu=args.cpuset_cpu,
        )
    noise = {
        benchmark_id: noise_summary(wrapped["report"])
        for benchmark_id, wrapped in case_reports.items()
    }
    control_noise = noise["upstream.qt-process-control.v1"]
    control_report = case_reports[
        "upstream.qt-process-control.v1"
    ]["report"]
    control_rss_samples = control_report["summary"][
        "peak_rss_bytes"
    ]["sample_count"]
    noise_interpretation = {
        "control_classification": (
            "high_tail_noise"
            if control_noise["p95_over_median"] > 1.50
            else "low_tail_noise"
        ),
        "control_peak_rss_complete": (
            control_rss_samples
            == control_report["execution"]["measured_runs"]
        ),
        "control_peak_rss_product_evidence": False,
        "control_peak_rss_samples": control_rss_samples,
        "guardrails": NOISE_GUARDRAILS,
        "short_process_regression_eligible": False,
    }
    environment: dict[str, Any] = {
        "cgroup": cgroup,
        "container_limits": limits,
        "image": args.image,
        "image_identity": image,
    }
    if args.cpuset_cpu is not None:
        environment["cpu_affinity"] = {
            "requested_cpuset_cpu": args.cpuset_cpu,
            "scope": "linux_vcpu",
        }
    report: dict[str, Any] = {
        "baseline_scope": "descriptive_upstream_only",
        "case_reports": case_reports,
        "environment": environment,
        "image_corpora": corpora,
        "noise": noise,
        "noise_interpretation": noise_interpretation,
        "plan_suite": plans,
        "plan_suite_sha256": sha256(raw_plans),
        "schema_version": SCHEMA_VERSION,
        "targets_frozen": False,
        "upstream_commit": EXPECTED_REVISION,
    }
    failures = evaluate_report(report)
    report["failures"] = failures
    report["passed"] = not failures
    raw_report = serialize(report)
    if args.output is None:
        sys.stdout.buffer.write(raw_report)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(raw_report)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

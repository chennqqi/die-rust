#!/usr/bin/env python3
"""Freeze cache-control boundaries of the pinned Linux benchmark image."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


SCHEMA_VERSION = 1
EXPECTED_REVISION = "74eaf505c250ab47e709024e9dc41657cd8f2254"
EXPECTED_IMAGE = "die-rust/upstream-benchmark-qt5:74eaf505"
EXPECTED_IMAGE_ID = (
    "sha256:9f1d70a8d4513404cdc457074e00dec"
    "4a9b8a6f043a572ffc17465bbe699eb09"
)
EXPECTED_PAGE_CACHE_SHA256 = (
    "081ab455705587089a03401935c8109cd"
    "c271f426e11295b2c848f4186b933eb"
)
EXPECTED_CPU = "0"
GENERATOR = (
    "tools/benchmark/"
    "probe_upstream_benchmark_cache_environment.py"
)
OBSERVER = (
    "tools/benchmark/observe_linux_cache_environment.py"
)
CONTAINER_OBSERVER = (
    "/opt/die-benchmark/observe_linux_cache_environment.py"
)
KERNEL_CONTRACT_SOURCES = [
    {
        "claim": (
            "drop_caches values 1/2/3 reclaim clean page cache, "
            "dentries and inodes; use may cause performance problems"
        ),
        "url": (
            "https://docs.kernel.org/6.6/"
            "admin-guide/sysctl/vm.html#drop-caches"
        ),
    },
    {
        "claim": (
            "POSIX_FADV_DONTNEED attempts to free file pages and "
            "mincore can snapshot file-page residency"
        ),
        "url": (
            "https://man7.org/linux/man-pages/man2/"
            "posix_fadvise.2.html"
        ),
    },
    {
        "claim": (
            "Linux exposes cgroup, IPC, mount, network, PID, time, "
            "user and UTS namespaces, not a page-cache namespace"
        ),
        "url": (
            "https://man7.org/linux/man-pages/man7/"
            "namespaces.7.html"
        ),
    },
    {
        "claim": (
            "Docker overlay2 containers accessing the same file "
            "share a page-cache entry"
        ),
        "url": (
            "https://docs.docker.com/engine/storage/drivers/"
            "overlayfs-driver/#page-caching"
        ),
    },
]


class CacheEnvironmentProbeError(ValueError):
    """The cache-control environment is not the reviewed boundary."""


def reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CacheEnvironmentProbeError(
                f"duplicate JSON key: {key}"
            )
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise CacheEnvironmentProbeError(
        f"non-finite JSON constant: {value}"
    )


def parse_json(raw: bytes, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CacheEnvironmentProbeError(
            f"invalid {description} JSON: {error}"
        ) from error
    if not isinstance(value, dict):
        raise CacheEnvironmentProbeError(
            f"{description} root must be an object"
        )
    return value


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


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
        raise CacheEnvironmentProbeError(
            f"cannot load module: {path}"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run_observer(
    image: str,
    limits: dict[str, Any],
    observer: Path,
) -> dict[str, Any]:
    command = [
        "docker",
        "run",
        "--rm",
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
        "--mount",
        (
            f"type=bind,source={observer.resolve()},"
            f"target={CONTAINER_OBSERVER},readonly"
        ),
        "--entrypoint",
        "/usr/bin/python3",
        image,
        CONTAINER_OBSERVER,
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0 or completed.stderr:
        raise CacheEnvironmentProbeError(
            "cache observer failed: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    return parse_json(
        completed.stdout,
        "cache environment observation",
    )


def validate_observation(
    observation: dict[str, Any],
) -> None:
    if observation.get("schema_version") != 1:
        raise CacheEnvironmentProbeError(
            "observer schema mismatch"
        )
    kernel = observation.get("kernel", {})
    if (
        kernel.get("system") != "Linux"
        or kernel.get("machine") != "x86_64"
        or not kernel.get("release")
        or not kernel.get("version")
    ):
        raise CacheEnvironmentProbeError(
            "kernel identity is incomplete"
        )
    process = observation.get("process", {})
    expected_namespaces = {
        "cgroup",
        "ipc",
        "mnt",
        "net",
        "pid",
        "pid_for_children",
        "time",
        "time_for_children",
        "user",
        "uts",
    }
    if (
        set(process.get("namespace_types", []))
        != expected_namespaces
        or process.get("page_cache_namespace_exposed") is not False
        or process.get("cap_sys_admin_bit") != 21
        or process.get("cap_sys_admin_effective") is not False
        or process.get("initial_user_namespace_uid_map") is not True
        or process.get("seccomp_mode") != 2
    ):
        raise CacheEnvironmentProbeError(
            "namespace, capability or seccomp boundary drifted"
        )
    mounts = observation.get("mounts", {})
    if (
        mounts.get("/", {}).get("filesystem_type") != "overlay"
        or "rw" not in mounts.get("/", {}).get(
            "mount_options", []
        )
        or mounts.get("/proc/sys", {}).get("filesystem_type")
        != "proc"
        or "ro" not in mounts.get("/proc/sys", {}).get(
            "mount_options", []
        )
        or mounts.get("/sys/fs/cgroup", {}).get(
            "filesystem_type"
        )
        != "cgroup2"
    ):
        raise CacheEnvironmentProbeError(
            "cache-relevant mount boundary drifted"
        )
    drop = observation.get("vm", {}).get("drop_caches", {})
    if (
        drop.get("path") != "/proc/sys/vm/drop_caches"
        or drop.get("is_regular_file") is not True
        or drop.get("permission_bits_octal") != "0200"
        or drop.get("os_access_read") is not False
        or drop.get("os_access_write") is not False
        or drop.get("open_write_without_write_succeeded")
        is not False
        or drop.get("open_write_errno") != 30
        or drop.get("open_write_error") != "EROFS"
        or drop.get("write_attempted") is not False
        or drop.get("sync_executed") is not False
        or drop.get("drop_caches_executed") is not False
        or observation.get("vm", {}).get("vfs_cache_pressure")
        != 100
    ):
        raise CacheEnvironmentProbeError(
            "drop_caches safety boundary drifted"
        )
    if observation.get("scope") != {
        "cache_state_changed": False,
        "read_only_observation": True,
    }:
        raise CacheEnvironmentProbeError(
            "observer scope drifted"
        )


def build_report(
    repo: Path,
    image: str,
    plans_path: Path,
    page_cache_path: Path,
) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    benchmark_probe = load_module(
        "probe_upstream_benchmark_for_cache_environment",
        repo / "tools/benchmark/probe_upstream_benchmark.py",
    )
    plans, plans_raw = benchmark_probe.load_plans(plans_path)
    limits = plans["container_limits"]
    image_identity = benchmark_probe.docker_inspect(image)
    if image_identity["id"] != EXPECTED_IMAGE_ID:
        raise CacheEnvironmentProbeError(
            "benchmark image ID mismatch"
        )
    page_cache_raw = page_cache_path.read_bytes()
    if sha256(page_cache_raw) != EXPECTED_PAGE_CACHE_SHA256:
        raise CacheEnvironmentProbeError(
            "page-cache report SHA-256 mismatch"
        )
    page_cache = parse_json(
        page_cache_raw,
        "page-cache report",
    )
    if (
        page_cache["environment"]["image_identity"]
        != image_identity
        or page_cache["upstream_commit"] != EXPECTED_REVISION
    ):
        raise CacheEnvironmentProbeError(
            "page-cache report identity mismatch"
        )
    cgroup = benchmark_probe.observe_cgroup(
        image,
        limits,
        cpuset_cpu=EXPECTED_CPU,
    )
    observer_path = repo / OBSERVER
    first = run_observer(image, limits, observer_path)
    second = run_observer(image, limits, observer_path)
    validate_observation(first)
    validate_observation(second)
    if first != second:
        raise CacheEnvironmentProbeError(
            "repeated cache-environment observations differ"
        )
    relationships = {
        "repeated_observations_identical": True,
        "container_root_is_overlayfs": True,
        "overlayfs_page_cache_may_be_shared": True,
        "proc_sys_is_read_only": True,
        "cap_sys_admin_is_absent": True,
        "drop_caches_open_is_rejected_with_erofs": True,
        "no_page_cache_namespace_is_exposed": True,
        "no_cache_state_was_changed": True,
        "generic_cold_label_is_rejected": True,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": GENERATOR,
        "generator_sha256": sha256(Path(__file__).read_bytes()),
        "observer": {
            "path": OBSERVER,
            "sha256": sha256(observer_path.read_bytes()),
            "repetitions": 2,
        },
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
        },
        "plan_suite": {
            "path": plans_path.relative_to(repo).as_posix(),
            "bytes": len(plans_raw),
            "sha256": sha256(plans_raw),
        },
        "page_cache_evidence": {
            "path": page_cache_path.relative_to(repo).as_posix(),
            "bytes": len(page_cache_raw),
            "sha256": EXPECTED_PAGE_CACHE_SHA256,
        },
        "observation": first,
        "kernel_contract_sources": KERNEL_CONTRACT_SOURCES,
        "relationships": relationships,
        "decision_inputs": {
            "warm": (
                "existing runner contract; explicit process warmups"
            ),
            "file_content_nonresident_metadata_warm": (
                "eligible only with per-path mincore proof immediately "
                "before every measured command"
            ),
            "system_cold": (
                "requires a disposable dedicated VM or bare-metal host, "
                "explicit authority, global drop validation and no "
                "unrelated workloads"
            ),
            "generic_cold": "forbidden because it is ambiguous",
        },
        "scope": {
            "read_only_probe": True,
            "host_global_drop_caches_executed": False,
            "privileged_container_started": False,
            "cap_sys_admin_added": False,
            "container_page_cache_isolation_proven": False,
            "directory_dentry_inode_eviction_proven": False,
            "system_cold_cache_controlled": False,
        },
        "limitations": [
            "the immutable image does not pin the Docker Desktop WSL2 kernel, so the exact observed kernel identity remains part of the report",
            "mount namespaces isolate mount views, not page-cache instances; overlay2 may share page-cache entries across containers",
            "the benchmark container has no CAP_SYS_ADMIN and /proc/sys is read-only; no privileged container was attempted",
            "writing drop_caches would affect kernel-wide caches and can harm unrelated workloads, so it is outside this probe's authority",
            "the existing per-file fadvise/mincore evidence remains valid only for the named file-content-nonresident metadata-warm layer",
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
        "--page-cache",
        type=Path,
        default=(
            root
            / "docs/research/data/"
            "upstream-benchmark-linux-qt5-page-cache.json"
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
            args.page_cache,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(serialize(report))
    except (
        CacheEnvironmentProbeError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"cache environment probe error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

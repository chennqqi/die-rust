#!/usr/bin/env python3
"""Capture the Binary signature execution order from pinned Docker oracles."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
from dataclasses import dataclass
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
DATABASE_ARGS = (
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
)


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


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_order_bytes(order: list[str]) -> bytes:
    return "".join(f"{name}\n" for name in order).encode("utf-8")


def extract_order(stdout: bytes, expected_names: set[str]) -> list[str]:
    encoded = {name.encode("utf-8"): name for name in expected_names}
    return [
        encoded[line.rstrip(b"\r")]
        for line in stdout.splitlines()
        if line.rstrip(b"\r") in encoded
    ]


def validate_order(order: list[str], expected_names: set[str]) -> None:
    counts = {name: order.count(name) for name in set(order)}
    duplicates = sorted(name for name, count in counts.items() if count != 1)
    missing = sorted(expected_names.difference(order))
    unexpected = sorted(set(order).difference(expected_names))
    if duplicates or missing or unexpected or len(order) != len(expected_names):
        raise ValueError(
            "invalid Binary profiling order: "
            f"count={len(order)}, duplicates={duplicates}, "
            f"missing={missing}, unexpected={unexpected}"
        )


def load_expected_names(lifecycle_path: pathlib.Path) -> tuple[set[str], str]:
    data = lifecycle_path.read_bytes()
    document = json.loads(data)
    if document.get("upstream_commit") != UPSTREAM_COMMIT:
        raise ValueError("lifecycle manifest upstream commit mismatch")
    if document.get("rules_commit") != RULES_COMMIT:
        raise ValueError("lifecycle manifest rules commit mismatch")
    records = document["binary"]["records_by_database"]
    names = {
        record["name"]
        for database in ("db", "db_extra", "db_custom")
        for record in records[database]
        if record["name"] != "_init"
    }
    expected_count = sum(
        document["binary"]["executable_count_by_database"].values()
    )
    if len(names) != expected_count:
        raise ValueError("Binary signature names are not unique across databases")
    return names, sha256(data)


def load_sample(
    corpus_dir: pathlib.Path, manifest_path: pathlib.Path, sample_name: str
) -> tuple[pathlib.Path, dict[str, Any]]:
    manifest = json.loads(manifest_path.read_bytes())
    if (
        manifest.get("generator")
        != "tools/corpus/generate_nintendo_certified_corpus.py"
    ):
        raise ValueError("unexpected corpus generator")
    matches = [
        sample for sample in manifest["samples"] if sample["name"] == sample_name
    ]
    if len(matches) != 1:
        raise ValueError(f"sample is not uniquely declared: {sample_name}")
    expected = matches[0]
    path = corpus_dir / sample_name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"sample is missing or a symlink: {path}")
    data = path.read_bytes()
    if len(data) != expected["size"] or sha256(data) != expected["sha256"]:
        raise ValueError(f"sample identity mismatch: {path}")
    return path, expected


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


def observe(
    oracle: Oracle,
    corpus_dir: pathlib.Path,
    sample_name: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--mount",
            f"type=bind,source={corpus_dir},target=/corpus,readonly",
            oracle.image,
            oracle.binary,
            "--profiling",
            "--messages",
            "--json",
            "--deepscan",
            "--heuristicscan",
            *DATABASE_ARGS,
            f"/corpus/{sample_name}",
        ],
        check=False,
        capture_output=True,
    )


def build_report(
    repo: pathlib.Path,
    corpus_dir: pathlib.Path,
    raw_dir: pathlib.Path,
    sample_name: str,
) -> dict[str, Any]:
    lifecycle_path = (
        repo / "docs" / "research" / "data" / "binary-rule-lifecycle.json"
    )
    corpus_manifest_path = (
        repo / "docs" / "research" / "data" / "nintendo-certified-corpus.json"
    )
    expected_names, lifecycle_sha256 = load_expected_names(lifecycle_path)
    _, sample = load_sample(corpus_dir, corpus_manifest_path, sample_name)
    raw_dir.mkdir(parents=True, exist_ok=True)

    observations = []
    orders = []
    for oracle in ORACLES:
        image_id, revision = inspect_image(oracle.image)
        process = observe(oracle, corpus_dir, sample_name)
        stdout_path = raw_dir / f"{oracle.name}.stdout"
        stderr_path = raw_dir / f"{oracle.name}.stderr"
        stdout_path.write_bytes(process.stdout)
        stderr_path.write_bytes(process.stderr)
        order = extract_order(process.stdout, expected_names)
        validate_order(order, expected_names)
        if process.returncode != 0:
            raise ValueError(
                f"{oracle.name} exited with {process.returncode}"
            )
        if process.stderr:
            raise ValueError(f"{oracle.name} wrote stderr")
        orders.append(order)
        observations.append(
            {
                "name": oracle.name,
                "image": oracle.image,
                "image_id": image_id,
                "revision": revision,
                "binary": oracle.binary,
                "exit_code": process.returncode,
                "raw_stdout_bytes": len(process.stdout),
                "raw_stdout_sha256": sha256(process.stdout),
                "raw_stderr_bytes": len(process.stderr),
                "raw_stderr_sha256": sha256(process.stderr),
                "order_count": len(order),
                "order_sha256": sha256(canonical_order_bytes(order)),
            }
        )

    all_orders_equal = all(order == orders[0] for order in orders[1:])
    if not all_orders_equal:
        raise ValueError("qmake and CMake Binary execution orders differ")
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_binary_rule_order.py",
        "upstream_commit": UPSTREAM_COMMIT,
        "rules_commit": RULES_COMMIT,
        "platform": "linux-amd64-qt5",
        "sample": sample,
        "lifecycle_manifest": {
            "path": "docs/research/data/binary-rule-lifecycle.json",
            "sha256": lifecycle_sha256,
        },
        "arguments": [
            "--profiling",
            "--messages",
            "--json",
            "--deepscan",
            "--heuristicscan",
            *DATABASE_ARGS,
            f"/corpus/{sample_name}",
        ],
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir",
            "profiling_times_are_nondeterministic": True,
        },
        "oracles": observations,
        "orders_equal": all_orders_equal,
        "order_count": len(orders[0]),
        "order_sha256": sha256(canonical_order_bytes(orders[0])),
        "order": orders[0],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[2],
    )
    parser.add_argument("--corpus-dir", type=pathlib.Path, required=True)
    parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument(
        "--sample", default="ps3-type-1-elf.self"
    )
    args = parser.parse_args()
    report = build_report(
        args.repo.resolve(),
        args.corpus_dir.resolve(),
        args.raw_dir.resolve(),
        args.sample,
    )
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

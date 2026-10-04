#!/usr/bin/env python3
"""Probe cross-evaluate JavaScript scope semantics in pinned Qt oracles."""

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


def load_and_verify_fixture(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
    expected_generator: str = "tools/corpus/generate_script_scope_fixture.py",
) -> tuple[dict[str, Any], str]:
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get("generator") != expected_generator:
        raise ValueError("unexpected script semantics fixture generator")

    declared = set()
    for entry in manifest["entries"]:
        relative = pathlib.PurePosixPath(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe fixture path: {relative}")
        path = fixture_dir / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"fixture file is missing or a symlink: {path}")
        data = path.read_bytes()
        if len(data) != entry["size"] or sha256(data) != entry["sha256"]:
            raise ValueError(f"fixture identity mismatch: {path}")
        declared.add(relative.as_posix())

    actual = {
        path.relative_to(fixture_dir).as_posix()
        for path in fixture_dir.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    if actual != declared:
        raise ValueError(
            f"fixture file inventory mismatch: "
            f"missing={sorted(declared - actual)}, "
            f"unexpected={sorted(actual - declared)}"
        )
    return manifest, sha256(manifest_bytes)


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
    oracle: Oracle, fixture_dir: pathlib.Path
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--mount",
            f"type=bind,source={fixture_dir},target=/scope,readonly",
            oracle.image,
            oracle.binary,
            "--profiling",
            "--messages",
            "--json",
            "--database",
            "/scope/main",
            "--extradatabase",
            "/scope/extra",
            "--customdatabase",
            "/scope/custom",
            "/scope/input/probe.bin",
        ],
        check=False,
        capture_output=True,
    )


def parse_stdout(
    stdout: bytes, expected_order: list[str]
) -> tuple[list[str], list[dict[str, str]]]:
    text = stdout.decode("utf-8")
    lines = text.splitlines()
    order = [line for line in lines if line in set(expected_order)]
    if order != expected_order:
        raise ValueError(f"unexpected profiling order: {order}")

    json_offsets = [
        offset
        for offset, line in enumerate(lines)
        if line.startswith("{")
    ]
    if len(json_offsets) != 1:
        raise ValueError("expected exactly one JSON document")
    json_text = "\n".join(lines[json_offsets[0] :])
    document, end = json.JSONDecoder().raw_decode(json_text)
    trailing = json_text[end:].strip()
    if trailing:
        raise ValueError(f"oracle emitted trailing diagnostics: {trailing}")
    values = [
        value
        for detection in document["detects"]
        for value in detection["values"]
    ]
    normalized = [
        {
            "type": value["type"],
            "name": value["name"],
            "version": value["version"],
            "info": value["info"],
        }
        for value in values
    ]
    return order, normalized


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
    raw_dir: pathlib.Path,
    *,
    expected_generator: str = (
        "tools/corpus/generate_script_scope_fixture.py"
    ),
    report_generator: str = "tools/upstream/probe_script_scope.py",
    manifest_report_path: str = (
        "docs/research/data/script-scope-fixture.json"
    ),
) -> dict[str, Any]:
    manifest, manifest_sha256 = load_and_verify_fixture(
        fixture_dir, manifest_path, expected_generator
    )
    expected_order = manifest["rule_order"]
    raw_dir.mkdir(parents=True, exist_ok=True)

    observations = []
    normalized_outputs = []
    for oracle in ORACLES:
        image_id, revision = inspect_image(oracle.image)
        process = observe(oracle, fixture_dir)
        (raw_dir / f"{oracle.name}.stdout").write_bytes(process.stdout)
        (raw_dir / f"{oracle.name}.stderr").write_bytes(process.stderr)
        if process.returncode != 0:
            raise ValueError(
                f"{oracle.name} exited with {process.returncode}"
            )
        if process.stderr:
            raise ValueError(f"{oracle.name} wrote stderr")
        order, detections = parse_stdout(process.stdout, expected_order)
        normalized_outputs.append((order, detections))
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
                "rule_order": order,
                "detections": detections,
            }
        )

    normalized_equal = all(
        output == normalized_outputs[0] for output in normalized_outputs[1:]
    )
    if not normalized_equal:
        raise ValueError("qmake and CMake normalized observations differ")
    return {
        "schema_version": 1,
        "generator": report_generator,
        "upstream_commit": UPSTREAM_COMMIT,
        "platform": "linux-amd64-qt5",
        "fixture_manifest": {
            "path": manifest_report_path,
            "sha256": manifest_sha256,
        },
        "arguments": [
            "--profiling",
            "--messages",
            "--json",
            "--database",
            "/scope/main",
            "--extradatabase",
            "/scope/extra",
            "--customdatabase",
            "/scope/custom",
            "/scope/input/probe.bin",
        ],
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir",
            "profiling_times_are_nondeterministic": True,
        },
        "oracles": observations,
        "normalized_outputs_equal": normalized_equal,
        "rule_order": normalized_outputs[0][0],
        "detections": normalized_outputs[0][1],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    repo = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=repo
        / "docs"
        / "research"
        / "data"
        / "script-scope-fixture.json",
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
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

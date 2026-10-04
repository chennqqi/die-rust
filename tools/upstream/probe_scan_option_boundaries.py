#!/usr/bin/env python3
"""Probe deep/aggressive/resource-count boundaries on pinned Qt5 CLIs."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import zlib
from dataclasses import dataclass
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
FIXTURE_GENERATOR = (
    "tools/corpus/generate_scan_option_boundary_fixture.py"
)
RESOURCE_SOURCE = "/opt/die-source/XScanEngine/xscanengine.cpp"
CONSOLE_SOURCE = "/opt/die-source/src/console/main_console.cpp"
PE_SOURCE = "/opt/die-source/Formats/exec/xpe.cpp"
RESOURCE_PATTERNS = {
    "file_part_enumeration_limit": (
        "XBinary::FILEPART_RESOURCE, 10000, false, -1"
    ),
    "default_limit": "qint32 nLimit = 20;",
    "aggressive_limit": "nLimit = 2000;",
    "inclusive_limit": "if (nCurrentIndex <= nLimit)",
    "aggressive_gate": "bScan = pScanOptions->bIsAggressiveScan;",
    "scanable_gate": "bScan = isScanable(_stFT);",
}
RESOURCE_PATTERN_COUNTS = {
    "file_part_enumeration_limit": 1,
    "default_limit": 2,
    "aggressive_limit": 1,
    "inclusive_limit": 1,
    "aggressive_gate": 2,
    "scanable_gate": 2,
}
CONSOLE_PATTERNS = {
    "deep_mapping": (
        "scanOptions.bIsDeepScan = parser.isSet(clDeepScan);"
    ),
    "aggressive_mapping": (
        "scanOptions.bIsAggressiveScan = parser.isSet(clAggresiveScan);"
    ),
    "recursive_mapping": (
        "scanOptions.bIsRecursiveScan = parser.isSet(clRecursiveScan);"
    ),
}
PE_PATTERNS = {
    "root_directory_sanity_limit": (
        "rd[0].NumberOfIdEntries + rd[0].NumberOfNamedEntries <= 1000"
    ),
    "type_directory_sanity_limit": (
        "rd[1].NumberOfIdEntries + rd[1].NumberOfNamedEntries <= 1000"
    ),
    "language_directory_sanity_limit": (
        "rd[2].NumberOfIdEntries + rd[2].NumberOfNamedEntries <= 1000"
    ),
}


@dataclass(frozen=True)
class Oracle:
    name: str
    image: str
    binary: str


@dataclass(frozen=True)
class Case:
    name: str
    sample: str
    flags: tuple[str, ...]


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
    Case("deep_default", "probe.bin", ()),
    Case("deep_enabled", "probe.bin", ("--deepscan",)),
    Case(
        "aggressive_without_recursive",
        "pe-one-unclassified.exe",
        ("--aggressivecscan",),
    ),
    Case(
        "recursive_unclassified",
        "pe-one-unclassified.exe",
        ("--recursivescan",),
    ),
    Case(
        "recursive_aggressive_unclassified",
        "pe-one-unclassified.exe",
        ("--recursivescan", "--aggressivecscan"),
    ),
    Case(
        "recursive_pdf_22",
        "pe-22-pdf.exe",
        ("--recursivescan",),
    ),
    Case(
        "recursive_aggressive_pdf_22",
        "pe-22-pdf.exe",
        ("--recursivescan", "--aggressivecscan"),
    ),
    Case(
        "recursive_aggressive_unclassified_2002",
        "pe-2002-unclassified.exe",
        ("--recursivescan", "--aggressivecscan"),
    ),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(data: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(
        data.decode("utf-8"),
        parse_constant=reject_constant,
        object_pairs_hook=closed_pairs,
    )


def load_fixture(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
) -> tuple[dict[str, Any], str]:
    manifest_bytes = manifest_path.read_bytes()
    manifest = strict_json(manifest_bytes)
    if not isinstance(manifest, dict):
        raise ValueError("fixture manifest must be an object")
    if set(manifest) != {
        "schema_version",
        "generator",
        "license",
        "directories",
        "boundaries",
        "entries",
    }:
        raise ValueError("fixture manifest fields changed")
    if manifest["schema_version"] != 1:
        raise ValueError("unsupported fixture schema")
    if manifest["generator"] != FIXTURE_GENERATOR:
        raise ValueError("unexpected fixture generator")
    if manifest["boundaries"] != {
        "default_resource_scan_count": 21,
        "aggressive_resource_scan_count": 2001,
        "resource_enumeration_count": 10000,
    }:
        raise ValueError("fixture boundary contract changed")

    declared_directories = set(manifest["directories"])
    actual_directories = {
        path.relative_to(fixture_dir).as_posix()
        for path in fixture_dir.rglob("*")
        if path.is_dir()
    }
    if declared_directories != actual_directories:
        raise ValueError("fixture directory inventory mismatch")

    declared_files = set()
    for entry in manifest["entries"]:
        if set(entry) != {
            "path",
            "purpose",
            "source",
            "size",
            "sha256",
        }:
            raise ValueError("fixture entry fields changed")
        relative = pathlib.PurePosixPath(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe fixture path: {relative}")
        path = fixture_dir / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"fixture file missing or symlinked: {path}")
        data = path.read_bytes()
        if len(data) != entry["size"] or sha256(data) != entry["sha256"]:
            raise ValueError(f"fixture identity mismatch: {path}")
        declared_files.add(relative.as_posix())
    actual_files = {
        path.relative_to(fixture_dir).as_posix()
        for path in fixture_dir.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    if actual_files != declared_files:
        raise ValueError("fixture file inventory mismatch")
    return manifest, sha256(manifest_bytes)


def inspect_image(oracle: Oracle) -> dict[str, str]:
    process = subprocess.run(
        ["docker", "image", "inspect", oracle.image],
        check=True,
        capture_output=True,
    )
    document = strict_json(process.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision",
        "",
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError(f"oracle revision mismatch: {oracle.name}")
    hashes = container_hashes(
        oracle.image,
        (oracle.binary, RESOURCE_SOURCE, CONSOLE_SOURCE, PE_SOURCE),
    )
    return {
        "image_id": document["Id"],
        "revision": revision,
        "binary_sha256": hashes[oracle.binary],
        "resource_source_sha256": hashes[RESOURCE_SOURCE],
        "console_source_sha256": hashes[CONSOLE_SOURCE],
        "pe_source_sha256": hashes[PE_SOURCE],
    }


def container_hashes(
    image: str,
    paths: tuple[str, ...],
) -> dict[str, str]:
    process = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", image,
         "sha256sum", *paths],
        check=True,
        capture_output=True,
    )
    result: dict[str, str] = {}
    for raw_line in process.stdout.decode("ascii").splitlines():
        digest, path = raw_line.split(maxsplit=1)
        result[path] = digest
    if set(result) != set(paths):
        raise ValueError("container hash inventory mismatch")
    return result


def source_audit(image: str) -> dict[str, Any]:
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            image,
            "python3",
            "-c",
            (
                "import json,pathlib;"
                f"r=pathlib.Path({RESOURCE_SOURCE!r}).read_text();"
                f"c=pathlib.Path({CONSOLE_SOURCE!r}).read_text();"
                f"p=pathlib.Path({PE_SOURCE!r}).read_text();"
                "print(json.dumps({'resource':{"
                + ",".join(
                    f"{name!r}:r.count({pattern!r})"
                    for name, pattern in RESOURCE_PATTERNS.items()
                )
                + "},'console':{"
                + ",".join(
                    f"{name!r}:c.count({pattern!r})"
                    for name, pattern in CONSOLE_PATTERNS.items()
                )
                + "},'pe':{"
                + ",".join(
                    f"{name!r}:p.count({pattern!r})"
                    for name, pattern in PE_PATTERNS.items()
                )
                + "}},sort_keys=True))"
            ),
        ],
        check=True,
        capture_output=True,
    )
    counts = strict_json(process.stdout)
    expected_counts = {
        "resource": RESOURCE_PATTERN_COUNTS,
        "console": {name: 1 for name in CONSOLE_PATTERNS},
        "pe": {name: 1 for name in PE_PATTERNS},
    }
    if counts != expected_counts:
        raise ValueError(f"source pattern count changed: {counts}")
    return {
        "paths": {
            "resource": RESOURCE_SOURCE,
            "console": CONSOLE_SOURCE,
            "pe": PE_SOURCE,
        },
        "required_pattern_counts": counts,
    }


def arguments(case: Case) -> tuple[str, ...]:
    return (
        "--json",
        *case.flags,
        "--database",
        "/fixture/database",
        "--extradatabase",
        "/fixture/extra",
        "--customdatabase",
        "/fixture/custom",
        f"/fixture/input/{case.sample}",
    )


def observe(
    oracle: Oracle,
    fixture_dir: pathlib.Path,
    case: Case,
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
            "--read-only",
            "--mount",
            f"type=bind,src={fixture_dir},dst=/fixture,readonly",
            oracle.image,
            oracle.binary,
            *arguments(case),
        ],
        capture_output=True,
        timeout=180,
        check=False,
    )


def walk_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def nonnegative_integer(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must not be boolean")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        result = int(value)
    else:
        raise ValueError(f"{field} is not a decimal integer")
    if result < 0:
        raise ValueError(f"{field} must be non-negative")
    return result


def summarize_document(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {"detects"}:
        raise ValueError("unexpected scan JSON root")
    records = [
        item
        for item in walk_dicts(document["detects"])
        if "parentfilepart" in item
    ]
    resource_records = [
        record
        for record in records
        if record.get("parentfilepart") == "Resource"
    ]
    detections = [
        item["name"]
        for item in walk_dicts(document["detects"])
        if set(item) == {
            "info",
            "name",
            "string",
            "type",
            "version",
        }
    ]
    offsets = [
        nonnegative_integer(record["offset"], "resource offset")
        for record in resource_records
    ]
    sizes = [
        nonnegative_integer(record["size"], "resource size")
        for record in resource_records
    ]
    return {
        "detection_names": detections,
        "resource_count": len(resource_records),
        "resource_offsets_strictly_increasing": all(
            left < right for left, right in zip(offsets, offsets[1:])
        ),
        "first_resource_offset": offsets[0] if offsets else None,
        "last_resource_offset": offsets[-1] if offsets else None,
        "resource_sizes": sorted(set(sizes)),
    }


def raw_stream(
    data: bytes,
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    digest = sha256(data)
    compressed = zlib.compress(data, level=9)
    artifact = {
        "bytes": len(data),
        "encoding": "zlib+base64",
        "compressed_bytes": len(compressed),
        "base64": base64.b64encode(compressed).decode("ascii"),
    }
    previous = artifacts.setdefault(digest, artifact)
    if previous != artifact:
        raise ValueError("raw artifact digest collision")
    return {
        "bytes": len(data),
        "sha256": digest,
        "artifact_sha256": digest,
    }


def validate_summaries(summaries: dict[str, dict[str, Any]]) -> None:
    expected = {
        "deep_default": (["Binary normal"], 0),
        "deep_enabled": (
            ["Binary normal", "Binary deep", "Binary entrypoint"],
            0,
        ),
        "aggressive_without_recursive": (["PE root"], 0),
        "recursive_unclassified": (["PE root"], 0),
        "recursive_aggressive_unclassified": (
            ["PE root", "Binary normal"],
            1,
        ),
        "recursive_pdf_22": (["PE root", *(["PDF child"] * 21)], 21),
        "recursive_aggressive_pdf_22": (
            ["PE root", *(["PDF child"] * 22)],
            22,
        ),
        "recursive_aggressive_unclassified_2002": (
            ["PE root", *(["Binary normal"] * 2001)],
            2001,
        ),
    }
    for name, (names, resource_count) in expected.items():
        summary = summaries[name]
        if summary["detection_names"] != names:
            raise ValueError(f"unexpected detection order: {name}")
        if summary["resource_count"] != resource_count:
            raise ValueError(f"unexpected resource count: {name}")
        if resource_count > 1 and not summary[
            "resource_offsets_strictly_increasing"
        ]:
            raise ValueError(f"resource order changed: {name}")


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
) -> dict[str, Any]:
    manifest, manifest_sha256 = load_fixture(
        fixture_dir,
        manifest_path,
    )
    identities = {
        oracle.name: inspect_image(oracle) for oracle in ORACLES
    }
    if len({
        identity["resource_source_sha256"]
        for identity in identities.values()
    }) != 1:
        raise ValueError("resource source differs between oracles")
    if len({
        identity["console_source_sha256"]
        for identity in identities.values()
    }) != 1:
        raise ValueError("console source differs between oracles")
    if len({
        identity["pe_source_sha256"]
        for identity in identities.values()
    }) != 1:
        raise ValueError("PE source differs between oracles")

    observations: dict[str, Any] = {}
    raw_artifacts: dict[str, dict[str, Any]] = {}
    normalized_by_oracle: list[dict[str, dict[str, Any]]] = []
    raw_by_oracle: list[dict[str, tuple[bytes, bytes]]] = []
    for oracle in ORACLES:
        cases: dict[str, Any] = {}
        summaries: dict[str, dict[str, Any]] = {}
        raw_cases: dict[str, tuple[bytes, bytes]] = {}
        for case in CASES:
            process = observe(oracle, fixture_dir, case)
            if process.returncode != 0 or process.stderr:
                raise ValueError(
                    f"oracle execution failed: {oracle.name}/{case.name}"
                )
            document = strict_json(process.stdout)
            summary = summarize_document(document)
            summaries[case.name] = summary
            raw_cases[case.name] = (process.stdout, process.stderr)
            cases[case.name] = {
                "sample": case.sample,
                "arguments": list(arguments(case)),
                "exit_code": process.returncode,
                "stdout": raw_stream(process.stdout, raw_artifacts),
                "stderr": raw_stream(process.stderr, raw_artifacts),
                "summary": summary,
            }
        validate_summaries(summaries)
        normalized_by_oracle.append(summaries)
        raw_by_oracle.append(raw_cases)
        observations[oracle.name] = {
            **identities[oracle.name],
            "image": oracle.image,
            "binary": oracle.binary,
            "cases": cases,
        }

    if normalized_by_oracle[0] != normalized_by_oracle[1]:
        raise ValueError("qmake/CMake normalized outputs differ")
    for case in CASES:
        if raw_by_oracle[0][case.name] != raw_by_oracle[1][case.name]:
            raise ValueError(f"qmake/CMake raw output differs: {case.name}")

    facts = {
        "deep_adds_ds_and_ep_in_rule_order": True,
        "aggressive_alone_does_not_enable_resource_scan": True,
        "recursive_skips_unclassified_resource_without_aggressive": True,
        "recursive_aggressive_scans_unclassified_resource": True,
        "default_scanable_resource_limit_is_inclusive_21": True,
        "aggressive_resource_limit_is_inclusive_2001": True,
        "resource_children_preserve_enumeration_order": True,
        "grouped_fixture_respects_pe_per_directory_limit": True,
        "qmake_and_cmake_raw_outputs_are_equal": True,
    }
    return {
        "schema_version": 1,
        "generator": (
            "tools/upstream/probe_scan_option_boundaries.py"
        ),
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "platform": "linux-x86_64-qt5",
        "resource_limits": {
            "network": "none",
            "cpus": 1,
            "memory_bytes": 512 * 1024 * 1024,
            "pids": 128,
            "timeout_seconds_per_execution": 180,
            "fixture_mount": "read-only",
            "container_root": "read-only",
        },
        "fixture_manifest": {
            "path": (
                "docs/research/data/"
                "scan-option-boundary-fixture.json"
            ),
            "sha256": manifest_sha256,
            "entry_count": len(manifest["entries"]),
        },
        "local_sources": {
            "fixture_generator": {
                "path": FIXTURE_GENERATOR,
                "sha256": sha256(
                    (
                        pathlib.Path(__file__).resolve().parents[1]
                        / "corpus"
                        / "generate_scan_option_boundary_fixture.py"
                    ).read_bytes()
                ),
            },
            "nested_fixture_generator": {
                "path": "tools/corpus/generate_nested_corpus.py",
                "sha256": sha256(
                    (
                        pathlib.Path(__file__).resolve().parents[1]
                        / "corpus"
                        / "generate_nested_corpus.py"
                    ).read_bytes()
                ),
            },
        },
        "source_audit": source_audit(ORACLES[1].image),
        "observations": observations,
        "raw_artifacts": raw_artifacts,
        "facts": facts,
        "passed": all(facts.values()),
        "failures": [],
        "closed_corpus_gap": "CAP-GAP-005",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    repo = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument("--fixture-dir", required=True, type=pathlib.Path)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=(
            repo
            / "docs"
            / "research"
            / "data"
            / "scan-option-boundary-fixture.json"
        ),
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    report = build_report(
        args.fixture_dir.resolve(),
        args.manifest.resolve(),
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

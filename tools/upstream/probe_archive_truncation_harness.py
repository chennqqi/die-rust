#!/usr/bin/env python3
"""Probe pinned DIE archive truncation boundary behavior."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
from typing import Any
import zlib


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
FIXTURE_GENERATOR = (
    "tools/corpus/generate_archive_truncation_fixture.py"
)
SOURCE_GENERATOR = "tools/corpus/generate_archive_format_fixture.py"
HARNESS_SOURCE = "tools/upstream/archive_harness_main.cpp"
HARNESS_DOCKERFILE = "tools/upstream/Dockerfile.archive-harness-qt5"
IMAGE = "die-rust/upstream-archive-harness:74eaf505"
HARNESS_BINARY = "/opt/die-build/src/console/die-archive-harness"
RELEASE_BINARY = "/opt/die-build/src/console/diec"
DATABASE_ARGS = (
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
)
SOURCE_PATHS = {
    "engine": "/opt/die-source/XScanEngine/xscanengine.cpp",
    "sevenzip": "/opt/die-source/XArchive/xsevenzip.cpp",
    "rar": "/opt/die-source/XArchive/xrar.cpp",
    "cab": "/opt/die-source/XArchive/xcab.cpp",
    "iso9660": "/opt/die-source/XArchive/xiso9660.cpp",
}
SOURCE_PATTERNS = {
    "engine": (
        "XBinary::createFileBuffer("
        "archiveRecord.mapProperties.value("
        "XBinary::FPART_PROP_UNCOMPRESSEDSIZE).toLongLong(), "
        "pPdStruct)"
    ),
    "sevenzip": "bool XSevenZip::initUnpack(",
    "rar": "bool XRar::initUnpack(",
    "cab": "bool XCab::initUnpack(",
    "iso9660": "bool XISO9660::initUnpack(",
}
EXPECTED_ROOTS = {
    "sevenzip-signature.7z": ("Binary", ["Unknown"]),
    "sevenzip-header-minus-one.7z": ("Binary", ["Unknown"]),
    "sevenzip-header.7z": ("Binary", ["Unknown"]),
    "sevenzip-packed-data.7z": ("Binary", ["7-Zip"]),
    "sevenzip-full-minus-one.7z": ("Binary", ["7-Zip"]),
    "sevenzip-full.7z": ("Binary", ["7-Zip"]),
    "rar4-signature.rar": ("Binary", ["Unknown"]),
    "rar4-main-header-minus-one.rar": ("Binary", ["Unknown"]),
    "rar4-main-header.rar": ("Binary", ["Unknown"]),
    "rar4-file-header.rar": ("RAR", ["Unknown"]),
    "rar4-payload.rar": ("RAR", ["Unknown"]),
    "rar4-full-minus-one.rar": ("RAR", ["Unknown"]),
    "rar4-full.rar": ("RAR", ["Unknown"]),
    "cab-signature.cab": ("Binary", ["Plain text"]),
    "cab-header-minus-one.cab": ("Binary", ["Unknown"]),
    "cab-header.cab": ("Binary", ["Unknown"]),
    "cab-folder.cab": ("Binary", ["Unknown"]),
    "cab-data-start.cab": ("Binary", ["CAB"]),
    "cab-full-minus-one.cab": ("Binary", ["CAB"]),
    "cab-full.cab": ("Binary", ["CAB"]),
    "iso9660-descriptor-signature.iso": ("ISO 9660", ["Unknown"]),
    "iso9660-descriptor-version.iso": ("ISO 9660", ["Unknown"]),
    "iso9660-primary-descriptor.iso": ("ISO 9660", ["Unknown"]),
    "iso9660-directory-end.iso": ("ISO 9660", ["Unknown"]),
    "iso9660-full-minus-one.iso": ("ISO 9660", ["Unknown"]),
    "iso9660-full.iso": ("ISO 9660", ["Unknown"]),
}
CHILD_SAMPLES = {
    "sevenzip-full.7z",
    "rar4-payload.rar",
    "rar4-full-minus-one.rar",
    "rar4-full.rar",
    "cab-full.cab",
    "iso9660-full-minus-one.iso",
    "iso9660-full.iso",
}
EXPECTED_CHILD = {
    "detection_names": ["PDF", "HeaderComment"],
    "filetype": "PDF",
    "size": "331",
}


class ProbeError(ValueError):
    """The archive truncation fixture, oracle, or report is invalid."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(data: bytes) -> Any:
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ProbeError(f"non-finite JSON constant: {value}")
        ),
    )


def load_fixture(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
) -> tuple[dict[str, Any], str]:
    manifest_bytes = manifest_path.read_bytes()
    manifest = strict_json(manifest_bytes)
    if not isinstance(manifest, dict) or set(manifest) != {
        "generator",
        "license",
        "samples",
        "schema_version",
        "source_generator",
    }:
        raise ProbeError("fixture manifest fields changed")
    if manifest["schema_version"] != 1:
        raise ProbeError("unsupported fixture schema")
    if manifest["generator"] != FIXTURE_GENERATOR:
        raise ProbeError("unexpected fixture generator")
    if manifest["license"] != "project-generated":
        raise ProbeError("fixture license changed")
    if manifest["source_generator"].get("path") != SOURCE_GENERATOR:
        raise ProbeError("fixture source generator changed")
    if len(manifest["samples"]) != len(EXPECTED_ROOTS):
        raise ProbeError("fixture sample count changed")

    declared = set()
    for sample in manifest["samples"]:
        if set(sample) != {
            "archive_format",
            "boundary",
            "control_name",
            "cut_offset",
            "full_sha256",
            "full_size",
            "name",
            "purpose",
            "sha256",
            "size",
        }:
            raise ProbeError("fixture sample fields changed")
        name = sample["name"]
        if (
            pathlib.PurePosixPath(name).name != name
            or name in declared
            or name not in EXPECTED_ROOTS
        ):
            raise ProbeError(
                f"unsafe, unknown, or duplicate fixture name: {name}"
            )
        path = fixture_dir / name
        if path.is_symlink() or not path.is_file():
            raise ProbeError(
                f"fixture file missing or symlinked: {name}"
            )
        data = path.read_bytes()
        if (
            len(data) != sample["size"]
            or sample["cut_offset"] != sample["size"]
            or sha256(data) != sample["sha256"]
        ):
            raise ProbeError(f"fixture identity mismatch: {name}")
        declared.add(name)
    if declared != set(EXPECTED_ROOTS):
        raise ProbeError("fixture expected inventory changed")
    actual = {
        path.name
        for path in fixture_dir.iterdir()
        if path.is_file() and path.name != "manifest.json"
    }
    if actual != declared:
        raise ProbeError("fixture file inventory mismatch")
    return manifest, sha256(manifest_bytes)


def inspect_image() -> dict[str, Any]:
    process = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        check=True,
        capture_output=True,
    )
    documents = strict_json(process.stdout)
    if not isinstance(documents, list) or len(documents) != 1:
        raise ProbeError("unexpected image inspection shape")
    document = documents[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision",
        "",
    )
    if revision != UPSTREAM_COMMIT:
        raise ProbeError("archive harness revision changed")
    return {
        "id": document["Id"],
        "repo_digests": sorted(document.get("RepoDigests") or []),
        "revision": revision,
    }


def read_container_files(paths: tuple[str, ...]) -> dict[str, bytes]:
    script = (
        "import base64,json,pathlib;"
        f"paths={paths!r};"
        "print(json.dumps({p:base64.b64encode("
        "pathlib.Path(p).read_bytes()).decode('ascii') for p in paths},"
        "sort_keys=True))"
    )
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            IMAGE,
            "python3",
            "-c",
            script,
        ],
        check=True,
        capture_output=True,
    )
    encoded = strict_json(process.stdout)
    if set(encoded) != set(paths):
        raise ProbeError("container file inventory changed")
    return {
        path: base64.b64decode(value, validate=True)
        for path, value in encoded.items()
    }


def source_contract(files: dict[str, bytes]) -> dict[str, Any]:
    result = {}
    for name, path in SOURCE_PATHS.items():
        data = files[path]
        count = data.decode("utf-8").count(SOURCE_PATTERNS[name])
        if count < 1:
            raise ProbeError(f"source pattern missing: {name}")
        result[name] = {
            "path": path,
            "required_pattern": SOURCE_PATTERNS[name],
            "required_pattern_count": count,
            "sha256": sha256(data),
        }
    return result


def run_binary(
    *,
    binary: str,
    fixture_dir: pathlib.Path,
    arguments: tuple[str, ...],
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
            IMAGE,
            binary,
            *arguments,
        ],
        capture_output=True,
        timeout=60,
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


def summarize(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {"detects"}:
        raise ProbeError("unexpected scan JSON root")
    detects = document["detects"]
    if not isinstance(detects, list) or len(detects) != 1:
        raise ProbeError("expected exactly one root detection")
    root = detects[0]
    streams = [
        item
        for item in walk_dicts(root)
        if item.get("parentfilepart") == "Stream"
    ]
    return {
        "root_detection_names": [
            value["name"]
            for value in root.get("values", [])
            if (
                isinstance(value, dict)
                and "parentfilepart" not in value
            )
        ],
        "root_filetype": root.get("filetype"),
        "stream_count": len(streams),
        "streams": [
            {
                "detection_names": [
                    value["name"]
                    for value in stream.get("values", [])
                    if (
                        isinstance(value, dict)
                        and "parentfilepart" not in value
                    )
                ],
                "filetype": stream.get("filetype"),
                "size": stream.get("size"),
            }
            for stream in streams
        ],
    }


def raw_ref(
    data: bytes,
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    digest = sha256(data)
    compressed = zlib.compress(data, 9)
    artifact = {
        "base64": base64.b64encode(compressed).decode("ascii"),
        "bytes": len(data),
        "compressed_bytes": len(compressed),
        "encoding": "zlib+base64",
    }
    previous = artifacts.setdefault(digest, artifact)
    if previous != artifact:
        raise ProbeError("raw artifact digest collision")
    return {
        "artifact_sha256": digest,
        "bytes": len(data),
        "sha256": digest,
    }


def validate_case(
    *,
    sample_name: str,
    mode: str,
    process: subprocess.CompletedProcess[bytes],
    summary: dict[str, Any],
) -> None:
    if process.returncode != 0:
        raise ProbeError(f"nonzero exit: {sample_name}/{mode}")
    if process.stderr:
        raise ProbeError(f"stderr changed: {sample_name}/{mode}")
    expected_filetype, expected_names = EXPECTED_ROOTS[sample_name]
    if (
        summary["root_filetype"] != expected_filetype
        or summary["root_detection_names"] != expected_names
    ):
        raise ProbeError(
            f"root detection changed: {sample_name}/{mode}"
        )
    expected_streams = (
        [EXPECTED_CHILD]
        if (
            mode not in {"default", "release_default"}
            and sample_name in CHILD_SAMPLES
        )
        else []
    )
    if (
        summary["streams"] != expected_streams
        or summary["stream_count"] != len(expected_streams)
    ):
        raise ProbeError(f"stream result changed: {sample_name}/{mode}")


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
) -> dict[str, Any]:
    manifest, manifest_sha256 = load_fixture(
        fixture_dir,
        manifest_path,
    )
    container_paths = (
        HARNESS_BINARY,
        RELEASE_BINARY,
        *SOURCE_PATHS.values(),
    )
    container_files = read_container_files(container_paths)
    artifacts: dict[str, dict[str, Any]] = {}
    cases: dict[str, Any] = {}

    for sample in manifest["samples"]:
        sample_name = sample["name"]
        sample_cases: dict[str, Any] = {}
        raw_modes: dict[str, tuple[bytes, bytes]] = {}
        for mode, flags in (
            ("default", ()),
            ("archive", ("--archive",)),
            (
                "archive_aggressive",
                ("--archive", "--aggressive"),
            ),
        ):
            arguments = (*flags, f"/fixture/{sample_name}")
            process = run_binary(
                binary=HARNESS_BINARY,
                fixture_dir=fixture_dir,
                arguments=arguments,
            )
            summary = summarize(strict_json(process.stdout))
            validate_case(
                sample_name=sample_name,
                mode=mode,
                process=process,
                summary=summary,
            )
            raw_modes[mode] = (process.stdout, process.stderr)
            sample_cases[mode] = {
                "arguments": list(arguments),
                "exit_code": process.returncode,
                "stderr": raw_ref(process.stderr, artifacts),
                "stdout": raw_ref(process.stdout, artifacts),
                "summary": summary,
            }

        if raw_modes["archive"] != raw_modes["archive_aggressive"]:
            raise ProbeError(
                f"aggressive unexpectedly changed output: {sample_name}"
            )

        release_arguments = (
            "--json",
            *DATABASE_ARGS,
            f"/fixture/{sample_name}",
        )
        release = run_binary(
            binary=RELEASE_BINARY,
            fixture_dir=fixture_dir,
            arguments=release_arguments,
        )
        release_summary = summarize(strict_json(release.stdout))
        validate_case(
            sample_name=sample_name,
            mode="release_default",
            process=release,
            summary=release_summary,
        )
        if (release.stdout, release.stderr) != raw_modes["default"]:
            raise ProbeError(
                f"harness/release default drift: {sample_name}"
            )
        sample_cases["release_default"] = {
            "arguments": list(release_arguments),
            "exit_code": release.returncode,
            "stderr": raw_ref(release.stderr, artifacts),
            "stdout": raw_ref(release.stdout, artifacts),
            "summary": release_summary,
        }
        cases[sample_name] = sample_cases

    facts = {
        "all_truncation_cases_exit_zero_without_stderr": True,
        "release_and_harness_default_outputs_are_equal": True,
        "archive_and_aggressive_outputs_are_equal": True,
        "sevenzip_full_minus_one_detects_but_has_no_child": True,
        "cab_full_minus_one_detects_but_has_no_child": True,
        "rar4_payload_boundary_reaches_pdf_without_end_header": True,
        "iso9660_full_minus_one_reaches_declared_pdf_child": True,
        "signature_or_partial_headers_do_not_produce_children": True,
    }
    root = pathlib.Path(__file__).resolve().parents[2]
    return {
        "binaries": {
            "harness": {
                "path": HARNESS_BINARY,
                "sha256": sha256(container_files[HARNESS_BINARY]),
                "size": len(container_files[HARNESS_BINARY]),
            },
            "release": {
                "path": RELEASE_BINARY,
                "sha256": sha256(container_files[RELEASE_BINARY]),
                "size": len(container_files[RELEASE_BINARY]),
            },
        },
        "cases": cases,
        "execution_count": len(cases) * 4,
        "facts": facts,
        "failures": [],
        "fixture_manifest": {
            "path": (
                "docs/research/data/"
                "archive-truncation-corpus.json"
            ),
            "sample_count": len(manifest["samples"]),
            "sha256": manifest_sha256,
        },
        "generator": (
            "tools/upstream/"
            "probe_archive_truncation_harness.py"
        ),
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "image": {
            **inspect_image(),
            "name": IMAGE,
        },
        "local_sources": {
            "fixture_generator": {
                "path": FIXTURE_GENERATOR,
                "sha256": sha256(
                    (root / FIXTURE_GENERATOR).read_bytes()
                ),
            },
            "source_generator": {
                "path": SOURCE_GENERATOR,
                "sha256": sha256(
                    (root / SOURCE_GENERATOR).read_bytes()
                ),
            },
            "harness_dockerfile": {
                "path": HARNESS_DOCKERFILE,
                "sha256": sha256(
                    (root / HARNESS_DOCKERFILE).read_bytes()
                ),
            },
            "harness_source": {
                "path": HARNESS_SOURCE,
                "sha256": sha256(
                    (root / HARNESS_SOURCE).read_bytes()
                ),
            },
        },
        "passed": all(facts.values()),
        "platform": "linux-x86_64-qt5",
        "raw_artifacts": artifacts,
        "remaining_gap": "CAP-GAP-006",
        "resource_limits": {
            "container_root": "read-only",
            "cpus": 1,
            "fixture_mount": "read-only",
            "memory_bytes": 512 * 1024 * 1024,
            "network": "none",
            "pids": 128,
            "timeout_seconds_per_execution": 60,
        },
        "schema_version": 1,
        "source_contract": source_contract(container_files),
        "upstream_commit": UPSTREAM_COMMIT,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    root = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument("--fixture-dir", required=True, type=pathlib.Path)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=(
            root
            / "docs"
            / "research"
            / "data"
            / "archive-truncation-corpus.json"
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

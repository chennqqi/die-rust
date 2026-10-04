#!/usr/bin/env python3
"""Probe generic Archive dispatch in the pinned upstream engine."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import zlib
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
COMPONENT_COMMITS = {
    "Detect-It-Easy": "c2c17dfa5ea4e078ba31eab55d87430c96622fb6",
    "Formats": "1151e7254fdee3c0294ff7095edbdd7bfccf8201",
    "XArchive": "0fcd4e8d3e9933baac3b12246d82ac026557ffd0",
    "XScanEngine": "dfe4a419e4f491bb23688ba03c5a5bf39e34da83",
    "die_script": "5d82316c110abf0eb863b50bc679d330e05067b6",
}
FIXTURE_GENERATOR = (
    "tools/corpus/generate_generic_archive_dispatch_fixture.py"
)
BASELINE_GENERATOR = "tools/corpus/generate_baseline_corpus.py"
FIXTURE_MANIFEST = (
    "docs/research/data/generic-archive-dispatch-fixture.json"
)
HARNESS_SOURCE = (
    "tools/upstream/generic_archive_dispatch_harness_main.cpp"
)
HARNESS_DOCKERFILE = (
    "tools/upstream/"
    "Dockerfile.generic-archive-dispatch-harness-qt5"
)
HARNESS_IMAGE = (
    "die-rust/generic-archive-dispatch-harness-qt5:74eaf505"
)
QMAKE_IMAGE = "die-rust/upstream-oracle:74eaf505-repro"
HARNESS_BINARY = (
    "/opt/die-build/src/console/"
    "die-generic-archive-dispatch-harness"
)
CMAKE_RELEASE_BINARY = "/opt/die-build/src/console/diec"
QMAKE_RELEASE_BINARY = "/opt/die-source/build/release/diec"
DATABASE_ARGS = (
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
)
SOURCE_PATHS = {
    "archive_rule": (
        "/opt/die-source/Detect-It-Easy/db/Archive/_Archive.0.sg"
    ),
    "binary_archive_rule": (
        "/opt/die-source/Detect-It-Easy/db/Binary/"
        "archive_archives.1.sg"
    ),
    "formats": "/opt/die-source/Formats/xformats.cpp",
    "scan_engine": "/opt/die-source/XScanEngine/xscanengine.cpp",
    "script_engine": "/opt/die-source/die_script/die_scriptengine.cpp",
    "zip_rule": (
        "/opt/die-source/Detect-It-Easy/db/ZIP/_ZIP.0.sg"
    ),
}
SOURCE_PATTERNS = {
    "archive_rule": (
        "if (Archive.isVerbose()) {",
        "Archive.getFileFormatName()",
    ),
    "binary_archive_rule": (
        'Binary.compare("00\'ustar\'", 0x100)',
        'sName = "tar";',
    ),
    "formats": (
        "stResult.insert(XBinary::FT_ARCHIVE);",
        "stResult.insert(XBinary::FT_ZIP);",
        "stResult.insert(XBinary::FT_TAR);",
        "stResult.insert(XBinary::FT_GZIP);",
        "XBinary::checkFileType(XBinary::FT_ZIP, fileType)",
        "XBinary::checkFileType(XBinary::FT_TAR, fileType)",
        "XBinary::checkFileType(XBinary::FT_GZIP, fileType)",
    ),
    "scan_engine": (
        "stFT.contains(XBinary::FT_ARCHIVE) && (stFT.size() == 1)",
        "XBinary::FT_ARCHIVE, pScanOptions, true",
    ),
    "script_engine": (
        "XBinary::checkFileType(XBinary::FT_ARCHIVE, fileType)",
        "QSet<XBinary::FT> fileTypes = "
        "XBinary::getFileTypes(pDevice, true);",
        "XFormats::createClass(_fileType, pDevice)",
        "new Archive_Script(_pArchive",
    ),
    "zip_rule": (
        "if (ZIP.isVerbose()) {",
        "ZIP.getFileFormatName()",
    ),
}
EXPECTED = {
    "payload.zip": {
        "detected": "BINARY|ARCHIVE|ZIP",
        "initial": "ZIP",
        "automatic_quiet": [
            ("ZIP", "Unknown", "Unknown", "", True),
        ],
        "automatic_verbose": [
            ("ZIP", "format", "ZIP", "_ZIP.0.sg", False),
        ],
        "forced_name": "ZIP",
    },
    "payload.tar": {
        "detected": "BINARY|ARCHIVE|TAR|TEXT|UTF8",
        "initial": "Binary",
        "automatic_quiet": [
            (
                "Binary",
                "archive",
                "tar",
                "archive_archives.1.sg",
                False,
            ),
        ],
        "automatic_verbose": [
            (
                "Binary",
                "archive",
                "tar",
                "archive_archives.1.sg",
                False,
            ),
        ],
        "forced_name": "tar",
    },
    "payload.txt.gz": {
        "detected": "BINARY|ARCHIVE|GZIP",
        "initial": "Binary",
        "automatic_quiet": [
            ("Binary", "Unknown", "Unknown", "", True),
        ],
        "automatic_verbose": [
            ("Binary", "Unknown", "Unknown", "", True),
        ],
        "forced_name": "GZIP",
    },
}
ROOT = pathlib.Path(__file__).resolve().parents[2]


class ProbeError(ValueError):
    """The fixture, oracle, or Archive behavior contract is invalid."""


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
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProbeError(f"non-finite JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError("invalid UTF-8 JSON") from error


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
    }:
        raise ProbeError("fixture manifest fields changed")
    if manifest["schema_version"] != 1:
        raise ProbeError("unsupported fixture schema")
    if manifest["generator"] != FIXTURE_GENERATOR:
        raise ProbeError("unexpected fixture generator")
    if len(manifest["samples"]) != 3:
        raise ProbeError("fixture sample count changed")

    declared = set()
    for sample in manifest["samples"]:
        if set(sample) != {
            "archive_format",
            "expected_member_name",
            "expected_payload_sha256",
            "name",
            "purpose",
            "sha256",
            "size",
        }:
            raise ProbeError("fixture sample fields changed")
        name = sample["name"]
        if pathlib.PurePosixPath(name).name != name or name in declared:
            raise ProbeError(f"unsafe or duplicate fixture name: {name}")
        path = fixture_dir / name
        if path.is_symlink() or not path.is_file():
            raise ProbeError(f"fixture file missing or symlinked: {name}")
        data = path.read_bytes()
        if len(data) != sample["size"] or sha256(data) != sample["sha256"]:
            raise ProbeError(f"fixture identity mismatch: {name}")
        declared.add(name)
    actual = {
        path.name
        for path in fixture_dir.iterdir()
        if path.is_file() and path.name != "manifest.json"
    }
    if actual != declared:
        raise ProbeError("fixture file inventory mismatch")
    generated_manifest = fixture_dir / "manifest.json"
    if (
        generated_manifest.exists()
        and generated_manifest.read_bytes() != manifest_bytes
    ):
        raise ProbeError("generated fixture manifest differs from committed")
    return manifest, sha256(manifest_bytes)


def inspect_image(image: str) -> dict[str, Any]:
    process = subprocess.run(
        ["docker", "image", "inspect", image],
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
        raise ProbeError(f"image revision changed: {image}")
    return {
        "id": document["Id"],
        "name": image,
        "repo_digests": sorted(document.get("RepoDigests") or []),
        "revision": revision,
    }


def docker_bytes(
    image: str,
    entrypoint: str,
    *arguments: str,
) -> bytes:
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--entrypoint",
            entrypoint,
            image,
            *arguments,
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    if process.stderr:
        raise ProbeError(f"{entrypoint} wrote stderr")
    return process.stdout


def read_container_files(
    image: str,
    paths: tuple[str, ...],
) -> dict[str, bytes]:
    script = (
        "import base64,json,pathlib;"
        f"paths={paths!r};"
        "print(json.dumps({p:base64.b64encode("
        "pathlib.Path(p).read_bytes()).decode('ascii') for p in paths},"
        "sort_keys=True))"
    )
    encoded = strict_json(
        docker_bytes(image, "/usr/bin/python3", "-c", script)
    )
    return {
        path: base64.b64decode(value, validate=True)
        for path, value in encoded.items()
    }


def verify_component_commits() -> dict[str, str]:
    observed = {}
    for name, expected in COMPONENT_COMMITS.items():
        commit = docker_bytes(
            HARNESS_IMAGE,
            "/usr/bin/git",
            "-C",
            f"/opt/die-source/{name}",
            "rev-parse",
            "HEAD",
        ).decode("ascii").strip()
        if commit != expected:
            raise ProbeError(f"{name} component commit changed")
        observed[name] = commit
    return observed


def source_contract(
    container_files: dict[str, bytes],
) -> dict[str, Any]:
    result = {}
    for name, path in SOURCE_PATHS.items():
        data = container_files[path]
        text = data.decode("utf-8")
        patterns = []
        for pattern in SOURCE_PATTERNS[name]:
            count = text.count(pattern)
            if count < 1:
                raise ProbeError(f"source pattern missing: {name}")
            patterns.append({"text": pattern, "count": count})
        result[name] = {
            "path": path,
            "sha256": sha256(data),
            "required_patterns": patterns,
        }
    return result


def run_binary(
    *,
    image: str,
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
            image,
            binary,
            *arguments,
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )


def record_tuples(scan: dict[str, Any]) -> list[tuple[Any, ...]]:
    return [
        (
            record["filetype"],
            record["type"],
            record["name"],
            record["signature"],
            record["unknown"],
        )
        for record in scan["records"]
    ]


def validate_scan_common(scan: dict[str, Any]) -> None:
    if not scan["database_loaded"]:
        raise ProbeError("database did not load")
    if scan["error_count"] != 0 or not scan["scan_success"]:
        raise ProbeError("scan failed")
    if scan["record_count"] != len(scan["records"]):
        raise ProbeError("record count changed")


def validate_harness(
    document: dict[str, Any],
    sample: dict[str, Any],
) -> None:
    expected_header = {
        "schema_version": 1,
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": COMPONENT_COMMITS["Formats"],
        "xscanengine_commit": COMPONENT_COMMITS["XScanEngine"],
        "die_script_commit": COMPONENT_COMMITS["die_script"],
        "input_name": sample["name"],
        "input_size": sample["size"],
    }
    for key, value in expected_header.items():
        if document.get(key) != value:
            raise ProbeError(f"harness field changed: {key}")
    expected = EXPECTED[sample["name"]]

    for mode, verbose in (
        ("automatic_quiet", False),
        ("automatic_verbose", True),
    ):
        scan = document[mode]
        validate_scan_common(scan)
        if (
            scan["forced"]
            or scan["verbose"] is not verbose
            or scan["property"] != ""
            or scan["detected_filetypes"] != expected["detected"]
            or scan["initial_filetype"] != expected["initial"]
            or record_tuples(scan) != expected[mode]
        ):
            raise ProbeError(f"automatic Archive behavior changed: {mode}")

    quiet = document["forced_archive_quiet"]
    validate_scan_common(quiet)
    if (
        not quiet["forced"]
        or quiet["verbose"]
        or quiet["property"] != "ARCHIVE"
        or quiet["detected_filetypes"] != "ARCHIVE"
        or quiet["initial_filetype"] != "Archive"
        or record_tuples(quiet)
        != [("Archive", "Unknown", "Unknown", "", True)]
    ):
        raise ProbeError("forced quiet Archive behavior changed")

    verbose = document["forced_archive_verbose"]
    validate_scan_common(verbose)
    if (
        not verbose["forced"]
        or not verbose["verbose"]
        or verbose["property"] != "ARCHIVE"
        or verbose["detected_filetypes"] != "ARCHIVE"
        or verbose["initial_filetype"] != "Archive"
        or record_tuples(verbose)
        != [
            (
                "Archive",
                "format",
                expected["forced_name"],
                "_Archive.0.sg",
                False,
            )
        ]
    ):
        raise ProbeError("forced verbose Archive behavior changed")


def summarize_release(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {"detects"}:
        raise ProbeError("unexpected release JSON root")
    detects = document["detects"]
    if not isinstance(detects, list) or len(detects) != 1:
        raise ProbeError("expected one release root")
    root = detects[0]
    return {
        "filetype": root.get("filetype"),
        "names": [
            record.get("name")
            for record in root.get("values", [])
        ],
        "offset": root.get("offset"),
        "parentfilepart": root.get("parentfilepart"),
        "size": root.get("size"),
    }


def validate_release_summary(
    summary: dict[str, Any],
    sample: dict[str, Any],
    *,
    verbose: bool,
) -> None:
    expected = EXPECTED[sample["name"]]
    harness_mode = (
        "automatic_verbose" if verbose else "automatic_quiet"
    )
    names = [record[2] for record in expected[harness_mode]]
    if summary != {
        "filetype": expected["initial"],
        "names": names,
        "offset": "0",
        "parentfilepart": "Header",
        "size": str(sample["size"]),
    }:
        raise ProbeError("release summary changed")


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


def execution(
    process: subprocess.CompletedProcess[bytes],
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "exit_code": process.returncode,
        "stderr": raw_ref(process.stderr, artifacts),
        "stdout": raw_ref(process.stdout, artifacts),
    }


def run_release_pair(
    *,
    fixture_dir: pathlib.Path,
    fixture_argument: str,
    verbose: bool,
) -> tuple[
    subprocess.CompletedProcess[bytes],
    subprocess.CompletedProcess[bytes],
    tuple[str, ...],
]:
    flags = ("--verbose",) if verbose else ()
    arguments = (
        "--json",
        *flags,
        *DATABASE_ARGS,
        fixture_argument,
    )
    cmake = run_binary(
        image=HARNESS_IMAGE,
        binary=CMAKE_RELEASE_BINARY,
        fixture_dir=fixture_dir,
        arguments=arguments,
    )
    qmake = run_binary(
        image=QMAKE_IMAGE,
        binary=QMAKE_RELEASE_BINARY,
        fixture_dir=fixture_dir,
        arguments=arguments,
    )
    if (
        cmake.returncode != 0
        or qmake.returncode != 0
        or cmake.stderr
        or qmake.stderr
    ):
        raise ProbeError("release oracle failed")
    if (cmake.stdout, cmake.stderr) != (
        qmake.stdout,
        qmake.stderr,
    ):
        raise ProbeError("qmake/CMake output drift")
    return cmake, qmake, arguments


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
) -> dict[str, Any]:
    manifest, manifest_sha256 = load_fixture(
        fixture_dir,
        manifest_path,
    )
    harness_paths = (
        HARNESS_BINARY,
        CMAKE_RELEASE_BINARY,
        *SOURCE_PATHS.values(),
    )
    harness_files = read_container_files(HARNESS_IMAGE, harness_paths)
    qmake_files = read_container_files(
        QMAKE_IMAGE,
        (QMAKE_RELEASE_BINARY,),
    )
    artifacts: dict[str, dict[str, Any]] = {}
    cases = {}

    for sample in manifest["samples"]:
        sample_name = sample["name"]
        fixture_argument = f"/fixture/{sample_name}"
        harness = run_binary(
            image=HARNESS_IMAGE,
            binary=HARNESS_BINARY,
            fixture_dir=fixture_dir,
            arguments=(fixture_argument,),
        )
        if harness.returncode != 0 or harness.stderr:
            raise ProbeError(f"harness failed: {sample_name}")
        harness_document = strict_json(harness.stdout)
        validate_harness(harness_document, sample)

        case: dict[str, Any] = {
            "harness": {
                **execution(harness, artifacts),
                "arguments": [fixture_argument],
                "output": harness_document,
            }
        }
        for mode, verbose in (("quiet", False), ("verbose", True)):
            cmake, qmake, arguments = run_release_pair(
                fixture_dir=fixture_dir,
                fixture_argument=fixture_argument,
                verbose=verbose,
            )
            summary = summarize_release(strict_json(cmake.stdout))
            validate_release_summary(
                summary,
                sample,
                verbose=verbose,
            )
            case[f"cmake_release_{mode}"] = {
                **execution(cmake, artifacts),
                "arguments": list(arguments),
                "summary": summary,
            }
            case[f"qmake_release_{mode}"] = {
                **execution(qmake, artifacts),
                "arguments": list(arguments),
                "summary": summary,
            }
        cases[sample_name] = case

    facts = {
        "natural_detection_pairs_archive_with_concrete_subtype": all(
            "ARCHIVE"
            in case["harness"]["output"]["automatic_quiet"][
                "detected_filetypes"
            ].split("|")
            and len(
                case["harness"]["output"]["automatic_quiet"][
                    "detected_filetypes"
                ].split("|")
            )
            > 1
            for case in cases.values()
        ),
        "automatic_scan_never_initializes_generic_archive": all(
            case["harness"]["output"]["automatic_quiet"][
                "initial_filetype"
            ]
            != "Archive"
            for case in cases.values()
        ),
        "zip_uses_specialized_public_branch": (
            cases["payload.zip"]["harness"]["output"][
                "automatic_quiet"
            ]["initial_filetype"]
            == "ZIP"
        ),
        "tar_and_gzip_use_binary_public_fallback": all(
            cases[name]["harness"]["output"]["automatic_quiet"][
                "initial_filetype"
            ]
            == "Binary"
            for name in ("payload.tar", "payload.txt.gz")
        ),
        "automatic_verbose_does_not_force_generic_archive": all(
            case["harness"]["output"]["automatic_verbose"][
                "initial_filetype"
            ]
            != "Archive"
            for case in cases.values()
        ),
        "forced_quiet_archive_is_unknown": all(
            case["harness"]["output"]["forced_archive_quiet"][
                "records"
            ][0]["unknown"]
            for case in cases.values()
        ),
        "forced_verbose_archive_redetects_all_adapters": (
            [
                cases[name]["harness"]["output"][
                    "forced_archive_verbose"
                ]["records"][0]["name"]
                for name in EXPECTED
            ]
            == ["ZIP", "tar", "GZIP"]
        ),
        "qmake_and_cmake_release_outputs_are_byte_equal": all(
            case[f"qmake_release_{mode}"]["stdout"]
            == case[f"cmake_release_{mode}"]["stdout"]
            and case[f"qmake_release_{mode}"]["stderr"]
            == case[f"cmake_release_{mode}"]["stderr"]
            for case in cases.values()
            for mode in ("quiet", "verbose")
        ),
        "release_and_harness_automatic_semantics_agree": all(
            case[f"cmake_release_{release_mode}"]["summary"][
                "filetype"
            ]
            == case["harness"]["output"][harness_mode][
                "initial_filetype"
            ]
            and case[f"cmake_release_{release_mode}"]["summary"][
                "names"
            ]
            == [
                record["name"]
                for record in case["harness"]["output"][harness_mode][
                    "records"
                ]
            ]
            for case in cases.values()
            for release_mode, harness_mode in (
                ("quiet", "automatic_quiet"),
                ("verbose", "automatic_verbose"),
            )
        ),
    }
    if not all(facts.values()):
        raise ProbeError("derived generic Archive facts failed")

    local_sources = {}
    for name, path in {
        "baseline_generator": BASELINE_GENERATOR,
        "fixture_generator": FIXTURE_GENERATOR,
        "harness_dockerfile": HARNESS_DOCKERFILE,
        "harness_source": HARNESS_SOURCE,
        "probe": (
            "tools/upstream/"
            "probe_generic_archive_dispatch_harness.py"
        ),
    }.items():
        local_sources[name] = {
            "path": path,
            "sha256": sha256((ROOT / path).read_bytes()),
        }

    return {
        "schema_version": 1,
        "generator": (
            "tools/upstream/"
            "probe_generic_archive_dispatch_harness.py"
        ),
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "component_commits": verify_component_commits(),
        "platform": "linux-x86_64-qt5",
        "images": {
            "harness_cmake": inspect_image(HARNESS_IMAGE),
            "release_qmake": inspect_image(QMAKE_IMAGE),
        },
        "binaries": {
            "harness": {
                "path": HARNESS_BINARY,
                "sha256": sha256(harness_files[HARNESS_BINARY]),
                "size": len(harness_files[HARNESS_BINARY]),
            },
            "release_cmake": {
                "path": CMAKE_RELEASE_BINARY,
                "sha256": sha256(
                    harness_files[CMAKE_RELEASE_BINARY]
                ),
                "size": len(harness_files[CMAKE_RELEASE_BINARY]),
            },
            "release_qmake": {
                "path": QMAKE_RELEASE_BINARY,
                "sha256": sha256(
                    qmake_files[QMAKE_RELEASE_BINARY]
                ),
                "size": len(qmake_files[QMAKE_RELEASE_BINARY]),
            },
        },
        "local_sources": local_sources,
        "source_contract": source_contract(harness_files),
        "fixture_manifest": {
            "path": FIXTURE_MANIFEST,
            "sample_count": len(manifest["samples"]),
            "sha256": manifest_sha256,
        },
        "resource_limits": {
            "container_root": "read-only",
            "cpus": 1,
            "fixture_mount": "read-only",
            "memory_bytes": 512 * 1024 * 1024,
            "network": "none",
            "pids": 128,
            "timeout_seconds_per_execution": 60,
        },
        "cases": cases,
        "raw_artifacts": artifacts,
        "facts": facts,
        "passed": True,
        "failures": [],
        "remaining_gap": "CAP-GAP-006",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", required=True, type=pathlib.Path)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=ROOT / FIXTURE_MANIFEST,
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

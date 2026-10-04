#!/usr/bin/env python3
"""Probe NPM detector reachability in the pinned upstream engine."""

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
    "Formats": "1151e7254fdee3c0294ff7095edbdd7bfccf8201",
    "XArchive": "0fcd4e8d3e9933baac3b12246d82ac026557ffd0",
    "XScanEngine": "dfe4a419e4f491bb23688ba03c5a5bf39e34da83",
    "die_script": "5d82316c110abf0eb863b50bc679d330e05067b6",
}
FIXTURE_GENERATOR = "tools/corpus/generate_npm_dispatch_fixture.py"
FIXTURE_MANIFEST = "docs/research/data/npm-dispatch-fixture.json"
HARNESS_SOURCE = "tools/upstream/npm_dispatch_harness_main.cpp"
HARNESS_DOCKERFILE = (
    "tools/upstream/Dockerfile.npm-dispatch-harness-qt5"
)
HARNESS_IMAGE = "die-rust/npm-dispatch-harness-qt5:74eaf505"
QMAKE_IMAGE = "die-rust/upstream-oracle:74eaf505-repro"
HARNESS_BINARY = (
    "/opt/die-build/src/console/die-npm-dispatch-harness"
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
    "formats": "/opt/die-source/Formats/xformats.cpp",
    "npm": "/opt/die-source/XArchive/xnpm.cpp",
    "npm_format_rule": (
        "/opt/die-source/Detect-It-Easy/db/NPM/_NPM.0.sg"
    ),
    "npm_javascript_rule": (
        "/opt/die-source/Detect-It-Easy/db/NPM/"
        "language_JavaScript.5.sg"
    ),
    "npm_package_rule": (
        "/opt/die-source/Detect-It-Easy/db/NPM/"
        "package_PackageName.1.sg"
    ),
    "npm_typescript_rule": (
        "/opt/die-source/Detect-It-Easy/db/NPM/"
        "language_TypeScript.5.sg"
    ),
    "scan_engine": "/opt/die-source/XScanEngine/xscanengine.cpp",
    "script_engine": "/opt/die-source/die_script/die_scriptengine.cpp",
}
SOURCE_PATTERNS = {
    "formats": (
        "QSet<XBinary::FT> XFormats::getFileTypesTGZ(",
        "stResult.insert(XBinary::FT_NPM);",
        "QSet<XBinary::FT> XFormats::getFileTypesGZIP(",
        "//         stResult += getFileTypesTGZ(",
        "stResult.insert(XBinary::FT_GZIP);",
    ),
    "npm": (
        'XArchive::isArchiveRecordPresent("package/package.json"',
    ),
    "npm_format_rule": (
        "if (NPM.isVerbose()) {",
    ),
    "npm_javascript_rule": (
        'NPM.isArchiveRecordPresentExp("(.*?).js")',
    ),
    "npm_package_rule": (
        'NPM.getPackageJsonRecord("name")',
        'NPM.getPackageJsonRecord("version")',
    ),
    "npm_typescript_rule": (
        'NPM.isArchiveRecordPresentExp("(.*?).ts")',
    ),
    "scan_engine": (
        "} else if (stFT.contains(XBinary::FT_NPM)) {",
        "_processDetect(&scanIdMain, pScanResult, _pDevice, "
        "parentId, XBinary::FT_NPM",
    ),
    "script_engine": (
        "NPM_Script *pExtraScript = new NPM_Script(",
    ),
}
EXPECTED_FORCED_RECORDS = {
    "npm-valid.tgz": [
        ("JavaScript", "language_JavaScript.5.sg"),
    ],
    "npm-invalid-json.tgz": [
        ("JavaScript", "language_JavaScript.5.sg"),
        ("TypeScript", "language_TypeScript.5.sg"),
    ],
    "root-package-json.tgz": [
        ("JavaScript", "language_JavaScript.5.sg"),
    ],
    "case-package-json.tgz": [
        ("JavaScript", "language_JavaScript.5.sg"),
        ("TypeScript", "language_TypeScript.5.sg"),
    ],
}
ROOT = pathlib.Path(__file__).resolve().parents[2]


class ProbeError(ValueError):
    """The fixture, oracle, or NPM behavior contract is invalid."""


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
    if len(manifest["samples"]) != 4:
        raise ProbeError("fixture sample count changed")

    declared = set()
    for sample in manifest["samples"]:
        if set(sample) != {
            "detector_control",
            "entries",
            "expected_npm",
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
        path = f"/opt/die-source/{name}"
        commit = docker_bytes(
            HARNESS_IMAGE,
            "/usr/bin/git",
            "-C",
            path,
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


def validate_scan_common(scan: dict[str, Any]) -> None:
    if not scan["database_loaded"]:
        raise ProbeError("database did not load")
    if scan["error_count"] != 0 or not scan["scan_success"]:
        raise ProbeError("scan failed")


def validate_harness(
    document: dict[str, Any],
    sample: dict[str, Any],
) -> None:
    expected_header = {
        "schema_version": 1,
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": COMPONENT_COMMITS["Formats"],
        "xarchive_commit": COMPONENT_COMMITS["XArchive"],
        "xscanengine_commit": COMPONENT_COMMITS["XScanEngine"],
        "input_name": sample["name"],
        "input_size": sample["size"],
    }
    for key, value in expected_header.items():
        if document.get(key) != value:
            raise ProbeError(f"harness field changed: {key}")
    if document.get("direct_npm_valid") is not sample["expected_npm"]:
        raise ProbeError("direct NPM detector result changed")

    automatic = document["automatic"]
    validate_scan_common(automatic)
    if (
        automatic["forced"]
        or automatic["property"] != ""
        or automatic["detected_filetypes"] != "BINARY|ARCHIVE|GZIP"
        or automatic["initial_filetype"] != "Binary"
        or automatic["record_count"] != 1
    ):
        raise ProbeError("automatic NPM dispatch behavior changed")
    automatic_records = automatic["records"]
    if (
        len(automatic_records) != 1
        or automatic_records[0]["filetype"] != "Binary"
        or automatic_records[0]["name"] != "Unknown"
        or not automatic_records[0]["unknown"]
    ):
        raise ProbeError("automatic fallback record changed")

    forced = document["forced_npm"]
    validate_scan_common(forced)
    if (
        not forced["forced"]
        or forced["property"] != "NPM"
        or forced["detected_filetypes"] != "NPM"
        or forced["initial_filetype"] != "NPM"
    ):
        raise ProbeError("forced NPM dispatch behavior changed")
    observed_records = [
        (record["name"], record["signature"])
        for record in forced["records"]
    ]
    if observed_records != EXPECTED_FORCED_RECORDS[sample["name"]]:
        raise ProbeError("forced NPM rule records changed")
    if forced["record_count"] != len(observed_records):
        raise ProbeError("forced NPM record count changed")
    if any(
        record["filetype"] != "NPM"
        or record["type"] != "language"
        or record["unknown"]
        for record in forced["records"]
    ):
        raise ProbeError("forced NPM record shape changed")


def summarize_release(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {"detects"}:
        raise ProbeError("unexpected release JSON root")
    detects = document["detects"]
    if not isinstance(detects, list) or len(detects) != 1:
        raise ProbeError("expected one release root")
    root = detects[0]
    names = [record.get("name") for record in root.get("values", [])]
    summary = {
        "filetype": root.get("filetype"),
        "names": names,
        "offset": root.get("offset"),
        "parentfilepart": root.get("parentfilepart"),
        "size": root.get("size"),
    }
    if (
        summary["filetype"] != "Binary"
        or summary["names"] != ["Unknown"]
        or summary["offset"] != "0"
        or summary["parentfilepart"] != "Header"
    ):
        raise ProbeError("release Binary fallback changed")
    return summary


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

        release_arguments = (
            "--json",
            *DATABASE_ARGS,
            fixture_argument,
        )
        cmake = run_binary(
            image=HARNESS_IMAGE,
            binary=CMAKE_RELEASE_BINARY,
            fixture_dir=fixture_dir,
            arguments=release_arguments,
        )
        qmake = run_binary(
            image=QMAKE_IMAGE,
            binary=QMAKE_RELEASE_BINARY,
            fixture_dir=fixture_dir,
            arguments=release_arguments,
        )
        if (
            cmake.returncode != 0
            or qmake.returncode != 0
            or cmake.stderr
            or qmake.stderr
        ):
            raise ProbeError(f"release oracle failed: {sample_name}")
        if (cmake.stdout, cmake.stderr) != (
            qmake.stdout,
            qmake.stderr,
        ):
            raise ProbeError(f"qmake/CMake output drift: {sample_name}")
        release_summary = summarize_release(strict_json(cmake.stdout))
        if release_summary["size"] != str(sample["size"]):
            raise ProbeError(f"release size changed: {sample_name}")

        cases[sample_name] = {
            "cmake_release": {
                **execution(cmake, artifacts),
                "arguments": list(release_arguments),
                "summary": release_summary,
            },
            "harness": {
                **execution(harness, artifacts),
                "arguments": [fixture_argument],
                "output": harness_document,
            },
            "qmake_release": {
                **execution(qmake, artifacts),
                "arguments": list(release_arguments),
                "summary": release_summary,
            },
        }

    facts = {
        "direct_detector_accepts_exact_package_json_path": all(
            cases[name]["harness"]["output"]["direct_npm_valid"]
            for name in ("npm-valid.tgz", "npm-invalid-json.tgz")
        ),
        "direct_detector_rejects_path_and_case_controls": all(
            not cases[name]["harness"]["output"]["direct_npm_valid"]
            for name in (
                "root-package-json.tgz",
                "case-package-json.tgz",
            )
        ),
        "direct_detector_does_not_parse_package_json": (
            cases["npm-invalid-json.tgz"]["harness"]["output"][
                "direct_npm_valid"
            ]
        ),
        "automatic_detection_never_emits_npm": all(
            "NPM"
            not in case["harness"]["output"]["automatic"][
                "detected_filetypes"
            ].split("|")
            for case in cases.values()
        ),
        "automatic_scan_falls_back_to_binary_unknown": all(
            case["harness"]["output"]["automatic"]["initial_filetype"]
            == "Binary"
            and case["harness"]["output"]["automatic"]["records"][0][
                "name"
            ]
            == "Unknown"
            for case in cases.values()
        ),
        "forced_property_reaches_npm_language_rules": all(
            case["harness"]["output"]["forced_npm"]["initial_filetype"]
            == "NPM"
            and case["harness"]["output"]["forced_npm"]["record_count"]
            >= 1
            for case in cases.values()
        ),
        "valid_package_metadata_is_not_reported_by_default_options": (
            [
                record["type"]
                for record in cases["npm-valid.tgz"]["harness"][
                    "output"
                ]["forced_npm"]["records"]
            ]
            == ["language"]
        ),
        "qmake_and_cmake_release_outputs_are_byte_equal": all(
            case["qmake_release"]["stdout"]
            == case["cmake_release"]["stdout"]
            and case["qmake_release"]["stderr"]
            == case["cmake_release"]["stderr"]
            for case in cases.values()
        ),
        "release_and_harness_automatic_semantics_agree": all(
            case["cmake_release"]["summary"]["filetype"]
            == case["harness"]["output"]["automatic"][
                "initial_filetype"
            ]
            and case["cmake_release"]["summary"]["names"]
            == [
                record["name"]
                for record in case["harness"]["output"]["automatic"][
                    "records"
                ]
            ]
            for case in cases.values()
        ),
    }
    if not all(facts.values()):
        raise ProbeError("derived NPM facts failed")

    local_sources = {}
    for name, path in {
        "fixture_generator": FIXTURE_GENERATOR,
        "harness_dockerfile": HARNESS_DOCKERFILE,
        "harness_source": HARNESS_SOURCE,
        "probe": "tools/upstream/probe_npm_dispatch_harness.py",
    }.items():
        local_sources[name] = {
            "path": path,
            "sha256": sha256((ROOT / path).read_bytes()),
        }

    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_npm_dispatch_harness.py",
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

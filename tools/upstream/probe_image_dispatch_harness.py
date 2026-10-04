#!/usr/bin/env python3
"""Probe natural and forced generic-Image dispatch on pinned Qt5."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
FORMATS_COMMIT = "1151e7254fdee3c0294ff7095edbdd7bfccf8201"
XSCANENGINE_COMMIT = "dfe4a419e4f491bb23688ba03c5a5bf39e34da83"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
IMAGE = "die-rust/image-dispatch-harness-qt5:74eaf505"
BINARY = "/opt/die-build/src/console/die-image-dispatch-harness"
FIXTURE_ROOT = "/fixtures/image"
MANIFEST_SHA256 = (
    "77e2e743897d9c85ed7c539b1213ce1270bf43aa2cf976a3bf470bdd185a9238"
)
ROOT = Path(__file__).resolve().parents[2]
GENERATOR = (
    ROOT / "tools" / "corpus" / "generate_image_dispatch_fixture.py"
)
HARNESS_SOURCE = (
    ROOT / "tools" / "upstream" / "image_dispatch_harness_main.cpp"
)
DOCKERFILE = (
    ROOT
    / "tools"
    / "upstream"
    / "Dockerfile.image-dispatch-harness-qt5"
)
EXPECTED_DETECTED = {
    "BMP": ["BMP", "Binary", "Image"],
    "GIF": ["Binary", "GIF", "Image"],
    "TIFF": ["Binary", "Image", "TIFF", "Text", "UTF8"],
    "ICO": ["Binary", "ICO", "Image", "Text", "UTF8"],
    "CUR": ["Binary", "CUR", "Image", "Text", "UTF8"],
    "ICC": ["Binary", "ICC", "Image"],
    "WebP": ["Binary", "Image", "RIFF", "Text", "UTF8", "WebP"],
}
EXPECTED_AUTOMATIC = {
    "BMP": ("Windows Bitmap", False),
    "GIF": ("Unknown", True),
    "TIFF": ("Tagged Image File Format (.TIFF)", False),
    "ICO": ("Windows Icon", False),
    "CUR": ("Unknown", True),
    "ICC": ("Unknown", True),
    "WebP": ("WebP", False),
}
EXPECTED_IMAGE_ERROR = (
    "Image/_Image.0.sg: 7: TypeError: Result of expression "
    "'Image' [null] is not an object."
)


class ProbeError(ValueError):
    """The image-dispatch evidence does not match its fixed contract."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ProbeError(f"non-finite JSON constant: {constant}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError(f"invalid {description}: {error}") from error
    if not isinstance(value, dict):
        raise ProbeError(f"{description} root must be an object")
    return value


def inspect_image() -> dict[str, Any]:
    completed = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        check=True,
        capture_output=True,
    )
    document = json.loads(completed.stdout)
    if not isinstance(document, list) or len(document) != 1:
        raise ProbeError("unexpected image inspect result")
    inspected = document[0]
    revision = (
        inspected.get("Config", {})
        .get("Labels", {})
        .get("org.opencontainers.image.revision")
    )
    if revision != UPSTREAM_COMMIT:
        raise ProbeError("image revision mismatch")
    return {
        "id": inspected["Id"],
        "repo_digests": sorted(inspected.get("RepoDigests") or []),
        "revision": revision,
    }


def docker_process(
    entrypoint: str,
    *arguments: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            entrypoint,
            IMAGE,
            *arguments,
        ],
        capture_output=True,
        timeout=60,
    )


def docker_bytes(entrypoint: str, *arguments: str) -> bytes:
    completed = docker_process(entrypoint, *arguments)
    if completed.returncode != 0 or completed.stderr:
        raise ProbeError(f"cannot read image artifact via {entrypoint}")
    return completed.stdout


def verify_fixture() -> tuple[dict[str, Any], bytes]:
    image_generator = docker_bytes(
        "/usr/bin/cat",
        "/opt/die-image/generate_image_dispatch_fixture.py",
    )
    if image_generator != GENERATOR.read_bytes():
        raise ProbeError("image fixture generator differs from repository")
    image_manifest = docker_bytes(
        "/usr/bin/cat",
        f"{FIXTURE_ROOT}/manifest.json",
    )
    if sha256(image_manifest) != MANIFEST_SHA256:
        raise ProbeError("image fixture manifest hash mismatch")
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory)
        completed = subprocess.run(
            [sys.executable, str(GENERATOR), str(output)],
            capture_output=True,
        )
        if completed.returncode != 0 or completed.stderr:
            raise ProbeError("local fixture generation failed")
        local_manifest = (output / "manifest.json").read_bytes()
    if local_manifest != image_manifest:
        raise ProbeError("image fixture is not exact local generator output")
    manifest = parse_json(image_manifest, "fixture manifest")
    if set(manifest) != {
        "capability",
        "coverage_gap",
        "generator",
        "license",
        "samples",
        "schema_version",
    }:
        raise ProbeError("fixture manifest fields changed")
    if manifest["schema_version"] != 1:
        raise ProbeError("unsupported fixture manifest schema")
    if manifest["capability"] != "CAP-DISPATCH-007":
        raise ProbeError("fixture capability mismatch")
    if manifest["coverage_gap"] != "CAP-GAP-012":
        raise ProbeError("fixture coverage gap mismatch")
    samples = manifest["samples"]
    if not isinstance(samples, list) or len(samples) != 7:
        raise ProbeError("fixture must contain seven samples")
    if {item["specific_filetype"] for item in samples} != set(
        EXPECTED_DETECTED
    ):
        raise ProbeError("fixture specific filetype set changed")
    return manifest, image_manifest


def sample_map(
    document: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    samples = document.get("samples")
    if not isinstance(samples, list):
        raise ProbeError("harness samples must be an array")
    if document.get("sample_count") != len(samples):
        raise ProbeError("harness sample count mismatch")
    result = {
        str(sample.get("specific_filetype")): sample
        for sample in samples
    }
    if len(result) != len(samples):
        raise ProbeError("duplicate harness specific filetype")
    return result


def validate(
    document: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, bool]:
    expected_identity = {
        "formats_commit": FORMATS_COMMIT,
        "manifest_sha256": MANIFEST_SHA256,
        "rules_commit": RULES_COMMIT,
        "schema_version": 1,
        "upstream_commit": UPSTREAM_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
    }
    for field, expected in expected_identity.items():
        if document.get(field) != expected:
            raise ProbeError(f"harness identity mismatch: {field}")
    if document.get("qt_version") != "5.15.13":
        raise ProbeError("harness Qt version mismatch")

    samples = sample_map(document)
    manifest_samples = {
        item["specific_filetype"]: item
        for item in manifest["samples"]
    }
    if set(samples) != set(EXPECTED_DETECTED):
        raise ProbeError("unexpected harness sample inventory")
    if set(manifest_samples) != set(samples):
        raise ProbeError("harness and manifest sample sets differ")

    for specific, sample in samples.items():
        expected_manifest = manifest_samples[specific]
        for field in ("name", "sha256", "size", "specific_filetype"):
            if sample.get(field) != expected_manifest.get(field):
                raise ProbeError(f"{specific} manifest field drift: {field}")
        if sample.get("detected_filetypes") != EXPECTED_DETECTED[specific]:
            raise ProbeError(f"{specific} detector set drift")
        if sample.get("image_filtered_filetypes") != ["Image"]:
            raise ProbeError(f"{specific} Image filter drift")

        automatic = sample.get("automatic", {})
        if automatic.get("initial_filetype") != "Binary":
            raise ProbeError(f"{specific} automatic dispatch is not Binary")
        if automatic.get("option_filetype") != "Unknown":
            raise ProbeError(f"{specific} automatic option drift")
        if automatic.get("errors") != []:
            raise ProbeError(f"{specific} automatic scan emitted errors")
        automatic_records = automatic.get("records")
        if not isinstance(automatic_records, list) or len(
            automatic_records
        ) != 1:
            raise ProbeError(f"{specific} automatic record count drift")
        name, unknown = EXPECTED_AUTOMATIC[specific]
        record = automatic_records[0]
        if (
            record.get("filetype") != "Binary"
            or record.get("name") != name
            or record.get("unknown") is not unknown
        ):
            raise ProbeError(f"{specific} automatic record drift")

        forced = sample.get("forced_image", {})
        if forced.get("initial_filetype") != "Image":
            raise ProbeError(f"{specific} forced dispatch did not reach Image")
        if forced.get("option_filetype") != "Image":
            raise ProbeError(f"{specific} forced option drift")
        if forced.get("errors") != [
            {
                "message": EXPECTED_IMAGE_ERROR,
                "script": "_Image.0.sg",
            }
        ]:
            raise ProbeError(f"{specific} forced Image error drift")
        forced_records = forced.get("records")
        if not isinstance(forced_records, list) or len(forced_records) != 1:
            raise ProbeError(f"{specific} forced record count drift")
        forced_record = forced_records[0]
        if (
            forced_record.get("filetype") != "Image"
            or forced_record.get("name") != "Unknown"
            or forced_record.get("unknown") is not True
        ):
            raise ProbeError(f"{specific} forced unknown record drift")
        if (
            automatic.get("scan_success") is not True
            or forced.get("scan_success") is not True
        ):
            raise ProbeError(f"{specific} scan state failed")

    relationships = {
        "seven_non_jpeg_png_variants_detected": True,
        "all_detectors_include_image_and_specific_type": True,
        "image_filter_collapses_each_set_to_image": True,
        "automatic_dispatch_falls_back_to_binary": True,
        "forced_option_reaches_generic_image_branch": True,
        "generic_image_adapter_is_null_and_reports_error": True,
        "all_scans_complete_with_stable_unknown_fallback": True,
    }
    return relationships


def build_report(raw_dir: Path) -> dict[str, Any]:
    image_identity = inspect_image()
    manifest, raw_manifest = verify_fixture()
    image_harness = docker_bytes(
        "/usr/bin/cat",
        "/tmp/image_dispatch_harness_main.cpp",
    )
    if image_harness != HARNESS_SOURCE.read_bytes():
        raise ProbeError("image harness source differs from repository")
    binary_hash = docker_bytes(
        "/usr/bin/sha256sum",
        BINARY,
    ).split()[0].decode("ascii")
    process = docker_process(BINARY, FIXTURE_ROOT)
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "image-dispatch.stdout").write_bytes(process.stdout)
    (raw_dir / "image-dispatch.stderr").write_bytes(process.stderr)
    if process.returncode != 0 or process.stderr:
        raise ProbeError("image dispatch harness process failed")
    document = parse_json(process.stdout, "harness output")
    relationships = validate(document, manifest)
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_image_dispatch_harness.py",
        "generator_sha256": sha256(Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "rules_commit": RULES_COMMIT,
        "platform": "linux-x86_64-qt5",
        "capability": "CAP-DISPATCH-007",
        "closed_corpus_gap": "CAP-GAP-012",
        "fixture": {
            "generator": (
                "tools/corpus/generate_image_dispatch_fixture.py"
            ),
            "generator_sha256": sha256(GENERATOR.read_bytes()),
            "manifest": manifest,
            "manifest_bytes": len(raw_manifest),
            "manifest_sha256": sha256(raw_manifest),
        },
        "harness": {
            "source": (
                "tools/upstream/image_dispatch_harness_main.cpp"
            ),
            "source_sha256": sha256(HARNESS_SOURCE.read_bytes()),
            "dockerfile": (
                "tools/upstream/Dockerfile.image-dispatch-harness-qt5"
            ),
            "dockerfile_sha256": sha256(DOCKERFILE.read_bytes()),
        },
        "oracle": {
            "image": IMAGE,
            "image_identity": image_identity,
            "binary": BINARY,
            "binary_sha256": binary_hash,
            "exit_code": process.returncode,
            "raw_stdout_bytes": len(process.stdout),
            "raw_stdout_sha256": sha256(process.stdout),
            "raw_stderr_bytes": len(process.stderr),
            "raw_stderr_sha256": sha256(process.stderr),
        },
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir"
        },
        "relationships": relationships,
        "harness_output": document,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args.raw_dir.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

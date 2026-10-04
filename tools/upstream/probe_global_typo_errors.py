#!/usr/bin/env python3
"""Reach two pinned undefined globals in both Qt5 CLI oracles."""

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
EXPECTED_ERRORS = {
    "debug-dwarf-typo.bin": (
        "debug_data_debugData.1.sg: "
        "Binary/debug_data_debugData.1.sg: 58: "
        "ReferenceError: Can't find variable: get_DWRAF_vi"
    ),
    "audio-xma2-typo.wem": (
        "audio_WEM.1.sg: Binary/audio_WEM.1.sg: 55: "
        "ReferenceError: Can't find variable: xma2_pase_xma2_chunk"
    ),
}
EXPECTED_ERRORS_QT6 = {
    "debug-dwarf-typo.bin": (
        "debug_data_debugData.1.sg: "
        "Binary/debug_data_debugData.1.sg: 58: "
        "ReferenceError: get_DWRAF_vi is not defined"
    ),
    "audio-xma2-typo.wem": (
        "audio_WEM.1.sg: Binary/audio_WEM.1.sg: 55: "
        "ReferenceError: xma2_pase_xma2_chunk is not defined"
    ),
}


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
QT6_ORACLE = Oracle(
    "linux-qt6-cmake",
    "die-rust/upstream-oracle-cmake-qt6:74eaf505",
    "/opt/die-build/src/console/diec",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_and_verify_fixture(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
    rules_root: pathlib.Path,
) -> tuple[dict[str, Any], str]:
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if (
        manifest.get("generator")
        != "tools/corpus/generate_global_typo_corpus.py"
        or manifest.get("rules_commit") != RULES_COMMIT
    ):
        raise ValueError("unexpected global typo fixture identity")
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
        for path in fixture_dir.iterdir()
        if path.is_file() and path.name != "manifest.json"
    }
    if actual != declared:
        raise ValueError(
            f"fixture inventory mismatch: missing={sorted(declared - actual)}, "
            f"unexpected={sorted(actual - declared)}"
        )
    for evidence in manifest["rule_evidence"]:
        path = rules_root / pathlib.PurePosixPath(evidence["path"])
        if sha256(path.read_bytes()) != evidence["sha256"]:
            raise ValueError(f"rule evidence identity mismatch: {path}")
    if set(declared) != set(EXPECTED_ERRORS):
        raise ValueError("fixture/error expectation set mismatch")
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
    oracle: Oracle,
    fixture_dir: pathlib.Path,
    input_name: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--pids-limit",
            "128",
            "--mount",
            f"type=bind,source={fixture_dir},target=/corpus,readonly",
            oracle.image,
            oracle.binary,
            "--messages",
            "--json",
            "--database",
            "/opt/die-source/Detect-It-Easy/db",
            "--extradatabase",
            "/opt/die-source/Detect-It-Easy/db_extra",
            f"/corpus/{input_name}",
        ],
        check=False,
        capture_output=True,
    )


def parse_stdout(
    stdout: bytes,
    input_name: str,
    expected_size: int,
    expected_errors: dict[str, str] = EXPECTED_ERRORS,
) -> dict[str, Any]:
    text = stdout.decode("utf-8")
    document, end = json.JSONDecoder().raw_decode(text)
    messages = [
        line for line in text[end:].splitlines() if line.strip()
    ]
    if messages != [expected_errors[input_name]]:
        raise ValueError(f"unexpected oracle messages: {messages}")
    detects = document.get("detects", [])
    if len(detects) != 1:
        raise ValueError("expected one detection node")
    detection = detects[0]
    normalized = {
        "filetype": detection["filetype"],
        "offset": detection["offset"],
        "size": detection["size"],
        "parentfilepart": detection["parentfilepart"],
        "values": [
            {
                "type": value["type"],
                "name": value["name"],
                "version": value["version"],
                "info": value["info"],
            }
            for value in detection["values"]
        ],
    }
    expected_detection = {
        "filetype": "Binary",
        "offset": "0",
        "size": str(expected_size),
        "parentfilepart": "Header",
        "values": [
            {
                "type": "Unknown",
                "name": "Unknown",
                "version": "",
                "info": "",
            }
        ],
    }
    if normalized != expected_detection:
        raise ValueError(f"unexpected normalized detection: {normalized}")
    return {
        "diagnostic": messages[0],
        "normalized_detection": normalized,
    }


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
    rules_root: pathlib.Path,
    raw_dir: pathlib.Path,
    oracles: tuple[Oracle, ...] = ORACLES,
) -> dict[str, Any]:
    manifest, manifest_sha256 = load_and_verify_fixture(
        fixture_dir, manifest_path, rules_root
    )
    raw_dir.mkdir(parents=True, exist_ok=True)
    observations = []
    normalized_by_input: dict[str, list[dict[str, Any]]] = {
        entry["path"]: [] for entry in manifest["entries"]
    }
    diagnostics_by_input: dict[str, list[str]] = {
        entry["path"]: [] for entry in manifest["entries"]
    }
    for oracle in oracles:
        image_id, revision = inspect_image(oracle.image)
        expected_errors = (
            EXPECTED_ERRORS_QT6
            if oracle == QT6_ORACLE
            else EXPECTED_ERRORS
        )
        inputs = []
        for entry in manifest["entries"]:
            input_name = entry["path"]
            process = observe(oracle, fixture_dir, input_name)
            stem = pathlib.Path(input_name).stem
            (raw_dir / f"{oracle.name}-{stem}.stdout").write_bytes(
                process.stdout
            )
            (raw_dir / f"{oracle.name}-{stem}.stderr").write_bytes(
                process.stderr
            )
            if process.returncode != 0:
                raise ValueError(
                    f"{oracle.name}/{input_name} exited "
                    f"with {process.returncode}"
                )
            if process.stderr:
                raise ValueError(f"{oracle.name}/{input_name} wrote stderr")
            parsed = parse_stdout(
                process.stdout,
                input_name,
                entry["size"],
                expected_errors,
            )
            normalized_by_input[input_name].append(
                parsed["normalized_detection"]
            )
            diagnostics_by_input[input_name].append(
                parsed["diagnostic"]
            )
            inputs.append(
                {
                    "path": input_name,
                    "exit_code": process.returncode,
                    "raw_stdout_bytes": len(process.stdout),
                    "raw_stdout_sha256": sha256(process.stdout),
                    "raw_stderr_bytes": len(process.stderr),
                    "raw_stderr_sha256": sha256(process.stderr),
                    **parsed,
                }
            )
        observations.append(
            {
                "name": oracle.name,
                "image": oracle.image,
                "image_id": image_id,
                "revision": revision,
                "binary": oracle.binary,
                "inputs": inputs,
            }
        )
    normalized_equal = all(
        len(outputs) == len(oracles)
        and all(output == outputs[0] for output in outputs[1:])
        for outputs in normalized_by_input.values()
    )
    if not normalized_equal:
        raise ValueError("oracle normalized typo detections differ")
    report = {
        "schema_version": 1,
        "generator": "tools/upstream/probe_global_typo_errors.py",
        "upstream_commit": UPSTREAM_COMMIT,
        "rules_commit": RULES_COMMIT,
        "platform": (
            "linux-amd64-qt5"
            if oracles == ORACLES
            else "linux-amd64-qt5-qt6"
        ),
        "fixture_manifest": {
            "path": "docs/research/data/global-typo-corpus.json",
            "sha256": manifest_sha256,
        },
        "arguments": [
            "--messages",
            "--json",
            "--database",
            "/opt/die-source/Detect-It-Easy/db",
            "--extradatabase",
            "/opt/die-source/Detect-It-Easy/db_extra",
            "/corpus/<input>",
        ],
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir",
        },
        "oracles": observations,
    }
    if oracles == ORACLES:
        report["normalized_outputs_equal"] = all(
            len(outputs) == len(oracles)
            and all(output == outputs[0] for output in outputs[1:])
            for outputs in diagnostics_by_input.values()
        )
    else:
        report["normalized_detections_equal"] = normalized_equal
        report["diagnostics_equal"] = all(
            all(output == outputs[0] for output in outputs[1:])
            for outputs in diagnostics_by_input.values()
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    repo = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=repo / "docs/research/data/global-typo-corpus.json",
    )
    parser.add_argument(
        "--rules-root",
        type=pathlib.Path,
        default=repo / "upstream/Detect-It-Easy",
    )
    parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument(
        "--include-qt6",
        action="store_true",
        help="Also run the fixed CMake Qt 6 oracle",
    )
    args = parser.parse_args()
    report = build_report(
        args.fixture_dir.resolve(),
        args.manifest.resolve(),
        args.rules_root.resolve(),
        args.raw_dir.resolve(),
        ORACLES + (QT6_ORACLE,) if args.include_qt6 else ORACLES,
    )
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

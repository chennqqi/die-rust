#!/usr/bin/env python3
"""Probe DIE rule ordering, init, layer, type, and mode filters."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
from dataclasses import dataclass
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
FIXTURE_GENERATOR = (
    "tools/corpus/generate_rule_orchestration_fixture.py"
)
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

MODES = {
    "default": (),
    "deep": ("--deepscan",),
    "heuristic": ("--heuristicscan",),
    "combined": ("--deepscan", "--heuristicscan"),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_and_verify_fixture(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
) -> tuple[dict[str, Any], str]:
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported orchestration fixture schema")
    if manifest.get("generator") != FIXTURE_GENERATOR:
        raise ValueError("unexpected orchestration fixture generator")

    declared_files = set()
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
        declared_files.add(relative.as_posix())

    actual_files = {
        path.relative_to(fixture_dir).as_posix()
        for path in fixture_dir.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    if actual_files != declared_files:
        raise ValueError(
            "fixture inventory mismatch: "
            f"missing={sorted(declared_files - actual_files)}, "
            f"unexpected={sorted(actual_files - declared_files)}"
        )

    actual_directories = {
        path.relative_to(fixture_dir).as_posix()
        for path in fixture_dir.rglob("*")
        if path.is_dir()
    }
    if actual_directories != set(manifest["directories"]):
        raise ValueError("fixture directory inventory mismatch")
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


def scan_arguments(mode: str, empty: bool = False) -> tuple[str, ...]:
    prefix = "empty-" if empty else ""
    return (
        "--profiling",
        "--messages",
        "--json",
        *MODES[mode],
        "--database",
        f"/fixture/{prefix}main",
        "--extradatabase",
        f"/fixture/{prefix}extra",
        "--customdatabase",
        f"/fixture/{prefix}custom",
        "/fixture/input/probe.bin",
    )


def priority_arguments() -> tuple[str, ...]:
    return (
        "--profiling",
        "--messages",
        "--json",
        "--database",
        "/fixture/priority-main",
        "--extradatabase",
        "/fixture/priority-extra",
        "--customdatabase",
        "/fixture/priority-custom",
        "/fixture/input/probe.bin",
    )


def ordering_arguments(database_prefix: str) -> tuple[str, ...]:
    return (
        "--profiling",
        "--messages",
        "--json",
        "--database",
        f"/fixture/{database_prefix}-main",
        "--extradatabase",
        f"/fixture/{database_prefix}-extra",
        "--customdatabase",
        f"/fixture/{database_prefix}-custom",
        "/fixture/input/probe.bin",
    )


def observe(
    oracle: Oracle,
    fixture_dir: pathlib.Path,
    arguments: tuple[str, ...],
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--mount",
            (
                f"type=bind,source={fixture_dir},"
                "target=/fixture,readonly"
            ),
            "--entrypoint",
            oracle.binary,
            oracle.image,
            *arguments,
        ],
        check=False,
        capture_output=True,
    )


def parse_stdout(
    stdout: bytes,
    known_rule_names: set[str],
) -> tuple[list[str], list[dict[str, str]]]:
    text = stdout.decode("utf-8")
    lines = text.splitlines()
    order = [line for line in lines if line in known_rule_names]
    json_offsets = [
        offset for offset, line in enumerate(lines) if line.startswith("{")
    ]
    if len(json_offsets) != 1:
        raise ValueError("expected exactly one JSON document")
    json_text = "\n".join(lines[json_offsets[0] :])
    document, end = json.JSONDecoder().raw_decode(json_text)
    if json_text[end:].strip():
        raise ValueError("oracle emitted trailing diagnostics")

    values = []
    for detection in document.get("detects", []):
        for value in detection.get("values", []):
            values.append(
                {
                    key: value.get(key, "")
                    for key in ("type", "name", "version", "info")
                }
            )
    if not values:
        raise ValueError("oracle JSON contains no detection values")
    return order, values


def detection_names_by_rule(
    manifest: dict[str, Any],
) -> dict[str, str]:
    return {
        pathlib.PurePosixPath(entry["path"]).name: entry["detection_name"]
        for entry in manifest["entries"]
        if "detection_name" in entry
    }


def validate_case(
    mode: str,
    order: list[str],
    detections: list[dict[str, str]],
    manifest: dict[str, Any],
) -> None:
    expected_order = manifest["mode_orders"][mode]
    if order != expected_order:
        raise ValueError(
            f"{mode} execution order mismatch: "
            f"expected={expected_order}, actual={order}"
        )

    names_by_rule = detection_names_by_rule(manifest)
    expected_detection_names = {
        names_by_rule[rule_name] for rule_name in expected_order
    }
    actual_detection_names = {
        detection["name"] for detection in detections
    }
    if actual_detection_names != expected_detection_names:
        raise ValueError(
            f"{mode} detection set mismatch: "
            f"expected={sorted(expected_detection_names)}, "
            f"actual={sorted(actual_detection_names)}"
        )

    expected_init = manifest["expected_init_value"]
    for detection in detections:
        if detection != {
            "type": "format",
            "name": detection["name"],
            "version": expected_init,
            "info": "",
        }:
            raise ValueError(
                f"{mode} detection/init value mismatch: {detection}"
            )


def validate_unknown(
    order: list[str],
    detections: list[dict[str, str]],
) -> None:
    if order:
        raise ValueError("empty database unexpectedly executed a rule")
    expected = [
        {
            "type": "Unknown",
            "name": "Unknown",
            "version": "",
            "info": "",
        }
    ]
    if detections != expected:
        raise ValueError(
            f"empty database Unknown behavior mismatch: {detections}"
        )


def validate_priority_only(
    order: list[str],
    detections: list[dict[str, str]],
    manifest: dict[str, Any],
) -> None:
    expected_order = manifest["priority_only_order"]
    if order != expected_order:
        raise ValueError(
            "priority-only execution order mismatch: "
            f"expected={expected_order}, actual={order}"
        )
    names_by_rule = detection_names_by_rule(manifest)
    expected_names = {
        names_by_rule[rule_name] for rule_name in expected_order
    }
    if {detection["name"] for detection in detections} != expected_names:
        raise ValueError("priority-only detection set mismatch")
    for detection in detections:
        if (
            detection["type"] != "format"
            or detection["version"] != "priority-only"
            or detection["info"]
        ):
            raise ValueError(
                f"priority-only detection mismatch: {detection}"
            )


def validate_ordering_case(
    case_name: str,
    order: list[str],
    detections: list[dict[str, str]],
    manifest: dict[str, Any],
) -> None:
    expected_order = manifest["ordering_cases"][case_name][
        "execution_order"
    ]
    if order != expected_order:
        raise ValueError(
            f"{case_name} execution order mismatch: "
            f"expected={expected_order}, actual={order}"
        )
    names_by_rule = detection_names_by_rule(manifest)
    expected_names = {names_by_rule[rule_name] for rule_name in order}
    if {detection["name"] for detection in detections} != expected_names:
        raise ValueError(f"{case_name} detection set mismatch")
    for detection in detections:
        if detection != {
            "type": "format",
            "name": detection["name"],
            "version": "ordering-edge",
            "info": "",
        }:
            raise ValueError(
                f"{case_name} detection mismatch: {detection}"
            )


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
    raw_dir: pathlib.Path,
) -> dict[str, Any]:
    manifest, manifest_sha256 = load_and_verify_fixture(
        fixture_dir,
        manifest_path,
    )
    known_rule_names = set(detection_names_by_rule(manifest))
    raw_dir.mkdir(parents=True, exist_ok=True)
    observations = []
    normalized_by_oracle = []

    for oracle in ORACLES:
        image_id, revision = inspect_image(oracle.image)
        cases = {}
        normalized_cases = {}
        for mode in MODES:
            arguments = scan_arguments(mode)
            process = observe(oracle, fixture_dir, arguments)
            (raw_dir / f"{oracle.name}-{mode}.stdout").write_bytes(
                process.stdout
            )
            (raw_dir / f"{oracle.name}-{mode}.stderr").write_bytes(
                process.stderr
            )
            if process.returncode != 0:
                raise ValueError(
                    f"{oracle.name}/{mode} exited with "
                    f"{process.returncode}"
                )
            if process.stderr:
                raise ValueError(f"{oracle.name}/{mode} wrote stderr")
            order, detections = parse_stdout(
                process.stdout,
                known_rule_names,
            )
            validate_case(mode, order, detections, manifest)
            normalized_cases[mode] = (order, detections)
            cases[mode] = {
                "arguments": list(arguments),
                "exit_code": process.returncode,
                "raw_stdout_bytes": len(process.stdout),
                "raw_stdout_sha256": sha256(process.stdout),
                "raw_stderr_bytes": len(process.stderr),
                "raw_stderr_sha256": sha256(process.stderr),
                "execution_order": order,
                "detections": detections,
            }

        priority_scan_arguments = priority_arguments()
        priority_process = observe(
            oracle,
            fixture_dir,
            priority_scan_arguments,
        )
        (raw_dir / f"{oracle.name}-priority-only.stdout").write_bytes(
            priority_process.stdout
        )
        (raw_dir / f"{oracle.name}-priority-only.stderr").write_bytes(
            priority_process.stderr
        )
        if priority_process.returncode != 0 or priority_process.stderr:
            raise ValueError(f"{oracle.name}/priority-only scan failed")
        priority_order, priority_detections = parse_stdout(
            priority_process.stdout,
            known_rule_names,
        )
        validate_priority_only(
            priority_order,
            priority_detections,
            manifest,
        )
        normalized_cases["priority_only"] = (
            priority_order,
            priority_detections,
        )
        cases["priority_only"] = {
            "arguments": list(priority_scan_arguments),
            "exit_code": priority_process.returncode,
            "raw_stdout_bytes": len(priority_process.stdout),
            "raw_stdout_sha256": sha256(priority_process.stdout),
            "raw_stderr_bytes": len(priority_process.stderr),
            "raw_stderr_sha256": sha256(priority_process.stderr),
            "execution_order": priority_order,
            "detections": priority_detections,
        }

        for case_name, specification in manifest[
            "ordering_cases"
        ].items():
            edge_arguments = ordering_arguments(
                specification["database_prefix"]
            )
            edge_process = observe(
                oracle,
                fixture_dir,
                edge_arguments,
            )
            (raw_dir / f"{oracle.name}-{case_name}.stdout").write_bytes(
                edge_process.stdout
            )
            (raw_dir / f"{oracle.name}-{case_name}.stderr").write_bytes(
                edge_process.stderr
            )
            if edge_process.returncode != 0 or edge_process.stderr:
                raise ValueError(
                    f"{oracle.name}/{case_name} scan failed"
                )
            edge_order, edge_detections = parse_stdout(
                edge_process.stdout,
                known_rule_names,
            )
            validate_ordering_case(
                case_name,
                edge_order,
                edge_detections,
                manifest,
            )
            normalized_cases[case_name] = (
                edge_order,
                edge_detections,
            )
            cases[case_name] = {
                "arguments": list(edge_arguments),
                "exit_code": edge_process.returncode,
                "raw_stdout_bytes": len(edge_process.stdout),
                "raw_stdout_sha256": sha256(edge_process.stdout),
                "raw_stderr_bytes": len(edge_process.stderr),
                "raw_stderr_sha256": sha256(edge_process.stderr),
                "execution_order": edge_order,
                "detections": edge_detections,
            }

        unknown_arguments = scan_arguments("default", empty=True)
        unknown_process = observe(
            oracle,
            fixture_dir,
            unknown_arguments,
        )
        (raw_dir / f"{oracle.name}-unknown.stdout").write_bytes(
            unknown_process.stdout
        )
        (raw_dir / f"{oracle.name}-unknown.stderr").write_bytes(
            unknown_process.stderr
        )
        if unknown_process.returncode != 0 or unknown_process.stderr:
            raise ValueError(f"{oracle.name}/unknown scan failed")
        unknown_order, unknown_detections = parse_stdout(
            unknown_process.stdout,
            known_rule_names,
        )
        validate_unknown(unknown_order, unknown_detections)
        normalized_cases["unknown"] = (
            unknown_order,
            unknown_detections,
        )
        cases["unknown"] = {
            "arguments": list(unknown_arguments),
            "exit_code": unknown_process.returncode,
            "raw_stdout_bytes": len(unknown_process.stdout),
            "raw_stdout_sha256": sha256(unknown_process.stdout),
            "raw_stderr_bytes": len(unknown_process.stderr),
            "raw_stderr_sha256": sha256(unknown_process.stderr),
            "execution_order": unknown_order,
            "detections": unknown_detections,
        }
        normalized_by_oracle.append(normalized_cases)
        observations.append(
            {
                "name": oracle.name,
                "image": oracle.image,
                "image_id": image_id,
                "revision": revision,
                "binary": oracle.binary,
                "cases": cases,
            }
        )

    normalized_equal = all(
        normalized == normalized_by_oracle[0]
        for normalized in normalized_by_oracle[1:]
    )
    if not normalized_equal:
        raise ValueError("qmake/CMake normalized observations differ")

    combined_order = manifest["mode_orders"]["combined"]
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_rule_orchestration.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "platform": "linux-amd64-qt5",
        "fixture_manifest": {
            "path": (
                "docs/research/data/"
                "rule-orchestration-fixture.json"
            ),
            "sha256": manifest_sha256,
        },
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir",
            "profiling_times_are_nondeterministic": True,
        },
        "oracles": observations,
        "normalized_outputs_equal": normalized_equal,
        "relationships": {
            "main_global_init_wins": True,
            "main_type_init_wins": True,
            "main_same_name_include_wins": True,
            "priority_only_beats_lexical_name": (
                manifest["priority_only_order"][0]
                == "z_priority.1.sg"
            ),
            "equal_priority_falls_back_to_name": (
                manifest["ordering_cases"]["equal_priority"][
                    "execution_order"
                ]
                == [
                    "a_equal.2.sg",
                    "m_equal.2.sg",
                    "z_equal.2.sg",
                ]
            ),
            "priority_segments_are_lexicographic": (
                manifest["ordering_cases"]["lexical_priority"][
                    "execution_order"
                ][0]
                == "z_ten.10.sg"
            ),
            "missing_priority_disables_pairwise_priority": (
                manifest["ordering_cases"]["missing_priority"][
                    "execution_order"
                ][0]
                == "a_plain.sg"
            ),
            "empty_priority_disables_pairwise_priority": (
                manifest["ordering_cases"]["empty_priority"][
                    "execution_order"
                ][0]
                == "a_empty..sg"
            ),
            "type_init_list_order_is_not_pure_priority": (
                combined_order.index("z_normal.1.sg")
                > combined_order.index("EP.entrypoint.4.sg")
            ),
            "database_layers_are_appended_main_extra_custom": (
                combined_order[-2:]
                == ["a_extra.0.sg", "a_custom.0.sg"]
            ),
            "ds_and_ep_require_deep": True,
            "heur_requires_heuristic": True,
            "wrong_file_type_rule_never_executes": True,
            "empty_database_adds_unknown": True,
        },
        "closed_corpus_gap": "CAP-GAP-010",
        "canonical_cases": {
            mode: {
                "execution_order": normalized_by_oracle[0][mode][0],
                "detections": normalized_by_oracle[0][mode][1],
            }
            for mode in (
                *MODES,
                "priority_only",
                *manifest["ordering_cases"],
                "unknown",
            )
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    repo = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=(
            repo
            / "docs"
            / "research"
            / "data"
            / "rule-orchestration-fixture.json"
        ),
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

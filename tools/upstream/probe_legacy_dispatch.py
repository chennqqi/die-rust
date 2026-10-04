#!/usr/bin/env python3
"""Probe Amiga Hunk and Atari ST dispatch in the pinned Qt5 oracles."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import sys
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
SHARED_PATH = ROOT / "tools" / "upstream" / "compare_cli_oracles.py"
SHARED_SPEC = importlib.util.spec_from_file_location(
    "compare_cli_oracles_legacy_dispatch", SHARED_PATH
)
assert SHARED_SPEC is not None and SHARED_SPEC.loader is not None
SHARED = importlib.util.module_from_spec(SHARED_SPEC)
sys.modules[SHARED_SPEC.name] = SHARED
SHARED_SPEC.loader.exec_module(SHARED)


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
FORMATS_COMMIT = "1151e7254fdee3c0294ff7095edbdd7bfccf8201"
MANIFEST_PATH = (
    ROOT / "docs" / "research" / "data" / "legacy-dispatch-corpus.json"
)
EXPECTED_GENERATOR = (
    "tools/corpus/generate_legacy_dispatch_corpus.py"
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


def load_fixture(
    repo: pathlib.Path,
    corpus_dir: pathlib.Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], bytes]:
    reference_path = (
        repo
        / "docs"
        / "research"
        / "data"
        / "legacy-dispatch-corpus.json"
    )
    reference = reference_path.read_bytes()
    generated_path = corpus_dir / "manifest.json"
    generated = generated_path.read_bytes()
    if generated != reference:
        raise ValueError("generated corpus manifest differs from reference")

    manifest = json.loads(generated)
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported legacy dispatch manifest schema")
    if manifest.get("generator") != EXPECTED_GENERATOR:
        raise ValueError("unexpected legacy dispatch corpus generator")
    if manifest.get("capability") != "CAP-DISPATCH-003":
        raise ValueError("unexpected legacy dispatch capability")
    if (
        manifest.get("source_identity", {}).get("commit")
        != FORMATS_COMMIT
    ):
        raise ValueError("legacy dispatch Formats commit mismatch")

    samples = SHARED.load_corpus(corpus_dir)
    for sample in samples:
        expectation = sample.get("expected_dispatch")
        if not isinstance(expectation, dict):
            raise ValueError("dispatch expectation must be an object")
        for key in ("present_filetypes", "absent_filetypes"):
            values = expectation.get(key)
            if (
                not isinstance(values, list)
                or any(not isinstance(item, str) for item in values)
            ):
                raise ValueError(f"invalid dispatch expectation: {key}")
        if set(expectation["present_filetypes"]) & set(
            expectation["absent_filetypes"]
        ):
            raise ValueError("dispatch expectation overlaps")
        if not isinstance(expectation.get("info_filetype"), str):
            raise ValueError("invalid dispatch expectation: info_filetype")
    return manifest, samples, reference


def inspect_image(image: str) -> tuple[str, str]:
    result = SHARED.subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        capture_output=True,
    )
    document = json.loads(result.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision", ""
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError(f"oracle image revision mismatch: {image}")
    return document["Id"], revision


def observed_filetypes(tree: object) -> set[str]:
    result: set[str] = set()

    def visit(value: object) -> None:
        if isinstance(value, dict):
            filetype = value.get("filetype")
            if isinstance(filetype, str):
                result.add(filetype)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(tree)
    return result


def expectation_failures(
    prefix: str,
    tree: object,
    expectation: dict[str, list[str]],
) -> list[str]:
    if tree is None:
        return [f"{prefix}.invalid_json_detect_tree"]
    observed = observed_filetypes(tree)
    failures = []
    for filetype in expectation["present_filetypes"]:
        if filetype not in observed:
            failures.append(f"{prefix}.missing_filetype.{filetype}")
    for filetype in expectation["absent_filetypes"]:
        if filetype in observed:
            failures.append(f"{prefix}.unexpected_filetype.{filetype}")
    return failures


def info_filetype(stdout: bytes) -> str | None:
    try:
        document = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    try:
        value = document["data"]["Info"]["File type"]
    except (KeyError, TypeError):
        return None
    return value if isinstance(value, str) else None


def probe_dispatch_cases(
    corpus_dir: pathlib.Path,
    raw_dir: pathlib.Path,
    samples: list[dict[str, Any]],
    include_detector_info: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    raw_dir.mkdir(parents=True, exist_ok=True)

    oracle_identities = {}
    for oracle in ORACLES:
        image_id, revision = inspect_image(oracle.image)
        oracle_identities[oracle.name] = {
            "image": oracle.image,
            "image_id": image_id,
            "revision": revision,
            "binary": oracle.binary,
        }

    failures: list[str] = []
    cases = {}
    for sample in samples:
        name = str(sample["name"])
        scan_arguments = (
            "--json",
            *SHARED.DATABASE_ARGS,
            f"/corpus/{name}",
        )
        info_arguments = (
            "--info",
            "--json",
            f"/corpus/{name}",
        )
        observations = {}
        trees = {}
        info_filetypes = {}
        for oracle in ORACLES:
            scan_observation = SHARED.observe(
                oracle.image,
                oracle.binary,
                scan_arguments,
                corpus_dir,
            )
            scan_mode = ".scan" if include_detector_info else ""
            scan_stdout_name = (
                f"{name}.{oracle.name}{scan_mode}.stdout"
            )
            scan_stderr_name = (
                f"{name}.{oracle.name}{scan_mode}.stderr"
            )
            (raw_dir / scan_stdout_name).write_bytes(
                scan_observation.stdout
            )
            (raw_dir / scan_stderr_name).write_bytes(
                scan_observation.stderr
            )
            tree = SHARED.json_detect_tree(scan_observation.stdout)
            trees[oracle.name] = tree
            if include_detector_info:
                info_observation = SHARED.observe(
                    oracle.image,
                    oracle.binary,
                    info_arguments,
                    corpus_dir,
                )
                info_stdout_name = f"{name}.{oracle.name}.info.stdout"
                info_stderr_name = f"{name}.{oracle.name}.info.stderr"
                (raw_dir / info_stdout_name).write_bytes(
                    info_observation.stdout
                )
                (raw_dir / info_stderr_name).write_bytes(
                    info_observation.stderr
                )
                observed_info_filetype = info_filetype(
                    info_observation.stdout
                )
                info_filetypes[oracle.name] = observed_info_filetype
                observations[oracle.name] = {
                    "scan": {
                        **scan_observation.summary(),
                        "arguments": list(scan_arguments),
                        "raw_stdout": scan_stdout_name,
                        "raw_stderr": scan_stderr_name,
                        "detect_tree": tree,
                    },
                    "detector_info": {
                        **info_observation.summary(),
                        "arguments": list(info_arguments),
                        "raw_stdout": info_stdout_name,
                        "raw_stderr": info_stderr_name,
                        "filetype": observed_info_filetype,
                    },
                }
            else:
                observations[oracle.name] = {
                    **scan_observation.summary(),
                    "arguments": list(scan_arguments),
                    "raw_stdout": scan_stdout_name,
                    "raw_stderr": scan_stderr_name,
                    "detect_tree": tree,
                }
            if scan_observation.exit_code != 0:
                scan_exit_field = (
                    "scan.exit_code"
                    if include_detector_info
                    else "exit_code"
                )
                failures.append(
                    f"cases.{name}.{oracle.name}.{scan_exit_field}"
                )
            if include_detector_info and info_observation.exit_code != 0:
                failures.append(
                    f"cases.{name}.{oracle.name}.info.exit_code"
                )
            failures.extend(
                expectation_failures(
                    f"cases.{name}.{oracle.name}",
                    tree,
                    sample["expected_dispatch"],
                )
            )
            if include_detector_info and (
                observed_info_filetype
                != sample["expected_dispatch"]["info_filetype"]
            ):
                failures.append(
                    f"cases.{name}.{oracle.name}.info.filetype"
                )

        left = ORACLES[0].name
        right = ORACLES[1].name
        scan_left = (
            observations[left]["scan"]
            if include_detector_info
            else observations[left]
        )
        scan_right = (
            observations[right]["scan"]
            if include_detector_info
            else observations[right]
        )
        if (
            scan_left["exit_code"]
            != scan_right["exit_code"]
        ):
            suffix = (
                "scan.exit_code"
                if include_detector_info
                else "exit_code"
            )
            failures.append(f"cases.{name}.oracle_diff.{suffix}")
        if (
            scan_left["stdout_sha256"]
            != scan_right["stdout_sha256"]
        ):
            suffix = "scan.stdout" if include_detector_info else "stdout"
            failures.append(f"cases.{name}.oracle_diff.{suffix}")
        if (
            scan_left["stderr_sha256"]
            != scan_right["stderr_sha256"]
        ):
            suffix = "scan.stderr" if include_detector_info else "stderr"
            failures.append(f"cases.{name}.oracle_diff.{suffix}")
        if trees[left] != trees[right]:
            suffix = (
                "scan.detect_tree"
                if include_detector_info
                else "detect_tree"
            )
            failures.append(f"cases.{name}.oracle_diff.{suffix}")
        if include_detector_info and (
            observations[left]["detector_info"]["exit_code"]
            != observations[right]["detector_info"]["exit_code"]
        ):
            failures.append(f"cases.{name}.oracle_diff.info.exit_code")
        if include_detector_info and (
            observations[left]["detector_info"]["stdout_sha256"]
            != observations[right]["detector_info"]["stdout_sha256"]
        ):
            failures.append(f"cases.{name}.oracle_diff.info.stdout")
        if include_detector_info and (
            observations[left]["detector_info"]["stderr_sha256"]
            != observations[right]["detector_info"]["stderr_sha256"]
        ):
            failures.append(f"cases.{name}.oracle_diff.info.stderr")
        if (
            include_detector_info
            and info_filetypes[left] != info_filetypes[right]
        ):
            failures.append(f"cases.{name}.oracle_diff.info.filetype")

        case = {
            "case_kind": sample["case_kind"],
            "target_filetype": sample["target_filetype"],
            "expected_dispatch": sample["expected_dispatch"],
            "size": sample["size"],
            "sha256": sample["sha256"],
            "oracles": observations,
        }
        if not include_detector_info:
            case["arguments"] = list(scan_arguments)
        cases[name] = case

    unique_failures = list(dict.fromkeys(failures))
    return oracle_identities, cases, unique_failures


def build_report(
    repo: pathlib.Path,
    corpus_dir: pathlib.Path,
    raw_dir: pathlib.Path,
) -> dict[str, Any]:
    manifest, samples, manifest_bytes = load_fixture(repo, corpus_dir)
    oracle_identities, cases, unique_failures = probe_dispatch_cases(
        corpus_dir,
        raw_dir,
        samples,
        include_detector_info=True,
    )
    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_legacy_dispatch.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "result": "pass" if not unique_failures else "fail",
        "upstream_commit": UPSTREAM_COMMIT,
        "rules_commit": RULES_COMMIT,
        "formats_commit": FORMATS_COMMIT,
        "platform": "linux-amd64-qt5",
        "capability": "CAP-DISPATCH-003",
        "corpus_manifest": {
            "path": (
                "docs/research/data/legacy-dispatch-corpus.json"
            ),
            "sha256": sha256(manifest_bytes),
            "sample_count": len(manifest["samples"]),
        },
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir",
            "stdout_and_stderr_retained_for_every_case": True,
        },
        "oracle_identities": oracle_identities,
        "cases": cases,
        "failures": unique_failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        type=pathlib.Path,
        default=ROOT,
    )
    parser.add_argument("--corpus-dir", type=pathlib.Path, required=True)
    parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = build_report(
        args.repo.resolve(),
        args.corpus_dir.resolve(),
        args.raw_dir.resolve(),
    )
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
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

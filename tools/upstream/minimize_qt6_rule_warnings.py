#!/usr/bin/env python3
"""Minimize Qt 6 stderr warnings to pinned PE signature files."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Callable, Sequence


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
IMAGE = "die-rust/upstream-oracle-cmake-qt6:74eaf505"
BINARY = "/opt/die-build/src/console/diec"
INPUT_NAME = "minimal.exe"
INPUT_SHA256 = (
    "afb1bcd812caa45095075a60ff49599c7d5e767c7732226c3e0007708cb198a2"
)
WARNING = b"Unimplemented code."


@dataclass(frozen=True)
class Observation:
    warning_count: int
    stdout: bytes
    stderr: bytes


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def warning_count(stderr: bytes) -> int:
    lines = [line for line in stderr.splitlines() if line]
    unexpected = [line for line in lines if line != WARNING]
    if unexpected:
        raise ValueError(f"unexpected stderr lines: {unexpected!r}")
    return len(lines)


def locate_independent_sources(
    candidates: Sequence[pathlib.Path],
    total: int,
    observe_count: Callable[[Sequence[pathlib.Path]], int],
) -> list[tuple[pathlib.Path, int]]:
    if total == 0:
        return []
    if not candidates:
        raise ValueError("nonzero warning count has no candidates")
    if len(candidates) == 1:
        return [(candidates[0], total)]

    midpoint = len(candidates) // 2
    left = candidates[:midpoint]
    right = candidates[midpoint:]
    left_count = observe_count(left)
    right_count = observe_count(right)
    if left_count + right_count != total:
        raise ValueError(
            "warning sources are not independently additive: "
            f"parent={total}, left={left_count}, right={right_count}"
        )
    return [
        *locate_independent_sources(left, left_count, observe_count),
        *locate_independent_sources(right, right_count, observe_count),
    ]


def verify_inputs(
    rules_root: pathlib.Path,
    corpus_dir: pathlib.Path,
) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    manifest = json.loads(
        (corpus_dir / "manifest.json").read_text(encoding="utf-8")
    )
    entries = {
        entry["name"]: entry for entry in manifest.get("samples", [])
    }
    if (
        manifest.get("generator")
        != "tools/corpus/generate_baseline_corpus.py"
        or entries.get(INPUT_NAME, {}).get("sha256") != INPUT_SHA256
        or sha256((corpus_dir / INPUT_NAME).read_bytes()) != INPUT_SHA256
    ):
        raise ValueError("unexpected baseline PE input identity")

    helpers = sorted(
        (
            path
            for path in rules_root.iterdir()
            if path.is_file() and path.suffix == ""
        ),
        key=lambda path: path.name,
    )
    pe_init = rules_root / "PE/_init"
    if not pe_init.is_file():
        raise ValueError("PE init is missing")
    candidates = sorted(
        (rules_root / "PE").glob("*.sg"),
        key=lambda path: path.name,
    )
    if not helpers or not candidates:
        raise ValueError("rule helper or PE signature inventory is empty")
    return helpers, candidates


def prepare_database(
    target: pathlib.Path,
    rules_root: pathlib.Path,
    helpers: Sequence[pathlib.Path],
    candidates: Sequence[pathlib.Path],
) -> None:
    main = target / "main"
    pe = main / "PE"
    pe.mkdir(parents=True)
    (target / "extra").mkdir()
    (target / "custom").mkdir()
    for helper in helpers:
        shutil.copy2(helper, main / helper.name)
    shutil.copy2(rules_root / "PE/_init", pe / "_init")
    for candidate in candidates:
        shutil.copy2(candidate, pe / candidate.name)


def observe(
    rules_root: pathlib.Path,
    helpers: Sequence[pathlib.Path],
    candidates: Sequence[pathlib.Path],
    corpus_dir: pathlib.Path,
    work_root: pathlib.Path,
) -> Observation:
    with tempfile.TemporaryDirectory(
        prefix="die-rust-qt6-warning-",
        dir=work_root,
    ) as directory:
        database = pathlib.Path(directory)
        prepare_database(
            database,
            rules_root,
            helpers,
            candidates,
        )
        process = subprocess.run(
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
                (
                    f"type=bind,source={database},"
                    "target=/dbfx,readonly"
                ),
                "--mount",
                (
                    f"type=bind,source={corpus_dir},"
                    "target=/corpus,readonly"
                ),
                IMAGE,
                BINARY,
                "--json",
                "--database",
                "/dbfx/main",
                "--extradatabase",
                "/dbfx/extra",
                "--customdatabase",
                "/dbfx/custom",
                f"/corpus/{INPUT_NAME}",
            ],
            check=False,
            capture_output=True,
        )
    if process.returncode != 0:
        raise ValueError(f"oracle exited with {process.returncode}")
    json.loads(process.stdout)
    return Observation(
        warning_count(process.stderr),
        process.stdout,
        process.stderr,
    )


def image_identity() -> dict[str, str]:
    process = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        check=True,
        capture_output=True,
    )
    document = json.loads(process.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision", ""
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError("unexpected Qt6 oracle revision")
    return {
        "name": IMAGE,
        "id": document["Id"],
        "revision": revision,
        "binary": BINARY,
    }


def build_report(
    rules_root: pathlib.Path,
    corpus_dir: pathlib.Path,
    work_root: pathlib.Path,
    raw_dir: pathlib.Path,
) -> dict[str, object]:
    helpers, candidates = verify_inputs(rules_root, corpus_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)
    observations = 0

    def run(selected: Sequence[pathlib.Path]) -> Observation:
        nonlocal observations
        observations += 1
        return observe(
            rules_root,
            helpers,
            selected,
            corpus_dir,
            work_root,
        )

    init_only = run(())
    if init_only.warning_count != 0:
        raise ValueError("PE init-only fixture unexpectedly warns")
    full = run(candidates)
    if full.warning_count != 4:
        raise ValueError(
            f"expected four full-database warnings, got {full.warning_count}"
        )

    findings = locate_independent_sources(
        candidates,
        full.warning_count,
        lambda selected: run(selected).warning_count,
    )
    combined = run([path for path, _ in findings])
    if combined.warning_count != full.warning_count:
        raise ValueError("minimized sources do not reproduce full warnings")

    finding_report = []
    for path, count in findings:
        single = run((path,))
        if single.warning_count != count:
            raise ValueError("single-rule warning count is unstable")
        relative = path.relative_to(rules_root).as_posix()
        stem = path.stem
        stdout_path = raw_dir / f"{stem}.stdout"
        stderr_path = raw_dir / f"{stem}.stderr"
        stdout_path.write_bytes(single.stdout)
        stderr_path.write_bytes(single.stderr)
        finding_report.append(
            {
                "path": relative,
                "sha256": sha256(path.read_bytes()),
                "warning_count": count,
                "stderr_lines": [
                    line.decode("utf-8")
                    for line in single.stderr.splitlines()
                    if line
                ],
                "raw_stdout_bytes": len(single.stdout),
                "raw_stdout_sha256": sha256(single.stdout),
                "raw_stderr_bytes": len(single.stderr),
                "raw_stderr_sha256": sha256(single.stderr),
            }
        )

    return {
        "schema_version": 1,
        "generator": "tools/upstream/minimize_qt6_rule_warnings.py",
        "upstream_commit": UPSTREAM_COMMIT,
        "rules_commit": RULES_COMMIT,
        "platform": "linux-amd64-qt6",
        "oracle": image_identity(),
        "input": {
            "manifest": "docs/research/data/baseline-corpus.json",
            "name": INPUT_NAME,
            "sha256": INPUT_SHA256,
        },
        "candidate_scope": {
            "directory": "db/PE",
            "signature_count": len(candidates),
            "helper_count": len(helpers),
            "pe_init": "db/PE/_init",
        },
        "observations": observations,
        "init_only_warning_count": init_only.warning_count,
        "full_warning_count": full.warning_count,
        "combined_minimized_warning_count": combined.warning_count,
        "independently_additive": True,
        "findings": finding_report,
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    repo = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument(
        "--rules-root",
        type=pathlib.Path,
        default=repo / "upstream/Detect-It-Easy/db",
    )
    parser.add_argument("--corpus-dir", type=pathlib.Path, required=True)
    parser.add_argument("--work-root", type=pathlib.Path, required=True)
    parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = build_report(
        args.rules_root.resolve(),
        args.corpus_dir.resolve(),
        args.work_root.resolve(),
        args.raw_dir.resolve(),
    )
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

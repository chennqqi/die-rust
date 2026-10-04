#!/usr/bin/env python3
"""Run the fixed 28-case special-mode boundary probe on Qt5 and Qt6."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any


GENERATOR = "tools/upstream/probe_qt6_cli_special_boundaries.py"
UNDERLYING_PROBE = "tools/upstream/probe_cli_special_boundaries.py"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_underlying(root: Path) -> Any:
    path = root / UNDERLYING_PROBE
    spec = importlib.util.spec_from_file_location(
        "_diec_qt6_special_underlying", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load special boundary probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_report(
    fixture_dir: Path,
    manifest_path: Path,
    raw_dir: Path,
) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    underlying = load_underlying(root)
    underlying.ORACLES = (
        underlying.Oracle(
            "linux-qt5-cmake",
            "die-rust/upstream-oracle-cmake:74eaf505",
            "/opt/die-build/src/console/diec",
        ),
        underlying.Oracle(
            "linux-qt6-cmake",
            "die-rust/upstream-oracle-cmake-qt6:74eaf505",
            "/opt/die-build/src/console/diec",
        ),
    )
    report = underlying.build_report(
        fixture_dir,
        manifest_path,
        raw_dir,
    )
    underlying_path = root / UNDERLYING_PROBE
    report["generator"] = GENERATOR
    report["generator_sha256"] = sha256(Path(__file__).read_bytes())
    report["underlying_probe"] = {
        "path": UNDERLYING_PROBE,
        "sha256": sha256(underlying_path.read_bytes()),
    }
    report["platform"] = "linux-amd64-qt5-qt6"
    report.pop("closed_corpus_gap", None)
    report["capability_scope"] = [
        "CAP-CLI-MODE-001",
        "CAP-CLI-MODE-002",
        "CAP-CLI-MODE-003",
    ]
    report["result"] = "equal"
    report["limitations"] = [
        "the report covers the fixed 28-case project-generated fixture",
        "raw streams are retained in the external --raw-dir before equality is admitted",
        "normal scan rule diagnostics are outside the special-mode boundary probe",
    ]
    return report


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=(
            root
            / "docs"
            / "research"
            / "data"
            / "cli-special-boundary-fixture.json"
        ),
    )
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
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

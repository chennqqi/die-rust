#!/usr/bin/env python3
"""Run the fixed engine-contract harness on the Qt6 oracle."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any


GENERATOR = "tools/upstream/probe_qt6_engine_contract.py"
UNDERLYING_PROBE = "tools/upstream/probe_engine_contract.py"
IMAGE = "die-rust/engine-contract-harness-qt6:74eaf505"
DOCKERFILE = "tools/upstream/Dockerfile.engine-contract-harness-qt6"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_underlying(root: Path) -> Any:
    upstream_dir = root / "tools" / "upstream"
    sys.path.insert(0, str(upstream_dir))
    path = root / UNDERLYING_PROBE
    spec = importlib.util.spec_from_file_location(
        "_diec_qt6_engine_contract_underlying", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load engine-contract probe")
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
    underlying.IMAGE = IMAGE
    underlying.HARNESS_DOCKERFILE = DOCKERFILE
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
    report["platform"] = "linux-amd64-qt6"
    report.pop("closed_corpus_gap", None)
    report["capability_scope"] = [
        "CAP-ENG-IN-001",
        "CAP-ENG-IN-002",
        "CAP-RULE-006",
        "CAP-RULE-009",
        "CAP-RULE-012",
    ]
    report["result"] = "observed"
    report["limitations"] = [
        "the report is one Qt6 execution of the fixed 37-case harness",
        "random record identifiers are validated by invariants rather than raw equality",
        "Qt5/Qt6 relationship equality is checked by the closure synthesis",
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
            / "rule-orchestration-fixture.json"
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

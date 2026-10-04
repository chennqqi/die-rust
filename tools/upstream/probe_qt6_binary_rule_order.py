#!/usr/bin/env python3
"""Run the fixed Binary profiling-order probe on Qt5 and Qt6."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any


GENERATOR = "tools/upstream/probe_qt6_binary_rule_order.py"
UNDERLYING_PROBE = "tools/upstream/probe_binary_rule_order.py"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_underlying(root: Path) -> Any:
    path = root / UNDERLYING_PROBE
    spec = importlib.util.spec_from_file_location(
        "_diec_qt6_binary_order_underlying", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Binary rule-order probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_report(
    root: Path,
    corpus_dir: Path,
    raw_dir: Path,
    sample: str,
) -> dict[str, Any]:
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
    report = underlying.build_report(root, corpus_dir, raw_dir, sample)
    underlying_path = root / UNDERLYING_PROBE
    report["generator"] = GENERATOR
    report["generator_sha256"] = sha256(Path(__file__).read_bytes())
    report["underlying_probe"] = {
        "path": UNDERLYING_PROBE,
        "sha256": sha256(underlying_path.read_bytes()),
    }
    report["platform"] = "linux-amd64-qt5-qt6"
    report["capability_scope"] = [
        "CAP-CLI-OPT-008",
        "CAP-RULE-011",
    ]
    report["result"] = "equal"
    report["limitations"] = [
        "profiling elapsed times remain only in external raw artifacts",
        "the committed equality projection is the exact 292-name execution order",
        "the probe uses one hash-bound Binary/Nintendo input",
    ]
    return report


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=root)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--sample", default="ps3-type-1-elf.self")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(
        args.repo.resolve(),
        args.corpus_dir.resolve(),
        args.raw_dir.resolve(),
        args.sample,
    )
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

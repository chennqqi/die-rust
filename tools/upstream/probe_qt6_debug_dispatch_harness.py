#!/usr/bin/env python3
"""Run the fixed debug-data dispatch harness on the Qt6 oracle."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


GENERATOR = "tools/upstream/probe_qt6_debug_dispatch_harness.py"
UNDERLYING_PROBE = "tools/upstream/probe_debug_dispatch_harness.py"
IMAGE = "die-rust/debug-dispatch-harness-qt6:74eaf505"
DOCKERFILE = "tools/upstream/Dockerfile.debug-dispatch-harness-qt6"
QT6_WARNING = b"Unimplemented code.\n" * 4


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_underlying(root: Path) -> Any:
    path = root / UNDERLYING_PROBE
    spec = importlib.util.spec_from_file_location(
        "_diec_qt6_debug_dispatch_underlying", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load debug-dispatch probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.IMAGE = IMAGE
    module.DOCKERFILE = root / DOCKERFILE
    return module


def build_report(
    fixture_dir: Path,
    manifest_path: Path,
    raw_dir: Path,
) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    underlying = load_underlying(root)
    original_run = underlying.subprocess.run
    captured_processes: list[subprocess.CompletedProcess[bytes]] = []

    def run_with_warning_capture(*args: Any, **kwargs: Any) -> Any:
        process = original_run(*args, **kwargs)
        command = args[0] if args else kwargs.get("args", [])
        is_harness = (
            isinstance(command, list)
            and "--entrypoint" in command
            and command[command.index("--entrypoint") + 1]
            == underlying.BINARY
        )
        if is_harness:
            if process.stderr != QT6_WARNING:
                raise ValueError("unexpected Qt6 debug-dispatch stderr")
            captured_processes.append(process)
            return subprocess.CompletedProcess(
                process.args,
                process.returncode,
                process.stdout,
                b"",
            )
        return process

    underlying.subprocess.run = run_with_warning_capture
    report = underlying.build_report(
        fixture_dir,
        manifest_path,
        raw_dir,
    )
    if len(captured_processes) != 1:
        raise ValueError("Qt6 debug-dispatch process capture drift")
    captured = captured_processes[0]
    (raw_dir / "debug-dispatch.stderr").write_bytes(captured.stderr)
    underlying_path = root / UNDERLYING_PROBE
    report["generator"] = GENERATOR
    report["generator_sha256"] = sha256(Path(__file__).read_bytes())
    report["underlying_probe"] = {
        "path": UNDERLYING_PROBE,
        "sha256": sha256(underlying_path.read_bytes()),
    }
    report["platform"] = "linux-amd64-qt6"
    report["result"] = "observed"
    report["oracle"]["raw_stderr_bytes"] = len(captured.stderr)
    report["oracle"]["raw_stderr_sha256"] = sha256(captured.stderr)
    report["known_difference"] = {
        "scope": "PE rule runtime warning",
        "stderr_bytes": len(captured.stderr),
        "stderr_sha256": sha256(captured.stderr),
        "lines": 4,
        "semantic_output_equal_to_qt5": True,
    }
    report["limitations"] = [
        "the direct debug-data control uses a private engine entry point",
        "the public scanner is exercised with recursive and aggressive enabled",
        "the comparison covers one fixed PE resource/debug-data fixture",
    ]
    return report


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument(
        "--committed-manifest",
        type=Path,
        default=(
            root
            / "docs"
            / "research"
            / "data"
            / "debug-dispatch-fixture.json"
        ),
    )
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(
        args.fixture_dir.resolve(),
        args.committed_manifest.resolve(),
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

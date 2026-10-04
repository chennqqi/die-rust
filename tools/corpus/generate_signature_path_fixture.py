#!/usr/bin/env python3
"""Generate benign same-name rules for private path-filter experiments."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


DIRECTORIES = (
    "main",
    "main/Binary",
    "extra",
    "extra/Binary",
    "input",
)
INPUT = b"die-rust signature path filter input\n"


def result_rule(name: str) -> bytes:
    return (
        b"function detect() {\n"
        + f'    _setResult("format", "{name}", "", "");\n'.encode(
            "ascii"
        )
        + b"    return true;\n"
        + b"}\n"
    )


FILES = (
    (
        "input/probe.bin",
        INPUT,
        "benign Binary scan input",
    ),
    (
        "main/Binary/shared.1.sg",
        result_rule("main-path"),
        "main-layer rule sharing a basename with the extra rule",
    ),
    (
        "extra/Binary/shared.1.sg",
        result_rule("extra-path"),
        "extra-layer rule sharing a basename with the main rule",
    ),
)

CASES = {
    "empty_filter": {
        "filter": "",
        "expected_names": ["main-path", "extra-path"],
    },
    "exact_main": {
        "filter": "main/Binary/shared.1.sg",
        "expected_names": ["main-path"],
    },
    "exact_extra": {
        "filter": "extra/Binary/shared.1.sg",
        "expected_names": ["extra-path"],
    },
    "missing": {
        "filter": "main/Binary/missing.1.sg",
        "expected_names": [],
    },
    "case_mismatch": {
        "filter": "main/Binary/SHARED.1.SG",
        "expected_names": [],
    },
    "dot_segment": {
        "filter": "main/Binary/../Binary/shared.1.sg",
        "expected_names": [],
    },
    "basename_only": {
        "filter": "shared.1.sg",
        "expected_names": [],
    },
}


def generate(output_dir: pathlib.Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    for directory in DIRECTORIES:
        (output_dir / pathlib.PurePosixPath(directory)).mkdir(
            parents=True,
            exist_ok=True,
        )

    entries = []
    for relative_path, data, purpose in FILES:
        destination = output_dir / pathlib.PurePosixPath(relative_path)
        destination.write_bytes(data)
        entries.append(
            {
                "path": relative_path,
                "source": "project-generated",
                "purpose": purpose,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    manifest: dict[str, object] = {
        "schema_version": 1,
        "generator": (
            "tools/corpus/generate_signature_path_fixture.py"
        ),
        "license": "project-generated; no third-party sample or rule bytes",
        "capability": "CAP-RULE-007",
        "directories": list(DIRECTORIES),
        "entries": entries,
        "cases": CASES,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(
            manifest,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=pathlib.Path)
    args = parser.parse_args()
    manifest = generate(args.output_dir.resolve())
    json.dump(
        manifest,
        fp=sys.stdout,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

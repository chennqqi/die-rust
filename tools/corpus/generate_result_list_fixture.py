#!/usr/bin/env python3
"""Generate benign rules for SCAN_RESULT list-contract experiments."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


DIRECTORIES = ("main", "main/Binary", "input")
INPUT = b"die-rust result list contract input\n"


def result_rule() -> bytes:
    return (
        b"function detect() {\n"
        b'    _setResult("format", "Duplicate", "1", "same");\n'
        b"    return true;\n"
        b"}\n"
    )


FILES = (
    (
        "input/probe.bin",
        INPUT,
        "benign Binary scan input",
    ),
    (
        "main/Binary/a_first.1.sg",
        result_rule(),
        "first exact duplicate result",
    ),
    (
        "main/Binary/b_second.1.sg",
        result_rule(),
        "second exact duplicate result",
    ),
    (
        "main/Binary/c_runtime_error.1.sg",
        (
            b"function detect() {\n"
            b'    throw new Error("result list runtime fixture");\n'
            b"}\n"
        ),
        "JavaScript runtime error",
    ),
    (
        "main/Binary/d_parse_error.1.sg",
        b"function detect( {\n",
        "JavaScript syntax error",
    ),
)


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
        "generator": "tools/corpus/generate_result_list_fixture.py",
        "license": "project-generated; no third-party sample or rule bytes",
        "capability": "CAP-RESULT-002",
        "directories": list(DIRECTORIES),
        "entries": entries,
        "expected_signature_order": [
            "a_first.1.sg",
            "b_second.1.sg",
            "c_runtime_error.1.sg",
            "d_parse_error.1.sg",
        ],
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
    manifest = generate(output_dir=args.output_dir.resolve())
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

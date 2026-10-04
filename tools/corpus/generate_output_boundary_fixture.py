#!/usr/bin/env python3
"""Generate benign rules that exercise legacy CLI output escaping."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


INPUT = b"die-rust output boundary fixture\n"
SPECIAL_NAME = (
    'Quote" Backslash\\ Slash/ Semi; Comma, Tab\t CR\r LF\n '
    "XML<>&' Snowman\u2603 CJK\u4e2d Emoji\U0001f600 "
    "LS\u2028PS\u2029"
)
SPECIAL_VERSION = 'v"\\;\t\r\n<>&\''
SPECIAL_INFO = 'info;,\t\r\n"\\/<>&\' \u2603\u4e2d\U0001f600'

EXPECTED_RECORDS = (
    {
        "type": "format",
        "name": SPECIAL_NAME,
        "version": SPECIAL_VERSION,
        "info": SPECIAL_INFO,
    },
    {
        "type": "compiler",
        "name": "Second;compiler",
        "version": "2\tbeta",
        "info": "line1\nline2",
    },
    {
        "type": "tool",
        "name": "Third",
        "version": "",
        "info": "tail",
    },
)


def javascript_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def build_rule() -> bytes:
    calls = "\n".join(
        "    _setResult("
        + ", ".join(
            javascript_string(record[field])
            for field in ("type", "name", "version", "info")
        )
        + ");"
        for record in EXPECTED_RECORDS
    )
    return (
        "function detect() {\n"
        f"{calls}\n"
        "    return true;\n"
        "}\n"
    ).encode("ascii")


RULE = build_rule()
DIRECTORIES = ("database", "database/Binary", "input")
FILES = (
    (
        "database/Binary/output-boundary.1.sg",
        RULE,
        "rule emitting output delimiter and Unicode boundaries",
    ),
    (
        "input/plain.bin",
        INPUT,
        "benign Binary input",
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
                "purpose": purpose,
                "source": "project-generated",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    manifest: dict[str, object] = {
        "schema_version": 1,
        "generator": (
            "tools/corpus/generate_output_boundary_fixture.py"
        ),
        "license": "project-generated; no third-party sample or rule bytes",
        "directories": list(DIRECTORIES),
        "expected_records": list(EXPECTED_RECORDS),
        "entries": entries,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(
            manifest,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=pathlib.Path)
    args = parser.parse_args()
    manifest = generate(args.output_dir.resolve())
    sys.stdout.buffer.write(
        (
            json.dumps(
                manifest,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

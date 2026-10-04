#!/usr/bin/env python3
"""Generate benign deterministic include lifecycle fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


CASE_NAMES = ("self-cycle", "two-cycle", "parse-error", "missing")
DIRECTORIES = tuple(
    directory
    for case in CASE_NAMES
    for directory in (
        f"{case}-main",
        f"{case}-main/Binary",
        f"{case}-extra",
        f"{case}-custom",
    )
) + ("input",)

FILES = (
    (
        "input/probe.bin",
        b"die-rust include lifecycle fixture\n",
        "benign Binary scan input",
    ),
    (
        "self-cycle-main/_init",
        b'includeScript("self");\n',
        "global init enters self include",
    ),
    (
        "self-cycle-main/self",
        b'includeScript("self");\n',
        "direct include cycle",
    ),
    (
        "self-cycle-main/Binary/after.1.sg",
        (
            b"function detect() {\n"
            b'    _setResult("format", "After self cycle", "", "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "detect whether traversal continues after self cycle",
    ),
    (
        "two-cycle-main/_init",
        b'includeScript("cycle-a");\n',
        "global init enters two-node include cycle",
    ),
    (
        "two-cycle-main/cycle-a",
        b'includeScript("cycle-b");\n',
        "two-node include cycle first helper",
    ),
    (
        "two-cycle-main/cycle-b",
        b'includeScript("cycle-a");\n',
        "two-node include cycle second helper",
    ),
    (
        "two-cycle-main/Binary/after.1.sg",
        (
            b"function detect() {\n"
            b'    _setResult("format", "After two cycle", "", "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "detect whether traversal continues after two-node cycle",
    ),
    (
        "parse-error-main/_init",
        b'includeScript("broken-helper");\n',
        "global init includes malformed helper",
    ),
    (
        "parse-error-main/broken-helper",
        b"function broken( {\n",
        "included JavaScript syntax error",
    ),
    (
        "parse-error-main/Binary/after.1.sg",
        (
            b"function detect() {\n"
            b'    _setResult("format", "After parse error", "", "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "detect whether traversal continues after include parse error",
    ),
    (
        "missing-main/_init",
        b'includeScript("not-present");\n',
        "global init includes absent helper",
    ),
    (
        "missing-main/Binary/after.1.sg",
        (
            b"function detect() {\n"
            b'    _setResult("format", "After missing include", "", "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "detect whether traversal continues after missing include",
    ),
)


def generate(output_dir: pathlib.Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    for directory in DIRECTORIES:
        (output_dir / pathlib.PurePosixPath(directory)).mkdir(
            parents=True, exist_ok=True
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
        "generator": "tools/corpus/generate_include_fixture.py",
        "license": "project-generated; no third-party sample or rule bytes",
        "directories": list(DIRECTORIES),
        "entries": entries,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=pathlib.Path)
    args = parser.parse_args()
    manifest = generate(args.output_dir.resolve())
    json.dump(manifest, fp=sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

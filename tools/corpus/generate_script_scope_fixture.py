#!/usr/bin/env python3
"""Generate benign rules that expose cross-evaluate script scope semantics."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


DIRECTORIES = ("main", "main/Binary", "extra", "custom", "input")

FILES = (
    (
        "input/probe.bin",
        b"die-rust script scope probe\n",
        "benign scan input",
    ),
    (
        "main/Binary/scope_const_define.1.sg",
        (
            b"const scopeValue = 1;\n"
            b"function detect() {\n"
            b'    _setResult("format", "Scope const define", '
            b'String(scopeValue), "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "define a top-level const and observe it from detect",
    ),
    (
        "main/Binary/scope_const_assign.2.sg",
        (
            b"scopeValue = 2;\n"
            b"function detect() {\n"
            b'    _setResult("format", "Scope const assignment", '
            b'String(scopeValue), "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "assign a name declared const by the preceding evaluate",
    ),
    (
        "main/Binary/scope_function_detect.3.sg",
        (
            b"function detect() {\n"
            b'    _setResult("format", "Scope function detect", "", "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "establish a function declaration named detect",
    ),
    (
        "main/Binary/scope_const_detect.4.sg",
        (
            b"const detect = main;\n"
            b"function main() {\n"
            b'    _setResult("format", "Scope const detect", "", "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "bind const detect after a preceding function declaration",
    ),
    (
        "main/Binary/scope_after_const_detect.5.sg",
        (
            b"function detect() {\n"
            b'    _setResult("format", "Scope after const detect", "", "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "declare function detect after a preceding const detect",
    ),
    (
        "main/Binary/scope_debug_const.6.sg",
        (
            b"const debug = 1;\n"
            b"function detect() {\n"
            b'    _setResult("format", "Scope debug const", '
            b'String(debug), "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "define a second top-level const used by a later rule",
    ),
    (
        "main/Binary/scope_debug_assign.7.sg",
        (
            b"debug = 2;\n"
            b"function detect() {\n"
            b'    _setResult("format", "Scope debug assignment", '
            b'String(debug), "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "assign the second name declared const by a preceding evaluate",
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
        "generator": "tools/corpus/generate_script_scope_fixture.py",
        "license": "project-generated; no third-party sample or rule bytes",
        "directories": list(DIRECTORIES),
        "rule_order": [
            relative_path.removeprefix("main/Binary/")
            for relative_path, _, _ in FILES
            if relative_path.startswith("main/Binary/")
        ],
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

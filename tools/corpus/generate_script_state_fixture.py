#!/usr/bin/env python3
"""Generate benign rules that expose persistent cross-evaluate state."""

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
        b"die-rust script state probe\n",
        "benign scan input",
    ),
    (
        "main/Binary/state_var_define.1.sg",
        (
            b"var sharedVar = 40;\n"
            b"function detect() {\n"
            b'    _setResult("format", "State var define", '
            b'String(sharedVar), "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "define and observe a top-level var",
    ),
    (
        "main/Binary/state_var_update.2.sg",
        (
            b"sharedVar += 2;\n"
            b"function detect() {\n"
            b'    _setResult("format", "State var update", '
            b'String(sharedVar), "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "read and update a var from the preceding evaluate",
    ),
    (
        "main/Binary/state_function_define.3.sg",
        (
            b"function sharedFunction() { return 42; }\n"
            b"function detect() {\n"
            b'    _setResult("format", "State function define", '
            b'String(sharedFunction()), "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "define and observe a top-level helper function",
    ),
    (
        "main/Binary/state_function_read.4.sg",
        (
            b"function detect() {\n"
            b'    _setResult("format", "State function read", '
            b'String(sharedFunction()), "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "call a helper function from the preceding evaluate",
    ),
    (
        "main/Binary/state_implicit_define.5.sg",
        (
            b"sharedImplicit = 7;\n"
            b"function detect() {\n"
            b'    _setResult("format", "State implicit define", '
            b'String(sharedImplicit), "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "create an implicit global in sloppy mode",
    ),
    (
        "main/Binary/state_implicit_read.6.sg",
        (
            b"function detect() {\n"
            b'    _setResult("format", "State implicit read", '
            b'String(sharedImplicit), "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "read an implicit global from the preceding evaluate",
    ),
    (
        "main/Binary/state_this.7.sg",
        (
            b"var capturedThis = this;\n"
            b"capturedThis.stateThisMarker = 9;\n"
            b"function detect() {\n"
            b'    _setResult("format", "State top-level this", '
            b'String(this === capturedThis && stateThisMarker === 9), "");\n'
            b"    return true;\n"
            b"}\n"
        ),
        "observe top-level this identity without modern globalThis",
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
        "generator": "tools/corpus/generate_script_state_fixture.py",
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

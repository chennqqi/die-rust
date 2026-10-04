#!/usr/bin/env python3
"""Generate benign rules for record type/name enum experiments."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


DIRECTORIES = ("main", "main/Binary", "empty-main", "input")
INPUT = b"die-rust result enum contract input\n"


def result_rule(result_type: str, name: str) -> bytes:
    return (
        b"function detect() {\n"
        + f'    _setResult("{result_type}", "{name}", "", "");\n'.encode(
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
        "main/Binary/known_alias.1.sg",
        result_rule("PE-Tool", "7 ZIP"),
        "known type/name using non-canonical spelling",
    ),
    (
        "main/Binary/HEUR.heuristic.2.sg",
        result_rule("~format", "7-Zip"),
        "heuristic raw type mapped to the Format enum",
    ),
    (
        "main/Binary/custom.3.sg",
        result_rule("Vendor-Custom", "Project/Custom"),
        "unrecognized raw type/name retained beside Unknown enums",
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
        "generator": "tools/corpus/generate_result_enum_fixture.py",
        "license": "project-generated; no third-party sample or rule bytes",
        "capability": "CAP-RESULT-005",
        "directories": list(DIRECTORIES),
        "entries": entries,
        "cases": {
            "known_alias": {
                "database": "main",
                "signature": "known_alias.1.sg",
                "heuristic_scan": False,
            },
            "heuristic_prefix": {
                "database": "main",
                "signature": "HEUR.heuristic.2.sg",
                "heuristic_scan": True,
            },
            "custom_raw": {
                "database": "main",
                "signature": "custom.3.sg",
                "heuristic_scan": False,
            },
            "unknown_fallback": {
                "database": "empty-main",
                "signature": "",
                "heuristic_scan": False,
            },
        },
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

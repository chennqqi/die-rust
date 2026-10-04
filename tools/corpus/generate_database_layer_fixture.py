#!/usr/bin/env python3
"""Generate benign main/extra/custom database-layer fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


INPUT = b"die-rust deterministic database layer corpus\n"
LAYERS = ("main", "extra", "custom")
RULES = (
    ("layer-low.1.sg", "Low"),
    ("shared.5.sg", "Shared"),
    ("layer-high.9.sg", "High"),
)


def result_rule(name: str) -> bytes:
    return (
        b"function detect() {\n"
        + f'    _setResult("format", "{name}", "1", "");\n'.encode()
        + b"    return true;\n"
        + b"}\n"
    )


def generate(output_dir: pathlib.Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, object]] = []

    input_path = output_dir / "input.bin"
    input_path.write_bytes(INPUT)
    entries.append(
        {
            "path": "input.bin",
            "source": "project-generated",
            "purpose": "benign Binary scan input",
            "size": len(INPUT),
            "sha256": hashlib.sha256(INPUT).hexdigest(),
        }
    )

    for layer in LAYERS:
        binary_dir = output_dir / layer / "Binary"
        binary_dir.mkdir(parents=True, exist_ok=True)
        title = layer.title()
        for filename, suffix in RULES:
            data = result_rule(f"{title}{suffix}")
            relative_path = f"{layer}/Binary/{filename}"
            (output_dir / pathlib.PurePosixPath(relative_path)).write_bytes(
                data
            )
            entries.append(
                {
                    "path": relative_path,
                    "source": "project-generated",
                    "purpose": (
                        f"{layer} layer {suffix.lower()} priority rule"
                    ),
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )

    manifest: dict[str, object] = {
        "schema_version": 1,
        "generator": (
            "tools/corpus/generate_database_layer_fixture.py"
        ),
        "license": (
            "project-generated; no third-party sample or rule bytes"
        ),
        "layers": list(LAYERS),
        "rule_filenames": [filename for filename, _ in RULES],
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

#!/usr/bin/env python3
"""Generate benign database success/failure fixtures for upstream CLI tests."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import sys
import warnings
import zipfile


DIRECTORIES = (
    "empty-main",
    "empty-extra",
    "empty-custom",
    "malformed-main",
    "malformed-main/Binary",
    "throwing-main",
    "throwing-main/Binary",
    "valid-main",
    "valid-main/Binary",
    "input",
)

INPUT = b"die-rust deterministic corpus\n"
MALFORMED_RULE = b"function detect( {\n"
THROWING_RULE = (
    b'function detect() {\n'
    b'    throw new Error("database fixture");\n'
    b"}\n"
)


def result_rule(name: str) -> bytes:
    return (
        b"function detect() {\n"
        + f'    _setResult("format", "{name}", "1", "");\n'.encode()
        + b"    return true;\n"
        + b"}\n"
    )


VALID_RULE = result_rule("Fixture")


def make_zip(entries: tuple[tuple[str, bytes], ...]) -> bytes:
    """Create a byte-stable, stored ZIP while preserving duplicate names."""
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(
            output,
            mode="w",
            compression=zipfile.ZIP_STORED,
        ) as archive:
            for name, data in entries:
                info = zipfile.ZipInfo(
                    filename=name,
                    date_time=(1980, 1, 1, 0, 0, 0),
                )
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data)
    return output.getvalue()


VALID_ZIP = make_zip((("Binary/fixture.1.sg", VALID_RULE),))
EMPTY_ZIP = make_zip(())
DUPLICATE_ZIP = make_zip(
    (
        ("Binary/duplicate.1.sg", result_rule("DuplicateFirst")),
        ("Binary/duplicate.1.sg", result_rule("DuplicateSecond")),
    )
)
TRAVERSAL_ZIP = make_zip(
    (("Binary/../traversal.1.sg", result_rule("TraversalName")),)
)
PREFIXED_ZIP = make_zip(
    (("database/Binary/prefixed.1.sg", result_rule("Prefixed")),)
)
CENTRAL_DIRECTORY_OFFSET = VALID_ZIP.index(b"PK\x01\x02")
EOCD_TRUNCATED_ZIP = VALID_ZIP[:-22]
CENTRAL_DIRECTORY_TRUNCATED_ZIP = VALID_ZIP[:CENTRAL_DIRECTORY_OFFSET]
PAYLOAD_TRUNCATED_ZIP = VALID_ZIP[: CENTRAL_DIRECTORY_OFFSET - 1]
PAYLOAD_STRUCTURE_TRUNCATED_ZIP = VALID_ZIP[
    : CENTRAL_DIRECTORY_OFFSET - 2
]
LOCAL_HEADER_TRUNCATED_ZIP = VALID_ZIP[:29]


FILES = (
    ("input/plain.txt", INPUT, "benign scan input"),
    (
        "not-a-database.bin",
        b"not a ZIP database\n",
        "invalid database archive",
    ),
    (
        "malformed-main/Binary/broken.1.sg",
        MALFORMED_RULE,
        "JavaScript syntax error",
    ),
    (
        "throwing-main/Binary/throw.1.sg",
        THROWING_RULE,
        "JavaScript runtime error",
    ),
    (
        "valid-main/Binary/fixture.1.sg",
        VALID_RULE,
        "deterministic successful detection",
    ),
    (
        "valid-main.zip",
        VALID_ZIP,
        "valid ZIP database with one Binary rule",
    ),
    (
        "empty-main.zip",
        EMPTY_ZIP,
        "valid empty ZIP database",
    ),
    (
        "truncated-main.zip",
        EOCD_TRUNCATED_ZIP,
        "database ZIP with the 22-byte EOCD removed",
    ),
    (
        "local-only-main.zip",
        CENTRAL_DIRECTORY_TRUNCATED_ZIP,
        "database ZIP containing only local header and complete payload",
    ),
    (
        "payload-truncated-main.zip",
        PAYLOAD_TRUNCATED_ZIP,
        "database ZIP truncated one byte before the rule payload ends",
    ),
    (
        "payload-structure-truncated-main.zip",
        PAYLOAD_STRUCTURE_TRUNCATED_ZIP,
        "database ZIP truncated before the rule closing brace and newline",
    ),
    (
        "local-header-truncated-main.zip",
        LOCAL_HEADER_TRUNCATED_ZIP,
        "database ZIP truncated inside the first local header",
    ),
    (
        "duplicate-main.zip",
        DUPLICATE_ZIP,
        "ZIP database with duplicate Binary entry names",
    ),
    (
        "traversal-main.zip",
        TRAVERSAL_ZIP,
        "ZIP database with a Binary/../ rule entry name",
    ),
    (
        "prefixed-main.zip",
        PREFIXED_ZIP,
        "ZIP database with an additional root directory prefix",
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
        "generator": "tools/corpus/generate_database_fixture.py",
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

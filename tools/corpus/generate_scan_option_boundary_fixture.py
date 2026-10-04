#!/usr/bin/env python3
"""Generate benign deep/aggressive/resource-count boundary fixtures."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys


GENERATOR = "tools/corpus/generate_scan_option_boundary_fixture.py"
DIRECTORIES = (
    "database",
    "database/Binary",
    "database/PE",
    "database/PDF",
    "extra",
    "custom",
    "input",
)


def _load_nested_generator():
    module_path = pathlib.Path(__file__).with_name(
        "generate_nested_corpus.py"
    )
    spec = importlib.util.spec_from_file_location(
        "_diec_nested_fixture_generator",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load nested fixture generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


NESTED = _load_nested_generator()


def make_grouped_pe_resources(
    counts: tuple[int, ...],
    payload: bytes,
    first_resource_type: int = 24,
) -> bytes:
    """Create a PE32 whose resource count spans multiple type directories."""
    if not counts or any(count < 1 or count > 1000 for count in counts):
        raise ValueError("each PE resource group must contain 1..1000 items")
    if sum(counts) < 1 or not payload:
        raise ValueError("grouped PE resources require data")

    total = sum(counts)
    root_directory_offset = 0
    type_directories_offset = 0x10 + len(counts) * 8
    type_offsets = []
    cursor = type_directories_offset
    for count in counts:
        type_offsets.append(cursor)
        cursor += 0x10 + count * 8
    language_directories_offset = cursor
    data_entries_offset = language_directories_offset + total * 0x18
    resource_payload_offset = NESTED._align_up(
        data_entries_offset + total * 0x10,
        0x10,
    )
    resource_virtual_address = 0x1000
    resource_size = resource_payload_offset + total * len(payload)
    raw_size = NESTED._align_up(resource_size, 0x200)
    image = bytearray(0x200 + raw_size)

    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH", image, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x0102
    )
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<II", image, optional + 20, 0x1000, 0x1000)
    struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", image, optional + 68, 3)
    struct.pack_into("<I", image, optional + 92, 16)
    struct.pack_into(
        "<II",
        image,
        optional + 96 + 2 * 8,
        resource_virtual_address,
        resource_size,
    )
    section = optional + 224
    image[section : section + 8] = b".rsrc\0\0\0"
    struct.pack_into(
        "<IIIIIIHHI",
        image,
        section + 8,
        resource_size,
        resource_virtual_address,
        raw_size,
        0x200,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    struct.pack_into(
        "<I",
        image,
        optional + 56,
        NESTED._align_up(0x1000 + resource_size, 0x1000),
    )

    resource = 0x200
    struct.pack_into(
        "<IIHHHH",
        image,
        resource + root_directory_offset,
        0,
        0,
        0,
        0,
        0,
        len(counts),
    )
    global_index = 0
    for group_index, (count, type_offset) in enumerate(
        zip(counts, type_offsets)
    ):
        struct.pack_into(
            "<II",
            image,
            resource + 0x10 + group_index * 8,
            first_resource_type + group_index,
            0x80000000 | type_offset,
        )
        struct.pack_into(
            "<IIHHHH",
            image,
            resource + type_offset,
            0,
            0,
            0,
            0,
            0,
            count,
        )
        for item_index in range(count):
            language_offset = (
                language_directories_offset + global_index * 0x18
            )
            data_entry_offset = data_entries_offset + global_index * 0x10
            payload_offset = (
                resource_payload_offset + global_index * len(payload)
            )
            struct.pack_into(
                "<II",
                image,
                resource + type_offset + 0x10 + item_index * 8,
                item_index + 1,
                0x80000000 | language_offset,
            )
            struct.pack_into(
                "<IIHHHH",
                image,
                resource + language_offset,
                0,
                0,
                0,
                0,
                0,
                1,
            )
            struct.pack_into(
                "<II",
                image,
                resource + language_offset + 0x10,
                0x409,
                data_entry_offset,
            )
            struct.pack_into(
                "<IIII",
                image,
                resource + data_entry_offset,
                resource_virtual_address + payload_offset,
                len(payload),
                0,
                0,
            )
            image[resource + payload_offset] = payload[0]
            if len(payload) > 1:
                image[
                    resource + payload_offset :
                    resource + payload_offset + len(payload)
                ] = payload
            global_index += 1
    return bytes(image)


def detection_rule(name: str) -> bytes:
    return (
        "function detect() {\n"
        f'    _setResult("format", "{name}", "", "");\n'
        "    return true;\n"
        "}\n"
    ).encode("ascii")


FILES = (
    (
        "database/Binary/normal.1.sg",
        detection_rule("Binary normal"),
        "ordinary Binary rule",
    ),
    (
        "database/Binary/DS.deep.2.sg",
        detection_rule("Binary deep"),
        "DS rule enabled only by deep scan",
    ),
    (
        "database/Binary/EP.entrypoint.3.sg",
        detection_rule("Binary entrypoint"),
        "EP rule enabled only by deep scan",
    ),
    (
        "database/PE/root.1.sg",
        detection_rule("PE root"),
        "stable parent record for resource scans",
    ),
    (
        "database/PDF/pdf.1.sg",
        detection_rule("PDF child"),
        "stable record for scanable PDF resources",
    ),
    (
        "input/probe.bin",
        b"die-rust scan option boundary probe\n",
        "benign Binary input for deep filtering",
    ),
    (
        "input/pe-one-unclassified.exe",
        NESTED.make_pe_resources(1, b"\0", 24),
        "PE32 with one unclassified resource",
    ),
    (
        "input/pe-22-pdf.exe",
        NESTED.make_pe_pdf_resources(22),
        "PE32 with 22 scanable PDF resources",
    ),
    (
        "input/pe-2002-unclassified.exe",
        make_grouped_pe_resources((668, 667, 667), b"\0"),
        "PE32 with 2002 unclassified resources across three types",
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
        "generator": GENERATOR,
        "license": "project-generated; no third-party sample or rule bytes",
        "directories": list(DIRECTORIES),
        "boundaries": {
            "default_resource_scan_count": 21,
            "aggressive_resource_scan_count": 2001,
            "resource_enumeration_count": 10000,
        },
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
    sys.stdout.buffer.write(
        (
            json.dumps(manifest, indent=2, sort_keys=True)
            + "\n"
        ).encode("utf-8")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

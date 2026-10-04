#!/usr/bin/env python3
"""Generate a benign PE with one Manifest resource and one RSDS record."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
import sys


SAMPLE_NAME = "pe-resource-debug.exe"
MANIFEST_PAYLOAD = b"\0DIEC-RUST-MANIFEST\0"
RSDS_PAYLOAD = (
    b"RSDS"
    + bytes.fromhex("00112233445566778899aabbccddeeff")
    + struct.pack("<I", 1)
    + b"die-rust.pdb\0"
)
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
RESOURCE_RAW = 0x200
RESOURCE_RVA = 0x1000
RESOURCE_PAYLOAD_RELATIVE = 0x60
DEBUG_RAW = 0x400
DEBUG_RVA = 0x2000
DEBUG_PAYLOAD_RELATIVE = 0x40


def make_pe_resource_debug() -> bytes:
    image = bytearray(0x600)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        image,
        0x84,
        0x14C,
        2,
        0,
        0,
        0,
        224,
        0x0102,
    )

    optional = 0x98
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<II", image, optional + 20, 0x1000, 0x1000)
    struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into(
        "<II",
        image,
        optional + 32,
        SECTION_ALIGNMENT,
        FILE_ALIGNMENT,
    )
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x200)
    struct.pack_into("<H", image, optional + 68, 3)
    struct.pack_into("<I", image, optional + 92, 16)

    resource_size = (
        RESOURCE_PAYLOAD_RELATIVE + len(MANIFEST_PAYLOAD)
    )
    debug_size = DEBUG_PAYLOAD_RELATIVE + len(RSDS_PAYLOAD)
    struct.pack_into(
        "<II",
        image,
        optional + 96 + 2 * 8,
        RESOURCE_RVA,
        resource_size,
    )
    struct.pack_into(
        "<II",
        image,
        optional + 96 + 6 * 8,
        DEBUG_RVA,
        28,
    )

    resource_section = optional + 224
    image[
        resource_section : resource_section + 8
    ] = b".rsrc\0\0\0"
    struct.pack_into(
        "<IIIIIIHHI",
        image,
        resource_section + 8,
        resource_size,
        RESOURCE_RVA,
        FILE_ALIGNMENT,
        RESOURCE_RAW,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    debug_section = resource_section + 40
    image[debug_section : debug_section + 8] = b".debug\0\0"
    struct.pack_into(
        "<IIIIIIHHI",
        image,
        debug_section + 8,
        debug_size,
        DEBUG_RVA,
        FILE_ALIGNMENT,
        DEBUG_RAW,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    resource = RESOURCE_RAW
    struct.pack_into("<IIHHHH", image, resource, 0, 0, 0, 0, 0, 1)
    struct.pack_into(
        "<II",
        image,
        resource + 0x10,
        24,
        0x80000018,
    )
    struct.pack_into(
        "<IIHHHH",
        image,
        resource + 0x18,
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
        resource + 0x28,
        1,
        0x80000030,
    )
    struct.pack_into(
        "<IIHHHH",
        image,
        resource + 0x30,
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
        resource + 0x40,
        0x409,
        0x48,
    )
    struct.pack_into(
        "<IIII",
        image,
        resource + 0x48,
        RESOURCE_RVA + RESOURCE_PAYLOAD_RELATIVE,
        len(MANIFEST_PAYLOAD),
        0,
        0,
    )
    resource_payload = RESOURCE_RAW + RESOURCE_PAYLOAD_RELATIVE
    image[
        resource_payload : resource_payload + len(MANIFEST_PAYLOAD)
    ] = MANIFEST_PAYLOAD

    debug_payload = DEBUG_RAW + DEBUG_PAYLOAD_RELATIVE
    struct.pack_into(
        "<IIHHIIII",
        image,
        DEBUG_RAW,
        0,
        0,
        0,
        0,
        2,
        len(RSDS_PAYLOAD),
        DEBUG_RVA + DEBUG_PAYLOAD_RELATIVE,
        debug_payload,
    )
    image[
        debug_payload : debug_payload + len(RSDS_PAYLOAD)
    ] = RSDS_PAYLOAD
    return bytes(image)


def generate(output_dir: pathlib.Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    data = make_pe_resource_debug()
    (output_dir / SAMPLE_NAME).write_bytes(data)
    manifest: dict[str, object] = {
        "schema_version": 1,
        "generator": (
            "tools/corpus/generate_debug_dispatch_fixture.py"
        ),
        "license": "project-generated; no third-party sample bytes",
        "capability": "CAP-NEST-007",
        "sample": {
            "name": SAMPLE_NAME,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "resource": {
                "type_id": 24,
                "offset": (
                    RESOURCE_RAW + RESOURCE_PAYLOAD_RELATIVE
                ),
                "size": len(MANIFEST_PAYLOAD),
                "sha256": hashlib.sha256(
                    MANIFEST_PAYLOAD
                ).hexdigest(),
            },
            "debug_data": {
                "type": 2,
                "offset": DEBUG_RAW + DEBUG_PAYLOAD_RELATIVE,
                "size": len(RSDS_PAYLOAD),
                "sha256": hashlib.sha256(
                    RSDS_PAYLOAD
                ).hexdigest(),
                "signature": "RSDS",
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

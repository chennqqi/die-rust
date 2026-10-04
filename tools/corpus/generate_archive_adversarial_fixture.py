#!/usr/bin/env python3
"""Generate deterministic compressed, encrypted, and malformed ZIP fixtures."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import zlib


GENERATOR = "tools/corpus/generate_archive_adversarial_fixture.py"
PASSWORD = b"die-rust"


def _load_baseline_module():
    module_path = pathlib.Path(__file__).with_name(
        "generate_baseline_corpus.py"
    )
    spec = importlib.util.spec_from_file_location(
        "_diec_archive_adversarial_baseline",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load baseline corpus builders")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BASELINE = _load_baseline_module()
PDF = BASELINE.make_pdf()
HIGH_RATIO_PAYLOAD = PDF + bytes(1024 * 1024 - len(PDF))


def _raw_deflate(payload: bytes) -> bytes:
    compressor = zlib.compressobj(
        level=9,
        method=zlib.DEFLATED,
        wbits=-15,
    )
    return compressor.compress(payload) + compressor.flush()


def _crc32_byte(value: int, byte: int) -> int:
    return (
        binascii.crc32(bytes((byte,)), value ^ 0xFFFFFFFF)
        ^ 0xFFFFFFFF
    ) & 0xFFFFFFFF


def _zipcrypto_encrypt(payload: bytes, password: bytes, crc: int) -> bytes:
    key0 = 0x12345678
    key1 = 0x23456789
    key2 = 0x34567890

    def update_keys(byte: int) -> None:
        nonlocal key0, key1, key2
        key0 = _crc32_byte(key0, byte)
        key1 = (
            (key1 + (key0 & 0xFF)) * 134775813 + 1
        ) & 0xFFFFFFFF
        key2 = _crc32_byte(key2, key1 >> 24)

    for byte in password:
        update_keys(byte)

    header = bytes(range(11)) + bytes(((crc >> 24) & 0xFF,))
    result = bytearray()
    for clear in header + payload:
        temporary = (key2 | 2) & 0xFFFFFFFF
        mask = ((temporary * (temporary ^ 1)) >> 8) & 0xFF
        result.append(clear ^ mask)
        update_keys(clear)
    return bytes(result)


def make_entry(
    name: str,
    payload: bytes,
    *,
    method: int = 0,
    encrypted: bool = False,
    crc_override: int | None = None,
    uncompressed_size_override: int | None = None,
    compressed_bytes_override: bytes | None = None,
    compressed_size_override: int | None = None,
) -> dict[str, object]:
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    compressed = payload if method in (0, 99) else _raw_deflate(payload)
    if compressed_bytes_override is not None:
        compressed = compressed_bytes_override
    flags = 0
    if encrypted:
        flags |= 1
        compressed = _zipcrypto_encrypt(
            compressed,
            PASSWORD,
            crc,
        )
    return {
        "compressed": compressed,
        "compressed_size": (
            len(compressed)
            if compressed_size_override is None
            else compressed_size_override
        ),
        "crc": crc if crc_override is None else crc_override,
        "flags": flags,
        "method": method,
        "name": name.encode("ascii"),
        "uncompressed_size": (
            len(payload)
            if uncompressed_size_override is None
            else uncompressed_size_override
        ),
    }


def make_zip(
    entries: list[dict[str, object]],
    *,
    include_central_directory: bool = True,
    include_eocd: bool = True,
    local_offset_overrides: dict[int, int] | None = None,
) -> bytes:
    local = bytearray()
    central = bytearray()
    local_offsets: list[int] = []
    for entry in entries:
        name = entry["name"]
        assert isinstance(name, bytes)
        compressed = entry["compressed"]
        assert isinstance(compressed, bytes)
        local_offsets.append(len(local))
        local.extend(
            struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50,
                20,
                entry["flags"],
                entry["method"],
                0,
                0,
                entry["crc"],
                entry["compressed_size"],
                entry["uncompressed_size"],
                len(name),
                0,
            )
        )
        local.extend(name)
        local.extend(compressed)

    if not include_central_directory:
        return bytes(local)

    for index, entry in enumerate(entries):
        name = entry["name"]
        assert isinstance(name, bytes)
        local_offset = local_offsets[index]
        if local_offset_overrides and index in local_offset_overrides:
            local_offset = local_offset_overrides[index]
        central.extend(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                0x0314,
                20,
                entry["flags"],
                entry["method"],
                0,
                0,
                entry["crc"],
                entry["compressed_size"],
                entry["uncompressed_size"],
                len(name),
                0,
                0,
                0,
                0,
                0,
                local_offset,
            )
        )
        central.extend(name)

    result = bytes(local + central)
    if not include_eocd:
        return result
    return result + struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        len(entries),
        len(entries),
        len(central),
        len(local),
        0,
    )


def _corrupted_deflate(payload: bytes) -> bytes:
    compressed = bytearray(_raw_deflate(payload))
    compressed[len(compressed) // 2] ^= 0x80
    return bytes(compressed)


def _truncated_deflate_entry() -> dict[str, object]:
    compressed = _raw_deflate(PDF)
    return make_entry(
        "payload.pdf",
        PDF,
        method=8,
        compressed_bytes_override=compressed[: len(compressed) // 2],
        compressed_size_override=len(compressed),
    )


FIXTURES = (
    {
        "category": "control",
        "data": lambda: make_zip(
            [make_entry("payload.pdf", PDF)]
        ),
        "member_count": 1,
        "name": "stored-valid.zip",
        "purpose": "stored PDF positive control",
        "zipfile_readable": True,
    },
    {
        "category": "compressed",
        "data": lambda: make_zip(
            [make_entry("payload.pdf", PDF, method=8)]
        ),
        "member_count": 1,
        "name": "deflate-valid.zip",
        "purpose": "deflate PDF positive control",
        "zipfile_readable": True,
    },
    {
        "category": "high_ratio",
        "data": lambda: make_zip(
            [
                make_entry(
                    "payload.pdf",
                    HIGH_RATIO_PAYLOAD,
                    method=8,
                )
            ]
        ),
        "member_count": 1,
        "name": "deflate-high-ratio.zip",
        "purpose": "1 MiB PDF-prefix payload compressed with deflate",
        "zipfile_readable": True,
    },
    {
        "category": "encrypted",
        "data": lambda: make_zip(
            [
                make_entry(
                    "payload.pdf",
                    PDF,
                    encrypted=True,
                )
            ]
        ),
        "member_count": 1,
        "name": "zipcrypto-stored.zip",
        "purpose": "traditional ZipCrypto member without scanner password API",
        "zipfile_readable": True,
    },
    {
        "category": "malformed_crc",
        "data": lambda: make_zip(
            [
                make_entry(
                    "payload.pdf",
                    PDF,
                    crc_override=(
                        (binascii.crc32(PDF) & 0xFFFFFFFF) ^ 1
                    ),
                )
            ]
        ),
        "member_count": 1,
        "name": "stored-bad-crc.zip",
        "purpose": "stored member with mismatched CRC",
        "zipfile_readable": False,
    },
    {
        "category": "malformed_compressed_data",
        "data": lambda: make_zip(
            [
                make_entry(
                    "payload.pdf",
                    PDF,
                    method=8,
                    compressed_bytes_override=_corrupted_deflate(PDF),
                )
            ]
        ),
        "member_count": 1,
        "name": "deflate-corrupt.zip",
        "purpose": "deflate member with one corrupted compressed byte",
        "zipfile_readable": False,
    },
    {
        "category": "malformed_truncation",
        "data": lambda: make_zip([_truncated_deflate_entry()]),
        "member_count": 1,
        "name": "deflate-truncated.zip",
        "purpose": "truncated deflate stream with original declared size",
        "zipfile_readable": False,
    },
    {
        "category": "local_header_fallback",
        "data": lambda: make_zip(
            [make_entry("payload.pdf", PDF)],
            include_central_directory=False,
            include_eocd=False,
        ),
        "member_count": 1,
        "name": "stored-local-only.zip",
        "purpose": "valid local record without central directory or EOCD",
        "zipfile_readable": False,
    },
    {
        "category": "malformed_offset",
        "data": lambda: make_zip(
            [make_entry("payload.pdf", PDF)],
            local_offset_overrides={0: 0xFFFFFF00},
        ),
        "member_count": 1,
        "name": "stored-invalid-local-offset.zip",
        "purpose": "central record points outside the archive",
        "zipfile_readable": False,
    },
    {
        "category": "unsupported_method",
        "data": lambda: make_zip(
            [
                make_entry(
                    "payload.pdf",
                    PDF,
                    method=99,
                    crc_override=0,
                )
            ]
        ),
        "member_count": 1,
        "name": "unsupported-method-99.zip",
        "purpose": "unknown ZIP method with CRC verification disabled",
        "zipfile_readable": False,
    },
    {
        "category": "path_metadata",
        "data": lambda: make_zip(
            [make_entry("../escape.pdf", PDF)]
        ),
        "member_count": 1,
        "name": "stored-traversal-name.zip",
        "purpose": "stored PDF carrying parent-directory path metadata",
        "zipfile_readable": True,
    },
    {
        "category": "mixed_members",
        "data": lambda: make_zip(
            [
                make_entry("payload.pdf", PDF),
                make_entry("note.bin", b"A"),
            ]
        ),
        "member_count": 2,
        "name": "mixed-members.zip",
        "purpose": "scanable PDF followed by one-byte non-scanable member",
        "zipfile_readable": True,
    },
)


def generate(output_dir: pathlib.Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    samples = []
    for fixture in FIXTURES:
        data = fixture["data"]()
        name = fixture["name"]
        assert isinstance(data, bytes)
        assert isinstance(name, str)
        (output_dir / name).write_bytes(data)
        samples.append(
            {
                "archive_format": "ZIP",
                "category": fixture["category"],
                "member_count": fixture["member_count"],
                "name": name,
                "purpose": fixture["purpose"],
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "zipfile_readable": fixture["zipfile_readable"],
            }
        )
    manifest: dict[str, object] = {
        "generator": GENERATOR,
        "license": "project-generated; no third-party sample bytes",
        "password": PASSWORD.decode("ascii"),
        "samples": samples,
        "schema_version": 1,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=pathlib.Path)
    args = parser.parse_args()
    manifest = generate(args.output_dir.resolve())
    json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

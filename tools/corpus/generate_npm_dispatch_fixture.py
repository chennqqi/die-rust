#!/usr/bin/env python3
"""Generate deterministic NPM tar.gz dispatch fixtures."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys


GENERATOR = "tools/corpus/generate_npm_dispatch_fixture.py"
VALID_PACKAGE_JSON = b'{"name":"die-fixture","version":"1.2.3"}\n'
INVALID_PACKAGE_JSON = b'{"name":'
JAVASCRIPT = b"module.exports = 1;\n"
TYPESCRIPT = b"export const value: number = 1;\n"


def _load_baseline_module():
    module_path = pathlib.Path(__file__).with_name(
        "generate_baseline_corpus.py"
    )
    spec = importlib.util.spec_from_file_location(
        "_diec_npm_dispatch_baseline",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load baseline corpus builders")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BASELINE = _load_baseline_module()


def tar_entry(name: str, data: bytes) -> bytes:
    encoded_name = name.encode("utf-8")
    if not encoded_name or len(encoded_name) > 100:
        raise ValueError("fixture TAR name must use the USTAR name field")
    header = bytearray(512)
    header[0 : len(encoded_name)] = encoded_name
    header[100:108] = BASELINE._tar_octal(0o644, 8)
    header[108:116] = BASELINE._tar_octal(0, 8)
    header[116:124] = BASELINE._tar_octal(0, 8)
    header[124:136] = BASELINE._tar_octal(len(data), 12)
    header[136:148] = BASELINE._tar_octal(0, 12)
    header[148:156] = b"        "
    header[156:157] = b"0"
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[265:297] = b"die-rust".ljust(32, b"\0")
    header[297:329] = b"die-rust".ljust(32, b"\0")
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
    return bytes(header) + data + bytes((-len(data)) % 512)


def make_tar_gz(entries: tuple[tuple[str, bytes], ...]) -> bytes:
    tar = b"".join(tar_entry(name, data) for name, data in entries)
    tar += bytes(1024)
    return (
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"
        + BASELINE._stored_deflate(tar)
        + struct.pack(
            "<II",
            binascii.crc32(tar) & 0xFFFFFFFF,
            len(tar) & 0xFFFFFFFF,
        )
    )


CASES = (
    {
        "detector_control": "exact path with valid JSON",
        "entries": (
            ("package/package.json", VALID_PACKAGE_JSON),
            ("package/index.js", JAVASCRIPT),
        ),
        "expected_npm": True,
        "name": "npm-valid.tgz",
        "purpose": "natural NPM positive with package metadata and JavaScript",
    },
    {
        "detector_control": "exact path with invalid JSON",
        "entries": (
            ("package/package.json", INVALID_PACKAGE_JSON),
            ("package/index.ts", TYPESCRIPT),
        ),
        "expected_npm": True,
        "name": "npm-invalid-json.tgz",
        "purpose": "NPM path positive independent of package JSON validity",
    },
    {
        "detector_control": "package.json at archive root",
        "entries": (
            ("package.json", VALID_PACKAGE_JSON),
            ("package/index.js", JAVASCRIPT),
        ),
        "expected_npm": False,
        "name": "root-package-json.tgz",
        "purpose": "near control with package.json outside package directory",
    },
    {
        "detector_control": "case-mismatched package/Package.json",
        "entries": (
            ("package/Package.json", VALID_PACKAGE_JSON),
            ("package/index.ts", TYPESCRIPT),
        ),
        "expected_npm": False,
        "name": "case-package-json.tgz",
        "purpose": "near control for case-sensitive archive record matching",
    },
)


def generate(output_dir: pathlib.Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    samples = []
    for case in CASES:
        entries = case["entries"]
        data = make_tar_gz(entries)
        name = case["name"]
        (output_dir / name).write_bytes(data)
        samples.append(
            {
                "detector_control": case["detector_control"],
                "entries": [entry_name for entry_name, _ in entries],
                "expected_npm": case["expected_npm"],
                "name": name,
                "purpose": case["purpose"],
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    manifest: dict[str, object] = {
        "generator": GENERATOR,
        "license": "project-generated; no third-party sample bytes",
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
    sys.stdout.buffer.write(
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

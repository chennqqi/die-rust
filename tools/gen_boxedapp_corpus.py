#!/usr/bin/env python3
"""Deterministic BoxedApp container fixture.

Mirrors upstream `XBoxedApp`:

- PE32 with exactly one `.bxpck` and one `.main` section; `.main`
  carries the `BoxedApp::` ANSI engine marker.
- VFS nodes inside `.bxpck`: `u32 node_size | u16 5 | u32 0xFFFFFFFF`,
  `u32 orig_size @ +0x2A`, five ascending in-node offsets `@ +0x3E`
  (`off3` = UTF-16LE name start, `off4` = data slot).
- STORE node: `orig_size == node_end - off4`, raw bytes at the slot.
- Compressed node: slot = `[34 pad][u16 0x0010][u32 method][u32 0]
  [u32 stored][content]`; method 1 content is a zlib stream that must
  inflate to exactly `orig_size` with exact input consumption.
"""

import os
import struct
import sys
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "corpus")


def utf16z(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def node(name: str, orig_size: int, slot_payload: bytes) -> bytes:
    """Build one VFS node; `slot_payload` starts at off4."""
    name_b = utf16z(name)
    off3 = 0x5C
    off4 = off3 + len(name_b)
    node_size = off4 + len(slot_payload)
    body = bytearray(node_size)
    struct.pack_into("<I", body, 0, node_size)
    struct.pack_into("<H", body, 4, 5)
    struct.pack_into("<I", body, 6, 0xFFFFFFFF)
    struct.pack_into("<I", body, 0x2A, orig_size)
    offs = [0x50, 0x54, 0x58, off3, off4]
    for i, o in enumerate(offs):
        struct.pack_into("<I", body, 0x3E + i * 4, o)
    body[off3 : off3 + len(name_b)] = name_b
    body[off4:] = slot_payload
    return bytes(body)


def build() -> bytes:
    bx_raw, bx_size = 0x400, 0x400
    mn_raw, mn_size = 0x800, 0x200
    total = mn_raw + mn_size
    data = bytearray(total)

    # DOS + PE headers.
    struct.pack_into("<H", data, 0, 0x5A4D)
    struct.pack_into("<I", data, 0x3C, 0x80)
    pe = 0x80
    struct.pack_into("<I", data, pe, 0x4550)
    fh = pe + 4
    struct.pack_into("<H", data, fh + 0, 0x014C)
    struct.pack_into("<H", data, fh + 2, 2)
    struct.pack_into("<H", data, fh + 16, 0xE0)
    struct.pack_into("<H", data, fh + 18, 0x010F)
    oh = fh + 20
    struct.pack_into("<I", data, oh + 0, 0x010B)
    struct.pack_into("<I", data, oh + 16, 0x1000)
    struct.pack_into("<I", data, oh + 28, 0x400000)
    struct.pack_into("<I", data, oh + 32, 0x1000)
    struct.pack_into("<I", data, oh + 36, 0x200)
    struct.pack_into("<I", data, oh + 56, 0x3000)
    struct.pack_into("<I", data, oh + 60, 0x400)
    struct.pack_into("<H", data, oh + 68, 2)
    struct.pack_into("<I", data, oh + 92, 16)

    # Section table.
    s0 = oh + 0xE0
    data[s0 : s0 + 8] = b".bxpck\0\0"
    struct.pack_into("<I", data, s0 + 8, bx_size)
    struct.pack_into("<I", data, s0 + 12, 0x1000)
    struct.pack_into("<I", data, s0 + 16, bx_size)
    struct.pack_into("<I", data, s0 + 20, bx_raw)
    s1 = s0 + 40
    data[s1 : s1 + 8] = b".main\0\0\0"
    struct.pack_into("<I", data, s1 + 8, mn_size)
    struct.pack_into("<I", data, s1 + 12, 0x2000)
    struct.pack_into("<I", data, s1 + 16, mn_size)
    struct.pack_into("<I", data, s1 + 20, mn_raw)

    # .main: engine marker string only.
    marker = b"BoxedApp::Engine\x00"
    data[mn_raw : mn_raw + 0x20] = marker + bytes(0x20 - len(marker))

    # .bxpck nodes.
    payload_a = b"boxedapp stored file body!" + bytes(range(16))
    payload_b = b"boxedapp compressed member contents " * 4

    n_a = node("app.exe", len(payload_a), payload_a)

    comp = zlib.compress(payload_b)
    slot = bytes(34)
    slot += struct.pack("<H", 0x0010)
    slot += struct.pack("<I", 1)  # method zlib
    slot += struct.pack("<I", 0)  # reserved
    slot += struct.pack("<I", len(comp))
    slot += comp
    n_b = node("lib.dll", len(payload_b), slot)

    region = n_a + n_b
    assert len(region) <= bx_size
    data[bx_raw : bx_raw + len(region)] = region
    return bytes(data)


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "boxedapp-minimal.exe")
    with open(path, "wb") as f:
        f.write(build())
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    sys.exit(main())

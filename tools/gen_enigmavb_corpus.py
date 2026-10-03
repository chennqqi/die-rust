#!/usr/bin/env python3
"""Deterministic Enigma Virtual Box container fixture.

Layout mirrored from upstream `XEnigmaVB`:

- PE32 with `.enigma1` + `.enigma2` sections.
- `.enigma1` starts with the 0x53-byte `EVB\0` header (format dword at
  +0x14, top-level node count at +0x4C).
- Pre-order node tree: `u32 id | u32 type | u32 children` + UTF-16LE
  NUL-terminated name; dir nodes pad 30, file nodes carry
  `+3 | u64 orig | +39 | u64 stored`.
- Blob stream follows the tree in record order; a stored member is
  `stored == orig` verbatim bytes, a compressed member is
  `[u64 12][u32 aplib_len][aPLib stream]` (literal-only aPLib emitted
  by this generator), then a 0x16 terminator and zero padding.
"""

import os
import struct
import sys

OUT = os.path.join(os.path.dirname(__file__), "..", "corpus")


def aplib_literal(payload: bytes) -> bytes:
    """Standard aPLib stream producing `payload` via literals only.

    First source byte is the first literal. Every later literal costs
    one `0` tag bit followed by the raw byte; the stream ends with the
    `1,1,0` tag plus a zero offset byte.
    """
    if not payload:
        raise ValueError("aPLib stream needs a nonempty payload")
    tags = [0] * (len(payload) - 1) + [1, 1, 0]
    data = list(payload[1:]) + [0x00]
    out = bytearray([payload[0]])
    di = 0
    for i in range(0, len(tags), 8):
        group = tags[i : i + 8]
        tag = 0
        for bit in group:
            tag = (tag << 1) | bit
        tag <<= 8 - len(group)
        out.append(tag)
        for bit in group:
            if bit == 0:
                out.append(data[di])
                di += 1
    assert di == len(data)
    return bytes(out)


def utf16z(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def build() -> bytes:
    e1_raw, e1_size = 0x400, 0x400
    e2_raw, e2_size = e1_raw + e1_size, 0x200
    total = e2_raw + e2_size
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
    data[s0 : s0 + 8] = b".enigma1"
    struct.pack_into("<I", data, s0 + 8, e1_size)
    struct.pack_into("<I", data, s0 + 12, 0x1000)
    struct.pack_into("<I", data, s0 + 16, e1_size)
    struct.pack_into("<I", data, s0 + 20, e1_raw)
    s1 = s0 + 40
    data[s1 : s1 + 8] = b".enigma2"
    struct.pack_into("<I", data, s1 + 8, e2_size)
    struct.pack_into("<I", data, s1 + 12, 0x2000)
    struct.pack_into("<I", data, s1 + 16, e2_size)
    struct.pack_into("<I", data, s1 + 20, e2_raw)

    # --- .enigma1 contents -------------------------------------------------
    e1 = bytearray(e1_size)
    e1[0:4] = b"EVB\0"
    struct.pack_into("<I", e1, 0x14, 0x0005)  # fmt -> "package v5"
    struct.pack_into("<I", e1, 0x4C, 1)  # one root node (dir)
    cur = 0x53

    # dir node: id=1 type=1 children=2 name "docs"
    struct.pack_into("<III", e1, cur, 1, 1, 2)
    cur += 12
    name = utf16z("docs")
    e1[cur : cur + len(name)] = name
    cur += len(name)
    cur += 30

    payload_a = b"enigma stored member payload!!!" + b"\x00"
    payload_b = b"EVB compressed member body" * 2

    # file node A (stored): id=2
    struct.pack_into("<III", e1, cur, 2, 2, 0)
    cur += 12
    name = utf16z("readme.txt")
    e1[cur : cur + len(name)] = name
    cur += len(name)
    cur += 3
    struct.pack_into("<Q", e1, cur, len(payload_a))
    cur += 8
    cur += 39
    struct.pack_into("<Q", e1, cur, len(payload_a))
    cur += 8

    # file node B (compressed): id=3
    stream = aplib_literal(payload_b)
    blob = struct.pack("<Q", 12) + struct.pack("<I", len(stream)) + stream
    struct.pack_into("<III", e1, cur, 3, 2, 0)
    cur += 12
    name = utf16z("data.bin")
    e1[cur : cur + len(name)] = name
    cur += len(name)
    cur += 3
    struct.pack_into("<Q", e1, cur, len(payload_b))
    cur += 8
    cur += 39
    struct.pack_into("<Q", e1, cur, len(blob))
    cur += 8

    # blob stream
    e1[cur : cur + len(payload_a)] = payload_a
    cur += len(payload_a)
    e1[cur : cur + len(blob)] = blob
    cur += len(blob)
    e1[cur] = 0x16
    cur += 1
    # rest is already zero padding

    assert cur <= e1_size
    data[e1_raw : e1_raw + e1_size] = e1
    return bytes(data)


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "enigmavb-minimal.exe")
    with open(path, "wb") as f:
        f.write(build())
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    sys.exit(main())

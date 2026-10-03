#!/usr/bin/env python3
"""Deterministic synthetic Petite 2.x packed PE for oracle differential.

Upstream `XPETITE::_detect` requires:
  - PE32, EP = `B8 <last-section VA + imageBase>` (version 2.x)
  - ep[0x80] != 0x163c988d

`_inflate` walks an op table found via `B8 <loaderbase> ... 8D 80 <imm>`
(lea eax,[eax+imm]) inside the loader section; each op is {srva, size,
thisrva} terminated by a zero srva. The decoder is a sentinel-bit stream:
first byte raw, then literal = streambyte ^ remaining-size, or gamma-coded
matches. Literal-only streams suffice for a deterministic fixture.

Layout (file offsets):
  0x138  section[0] (.code): vsz=0x1000 va=0x1000 raw 0x400 @0x200
  0x160  section[1] (loader): vsz=0x1000 va=0x2000 raw 0x400 @0x600
  0x600  EP: B8 <0x402000> 8D 80 <0x200>
  0x800  op table (buf offset 0x1200): two section ops + terminator
  0x900  op0 stream -> produces {41 42 43 44} at thisrva 0x1000
  0x950  op1 stream -> produces {45 46 47 48} at thisrva 0x1100
"""

import struct
import sys

IMG = 0x400000
SEC0_VA = 0x1000
SEC1_VA = 0x2000  # loader
SEC0_RAW = 0x200
SEC1_RAW = 0x600
SEC_RSZ = 0x400


def literal_stream(out: bytes) -> bytes:
    """Encode a literal-only petite stream producing `out` (<=8 bytes)."""
    n = len(out)
    assert 1 <= n <= 8
    stream = bytearray([out[0]])
    # One refill byte of all-zero bits covers up to 7 literals.
    stream.append(0x00)
    size = n - 1
    for b in out[1:]:
        stream.append(b ^ (size & 0xFF))
        size -= 1
    return bytes(stream)


def build() -> bytes:
    data = bytearray(SEC1_RAW + SEC_RSZ)

    # DOS + PE headers.
    struct.pack_into("<H", data, 0, 0x5A4D)
    struct.pack_into("<I", data, 0x3C, 0x40)
    pe = 0x40
    struct.pack_into("<I", data, pe, 0x4550)
    fh = pe + 4
    struct.pack_into("<H", data, fh + 0, 0x014C)
    struct.pack_into("<H", data, fh + 2, 2)
    struct.pack_into("<H", data, fh + 16, 0xE0)
    struct.pack_into("<H", data, fh + 18, 0x010F)
    oh = fh + 20
    struct.pack_into("<H", data, oh + 0, 0x010B)
    struct.pack_into("<I", data, oh + 16, SEC1_VA)   # EP = loader VA
    struct.pack_into("<I", data, oh + 28, IMG)
    struct.pack_into("<I", data, oh + 32, 0x1000)
    struct.pack_into("<I", data, oh + 36, 0x200)
    struct.pack_into("<I", data, oh + 56, 0x3000)
    struct.pack_into("<I", data, oh + 60, 0x200)
    struct.pack_into("<H", data, oh + 68, 2)
    struct.pack_into("<I", data, oh + 92, 16)

    sec = oh + 0xE0  # 0x138
    data[sec:sec + 8] = b".code\0\0\0"
    struct.pack_into("<I", data, sec + 8, 0x1000)
    struct.pack_into("<I", data, sec + 12, SEC0_VA)
    struct.pack_into("<I", data, sec + 16, SEC_RSZ)
    struct.pack_into("<I", data, sec + 20, SEC0_RAW)
    struct.pack_into("<I", data, sec + 36, 0xE00000E0)
    sec += 0x28  # 0x160
    data[sec:sec + 8] = b".petite\0"
    struct.pack_into("<I", data, sec + 8, 0x1000)
    struct.pack_into("<I", data, sec + 12, SEC1_VA)
    struct.pack_into("<I", data, sec + 16, SEC_RSZ)
    struct.pack_into("<I", data, sec + 20, SEC1_RAW)
    struct.pack_into("<I", data, sec + 36, 0xE00000E0)

    # EP stub: mov eax, loaderBase; lea eax, [eax+0x200]
    data[SEC1_RAW] = 0xB8
    struct.pack_into("<I", data, SEC1_RAW + 1, IMG + SEC1_VA)
    data[SEC1_RAW + 5] = 0x8D
    data[SEC1_RAW + 6] = 0x80
    struct.pack_into("<I", data, SEC1_RAW + 7, 0x200)

    # Op table at loader+0x200 = file 0x800.
    ops = SEC1_RAW + 0x200
    struct.pack_into("<I", data, ops + 0x00, SEC1_VA + 0x300)  # srva
    struct.pack_into("<I", data, ops + 0x04, 4)                # size
    struct.pack_into("<I", data, ops + 0x08, SEC0_VA)          # thisrva
    struct.pack_into("<I", data, ops + 0x10, SEC1_VA + 0x350)
    struct.pack_into("<I", data, ops + 0x14, 4)
    struct.pack_into("<I", data, ops + 0x18, SEC0_VA + 0x100)
    struct.pack_into("<I", data, ops + 0x20, 0)                # terminator

    # Streams: buf offset = file offset (loader raw starts at 0x600 -> buf 0x1000).
    data[SEC1_RAW + 0x300:SEC1_RAW + 0x305] = literal_stream(bytes([0x41, 0x42, 0x43, 0x44]))
    data[SEC1_RAW + 0x350:SEC1_RAW + 0x355] = literal_stream(bytes([0x45, 0x46, 0x47, 0x48]))
    return bytes(data)


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/petite2-minimal.exe"
    with open(out, "wb") as f:
        f.write(build())
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

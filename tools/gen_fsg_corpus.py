#!/usr/bin/env python3
"""Deterministic synthetic FSG 1.0-1.3 packed PE for oracle differential.

Upstream `XFSG::_detect` v100 arm requires:
  - PE32 with a raw=0/vsz!=0 section followed by a nonempty one
  - EP inside a section; stub = BB <supVA> BF <dstVA> BE <srcVA> 53
    plus the v100 get-bit routine bytes at EP+16..30
  - support pointer below the first section RVA (PE header region)
  - 16-bit word-list support table; word 2 terminates
  - `0F 84` OEP jump at stub+224 anchored by `FE` at stub+222

The packed payload is a minimal literal-only aPLib stream
[first_literal, 0xC0, 0x00] producing exactly one output byte.
"""

import struct
import sys


def build_fsg_v100(payload_byte: int = 0x42, two_sections: bool = False) -> bytes:
    image_base = 0x400000
    dst_rva = 0x1000
    src_rva = 0x2000
    ep_rva = src_rva
    support_rva = 0x40
    stream_rva = src_rva + 0x100
    # Second rebuilt section must live inside [dst_rva, dst_rva+dst_vsz).
    extra_rva = 0x1200
    extra_word = ((extra_rva + image_base) >> 12) + 2

    src_off = 0x400
    support_off = 0x40
    dst_vsz = 0x400  # must exceed src raw size
    src_raw = 0x200

    total = src_off + src_raw
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
    struct.pack_into("<H", data, oh + 0, 0x010B)
    struct.pack_into("<I", data, oh + 16, ep_rva)
    struct.pack_into("<I", data, oh + 28, image_base)
    struct.pack_into("<I", data, oh + 32, 0x1000)
    struct.pack_into("<I", data, oh + 36, 0x200)
    struct.pack_into("<I", data, oh + 56, 0x3000)
    struct.pack_into("<I", data, oh + 60, 0x200)
    struct.pack_into("<H", data, oh + 68, 2)
    struct.pack_into("<I", data, oh + 92, 16)

    # Section table: dst (empty raw), src (raw data).
    sec = oh + 0xE0
    data[sec:sec + 8] = b".dst\0\0\0\0"
    struct.pack_into("<I", data, sec + 8, dst_vsz)
    struct.pack_into("<I", data, sec + 12, dst_rva)
    struct.pack_into("<I", data, sec + 16, 0)
    struct.pack_into("<I", data, sec + 20, 0)
    struct.pack_into("<I", data, sec + 36, 0xE00000E0)
    sec += 0x28
    data[sec:sec + 8] = b".src\0\0\0\0"
    struct.pack_into("<I", data, sec + 8, src_raw)
    struct.pack_into("<I", data, sec + 12, src_rva)
    struct.pack_into("<I", data, sec + 16, src_raw)
    struct.pack_into("<I", data, sec + 20, src_off)
    struct.pack_into("<I", data, sec + 36, 0xE00000E0)

    # Word-list support table in the header region.
    if two_sections:
        struct.pack_into("<H", data, support_off, extra_word)
        struct.pack_into("<H", data, support_off + 2, 2)
    else:
        struct.pack_into("<H", data, support_off, 2)

    # EP stub at the entry point.
    stub = src_off  # EP file offset
    data[stub + 0] = 0xBB
    struct.pack_into("<I", data, stub + 1, image_base + support_rva)
    data[stub + 5] = 0xBF
    struct.pack_into("<I", data, stub + 6, image_base + dst_rva)
    data[stub + 10] = 0xBE
    struct.pack_into("<I", data, stub + 11, image_base + stream_rva)
    data[stub + 15] = 0x53
    # v100 get-bit routine opener at stub+16..30.
    data[stub + 16:stub + 31] = bytes(
        [0xE8, 0x0A, 0x00, 0x00, 0x00, 0x02, 0xD2, 0x75, 0x05,
         0x8A, 0x16, 0x46, 0x12, 0xD2, 0xC3])
    # OEP anchor: FE at stub+222, 0F 84 rel32 at stub+224.
    data[stub + 222] = 0xFE
    data[stub + 224] = 0x0F
    data[stub + 225] = 0x84
    rel32 = (dst_rva - (ep_rva + 224 + 6)) & 0xFFFFFFFF
    struct.pack_into("<I", data, stub + 226, rel32)

    # aPLib literal-only stream(s) at stream_rva's file offset.
    stream_off = src_off + (stream_rva - src_rva)
    data[stream_off:stream_off + 3] = bytes([payload_byte, 0xC0, 0x00])
    if two_sections:
        data[stream_off + 3:stream_off + 6] = bytes([payload_byte + 1, 0xC0, 0x00])
    return bytes(data)


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/fsg-v100-minimal.exe"
    two = len(sys.argv) > 2 and sys.argv[2] == "two"
    with open(out, "wb") as f:
        f.write(build_fsg_v100(two_sections=two))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Deterministic synthetic MEW-packed PE fixtures for oracle differential.

Upstream `XMEW::_detect` requires:
  - PE32 with an empty-raw/nonzero-vsz section followed by a nonempty one
  - EP: bare `E9 rel32` (v11) or `33 C0 E9 rel32` (v10) whose target
    RVA numerically equals file offset 0x154/0x155/0x158
  - stub table at that file offset: tbuff[0]=0xBE, [5,6]=8B DE (v11)
    or AC 91 (v10), dword at +1 = stored VA (offDiff anchor)
  - tbuff[0x7B] != 0xE8 -> aPLib block-chain path (no LZMA)

The stub table overlaps section headers (file 0x154 lands inside the
first section header with a 2-section table); unused fields carry the
stub bytes.

Layout (file offsets):
  0x138  section[0] header (dst): vsz=0x1000, va=0x1000, raw=0
  0x160  section[1] header (src): vsz=0x1000, va=0x2000, raw=0x200 @0x200
  0x154  stub table (inside section[0] header's unused fields)
  0x200  src raw: EP stub, then header at +0x20, then aPLib stream
"""

import struct
import sys

IMG = 0x400000
VADD = 0x1000  # section[0] VA
SRC_VA = 0x2000  # section[1] VA
VMA = IMG + VADD
DSIZE = 0x1000
SSIZE = 0x1000
SRC_RAW = 0x200
SRC_RSZ = 0x200
OFFDIFF = 0x20
STORED_VA = IMG + SRC_VA + OFFDIFF  # 0x402020


def pe_header(data: bytearray, ep_rva: int) -> None:
    """Write DOS/PE headers; section table lands at 0x138."""
    struct.pack_into("<H", data, 0, 0x5A4D)
    struct.pack_into("<I", data, 0x3C, 0x40)
    pe = 0x40
    struct.pack_into("<I", data, pe, 0x4550)
    fh = pe + 4
    struct.pack_into("<H", data, fh + 0, 0x014C)
    struct.pack_into("<H", data, fh + 2, 2)
    struct.pack_into("<H", data, fh + 16, 0xE0)
    struct.pack_into("<H", data, fh + 18, 0x010F)
    oh = fh + 20  # 0x58
    struct.pack_into("<H", data, oh + 0, 0x010B)
    struct.pack_into("<I", data, oh + 16, ep_rva)
    struct.pack_into("<I", data, oh + 28, IMG)
    struct.pack_into("<I", data, oh + 32, 0x1000)
    struct.pack_into("<I", data, oh + 36, 0x200)
    struct.pack_into("<I", data, oh + 56, 0x3000)
    struct.pack_into("<I", data, oh + 60, 0x200)
    struct.pack_into("<H", data, oh + 68, 2)
    struct.pack_into("<I", data, oh + 92, 16)


def sections(data: bytearray) -> None:
    """Section[0]=dst (empty), section[1]=src; headers at 0x138/0x160."""
    sec = 0x138
    data[sec:sec + 8] = b".dst\0\0\0\0"
    struct.pack_into("<I", data, sec + 8, DSIZE)   # VirtualSize  @0x140
    struct.pack_into("<I", data, sec + 12, VADD)   # VirtualAddr  @0x144
    struct.pack_into("<I", data, sec + 16, 0)      # RawSize      @0x148
    struct.pack_into("<I", data, sec + 20, 0)      # RawPtr       @0x14C
    # 0x150..0x15C carry stub-table bytes (ptrReloc/ptrLine/nReloc/nLine)
    struct.pack_into("<I", data, sec + 36, 0xE00000E0)
    sec = 0x160
    data[sec:sec + 8] = b".src\0\0\0\0"
    struct.pack_into("<I", data, sec + 8, SSIZE)   # @0x168 = tbuff[0x14]
    struct.pack_into("<I", data, sec + 12, SRC_VA)  # @0x16C
    struct.pack_into("<I", data, sec + 16, SRC_RSZ)  # @0x170
    struct.pack_into("<I", data, sec + 20, SRC_RAW)  # @0x174
    struct.pack_into("<I", data, sec + 36, 0xE00000E0)


def stub_table(data: bytearray, version: int) -> None:
    """Stub table at file 0x154, overlapping section[0] unused fields."""
    data[0x154] = 0xBE
    struct.pack_into("<I", data, 0x155, STORED_VA)  # tbuff+1: offDiff anchor
    if version == 11:
        data[0x159] = 0x8B
        data[0x15A] = 0xDE  # mov ebx,esi
    else:
        data[0x159] = 0xAC
        data[0x15A] = 0x91  # lodsb / xchg eax,ecx
    # tbuff[0x7B] @0x1CF stays 0 -> aPLib path (useLzma=0)


def ep_stub(data: bytearray, version: int) -> None:
    """EP bytes at SRC_RAW (file 0x200): jump to stub table RVA 0x154."""
    if version == 11:
        disp = (0x154 - (SRC_VA + 0 + 5)) & 0xFFFFFFFF
        data[SRC_RAW] = 0xE9
        struct.pack_into("<I", data, SRC_RAW + 1, disp)
    else:
        disp = (0x154 - (SRC_VA + 2 + 5)) & 0xFFFFFFFF
        data[SRC_RAW:SRC_RAW + 2] = bytes([0x33, 0xC0])
        data[SRC_RAW + 2] = 0xE9
        struct.pack_into("<I", data, SRC_RAW + 3, disp)


def mew11() -> bytes:
    """MEW 11 aPLib path: 12-byte header then aPLib stream + nextRva=0."""
    data = bytearray(SRC_RAW + SRC_RSZ)
    pe_header(data, SRC_VA)
    sections(data)
    stub_table(data, 11)
    ep_stub(data, 11)

    hdr = SRC_RAW + OFFDIFF  # file 0x220 -> buf[DSIZE+OFFDIFF]
    # header: [0..4] unused, [4..8] entryPoint VA, [8..12] newEdi VA
    struct.pack_into("<I", data, hdr + 4, IMG + 0x1000)  # OEP = RVA 0x1000
    struct.pack_into("<I", data, hdr + 8, VMA)           # newEdi -> ledi=0
    # aPLib stream at 0x22C producing {41 42 43 44} then nextRva=0.
    stream = bytes([0x41, 0x18, 0x42, 0x43, 0x44, 0x00])
    data[hdr + 12:hdr + 12 + len(stream)] = stream
    struct.pack_into("<I", data, hdr + 12 + len(stream), 0)  # nextRva
    return bytes(data)


def mew10() -> bytes:
    """MEW 10: count-prefixed block table + continuous source stream."""
    data = bytearray(SRC_RAW + SRC_RSZ)
    pe_header(data, SRC_VA)
    sections(data)
    stub_table(data, 10)
    ep_stub(data, 10)

    hdr = SRC_RAW + OFFDIFF  # file 0x220 -> buf[DSIZE+OFFDIFF]
    nblocks = 1
    # header: [nBlocks][helper 4B][srcVA 4B][destVA*4][fixerVA 4B]
    stream_va = VMA + DSIZE + OFFDIFF + 13 + 4 * nblocks
    fixer_va = VMA + DSIZE + 0x100
    data[hdr] = nblocks
    struct.pack_into("<I", data, hdr + 5, stream_va)
    struct.pack_into("<I", data, hdr + 9, VMA)          # destVA -> ledi=0
    struct.pack_into("<I", data, hdr + 9 + 4 * nblocks, fixer_va)
    # aPLib stream at file offset of stream_va.
    stream_off = SRC_RAW + (stream_va - VMA) - DSIZE
    stream = bytes([0x41, 0x18, 0x42, 0x43, 0x44, 0x00])
    data[stream_off:stream_off + len(stream)] = stream
    # storedOep at buf[fixer-dsize-4] = file SRC_RAW+0xFC.
    struct.pack_into("<I", data, SRC_RAW + 0xFC, IMG + 0x1000)
    return bytes(data)


def main() -> None:
    which = sys.argv[1] if len(sys.argv) > 1 else "11"
    out = sys.argv[2] if len(sys.argv) > 2 else f"corpus/mew{which}-minimal.exe"
    blob = mew11() if which == "11" else mew10()
    with open(out, "wb") as f:
        f.write(blob)
    print(f"wrote {out} ({len(blob)} bytes)")


if __name__ == "__main__":
    main()

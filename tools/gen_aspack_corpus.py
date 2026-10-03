#!/usr/bin/env python3
"""Deterministic synthetic ASPack 2.12 corpus generator.

Builds a PE32 satisfying `XASPACK::_detect` layout row 0 ("2.12") and
carrying one literal-only compressed block, encoded with the inverse of
the upstream dynamic-Huffman decoder so the Qt oracle can verify it.

Stream construction (MSB-first, mirrors `_readstream`/`_getdec`):
- dict flag bit = 1 (skip the zero-fill branch)
- array1 = [1,1,0,...] (19 x 4-bit code lengths for dict3):
  symbols 0 and 1 get 1-bit codes; dict3 emits code-length *values*
  for array2. bus[1]=2 -> sum = 2<<23 = 0x1000000 -> valid.
- 757 getdec(3)-encoded code lengths for array2[1..758]:
  dict0 (721 sym): lengths [1,1] on symbols 64/65, else 0
  dict1 (28 sym):  lengths [1,1] on the first two, else 0
  dict2 (8 sym):   lengths [1,1] on the first two, else 0
- 8 x dict0 code '1' -> literal 0x41 ('A') x 8.

Layout offsets (layout row 2.12, all `(AEP-1)`-relative except the
push/ret marker which is `AEP`-relative):
  sig 60 E8 03 00 00 00 E9 EB @AEP, marker @AEP+0x3B9,
  oep @0x39B, wrkbuf @0x148, blocks @0x57C, compB @0x6D6,
  strMlt @0x70E.
"""
import struct
import sys

COMP_B = bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x14, 0x18, 0x1c,
    0x20, 0x28, 0x30, 0x38, 0x40, 0x50, 0x60, 0x70, 0x80, 0xa0, 0xc0, 0xe0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x02,
    0x03, 0x03, 0x04, 0x04, 0x05, 0x05, 0x06, 0x06, 0x07, 0x07, 0x08, 0x08, 0x09, 0x09, 0x0a, 0x0a,
    0x0b, 0x0b, 0x0c, 0x0c, 0x0d, 0x0d, 0x0e, 0x0e, 0x0f, 0x0f, 0x10, 0x10, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
    0x12, 0x12,
])
assert len(COMP_B) == 0x72


def make_stream():
    bits = []

    def put(v, n):
        for k in range(n - 1, -1, -1):
            bits.append((v >> k) & 1)

    put(1, 1)  # dict flag: keep zero dict (it was memset anyway)
    for v in [1, 1] + [0] * 17:
        put(v, 4)
    # array2 fill: c index -> array2[1+c]; 1s at c=64,65 (dict0 syms
    # 64/65), c=721,722 (dict1 first two), c=749,750 (dict2 first two)
    seq = [0] * 64 + [1, 1] + [0] * (721 - 66) + [1, 1] \
        + [0] * (749 - 723) + [1, 1] + [0] * (757 - 751)
    assert len(seq) == 757
    for v in seq:
        put(v, 1)
    for _ in range(8):
        put(1, 1)  # literal 'A' x8 via dict0 symbol 65
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for bit in bits[i:i + 8]:
            b = (b << 1) | bit
        out.append(b << (8 - len(bits[i:i + 8])))
    return bytes(out)


def build(path):
    align_f = 0x200
    hdr_size = (0x40 + 4 + 20 + 0xE0 + 40 + align_f - 1) // align_f * align_f
    sec_raw_ptr = hdr_size
    sec_rva = 0x1000
    sec_vsize = 0x3000

    stream = make_stream()
    block_rva = 0x2000
    stub = bytearray(0x3000)
    # AEP = section_rva + 1 so that the stub base (AEP-1) sits at the
    # section start; all `(AEP-1)`-relative offsets index `stub` directly.
    aep = sec_rva + 1
    nep = aep - 1
    base = nep - sec_rva  # == 0: stub is the section's raw content
    assert base == 0
    # signature at AEP
    stub[base + 1:base + 9] = b"\x60\xe8\x03\x00\x00\x00\xe9\xeb"
    # marker at AEP+0x3B9
    stub[base + 1 + 0x3B9:base + 1 + 0x3BF] = b"\x68\x00\x00\x00\x00\xC3"
    # oep dword @(AEP-1)+0x39B
    struct.pack_into("<I", stub, base + 0x39B, 0x1000)
    # wrkbuf mark byte @(AEP-1)+0x148
    stub[base + 0x148] = 0xAA
    # blocks table @(AEP-1)+0x57C: [rva,size]... terminating zero pair
    struct.pack_into("<II", stub, base + 0x57C, block_rva, len(stream))
    struct.pack_into("<II", stub, base + 0x57C + 8, 0, 0)
    # compB table @(AEP-1)+0x6D6
    stub[base + 0x6D6:base + 0x6D6 + 0x72] = COMP_B
    # strMlt 58 bytes @(AEP-1)+0x70E (multiplier table, zeros are fine)
    # compressed block at image rva 0x2000 (stub index 0x1000)
    stub[block_rva - sec_rva:block_rva - sec_rva + len(stream)] = stream

    pe = bytearray(sec_raw_ptr + len(stub))
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x40)
    pe[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", pe, 0x44, 0x14C)
    struct.pack_into("<H", pe, 0x46, 1)
    struct.pack_into("<H", pe, 0x54, 0xE0)
    struct.pack_into("<H", pe, 0x56, 0x010F)
    oh = 0x58
    struct.pack_into("<H", pe, oh, 0x10B)
    struct.pack_into("<I", pe, oh + 16, sec_rva + 1)  # EP = AEP
    struct.pack_into("<I", pe, oh + 28, 0x400000)
    struct.pack_into("<I", pe, oh + 32, 0x1000)
    struct.pack_into("<I", pe, oh + 36, align_f)
    struct.pack_into("<H", pe, oh + 40, 4)
    struct.pack_into("<H", pe, oh + 48, 4)
    struct.pack_into("<I", pe, oh + 56, 0x4000)  # SizeOfImage
    struct.pack_into("<I", pe, oh + 60, sec_raw_ptr)
    struct.pack_into("<H", pe, oh + 68, 2)
    struct.pack_into("<I", pe, oh + 92, 16)

    so = oh + 0xE0
    pe[so:so + 8] = b".aspack\0"
    struct.pack_into("<IIIIII", pe, so + 8, sec_vsize, sec_rva,
                     len(stub), sec_raw_ptr, 0, 0)
    struct.pack_into("<I", pe, so + 36, 0xE0000020)
    pe[sec_raw_ptr:sec_raw_ptr + len(stub)] = stub

    with open(path, "wb") as f:
        f.write(pe)
    print(f"wrote {path} ({len(stream)}-byte stream)")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "/tmp/aspack212.exe")

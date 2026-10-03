#!/usr/bin/env python3
"""Deterministic synthetic yoda's Crypter (yC 1.3) corpus generator.

Builds a PE32 whose last section is a synthetic yC stub satisfying
`XYODA::_detect`, with two layers of the 0x30-byte `_polyEmulate`
bytecode program. The fixture is meant to be fed through the upstream
Qt oracle (`tools/nfd-oracle/build/unpack-oracle`); its output is stored
as the byte-exact expectation for the Rust `unpack_yoda`.

Layout facts mirrored from upstream xyoda.cpp:
- EP RVA == last_section.VirtualAddress + 0x60, yC 1.3 signature.
- ecx = imm32@EP+0x14 - imm32@EP+0x1a must be in (0x800, 0x2000).
- `0x6c - imm32@EP+0xf + imm32@EP+0x22 == 0xC6`, marker AA E2 CC @EP+0x63.
- yC data (section-relative, bias 0): +0x93 layer-1 program (0x30),
  +0xC6 layer-1 encrypted region (ecx bytes), +0x457 layer-2 program,
  +0xA0F stored OEP dword.
- Layer 2 encrypts each original section's raw data; layer 1's region
  covers +0xC6..+0xC6+ecx and thus the layer-2 program itself is stored
  encrypted under layer 1.

Programs used: L1 = [XOR AL,0x5A] + NOPs; L2 = [XOR AL,0xA5] + NOPs.
"""
import struct
import sys


def pe16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def build(path):
    align_s, align_f = 0x1000, 0x200
    nsec = 3  # two payload sections + yC stub section

    sec0_plain = bytes((i * 7 + 3) & 0xFF for i in range(0x200))
    sec1_plain = bytes((i * 5 + 0x40) & 0xFF for i in range(0x180)) + bytes(0x80)
    sec0_raw = bytes(b ^ 0xA5 for b in sec0_plain)
    sec1_raw = bytes(b ^ 0xA5 for b in sec1_plain)

    ecx = 0x900
    yc = bytearray(0xC00)
    # yC 1.3 EP signature at stub_rva+0x60 (file offset raw+0x60).
    ep = bytearray(0x80)
    ep[0x00:0x0F] = b"\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED"
    struct.pack_into("<I", ep, 0x0F, 0)  # imm @0xf -> 0 (constraint term)
    ep[0x13] = 0xB9
    struct.pack_into("<I", ep, 0x14, ecx)  # ecx base
    struct.pack_into("<H", ep, 0x18, 0xE981)  # sub ecx,imm
    struct.pack_into("<I", ep, 0x1A, 0)  # imm @0x1a -> 0
    ep[0x1E:0x22] = b"\x8B\xD5\x81\xC2"
    struct.pack_into("<I", ep, 0x22, 0x5A)  # 0x6c-0+0x5a == 0xc6
    ep[0x26:0x33] = b"\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC"
    ep[0x63:0x66] = b"\xAA\xE2\xCC"
    yc[0x60:0xE0] = ep
    # layer-1 program: XOR AL,0x5A then NOPs.
    yc[0x93:0x95] = b"\x34\x5A"
    for i in range(0x95, 0x93 + 0x30):
        yc[i] = 0x90
    # layer-2 program stored ENCRYPTED by layer 1 (inside +0xC6..+0x9C6):
    # real L2 = [XOR AL,0xA5] + NOPs -> stored = bytes ^ 0x5A.
    l2 = bytearray([0x34, 0xA5] + [0x90] * 0x2E)
    yc[0x457:0x457 + 0x30] = bytes(b ^ 0x5A for b in l2)
    # rest of the L1-encrypted region: arbitrary ciphertext.
    for i in range(0xC6, 0xC6 + ecx):
        if 0x457 <= i < 0x457 + 0x30:
            continue
        if yc[i] == 0 and not (0x93 <= i < 0x93 + 0x30):
            yc[i] = (i * 11) & 0xFF
    struct.pack_into("<I", yc, 0xA0F, 0x1000)  # stored OEP

    hdr_size = 0x40 + 4 + 20 + 0xE0 + nsec * 40
    hdr_size = (hdr_size + align_f - 1) // align_f * align_f
    pe = bytearray(hdr_size + len(sec0_raw) + len(sec1_raw) + len(yc))

    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x40)
    pe[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", pe, 0x44, 0x14C)
    struct.pack_into("<H", pe, 0x46, nsec)
    struct.pack_into("<H", pe, 0x54, 0xE0)
    struct.pack_into("<H", pe, 0x56, 0x010F)
    oh = 0x58
    struct.pack_into("<H", pe, oh, 0x10B)
    struct.pack_into("<I", pe, oh + 16, 0x3060)  # EP = last va + 0x60
    struct.pack_into("<I", pe, oh + 28, 0x400000)  # ImageBase
    struct.pack_into("<I", pe, oh + 32, align_s)
    struct.pack_into("<I", pe, oh + 36, align_f)
    struct.pack_into("<H", pe, oh + 40, 4)
    struct.pack_into("<H", pe, oh + 48, 4)
    struct.pack_into("<I", pe, oh + 56, 0x5000)  # SizeOfImage
    struct.pack_into("<I", pe, oh + 60, hdr_size)  # SizeOfHeaders
    struct.pack_into("<H", pe, oh + 68, 2)  # subsystem GUI
    struct.pack_into("<I", pe, oh + 92, 16)  # NumberOfRvaAndSizes

    secs = [
        (b".code\0\0\0", 0x200, 0x1000, len(sec0_raw), hdr_size),
        (b".data\0\0\0", 0x200, 0x2000, len(sec1_raw), hdr_size + len(sec0_raw)),
        (b"yCstub\0\0", 0x1000, 0x3000, len(yc), hdr_size + len(sec0_raw) + len(sec1_raw)),
    ]
    so = oh + 0xE0
    for i, (nm, vs, va, rs, rp) in enumerate(secs):
        o = so + i * 40
        pe[o:o + 8] = nm
        struct.pack_into("<IIIIII", pe, o + 8, vs, va, rs, rp, 0, 0)
        struct.pack_into("<I", pe, o + 36, 0xE0000020)

    pe[hdr_size:hdr_size + len(sec0_raw)] = sec0_raw
    off = hdr_size + len(sec0_raw)
    pe[off:off + len(sec1_raw)] = sec1_raw
    off += len(sec1_raw)
    pe[off:off + len(yc)] = yc

    with open(path, "wb") as f:
        f.write(pe)
    print(f"wrote {path}")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "/tmp/yoda13.exe")

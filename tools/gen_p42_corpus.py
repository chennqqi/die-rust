#!/usr/bin/env python3
"""Generate MSDOS (MZ) fixtures for Phase 42 host-API differential testing.

Each fixture exercises a distinct aspect of the upstream XMSDOS memory map:
e_cp/e_cblp image-size formula, e_cparhdr header size, CS:IP entry point,
e_lfanew secondary headers (NE/LE/LX/PE), DOS stub, Rich signature block,
overlays, truncation, and 16-bit disassembly bytes.

Usage: tools/gen_p42_corpus.py <out_dir>
"""
import os
import struct
import sys


def mz_header(*, cblp=0, cp=0, cparhdr=4, cs=0, ip=0, lfanew=0, magic=b"MZ"):
    """Build a 0x40-byte DOS header (IMAGE_DOS_HEADEREX prefix)."""
    h = bytearray(0x40)
    h[0:2] = magic
    struct.pack_into("<H", h, 0x02, cblp)       # e_cblp
    struct.pack_into("<H", h, 0x04, cp)         # e_cp
    struct.pack_into("<H", h, 0x08, cparhdr)    # e_cparhdr
    struct.pack_into("<H", h, 0x14, ip)         # e_ip
    struct.pack_into("<H", h, 0x16, cs)         # e_cs
    struct.pack_into("<I", h, 0x3C, lfanew)     # e_lfanew
    return bytes(h)


def dos_stub(size, rich=False):
    """Build a DOS stub region of `size` bytes (normally e_lfanew - 0x40).

    When `rich` is true, embed a valid Rich signature block:
    DanS marker (XORed), three padding dwords, two (id,version,count)
    records, then the 'Rich' marker and the XOR key. Layout matches
    upstream XMSDOS::getRichSignatureRecords expectations.
    """
    stub = bytearray(size)
    text = b"This program cannot be run in DOS mode.\r\r\n$"
    stub[: min(len(text), size)] = text[:size]
    if rich:
        key = 0x12345678
        dans_off = 0x10  # relative to stub start (absolute 0x50)
        rich_off = 0x58  # 'Rich' marker (absolute 0x98) when stub >= 0x60
        # DanS + 3 padding dwords (16 bytes total), all XORed.
        struct.pack_into("<I", stub, dans_off, 0x536E6144 ^ key)
        for i in range(4, 16, 4):
            struct.pack_into("<I", stub, dans_off + i, 0 ^ key)
        # Records at dans_off+16 .. rich_off, 8 bytes each.
        records = [(0x0102, 0x1234, 5), (0x00FF, 0x5678, 3)]
        rec = dans_off + 16
        for rid, ver, cnt in records:
            struct.pack_into("<I", stub, rec, ((rid << 16) | ver) ^ key)
            struct.pack_into("<I", stub, rec + 4, cnt ^ key)
            rec += 8
        # Zero-fill remaining record slots (still XORed zeros).
        while rec < rich_off:
            struct.pack_into("<I", stub, rec, 0 ^ key)
            struct.pack_into("<I", stub, rec + 4, 0 ^ key)
            rec += 8
        stub[rich_off:rich_off + 4] = b"Rich"
        struct.pack_into("<I", stub, rich_off + 4, key)
    return bytes(stub)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/p42"
    os.makedirs(out, exist_ok=True)

    # 1. Basic MZ: header 0x40 + code 0x40 = 0x80; imageSize == fileSize.
    #    e_cblp=0x80, e_cp=1 -> imageSize = 0x200 - 0x180 = 0x80.
    #    Code layout for disasm probes (file offsets):
    #      0x40: EB 04      jmp short +4      -> target seg+6
    #      0x42: 90 90      nop nop
    #      0x48: E9 03 00   jmp rel16 +3      -> target seg+0x0E
    code = bytes([0xEB, 0x04, 0x90, 0x90, 0x8B, 0xC0, 0xCC, 0xCC,
                  0xE9, 0x03, 0x00, 0x90, 0xB8, 0x34, 0x12, 0xCB])
    code = code.ljust(0x40, b"\x90")
    data = mz_header(cblp=0x80, cp=1, cparhdr=4, cs=0x10, ip=0) + code
    assert len(data) == 0x80
    open(f"{out}/p42-basic.exe", "wb").write(data)

    # 2. Overlay MZ: header 0x40 + code 0x20 = imageSize 0x60, file 0x80.
    #    e_cblp=0x60, e_cp=1 -> 0x200 - 0x1A0 = 0x60. Overlay 0x20 at 0x60.
    code2 = bytes([0xB8, 0x34, 0x12, 0xCD, 0x21]).ljust(0x20, b"\x90")
    overlay = bytes([0xAA]) + b"BBBB" + bytes(0x20 - 5)
    data = mz_header(cblp=0x60, cp=1, cparhdr=4, cs=0, ip=0) + code2 + overlay
    assert len(data) == 0x80
    open(f"{out}/p42-overlay.exe", "wb").write(data)

    # 3-5. NE / LE / LX: e_lfanew=0x80, stub 0x40..0x80, sig at 0x80,
    #      body 0x40 -> file 0xC2. e_cblp=0xC2, e_cp=1 -> imageSize 0xC2.
    for tag, sig in (("ne", b"NE"), ("le", b"LE"), ("lx", b"LX")):
        stub = dos_stub(0x40)
        body = bytes(0x40)
        data = mz_header(cblp=0xC2, cp=1, cparhdr=4, cs=0, ip=0x20,
                         lfanew=0x80) + stub + sig + body
        assert len(data) == 0xC2
        open(f"{out}/p42-{tag}.exe", "wb").write(data)

    # 6-7. PE fixtures: e_lfanew=0xC0, stub 0x40..0xC0, then a minimal
    #      but structurally complete PE32 (COFF + 224-byte optional
    #      header, magic 0x10B, all other fields zero — equivalent to
    #      upstream's OOB-zero reads on the earlier stub).
    pe_tail = (b"PE\x00\x00"
               + struct.pack("<HHIIIHH", 0x014C, 0, 0, 0, 0, 224, 0x0102)
               + struct.pack("<H", 0x010B).ljust(224, b"\x00"))
    fsize = 0xC0 + len(pe_tail)

    # 6. PE with embedded Rich block in the DOS stub.
    stub = dos_stub(0x80, rich=True)
    data = mz_header(cblp=fsize & 0x1FF, cp=(fsize + 0x1FF) // 0x200,
                     cparhdr=4, cs=0, ip=0, lfanew=0xC0) + stub + pe_tail
    assert len(data) == fsize
    open(f"{out}/p42-pe-rich.exe", "wb").write(data)

    # 7. PE without Rich: same layout, plain stub.
    stub = dos_stub(0x80)
    data = mz_header(cblp=fsize & 0x1FF, cp=(fsize + 0x1FF) // 0x200,
                     cparhdr=4, cs=0, ip=0, lfanew=0xC0) + stub + pe_tail
    assert len(data) == fsize
    open(f"{out}/p42-pe.exe", "wb").write(data)

    # 8. Tiny MZ: only 0x20 bytes; e_lfanew field out of bounds.
    data = mz_header(cblp=0, cp=0, cparhdr=2, cs=0, ip=0)[:0x20]
    open(f"{out}/p42-tiny.exe", "wb").write(data)

    # 9. Bad e_lfanew: points past EOF.
    data = mz_header(cblp=0x80, cp=1, cparhdr=4, cs=0, ip=0,
                     lfanew=0x1000) + code
    open(f"{out}/p42-bad-lfanew.exe", "wb").write(data)

    # 10. Segment wrap: e_cs=0xFFFF, e_ip=0xFFFF -> EP wraps at 0x100000.
    data = mz_header(cblp=0x80, cp=1, cparhdr=4, cs=0xFFFF, ip=0xFFFF) + code
    open(f"{out}/p42-epwrap.exe", "wb").write(data)

    # 11. Oversized e_cp: claims 0xFFFF pages -> imageSize clamps to file.
    data = mz_header(cblp=0, cp=0xFFFF, cparhdr=4, cs=0x10, ip=0) + code
    open(f"{out}/p42-huge.exe", "wb").write(data)

    # 12. ZM magic variant (0x4D5A).
    data = mz_header(cblp=0x80, cp=1, cparhdr=4, cs=0x10, ip=0,
                     magic=b"ZM") + code
    open(f"{out}/p42-zm.exe", "wb").write(data)

    print("generated 12 fixtures in", out)


if __name__ == "__main__":
    main()

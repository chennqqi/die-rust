#!/usr/bin/env python3
"""Deterministic synthetic NsPack corpus generator.

Builds PE32 files satisfying `XNSPACK::_detect` (1.4/3.x path) whose
`nsp0` stream is produced by the exact inverse of the upstream
LZMA-variant range decoder (`_decompress`), so the Qt oracle can verify
round-trip output.

Mode byte c=0 -> nFirstByte=0, nAllocsz=0, nTre=0, table = 0xA36 entries.
With those parameters the literal path degenerates to:
    get_bit(table[0]) == 0   (literal flag, damian/backsize contexts 0)
    _get100(table + 0x736)   (plain 8-level literal tree)
so a literal-only stream needs only those two primitives encoded.

Range encoder mirrors `_getBit`/`_getBitmap`:
    range starts 0xffffffff, renorm when range < 0x1000000 (one byte
    per call), low kept mod 2^32 with the classic cache+carry flush
    (identical to the LZMA SDK RangeEncoder). The decoder's 5-byte init
    drops stream byte 0, matching cacheSize=1 startup.

Two fixtures:
- nspack-minimal.exe : stub header fields do NOT match the loader RVA,
  so `_readCallJmpControl`/`_reconstructImports` fail closed and the
  naive whole-blob E8/E9 inverse runs (blob contains one fake site).
- nspack-gated.exe   : stub header +0x10 == loader RVA (3.x layout) with
  count=2, marker=0xAA, gate=1 -> marker-gated deFilter, plus a working
  two-DLL descriptor stream so `_reconstructImports` emits .idata.
"""
import struct
import sys


class RangeEnc:
    """Inverse of XNSPACK::_getBit (cache/carry range encoder)."""

    def __init__(self):
        self.table = [0x400] * 0xA36
        self.low = 0  # u64 accumulator; only low 32 bits + carry matter
        self.rng = 0xFFFFFFFF
        self.cache = 0
        self.cache_size = 1
        self.out = bytearray()

    def shift_low(self):
        if (self.low & 0xFFFFFFFF) < 0xFF000000 or (self.low >> 32) != 0:
            temp = self.cache
            carry = (self.low >> 32) & 0xFF
            while True:
                self.out.append((temp + carry) & 0xFF)
                temp = 0xFF
                self.cache_size -= 1
                if self.cache_size == 0:
                    break
            self.cache = (self.low >> 24) & 0xFF
        self.cache_size += 1
        self.low = ((self.low & 0xFFFFFFFF) << 8) & 0xFFFFFFFF

    def enc_bit(self, idx, bit):
        pv = self.table[idx]
        nval = pv * (self.rng >> 11)
        if bit == 0:
            self.rng = nval
            self.table[idx] = pv + ((0x800 - pv) >> 5)
        else:
            self.low += nval
            self.rng -= nval
            self.table[idx] = pv - (pv >> 5)
        if self.rng < 0x1000000:
            self.shift_low()
            self.rng <<= 8

    def enc100(self, base, byte):
        count = 1
        for i in range(8):
            b = (byte >> (7 - i)) & 1
            self.enc_bit(base + count, b)
            count = (count << 1) | b

    def flush(self):
        for _ in range(5):
            self.shift_low()
        self.out.append(self.cache)


def encode_literals(blob):
    """Literal-only stream: flag bit0 @table[0], literal @_get100(0x736)."""
    e = RangeEnc()
    for b in blob:
        e.enc_bit(0, 0)
        e.enc100(0x736, b)
    e.flush()
    return bytes(e.out)


def find_sos(data, dsize):
    """Python twin of `_findStartOfStuff`; returns last valid sos."""
    needle = struct.pack("<I", dsize)
    best = -1
    pos = 0
    while True:
        hit = data.find(needle, pos)
        if hit < 0:
            return best
        pos = hit + 1
        sos = hit - 9
        if sos < 0 or sos <= best:
            continue
        h = data[sos:sos + 14]
        if len(h) < 14:
            continue
        c = h[0]
        if c >= 0xE1:
            continue
        if c >= 0x2D:
            c -= 0x2D * (c // 0x2D)
        allocsz = 0
        if c >= 9:
            allocsz = c // 9
            c -= 9 * allocsz
        if (allocsz + c) & 0xFF > 12:
            continue
        ssize = struct.unpack_from("<I", h, 5)[0]
        if ssize <= 13 or sos + ssize > len(data):
            continue
        best = sos


def build_pe(sec_name, ep_rva, image_base, blob_rva, blob_vsize, raw,
             imp_dir=(0, 0)):
    """Minimal PE32 skeleton: headers + one section."""
    align_f = 0x200
    nsec = 1
    hdr_size = (0x40 + 4 + 20 + 0xE0 + 0x28 * nsec + align_f - 1) \
        // align_f * align_f
    raw_ptr = hdr_size
    raw_size = (len(raw) + align_f - 1) // align_f * align_f
    pe = bytearray(raw_ptr + raw_size)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x40)
    pe[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", pe, 0x44, 0x14C)
    struct.pack_into("<H", pe, 0x46, nsec)
    struct.pack_into("<H", pe, 0x54, 0xE0)
    struct.pack_into("<H", pe, 0x56, 0x010F)
    oh = 0x58
    struct.pack_into("<H", pe, oh, 0x10B)
    struct.pack_into("<I", pe, oh + 16, ep_rva)
    struct.pack_into("<I", pe, oh + 28, image_base)
    struct.pack_into("<I", pe, oh + 32, 0x1000)
    struct.pack_into("<I", pe, oh + 36, align_f)
    struct.pack_into("<H", pe, oh + 40, 4)
    struct.pack_into("<H", pe, oh + 48, 4)
    struct.pack_into("<I", pe, oh + 56, 0x8000)  # SizeOfImage
    struct.pack_into("<I", pe, oh + 60, raw_ptr)
    struct.pack_into("<H", pe, oh + 68, 2)
    struct.pack_into("<I", pe, oh + 92, 16)
    struct.pack_into("<II", pe, oh + 96 + 8, imp_dir[0], imp_dir[1])
    so = oh + 0xE0
    pe[so:so + 8] = sec_name
    struct.pack_into("<IIIIII", pe, so + 8, blob_vsize, blob_rva,
                     len(raw), raw_ptr, 0, 0)
    struct.pack_into("<I", pe, so + 36, 0xE00000E0)
    pe[raw_ptr:raw_ptr + len(raw)] = raw
    return pe


def make_blob_minimal(dsize):
    """'A' payload plus one fake E8 site for the naive deFilter."""
    blob = bytearray(b"A" * dsize)
    blob[0x40:0x45] = b"\xE8\x78\x56\x34\x12"
    blob[0x60:0x65] = b"\xE9\x01\x02\x03\x04"
    return bytes(blob)


def make_blob_gated(dsize, desc_off):
    """Blob for the gated fixture: two-DLL descriptor stream at
    `desc_off`, IAT slots at 0x800/0x810, marker-gated E8 sites."""
    blob = bytearray(b"B" * dsize)
    # two gated E8 sites: operand byte0 == marker 0xAA
    blob[0x20:0x25] = b"\xE8\xAA\x01\x02\x03"
    blob[0x30:0x35] = b"\xE8\xAA\x10\x20\x30"
    # non-matching opcode (operand byte0 != marker) -> skipped
    blob[0x40:0x45] = b"\xE8\xBB\x05\x06\x07"

    # descriptor 1: KERNEL32, funcs "ExitProcess"(11), "GetVersion"(10)
    d = desc_off
    names1 = b"ExitProcess" + b"GetVersion"  # name_advance block
    struct.pack_into("<IIII", blob, d, 16 + 2 + 1, 0, 0x1800, 19)
    blob[d + 16:d + 18] = bytes([11, 10])
    blob[d + 18] = 0
    blob[d + 19:d + 19 + len(names1)] = names1

    # descriptor 2: USER32, funcs "MessageBoxA"(11), ordinal 0x78 (5B)
    d2 = d + 19 + len(names1)
    names2 = b"MessageBoxA"
    struct.pack_into("<IIII", blob, d2, 16 + 2 + 1, 13, 0x1810, 19)
    blob[d2 + 16:d2 + 18] = bytes([11, 5])
    blob[d2 + 18] = 0
    blob[d2 + 19:d2 + 19 + len(names2)] = names2
    struct.pack_into("<I", blob, d2 + 19 + len(names2), 0x78)
    # 0xFF marker precedes the ordinal
    blob[d2 + 19 + len(names2)] = 0xFF
    # terminator descriptor (all-zero marker/nameOff/iat)
    # IAT slots at blob[0x800..0x808] and blob[0x810..0x818] stay zero;
    # _reconstructImports fills them with the synthesized entries.
    return bytes(blob)


def assemble(path, blob, gated):
    """Emit one fixture; `gated` selects the 3.x stub-header layout with
    call/jmp control + import descriptor anchor."""
    image_base = 0x400000
    sec_rva = 0x1000
    dsize = len(blob)

    stream = encode_literals(blob)
    sos_size_field = 0xD + len(stream)

    # section raw: loader prologue @0 (EP = sec_rva), stub params,
    # optional import dir + name pool, sos header + stream, tail pad.
    raw = bytearray(0x1400)
    # 1.4/3.x loader prologue; +8 must NOT be `B8 07 00 00 00` (2.x).
    raw[0:8] = b"\x9C\x60\xE8\x00\x00\x00\x00\x5D"
    desc_rva = 0x1400  # blob-relative base + 0x400

    imp_dir = (0, 0)
    if gated:
        # 3.x stub header: +0x10 == loader RVA (0x1000); +0x08 = desc RVA
        struct.pack_into("<I", raw, 0x08, desc_rva)
        struct.pack_into("<I", raw, 0x10, sec_rva)
        # call/jmp control: count@0x48, marker@0x50, gate@0x51
        struct.pack_into("<I", raw, 0x48, 2)
        raw[0x50] = 0xAA
        raw[0x51] = 1
        # import dir @sec0+0xC0: one descriptor; Name -> "KERNEL32.DLL"
        imp_rva = sec_rva + 0xC0
        struct.pack_into("<IIIII", raw, 0xC0, 0, 0, 0, imp_rva + 0x14, 0)
        # zero terminator descriptor
        pool = b"KERNEL32.DLL\x00USER32.DLL\x00"
        raw[0xD4:0xD4 + len(pool)] = pool
        imp_dir = (imp_rva, 40)
    else:
        # fields at +8/+0x10 must not equal the loader RVA and must not
        # look like the 2.x signature either.
        struct.pack_into("<I", raw, 0x08, 0xDEADBEEF)
        struct.pack_into("<I", raw, 0x10, 0xDEADBEEF)

    sos = 0x600
    raw[sos] = 0x00  # mode byte c=0
    struct.pack_into("<I", raw, sos + 5, sos_size_field)
    struct.pack_into("<I", raw, sos + 9, dsize)
    raw[sos + 0xD:sos + 0xD + len(stream)] = stream
    # stream must end <= file_end - 13 (decoder window guard)
    assert sos + 0xD + len(stream) <= len(raw) - 13

    pe = build_pe(b".nsp0\x00\x00\x00", sec_rva, image_base,
                  sec_rva, dsize, bytes(raw), imp_dir)

    got = find_sos(pe, dsize)
    expected_sos = (0x40 + 4 + 20 + 0xE0 + 0x28 + 0x200 - 1) \
        // 0x200 * 0x200 + sos
    assert got == expected_sos, f"sos scan picked {got:#x}, want {expected_sos:#x}"

    with open(path, "wb") as f:
        f.write(pe)
    print(f"wrote {path} (dsize={dsize}, stream={len(stream)}B, sos=0x{sos:x})")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus"
    blob = make_blob_minimal(0x410)
    assemble(f"{out}/nspack-minimal.exe", blob, gated=False)
    desc_off = 0x400
    blob2 = make_blob_gated(0x900, desc_off)
    assemble(f"{out}/nspack-gated.exe", blob2, gated=True)


if __name__ == "__main__":
    main()

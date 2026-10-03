#!/usr/bin/env python3
"""Deterministic AutoIt (v2 / EA05 / EA06) container fixtures.

Mirrors the upstream XAUTOIT wire format so the Qt oracle can verify the
Rust port record-for-record:

- v2: 16-byte signature + subtype + password block + FILE records +
  trailing backlink DWORD. LCG XOR stream; optional "JB01" literal-only
  bitstream.
- EA05: "AU3!EA05" + 16 header bytes (m4sum) + FILE records. MT19937
  variant XOR stream; optional "EA05"-header bitstream.
- EA06: "AU3!EA06" + 16 skipped bytes + FILE records with UTF-16LE
  metadata. LAME-generator XOR stream; optional "EA06"-header bitstream.

Each fixture carries two records: one stored (comp=0) and one
literal-only compressed (comp=1), which exercises every decryptor plus
the custom inflate without needing an LZ encoder.
"""

import os
import struct
import sys

OUT = os.path.join(os.path.dirname(__file__), "..", "corpus")


def rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


# --------------------------------------------------------------------------
# stream ciphers (XOR-symmetric: encrypt == decrypt)
# --------------------------------------------------------------------------

def v2_crypt(buf, seed):
    out = bytearray(buf)
    for i in range(len(out)):
        seed = (seed * 214013 + 2531011) & 0xFFFFFFFF
        out[i] ^= (seed >> 16) & 0xFF
    return bytes(out)


def mt_crypt(buf, seed):
    mt = [0] * 624
    mt[0] = seed & 0xFFFFFFFF
    for i in range(1, 624):
        mt[i] = (i + 0x6C078965 * ((mt[i - 1] >> 30) ^ mt[i - 1])) & 0xFFFFFFFF
    items = 1
    nxt = 0
    out = bytearray(buf)
    for k in range(len(out)):
        items -= 1
        if items == 0:
            items = 624
            nxt = 0
            for i in range(227):
                mt[i] = ((((mt[i] ^ mt[i + 1]) & 0x7FFFFFFE) ^ mt[i]) >> 1) \
                    ^ ((-(mt[i + 1] & 1)) & 0x9908B0DF) ^ mt[i + 397]
            for i in range(227, 623):
                mt[i] = ((((mt[i] ^ mt[i + 1]) & 0x7FFFFFFE) ^ mt[i]) >> 1) \
                    ^ ((-(mt[i + 1] & 1)) & 0x9908B0DF) ^ mt[i - 227]
            mt[623] = ((((mt[623] ^ mt[0]) & 0x7FFFFFFE) ^ mt[623]) >> 1) \
                ^ ((-(mt[0] & 1)) & 0x9908B0DF) ^ mt[396]
        r = mt[nxt]
        nxt += 1
        r ^= r >> 11
        r = (r ^ ((r & 0xFF3A58AD) << 7)) & 0xFFFFFFFF
        r = (r ^ ((r & 0xFFFFDF8C) << 15)) & 0xFFFFFFFF
        r ^= r >> 18
        out[k] ^= (r >> 1) & 0xFF
    return bytes(out)


class Lame:
    """EA06 LAME PRNG (rotl double-mantissa generator)."""

    def __init__(self, seed):
        self.i0 = 0
        self.i1 = 10
        self.v = []
        s = seed & 0xFFFFFFFF
        for _ in range(17):
            s = (s * 0x53A9B4FB) & 0xFFFFFFFF
            s = (1 - s) & 0xFFFFFFFF
            self.v.append(s)
        for _ in range(9):
            self.push()

    def push(self):
        r = (rotl32(self.v[self.i0], 9) + rotl32(self.v[self.i1], 13)) & 0xFFFFFFFF
        self.v[self.i0] = r
        self.i0 = 16 if self.i0 == 0 else self.i0 - 1
        self.i1 = 16 if self.i1 == 0 else self.i1 - 1
        bits = ((0x3FF00000 | (r >> 12)) << 32) | (r << 20)
        return struct.unpack("<d", struct.pack("<Q", bits))[0] - 1.0

    def next(self):
        self.push()
        v = int(self.push() * 256.0)
        return v if v < 256 else 0xFF


def lame_crypt(buf, seed):
    st = Lame(seed & 0xFFFF)
    out = bytearray(buf)
    for i in range(len(out)):
        out[i] ^= st.next()
    return bytes(out)


# --------------------------------------------------------------------------
# MSB-first bit writer (inverse of AI_BITREADER / aiGetBits)
# --------------------------------------------------------------------------

class BitWriter:
    def __init__(self):
        self.acc = 0
        self.nbits = 0
        self.out = bytearray()

    def bits(self, val, cnt):
        for i in range(cnt - 1, -1, -1):
            self.acc = (self.acc << 1) | ((val >> i) & 1)
            self.nbits += 1
            if self.nbits == 16:
                self.out += bytes([(self.acc >> 8) & 0xFF, self.acc & 0xFF])
                self.acc = 0
                self.nbits = 0

    def flush(self):
        if self.nbits:
            self.acc <<= 16 - self.nbits
            self.out += bytes([(self.acc >> 8) & 0xFF, self.acc & 0xFF])
            self.acc = 0
            self.nbits = 0
        return bytes(self.out)


def literal_stream(payload, ea06):
    """_inflate-compatible stream: flag bit + 8-bit literal per byte.

    EA05 reads flag 0 as "literal"; EA06 inverts the flag so 1 = literal.
    """
    w = BitWriter()
    for b in payload:
        w.bits(1 if ea06 else 0, 1)
        w.bits(b, 8)
    return w.flush()


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

V2_SIG = bytes([
    0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9,
    0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48, 0x7D,
])


def gen_v2():
    """AutoIt v2 container: stored + JB01-compressed records."""
    data_seed = 0x22AF  # empty password -> sum 0

    payload_a = b"compiled autoit v2 script body 0123456789" + bytes(64)
    payload_b = b"\xde\xad\xbe\xef" * 8

    records = bytearray()
    # record A: stored
    records += v2_crypt(b"FILE", 0x16FA)
    src = b"AUTOIT SCRIPT"
    records += struct.pack("<I", len(src) ^ 0x29BC)
    records += v2_crypt(src, 0xA25E + len(src))
    name = b"build.bin"
    records += struct.pack("<I", len(name) ^ 0x29AC)
    records += v2_crypt(name, 0xF25E + len(name))
    records += bytes([0])
    records += struct.pack("<I", len(payload_a) ^ 0x45AA)
    records += struct.pack("<I", len(payload_a) ^ 0x45AA)
    records += v2_crypt(payload_a, data_seed)

    # record B: JB01 literal-only compressed
    comp = b"JB01" + struct.pack(">I", len(payload_b)) + literal_stream(payload_b, False)
    records += v2_crypt(b"FILE", 0x16FA)
    src_b = b"res\\data.dat"
    records += struct.pack("<I", len(src_b) ^ 0x29BC)
    records += v2_crypt(src_b, 0xA25E + len(src_b))
    name_b = b""
    records += struct.pack("<I", len(name_b) ^ 0x29AC)
    records += bytes([1])
    records += struct.pack("<I", len(comp) ^ 0x45AA)
    records += struct.pack("<I", len(payload_b) ^ 0x45AA)
    records += v2_crypt(comp, data_seed)

    # container = signature + subtype + pwsize + records; backlink appended
    head = V2_SIG + bytes([1]) + struct.pack("<I", 0 ^ 0xFAC1)
    body = head + bytes(records)
    trailer = struct.pack("<I", 0)  # backlink -> offset 0 of container
    return body + trailer


def gen_ea05():
    """EA05 container: stored + 'EA05'-compressed records."""
    payload_a = b"<<<EA05 script record payload>>>" + bytes(range(48))
    payload_b = b"\x01\x02\x03\x04" * 16

    header16 = bytes(16)  # m4sum = 0
    m4sum = 0

    records = bytearray()
    # record A: stored
    records += struct.pack("<I", 0xCEB06DFF)
    magic = b"<<<EA05 MAGIC>>>"
    records += struct.pack("<I", len(magic) ^ 0x29BC) + magic
    name = b"script.a3x"
    records += struct.pack("<I", len(name) ^ 0x29AC)
    records += mt_crypt(name, len(name) + 0xF25E)
    records += bytes([0])
    records += struct.pack("<I", len(payload_a) ^ 0x45AA)
    records += bytes(8 + 16)
    records += mt_crypt(payload_a, 0x22AF + m4sum)

    # record B: compressed
    comp = b"EA05" + struct.pack(">I", len(payload_b)) + literal_stream(payload_b, False)
    records += struct.pack("<I", 0xCEB06DFF)
    records += struct.pack("<I", len(magic) ^ 0x29BC) + magic
    name_b = b"res.bin"
    records += struct.pack("<I", len(name_b) ^ 0x29AC)
    records += mt_crypt(name_b, len(name_b) + 0xF25E)
    records += bytes([1])
    records += struct.pack("<I", len(comp) ^ 0x45AA)
    records += bytes(8 + 16)
    records += mt_crypt(comp, 0x22AF + m4sum)

    return b"AU3!EA05" + header16 + bytes(records)


def gen_ea06():
    """EA06 container: stored + 'EA06'-compressed records (UTF-16 meta)."""
    payload_a = b"<<<EA06 script record payload>>>" + bytes(range(40))
    payload_b = b"\xAA\x55" * 32

    def enc_u16(text, seed_base):
        raw = text.encode("utf-16-le")
        return lame_crypt(raw, (len(text) + seed_base) & 0xFFFF)

    records = bytearray()
    # record A: stored, script magic
    magic_text = ">>>AUTOIT SCRIPT<<<"
    name_text = "build.a3x"
    records += struct.pack("<I", 0x52CA436B)
    records += struct.pack("<I", len(magic_text) ^ 0xADBC)
    records += enc_u16(magic_text, 0xB33F)
    records += struct.pack("<I", len(name_text) ^ 0xF820)
    records += enc_u16(name_text, 0xF479)
    records += bytes([0])
    records += struct.pack("<I", len(payload_a) ^ 0x87BC)
    records += bytes(8 + 16)
    records += lame_crypt(payload_a, 0x2477)

    # record B: compressed, file magic
    magic_b = "dir\\res.dat"
    name_b = "res.dat"
    comp = b"EA06" + struct.pack(">I", len(payload_b)) + literal_stream(payload_b, True)
    records += struct.pack("<I", 0x52CA436B)
    records += struct.pack("<I", len(magic_b) ^ 0xADBC)
    records += enc_u16(magic_b, 0xB33F)
    records += struct.pack("<I", len(name_b) ^ 0xF820)
    records += enc_u16(name_b, 0xF479)
    records += bytes([1])
    records += struct.pack("<I", len(comp) ^ 0x87BC)
    records += bytes(8 + 16)
    records += lame_crypt(comp, 0x2477)

    return b"AU3!EA06" + bytes(16) + bytes(records)


def main():
    os.makedirs(OUT, exist_ok=True)
    fixtures = {
        "autoit-v2.bin": gen_v2(),
        "autoit-ea05.bin": gen_ea05(),
        "autoit-ea06.bin": gen_ea06(),
    }
    for name, data in fixtures.items():
        path = os.path.join(OUT, name)
        with open(path, "wb") as f:
            f.write(data)
        print(f"wrote {path} ({len(data)} bytes)")


if __name__ == "__main__":
    sys.exit(main())

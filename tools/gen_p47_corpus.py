#!/usr/bin/env python3
"""Phase 47 corpus — RNC old-variant and encrypted-stream fixtures.

Produced streams are verified against the pinned upstream oracle
(`tools/nfd-oracle`) before being committed:

  rnc1-old.rnc1   RNC1 old stream: 12-byte header, backward bit stream
                  (anchor byte 0x80), literals + one back-reference.
  rnc2-old.rnc2   RNC2 old stream: leading-consumed config byte at the
                  stream tail (dist_bits=12, len_bits=10) + anchor,
                  literals only.
  rnc1-enc-known.rnc1
                  RNC1 new stream, locked flag: single literal run XORed
                  with the low byte of known key 0x04d2 -> KNOWN_KEYS path.
  rnc1-enc-unique.rnc1
                  RNC1 new stream, locked flag: 9 literal runs interleaved
                  with distance-1 matches, run indexes 0..8 constrain all
                  16 key bits -> unique-key GF(2) recovery path.
  rnc1-enc-badkey.rnc1
                  Single-run locked stream with a non-known key: the key
                  is underdetermined -> output stays encrypted -> CRC
                  verify fails (negative parity, unpacked:false).

Bit-level writers mirror the Rust decoder (`crates/diec-nfd/src/ancient.rs`,
ports of `RNCDecompressOld`/`RNC1DecompressNew`): the readers share one
stream cursor between the bit buffer and raw `byte()` reads, so literal
bytes interleave with partially-consumed bit words — the writers allocate
positions in exactly the reader's consumption order.
"""

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"


def crc16(data: bytes, acc: int = 0) -> int:
    """Reflected CRC16 (poly 0xA001), matching upstream `CRC16`."""
    for b in data:
        a = acc ^ b
        for _ in range(8):
            a = (a >> 1) ^ (0xA001 if a & 1 else 0)
        acc = a & 0xFFFF
    return acc


def ror16(key: int, n: int) -> int:
    n &= 15
    return ((key >> n) | (key << (16 - n))) & 0xFFFF


# ---------------------------------------------------------------------
# Old variants — backward stream (`In::bwd` + MSB bit reader)
# ---------------------------------------------------------------------


class BwdWriter:
    """Backward-stream writer mirroring `In::bwd` + `MSBBitReader`.

    Positions are allocated in consumption order: a bit byte is reserved
    on the first `put_bits` after exhaustion and filled MSB-first;
    `put_byte` takes the next position while the partially-filled bit
    byte keeps its remaining slots — matching the decoder's shared
    cursor + buffered bits.
    """

    def __init__(self) -> None:
        self.pos: dict[int, int] = {}
        self.cursor = -1  # next position to allocate (ascending = consumed earlier)
        self.bit_fill = 0  # filled slots of the current bit byte (0..8)

    def put_bits(self, value: int, nbits: int) -> None:
        for k in range(nbits - 1, -1, -1):
            if self.bit_fill == 0:
                self.cursor += 1
                self.pos[self.cursor] = 0
            bit = (value >> k) & 1
            self.pos[self.cursor] |= bit << (7 - self.bit_fill)
            self.bit_fill = (self.bit_fill + 1) % 8

    def put_byte(self, b: int) -> None:
        self.cursor += 1
        self.pos[self.cursor] = b

    def anchor(self) -> None:
        """Emit the anchor byte 0x80: bit7 set, no data slots — the first
        `put_bits` reserves a fresh byte below it, matching
        `bits_reset(0x80 >> 8, 0)` leaving `blen == 0`."""
        self.cursor += 1
        self.pos[self.cursor] = 0x80

    def finish(self, tail: bytes = b"") -> bytes:
        """Serialize to file order: positions ascending = file bytes
        descending. `tail` (the RNC2 config byte) sits at the file end
        so it is consumed first."""
        out = bytearray(self.cursor + 1)
        for p, b in self.pos.items():
            out[p] = b
        return bytes(reversed(out)) + tail


# ---------------------------------------------------------------------
# New variant — forward stream (`In::fwd` + LSB 16-bit bit reader)
# ---------------------------------------------------------------------


class FwdWriter:
    """Forward-stream writer mirroring `In::fwd` + `LSBBitReader` with
    16-bit little-endian refills.

    Bit slots live in a queue of (position, bit_index) taken from the
    buffered word; the reader refills a fresh 16-bit LE word only when
    `blen == 0` (`bits()`'s `if self.blen == 0`), so the writer refills
    lazily on an empty queue and never holds more than one word.
    `put_byte` allocates the next position past every buffered word,
    mirroring `byte()` reading `d[cur]` while buffered bits persist.
    """

    def __init__(self) -> None:
        self.pos: dict[int, int] = {}
        self.cursor = 0
        self.slots: list[tuple[int, int]] = []  # pending (pos, bit)

    def _refill(self) -> None:
        p = self.cursor
        self.cursor += 2
        self.pos[p] = 0
        self.pos[p + 1] = 0
        for i in range(8):
            self.slots.append((p, i))
        for i in range(8):
            self.slots.append((p + 1, i))

    def _emit(self, bit: int) -> None:
        if not self.slots:
            self._refill()
        p, bi = self.slots.pop(0)
        self.pos[p] |= (bit & 1) << bi

    def put(self, value: int, nbits: int) -> None:
        """Emit `nbits` LSB-first — the reader's consumption order."""
        for i in range(nbits):
            self._emit((value >> i) & 1)

    def put_code(self, code: int, nbits: int) -> None:
        """Emit a Huffman code consumed bit-by-bit MSB-first."""
        for k in range(nbits - 1, -1, -1):
            self._emit((code >> k) & 1)

    def put_byte(self, b: int) -> None:
        self.pos[self.cursor] = b
        self.cursor += 1

    def finish(self) -> bytes:
        out = bytearray(self.cursor)
        for p, b in self.pos.items():
            out[p] = b
        return bytes(out)


# ---------------------------------------------------------------------
# Old-variant VLC code tables (mirror `lit_vlc1`/`lit_vlc2`, `len_huff`/
# `len_vlc`, `dist_huff`/`dist_vlc`)
# ---------------------------------------------------------------------


def rnc1_lit_vlc(n: int) -> tuple[int, int]:
    """lit_vlc1 cascade code for n literals (code + length, MSB-first)."""
    if n == 0:
        return 0b0, 1
    if n == 1:
        return 0b10, 2
    if 2 <= n <= 4:
        return 0b1100 | (n - 2), 4
    if 5 <= n <= 8:
        return (0b1111 << 2) | (n - 5), 6
    if 9 <= n <= 14:
        return (0b111111 << 3) | (n - 8), 9
    if 15 <= n <= 1030:
        return (0b111111111 << 10) | (n - 15), 19
    raise ValueError(n)


def rnc2_lit_vlc(n: int) -> tuple[int, int]:
    """lit_vlc2 cascade code (code + length, MSB-first)."""
    if n == 0:
        return 0b0, 1
    if n == 1:
        return 0b10, 2
    if n == 2:
        return 0b110, 3
    if 3 <= n <= 5:
        return (0b111 << 2) | (n - 3), 5
    if 6 <= n <= 13:
        return (0b11111 << 3) | (n - 6), 8
    if 14 <= n <= 29:
        return (0b11111111 << 4) | (n - 14), 12
    raise ValueError(n)


def rnc_len_code(count: int) -> list[tuple[int, int]]:
    """len_huff + len_vlc bits for a match of `count` bytes (count >= 2)."""
    base_val = count - 2
    if base_val <= 1:
        base, extra, extra_len = base_val, 0, 0
    elif base_val <= 3:
        base, extra, extra_len = 2, base_val - 2, 1
    elif base_val <= 7:
        base, extra, extra_len = 3, base_val - 4, 2
    else:
        base, extra, extra_len = 4, base_val - 8, 10
    huff = {0: (0b0, 1), 1: (0b10, 2), 2: (0b110, 3), 3: (0b1110, 4), 4: (0b1111, 4)}[base]
    out = [huff]
    if extra_len:
        out.append((extra, extra_len))
    return out


def rnc_dist_code(distance: int, count: int) -> list[tuple[int, int]]:
    """dist encoding: count==2 -> flag + 6/9 bits; else dist_huff+dist_vlc."""
    if count == 2:
        if distance < 64:
            return [(0, 1), (distance, 6)]
        return [(1, 1), (distance - 64, 9)]
    if distance < 32:
        base, extra, extra_len = 0, distance, 5
    elif distance < 288:
        base, extra, extra_len = 1, distance - 32, 8
    else:
        base, extra, extra_len = 2, distance - 288, 12
    huff = {1: (0b0, 1), 0: (0b10, 2), 2: (0b11, 2)}[base]
    return [huff, (extra, extra_len)]


def rnc1_header(raw: int, packed: int) -> bytes:
    return b"RNC\x01" + struct.pack(">I", raw) + struct.pack(">I", packed)


def rnc2_header(raw: int, packed: int) -> bytes:
    return b"RNC\x02" + struct.pack(">I", raw) + struct.pack(">I", packed)


def gen_rnc1_old() -> tuple[bytes, bytes]:
    """'ABAB' via 2 literals + one match (decoded distance 1, count 2 ->
    copy distance 2). Exercises the backward bit stream, lit_vlc cascade
    and BOut::copy."""
    plain = b"ABAB"
    w = BwdWriter()
    w.anchor()
    code, ln = rnc1_lit_vlc(2)
    w.put_bits(code, ln)
    # BOut writes downward: first literal lands at the output end.
    w.put_byte(ord("B"))
    w.put_byte(ord("A"))
    for code, ln in rnc_len_code(2):
        w.put_bits(code, ln)
    for code, ln in rnc_dist_code(1, 2):
        w.put_bits(code, ln)
    stream = w.finish()
    return rnc1_header(len(plain), len(stream)) + stream, plain


def gen_rnc2_old() -> tuple[bytes, bytes]:
    """'WXYZ' literals only. The config byte 0x9B sits at the stream tail
    (consumed first): tmp=0x9C -> dist_bits=12, len_bits=10."""
    plain = b"WXYZ"
    w = BwdWriter()
    w.anchor()
    code, ln = rnc2_lit_vlc(4)
    w.put_bits(code, ln)
    for b in reversed(plain):
        w.put_byte(b)
    stream = w.finish(tail=bytes([0x9B]))
    return rnc2_header(len(plain), len(stream)) + stream, plain


# ---------------------------------------------------------------------
# New variant — locked (encrypted) streams
# ---------------------------------------------------------------------


def rnc1_new_header(raw: bytes, packed: bytes) -> bytes:
    return (
        b"RNC\x01"
        + struct.pack(">I", len(raw))
        + struct.pack(">I", len(packed))
        + struct.pack(">H", crc16(raw))
        + struct.pack(">H", crc16(packed))
        + b"\x00\x01"
    )


def gen_rnc1_enc_known() -> tuple[bytes, bytes]:
    """Single literal run XORed with key&0xff of known key 0x04d2."""
    key = 0x04D2
    plain = b"ABCD"
    w = FwdWriter()
    w.put(2, 2)            # flags: locked bit
    w.put(4, 5)            # lit table length 4
    for v in (1, 0, 0, 2):
        w.put(v, 4)        # lens [1,0,0,2] -> sym0 '0', sym3 '10'
    w.put(0, 5)            # dist table empty
    w.put(0, 5)            # len table empty
    w.put(1, 16)           # count=1 -> only the trailing literal run
    w.put_code(0b10, 2)    # lit sym3 -> ret=3 -> (1<<2) | 2 extra bits
    w.put(0, 2)            # extra bits -> lit_len=4
    for b in plain:
        w.put_byte(b ^ (key & 0xFF))
    stream = w.finish()
    return rnc1_new_header(plain, stream) + stream, plain


def gen_rnc1_enc_unique() -> tuple[bytes, bytes]:
    """9 literal runs (run indexes 0..8) with distance-1 matches between;
    key 0xBEEF recoverable only via the unique-key GF(2) search.

    Plaintext: 8 tripled bytes + trailing byte => 25 bytes. Run i covers
    positions 3i..3i+2 (literal + 2 match-propagated), the trailing run 8
    covers position 24."""
    key = 0xBEEF
    plain = b"".join(bytes([ord("A") + i]) * 3 for i in range(8)) + b"I"
    assert len(plain) == 25

    w = FwdWriter()
    w.put(2, 2)            # flags: locked
    w.put(2, 5)            # lit table length 2
    w.put(1, 4)
    w.put(1, 4)            # lens [1,1] -> sym0 '0', sym1 '1'
    w.put(1, 5)            # dist table length 1
    w.put(1, 4)            # lens [1] -> sym0 '0'
    w.put(1, 5)            # len table length 1
    w.put(1, 4)            # lens [1] -> sym0 '0'
    w.put(9, 16)           # count=9 -> 8 (lit+match) cycles + trailing lit
    for i in range(8):
        w.put_code(0b1, 1)  # lit sym1 -> lit_len=1
        w.put_byte(plain[3 * i] ^ (ror16(key, i) & 0xFF))
        w.put_code(0b0, 1)  # dist sym0 -> distance 1
        w.put_code(0b0, 1)  # len sym0  -> sub_count 2
    w.put_code(0b1, 1)      # trailing lit sym1 -> lit_len=1
    w.put_byte(plain[24] ^ (ror16(key, 8) & 0xFF))
    stream = w.finish()
    return rnc1_new_header(plain, stream) + stream, plain


def gen_rnc1_enc_badkey() -> tuple[bytes, bytes]:
    """Single-run locked stream, non-known key 0xAB: underdetermined ->
    upstream leaves output encrypted and the CRC verify fails."""
    key = 0xAB
    plain = b"ABCD"
    w = FwdWriter()
    w.put(2, 2)
    w.put(4, 5)
    for v in (1, 0, 0, 2):
        w.put(v, 4)
    w.put(0, 5)
    w.put(0, 5)
    w.put(1, 16)
    w.put_code(0b10, 2)    # sym3 -> ret=3
    w.put(0, 2)            # extra -> lit_len=4
    for b in plain:
        w.put_byte(b ^ (key & 0xFF))
    stream = w.finish()
    return rnc1_new_header(plain, stream) + stream, plain


def main() -> int:
    fixtures = {
        "rnc1-old.rnc1": gen_rnc1_old(),
        "rnc2-old.rnc2": gen_rnc2_old(),
        "rnc1-enc-known.rnc1": gen_rnc1_enc_known(),
        "rnc1-enc-unique.rnc1": gen_rnc1_enc_unique(),
        "rnc1-enc-badkey.rnc1": gen_rnc1_enc_badkey(),
    }
    for name, (blob, plain) in fixtures.items():
        (CORPUS / name).write_bytes(blob)
        print(f"{name}: {len(blob)}B packed -> {len(plain)}B raw")
    return 0


if __name__ == "__main__":
    sys.exit(main())

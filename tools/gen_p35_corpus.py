#!/usr/bin/env python3
"""Phase 35 corpus generator: LHA legacy methods + -lh1- (LZHUF).

Each member's compressed payload is produced by a Python encoder that
mirrors the upstream decoder's bit-level semantics, then wrapped in a
level-0 LHA header whose CRC-16/ARC covers the *unpacked* data (the
upstream unpack path validates it). Expected outputs are encoded in
the token streams themselves; the oracle extraction snapshot is the
ground truth.
"""

import os
import struct

OUT = "corpus"


def w(path, name, data):
    with open(path, "wb") as f:
        f.write(data)
    print(f"  {name}: {len(data)} bytes")


def crc16_arc(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def lha_header(name, method, payload, level=0, crc16=None, is_dir=False, orig=None):
    if crc16 is None:
        crc16 = crc16_arc(payload)
    if orig is None:
        orig = len(payload)
    name_b = name.encode("latin-1")
    if level == 0:
        hsize = 22 + len(name_b)
        h = bytearray()
        h.append(hsize)
        h.append(0)
        h += method
        h += struct.pack("<I", len(payload))
        h += struct.pack("<I", orig)
        h += struct.pack("<I", 0)
        h.append(0x20)
        h.append(0)
        h.append(len(name_b))
        h += name_b
        h += struct.pack("<H", crc16)
        h[1] = sum(h[2:2 + hsize]) & 0xFF
        return bytes(h) + payload
    # level 1: base header + ext chain terminator; OS byte 0x20 marks
    # the generic/LHARK variant (upstream remaps -lh7- -> -lk7- here).
    hsize = 25 + len(name_b)
    h = bytearray()
    h.append(hsize)
    h.append(0)
    h += method
    h += struct.pack("<I", len(payload))
    h += struct.pack("<I", orig)
    h += struct.pack("<I", 0)
    h.append(0x20)
    h.append(1)
    h.append(len(name_b))
    h += name_b
    h += struct.pack("<H", crc16)
    h.append(0x20)  # OS id
    h += struct.pack("<H", 0)  # ext chain terminator
    h[1] = sum(h[2:2 + hsize]) & 0xFF
    return bytes(h) + payload


class BitWriter:
    """MSB-first bit writer matching the legacy BitStreamReader."""

    def __init__(self):
        self.buf = bytearray()
        self.acc = 0
        self.nbits = 0

    def put(self, v, n):
        for i in range(n - 1, -1, -1):
            self.acc = (self.acc << 1) | ((v >> i) & 1)
            self.nbits += 1
            if self.nbits == 8:
                self.buf.append(self.acc)
                self.acc = 0
                self.nbits = 0

    def finish(self):
        if self.nbits:
            self.buf.append(self.acc << (8 - self.nbits))
            self.acc = 0
            self.nbits = 0
        return bytes(self.buf)


# ---------------------------------------------------------------------
# -lzs- : bit 1 + 8-bit literal | bit 0 + 11-bit pos + 4-bit (len-2).
# Ring buffer 2048, initial pos = 2048 - 17 = 2031.
# ---------------------------------------------------------------------

def lzs_encode(tokens):
    bw = BitWriter()
    for kind, *a in tokens:
        if kind == "lit":
            bw.put(1, 1)
            bw.put(a[0], 8)
        else:  # ("copy", ring_pos, len)
            bw.put(0, 1)
            bw.put(a[0], 11)
            bw.put(a[1] - 2, 4)
    return bw.finish()


# ---------------------------------------------------------------------
# -lz5- : byte-oriented. bitmap byte, bits consumed LSB-first;
# set bit = literal byte, clear bit = 2-byte copy (pos = ((c1&0xf0)<<4)|c0,
# len = (c1&0x0f)+3). Ring pos starts at 4096 - 18 = 4078.
# ---------------------------------------------------------------------

def lz5_encode(commands):
    out = bytearray()
    for i in range(0, len(commands), 8):
        group = commands[i:i + 8]
        bitmap = 0
        body = bytearray()
        for j, cmd in enumerate(group):
            if cmd[0] == "lit":
                bitmap |= 1 << j
                body.append(cmd[1])
            else:  # ("copy", pos, len)
                bitmap &= ~(1 << j)
                pos, ln = cmd[1], cmd[2]
                body.append(pos & 0xFF)
                body.append(((pos >> 4) & 0xF0) | ((ln - 3) & 0x0F))
        out.append(bitmap)
        out += body
    return bytes(out)


# ---------------------------------------------------------------------
# lh_new template (-lhx- / -lk7-): per block
#   16-bit command count
#   temp table: 5-bit n (=0 -> single code) + 5-bit code
#   code table: 9-bit n (=0 -> single code) + 9-bit symbol
#   offset table: OFFSET_BITS n (=0 -> single) + OFFSET_BITS code
# ---------------------------------------------------------------------

def lhnew_encode(offset_bits, blocks):
    bw = BitWriter()
    for count, code_sym, off_sym in blocks:
        bw.put(count, 16)
        bw.put(0, 5)
        bw.put(0, 5)      # temp single code (unused)
        bw.put(0, 9)
        bw.put(code_sym, 9)
        bw.put(0, offset_bits)
        bw.put(off_sym, offset_bits)
    return bw.finish()


# ---------------------------------------------------------------------
# -pm1-: 5-bit start header (tree index) then commands:
#   bit 1 -> byte block: static-huffman count + per-byte index walk
#          (tree index via the selected mini-tree) + 4-bit value;
#          a non-maximal block is followed by a mandatory copy command.
#   bit 0 -> copy command: range bits + variable-length distance.
# Tree 31 is {0x00}: read_byte_decode_index returns 0 without bits,
# so each literal is just the 4-bit byte_ranges[0] value (walk 0-15
# into the move-to-front history list).
# ---------------------------------------------------------------------

class Pm1History:
    """Mirror of the PMarc history linked list."""

    def __init__(self):
        self.prev = [(i + 1) & 0xFF for i in range(256)]
        self.next = [(i - 1) & 0xFF for i in range(256)]
        self.head = 0x20
        self.prev[0x7F] = 0x00
        self.next[0x00] = 0x7F
        self.prev[0x1F] = 0xA0
        self.next[0xA0] = 0x1F
        self.prev[0xDF] = 0x80
        self.next[0x80] = 0xDF
        self.prev[0x9F] = 0xE0
        self.next[0xE0] = 0x9F
        self.prev[0xFF] = 0x20
        self.next[0x20] = 0xFF

    def find(self, count):
        code = self.head
        if count < 128:
            for _ in range(count):
                code = self.prev[code]
        else:
            for _ in range(256 - count):
                code = self.next[code]
        return code

    def distance(self, b):
        code, d = self.head, 0
        while code != b and d < 255:
            code = self.prev[code]
            d += 1
        return d if code == b else -1

    def update(self, b):
        if self.head == b:
            return
        self.prev[self.next[b]] = self.prev[b]
        self.next[self.prev[b]] = self.next[b]
        h = self.head
        self.prev[b] = h
        self.next[b] = self.next[h]
        self.prev[self.next[h]] = b
        self.next[h] = b
        self.head = b


def pm1_encode(blocks):
    """blocks: list of literal-value lists (each value 0-15 -> distance
    walked in the history list). A trailing copy (range 0 => 2 bytes
    from distance 0..63) is appended after every block."""
    bw = BitWriter()
    bw.put(31, 5)  # start header -> flat tree {0x00}
    hist = Pm1History()
    out_pos = 0
    emitted = []
    for vals in blocks:
        n = len(vals)
        if not 1 <= n <= 3:
            raise ValueError("fixture keeps block count in 1..3")
        bw.put(1, 1)          # byte block command
        bw.put(n - 1, 2)      # static huffman x<3 -> count = x+1
        for v in vals:
            bw.put(v, 4)      # byte_ranges[0] = {0,4}
            b = hist.find(v)
            hist.update(b)
            emitted.append(b)
            out_pos += 1
        # trailing copy: first bit 0 -> range 0 while output < 64,
        # then copy_ranges[0] = {0,6} -> 6-bit distance.
        bw.put(0, 1)
        dist = 0
        bw.put(dist, 6)
        last = emitted[-1]
        for _ in range(2):
            emitted.append(last)
            hist.update(last)
            out_pos += 1
    return bw.finish(), bytes(emitted)


# ---------------------------------------------------------------------
# -pm2-: first bit discarded; initial code tree: 5-bit num_codes +
# 3-bit min_len (0 -> single code = num_codes-1). With num_codes=2
# every command decodes to code 1 -> literal via history_decode[1]
# {8,3}: 3-bit value -> walk distance 8+v.
# ---------------------------------------------------------------------

def pm2_encode(vals):
    bw = BitWriter()
    bw.put(0, 1)   # discarded first bit
    bw.put(2, 5)   # num_codes = 2
    bw.put(0, 3)   # min_code_length = 0 -> single code 1 (literal)
    hist = Pm1History()
    emitted = []
    for v in vals:
        bw.put(v, 3)   # history_decode[1] -> distance 8+v
        b = hist.find(8 + v)
        hist.update(b)
        emitted.append(b)
    return bw.finish(), bytes(emitted)


# ---------------------------------------------------------------------
# -lh1- (LZHUF): adaptive Huffman + fixed position table.
# The encoder simulates the decoder's freq/son/prnt arrays exactly so
# emitted codes match the tree state at decode time.
# ---------------------------------------------------------------------

N_CHAR = 314
T = N_CHAR * 2 - 1
R = T - 1
MAX_FREQ = 0x8000


class Lh1Coder:
    def __init__(self):
        self.freq = [0] * (T + 1)
        self.prnt = [0] * (T + N_CHAR)
        self.son = [0] * T
        self.start_huff()
        # dCode/dLen canonical layout: lens 3..8, counts 1,3,8,12,24,16.
        self.len_of_sym = {}
        self.code_of_sym = {}
        n_syms = [1, 3, 8, 12, 24, 16]
        sym = 0
        base = 0
        for i, count in enumerate(n_syms):
            ln = i + 3
            for k in range(count):
                self.len_of_sym[sym] = ln
                self.code_of_sym[sym] = base + k
                sym += 1
            base = (base + count) << 1

    def start_huff(self):
        for i in range(N_CHAR):
            self.freq[i] = 1
            self.son[i] = i + T
            self.prnt[i + T] = i
        i, j = 0, N_CHAR
        while j <= R:
            self.freq[j] = self.freq[i] + self.freq[i + 1]
            self.son[j] = i
            self.prnt[i] = self.prnt[i + 1] = j
            i += 2
            j += 1
        self.freq[T] = 0xFFFF
        self.prnt[R] = 0

    def reconst(self):
        j = 0
        for i in range(T):
            if self.son[i] >= T:
                self.freq[j] = (self.freq[i] + 1) // 2
                self.son[j] = self.son[i]
                j += 1
        i, k = 0, N_CHAR
        while k < T:
            f = self.freq[i] + self.freq[i + 1]
            self.freq[k] = f
            l = k - 1
            while f < self.freq[l]:
                l -= 1
            l += 1
            for m in range(k, l, -1):
                self.freq[m] = self.freq[m - 1]
                self.son[m] = self.son[m - 1]
            self.freq[l] = f
            self.son[l] = i
            i += 2
            k += 1
        for i in range(T):
            k = self.son[i]
            if k >= T:
                self.prnt[k] = i
            else:
                self.prnt[k] = self.prnt[k + 1] = i

    def update(self, c):
        if self.freq[R] == MAX_FREQ:
            self.reconst()
        c = self.prnt[c + T]
        while True:
            self.freq[c] += 1
            k = self.freq[c]
            l = c + 1
            if k > self.freq[l]:
                while k > self.freq[l + 1]:
                    l += 1
                self.freq[c], self.freq[l] = self.freq[l], k
                i = self.son[c]
                self.prnt[i] = l
                if i < T:
                    self.prnt[i + 1] = l
                j = self.son[l]
                self.son[l] = i
                self.prnt[j] = c
                if j < T:
                    self.prnt[j + 1] = c
                self.son[c] = j
                c = l
            c = self.prnt[c]
            if c == 0:
                break

    def encode_symbol(self, bw, c):
        # Collect bits leaf -> root then emit root -> leaf. The leaf
        # itself occupies the holder slot prnt[c + T]: the decoder's
        # c += bit; c = son[c] selects a *position*, so the code only
        # covers the internal-node chain — the leaf lookup is free.
        bits = []
        node = self.prnt[c + T]
        while node != R:
            p = self.prnt[node]
            bits.append(node - self.son[p])
            node = p
        for b in reversed(bits):
            bw.put(b, 1)
        self.update(c)


def lh1_encode(tokens):
    """tokens: ("lit", byte) | ("match", len, dist)."""
    bw = BitWriter()
    coder = Lh1Coder()
    for kind, *a in tokens:
        if kind == "lit":
            coder.encode_symbol(bw, a[0])
        else:
            ln, dist = a
            coder.encode_symbol(bw, ln - 3 + 256)
            pos = dist - 1
            sym = pos >> 6
            low6 = pos & 0x3F
            plen = coder.len_of_sym[sym]
            pcode = coder.code_of_sym[sym]
            extra = plen - 2
            byte = (pcode << (8 - plen)) | (low6 >> extra)
            bw.put(byte, 8)
            bw.put(low6 & ((1 << extra) - 1), extra)
    return bw.finish()


def gen():
    os.makedirs(OUT, exist_ok=True)

    # -lzs-: literals 'H','i' then two copies walking the ring.
    # ring pos 2031: 'H'@2031 'i'@2032; copy(2031,4) -> 'HiHi';
    # copy(2031,2) -> 'Hi'  => "HiHiHiHi" (8 bytes).
    p = lzs_encode([("lit", 72), ("lit", 105), ("copy", 2031, 4),
                    ("copy", 2031, 2)])
    e = b"HiHiHiHi"
    w(f"{OUT}/test-lzs.lha", "test-lzs.lha",
      lha_header("lzs.bin", b"-lzs-", p, crc16=crc16_arc(e), orig=len(e)))

    # -lz5-: bitmap 0xFD -> lit 'Q', copy(pos 4078, len 4) -> 'QQQQ',
    # then six literals. Output "QQQQQ" + "XYZ123" (11 bytes).
    p = lz5_encode([("lit", 81), ("copy", 4078, 4),
                    ("lit", 88), ("lit", 89), ("lit", 90),
                    ("lit", 49), ("lit", 50), ("lit", 51)])
    e = b"QQQQQXYZ123"
    w(f"{OUT}/test-lz5.lha", "test-lz5.lha",
      lha_header("lz5.bin", b"-lz5-", p, crc16=crc16_arc(e), orig=len(e)))

    # -lhx-: literal block 'H', literal block 'i'x2, copy block
    # (code 257 -> len 4, offset single 0 -> repeat last byte),
    # literal '!'.  "H" + "ii" + "iiii" + "!" = "Hiiiiii!" (8 bytes).
    p = lhnew_encode(5, [(1, 72, 0), (2, 105, 0), (1, 257, 0), (1, 33, 0)])
    e = b"Hiiiiii!"
    w(f"{OUT}/test-lhx.lha", "test-lhx.lha",
      lha_header("lhx.bin", b"-lhx-", p, crc16=crc16_arc(e), orig=len(e)))

    # -lk7- (LHARK): level-1 header, OS 0x20, tag -lh7- (upstream
    # remaps to -lk7-). OFFSET_BITS=6; 'K'x3 + copy code 257 ->
    # lhark count 4 + '!' = "KKKKKKK!" (8 bytes).
    p = lhnew_encode(6, [(3, 75, 0), (1, 257, 0), (1, 33, 0)])
    e = b"KKKKKKK!"
    w(f"{OUT}/test-lk7.lha", "test-lk7.lha",
      lha_header("lk7.bin", b"-lh7-", p, level=1,
                 crc16=crc16_arc(e), orig=len(e)))

    # -pm1-: two byte blocks (2 + 3 literals) each with a trailing
    # 2-byte copy -> 4 + 5 = 9 bytes. Values are history distances.
    p, e = pm1_encode([[0, 1], [2, 1, 0]])
    w(f"{OUT}/test-pm1.lha", "test-pm1.lha",
      lha_header("pm1.bin", b"-pm1-", p, crc16=crc16_arc(e), orig=len(e)))

    # -pm2-: single-code literal tree; eight 3-bit history distances.
    p, e = pm2_encode([0, 1, 2, 3, 4, 5, 6, 7])
    w(f"{OUT}/test-pm2.lha", "test-pm2.lha",
      lha_header("pm2.bin", b"-pm2-", p, crc16=crc16_arc(e), orig=len(e)))

    # -lh1- (LZHUF): 'H','i' literals + match(len3, dist2) + '!' ->
    # "Hi" + "HiH" + "!" = "HiHiH!" (6 bytes).
    p = lh1_encode([("lit", 72), ("lit", 105), ("match", 3, 2),
                    ("lit", 33)])
    e = b"HiHiH!"
    w(f"{OUT}/test-lh1.lha", "test-lh1.lha",
      lha_header("lh1.bin", b"-lh1-", p, crc16=crc16_arc(e), orig=len(e)))


if __name__ == "__main__":
    gen()

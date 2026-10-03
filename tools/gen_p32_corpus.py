#!/usr/bin/env python3
"""Generate synthetic ARJ / LHA fixtures for Phase 32 differential tests.

ARJ layout (upstream xarj.cpp):
  per entry: '60 EA' | u16 basic_size | basic header | u16 header_crc |
             ext chain (u16 size + data + u32 crc, 0 terminates) | data
  basic header: first_hdr_size(1) archiver(1) min_ver(1) host_os(1)
                flags(1) method(1) file_type(1) reserved(1) dos_dt(4)
                comp(4) orig(4) crc32(4) name_pos(2) access(2)
                first_ch(1) last_ch(1) | name NUL
  first_hdr_size = 30 (offset of the name inside the basic header).
  Main header at 0 is followed by file records; '60 EA' + 0 ends the
  archive.

LHA level-0 layout (upstream xlha.cpp::_readMember):
  u8 header_size | u8 checksum(sum of bytes 2..2+header_size) | "-lh?-" |
  u32 comp | u32 orig | u32 datetime | u8 attr | u8 level=0 |
  u8 name_len | name | u16 crc16 | data
  header_size = 22 + name_len; basic size = header_size + 2.

Level-1 adds u8 os + u16 ext_size chain entries after the CRC16;
skip_sz (bytes 7-10) covers ext headers + compressed data.
"""
import os
import binascii
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "corpus"


def w(p, n, b):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(b)
    print(f"  {n}: {len(b)} bytes")


def crc16_arc(data):
    """CRC-16/ARC: reflected, poly 0xA001, init 0 (upstream lhaReadCrc16)."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc & 0xFFFF


def dos_dt(y=2020, mo=6, d=15, h=12, mi=30, s=44):
    return ((y - 1980) << 25) | (mo << 21) | (d << 16) | (h << 11) | (mi << 5) | (s // 2)


def arj_basic(first, archiver, minv, host, flags, method, ftype, dt, comp, orig, crc, name):
    name_b = name.encode("latin-1")
    basic_size = first + len(name_b) + 1
    h = struct.pack(
        "<BBBBBBBBIIIIHHBB",
        first, archiver, minv, host, flags, method, ftype, 0,
        dt, comp, orig, crc, first, 0, 0, 0,
    )
    assert len(h) == 30 == first
    h += name_b + b"\0"
    # 4-byte header CRC + u16 ext_size = 0 (empty extended-header chain).
    return struct.pack("<H", basic_size) + h + b"\0\0\0\0" + b"\0\0"


def gen_arj():
    """ARJ with main header + one stored file + one 'compressed' file +
    directory entry + EOA marker."""
    data1 = b"ARJ stored member\n"
    data2 = bytes(range(64))
    out = bytearray()
    # main header (file_type 0 = archive comment header fields)
    out += b"\x60\xea" + arj_basic(
        30, 100, 50, 2, 0, 0, 0, dos_dt(), 0, 0, 0, "TESTARJ"
    )
    # stored file record
    out += b"\x60\xea" + arj_basic(
        30, 100, 50, 2, 0, 0, 0, dos_dt(), len(data1), len(data1),
        binascii.crc32(data1), "dir\\hello.txt",
    )
    out += data1
    # "compressed most" member (we can't decode, list only)
    out += b"\x60\xea" + arj_basic(
        30, 100, 50, 2, 0, 1, 0, dos_dt(), len(data2), 128, 0x11223344,
        "packed.bin",
    )
    out += data2
    # directory entry (file_type 3)
    out += b"\x60\xea" + arj_basic(
        30, 100, 50, 2, 0, 0, 3, dos_dt(), 0, 0, 0, "dir\\sub"
    )
    out += b"\x60\xea\x00\x00"  # end of archive
    w(f"{OUT}/test.arj", "test.arj", bytes(out))


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
        h.append(0)  # checksum placeholder
        h += method
        h += struct.pack("<I", len(payload))
        h += struct.pack("<I", orig)
        h += struct.pack("<I", 0)  # datetime
        h.append(0x20)
        h.append(0)
        h.append(len(name_b))
        h += name_b
        h += struct.pack("<H", crc16)
        h[1] = sum(h[2:2 + hsize]) & 0xFF
        return bytes(h) + payload
    # level 1: declared size covers bytes 2..end of the base header
    # (method..next-size terminator): 20+1+1+name+2(crc)+1(os)+2(next).
    hsize = 25 + len(name_b)
    h = bytearray()
    h.append(hsize)
    h.append(0)
    h += method
    h += struct.pack("<I", len(payload))  # skip_sz (ext + comp)
    h += struct.pack("<I", orig)
    h += struct.pack("<I", 0)
    h.append(0x20)
    h.append(1)
    h.append(len(name_b))
    h += name_b
    h += struct.pack("<H", crc16)
    h.append(0x20)  # OS ' ' (generic)
    h += struct.pack("<H", 0)  # ext chain: terminator
    h[1] = sum(h[2:2 + hsize]) & 0xFF
    return bytes(h) + payload


def gen_lha():
    """LHA: two level-0 -lh0- stored members + a level-0 -lhd- dir."""
    payload = b"LHA stored member\n"
    out = lha_header("hello.txt", b"-lh0-", payload)
    out += lha_header("dir/", b"-lhd-", b"")
    out += lha_header("two.bin", b"-lh0-", bytes(range(32)))
    w(f"{OUT}/test-l0.lha", "test-l0.lha", out)

    out = lha_header("one.txt", b"-lh0-", b"level1\n", level=1)
    w(f"{OUT}/test-l1.lha", "test-l1.lha", out)


def ace_block(head_type, flags, body):
    """ACE block: u16 head_crc | u16 head_size | body (head_type+flags+fields)."""
    full = bytes([head_type]) + struct.pack("<H", flags) + body
    head_size = len(full)
    crc = 0xFFFFFFFF
    for b in full:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    return struct.pack("<HH", crc & 0xFFFF, head_size) + full


def gen_ace():
    """ACE 1.x: main header + one STORED file + one LZ77-tech file."""
    main_body = b"**ACE**" + bytes([10, 20, 2, 0]) + struct.pack(
        "<IHHI", dos_dt(), 0, 0, 0
    ) + bytes([0])
    data1 = b"ACE stored member\n"
    file_hdr = (
        struct.pack("<IIII", len(data1), len(data1), dos_dt(), 0x20)
        + struct.pack("<I", binascii.crc32(data1) ^ 0xFFFFFFFF)
        + bytes([0, 0])
        + struct.pack("<HH", 0, 0)
        + struct.pack("<H", len(b"stored.txt"))
        + b"stored.txt"
    )
    data2 = bytes(range(48))
    comp_hdr = (
        struct.pack("<IIII", len(data2), 96, dos_dt(), 0x20)
        + struct.pack("<I", binascii.crc32(data2) ^ 0xFFFFFFFF)
        + bytes([1, 0])
        + struct.pack("<HH", 0, 0)
        + struct.pack("<H", len(b"packed.bin"))
        + b"packed.bin"
    )
    out = ace_block(0, 0, main_body)
    out += ace_block(1, 0x0001, file_hdr) + data1
    out += ace_block(1, 0x0001, comp_hdr) + data2
    w(f"{OUT}/test.ace", "test.ace", bytes(out))


class BitWriter:
    """MSB-first bit writer matching the ARJ decoder's fill_buf order."""

    def __init__(self):
        self.bits = 0
        self.nbits = 0
        self.out = bytearray()

    def put(self, value, width):
        """Append `width` bits of `value` (MSB first)."""
        assert 0 <= width <= 24 and 0 <= value < (1 << max(width, 1))
        self.bits = (self.bits << width) | value
        self.nbits += width
        while self.nbits >= 8:
            self.nbits -= 8
            self.out.append((self.bits >> self.nbits) & 0xFF)
            self.bits &= (1 << self.nbits) - 1

    def finish(self):
        """Flush zero-padded tail; returns packed bytes."""
        if self.nbits:
            self.out.append((self.bits << (8 - self.nbits)) & 0xFF)
            self.bits = 0
            self.nbits = 0
        return bytes(self.out)


def arj_m1_encode(tokens):
    """Encode a token list as an ARJ method-1 (LZSS+Huffman) stream.

    `tokens`: [('lit', byte) | ('match', len)] — matches always use
    dist=1 (decodeP returns 0 via the single-symbol pLen table).

    Table layout (mirrors upstream decode order):
      blockSize(16) | ptLen(NT=19,TBIT=5,special=3) | cLen(CBIT=9) |
      ptLen(NP=17,PBIT=5,special=-1) | tokens

    ptLen#1 assigns len1 to symbols {10,11} (complete tree, canonical
    codes 0/1 by symbol order). cLen assigns len8 to symbols {0,1} and
    len9 to symbols {2..509} (Kraft: 2/256 + 508/512 == 1); canonical
    codes are sym index for len8 syms and sym+2 for len9 syms. A
    match of length m is token 253+m, encoded as the 9-bit code m+255.
    """
    for kind, v in tokens:
        if kind == "lit" and not 0 <= v <= 255:
            raise ValueError("literal out of range")
        if kind == "match" and not 3 <= v <= 258:
            raise ValueError("match len out of range")
    if not tokens or len(tokens) > 0xFFFF:
        raise ValueError("bad token count")
    # len9 token count must be 4 mod 8 so consumed bits end on a byte
    # boundary (upstream requires exact input consumption).
    len9 = sum(1 for k, v in tokens if k == "match" or v > 1)
    if len9 % 8 != 4:
        raise ValueError("len9 token count must be 4 mod 8")
    w = BitWriter()
    w.put(len(tokens), 16)
    # ptLen #1: emit n=12 lengths, skip field fires after i==3.
    w.put(12, 5)
    for i in range(12):
        w.put(1 if i in (10, 11) else 0, 3)
        if i + 1 == 3:
            w.put(0, 2)
    # cLen: 510 entries via pt codes (sym10='0' -> len8, sym11='1' -> len9).
    w.put(510, 9)
    for i in range(510):
        w.put(0 if i < 2 else 1, 1)
    # ptLen #2: n=0 -> uniform single-symbol table, nC=0 (decodeP -> 0).
    w.put(0, 5)
    w.put(0, 5)
    # tokens: literal 0/1 -> 8-bit canonical code = byte;
    # literal b>=2 -> 9-bit code b+2; match m -> 9-bit code m+255.
    for kind, v in tokens:
        if kind == "lit":
            if v < 2:
                w.put(v, 8)
            else:
                w.put(v + 2, 9)
        else:
            w.put(v + 255, 9)
    return w.finish()


def gen_arj_compressed():
    """ARJ with a real method-1 compressed member (oracle-decodable)."""
    tokens = [("lit", 65), ("match", 10), ("lit", 66), ("match", 5)]
    payload = arj_m1_encode(tokens)
    expected = b"A" * 11 + b"B" * 6
    data1 = b"ARJ stored member\n"
    out = bytearray()
    out += b"\x60\xea" + arj_basic(
        30, 100, 50, 2, 0, 0, 0, dos_dt(), 0, 0, 0, "TESTARJ"
    )
    out += b"\x60\xea" + arj_basic(
        30, 100, 50, 2, 0, 0, 0, dos_dt(), len(data1), len(data1),
        binascii.crc32(data1), "dir\\hello.txt",
    )
    out += data1
    out += b"\x60\xea" + arj_basic(
        30, 100, 50, 2, 0, 1, 0, dos_dt(), len(payload), len(expected),
        binascii.crc32(expected), "packed.bin",
    )
    out += payload
    out += b"\x60\xea" + arj_basic(
        30, 100, 50, 2, 0, 0, 3, dos_dt(), 0, 0, 0, "dir\\sub"
    )
    out += b"\x60\xea\x00\x00"
    w(f"{OUT}/test-m1.arj", "test-m1.arj", bytes(out))




class AceWriter:
    """MSB-first bits packed into little-endian 32-bit words.

    Mirrors XAceDecoder's readdat layout: the stream is consumed as
    u32 LE words, MSB first within each word.
    """

    def __init__(self):
        self.words = []
        self.acc = 0
        self.n = 0

    def put(self, value, width):
        """Append `width` bits of `value` (MSB first)."""
        assert 0 <= width <= 32 and 0 <= value < (1 << max(width, 1))
        self.acc = (self.acc << width) | value
        self.n += width
        while self.n >= 32:
            self.n -= 32
            self.words.append((self.acc >> self.n) & 0xFFFFFFFF)
            self.acc &= (1 << self.n) - 1

    def finish(self):
        """Flush zero-padded tail word; returns packed bytes.

        Upstream requires < 32 slack bits at stream end, so only the
        final partial word is padded.
        """
        if self.n:
            self.words.append((self.acc << (32 - self.n)) & 0xFFFFFFFF)
        out = bytearray()
        for x in self.words:
            out += x.to_bytes(4, "little")
        return bytes(out)


def _ace_sort_range(freq, org, left, right):
    """Verbatim mirror of XAceDecoder::sortRange (quicksort partition)."""
    zl, zr = left, right
    hyphen = freq[right]
    while True:
        while freq[zl] > hyphen:
            zl += 1
        while freq[zr] < hyphen:
            zr -= 1
        if zl <= zr:
            freq[zl], freq[zr] = freq[zr], freq[zl]
            org[zl], org[zr] = org[zr], org[zl]
            zl += 1
            zr -= 1
        if zl >= zr:
            break
    if left < zr:
        if left < zr - 1:
            _ace_sort_range(freq, org, left, zr)
        elif freq[left] < freq[zr]:
            freq[left], freq[zr] = freq[zr], freq[left]
            org[left], org[zr] = org[zr], org[left]
    if right > zl:
        if zl < right - 1:
            _ace_sort_range(freq, org, zl, right)
        elif freq[zl] < freq[right]:
            freq[zl], freq[right] = freq[right], freq[zl]
            org[zl], org[right] = org[right], org[zl]


def _ace_makecode(maxwd, wd):
    """Mirror of XAceDecoder::makeCode; returns slot->symbol table.

    `wd` is modified in place like the upstream pWd array.
    """
    size1t = len(wd) - 1
    freq = wd[:] + [0] * (284 - len(wd))
    org = list(range(len(freq)))
    if size1t > 0:
        _ace_sort_range(freq, org, 0, size1t)
    else:
        org[0] = 0
    freq[size1t + 1] = 0
    size2t = 0
    while freq[size2t]:
        size2t += 1
    if size2t < 2:
        wd[org[0]] = 1
        if size2t == 0:
            size2t = 1
    size2t -= 1
    table = [0xFFFF] * (1 << maxwd)
    c = 0
    i = size2t + 1
    while i != 0 and c < len(table):
        i -= 1
        width = freq[i]
        if width > maxwd:
            raise ValueError("width exceeds maxwd")
        maxc = 1 << (maxwd - width)
        if maxc > len(table) - c:
            raise ValueError("overcomplete table")
        for k in range(maxc):
            table[c + k] = org[i]
        c += maxc
    return table


def _ace_code(table, sym, wd, maxwd):
    """Return (code value, width) whose MSB-first bits land on `sym`."""
    w_ = wd[sym]
    assert w_ > 0 and w_ <= maxwd
    span = 1 << (maxwd - w_)
    try:
        i = table.index(sym)
    except ValueError:
        raise ValueError(f"symbol {sym} not in table")
    lo = i - (i % span)
    assert i == lo and all(t == sym for t in table[lo:lo + span]), \
        f"code for {sym} not aligned"
    return lo >> (maxwd - w_), w_


def _emit_wd(bw, target, uplim, meta_wd):
    """Emit one read_wd table for `target` widths (index 0..num_el).

    `meta_wd`: widths for meta symbols 0..uplim (uplim+1 entries); the
    run symbol is `uplim` itself. lolim is fixed at 0, so all non-zero
    target widths must be < uplim.
    """
    num_el = len(target) - 1
    # Pre-delta raw widths: r[0]=target[0], r[i]=(target[i]-target[i-1])%uplim.
    raws = [target[0]] + [
        (target[i] - target[i - 1]) % uplim for i in range(1, num_el + 1)
    ]
    meta_table = _ace_makecode(7, meta_wd)
    bw.put(num_el, 9)
    bw.put(0, 4)  # lolim
    bw.put(uplim, 4)
    for i in range(uplim + 1):
        bw.put(meta_wd[i], 3)
    run_code, run_w = _ace_code(meta_table, uplim, meta_wd, 7)
    sym_codes = {
        s: _ace_code(meta_table, s, meta_wd, 7) for s in range(uplim)
    }
    j = 0
    while j <= num_el:
        if raws[j] == 0:
            run = 0
            while j + run <= num_el and raws[j + run] == 0:
                run += 1
            if run >= 4:
                left = run
                while left >= 4:
                    chunk = min(left, 19)
                    bw.put(run_code, run_w)
                    bw.put(chunk - 4, 4)
                    left -= chunk
                    j += chunk
                continue
        v = raws[j]
        assert v < uplim, "raw width must be < uplim"
        code, w_ = sym_codes[v]
        bw.put(code, w_)
        j += 1


def ace_m1_encode(literals, matches=()):
    """Encode a token list as an ACE tech-1 (LZ+Huffman) stream.

    `literals`/`matches`: ("lit", sym) / ("match", dist_prefix_bits,
    dc, lg) — main widths are fixed: each literal sym gets width 1 or 2
    via caller-supplied `lit_widths` in `matches[0]`... simplified:
    caller passes explicit token list in `literals`.
    """
    raise NotImplementedError




def lzh_encode(method, blocks, lt_widths=None):
    """Encode an LHA -lhN- (method 4-7) stream for fixture use.

    `blocks`: list of token lists; tokens are ("lit", sym) or
    ("match", 3). `lt_widths`: {sym: bitlen} for the literal/length
    table; default assigns width 1 to every used symbol (valid only
    for <=2 symbols). Simplifications (still a valid stream):
      - literal PT meta-table fixed at bitlens {0:1,1:2,2:3,3:4,4:5,5:5}
        -> canonical codes 0:'0' 1:'10' 2:'110' 3:'1110' 4:'11110'
        5:'11111', covering lt bitlen values 0-4 (value = sym-2).
      - position table is a "fake table" (len_avail=0) returning
        sym 0 -> dist 1 with zero bits per match.
    """
    w_bits = {4: 12, 5: 13, 6: 15, 7: 16}[method]
    pos_pt_bits = 5 if w_bits in (15, 16) else 4
    # meta-code table: sym -> (bit pattern, length), canonical order.
    meta = {0: (0b0, 1), 1: (0b10, 2), 2: (0b110, 3),
            3: (0b1110, 4), 4: (0b11110, 5), 5: (0b11111, 5)}
    bw = BitWriter()

    def put_zeros(count):
        """Emit `count` zero bitlens via c0/c1/c2 runs."""
        while count >= 23:
            n = min(count - 20, 511)
            bw.put(0b110, 3)
            bw.put(n, 9)
            count -= 20 + n
        if count >= 3:
            n = min(count - 3, 15)
            bw.put(0b10, 2)
            bw.put(n, 4)
            count -= 3 + n
        for _ in range(count):
            bw.put(0, 1)

    for tokens in blocks:
        n_tok = len(tokens)
        assert 0 < n_tok <= 0xFFFF
        literals = sorted({v for k, v in tokens if k == "lit"})
        has_match = any(k == "match" for k, _ in tokens)
        used = literals + ([256] if has_match else [])
        widths = lt_widths or {sym: 1 for sym in used}
        assert set(widths) == set(used) and max(widths.values()) <= 4
        max_sym = max(used)
        # canonical codes: assigned in symbol order within each length,
        # matching the decoder's bitptn/weight walk.
        codes = {}
        nxt = {}
        ptn = 0
        for ln in range(1, 17):
            syms = [s for s in used if widths[s] == ln]
            for sym in sorted(syms):
                codes[sym] = (ptn, ln)
                ptn += 1
            ptn <<= 1
        assert all(len(bin(c)) - 2 <= ln for sym, (c, ln) in codes.items())
        bw.put(n_tok, 16)
        # literal PT table (19 syms, len_bits=5):
        # bitlens {0:1,1:2,2:3,3:4,4:5,5:5}, len_avail=6
        bw.put(6, 5)
        for v in (1, 2, 3):
            bw.put(v, 3)
        bw.put(0, 2)          # no extra zeros skipped after index 3
        for v in (4, 5, 5):
            bw.put(v, 3)      # bitlens at indices 3,4,5
        # literal table (len_bits=9)
        bw.put(max_sym + 1, 9)
        i = 0
        for sym in used:
            put_zeros(sym - i)
            code, ln = meta[widths[sym] + 2]
            bw.put(code, ln)
            i = sym + 1
        put_zeros(max_sym + 1 - i)
        # position table: fake table, sym 0 -> dist 1, 0 bits per use
        bw.put(0, pos_pt_bits)
        bw.put(0, pos_pt_bits)
        for kind, v in tokens:
            sym = v if kind == "lit" else 256
            if kind == "match":
                assert v == 3
            code, ln = codes[sym]
            bw.put(code, ln)
    return bw.finish()


def gen_lha_compressed():
    """LHA with real -lh4..-lh7- compressed members (oracle-decodable).

    lh5: 2 'B' literals + len3/dist1 match + 2 'B' -> "BBBBBBB".
    lh7: 6 'C' + 6 'D' literals.
    lh4: 'EE' + len3/dist1 match + 'E' + 'F' -> 7 bytes, exercises
         the 3-symbol non-uniform literal table.
    lh6: 5 'G' + 5 'H' literals (5-bit position-table metadata path).
    """
    p5 = lzh_encode(5, [[("lit", 66), ("lit", 66), ("match", 3),
                         ("lit", 66), ("lit", 66)]])
    e5 = b"B" * 7
    w(f"{OUT}/test-lh5.lha", "test-lh5.lha",
      lha_header("m5.bin", b"-lh5-", p5, crc16=crc16_arc(e5), orig=len(e5)))
    p7 = lzh_encode(7, [[("lit", 67)] * 6 + [("lit", 68)] * 6])
    e7 = b"C" * 6 + b"D" * 6
    w(f"{OUT}/test-lh7.lha", "test-lh7.lha",
      lha_header("m7.bin", b"-lh7-", p7, crc16=crc16_arc(e7), orig=len(e7)))
    p4 = lzh_encode(4, [[("lit", 69), ("lit", 69), ("match", 3),
                         ("lit", 69), ("lit", 70)]],
                    lt_widths={69: 1, 70: 2, 256: 2})
    e4 = bytes([69, 69, 69, 69, 69, 69, 70])
    w(f"{OUT}/test-lh4.lha", "test-lh4.lha",
      lha_header("m4.bin", b"-lh4-", p4, crc16=crc16_arc(e4), orig=len(e4)))
    p6 = lzh_encode(6, [[("lit", 71)] * 5 + [("lit", 72)] * 5])
    e6 = b"G" * 5 + b"H" * 5
    w(f"{OUT}/test-lh6.lha", "test-lh6.lha",
      lha_header("m6.bin", b"-lh6-", p6, crc16=crc16_arc(e6), orig=len(e6)))


def arj_m4_encode(tokens):
    """Encode tokens as an ARJ method-4 (fastest) stream.

    tokens: ("lit", byte) | ("match", len, dist).

    decodeLen token v: `n` leading '1' bits + '0' (n<7) + n-bit suffix
    (v - (2**n - 1)); n minimal with v <= 2**(n+1) - 2. token==0 is a
    literal flag followed by the raw byte; else match_len = token + 2.
    decodePtr pos v: same scheme with widths 9..13; pos = dist - 1.
    """
    bw = BitWriter()

    def put_len(v):
        n = 0
        while n < 7 and v > (1 << (n + 1)) - 2:
            n += 1
        for _ in range(n):
            bw.put(1, 1)
        if n < 7:
            bw.put(0, 1)
        bw.put(v - ((1 << n) - 1), n)

    def put_ptr(v):
        n = 9
        while n < 13 and v > (1 << (n + 1)) - 513:
            n += 1
        for _ in range(n - 9):
            bw.put(1, 1)
        if n < 13:
            bw.put(0, 1)
        bw.put(v - ((1 << n) - 512), n)

    for kind, *args in tokens:
        if kind == "lit":
            bw.put(0, 1)
            bw.put(args[0], 8)
        else:
            ln, dist = args
            if not 3 <= ln <= 256 or not 1 <= dist <= 15872:
                raise ValueError("match out of range")
            put_len(ln - 2)
            put_ptr(dist - 1)
    return bw.finish()


def gen_arj_m4():
    """ARJ with a real method-4 (fastest) compressed member."""
    tokens = [("lit", 65), ("match", 10, 1), ("lit", 66), ("match", 5, 2)]
    payload = arj_m4_encode(tokens)
    # 'A' + 'A'x10 + 'B' + copy(dist2,len5) = "AAAAAAAAAAAB" + "ABABA"
    expected = b"AAAAAAAAAAAB" + b"ABABA"
    data1 = b"ARJ stored member\n"
    out = bytearray()
    out += b"\x60\xea" + arj_basic(
        30, 100, 50, 2, 0, 0, 0, dos_dt(), 0, 0, 0, "TESTARJ"
    )
    out += b"\x60\xea" + arj_basic(
        30, 100, 50, 2, 0, 0, 0, dos_dt(), len(data1), len(data1),
        binascii.crc32(data1), "stored.txt",
    )
    out += data1
    out += b"\x60\xea" + arj_basic(
        30, 100, 50, 2, 0, 4, 0, dos_dt(), len(payload), len(expected),
        binascii.crc32(expected), "packed4.bin",
    )
    out += payload
    out += b"\x60\xea\x00\x00"
    w(f"{OUT}/test-m4.arj", "test-m4.arj", bytes(out))


def gen_ace_compressed():
    """ACE 1.x with a real tech-1 compressed member (oracle-decodable).

    Stream layout (mirroring decoder consumption):
      readWd#1 (main):  num_el=262, uplim=3, meta=[2,2,2,2],
                        widths 65->1, 66->2, 262->2 (Kraft=1)
      readWd#2 (length): num_el=8, uplim=0, meta=[0], width 8->1
      blocksize(15) | symbols

    Symbols: A='1'(1b)  B/C codes derived via the mirrored makeCode.
    Content: lit A, lit B, lit A, match(sym262: dc=2, dist='0'->3),
    lg sym8 (len=8+2=10), lit B, lit B -> 15 bytes
    "ABA" + "ABAABAABAA" + "BB".
    """
    meta_wd = [2, 2, 2, 2]
    bw = AceWriter()
    # Main table: widths for symbols 0..262.
    main_wd = [0] * 263
    main_wd[65] = 1
    main_wd[66] = 2
    main_wd[262] = 2
    _emit_wd(bw, main_wd, 3, meta_wd)
    main_table = _ace_makecode(11, main_wd)
    # Length table: single symbol 8, width 1.
    lg_wd = [0] * 9
    lg_wd[8] = 1
    lg_target = lg_wd[:]
    _emit_wd(bw, lg_target, 3, meta_wd)
    # num_el=8 so the decoder reads widths for 0..8; target has 9 entries.
    lg_table = _ace_makecode(11, lg_wd)
    bw.put(6, 15)  # blocksize: 6 symbols
    expected = b"ABA" + b"ABAABAABAA" + b"BB"
    code, w_ = _ace_code(main_table, 65, main_wd, 11)
    bw.put(code, w_)  # lit 'A'
    code, w_ = _ace_code(main_table, 66, main_wd, 11)
    bw.put(code, w_)  # lit 'B'
    code, w_ = _ace_code(main_table, 65, main_wd, 11)
    bw.put(code, w_)  # lit 'A'
    code, w_ = _ace_code(main_table, 262, main_wd, 11)
    bw.put(code, w_)  # new-dist ref, dc=2
    bw.put(0, 1)      # dist prefix '0' -> dist=2 -> +1 -> 3
    code, w_ = _ace_code(lg_table, 8, lg_wd, 11)
    bw.put(code, w_)  # len = 8 + i(2) = 10
    code, w_ = _ace_code(main_table, 66, main_wd, 11)
    bw.put(code, w_)  # lit 'B'
    bw.put(code, w_)  # lit 'B'
    payload = bw.finish()

    main_body = b"**ACE**" + bytes([10, 20, 2, 0]) + struct.pack(
        "<IHHI", dos_dt(), 0, 0, 0
    ) + bytes([0])
    data1 = b"ACE stored member\n"
    file_hdr = (
        struct.pack("<IIII", len(data1), len(data1), dos_dt(), 0x20)
        + struct.pack("<I", binascii.crc32(data1) ^ 0xFFFFFFFF)
        + bytes([0, 0])
        + struct.pack("<HH", 0, 0)
        + struct.pack("<H", len(b"stored.txt"))
        + b"stored.txt"
    )
    comp_hdr = (
        struct.pack("<IIII", len(payload), len(expected), dos_dt(), 0x20)
        + struct.pack("<I", binascii.crc32(expected) ^ 0xFFFFFFFF)
        + bytes([1, 0])  # tech_type=1, tech_parameter=0 (1 KiB dict)
        + struct.pack("<HH", 0, 0)
        + struct.pack("<H", len(b"packed.bin"))
        + b"packed.bin"
    )
    out = ace_block(0, 0, main_body)
    out += ace_block(1, 0x0001, file_hdr) + data1
    out += ace_block(1, 0x0001, comp_hdr) + payload
    w(f"{OUT}/test-m1.ace", "test-m1.ace", bytes(out))


if __name__ == "__main__":
    gen_arj()
    gen_arj_compressed()
    gen_arj_m4()
    gen_lha()
    gen_lha_compressed()
    gen_ace()
    gen_ace_compressed()

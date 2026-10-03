#!/usr/bin/env python3
"""Phase 41 corpus generator: compressed WIM images.

Synthesizes two minimal compressed WIMs (v1.12, 0xD0 header) that the
upstream `XWIM::initUnpack`/`_stageChunkedResource` pipeline accepts:

* ``test-xpress.wim`` — ``HEADER_FLAG_COMPRESSION|HEADER_FLAG_XPRESS``,
  XPRESS-Huffman chunks plus one stored member;
* ``test-lzx.wim`` — ``HEADER_FLAG_COMPRESSION|HEADER_FLAG_LZX``, LZX
  ``BLOCK_UNCOMPRESSED`` chunks, one stored passthrough chunk inside a
  compressed resource, and an odd-size chunk tail.

Both images use a compressed metadata resource so `read_resource` must
decode it during enumeration, exactly like real-world images.

The encoders mirror the upstream decoders' acceptance contract:

* XPRESS: all 512 symbols get code length 9 (a complete canonical code,
  so a symbol's 9-bit code is the symbol index itself); the stream ends
  with symbol 256 and is padded with zero bits so the decoder finishes
  with ``nBitBuf == 0 && nInPos == nInSize``.
* LZX: ``BLOCK_UNCOMPRESSED`` (type 3) with either the 32768 short-size
  flag or an explicit 16-bit block size, then 12 bytes of R0/R1/R2 and
  raw payload; odd payloads carry the required zero pad byte.
"""

import hashlib
import os
import struct

BLOCK = 0xD0
OUT = "corpus"

RES_METADATA = 0x02
RES_COMPRESSED = 0x04

FLAG_COMPRESSION = 1 << 1
FLAG_XPRESS = 1 << 17
FLAG_LZX = 1 << 18


def res_info(pack: int, off: int, unpack: int, flags: int = 0) -> bytes:
    """24-byte WIM resource descriptor."""
    return struct.pack("<Q", (flags << 56) | pack) + struct.pack(
        "<QQ", off, unpack)


def dir_entry(length: int, attrs: int, subdir: int, sha: bytes,
              name: str = "", alt: int = 0) -> bytes:
    """0x66-byte new-format directory entry + UTF-16LE name."""
    de = bytearray(0x66)
    struct.pack_into("<Q", de, 0x00, length)
    struct.pack_into("<I", de, 0x08, attrs)
    struct.pack_into("<Q", de, 0x10, subdir)
    de[0x40:0x54] = sha
    struct.pack_into("<H", de, 0x60, alt)
    struct.pack_into("<H", de, 0x62, 0)
    nb = name.encode("utf-16-le")
    struct.pack_into("<H", de, 0x64, len(nb))
    body = bytes(de) + nb + b"\x00\x00" if nb else bytes(de)
    return body + bytes(length - len(body))


def align8(v: int) -> int:
    return (v + 7) & ~7


class BitWriter:
    """MSB-first bits packed into little-endian 16-bit words (the exact
    layout both XPRESS and LZX decoders consume)."""

    def __init__(self) -> None:
        self._bits = 0
        self._count = 0
        self.words = bytearray()

    def put(self, value: int, nbits: int) -> None:
        for i in range(nbits - 1, -1, -1):
            self._bits = (self._bits << 1) | ((value >> i) & 1)
            self._count += 1
            if self._count == 16:
                self.words += struct.pack("<H", self._bits & 0xFFFF)
                self._bits = 0
                self._count = 0

    def pad(self) -> None:
        """Zero-pad to the next 16-bit boundary."""
        while self._count:
            self.put(0, 1)


def xpress_encode(out_size: int, tokens: list) -> bytes:
    """XPRESS Huffman chunk: 256-byte all-9 lens table + 9-bit symbols.

    ``tokens`` is a list of (symbol, extra_bits_value, extra_bits_count)
    triples; the caller appends the 256 terminator last.
    """
    table = b"\x99" * 256
    w = BitWriter()
    for sym, extra, ebits in tokens:
        w.put(sym, 9)
        if ebits:
            w.put(extra, ebits)
    # Simulate the decoder's just-in-time word loads to find how many
    # words the stream must contain: init primes 2, each read refills
    # when fewer than 16 bits remain.
    total_bits = w._count + 16 * (len(w.words) // 2)
    count = 32  # bits available after the two primed words
    consumed = 0
    loaded = 2
    for sym, extra, ebits in tokens:
        need = 9 + ebits
        # Read the symbol bit-by-bit exactly like decodeSym does: the
        # refill happens after every read_bits call, model it per 9+ebits
        # chunk which is equivalent for the load counter.
        consumed += need
        count -= need
        while count < 16:
            count += 16
            loaded += 1
    assert total_bits <= loaded * 16, "symbols must fit loaded words"
    w.pad()
    # `loaded` words must be present in the stream.
    need_bytes = loaded * 2
    assert len(w.words) <= need_bytes
    while len(w.words) < need_bytes:
        w.words += b"\x00\x00"
    return table + bytes(w.words)


def xpress_run(byte: int, n: int) -> list:
    """Tokens producing ``byte`` repeated ``n`` times: one literal, then
    offset-1 length-17 matches (symbol 270), then literal tail."""
    if n <= 0:
        return []
    toks = [(byte, 0, 0)]
    n -= 1
    while n >= 17:
        toks.append((256 + 14, 0, 0))  # match sym 270: len 17, off 1
        n -= 17
    toks += [(byte, 0, 0)] * n
    return toks


def lzx_uncomp_block(payload: bytes, window_bits: int = 15) -> bytes:
    """One LZX BLOCK_UNCOMPRESSED stream for a whole chunk."""
    w = BitWriter()
    w.put(3, 3)  # block type 3 (uncompressed)
    if len(payload) == 32768:
        w.put(1, 1)  # short form: block size 32768
    else:
        w.put(0, 1)
        w.put(len(payload), 16)
        if window_bits >= 16:
            w.put(0, 8)
    w.pad()  # align16(true): drop nonzero-check zero bits
    out = bytearray(w.words)
    out += struct.pack("<III", 1, 1, 1)  # R0/R1/R2
    out += payload
    if len(payload) & 1:
        out += b"\x00"  # odd-size pad byte before any next block
    return bytes(out)


def compressed_resource(unpack: int, chunks: list) -> tuple:
    """Build (packed bytes, pack_size) for a chunked resource.

    ``chunks`` is a list of already-encoded compressed chunks (or raw
    bytes for stored passthrough chunks); the chunk table stores the
    cumulative end offsets of all but the last chunk.
    """
    table = b""
    end = 0
    for c in chunks[:-1]:
        end += len(c)
        table += struct.pack("<I", end)
    packed = table + b"".join(chunks)
    return packed, len(packed)


def stream_entry(pack: int, off: int, unpack: int, sha: bytes,
                 flags: int = 0, ref: int = 1, part: int = 1) -> bytes:
    """50-byte offset-table stream descriptor."""
    return res_info(pack, off, unpack, flags) + struct.pack(
        "<HI", part, ref) + sha


def wim_image(flags: int, chunk_size: int, streams: list,
              meta_packed: bytes, meta_unpack: int, meta_sha: bytes,
              meta_flags: int) -> bytes:
    """Assemble the full image: header | stream data | metadata | LUT."""
    off = BLOCK
    lut = b""
    blob = b""
    for pack_bytes, unpack, sha, sflags in streams:
        off64 = off
        lut += stream_entry(len(pack_bytes), off64, unpack, sha, sflags)
        blob += pack_bytes
        off += len(pack_bytes)
    meta_off = off
    lut += stream_entry(len(meta_packed), meta_off, meta_unpack,
                        meta_sha, meta_flags)
    blob += meta_packed
    off += len(meta_packed)
    lut_off = off

    hdr = bytearray(BLOCK)
    hdr[0:8] = b"MSWIM\x00\x00\x00"
    struct.pack_into("<I", hdr, 0x08, BLOCK)
    struct.pack_into("<I", hdr, 0x0C, 0x10C00)
    struct.pack_into("<I", hdr, 0x10, flags)
    struct.pack_into("<I", hdr, 0x14, chunk_size)
    hdr[0x18:0x28] = bytes(range(16))
    struct.pack_into("<H", hdr, 0x28, 1)
    struct.pack_into("<H", hdr, 0x2A, 1)
    hdr[0x2C:0x2C + 0x18] = res_info(len(lut), lut_off, len(lut))
    return bytes(hdr) + blob + lut


def build_xpress() -> bytes:
    """XPRESS image: two-chunk compressed file, match-path file,
    stored file, subdir, compressed metadata."""
    content_big = b"A" * 32768 + b"B" * 7232
    c_big_0 = xpress_encode(32768, xpress_run(ord("A"), 32768)
                          + [(256, 0, 0)])
    c_big_1 = xpress_encode(7232, xpress_run(ord("B"), 7232)
                            + [(256, 0, 0)])
    pack_big, pack_big_sz = compressed_resource(
        len(content_big), [c_big_0, c_big_1])
    h_big = hashlib.sha1(content_big).digest()

    content_match = b"WIM xpress test " + b"WIM xpress test"
    toks = [(c, 0, 0) for c in b"WIM xpress test "]
    # match sym: offset slot 4 (offset = 16 + 4 bits), len hdr 12 (15)
    toks.append((256 + 4 * 16 + 12, 0, 4))
    toks.append((256, 0, 0))
    pack_match = xpress_encode(len(content_match), toks)
    h_match = hashlib.sha1(content_match).digest()

    content_stored = b"stored member in compressed WIM\n"
    h_stored = hashlib.sha1(content_stored).digest()

    content_inner = b"inner\n"
    h_inner = hashlib.sha1(content_inner).digest()

    big_len = align8(0x66 + len("big.bin".encode("utf-16-le")) + 2)
    match_len = align8(0x66 + len("match.bin".encode("utf-16-le")) + 2)
    stored_len = align8(0x66 + len("stored.bin".encode("utf-16-le")) + 2)
    inner_len = align8(0x66 + len("inner.txt".encode("utf-16-le")) + 2)
    sub_children_off = 0x78 + big_len + match_len + stored_len \
        + align8(0x66 + len("sub".encode("utf-16-le")) + 2) + 8
    children = b""
    children += dir_entry(big_len, 0x80, 0, h_big, "big.bin")
    children += dir_entry(match_len, 0x80, 0, h_match, "match.bin")
    children += dir_entry(stored_len, 0x80, 0, h_stored, "stored.bin")
    children += dir_entry(
        align8(0x66 + len("sub".encode("utf-16-le")) + 2), 0x10,
        sub_children_off, bytes(20), "sub")
    children += b"\x00" * 8
    children += dir_entry(inner_len, 0x80, 0, h_inner, "inner.txt")
    children += b"\x00" * 8
    meta = struct.pack("<II", 8, 0) + dir_entry(
        0x68, 0x10, 0x78, bytes(20)) + b"\x00" * 8 + children

    # Compress metadata as one XPRESS chunk.
    m_toks = [(c, 0, 0) for c in meta]
    # Pad with len-17 offset-1 matches where beneficial is unnecessary;
    # all-literal stream is a valid chunk regardless of size ratio.
    m_toks.append((256, 0, 0))
    meta_pack = xpress_encode(len(meta), m_toks)
    meta_sha = hashlib.sha1(meta).digest()

    streams = [
        (pack_big, len(content_big), h_big, RES_COMPRESSED),
        (pack_match, len(content_match), h_match, RES_COMPRESSED),
        (content_stored, len(content_stored), h_stored, 0),
        (content_inner, len(content_inner), h_inner, 0),
    ]
    return wim_image(FLAG_COMPRESSION | FLAG_XPRESS, 32768, streams,
                     meta_pack, len(meta), meta_sha,
                     RES_METADATA | RES_COMPRESSED)


def build_lzx() -> bytes:
    """LZX image: multi-chunk file mixing a stored passthrough chunk
    with a decoded BLOCK_UNCOMPRESSED chunk, single-chunk members, an
    odd-size chunk, an E8-magic member, stored member, compressed
    metadata."""
    content_mixed = b"M" * 32768 + b"N" * 7232
    c_mix_0 = content_mixed[:32768]  # stored passthrough chunk
    c_mix_1 = lzx_uncomp_block(content_mixed[32768:])
    pack_mixed, _ = compressed_resource(len(content_mixed),
                                        [c_mix_0, c_mix_1])
    h_mixed = hashlib.sha1(content_mixed).digest()

    content_small = b"S" * 7232
    pack_small = lzx_uncomp_block(content_small)
    h_small = hashlib.sha1(content_small).digest()

    content_odd = b"O" * 101
    pack_odd = lzx_uncomp_block(content_odd)
    h_odd = hashlib.sha1(content_odd).digest()

    # E8 member: the magic 0xE8 with an abs offset >= 12000000 so the
    # undo pass leaves the bytes untouched.
    content_e8 = b"pre" + b"\xE8\xff\xff\xff\x7f" + b"post"
    pack_e8 = lzx_uncomp_block(content_e8)
    h_e8 = hashlib.sha1(content_e8).digest()

    content_stored = b"stored lzx member\n"
    h_stored = hashlib.sha1(content_stored).digest()

    big_len = align8(0x66 + len("mixed.bin".encode("utf-16-le")) + 2)
    small_len = align8(0x66 + len("small.bin".encode("utf-16-le")) + 2)
    odd_len = align8(0x66 + len("odd.bin".encode("utf-16-le")) + 2)
    e8_len = align8(0x66 + len("e8.bin".encode("utf-16-le")) + 2)
    stored_len = align8(0x66 + len("stored.bin".encode("utf-16-le")) + 2)
    children = b""
    children += dir_entry(big_len, 0x80, 0, h_mixed, "mixed.bin")
    children += dir_entry(small_len, 0x80, 0, h_small, "small.bin")
    children += dir_entry(odd_len, 0x80, 0, h_odd, "odd.bin")
    children += dir_entry(e8_len, 0x80, 0, h_e8, "e8.bin")
    children += dir_entry(stored_len, 0x80, 0, h_stored, "stored.bin")
    children += b"\x00" * 8
    meta = struct.pack("<II", 8, 0) + dir_entry(
        0x68, 0x10, 0x78, bytes(20)) + b"\x00" * 8 + children

    # Compress metadata as one LZX uncompressed chunk.
    meta_pack = lzx_uncomp_block(meta)
    meta_sha = hashlib.sha1(meta).digest()

    streams = [
        (pack_mixed, len(content_mixed), h_mixed, RES_COMPRESSED),
        (pack_small, len(content_small), h_small, RES_COMPRESSED),
        (pack_odd, len(content_odd), h_odd, RES_COMPRESSED),
        (pack_e8, len(content_e8), h_e8, RES_COMPRESSED),
        (content_stored, len(content_stored), h_stored, 0),
    ]
    return wim_image(FLAG_COMPRESSION | FLAG_LZX, 32768, streams,
                     meta_pack, len(meta), meta_sha,
                     RES_METADATA | RES_COMPRESSED)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    data = build_xpress()
    with open(f"{OUT}/test-xpress.wim", "wb") as f:
        f.write(data)
    print(f"corpus/test-xpress.wim {len(data)} bytes")
    data = build_lzx()
    with open(f"{OUT}/test-lzx.wim", "wb") as f:
        f.write(data)
    print(f"corpus/test-lzx.wim {len(data)} bytes")

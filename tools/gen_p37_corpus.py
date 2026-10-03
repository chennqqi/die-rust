#!/usr/bin/env python3
"""Phase 37 corpus generator: WIM image.

Synthesizes a minimal uncompressed WIM (v1.13, 0xD0 header) that
satisfies the upstream `XWIM::initUnpack` validation chain:

* offset table entries are 50-byte stream descriptors with unique,
  non-empty SHA-1 hashes and honest refcounts;
* physical ranges (header / streams / metadata / offset table) do not
  overlap;
* the metadata resource's hash equals SHA-1 of the metadata blob;
* directory entries use the 0x66-byte new layout, 8-byte alignment,
  UTF-16LE names with terminators and a zero-length terminator;
* stream reference counts reconcile with the directory walk.

Records produced: ``readme.txt`` (file), ``subdir`` (dir),
``subdir/inner.bin`` (file).
"""

import hashlib
import os
import struct

BLOCK = 0xD0  # header size (new)
OUT = "corpus"


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
    de[0x40:0x54] = sha                # stream hash (20B)
    # ctime/mtime/atime at 0x28/0x30/0x38 left zero -> no mtime
    struct.pack_into("<H", de, 0x60, alt)
    struct.pack_into("<H", de, 0x62, 0)          # short name size
    nb = name.encode("utf-16-le")
    struct.pack_into("<H", de, 0x64, len(nb))    # file name size
    body = bytes(de) + nb + b"\x00\x00" if nb else bytes(de)
    return body + bytes(length - len(body))


def align8(v: int) -> int:
    return (v + 7) & ~7


def build() -> bytes:
    c1 = b"WIM phase 37 contents\n"
    c2 = bytes(range(0x20, 0x60))
    h1 = hashlib.sha1(c1).digest()
    h2 = hashlib.sha1(c2).digest()

    # --- metadata blob ---
    inner_len = align8(0x66 + len("inner.bin".encode("utf-16-le")) + 2)
    inner = dir_entry(inner_len, 0x80, 0, h2, "inner.bin")
    sub_children = inner + b"\x00" * 8

    readme_len = align8(0x66 + len("readme.txt".encode("utf-16-le")) + 2)
    readme = dir_entry(readme_len, 0x80, 0, h1, "readme.txt")
    subdir_len = align8(0x66 + len("subdir".encode("utf-16-le")) + 2)

    # Layout: root@8 (0x68), term@0x70, children@0x78, subterm,
    #         sub's children, term.
    root = dir_entry(0x68, 0x10, 0x78, bytes(20))
    children = readme
    children_off = 0x78
    subdir_off_in_children = children_off + len(readme)
    sub_children_off = subdir_off_in_children + subdir_len + 8
    subdir = dir_entry(subdir_len, 0x10, sub_children_off, bytes(20), "subdir")
    children += subdir + b"\x00" * 8 + sub_children

    metadata = struct.pack("<II", 8, 0) + root + b"\x00" * 8 + children
    assert len(metadata) == sub_children_off + len(sub_children)
    mh = hashlib.sha1(metadata).digest()

    # --- file layout ---
    off_c1 = BLOCK
    off_c2 = off_c1 + len(c1)
    off_meta = off_c2 + len(c2)
    off_lut = off_meta + len(metadata)

    lut = b""
    lut += struct.pack("<Q", len(c1)) + struct.pack("<QQ", off_c1, len(c1))
    lut += struct.pack("<HI", 1, 1) + h1
    lut += struct.pack("<Q", len(c2)) + struct.pack("<QQ", off_c2, len(c2))
    lut += struct.pack("<HI", 1, 1) + h2
    lut += struct.pack("<Q", (2 << 56) | len(metadata)) + struct.pack(
        "<QQ", off_meta, len(metadata))
    lut += struct.pack("<HI", 1, 1) + mh
    assert len(lut) == 150

    # --- header ---
    hdr = bytearray(BLOCK)
    hdr[0:8] = b"MSWIM\x00\x00\x00"
    struct.pack_into("<I", hdr, 0x08, BLOCK)
    struct.pack_into("<I", hdr, 0x0C, 0x10C00)
    struct.pack_into("<I", hdr, 0x10, 0)      # flags: uncompressed
    struct.pack_into("<I", hdr, 0x14, 0)      # chunk size
    hdr[0x18:0x28] = bytes(range(16))          # GUID
    struct.pack_into("<H", hdr, 0x28, 1)       # part number
    struct.pack_into("<H", hdr, 0x2A, 1)       # number of parts
    hdr[0x2C:0x2C + 0x18] = res_info(len(lut), off_lut, len(lut))
    # xml / boot-metadata / (no integrity for v10C00): zero

    return bytes(hdr) + c1 + c2 + metadata + lut


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    data = build()
    path = f"{OUT}/test.wim"
    with open(path, "wb") as f:
        f.write(data)
    print(f"{path} {len(data)} bytes")

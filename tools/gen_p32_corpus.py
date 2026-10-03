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


def lha_header(name, method, payload, level=0, crc16=None, is_dir=False):
    if crc16 is None:
        crc16 = crc16_arc(payload)
    name_b = name.encode("latin-1")
    if level == 0:
        hsize = 22 + len(name_b)
        h = bytearray()
        h.append(hsize)
        h.append(0)  # checksum placeholder
        h += method
        h += struct.pack("<I", len(payload))
        h += struct.pack("<I", len(payload))
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
    h += struct.pack("<I", len(payload))
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


if __name__ == "__main__":
    gen_arj()
    gen_lha()
    gen_ace()

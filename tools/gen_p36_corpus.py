#!/usr/bin/env python3
"""Phase 36 corpus generator: UDF filesystem image.

Synthesizes a minimal but *checksum-conforming* ECMA-167 UDF 1.50
volume that the upstream `XUDF::isValid` accepts on the strict anchor
probe path (sector-256 AVDP with valid tag checksum, descriptor
version, reserved byte, TagLocation and DescriptorCRC).

Layout (2048-byte logical blocks):
  16..18  Volume Recognition Sequence (BEA01 / NSR03 / TEA01)
  32      Primary Volume Descriptor (tag 1)
  33      Logical Volume Descriptor (tag 6, FSD extent at +248)
  34      Terminating Descriptor (tag 8)
  40      File Set Descriptor (tag 256, root ICB long_ad at +352)
  41      Root directory File Entry (tag 261, dir data at 42)
  42      Root directory data (parent FID + file FID + dir FID)
  43      hello.txt File Entry (short_ad data at 44)
  44      hello.txt data
  45      sub/ File Entry (dir data at 46)
  46      sub/ directory data (parent FID + file FID)
  47      sub/deep.bin File Entry (short_ad data at 48)
  48      sub/deep.bin data
  256     Anchor Volume Descriptor Pointer (tag 2)
"""

import struct

BLOCK = 2048
OUT = "corpus"


def tag_checksum(tag: bytes) -> int:
    """ECMA-167 4/7.2.3: sum of tag bytes 0-3 and 5-15 mod 256."""
    return sum(b for i, b in enumerate(tag[:16]) if i != 4) & 0xFF


def descriptor_crc(data: bytes) -> int:
    """ECMA-167 Annex A CRC-ITU-T (0x1021, init 0, no reflection)."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def descriptor(tag_id: int, body: bytes, location: int, version: int = 2,
               crc_len: int = 0) -> bytes:
    """Build a 2048-byte sector holding a descriptor with a valid tag.

    `crc_len` is the number of body bytes covered by DescriptorCRC.
    """
    tag = bytearray(16)
    struct.pack_into("<H", tag, 0, tag_id)
    struct.pack_into("<H", tag, 2, version)
    tag[5] = 0
    struct.pack_into("<H", tag, 6, 0)  # TagSerialNumber
    body_crc = descriptor_crc(body[:crc_len]) if crc_len else 0
    struct.pack_into("<H", tag, 8, body_crc)
    struct.pack_into("<H", tag, 10, crc_len)
    struct.pack_into("<I", tag, 12, location)
    tag[4] = tag_checksum(bytes(tag))
    sector = bytes(tag) + body
    return sector + bytes(BLOCK - len(sector))


def vrs_entry(ident: bytes) -> bytes:
    """2048-byte Volume Structure Descriptor."""
    s = bytearray(BLOCK)
    s[0] = 0
    s[1:6] = ident
    s[6] = 1
    return bytes(s)


def long_ad(length: int, loc: int, part: int = 0) -> bytes:
    """16-byte long_ad extent descriptor."""
    return struct.pack("<IIH", length, loc, part) + bytes(6)


def file_entry(icb_file_type: int, alloc_type: int, info_len: int,
               alloc_descs: bytes, unique: int) -> bytes:
    """File Entry body after the 16-byte tag (fixed 160 bytes) + ADs.

    Body offsets mirror what upstream reads: ICBTag file type at
    descriptor +28 (body +12), ICBTag flags at +34 (body +18),
    InformationLength at +56 (body +40), LenExtAttrs at +168
    (body +152), LenAllocDescs at +172 (body +156).
    """
    b = bytearray(160)
    struct.pack_into("<I", b, 0, 0)       # ICBTag.priorLinked
    b[12] = icb_file_type                  # ICBTag file type
    struct.pack_into("<H", b, 18, alloc_type & 0x07)  # ICBTag flags
    struct.pack_into("<I", b, 20, 0)       # uid
    struct.pack_into("<I", b, 24, 0)       # gid
    struct.pack_into("<I", b, 28, 0)       # permissions
    struct.pack_into("<H", b, 32, 1)       # file link count
    struct.pack_into("<Q", b, 40, info_len)   # InformationLength
    struct.pack_into("<Q", b, 48, (info_len + BLOCK - 1) // BLOCK)
    struct.pack_into("<Q", b, 144, unique)    # UniqueID
    struct.pack_into("<I", b, 152, 0)         # LengthOfExtendedAttributes
    struct.pack_into("<I", b, 156, len(alloc_descs))  # LengthOfADs
    return bytes(b) + alloc_descs


def file_id(chars: int, icb_loc: int, name: bytes = b"") -> bytes:
    """File Identifier Descriptor (tag 257, incl. 16-byte tag).

    Upstream reads: characteristics +18, len-file-id +19, ICB loc
    +24, len-impl-use +36, name at +38+impl-use (descriptor
    offsets); FID size = 38 + impl + name, 4-aligned.
    """
    body_len = 22 + len(name)
    b = bytearray(body_len)
    struct.pack_into("<H", b, 0, 1)      # FileVersionNumber
    b[2] = chars                          # FileCharacteristics
    b[3] = len(name)                      # LengthOfFileIdentifier
    b[4:20] = long_ad(0, icb_loc)         # ICB long_ad (loc at +8)
    struct.pack_into("<H", b, 20, 0)      # LengthOfImplementationUse
    b[22:22 + len(name)] = name

    tag = bytearray(16)
    struct.pack_into("<H", tag, 0, 257)
    struct.pack_into("<H", tag, 2, 2)
    struct.pack_into("<I", tag, 12, 0)
    tag[4] = tag_checksum(bytes(tag))

    fid_len = 38 + len(name)
    padded = (fid_len + 3) & ~3
    return bytes(tag) + bytes(b) + bytes(padded - fid_len)


def build() -> bytes:
    image = bytearray(BLOCK * 300)

    hello = b"Hello UDF Phase 36!\n"
    deep = bytes(range(64))

    # --- VRS (sectors 16..18) ---
    image[16 * BLOCK:17 * BLOCK] = vrs_entry(b"BEA01")
    image[17 * BLOCK:18 * BLOCK] = vrs_entry(b"NSR03")
    image[18 * BLOCK:19 * BLOCK] = vrs_entry(b"TEA01")

    # --- VDS (sectors 32..34) ---
    pvd = bytearray(64)
    pvd[20:32] = b"RUST-UDF-TEST"  # VolumeIdentifier at body+20
    image[32 * BLOCK:33 * BLOCK] = descriptor(1, bytes(pvd), 32, crc_len=64)

    lvd = bytearray(456)
    # Upstream quirk: it reads descriptor offset +248 (body +232) as
    # the FSD *sector number* directly — the ECMA extent_ad length
    # field position — rather than the location field at +252.
    struct.pack_into("<II", lvd, 232, 40, 0)
    image[33 * BLOCK:34 * BLOCK] = descriptor(6, bytes(lvd), 33, crc_len=456)

    image[34 * BLOCK:35 * BLOCK] = descriptor(8, bytes(496), 34, crc_len=0)

    # --- FSD (sector 40): root ICB long_ad at +352 -> sector 41 ---
    fsd = bytearray(368)
    fsd[336:352] = long_ad(BLOCK, 41)
    image[40 * BLOCK:41 * BLOCK] = descriptor(256, bytes(fsd), 40, crc_len=368)

    # --- Root FE (41) + dir data (42) ---
    root_fids = (file_id(0x0A, 41) +                      # parent (dir|parent)
                 file_id(0x00, 43, b"\x08hello.txt") +     # file
                 file_id(0x02, 45, b"\x08sub"))            # dir
    ad = struct.pack("<II", len(root_fids), 42)
    body = file_entry(4, 0, len(root_fids), ad, 1)
    image[41 * BLOCK:42 * BLOCK] = descriptor(261, body, 41, crc_len=len(body))
    image[42 * BLOCK:43 * BLOCK] = root_fids + bytes(BLOCK - len(root_fids))

    # --- hello.txt FE (43) + data (44) ---
    ad = struct.pack("<II", len(hello), 44)
    body = file_entry(5, 0, len(hello), ad, 2)
    image[43 * BLOCK:44 * BLOCK] = descriptor(261, body, 43, crc_len=len(body))
    image[44 * BLOCK:44 * BLOCK + len(hello)] = hello

    # --- sub/ FE (45) + dir data (46) ---
    sub_fids = (file_id(0x0A, 41) +                       # parent -> root
                file_id(0x00, 47, b"\x08deep.bin"))       # file
    ad = struct.pack("<II", len(sub_fids), 46)
    body = file_entry(4, 0, len(sub_fids), ad, 3)
    image[45 * BLOCK:46 * BLOCK] = descriptor(261, body, 45, crc_len=len(body))
    image[46 * BLOCK:47 * BLOCK] = sub_fids + bytes(BLOCK - len(sub_fids))

    # --- sub/deep.bin FE (47) + data (48) ---
    ad = struct.pack("<II", len(deep), 48)
    body = file_entry(5, 0, len(deep), ad, 4)
    image[47 * BLOCK:48 * BLOCK] = descriptor(261, body, 47, crc_len=len(body))
    image[48 * BLOCK:48 * BLOCK + len(deep)] = deep

    # --- AVDP (sector 256): main VDS extent sectors 32..34 ---
    avdp = bytearray(496)
    struct.pack_into("<II", avdp, 0, 3 * BLOCK, 32)   # main VDS
    struct.pack_into("<II", avdp, 8, 3 * BLOCK, 32)   # reserve VDS
    image[256 * BLOCK:257 * BLOCK] = descriptor(2, bytes(avdp), 256,
                                              crc_len=496)
    return bytes(image)


if __name__ == "__main__":
    import os
    os.makedirs(OUT, exist_ok=True)
    data = build()
    path = f"{OUT}/test.udf"
    with open(path, "wb") as f:
        f.write(data)
    print(f"{path} {len(data)} bytes")

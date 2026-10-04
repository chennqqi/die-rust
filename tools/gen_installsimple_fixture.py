#!/usr/bin/env python3
"""Generate a synthetic InstallSimple package for differential testing.

Upstream `XInstallSimple` decodes overlay records by running the
UPX-unpacked host stub's in-image decoder under XEmulator. This script
builds a fully synthetic package along the same structure so both the
upstream oracle (`xemulator-oracle unpack`) and the Rust
`extract_installsimple` path can be exercised end to end without a real
InstallSimple sample:

  * an unpacked "decoder stub" PE32 (image base 0x400000) whose init and
    driver entry points start with the byte signatures upstream's
    `is_load_decoder_image` requires, followed by a tiny pass-through
    decoder (copies record bodies to the output region, honours the
    OUTER context block);
  * the stub wrapped in a synthetic UPX PE container (UPX0/UPX1/.rsrc
    sections, version>=10 pack header, raw DEFLATE stream);
  * an InstallSimple overlay of two range-coded records — one payload
    and one manifest — in the upstream length/marker framing where the
    next record begins at `pos + length - 6`.

The synthetic decoder does NOT reproduce the real range coder; it only
exercises the emulator plumbing (init/driver calls, OUTER block, step
budget, manifest grammar) which is what `xinstallsimple.cpp` adds on
top of XEmulator.

Usage: gen_installsimple_fixture.py <output-file>
"""

import struct
import sys
import zlib

IS_IMAGE_BASE = 0x400000

# --------------------------------------------------------------------
# Synthetic decoder stub (this is what UPX decompression must yield).
# --------------------------------------------------------------------

# Upstream signature prefixes (xinstallsimple.cpp is_load_decoder_image).
INIT_SIG = bytes.fromhex("53555657" "8b742414" "33d2" "8b6c2418" "8b46")
DRIVER_SIG = bytes.fromhex("8b442404" "56" "8b7020" "85f6" "7509" "b8feffff")

CTX = 0x00900040  # IS_OUTER + 0x40, used as the decoder context pointer


def build_init() -> bytes:
    """Init entry at RVA 0x1000: sig bytes then context setup + ret 0x0c."""
    code = bytearray(INIT_SIG)
    # INIT_SIG ends mid-instruction: `8b 46` = mov eax,[esi+disp8].
    code += b"\x00"  # disp8 = 0 -> eax = [OUTER+0x00] (input ptr, harmless)
    code += b"\xc7\x46\x20" + struct.pack("<I", CTX)  # [OUTER+0x20] = ctx
    code += b"\x5f\x5e\x5d\x5b"  # pop edi, esi, ebp, ebx (restore sig pushes)
    code += b"\xc2\x0c\x00"  # ret 0x0c (stdcall, 3 args)
    return bytes(code)


def build_driver() -> bytes:
    """Driver entry at RVA 0x1090: sig bytes, -2 fail path, then copier.

    Per call: consume up to 64 bytes from input[src_pos] into
    output[total], updating OUTER+0x04 (remaining) and OUTER+0x18
    (total). First call skips the 14-byte record header (6 zero prefix
    + length + marker). Returns -1 once remaining reaches zero.
    """
    code = bytearray(DRIVER_SIG)
    # DRIVER_SIG ends mid `mov eax, imm32` (b8 fe ff ff + imm byte) and
    # starts with `push esi` — every return path must `pop esi` first.
    # esi==0 path (jz not taken): eax = 0xFFFFFFFE -> error, ret 4.
    code += b"\xff"  # imm8 -> 0xFFFFFFFE
    code += b"\x5e"  # pop esi (restore sig push)
    code += b"\xc2\x04\x00"  # ret 4  (offsets 18-20)
    assert len(code) == 21

    # --- real driver, reached via `jnz +9` from the sig -------------
    # esi = ctx ptr, eax = OUTER base
    code += b"\x83\x7e\x04\x00"  # cmp dword [esi+4], 0
    code += b"\x75\x11"  # jne started (+0x11 -> offset 44)
    code += b"\xc7\x46\x04\x01\x00\x00\x00"  # mov dword [esi+4], 1
    code += b"\xc7\x06\x0e\x00\x00\x00"  # mov dword [esi], 14 (skip hdr)
    code += b"\x83\x68\x04\x0e"  # sub dword [eax+4], 14
    # offset 45 = "started"
    code += b"\x8b\x48\x04"  # mov ecx, [eax+4]        ; remaining
    code += b"\x85\xc9"  # test ecx, ecx
    code += b"\x74\x2a"  # jz finished (+0x2a -> offset 93)
    code += b"\x83\xf9\x40"  # cmp ecx, 64
    code += b"\x76\x05"  # jbe n_ok
    code += b"\xb9\x40\x00\x00\x00"  # mov ecx, 64
    code += b"\x51"  # push ecx (save n)
    code += b"\x56"  # push esi (save ctx)
    code += b"\x8b\x10"  # mov edx, [eax]            ; input base
    code += b"\x03\x16"  # add edx, [esi]            ; + src_pos
    code += b"\x8b\x78\x10"  # mov edi, [eax+0x10]      ; output base
    code += b"\x03\x78\x18"  # add edi, [eax+0x18]      ; + total
    code += b"\x8b\xf2"  # mov esi, edx
    code += b"\xf3\xa4"  # rep movsb
    code += b"\x5e"  # pop esi
    code += b"\x59"  # pop ecx
    code += b"\x01\x0e"  # add [esi], ecx            ; src_pos += n
    code += b"\x29\x48\x04"  # sub [eax+4], ecx         ; remaining -= n
    code += b"\x01\x48\x18"  # add [eax+0x18], ecx      ; total += n
    code += b"\x31\xc0"  # xor eax, eax              ; status = continue
    code += b"\x5e"  # pop esi (restore sig push)
    code += b"\xc2\x04\x00"  # ret 4
    # offset 93 = "finished"
    assert len(code) == 93
    code += b"\x83\xc8\xff"  # or eax, -1
    code += b"\x5e"  # pop esi
    code += b"\xc2\x04\x00"  # ret 4
    return bytes(code)


def build_pe(
    sections,
    entry_rva,
    size_of_image,
    image_base=IS_IMAGE_BASE,
    section_alignment=0x1000,
    file_alignment=0x200,
    headers_size=0x200,
) -> bytes:
    """Assemble a minimal PE32 from (name, vsize, rva, raw) tuples.

    `raw` is the section file content; raw pointer is appended
    sequentially at `headers_size`. Returns (file_bytes, raw_offsets).
    """
    file_alignment = max(file_alignment, 0x200)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x14C,  # Machine I386
        len(sections),
        0,  # TimeDateStamp
        0,
        0,
        0xE0,  # SizeOfOptionalHeader
        0x010F,  # Characteristics: reloc stripped, exec, 32bit, 1/2/4g
    )

    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)  # PE32 magic
    struct.pack_into("<I", opt, 16, entry_rva)
    struct.pack_into("<I", opt, 20, sections[0][2] if sections else 0)  # BaseOfCode
    struct.pack_into("<I", opt, 28, image_base)
    struct.pack_into("<I", opt, 32, section_alignment)
    struct.pack_into("<I", opt, 36, file_alignment)
    struct.pack_into("<HHHHHH", opt, 40, 4, 0, 0, 0, 4, 0)
    struct.pack_into("<I", opt, 56, size_of_image)
    struct.pack_into("<I", opt, 60, headers_size)
    struct.pack_into("<H", opt, 68, 3)  # Subsystem CUI
    struct.pack_into("<I", opt, 72, 0x100000)  # SizeOfStackReserve
    struct.pack_into("<I", opt, 76, 0x1000)  # SizeOfStackCommit
    struct.pack_into("<I", opt, 80, 0x100000)  # SizeOfHeapReserve
    struct.pack_into("<I", opt, 84, 0x1000)  # SizeOfHeapCommit
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes

    out = bytearray(dos + b"PE\0\0" + coff + bytes(opt))

    raw_ptr = headers_size
    offsets = []
    for name, vsize, rva, raw in sections:
        raw_size = (len(raw) + file_alignment - 1) & ~(file_alignment - 1)
        offsets.append(raw_ptr if raw_size else 0)
        sh = bytearray(40)
        sh[0:8] = name[:8].ljust(8, b"\0")
        struct.pack_into("<IIIIIIHHI", sh, 8, vsize, rva,
                         raw_size, offsets[-1], 0, 0, 0, 0,
                         0x60000020)  # code/exec/read
        out += sh
        raw_ptr += raw_size

    out += b"\0" * (headers_size - len(out))
    for (_, _, _, raw), off in zip(sections, offsets):
        if off == 0 and not raw:
            continue
        out += raw + b"\0" * (headers_size and ((len(raw) + 0x1FF) & ~0x1FF) - len(raw))
    return bytes(out)


def build_decoder_stub() -> bytes:
    """Unpacked decoder image: base 0x400000, init@0x1000, driver@0x1090."""
    text = bytearray(0x1000)
    text[0:len(build_init())] = build_init()
    text[0x90:0x90 + len(build_driver())] = build_driver()

    file = build_pe(
        sections=[(b".text", 0xA000, 0x1000, bytes(text))],
        entry_rva=0x1000,
        size_of_image=0xB000,
    )
    return file


# --------------------------------------------------------------------
# UPX wrap + InstallSimple overlay
# --------------------------------------------------------------------

def adler32(b: bytes) -> int:
    return zlib.adler32(b) & 0xFFFFFFFF


def build_upx_wrapper(stub: bytes) -> bytes:
    """Wrap `stub` in a synthetic UPX PE (method=DEFLATE, v13 header)."""
    headers_size = 0x200
    # payload = stub image data (file bytes at/after size_of_headers)
    #         + extra-info block (NT headers + section headers) + u32.
    image_data = stub[headers_size:]
    extra_off = len(image_data)
    nt = stub[0x80 : 0x80 + 4 + 20 + 0xE0]  # sig + coff + opt
    sect = stub[0x80 + 4 + 20 + 0xE0 : 0x80 + 4 + 20 + 0xE0 + 40]  # 1 sect
    payload = image_data + nt + sect + struct.pack("<I", extra_off)

    comp = zlib.compressobj(level=9, wbits=-15)
    cstream = comp.compress(payload) + comp.flush()

    pack = bytearray(32)
    pack[0:4] = b"UPX!"
    pack[4] = 13  # version >=10 -> 32-byte header, filter byte present
    pack[5] = 9  # UPX_F_W32PE_I386
    pack[6] = 15  # M_DEFLATE
    pack[7] = 8  # level
    struct.pack_into("<I", pack, 8, adler32(payload))  # u_adler
    struct.pack_into("<I", pack, 12, adler32(cstream))  # c_adler
    struct.pack_into("<I", pack, 16, len(payload))  # u_len
    struct.pack_into("<I", pack, 20, len(cstream))  # c_len
    struct.pack_into("<I", pack, 24, len(stub))  # u_file_size
    pack[28] = 0  # filter

    upx1_raw = bytes(pack) + cstream
    upx1_raw_size = (len(upx1_raw) + 0x1FF) & ~0x1FF
    rsrc_off = headers_size + upx1_raw_size

    wrapper = build_pe(
        sections=[
            (b"UPX0", 0xD000, 0x1000, b""),
            (b"UPX1", 0x1000, 0xE000, upx1_raw),
            (b".rsrc", 0x1000, 0xF000, b"\0" * 0x200),
        ],
        entry_rva=0xE830,  # InstallSimple 3.5.2 AEP marker
        size_of_image=0x10000,
    )
    assert len(wrapper) == rsrc_off + 0x200
    return wrapper


def record(body: bytes) -> bytes:
    """InstallSimple record: u32 length (14 + body) + FFFFFFFF + body."""
    return struct.pack("<I", 14 + len(body)) + b"\xff\xff\xff\xff" + body


def manifest(names) -> bytes:
    """Manifest record body: 19 zeros, marker, names + 10B descriptors."""
    body = bytearray(19) + b"InstallSimple\0\0"
    for n in names:
        body += n.encode("ascii") + b"\0" + bytes(range(10))
    return bytes(body)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.splitlines()[0])
        return 2

    payload_data = b"synthetic installsimple payload\n" * 5  # 160 bytes
    name = "payload.bin"

    stub = build_decoder_stub()
    wrapper = build_upx_wrapper(stub)

    overlay = record(payload_data) + record(manifest([name]))
    package = wrapper + overlay

    with open(sys.argv[1], "wb") as f:
        f.write(package)

    print(
        f"wrote {sys.argv[1]}: package={len(package)} stub={len(stub)} "
        f"wrapper={len(wrapper)} overlay={len(overlay)} "
        f"payload={len(payload_data)} name={name}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

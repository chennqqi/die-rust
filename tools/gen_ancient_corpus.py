"""Generate the NFDCompression `ancient` corpus fixtures (RNC/TPWM/pack).

Each file is a hand-crafted minimal stream verified against the pinned
upstream oracle (`tools/nfd-oracle`). Regeneration is deterministic.
"""
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def crc16(data: bytes, acc: int = 0) -> int:
    """Reflected CRC16 (poly 0xA001), matching upstream `CRC16`."""
    for b in data:
        a = acc ^ b
        for _ in range(8):
            a = (a >> 1) ^ (0xA001 if a & 1 else 0)
        acc = a & 0xFFFF
    return acc


def gen_tpwm() -> bytes:
    # MSB bit reader over bytes 8..; flag 0 => literal byte follows.
    return b"TPWM" + struct.pack(">I", 4) + bytes([0x00]) + b"ABCD"


def gen_pack() -> bytes:
    # 0x1f1e "new" pack: maxLevel=1, levelCounts=[0] (+2 -> 'A' & EOF),
    # four zero bits decode "AAAA"; two trailing bytes (allowed <=16).
    return (
        b"\x1f\x1e"
        + struct.pack(">I", 4)
        + bytes([1, 0, 0x41, 0x00])
        + b"\x00\x00"
    )


def gen_rnc1() -> bytes:
    # RNC1 new stream, LSB bits with LE16 refill:
    # flags=0; lit table len=4 lens[1,0,0,2]; dist/len tables empty;
    # count=1 -> single literal run of 4 ("ABCD").
    bits: list[int] = []

    def put(v: int, n: int) -> None:
        for i in range(n):
            bits.append((v >> i) & 1)

    put(0, 2)
    put(4, 5)
    for v in (1, 0, 0, 2):
        put(v, 4)
    put(0, 5)
    put(0, 5)
    put(1, 16)
    put(1, 1)
    put(0, 1)
    put(0, 2)
    stream = bytearray()
    for i in range(0, len(bits), 16):
        w = 0
        for j, b in enumerate(bits[i : i + 16]):
            w |= b << j
        stream += struct.pack("<H", w)
    stream += b"ABCD"
    packed, raw = bytes(stream), b"ABCD"
    hdr = (
        b"RNC\x01"
        + struct.pack(">I", len(raw))
        + struct.pack(">I", len(packed))
        + struct.pack(">H", crc16(raw))
        + struct.pack(">H", crc16(packed))
        + b"\x00\x01"
    )
    return hdr + packed


def gen_rnc2() -> bytes:
    # RNC2 new stream, MSB byte-refill bits:
    # pad,pad ; LIT(0) ; 'A' ; CND(1111) ; count=0 ; done(1)
    # -> byte0 0b00011111, literal byte, count byte.
    stream = bytes([0x1F]) + b"A" + bytes([0x00])
    raw = b"A"
    hdr = (
        b"RNC\x02"
        + struct.pack(">I", len(raw))
        + struct.pack(">I", len(stream))
        + struct.pack(">H", crc16(raw))
        + struct.pack(">H", crc16(stream))
        + b"\x00\x01"
    )
    return hdr + stream


def main() -> None:
    out = ROOT / "corpus"
    files = {
        "minimal.tpwm": gen_tpwm(),
        "minimal.pack": gen_pack(),
        "minimal.rnc1": gen_rnc1(),
        "minimal.rnc2": gen_rnc2(),
    }
    for name, data in files.items():
        (out / name).write_bytes(data)
        print(f"wrote corpus/{name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()

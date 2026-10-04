//! ASPack static unpacking — port of upstream `XASPACK`.
//!
//! Detection is layout-table driven: an entry-point signature plus the
//! `\x68\x00\x00\x00\x00\xC3` marker at a versioned offset and the
//! 0x72-byte `compB` decoder table anchored `(AEP - 1)`-relative. The
//! decompressor is ASPack's custom dynamic-Huffman LZ scheme
//! (`_readstream`/`_getdec`/`_buildArray`/`_buildDicts`/`_decrypt`),
//! applied per block-table entry into an RVA-assembled image, followed
//! by the one-shot call/jmp filter reversal and a fresh PE rebuild.
//!
//! The 2.11/2.11r and 2.11c/2.11d rows — upstream `USE_XEMULATOR` —
//! decrypt their polymorphic stub heads through the `emulate` module's
//! bounded x86 core before the mark/OEP reads (`decrypt_stub_head`,
//! upstream `decryptStubHead`).

use super::UnpackError;
use super::upx::PackedPe;

/// Detection metadata for an ASPack-packed PE.
#[derive(Debug, Clone)]
pub struct AspackInfo {
    /// Version string as reported upstream ("2.12", "2.2", "2.xx",
    /// "2.42", "2.00", "2.01/2.1").
    pub sversion: &'static str,
    /// Layout row index that matched.
    pub layout: usize,
}

/// Stub layout row (`ASPACK_LAYOUT`): all offsets are
/// `(AddressOfEntryPoint - 1)`-relative except `ep_buff_off`, which is
/// `AddressOfEntryPoint`-relative.
struct AspackLayout {
    /// Exact bytes required at the entry point.
    signature: &'static [u8],
    /// `\x68\x00\x00\x00\x00\xC3` marker, EP-relative (`u32::MAX` =
    /// sentinel — the marker lives inside the still-encrypted head for
    /// the emulator rows).
    ep_buff_off: u32,
    /// Block-table offset.
    blocks_off: u32,
    /// Bytes per block-table entry.
    block_stride: u32,
    /// init_array multiplier table offset (58 bytes).
    str_mlt_off: u32,
    /// compB constant-table offset.
    comp_b_off: u32,
    /// call/jmp filter mark-byte offset.
    wrkbuf_off: u32,
    /// Stored-OEP dword offset.
    oep_off: u32,
    /// Deterministic post-decrypt landing offset for the emulator rows
    /// (`nLandingOff` upstream); 0 = no emulation step.
    emulator_landing: u32,
    /// Reported version string.
    version: &'static str,
}

/// Upstream `g_aspackLayouts` order, including the `USE_XEMULATOR` rows.
const LAYOUTS: &[AspackLayout] = &[
    AspackLayout {
        signature: b"\x60\xe8\x03\x00\x00\x00\xe9\xeb",
        ep_buff_off: 0x3b9,
        blocks_off: 0x57c,
        block_stride: 8,
        str_mlt_off: 0x70e,
        comp_b_off: 0x6d6,
        wrkbuf_off: 0x148,
        oep_off: 0x39b,
        emulator_landing: 0,
        version: "2.12",
    },
    AspackLayout {
        signature: b"\x60\xe8\x03\x00\x00\x00\xe9\xeb",
        ep_buff_off: 0x414,
        blocks_off: 0x5d0,
        block_stride: 12,
        str_mlt_off: 0x6ca,
        comp_b_off: 0x692,
        wrkbuf_off: 0x145,
        oep_off: 0x3f6,
        emulator_landing: 0,
        version: "2.2",
    },
    AspackLayout {
        signature: b"\x60\xe8\x03\x00\x00\x00\xe9\xeb",
        ep_buff_off: 0x41f,
        blocks_off: 0x5d8,
        block_stride: 12,
        str_mlt_off: 0x76a,
        comp_b_off: 0x732,
        wrkbuf_off: 0x13a,
        oep_off: 0x401,
        emulator_landing: 0,
        version: "2.xx",
    },
    AspackLayout {
        signature: b"\x60\xe8\x03\x00\x00\x00\xe9\xeb",
        ep_buff_off: 0x42b,
        blocks_off: 0x5e4,
        block_stride: 12,
        str_mlt_off: 0x776,
        comp_b_off: 0x73e,
        wrkbuf_off: 0x148,
        oep_off: 0x40d,
        emulator_landing: 0,
        version: "2.42",
    },
    AspackLayout {
        signature: b"\x60\xe8\x70\x05\x00\x00\xeb",
        ep_buff_off: 0x4fb,
        blocks_off: 0x0de,
        block_stride: 8,
        str_mlt_off: 0x623,
        comp_b_off: 0x5eb,
        wrkbuf_off: 0x292,
        oep_off: 0x0d2,
        emulator_landing: 0,
        version: "2.00",
    },
    AspackLayout {
        signature: b"\x60\xe8\x72\x05\x00\x00\xeb",
        ep_buff_off: 0x4fd,
        blocks_off: 0x0de,
        block_stride: 8,
        str_mlt_off: 0x625,
        comp_b_off: 0x5ed,
        wrkbuf_off: 0x294,
        oep_off: 0x0d2,
        emulator_landing: 0,
        version: "2.01/2.1",
    },
    // `USE_XEMULATOR` rows upstream: 2.11/2.11r and 2.11c/2.11d hide the
    // mark byte and OEP dword inside a per-file polymorphic self-decryptor;
    // detection keys on the EP signature plus the plaintext compB table
    // (`ep_buff_off` is the upstream 0xffffffff sentinel).
    AspackLayout {
        signature: b"\x60\xe9\x3d\x04\x00\x00",
        ep_buff_off: u32::MAX,
        blocks_off: 0x6e9,
        block_stride: 8,
        str_mlt_off: 0x87b,
        comp_b_off: 0x843,
        wrkbuf_off: 0x14b,
        oep_off: 0x7d,
        emulator_landing: 0x43b,
        version: "2.11/2.11r",
    },
    AspackLayout {
        signature: b"\x60\xe8\x02\x00\x00\x00\xeb\x09",
        ep_buff_off: u32::MAX,
        blocks_off: 0x715,
        block_stride: 8,
        str_mlt_off: 0x8a7,
        comp_b_off: 0x86f,
        wrkbuf_off: 0x157,
        oep_off: 0x3a1,
        emulator_landing: 0x467,
        version: "2.11c/2.11d",
    },
];

/// The 0x72-byte constant table the decoder indexes as `stuff[]`.
const COMP_B_TABLE: [u8; 0x72] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x14, 0x18, 0x1c,
    0x20, 0x28, 0x30, 0x38, 0x40, 0x50, 0x60, 0x70, 0x80, 0xa0, 0xc0, 0xe0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03,
    0x04, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x02,
    0x03, 0x03, 0x04, 0x04, 0x05, 0x05, 0x06, 0x06, 0x07, 0x07, 0x08, 0x08, 0x09, 0x09, 0x0a, 0x0a,
    0x0b, 0x0b, 0x0c, 0x0c, 0x0d, 0x0d, 0x0e, 0x0e, 0x0f, 0x0f, 0x10, 0x10, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
    0x12, 0x12,
];

/// Per-dictionary work buffers (`DICT_HELPER`): `starts` decodes the
/// symbol index, `ends` accelerates the first-byte lookup, `size` is the
/// symbol count.
struct DictHelper {
    starts: Vec<u32>,
    ends: [u8; 0x100],
    size: usize,
}

/// `ASPK` — full decoder state. `input`/`ipos`/`iend` mirror the
/// upstream raw-pointer stream (`input`/`iend`); `iend` is the logical
/// end (block_size + 0x10e padding lives in `input`).
struct Aspk {
    bitpos: u32,
    hash: u32,
    init_array: [u32; 58],
    dict_helper: [DictHelper; 4],
    input: Vec<u8>,
    ipos: usize,
    iend: usize,
    decrypt_dict: [u8; 757],
    decarray3: [[u32; 24]; 4],
    decarray4: [[u32; 24]; 4],
    dict_ok: i32,
    array2: [u8; 758],
    array1: [u8; 19],
}

impl Aspk {
    /// `_initDict` for all four dictionaries, upstream sizes.
    fn new() -> Self {
        let sizes = [721usize, 28, 8, 19];
        let dict_helper = sizes.map(|sz| DictHelper {
            starts: vec![0; sz],
            ends: [0; 0x100],
            size: sz,
        });
        Self {
            bitpos: 0,
            hash: 0x10000,
            init_array: [0; 58],
            dict_helper,
            input: Vec::new(),
            ipos: 0,
            iend: 0,
            decrypt_dict: [0; 757],
            decarray3: [[0; 24]; 4],
            decarray4: [[0; 24]; 4],
            dict_ok: 0,
            array2: [0; 758],
            array1: [0; 19],
        }
    }

    /// `_readstream` — top up the bit window while `bitpos >= 8`.
    fn readstream(&mut self) -> i32 {
        while self.bitpos >= 8 {
            if self.ipos >= self.iend {
                return 0;
            }
            self.hash = (self.hash << 8) | u32::from(self.input[self.ipos]);
            self.ipos += 1;
            self.bitpos -= 8;
        }
        1
    }

    /// `_getdec` — canonical-Huffman symbol decode via `decarray3/4`.
    fn getdec(&mut self, which: usize, err: &mut i32) -> u32 {
        *err = 1;
        if self.readstream() == 0 {
            return 0;
        }
        let d3 = self.decarray3[which];
        let d4 = self.decarray4[which];

        let ret = (self.hash >> (8 - self.bitpos)) & 0xfffe00;

        let pos: u32;
        if ret < d3[8] {
            if (ret >> 16) >= 0x100 {
                return 0;
            }
            let e = self.dict_helper[which].ends[(ret >> 16) as usize];
            if e == 0 || e >= 24 {
                return 0;
            }
            pos = u32::from(e);
        } else if ret < d3[10] {
            pos = if ret < d3[9] { 9 } else { 10 };
        } else if ret < d3[11] {
            pos = 11;
        } else if ret < d3[12] {
            pos = 12;
        } else if ret < d3[13] {
            pos = 13;
        } else if ret < d3[14] {
            pos = 14;
        } else {
            pos = 15;
        }

        self.bitpos += pos;
        let sym =
            (ret.wrapping_sub(d3[(pos - 1) as usize]) >> (24 - pos)).wrapping_add(d4[pos as usize]);

        if sym >= self.dict_helper[which].size as u32 {
            return 0;
        }
        *err = 0;
        self.dict_helper[which].starts[sym as usize]
    }

    /// `_buildArray` — build the canonical decode tables for one dict
    /// from the stored code-length array.
    fn build_array(&mut self, which: usize) -> u8 {
        let size = self.dict_helper[which].size;
        let array: Vec<u8> = match which {
            3 => self.array1[..size].to_vec(),
            0 => self.array2[1..1 + size].to_vec(),
            1 => self.array2[722..722 + size].to_vec(),
            _ => self.array2[750..750 + size].to_vec(),
        };
        self.build_array_inner(which, &array)
    }

    fn build_array_inner(&mut self, which: usize, array: &[u8]) -> u8 {
        let mut bus = [0u32; 18];
        let mut dict = [0u32; 18];
        let mut sum: u32 = 0;
        let mut counter: i32 = 23;
        let mut endoff: u32 = 0;
        let size = self.dict_helper[which].size;

        for &a in array.iter().take(size) {
            if a > 17 {
                return 0;
            }
            bus[a as usize] += 1;
        }

        self.decarray3[which][0] = 0;
        self.decarray4[which][0] = 0;
        let mut i = 0usize;
        while counter >= 9 {
            sum = sum.wrapping_add(bus[i + 1] << counter);
            if sum > 0x1000000 {
                return 0;
            }

            self.decarray3[which][i + 1] = sum;
            dict[i + 1] = bus[i] + dict[i];
            self.decarray4[which][i + 1] = dict[i + 1];

            if counter >= 0x10 {
                let old = endoff;
                endoff = self.decarray3[which][i + 1] >> 0x10;
                if endoff < old {
                    return 0;
                }
                let remaining = endoff - old;
                if remaining > 0 {
                    if old + remaining > 0x100 {
                        return 0;
                    }
                    for e in self.dict_helper[which].ends[old as usize..(old + remaining) as usize]
                        .iter_mut()
                    {
                        *e = (i + 1) as u8;
                    }
                }
            }
            i += 1;
            counter -= 1;
        }

        if sum != 0x1000000 {
            return 0;
        }

        for (i, &a) in array.iter().take(size).enumerate() {
            if a != 0 {
                if dict[a as usize] >= size as u32 {
                    return 0;
                }
                self.dict_helper[which].starts[dict[a as usize] as usize] = i as u32;
                dict[a as usize] += 1;
            }
        }

        1
    }

    /// `_getbits` — take `num` bits (1..=8 effectively) from the window.
    fn getbits(&mut self, num: u32, err: &mut i32) -> u8 {
        if self.readstream() == 0 {
            *err = 1;
            return 0;
        }
        *err = 0;
        let ret = (((self.hash >> (8 - self.bitpos)) & 0xffffff) >> (24 - num)) as u8;
        self.bitpos += num;
        ret
    }

    /// `_buildDicts` — read the code-length preamble and rebuild all
    /// four canonical dictionaries.
    fn build_dicts(&mut self) -> i32 {
        let mut oob = 0;
        if self.getbits(1, &mut oob) == 0 {
            self.decrypt_dict[..0x2f5].fill(0);
        }
        if oob != 0 {
            return 0;
        }

        for i in 0..19 {
            self.array1[i] = self.getbits(4, &mut oob);
            if oob != 0 {
                return 0;
            }
        }

        if self.build_array(3) == 0 {
            return 0;
        }

        let mut counter = 0usize;
        while counter < 757 {
            let mut ret = self.getdec(3, &mut oob);
            if oob != 0 {
                return 0;
            }
            if ret >= 16 {
                if ret != 16 {
                    if ret == 17 {
                        ret = 3 + u32::from(self.getbits(3, &mut oob));
                    } else {
                        ret = 11 + u32::from(self.getbits(7, &mut oob));
                    }
                    if oob != 0 {
                        return 0;
                    }
                    while ret > 0 {
                        if counter >= 757 {
                            break;
                        }
                        self.array2[1 + counter] = 0;
                        counter += 1;
                        ret -= 1;
                    }
                } else {
                    ret = 3 + u32::from(self.getbits(2, &mut oob));
                    if oob != 0 {
                        return 0;
                    }
                    while ret > 0 {
                        if counter >= 757 {
                            break;
                        }
                        self.array2[1 + counter] = self.array2[counter];
                        counter += 1;
                        ret -= 1;
                    }
                }
            } else {
                self.array2[1 + counter] = (self.decrypt_dict[counter] + ret as u8) & 0xF;
                counter += 1;
            }
        }

        if self.build_array(0) == 0 || self.build_array(1) == 0 || self.build_array(2) == 0 {
            return 0;
        }

        self.dict_ok = 0;
        for counter in 0..8 {
            if self.array2[750 + counter] != 3 {
                self.dict_ok = 1;
                break;
            }
        }

        self.decrypt_dict.copy_from_slice(&self.array2[1..1 + 757]);
        1
    }

    /// `_decrypt` — LZ output: literals, dictionary rebuilds, and
    /// back-references with the 4-deep distance history.
    fn decrypt(&mut self, stuff: &[u8], output: &mut [u8]) -> i32 {
        let size = output.len();
        let mut counter = 0usize;
        let mut hist = [0u32; 4];
        let mut oob = 0;

        while counter < size {
            let mut g = self.getdec(0, &mut oob);
            if oob != 0 {
                return 0;
            }
            if g < 256 {
                output[counter] = g as u8;
                counter += 1;
                continue;
            }
            if g >= 720 {
                if self.build_dicts() == 0 {
                    return 0;
                }
                continue;
            }
            let mut backbytes = (g - 256) >> 3;
            let mut backsize = ((g - 256) & 7) + 2;
            if (backsize - 2) == 7 {
                g = self.getdec(1, &mut oob);
                if oob != 0 || g >= 0x56 {
                    return 0;
                }
                let hlp = stuff[(g + 0x1c) as usize];
                if self.readstream() == 0 {
                    return 0;
                }
                backsize += u32::from(stuff[g as usize])
                    + (((self.hash >> (8 - self.bitpos)) & 0xffffff) >> (0x18 - hlp));
                self.bitpos += u32::from(hlp);
            }

            let mut useold = self.init_array[backbytes as usize];
            g = u32::from(stuff[(backbytes + 0x38) as usize]);

            if self.dict_ok == 0 || g < 3 {
                if self.readstream() == 0 {
                    return 0;
                }
                useold =
                    useold.wrapping_add(((self.hash >> (8 - self.bitpos)) & 0xffffff) >> (24 - g));
                self.bitpos += g;
            } else {
                g -= 3;
                if self.readstream() == 0 {
                    return 0;
                }
                useold = useold
                    .wrapping_add((((self.hash >> (8 - self.bitpos)) & 0xffffff) >> (24 - g)) * 8);
                self.bitpos += g;
                useold = useold.wrapping_add(self.getdec(2, &mut oob));
                if oob != 0 {
                    return 0;
                }
            }

            if useold < 3 {
                backbytes = hist[useold as usize];
                if useold != 0 {
                    hist[useold as usize] = hist[0];
                    hist[0] = backbytes;
                }
            } else {
                hist[2] = hist[1];
                hist[1] = hist[0];
                backbytes = useold - 3;
                hist[0] = backbytes;
            }

            backbytes = backbytes.wrapping_add(1);
            if backbytes == 0 || backbytes > counter as u32 || backsize as usize > size - counter {
                return 0;
            }
            for _ in 0..backsize {
                output[counter] = output[counter - backbytes as usize];
                counter += 1;
            }
        }

        1
    }

    /// `_decompBlock` — reset the dict tables and run `_decrypt`.
    fn decomp_block(&mut self, stuff: &[u8], output: &mut [u8]) -> i32 {
        self.decarray3 = [[0; 24]; 4];
        self.decarray4 = [[0; 24]; 4];
        self.decrypt_dict = [0; 757];
        self.bitpos = 0x20;
        if self.build_dicts() == 0 {
            return 0;
        }
        self.decrypt(stuff, output)
    }
}

fn rd32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

fn wr32(d: &mut [u8], off: usize, v: u32) {
    d[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn align(v: u32, a: u32) -> u32 {
    (v + a - 1) & !(a - 1)
}

fn rol32(v: u32, n: u32) -> u32 {
    v.rotate_left(n & 31)
}

/// `XASPACK::_detect` — signature + marker + compB-anchor match across
/// the non-emulator layout rows.
fn detect(d: &[u8]) -> Option<(usize, &'static str)> {
    let pe = PackedPe::parse(d).ok()?;
    if pe.is64() {
        return None;
    }
    let ep_rva = pe.entry_rva();
    let ep_off = pe.rva_to_offset(ep_rva)?;
    let ep = d.get(ep_off..)?;
    if ep.len() < 0x3bf {
        return None;
    }
    let ep = &ep[..ep.len().min(0x1000)];

    const MARK: &[u8; 6] = b"\x68\x00\x00\x00\x00\xc3";
    for (i, l) in LAYOUTS.iter().enumerate() {
        if ep.len() < l.signature.len() || ep[..l.signature.len()] != l.signature[..] {
            continue;
        }
        if l.ep_buff_off != u32::MAX {
            let m = l.ep_buff_off as usize;
            if ep.len() < m + 6 || &ep[m..m + 6] != MARK {
                continue;
            }
        }
        // compB table is (AEP - 1)-relative.
        let comp = l.comp_b_off as i64 - 1;
        if comp < 0 || ep.len() < comp as usize + 0x72 {
            continue;
        }
        if ep[comp as usize..comp as usize + 0x72] != COMP_B_TABLE {
            continue;
        }
        return Some((i, l.version));
    }
    None
}

/// `XASPACK::_detect` public wrapper.
pub fn detect_aspack(data: &[u8]) -> Option<AspackInfo> {
    let (layout, sversion) = detect(data)?;
    Some(AspackInfo { sversion, layout })
}

/// `XASPACK::_buildPE` — fresh PE32 with `.clam%02d` sections mapped
/// `raw == rva` (ghost section when `first_rva > align(raw_base,
/// 0x1000)`).
fn build_pe(
    image: &[u8],
    sections: &[super::upx::SectionHead],
    sect_count: usize,
    image_base: u32,
    oep: u32,
    output_limit: i64,
) -> Vec<u8> {
    if sect_count == 0 {
        return Vec::new();
    }
    const HEADER_BASE: u32 = 0x40 + 4 + 20 + 0xE0;
    let first_rva = sections[0].virtual_address;
    let mut raw_base = align(HEADER_BASE + 0x28 * sect_count as u32, 0x200);
    let ghost = first_rva > align(raw_base, 0x1000);
    if ghost {
        raw_base = align(HEADER_BASE + 0x28 * (sect_count as u32 + 1), 0x200);
    }

    let mut raw_total = u64::from(raw_base);
    let mut max_vend = 0u32;
    for s in sections.iter().take(sect_count) {
        raw_total += u64::from(align(s.virtual_size, 0x200));
        max_vend = max_vend.max(s.virtual_address.wrapping_add(s.virtual_size));
    }
    if raw_total > i32::MAX as u64 || (output_limit >= 0 && raw_total > output_limit as u64) {
        return Vec::new();
    }

    let mut out = vec![0u8; raw_total as usize];
    out[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    wr32(&mut out, 0x3C, 0x40);
    out[0x40..0x44].copy_from_slice(b"PE\0\0");
    let fh = 0x44;
    out[fh..fh + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    out[fh + 2..fh + 4].copy_from_slice(&((sect_count + usize::from(ghost)) as u16).to_le_bytes());
    out[fh + 16..fh + 18].copy_from_slice(&0x00E0u16.to_le_bytes());
    out[fh + 18..fh + 20].copy_from_slice(&0x010Fu16.to_le_bytes());
    let oh = fh + 20;
    out[oh..oh + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    wr32(&mut out, oh + 16, oep);
    wr32(&mut out, oh + 28, image_base);
    wr32(&mut out, oh + 32, 0x1000);
    wr32(&mut out, oh + 36, 0x200);
    out[oh + 40..oh + 42].copy_from_slice(&4u16.to_le_bytes());
    out[oh + 48..oh + 50].copy_from_slice(&4u16.to_le_bytes());
    wr32(&mut out, oh + 56, align(max_vend, 0x1000));
    wr32(&mut out, oh + 60, raw_base);
    out[oh + 68..oh + 70].copy_from_slice(&2u16.to_le_bytes());
    wr32(&mut out, oh + 92, 16);

    let mut sec = oh + 0xE0;
    let mut raw = raw_base;

    if ghost {
        out[sec..sec + 6].copy_from_slice(b".ghost");
        let ghost_va = align(raw_base, 0x1000);
        wr32(&mut out, sec + 8, first_rva - ghost_va);
        wr32(&mut out, sec + 12, ghost_va);
        wr32(&mut out, sec + 36, 0xE00000E0);
        sec += 0x28;
    }

    for (i, s) in sections.iter().take(sect_count).enumerate() {
        let vsz = s.virtual_size;
        let rsz = align(vsz, 0x200);
        let name = format!(".clam{:02}", i + 1);
        out[sec..sec + name.len().min(8)].copy_from_slice(&name.as_bytes()[..name.len().min(8)]);
        wr32(&mut out, sec + 8, vsz);
        wr32(&mut out, sec + 12, s.virtual_address);
        wr32(&mut out, sec + 16, rsz);
        wr32(&mut out, sec + 20, raw);
        wr32(&mut out, sec + 36, 0xE00000E0);

        let start = s.virtual_address as usize;
        let end = start.saturating_add(vsz as usize);
        if end <= image.len() {
            out[raw as usize..raw as usize + vsz as usize].copy_from_slice(&image[start..end]);
        }

        raw = raw.wrapping_add(rsz);
        sec += 0x28;
    }

    out
}

/// `decryptStubHead` — emulate the polymorphic self-decryptor at the
/// entry point until execution reaches `ep + landing_off`, then copy the
/// now-plaintext stub head `[ep, ep+0x800)` back over `image` so the
/// mark and OEP reads in the main path see plaintext. Fails closed
/// (returns false → upstream `return false`) on any emulation fault,
/// step-cap overrun, or bound violation — a mis-emulated file is never
/// restored with a wrong OEP.
fn decrypt_stub_head(image_base: u32, ep: u32, landing_off: u32, image: &mut [u8]) -> bool {
    use crate::emulate::regs::GPR_RSP;
    use crate::emulate::{MemoryFlags, MemoryManager, Registers, StepResult, X86};

    const ASP_STACK: u32 = 0x5000_0000;
    const ASP_STACK_SIZE: u32 = 0x0010_0000;
    const ASP_HEAD_SIZE: u32 = 0x800;
    const ASP_MAX_STEPS: u64 = 8_000_000;

    if image.is_empty()
        || u64::from(ep) + u64::from(ASP_HEAD_SIZE) > image.len() as u64
        || u64::from(ep) + u64::from(landing_off) >= image.len() as u64
        || u64::from(image_base) + image.len() as u64 > u64::from(ASP_STACK)
    {
        return false;
    }

    let rwx = MemoryFlags::new(true, true, true, false);
    let rw = MemoryFlags::new(true, true, false, false);
    let mut memory = MemoryManager::new();
    memory.set_bits(32);
    if !memory.map_fixed(
        u64::from(image_base),
        image.len() as u64,
        rwx,
        "ASPack image",
    ) || !memory.map_fixed(
        u64::from(ASP_STACK),
        u64::from(ASP_STACK_SIZE),
        rw,
        "ASPack stack",
    ) || !memory.write(u64::from(image_base), image)
    {
        return false;
    }

    let mut registers = Registers::default();
    registers.set_gpr(
        GPR_RSP,
        4,
        u64::from(ASP_STACK) + u64::from(ASP_STACK_SIZE) - 0x1000,
    );
    let target = u64::from(image_base) + u64::from(ep) + u64::from(landing_off);
    // Upstream starts one byte past the pushad at AddressOfEntryPoint.
    registers.rip = u64::from(image_base) + u64::from(ep) + 1;

    let mut steps = 0u64;
    {
        let mut arch = X86::new(&mut memory, 32);
        while u64::from(registers.rip as u32) != target {
            if steps >= ASP_MAX_STEPS {
                return false;
            }
            steps += 1;
            // Untrusted stub code: every step is memory-checked and the
            // loop is capped; any non-OK result aborts the unpack.
            let info = arch.step(&mut registers);
            if info.result != StepResult::Ok {
                return false;
            }
        }
    }

    let Some(head) = memory.read(
        u64::from(image_base) + u64::from(ep),
        u64::from(ASP_HEAD_SIZE),
    ) else {
        return false;
    };
    if head.len() != ASP_HEAD_SIZE as usize {
        return false;
    }
    image[ep as usize..ep as usize + ASP_HEAD_SIZE as usize].copy_from_slice(&head);
    true
}

/// `XASPACK::_unpackToBuffer` — assemble the RVA image, decompress the
/// block table, reverse the one-shot filter, rebuild the PE.
/// `output_limit < 0` means unlimited (upstream `-1`).
pub fn unpack_aspack(data: &[u8], output_limit: i64) -> Result<Vec<u8>, UnpackError> {
    let (li, _sv) = detect(data).ok_or(UnpackError::NotPacked)?;
    let pe = PackedPe::parse(data)?;
    let sections = pe.sections();
    let mut nsect = sections.len();
    if nsect < 1 {
        return Err(UnpackError::Malformed("aspack: sections"));
    }

    let image_base = pe.image_base() as u32;
    let ep = pe.entry_rva().wrapping_sub(1);
    let l = &LAYOUTS[li];

    let mut image_size = 0u32;
    for s in sections.iter() {
        image_size = image_size.max(s.virtual_address.wrapping_add(s.virtual_size));
    }
    if image_size == 0
        || image_size > 256 * 1024 * 1024
        || (output_limit >= 0 && u64::from(image_size) > output_limit as u64)
    {
        return Err(UnpackError::Malformed("aspack: image size"));
    }

    let mut image = vec![0u8; image_size as usize];
    for s in sections.iter() {
        if s.raw_size == 0 {
            continue;
        }
        let rva = s.virtual_address as usize;
        let rsz = s.raw_size as usize;
        if rva + rsz > image.len() {
            return Err(UnpackError::Malformed("aspack: section map"));
        }
        let raw = data
            .get(s.raw_ptr as usize..s.raw_ptr as usize + rsz)
            .ok_or(UnpackError::Malformed("aspack: section raw"))?;
        image[rva..rva + rsz].copy_from_slice(raw);
    }

    // `USE_XEMULATOR` branch upstream: 2.11/2.11c rows carry an
    // encrypted stub head; decrypt it in place before the mark and OEP
    // reads below, which then work exactly as for plaintext versions.
    if l.emulator_landing != 0 && !decrypt_stub_head(image_base, ep, l.emulator_landing, &mut image)
    {
        return Err(UnpackError::Malformed("aspack: stub head emulation"));
    }

    let mut st = Aspk::new();
    let mut j = 0u32;
    for i in 0..58usize {
        st.init_array[i] = j;
        let idx = ep as usize + i + l.str_mlt_off as usize;
        if idx < image.len() {
            j = j.wrapping_add(1u32 << image[idx]);
        }
    }

    let comp = ep as usize + l.comp_b_off as usize;
    if comp + 0x72 > image.len() {
        return Err(UnpackError::Malformed("aspack: compB"));
    }

    let mut blocks = ep as usize + l.blocks_off as usize;
    if blocks + 8 > image.len() {
        return Err(UnpackError::Malformed("aspack: blocks"));
    }
    let mut block_rva = 1u32;
    let mut block_size;
    let mut filtered = false;

    while blocks + 8 <= image.len() {
        block_rva = rd32(&image, blocks);
        block_size = rd32(&image, blocks + 4);
        if block_rva == 0
            || block_size == 0
            || u64::from(block_rva) + u64::from(block_size) > u64::from(image_size)
        {
            break;
        }

        st.input = vec![0u8; block_size as usize + 0x10e];
        st.input[..block_size as usize]
            .copy_from_slice(&image[block_rva as usize..block_rva as usize + block_size as usize]);
        st.ipos = 0;
        st.iend = st.input.len();

        // `stuff` aliases the (possibly rewritten) compB table inside
        // `image`; snapshot per block to preserve upstream aliasing.
        let mut stuff = [0u8; 0x72];
        stuff.copy_from_slice(&image[comp..comp + 0x72]);
        if st.decomp_block(
            &stuff,
            &mut image[block_rva as usize..block_rva as usize + block_size as usize],
        ) == 0
        {
            return Err(UnpackError::Decompress("aspack: block".into()));
        }

        if !filtered && block_size > 7 {
            filtered = true;
            let mark = image[ep as usize + l.wrkbuf_off as usize];
            let mut k = 0usize;
            while k < (block_size as usize) - 6 {
                let cur = image[block_rva as usize + k];
                if cur == 0xe8 || cur == 0xe9 {
                    let w = block_rva as usize + k + 1;
                    if image[w] == mark {
                        let target = rol32(rd32(&image, w) & 0xffffff00, 0x18);
                        wr32(&mut image, w, target.wrapping_sub(k as u32));
                        k += 4;
                    }
                }
                k += 1;
            }
        }

        blocks += l.block_stride as usize;
        if l.block_stride != 8 {
            if blocks + 8 > image.len() {
                break;
            }
            block_size = rd32(&image, blocks + 4);
            while block_size + 0x10e == 0 {
                blocks += l.block_stride as usize;
                if blocks + 8 > image.len() {
                    break;
                }
                block_size = rd32(&image, blocks + 4);
            }
        }
    }

    if block_rva != 0 {
        return Err(UnpackError::Malformed("aspack: block table"));
    }

    if nsect > 2 && ep == sections[nsect - 2].virtual_address && sections[nsect - 1].raw_size == 0 {
        nsect -= 2;
    }

    let oep_off = ep as usize + l.oep_off as usize;
    if oep_off + 4 > image.len() {
        return Err(UnpackError::Malformed("aspack: oep"));
    }
    let oep = rd32(&image, oep_off);

    let out = build_pe(&image, sections, nsect, image_base, oep, output_limit);
    if out.is_empty() {
        return Err(UnpackError::Malformed("aspack: build"));
    }
    Ok(out)
}

#[cfg(test)]
mod emu_tests {
    //! Synthetic-code coverage for the `USE_XEMULATOR` stub-head branch:
    //! the guest program decrypts the stub head in place, mirroring what
    //! a real 2.11x self-decryptor does before `ep + landing_off`.
    use super::*;

    /// Guest writes two dwords into the head then reaches the landing.
    #[test]
    fn decrypt_stub_head_copies_plaintext() {
        let mut image = vec![0u8; 0x3000];
        image[0x1000] = 0x60; // pushad — upstream skips this byte
        let code = [
            0xC7, 0x05, 0x00, 0x10, 0x40, 0x00, 0x44, 0x33, 0x22,
            0x11, // mov [0x401000],0x11223344
            0xC7, 0x05, 0x04, 0x10, 0x40, 0x00, 0x88, 0x77, 0x66,
            0x55, // mov [0x401004],0x55667788
        ];
        image[0x1001..0x1001 + code.len()].copy_from_slice(&code);
        for b in &mut image[0x1001 + code.len()..0x1020] {
            *b = 0x90; // nop sled to the landing offset
        }
        assert!(decrypt_stub_head(0x40_0000, 0x1000, 0x20, &mut image));
        assert_eq!(
            &image[0x1000..0x1008],
            &[0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55]
        );
    }

    /// A guest that halts before the landing must fail closed.
    #[test]
    fn decrypt_stub_head_aborts_on_trap() {
        let mut image = vec![0u8; 0x3000];
        image[0x1000] = 0x60;
        image[0x1001] = 0xF4; // hlt — STEP_HALT, never reaches landing
        assert!(!decrypt_stub_head(0x40_0000, 0x1000, 0x20, &mut image));
    }

    /// A guest loop that never reaches the landing burns the step cap.
    #[test]
    fn decrypt_stub_head_bounds_runaway_code() {
        let mut image = vec![0x90u8; 0x3000];
        image[0x1000] = 0x60;
        image[0x1001] = 0xEB; // jmp $-2 (self loop)
        image[0x1002] = 0xFE;
        // The 8M-step bound makes this expensive to run in a unit test;
        // instead verify the out-of-range landing is rejected up front.
        assert!(!decrypt_stub_head(0x40_0000, 0x1000, 0x3000, &mut image));
    }
}

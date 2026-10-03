//! NsPack static unpacking — port of upstream `XNSPACK`.
//!
//! NsPack uses an LZMA-variant binary range coder (`_decompress`) with
//! adaptive per-context probabilities, a literal tree, rep-distance
//! history (`oldback` chain) and position-state (`damian`) modelling.
//! Detection follows the loader prologue (`9C 60 E8 00 00 00 00 5D`)
//! with an optional E9 redirector (2.x), locates the `nsp0` block via
//! `_findStartOfStuff` (needle = section-0 VirtualSize == `dsize`), then
//! optionally reconstructs imports (`_reconstructImports`) and reverses
//! the E8/E9 call/jmp filter (`_deFilterCallJmp`) before `_buildPE`
//! writes a fresh single-section PE32.

use super::UnpackError;
use super::upx::PackedPe;

/// Detection metadata for an NsPack-packed PE.
#[derive(Debug, Clone)]
pub struct NsPackInfo {
    /// File offset of the `nsp0` block (`start-of-stuff`).
    pub start_of_stuff: u64,
    /// Compressed stream size field.
    pub ssize: u32,
    /// Decompressed blob size (== section-0 VirtualSize).
    pub dsize: u32,
    /// Recovered original entry point RVA.
    pub oep: u32,
    /// RVA where the blob is mapped (section-0 VirtualAddress).
    pub rva: u32,
    /// Image base.
    pub image_base: u32,
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

/// `NSP_STATE` — binary range-coder state over the source stream.
struct NspState<'a> {
    src: &'a [u8],
    ipos: usize,
    iend: usize,
    oldval: u32,
    bitmap: u32,
    table: &'a mut [u16],
    error: i32,
}

impl NspState<'_> {
    /// `_getByte` — bounded stream read; out-of-range sets `error`.
    fn get_byte(&mut self) -> u8 {
        if self.ipos >= self.iend {
            self.error = 1;
            return 0xff;
        }
        let b = self.src[self.ipos];
        self.ipos += 1;
        b
    }

    /// `_getBit` — adaptive binary decode at `table[index]`.
    fn get_bit(&mut self, index: u32) -> u32 {
        let idx = index as usize;
        if idx >= self.table.len() {
            self.error = 1;
            return 0xff;
        }
        let pv = u32::from(self.table[idx]);
        let nval = pv.wrapping_mul(self.bitmap >> 0xb);

        if self.oldval < nval {
            self.bitmap = nval;
            let mut sval = ((0x800u32.wrapping_sub(pv)) as i32 >> 5) as u32;
            sval = sval.wrapping_add(pv);
            self.table[idx] = sval as u16;
            if self.bitmap < 0x1000000 {
                self.oldval = (self.oldval << 8) | u32::from(self.get_byte());
                self.bitmap <<= 8;
            }
            return 0;
        }

        self.bitmap = self.bitmap.wrapping_sub(nval);
        self.oldval = self.oldval.wrapping_sub(nval);
        let nv = pv - (pv >> 5);
        self.table[idx] = nv as u16;
        if self.bitmap < 0x1000000 {
            self.oldval = (self.oldval << 8) | u32::from(self.get_byte());
            self.bitmap <<= 8;
        }
        1
    }

    /// `_get100Size` — literal-tree decode conditioned on the previous
    /// match byte (the match byte shifts left one bit per round).
    fn get100_size(&mut self, base: u32, match_byte: u32) -> u32 {
        let mut count = 1u32;
        let mut mb = match_byte;
        while count < 0x100 {
            let mut lpos = mb & 0xff;
            mb = (mb & 0xffffff00) | ((lpos << 1) & 0xff);
            lpos >>= 7;
            let mut tpos = lpos + 1;
            tpos <<= 8;
            tpos += count;
            let bit = self.get_bit(base + tpos);
            count = (count * 2) | bit;
            if lpos != bit {
                while count < 0x100 {
                    count = (count * 2) | self.get_bit(base + count);
                }
            }
        }
        count & 0xff
    }

    /// `_get100` — plain literal-tree decode (8 bits).
    fn get100(&mut self, base: u32) -> u32 {
        let mut count = 1u32;
        while count < 0x100 {
            let b = self.get_bit(base + count);
            count = (count * 2) | b;
        }
        count & 0xff
    }

    /// `_getN` — `n_bits`-level tree decode.
    fn get_n(&mut self, base: u32, n_bits: u32) -> u32 {
        let mut count = 1u32;
        let mut bc = n_bits;
        while bc > 0 {
            bc -= 1;
            let b = self.get_bit(base.wrapping_add(count));
            count = count.wrapping_mul(2).wrapping_add(b);
        }
        count.wrapping_sub(1u32.wrapping_shl(n_bits & 0xff))
    }

    /// `_getNSize` — match-length decode (3 cascaded trees).
    fn get_n_size(&mut self, base: u32, backsize: u32) -> u32 {
        if self.get_bit(base) == 0 {
            return self.get_n(base + (backsize << 3) + 2, 3);
        }
        if self.get_bit(base + 1) == 0 {
            return 8 + self.get_n(base + (backsize << 3) + 0x82, 3);
        }
        0x10 + self.get_n(base + 0x102, 8)
    }

    /// `_getBB` — `back`-bit direct-tree decode.
    fn get_bb(&mut self, base: u32, back: u32) -> u32 {
        let mut pos = 1u32;
        let mut bb = 0u32;
        if (back as i32) <= 0 {
            return 0;
        }
        for i in 0..back {
            let bit = self.get_bit(base.wrapping_add(pos));
            pos = pos.wrapping_mul(2).wrapping_add(bit);
            bb |= bit.wrapping_shl(i);
        }
        bb
    }

    /// `_getBitmap` — `n_bits` raw bits straight off the code value.
    fn get_bitmap(&mut self, n_bits: u32) -> u32 {
        let mut retv = 0u32;
        if (n_bits as i32) <= 0 {
            return 0;
        }
        let mut nb = n_bits;
        while nb > 0 {
            nb -= 1;
            self.bitmap >>= 1;
            retv <<= 1;
            if self.oldval >= self.bitmap {
                self.oldval = self.oldval.wrapping_sub(self.bitmap);
                retv |= 1;
            }
            if self.bitmap < 0x1000000 {
                self.bitmap <<= 8;
                self.oldval = (self.oldval << 8) | u32::from(self.get_byte());
            }
        }
        retv
    }
}

/// `XNSPACK::_decompress` — LZMA-variant literal/match decoder.
/// Returns the number of output bytes produced, or `None` on any
/// upstream `return false` path.
fn decompress(
    tre: u32,
    allocsz: u32,
    first_byte: u32,
    src: &[u8],
    dst: &mut [u8],
    table: &mut [u16],
) -> Option<u32> {
    let n_init = (0x300u32)
        .wrapping_shl((allocsz.wrapping_add(tre)) & 0xff)
        .wrapping_add(0x736);
    if (table.len() as u32) < n_init {
        return None;
    }
    for t in table.iter_mut().take(n_init as usize) {
        *t = 0x400;
    }

    let mut st = NspState {
        src,
        ipos: 0,
        iend: src.len().saturating_sub(13),
        oldval: 0,
        bitmap: 0xffffffff,
        table,
        error: 0,
    };

    for _ in 0..5 {
        st.oldval = (st.oldval << 8) | u32::from(st.get_byte());
    }
    if st.error != 0 {
        return None;
    }

    let mut prev_bit = 0u32;
    let mut done = 0usize;
    let mut backbytes = 1u32;
    let mut oldback = 1u32;
    let mut old_oldback = 1u32;
    let mut old_old_oldback = 1u32;
    let mut damian = 0u32;
    let put = (1u32.wrapping_shl(allocsz & 0xff)).wrapping_sub(1);
    let mut bielle = 0u32;
    let first_mask = (1u32.wrapping_shl(first_byte & 0xff)).wrapping_sub(1);
    let dsize = dst.len();

    loop {
        if st.error != 0 {
            return None;
        }
        let mut backsize = first_mask & done as u32;
        let mut tpos;

        if st.get_bit((damian << 4).wrapping_add(backsize)) == 0 {
            // literal
            let shft = (8u32.wrapping_sub(tre & 0xff)) & 0xff;
            tpos = bielle
                .checked_shr(shft)
                .unwrap_or(0)
                .wrapping_add((put & done as u32).wrapping_shl(tre & 0xff));
            tpos = tpos.wrapping_mul(3);
            tpos <<= 8;

            if damian as i32 >= 4 {
                damian = damian.wrapping_sub(if damian as i32 >= 0xa { 6 } else { 3 });
            } else {
                damian = 0;
            }

            if prev_bit != 0 {
                if backbytes as usize > done {
                    return None;
                }
                let match_byte = u32::from(dst[done - backbytes as usize]);
                bielle = st.get100_size(tpos + 0x736, match_byte);
                prev_bit = 0;
            } else {
                bielle = st.get100(tpos + 0x736);
            }

            if done >= dsize {
                return None;
            }
            dst[done] = bielle as u8;
            done += 1;
            if done >= dsize {
                return Some(done as u32);
            }
            continue;
        }

        // match
        bielle = 1;
        prev_bit = 1;

        if st.get_bit(damian.wrapping_add(0xc0)) != 0 {
            if st.get_bit(damian.wrapping_add(0xcc)) == 0 {
                tpos = damian.wrapping_add(0xf);
                tpos = tpos.wrapping_shl(4);
                tpos = tpos.wrapping_add(backsize);
                if st.get_bit(tpos) == 0 {
                    if done == 0 {
                        return None;
                    }
                    damian = 2 * u32::from(damian as i32 >= 7) + 9;
                    if backbytes as usize > done {
                        return None;
                    }
                    bielle = u32::from(dst[done - backbytes as usize]);
                    if done >= dsize {
                        return None;
                    }
                    dst[done] = bielle as u8;
                    done += 1;
                    if done >= dsize {
                        return Some(done as u32);
                    }
                    continue;
                } else {
                    backsize = st.get_n_size(0x534, backsize);
                    damian = u32::from(damian as i32 >= 7);
                    damian = (damian.wrapping_sub(1) & 0xfffffffd).wrapping_add(0xb);
                }
            } else {
                if st.get_bit(damian.wrapping_add(0xd8)) == 0 {
                    tpos = oldback;
                } else {
                    if st.get_bit(damian.wrapping_add(0xe4)) == 0 {
                        tpos = old_oldback;
                    } else {
                        tpos = old_old_oldback;
                        old_old_oldback = old_oldback;
                    }
                    old_oldback = oldback;
                }
                oldback = backbytes;
                backbytes = tpos;

                backsize = st.get_n_size(0x534, backsize);
                damian = u32::from(damian as i32 >= 7);
                damian = (damian.wrapping_sub(1) & 0xfffffffd).wrapping_add(0xb);
            }
        } else {
            old_old_oldback = old_oldback;
            old_oldback = oldback;
            oldback = backbytes;

            damian = u32::from(damian as i32 >= 7);
            damian = (damian.wrapping_sub(1) & 0xfffffffd).wrapping_add(0xa);

            backsize = st.get_n_size(0x332, backsize);

            tpos = if backsize as i32 >= 4 { 3 } else { backsize };
            tpos = tpos.wrapping_shl(6);
            tpos = st.get_n(0x1b0u32.wrapping_add(tpos), 6);

            let mut temp;
            if tpos >= 4 {
                let mut sbits = tpos;
                sbits >>= 1;
                sbits = sbits.wrapping_sub(1);
                temp = (tpos & bielle) | 2;
                temp = temp.wrapping_shl(sbits & 0xff);
                if (tpos as i32) < 0xe {
                    temp = temp.wrapping_add(
                        st.get_bb(temp.wrapping_sub(tpos).wrapping_add(0x2af), sbits),
                    );
                } else {
                    sbits = sbits.wrapping_add(0xfffffffc);
                    tpos = st.get_bitmap(sbits);
                    tpos = tpos.wrapping_shl(4);
                    temp = temp.wrapping_add(tpos);
                    temp = temp.wrapping_add(st.get_bb(0x322, 4));
                }
            } else {
                temp = tpos;
            }
            backbytes = temp.wrapping_add(1);
        }

        // checkloop_and_backcopy
        if backbytes == 0 {
            return Some(done as u32);
        }
        if backbytes as usize > done {
            return None;
        }

        backsize = backsize.wrapping_add(2);
        if done as u64 + u64::from(backsize) > dsize as u64 || backbytes as usize > done {
            return None;
        }

        loop {
            dst[done] = dst[done - backbytes as usize];
            done += 1;
            backsize -= 1;
            if backsize == 0 || done >= dsize {
                break;
            }
        }
        bielle = u32::from(dst[done - 1]);

        if done >= dsize {
            return Some(done as u32);
        }
    }
}

/// `XNSPACK::_deFilterCallJmp` — inverse of the loader's E8/E9
/// address-biasing pass (naive whole-blob scan when the control fields
/// are unreadable).
fn de_filter_call_jmp(data: &mut [u8], count: u32, marker: u8, gate: u8, control_valid: bool) {
    let n = data.len();
    if n < 5 {
        return;
    }
    if !control_valid || gate == 0 {
        let mut i = 0usize;
        while i + 5 <= n {
            let cur = data[i];
            if cur == 0xE8 || cur == 0xE9 {
                let be = (u32::from(data[i + 1]) << 24)
                    | (u32::from(data[i + 2]) << 16)
                    | (u32::from(data[i + 3]) << 8)
                    | u32::from(data[i + 4]);
                let rel = be.wrapping_sub(i as u32 + 1);
                data[i + 1..i + 5].copy_from_slice(&rel.to_le_bytes());
                i += 5;
            } else {
                i += 1;
            }
        }
        return;
    }

    let mut done = 0u32;
    let mut i = 0usize;
    while i + 5 <= n {
        let cur = data[i];
        if cur == 0xE8 || cur == 0xE9 {
            if data[i + 1] == marker && done < count {
                let be24 = (u32::from(data[i + 2]) << 16)
                    | (u32::from(data[i + 3]) << 8)
                    | u32::from(data[i + 4]);
                let mut rel = be24.wrapping_sub(i as u32 + 1) & 0x00FF_FFFF;
                if rel & 0x0080_0000 != 0 {
                    rel |= 0xFF00_0000;
                }
                data[i + 1..i + 5].copy_from_slice(&rel.to_le_bytes());
                done += 1;
                i += 5;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
}

/// Loader anchor shared by `_readCallJmpControl` and
/// `_reconstructImports`: optional E9 redirector, stub prologue check,
/// then the loader's RVA. Returns `(loader_rva, loader_offset)`.
fn loader_anchor(pe: &PackedPe, d: &[u8]) -> Option<(u32, usize)> {
    let mut ep_rva = pe.entry_rva();
    let mut off = pe.rva_to_offset(ep_rva)?;
    let mut head = d.get(off..off + 8)?;
    if head.len() >= 5 && head[0] == 0xe9 {
        ep_rva = rd32(head, 1).wrapping_add(ep_rva).wrapping_add(5);
        off = pe.rva_to_offset(ep_rva)?;
        head = d.get(off..off + 8)?;
    }
    if head.len() < 8 || &head[..8] != b"\x9c\x60\xe8\x00\x00\x00\x00\x5d" {
        return None;
    }
    Some((ep_rva, off))
}

/// Section base RVA containing `rva` (max of VirtualSize/RawSize rule).
fn stub_section_rva(pe: &PackedPe, rva: u32) -> Option<u32> {
    for s in pe.sections() {
        if s.raw_size == 0 {
            continue;
        }
        let sec_size = s.virtual_size.max(s.raw_size);
        if sec_size == 0 {
            continue;
        }
        if rva >= s.virtual_address && rva < s.virtual_address.wrapping_add(sec_size) {
            return Some(s.virtual_address);
        }
    }
    None
}

/// `XNSPACK::_readCallJmpControl` — marker/count/gate fields from the
/// stub parameter block; `None` for unknown layouts (fail-safe).
fn read_call_jmp_control(pe: &PackedPe, d: &[u8]) -> Option<(u32, u8, u8)> {
    let (loader_rva, _) = loader_anchor(pe, d)?;
    let hdr_rva = stub_section_rva(pe, loader_rva)?;
    let hdr_off = pe.rva_to_offset(hdr_rva)?;
    let hdr = d.get(hdr_off..hdr_off + 0x54)?;
    if hdr.len() < 0x54 {
        return None;
    }
    if rd32(hdr, 0x10) == loader_rva {
        Some((rd32(hdr, 0x48), hdr[0x50], hdr[0x51]))
    } else if rd32(hdr, 0x08) == loader_rva {
        Some((rd32(hdr, 0x24), hdr[0x28], hdr[0x29]))
    } else {
        None
    }
}

struct RFunc {
    ord: bool,
    ordinal: u32,
    name: Vec<u8>,
    iat_rva: u32,
}

struct RDll {
    name: Vec<u8>,
    first_thunk: u32,
    funcs: Vec<RFunc>,
}

/// `XNSPACK::_reconstructImports` — decode the per-DLL descriptor
/// stream, synthesize a standard import directory, and patch the real
/// IAT slots inside `blob`. Returns `(section_bytes, descriptor_size)`
/// or `None` on any fail-closed path.
fn reconstruct_imports(
    pe: &PackedPe,
    d: &[u8],
    blob: &mut [u8],
    rva: u32,
    imp_rva: u32,
) -> Option<(Vec<u8>, u32)> {
    if blob.is_empty() {
        return None;
    }
    let (loader_rva, _) = loader_anchor(pe, d)?;
    let hdr_rva = stub_section_rva(pe, loader_rva)?;
    let hdr_off = pe.rva_to_offset(hdr_rva)?;
    let hdr = d.get(hdr_off..hdr_off + 0x14)?;
    if hdr.len() < 0x14 {
        return None;
    }

    let desc_rva = if rd32(hdr, 0x10) == loader_rva {
        rd32(hdr, 0x08) // 3.1-3.7
    } else if rd32(hdr, 0x08) == loader_rva {
        rd32(hdr, 0x04) // 1.4
    } else {
        return None;
    };
    if desc_rva == 0 {
        return None;
    }

    // DLL-name pool: base = this file's first import descriptor Name,
    // which must read "KERNEL32.DLL".
    let (imp_dir_rva, _) = pe.data_directory(1)?;
    if imp_dir_rva == 0 {
        return None;
    }
    let imp_dir_off = pe.rva_to_offset(imp_dir_rva)?;
    let desc0 = d.get(imp_dir_off..imp_dir_off + 20)?;
    if desc0.len() < 20 {
        return None;
    }
    let dll_tbl_rva = rd32(desc0, 12);
    if dll_tbl_rva == 0 {
        return None;
    }
    let dll_tbl_off = pe.rva_to_offset(dll_tbl_rva)?;
    let probe = d.get(dll_tbl_off..dll_tbl_off + 13)?;
    if !probe.eq_ignore_ascii_case(b"KERNEL32.DLL\0") {
        return None;
    }

    let blob_size = blob.len();
    if desc_rva < rva || u64::from(desc_rva - rva) + 16 > blob_size as u64 {
        return None;
    }

    let mut dlls: Vec<RDll> = Vec::new();
    let mut dd = (desc_rva - rva) as usize;
    let mut guard = 0;
    while {
        guard += 1;
        guard < 4096
    } {
        if dd + 16 > blob_size {
            return None;
        }
        let marker = rd32(blob, dd);
        let name_off = rd32(blob, dd + 4);
        let iat = rd32(blob, dd + 8);
        if marker == 0 && name_off == 0 && iat == 0 {
            break;
        }
        let name_advance = rd32(blob, dd + 12);

        let mut lp = dd + 16;
        let mut lengths = Vec::new();
        while lp < blob_size && blob[lp] != 0 {
            lengths.push(blob[lp]);
            lp += 1;
        }
        if lp >= blob_size {
            return None;
        }
        if marker != (lp + 1 - dd) as u32 {
            return None;
        }

        let dll_name_off = pe.rva_to_offset(dll_tbl_rva.wrapping_add(name_off))?;
        let name_region = d.get(dll_name_off..dll_name_off + 64)?;
        let nul = name_region
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_region.len());
        if nul == 0 {
            return None;
        }
        let dll_name = name_region[..nul].to_vec();

        let mut funcs = Vec::new();
        let mut fb = dd + name_advance as usize;
        let mut slot = iat;
        for &l in &lengths {
            let l = l as usize;
            if fb + l + 5 > blob_size {
                return None;
            }
            let mut f = RFunc {
                ord: false,
                ordinal: 0,
                name: Vec::new(),
                iat_rva: slot,
            };
            if blob[fb] == 0xff {
                f.ord = true;
                f.ordinal = rd32(blob, fb + 1) & 0x7fffffff;
            } else {
                f.name = blob[fb..fb + l].to_vec();
            }
            funcs.push(f);
            fb += l;
            slot = slot.wrapping_add(4);
        }
        dlls.push(RDll {
            name: dll_name,
            first_thunk: iat,
            funcs,
        });
        dd = lp + 1;
    }
    if dlls.is_empty() {
        return None;
    }

    // layout: [descriptors][INTs][hint/names][dll strings]
    let desc_size = (dlls.len() as u32 + 1) * 20;
    let mut cur = desc_size;
    let mut int_rvas = Vec::with_capacity(dlls.len());
    for dll in &dlls {
        int_rvas.push(cur);
        cur += (dll.funcs.len() as u32 + 1) * 4;
    }
    let mut hint_map: Vec<(Vec<u8>, u32)> = Vec::new();
    let names_start = cur;
    let mut names = Vec::new();
    for dll in &dlls {
        for f in &dll.funcs {
            if !f.ord && !hint_map.iter().any(|(n, _)| n == &f.name) {
                hint_map.push((f.name.clone(), names_start + names.len() as u32));
                names.extend_from_slice(&[0, 0]);
                names.extend_from_slice(&f.name);
                names.push(0);
                if names.len() & 1 == 1 {
                    names.push(0);
                }
            }
        }
    }
    cur = names_start + names.len() as u32;
    let dll_start = cur;
    let mut dll_map: Vec<(Vec<u8>, u32)> = Vec::new();
    let mut dll_strings = Vec::new();
    for dll in &dlls {
        if !dll_map.iter().any(|(n, _)| n == &dll.name) {
            dll_map.push((dll.name.clone(), dll_start + dll_strings.len() as u32));
            dll_strings.extend_from_slice(&dll.name);
            dll_strings.push(0);
        }
    }
    let imp_size = dll_start + dll_strings.len() as u32;

    let mut section = vec![0u8; imp_size as usize];
    for (i, dll) in dlls.iter().enumerate() {
        let pd = i * 20;
        wr32(&mut section, pd, imp_rva.wrapping_add(int_rvas[i]));
        let name_rva = dll_map
            .iter()
            .find(|(n, _)| n == &dll.name)
            .map(|(_, r)| *r)
            .unwrap_or(0);
        wr32(&mut section, pd + 12, imp_rva.wrapping_add(name_rva));
        wr32(&mut section, pd + 16, dll.first_thunk);
        for (j, f) in dll.funcs.iter().enumerate() {
            let entry = if f.ord {
                0x8000_0000 | f.ordinal
            } else {
                let r = hint_map
                    .iter()
                    .find(|(n, _)| n == &f.name)
                    .map(|(_, r)| *r)
                    .unwrap_or(0);
                imp_rva.wrapping_add(r)
            };
            wr32(&mut section, (int_rvas[i] + j as u32 * 4) as usize, entry);
            if f.iat_rva >= rva && u64::from(f.iat_rva - rva) + 4 <= blob_size as u64 {
                let o = (f.iat_rva - rva) as usize;
                blob[o..o + 4].copy_from_slice(&entry.to_le_bytes());
            }
        }
    }
    section[names_start as usize..names_start as usize + names.len()].copy_from_slice(&names);
    section[dll_start as usize..dll_start as usize + dll_strings.len()]
        .copy_from_slice(&dll_strings);

    Some((section, desc_size))
}

/// `XNSPACK::_buildPE` — minimal single-section PE32 (+ `.idata` when
/// imports were reconstructed, + `.ghost` when the blob RVA needs it).
#[allow(clippy::too_many_arguments)]
fn build_pe(
    pe_src: &PackedPe,
    d: &[u8],
    blob: &[u8],
    rva: u32,
    image_base: u32,
    oep: u32,
    import_section: &[u8],
    imp_rva: u32,
    desc_size: u32,
    output_limit: i64,
) -> Vec<u8> {
    let has_imports = !import_section.is_empty();
    const HEADER_BASE: u32 = 0x40 + 4 + 20 + 0xE0;
    let base_secs = 1 + u32::from(has_imports);
    let mut raw_base = align(HEADER_BASE + 0x28 * base_secs, 0x200);
    let ghost = rva > align(raw_base, 0x1000);
    if ghost {
        raw_base = align(HEADER_BASE + 0x28 * (base_secs + 1), 0x200);
    }
    let num_sections = base_secs + u32::from(ghost);

    let rsz = align(blob.len() as u32, 0x200);
    let imp_raw = u64::from(raw_base) + u64::from(rsz);
    let imp_rsz = if has_imports {
        align(import_section.len() as u32, 0x200)
    } else {
        0
    };
    let raw_total = imp_raw + u64::from(imp_rsz);
    if raw_total > i32::MAX as u64 || (output_limit >= 0 && raw_total > output_limit as u64) {
        return Vec::new();
    }
    let mut out = vec![0u8; raw_total as usize];

    out[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    wr32(&mut out, 0x3C, 0x40);
    out[0x40..0x44].copy_from_slice(b"PE\0\0");
    let fh = 0x44;
    out[fh..fh + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    out[fh + 2..fh + 4].copy_from_slice(&(num_sections as u16).to_le_bytes());
    out[fh + 16..fh + 18].copy_from_slice(&0x00E0u16.to_le_bytes());
    out[fh + 18..fh + 20].copy_from_slice(&0x010Fu16.to_le_bytes());

    let mut image_end = align(rva.wrapping_add(blob.len() as u32), 0x1000);
    if has_imports {
        image_end = align(imp_rva.wrapping_add(import_section.len() as u32), 0x1000);
    }

    let oh = fh + 20;
    out[oh..oh + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    wr32(&mut out, oh + 16, oep);
    wr32(&mut out, oh + 28, image_base);
    wr32(&mut out, oh + 32, 0x1000);
    wr32(&mut out, oh + 36, 0x200);
    out[oh + 40..oh + 42].copy_from_slice(&4u16.to_le_bytes());
    out[oh + 48..oh + 50].copy_from_slice(&4u16.to_le_bytes());
    wr32(&mut out, oh + 56, image_end);
    wr32(&mut out, oh + 60, raw_base);
    out[oh + 68..oh + 70].copy_from_slice(&2u16.to_le_bytes());
    wr32(&mut out, oh + 92, 16);
    if has_imports {
        wr32(&mut out, oh + 104, imp_rva);
        wr32(&mut out, oh + 108, desc_size);
    }

    // TLS directory recovery: match the stub's relocated 12-byte
    // (Start/End/Index) signature inside the blob; prefer the single
    // "live" copy (nonzero AddressOfCallBacks at +0xC).
    if let Some((tls_rva, tls_size)) = pe_src.data_directory(9)
        && tls_rva != 0
        && tls_size >= 0x18
        && let Some(tls_off) = pe_src.rva_to_offset(tls_rva)
        && let Some(stub_tls) = d.get(tls_off..tls_off + 0x18)
        && stub_tls.len() >= 0x18
        && rd32(stub_tls, 0) != 0
    {
        let sig = &stub_tls[..12];
        let mut count = 0i32;
        let mut found = -1i64;
        let mut live = 0i32;
        let mut live_found = -1i64;
        let mut pos = 0usize;
        while pos + 12 <= blob.len() {
            if &blob[pos..pos + 12] == sig {
                count += 1;
                found = pos as i64;
                if pos + 16 <= blob.len() && rd32(blob, pos + 12) != 0 {
                    live += 1;
                    live_found = pos as i64;
                }
            }
            pos += 1;
        }
        let sel = if live == 1 {
            live_found
        } else if live == 0 && count == 1 {
            found
        } else {
            -1
        };
        if sel != -1 {
            wr32(&mut out, oh + 96 + 9 * 8, rva.wrapping_add(sel as u32));
            wr32(&mut out, oh + 96 + 9 * 8 + 4, tls_size);
        }
    }

    // Resource directory copy-through when it lands inside the blob.
    if let Some((res_rva, res_size)) = pe_src.data_directory(2)
        && res_rva != 0
        && res_size != 0
        && res_rva >= rva
        && u64::from(res_rva) + u64::from(res_size) <= u64::from(rva) + blob.len() as u64
    {
        wr32(&mut out, oh + 96 + 2 * 8, res_rva);
        wr32(&mut out, oh + 96 + 2 * 8 + 4, res_size);
    }

    let mut sec = oh + 0xE0;
    if ghost {
        out[sec..sec + 6].copy_from_slice(b".ghost");
        let ghost_va = align(raw_base, 0x1000);
        wr32(&mut out, sec + 8, rva - ghost_va);
        wr32(&mut out, sec + 12, ghost_va);
        wr32(&mut out, sec + 36, 0xE00000E0);
        sec += 0x28;
    }

    out[sec..sec + 7].copy_from_slice(b".clam01");
    wr32(&mut out, sec + 8, blob.len() as u32);
    wr32(&mut out, sec + 12, rva);
    wr32(&mut out, sec + 16, rsz);
    wr32(&mut out, sec + 20, raw_base);
    wr32(&mut out, sec + 36, 0xE00000E0);
    out[raw_base as usize..raw_base as usize + blob.len()].copy_from_slice(blob);

    if has_imports {
        sec += 0x28;
        out[sec..sec + 6].copy_from_slice(b".idata");
        wr32(&mut out, sec + 8, import_section.len() as u32);
        wr32(&mut out, sec + 12, imp_rva);
        wr32(&mut out, sec + 16, imp_rsz);
        wr32(&mut out, sec + 20, imp_raw as u32);
        wr32(&mut out, sec + 36, 0xC0000040);
        out[imp_raw as usize..imp_raw as usize + import_section.len()]
            .copy_from_slice(import_section);
    }

    out
}

/// `XNSPACK::_findStartOfStuff` — scan for `u32le(dsize)`; each hit's
/// `hit - 9` is a candidate `nsp0` header validated by mode byte and
/// `ssize` range.
fn find_start_of_stuff(d: &[u8], sec0_vsize: u32) -> i64 {
    if d.len() < 14 {
        return -1;
    }
    let needle = sec0_vsize.to_le_bytes();
    let mut best = -1i64;
    let mut from = 0usize;
    while let Some(hit) = d[from..]
        .windows(4)
        .position(|w| w == needle)
        .map(|p| p + from)
    {
        from = hit + 1;
        if hit < 9 {
            continue;
        }
        let sos = (hit - 9) as i64;
        if sos <= best {
            continue;
        }
        let h = &d[sos as usize..];
        if h.len() < 14 {
            continue;
        }
        let mut c = h[0];
        if c >= 0xe1 {
            continue;
        }
        if c >= 0x2d {
            c -= 0x2d * (c / 0x2d);
        }
        let allocsz = if c >= 9 {
            let a = u32::from(c / 9);
            c -= 9 * a as u8;
            a
        } else {
            0
        };
        if (allocsz + u32::from(c)) & 0xff > 12 {
            continue;
        }
        let ssize = rd32(h, 5);
        if ssize <= 13 || (sos as u64) + u64::from(ssize) > d.len() as u64 {
            continue;
        }
        best = sos;
    }
    best
}

/// `XNSPACK::_detect` — prologue match + 2.x/1.4-3.x start-of-stuff +
/// OEP recovery.
fn detect(d: &[u8]) -> Option<NsPackInfo> {
    let pe = PackedPe::parse(d).ok()?;
    if pe.is64() {
        return None;
    }
    let sections = pe.sections();
    if sections.is_empty() {
        return None;
    }
    let image_base = pe.image_base() as u32;
    let ep_rva = pe.entry_rva();
    let mut rep = pe.rva_to_offset(ep_rva)?;
    let mut src = d.get(rep..rep + 24)?;
    if src.len() < 24 {
        return None;
    }
    let mut eprva = ep_rva;
    if src[0] == 0xe9 {
        eprva = rd32(src, 1).wrapping_add(ep_rva).wrapping_add(5);
        rep = pe.rva_to_offset(eprva)?;
        src = d.get(rep..rep + 24)?;
        if src.len() < 24 {
            return None;
        }
    }
    if &src[..8] != b"\x9c\x60\xe8\x00\x00\x00\x00\x5d" {
        return None;
    }
    let b2x = &src[8..13] == b"\xb8\x07\x00\x00\x00";
    let sec0_vsize = sections[0].virtual_size;

    let start_of_stuff;
    let mut oep = sections[0].virtual_address;

    if b2x {
        let nowinldr = 0x54u32.wrapping_sub(rd32(src, 17));
        if (rep as i64) - i64::from(nowinldr) < 0 {
            return None;
        }
        let delta = d.get(rep - nowinldr as usize..rep - nowinldr as usize + 4)?;
        if delta.len() < 4 {
            return None;
        }
        let mut sos = (rep as u64).wrapping_add(u64::from(rd32(delta, 0))) as i64;
        let sos0 = d.get(sos as usize..sos as usize + 20)?;
        if sos0.len() < 20 {
            return None;
        }
        if rd32(sos0, 0) == 0 {
            sos += 4;
        }
        start_of_stuff = sos;

        let oep_jmp_rva = eprva.wrapping_add(0x27a);
        if let Some(rep_oep) = pe.rva_to_offset(oep_jmp_rva)
            && let Some(b) = d.get(rep_oep..rep_oep + 5)
            && b.len() >= 5
        {
            oep = oep_jmp_rva.wrapping_add(5).wrapping_add(rd32(b, 1));
        }
    } else {
        start_of_stuff = find_start_of_stuff(d, sec0_vsize);
        if start_of_stuff == -1 {
            return None;
        }
        let loader = d.get(rep..rep + 0x600).unwrap_or(&[]);
        let sec1_rva = if sections.len() > 1 {
            sections[1].virtual_address
        } else {
            0xFFFF_FFFF
        };
        for i in 0..loader.len().saturating_sub(6) {
            let q = &loader[i..];
            if q[0] == 0x61 && q[1] == 0x9d && q[2] == 0xe9 {
                let tgt = eprva
                    .wrapping_add(i as u32)
                    .wrapping_add(2)
                    .wrapping_add(5)
                    .wrapping_add(rd32(q, 3));
                if tgt >= sections[0].virtual_address && tgt < sec1_rva {
                    oep = tgt;
                    break;
                }
            }
        }
    }

    let sos = d.get(start_of_stuff as usize..start_of_stuff as usize + 14)?;
    if sos.len() < 14 {
        return None;
    }
    let ssize = rd32(sos, 5);
    let dsize = rd32(sos, 9);
    if ssize == 0 || dsize == 0 || dsize != sec0_vsize {
        return None;
    }

    Some(NsPackInfo {
        start_of_stuff: start_of_stuff as u64,
        ssize,
        dsize,
        oep,
        rva: sections[0].virtual_address,
        image_base,
    })
}

/// `XNSPACK::_detect` public wrapper.
pub fn detect_nspack(data: &[u8]) -> Option<NsPackInfo> {
    detect(data)
}

/// `XNSPACK::_unpackToBuffer` — detect, decompress, de-filter, rebuild
/// imports, rebuild the PE. `output_limit < 0` means unlimited.
pub fn unpack_nspack(data: &[u8], output_limit: i64) -> Result<Vec<u8>, UnpackError> {
    let info = detect(data).ok_or(UnpackError::NotPacked)?;
    let pe = PackedPe::parse(data)?;

    let avail = data.len() as i64 - info.start_of_stuff as i64;
    if avail <= 13 {
        return Err(UnpackError::Malformed("nspack: stuff range"));
    }
    let stuff = &data[info.start_of_stuff as usize..];

    let mut c = stuff[0];
    if c >= 0xe1 {
        return Err(UnpackError::Malformed("nspack: mode"));
    }
    let first_byte = if c >= 0x2d {
        let fb = u32::from(c / 0x2d);
        c -= 0x2d * fb as u8;
        fb
    } else {
        0
    };
    let allocsz = if c >= 9 {
        let a = u32::from(c / 9);
        c -= 9 * a as u8;
        a
    } else {
        0
    };
    let tre = u32::from(c);

    let shift = (tre + allocsz) & 0xff;
    if shift > 12 {
        return Err(UnpackError::Malformed("nspack: shift"));
    }
    let table_entries = (0x300u32.wrapping_shl(shift)).wrapping_add(0x736);

    let dsize = rd32(stuff, 9);
    let ssize = rd32(stuff, 5);
    // Upstream runs with nOutputLimit == -1 (unlimited); a 256 MiB hard
    // cap mirrors the upstream `XASPACK` image-size guard so hostile
    // `dsize` fields stay fail-closed instead of aborting on alloc.
    const HARD_CAP: u64 = 256 * 1024 * 1024;
    if ssize <= 13
        || dsize != info.dsize
        || u64::from(dsize) > HARD_CAP
        || (output_limit >= 0 && u64::from(dsize) > output_limit as u64)
    {
        return Err(UnpackError::Malformed("nspack: sizes"));
    }

    let mut table = vec![0u16; table_entries as usize];
    let mut blob = vec![0u8; dsize as usize];
    decompress(
        tre,
        allocsz,
        first_byte,
        &stuff[0xd..],
        &mut blob,
        &mut table,
    )
    .ok_or(UnpackError::Decompress("nspack: stream".into()))?;

    let (cj_valid, cc, cm, cg) = match read_call_jmp_control(&pe, data) {
        Some((c, m, g)) => (true, c, m, g),
        None => (false, 0, 0, 0),
    };
    de_filter_call_jmp(&mut blob, cc, cm, cg, cj_valid);

    let imp_rva = align(info.rva.wrapping_add(blob.len() as u32), 0x1000);
    let (imports, desc_size) =
        reconstruct_imports(&pe, data, &mut blob, info.rva, imp_rva).unwrap_or((Vec::new(), 0));

    let out = build_pe(
        &pe,
        data,
        &blob,
        info.rva,
        info.image_base,
        info.oep,
        &imports,
        imp_rva,
        desc_size,
        output_limit,
    );
    if out.is_empty() {
        return Err(UnpackError::Malformed("nspack: build"));
    }
    Ok(out)
}

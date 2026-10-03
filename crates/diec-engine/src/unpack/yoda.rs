//! yoda's Crypter (yC) static unpacking — port of upstream `XYODA`.
//!
//! Detection keys on the yC stub entry-point signatures (1.3, 1.3
//! variant, 1.x modified) plus the `\xAA\xE2\xCC` marker. The packed
//! payload carries two layers of a 0x30-byte **bytecode decryptor**
//! (`_polyEmulate`): a tiny AL-op interpreter (xor/add/sub/rot + short
//! jumps) that runs per output byte. Layer 1 decrypts the section
//! decryptor, layer 2 decrypts each original section in place; the
//! final yC section is then truncated off and the header repaired.

use super::UnpackError;
use super::upx::PackedPe;

/// Detection metadata for a yC-packed PE.
#[derive(Debug, Clone)]
pub struct YodaInfo {
    /// Version string as reported upstream ("1.3", "1.3 (variant)",
    /// "1.x (modified)").
    pub sversion: &'static str,
    /// Detected bytecode-program offset bias (`nOffset`).
    pub bias: i64,
    /// Layer-1 decrypt length / initial `cl` counter (`nEcx`).
    pub ecx: u32,
}

struct Detect {
    bias: i64,
    ecx: u32,
    sversion: &'static str,
}

fn rd_u16(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([d[off], d[off + 1]])
}

fn rd_u32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

/// `XYODA::_detect` — yC stub signature match, `nEcx` derivation, marker
/// check, and the file-range pre-validation for both consumed regions.
fn detect(d: &[u8]) -> Option<Detect> {
    let pe = PackedPe::parse(d).ok()?;
    if pe.is64() {
        return None;
    }
    let n = pe.sections().len();
    if n <= 1 {
        return None;
    }
    let ep_rva = pe.entry_rva();
    if ep_rva != pe.sections()[n - 1].virtual_address.wrapping_add(0x60) {
        return None;
    }
    let ep_off = pe.rva_to_offset(ep_rva)?;
    let ep = d.get(ep_off..ep_off + 0x80)?;
    if ep.len() < 0x80 {
        return None;
    }

    let mut bias = 0i64;
    let mut ecx = 0u32;
    let mut sversion = "";

    // yC 1.3
    if ep[..15] == b"\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED"[..]
        && ep[0x26..0x33] == b"\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC"[..]
        && ep[0x13] == 0xB9
        && rd_u16(ep, 0x18) == 0xE981
        && ep[0x1e..0x22] == b"\x8B\xD5\x81\xC2"[..]
    {
        bias = 0;
        if 0x6cu32
            .wrapping_sub(rd_u32(ep, 0xf))
            .wrapping_add(rd_u32(ep, 0x22))
            == 0xC6
        {
            ecx = rd_u32(ep, 0x14).wrapping_sub(rd_u32(ep, 0x1a));
            sversion = "1.3";
        }
    }

    // yC 1.3 variant
    if ecx == 0
        && ep[..9] == b"\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57"[..]
        && ep[0x17..0x1f] == b"\xe8\x00\x00\x00\x00\x5d\x81\xed"[..]
        && ep[0x23] == 0xB9
    {
        bias = 0x10;
        if 0x6cu32
            .wrapping_sub(rd_u32(ep, 0x1f))
            .wrapping_add(rd_u32(ep, 0x32))
            == 0xC6
        {
            ecx = rd_u32(ep, 0x24).wrapping_sub(rd_u32(ep, 0x2a));
            sversion = "1.3 (variant)";
        }
    }

    // yC 1.x / modified
    if ecx == 0
        && ep[..9] == b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed"[..]
        && ep[0xd] == 0xb9
        && rd_u16(ep, 0x12) == 0xbd8d
        && ep[0x18..0x1b] == b"\x8b\xf7\xac"[..]
    {
        bias = -0x18;
        if 0x66u32
            .wrapping_sub(rd_u32(ep, 0x9))
            .wrapping_add(rd_u32(ep, 0x14))
            == 0xae
        {
            ecx = rd_u32(ep, 0xe);
            sversion = "1.x (modified)";
        }
    }

    if ecx <= 0x800 || ecx >= 0x2000 {
        return None;
    }

    let marker = 0x63i64 + bias;
    if marker < 0 || ep.get(marker as usize..marker as usize + 3) != Some(b"\xaa\xe2\xcc") {
        return None;
    }

    // Reject when either consumed region would be truncated (upstream
    // isRangeWithinFile pre-validation).
    let yc_sect = pe.sections()[n - 1].raw_ptr as i64 + bias;
    let fs = d.len() as i64;
    let in_file = |off: i64, size: i64| off >= 0 && size >= 0 && off <= fs && size <= fs - off;
    if !in_file(yc_sect + 0xc6, ecx as i64) || !in_file(yc_sect + 0xa0f, 4) {
        return None;
    }

    Some(Detect {
        bias,
        ecx,
        sversion,
    })
}

/// `yodaOob` — strict range check helper.
fn oob(off: i64, size: i64) -> bool {
    off < 0 || off >= size
}

fn rol8(v: u8, n: u8) -> u8 {
    v.rotate_left(u32::from(n & 7))
}

fn ror8(v: u8, n: u8) -> u8 {
    v.rotate_right(u32::from(n & 7))
}

/// `XYODA::_polyEmulate` — run the 0x30-byte AL-op program at `dec_off`
/// against each byte of `[code_off, code_off + min(ecx, max_emu))`.
/// Returns the upstream status code (0 ok, 1 unknown opcode, 2 OOB).
fn poly_emulate(base: &mut [u8], dec_off: i64, code_off: i64, ecx: u32, max_emu: u32) -> i32 {
    let size = base.len() as i64;
    let mut cl = (ecx & 0xff) as u8;
    let mut max_jmp = 100_000_000u32;

    for i in 0..ecx.min(max_emu) {
        if oob(code_off + i as i64, size) {
            return 2;
        }
        let mut al = base[(code_off + i as i64) as usize];

        let mut j: i64 = 0;
        while j < 0x30 {
            if oob(dec_off + j, size) {
                return 2;
            }
            let op = base[(dec_off + j) as usize];
            match op {
                0xEB => {
                    // JMP short
                    j += 1;
                    if oob(dec_off + j, size) {
                        return 2;
                    }
                    if max_jmp == 0 {
                        return 2;
                    }
                    max_jmp -= 1;
                    j = j.wrapping_add(base[(dec_off + j) as usize] as i8 as i64);
                }
                0xFE => {
                    al = al.wrapping_sub(1);
                    j += 1;
                }
                0x2A => {
                    al = al.wrapping_sub(cl);
                    j += 1;
                }
                0x02 => {
                    al = al.wrapping_add(cl);
                    j += 1;
                }
                0x32 => {
                    al ^= cl;
                    j += 1;
                }
                0x04 => {
                    j += 1;
                    if oob(dec_off + j, size) {
                        return 2;
                    }
                    al = al.wrapping_add(base[(dec_off + j) as usize]);
                }
                0x34 => {
                    j += 1;
                    if oob(dec_off + j, size) {
                        return 2;
                    }
                    al ^= base[(dec_off + j) as usize];
                }
                0x2C => {
                    j += 1;
                    if oob(dec_off + j, size) {
                        return 2;
                    }
                    al = al.wrapping_sub(base[(dec_off + j) as usize]);
                }
                0xC0 => {
                    j += 1;
                    if oob(dec_off + j, size) {
                        return 2;
                    }
                    if base[(dec_off + j) as usize] == 0xC0 {
                        j += 1;
                        if oob(dec_off + j, size) {
                            return 2;
                        }
                        al = rol8(al, base[(dec_off + j) as usize]);
                    } else {
                        j += 1;
                        if oob(dec_off + j, size) {
                            return 2;
                        }
                        al = ror8(al, base[(dec_off + j) as usize]);
                    }
                }
                0xD2 => {
                    j += 1;
                    if oob(dec_off + j, size) {
                        return 2;
                    }
                    if base[(dec_off + j) as usize] == 0xC8 {
                        j += 1;
                        al = ror8(al, cl);
                    } else {
                        j += 1;
                        al = rol8(al, cl);
                    }
                }
                0x90 | 0xF8 | 0xF9 => {}
                _ => return 1,
            }
            j += 1;
        }

        cl = cl.wrapping_sub(1);
        if oob(code_off + i as i64, size) {
            return 2;
        }
        base[(code_off + i as i64) as usize] = al;
    }

    0
}

/// `XYODA::_detect` public wrapper.
pub fn detect_yoda(data: &[u8]) -> Option<YodaInfo> {
    let det = detect(data)?;
    Some(YodaInfo {
        sversion: det.sversion,
        bias: det.bias,
        ecx: det.ecx,
    })
}

/// Section-name DWORD values skipped by the layer-2 pass (`.rsrc`,
/// `srcc`, `reloc`-family names and the `yC` marker), upstream order.
const SKIP_NAMES: [u32; 8] = [
    0x6372_7372, // "rsrc"
    0x7273_722E, // ".rsr"
    0x6F6C_6572, // "relo"
    0x6C65_722E, // ".rel"
    0x6164_652E, // ".eda"
    0x6164_722E, // ".rda"
    0x6164_692E, // ".ida"
    0x736C_742E, // ".tls"
];

/// `XYODA::_unpackToBuffer` — decrypt sections in place, drop the yC
/// section, repair NumberOfSections/import dir/OEP/SizeOfImage.
/// `output_limit < 0` means unlimited (upstream `-1`).
pub fn unpack_yoda(data: &[u8], output_limit: i64) -> Result<Vec<u8>, UnpackError> {
    let det = detect(data).ok_or(UnpackError::NotPacked)?;
    let pe = PackedPe::parse(data)?;
    let n = pe.sections().len();
    if n <= 1 {
        return Err(UnpackError::Malformed("yoda: sections"));
    }
    let nsect = n - 1;

    let fs = data.len() as i64;
    let last_raw = pe.sections()[nsect].raw_ptr as i64;
    let decl_yc = pe.sections()[nsect].raw_size as i64;
    if fs <= 0 || fs > 0x7fff_ffff || last_raw < 0 || last_raw >= fs || decl_yc <= 0 {
        return Err(UnpackError::Malformed("yoda: yc range"));
    }
    let eff_yc = decl_yc.min(fs - last_raw);
    let cur_size = fs - eff_yc;
    if cur_size <= 0 || (output_limit >= 0 && cur_size as u64 > output_limit as u64) {
        return Err(UnpackError::Malformed("yoda: output limit"));
    }

    let mut buf = data.to_vec();
    let yc_sect = last_raw + det.bias;

    // layer 1: decrypt the section decryptor bytecode region.
    if poly_emulate(&mut buf, yc_sect + 0x93, yc_sect + 0xc6, det.ecx, det.ecx) != 0 {
        return Err(UnpackError::Decompress("yoda: layer1".into()));
    }

    // layer 2: decrypt each original section.
    let dec_off = yc_sect + if det.bias == -0x18 { 0x3ea } else { 0x457 };
    for i in 0..nsect {
        let sec = &pe.sections()[i];
        let name32 = u32::from_le_bytes([sec.name[0], sec.name[1], sec.name[2], sec.name[3]]);
        if sec.raw_ptr == 0
            || sec.raw_size == 0
            || SKIP_NAMES.contains(&name32)
            || (name32 & 0xffff) == 0x4379
        {
            continue;
        }
        if (sec.raw_ptr as i64) >= cur_size {
            return Err(UnpackError::Malformed("yoda: section raw"));
        }
        let max_emu = (cur_size - sec.raw_ptr as i64) as u32;
        let eff_raw = (sec.raw_size as i64).min(fs - sec.raw_ptr as i64) as u32;
        if poly_emulate(&mut buf, dec_off, sec.raw_ptr as i64, eff_raw, max_emu) != 0 {
            return Err(UnpackError::Decompress("yoda: layer2".into()));
        }
    }

    // header fixups
    let pe_off = rd_u32(&buf, 0x3C) as i64;
    if pe_off <= 0
        || pe_off > cur_size
        || 0x18 + 0x70 > cur_size - pe_off
        || yc_sect < 0
        || yc_sect > fs
        || 0xa0f + 4 > fs - yc_sect
    {
        return Err(UnpackError::Malformed("yoda: header"));
    }
    let pu = pe_off as usize;
    buf[pu + 6..pu + 8].copy_from_slice(&(nsect as u16).to_le_bytes());
    buf[pu + 0x18 + 0x68..pu + 0x18 + 0x70].fill(0);
    let oep = rd_u32(&buf, yc_sect as usize + 0xa0f);
    buf[pu + 0x18 + 16..pu + 0x18 + 20].copy_from_slice(&oep.to_le_bytes());
    let soi = rd_u32(&buf, pu + 0x18 + 0x38);
    let yc_vsize = pe.sections()[nsect].virtual_size;
    if soi < yc_vsize {
        return Err(UnpackError::Malformed("yoda: image size"));
    }
    buf[pu + 0x18 + 0x38..pu + 0x18 + 0x3c].copy_from_slice(&(soi - yc_vsize).to_le_bytes());

    buf.truncate(cur_size as usize);
    Ok(buf)
}

//! Petite (2.x / 2.x level 1) static unpacker — port of upstream
//! `XStaticUnpacker/xpetite.cpp` (the `petite_inflate2x_1to9` path).
//!
//! The embedded-decoder emulation path (`USE_XEMULATOR`) is not part of
//! the upstream oracle build either, so only the classic op-table inflate
//! is ported; embedded-decoder samples fail closed.

use super::PackedPe;
use super::upx::UnpackError;

fn rd32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

fn align(v: u32, a: u32) -> u32 {
    v.wrapping_add(a - 1) & !(a - 1)
}

fn cont(sz: usize, off: i64, len: i64) -> bool {
    off >= 0 && len >= 0 && off + len <= sz as i64
}

fn read_safe(b: &[u8], off: i64) -> i64 {
    if off >= 0 && off + 4 <= b.len() as i64 {
        rd32(b, off as usize) as i64
    } else {
        -1
    }
}

fn rel(min_rva: u32, rva: u32) -> i64 {
    rva as i64 - min_rva as i64
}

fn valid_rva(v: u32, min: u32, max: u32) -> bool {
    let v = v & 0x7fffffff;
    v >= min && v < max
}

/// `_doubledl` — same aPLib sentinel-bit refill reader as FSG/MEW.
fn doubledl(buf: &[u8], s: &mut i64, mydl: &mut u8) -> i64 {
    let old = *mydl;
    *mydl = old.wrapping_mul(2);
    if old & 0x7f == 0 {
        if *s < 0 || *s >= buf.len() as i64 - 1 {
            return -1;
        }
        let b = buf[*s as usize];
        *mydl = b.wrapping_mul(2).wrapping_add(1);
        *s += 1;
        return (b >> 7) as i64;
    }
    (old >> 7) as i64
}

/// Public detection result (`XPETITE::INTERNAL_INFO`).
pub struct PetiteInfo {
    /// Upstream version string ("2.x" or "2.x (level 1)").
    pub sversion: &'static str,
}

/// `XPETITE::_detect` — `mov eax, <loader base>` at the entry point.
fn detect_version(pe: &PackedPe) -> Option<u32> {
    if pe.is64() {
        return None;
    }
    let secs = pe.sections();
    if secs.is_empty() {
        return None;
    }
    let ep_off = pe.rva_to_offset(pe.entry_rva())?;
    let ep = pe.data().get(ep_off..ep_off + 0x84)?;
    if ep.len() < 0x84 {
        return None;
    }
    let image_base = pe.image_base() as u32;
    let n = secs.len();
    let found =
        if ep[0] == 0xb8 && rd32(ep, 1) == secs[n - 1].virtual_address.wrapping_add(image_base) {
            2
        } else if n >= 2
            && ep[0] == 0xb8
            && rd32(ep, 1) == secs[n - 2].virtual_address.wrapping_add(image_base)
        {
            1
        } else {
            0
        };
    if found == 0 {
        return None;
    }
    // Level-zero compression is not supported upstream either.
    if rd32(ep, 0x80) == 0x163c988d {
        return None;
    }
    Some(found)
}

/// `XPETITE::isValid`.
pub fn detect_petite(data: &[u8]) -> Option<PetiteInfo> {
    let pe = PackedPe::parse(data).ok()?;
    let found = detect_version(&pe)?;
    Some(PetiteInfo {
        sversion: if found == 2 { "2.x" } else { "2.x (level 1)" },
    })
}

/// `petParseOps` — op count if the stream terminates on a zero srva
/// with ≥2 ops and all RVAs in range, else -1.
fn parse_ops(buf: &[u8], min_rva: u32, max_rva: u32, pk: i64) -> i64 {
    let mut pk = pk;
    let mut nops = 0i64;
    while nops < 4096 {
        let sv = read_safe(buf, pk);
        if sv < 0 {
            return -1;
        }
        if sv == 0 {
            return if nops >= 2 { nops } else { -1 };
        }
        let size = (sv as u32) & 0x7fffffff;
        if sv as u32 != size {
            // copy op {srva|flag, src, dst}
            let s = read_safe(buf, pk + 4);
            let dd = read_safe(buf, pk + 8);
            if s < 0
                || dd < 0
                || !valid_rva(s as u32, min_rva, max_rva)
                || !valid_rva(dd as u32, min_rva, max_rva)
            {
                return -1;
            }
            pk += 0xc;
        } else {
            // section op {srva, size, thisrva}
            if !valid_rva(sv as u32, min_rva, max_rva) {
                return -1;
            }
            let tr = read_safe(buf, pk + 8);
            if tr < 0 || !valid_rva(tr as u32, min_rva, max_rva) {
                return -1;
            }
            pk += 0x10;
        }
        nops += 1;
    }
    -1
}

/// `_findOpTable` — locate the op table via `mov eax,loaderbase;
/// lea reg,[eax+imm]`; returns the buffer offset or -1.
fn find_op_table(
    buf: &[u8],
    min_rva: u32,
    loader_rva: u32,
    loader_vsz: u32,
    image_base: u32,
) -> i64 {
    let bufsz = buf.len() as i64;
    let max_rva = min_rva.wrapping_add(buf.len() as u32);
    let lo = loader_rva as i64 - min_rva as i64;
    if lo < 0 || lo >= bufsz {
        return -1;
    }
    let hi = (lo + loader_vsz as i64).min(bufsz);
    let loader_base = image_base.wrapping_add(loader_rva);

    let mut best_pk = -1i64;
    let mut best_ops = 0i64;
    let mut i = lo;
    while i + 5 <= hi {
        if buf[i as usize] != 0xb8 || rd32(buf, i as usize + 1) != loader_base {
            i += 1;
            continue;
        }
        let mut k = i + 5;
        while k + 6 <= hi && k < i + 5 + 0x140 {
            if buf[k as usize] != 0x8d || (buf[k as usize + 1] & 0xc7) != 0x80 {
                k += 1;
                continue;
            }
            let imm = rd32(buf, k as usize + 2) as i32;
            if imm < 0x100 || (imm as u32) >= loader_vsz {
                k += 1;
                continue;
            }
            let mut s = 0i64;
            while s < 0x40 {
                let nops = parse_ops(buf, min_rva, max_rva, lo + imm as i64 + s);
                if nops > best_ops {
                    best_ops = nops;
                    best_pk = lo + imm as i64 + s;
                }
                s += 4;
            }
            k += 1;
        }
        i += 1;
    }
    best_pk
}

/// One output section (`XPETITE::USECT`).
#[derive(Clone)]
struct USect {
    rva: u32,
    rsz: u32,
    vsz: u32,
    raw: u32,
}

/// `_inflate` — the op-table driven decode, shared-buffer semantics
/// (decode reads and writes the same work buffer like upstream).
#[allow(clippy::too_many_arguments)]
fn inflate(
    buf: &mut [u8],
    min_rva: u32,
    sections: &[super::upx::SectionHead],
    sect_count: usize,
    image_base: u32,
    pep: u32,
    version: u32,
) -> Result<(Vec<USect>, u32, bool), UnpackError> {
    let bufsz = buf.len();
    let (grown, skew) = if version != 2 {
        (0x323u32, 0x34u32)
    } else {
        (0x355, 0x35)
    };

    let loader_rva = sections[sect_count - 1].virtual_address;
    let loader_vsz = sections[sect_count - 1]
        .virtual_size
        .max(sections[sect_count - 1].raw_size);

    let mut pk = find_op_table(buf, min_rva, loader_rva, loader_vsz, image_base);
    if pk == -1 {
        pk = rel(min_rva, loader_rva) + if version == 2 { 0x1b8 } else { 0x178 };
    }

    let mut usects: Vec<USect> = Vec::new();
    let mut bottom = 0u32;
    let mut enc_ep = 0u32;
    let mut irva = 0u32;
    let mut workdone = 0u32;
    let mut mangled = 0i32;
    let mut check4resources = 0i32;
    let mut degraded = false;

    loop {
        if !cont(bufsz, pk, 4) {
            return Err(UnpackError::Malformed("petite: op table"));
        }
        let srva = rd32(buf, pk as usize);

        if srva == 0 {
            if usects.is_empty() {
                return Err(UnpackError::Malformed("petite: no sections"));
            }
            usects.sort_by_key(|u| u.rva);
            let j = usects.len();
            for t in 0..j.saturating_sub(1) {
                let want = usects[t + 1].rva.wrapping_sub(usects[t].rva);
                if usects[t].vsz != want {
                    usects[t].vsz = want;
                }
            }

            if enc_ep != 0 {
                let mut virtaddr = pep.wrapping_add(5).wrapping_add(image_base);
                let mut rndm = 0i32;
                let mut dummy = 1;
                let mut thunk = rel(min_rva, irva);

                if version == 2 {
                    while dummy != 0 && cont(bufsz, thunk, 4) {
                        if rd32(buf, thunk as usize) == 0 {
                            workdone = 1;
                            break;
                        }
                        let mut imports = rel(min_rva, rd32(buf, thunk as usize));
                        thunk += 4;
                        dummy = 0;
                        while cont(bufsz, imports, 4) {
                            dummy = 0;
                            imports += 4;
                            let mut api = rd32(buf, (imports - 4) as usize);
                            if api == 0 {
                                dummy = 1;
                                break;
                            }
                            if api & 0x80000000 == 0 && mangled != 0 {
                                rndm -= 1;
                                if rndm < 0 {
                                    api = virtaddr;
                                    virtaddr = virtaddr.wrapping_add(5);
                                    rndm = (virtaddr & 7) as i32;
                                } else {
                                    api = 0xbff01337;
                                }
                            } else {
                                api = 0xbff01337;
                            }
                            if sections[sect_count - 1]
                                .virtual_address
                                .wrapping_add(image_base)
                                < api
                            {
                                enc_ep = enc_ep.wrapping_sub(1);
                            }
                            if api < virtaddr {
                                enc_ep = enc_ep.wrapping_sub(1);
                            }
                            let tmpep = (enc_ep & 0xfffffff8) >> 3 & 0x1fffffff;
                            enc_ep = (enc_ep & 7) << 29 | tmpep;
                        }
                    }
                } else {
                    workdone = 1;
                }
                enc_ep = pep.wrapping_add(5).wrapping_add(enc_ep);
                if workdone != 1 {
                    enc_ep = usects[0].rva;
                    degraded = true;
                }
            }

            // Compact produced data into sequential raw offsets.
            for t in 0..usects.len() {
                usects[t].raw = if t > 0 {
                    usects[t - 1].raw + usects[t - 1].rsz
                } else {
                    0
                };
                if usects[t].rsz != 0 {
                    let dst = usects[t].raw as usize;
                    let src = rel(min_rva, usects[t].rva) as usize;
                    if cont(bufsz, dst as i64, usects[t].rsz as i64)
                        && (src as i64) >= 0
                        && src + usects[t].rsz as usize <= bufsz
                    {
                        buf.copy_within(src..src + usects[t].rsz as usize, dst);
                    } else {
                        usects[t].raw = if t > 0 { usects[t - 1].raw } else { 0 };
                        usects[t].rsz = 0;
                    }
                }
            }
            return Ok((usects, enc_ep, degraded));
        }

        let size_flag = srva & 0x7fffffff;
        if srva != size_flag {
            // copy packed data op {srva|flag, src, dst}
            check4resources = 0;
            if !cont(bufsz, pk + 4, 8) {
                return Err(UnpackError::Malformed("petite: copy op"));
            }
            bottom = rd32(buf, (pk + 8) as usize);
            if bottom > 0xFFFFFFFB {
                return Err(UnpackError::Malformed("petite: bottom"));
            }
            bottom = bottom.wrapping_add(4);
            let size = size_flag;
            let ssrc = rel(min_rva, rd32(buf, (pk + 4) as usize)) - (size as i64 - 1) * 4;
            let ddst = rel(min_rva, rd32(buf, (pk + 8) as usize)) - (size as i64 - 1) * 4;
            if !cont(bufsz, ssrc, size as i64 * 4) || !cont(bufsz, ddst, size as i64 * 4) {
                return Err(UnpackError::Malformed("petite: copy range"));
            }
            buf.copy_within(
                ssrc as usize..ssrc as usize + size as usize * 4,
                ddst as usize,
            );
            pk += 0x0c;
            continue;
        }

        // section op {srva, size, thisrva}
        if !cont(bufsz, pk + 4, 8) {
            return Err(UnpackError::Malformed("petite: sect op"));
        }
        let mut size = rd32(buf, (pk + 4) as usize);
        let thisrva = rd32(buf, (pk + 8) as usize);
        pk += 0x10;

        if usects.len() >= 96 {
            return Err(UnpackError::Malformed("petite: usect count"));
        }
        let mut us = USect {
            rva: thisrva,
            rsz: size,
            vsz: if (bottom.wrapping_sub(thisrva) as i32) > 0 {
                bottom.wrapping_sub(thisrva)
            } else {
                size
            },
            raw: 0,
        };
        if size == 0 {
            usects.push(us);
            continue;
        }

        let mut ssrc = rel(min_rva, srva);
        let mut ddst = rel(min_rva, thisrva);

        let mut q = 0usize;
        while q < sect_count {
            let sbb = sections[q].virtual_address;
            let sbbsz = sections[q].virtual_size;
            if us.rva >= sbb && (us.rva as u64 + us.vsz as u64) <= (sbb as u64 + sbbsz as u64) {
                if check4resources == 0 {
                    us.rva = sbb;
                    us.rsz = thisrva.wrapping_sub(sbb).wrapping_add(size);
                }
                break;
            }
            q += 1;
        }
        if q == sect_count {
            return Err(UnpackError::Malformed("petite: rva not in section"));
        }
        usects.push(us.clone());

        // Decode `size` bytes from buf[ssrc] to buf[ddst].
        let (check1, check2, goback) = if size < 0x10000 {
            (0x0FFFFC060u32, 0x0FFFFFC60u32, 5i32)
        } else if size < 0x40000 {
            (0x0FFFF8180, 0x0FFFFF980, 7)
        } else {
            (0x0FFFF8300, 0x0FFFFFB00, 8)
        };

        if !cont(bufsz, ssrc, 1) || !cont(bufsz, ddst, 1) {
            return Err(UnpackError::Malformed("petite: decode bounds"));
        }
        size -= 1;
        buf[ddst as usize] = buf[ssrc as usize];
        ddst += 1;
        ssrc += 1;
        let mut mydl = 0u8;
        let mut backbytes = 0i32;
        let mut oldback = 0i32;
        let mut size_left = size as i64;

        while size_left > 0 {
            let oob = doubledl(buf, &mut ssrc, &mut mydl);
            if oob == -1 {
                return Err(UnpackError::Malformed("petite: stream"));
            }
            if oob == 0 {
                if !cont(bufsz, ssrc, 1) || !cont(bufsz, ddst, 1) {
                    return Err(UnpackError::Malformed("petite: literal bounds"));
                }
                buf[ddst as usize] = buf[ssrc as usize] ^ (size_left as u8);
                ddst += 1;
                ssrc += 1;
                size_left -= 1;
            } else {
                let mut addsize = 0i32;
                backbytes += 1;
                loop {
                    let o = doubledl(buf, &mut ssrc, &mut mydl);
                    if o == -1 {
                        return Err(UnpackError::Malformed("petite: stream"));
                    }
                    if backbytes >= i32::MAX / 2 {
                        return Err(UnpackError::Malformed("petite: backbytes"));
                    }
                    backbytes = backbytes * 2 + o as i32;
                    let o2 = doubledl(buf, &mut ssrc, &mut mydl);
                    if o2 == -1 {
                        return Err(UnpackError::Malformed("petite: stream"));
                    }
                    if o2 == 0 {
                        break;
                    }
                }
                backbytes -= 3;
                let mut backsize: i64;
                if backbytes >= 0 {
                    backsize = goback as i64;
                    loop {
                        let o = doubledl(buf, &mut ssrc, &mut mydl);
                        if o == -1 {
                            return Err(UnpackError::Malformed("petite: stream"));
                        }
                        if backbytes >= i32::MAX / 2 {
                            return Err(UnpackError::Malformed("petite: backbytes"));
                        }
                        backbytes = backbytes * 2 + o as i32;
                        backsize -= 1;
                        if backsize == 0 {
                            break;
                        }
                    }
                    backbytes ^= -1;
                    addsize +=
                        1 + (backbytes < check1 as i32) as i32 + (backbytes < check2 as i32) as i32;
                    oldback = backbytes;
                } else {
                    backsize = (backbytes + 1) as i64;
                    backbytes = oldback;
                }

                let o = doubledl(buf, &mut ssrc, &mut mydl);
                if o == -1 {
                    return Err(UnpackError::Malformed("petite: stream"));
                }
                backsize = backsize * 2 + o;
                let o2 = doubledl(buf, &mut ssrc, &mut mydl);
                if o2 == -1 {
                    return Err(UnpackError::Malformed("petite: stream"));
                }
                backsize = backsize * 2 + o2;
                if backsize == 0 {
                    backsize += 1;
                    loop {
                        let x = doubledl(buf, &mut ssrc, &mut mydl);
                        if x == -1 {
                            return Err(UnpackError::Malformed("petite: stream"));
                        }
                        backsize = backsize * 2 + x;
                        let x2 = doubledl(buf, &mut ssrc, &mut mydl);
                        if x2 == -1 {
                            return Err(UnpackError::Malformed("petite: stream"));
                        }
                        if x2 == 0 {
                            break;
                        }
                    }
                    backsize += 2;
                }
                backsize += addsize as i64;
                if backsize > size_left
                    || !cont(bufsz, ddst, backsize)
                    || !cont(bufsz, ddst + backbytes as i64, backsize)
                {
                    return Err(UnpackError::Malformed("petite: match bounds"));
                }
                size_left -= backsize;
                let mut n = backsize;
                while n > 0 {
                    buf[ddst as usize] = buf[(ddst + backbytes as i64) as usize];
                    ddst += 1;
                    n -= 1;
                }
                backbytes = 0;
            }
        }

        // strip trailing petite loader code
        let j = usects.len();
        let mut strippetite = false;
        let mut reloc = 0u32;
        if usects[j - 1].rsz > grown
            && cont(bufsz, ddst - grown as i64 + 5 + 0x4f, 8)
            && rd32(buf, (ddst - grown as i64 + 5 + 0x4f) as usize) == 0x645ec033
            && rd32(buf, (ddst - grown as i64 + 5 + 0x4f + 4) as usize) == 0x1b8b188b
        {
            reloc = 0;
            strippetite = true;
        }
        if !strippetite
            && usects[j - 1].rsz > grown + skew
            && cont(bufsz, ddst - grown as i64 + 5 + 0x4f - skew as i64, 8)
            && rd32(buf, (ddst - grown as i64 + 5 + 0x4f - skew as i64) as usize) == 0x645ec033
            && rd32(
                buf,
                (ddst - grown as i64 + 5 + 0x4f + 4 - skew as i64) as usize,
            ) == 0x1b8b188b
        {
            reloc = skew;
            strippetite = true;
        }
        if strippetite && cont(bufsz, ddst - grown as i64 + 0x0f - 8 - reloc as i64, 8) {
            let test1 = rd32(
                buf,
                (ddst - grown as i64 + 0x0f - 8 - reloc as i64) as usize,
            ) ^ 0x9d6661aa;
            let test2 = rd32(
                buf,
                (ddst - grown as i64 + 0x0f - 4 - reloc as i64) as usize,
            ) ^ 0xe908c483;
            if test1 == test2
                && cont(
                    bufsz,
                    ddst - grown as i64 + 0x0f - reloc as i64,
                    0x1c0 - 0x0f + 4,
                )
            {
                irva = rd32(buf, (ddst - grown as i64 + 0x121 - reloc as i64) as usize);
                enc_ep = rd32(buf, (ddst - grown as i64 + 0x0f - reloc as i64) as usize) ^ test1;
                mangled = (rd32(buf, (ddst - grown as i64 + 0x1c0 - reloc as i64) as usize)
                    != 0x90909090) as i32;
            }
            usects[j - 1].rsz = usects[j - 1].rsz.wrapping_sub(grown + reloc);
        }
        check4resources += 1;
    }
}

/// `XPETITE::_buildPE` — same frame as MEW's but 0x200-aligned raws and
/// a preserved resource data directory.
fn build_pe(
    buf: &[u8],
    out: &[USect],
    image_base: u32,
    oep: u32,
    res_rva: u32,
    res_size: u32,
    output_limit: i64,
) -> Result<Vec<u8>, UnpackError> {
    if out.is_empty() {
        return Err(UnpackError::Malformed("petite: no sections"));
    }
    let nsects = out.len() as u32;
    let header_base = 0x40 + 4 + 20 + 0xE0u32;
    let first_rva = out[0].rva;
    let mut raw_base = align(header_base + 0x28 * nsects, 0x200);
    let ghost = first_rva > align(raw_base, 0x1000);
    if ghost {
        raw_base = align(header_base + 0x28 * (nsects + 1), 0x200);
    }

    let mut raw_total = u64::from(raw_base);
    let mut max_vend = 0u32;
    for s in out {
        raw_total += u64::from(align(s.rsz, 0x200));
        max_vend = max_vend.max(s.rva.saturating_add(s.vsz.max(s.rsz)));
    }
    if raw_total > i32::MAX as u64 || (output_limit >= 0 && raw_total > output_limit as u64) {
        return Err(UnpackError::Malformed("petite: output too large"));
    }
    let mut o = vec![0u8; raw_total as usize];

    o[0] = 0x4D;
    o[1] = 0x5A;
    o[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    let pe = 0x40;
    o[pe..pe + 4].copy_from_slice(&0x4550u32.to_le_bytes());
    let fh = pe + 4;
    o[fh..fh + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    o[fh + 2..fh + 4].copy_from_slice(&((nsects + u32::from(ghost)) as u16).to_le_bytes());
    o[fh + 16..fh + 18].copy_from_slice(&0x00E0u16.to_le_bytes());
    o[fh + 18..fh + 20].copy_from_slice(&0x010Fu16.to_le_bytes());
    let oh = fh + 20;
    o[oh..oh + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    o[oh + 16..oh + 20].copy_from_slice(&oep.to_le_bytes());
    o[oh + 28..oh + 32].copy_from_slice(&image_base.to_le_bytes());
    o[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    o[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes());
    o[oh + 40..oh + 42].copy_from_slice(&4u16.to_le_bytes());
    o[oh + 48..oh + 50].copy_from_slice(&4u16.to_le_bytes());
    o[oh + 56..oh + 60].copy_from_slice(&align(max_vend, 0x1000).to_le_bytes());
    o[oh + 60..oh + 64].copy_from_slice(&raw_base.to_le_bytes());
    o[oh + 68..oh + 70].copy_from_slice(&2u16.to_le_bytes());
    o[oh + 92..oh + 96].copy_from_slice(&16u32.to_le_bytes());
    o[oh + 0x60 + 16..oh + 0x60 + 20].copy_from_slice(&res_rva.to_le_bytes());
    o[oh + 0x60 + 20..oh + 0x60 + 24].copy_from_slice(&res_size.to_le_bytes());

    let mut sec = oh + 0xE0;
    let mut raw = raw_base as usize;
    if ghost {
        o[sec..sec + 6].copy_from_slice(b".ghost");
        let ghost_va = align(raw_base, 0x1000);
        o[sec + 8..sec + 12].copy_from_slice(&first_rva.wrapping_sub(ghost_va).to_le_bytes());
        o[sec + 12..sec + 16].copy_from_slice(&ghost_va.to_le_bytes());
        o[sec + 36..sec + 40].copy_from_slice(&0xE00000E0u32.to_le_bytes());
        sec += 0x28;
    }
    for (i, u) in out.iter().enumerate() {
        let name = format!(".clam{:02}", i + 1);
        o[sec..sec + name.len()].copy_from_slice(name.as_bytes());
        let rsz = align(u.rsz, 0x200);
        o[sec + 8..sec + 12].copy_from_slice(&if u.vsz != 0 { u.vsz } else { u.rsz }.to_le_bytes());
        o[sec + 12..sec + 16].copy_from_slice(&u.rva.to_le_bytes());
        o[sec + 16..sec + 20].copy_from_slice(&rsz.to_le_bytes());
        o[sec + 20..sec + 24].copy_from_slice(&(raw as u32).to_le_bytes());
        o[sec + 36..sec + 40].copy_from_slice(&0xE00000E0u32.to_le_bytes());
        let end = u.raw as usize + u.rsz as usize;
        if end <= buf.len() {
            o[raw..raw + u.rsz as usize].copy_from_slice(&buf[u.raw as usize..end]);
        }
        raw += rsz as usize;
        sec += 0x28;
    }
    Ok(o)
}

/// `XPETITE::_unpackToBuffer`.
pub fn unpack_petite(data: &[u8], output_limit: i64) -> Result<Vec<u8>, UnpackError> {
    let pe = PackedPe::parse(data)?;
    let version = detect_version(&pe).ok_or(UnpackError::Malformed("petite: not detected"))?;
    let secs = pe.sections();
    if secs.is_empty() {
        return Err(UnpackError::Malformed("petite: sections"));
    }
    let image_base = pe.image_base() as u32;
    let vep = pe.entry_rva();

    let mut n_min = u32::MAX;
    let mut n_max = 0u32;
    for s in secs {
        n_min = n_min.min(s.virtual_address);
        n_max = n_max.max(
            s.virtual_address
                .saturating_add(s.virtual_size.max(s.raw_size)),
        );
    }
    if n_max <= n_min {
        return Err(UnpackError::Malformed("petite: extent"));
    }
    let dsize = n_max - n_min;
    if dsize > 256 * 1024 * 1024 || (output_limit >= 0 && u64::from(dsize) > output_limit as u64) {
        return Err(UnpackError::Malformed("petite: size"));
    }

    let mut buf = vec![0u8; dsize as usize];
    for s in secs {
        if s.raw_ptr == 0 || s.raw_size == 0 {
            continue;
        }
        let off = s.virtual_address as i64 - n_min as i64;
        if off < 0 || off + s.raw_size as i64 > dsize as i64 {
            return Err(UnpackError::Malformed("petite: section range"));
        }
        let src = data
            .get(s.raw_ptr as usize..s.raw_ptr as usize + s.raw_size as usize)
            .ok_or(UnpackError::Malformed("petite: section read"))?;
        buf[off as usize..off as usize + s.raw_size as usize].copy_from_slice(src);
    }

    let sect_count = secs.len() - usize::from(version == 1);
    if sect_count < 1 {
        return Err(UnpackError::Malformed("petite: sect count"));
    }

    let res = pe.data_directory(2).unwrap_or((0, 0));
    let (out, enc_ep, _degraded) =
        inflate(&mut buf, n_min, secs, sect_count, image_base, vep, version)?;
    build_pe(&buf, &out, image_base, enc_ep, res.0, res.1, output_limit)
}

//! MEW (10 / 11 SE) static unpacker — port of upstream
//! `XStaticUnpacker/xmew.cpp`.
//!
//! MEW's non-LZMA path uses the same aPLib bitstream as FSG; the LZMA
//! path is stock raw LZMA1 (lc=4/lp=0/pb=2) framed by a MEW-specific
//! container after the aPLib loader blocks.

use super::PackedPe;
use super::aplib::aplib_depack_in_place;
use super::upx::UnpackError;

fn rd32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

fn align(v: u32, a: u32) -> u32 {
    v.wrapping_add(a - 1) & !(a - 1)
}

fn cont(size: u64, off: i64, len: u64) -> bool {
    off >= 0 && off as u64 + len <= size
}

/// Detection state extracted by `XMEW::_detect` (`DETECT`).
struct Detect {
    /// 10 or 11 (11 covers MEW 11 and 11 SE).
    version: u32,
    off_diff: u32,
    ssize: u32,
    dsize: u32,
    /// section[i+1] PointerToRawData.
    src_raw: u32,
    /// section[i+1] SizeOfRawData.
    src_rsz: u32,
    /// section[0].rva.
    vadd: u32,
    image_base: u32,
    use_lzma: u32,
}

/// Public detection result (`XMEW::INTERNAL_INFO`).
pub struct MewInfo {
    /// Upstream version string ("10" or "11 SE").
    pub sversion: &'static str,
    /// Whether the payload uses the LZMA container path.
    pub uses_lzma: bool,
}

/// `XMEW::_detect` — EP jump to the stub table at file offset
/// 0x154/0x155/0x158, then version-splitting bytes.
fn detect(pe: &PackedPe) -> Option<Detect> {
    if pe.is64() {
        return None;
    }
    let secs = pe.sections();
    if secs.len() < 2 {
        return None;
    }
    let index = (0..secs.len() - 1).find(|&k| {
        secs[k].raw_size == 0
            && secs[k].virtual_size != 0
            && secs[k + 1].raw_size != 0
            && secs[k + 1].virtual_size != 0
    })?;

    let vep = pe.entry_rva();
    let image_base = pe.image_base() as u32;
    let ep_off = pe.rva_to_offset(vep)?;
    let ep = pe.data().get(ep_off..ep_off + 16)?;
    if ep.len() < 16 {
        return None;
    }

    // MEW 11/11 SE enter with a bare `jmp rel32`; MEW 10 prefixes
    // `xor eax,eax`.
    let prefix = if ep[0] == 0xe9 {
        0usize
    } else if ep[0] == 0x33 && ep[1] == 0xc0 && ep[2] == 0xe9 {
        2
    } else {
        return None;
    };
    let file_offset = vep
        .wrapping_add(prefix as u32)
        .wrapping_add(rd32(ep, prefix + 1))
        .wrapping_add(5);
    if file_offset != 0x154 && file_offset != 0x155 && file_offset != 0x158 {
        return None;
    }
    let tbuff = pe
        .data()
        .get(file_offset as usize..file_offset as usize + 0xb0)?;
    if tbuff.len() < 0xb0 || tbuff[0] != 0xbe {
        return None;
    }
    let version = if tbuff[5] == 0xac && tbuff[6] == 0x91 {
        10
    } else if tbuff[5] == 0x8b && tbuff[6] == 0xde {
        11
    } else {
        return None;
    };

    let src_sec = &secs[index + 1];
    let dst_sec = &secs[index];
    let mut off_diff = rd32(tbuff, 1).wrapping_sub(image_base);
    if off_diff <= src_sec.virtual_address
        || off_diff
            >= src_sec
                .virtual_address
                .wrapping_add(src_sec.raw_ptr)
                .saturating_sub(4)
    {
        return None;
    }
    off_diff -= src_sec.virtual_address;

    let ssize = src_sec.virtual_size;
    let dsize = dst_sec.virtual_size;
    if ssize.checked_add(dsize).is_none()
        || u64::from(off_diff) >= u64::from(ssize) + u64::from(dsize)
    {
        return None;
    }
    if src_sec.raw_size < off_diff + 12 || src_sec.raw_size > ssize {
        return None;
    }

    let mut use_lzma = 0u32;
    if version == 11 && tbuff[0x7b] == 0xe8 {
        use_lzma = rd32(tbuff, 0x7c).wrapping_sub(
            secs[0]
                .virtual_address
                .wrapping_sub(file_offset)
                .wrapping_sub(0x80),
        );
    }

    Some(Detect {
        version,
        off_diff,
        ssize,
        dsize,
        src_raw: src_sec.raw_ptr,
        src_rsz: src_sec.raw_size,
        vadd: secs[0].virtual_address,
        image_base,
        use_lzma,
    })
}

/// One rebuilt output section (`XMEW::SECT`).
struct Sect {
    rva: u32,
    rsz: u32,
    vsz: u32,
    /// Offset into the work buffer.
    raw: usize,
}

/// `XMEW::_buildPE` — same frame as FSG's `_rebuildPE` but 0x1000-aligned
/// section raw sizes and content read from the work buffer.
fn build_pe(
    buf: &[u8],
    sections: &[Sect],
    image_base: u32,
    oep: u32,
    output_limit: i64,
) -> Result<Vec<u8>, UnpackError> {
    if sections.is_empty() {
        return Err(UnpackError::Malformed("mew: no sections"));
    }
    let nsects = sections.len() as u32;
    let header_base = 0x40 + 4 + 20 + 0xE0u32;
    let first_rva = sections[0].rva;
    let mut raw_base = align(header_base + 0x28 * nsects, 0x200);
    let ghost = first_rva > align(raw_base, 0x1000);
    if ghost {
        raw_base = align(header_base + 0x28 * (nsects + 1), 0x200);
    }

    let mut raw_total = u64::from(raw_base);
    let mut max_vend = 0u32;
    for s in sections {
        raw_total += u64::from(align(s.rsz, 0x1000));
        max_vend = max_vend.max(s.rva.saturating_add(s.vsz.max(s.rsz)));
    }
    if raw_total > i64::MAX as u64 || (output_limit >= 0 && raw_total > output_limit as u64) {
        return Err(UnpackError::Malformed("mew: output too large"));
    }
    let mut out = vec![0u8; raw_total as usize];

    out[0] = 0x4D;
    out[1] = 0x5A;
    out[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    let pe = 0x40;
    out[pe..pe + 4].copy_from_slice(&0x4550u32.to_le_bytes());
    let fh = pe + 4;
    out[fh..fh + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    out[fh + 2..fh + 4].copy_from_slice(&((nsects + u32::from(ghost)) as u16).to_le_bytes());
    out[fh + 16..fh + 18].copy_from_slice(&0x00E0u16.to_le_bytes());
    out[fh + 18..fh + 20].copy_from_slice(&0x010Fu16.to_le_bytes());
    let oh = fh + 20;
    out[oh..oh + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    out[oh + 16..oh + 20].copy_from_slice(&oep.to_le_bytes());
    out[oh + 28..oh + 32].copy_from_slice(&image_base.to_le_bytes());
    out[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    out[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes());
    out[oh + 40..oh + 42].copy_from_slice(&4u16.to_le_bytes());
    out[oh + 48..oh + 50].copy_from_slice(&4u16.to_le_bytes());
    out[oh + 56..oh + 60].copy_from_slice(&align(max_vend, 0x1000).to_le_bytes());
    out[oh + 60..oh + 64].copy_from_slice(&raw_base.to_le_bytes());
    out[oh + 68..oh + 70].copy_from_slice(&2u16.to_le_bytes());
    out[oh + 92..oh + 96].copy_from_slice(&16u32.to_le_bytes());

    let mut sec = oh + 0xE0;
    let mut raw = raw_base as usize;
    if ghost {
        out[sec..sec + 6].copy_from_slice(b".ghost");
        let ghost_va = align(raw_base, 0x1000);
        out[sec + 8..sec + 12].copy_from_slice(&first_rva.wrapping_sub(ghost_va).to_le_bytes());
        out[sec + 12..sec + 16].copy_from_slice(&ghost_va.to_le_bytes());
        out[sec + 36..sec + 40].copy_from_slice(&0xE00000E0u32.to_le_bytes());
        sec += 0x28;
    }
    for (i, s) in sections.iter().enumerate() {
        let name = format!(".clam{:02}", i + 1);
        out[sec..sec + name.len()].copy_from_slice(name.as_bytes());
        let rsz = align(s.rsz, 0x1000);
        out[sec + 8..sec + 12]
            .copy_from_slice(&if s.vsz != 0 { s.vsz } else { s.rsz }.to_le_bytes());
        out[sec + 12..sec + 16].copy_from_slice(&s.rva.to_le_bytes());
        out[sec + 16..sec + 20].copy_from_slice(&rsz.to_le_bytes());
        out[sec + 20..sec + 24].copy_from_slice(&(raw as u32).to_le_bytes());
        out[sec + 36..sec + 40].copy_from_slice(&0xE00000E0u32.to_le_bytes());
        let end = s.raw.saturating_add(s.rsz as usize);
        if end <= buf.len() {
            out[raw..raw + s.rsz as usize].copy_from_slice(&buf[s.raw..end]);
        }
        raw += rsz as usize;
        sec += 0x28;
    }
    Ok(out)
}

/// `XMEW::_decodeRawLzma` — stock raw LZMA1 (lc=4/lp=0/pb=2) with the
/// container's exact uncompressed size as the success test.
fn decode_raw_lzma(src: &[u8], dst_size: usize, dict_size: u32) -> Result<Vec<u8>, UnpackError> {
    use lzma_rs::decompress::raw::{LzmaDecoder, LzmaParams, LzmaProperties};
    if src.len() <= 16 || dst_size == 0 {
        return Err(UnpackError::Malformed("mew: lzma size"));
    }
    let props = LzmaProperties {
        lc: 4,
        lp: 0,
        pb: 2,
    };
    let params = LzmaParams::new(props, dict_size.max(0x1000), Some(dst_size as u64));
    let mut dec =
        LzmaDecoder::new(params, None).map_err(|_| UnpackError::Malformed("mew: lzma init"))?;
    let mut out = Vec::with_capacity(dst_size);
    let mut input = std::io::BufReader::new(src);
    dec.decompress(&mut input, &mut out)
        .map_err(|_| UnpackError::Malformed("mew: lzma decode"))?;
    if out.len() != dst_size {
        return Err(UnpackError::Malformed("mew: lzma size mismatch"));
    }
    Ok(out)
}

/// `XMEW::_bcjFilter` — "special" mode x86 call/jmp de-filter.
fn bcj_filter(data: &mut [u8], size: u32, len: u32) {
    if len < 5 {
        return;
    }
    let len = len.min(size) as usize;
    let mut i = 0usize;
    while i + 5 < len {
        if data[i] == 0xe8 || data[i] == 0xe9 {
            let v = rd32(data, i + 1);
            let bs = v.swap_bytes();
            let out_v = bs.wrapping_sub(i as u32).wrapping_sub(1);
            data[i + 1..i + 5].copy_from_slice(&out_v.to_le_bytes());
            i += 4;
        }
        i += 1;
    }
}

/// `XMEW::_lzmaDepack` — MEW LZMA container walk + raw LZMA1 decode.
fn lzma_depack(
    buf: &mut [u8],
    container_off: usize,
    use_lzma: u32,
    dsize: u32,
    vma: u32,
) -> Result<(), UnpackError> {
    let size = buf.len() as u64;
    if !cont(size, use_lzma as i64 + 8, 4) {
        return Err(UnpackError::Malformed("mew: lzma tag"));
    }
    let uz = use_lzma as usize;
    let special = buf[uz + 0x0b] == 0x56 || buf[uz + 8] == 0x50;

    let mut p = container_off;
    if !cont(size, p as i64, 4) {
        return Err(UnpackError::Malformed("mew: lzma container"));
    }
    p += 4; // prob-array RVA (unused by the SDK decode)

    let mut blocks = 0usize;
    loop {
        if !special {
            if !cont(size, p as i64, 4) {
                return Err(UnpackError::Malformed("mew: lzma term"));
            }
            if rd32(buf, p) == 0 {
                break;
            }
        }
        if !cont(size, p as i64, 13) {
            return Err(UnpackError::Malformed("mew: lzma block hdr"));
        }
        let unp_size = rd32(buf, p);
        p += 4;
        let dest_rva = rd32(buf, p);
        p += 4;
        let csize = rd32(buf, p);
        p += 5; // 4-byte size + 1 skipped byte
        let stream_off = p;
        p += csize as usize;

        if unp_size == 0 {
            return Err(UnpackError::Malformed("mew: lzma zero size"));
        }
        let dest_off = dest_rva as i64 - vma as i64;
        if !cont(size, dest_off, u64::from(unp_size)) {
            return Err(UnpackError::Malformed("mew: lzma dest"));
        }
        let src = buf
            .get(stream_off..)
            .ok_or(UnpackError::Malformed("mew: lzma stream"))?;
        let dict = if dsize != 0 { dsize } else { unp_size };
        let decoded = decode_raw_lzma(src, unp_size as usize, dict)?;
        let d = dest_off as usize;
        buf[d..d + unp_size as usize].copy_from_slice(&decoded);

        if special {
            bcj_filter(&mut buf[d..d + unp_size as usize], unp_size, unp_size);
            break; // special mode processes exactly one block
        }
        blocks += 1;
        if blocks > 4096 {
            return Err(UnpackError::Malformed("mew: lzma block count"));
        }
    }
    Ok(())
}

/// `XMEW::_unpackMew10` — header `db nBlocks | dd helper | dd srcVA |
/// nBlocks*dd destVA | dd fixerVA`; continuous source stream; OEP is
/// the dword before the import fixer.
fn unpack_mew10(buf: &mut [u8], d: &Detect, output_limit: i64) -> Result<Vec<u8>, UnpackError> {
    let size_sum = u64::from(d.ssize) + u64::from(d.dsize);
    let base = d.image_base;
    let vma = base.wrapping_add(d.vadd);

    let hdr = i64::from(d.dsize) + i64::from(d.off_diff);
    if !cont(size_sum, hdr, 1) {
        return Err(UnpackError::Malformed("mew10: header"));
    }
    let nblocks = buf[hdr as usize] as u32;
    if nblocks == 0 || nblocks > 64 {
        return Err(UnpackError::Malformed("mew10: block count"));
    }
    if !cont(size_sum, hdr, 13 + 4 * u64::from(nblocks)) {
        return Err(UnpackError::Malformed("mew10: header size"));
    }
    let mut lesi = i64::from(rd32(buf, hdr as usize + 5).wrapping_sub(vma));

    let mut sections = Vec::new();
    for k in 0..nblocks {
        let dest_va = rd32(buf, hdr as usize + 9 + 4 * k as usize);
        let ledi = i64::from(dest_va) - i64::from(vma);
        if lesi < 0 || lesi as u64 >= size_sum || ledi < 0 || ledi as u64 >= size_sum {
            return Err(UnpackError::Malformed("mew10: block range"));
        }
        let (produced, consumed) = aplib_depack_in_place(
            buf,
            lesi as usize,
            (size_sum as usize).saturating_sub(lesi as usize),
            ledi as usize,
            (size_sum as usize).saturating_sub(ledi as usize),
        )?;
        if consumed == 0 {
            return Err(UnpackError::Malformed("mew10: zero consumed"));
        }
        // The final block lands in the source section: the import
        // fixer, not a section of the original image.
        if ledi + produced as i64 <= i64::from(d.dsize) {
            if dest_va < base {
                return Err(UnpackError::Malformed("mew10: dest va"));
            }
            sections.push(Sect {
                raw: ledi as usize,
                rva: dest_va - base,
                rsz: produced as u32,
                vsz: produced as u32,
            });
        }
        lesi += consumed as i64;
    }
    if sections.is_empty() {
        return Err(UnpackError::Malformed("mew10: no sections"));
    }
    let fixer = i64::from(rd32(buf, hdr as usize + 9 + 4 * nblocks as usize).wrapping_sub(vma));
    if !cont(size_sum, fixer - 4, 4) {
        return Err(UnpackError::Malformed("mew10: fixer"));
    }
    let stored_oep = rd32(buf, (fixer - 4) as usize);
    if stored_oep < base {
        return Err(UnpackError::Malformed("mew10: oep"));
    }
    build_pe(buf, &sections, base, stored_oep - base, output_limit)
}

/// `XMEW::isValid` — detection only.
pub fn detect_mew(data: &[u8]) -> Option<MewInfo> {
    let pe = PackedPe::parse(data).ok()?;
    let d = detect(&pe)?;
    Some(MewInfo {
        sversion: if d.version == 10 { "10" } else { "11 SE" },
        uses_lzma: d.use_lzma != 0,
    })
}

/// `XMEW::_unpackToBuffer` — detect, build the ssize+dsize work buffer,
/// walk the aPLib block chain (and the LZMA container when flagged).
pub fn unpack_mew(data: &[u8], output_limit: i64) -> Result<Vec<u8>, UnpackError> {
    let pe = PackedPe::parse(data)?;
    let d = detect(&pe).ok_or(UnpackError::Malformed("mew: not detected"))?;

    let ssize = d.ssize;
    let dsize = d.dsize;
    let size_sum = u64::from(ssize) + u64::from(dsize);
    if size_sum > i64::MAX as u64 || (output_limit >= 0 && u64::from(dsize) > output_limit as u64) {
        return Err(UnpackError::Malformed("mew: size"));
    }
    let vadd = d.vadd;
    let base = d.image_base;
    let vma = base.wrapping_add(vadd);
    let off = d.off_diff;

    let mut buf = vec![0u8; size_sum as usize];
    let src = data
        .get(d.src_raw as usize..d.src_raw as usize + d.src_rsz as usize)
        .ok_or(UnpackError::Malformed("mew: src read"))?;
    buf[dsize as usize..dsize as usize + d.src_rsz as usize].copy_from_slice(src);

    if d.version == 10 {
        return unpack_mew10(&mut buf, &d, output_limit);
    }

    if !cont(size_sum, i64::from(off), 12) {
        return Err(UnpackError::Malformed("mew: header"));
    }
    let source_off = dsize as usize + off as usize;
    let mut lesi = (source_off + 12) as i64;
    let entry_point = rd32(&buf, source_off + 4);
    let new_edi = rd32(&buf, source_off + 8);
    let mut ledi = i64::from(new_edi) - i64::from(vma);
    // The destination budget spans the whole ssize+dsize buffer, not
    // just dsize (LZMA stubs land in the source region).
    let mut loc_ds = size_sum as i64 - (i64::from(new_edi) - i64::from(vma));
    let mut loc_ss = i64::from(ssize) - 12 - i64::from(off);

    let mut sections = vec![Sect {
        raw: 0,
        rva: vadd,
        rsz: 0,
        vsz: 0,
    }];

    let mut idx = 0usize;
    loop {
        if !cont(size_sum, lesi, loc_ss as u64) || !cont(size_sum, ledi, loc_ds as u64) {
            return Err(UnpackError::Malformed("mew: block range"));
        }
        let (produced, consumed) = aplib_depack_in_place(
            &mut buf,
            lesi as usize,
            loc_ss as usize,
            ledi as usize,
            loc_ds as usize,
        )?;

        let f1 = lesi + consumed as i64;
        let f2 = ledi + produced as i64;
        if !cont(size_sum, f1, 4) {
            return Err(UnpackError::Malformed("mew: next rva"));
        }
        loc_ss -= f1 + 4 - lesi;
        lesi = f1 + 4;

        let next_rva = rd32(&buf, f1 as usize);
        ledi = i64::from(next_rva) - i64::from(vma);
        loc_ds = size_sum as i64 - (i64::from(next_rva) - i64::from(vma));

        if d.use_lzma == 0 {
            let val = align(f2 as u32, 0x1000);
            if idx != 0 && val < sections[idx].raw as u32 {
                return Err(UnpackError::Malformed("mew: rva order"));
            }
            if sections.len() < idx + 2 {
                sections.push(Sect {
                    raw: val as usize,
                    rva: val.wrapping_add(vadd),
                    rsz: 0,
                    vsz: 0,
                });
            } else {
                sections[idx + 1].raw = val as usize;
                sections[idx + 1].rva = val.wrapping_add(vadd);
            }
            let prev_rsz = if idx != 0 {
                val as usize - sections[idx].raw
            } else {
                val as usize
            };
            sections[idx].rsz = prev_rsz as u32;
            sections[idx].vsz = prev_rsz as u32;
            if sections[idx].raw + prev_rsz > dsize as usize {
                return Err(UnpackError::Malformed("mew: section bounds"));
            }
        }
        idx += 1;
        if next_rva == 0 {
            break;
        }
        if idx > 4096 {
            return Err(UnpackError::Malformed("mew: block count"));
        }
    }

    if d.use_lzma != 0 {
        lzma_depack(&mut buf, lesi as usize, d.use_lzma, dsize, vma)?;
        let sections = vec![Sect {
            raw: 0,
            rva: vadd,
            rsz: dsize,
            vsz: dsize,
        }];
        return build_pe(
            &buf,
            &sections,
            base,
            entry_point.wrapping_sub(base),
            output_limit,
        );
    }

    sections.truncate(idx);
    build_pe(
        &buf,
        &sections,
        base,
        entry_point.wrapping_sub(base),
        output_limit,
    )
}

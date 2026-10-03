//! FSG 1.x/2.x static unpacker — port of upstream `XStaticUnpacker/xfsg.cpp`.
//!
//! FSG stores the aPLib-packed image in a section pair: an empty-raw-data
//! destination section followed by the packed-source section. The loader
//! stub at the entry point carries the support/dest/src immediates; the
//! per-section RVA list lives in a 16-bit word list (1.x) or a 32-bit
//! table (1.33); FSG 2.0 resolves them from a stub-pointer chain. FSG
//! 1.1/1.2 wraps the v100 stub in a fixed byte-decryptor.

use super::PackedPe;
use super::aplib::aplib_depack;
use super::upx::UnpackError;

/// Encrypted-stub geometry shared by `_detect` and `_resolveOep`.
const FSG_ENC_STUB_SIZE: usize = 0x80;
const FSG_ENC_BODY_SIZE: usize = 0xF4;

fn align(v: u32, a: u32) -> u32 {
    v.wrapping_add(a - 1) & !(a - 1)
}

fn rd32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

/// `fsgDecryptByte`: the constant per-byte transform (add 0x5C, xor 0xB6,
/// add 0x46, xor 0x02) hiding the v100 loader in FSG 1.1/1.2.
fn decrypt_stub(buf: &mut [u8]) {
    for x in buf.iter_mut() {
        let t = x.wrapping_add(0x5C) ^ 0xB6;
        *x = t.wrapping_add(0x46) ^ 0x02;
    }
}

/// Bounds test used by the FSG stub-pointer chain walk (`fsgInSrc`).
fn in_src(rva: u32, len: u64, src_va: u32, ssize: u64) -> bool {
    rva >= src_va && u64::from(rva - src_va) + len <= ssize
}

/// One rebuilt output section (`XFSG::SECTIONINFO`).
struct SectionInfo {
    rva: u32,
    rsz: u32,
    vsz: u32,
    /// Offset into the decompressed blob.
    raw: usize,
}

/// `XFSG::_rebuildPE`: minimal analysis-PE rebuild.
fn rebuild_pe(
    blob: &[u8],
    sections: &[SectionInfo],
    image_base: u32,
    oep: u32,
    output_limit: i64,
) -> Result<Vec<u8>, UnpackError> {
    if sections.is_empty() {
        return Err(UnpackError::Malformed("fsg: no sections"));
    }
    let nsects = sections.len() as u32;
    let header_base = 0x40 + 4 + 20 + 0xE0u32;

    let mut raw_base = align(header_base + 0x28 * nsects, 0x200);
    let ghost = sections[0].rva > align(raw_base, 0x1000);
    if ghost {
        raw_base = align(header_base + 0x28 * (nsects + 1), 0x200);
    }

    let mut raw_total = u64::from(raw_base);
    let mut max_virtual_end = 0u32;
    for s in sections {
        raw_total += u64::from(align(s.rsz, 0x200));
        max_virtual_end = max_virtual_end.max(s.rva.saturating_add(s.vsz.max(s.rsz)));
    }
    if raw_total > i64::MAX as u64 || (output_limit >= 0 && raw_total > output_limit as u64) {
        return Err(UnpackError::Malformed("fsg: output too large"));
    }
    let mut out = vec![0u8; raw_total as usize];

    // DOS header + PE signature + file header.
    out[0] = 0x4D;
    out[1] = 0x5A;
    out[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    let pe = 0x40;
    out[pe..pe + 4].copy_from_slice(&0x4550u32.to_le_bytes());
    let fh = pe + 4;
    out[fh..fh + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    let nsec_field = nsects + u32::from(ghost);
    out[fh + 2..fh + 4].copy_from_slice(&(nsec_field as u16).to_le_bytes());
    out[fh + 16..fh + 18].copy_from_slice(&0x00E0u16.to_le_bytes());
    out[fh + 18..fh + 20].copy_from_slice(&0x010Fu16.to_le_bytes());

    // IMAGE_OPTIONAL_HEADER32.
    let oh = fh + 20;
    out[oh..oh + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    out[oh + 16..oh + 20].copy_from_slice(&oep.to_le_bytes());
    out[oh + 28..oh + 32].copy_from_slice(&image_base.to_le_bytes());
    out[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    out[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes());
    out[oh + 40..oh + 42].copy_from_slice(&4u16.to_le_bytes());
    out[oh + 48..oh + 50].copy_from_slice(&4u16.to_le_bytes());
    out[oh + 56..oh + 60].copy_from_slice(&align(max_virtual_end, 0x1000).to_le_bytes());
    out[oh + 60..oh + 64].copy_from_slice(&raw_base.to_le_bytes());
    out[oh + 68..oh + 70].copy_from_slice(&2u16.to_le_bytes());
    out[oh + 92..oh + 96].copy_from_slice(&16u32.to_le_bytes());

    // Section table.
    let mut sec = oh + 0xE0;
    let mut raw = raw_base as usize;
    if ghost {
        out[sec..sec + 6].copy_from_slice(b".ghost");
        let ghost_va = align(raw_base, 0x1000);
        out[sec + 8..sec + 12]
            .copy_from_slice(&sections[0].rva.wrapping_sub(ghost_va).to_le_bytes());
        out[sec + 12..sec + 16].copy_from_slice(&ghost_va.to_le_bytes());
        out[sec + 36..sec + 40].copy_from_slice(&0xE00000E0u32.to_le_bytes());
        sec += 0x28;
    }
    for (i, s) in sections.iter().enumerate() {
        let name = format!(".clam{:02}", i + 1);
        out[sec..sec + name.len()].copy_from_slice(name.as_bytes());
        let rsz = align(s.rsz, 0x200);
        out[sec + 8..sec + 12]
            .copy_from_slice(&if s.vsz != 0 { s.vsz } else { s.rsz }.to_le_bytes());
        out[sec + 12..sec + 16].copy_from_slice(&s.rva.to_le_bytes());
        out[sec + 16..sec + 20].copy_from_slice(&rsz.to_le_bytes());
        out[sec + 20..sec + 24].copy_from_slice(&(raw as u32).to_le_bytes());
        out[sec + 36..sec + 40].copy_from_slice(&0xE00000E0u32.to_le_bytes());
        let end = s.raw.saturating_add(s.rsz as usize);
        if end <= blob.len() {
            out[raw..raw + s.rsz as usize].copy_from_slice(&blob[s.raw..end]);
        }
        raw += rsz as usize;
        sec += 0x28;
    }
    Ok(out)
}

/// Detected FSG variant and the state `_detect` extracts (`INTERNAL_INFO`).
pub struct FsgInfo {
    /// Numeric variant: 100 (1.0-1.3), 112 (1.1/1.2), 131 (1.31),
    /// 133, or 200 (2.0).
    pub version: u32,
    /// Upstream version string.
    pub sversion: &'static str,
    /// Support/relocation table RVA (1.x paths).
    pub support_rva: u32,
    /// Destination VA from the entry-point immediates.
    pub dest_va: u32,
    /// Packed-stream VA from the entry-point immediates.
    pub src_va: u32,
    /// `0F 84` OEP anchor offset, entry-point relative (-1 when none).
    pub je_offset: i64,
    /// 16-bit support list (pre-1.33) instead of 32-bit.
    pub word_list: bool,
    /// 1.1/1.2 polymorphic stub encryption.
    pub encrypted_stub: bool,
}

/// `XFSG::_findEmptyPair`: first raw=0/vsz!=0 section followed by a
/// nonempty one.
fn find_empty_pair(pe: &PackedPe) -> Option<usize> {
    let secs = pe.sections();
    (0..secs.len().saturating_sub(1)).find(|&i| {
        secs[i].raw_size == 0
            && secs[i].virtual_size != 0
            && secs[i + 1].raw_size != 0
            && secs[i + 1].virtual_size != 0
    })
}

/// `XFSG::_detect` — variant dispatch on the entry-point opener.
fn detect(pe: &PackedPe) -> Option<FsgInfo> {
    if pe.is64() {
        return None;
    }
    let ep_off = pe.rva_to_offset(pe.entry_rva())?;
    let ep = pe.data().get(ep_off..ep_off + 0x80)?;
    if ep.len() < 0x20 {
        return None;
    }
    let image_base = pe.image_base() as u32;
    let aoe = pe.entry_rva();
    let min_rva = pe
        .sections()
        .iter()
        .map(|s| s.virtual_address)
        .min()
        .unwrap_or(u32::MAX);
    let is_plausible_support = |n: u32| n < min_rva && aoe >= min_rva;

    if ep[0] == 0x87 && ep[1] == 0x25 {
        return Some(FsgInfo {
            version: 200,
            sversion: "2.0",
            support_rva: 0,
            dest_va: 0,
            src_va: 0,
            je_offset: -1,
            word_list: false,
            encrypted_stub: false,
        });
    }
    if ep[0] == 0xBE {
        let ptr = rd32(ep, 1).wrapping_sub(image_base);
        if is_plausible_support(ptr) {
            return Some(FsgInfo {
                version: 133,
                sversion: "1.33",
                support_rva: ptr,
                dest_va: 0,
                src_va: 0,
                je_offset: 161,
                word_list: false,
                encrypted_stub: false,
            });
        }
        return None;
    }
    if ep[0] == 0xBB && ep[5] == 0xBF && ep[10] == 0xBE && ep[15] == 0x53 {
        let ptr = rd32(ep, 1).wrapping_sub(image_base);
        if is_plausible_support(ptr) {
            let v100_tail = ep[16] == 0xE8
                && rd32(ep, 17) == 0x0000_000A
                && ep[21] == 0x02
                && ep[22] == 0xD2
                && ep[23] == 0x75
                && ep[24] == 0x05
                && ep[25] == 0x8A
                && ep[26] == 0x16
                && ep[27] == 0x46
                && ep[28] == 0x12
                && ep[29] == 0xD2
                && ep[30] == 0xC3;
            let v131_tail = ep[16] == 0xBB
                && ep[21] == 0xB2
                && ep[22] == 0x80
                && ep[23] == 0xA4
                && ep[24] == 0xB6
                && ep[25] == 0x80
                && ep[26] == 0xFF
                && ep[27] == 0xD3
                && ep[28] == 0x73
                && ep[29] == 0xF9;
            let (version, sversion, je_offset) = if v100_tail {
                (100, "1.0-1.3", 224i64)
            } else if v131_tail {
                (131, "1.31", 218i64)
            } else {
                return None;
            };
            return Some(FsgInfo {
                version,
                sversion,
                support_rva: ptr,
                dest_va: rd32(ep, 6),
                src_va: rd32(ep, 11),
                je_offset,
                word_list: true,
                encrypted_stub: false,
            });
        }
        return None;
    }
    // FSG 1.1/1.2: the v100 loader wrapped by the fixed byte-decryptor.
    if ep[0] == 0xE8 && ep.len() >= FSG_ENC_STUB_SIZE {
        let body_rva = aoe.wrapping_add(FSG_ENC_STUB_SIZE as u32);
        let body_off = pe.rva_to_offset(body_rva)?;
        let body_src = pe.data().get(body_off..body_off + FSG_ENC_BODY_SIZE)?;
        let mut body = body_src.to_vec();
        decrypt_stub(&mut body);
        let b = &body;
        if b[0] == 0xBB && b[5] == 0xBF && b[10] == 0xBE && b[15] == 0x53 {
            let ptr = rd32(b, 1).wrapping_sub(image_base);
            if is_plausible_support(ptr) {
                return Some(FsgInfo {
                    version: 112,
                    sversion: "1.1/1.2",
                    support_rva: ptr,
                    dest_va: rd32(b, 6),
                    src_va: rd32(b, 11),
                    je_offset: -1,
                    word_list: true,
                    encrypted_stub: true,
                });
            }
        }
    }
    None
}

/// `XFSG::_resolveOep`: locate the stub's single `0F 84` OEP jump.
fn resolve_oep(pe: &PackedPe, info: &FsgInfo) -> Option<u32> {
    let aoe = pe.entry_rva();
    if info.encrypted_stub {
        let body_off = pe.rva_to_offset(aoe.wrapping_add(FSG_ENC_STUB_SIZE as u32))?;
        let body_src = pe.data().get(body_off..body_off + FSG_ENC_BODY_SIZE)?;
        let mut body = body_src.to_vec();
        decrypt_stub(&mut body);
        let mut hit: Option<usize> = None;
        for i in 2..body.len().saturating_sub(5) {
            if body[i] == 0x0F && body[i + 1] == 0x84 && body[i - 2] == 0xFE {
                if hit.is_some() {
                    return None; // must be unique
                }
                hit = Some(i);
            }
        }
        let i = hit?;
        return Some(
            aoe.wrapping_add(FSG_ENC_STUB_SIZE as u32)
                .wrapping_add(i as u32)
                .wrapping_add(6)
                .wrapping_add(rd32(&body, i + 2)),
        );
    }
    if info.je_offset < 0 {
        return None;
    }
    let je = info.je_offset as usize;
    let ep_off = pe.rva_to_offset(aoe)?;
    let stub = pe.data().get(ep_off..ep_off + je + 6 + 0x40)?;
    if stub.len() < je + 6 {
        return None;
    }
    if stub[je] != 0x0F || stub[je + 1] != 0x84 {
        return None;
    }
    if je >= 2 && stub[je - 2] != 0xFE {
        return None;
    }
    Some(
        aoe.wrapping_add(je as u32)
            .wrapping_add(6)
            .wrapping_add(rd32(stub, je + 2)),
    )
}

/// `XFSG::_unpackV200` — FSG 2.0 stub-pointer chain.
fn unpack_v200(pe: &PackedPe, index: usize, output_limit: i64) -> Result<Vec<u8>, UnpackError> {
    let secs = pe.sections();
    if index + 1 >= secs.len() {
        return Err(UnpackError::Malformed("fsg2.0: section pair"));
    }
    let sec_dst = &secs[index];
    let sec_src = &secs[index + 1];
    let image_base = pe.image_base() as u32;
    let ssize = sec_src.raw_size;
    let dsize = sec_dst.virtual_size;
    if ssize <= 0x19
        || dsize <= ssize
        || (output_limit >= 0 && u64::from(dsize) > output_limit as u64)
    {
        return Err(UnpackError::Malformed("fsg2.0: size gates"));
    }
    let ep_off = pe
        .rva_to_offset(pe.entry_rva())
        .ok_or(UnpackError::Malformed("fsg2.0: ep"))?;
    let ep = pe
        .data()
        .get(ep_off..ep_off + 0x20)
        .ok_or(UnpackError::Malformed("fsg2.0: ep read"))?;
    let src = pe
        .data()
        .get(sec_src.raw_ptr as usize..sec_src.raw_ptr as usize + ssize as usize)
        .ok_or(UnpackError::Malformed("fsg2.0: src read"))?;

    let mut edx = rd32(ep, 2).wrapping_sub(image_base);
    if !in_src(edx, 4, sec_src.virtual_address, u64::from(ssize)) {
        return Err(UnpackError::Malformed("fsg2.0: chain 1"));
    }
    edx = rd32(src, (edx - sec_src.virtual_address) as usize).wrapping_sub(image_base);
    if !in_src(edx, 4, sec_src.virtual_address, u64::from(ssize))
        || !in_src(edx, 32, sec_src.virtual_address, u64::from(ssize))
    {
        return Err(UnpackError::Malformed("fsg2.0: chain 2"));
    }
    let base = (edx - sec_src.virtual_address) as usize;
    let edi = rd32(src, base).wrapping_sub(image_base);
    let esi = rd32(src, base + 4).wrapping_sub(image_base);
    let ebx = rd32(src, base + 16).wrapping_sub(image_base);
    if edi != sec_dst.virtual_address {
        return Err(UnpackError::Malformed("fsg2.0: dst va"));
    }
    if esi < sec_src.virtual_address || u64::from(esi - sec_src.virtual_address) >= u64::from(ssize)
    {
        return Err(UnpackError::Malformed("fsg2.0: src va"));
    }
    if !in_src(ebx, 16, sec_src.virtual_address, u64::from(ssize)) {
        return Err(UnpackError::Malformed("fsg2.0: oep ptr"));
    }
    let oep = rd32(src, (ebx + 12 - sec_src.virtual_address) as usize).wrapping_sub(image_base);

    let mut dst = vec![0u8; dsize as usize];
    let src_start = (esi - sec_src.virtual_address) as usize;
    let (produced, _) = aplib_depack(&src[src_start..], &mut dst)?;
    let sections = vec![SectionInfo {
        rva: edi,
        raw: 0,
        rsz: produced as u32,
        vsz: produced as u32,
    }];
    rebuild_pe(&dst, &sections, image_base, oep, output_limit)
}

/// `XFSG::_unpackV133` — FSG 1.33 32-bit support table.
fn unpack_v133(pe: &PackedPe, index: usize, output_limit: i64) -> Result<Vec<u8>, UnpackError> {
    let secs = pe.sections();
    if index + 1 >= secs.len() {
        return Err(UnpackError::Malformed("fsg1.33: section pair"));
    }
    let sec_dst = &secs[index];
    let sec_src = &secs[index + 1];
    let image_base = pe.image_base() as u32;
    let ssize = sec_src.raw_size;
    let dsize = sec_dst.virtual_size;
    if ssize <= 0x19
        || dsize <= ssize
        || (output_limit >= 0 && u64::from(dsize) > output_limit as u64)
    {
        return Err(UnpackError::Malformed("fsg1.33: size gates"));
    }
    let ep_off = pe
        .rva_to_offset(pe.entry_rva())
        .ok_or(UnpackError::Malformed("fsg1.33: ep"))?;
    let ep = pe
        .data()
        .get(ep_off..ep_off + 0xC0)
        .ok_or(UnpackError::Malformed("fsg1.33: ep read"))?;
    if ep.len() < 0xC0 {
        return Err(UnpackError::Malformed("fsg1.33: ep read"));
    }
    let support_rva = rd32(ep, 1).wrapping_sub(image_base);
    let support_off = pe
        .rva_to_offset(support_rva)
        .ok_or(UnpackError::Malformed("fsg1.33: support"))?;
    let gp = sec_src.raw_ptr as i64 - support_off as i64;
    if !(12..=0x10000).contains(&gp) {
        return Err(UnpackError::Malformed("fsg1.33: support span"));
    }
    let support = pe
        .data()
        .get(support_off..support_off + gp as usize)
        .ok_or(UnpackError::Malformed("fsg1.33: support read"))?;

    let edi = rd32(support, 4).wrapping_sub(image_base);
    let esi = rd32(support, 8).wrapping_sub(image_base);
    if esi < sec_src.virtual_address || u64::from(esi - sec_src.virtual_address) >= u64::from(ssize)
    {
        return Err(UnpackError::Malformed("fsg1.33: src va"));
    }
    if edi != sec_dst.virtual_address {
        return Err(UnpackError::Malformed("fsg1.33: dst va"));
    }
    let mut sect_cnt = 0usize;
    let mut t = 12usize;
    while t + 4 <= gp as usize {
        let rva = rd32(support, t);
        if rva == 0 {
            break;
        }
        let rva = rva.wrapping_sub(image_base + 1);
        sect_cnt += 1;
        if rva < sec_dst.virtual_address
            || u64::from(rva - sec_dst.virtual_address) >= u64::from(dsize)
        {
            break;
        }
        t += 4;
    }
    if t + 4 > gp as usize || rd32(support, t) != 0 {
        return Err(UnpackError::Malformed("fsg1.33: table tail"));
    }
    let mut list_rva = vec![edi];
    for k in 1..=sect_cnt {
        list_rva.push(
            rd32(support, 8 + k * 4)
                .wrapping_sub(1)
                .wrapping_sub(image_base),
        );
    }
    let src = pe
        .data()
        .get(sec_src.raw_ptr as usize..sec_src.raw_ptr as usize + ssize as usize)
        .ok_or(UnpackError::Malformed("fsg1.33: src read"))?;
    let oep = pe
        .entry_rva()
        .wrapping_add(161 + 6)
        .wrapping_add(rd32(ep, 163));

    let mut dst = vec![0u8; dsize as usize];
    let mut out_secs = Vec::with_capacity(list_rva.len());
    let mut src_pos = (esi - sec_src.virtual_address) as usize;
    let mut dst_pos = 0usize;
    for &rva in &list_rva {
        let (produced, consumed) = aplib_depack(&src[src_pos..], &mut dst[dst_pos..])?;
        out_secs.push(SectionInfo {
            rva,
            raw: dst_pos,
            rsz: produced as u32,
            vsz: 0,
        });
        src_pos += consumed;
        dst_pos += produced;
    }
    finish_sections(&mut out_secs, dsize);
    rebuild_pe(&dst, &out_secs, image_base, oep, output_limit)
}

/// `XFSG::_unpackV1x` — 1.0/1.3/1.31/1.1-1.2 16-bit word-list path.
fn unpack_v1x(
    pe: &PackedPe,
    index: usize,
    info: &FsgInfo,
    output_limit: i64,
) -> Result<Vec<u8>, UnpackError> {
    let secs = pe.sections();
    if index + 1 >= secs.len() {
        return Err(UnpackError::Malformed("fsg1.x: section pair"));
    }
    let sec_dst = &secs[index];
    let sec_src = &secs[index + 1];
    let image_base = pe.image_base() as u32;
    let ssize = sec_src.raw_size;
    let dsize = sec_dst.virtual_size;
    if ssize <= 0x19
        || dsize <= ssize
        || (output_limit >= 0 && u64::from(dsize) > output_limit as u64)
    {
        return Err(UnpackError::Malformed("fsg1.x: size gates"));
    }
    let dest_rva = info.dest_va.wrapping_sub(image_base);
    let src_rva = info.src_va.wrapping_sub(image_base);
    if dest_rva != sec_dst.virtual_address {
        return Err(UnpackError::Malformed("fsg1.x: dst va"));
    }
    if src_rva < sec_src.virtual_address
        || u64::from(src_rva - sec_src.virtual_address) >= u64::from(ssize)
    {
        return Err(UnpackError::Malformed("fsg1.x: src va"));
    }
    let support_off = pe
        .rva_to_offset(info.support_rva)
        .ok_or(UnpackError::Malformed("fsg1.x: support"))?;
    let gp = sec_src.raw_ptr as i64 - support_off as i64;
    if !(4..=0x10000).contains(&gp) {
        return Err(UnpackError::Malformed("fsg1.x: support span"));
    }
    let support = pe
        .data()
        .get(support_off..support_off + gp as usize)
        .ok_or(UnpackError::Malformed("fsg1.x: support read"))?;

    // 16-bit record grammar: 1 -> 6-byte import record, 2 -> terminator,
    // W -> section VA = (W - 2) << 12.
    let mut list_rva = vec![dest_rva];
    let mut t = 0usize;
    let mut terminated = false;
    while t + 2 <= gp as usize {
        let w = u32::from(support[t]) | (u32::from(support[t + 1]) << 8);
        if w == 2 {
            terminated = true;
            break;
        }
        if w == 1 {
            if t + 6 > gp as usize {
                return Err(UnpackError::Malformed("fsg1.x: import record"));
            }
            t += 6;
            continue;
        }
        let rva = ((w - 2) << 12).wrapping_sub(image_base);
        if rva < sec_dst.virtual_address
            || u64::from(rva - sec_dst.virtual_address) >= u64::from(dsize)
        {
            return Err(UnpackError::Malformed("fsg1.x: section rva"));
        }
        list_rva.push(rva);
        if list_rva.len() > 96 {
            return Err(UnpackError::Malformed("fsg1.x: too many sections"));
        }
        t += 2;
    }
    if !terminated {
        return Err(UnpackError::Malformed("fsg1.x: unterminated list"));
    }
    let src = pe
        .data()
        .get(sec_src.raw_ptr as usize..sec_src.raw_ptr as usize + ssize as usize)
        .ok_or(UnpackError::Malformed("fsg1.x: src read"))?;
    let oep = resolve_oep(pe, info).ok_or(UnpackError::Malformed("fsg1.x: oep"))?;

    let mut dst = vec![0u8; dsize as usize];
    let mut out_secs = Vec::with_capacity(list_rva.len());
    let mut src_pos = (src_rva - sec_src.virtual_address) as usize;
    let mut dst_pos = 0usize;
    for &rva in &list_rva {
        let (produced, consumed) = aplib_depack(&src[src_pos..], &mut dst[dst_pos..])?;
        out_secs.push(SectionInfo {
            rva,
            raw: dst_pos,
            rsz: produced as u32,
            vsz: 0,
        });
        src_pos += consumed;
        dst_pos += produced;
    }
    finish_sections(&mut out_secs, dsize);
    rebuild_pe(&dst, &out_secs, image_base, oep, output_limit)
}

/// Sort by RVA and derive virtual sizes from neighbours + `nDsize`.
fn finish_sections(out_secs: &mut [SectionInfo], dsize: u32) {
    out_secs.sort_by_key(|s| s.rva);
    let mut last = dsize;
    for i in 0..out_secs.len() {
        if i + 1 < out_secs.len() {
            out_secs[i].vsz = out_secs[i + 1].rva.wrapping_sub(out_secs[i].rva);
            last = last.saturating_sub(out_secs[i].vsz);
        } else {
            out_secs[i].vsz = last;
        }
    }
}

/// `XFSG::isValid`-equivalent detection. Returns the variant info.
pub fn detect_fsg(data: &[u8]) -> Option<FsgInfo> {
    let pe = PackedPe::parse(data).ok()?;
    find_empty_pair(&pe)?;
    detect(&pe)
}

/// `XFSG::_unpackToBuffer` — detect, dispatch on variant, rebuild PE.
pub fn unpack_fsg(data: &[u8], output_limit: i64) -> Result<Vec<u8>, UnpackError> {
    let pe = PackedPe::parse(data)?;
    let index = find_empty_pair(&pe).ok_or(UnpackError::Malformed("fsg: no section pair"))?;
    let info = detect(&pe).ok_or(UnpackError::Malformed("fsg: not detected"))?;
    match info.version {
        200 => unpack_v200(&pe, index, output_limit),
        133 => unpack_v133(&pe, index, output_limit),
        _ if info.word_list => unpack_v1x(&pe, index, &info, output_limit),
        _ => Err(UnpackError::Malformed("fsg: unsupported variant")),
    }
}

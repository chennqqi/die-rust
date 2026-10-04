//! Enigma Virtual Box container extraction — port of upstream
//! `XEnigmaVB`.
//!
//! The VFS tree lives inside the `.enigma1` PE section beginning with a
//! 0x53-byte `EVB\0` header (node count at +0x4C, package format dword
//! at +0x14). A pre-order walk of `id/type/children + UTF-16LE name`
//! nodes collects file records; blobs follow the tree in record order,
//! either stored verbatim or aPLib-compressed behind a
//! `[qword 12][dword stream_len][stream]` prefix. Extraction is atomic:
//! the blob stream must end in a `0x16` terminator followed by zero
//! padding up to the `.enigma1` raw size.

use super::PackedPe;
use super::UnpackError;
use super::autoit::ContainerRecord;
use std::collections::HashSet;

/// Upstream `EVB_MAX_CONTAINER_SIZE`.
const MAX_CONTAINER: u64 = 512 << 20;
/// Upstream `EVB_MAX_FILE_SIZE`.
const MAX_FILE: u64 = 256 << 20;
/// Upstream `EVB_MAX_TOTAL_OUTPUT`.
const MAX_TOTAL: u64 = 512 << 20;
/// Upstream `EVB_MAX_NODE_COUNT`.
const MAX_NODES: usize = 100000;
/// Upstream `EVB_MAX_TREE_DEPTH`.
const MAX_DEPTH: usize = 1024;
/// Upstream `EVB_MAX_NAME_CHARS`.
const MAX_NAME: usize = 255;
/// `EVB\0` package header size.
const HDR: usize = 0x53;

/// Detection metadata for an EnigmaVB package.
#[derive(Debug, Clone)]
pub struct EnigmaVbInfo {
    /// `"package vN"` when the format dword is in `(0, 0x1000)`.
    pub sversion: String,
    /// File offset of the `EVB\0` header.
    pub magic_offset: usize,
    /// `.enigma1` raw offset (container base).
    pub base_offset: usize,
    /// `.enigma1` … `.enigma2` span.
    pub base_size: usize,
    /// `.enigma1` raw size (tree + blob limit).
    pub tree_size: usize,
}

fn rd16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}

fn rd32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

fn rd64(d: &[u8], o: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..8 {
        v |= u64::from(d[o + i]) << (8 * i);
    }
    v
}

fn is_range_valid(off: u64, size: u64, total: u64) -> bool {
    off <= total && size <= total - off
}

fn sec_name(name: &[u8; 8]) -> &[u8] {
    let end = name.iter().position(|&b| b == 0).unwrap_or(8);
    &name[..end]
}

/// `XEnigmaVB::_detect`.
pub fn detect_enigmavb(data: &[u8]) -> Option<EnigmaVbInfo> {
    if data.is_empty() {
        return None;
    }
    let pe = PackedPe::parse(data).ok()?;
    let file_size = data.len() as u64;

    let mut e1: Option<(u64, u64)> = None;
    let mut e2: Option<(u64, u64)> = None;
    for s in pe.sections() {
        match sec_name(&s.name) {
            b".enigma1" => {
                if e1.is_some() {
                    return None;
                }
                e1 = Some((u64::from(s.raw_ptr), u64::from(s.raw_size)));
            }
            b".enigma2" => {
                if e2.is_some() {
                    return None;
                }
                let (raw, size) = (u64::from(s.raw_ptr), u64::from(s.raw_size));
                if size == 0 || !is_range_valid(raw, size, file_size) {
                    return None;
                }
                e2 = Some((raw, size));
            }
            _ => {}
        }
    }
    let (e1raw, e1size) = e1?;
    let (e2raw, e2size) = e2?;
    if e1size < HDR as u64 || !is_range_valid(e1raw, e1size, file_size) || e2raw < e1raw + e1size {
        return None;
    }
    let container = e2raw + e2size - e1raw;
    if container < e1size || container > MAX_CONTAINER {
        return None;
    }

    let e1r = e1raw as usize;
    let e1s = e1size as usize;
    let magic_rel = data[e1r..e1r + e1s]
        .windows(4)
        .position(|w| w == b"EVB\0")?;
    let magic = e1r + magic_rel;
    if magic + HDR > e1r + e1s {
        return None;
    }
    let header = &data[magic..magic + HDR];
    if &header[..4] != b"EVB\0" {
        return None;
    }
    let top_count = rd32(header, 0x4c);
    if top_count > MAX_NODES as u32 {
        return None;
    }
    let fmt = rd32(header, 0x14);
    let sversion = if fmt != 0 && fmt < 0x1000 {
        format!("package v{fmt}")
    } else {
        String::new()
    };
    Some(EnigmaVbInfo {
        sversion,
        magic_offset: magic,
        base_offset: e1r,
        base_size: container as usize,
        tree_size: e1s,
    })
}

/// `evbIsSafeBaseName` — Windows basename policy. Non-BMP / surrogate
/// units are mapped to a control char by the caller so they fail here.
fn is_safe_name(name: &str) -> bool {
    if name.is_empty()
        || name.chars().count() > MAX_NAME
        || name == "."
        || name == ".."
        || name.ends_with(' ')
        || name.ends_with('.')
    {
        return false;
    }
    for c in name.chars() {
        if "<>:\"/\\|?*".contains(c) || c.is_control() {
            return false;
        }
    }
    const RESERVED: &[&str] = &[
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
        "COM\u{b9}",
        "COM\u{b2}",
        "COM\u{b3}",
        "LPT\u{b9}",
        "LPT\u{b2}",
        "LPT\u{b3}",
        "CONIN$",
        "CONOUT$",
        "CLOCK$",
    ];
    let stem = name.split('.').next().unwrap_or("").to_uppercase();
    !RESERVED.contains(&stem.as_str())
}

/// `evbUniqueOutputName` — sanitize, then dedup case-insensitively.
fn unique_name(parsed: &str, index: usize, seen: &mut HashSet<String>) -> Option<String> {
    let mut result = if is_safe_name(parsed) {
        parsed.to_string()
    } else {
        format!("file_{index:04}")
    };
    let mut key = result.to_lowercase();
    if !seen.contains(&key) {
        seen.insert(key);
        return Some(result);
    }
    let fallback = format!("file_{index:04}");
    for i in 1..=MAX_NODES {
        result = if i == 1 {
            fallback.clone()
        } else {
            format!("{fallback}_{i}")
        };
        key = result.to_lowercase();
        if !seen.contains(&key) {
            seen.insert(key);
            return Some(result);
        }
    }
    None
}

/// `evbAplibDepack` — standard aPLib safe depacker (gamma-coded).
fn aplib_depack(src: &[u8], expected: usize) -> Option<Vec<u8>> {
    if src.is_empty() || expected == 0 || expected as u64 > MAX_FILE {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(expected);
    let mut pos = 0usize;
    let mut tag = 0u8;
    let mut bitcount = 0i32;

    macro_rules! get_bit {
        () => {{
            if bitcount == 0 {
                if pos >= src.len() {
                    return None;
                }
                tag = src[pos];
                pos += 1;
                bitcount = 8;
            }
            let b = (tag >> 7) & 1;
            tag <<= 1;
            bitcount -= 1;
            b as i32
        }};
    }

    macro_rules! get_gamma {
        () => {{
            let mut v: u64 = 1;
            loop {
                let bit = get_bit!();
                if v > (MAX_FILE - bit as u64) / 2 {
                    return None;
                }
                v = v * 2 + bit as u64;
                if get_bit!() == 0 {
                    break;
                }
            }
            v
        }};
    }

    macro_rules! append {
        ($b:expr) => {{
            if out.len() >= expected {
                return None;
            }
            out.push($b);
        }};
    }

    macro_rules! copy_match {
        ($off:expr, $len:expr) => {{
            let off = $off as u64;
            let len = $len as u64;
            if off == 0 || off > out.len() as u64 || len > (expected - out.len()) as u64 {
                return None;
            }
            for _ in 0..len {
                let b = out[out.len() - off as usize];
                out.push(b);
            }
        }};
    }

    append!(src[pos]);
    pos += 1;

    let mut r0: u64 = 0;
    let mut lwm = 0i32;
    let mut done = false;
    while !done {
        let b0 = get_bit!();
        if b0 != 0 {
            let b1 = get_bit!();
            if b1 != 0 {
                let b2 = get_bit!();
                if b2 != 0 {
                    let mut offset: u64 = 0;
                    for _ in 0..4 {
                        offset = offset * 2 + get_bit!() as u64;
                    }
                    if offset != 0 {
                        copy_match!(offset, 1);
                    } else {
                        append!(0);
                    }
                    lwm = 0;
                } else {
                    if pos >= src.len() {
                        return None;
                    }
                    let byte = src[pos];
                    pos += 1;
                    let length = 2 + u64::from(byte & 1);
                    let offset = u64::from(byte >> 1);
                    if offset == 0 {
                        done = true;
                    } else {
                        copy_match!(offset, length);
                    }
                    r0 = offset;
                    lwm = 1;
                }
            } else {
                let offset_code = get_gamma!();
                if lwm == 0 && offset_code == 2 {
                    let length = get_gamma!();
                    copy_match!(r0, length);
                } else {
                    let delta = if lwm == 0 { 3u64 } else { 2 };
                    if offset_code < delta || pos >= src.len() {
                        return None;
                    }
                    let offset_high = offset_code - delta;
                    if offset_high > MAX_FILE / 256 {
                        return None;
                    }
                    let offset = offset_high * 256 + u64::from(src[pos]);
                    pos += 1;
                    let mut length = get_gamma!();
                    if offset >= 32000 {
                        length += 1;
                    }
                    if offset >= 1280 {
                        length += 1;
                    }
                    if offset < 128 {
                        length += 2;
                    }
                    copy_match!(offset, length);
                    r0 = offset;
                }
                lwm = 1;
            }
        } else {
            if pos >= src.len() {
                return None;
            }
            append!(src[pos]);
            pos += 1;
            lwm = 0;
        }
    }

    if !done || pos != src.len() || out.len() != expected {
        return None;
    }
    Some(out)
}

struct TmpRec {
    name: String,
    orig: u64,
    stored: u64,
}

/// `XEnigmaVB::initUnpack` record walk — atomic extraction of every
/// declared file. Any structural deviation fails the whole archive.
pub fn extract_enigmavb(data: &[u8]) -> Result<Vec<ContainerRecord>, UnpackError> {
    let info = detect_enigmavb(data).ok_or(UnpackError::NotPacked)?;
    if info.base_size > i32::MAX as usize
        || !is_range_valid(
            info.base_offset as u64,
            info.base_size as u64,
            data.len() as u64,
        )
    {
        return Err(UnpackError::Malformed("enigmavb: container range"));
    }
    let p = &data[info.base_offset..info.base_offset + info.base_size];
    let tree_limit = info.tree_size;
    let magic_idx = info.magic_offset - info.base_offset;
    if magic_idx + HDR > tree_limit || &p[magic_idx..magic_idx + 4] != b"EVB\0" {
        return Err(UnpackError::Malformed("enigmavb: header"));
    }
    let top_count = rd32(p, magic_idx + 0x4c) as usize;
    if top_count > MAX_NODES {
        return Err(UnpackError::Malformed("enigmavb: node count"));
    }

    let mut tmp: Vec<TmpRec> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    if top_count != 0 {
        stack.push(top_count);
    }
    let mut cursor = magic_idx + HDR;
    let mut scheduled = top_count;
    let mut parsed = 0usize;
    let mut node_ids: HashSet<u32> = HashSet::new();

    while let Some(last) = stack.last_mut() {
        if *last == 0 {
            stack.pop();
            continue;
        }
        *last -= 1;
        if parsed >= scheduled
            || parsed >= MAX_NODES
            || cursor > tree_limit
            || tree_limit - cursor < 12
        {
            return Err(UnpackError::Malformed("enigmavb: node bounds"));
        }
        parsed += 1;

        let node_id = rd32(p, cursor);
        let ntype = rd32(p, cursor + 4);
        let children = rd32(p, cursor + 8) as usize;
        if !node_ids.insert(node_id) {
            return Err(UnpackError::Malformed("enigmavb: dup node"));
        }
        cursor += 12;

        let mut name = String::new();
        let mut terminated = false;
        while cursor <= tree_limit && tree_limit - cursor >= 2 {
            let ch = rd16(p, cursor);
            cursor += 2;
            if ch == 0 {
                terminated = true;
                break;
            }
            if name.chars().count() >= MAX_NAME {
                return Err(UnpackError::Malformed("enigmavb: name"));
            }
            name.push(char::from_u32(u32::from(ch)).unwrap_or('\x01'));
        }
        if !terminated {
            return Err(UnpackError::Malformed("enigmavb: name eos"));
        }

        if ntype == 1 {
            if cursor > tree_limit || tree_limit - cursor < 30 {
                return Err(UnpackError::Malformed("enigmavb: dir"));
            }
            cursor += 30;
            if children > MAX_NODES - scheduled {
                return Err(UnpackError::Malformed("enigmavb: children"));
            }
            scheduled += children;
            if children != 0 {
                if stack.len() >= MAX_DEPTH {
                    return Err(UnpackError::Malformed("enigmavb: depth"));
                }
                stack.push(children);
            }
        } else if ntype == 2 {
            if children != 0
                || cursor > tree_limit
                || tree_limit - cursor < 58
                || tmp.len() >= MAX_NODES
            {
                return Err(UnpackError::Malformed("enigmavb: file"));
            }
            cursor += 3;
            let orig = rd64(p, cursor);
            cursor += 8;
            cursor += 39;
            let stored = rd64(p, cursor);
            cursor += 8;
            tmp.push(TmpRec { name, orig, stored });
        } else {
            return Err(UnpackError::Malformed("enigmavb: node type"));
        }
    }
    if parsed != scheduled {
        return Err(UnpackError::Malformed("enigmavb: scheduled"));
    }

    let mut running = cursor;
    let mut total: u64 = 0;
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<ContainerRecord> = Vec::with_capacity(tmp.len());
    for (i, rec) in tmp.iter().enumerate() {
        if rec.orig > MAX_FILE
            || running > tree_limit
            || rec.stored > (tree_limit - running) as u64
            || rec.orig > MAX_TOTAL - total
        {
            return Err(UnpackError::Malformed("enigmavb: record bounds"));
        }
        let name = unique_name(&rec.name, i, &mut seen)
            .ok_or(UnpackError::Malformed("enigmavb: name dedup"))?;
        let blob = &p[running..];
        let data_out = if rec.stored == rec.orig {
            if rec.orig > MAX_FILE {
                return Err(UnpackError::Malformed("enigmavb: stored"));
            }
            blob[..rec.orig as usize].to_vec()
        } else {
            if rec.stored < 12 {
                return Err(UnpackError::Malformed("enigmavb: blob"));
            }
            let header_size = rd64(blob, 0);
            let aplib_size = rd32(blob, 8) as u64;
            if header_size != 12 || rec.stored != header_size + aplib_size {
                return Err(UnpackError::Malformed("enigmavb: blob hdr"));
            }
            aplib_depack(
                &blob[header_size as usize..header_size as usize + aplib_size as usize],
                rec.orig as usize,
            )
            .ok_or(UnpackError::Malformed("enigmavb: depack"))?
        };
        if data_out.len() as u64 != rec.orig || data_out.len() as u64 > MAX_TOTAL - total {
            return Err(UnpackError::Malformed("enigmavb: output"));
        }
        total += data_out.len() as u64;
        out.push(ContainerRecord {
            name,
            data: data_out,
        });
        running += rec.stored as usize;
    }

    if !tmp.is_empty() {
        if running >= tree_limit || p[running] != 0x16 {
            return Err(UnpackError::Malformed("enigmavb: terminator"));
        }
        running += 1;
    }
    while running < tree_limit {
        let end = tree_limit.min(running + (1 << 20));
        for &b in &p[running..end] {
            if b != 0 {
                return Err(UnpackError::Malformed("enigmavb: padding"));
            }
        }
        running = end;
    }

    if out.len() != tmp.len() {
        return Err(UnpackError::Malformed("enigmavb: count"));
    }
    Ok(out)
}

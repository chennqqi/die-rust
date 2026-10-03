//! BoxedApp packer container extraction — port of upstream `XBoxedApp`.
//!
//! Detection needs exactly one `.bxpck` and one `.main` PE section
//! (non-overlapping, in-range), plus the `BoxedApp::` engine-string
//! marker inside `.main`. The VFS node walk (`_scanRecords`) accepts
//! nodes at any offset where `baReadNodeMetadata` authenticates:
//! `u32 node_size`, `u16 5`, `u32 0xFFFFFFFF`, five ascending in-node
//! offsets and a UTF-16LE name in `[off3, off4)`. A declared node that
//! fails to decode aborts the whole extraction.
//!
//! Payloads are either STORE (`orig_size == node_end - data_slot`) or
//! the tagged record `[pad 34][u16 0x0010][u32 method][u32 0][u32
//! stored][content]` with method 0 = raw / method 1 = zlib.

use super::PackedPe;
use super::UnpackError;
use super::autoit::ContainerRecord;
use std::collections::HashSet;

/// Upstream `BA_MAX_CONTAINER_SIZE`.
const MAX_CONTAINER: u64 = 512 << 20;
/// Upstream `BA_MAX_FILE_SIZE`.
const MAX_FILE: u64 = 256 << 20;
/// Upstream `BA_MAX_TOTAL_OUTPUT`.
const MAX_TOTAL: u64 = 512 << 20;
/// Upstream `BA_MAX_FILE_COUNT`.
const MAX_COUNT: usize = 65536;
/// Minimum node span (upstream `0x56`).
const NODE_MIN: u64 = 0x56;

/// Detection metadata for a BoxedApp package.
#[derive(Debug, Clone)]
pub struct BoxedAppInfo {
    /// `"demo"` for trial builds, else empty.
    pub sversion: String,
    /// `.bxpck` raw offset.
    pub bxpck_offset: usize,
    /// `.bxpck` raw size.
    pub bxpck_size: usize,
    /// `.main` raw offset.
    pub main_offset: usize,
    /// `.main` raw size.
    pub main_size: usize,
}

fn rd16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}

fn rd32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

fn sec_name(name: &[u8; 8]) -> &[u8] {
    let end = name.iter().position(|&b| b == 0).unwrap_or(8);
    &name[..end]
}

/// `XBoxedApp::_detect`.
pub fn detect_boxedapp(data: &[u8]) -> Option<BoxedAppInfo> {
    let pe = PackedPe::parse(data).ok()?;
    let size = data.len() as u64;

    let mut bxpck: Option<(u64, u64)> = None;
    let mut main: Option<(u64, u64)> = None;
    let mut n_bxpck = 0u32;
    let mut n_main = 0u32;
    for s in pe.sections() {
        match sec_name(&s.name) {
            b".bxpck" => {
                n_bxpck += 1;
                bxpck = Some((u64::from(s.raw_ptr), u64::from(s.raw_size)));
            }
            b".main" => {
                n_main += 1;
                main = Some((u64::from(s.raw_ptr), u64::from(s.raw_size)));
            }
            _ => {}
        }
    }
    let (bx_off, bx_size) = bxpck.unwrap_or((u64::MAX, 0));
    let (mn_off, mn_size) = main.unwrap_or((u64::MAX, 0));
    if n_bxpck != 1
        || n_main != 1
        || bx_size == 0
        || bx_off > size
        || bx_size > size - bx_off.min(size)
        || mn_size == 0
        || mn_off > size
        || mn_size > size - mn_off.min(size)
        || bx_size > MAX_CONTAINER
        || mn_size > MAX_CONTAINER
        || bx_size > MAX_CONTAINER - mn_size
    {
        return None;
    }
    if bx_off < mn_off + mn_size && mn_off < bx_off + bx_size {
        return None;
    }
    // "BoxedApp::" ANSI marker inside .main.
    let m = mn_off as usize;
    let m_end = m + mn_size as usize;
    data[m..m_end]
        .windows(10)
        .position(|w| w == b"BoxedApp::")?;

    // Trial builds embed a UTF-16LE demo nag screen in .bxpck.
    let demo: Vec<u8> = b"demo version of BoxedApp"
        .iter()
        .flat_map(|&b| [b, 0])
        .collect();
    let b = bx_off as usize;
    let sversion = if data[b..b + bx_size as usize]
        .windows(demo.len())
        .any(|w| w == demo.as_slice())
    {
        "demo".to_string()
    } else {
        String::new()
    };
    Some(BoxedAppInfo {
        sversion,
        bxpck_offset: b,
        bxpck_size: bx_size as usize,
        main_offset: m,
        main_size: mn_size as usize,
    })
}

/// `baIsSafeBaseName` — mirrors upstream, including the superscript
/// digit folding (`¹²³` -> `123`) the EVB variant does not have.
fn is_safe_name(name: &str) -> bool {
    if name.is_empty()
        || name.chars().count() > 255
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
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .to_uppercase()
        .replace('\u{b9}', "1")
        .replace('\u{b2}', "2")
        .replace('\u{b3}', "3");
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$",
        "CONOUT$", "CLOCK$",
    ];
    !RESERVED.contains(&stem.as_str())
}

/// `baReadName` — UTF-16LE name in `[start, limit)`; basename must be
/// safe. Returns `None` for any deviation (upstream returns "" which
/// callers treat as failure).
fn read_name(p: &[u8], start: usize, limit: usize) -> Option<String> {
    let mut result = String::new();
    let mut terminated = false;
    let mut i = start;
    while i + 2 <= limit {
        let ch = rd16(p, i);
        if ch == 0 {
            terminated = true;
            break;
        }
        if ch < 0x20 || ch == 0x7f {
            return None;
        }
        result.push(char::from_u32(u32::from(ch)).unwrap_or('\x01'));
        if result.chars().count() > 260 {
            return None;
        }
        i += 2;
    }
    if !terminated {
        return None;
    }
    let slash = result.rfind(['/', '\\']);
    let base = match slash {
        Some(pos) => &result[pos + 1..],
        None => result.as_str(),
    };
    is_safe_name(base).then(|| base.to_string())
}

struct NodeMeta {
    end: usize,
    data_slot: usize,
    orig_size: u32,
    name: String,
}

/// `baReadNodeMetadata`.
fn read_node(region: &[u8], pos: usize) -> Option<NodeMeta> {
    if region.len() - pos < NODE_MIN as usize {
        return None;
    }
    let node_size = rd32(region, pos) as usize;
    if rd16(region, pos + 4) != 5
        || rd32(region, pos + 6) != 0xffff_ffff
        || node_size < NODE_MIN as usize
        || node_size > region.len() - pos
    {
        return None;
    }
    let orig_size = rd32(region, pos + 0x2a);
    let mut ok = u64::from(orig_size) <= MAX_FILE;
    let mut offsets = [0u32; 5];
    for i in 0..5 {
        let off = rd32(region, pos + 0x3e + i * 4);
        if (off < 0x50)
            || (i < 4 && off >= node_size as u32)
            || (i == 4 && off > node_size as u32)
            || (i > 0 && off < offsets[i - 1])
        {
            ok = false;
        }
        offsets[i] = off;
    }
    if !ok {
        return None;
    }
    let name = read_name(region, pos + offsets[3] as usize, pos + offsets[4] as usize)?;
    Some(NodeMeta {
        end: pos + node_size,
        data_slot: pos + offsets[4] as usize,
        orig_size,
        name,
    })
}

/// `baNameKey` — case-folded comparison key.
fn name_key(name: &str) -> String {
    name.to_lowercase()
}

/// `baCollectDeclaredNames` — count nodes and record declared names.
fn collect_declared(region: &[u8], names: &mut HashSet<String>, count: &mut usize) -> bool {
    if region.len() as u64 > MAX_CONTAINER {
        return false;
    }
    let mut pos = 0usize;
    while pos + NODE_MIN as usize <= region.len() {
        match read_node(region, pos) {
            None => pos += 1,
            Some(node) => {
                *count += 1;
                if *count > MAX_COUNT {
                    return false;
                }
                names.insert(name_key(&node.name));
                pos = node.end;
            }
        }
    }
    true
}

/// `baInflate` — zlib inflate requiring exact input consumption and
/// exact declared output size.
fn ba_inflate(src: &[u8], expected: u64) -> Option<Vec<u8>> {
    if src.is_empty() || src.len() > 0x7fff_ffff || expected > MAX_FILE {
        return None;
    }
    let mut de = flate2::Decompress::new(true);
    let mut out: Vec<u8> = Vec::with_capacity((expected as usize).min(1 << 20));
    let mut chunk = vec![0u8; 65536];
    loop {
        let before_in = de.total_in() as usize;
        let before_out = de.total_out() as usize;
        let status = de
            .decompress(&src[before_in..], &mut chunk, flate2::FlushDecompress::None)
            .ok()?;
        let produced = de.total_out() as usize - before_out;
        if produced as u64 > expected - out.len() as u64 {
            return None;
        }
        out.extend_from_slice(&chunk[..produced]);
        match status {
            flate2::Status::StreamEnd => {
                return (de.total_in() == src.len() as u64 && out.len() as u64 == expected)
                    .then_some(out);
            }
            // Z_BUF_ERROR (no progress possible) or a stall with the
            // input exhausted — upstream breaks and fails.
            _ => {
                if de.total_in() as usize == before_in && produced == 0 {
                    return None;
                }
                if de.total_in() as usize >= src.len() {
                    return None;
                }
            }
        }
    }
}

/// `baUniqueOutputName`.
fn unique_name(
    preferred: &str,
    index: usize,
    declared: &HashSet<String>,
    assigned: &mut HashSet<String>,
) -> Option<String> {
    if preferred.is_empty() {
        return None;
    }
    let key = name_key(preferred);
    if !assigned.contains(&key) {
        assigned.insert(key);
        return Some(preferred.to_string());
    }
    let base = format!("file_{index:04}");
    for i in 0..=MAX_COUNT {
        let candidate = if i == 0 {
            base.clone()
        } else {
            format!("{base}_{i}")
        };
        let key = name_key(&candidate);
        if !declared.contains(&key) && !assigned.contains(&key) {
            assigned.insert(key);
            return Some(candidate);
        }
    }
    None
}

/// `XBoxedApp::_scanRecords` — one region pass. `Ok(count)` on full
/// success; any authenticated-but-undecodable node is a hard error.
fn scan_records(
    region: &[u8],
    declared: &HashSet<String>,
    out: &mut Vec<ContainerRecord>,
    assigned: &mut HashSet<String>,
    total: &mut u64,
) -> Result<(), UnpackError> {
    if region.len() as u64 > MAX_CONTAINER {
        return Err(UnpackError::Malformed("boxedapp: region"));
    }
    let mut pos = 0usize;
    while pos + NODE_MIN as usize <= region.len() {
        let node = match read_node(region, pos) {
            None => {
                pos += 1;
                continue;
            }
            Some(n) => n,
        };
        if out.len() >= MAX_COUNT || u64::from(node.orig_size) > MAX_TOTAL - *total {
            return Err(UnpackError::Malformed("boxedapp: bounds"));
        }
        let name = unique_name(&node.name, out.len(), declared, assigned)
            .ok_or(UnpackError::Malformed("boxedapp: name"))?;

        let node_end = node.end;
        let slot = node.data_slot;
        let mut produced: Option<Vec<u8>> = None;

        let marker = slot + 34;
        let mut compressed = false;
        if marker + 14 <= node_end && rd16(region, marker) == 0x0010 {
            let method = rd32(region, marker + 2);
            let reserved = rd32(region, marker + 6);
            let stored = rd32(region, marker + 10);
            let content = marker + 14;
            if reserved == 0 && method <= 1 && u64::from(stored) == (node_end - content) as u64 {
                compressed = true;
                if method == 0 {
                    if u64::from(stored) == u64::from(node.orig_size) {
                        produced = Some(region[content..content + stored as usize].to_vec());
                    }
                } else if stored > 0 && region[content] == 0x78 {
                    produced = ba_inflate(
                        &region[content..content + stored as usize],
                        u64::from(node.orig_size),
                    );
                }
            }
        }
        if !compressed && u64::from(node.orig_size) == (node_end - slot) as u64 {
            produced = Some(region[slot..node_end].to_vec());
        }

        match produced {
            Some(data) if data.len() as u32 == node.orig_size => {
                *total += data.len() as u64;
                out.push(ContainerRecord { name, data });
                pos = node_end;
            }
            // Authenticated header + bad payload: corruption, not a miss.
            _ => return Err(UnpackError::Malformed("boxedapp: payload")),
        }
    }
    Ok(())
}

/// `XBoxedApp::initUnpack` — declared-name pass over both regions, then
/// the decode pass; the declared count must equal the decoded count.
pub fn extract_boxedapp(data: &[u8]) -> Result<Vec<ContainerRecord>, UnpackError> {
    let info = detect_boxedapp(data).ok_or(UnpackError::NotPacked)?;

    let mut declared_names: HashSet<String> = HashSet::new();
    let mut declared = 0usize;
    let bx = &data[info.bxpck_offset..info.bxpck_offset + info.bxpck_size];
    if !collect_declared(bx, &mut declared_names, &mut declared) {
        return Err(UnpackError::Malformed("boxedapp: bxpck names"));
    }
    let mn = &data[info.main_offset..info.main_offset + info.main_size];
    if !collect_declared(mn, &mut declared_names, &mut declared) {
        return Err(UnpackError::Malformed("boxedapp: main names"));
    }

    let mut out = Vec::new();
    let mut assigned = HashSet::new();
    let mut total = 0u64;
    scan_records(bx, &declared_names, &mut out, &mut assigned, &mut total)?;
    scan_records(mn, &declared_names, &mut out, &mut assigned, &mut total)?;

    if declared == 0 || out.len() != declared {
        return Err(UnpackError::Malformed("boxedapp: count mismatch"));
    }
    Ok(out)
}

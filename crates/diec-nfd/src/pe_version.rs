//! `VS_VERSIONINFO` version-resource parser — bounded port of
//! `XPE::__getResourcesVersion`/`getResourcesVersionValue`/
//! `getFileVersionMS` semantics for the NFD PE handlers.
//!
//! The resource tree leaf (type `S_RT_VERSION`=16) yields a
//! `VS_VERSION_INFO` node: `{wLength, wValueLength, wType}` (u16×3)
//! followed by a UTF-16LE title and an aligned value. Children are
//! walked recursively to level 3 (`StringFileInfo.<lang>.<Key>`),
//! where each node contributes a `key → value` record.

use crate::parse::{rd_u16, rd_u32};

/// Parsed version-resource facts (`XPE::RESOURCES_VERSION` subset).
#[derive(Debug, Default)]
pub struct ResourcesVersion {
    /// Level-3 records as `(key, value)` — `FileVersion`,
    /// `FileDescription`, `ProductName`, etc. First match wins on
    /// lookup, mirroring upstream `listRecords` scan order.
    pub records: Vec<(String, String)>,
    /// `VS_FIXEDFILEINFO.dwFileVersionMS` when the root node carried a
    /// full 52-byte fixed block.
    pub file_version_ms: u32,
    /// `VS_FIXEDFILEINFO.dwProductVersionMS`.
    pub product_version_ms: u32,
}

/// Read a NUL-terminated UTF-16LE string at `off` (bounded to 256
/// chars), matching `read_unicodeString`.
fn read_utf16(d: &[u8], off: usize) -> Option<String> {
    let mut s = String::new();
    for i in 0..256usize {
        let w = rd_u16(d, off + i * 2)?;
        if w == 0 {
            return Some(s);
        }
        s.push(char::from_u32(u32::from(w))?);
    }
    Some(s)
}

/// Read a length-limited UTF-16LE string (`read_unicodeString` with
/// `nMaxSize` characters).
fn read_utf16_len(d: &[u8], off: usize, chars: usize) -> Option<String> {
    let mut s = String::new();
    for i in 0..chars.min(1024) {
        let w = rd_u16(d, off + i * 2)?;
        if w == 0 {
            break; // upstream read_unicodeString stops at NUL
        }
        s.push(char::from_u32(u32::from(w))?);
    }
    Some(s)
}

const ALIGN4: fn(usize) -> usize = |v| v.div_ceil(4) * 4;

/// Recursive `__getResourcesVersion`: parse one `VS_VERSION_INFO` node
/// at `off` (bounded by `size`), append level-3 records, recurse into
/// children. Returns consumed `wLength` (0 = stop sibling walk).
fn get_resources_version_rec(
    d: &[u8],
    off: usize,
    size: usize,
    prefix: &str,
    level: u32,
    out: &mut ResourcesVersion,
    depth: &mut u32,
) -> usize {
    if *depth > 64 || size < 6 {
        return 0;
    }
    *depth += 1;
    let (Some(w_len), Some(w_vlen)) = (rd_u16(d, off), rd_u16(d, off + 2)) else {
        return 0;
    };
    let w_len = w_len as usize;
    let w_vlen = w_vlen as usize;
    if w_len == 0 || w_len > size || w_vlen >= w_len {
        return 0;
    }
    let title = read_utf16(d, off + 6).unwrap_or_default();
    let mut delta = 6 + (title.chars().count() + 1) * 2;
    delta = ALIGN4(delta);
    let path = if prefix.is_empty() {
        title.clone()
    } else {
        format!("{prefix}.{title}")
    };

    if path == "VS_VERSION_INFO" && w_vlen >= 52 {
        // VS_FIXEDFILEINFO begins at off+delta.
        out.file_version_ms = rd_u32(d, off + delta + 8).unwrap_or(0);
        out.product_version_ms = rd_u32(d, off + delta + 16).unwrap_or(0);
    }
    if level == 3 {
        let n_chars = w_vlen.min(w_len.saturating_sub(delta) / 2);
        let value = read_utf16_len(d, off + delta, n_chars).unwrap_or_default();
        out.records.push((title.clone(), value));
    }
    // VarFileInfo.Translation leaf records are not consumed by any NFD
    // handler — omitted (upstream appends a hex record; no reader).

    let mut n_delta = delta + w_vlen;
    if level < 3 {
        let mut rest = w_len.saturating_sub(n_delta);
        while rest > 0 {
            let child = get_resources_version_rec(
                d,
                off + n_delta,
                w_len - n_delta,
                &path,
                level + 1,
                out,
                depth,
            );
            if child == 0 {
                break;
            }
            let step = ALIGN4(child);
            n_delta += step;
            rest = rest.saturating_sub(step);
        }
    }
    w_len
}

impl ResourcesVersion {
    /// `getResourcesVersionValue(key)` — first level-3 record whose key
    /// matches; empty string when absent (upstream returns "" not an
    /// error).
    pub fn value(&self, key: &str) -> &str {
        self.records
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }

    /// `getFileVersionMS` — `hi.lo` of `dwFileVersionMS`.
    pub fn file_version_ms_str(&self) -> String {
        format!(
            "{}.{}",
            self.file_version_ms >> 16,
            self.file_version_ms & 0xFFFF
        )
    }
}

/// Parse the first `RT_VERSION` (type 16) resource of the image.
/// Empty result when no version resource or malformed layout.
pub fn resources_version(d: &[u8]) -> ResourcesVersion {
    let mut out = ResourcesVersion::default();
    let res = crate::pe::collect_resources(d);
    let Some(vr) = res
        .iter()
        .find(|r| r.id1 == 16 && r.data_off != 0 && r.data_size >= 6)
    else {
        return out;
    };
    let mut depth = 0;
    get_resources_version_rec(d, vr.data_off, vr.data_size, "", 0, &mut out, &mut depth);
    out
}

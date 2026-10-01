//! Android binary XML (AXML) decoder.
//!
//! Ports `XAndroidBinary::recordToString` semantics (XDex @ master,
//! headers from `xandroidbinary_def.h`) to produce the text XML used by
//! upstream `APK_Script::getAndroidManifest`. The output is fed to the
//! `key="value"` record regex in the script bridge, so attributes are
//! emitted as `prefix:name="value"` using the namespace-prefix mapping
//! declared by RES_XML_START_NAMESPACE chunks.
//!
//! All input is untrusted: every offset is bounds-checked, string counts
//! are clamped to what fits in the chunk, recursion is depth-capped, and
//! output length is bounded.

/// ResChunk_header / ResXMLTree_node types (xandroidbinary_def.h).
const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;

const STRING_POOL_UTF8_FLAG: u32 = 1 << 8;

/// Size of ResChunk_header (type, headerSize, size).
const HEADER_SIZE: usize = 8;
/// Fields of ResXMLTree_attrExt before the attribute array
/// (ns, name, attributeStart, attributeSize, attributeCount, idIndex,
/// classIndex, styleIndex after header+lineNumber+comment).
const XML_START_FIXED_SIZE: usize = 36;
/// ResXMLTree_attribute size.
const XML_ATTR_SIZE: usize = 20;

/// Maximum nesting depth for chunk records (upstream caps at 128).
const MAX_DEPTH: usize = 128;
/// Maximum decoded output bytes.
const MAX_OUTPUT: usize = 4 * 1024 * 1024;
/// Maximum string-pool strings materialized.
const MAX_STRINGS: usize = 1 << 20;
/// Maximum XML chunks walked.
const MAX_CHUNKS: usize = 1 << 20;

#[inline]
fn u16le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
fn u32le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

struct Header {
    kind: u16,
    header_size: usize,
    data_size: usize,
}

fn read_header(data: &[u8], off: usize) -> Option<Header> {
    Some(Header {
        kind: u16le(data, off)?,
        header_size: u16le(data, off + 2)? as usize,
        data_size: u32le(data, off + 4)? as usize,
    })
}

/// Read one string-pool string (UTF-8 or UTF-16 with 1-2 byte length
/// prefixes), mirroring `XAndroidBinary::_readStringPoolString`.
fn read_pool_string(data: &[u8], off: usize, utf8: bool) -> String {
    if utf8 {
        // UTF-16 char count (ignored), then UTF-8 byte count.
        let Some(&len16) = data.get(off) else {
            return String::new();
        };
        let mut pos = off + 1;
        if len16 & 0x80 != 0 {
            pos += 1;
        }
        let Some(&len8a) = data.get(pos) else {
            return String::new();
        };
        pos += 1;
        let byte_len = if len8a & 0x80 != 0 {
            let Some(&len8b) = data.get(pos) else {
                return String::new();
            };
            pos += 1;
            (((len8a & 0x7F) as usize) << 8) | len8b as usize
        } else {
            len8a as usize
        };
        let end = pos.saturating_add(byte_len).min(data.len());
        String::from_utf8_lossy(&data[pos..end]).into_owned()
    } else {
        let Some(unit0) = u16le(data, off) else {
            return String::new();
        };
        let mut pos = off + 2;
        let unit_len = if unit0 & 0x8000 != 0 {
            let Some(unit1) = u16le(data, pos) else {
                return String::new();
            };
            pos += 2;
            (((unit0 & 0x7FFF) as usize) << 16) | unit1 as usize
        } else {
            unit0 as usize
        };
        let byte_len = unit_len.saturating_mul(2);
        let end = pos.saturating_add(byte_len).min(data.len());
        let units: Vec<u16> = data[pos..end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

/// `getStringByIndex`: out-of-range index yields an empty string.
fn str_by_index(strings: &[String], idx: u32) -> &str {
    strings.get(idx as usize).map(String::as_str).unwrap_or("")
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Collect direct children of a container chunk (RES_XML_TYPE at the top
/// level). Mirrors `XAndroidBinary::getRecord` child enumeration.
fn chunk_children(data: &[u8], base: usize, h: &Header, depth: usize) -> Vec<(usize, Header)> {
    let mut out = Vec::new();
    if depth > MAX_DEPTH {
        return out;
    }
    let end = base.saturating_add(h.data_size).min(data.len());
    let mut cur = base.saturating_add(h.header_size);
    let mut n = 0usize;
    while cur + HEADER_SIZE <= end && n < MAX_CHUNKS {
        let Some(child) = read_header(data, cur) else {
            break;
        };
        if child.data_size < HEADER_SIZE {
            break;
        }
        let size = child.data_size;
        out.push((cur, child));
        cur += size;
        n += 1;
    }
    out
}

/// Decode an AXML buffer to text XML. Mirrors
/// `XAndroidBinary::recordToString` for RES_XML_TYPE content.
pub fn decode_axml(data: &[u8]) -> String {
    let Some(root) = read_header(data, 0) else {
        return String::new();
    };
    if root.kind != RES_XML_TYPE {
        return String::new();
    }

    let children = chunk_children(data, 0, &root, 0);
    let mut strings: Vec<String> = Vec::new();
    let mut ns_stack: Vec<(String, String)> = Vec::new(); // (prefix, uri)
    let mut out = String::new();
    let mut elements_open: Vec<String> = Vec::new();

    for (off, h) in children {
        if out.len() > MAX_OUTPUT {
            break;
        }
        match h.kind {
            RES_STRING_POOL_TYPE => {
                let chunk_end = (off + h.data_size).min(data.len());
                let Some(string_count) = u32le(data, off + 8) else {
                    continue;
                };
                let Some(flags) = u32le(data, off + 16) else {
                    continue;
                };
                let Some(strings_start) = u32le(data, off + 20) else {
                    continue;
                };
                let utf8 = flags & STRING_POOL_UTF8_FLAG != 0;
                // Offsets array starts right after the pool header
                // (header.header_size covers it).
                let mut count = string_count as usize;
                let offs_base = off + h.header_size;
                let max_entries = chunk_end.saturating_sub(offs_base) / 4;
                if count > max_entries {
                    count = max_entries;
                }
                if count > MAX_STRINGS {
                    count = MAX_STRINGS;
                }
                let data_base = off + strings_start as usize;
                for j in 0..count {
                    let Some(rel) = u32le(data, offs_base + j * 4) else {
                        break;
                    };
                    let abs = data_base.saturating_add(rel as usize);
                    strings.push(read_pool_string(data, abs, utf8));
                }
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                // Resource IDs are not needed for manifest text output.
            }
            RES_XML_START_NAMESPACE_TYPE => {
                let prefix_idx = u32le(data, off + 16).unwrap_or(u32::MAX);
                let uri_idx = u32le(data, off + 20).unwrap_or(u32::MAX);
                let prefix = str_by_index(&strings, prefix_idx).to_string();
                let uri = str_by_index(&strings, uri_idx).to_string();
                ns_stack.push((prefix, uri));
            }
            RES_XML_END_NAMESPACE_TYPE => {
                ns_stack.pop();
            }
            RES_XML_START_ELEMENT_TYPE => {
                // Upstream reads ResXMLTree_attrExt fields at fixed offsets
                // regardless of the declared headerSize (16 in real files).
                let ns_idx = u32le(data, off + 16).unwrap_or(u32::MAX);
                let name_idx = u32le(data, off + 20).unwrap_or(u32::MAX);
                let attr_count = u16le(data, off + 28).unwrap_or(0) as usize;

                let name = str_by_index(&strings, name_idx);
                let ns = str_by_index(&strings, ns_idx);
                out.push('<');
                if !ns.is_empty()
                    && let Some(p) = ns_prefix(&ns_stack, ns)
                {
                    out.push_str(&p);
                    out.push(':');
                }
                out.push_str(name);
                elements_open.push(name.to_string());

                // Upstream reads attributes at off + sizeof(HEADER_XML_START)
                // (=36) with a fixed stride of sizeof(HEADER_XML_ATTRIBUTE)
                // (=20), ignoring attributeStart/attributeSize fields.
                for a in 0..attr_count {
                    let Some(aoff) = off.checked_add(XML_START_FIXED_SIZE + a * XML_ATTR_SIZE)
                    else {
                        break;
                    };
                    if aoff + XML_ATTR_SIZE > data.len() {
                        break;
                    }
                    let a_ns = u32le(data, aoff).unwrap_or(u32::MAX);
                    let a_name = u32le(data, aoff + 4).unwrap_or(u32::MAX);
                    let data_type = data.get(aoff + 15).copied().unwrap_or(0);
                    let a_data = u32le(data, aoff + 16).unwrap_or(0);

                    let value = match data_type {
                        // TYPE_REFERENCE
                        1 => format!("@{a_data:x}"),
                        // TYPE_STRING
                        3 => str_by_index(&strings, a_data).to_string(),
                        // TYPE_INT_DEC
                        16 => a_data.to_string(),
                        // TYPE_INT_HEX / flags
                        17 => format!("0x{a_data:x}"),
                        // TYPE_INT_BOOLEAN
                        18 => {
                            if a_data == 0xFFFF_FFFF {
                                "true".to_string()
                            } else {
                                "false".to_string()
                            }
                        }
                        // Upstream leaves other typed values empty.
                        _ => String::new(),
                    };

                    let mut aname = str_by_index(&strings, a_name).to_string();
                    if aname == ":" {
                        aname.clear();
                    }
                    if aname.is_empty() {
                        continue;
                    }
                    let a_ns_str = str_by_index(&strings, a_ns);
                    out.push(' ');
                    if !a_ns_str.is_empty()
                        && let Some(p) = ns_prefix(&ns_stack, a_ns_str)
                    {
                        out.push_str(&p);
                        out.push(':');
                    }
                    out.push_str(&aname);
                    out.push_str("=\"");
                    out.push_str(&xml_escape(&value));
                    out.push('"');
                }
                out.push('>');
            }
            RES_XML_END_ELEMENT_TYPE => {
                if let Some(name) = elements_open.pop() {
                    out.push_str("</");
                    out.push_str(&name);
                    out.push('>');
                }
            }
            RES_XML_CDATA_TYPE => {
                let idx = u32le(data, off + 16).unwrap_or(u32::MAX);
                out.push_str(&xml_escape(str_by_index(&strings, idx)));
            }
            _ => {}
        }
    }

    out
}

/// Resolve a namespace URI to its most recently declared prefix.
fn ns_prefix(stack: &[(String, String)], uri: &str) -> Option<String> {
    stack
        .iter()
        .rev()
        .find(|(_, u)| u == uri)
        .map(|(p, _)| p.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_chunk(strs: &[&str]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offs = Vec::new();
        for s in strs {
            offs.push(data.len() as u32);
            data.push(s.len() as u8);
            data.push(s.len() as u8);
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }
        let n = strs.len() as u32;
        let strings_start = 28 + n * 4;
        let size = strings_start + data.len() as u32;
        let mut c = Vec::new();
        c.extend_from_slice(&0x0001u16.to_le_bytes());
        c.extend_from_slice(&28u16.to_le_bytes());
        c.extend_from_slice(&size.to_le_bytes());
        c.extend_from_slice(&n.to_le_bytes());
        c.extend_from_slice(&0u32.to_le_bytes());
        c.extend_from_slice(&0x100u32.to_le_bytes());
        c.extend_from_slice(&strings_start.to_le_bytes());
        c.extend_from_slice(&0u32.to_le_bytes());
        for o in &offs {
            c.extend_from_slice(&o.to_le_bytes());
        }
        c.extend_from_slice(&data);
        c
    }

    #[test]
    fn decodes_manifest_package_attr() {
        let strings = ["ns-uri", "android", "manifest", "package", "com.x.y"];
        let pool = pool_chunk(&strings);
        let mut el = Vec::new();
        el.extend_from_slice(&0x0102u16.to_le_bytes());
        el.extend_from_slice(&16u16.to_le_bytes());
        el.extend_from_slice(&56u32.to_le_bytes());
        el.extend_from_slice(&0u32.to_le_bytes());
        el.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        el.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        el.extend_from_slice(&2u32.to_le_bytes());
        el.extend_from_slice(&20u16.to_le_bytes());
        el.extend_from_slice(&20u16.to_le_bytes());
        el.extend_from_slice(&1u16.to_le_bytes());
        for _ in 0..3 {
            el.extend_from_slice(&0u16.to_le_bytes());
        }
        // attr: ns=-1, name="package"(3), rawValue=-1, size=8, type=3, data=4
        el.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        el.extend_from_slice(&3u32.to_le_bytes());
        el.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        el.extend_from_slice(&8u16.to_le_bytes());
        el.push(0);
        el.push(3);
        el.extend_from_slice(&4u32.to_le_bytes());
        let mut end = Vec::new();
        end.extend_from_slice(&0x0103u16.to_le_bytes());
        end.extend_from_slice(&16u16.to_le_bytes());
        end.extend_from_slice(&24u32.to_le_bytes());
        end.extend_from_slice(&[0u8; 16]);

        let total = 8 + pool.len() + el.len() + end.len();
        let mut axml = Vec::new();
        axml.extend_from_slice(&0x0003u16.to_le_bytes());
        axml.extend_from_slice(&8u16.to_le_bytes());
        axml.extend_from_slice(&(total as u32).to_le_bytes());
        axml.extend_from_slice(&pool);
        axml.extend_from_slice(&el);
        axml.extend_from_slice(&end);

        let out = decode_axml(&axml);
        assert!(out.contains("package=\"com.x.y\""), "got: {out}");
        assert!(out.contains("<manifest") && out.contains("</manifest>"));
    }
}

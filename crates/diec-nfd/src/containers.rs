//! Port of `NFDContainers` — structural validators for disk-image and
//! package containers: DMG (UDIF), VHD, VHDX, QCOW2/3, VDI, VMDK
//! (SESparse + sparse extent), cpio (newc/odc/binary), ar (+deb), RPM,
//! SQLite and WIM, plus Git loose objects.
//!
//! Upstream semantics: `database` results (SQLite) go to
//! `mapResultDatabases` with `RECORD_TYPE_DATABASE`; everything else is
//! `RECORD_TYPE_FORMAT` in `mapResultArchives` and sets
//! `id.fileType = FT_ARCHIVE` (tracked by the caller through the return
//! value).

use crate::gen_names::{ft, name as n, rtype as rt};
use crate::scans::{ResultMaps, ScanRecord};

/// Recognition budgets, independent of declared payload size.
const READ_BUDGET: u64 = 2 * 1024 * 1024;
const MAX_READ: u64 = 256 * 1024;
const MAX_RECORDS: u32 = 4096;

/// Bounded reader over the input buffer — mirrors the QIODevice `Reader`
/// of upstream (read budget, per-read cap, read count cap).
struct Reader<'a> {
    d: &'a [u8],
    used: u64,
    reads: u32,
    /// `stringWork` budget for RPM string-table walks.
    string_work: u64,
}

impl<'a> Reader<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self {
            d,
            used: 0,
            reads: 0,
            string_work: READ_BUDGET,
        }
    }
    fn size(&self) -> u64 {
        self.d.len() as u64
    }
    fn range(&self, off: u64, len: u64) -> bool {
        off <= self.size() && len <= self.size() - off
    }
    fn read(&mut self, off: u64, len: u64) -> Option<&'a [u8]> {
        if !self.range(off, len) || len > MAX_READ || len > READ_BUDGET - self.used {
            return None;
        }
        self.reads += 1;
        if self.reads > 16384 {
            return None;
        }
        self.used += len;
        Some(&self.d[off as usize..(off + len) as usize])
    }
    /// `zeroes` — require the whole span to be zero bytes.
    fn zeroes(&mut self, mut off: u64, mut len: u64) -> bool {
        while len != 0 {
            let n = len.min(4096);
            let Some(b) = self.read(off, n) else {
                return false;
            };
            if b.len() as u64 != n || b.iter().any(|&c| c != 0) {
                return false;
            }
            off += n;
            len -= n;
        }
        true
    }
}

fn u8at(b: &[u8], o: usize) -> u8 {
    b.get(o).copied().unwrap_or(0)
}
fn number(b: &[u8], off: usize, bytes: usize, big: bool) -> u64 {
    let mut n = 0u64;
    for i in 0..bytes {
        let idx = if big { i } else { bytes - 1 - i };
        n = (n << 8) | u64::from(u8at(b, off + idx));
    }
    n
}
fn u32v(b: &[u8], o: usize, be: bool) -> u32 {
    u32::try_from(number(b, o, 4, be)).unwrap_or(0)
}
fn u16v(b: &[u8], o: usize, be: bool) -> u16 {
    u16::try_from(number(b, o, 2, be)).unwrap_or(0)
}
fn u64v(b: &[u8], o: usize, be: bool) -> u64 {
    number(b, o, 8, be)
}
fn power2(v: u64) -> bool {
    v != 0 && v & (v - 1) == 0
}
fn span(off: u64, len: u64, end: u64) -> bool {
    off <= end && len <= end - off
}
/// Offset/length measured in 512-byte sectors of the whole input.
fn sectors(r: &Reader, off: u64, len: u64) -> bool {
    off <= r.size() / 512 && len <= r.size() / 512 - off
}

/// `asciiNumber` — parse a fixed-width ASCII field in `base` (8/10/16),
/// optionally whitespace-padded.
fn ascii_number(b: &[u8], off: usize, len: usize, base: u64, padded: bool) -> Option<u64> {
    let s = b.get(off..off + len)?;
    let s: &[u8] = if padded {
        let mut s = s;
        while let Some((&f, rest)) = s.split_first() {
            if f == b' ' || f == b'\t' {
                s = rest;
            } else {
                break;
            }
        }
        while let Some((&l, rest)) = s.split_last() {
            if l == b' ' || l == b'\t' {
                s = rest;
            } else {
                break;
            }
        }
        s
    } else {
        s
    };
    if s.is_empty() {
        return None;
    }
    let mut v = 0u64;
    for &c in s {
        let digit = match c {
            b'0'..=b'9' => u64::from(c - b'0'),
            b'a'..=b'f' => u64::from(c - b'a') + 10,
            b'A'..=b'F' => u64::from(c - b'A') + 10,
            _ => return None,
        };
        if digit >= base || v > (u64::MAX - digit) / base {
            return None;
        }
        v = v * base + digit;
    }
    Some(v)
}

/// `sumValid` — one's-complement sum over the block, checksum field
/// excluded, compared big-endian.
fn sum_valid(b: &[u8], checksum: usize) -> bool {
    let mut sum = 0u32;
    for (i, &c) in b.iter().enumerate() {
        if i < checksum || i >= checksum + 4 {
            sum = sum.wrapping_add(u32::from(c));
        }
    }
    !sum == u32v(b, checksum, true)
}

/// `crc32cValid` — CRC-32C (Castagnoli), bytes 4..8 zeroed during the
/// pass, compared little-endian at offset 4.
fn crc32c_valid(b: &[u8]) -> bool {
    let mut crc = !0u32;
    for (i, &c) in b.iter().enumerate() {
        crc ^= if (4..8).contains(&i) { 0 } else { u32::from(c) };
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0x82F6_3B78 } else { 0 };
        }
    }
    !crc == u32v(b, 4, false)
}

/// Upstream `Result` aggregate — `key` is the `RECORD_NAME` for the map
/// key (UNKNOWN unless set), `database` routes to mapResultDatabases.
#[derive(Default)]
struct Result {
    name: &'static str,
    version: String,
    info: String,
    key: u16,
    database: bool,
}

/// DMG — UDIF `koly` trailer + plist XML containing a `blkx` key.
fn dmg(r: &mut Reader, out: &mut Result) -> bool {
    if r.size() < 512 {
        return false;
    }
    let end = r.size() - 512;
    let Some(h) = r.read(end, 512) else {
        return false;
    };
    if h.len() != 512 || !h.starts_with(b"koly") || u32v(h, 4, true) != 4 || u32v(h, 8, true) != 512
    {
        return false;
    }
    if u32v(h, 56, true) != 1 || u32v(h, 60, true) != 1 || u64v(h, 492, true) == 0 {
        return false;
    }
    let data = u64v(h, 24, true);
    let data_size = u64v(h, 32, true);
    let xml = u64v(h, 216, true);
    let xml_size = u64v(h, 224, true);
    if !span(data, data_size, end)
        || data_size == 0
        || xml_size == 0
        || xml < data + data_size
        || !span(xml, xml_size, end)
    {
        return false;
    }
    if !span(u64v(h, 40, true), u64v(h, 48, true), end) {
        return false;
    }
    for pos in [80usize, 352] {
        let ty = u32v(h, pos, true);
        let bits = u32v(h, pos + 4, true);
        if bits > 1024 || (ty == 2 && bits != 32) {
            return false;
        }
    }
    let Some(x) = r.read(xml, xml_size) else {
        return false;
    };
    if x.len() as u64 != xml_size {
        return false;
    }
    // Minimal plist scan: root <plist> element and a <key>blkx</key>.
    let text = String::from_utf8_lossy(x);
    let trimmed = text.trim_start();
    if !trimmed.contains("<plist") || !text.contains("<key>blkx</key>") {
        return false;
    }
    *out = Result {
        name: "Apple Disk Image (UDIF)",
        version: "4".to_string(),
        info: "XML metadata; format revision".to_string(),
        ..Default::default()
    };
    true
}

/// VHD — `conectix` footer, one's-complement checksum, then the
/// fixed/dynamic/differencing structure rules.
fn vhd(r: &mut Reader, out: &mut Result) -> bool {
    if r.size() < 1024 || !r.size().is_multiple_of(512) {
        return false;
    }
    let Some(h) = r.read(r.size() - 512, 512) else {
        return false;
    };
    if h.len() != 512
        || !h.starts_with(b"conectix")
        || u32v(h, 12, true) != 0x10000
        || !sum_valid(h, 64)
    {
        return false;
    }
    let ty = u32v(h, 60, true);
    let disk_size = u64v(h, 48, true);
    let next = u64v(h, 16, true);
    if disk_size == 0 || !disk_size.is_multiple_of(512) || u32v(h, 8, true) & 2 == 0 {
        return false;
    }
    let kind: &str;
    if ty == 2 {
        if next != u64::MAX || disk_size != r.size() - 512 {
            return false;
        }
        kind = "fixed";
    } else if ty == 3 || ty == 4 {
        if !next.is_multiple_of(512) || !span(next, 1024, r.size() - 512) {
            return false;
        }
        let Some(d) = r.read(next, 1024) else {
            return false;
        };
        if d.len() != 1024
            || !d.starts_with(b"cxsparse")
            || u64v(d, 8, true) != u64::MAX
            || u32v(d, 24, true) != 0x10000
            || !sum_valid(d, 36)
        {
            return false;
        }
        let count = u64::from(u32v(d, 28, true));
        let block = u64::from(u32v(d, 32, true));
        let bat = u64v(d, 16, true);
        if !power2(block)
            || block < 512
            || count == 0
            || count < (disk_size - 1) / block + 1
            || !bat.is_multiple_of(512)
            || !span(bat, count * 4, r.size() - 512)
        {
            return false;
        }
        kind = if ty == 3 { "dynamic" } else { "differencing" };
    } else {
        return false;
    }
    *out = Result {
        name: "VHD",
        version: "1.0".to_string(),
        info: format!("{kind}; checksummed format header"),
        ..Default::default()
    };
    true
}

/// `vhdxMetadata` — validate the `regi` region table then the metadata
/// region items (file size / logical sector / physical parameters).
fn vhdx_metadata(r: &mut Reader, t: &[u8], out: &mut Result) -> bool {
    let count = u32v(t, 8, false);
    if count == 0 || count > 2047 || u32v(t, 12, false) != 0 {
        return false;
    }
    const BAT_GUID: [u8; 16] = [
        0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a,
        0x08,
    ];
    const META_GUID: [u8; 16] = [
        0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88,
        0x6e,
    ];
    let mut meta = 0u64;
    let mut meta_size = 0u64;
    let mut bat = false;
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for i in 0..count {
        let p = 16 + i as usize * 32;
        let off = u64v(t, p + 16, false);
        let len = u64::from(u32v(t, p + 24, false));
        if off < 1048576
            || !off.is_multiple_of(1048576)
            || len == 0
            || len % 1048576 != 0
            || !r.range(off, len)
            || u32v(t, p + 28, false) > 1
        {
            return false;
        }
        for &(s0, s1) in &spans {
            if off < s0 + s1 && s0 < off + len {
                return false;
            }
        }
        spans.push((off, len));
        let id = t.get(p..p + 16).unwrap_or(&[]);
        if id == BAT_GUID {
            if bat {
                return false;
            }
            bat = true;
        }
        if id == META_GUID {
            if meta != 0 {
                return false;
            }
            meta = off;
            meta_size = len;
        }
    }
    if !bat || meta == 0 {
        return false;
    }
    let Some(m) = r.read(meta, 65536) else {
        return false;
    };
    if m.len() != 65536 || !m.starts_with(b"metadata") || u16v(m, 8, false) != 0 {
        return false;
    }
    let entries = u16v(m, 10, false);
    if entries == 0 || entries > 2047 {
        return false;
    }
    const SIZE_GUID: [u8; 16] = [
        0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4,
        0xb8,
    ];
    const PARAM_GUID: [u8; 16] = [
        0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7,
        0x6b,
    ];
    const SECTOR_GUID: [u8; 16] = [
        0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab,
        0x5f,
    ];
    let mut disk = 0u64;
    let mut flags = 0u32;
    let mut sector = 0u32;
    let mut parameters = false;
    for i in 0..entries {
        let p = 32 + i as usize * 32;
        let off = u64::from(u32v(m, p + 16, false));
        let len = u64::from(u32v(m, p + 20, false));
        if (len != 0 && off < 65536)
            || (len == 0 && off != 0)
            || !span(off, len, meta_size)
            || len > 1048576
        {
            return false;
        }
        let id = m.get(p..p + 16).unwrap_or(&[]);
        if id != SIZE_GUID && id != PARAM_GUID && id != SECTOR_GUID {
            continue;
        }
        if len != if id == SECTOR_GUID { 4 } else { 8 } {
            return false;
        }
        let Some(v) = r.read(meta + off, len) else {
            return false;
        };
        if v.len() as u64 != len {
            return false;
        }
        if id == SIZE_GUID {
            if disk != 0 {
                return false;
            }
            disk = u64v(v, 0, false);
        }
        if id == PARAM_GUID {
            let block = u32v(v, 0, false);
            if parameters
                || !power2(u64::from(block))
                || !(1048576..=256 * 1048576).contains(&block)
            {
                return false;
            }
            parameters = true;
            flags = u32v(v, 4, false);
        }
        if id == SECTOR_GUID {
            if sector != 0 {
                return false;
            }
            sector = u32v(v, 0, false);
        }
    }
    if disk == 0
        || !parameters
        || (sector != 512 && sector != 4096)
        || !disk.is_multiple_of(u64::from(sector))
    {
        return false;
    }
    *out = Result {
        name: "VHDX",
        version: "1".to_string(),
        info: if flags & 2 != 0 {
            "differencing".to_string()
        } else if flags & 1 != 0 {
            "fixed".to_string()
        } else {
            "dynamic".to_string()
        },
        ..Default::default()
    };
    true
}

/// VHDX — `vhdxfile` signature, dual `head` log headers with CRC32C, and
/// a valid region table + metadata region.
fn vhdx(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if !h.starts_with(b"vhdxfile") || r.size() < 1048576 {
        return false;
    }
    let a = r.read(65536, 4096).map(|s| s.to_vec());
    let b = r.read(131072, 4096).map(|s| s.to_vec());
    let va = matches!(&a, Some(v) if v.len() == 4096 && v.starts_with(b"head") && crc32c_valid(v));
    let vb = matches!(&b, Some(v) if v.len() == 4096 && v.starts_with(b"head") && crc32c_valid(v));
    if (!va && !vb)
        || (va
            && vb
            && u64v(a.as_deref().unwrap(), 8, false) == u64v(b.as_deref().unwrap(), 8, false))
    {
        return false;
    }
    let current: &[u8] = if va
        && (!vb || u64v(a.as_deref().unwrap(), 8, false) > u64v(b.as_deref().unwrap(), 8, false))
    {
        a.as_deref().unwrap()
    } else {
        b.as_deref().unwrap()
    };
    let log = u64v(current, 72, false);
    let length = u64::from(u32v(current, 68, false));
    if u16v(current, 64, false) != 0
        || u16v(current, 66, false) != 1
        || length < 1048576
        || length % 1048576 != 0
        || log < 1048576
        || !log.is_multiple_of(1048576)
        || !r.range(log, length)
    {
        return false;
    }
    for off in [196608u64, 262144] {
        if let Some(t) = r.read(off, 65536)
            && t.len() == 65536
            && t.starts_with(b"regi")
            && crc32c_valid(t)
            && vhdx_metadata(r, t, out)
        {
            return true;
        }
    }
    false
}

/// QCOW2/3 — `QFI\xFB` magic, version 2/3 only, cluster and table spans.
fn qcow(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 104 || h[..4] != [0x51, 0x46, 0x49, 0xFB] {
        return false;
    }
    let version = u32v(h, 4, true);
    let bits = u32v(h, 20, true);
    if (version != 2 && version != 3)
        || !(9..=21).contains(&bits)
        || u64v(h, 24, true) == 0
        || u32v(h, 32, true) > 2
    {
        return false;
    }
    let cluster = 1u64 << bits;
    let l1 = u64v(h, 40, true);
    let refs = u64v(h, 48, true);
    let entries = u64::from(u32v(h, 36, true));
    let ref_clusters = u64::from(u32v(h, 56, true));
    let backing = u64v(h, 8, true);
    let backing_len = u32v(h, 16, true);
    if entries == 0
        || ref_clusters == 0
        || l1 < cluster
        || refs < cluster
        || !l1.is_multiple_of(cluster)
        || !refs.is_multiple_of(cluster)
        || !r.range(l1, entries * 8)
        || !r.range(refs, ref_clusters * cluster)
    {
        return false;
    }
    if backing != 0
        && (backing_len > 1023
            || backing_len == 0
            || !span(backing, u64::from(backing_len), cluster)
            || !r.range(backing, u64::from(backing_len)))
    {
        return false;
    }
    let features = if version == 3 { u64v(h, 72, true) } else { 0 };
    let header_size = if version == 3 {
        u64::from(u32v(h, 100, true))
    } else {
        72
    };
    if version == 3
        && (header_size < 104
            || header_size % 8 != 0
            || header_size > cluster
            || !r.range(0, header_size)
            || u32v(h, 96, true) > 6)
    {
        return false;
    }
    if backing != 0 && backing < header_size {
        return false;
    }
    let coverage = cluster * (cluster / if features & 16 != 0 { 16 } else { 8 });
    if (features & 16 != 0) && bits < 14 {
        return false;
    }
    if entries < (u64v(h, 24, true) - 1) / coverage + 1 {
        return false;
    }
    if u32v(h, 60, true) != 0
        && (u64v(h, 64, true) == 0
            || !u64v(h, 64, true).is_multiple_of(8)
            || !r.range(u64v(h, 64, true), 40))
    {
        return false;
    }
    let mut compression = String::new();
    if features & 8 != 0 {
        if header_size < 112 || h.len() < 112 || u8at(h, 104) != 1 {
            return false;
        }
        compression = "Zstandard compressed clusters".to_string();
    }
    *out = Result {
        name: "QCOW2",
        version: format!("{version}"),
        info: compression,
        ..Default::default()
    };
    true
}

/// VDI — image-type/mode signature at 0x40 and the block-map structure.
fn vdi(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 456 || u32v(h, 64, false) != 0xbeda107f || u32v(h, 68, false) != 0x10001 {
        return false;
    }
    let header = u64::from(u32v(h, 72, false));
    let map = u64::from(u32v(h, 340, false));
    let data = u64::from(u32v(h, 344, false));
    let ty = u32v(h, 76, false);
    let sector = u64::from(u32v(h, 360, false));
    let block = u64::from(u32v(h, 376, false));
    let extra = u64::from(u32v(h, 380, false));
    let size = u64v(h, 368, false);
    let blocks = u64::from(u32v(h, 384, false));
    let allocated = u64::from(u32v(h, 388, false));
    if header < 384
        || !r.range(72, header)
        || !(1..=4).contains(&ty)
        || sector != 512
        || size == 0
        || !size.is_multiple_of(sector)
        || !power2(block)
        || block < sector
    {
        return false;
    }
    if blocks == 0
        || allocated > blocks
        || blocks != (size - 1) / block + 1
        || map < 72 + header
        || data < map
        || !span(map, blocks * 4, data)
    {
        return false;
    }
    if data > r.size() || allocated > (r.size() - data) / (block + extra) {
        return false;
    }
    if ty == 2 && allocated != blocks {
        return false;
    }
    *out = Result {
        name: "VirtualBox Disk Image (VDI)",
        version: "1.1".to_string(),
        info: if ty == 1 {
            "dynamic".to_string()
        } else if ty == 2 {
            "fixed".to_string()
        } else {
            "differencing".to_string()
        },
        ..Default::default()
    };
    true
}

/// VMDK — SESparse header or `KDMV` sparse extent.
fn vmdk(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 512 {
        return false;
    }
    if u64v(h, 0, false) == 0xCAFEBABE {
        // SESparse uses virtual grains_size; only allocated data must exist.
        if u64v(h, 8, false) != 0x200000001
            || u64v(h, 16, false) == 0
            || u64v(h, 24, false) != 8
            || u64v(h, 32, false) != 64
            || u64v(h, 40, false) != 0
        {
            return false;
        }
        for p in (48..80).step_by(8) {
            if u64v(h, p, false) != 0 {
                return false;
            }
        }
        for p in (80..192).step_by(16) {
            if u64v(h, p + 8, false) == 0 || !sectors(r, u64v(h, p, false), u64v(h, p + 8, false)) {
                return false;
            }
        }
        if u64v(h, 88, false) != 1
            || !sectors(r, u64v(h, 192, false), 0)
            || u64v(h, 200, false) < u64v(h, 16, false)
        {
            return false;
        }
        let Some(v) = r.read(u64v(h, 80, false) * 512, 512) else {
            return false;
        };
        if v.len() != 512 || u64v(v, 0, false) != 0xCAFECAFE {
            return false;
        }
        *out = Result {
            name: "VMDK",
            version: "0x0000000200000001".to_string(),
            info: "SESparse; extent format revision".to_string(),
            ..Default::default()
        };
        return true;
    }
    if !h.starts_with(b"KDMV") {
        return false;
    }
    let version = u32v(h, 4, false);
    let flags = u32v(h, 8, false);
    let entries = u64::from(u32v(h, 44, false));
    let capacity = u64v(h, 12, false);
    let grain = u64v(h, 20, false);
    let descriptor = u64v(h, 28, false);
    let descriptor_size = u64v(h, 36, false);
    let mut directory = u64v(h, 56, false);
    let overhead = u64v(h, 64, false);
    if !(1..=3).contains(&version)
        || capacity == 0
        || !power2(grain)
        || grain < 8
        || !power2(entries)
        || entries > 65536
        || overhead == 0
        || !sectors(r, 0, overhead)
    {
        return false;
    }
    if descriptor_size != 0 && (descriptor == 0 || !sectors(r, descriptor, descriptor_size)) {
        return false;
    }
    if (flags & 1) != 0 && h.get(73..77) != Some(&[0x0A, 0x20, 0x0D, 0x0A]) {
        return false;
    }
    if u16v(h, 77, false) > 1 {
        return false;
    }
    let tables = (capacity - 1) / grain / entries + 1;
    if directory == u64::MAX {
        if flags & 0x20000 == 0 || r.size() < 1536 {
            return false;
        }
        let Some(footer) = r.read(r.size() - 1024, 512) else {
            return false;
        };
        if footer.len() != 512
            || !footer.starts_with(b"KDMV")
            || u32v(footer, 4, false) != version
            || u64v(footer, 12, false) != capacity
        {
            return false;
        }
        directory = u64v(footer, 56, false);
    }
    if directory == 0 || !sectors(r, directory, (tables * 4).div_ceil(512)) {
        return false;
    }
    *out = Result {
        name: "VMDK",
        version: format!("{version}"),
        info: if flags & 0x10000 != 0 {
            "compressed sparse extent".to_string()
        } else {
            "sparse extent".to_string()
        },
        ..Default::default()
    };
    true
}

/// cpio — full member walk (newc/odc/binary) down to `TRAILER!!!`.
fn cpio(r: &mut Reader, head: &[u8], out: &mut Result) -> bool {
    let magic = &head[..head.len().min(6)];
    let newc = magic == b"070701" || magic == b"070702";
    let crc = magic == b"070702";
    let odc = magic == b"070707";
    let be = head.len() >= 2 && head[..2] == [0x71, 0xC7];
    let binary = be || (head.len() >= 2 && head[..2] == [0xC7, 0x71]);
    if !newc && !odc && !binary {
        return false;
    }
    let mut off = 0u64;
    for _record in 0..MAX_RECORDS {
        let header_size = if newc {
            110
        } else if odc {
            76
        } else {
            26
        };
        let Some(h) = r.read(off, header_size) else {
            return false;
        };
        if h.len() as u64 != header_size {
            return false;
        }
        let name_size: u64;
        let file_size: u64;
        let mut checksum = 0u64;
        let mode: u64;
        let links: u64;
        if newc {
            if h[..6] != *magic {
                return false;
            }
            let mut fields = [0u64; 13];
            for (i, f) in fields.iter_mut().enumerate() {
                let Some(v) = ascii_number(h, 6 + i * 8, 8, 16, false) else {
                    return false;
                };
                *f = v;
            }
            mode = fields[1];
            links = fields[4];
            file_size = fields[6];
            name_size = fields[11];
            checksum = fields[12];
            if !crc && checksum != 0 {
                return false;
            }
        } else if odc {
            if h[..6] != *magic {
                return false;
            }
            for i in 0..7 {
                if ascii_number(h, 6 + i * 6, 6, 8, false).is_none() {
                    return false;
                }
            }
            let (Some(_d0), Some(ns), Some(fs), Some(md), Some(ln)) = (
                ascii_number(h, 48, 11, 8, false),
                ascii_number(h, 59, 6, 8, false),
                ascii_number(h, 65, 11, 8, false),
                ascii_number(h, 18, 6, 8, false),
                ascii_number(h, 36, 6, 8, false),
            ) else {
                return false;
            };
            name_size = ns;
            file_size = fs;
            mode = md;
            links = ln;
        } else {
            if u16v(h, 0, be) != 0o070707 {
                return false;
            }
            mode = u64::from(u16v(h, 6, be));
            links = u64::from(u16v(h, 12, be));
            name_size = u64::from(u16v(h, 20, be));
            file_size = (u64::from(u16v(h, 22, be)) << 16) | u64::from(u16v(h, 24, be));
        }
        if name_size == 0 || name_size > 4096 || !r.range(off + header_size, name_size) {
            return false;
        }
        let Some(name) = r.read(off + header_size, name_size) else {
            return false;
        };
        if name.len() as u64 != name_size
            || name.last().copied().unwrap_or(1) != 0
            || name[..name.len() - 1].contains(&0)
        {
            return false;
        }
        let mut data = off + header_size + name_size;
        let alignment = if newc {
            4
        } else if binary {
            2
        } else {
            1
        };
        data = (data + alignment - 1) & !(alignment - 1);
        if !r.range(data, file_size) {
            return false;
        }
        if name == b"TRAILER!!!\0" {
            if file_size != 0 {
                return false;
            }
            *out = Result {
                name: "CPIO",
                version: if newc {
                    String::from_utf8_lossy(magic).into_owned()
                } else if odc {
                    "070707".to_string()
                } else {
                    "binary 070707".to_string()
                },
                info: if newc {
                    if crc {
                        "new ASCII; additive checksum"
                    } else {
                        "new ASCII"
                    }
                } else if odc {
                    "old ASCII"
                } else if be {
                    "big-endian"
                } else {
                    "little-endian"
                }
                .to_string(),
                ..Default::default()
            };
            return true;
        }
        let kind = mode & 0o170000;
        if links == 0
            || ![
                0o100000, 0o040000, 0o120000, 0o060000, 0o020000, 0o010000, 0o140000,
            ]
            .contains(&kind)
        {
            return false;
        }
        if crc {
            let mut sum = 0u32;
            let mut done = 0u64;
            while done < file_size {
                let cnt = (file_size - done).min(16384);
                let Some(d) = r.read(data + done, cnt) else {
                    return false;
                };
                if d.len() as u64 != cnt {
                    return false;
                }
                for &c in d {
                    sum = sum.wrapping_add(u32::from(c));
                }
                done += cnt;
            }
            if sum as u64 != checksum {
                return false;
            }
        }
        off = (data + file_size + alignment - 1) & !(alignment - 1);
        if off > r.size() {
            return false;
        }
    }
    false
}

/// ar — full member walk; `debian-binary`+`control.tar`+`data.tar`
/// promote the result to a DEB record.
fn ar(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if !h.starts_with(b"!<arch>\n") {
        return false;
    }
    let mut off = 8u64;
    let (mut deb, mut control, mut data_flag) = (false, false, false);
    let mut count = 0u32;
    while off < r.size() && count < MAX_RECORDS {
        let Some(a) = r.read(off, 60) else {
            return false;
        };
        if a.len() != 60 || a[58..60] != *b"`\n" {
            return false;
        }
        let Some(length) = ascii_number(a, 48, 10, 10, true) else {
            return false;
        };
        if !r.range(off + 60, length) {
            return false;
        }
        // GNU symbol/string tables may leave ownership fields blank.
        for &(fo, fl, fb) in &[
            (16usize, 12usize, 10u64),
            (28, 6, 10),
            (34, 6, 10),
            (40, 8, 8),
        ] {
            let field = &a[fo..fo + fl];
            let blank = field.iter().all(|&b| b == b' ' || b == b'\t');
            if !blank && ascii_number(a, fo, fl, fb, true).is_none() {
                return false;
            }
        }
        let mut name: &[u8] = &a[..16];
        while let Some((&b' ', rest)) = name.split_last() {
            name = rest;
        }
        if name.is_empty() {
            return false;
        }
        if name.starts_with(b"#1/") {
            let Some(long_len) = ascii_number(name, 3, name.len() - 3, 10, false) else {
                return false;
            };
            if long_len == 0 || long_len > length || long_len > 4096 {
                return false;
            }
        }
        let name_s = String::from_utf8_lossy(name).into_owned();
        let name_trim = name_s.strip_suffix('/').unwrap_or(&name_s).to_string();
        if count == 0 && name_trim == "debian-binary" && length == 4 {
            deb = r.read(off + 60, 4) == Some(b"2.0\n".as_slice());
        }
        if name_trim == "control.tar" || name_trim.starts_with("control.tar.") {
            control = true;
        }
        if name_trim == "data.tar" || name_trim.starts_with("data.tar.") {
            data_flag = true;
        }
        off += 60 + length;
        if length & 1 != 0 {
            if r.read(off, 1) != Some(b"\n".as_slice()) {
                return false;
            }
            off += 1;
        }
        count += 1;
    }
    if count == 0 || off != r.size() {
        return false;
    }
    *out = if deb && control && data_flag {
        Result {
            name: "Debian package",
            version: "2.0".to_string(),
            info: "ar container".to_string(),
            key: n::RECORD_NAME_DEB,
            database: false,
        }
    } else {
        Result {
            name: "ar",
            version: String::new(),
            info: "Unix archive".to_string(),
            key: n::RECORD_NAME_AR,
            database: false,
        }
    };
    true
}

/// `rpmHeader` — validate one RPM header structure (signature or main).
fn rpm_header(r: &mut Reader, off: u64, end: &mut u64) -> bool {
    let Some(h) = r.read(off, 16) else {
        return false;
    };
    if h.len() != 16 || h[..8] != [0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0] {
        return false;
    }
    let count = u64::from(u32v(h, 8, true));
    let bytes = u64::from(u32v(h, 12, true));
    if count == 0 || count > 4096 || bytes > MAX_READ || !r.range(off + 16, count * 16 + bytes) {
        return false;
    }
    let Some(index) = r.read(off + 16, count * 16) else {
        return false;
    };
    if index.len() as u64 != count * 16 {
        return false;
    }
    let index = index.to_vec();
    let Some(store) = r.read(off + 16 + count * 16, bytes) else {
        return false;
    };
    if store.len() as u64 != bytes {
        return false;
    }
    let store = store.to_vec();
    for i in 0..count {
        let p = i as usize * 16;
        let ty = u32v(&index, p + 4, true);
        let start = u64::from(u32v(&index, p + 8, true));
        let num = u64::from(u32v(&index, p + 12, true));
        if ty > 9 || start > bytes || num > READ_BUDGET {
            return false;
        }
        let width: u64 = if ty == 3 {
            2
        } else if ty == 4 {
            4
        } else if ty == 5 {
            8
        } else {
            1
        };
        if ty <= 5 || ty == 7 {
            if !span(start, num * width, bytes) || start % width != 0 {
                return false;
            }
        } else {
            if (ty == 6 && num != 1) || num == 0 || num > bytes - start {
                return false;
            }
            let mut pos = start as usize;
            for _ in 0..num {
                if r.string_work == 0 {
                    return false;
                }
                let limit = (store.len() - pos).min(r.string_work as usize);
                let found = store[pos..pos + limit].iter().position(|&c| c == 0);
                let scanned = found.map(|f| f + 1).unwrap_or(limit);
                r.string_work -= scanned as u64;
                if found.is_none() {
                    return false;
                }
                pos += scanned;
            }
        }
    }
    *end = off + 16 + count * 16 + bytes;
    true
}

/// RPM — `ED AB EE DB` lead then signature and main header structures.
fn rpm(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 96
        || h[..4] != [0xED, 0xAB, 0xEE, 0xDB]
        || u8at(h, 4) != 3
        || h[5] != 0
        || u16v(h, 6, true) > 1
        || u16v(h, 78, true) != 5
        || !h[10..76.min(h.len())].contains(&0)
    {
        return false;
    }
    let mut sig = 0u64;
    if !rpm_header(r, 96, &mut sig) {
        return false;
    }
    let aligned = (sig + 7) & !7;
    if !r.zeroes(sig, aligned - sig) {
        return false;
    }
    let mut main = 0u64;
    if !rpm_header(r, aligned, &mut main) || main >= r.size() {
        return false;
    }
    *out = Result {
        name: "RPM",
        version: "lead 3.0; header 1".to_string(),
        info: "package container; signatures not verified".to_string(),
        ..Default::default()
    };
    true
}

/// Git loose object — the whole file is one zlib stream decoding to
/// `<kind> <len>\0<payload>`.
fn git(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if r.size() < 8 || r.size() > 65536 || h.len() < 2 {
        return false;
    }
    let z = u16v(h, 0, true);
    if (u8at(h, 0) & 15) != 8
        || (u8at(h, 0) >> 4) > 7
        || !z.is_multiple_of(31)
        || (u8at(h, 1) & 32) != 0
    {
        return false;
    }
    let Some(compressed) = r.read(0, r.size()) else {
        return false;
    };
    if compressed.len() as u64 != r.size() {
        return false;
    }
    let mut dec = flate2::Decompress::new(true);
    let mut decoded = vec![0u8; 65536];
    let status = dec.decompress(compressed, &mut decoded, flate2::FlushDecompress::Finish);
    let size = dec.total_out() as usize;
    if !matches!(status, Ok(flate2::Status::StreamEnd)) || dec.total_in() != r.size() {
        return false;
    }
    decoded.truncate(size);
    let zero = decoded
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(decoded.len());
    let space = decoded
        .iter()
        .position(|&b| b == b' ')
        .unwrap_or(decoded.len());
    if space == 0 || space > zero || zero <= space + 1 || zero > 64 {
        return false;
    }
    let kind = String::from_utf8_lossy(&decoded[..space]).into_owned();
    if !matches!(kind.as_str(), "blob" | "tree" | "commit" | "tag") {
        return false;
    }
    let Some(length) = ascii_number(&decoded, space + 1, zero - space - 1, 10, false) else {
        return false;
    };
    if length != (decoded.len() - zero - 1) as u64
        || (zero > space + 2 && decoded[space + 1] == b'0')
    {
        return false;
    }
    *out = Result {
        name: "Git loose object",
        version: String::new(),
        info: format!("{kind}; {length} payload bytes"),
        ..Default::default()
    };
    true
}

/// SQLite — `SQLite format 3\0` banner plus header field and first
/// b-tree page validation; routed to `mapResultDatabases`.
fn sqlite(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 108 || h[..16] != *b"SQLite format 3\0" {
        return false;
    }
    let mut page = u64::from(u16v(h, 16, true));
    if page == 1 {
        page = 65536;
    }
    if !power2(page)
        || !(512..=65536).contains(&page)
        || !r.size().is_multiple_of(page)
        || r.size() < page
        || u64::from(u8at(h, 20)) > page - 480
        || h[21..24] != [0x40, 0x20, 0x20]
    {
        return false;
    }
    let write = u8at(h, 18);
    let read = u8at(h, 19);
    let schema = u32v(h, 44, true);
    let encoding = u32v(h, 56, true);
    if !(1..=2).contains(&write)
        || !(1..=2).contains(&read)
        || schema > 4
        || encoding > 3
        || (schema != 0 && encoding == 0)
    {
        return false;
    }
    if h[72..92].iter().any(|&b| b != 0) {
        return false;
    }
    let declared = u64::from(u32v(h, 28, true));
    if declared != 0 && u32v(h, 24, true) == u32v(h, 92, true) && declared > r.size() / page {
        return false;
    }
    let ty = u8at(h, 100);
    if ty != 5 && ty != 13 {
        return false;
    }
    let cells = u64::from(u16v(h, 103, true));
    let mut content = u64::from(u16v(h, 105, true));
    if content == 0 {
        content = 65536;
    }
    let header_len = if ty == 5 { 112 } else { 108 };
    if header_len + cells * 2 > page
        || content < header_len + cells * 2
        || content > page - u64::from(u8at(h, 20))
        || u8at(h, 107) > 60
    {
        return false;
    }
    if schema == 0 && (ty != 13 || cells != 0) {
        return false;
    }
    *out = Result {
        name: "SQLite 3",
        version: format!("schema {schema}; read {read}, write {write}"),
        info: format!("{page}-byte pages"),
        key: 0,
        database: true,
    };
    true
}

/// WIM — `MSWIM` magic plus header/parts structure validation.
fn wim(r: &mut Reader, h: &[u8], out: &mut Result) -> bool {
    if h.len() < 208 || h[..8] != *b"MSWIM\0\0\0" || u32v(h, 8, false) != 208 {
        return false;
    }
    let version = u32v(h, 12, false);
    let chunk = u32v(h, 20, false);
    let flags = u32v(h, 16, false);
    if (version != 0x10d00 && version != 0xe00)
        || u16v(h, 40, false) == 0
        || u16v(h, 40, false) > u16v(h, 42, false)
        || u32v(h, 120, false) > u32v(h, 44, false)
    {
        return false;
    }
    if flags & 2 != 0 {
        if !power2(u64::from(chunk)) || !(4096..=67108864).contains(&chunk) {
            return false;
        }
    } else if chunk != 0 {
        return false;
    }
    for p in [48usize, 72, 96, 124] {
        let size = u64v(h, p, false) & 0x00FF_FFFF_FFFF_FFFF;
        let off = u64v(h, p + 8, false);
        if (size == 0 && off != 0) || (size != 0 && off < 208) || !r.range(off, size) {
            return false;
        }
    }
    if u64v(h, 72, false) & 0x00FF_FFFF_FFFF_FFFF == 0 {
        return false;
    }
    *out = Result {
        name: "WIM",
        version: format!("0x{version:08x}"),
        info: format!(
            "{} image(s); part {}/{}",
            u32v(h, 44, false),
            u16v(h, 40, false),
            u16v(h, 42, false)
        ),
        ..Default::default()
    };
    true
}

/// `NFDContainers::detect` — first hit wins; returns `true` when a
/// container record was inserted. Non-database hits go to
/// `mapResultArchives`, database hits to `mapResultDatabases` with
/// `RECORD_TYPE_DATABASE`.
pub fn detect(d: &[u8], res: &mut ResultMaps) -> bool {
    if d.len() < 8 {
        return false;
    }
    let mut reader = Reader::new(d);
    let Some(h) = reader.read(0, reader.size().min(512)) else {
        return false;
    };
    let h = h.to_vec();
    let mut result = Result::default();
    // Footer recognition precedes short compression signatures, especially
    // a UDIF data fork that happens to start with a zlib stream.
    let found = dmg(&mut reader, &mut result)
        || vhd(&mut reader, &mut result)
        || vhdx(&mut reader, &h, &mut result)
        || qcow(&mut reader, &h, &mut result)
        || vdi(&mut reader, &h, &mut result)
        || vmdk(&mut reader, &h, &mut result)
        || cpio(&mut reader, &h, &mut result)
        || ar(&mut reader, &h, &mut result)
        || rpm(&mut reader, &h, &mut result)
        || sqlite(&mut reader, &h, &mut result)
        || wim(&mut reader, &h, &mut result)
        || git(&mut reader, &h, &mut result);
    if !found {
        return false;
    }
    let rec = ScanRecord {
        name: if result.key == 0 {
            n::RECORD_NAME_UNKNOWN
        } else {
            result.key
        },
        rtype: if result.database {
            rt::RECORD_TYPE_DATABASE
        } else {
            rt::RECORD_TYPE_FORMAT
        },
        ft: if result.database {
            ft::FT_BINARY
        } else {
            ft::FT_ARCHIVE
        },
        variant: 0,
        version: result.version.clone(),
        info: result.info.clone(),
        heuristic: false,
        unknown: false,
        sname: Some(std::borrow::Cow::Borrowed(result.name)),
        stype: None,
    };
    if result.database {
        res.databases.insert(rec.name, rec);
    } else {
        res.archives.insert(rec.name, rec);
    }
    true
}

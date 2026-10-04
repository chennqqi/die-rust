//! WIM image enumeration — port of upstream `xwim.cpp`
//! (`isValid` + the `initUnpack` enumeration pipeline).
//!
//! Upstream is unusually strict here: the lookup table must contain
//! unique non-empty hashes for data streams, physical resource ranges
//! must not overlap (header, offset table, XML, integrity and every
//! local stream), each metadata resource's SHA-1 is verified against
//! its lookup hash, directory entries carry UTF-16LE names with
//! terminators, stream reference counts are reconciled against the
//! actual references found in the metadata, and the boot descriptor
//! must alias a live metadata resource.
//!
//! Scope: stored, XPRESS-Huffman and LZX chunked resources are read
//! and decoded (`wim_decode`); LZMS stays unsupported, matching the
//! upstream `_stageChunkedResource` contract which rejects it.

use super::wim_decode;
use std::collections::{BTreeMap, HashMap, HashSet};

use super::SecondaryRecord;

const HEADER_OLD: u64 = 0x60;
const HEADER_NEW: u64 = 0xD0;
const STREAM_INFO: usize = 50;
const STREAM_INFO_OLD: usize = 52;
const DIR_ENTRY: usize = 0x66;
const DIR_ENTRY_OLD: usize = 0x3E;
const HASH_SIZE: usize = 20;

const FLAG_COMPRESSION: u32 = 1 << 1;
const FLAG_XPRESS: u32 = 1 << 17;
const FLAG_XPRESS2: u32 = 1 << 21;
const FLAG_LZX: u32 = 1 << 18;
const FLAG_LZMS: u32 = 1 << 19;

const RES_METADATA: u8 = 1 << 1;
const RES_COMPRESSED: u8 = 1 << 2;
const RES_SOLID: u8 = 1 << 4;

const MAX_IMAGES: usize = 65536;
const MAX_RECORDS: usize = 1_000_000;
const MAX_DEPTH: usize = 256;
const MAX_PATH: usize = 32768;
const MAX_BUFFERED: u64 = 256 * 1024 * 1024;
const MAX_CHUNK: u32 = 0x4000_0000;
const MAX_XPRESS_CHUNK: u32 = 64 * 1024;

fn rd_u16(d: &[u8], off: usize) -> Option<u16> {
    let b = d.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    let b = d.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn rd_u64(d: &[u8], off: usize) -> Option<u64> {
    let b = d.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// `RESOURCE_INFO`: packed size plus flag byte in one qword.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Resource {
    pack_size: u64,
    offset: u64,
    unpack_size: u64,
    flags: u8,
}

fn read_resource(d: &[u8], off: usize) -> Resource {
    let size = d.len();
    if off + 0x18 > size {
        return Resource::default();
    }
    let packed = rd_u64(d, off).unwrap_or(0);
    Resource {
        flags: (packed >> 56) as u8,
        pack_size: packed & 0x00FF_FFFF_FFFF_FFFF,
        offset: rd_u64(d, off + 8).unwrap_or(0),
        unpack_size: rd_u64(d, off + 16).unwrap_or(0),
    }
}

#[derive(Default)]
struct Header {
    header_size: u32,
    version: u32,
    flags: u32,
    chunk_size: u32,
    part_number: u16,
    number_of_parts: u16,
    number_of_images: u32,
    boot_index: u32,
    offset_table: Resource,
    xml: Resource,
    boot_metadata: Resource,
    integrity: Resource,
}

/// `_isSupportedVersion`.
fn supported_version(version: u32, header_size: u32) -> bool {
    if version == 0x0000_0E00 {
        return header_size as u64 == HEADER_NEW;
    }
    if !(0x0001_0900..=0x0002_0E00).contains(&version) {
        return false;
    }
    if version <= 0x0001_0A00 {
        return header_size as u64 == HEADER_OLD;
    }
    if version == 0x0001_0B00 {
        let s = header_size as u64;
        return s == HEADER_OLD || (0x74..=HEADER_NEW).contains(&s);
    }
    if version == 0x0001_0C00 {
        return (0x74..=HEADER_NEW).contains(&(header_size as u64));
    }
    header_size as u64 == HEADER_NEW
}

/// `_isCompressionConfigurationValid`.
fn compression_config_valid(flags: u32, chunk: u32, require_implemented: bool) -> bool {
    if chunk != 0 && (!(4096..=MAX_CHUNK).contains(&chunk) || (chunk & (chunk - 1)) != 0) {
        return false;
    }
    let method = flags & 0xFFFE_0000;
    if flags & FLAG_COMPRESSION == 0 {
        return method == 0;
    }
    if method != FLAG_XPRESS && method != FLAG_XPRESS2 && method != FLAG_LZX && method != FLAG_LZMS
    {
        return false;
    }
    if !require_implemented {
        return true;
    }
    if method == FLAG_LZMS {
        return false;
    }
    let eff = if chunk == 0 { 32768 } else { chunk };
    if method == FLAG_LZX && !(1 << 15..=1 << 21).contains(&eff) {
        return false;
    }
    if (method == FLAG_XPRESS || method == FLAG_XPRESS2) && eff > MAX_XPRESS_CHUNK {
        return false;
    }
    true
}

/// `isWimResourceExtentValid`.
fn resource_extent_valid(r: &Resource, file_size: u64) -> bool {
    r.offset <= file_size && r.pack_size <= file_size - r.offset
}

/// `isWimResourceDescriptorSupported`.
fn resource_supported(r: &Resource, version: u32, live: bool) -> bool {
    if r.flags & !0x1F != 0 {
        return false;
    }
    if r.flags & 0x10 != 0 && (version != 0x0000_0E00 || live) {
        return false;
    }
    if r.flags & 0x10 == 0 && ((r.unpack_size == 0) != (r.pack_size == 0)) {
        return false;
    }
    true
}

/// `_isResourceStored`: no compression flags and pack == unpack.
fn resource_stored(r: &Resource) -> bool {
    r.flags & (RES_COMPRESSED | RES_SOLID) == 0 && r.pack_size == r.unpack_size
}

fn read_header(d: &[u8]) -> Option<Header> {
    let size = d.len() as u64;
    if size < HEADER_OLD {
        return None;
    }
    let mut h = Header {
        header_size: rd_u32(d, 0x08)?,
        version: rd_u32(d, 0x0C)?,
        flags: rd_u32(d, 0x10)?,
        chunk_size: rd_u32(d, 0x14)?,
        ..Default::default()
    };
    let hs = u64::from(h.header_size);
    if !(HEADER_OLD..=HEADER_NEW).contains(&hs)
        || hs > size
        || !supported_version(h.version, h.header_size)
        || !compression_config_valid(h.flags, h.chunk_size, false)
    {
        return None;
    }
    if hs == HEADER_OLD {
        h.part_number = 1;
        h.number_of_parts = 1;
        h.offset_table = read_resource(d, 0x18);
        h.xml = read_resource(d, 0x30);
        h.boot_metadata = read_resource(d, 0x48);
        return Some(h);
    }
    if hs < 0x74 {
        return None;
    }
    h.part_number = rd_u16(d, 0x28)?;
    h.number_of_parts = rd_u16(d, 0x2A)?;
    let is_new = h.version == 0x0000_0E00 || h.version >= 0x0001_0D00;
    let res_off = if is_new {
        h.number_of_images = rd_u32(d, 0x2C)?;
        0x30
    } else {
        0x2C
    };
    h.offset_table = read_resource(d, res_off);
    h.xml = read_resource(d, res_off + 0x18);
    h.boot_metadata = read_resource(d, res_off + 0x30);
    if is_new {
        h.boot_index = rd_u32(d, res_off + 0x48)?;
        h.integrity = read_resource(d, res_off + 0x4C);
    }
    Some(h)
}

/// Upstream `XWIM::isValid`.
pub fn is_wim(d: &[u8]) -> bool {
    if d.len() < HEADER_OLD as usize {
        return false;
    }
    if d.get(..8) != Some(b"MSWIM\0\0\0") {
        return false;
    }
    let Some(h) = read_header(d) else {
        return false;
    };
    if h.header_size as u64 == HEADER_OLD {
        return true;
    }
    h.part_number != 0 && h.number_of_parts != 0 && h.part_number <= h.number_of_parts
}

/// `_readStoredResource`.
fn read_stored_resource(d: &[u8], r: &Resource) -> Option<Vec<u8>> {
    if !resource_stored(r) {
        return None;
    }
    if r.pack_size == 0 {
        return Some(Vec::new());
    }
    if r.pack_size > MAX_BUFFERED || r.pack_size > i64::MAX as u64 {
        return None;
    }
    let off = r.offset as usize;
    let end = off.checked_add(r.pack_size as usize)?;
    d.get(off..end).map(<[u8]>::to_vec)
}

/// `_getChunkSize`: WIM v1 defaults to the fixed 32768-byte chunk;
/// explicit sizes must be powers of two inside [4096, MAX_CHUNK].
fn effective_chunk_size(chunk: u32) -> Option<u32> {
    if chunk == 0 {
        return Some(32768);
    }
    if !(4096..=MAX_CHUNK).contains(&chunk) || (chunk & (chunk - 1)) != 0 || chunk > i32::MAX as u32
    {
        return None;
    }
    Some(chunk)
}

/// `_getCompressionType`: header flags to the compression enum used by
/// `_readResource`/`_stageChunkedResource`.
fn compression_type(flags: u32) -> Option<wim_decode::WimCompression> {
    if flags & FLAG_COMPRESSION == 0 {
        return None;
    }
    if flags & FLAG_LZX != 0 {
        return Some(wim_decode::WimCompression::Lzx);
    }
    if flags & (FLAG_XPRESS | FLAG_XPRESS2) != 0 {
        return Some(wim_decode::WimCompression::Xpress);
    }
    None
}

/// `_readResource` + `_decompressChunkedResource`: stored resources
/// copy verbatim; compressed non-solid resources are staged through the
/// chunk table by `wim_decode`. LZMS and solid resources return `None`
/// (upstream does not decode them either).
fn read_resource_data(d: &[u8], r: &Resource, h: &Header) -> Option<Vec<u8>> {
    if !resource_extent_valid(r, d.len() as u64)
        || r.pack_size > MAX_BUFFERED
        || r.unpack_size > MAX_BUFFERED
    {
        return None;
    }
    if resource_stored(r) {
        return read_stored_resource(d, r);
    }
    if r.flags & RES_COMPRESSED == 0 || r.flags & RES_SOLID != 0 {
        return None;
    }
    if r.unpack_size == 0 || r.unpack_size > i32::MAX as u64 {
        return None;
    }
    let chunk = effective_chunk_size(h.chunk_size)?;
    let compression = compression_type(h.flags)?;
    wim_decode::stage_chunked_resource(d, r.offset, r.pack_size, r.unpack_size, compression, chunk)
}

#[derive(Clone, Default)]
struct StreamInfo {
    resource: Resource,
    part_number: u16,
    ref_count: u32,
    id: u32,
    hash: Vec<u8>,
}

fn is_empty_hash(h: &[u8]) -> bool {
    h.len() < HASH_SIZE || h.iter().take(HASH_SIZE).all(|&b| b == 0)
}

/// `insertWimResourceRange`: reject overlapping physical ranges.
struct Ranges {
    map: BTreeMap<u64, u64>, // start -> end
}

impl Ranges {
    fn insert(&mut self, start: u64, size: u64) -> bool {
        if size == 0 {
            return true;
        }
        let Some(end) = start.checked_add(size) else {
            return false;
        };
        if let Some((&k, _)) = self.map.range(start..).next()
            && end > k
        {
            return false;
        }
        if let Some((_, &v)) = self.map.range(..start).next_back()
            && v > start
        {
            return false;
        }
        self.map.insert(start, end);
        true
    }
}

/// `_readStreamInfoList`: parse the lookup table with the full set of
/// upstream consistency checks.
fn read_stream_list(d: &[u8], h: &Header) -> Option<Vec<StreamInfo>> {
    let size = d.len() as u64;
    if h.part_number == 0
        || h.number_of_parts == 0
        || h.part_number > h.number_of_parts
        || !resource_extent_valid(&h.offset_table, size)
        || !resource_extent_valid(&h.xml, size)
        || !resource_extent_valid(&h.boot_metadata, size)
        || !resource_extent_valid(&h.integrity, size)
        || !resource_supported(&h.offset_table, h.version, true)
        || !resource_supported(&h.xml, h.version, h.xml.pack_size != 0)
        || !resource_supported(&h.boot_metadata, h.version, h.boot_metadata.pack_size != 0)
        || !resource_supported(&h.integrity, h.version, h.integrity.pack_size != 0)
    {
        return None;
    }

    let mut ranges = Ranges {
        map: BTreeMap::new(),
    };
    if !ranges.insert(0, u64::from(h.header_size))
        || !ranges.insert(h.offset_table.offset, h.offset_table.pack_size)
        || !ranges.insert(h.xml.offset, h.xml.pack_size)
        || !ranges.insert(h.integrity.offset, h.integrity.pack_size)
    {
        return None;
    }

    let legacy = u64::from(h.header_size) == HEADER_OLD;
    let entry_size = if legacy { STREAM_INFO_OLD } else { STREAM_INFO };
    let max_table = (MAX_RECORDS + MAX_IMAGES) as u64 * entry_size as u64;
    if h.offset_table.unpack_size == 0
        || h.offset_table.unpack_size > max_table
        || !h.offset_table.unpack_size.is_multiple_of(entry_size as u64)
    {
        return None;
    }
    let table = read_stored_resource(d, &h.offset_table)?;
    if table.is_empty() || table.len() % entry_size != 0 {
        return None;
    }
    let count = table.len() / entry_size;
    if count == 0 || count > MAX_RECORDS + MAX_IMAGES {
        return None;
    }

    let mut streams = Vec::with_capacity(count);
    let mut legacy_ids = HashSet::new();
    let mut modern_hashes = HashSet::new();
    for i in 0..count {
        let off = i * entry_size;
        let packed = rd_u64(&table, off)?;
        let mut s = StreamInfo {
            resource: Resource {
                flags: (packed >> 56) as u8,
                pack_size: packed & 0x00FF_FFFF_FFFF_FFFF,
                offset: rd_u64(&table, off + 8)?,
                unpack_size: rd_u64(&table, off + 16)?,
            },
            ..Default::default()
        };
        if legacy {
            s.part_number = 1;
            s.id = rd_u32(&table, off + 24)?;
            s.ref_count = rd_u32(&table, off + 28)?;
            s.hash = table.get(off + 32..off + 32 + HASH_SIZE)?.to_vec();
        } else {
            s.part_number = rd_u16(&table, off + 24)?;
            s.ref_count = rd_u32(&table, off + 26)?;
            s.hash = table.get(off + 30..off + 30 + HASH_SIZE)?.to_vec();
        }
        let live = s.ref_count != 0;
        if s.hash.len() != HASH_SIZE
            || s.part_number == 0
            || s.part_number > h.number_of_parts
            || !resource_supported(&s.resource, h.version, live)
            || (s.part_number == h.part_number && !resource_extent_valid(&s.resource, size))
        {
            return None;
        }
        let data_stream = s.resource.flags & RES_METADATA == 0;
        if legacy && data_stream {
            if !legacy_ids.insert(s.id) {
                return None;
            }
            if live && s.id == 0 {
                return None;
            }
        }
        if !legacy
            && data_stream
            && (is_empty_hash(&s.hash) || !modern_hashes.insert(s.hash.clone()))
        {
            return None;
        }
        let deleted_metadata = !data_stream && !live;
        let dead_solid = !live && h.version == 0x0000_0E00 && s.resource.flags & RES_SOLID != 0;
        if s.part_number == h.part_number
            && !deleted_metadata
            && !dead_solid
            && !ranges.insert(s.resource.offset, s.resource.pack_size)
        {
            return None;
        }
        streams.push(s);
    }
    if streams.is_empty() {
        return None;
    }
    Some(streams)
}

/// `isWimUtf16LEValid`.
fn utf16_valid(d: &[u8], off: usize, size: usize) -> bool {
    if size & 1 != 0 || off > d.len().saturating_sub(size) {
        return false;
    }
    let mut i = 0;
    while i < size {
        let unit = rd_u16(d, off + i).unwrap_or(0);
        if unit == 0 {
            return false;
        }
        if (0xD800..=0xDBFF).contains(&unit) {
            if i + 4 > size {
                return false;
            }
            let low = rd_u16(d, off + i + 2).unwrap_or(0);
            if !(0xDC00..=0xDFFF).contains(&low) {
                return false;
            }
            i += 4;
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            return false;
        } else {
            i += 2;
        }
    }
    true
}

fn read_utf16(d: &[u8], off: usize, size: usize) -> String {
    if size == 0 || size & 1 != 0 || off > d.len().saturating_sub(size) {
        return String::new();
    }
    let units: Vec<u16> = (0..size / 2)
        .map(|i| rd_u16(d, off + i * 2).unwrap_or(0xFFFD))
        .collect();
    String::from_utf16_lossy(&units)
}

/// `winFileTimeToQDateTime` -> `YYYY-MM-DD HH:MM:SS` (UTC), `None`
/// when the FILETIME is zero or predates the Unix epoch.
fn filetime_to_string(ft: u64) -> Option<String> {
    const EPOCH_DELTA: u64 = 116_444_736_000_000_000;
    if ft < EPOCH_DELTA {
        return None;
    }
    let secs = (ft - EPOCH_DELTA) / 10_000_000;
    if secs > i64::MAX as u64 {
        return None;
    }
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    // Howard Hinnant's civil-from-days algorithm (epoch 1970-01-01).
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let dy = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    Some(format!("{y:04}-{mo:02}-{dy:02} {h:02}:{m:02}:{s:02}"))
}

#[derive(Clone)]
struct Record {
    name: String,
    is_folder: bool,
    stream_offset: u64,
    stream_size: u64,
    uncompressed_size: u64,
    resource: Resource,
    hash: Vec<u8>,
    stream_id: u32,
    method: u32,
    mtime: Option<String>,
    valid: bool,
}

impl Record {
    /// A store-method record with no stream reference (upstream zero
    /// init plus `handleMethod = HANDLE_METHOD_STORE`).
    fn empty() -> Self {
        Self {
            name: String::new(),
            is_folder: false,
            stream_offset: 0,
            stream_size: 0,
            uncompressed_size: 0,
            resource: Resource::default(),
            hash: Vec::new(),
            stream_id: 0,
            method: 1, // HANDLE_METHOD_STORE
            mtime: None,
            valid: false,
        }
    }
}

impl Default for Record {
    fn default() -> Self {
        Self::empty()
    }
}

struct MetaCtx<'a> {
    meta: &'a [u8],
    legacy: bool,
    align: u64,
    dir_entry: usize,
    dir_start: usize,
    by_hash: &'a HashMap<Vec<u8>, StreamInfo>,
    by_id: &'a HashMap<u32, StreamInfo>,
    hash_refs: HashMap<Vec<u8>, u64>,
    id_refs: HashMap<u32, u64>,
    records: Vec<Record>,
    reserved: Vec<(u64, u64)>,
}

impl MetaCtx<'_> {
    /// `_reserveMetadataRange`: byte ranges may not be parsed twice.
    fn reserve(&mut self, off: u64, size: u64, meta_size: usize) -> bool {
        if size == 0 || off.checked_add(size).is_none() || off + size > meta_size as u64 {
            return false;
        }
        for &(s, e) in &self.reserved {
            if off < e && off + size > s {
                return false;
            }
        }
        self.reserved.push((off, off + size));
        true
    }

    /// `_applyStreamInfo`.
    fn apply_stream(&self, s: &StreamInfo, r: &mut Record) -> bool {
        r.stream_offset = s.resource.offset;
        r.stream_size = s.resource.pack_size;
        r.uncompressed_size = s.resource.unpack_size;
        r.resource = s.resource;
        r.hash = s.hash.clone();
        r.stream_id = s.id;
        r.method = if resource_stored(&s.resource) { 1 } else { 0 };
        true
    }

    /// `_applyStreamReference`.
    fn apply_ref(&self, hash: &[u8], id: u32, r: &mut Record) -> bool {
        if self.legacy {
            if id == 0 {
                return true;
            }
            let Some(s) = self.by_id.get(&id) else {
                return false;
            };
            return self.apply_stream(s, r);
        }
        if hash.len() != HASH_SIZE {
            return false;
        }
        if is_empty_hash(hash) {
            return true;
        }
        let Some(s) = self.by_hash.get(hash) else {
            return false;
        };
        self.apply_stream(s, r)
    }

    /// `_countStreamReference`.
    fn count_ref(&mut self, r: &Record) {
        if self.legacy {
            if r.stream_id != 0 {
                *self.id_refs.entry(r.stream_id).or_default() += 1;
            }
        } else if !is_empty_hash(&r.hash) {
            *self.hash_refs.entry(r.hash.clone()).or_default() += 1;
        }
    }

    /// `_createRecordFromMetadataItem`.
    fn record_from_item(&self, off: usize, parent: &str) -> Record {
        let mut r = Record::default();
        let attrs = rd_u32(self.meta, off + 8).unwrap_or(0);
        let name_size = rd_u16(self.meta, off + self.dir_entry - 2).unwrap_or(0) as usize;
        let mut name = read_utf16(self.meta, off + self.dir_entry, name_size);
        name = name.replace(['/', '\\'], "_");
        if name == "." || name == ".." {
            return r;
        }
        r.name = if !name.is_empty() {
            if parent.is_empty() {
                name
            } else {
                format!("{parent}/{name}")
            }
        } else {
            parent.to_string()
        };
        if r.name.len() > MAX_PATH {
            return r;
        }
        r.is_folder = attrs & 0x10 != 0;
        r.method = 1;
        let ft_off = off + if self.legacy { 0x28 } else { 0x38 };
        r.mtime = filetime_to_string(rd_u64(self.meta, ft_off).unwrap_or(0));
        if self.legacy {
            r.valid = r.is_folder
                || self.apply_ref(&[], rd_u32(self.meta, off + 0x10).unwrap_or(0), &mut r);
        } else {
            let hash = self
                .meta
                .get(off + 0x40..off + 0x40 + HASH_SIZE)
                .unwrap_or(&[]);
            r.valid = self.apply_ref(hash, 0, &mut r);
        }
        r
    }

    /// `_parseMetadataDir`.
    fn parse_dir(&mut self, offset: usize, parent: &str, depth: usize) -> bool {
        if depth > MAX_DEPTH || parent.len() > MAX_PATH {
            return false;
        }
        let align = self.align;
        let de = self.dir_entry;
        if offset < self.dir_start
            || offset as u64 & (align - 1) != 0
            || offset > self.meta.len().saturating_sub(8)
        {
            return false;
        }
        let mut cur = offset;
        while cur >= self.dir_start {
            if cur > self.meta.len().saturating_sub(8) {
                return false;
            }
            let length = match rd_u64(self.meta, cur) {
                Some(v) => v,
                None => return false,
            };
            if length == 0 {
                return self.reserve(cur as u64, 8, self.meta.len());
            }
            if length & (align - 1) != 0
                || length < de as u64
                || length > (self.meta.len() - cur) as u64
                || !self.reserve(cur as u64, length, self.meta.len())
            {
                return false;
            }
            let base = cur;
            let alt_streams = rd_u16(self.meta, base + de - 6).unwrap_or(0);
            let short_size = rd_u16(self.meta, base + de - 4).unwrap_or(0);
            let name_size = rd_u16(self.meta, base + de - 2).unwrap_or(0);
            if short_size & 1 != 0 || name_size & 1 != 0 {
                return false;
            }
            let short_with_term = if short_size != 0 {
                short_size as u64 + 2
            } else {
                0
            };
            let name_with_term = if name_size != 0 {
                name_size as u64 + 2
            } else {
                0
            };
            if (de as u64 + name_with_term + short_with_term + align - 1) & !(align - 1) > length {
                return false;
            }
            let name_off = base + de;
            let short_off = name_off + name_with_term as usize;
            if !utf16_valid(self.meta, name_off, name_size as usize)
                || rd_u16(self.meta, name_off + name_size as usize) != Some(0)
                || (short_size != 0
                    && (!utf16_valid(self.meta, short_off, short_size as usize)
                        || rd_u16(self.meta, short_off + short_size as usize) != Some(0)))
            {
                return false;
            }

            let mut record = self.record_from_item(base, parent);
            let legacy_main_may_follow = self.legacy && !record.is_folder && alt_streams != 0;
            if (!record.valid && !legacy_main_may_follow)
                || (record.name.is_empty() && !record.is_folder)
            {
                return false;
            }

            let attrs = rd_u32(self.meta, base + 8).unwrap_or(0);
            let main_hash = if self.legacy {
                Vec::new()
            } else {
                self.meta
                    .get(base + 0x40..base + 0x40 + HASH_SIZE)
                    .unwrap_or(&[])
                    .to_vec()
            };
            let main_id = if self.legacy && !record.is_folder {
                rd_u32(self.meta, base + 0x10).unwrap_or(0)
            } else {
                0
            };
            let mut main_ref_empty = if self.legacy {
                main_id == 0
            } else {
                is_empty_hash(&main_hash)
            };

            let subdir = rd_u64(self.meta, base + 0x10).unwrap_or(0);
            if self.legacy && !record.is_folder && rd_u32(self.meta, base + 0x14) != Some(0) {
                return false;
            }
            if subdir > i64::MAX as u64 {
                return false;
            }
            if !self.legacy && !record.is_folder && subdir != 0 {
                return false;
            }

            let mut alt_records = Vec::new();
            let mut alt_names = HashSet::new();
            let mut next = base + length as usize;

            for i in 0..alt_streams {
                if next > self.meta.len().saturating_sub(8) {
                    return false;
                }
                let alt_len = match rd_u64(self.meta, next) {
                    Some(v) => v,
                    None => return false,
                };
                let alt_min = if self.legacy { 0x18 } else { 0x28 };
                if alt_len & (align - 1) != 0
                    || alt_len < alt_min
                    || alt_len > (self.meta.len() - next) as u64
                    || !self.reserve(next as u64, alt_len, self.meta.len())
                {
                    return false;
                }
                let alt_id = if self.legacy {
                    rd_u32(self.meta, next + 8).unwrap_or(0)
                } else {
                    0
                };
                if self.legacy {
                    if rd_u32(self.meta, next + 0x0C) != Some(0) {
                        return false;
                    }
                } else if rd_u64(self.meta, next + 8) != Some(0) {
                    return false;
                }
                let alt_hash = if self.legacy {
                    Vec::new()
                } else {
                    self.meta
                        .get(next + 0x10..next + 0x10 + HASH_SIZE)
                        .unwrap_or(&[])
                        .to_vec()
                };
                let alt_name_len_off = next + if self.legacy { 0x10 } else { 0x24 };
                let alt_name_size = rd_u16(self.meta, alt_name_len_off).unwrap_or(0) as usize;
                let alt_name_off = alt_name_len_off + 2;
                if alt_name_size & 1 != 0
                    || ((alt_name_off - next) as u64 + alt_name_size as u64 + 2 + align - 1)
                        & !(align - 1)
                        > alt_len
                    || !utf16_valid(self.meta, alt_name_off, alt_name_size)
                    || rd_u16(self.meta, alt_name_off + alt_name_size) != Some(0)
                {
                    return false;
                }
                let mut alt_name = read_utf16(self.meta, alt_name_off, alt_name_size);
                alt_name = alt_name.replace(['/', '\\'], "_");
                if alt_name == "." || alt_name == ".." {
                    return false;
                }

                let represents_main = alt_name.is_empty()
                    && (self.legacy || main_ref_empty)
                    && (attrs & 0x400 != 0 || !record.is_folder);
                if represents_main {
                    if self.legacy && alt_id == 0 {
                        record.stream_offset = 0;
                        record.stream_size = 0;
                        record.uncompressed_size = 0;
                        record.resource = Resource::default();
                        record.hash.clear();
                        record.stream_id = 0;
                        record.method = 1;
                    }
                    if !self.apply_ref(&alt_hash, alt_id, &mut record) {
                        return false;
                    }
                    record.valid = true;
                    if !self.legacy {
                        main_ref_empty = is_empty_hash(&alt_hash);
                    }
                } else {
                    if record.name.is_empty() {
                        return false;
                    }
                    if alt_name.is_empty() {
                        alt_name = format!("unnamed_{i}");
                    }
                    if !alt_names.insert(alt_name.clone()) {
                        return false;
                    }
                    let mut alt_rec = Record {
                        name: format!("{}.__streams__/{}", record.name, alt_name),
                        method: 1,
                        mtime: record.mtime.clone(),
                        ..Default::default()
                    };
                    if !self.apply_ref(&alt_hash, alt_id, &mut alt_rec) {
                        return false;
                    }
                    alt_rec.valid = true;
                    alt_records.push(alt_rec);
                }
                next += alt_len as usize;
            }

            if !record.valid {
                return false;
            }
            self.count_ref(&record);
            let mut alt_list = Vec::new();
            for a in &alt_records {
                self.count_ref(a);
                alt_list.push(a.clone());
            }

            // Some old DISM/Longhorn images put otherwise hidden root
            // entries directly after the empty root terminator while
            // pointing SubdirOffset past them (upstream correction).
            let mut subdir_off = subdir as usize;
            if depth == 0
                && cur == offset
                && record.is_folder
                && short_size == 0
                && name_size == 0
                && subdir != 0
                && next <= self.meta.len().saturating_sub(16)
                && rd_u64(self.meta, next) == Some(0)
                && rd_u64(self.meta, next + 8) != Some(0)
                && next + 8 < subdir_off
            {
                subdir_off = next + 8;
            }

            if self.records.len() + alt_list.len() + usize::from(!record.name.is_empty())
                > MAX_RECORDS
            {
                return false;
            }
            if !record.name.is_empty() {
                self.records.push(record.clone());
            }
            self.records.append(&mut alt_list);

            if record.is_folder && subdir_off != 0 {
                let child_parent = if record.name.is_empty() {
                    parent.to_string()
                } else {
                    record.name.clone()
                };
                if subdir_off < self.dir_start
                    || subdir_off as u64 & (align - 1) != 0
                    || subdir_off > self.meta.len().saturating_sub(8)
                    || !self.parse_dir(subdir_off, &child_parent, depth + 1)
                {
                    return false;
                }
            }
            cur = next;
        }
        true
    }
}

/// `_parseMetadata`.
type RefCounts = (HashMap<Vec<u8>, u64>, HashMap<u32, u64>);

fn parse_metadata(
    meta: &[u8],
    h: &Header,
    by_hash: &HashMap<Vec<u8>, StreamInfo>,
    by_id: &HashMap<u32, StreamInfo>,
) -> Option<(Vec<Record>, RefCounts)> {
    if meta.len() < 8 {
        return None;
    }
    let legacy = u64::from(h.header_size) == HEADER_OLD;
    let align: u64 = if h.version == 0x0001_0900 { 4 } else { 8 };
    let mut dir_offset = 8usize;
    let total_len = rd_u32(meta, 0)? as usize;
    if legacy {
        let n_sec = rd_u32(meta, 4)?;
        if n_sec > 1 << 28 || n_sec as usize > meta.len() >> 3 {
            return None;
        }
        let mut sec_end = if n_sec != 0 { n_sec as usize * 8 } else { 8 };
        if sec_end > meta.len() {
            return None;
        }
        for i in 0..n_sec as usize {
            let eoff = i * 8;
            let sec_size = rd_u32(meta, eoff)? as usize;
            if i != 0 && rd_u32(meta, eoff + 4) != Some(0) {
                return None;
            }
            if sec_size > meta.len() - sec_end {
                return None;
            }
            sec_end += sec_size;
        }
        dir_offset = (sec_end as u64 + (align - 1)) as usize & !(align as usize - 1);
    } else if total_len != 0 {
        if total_len < 8 || total_len > meta.len() {
            return None;
        }
        let n_sec = rd_u32(meta, 4)? as usize;
        if n_sec > (total_len - 8) >> 3 {
            return None;
        }
        let mut sec_end = 8usize + n_sec * 8;
        let mut eoff = 8usize;
        for _ in 0..n_sec {
            let sec_size = rd_u64(meta, eoff)? as usize;
            if sec_size > total_len - sec_end {
                return None;
            }
            sec_end += sec_size;
            eoff += 8;
        }
        if (sec_end + 7) & !7 != (total_len + 7) & !7 {
            return None;
        }
        dir_offset = (sec_end + 7) & !7;
    }
    if dir_offset < 8 || dir_offset > meta.len().saturating_sub(8) {
        return None;
    }
    let mut ctx = MetaCtx {
        meta,
        legacy,
        align,
        dir_entry: if legacy { DIR_ENTRY_OLD } else { DIR_ENTRY },
        dir_start: dir_offset,
        by_hash,
        by_id,
        hash_refs: HashMap::new(),
        id_refs: HashMap::new(),
        records: Vec::new(),
        reserved: Vec::new(),
    };
    if !ctx.parse_dir(dir_offset, "", 0) {
        return None;
    }
    Some((ctx.records, (ctx.hash_refs, ctx.id_refs)))
}

fn sha1(d: &[u8]) -> Vec<u8> {
    use sha1::Digest;
    sha1::Sha1::digest(d).to_vec()
}

/// Parsed image context shared by `list` and `extract`.
struct Collected {
    flags: u32,
    chunk_size: u32,
    legacy: bool,
    /// Image index of the first record when a multi-image prefix is used.
    first_image: u32,
    images: Vec<Vec<Record>>,
}

/// `initUnpack` enumeration: header checks -> stream list -> metadata
/// parse + SHA-1 verify -> refcount reconciliation -> image list.
fn collect(d: &[u8]) -> Option<Collected> {
    if !is_wim(d) {
        return None;
    }
    let h = read_header(d)?;
    if h.part_number != 1 || h.number_of_parts != 1 {
        return None;
    }
    if !compression_config_valid(h.flags, h.chunk_size, true) {
        return None;
    }
    let streams = read_stream_list(d, &h)?;
    let legacy = u64::from(h.header_size) == HEADER_OLD;
    let mut by_hash: HashMap<Vec<u8>, StreamInfo> = HashMap::new();
    let mut by_id: HashMap<u32, StreamInfo> = HashMap::new();
    for s in &streams {
        if s.ref_count != 0 && s.resource.flags & RES_SOLID != 0 {
            return None;
        }
        if s.resource.flags & RES_METADATA != 0 || s.ref_count == 0 {
            continue;
        }
        if legacy {
            if s.id == 0 || s.hash.len() != HASH_SIZE || by_id.contains_key(&s.id) {
                return None;
            }
            by_id.insert(s.id, s.clone());
        } else {
            if is_empty_hash(&s.hash) || by_hash.contains_key(&s.hash) {
                return None;
            }
            by_hash.insert(s.hash.clone(), s.clone());
        }
    }

    let mut images: Vec<Vec<Record>> = Vec::new();
    let mut live_metadata: Vec<Resource> = Vec::new();
    let mut hash_refs: HashMap<Vec<u8>, u64> = HashMap::new();
    let mut id_refs: HashMap<u32, u64> = HashMap::new();
    let mut pending = 0usize;

    for s in &streams {
        if s.resource.flags & RES_METADATA == 0 {
            continue;
        }
        if s.ref_count == 0 {
            continue;
        }
        if s.ref_count != 1 || images.len() >= MAX_IMAGES {
            return None;
        }
        let blob = read_resource_data(d, &s.resource, &h)?;
        if blob.is_empty() {
            return None;
        }
        let digest_matches = s.hash.len() == HASH_SIZE && sha1(&blob) == s.hash;
        if !(digest_matches || legacy && is_empty_hash(&s.hash)) {
            return None;
        }
        let (records, (hr, ir)) = parse_metadata(&blob, &h, &by_hash, &by_id)?;
        for (k, v) in hr {
            *hash_refs.entry(k).or_default() += v;
        }
        for (k, v) in ir {
            *id_refs.entry(k).or_default() += v;
        }
        let mut names = HashSet::new();
        for r in &records {
            if r.name.is_empty() || !names.insert(r.name.clone()) {
                return None;
            }
        }
        if records.len() > MAX_RECORDS - pending {
            return None;
        }
        pending += records.len();
        images.push(records);
        live_metadata.push(s.resource);
    }

    let has_image_count = h.version == 0x0000_0E00 || h.version >= 0x0001_0D00;
    if has_image_count
        && (h.number_of_images == 0
            || h.number_of_images as usize > MAX_IMAGES
            || h.number_of_images as usize != images.len())
    {
        return None;
    }
    if h.boot_metadata.unpack_size == 0 {
        if h.boot_metadata.pack_size != 0 || (has_image_count && h.boot_index != 0) {
            return None;
        }
    } else {
        let mut boot_image: i64 = -1;
        for (i, r) in live_metadata.iter().enumerate() {
            if *r == h.boot_metadata {
                if boot_image != -1 {
                    return None;
                }
                boot_image = i as i64;
            }
        }
        if boot_image < 0 || (has_image_count && h.boot_index != (boot_image + 1) as u32) {
            return None;
        }
    }
    for s in &streams {
        if s.resource.flags & RES_METADATA != 0 {
            continue;
        }
        let actual = if legacy {
            id_refs.get(&s.id).copied().unwrap_or(0)
        } else {
            hash_refs.get(&s.hash).copied().unwrap_or(0)
        };
        if actual != u64::from(s.ref_count) {
            return None;
        }
    }
    if images.is_empty() {
        return None;
    }

    let first_image = if h.version == 0x0001_0900 { 0 } else { 1 };
    Some(Collected {
        flags: h.flags,
        chunk_size: h.chunk_size,
        legacy,
        first_image,
        images,
    })
}

/// `initUnpack` enumeration plus `SecondaryRecord` projection.
pub fn list(d: &[u8]) -> Option<Vec<SecondaryRecord>> {
    let c = collect(d)?;
    // Upstream HANDLE_METHOD values: LZX=69, XPRESS_HUFF=71.
    let compressed_method: u32 = {
        if c.flags & FLAG_COMPRESSION == 0 {
            0
        } else if c.flags & FLAG_LZX != 0 {
            69
        } else if c.flags & (FLAG_XPRESS | FLAG_XPRESS2) != 0 {
            71
        } else {
            0
        }
    };

    let use_prefix = c.images.len() > 1;
    let mut out = Vec::new();
    let mut final_names = HashSet::new();
    for (i, records) in c.images.iter().enumerate() {
        let prefix = if use_prefix {
            format!("image_{}/", c.first_image + i as u32)
        } else {
            String::new()
        };
        for r in records {
            let mut r = r.clone();
            r.name = format!("{prefix}{}", r.name);
            if r.method == 0
                && r.resource.flags & RES_COMPRESSED != 0
                && r.resource.flags & RES_SOLID == 0
            {
                r.method = compressed_method;
            }
            if r.name.len() > MAX_PATH
                || !final_names.insert(r.name.clone())
                || out.len() >= MAX_RECORDS
            {
                return None;
            }
            out.push(SecondaryRecord {
                name: r.name,
                size: r.uncompressed_size,
                packed_size: r.stream_size,
                is_directory: r.is_folder,
                modified: r.mtime,
                data_offset: r.stream_offset,
                method: r.method,
                window_size: r.resource.unpack_size,
            });
        }
    }
    Some(out)
}

/// `_stageResource` + the digest check from `unpackCurrent`: stage the
/// record's resource (stored or chunked-compressed), verify SHA-1 when
/// the digest is required, and return the uncompressed bytes.
pub fn extract(d: &[u8], name: &str) -> Vec<u8> {
    let Some(c) = collect(d) else {
        return Vec::new();
    };
    let use_prefix = c.images.len() > 1;
    let mut target: Option<&Record> = None;
    for (i, records) in c.images.iter().enumerate() {
        let prefix = if use_prefix {
            format!("image_{}/", c.first_image + i as u32)
        } else {
            String::new()
        };
        for r in records {
            let full = format!("{prefix}{}", r.name);
            if full == name {
                target = Some(r);
                break;
            }
        }
        if target.is_some() {
            break;
        }
    }
    let Some(r) = target else {
        return Vec::new();
    };
    if r.is_folder
        || r.uncompressed_size == 0
        || r.uncompressed_size != r.resource.unpack_size
        || r.hash.len() != HASH_SIZE
        || (!c.legacy && is_empty_hash(&r.hash))
        || !resource_extent_valid(&r.resource, d.len() as u64)
    {
        return Vec::new();
    }

    let staged = if resource_stored(&r.resource) {
        read_stored_resource(d, &r.resource)
    } else if r.resource.flags & RES_COMPRESSED != 0 && r.resource.flags & RES_SOLID == 0 {
        let chunk = match effective_chunk_size(c.chunk_size) {
            Some(v) => v,
            None => return Vec::new(),
        };
        let Some(compression) = compression_type(c.flags) else {
            return Vec::new();
        };
        wim_decode::stage_chunked_resource(
            d,
            r.resource.offset,
            r.resource.pack_size,
            r.resource.unpack_size,
            compression,
            chunk,
        )
    } else {
        None
    };
    let Some(out) = staged else {
        return Vec::new();
    };

    // `bDigestRequired && baDigest != record.baHash` in `unpackCurrent`.
    let digest_required = !(c.legacy && is_empty_hash(&r.hash));
    if digest_required && sha1(&out) != r.hash {
        return Vec::new();
    }
    if out.len() as u64 != r.uncompressed_size {
        return Vec::new();
    }
    out
}

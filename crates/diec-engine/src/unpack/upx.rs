//! UPX detection and static unpacking, aligned with upstream DIE's
//! `XStaticUnpacker` (`xupx.cpp`): pack-header parsing, NRV/LZMA/DEFLATE
//! decompression and the in-process PE rebuild performed by
//! `XUPX::_unpackPE`. ELF/Mach/DOS containers are detected but their
//! reconstruction is not implemented yet.
//!
//! All input is untrusted: every offset, length and index is bounds-checked;
//! decompressed and rebuilt sizes are capped at `MAX_OUTPUT_SIZE`.

use super::nrv::{BitWidth, NrvAlgorithm, NrvError, nrv_decompress};
use std::collections::HashSet;

/// Maximum bytes scanned for the `UPX!` magic (`XUPX_HEADER_SEARCH_SIZE`).
const HEADER_SEARCH_SIZE: usize = 0x1000;
/// Bytes read at the magic position (`XUPX_PACK_HEADER_SIZE`).
const PACK_HEADER_SIZE: usize = 36;
/// Minimum plausible pack header (`XUPX_MIN_PACK_HEADER_SIZE`).
const MIN_PACK_HEADER_SIZE: usize = 20;
/// Output cap for decompression/rebuild; mirrors the GUI output budget.
const MAX_OUTPUT_SIZE: usize = 512 * 1024 * 1024;
/// Upper bound for PE sections accepted from the packed stream.
const MAX_SECTIONS: usize = 96;
/// Upper bound for decoded base-relocation records.
const MAX_RELOCS: usize = 1_000_000;
/// Upper bound for resource leaf records.
const MAX_RESOURCES: usize = 10_000;

// UPX method ids (p_com.h / xupx.h).
const M_NRV2B_LE32: u8 = 2;
const M_NRV2B_8: u8 = 3;
const M_NRV2B_LE16: u8 = 4;
const M_NRV2D_LE32: u8 = 5;
const M_NRV2D_8: u8 = 6;
const M_NRV2D_LE16: u8 = 7;
const M_NRV2E_LE32: u8 = 8;
const M_NRV2E_8: u8 = 9;
const M_NRV2E_LE16: u8 = 10;
const M_LZMA: u8 = 14;
const M_DEFLATE: u8 = 15;

// UPX format ids.
const UPX_F_DOS_COM: u8 = 2;
const UPX_F_DOS_SYS: u8 = 3;
const UPX_F_DOS_EXE: u8 = 4;
const UPX_F_DOS_EXEH: u8 = 5;
const UPX_F_W32PE_I386: u8 = 9;
const UPX_F_W64PE_AMD64: u8 = 36;

// PE directory indices.
const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_RESOURCE: usize = 2;
const DIR_BASERELOC: usize = 5;
const DIR_DEBUG: usize = 6;
const DIR_BOUND_IMPORT: usize = 11;

const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
const RT_GROUP_ICON: u32 = 14;

const NT_HEADERS32_SIZE: usize = 248;
const NT_HEADERS64_SIZE: usize = 264;
const SECTION_HEADER_SIZE: usize = 40;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const DOS_HEADER_SIZE: usize = 64;

/// Decoded UPX pack header plus stream positions (`XUPX::INTERNAL_INFO`).
#[derive(Clone, Debug)]
pub struct UpxInfo {
    /// UPX version field.
    pub version: u8,
    /// Container format id (`UPX_F_*`).
    pub format: u8,
    /// Compression method id (`UPX_M_*`).
    pub method: u8,
    /// Compression level (low nibble).
    pub level: u8,
    /// Applied input filter id, 0 when none.
    pub filter: u8,
    /// Filter calltrick offset byte.
    pub filter_cto: u8,
    /// Uncompressed payload size.
    pub u_len: u32,
    /// Compressed payload size.
    pub c_len: u32,
    /// Adler32 of the uncompressed payload.
    pub u_adler: u32,
    /// Adler32 of the compressed payload.
    pub c_adler: u32,
    /// Original file size recorded by the packer.
    pub u_file_size: u32,
    /// MRU flag decoded from the header.
    pub n_mru: u8,
    /// Byte size of the pack header itself.
    pub pack_header_size: u32,
    /// File offset of the `UPX!` magic.
    pub header_offset: usize,
    /// File offset of the compressed stream.
    pub data_offset: usize,
}

impl UpxInfo {
    /// Human readable method name matching upstream `upxMethodToString`.
    pub fn method_name(&self) -> String {
        match self.method {
            M_NRV2B_LE32 => "NRV2B_LE32".into(),
            M_NRV2B_8 => "NRV2B_8".into(),
            M_NRV2B_LE16 => "NRV2B_LE16".into(),
            M_NRV2D_LE32 => "NRV2D_LE32".into(),
            M_NRV2D_8 => "NRV2D_8".into(),
            M_NRV2D_LE16 => "NRV2D_LE16".into(),
            M_NRV2E_LE32 => "NRV2E_LE32".into(),
            M_NRV2E_8 => "NRV2E_8".into(),
            M_NRV2E_LE16 => "NRV2E_LE16".into(),
            M_LZMA => "LZMA".into(),
            M_DEFLATE => "DEFLATE".into(),
            other => format!("Unknown ({other})"),
        }
    }
}

/// Errors surfaced by UPX detection/unpacking.
#[derive(Debug)]
pub enum UnpackError {
    /// No valid `UPX!` pack header was found.
    NotPacked,
    /// Detected container/method combination is not implemented.
    Unsupported(&'static str),
    /// Input is malformed; carries a static description.
    Malformed(&'static str),
    /// Compression layer failure.
    Decompress(String),
}

impl core::fmt::Display for UnpackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotPacked => f.write_str("not packed with a supported packer"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
            Self::Malformed(s) => write!(f, "malformed input: {s}"),
            Self::Decompress(s) => write!(f, "decompression failed: {s}"),
        }
    }
}

impl std::error::Error for UnpackError {}

impl From<NrvError> for UnpackError {
    fn from(e: NrvError) -> Self {
        Self::Decompress(e.to_string())
    }
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u24(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 3)
        .map(|b| b[0] as u32 | (b[1] as u32) << 8 | (b[2] as u32) << 16)
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    if let Some(b) = buf.get_mut(off..off + 4) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}

fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    if let Some(b) = buf.get_mut(off..off + 8) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}

fn write_bytes(buf: &mut [u8], off: usize, bytes: &[u8]) -> bool {
    match buf.get_mut(off..off + bytes.len()) {
        Some(dst) if dst.len() == bytes.len() => {
            dst.copy_from_slice(bytes);
            true
        }
        _ => false,
    }
}

fn cstrlen(buf: &[u8]) -> usize {
    buf.iter().position(|&b| b == 0).unwrap_or(buf.len())
}

fn align_up(v: u64, a: u64) -> u64 {
    if a <= 1 {
        return v;
    }
    (v + a - 1) & !(a - 1)
}

/// Parses a pack header starting at `buf[0]` (`UPX!` must already match),
/// mirroring `XUPX::_read_packheader` including the version-dependent field
/// layout and the pre-v10 filter reconstruction.
fn parse_pack_header(buf: &[u8]) -> Option<UpxInfo> {
    if buf.len() < 16 || &buf[0..4] != b"UPX!" {
        return None;
    }
    let version = buf[4];
    let format = buf[5];
    let method = buf[6];
    let mut level = buf[7];

    let mut info = UpxInfo {
        version,
        format,
        method,
        level,
        filter: 0,
        filter_cto: 0,
        u_len: 0,
        c_len: 0,
        u_adler: 0,
        c_adler: 0,
        u_file_size: 0,
        n_mru: 0,
        pack_header_size: 0,
        header_offset: 0,
        data_offset: 0,
    };

    let off_filter;
    if format < 128 {
        info.u_adler = read_u32(buf, 8)?;
        info.c_adler = read_u32(buf, 12)?;
        if format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS {
            if buf.len() < 21 {
                return None;
            }
            info.u_len = read_u16(buf, 16)? as u32;
            info.c_len = read_u16(buf, 18)? as u32;
            info.u_file_size = info.u_len;
            off_filter = 20;
        } else if format == UPX_F_DOS_EXE || format == UPX_F_DOS_EXEH {
            if buf.len() < 26 {
                return None;
            }
            info.u_len = read_u24(buf, 16)?;
            info.c_len = read_u24(buf, 19)?;
            info.u_file_size = read_u24(buf, 22)?;
            off_filter = 25;
        } else {
            if buf.len() < 32 {
                return None;
            }
            info.u_len = read_u32(buf, 16)?;
            info.c_len = read_u32(buf, 20)?;
            info.u_file_size = read_u32(buf, 24)?;
            off_filter = 28;
            info.filter_cto = buf[29];
            info.n_mru = if buf[30] != 0 { 1 + buf[30] } else { 0 };
        }
    } else {
        if buf.len() < 32 {
            return None;
        }
        info.u_len = read_u32(buf, 8)?;
        info.c_len = read_u32(buf, 12)?;
        info.u_adler = read_u32(buf, 16)?;
        info.c_adler = read_u32(buf, 20)?;
        info.u_file_size = read_u32(buf, 24)?;
        off_filter = 28;
        info.filter_cto = buf[29];
        info.n_mru = if buf[30] != 0 { 1 + buf[30] } else { 0 };
    }

    info.pack_header_size = if version <= 3 {
        24
    } else if version <= 9 {
        match format {
            UPX_F_DOS_COM | UPX_F_DOS_SYS => 20,
            UPX_F_DOS_EXE | UPX_F_DOS_EXEH => 25,
            _ => 28,
        }
    } else {
        match format {
            UPX_F_DOS_COM | UPX_F_DOS_SYS => 22,
            UPX_F_DOS_EXE | UPX_F_DOS_EXEH => 27,
            _ => 32,
        }
    };

    // Pre-v10 headers have no filter byte; the filter flag rides on bit 7 of
    // `level` and the id is implied by the format (upstream comment).
    if version >= 10 {
        info.filter = *buf.get(off_filter)?;
    } else if level & 128 == 0 {
        info.filter = 0;
    } else {
        level &= 127;
        info.filter = if format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS {
            0x06
        } else {
            0x26
        };
    }
    info.level = level & 15;

    Some(info)
}

fn method_supported(method: u8) -> bool {
    matches!(
        method,
        M_NRV2B_LE32
            | M_NRV2B_8
            | M_NRV2B_LE16
            | M_NRV2D_LE32
            | M_NRV2D_8
            | M_NRV2D_LE16
            | M_NRV2E_LE32
            | M_NRV2E_8
            | M_NRV2E_LE16
            | M_LZMA
            | M_DEFLATE
    )
}

/// Minimal PE validity check (MZ + PE signature) used by detection.
fn is_pe(data: &[u8]) -> bool {
    if data.len() < 2 || &data[0..2] != b"MZ" {
        return false;
    }
    let Some(e_lfanew) = read_u32(data, 0x3c) else {
        return false;
    };
    let off = e_lfanew as usize;
    matches!(data.get(off..off + 4), Some(b"PE\0\0"))
}

/// Locates and validates the UPX pack header on a PE file, mirroring
/// `XUPX::_detectPEInfo`: `UPX!` search in the first 0x1000 bytes followed by
/// the full header parse and stream bounds validation.
pub fn detect_upx(data: &[u8]) -> Option<UpxInfo> {
    if !is_pe(data) {
        return None;
    }
    let search = HEADER_SEARCH_SIZE.min(data.len());
    if search < MIN_PACK_HEADER_SIZE {
        return None;
    }
    let idx = data[..search].windows(4).position(|w| w == b"UPX!")?;
    let mut info = parse_pack_header(data.get(idx..idx + PACK_HEADER_SIZE)?)?;
    if !method_supported(info.method) || info.u_len == 0 || info.c_len == 0 {
        return None;
    }
    info.header_offset = idx;
    info.data_offset = idx + info.pack_header_size as usize;
    if info.data_offset > data.len() || info.c_len as usize > data.len() - info.data_offset {
        return None;
    }
    // `upxIsDeclaredOriginalSizeSane`: the declared original size (when
    // recorded) must exceed the packed size.
    let original = if info.u_file_size != 0 {
        info.u_file_size
    } else {
        info.u_len
    } as u64;
    if original > 0 && original <= data.len() as u64 {
        return None;
    }
    Some(info)
}

/// Decompresses the UPX payload per `XUPX::_upxDecompress`. Returns the bytes
/// actually produced; callers compare against `u_len` as upstream does.
pub fn decompress_payload(src: &[u8], u_len: usize, method: u8) -> Result<Vec<u8>, UnpackError> {
    if u_len == 0 || u_len > MAX_OUTPUT_SIZE {
        return Err(UnpackError::Malformed("unreasonable uncompressed size"));
    }
    match method {
        M_NRV2B_8 | M_NRV2B_LE16 | M_NRV2B_LE32 | M_NRV2D_8 | M_NRV2D_LE16 | M_NRV2D_LE32
        | M_NRV2E_8 | M_NRV2E_LE16 | M_NRV2E_LE32 => {
            let (algo, width) = match method {
                M_NRV2B_8 => (NrvAlgorithm::B, BitWidth::W8),
                M_NRV2B_LE16 => (NrvAlgorithm::B, BitWidth::Le16),
                M_NRV2B_LE32 => (NrvAlgorithm::B, BitWidth::Le32),
                M_NRV2D_8 => (NrvAlgorithm::D, BitWidth::W8),
                M_NRV2D_LE16 => (NrvAlgorithm::D, BitWidth::Le16),
                M_NRV2D_LE32 => (NrvAlgorithm::D, BitWidth::Le32),
                M_NRV2E_8 => (NrvAlgorithm::E, BitWidth::W8),
                M_NRV2E_LE16 => (NrvAlgorithm::E, BitWidth::Le16),
                M_NRV2E_LE32 => (NrvAlgorithm::E, BitWidth::Le32),
                _ => unreachable!(),
            };
            let mut dst = vec![0u8; u_len];
            let produced = nrv_decompress(src, &mut dst, algo, width)?;
            dst.truncate(produced);
            Ok(dst)
        }
        M_LZMA => decompress_upx_lzma(src, u_len),
        M_DEFLATE => decompress_upx_deflate(src, u_len),
        _ => Err(UnpackError::Unsupported("unknown compression method")),
    }
}

/// UPX stores LZMA parameters as a two-byte prefix. Upstream decodes
/// `pb = src[0]&7`, `lp = src[1]>>4`, `lc = src[1]&0x0f`, validates
/// `src[0]>>3 == lc+lp`, then feeds a raw LZMA stream to `X_LzmaDecode`.
/// Here the stream is wrapped in a synthetic LZMA-Alone header for `lzma-rs`.
fn decompress_upx_lzma(src: &[u8], u_len: usize) -> Result<Vec<u8>, UnpackError> {
    if src.len() < 3 {
        return Err(UnpackError::Malformed("lzma stream too short"));
    }
    let pb = (src[0] & 7) as u32;
    let lp = (src[1] >> 4) as u32;
    let lc = (src[1] & 0x0f) as u32;
    if pb >= 5 || lp >= 5 || lc >= 9 {
        return Err(UnpackError::Malformed("bad lzma parameters"));
    }
    if (src[0] >> 3) != (lc + lp) as u8 {
        return Err(UnpackError::Malformed("lzma header mismatch"));
    }
    let mut alone = Vec::with_capacity(13 + src.len() - 2);
    alone.push(((pb * 5 + lp) * 9 + lc) as u8);
    alone.extend_from_slice(&(u_len.max(1) as u32).to_le_bytes());
    alone.extend_from_slice(&(u_len as u64).to_le_bytes());
    alone.extend_from_slice(&src[2..]);
    let mut out = Vec::with_capacity(u_len);
    let mut cursor = std::io::Cursor::new(alone);
    lzma_rs::lzma_decompress(&mut cursor, &mut out)
        .map_err(|e| UnpackError::Decompress(format!("lzma: {e}")))?;
    if out.len() > u_len {
        out.truncate(u_len);
    }
    Ok(out)
}

/// Raw DEFLATE stream (`inflateInit2(-MAX_WBITS)` in upstream).
fn decompress_upx_deflate(src: &[u8], u_len: usize) -> Result<Vec<u8>, UnpackError> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut dec = Decompress::new(false);
    let mut out = vec![0u8; u_len];
    let status = dec
        .decompress(src, &mut out, FlushDecompress::Finish)
        .map_err(|e| UnpackError::Decompress(format!("deflate: {e}")))?;
    if status != Status::StreamEnd {
        return Err(UnpackError::Decompress(
            "deflate stream not finished".into(),
        ));
    }
    out.truncate(dec.total_out() as usize);
    Ok(out)
}

/// Undoes an UPX input filter on `data` in place, mirroring the unfilter
/// direction of `applyPEFilter` in `xupx.cpp`.
fn apply_pe_filter(
    data: &mut [u8],
    filter: u8,
    filter_cto: u8,
    add_value: u32,
) -> Result<(), UnpackError> {
    if filter == 0 {
        return Ok(());
    }
    let n = data.len();
    if n == 0 {
        return Err(UnpackError::Malformed("empty filter region"));
    }
    if (0x01..=0x06).contains(&filter) {
        // CT16 calltrick: operand at i+1, index counts from the operand base.
        // CT16 calltrick: operand at i+1, index counts from the operand base.
        // Upstream reads per `bBigEndianSource` but always writes LE
        // (`_write_uint16` default) — the swap is part of the unfilter.
        let match_e8 = matches!(filter, 0x01 | 0x03 | 0x04 | 0x06);
        let match_e9 = matches!(filter, 0x02 | 0x03 | 0x05 | 0x06);
        let big_endian_src = filter >= 0x04;
        let mut i = 0usize;
        while i + 3 < n {
            if (match_e8 && data[i] == 0xe8) || (match_e9 && data[i] == 0xe9) {
                let jc = if big_endian_src {
                    u16::from_be_bytes([data[i + 1], data[i + 2]])
                } else {
                    u16::from_le_bytes([data[i + 1], data[i + 2]])
                };
                let v = (jc as u32)
                    .wrapping_sub(i as u32 + 1)
                    .wrapping_sub(add_value) as u16;
                data[i + 1..i + 3].copy_from_slice(&v.to_le_bytes());
                i += 2;
            }
            i += 1;
        }
        return Ok(());
    }

    // 32-bit calltrick family. `want_jcc` matches upstream's
    // `(9 <= (0x0f & nFilter))` term: it is only true for 0x49; for
    // 0x36/0x46 the conditional jump extension is dead code upstream.
    let (want_e9, want_cto, want_jcc) = match filter {
        0x14 => (false, false, false),
        0x16 => (true, false, false),
        0x24 => (false, true, false),
        0x26 => (true, true, false),
        0x36 | 0x46 | 0x49 => (true, true, filter & 0x0f >= 9),
        _ => return Err(UnpackError::Unsupported("unknown PE filter")),
    };
    let cto = (filter_cto as u32) << 24;
    let mut last_call: u32 = 0;
    let mut i = 0usize;
    while i + 5 < n {
        let mut m = data[i] == 0xe8 || (want_e9 && data[i] == 0xe9);
        if !m
            && want_jcc
            && i > 0
            && last_call != i as u32
            && data[i - 1] == 0x0f
            && (0x80..=0x8f).contains(&data[i])
        {
            m = true;
        }
        if m && (!want_cto || data[i + 1] == filter_cto) {
            // Upstream reads the operand big-endian and writes little-endian
            // (`_write_uint32` default) — the bswap is the unfilter itself.
            let jc = u32::from_be_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let v = jc
                .wrapping_sub(i as u32)
                .wrapping_sub(1)
                .wrapping_sub(add_value)
                .wrapping_sub(cto);
            data[i + 1..i + 5].copy_from_slice(&v.to_le_bytes());
            i += 4;
            last_call = i as u32 + 1;
        }
        i += 1;
    }
    Ok(())
}

/// Section header view used for both packed and output images.
#[derive(Clone, Copy)]
pub(crate) struct SectionHead {
    /// Raw 8-byte section name (yoda's name-DWORD skip list).
    pub(crate) name: [u8; 8],
    pub(crate) virtual_size: u32,
    pub(crate) virtual_address: u32,
    pub(crate) raw_size: u32,
    pub(crate) raw_ptr: u32,
}

/// Minimal PE view over the packed file; only what `_unpackPE` consumes.
pub(crate) struct PackedPe<'a> {
    data: &'a [u8],
    pe_offset: usize,
    is64: bool,
    image_base: u64,
    entry_rva: u32,
    sections: Vec<SectionHead>,
    /// (VirtualAddress, Size) for each of the 16 directories.
    dirs: [(u32, u32); 16],
}

impl<'a> PackedPe<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self, UnpackError> {
        if !is_pe(data) {
            return Err(UnpackError::Malformed("not a PE file"));
        }
        let pe_offset = read_u32(data, 0x3c).unwrap_or(0) as usize;
        let coff = pe_offset + 4;
        let number_of_sections =
            read_u16(data, coff + 2).ok_or(UnpackError::Malformed("coff header"))? as usize;
        if number_of_sections > MAX_SECTIONS {
            return Err(UnpackError::Malformed("section count"));
        }
        let opt_size =
            read_u16(data, coff + 16).ok_or(UnpackError::Malformed("opt header"))? as usize;
        let opt = coff + 20;
        let opt_end = opt
            .checked_add(opt_size)
            .ok_or(UnpackError::Malformed("opt header"))?;
        if opt_end > data.len() || opt_size < 96 {
            return Err(UnpackError::Malformed("optional header truncated"));
        }
        let magic = read_u16(data, opt).ok_or(UnpackError::Malformed("opt magic"))?;
        let is64 = match magic {
            0x10b => false,
            0x20b => true,
            _ => return Err(UnpackError::Malformed("bad optional magic")),
        };
        let image_base = if is64 {
            let lo = read_u32(data, opt + 24).unwrap_or(0) as u64;
            let hi = read_u32(data, opt + 28).unwrap_or(0) as u64;
            (hi << 32) | lo
        } else {
            read_u32(data, opt + 28).unwrap_or(0) as u64
        };
        let entry_rva = read_u32(data, opt + 16).unwrap_or(0);
        let dir_base = opt + if is64 { 112 } else { 96 };
        let num_dirs = read_u32(data, opt + if is64 { 108 } else { 92 })
            .unwrap_or(0)
            .min(16) as usize;
        let mut dirs = [(0u32, 0u32); 16];
        for (i, d) in dirs.iter_mut().enumerate().take(num_dirs) {
            *d = (
                read_u32(data, dir_base + i * 8).unwrap_or(0),
                read_u32(data, dir_base + i * 8 + 4).unwrap_or(0),
            );
        }
        let mut sections = Vec::with_capacity(number_of_sections);
        for i in 0..number_of_sections {
            let s = opt_end + i * SECTION_HEADER_SIZE;
            if s + SECTION_HEADER_SIZE > data.len() {
                return Err(UnpackError::Malformed("section table truncated"));
            }
            let mut name = [0u8; 8];
            name.copy_from_slice(&data[s..s + 8]);
            sections.push(SectionHead {
                name,
                virtual_size: read_u32(data, s + 8).unwrap_or(0),
                virtual_address: read_u32(data, s + 12).unwrap_or(0),
                raw_size: read_u32(data, s + 16).unwrap_or(0),
                raw_ptr: read_u32(data, s + 20).unwrap_or(0),
            });
        }
        Ok(Self {
            data,
            pe_offset,
            is64,
            image_base,
            entry_rva,
            sections,
            dirs,
        })
    }

    /// `XPE::getOptionalHeader_AddressOfEntryPoint` (RVA).
    pub(crate) fn entry_rva(&self) -> u32 {
        self.entry_rva
    }

    /// `XPE::getOptionalHeader_ImageBase`.
    pub(crate) fn image_base(&self) -> u64 {
        self.image_base
    }

    /// `XPE::is64` — PE32+ optional-header magic.
    pub(crate) fn is64(&self) -> bool {
        self.is64
    }

    /// `XPE::getSectionHeaders` view used by static unpackers.
    pub(crate) fn sections(&self) -> &[SectionHead] {
        &self.sections
    }

    /// Raw file bytes of the packed image.
    pub(crate) fn data(&self) -> &'a [u8] {
        self.data
    }

    /// `XPE::getOptionalHeader_DataDirectory` — (VirtualAddress, Size).
    pub(crate) fn data_directory(&self, index: usize) -> Option<(u32, u32)> {
        self.dirs.get(index).copied()
    }

    /// Maps an RVA to a file offset within the packed image.
    pub(crate) fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            let span = s.virtual_size.max(s.raw_size);
            if rva >= s.virtual_address && rva < s.virtual_address.saturating_add(span) {
                return Some(s.raw_ptr as usize + (rva - s.virtual_address) as usize);
            }
        }
        // Header region: RVAs below the first section map 1:1.
        let first_va = self
            .sections
            .iter()
            .map(|s| s.virtual_address)
            .min()
            .unwrap_or(0);
        if rva < first_va && (rva as usize) < self.data.len() {
            return Some(rva as usize);
        }
        None
    }

    /// Reads `size` file bytes belonging to data directory `index`.
    fn dir_bytes(&self, index: usize) -> Option<&'a [u8]> {
        let (va, size) = self.dirs[index];
        if va == 0 || size == 0 {
            return None;
        }
        let off = self.rva_to_offset(va)?;
        self.data.get(off..off.saturating_add(size as usize))
    }

    /// File offset where the overlay starts (end of the last raw section).
    fn overlay_offset(&self) -> usize {
        let mut end = 0usize;
        for s in &self.sections {
            if s.raw_ptr != 0 {
                end = end.max(s.raw_ptr as usize + s.raw_size as usize);
            }
        }
        end
    }

    /// DOS stub bytes between the fixed header and `e_lfanew`.
    fn dos_stub(&self) -> &'a [u8] {
        let start = DOS_HEADER_SIZE.min(self.data.len());
        let end = self.pe_offset.min(self.data.len()).max(start);
        &self.data[start..end]
    }
}

/// A leaf of the packed file's resource directory plus the bookkeeping the
/// rebuild pass needs (subset of `XPE::RESOURCE_RECORD`).
struct ResourceLeaf {
    /// Offset of the IMAGE_RESOURCE_DATA_ENTRY relative to the resource root.
    irde_offset: usize,
    /// `OffsetToData` value stored in the packed file, as absolute VA
    /// (RVA + image base), matching upstream's `nAddress`.
    address: u64,
    /// `Size` field of the data entry.
    size: u32,
    /// Root-level type id when it is numeric (`irin[0].nID`).
    root_id: Option<u32>,
    /// File offset of the resource payload in the packed image.
    data_file_offset: usize,
}

/// Recursively walks the packed file's resource directory collecting leaves
/// and the unique name-string offsets used by the `nMaxOffset` estimate.
fn walk_resource_dir(
    pe: &PackedPe<'_>,
    root_off: usize,
    dir_off: usize,
    depth: usize,
    root_id: Option<u32>,
    leaves: &mut Vec<ResourceLeaf>,
    name_offsets: &mut HashSet<u32>,
) -> Result<(), UnpackError> {
    if depth > 3 || leaves.len() >= MAX_RESOURCES {
        return Ok(());
    }
    let entries_off = dir_off
        .checked_add(16)
        .ok_or(UnpackError::Malformed("resource bounds"))?;
    if entries_off > pe.data.len() {
        return Err(UnpackError::Malformed("resource bounds"));
    }
    let named = read_u16(pe.data, dir_off + 12).unwrap_or(0) as usize;
    let ids = read_u16(pe.data, dir_off + 14).unwrap_or(0) as usize;
    for i in 0..named.saturating_add(ids).min(4096) {
        if leaves.len() >= MAX_RESOURCES {
            return Ok(());
        }
        let e = entries_off + i * 8;
        if e + 8 > pe.data.len() {
            return Err(UnpackError::Malformed("resource entry truncated"));
        }
        let name = read_u32(pe.data, e).unwrap_or(0);
        let target = read_u32(pe.data, e + 4).unwrap_or(0);
        let this_root = if depth == 0 && name & 0x8000_0000 == 0 {
            Some(name & 0xffff)
        } else {
            root_id
        };
        if name & 0x8000_0000 != 0 {
            name_offsets.insert(name & 0x7fff_ffff);
        }
        if target & 0x8000_0000 != 0 {
            let sub = root_off.saturating_add((target & 0x7fff_ffff) as usize);
            walk_resource_dir(
                pe,
                root_off,
                sub,
                depth + 1,
                this_root,
                leaves,
                name_offsets,
            )?;
            continue;
        }
        let leaf_off = root_off.saturating_add((target & 0x7fff_ffff) as usize);
        if leaf_off + 16 > pe.data.len() {
            return Err(UnpackError::Malformed("resource data entry"));
        }
        let offset_to_data = read_u32(pe.data, leaf_off).unwrap_or(0);
        let size = read_u32(pe.data, leaf_off + 4).unwrap_or(0);
        let Some(file_off) = pe.rva_to_offset(offset_to_data) else {
            continue; // upstream records nOffset == -1 and skips it later
        };
        leaves.push(ResourceLeaf {
            irde_offset: leaf_off - root_off,
            address: offset_to_data as u64 + pe.image_base,
            size,
            root_id: this_root,
            data_file_offset: file_off,
        });
    }
    Ok(())
}

/// Converts a sorted RVA list into `.reloc` block format
/// (`XPE::relocsAsRVAListToByteArray`).
fn relocs_as_byte_array(relocs: &[u64], is64: bool) -> Vec<u8> {
    let type_bits: u16 = if is64 { 0xA000 } else { 0x3000 };
    let mut out = Vec::new();
    let mut i = 0;
    while i < relocs.len() {
        let base = relocs[i] & !0xfff;
        let mut j = i;
        while j < relocs.len() && (relocs[j] & !0xfff) == base {
            j += 1;
        }
        let count = j - i;
        let mut block_size = 8 + count * 2;
        let pad = (4 - block_size % 4) % 4;
        block_size += pad;
        out.extend_from_slice(&(base as u32).to_le_bytes());
        out.extend_from_slice(&(block_size as u32).to_le_bytes());
        for r in &relocs[i..j] {
            let entry = ((*r - base) as u16) | type_bits;
            out.extend_from_slice(&entry.to_le_bytes());
        }
        out.resize(out.len() + pad, 0);
        i = j;
    }
    out
}

/// Optional header field offsets shared between PE32 and PE32+.
struct OptLayout {
    size_of_code: usize,
    base_of_code: usize,
    image_base: usize,
    section_alignment: usize,
    file_alignment: usize,
    size_of_headers: usize,
    number_of_dirs: usize,
    dir_base: usize,
}

fn opt_layout(is64: bool) -> OptLayout {
    OptLayout {
        size_of_code: 4,
        base_of_code: 20,
        image_base: if is64 { 24 } else { 28 },
        section_alignment: 32,
        file_alignment: 36,
        size_of_headers: 60,
        number_of_dirs: if is64 { 108 } else { 92 },
        dir_base: if is64 { 112 } else { 96 },
    }
}

/// Reads the 16 data directories at `opt + layout.dir_base`.
fn read_dirs(buf: &[u8], opt: usize, layout: &OptLayout) -> [(u32, u32); 16] {
    let num = read_u32(buf, opt + layout.number_of_dirs)
        .unwrap_or(0)
        .min(16) as usize;
    let mut dirs = [(0u32, 0u32); 16];
    for (i, d) in dirs.iter_mut().enumerate().take(num) {
        *d = (
            read_u32(buf, opt + layout.dir_base + i * 8).unwrap_or(0),
            read_u32(buf, opt + layout.dir_base + i * 8 + 4).unwrap_or(0),
        );
    }
    dirs
}

/// Unpacks a UPX-compressed PE file, mirroring `XUPX::_unpackPE`.
pub fn unpack_pe(data: &[u8], info: &UpxInfo) -> Result<Vec<u8>, UnpackError> {
    if info.c_len == 0 || info.u_len == 0 {
        return Err(UnpackError::Malformed("empty payload lengths"));
    }
    let compressed = data
        .get(info.data_offset..info.data_offset.saturating_add(info.c_len as usize))
        .ok_or(UnpackError::Malformed("compressed data truncated"))?;
    let payload = decompress_payload(compressed, info.u_len as usize, info.method)?;
    if payload.len() < 4 {
        return Err(UnpackError::Malformed("payload too small"));
    }

    let pe = PackedPe::parse(data)?;

    let extra_off = read_u32(&payload, payload.len() - 4).unwrap() as usize;
    let ih_size = if pe.is64 {
        NT_HEADERS64_SIZE
    } else {
        NT_HEADERS32_SIZE
    };
    let ih_end = extra_off
        .checked_add(ih_size)
        .ok_or(UnpackError::Malformed("extra info bounds"))?;
    let ih = payload
        .get(extra_off..ih_end)
        .ok_or(UnpackError::Malformed("NT headers outside payload"))?;
    if &ih[0..4] != b"PE\0\0" {
        return Err(UnpackError::Malformed("bad signature in extra info"));
    }

    let layout = opt_layout(pe.is64);
    let opt = 24usize; // signature(4) + coff(20)
    let file_alignment = read_u32(ih, opt + layout.file_alignment)
        .unwrap_or(0)
        .max(0x200);
    let section_alignment = read_u32(ih, opt + layout.section_alignment)
        .unwrap_or(0)
        .max(0x1000);
    let number_of_sections = read_u16(ih, 6).unwrap_or(0) as usize;
    if number_of_sections == 0 || number_of_sections > MAX_SECTIONS {
        return Err(UnpackError::Malformed("section count"));
    }
    let characteristics = read_u16(ih, 22).unwrap_or(0);
    let base_of_code = read_u32(ih, opt + layout.base_of_code).unwrap_or(0);
    let size_of_code = read_u32(ih, opt + layout.size_of_code).unwrap_or(0);
    let image_base = if pe.is64 {
        let lo = read_u32(ih, opt + layout.image_base).unwrap_or(0) as u64;
        let hi = read_u32(ih, opt + layout.image_base + 4).unwrap_or(0) as u64;
        (hi << 32) | lo
    } else {
        read_u32(ih, opt + layout.image_base).unwrap_or(0) as u64
    };
    let rvamin = align_up(
        read_u32(ih, opt + layout.size_of_headers).unwrap_or(0) as u64,
        section_alignment as u64,
    ) as usize;
    let mut dirs = read_dirs(ih, opt, &layout);

    // Section headers follow the NT headers in the extra info.
    let sect_off = ih_end;
    let mut out_sections: Vec<[u8; SECTION_HEADER_SIZE]> = Vec::with_capacity(number_of_sections);
    for i in 0..number_of_sections {
        let s = sect_off + i * SECTION_HEADER_SIZE;
        let raw = payload
            .get(s..s + SECTION_HEADER_SIZE)
            .ok_or(UnpackError::Malformed("section table outside payload"))?;
        let mut h = [0u8; SECTION_HEADER_SIZE];
        h.copy_from_slice(raw);
        out_sections.push(h);
    }
    let mut cursor = sect_off + number_of_sections * SECTION_HEADER_SIZE;

    // Memory image: headers occupy [0, rvamin), payload maps at rvamin.
    let image_len = rvamin
        .checked_add(payload.len())
        .ok_or(UnpackError::Malformed("image too large"))?;
    if image_len > MAX_OUTPUT_SIZE {
        return Err(UnpackError::Malformed("image too large"));
    }
    let mut image = vec![0u8; image_len];
    image[rvamin..rvamin + payload.len()].copy_from_slice(&payload);

    // Undo the input filter on the code range.
    if size_of_code != 0
        && base_of_code as usize >= rvamin
        && base_of_code as usize - rvamin + size_of_code as usize <= payload.len()
    {
        let start = base_of_code as usize;
        let end = start + size_of_code as usize;
        apply_pe_filter(
            &mut image[start..end],
            info.filter,
            info.filter_cto,
            base_of_code - rvamin as u32,
        )?;
    }

    let import_present = dirs[DIR_IMPORT].0 != 0;
    let td_relocs = dirs[DIR_BASERELOC].1 == 8;
    let relocs_present = dirs[DIR_BASERELOC].0 != 0
        && dirs[DIR_BASERELOC].1 != 0
        && characteristics & IMAGE_FILE_RELOCS_STRIPPED == 0;
    let export_present = dirs[DIR_EXPORT].0 != pe.dirs[DIR_EXPORT].0;
    let resources_present = dirs[DIR_RESOURCE].0 != 0;

    if import_present {
        rebuild_imports(
            &mut image,
            rvamin,
            &payload,
            &mut cursor,
            &pe,
            &dirs,
            pe.is64,
        )?;
    }
    if td_relocs {
        // Degenerate ".reloc" placeholder: two u32 {0, 8}.
        let dst = dirs[DIR_BASERELOC].0 as usize;
        if !write_u32_into(&mut image, dst, 0) || !write_u32_into(&mut image, dst + 4, 8) {
            return Err(UnpackError::Malformed("reloc placeholder bounds"));
        }
    } else if relocs_present {
        let reloc_size = rebuild_relocs(
            &mut image,
            rvamin,
            &payload,
            &mut cursor,
            image_base,
            &dirs,
            pe.is64,
        )?;
        // The rebuilt size replaces the directory size in the output headers.
        dirs[DIR_BASERELOC].1 = reloc_size;
    }
    if export_present {
        rebuild_exports(&mut image, &pe, &dirs)?;
    }
    if resources_present {
        rebuild_resources(&mut image, &payload, &mut cursor, &pe, &dirs)?;
    }

    assemble_output(data, &pe, ih, &out_sections, dirs, &image, file_alignment)
}

fn write_u32_into(buf: &mut [u8], off: usize, v: u32) -> bool {
    match buf.get_mut(off..off + 4) {
        Some(b) => {
            b.copy_from_slice(&v.to_le_bytes());
            true
        }
        None => false,
    }
}

/// Rebuilds the import table from the compressed import list
/// (`bIsImportPresent` in `_unpackPE`). The packed file's own import
/// directory doubles as the DLL-name/thunk lookup table.
fn rebuild_imports(
    image: &mut [u8],
    rvamin: usize,
    payload: &[u8],
    cursor: &mut usize,
    pe: &PackedPe<'_>,
    dirs: &[(u32, u32); 16],
    is64: bool,
) -> Result<(), UnpackError> {
    let import_off = read_u32(payload, *cursor).ok_or(UnpackError::Malformed("import info"))?;
    let iname_position =
        read_u32(payload, *cursor + 4).ok_or(UnpackError::Malformed("import info"))?;
    *cursor += 8;
    let idata = rvamin
        .checked_add(import_off as usize)
        .ok_or(UnpackError::Malformed("import list offset"))?;
    let ba_import = pe.dir_bytes(DIR_IMPORT).unwrap_or(&[]);
    let iid_va = dirs[DIR_IMPORT].0 as usize;

    // First pass: total size of the packed DLL names (aligned up to 2).
    let mut dll_names = 0usize;
    let mut p = idata;
    loop {
        let name_idx = read_u32(image, p).ok_or(UnpackError::Malformed("import list"))? as usize;
        if name_idx == 0 {
            break;
        }
        if name_idx >= ba_import.len() {
            return Err(UnpackError::Malformed("import name index"));
        }
        dll_names += cstrlen(&ba_import[name_idx..]) + 1;
        p += 8;
        loop {
            let tag = *image.get(p).ok_or(UnpackError::Malformed("import list"))?;
            match tag {
                0 => break,
                1 => {
                    p += 1;
                    let s = image
                        .get(p..)
                        .ok_or(UnpackError::Malformed("import name"))?;
                    p += cstrlen(s) + 1;
                }
                0xff => p += 3,
                _ => p += 5,
            }
        }
        p += 1; // record terminator
    }
    let dll_names = align_up(dll_names as u64, 2) as usize;

    let mut p_dll_names = iname_position as usize;
    let mut p_imported_names = p_dll_names.saturating_add(dll_names);
    let imported_names_start = p_imported_names;
    let mut iid = iid_va;
    let mut p = idata;
    loop {
        let name_idx = read_u32(image, p).ok_or(UnpackError::Malformed("import list"))? as usize;
        if name_idx == 0 {
            break;
        }
        if name_idx >= ba_import.len() {
            return Err(UnpackError::Malformed("import name index"));
        }
        let name_len = cstrlen(&ba_import[name_idx..]);
        let name = ba_import[name_idx..name_idx + name_len].to_vec();
        let iat_rva = read_u32(image, p + 4)
            .ok_or(UnpackError::Malformed("import iat"))?
            .wrapping_add(rvamin as u32);

        if iname_position != 0 {
            write_bytes(image, p_dll_names, &name);
            write_bytes(image, p_dll_names + name_len, &[0]);
            write_u32(image, iid + 12, p_dll_names as u32); // Name
            p_dll_names += name_len + 1;
        } else {
            let name_rva = read_u32(image, iid + 12).unwrap_or(0) as usize;
            write_bytes(image, name_rva, &name);
            write_bytes(image, name_rva + name_len, &[0]);
        }
        write_u32(image, iid + 16, iat_rva); // FirstThunk
        p += 8;
        let step = if is64 { 8 } else { 4 };
        let mut iat = iat_rva as usize;
        loop {
            let tag = *image
                .get(p)
                .ok_or(UnpackError::Malformed("import entries"))?;
            if tag == 0 {
                break;
            }
            if tag == 1 {
                // By-name import: hint/name string follows.
                p += 1;
                let s = image
                    .get(p..)
                    .ok_or(UnpackError::Malformed("import name"))?;
                let l = cstrlen(s);
                let name_with_nul = s[..(l + 1).min(s.len())].to_vec();
                if iname_position != 0 {
                    if (p_imported_names - imported_names_start) & 1 != 0 {
                        p_imported_names -= 1;
                    }
                    write_bytes(image, p_imported_names + 2, &name_with_nul);
                    write_u32(image, iat, p_imported_names as u32);
                    p_imported_names += 2 + l + 1;
                } else {
                    let addr = read_u32(image, iat).unwrap_or(0) as usize;
                    write_bytes(image, addr + 2, &name_with_nul);
                }
                p += l + 1;
            } else if tag == 0xff {
                // Ordinal import.
                let ord = read_u16(image, p + 1).unwrap_or(0) as u64;
                if is64 {
                    write_u64(image, iat, ord | 0x8000_0000_0000_0000);
                } else {
                    write_u32(image, iat, ord as u32 | 0x8000_0000);
                }
                p += 3;
            } else {
                // Indirect thunk reference into the packed import data.
                let thunk_off =
                    read_u32(image, p + 1).ok_or(UnpackError::Malformed("thunk offset"))? as usize;
                let thunk_val =
                    read_u32(ba_import, thunk_off).ok_or(UnpackError::Malformed("thunk value"))?;
                if is64 {
                    write_u64(image, iat, thunk_val as u64);
                } else {
                    write_u32(image, iat, thunk_val);
                }
                p += 5;
            }
            iat += step;
        }
        if is64 {
            write_u64(image, iat, 0);
        } else {
            write_u32(image, iat, 0);
        }
        p += 1; // terminator
        iid += IMPORT_DESCRIPTOR_SIZE;
    }
    Ok(())
}

/// Rebuilds base relocations from the compressed relocation stream
/// (`bIsRelocsPresent` in `_unpackPE`) and returns the `.reloc` block bytes.
fn rebuild_relocs(
    image: &mut [u8],
    rvamin: usize,
    payload: &[u8],
    cursor: &mut usize,
    image_base: u64,
    dirs: &[(u32, u32); 16],
    is64: bool,
) -> Result<u32, UnpackError> {
    let relocs_off = read_u32(payload, *cursor).ok_or(UnpackError::Malformed("reloc info"))?;
    let _big = *payload
        .get(*cursor + 4)
        .ok_or(UnpackError::Malformed("reloc info"))?;
    *cursor += 5;
    let start = rvamin
        .checked_add(relocs_off as usize)
        .ok_or(UnpackError::Malformed("reloc offset"))?;

    // Pass 1: decode the run-length list; `jc` accumulates offsets starting
    // at -4 (matches upstream `quint32 jc = (quint32)-4`).
    let mut offsets: Vec<u32> = Vec::new();
    let mut jc: u32 = 0u32.wrapping_sub(4);
    let mut p = start;
    loop {
        let b = *image.get(p).ok_or(UnpackError::Malformed("reloc stream"))?;
        p += 1;
        if b == 0 {
            break;
        }
        if b < 0xf0 {
            jc = jc.wrapping_add(b as u32);
        } else {
            let mut dif = (((b as u32) & 0x0f) << 16) | read_u16(image, p).unwrap_or(0) as u32;
            p += 2;
            if dif == 0 {
                dif = read_u32(image, p).ok_or(UnpackError::Malformed("reloc dif"))?;
                p += 4;
            }
            jc = jc.wrapping_add(dif);
        }
        if offsets.len() >= MAX_RELOCS {
            return Err(UnpackError::Malformed("reloc count"));
        }
        offsets.push(jc);
        // Byte-swap the stored value at the reloc target (upstream writes the
        // LE-read value back big-endian).
        let t = rvamin.wrapping_add(jc as usize);
        if is64 {
            if let Some(bytes) = image.get(t..t + 8) {
                let v = u64::from_le_bytes(bytes.try_into().unwrap());
                write_u64(image, t, v.swap_bytes());
            }
        } else if let Some(bytes) = image.get(t..t + 4) {
            let v = u32::from_le_bytes(bytes.try_into().unwrap());
            write_u32(image, t, v.swap_bytes());
        }
    }

    // Pass 2: add ImageBase + rvamin to each target; collect sorted RVAs.
    let mut list_relocs: Vec<u64> = Vec::with_capacity(offsets.len());
    for off in &offsets {
        let t = rvamin.wrapping_add(*off as usize);
        if is64 {
            if let Some(bytes) = image.get(t..t + 8) {
                let v = u64::from_le_bytes(bytes.try_into().unwrap());
                write_u64(
                    image,
                    t,
                    v.wrapping_add(image_base).wrapping_add(rvamin as u64),
                );
            }
        } else if let Some(bytes) = image.get(t..t + 4) {
            let v = u32::from_le_bytes(bytes.try_into().unwrap());
            write_u32(
                image,
                t,
                v.wrapping_add(image_base as u32)
                    .wrapping_add(rvamin as u32),
            );
        }
        list_relocs.push(rvamin as u64 + *off as u64);
    }
    let ba_relocs = relocs_as_byte_array(&list_relocs, is64);
    let dst = dirs[DIR_BASERELOC].0 as usize;
    if !write_bytes(image, dst, &ba_relocs) {
        return Err(UnpackError::Malformed("reloc output bounds"));
    }
    Ok(ba_relocs.len() as u32)
}

/// Copies the packed file's export block to the original RVA and rebases its
/// internal pointers (`bIsExportPresent` in `_unpackPE`).
fn rebuild_exports(
    image: &mut [u8],
    pe: &PackedPe<'_>,
    dirs: &[(u32, u32); 16],
) -> Result<(), UnpackError> {
    let dst_rva = dirs[DIR_EXPORT].0 as usize;
    let (packed_va, packed_size) = pe.dirs[DIR_EXPORT];
    let packed_off = pe
        .rva_to_offset(packed_va)
        .ok_or(UnpackError::Malformed("export dir offset"))?;
    let packed = pe
        .data
        .get(packed_off..packed_off + packed_size as usize)
        .ok_or(UnpackError::Malformed("export dir truncated"))?;
    if !write_bytes(image, dst_rva, packed) {
        return Err(UnpackError::Malformed("export dst bounds"));
    }
    let delta = packed_va.wrapping_sub(dirs[DIR_EXPORT].0);
    // IMAGE_EXPORT_DIRECTORY RVA fields: Name(12), AddressOfFunctions(28),
    // AddressOfNames(32), AddressOfNameOrdinals(36).
    for field in [12usize, 28, 32, 36] {
        let cur = read_u32(image, dst_rva + field).unwrap_or(0);
        write_u32(image, dst_rva + field, cur.wrapping_sub(delta));
    }
    let number_of_names = read_u32(image, dst_rva + 24).unwrap_or(0).min(1_000_000);
    let mut names = read_u32(image, dst_rva + 32).unwrap_or(0) as usize;
    for _ in 0..number_of_names {
        let cur = read_u32(image, names).unwrap_or(0);
        write_u32(image, names, cur.wrapping_sub(delta));
        names += 4;
    }
    Ok(())
}

/// Rebuilds the resource tree (`bIsResourcesPresent` in `_unpackPE`): copies
/// the packed directory bytes clamped to `nMaxOffset`, then patches each leaf
/// data entry back to the original RVA and copies the stored blob.
fn rebuild_resources(
    image: &mut [u8],
    payload: &[u8],
    cursor: &mut usize,
    pe: &PackedPe<'_>,
    dirs: &[(u32, u32); 16],
) -> Result<(), UnpackError> {
    let mut icon_dir_count = read_u16(payload, *cursor).unwrap_or(0);
    *cursor += 2;
    let mut leaves = Vec::new();
    let mut name_offsets = HashSet::new();
    let (res_va, res_size) = dirs[DIR_RESOURCE];
    if res_va == 0 {
        return Ok(());
    }
    let (packed_va, packed_size) = pe.dirs[DIR_RESOURCE];
    let packed_off = pe
        .rva_to_offset(packed_va)
        .ok_or(UnpackError::Malformed("resource dir offset"))?;
    let root_off = packed_off;
    walk_resource_dir(
        pe,
        root_off,
        root_off,
        0,
        None,
        &mut leaves,
        &mut name_offsets,
    )?;

    // nMaxOffset: furthest data entry end + resource name-string bytes,
    // clamped to the original resource directory size.
    let mut max_offset = 0usize;
    for leaf in &leaves {
        max_offset = max_offset.max(leaf.irde_offset + 16);
    }
    for off in &name_offsets {
        let pos = root_off + *off as usize;
        if let Some(len) = read_u16(pe.data, pos) {
            max_offset += 2 + len as usize * 2;
        }
    }
    let copy_len = max_offset
        .min(res_size as usize)
        .min(pe.data.len().saturating_sub(packed_off))
        .min(packed_size as usize);
    if copy_len > 0 {
        let src = pe
            .data
            .get(packed_off..packed_off + copy_len)
            .ok_or(UnpackError::Malformed("resource dir truncated"))?
            .to_vec();
        if !write_bytes(image, res_va as usize, &src) {
            return Err(UnpackError::Malformed("resource dst bounds"));
        }
    }

    let section2_va = pe.sections.get(2).map(|s| s.virtual_address).unwrap_or(0) as u64;
    for leaf in &leaves {
        if leaf.address < section2_va + pe.image_base {
            continue;
        }
        let Some(orig_rva) = leaf
            .data_file_offset
            .checked_sub(4)
            .and_then(|o| read_u32(pe.data, o))
        else {
            continue;
        };
        write_u32(image, res_va as usize + leaf.irde_offset, orig_rva);
        let copy = align_up(leaf.size as u64, 4) as usize;
        if let Some(src) = pe
            .data
            .get(leaf.data_file_offset..leaf.data_file_offset + copy)
        {
            let src = src.to_vec();
            let dst = orig_rva as usize;
            if dst + src.len() <= image.len()
                && write_bytes(image, dst, &src)
                && icon_dir_count != 0
                && leaf.root_id == Some(RT_GROUP_ICON)
            {
                write_u32(image, dst + 4, icon_dir_count as u32);
                icon_dir_count = 0;
            }
        }
    }
    Ok(())
}

/// Assembles the output file: DOS header + stub from the packed file, the
/// recovered NT headers and section table, section data, overlay.
fn assemble_output(
    data: &[u8],
    pe: &PackedPe<'_>,
    ih: &[u8],
    sections: &[[u8; SECTION_HEADER_SIZE]],
    dirs: [(u32, u32); 16],
    image: &[u8],
    file_alignment: u32,
) -> Result<Vec<u8>, UnpackError> {
    let mut file_size = 0u64;
    for s in sections {
        let raw_ptr = read_u32(s, 20).unwrap_or(0);
        let raw_size = read_u32(s, 16).unwrap_or(0);
        if raw_ptr != 0 {
            file_size = file_size.max(raw_ptr as u64 + raw_size as u64);
        }
    }
    file_size = align_up(file_size, file_alignment as u64);
    if file_size as usize > MAX_OUTPUT_SIZE {
        return Err(UnpackError::Malformed("output too large"));
    }
    let mut out = vec![0u8; file_size as usize];

    // IMAGE_DOS_HEADEREX (64 bytes) + DOS stub from the packed file.
    let hdr_len = DOS_HEADER_SIZE.min(data.len());
    out[..hdr_len].copy_from_slice(&data[..hdr_len]);
    let stub = pe.dos_stub();
    let mut pos = hdr_len;
    if pos + stub.len() > out.len() {
        return Err(UnpackError::Malformed("stub too large"));
    }
    out[pos..pos + stub.len()].copy_from_slice(stub);
    pos += stub.len();

    // NT headers verbatim with DEBUG and BOUND_IMPORT cleared (upstream).
    let mut ih_buf = ih.to_vec();
    let dir_base = 24 + if pe.is64 { 112 } else { 96 };
    for idx in [DIR_DEBUG, DIR_BOUND_IMPORT] {
        let d = dir_base + idx * 8;
        if d + 8 <= ih_buf.len() {
            ih_buf[d..d + 8].fill(0);
        }
    }
    // Updated BASE relocation size after the rebuild.
    if dirs[DIR_BASERELOC].1 != 0 {
        let d = dir_base + DIR_BASERELOC * 8 + 4;
        write_u32(&mut ih_buf, d, dirs[DIR_BASERELOC].1);
    }
    if pos + ih_buf.len() > out.len() {
        return Err(UnpackError::Malformed("headers too large"));
    }
    out[pos..pos + ih_buf.len()].copy_from_slice(&ih_buf);

    // Section table verbatim.
    let mut t = pos + ih_buf.len();
    for s in sections {
        if t + SECTION_HEADER_SIZE > out.len() {
            return Err(UnpackError::Malformed("section table overflow"));
        }
        out[t..t + SECTION_HEADER_SIZE].copy_from_slice(s);
        t += SECTION_HEADER_SIZE;
    }

    // Section contents from the memory image.
    for s in sections {
        let raw_ptr = read_u32(s, 20).unwrap_or(0) as usize;
        let raw_size = read_u32(s, 16).unwrap_or(0);
        let va = read_u32(s, 12).unwrap_or(0) as usize;
        if raw_ptr == 0 {
            continue;
        }
        let len = align_up(raw_size as u64, file_alignment as u64) as usize;
        if va + len > image.len() || raw_ptr + len > out.len() {
            return Err(UnpackError::Malformed("section data bounds"));
        }
        out[raw_ptr..raw_ptr + len].copy_from_slice(&image[va..va + len]);
    }

    // Overlay: bytes beyond the last raw section of the packed file.
    let overlay_off = pe.overlay_offset();
    if overlay_off > 0 && overlay_off < data.len() {
        out.extend_from_slice(&data[overlay_off..]);
    }
    Ok(out)
}

/// Top-level entry: detect and unpack a UPX file. Only PE containers are
/// rebuilt in-process (matching `XUPX::_unpackPE`); other containers return
/// `Unsupported`.
pub fn unpack(data: &[u8]) -> Result<Vec<u8>, UnpackError> {
    let info = detect_upx(data).ok_or(UnpackError::NotPacked)?;
    if !is_pe(data) {
        return Err(UnpackError::Unsupported("non-PE UPX container"));
    }
    if !matches!(info.format, UPX_F_W32PE_I386 | UPX_F_W64PE_AMD64) {
        // A PE container with an unexpected format id is still attempted:
        // upstream detects by PE validity, not by the format byte.
    }
    unpack_pe(data, &info)
}

/// Returns `true` when `data` looks like a UPX-packed PE.
pub fn is_upx_packed(data: &[u8]) -> bool {
    detect_upx(data).is_some()
}

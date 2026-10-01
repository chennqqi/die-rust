//! Archive format probes (CAP-DISPATCH-004).
//!
//! Archive detection by magic number:
//! - ZIP/JAR/APK/NPM: local file header magic `PK\x03\x04`. ZIP is the base
//!   format; JAR/APK/NPM are ZIP-based but distinguished by content, not
//!   magic. This probe reports ZIP; APK/JAR/NPM identification is deferred
//!   to content-level analysis.
//! - RAR4: magic `Rar!\x1A\x07\x00`.
//! - RAR5: magic `Rar!\x1A\x07\x01\x00`.
//! - 7Z: magic `7z\xBC\xAF\x27\x1C`.
//! - GZIP: magic `\x1F\x8B`.
//! - TAR: USTAR magic at offset 257 (`ustar`). POSIX/GNU tar use this.
//!   Old-format tar (without ustar) is not detected by magic alone.
//! - ISO9660: magic `CD001` at sector 16 (offset 0x8000, 32768). This
//!   requires reading at a large offset, which is supported by ByteView.
//! - CAB: magic `MSCF` at offset 0.

use crate::probe::{FormatProbe, ProbeError, ProbeOutcome, strong_deferred};
use diec_core::format::FileType;
use diec_core::input::ByteView;

/// ZIP format probe (base for JAR/APK/NPM).
#[derive(Debug, Default)]
pub struct ZipProbe;

/// RAR format probe (detects RAR4 and RAR5).
#[derive(Debug, Default)]
pub struct RarProbe;

/// 7Z format probe.
#[derive(Debug, Default)]
pub struct SevenZProbe;

/// GZIP format probe.
#[derive(Debug, Default)]
pub struct GzipProbe;

/// TAR format probe (USTAR).
#[derive(Debug, Default)]
pub struct TarProbe;

/// ISO9660 format probe.
#[derive(Debug, Default)]
pub struct Iso9660Probe;

/// CAB format probe.
#[derive(Debug, Default)]
pub struct CabProbe;

/// ZIP local file header magic: `PK\x03\x04`.
#[cfg(test)]
const ZIP_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
/// RAR4 magic: `Rar!\x1A\x07\x00`.
const RAR4_MAGIC: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
/// RAR5 magic: `Rar!\x1A\x07\x01\x00`.
const RAR5_MAGIC: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
/// 7Z magic: `7z\xBC\xAF\x27\x1C`.
const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
/// GZIP magic: `\x1F\x8B`.
const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];
/// USTAR magic at offset 257 in tar header.
const USTAR_OFFSET: u64 = 257;
/// USTAR magic: `ustar`.
const USTAR_MAGIC: [u8; 5] = [0x75, 0x73, 0x74, 0x61, 0x72];
/// ISO9660 magic at sector 16 (offset 32768).
const ISO9660_OFFSET: u64 = 0x8000;
/// ISO9660 magic: `CD001`.
const ISO9660_MAGIC: [u8; 5] = [0x43, 0x44, 0x30, 0x30, 0x31];
/// CAB magic: `MSCF`.
const CAB_MAGIC: [u8; 4] = [0x4D, 0x53, 0x43, 0x46];

/// ZIP end-of-central-directory signature: `PK\x05\x06`.
const EOCD_MAGIC: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
/// ZIP central directory entry signature: `PK\x01\x02`.
const CD_MAGIC: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
/// ZIP local file header signature: `PK\x03\x04`.
const LFD_MAGIC_U32: u32 = 0x0403_4B50;
/// Central-directory digital signature record: `PK\x05\x05`.
const CD_SIGNATURE_U32: u32 = 0x0505_4B50;
/// Archive extra data record signature: `PK\x06\x08`.
const ARCHIVE_EXTRA_U32: u32 = 0x0806_4B50;
/// Data descriptor signature: `PK\x07\x08`.
const DATA_DESCRIPTOR_U32: u32 = 0x0807_4B50;
/// ZIP "stored" (no compression) method.
const CMETHOD_STORE: u16 = 0;
/// ZIP "deflate" compression method.
const CMETHOD_DEFLATE: u16 = 8;
/// Local/central flag bit: sizes follow in a data descriptor.
const ZIP_FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
/// Local/central flag bit: name is UTF-8 encoded.
const ZIP_FLAG_UTF8: u16 = 0x0800;
/// LOCALFILEHEADER fixed size.
const LFH_SIZE: u64 = 30;
/// CENTRALDIRECTORYFILEHEADER fixed size.
const CDH_SIZE: u64 = 46;
/// ENDOFCENTRALDIRECTORYRECORD fixed size.
const ECD_SIZE: u64 = 22;
/// Maximum bytes searched backwards for the EOCD record (upstream
/// `XZip::findECDOffset` scans `0xFFFF + sizeof(ECD)` tail bytes).
const EOCD_SCAN_MAX: u64 = 0xFFFF + ECD_SIZE;
/// Maximum central directory entries inspected for subtype classification
/// (mirrors upstream `getRecords(20000)`).
const MAX_CD_RECORDS: u32 = 20_000;

/// Minimal EOCD record name/size pair used for ZIP subtype classification.
struct CdEntry {
    /// Central directory member name (raw bytes, `/` separators).
    name: Vec<u8>,
    /// Uncompressed size field from the central directory record.
    uncompressed_size: u32,
}

/// Read a u16 little-endian field from `buf` at `pos` (bounds-checked by the
/// caller layout; callers slice only fixed-size record buffers).
fn u16le(buf: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes([buf[pos], buf[pos + 1]])
}

/// Read a u32 little-endian field from `buf` at `pos`.
fn u32le(buf: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
}

/// Upstream `_readFileName` validity semantics: the name and extra-field
/// ranges must be in bounds, each <= i32::MAX, and the name must decode —
/// strict UTF-8 when flag 0x0800 is set (upstream `decodeZipUtf8Strict`
/// rejects overlongs, surrogates, and > U+10FFFF, matching Rust UTF-8
/// validation), CP437 otherwise (which never fails).
fn zip_name_decodable(
    view: &ByteView<'_>,
    name_off: u64,
    name_len: u64,
    flags: u16,
    extra_off: u64,
    extra_len: u64,
) -> bool {
    let size = view.len();
    if name_off > size || name_len > size - name_off {
        return false;
    }
    if extra_off > size || extra_len > size - extra_off {
        return false;
    }
    if name_len > i32::MAX as u64 || extra_len > i32::MAX as u64 {
        return false;
    }
    let mut name_buf = vec![0u8; name_len as usize];
    if view.read_exact_at(name_off, &mut name_buf).is_err() {
        return false;
    }
    let mut extra_buf = vec![0u8; extra_len as usize];
    if view.read_exact_at(extra_off, &mut extra_buf).is_err() {
        return false;
    }
    if flags & ZIP_FLAG_UTF8 != 0 && std::str::from_utf8(&name_buf).is_err() {
        return false;
    }
    true
}

/// Upstream `zipNamesEquivalent`: identical length, and positions may differ
/// only where BOTH sides carry a byte >= 0x80 (DOS/ANSI codepage remap).
fn zip_names_equivalent(local: &[u8], central: &[u8]) -> bool {
    if local.len() != central.len() {
        return false;
    }
    local
        .iter()
        .zip(central.iter())
        .all(|(&l, &c)| l == c || (l >= 0x80 && c >= 0x80))
}

/// Port of upstream `XZip::_getNumberOfLocalFileHeaders`: walk complete
/// local file records starting at `offset`, bounded to `offset+size`.
/// Returns (record count, bytes covered). Descriptor-based entries
/// (flag 0x0008) stop the walk because their real sizes are unknown.
fn count_local_file_headers(view: &ByteView<'_>, offset: u64, size: u64) -> (u32, u64) {
    let device_size = view.len();
    let mut count = 0u32;
    if offset > device_size || size > device_size - offset {
        return (0, 0);
    }
    let end = offset + size;
    let mut cur = offset;
    while cur >= offset && end - cur >= LFH_SIZE {
        let mut hdr = [0u8; LFH_SIZE as usize];
        if view.read_exact_at(cur, &mut hdr).is_err() {
            return (0, 0);
        }
        if u32le(&hdr, 0) != LFD_MAGIC_U32 {
            break;
        }
        let flags = u16le(&hdr, 6);
        let compressed = u64::from(u32le(&hdr, 18));
        let name_len = u64::from(u16le(&hdr, 26));
        let extra_len = u64::from(u16le(&hdr, 28));
        let record_size = LFH_SIZE + name_len + extra_len + compressed;
        if record_size == 0 || record_size > end - cur {
            break;
        }
        if flags & ZIP_FLAG_DATA_DESCRIPTOR != 0 {
            break;
        }
        let name_off = cur + LFH_SIZE;
        let extra_off = name_off + name_len;
        if !zip_name_decodable(view, name_off, name_len, flags, extra_off, extra_len) {
            break;
        }
        count += 1;
        cur += record_size;
    }
    (count, cur.saturating_sub(offset))
}

/// Upstream `XZip::_isECDSignaturePresent`: any `PK\x05\x06` u32 found in
/// `[offset, size)` means the stream is not a CD-less ZIP.
fn is_ecd_sig_present(view: &ByteView<'_>, offset: u64) -> bool {
    let size = view.len();
    if offset >= size {
        return false;
    }
    let mut buf = vec![0u8; (size - offset) as usize];
    if view.read_exact_at(offset, &mut buf).is_err() {
        return false;
    }
    buf.windows(4).any(|w| w == EOCD_MAGIC)
}

/// Validate one EOCD candidate's central directory, porting the
/// `findECDOffset` record walk (xzip.cpp): every central record must match
/// its local header, local record ranges must be ordered/non-overlapping,
/// and optional trailing signature records must parse exactly.
#[allow(clippy::too_many_arguments)]
fn validate_central_directory(
    view: &ByteView<'_>,
    ecd: u64,
    total_records: u32,
    cd_offset: u64,
) -> bool {
    let mut cur = cd_offset;
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for _ in 0..total_records {
        if ecd - cur < CDH_SIZE {
            return false;
        }
        let mut cdh = [0u8; CDH_SIZE as usize];
        if view.read_exact_at(cur, &mut cdh).is_err() {
            return false;
        }
        if cdh[0..4] != CD_MAGIC {
            return false;
        }
        let c_min_version = cdh[6];
        let c_min_os = cdh[7];
        let c_flags = u16le(&cdh, 8);
        let c_method = u16le(&cdh, 10);
        let c_crc = u32le(&cdh, 16);
        let c_comp = u32le(&cdh, 20);
        let c_uncomp = u32le(&cdh, 24);
        let c_name_len = u64::from(u16le(&cdh, 28));
        let c_extra_len = u64::from(u16le(&cdh, 30));
        let c_comment_len = u64::from(u16le(&cdh, 32));
        let c_start_disk = u16le(&cdh, 34);
        let c_local_off = u64::from(u32le(&cdh, 42));

        let record_size = CDH_SIZE + c_name_len + c_extra_len + c_comment_len;
        if c_start_disk > 1
            || c_comp == 0xFFFF_FFFF
            || c_uncomp == 0xFFFF_FFFF
            || c_local_off == 0xFFFF_FFFF
            || (c_method == CMETHOD_STORE && c_flags & 0x0001 == 0 && c_comp != c_uncomp)
            || record_size > ecd - cur
        {
            return false;
        }
        // _readFileName on the central record.
        let c_name_off = cur + CDH_SIZE;
        let c_extra_off = c_name_off + c_name_len;
        if !zip_name_decodable(
            view,
            c_name_off,
            c_name_len,
            c_flags,
            c_extra_off,
            c_extra_len,
        ) {
            return false;
        }
        // Local header linkage: unique, inside the pre-CD area, readable.
        if c_local_off + LFH_SIZE > cd_offset || ranges.iter().any(|&(s, _)| s == c_local_off) {
            return false;
        }
        let mut lfh = [0u8; LFH_SIZE as usize];
        if view.read_exact_at(c_local_off, &mut lfh).is_err() {
            return false;
        }
        let l_min_version = lfh[4];
        let l_min_os = lfh[5];
        let l_flags = u16le(&lfh, 6);
        let l_method = u16le(&lfh, 8);
        let l_crc = u32le(&lfh, 14);
        let l_comp = u32le(&lfh, 18);
        let l_uncomp = u32le(&lfh, 22);
        let l_name_len = u64::from(u16le(&lfh, 26));
        let l_extra_len = u64::from(u16le(&lfh, 28));
        let local_data_off = c_local_off + LFH_SIZE + l_name_len + l_extra_len;

        let mut l_name = vec![0u8; l_name_len as usize];
        let mut c_name = vec![0u8; c_name_len as usize];
        if view
            .read_exact_at(c_local_off + LFH_SIZE, &mut l_name)
            .is_err()
            || view.read_exact_at(c_name_off, &mut c_name).is_err()
        {
            return false;
        }

        let flags_compatible = l_flags == c_flags
            || (l_method == CMETHOD_DEFLATE && (l_flags ^ c_flags) & !0x8006u16 == 0);
        if u32le(&lfh, 0) != LFD_MAGIC_U32
            || l_min_version != c_min_version
            || l_min_os != c_min_os
            || !flags_compatible
            || l_method != c_method
            || l_name_len != c_name_len
            || local_data_off > cd_offset
            || u64::from(c_comp) > cd_offset - local_data_off
            || !zip_names_equivalent(&l_name, &c_name)
            || (l_flags & ZIP_FLAG_DATA_DESCRIPTOR == 0
                && (l_crc != c_crc || l_comp != c_comp || l_uncomp != c_uncomp))
        {
            return false;
        }

        // Local ZIP64 extra field (upstream bLocalZip64 branch).
        let local_zip64 = l_comp == 0xFFFF_FFFF || l_uncomp == 0xFFFF_FFFF;
        if local_zip64 {
            if l_min_version < 45 || l_flags & ZIP_FLAG_DATA_DESCRIPTOR == 0 {
                return false;
            }
            let l_extra_off = c_local_off + LFH_SIZE + l_name_len;
            let mut extra = vec![0u8; l_extra_len as usize];
            if view.read_exact_at(l_extra_off, &mut extra).is_err() {
                return false;
            }
            let mut found_zip64 = false;
            let mut pos = 0usize;
            while pos < extra.len() {
                if extra.len() - pos < 4 {
                    return false;
                }
                let tag = u16le(&extra, pos);
                let flen = u16le(&extra, pos + 2) as usize;
                pos += 4;
                if flen > extra.len() - pos {
                    return false;
                }
                if tag == 1 {
                    let missing_uncomp = l_uncomp == 0xFFFF_FFFF;
                    let missing_comp = l_comp == 0xFFFF_FFFF;
                    let size_pair = flen == 16;
                    let single_size = flen == 8 && (missing_uncomp != missing_comp);
                    if found_zip64 || (!size_pair && !single_size) {
                        return false;
                    }
                    found_zip64 = true;
                    let mut vpos = pos;
                    if size_pair || missing_uncomp {
                        let v = u64::from_le_bytes(
                            extra[vpos..vpos + 8].try_into().unwrap_or_default(),
                        );
                        if v != 0 && v != u64::from(c_uncomp) {
                            return false;
                        }
                        vpos += 8;
                    }
                    if size_pair || missing_comp {
                        let v = u64::from_le_bytes(
                            extra[vpos..vpos + 8].try_into().unwrap_or_default(),
                        );
                        if v != 0 && v != u64::from(c_comp) {
                            return false;
                        }
                    }
                }
                pos += flen;
            }
            if !found_zip64 {
                return false;
            }
        }

        let mut local_record_end = local_data_off + u64::from(c_comp);
        if l_flags & ZIP_FLAG_DATA_DESCRIPTOR != 0 {
            // Nonzero local placeholders must agree with the CD values.
            if (l_crc != 0 && l_crc != c_crc)
                || (l_comp != 0 && l_comp != 0xFFFF_FFFF && l_comp != c_comp)
                || (l_uncomp != 0 && l_uncomp != 0xFFFF_FFFF && l_uncomp != c_uncomp)
            {
                return false;
            }
            // Data descriptor validation at local_record_end.
            let avail = cd_offset.saturating_sub(local_record_end);
            let read_size = (if local_zip64 { 24 } else { 16 }).min(avail);
            let mut desc_ok = false;
            let mut desc_size = 0u64;
            let mut desc = vec![0u8; read_size as usize];
            if read_size < 12 || view.read_exact_at(local_record_end, &mut desc).is_ok() {
                if local_zip64 {
                    if desc.len() >= 24
                        && u32le(&desc, 0) == DATA_DESCRIPTOR_U32
                        && u32le(&desc, 4) == c_crc
                        && u64::from_le_bytes(desc[8..16].try_into().unwrap_or_default())
                            == u64::from(c_comp)
                        && u64::from_le_bytes(desc[16..24].try_into().unwrap_or_default())
                            == u64::from(c_uncomp)
                    {
                        desc_ok = true;
                        desc_size = 24;
                    }
                    if !desc_ok
                        && desc.len() >= 20
                        && u32le(&desc, 0) == c_crc
                        && u64::from_le_bytes(desc[4..12].try_into().unwrap_or_default())
                            == u64::from(c_comp)
                        && u64::from_le_bytes(desc[12..20].try_into().unwrap_or_default())
                            == u64::from(c_uncomp)
                    {
                        desc_ok = true;
                        desc_size = 20;
                    }
                }
                if !local_zip64
                    && desc.len() >= 16
                    && u32le(&desc, 0) == DATA_DESCRIPTOR_U32
                    && u32le(&desc, 4) == c_crc
                    && u32le(&desc, 8) == c_comp
                    && u32le(&desc, 12) == c_uncomp
                {
                    desc_ok = true;
                    desc_size = 16;
                }
                if !local_zip64
                    && !desc_ok
                    && desc.len() >= 12
                    && u32le(&desc, 0) == c_crc
                    && u32le(&desc, 4) == c_comp
                    && u32le(&desc, 8) == c_uncomp
                {
                    desc_ok = true;
                    desc_size = 12;
                }
            }
            if !desc_ok {
                return false;
            }
            local_record_end += desc_size;
        }
        ranges.push((c_local_off, local_record_end));
        cur += record_size;
    }

    // Local record ranges must be ordered and non-overlapping.
    ranges.sort_by_key(|r| r.0);
    for (i, &(start, end)) in ranges.iter().enumerate() {
        if end <= start || end > cd_offset || (i > 0 && start < ranges[i - 1].1) {
            return false;
        }
    }

    // Optional digital-signature / archive-extra records fill the gap
    // between the last central header and the ECD.
    while cur < ecd {
        if ecd - cur < 6 {
            return false;
        }
        let mut opt = [0u8; 8];
        let opt_len = 8.min(ecd - cur) as usize;
        if view.read_exact_at(cur, &mut opt[..opt_len]).is_err() {
            return false;
        }
        let sig = u32le(&opt, 0);
        let record_size = if sig == CD_SIGNATURE_U32 {
            6 + u64::from(u16le(&opt, 4))
        } else if sig == ARCHIVE_EXTRA_U32 {
            if ecd - cur < 8 {
                return false;
            }
            8 + u64::from(u32le(&opt, 4))
        } else {
            return false;
        };
        if record_size == 0 || record_size > ecd - cur {
            return false;
        }
        cur += record_size;
    }

    cur == ecd
}

/// Port of upstream `XZip::findECDOffset`: locate a *valid* EOCD record in
/// the trailing `0xFFFF + 22` bytes. Candidates are tried rightmost first;
/// each must pass the ECD field checks plus the full central-directory
/// cross-validation. Returns the absolute ECD offset.
fn find_eocd(view: &ByteView<'_>) -> Option<u64> {
    let len = view.len();
    if len < ECD_SIZE {
        return None;
    }
    let scan_len = len.min(EOCD_SCAN_MAX);
    let start = len - scan_len;
    let mut buf = vec![0u8; scan_len as usize];
    view.read_exact_at(start, &mut buf).ok()?;

    // Collect all PK\x05\x06 candidates, then iterate rightmost first.
    let mut positions: Vec<usize> = Vec::new();
    for (i, w) in buf.windows(4).enumerate() {
        if w == EOCD_MAGIC {
            positions.push(i);
        }
    }
    for &pos in positions.iter().rev() {
        let cur = start + pos as u64;
        if len - cur < ECD_SIZE {
            continue;
        }
        let ecd = &buf[pos..pos + ECD_SIZE as usize];
        if ecd[0..4] != EOCD_MAGIC {
            continue;
        }
        let comment_len = u64::from(u16le(ecd, 20));
        if comment_len > len - cur - ECD_SIZE {
            continue;
        }
        let disk_number = u16le(ecd, 4);
        let start_disk = u16le(ecd, 6);
        let disk_records = u16le(ecd, 8);
        let total_records = u16le(ecd, 10);
        let cd_size = u64::from(u32le(ecd, 12));
        let cd_offset = u64::from(u32le(ecd, 16));
        if disk_number != 0
            || start_disk != 0
            || disk_records != total_records
            || total_records == 0xFFFF
            || cd_size == 0xFFFF_FFFF
            || cd_offset == 0xFFFF_FFFF
        {
            continue;
        }
        if total_records == 0 {
            if cd_size == 0 && cd_offset == cur {
                return Some(cur);
            }
            continue;
        }
        if cd_offset > cur || cd_size != cur - cd_offset {
            continue;
        }
        if validate_central_directory(view, cur, u32::from(total_records), cd_offset) {
            return Some(cur);
        }
    }
    None
}

/// Read central directory member names referenced by the EOCD at `eocd`.
/// Bounded by `MAX_CD_RECORDS` and by the declared directory size.
fn read_cd_entries(view: &ByteView<'_>, eocd: u64) -> Vec<CdEntry> {
    let entry_count = view.read_u16_le(eocd + 10).unwrap_or(0) as u32;
    let cd_size = u64::from(view.read_u32_le(eocd + 12).unwrap_or(0));
    let cd_offset = u64::from(view.read_u32_le(eocd + 16).unwrap_or(0));

    let mut entries = Vec::new();
    let mut off = cd_offset;
    let cd_end = cd_offset.saturating_add(cd_size).min(view.len());
    for _ in 0..entry_count.min(MAX_CD_RECORDS) {
        if off + 46 > cd_end {
            break;
        }
        let mut sig = [0u8; 4];
        if view.read_exact_at(off, &mut sig).is_err() || sig != CD_MAGIC {
            break;
        }
        let usize_ = view.read_u32_le(off + 24).unwrap_or(0);
        let name_len = u64::from(view.read_u16_le(off + 28).unwrap_or(0));
        let extra_len = u64::from(view.read_u16_le(off + 30).unwrap_or(0));
        let comment_len = u64::from(view.read_u16_le(off + 32).unwrap_or(0));
        let name_start = off + 46;
        if name_start + name_len > cd_end {
            break;
        }
        let mut name = vec![0u8; name_len as usize];
        if view.read_exact_at(name_start, &mut name).is_err() {
            break;
        }
        entries.push(CdEntry {
            name,
            uncompressed_size: usize_,
        });
        off = name_start + name_len + extra_len + comment_len;
    }
    entries
}

/// True when `name` is an IPA-style `Payload/<App>.app/Info.plist` record,
/// mirroring upstream `isInfoPlistRecord` (Formats/archives/xipa.cpp):
/// exactly one path component between `Payload/` and `/Info.plist`, longer
/// than 4 chars, ending in `.app`.
fn is_ipa_info_plist(name: &[u8]) -> bool {
    let name: Vec<u8> = name
        .iter()
        .map(|&c| if c == b'\\' { b'/' } else { c })
        .collect();
    if !name.starts_with(b"Payload/") || !name.ends_with(b"/Info.plist") {
        return false;
    }
    let app = &name[8..name.len() - 11];
    !app.contains(&b'/') && app.len() > 4 && app.ends_with(b".app")
}

/// Classify a ZIP container by member names, mirroring upstream
/// `XFormats::getFileTypesZIP` precedence (APK > IPA > JAR > ZIP).
/// The upstream check also decompresses the marker record; the name+size
/// check here is a documented approximation.
fn classify_zip(entries: &[CdEntry]) -> &'static str {
    let has = |n: &[u8]| {
        entries
            .iter()
            .any(|e| e.name == n && e.uncompressed_size > 0)
    };
    if has(b"AndroidManifest.xml") {
        "APK"
    } else if entries
        .iter()
        .any(|e| e.uncompressed_size > 0 && is_ipa_info_plist(&e.name))
    {
        "IPA"
    } else if has(b"META-INF/MANIFEST.MF") {
        "JAR"
    } else {
        "ZIP"
    }
}

impl FormatProbe for ZipProbe {
    fn file_type(&self) -> FileType {
        FileType::new("ZIP")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        // Upstream `XZip::isValid` (xzip.cpp): a fully validated
        // end-of-central-directory record (CD records cross-checked against
        // local headers) makes the file a ZIP; subtype classification comes
        // from member names.
        if let Some(eocd) = find_eocd(view) {
            let entries = read_cd_entries(view, eocd);
            return Ok(Some(ProbeOutcome {
                candidate: strong_deferred(classify_zip(&entries)),
            }));
        }

        // Central-directory-less streams: a `PK\x03\x04` at offset 0 plus at
        // least one complete local record, and NO ECD signature anywhere
        // after the records (otherwise the upstream strict path above
        // already rejected the file and this fallback must not rescue it).
        if view.len() >= 4 && view.read_u32_le(0).ok() == Some(LFD_MAGIC_U32) {
            let (count, real_size) = count_local_file_headers(view, 0, view.len());
            if count > 0 && real_size > 0 && !is_ecd_sig_present(view, real_size) {
                return Ok(Some(ProbeOutcome {
                    candidate: strong_deferred("ZIP"),
                }));
            }
        }
        Ok(None)
    }
}

/// Maximum RAR5 header size (upstream `XRAR_MAX_RAR5_HEADER_SIZE`).
const RAR5_MAX_HEADER: u64 = 4 * 1024 * 1024;
/// Upstream record bound (`XRAR_MAX_RECORDS`); far above any probe need.
const RAR_MAX_RECORDS: u32 = 1_000_000;

/// Read a RAR4 generic block snapshot at `off`, mirroring upstream
/// `XRar::readBlock4Snapshot`: 7-byte fixed prefix, `HEAD_SIZE` at +5
/// (u16le, must be >= 7), plus the RAR 1.5 owner-data (`SUBBLOCK`/`0x101`)
/// extension that appends a name list beyond `HEAD_SIZE`.
fn rar4_block_snapshot(view: &ByteView<'_>, off: u64) -> Option<Vec<u8>> {
    let mut fixed = [0u8; 7];
    view.read_exact_at(off, &mut fixed).ok()?;
    let header_size = u16::from_le_bytes([fixed[5], fixed[6]]) as usize;
    if header_size < 7 {
        return None;
    }
    let mut header = fixed.to_vec();
    if header_size > 7 {
        header.resize(header_size, 0);
        view.read_exact_at(off, &mut header).ok()?;
    }
    // Owner-data blocks (type 0x77, LONG_BLOCK, HEAD_SIZE=18, magic 0x101)
    // carry a name list of `names` bytes right after the fixed header.
    if header.len() >= 18
        && header[2] == 0x77
        && u16::from_le_bytes([header[3], header[4]]) & 0x8000 != 0
        && u16::from_le_bytes([header[5], header[6]]) == 18
        && u16::from_le_bytes([header[11], header[12]]) == 0x0101
    {
        let names = u16::from_le_bytes([header[14], header[15]]) as usize
            + u16::from_le_bytes([header[16], header[17]]) as usize;
        if names as u64 == u32::from_le_bytes([header[7], header[8], header[9], header[10]]) as u64
        {
            let base = header.len();
            header.resize(base + names, 0);
            view.read_exact_at(off + base as u64, &mut header[base..])
                .ok()?;
        }
    }
    Some(header)
}

/// Byte count covered by a RAR4 `HEAD_CRC`, mirroring upstream
/// `xrarHeaderCRCSize4` per-type quirks. `None` when the layout cannot be
/// checksummed.
fn rar4_crc_size(h: &[u8]) -> Option<usize> {
    if h.len() < 7 {
        return None;
    }
    let btype = h[2];
    let flags = u16::from_le_bytes([h[3], h[4]]);
    let mut size = h.len();
    if btype == 0x73 && flags & 0x0002 != 0 {
        // Archive header with comment: CRC covers the first 13 bytes only.
        size = 13;
        if size > h.len() || h.len() - size < 13 {
            return None;
        }
    } else if btype == 0x74 && flags & 0x0008 != 0 {
        // Pre-RAR3 comment layout.
        if h.len() < 32 || h[24] >= 29 || flags & 0x1400 != 0 {
            return None;
        }
        size = 32
            + if flags & 0x0100 != 0 { 8 } else { 0 }
            + u16::from_le_bytes([h[26], h[27]]) as usize;
        if size > h.len() || h.len() - size < 13 {
            return None;
        }
    } else if btype == 0x75 {
        return (h.len() >= 13).then_some(13);
    } else if btype == 0x76 {
        // Old-style AV header: accept the narrow 14-byte CRC form only
        // when it verifies; otherwise the CRC covers the whole header.
        if h.len() >= 14 {
            let crc = !crc32_ieee(&h[2..14]);
            if (crc & 0xFFFF) as u16 == u16::from_le_bytes([h[0], h[1]]) {
                return Some(14);
            }
        }
    }
    Some(size)
}

/// Parsed RAR4 generic block after snapshot + CRC validation, mirroring
/// upstream `parseGenericBlock4Snapshot` (HEAD_CRC is the low 16 bits of a
/// standard CRC32 over the covered bytes).
struct Rar4Block {
    btype: u8,
    flags: u16,
    header_size: usize,
}

/// Parse and CRC-verify a RAR4 block snapshot.
fn rar4_parse_block(h: &[u8]) -> Option<Rar4Block> {
    if h.len() < 7 || h.len() > 18 + 2 * 0xFFFF {
        return None;
    }
    let crc16 = u16::from_le_bytes([h[0], h[1]]);
    let btype = h[2];
    let flags = u16::from_le_bytes([h[3], h[4]]);
    let header_size = u16::from_le_bytes([h[5], h[6]]) as usize;
    // Owner-data blocks legitimately extend beyond HEAD_SIZE.
    let owner_data = h.len() >= 18
        && btype == 0x77
        && flags & 0x8000 != 0
        && header_size == 18
        && u16::from_le_bytes([h[11], h[12]]) == 0x0101
        && (u16::from_le_bytes([h[14], h[15]]) as usize
            + u16::from_le_bytes([h[16], h[17]]) as usize)
            == u32::from_le_bytes([h[7], h[8], h[9], h[10]]) as usize;
    if owner_data {
        if h.len() != 18 + (u32::from_le_bytes([h[7], h[8], h[9], h[10]]) as usize) {
            return None;
        }
    } else if header_size != h.len() {
        return None;
    }
    let crc_size = rar4_crc_size(h)?;
    if crc_size < 7 || crc_size > h.len() {
        return None;
    }
    let crc = !crc32_ieee(&h[2..crc_size]);
    if (crc & 0xFFFF) as u16 != crc16 {
        return None;
    }
    Some(Rar4Block {
        btype,
        flags,
        header_size,
    })
}

/// Walk a RAR4 block chain exactly like upstream `XRar::initUnpack`
/// (version-4 branch): MAIN_HEAD must follow the marker, then a
/// CRC-verified block sequence must either reach `ENDARC_HEAD` or end
/// exactly at EOF with at least one pre-RAR5 file block.
fn is_valid_rar4(view: &ByteView<'_>) -> bool {
    let total = view.len();
    let main = rar4_block_snapshot(view, 7).and_then(|h| rar4_parse_block(&h));
    let main = match main {
        Some(b) if b.btype == 0x73 && b.header_size >= 13 => b,
        _ => return false,
    };
    let mut off = 7 + main.header_size as u64;
    // Encrypted headers: upstream accepts the archive when more data follows.
    if main.flags & 0x0080 != 0 {
        return off < total;
    }
    let mut block_count: u32 = 0;
    let mut files = 0u32;
    let mut all_unp_ver_old = true;
    let mut reached_end = false;
    while off < total {
        if block_count >= RAR_MAX_RECORDS {
            return false;
        }
        let snap = match rar4_block_snapshot(view, off) {
            Some(s) => s,
            None => return false,
        };
        let block = match rar4_parse_block(&snap) {
            Some(b) => b,
            None => return false,
        };
        if !(0x72..=0x7B).contains(&block.btype) {
            return false;
        }
        let mut data_size: u64 = 0;
        if block.btype == 0x74 || block.btype == 0x7A {
            // FILE / new-style subblock: header must hold the fixed file
            // fields (7 generic + 25 file bytes).
            if block.header_size < 32 {
                return false;
            }
            let pack = u32::from_le_bytes([snap[7], snap[8], snap[9], snap[10]]) as u64;
            if block.flags & 0x0100 != 0 {
                // LHD_LARGE: high 32 bits of pack size follow the attrs.
                let high = u32::from_le_bytes([snap[32], snap[33], snap[34], snap[35]]) as u64;
                data_size = pack | (high << 32);
            } else {
                data_size = pack;
            }
            if block.btype == 0x74 {
                files += 1;
                // unpVer at header offset 24; RAR5-era files (>= 29) must
                // not appear in a v4 chain without ENDARC.
                if snap[24] >= 29 {
                    all_unp_ver_old = false;
                }
            }
        } else if block.flags & 0x8000 != 0 {
            // LONG_BLOCK: data size stored right after the generic header.
            if block.header_size < 11 {
                return false;
            }
            data_size = u32::from_le_bytes([snap[7], snap[8], snap[9], snap[10]]) as u64;
        }
        let block_size = block.header_size as u64 + data_size;
        if block_size > total - off {
            return false;
        }
        off += block_size;
        block_count += 1;
        if block.btype == 0x7B {
            reached_end = true;
            break;
        }
    }
    if !reached_end && (off != total || files == 0 || !all_unp_ver_old) {
        return false;
    }
    true
}

/// Read a bounded RAR5 varint (`xrarReadVInt`, max 10 bytes).
fn rar5_vint(h: &[u8], pos: &mut usize, end: usize, max_bytes: usize) -> Option<u64> {
    if *pos >= end || max_bytes == 0 || max_bytes > 10 {
        return None;
    }
    let limit = (*pos + max_bytes).min(end).min(h.len());
    let mut value: u64 = 0;
    let mut shift = 0u32;
    while *pos < limit {
        let b = h[*pos];
        *pos += 1;
        value |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

/// A parsed RAR5 generic header, mirroring `GENERICHEADER5`.
struct Rar5Header {
    /// Total on-disk header size (crc32 + size vint + body).
    header_size: u64,
    /// Header-type vint.
    btype: u64,
    /// Header flags (bit0: extra area, bit1: data area, bit2: skip check).
    flags: u64,
    /// Extra-area size when flag bit0 is set.
    extra_size: u64,
    /// Trailing data size when flag bit1 is set.
    data_size: u64,
    /// Offset of the body within the snapshot (after type/flags/area vints).
    body_off: usize,
}

/// Read a complete RAR5 header snapshot at `off`, mirroring upstream
/// `readHeader5Snapshot` + `parseGenericHeader5Snapshot` (including the
/// header CRC32 check).
fn rar5_header(view: &ByteView<'_>, off: u64) -> Option<Rar5Header> {
    let total = view.len();
    if total - off.min(total) < 7 {
        return None;
    }
    let prefix_size = 14usize.min((total - off) as usize);
    let mut prefix = vec![0u8; prefix_size];
    view.read_exact_at(off, &mut prefix).ok()?;
    let mut pos = 4usize;
    let data_size = rar5_vint(&prefix, &mut pos, prefix.len(), 10)?;
    if !(2..=RAR5_MAX_HEADER).contains(&data_size) {
        return None;
    }
    let total_header = 4 + (pos as u64 - 4) + data_size;
    if total_header > RAR5_MAX_HEADER || total_header > total - off {
        return None;
    }
    let header_len = total_header as usize;
    let mut h = prefix;
    if h.len() < header_len {
        h.resize(header_len, 0);
        view.read_exact_at(off, &mut h).ok()?;
    } else {
        h.truncate(header_len);
    }
    // parseGenericHeader5Snapshot.
    if h.len() < 7 {
        return None;
    }
    let crc32_field = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    let mut pos = 4usize;
    let size_vint = rar5_vint(&h, &mut pos, h.len(), 10)?;
    if !(2..=RAR5_MAX_HEADER).contains(&size_vint) {
        return None;
    }
    if 4 + (pos as u64 - 4) + size_vint != h.len() as u64 {
        return None;
    }
    let btype = rar5_vint(&h, &mut pos, h.len(), 10)?;
    let flags = rar5_vint(&h, &mut pos, h.len(), 10)?;
    let extra_size = if flags & 0x0001 != 0 {
        rar5_vint(&h, &mut pos, h.len(), 10)?
    } else {
        0
    };
    let data = if flags & 0x0002 != 0 {
        rar5_vint(&h, &mut pos, h.len(), 10)?
    } else {
        0
    };
    if extra_size > (h.len() - pos) as u64 {
        return None;
    }
    if (!crc32_ieee(&h[4..])) != crc32_field {
        return None;
    }
    Some(Rar5Header {
        header_size: total_header,
        btype,
        flags,
        extra_size,
        data_size: data,
        body_off: pos,
    })
}

/// Validate a MAIN or ENDARC header body, mirroring the
/// `isMainOrEndHeader5Valid` archive-flags check (ENDARC: none; MAIN:
/// flags vint, optional volume-number vint when flag 0x2 is set).
fn rar5_main_or_end_valid(h: &[u8], hdr: &Rar5Header) -> bool {
    if hdr.btype != 1 && hdr.btype != 5 {
        return false;
    }
    let body_end = h.len() - hdr.extra_size as usize;
    let mut pos = hdr.body_off;
    let archive_flags = match rar5_vint(h, &mut pos, body_end, 10) {
        Some(v) => v,
        None => return false,
    };
    if hdr.btype == 1 && archive_flags & 0x0002 != 0 {
        // Volume number follows when MHFL_VOLNUMBER is set.
        if rar5_vint(h, &mut pos, body_end, 10).is_none() {
            return false;
        }
    }
    true
}

/// Walk a RAR5 header chain like the upstream `initUnpack` version-5
/// branch: the first header must be MAIN (or a lone ENCRYPTION header),
/// each header carries a valid CRC32, and the chain ends at ENDARC —
/// unless an ENCRYPTION header stops parsing (no password available).
fn is_valid_rar5(view: &ByteView<'_>) -> bool {
    let total = view.len();
    let mut off = 8u64;
    let mut header_count: u32 = 0;
    let mut saw_main = false;
    let mut reached_end = false;
    let mut stopped_encrypted = false;
    while off < total {
        if header_count >= RAR_MAX_RECORDS {
            return false;
        }
        let snap_len;
        let hdr = {
            let h = match rar5_header(view, off) {
                Some(h) => h,
                None => return false,
            };
            // Read the raw snapshot again for the body checks.
            snap_len = h.header_size;
            let mut buf = vec![0u8; snap_len as usize];
            if view.read_exact_at(off, &mut buf).is_err() {
                return false;
            }
            (buf, h)
        };
        let (raw, hdr) = hdr;
        let header_end = off + hdr.header_size;
        if hdr.data_size > total - header_end
            || (hdr.btype > 5 && hdr.flags & 0x0004 == 0)
            || hdr.btype == 0
        {
            return false;
        }
        match hdr.btype {
            1 => {
                // MAIN
                if saw_main || header_count != 0 || hdr.data_size != 0 {
                    return false;
                }
                if !rar5_main_or_end_valid(&raw, &hdr) {
                    return false;
                }
                saw_main = true;
            }
            4 => {
                // ENCRYPTION: valid only as the first header; upstream then
                // stops (no password) and accepts if more data follows.
                if header_count != 0 {
                    return false;
                }
                if header_end + hdr.data_size >= total {
                    return false;
                }
                stopped_encrypted = true;
                break;
            }
            2 | 3 => {
                if !saw_main {
                    return false;
                }
                // FILE / SERVICE: upstream re-parses the file header; the
                // generic header already validated size+CRC here.
            }
            5 => {
                // ENDARC
                if !saw_main || !rar5_main_or_end_valid(&raw, &hdr) {
                    return false;
                }
                reached_end = true;
                break;
            }
            _ => {
                if !saw_main {
                    return false;
                }
            }
        }
        off = header_end + hdr.data_size;
        header_count += 1;
    }
    reached_end || stopped_encrypted
}

/// Walk a RAR 1.4 (`RE~^`) FILEBLOCK14 chain, mirroring the version-1
/// branch of upstream `initUnpack`: fixed 24-byte header starting with
/// `07 00`, `HEAD_SIZE = 24 + nameLen@22`, records must tile to EOF.
fn is_valid_rar14(view: &ByteView<'_>) -> bool {
    let total = view.len();
    let mut off = 4u64;
    let mut records: u32 = 0;
    while off < total {
        if records >= RAR_MAX_RECORDS {
            return false;
        }
        let mut fixed = [0u8; 24];
        if view.read_exact_at(off, &mut fixed).is_err() || fixed[0] != 0x07 || fixed[1] != 0x00 {
            return false;
        }
        let header_size = 24u64 + u64::from(fixed[22]);
        let pack_size = u32::from_le_bytes([fixed[3], fixed[4], fixed[5], fixed[6]]) as u64;
        let record_size = header_size + pack_size;
        if record_size > total - off {
            return false;
        }
        off += record_size;
        records += 1;
    }
    records > 0 && off == total
}

impl FormatProbe for RarProbe {
    fn file_type(&self) -> FileType {
        FileType::new("RAR")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        if view.len() >= 8 {
            let mut magic8 = [0u8; 8];
            view.read_exact_at(0, &mut magic8)
                .map_err(|cause| ProbeError::Truncated {
                    file_type: FileType::new("RAR"),
                    cause,
                })?;
            if magic8 == RAR5_MAGIC {
                return Ok(is_valid_rar5(view).then_some(ProbeOutcome {
                    candidate: strong_deferred("RAR"),
                }));
            }
        }
        if view.len() >= 7 {
            let mut magic = [0u8; 7];
            view.read_exact_at(0, &mut magic)
                .map_err(|cause| ProbeError::Truncated {
                    file_type: FileType::new("RAR"),
                    cause,
                })?;
            if magic == RAR4_MAGIC {
                return Ok(is_valid_rar4(view).then_some(ProbeOutcome {
                    candidate: strong_deferred("RAR"),
                }));
            }
        }
        // RAR 1.4 used the `RE~^` marker (upstream `getInternVersion` = 1).
        if view.len() >= 5 {
            let mut m = [0u8; 4];
            if view.read_exact_at(0, &mut m).is_ok() && m == *b"RE~^" && is_valid_rar14(view) {
                return Ok(Some(ProbeOutcome {
                    candidate: strong_deferred("RAR"),
                }));
            }
        }
        Ok(None)
    }
}

/// IEEE CRC32 (poly 0xEDB88320) used by RAR4/RAR5 header checksums.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc
}

impl FormatProbe for SevenZProbe {
    fn file_type(&self) -> FileType {
        FileType::new("7Z")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        if view.len() < 6 {
            return Ok(None);
        }
        let mut magic = [0u8; 6];
        view.read_exact_at(0, &mut magic)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("7Z"),
                cause,
            })?;
        if magic == SEVENZ_MAGIC {
            Ok(Some(ProbeOutcome {
                candidate: strong_deferred("7Z"),
            }))
        } else {
            Ok(None)
        }
    }
}

impl FormatProbe for GzipProbe {
    fn file_type(&self) -> FileType {
        FileType::new("GZIP")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        if view.len() < 2 {
            return Ok(None);
        }
        let mut magic = [0u8; 2];
        view.read_exact_at(0, &mut magic)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("GZIP"),
                cause,
            })?;
        if magic == GZIP_MAGIC {
            Ok(Some(ProbeOutcome {
                candidate: strong_deferred("GZIP"),
            }))
        } else {
            Ok(None)
        }
    }
}

impl FormatProbe for TarProbe {
    fn file_type(&self) -> FileType {
        FileType::new("TAR")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        // USTAR magic is at offset 257, need at least 262 bytes.
        if view.len() < USTAR_OFFSET + 5 {
            return Ok(None);
        }
        let mut magic = [0u8; 5];
        view.read_exact_at(USTAR_OFFSET, &mut magic)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("TAR"),
                cause,
            })?;
        if magic == USTAR_MAGIC {
            Ok(Some(ProbeOutcome {
                candidate: strong_deferred("TAR"),
            }))
        } else {
            Ok(None)
        }
    }
}

/// ISO9660 logical sector size (2048 bytes).
const ISO_SECTOR: u64 = 2048;

/// Validate an ISO9660 volume descriptor chain, mirroring upstream
/// `selectIsoDescriptor` (Formats/archives/xiso9660.cpp): sectors 16..272
/// must form a `CD001` (version 1) descriptor sequence containing at least
/// one primary (type 1) or Joliet (type 2 with %/@, %/E or %/G escape
/// sequences) descriptor, terminated by a type-255 record.
fn has_valid_iso9660_chain(view: &ByteView<'_>) -> bool {
    let sector_count = view.len() / ISO_SECTOR;
    // Upstream requires at least sectors 0..16 plus one descriptor sector.
    if sector_count < 17 {
        return false;
    }
    let scan_end = sector_count.min(16 + 256);
    let mut found_terminator = false;
    let mut found_primary = false;
    let mut found_joliet = false;
    for sector in 16..scan_end {
        let off = sector * ISO_SECTOR;
        let mut head = [0u8; 7];
        if view.read_exact_at(off, &mut head).is_err() {
            return false;
        }
        if head[1..6] != ISO9660_MAGIC || head[6] != 1 {
            break;
        }
        match head[0] {
            255 => {
                found_terminator = true;
                break;
            }
            1 => found_primary = true,
            2 => {
                // Joliet supplementary descriptors carry UCS-2 escape
                // sequences at offset 88 within the sector.
                let mut esc = [0u8; 3];
                if view.read_exact_at(off + 88, &mut esc).is_err() {
                    return false;
                }
                if esc == *b"%/@" || esc == *b"%/E" || esc == *b"%/G" {
                    found_joliet = true;
                }
            }
            _ => {}
        }
    }
    found_terminator && (found_primary || found_joliet)
}

impl FormatProbe for Iso9660Probe {
    fn file_type(&self) -> FileType {
        FileType::new("ISO9660")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        // ISO9660 volume descriptors start at sector 16 (offset 0x8000).
        if view.len() < ISO9660_OFFSET + ISO_SECTOR {
            return Ok(None);
        }
        let mut head = [0u8; 7];
        view.read_exact_at(ISO9660_OFFSET, &mut head)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("ISO9660"),
                cause,
            })?;
        if head[1..6] != ISO9660_MAGIC {
            return Ok(None);
        }
        Ok(has_valid_iso9660_chain(view).then_some(ProbeOutcome {
            candidate: strong_deferred("ISO9660"),
        }))
    }
}

impl FormatProbe for CabProbe {
    fn file_type(&self) -> FileType {
        FileType::new("CAB")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        if view.len() < 4 {
            return Ok(None);
        }
        let mut magic = [0u8; 4];
        view.read_exact_at(0, &mut magic)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("CAB"),
                cause,
            })?;
        if magic == CAB_MAGIC {
            Ok(Some(ProbeOutcome {
                candidate: strong_deferred("CAB"),
            }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::FormatProbe;
    use diec_core::format::FormatStrength;
    use diec_core::input::{ByteRange, ByteSource, ByteView, MemorySource};

    fn view_of<'a>(src: &'a MemorySource<'a>) -> ByteView<'a> {
        ByteView::new(src, ByteRange::new(0, src.len()).unwrap()).unwrap()
    }

    /// Build an empty ZIP (EOCD record only, 22 bytes).
    fn empty_zip() -> Vec<u8> {
        let mut d = vec![0x50, 0x4B, 0x05, 0x06];
        d.extend_from_slice(&[0u8; 18]);
        d
    }

    /// Build a minimal RAR4 file: marker block + one MAIN_HEAD-like block
    /// (type 0x73, size 7).
    fn minimal_rar4() -> Vec<u8> {
        // Marker + CRC-valid MAIN_HEAD (type 0x73, size 13) + ENDARC
        // (type 0x7B, size 7); HEAD_CRC = low16 of ~CRC32(bytes[2..]).
        let mut d = RAR4_MAGIC.to_vec();
        d.extend_from_slice(&[
            0xCF, 0x90, 0x73, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        d.extend_from_slice(&[0x04, 0xB0, 0x7B, 0x00, 0x00, 0x07, 0x00]);
        d
    }

    /// Build a minimal RAR5 file: 8-byte magic + crc32(4) + varint size(4)
    /// + 4-byte header body.
    fn minimal_rar5() -> Vec<u8> {
        // Magic + CRC32-valid MAIN header (type 1, size-3 body
        // [type,flags,archiveFlags]) + ENDARC header (type 5).
        let mut d = RAR5_MAGIC.to_vec();
        d.extend_from_slice(&[0xC5, 0x1A, 0x33, 0x32, 0x03, 0x01, 0x00, 0x00]);
        d.extend_from_slice(&[0x19, 0xB2, 0x3A, 0x35, 0x03, 0x05, 0x00, 0x00]);
        d
    }

    /// Build a minimal ISO9660 image: sector 16 = primary descriptor,
    /// sector 17 = terminator.
    fn minimal_iso9660() -> Vec<u8> {
        let mut d = vec![0u8; 18 * ISO_SECTOR as usize];
        d[0x8000] = 1;
        d[0x8001..0x8006].copy_from_slice(&ISO9660_MAGIC);
        d[0x8006] = 1;
        d[0x8800] = 255;
        d[0x8801..0x8806].copy_from_slice(&ISO9660_MAGIC);
        d[0x8806] = 1;
        d
    }

    #[test]
    fn zip_matches() {
        let data = empty_zip();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ZipProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "ZIP");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
    }

    /// Build a minimal ZIP whose central directory holds one record
    /// named `name` with non-zero uncompressed size.
    /// Build a structurally valid single-member ZIP: local file header +
    /// data + central directory + EOCD, matching upstream
    /// `XZip::findECDOffset` cross-validation.
    fn zip_with_member(name: &[u8]) -> Vec<u8> {
        let data = [0x41u8]; // single byte payload
        // Local file header (30 bytes) + name + data.
        let mut d = Vec::new();
        d.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // LFD
        d.push(20); // nMinVersion
        d.push(0); // nMinOS
        d.extend_from_slice(&[0u8; 2]); // flags
        d.extend_from_slice(&[0u8; 2]); // method = store
        d.extend_from_slice(&[0u8; 4]); // mod time + date
        d.extend_from_slice(&[0u8; 4]); // crc32
        d.extend_from_slice(&1u32.to_le_bytes()); // csize
        d.extend_from_slice(&1u32.to_le_bytes()); // usize
        d.extend_from_slice(&(name.len() as u16).to_le_bytes());
        d.extend_from_slice(&[0u8; 2]); // extra len
        d.extend_from_slice(name);
        d.extend_from_slice(&data);
        let cd_offset = d.len() as u32;
        // Central directory header (46 bytes) + name.
        let mut cd = Vec::new();
        cd.extend_from_slice(&CD_MAGIC);
        cd.push(20); // nVersion
        cd.push(0); // nOS
        cd.push(20); // nMinVersion (must equal lfh)
        cd.push(0); // nMinOS (must equal lfh)
        cd.extend_from_slice(&[0u8; 2]); // flags
        cd.extend_from_slice(&[0u8; 2]); // method = store
        cd.extend_from_slice(&[0u8; 4]); // mod time + date
        cd.extend_from_slice(&[0u8; 4]); // crc32
        cd.extend_from_slice(&1u32.to_le_bytes()); // csize
        cd.extend_from_slice(&1u32.to_le_bytes()); // usize
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0u8; 8]); // extra/comment/disk/int.attr
        cd.extend_from_slice(&[0u8; 4]); // ext.attr
        cd.extend_from_slice(&0u32.to_le_bytes()); // local header offset = 0
        cd.extend_from_slice(name);
        d.extend_from_slice(&cd);
        // EOCD (22 bytes).
        d.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
        d.extend_from_slice(&[0u8; 2]); // disk number
        d.extend_from_slice(&[0u8; 2]); // start disk
        d.extend_from_slice(&1u16.to_le_bytes()); // disk records
        d.extend_from_slice(&1u16.to_le_bytes()); // total records
        d.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        d.extend_from_slice(&cd_offset.to_le_bytes());
        d.extend_from_slice(&[0u8; 2]); // comment len
        d
    }

    #[test]
    fn zip_apk_subtype_detected() {
        let d = zip_with_member(b"AndroidManifest.xml");
        let src = MemorySource::new(&d);
        let view = view_of(&src);
        let outcome = ZipProbe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "APK");
    }

    #[test]
    fn zip_jar_subtype_detected() {
        let d = zip_with_member(b"META-INF/MANIFEST.MF");
        let src = MemorySource::new(&d);
        let view = view_of(&src);
        let outcome = ZipProbe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "JAR");
    }

    #[test]
    fn zip_ipa_subtype_detected() {
        let d = zip_with_member(b"Payload/TestApp.app/Info.plist");
        let src = MemorySource::new(&d);
        let view = view_of(&src);
        let outcome = ZipProbe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "IPA");
    }

    #[test]
    fn zip_plain_member_stays_zip() {
        let d = zip_with_member(b"readme.txt");
        let src = MemorySource::new(&d);
        let view = view_of(&src);
        let outcome = ZipProbe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "ZIP");
    }

    #[test]
    fn zip_stream_with_local_record_matches() {
        // No EOCD: PK\x03\x04 + complete local file header + data.
        let mut d = vec![0x50, 0x4B, 0x03, 0x04];
        d.extend_from_slice(&[0u8; 6]); // version + flags + method
        d.extend_from_slice(&[0u8; 4]); // mod time + date
        d.extend_from_slice(&[0u8; 4]); // crc32
        d.extend_from_slice(&1u32.to_le_bytes()); // csize = 1
        d.extend_from_slice(&1u32.to_le_bytes()); // usize
        d.extend_from_slice(&1u16.to_le_bytes()); // name len = 1
        d.extend_from_slice(&0u16.to_le_bytes()); // extra len = 0
        d.push(b'a'); // name
        d.push(0x00); // data
        let src = MemorySource::new(&d);
        let view = view_of(&src);
        let outcome = ZipProbe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "ZIP");
    }

    #[test]
    fn zip_magic_only_does_not_match() {
        // Bare PK\x03\x04 without ECD or a complete local record: upstream
        // XZip::isValid rejects this.
        let data = [0x50u8, 0x4B, 0x03, 0x04];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(ZipProbe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn zip_too_short_does_not_match() {
        let data = [0x50u8, 0x4B, 0x03];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ZipProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn rar4_matches() {
        let data = minimal_rar4();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = RarProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "RAR");
    }

    #[test]
    fn rar4_marker_only_does_not_match() {
        // Bare 7-byte marker: upstream XRar::isValid requires at least one
        // block header after the marker.
        let data = RAR4_MAGIC.to_vec();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(RarProbe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn rar5_matches() {
        let data = minimal_rar5();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = RarProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "RAR");
    }

    #[test]
    fn rar_too_short_does_not_match() {
        let data = &RAR4_MAGIC[..5];
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = RarProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn sevenz_matches() {
        let data = SEVENZ_MAGIC.to_vec();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = SevenZProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "7Z");
    }

    #[test]
    fn gzip_matches() {
        let data = [0x1Fu8, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = GzipProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "GZIP");
    }

    #[test]
    fn tar_matches() {
        // Minimal tar: 512-byte header with ustar magic at offset 257.
        let mut data = vec![0u8; 512];
        data[257..262].copy_from_slice(&USTAR_MAGIC);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = TarProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "TAR");
    }

    #[test]
    fn tar_too_short_does_not_match() {
        let data = vec![0u8; 256];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = TarProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn iso9660_matches() {
        let data = minimal_iso9660();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = Iso9660Probe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "ISO9660");
    }

    #[test]
    fn iso9660_descriptor_without_terminator_does_not_match() {
        // CD001 at sector 16 but no type-255 terminator: upstream
        // selectIsoDescriptor requires the descriptor chain to terminate.
        let mut data = vec![0u8; 18 * ISO_SECTOR as usize];
        data[0x8000] = 1;
        data[0x8001..0x8006].copy_from_slice(&ISO9660_MAGIC);
        data[0x8006] = 1;
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(Iso9660Probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn iso9660_magic_only_does_not_match() {
        // Sector 16 with type 0 + CD001 but version byte 0: upstream
        // requires descriptor version 1.
        let mut data = vec![0u8; 0x8000 + 6];
        data[0x8000 + 1..0x8000 + 6].copy_from_slice(&ISO9660_MAGIC);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(Iso9660Probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn iso9660_too_short_does_not_match() {
        let data = vec![0u8; 0x8000];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = Iso9660Probe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn cab_matches() {
        let data = [0x4Du8, 0x53, 0x43, 0x46, 0x00, 0x00, 0x00, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = CabProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "CAB");
    }

    // --- Malformed / non-matching tests ---

    #[test]
    fn zip_non_zip_does_not_match() {
        let data = [0x50u8, 0x4B, 0x05, 0x06]; // empty archive sig, not local file header
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ZipProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn rar_non_rar_does_not_match() {
        let data = [0x52u8, 0x61, 0x72, 0x21, 0x00, 0x00, 0x00, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = RarProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn sevenz_non_sevenz_does_not_match() {
        let data = [0x37u8, 0x7A, 0x00, 0x00, 0x00, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = SevenZProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn sevenz_too_short_does_not_match() {
        let data = &SEVENZ_MAGIC[..5];
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = SevenZProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn gzip_non_gzip_does_not_match() {
        let data = [0x1Fu8, 0x00, 0x08, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = GzipProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn gzip_too_short_does_not_match() {
        let data = [0x1Fu8];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = GzipProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn tar_non_ustar_does_not_match() {
        let mut data = vec![0u8; 512];
        // "gnuta" is not "ustar"
        data[257..262].copy_from_slice(b"gnuta");
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = TarProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn tar_boundary_exact_262_bytes_matches() {
        // Exactly enough bytes for ustar magic at offset 257 (257 + 5 = 262).
        let mut data = vec![0u8; 262];
        data[257..262].copy_from_slice(&USTAR_MAGIC);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = TarProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn tar_boundary_261_bytes_does_not_match() {
        // One byte short of the ustar magic end.
        let mut data = vec![0u8; 261];
        data[257..261].copy_from_slice(&USTAR_MAGIC[..4]);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = TarProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn iso9660_non_iso_does_not_match() {
        let mut data = vec![0u8; 0x8006];
        data[0x8001..0x8006].copy_from_slice(b"BEER0");
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = Iso9660Probe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn iso9660_boundary_exact_magic_end_does_not_match() {
        // Bare CD001 marker without a valid descriptor chain is not ISO9660.
        let mut data = vec![0u8; 0x8006];
        data[0x8001..0x8006].copy_from_slice(&ISO9660_MAGIC);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = Iso9660Probe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn iso9660_boundary_one_byte_short_does_not_match() {
        let mut data = vec![0u8; 0x8005];
        data[0x8001..0x8005].copy_from_slice(&ISO9660_MAGIC[..4]);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = Iso9660Probe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn cab_non_cab_does_not_match() {
        // MSCE instead of MSCF.
        let data = [0x4Du8, 0x53, 0x43, 0x45, 0x00, 0x00, 0x00, 0x00];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = CabProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn cab_too_short_does_not_match() {
        let data = [0x4Du8, 0x53, 0x43];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = CabProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    // --- Boundary tests: exact minimum size ---

    #[test]
    fn zip_boundary_exact_4_bytes_does_not_match() {
        // Bare local-file-header magic without ECD or a complete local
        // record is not a ZIP (upstream XZip::isValid).
        let data = ZIP_MAGIC;
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = ZipProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn zip_boundary_3_bytes_does_not_match() {
        let data = &ZIP_MAGIC[..3];
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = ZipProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn rar4_boundary_exact_7_bytes_does_not_match() {
        let data = &RAR4_MAGIC;
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = RarProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn rar5_boundary_exact_8_bytes_does_not_match() {
        let data = &RAR5_MAGIC;
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = RarProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn sevenz_boundary_exact_6_bytes_matches() {
        let data = &SEVENZ_MAGIC;
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = SevenZProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn gzip_boundary_exact_2_bytes_matches() {
        let data = &GZIP_MAGIC;
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = GzipProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn cab_boundary_exact_4_bytes_matches() {
        let data = &CAB_MAGIC;
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = CabProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn empty_input_does_not_match_any_archive() {
        let data: [u8; 0] = [];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        assert!(ZipProbe.probe(&view).unwrap().is_none());
        assert!(RarProbe.probe(&view).unwrap().is_none());
        assert!(SevenZProbe.probe(&view).unwrap().is_none());
        assert!(GzipProbe.probe(&view).unwrap().is_none());
        assert!(TarProbe.probe(&view).unwrap().is_none());
        assert!(Iso9660Probe.probe(&view).unwrap().is_none());
        assert!(CabProbe.probe(&view).unwrap().is_none());
    }
}

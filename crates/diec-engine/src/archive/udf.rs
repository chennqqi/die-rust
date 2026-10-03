//! UDF filesystem image enumeration — port of upstream
//! `xudf.cpp` (`isValid` + `_parseFileSystem`).
//!
//! Detection is deliberately strict, mirroring the hardened upstream
//! code: a candidate must be at least `0x8000 + 2048` bytes and expose
//! an Anchor Volume Descriptor Pointer whose tag checksum, descriptor
//! version (2 or 3), reserved byte, tag location and descriptor CRC
//! all verify (ECMA-167 4/7.2). The non-strict probe is only retried
//! when the Volume Recognition Sequence independently declares an
//! `NSR02`/`NSR03` descriptor between `BEA01` and `TEA01`.
//!
//! Enumeration BFS-walks the file-entry tree from the File Set
//! Descriptor's root ICB, emitting a directory record per non-root
//! directory and a STORE record per regular file (short/long/inline
//! allocation descriptors resolved to a stream offset+size).

use super::SecondaryRecord;

/// UDF logical block size (upstream `_getBlockSize` is fixed 2048).
const BLOCK: u64 = 2048;
const TAG_SIZE: u64 = 16;

/// ECMA-167 tag identifiers used by the walker.
const TAG_AVDP: u16 = 2;
const TAG_LVD: u16 = 6;
const TAG_TERMINATING: u16 = 8;
const TAG_FILE_SET: u16 = 256;
const TAG_FILE_ID: u16 = 257;
const TAG_FILE_ENTRY: u16 = 261;
const TAG_FILE_ENTRY_EXT: u16 = 266;

fn rd_u8(d: &[u8], off: u64) -> Option<u8> {
    d.get(off as usize).copied()
}

fn rd_u16(d: &[u8], off: u64) -> Option<u16> {
    let b = d.get(off as usize..off as usize + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn rd_u32(d: &[u8], off: u64) -> Option<u32> {
    let b = d.get(off as usize..off as usize + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn rd_u64(d: &[u8], off: u64) -> Option<u64> {
    let b = d.get(off as usize..off as usize + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// `UDF_TAG` fields relevant to validation and walking.
#[derive(Clone, Copy, Default)]
struct Tag {
    id: u16,
    version: u16,
    checksum: u8,
    reserved: u8,
    crc: u16,
    crc_len: u16,
    location: u32,
}

fn read_tag(d: &[u8], off: u64) -> Option<Tag> {
    let b = d.get(off as usize..off as usize + TAG_SIZE as usize)?;
    Some(Tag {
        id: u16::from_le_bytes([b[0], b[1]]),
        version: u16::from_le_bytes([b[2], b[3]]),
        checksum: b[4],
        reserved: b[5],
        crc: u16::from_le_bytes([b[8], b[9]]),
        crc_len: u16::from_le_bytes([b[10], b[11]]),
        location: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
    })
}

/// ECMA-167 4/7.2.3 tag checksum: sum of bytes 0-3 and 5-15 mod 256.
fn tag_checksum(b: &[u8]) -> u8 {
    let mut sum: u32 = 0;
    for (i, &v) in b.iter().enumerate().take(16) {
        if i != 4 {
            sum += u32::from(v);
        }
    }
    (sum & 0xFF) as u8
}

/// ECMA-167 Annex A CRC-ITU-T (0x1021, init 0, no reflection/xor).
fn descriptor_crc(d: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in d {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// `_isValidDescriptorTag`: checksum + version + reserved byte always;
/// `strict` additionally requires the recorded sector number to match
/// the descriptor's own sector and the descriptor CRC to verify.
fn is_valid_tag(d: &[u8], off: u64, expected: u16, strict: bool) -> Option<Tag> {
    let tag = read_tag(d, off)?;
    if tag.id != expected {
        return None;
    }
    if tag.version != 2 && tag.version != 3 {
        return None;
    }
    if tag.reserved != 0 {
        return None;
    }
    let raw = d.get(off as usize..off as usize + TAG_SIZE as usize)?;
    if tag_checksum(raw) != tag.checksum {
        return None;
    }
    if strict {
        if u64::from(tag.location) != off / BLOCK {
            return None;
        }
        if tag.crc_len > 0 {
            if u64::from(tag.crc_len) > BLOCK - TAG_SIZE {
                return None;
            }
            let body_off = off.checked_add(TAG_SIZE)? as usize;
            let body = d.get(body_off..body_off + usize::from(tag.crc_len))?;
            if descriptor_crc(body) != tag.crc {
                return None;
            }
        }
    }
    Some(tag)
}

/// `_isAnchorVolumeDescriptorPointer`: valid tag 2 plus a non-empty,
/// block-aligned main VDS extent inside the volume.
fn is_avdp(d: &[u8], off: u64, strict: bool) -> bool {
    if is_valid_tag(d, off, TAG_AVDP, strict).is_none() {
        return false;
    }
    let main_len = match rd_u32(d, off + TAG_SIZE) {
        Some(v) => v,
        None => return false,
    };
    let main_loc = match rd_u32(d, off + TAG_SIZE + 4) {
        Some(v) => v,
        None => return false,
    };
    if main_len == 0 || u64::from(main_len) % BLOCK != 0 {
        return false;
    }
    let main_off = u64::from(main_loc) * BLOCK;
    main_off > 0 && main_off < d.len() as u64
}

/// `_hasVolumeRecognitionSequence`: `NSR02`/`NSR03` between `BEA01`
/// and `TEA01` in the 32 KiB+ VRS area.
fn has_vrs(d: &[u8]) -> bool {
    let mut extended = false;
    for i in 0..64u64 {
        let off = 0x8000 + i * BLOCK;
        let id = match d.get(off as usize + 1..off as usize + 6) {
            Some(v) => v,
            None => break,
        };
        match id {
            b"BEA01" => extended = true,
            b"TEA01" => break,
            b"NSR02" | b"NSR03" if extended => return true,
            b"CD001" | b"CDW02" | b"BOOT2" => {}
            _ => break,
        }
    }
    false
}

/// `_getAnchorVolumeDescriptorOffset`: probe sector 256, last sector,
/// last-256, sector 512 (strict), then non-strict when the VRS claims
/// the volume is UDF.
fn anchor_offset(d: &[u8]) -> Option<u64> {
    let size = d.len() as u64;
    if size < BLOCK {
        return None;
    }
    let last = size / BLOCK - 1;
    let mut candidates = vec![256 * BLOCK, last * BLOCK];
    if last >= 256 {
        candidates.push((last - 256) * BLOCK);
    }
    candidates.push(512 * BLOCK);
    for &off in &candidates {
        if is_avdp(d, off, true) {
            return Some(off);
        }
    }
    if has_vrs(d) {
        for &off in &candidates {
            if is_avdp(d, off, false) {
                return Some(off);
            }
        }
    }
    None
}

/// Upstream `XUDF::isValid`.
pub fn is_udf(d: &[u8]) -> bool {
    d.len() as u64 >= 0x8000 + BLOCK && anchor_offset(d).is_some()
}

/// Decode an OSTA CS0 file identifier: byte 0 selects the alphabet
/// (8 = Latin-1 tail, 16 = UTF-16BE tail).
fn osta_name(raw: &[u8]) -> String {
    match raw.first() {
        Some(8) if raw.len() >= 2 => raw[1..].iter().map(|&b| char::from(b)).collect::<String>(),
        Some(16) if raw.len() >= 3 => raw[1..]
            .chunks_exact(2)
            .map(|p| {
                char::from_u32(u32::from(u16::from_be_bytes([p[0], p[1]]))).unwrap_or('\u{FFFD}')
            })
            .collect(),
        _ => String::new(),
    }
}

/// `_parseFileSystem`: AVDP -> VDS scan for the LVD's FSD extent ->
/// FSD root ICB -> BFS over file entries.
pub fn list(d: &[u8]) -> Option<Vec<SecondaryRecord>> {
    let size = d.len() as u64;
    let anchor_off = anchor_offset(d)?;
    let main_len = u64::from(rd_u32(d, anchor_off + TAG_SIZE)?);
    let main_loc = u64::from(rd_u32(d, anchor_off + TAG_SIZE + 4)?);
    let vds_off = main_loc * BLOCK;
    let vds_end = vds_off + main_len;
    if vds_off == 0 || vds_off >= size {
        return None;
    }

    // Scan VDS sectors for the Logical Volume Descriptor; its FSD
    // extent sits at +248 (LogicalVolumeContentsUse).
    let mut fsd_location: i64 = -1;
    let mut cur = vds_off;
    while cur + TAG_SIZE <= vds_end {
        let tag = match read_tag(d, cur) {
            Some(t) => t,
            None => return Some(Vec::new()),
        };
        if tag.id == TAG_TERMINATING {
            break;
        }
        if tag.id == TAG_LVD {
            let loc = rd_u32(d, cur + 248)?;
            if loc > 0 {
                fsd_location = (u64::from(loc) * BLOCK) as i64;
            }
        }
        cur += BLOCK;
    }
    if fsd_location <= 0 || fsd_location as u64 >= size {
        return Some(Vec::new());
    }
    let fsd_off = fsd_location as u64;

    // File Set Descriptor must carry tag 256; root ICB long_ad at +352
    // (extent location at +352+4).
    match read_tag(d, fsd_off) {
        Some(t) if t.id == TAG_FILE_SET => {}
        _ => return Some(Vec::new()),
    }
    let root_loc = u64::from(rd_u32(d, fsd_off + 352 + 4)?);
    if root_loc == 0 {
        return Some(Vec::new());
    }
    let root_fe = root_loc * BLOCK;
    if root_fe >= size {
        return Some(Vec::new());
    }

    let mut records = Vec::new();
    // Upstream takes the head of the queue (FIFO BFS order).
    let mut queue = std::collections::VecDeque::from([(root_fe, String::new())]);
    let mut visited = vec![root_fe];
    const MAX_ENTRIES: usize = 0x100000;
    while let Some((fe_off, path)) = queue.pop_front() {
        if records.len() + queue.len() + visited.len() >= MAX_ENTRIES {
            break;
        }
        let tag = match read_tag(d, fe_off) {
            Some(t) => t,
            None => return Some(records),
        };
        if tag.id != TAG_FILE_ENTRY && tag.id != TAG_FILE_ENTRY_EXT {
            continue;
        }
        let len_ext_attrs = rd_u32(d, fe_off + 168)? as u64;
        let len_alloc_descs = rd_u32(d, fe_off + 172)? as u64;
        let icb_file_type = rd_u8(d, fe_off + 28)?;
        let icb_flags = rd_u16(d, fe_off + 34)?;
        let alloc_type = icb_flags & 0x07;
        let is_dir = icb_file_type == 4;
        let info_len = rd_u64(d, fe_off + 56)?;
        let alloc_off = fe_off + 176 + len_ext_attrs;

        // Resolve the first allocation descriptor to a stream range.
        // Upstream reads the extent position at +4 for both the short
        // (type 0, 8-byte) and long (type 1, 16-byte) descriptor.
        let stream = if (alloc_type == 0 && len_alloc_descs >= 8)
            || (alloc_type == 1 && len_alloc_descs >= 16)
        {
            let ext_pos = rd_u32(d, alloc_off + 4)?;
            Some((u64::from(ext_pos) * BLOCK, info_len))
        } else if alloc_type == 3 && len_alloc_descs > 0 {
            Some((alloc_off, len_alloc_descs))
        } else {
            None
        };

        if !is_dir {
            // Regular file record: STORE method, size = InformationLength.
            // Upstream extraction copies `nStreamSize` (extent length)
            // bytes from `nStreamOffset`; the stream length rides in
            // `window_size` (unused by UDF) for `extract_secondary`.
            let (stream_off, stream_len) = stream.unwrap_or((0, 0));
            records.push(SecondaryRecord {
                name: path,
                size: info_len,
                packed_size: info_len,
                is_directory: false,
                modified: None,
                data_offset: stream_off,
                method: 1,
                window_size: stream_len,
            });
        } else {
            if !path.is_empty() {
                records.push(SecondaryRecord {
                    name: path.clone(),
                    size: 0,
                    packed_size: 0,
                    is_directory: true,
                    modified: None,
                    data_offset: 0,
                    method: 1,
                    window_size: 0,
                });
            }
            // Parse FIDs inside the directory data extent.
            let (dir_off, dir_len) = match stream {
                Some(v) => v,
                None => continue,
            };
            if dir_off == 0 || dir_len == 0 || dir_off >= size {
                continue;
            }
            let mut fid_off = dir_off;
            let fid_end = dir_off.saturating_add(dir_len);
            while fid_off < fid_end && fid_off + TAG_SIZE <= size {
                let fid_tag = match read_tag(d, fid_off) {
                    Some(t) => t,
                    None => break,
                };
                if fid_tag.id != TAG_FILE_ID {
                    break;
                }
                let characteristics = match rd_u8(d, fid_off + 18) {
                    Some(v) => v,
                    None => break,
                };
                let len_file_id = match rd_u8(d, fid_off + 19) {
                    Some(v) => v,
                    None => break,
                };
                let len_impl_use = match rd_u16(d, fid_off + 36) {
                    Some(v) => v,
                    None => break,
                };
                let child_loc = match rd_u32(d, fid_off + 24) {
                    Some(v) => v,
                    None => break,
                };
                let is_parent = characteristics & 0x08 != 0;
                let name_off = fid_off + 38 + u64::from(len_impl_use);
                let name = if !is_parent && len_file_id > 0 {
                    match d.get(name_off as usize..name_off as usize + usize::from(len_file_id)) {
                        Some(raw) => osta_name(raw),
                        None => String::new(),
                    }
                } else {
                    String::new()
                };
                let fid_size = 38 + u64::from(len_impl_use) + u64::from(len_file_id);
                let fid_padded = (fid_size + 3) & !3;
                if fid_padded == 0 {
                    break;
                }
                if !is_parent && !name.is_empty() && child_loc > 0 {
                    let child_fe = u64::from(child_loc) * BLOCK;
                    if child_fe < size && !visited.contains(&child_fe) {
                        visited.push(child_fe);
                        let child_path = if path.is_empty() {
                            name
                        } else {
                            format!("{}/{}", path, name)
                        };
                        queue.push_back((child_fe, child_path));
                    }
                }
                fid_off += fid_padded;
            }
        }
    }
    Some(records)
}

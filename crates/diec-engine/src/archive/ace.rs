//! ACE 1.x archive enumeration, ported from upstream
//! `upstream/DIE-engine/dep/XArchive/archives/xace.cpp`
//! (pin 23fec32cac2a562342c1c2db8e22ce231b58f346).
//!
//! ACE is a block-chained container: a main header (`**ACE**` magic)
//! followed by file blocks carrying a 16-bit header CRC over the block
//! body (standard CRC-32/EDB88320 truncated to 16 bits). Only file blocks
//! become records; recovery blocks are skipped like upstream.
//!
//! Parity notes:
//! - `HANDLE_METHOD_STORE` is only reported for tech_type 0 members
//!   without solid/password/split flags (mirrors `bUnsupportedFlags`).
//! - `mtime` uses the ACE DOS timestamp (`nFileTime`).
//! - `is_directory` maps `nAttributes & 0x10` (upstream `FPART_PROP_ISFOLDER`).

use super::SecondaryRecord;

const MAGIC: &[u8; 7] = b"**ACE**";
const HEADTYPE_ARCHIVE: u8 = 0;
const HEADTYPE_FILE: u8 = 1;
const HEADTYPE_RECOVERY: u8 = 2;
const FLAG_ADDSIZE: u16 = 0x0001;
const FLAG_COMMENT: u16 = 0x0002;
const ACE1_MAIN_MIN_HEAD_SIZE: usize = 27;
const ACE1_FILE_MIN_HEAD_SIZE: usize = 31;
const ACE1_MAIN_ALLOWED_FLAGS: u16 = 0xFE02;
const ACE1_FILE_ALLOWED_FLAGS: u16 = 0xF003;
const ACE1_MAX_FILENAME: usize = 512;
const ACE1_MAX_COMMENT: usize = 0x8000;
const ACE1_RECOVERY_MIN_HEAD_SIZE: usize = 34;
const MAX_RECORDS: usize = 0x100000;

const FILEFLAG_SPLIT_BEFORE: u16 = 0x1000;
const FILEFLAG_SPLIT_AFTER: u16 = 0x2000;
const FILEFLAG_PASSWORD: u16 = 0x4000;
const FILEFLAG_SOLID: u16 = 0x8000;
const ARCHFLAG_SOLID: u16 = 0x8000;

fn rd16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}

fn rd32(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}

/// CRC-32/EDB88320 with init 0xFFFFFFFF and no final xor, truncated to
/// the low 16 bits — the ACE header checksum.
fn header_crc(d: &[u8]) -> u16 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &b in d {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB88320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    (crc & 0xFFFF) as u16
}

/// One parsed ACE block (main, file, or recovery).
struct Block {
    head_type: u8,
    head_flags: u16,
    /// Bytes of packed data following the block header (`ADD_SIZE`).
    add_size: u64,
    /// Absolute offset of the packed data stream.
    data_offset: usize,
    name: String,
    packed: u32,
    unpacked: u32,
    file_time: u32,
    attributes: u32,
    tech_type: u8,
    volume_number: u8,
    version_extract: u8,
}

/// `_readBlock` for one block at `off`. `None` stops the chain.
fn read_block(d: &[u8], off: usize) -> Option<Block> {
    if off.checked_add(4)? > d.len() {
        return None;
    }
    let head_crc = rd16(d, off)?;
    let head_size = rd16(d, off + 2)? as usize;
    if head_size < 3 || head_size > d.len() - off - 4 {
        return None;
    }
    let body = d.get(off + 4..off + 4 + head_size)?;
    if header_crc(body) != head_crc {
        return None;
    }
    let head_type = body[0];
    let head_flags = u16::from_le_bytes([body[1], body[2]]);
    if head_type != HEADTYPE_ARCHIVE && head_type != HEADTYPE_FILE && head_type != HEADTYPE_RECOVERY
    {
        return None;
    }
    let mut add_size = 0u64;
    if head_flags & FLAG_ADDSIZE != 0 {
        if head_size < 7 {
            return None;
        }
        add_size = u64::from(rd32(d, off + 7)?);
    }
    let data_offset = off + 4 + head_size;
    if add_size > (d.len() - data_offset) as u64 {
        return None;
    }
    let mut b = Block {
        head_type,
        head_flags,
        add_size,
        data_offset,
        name: String::new(),
        packed: 0,
        unpacked: 0,
        file_time: 0,
        attributes: 0,
        tech_type: 0,
        volume_number: 0,
        version_extract: 0,
    };
    match head_type {
        HEADTYPE_ARCHIVE => {
            if head_flags & !ACE1_MAIN_ALLOWED_FLAGS != 0 || head_size < ACE1_MAIN_MIN_HEAD_SIZE {
                return None;
            }
            if body.get(3..10)? != MAGIC {
                return None;
            }
            // Absolute off+14 (version extract) is body[10]; off+17
            // (volume number) is body[13].
            b.version_extract = body[10];
            b.volume_number = body[13];
            let av_size = body[26] as usize;
            let has_av = head_flags & 0x1000 != 0;
            if has_av != (av_size != 0) {
                return None;
            }
            let variable_end = ACE1_MAIN_MIN_HEAD_SIZE + av_size;
            if variable_end > head_size {
                return None;
            }
            if head_flags & FLAG_COMMENT != 0 {
                if head_size - variable_end < 2 {
                    return None;
                }
                let csize =
                    u16::from_le_bytes([body[variable_end], body[variable_end + 1]]) as usize;
                if csize > ACE1_MAX_COMMENT || csize > head_size - variable_end - 2 {
                    return None;
                }
            }
        }
        HEADTYPE_FILE => {
            if head_flags & !ACE1_FILE_ALLOWED_FLAGS != 0
                || head_flags & FLAG_ADDSIZE == 0
                || head_size < ACE1_FILE_MIN_HEAD_SIZE
            {
                return None;
            }
            // Field offsets within the block: absolute file offsets minus
            // `off`. Header bytes begin at off+4 (head_type), so file
            // fields start at off+7 == body[3].
            b.packed = rd32(d, off + 7)?;
            b.unpacked = rd32(d, off + 11)?;
            b.file_time = rd32(d, off + 15)?;
            b.attributes = rd32(d, off + 19)?;
            b.tech_type = *body.get(23)?; // off+27
            let name_size = rd16(d, off + 33)? as usize;
            if name_size > ACE1_MAX_FILENAME || name_size > head_size - ACE1_FILE_MIN_HEAD_SIZE {
                return None;
            }
            let raw = d.get(off + 35..off + 35 + name_size)?;
            if raw.contains(&0) {
                return None;
            }
            // OEM names decode via the archive codepage; latin-1 keeps the
            // byte values observable (upstream default codepage is the
            // system OEM page, but records stay byte-faithful this way).
            b.name = String::from_utf8_lossy(raw).into_owned();
        }
        _ => {
            // Recovery record (32-bit): flags must be exactly ADDSIZE and
            // head size the fixed recovery minimum.
            if head_flags != FLAG_ADDSIZE || head_size != ACE1_RECOVERY_MIN_HEAD_SIZE {
                return None;
            }
            if body.get(3..10)? != MAGIC {
                return None;
            }
        }
    }
    Some(b)
}

/// `_collectBlocks`: first block must be a raw ACE1 main header, then a
/// chain of file blocks (recovery allowed once, terminal only) that must
/// end exactly at EOF.
fn collect_blocks(d: &[u8]) -> Option<Vec<Block>> {
    let main = read_block(d, 0)?;
    // `_isRawAce1Main`: archive type at offset 0, no V20 flag,
    // version-extract in [10, 20].
    if main.head_type != HEADTYPE_ARCHIVE
        || main.head_flags & 0x0100 != 0
        || !(10..=20).contains(&main.version_extract)
    {
        return None;
    }
    let main_flags = main.head_flags;
    let main_volume = main.volume_number;
    if main_flags & 0x0800 == 0 && main_volume != 0 {
        return None;
    }
    let mut off = main.data_offset.checked_add(main.add_size as usize)?;
    let mut out = vec![main];
    let mut has_recovery = false;
    while off < d.len() {
        if out.len() >= MAX_RECORDS {
            return None;
        }
        let b = read_block(d, off)?;
        if b.head_type == HEADTYPE_ARCHIVE {
            return None;
        }
        let end = b.data_offset.checked_add(b.add_size as usize)?;
        if b.head_type == HEADTYPE_FILE {
            let split = b.head_flags & (FILEFLAG_SPLIT_BEFORE | FILEFLAG_SPLIT_AFTER);
            if (split != 0 && main_flags & 0x0800 == 0)
                || (b.head_flags & FILEFLAG_SPLIT_BEFORE != 0 && main_volume == 0)
                || (b.head_flags & FILEFLAG_SOLID != 0 && main_flags & ARCHFLAG_SOLID == 0)
            {
                return None;
            }
        } else if has_recovery || end != d.len() {
            // A recovery record is unique and must be the terminal block.
            return None;
        }
        if b.head_type == HEADTYPE_RECOVERY {
            has_recovery = true;
        }
        out.push(b);
        off = end;
    }
    let recovery_declared = main_flags & 0x2000 != 0;
    if off != d.len() || recovery_declared != has_recovery {
        return None;
    }
    Some(out)
}

/// `isValid`/`_collectBlocks` parity: the whole chain must parse and end
/// exactly at EOF.
pub fn is_ace(d: &[u8]) -> bool {
    collect_blocks(d).is_some()
}

/// DOS timestamp → `YYYY-MM-DD HH:MM:SS` (ACE stores date in the high
/// word of `nFileTime`).
fn format_dos(ft: u32) -> Option<String> {
    let time = (ft & 0xFFFF) as u16;
    let date = (ft >> 16) as u16;
    let year = ((date >> 9) & 0x7F) as i32 + 1980;
    let month = (date >> 5) & 0x0F;
    let day = date & 0x1F;
    let hour = (time >> 11) & 0x1F;
    let min = (time >> 5) & 0x3F;
    let sec = (time & 0x1F) * 2;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || sec > 59 || min > 59 || hour > 23 {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}"
    ))
}

/// Enumerate file-block records. `None` when the chain is malformed.
pub fn list(d: &[u8]) -> Option<Vec<SecondaryRecord>> {
    let blocks = collect_blocks(d)?;
    let archive_flags = blocks.first()?.head_flags;
    let volume_number = blocks.first()?.volume_number;
    let mut out = Vec::new();
    let mut idx = 0usize;
    for b in &blocks {
        if b.head_type != HEADTYPE_FILE {
            continue;
        }
        // `bSolid` mirror: archive/file solid flag, not first record of
        // volume 0, and non-STORE tech type.
        let solid_archive =
            archive_flags & ARCHFLAG_SOLID != 0 || b.head_flags & FILEFLAG_SOLID != 0;
        let first_in_chain = idx == 0 && volume_number == 0;
        let solid = solid_archive && !first_in_chain && b.tech_type != 0;
        let unsupported = (solid && b.tech_type != 0)
            || b.head_flags & (FILEFLAG_PASSWORD | FILEFLAG_SPLIT_BEFORE | FILEFLAG_SPLIT_AFTER)
                != 0;
        // HANDLE_METHOD_STORE==1, HANDLE_METHOD_ACE==61, UNKNOWN==0.
        let method = if unsupported {
            0
        } else if b.tech_type == 0 {
            1
        } else if b.tech_type == 1 {
            61
        } else {
            0
        };
        out.push(SecondaryRecord {
            name: b.name.replace('\\', "/"),
            size: u64::from(b.unpacked),
            packed_size: u64::from(b.packed),
            is_directory: b.attributes & 0x10 != 0,
            modified: format_dos(b.file_time),
            data_offset: b.data_offset as u64,
            method,
        });
        idx += 1;
    }
    Some(out)
}

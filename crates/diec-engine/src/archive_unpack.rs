//! Archive member extraction for nested recursive scanning.
//!
//! Supports ZIP, 7Z, RAR, CAB, and ISO9660 archive formats. Each format has
//! a dedicated extraction function that returns extracted member bytes with
//! safety bounds enforcement (ADR 0030).
//!
//! ISO9660 support is a minimal base-spec reader (ECMA-119 primary volume
//! descriptor + directory record walk). Joliet and Rock Ridge name
//! extensions are not decoded; names come from the base descriptor.

use crate::host::ScanFlags;
use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

/// Maximum number of archive members to extract in normal mode.
const MAX_MEMBERS_NORMAL: usize = 20;

/// Maximum number of archive members to extract in aggressive mode.
const MAX_MEMBERS_AGGRESSIVE: usize = 100000;

/// Maximum single-member decompressed size (128 MiB, ADR 0030).
const MAX_SINGLE_MEMBER_BYTES: u64 = 128 * 1024 * 1024;

/// Maximum total decompressed bytes across all members (512 MiB, ADR 0030).
const MAX_TOTAL_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum compression ratio (100:1, ADR 0030).
const MAX_COMPRESSION_RATIO: u64 = 100;

/// An extracted archive member.
#[derive(Debug, Clone)]
pub struct ArchiveMember {
    /// Member name (e.g., "file.txt" or "dir/file.txt").
    pub name: String,
    /// The extracted member bytes.
    pub data: Vec<u8>,
}

/// Check if data is a ZIP archive (PK signature).
pub fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == 0x50
        && data[1] == 0x4B
        && (data[2] == 0x03 || data[2] == 0x05 || data[2] == 0x07)
}

/// Check if data is a 7Z archive.
pub fn is_7z(data: &[u8]) -> bool {
    data.len() >= 6 && data[0..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]
}

/// Check if data is a RAR archive (RAR signature).
pub fn is_rar(data: &[u8]) -> bool {
    // RAR 1.5-4.x: 52 61 72 21 1A 07 00
    // RAR 5.x:     52 61 72 21 1A 07 01 00
    data.len() >= 7 && &data[0..4] == b"Rar!" && data[4] == 0x1A && data[5] == 0x07
}

/// Check if data is a CAB archive (MSCF signature).
pub fn is_cab(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"MSCF"
}

/// Check if data is a BZ2 compressed stream (`BZh1`..`BZh9` magic).
///
/// Upstream `XArchive` treats single-stream formats as one-member archives;
/// the same applies here.
pub fn is_bz2(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..3] == b"BZh" && data[3].is_ascii_digit() && data[3] != b'0'
}

/// Check if data is an XZ stream (`FD 37 7A 58 5A 00` magic).
pub fn is_xz(data: &[u8]) -> bool {
    data.len() >= 6 && data[0..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]
}

/// Check if data looks like an LZMA-Alone (`.lzma`) stream.
///
/// The format has no magic; detection uses the header layout: a properties
/// byte below 225, a plausible dictionary size, and an uncompressed-size
/// field that is either `u64::MAX` (unknown) or within the extraction cap.
/// False positives are bounded: callers still fail through the decoder.
pub fn is_lzma(data: &[u8]) -> bool {
    if data.len() < 14 {
        return false;
    }
    // props = lc + lp*9 + pb*45; valid range 0..=224.
    if data[0] >= 225 {
        return false;
    }
    let dict = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    if dict == 0 || dict > (1 << 30) {
        return false;
    }
    let unpacked = u64::from_le_bytes(data[5..13].try_into().unwrap());
    unpacked == u64::MAX || unpacked <= MAX_SINGLE_MEMBER_BYTES
}

/// ISO9660 logical sector size in bytes.
const ISO_SECTOR: usize = 2048;

/// Maximum directory depth for the ISO9660 tree walk.
const ISO_MAX_DEPTH: usize = 8;

/// Check if data is an ISO9660 image (primary volume descriptor `CD001`).
///
/// Checks the descriptor at sector 16 of a 2048-byte-sector image. Raw
/// 2352-byte-sector dumps and multi-session images are not probed.
pub fn is_iso9660(data: &[u8]) -> bool {
    const PVD: usize = 16 * ISO_SECTOR;
    data.len() >= PVD + 6 && data[PVD] == 0x01 && &data[PVD + 1..PVD + 6] == b"CD001"
}

/// Extract members from a ZIP archive with safety bounds (ADR 0030).
///
/// Returns a list of extracted members. Returns empty vector on error or
/// if safety bounds are exceeded.
pub fn extract_zip(data: &[u8], flags: &ScanFlags) -> Vec<ArchiveMember> {
    let max_members = if flags.aggressive {
        MAX_MEMBERS_AGGRESSIVE
    } else {
        MAX_MEMBERS_NORMAL
    };

    let cursor = std::io::Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return vec![],
    };

    let mut members = Vec::new();
    let mut total_decompressed: u64 = 0;

    for i in 0..archive.len().min(max_members) {
        let mut file = match archive.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };

        // Skip directories.
        if file.is_dir() {
            continue;
        }

        let name = file.name().to_string();
        let compressed_size = file.compressed_size();
        let uncompressed_size = file.size();

        // Safety check: single-member size limit.
        if uncompressed_size > MAX_SINGLE_MEMBER_BYTES {
            continue;
        }

        // Safety check: compression ratio limit.
        if let Some(ratio) = uncompressed_size.checked_div(compressed_size)
            && ratio > MAX_COMPRESSION_RATIO
        {
            continue;
        }

        // Safety check: total decompressed bytes limit.
        if total_decompressed + uncompressed_size > MAX_TOTAL_DECOMPRESSED_BYTES {
            break;
        }

        // Extract member data.
        let mut buf = Vec::with_capacity(uncompressed_size.min(MAX_SINGLE_MEMBER_BYTES) as usize);
        if std::io::Read::read_to_end(&mut file, &mut buf).is_err() {
            continue;
        }

        total_decompressed += buf.len() as u64;
        members.push(ArchiveMember { name, data: buf });
    }

    members
}

/// Maximum members enumerated by `zip_member_names` (central directory is
/// cheap to walk; cap only guards against malicious huge archives).
const MAX_MEMBER_NAMES: usize = 65536;

/// Maximum bytes decompressed for a single member read by
/// `zip_member_string` (16 MiB — manifests and manifests-like records are
/// small; larger members are truncated, matching upstream's unbounded read
/// is not acceptable for untrusted input).
const MAX_MEMBER_STRING_BYTES: u64 = 16 * 1024 * 1024;

/// List ZIP member file names without decompressing member contents.
///
/// Mirrors upstream `XArchive::getRecords` name enumeration for ZIP-family
/// archives (ZIP/JAR/APK). Returns an empty vector for non-ZIP input or
/// parse failure.
pub fn zip_member_names(data: &[u8]) -> Vec<String> {
    if !is_zip(data) {
        return Vec::new();
    }
    let cursor = std::io::Cursor::new(data);
    let archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    archive
        .file_names()
        .take(MAX_MEMBER_NAMES)
        .map(|s| s.to_string())
        .collect()
}

/// Decompress a single ZIP member by exact name and return raw bytes,
/// bounded to `MAX_MEMBER_STRING_BYTES`.
///
/// Mirrors upstream `XArchive::decompress(record)`. Returns an empty
/// vector when the member is absent or undecodable.
pub fn zip_member_bytes(data: &[u8], name: &str) -> Vec<u8> {
    if !is_zip(data) || name.is_empty() {
        return Vec::new();
    }
    let cursor = std::io::Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    let mut file = match archive.by_name(name) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    if file.is_dir() || file.size() > MAX_MEMBER_STRING_BYTES {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity(file.size() as usize);
    if std::io::Read::read_to_end(&mut file, &mut buf).is_err() {
        return Vec::new();
    }
    buf
}

/// Decompress a single ZIP member by exact name and return it as a
/// lossy-UTF8 string, bounded to `MAX_MEMBER_STRING_BYTES`.
///
/// Mirrors upstream `XArchive::decompress(record)` for text records such as
/// `META-INF/MANIFEST.MF` (JAR/APK) and `package/package.json` (NPM).
/// Returns an empty string when the member is absent or undecodable.
pub fn zip_member_string(data: &[u8], name: &str) -> String {
    String::from_utf8_lossy(&zip_member_bytes(data, name)).into_owned()
}

/// Extract members from a 7Z archive with safety bounds (ADR 0030).
///
/// Uses a temporary directory for extraction since sevenz-rust requires
/// a filesystem path. Members are read back into memory.
pub fn extract_7z(data: &[u8], flags: &ScanFlags) -> Vec<ArchiveMember> {
    let max_members = if flags.aggressive {
        MAX_MEMBERS_AGGRESSIVE
    } else {
        MAX_MEMBERS_NORMAL
    };

    // Create a temporary directory for extraction.
    let temp_dir = std::env::temp_dir().join(format!("diec_7z_{}", std::process::id()));
    if std::fs::create_dir_all(&temp_dir).is_err() {
        return vec![];
    }

    let mut members = Vec::new();
    let mut total_decompressed: u64 = 0;
    let mut member_count = 0usize;
    let mut stop = false;

    let cursor = std::io::Cursor::new(data);
    let extract_result = sevenz_rust::decompress_with_extract_fn(
        cursor,
        &temp_dir,
        |entry, reader, _path| -> Result<bool, sevenz_rust::Error> {
            if stop || member_count >= max_members {
                stop = true;
                return Ok(false);
            }

            // Skip directories.
            if entry.is_directory() {
                return Ok(true);
            }

            let name = entry.name.clone();
            let uncompressed_size = entry.size();

            // Safety check: single-member size limit.
            if uncompressed_size > MAX_SINGLE_MEMBER_BYTES {
                member_count += 1;
                return Ok(true);
            }

            // Safety check: total decompressed bytes limit.
            if total_decompressed > MAX_TOTAL_DECOMPRESSED_BYTES {
                stop = true;
                return Ok(false);
            }

            let mut buf = Vec::new();
            if std::io::Read::read_to_end(reader, &mut buf).is_err() {
                member_count += 1;
                return Ok(true);
            }

            total_decompressed += buf.len() as u64;
            members.push(ArchiveMember { name, data: buf });
            member_count += 1;
            Ok(true)
        },
    );

    // Clean up temp directory.
    let _ = std::fs::remove_dir_all(&temp_dir);

    if extract_result.is_err() {
        // Return whatever we extracted so far.
    }

    members
}

/// Extract members from a RAR archive with safety bounds (ADR 0030).
pub fn extract_rar(data: &[u8], flags: &ScanFlags) -> Vec<ArchiveMember> {
    let max_members = if flags.aggressive {
        MAX_MEMBERS_AGGRESSIVE
    } else {
        MAX_MEMBERS_NORMAL
    };

    let archive = match rars::ArchiveReader::read(data) {
        Ok(a) => a,
        Err(_) => return vec![],
    };

    // Use Rc<RefCell> to share state with the 'static closure.
    let members: Rc<RefCell<Vec<ArchiveMember>>> = Rc::new(RefCell::new(Vec::new()));
    let total: Rc<RefCell<u64>> = Rc::new(RefCell::new(0));
    let count: Rc<RefCell<usize>> = Rc::new(RefCell::new(0));
    let stop: Rc<RefCell<bool>> = Rc::new(RefCell::new(false));

    let members_clone = members.clone();
    let total_clone = total.clone();
    let count_clone = count.clone();
    let stop_clone = stop.clone();

    let _ = archive.extract_to(None, move |meta| {
        if *stop_clone.borrow() || *count_clone.borrow() >= max_members {
            *stop_clone.borrow_mut() = true;
            return Err(rars::Error::from(std::io::Error::other("limit reached")));
        }

        // Skip directories.
        if meta.is_directory {
            *count_clone.borrow_mut() += 1;
            return Err(rars::Error::from(std::io::Error::other("skip directory")));
        }

        let name = meta.name_lossy();
        *count_clone.borrow_mut() += 1;

        // Safety check: total decompressed bytes limit.
        if *total_clone.borrow() > MAX_TOTAL_DECOMPRESSED_BYTES {
            *stop_clone.borrow_mut() = true;
            return Err(rars::Error::from(std::io::Error::other(
                "total limit reached",
            )));
        }

        Ok(Box::new(MemberWriter {
            name,
            buf: Vec::new(),
            members: members_clone.clone(),
            total: total_clone.clone(),
        }))
    });

    members.take()
}

/// A writer that collects extracted bytes and pushes to the members list on drop.
struct MemberWriter {
    name: String,
    buf: Vec<u8>,
    members: Rc<RefCell<Vec<ArchiveMember>>>,
    total: Rc<RefCell<u64>>,
}

impl Write for MemberWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        // Safety check: single-member size limit.
        if (self.buf.len() + data.len()) as u64 > MAX_SINGLE_MEMBER_BYTES {
            return Err(std::io::Error::other("single member size limit exceeded"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for MemberWriter {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            *self.total.borrow_mut() += self.buf.len() as u64;
            self.members.borrow_mut().push(ArchiveMember {
                name: self.name.clone(),
                data: std::mem::take(&mut self.buf),
            });
        }
    }
}

/// Extract members from a CAB archive with safety bounds (ADR 0030).
///
/// Uses the pure-Rust `cab` crate (MSZIP/LZX/Quantum decompression).
/// Returns empty vector on error or if safety bounds are exceeded.
pub fn extract_cab(data: &[u8], flags: &ScanFlags) -> Vec<ArchiveMember> {
    let max_members = if flags.aggressive {
        MAX_MEMBERS_AGGRESSIVE
    } else {
        MAX_MEMBERS_NORMAL
    };
    let cursor = std::io::Cursor::new(data);
    let mut cabinet = match cab::Cabinet::new(cursor) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let names: Vec<String> = cabinet
        .folder_entries()
        .flat_map(|folder| {
            folder
                .file_entries()
                .map(|e| e.name().to_string())
                .collect::<Vec<_>>()
        })
        .take(max_members)
        .collect();
    let mut members = Vec::new();
    let mut total: u64 = 0;
    for name in names {
        let mut reader = match cabinet.read_file(&name) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut buf = Vec::new();
        let mut take = std::io::Read::take(&mut reader, MAX_SINGLE_MEMBER_BYTES + 1);
        if std::io::Read::read_to_end(&mut take, &mut buf).is_err()
            || buf.len() as u64 > MAX_SINGLE_MEMBER_BYTES
        {
            continue;
        }
        total = total.saturating_add(buf.len() as u64);
        if total > MAX_TOTAL_DECOMPRESSED_BYTES {
            break;
        }
        members.push(ArchiveMember { name, data: buf });
    }
    members
}

/// Extract file members from an ISO9660 image with safety bounds.
///
/// Only regular files are returned; directories contribute names to the
/// listing APIs but no payload here. Multi-extent files are truncated to
/// their first extent.
pub fn extract_iso9660(data: &[u8], flags: &ScanFlags) -> Vec<ArchiveMember> {
    let max_members = if flags.aggressive {
        MAX_MEMBERS_AGGRESSIVE
    } else {
        MAX_MEMBERS_NORMAL
    };
    let mut members = Vec::new();
    let mut total: u64 = 0;
    walk_iso9660(data, &mut |path, is_dir, lba, size| {
        if is_dir || members.len() >= max_members || size > MAX_SINGLE_MEMBER_BYTES {
            return;
        }
        let off = lba as usize * ISO_SECTOR;
        let end = match off.checked_add(size as usize) {
            Some(e) if e <= data.len() => e,
            _ => return,
        };
        total = total.saturating_add(size);
        if total > MAX_TOTAL_DECOMPRESSED_BYTES {
            return;
        }
        members.push(ArchiveMember {
            name: path.to_string(),
            data: data[off..end].to_vec(),
        });
    });
    members
}

/// Walk an ISO9660 directory tree, calling `visit(path, is_dir, extent_lba,
/// extent_size)` for every record. Paths are `/`-separated, relative to the
/// root directory (no leading slash).
///
/// Returns `false` when the image has no valid primary volume descriptor.
/// Stops descending at [`ISO_MAX_DEPTH`] and caps visited records at
/// [`MAX_MEMBER_NAMES`]. Joliet/Rock Ridge names are not decoded.
fn walk_iso9660(data: &[u8], visit: &mut dyn FnMut(&str, bool, u64, u64)) -> bool {
    if !is_iso9660(data) {
        return false;
    }
    // Root directory record lives at byte 156 of the primary volume
    // descriptor (ECMA-119 §9.1).
    let root = match iso_dir_record_at(data, 16 * ISO_SECTOR + 156) {
        Some(r) => r,
        None => return false,
    };
    let mut visited = 0usize;
    let mut stack: Vec<(u64, u64, usize, String)> = vec![(root.lba, root.size, 0, String::new())];
    while let Some((lba, size, depth, path)) = stack.pop() {
        let base = match (lba as usize)
            .checked_mul(ISO_SECTOR)
            .and_then(|b| b.checked_add(size as usize))
        {
            Some(end) if end <= data.len() => lba as usize * ISO_SECTOR,
            _ => continue,
        };
        let end = base + size as usize;
        let mut pos = base;
        while pos + 34 <= end {
            let rec_len = data[pos] as usize;
            if rec_len == 0 {
                // Padding: records never cross a sector boundary.
                pos = pos / ISO_SECTOR * ISO_SECTOR + ISO_SECTOR;
                continue;
            }
            if rec_len < 34 || pos + rec_len > end {
                break;
            }
            if let Some(rec) = iso_dir_record_at(data, pos) {
                pos += rec_len;
                // Skip "." and ".." entries (single byte 0x00 / 0x01 names).
                if rec.special {
                    continue;
                }
                visited += 1;
                if visited > MAX_MEMBER_NAMES {
                    return true;
                }
                let child = if path.is_empty() {
                    rec.name.clone()
                } else {
                    format!("{}/{}", path, rec.name)
                };
                visit(&child, rec.is_dir, rec.lba, rec.size);
                if rec.is_dir && depth < ISO_MAX_DEPTH {
                    stack.push((rec.lba, rec.size, depth + 1, child));
                }
            } else {
                break;
            }
        }
    }
    true
}

/// One parsed ISO9660 directory record.
struct IsoRecord {
    /// Extent location (logical block address).
    lba: u64,
    /// Extent data length in bytes.
    size: u64,
    /// Whether the record is a directory.
    is_dir: bool,
    /// Whether this is the special `.`/`..` entry.
    special: bool,
    /// Decoded file name (`;N` version suffix stripped for files).
    name: String,
}

/// Parse one ISO9660 directory record at `pos` (ECMA-119 §9.1).
///
/// Returns `None` for zero-length padding or malformed records. Uses the
/// little-endian halves of the both-endian extent fields.
fn iso_dir_record_at(data: &[u8], pos: usize) -> Option<IsoRecord> {
    let len = *data.get(pos)? as usize;
    if len < 34 || pos.checked_add(len)? > data.len() {
        return None;
    }
    let rec = &data[pos..pos + len];
    let lba = u64::from(u32::from_le_bytes([rec[2], rec[3], rec[4], rec[5]]));
    let size = u64::from(u32::from_le_bytes([rec[10], rec[11], rec[12], rec[13]]));
    let is_dir = rec[25] & 0x02 != 0;
    let name_len = rec[32] as usize;
    if 33 + name_len > len || name_len == 0 {
        return None;
    }
    let raw = &rec[33..33 + name_len];
    // "." = 0x00, ".." = 0x01.
    if name_len == 1 && raw[0] <= 1 {
        return Some(IsoRecord {
            lba,
            size,
            is_dir,
            special: true,
            name: String::new(),
        });
    }
    let mut name = String::from_utf8_lossy(raw).into_owned();
    if !is_dir {
        // Strip the ";1" file version suffix.
        if let Some(sep) = name.rfind(';') {
            name.truncate(sep);
        }
    }
    Some(IsoRecord {
        lba,
        size,
        is_dir,
        special: false,
        name,
    })
}

/// Extract archive members based on the detected format.
///
/// Returns empty vector for unsupported formats or extraction errors.
pub fn extract_archive(data: &[u8], flags: &ScanFlags) -> Vec<ArchiveMember> {
    if is_zip(data) {
        extract_zip(data, flags)
    } else if is_7z(data) {
        extract_7z(data, flags)
    } else if is_rar(data) {
        extract_rar(data, flags)
    } else if is_cab(data) {
        extract_cab(data, flags)
    } else if is_iso9660(data) {
        extract_iso9660(data, flags)
    } else if let Some(out) = decompress_stream(data) {
        vec![ArchiveMember {
            name: "data".to_string(),
            data: out,
        }]
    } else {
        vec![]
    }
}

/// Check if data is any supported archive format.
pub fn is_archive(data: &[u8]) -> bool {
    is_zip(data)
        || is_7z(data)
        || is_rar(data)
        || is_cab(data)
        || is_iso9660(data)
        || is_bz2(data)
        || is_xz(data)
        || is_lzma(data)
}

/// Decompress a BZ2/XZ/LZMA-Alone stream into `MAX_SINGLE_MEMBER_BYTES`.
///
/// Returns `None` when the magic does not match or decompression fails.
/// Output is capped; oversized payloads return `None` rather than a
/// truncated stream so callers never emit silently-short data.
fn decompress_stream(data: &[u8]) -> Option<Vec<u8>> {
    if is_bz2(data) {
        let mut reader = bzip2_rs::DecoderReader::new(data);
        let mut buf = Vec::new();
        let mut take = std::io::Read::take(&mut reader, MAX_SINGLE_MEMBER_BYTES + 1);
        if std::io::Read::read_to_end(&mut take, &mut buf).is_err() {
            return None;
        }
        return (buf.len() as u64 <= MAX_SINGLE_MEMBER_BYTES).then_some(buf);
    }
    if is_xz(data) || is_lzma(data) {
        let mut input = std::io::BufReader::new(data);
        let mut output = CappedWriter::new(MAX_SINGLE_MEMBER_BYTES);
        let ok = if is_xz(data) {
            lzma_rs::xz_decompress(&mut input, &mut output)
        } else {
            lzma_rs::lzma_decompress(&mut input, &mut output)
        };
        return match ok {
            Ok(()) if !output.overflowed => Some(output.buf),
            _ => None,
        };
    }
    None
}

/// Writer that buffers output up to `limit` bytes and flags overflow.
struct CappedWriter {
    buf: Vec<u8>,
    limit: u64,
    overflowed: bool,
}

impl CappedWriter {
    /// Create a writer capped at `limit` total bytes.
    fn new(limit: u64) -> Self {
        Self {
            buf: Vec::new(),
            limit,
            overflowed: false,
        }
    }
}

impl Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if (self.buf.len() + data.len()) as u64 > self.limit {
            self.overflowed = true;
            return Err(std::io::Error::other("output size limit exceeded"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ============================================================================
// Metadata-only listing (GUI "Files" view, upstream `XArchive::getRecords`)
// ============================================================================

/// Archive format detected by [`list_archive_members`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    /// ZIP archive (also covers JAR/APK/IPA).
    Zip,
    /// 7Z archive.
    SevenZ,
    /// RAR archive (1.5/4.x/5.x).
    Rar,
    /// Windows cabinet (CAB) archive.
    Cab,
    /// ISO9660 CD/DVD filesystem image (base spec only).
    Iso9660,
    /// BZ2 single-stream compression.
    Bz2,
    /// XZ single-stream compression.
    Xz,
    /// LZMA-Alone (`.lzma`) single-stream compression.
    Lzma,
    /// AutoIt compiled-script container (v2/EA05/EA06 records).
    AutoIt,
    /// Enigma Virtual Box container (PE-carried).
    EnigmaVb,
    /// BoxedApp packer container (PE-carried).
    BoxedApp,
}

impl ArchiveKind {
    /// Uppercase display name (upstream archive widget style).
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Zip => "ZIP",
            Self::SevenZ => "7Z",
            Self::Rar => "RAR",
            Self::Cab => "CAB",
            Self::Iso9660 => "ISO9660",
            Self::Bz2 => "BZ2",
            Self::Xz => "XZ",
            Self::Lzma => "LZMA",
            Self::AutoIt => "AUTOIT",
            Self::EnigmaVb => "ENIGMAVB",
            Self::BoxedApp => "BOXEDAPP",
        }
    }
}

/// Metadata for one archive member for list views (no payload extraction).
#[derive(Debug, Clone)]
pub struct ArchiveMemberInfo {
    /// Member name (path within the archive).
    pub name: String,
    /// Unpacked size in bytes.
    pub size: u64,
    /// Packed/compressed size in bytes (0 when the format does not expose
    /// a per-member packed size, e.g. 7Z solid streams).
    pub packed_size: u64,
    /// Whether the member is a directory.
    pub is_directory: bool,
    /// Last-modified time formatted as `YYYY-MM-DD HH:MM:SS` UTC.
    pub modified: Option<String>,
}

/// List members of a supported archive (ZIP/7Z/RAR/CAB/ISO9660) with
/// metadata only.
///
/// Mirrors upstream `XArchive::getRecords` name enumeration. Returns `None`
/// for unsupported formats or unparseable archives. Member payloads are not
/// decompressed; counts are capped at `MAX_MEMBER_NAMES`.
pub fn list_archive_members(data: &[u8]) -> Option<(ArchiveKind, Vec<ArchiveMemberInfo>)> {
    if is_zip(data) {
        list_zip_members(data).map(|m| (ArchiveKind::Zip, m))
    } else if is_7z(data) {
        list_7z_members(data).map(|m| (ArchiveKind::SevenZ, m))
    } else if is_rar(data) {
        list_rar_members(data).map(|m| (ArchiveKind::Rar, m))
    } else if is_cab(data) {
        list_cab_members(data).map(|m| (ArchiveKind::Cab, m))
    } else if is_iso9660(data) {
        list_iso9660_members(data).map(|m| (ArchiveKind::Iso9660, m))
    } else if let Some(m) = list_container_members(data) {
        // Packer/protector containers (upstream XStaticUnpacker record
        // enumeration). These are NOT part of `is_archive`/`extract_archive`:
        // upstream only probes them under the opt-in
        // `FT_FLAG_STATICUNPACKERS` flag and never recurses into them during
        // nested scans. They are listed here so the explicit browse/extract
        // path (GUI archive view) matches upstream's archive widget.
        //
        // Probed before the weak BZ2/XZ/LZMA stream heuristics: a PE-carried
        // container's MZ header can accidentally satisfy `is_lzma`.
        Some(m)
    } else {
        list_stream_members(data)
    }
}

/// List members of a packer/protector container (AutoIt/EnigmaVB/BoxedApp).
///
/// Returns `None` when no container detector matches. Member records are
/// produced by the Phase 28 static unpackers; `packed_size` is reported as
/// 0 because these formats do not expose a meaningful per-member packed
/// size through the record API.
fn list_container_members(data: &[u8]) -> Option<(ArchiveKind, Vec<ArchiveMemberInfo>)> {
    let (kind, records) = container_records(data)?;
    let members = records
        .iter()
        .take(MAX_MEMBER_NAMES)
        .map(|r| ArchiveMemberInfo {
            name: r.name.clone(),
            size: r.data.len() as u64,
            packed_size: 0,
            is_directory: false,
            modified: None,
        })
        .collect();
    Some((kind, members))
}

/// Run the container extractors and return the detected kind plus the
/// full record list. Probe order mirrors the upstream `xformats.cpp`
/// static-unpacker chain (AutoIt -> BoxedApp -> EnigmaVB).
fn container_records(data: &[u8]) -> Option<(ArchiveKind, Vec<crate::unpack::ContainerRecord>)> {
    if crate::unpack::detect_autoit(data).is_some()
        && let Ok(records) = crate::unpack::extract_autoit(data, -1)
    {
        return Some((ArchiveKind::AutoIt, records));
    }
    if crate::unpack::detect_boxedapp(data).is_some()
        && let Ok(records) = crate::unpack::extract_boxedapp(data)
    {
        return Some((ArchiveKind::BoxedApp, records));
    }
    if crate::unpack::detect_enigmavb(data).is_some()
        && let Ok(records) = crate::unpack::extract_enigmavb(data)
    {
        return Some((ArchiveKind::EnigmaVb, records));
    }
    None
}

/// List a BZ2/XZ/LZMA stream as one pseudo-member named `data`.
///
/// Single-stream formats carry no file table; the decompressed size is
/// discovered by a bounded decode (mirrors upstream showing one record).
fn list_stream_members(data: &[u8]) -> Option<(ArchiveKind, Vec<ArchiveMemberInfo>)> {
    let kind = if is_bz2(data) {
        ArchiveKind::Bz2
    } else if is_xz(data) {
        ArchiveKind::Xz
    } else if is_lzma(data) {
        ArchiveKind::Lzma
    } else {
        return None;
    };
    let out = decompress_stream(data)?;
    Some((
        kind,
        vec![ArchiveMemberInfo {
            name: "data".to_string(),
            size: out.len() as u64,
            packed_size: data.len() as u64,
            is_directory: false,
            modified: None,
        }],
    ))
}

/// List ZIP members from the central directory (metadata only).
fn list_zip_members(data: &[u8]) -> Option<Vec<ArchiveMemberInfo>> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;
    let mut members = Vec::with_capacity(archive.len().min(MAX_MEMBER_NAMES));
    for i in 0..archive.len().min(MAX_MEMBER_NAMES) {
        if let Ok(f) = archive.by_index(i) {
            members.push(ArchiveMemberInfo {
                name: f.name().to_string(),
                size: f.size(),
                packed_size: f.compressed_size(),
                is_directory: f.is_dir(),
                modified: f.last_modified().map(|d| format!("{}", d)),
            });
        }
    }
    Some(members)
}

/// List 7Z members by reading the archive header only.
fn list_7z_members(data: &[u8]) -> Option<Vec<ArchiveMemberInfo>> {
    let mut cursor = std::io::Cursor::new(data);
    let archive = sevenz_rust::Archive::read(&mut cursor, data.len() as u64, &[] as &[u8]).ok()?;
    let members = archive
        .files
        .iter()
        .take(MAX_MEMBER_NAMES)
        .map(|e| ArchiveMemberInfo {
            name: e.name().to_string(),
            size: e.size(),
            // 7Z solid streams have no meaningful per-member packed size.
            packed_size: 0,
            is_directory: e.is_directory(),
            modified: e
                .has_last_modified_date
                .then(|| format_unix_time(e.last_modified_date().to_unix_time())),
        })
        .collect();
    Some(members)
}

/// List RAR members via `rars` header metadata.
fn list_rar_members(data: &[u8]) -> Option<Vec<ArchiveMemberInfo>> {
    let archive = rars::ArchiveReader::read(data).ok()?;
    let members = archive
        .members()
        .take(MAX_MEMBER_NAMES)
        .map(|m| {
            let meta = &m.meta;
            ArchiveMemberInfo {
                name: meta.name_lossy(),
                size: meta.unpacked_size,
                packed_size: meta.packed_size,
                is_directory: meta.is_directory,
                modified: meta.file_time.and_then(format_dos_time),
            }
        })
        .collect();
    Some(members)
}

/// List CAB members from the file-entry tables (metadata only).
fn list_cab_members(data: &[u8]) -> Option<Vec<ArchiveMemberInfo>> {
    let cursor = std::io::Cursor::new(data);
    let cabinet = cab::Cabinet::new(cursor).ok()?;
    let mut members = Vec::new();
    'outer: for folder in cabinet.folder_entries() {
        for file in folder.file_entries() {
            if members.len() >= MAX_MEMBER_NAMES {
                break 'outer;
            }
            members.push(ArchiveMemberInfo {
                name: file.name().to_string(),
                size: u64::from(file.uncompressed_size()),
                // CAB does not expose a per-file packed size.
                packed_size: 0,
                is_directory: false,
                modified: file.datetime().map(|d| {
                    format!(
                        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                        d.year(),
                        d.month(),
                        d.day(),
                        d.hour(),
                        d.minute(),
                        d.second()
                    )
                }),
            });
        }
    }
    Some(members)
}

/// List ISO9660 members by walking the base-spec directory tree.
fn list_iso9660_members(data: &[u8]) -> Option<Vec<ArchiveMemberInfo>> {
    let mut members = Vec::new();
    if !walk_iso9660(data, &mut |path, is_dir, _lba, size| {
        if members.len() < MAX_MEMBER_NAMES {
            members.push(ArchiveMemberInfo {
                name: path.to_string(),
                size,
                packed_size: size,
                is_directory: is_dir,
                modified: None,
            });
        }
    }) {
        return None;
    }
    Some(members)
}

/// Extract a single member's bytes by exact name, bounded to
/// `MAX_SINGLE_MEMBER_BYTES`.
///
/// Mirrors upstream `XArchive::decompress(record)` for GUI member extraction.
/// Returns an empty vector when the member is absent or undecodable.
pub fn extract_member(data: &[u8], name: &str) -> Vec<u8> {
    if name.is_empty() {
        return Vec::new();
    }
    if is_zip(data) {
        extract_member_zip(data, name)
    } else if is_7z(data) {
        extract_member_7z(data, name)
    } else if is_rar(data) {
        extract_member_rar(data, name)
    } else if is_cab(data) {
        extract_member_cab(data, name)
    } else if is_iso9660(data) {
        extract_member_iso9660(data, name)
    } else if let Some((_kind, records)) = container_records(data) {
        // Packer/protector containers: exact-name member lookup
        // (upstream `XStaticUnpacker` record extraction).
        records
            .into_iter()
            .find(|r| r.name == name)
            .map(|r| r.data)
            .unwrap_or_default()
    } else {
        // Single-stream formats expose exactly one pseudo-member, `data`.
        if name == "data" {
            decompress_stream(data).unwrap_or_default()
        } else {
            Vec::new()
        }
    }
}

/// Extract one ZIP member bounded to `MAX_SINGLE_MEMBER_BYTES`.
fn extract_member_zip(data: &[u8], name: &str) -> Vec<u8> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    let mut file = match archive.by_name(name) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    if file.is_dir() || file.size() > MAX_SINGLE_MEMBER_BYTES {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity(file.size() as usize);
    if std::io::Read::read_to_end(&mut file, &mut buf).is_err() {
        return Vec::new();
    }
    buf
}

/// Extract one 7Z member bounded to `MAX_SINGLE_MEMBER_BYTES`.
fn extract_member_7z(data: &[u8], name: &str) -> Vec<u8> {
    let temp_dir = std::env::temp_dir().join(format!("diec_7z_member_{}", std::process::id()));
    if std::fs::create_dir_all(&temp_dir).is_err() {
        return Vec::new();
    }
    let cursor = std::io::Cursor::new(data);
    let found: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
    let found_clone = found.clone();
    let _ = sevenz_rust::decompress_with_extract_fn(
        cursor,
        &temp_dir,
        move |entry, reader, _path| -> Result<bool, sevenz_rust::Error> {
            if entry.name != name || entry.is_directory() {
                return Ok(true);
            }
            let mut buf = Vec::new();
            let mut take = std::io::Read::take(reader, MAX_SINGLE_MEMBER_BYTES);
            if std::io::Read::read_to_end(&mut take, &mut buf).is_ok() {
                *found_clone.borrow_mut() = buf;
            }
            // Stop after the matched member.
            Ok(false)
        },
    );
    let _ = std::fs::remove_dir_all(&temp_dir);
    found.take()
}

/// Extract one RAR member bounded to `MAX_SINGLE_MEMBER_BYTES`.
fn extract_member_rar(data: &[u8], name: &str) -> Vec<u8> {
    let archive = match rars::ArchiveReader::read(data) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    let found: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
    let found_clone = found.clone();
    let _ = archive.extract_to(None, move |meta| {
        if meta.is_directory || meta.name_lossy() != name {
            return Err(rars::Error::from(std::io::Error::other("skip member")));
        }
        Ok(Box::new(SingleMemberWriter {
            buf: Vec::new(),
            out: found_clone.clone(),
        }) as Box<dyn Write>)
    });
    found.take()
}

/// Extract one CAB member bounded to `MAX_SINGLE_MEMBER_BYTES`.
fn extract_member_cab(data: &[u8], name: &str) -> Vec<u8> {
    let cursor = std::io::Cursor::new(data);
    let mut cabinet = match cab::Cabinet::new(cursor) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    // Reject oversized members before decompression.
    let oversized = cabinet
        .folder_entries()
        .flat_map(|folder| {
            folder
                .file_entries()
                .map(|e| (e.name().to_string(), e.uncompressed_size()))
                .collect::<Vec<_>>()
        })
        .any(|(n, sz)| n == name && u64::from(sz) > MAX_SINGLE_MEMBER_BYTES);
    if oversized {
        return Vec::new();
    }
    let mut reader = match cabinet.read_file(name) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut buf = Vec::new();
    let mut take = std::io::Read::take(&mut reader, MAX_SINGLE_MEMBER_BYTES + 1);
    if std::io::Read::read_to_end(&mut take, &mut buf).is_err()
        || buf.len() as u64 > MAX_SINGLE_MEMBER_BYTES
    {
        return Vec::new();
    }
    buf
}

/// Extract one ISO9660 member bounded to `MAX_SINGLE_MEMBER_BYTES`.
fn extract_member_iso9660(data: &[u8], name: &str) -> Vec<u8> {
    let target = name.trim_matches('/');
    let mut found: Vec<u8> = Vec::new();
    walk_iso9660(data, &mut |path, is_dir, lba, size| {
        if !found.is_empty() || is_dir || path != target || size > MAX_SINGLE_MEMBER_BYTES {
            return;
        }
        let off = lba as usize * ISO_SECTOR;
        if let Some(end) = off.checked_add(size as usize).filter(|&e| e <= data.len()) {
            found = data[off..end].to_vec();
        }
    });
    found
}

/// Writer that collects bytes and stores them into `out` on drop.
struct SingleMemberWriter {
    buf: Vec<u8>,
    out: Rc<RefCell<Vec<u8>>>,
}

impl Write for SingleMemberWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if (self.buf.len() + data.len()) as u64 > MAX_SINGLE_MEMBER_BYTES {
            return Err(std::io::Error::other("single member size limit exceeded"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for SingleMemberWriter {
    fn drop(&mut self) {
        *self.out.borrow_mut() = std::mem::take(&mut self.buf);
    }
}

/// Format a DOS packed timestamp (`0xYYYYMMDD HHMMSS` split form) as
/// `YYYY-MM-DD HH:MM:SS`. Returns `None` for zero/out-of-range fields.
fn format_dos_time(dos: u32) -> Option<String> {
    let date = dos >> 16;
    let time = dos & 0xFFFF;
    let year = ((date >> 9) & 0x7F) + 1980;
    let month = (date >> 5) & 0x0F;
    let day = date & 0x1F;
    let hour = (time >> 11) & 0x1F;
    let min = (time >> 5) & 0x3F;
    let sec = (time & 0x1F) * 2;
    if year < 1980 || month == 0 || month > 12 || day == 0 || day > 31 {
        return None;
    }
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec
    ))
}

/// Format Unix seconds since epoch as `YYYY-MM-DD HH:MM:SS` UTC
/// (no chrono dependency; civil-from-days algorithm).
fn format_unix_time(secs: i64) -> String {
    if secs < 0 {
        return String::new();
    }
    let secs = secs as u64;
    let days = secs / 86400;
    let rem = secs % 86400;
    let (year, month, day) = days_to_date(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year,
        month,
        day,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Convert days since 1970-01-01 to (year, month, day).
fn days_to_date(days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    let mut remaining = days;
    loop {
        let dy = if is_leap_year(year) { 366 } else { 365 };
        if remaining < dy {
            break;
        }
        remaining -= dy;
        year += 1;
    }
    let month_lengths = if is_leap_year(year) {
        [31u64, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for &mlen in &month_lengths {
        if remaining < mlen {
            break;
        }
        remaining -= mlen;
        month += 1;
    }
    (year, month, remaining + 1)
}

/// Check if a year is a leap year.
fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_zip_valid() {
        let data = b"PK\x03\x04";
        assert!(is_zip(data));
    }

    #[test]
    fn is_zip_invalid() {
        assert!(!is_zip(b"not a zip"));
    }

    #[test]
    fn is_7z_valid() {
        let data = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
        assert!(is_7z(&data));
    }

    #[test]
    fn is_rar_valid_v4() {
        let data = b"Rar!\x1A\x07\x00";
        assert!(is_rar(data));
    }

    #[test]
    fn is_rar_valid_v5() {
        let data = b"Rar!\x1A\x07\x01\x00";
        assert!(is_rar(data));
    }

    #[test]
    fn extract_zip_empty_data() {
        let flags = ScanFlags::default();
        let members = extract_zip(&[], &flags);
        assert!(members.is_empty());
    }

    #[test]
    fn extract_7z_empty_data() {
        let flags = ScanFlags::default();
        let members = extract_7z(&[], &flags);
        assert!(members.is_empty());
    }

    #[test]
    fn extract_rar_empty_data() {
        let flags = ScanFlags::default();
        let members = extract_rar(&[], &flags);
        assert!(members.is_empty());
    }

    #[test]
    fn extract_archive_unknown_format() {
        let flags = ScanFlags::default();
        let members = extract_archive(b"not an archive", &flags);
        assert!(members.is_empty());
    }

    #[test]
    fn max_members_normal_is_20() {
        assert_eq!(MAX_MEMBERS_NORMAL, 20);
    }

    #[test]
    fn max_compression_ratio_is_100() {
        assert_eq!(MAX_COMPRESSION_RATIO, 100);
    }

    #[test]
    fn is_archive_zip() {
        assert!(is_archive(b"PK\x03\x04\x00\x00"));
    }

    #[test]
    fn is_archive_7z() {
        assert!(is_archive(&[
            0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04
        ]));
    }

    #[test]
    fn is_archive_not() {
        assert!(!is_archive(b"not an archive"));
    }

    // -- list_archive_members / extract_member --

    /// Build a minimal in-memory ZIP with two members for testing.
    fn make_test_zip() -> Vec<u8> {
        use zip::write::SimpleFileOptions;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        w.start_file("dir/hello.txt", opts).unwrap();
        std::io::Write::write_all(&mut w, b"hello world").unwrap();
        w.start_file("dir/", opts).unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn list_zip_members_roundtrip() {
        let data = make_test_zip();
        let (kind, members) = list_archive_members(&data).unwrap();
        assert_eq!(kind, ArchiveKind::Zip);
        assert!(members.iter().any(|m| m.name == "dir/hello.txt"));
        let file = members.iter().find(|m| m.name == "dir/hello.txt").unwrap();
        assert_eq!(file.size, 11);
        assert!(file.packed_size > 0);
        assert!(!file.is_directory);
    }

    #[test]
    fn extract_member_zip_roundtrip() {
        let data = make_test_zip();
        let bytes = extract_member(&data, "dir/hello.txt");
        assert_eq!(bytes, b"hello world");
        assert!(extract_member(&data, "missing").is_empty());
    }

    #[test]
    fn extract_member_zip_directory_is_empty() {
        let data = make_test_zip();
        assert!(extract_member(&data, "dir/").is_empty());
    }

    #[test]
    fn list_archive_members_rejects_non_archive() {
        assert!(list_archive_members(b"not an archive").is_none());
    }

    #[test]
    fn extract_member_rejects_non_archive() {
        assert!(extract_member(b"not an archive", "x").is_empty());
        assert!(extract_member(b"PK\x03\x04", "").is_empty());
    }

    #[test]
    fn list_archive_members_malformed_does_not_panic() {
        // Truncated ZIP header — must not panic.
        assert!(
            list_archive_members(b"PK\x03\x04\xff\xff").is_none()
                || list_archive_members(b"PK\x03\x04\xff\xff").is_some()
        );
        assert!(list_archive_members(b"Rar!\x1a\x07\x00\xff").is_none());
        assert!(list_archive_members(b"7z\xbc\xaf\x27\x1c\x00\xff\xff\xff\xff").is_none());
    }

    #[test]
    fn format_dos_time_decodes() {
        // 2024-01-15 10:30:00 -> date 0x582F, time 0x53C0.
        let s = format_dos_time((0x582F << 16) | 0x53C0).unwrap();
        assert_eq!(&s[..10], "2024-01-15");
        assert_eq!(&s[11..], "10:30:00");
        assert!(format_dos_time(0).is_none());
    }

    #[test]
    fn format_unix_time_epoch() {
        assert_eq!(format_unix_time(0), "1970-01-01 00:00:00");
        assert_eq!(format_unix_time(1704067200), "2024-01-01 00:00:00");
        assert_eq!(format_unix_time(-1), "");
    }

    // -- Phase 18.B: CAB -------------------------------------------------

    /// Build a minimal CAB holding `hello.txt` via the `cab` crate writer.
    fn make_test_cab() -> Vec<u8> {
        let mut builder = cab::CabinetBuilder::new();
        builder
            .add_folder(cab::CompressionType::None)
            .add_file("hello.txt");
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = builder.build(cursor).unwrap();
        while let Some(mut file_writer) = writer.next_file().unwrap() {
            use std::io::Write as _;
            file_writer.write_all(b"hello world").unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn cab_list_and_extract() {
        let data = make_test_cab();
        assert!(is_cab(&data));
        assert!(is_archive(&data));
        let (kind, members) = list_archive_members(&data).unwrap();
        assert_eq!(kind, ArchiveKind::Cab);
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "hello.txt");
        assert_eq!(members[0].size, 11);
        assert_eq!(extract_member(&data, "hello.txt"), b"hello world");
        let flags = ScanFlags::default();
        let extracted = extract_cab(&data, &flags);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].data, b"hello world");
    }

    #[test]
    fn cab_truncated_does_not_panic() {
        let data = make_test_cab();
        for cut in [8, data.len() / 2] {
            let flags = ScanFlags::default();
            let _ = extract_cab(&data[..cut], &flags);
            let _ = list_archive_members(&data[..cut]);
            let _ = extract_member(&data[..cut], "hello.txt");
        }
    }

    // -- Phase 18.B: ISO9660 ----------------------------------------------

    /// Write an ISO9660 directory record into `buf` (which must be at
    /// least 34 + name_len bytes). Returns the record length written.
    fn put_dir_record(buf: &mut [u8], lba: u32, size: u32, flags_byte: u8, name: &[u8]) -> usize {
        let name_len = name.len();
        let len = 33 + name_len + usize::from(name_len.is_multiple_of(2));
        buf[0] = len as u8;
        buf[1] = 0; // extended attribute length
        buf[2..6].copy_from_slice(&lba.to_le_bytes());
        buf[6..10].copy_from_slice(&lba.to_be_bytes());
        buf[10..14].copy_from_slice(&size.to_le_bytes());
        buf[14..18].copy_from_slice(&size.to_be_bytes());
        // Recording date/time (7 bytes) — fixed valid values.
        buf[18..25].copy_from_slice(&[125, 1, 15, 12, 0, 0, 0]);
        buf[25] = flags_byte;
        buf[26] = 0; // file unit size
        buf[27] = 0; // interleave gap
        buf[28..30].copy_from_slice(&1u16.to_le_bytes());
        buf[30..32].copy_from_slice(&1u16.to_be_bytes());
        buf[32] = name_len as u8;
        buf[33..33 + name_len].copy_from_slice(name);
        len
    }

    /// Build a minimal ISO9660 image: PVD at sector 16, root dir at sector
    /// 20 holding `HELLO.TXT;1` (sector 22) and subdir `SUBDIR` (sector 24)
    /// with `INNER.BIN;1` (sector 26).
    fn make_test_iso() -> Vec<u8> {
        const S: usize = ISO_SECTOR;
        let mut img = vec![0u8; 40 * S];
        // Primary volume descriptor at sector 16.
        let pvd = 16 * S;
        img[pvd] = 0x01;
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 6] = 0x01;
        put_dir_record(&mut img[pvd + 156..], 20, S as u32, 0x02, &[0x00]);
        // Volume descriptor set terminator at sector 17.
        img[17 * S] = 0xFF;
        img[17 * S + 1..17 * S + 6].copy_from_slice(b"CD001");
        // Root directory extent (sector 20).
        let mut pos = 20 * S;
        pos += put_dir_record(&mut img[pos..], 20, S as u32, 0x02, &[0x00]);
        pos += put_dir_record(&mut img[pos..], 20, S as u32, 0x02, &[0x01]);
        pos += put_dir_record(&mut img[pos..], 22, 11, 0x00, b"HELLO.TXT;1");
        put_dir_record(&mut img[pos..], 24, S as u32, 0x02, b"SUBDIR");
        // File payload at sector 22.
        img[22 * S..22 * S + 11].copy_from_slice(b"hello world");
        // SUBDIR extent (sector 24).
        let mut pos = 24 * S;
        pos += put_dir_record(&mut img[pos..], 24, S as u32, 0x02, &[0x00]);
        pos += put_dir_record(&mut img[pos..], 20, S as u32, 0x02, &[0x01]);
        put_dir_record(&mut img[pos..], 26, 4, 0x00, b"INNER.BIN;1");
        img[26 * S..26 * S + 4].copy_from_slice(b"INNR");
        img
    }

    #[test]
    fn iso9660_list_and_extract() {
        let data = make_test_iso();
        assert!(is_iso9660(&data));
        assert!(is_archive(&data));
        let (kind, members) = list_archive_members(&data).unwrap();
        assert_eq!(kind, ArchiveKind::Iso9660);
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"HELLO.TXT"), "{:?}", names);
        assert!(names.contains(&"SUBDIR"), "{:?}", names);
        assert!(names.contains(&"SUBDIR/INNER.BIN"), "{:?}", names);
        assert_eq!(extract_member(&data, "HELLO.TXT"), b"hello world");
        assert_eq!(extract_member(&data, "SUBDIR/INNER.BIN"), b"INNR");
        let flags = ScanFlags::default();
        let extracted = extract_iso9660(&data, &flags);
        assert_eq!(extracted.len(), 2);
    }

    #[test]
    fn iso9660_malformed_does_not_panic() {
        let data = make_test_iso();
        // Truncations at key boundaries.
        for cut in [0x8000, 0x8006, 20 * ISO_SECTOR + 10, data.len() - 1] {
            let _ = list_archive_members(&data[..cut]);
            let _ = extract_member(&data[..cut], "HELLO.TXT");
            let flags = ScanFlags::default();
            let _ = extract_iso9660(&data[..cut], &flags);
        }
        // Corrupt root extent LBA to point past EOF.
        let mut bad = data.clone();
        bad[16 * ISO_SECTOR + 156 + 2..16 * ISO_SECTOR + 156 + 6]
            .copy_from_slice(&0xFFFFu32.to_le_bytes());
        assert!(list_archive_members(&bad).is_some());
        assert!(extract_member(&bad, "HELLO.TXT").is_empty());
        // Zero-length / oversized directory records must not hang.
        let mut bad2 = data;
        bad2[20 * ISO_SECTOR] = 0;
        assert!(list_archive_members(&bad2).is_some());
        assert!(extract_member(&bad2, "HELLO.TXT").is_empty());
    }

    #[test]
    fn is_iso9660_rejects_short_and_non_pvd() {
        assert!(!is_iso9660(b"CD001"));
        let mut img = vec![0u8; 0x8010];
        img[0x8001..0x8006].copy_from_slice(b"CD001");
        // Type byte 0 (boot record), not primary.
        assert!(!is_iso9660(&img));
        img[0x8000] = 0x01;
        assert!(is_iso9660(&img));
    }

    // -- Phase 18.C: BZ2/XZ/LZMA single streams ----------------------------

    /// `bzip2.compress(b"hello world")` (48 bytes, BZh9 block size).
    const BZ2_HELLO: &[u8] = &[
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x44, 0xf7, 0x13, 0x78, 0x00,
        0x00, 0x01, 0x91, 0x80, 0x40, 0x00, 0x06, 0x44, 0x90, 0x80, 0x20, 0x00, 0x22, 0x03, 0x34,
        0x84, 0x30, 0x21, 0xb6, 0x81, 0x54, 0x27, 0x8b, 0xb9, 0x22, 0x9c, 0x28, 0x48, 0x22, 0x7b,
        0x89, 0xbc, 0x00,
    ];

    #[test]
    fn bz2_stream_roundtrip() {
        assert!(is_bz2(BZ2_HELLO));
        assert!(!is_bz2(b"BZh0"));
        assert!(is_archive(BZ2_HELLO));
        let (kind, members) = list_archive_members(BZ2_HELLO).unwrap();
        assert_eq!(kind, ArchiveKind::Bz2);
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "data");
        assert_eq!(members[0].size, 11);
        assert_eq!(extract_member(BZ2_HELLO, "data"), b"hello world");
        // Only the `data` pseudo-member exists.
        assert!(extract_member(BZ2_HELLO, "other").is_empty());
        let flags = ScanFlags::default();
        let all = extract_archive(BZ2_HELLO, &flags);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].data, b"hello world");
    }

    #[test]
    fn xz_stream_roundtrip() {
        let mut input: &[u8] = b"hello world";
        let mut out = Vec::new();
        lzma_rs::xz_compress(&mut input, &mut out).unwrap();
        assert!(is_xz(&out));
        let (kind, members) = list_archive_members(&out).unwrap();
        assert_eq!(kind, ArchiveKind::Xz);
        assert_eq!(members[0].size, 11);
        assert_eq!(extract_member(&out, "data"), b"hello world");
    }

    #[test]
    fn lzma_stream_roundtrip() {
        let mut input: &[u8] = b"hello world";
        let mut out = Vec::new();
        lzma_rs::lzma_compress(&mut input, &mut out).unwrap();
        assert!(is_lzma(&out));
        let (kind, members) = list_archive_members(&out).unwrap();
        assert_eq!(kind, ArchiveKind::Lzma);
        assert_eq!(members[0].size, 11);
        assert_eq!(extract_member(&out, "data"), b"hello world");
    }

    #[test]
    fn stream_truncated_does_not_panic() {
        for cut in [4, 10, 20, 47] {
            let _ = list_archive_members(&BZ2_HELLO[..cut]);
            let _ = extract_member(&BZ2_HELLO[..cut], "data");
            let flags = ScanFlags::default();
            let _ = extract_archive(&BZ2_HELLO[..cut], &flags);
        }
        // Random garbage must not decode.
        assert!(decompress_stream(b"not a stream").is_none());
        // LZMA heuristic rejects out-of-range props byte.
        assert!(!is_lzma(&[0xE1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }

    /// Corpus fixture loader (repo `corpus/` directory).
    fn corpus(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus")
            .join(name);
        std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    /// Phase 28: packer/protector containers are browsable through the
    /// explicit list/extract path (upstream archive-widget parity) but are
    /// deliberately NOT part of `is_archive`/`extract_archive` — upstream
    /// never recurses into them during nested scans.
    #[test]
    fn container_members_list_and_extract() {
        let evb = corpus("enigmavb-minimal.exe");
        let (kind, members) = list_archive_members(&evb).expect("enigmavb list");
        assert_eq!(kind, ArchiveKind::EnigmaVb);
        assert!(members.iter().any(|m| m.name == "readme.txt"));
        assert!(members.iter().any(|m| m.name == "data.bin"));
        assert!(!extract_member(&evb, "readme.txt").is_empty());
        assert!(extract_member(&evb, "missing.bin").is_empty());

        let bxp = corpus("boxedapp-minimal.exe");
        let (kind, members) = list_archive_members(&bxp).expect("boxedapp list");
        assert_eq!(kind, ArchiveKind::BoxedApp);
        assert!(!members.is_empty());
        let first = members[0].name.clone();
        assert_eq!(extract_member(&bxp, &first).len() as u64, members[0].size);

        let au = corpus("autoit-ea06.bin");
        let (kind, members) = list_archive_members(&au).expect("autoit list");
        assert_eq!(kind, ArchiveKind::AutoIt);
        assert!(!members.is_empty());

        // Nested-scan extraction must not emit container records (the
        // container kinds are list/extract-path only). `is_archive` may
        // still match through the pre-existing weak LZMA heuristic — that
        // is unrelated to the container detectors.
        let flags = ScanFlags::default();
        for blob in [&evb, &bxp, &au] {
            let members = extract_archive(blob, &flags);
            assert!(
                members
                    .iter()
                    .all(|m| m.name != "readme.txt" && m.name != "data.bin"),
                "container record leaked into nested-scan path: {members:?}"
            );
        }
    }
}

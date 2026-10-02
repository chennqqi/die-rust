//! Archive member extraction for nested recursive scanning.
//!
//! Supports ZIP, 7Z, and RAR archive formats. Each format has a dedicated
//! extraction function that returns extracted member bytes with safety bounds
//! enforcement (ADR 0030).
//!
//! CAB and ISO9660 are not yet implemented (deferred to future work).
//! The upstream DIE-engine supports all 5 formats, but CAB and ISO9660
//! extraction requires additional libraries that are not yet integrated.

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
    } else {
        vec![]
    }
}

/// Check if data is any supported archive format.
pub fn is_archive(data: &[u8]) -> bool {
    is_zip(data) || is_7z(data) || is_rar(data)
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
}

impl ArchiveKind {
    /// Uppercase display name (upstream archive widget style).
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Zip => "ZIP",
            Self::SevenZ => "7Z",
            Self::Rar => "RAR",
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

/// List members of a supported archive (ZIP/7Z/RAR) with metadata only.
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
    } else {
        None
    }
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
    } else {
        Vec::new()
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
}

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

/// Decompress a single ZIP member by exact name and return it as a
/// lossy-UTF8 string, bounded to `MAX_MEMBER_STRING_BYTES`.
///
/// Mirrors upstream `XArchive::decompress(record)` for text records such as
/// `META-INF/MANIFEST.MF` (JAR/APK) and `package/package.json` (NPM).
/// Returns an empty string when the member is absent or undecodable.
pub fn zip_member_string(data: &[u8], name: &str) -> String {
    if !is_zip(data) || name.is_empty() {
        return String::new();
    }
    let cursor = std::io::Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return String::new(),
    };
    let mut file = match archive.by_name(name) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    if file.is_dir() || file.size() > MAX_MEMBER_STRING_BYTES {
        return String::new();
    }
    let mut buf = Vec::with_capacity(file.size() as usize);
    if std::io::Read::read_to_end(&mut file, &mut buf).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&buf).into_owned()
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
}

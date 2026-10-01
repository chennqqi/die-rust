//! Host API adapter bridging `diec-rules::HostApi` to file bytes.
//!
//! This adapter provides the `HostApi` implementation that rule scripts
//! use to access binary file data. It wraps an `OwnedSource` and provides
//! read primitives, signature checking, and string reading.

use diec_core::format::FileType;
use diec_core::input::{ByteSource, ByteView, OwnedSource};
use diec_rules::host_api::{HostApi, HostApiError};
use diec_rules::host_api_bridge::{match_signature, parse_signature};
use std::sync::Arc;

/// A simple host API backed by an in-memory byte buffer.
///
/// This adapter provides the core `Binary_Script` host API methods
/// by reading directly from the owned byte source. Format-specific
/// methods (PE sections, ELF segments, etc.) are not implemented here.
/// Scan options that control rule behavior (deep, heuristic, verbose, etc.).
/// These map to upstream CLI flags: --deepscan, --heuristicscan, --verbose,
/// --aggressivescan, --alltypes, --hideunknown.
#[derive(Debug, Clone, Default)]
pub struct ScanFlags {
    /// Deep scan mode (--deepscan).
    pub deep: bool,
    /// Heuristic scan mode (--heuristicscan).
    pub heuristic: bool,
    /// Verbose output (--verbose).
    pub verbose: bool,
    /// Aggressive scan mode (--aggressivescan).
    pub aggressive: bool,
    /// All types scan mode (--alltypes).
    pub all_types: bool,
    /// Hide unknown detections (--hideunknown).
    pub hide_unknown: bool,
    /// Disable result deduplication (--no-dedup).
    ///
    /// When `false` (default), duplicate detections from `--alltypes` mode
    /// are removed. When `true`, all detections are kept (matching upstream
    /// behavior). See ADR 0027.
    pub no_dedup: bool,
    /// Optional file type override. When `Some`, only rules for the specified
    /// file type are run, bypassing automatic format detection. This maps to
    /// the upstream `comboBoxType` file type selector in the GUI.
    pub file_type: Option<String>,
    /// Intra-file recursive scan (--recursivescan / -r).
    ///
    /// When true, PE resources and overlay are extracted and recursively
    /// scanned as sub-devices. Matches upstream `bIsRecursiveScan`.
    /// See ADR 0028.
    pub recursive: bool,
    /// Scan PE resources (--resources). When true, only resources are
    /// extracted and scanned. Implied by `recursive`.
    pub resources: bool,
    /// Scan PE overlay (--overlays). When true, only overlay is extracted
    /// and scanned. Implied by `recursive`.
    pub overlays: bool,
    /// Scan archive members (--archives). When true, archive members are
    /// extracted and recursively scanned. See ADR 0030.
    pub archives: bool,
}

/// A host API implementation backed by an in-memory byte buffer.
/// Provides file data access and scan mode flags to the rule runtime.
pub struct BufferHost {
    /// The file type context.
    file_type: FileType,
    /// The owned byte source.
    source: OwnedSource,
    /// The file name.
    file_name: String,
    /// Scan flags controlling rule behavior.
    flags: ScanFlags,
}

impl BufferHost {
    /// Create a new `BufferHost` from a byte buffer and file name.
    pub fn new(data: Vec<u8>, file_name: String) -> Self {
        let arc_data: Arc<[u8]> = Arc::from(data);
        let source = OwnedSource::new(arc_data);
        let file_type = determine_file_type(&file_name);
        Self {
            file_type,
            source,
            file_name,
            flags: ScanFlags::default(),
        }
    }

    /// Create a `BufferHost` for a specific file type.
    pub fn with_type(data: Vec<u8>, file_name: String, file_type: &str) -> Self {
        let arc_data: Arc<[u8]> = Arc::from(data);
        let source = OwnedSource::new(arc_data);
        Self {
            file_type: FileType::new(file_type),
            source,
            file_name,
            flags: ScanFlags::default(),
        }
    }

    /// Set scan flags on this host.
    pub fn with_flags(mut self, flags: ScanFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Get the underlying data as a slice.
    fn data(&self) -> &[u8] {
        self.source.as_slice()
    }
}

/// Determine the file type from the file name extension.
fn determine_file_type(name: &str) -> FileType {
    let lower = name.to_lowercase();
    if lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".sys") {
        FileType::new("PE")
    } else if lower.ends_with(".so") || lower.ends_with(".o") || lower.ends_with(".elf") {
        FileType::new("ELF")
    } else if lower.ends_with(".dylib") || lower.ends_with(".macho") {
        FileType::new("MACH")
    } else {
        FileType::new("Binary")
    }
}

impl HostApi for BufferHost {
    fn file_type(&self) -> &FileType {
        &self.file_type
    }

    fn view(&self) -> &ByteView<'_> {
        // Create a temporary view on each call. This is not ideal but
        // works for the current usage where view() is rarely called.
        // A proper solution would use self-referential types or
        // restructure the trait to avoid the lifetime issue.
        unimplemented!("ByteView lifetime prevents storing it; use data() directly")
    }

    fn read_u8(&self, offset: u64) -> Result<u8, HostApiError> {
        let data = self.data();
        let idx = offset as usize;
        if idx >= data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: data.len() as u64,
            });
        }
        Ok(data[idx])
    }

    /// Bulk copy override for `read_bytes`: copies the in-bounds prefix of
    /// `buf` directly from the backing slice.
    fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> usize {
        let data = self.data();
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        if start >= data.len() {
            return 0;
        }
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        n
    }

    /// ZIP-family member name enumeration (upstream `XArchive::getRecords`).
    fn archive_record_names(&self) -> Vec<String> {
        crate::archive_unpack::zip_member_names(self.data())
    }

    /// ZIP-family member decompression (upstream `XArchive::decompress`).
    fn archive_record_string(&self, name: &str) -> String {
        crate::archive_unpack::zip_member_string(self.data(), name)
    }

    /// Decoded AndroidManifest.xml (upstream `XAndroidBinary::getDecoded`).
    fn android_manifest(&self) -> String {
        let bytes = crate::archive_unpack::zip_member_bytes(self.data(), "AndroidManifest.xml");
        if bytes.is_empty() {
            return String::new();
        }
        crate::axml::decode_axml(&bytes)
    }

    fn read_u16_le(&self, offset: u64) -> Result<u16, HostApiError> {
        let data = self.data();
        let idx = offset as usize;
        let end = idx.checked_add(2).ok_or(HostApiError::OutOfBounds {
            offset,
            file_size: data.len() as u64,
        })?;
        if end > data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: data.len() as u64,
            });
        }
        Ok(u16::from_le_bytes([data[idx], data[idx + 1]]))
    }

    fn read_u16_be(&self, offset: u64) -> Result<u16, HostApiError> {
        let data = self.data();
        let idx = offset as usize;
        let end = idx.checked_add(2).ok_or(HostApiError::OutOfBounds {
            offset,
            file_size: data.len() as u64,
        })?;
        if end > data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: data.len() as u64,
            });
        }
        Ok(u16::from_be_bytes([data[idx], data[idx + 1]]))
    }

    fn read_u24_le(&self, offset: u64) -> Result<u32, HostApiError> {
        let data = self.data();
        let idx = offset as usize;
        let end = idx.checked_add(3).ok_or(HostApiError::OutOfBounds {
            offset,
            file_size: data.len() as u64,
        })?;
        if end > data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: data.len() as u64,
            });
        }
        Ok(u32::from_le_bytes([
            data[idx],
            data[idx + 1],
            data[idx + 2],
            0,
        ]))
    }

    fn read_u24_be(&self, offset: u64) -> Result<u32, HostApiError> {
        let data = self.data();
        let idx = offset as usize;
        let end = idx.checked_add(3).ok_or(HostApiError::OutOfBounds {
            offset,
            file_size: data.len() as u64,
        })?;
        if end > data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: data.len() as u64,
            });
        }
        Ok(u32::from_be_bytes([
            data[idx],
            data[idx + 1],
            data[idx + 2],
            0,
        ]))
    }

    fn read_u32_le(&self, offset: u64) -> Result<u32, HostApiError> {
        let data = self.data();
        let idx = offset as usize;
        let end = idx.checked_add(4).ok_or(HostApiError::OutOfBounds {
            offset,
            file_size: data.len() as u64,
        })?;
        if end > data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: data.len() as u64,
            });
        }
        Ok(u32::from_le_bytes([
            data[idx],
            data[idx + 1],
            data[idx + 2],
            data[idx + 3],
        ]))
    }

    fn read_u32_be(&self, offset: u64) -> Result<u32, HostApiError> {
        let data = self.data();
        let idx = offset as usize;
        let end = idx.checked_add(4).ok_or(HostApiError::OutOfBounds {
            offset,
            file_size: data.len() as u64,
        })?;
        if end > data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: data.len() as u64,
            });
        }
        Ok(u32::from_be_bytes([
            data[idx],
            data[idx + 1],
            data[idx + 2],
            data[idx + 3],
        ]))
    }

    fn read_u64_le(&self, offset: u64) -> Result<u64, HostApiError> {
        let data = self.data();
        let idx = offset as usize;
        let end = idx.checked_add(8).ok_or(HostApiError::OutOfBounds {
            offset,
            file_size: data.len() as u64,
        })?;
        if end > data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: data.len() as u64,
            });
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[idx..end]);
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_u64_be(&self, offset: u64) -> Result<u64, HostApiError> {
        let data = self.data();
        let idx = offset as usize;
        let end = idx.checked_add(8).ok_or(HostApiError::OutOfBounds {
            offset,
            file_size: data.len() as u64,
        })?;
        if end > data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: data.len() as u64,
            });
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[idx..end]);
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_i8(&self, offset: u64) -> Result<i8, HostApiError> {
        self.read_u8(offset).map(|v| v as i8)
    }

    fn read_i16_le(&self, offset: u64) -> Result<i16, HostApiError> {
        self.read_u16_le(offset).map(|v| v as i16)
    }

    fn read_i32_le(&self, offset: u64) -> Result<i32, HostApiError> {
        self.read_u32_le(offset).map(|v| v as i32)
    }

    fn read_i64_le(&self, offset: u64) -> Result<i64, HostApiError> {
        self.read_u64_le(offset).map(|v| v as i64)
    }

    fn file_size(&self) -> u64 {
        self.source.len()
    }

    fn check_signature(&self, offset: u64, signature: &str) -> Result<bool, HostApiError> {
        let elements =
            parse_signature(signature).map_err(|detail| HostApiError::InvalidSignature {
                pattern: signature.into(),
                detail,
            })?;
        Ok(match_signature(self.data(), offset as usize, &elements))
    }

    fn find_signature(&self, start: u64, signature: &str) -> Result<Option<u64>, HostApiError> {
        let elements =
            parse_signature(signature).map_err(|detail| HostApiError::InvalidSignature {
                pattern: signature.into(),
                detail,
            })?;
        let data = self.data();
        let start = start as usize;
        if elements.is_empty()
            || start
                .checked_add(elements.len())
                .is_none_or(|end| end > data.len())
        {
            return Ok(None);
        }
        for i in start..=data.len() - elements.len() {
            if match_signature(data, i, &elements) {
                return Ok(Some(i as u64));
            }
        }
        Ok(None)
    }

    fn find_signature_in_range(
        &self,
        start: u64,
        end: u64,
        signature: &str,
    ) -> Result<Option<u64>, HostApiError> {
        let elements =
            parse_signature(signature).map_err(|detail| HostApiError::InvalidSignature {
                pattern: signature.into(),
                detail,
            })?;
        let data = self.data();
        let start = start as usize;
        let end = (end as usize).min(data.len());
        if elements.is_empty()
            || start >= end
            || end < elements.len()
            || start > end - elements.len()
        {
            return Ok(None);
        }
        for i in start..=end - elements.len() {
            if match_signature(data, i, &elements) {
                return Ok(Some(i as u64));
            }
        }
        Ok(None)
    }

    fn read_string(&self, offset: u64, max_len: u64) -> Result<String, HostApiError> {
        let data = self.data();
        let start = offset as usize;
        let max = if max_len == 0 {
            data.len()
        } else {
            (start + max_len as usize).min(data.len())
        };
        if start >= data.len() {
            return Ok(String::new());
        }
        let end = data[start..max]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(max);
        String::from_utf8(data[start..end].to_vec()).map_err(|e| HostApiError::Internal {
            detail: format!("invalid UTF-8 at offset {offset}: {e}"),
        })
    }

    fn file_name(&self) -> &str {
        &self.file_name
    }

    fn entry_point(&self) -> Result<u64, HostApiError> {
        Ok(0)
    }

    fn is_deep(&self) -> bool {
        self.flags.deep
    }

    fn is_heuristic(&self) -> bool {
        self.flags.heuristic
    }

    fn is_aggressive(&self) -> bool {
        self.flags.aggressive
    }

    fn is_verbose(&self) -> bool {
        self.flags.verbose
    }

    fn is_recursive(&self) -> bool {
        self.flags.recursive || self.flags.resources || self.flags.overlays
    }

    fn entropy(&self, offset: u64, size: u64) -> Result<f64, HostApiError> {
        let data = self.data();
        let start = offset as usize;
        let end = (start + size as usize).min(data.len());
        if start >= end {
            return Ok(0.0);
        }
        let mut counts = [0u32; 256];
        for &b in &data[start..end] {
            counts[b as usize] += 1;
        }
        let total = (end - start) as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }
        Ok(entropy)
    }

    fn md5(&self, offset: u64, size: u64) -> Result<String, HostApiError> {
        let data = self.data();
        let start = offset as usize;
        let end = start.saturating_add(size as usize);
        if start > data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: data.len() as u64,
            });
        }
        if end > data.len() {
            return Err(HostApiError::Truncated {
                offset,
                length: size,
                available: data.len().saturating_sub(start) as u64,
            });
        }
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(&data[start..end]);
        let digest = hasher.finalize();
        Ok(format!("{:x}", digest))
    }

    fn crc32(&self, offset: u64, size: u64) -> Result<u32, HostApiError> {
        let data = self.data();
        let start = offset as usize;
        let end = start.saturating_add(size as usize);
        if start > data.len() {
            return Err(HostApiError::OutOfBounds {
                offset,
                file_size: data.len() as u64,
            });
        }
        if end > data.len() {
            return Err(HostApiError::Truncated {
                offset,
                length: size,
                available: data.len().saturating_sub(start) as u64,
            });
        }
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&data[start..end]);
        Ok(hasher.finalize())
    }

    fn pe_batch(&self) -> Option<diec_rules::pe_native::PeBatchInfo> {
        diec_rules::pe_native::parse_batch(self.data())
    }

    fn pe_import_libraries(&self) -> Vec<String> {
        diec_rules::pe_native::get_import_libraries(self.data())
    }

    fn pe_import_functions(&self) -> Vec<String> {
        diec_rules::pe_native::get_import_functions(self.data())
    }

    fn pe_export_names(&self) -> Vec<String> {
        diec_rules::pe_native::get_export_names(self.data())
    }

    fn elf_import_libraries(&self) -> Vec<String> {
        diec_rules::elf_native::get_import_libraries(self.data())
    }

    fn elf_section_names(&self) -> Vec<String> {
        diec_rules::elf_native::get_section_names(self.data())
    }

    fn macho_import_libraries(&self) -> Vec<String> {
        diec_rules::macho_native::get_import_libraries(self.data())
    }

    fn macho_section_names(&self) -> Vec<String> {
        diec_rules::macho_native::get_section_names(self.data())
    }

    fn pe_manifest(&self) -> String {
        diec_rules::pe_native::get_manifest(self.data())
    }

    fn pe_is_net(&self) -> bool {
        diec_rules::pe_native::is_net(self.data())
    }

    fn pe_net_version(&self) -> String {
        diec_rules::pe_native::get_net_version(self.data())
    }

    fn pe_file_version(&self) -> String {
        diec_rules::pe_native::get_file_version(self.data())
    }

    fn pe_product_version(&self) -> String {
        diec_rules::pe_native::get_product_version(self.data())
    }

    fn pe_version_string(&self, key: &str) -> String {
        diec_rules::pe_native::get_version_string(self.data(), key)
    }

    fn pe_number_of_resources(&self) -> usize {
        diec_rules::pe_native::get_number_of_resources(self.data())
    }

    fn pe_is_resource_name_present(&self, name: &str) -> bool {
        diec_rules::pe_native::is_resource_name_present(self.data(), name)
    }

    fn pe_is_resource_group_name_present(&self, group_name: &str) -> bool {
        diec_rules::pe_native::is_resource_group_name_present(self.data(), group_name)
    }

    fn pe_is_resource_group_id_present(&self, group_id: u32) -> bool {
        diec_rules::pe_native::is_resource_group_id_present(self.data(), group_id)
    }

    fn pe_resource_section_offset(&self) -> i64 {
        diec_rules::pe_native::get_resource_section_offset(self.data())
    }

    fn pe_is_signed(&self) -> bool {
        diec_rules::pe_native::is_signed(self.data())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify md5() computes the correct hash for a known input.
    #[test]
    fn md5_computes_known_hash() {
        let data = b"hello world".to_vec();
        let host = BufferHost::new(data, "test.bin".to_string());
        let hash = host.md5(0, 11).unwrap();
        // Known MD5 of "hello world"
        assert_eq!(hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    /// Verify crc32() computes the correct checksum for a known input.
    #[test]
    fn crc32_computes_known_checksum() {
        // CRC32 of "hello world" (IEEE 802.3 polynomial)
        let data = b"hello world".to_vec();
        let host = BufferHost::new(data, "test.bin".to_string());
        let crc = host.crc32(0, 11).unwrap();
        assert_eq!(crc, 0x0d4a1185);
    }

    /// Verify md5() returns OutOfBounds for offset beyond file.
    #[test]
    fn md5_out_of_bounds_returns_error() {
        let data = b"short".to_vec();
        let host = BufferHost::new(data, "test.bin".to_string());
        let err = host.md5(100, 10).unwrap_err();
        assert!(matches!(err, HostApiError::OutOfBounds { .. }));
    }

    /// Verify crc32() returns Truncated when range extends beyond file.
    #[test]
    fn crc32_truncated_returns_error() {
        let data = b"short".to_vec();
        let host = BufferHost::new(data, "test.bin".to_string());
        let err = host.crc32(2, 100).unwrap_err();
        assert!(matches!(err, HostApiError::Truncated { .. }));
    }

    /// Verify md5() of empty range returns the empty-string MD5.
    #[test]
    fn md5_empty_range_returns_empty_hash() {
        let data = b"some data".to_vec();
        let host = BufferHost::new(data, "test.bin".to_string());
        let hash = host.md5(0, 0).unwrap();
        // MD5 of empty input
        assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }
}

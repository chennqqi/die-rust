//! Host data access API port.
//!
//! `HostApi` is the interface through which rule scripts access binary file
//! data. It is defined here in `diec-rules` and implemented by `diec-engine`'s
//! adapter, so the rule layer does not depend on `diec-formats`.
//!
//! See `docs/design/architecture.md` section 9: "`HostApi` 由 `diec-rules`
//! 定义，由 `diec-engine` 的 adapter 实现".
//!
//! The upstream host API has 337 methods across 30 classes. This trait
//! defines the core read primitives that all format-specific host objects
//! share. Format-specific extensions (PE sections, ELF segments, etc.) are
//! added via separate traits that extend `HostApi`.

use diec_core::format::FileType;
use diec_core::input::ByteView;

/// Host data access API for rule execution.
///
/// This trait provides the methods that rule scripts call via the `Binary`,
/// `PE`, `ELF`, `MACH`, etc. host objects. The implementor (diec-engine's
/// adapter) bridges between the rule runtime and the parsed format data.
///
/// All methods return `Result<T, HostApiError>` to allow the runtime to
/// distinguish between "not found" (returns default/false) and "internal
/// error" (produces a diagnostic).
pub trait HostApi {
    /// The file type context for this host API instance (e.g. "Binary", "PE").
    fn file_type(&self) -> &FileType;

    /// The byte view providing access to the file's raw bytes.
    fn view(&self) -> &ByteView<'_>;

    // --- Core read primitives (Binary_Script subset) ---

    /// Read an unsigned 8-bit integer at the given offset.
    fn read_u8(&self, offset: u64) -> Result<u8, HostApiError>;

    /// Read an unsigned 16-bit little-endian integer at the given offset.
    fn read_u16_le(&self, offset: u64) -> Result<u16, HostApiError>;

    /// Read an unsigned 16-bit big-endian integer at the given offset.
    fn read_u16_be(&self, offset: u64) -> Result<u16, HostApiError>;

    /// Read an unsigned 24-bit little-endian integer at the given offset.
    fn read_u24_le(&self, offset: u64) -> Result<u32, HostApiError>;

    /// Read an unsigned 24-bit big-endian integer at the given offset.
    fn read_u24_be(&self, offset: u64) -> Result<u32, HostApiError>;

    /// Read an unsigned 32-bit little-endian integer at the given offset.
    fn read_u32_le(&self, offset: u64) -> Result<u32, HostApiError>;

    /// Read an unsigned 32-bit big-endian integer at the given offset.
    fn read_u32_be(&self, offset: u64) -> Result<u32, HostApiError>;

    /// Read an unsigned 64-bit little-endian integer at the given offset.
    fn read_u64_le(&self, offset: u64) -> Result<u64, HostApiError>;

    /// Read an unsigned 64-bit big-endian integer at the given offset.
    fn read_u64_be(&self, offset: u64) -> Result<u64, HostApiError>;

    /// Read a signed 8-bit integer at the given offset.
    fn read_i8(&self, offset: u64) -> Result<i8, HostApiError>;

    /// Read a signed 16-bit little-endian integer at the given offset.
    fn read_i16_le(&self, offset: u64) -> Result<i16, HostApiError>;

    /// Read a signed 32-bit little-endian integer at the given offset.
    fn read_i32_le(&self, offset: u64) -> Result<i32, HostApiError>;

    /// Read a signed 64-bit little-endian integer at the given offset.
    fn read_i64_le(&self, offset: u64) -> Result<i64, HostApiError>;

    /// Get the total file size in bytes.
    fn file_size(&self) -> u64;

    // --- Signature and string search ---

    /// Check if a signature pattern matches at the given offset.
    ///
    /// The signature format follows the upstream DIE convention:
    /// `'hex'` for hex bytes, `"string"` for ASCII strings.
    fn check_signature(&self, offset: u64, signature: &str) -> Result<bool, HostApiError>;

    /// Find the first occurrence of a signature pattern starting from the
    /// given offset. Returns the offset of the match, or `None` if not found.
    fn find_signature(&self, start: u64, signature: &str) -> Result<Option<u64>, HostApiError>;

    /// Find the first occurrence of a signature pattern within the range
    /// `[start, end)`. Returns the offset of the match, or `None` if not found.
    fn find_signature_in_range(
        &self,
        start: u64,
        end: u64,
        signature: &str,
    ) -> Result<Option<u64>, HostApiError>;

    /// Read a NUL-terminated ASCII string starting at the given offset,
    /// up to `max_len` bytes.
    fn read_string(&self, offset: u64, max_len: u64) -> Result<String, HostApiError>;

    /// Read raw bytes into `buf` starting at `offset`, returning the number
    /// of bytes actually written. Reads stop at the end of the file or on
    /// the first failing byte; this mirrors `ByteView::read_at` semantics
    /// and never errors on a short read.
    ///
    /// The default implementation reads byte-by-byte via `read_u8`;
    /// implementors with contiguous storage should override it with a bulk
    /// copy for performance.
    fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> usize {
        for (i, b) in buf.iter_mut().enumerate() {
            match self.read_u8(offset + i as u64) {
                Ok(v) => *b = v,
                Err(_) => return i,
            }
        }
        buf.len()
    }

    // --- Archive record access (Archive_Script subset) ---

    /// Names of archive member records (e.g. ZIP central directory file
    /// names). Returns an empty vector for non-archive inputs.
    /// Mirrors upstream `XArchive::getRecords` names.
    fn archive_record_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Decompressed content of an archive member as a string, or an empty
    /// string when the member is absent or the input is not an archive.
    /// Mirrors upstream `XArchive::decompress(record)`.
    fn archive_record_string(&self, _name: &str) -> String {
        String::new()
    }

    // --- File metadata ---

    /// Get the file name (basename) as a string.
    fn file_name(&self) -> &str;

    /// Get the entry point offset (RVA for PE, entry for ELF, etc.).
    fn entry_point(&self) -> Result<u64, HostApiError>;

    /// Check if the scan is in "deep" mode.
    fn is_deep(&self) -> bool;

    /// Check if the scan is in "heuristic" mode.
    fn is_heuristic(&self) -> bool;

    /// Check if the scan is in "aggressive" mode.
    fn is_aggressive(&self) -> bool;

    /// Check if the scan is in "verbose" mode.
    fn is_verbose(&self) -> bool;

    /// Check if the scan is in "recursive" mode.
    fn is_recursive(&self) -> bool;

    // --- Entropy and hashes ---

    /// Calculate the entropy of a byte range (0.0 to 8.0).
    fn entropy(&self, offset: u64, size: u64) -> Result<f64, HostApiError>;

    /// Calculate MD5 hash of a byte range, returned as lowercase hex.
    fn md5(&self, offset: u64, size: u64) -> Result<String, HostApiError>;

    /// Calculate CRC32 of a byte range.
    fn crc32(&self, offset: u64, size: u64) -> Result<u32, HostApiError>;

    // --- PE batch parsing (performance-critical) ---
    //
    // These methods parse PE import/export tables in a single Rust call,
    // avoiding tens of thousands of per-byte JS→Rust FFI round-trips.

    /// Parse all PE information in a single pass (imports, exports, resources,
    /// manifest, version info, .NET, Authenticode). Returns None for non-PE.
    fn pe_batch(&self) -> Option<crate::pe_native::PeBatchInfo>;

    /// Parse the PE import table and return all imported library names.
    /// Returns an empty vector for non-PE files or files without imports.
    fn pe_import_libraries(&self) -> Vec<String>;

    /// Parse the PE import table and return all imported function names.
    /// Returns an empty vector for non-PE files or files without imports.
    fn pe_import_functions(&self) -> Vec<String>;

    /// Parse the PE export table and return all exported function names.
    /// Returns an empty vector for non-PE files or files without exports.
    fn pe_export_names(&self) -> Vec<String>;

    // --- ELF batch parsing (performance-critical) ---
    //
    // These methods parse ELF dynamic imports/sections in a single Rust
    // call, avoiding per-byte JS->Rust FFI round-trips.

    /// Parse the ELF dynamic table and return all DT_NEEDED library names.
    /// Returns an empty vector for non-ELF files or files without imports.
    fn elf_import_libraries(&self) -> Vec<String>;

    /// Parse the ELF section headers and return all section names.
    /// Returns an empty vector for non-ELF files or files without sections.
    fn elf_section_names(&self) -> Vec<String>;

    // --- Mach-O batch parsing (performance-critical) ---

    /// Parse the Mach-O load commands and return all LC_LOAD_DYLIB library names.
    /// Returns an empty vector for non-Mach-O files or files without imports.
    fn macho_import_libraries(&self) -> Vec<String>;

    /// Parse the Mach-O segments and return all section names.
    /// Returns an empty vector for non-Mach-O files or files without sections.
    fn macho_section_names(&self) -> Vec<String>;

    // --- PE resource/version info (native pelite-backed) ---

    /// Get the PE manifest XML string from resources.
    /// Returns empty string if no manifest or not a valid PE.
    fn pe_manifest(&self) -> String;

    /// Check if the PE has a .NET CLR header.
    fn pe_is_net(&self) -> bool;

    /// Get the .NET CLR runtime version string (e.g., "v4.0.30319").
    /// Returns empty string if not .NET or version cannot be parsed.
    fn pe_net_version(&self) -> String {
        String::new()
    }

    /// Get the PE file version string (from VS_FIXEDFILEINFO).
    /// Returns empty string if no version info or not a valid PE.
    fn pe_file_version(&self) -> String;

    /// Get the PE product version string (from VS_FIXEDFILEINFO).
    /// Returns empty string if no version info or not a valid PE.
    fn pe_product_version(&self) -> String;

    /// Get a string value from the PE version info's StringFileInfo table.
    /// Common keys: CompanyName, FileDescription, FileVersion, InternalName,
    /// LegalCopyright, OriginalFilename, ProductName, ProductVersion, Comments.
    /// Returns empty string if not found or not a valid PE.
    fn pe_version_string(&self, key: &str) -> String;

    /// Count the total number of resource data entries.
    /// Returns 0 if not a valid PE or no resources.
    fn pe_number_of_resources(&self) -> usize;

    /// Check if a resource name is present in the resource directory.
    /// Returns false if not a valid PE or resource not found.
    fn pe_is_resource_name_present(&self, name: &str) -> bool;

    /// Check if a resource group (type-level directory) with the given name
    /// exists in the PE resource directory tree.
    /// Returns false if not a valid PE or group not found.
    fn pe_is_resource_group_name_present(&self, _group_name: &str) -> bool {
        false
    }

    /// Check if a resource group (type-level directory) with the given ID
    /// exists in the PE resource directory tree.
    /// Returns false if not a valid PE or group not found.
    fn pe_is_resource_group_id_present(&self, _group_id: u32) -> bool {
        false
    }

    /// Get the resource section file offset (data directory index 2).
    /// Returns -1 if not a valid PE or no resource section.
    fn pe_resource_section_offset(&self) -> i64;

    /// Check if the PE file is signed (has a certificate/security directory).
    /// Returns false if not a valid PE or not signed.
    fn pe_is_signed(&self) -> bool;
}

/// Error returned by host API methods.
#[derive(Debug, Clone)]
pub enum HostApiError {
    /// The requested offset is outside the file bounds.
    OutOfBounds {
        /// Requested offset.
        offset: u64,
        /// File size.
        file_size: u64,
    },
    /// The requested read would extend beyond the file bounds.
    Truncated {
        /// Starting offset.
        offset: u64,
        /// Requested length.
        length: u64,
        /// Available bytes from offset.
        available: u64,
    },
    /// The signature pattern is invalid.
    InvalidSignature {
        /// The invalid pattern.
        pattern: String,
        /// Why it is invalid.
        detail: String,
    },
    /// The method is not implemented for this file type.
    NotImplemented {
        /// Method name.
        method: String,
    },
    /// An internal error occurred.
    Internal {
        /// Error detail.
        detail: String,
    },
}

impl std::fmt::Display for HostApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostApiError::OutOfBounds { offset, file_size } => {
                write!(f, "offset {offset} out of bounds (file size {file_size})")
            }
            HostApiError::Truncated {
                offset,
                length,
                available,
            } => {
                write!(
                    f,
                    "read at {offset} length {length} truncated (only {available} bytes available)"
                )
            }
            HostApiError::InvalidSignature { pattern, detail } => {
                write!(f, "invalid signature '{pattern}': {detail}")
            }
            HostApiError::NotImplemented { method } => {
                write!(f, "method '{method}' not implemented for this file type")
            }
            HostApiError::Internal { detail } => {
                write!(f, "host API internal error: {detail}")
            }
        }
    }
}

impl std::error::Error for HostApiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_bounds_displays() {
        let err = HostApiError::OutOfBounds {
            offset: 100,
            file_size: 50,
        };
        assert_eq!(err.to_string(), "offset 100 out of bounds (file size 50)");
    }

    #[test]
    fn truncated_displays() {
        let err = HostApiError::Truncated {
            offset: 40,
            length: 20,
            available: 10,
        };
        assert_eq!(
            err.to_string(),
            "read at 40 length 20 truncated (only 10 bytes available)"
        );
    }

    #[test]
    fn invalid_signature_displays() {
        let err = HostApiError::InvalidSignature {
            pattern: "'XYZ'".into(),
            detail: "odd number of hex digits".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid signature ''XYZ'': odd number of hex digits"
        );
    }

    #[test]
    fn not_implemented_displays() {
        let err = HostApiError::NotImplemented {
            method: "getSectionNumber".into(),
        };
        assert_eq!(
            err.to_string(),
            "method 'getSectionNumber' not implemented for this file type"
        );
    }
}

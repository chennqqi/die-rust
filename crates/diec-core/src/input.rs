//! Checked input model: read-only byte sources, validated views and scan
//! source variants.
//!
//! Parsers never open paths or seek global file handles directly. They consume
//! a [`ByteSource`] through checked ranges only. Offsets and lengths use `u64`
//! internally; conversions to `usize` and any allocation are checked against
//! platform limits and the request budget before being performed. See
//! `docs/design/architecture.md` section 7 and ADR 0013.

use core::fmt;
use std::path::Path;

/// A half-open byte range `[start, start + length)` relative to a known view.
///
/// `start` and `length` are non-negative. The range is stored uncombined so
/// that callers can distinguish "absolute offset" from "relative view offset"
/// at the field level instead of overloading a single field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// Absolute or view-relative start offset in bytes.
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
}

impl ByteRange {
    /// Construct a range, returning `None` when `start + length` overflows.
    pub fn new(start: u64, length: u64) -> Option<Self> {
        let end = start.checked_add(length)?;
        // A zero-length range at `u64::MAX` is still valid (end == start).
        let _ = end;
        Some(Self { start, length })
    }

    /// The exclusive end offset, or `None` on overflow.
    pub fn end(self) -> Option<u64> {
        self.start.checked_add(self.length)
    }
}

/// Typed I/O error classification for checked input. Distinguishes
/// not-found, permission, short read, seek, not-seekable and invalid
/// argument; see `docs/design/api.md` section 12 and ADR 0013.
///
/// Short reads and invalid ranges must fail closed: the scanner must not
/// continue format probing, rule execution or generate a success detection
/// after any of these errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoError {
    /// The path or resource was not found.
    NotFound,
    /// Permission was denied.
    PermissionDenied,
    /// The source ended before the requested bytes were available.
    ///
    /// `offset` is the absolute source offset where the short read occurred,
    /// `expected` is the number of bytes requested, and `actual` is the
    /// number of bytes successfully read before EOF (may be zero).
    ShortRead {
        /// Absolute source offset of the failed read.
        offset: u64,
        /// Number of bytes requested.
        expected: usize,
        /// Number of bytes read before EOF (may be zero).
        actual: usize,
    },
    /// A seek was requested outside the valid range.
    SeekError,
    /// The source does not support random access (seekable) reads.
    ///
    /// Sequential or non-seekable sources must be rejected before entering
    /// any random-access parser; see ADR 0013 decision 6.
    NotSeekable,
    /// An argument (offset, size, or range) was invalid.
    ///
    /// Used for negative C/FFI parameters converted to unsigned, zero-size
    /// subdevice requests, or ranges that overflow; see ADR 0013 decision 4.
    InvalidArgument(String),
    /// A raw read or metadata operation failed.
    Other(String),
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IoError::NotFound => f.write_str("input not found"),
            IoError::PermissionDenied => f.write_str("permission denied"),
            IoError::ShortRead {
                offset,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "short read at offset {offset}: expected {expected} bytes, got {actual}"
                )
            }
            IoError::SeekError => f.write_str("seek out of range"),
            IoError::NotSeekable => f.write_str("source is not seekable"),
            IoError::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            IoError::Other(msg) => write!(f, "io error: {msg}"),
        }
    }
}

impl std::error::Error for IoError {}

/// Fixed-length, random-access byte source contract.
///
/// Implementations may borrow memory, own bytes, back by a file or mmap. Chunk
/// reads may make positive progress and fill less than requested on a
/// well-typed EOF, but a short read, seek or I/O error must be reported as a
/// typed [`IoError`] before probing. Implementations must not touch bytes
/// outside the requested range. `unsafe` file or mmap adapters live in a
/// separate adapter module and document their safety invariants.
pub trait ByteSource: fmt::Debug {
    /// The stable logical length of the source in bytes.
    fn len(&self) -> u64;

    /// `true` if the source contains zero bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read `out` bytes starting at `offset`, filling as much as available and
    /// returning the number of bytes read. A failure before any positive
    /// progress returns an [`IoError`].
    ///
    /// Implementations must not read beyond `[offset, offset + out.len())`.
    /// A zero-length `out` returns `Ok(0)` without touching the source.
    fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<usize, IoError>;

    /// Read exactly `out.len()` bytes starting at `offset`, or fail with
    /// [`IoError::ShortRead`] if the source ends early.
    ///
    /// This is the primary checked read for parsers. It loops on partial
    /// reads as long as positive progress is made; zero progress or an I/O
    /// error terminates immediately. See ADR 0013 decision 1-3.
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<(), IoError> {
        if out.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(out.len() as u64)
            .ok_or(IoError::SeekError)?;
        if end > self.len() {
            return Err(IoError::ShortRead {
                offset,
                expected: out.len(),
                actual: 0,
            });
        }
        let mut filled = 0usize;
        while filled < out.len() {
            let abs = offset
                .checked_add(filled as u64)
                .ok_or(IoError::SeekError)?;
            let n = self.read_at(abs, &mut out[filled..])?;
            if n == 0 {
                // No positive progress: EOF or error.
                return Err(IoError::ShortRead {
                    offset: abs,
                    expected: out.len() - filled,
                    actual: 0,
                });
            }
            filled += n;
        }
        Ok(())
    }
}

/// A [`ByteSource`] backed by a borrowed byte slice.
///
/// Zero-copy, no allocation. The lifetime is tied to the borrowed slice.
#[derive(Debug, Clone, Copy)]
pub struct MemorySource<'a> {
    data: &'a [u8],
}

impl<'a> MemorySource<'a> {
    /// Create a source from a borrowed byte slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// The underlying byte slice.
    pub fn as_slice(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a> ByteSource for MemorySource<'a> {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<usize, IoError> {
        if out.is_empty() {
            return Ok(0);
        }
        let start = usize::try_from(offset).map_err(|_| IoError::SeekError)?;
        if start >= self.data.len() {
            return Ok(0); // EOF: zero progress, read_exact_at will surface ShortRead
        }
        let available = &self.data[start..];
        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }
}

/// A [`ByteSource`] backed by owned bytes (`Arc<[u8]>`).
///
/// Cheap to clone (refcount only). Suitable for decoded/decompressed buffers
/// that need to outlive the original source.
#[derive(Debug, Clone)]
pub struct OwnedSource {
    data: std::sync::Arc<[u8]>,
}

impl OwnedSource {
    /// Create a source from owned bytes.
    pub fn new(data: std::sync::Arc<[u8]>) -> Self {
        Self { data }
    }

    /// The underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl ByteSource for OwnedSource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<usize, IoError> {
        if out.is_empty() {
            return Ok(0);
        }
        let start = usize::try_from(offset).map_err(|_| IoError::SeekError)?;
        if start >= self.data.len() {
            return Ok(0);
        }
        let available = &self.data[start..];
        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }
}

/// A [`ByteSource`] backed by a file, read via positioned reads.
///
/// This implementation reads the file length once at construction and uses
/// `seek + read` for each `read_at`. It does not mmap. The file handle is
/// held via `Arc` so the source is cloneable and shareable across threads
/// (the inner `File` is `Send + Sync`).
#[derive(Debug, Clone)]
pub struct FileSource {
    file: std::sync::Arc<std::fs::File>,
    len: u64,
}

impl FileSource {
    /// Open a file and create a source, returning [`IoError::NotFound`] or
    /// [`IoError::PermissionDenied`] as appropriate.
    pub fn open(path: &Path) -> Result<Self, IoError> {
        let file = std::fs::File::open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                IoError::NotFound
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                IoError::PermissionDenied
            } else {
                IoError::Other(e.to_string())
            }
        })?;
        let len = file
            .metadata()
            .map_err(|e| IoError::Other(e.to_string()))?
            .len();
        Ok(Self {
            file: std::sync::Arc::new(file),
            len,
        })
    }

    /// The file length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// `true` if the file is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl ByteSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<usize, IoError> {
        if out.is_empty() {
            return Ok(0);
        }
        use std::io::{Read, Seek, SeekFrom};
        let mut handle = self.file.as_ref();
        handle
            .seek(SeekFrom::Start(offset))
            .map_err(|e| IoError::Other(e.to_string()))?;
        let n = handle
            .read(out)
            .map_err(|e| IoError::Other(e.to_string()))?;
        Ok(n)
    }
}

/// A [`ByteSource`] backed by a slice that simulates chunked reads for testing.
///
/// Each `read_at` call returns at most `chunk_size` bytes, exercising the
/// positive-progress loop in `read_exact_at`. This is test-only infrastructure
/// that proves the checked read layer handles legitimate chunked devices.
#[derive(Debug, Clone, Copy)]
pub struct ChunkedSource<'a> {
    data: &'a [u8],
    chunk_size: usize,
}

impl<'a> ChunkedSource<'a> {
    /// Create a chunked source from a borrowed slice with the given chunk size.
    ///
    /// Returns `None` if `chunk_size` is zero.
    pub fn new(data: &'a [u8], chunk_size: usize) -> Option<Self> {
        if chunk_size == 0 {
            return None;
        }
        Some(Self { data, chunk_size })
    }

    /// The chunk size used for each read.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }
}

impl<'a> ByteSource for ChunkedSource<'a> {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<usize, IoError> {
        if out.is_empty() {
            return Ok(0);
        }
        let start = usize::try_from(offset).map_err(|_| IoError::SeekError)?;
        if start >= self.data.len() {
            return Ok(0);
        }
        let available = &self.data[start..];
        let n = available.len().min(out.len()).min(self.chunk_size);
        out[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }
}

/// A [`ByteSource`] that always returns zero bytes (EOF on every read).
///
/// Used to test the fail-closed behavior of `read_exact_at` on truncated or
/// empty sources.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptySource;

impl ByteSource for EmptySource {
    fn len(&self) -> u64 {
        0
    }

    fn read_at(&self, _offset: u64, out: &mut [u8]) -> Result<usize, IoError> {
        let _ = out;
        Ok(0)
    }
}

/// A validated, read-only view over a [`ByteSource`] bounded by a checked
/// [`ByteRange`]. All integer reads first validate bounds; parsers must not
/// use slice panics to signal parse errors.
#[derive(Debug, Clone)]
pub struct ByteView<'a> {
    source: &'a dyn ByteSource,
    range: ByteRange,
}

impl<'a> ByteView<'a> {
    /// Construct a view, returning `None` if the range exceeds the source
    /// length or overflows.
    pub fn new(source: &'a dyn ByteSource, range: ByteRange) -> Option<Self> {
        let end = range.end()?;
        if end > source.len() {
            return None;
        }
        Some(Self { source, range })
    }

    /// The source-relative range covered by this view.
    pub fn range(&self) -> ByteRange {
        self.range
    }

    /// The length of this view in bytes.
    pub fn len(&self) -> u64 {
        self.range.length
    }

    /// `true` if the view covers zero bytes.
    pub fn is_empty(&self) -> bool {
        self.range.length == 0
    }

    /// Create a sub-view at `offset` of `length` bytes, checked against this
    /// view's bounds.
    pub fn subview(&self, offset: u64, length: u64) -> Option<ByteView<'_>> {
        let abs_start = self.range.start.checked_add(offset)?;
        let range = ByteRange::new(abs_start, length)?;
        ByteView::new(self.source, range)
    }

    /// Read `out` bytes starting at the view-relative `offset`.
    pub fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<usize, IoError> {
        let abs = self
            .range
            .start
            .checked_add(offset)
            .ok_or(IoError::SeekError)?;
        // Clamp to view bounds: never read past the view's end.
        let view_end = self.range.end().ok_or(IoError::SeekError)?;
        let max_read = view_end.saturating_sub(abs);
        if max_read == 0 {
            return Ok(0);
        }
        let out_len = out.len().min(usize::try_from(max_read).unwrap_or(0));
        if out_len == 0 {
            return Ok(0);
        }
        self.source.read_at(abs, &mut out[..out_len])
    }

    /// Read exactly `out.len()` bytes at the view-relative `offset`, or fail
    /// with [`IoError::ShortRead`] if the view ends early.
    ///
    /// This never reads past the view's `[start, end)` boundary.
    pub fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<(), IoError> {
        if out.is_empty() {
            return Ok(());
        }
        let abs = self
            .range
            .start
            .checked_add(offset)
            .ok_or(IoError::SeekError)?;
        let view_end = self.range.end().ok_or(IoError::SeekError)?;
        let available = view_end.saturating_sub(abs);
        let needed = out.len() as u64;
        if available < needed {
            return Err(IoError::ShortRead {
                offset: abs,
                expected: out.len(),
                actual: usize::try_from(available).unwrap_or(0),
            });
        }
        // Delegate to the source's read_exact_at, which loops on partial reads.
        self.source.read_exact_at(abs, out)
    }

    /// Read a little-endian `u16` at the view-relative `offset`.
    pub fn read_u16_le(&self, offset: u64) -> Result<u16, IoError> {
        let mut buf = [0u8; 2];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    /// Read a big-endian `u16` at the view-relative `offset`.
    pub fn read_u16_be(&self, offset: u64) -> Result<u16, IoError> {
        let mut buf = [0u8; 2];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    /// Read a little-endian `u32` at the view-relative `offset`.
    pub fn read_u32_le(&self, offset: u64) -> Result<u32, IoError> {
        let mut buf = [0u8; 4];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Read a big-endian `u32` at the view-relative `offset`.
    pub fn read_u32_be(&self, offset: u64) -> Result<u32, IoError> {
        let mut buf = [0u8; 4];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    /// Read a little-endian `u64` at the view-relative `offset`.
    pub fn read_u64_le(&self, offset: u64) -> Result<u64, IoError> {
        let mut buf = [0u8; 8];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Read a big-endian `u64` at the view-relative `offset`.
    pub fn read_u64_be(&self, offset: u64) -> Result<u64, IoError> {
        let mut buf = [0u8; 8];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }

    /// Read a single byte at the view-relative `offset`.
    pub fn read_u8(&self, offset: u64) -> Result<u8, IoError> {
        let mut buf = [0u8; 1];
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf[0])
    }
}

/// Display and provenance identity for a scan input. Identity is for display
/// and traceability only and must not participate in format identification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputIdentity {
    /// Optional human-readable name shown in output.
    pub display_name: Option<String>,
    /// Optional logical path used for rule extension checks and provenance.
    pub logical_path: Option<String>,
}

/// Input source variants accepted by the scan service. Path entry points open
/// the file and read metadata before converting to a checked source; the core
/// API uses platform-native paths and UTF-8 limitations belong only to FFI.
#[derive(Debug)]
pub enum ScanSource<'a> {
    /// In-memory bytes with an explicit identity.
    Bytes {
        /// The byte buffer.
        data: &'a [u8],
        /// Display/provenance identity.
        identity: InputIdentity,
    },
    /// A pre-built [`ByteSource`] with an explicit identity.
    ByteSource {
        /// The byte source.
        source: &'a dyn ByteSource,
        /// Display/provenance identity.
        identity: InputIdentity,
    },
    /// A filesystem path opened by the engine adapter.
    Path(&'a Path),
}

impl<'a> ScanSource<'a> {
    /// The identity for non-path sources, or `None` for path sources whose
    /// identity is derived after opening.
    pub fn identity(&self) -> Option<&InputIdentity> {
        match self {
            ScanSource::Bytes { identity, .. } | ScanSource::ByteSource { identity, .. } => {
                Some(identity)
            }
            ScanSource::Path(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ByteRange ---

    #[test]
    fn byte_range_basic() {
        let r = ByteRange::new(10, 20).unwrap();
        assert_eq!(r.start, 10);
        assert_eq!(r.length, 20);
        assert_eq!(r.end(), Some(30));
    }

    #[test]
    fn byte_range_overflow() {
        assert!(ByteRange::new(u64::MAX, 1).is_none());
    }

    #[test]
    fn byte_range_zero_length_at_max() {
        let r = ByteRange::new(u64::MAX, 0).unwrap();
        assert_eq!(r.end(), Some(u64::MAX));
    }

    // --- MemorySource ---

    #[test]
    fn memory_source_read_full() {
        let data = [0u8, 1, 2, 3, 4, 5];
        let src = MemorySource::new(&data);
        let mut out = [0u8; 6];
        let n = src.read_at(0, &mut out).unwrap();
        assert_eq!(n, 6);
        assert_eq!(out, data);
    }

    #[test]
    fn memory_source_read_partial() {
        let data = [0u8, 1, 2, 3, 4, 5];
        let src = MemorySource::new(&data);
        let mut out = [0u8; 10];
        let n = src.read_at(2, &mut out).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&out[..4], &[2, 3, 4, 5]);
    }

    #[test]
    fn memory_source_read_at_eof() {
        let data = [0u8, 1, 2];
        let src = MemorySource::new(&data);
        let mut out = [0u8; 4];
        let n = src.read_at(3, &mut out).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn memory_source_read_empty_out() {
        let data = [0u8, 1, 2];
        let src = MemorySource::new(&data);
        let n = src.read_at(0, &mut []).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn memory_source_read_exact_full() {
        let data = [0u8, 1, 2, 3, 4, 5];
        let src = MemorySource::new(&data);
        let mut out = [0u8; 6];
        src.read_exact_at(0, &mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn memory_source_read_exact_short_read() {
        let data = [0u8, 1, 2];
        let src = MemorySource::new(&data);
        let mut out = [0u8; 6];
        let err = src.read_exact_at(0, &mut out).unwrap_err();
        assert_eq!(
            err,
            IoError::ShortRead {
                offset: 0,
                expected: 6,
                actual: 0
            }
        );
    }

    #[test]
    fn memory_source_read_exact_offset_overflow() {
        let data = [0u8, 1, 2];
        let src = MemorySource::new(&data);
        let mut out = [0u8; 1];
        let err = src.read_exact_at(u64::MAX, &mut out).unwrap_err();
        assert_eq!(err, IoError::SeekError);
    }

    // --- ChunkedSource ---

    #[test]
    fn chunked_source_read_exact_loops() {
        let data: Vec<u8> = (0..35).collect();
        let src = ChunkedSource::new(&data, 3).unwrap();
        let mut out = [0u8; 35];
        src.read_exact_at(0, &mut out).unwrap();
        assert_eq!(out.to_vec(), data);
    }

    #[test]
    fn chunked_source_read_exact_short_read() {
        let data = [0u8, 1, 2];
        let src = ChunkedSource::new(&data, 2).unwrap();
        let mut out = [0u8; 10];
        let err = src.read_exact_at(0, &mut out).unwrap_err();
        assert!(matches!(err, IoError::ShortRead { .. }));
    }

    #[test]
    fn chunked_source_zero_chunk_rejected() {
        assert!(ChunkedSource::new(&[0u8; 4], 0).is_none());
    }

    // --- EmptySource ---

    #[test]
    fn empty_source_read_exact_fails() {
        let src = EmptySource;
        let mut out = [0u8; 1];
        let err = src.read_exact_at(0, &mut out).unwrap_err();
        assert!(matches!(err, IoError::ShortRead { .. }));
    }

    #[test]
    fn empty_source_len_is_zero() {
        let src = EmptySource;
        assert_eq!(src.len(), 0);
        assert!(src.is_empty());
    }

    // --- OwnedSource ---

    #[test]
    fn owned_source_read_exact() {
        let data: std::sync::Arc<[u8]> = (0..10).collect();
        let src = OwnedSource::new(data);
        let mut out = [0u8; 10];
        src.read_exact_at(0, &mut out).unwrap();
        assert_eq!(&out, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn owned_source_clone_shares_data() {
        let data: std::sync::Arc<[u8]> = (0..4).collect();
        let src1 = OwnedSource::new(data);
        let src2 = src1.clone();
        assert_eq!(src1.len(), src2.len());
        let mut out = [0u8; 4];
        src2.read_exact_at(0, &mut out).unwrap();
        assert_eq!(&out, &[0, 1, 2, 3]);
    }

    // --- ByteView ---

    #[test]
    fn byte_view_basic() {
        let data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let src = MemorySource::new(&data);
        let range = ByteRange::new(2, 5).unwrap();
        let view = ByteView::new(&src, range).unwrap();
        assert_eq!(view.len(), 5);
        assert!(!view.is_empty());
        assert_eq!(view.range().start, 2);
    }

    #[test]
    fn byte_view_exceeds_source() {
        let data = [0u8; 4];
        let src = MemorySource::new(&data);
        let range = ByteRange::new(0, 10).unwrap();
        assert!(ByteView::new(&src, range).is_none());
    }

    #[test]
    fn byte_view_subview() {
        let data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let src = MemorySource::new(&data);
        let range = ByteRange::new(0, 10).unwrap();
        let view = ByteView::new(&src, range).unwrap();
        let sub = view.subview(3, 4).unwrap();
        assert_eq!(sub.len(), 4);
        let mut out = [0u8; 4];
        sub.read_exact_at(0, &mut out).unwrap();
        assert_eq!(out, [3, 4, 5, 6]);
    }

    #[test]
    fn byte_view_subview_out_of_bounds() {
        let data = [0u8; 10];
        let src = MemorySource::new(&data);
        let range = ByteRange::new(0, 10).unwrap();
        let view = ByteView::new(&src, range).unwrap();
        assert!(view.subview(8, 5).is_none());
    }

    #[test]
    fn byte_view_read_does_not_exceed_view_bounds() {
        let data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let src = MemorySource::new(&data);
        let range = ByteRange::new(2, 3).unwrap(); // view covers [2, 5)
        let view = ByteView::new(&src, range).unwrap();
        let mut out = [0u8; 10];
        let n = view.read_at(0, &mut out).unwrap();
        assert_eq!(n, 3); // only 3 bytes available in view, not 8
        assert_eq!(&out[..3], &[2, 3, 4]);
    }

    #[test]
    fn byte_view_read_exact_at_view_boundary() {
        let data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let src = MemorySource::new(&data);
        let range = ByteRange::new(2, 5).unwrap(); // view covers [2, 7)
        let view = ByteView::new(&src, range).unwrap();
        // Read at the exact last byte of the view.
        let val = view.read_u8(4).unwrap();
        assert_eq!(val, 6);
    }

    #[test]
    fn byte_view_read_exact_past_view_fails() {
        let data = [0u8; 10];
        let src = MemorySource::new(&data);
        let range = ByteRange::new(2, 3).unwrap(); // view covers [2, 5)
        let view = ByteView::new(&src, range).unwrap();
        let mut out = [0u8; 2];
        let err = view.read_exact_at(4, &mut out).unwrap_err();
        assert!(matches!(err, IoError::ShortRead { .. }));
    }

    // --- Typed integer reads ---

    #[test]
    fn byte_view_read_u16_le() {
        let data = [0x78, 0x56, 0x34, 0x12];
        let src = MemorySource::new(&data);
        let view = ByteView::new(&src, ByteRange::new(0, 4).unwrap()).unwrap();
        assert_eq!(view.read_u16_le(0).unwrap(), 0x5678);
        assert_eq!(view.read_u16_le(2).unwrap(), 0x1234);
    }

    #[test]
    fn byte_view_read_u16_be() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let src = MemorySource::new(&data);
        let view = ByteView::new(&src, ByteRange::new(0, 4).unwrap()).unwrap();
        assert_eq!(view.read_u16_be(0).unwrap(), 0x1234);
        assert_eq!(view.read_u16_be(2).unwrap(), 0x5678);
    }

    #[test]
    fn byte_view_read_u32_le() {
        let data = [0x78, 0x56, 0x34, 0x12];
        let src = MemorySource::new(&data);
        let view = ByteView::new(&src, ByteRange::new(0, 4).unwrap()).unwrap();
        assert_eq!(view.read_u32_le(0).unwrap(), 0x12345678);
    }

    #[test]
    fn byte_view_read_u32_be() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let src = MemorySource::new(&data);
        let view = ByteView::new(&src, ByteRange::new(0, 4).unwrap()).unwrap();
        assert_eq!(view.read_u32_be(0).unwrap(), 0x12345678);
    }

    #[test]
    fn byte_view_read_u64_le() {
        let data = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        let src = MemorySource::new(&data);
        let view = ByteView::new(&src, ByteRange::new(0, 8).unwrap()).unwrap();
        assert_eq!(view.read_u64_le(0).unwrap(), 0x1122334455667788);
    }

    #[test]
    fn byte_view_read_u64_be() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let src = MemorySource::new(&data);
        let view = ByteView::new(&src, ByteRange::new(0, 8).unwrap()).unwrap();
        assert_eq!(view.read_u64_be(0).unwrap(), 0x1122334455667788);
    }

    #[test]
    fn byte_view_read_u8() {
        let data = [0x42, 0x00];
        let src = MemorySource::new(&data);
        let view = ByteView::new(&src, ByteRange::new(0, 2).unwrap()).unwrap();
        assert_eq!(view.read_u8(0).unwrap(), 0x42);
    }

    #[test]
    fn byte_view_typed_read_past_end_fails() {
        let data = [0u8; 2];
        let src = MemorySource::new(&data);
        let view = ByteView::new(&src, ByteRange::new(0, 2).unwrap()).unwrap();
        assert!(matches!(
            view.read_u32_le(0).unwrap_err(),
            IoError::ShortRead { .. }
        ));
    }

    // --- IoError display ---

    #[test]
    fn io_error_display() {
        assert_eq!(IoError::NotFound.to_string(), "input not found");
        assert_eq!(IoError::PermissionDenied.to_string(), "permission denied");
        assert_eq!(IoError::SeekError.to_string(), "seek out of range");
        assert_eq!(IoError::NotSeekable.to_string(), "source is not seekable");
        let short = IoError::ShortRead {
            offset: 10,
            expected: 4,
            actual: 2,
        };
        assert_eq!(
            short.to_string(),
            "short read at offset 10: expected 4 bytes, got 2"
        );
    }

    // --- FileSource ---

    #[test]
    fn file_source_open_not_found() {
        let err = FileSource::open(Path::new("nonexistent_file_12345678.bin")).unwrap_err();
        assert_eq!(err, IoError::NotFound);
    }

    #[test]
    fn file_source_read_exact() {
        let dir = std::env::temp_dir();
        let path = dir.join("diec_test_file_source.bin");
        std::fs::write(&path, [0x01, 0x02, 0x03, 0x04]).unwrap();
        let src = FileSource::open(&path).unwrap();
        assert_eq!(src.len(), 4);
        let mut out = [0u8; 4];
        src.read_exact_at(0, &mut out).unwrap();
        assert_eq!(out, [0x01, 0x02, 0x03, 0x04]);
        let _ = std::fs::remove_file(&path);
    }

    // --- Property-based tests (deterministic, no external dependency) ---
    // These tests use a simple xorshift PRNG to generate random offsets,
    // lengths and buffer sizes, verifying that ByteSource and ByteView
    // never panic, never read out of bounds, and always return typed errors
    // for short reads. See testing.md section 14: "fuzz invariant: no panic,
    // no out-of-bounds, deterministic, typed errors".

    /// Simple xorshift64 PRNG for deterministic property tests.
    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Generate a random u64 in [0, max).
    fn rand_u64(state: &mut u64, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        xorshift64(state) % max
    }

    #[test]
    fn property_memory_source_read_never_panics() {
        let data: Vec<u8> = (0..=255u8).collect();
        let src = MemorySource::new(&data);
        let mut state: u64 = 0x1234567890ABCDEF;
        for _ in 0..1000 {
            let offset = rand_u64(&mut state, 300);
            let len = rand_u64(&mut state, 64) as usize;
            let mut out = vec![0u8; len];
            let _ = src.read_at(offset, &mut out);
        }
    }

    #[test]
    fn property_read_exact_at_never_panics() {
        let data: Vec<u8> = (0..=199u8).collect();
        let src = MemorySource::new(&data);
        let mut state: u64 = 0xDEADBEEFCAFEBABE;
        for _ in 0..1000 {
            let offset = rand_u64(&mut state, 300);
            let len = rand_u64(&mut state, 64) as usize;
            let mut out = vec![0u8; len];
            let result = src.read_exact_at(offset, &mut out);
            // If Ok, the bytes must be within the source.
            if let Ok(()) = result
                && len > 0
            {
                let end = offset.checked_add(len as u64).unwrap();
                assert!(
                    end <= src.len(),
                    "read_exact_at succeeded past source end: end={end}, src.len()={}",
                    src.len()
                );
            }
        }
    }

    #[test]
    fn property_byte_view_subview_never_panics() {
        let data: Vec<u8> = (0..=127u8).collect();
        let src = MemorySource::new(&data);
        let range = ByteRange::new(0, 128).unwrap();
        let view = ByteView::new(&src, range).unwrap();
        let mut state: u64 = 0x4242424242424242;
        for _ in 0..1000 {
            let offset = rand_u64(&mut state, 200);
            let length = rand_u64(&mut state, 200);
            let _ = view.subview(offset, length);
        }
    }

    #[test]
    fn property_byte_view_read_never_exceeds_bounds() {
        let data: Vec<u8> = (0..=99u8).collect();
        let src = MemorySource::new(&data);
        // View covers [10, 50) = 40 bytes.
        let range = ByteRange::new(10, 40).unwrap();
        let view = ByteView::new(&src, range).unwrap();
        let mut state: u64 = 0x5555555555555555;
        for _ in 0..1000 {
            let offset = rand_u64(&mut state, 200);
            let len = rand_u64(&mut state, 64) as usize;
            let mut out = vec![0u8; len];
            if let Ok(n) = view.read_at(offset, &mut out) {
                // read_at must never return more bytes than the view has.
                let view_remaining = 40_u64.saturating_sub(offset);
                assert!(
                    n as u64 <= view_remaining,
                    "read_at returned {n} bytes but only {view_remaining} available in view"
                );
            }
        }
    }

    #[test]
    fn property_chunked_source_read_exact_consistent() {
        let data: Vec<u8> = (0..=63u8).collect();
        let mut state: u64 = 0x9999999999999999;
        for chunk_size in [1, 2, 3, 5, 7, 16, 64] {
            let src = ChunkedSource::new(&data, chunk_size).unwrap();
            for _ in 0..100 {
                let offset = rand_u64(&mut state, 64) as usize;
                let max_len = 64 - offset;
                let len = if max_len == 0 {
                    0
                } else {
                    rand_u64(&mut state, max_len as u64) as usize + 1
                };
                let mut out = vec![0u8; len];
                let result = src.read_exact_at(offset as u64, &mut out);
                if let Ok(()) = result {
                    assert_eq!(&out, &data[offset..offset + len]);
                }
            }
        }
    }

    #[test]
    fn property_typed_integer_reads_never_panics() {
        let data: Vec<u8> = (0..=31u8).collect();
        let src = MemorySource::new(&data);
        let range = ByteRange::new(0, 32).unwrap();
        let view = ByteView::new(&src, range).unwrap();
        let mut state: u64 = 0xAAAAAAAAAAAAAAAA;
        for _ in 0..1000 {
            let offset = rand_u64(&mut state, 64);
            let _ = view.read_u8(offset);
            let _ = view.read_u16_le(offset);
            let _ = view.read_u16_be(offset);
            let _ = view.read_u32_le(offset);
            let _ = view.read_u32_be(offset);
            let _ = view.read_u64_le(offset);
            let _ = view.read_u64_be(offset);
        }
    }

    #[test]
    fn property_empty_source_never_panics() {
        let src = EmptySource;
        let mut state: u64 = 0x7777777777777777;
        for _ in 0..1000 {
            let offset = rand_u64(&mut state, 1000);
            let len = rand_u64(&mut state, 64) as usize;
            let mut out = vec![0u8; len];
            let _ = src.read_at(offset, &mut out);
            let _ = src.read_exact_at(offset, &mut out);
        }
    }
}

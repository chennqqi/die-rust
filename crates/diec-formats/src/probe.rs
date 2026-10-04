//! Format probe framework: trait, error, context and candidate table.
//!
//! Format probing is driven by an explicit, versioned ordered probe table.
//! Each probe accesses bytes only through `diec-core`'s checked input and
//! reports whether it matches, how strongly, and whether expensive parsing
//! is deferred. Probes never write final detections or read the rule
//! database. See `docs/design/architecture.md` section 8.

use diec_core::format::{FileType, FormatCandidate, FormatStrength};
use diec_core::input::{ByteView, IoError};

/// Schema version of the format probe table.
///
/// Bumped when the probe order, membership or strength semantics change.
/// Differential tests bind to this version.
pub const PROBE_TABLE_VERSION: u32 = 1;

/// A typed error from a format probe.
///
/// Probes must distinguish "no match" (returned as `Ok(None)`) from actual
/// errors such as truncated headers or I/O failures. A probe error does not
/// necessarily abort the whole scan: the engine may record it as a
/// node-local diagnostic and continue with the next candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// The source ended before the probe could read its minimum header.
    Truncated {
        /// The file type the probe was testing.
        file_type: FileType,
        /// The underlying I/O error.
        cause: IoError,
    },
    /// A checked read returned an I/O error other than short read.
    Io(IoError),
    /// The probe read the magic but the header fields are inconsistent.
    InvalidHeader {
        /// The file type the probe was testing.
        file_type: FileType,
        /// Human-readable detail of the inconsistency.
        detail: String,
    },
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::Truncated { file_type, cause } => {
                write!(f, "truncated header for {}: {cause}", file_type.name)
            }
            ProbeError::Io(e) => write!(f, "probe io error: {e}"),
            ProbeError::InvalidHeader { file_type, detail } => {
                write!(f, "invalid {} header: {detail}", file_type.name)
            }
        }
    }
}

impl std::error::Error for ProbeError {}

/// The outcome of a single format probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// The candidate this probe produced, if any.
    pub candidate: FormatCandidate,
}

/// A format probe: a stateless function that inspects a byte view and reports
/// whether the source matches a specific format.
///
/// Probes are ordered in a [`ProbeTable`] and invoked sequentially. A probe
/// returns:
/// - `Ok(Some(outcome))` when the format matches;
/// - `Ok(None)` when the format does not match (not an error);
/// - `Err(ProbeError)` when the probe could not complete due to I/O or
///   header inconsistency.
///
/// Probes must not allocate large buffers or perform expensive parsing; they
/// read only the minimum bytes needed to identify the format and report
/// whether full parsing is deferred.
pub trait FormatProbe: std::fmt::Debug + Send + Sync {
    /// The file type this probe identifies.
    fn file_type(&self) -> FileType;

    /// Probe the given byte view.
    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError>;
}

/// A versioned, ordered table of format probes.
///
/// The table is the single source of truth for probe order. The engine
/// iterates probes in order and collects candidates. Order matters because
/// upstream dispatch checks PE before ELF before Mach-O, and a weak magic
/// match may be superseded by a later strong match.
#[derive(Debug)]
pub struct ProbeTable {
    /// Schema version.
    pub version: u32,
    probes: Vec<Box<dyn FormatProbe>>,
}

impl ProbeTable {
    /// Create a new empty table with the given schema version.
    pub fn new(version: u32) -> Self {
        Self {
            version,
            probes: Vec::new(),
        }
    }

    /// Add a probe to the end of the table.
    pub fn push(&mut self, probe: Box<dyn FormatProbe>) {
        self.probes.push(probe);
    }

    /// The number of probes in the table.
    pub fn len(&self) -> usize {
        self.probes.len()
    }

    /// `true` if the table has no probes.
    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    /// Run all probes against the given view and return candidates in order.
    ///
    /// Probe errors are collected separately; a probe error does not stop the
    /// remaining probes. The engine decides whether to record errors as
    /// node-local diagnostics.
    pub fn probe_all(&self, view: &ByteView<'_>) -> (Vec<FormatCandidate>, Vec<ProbeError>) {
        let mut candidates = Vec::new();
        let mut errors = Vec::new();
        for probe in &self.probes {
            match probe.probe(view) {
                Ok(Some(outcome)) => candidates.push(outcome.candidate),
                Ok(None) => {}
                Err(e) => errors.push(e),
            }
        }
        (candidates, errors)
    }

    /// Build the default probe table for the current version.
    ///
    /// The default table follows the upstream dispatch order from
    /// `capability-matrix.md` CAP-DISPATCH-001 through CAP-DISPATCH-008:
    /// PE/MSDOS, ELF, Mach-O, Archive, DEX/Class/PYC, PDF/CFBF, Image.
    pub fn default_phase2() -> Self {
        let mut table = Self::new(PROBE_TABLE_VERSION);
        // Order mirrors XScanEngine::scanProcess dispatch.
        // CAP-DISPATCH-001: PE/MSDOS, ELF, Mach-O
        table.push(Box::new(super::msdos::MsdosProbe));
        table.push(Box::new(super::pe::PeProbe));
        // MZ subtypes promoted via the signature at e_lfanew, mirroring
        // XFormats::getFileTypes (PE -> NE -> LE/LX ordering).
        table.push(Box::new(super::ne_lx::NeProbe));
        table.push(Box::new(super::ne_lx::LeLxProbe));
        table.push(Box::new(super::elf::ElfProbe));
        table.push(Box::new(super::macho::MachOProbe));
        // CAP-DISPATCH-004: Archive (ZIP, RAR, 7Z, GZIP, TAR, ISO9660, CAB)
        table.push(Box::new(super::archive::ZipProbe));
        table.push(Box::new(super::archive::RarProbe));
        table.push(Box::new(super::archive::SevenZProbe));
        table.push(Box::new(super::archive::GzipProbe));
        table.push(Box::new(super::archive::TarProbe));
        table.push(Box::new(super::archive::Iso9660Probe));
        table.push(Box::new(super::archive::CabProbe));
        // CAP-DISPATCH-005: DEX, Java Class, PYC
        table.push(Box::new(super::dex_class_pyc::DexProbe));
        table.push(Box::new(super::dex_class_pyc::JavaClassProbe));
        table.push(Box::new(super::dex_class_pyc::PycProbe));
        // CAP-DISPATCH-006: PDF, CFBF
        table.push(Box::new(super::pdf_cfbf::PdfProbe));
        table.push(Box::new(super::pdf_cfbf::CfbfProbe));
        // CAP-DISPATCH-007: JPEG, PNG, BMP, WAV
        table.push(Box::new(super::image::JpegProbe));
        table.push(Box::new(super::image::PngProbe));
        table.push(Box::new(super::image_extra::BmpProbe));
        table.push(Box::new(super::image_extra::WavProbe));
        table
    }
}

/// Helper to build a strong candidate with deferred parsing.
pub(crate) fn strong_deferred(file_type: impl Into<String>) -> FormatCandidate {
    FormatCandidate {
        file_type: FileType::new(file_type),
        strength: FormatStrength::Strong,
        deferred_parse: true,
    }
}

/// Helper to build a weak candidate.
pub(crate) fn weak(file_type: impl Into<String>) -> FormatCandidate {
    FormatCandidate {
        file_type: FileType::new(file_type),
        strength: FormatStrength::Weak,
        deferred_parse: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diec_core::input::{ByteRange, ByteSource, ByteView, MemorySource};

    fn view_of<'a>(src: &'a MemorySource<'a>) -> ByteView<'a> {
        ByteView::new(src, ByteRange::new(0, src.len()).unwrap()).unwrap()
    }

    #[test]
    fn empty_table_probes_nothing() {
        let table = ProbeTable::new(1);
        let src = MemorySource::new(&[0u8; 16]);
        let view = view_of(&src);
        let (cands, errs) = table.probe_all(&view);
        assert!(cands.is_empty());
        assert!(errs.is_empty());
    }

    #[test]
    fn default_phase2_table_has_all_probes() {
        let table = ProbeTable::default_phase2();
        // 6 (PE/MSDOS/NE/LE-LX/ELF/Mach-O) + 7 (Archive) + 3 (DEX/Class/PYC)
        // + 2 (PDF/CFBF) + 4 (Image: JPEG/PNG/BMP/WAV) = 22
        assert_eq!(table.len(), 22);
        assert_eq!(table.version, PROBE_TABLE_VERSION);
    }

    #[test]
    fn probe_error_display() {
        let e = ProbeError::Truncated {
            file_type: FileType::new("PE32"),
            cause: IoError::ShortRead {
                offset: 0,
                expected: 64,
                actual: 0,
            },
        };
        assert!(e.to_string().contains("PE32"));
        let e2 = ProbeError::InvalidHeader {
            file_type: FileType::new("ELF64"),
            detail: "bad class".into(),
        };
        assert!(e2.to_string().contains("ELF64"));
    }
}

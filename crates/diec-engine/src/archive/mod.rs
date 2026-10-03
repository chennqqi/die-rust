//! Secondary archive formats (Phase 32): ARJ, LHA/LZH, ACE, CPIO, UDF, WIM.
//!
//! Upstream `XFormats` can enumerate records for these formats, but the
//! `scanProcess` member-unpack gate only covers ZIP/7Z/RAR/CAB/ISO9660 —
//! these formats are therefore wired into the explicit list/extract path
//! (`list_archive_members` / `extract_member`) only, never into nested
//! recursive scanning (`archive-gap-closure.md`).

mod ace;
mod ace_decode;
mod arj;
mod arj_decode;
mod cpio;
mod lha;
mod lzh_decode;

/// Secondary format detected by [`list_secondary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondaryKind {
    /// ARJ archive (`60 EA` entry markers).
    Arj,
    /// LHA/LZH archive (`-lhx-` method tags at header offset 2).
    Lha,
    /// ACE archive (`**ACE**` signature).
    Ace,
    /// CPIO archive (`070701`/`070702`/`070707`/`0x71C7` magics).
    Cpio,
    /// UDF filesystem image (ECMA-167 descriptors at 32 KiB+).
    ///
    /// Gated (Phase 32): upstream `isValid` requires a checksum-verified
    /// Anchor Volume Descriptor chain and no generator/tool exists on this
    /// host to produce a conforming sample, so detection is not wired.
    Udf,
    /// WIM image (`MSWIM` signature).
    ///
    /// Gated (Phase 32): same reason as [`SecondaryKind::Udf`]; a valid
    /// WIM needs a correct lookup table plus XML metadata, which cannot
    /// be synthesized cheaply enough to satisfy the oracle gate.
    Wim,
}

impl SecondaryKind {
    /// Uppercase display name (upstream archive widget style).
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Arj => "ARJ",
            Self::Lha => "LHA",
            Self::Ace => "ACE",
            Self::Cpio => "CPIO",
            Self::Udf => "UDF",
            Self::Wim => "WIM",
        }
    }
}

/// One enumerated member with enough geometry for lazy extraction.
#[derive(Debug, Clone)]
pub struct SecondaryRecord {
    /// Member path (backslashes normalized to `/` per upstream).
    pub name: String,
    /// Unpacked size in bytes.
    pub size: u64,
    /// Packed/compressed size in bytes.
    pub packed_size: u64,
    /// Whether the member is a directory entry.
    pub is_directory: bool,
    /// Last-modified time as `YYYY-MM-DD HH:MM:SS` when the format carries one.
    pub modified: Option<String>,
    /// Absolute file offset of the packed stream (for `extract_secondary`).
    pub(crate) data_offset: u64,
    /// Compression method identifier (format-specific).
    pub(crate) method: u32,
    /// Decoder window size in bytes (format-specific; 0 when the format
    /// carries none). ACE: `1 << ((tech_parameter & 15) + 10)`.
    pub(crate) window_size: u64,
}

/// Enumerate members of a supported secondary archive format.
///
/// Returns `None` when no format signature matches or the record chain is
/// malformed. All offsets and sizes are validated against `data.len()`;
/// enumeration stops at the first broken entry (upstream stops the same way).
pub fn list_secondary(data: &[u8]) -> Option<(SecondaryKind, Vec<SecondaryRecord>)> {
    if arj::is_arj(data) {
        return arj::list(data).map(|m| (SecondaryKind::Arj, m));
    }
    if lha::is_lha(data) {
        return lha::list(data).map(|m| (SecondaryKind::Lha, m));
    }
    if cpio::is_cpio(data) {
        return cpio::list(data).map(|m| (SecondaryKind::Cpio, m));
    }
    if ace::is_ace(data) {
        return ace::list(data).map(|m| (SecondaryKind::Ace, m));
    }
    None
}

/// Extract one record's bytes by index into the enumeration order.
///
/// `stored`-style methods return the raw stream slice; compressed members
/// return an empty vector until the corresponding decoder is ported
/// (mirrors upstream, which reports the stream but cannot decode without
/// the optional algorithm modules).
pub fn extract_secondary(data: &[u8], kind: SecondaryKind, name: &str) -> Vec<u8> {
    let (_, records) = match list_secondary(data) {
        Some((k, r)) if k == kind => (k, r),
        _ => return Vec::new(),
    };
    let rec = match records.iter().find(|r| r.name == name) {
        Some(r) => r,
        None => return Vec::new(),
    };
    let off = rec.data_offset as usize;
    let end = match off.checked_add(rec.packed_size as usize) {
        Some(e) if e <= data.len() => e,
        _ => return Vec::new(),
    };
    if rec.is_directory {
        return Vec::new();
    }
    // Only stored/no-compression members extract byte-identically for now.
    let stored = match kind {
        // ARJ methods 5/6 are "no compression" variants alongside 0;
        // only those extract byte-identically without a decoder.
        SecondaryKind::Arj => matches!(rec.method, 0 | 5 | 6),
        // Upstream maps `-lh0-`/`-lz4-`/`-lhd-`/`-pm0-` to STORE;
        // `-lhd-` members are directories and return earlier anyway.
        SecondaryKind::Lha => matches!(
            rec.method.to_be_bytes(),
            [b'-', b'l', b'h', b'0'] | [b'-', b'l', b'z', b'4'] | [b'-', b'p', b'm', b'0']
        ),
        SecondaryKind::Cpio => true, // CPIO is an uncompressed container.
        // `method` carries the upstream HANDLE_METHOD value; 1 == STORE.
        SecondaryKind::Ace => rec.method == 1,
        _ => false,
    };
    if stored {
        return data[off..end].to_vec();
    }
    // Compressed members: decode when the ported decoder covers the
    // method; anything else yields empty (fail-closed, like upstream).
    if kind == SecondaryKind::Arj {
        let packed = &data[off..end];
        return match rec.method {
            // HANDLE_METHOD_ARJ (1-3) / ARJ_FASTEST (4) map to the raw
            // ARJ method byte stored in the header. `method` currently
            // carries the raw ARJ method for this format.
            1..=3 => {
                arj_decode::decompress_arj(packed, rec.size as usize, false).unwrap_or_default()
            }
            4 => arj_decode::decompress_arj(packed, rec.size as usize, true).unwrap_or_default(),
            _ => Vec::new(),
        };
    }
    if kind == SecondaryKind::Ace {
        let packed = &data[off..end];
        // HANDLE_METHOD_ACE (61) == tech type 1 (LZ+Huffman). The
        // decoder window comes from `TECH.PARM`'s low nibble.
        if rec.method == 61 {
            return ace_decode::decompress_ace(packed, rec.size as usize, rec.window_size)
                .unwrap_or_default();
        }
    }
    if kind == SecondaryKind::Lha {
        // `method` carries the first 4 tag bytes; `-lhN-` decodes via
        // the lh4-7 state machine (N selects the window size).
        let tag = rec.method.to_be_bytes();
        let packed = &data[off..end];
        if tag[..3] == *b"-lh" && (b'4'..=b'7').contains(&tag[3]) {
            return lzh_decode::decompress_lzh(packed, rec.size as usize, i32::from(tag[3] - b'0'))
                .unwrap_or_default();
        }
    }
    Vec::new()
}

//! Record layouts mirroring SpecAbstract's NFD_Binary record structs.
//!
//! Indices `rtype`, `name`, `ft` index into the display tables in
//! `gen_names` (`RECORD_TYPE_STR`, `RECORD_NAME_STR`, `FT_STR`).

/// Common per-record metadata (`_BASICINFO` in upstream).
#[derive(Debug, Clone, Copy)]
pub struct BasicRecord {
    /// Record variant number (upstream `nVariant`).
    pub variant: u32,
    /// File type this record applies to (index into `FT_STR`).
    pub ft: u16,
    /// `RECORD_TYPE` index into `RECORD_TYPE_STR`.
    pub rtype: u8,
    /// `RECORD_NAME` index into `RECORD_NAME_STR`.
    pub name: u16,
    /// Static version string from the record.
    pub version: &'static str,
    /// Static info string from the record.
    pub info: &'static str,
}

/// `SIGNATURE_RECORD`: header/section hex-signature match.
#[derive(Debug, Clone, Copy)]
pub struct SignatureRecord {
    /// Shared metadata.
    pub basic: BasicRecord,
    /// XBinary signature string (`hex`, `.`/`?` wildcards, `'ansi'`).
    pub signature: &'static str,
}

/// `STRING_RECORD`: string presence match (custom CRC32C comparison).
#[derive(Debug, Clone, Copy)]
pub struct StringRecord {
    /// Shared metadata.
    pub basic: BasicRecord,
    /// String to look up.
    pub string: &'static str,
}

/// `CONST_RECORD`: two-constant match (import hash / position hash).
#[derive(Debug, Clone, Copy)]
pub struct ConstRecord {
    /// Shared metadata.
    pub basic: BasicRecord,
    /// First constant (e.g. import hash).
    pub const1: u64,
    /// Second constant (e.g. expected value).
    pub const2: u64,
}

/// `PE_RESOURCES_RECORD`: PE resource name/id pair presence match.
#[derive(Debug, Clone, Copy)]
pub struct ResourcesRecord {
    /// Shared metadata.
    pub basic: BasicRecord,
    /// Whether `name1` is a string name (otherwise `id1` is used).
    pub is_string1: bool,
    /// Resource name 1 (type), valid when `is_string1`.
    pub name1: &'static str,
    /// Resource type id, valid when `!is_string1`.
    pub id1: u32,
    /// Whether `name2` is a string name (otherwise `id2` is used).
    pub is_string2: bool,
    /// Resource name 2, valid when `is_string2`.
    pub name2: &'static str,
    /// Resource name/id 2, valid when `!is_string2`.
    pub id2: u32,
}

/// `MSRICH_RECORD`: Rich signature (compid/build) match.
#[derive(Debug, Clone, Copy)]
pub struct MsRichRecord {
    /// Shared metadata.
    pub basic: BasicRecord,
    /// Rich compid.
    pub id: u16,
    /// Rich build number.
    pub build: u32,
}

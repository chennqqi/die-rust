//! Table-driven scan passes ported from `NFD_Binary` (SpecAbstract):
//! `signatureScan`, `stringScan`, `archiveScan`, `constScan`,
//! `PE_resourcesScan` and `msRichScan`.
//!
//! Each pass fills a name-keyed map; the first matching record per
//! `RECORD_NAME` wins (mirroring the `pMapRecords->contains` guard in
//! upstream). `bShowInternalDetects` (internal-detect reporting) is not
//! supported — detections are deduplicated by name.

use std::collections::HashMap;

use crate::records::{
    BasicRecord, ConstRecord, MsRichRecord, ResourcesRecord, SignatureRecord, StringRecord,
};
use crate::signature::{compare_signature_strings, string_custom_crc32};

/// A single detection, equivalent to upstream `SCANS_STRUCT`/`SCAN_STRUCT`.
#[derive(Debug, Clone)]
pub struct ScanRecord {
    /// `RECORD_NAME` index.
    pub name: u16,
    /// `RECORD_TYPE` index.
    pub rtype: u8,
    /// `FT` index of the record that matched.
    pub ft: u16,
    /// Record variant.
    pub variant: u32,
    /// Version string (from record or heuristic fixup).
    pub version: String,
    /// Info string (from record or heuristic fixup).
    pub info: String,
    /// Set by heuristic-only detects (`bIsHeuristic`).
    pub heuristic: bool,
    /// True for the synthetic "Unknown" record.
    pub unknown: bool,
}

impl ScanRecord {
    /// Build a record from a matched table entry.
    pub fn from_basic(b: &BasicRecord) -> Self {
        Self {
            name: b.name,
            rtype: b.rtype,
            ft: b.ft,
            variant: b.variant,
            version: b.version.to_string(),
            info: b.info.to_string(),
            heuristic: false,
            unknown: false,
        }
    }
}

/// Name-keyed detection map (`QMap<RECORD_NAME, SCANS_STRUCT>` upstream).
pub type DetectMap = HashMap<u16, ScanRecord>;

fn ft_matches(rec_ft: u16, ft1: u16, ft2: u16) -> bool {
    rec_ft == ft1 || rec_ft == ft2
}

/// Port of `NFD_Binary::signatureScan`: match a hex signature string
/// against `SignatureRecord` patterns (prefix + `.` wildcards).
pub fn signature_scan(
    map: &mut DetectMap,
    base_signature: &str,
    records: &[SignatureRecord],
    ft1: u16,
    ft2: u16,
) {
    for rec in records {
        if !ft_matches(rec.basic.ft, ft1, ft2) || map.contains_key(&rec.basic.name) {
            continue;
        }
        if compare_signature_strings(base_signature, rec.signature) {
            map.insert(rec.basic.name, ScanRecord::from_basic(&rec.basic));
        }
    }
}

/// Port of `NFD_Binary::stringScan`: custom-CRC32 equality between file
/// strings and record strings.
pub fn string_scan(
    map: &mut DetectMap,
    strings: &[String],
    records: &[StringRecord],
    ft1: u16,
    ft2: u16,
) {
    let string_crcs: Vec<u32> = strings.iter().map(|s| string_custom_crc32(s)).collect();
    for &crc in &string_crcs {
        for rec in records {
            if !ft_matches(rec.basic.ft, ft1, ft2) || map.contains_key(&rec.basic.name) {
                continue;
            }
            if crc == string_custom_crc32(rec.string) {
                map.insert(rec.basic.name, ScanRecord::from_basic(&rec.basic));
            }
        }
    }
}

/// Port of `NFD_Binary::archiveScan`: same CRC32 matching against archive
/// member names.
#[allow(dead_code)] // wired up when the APK/JAR/ZIP modules land.
pub fn archive_scan(
    map: &mut DetectMap,
    member_names: &[String],
    records: &[StringRecord],
    ft1: u16,
    ft2: u16,
) {
    string_scan(map, member_names, records, ft1, ft2);
}

/// Port of `NFD_Binary::archiveExpScan`: regex (`XBinary::isRegExpPresent`,
/// substring match) between member names and record patterns.
pub fn archive_exp_scan(
    map: &mut DetectMap,
    member_names: &[String],
    records: &[StringRecord],
    ft1: u16,
    ft2: u16,
) {
    for name_str in member_names {
        for rec in records {
            if !ft_matches(rec.basic.ft, ft1, ft2) || map.contains_key(&rec.basic.name) {
                continue;
            }
            let Ok(re) = fancy_regex::Regex::new(rec.string) else {
                continue;
            };
            if matches!(re.find(name_str), Ok(Some(_))) {
                map.insert(rec.basic.name, ScanRecord::from_basic(&rec.basic));
            }
        }
    }
}

/// Port of `NFD_Binary::constScan`: match `(const1, const2)` with
/// `0xFFFFFFFF` acting as a per-field wildcard. A wildcard-const1 record
/// may replace an existing entry.
pub fn const_scan(
    map: &mut DetectMap,
    const1: u64,
    const2: u64,
    records: &[ConstRecord],
    ft1: u16,
    ft2: u16,
) {
    for rec in records {
        if !ft_matches(rec.basic.ft, ft1, ft2) {
            continue;
        }
        if map.contains_key(&rec.basic.name) && rec.const1 != 0xFFFF_FFFF {
            continue;
        }
        let ok = (rec.const1 == const1 || rec.const1 == 0xFFFF_FFFF)
            && (rec.const2 == const2 || rec.const2 == 0xFFFF_FFFF);
        if ok && (!map.contains_key(&rec.basic.name) || rec.const1 == 0xFFFF_FFFF) {
            map.insert(rec.basic.name, ScanRecord::from_basic(&rec.basic));
        }
    }
}

/// One flattened PE resource (type + name/id pair) used by
/// `resources_scan`. `name` is the string form when the resource uses a
/// string identifier, otherwise `id` carries the numeric id.
#[derive(Debug, Clone)]
pub struct ResourceEntry {
    /// Level-1 (type) name when string-identified.
    pub name1: Option<String>,
    /// Level-1 numeric id when not string-identified.
    pub id1: u32,
    /// Level-2 (name) string when string-identified.
    pub name2: Option<String>,
    /// Level-2 numeric id when not string-identified.
    pub id2: u32,
    /// Leaf data file offset (first language entry), 0 when unresolved.
    pub data_off: usize,
    /// Leaf data size (`Size` of the level-3 data entry).
    pub data_size: usize,
}

/// Port of `NFD_Binary::PE_resourcesScan` (`XPE::isResourcePresent`
/// two-level name/id matching).
pub fn resources_scan(
    map: &mut DetectMap,
    resources: &[ResourceEntry],
    records: &[ResourcesRecord],
    ft1: u16,
    ft2: u16,
) {
    for rec in records {
        if !ft_matches(rec.basic.ft, ft1, ft2) || map.contains_key(&rec.basic.name) {
            continue;
        }
        let hit = resources.iter().any(|e| {
            let l1 = match (rec.is_string1, &e.name1) {
                (true, Some(n)) => n == rec.name1,
                (true, None) => false,
                (false, _) => e.name1.is_none() && e.id1 == rec.id1,
            };
            let l2 = match (rec.is_string2, &e.name2) {
                (true, Some(n)) => n == rec.name2,
                (true, None) => false,
                (false, _) => e.name2.is_none() && e.id2 == rec.id2,
            };
            l1 && l2
        });
        if hit {
            map.insert(rec.basic.name, ScanRecord::from_basic(&rec.basic));
        }
    }
}

/// Rich-signature record from a PE (compid + build).
#[derive(Debug, Clone, Copy)]
pub struct MsRichEntry {
    /// Compid.
    pub id: u16,
    /// Build number.
    pub build: u32,
}

/// Port of `NFD_MSDOS::MSDOS_richScan` (`g_MS_rich_records`): `id` and
/// `build` each accept an all-ones wildcard; a wildcard build appends
/// `.{build}` to the record version (matching `sVersion += ".%1"`).
pub fn msrich_scan(
    map: &mut DetectMap,
    entries: &[MsRichEntry],
    records: &[MsRichRecord],
    ft1: u16,
    ft2: u16,
) {
    for e in entries {
        for rec in records {
            if !ft_matches(rec.basic.ft, ft1, ft2) || map.contains_key(&rec.basic.name) {
                continue;
            }
            let id_ok = rec.id == e.id || rec.id == 0xFFFF;
            let build_ok = rec.build == e.build || rec.build == 0xFFFF_FFFF;
            if id_ok && build_ok {
                let mut sr = ScanRecord::from_basic(&rec.basic);
                if rec.build == 0xFFFF_FFFF {
                    sr.version = format!("{}.{}", sr.version, e.build);
                }
                map.insert(rec.basic.name, sr);
            }
        }
    }
}

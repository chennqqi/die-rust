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
    /// Display-name override (`SCAN_STRUCT::sName`), e.g. "Plain text".
    /// `Cow` so handler-synthesized names (shebang interpreter) work too.
    pub sname: Option<std::borrow::Cow<'static, str>>,
    /// Display-type override (`SCAN_STRUCT::sType`), e.g. "sfx".
    pub stype: Option<&'static str>,
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
            sname: None,
            stype: None,
        }
    }
}

/// Name-keyed detection map (`QMap<RECORD_NAME, SCANS_STRUCT>` upstream).
/// Used for the *intermediate* collections (`mapHeaderDetects`,
/// `mapEntryPointDetects`, …) which never reach the output directly.
pub type DetectMap = HashMap<u16, ScanRecord>;

/// Category result maps mirroring the `mapResult*` fields of upstream
/// `NFD_Binary::BASIC_INFO`. Records route into the map matching their
/// `rtype` (upstream handlers write `mapResultPackers` etc. directly);
/// `ordered_values` reproduces the fixed `_handleResult` append order.
///
/// The field set deliberately stays private-ish: promotion code that
/// knows the exact upstream destination map writes it directly (e.g.
/// the CFBF→MSI installer record lands in `formats`).
#[derive(Debug, Default)]
pub struct ResultMaps {
    /// `mapResultOperationSystems` (also holds `VIRTUALMACHINE` records).
    pub operation_systems: DetectMap,
    /// `mapResultFormats`.
    pub formats: DetectMap,
    /// `mapResultDosExtenders`.
    pub dosextenders: DetectMap,
    /// `mapResultLinkers`.
    pub linkers: DetectMap,
    /// `mapResultCompilers`.
    pub compilers: DetectMap,
    /// `mapResultLanguages` — filled by `get_language` at drain time.
    pub languages: DetectMap,
    /// `mapResultLibraries`.
    pub libraries: DetectMap,
    /// `mapResultTools`.
    pub tools: DetectMap,
    /// `mapResultPackers`.
    pub packers: DetectMap,
    /// `mapResultSFX`.
    pub sfx: DetectMap,
    /// `mapResultProtectors`.
    pub protectors: DetectMap,
    /// `mapResultAPKProtectors`.
    pub apk_protectors: DetectMap,
    /// `mapResultDongleProtection`.
    pub dongle: DetectMap,
    /// `mapResultSigntools`.
    pub signtools: DetectMap,
    /// `mapResultInstallers`.
    pub installers: DetectMap,
    /// `mapResultJoiners`.
    pub joiners: DetectMap,
    /// `mapResultPETools`.
    pub petools: DetectMap,
    /// `mapResultTexts` (source/script records).
    pub texts: DetectMap,
    /// `mapResultArchives`.
    pub archives: DetectMap,
    /// `mapResultCertificates`.
    pub certificates: DetectMap,
    /// `mapResultDebugData`.
    pub debugdata: DetectMap,
    /// `mapResultInstallerData`.
    pub installerdata: DetectMap,
    /// `mapResultSFXData`.
    pub sfxdata: DetectMap,
    /// `mapResultProtectorData`.
    pub protectordata: DetectMap,
    /// `mapResultLibraryData`.
    pub librarydata: DetectMap,
    /// `mapResultResources`.
    pub resources: DetectMap,
    /// `mapResultDatabases`.
    pub databases: DetectMap,
    /// `mapResultImages`.
    pub images: DetectMap,
    /// Records whose `rtype` has no dedicated upstream result map;
    /// drained last so nothing is silently dropped.
    pub other: DetectMap,
}

impl ResultMaps {
    /// All category maps in upstream `_handleResult` append order.
    fn all(&self) -> [&DetectMap; 29] {
        [
            &self.operation_systems,
            &self.formats,
            &self.dosextenders,
            &self.linkers,
            &self.compilers,
            &self.languages,
            &self.libraries,
            &self.tools,
            &self.packers,
            &self.sfx,
            &self.protectors,
            &self.apk_protectors,
            &self.dongle,
            &self.signtools,
            &self.installers,
            &self.joiners,
            &self.petools,
            &self.texts,
            &self.archives,
            &self.certificates,
            &self.debugdata,
            &self.installerdata,
            &self.sfxdata,
            &self.protectordata,
            &self.librarydata,
            &self.resources,
            &self.databases,
            &self.images,
            &self.other,
        ]
    }

    /// Mutable view of [`Self::all`].
    fn all_mut(&mut self) -> [&mut DetectMap; 29] {
        [
            &mut self.operation_systems,
            &mut self.formats,
            &mut self.dosextenders,
            &mut self.linkers,
            &mut self.compilers,
            &mut self.languages,
            &mut self.libraries,
            &mut self.tools,
            &mut self.packers,
            &mut self.sfx,
            &mut self.protectors,
            &mut self.apk_protectors,
            &mut self.dongle,
            &mut self.signtools,
            &mut self.installers,
            &mut self.joiners,
            &mut self.petools,
            &mut self.texts,
            &mut self.archives,
            &mut self.certificates,
            &mut self.debugdata,
            &mut self.installerdata,
            &mut self.sfxdata,
            &mut self.protectordata,
            &mut self.librarydata,
            &mut self.resources,
            &mut self.databases,
            &mut self.images,
            &mut self.other,
        ]
    }

    /// Destination map for a record of the given `RECORD_TYPE`.
    ///
    /// Mirrors where upstream handlers insert each type; the CRYPTO/OBF
    /// families land in `protectors`, the APK-specific types in
    /// `apk_protectors`/`tools`, `SOURCECODE` records in `texts`.
    pub fn map_for(&mut self, rtype: u8) -> &mut DetectMap {
        use crate::gen_names::rtype as rt;
        match rtype {
            x if x == rt::RECORD_TYPE_OPERATIONSYSTEM || x == rt::RECORD_TYPE_VIRTUALMACHINE => {
                &mut self.operation_systems
            }
            x if x == rt::RECORD_TYPE_FORMAT
                || x == rt::RECORD_TYPE_GENERIC
                || x == rt::RECORD_TYPE_DOCUMENT =>
            {
                &mut self.formats
            }
            x if x == rt::RECORD_TYPE_DOSEXTENDER => &mut self.dosextenders,
            x if x == rt::RECORD_TYPE_LINKER => &mut self.linkers,
            x if x == rt::RECORD_TYPE_COMPILER => &mut self.compilers,
            x if x == rt::RECORD_TYPE_LANGUAGE => &mut self.languages,
            x if x == rt::RECORD_TYPE_LIBRARY => &mut self.libraries,
            x if x == rt::RECORD_TYPE_TOOL
                || x == rt::RECORD_TYPE_APKTOOL
                || x == rt::RECORD_TYPE_PRODUCER
                || x == rt::RECORD_TYPE_CREATOR
                || x == rt::RECORD_TYPE_AUTHOR =>
            {
                &mut self.tools
            }
            x if x == rt::RECORD_TYPE_PACKER
                || x == rt::RECORD_TYPE_COMPRESSOR
                || x == rt::RECORD_TYPE_NETCOMPRESSOR =>
            {
                &mut self.packers
            }
            x if x == rt::RECORD_TYPE_SFX => &mut self.sfx,
            x if x == rt::RECORD_TYPE_PROTECTOR
                || x == rt::RECORD_TYPE_PROTECTION
                || x == rt::RECORD_TYPE_CRYPTER
                || x == rt::RECORD_TYPE_CRYPTOR
                || x == rt::RECORD_TYPE_OBFUSCATOR
                || x == rt::RECORD_TYPE_NETOBFUSCATOR
                || x == rt::RECORD_TYPE_JAROBFUSCATOR =>
            {
                &mut self.protectors
            }
            x if x == rt::RECORD_TYPE_APKOBFUSCATOR => &mut self.apk_protectors,
            x if x == rt::RECORD_TYPE_DONGLEPROTECTION => &mut self.dongle,
            x if x == rt::RECORD_TYPE_SIGNTOOL => &mut self.signtools,
            x if x == rt::RECORD_TYPE_INSTALLER => &mut self.installers,
            x if x == rt::RECORD_TYPE_JOINER => &mut self.joiners,
            x if x == rt::RECORD_TYPE_PETOOL => &mut self.petools,
            x if x == rt::RECORD_TYPE_SOURCECODE => &mut self.texts,
            x if x == rt::RECORD_TYPE_ARCHIVE => &mut self.archives,
            x if x == rt::RECORD_TYPE_CERTIFICATE => &mut self.certificates,
            x if x == rt::RECORD_TYPE_DEBUGDATA => &mut self.debugdata,
            x if x == rt::RECORD_TYPE_INSTALLERDATA => &mut self.installerdata,
            x if x == rt::RECORD_TYPE_SFXDATA => &mut self.sfxdata,
            x if x == rt::RECORD_TYPE_PROTECTORDATA => &mut self.protectordata,
            x if x == rt::RECORD_TYPE_DATABASE => &mut self.databases,
            x if x == rt::RECORD_TYPE_IMAGE => &mut self.images,
            _ => &mut self.other,
        }
    }

    /// Insert a record routed by `rtype`, replacing any record of the
    /// same name already in that map (`QMap::insert` last-write-wins).
    /// `key` mirrors the call-site `map.insert(name, rec)` shape; the
    /// record's own `name` field is authoritative.
    pub fn insert(&mut self, _key: u16, rec: ScanRecord) {
        self.map_for(rec.rtype).insert(rec.name, rec);
    }

    /// `QMap::contains` over the union of result maps — used by handlers
    /// guarding "already emitted" checks.
    pub fn contains_key(&self, name: &u16) -> bool {
        self.all().iter().any(|m| m.contains_key(name))
    }

    /// Mutable access to the first result record with this name
    /// (maps searched in drain order).
    #[allow(dead_code)] // used by Phase 23 fixup promotions
    pub fn get_mut(&mut self, name: &u16) -> Option<&mut ScanRecord> {
        // Borrow rules prevent iterating `all_mut()` twice; walk fields
        // through an index loop is impossible for disjoint mut refs, so
        // destructure manually via each() helper below.
        self.find_map_mut(name)
    }

    #[allow(dead_code)]
    fn find_map_mut(&mut self, name: &u16) -> Option<&mut ScanRecord> {
        for m in self.all_mut() {
            if let Some(r) = m.get_mut(name) {
                return Some(r);
            }
        }
        None
    }

    /// Remove `name` from every result map (upstream removes only from
    /// the target map; names are effectively unique per rtype so this is
    /// equivalent for our records).
    pub fn remove(&mut self, name: &u16) -> Option<ScanRecord> {
        for m in self.all_mut() {
            if let Some(r) = m.remove(name) {
                return Some(r);
            }
        }
        None
    }

    /// Insert `f()` only when no result map already holds `name`
    /// (`map.entry(name).or_insert_with` shape).
    pub fn entry_or_insert(&mut self, name: u16, f: impl FnOnce() -> ScanRecord) {
        if !self.contains_key(&name) {
            let rec = f();
            self.map_for(rec.rtype).insert(rec.name, rec);
        }
    }

    /// Read-only view of a record by name (first hit in drain order).
    pub fn get(&self, name: &u16) -> Option<&ScanRecord> {
        self.all().iter().find_map(|m| m.get(name))
    }

    /// All records across maps (drain order is irrelevant here — used
    /// for `values().any(...)` membership scans in handlers).
    pub fn values(&self) -> impl Iterator<Item = &ScanRecord> {
        self.all().into_iter().flat_map(|m| m.values())
    }

    /// Whether every result map is empty.
    #[allow(dead_code)] // used by Phase 23 fixup promotions
    pub fn is_empty(&self) -> bool {
        self.all().iter().all(|m| m.is_empty())
    }

    /// Ordered records: each map sorted by name id (QMap key order),
    /// maps appended in `_handleResult` order.
    pub fn ordered_values(&self) -> Vec<&ScanRecord> {
        let mut out = Vec::new();
        for m in self.all() {
            let mut v: Vec<&ScanRecord> = m.values().collect();
            v.sort_by_key(|r| r.name);
            out.extend(v);
        }
        out
    }
}

/// Insert target shared by intermediate `DetectMap`s (keyed by name)
/// and `ResultMaps` (routed by rtype). Lets the per-module `emit`/`put`
/// helpers stay generic over both.
pub trait EmitTarget {
    /// Insert a record with last-write-wins semantics.
    fn push_rec(&mut self, rec: ScanRecord);
}

impl EmitTarget for DetectMap {
    fn push_rec(&mut self, rec: ScanRecord) {
        self.insert(rec.name, rec);
    }
}

impl EmitTarget for ResultMaps {
    fn push_rec(&mut self, rec: ScanRecord) {
        self.insert(rec.name, rec);
    }
}

/// Insert a record into a result map. Upstream `QMap::insert` overwrites an
/// existing key, so the last write wins.
#[allow(clippy::too_many_arguments)]
pub fn push(
    map: &mut impl EmitTarget,
    ft: u16,
    rtype: u8,
    name: u16,
    ver: &str,
    info: &str,
    sname: Option<&'static str>,
    stype: Option<&'static str>,
) {
    map.push_rec(ScanRecord {
        name,
        rtype,
        ft,
        variant: 0,
        version: ver.to_string(),
        info: info.to_string(),
        heuristic: false,
        unknown: false,
        sname: sname.map(std::borrow::Cow::Borrowed),
        stype,
    });
}

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

/// `XBinary::regExp` — capture group `group` of the first regex match,
/// or "" (bad pattern / no match).
pub fn reg_exp(pattern: &str, text: &str, group: usize) -> String {
    let Ok(re) = fancy_regex::Regex::new(pattern) else {
        return String::new();
    };
    re.captures(text)
        .ok()
        .flatten()
        .and_then(|c| c.get(group))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default()
}

/// `XBinary::isRegExpPresent` — whether the pattern matches anywhere.
pub fn reg_exp_present(pattern: &str, text: &str) -> bool {
    fancy_regex::Regex::new(pattern)
        .ok()
        .and_then(|re| re.find(text).ok().flatten())
        .is_some()
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

/// `MSDOS_richScan` list form — every matching record per rich entry
/// (name duplicates preserved), used by `handle_Microsoft`'s toolchain
/// selection which compares versions across matches.
pub fn msrich_scan_list(
    entries: &[MsRichEntry],
    records: &[MsRichRecord],
    ft1: u16,
    ft2: u16,
) -> Vec<ScanRecord> {
    let mut out = Vec::new();
    for e in entries {
        for rec in records {
            if !ft_matches(rec.basic.ft, ft1, ft2) {
                continue;
            }
            let id_ok = rec.id == e.id || rec.id == 0xFFFF;
            let build_ok = rec.build == e.build || rec.build == 0xFFFF_FFFF;
            if id_ok && build_ok {
                let mut sr = ScanRecord::from_basic(&rec.basic);
                if rec.build == 0xFFFF_FFFF {
                    sr.version = format!("{}.{}", sr.version, e.build);
                }
                out.push(sr);
            }
        }
    }
    out
}

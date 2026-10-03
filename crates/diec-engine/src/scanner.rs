//! Scan orchestration: run rules against file bytes and collect results.
//!
//! The scanner creates a rule runtime per rule, loads the database
//! framework (init + includes), and evaluates each rule in isolation.
//! Results are aggregated into a `ScanResult`.
//!
//! For batch scanning, [`Scanner`] reuses runtimes across files of the
//! same file type (ADR 0016), avoiding repeated runtime creation and
//! framework loading.

use crate::database::Database;
use crate::host::BufferHost;
use diec_core::cancel::CancellationToken;
use diec_core::input::{ByteRange, ByteSource, ByteView, MemorySource};
use diec_formats::probe::ProbeTable;
use diec_rules::backend_rquickjs::RquickjsRuntime;
use diec_rules::runtime::{DatabaseSnapshot, LoadedRule, RuleRuntime, RuntimeConfig};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Detect the file format and return the set of rule file types that
/// should be run.
///
/// Upstream DIE's `scanProcess` uses an if-else-if chain that picks the
/// first matching format and calls `_processDetect` with that specific
/// file type. `checkFileType` then ensures only rules whose `fileType`
/// matches the detected format are executed. Binary rules (FT_UNKNOWN)
/// do NOT run when a specific format is detected.
///
/// This function mirrors that logic. For executable formats (PE, ELF,
/// MACH, MACHOFAT), only the format-specific rules are run — Binary
/// rules are excluded to avoid false positives from magic byte
/// ambiguities (e.g., CAFEBABE is both Mach-O FAT and Java Class).
///
/// For non-executable formats (JPEG, PNG, PDF, ZIP, etc.), both
/// format-specific and Binary rules are run, because the format-specific
/// host APIs (Jpeg, Pdf, etc.) are not yet implemented and the Binary
/// rules provide the actual detection logic using the generic API.
/// Whether the file name ends with a `.COM` suffix, the sole criterion
/// upstream uses to insert `FT_COM` into the detected type set
/// (`xformats.cpp::_getFileTypes`: `getDeviceFileSuffix(device) == "COM"`).
fn has_com_suffix(file_name: &str) -> bool {
    file_name
        .rsplit('.')
        .next()
        .map(|ext| ext.eq_ignore_ascii_case("com"))
        .unwrap_or(false)
        && file_name.contains('.')
}

/// Upstream `XCOM::isValid`: the whole image must fit in the 16-bit COM
/// address space (`XCOM_DEF::IMAGESIZE - ADDRESS_BEGIN` = 0xFF00 bytes).
fn com_image_valid(data_len: usize) -> bool {
    data_len <= 0xFF00
}

fn detect_rule_types(data: &[u8], file_name: &str) -> Vec<&'static str> {
    let source = MemorySource::new(data);
    let range = ByteRange::new(0, source.len()).unwrap_or(ByteRange {
        start: 0,
        length: 0,
    });
    let view = match ByteView::new(&source, range) {
        Some(v) => v,
        None => return vec!["Binary"],
    };

    let table = ProbeTable::default_phase2();
    let (candidates, _errors) = table.probe_all(&view);

    // Collect all detected format names.
    let detected: Vec<&str> = candidates
        .iter()
        .map(|c| c.file_type.name.as_str())
        .collect();

    // Executable formats: only run format-specific rules (no Binary).
    // This prevents false positives like CAFEBABE matching both Mach-O FAT
    // and Java Class File.
    if detected.iter().any(|&n| n == "PE32" || n == "PE64") {
        return vec!["PE"];
    }
    if detected
        .iter()
        .any(|&n| n == "ELF32" || n == "ELF64" || n == "ELF")
    {
        return vec!["ELF"];
    }
    if detected
        .iter()
        .any(|&n| n == "Mach-O 32" || n == "Mach-O" || n == "Mach-O 64")
    {
        return vec!["MACH"];
    }
    // MZ subtypes promoted from the signature at e_lfanew, matching the
    // upstream dispatch order LX -> LE -> NE (xscanengine.cpp: FT_LX,
    // FT_LE, FT_NE branches all precede FT_MSDOS). They are disjoint in
    // practice because a file carries exactly one signature at e_lfanew.
    if detected.contains(&"LX") {
        return vec!["LX"];
    }
    if detected.contains(&"LE") {
        return vec!["LE"];
    }
    if detected.contains(&"NE") {
        return vec!["NE"];
    }
    // Java Class must be checked BEFORE Mach-O FAT because CAFEBABE is
    // the magic for both. The JavaClassProbe validates major version >= 45,
    // so a real Java Class file will match both probes, but Java Class is
    // the correct detection. A real Mach-O FAT file (nfat_arch < 45) will
    // only match the Mach-O probe.
    // JavaClass host API is now implemented (getFileFormatName/Version),
    // so only JavaClass rules are run. Binary rules are excluded to avoid
    // duplicate detections (format_bin.Java.1.sg outputs a different name).
    if detected.contains(&"Java Class") {
        return vec!["JavaClass"];
    }
    if detected
        .iter()
        .any(|&n| n == "Mach-O FAT" || n == "Mach-O FAT64")
    {
        return vec!["MACHOFAT"];
    }

    // Non-executable formats: run only the detected format's rule group.
    // This mirrors the upstream dispatch chain in XScanEngine::scanProcess
    // (xscanengine.cpp): once stFT contains a recognized type, only that
    // type's rules run — Binary rules run only in the trailing fallback.
    // Upstream quirks reproduced here:
    // - IPA: the FT_IPA branch is commented out upstream, so IPA files are
    //   scanned with the Binary group instead.
    // - Archive subtypes that upstream tracks as FT_ARCHIVE (GZIP, 7z, TAR,
    //   CAB) fall through to the Binary fallback, matching upstream's
    //   else-branch which runs COM+Binary.
    // - ZIP/APK/JAR/RAR/NPM/ISO9660/PNG/JPEG run their own group only; the
    //   upstream `FT_BINARY` companion call for ZIP is commented out.
    let mut types: Vec<&'static str> = Vec::new();

    if detected.contains(&"MSDOS") {
        types.push("MSDOS");
    }
    if detected.contains(&"APK") {
        types.push("APK");
    }
    if detected.contains(&"IPA") {
        // Upstream scans IPA with the Binary rule group (the FT_IPA branch
        // in scanProcess is commented out).
        types.push("Binary");
    }
    if detected.contains(&"JAR") {
        types.push("JAR");
    }
    if detected.contains(&"ZIP") {
        types.push("ZIP");
    }
    if detected.contains(&"DEX") {
        types.push("DEX");
    }
    if detected.contains(&"NPM") {
        types.push("NPM");
    }
    if detected.contains(&"PDF") {
        types.push("PDF");
    }
    if detected.contains(&"CFBF") {
        types.push("CFBF");
    }
    if detected.contains(&"RAR") {
        types.push("RAR");
    }
    if detected.iter().any(|&n| n == "ISO 9660" || n == "ISO9660") {
        types.push("ISO9660");
    }
    if detected.contains(&"JPEG") {
        types.push("JPEG");
    }
    if detected.contains(&"PNG") {
        types.push("PNG");
    }
    if detected
        .iter()
        .any(|&n| n == "Python Compiled" || n == "PYC")
    {
        types.push("PYC");
    }

    // If no format-specific type was identified, fall back to Binary rules.
    // This handles unrecognized files (plain text, empty, etc.) and any
    // format we don't yet have a specific rule directory for.
    if types.is_empty() {
        // Upstream `XScanEngine::scanProcess`: files that survive to the
        // COM/archive fallback are first offered to the COM rule group.
        // With a ".COM" file suffix and a 16-bit-fitting image, FT_COM is
        // in stFT and the COM group runs as the primary type (Binary only
        // joins under deep scan, which is off by default). Otherwise the
        // COM group still runs non-primary — upstream appends its
        // non-generic records after the Binary results.
        if com_image_valid(data.len()) && has_com_suffix(file_name) {
            types.push("COM");
        } else if com_image_valid(data.len()) {
            types.push("Binary");
            types.push("COM");
        } else {
            types.push("Binary");
        }
    }

    types
}

/// Error type for scan operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// Database loading or initialization failed.
    DatabaseInit {
        /// Error detail.
        detail: String,
    },
    /// Host API registration failed.
    HostApi {
        /// Error detail.
        detail: String,
    },
    /// Rule evaluation failed.
    RuleEval {
        /// The rule path that failed.
        path: String,
        /// Error detail.
        detail: String,
    },
    /// Input I/O error.
    Input {
        /// The file path that could not be read.
        path: String,
        /// Error detail.
        detail: String,
    },
    /// The operation was cancelled.
    Cancelled,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::DatabaseInit { detail } => {
                write!(f, "database initialization failed: {detail}")
            }
            ScanError::HostApi { detail } => write!(f, "host API error: {detail}"),
            ScanError::RuleEval { path, detail } => {
                write!(f, "rule evaluation error in {path}: {detail}")
            }
            ScanError::Input { path, detail } => {
                write!(f, "input error reading {path}: {detail}")
            }
            ScanError::Cancelled => write!(f, "scan cancelled"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Remove duplicate detections by (type_name, name, version, options, offset, size).
///
/// Keeps the first occurrence, discarding subsequent duplicates. This is
/// used in `--alltypes` mode where multiple file_type rule groups can
/// produce identical detections (e.g., PE and MSDOS both output "MS-DOS").
/// See ADR 0027.
fn dedup_detections(detections: &mut Vec<ScanDetection>) {
    use std::collections::HashSet;
    type DedupKey = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<u64>,
        Option<u64>,
    );
    let mut seen: HashSet<DedupKey> = HashSet::new();
    detections.retain(|d| {
        seen.insert((
            d.type_name.clone(),
            d.name.clone(),
            d.version.clone(),
            d.options.clone(),
            d.offset,
            d.size,
        ))
    });
}

/// Return the rule file types for `--alltypes` mode.
///
/// Upstream `bIsAllTypesScan` does NOT run every format's rules blindly.
/// It first probes the format via `XFormats::getFileTypes`, then runs the
/// detected format's rules plus compatible parent-type rules (e.g., PE also
/// runs MS-DOS rules because PE contains a DOS stub; APK also runs JAR/ZIP
/// rules because APK is a ZIP container).
///
/// Running all 18 format rule sets on every file causes massive false
/// positives (e.g., an ELF file matching JPEG/PDF/PNG byte patterns). This
/// function delegates to `detect_rule_types` for the probe, then appends
/// the compatible parent types.
/// Check whether the probe layer classified the buffer as IPA.
///
/// `detect_rule_types` maps IPA to the Binary rule group (the upstream
/// FT_IPA dispatch branch is commented out), so the IPA membership is no
/// longer visible in its return value; re-probe cheaply for alltypes.
fn detected_ipa(data: &[u8]) -> bool {
    let source = MemorySource::new(data);
    let Some(range) = ByteRange::new(0, source.len()) else {
        return false;
    };
    let Some(view) = ByteView::new(&source, range) else {
        return false;
    };
    let table = ProbeTable::default_phase2();
    let (candidates, _errors) = table.probe_all(&view);
    candidates.iter().any(|c| c.file_type.name == "IPA")
}

fn alltypes_rule_types(data: &[u8], file_name: &str) -> Vec<&'static str> {
    let mut types = detect_rule_types(data, file_name);

    // Compatible parent types: container/wrapper formats also run their
    // parent format's rules.
    let has_pe = types.contains(&"PE");
    let has_apk = types.contains(&"APK");
    let has_ipa = detected_ipa(data);
    let has_jar = types.contains(&"JAR");

    // Upstream runs the MSDOS rule group for every MZ-derived executable
    // (PE32/PE64/LE/LX/NE), not just PE (xscanengine.cpp prepass).
    let has_dos_exec =
        has_pe || types.contains(&"NE") || types.contains(&"LE") || types.contains(&"LX");
    if has_dos_exec {
        types.push("MSDOS");
    }
    // Upstream prepass: APK and IPA additionally run the JAR and ZIP
    // rule groups; a plain JAR additionally runs ZIP rules.
    if has_apk || has_ipa {
        types.push("JAR");
        types.push("ZIP");
    } else if has_jar {
        types.push("ZIP");
    }

    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    types.retain(|t| seen.insert(*t));
    types
}

/// A single detection result from scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanDetection {
    /// The file type that produced this detection.
    pub file_type: String,
    /// The detection type (e.g. "archive", "compiler", "linker").
    pub type_name: String,
    /// The detection name (e.g. "7-Zip", "Borland C++").
    pub name: String,
    /// Optional version string.
    pub version: Option<String>,
    /// Optional options/info string.
    pub options: Option<String>,
    /// Path to the signature file that produced this detection (relative to db root).
    /// Used by the GUI Advanced mode to display the matching signature source.
    pub signature_path: Option<String>,
    /// Optional unique identifier for this detection (used for nested tree building).
    /// When `Some`, detections with `parent_id` matching this id are nested children.
    pub id: Option<String>,
    /// Optional parent detection id for building nested result trees.
    /// When `Some`, this detection is a child of the detection with the matching id.
    pub parent_id: Option<String>,
    /// Optional file part where this detection originated.
    /// Values: "Header", "Resource", "Overlay", "Archive", etc.
    pub file_part: Option<String>,
    /// Optional offset of the detected region within the file.
    pub offset: Option<u64>,
    /// Optional size of the detected region in bytes.
    pub size: Option<u64>,
    /// Optional heuristic detection marker.
    /// When `Some(true)`, the detection was produced by a heuristic rule.
    pub is_heuristic: Option<bool>,
    /// Optional A-Heuristic (advanced heuristic) detection marker.
    pub is_a_heuristic: Option<bool>,
    /// Optional original name for archive/container entries.
    pub original_name: Option<String>,
    /// Engine that produced this detection.
    ///
    /// `None`/`"die"` for the script-rule engine; `"nfd"` for the
    /// SpecAbstract-compatible table engine (Phase 21, ADR 0035).
    pub engine: Option<String>,
}

/// A structured diagnostic entry with file/line context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// The signature file that produced the diagnostic (e.g. "PE/compiler.1.sg").
    pub file: String,
    /// Line number in the signature file, if known.
    pub line: Option<u32>,
    /// The diagnostic message.
    pub message: String,
    /// The kind: "error", "warning", "info".
    pub kind: String,
}

/// Per-signature profiling data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureProfile {
    /// The signature file path.
    pub file: String,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
}

/// The result of scanning a single file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// The file path that was scanned.
    pub path: String,
    /// All detections found.
    pub detections: Vec<ScanDetection>,
    /// Diagnostics (errors, warnings) encountered during scanning.
    /// Kept as strings for backward compatibility with JSON consumers.
    pub diagnostics: Vec<String>,
    /// Structured diagnostics with file/line/kind separation.
    pub structured_diagnostics: Vec<Diagnostic>,
    /// Per-signature profiling data (elapsed time per rule file).
    pub profiling: Vec<SignatureProfile>,
}

/// Convert a `DetectionResult` from the rule runtime into a `ScanDetection`.
///
/// This helper centralizes the mapping so that both `scan_bytes` and
/// `Scanner::scan_bytes` produce identical detections. New optional fields
/// are populated from the `DetectionResult` extended fields; when the rule
/// runtime does not provide them, they default to `None`.
fn detection_from_result(
    file_type: &str,
    rule_path: &str,
    result: diec_rules::runtime::DetectionResult,
) -> ScanDetection {
    ScanDetection {
        file_type: file_type.to_string(),
        type_name: result.type_name,
        name: result.name,
        version: if result.version.is_empty() {
            None
        } else {
            Some(result.version)
        },
        options: if result.options.is_empty() {
            None
        } else {
            Some(result.options)
        },
        signature_path: Some(rule_path.to_string()),
        id: result.id,
        parent_id: result.parent_id,
        file_part: result.file_part,
        offset: result.offset,
        size: result.size,
        is_heuristic: result.is_heuristic,
        is_a_heuristic: result.is_a_heuristic,
        original_name: result.original_name,
        engine: None,
    }
}

/// Convert an NFD engine output record into a `ScanDetection`.
///
/// The `engine` marker is `"nfd"`; the reported `file_type` is the
/// sniffed SpecAbstract `FT_*` display name.
fn detection_from_nfd(file_type: &str, rec: diec_nfd::Detection) -> ScanDetection {
    ScanDetection {
        file_type: file_type.to_string(),
        type_name: rec.record_type.to_string(),
        name: rec.record_name.to_string(),
        version: if rec.version.is_empty() {
            None
        } else {
            Some(rec.version)
        },
        options: if rec.info.is_empty() {
            None
        } else {
            Some(rec.info)
        },
        signature_path: None,
        id: None,
        parent_id: None,
        file_part: None,
        offset: None,
        size: None,
        is_heuristic: if rec.heuristic { Some(true) } else { None },
        is_a_heuristic: None,
        original_name: None,
        engine: Some("nfd".to_string()),
    }
}

/// Run the NFD/SpecAbstract second engine over `data` and append its
/// records to `detections`.
///
/// `diec_nfd::sniff_ft` recovers the broad file class from magic bytes,
/// mirroring the `SpecAbstract::_processDetect` dispatch. Only the deep
/// scan flag is currently consulted by the ported paths.
fn run_nfd_pass(
    data: &[u8],
    file_name: &str,
    flags: &crate::host::ScanFlags,
    detections: &mut Vec<ScanDetection>,
) {
    let opts = diec_nfd::ScanOptions {
        deep_scan: flags.deep,
        heuristic_scan: flags.heuristic,
        verbose: flags.verbose,
        all_types: flags.all_types,
        archives_scan: flags.archives,
        recursive_scan: flags.recursive,
        resources_scan: flags.resources,
        overlay_scan: flags.overlays,
        aggressive_scan: flags.aggressive,
    };
    detections.extend(nfd_scan_opts(data, file_name, opts));
}

/// Shared NFD entry: sniff the file type, run `diec_nfd::scan`, map
/// records to `ScanDetection` (engine marker `"nfd"`).
fn nfd_scan_opts(data: &[u8], file_name: &str, opts: diec_nfd::ScanOptions) -> Vec<ScanDetection> {
    let ft = diec_nfd::sniff_ft_named(data, file_name);
    let ft_label = diec_nfd::ft_name(ft);
    diec_nfd::scan(data, ft, opts)
        .into_iter()
        .map(|rec| detection_from_nfd(ft_label, rec))
        .collect()
}

/// Standalone NFD scan for the GUI NFD view (upstream's dedicated NFD
/// panel shows the engine's own records, independent of the merged DIE
/// result list). `deep`/`heuristic`/`verbose` mirror the three
/// user-visible scan options; archive/recursive scanning stay enabled to
/// match the oracle defaults.
pub fn nfd_scan(
    data: &[u8],
    file_name: &str,
    deep: bool,
    heuristic: bool,
    verbose: bool,
) -> Vec<ScanDetection> {
    nfd_scan_opts(
        data,
        file_name,
        diec_nfd::ScanOptions {
            deep_scan: deep,
            heuristic_scan: heuristic,
            verbose,
            all_types: false,
            archives_scan: true,
            recursive_scan: true,
            resources_scan: true,
            overlay_scan: true,
            aggressive_scan: false,
        },
    )
}

/// Scan a single file against the database.
///
/// This is the main entry point for scanning. It reads the file,
/// creates a host adapter, and evaluates all applicable rules.
pub fn scan_once(
    database: &Database,
    path: &str,
    flags: crate::host::ScanFlags,
    cancel: &CancellationToken,
) -> Result<ScanResult, ScanError> {
    let data = std::fs::read(path).map_err(|e| ScanError::Input {
        path: path.to_string(),
        detail: e.to_string(),
    })?;

    scan_bytes(database, path, data, flags, cancel)
}

/// Scan a byte buffer against the database.
///
/// Rules are grouped by file type. One runtime is created per file
/// type group, and each rule is evaluated in an isolated scope within
/// that runtime. This avoids the overhead of creating a runtime per
/// rule while preventing scope pollution between rules.
pub fn scan_bytes(
    database: &Database,
    file_name: &str,
    data: Vec<u8>,
    flags: crate::host::ScanFlags,
    cancel: &CancellationToken,
) -> Result<ScanResult, ScanError> {
    let snapshot = database.snapshot();
    let mut detections = Vec::new();
    let mut diagnostics = Vec::new();
    let mut structured_diagnostics: Vec<Diagnostic> = Vec::new();
    let mut profiling: Vec<SignatureProfile> = Vec::new();

    // Detect the file format to determine which rule types to run.
    // With --alltypes, the detected format's rules plus compatible parent
    // types are run (matching upstream bIsAllTypesScan: PE also reports
    // MSDOS, APK also reports JAR/ZIP). This avoids false positives from
    // running unrelated format rules on every file.
    // With file_type override, only the specified type's rules are run.
    let active_types: Vec<&str> = if let Some(ref ft) = flags.file_type {
        vec![ft.as_str()]
    } else if flags.all_types {
        alltypes_rule_types(&data, file_name)
    } else {
        detect_rule_types(&data, file_name)
    };

    // Group rules by file type, but only for types that match the
    // detected format.
    let mut groups: std::collections::BTreeMap<&str, Vec<&diec_rules::runtime::LoadedRule>> =
        std::collections::BTreeMap::new();
    for rule in &snapshot.rules {
        if active_types.contains(&rule.file_type.as_str()) {
            groups.entry(&rule.file_type).or_default().push(rule);
        }
    }

    // Process each file type group with a shared runtime.
    for (file_type, rules) in &groups {
        if cancel.is_cancelled() {
            return Err(ScanError::Cancelled);
        }

        // Create one runtime for this file type.
        let mut runtime = match RquickjsRuntime::new(RuntimeConfig::default()) {
            Ok(rt) => rt,
            Err(e) => {
                diagnostics.push(format!("runtime create error for {file_type}: {e}"));
                continue;
            }
        };

        // Create a host with the file data and scan flags.
        let host = Arc::new(
            BufferHost::new(data.clone(), file_name.to_string()).with_flags(flags.clone()),
        );
        if let Err(e) = runtime.register_host_api(host.clone()) {
            diagnostics.push(format!("host API error for {file_type}: {e}"));
            continue;
        }

        // Load the framework (init + type init + includes) with no rules.
        // Only include the type init script that matches this file type.
        let type_init: Vec<(String, String)> = snapshot
            .type_init_scripts
            .iter()
            .filter(|(ft, _)| ft == file_type)
            .cloned()
            .collect();
        let framework_snapshot = DatabaseSnapshot {
            rules: Vec::new(),
            init_script: snapshot.init_script.clone(),
            type_init_scripts: type_init,
            include_scripts: snapshot.include_scripts.clone(),
        };

        if let Err(e) = runtime.load_database(&framework_snapshot) {
            diagnostics.push(format!("load_database error for {file_type}: {e}"));
            continue;
        }

        // Initialize the runtime (execute type init scripts).
        let host_ref: &dyn diec_rules::host_api::HostApi = &*host;
        if let Err(e) = runtime.init(host_ref) {
            diagnostics.push(format!("init error for {file_type}: {e}"));
            continue;
        }

        // Evaluate each rule in an isolated scope over a shared result
        // list. Upstream sorts signatures ascending by the priority digit in
        // the file name (`sort_signature_prio`) so post-processing rules like
        // `_FixDetects.9.sg` run last and observe every result appended to
        // the shared `m_pListScanStructs` — `_isResultPresent`,
        // `_getNumberOfResults` and `_removeResult` must see prior rules'
        // records (e.g. `_Microsoft.6.sg` skips its Rich-derived MSVC record
        // when an EP-based compiler result already exists).
        if let Err(e) = runtime.begin_result_group() {
            diagnostics.push(format!("result group reset error for {file_type}: {e}"));
            continue;
        }
        for rule in rules {
            if cancel.is_cancelled() {
                return Err(ScanError::Cancelled);
            }

            let start = std::time::Instant::now();
            match runtime.evaluate_rule_in_group(&rule.path, &rule.source, cancel) {
                Ok(()) => {}
                Err(e) => {
                    let msg = format!("{}: {}", rule.path, e);
                    diagnostics.push(msg.clone());
                    structured_diagnostics.push(Diagnostic {
                        file: rule.path.clone(),
                        line: None,
                        message: e.to_string(),
                        kind: "error".to_string(),
                    });
                }
            }
            // Non-fatal rule diagnostics (upstream PDSTRUCT error list —
            // e.g. "Invalid signature" from malformed upstream rules) are
            // attributed to the rule that produced them.
            for msg in host.drain_scan_errors() {
                diagnostics.push(format!("{}: {}", rule.path, msg));
            }
            profiling.push(SignatureProfile {
                file: rule.path.clone(),
                elapsed_ms: start.elapsed().as_millis() as u64,
            });
        }

        // Emit the group's surviving results once, attributed by the rule
        // stamp so records removed by `_removeResult` are excluded.
        match runtime.read_results() {
            Ok(results) => {
                for result in results {
                    let rule_path = result.rule_path.clone();
                    detections.push(detection_from_result(file_type, &rule_path, result));
                }
            }
            Err(e) => diagnostics.push(format!("read results error for {file_type}: {e}")),
        }

        runtime.shutdown();
    }

    // Apply --hideunknown filter: remove detections with empty or "Unknown" name.
    if flags.hide_unknown {
        detections.retain(|d| !d.name.is_empty() && d.name != "Unknown");
    }

    // Apply result deduplication (ADR 0027). Default: dedup on.
    // --no-dedup disables it to match upstream behavior.
    if !flags.no_dedup {
        dedup_detections(&mut detections);
    }

    // Intra-file recursive scanning (ADR 0028): if recursive/resources/overlays
    // flag is set and the file is a PE, extract resources and overlay and
    // recursively scan each as a sub-device.
    if (flags.recursive || flags.resources || flags.overlays) && diec_rules::pe_native::is_pe(&data)
    {
        let nested_detections = scan_nested_pe_inline(file_name, &data, &flags, cancel, database)?;
        detections.extend(nested_detections);
    }

    // Archive member recursive scanning (ADR 0030): if archives flag is set
    // and the file is a supported archive, extract members and recursively
    // scan each.
    if flags.archives && crate::archive_unpack::is_archive(&data) {
        let archive_detections =
            scan_archive_members_inline(file_name, &data, &flags, cancel, database)?;
        detections.extend(archive_detections);
    }

    // NFD/SpecAbstract second engine (--nfd / GUI engine selector).
    // Its records are appended after the DIE results and carry the
    // `engine = "nfd"` marker. See ADR 0035.
    if flags.nfd {
        run_nfd_pass(&data, file_name, &flags, &mut detections);
    }

    // Add "Unknown" placeholder when no detections were found.
    // Matches upstream XScanEngine::_processDetect with bAddUnknown=true:
    // when listRecords is empty, an "Unknown" record is appended so that
    // the output always has at least one entry. --hideunknown suppresses this.
    if detections.is_empty() && !flags.hide_unknown {
        // Use the first detected format type as the file_type for the
        // Unknown placeholder, so that --alltypes negative tests don't
        // treat it as a cross-format false positive.
        let unknown_ft = active_types
            .first()
            .map(|s| s.to_string())
            .unwrap_or_default();
        detections.push(ScanDetection {
            file_type: unknown_ft,
            type_name: "unknown".to_string(),
            name: "Unknown".to_string(),
            version: None,
            options: None,
            signature_path: None,
            parent_id: None,
            id: None,
            file_part: None,
            offset: None,
            size: None,
            is_heuristic: None,
            is_a_heuristic: None,
            original_name: None,
            engine: None,
        });
    }

    Ok(ScanResult {
        path: file_name.to_string(),
        detections,
        diagnostics,
        structured_diagnostics,
        profiling,
    })
}

/// Inline nested PE scanner for `scan_bytes` (free function version).
///
/// Creates a closure that calls `scan_bytes` recursively with `recursive`
/// disabled to prevent infinite loops.
fn scan_nested_pe_inline(
    file_name: &str,
    data: &[u8],
    flags: &crate::host::ScanFlags,
    cancel: &CancellationToken,
    database: &Database,
) -> Result<Vec<ScanDetection>, ScanError> {
    let scan_fn =
        |name: &str, bytes: &[u8], sub_flags: &crate::host::ScanFlags, ct: &CancellationToken| {
            // Create a sub-scan with the nested data.
            // We use a simplified scan that only collects detections.
            let sub_result = scan_bytes(database, name, bytes.to_vec(), sub_flags.clone(), ct)?;
            Ok(sub_result.detections)
        };
    crate::nested_scan::scan_nested_pe(file_name, data, flags, cancel, &scan_fn)
}

/// Inline archive member scanner for `scan_bytes` (free function version).
///
/// Extracts archive members and recursively scans each as a sub-device.
fn scan_archive_members_inline(
    file_name: &str,
    data: &[u8],
    flags: &crate::host::ScanFlags,
    cancel: &CancellationToken,
    database: &Database,
) -> Result<Vec<ScanDetection>, ScanError> {
    let members = crate::archive_unpack::extract_archive(data, flags);
    let mut nested_detections = Vec::new();

    for member in members {
        if cancel.is_cancelled() {
            return Err(ScanError::Cancelled);
        }
        if member.data.is_empty() {
            continue;
        }

        // Upstream `XScanEngine::isScanable` gate: archive members are
        // scanned only when they sniff as an executable/structured
        // format; plain text and data members are skipped entirely.
        if !diec_nfd::is_scanable_ft(diec_nfd::sniff_ft(&member.data)) {
            continue;
        }

        let member_name = format!("{file_name}:Archive({})", member.name);
        let child_flags = crate::host::ScanFlags {
            // Nested scans don't recurse further (avoid infinite loops).
            // The NFD engine performs its own file-part recursion inside
            // `diec_nfd::scan`; disable it here to avoid duplicate records.
            recursive: false,
            resources: false,
            overlays: false,
            archives: false,
            nfd: false,
            ..flags.clone()
        };

        match scan_bytes(database, &member_name, member.data, child_flags, cancel) {
            Ok(sub_result) => {
                for mut det in sub_result.detections {
                    det.file_part = Some("Archive".to_string());
                    nested_detections.push(det);
                }
            }
            Err(ScanError::Cancelled) => return Err(ScanError::Cancelled),
            Err(_) => {
                // Skip failed nested scans.
            }
        }
    }

    Ok(nested_detections)
}

// ---------------------------------------------------------------------------
// Scanner: stateful scanner with per-file-type runtime reuse (ADR 0016)
// ---------------------------------------------------------------------------

/// A cached runtime for a specific file type, ready to be reused across
/// multiple file scans.
///
/// The runtime has the framework loaded (globals + init + read include +
/// type init). To scan a new file, call `register_host_api` with the new
/// file's host, then `reinit` to update host aliases, then evaluate rules.
struct CachedRuntime {
    /// The QuickJS runtime with framework already loaded.
    runtime: RquickjsRuntime,
}

/// A stateful scanner that reuses rule runtimes across files of the same
/// file type.
///
/// The free function [`scan_bytes`] creates a new runtime for each file
/// type group on every call. `Scanner` instead caches one runtime per file
/// type and reuses it for subsequent files, avoiding the cost of runtime
/// creation and framework loading (ADR 0016).
///
/// **Safety**: the framework's `result()` function resets global detection
/// variables (`bDetected`, `sName`, `sVersion`, etc.) after each rule.
/// Rule-specific bare assignments are low risk because they are initialized
/// before use within each rule's `detect()` function. See
/// `docs/research/runtime-reuse-state-audit.md` for the full audit.
///
/// If a runtime encounters an error (OOM, uncaught exception), it is
/// evicted from the cache and a fresh one is created for the next file.
///
/// `Scanner` is not `Send` because `RquickjsRuntime` is not `Send` (QuickJS
/// contexts are thread-local). For multi-threaded use (e.g. the server
/// layer), each worker thread should own its own `Scanner`.
pub struct Scanner {
    /// The immutable database shared across all scans.
    database: Arc<Database>,
    /// Cached runtimes keyed by file type (e.g. "PE", "ELF", "Binary").
    cache: BTreeMap<String, CachedRuntime>,
}

impl Scanner {
    /// Create a new `Scanner` with the given database.
    ///
    /// The database is wrapped in `Arc` for sharing. Runtimes are created
    /// lazily on the first scan of each file type.
    pub fn new(database: Arc<Database>) -> Self {
        Self {
            database,
            cache: BTreeMap::new(),
        }
    }

    /// Clear all cached runtimes, forcing fresh runtime creation on the
    /// next scan.
    ///
    /// Call this after a database reload or when memory usage from cached
    /// runtimes needs to be reclaimed.
    pub fn reset(&mut self) {
        self.cache.clear();
    }

    /// Scan a single file by path, reusing cached runtimes.
    ///
    /// This is the stateful equivalent of [`scan_once`]. It reads the file
    /// from disk and delegates to [`Scanner::scan_bytes`].
    pub fn scan_file(
        &mut self,
        path: &str,
        flags: crate::host::ScanFlags,
        cancel: &CancellationToken,
    ) -> Result<ScanResult, ScanError> {
        let data = std::fs::read(path).map_err(|e| ScanError::Input {
            path: path.to_string(),
            detail: e.to_string(),
        })?;
        self.scan_bytes(path, data, flags, cancel)
    }

    /// Scan a byte buffer, reusing cached runtimes.
    ///
    /// This is the stateful equivalent of [`scan_bytes`]. The detection
    /// logic is identical; the only difference is that runtimes are cached
    /// per file type and reused across calls.
    pub fn scan_bytes(
        &mut self,
        file_name: &str,
        data: Vec<u8>,
        flags: crate::host::ScanFlags,
        cancel: &CancellationToken,
    ) -> Result<ScanResult, ScanError> {
        let snapshot = self.database.snapshot();
        let mut detections = Vec::new();
        let mut diagnostics = Vec::new();
        let mut structured_diagnostics: Vec<Diagnostic> = Vec::new();
        let mut profiling: Vec<SignatureProfile> = Vec::new();

        // Detect the file format to determine which rule types to run.
        // With --alltypes, detected format + compatible parent types are run.
        // With file_type override, only the specified type's rules are run.
        let active_types: Vec<&str> = if let Some(ref ft) = flags.file_type {
            vec![ft.as_str()]
        } else if flags.all_types {
            alltypes_rule_types(&data, file_name)
        } else {
            detect_rule_types(&data, file_name)
        };

        // Group rules by file type.
        let mut groups: BTreeMap<&str, Vec<&LoadedRule>> = BTreeMap::new();
        for rule in &snapshot.rules {
            if active_types.contains(&rule.file_type.as_str()) {
                groups.entry(&rule.file_type).or_default().push(rule);
            }
        }

        // Process each file type group.
        for (file_type, rules) in &groups {
            if cancel.is_cancelled() {
                return Err(ScanError::Cancelled);
            }

            // Try to get a cached runtime for this file type, or create one.
            let need_create = !self.cache.contains_key(*file_type);

            if need_create {
                let runtime = match self.create_runtime_for_type(snapshot, file_type) {
                    Ok(rt) => rt,
                    Err(e) => {
                        diagnostics.push(format!("runtime create error for {file_type}: {e}"));
                        continue;
                    }
                };
                self.cache
                    .insert(file_type.to_string(), CachedRuntime { runtime });
            }

            // Get the cached runtime (mutable).
            let cached = self
                .cache
                .get_mut(*file_type)
                .expect("just inserted or existed");

            // Register the new file's host API, overwriting the previous one.
            let host = Arc::new(
                BufferHost::new(data.clone(), file_name.to_string()).with_flags(flags.clone()),
            );
            if let Err(e) = cached.runtime.register_host_api(host.clone()) {
                diagnostics.push(format!("host API error for {file_type}: {e}"));
                // Evict the broken runtime so next scan creates a fresh one.
                self.cache.remove(*file_type);
                continue;
            }

            // Re-run type init scripts to update host aliases
            // (e.g. `var File = PE; var X = PE;`).
            if let Err(e) = cached.runtime.reinit() {
                diagnostics.push(format!("reinit error for {file_type}: {e}"));
                self.cache.remove(*file_type);
                continue;
            }

            // Evaluate each rule in an isolated scope over a shared result
            // list, matching upstream `m_pListScanStructs` semantics so that
            // `_isResultPresent`/`_removeResult` see prior rules' records.
            if let Err(e) = cached.runtime.begin_result_group() {
                diagnostics.push(format!("result group reset error for {file_type}: {e}"));
                self.cache.remove(*file_type);
                continue;
            }
            let mut runtime_error = false;
            for rule in rules {
                if cancel.is_cancelled() {
                    return Err(ScanError::Cancelled);
                }

                let start = std::time::Instant::now();
                match cached
                    .runtime
                    .evaluate_rule_in_group(&rule.path, &rule.source, cancel)
                {
                    Ok(()) => {}
                    Err(e) => {
                        let msg = format!("{}: {}", rule.path, e);
                        diagnostics.push(msg.clone());
                        structured_diagnostics.push(Diagnostic {
                            file: rule.path.clone(),
                            line: None,
                            message: e.to_string(),
                            kind: "error".to_string(),
                        });
                        // A script exception does not corrupt the runtime;
                        // continue with the next rule. Only OOM/limit errors
                        // require eviction (checked below).
                        if matches!(e, diec_rules::error::RuleError::BudgetExceeded { .. }) {
                            runtime_error = true;
                            profiling.push(SignatureProfile {
                                file: rule.path.clone(),
                                elapsed_ms: start.elapsed().as_millis() as u64,
                            });
                            break;
                        }
                    }
                }
                // Non-fatal rule diagnostics (upstream PDSTRUCT error list)
                // are attributed to the rule that produced them.
                for msg in host.drain_scan_errors() {
                    diagnostics.push(format!("{}: {}", rule.path, msg));
                }
                profiling.push(SignatureProfile {
                    file: rule.path.clone(),
                    elapsed_ms: start.elapsed().as_millis() as u64,
                });
            }

            // Emit the group's surviving results once, attributed by the
            // rule stamp so records removed by `_removeResult` are excluded.
            match cached.runtime.read_results() {
                Ok(results) => {
                    for result in results {
                        let rule_path = result.rule_path.clone();
                        detections.push(detection_from_result(file_type, &rule_path, result));
                    }
                }
                Err(e) => diagnostics.push(format!("read results error for {file_type}: {e}")),
            }

            // If the runtime hit a budget limit, evict it.
            if runtime_error {
                self.cache.remove(*file_type);
            }
        }

        // Apply --hideunknown filter.
        if flags.hide_unknown {
            detections.retain(|d| !d.name.is_empty() && d.name != "Unknown");
        }

        // Apply result deduplication (ADR 0027). Default: dedup on.
        // --no-dedup disables it to match upstream behavior.
        if !flags.no_dedup {
            dedup_detections(&mut detections);
        }

        // Intra-file recursive scanning (ADR 0028): if recursive/resources/overlays
        // flag is set and the file is a PE, extract resources and overlay and
        // recursively scan each as a sub-device.
        if (flags.recursive || flags.resources || flags.overlays)
            && diec_rules::pe_native::is_pe(&data)
        {
            let nested_detections = self.scan_nested_pe_inline(file_name, &data, &flags, cancel)?;
            detections.extend(nested_detections);
        }

        // Archive member recursive scanning (ADR 0030): if archives flag is set
        // and the file is a supported archive, extract members and recursively
        // scan each.
        if flags.archives && crate::archive_unpack::is_archive(&data) {
            let archive_detections =
                self.scan_archive_members_inline(file_name, &data, &flags, cancel)?;
            detections.extend(archive_detections);
        }

        // NFD/SpecAbstract second engine (--nfd / GUI engine selector).
        // Its records are appended after the DIE results and carry the
        // `engine = "nfd"` marker. See ADR 0035.
        if flags.nfd {
            run_nfd_pass(&data, file_name, &flags, &mut detections);
        }

        // Add "Unknown" placeholder when no detections were found.
        // Matches upstream XScanEngine::_processDetect with bAddUnknown=true.
        if detections.is_empty() && !flags.hide_unknown {
            let unknown_ft = active_types
                .first()
                .map(|s| s.to_string())
                .unwrap_or_default();
            detections.push(ScanDetection {
                file_type: unknown_ft,
                type_name: "unknown".to_string(),
                name: "Unknown".to_string(),
                version: None,
                options: None,
                signature_path: None,
                parent_id: None,
                id: None,
                file_part: None,
                offset: None,
                size: None,
                is_heuristic: None,
                is_a_heuristic: None,
                original_name: None,
                engine: None,
            });
        }

        Ok(ScanResult {
            path: file_name.to_string(),
            detections,
            diagnostics,
            structured_diagnostics,
            profiling,
        })
    }

    /// Inline nested PE scanner for `Scanner::scan_bytes`.
    ///
    /// Creates a closure that calls `self.scan_bytes` recursively with
    /// `recursive` disabled to prevent infinite loops.
    fn scan_nested_pe_inline(
        &mut self,
        file_name: &str,
        data: &[u8],
        flags: &crate::host::ScanFlags,
        cancel: &CancellationToken,
    ) -> Result<Vec<ScanDetection>, ScanError> {
        // We can't capture `self` in a closure that also calls `self.scan_bytes`
        // due to borrow checker constraints. Instead, we extract the parts
        // directly here and scan each one.
        let parts = crate::nested_scan::extract_nested_parts(data, flags);
        let mut nested_detections = Vec::new();

        for part in parts {
            if cancel.is_cancelled() {
                return Err(ScanError::Cancelled);
            }
            if part.data.is_empty() {
                continue;
            }

            let part_name = format!("{file_name}:{}({})", part.part_type, part.name);
            let child_flags = crate::host::ScanFlags {
                recursive: false,
                resources: false,
                overlays: false,
                nfd: false,
                ..flags.clone()
            };

            match self.scan_bytes(&part_name, part.data, child_flags, cancel) {
                Ok(sub_result) => {
                    for mut det in sub_result.detections {
                        det.file_part = Some(part.part_type.to_string());
                        nested_detections.push(det);
                    }
                }
                Err(ScanError::Cancelled) => return Err(ScanError::Cancelled),
                Err(_) => {
                    // Skip failed nested scans.
                }
            }
        }

        Ok(nested_detections)
    }

    /// Inline archive member scanner for `Scanner::scan_bytes`.
    ///
    /// Extracts archive members and recursively scans each as a sub-device.
    fn scan_archive_members_inline(
        &mut self,
        file_name: &str,
        data: &[u8],
        flags: &crate::host::ScanFlags,
        cancel: &CancellationToken,
    ) -> Result<Vec<ScanDetection>, ScanError> {
        let members = crate::archive_unpack::extract_archive(data, flags);
        let mut nested_detections = Vec::new();

        for member in members {
            if cancel.is_cancelled() {
                return Err(ScanError::Cancelled);
            }
            if member.data.is_empty() {
                continue;
            }

            // Upstream `XScanEngine::isScanable` gate: archive members
            // are scanned only when they sniff as an executable or
            // structured format; plain text and data members are
            // skipped entirely.
            if !diec_nfd::is_scanable_ft(diec_nfd::sniff_ft(&member.data)) {
                continue;
            }

            let member_name = format!("{file_name}:Archive({})", member.name);
            let child_flags = crate::host::ScanFlags {
                recursive: false,
                resources: false,
                overlays: false,
                archives: false,
                nfd: false,
                ..flags.clone()
            };

            match self.scan_bytes(&member_name, member.data, child_flags, cancel) {
                Ok(sub_result) => {
                    for mut det in sub_result.detections {
                        det.file_part = Some("Archive".to_string());
                        nested_detections.push(det);
                    }
                }
                Err(ScanError::Cancelled) => return Err(ScanError::Cancelled),
                Err(_) => {
                    // Skip failed nested scans.
                }
            }
        }

        Ok(nested_detections)
    }

    /// Create a new runtime for a file type, load the framework, and
    /// initialize it with a placeholder host.
    ///
    /// The host API is registered later by the caller (before `reinit`).
    /// However, `init()` requires a host to be registered first. We
    /// register a dummy host here, then the caller overwrites it.
    fn create_runtime_for_type(
        &self,
        snapshot: &DatabaseSnapshot,
        file_type: &str,
    ) -> Result<RquickjsRuntime, ScanError> {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).map_err(|e| {
            ScanError::DatabaseInit {
                detail: e.to_string(),
            }
        })?;

        // Load the framework (init + type init + includes) with no rules.
        let type_init: Vec<(String, String)> = snapshot
            .type_init_scripts
            .iter()
            .filter(|(ft, _)| ft == file_type)
            .cloned()
            .collect();
        let framework_snapshot = DatabaseSnapshot {
            rules: Vec::new(),
            init_script: snapshot.init_script.clone(),
            type_init_scripts: type_init,
            include_scripts: snapshot.include_scripts.clone(),
        };

        runtime
            .load_database(&framework_snapshot)
            .map_err(|e| ScanError::DatabaseInit {
                detail: e.to_string(),
            })?;

        // Register a placeholder host so init() can run type_init scripts
        // that reference host objects (e.g. `var File = Binary;`).
        // The caller will overwrite this with the real file's host.
        let dummy_host = Arc::new(
            BufferHost::new(Vec::new(), "__init__".to_string())
                .with_flags(crate::host::ScanFlags::default()),
        );
        runtime
            .register_host_api(dummy_host.clone())
            .map_err(|e| ScanError::HostApi {
                detail: e.to_string(),
            })?;

        let host_ref: &dyn diec_rules::host_api::HostApi = &*dummy_host;
        runtime
            .init(host_ref)
            .map_err(|e| ScanError::DatabaseInit {
                detail: e.to_string(),
            })?;

        Ok(runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DatabaseBuilder;

    fn db_root() -> String {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let root = std::path::Path::new(manifest)
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root");
        root.join("upstream/Detect-It-Easy/db")
            .to_str()
            .expect("utf-8 path")
            .to_string()
    }

    #[test]
    fn scan_7z_signature() {
        let db_path = db_root();
        let database = match DatabaseBuilder::new(&db_path).build() {
            Ok(db) => db,
            Err(_) => {
                eprintln!("Skipping: upstream database not found");
                return;
            }
        };

        // 7z magic: 37 7A BC AF 27 1C + version bytes
        let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
        data.resize(64, 0);

        let cancel = CancellationToken::new();
        let result = scan_bytes(
            &database,
            "test.7z",
            data,
            crate::host::ScanFlags::default(),
            &cancel,
        )
        .unwrap();

        let found = result.detections.iter().any(|d| d.name == "7-Zip");
        assert!(
            found,
            "Expected 7-Zip detection, got: {:?}",
            result.detections
        );
    }

    #[test]
    fn scan_bzip_signature() {
        let db_path = db_root();
        let database = match DatabaseBuilder::new(&db_path).build() {
            Ok(db) => db,
            Err(_) => {
                eprintln!("Skipping: upstream database not found");
                return;
            }
        };

        // BZip2 magic: "BZh" + level digit + block magic 314159265359
        let mut data = b"BZh9".to_vec();
        data.extend_from_slice(&[0x31, 0x41, 0x59, 0x26, 0x53, 0x59]);
        data.resize(64, 0);

        let cancel = CancellationToken::new();
        let result = scan_bytes(
            &database,
            "test.bz2",
            data,
            crate::host::ScanFlags::default(),
            &cancel,
        )
        .unwrap();

        let found = result
            .detections
            .iter()
            .any(|d| d.name.contains("BZip") || d.name.contains("bzip"));
        assert!(
            found,
            "Expected BZip detection, got: {:?}",
            result.detections
        );
    }

    #[test]
    fn scan_random_data_no_false_positive() {
        let db_path = db_root();
        let database = match DatabaseBuilder::new(&db_path).build() {
            Ok(db) => db,
            Err(_) => {
                eprintln!("Skipping: upstream database not found");
                return;
            }
        };

        // Random data that shouldn't match any specific format.
        let data: Vec<u8> = (0..128).map(|i| (i * 7 + 13) as u8).collect();

        let cancel = CancellationToken::new();
        let result = scan_bytes(
            &database,
            "random.bin",
            data,
            crate::host::ScanFlags::default(),
            &cancel,
        )
        .unwrap();

        // Random data should not produce specific format detections.
        let has_specific = result
            .detections
            .iter()
            .any(|d| d.name == "7-Zip" || d.name == "GZIP" || d.name == "BZip");
        assert!(
            !has_specific,
            "Random data should not produce specific detections: {:?}",
            result.detections
        );
    }

    #[test]
    fn scan_jpeg_signature() {
        let db_path = db_root();
        let database = match DatabaseBuilder::new(&db_path).build() {
            Ok(db) => db,
            Err(_) => {
                eprintln!("Skipping: upstream database not found");
                return;
            }
        };

        // JPEG magic: FF D8 FF E0 + JFIF
        let mut data = vec![
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00,
        ];
        data.resize(64, 0);

        let cancel = CancellationToken::new();
        let result = scan_bytes(
            &database,
            "test.jpg",
            data,
            crate::host::ScanFlags::default(),
            &cancel,
        )
        .unwrap();

        let found = result
            .detections
            .iter()
            .any(|d| d.name.contains("JPEG") || d.name.contains("jpeg"));
        assert!(
            found,
            "Expected JPEG detection, got: {:?}",
            result.detections
        );
    }

    #[test]
    fn scan_rar_signature() {
        let db_path = db_root();
        let database = match DatabaseBuilder::new(&db_path).build() {
            Ok(db) => db,
            Err(_) => {
                eprintln!("Skipping: upstream database not found");
                return;
            }
        };

        // RAR v4 signature: Rar!\x1a\x07\x00 + MAIN_HEAD (needs >= 64 bytes
        // for the Binary archive_RAR rule's nSize check). The header chain
        // is intentionally incomplete (no ENDARC), so upstream
        // XRar::isValid rejects it and the file falls back to the Binary
        // group — where archive_RAR.1.sg still fires on the marker.
        // Upstream oracle: Binary / archive: RAR (4).
        let mut data: Vec<u8> = vec![
            0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00, 0xCF, 0x90, 0x73, 0x00, 0x00, 0x0D, 0x00,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        ];
        data.resize(64, 0);

        let cancel = CancellationToken::new();
        let result = scan_bytes(
            &database,
            "test.rar",
            data,
            crate::host::ScanFlags::default(),
            &cancel,
        )
        .unwrap();

        let found = result
            .detections
            .iter()
            .any(|d| d.file_type == "Binary" && d.name == "RAR");
        assert!(
            found,
            "Expected Binary archive RAR detection, got: {:?}",
            result.detections
        );
    }

    #[test]
    fn detect_rule_types_elf() {
        let elf_header: Vec<u8> = vec![
            0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let types = detect_rule_types(&elf_header, "test.elf");
        assert!(
            types.contains(&"ELF"),
            "Expected ELF in detected types, got: {:?}",
            types
        );
        // ELF is an executable format — Binary rules should NOT run.
        assert!(
            !types.contains(&"Binary"),
            "Binary should not be included for ELF files, got: {:?}",
            types
        );
    }

    #[test]
    fn alltypes_rule_types_elf_no_false_positive() {
        // Regression test for Phase 14.3: --alltypes must NOT run all 18
        // format rule sets blindly. An ELF file should only run ELF rules
        // (no PE/JPEG/PDF/PNG/CFBF/DEX false positives).
        let elf_header: Vec<u8> = vec![
            0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let types = alltypes_rule_types(&elf_header, "test.elf");
        assert!(types.contains(&"ELF"), "ELF must be in --alltypes types");
        // Unrelated formats must NOT appear.
        for bad in [
            "PE",
            "JPEG",
            "PDF",
            "PNG",
            "CFBF",
            "DEX",
            "MACH",
            "JavaClass",
        ] {
            assert!(
                !types.contains(&bad),
                "{bad} should not be in --alltypes for ELF, got: {:?}",
                types
            );
        }
    }

    #[test]
    fn alltypes_rule_types_pe_includes_msdos() {
        // --alltypes for PE should include PE + MSDOS (PE contains DOS stub).
        let pe_header: Vec<u8> = {
            let mut h = vec![0x4D, 0x5A]; // MZ
            h.resize(0x80, 0); // DOS header
            // e_lfanew at 0x3C -> 0x80
            h[0x3C] = 0x80;
            h[0x3D] = 0x00;
            h[0x3E] = 0x00;
            h[0x3F] = 0x00;
            // PE signature at 0x80
            h.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]);
            // COFF header (machine = 0x14C = i386)
            h.extend_from_slice(&[
                0x4C, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);
            // Optional header magic 0x10B = PE32
            h.extend_from_slice(&[0x0B, 0x01]);
            h.resize(0x200, 0);
            h
        };

        let types = alltypes_rule_types(&pe_header, "test.exe");
        assert!(types.contains(&"PE"), "PE must be in --alltypes types");
        assert!(
            types.contains(&"MSDOS"),
            "MSDOS must be in --alltypes for PE (parent type), got: {:?}",
            types
        );
        // Unrelated formats must NOT appear.
        for bad in ["ELF", "MACH", "JPEG", "PDF", "PNG", "DEX"] {
            assert!(
                !types.contains(&bad),
                "{bad} should not be in --alltypes for PE, got: {:?}",
                types
            );
        }
    }

    #[test]
    fn detect_rule_types_macho_fat() {
        // Mach-O FAT magic is CAFEBABE — same as Java Class File.
        // Binary rules must NOT run to avoid false positive.
        // Structurally valid FAT header: nfat=1 plus one arch record whose
        // offset/size fall inside the file.
        let mut macho_fat_header: Vec<u8> = vec![0xCA, 0xFE, 0xBA, 0xBE];
        macho_fat_header.extend_from_slice(&1u32.to_be_bytes()); // nfat_arch
        macho_fat_header.extend_from_slice(&7u32.to_be_bytes()); // cputype = x86
        macho_fat_header.extend_from_slice(&3u32.to_be_bytes()); // cpusubtype
        macho_fat_header.extend_from_slice(&48u32.to_be_bytes()); // offset
        macho_fat_header.extend_from_slice(&4u32.to_be_bytes()); // size
        macho_fat_header.extend_from_slice(&0u32.to_be_bytes()); // align
        macho_fat_header.resize(52, 0);

        let types = detect_rule_types(&macho_fat_header, "test.bin");
        assert!(
            types.contains(&"MACHOFAT"),
            "Expected MACHOFAT in detected types, got: {:?}",
            types
        );
        // Binary rules should NOT run for Mach-O FAT to avoid
        // false positive Java Class File detection (CAFEBABE ambiguity).
        assert!(
            !types.contains(&"Binary"),
            "Binary should not be included for Mach-O FAT files, got: {:?}",
            types
        );
    }

    #[test]
    fn detect_rule_types_jpeg_excludes_binary() {
        // JPEG is a non-executable format — only JPEG rules should run,
        // not Binary rules (to avoid duplicate detections from
        // Binary/image_jpeg.1.sg and JPEG/format_jpeg.1.sg).
        // Upstream XJpeg::isValid requires a complete SOI..EOI marker
        // chain, so the fixture must be a structurally complete JPEG.
        let jpeg_header: Vec<u8> = {
            let mut d = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
            d.extend_from_slice(b"JFIF\0");
            d.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
            d.extend_from_slice(&[0xFF, 0xD9]);
            d
        };

        let types = detect_rule_types(&jpeg_header, "test.jpg");
        assert!(
            types.contains(&"JPEG"),
            "Expected JPEG in detected types, got: {:?}",
            types
        );
        assert!(
            !types.contains(&"Binary"),
            "Binary should NOT be included for JPEG files, got: {:?}",
            types
        );
    }

    // --- Scanner (ADR 0016) tests ---

    /// Helper: build a database or skip the test if upstream db is missing.
    fn build_db() -> Option<Database> {
        let db_path = db_root();
        match DatabaseBuilder::new(&db_path).build() {
            Ok(db) => Some(db),
            Err(_) => {
                eprintln!("Skipping: upstream database not found");
                None
            }
        }
    }

    /// Test data samples for differential testing: each sample targets a
    /// different file type to exercise different runtime caches.
    fn differential_samples() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            // 7z archive (Binary rules)
            ("test.7z", {
                let mut d = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
                d.resize(64, 0);
                d
            }),
            // JPEG image (JPEG rules)
            ("test.jpg", {
                let mut d = vec![
                    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00,
                ];
                d.resize(64, 0);
                d
            }),
            // RAR archive (Binary rules)
            ("test.rar", {
                let mut d: Vec<u8> = vec![
                    0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00, 0xCF, 0x90, 0x73, 0x00, 0x00, 0x0D,
                    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                ];
                d.resize(64, 0);
                d
            }),
            // Random data (Binary rules, no detection expected)
            ("random.bin", (0..128).map(|i| (i * 7 + 13) as u8).collect()),
        ]
    }

    #[test]
    fn scanner_differential_reuse_vs_no_reuse() {
        let database = match build_db() {
            Some(db) => db,
            None => return,
        };
        let database = Arc::new(database);
        let cancel = CancellationToken::new();
        let flags = crate::host::ScanFlags::default();

        // Scan all samples with the free function (no reuse, fresh runtime
        // per file per file_type).
        let mut baseline_results: Vec<(String, ScanResult)> = Vec::new();
        for (name, data) in differential_samples() {
            let result = scan_bytes(&database, name, data.clone(), flags.clone(), &cancel)
                .expect("scan_bytes should not fail");
            baseline_results.push((name.to_string(), result));
        }

        // Scan the same samples with Scanner (runtime reuse across files).
        let mut scanner = Scanner::new(database.clone());
        for (name, data) in differential_samples() {
            let result = scanner
                .scan_bytes(name, data.clone(), flags.clone(), &cancel)
                .expect("Scanner::scan_bytes should not fail");
            // Find the baseline result for this sample.
            let baseline = baseline_results
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, r)| r)
                .expect("baseline result should exist");

            // The detections must match exactly.
            assert_eq!(
                result.detections, baseline.detections,
                "Scanner (reuse) vs scan_bytes (no reuse) mismatch for '{name}':\n\
                 reuse:     {:?}\n\
                 no-reuse:  {:?}",
                result.detections, baseline.detections
            );
        }
    }

    #[test]
    fn scanner_differential_same_file_twice() {
        // Scanning the same file twice with a reused runtime should produce
        // identical results. This verifies that stale global state from the
        // first scan does not affect the second.
        let database = match build_db() {
            Some(db) => db,
            None => return,
        };
        let database = Arc::new(database);
        let cancel = CancellationToken::new();
        let flags = crate::host::ScanFlags::default();

        let mut scanner = Scanner::new(database);

        // Scan a 7z file twice.
        let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
        data.resize(64, 0);

        let result1 = scanner
            .scan_bytes("test.7z", data.clone(), flags.clone(), &cancel)
            .unwrap();
        let result2 = scanner
            .scan_bytes("test.7z", data.clone(), flags.clone(), &cancel)
            .unwrap();

        assert_eq!(
            result1.detections, result2.detections,
            "Scanning the same file twice should produce identical results:\n\
             first:  {:?}\n\
             second: {:?}",
            result1.detections, result2.detections
        );
    }

    #[test]
    fn scanner_differential_multiple_formats_sequence() {
        // Scan files of different formats in sequence to verify that
        // switching between file types (and thus different runtime caches)
        // does not cause cross-contamination.
        let database = match build_db() {
            Some(db) => db,
            None => return,
        };
        let database = Arc::new(database);
        let cancel = CancellationToken::new();
        let flags = crate::host::ScanFlags::default();

        let samples = differential_samples();

        // Baseline: no reuse.
        let mut baseline: Vec<(String, ScanResult)> = Vec::new();
        for (name, data) in &samples {
            let r = scan_bytes(&database, name, data.clone(), flags.clone(), &cancel).unwrap();
            baseline.push((name.to_string(), r));
        }

        // Scanner: reuse, scan in the same order.
        let mut scanner = Scanner::new(database.clone());
        for (name, data) in &samples {
            let r = scanner
                .scan_bytes(name, data.clone(), flags.clone(), &cancel)
                .unwrap();
            let b = baseline
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, r)| r)
                .unwrap();
            assert_eq!(
                r.detections, b.detections,
                "Mismatch for '{name}' in multi-format sequence"
            );
        }

        // Scan again in REVERSE order to catch any order-dependent state.
        for (name, data) in samples.iter().rev() {
            let r = scanner
                .scan_bytes(name, data.clone(), flags.clone(), &cancel)
                .unwrap();
            let b = baseline
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, r)| r)
                .unwrap();
            assert_eq!(
                r.detections, b.detections,
                "Mismatch for '{name}' in reverse-order scan (order-dependent state leak)"
            );
        }
    }

    #[test]
    fn scanner_reset_clears_cache() {
        let database = match build_db() {
            Some(db) => db,
            None => return,
        };
        let database = Arc::new(database);
        let cancel = CancellationToken::new();
        let flags = crate::host::ScanFlags::default();

        let mut scanner = Scanner::new(database);

        // Scan a file to populate the cache.
        let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
        data.resize(64, 0);
        let _ = scanner
            .scan_bytes("test.7z", data.clone(), flags.clone(), &cancel)
            .unwrap();

        // Reset should clear the cache (no panic, no error).
        scanner.reset();

        // Scanning after reset should work (creates fresh runtime).
        let result = scanner.scan_bytes("test.7z", data, flags, &cancel).unwrap();
        let found = result.detections.iter().any(|d| d.name == "7-Zip");
        assert!(found, "Expected 7-Zip detection after reset");
    }

    /// Standalone NFD pass (GUI NFD view): records carry the `"nfd"`
    /// engine marker and reproduce the NFD-side detections the merged
    /// scan would append.
    #[test]
    fn nfd_scan_standalone_marks_engine() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let root = std::path::Path::new(manifest)
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root");
        let fixture = root.join("corpus/enigmavb-minimal.exe");
        let data = std::fs::read(&fixture).expect("corpus fixture");
        let name = fixture.file_name().unwrap().to_str().unwrap();

        let recs = nfd_scan(&data, name, true, true, false);
        assert!(!recs.is_empty());
        assert!(recs.iter().all(|r| r.engine.as_deref() == Some("nfd")));
        // The fixture's `.enigma1/.enigma2` sections must surface the
        // Enigma Virtual Box protector record (case-sensitive section
        // names — regression for the Phase 28 casing fix).
        assert!(
            recs.iter().any(|r| r.name == "Enigma Virtual Box"),
            "missing Enigma Virtual Box record: {recs:?}"
        );
    }
}

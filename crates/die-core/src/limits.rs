//! Resource limit contracts for scan, script runtime, database load and
//! traversal.
//!
//! Every field has a non-zero safe hard maximum. Callers may lower a limit
//! but never exceed the compile/release policy ceiling. `Duration::ZERO` means
//! "use project default", not "unlimited"; disabling a soft deadline requires
//! an explicit enum, while hard allocation, depth and integer limits always
//! exist. Implementation must never fall back to `0` or integer maximum as an
//! unbounded value (see `docs/design/api.md` section 8 and ADR 0012).
//!
//! The numeric defaults in [`ScanLimits::skeleton_default`] and
//! [`ScriptLimits::skeleton_default`] mirror the ADR 0012 review candidates.
//! They are finite and non-zero but are **not yet admitted production
//! defaults**; they are placeholders that keep the skeleton bounded until the
//! resource-limit policy is admitted.

use std::time::Duration;

/// The kind of resource limit that was reached. Each variant maps to a
/// `ScanLimits`/`ScriptLimits`/`DatabaseLimits`/`TraversalLimits` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    /// Scan wall-clock timeout (`ScanLimits::timeout`).
    Timeout,
    /// Root input logical length (`ScanLimits::max_input_bytes`).
    InputBytes,
    /// Cumulative read/mapped bytes (`ScanLimits::max_total_read_bytes`).
    TotalReadBytes,
    /// Cumulative decompressed bytes (`ScanLimits::max_total_decompressed_bytes`).
    TotalDecompressedBytes,
    /// Single allocation capacity (`ScanLimits::max_single_allocation_bytes`).
    SingleAllocation,
    /// Cumulative scan-owned allocation capacity (`ScanLimits::max_total_allocation_bytes`).
    TotalAllocation,
    /// Result node count (`ScanLimits::max_nodes`).
    Nodes,
    /// Typed diagnostic count (`ScanLimits::max_diagnostics`).
    Diagnostics,
    /// Archive entry count (`ScanLimits::max_archive_entries`).
    ArchiveEntries,
    /// Nested scan depth (`ScanLimits::max_depth`).
    Depth,
    /// Work queue length (`ScanLimits::max_queue_items`).
    QueueItems,
    /// Script runtime VM heap (`ScriptLimits::max_heap_bytes`).
    ScriptHeap,
    /// Script VM stack (`ScriptLimits::max_stack_bytes`).
    ScriptStack,
    /// Script fuel/instruction quanta (`ScriptLimits::max_fuel_quanta`).
    ScriptFuel,
    /// Script runtime deadline (`ScriptLimits::runtime_deadline`).
    ScriptDeadline,
}

/// A structured record produced when a hard limit is reached. It does not
/// occupy a diagnostic slot; `Completion::Limited` carries it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitReached {
    /// Which limit was reached.
    pub kind: LimitKind,
    /// The configured limit value.
    pub configured: u64,
    /// The observed or requested value that exceeded the limit.
    pub observed: u64,
}

/// Scan-wide cumulative resource budget. Child work does not reset any field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    /// Scan wall-clock timeout. `Duration::ZERO` means project default.
    pub timeout: Duration,
    /// Root source stable logical length ceiling.
    pub max_input_bytes: u64,
    /// Cumulative read/re-read/exposed mapped bytes.
    pub max_total_read_bytes: u64,
    /// Cumulative decompressed bytes.
    pub max_total_decompressed_bytes: u64,
    /// Single allocation capacity ceiling.
    pub max_single_allocation_bytes: u64,
    /// Cumulative scan-owned allocation capacity.
    pub max_total_allocation_bytes: u64,
    /// Maximum result node count.
    pub max_nodes: u64,
    /// Maximum typed diagnostic count.
    pub max_diagnostics: u64,
    /// Maximum archive entry count.
    pub max_archive_entries: u64,
    /// Maximum nested scan depth.
    pub max_depth: u32,
    /// Maximum work queue length.
    pub max_queue_items: u64,
    /// Script runtime limits.
    pub script: ScriptLimits,
}

impl ScanLimits {
    /// Skeleton defaults mirroring the ADR 0012 review candidates. Finite and
    /// non-zero, but **not an admitted production default**.
    pub fn skeleton_default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_input_bytes: 1024 * 1024 * 1024, // 1 GiB
            max_total_read_bytes: 1024 * 1024 * 1024,
            max_total_decompressed_bytes: 512 * 1024 * 1024,
            max_single_allocation_bytes: 128 * 1024 * 1024,
            max_total_allocation_bytes: 1024 * 1024 * 1024,
            max_nodes: 4096,
            max_diagnostics: 4096,
            max_archive_entries: 4096,
            max_depth: 32,
            max_queue_items: 4096,
            script: ScriptLimits::skeleton_default(),
        }
    }
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self::skeleton_default()
    }
}

/// Script runtime limits. The fuel unit is a project-level VM interrupt poll
/// quantum or native HostApi cooperative checkpoint, not a QuickJS-internal
/// counter. Global/type init, include, rule, child and exception recovery
/// never reset fuel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptLimits {
    /// Per-scan live VM allocator limit.
    pub max_heap_bytes: u64,
    /// JS VM stack limit.
    pub max_stack_bytes: u64,
    /// Cumulative fuel/instruction quanta.
    pub max_fuel_quanta: u64,
    /// Absolute cumulative script deadline.
    pub runtime_deadline: Duration,
}

impl ScriptLimits {
    /// Skeleton defaults mirroring the modern review candidates. Finite and
    /// non-zero, but **not an admitted production default**.
    pub fn skeleton_default() -> Self {
        Self {
            max_heap_bytes: 32 * 1024 * 1024,
            max_stack_bytes: 512 * 1024,
            max_fuel_quanta: 131_072,
            runtime_deadline: Duration::from_secs(10),
        }
    }
}

impl Default for ScriptLimits {
    fn default() -> Self {
        Self::skeleton_default()
    }
}

/// Database load budget, independent from scan budget because database sources
/// are untrusted directories, archives, embedded bundles or caches loaded
/// before a scanner exists. directory, ZIP, embedded, cache hit and fallback
/// share one cumulative budget; fallback never resets consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatabaseLimits {
    /// Maximum number of database sources.
    pub max_sources: u32,
    /// Maximum total rule entries.
    pub max_entries: u64,
    /// Maximum single entry byte length.
    pub max_single_entry_bytes: u64,
    /// Maximum cumulative entry byte length.
    pub max_total_entry_bytes: u64,
    /// Maximum single container byte length.
    pub max_single_container_bytes: u64,
    /// Maximum cumulative container byte length.
    pub max_total_container_bytes: u64,
    /// Maximum single UTF-8 logical path byte length.
    pub max_single_logical_path_bytes: u32,
    /// Maximum cumulative UTF-8 logical path byte length.
    pub max_total_logical_path_bytes: u64,
    /// Maximum derived cache byte size.
    pub max_cache_bytes: u64,
    /// Maximum derived cache record count.
    pub max_cache_records: u64,
}

impl DatabaseLimits {
    /// Skeleton defaults. Finite and non-zero, but **not an admitted production
    /// default**.
    pub fn skeleton_default() -> Self {
        Self {
            max_sources: 16,
            max_entries: 1_000_000,
            max_single_entry_bytes: 8 * 1024 * 1024,
            max_total_entry_bytes: 512 * 1024 * 1024,
            max_single_container_bytes: 256 * 1024 * 1024,
            max_total_container_bytes: 1024 * 1024 * 1024,
            max_single_logical_path_bytes: 4096,
            max_total_logical_path_bytes: 64 * 1024 * 1024,
            max_cache_bytes: 512 * 1024 * 1024,
            max_cache_records: 1_000_000,
        }
    }
}

impl Default for DatabaseLimits {
    fn default() -> Self {
        Self::skeleton_default()
    }
}

/// Traversal budget for batch/directory expansion, independent from scan
/// budget. Each metadata/type/identity/read-link query or handle
/// acquire/reacquire reserves against `max_metadata_open_attempts` before
/// calling the filesystem adapter; failures and retries also count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalLimits {
    /// Traversal wall-clock timeout. `Duration::ZERO` means project default.
    pub timeout: Duration,
    /// Maximum directory depth.
    pub max_directory_depth: u32,
    /// Maximum considered entries.
    pub max_entries_considered: u64,
    /// Maximum emitted files.
    pub max_files_emitted: u64,
    /// Maximum cumulative native path encoding bytes.
    pub max_total_native_path_bytes: u64,
    /// Maximum metadata/open attempts.
    pub max_metadata_open_attempts: u64,
}

impl TraversalLimits {
    /// Skeleton defaults. Finite and non-zero, but **not an admitted production
    /// default**.
    pub fn skeleton_default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            max_directory_depth: 64,
            max_entries_considered: 1_000_000,
            max_files_emitted: 1_000_000,
            max_total_native_path_bytes: 64 * 1024 * 1024,
            max_metadata_open_attempts: 524_288,
        }
    }
}

impl Default for TraversalLimits {
    fn default() -> Self {
        Self::skeleton_default()
    }
}

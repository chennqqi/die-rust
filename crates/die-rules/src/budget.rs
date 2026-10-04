//! Rule runtime resource budgets.
//!
//! These limits govern the JavaScript VM and native host API loops during
//! rule execution. They are derived from ADR 0006 (rquickjs backend) and
//! ADR 0012 (bounded nested scan budget). Two profiles are defined:
//!
//! - `Modern`: the default resource-constrained profile.
//! - `LegacyHighResource`: a permissive profile for legacy rule sets that
//!   require more headroom.
//!
//! See `docs/design/decisions/0006-rquickjs-rule-runtime.md` for the
//! rationale behind each default value.

/// Resource budget profile for the rule runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleBudgetProfile {
    /// Maximum live VM heap in bytes.
    pub max_heap: u64,
    /// Maximum JavaScript VM stack depth.
    pub max_stack: u64,
    /// Maximum VM/native fuel quanta per rule evaluation.
    pub max_fuel: u64,
    /// Cumulative script deadline in milliseconds.
    pub deadline_ms: u64,
    /// Maximum include depth (ADR 0010).
    pub max_include_depth: u32,
    /// Maximum total cumulative include evaluations (ADR 0010).
    pub max_include_evaluations: u32,
}

impl RuleBudgetProfile {
    /// Modern resource-constrained profile.
    ///
    /// Suitable for most production scans. Derived from ADR 0006.
    pub const MODERN: Self = Self {
        max_heap: 128 * 1024 * 1024, // 128 MiB (sufficient for PE rules)
        max_stack: 1024 * 1024,      // 1 MiB
        max_fuel: 524_288,           // 2^19
        deadline_ms: 30_000,         // 30 s
        max_include_depth: 32,
        max_include_evaluations: 1024,
    };

    /// Legacy high-resource profile.
    ///
    /// For legacy rule sets that require more headroom. Derived from ADR 0006.
    pub const LEGACY_HIGH_RESOURCE: Self = Self {
        max_heap: 256 * 1024 * 1024, // 256 MiB
        max_stack: 2 * 1024 * 1024,  // 2 MiB
        max_fuel: 1_048_576,         // 2^20
        deadline_ms: 60_000,         // 60 s
        max_include_depth: 64,
        max_include_evaluations: 4_096,
    };
}

impl Default for RuleBudgetProfile {
    fn default() -> Self {
        Self::MODERN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_profile_defaults() {
        let p = RuleBudgetProfile::MODERN;
        assert_eq!(p.max_heap, 128 * 1024 * 1024);
        assert_eq!(p.max_stack, 1024 * 1024);
        assert_eq!(p.max_fuel, 524_288);
        assert_eq!(p.deadline_ms, 30_000);
        assert_eq!(p.max_include_depth, 32);
        assert_eq!(p.max_include_evaluations, 1024);
    }

    #[test]
    fn legacy_high_resource_profile_defaults() {
        let p = RuleBudgetProfile::LEGACY_HIGH_RESOURCE;
        assert_eq!(p.max_heap, 256 * 1024 * 1024);
        assert_eq!(p.max_stack, 2 * 1024 * 1024);
        assert_eq!(p.max_fuel, 1_048_576);
        assert_eq!(p.deadline_ms, 60_000);
        assert_eq!(p.max_include_depth, 64);
        assert_eq!(p.max_include_evaluations, 4_096);
    }

    #[test]
    fn default_is_modern() {
        assert_eq!(RuleBudgetProfile::default(), RuleBudgetProfile::MODERN);
    }

    #[test]
    fn legacy_has_more_headroom_than_modern() {
        let m = RuleBudgetProfile::MODERN;
        let l = RuleBudgetProfile::LEGACY_HIGH_RESOURCE;
        assert!(l.max_heap > m.max_heap);
        assert!(l.max_stack > m.max_stack);
        assert!(l.max_fuel > m.max_fuel);
        assert!(l.deadline_ms > m.deadline_ms);
        assert!(l.max_include_depth > m.max_include_depth);
        assert!(l.max_include_evaluations > m.max_include_evaluations);
    }
}

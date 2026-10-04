//! Rule runtime error types.
//!
//! All rule loading, parsing, execution and host API failures produce a
//! `RuleError`. Unknown syntax, include failures, budget exhaustion and
//! host API contract violations must become explicit errors — never
//! silently skipped (see AGENTS.md: "规则解析不得静默忽略未知语法").

use die_core::format::FileType;
use std::fmt;

/// Error originating from the rule database or runtime.
#[derive(Debug)]
pub enum RuleError {
    /// A rule file could not be loaded from disk.
    Load {
        /// Relative path of the rule file.
        path: String,
        /// Underlying I/O or parse error.
        cause: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A rule file contains unknown or unsupported syntax.
    ///
    /// This is a compatibility failure: the rule cannot be loaded as-is
    /// and must produce an explicit diagnostic.
    UnsupportedSyntax {
        /// Relative path of the rule file.
        path: String,
        /// Line number (1-based) if known, else 0.
        line: u32,
        /// Human-readable description of the unsupported construct.
        detail: String,
    },
    /// An `includeScript()` call failed.
    Include {
        /// Name passed to `includeScript()`.
        script_name: String,
        /// Why the include failed.
        cause: IncludeCause,
    },
    /// The include graph contains a cycle (ADR 0010).
    IncludeCycle {
        /// Cycle path, e.g. `["a", "b", "a"]`.
        cycle: Vec<String>,
    },
    /// The include depth or total evaluation count exceeded the budget.
    IncludeBudgetExceeded {
        /// Which limit was hit.
        limit: IncludeLimit,
        /// Current value when the limit was hit.
        current: u64,
        /// Configured maximum.
        maximum: u64,
    },
    /// A rule file parsed but the expected `detect` function was missing.
    MissingDetect {
        /// Relative path of the rule file.
        path: String,
    },
    /// The rule runtime exceeded its resource budget.
    BudgetExceeded {
        /// Which budget was exhausted.
        budget: RuleBudget,
        /// Current consumption when the limit was hit.
        current: u64,
        /// Configured maximum.
        maximum: u64,
    },
    /// The scan was cancelled via the cancel token.
    Cancelled,
    /// A host API method returned an error.
    HostApi {
        /// File type context (e.g. "Binary", "PE").
        file_type: FileType,
        /// Method name that failed.
        method: String,
        /// Error detail.
        detail: String,
    },
    /// A rule script threw a JavaScript-level exception.
    ScriptException {
        /// Relative path of the rule file.
        path: String,
        /// Exception message.
        message: String,
    },
    /// The backend reported an internal error.
    Backend {
        /// Backend-specific error message.
        detail: String,
    },
}

/// Why an `includeScript()` call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncludeCause {
    /// The included script was not found in the database.
    NotFound,
    /// The included script failed to load or parse.
    LoadFailed,
    /// The include depth limit was exceeded.
    DepthExceeded,
}

/// Which include budget was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncludeLimit {
    /// Maximum include depth.
    Depth,
    /// Total cumulative include evaluations.
    TotalEvaluations,
}

/// Which rule runtime budget was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleBudget {
    /// Live VM heap in bytes.
    Heap,
    /// JavaScript VM stack depth.
    Stack,
    /// VM/native fuel quanta consumed.
    Fuel,
    /// Cumulative wall-clock deadline in milliseconds.
    Deadline,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleError::Load { path, cause } => {
                write!(f, "failed to load rule '{path}': {cause}")
            }
            RuleError::UnsupportedSyntax { path, line, detail } => {
                if *line > 0 {
                    write!(f, "unsupported syntax in '{path}' at line {line}: {detail}")
                } else {
                    write!(f, "unsupported syntax in '{path}': {detail}")
                }
            }
            RuleError::Include { script_name, cause } => match cause {
                IncludeCause::NotFound => {
                    write!(f, "includeScript('{script_name}'): script not found")
                }
                IncludeCause::LoadFailed => {
                    write!(f, "includeScript('{script_name}'): load failed")
                }
                IncludeCause::DepthExceeded => {
                    write!(f, "includeScript('{script_name}'): depth exceeded")
                }
            },
            RuleError::IncludeCycle { cycle } => {
                write!(f, "include cycle detected: {}", cycle.join(" -> "))
            }
            RuleError::IncludeBudgetExceeded {
                limit,
                current,
                maximum,
            } => match limit {
                IncludeLimit::Depth => {
                    write!(f, "include depth {current} exceeded maximum {maximum}")
                }
                IncludeLimit::TotalEvaluations => write!(
                    f,
                    "total include evaluations {current} exceeded maximum {maximum}"
                ),
            },
            RuleError::MissingDetect { path } => {
                write!(f, "rule '{path}' has no detect() function")
            }
            RuleError::BudgetExceeded {
                budget,
                current,
                maximum,
            } => match budget {
                RuleBudget::Heap => {
                    write!(f, "heap budget {current} exceeded maximum {maximum}")
                }
                RuleBudget::Stack => {
                    write!(f, "stack depth {current} exceeded maximum {maximum}")
                }
                RuleBudget::Fuel => {
                    write!(f, "fuel {current} exceeded maximum {maximum}")
                }
                RuleBudget::Deadline => {
                    write!(f, "deadline {current}ms exceeded maximum {maximum}ms")
                }
            },
            RuleError::Cancelled => write!(f, "scan cancelled"),
            RuleError::HostApi {
                file_type,
                method,
                detail,
            } => {
                write!(f, "host API {}.{}: {}", file_type.name, method, detail)
            }
            RuleError::ScriptException { path, message } => {
                write!(f, "script exception in '{path}': {message}")
            }
            RuleError::Backend { detail } => {
                write!(f, "rule backend error: {detail}")
            }
        }
    }
}

impl std::error::Error for RuleError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_error_displays() {
        let err = RuleError::Load {
            path: "db/Binary/test.sg".into(),
            cause: "file not found".into(),
        };
        assert_eq!(
            err.to_string(),
            "failed to load rule 'db/Binary/test.sg': file not found"
        );
    }

    #[test]
    fn unsupported_syntax_with_line_displays() {
        let err = RuleError::UnsupportedSyntax {
            path: "db/Binary/test.sg".into(),
            line: 42,
            detail: "unsupported const redefinition".into(),
        };
        assert_eq!(
            err.to_string(),
            "unsupported syntax in 'db/Binary/test.sg' at line 42: unsupported const redefinition"
        );
    }

    #[test]
    fn unsupported_syntax_without_line_displays() {
        let err = RuleError::UnsupportedSyntax {
            path: "db/Binary/test.sg".into(),
            line: 0,
            detail: "unsupported syntax".into(),
        };
        assert_eq!(
            err.to_string(),
            "unsupported syntax in 'db/Binary/test.sg': unsupported syntax"
        );
    }

    #[test]
    fn include_not_found_displays() {
        let err = RuleError::Include {
            script_name: "chunkparsers".into(),
            cause: IncludeCause::NotFound,
        };
        assert_eq!(
            err.to_string(),
            "includeScript('chunkparsers'): script not found"
        );
    }

    #[test]
    fn include_cycle_displays() {
        let err = RuleError::IncludeCycle {
            cycle: vec!["a".into(), "b".into(), "a".into()],
        };
        assert_eq!(err.to_string(), "include cycle detected: a -> b -> a");
    }

    #[test]
    fn budget_exceeded_displays() {
        let err = RuleError::BudgetExceeded {
            budget: RuleBudget::Heap,
            current: 33_554_432,
            maximum: 33_554_432,
        };
        assert_eq!(
            err.to_string(),
            "heap budget 33554432 exceeded maximum 33554432"
        );
    }

    #[test]
    fn cancelled_displays() {
        let err = RuleError::Cancelled;
        assert_eq!(err.to_string(), "scan cancelled");
    }

    #[test]
    fn host_api_error_displays() {
        let err = RuleError::HostApi {
            file_type: FileType::new("PE"),
            method: "getSectionNumber".into(),
            detail: "invalid section index".into(),
        };
        assert_eq!(
            err.to_string(),
            "host API PE.getSectionNumber: invalid section index"
        );
    }

    #[test]
    fn script_exception_displays() {
        let err = RuleError::ScriptException {
            path: "db/Binary/test.sg".into(),
            message: "TypeError: cannot read property 'foo' of undefined".into(),
        };
        assert_eq!(
            err.to_string(),
            "script exception in 'db/Binary/test.sg': TypeError: cannot read property 'foo' of undefined"
        );
    }
}

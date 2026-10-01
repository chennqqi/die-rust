//! `diec-rules` owns three boundaries: the original rule assets and source
//! manifest, rule metadata/load diagnostics and disposable derived caches, and
//! the `RuleRuntime`/`HostApi` ports.
//!
//! Rule source files are never formatted or hand-corrected. Unknown syntax,
//! include failures and database conflicts must become explicit errors or
//! compatibility failures, never silently skipped. `HostApi` is defined here
//! and implemented by `diec-engine`'s adapter, so the rule layer does not
//! depend on `diec-formats`. See `docs/design/architecture.md` section 9.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod budget;
pub mod error;
pub mod host_api;
pub mod include_graph;
pub mod inventory;
pub mod manifest;
pub mod order_manifest;
pub mod pdf_encrypt;
pub mod runtime;

/// rquickjs backend module (ADR 0006).
///
/// All rquickjs/QuickJS types are private to this module. They never
/// appear in core, formats, engine, output, CLI, FFI or the public C ABI.
pub mod backend_rquickjs;

/// Host API bridge for the rquickjs backend.
///
/// Bridges the Rust `HostApi` trait to JavaScript `Binary`/`X`/`File`
/// objects with 155 Binary_Script methods.
pub mod host_api_bridge;

/// Native PE host API methods backed by `pelite`.
///
/// Replaces hand-written JavaScript PE parsing with native Rust.
pub mod elf_native;
pub mod macho_native;
pub mod pe_native;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_loads() {
        // Smoke test: ensure all modules compile and link.
        let _ = super::budget::RuleBudgetProfile::MODERN;
    }
}

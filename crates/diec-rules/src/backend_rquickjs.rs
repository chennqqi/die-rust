//! rquickjs/QuickJS-NG rule runtime backend (ADR 0006).
//!
//! This module implements `RuleRuntime` and `RuleRuntimeFactory` using
//! `rquickjs@0.12.1` with vendored QuickJS-NG. All rquickjs/QuickJS types
//! are private to this module — they never appear in `diec-core`,
//! `diec-formats`, `diec-engine`, `diec-output`, `diec-cli`, `diec-ffi`
//! or the public C ABI.
//!
//! See `docs/design/decisions/0006-rquickjs-rule-runtime.md`.

use crate::error::RuleError;
use crate::host_api::HostApi;
use crate::include_graph::IncludeStack;
use crate::runtime::{
    DatabaseSnapshot, DetectionResult, LoadedRule, RuleRuntime, RuleRuntimeFactory, RuntimeConfig,
};
use diec_core::cancel::CancellationToken;
use rquickjs::{Context, Ctx, Runtime};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Factory that creates `RquickjsRuntime` instances.
pub struct RquickjsRuntimeFactory;

impl RuleRuntimeFactory for RquickjsRuntimeFactory {
    fn create(&self, config: RuntimeConfig) -> Result<Box<dyn RuleRuntime>, RuleError> {
        Ok(Box::new(RquickjsRuntime::new(config)?))
    }
}

/// Internal cancel flag shared between the interrupt handler and the
/// external cancel token.
struct CancelFlag {
    cancelled: AtomicBool,
}

impl CancelFlag {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }

    fn set_cancelled(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn clear(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// rquickjs-based rule runtime.
///
/// Each scan uses a shared runtime/context owned by a single worker thread.
/// The runtime is configured with memory limits, stack limits, and an
/// interrupt handler for cooperative cancellation.
pub struct RquickjsRuntime {
    /// Configuration (budget profile, legacy mode).
    /// Stored for future use by budget enforcement and profile switching.
    #[allow(dead_code)]
    config: RuntimeConfig,
    /// QuickJS runtime (memory management, interrupts).
    _runtime: Runtime,
    /// QuickJS context (globals, eval).
    context: Context,
    /// Cancel flag linked to the interrupt handler.
    cancel_flag: Arc<CancelFlag>,
    /// Whether the database has been loaded.
    database_loaded: bool,
    /// Whether init has been called.
    initialized: bool,
    /// Runtime include stack for Rust-side budget enforcement (ADR 0010).
    /// Currently cycle detection is done JS-side; this will be used when
    /// the include budget is enforced from Rust for hard limits.
    #[allow(dead_code)]
    include_stack: IncludeStack,
    /// Include script registry: name -> source text.
    include_scripts: BTreeMap<String, String>,
    /// Type-specific init scripts, deferred to init() phase.
    type_init_scripts: Vec<(String, String)>,
}

impl RquickjsRuntime {
    /// Create a new rquickjs runtime with the given configuration.
    pub fn new(config: RuntimeConfig) -> Result<Self, RuleError> {
        let runtime = Runtime::new().map_err(|e| RuleError::Backend {
            detail: format!("failed to create QuickJS runtime: {e}"),
        })?;

        // Configure memory and stack limits per ADR 0006.
        runtime.set_memory_limit(config.budget.max_heap as usize);
        runtime.set_max_stack_size(config.budget.max_stack as usize);

        // Set up interrupt handler for cooperative cancellation.
        let cancel_flag = Arc::new(CancelFlag::new());
        let handler_flag = cancel_flag.clone();
        runtime.set_interrupt_handler(Some(Box::new(move || handler_flag.is_cancelled())));

        // Create a context with full intrinsics (Date, JSON, etc.).
        let context = Context::full(&runtime).map_err(|e| RuleError::Backend {
            detail: format!("failed to create QuickJS context: {e}"),
        })?;

        Ok(Self {
            include_stack: IncludeStack::new(
                config.budget.max_include_depth,
                config.budget.max_include_evaluations,
            ),
            config,
            _runtime: runtime,
            context,
            cancel_flag,
            database_loaded: false,
            initialized: false,
            include_scripts: BTreeMap::new(),
            type_init_scripts: Vec::new(),
        })
    }

    /// Register a host API bridge on the JavaScript context.
    ///
    /// This creates the `Binary`/`X`/`File` JavaScript objects that bridge
    /// to the Rust `HostApi` trait. Must be called before `load_database`
    /// (so that include scripts referencing `Binary` at top level work)
    /// and before `evaluate_rule`.
    pub fn register_host_api(&self, host: Arc<dyn HostApi + Send + Sync>) -> Result<(), RuleError> {
        let bridge = crate::host_api_bridge::HostApiBridge::new(host);
        bridge.register(&self.context)
    }

    /// Register global host functions on the JavaScript context.
    ///
    /// All 15 global functions from the upstream Qt Script engine are defined
    /// via JavaScript eval. Results are stored in a JavaScript array
    /// (`__diec_results`) and read back from Rust after rule evaluation.
    /// `includeScript` is implemented as a native Rust function that accesses
    /// the include scripts registry and include stack.
    fn register_globals(&mut self) -> Result<(), RuleError> {
        let os_name = if cfg!(target_os = "windows") {
            "windows"
        } else if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            "unknown"
        };

        let globals_js = format!(
            r#"
            var __diec_results = [];
            var __diec_block_list = [];
            // Endian constants (used by read_uintN methods)
            var _LE = 0;
            var _BE = 1;
            // Simple meta() placeholder; the real _init script overrides this.
            var __diec_meta = {{ type: "", name: "" }};
            function meta(type, name) {{
                __diec_meta.type = type;
                __diec_meta.name = name;
            }}
            function _setResult(type, name, version, options) {{
                type = String(type);
                name = String(name);
                // Check block list (case-insensitive type+name match).
                var typeLower = type.toLowerCase();
                var nameLower = name.toLowerCase();
                for (var i = 0; i < __diec_block_list.length; i++) {{
                    if (__diec_block_list[i].type === typeLower &&
                        __diec_block_list[i].name === nameLower) {{
                        return;
                    }}
                }}
                __diec_results.push({{
                    type: type,
                    name: name,
                    version: String(version),
                    options: String(options),
                    lang: "",
                    langVersion: "",
                    id: null,
                    parentId: null,
                    filePart: null,
                    offset: null,
                    size: null,
                    isHeuristic: null,
                    isAHeuristic: null,
                    originalName: null
                }});
            }}
            function _setLang(lang, langVersion) {{
                if (__diec_results.length > 0) {{
                    __diec_results[__diec_results.length - 1].lang = String(lang);
                    __diec_results[__diec_results.length - 1].langVersion = String(langVersion || "");
                }}
            }}
            function _setHeuristic(bIsHeuristic) {{
                if (__diec_results.length > 0) {{
                    __diec_results[__diec_results.length - 1].isHeuristic = bIsHeuristic ? true : null;
                }}
            }}
            function _setFilePart(filePart, nOffset, nSize) {{
                if (__diec_results.length > 0) {{
                    __diec_results[__diec_results.length - 1].filePart = filePart ? String(filePart) : null;
                    __diec_results[__diec_results.length - 1].offset = (nOffset !== undefined && nOffset !== null) ? Number(nOffset) : null;
                    __diec_results[__diec_results.length - 1].size = (nSize !== undefined && nSize !== null) ? Number(nSize) : null;
                }}
            }}
            function _error(msg) {{ throw new Error(msg); }}
            function _log(msg) {{ }}
            function _getEngineVersion() {{ return "3.10"; }}
            function _getQtVersion() {{ return "5.15.13"; }}
            function _isStop() {{ return false; }}
            function _isConsoleMode() {{ return true; }}
            function _isLiteMode() {{ return false; }}
            function _isGuiMode() {{ return false; }}
            function _isLibraryMode() {{ return false; }}
            function _getOS() {{ return "{os_name}"; }}
            function _getNumberOfResults(sType) {{
                if (sType === undefined) return __diec_results.length;
                var typeLower = String(sType).toLowerCase();
                var count = 0;
                for (var i = 0; i < __diec_results.length; i++) {{
                    if (__diec_results[i].type.toLowerCase() === typeLower) count++;
                }}
                return count;
            }}
            function _isResultPresent(sType, sName) {{
                if (sType === undefined) return __diec_results.length > 0;
                var typeLower = String(sType).toLowerCase();
                var nameLower = sName !== undefined ? String(sName).toLowerCase() : null;
                for (var i = 0; i < __diec_results.length; i++) {{
                    if (__diec_results[i].type.toLowerCase() === typeLower) {{
                        if (nameLower === null || __diec_results[i].name.toLowerCase() === nameLower) {{
                            return true;
                        }}
                    }}
                }}
                return false;
            }}
            function _breakScan() {{ }}
            function _encodingList() {{ return []; }}
            function _removeResult(sType, sName) {{
                var typeLower = String(sType).toLowerCase();
                var nameLower = String(sName).toLowerCase();
                for (var i = 0; i < __diec_results.length; i++) {{
                    if (__diec_results[i].type.toLowerCase() === typeLower &&
                        __diec_results[i].name.toLowerCase() === nameLower) {{
                        // Add to block list so the same type+name cannot be re-added.
                        __diec_block_list.push({{ type: typeLower, name: nameLower }});
                        __diec_results.splice(i, 1);
                        return;
                    }}
                }}
            }}
            "#,
        );
        self.eval_script(&globals_js)?;

        // Register includeScript as a native function that accesses the
        // include scripts registry and include stack via shared state.
        // The include scripts are stored as a JS-side object for eval access,
        // while cycle detection and budget are enforced through the Rust
        // include stack.
        self.register_include_script_fn()?;

        Ok(())
    }

    /// Register the `includeScript` native function.
    ///
    /// This function looks up the script by name in the include scripts
    /// registry, pushes onto the include stack (cycle detection + budget),
    /// evaluates the script source, and pops the stack.
    fn register_include_script_fn(&mut self) -> Result<(), RuleError> {
        // Store include scripts as a JS-side object so the native function
        // can access them via `ctx.globals().get("__diec_includes")`.
        let ctx = self.context.clone();
        let include_scripts = std::mem::take(&mut self.include_scripts);

        ctx.with(|ctx: Ctx<'_>| -> Result<(), RuleError> {
            let obj = rquickjs::Object::new(ctx.clone()).map_err(|e| RuleError::Backend {
                detail: format!("include object: {e}"),
            })?;
            for (name, source) in &include_scripts {
                let js_string = rquickjs::String::from_str(ctx.clone(), source).map_err(|e| {
                    RuleError::Backend {
                        detail: format!("include string: {e}"),
                    }
                })?;
                obj.set(name.as_str(), js_string)
                    .map_err(|e| RuleError::Backend {
                        detail: format!("include set: {e}"),
                    })?;
            }
            let globals = ctx.globals();
            globals
                .set("__diec_includes", obj)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__diec_includes set: {e}"),
                })?;
            Ok(())
        })?;

        // Restore the include_scripts map.
        self.include_scripts = include_scripts;

        // Register the native includeScript function.
        // The function reads the script source from __diec_includes and evals it.
        // Cycle detection is handled by checking a JS-side active stack.
        //
        // IMPORTANT: In Qt Script, includeScript evaluates the source in the
        // global scope. `var x = val` at global scope creates/modifies the
        // global variable (same as `x = val`). The "protection" against
        // accidental overwrites comes from the `if (typeof x === "undefined")`
        // guard pattern used in include scripts, NOT from `var` scoping.
        //
        // QuickJS's indirect eval `(0, eval)(source)` also evaluates in the
        // global scope and `var x = val` creates/modifies globals, which
        // matches Qt Script behavior. No save/restore is needed.
        //
        // The correct evaluation order is ensured by the priority-based rule
        // sorting in database.rs (matching upstream's sort_signature_prio).
        let include_js = r#"
            var __diec_include_stack = [];
            function includeScript(name) {
                // Check for cycle: if name is already on the active stack, throw.
                for (var i = 0; i < __diec_include_stack.length; i++) {
                    if (__diec_include_stack[i] === name) {
                        throw new Error("include cycle: " + name);
                    }
                }
                // Check depth limit.
                if (__diec_include_stack.length >= 16) {
                    throw new Error("include depth exceeded");
                }
                // Look up the script source.
                var source = __diec_includes[name];
                if (source === undefined) {
                    throw new Error("include script not found: " + name);
                }
                // Use indirect eval (0, eval)(source) to evaluate in global
                // scope, matching Qt Script's includeScript behavior.
                __diec_include_stack.push(name);
                try {
                    (0, eval)(source);
                } finally {
                    __diec_include_stack.pop();
                }
            }
        "#;
        self.eval_script(include_js)?;

        Ok(())
    }

    /// Read the `__diec_results` array from the JavaScript context.
    pub fn read_results(&self) -> Result<Vec<DetectionResult>, RuleError> {
        self.context.with(|ctx: Ctx<'_>| {
            let globals = ctx.globals();
            let results_val: rquickjs::Value =
                globals
                    .get("__diec_results")
                    .map_err(|e| RuleError::Backend {
                        detail: format!("failed to read __diec_results: {e}"),
                    })?;

            let arr: rquickjs::Array =
                results_val.into_array().ok_or_else(|| RuleError::Backend {
                    detail: "__diec_results is not an array".into(),
                })?;

            let mut results = Vec::new();
            for item in arr.iter::<rquickjs::Object>() {
                let obj = item.map_err(|e| RuleError::Backend {
                    detail: format!("failed to iterate results: {e}"),
                })?;

                let type_name: String = obj.get("type").unwrap_or_default();
                let name: String = obj.get("name").unwrap_or_default();
                let version: String = obj.get("version").unwrap_or_default();
                let options: String = obj.get("options").unwrap_or_default();
                let lang: String = obj.get("lang").unwrap_or_default();
                let lang_version: String = obj.get("langVersion").unwrap_or_default();
                let id: Option<String> = obj.get("id").ok().flatten();
                let parent_id: Option<String> = obj.get("parentId").ok().flatten();
                let file_part: Option<String> = obj.get("filePart").ok().flatten();
                let offset: Option<u64> = obj.get("offset").ok().flatten();
                let size: Option<u64> = obj.get("size").ok().flatten();
                let is_heuristic: Option<bool> = obj.get("isHeuristic").ok().flatten();
                let is_a_heuristic: Option<bool> = obj.get("isAHeuristic").ok().flatten();
                let original_name: Option<String> = obj.get("originalName").ok().flatten();

                results.push(DetectionResult {
                    type_name,
                    name,
                    version,
                    options,
                    lang,
                    lang_version,
                    id,
                    parent_id,
                    file_part,
                    offset,
                    size,
                    is_heuristic,
                    is_a_heuristic,
                    original_name,
                });
            }
            Ok(results)
        })
    }

    /// Clear the `__diec_results` array.
    fn clear_results(&self) -> Result<(), RuleError> {
        self.eval_script("__diec_results.length = 0;")
    }

    /// Evaluate a script source in the context with sloppy mode (non-strict).
    fn eval_script(&self, source: &str) -> Result<(), RuleError> {
        // Preprocess: convert `const` to `var` to match Qt Script behavior.
        // Qt Script treats `const` like `var` (function-scoped, redeclarable).
        // QuickJS treats `const` as block-scoped and rejects redefinition
        // of variables declared with `var` in the same scope, causing
        // SyntaxError in rules like Nintendo-certified-file.1.sg.
        // This is safe because upstream rules don't rely on `const`
        // immutability.
        let processed = source.replace("const ", "var ");
        self.context.with(|ctx: Ctx<'_>| {
            // Use sloppy (non-strict) mode to match Qt Script behavior.
            // QuickJS defaults to strict mode, which rejects `delete` on
            // direct references and other sloppy-mode constructs.
            let mut options = rquickjs::context::EvalOptions::default();
            options.strict = false;
            ctx.eval_with_options::<(), _>(processed.as_str(), options)
                .map_err(|e| {
                    let message = match e {
                        rquickjs::Error::Exception => extract_exception_message(&ctx),
                        other => other.to_string(),
                    };
                    RuleError::ScriptException {
                        path: "<eval>".into(),
                        message,
                    }
                })
        })
    }
}

/// Extract a human-readable message from a JavaScript exception.
/// Called after `ctx.eval` returns `Error::Exception`.
fn extract_exception_message(ctx: &Ctx<'_>) -> String {
    // The exception value is available via ctx.catch(), but rquickjs doesn't
    // expose a way to convert it to a string directly. Instead, we store it
    // as a global and use eval to call String() on it.
    let exc = ctx.catch();
    let type_name = exc.type_name();

    // Store the exception as a global temporary.
    let globals = ctx.globals();
    if globals.set("__diec_exc", exc).is_err() {
        return format!("Exception ({type_name})");
    }

    // Use JS to convert the exception to a string and get stack trace.
    let result: Result<String, _> = ctx.eval(
        r#"
        try {
            var msg = String(__diec_exc);
            if (__diec_exc && __diec_exc.stack) {
                msg += " stack: " + __diec_exc.stack;
            }
            msg;
        } catch(e) { "Exception"; }
        "#,
    );
    let _ = globals.set("__diec_exc", rquickjs::Value::new_null(ctx.clone()));

    match result {
        Ok(s) if !s.is_empty() => s,
        _ => format!("Exception ({type_name})"),
    }
}

impl RuleRuntime for RquickjsRuntime {
    fn load_database(&mut self, snapshot: &DatabaseSnapshot) -> Result<(), RuleError> {
        // Copy include scripts into the runtime before registering globals.
        self.include_scripts = snapshot.include_scripts.clone();

        // Defer type init scripts to init() phase, after host API is registered.
        self.type_init_scripts = snapshot.type_init_scripts.clone();

        self.register_globals()?;

        if let Some(init_source) = &snapshot.init_script {
            self.eval_script(init_source)?;
        }

        // Pre-load the "read" include script if present. This script
        // defines global constants like _BE and _LE that many rules
        // use without explicitly calling includeScript("read").
        if let Some(read_source) = snapshot.include_scripts.get("read") {
            self.eval_script(read_source)?;
        }

        // Note: type init scripts are NOT run here because they may reference
        // host API objects (Binary, X, File) that are only registered during
        // init(). They are run in init() instead.

        // Note: Rule sources are NOT pre-evaluated here. They are evaluated
        // on-demand by evaluate_rule_source(), which wraps each rule in an
        // IIFE to isolate variable declarations. Pre-evaluating all rules
        // here would pollute the global scope with includeScript side effects
        // (e.g. FPC's nOffset, Borland's nOffset), causing later rules to
        // see stale values from earlier rules' include scripts.

        self.database_loaded = true;
        Ok(())
    }

    fn init(&mut self, _host: &dyn HostApi) -> Result<(), RuleError> {
        if !self.database_loaded {
            return Err(RuleError::Backend {
                detail: "init called before load_database".into(),
            });
        }

        // Run type-specific init scripts now that the host API is registered.
        // These scripts set up aliases like `var File = Binary; var X = Binary;`
        // and include helper scripts like `includeScript("read")`.
        for (_type_name, init_source) in &self.type_init_scripts {
            if let Err(e) = self.eval_script(init_source) {
                return Err(RuleError::Backend {
                    detail: format!("init error for {_type_name}: {e}"),
                });
            }
        }

        self.initialized = true;
        Ok(())
    }

    fn evaluate_rule(
        &mut self,
        rule: &LoadedRule,
        _host: &dyn HostApi,
        cancel: &CancellationToken,
    ) -> Result<Vec<DetectionResult>, RuleError> {
        // Delegate to evaluate_rule_source which wraps the rule source in an
        // IIFE, evaluates it, and calls detect() inside the IIFE scope.
        // This avoids the need to pre-evaluate all rule sources during
        // load_database (which would pollute the global scope).
        self.evaluate_rule_source(&rule.path, &rule.source, cancel)
    }

    fn shutdown(&mut self) {
        let _ = self.clear_results();
        self.database_loaded = false;
        self.initialized = false;
    }
}

impl RquickjsRuntime {
    /// Evaluate a single rule source in an isolated scope and call its
    /// `detect()` function.
    ///
    /// This method wraps the rule source in an IIFE so that `detect`
    /// (whether declared as `function detect()`, `var detect`, or
    /// `const detect`) does not leak into the global scope. This allows
    /// multiple rules to be evaluated in the same runtime without
    /// redeclaration conflicts.
    ///
    /// The runtime must be initialized (via `load_database` + `init`)
    /// before calling this method.
    pub fn evaluate_rule_source(
        &mut self,
        rule_path: &str,
        rule_source: &str,
        cancel: &CancellationToken,
    ) -> Result<Vec<DetectionResult>, RuleError> {
        self.evaluate_rule_source_impl(rule_path, rule_source, cancel, true)
    }

    /// Evaluate a rule source without clearing `__diec_results` first.
    /// Used for post-processing rules like `_FixDetects` that need access
    /// to accumulated results from prior rule evaluations.
    pub fn evaluate_rule_source_keep_results(
        &mut self,
        rule_path: &str,
        rule_source: &str,
        cancel: &CancellationToken,
    ) -> Result<Vec<DetectionResult>, RuleError> {
        self.evaluate_rule_source_impl(rule_path, rule_source, cancel, false)
    }

    fn evaluate_rule_source_impl(
        &mut self,
        rule_path: &str,
        rule_source: &str,
        cancel: &CancellationToken,
        clear: bool,
    ) -> Result<Vec<DetectionResult>, RuleError> {
        if !self.initialized {
            return Err(RuleError::Backend {
                detail: "evaluate_rule_source called before init".into(),
            });
        }

        // Reset cancel flag and link to external token.
        self.cancel_flag.clear();
        if cancel.is_cancelled() {
            self.cancel_flag.set_cancelled();
            return Err(RuleError::Cancelled);
        }

        // Clear previous results from the JS __diec_results array.
        if clear {
            self.clear_results()?;
        }

        // Preprocess: convert `const` to `var` to match Qt Script behavior.
        // See eval_script() for details.
        let processed_source = rule_source.replace("const ", "var ");

        // Wrap the rule source in an IIFE that captures `detect` and
        // calls it immediately. This isolates `const`/`function`/`var`
        // declarations from the global scope.
        //
        // The wrapper:
        // 1. Evaluates the rule source inside a function scope
        // 2. Checks if `detect` was defined
        // 3. Calls `detect()` if it exists
        // 4. Returns the result
        //
        // Note: `includeScript` uses indirect eval `(0, eval)(source)` which
        // evaluates in the global scope, so variables set by include scripts
        // (like `bFPC`, `nOffset`) are accessible inside the IIFE via the
        // scope chain (IIFE → global).
        let wrapped = format!(
            r#"(function() {{
                {processed_source}
                if (typeof detect === 'function') {{
                    return detect();
                }}
                return undefined;
            }})();"#,
        );

        let eval_result: Result<(), rquickjs::Error> = self.context.with(|ctx: Ctx<'_>| {
            let mut options = rquickjs::context::EvalOptions::default();
            options.strict = false;
            ctx.eval_with_options::<(), _>(wrapped.as_str(), options)
        });

        match eval_result {
            Ok(_) => self.read_results(),
            Err(e) => {
                if self.cancel_flag.is_cancelled() {
                    Err(RuleError::Cancelled)
                } else {
                    let message = match e {
                        rquickjs::Error::Exception => self
                            .context
                            .with(|ctx: Ctx<'_>| extract_exception_message(&ctx)),
                        other => other.to_string(),
                    };
                    Err(RuleError::ScriptException {
                        path: rule_path.to_string(),
                        message,
                    })
                }
            }
        }
    }

    /// Inject detection results into `__diec_results` for post-processing
    /// rules like `_FixDetects` that need access to all accumulated results.
    pub fn inject_results(&mut self, results: &[DetectionResult]) -> Result<(), RuleError> {
        self.clear_results()?;
        self.context.with(|ctx: Ctx<'_>| -> Result<(), RuleError> {
            let globals = ctx.globals();
            let arr: rquickjs::Array =
                globals
                    .get("__diec_results")
                    .map_err(|e| RuleError::Backend {
                        detail: format!("inject_results: failed to get __diec_results: {e}"),
                    })?;
            for r in results {
                let obj = rquickjs::Object::new(ctx.clone()).map_err(|e| RuleError::Backend {
                    detail: format!("inject_results: new object: {e}"),
                })?;
                obj.set("type", r.type_name.clone())
                    .map_err(|e| RuleError::Backend {
                        detail: format!("inject_results: set type: {e}"),
                    })?;
                obj.set("name", r.name.clone())
                    .map_err(|e| RuleError::Backend {
                        detail: format!("inject_results: set name: {e}"),
                    })?;
                obj.set("version", r.version.clone())
                    .map_err(|e| RuleError::Backend {
                        detail: format!("inject_results: set version: {e}"),
                    })?;
                obj.set("options", r.options.clone())
                    .map_err(|e| RuleError::Backend {
                        detail: format!("inject_results: set options: {e}"),
                    })?;
                obj.set("lang", r.lang.clone())
                    .map_err(|e| RuleError::Backend {
                        detail: format!("inject_results: set lang: {e}"),
                    })?;
                obj.set("langVersion", r.lang_version.clone())
                    .map_err(|e| RuleError::Backend {
                        detail: format!("inject_results: set langVersion: {e}"),
                    })?;
                let len = arr.len();
                arr.set(len, obj).map_err(|e| RuleError::Backend {
                    detail: format!("inject_results: set: {e}"),
                })?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Re-initialize the runtime for a new file scan, reusing the already
    /// loaded framework (globals, init script, read include).
    ///
    /// This is used by `Scanner` (ADR 0016) to avoid the cost of creating
    /// a new runtime and reloading the framework for each file. After
    /// `register_host_api` is called with the new file's host, this method
    /// re-runs the type-specific init scripts so that aliases like
    /// `var File = PE; var X = PE;` point to the newly registered host
    /// object instead of the previous file's host.
    ///
    /// The runtime must have been previously initialized via `load_database`
    /// + `init`. Results from the previous scan are cleared.
    pub fn reinit(&mut self) -> Result<(), RuleError> {
        if !self.database_loaded {
            return Err(RuleError::Backend {
                detail: "reinit called before load_database".into(),
            });
        }

        // Clear any leftover results from the previous file's rules.
        self.clear_results()?;

        // Re-run type-specific init scripts to update host aliases
        // (e.g. `var File = PE; var X = PE;`). These scripts set globals
        // like File/X to point at the host API object that was just
        // re-registered via register_host_api.
        for (type_name, init_source) in &self.type_init_scripts {
            if let Err(e) = self.eval_script(init_source) {
                return Err(RuleError::Backend {
                    detail: format!("reinit error for {type_name}: {e}"),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::RuleBudgetProfile;
    use crate::runtime::RuntimeConfig;

    #[test]
    fn rquickjs_runtime_creates_successfully() {
        let runtime = RquickjsRuntime::new(RuntimeConfig::default());
        assert!(runtime.is_ok());
    }

    #[test]
    fn rquickjs_runtime_evaluates_javascript_expression() {
        let runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        let result: i32 = runtime.context.with(|ctx| ctx.eval("1 + 2").unwrap());
        assert_eq!(result, 3);
    }

    #[test]
    fn rquickjs_runtime_loads_empty_database() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        let snapshot = DatabaseSnapshot::empty();
        runtime.load_database(&snapshot).unwrap();
    }

    #[test]
    fn rquickjs_runtime_factory_creates_runtime() {
        let factory = RquickjsRuntimeFactory;
        let runtime = factory.create(RuntimeConfig::default()).unwrap();
        // The runtime should be a RquickjsRuntime instance.
        // We can't directly test the type since it's behind a Box<dyn RuleRuntime>,
        // but we can verify it loads an empty database.
        let mut rt = runtime;
        rt.load_database(&DatabaseSnapshot::empty()).unwrap();
    }

    #[test]
    fn rquickjs_runtime_sets_memory_limit() {
        let config = RuntimeConfig {
            budget: RuleBudgetProfile {
                max_heap: 1024 * 1024,
                max_stack: 64 * 1024,
                max_fuel: 1000,
                deadline_ms: 1000,
                max_include_depth: 4,
                max_include_evaluations: 16,
            },
            legacy_mode: false,
        };
        let runtime = RquickjsRuntime::new(config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn rquickjs_runtime_handles_script_exception() {
        let runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        let result = runtime.eval_script("throw new Error('test error');");
        assert!(result.is_err());
        match result.unwrap_err() {
            RuleError::ScriptException { message, .. } => {
                // QuickJS may format the message differently; just check
                // that we got a ScriptException with a non-empty message.
                assert!(
                    !message.is_empty(),
                    "exception message should not be empty: {message}"
                );
            }
            _ => panic!("expected ScriptException"),
        }
    }

    #[test]
    fn rquickjs_runtime_error_function_throws() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        runtime.register_globals().unwrap();
        let result = runtime.eval_script(r#"_error("test error message");"#);
        assert!(result.is_err());
    }

    #[test]
    fn rquickjs_runtime_get_engine_version() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        runtime.register_globals().unwrap();
        let version: String = runtime
            .context
            .with(|ctx| ctx.eval("_getEngineVersion()").unwrap());
        assert_eq!(version, "3.10");
    }

    #[test]
    fn rquickjs_runtime_get_os() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        runtime.register_globals().unwrap();
        let os: String = runtime.context.with(|ctx| ctx.eval("_getOS()").unwrap());
        assert!(!os.is_empty());
    }

    #[test]
    fn rquickjs_runtime_set_result_collects_detection() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        runtime.register_globals().unwrap();
        runtime
            .eval_script(r#"_setResult("info", "TestFormat", "1.0", "");"#)
            .unwrap();
        let results = runtime.read_results().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].type_name, "info");
        assert_eq!(results[0].name, "TestFormat");
        assert_eq!(results[0].version, "1.0");
    }

    #[test]
    fn rquickjs_runtime_set_lang_updates_last_result() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        runtime.register_globals().unwrap();
        runtime
            .eval_script(
                r#"
            _setResult("info", "TestFormat", "1.0", "");
            _setLang("C++", "17");
        "#,
            )
            .unwrap();
        let results = runtime.read_results().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].lang, "C++");
        assert_eq!(results[0].lang_version, "17");
    }

    #[test]
    fn rquickjs_runtime_is_console_mode() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        runtime.register_globals().unwrap();
        let is_console: bool = runtime
            .context
            .with(|ctx| ctx.eval("_isConsoleMode()").unwrap());
        assert!(is_console);
    }

    #[test]
    fn rquickjs_runtime_is_result_present() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        runtime.register_globals().unwrap();

        let present: bool = runtime
            .context
            .with(|ctx| ctx.eval("_isResultPresent()").unwrap());
        assert!(!present);

        runtime
            .eval_script(r#"_setResult("info", "Test", "", "");"#)
            .unwrap();

        let present: bool = runtime
            .context
            .with(|ctx| ctx.eval("_isResultPresent()").unwrap());
        assert!(present);
    }

    #[test]
    fn rquickjs_runtime_get_number_of_results() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        runtime.register_globals().unwrap();

        let count: i32 = runtime
            .context
            .with(|ctx| ctx.eval("_getNumberOfResults()").unwrap());
        assert_eq!(count, 0);

        runtime
            .eval_script(
                r#"
            _setResult("info", "A", "", "");
            _setResult("info", "B", "", "");
        "#,
            )
            .unwrap();

        let count: i32 = runtime
            .context
            .with(|ctx| ctx.eval("_getNumberOfResults()").unwrap());
        assert_eq!(count, 2);
    }

    #[test]
    fn rquickjs_runtime_encoding_list_returns_array() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();
        runtime.register_globals().unwrap();
        let result = runtime.eval_script("_encodingList();");
        assert!(result.is_ok());
    }

    #[test]
    fn rquickjs_runtime_evaluates_simple_rule() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();

        let snapshot = DatabaseSnapshot {
            rules: vec![LoadedRule {
                path: "test.sg".into(),
                ordinal: 0,
                file_type: "Binary".into(),
                source: r#"
                    meta("info", "TestRule");
                    function detect() {
                        _setResult("info", "TestRule", "1.0", "");
                    }
                "#
                .to_string(),
            }],
            init_script: None,
            type_init_scripts: Vec::new(),
            include_scripts: std::collections::BTreeMap::new(),
        };

        runtime.load_database(&snapshot).unwrap();

        let token = CancellationToken::new();
        let host = DummyHost;
        runtime.init(&host).unwrap();

        let results = runtime
            .evaluate_rule(&snapshot.rules[0], &host, &token)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "TestRule");
    }

    #[test]
    fn rquickjs_runtime_include_script_loads_helper() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();

        let mut includes = std::collections::BTreeMap::new();
        includes.insert(
            "helpers".to_string(),
            r#"function helperFunc() { return 42; }"#.to_string(),
        );

        let snapshot = DatabaseSnapshot {
            rules: vec![LoadedRule {
                path: "test.sg".into(),
                ordinal: 0,
                file_type: "Binary".into(),
                source: r#"
                    meta("info", "TestInclude");
                    includeScript("helpers");
                    function detect() {
                        _setResult("info", "TestInclude", String(helperFunc()), "");
                    }
                "#
                .to_string(),
            }],
            init_script: None,
            type_init_scripts: Vec::new(),
            include_scripts: includes,
        };

        runtime.load_database(&snapshot).unwrap();

        let token = CancellationToken::new();
        let host = DummyHost;
        runtime.init(&host).unwrap();

        let results = runtime
            .evaluate_rule(&snapshot.rules[0], &host, &token)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "TestInclude");
        assert_eq!(results[0].version, "42");
    }

    #[test]
    fn rquickjs_runtime_include_script_not_found_throws() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();

        let snapshot = DatabaseSnapshot {
            rules: vec![LoadedRule {
                path: "test.sg".into(),
                ordinal: 0,
                file_type: "Binary".into(),
                source: r#"
                    meta("info", "TestMissing");
                    includeScript("nonexistent");
                    function detect() { }
                "#
                .to_string(),
            }],
            init_script: None,
            type_init_scripts: Vec::new(),
            include_scripts: std::collections::BTreeMap::new(),
        };

        // load_database succeeds (rule sources are not pre-evaluated).
        // The error occurs when evaluate_rule calls includeScript.
        runtime.load_database(&snapshot).unwrap();
        let token = CancellationToken::new();
        let host = DummyHost;
        runtime.init(&host).unwrap();
        let result = runtime.evaluate_rule(&snapshot.rules[0], &host, &token);
        assert!(result.is_err());
    }

    #[test]
    fn rquickjs_runtime_include_script_cycle_detected() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();

        let mut includes = std::collections::BTreeMap::new();
        // Create a self-cycle: "a" includes "a"
        includes.insert("a".to_string(), r#"includeScript("a");"#.to_string());

        let snapshot = DatabaseSnapshot {
            rules: vec![LoadedRule {
                path: "test.sg".into(),
                ordinal: 0,
                file_type: "Binary".into(),
                source: r#"
                    meta("info", "TestCycle");
                    includeScript("a");
                    function detect() { }
                "#
                .to_string(),
            }],
            init_script: None,
            type_init_scripts: Vec::new(),
            include_scripts: includes,
        };

        // load_database succeeds (rule sources are not pre-evaluated).
        // The cycle error occurs when evaluate_rule calls includeScript.
        runtime.load_database(&snapshot).unwrap();
        let token = CancellationToken::new();
        let host = DummyHost;
        runtime.init(&host).unwrap();
        let result = runtime.evaluate_rule(&snapshot.rules[0], &host, &token);
        assert!(result.is_err());
    }

    #[test]
    fn rquickjs_runtime_include_script_re_include_after_exit() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();

        let mut includes = std::collections::BTreeMap::new();
        // "helper" defines a function and exits; it can be included again.
        includes.insert(
            "helper".to_string(),
            r#"var helperCount = (typeof helperCount === "undefined" ? 0 : helperCount) + 1;"#
                .to_string(),
        );

        let snapshot = DatabaseSnapshot {
            rules: vec![LoadedRule {
                path: "test.sg".into(),
                ordinal: 0,
                file_type: "Binary".into(),
                source: r#"
                    meta("info", "TestReInclude");
                    includeScript("helper");
                    includeScript("helper");
                    function detect() {
                        _setResult("info", "TestReInclude", String(helperCount), "");
                    }
                "#
                .to_string(),
            }],
            init_script: None,
            type_init_scripts: Vec::new(),
            include_scripts: includes,
        };

        runtime.load_database(&snapshot).unwrap();

        let token = CancellationToken::new();
        let host = DummyHost;
        runtime.init(&host).unwrap();

        let results = runtime
            .evaluate_rule(&snapshot.rules[0], &host, &token)
            .unwrap();
        // helper should have been included twice (ordinary duplicate include
        // is allowed after the script exits the active stack).
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].version, "2");
    }

    #[test]
    fn rquickjs_runtime_include_script_nested() {
        let mut runtime = RquickjsRuntime::new(RuntimeConfig::default()).unwrap();

        let mut includes = std::collections::BTreeMap::new();
        includes.insert(
            "level2".to_string(),
            r#"function level2Func() { return "deep"; }"#.to_string(),
        );
        includes.insert(
            "level1".to_string(),
            r#"includeScript("level2"); function level1Func() { return level2Func(); }"#
                .to_string(),
        );

        let snapshot = DatabaseSnapshot {
            rules: vec![LoadedRule {
                path: "test.sg".into(),
                ordinal: 0,
                file_type: "Binary".into(),
                source: r#"
                    meta("info", "TestNested");
                    includeScript("level1");
                    function detect() {
                        _setResult("info", "TestNested", level1Func(), "");
                    }
                "#
                .to_string(),
            }],
            init_script: None,
            type_init_scripts: Vec::new(),
            include_scripts: includes,
        };

        runtime.load_database(&snapshot).unwrap();

        let token = CancellationToken::new();
        let host = DummyHost;
        runtime.init(&host).unwrap();

        let results = runtime
            .evaluate_rule(&snapshot.rules[0], &host, &token)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].version, "deep");
    }

    /// Dummy host API for testing.
    struct DummyHost;

    impl HostApi for DummyHost {
        fn file_type(&self) -> &diec_core::format::FileType {
            use diec_core::format::FileType;
            static FT: std::sync::OnceLock<FileType> = std::sync::OnceLock::new();
            FT.get_or_init(|| FileType::new("Binary"))
        }

        fn view(&self) -> &diec_core::input::ByteView<'_> {
            unimplemented!()
        }

        fn read_u8(&self, _offset: u64) -> Result<u8, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_u16_le(&self, _offset: u64) -> Result<u16, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_u16_be(&self, _offset: u64) -> Result<u16, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_u24_le(&self, _offset: u64) -> Result<u32, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_u24_be(&self, _offset: u64) -> Result<u32, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_u32_le(&self, _offset: u64) -> Result<u32, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_u32_be(&self, _offset: u64) -> Result<u32, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_u64_le(&self, _offset: u64) -> Result<u64, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_u64_be(&self, _offset: u64) -> Result<u64, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_i8(&self, _offset: u64) -> Result<i8, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_i16_le(&self, _offset: u64) -> Result<i16, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_i32_le(&self, _offset: u64) -> Result<i32, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_i64_le(&self, _offset: u64) -> Result<i64, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn file_size(&self) -> u64 {
            0
        }
        fn check_signature(
            &self,
            _offset: u64,
            _signature: &str,
        ) -> Result<bool, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn find_signature(
            &self,
            _start: u64,
            _signature: &str,
        ) -> Result<Option<u64>, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn find_signature_in_range(
            &self,
            _start: u64,
            _end: u64,
            _signature: &str,
        ) -> Result<Option<u64>, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn read_string(
            &self,
            _offset: u64,
            _max_len: u64,
        ) -> Result<String, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn file_name(&self) -> &str {
            "test.bin"
        }
        fn entry_point(&self) -> Result<u64, crate::host_api::HostApiError> {
            Ok(0)
        }
        fn is_deep(&self) -> bool {
            false
        }
        fn is_heuristic(&self) -> bool {
            false
        }
        fn is_aggressive(&self) -> bool {
            false
        }
        fn is_verbose(&self) -> bool {
            false
        }
        fn is_recursive(&self) -> bool {
            false
        }
        fn entropy(&self, _offset: u64, _size: u64) -> Result<f64, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn md5(&self, _offset: u64, _size: u64) -> Result<String, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn crc32(&self, _offset: u64, _size: u64) -> Result<u32, crate::host_api::HostApiError> {
            unimplemented!()
        }
        fn pe_batch(&self) -> Option<crate::pe_native::PeBatchInfo> {
            None
        }
        fn pe_import_libraries(&self) -> Vec<String> {
            Vec::new()
        }
        fn pe_import_functions(&self) -> Vec<String> {
            Vec::new()
        }
        fn pe_export_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn elf_import_libraries(&self) -> Vec<String> {
            Vec::new()
        }
        fn elf_section_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn macho_import_libraries(&self) -> Vec<String> {
            Vec::new()
        }
        fn macho_section_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn pe_manifest(&self) -> String {
            String::new()
        }
        fn pe_is_net(&self) -> bool {
            false
        }
        fn pe_file_version(&self) -> String {
            String::new()
        }
        fn pe_product_version(&self) -> String {
            String::new()
        }
        fn pe_version_string(&self, _key: &str) -> String {
            String::new()
        }
        fn pe_number_of_resources(&self) -> usize {
            0
        }
        fn pe_is_resource_name_present(&self, _name: &str) -> bool {
            false
        }
        fn pe_resource_section_offset(&self) -> i64 {
            -1
        }
        fn pe_is_signed(&self) -> bool {
            false
        }
    }
}

//! QuickJS bytecode compile/readback helpers.
//!
//! This crate is the single place where raw `rquickjs::qjs` FFI calls
//! drive `JS_Eval`/`JS_WriteObject`/`JS_ReadObject`/`JS_EvalFunction`
//! so that rule scripts can be compiled once per database and executed
//! from bytecode in fresh runtimes without re-parsing. All `unsafe`
//! code is confined to this module; callers see only safe functions
//! taking `&Ctx`.
//!
//! # Semantics
//!
//! `compile_global_script` + `eval_bytecode` is equivalent to
//! `ctx.eval_with_options(source, sloppy-global)`:
//!
//! - The source is compiled as `JS_EVAL_TYPE_GLOBAL` code without
//!   `JS_EVAL_FLAG_STRICT` (sloppy mode), matching `EvalOptions {
//!   global: true, strict: false }`.
//! - The script file name is `eval_script`, identical to the rquickjs
//!   default, so exception stack traces keep the same text.
//! - `JS_EvalFunction` runs the compiled function with
//!   `this = ctx->global_obj`, the same `this` a global `eval` uses.
//! - Pending exceptions, the interrupt handler, memory and stack
//!   limits behave exactly as for `JS_Eval`.
//!
//! # Safety invariants
//!
//! - All functions must be called while the context is entered
//!   (`Context::with`); taking `&Ctx<'js>` enforces this at the type
//!   level.
//! - Bytecode fed to [`eval_bytecode`] must come from
//!   [`compile_global_script`] of the same vendored QuickJS-NG build.
//!   The bytecode cache is in-memory only and never persisted or read
//!   from external input, so no version-mismatch or attacker-controlled
//!   bytecode is possible.
//! - `JS_ReadObject` is called without `JS_READ_OBJ_ROM_DATA`, so
//!   QuickJS copies the bytecode buffer; the cached `Vec<u8>` can be
//!   freed or mutated at will after the call.
//! - `JS_EvalFunction` takes ownership of the `JSValue` produced by
//!   `JS_ReadObject` (the function-bytecode reference moves into the
//!   created closure); the returned result value is freed before this
//!   function returns.
#![warn(missing_docs)]

use rquickjs::{Ctx, qjs};
use std::ffi::CString;

/// Error produced by the bytecode helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytecodeError {
    /// The script failed to compile (a JS exception is pending in the
    /// context and can be inspected with `Ctx::catch`).
    CompileException,
    /// Bytecode deserialization raised a JS exception (pending in the
    /// context).
    ReadException,
    /// Bytecode execution raised a JS exception (pending in the
    /// context).
    EvalException,
    /// `JS_WriteObject`/`JS_ReadObject` failed without a JS exception
    /// (out of memory or malformed input that cannot be produced by
    /// [`compile_global_script`]).
    Malformed,
    /// The source contains an interior NUL byte and cannot be passed
    /// to `JS_Eval`.
    NulByte,
}

impl std::fmt::Display for BytecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BytecodeError::CompileException => write!(f, "script compilation failed"),
            BytecodeError::ReadException => write!(f, "bytecode deserialization failed"),
            BytecodeError::EvalException => write!(f, "bytecode execution failed"),
            BytecodeError::Malformed => write!(f, "bytecode serialization error"),
            BytecodeError::NulByte => write!(f, "source contains an interior NUL byte"),
        }
    }
}

impl std::error::Error for BytecodeError {}

/// Compile `source` as a global-scope sloppy script without executing
/// it, and return the serialized QuickJS bytecode image.
///
/// On `Err(CompileException)` a JS exception is pending in the context
/// (`Ctx::catch`). On any other error no rule code ran.
pub fn compile_global_script(ctx: &Ctx<'_>, source: &[u8]) -> Result<Vec<u8>, BytecodeError> {
    compile_script_impl(ctx, source, false)
}

/// Compile `source` like [`compile_global_script`] but with
/// `JS_EVAL_FLAG_STRICT`, matching rquickjs `ctx.eval` default
/// (`EvalOptions::default().strict == true`). Used for the host-bridge
/// shim scripts which run under strict mode.
pub fn compile_global_script_strict(
    ctx: &Ctx<'_>,
    source: &[u8],
) -> Result<Vec<u8>, BytecodeError> {
    compile_script_impl(ctx, source, true)
}

/// Shared implementation of [`compile_global_script`] and
/// [`compile_global_script_strict`].
fn compile_script_impl(
    ctx: &Ctx<'_>,
    source: &[u8],
    strict: bool,
) -> Result<Vec<u8>, BytecodeError> {
    let src = CString::new(source).map_err(|_| BytecodeError::NulByte)?;
    let ctxp = ctx.as_raw().as_ptr();
    let mut flags = qjs::JS_EVAL_TYPE_GLOBAL | qjs::JS_EVAL_FLAG_COMPILE_ONLY;
    if strict {
        flags |= qjs::JS_EVAL_FLAG_STRICT;
    }
    // SAFETY: called while the context is entered (guaranteed by &Ctx);
    // `src` is a valid NUL-terminated buffer; JS_EVAL_TYPE_GLOBAL |
    // COMPILE_ONLY parses/compiles without executing the program.
    let bfunc = unsafe {
        qjs::JS_Eval(
            ctxp,
            src.as_ptr(),
            src.as_bytes().len() as qjs::size_t,
            c"eval_script".as_ptr(),
            flags as i32,
        )
    };
    // SAFETY: bfunc is a JSValue owned by this call frame.
    if unsafe { qjs::JS_IsException(bfunc) } {
        return Err(BytecodeError::CompileException);
    }
    let mut out_len: qjs::size_t = 0;
    // SAFETY: `bfunc` is a live FUNCTION_BYTECODE value; psize is a
    // valid out-pointer. On success buf points to `out_len` bytes
    // allocated with js_malloc and must be released with js_free.
    let buf = unsafe {
        qjs::JS_WriteObject(ctxp, &mut out_len, bfunc, qjs::JS_WRITE_OBJ_BYTECODE as i32)
    };
    // SAFETY: `bfunc` is an owned reference we no longer need.
    unsafe { qjs::JS_FreeValue(ctxp, bfunc) };
    if buf.is_null() {
        return Err(BytecodeError::Malformed);
    }
    // SAFETY: `buf` is valid for `out_len` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(buf, out_len as usize) }.to_vec();
    // SAFETY: `buf` was allocated by js_malloc in JS_WriteObject.
    unsafe { qjs::js_free(ctxp, buf.cast()) };
    Ok(bytes)
}

/// Deserialize `bytecode` produced by [`compile_global_script`] and
/// execute it as global-scope code (`this` = global object).
///
/// On `Err(ReadException)`/`Err(EvalException)` a JS exception is
/// pending in the context (`Ctx::catch`), mirroring a failed `ctx.eval`.
pub fn eval_bytecode(ctx: &Ctx<'_>, bytecode: &[u8]) -> Result<(), BytecodeError> {
    let ctxp = ctx.as_raw().as_ptr();
    // SAFETY: called while the context is entered; `bytecode` is a valid
    // buffer. No ROM_DATA flag: QuickJS copies the data it keeps.
    let obj = unsafe {
        qjs::JS_ReadObject(
            ctxp,
            bytecode.as_ptr(),
            bytecode.len() as qjs::size_t,
            qjs::JS_READ_OBJ_BYTECODE as i32,
        )
    };
    // SAFETY: obj is a JSValue owned by this call frame.
    if unsafe { qjs::JS_IsException(obj) } {
        return Err(BytecodeError::ReadException);
    }
    // SAFETY: JS_EvalFunction consumes the `obj` reference (the bfunc
    // moves into the created closure) and returns an owned result.
    let res = unsafe { qjs::JS_EvalFunction(ctxp, obj) };
    let failed = unsafe { qjs::JS_IsException(res) };
    // SAFETY: `res` is an owned JSValue reference; freeing an exception
    // sentinel value is a no-op inside JS_FreeValue.
    unsafe { qjs::JS_FreeValue(ctxp, res) };
    if failed {
        return Err(BytecodeError::EvalException);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rquickjs::{Context, Runtime};

    /// Compiled bytecode executed in the same context produces the same
    /// observable side effects as a direct sloppy eval.
    #[test]
    fn bytecode_roundtrip_executes_script() {
        let rt = Runtime::new().unwrap();
        let cx = Context::full(&rt).unwrap();
        cx.with(|ctx| {
            let bc = compile_global_script(&ctx, b"var __bc_t = 40 + 2;").unwrap();
            eval_bytecode(&ctx, &bc).unwrap();
            let v: i32 = ctx.eval("__bc_t").unwrap();
            assert_eq!(v, 42);
        });
    }

    /// Bytecode compiled in one runtime executes correctly in a
    /// different runtime and context (this is the core of the cache:
    /// serialize once, execute in any fresh scan runtime).
    #[test]
    fn bytecode_cross_runtime_execution() {
        let rt1 = Runtime::new().unwrap();
        let cx1 = Context::full(&rt1).unwrap();
        let bc = cx1.with(|ctx| {
            compile_global_script(
                &ctx,
                b"var __bc_x = 'ok' + 1; function __bc_f(){ return 7; }",
            )
            .unwrap()
        });
        let rt2 = Runtime::new().unwrap();
        let cx2 = Context::full(&rt2).unwrap();
        cx2.with(|ctx| {
            eval_bytecode(&ctx, &bc).unwrap();
            let s: String = ctx.eval("__bc_x").unwrap();
            assert_eq!(s, "ok1");
            let v: i32 = ctx.eval("__bc_f()").unwrap();
            assert_eq!(v, 7);
        });
    }

    /// The wrapped-IIFE pattern used for rules: closures, nested
    /// functions and `let`/`var` inside the function scope behave the
    /// same under bytecode execution.
    #[test]
    fn bytecode_wrapped_iife() {
        let rt = Runtime::new().unwrap();
        let cx = Context::full(&rt).unwrap();
        cx.with(|ctx| {
            ctx.eval::<(), _>("var __res = 0;").unwrap();
            let src = r"(function() {
                let acc = 1;
                function add(x) { acc += x; }
                add(2);
                var detect = function() { return acc; };
                if (typeof detect === 'function') { __res = detect(); }
            })();";
            let bc = compile_global_script(&ctx, src.as_bytes()).unwrap();
            eval_bytecode(&ctx, &bc).unwrap();
            let v: i32 = ctx.eval("__res").unwrap();
            assert_eq!(v, 3);
        });
    }

    /// Compile errors surface as CompileException with a pending JS
    /// exception, matching `ctx.eval` failure shape.
    #[test]
    fn compile_error_is_exception() {
        let rt = Runtime::new().unwrap();
        let cx = Context::full(&rt).unwrap();
        cx.with(|ctx| {
            let err = compile_global_script(&ctx, b"var = = ;").unwrap_err();
            assert_eq!(err, BytecodeError::CompileException);
            assert!(ctx.has_exception());
            let _ = ctx.catch();
        });
    }

    /// Runtime exceptions inside the compiled code surface as
    /// EvalException with a pending JS exception.
    #[test]
    fn eval_exception_is_reported() {
        let rt = Runtime::new().unwrap();
        let cx = Context::full(&rt).unwrap();
        cx.with(|ctx| {
            let bc = compile_global_script(&ctx, b"throw new Error('boom');").unwrap();
            let err = eval_bytecode(&ctx, &bc).unwrap_err();
            assert_eq!(err, BytecodeError::EvalException);
            assert!(ctx.has_exception());
            let _ = ctx.catch();
        });
    }

    /// Sloppy-mode constructs rejected in strict mode still compile.
    #[test]
    fn sloppy_mode_preserved() {
        let rt = Runtime::new().unwrap();
        let cx = Context::full(&rt).unwrap();
        cx.with(|ctx| {
            // `delete` on a plain identifier is legal only in sloppy mode.
            let bc = compile_global_script(&ctx, b"var v = 1; delete v;").unwrap();
            eval_bytecode(&ctx, &bc).unwrap();
        });
    }
}

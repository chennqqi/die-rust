use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use boa_engine::{Context, JsResult, JsValue, NativeFunction, Source, js_string, script::Script};
use serde_json::json;

fn collect_rule_files(root: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        fs::read_dir(root).map_err(|error| format!("cannot read {}: {error}", root.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("cannot enumerate {}: {error}", root.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_rule_files(&path, output)?;
        } else if file_type.is_file()
            && (path.extension().is_none()
                || path.extension().is_some_and(|extension| extension == "sg"))
        {
            output.push(path);
        }
    }
    Ok(())
}

fn normalized_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn parse_corpus(roots: &[PathBuf], shared_realm: bool) -> Result<bool, String> {
    let mut files = Vec::new();
    for root in roots {
        collect_rule_files(root, &mut files)?;
    }
    files.sort_by_key(|path| normalized_path(path));

    let started = Instant::now();
    let mut errors = Vec::new();
    let mut total_bytes = 0_u64;
    let mut shared_context = Context::default();

    for path in &files {
        let bytes =
            fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        total_bytes = total_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| "rule byte count overflow".to_owned())?;
        let mut isolated_context = Context::default();
        let context = if shared_realm {
            &mut shared_context
        } else {
            &mut isolated_context
        };
        if let Err(error) = Script::parse(Source::from_bytes(&bytes), None, context) {
            errors.push(json!({
                "path": normalized_path(path),
                "error": error.to_string(),
            }));
        }
    }

    let report = json!({
        "schema_version": 1,
        "runtime": {
            "crate": "boa_engine",
            "version": "0.21.1",
            "default_features": false,
        },
        "realm_mode": if shared_realm { "shared" } else { "isolated" },
        "selection": "recursive files with .sg or no extension",
        "roots": roots
            .iter()
            .map(|path| normalized_path(path))
            .collect::<Vec<_>>(),
        "files": files.len(),
        "bytes": total_bytes,
        "parse_errors": errors,
        "parse_error_count": errors.len(),
        "elapsed_ms": started.elapsed().as_millis(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot serialize report: {error}"))?
    );
    Ok(errors.is_empty())
}

fn host_add(_this: &JsValue, arguments: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let left = arguments
        .first()
        .cloned()
        .unwrap_or_else(JsValue::undefined)
        .to_number(context)?;
    let right = arguments
        .get(1)
        .cloned()
        .unwrap_or_else(JsValue::undefined)
        .to_number(context)?;
    Ok((left + right).into())
}

fn eval_string(context: &mut Context, source: &[u8]) -> Result<String, String> {
    let value = context
        .eval(Source::from_bytes(source))
        .map_err(|error| error.to_string())?;
    value
        .to_string(context)
        .map(|value| value.to_std_string_escaped())
        .map_err(|error| error.to_string())
}

fn run_fixture(rule_root: &Path) -> Result<bool, String> {
    let started = Instant::now();
    let mut context = Context::default();
    context
        .register_global_builtin_callable(
            js_string!("hostAdd"),
            2,
            NativeFunction::from_fn_ptr(host_add),
        )
        .map_err(|error| error.to_string())?;

    let host_result = eval_string(&mut context, b"hostAdd(20, 22)")?;
    let helper_path = rule_root.join("_runtime_helpers");
    let helper_bytes = fs::read(&helper_path)
        .map_err(|error| format!("cannot read {}: {error}", helper_path.display()))?;
    context
        .eval(Source::from_bytes(&helper_bytes))
        .map_err(|error| error.to_string())?;
    let helper_result = eval_string(
        &mut context,
        br#""a".append("b").appendS("c", "/") + "|" + (7).padStart(3, "0")"#,
    )?;

    let mut audio_context = Context::default();
    audio_context
        .eval(Source::from_bytes(
            br#"
                var included = [];
                function meta(type, name) {
                    globalThis.metaType = type;
                    globalThis.metaName = name;
                }
                function includeScript(name) { included.push(name); }
            "#,
        ))
        .map_err(|error| error.to_string())?;
    let audio_path = rule_root.join("Binary").join("audio.1.sg");
    let audio_bytes = fs::read(&audio_path)
        .map_err(|error| format!("cannot read {}: {error}", audio_path.display()))?;
    audio_context
        .eval(Source::from_bytes(&audio_bytes))
        .map_err(|error| error.to_string())?;
    let audio_result = eval_string(
        &mut audio_context,
        br#"metaType + "|" + metaName + "|" + included.join(",") + "|" + typeof detect"#,
    )?;

    let mut redeclaration_context = Context::default();
    let invalid_redeclaration = redeclaration_context.eval(Source::from_bytes(
        b"function detect() { var value, other; const first = 1, value = 2; }",
    ));

    let mut shared_lexical_context = Context::default();
    shared_lexical_context
        .eval(Source::from_bytes(b"const sharedName = 1;"))
        .map_err(|error| error.to_string())?;
    let shared_lexical_redeclaration = shared_lexical_context
        .eval(Source::from_bytes(b"const sharedName = 2;"))
        .map(|_| None)
        .unwrap_or_else(|error| Some(error.to_string()));

    let mut nintendo_context = Context::default();
    nintendo_context
        .eval(Source::from_bytes(
            b"function meta(type, name) { globalThis.metaName = name; }",
        ))
        .map_err(|error| error.to_string())?;
    let nintendo_path = rule_root
        .join("Binary")
        .join("format_bin.Nintendo-certified-file.1.sg");
    let nintendo_bytes = fs::read(&nintendo_path)
        .map_err(|error| format!("cannot read {}: {error}", nintendo_path.display()))?;
    let nintendo_eval = nintendo_context.eval(Source::from_bytes(&nintendo_bytes));

    let mut limited_context = Context::default();
    limited_context
        .runtime_limits_mut()
        .set_loop_iteration_limit(32);
    let loop_limit_error = limited_context
        .eval(Source::from_bytes(b"for (;;) {}"))
        .map(|_| None)
        .unwrap_or_else(|error| Some(error.to_string()));

    let passed = host_result == "42"
        && helper_result == "a, b/c|007"
        && audio_result == "audio||chunkparsers,soundchips,bytecodeparsers|function"
        && shared_lexical_redeclaration.is_some()
        && nintendo_eval.is_err()
        && loop_limit_error.as_deref().is_some_and(|error| {
            error
                .to_ascii_lowercase()
                .contains("maximum loop iteration limit")
        });
    let report = json!({
        "schema_version": 1,
        "runtime": {
            "crate": "boa_engine",
            "version": "0.21.1",
            "default_features": false,
        },
        "host_function_result": host_result,
        "runtime_helpers_result": helper_result,
        "audio_rule": {
            "path": normalized_path(&audio_path),
            "bytes": audio_bytes.len(),
            "result": audio_result,
        },
        "invalid_var_const_redeclaration": {
            "eval_accepted": invalid_redeclaration.is_ok(),
            "eval_error": invalid_redeclaration.err().map(|error| error.to_string()),
        },
        "shared_const_redeclaration": {
            "second_eval_accepted": shared_lexical_redeclaration.is_none(),
            "second_eval_error": shared_lexical_redeclaration,
        },
        "nintendo_rule": {
            "path": normalized_path(&nintendo_path),
            "bytes": nintendo_bytes.len(),
            "eval_accepted": nintendo_eval.is_ok(),
            "eval_error": nintendo_eval.err().map(|error| error.to_string()),
        },
        "loop_limit_error": loop_limit_error,
        "elapsed_ms": started.elapsed().as_millis(),
        "candidate_compatible_with_fixed_rules": false,
        "passed": passed,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot serialize report: {error}"))?
    );
    Ok(passed)
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: die-boa-rule-runtime-spike \
         <parse-isolated|parse-shared> <rule-root>...\n       \
         die-boa-rule-runtime-spike fixture <main-rule-root>"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        return usage();
    };
    let roots = arguments.map(PathBuf::from).collect::<Vec<_>>();
    if roots.is_empty() {
        return usage();
    }

    let result = if command == "parse-isolated" {
        parse_corpus(&roots, false)
    } else if command == "parse-shared" {
        parse_corpus(&roots, true)
    } else if command == "fixture" && roots.len() == 1 {
        run_fixture(&roots[0])
    } else {
        return usage();
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{collect_rule_files, normalized_path};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should follow Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("die-boa-spike-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn corpus_selection_keeps_sg_and_extensionless_files_only() {
        let root = temporary_directory();
        let nested = root.join("PE");
        fs::create_dir_all(&nested).expect("temporary tree should be created");
        fs::write(root.join("_init"), b"init").expect("helper should be written");
        fs::write(nested.join("rule.sg"), b"rule").expect("rule should be written");
        fs::write(nested.join("notes.txt"), b"notes").expect("non-rule should be written");

        let mut files = Vec::new();
        collect_rule_files(&root, &mut files).expect("tree should be readable");
        files.sort();
        let relative = files
            .iter()
            .map(|path| {
                normalized_path(
                    path.strip_prefix(&root)
                        .expect("selected path should remain under root"),
                )
            })
            .collect::<Vec<_>>();

        fs::remove_dir_all(&root).expect("temporary tree should be removed");
        assert_eq!(relative, ["PE/rule.sg", "_init"]);
    }

    #[test]
    fn path_normalization_uses_forward_slashes() {
        assert_eq!(
            normalized_path(&PathBuf::from(r"db\Binary\audio.1.sg")),
            "db/Binary/audio.1.sg"
        );
    }
}

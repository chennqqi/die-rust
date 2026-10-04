#!/usr/bin/env python3
"""Capture pinned Qt 5/Qt 6 native global HostApi behavior oracles."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import re
import subprocess
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
DIE_SCRIPT_COMMIT = "5d82316c110abf0eb863b50bc679d330e05067b6"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
QT5_IMAGE = "die-rust/upstream-global-host-api-harness:74eaf505"
QT6_IMAGE = "die-rust/upstream-global-host-api-harness-qt6:74eaf505"
DEFAULT_BINARY = "/opt/die-build/src/console/die-global-host-api-harness"
QT5_GLOBALS = (
    "includeScript",
    "_log",
    "_setResult",
    "_isResultPresent",
    "_getNumberOfResults",
    "_removeResult",
    "_isStop",
    "_encodingList",
    "_isConsoleMode",
    "_isLiteMode",
    "_isGuiMode",
    "_isLibraryMode",
    "_breakScan",
    "_getEngineVersion",
    "_getOS",
)
QT6_ALLOWED_ERRORS = {
    "_log()": "%entry@file:log-missing.js:1",
    "_setResult()": "%entry@file:missing-set-result.js:1",
    "_isResultPresent()": "%entry@file:missing-is-present.js:1",
    "_getNumberOfResults()": "%entry@file:missing-count.js:1",
}
QT5_THROWING_CONVERSION_SOURCE = (
    "_getNumberOfResults({toString:function(){"
    "throw new Error('conversion-boom');}})"
)
QT5_THROWING_CONVERSION_BACKTRACE = [
    (
        "<anonymous>() at "
        "query-conversion-throwing_object_count.js:1"
    ),
    "<native>(Error: conversion-boom) at -1",
    "<global>() at query-conversion-throwing_object_count.js:1",
]
QT5_ALLOWED_ERRORS = {
    QT5_THROWING_CONVERSION_SOURCE: {
        "error_name": "Error",
        "error_message": "conversion-boom",
        "error_line": 1,
        "string": "Error: conversion-boom",
        "backtrace": QT5_THROWING_CONVERSION_BACKTRACE,
    },
    "includeScript('probe-include-parse-error')": {
        "error_name": "SyntaxError",
        "error_message": "Parse error",
        "error_line": 1,
        "string": "SyntaxError: Parse error",
        "backtrace": ["<global>() at include-parse-error.js:1"],
    },
    "includeScript('probe-include-runtime-error')": {
        "error_name": "Error",
        "error_message": "include-runtime-boom",
        "error_line": 1,
        "string": "Error: include-runtime-boom",
        "backtrace": [
            "<eval>() at probe-include-runtime-error:1",
            "<native>('probe-include-runtime-error') at -1",
            "<global>() at include-runtime-error.js:1",
        ],
    },
}
QT6_EXPECTED_STDERR = (
    b"%entry@file:query-conversion-extra_present_arguments.js:1\n"
    b"Too many arguments, ignoring 1\n"
    b"%entry@file:query-conversion-extra_count_arguments.js:1\n"
    b"Too many arguments, ignoring 1\n"
)
ISOLATED_QUERY_CASES = {
    "cyclic_plain_object_count": {
        "record_type": "[object Object]",
        "record_name": "PlainObject",
        "qt5": 1,
        "qt6": 1,
    },
    "cyclic_array_count": {
        "record_type": "seed",
        "record_name": "Seed",
        "qt5": 1,
        "qt6": None,
    },
    "proxy_object_count": {
        "record_type": "proxy-type",
        "record_name": "Proxy",
        "qt5": -1,
        "qt6": 1,
    },
    "bigint_count": {
        "record_type": "1",
        "record_name": "BigInt",
        "qt5": -1,
        "qt6": -1,
    },
    "symbol_count": {
        "record_type": "Symbol(probe)",
        "record_name": "Symbol",
        "qt5": -1,
        "qt6": 1,
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _evaluation(step: dict[str, Any]) -> dict[str, Any]:
    return step["evaluation"]


def _record_names(step: dict[str, Any]) -> list[str]:
    return [record["name"] for record in step["records"]]


def _decode_byte_snapshot(
    snapshot: dict[str, Any],
    label: str,
) -> bytes:
    if set(snapshot) != {"bytes", "sha256", "base64"}:
        raise ValueError(f"unexpected {label} byte snapshot fields")
    try:
        data = base64.b64decode(snapshot["base64"], validate=True)
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid {label} base64") from error
    if len(data) != snapshot["bytes"] or sha256(data) != snapshot["sha256"]:
        raise ValueError(f"{label} byte identity drift")
    return data


def validate_isolated_query_conversions(
    observations: dict[str, Any],
    runtime: str,
) -> None:
    if set(observations) != set(ISOLATED_QUERY_CASES):
        raise ValueError("isolated query case inventory drift")
    record_fields = {
        "started",
        "finished",
        "timed_out",
        "exit_code",
        "exit_status",
        "process_error_code",
        "stdout",
        "stderr",
    }
    for case_name, expected in ISOLATED_QUERY_CASES.items():
        record = observations[case_name]
        expected_result = expected[runtime]
        expected_fields = record_fields | (
            set() if expected_result is None else {"observation"}
        )
        if set(record) != expected_fields:
            raise ValueError(f"isolated query record drift: {case_name}")
        stdout = _decode_byte_snapshot(
            record["stdout"],
            f"{case_name} stdout",
        )
        stderr = _decode_byte_snapshot(
            record["stderr"],
            f"{case_name} stderr",
        )
        if (
            record["started"] is not True
            or record["finished"] is not True
            or record["timed_out"] is not False
            or stderr
        ):
            raise ValueError(f"isolated query lifecycle drift: {case_name}")
        if expected_result is None:
            if (
                runtime != "qt6"
                or case_name != "cyclic_array_count"
                or record["exit_status"] != "crash"
                or record["exit_code"] != 11
                or record["process_error_code"] != 1
                or stdout
            ):
                raise ValueError("Qt6 cyclic array crash behavior drift")
            continue
        if (
            record["exit_status"] != "normal"
            or record["exit_code"] != 0
            or record["process_error_code"] != 5
        ):
            raise ValueError(f"isolated query exit drift: {case_name}")
        try:
            decoded = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(
                f"isolated query stdout is not JSON: {case_name}"
            ) from error
        if decoded != record["observation"]:
            raise ValueError(
                f"isolated query replay drift: {case_name}"
            )
        observation = record["observation"]
        if (
            observation.get("schema_version") != 1
            or observation.get("case") != case_name
            or observation["evaluation"].get("number") != expected_result
            or len(observation["final_records"]) != 1
            or observation["final_records"][0]["type"]
            != expected["record_type"]
            or observation["final_records"][0]["name"]
            != expected["record_name"]
        ):
            raise ValueError(
                f"isolated query observation drift: {case_name}"
            )


def validate_observation(
    observation: dict[str, Any],
    runtime: str = "qt5",
) -> None:
    if runtime not in {"qt5", "qt6"}:
        raise ValueError("unsupported runtime profile")
    identities = {
        "schema_version": 5,
        "upstream_commit": UPSTREAM_COMMIT,
        "die_script_commit": DIE_SCRIPT_COMMIT,
        "rules_commit": RULES_COMMIT,
        "qt_version": "5.15.13" if runtime == "qt5" else "6.4.2",
    }
    for key, expected in identities.items():
        if observation.get(key) != expected:
            raise ValueError(f"unexpected {key}")

    observed_errors: dict[str, str] = {}

    def validate_errors(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("is_error") is True:
                source = value.get("source", "")
                if runtime == "qt6" and source in QT6_ALLOWED_ERRORS:
                    if (
                        value.get("error_name") != "Error"
                        or value.get("error_message")
                        != "Insufficient arguments"
                        or value.get("error_line") != 1
                        or value.get("string")
                        != "Error: Insufficient arguments"
                        or value.get("backtrace")
                        != [QT6_ALLOWED_ERRORS[source]]
                    ):
                        raise ValueError(
                            "unexpected Qt6 missing-argument error"
                        )
                elif runtime == "qt5" and source in QT5_ALLOWED_ERRORS:
                    expected = QT5_ALLOWED_ERRORS[source]
                    if any(
                        value.get(key) != expected_value
                        for key, expected_value in expected.items()
                    ):
                        raise ValueError(
                            "unexpected Qt5 JavaScript error"
                        )
                else:
                    raise ValueError("unexpected JavaScript error")
                observed_errors[source] = value["error_message"]
            for child in value.values():
                validate_errors(child)
        elif isinstance(value, list):
            for child in value:
                validate_errors(child)

    validate_errors(observation)
    expected_error_sources = (
        set(QT5_ALLOWED_ERRORS)
        if runtime == "qt5"
        else set(QT6_ALLOWED_ERRORS)
    )
    if set(observed_errors) != expected_error_sources:
        raise ValueError("missing expected JavaScript error")

    methods = observation["surface"]["methods"]
    if set(methods) != set(QT5_GLOBALS) | {"_getQtVersion"}:
        raise ValueError("unexpected native global surface")
    for name in (
        QT5_GLOBALS
        if runtime == "qt5"
        else QT5_GLOBALS + ("_getQtVersion",)
    ):
        if methods[name]["type"].get("string") != "function":
            raise ValueError(f"{name} is not a function")
        if methods[name]["length"].get("number") != 0:
            raise ValueError(f"{name} wrapper length is not zero")
    if runtime == "qt5":
        if (
            methods["_getQtVersion"]["type"].get("string") != "undefined"
            or not methods["_getQtVersion"]["length"]["is_null"]
        ):
            raise ValueError("Qt5 unexpectedly exposes _getQtVersion")

    steps = observation["results"]["steps"]
    if [len(step["records"]) for step in steps] != [1, 2, 2, 2, 1, 1, 1]:
        raise ValueError("unexpected result mutation sequence")
    if _record_names(steps[1]) != ["Rust", "rust"]:
        raise ValueError("case-insensitive duplicate was not retained")
    if _evaluation(steps[2]).get("boolean") is not True:
        raise ValueError("case-insensitive result lookup failed")
    if _evaluation(steps[3]).get("number") != 2:
        raise ValueError("empty result type did not count all records")
    if _record_names(steps[4]) != ["rust"]:
        raise ValueError("removeResult did not remove only the first match")
    if _record_names(steps[5]) != ["rust"]:
        raise ValueError("removed result was not blocked from re-add")
    if _record_names(steps[6]) != ["rust"]:
        raise ValueError("empty removeResult name unexpectedly acted as wildcard")

    array_removal = observation["array_removal"]
    if [record["name"] for record in array_removal["before"]] != [
        "Enigma",
        "Denuvo",
    ]:
        raise ValueError("unexpected array-removal fixture seed")
    if _record_names(array_removal["removal"]) != ["Enigma", "Denuvo"]:
        raise ValueError("array removeResult unexpectedly removed records")
    if _record_names(array_removal["add_combined"]) != ["Enigma", "Denuvo"]:
        raise ValueError("array string block did not suppress combined result")

    missing = observation["missing_arguments"]
    missing_record = missing["set_result"]["records"]
    if runtime == "qt5":
        if len(missing_record) != 1 or {
            missing_record[0][key]
            for key in ("type", "name", "version", "info")
        } != {"undefined"}:
            raise ValueError("missing _setResult arguments did not stringify")
        if _evaluation(missing["is_present"]).get("boolean") is not True:
            raise ValueError(
                "missing result query did not match undefined record"
            )
        if _evaluation(missing["count"]).get("number") != 1:
            raise ValueError("missing result count did not count all records")
    elif (
        missing_record
        or not _evaluation(missing["set_result"])["is_error"]
        or not _evaluation(missing["is_present"])["is_error"]
        or not _evaluation(missing["count"])["is_error"]
    ):
        raise ValueError("Qt6 missing arguments did not fail atomically")

    conversions = observation["query_conversions"]
    if (
        conversions["seed_record_count"] != 17
        or len(conversions["final_records"]) != 23
    ):
        raise ValueError("query conversion fixture drift")
    expected_utf16_records = [
        ("Surrogate", "\ud800"),
        ("LoneLowSurrogate", "\udc00"),
        ("DoubleHighSurrogate", "\ud800\ud800"),
        ("DoubleLowSurrogate", "\udc00\udc00"),
        ("ReversedSurrogate", "\udc00\ud800"),
        ("ValidSurrogatePair", "\U00010000"),
    ]
    if [
        (record["name"], record["type"])
        for record in conversions["final_records"][-6:]
    ] != expected_utf16_records:
        raise ValueError("query conversion UTF-16 records drift")
    evaluations = conversions["evaluations"]
    expected_names = {
        "undefined_count",
        "null_count",
        "array_single_present",
        "array_multiple_present",
        "array_count",
        "plain_object_count",
        "custom_object_count",
        "throwing_object_count",
        "nan_count",
        "positive_infinity_count",
        "negative_infinity_count",
        "negative_zero_count",
        "large_integer_count",
        "proxy_type",
        "bigint_type",
        "symbol_type",
        "max_safe_integer_count",
        "above_max_safe_literal_count",
        "above_max_safe_even_count",
        "negative_max_safe_integer_count",
        "negative_large_integer_count",
        "negative_above_max_safe_even_count",
        "invalid_utf16_count",
        "lone_low_surrogate_count",
        "double_high_surrogate_count",
        "double_low_surrogate_count",
        "reversed_surrogate_count",
        "valid_surrogate_pair_count",
        "extra_present_arguments",
        "extra_count_arguments",
    }
    if set(evaluations) != expected_names:
        raise ValueError("query conversion case inventory drift")
    for name in (
        "array_single_present",
        "array_multiple_present",
        "extra_present_arguments",
    ):
        if evaluations[name].get("boolean") is not True:
            raise ValueError(f"query conversion boolean drift: {name}")
    for name in (
        "array_count",
        "plain_object_count",
        "custom_object_count",
        "nan_count",
        "positive_infinity_count",
        "negative_infinity_count",
        "negative_zero_count",
        "large_integer_count",
        "max_safe_integer_count",
        "above_max_safe_literal_count",
        "above_max_safe_even_count",
        "negative_max_safe_integer_count",
        "negative_large_integer_count",
        "negative_above_max_safe_even_count",
        "invalid_utf16_count",
        "lone_low_surrogate_count",
        "double_high_surrogate_count",
        "double_low_surrogate_count",
        "reversed_surrogate_count",
        "valid_surrogate_pair_count",
        "extra_count_arguments",
    ):
        if evaluations[name].get("number") != 1:
            raise ValueError(f"query conversion count drift: {name}")
    if runtime == "qt5":
        if (
            evaluations["undefined_count"].get("number") != 0
            or evaluations["null_count"].get("number") != 0
            or not evaluations["throwing_object_count"]["is_error"]
            or evaluations["proxy_type"].get("string") != "undefined"
            or evaluations["bigint_type"].get("string") != "undefined"
            or evaluations["symbol_type"].get("string") != "undefined"
        ):
            raise ValueError("Qt5 query conversion behavior drift")
    elif (
        evaluations["undefined_count"].get("number") != 17
        or evaluations["null_count"].get("number") != 17
        or evaluations["throwing_object_count"].get("number") != 0
        or evaluations["proxy_type"].get("string") != "function"
        or evaluations["bigint_type"].get("string") != "undefined"
        or evaluations["symbol_type"].get("string") != "function"
    ):
        raise ValueError("Qt6 query conversion behavior drift")
    validate_isolated_query_conversions(
        observation["isolated_query_conversions"],
        runtime,
    )

    stop = observation["stop"]
    if stop["compiler"]["records"]:
        raise ValueError("first-wrapper compiler result was retained")
    if len(stop["protection"]["records"]) != 1:
        raise ValueError("first-wrapper protection result was not retained")
    if not stop["protection"]["engine_is_stopped"]:
        raise ValueError("first-wrapper internal stop was not set")
    if _evaluation(stop["js_stop_before_break"]).get("boolean") is not False:
        raise ValueError("_isStop unexpectedly observes internal wrapper stop")
    if _evaluation(stop["js_stop_after_break"]).get("boolean") is not True:
        raise ValueError("_breakScan did not set the PDSTRUCT stop")

    include = observation["include"]
    if _evaluation(include["value_after_first"]).get("number") != 1:
        raise ValueError("case-insensitive include failed")
    if _evaluation(include["value_after_second"]).get("number") != 2:
        raise ValueError("repeated include did not re-evaluate")
    missing_include_error = "Cannot find: missing-include"
    parse_include_error = (
        "includeScript probe-include-parse-error: 1: "
        + (
            "SyntaxError: Parse error"
            if runtime == "qt5"
            else "SyntaxError: Expected token `}'"
        )
    )
    runtime_include_error = (
        "includeScript probe-include-runtime-error: 1: "
        "Error: include-runtime-boom"
    )
    if include["errors_after_missing"] != [missing_include_error]:
        raise ValueError("unexpected missing include diagnostic")
    if include["errors_after_parse"] != [
        missing_include_error,
        parse_include_error,
    ]:
        raise ValueError("unexpected parse include diagnostic")
    if include["errors_after_runtime"] != [
        missing_include_error,
        parse_include_error,
        runtime_include_error,
    ]:
        raise ValueError("unexpected runtime include diagnostic")
    if _evaluation(include["parse_visibility"]).get("string") != "undefined":
        raise ValueError("parse-error include executed source")
    if (
        _evaluation(include["runtime_before_visibility"]).get("string")
        != "number"
        or _evaluation(include["runtime_after_visibility"]).get("string")
        != "undefined"
    ):
        raise ValueError("runtime-error include execution boundary changed")
    if runtime == "qt5":
        if (
            not _evaluation(include["parse_error"])["is_error"]
            or not _evaluation(include["runtime_error"])["is_error"]
        ):
            raise ValueError("Qt5 include errors did not propagate")
    elif (
        not _evaluation(include["parse_error"])["is_undefined"]
        or not _evaluation(include["runtime_error"])["is_undefined"]
    ):
        raise ValueError("Qt6 include errors unexpectedly propagated")

    info = observation["info"]
    if runtime == "qt5":
        if info["log_messages"] != ["undefined", "null", "42"]:
            raise ValueError("_log conversion behavior changed")
        if [
            info["pd_info_initial"],
            info["pd_info_after_missing"],
            info["pd_info_after_null"],
            info["pd_info_after_number"],
            info["pd_info_after_encoding"],
        ] != ["", "undefined", "null", "42", "42"]:
            raise ValueError("Qt5 _log PDSTRUCT behavior changed")
        if _evaluation(info["encoding_call"]).get("boolean") is not False:
            raise ValueError("_encodingList return value changed")
        if (
            info["encoding_message_count"] != 104
            or info["encoding_first"] != ""
            or info["encoding_last"] != "TIS-620"
            or info["encoding_messages_sha256"]
            != (
                "4ca2afaa9d6924630d5329ad327d6651d"
                "eb705e8bc4ecc9b46fecaf030474d02"
            )
        ):
            raise ValueError("encoding list behavior changed")
    elif (
        info["log_messages"] != ["", "42"]
        or not _evaluation(info["missing"])["is_error"]
        or [
            info["pd_info_initial"],
            info["pd_info_after_missing"],
            info["pd_info_after_null"],
            info["pd_info_after_number"],
            info["pd_info_after_encoding"],
        ]
        != ["", "", "", "42", "42"]
        or not _evaluation(info["encoding_call"])["is_undefined"]
        or info["encoding_message_count"] != 0
        or info["encoding_first"] != ""
        or info["encoding_last"] != ""
        or info["encoding_messages_sha256"] != sha256(b"")
    ):
        raise ValueError("unexpected Qt6 log/encoding behavior")

    modes = observation["modes"]
    if (
        modes["die"]["application_name"] != "die"
        or modes["die"]["console"].get("boolean") is not True
        or modes["die"]["gui"].get("boolean") is not False
        or modes["die"]["lite"].get("boolean") is not False
        or modes["die"]["library"].get("boolean") is not False
    ):
        raise ValueError("console mode behavior changed")
    if modes["diel"]["lite"].get("boolean") is not True:
        raise ValueError("lite mode behavior changed")
    if (
        modes["empty_requested"]["application_name"]
        != "die-global-host-api-harness"
        or modes["empty_requested"]["library"].get("boolean") is not False
    ):
        raise ValueError("empty application-name fallback changed")
    embedded = modes["empty_argv0_process"]
    if set(embedded) != {
        "started",
        "finished",
        "timed_out",
        "exit_code",
        "exit_status",
        "process_error_code",
        "stdout",
        "stderr",
        "observation",
    }:
        raise ValueError("empty argv[0] process record drift")
    embedded_stdout = _decode_byte_snapshot(
        embedded["stdout"],
        "empty argv[0] stdout",
    )
    embedded_stderr = _decode_byte_snapshot(
        embedded["stderr"],
        "empty argv[0] stderr",
    )
    try:
        replayed_embedded = json.loads(embedded_stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("empty argv[0] stdout is not JSON") from error
    embedded_observation = embedded.get("observation", {})
    if (
        embedded["started"] is not True
        or embedded["finished"] is not True
        or embedded["timed_out"] is not False
        or embedded["exit_code"] != 0
        or embedded["exit_status"] != "normal"
        or embedded["process_error_code"] != 5
        or embedded_stderr
        or replayed_embedded != embedded_observation
        or embedded_observation.get("schema_version") != 1
        or embedded_observation.get("case") != "empty_argv0_mode"
        or embedded_observation.get("application_name") != ""
        or embedded_observation.get("console", {}).get("boolean") is not False
        or embedded_observation.get("gui", {}).get("boolean") is not False
        or embedded_observation.get("lite", {}).get("boolean") is not False
        or embedded_observation.get("library", {}).get("boolean") is not True
    ):
        raise ValueError("empty argv[0] library-mode behavior changed")
    version = modes["engine_version"].get("string", "")
    if not re.fullmatch(r"9\.9\.9\.\d{4}\.\d{2}\.\d{2}", version):
        raise ValueError("engine version does not expose the compile date")
    if modes["os"].get("string") != "Linux Ubuntu x64":
        raise ValueError("unexpected fixed oracle OS string")
    if runtime == "qt5":
        if "qt_version" in modes:
            raise ValueError("Qt5 unexpectedly called _getQtVersion")
    elif modes["qt_version"].get("string") != "6.4.2":
        raise ValueError("Qt6 _getQtVersion return changed")


def parse_observation(
    stdout: bytes,
    stderr: bytes,
    returncode: int,
    runtime: str = "qt5",
) -> dict[str, Any]:
    if returncode != 0:
        raise ValueError(f"harness exited with {returncode}")
    expected_stderr = b"" if runtime == "qt5" else QT6_EXPECTED_STDERR
    if stderr != expected_stderr:
        raise ValueError("harness stderr changed")
    try:
        text = stdout.decode("utf-8")
        observation, end = json.JSONDecoder().raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("harness did not emit one UTF-8 JSON document") from error
    if text[end:].strip():
        raise ValueError("harness emitted trailing stdout")
    validate_observation(observation, runtime)
    return observation


def stream_record(data: bytes) -> dict[str, Any]:
    return {
        "bytes": len(data),
        "sha256": sha256(data),
        "base64": base64.b64encode(data).decode("ascii"),
    }


def validate_streams(
    streams: dict[str, Any],
    observation: dict[str, Any],
    runtime: str,
) -> None:
    if set(streams) != {"exit_code", "stdout", "stderr"}:
        raise ValueError("unexpected stream fields")
    if streams["exit_code"] != 0:
        raise ValueError("recorded harness exit changed")
    decoded = {}
    for name in ("stdout", "stderr"):
        record = streams[name]
        if set(record) != {"bytes", "sha256", "base64"}:
            raise ValueError(f"unexpected {name} stream fields")
        try:
            data = base64.b64decode(record["base64"], validate=True)
        except (TypeError, ValueError) as error:
            raise ValueError(f"invalid {name} base64") from error
        if len(data) != record["bytes"] or sha256(data) != record["sha256"]:
            raise ValueError(f"{name} stream identity drift")
        decoded[name] = data
    replayed = parse_observation(
        decoded["stdout"],
        decoded["stderr"],
        streams["exit_code"],
        runtime,
    )
    if replayed != observation:
        raise ValueError("raw stdout does not match observation")


def inspect_image(image: str) -> tuple[str, str]:
    process = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        capture_output=True,
    )
    document = json.loads(process.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision", ""
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError("harness image revision mismatch")
    return document["Id"], revision


def binary_sha256(image: str, binary: str) -> str:
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            image,
            "sha256sum",
            binary,
        ],
        check=True,
        capture_output=True,
    )
    return process.stdout.decode("ascii").split()[0]


def observe(image: str, binary: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--pids-limit",
            "128",
            image,
            binary,
        ],
        check=False,
        capture_output=True,
    )


def build_report(
    repo: pathlib.Path,
    runtime: str = "qt5",
    image: str | None = None,
    binary: str = DEFAULT_BINARY,
) -> dict[str, Any]:
    if runtime not in {"qt5", "qt6"}:
        raise ValueError("unsupported runtime profile")
    if image is None:
        image = QT5_IMAGE if runtime == "qt5" else QT6_IMAGE
    image_id, revision = inspect_image(image)
    process = observe(image, binary)
    observation = parse_observation(
        process.stdout, process.stderr, process.returncode, runtime
    )
    sources = {}
    for relative in (
        "tools/upstream/global_host_api_harness_main.cpp",
        f"tools/upstream/Dockerfile.global-host-api-harness-{runtime}",
        "tools/upstream/probe_global_host_api.py",
    ):
        data = (repo / relative).read_bytes()
        sources[relative] = {"bytes": len(data), "sha256": sha256(data)}
    streams = {
        "exit_code": process.returncode,
        "stdout": stream_record(process.stdout),
        "stderr": stream_record(process.stderr),
    }
    validate_streams(streams, observation, runtime)
    return {
        "schema_version": 5,
        "generator": "tools/upstream/probe_global_host_api.py",
        "runtime_profile": runtime,
        "image": {
            "name": image,
            "id": image_id,
            "revision": revision,
        },
        "binary": {"path": binary, "sha256": binary_sha256(image, binary)},
        "sources": sources,
        "streams": streams,
        "observation": observation,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    repo = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument("--runtime", choices=("qt5", "qt6"), default="qt5")
    parser.add_argument("--image")
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    output = args.output or (
        repo / f"docs/research/data/global-host-api-{args.runtime}.json"
    )
    report = build_report(repo, args.runtime, args.image, args.binary)
    output.write_text(
        json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

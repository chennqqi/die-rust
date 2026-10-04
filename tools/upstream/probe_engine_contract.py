#!/usr/bin/env python3
"""Probe fixed DIE engine filtering, sorting, cancellation, and entry points."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
from typing import Any

from probe_rule_orchestration import load_and_verify_fixture


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
IMAGE = "die-rust/engine-contract-harness-qt5:74eaf505"
BINARY = "/opt/die-build/src/console/die-engine-contract-harness"
HARNESS_SOURCE = "tools/upstream/engine_contract_harness_main.cpp"
HARNESS_DOCKERFILE = (
    "tools/upstream/Dockerfile.engine-contract-harness-qt5"
)
SOURCE_PATHS = (
    "/opt/die-source/XScanEngine/xscanengine.h",
    "/opt/die-source/XScanEngine/xscanengine.cpp",
    "/opt/die-source/die_script/die_script.h",
    "/opt/die-source/die_script/die_script.cpp",
    "/opt/die-source/Formats/xbinary.cpp",
    "/opt/die-source/Formats/subdevice.cpp",
    "/opt/die-source/Formats/xbinary.h",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def docker_bytes(entrypoint: str, *arguments: str) -> bytes:
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            entrypoint,
            IMAGE,
            *arguments,
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError(f"{entrypoint} wrote stderr")
    return process.stdout


def inspect_image() -> tuple[str, str]:
    process = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
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


def audit_source_contracts() -> dict[str, Any]:
    sources = {
        path: docker_bytes("/bin/cat", path) for path in SOURCE_PATHS
    }
    header = sources[SOURCE_PATHS[0]].decode("utf-8")
    scan_implementation = sources[SOURCE_PATHS[1]].decode("utf-8")
    script_header = sources[SOURCE_PATHS[2]].decode("utf-8")
    implementation = sources[SOURCE_PATHS[3]].decode("utf-8")
    binary_implementation = sources[SOURCE_PATHS[4]].decode("utf-8")
    subdevice_implementation = sources[SOURCE_PATHS[5]].decode("utf-8")
    binary_header = sources[SOURCE_PATHS[6]].decode("utf-8")

    options_match = re.search(
        r"struct\s+SCAN_OPTIONS\s*\{(?P<body>.*?)\n\s*\};",
        header,
        re.DOTALL,
    )
    if options_match is None:
        raise ValueError("SCAN_OPTIONS definition not found")
    options_body = options_match.group("body")
    public_option_absent = "sSignatureFilePath" not in options_body
    name_option_present = "sSignatureName" in options_body
    private_parameter_present = (
        "const QString &sSignatureFilePath" in script_header
    )
    protected_passes_empty = bool(
        re.search(
            r"DiE_Script::_processDetect\(.*?\)\s*\{\s*"
            r"processDetect\(.*?,\s*\"\",\s*bAddUnknown,\s*"
            r"pPdStruct\);\s*\}",
            implementation,
            re.DOTALL,
        )
    )
    call_argument_count = len(
        re.findall(r"\bprocessDetect\s*\(", implementation)
    )
    reachable = not (
        public_option_absent
        and private_parameter_present
        and protected_passes_empty
        and call_argument_count == 2
    )
    if not name_option_present or reachable:
        raise ValueError("signature file-path reachability assumptions changed")

    small_copy_match = re.search(
        r"pBuffer\s*=\s*new char\[nSize\];.*?"
        r"XBinary::read_array_process\("
        r"_pDevice,\s*0,\s*pBuffer,\s*nSize,\s*pPdStruct\);.*?"
        r"bufDevice->setData\(pBuffer,\s*nSize\);",
        scan_implementation,
        re.DOTALL,
    )
    safe_read_match = re.search(
        r"qint64 XBinary::safeReadData\(.*?\n\}"
        r"\n\nqint64 XBinary::safeWriteData",
        binary_implementation,
        re.DOTALL,
    )
    if safe_read_match is None:
        raise ValueError("safeReadData implementation not found")
    safe_read_body = safe_read_match.group(0)
    safe_read_silent = (
        "if (nCurrentSize <= 0)" in safe_read_body
        and "break;" in safe_read_body
        and "setPdStructErrorString" not in safe_read_body
    )
    range_gate = bool(
        re.search(
            r"scanSubdevice\(.*?\).*?"
            r"if \(XBinary::isOffsetAndSizeValid\("
            r"pDevice,\s*nOffset,\s*nSize\)\)",
            scan_implementation,
            re.DOTALL,
        )
    )
    range_check = bool(
        re.search(
            r"isOffsetAndSizeValid\(.*?qint64 nOffset,\s*qint64 nSize\)"
            r".*?if \(nSize > 0\).*?"
            r"nOffset \+ nSize - 1",
            binary_implementation,
            re.DOTALL,
        )
    )
    subdevice_ignores_seek = bool(
        re.search(
            r"setSize\(nSize\);.*?pDevice->seek\(nOffset\);",
            subdevice_implementation,
            re.DOTALL,
        )
    )
    device_assumptions = {
        "small_device_copy_ignores_read_count": (
            small_copy_match is not None
        ),
        "safe_read_stops_without_pd_error_on_nonpositive_read": (
            safe_read_silent
        ),
        "scan_subdevice_uses_offset_size_gate": range_gate,
        "range_gate_requires_positive_size_and_valid_last_byte": (
            range_check
        ),
        "subdevice_constructor_ignores_parent_seek_result": (
            subdevice_ignores_seek
        ),
    }
    failed_device_assumptions = [
        name for name, value in device_assumptions.items() if not value
    ]
    if failed_device_assumptions:
        raise ValueError(
            "device source assumptions changed: "
            f"{failed_device_assumptions}"
        )

    pdstruct_match = re.search(
        r"struct\s+PDSTRUCT\s*\{(?P<body>.*?)\n\s*\};",
        binary_header,
        re.DOTALL,
    )
    if pdstruct_match is None:
        raise ValueError("PDSTRUCT definition not found")
    pdstruct_body = pdstruct_match.group("body")
    stop_setter_match = re.search(
        r"void XBinary::setPdStructStopped\(.*?\n\}",
        binary_implementation,
        re.DOTALL,
    )
    stop_reader_match = re.search(
        r"bool XBinary::isPdStructNotCanceled\(.*?\n\}",
        binary_implementation,
        re.DOTALL,
    )
    if stop_setter_match is None or stop_reader_match is None:
        raise ValueError("PDSTRUCT stop accessors not found")
    cancellation_assumptions = {
        "stop_flag_is_plain_bool": bool(
            re.search(r"\bbool\s+bIsStop\s*;", pdstruct_body)
        )
        and "atomic" not in pdstruct_body,
        "stop_setter_is_plain_assignment": (
            "pPdStruct->bIsStop = true;"
            in stop_setter_match.group(0)
        ),
        "stop_reader_is_plain_read": (
            "if (pPdStruct->bIsStop)"
            in stop_reader_match.group(0)
        ),
    }
    failed_cancellation_assumptions = [
        name
        for name, value in cancellation_assumptions.items()
        if not value
    ]
    if failed_cancellation_assumptions:
        raise ValueError(
            "cancellation source assumptions changed: "
            f"{failed_cancellation_assumptions}"
        )

    return {
        "public_scan_options_has_signature_name": name_option_present,
        "public_scan_options_has_signature_file_path": (
            not public_option_absent
        ),
        "private_process_detect_has_signature_file_path": (
            private_parameter_present
        ),
        "protected_process_detect_passes_empty_path": protected_passes_empty,
        "implementation_process_detect_occurrences": call_argument_count,
        "public_runtime_filter_reachable": reachable,
        "device_contracts": device_assumptions,
        "cancellation_contracts": cancellation_assumptions,
        "sources": {
            path: {
                "bytes": len(data),
                "sha256": sha256(data),
            }
            for path, data in sources.items()
        },
    }


def case_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cases = document["cases"]
    if document["case_count"] != len(cases):
        raise ValueError("harness case count mismatch")
    result = {case["id"]: case for case in cases}
    if len(result) != len(cases):
        raise ValueError("duplicate harness case id")
    return result


def names(case: dict[str, Any]) -> list[str]:
    return [record["name"] for record in case["records"]]


def validate(document: dict[str, Any]) -> dict[str, bool]:
    if document["upstream_commit"] != UPSTREAM_COMMIT:
        raise ValueError("harness upstream commit mismatch")
    cases = case_map(document)
    expected_ids = {
        "filter_all",
        "filter_exact_extra",
        "filter_missing",
        "filter_case_mismatch",
        "filter_deep_disabled",
        "filter_deep_enabled",
        "sort_disabled",
        "sort_enabled",
        "callback_continue",
        "callback_stop_first",
        "callback_stop_second",
        "callback_stop_last",
        "external_stop_second",
        "post_cancel_fresh_state_recovery",
        "break_scan",
        "pre_stopped",
        "entry_file",
        "entry_memory",
        "entry_device",
        "entry_subdevice",
        "device_chunked_read",
        "device_early_eof",
        "device_read_error",
        "device_seek_error",
        "device_sequential",
        "device_initial_position",
        "subdevice_chunked_read",
        "subdevice_early_eof",
        "subdevice_read_error",
        "subdevice_seek_error",
        "subdevice_sequential",
        "subdevice_negative_offset",
        "subdevice_zero_size",
        "subdevice_negative_size",
        "subdevice_offset_at_end",
        "subdevice_crosses_end",
        "subdevice_exact_tail",
    }
    if set(cases) != expected_ids:
        raise ValueError("unexpected harness case inventory")

    incomplete_ids = (
        "device_early_eof",
        "device_read_error",
        "device_seek_error",
        "device_sequential",
        "subdevice_early_eof",
        "subdevice_read_error",
        "subdevice_seek_error",
        "subdevice_sequential",
    )
    invalid_range_ids = (
        "subdevice_negative_offset",
        "subdevice_zero_size",
        "subdevice_negative_size",
        "subdevice_offset_at_end",
        "subdevice_crosses_end",
    )
    successful_boundary_ids = (
        "device_chunked_read",
        "device_initial_position",
        "subdevice_chunked_read",
        "subdevice_exact_tail",
        *incomplete_ids,
    )

    relationships = {
        "signature_name_exact_match_selects_one_rule": (
            names(cases["filter_exact_extra"]) == ["Extra normal"]
        ),
        "signature_name_is_case_sensitive": (
            names(cases["filter_case_mismatch"]) == ["Unknown"]
        ),
        "missing_signature_adds_unknown": (
            names(cases["filter_missing"]) == ["Unknown"]
        ),
        "deep_filter_still_applies_to_exact_name": (
            names(cases["filter_deep_disabled"]) == ["Unknown"]
            and names(cases["filter_deep_enabled"]) == ["Main deep"]
        ),
        "sort_disabled_preserves_insertion_order": (
            names(cases["sort_disabled"])
            == ["Packer last", "Format first", "Compiler middle"]
        ),
        "sort_enabled_orders_by_type_priority": (
            names(cases["sort_enabled"])
            == ["Format first", "Compiler middle", "Packer last"]
        ),
        "callback_false_keeps_current_then_stops": (
            names(cases["callback_stop_first"]) == ["Priority one"]
            and len(cases["callback_stop_first"]["callback_events"]) == 1
            and cases["callback_stop_first"]["pd_stopped"]
            and not cases["callback_stop_first"]["pd_success"]
        ),
        "callback_false_at_second_keeps_two_record_prefix": (
            names(cases["callback_stop_second"])
            == ["Priority one", "Priority two"]
            and len(cases["callback_stop_second"]["callback_events"]) == 2
            and cases["callback_stop_second"]["pd_stopped"]
            and not cases["callback_stop_second"]["pd_success"]
        ),
        "callback_false_at_last_keeps_complete_records_but_cancels": (
            names(cases["callback_stop_last"])
            == ["Priority one", "Priority two", "Priority four"]
            and len(cases["callback_stop_last"]["callback_events"]) == 3
            and cases["callback_stop_last"]["pd_stopped"]
            and not cases["callback_stop_last"]["pd_success"]
        ),
        "synchronized_external_stop_at_second_keeps_current_rule": (
            names(cases["external_stop_second"])
            == ["Priority one", "Priority two"]
            and len(cases["external_stop_second"]["callback_events"]) == 2
            and cases["external_stop_second"]["external_stop_writes"] == 1
            and cases["external_stop_second"][
                "external_stop_thread_distinct"
            ]
            and cases["external_stop_second"]["pd_stopped"]
            and not cases["external_stop_second"]["pd_success"]
        ),
        "fresh_state_recovers_same_engine_after_cancel": (
            [
                record["name"]
                for record in cases[
                    "post_cancel_fresh_state_recovery"
                ]["canceled"]["records"]
            ]
            == ["Priority one", "Priority two"]
            and cases["post_cancel_fresh_state_recovery"]["canceled"][
                "pd_stopped"
            ]
            and not cases["post_cancel_fresh_state_recovery"][
                "canceled"
            ]["pd_success"]
            and [
                record["name"]
                for record in cases[
                    "post_cancel_fresh_state_recovery"
                ]["fresh"]["records"]
            ]
            == ["Priority one", "Priority two", "Priority four"]
            and not cases["post_cancel_fresh_state_recovery"]["fresh"][
                "pd_stopped"
            ]
            and cases["post_cancel_fresh_state_recovery"]["fresh"][
                "pd_success"
            ]
        ),
        "break_scan_keeps_current_then_stops": (
            names(cases["break_scan"]) == ["Break first"]
            and cases["break_scan"]["pd_stopped"]
            and not cases["break_scan"]["pd_success"]
        ),
        "pre_stopped_adds_unknown": (
            names(cases["pre_stopped"]) == ["Unknown"]
            and cases["pre_stopped"]["pd_stopped"]
        ),
        "entry_points_are_semantically_equal": (
            cases["entry_file"]["records"]
            == cases["entry_memory"]["records"]
            == cases["entry_device"]["records"]
            == cases["entry_subdevice"]["records"]
        ),
        "chunked_direct_read_completes": (
            cases["device_chunked_read"]["bytes_returned"] == 35
            and cases["device_chunked_read"]["read_returns"]
            == ["3"] * 11 + ["2"]
        ),
        "chunked_subdevice_parent_overreads_one_buffered_byte": (
            cases["subdevice_chunked_read"]["result_size"] == 35
            and cases["subdevice_chunked_read"]["bytes_returned"] == 36
            and cases["subdevice_chunked_read"]["read_returns"]
            == ["3"] * 12
        ),
        "incomplete_device_reads_are_silent_success": all(
            names(cases[case_id]) == ["Priority one"]
            and cases[case_id]["errors"] == []
            and cases[case_id]["pd_error"] == ""
            and cases[case_id]["pd_success"]
            and cases[case_id]["pd_finished"]
            and cases[case_id]["bytes_returned"]
            < cases[case_id]["result_size"]
            for case_id in incomplete_ids
        ),
        "read_error_is_only_device_local": (
            cases["device_read_error"]["device_error"]
            == "injected read error"
            and cases["subdevice_read_error"]["device_error"]
            == "injected read error"
            and cases["device_read_error"]["read_returns"] == ["-1"]
            and cases["subdevice_read_error"]["read_returns"] == ["-1"]
        ),
        "seek_failure_and_sequential_device_do_not_read": all(
            cases[case_id]["seek_calls"] >= 1
            and cases[case_id]["read_calls"] == 0
            for case_id in (
                "device_seek_error",
                "device_sequential",
                "subdevice_seek_error",
                "subdevice_sequential",
            )
        ),
        "initial_device_position_is_reset_then_consumed": (
            cases["device_initial_position"]["seek_positions"]
            == ["7", "0"]
            and cases["device_initial_position"]["final_position"] == 35
        ),
        "invalid_subdevice_ranges_return_zero_without_io": all(
            not cases[case_id]["range_valid"]
            and cases[case_id]["result_size"] == 0
            and cases[case_id]["result_filetype"] == "Unknown"
            and cases[case_id]["records"] == []
            and cases[case_id]["errors"] == []
            and cases[case_id]["seek_calls"] == 0
            and cases[case_id]["read_calls"] == 0
            and not cases[case_id]["pd_success"]
            and not cases[case_id]["pd_finished"]
            and cases[case_id]["pd_n_finished"] == 0
            for case_id in invalid_range_ids
        ),
        "exact_tail_subdevice_is_accepted": (
            cases["subdevice_exact_tail"]["range_valid"]
            and cases["subdevice_exact_tail"]["result_size"] == 1
            and cases["subdevice_exact_tail"]["bytes_returned"] == 1
            and names(cases["subdevice_exact_tail"])
            == ["Priority one"]
        ),
        "successful_boundary_cases_keep_forced_binary_result": all(
            cases[case_id]["result_filetype"] == "Binary"
            and names(cases[case_id]) == ["Priority one"]
            and cases[case_id]["errors"] == []
            for case_id in successful_boundary_ids
        ),
    }
    failed = [name for name, value in relationships.items() if not value]
    if failed:
        raise ValueError(f"engine contract relationships failed: {failed}")
    return relationships


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
    raw_dir: pathlib.Path,
) -> dict[str, Any]:
    repo = pathlib.Path(__file__).resolve().parents[2]
    _, manifest_sha256 = load_and_verify_fixture(
        fixture_dir, manifest_path
    )
    image_id, revision = inspect_image()
    binary_digest = docker_bytes("/usr/bin/sha256sum", BINARY).split()[0]

    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--mount",
            f"type=bind,source={fixture_dir},target=/fixture,readonly",
            "--entrypoint",
            BINARY,
            IMAGE,
            "/fixture",
        ],
        check=False,
        capture_output=True,
    )
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "engine-contract.stdout").write_bytes(process.stdout)
    (raw_dir / "engine-contract.stderr").write_bytes(process.stderr)
    if process.returncode != 0 or process.stderr:
        raise ValueError("engine contract harness failed")
    document = json.loads(process.stdout)
    relationships = validate(document)
    source_audit = audit_source_contracts()

    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_engine_contract.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "platform": "linux-amd64-qt5",
        "harness_inputs": {
            "source": {
                "path": HARNESS_SOURCE,
                "sha256": sha256((repo / HARNESS_SOURCE).read_bytes()),
            },
            "dockerfile": {
                "path": HARNESS_DOCKERFILE,
                "sha256": sha256(
                    (repo / HARNESS_DOCKERFILE).read_bytes()
                ),
            },
        },
        "fixture_manifest": {
            "path": (
                "docs/research/data/"
                "rule-orchestration-fixture.json"
            ),
            "sha256": manifest_sha256,
        },
        "oracle": {
            "image": IMAGE,
            "image_id": image_id,
            "revision": revision,
            "binary": BINARY,
            "binary_sha256": binary_digest.decode("ascii"),
            "exit_code": process.returncode,
            "raw_stdout_bytes": len(process.stdout),
            "raw_stdout_sha256": sha256(process.stdout),
            "raw_stderr_bytes": len(process.stderr),
            "raw_stderr_sha256": sha256(process.stderr),
        },
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir"
        },
        "closed_corpus_gap": "CAP-GAP-011",
        "relationships": relationships,
        "source_audit": source_audit,
        "harness_output": document,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    repo = pathlib.Path(__file__).resolve().parents[2]
    parser.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=(
            repo
            / "docs/research/data/rule-orchestration-fixture.json"
        ),
    )
    parser.add_argument("--raw-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = build_report(
        args.fixture_dir.resolve(),
        args.manifest.resolve(),
        args.raw_dir.resolve(),
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

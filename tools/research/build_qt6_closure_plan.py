#!/usr/bin/env python3
"""Build the 68-row Linux Qt6 capability closure plan."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import zlib
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
EVALUATED_ON = "2026-07-29"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
PLATFORM = "linux-x86_64-qt6"
TRACEABILITY_PATH = "docs/research/data/capability-traceability.json"
REPORT_PATHS = (
    "docs/research/data/qt5-qt6-cli.json",
    "docs/research/data/global-host-api-qt5-qt6.json",
    "docs/research/data/host-api-arity-qt5-qt6.json",
    "docs/research/data/global-typo-errors-qt5-qt6.json",
    "docs/research/data/cli-output-boundaries-linux-qt5-qt6.json",
    "docs/research/data/cli-output-matrix-linux-qt5-qt6.json",
    "docs/research/data/cli-scan-nested-matrix-linux-qt5-qt6.json",
    "docs/research/data/qt6-alltypes-diagnostics.json",
    "docs/research/data/cli-special-matrix-linux-qt5-qt6.json",
    "docs/research/data/cli-special-boundaries-linux-qt5-qt6.json",
    "docs/research/data/cli-path-matrix-linux-qt5-qt6.json",
    "docs/research/data/cli-database-matrix-linux-qt5-qt6.json",
    "docs/research/data/qt6-database-diagnostics.json",
    "docs/research/data/cli-option-behavior-linux-qt5-qt6.json",
    "docs/research/data/binary-rule-order-linux-qt5-qt6.json",
    "docs/research/data/engine-contract-linux-qt5.json",
    "docs/research/data/engine-contract-linux-qt6.json",
    "docs/research/data/rule-orchestration-linux-qt5.json",
    "docs/research/data/rule-orchestration-linux-qt5-qt6.json",
    "docs/research/data/result-metadata-engine-qt5.json",
    "docs/research/data/result-lists-engine-qt5.json",
    "docs/research/data/result-ids-engine-qt5.json",
    "docs/research/data/result-flags-engine-qt5.json",
    "docs/research/data/result-enums-engine-qt5.json",
    "docs/research/data/global-host-api-qt5.json",
    "docs/research/data/global-host-api-qt6.json",
    "docs/research/data/result-model-engine-qt6.json",
    "docs/research/data/signature-path-engine-qt5.json",
    "docs/research/data/signature-path-engine-qt6.json",
    "docs/research/data/debug-dispatch-engine-qt5.json",
    "docs/research/data/debug-dispatch-engine-qt6.json",
    "docs/research/data/resource-context-chain-qt5.json",
    "docs/research/data/resource-context-chain-qt6.json",
    "docs/research/data/archive-option-engine-qt5-qt6.json",
    "docs/research/data/archive-iteration-boundary-engine-qt5.json",
    "docs/research/data/archive-iteration-boundary-engine-qt6.json",
    "docs/research/data/qt-null-filename-semantics-qt5-qt6.json",
    "docs/research/data/scan-option-boundaries-linux-qt5.json",
    "docs/research/data/scan-option-boundaries-linux-qt6.json",
    "docs/research/data/legacy-dispatch-linux-qt5-qt6.json",
    "docs/research/data/dos-dispatch-linux-qt5-qt6.json",
    "docs/research/data/bw-dispatch-engine-qt5-qt6.json",
    "docs/research/data/path-boundaries-linux-qt5-qt6.json",
    "docs/research/data/archive-dispatch-linux-qt5-qt6.json",
    "docs/research/data/archive-limit-engine-qt5-qt6.json",
)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
QT6_UNIMPLEMENTED_SHA256 = (
    "b303e6913e76b70a6f0d6a4d3ccd389bc342589e45e1615873a37334dea8c51b"
)


class ClosurePlanError(ValueError):
    """The Qt6 closure plan cannot be generated safely."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ClosurePlanError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ClosurePlanError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(value, dict):
        raise ClosurePlanError(f"JSON root must be an object: {path}")
    return value, raw


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


# These are deliberately narrow. A capability is complete only when the existing
# Qt6 comparison exercises the entire behavior named by the matrix row.
COMPLETE: dict[str, str] = {
    "CAP-CLI-IN-001": "15 hash-bound corpus files exercise one positional target",
    "CAP-CLI-IN-002": "ordered, duplicate, missing-plus-valid, and directory-plus-file targets are equal",
    "CAP-CLI-IN-003": "all 47 special-path, filesystem, large-directory, TOCTOU, and locale/filesystem cases match Qt5 across two Qt6 repetitions",
    "CAP-CLI-IN-004": "single-file directory and empty-directory behavior is equal",
    "CAP-CLI-OPT-001": "all eight nested fixtures have equal recursive-scan detection trees",
    "CAP-CLI-OPT-002": "the five-sample deep-scan matrix has equal stdout and exit codes",
    "CAP-CLI-OPT-003": "the five-sample heuristic matrix has equal detection semantics",
    "CAP-CLI-OPT-004": "verbose adds the same single Linux OS record",
    "CAP-CLI-OPT-005": "the five-sample aggressive matrix has equal stdout and exit codes",
    "CAP-CLI-OPT-006": "alltypes detections are equal; the complete Qt6 diagnostic difference is retained",
    "CAP-CLI-OPT-007": "the five-sample format-result matrix has equal stdout and exit codes",
    "CAP-CLI-OPT-008": "no-message behavior and full 292-rule profiling order are equal",
    "CAP-CLI-OPT-009": "database load messages and structured-output contamination are equal",
    "CAP-CLI-OPT-010": "the five-sample hide-unknown matrix has equal stdout and exit codes",
    "CAP-CLI-TEST-001": "test mode remains the same directory-agnostic no-op",
    "CAP-CLI-TEST-002": "createtest complete and missing-argument behavior is equal",
    "CAP-CLI-MODE-001": "five-sample formatter and exact 6.5 entropy boundaries are equal",
    "CAP-CLI-MODE-002": "five-sample formatter, priority, and multi-target info boundaries are equal",
    "CAP-CLI-MODE-003": "generic and 11 format-specific struct method boundaries are equal",
    "CAP-CLI-MODE-004": "--showstructs is equal both with and without a target",
    "CAP-CLI-MODE-005": "--help and no-argument help are byte-identical",
    "CAP-CLI-MODE-006": "--version is byte-identical",
    "CAP-CLI-OUT-001": "the five-sample XML matrix has equal stdout and exit codes",
    "CAP-CLI-OUT-002": "all 15 normal scans have equal JSON detection trees",
    "CAP-CLI-OUT-003": "the five-sample CSV matrix and all-flags precedence are equal",
    "CAP-CLI-OUT-004": "the five-sample TSV matrix has equal stdout and exit codes",
    "CAP-CLI-OUT-005": "the five-sample plain-text matrix has equal stdout and exit codes",
    "CAP-CLI-DB-001": "the main database argument and reported path are equal",
    "CAP-CLI-DB-002": "the extra database argument and reported path are equal",
    "CAP-CLI-DB-003": "the custom database argument and reported path are equal",
    "CAP-CLI-DB-004": "--showdatabase output is byte-identical",
    "CAP-DISPATCH-001": "PE32/64, ELF32/64, Mach-O 32/64/FAT detection trees are equal",
    "CAP-DISPATCH-005": "DEX, Java Class, and PYC detection trees are equal",
    "CAP-DISPATCH-006": "the PDF and CFBF fixtures have equal detection trees",
    "CAP-DISPATCH-007": "JPEG, PNG, and generic Image/BMP detection trees are equal",
    "CAP-DISPATCH-008": "empty and plain binary fallback fixtures are equal",
    "CAP-NEST-001": "directory traversal and internal recursive-scan controls are both equal",
    "CAP-NEST-002": "resource and overlay recursive-scan gates have equal detection trees",
    "CAP-NEST-005": "overlay and resource subdevice gate controls have equal detection trees",
    "CAP-NEST-008": "all five nested formatter stdout streams, including the JSON tree, are equal",
    "CAP-RULE-008": "an empty valid database produces the same sole Unknown fallback",
    "CAP-RULE-010": "parse/runtime errors are collected with exact runtime-specific diagnostics",
    "CAP-RULE-011": "all 292 Binary profiling announcements have identical order",
    "CAP-ENG-IN-001": "all four public engine entry points produce equal records",
    "CAP-ENG-IN-002": "device/subdevice read, seek, range, and failure boundaries match Qt5",
    "CAP-RULE-006": "exact signature-name filtering, case, deep, and missing controls match Qt5",
    "CAP-RULE-009": "callback, break, pre-stop, and synchronized stop boundaries match Qt5",
    "CAP-RULE-012": "sort enabled/disabled ordering and priority metadata match Qt5",
    "CAP-RULE-001": "main, extra, and custom database layer append behavior matches Qt5",
    "CAP-RULE-002": "priority, lexical, missing, empty, and type-init ordering matches Qt5",
    "CAP-RULE-003": "global init, type init, and same-name include precedence matches Qt5",
    "CAP-RULE-004": "wrong-file-type rules remain excluded in all four scan modes",
    "CAP-RULE-005": "deep, entry-point, and heuristic gates are independently equal",
    "CAP-RESULT-001": "four-entry scalar metadata differs only in nondeterministic scan time",
    "CAP-RESULT-002": "all four result lists match aside from the classified Qt parse diagnostic",
    "CAP-RESULT-003": "heuristic, advanced heuristic, and unknown flag truth table matches Qt5",
    "CAP-RESULT-004": "record and parent identifier shape and invariants match modulo UUID values",
    "CAP-RESULT-005": "raw, numeric, canonical, reserved, and fallback enum behavior is identical",
    "CAP-RESULT-006": "normal record version, info, priority, rule name, and rule path fields match Qt5",
    "CAP-RULE-007": "all seven private signature-path filter boundaries are byte-identical to Qt5",
    "CAP-NEST-007": "public omission and direct debug-data positive control match Qt5 exactly",
    "CAP-NEST-006": "all four recursive/aggressive resource-context controls match Qt5 exactly",
    "CAP-NEST-003": "all 64 engine option cases and 32 release controls match Qt5",
    "CAP-NEST-004": "Qt6 executes the 99999/100000/100001 archive iteration boundary and the inclusive 21/2001 resource-count boundary; the ISO NUL difference is classified",
    "CAP-DISPATCH-003": "all eight Amiga Hunk and Atari ST positive/truncated/endian/magic cases retain equal detector and scanner dispatch with raw-equal Qt5/Qt6 streams",
    "CAP-DISPATCH-002": "all 19 public DOS/COM cases retain equal dispatch after classified Qt6 formatter/TypeError differences, and the BW property-only branch is raw-equal to Qt5",
    "CAP-DISPATCH-004": "all eight APK/IPA/JAR/ZIP/RAR/NPM/ISO9660/Archive members retain equal public or property-only dispatch across fixed Qt5/Qt6 evidence",
    "CAP-NEST-009": "the same 14-case archive-limit corpus reaches depth 64 and 33,554,546 cumulative expanded bytes on Qt5 and Qt6 with an equal deterministic cancellation prefix and stable result projection",
}

PARTIAL: dict[str, str] = {}


def _same_stdout_and_exit(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        left.get("exit_code") == right.get("exit_code")
        and left.get("stdout_sha256") == right.get("stdout_sha256")
        and left.get("stdout_bytes") == right.get("stdout_bytes")
    )


def _is_known_qt6_warning(
    left: dict[str, Any], right: dict[str, Any]
) -> bool:
    return (
        left.get("stderr_sha256") == EMPTY_SHA256
        and left.get("stderr_bytes") == 0
        and right.get("stderr_sha256") == QT6_UNIMPLEMENTED_SHA256
        and right.get("stderr_bytes") == 80
    )


def _validate_output_boundary_report(report: dict[str, Any]) -> None:
    if report.get("expected_revision") != UPSTREAM_COMMIT:
        raise ClosurePlanError("output-boundary revision drift")
    for side in ("left", "right"):
        if report.get(side, {}).get("image_revision") != UPSTREAM_COMMIT:
            raise ClosurePlanError(f"output-boundary {side} revision drift")
    cases = report.get("cases")
    if not isinstance(cases, list):
        raise ClosurePlanError("output-boundary cases must be an array")
    expected_ids = {
        f"{scope}_{formatter}"
        for scope in ("escaping", "nested")
        for formatter in ("json", "xml", "csv", "tsv", "plaintext")
    }
    if {case.get("id") for case in cases} != expected_ids:
        raise ClosurePlanError("output-boundary case catalog drift")
    expected_failures = {
        f"case.nested_{formatter}.oracle_difference"
        for formatter in ("json", "xml", "csv", "tsv", "plaintext")
    }
    if set(report.get("failures", [])) != expected_failures:
        raise ClosurePlanError("output-boundary failure catalog drift")
    if report.get("passed") is not False:
        raise ClosurePlanError("output-boundary must retain raw Qt6 warnings")
    facts = report.get("facts")
    if not isinstance(facts, dict) or not facts or not all(
        value is True for value in facts.values()
    ):
        raise ClosurePlanError("output-boundary semantic facts changed")
    for case in cases:
        left = case.get("left", {})
        right = case.get("right", {})
        if not _same_stdout_and_exit(left, right):
            raise ClosurePlanError(
                f"output-boundary semantic difference: {case.get('id')}"
            )
        if case["scope"] == "escaping":
            if case.get("oracles_equal") is not True:
                raise ClosurePlanError("escaping formatter difference")
        elif not (
            case.get("oracles_equal") is False
            and _is_known_qt6_warning(left, right)
        ):
            raise ClosurePlanError("unexpected nested formatter difference")


def _validate_paired_observation(
    record: dict[str, Any],
    expected_differences: set[tuple[str, ...]],
    label: str,
) -> tuple[str, ...]:
    left = record.get("left", {})
    right = record.get("right", {})
    if not _same_stdout_and_exit(left, right):
        raise ClosurePlanError(f"CLI matrix semantic difference: {label}")
    differences = tuple(record.get("differences", []))
    if differences not in expected_differences:
        raise ClosurePlanError(f"unexpected CLI matrix difference: {label}")
    if differences == ("stderr",) and not _is_known_qt6_warning(left, right):
        raise ClosurePlanError(f"unexpected CLI matrix stderr: {label}")
    return differences


def _validate_output_matrix_report(report: dict[str, Any]) -> None:
    if (
        report.get("expected_revision") != UPSTREAM_COMMIT
        or report.get("left_revision") != UPSTREAM_COMMIT
        or report.get("right_revision") != UPSTREAM_COMMIT
    ):
        raise ClosurePlanError("CLI output matrix revision drift")
    if report.get("equal") is not False:
        raise ClosurePlanError("CLI output matrix must retain raw Qt6 warnings")

    failures = {
        "corpus.minimal.exe.stderr",
        "corpus.minimal-pe64.exe.stderr",
        *{
            f"matrix.minimal.exe.output.{case}.stderr"
            for case in (
                "text",
                "plaintext",
                "json",
                "xml",
                "csv",
                "tsv",
                "all_output_flags",
            )
        },
    }
    if set(report.get("failures", [])) != failures:
        raise ClosurePlanError("CLI output matrix failure catalog drift")

    cases = report.get("cases")
    unreadable = report.get("unreadable_input")
    corpus = report.get("corpus")
    matrix = report.get("matrix")
    if not all(
        isinstance(value, dict)
        for value in (cases, unreadable, corpus, matrix)
    ):
        raise ClosurePlanError("CLI output matrix sections are missing")
    if len(corpus) != 26:
        raise ClosurePlanError("CLI output matrix corpus drift")
    expected_samples = {
        "empty.bin",
        "minimal.exe",
        "minimal.pdf",
        "payload.zip",
        "plain.txt",
    }
    if set(matrix) != expected_samples:
        raise ClosurePlanError("CLI output matrix sample catalog drift")
    expected_formatters = {
        "text",
        "plaintext",
        "json",
        "xml",
        "csv",
        "tsv",
        "all_output_flags",
    }

    observed_failures = set()
    for name, record in cases.items():
        differences = _validate_paired_observation(
            record, {()}, f"cases.{name}"
        )
        if differences:
            observed_failures.add(f"{name}.{differences[0]}")
    for name, record in unreadable.items():
        differences = _validate_paired_observation(
            record, {()}, f"unreadable_input.{name}"
        )
        if differences:
            observed_failures.add(
                f"unreadable_input.{name}.{differences[0]}"
            )
    for name, record in corpus.items():
        differences = _validate_paired_observation(
            record, {(), ("stderr",)}, f"corpus.{name}"
        )
        if differences:
            observed_failures.add(f"corpus.{name}.{differences[0]}")
        if record.get("left_detect_tree") != record.get("right_detect_tree"):
            raise ClosurePlanError(f"corpus detection tree difference: {name}")
    for sample, sample_record in matrix.items():
        output = sample_record.get("output")
        if not isinstance(output, dict) or set(output) != expected_formatters:
            raise ClosurePlanError(
                f"CLI output formatter catalog drift: {sample}"
            )
        for name, record in output.items():
            differences = _validate_paired_observation(
                record,
                {(), ("stderr",)},
                f"matrix.{sample}.output.{name}",
            )
            if differences:
                observed_failures.add(
                    f"matrix.{sample}.output.{name}.{differences[0]}"
                )
    if observed_failures != failures:
        raise ClosurePlanError("CLI output matrix derived failures drift")


def _validate_scan_nested_report(report: dict[str, Any]) -> None:
    if (
        report.get("expected_revision") != UPSTREAM_COMMIT
        or report.get("left_revision") != UPSTREAM_COMMIT
        or report.get("right_revision") != UPSTREAM_COMMIT
    ):
        raise ClosurePlanError("CLI scan/nested matrix revision drift")
    if report.get("equal") is not False:
        raise ClosurePlanError(
            "CLI scan/nested matrix must retain Qt6 differences"
        )
    cases = report.get("cases")
    unreadable = report.get("unreadable_input")
    corpus = report.get("corpus")
    matrix = report.get("matrix")
    nested = report.get("nested_corpus", {}).get("cases")
    if not all(
        isinstance(value, dict)
        for value in (cases, unreadable, corpus, matrix, nested)
    ):
        raise ClosurePlanError("CLI scan/nested matrix sections are missing")
    if len(corpus) != 26:
        raise ClosurePlanError("CLI scan/nested corpus drift")
    expected_samples = {
        "empty.bin",
        "minimal.exe",
        "minimal.pdf",
        "payload.zip",
        "plain.txt",
    }
    if set(matrix) != expected_samples:
        raise ClosurePlanError("CLI scan matrix sample catalog drift")
    expected_scan_cases = {
        "default",
        "deep",
        "heuristic",
        "aggressive",
        "alltypes",
        "format",
        "hideunknown",
        "combined",
    }
    expected_nested_samples = {
        "pdf-member.zip",
        "nested-zip.zip",
        "many-pdf-members.zip",
        "pe-pdf-overlay.exe",
        "pe-pdf-resource.exe",
        "pe-many-pdf-resources.exe",
        "pe-manifest-resource.exe",
        "pe-zip-overlay.exe",
    }
    if set(nested) != expected_nested_samples:
        raise ClosurePlanError("CLI nested sample catalog drift")
    expected_nested_cases = {
        "default",
        "recursive",
        "aggressive",
        "recursive_aggressive",
    }

    observed_failures = set()
    for name, record in cases.items():
        _validate_paired_observation(record, {()}, f"cases.{name}")
    for name, record in unreadable.items():
        _validate_paired_observation(
            record, {()}, f"unreadable_input.{name}"
        )
    for name, record in corpus.items():
        differences = _validate_paired_observation(
            record, {(), ("stderr",)}, f"corpus.{name}"
        )
        if differences:
            observed_failures.add(f"corpus.{name}.{differences[0]}")
        if record.get("left_detect_tree") != record.get("right_detect_tree"):
            raise ClosurePlanError(f"corpus detection tree difference: {name}")

    for sample, sample_record in matrix.items():
        scan = sample_record.get("scan")
        if not isinstance(scan, dict) or set(scan) != expected_scan_cases:
            raise ClosurePlanError(f"CLI scan case catalog drift: {sample}")
        for name, record in scan.items():
            label = f"matrix.{sample}.scan.{name}"
            differences = tuple(record.get("differences", []))
            if sample == "minimal.exe" and name in {
                "alltypes",
                "combined",
            }:
                if differences != ("stdout", "stderr"):
                    raise ClosurePlanError(
                        f"alltypes diagnostic difference drift: {label}"
                    )
                if not _is_known_qt6_warning(
                    record.get("left", {}), record.get("right", {})
                ):
                    raise ClosurePlanError(
                        f"alltypes stderr difference drift: {label}"
                    )
                if (
                    tuple(record.get("left_changes", []))
                    != ("stdout",)
                    or tuple(record.get("right_changes", []))
                    != ("stdout",)
                ):
                    raise ClosurePlanError(
                        f"alltypes relative effect drift: {label}"
                    )
            else:
                differences = _validate_paired_observation(
                    record, {(), ("stderr",)}, label
                )
                if record.get("left_changes") != record.get("right_changes"):
                    raise ClosurePlanError(
                        f"scan relative effect difference: {label}"
                    )
            for difference in differences:
                observed_failures.add(f"{label}.{difference}")

    for sample, sample_record in nested.items():
        if set(sample_record) != expected_nested_cases:
            raise ClosurePlanError(
                f"CLI nested case catalog drift: {sample}"
            )
        for name, record in sample_record.items():
            label = f"nested_corpus.{sample}.{name}"
            differences = _validate_paired_observation(
                record, {(), ("stderr",)}, label
            )
            if record.get("left_detect_tree") != record.get(
                "right_detect_tree"
            ):
                raise ClosurePlanError(
                    f"nested detection tree difference: {label}"
                )
            if record.get("left_changes") != record.get("right_changes"):
                raise ClosurePlanError(
                    f"nested relative effect difference: {label}"
                )
            for difference in differences:
                observed_failures.add(f"{label}.{difference}")
    if observed_failures != set(report.get("failures", [])):
        raise ClosurePlanError("CLI scan/nested derived failures drift")


def _validate_alltypes_diagnostics(report: dict[str, Any]) -> None:
    if report.get("upstream_commit") != UPSTREAM_COMMIT:
        raise ClosurePlanError("alltypes diagnostic revision drift")
    if report.get("passed") is not True:
        raise ClosurePlanError("alltypes diagnostic probe did not pass")
    facts = report.get("facts")
    if not isinstance(facts, dict) or not facts or not all(
        value is True for value in facts.values()
    ):
        raise ClosurePlanError("alltypes diagnostic facts changed")
    repetitions = report.get("repetitions")
    if not isinstance(repetitions, int) or repetitions < 2:
        raise ClosurePlanError("alltypes diagnostic repetitions drift")
    cases = report.get("cases")
    if not isinstance(cases, dict) or set(cases) != {
        "alltypes",
        "combined",
    }:
        raise ClosurePlanError("alltypes diagnostic case catalog drift")
    expected = report.get("expected_normalized_diagnostics")
    if not isinstance(expected, str) or "MSDOS_Script(<address>)" not in expected:
        raise ClosurePlanError("alltypes normalized diagnostic drift")
    for case_name, case in cases.items():
        observations = case.get("observations")
        if not isinstance(observations, dict) or set(observations) != {
            "qt5",
            "qt6",
        }:
            raise ClosurePlanError(
                f"alltypes oracle catalog drift: {case_name}"
            )
        qt5 = observations["qt5"]
        qt6 = observations["qt6"]
        if len(qt5) != repetitions or len(qt6) != repetitions:
            raise ClosurePlanError(
                f"alltypes repetition count drift: {case_name}"
            )
        baseline_document = qt5[0].get("json_document")
        for oracle_name, items in observations.items():
            for index, item in enumerate(items):
                label = f"{case_name}.{oracle_name}.{index}"
                try:
                    stdout = base64.b64decode(
                        item["stdout_base64"], validate=True
                    )
                    stderr = base64.b64decode(
                        item["stderr_base64"], validate=True
                    )
                except (KeyError, ValueError) as error:
                    raise ClosurePlanError(
                        f"invalid alltypes raw stream: {label}"
                    ) from error
                if (
                    len(stdout) != item.get("stdout_bytes")
                    or sha256(stdout) != item.get("stdout_sha256")
                    or len(stderr) != item.get("stderr_bytes")
                    or sha256(stderr) != item.get("stderr_sha256")
                ):
                    raise ClosurePlanError(
                        f"alltypes raw stream identity drift: {label}"
                    )
                if item.get("json_document") != baseline_document:
                    raise ClosurePlanError(
                        f"alltypes JSON difference: {label}"
                    )
                if oracle_name == "qt5":
                    if item.get("diagnostics") != "" or stderr != b"":
                        raise ClosurePlanError(
                            f"unexpected Qt5 alltypes diagnostic: {label}"
                        )
                elif (
                    item.get("normalized_diagnostics") != expected
                    or "0x" not in item.get("diagnostics", "")
                    or stderr != b"Unimplemented code.\n" * 4
                ):
                    raise ClosurePlanError(
                        f"unexpected Qt6 alltypes diagnostic: {label}"
                    )


def _validate_special_matrix_report(report: dict[str, Any]) -> None:
    if (
        report.get("expected_revision") != UPSTREAM_COMMIT
        or report.get("left_revision") != UPSTREAM_COMMIT
        or report.get("right_revision") != UPSTREAM_COMMIT
    ):
        raise ClosurePlanError("CLI special matrix revision drift")
    if report.get("equal") is not False:
        raise ClosurePlanError(
            "CLI special matrix must retain corpus Qt6 warnings"
        )
    cases = report.get("cases")
    unreadable = report.get("unreadable_input")
    corpus = report.get("corpus")
    matrix = report.get("matrix")
    if not all(
        isinstance(value, dict)
        for value in (cases, unreadable, corpus, matrix)
    ):
        raise ClosurePlanError("CLI special matrix sections are missing")
    if len(corpus) != 26:
        raise ClosurePlanError("CLI special matrix corpus drift")
    expected_samples = {
        "empty.bin",
        "minimal.exe",
        "minimal.pdf",
        "payload.zip",
        "plain.txt",
    }
    if set(matrix) != expected_samples:
        raise ClosurePlanError("CLI special matrix sample catalog drift")
    expected_cases = {
        "entropy_text",
        "entropy_plaintext",
        "entropy_json",
        "entropy_xml",
        "entropy_csv",
        "entropy_tsv",
        "entropy_all_output_flags",
        "info_text",
        "info_plaintext",
        "info_json",
        "info_xml",
        "info_csv",
        "info_tsv",
        "info_all_output_flags",
        "struct_hash_json",
        "struct_hash_md5_json",
        "struct_unknown_json",
        "entropy_over_info_struct_json",
        "struct_over_info_json",
    }
    observed_failures = set()
    for name, record in cases.items():
        _validate_paired_observation(record, {()}, f"cases.{name}")
    for name, record in unreadable.items():
        _validate_paired_observation(
            record, {()}, f"unreadable_input.{name}"
        )
    for name, record in corpus.items():
        differences = _validate_paired_observation(
            record, {(), ("stderr",)}, f"corpus.{name}"
        )
        if differences:
            observed_failures.add(f"corpus.{name}.{differences[0]}")
        if record.get("left_detect_tree") != record.get("right_detect_tree"):
            raise ClosurePlanError(f"corpus detection tree difference: {name}")
    for sample, sample_record in matrix.items():
        special = sample_record.get("special")
        if not isinstance(special, dict) or set(special) != expected_cases:
            raise ClosurePlanError(
                f"CLI special case catalog drift: {sample}"
            )
        for name, record in special.items():
            _validate_paired_observation(
                record, {()}, f"matrix.{sample}.special.{name}"
            )
    if observed_failures != set(report.get("failures", [])):
        raise ClosurePlanError("CLI special matrix derived failures drift")


def _validate_special_boundary_report(report: dict[str, Any]) -> None:
    if report.get("upstream_commit") != UPSTREAM_COMMIT:
        raise ClosurePlanError("CLI special boundary revision drift")
    if report.get("result") != "equal":
        raise ClosurePlanError("CLI special boundary result changed")
    cases = report.get("cases")
    expected_cases = {
        "dex_header_json",
        "elf_ehdr_json",
        "elf_entry_point_json",
        "entropy_above_json",
        "entropy_below_json",
        "entropy_exact_json",
        "entropy_exact_text",
        "entropy_over_struct_json",
        "entropy_two_json",
        "info_struct_empty_json",
        "info_two_json",
        "macho_entry_point_json",
        "macho_header_json",
        "pe_dos_header_json",
        "pe_entry_point_json",
        "pe_export_directory_json",
        "pe_nt_headers_json",
        "pe_resource_directory_json",
        "pe_section_header_json",
        "struct_check_format_json",
        "struct_empty_json",
        "struct_entropy_json",
        "struct_hash_empty_segment_json",
        "struct_hash_md5_casefold_json",
        "struct_hash_md5_trailing_json",
        "struct_hash_md5_two_json",
        "struct_hash_unknown_child_json",
        "struct_unknown_nested_json",
    }
    if (
        not isinstance(cases, dict)
        or set(cases) != expected_cases
        or report.get("case_count") != len(expected_cases)
    ):
        raise ClosurePlanError("CLI special boundary case catalog drift")
    if not all(
        case.get("all_oracles_equal") is True for case in cases.values()
    ):
        raise ClosurePlanError("CLI special boundary oracle difference")
    oracles = report.get("oracles")
    if (
        not isinstance(oracles, list)
        or [oracle.get("name") for oracle in oracles]
        != ["linux-qt5-cmake", "linux-qt6-cmake"]
        or any(
            oracle.get("revision") != UPSTREAM_COMMIT
            for oracle in oracles
        )
    ):
        raise ClosurePlanError("CLI special boundary oracle identity drift")
    relationships = report.get("relationships")
    if not isinstance(relationships, dict):
        raise ClosurePlanError("CLI special boundary relationships missing")
    if relationships.get("runtime_entropy_statuses") != {
        "below": "not packed",
        "exact": "not packed",
        "above": "packed",
    }:
        raise ClosurePlanError("CLI entropy boundary drift")
    required_true = (
        "struct_filter_is_case_insensitive",
        "struct_trailing_segments_are_ignored",
        "empty_struct_value_falls_back_to_normal_scan",
        "entropy_precedes_struct",
    )
    if not all(relationships.get(name) is True for name in required_true):
        raise ClosurePlanError("CLI struct/priority boundary drift")
    if len(relationships.get("format_struct_methods", {})) != 11:
        raise ClosurePlanError("CLI format struct method catalog drift")
    if set(relationships.get("multi_target_structured_outputs", {})) != {
        "entropy_two_json",
        "info_two_json",
        "struct_hash_md5_two_json",
    }:
        raise ClosurePlanError("CLI special multi-target catalog drift")
    source_audit = report.get("source_audit", {}).get("assumptions")
    if not isinstance(source_audit, dict) or not all(
        value is True for value in source_audit.values()
    ):
        raise ClosurePlanError("CLI special source audit drift")


def _validate_path_matrix_report(report: dict[str, Any]) -> None:
    if (
        report.get("expected_revision") != UPSTREAM_COMMIT
        or report.get("left_revision") != UPSTREAM_COMMIT
        or report.get("right_revision") != UPSTREAM_COMMIT
    ):
        raise ClosurePlanError("CLI path matrix revision drift")
    if report.get("equal") is not False:
        raise ClosurePlanError("CLI path matrix must retain Qt6 warnings")
    cases = report.get("cases")
    unreadable = report.get("unreadable_input")
    path_corpus = report.get("path_corpus")
    path_cases = (
        path_corpus.get("cases")
        if isinstance(path_corpus, dict)
        else None
    )
    if not all(
        isinstance(value, dict)
        for value in (cases, unreadable, path_corpus, path_cases)
    ):
        raise ClosurePlanError("CLI path matrix sections are missing")
    expected_cases = {
        "single_file_json",
        "two_files_json",
        "duplicate_file_json",
        "tree_json",
        "tree_recursive_json",
        "tree_xml",
        "tree_csv",
        "tree_plaintext",
        "tree_entropy_json",
        "tree_info_json",
        "single_directory_json",
        "empty_directory_json",
        "missing_and_existing_json",
        "directory_plus_duplicate_json",
    }
    if set(path_cases) != expected_cases:
        raise ClosurePlanError("CLI path case catalog drift")
    expected_failures = {
        f"path_corpus.{name}.stderr"
        for name in (
            "tree_json",
            "tree_recursive_json",
            "tree_xml",
            "tree_csv",
            "tree_plaintext",
            "directory_plus_duplicate_json",
        )
    }
    observed_failures = set()
    for name, record in cases.items():
        _validate_paired_observation(record, {()}, f"cases.{name}")
    for name, record in unreadable.items():
        _validate_paired_observation(
            record, {()}, f"unreadable_input.{name}"
        )
    for name, record in path_cases.items():
        label = f"path_corpus.{name}"
        differences = _validate_paired_observation(
            record, {(), ("stderr",)}, label
        )
        if differences:
            observed_failures.add(f"{label}.{differences[0]}")
        if record.get("left_filename_prefixes") != record.get(
            "right_filename_prefixes"
        ):
            raise ClosurePlanError(f"CLI path prefix difference: {name}")
        for format_name in ("json", "xml"):
            left_key = f"left_valid_{format_name}"
            right_key = f"right_valid_{format_name}"
            if left_key in record and record.get(left_key) != record.get(
                right_key
            ):
                raise ClosurePlanError(
                    f"CLI path {format_name} validity difference: {name}"
                )
        if "left_changes" in record and record.get(
            "left_changes"
        ) != record.get("right_changes"):
            raise ClosurePlanError(
                f"CLI path recursive effect difference: {name}"
            )
    if observed_failures != expected_failures or set(
        report.get("failures", [])
    ) != expected_failures:
        raise ClosurePlanError("CLI path failure catalog drift")
    if (
        path_corpus.get("generator")
        != "tools/corpus/generate_path_corpus.py"
        or len(path_corpus.get("directories", [])) != 5
        or len(path_corpus.get("entries", [])) != 5
    ):
        raise ClosurePlanError("CLI path fixture catalog drift")


def _validate_path_boundary_report(report: dict[str, Any]) -> None:
    expected_catalogs = {
        "special_path": {
            "directory_non_utf8",
            "directory_special",
            "directory_unicode",
            "explicit_non_utf8_c0af",
            "explicit_non_utf8_ff",
            "explicit_non_utf8_truncated_e282",
            "explicit_order",
            "single_backslash",
            "single_cjk",
            "single_colon",
            "single_emoji",
            "single_hidden",
            "single_leading_dash_absolute",
            "single_leading_dash_relative_escaped",
            "single_leading_dash_relative_unescaped",
            "single_leading_space",
            "single_newline",
            "single_nfc",
            "single_nfd",
            "single_non_utf8_control",
            "single_space",
            "single_tab",
            "single_trailing_space",
        },
        "filesystem": {
            "dangling_symlink",
            "deep_64",
            "denied_as_nobody",
            "denied_as_root",
            "direct_control",
            "directory_symlink",
            "file_symlink",
            "self_cycle",
            "symlink_tree",
        },
        "large_directory": {
            "empty_0",
            "flat_256",
            "flat_4096",
            "nested_4096",
            "single_1",
        },
        "toctou": {
            "remove_old_after_enumeration",
            "stable_new",
            "stable_old",
            "swap_old_to_new",
        },
        "locale_filesystem": {
            "C.utf8/tmpfs",
            "C.utf8/volume",
            "C/tmpfs",
            "C/volume",
            "POSIX/tmpfs",
            "POSIX/volume",
        },
    }
    expected_baselines = {
        "special_path": (
            "special-path-engine-qt5.json",
            "0b5fc241e2c30449e1df11aa08532a7b0adbf9c81362d552bf7770f8cd159f82",
            "3a978769f2667a13532d21b68c9cfaeeb4b353842b630eb8a6da8b9ffbc2a8c0",
        ),
        "filesystem": (
            "path-filesystem-engine-qt5.json",
            "97549da236a57cc5502b43a8157f81865fa6d9a0ab626035ebcf63df97792dbb",
            "76d433ad993c7152263ed6f6ab0479f6d210bf9bff94d085b75d6a1258a07f47",
        ),
        "large_directory": (
            "large-path-engine-qt5.json",
            "100562d79fa661055fd79e0efe6ce8f58a31b8e4faebedf410f80f51e817883b",
            "6ff37d6169753b1b4c6e652f84e4347449a1ca4171af6bce23c9dcdcdccee651",
        ),
        "toctou": (
            "path-toctou-engine-qt5.json",
            "733b136667c39f46e2d32bfb6a15c7da7077eee98232d7ff3a06a812f6913cf9",
            "3fb66ffd9d25cac0865dfee9a3921a9f8336fe56849568c0b50a415f32f1a174",
        ),
        "locale_filesystem": (
            "path-locale-filesystem-engine-qt5.json",
            "e3ba7c8b35d7aa82b215402c28e3aadf95d6ac95ab6b64af8dc68b38a439ff6a",
            "48bb91f7c0d919cf83e5d7f139ae72ddc21b548bf5d5b9d9c7c860a8b0e287bf",
        ),
    }
    expected_order = list(expected_catalogs)
    if (
        report.get("schema_version") != 1
        or report.get("capability") != "CAP-CLI-IN-003"
        or report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("platform") != "linux-x86_64-qt5-qt6"
        or report.get("qt6_image")
        != "die-rust/upstream-oracle-cmake-qt6:74eaf505"
        or report.get("qt6_binary") != "/opt/die-build/src/console/diec"
        or report.get("generator")
        != "tools/upstream/probe_qt6_path_boundaries.py"
        or report.get("generator_sha256")
        != "5cadc79946ccbb2ab519ca443e67fea1572df1ba6a849c08af4ae3038f0be2f1"
        or report.get("passed") is not True
        or report.get("failures") != []
        or report.get("suite_order") != expected_order
    ):
        raise ClosurePlanError("Qt6 path-boundary identity drift")
    facts = report.get("facts")
    if (
        not isinstance(facts, dict)
        or set(facts)
        != {
            "all_five_qt5_boundaries_replayed",
            "all_qt6_repetitions_are_equal",
            "all_qt6_results_equal_qt5",
        }
        or not all(value is True for value in facts.values())
    ):
        raise ClosurePlanError("Qt6 path-boundary relationship drift")
    suites = report.get("suites")
    if not isinstance(suites, dict) or set(suites) != set(expected_order):
        raise ClosurePlanError("Qt6 path-boundary suite catalog drift")

    for suite_id, expected_cases in expected_catalogs.items():
        suite = suites[suite_id]
        comparison = suite.get("comparison")
        qt6 = suite.get("qt6")
        if not isinstance(comparison, dict) or not isinstance(qt6, dict):
            raise ClosurePlanError("Qt6 path-boundary suite shape drift")
        baseline_name, baseline_sha, projection_sha = expected_baselines[
            suite_id
        ]
        if comparison != {
            "behavior_projection_equal": True,
            "behavior_projection_sha256": projection_sha,
            "qt5_report_path": f"docs/research/data/{baseline_name}",
            "qt5_report_sha256": baseline_sha,
        }:
            raise ClosurePlanError(
                f"Qt6 path-boundary comparison drift: {suite_id}"
            )
        oracle = qt6.get("qt6_oracle")
        binary = qt6.get("qt6_binary")
        if (
            qt6.get("platform") != "linux-x86_64-qt6"
            or qt6.get("upstream_commit") != UPSTREAM_COMMIT
            or qt6.get("passed") is not True
            or qt6.get("failures") != []
            or not isinstance(oracle, dict)
            or oracle.get("id")
            != "sha256:e015495c313d0715f0b80f395da983a113a439f2a135eb637e9f0638c225200b"
            or not isinstance(binary, dict)
            or binary.get("sha256")
            != "e3321105af0349b29195325e79d5d2c7cc25ead2f28f84e242e3835b98f7283e"
            or qt6.get("facts", {}).get(
                "qt6_repetitions_are_byte_equal"
            )
            is not True
        ):
            raise ClosurePlanError(
                f"Qt6 path-boundary oracle drift: {suite_id}"
            )
        case_map = qt6.get(
            "matrix" if suite_id == "locale_filesystem" else "cases"
        )
        if not isinstance(case_map, dict) or set(case_map) != expected_cases:
            raise ClosurePlanError(
                f"Qt6 path-boundary case catalog drift: {suite_id}"
            )
        for case_name, case in case_map.items():
            observations = case.get("observations")
            if (
                not isinstance(observations, dict)
                or set(observations)
                != {"repetition_1", "repetition_2"}
            ):
                raise ClosurePlanError(
                    f"Qt6 path-boundary repetitions missing: "
                    f"{suite_id}/{case_name}"
                )
            first = observations["repetition_1"]
            second = observations["repetition_2"]
            for field in ("exit_code", "stdout", "stderr"):
                if first.get(field) != second.get(field):
                    raise ClosurePlanError(
                        f"Qt6 path-boundary repetition drift: "
                        f"{suite_id}/{case_name}/{field}"
                    )

        artifacts = qt6.get("raw_artifacts")
        if not isinstance(artifacts, dict) or not artifacts:
            raise ClosurePlanError(
                f"Qt6 path-boundary artifacts missing: {suite_id}"
            )
        decoded = {}
        for digest, artifact in artifacts.items():
            try:
                compressed = base64.b64decode(
                    artifact["base64"], validate=True
                )
                raw = zlib.decompress(compressed)
            except (KeyError, ValueError, zlib.error) as error:
                raise ClosurePlanError(
                    f"Qt6 path-boundary artifact invalid: {suite_id}"
                ) from error
            if (
                len(raw) != artifact.get("bytes")
                or sha256(raw) != digest
            ):
                raise ClosurePlanError(
                    f"Qt6 path-boundary artifact drift: {suite_id}"
                )
            decoded[digest] = raw
        referenced = {
            observation[stream]["artifact_sha256"]
            for case in case_map.values()
            for observation in case["observations"].values()
            for stream in ("stdout", "stderr")
        }
        if referenced != set(decoded):
            raise ClosurePlanError(
                f"Qt6 path-boundary artifact references drift: {suite_id}"
            )

    filesystem = suites["filesystem"]["qt6"]["cases"]
    large = suites["large_directory"]["qt6"]["cases"]
    toctou = suites["toctou"]["qt6"]["cases"]
    locale = suites["locale_filesystem"]["qt6"]
    if (
        filesystem["self_cycle"]["summary"]["pdf_root_count"] != 41
        or large["flat_4096"]["prefix_count"] != 4096
        or large["nested_4096"]["entropy_document_count"] != 4096
        or toctou["swap_old_to_new"]["stdout_sha256"]
        != toctou["stable_new"]["stdout_sha256"]
        or toctou["swap_old_to_new"]["stdout_sha256"]
        == toctou["stable_old"]["stdout_sha256"]
        or locale.get("output_equivalence", {}).get(
            "filesystem_stdout_byte_equal_within_locale"
        )
        is not False
    ):
        raise ClosurePlanError("Qt6 path-boundary semantic drift")


def _validate_archive_dispatch_report(report: dict[str, Any]) -> None:
    named_members = [
        "APK",
        "IPA",
        "JAR",
        "ZIP",
        "RAR",
        "NPM",
        "ISO9660",
        "Archive",
    ]
    expected_public = {
        "minimal.apk": "APK",
        "minimal.ipa": "Binary",
        "minimal.iso": "ISO 9660",
        "minimal.jar": "JAR",
        "minimal.rar": "RAR",
        "payload.tar": "Binary",
        "payload.txt.gz": "Binary",
        "payload.zip": "ZIP",
    }
    if (
        report.get("schema_version") != 1
        or report.get("capability") != "CAP-DISPATCH-004"
        or report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("platform") != "linux-x86_64-qt5-qt6"
        or report.get("generator")
        != "tools/upstream/probe_qt6_archive_dispatch.py"
        or report.get("generator_sha256")
        != "c307439025c40b26d769fb848fd30904e05011976edb91d110ea6d12f309f31d"
        or report.get("named_members") != named_members
        or report.get("passed") is not True
        or report.get("failures") != []
        or report.get("private_suite_order")
        != ["npm", "generic_archive"]
    ):
        raise ClosurePlanError("Qt6 archive-dispatch identity drift")
    facts = report.get("facts")
    if (
        not isinstance(facts, dict)
        or set(facts)
        != {
            "all_eight_named_dispatch_members_are_covered",
            "all_public_dispatch_and_generic_controls_are_covered",
            "generic_archive_private_branch_matches_qt5",
            "npm_private_branch_matches_qt5",
            "public_dispatch_matches_qt5",
            "source_family_inventory_is_exhaustive",
        }
        or not all(value is True for value in facts.values())
    ):
        raise ClosurePlanError("Qt6 archive-dispatch relationship drift")
    public = report.get("public_dispatch")
    if (
        not isinstance(public, dict)
        or public.get("report_path")
        != "docs/research/data/cli-output-matrix-linux-qt5-qt6.json"
        or public.get("report_sha256")
        != "3e032534ce269597c98eee45c1e477796a11402ec1fb07b7a79a7806cad7ba2c"
        or not isinstance(public.get("cases"), dict)
        or set(public["cases"]) != set(expected_public)
    ):
        raise ClosurePlanError("Qt6 archive-dispatch public catalog drift")
    for case_name, expected_filetype in expected_public.items():
        case = public["cases"][case_name]
        tree = case.get("detect_tree")
        if (
            case.get("qt5") != case.get("qt6")
            or not isinstance(tree, list)
            or len(tree) != 1
            or tree[0].get("filetype") != expected_filetype
            or case.get("qt5", {}).get("exit_code") != 0
        ):
            raise ClosurePlanError(
                f"Qt6 archive-dispatch public drift: {case_name}"
            )
    if report.get("archive_gap_reference") != {
        "engine_extraction_families": [
            "ZIP",
            "7Z",
            "RAR",
            "CAB",
            "ISO9660",
        ],
        "report_path": "docs/research/data/archive-gap-closure.json",
        "report_sha256": (
            "1b727c06c87a14fcb217e0fd69b3b8f935e1f2b7930461ff2a76dc3ffa8996b5"
        ),
        "source_inventory_is_exhaustive": True,
    }:
        raise ClosurePlanError(
            "Qt6 archive-dispatch source inventory drift"
        )

    expected_private = {
        "npm": {
            "baseline": "npm-dispatch-engine-qt5.json",
            "baseline_sha": (
                "d23168aff29696f46d3579f6d914353865035bd02a8bbbcf9af065475c036ce7"
            ),
            "projection": (
                "ca5a01ab0178e877089e0a584f8f3649da48dd4ae49dfb49c0bf314592073911"
            ),
            "image": (
                "sha256:8c6311d4740eb15055cb8bf474b1c3c36ede78fe9f2293ce5673b86c12957f64"
            ),
            "harness": (
                "b623930bca7301706edad4ab66ebef4718012d112015da7a1b2dae76ea70416f"
            ),
            "dockerfile": (
                "tools/upstream/Dockerfile.npm-dispatch-harness-qt6"
            ),
            "dockerfile_sha": (
                "1733d2191c6899182b5f89168a7580857a97985f90a45b249623bc72a64a3d3e"
            ),
            "cases": {
                "case-package-json.tgz",
                "npm-invalid-json.tgz",
                "npm-valid.tgz",
                "root-package-json.tgz",
            },
        },
        "generic_archive": {
            "baseline": "generic-archive-dispatch-engine-qt5.json",
            "baseline_sha": (
                "960fca28122af3bddb2fcd22706f5350ee8f4753a79a61cc2338aba7d1f53c04"
            ),
            "projection": (
                "ff2d7f5810f766e629486eeb35f91ca8c2c9b8699bb97524b417e4343b672da6"
            ),
            "image": (
                "sha256:384844c09790b019a388381ed8beee2f160e6d3bd405f19b88cea9b87662095f"
            ),
            "harness": (
                "0969dd12914d20964b2d60d660e904f7706c1b4857f66314589386cddf615be7"
            ),
            "dockerfile": (
                "tools/upstream/"
                "Dockerfile.generic-archive-dispatch-harness-qt6"
            ),
            "dockerfile_sha": (
                "1bda50e76ef9d4b8e4e2d2f9ff263016c08fab4ba38adcd9d7b5f1df89f13247"
            ),
            "cases": {"payload.tar", "payload.txt.gz", "payload.zip"},
        },
    }
    suites = report.get("private_suites")
    if not isinstance(suites, dict) or set(suites) != set(expected_private):
        raise ClosurePlanError(
            "Qt6 archive-dispatch private suite catalog drift"
        )
    for suite_id, expected in expected_private.items():
        suite = suites[suite_id]
        comparison = suite.get("comparison")
        qt6 = suite.get("qt6")
        if comparison != {
            "behavior_projection_equal": True,
            "behavior_projection_sha256": expected["projection"],
            "qt5_report_path": (
                f"docs/research/data/{expected['baseline']}"
            ),
            "qt5_report_sha256": expected["baseline_sha"],
        }:
            raise ClosurePlanError(
                f"Qt6 archive-dispatch comparison drift: {suite_id}"
            )
        if (
            not isinstance(qt6, dict)
            or qt6.get("platform") != "linux-x86_64-qt6"
            or qt6.get("upstream_commit") != UPSTREAM_COMMIT
            or qt6.get("passed") is not True
            or qt6.get("failures") != []
            or qt6.get("qt6_image", {}).get("id") != expected["image"]
            or qt6.get("qt6_binaries", {})
            .get("harness", {})
            .get("sha256")
            != expected["harness"]
            or qt6.get("qt6_binaries", {})
            .get("release", {})
            .get("sha256")
            != "e3321105af0349b29195325e79d5d2c7cc25ead2f28f84e242e3835b98f7283e"
            or qt6.get("local_sources", {})
            .get("harness_dockerfile")
            != {
                "path": expected["dockerfile"],
                "sha256": expected["dockerfile_sha"],
            }
            or qt6.get("facts", {}).get(
                "qt6_release_repetitions_are_byte_equal"
            )
            is not True
        ):
            raise ClosurePlanError(
                f"Qt6 archive-dispatch oracle drift: {suite_id}"
            )
        cases = qt6.get("cases")
        if not isinstance(cases, dict) or set(cases) != expected["cases"]:
            raise ClosurePlanError(
                f"Qt6 archive-dispatch case catalog drift: {suite_id}"
            )
        artifacts = qt6.get("raw_artifacts")
        if not isinstance(artifacts, dict) or not artifacts:
            raise ClosurePlanError(
                f"Qt6 archive-dispatch artifacts missing: {suite_id}"
            )
        for digest, artifact in artifacts.items():
            try:
                compressed = base64.b64decode(
                    artifact["base64"], validate=True
                )
                raw = zlib.decompress(compressed)
            except (KeyError, ValueError, zlib.error) as error:
                raise ClosurePlanError(
                    f"Qt6 archive-dispatch artifact invalid: {suite_id}"
                ) from error
            if (
                len(raw) != artifact.get("bytes")
                or sha256(raw) != digest
            ):
                raise ClosurePlanError(
                    f"Qt6 archive-dispatch artifact drift: {suite_id}"
                )
        referenced = set()
        for case in cases.values():
            for observation in case.values():
                if not isinstance(observation, dict):
                    continue
                for stream in ("stdout", "stderr"):
                    reference = observation.get(stream)
                    if (
                        isinstance(reference, dict)
                        and "artifact_sha256" in reference
                    ):
                        referenced.add(reference["artifact_sha256"])
        if referenced != set(artifacts):
            raise ClosurePlanError(
                f"Qt6 archive-dispatch artifact references drift: {suite_id}"
            )

    npm_cases = suites["npm"]["qt6"]["cases"]
    for name, case in npm_cases.items():
        output = case["harness"]["output"]
        expected_direct = name in {
            "npm-valid.tgz",
            "npm-invalid-json.tgz",
        }
        if (
            output.get("direct_npm_valid") is not expected_direct
            or output.get("automatic", {}).get("initial_filetype")
            != "Binary"
            or output.get("forced_npm", {}).get("initial_filetype")
            != "NPM"
            or case.get("release_repetition_1")
            != case.get("release_repetition_2")
        ):
            raise ClosurePlanError(
                f"Qt6 archive-dispatch NPM semantic drift: {name}"
            )
    generic_cases = suites["generic_archive"]["qt6"]["cases"]
    for name, case in generic_cases.items():
        output = case["harness"]["output"]
        quiet_records = output.get("forced_archive_quiet", {}).get(
            "records"
        )
        verbose_records = output.get(
            "forced_archive_verbose", {}
        ).get("records")
        if (
            output.get("automatic_quiet", {}).get("initial_filetype")
            == "Archive"
            or not isinstance(quiet_records, list)
            or len(quiet_records) != 1
            or quiet_records[0].get("name") != "Unknown"
            or not isinstance(verbose_records, list)
            or len(verbose_records) != 1
            or verbose_records[0].get("name") == "Unknown"
            or case.get("release_repetition_1_quiet")
            != case.get("release_repetition_2_quiet")
            or case.get("release_repetition_1_verbose")
            != case.get("release_repetition_2_verbose")
        ):
            raise ClosurePlanError(
                f"Qt6 archive-dispatch generic semantic drift: {name}"
            )


def _validate_archive_limit_report(report: dict[str, Any]) -> None:
    stable_fields = [
        "callback_calls",
        "cancel_after_callbacks",
        "cyclic_node_count",
        "debug_record_count",
        "deepest_pdf_depth",
        "error_count",
        "handler_count",
        "max_depth",
        "max_stream_depth",
        "node_count",
        "pdf_node_count",
        "pd_stopped",
        "record_count",
        "stream_node_count",
    ]
    expected_local_sources = {
        "tools/upstream/Dockerfile.archive-limits-harness-qt6": (
            "2e5faf4b76cd2097670e571cb630691067a526e1c364b6f2ee86e4c923317ecf"
        ),
        "tools/upstream/archive_limits_harness_main.cpp": (
            "9bba1c21cf01b93a1ac80ab5cea4145330e1b2621d9f2b6e4275ab04723a68a4"
        ),
        "tools/upstream/probe_archive_limits_harness.py": (
            "d26e07aea850a5b9f1939fe23df7f01abd5e5f0857cf07d80463a85c9a1c8f12"
        ),
    }
    expected_supporting_hashes = {
        "archive_family_and_qt5_limit_closure": (
            "docs/research/data/archive-gap-closure.json",
            "1b727c06c87a14fcb217e0fd69b3b8f935e1f2b7930461ff2a76dc3ffa8996b5",
        ),
        "archive_iteration_boundary": (
            "docs/research/data/archive-iteration-boundary-engine-qt6.json",
            "50b23210a24620561c19c9bf902f165030e4dbb10b8ecda9ebe5bc996670ba65",
        ),
        "archive_option_and_internal_recursion_gate": (
            "docs/research/data/archive-option-engine-qt5-qt6.json",
            "5cdadeb09d97a0afd03b2f73ebbb5eb4ffd227b9a21973d34d5a3db739bb8d65",
        ),
        "archive_private_and_public_dispatch": (
            "docs/research/data/archive-dispatch-linux-qt5-qt6.json",
            "7f4492a0ab48714d5654f5d244266de822c2268c766a2eb75a9de066cc1cb52b",
        ),
        "cli_recursion_gate": (
            "docs/research/data/cli-scan-nested-matrix-linux-qt5-qt6.json",
            "a81ed4e791286c78247ca1d758fcb49900ca93ac46941af3d0542801d7e603f8",
        ),
        "resource_context_and_subdevice_gate": (
            "docs/research/data/resource-context-chain-qt6.json",
            "0619aa5e1768ef4044d9cd60378dd991057bb97960b70887b0de84552978aabc",
        ),
        "resource_record_count_boundary": (
            "docs/research/data/scan-option-boundaries-linux-qt6.json",
            "4f9f4e1c249ebc7b8b6277544ba4c5790bbab3a5ed2158580b79dd6356b6841f",
        ),
    }
    expected_supporting = {
        role: {"path": path, "sha256": digest}
        for role, (path, digest) in expected_supporting_hashes.items()
    }
    expected_facts = {
        "cancellation_partial_prefix_is_equal",
        "depth_64_is_reached_on_both_qt_versions",
        "expanded_33554546_bytes_is_reached_on_both_qt_versions",
        "full_stable_behavior_projection_is_equal",
        "local_probe_sources_are_hash_bound",
        "raw_qt6_stdout_stderr_are_retained",
        "source_contract_is_equal",
        "supporting_nested_boundaries_are_hash_bound",
    }
    facts = report.get("facts", {})
    if (
        report.get("schema_version") != 1
        or report.get("capability") != "CAP-NEST-009"
        or report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("platform") != "linux-x86_64-qt5-qt6"
        or report.get("generator")
        != "tools/upstream/probe_qt6_archive_limits.py"
        or report.get("generator_sha256")
        != "08dd4329d2712257596cb8095c94117a1a34e6dfca23dbe3b7998db6ec07f980"
        or report.get("passed") is not True
        or report.get("failures") != []
        or report.get("local_sources") != expected_local_sources
        or report.get("supporting_reports") != expected_supporting
        or set(facts) != expected_facts
        or not all(value is True for value in facts.values())
    ):
        raise ClosurePlanError("Qt6 archive-limit identity drift")
    if report.get("qt5_reference") != {
        "path": "docs/research/data/archive-limit-engine-qt5.json",
        "sha256": (
            "e4786dcc578fb0714c86f71955161f981a06be26aefe663281d74202f5372ecd"
        ),
    }:
        raise ClosurePlanError("Qt5 archive-limit reference drift")
    comparison = report.get("comparison", {})
    if (
        comparison.get("behavior_projection_equal") is not True
        or comparison.get("behavior_projection_sha256")
        != "b10e21874a95cf675d521ae04ff8a1297fbb9bb054cdbe29b6757f5277503848"
        or comparison.get("stable_harness_fields") != stable_fields
    ):
        raise ClosurePlanError("archive-limit comparison drift")

    qt6 = report.get("qt6", {})
    environment = qt6.get("environment", {})
    source = qt6.get("source_contract", {})
    assertions = qt6.get("assertions", {})
    if (
        qt6.get("schema_version") != 1
        or qt6.get("capability") != "CAP-NEST-009"
        or qt6.get("upstream_commit") != UPSTREAM_COMMIT
        or qt6.get("xscanengine_commit")
        != "dfe4a419e4f491bb23688ba03c5a5bf39e34da83"
        or qt6.get("passed") is not True
        or qt6.get("failures") != []
        or not assertions
        or not all(value is True for value in assertions.values())
        or environment.get("platform") != "linux-x86_64-qt6"
        or environment.get("container_network") != "none"
        or environment.get("image_identity", {}).get("id")
        != "sha256:1a264871bcffab7b2c222d79c2f9800ac272df053166a91c3cdf36c6941b08e2"
        or qt6.get("harness_binary", {}).get("sha256")
        != "31c38b40ee7a0afa0d0e482789b75f7ab151448bb2ee0c0150011f51a596dcc9"
        or qt6.get("corpus_manifest_sha256")
        != "09e31c8373cd151c68d41aab18fefd7e18fff54c29b8d56c16196276660c5cd5"
        or source.get("sha256")
        != "e088bebb7c8345ce5832cc51de712c05a8b239873d7f092db3ae5566a761b498"
        or any(source.get("negative_token_counts", {}).values())
    ):
        raise ClosurePlanError("Qt6 archive-limit oracle drift")

    samples = qt6.get("corpus", {}).get("samples", [])
    cases = qt6.get("normal_cases", [])
    if len(samples) != 14 or len(cases) != 14:
        raise ClosurePlanError("Qt6 archive-limit case catalog drift")
    sample_by_name = {sample.get("name"): sample for sample in samples}
    case_by_name = {case.get("sample"): case for case in cases}
    if set(sample_by_name) != set(case_by_name):
        raise ClosurePlanError("Qt6 archive-limit sample mapping drift")

    def project_case(case: dict[str, Any]) -> dict[str, Any]:
        harness = case.get("harness", {})
        stdout = case.get("stdout", "").encode("utf-8")
        stderr = case.get("stderr", "").encode("utf-8")
        try:
            decoded_stdout = json.loads(stdout)
        except json.JSONDecodeError as error:
            raise ClosurePlanError(
                f"Qt6 archive-limit invalid stdout: {case.get('case')}"
            ) from error
        if (
            hashlib.sha256(stdout).hexdigest()
            != case.get("stdout_sha256")
            or hashlib.sha256(stderr).hexdigest()
            != case.get("stderr_sha256")
            or decoded_stdout != harness
            or case.get("exit_code") != 0
            or case.get("timed_out") is not False
            or case.get("possible_oom_exit_137") is not False
            or stderr
        ):
            raise ClosurePlanError(
                f"Qt6 archive-limit raw case drift: {case.get('case')}"
            )
        return {
            "arguments": case.get("arguments"),
            "case": case.get("case"),
            "exit_code": case.get("exit_code"),
            "harness": {
                field: harness.get(field) for field in stable_fields
            },
            "possible_oom_exit_137": case.get(
                "possible_oom_exit_137"
            ),
            "sample": case.get("sample"),
            "stderr": case.get("stderr"),
            "stderr_sha256": case.get("stderr_sha256"),
            "timed_out": case.get("timed_out"),
        }

    projected_cases = [project_case(case) for case in cases]
    cancellation = qt6.get("cancellation_case", {})
    projected_cancellation = project_case(cancellation)
    deepest = case_by_name.get("depth-64.zip", {}).get("harness", {})
    largest = case_by_name.get(
        "expanded-16777216.zip", {}
    ).get("harness", {})
    if (
        sample_by_name.get("depth-64.zip", {}).get("depth") != 64
        or deepest.get("deepest_pdf_depth") != 64
        or deepest.get("stream_node_count") != 64
        or sample_by_name.get(
            "expanded-16777216.zip", {}
        ).get("cumulative_expanded_bytes")
        != 33_554_546
        or largest.get("deepest_pdf_depth") != 2
        or cancellation.get("sample") != "depth-64.zip"
        or cancellation.get("harness", {}).get("pd_stopped") is not True
        or cancellation.get("harness", {}).get("record_count", 0)
        >= deepest.get("record_count", 0)
    ):
        raise ClosurePlanError("Qt6 archive-limit semantic drift")
    projection = {
        "assertions": qt6.get("assertions"),
        "cancellation_case": projected_cancellation,
        "corpus": qt6.get("corpus"),
        "corpus_manifest_sha256": qt6.get("corpus_manifest_sha256"),
        "normal_cases": projected_cases,
        "source_contract": qt6.get("source_contract"),
        "upstream_commit": qt6.get("upstream_commit"),
        "xscanengine_commit": qt6.get("xscanengine_commit"),
    }
    projection_hash = hashlib.sha256(
        json.dumps(
            projection,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    if projection_hash != comparison["behavior_projection_sha256"]:
        raise ClosurePlanError(
            "Qt6 archive-limit stable projection drift"
        )


def _validate_database_matrix_report(report: dict[str, Any]) -> None:
    if (
        report.get("expected_revision") != UPSTREAM_COMMIT
        or report.get("left_revision") != UPSTREAM_COMMIT
        or report.get("right_revision") != UPSTREAM_COMMIT
    ):
        raise ClosurePlanError("CLI database matrix revision drift")
    if report.get("equal") is not False:
        raise ClosurePlanError(
            "CLI database matrix must retain parse diagnostic difference"
        )
    cases = report.get("cases")
    unreadable = report.get("unreadable_input")
    fixture = report.get("database_fixture")
    database_cases = (
        fixture.get("cases") if isinstance(fixture, dict) else None
    )
    if not all(
        isinstance(value, dict)
        for value in (cases, unreadable, fixture, database_cases)
    ):
        raise ClosurePlanError("CLI database matrix sections are missing")
    expected_cases = {
        "show_database_missing_main",
        "show_database_missing_main_messages",
        "show_database_empty_main",
        "show_database_invalid_archive",
        "show_database_invalid_archive_messages",
        "show_database_malformed_main",
        "scan_missing_main_json",
        "scan_missing_main_messages_json",
        "scan_empty_main_json",
        "scan_invalid_archive_json",
        "scan_invalid_archive_messages_json",
        "scan_malformed_main_json",
        "scan_throwing_main_json",
        "scan_valid_main_json",
        "entropy_missing_main_messages_json",
        "info_missing_main_messages_json",
        "scan_valid_main_missing_extra_json",
        "show_database_valid_main_missing_extra",
    }
    if set(database_cases) != expected_cases:
        raise ClosurePlanError("CLI database case catalog drift")
    expected_failures = {
        "database_fixture.scan_malformed_main_json.stdout"
    }
    for name, record in cases.items():
        _validate_paired_observation(record, {()}, f"cases.{name}")
    for name, record in unreadable.items():
        _validate_paired_observation(
            record, {()}, f"unreadable_input.{name}"
        )
    for name, record in database_cases.items():
        label = f"database_fixture.{name}"
        differences = tuple(record.get("differences", []))
        if name == "scan_malformed_main_json":
            if (
                differences != ("stdout",)
                or record.get("left", {}).get("exit_code")
                != record.get("right", {}).get("exit_code")
                or record.get("left", {}).get("stderr_sha256")
                != record.get("right", {}).get("stderr_sha256")
            ):
                raise ClosurePlanError(
                    "CLI malformed database difference drift"
                )
        else:
            _validate_paired_observation(record, {()}, label)
        if record.get("left_reports_load_error") != record.get(
            "right_reports_load_error"
        ):
            raise ClosurePlanError(
                f"CLI database load-error difference: {name}"
            )
        if "left_valid_json" in record and record.get(
            "left_valid_json"
        ) != record.get("right_valid_json"):
            raise ClosurePlanError(
                f"CLI database JSON framing difference: {name}"
            )
    for name in (
        "show_database_missing_main_messages",
        "scan_missing_main_messages_json",
        "entropy_missing_main_messages_json",
        "info_missing_main_messages_json",
    ):
        if database_cases[name].get("left_reports_load_error") is not True:
            raise ClosurePlanError(
                f"CLI database message channel drift: {name}"
            )
    empty = database_cases["scan_empty_main_json"]
    if (
        empty["left"].get("stdout_sha256")
        != "83cbe006c9b24c93260312b75a213904e76b75b7fcdb17612c6640f37a20c78c"
        or empty["right"].get("stdout_sha256")
        != empty["left"].get("stdout_sha256")
    ):
        raise ClosurePlanError("CLI empty database fallback drift")
    if set(report.get("failures", [])) != expected_failures:
        raise ClosurePlanError("CLI database failure catalog drift")
    if (
        fixture.get("generator")
        != "tools/corpus/generate_database_fixture.py"
        or len(fixture.get("directories", [])) != 10
        or len(fixture.get("entries", [])) != 15
    ):
        raise ClosurePlanError("CLI database fixture catalog drift")


def _validate_database_diagnostics(report: dict[str, Any]) -> None:
    if report.get("upstream_commit") != UPSTREAM_COMMIT:
        raise ClosurePlanError("database diagnostic revision drift")
    if report.get("passed") is not True:
        raise ClosurePlanError("database diagnostic probe did not pass")
    facts = report.get("facts")
    if not isinstance(facts, dict) or not facts or not all(
        value is True for value in facts.values()
    ):
        raise ClosurePlanError("database diagnostic facts changed")
    repetitions = report.get("repetitions")
    if not isinstance(repetitions, int) or repetitions < 2:
        raise ClosurePlanError("database diagnostic repetitions drift")
    expected = {
        "malformed": {
            "qt5": (
                "broken.1.sg: Binary/broken.1.sg: 1: "
                "SyntaxError: Parse error\n\n"
            ),
            "qt6": (
                "broken.1.sg: Binary/broken.1.sg: 2: "
                "SyntaxError: Expected token `}'\n\n"
            ),
        },
        "throwing": {
            "qt5": (
                "throw.1.sg: Binary/throw.1.sg: 2: "
                "Error: database fixture\n\n"
            ),
            "qt6": (
                "throw.1.sg: Binary/throw.1.sg: 2: "
                "Error: database fixture\n\n"
            ),
        },
    }
    if report.get("expected_diagnostics") != expected:
        raise ClosurePlanError("database expected diagnostics drift")
    cases = report.get("cases")
    if not isinstance(cases, dict) or set(cases) != set(expected):
        raise ClosurePlanError("database diagnostic case catalog drift")
    for case_name, case in cases.items():
        observations = case.get("observations")
        if not isinstance(observations, dict) or set(observations) != {
            "qt5",
            "qt6",
        }:
            raise ClosurePlanError(
                f"database diagnostic oracle drift: {case_name}"
            )
        baseline = observations["qt5"][0].get("json_document")
        for oracle_name, items in observations.items():
            if len(items) != repetitions:
                raise ClosurePlanError(
                    f"database diagnostic repetition drift: {case_name}"
                )
            for index, item in enumerate(items):
                label = f"{case_name}.{oracle_name}.{index}"
                try:
                    stdout = base64.b64decode(
                        item["stdout_base64"], validate=True
                    )
                    stderr = base64.b64decode(
                        item["stderr_base64"], validate=True
                    )
                except (KeyError, ValueError) as error:
                    raise ClosurePlanError(
                        f"invalid database raw stream: {label}"
                    ) from error
                if (
                    len(stdout) != item.get("stdout_bytes")
                    or sha256(stdout) != item.get("stdout_sha256")
                    or len(stderr) != item.get("stderr_bytes")
                    or sha256(stderr) != item.get("stderr_sha256")
                ):
                    raise ClosurePlanError(
                        f"database raw stream identity drift: {label}"
                    )
                if (
                    item.get("json_document") != baseline
                    or item.get("diagnostics")
                    != expected[case_name][oracle_name]
                    or stderr != b""
                    or item.get("exit_code") != 0
                ):
                    raise ClosurePlanError(
                        f"database diagnostic semantic drift: {label}"
                    )


def _validate_option_behavior_report(report: dict[str, Any]) -> None:
    if (
        report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("result") != "equal"
    ):
        raise ClosurePlanError("CLI option report identity/result drift")
    cases = report.get("cases")
    expected_cases = {
        "test_existing_directory",
        "test_missing_directory",
        "createtest_missing_positionals",
        "createtest_complete",
        "scan_default_json",
        "scan_verbose_json",
        "scan_profiling_without_messages_json",
        "showdatabase_missing_without_messages",
        "showdatabase_missing_with_messages",
    }
    if not isinstance(cases, dict) or set(cases) != expected_cases:
        raise ClosurePlanError("CLI option case catalog drift")
    if not all(
        case.get("all_oracles_equal") is True for case in cases.values()
    ):
        raise ClosurePlanError("CLI option oracle difference")
    oracles = report.get("oracles")
    if (
        not isinstance(oracles, list)
        or [oracle.get("name") for oracle in oracles]
        != ["linux-qt5-cmake", "linux-qt6-cmake"]
        or any(
            oracle.get("revision") != UPSTREAM_COMMIT
            for oracle in oracles
        )
    ):
        raise ClosurePlanError("CLI option oracle identity drift")
    relationships = report.get("relationships")
    if not isinstance(relationships, dict):
        raise ClosurePlanError("CLI option relationships missing")
    required_true = (
        "test_directory_value_is_unvalidated",
        "createtest_complete_only_prints_announcement",
        "createtest_missing_positionals_uses_addtest_name",
        "profiling_without_messages_equals_default",
        "all_stderr_empty",
    )
    if not all(relationships.get(name) is True for name in required_true):
        raise ClosurePlanError("CLI option relationship drift")
    if (
        relationships.get("createtest_missing_positionals_exit_code") != 4
        or relationships.get("verbose_added_values")
        != [
            {
                "info": "AMD64, 64-bit",
                "name": "Linux",
                "type": "operation system",
                "version": "ABI: 3.2.0",
            }
        ]
        or relationships.get("verbose_removed_values") != []
    ):
        raise ClosurePlanError("CLI option delta drift")


def _validate_binary_rule_order_report(report: dict[str, Any]) -> None:
    if (
        report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("rules_commit") != RULES_COMMIT
        or report.get("result") != "equal"
        or report.get("orders_equal") is not True
    ):
        raise ClosurePlanError("Binary profiling report identity/result drift")
    order = report.get("order")
    if (
        not isinstance(order, list)
        or len(order) != 292
        or len(set(order)) != 292
        or report.get("order_count") != 292
    ):
        raise ClosurePlanError("Binary profiling order catalog drift")
    order_bytes = "".join(f"{name}\n" for name in order).encode("utf-8")
    expected_hash = (
        "27138d68ed788dd2609b7c533fecf540593fa2e4ddb7195adc26b1a9ff0e1ff3"
    )
    if (
        sha256(order_bytes) != expected_hash
        or report.get("order_sha256") != expected_hash
    ):
        raise ClosurePlanError("Binary profiling order hash drift")
    lifecycle = report.get("lifecycle_manifest")
    if lifecycle != {
        "path": "docs/research/data/binary-rule-lifecycle.json",
        "sha256": (
            "6cf78bbe8c95886978dfba825e2f4d4b130cd92491ecb7f19049cfbd6374e092"
        ),
    }:
        raise ClosurePlanError("Binary profiling lifecycle identity drift")
    oracles = report.get("oracles")
    if (
        not isinstance(oracles, list)
        or [oracle.get("name") for oracle in oracles]
        != ["linux-qt5-cmake", "linux-qt6-cmake"]
    ):
        raise ClosurePlanError("Binary profiling oracle catalog drift")
    for oracle in oracles:
        if (
            oracle.get("revision") != UPSTREAM_COMMIT
            or oracle.get("exit_code") != 0
            or oracle.get("raw_stderr_bytes") != 0
            or oracle.get("raw_stderr_sha256") != EMPTY_SHA256
            or oracle.get("order_count") != 292
            or oracle.get("order_sha256") != expected_hash
        ):
            raise ClosurePlanError(
                f"Binary profiling oracle drift: {oracle.get('name')}"
            )


def _validate_engine_contract_reports(
    qt5: dict[str, Any], qt6: dict[str, Any]
) -> None:
    expected_scope = {
        "CAP-ENG-IN-001",
        "CAP-ENG-IN-002",
        "CAP-RULE-006",
        "CAP-RULE-009",
        "CAP-RULE-012",
    }
    if (
        qt6.get("schema_version") != 1
        or qt6.get("upstream_commit") != UPSTREAM_COMMIT
        or qt6.get("platform") != "linux-amd64-qt6"
        or qt6.get("result") != "observed"
        or set(qt6.get("capability_scope", [])) != expected_scope
    ):
        raise ClosurePlanError("Qt6 engine-contract identity/result drift")
    oracle = qt6.get("oracle", {})
    if (
        oracle.get("image")
        != "die-rust/engine-contract-harness-qt6:74eaf505"
        or oracle.get("image_id")
        != "sha256:ffd09170f4c37a49bffff6a3c3c59469c19caabf6aa9c78f0981e1bd95591a6b"
        or oracle.get("revision") != UPSTREAM_COMMIT
        or oracle.get("exit_code") != 0
        or oracle.get("raw_stderr_bytes") != 0
        or oracle.get("raw_stderr_sha256") != EMPTY_SHA256
    ):
        raise ClosurePlanError("Qt6 engine-contract oracle drift")
    output = qt6.get("harness_output", {})
    if (
        output.get("case_count") != 37
        or not isinstance(output.get("cases"), list)
        or len(output["cases"]) != 37
    ):
        raise ClosurePlanError("Qt6 engine-contract case catalog drift")
    relationships = qt6.get("relationships")
    if (
        not isinstance(relationships, dict)
        or len(relationships) != 23
        or not all(value is True for value in relationships.values())
    ):
        raise ClosurePlanError("Qt6 engine-contract relationship drift")
    if relationships != qt5.get("relationships"):
        raise ClosurePlanError("Qt5/Qt6 engine-contract relationship drift")
    if qt6.get("fixture_manifest") != qt5.get("fixture_manifest"):
        raise ClosurePlanError("Qt5/Qt6 engine-contract fixture drift")
    if qt6.get("source_audit") != qt5.get("source_audit"):
        raise ClosurePlanError("Qt5/Qt6 engine-contract source audit drift")


def _validate_rule_orchestration_reports(
    qt5: dict[str, Any], comparison: dict[str, Any]
) -> None:
    expected_scope = {
        "CAP-RULE-001",
        "CAP-RULE-002",
        "CAP-RULE-003",
        "CAP-RULE-004",
        "CAP-RULE-005",
    }
    if (
        comparison.get("schema_version") != 1
        or comparison.get("upstream_commit") != UPSTREAM_COMMIT
        or comparison.get("platform") != "linux-amd64-qt5-qt6"
        or comparison.get("result") != "equal"
        or comparison.get("normalized_outputs_equal") is not True
        or set(comparison.get("capability_scope", [])) != expected_scope
    ):
        raise ClosurePlanError(
            "Qt6 rule-orchestration identity/result drift"
        )
    oracles = comparison.get("oracles")
    expected_oracles = (
        (
            "linux-qt5-cmake",
            "sha256:466102628c3a94b7ab1048f0c24261b1920e61a40029b128763cf79370255040",
        ),
        (
            "linux-qt6-cmake",
            "sha256:e015495c313d0715f0b80f395da983a113a439f2a135eb637e9f0638c225200b",
        ),
    )
    if (
        not isinstance(oracles, list)
        or len(oracles) != 2
        or tuple(
            (oracle.get("name"), oracle.get("image_id"))
            for oracle in oracles
        )
        != expected_oracles
    ):
        raise ClosurePlanError("Qt6 rule-orchestration oracle drift")
    for oracle in oracles:
        if oracle.get("revision") != UPSTREAM_COMMIT:
            raise ClosurePlanError(
                "Qt6 rule-orchestration oracle revision drift"
            )
        cases = oracle.get("cases")
        if not isinstance(cases, dict) or len(cases) != 10:
            raise ClosurePlanError(
                "Qt6 rule-orchestration case catalog drift"
            )
        if any(
            case.get("exit_code") != 0
            or case.get("raw_stderr_bytes") != 0
            or case.get("raw_stderr_sha256") != EMPTY_SHA256
            for case in cases.values()
        ):
            raise ClosurePlanError(
                "Qt6 rule-orchestration raw observation drift"
            )
    relationships = comparison.get("relationships")
    if (
        not isinstance(relationships, dict)
        or len(relationships) != 14
        or not all(value is True for value in relationships.values())
    ):
        raise ClosurePlanError(
            "Qt6 rule-orchestration relationship drift"
        )
    if relationships != qt5.get("relationships"):
        raise ClosurePlanError(
            "Qt5/Qt6 rule-orchestration relationship drift"
        )
    if comparison.get("canonical_cases") != qt5.get("canonical_cases"):
        raise ClosurePlanError(
            "Qt5/Qt6 rule-orchestration canonical case drift"
        )
    if comparison.get("fixture_manifest") != qt5.get("fixture_manifest"):
        raise ClosurePlanError(
            "Qt5/Qt6 rule-orchestration fixture drift"
        )


def _scalar_differences(
    left: Any, right: Any, path: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    if type(left) is not type(right):
        return [{"path": "/".join(path), "qt5": left, "qt6": right}]
    if isinstance(left, dict):
        differences = []
        for key in sorted(set(left) | set(right)):
            child_path = (*path, str(key))
            if key not in left or key not in right:
                differences.append(
                    {
                        "path": "/".join(child_path),
                        "qt5": left.get(key, "<missing>"),
                        "qt6": right.get(key, "<missing>"),
                    }
                )
            else:
                differences.extend(
                    _scalar_differences(
                        left[key],
                        right[key],
                        child_path,
                    )
                )
        return differences
    if isinstance(left, list):
        if len(left) != len(right):
            return [
                {
                    "path": "/".join((*path, "length")),
                    "qt5": len(left),
                    "qt6": len(right),
                }
            ]
        differences = []
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            differences.extend(
                _scalar_differences(
                    left_item,
                    right_item,
                    (*path, str(index)),
                )
            )
        return differences
    if left == right:
        return []
    return [{"path": "/".join(path), "qt5": left, "qt6": right}]


def _collect_result_records(
    value: Any, path: tuple[str, ...] = ()
) -> dict[str, dict[str, Any]]:
    records = {}
    if isinstance(value, dict):
        if {"type", "name", "version", "info", "priority"} <= set(value):
            records["/".join(path)] = value
        for key, child in value.items():
            records.update(
                _collect_result_records(child, (*path, str(key)))
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            records.update(
                _collect_result_records(child, (*path, str(index)))
            )
    return records


def _validate_result_model_reports(
    qt5_reports: dict[str, dict[str, Any]],
    global_qt5: dict[str, Any],
    global_qt6: dict[str, Any],
    engine_qt6: dict[str, Any],
    bundle: dict[str, Any],
) -> None:
    profiles = ("metadata", "lists", "ids", "flags", "enums")
    expected_scope = {f"CAP-RESULT-00{index}" for index in range(1, 7)}
    if (
        bundle.get("schema_version") != 1
        or bundle.get("upstream_commit") != UPSTREAM_COMMIT
        or bundle.get("platform") != "linux-amd64-qt6"
        or bundle.get("result") != "observed"
        or set(bundle.get("capability_scope", [])) != expected_scope
        or set(bundle.get("reports", {})) != set(profiles)
        or set(bundle.get("comparisons", {})) != set(profiles)
    ):
        raise ClosurePlanError("Qt6 result-model identity/result drift")
    expected_images = {
        "metadata": "sha256:50a28ac93d422b86246be12da48e0c25ed71786cb8a069b32d436fcf44679cfa",
        "lists": "sha256:7b3f4b9f9a87a6cf07a2c9a6dafdf32cc5020071174bcb0e89f2e86842645444",
        "ids": "sha256:5a705ac19dbcff4ff3d72710dfaa4542401cb4e04414d896606e8812f2105bc4",
        "flags": "sha256:7476806c3f776636993bf0c48911557dcde1d677c2d960a5336ca81101153fe6",
        "enums": "sha256:ea9e04d6ad279f7c058e58571ace05313c95ff3cb4e4c8a05d322d999810c434",
    }
    expected_paths = {
        "metadata": {
            f"cases/{index}/nScanTime" for index in range(4)
        },
        "lists": {"cases/1/errors/1/message"},
        "ids": {
            "records/0/id/uuid",
            "records/1/id/uuid",
            "records/1/parent_id/uuid",
        },
        "flags": set(),
        "enums": set(),
    }
    for profile in profiles:
        qt5 = qt5_reports[profile]
        qt6 = bundle["reports"][profile]
        oracle = qt6.get("oracle", {})
        if (
            qt6.get("platform") != "linux-amd64-qt6"
            or oracle.get("image_id") != expected_images[profile]
            or oracle.get("revision") != UPSTREAM_COMMIT
            or oracle.get("exit_code") != 0
            or oracle.get("raw_stderr_bytes") != 0
            or oracle.get("raw_stderr_sha256") != EMPTY_SHA256
            or not all(qt6.get("relationships", {}).values())
        ):
            raise ClosurePlanError(
                f"Qt6 result-model oracle drift: {profile}"
            )
        comparison = bundle["comparisons"][profile]
        differences = _scalar_differences(
            qt5.get("harness_output"),
            qt6.get("harness_output"),
        )
        if (
            qt5.get("relationships") != qt6.get("relationships")
            or qt5.get("fixture") != qt6.get("fixture")
            or comparison.get("relationships_equal") is not True
            or comparison.get("fixture_equal") is not True
            or comparison.get("differences_classified") is not True
            or comparison.get("harness_output_differences") != differences
            or {item["path"] for item in differences}
            != expected_paths[profile]
        ):
            raise ClosurePlanError(
                f"Qt5/Qt6 result-model comparison drift: {profile}"
            )
    list_differences = bundle["comparisons"]["lists"][
        "harness_output_differences"
    ]
    if list_differences != [
        {
            "path": "cases/1/errors/1/message",
            "qt5": (
                "Binary/d_parse_error.1.sg: 1: SyntaxError: Parse error"
            ),
            "qt6": (
                "Binary/d_parse_error.1.sg: 2: "
                "SyntaxError: Expected token `}'"
            ),
        }
    ]:
        raise ClosurePlanError("Qt6 result-list diagnostic drift")

    qt5_records = _collect_result_records(global_qt5["observation"])
    qt6_records = _collect_result_records(global_qt6["observation"])
    common_paths = set(qt5_records) & set(qt6_records)
    qt5_only = sorted(set(qt5_records) - set(qt6_records))
    expected_qt5_only = [
        (
            "isolated_query_conversions/cyclic_array_count/"
            "observation/final_records/0"
        ),
        "missing_arguments/count/records/0",
        "missing_arguments/is_present/records/0",
        "missing_arguments/set_result/records/0",
    ]
    common_values = [qt6_records[path] for path in sorted(common_paths)]
    engine_records = _collect_result_records(
        engine_qt6["harness_output"]
    )
    rule_records = [
        record
        for record in engine_records.values()
        if record.get("signature") and record.get("signature_file")
    ]
    expected_facts = {
        "common_hostapi_records_equal": all(
            qt5_records[path] == qt6_records[path]
            for path in common_paths
        ),
        "runtime_specific_record_difference_is_exact": (
            qt5_only == expected_qt5_only
            and not (set(qt6_records) - set(qt5_records))
        ),
        "nonempty_version_and_info_are_observed": any(
            record["version"] and record["info"]
            for record in common_values
        ),
        "hostapi_priorities_cover_multiple_types": (
            {30, 70, 90}
            <= {record["priority"] for record in common_values}
        ),
        "engine_rule_name_and_path_are_observed": bool(rule_records),
        "engine_rule_priorities_are_observed": (
            {12, 30, 100}
            <= {record["priority"] for record in rule_records}
        ),
    }
    metadata = bundle.get("record_metadata_comparison", {})
    if (
        metadata.get("common_record_count") != len(common_paths)
        or metadata.get("qt5_only_record_paths") != qt5_only
        or metadata.get("qt6_only_record_paths") != []
        or metadata.get("facts") != expected_facts
        or not all(expected_facts.values())
    ):
        raise ClosurePlanError("Qt6 result record metadata drift")


def _validate_signature_path_reports(
    qt5: dict[str, Any], qt6: dict[str, Any]
) -> None:
    oracle = qt6.get("oracle", {})
    if (
        qt6.get("schema_version") != 1
        or qt6.get("upstream_commit") != UPSTREAM_COMMIT
        or qt6.get("platform") != "linux-amd64-qt6"
        or qt6.get("capability") != "CAP-RULE-007"
        or qt6.get("result") != "observed"
        or oracle.get("image")
        != "die-rust/signature-path-harness-qt6:74eaf505"
        or oracle.get("image_id")
        != "sha256:df9be77359a4b9eb877ddf03c247ab553385b35b103d617655f973e916a333fd"
        or oracle.get("revision") != UPSTREAM_COMMIT
        or oracle.get("exit_code") != 0
        or oracle.get("raw_stderr_bytes") != 0
        or oracle.get("raw_stderr_sha256") != EMPTY_SHA256
    ):
        raise ClosurePlanError("Qt6 signature-path identity/oracle drift")
    relationships = qt6.get("relationships")
    if (
        not isinstance(relationships, dict)
        or len(relationships) != 11
        or not all(value is True for value in relationships.values())
        or relationships != qt5.get("relationships")
    ):
        raise ClosurePlanError("Qt5/Qt6 signature-path relationship drift")
    if (
        qt6.get("harness_output") != qt5.get("harness_output")
        or qt6.get("fixture") != qt5.get("fixture")
        or qt6.get("harness_output", {}).get("case_count") != 7
    ):
        raise ClosurePlanError("Qt5/Qt6 signature-path output drift")


def _validate_debug_dispatch_reports(
    qt5: dict[str, Any], qt6: dict[str, Any]
) -> None:
    oracle = qt6.get("oracle", {})
    if (
        qt6.get("schema_version") != 1
        or qt6.get("upstream_commit") != UPSTREAM_COMMIT
        or qt6.get("rules_commit") != RULES_COMMIT
        or qt6.get("platform") != "linux-amd64-qt6"
        or qt6.get("capability") != "CAP-NEST-007"
        or qt6.get("result") != "observed"
        or oracle.get("image")
        != "die-rust/debug-dispatch-harness-qt6:74eaf505"
        or oracle.get("image_id")
        != "sha256:10a4ab04d46419ae7e3ea7285588d2c8cd9dc7fd75b82e00d6aa9e8f7156f3c3"
        or oracle.get("revision") != UPSTREAM_COMMIT
        or oracle.get("exit_code") != 0
        or oracle.get("raw_stderr_bytes") != 80
        or oracle.get("raw_stderr_sha256")
        != QT6_UNIMPLEMENTED_SHA256
    ):
        raise ClosurePlanError("Qt6 debug-dispatch identity/oracle drift")
    expected_difference = {
        "scope": "PE rule runtime warning",
        "stderr_bytes": 80,
        "stderr_sha256": QT6_UNIMPLEMENTED_SHA256,
        "lines": 4,
        "semantic_output_equal_to_qt5": True,
    }
    relationships = qt6.get("relationships")
    if (
        qt6.get("known_difference") != expected_difference
        or not isinstance(relationships, dict)
        or len(relationships) != 9
        or not all(value is True for value in relationships.values())
        or relationships != qt5.get("relationships")
    ):
        raise ClosurePlanError(
            "Qt5/Qt6 debug-dispatch relationship drift"
        )
    if (
        qt6.get("harness_output") != qt5.get("harness_output")
        or qt6.get("fixture") != qt5.get("fixture")
        or oracle.get("raw_stdout_sha256")
        != qt5.get("oracle", {}).get("raw_stdout_sha256")
    ):
        raise ClosurePlanError("Qt5/Qt6 debug-dispatch output drift")


def _validate_resource_context_reports(
    qt5: dict[str, Any], qt6: dict[str, Any]
) -> None:
    oracle = qt6.get("oracle", {})
    expected_baseline_hash = (
        "56090cee25f736eeb1c1fbb90a1619199f0fc2a93c7c318c0731ddffb585de64"
    )
    if (
        qt5.get("schema_version") != 1
        or qt5.get("upstream_commit") != UPSTREAM_COMMIT
        or qt6.get("schema_version") != 1
        or qt6.get("upstream_commit") != UPSTREAM_COMMIT
        or qt6.get("rules_commit") != RULES_COMMIT
        or qt6.get("platform") != "linux-amd64-qt6"
        or qt6.get("result") != "observed"
        or oracle.get("image")
        != "die-rust/upstream-oracle-cmake-qt6:74eaf505"
        or oracle.get("image_id")
        != "sha256:e015495c313d0715f0b80f395da983a113a439f2a135eb637e9f0638c225200b"
        or oracle.get("image_revision") != UPSTREAM_COMMIT
        or oracle.get("binary") != "/opt/die-build/src/console/diec"
        or oracle.get("binary_sha256")
        != "e3321105af0349b29195325e79d5d2c7cc25ead2f28f84e242e3835b98f7283e"
        or qt6.get("qt5_baseline")
        != {
            "path": "docs/research/data/resource-context-chain-qt5.json",
            "sha256": expected_baseline_hash,
        }
    ):
        raise ClosurePlanError("Qt6 resource-context identity/oracle drift")

    expected_sample = {
        "intended_structure": "PE32 with an unclassified RT_MANIFEST resource",
        "layers": ["pe", "resource", "binary"],
        "name": "pe-manifest-resource.exe",
        "sha256": (
            "0a973cbde2f520bdbd6e1b75304e4a412462113d4de9a8139cdf997af16641ee"
        ),
        "size": 1024,
    }
    if qt5.get("sample") != expected_sample or qt6.get("sample") != expected_sample:
        raise ClosurePlanError("Qt5/Qt6 resource-context sample drift")

    expected_difference = {
        "scope": "PE rule runtime warning in each CLI invocation",
        "case_count": 4,
        "stderr_bytes_per_case": 80,
        "stderr_sha256_per_case": QT6_UNIMPLEMENTED_SHA256,
        "lines_per_case": 4,
        "semantic_output_equal_to_qt5": True,
    }
    expected_relationships = {
        "all_exit_codes_match_qt5",
        "all_stdout_streams_match_qt5",
        "all_detection_trees_match_qt5",
        "default_omits_resource_child",
        "recursive_alone_omits_unclassified_resource",
        "aggressive_alone_omits_resource_child",
        "recursive_and_aggressive_reaches_resource_child",
        "resource_context_is_propagated",
        "manifest_rule_observes_original_resource_type",
    }
    relationships = qt6.get("relationships")
    if (
        qt6.get("known_difference") != expected_difference
        or not isinstance(relationships, dict)
        or set(relationships) != expected_relationships
        or not all(value is True for value in relationships.values())
    ):
        raise ClosurePlanError("Qt6 resource-context relationship drift")

    qt5_cases = qt5.get("cases")
    qt6_cases = qt6.get("cases")
    expected_cases = {
        "default",
        "recursive",
        "aggressive",
        "recursive_aggressive",
    }
    if (
        not isinstance(qt5_cases, dict)
        or not isinstance(qt6_cases, dict)
        or set(qt5_cases) != expected_cases
        or set(qt6_cases) != expected_cases
    ):
        raise ClosurePlanError("Qt5/Qt6 resource-context case catalog drift")
    expected_stdout_hashes = {
        "default": "94941d54fe62e2c43a0709062c7628eb2fa26d7fda825dc366547a4dc85a8f8b",
        "recursive": "94941d54fe62e2c43a0709062c7628eb2fa26d7fda825dc366547a4dc85a8f8b",
        "aggressive": "94941d54fe62e2c43a0709062c7628eb2fa26d7fda825dc366547a4dc85a8f8b",
        "recursive_aggressive": "c9e8a5c7f3eab49f1f8b533917aba24abebc9f1f05128bf4a359bedbeffab7fa",
    }
    expected_comparison = {
        "exit_code_equal": True,
        "stdout_equal": True,
        "normalized_detect_tree_equal": True,
        "stderr_difference": "known_qt6_pe_warning",
    }
    for case_name in expected_cases:
        qt5_case = qt5_cases[case_name]
        qt6_case = qt6_cases[case_name]
        try:
            qt5_stdout = qt5_case["raw_stdout"].encode("utf-8")
            qt6_stdout = qt6_case["raw_stdout"].encode("utf-8")
            qt5_stderr = bytes.fromhex(qt5_case["raw_stderr_hex"])
            qt6_stderr = bytes.fromhex(qt6_case["raw_stderr_hex"])
        except (KeyError, ValueError, AttributeError) as error:
            raise ClosurePlanError(
                f"invalid resource-context raw stream: {case_name}"
            ) from error
        expected_stdout_hash = expected_stdout_hashes[case_name]
        if (
            qt5_case.get("exit_code") != 0
            or qt6_case.get("exit_code") != 0
            or qt5_stdout != qt6_stdout
            or sha256(qt5_stdout) != expected_stdout_hash
            or sha256(qt6_stdout) != expected_stdout_hash
            or qt5_case.get("raw_stdout_sha256") != expected_stdout_hash
            or qt6_case.get("raw_stdout_sha256") != expected_stdout_hash
            or qt5_stderr != b""
            or qt6_stderr != b"Unimplemented code.\n" * 4
            or qt5_case.get("raw_stderr_sha256") != EMPTY_SHA256
            or qt6_case.get("raw_stderr_sha256")
            != QT6_UNIMPLEMENTED_SHA256
            or qt5_case.get("normalized_detect_tree")
            != qt6_case.get("normalized_detect_tree")
            or qt5_case.get("arguments") != qt6_case.get("arguments")
            or qt6_case.get("comparison_to_qt5") != expected_comparison
        ):
            raise ClosurePlanError(
                f"Qt5/Qt6 resource-context output drift: {case_name}"
            )


def _validate_archive_option_report(report: dict[str, Any]) -> None:
    expected_oracles = {
        "qt5": {
            "harness": {
                "image": "die-rust/upstream-archive-harness:74eaf505",
                "image_id": (
                    "sha256:771b9094a2ad6ab4f6250dd89307ab727c07a1aae885a894695abfa959bab5dc"
                ),
                "revision": UPSTREAM_COMMIT,
                "binary": "/opt/die-build/src/console/die-archive-harness",
                "binary_sha256": (
                    "b7ea9b151b58b630c017e9989333fa035b7d86ffab366a5d3a1f74bab9f1e96e"
                ),
            },
            "release": {
                "image": "die-rust/upstream-oracle-cmake:74eaf505",
                "image_id": (
                    "sha256:466102628c3a94b7ab1048f0c24261b1920e61a40029b128763cf79370255040"
                ),
                "revision": UPSTREAM_COMMIT,
                "binary": "/opt/die-build/src/console/diec",
                "binary_sha256": (
                    "da1fab49f7ba5970d1fc1c7fe3d4f380cf5e8775dd8097207e7b3c30f08236cf"
                ),
            },
        },
        "qt6": {
            "harness": {
                "image": (
                    "die-rust/upstream-archive-harness-qt6:74eaf505"
                ),
                "image_id": (
                    "sha256:2e46aa3e3d2fa731e92bd57c11f905bc3ff4a4064106d020314ad05a422c4488"
                ),
                "revision": UPSTREAM_COMMIT,
                "binary": "/opt/die-build/src/console/die-archive-harness",
                "binary_sha256": (
                    "6fed831d6c11b67e0a9e0ea0aa57b2a9e380a5a6f53dd46f426122aec3839d76"
                ),
            },
            "release": {
                "image": (
                    "die-rust/upstream-oracle-cmake-qt6:74eaf505"
                ),
                "image_id": (
                    "sha256:e015495c313d0715f0b80f395da983a113a439f2a135eb637e9f0638c225200b"
                ),
                "revision": UPSTREAM_COMMIT,
                "binary": "/opt/die-build/src/console/diec",
                "binary_sha256": (
                    "e3321105af0349b29195325e79d5d2c7cc25ead2f28f84e242e3835b98f7283e"
                ),
            },
        },
    }
    if (
        report.get("schema_version") != 1
        or report.get("capability") != "CAP-NEST-003"
        or report.get("platform") != "linux-amd64-qt5-qt6"
        or report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("rules_commit") != RULES_COMMIT
        or report.get("result") != "observed"
        or report.get("oracles") != expected_oracles
        or report.get("case_count") != 64
        or report.get("release_control_count") != 32
    ):
        raise ClosurePlanError("archive-option identity/oracle drift")

    fixture = report.get("fixture", {})
    expected_samples = {
        "pdf-member.zip",
        "nested-zip.zip",
        "many-pdf-members.zip",
        "pe-pdf-overlay.exe",
        "pe-pdf-resource.exe",
        "pe-many-pdf-resources.exe",
        "pe-manifest-resource.exe",
        "pe-zip-overlay.exe",
    }
    if (
        fixture.get("manifest")
        != "docs/research/data/nested-corpus.json"
        or fixture.get("manifest_sha256")
        != "b382bd0a903cd4dda5a8128508f7a3f514a67a721baacda4c6722c99aefc4229"
        or not isinstance(fixture.get("samples"), list)
        or {item.get("name") for item in fixture["samples"]}
        != expected_samples
    ):
        raise ClosurePlanError("archive-option fixture drift")

    expected_difference = {
        "scope": "Qt6 PE rule runtime warning",
        "affected_samples": sorted(
            name for name in expected_samples if name.startswith("pe-")
        ),
        "harness_invocations": 40,
        "release_invocations": 20,
        "stderr_bytes_per_invocation": 80,
        "stderr_sha256_per_invocation": QT6_UNIMPLEMENTED_SHA256,
        "lines_per_invocation": 4,
        "all_stdout_equal": True,
    }
    relationships = report.get("relationships")
    if (
        report.get("known_difference") != expected_difference
        or not isinstance(relationships, dict)
        or len(relationships) != 11
        or not all(value is True for value in relationships.values())
    ):
        raise ClosurePlanError("archive-option relationship drift")

    raw_streams = report.get("raw_streams")
    detection_trees = report.get("detection_trees")
    if not isinstance(raw_streams, dict) or not isinstance(
        detection_trees, dict
    ):
        raise ClosurePlanError("archive-option content catalogs missing")
    for stream_hash, item in raw_streams.items():
        try:
            stream = base64.b64decode(item["base64"], validate=True)
        except (KeyError, ValueError, TypeError) as error:
            raise ClosurePlanError(
                "invalid archive-option raw stream"
            ) from error
        if (
            len(stream) != item.get("bytes")
            or sha256(stream) != stream_hash
        ):
            raise ClosurePlanError("archive-option raw stream drift")
    for tree_hash, tree in detection_trees.items():
        encoded = json.dumps(
            tree,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if sha256(encoded) != tree_hash:
            raise ClosurePlanError("archive-option detection tree drift")

    expected_cases = {
        "default",
        "archive",
        "aggressive",
        "archive_aggressive",
        "recursive",
        "recursive_aggressive",
        "archive_recursive",
        "archive_recursive_aggressive",
    }
    release_cases = {
        "default",
        "aggressive",
        "recursive",
        "recursive_aggressive",
    }
    cases = report.get("cases")
    if not isinstance(cases, dict) or set(cases) != expected_samples:
        raise ClosurePlanError("archive-option sample catalog drift")

    def validate_observation(
        observation: dict[str, Any],
        expected_stderr_hash: str,
        label: str,
    ) -> None:
        stdout_hash = observation.get("stdout_sha256")
        stderr_hash = observation.get("stderr_sha256")
        tree_hash = observation.get("detect_tree_sha256")
        if (
            observation.get("exit_code") != 0
            or stdout_hash not in raw_streams
            or stderr_hash not in raw_streams
            or tree_hash not in detection_trees
            or raw_streams[stdout_hash].get("bytes")
            != observation.get("stdout_bytes")
            or raw_streams[stderr_hash].get("bytes")
            != observation.get("stderr_bytes")
            or stderr_hash != expected_stderr_hash
        ):
            raise ClosurePlanError(
                f"archive-option observation drift: {label}"
            )

    for sample_name, sample_cases in cases.items():
        if not isinstance(sample_cases, dict) or set(
            sample_cases
        ) != expected_cases:
            raise ClosurePlanError(
                f"archive-option case catalog drift: {sample_name}"
            )
        qt6_stderr = (
            QT6_UNIMPLEMENTED_SHA256
            if sample_name.startswith("pe-")
            else EMPTY_SHA256
        )
        for case_name, case in sample_cases.items():
            observations = case.get("observations")
            if not isinstance(observations, dict) or set(observations) != {
                "qt5",
                "qt6",
            }:
                raise ClosurePlanError(
                    f"archive-option oracle catalog drift: {sample_name}.{case_name}"
                )
            validate_observation(
                observations["qt5"],
                EMPTY_SHA256,
                f"{sample_name}.{case_name}.qt5",
            )
            validate_observation(
                observations["qt6"],
                qt6_stderr,
                f"{sample_name}.{case_name}.qt6",
            )
            expected_classification = (
                "known_qt6_pe_warning"
                if sample_name.startswith("pe-")
                else "equal_empty"
            )
            if (
                observations["qt5"].get("stdout_sha256")
                != observations["qt6"].get("stdout_sha256")
                or observations["qt5"].get("detect_tree_sha256")
                != observations["qt6"].get("detect_tree_sha256")
                or case.get("comparison")
                != {
                    "exit_code_equal": True,
                    "stdout_equal": True,
                    "detect_tree_equal": True,
                    "stderr_classification": expected_classification,
                }
            ):
                raise ClosurePlanError(
                    f"Qt5/Qt6 archive-option output drift: {sample_name}.{case_name}"
                )
            release = case.get("release_control")
            if case_name in release_cases:
                if (
                    not isinstance(release, dict)
                    or release.get("harness_equal")
                    != {"qt5": True, "qt6": True}
                    or set(release.get("observations", {}))
                    != {"qt5", "qt6"}
                ):
                    raise ClosurePlanError(
                        f"archive-option release control drift: {sample_name}.{case_name}"
                    )
                for oracle_name, expected_stderr in (
                    ("qt5", EMPTY_SHA256),
                    ("qt6", qt6_stderr),
                ):
                    release_observation = release["observations"][
                        oracle_name
                    ]
                    validate_observation(
                        release_observation,
                        expected_stderr,
                        f"{sample_name}.{case_name}.release.{oracle_name}",
                    )
                    harness_observation = observations[oracle_name]
                    if (
                        release_observation.get("stdout_sha256")
                        != harness_observation.get("stdout_sha256")
                        or release_observation.get("stderr_sha256")
                        != harness_observation.get("stderr_sha256")
                        or release_observation.get("detect_tree_sha256")
                        != harness_observation.get("detect_tree_sha256")
                    ):
                        raise ClosurePlanError(
                            f"archive-option release output drift: {sample_name}.{case_name}"
                        )
            elif release is not None:
                raise ClosurePlanError(
                    f"unexpected archive-option release control: {sample_name}.{case_name}"
                )

    count_expectations = {
        ("many-pdf-members.zip", "archive", "stream_count"): 21,
        (
            "many-pdf-members.zip",
            "archive_aggressive",
            "stream_count",
        ): 22,
        (
            "pe-many-pdf-resources.exe",
            "recursive",
            "resource_count",
        ): 21,
        (
            "pe-many-pdf-resources.exe",
            "recursive_aggressive",
            "resource_count",
        ): 22,
    }
    for (sample_name, case_name, field), expected in count_expectations.items():
        for oracle_name in ("qt5", "qt6"):
            if (
                cases[sample_name][case_name]["observations"][
                    oracle_name
                ].get(field)
                != expected
            ):
                raise ClosurePlanError(
                    f"archive-option count drift: {sample_name}.{case_name}.{field}"
                )


def _validate_archive_iteration_reports(
    qt5: dict[str, Any],
    qt6: dict[str, Any],
    nul_semantics: dict[str, Any],
) -> None:
    common_source = {
        "path": "/opt/die-source/XScanEngine/xscanengine.cpp",
        "sha256": (
            "e088bebb7c8345ce5832cc51de712c05a8b239873d7f092db3ae5566a761b498"
        ),
        "component_commit": "dfe4a419e4f491bb23688ba03c5a5bf39e34da83",
    }
    expected_platforms = {
        "qt5": (
            qt5,
            "linux-x86_64-qt5",
            "sha256:6cfc6dfb568e1287103bbe92f31e75864153b6bf5f196a744178d9c86ae19392",
            "5fba6113410416fc828c8687f9d179d4875862115b53a5a7e993e0760eb87eaa",
        ),
        "qt6": (
            qt6,
            "linux-x86_64-qt6",
            "sha256:a51310e8e03ada9fb907d6ea3d3d3b0a5d0c1917a3aaef971f3a07683486508f",
            "d13b381bc5353f8e261a741c235a825e65461d8ab38cf9f9ba71c16fb94dfbcb",
        ),
    }
    for name, (
        report,
        platform,
        image_id,
        binary_sha256,
    ) in expected_platforms.items():
        source = report.get("source_contract", {})
        environment = report.get("environment", {})
        if (
            report.get("schema_version") != 1
            or report.get("capability") != "CAP-GAP-006"
            or report.get("upstream_commit") != UPSTREAM_COMMIT
            or report.get("xscanengine_commit")
            != common_source["component_commit"]
            or report.get("corpus_manifest_sha256")
            != "e7f5e3c7aaa04add2b987bbfbc12df5683a3418b227b64fe501b1c8038c08e10"
            or report.get("passed") is not True
            or report.get("failures") != []
            or environment.get("platform") != platform
            or environment.get("image_identity", {}).get("id") != image_id
            or environment.get("image_identity", {}).get("revision")
            != UPSTREAM_COMMIT
            or report.get("harness_binary", {}).get("sha256")
            != binary_sha256
            or any(source.get(key) != value for key, value in common_source.items())
            or source.get("source_order_verified") is not True
        ):
            raise ClosurePlanError(
                f"archive-iteration {name} identity/source drift"
            )

    expected_assertions = {
        "qt5": {
            "aggressive_member_limit_is_unreachable_before_hard_guard",
            "record_100000_is_reachable",
            "record_100001_is_not_reachable",
            "record_99999_is_reachable_control",
        },
        "qt6": {
            "aggressive_member_limit_is_unreachable_before_hard_guard",
            "dot_directory_entry_adds_one_stream",
            "record_100000_is_not_reachable",
            "record_100001_is_not_reachable",
            "record_99999_is_reachable_control",
        },
    }
    expected_counts = {
        "qt5": {
            "sentinel-099999.iso": (2, 1, 3, 1),
            "sentinel-100000.iso": (2, 1, 3, 1),
            "sentinel-100001.iso": (1, 0, 1, 0),
        },
        "qt6": {
            "sentinel-099999.iso": (3, 1, 4, 2),
            "sentinel-100000.iso": (2, 0, 2, 1),
            "sentinel-100001.iso": (2, 0, 2, 1),
        },
    }
    for name, report in (("qt5", qt5), ("qt6", qt6)):
        assertions = report.get("assertions")
        cases = report.get("cases")
        if (
            not isinstance(assertions, dict)
            or set(assertions) != expected_assertions[name]
            or not all(value is True for value in assertions.values())
            or not isinstance(cases, list)
            or {case.get("sample") for case in cases}
            != set(expected_counts[name])
        ):
            raise ClosurePlanError(
                f"archive-iteration {name} assertion/case drift"
            )
        for case in cases:
            harness = case.get("harness", {})
            observed = (
                harness.get("node_count"),
                harness.get("pdf_node_count"),
                harness.get("record_count"),
                harness.get("stream_node_count"),
            )
            if (
                observed != expected_counts[name][case["sample"]]
                or case.get("exit_code") != 0
                or case.get("stderr") != ""
                or case.get("stderr_sha256") != EMPTY_SHA256
                or case.get("timed_out") is not False
                or case.get("possible_oom_exit_137") is not False
                or harness.get("error_count") != 0
                or harness.get("pd_stopped") is not False
            ):
                raise ClosurePlanError(
                    f"archive-iteration {name} output drift: "
                    f"{case.get('sample')}"
                )

    if qt6.get("known_difference") != {
        "qt5_last_reachable_pdf_ordinal": 100000,
        "qt6_extra_stream_count_per_case": 1,
        "qt6_last_reachable_pdf_ordinal": 99999,
        "requires_qt_string_semantics_probe": True,
        "scope": "ISO9660 NUL dot-entry filtering",
        "source_revision_equal": True,
    }:
        raise ClosurePlanError("archive-iteration known difference drift")
    if qt6.get("iso_source_contract") != {
        "dot_filter_line": 546,
        "dot_filter_pattern": (
            'if (nFileNameLength == 1 && (sFileName == "\\x00" || '
            'sFileName == "\\x01")) {'
        ),
        "dot_filter_pattern_count": 1,
        "path": "/opt/die-source/XArchive/xiso9660.cpp",
        "sha256": (
            "d6e97c4ff2395b812b65da5ab480e937c6b365e6e6e8b0288ddf48b8fd398fb1"
        ),
    }:
        raise ClosurePlanError("archive-iteration ISO source drift")

    observations = nul_semantics.get("observations", {})
    expected_results = {
        "qt5": {
            "equals_c_string": True,
            "equals_explicit_null": False,
            "first_code_unit": -1,
            "qt_version": "5.15.13",
            "string_size": 0,
        },
        "qt6": {
            "equals_c_string": False,
            "equals_explicit_null": True,
            "first_code_unit": 0,
            "qt_version": "6.4.2",
            "string_size": 1,
        },
    }
    if (
        nul_semantics.get("schema_version") != 1
        or nul_semantics.get("upstream_commit") != UPSTREAM_COMMIT
        or nul_semantics.get("platform") != "linux-x86_64-qt5-qt6"
        or nul_semantics.get("result") != "observed"
        or set(observations) != {"qt5", "qt6"}
        or not isinstance(nul_semantics.get("relationships"), dict)
        or len(nul_semantics["relationships"]) != 5
        or not all(nul_semantics["relationships"].values())
    ):
        raise ClosurePlanError("Qt NUL semantics identity drift")
    for name, expected in expected_results.items():
        observation = observations[name]
        if (
            observation.get("result") != expected
            or observation.get("exit_code") != 0
            or observation.get("stderr") != ""
            or observation.get("stderr_sha256") != EMPTY_SHA256
            or observation.get("revision") != UPSTREAM_COMMIT
        ):
            raise ClosurePlanError(f"Qt NUL semantics output drift: {name}")


def _decode_zlib_artifacts(
    report: dict[str, Any],
    label: str,
) -> dict[str, bytes]:
    artifacts = report.get("raw_artifacts")
    if not isinstance(artifacts, dict):
        raise ClosurePlanError(f"{label} raw artifact catalog missing")
    decoded = {}
    for digest, artifact in artifacts.items():
        try:
            compressed = base64.b64decode(
                artifact["base64"],
                validate=True,
            )
            data = zlib.decompress(compressed)
        except (KeyError, TypeError, ValueError, zlib.error) as error:
            raise ClosurePlanError(
                f"{label} raw artifact is invalid"
            ) from error
        if (
            artifact.get("encoding") != "zlib+base64"
            or len(compressed) != artifact.get("compressed_bytes")
            or len(data) != artifact.get("bytes")
            or sha256(data) != digest
        ):
            raise ClosurePlanError(f"{label} raw artifact drift")
        decoded[digest] = data
    return decoded


def _validate_scan_option_boundary_reports(
    qt5: dict[str, Any],
    qt6: dict[str, Any],
) -> None:
    fixture_sha256 = (
        "e444b6aa0bacaa29077eae1e9710546d8fc5a38f50059c486ce8a1807afd71b2"
    )
    if (
        qt5.get("schema_version") != 1
        or qt5.get("upstream_commit") != UPSTREAM_COMMIT
        or qt5.get("platform") != "linux-x86_64-qt5"
        or qt5.get("passed") is not True
        or qt5.get("failures") != []
        or qt5.get("fixture_manifest", {}).get("sha256")
        != fixture_sha256
        or qt6.get("schema_version") != 1
        or qt6.get("upstream_commit") != UPSTREAM_COMMIT
        or qt6.get("platform") != "linux-x86_64-qt6"
        or qt6.get("passed") is not True
        or qt6.get("failures") != []
        or qt6.get("closed_capability") != "CAP-NEST-004"
        or qt6.get("fixture_manifest", {}).get("sha256")
        != fixture_sha256
        or qt6.get("qt5_reference", {}).get("sha256")
        != "f193a9f308b04a89dd7ceeda52a658eda2ef13eb82b9c0662c66215248bbf49d"
    ):
        raise ClosurePlanError("scan-option boundary identity drift")

    qt5_artifacts = _decode_zlib_artifacts(qt5, "Qt5 scan-option")
    qt6_artifacts = _decode_zlib_artifacts(qt6, "Qt6 scan-option")
    expected_names = {
        "deep_default": (["Binary normal"], 0),
        "deep_enabled": (
            ["Binary normal", "Binary deep", "Binary entrypoint"],
            0,
        ),
        "aggressive_without_recursive": (["PE root"], 0),
        "recursive_unclassified": (["PE root"], 0),
        "recursive_aggressive_unclassified": (
            ["PE root", "Binary normal"],
            1,
        ),
        "recursive_pdf_22": (["PE root", *(["PDF child"] * 21)], 21),
        "recursive_aggressive_pdf_22": (
            ["PE root", *(["PDF child"] * 22)],
            22,
        ),
        "recursive_aggressive_unclassified_2002": (
            ["PE root", *(["Binary normal"] * 2001)],
            2001,
        ),
    }
    qt5_observations = qt5.get("observations", {})
    if set(qt5_observations) != {
        "linux-qt5-qmake",
        "linux-qt5-cmake",
    }:
        raise ClosurePlanError("Qt5 scan-option oracle catalog drift")
    qt5_cases_by_oracle = []
    for oracle_name, oracle in qt5_observations.items():
        cases = oracle.get("cases", {})
        if set(cases) != set(expected_names):
            raise ClosurePlanError(
                f"Qt5 scan-option case catalog drift: {oracle_name}"
            )
        qt5_cases_by_oracle.append(cases)
        for case_name, case in cases.items():
            names, count = expected_names[case_name]
            if (
                case.get("exit_code") != 0
                or case.get("summary", {}).get("detection_names") != names
                or case.get("summary", {}).get("resource_count") != count
            ):
                raise ClosurePlanError(
                    f"Qt5 scan-option output drift: {case_name}"
                )
            for stream_name in ("stdout", "stderr"):
                stream = case.get(stream_name, {})
                digest = stream.get("artifact_sha256")
                if (
                    digest not in qt5_artifacts
                    or stream.get("sha256") != digest
                    or len(qt5_artifacts[digest]) != stream.get("bytes")
                ):
                    raise ClosurePlanError(
                        f"Qt5 scan-option raw reference drift: {case_name}"
                    )
    for case_name in expected_names:
        if (
            qt5_cases_by_oracle[0][case_name]["summary"]
            != qt5_cases_by_oracle[1][case_name]["summary"]
        ):
            raise ClosurePlanError(
                f"Qt5 scan-option oracle difference: {case_name}"
            )

    observation = qt6.get("observation", {})
    qt6_cases = observation.get("cases", {})
    if (
        observation.get("image_id")
        != "sha256:e015495c313d0715f0b80f395da983a113a439f2a135eb637e9f0638c225200b"
        or observation.get("binary_sha256")
        != "e3321105af0349b29195325e79d5d2c7cc25ead2f28f84e242e3835b98f7283e"
        or observation.get("resource_source_sha256")
        != "e088bebb7c8345ce5832cc51de712c05a8b239873d7f092db3ae5566a761b498"
        or observation.get("repetitions") != 2
        or set(qt6_cases) != set(expected_names)
    ):
        raise ClosurePlanError("Qt6 scan-option oracle/case drift")
    for case_name, case in qt6_cases.items():
        names, count = expected_names[case_name]
        executions = case.get("executions")
        if (
            case.get("summary", {}).get("detection_names") != names
            or case.get("summary", {}).get("resource_count") != count
            or case.get("summary")
            != qt5_cases_by_oracle[1][case_name]["summary"]
            or not isinstance(executions, list)
            or len(executions) != 2
            or executions[0] != executions[1]
        ):
            raise ClosurePlanError(
                f"Qt6 scan-option output drift: {case_name}"
            )
        for execution in executions:
            if execution.get("exit_code") != 0:
                raise ClosurePlanError(
                    f"Qt6 scan-option exit drift: {case_name}"
                )
            for stream_name in ("stdout", "stderr"):
                stream = execution.get(stream_name, {})
                digest = stream.get("artifact_sha256")
                if (
                    digest not in qt6_artifacts
                    or stream.get("sha256") != digest
                    or len(qt6_artifacts[digest]) != stream.get("bytes")
                ):
                    raise ClosurePlanError(
                        f"Qt6 scan-option raw reference drift: {case_name}"
                    )
            if execution["stderr"]["sha256"] != EMPTY_SHA256:
                raise ClosurePlanError(
                    f"Qt6 scan-option stderr drift: {case_name}"
                )
    diagnostic = qt6.get("known_qt6_diagnostic", {})
    if (
        diagnostic.get("affected_cases") != []
        or diagnostic.get("raw_streams_retained") is not True
        or diagnostic.get("stderr_bytes_per_affected_execution") != 80
        or diagnostic.get("stderr_sha256_per_affected_execution")
        != QT6_UNIMPLEMENTED_SHA256
        or not isinstance(qt6.get("facts"), dict)
        or len(qt6["facts"]) != 7
        or not all(qt6["facts"].values())
    ):
        raise ClosurePlanError("Qt6 scan-option diagnostic/fact drift")


def _validate_legacy_dispatch_report(report: dict[str, Any]) -> None:
    if (
        report.get("schema_version") != 1
        or report.get("result") != "pass"
        or report.get("failures") != []
        or report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("rules_commit") != RULES_COMMIT
        or report.get("formats_commit")
        != "1151e7254fdee3c0294ff7095edbdd7bfccf8201"
        or report.get("platform") != "linux-amd64-qt5-qt6"
        or report.get("capability") != "CAP-DISPATCH-003"
        or report.get("closed_capability") != "CAP-DISPATCH-003"
        or report.get("corpus_manifest", {}).get("sha256")
        != "7c0d55a9b7b93d3443cefb7c198223e33c11a48f9855e21fd2d6a104105388c0"
        or report.get("corpus_manifest", {}).get("sample_count") != 8
        or report.get("qt5_reference", {}).get("sha256")
        != "9dd1d4de3535fc035d4624205a24405d05d1b9a9589ca89b4a1e0a4cfdace5fc"
        or report.get("repetitions") != 2
        or report.get("known_differences") != []
    ):
        raise ClosurePlanError("legacy-dispatch identity/reference drift")
    oracle = report.get("qt6_oracle", {})
    if (
        oracle.get("image_id")
        != "sha256:e015495c313d0715f0b80f395da983a113a439f2a135eb637e9f0638c225200b"
        or oracle.get("revision") != UPSTREAM_COMMIT
        or oracle.get("binary_sha256")
        != "e3321105af0349b29195325e79d5d2c7cc25ead2f28f84e242e3835b98f7283e"
        or oracle.get("source_sha256")
        != {
            "/opt/die-source/Formats/exec/xamigahunk.cpp": (
                "7cee077d4e9d6ab66fde355e06f62908d835a8d1818c9d0a47b59b9269d3e8a1"
            ),
            "/opt/die-source/Formats/exec/xatarist.cpp": (
                "7aeda5dda76eb0027bb735dbedd8925cb901f1049a0fcedeb2e2f01a443f1fd2"
            ),
            "/opt/die-source/Formats/xformats.cpp": (
                "674eba0046eb6cc947e547d1ac0b93ac695cbb30f68e11f135e5551d81e0b115"
            ),
            "/opt/die-source/XScanEngine/xscanengine.cpp": (
                "e088bebb7c8345ce5832cc51de712c05a8b239873d7f092db3ae5566a761b498"
            ),
        }
    ):
        raise ClosurePlanError("legacy-dispatch Qt6 oracle drift")
    if report.get("resource_limits") != {
        "network": "none",
        "cpus": 1,
        "memory_bytes": 536870912,
        "pids": 128,
        "timeout_seconds_per_execution": 60,
        "fixture_mount": "read-only",
        "container_root": "read-only",
    }:
        raise ClosurePlanError("legacy-dispatch resource limit drift")

    artifacts = _decode_zlib_artifacts(report, "legacy-dispatch")
    expected = {
        "minimal-amiga-hunk.bin": ("Amiga Hunk", "Amiga Hunk"),
        "minimal-atari-st.prg": ("Atari ST", "Binary"),
        "amiga-hunk-truncated.bin": ("Binary", "Binary"),
        "amiga-hunk-wrong-endian.bin": ("Binary", "Binary"),
        "amiga-hunk-near-magic.bin": ("Binary", "Binary"),
        "atari-st-truncated.prg": ("Binary", "Binary"),
        "atari-st-wrong-endian.prg": ("Binary", "Binary"),
        "atari-st-near-magic.prg": ("Binary", "Binary"),
    }
    cases = report.get("cases")
    if not isinstance(cases, dict) or set(cases) != set(expected):
        raise ClosurePlanError("legacy-dispatch case catalog drift")
    for case_name, (info_filetype, scan_filetype) in expected.items():
        case = cases[case_name]
        executions = case.get("qt6_executions")
        if (
            not isinstance(executions, list)
            or len(executions) != 2
            or executions[0] != executions[1]
            or case.get("comparison")
            != {
                "raw_stream_differences": [],
                "semantic_dispatch_equal": True,
            }
        ):
            raise ClosurePlanError(
                f"legacy-dispatch repetition/comparison drift: {case_name}"
            )
        execution = executions[0]
        qt5 = case.get("qt5_cmake", {})
        scan_tree = execution.get("scan", {}).get("detect_tree")
        if (
            not isinstance(scan_tree, list)
            or not scan_tree
            or not isinstance(scan_tree[0], dict)
            or scan_tree[0].get("filetype") != scan_filetype
            or execution.get("detector_info", {}).get("filetype")
            != info_filetype
            or qt5.get("scan", {}).get("detect_tree")
            != scan_tree
            or qt5.get("detector_info", {}).get("filetype")
            != info_filetype
        ):
            raise ClosurePlanError(
                f"legacy-dispatch semantic output drift: {case_name}"
            )
        for repeated in executions:
            for mode in ("scan", "detector_info"):
                qt5_mode = qt5[mode]
                qt6_mode = repeated[mode]
                if (
                    qt6_mode.get("exit_code") != 0
                    or qt5_mode.get("exit_code") != 0
                ):
                    raise ClosurePlanError(
                        f"legacy-dispatch exit drift: {case_name}.{mode}"
                    )
                for stream_name in ("stdout", "stderr"):
                    reference = qt6_mode.get(stream_name, {})
                    digest = reference.get("artifact_sha256")
                    if (
                        digest not in artifacts
                        or reference.get("sha256") != digest
                        or len(artifacts[digest])
                        != reference.get("bytes")
                        or qt5_mode.get(f"{stream_name}_sha256")
                        != digest
                        or qt5_mode.get(f"{stream_name}_bytes")
                        != len(artifacts[digest])
                    ):
                        raise ClosurePlanError(
                            "legacy-dispatch raw output drift: "
                            f"{case_name}.{mode}.{stream_name}"
                        )
    relationships = report.get("relationships")
    if (
        not isinstance(relationships, dict)
        or len(relationships) != 8
        or not all(relationships.values())
    ):
        raise ClosurePlanError("legacy-dispatch relationship drift")


def _observed_filetypes(value: Any) -> set[str]:
    result = set()
    if isinstance(value, dict):
        filetype = value.get("filetype")
        if isinstance(filetype, str):
            result.add(filetype)
        for child in value.values():
            result.update(_observed_filetypes(child))
    elif isinstance(value, list):
        for child in value:
            result.update(_observed_filetypes(child))
    return result


def _validate_dos_dispatch_report(report: dict[str, Any]) -> None:
    if (
        report.get("schema_version") != 1
        or report.get("result") != "pass"
        or report.get("failures") != []
        or report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("rules_commit") != RULES_COMMIT
        or report.get("formats_commit")
        != "1151e7254fdee3c0294ff7095edbdd7bfccf8201"
        or report.get("xarchive_commit")
        != "0fcd4e8d3e9933baac3b12246d82ac026557ffd0"
        or report.get("platform") != "linux-amd64-qt5-qt6"
        or report.get("capability") != "CAP-DISPATCH-002"
        or report.get("repetitions") != 2
        or report.get("corpus_manifest", {}).get("sha256")
        != "c6caeed47cbd3e0631a6aa04fd1b01fb2eb57a946f7f7c0cc217110e02cb067b"
        or report.get("corpus_manifest", {}).get("sample_count") != 19
        or report.get("source_audit", {}).get("sha256")
        != "07661cdefb773fb397870fdacbfefa010ae67fa1284253ddc000808ea7192c4c"
        or report.get("qt5_reference", {}).get("sha256")
        != "21abf20ac50e694fb135d31bc786d0d61c9d701530334900329f9360b9b5ee77"
    ):
        raise ClosurePlanError("DOS-dispatch identity/reference drift")
    oracle = report.get("qt6_oracle", {})
    if (
        oracle.get("image_id")
        != "sha256:e015495c313d0715f0b80f395da983a113a439f2a135eb637e9f0638c225200b"
        or oracle.get("revision") != UPSTREAM_COMMIT
        or oracle.get("binary_sha256")
        != "e3321105af0349b29195325e79d5d2c7cc25ead2f28f84e242e3835b98f7283e"
        or oracle.get("source_sha256")
        != {
            "/opt/die-source/Formats/xbinary.cpp": (
                "d82bd21326bb7ba07eb343020d50af0ae2cf7e8e534d8e08d07ffa8129913c34"
            ),
            "/opt/die-source/Formats/xformats.cpp": (
                "674eba0046eb6cc947e547d1ac0b93ac695cbb30f68e11f135e5551d81e0b115"
            ),
            "/opt/die-source/XScanEngine/xscanengine.cpp": (
                "e088bebb7c8345ce5832cc51de712c05a8b239873d7f092db3ae5566a761b498"
            ),
        }
    ):
        raise ClosurePlanError("DOS-dispatch Qt6 oracle drift")
    artifacts = _decode_zlib_artifacts(report, "DOS-dispatch")
    expected_cases = {
        "minimal-msdos.exe",
        "msdos-near-magic.exe",
        "minimal-ne.exe",
        "ne-truncated.exe",
        "ne-near-magic.exe",
        "minimal-le.exe",
        "le-near-magic.exe",
        "minimal-lx.exe",
        "lx-near-magic.exe",
        "minimal-dos16m.exe",
        "dos16m-truncated.exe",
        "dos16m-near-bw.exe",
        "minimal-dos4g.exe",
        "dos4g-truncated.exe",
        "dos4g-near-nested-magic.exe",
        "minimal.com",
        "com-wrong-suffix.bin",
        "com-max-size.com",
        "com-oversized.com",
    }
    diagnostic_cases = {
        "minimal-msdos.exe",
        "ne-truncated.exe",
        "ne-near-magic.exe",
        "le-near-magic.exe",
        "lx-near-magic.exe",
        "dos16m-truncated.exe",
        "dos16m-near-bw.exe",
        "dos4g-truncated.exe",
    }
    cases = report.get("cases")
    differences = report.get("known_differences")
    if (
        not isinstance(cases, dict)
        or set(cases) != expected_cases
        or not isinstance(differences, list)
        or {item.get("case") for item in differences} != expected_cases
    ):
        raise ClosurePlanError("DOS-dispatch case/difference catalog drift")
    difference_map = {item["case"]: item for item in differences}
    for case_name, case in cases.items():
        executions = case.get("qt6_executions")
        qt5 = case.get("qt5_cmake", {})
        comparison = case.get("comparison", {})
        if (
            not isinstance(executions, list)
            or len(executions) != 2
            or qt5.get("detect_tree")
            != executions[0].get("detect_tree")
            or executions[0].get("detect_tree")
            != executions[1].get("detect_tree")
            or comparison.get("semantic_dispatch_equal") is not True
        ):
            raise ClosurePlanError(
                f"DOS-dispatch semantic/repetition drift: {case_name}"
            )
        observed = _observed_filetypes(executions[0]["detect_tree"])
        expectation = case.get("expected_dispatch", {})
        if (
            not set(expectation.get("present_filetypes", [])) <= observed
            or set(expectation.get("absent_filetypes", [])) & observed
        ):
            raise ClosurePlanError(
                f"DOS-dispatch expectation drift: {case_name}"
            )
        expected_streams = ["stdout_json_fields"]
        if case_name in diagnostic_cases:
            expected_streams.append("stdout_diagnostics")
        item = difference_map[case_name]
        if (
            comparison.get("raw_stream_differences")
            != expected_streams
            or item.get("streams") != expected_streams
            or item.get("semantic_dispatch_equal") is not True
            or len(item.get("qt6_formatter_extras", [])) != 3
        ):
            raise ClosurePlanError(
                f"DOS-dispatch difference classification drift: {case_name}"
            )
        expected_diagnostic_sha256 = (
            "c6656b6859b2ae4f2f9db8bdddfa7129587757ec933bc89de232c84daade95c1"
            if case_name in diagnostic_cases
            else EMPTY_SHA256
        )
        if item.get(
            "normalized_stdout_diagnostics_sha256"
        ) != expected_diagnostic_sha256:
            raise ClosurePlanError(
                f"DOS-dispatch diagnostic drift: {case_name}"
            )
        for execution in executions:
            if (
                execution.get("exit_code") != 0
                or execution.get("stderr", {}).get("sha256")
                != EMPTY_SHA256
                or execution.get("normalized_diagnostics_sha256")
                != expected_diagnostic_sha256
                or execution.get("formatter_extras")
                != item["qt6_formatter_extras"]
            ):
                raise ClosurePlanError(
                    f"DOS-dispatch execution drift: {case_name}"
                )
            for stream_name in ("stdout", "stderr", "diagnostics"):
                reference = execution.get(stream_name, {})
                digest = reference.get("artifact_sha256")
                if (
                    digest not in artifacts
                    or reference.get("sha256") != digest
                    or len(artifacts[digest])
                    != reference.get("bytes")
                ):
                    raise ClosurePlanError(
                        f"DOS-dispatch raw reference drift: "
                        f"{case_name}.{stream_name}"
                    )
    relationships = report.get("relationships")
    if (
        not isinstance(relationships, dict)
        or len(relationships) != 7
        or not all(relationships.values())
    ):
        raise ClosurePlanError("DOS-dispatch relationship drift")


def _validate_bw_dispatch_report(report: dict[str, Any]) -> None:
    if (
        report.get("schema_version") != 1
        or report.get("failures") != []
        or report.get("upstream_commit") != UPSTREAM_COMMIT
        or report.get("formats_commit")
        != "1151e7254fdee3c0294ff7095edbdd7bfccf8201"
        or report.get("xscanengine_commit")
        != "dfe4a419e4f491bb23688ba03c5a5bf39e34da83"
        or report.get("platform") != "linux-amd64-qt5-qt6"
        or report.get("capability") != "CAP-DISPATCH-002"
        or report.get("repetitions") != 2
        or report.get("qt5_reference", {}).get("sha256")
        != "ab24ede4c85ab856e77639ad27f31ee47154c0d3e1885d88f9e0f6f8f4bfede8"
        or report.get("harness", {}).get("source_sha256")
        != "66376bdd27ea72177e7027980fac8bae75ef95010668ad0e2696f642d072c233"
        or report.get("harness", {}).get("qt6_dockerfile_sha256")
        != "a28aa0d60efbc0419b02253081c8b77eb5b908bcbf8cb40212afbb050163f5cd"
    ):
        raise ClosurePlanError("BW-dispatch identity/reference drift")
    oracle = report.get("qt6_oracle", {})
    if (
        oracle.get("image_id")
        != "sha256:f71568facffa71c29420f9f0701e58bce15db54ee1cb12603938bc19804f893e"
        or oracle.get("revision") != UPSTREAM_COMMIT
        or oracle.get("binary_sha256")
        != "556c8ff8ed0b2f3a534305aa15184fd7ad33408068cdd6be1f3992de92c23f32"
        or report.get("comparison")
        != {
            "raw_stream_differences": [],
            "semantic_output_equal": True,
        }
    ):
        raise ClosurePlanError("BW-dispatch oracle/comparison drift")
    artifacts = _decode_zlib_artifacts(report, "BW-dispatch")
    executions = report.get("executions")
    if (
        not isinstance(executions, list)
        or len(executions) != 2
        or executions[0] != executions[1]
    ):
        raise ClosurePlanError("BW-dispatch repetition drift")
    for execution in executions:
        if execution.get("exit_code") != 0:
            raise ClosurePlanError("BW-dispatch exit drift")
        for stream_name in ("stdout", "stderr"):
            reference = execution.get(stream_name, {})
            digest = reference.get("artifact_sha256")
            if (
                digest not in artifacts
                or reference.get("sha256") != digest
                or len(artifacts[digest]) != reference.get("bytes")
            ):
                raise ClosurePlanError(
                    f"BW-dispatch raw reference drift: {stream_name}"
                )
    output = report.get("harness_output", {})
    cases = output.get("cases")
    if (
        output.get("schema_version") != 1
        or output.get("case_count") != 2
        or not isinstance(cases, list)
        or {case.get("id") for case in cases}
        != {"automatic_detection", "forced_property"}
    ):
        raise ClosurePlanError("BW-dispatch harness output drift")
    mapped = {case["id"]: case for case in cases}
    automatic = mapped["automatic_detection"]
    forced = mapped["forced_property"]
    if (
        "BWDOS16M" in automatic.get("detected_filetypes", "").split("|")
        or automatic.get("initial_filetype") != "Binary"
        or forced.get("property") != "BWDOS16M"
        or forced.get("detected_filetypes") != "BWDOS16M"
        or forced.get("initial_filetype") != "BW DOS16M"
        or len(forced.get("records", [])) != 1
        or forced["records"][0].get("filetype") != "BW DOS16M"
        or forced["records"][0].get("unknown") is not True
        or not isinstance(report.get("relationships"), dict)
        or len(report["relationships"]) != 6
        or not all(report["relationships"].values())
    ):
        raise ClosurePlanError("BW-dispatch semantic relationship drift")


CAMPAIGNS: dict[str, dict[str, Any]] = {
    "cli_scan_baseline": {
        "fixture": "reuse baseline-corpus and scan-option-boundary fixtures",
        "harness": "run the pinned Qt5 and Qt6 CLI images with every scan-option vector",
        "assertions": [
            "exit code and normalized detection tree are equal",
            "raw stdout and stderr hashes are retained",
            "each documented option boundary has a named paired control",
        ],
    },
    "cli_path": {
        "fixture": "reuse path, special-path, filesystem, large-directory, TOCTOU, and locale fixtures",
        "harness": "port the fixed Linux Qt5 path probes to the pinned Qt6 CLI image",
        "assertions": [
            "target order, duplicate handling, and directory traversal are equal",
            "exit code and raw per-target framing are retained",
            "links, permissions, TOCTOU, locale, and large-directory controls are all executed",
        ],
    },
    "engine_contract": {
        "fixture": "reuse the 37-case engine-contract fixture and controls",
        "harness": "build and run an equivalent XScanEngine Qt6 harness",
        "assertions": [
            "memory, file, device, and subdevice result projections are equal",
            "read, seek, EOF, sequential, and invalid-range cases are equal",
            "sort, signature filter, cancellation, and fresh-state cases are equal",
        ],
    },
    "cli_options": {
        "fixture": "reuse CLI option and binary rule-order fixtures",
        "harness": "execute every short/long option and paired control on Qt5 and Qt6",
        "assertions": [
            "exit code and normalized detection output are equal",
            "message and profiling channels retain raw output before normalization",
            "no-op and malformed test-mode behaviors are exercised",
        ],
    },
    "cli_special": {
        "fixture": "reuse special-mode and boundary fixtures",
        "harness": "run entropy, info, struct, and showstructs matrices on Qt5 and Qt6",
        "assertions": [
            "all formatter and multi-target framing cases are equal",
            "floating-point and invalid/deep struct boundaries are equal",
            "format-specific PE/ELF/Mach-O/DEX struct methods are exercised",
        ],
    },
    "cli_control": {
        "fixture": "reuse control-mode arguments and no-target controls",
        "harness": "run help, version, missing-target, and no-argument cases",
        "assertions": [
            "exit codes are equal",
            "stdout and stderr hashes are equal",
            "target-independent control modes are tested with and without a target",
        ],
    },
    "cli_output": {
        "fixture": "reuse output-boundary fixture and five representative formats",
        "harness": "run XML, JSON, CSV, TSV, and plain output matrices",
        "assertions": [
            "raw bytes and parsed semantic projections are retained",
            "formatter precedence and multi-target framing are equal",
            "messages contamination and special-mode output are exercised",
        ],
    },
    "database": {
        "fixture": "reuse database layer, error, archive, and cache fixtures",
        "harness": "build Qt6 database-layer and cache harnesses plus CLI controls",
        "assertions": [
            "main, extra, and custom layer ordering is equal",
            "missing, malformed, archive, and cache behavior is equal",
            "showdatabase counts, paths, exit code, and raw streams are equal",
        ],
    },
    "rule_orchestration": {
        "fixture": "reuse rule-orchestration and scan-option fixtures",
        "harness": "run the full rule gate/order/init/error matrix under both script engines",
        "assertions": [
            "layer, priority, init, type, deep, heuristic, and fallback behavior is equal",
            "detections and diagnostics are compared separately",
            "each known Qt5/Qt6 diagnostic difference is explicit and reviewable",
        ],
    },
    "signature_path_filter": {
        "fixture": "reuse signature-path fixture",
        "harness": "build and run an equivalent private-path Qt6 harness",
        "assertions": [
            "absolute exact match and mismatch controls are equal",
            "case, dot-dot, basename, and empty public-entry behavior is equal",
            "raw records and errors are retained",
        ],
    },
    "debug_data_dispatch": {
        "fixture": "reuse debug-dispatch fixture and source-audit identity",
        "harness": "build and run an equivalent Qt6 debug-dispatch harness",
        "assertions": [
            "resource and debug enumerations are equal",
            "only resource candidates are scanner-dispatched",
            "positive resource and negative debug controls retain raw records",
        ],
    },
    "dispatch_source": {
        "fixture": "reuse every dispatch fixture named by the Qt5 evidence set",
        "harness": "build Qt6 variants of all public and private dispatch probes",
        "assertions": [
            "every format family and property-only or detector-only branch is exercised",
            "normalized detection records and raw diagnostics are compared",
            "archive adapters include positive, malformed, compressed, and boundary controls",
        ],
    },
    "nested_scan": {
        "fixture": "reuse nested, resource, archive-limit, iteration, adversarial, and structure fixtures",
        "harness": "build Qt6 nested/resource/archive harness variants",
        "assertions": [
            "CLI recursion and internal recursion gates are distinguished",
            "record-count, iteration, depth, and expanded-byte observations are equal",
            "parent tree, context propagation, subdevice gates, and raw errors are compared",
        ],
    },
    "result_model": {
        "fixture": "reuse engine result metadata/list/flag/id/enum fixtures",
        "harness": "build and run equivalent Qt6 result-model harnesses",
        "assertions": [
            "all scalar fields, lists, flags, IDs, enums, and rule metadata are projected",
            "stable fields are compared exactly and random IDs by declared invariants",
            "script-engine diagnostic differences remain separate from detection semantics",
        ],
    },
}


def _validate_inputs(
    traceability: dict[str, Any], reports: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    if traceability.get("schema_version") != 1:
        raise ClosurePlanError("unsupported traceability schema")
    if traceability.get("upstream_commit") != UPSTREAM_COMMIT:
        raise ClosurePlanError("traceability upstream commit drift")
    if traceability.get("rules_commit") != RULES_COMMIT:
        raise ClosurePlanError("traceability rules commit drift")
    capabilities = traceability.get("capabilities")
    if not isinstance(capabilities, list) or len(capabilities) != 68:
        raise ClosurePlanError("traceability must contain exactly 68 capabilities")
    ids = [item.get("id") for item in capabilities]
    if len(set(ids)) != len(ids):
        raise ClosurePlanError("duplicate capability id")
    evidence_sets = {item.get("evidence_set") for item in capabilities}
    if evidence_sets != set(CAMPAIGNS):
        raise ClosurePlanError(
            "Qt6 campaign catalog does not exactly match evidence sets"
        )
    known = set(COMPLETE) | set(PARTIAL)
    if not known <= set(ids):
        raise ClosurePlanError("Qt6 evidence catalog contains stale capability ids")

    cli = reports[REPORT_PATHS[0]]
    if (
        cli.get("expected_revision") != UPSTREAM_COMMIT
        or cli.get("left_revision") != UPSTREAM_COMMIT
        or cli.get("right_revision") != UPSTREAM_COMMIT
    ):
        raise ClosurePlanError("CLI comparison revision drift")
    for path in REPORT_PATHS[1:4]:
        report = reports[path]
        if report.get("upstream_commit") != UPSTREAM_COMMIT:
            raise ClosurePlanError(f"report upstream commit drift: {path}")
        if report.get("rules_commit") != RULES_COMMIT:
            raise ClosurePlanError(f"report rules commit drift: {path}")
    _validate_output_boundary_report(reports[REPORT_PATHS[4]])
    _validate_output_matrix_report(reports[REPORT_PATHS[5]])
    _validate_scan_nested_report(reports[REPORT_PATHS[6]])
    _validate_alltypes_diagnostics(reports[REPORT_PATHS[7]])
    _validate_special_matrix_report(reports[REPORT_PATHS[8]])
    _validate_special_boundary_report(reports[REPORT_PATHS[9]])
    _validate_path_matrix_report(reports[REPORT_PATHS[10]])
    _validate_database_matrix_report(reports[REPORT_PATHS[11]])
    _validate_database_diagnostics(reports[REPORT_PATHS[12]])
    _validate_option_behavior_report(reports[REPORT_PATHS[13]])
    _validate_binary_rule_order_report(reports[REPORT_PATHS[14]])
    _validate_engine_contract_reports(
        reports[REPORT_PATHS[15]], reports[REPORT_PATHS[16]]
    )
    _validate_rule_orchestration_reports(
        reports[REPORT_PATHS[17]], reports[REPORT_PATHS[18]]
    )
    _validate_result_model_reports(
        {
            "metadata": reports[REPORT_PATHS[19]],
            "lists": reports[REPORT_PATHS[20]],
            "ids": reports[REPORT_PATHS[21]],
            "flags": reports[REPORT_PATHS[22]],
            "enums": reports[REPORT_PATHS[23]],
        },
        reports[REPORT_PATHS[24]],
        reports[REPORT_PATHS[25]],
        reports[REPORT_PATHS[16]],
        reports[REPORT_PATHS[26]],
    )
    _validate_signature_path_reports(
        reports[REPORT_PATHS[27]], reports[REPORT_PATHS[28]]
    )
    _validate_debug_dispatch_reports(
        reports[REPORT_PATHS[29]], reports[REPORT_PATHS[30]]
    )
    _validate_resource_context_reports(
        reports[REPORT_PATHS[31]], reports[REPORT_PATHS[32]]
    )
    _validate_archive_option_report(reports[REPORT_PATHS[33]])
    _validate_archive_iteration_reports(
        reports[REPORT_PATHS[34]],
        reports[REPORT_PATHS[35]],
        reports[REPORT_PATHS[36]],
    )
    _validate_scan_option_boundary_reports(
        reports[REPORT_PATHS[37]],
        reports[REPORT_PATHS[38]],
    )
    _validate_legacy_dispatch_report(reports[REPORT_PATHS[39]])
    _validate_dos_dispatch_report(reports[REPORT_PATHS[40]])
    _validate_bw_dispatch_report(reports[REPORT_PATHS[41]])
    _validate_path_boundary_report(reports[REPORT_PATHS[42]])
    _validate_archive_dispatch_report(reports[REPORT_PATHS[43]])
    _validate_archive_limit_report(reports[REPORT_PATHS[44]])
    return capabilities


def build_plan(
    traceability: dict[str, Any],
    traceability_bytes: bytes,
    reports: dict[str, dict[str, Any]],
    report_bytes: dict[str, bytes],
) -> dict[str, Any]:
    capabilities = _validate_inputs(traceability, reports)
    rows = []
    for capability in capabilities:
        capability_id = capability["id"]
        evidence_set = capability["evidence_set"]
        if capability_id in COMPLETE:
            status = "evidence_complete"
            observed_scope = COMPLETE[capability_id]
            missing_scope = None
            experiment = None
        elif capability_id in PARTIAL:
            status = "partial"
            observed_scope = PARTIAL[capability_id]
            missing_scope = (
                "execute the remaining Qt5 capability boundary under the "
                "pinned Qt6 oracle"
            )
            experiment = CAMPAIGNS[evidence_set]
        else:
            status = "missing"
            observed_scope = None
            missing_scope = (
                "no row-complete Qt6 runtime evidence is currently admitted"
            )
            experiment = CAMPAIGNS[evidence_set]
        rows.append(
            {
                "id": capability_id,
                "name": capability["name"],
                "evidence_set": evidence_set,
                "status": status,
                "observed_scope": observed_scope,
                "missing_scope": missing_scope,
                "proposed_experiment": experiment,
                "acceptance": (
                    "the full Linux Qt5 row boundary is executed against the "
                    "pinned Qt6 oracle; raw and normalized outputs are retained; "
                    "every difference is either zero or explicitly classified"
                ),
            }
        )

    counts = {
        state: sum(row["status"] == state for row in rows)
        for state in ("evidence_complete", "partial", "missing")
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "evaluated_on": EVALUATED_ON,
        "result": (
            "complete"
            if counts["partial"] == 0 and counts["missing"] == 0
            else "incomplete"
        ),
        "platform": PLATFORM,
        "upstream_commit": UPSTREAM_COMMIT,
        "rules_commit": RULES_COMMIT,
        "sources": {
            TRACEABILITY_PATH: sha256(traceability_bytes),
            **{path: sha256(report_bytes[path]) for path in REPORT_PATHS},
        },
        "known_differences": [
            {
                "source": REPORT_PATHS[0],
                "scope": "minimal.exe stderr",
                "semantic_detection_equal": True,
            },
            {
                "source": REPORT_PATHS[1],
                "scope": "global HostApi runtime",
                "difference_count": reports[REPORT_PATHS[1]][
                    "difference_count"
                ],
            },
            {
                "source": REPORT_PATHS[2],
                "scope": "HostApi arity diagnostics",
                "difference_count": reports[REPORT_PATHS[2]][
                    "difference_count"
                ],
            },
            {
                "source": REPORT_PATHS[3],
                "scope": "global typo diagnostics",
                "semantic_detection_equal": reports[REPORT_PATHS[3]][
                    "normalized_detections_equal"
                ],
            },
            {
                "source": REPORT_PATHS[4],
                "scope": "five nested formatter stderr streams",
                "difference_count": len(
                    reports[REPORT_PATHS[4]]["failures"]
                ),
                "stdout_and_exit_equal": True,
                "right_stderr_sha256": QT6_UNIMPLEMENTED_SHA256,
            },
            {
                "source": REPORT_PATHS[5],
                "scope": "PE32/PE64 baseline and PE32 seven-formatter stderr streams",
                "difference_count": len(
                    reports[REPORT_PATHS[5]]["failures"]
                ),
                "stdout_and_exit_equal": True,
                "right_stderr_sha256": QT6_UNIMPLEMENTED_SHA256,
            },
            {
                "source": REPORT_PATHS[6],
                "scope": "scan-option and nested gate raw streams",
                "difference_count": len(
                    reports[REPORT_PATHS[6]]["failures"]
                ),
                "detection_semantics_equal_except_trailing_diagnostics": True,
            },
            {
                "source": REPORT_PATHS[7],
                "scope": "alltypes and combined trailing diagnostics",
                "repetitions": reports[REPORT_PATHS[7]]["repetitions"],
                "json_documents_equal": True,
                "raw_streams_retained_before_address_normalization": True,
            },
            {
                "source": REPORT_PATHS[8],
                "scope": "five-sample special formatter and priority matrix",
                "special_case_difference_count": 0,
                "corpus_warning_difference_count": len(
                    reports[REPORT_PATHS[8]]["failures"]
                ),
            },
            {
                "source": REPORT_PATHS[9],
                "scope": "28-case special-mode exact boundary matrix",
                "difference_count": 0,
                "all_raw_streams_equal": True,
            },
            {
                "source": REPORT_PATHS[10],
                "scope": "14-case basic path and directory matrix",
                "difference_count": len(
                    reports[REPORT_PATHS[10]]["failures"]
                ),
                "stdout_exit_prefix_and_framing_equal": True,
            },
            {
                "source": REPORT_PATHS[11],
                "scope": "18-case database load/error/messages matrix",
                "difference_count": len(
                    reports[REPORT_PATHS[11]]["failures"]
                ),
                "only_malformed_parse_diagnostic_differs": True,
            },
            {
                "source": REPORT_PATHS[12],
                "scope": "malformed parse and runtime error diagnostics",
                "repetitions": reports[REPORT_PATHS[12]]["repetitions"],
                "json_documents_equal": True,
                "raw_streams_retained": True,
            },
            {
                "source": REPORT_PATHS[13],
                "scope": "nine-case verbose/profiling/test/createtest option matrix",
                "difference_count": 0,
                "all_raw_streams_equal": True,
            },
            {
                "source": REPORT_PATHS[14],
                "scope": "292-name Binary profiling execution order",
                "difference_count": 0,
                "order_sha256": reports[REPORT_PATHS[14]][
                    "order_sha256"
                ],
            },
            {
                "source": REPORT_PATHS[16],
                "scope": "37-case public entry, device, filter, cancellation, and ordering contract",
                "difference_count": 0,
                "relationship_count": len(
                    reports[REPORT_PATHS[16]]["relationships"]
                ),
                "qt5_relationships_equal": True,
            },
            {
                "source": REPORT_PATHS[18],
                "scope": "ten-case database layer, ordering, init, type, and mode-filter contract",
                "difference_count": 0,
                "relationship_count": len(
                    reports[REPORT_PATHS[18]]["relationships"]
                ),
                "qt5_canonical_cases_equal": True,
            },
            {
                "source": REPORT_PATHS[26],
                "scope": "five-harness scalar, lists, flags, IDs, enums, and record metadata contract",
                "difference_count": sum(
                    len(comparison["harness_output_differences"])
                    for comparison in reports[REPORT_PATHS[26]][
                        "comparisons"
                    ].values()
                ),
                "all_differences_classified": True,
                "capability_count": 6,
            },
            {
                "source": REPORT_PATHS[28],
                "scope": "seven-case private signature-file path filter contract",
                "difference_count": 0,
                "relationship_count": 11,
                "raw_stdout_equal": True,
            },
            {
                "source": REPORT_PATHS[30],
                "scope": "public recursive omission and direct debug-data positive control",
                "difference_count": 1,
                "semantic_output_equal": True,
                "right_stderr_sha256": QT6_UNIMPLEMENTED_SHA256,
            },
            {
                "source": REPORT_PATHS[32],
                "scope": "four-mode RT_MANIFEST resource context propagation",
                "difference_count": 4,
                "semantic_output_equal": True,
                "right_stderr_sha256": QT6_UNIMPLEMENTED_SHA256,
            },
            {
                "source": REPORT_PATHS[33],
                "scope": "64 engine archive-option cases and 32 release controls",
                "difference_count": 60,
                "all_stdout_equal": True,
                "right_stderr_sha256": QT6_UNIMPLEMENTED_SHA256,
            },
            {
                "source": REPORT_PATHS[35],
                "root_cause_source": REPORT_PATHS[36],
                "scope": "ISO9660 NUL dot-entry filtering shifts the Qt6 hard iteration boundary by one record",
                "qt5_last_reachable_pdf_ordinal": 100000,
                "qt6_last_reachable_pdf_ordinal": 99999,
                "qt6_extra_stream_count_per_case": 1,
                "source_revision_equal": True,
            },
        ],
        "rows": rows,
        "summary": {
            "capability_count": len(rows),
            **counts,
            "closure_required": counts["partial"] + counts["missing"],
            "all_capabilities_accounted_for": len(rows) == 68,
            "cap_gap_007_closed": counts["partial"] == counts["missing"] == 0,
        },
        "limitations": [
            "Linux Qt6 platform coverage is promoted only while all 68 hash-bound rows remain evidence_complete",
            "partial evidence cannot satisfy a capability row",
            "diagnostic differences are not normalized away from compatibility review",
            "the current Qt6 image and reports remain pinned to exact identities",
        ],
    }


def serialize(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--traceability",
        type=Path,
        default=root / TRACEABILITY_PATH,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root
        / "docs"
        / "research"
        / "data"
        / "qt6-capability-closure-plan.json",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[2]
    traceability, traceability_raw = load_json(args.traceability)
    reports: dict[str, dict[str, Any]] = {}
    raw_reports: dict[str, bytes] = {}
    for relative_path in REPORT_PATHS:
        reports[relative_path], raw_reports[relative_path] = load_json(
            root / relative_path
        )
    plan = build_plan(
        traceability,
        traceability_raw,
        reports,
        raw_reports,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(serialize(plan))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

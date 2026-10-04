#!/usr/bin/env python3
"""Build a non-admitted macOS Qt5 database-cache engine harness."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
PLATFORM = "macos-x86_64-qt5"
BASELINE_COLLECTOR = "tools/upstream/collect_macos_cli_baseline.py"
ORACLE_VALIDATOR = "tools/upstream/validate_macos_qt5_oracle_report.py"
SHARED_HARNESS = "tools/upstream/database_cache_harness_main.cpp"
MACOS_ADAPTER = (
    "tools/upstream/database_cache_harness_macos_adapter.cpp"
)
VALIDATOR = (
    "tools/upstream/validate_macos_database_cache_harness_build.py"
)
REPORT_NAME = "database-cache-harness-build-candidate.json"
BINARY_NAME = "database-cache-harness-candidate"
PATCHED_MAKEFILE_NAME = "Makefile.DieDatabaseCacheHarness"
ADMISSION_REASON = (
    "database-cache engine harness build candidate only; no macOS "
    "runtime capability evidence is admitted"
)
LIMITATIONS = [
    (
        "the builder replaces only the generated console "
        "main_console.cpp object and reuses the remaining fixed "
        "qmake object/link closure"
    ),
    (
        "the adapter changes only the entry point to enable "
        "QStandardPaths test mode before invoking the shared "
        "19-case harness"
    ),
    (
        "a successful build is not runtime cache, permission, "
        "determinism, or Linux-semantic evidence"
    ),
]


class BuildError(ValueError):
    """The harness build identity or generated makefile is unsafe."""


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load(root: Path, relative: str, name: str) -> Any:
    path = root / relative
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise BuildError(f"cannot load helper module: {relative}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def generator_bindings(root: Path) -> dict[str, str]:
    paths = {
        "path": (
            "tools/upstream/build_macos_database_cache_harness.py"
        ),
        "validator_path": VALIDATOR,
        "baseline_collector_path": BASELINE_COLLECTOR,
        "oracle_validator_path": ORACLE_VALIDATOR,
        "shared_harness_path": SHARED_HARNESS,
        "macos_adapter_path": MACOS_ADAPTER,
    }
    result = dict(paths)
    for field, relative in paths.items():
        digest_field = (
            "sha256"
            if field == "path"
            else field.removesuffix("_path") + "_sha256"
        )
        result[digest_field] = sha256((root / relative).read_bytes())
    return result


def patch_qmake_makefile(
    raw: bytes,
    *,
    target: Path,
) -> tuple[bytes, dict[str, int | str]]:
    """Patch a qmake-generated Makefile to build the cache harness instead.

    On Linux and Windows, qmake emits a ``DESTDIR_TARGET`` variable that
    combines ``DESTDIR`` and ``TARGET``.  On macOS (Qt 5.15.2, macx-clang),
    qmake emits only ``TARGET`` with the full relative path and uses that
    same explicit path as the build-rule prerequisite.  Both formats are
    supported here.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BuildError("qmake makefile is not UTF-8") from error
    if any(character.isspace() for character in str(target)):
        raise BuildError("harness target path must not contain whitespace")

    # Detect which target-variable convention the Makefile uses.
    destdir_target_lines = list(
        re.finditer(r"(?m)^DESTDIR_TARGET\s*=.*$", text)
    )
    target_lines = list(
        re.finditer(r"(?m)^TARGET\s*=.*$", text)
    )
    if len(destdir_target_lines) == 1:
        target_variable = "DESTDIR_TARGET"
        target_replacements = 1
    elif (
        len(destdir_target_lines) == 0
        and len(target_lines) == 1
    ):
        # macOS qmake format: TARGET holds the full relative path and
        # the build-rule prerequisite is the same explicit path.
        target_variable = "TARGET"
        target_replacements = 1
        # Also patch the build-rule prerequisite line that uses the
        # original TARGET value as an explicit path target.
        original_target_match = re.search(
            r"(?m)^TARGET\s*=\s*(.+)$", text
        )
        if original_target_match is None:
            raise BuildError("TARGET assignment is malformed")
        original_target_path = original_target_match.group(1).strip()
        # Replace the build-rule prerequisite (e.g. the line
        # "../../path/diec:  $(OBJECTS)") with the new target path
        # so that `make <target.as_posix()>` can match the rule.
        rule_pattern = re.compile(
            re.escape(original_target_path) + r":\s+\$\(OBJECTS\)"
        )
        text, rule_replacement_count = rule_pattern.subn(
            f"{target.as_posix()}: $(OBJECTS)", text
        )
        if rule_replacement_count != 1:
            raise BuildError(
                "expected one build-rule prerequisite with $(OBJECTS)"
            )
        # Remove the mkdir -p line that references the original DESTDIR
        # directory, since the harness target is in the build directory.
        mkdir_pattern = re.compile(
            r"(?m)^\t@test -d [^\n]* \|\| mkdir -p [^\n]*\n",
        )
        text, mkdir_count = mkdir_pattern.subn("", text)
        target_replacements += rule_replacement_count + mkdir_count
    else:
        raise BuildError(
            "expected one DESTDIR_TARGET or one TARGET assignment"
        )

    object_count = text.count("main_console.o")
    if object_count < 2:
        raise BuildError("main_console.o contract is missing")
    source_pattern = re.compile(
        r"(?<!\S)\S*main_console\.cpp(?=\s|$)"
    )
    source_count = len(source_pattern.findall(text))
    if source_count < 2:
        raise BuildError("main_console.cpp contract is missing")
    text = source_pattern.sub(
        "database_cache_harness_macos_adapter.cpp", text
    )
    text = text.replace(
        "main_console.o",
        "database_cache_harness_macos_adapter.o",
    )
    text = re.sub(
        rf"(?m)^{target_variable}\s*=.*$",
        f"{target_variable} = {target.as_posix()}",
        text,
        count=1,
    )
    if "main_console.cpp" in text or "main_console.o" in text:
        raise BuildError("qmake makefile replacement was incomplete")
    return text.encode("utf-8"), {
        "source_token_replacements": source_count,
        "object_token_replacements": object_count,
        "destination_target_replacements": target_replacements,
        "target_variable": target_variable,
        "replaced_source": "main_console.cpp",
        "replacement_source": (
            "database_cache_harness_macos_adapter.cpp"
        ),
        "replaced_object": "main_console.o",
        "replacement_object": (
            "database_cache_harness_macos_adapter.o"
        ),
    }


def _run(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
    )


def _checked_text(
    arguments: list[str],
    *,
    description: str,
) -> str:
    process = _run(arguments)
    if process.returncode != 0 or process.stderr:
        raise BuildError(f"{description} failed")
    try:
        return process.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise BuildError(f"{description} output is not UTF-8") from error


def _write_raw(
    bundle: Path,
    relative: str,
    raw: bytes,
) -> dict[str, Any]:
    path = bundle / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {
        "path": relative,
        "bytes": len(raw),
        "sha256": sha256(raw),
    }


def build(
    *,
    root: Path,
    source_dir: Path,
    qt_dir: Path,
    build_dir: Path,
    oracle_path: Path,
    output_binary: Path,
    output_report: Path,
    jobs: int,
) -> dict[str, Any]:
    if sys.platform != "darwin" or platform.machine() != "x86_64":
        raise BuildError("builder requires native Darwin x86_64")
    if not 1 <= jobs <= 16:
        raise BuildError("jobs must be in 1..16")
    source_dir = source_dir.resolve(strict=True)
    qt_dir = qt_dir.resolve(strict=True)
    build_dir = build_dir.resolve(strict=True)
    oracle_path = oracle_path.resolve(strict=True)
    output_report = output_report.resolve()
    output_binary = output_binary.resolve()
    if not output_report.parent.is_dir():
        raise BuildError("harness evidence bundle directory is missing")
    if output_report.name != REPORT_NAME:
        raise BuildError(f"report name must be {REPORT_NAME}")
    if output_binary != output_report.parent / BINARY_NAME:
        raise BuildError(
            f"binary must be bundle-local with name {BINARY_NAME}"
        )
    if oracle_path != (
        output_report.parent / "oracle-candidate.json"
    ).resolve(strict=True):
        raise BuildError(
            "oracle report must be bundle-local: oracle-candidate.json"
        )
    if output_report.exists() or output_binary.exists():
        raise BuildError("harness output already exists")
    for protected in (source_dir, build_dir, qt_dir):
        try:
            output_report.parent.relative_to(protected)
        except ValueError:
            continue
        raise BuildError(
            "harness evidence bundle must be outside source/build/Qt"
        )
    planned_bundle_files = (
        "build-input/database-cache-console.Makefile",
        "build-input/database-cache-harness.Makefile",
        "build-input/database_cache_harness_main.cpp",
        (
            "build-input/"
            "database_cache_harness_macos_adapter.cpp"
        ),
        "raw/database-cache-harness-build.stdout",
        "raw/database-cache-harness-build.stderr",
    )
    if any(
        (output_report.parent / relative).exists()
        for relative in planned_bundle_files
    ):
        raise BuildError("pre-existing harness build evidence path")

    baseline = _load(
        root, BASELINE_COLLECTOR, "macos_baseline_for_cache_build"
    )
    cli = (source_dir / "build" / "release" / "diec").resolve(
        strict=True
    )
    oracle, oracle_raw = baseline.validate_oracle_inputs(
        root, oracle_path, source_dir, qt_dir, cli
    )
    oracle_build = Path(oracle["local_paths"]["build_dir"]).resolve(
        strict=True
    )
    if build_dir != oracle_build:
        raise BuildError("qmake build directory differs from oracle")
    common = baseline.load_module(
        "windows_cli_common_for_macos_cache_build",
        root / baseline.SHARED_COLLECTOR,
    )
    source = common.validate_source(source_dir)
    source["tracked_files_clean_before_and_after"] = True
    qt = baseline.validate_qt(common, qt_dir, oracle)
    cli_sha256 = common.sha256_file(cli)
    if cli_sha256 != oracle["artifact"]["sha256"]:
        raise BuildError("CLI differs from oracle report")

    console_build = (build_dir / "console_source").resolve(strict=True)
    makefile = console_build / "Makefile"
    if not makefile.is_file():
        raise BuildError("console qmake Makefile is missing")
    local_target = console_build / BINARY_NAME
    patched_makefile = console_build / PATCHED_MAKEFILE_NAME
    local_shared = console_build / Path(SHARED_HARNESS).name
    local_adapter = console_build / Path(MACOS_ADAPTER).name
    local_object = (
        console_build / "database_cache_harness_macos_adapter.o"
    )
    for path in (
        local_target,
        patched_makefile,
        local_shared,
        local_adapter,
        local_object,
    ):
        if path.exists():
            raise BuildError(
                f"pre-existing harness build path: {path.name}"
            )
    original_makefile = makefile.read_bytes()
    patched_raw, replacements = patch_qmake_makefile(
        original_makefile, target=local_target
    )
    shutil.copyfile(root / SHARED_HARNESS, local_shared)
    shutil.copyfile(root / MACOS_ADAPTER, local_adapter)
    patched_makefile.write_bytes(patched_raw)

    # Apply the same macOS build fix as the oracle builder: xbinary.h
    # line 114 includes CoreFoundation.h under Q_OS_MAC, which fails
    # when xdeflatedecoder.cpp includes xbinary.h inside function scope.
    # The include is unused in xbinary.h.  Restore via git checkout after.
    xbinary_path = source_dir / "Formats" / "xbinary.h"
    xbinary_patch_applied = False
    if (
        xbinary_path.is_file()
        and b"#include <CoreFoundation/CoreFoundation.h>"
        in xbinary_path.read_bytes()
    ):
        xbinary_original = xbinary_path.read_bytes()
        xbinary_patched = xbinary_original.replace(
            b"#include <CoreFoundation/CoreFoundation.h>  // Check",
            b"// #include <CoreFoundation/CoreFoundation.h>"
            b"  // macOS build fix: unused include causes"
            b" CFMessagePort.h error in function scope",
        )
        if xbinary_patched != xbinary_original:
            xbinary_path.write_bytes(xbinary_patched)
            xbinary_patch_applied = True

    environment = os.environ.copy()
    environment["PATH"] = (
        str(qt_dir / "bin")
        + os.pathsep
        + environment.get("PATH", "")
    )
    started = time.monotonic()
    process = _run(
        [
            "make",
            "-f",
            patched_makefile.name,
            f"-j{jobs}",
            local_target.as_posix(),
        ],
        cwd=console_build,
        environment=environment,
    )
    elapsed_ms = round((time.monotonic() - started) * 1000)

    # Restore the patched xbinary.h so the source tree is clean again.
    if xbinary_patch_applied:
        _run(
            ["git", "-C", str(source_dir / "Formats"), "checkout", "--",
             "xbinary.h"],
        )
    bundle = output_report.parent
    build_inputs = {
        "console_makefile": _write_raw(
            bundle,
            "build-input/database-cache-console.Makefile",
            original_makefile,
        ),
        "patched_makefile": _write_raw(
            bundle,
            "build-input/database-cache-harness.Makefile",
            patched_raw,
        ),
        "shared_harness": _write_raw(
            bundle,
            "build-input/database_cache_harness_main.cpp",
            (root / SHARED_HARNESS).read_bytes(),
        ),
        "macos_adapter": _write_raw(
            bundle,
            (
                "build-input/"
                "database_cache_harness_macos_adapter.cpp"
            ),
            (root / MACOS_ADAPTER).read_bytes(),
        ),
    }
    build_stdout = _write_raw(
        bundle,
        "raw/database-cache-harness-build.stdout",
        process.stdout,
    )
    build_stderr = _write_raw(
        bundle,
        "raw/database-cache-harness-build.stderr",
        process.stderr,
    )
    if process.returncode != 0:
        raise BuildError(
            f"database-cache harness build failed: {process.returncode}"
        )
    if not local_target.is_file():
        raise BuildError("harness target was not produced")
    shutil.copyfile(local_target, output_binary)
    output_binary.chmod(0o755)

    artifact_raw = output_binary.read_bytes()
    architectures = _checked_text(
        ["lipo", "-archs", str(output_binary)],
        description="lipo",
    ).split()
    if architectures != ["x86_64"]:
        raise BuildError("harness artifact architecture differs")
    file_description = _checked_text(
        ["file", "-b", str(output_binary)],
        description="file",
    )
    otool_process = _run(["otool", "-L", str(output_binary)])
    if otool_process.returncode != 0 or otool_process.stderr:
        raise BuildError("otool failed")
    try:
        otool_lines = otool_process.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise BuildError("otool output is not UTF-8") from error
    if not otool_lines or otool_lines[0] != f"{output_binary}:":
        raise BuildError("otool artifact header changed")
    otool_lines[0] = f"{BINARY_NAME}:"
    if common.sha256_file(cli) != cli_sha256:
        raise BuildError("harness build modified fixed CLI artifact")
    after_source = common.validate_source(source_dir)
    after_source["tracked_files_clean_before_and_after"] = True
    if after_source != source:
        raise BuildError("harness build modified tracked source identity")

    report = {
        "schema_version": 1,
        "result": "candidate",
        "platform": PLATFORM,
        "generator": generator_bindings(root),
        "oracle_report": {
            "path": "oracle-candidate.json",
            "sha256": sha256(oracle_raw),
        },
        "source": source,
        "qt": qt,
        "cli": {
            "relative_path": "build/release/diec",
            "size": cli.stat().st_size,
            "sha256": cli_sha256,
        },
        "build": {
            "system": "patched-qmake-makefile",
            "tool": "make",
            "jobs": jobs,
            "elapsed_milliseconds": elapsed_ms,
            "console_makefile_sha256": sha256(original_makefile),
            "patched_makefile_sha256": sha256(patched_raw),
            "replacements": replacements,
            "inputs": build_inputs,
            "exit_code": process.returncode,
            "stdout": build_stdout,
            "stderr": build_stderr,
        },
        "artifact": {
            "path": BINARY_NAME,
            "size": len(artifact_raw),
            "sha256": sha256(artifact_raw),
            "architectures": architectures,
            "file_description": file_description,
            "otool_l": otool_lines,
        },
        "local_paths": {
            "source_dir": str(source_dir),
            "qt_dir": str(qt_dir),
            "build_dir": str(build_dir),
            "console_build_dir": str(console_build),
            "original_makefile": str(makefile),
            "patched_makefile": str(patched_makefile),
            "local_artifact": str(local_target),
        },
        "admission": {
            "platform_admitted": False,
            "capability_rows_admitted": 0,
            "reason": ADMISSION_REASON,
        },
        "limitations": LIMITATIONS,
    }
    output_report.write_bytes(
        (
            json.dumps(
                report,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode()
    )
    return report


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--qt-dir", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--oracle-report", type=Path, required=True)
    parser.add_argument("--output-binary", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.set_defaults(root=root)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        build(
            root=args.root.resolve(),
            source_dir=args.source_dir,
            qt_dir=args.qt_dir,
            build_dir=args.build_dir,
            oracle_path=args.oracle_report,
            output_binary=args.output_binary,
            output_report=args.output_report,
            jobs=args.jobs,
        )
    except (BuildError, OSError, ValueError) as error:
        print(
            f"macOS database-cache harness build error: {error}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

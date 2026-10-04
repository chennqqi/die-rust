#!/usr/bin/env bash
set -euo pipefail

EXPECTED_COMMIT="74eaf505c250ab47e709024e9dc41657cd8f2254"
EXPECTED_RULES_COMMIT="c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
EXPECTED_SUBMODULE_COUNT=58
EXPECTED_QT_VERSION="5.15.2"
EXPECTED_QMAKE_SPEC="macx-clang"
EXPECTED_ARCH="x86_64"

usage() {
    cat <<'EOF'
Usage:
  build_macos_qt5_oracle.sh \
    --source-dir <clean recursive DIE-engine checkout> \
    --qt-dir <Qt 5.15.2 clang_64 directory> \
    --build-dir <empty external qmake directory> \
    --output <external candidate-report.json> \
    [--jobs <1..64>]

The output is a candidate identity report. It never admits the macOS
capability baseline; runtime collectors and a reviewed toolchain lock are
still required.
EOF
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command missing: $1"
}

resolve_directory() {
    [ -d "$1" ] || fail "directory does not exist: $1"
    (
        cd "$1"
        pwd -P
    )
}

sha256_file() {
    shasum -a 256 "$1" | awk '{print $1}'
}

is_hex_sha256() {
    case "$1" in
        *[!0-9a-f]*|'') return 1 ;;
        *) [ "${#1}" -eq 64 ] ;;
    esac
}

source_dir=""
qt_dir=""
build_dir=""
output_path=""
jobs=4

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-dir|--qt-dir|--build-dir|--output|--jobs)
            [ "$#" -ge 2 ] || fail "missing value for $1"
            case "$1" in
                --source-dir) source_dir="$2" ;;
                --qt-dir) qt_dir="$2" ;;
                --build-dir) build_dir="$2" ;;
                --output) output_path="$2" ;;
                --jobs) jobs="$2" ;;
            esac
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[ -n "$source_dir" ] || fail "--source-dir is required"
[ -n "$qt_dir" ] || fail "--qt-dir is required"
[ -n "$build_dir" ] || fail "--build-dir is required"
[ -n "$output_path" ] || fail "--output is required"
case "$jobs" in
    ''|*[!0-9]*) fail "--jobs must be an integer from 1 through 64" ;;
esac
[ "$jobs" -ge 1 ] && [ "$jobs" -le 64 ] ||
    fail "--jobs must be an integer from 1 through 64"

[ "$(uname -s)" = "Darwin" ] ||
    fail "this oracle builder only supports macOS"
[ "$(uname -m)" = "$EXPECTED_ARCH" ] ||
    fail "host architecture must be $EXPECTED_ARCH"

for command_name in \
    awk basename clang cmake cp date dirname file find git head lipo make \
    mktemp otool python3 rm shasum stat sw_vers sysctl
do
    require_command "$command_name"
done

source_dir="$(resolve_directory "$source_dir")"
qt_dir="$(resolve_directory "$qt_dir")"
mkdir -p "$build_dir"
build_dir="$(resolve_directory "$build_dir")"

case "$build_dir/" in
    "$source_dir/"*) fail "build directory must be outside the source tree" ;;
esac
case "$source_dir/" in
    "$build_dir/"*) fail "source directory must be outside the build tree" ;;
esac

if [ -n "$(find "$build_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    fail "build directory must be empty"
fi

output_parent="$(dirname "$output_path")"
mkdir -p "$output_parent"
output_parent="$(resolve_directory "$output_parent")"
output_path="$output_parent/$(basename "$output_path")"
case "$output_path" in
    "$source_dir"/*|"$build_dir"/*)
        fail "candidate report must be outside source and build trees"
        ;;
esac

root_commit="$(git -C "$source_dir" rev-parse HEAD)"
[ "$root_commit" = "$EXPECTED_COMMIT" ] ||
    fail "DIE-engine commit mismatch: $root_commit"

root_status="$(
    git -C "$source_dir" status --porcelain=v1 --untracked-files=no \
        --ignore-submodules=dirty
)"
[ -z "$root_status" ] || fail "DIE-engine has tracked changes"

submodule_status="$(
    git -C "$source_dir" submodule status --recursive
)"
submodule_count="$(
    printf '%s\n' "$submodule_status" |
        awk 'NF { count += 1 } END { print count + 0 }'
)"
[ "$submodule_count" -eq "$EXPECTED_SUBMODULE_COUNT" ] ||
    fail "expected $EXPECTED_SUBMODULE_COUNT recursive submodules, got $submodule_count"
if printf '%s\n' "$submodule_status" | awk 'NF && substr($0, 1, 1) != " " { exit 1 }'
then
    :
else
    fail "recursive submodule identity is not clean"
fi

submodule_changes="$(
    git -C "$source_dir" submodule foreach --quiet --recursive \
        'git status --porcelain=v1 --untracked-files=no'
)"
[ -z "$submodule_changes" ] || fail "submodules have tracked changes"

rules_dir="$source_dir/Detect-It-Easy"
[ -d "$rules_dir/.git" ] || [ -f "$rules_dir/.git" ] ||
    fail "Detect-It-Easy submodule is missing"
rules_commit="$(git -C "$rules_dir" rev-parse HEAD)"
[ "$rules_commit" = "$EXPECTED_RULES_COMMIT" ] ||
    fail "Detect-It-Easy commit mismatch: $rules_commit"

qmake="$qt_dir/bin/qmake"
[ -x "$qmake" ] || fail "qmake is not executable: $qmake"
qt_version="$("$qmake" -query QT_VERSION)"
[ "$qt_version" = "$EXPECTED_QT_VERSION" ] ||
    fail "Qt version mismatch: $qt_version"
qmake_spec="$("$qmake" -query QMAKE_SPEC)"
[ "$qmake_spec" = "$EXPECTED_QMAKE_SPEC" ] ||
    fail "qmake spec mismatch: $qmake_spec"
qt_libs="$("$qmake" -query QT_INSTALL_LIBS)"

qt_core="$qt_libs/QtCore.framework/Versions/5/QtCore"
qt_script="$qt_libs/QtScript.framework/Versions/5/QtScript"
[ -f "$qt_core" ] || fail "QtCore framework binary is missing: $qt_core"
[ -f "$qt_script" ] ||
    fail "QtScript framework binary is missing: $qt_script"

qmake_sha256="$(sha256_file "$qmake")"
qt_core_sha256="$(sha256_file "$qt_core")"
qt_script_sha256="$(sha256_file "$qt_script")"
is_hex_sha256 "$qmake_sha256" || fail "invalid qmake SHA-256"
is_hex_sha256 "$qt_core_sha256" || fail "invalid QtCore SHA-256"
is_hex_sha256 "$qt_script_sha256" || fail "invalid QtScript SHA-256"

project="$source_dir/die_source.pro"
[ -f "$project" ] || fail "top-level qmake project is missing"
artifact="$source_dir/build/release/diec"
[ ! -e "$artifact" ] ||
    fail "pre-existing CLI artifact would make the build ambiguous: $artifact"

# --- macOS build fix: remove unused CoreFoundation.h include ---
# xbinary.h line 114 includes CoreFoundation.h under Q_OS_MAC.
# xdeflatedecoder.cpp (10581-line amalgamation) includes xbinary.h
# inside function scope (9 unmatched braces at line 9482).
# CFMessagePort.h CF_EXPORT (extern) typedefs are invalid in function
# scope. The include is unused in xbinary.h (no CF types referenced).
# Linux/Windows unaffected (Q_OS_MAC undefined).
xbinary_path="$source_dir/Formats/xbinary.h"
patch_applied=false
if grep -q '#include <CoreFoundation/CoreFoundation.h>' "$xbinary_path" 2>/dev/null; then
    sed -i '' 's|#include <CoreFoundation/CoreFoundation.h>  // Check|// #include <CoreFoundation/CoreFoundation.h>  // macOS build fix: unused include causes CFMessagePort.h error in function scope|' "$xbinary_path"
    patch_applied=true
fi

started_at_epoch="$(date +%s)"
(
    cd "$build_dir"
    "$qmake" "$project" -spec "$EXPECTED_QMAKE_SPEC" "CONFIG+=release"
    make -j"$jobs" sub-build_libs-make_first
    make -j"$jobs" sub-console_source-make_first
)
finished_at_epoch="$(date +%s)"
elapsed_seconds="$((finished_at_epoch - started_at_epoch))"

# Restore the patched file so the source tree is clean again
if $patch_applied; then
    git -C "$source_dir/Formats" checkout -- xbinary.h
fi

[ -x "$artifact" ] || fail "diec CLI artifact was not produced: $artifact"
artifact_archs="$(lipo -archs "$artifact")"
[ "$artifact_archs" = "$EXPECTED_ARCH" ] ||
    fail "artifact architecture mismatch: $artifact_archs"

set +e
version_stdout="$("$artifact" --version 2>&1)"
version_exit_code=$?
set -e
[ "$version_exit_code" -eq 0 ] ||
    fail "diec --version failed with exit code $version_exit_code"
[ "$version_stdout" = "die 4.0.0" ] ||
    fail "diec version output mismatch: $version_stdout"

post_build_status="$(
    git -C "$source_dir" status --porcelain=v1 --untracked-files=no \
        --ignore-submodules=dirty
)"
[ -z "$post_build_status" ] ||
    fail "build modified tracked source files"

report_tmp="$(mktemp "${TMPDIR:-/tmp}/die-macos-oracle.XXXXXX")"
otool_tmp="$(mktemp "${TMPDIR:-/tmp}/die-macos-otool.XXXXXX")"
trap 'rm -f "$report_tmp" "$otool_tmp"' EXIT
otool -L "$artifact" >"$otool_tmp"

export DIE_MAC_SOURCE_DIR="$source_dir"
export DIE_MAC_QT_DIR="$qt_dir"
export DIE_MAC_BUILD_DIR="$build_dir"
export DIE_MAC_ROOT_COMMIT="$root_commit"
export DIE_MAC_RULES_COMMIT="$rules_commit"
export DIE_MAC_SUBMODULE_COUNT="$submodule_count"
export DIE_MAC_QT_VERSION="$qt_version"
export DIE_MAC_QMAKE_SPEC="$qmake_spec"
export DIE_MAC_QMAKE_SHA256="$qmake_sha256"
export DIE_MAC_QTCORE_SHA256="$qt_core_sha256"
export DIE_MAC_QTSCRIPT_SHA256="$qt_script_sha256"
export DIE_MAC_JOBS="$jobs"
export DIE_MAC_ELAPSED_SECONDS="$elapsed_seconds"
export DIE_MAC_ARTIFACT="$artifact"
export DIE_MAC_ARTIFACT_SHA256="$(sha256_file "$artifact")"
export DIE_MAC_ARTIFACT_SIZE="$(stat -f %z "$artifact")"
export DIE_MAC_ARTIFACT_ARCHS="$artifact_archs"
export DIE_MAC_ARTIFACT_FILE="$(file -b "$artifact")"
export DIE_MAC_VERSION_STDOUT="$version_stdout"
export DIE_MAC_VERSION_EXIT_CODE="$version_exit_code"
export DIE_MAC_OTOOL_PATH="$otool_tmp"
export DIE_MAC_SW_VERS="$(sw_vers)"
export DIE_MAC_UNAME="$(uname -a)"
export DIE_MAC_CPU_BRAND="$(sysctl -n machdep.cpu.brand_string)"
export DIE_MAC_LOGICAL_CPU="$(sysctl -n hw.logicalcpu)"
export DIE_MAC_XCODE_VERSION="$(xcodebuild -version 2>/dev/null || echo 'CommandLineTools only (no full Xcode)')"
export DIE_MAC_CLANG_VERSION="$(clang --version)"
export DIE_MAC_CMAKE_VERSION="$(cmake --version | head -n 1)"
export DIE_MAC_QMAKE_VERSION="$("$qmake" -v 2>&1)"
export DIE_MAC_BUILD_MAC_SHA256="$(sha256_file "$source_dir/build_mac.sh")"
export DIE_MAC_WORKFLOW_SHA256="$(
    sha256_file "$source_dir/.github/workflows/builder.yml"
)"
export DIE_MAC_BUILD_PRI_SHA256="$(sha256_file "$source_dir/build.pri")"
export DIE_MAC_CONSOLE_PRO_SHA256="$(
    sha256_file "$source_dir/console_source/console_source.pro"
)"
export DIE_MAC_DIE_PRO_SHA256="$(sha256_file "$source_dir/die_source.pro")"
export DIE_MAC_BUILD_PATCH_APPLIED="$patch_applied"

python3 - "$report_tmp" <<'PY'
import json
import os
from pathlib import Path
import sys


def env(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        raise SystemExit(f"missing report environment value: {name}")
    return value


otool_lines = Path(env("DIE_MAC_OTOOL_PATH")).read_text(
    encoding="utf-8"
).splitlines()
report = {
    "schema_version": 1,
    "result": "candidate",
    "platform": "macos-x86_64-qt5",
    "source": {
        "repository": "https://github.com/horsicq/DIE-engine",
        "commit": env("DIE_MAC_ROOT_COMMIT"),
        "rules_commit": env("DIE_MAC_RULES_COMMIT"),
        "recursive_submodule_count": int(
            env("DIE_MAC_SUBMODULE_COUNT")
        ),
        "tracked_files_clean_before_and_after": True,
    },
    "source_files": {
        ".github/workflows/builder.yml": env(
            "DIE_MAC_WORKFLOW_SHA256"
        ),
        "build.pri": env("DIE_MAC_BUILD_PRI_SHA256"),
        "build_mac.sh": env("DIE_MAC_BUILD_MAC_SHA256"),
        "console_source/console_source.pro": env(
            "DIE_MAC_CONSOLE_PRO_SHA256"
        ),
        "die_source.pro": env("DIE_MAC_DIE_PRO_SHA256"),
    },
    "host": {
        "sw_vers": env("DIE_MAC_SW_VERS").splitlines(),
        "uname": env("DIE_MAC_UNAME"),
        "cpu_brand": env("DIE_MAC_CPU_BRAND"),
        "logical_cpu_count": int(env("DIE_MAC_LOGICAL_CPU")),
        "xcode_version": env("DIE_MAC_XCODE_VERSION").splitlines(),
        "clang_version": env("DIE_MAC_CLANG_VERSION").splitlines(),
        "cmake_version": env("DIE_MAC_CMAKE_VERSION"),
    },
    "qt": {
        "version": env("DIE_MAC_QT_VERSION"),
        "qmake_spec": env("DIE_MAC_QMAKE_SPEC"),
        "qmake_version": env("DIE_MAC_QMAKE_VERSION").splitlines(),
        "qmake_sha256": env("DIE_MAC_QMAKE_SHA256"),
        "qtcore_sha256": env("DIE_MAC_QTCORE_SHA256"),
        "qtscript_sha256": env("DIE_MAC_QTSCRIPT_SHA256"),
    },
    "build": {
        "system": "qmake",
        "configuration": "release",
        "jobs": int(env("DIE_MAC_JOBS")),
        "targets": [
            "sub-build_libs-make_first",
            "sub-console_source-make_first",
        ],
        "elapsed_seconds": int(env("DIE_MAC_ELAPSED_SECONDS")),
        "macos_build_fix": {
            "applied": env("DIE_MAC_BUILD_PATCH_APPLIED") == "true",
            "file": "Formats/xbinary.h",
            "line": 114,
            "original": "#include <CoreFoundation/CoreFoundation.h>  // Check",
            "reason": (
                "xdeflatedecoder.cpp amalgamation includes xbinary.h "
                "inside function scope; CoreFoundation.h CF_EXPORT "
                "typedefs fail; include is unused in xbinary.h"
            ),
        },
    },
    "artifact": {
        "size": int(env("DIE_MAC_ARTIFACT_SIZE")),
        "sha256": env("DIE_MAC_ARTIFACT_SHA256"),
        "architectures": env("DIE_MAC_ARTIFACT_ARCHS").split(),
        "file_description": env("DIE_MAC_ARTIFACT_FILE"),
        "otool_l": otool_lines,
        "version_stdout": env("DIE_MAC_VERSION_STDOUT"),
        "version_exit_code": int(env("DIE_MAC_VERSION_EXIT_CODE")),
    },
    "admission": {
        "platform_admitted": False,
        "reason": (
            "candidate build identity only; paired runtime capability "
            "evidence and a reviewed toolchain lock are missing"
        ),
    },
    "local_paths": {
        "source_dir": env("DIE_MAC_SOURCE_DIR"),
        "qt_dir": env("DIE_MAC_QT_DIR"),
        "build_dir": env("DIE_MAC_BUILD_DIR"),
        "artifact": env("DIE_MAC_ARTIFACT"),
    },
}
Path(sys.argv[1]).write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

python3 "$(dirname "$0")/validate_macos_qt5_oracle_report.py" \
    "$report_tmp"
cp "$report_tmp" "$output_path"
printf '%s\n' "$output_path"

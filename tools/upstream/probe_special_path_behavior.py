#!/usr/bin/env python3
"""Probe pinned Linux Qt5 CLI behavior for Unicode and special paths."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import pathlib
import subprocess
import time
from typing import Any
import zlib


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
FIXTURE_GENERATOR = "tools/corpus/generate_special_path_fixture.py"
FIXTURE_MANIFEST = "docs/research/data/special-path-fixture.json"
ARCHIVE_NAME = "special-path-fixture.tar"
DATABASE_ARGS = (
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
)
ORACLES = {
    "qmake": {
        "image": "die-rust/upstream-oracle:74eaf505-repro",
        "binary": "/opt/die-source/build/release/diec",
    },
    "cmake": {
        "image": "die-rust/upstream-oracle-cmake:74eaf505",
        "binary": "/opt/die-build/src/console/diec",
    },
}
SOURCE_PATHS = {
    "console": "/opt/die-source/src/console/main_console.cpp",
    "formats": "/opt/die-source/Formats/xbinary.cpp",
}
SOURCE_PATTERNS = {
    "console": (
        "QDir().toNativeSeparators(sFileName).toUtf8().data()",
    ),
    "formats": (
        "QFileInfoList eil = dir.entryInfoList();",
        "findFiles(eil.at(i).absoluteFilePath(), pListFileNames, pPdStruct);",
    ),
}
EXPECTED_DIRECTORY_ORDER = (
    "paths/special/ leading-space.pdf",
    "paths/special/--leading-dash.pdf",
    "paths/special/00-ascii.pdf",
    "paths/special/a-case.pdf",
    "paths/special/A-case.pdf",
    "paths/special/backslash\\name.pdf",
    "paths/special/colon:name.pdf",
    "paths/special/emoji-😀.pdf",
    "paths/special/e\u0301-nfd.pdf",
    "paths/special/line\nbreak.pdf",
    "paths/special/space name.pdf",
    "paths/special/tab\tname.pdf",
    "paths/special/trailing-space.pdf ",
    "paths/special/é-nfc.pdf",
    "paths/special/中文.pdf",
)


@dataclass(frozen=True)
class Case:
    name: str
    cwd: str
    arguments: tuple[str, ...]
    expected_exit: int = 0
    expect_json: bool = True


@dataclass(frozen=True)
class RawArgvCase:
    name: str
    path_bytes_hex: str


def scan_case(name: str, path: str) -> Case:
    return Case(name, "/work", ("--json", *DATABASE_ARGS, path))


CASES = (
    scan_case("single_nfc", "paths/special/é-nfc.pdf"),
    scan_case("single_nfd", "paths/special/e\u0301-nfd.pdf"),
    scan_case("single_cjk", "paths/special/中文.pdf"),
    scan_case("single_emoji", "paths/special/emoji-😀.pdf"),
    scan_case("single_space", "paths/special/space name.pdf"),
    scan_case("single_leading_space", "paths/special/ leading-space.pdf"),
    scan_case("single_trailing_space", "paths/special/trailing-space.pdf "),
    scan_case("single_tab", "paths/special/tab\tname.pdf"),
    scan_case("single_newline", "paths/special/line\nbreak.pdf"),
    scan_case("single_colon", "paths/special/colon:name.pdf"),
    scan_case("single_backslash", "paths/special/backslash\\name.pdf"),
    scan_case("single_hidden", "paths/special/.hidden.pdf"),
    scan_case(
        "single_leading_dash_absolute",
        "/work/paths/special/--leading-dash.pdf",
    ),
    Case(
        "single_leading_dash_relative_unescaped",
        "/work/paths/special",
        ("--json", *DATABASE_ARGS, "--leading-dash.pdf"),
        expected_exit=1,
        expect_json=False,
    ),
    Case(
        "single_leading_dash_relative_escaped",
        "/work/paths/special",
        ("--json", *DATABASE_ARGS, "--", "--leading-dash.pdf"),
    ),
    Case(
        "directory_special",
        "/work",
        ("--json", *DATABASE_ARGS, "/work/paths/special"),
        expect_json=False,
    ),
    scan_case("directory_unicode", "/work/paths/目录 空格"),
    scan_case(
        "single_non_utf8_control",
        "/work/paths/nonutf8/ascii-control.pdf",
    ),
    Case(
        "directory_non_utf8",
        "/work",
        ("--json", *DATABASE_ARGS, "/work/paths/nonutf8"),
        expect_json=False,
    ),
    Case(
        "explicit_order",
        "/work",
        (
            "--json",
            *DATABASE_ARGS,
            "paths/special/emoji-😀.pdf",
            "paths/special/é-nfc.pdf",
            "paths/special/00-ascii.pdf",
        ),
        expect_json=False,
    ),
)

RAW_ARGV_CASES = (
    RawArgvCase(
        "explicit_non_utf8_ff",
        "70617468732f6e6f6e757466382f696e76616c69642d66662dff2e706466",
    ),
    RawArgvCase(
        "explicit_non_utf8_c0af",
        "70617468732f6e6f6e757466382f696e76616c69642d633061662dc0af2e706466",
    ),
    RawArgvCase(
        "explicit_non_utf8_truncated_e282",
        "70617468732f6e6f6e757466382f7472756e63617465642d653238322de2822e706466",
    ),
)
EXPECTED_RAW_ARGV = {
    "explicit_non_utf8_ff": {
        "replacement_character_count": 1,
        "stdout_sha256": (
            "58da8d8676a5e382e9093371147d1c2d8"
            "ec8416c57f152130d271f942eeb88e6"
        ),
    },
    "explicit_non_utf8_c0af": {
        "replacement_character_count": 2,
        "stdout_sha256": (
            "860db1ea8c00651c30ed6696e48920529"
            "8900c67b38f6a242056bc7a384c1ac3"
        ),
    },
    "explicit_non_utf8_truncated_e282": {
        "replacement_character_count": 2,
        "stdout_sha256": (
            "818700a7b873a54c3dbbdb28c2becc3"
            "e03244f9fad2a2334c3da0027f1906401"
        ),
    },
}


class ProbeError(ValueError):
    """The fixture, pinned oracle, or observed path behavior is invalid."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProbeError(f"non-finite JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError(f"invalid JSON: {error}") from error


def load_fixture(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
) -> tuple[dict[str, Any], bytes]:
    raw = manifest_path.read_bytes()
    manifest = strict_json(raw)
    expected_fields = {
        "archive",
        "directories",
        "files",
        "generator",
        "license",
        "payload",
        "raw_control_file",
        "raw_files",
        "schema_version",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_fields:
        raise ProbeError("fixture manifest fields changed")
    if manifest["schema_version"] != 1:
        raise ProbeError("unsupported fixture manifest schema")
    if manifest["generator"] != FIXTURE_GENERATOR:
        raise ProbeError("unexpected fixture generator")
    archive_record = manifest["archive"]
    if (
        not isinstance(archive_record, dict)
        or set(archive_record)
        != {"format", "name", "sha256", "size"}
        or archive_record["format"] != "ustar"
        or archive_record["name"] != ARCHIVE_NAME
    ):
        raise ProbeError("fixture archive identity changed")
    archive_path = fixture_dir / ARCHIVE_NAME
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ProbeError("fixture archive is missing or symlinked")
    archive = archive_path.read_bytes()
    if (
        len(archive) != archive_record["size"]
        or sha256(archive) != archive_record["sha256"]
    ):
        raise ProbeError("fixture archive bytes changed")

    paths = [entry.get("path") for entry in manifest["files"]]
    if (
        len(paths) != 17
        or len(paths) != len(set(paths))
        or any(not isinstance(path, str) for path in paths)
    ):
        raise ProbeError("fixture path inventory changed")
    required = {
        "paths/special/é-nfc.pdf",
        "paths/special/e\u0301-nfd.pdf",
        "paths/special/中文.pdf",
        "paths/special/emoji-😀.pdf",
        "paths/special/tab\tname.pdf",
        "paths/special/line\nbreak.pdf",
        "paths/special/backslash\\name.pdf",
        "paths/special/.hidden.pdf",
    }
    if not required.issubset(set(paths)):
        raise ProbeError("fixture special-path matrix changed")
    raw_control = manifest["raw_control_file"]
    if (
        not isinstance(raw_control, dict)
        or raw_control.get("path")
        != "paths/nonutf8/ascii-control.pdf"
    ):
        raise ProbeError("raw-path control changed")
    raw_files = manifest["raw_files"]
    if not isinstance(raw_files, list) or len(raw_files) != 3:
        raise ProbeError("raw-path matrix changed")
    raw_paths = []
    for record in raw_files:
        if not isinstance(record, dict) or set(record) != {
            "path_bytes_hex",
            "purpose",
            "sha256",
            "size",
            "source",
        }:
            raise ProbeError("raw-path record fields changed")
        try:
            path_bytes = bytes.fromhex(record["path_bytes_hex"])
        except (TypeError, ValueError) as error:
            raise ProbeError("invalid raw-path hex") from error
        try:
            path_bytes.decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            raise ProbeError("raw-path record is valid UTF-8")
        if (
            not path_bytes.startswith(b"paths/nonutf8/")
            or not path_bytes.endswith(b".pdf")
        ):
            raise ProbeError("raw path escaped fixture directory")
        raw_paths.append(path_bytes)
    if len(raw_paths) != len(set(raw_paths)):
        raise ProbeError("duplicate raw path")
    if {path.hex() for path in raw_paths} != {
        case.path_bytes_hex for case in RAW_ARGV_CASES
    }:
        raise ProbeError("raw argv and fixture matrices differ")
    return manifest, raw


def inspect_image(name: str, image: str) -> dict[str, Any]:
    process = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True,
        capture_output=True,
    )
    documents = strict_json(process.stdout)
    if not isinstance(documents, list) or len(documents) != 1:
        raise ProbeError(f"unexpected image inspection shape: {name}")
    document = documents[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision",
        "",
    )
    if revision != UPSTREAM_COMMIT:
        raise ProbeError(f"oracle revision changed: {name}")
    return {
        "binary": ORACLES[name]["binary"],
        "id": document["Id"],
        "image": image,
        "repo_digests": sorted(document.get("RepoDigests") or []),
        "revision": revision,
    }


def read_container_files(
    image: str, paths: tuple[str, ...]
) -> dict[str, bytes]:
    script = (
        "import base64,json,pathlib;"
        f"paths={paths!r};"
        "print(json.dumps({p:base64.b64encode("
        "pathlib.Path(p).read_bytes()).decode('ascii') for p in paths},"
        "sort_keys=True))"
    )
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            image,
            "python3",
            "-c",
            script,
        ],
        check=True,
        capture_output=True,
    )
    encoded = strict_json(process.stdout)
    if not isinstance(encoded, dict) or set(encoded) != set(paths):
        raise ProbeError("container file inventory changed")
    return {
        path: base64.b64decode(value, validate=True)
        for path, value in encoded.items()
    }


def run_case(
    *,
    image: str,
    binary: str,
    archive_path: pathlib.Path,
    case: Case,
) -> tuple[subprocess.CompletedProcess[bytes], int]:
    script = (
        "tar -xf /fixture/special-path-fixture.tar -C /work"
        ' && cd "$1" && shift && binary="$1" && shift'
        ' && exec "$binary" "$@"'
    )
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cpus",
        "1",
        "--memory",
        "512m",
        "--pids-limit",
        "128",
        "--read-only",
        "--tmpfs",
        "/work:rw,noexec,nosuid,nodev,size=16m",
        "--mount",
        (
            f"type=bind,src={archive_path.parent},"
            "dst=/fixture,readonly"
        ),
        image,
        "sh",
        "-c",
        script,
        "sh",
        case.cwd,
        binary,
        *case.arguments,
    ]
    started = time.monotonic()
    process = subprocess.run(
        command,
        capture_output=True,
        timeout=60,
        check=False,
    )
    return process, round((time.monotonic() - started) * 1000)


def inspect_extracted_raw_paths(
    *,
    image: str,
    archive_path: pathlib.Path,
) -> list[str]:
    script = (
        "import json,os;"
        "print(json.dumps(sorted("
        "name.hex() for name in "
        "os.listdir(b'/work/paths/nonutf8'))))"
    )
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cpus",
            "1",
            "--memory",
            "512m",
            "--pids-limit",
            "128",
            "--read-only",
            "--tmpfs",
            "/work:rw,noexec,nosuid,nodev,size=16m",
            "--mount",
            (
                f"type=bind,src={archive_path.parent},"
                "dst=/fixture,readonly"
            ),
            image,
            "sh",
            "-c",
            (
                "tar -xf /fixture/special-path-fixture.tar -C /work"
                ' && exec python3 -c "$1"'
            ),
            "sh",
            script,
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if process.returncode != 0 or process.stderr:
        raise ProbeError("raw-path extraction preflight failed")
    result = strict_json(process.stdout)
    if (
        not isinstance(result, list)
        or any(not isinstance(value, str) for value in result)
    ):
        raise ProbeError("raw-path extraction inventory changed shape")
    return result


def run_raw_argv_case(
    *,
    image: str,
    binary: str,
    archive_path: pathlib.Path,
    case: RawArgvCase,
) -> tuple[subprocess.CompletedProcess[bytes], int]:
    python = (
        "import os,sys;"
        "binary=sys.argv[1].encode('ascii');"
        "path=b'/work/'+bytes.fromhex(sys.argv[2]);"
        f"args=[binary]+[value.encode('ascii') for value in "
        f"{('--json', *DATABASE_ARGS)!r}]+[path];"
        "os.chdir(b'/work');"
        "os.execve(binary,args,os.environb)"
    )
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cpus",
        "1",
        "--memory",
        "512m",
        "--pids-limit",
        "128",
        "--read-only",
        "--tmpfs",
        "/work:rw,noexec,nosuid,nodev,size=16m",
        "--mount",
        (
            f"type=bind,src={archive_path.parent},"
            "dst=/fixture,readonly"
        ),
        image,
        "sh",
        "-c",
        (
            "tar -xf /fixture/special-path-fixture.tar -C /work"
            ' && exec python3 -c "$1" "$2" "$3"'
        ),
        "sh",
        python,
        binary,
        case.path_bytes_hex,
    ]
    started = time.monotonic()
    process = subprocess.run(
        command,
        capture_output=True,
        timeout=60,
        check=False,
    )
    return process, round((time.monotonic() - started) * 1000)


def validate_pdf_document(data: bytes) -> None:
    document = strict_json(data)
    if not isinstance(document, dict) or set(document) != {"detects"}:
        raise ProbeError("unexpected scan JSON root")
    detects = document["detects"]
    if not isinstance(detects, list) or len(detects) != 1:
        raise ProbeError("expected one PDF root")
    root = detects[0]
    if root.get("filetype") != "PDF":
        raise ProbeError("special-path sample did not scan as PDF")
    values = root.get("values")
    names = [
        value.get("name")
        for value in values
        if isinstance(value, dict)
    ]
    if names != ["PDF", "HeaderComment"]:
        raise ProbeError("PDF detection list changed")


def path_order(stdout: bytes, candidates: list[str]) -> list[str]:
    located: list[tuple[int, str]] = []
    for path in candidates:
        marker = f"/work/{path}:\n".encode("utf-8")
        count = stdout.count(marker)
        if count > 1:
            raise ProbeError(f"duplicate filename prefix: {path!r}")
        if count == 1:
            located.append((stdout.index(marker), path))
    return [path for _, path in sorted(located)]


def raw_ref(
    data: bytes,
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    digest = sha256(data)
    compressed = zlib.compress(data, 9)
    artifact = {
        "base64": base64.b64encode(compressed).decode("ascii"),
        "bytes": len(data),
        "compressed_bytes": len(compressed),
        "encoding": "zlib+base64",
    }
    previous = artifacts.setdefault(digest, artifact)
    if previous != artifact:
        raise ProbeError("raw artifact digest collision")
    return {
        "artifact_sha256": digest,
        "bytes": len(data),
        "sha256": digest,
    }


def source_contract(files: dict[str, bytes]) -> dict[str, Any]:
    result = {}
    for name, path in SOURCE_PATHS.items():
        text = files[path].decode("utf-8")
        patterns = {}
        for pattern in SOURCE_PATTERNS[name]:
            count = text.count(pattern)
            if count < 1:
                raise ProbeError(f"source pattern missing: {name}")
            patterns[pattern] = count
        result[name] = {
            "path": path,
            "required_patterns": patterns,
            "sha256": sha256(files[path]),
        }
    return result


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
) -> dict[str, Any]:
    manifest, manifest_raw = load_fixture(fixture_dir, manifest_path)
    archive_path = fixture_dir / ARCHIVE_NAME
    artifacts: dict[str, dict[str, Any]] = {}
    image_records = {
        name: inspect_image(name, oracle["image"])
        for name, oracle in ORACLES.items()
    }
    cmake_files = read_container_files(
        ORACLES["cmake"]["image"],
        (
            ORACLES["cmake"]["binary"],
            *SOURCE_PATHS.values(),
        ),
    )
    qmake_files = read_container_files(
        ORACLES["qmake"]["image"],
        (ORACLES["qmake"]["binary"],),
    )
    expected_raw_basenames = sorted(
        pathlib.PurePosixPath(
            bytes.fromhex(record["path_bytes_hex"]).decode(
                "utf-8", "surrogateescape"
            )
        )
        .name.encode("utf-8", "surrogateescape")
        .hex()
        for record in manifest["raw_files"]
    )
    expected_extracted = sorted(
        [
            pathlib.PurePosixPath(
                manifest["raw_control_file"]["path"]
            ).name.encode("utf-8").hex(),
            *expected_raw_basenames,
        ]
    )
    extracted_raw_paths = inspect_extracted_raw_paths(
        image=ORACLES["cmake"]["image"],
        archive_path=archive_path,
    )
    if extracted_raw_paths != expected_extracted:
        raise ProbeError("raw-path extraction inventory changed")

    fixture_paths = [entry["path"] for entry in manifest["files"]]
    fixture_paths.append(manifest["raw_control_file"]["path"])
    special_paths = [
        path for path in fixture_paths if path.startswith("paths/special/")
    ]
    non_hidden_special_paths = [
        path
        for path in special_paths
        if not pathlib.PurePosixPath(path).name.startswith(".")
    ]
    cases: dict[str, Any] = {}
    raw_by_case: dict[str, tuple[bytes, bytes, int]] = {}
    for case in CASES:
        observations = {}
        for oracle_name, oracle in ORACLES.items():
            process, elapsed_ms = run_case(
                image=oracle["image"],
                binary=oracle["binary"],
                archive_path=archive_path,
                case=case,
            )
            if process.returncode != case.expected_exit:
                raise ProbeError(
                    f"exit changed: {case.name}/{oracle_name}: "
                    f"{process.returncode}"
                )
            if (
                process.stderr
                and case.name
                != "single_leading_dash_relative_unescaped"
            ):
                raise ProbeError(
                    f"stderr changed: {case.name}/{oracle_name}"
                )
            if case.expect_json:
                validate_pdf_document(process.stdout)
            observations[oracle_name] = {
                "exit_code": process.returncode,
                "stderr": raw_ref(process.stderr, artifacts),
                "stdout": raw_ref(process.stdout, artifacts),
                "wall_elapsed_ms": elapsed_ms,
            }
            raw = (
                process.stdout,
                process.stderr,
                process.returncode,
            )
            previous = raw_by_case.setdefault(case.name, raw)
            if previous != raw:
                raise ProbeError(f"qmake/CMake drift: {case.name}")

        stdout = raw_by_case[case.name][0]
        order = path_order(stdout, fixture_paths)
        if case.name == "directory_special":
            if set(order) != set(non_hidden_special_paths):
                raise ProbeError(
                    "directory enumeration inventory changed"
                )
            if order != list(EXPECTED_DIRECTORY_ORDER):
                raise ProbeError("directory enumeration order changed")
        elif case.name == "directory_unicode":
            # The expanded file count is one, so the CLI deliberately omits
            # its filename prefix and emits one valid JSON document.
            if order:
                raise ProbeError("Unicode single-file directory gained prefix")
        elif case.name == "directory_non_utf8":
            pass
        elif case.name == "explicit_order":
            expected = [
                "paths/special/emoji-😀.pdf",
                "paths/special/é-nfc.pdf",
                "paths/special/00-ascii.pdf",
            ]
            if order != expected:
                raise ProbeError("explicit target order changed")
        elif order:
            raise ProbeError(
                f"single-target case gained filename prefix: {case.name}"
            )

        cases[case.name] = {
            "arguments": list(case.arguments),
            "cwd": case.cwd,
            "expected_exit": case.expected_exit,
            "expect_json": case.expect_json,
            "filename_prefix_order": order,
            "observations": observations,
        }
        if case.name == "directory_non_utf8":
            cases[case.name]["raw_path_summary"] = {
                "ascii_control_prefix_present": (
                    b"/work/paths/nonutf8/ascii-control.pdf:\n"
                    in stdout
                ),
                "pdf_root_count": (
                    stdout.count(b'"filetype":"PDF"')
                    + stdout.count(b'"filetype": "PDF"')
                ),
                "replacement_character_count": stdout.count(
                    b"\xef\xbf\xbd"
                ),
                "stdout_utf8_valid": True,
            }
            try:
                stdout.decode("utf-8")
            except UnicodeDecodeError:
                cases[case.name]["raw_path_summary"][
                    "stdout_utf8_valid"
                ] = False

    raw_argv_observations: dict[
        str, tuple[bytes, bytes, int]
    ] = {}
    for case in RAW_ARGV_CASES:
        observations = {}
        for oracle_name, oracle in ORACLES.items():
            process, elapsed_ms = run_raw_argv_case(
                image=oracle["image"],
                binary=oracle["binary"],
                archive_path=archive_path,
                case=case,
            )
            if process.stderr:
                raise ProbeError(
                    f"raw argv stderr changed: {case.name}/{oracle_name}"
                )
            if process.returncode != 1:
                raise ProbeError(
                    f"raw argv exit changed: {case.name}/{oracle_name}"
                )
            raw = (
                process.stdout,
                process.stderr,
                process.returncode,
            )
            previous = raw_argv_observations.setdefault(case.name, raw)
            if previous != raw:
                raise ProbeError(f"raw argv qmake/CMake drift: {case.name}")
            observations[oracle_name] = {
                "exit_code": process.returncode,
                "stderr": raw_ref(process.stderr, artifacts),
                "stdout": raw_ref(process.stdout, artifacts),
                "wall_elapsed_ms": elapsed_ms,
            }
        stdout = raw_argv_observations[case.name][0]
        try:
            stdout.decode("utf-8")
            stdout_utf8_valid = True
        except UnicodeDecodeError:
            stdout_utf8_valid = False
        summary = {
            "cannot_find_count": stdout.count(b"Cannot find:"),
            "pdf_root_count": (
                stdout.count(b'"filetype":"PDF"')
                + stdout.count(b'"filetype": "PDF"')
            ),
            "replacement_character_count": stdout.count(
                b"\xef\xbf\xbd"
            ),
            "stdout_utf8_valid": stdout_utf8_valid,
        }
        expected = EXPECTED_RAW_ARGV[case.name]
        if summary != {
            "cannot_find_count": 1,
            "pdf_root_count": 0,
            "replacement_character_count": expected[
                "replacement_character_count"
            ],
            "stdout_utf8_valid": True,
        }:
            raise ProbeError(f"raw argv summary changed: {case.name}")
        if sha256(stdout) != expected["stdout_sha256"]:
            raise ProbeError(f"raw argv diagnostic changed: {case.name}")
        cases[case.name] = {
            "observations": observations,
            "path_bytes_hex": case.path_bytes_hex,
            "raw_argv_summary": summary,
        }

    unescaped_raw = raw_by_case[
        "single_leading_dash_relative_unescaped"
    ]
    if (
        b"Unknown option 'leading-dash.pdf'."
        not in unescaped_raw[0] + unescaped_raw[1]
    ):
        raise ProbeError("leading-dash option diagnostic changed")
    raw_directory = raw_by_case["directory_non_utf8"]
    raw_control = raw_by_case["single_non_utf8_control"]
    if raw_directory != raw_control:
        raise ProbeError(
            "non-UTF-8 directory result differs from ASCII control"
        )
    raw_summary = cases["directory_non_utf8"]["raw_path_summary"]
    if raw_summary != {
        "ascii_control_prefix_present": False,
        "pdf_root_count": 1,
        "replacement_character_count": 0,
        "stdout_utf8_valid": True,
    }:
        raise ProbeError("non-UTF-8 directory summary changed")

    facts = {
        "all_utf8_single_file_paths_scan_as_pdf": True,
        "nfc_and_nfd_are_distinct_paths": True,
        "non_utf8_entries_are_present_before_scan": True,
        "non_utf8_entries_are_skipped_by_directory_enumeration": True,
        "non_utf8_explicit_argv_becomes_replacement_and_cannot_find": True,
        "directory_enumeration_excludes_hidden_entries": True,
        "explicit_hidden_path_is_scannable": True,
        "directory_enumeration_order_is_recorded": True,
        "explicit_multiple_targets_preserve_argument_order": True,
        "absolute_leading_dash_path_is_scannable": True,
        "relative_leading_dash_requires_option_terminator": True,
        "qmake_and_cmake_outputs_are_byte_equal": True,
    }
    root = pathlib.Path(__file__).resolve().parents[2]
    return {
        "binaries": {
            "cmake": {
                "path": ORACLES["cmake"]["binary"],
                "sha256": sha256(
                    cmake_files[ORACLES["cmake"]["binary"]]
                ),
                "size": len(
                    cmake_files[ORACLES["cmake"]["binary"]]
                ),
            },
            "qmake": {
                "path": ORACLES["qmake"]["binary"],
                "sha256": sha256(
                    qmake_files[ORACLES["qmake"]["binary"]]
                ),
                "size": len(
                    qmake_files[ORACLES["qmake"]["binary"]]
                ),
            },
        },
        "cases": cases,
        "facts": facts,
        "failures": [],
        "fixture": {
            "archive_sha256": manifest["archive"]["sha256"],
            "archive_size": manifest["archive"]["size"],
            "file_count": (
                len(manifest["files"])
                + 1
                + len(manifest["raw_files"])
            ),
            "manifest_path": FIXTURE_MANIFEST,
            "manifest_sha256": sha256(manifest_raw),
            "non_utf8_extracted_basename_hex": extracted_raw_paths,
        },
        "generator": "tools/upstream/probe_special_path_behavior.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "images": image_records,
        "local_sources": {
            "baseline_generator": {
                "path": "tools/corpus/generate_baseline_corpus.py",
                "sha256": sha256(
                    (
                        root
                        / "tools"
                        / "corpus"
                        / "generate_baseline_corpus.py"
                    ).read_bytes()
                ),
            },
            "fixture_generator": {
                "path": FIXTURE_GENERATOR,
                "sha256": sha256(
                    (root / FIXTURE_GENERATOR).read_bytes()
                ),
            },
        },
        "passed": all(facts.values()),
        "platform": "linux-x86_64-qt5",
        "raw_artifacts": artifacts,
        "remaining_gap": (
            "CAP-GAP-003: non-UTF-8, symlink/permission/depth, "
            "Windows, and macOS behavior"
        ),
        "resource_limits": {
            "container_root": "read-only",
            "cpus": 1,
            "fixture_mount": "read-only",
            "memory_bytes": 512 * 1024 * 1024,
            "network": "none",
            "pids": 128,
            "timeout_seconds_per_execution": 60,
            "work_tmpfs_bytes": 16 * 1024 * 1024,
        },
        "schema_version": 1,
        "source_contract": source_contract(cmake_files),
        "upstream_commit": UPSTREAM_COMMIT,
    }


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", required=True, type=pathlib.Path)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=root / FIXTURE_MANIFEST,
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    report = build_report(
        args.fixture_dir.resolve(),
        args.manifest.resolve(),
    )
    args.output.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

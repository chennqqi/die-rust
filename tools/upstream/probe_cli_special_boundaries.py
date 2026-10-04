#!/usr/bin/env python3
"""Probe pinned CLI entropy, struct, and multi-target boundaries."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import pathlib
import re
import subprocess
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
GENERATOR = "tools/upstream/probe_cli_special_boundaries.py"
FIXTURE_GENERATOR = (
    "tools/corpus/generate_cli_special_boundary_fixture.py"
)
FIXTURE_MANIFEST = (
    "docs/research/data/cli-special-boundary-fixture.json"
)
DATABASE_ARGS = (
    "--database",
    "/opt/die-source/Detect-It-Easy/db",
    "--extradatabase",
    "/opt/die-source/Detect-It-Easy/db_extra",
    "--customdatabase",
    "/opt/die-source/Detect-It-Easy/db_custom",
)
SOURCE_PATHS = (
    "/opt/die-source/src/console/main_console.cpp",
    "/opt/die-source/XEntropyWidget/entropyprocess.cpp",
    "/opt/die-source/Formats/xbinary.cpp",
    "/opt/die-source/Formats/xbinary.h",
    "/opt/die-source/XFileInfo/xfileinfo.cpp",
)


@dataclass(frozen=True)
class Oracle:
    name: str
    image: str
    binary: str


@dataclass(frozen=True)
class Case:
    name: str
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class Observation:
    exit_code: int
    stdout: bytes
    stderr: bytes


ORACLES = (
    Oracle(
        "qmake",
        "die-rust/upstream-oracle:74eaf505-repro",
        "/opt/die-source/build/release/diec",
    ),
    Oracle(
        "cmake",
        "die-rust/upstream-oracle-cmake:74eaf505",
        "/opt/die-build/src/console/diec",
    ),
)

BELOW = "/fixture/entropy-below-6_5.bin"
EXACT = "/fixture/entropy-exact-6_5.bin"
ABOVE = "/fixture/entropy-above-6_5.bin"
PE32 = "/fixture/minimal-pe32.exe"
ELF64 = "/fixture/minimal-elf64.elf"
MACHO64 = "/fixture/minimal-macho64.macho"
DEX = "/fixture/minimal.dex"


def arguments(*options: str, targets: tuple[str, ...]) -> tuple[str, ...]:
    return (*options, *DATABASE_ARGS, *targets)


CASES = (
    Case(
        "entropy_below_json",
        arguments("--entropy", "--json", targets=(BELOW,)),
    ),
    Case(
        "entropy_exact_json",
        arguments("--entropy", "--json", targets=(EXACT,)),
    ),
    Case(
        "entropy_above_json",
        arguments("--entropy", "--json", targets=(ABOVE,)),
    ),
    Case(
        "entropy_exact_text",
        arguments("--entropy", targets=(EXACT,)),
    ),
    Case(
        "struct_entropy_json",
        arguments("--struct", "Entropy", "--json", targets=(EXACT,)),
    ),
    Case(
        "struct_check_format_json",
        arguments(
            "--struct",
            "Check format",
            "--json",
            targets=(EXACT,),
        ),
    ),
    Case(
        "struct_hash_md5_casefold_json",
        arguments("--struct", "hAsH#mD5", "--json", targets=(EXACT,)),
    ),
    Case(
        "struct_hash_md5_trailing_json",
        arguments(
            "--struct",
            "Hash#MD5#Ignored",
            "--json",
            targets=(EXACT,),
        ),
    ),
    Case(
        "struct_hash_unknown_child_json",
        arguments(
            "--struct",
            "Hash#NoSuch",
            "--json",
            targets=(EXACT,),
        ),
    ),
    Case(
        "struct_hash_empty_segment_json",
        arguments("--struct", "Hash##MD5", "--json", targets=(EXACT,)),
    ),
    Case(
        "struct_unknown_nested_json",
        arguments(
            "--struct",
            "NoSuch#MD5",
            "--json",
            targets=(EXACT,),
        ),
    ),
    Case(
        "struct_empty_json",
        arguments("--struct", "", "--json", targets=(EXACT,)),
    ),
    Case(
        "info_struct_empty_json",
        arguments(
            "--info",
            "--struct",
            "",
            "--json",
            targets=(EXACT,),
        ),
    ),
    Case(
        "entropy_over_struct_json",
        arguments(
            "--entropy",
            "--struct",
            "Hash#MD5",
            "--json",
            targets=(EXACT,),
        ),
    ),
    Case(
        "entropy_two_json",
        arguments("--entropy", "--json", targets=(BELOW, ABOVE)),
    ),
    Case(
        "info_two_json",
        arguments("--info", "--json", targets=(BELOW, ABOVE)),
    ),
    Case(
        "struct_hash_md5_two_json",
        arguments(
            "--struct",
            "Hash#MD5",
            "--json",
            targets=(BELOW, ABOVE),
        ),
    ),
    Case(
        "pe_entry_point_json",
        arguments("--struct", "Entry point", "--json", targets=(PE32,)),
    ),
    Case(
        "pe_dos_header_json",
        arguments(
            "--struct",
            "IMAGE_DOS_HEADER",
            "--json",
            targets=(PE32,),
        ),
    ),
    Case(
        "pe_nt_headers_json",
        arguments(
            "--struct",
            "IMAGE_NT_HEADERS",
            "--json",
            targets=(PE32,),
        ),
    ),
    Case(
        "pe_section_header_json",
        arguments(
            "--struct",
            "IMAGE_SECTION_HEADER",
            "--json",
            targets=(PE32,),
        ),
    ),
    Case(
        "pe_resource_directory_json",
        arguments(
            "--struct",
            "IMAGE_RESOURCE_DIRECTORY",
            "--json",
            targets=(PE32,),
        ),
    ),
    Case(
        "pe_export_directory_json",
        arguments(
            "--struct",
            "IMAGE_EXPORT_DIRECTORY",
            "--json",
            targets=(PE32,),
        ),
    ),
    Case(
        "elf_entry_point_json",
        arguments("--struct", "Entry point", "--json", targets=(ELF64,)),
    ),
    Case(
        "elf_ehdr_json",
        arguments("--struct", "Elf_Ehdr", "--json", targets=(ELF64,)),
    ),
    Case(
        "macho_entry_point_json",
        arguments(
            "--struct",
            "Entry point",
            "--json",
            targets=(MACHO64,),
        ),
    ),
    Case(
        "macho_header_json",
        arguments("--struct", "Header", "--json", targets=(MACHO64,)),
    ),
    Case(
        "dex_header_json",
        arguments("--struct", "Header", "--json", targets=(DEX,)),
    ),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_fixture(
    fixture_dir: pathlib.Path,
    committed_manifest: pathlib.Path,
) -> tuple[dict[str, Any], str]:
    fixture_manifest_path = fixture_dir / "manifest.json"
    fixture_bytes = fixture_manifest_path.read_bytes()
    committed_bytes = committed_manifest.read_bytes()
    if fixture_bytes != committed_bytes:
        raise ValueError("fixture manifest differs from committed manifest")
    manifest = json.loads(fixture_bytes)
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported fixture schema")
    if manifest.get("generator") != FIXTURE_GENERATOR:
        raise ValueError("unexpected fixture generator")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != 7:
        raise ValueError("unexpected fixture entry inventory")

    expected_names = {
        "entropy-below-6_5.bin",
        "entropy-exact-6_5.bin",
        "entropy-above-6_5.bin",
        "minimal-pe32.exe",
        "minimal-elf64.elf",
        "minimal-macho64.macho",
        "minimal.dex",
    }
    actual_names = set()
    for entry in entries:
        name = entry.get("name")
        if not isinstance(name, str) or pathlib.PurePath(name).name != name:
            raise ValueError("unsafe fixture entry name")
        if name in actual_names:
            raise ValueError("duplicate fixture entry")
        actual_names.add(name)
        data = (fixture_dir / name).read_bytes()
        if (
            len(data) != entry.get("size")
            or sha256(data) != entry.get("sha256")
        ):
            raise ValueError(f"fixture entry mismatch: {name}")
    if actual_names != expected_names:
        raise ValueError("fixture entry names changed")
    fixture_paths = list(fixture_dir.iterdir())
    if any(
        path.is_symlink() or not path.is_file()
        for path in fixture_paths
    ):
        raise ValueError("fixture contains a symlink or non-file")
    actual_files = {path.name for path in fixture_paths}
    if actual_files != expected_names | {"manifest.json"}:
        raise ValueError("fixture contains undeclared files")
    return manifest, sha256(fixture_bytes)


def inspect_oracle(oracle: Oracle) -> dict[str, str]:
    process = subprocess.run(
        ["docker", "image", "inspect", oracle.image],
        check=True,
        capture_output=True,
    )
    document = json.loads(process.stdout)[0]
    revision = document["Config"]["Labels"].get(
        "org.opencontainers.image.revision", ""
    )
    if revision != UPSTREAM_COMMIT:
        raise ValueError(f"{oracle.name} image revision mismatch")
    digest_process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            "/usr/bin/sha256sum",
            oracle.image,
            oracle.binary,
        ],
        check=True,
        capture_output=True,
    )
    if digest_process.stderr:
        raise ValueError(f"{oracle.name} sha256sum wrote stderr")
    return {
        "name": oracle.name,
        "image": oracle.image,
        "image_id": document["Id"],
        "revision": revision,
        "binary": oracle.binary,
        "binary_sha256": digest_process.stdout.split()[0].decode("ascii"),
    }


def observe(
    oracle: Oracle,
    case: Case,
    fixture_dir: pathlib.Path,
) -> Observation:
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--mount",
            (
                f"type=bind,source={fixture_dir},"
                "target=/fixture,readonly"
            ),
            "--entrypoint",
            oracle.binary,
            oracle.image,
            *case.arguments,
        ],
        check=False,
        capture_output=True,
    )
    return Observation(
        process.returncode,
        process.stdout,
        process.stderr,
    )


def observation_document(observation: Observation) -> dict[str, Any]:
    try:
        stdout = observation.stdout.decode("utf-8")
        stderr = observation.stderr.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("CLI output is not UTF-8") from error
    return {
        "exit_code": observation.exit_code,
        "stdout_bytes": len(observation.stdout),
        "stdout_sha256": sha256(observation.stdout),
        "stdout_utf8": stdout,
        "stderr_bytes": len(observation.stderr),
        "stderr_sha256": sha256(observation.stderr),
        "stderr_utf8": stderr,
    }


def parse_json(observation: Observation) -> Any:
    return json.loads(observation.stdout)


def entropy_result(observation: Observation) -> tuple[float, str]:
    document = parse_json(observation)
    records = document.get("records")
    if not isinstance(records, list) or len(records) != 1:
        raise ValueError("unexpected entropy record inventory")
    record = records[0]
    if (
        record.get("name") != "Data"
        or record.get("offset") != 0
        or record.get("size") != 128
        or record.get("entropy") != document.get("total")
        or record.get("status") != document.get("status")
    ):
        raise ValueError("entropy record fields changed")
    return document["total"], document["status"]


def is_json_document(data: bytes) -> bool:
    try:
        json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return True


def validate(
    observations: dict[str, Observation],
) -> dict[str, Any]:
    if set(observations) != {case.name for case in CASES}:
        raise ValueError("special boundary case inventory changed")
    for name, observation in observations.items():
        if observation.exit_code != 0:
            raise ValueError(f"{name} exit code changed")
        if observation.stderr:
            raise ValueError(f"{name} wrote stderr")

    totals = {}
    statuses = {}
    for position in ("below", "exact", "above"):
        total, status = entropy_result(
            observations[f"entropy_{position}_json"]
        )
        totals[position] = total
        statuses[position] = status
    expected_totals = {
        "below": 6.484374999999999,
        "exact": 6.499999999999999,
        "above": 6.515624999999999,
    }
    if totals != expected_totals:
        raise ValueError("entropy floating boundary changed")
    if statuses != {
        "below": "not packed",
        "exact": "not packed",
        "above": "packed",
    }:
        raise ValueError("entropy packed boundary changed")

    if observations["entropy_exact_text"].stdout != (
        b"Total 6.5: not packed\n"
        b"  0|Data|0|128|6.5: not packed\n"
    ):
        raise ValueError("entropy text rounding changed")

    expected_md5 = "5c5ae785c5c84f0629700c10e6904677"
    casefold = parse_json(
        observations["struct_hash_md5_casefold_json"]
    )
    trailing = parse_json(
        observations["struct_hash_md5_trailing_json"]
    )
    expected_hash = {"data": {"Hash": {"MD5": expected_md5}}}
    if casefold != expected_hash or trailing != expected_hash:
        raise ValueError("struct casefold/trailing behavior changed")
    if parse_json(observations["struct_entropy_json"]) != {
        "data": {"Entropy": "6.5"}
    }:
        raise ValueError("struct entropy formatting changed")
    if parse_json(observations["struct_check_format_json"]) != {
        "data": ""
    }:
        raise ValueError("struct Check format behavior changed")
    if parse_json(
        observations["struct_hash_unknown_child_json"]
    ) != {"data": {"Hash": ""}}:
        raise ValueError("unknown struct child behavior changed")
    if parse_json(
        observations["struct_hash_empty_segment_json"]
    ) != {"data": {"Hash": ""}}:
        raise ValueError("empty struct segment behavior changed")
    if parse_json(observations["struct_unknown_nested_json"]) != {
        "data": ""
    }:
        raise ValueError("unknown nested struct behavior changed")

    empty_struct = parse_json(observations["struct_empty_json"])
    if empty_struct.get("detects", [{}])[0].get("values", [{}])[0].get(
        "name"
    ) != "Unknown":
        raise ValueError("empty --struct no longer falls back to scan")
    info_empty = parse_json(observations["info_struct_empty_json"])
    if "Info" not in info_empty.get("data", {}):
        raise ValueError("--info plus empty --struct no longer selects info")
    if parse_json(observations["entropy_over_struct_json"]) != parse_json(
        observations["entropy_exact_json"]
    ):
        raise ValueError("entropy precedence over struct changed")

    multi_target = {}
    for name in (
        "entropy_two_json",
        "info_two_json",
        "struct_hash_md5_two_json",
    ):
        data = observations[name].stdout
        prefixes = [
            line
            for line in data.decode("utf-8").splitlines()
            if line.startswith("/fixture/") and line.endswith(":")
        ]
        if prefixes != [f"{BELOW}:", f"{ABOVE}:"]:
            raise ValueError(f"{name} target prefix order changed")
        if is_json_document(data):
            raise ValueError(f"{name} unexpectedly became one JSON document")
        multi_target[name] = {
            "filename_prefixes": prefixes,
            "valid_single_json_document": False,
        }

    format_expectations = {
        "pe_entry_point_json": (
            "Entry point",
            "Address",
            "00400000",
        ),
        "pe_dos_header_json": (
            "IMAGE_DOS_HEADER",
            "e_magic",
            "5a4d",
        ),
        "pe_nt_headers_json": (
            "IMAGE_NT_HEADERS",
            "Signature",
            "4550",
        ),
        "elf_entry_point_json": (
            "Entry point",
            "Offset",
            "ffffffffffffffff",
        ),
        "elf_ehdr_json": (
            "Elf_Ehdr",
            "machine",
            "003e",
        ),
        "macho_entry_point_json": (
            "Entry point",
            "Address",
            "ffffffffffffffff",
        ),
        "macho_header_json": (
            "Header",
            "magic",
            "feedfacf",
        ),
        "dex_header_json": (
            "Header",
            "file_size",
            "00000070",
        ),
    }
    format_struct_methods = {}
    for name, (root, field, expected) in format_expectations.items():
        document = parse_json(observations[name])
        value = document.get("data", {}).get(root, {}).get(field)
        if value != expected:
            raise ValueError(f"{name} format struct fields changed")
        format_struct_methods[name] = {
            "root": root,
            "sentinel_field": field,
            "sentinel_value": value,
        }
    empty_format_methods = (
        "pe_section_header_json",
        "pe_resource_directory_json",
        "pe_export_directory_json",
    )
    for name in empty_format_methods:
        if parse_json(observations[name]) != {"data": ""}:
            raise ValueError(f"{name} empty method behavior changed")
        format_struct_methods[name] = {
            "root": None,
            "empty_data": True,
        }

    return {
        "runtime_entropy_totals": totals,
        "runtime_entropy_statuses": statuses,
        "theoretical_6_5_rounds_below_threshold": (
            totals["exact"] < 6.5
            and statuses["exact"] == "not packed"
        ),
        "text_rounds_exact_case_to_6_5_but_status_is_not_packed": True,
        "struct_filter_is_case_insensitive": casefold == expected_hash,
        "struct_trailing_segments_are_ignored": trailing == expected_hash,
        "empty_struct_value_falls_back_to_normal_scan": True,
        "entropy_precedes_struct": True,
        "multi_target_structured_outputs": multi_target,
        "format_struct_methods": format_struct_methods,
    }


def docker_bytes(entrypoint: str, *arguments_: str) -> bytes:
    oracle = ORACLES[1]
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint",
            entrypoint,
            oracle.image,
            *arguments_,
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError(f"{entrypoint} wrote stderr")
    return process.stdout


def audit_sources() -> dict[str, Any]:
    sources = {
        path: docker_bytes("/bin/cat", path) for path in SOURCE_PATHS
    }
    console = sources[SOURCE_PATHS[0]].decode("utf-8")
    entropy = sources[SOURCE_PATHS[1]].decode("utf-8")
    binary = sources[SOURCE_PATHS[2]].decode("utf-8")
    binary_header = sources[SOURCE_PATHS[3]].decode("utf-8")
    file_info = sources[SOURCE_PATHS[4]].decode("utf-8")

    assumptions = {
        "cli_precedence_entropy_before_info_or_struct": (
            console.find("if (pScanOptions->bShowEntropy)")
            < console.find(
                "} else if ((pScanOptions->bShowFileInfo) || "
                '(pScanOptions->sSpecial != "")) {'
            )
            and console.find("if (pScanOptions->bShowEntropy)") >= 0
        ),
        "entropy_threshold_is_6_5": (
            "const double XBinary::D_ENTROPY_THRESHOLD = 6.5;"
            in binary
            and "static const double D_ENTROPY_THRESHOLD;"
            in binary_header
        ),
        "packed_comparison_is_greater_or_equal": bool(
            re.search(
                r"bool XBinary::isPacked\(double dEntropy\).*?"
                r"return \(dEntropy >= D_ENTROPY_THRESHOLD\);",
                binary,
                re.DOTALL,
            )
        ),
        "entropy_uses_log_accumulation": (
            "dResult += -p * (log(p) * invLog2);" in binary
        ),
        "entropy_process_uses_binary_packed_predicate": (
            "binary.isPacked(m_pData->dTotalEntropy)" in entropy
        ),
        "struct_filter_is_case_insensitive": (
            'm_options.sString.section("#", i, i).toUpper()'
            in file_info
            and 'sCurrentString.section("#", i, i).toUpper()'
            in file_info
        ),
        "struct_missing_candidate_section_is_wildcard": (
            'if ((sOptionString != _sString) && (_sString != ""))'
            in file_info
        ),
        "format_specific_method_inventory_is_declared": all(
            f'_addMethod(&listResult, "{name}")' in file_info
            for name in (
                "Entry point",
                "Elf_Ehdr",
                "IMAGE_DOS_HEADER",
                "IMAGE_NT_HEADERS",
                "IMAGE_SECTION_HEADER",
                "IMAGE_RESOURCE_DIRECTORY",
                "IMAGE_EXPORT_DIRECTORY",
                "Header",
            )
        ),
    }
    failed = [name for name, value in assumptions.items() if not value]
    if failed:
        raise ValueError(f"special mode source assumptions changed: {failed}")
    return {
        "assumptions": assumptions,
        "sources": {
            path: {"bytes": len(data), "sha256": sha256(data)}
            for path, data in sources.items()
        },
    }


def build_report(
    fixture_dir: pathlib.Path,
    manifest_path: pathlib.Path,
    raw_dir: pathlib.Path,
) -> dict[str, Any]:
    repo = pathlib.Path(__file__).resolve().parents[2]
    manifest, manifest_sha256 = load_fixture(
        fixture_dir, manifest_path
    )
    raw_dir.mkdir(parents=True, exist_ok=True)
    oracle_metadata = [inspect_oracle(oracle) for oracle in ORACLES]
    observations_by_oracle: dict[str, dict[str, Observation]] = {}
    for oracle in ORACLES:
        observations = {}
        observations_by_oracle[oracle.name] = observations
        for case in CASES:
            observation = observe(oracle, case, fixture_dir)
            observations[case.name] = observation
            (raw_dir / f"{oracle.name}-{case.name}.stdout").write_bytes(
                observation.stdout
            )
            (raw_dir / f"{oracle.name}-{case.name}.stderr").write_bytes(
                observation.stderr
            )

    canonical = observations_by_oracle[ORACLES[0].name]
    for oracle in ORACLES[1:]:
        if observations_by_oracle[oracle.name] != canonical:
            raise ValueError(f"{oracle.name} special boundary output differs")
    relationships = validate(canonical)
    source_audit = audit_sources()
    cases = {
        case.name: {
            "arguments": list(case.arguments),
            "all_oracles_equal": True,
            "canonical": observation_document(canonical[case.name]),
        }
        for case in CASES
    }
    return {
        "schema_version": 1,
        "generator": GENERATOR,
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "platform": "linux-amd64-qt5",
        "closed_corpus_gap": "CAP-GAP-001",
        "fixture": {
            "manifest_path": FIXTURE_MANIFEST,
            "manifest_sha256": manifest_sha256,
            "generator": FIXTURE_GENERATOR,
            "generator_sha256": sha256(
                (repo / FIXTURE_GENERATOR).read_bytes()
            ),
            "entries": manifest["entries"],
        },
        "oracles": oracle_metadata,
        "case_count": len(CASES),
        "cases": cases,
        "relationships": relationships,
        "source_audit": source_audit,
        "raw_artifacts": {
            "storage": "untracked external directory selected by --raw-dir",
            "stdout_and_stderr_preserved_per_oracle_and_case": True,
        },
    }


def main() -> int:
    repo = pathlib.Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=repo / FIXTURE_MANIFEST,
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

#!/usr/bin/env python3
"""Map XArchive's XUCL amalgamation to the fixed official UCL 1.03 archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import tomllib
from typing import Any


IMAGE = "die-rust/upstream-oracle-cmake:74eaf505"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
XARCHIVE_COMMIT = "0fcd4e8d3e9933baac3b12246d82ac026557ffd0"
OFFICIAL_RELEASE_PAGE = "https://www.oberhumer.com/opensource/ucl/"
OFFICIAL_ARCHIVE_URL = (
    "https://www.oberhumer.com/opensource/ucl/download/ucl-1.03.tar.gz"
)
OFFICIAL_ARCHIVE_SHA1 = "5847003d136fbbca1334dd5de10554c76c755f7c"
OFFICIAL_ARCHIVE_SHA256 = (
    "b865299ffd45d73412293369c9754b07637680e5c826915f097577cd27350348"
)
OFFICIAL_ROOT = "ucl-1.03"
PRIOR_REPORT = (
    "docs/research/data/product-source-closure-linux-qt5.json"
)
EMBEDDED_PATHS = (
    "Algos/xucldecoder.cpp",
    "Algos/xucldecoder_acc.h",
)
SHINGLE_LENGTHS = (12, 64)
TOKEN_PATTERN = re.compile(
    r"""//[^\n]*|/\*.*?\*/|"""
    r"""(?:u8|u|U|L)?"(?:\\.|[^"\\])*"|"""
    r"""(?:u8|u|U|L)?'(?:\\.|[^'\\])*'|"""
    r"""[A-Za-z_]\w*|"""
    r"""0[xX][0-9A-Fa-f]+|"""
    r"""\d+(?:\.\d+)?(?:[eEpP][+-]?\d+)?[uUlLfF]*|"""
    r""">>=|<<=|->|\+\+|--|&&|\|\||==|!=|<=|>=|<<|>>|##|\.\.\.|\S""",
    re.DOTALL,
)


def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_head(path: pathlib.Path) -> str:
    process = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    if process.stderr:
        raise ValueError(f"git rev-parse wrote stderr: {path}")
    return process.stdout.strip()


def tokenize_c(data: bytes) -> list[str]:
    text = data.decode("utf-8-sig", errors="replace")
    return [
        match.group()
        for match in TOKEN_PATTERN.finditer(text)
        if not match.group().startswith(("//", "/*"))
    ]


def read_archive(path: pathlib.Path) -> dict[str, bytes]:
    result = {}
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive.getmembers():
            pure = pathlib.PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts:
                raise ValueError(f"unsafe official archive member: {member.name}")
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError(f"cannot read official member: {member.name}")
            if member.name in result:
                raise ValueError(f"duplicate official member: {member.name}")
            result[member.name] = extracted.read()
    return result


def official_source_files(
    archive_files: dict[str, bytes],
) -> dict[str, bytes]:
    result = {}
    prefixes = (
        f"{OFFICIAL_ROOT}/src/",
        f"{OFFICIAL_ROOT}/include/",
        f"{OFFICIAL_ROOT}/acc/",
    )
    for path, data in archive_files.items():
        if not path.startswith(prefixes):
            continue
        if pathlib.PurePosixPath(path).suffix.lower() not in {
            ".c",
            ".h",
            ".ch",
        }:
            continue
        result[path.removeprefix(f"{OFFICIAL_ROOT}/")] = data
    return result


def file_record(path: str, data: bytes) -> dict[str, Any]:
    return {
        "path": path,
        "bytes": len(data),
        "sha256": sha256(data),
    }


def shingle_evidence(
    embedded_tokens: list[str],
    reference_files: dict[str, bytes],
    length: int,
) -> dict[str, Any]:
    index: dict[tuple[str, ...], set[str]] = {}
    for path, data in reference_files.items():
        tokens = tokenize_c(data)
        for position in range(len(tokens) - length + 1):
            shingle = tuple(tokens[position : position + length])
            index.setdefault(shingle, set()).add(path)

    covered = [False] * len(embedded_tokens)
    matching_window_count = 0
    unique_counts: dict[str, int] = {}
    for position in range(len(embedded_tokens) - length + 1):
        shingle = tuple(embedded_tokens[position : position + length])
        origins = index.get(shingle)
        if not origins:
            continue
        matching_window_count += 1
        for covered_position in range(position, position + length):
            covered[covered_position] = True
        if len(origins) == 1:
            origin = next(iter(origins))
            unique_counts[origin] = unique_counts.get(origin, 0) + 1

    unique_origins = [
        {
            **file_record(path, reference_files[path]),
            "unique_matching_window_count": count,
        }
        for path, count in sorted(unique_counts.items())
    ]
    covered_count = sum(covered)
    return {
        "shingle_length": length,
        "embedded_token_count": len(embedded_tokens),
        "covered_token_count": covered_count,
        "coverage": covered_count / len(embedded_tokens),
        "matching_window_count": matching_window_count,
        "unique_origin_file_count": len(unique_origins),
        "unique_origin_files": unique_origins,
    }


def line_numbers(data: bytes, needle: str) -> list[int]:
    return [
        index
        for index, line in enumerate(
            data.decode("utf-8", errors="replace").splitlines(),
            start=1,
        )
        if needle in line
    ]


def build_inside_report(
    source_root: pathlib.Path,
    lock_path: pathlib.Path,
    prior_report_path: pathlib.Path,
    archive_path: pathlib.Path,
) -> dict[str, Any]:
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    if lock["baseline"]["commit"] != UPSTREAM_COMMIT:
        raise ValueError("component lock baseline mismatch")
    if git_head(source_root) != UPSTREAM_COMMIT:
        raise ValueError("source image root commit mismatch")
    xarchive_root = source_root / "XArchive"
    if (
        lock["gitlink"]["XArchive"]["commit"] != XARCHIVE_COMMIT
        or git_head(xarchive_root) != XARCHIVE_COMMIT
    ):
        raise ValueError("XArchive commit mismatch")

    prior_bytes = prior_report_path.read_bytes()
    prior = json.loads(prior_bytes)
    if (
        prior["upstream_commit"] != UPSTREAM_COMMIT
        or not all(prior["relationships"].values())
    ):
        raise ValueError("prior product source closure drift")
    finding = prior["notable_license_findings"]
    if (
        len(finding) != 1
        or finding[0]["id"] != "PRODUCT-LICENSE-GAP-001"
        or finding[0]["source"]
        != "XArchive/Algos/xucldecoder.cpp"
    ):
        raise ValueError("prior XUCL finding drift")

    archive_bytes = archive_path.read_bytes()
    if sha1(archive_bytes) != OFFICIAL_ARCHIVE_SHA1:
        raise ValueError("official UCL archive SHA-1 mismatch")
    if sha256(archive_bytes) != OFFICIAL_ARCHIVE_SHA256:
        raise ValueError("official UCL archive SHA-256 mismatch")
    archive_files = read_archive(archive_path)
    if not archive_files:
        raise ValueError("official UCL archive is empty")
    if {
        pathlib.PurePosixPath(path).parts[0] for path in archive_files
    } != {OFFICIAL_ROOT}:
        raise ValueError("official UCL archive root drift")
    references = official_source_files(archive_files)
    if not references:
        raise ValueError("official UCL source file set is empty")

    embedded_records = []
    combined_tokens = []
    per_file_evidence = {}
    for relative in EMBEDDED_PATHS:
        path = xarchive_root / relative
        data = path.read_bytes()
        tokens = tokenize_c(data)
        combined_tokens.extend(tokens)
        embedded_records.append(file_record(relative, data))
        per_file_evidence[relative] = [
            shingle_evidence(tokens, references, length)
            for length in SHINGLE_LENGTHS
        ]
    combined_evidence = [
        shingle_evidence(combined_tokens, references, length)
        for length in SHINGLE_LENGTHS
    ]

    required_paths = (
        f"{OFFICIAL_ROOT}/README",
        f"{OFFICIAL_ROOT}/COPYING",
        f"{OFFICIAL_ROOT}/acc/ACC_LICENSE",
        f"{OFFICIAL_ROOT}/src/n2_99.ch",
        f"{OFFICIAL_ROOT}/src/n2b_d.c",
    )
    if any(path not in archive_files for path in required_paths):
        raise ValueError("official UCL evidence path missing")
    readme = archive_files[required_paths[0]]
    copying = archive_files[required_paths[1]]
    acc_license = archive_files[required_paths[2]]
    n2_99 = archive_files[required_paths[3]]
    n2b_d = archive_files[required_paths[4]]
    embedded_cpp = (
        xarchive_root / "Algos/xucldecoder.cpp"
    ).read_bytes()
    embedded_acc = (
        xarchive_root / "Algos/xucldecoder_acc.h"
    ).read_bytes()

    relationships = {
        "official_archive_sha1_matches_author_page": (
            sha1(archive_bytes) == OFFICIAL_ARCHIVE_SHA1
        ),
        "official_archive_sha256_is_fixed": (
            sha256(archive_bytes) == OFFICIAL_ARCHIVE_SHA256
        ),
        "official_header_declares_version_1_03": (
            re.search(
                rb"#\s*define\s+UCL_VERSION_STRING\s+\"1\.03\"",
                archive_files[
                    f"{OFFICIAL_ROOT}/include/ucl/uclconf.h"
                ],
            )
            is not None
        ),
        "official_readme_still_labels_version_1_02": (
            b"Version 1.02" in readme
            and b"Version 1.03" not in readme
        ),
        "official_readme_declares_gpl": (
            b"distributed under the terms of the GNU General Public"
            in readme
        ),
        "official_source_declares_gpl_2_or_later": (
            b"either version 2 of" in n2_99
            and b"the License, or (at your option) any later version"
            in n2_99
            and b"either version 2 of" in n2b_d
        ),
        "copying_and_acc_license_are_gpl_version_2": (
            b"GNU GENERAL PUBLIC LICENSE" in copying
            and b"Version 2, June 1991" in copying
            and b"GNU GENERAL PUBLIC LICENSE" in acc_license
            and b"Version 2, June 1991" in acc_license
        ),
        "embedded_cpp_declares_ucl_version_1_03": (
            b"#define UCL_VERSION 0x010300L" in embedded_cpp
            and b'#define UCL_VERSION_STRING "1.03"' in embedded_cpp
            and b'#define UCL_VERSION_DATE "Jul 20 2004"'
            in embedded_cpp
        ),
        "embedded_cpp_references_acc_license": (
            line_numbers(embedded_cpp, "ACC_LICENSE") == [842]
        ),
        "embedded_acc_omits_official_copyright_header": (
            b"Markus Franz Xaver Johannes Oberhumer" not in embedded_acc
            and b"GNU General Public License" not in embedded_acc
            and b"#define ACC_VERSION     20040715L" in embedded_acc
        ),
        "combined_12_token_coverage_exceeds_90_percent": (
            combined_evidence[0]["coverage"] > 0.90
        ),
        "combined_64_token_coverage_exceeds_80_percent": (
            combined_evidence[1]["coverage"] > 0.80
        ),
        "prior_product_report_binds_embedded_cpp": (
            finding[0]["source_sha256"] == sha256(embedded_cpp)
            and finding[0]["linkage"] == "direct-object"
        ),
    }
    if not all(relationships.values()):
        failed = sorted(
            name
            for name, value in relationships.items()
            if not value
        )
        raise ValueError(
            "XUCL origin relationships are incomplete: "
            f"{failed}; combined coverage="
            f"{[item['coverage'] for item in combined_evidence]}"
        )

    license_files = [
        file_record(
            path.removeprefix(f"{OFFICIAL_ROOT}/"),
            archive_files[path],
        )
        for path in required_paths[:3]
    ]
    source_evidence = [
        file_record(
            path.removeprefix(f"{OFFICIAL_ROOT}/"),
            archive_files[path],
        )
        for path in required_paths[3:]
    ]
    return {
        "schema_version": 1,
        "generator": "tools/upstream/audit_xucl_origin.py",
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "xarchive_commit": XARCHIVE_COMMIT,
        "component_lock": {
            "path": "upstream/components.lock.toml",
            "sha256": sha256(lock_bytes),
        },
        "prior_product_source_closure": {
            "path": PRIOR_REPORT,
            "sha256": sha256(prior_bytes),
        },
        "official_release": {
            "name": "UCL",
            "version": "1.03",
            "released_on": "2004-07-20",
            "copyright_holder": (
                "Markus Franz Xaver Johannes Oberhumer"
            ),
            "release_page": OFFICIAL_RELEASE_PAGE,
            "archive_url": OFFICIAL_ARCHIVE_URL,
            "archive_bytes": len(archive_bytes),
            "archive_sha1": sha1(archive_bytes),
            "archive_sha256": sha256(archive_bytes),
            "archive_root": OFFICIAL_ROOT,
            "regular_file_count": len(archive_files),
            "indexed_source_file_count": len(references),
        },
        "relationships": relationships,
        "embedded_files": embedded_records,
        "per_file_shingle_evidence": per_file_evidence,
        "combined_shingle_evidence": combined_evidence,
        "official_license_evidence": license_files,
        "official_source_evidence": source_evidence,
        "license_classification": {
            "technical_spdx_expression": "GPL-2.0-or-later",
            "basis": [
                (
                    "official UCL 1.03 source headers state version 2 "
                    "or any later version"
                ),
                (
                    "official COPYING and acc/ACC_LICENSE contain the "
                    "GNU GPL version 2 text"
                ),
                (
                    "the author release page says UCL and its "
                    "implementations are distributed under the GPL"
                ),
            ],
            "special_or_commercial_license_evidence_in_xarchive": False,
            "copy_or_translation_approved": False,
            "legal_review_complete": False,
        },
        "distribution_requirements": [
            (
                "treat the embedded UCL-derived source as "
                "GPL-2.0-or-later technical evidence unless a different "
                "written license grant is produced and reviewed"
            ),
            (
                "restore the exact UCL 1.03 COPYING/ACC_LICENSE and "
                "copyright/source attribution for any authorized distribution"
            ),
            (
                "do not copy or translate XUCL into Rust before release/legal "
                "review resolves the upstream MIT/GPL combination"
            ),
        ],
        "limitations": [
            (
                "token shingle coverage proves substantial source origin, "
                "not byte identity or a legal conclusion"
            ),
            (
                "the official archive is external and is hash-bound but not "
                "committed to this repository"
            ),
            (
                "this report does not establish a commercial or special "
                "license grant to horsicq or this project"
            ),
        ],
    }


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
        raise ValueError("XUCL audit image revision mismatch")
    return document["Id"], revision


def run_in_fixed_image(
    repo: pathlib.Path,
    archive: pathlib.Path,
) -> dict[str, Any]:
    image_id, revision = inspect_image()
    process = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--mount",
            f"type=bind,source={repo},target=/repo,readonly",
            "--mount",
            (
                f"type=bind,source={archive.resolve()},"
                "target=/input/ucl-1.03.tar.gz,readonly"
            ),
            "--entrypoint",
            "/usr/bin/python3",
            IMAGE,
            "/repo/tools/upstream/audit_xucl_origin.py",
            "--inside",
            "--source-root",
            "/opt/die-source",
            "--lock",
            "/repo/upstream/components.lock.toml",
            "--prior-report",
            f"/repo/{PRIOR_REPORT}",
            "--archive",
            "/input/ucl-1.03.tar.gz",
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError("inside XUCL audit wrote stderr")
    report = json.loads(process.stdout)
    report["source_image"] = {
        "image": IMAGE,
        "image_id": image_id,
        "revision": revision,
        "network": "none",
        "repository_mount": "readonly",
        "official_archive_mount": "readonly",
    }
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--source-root", type=pathlib.Path)
    parser.add_argument("--lock", type=pathlib.Path)
    parser.add_argument("--prior-report", type=pathlib.Path)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.inside:
        if (
            args.source_root is None
            or args.lock is None
            or args.prior_report is None
        ):
            raise ValueError(
                "--inside requires source root, lock, and prior report"
            )
        report = build_inside_report(
            args.source_root,
            args.lock,
            args.prior_report,
            args.archive,
        )
    else:
        if args.output is None:
            raise ValueError("host mode requires --output")
        repo = pathlib.Path(__file__).resolve().parents[2]
        report = run_in_fixed_image(repo, args.archive)

    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(serialized)
    else:
        args.output.write_text(
            serialized, encoding="utf-8", newline="\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

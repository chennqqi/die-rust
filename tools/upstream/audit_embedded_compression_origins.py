#!/usr/bin/env python3
"""Compare XArchive amalgamations with pinned official compression sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any


IMAGE = "die-rust/upstream-oracle-cmake:74eaf505"
UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
XARCHIVE_COMMIT = "0fcd4e8d3e9933baac3b12246d82ac026557ffd0"
BROTLI_COMMIT = "028fb5a23661f123017c060daa546b55cf4bde29"
ZSTD_COMMIT = "5c7b7bad26808e6b40ac3b3d0075466e27738a9d"
BROTLI_REMOTE = "https://github.com/google/brotli.git"
ZSTD_REMOTE = "https://github.com/facebook/zstd.git"
SHINGLE_LENGTHS = (12, 64)
LICENSE_WORDS = (
    b"copyright",
    b"license",
    b"redistribution",
    b"permission is hereby granted",
    b"public domain",
)
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


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_git(path: pathlib.Path, *arguments: str) -> str:
    process = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={path}",
            "-C",
            str(path),
            *arguments,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    if process.stderr:
        raise ValueError(f"git wrote stderr: {path}: {' '.join(arguments)}")
    return process.stdout.strip()


def verify_checkout(
    path: pathlib.Path, commit: str, remote: str
) -> dict[str, str]:
    if run_git(path, "rev-parse", "HEAD") != commit:
        raise ValueError(f"official checkout commit mismatch: {path}")
    if run_git(path, "status", "--porcelain"):
        raise ValueError(f"official checkout is dirty: {path}")
    actual_remote = run_git(path, "remote", "get-url", "origin")
    if actual_remote.rstrip("/") != remote.rstrip("/"):
        raise ValueError(f"official checkout remote mismatch: {path}")
    return {"commit": commit, "remote": remote}


def tokenize_c(data: bytes) -> list[str]:
    text = data.decode("utf-8-sig", errors="replace")
    tokens = []
    for match in TOKEN_PATTERN.finditer(text):
        value = match.group()
        if value.startswith("//") or value.startswith("/*"):
            continue
        tokens.append(value)
    return tokens


def has_license_words(data: bytes) -> bool:
    folded = data.lower()
    return any(word in folded for word in LICENSE_WORDS)


def parse_version(
    data: bytes, prefix: str, suffixes: tuple[str, str, str]
) -> str:
    text = data.decode("utf-8-sig", errors="replace")
    values = []
    for suffix in suffixes:
        pattern = re.compile(
            rf"^\s*#\s*define\s+{re.escape(prefix + suffix)}\s+(\d+)\s*$",
            re.MULTILINE,
        )
        match = pattern.search(text)
        if match is None:
            raise ValueError(f"missing version macro: {prefix + suffix}")
        values.append(match.group(1))
    return ".".join(values)


def license_record(path: pathlib.Path, root: pathlib.Path) -> dict[str, Any]:
    data = path.read_bytes()
    first_nonempty = next(
        (
            line.strip()
            for line in data.decode(
                "utf-8", errors="replace"
            ).splitlines()
            if line.strip()
        ),
        "",
    )
    return {
        "path": path.relative_to(root).as_posix(),
        "bytes": len(data),
        "sha256": sha256(data),
        "first_nonempty_line": first_nonempty,
    }


def official_brotli_files(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(
        path
        for path in (root / "c").rglob("*")
        if path.is_file() and path.suffix in {".c", ".h"}
    )


def shingle_evidence(
    embedded_tokens: list[str],
    official_root: pathlib.Path,
    length: int,
) -> dict[str, Any]:
    index: dict[tuple[str, ...], set[str]] = {}
    official_tokens: dict[str, list[str]] = {}
    for path in official_brotli_files(official_root):
        relative = path.relative_to(official_root).as_posix()
        tokens = tokenize_c(path.read_bytes())
        official_tokens[relative] = tokens
        for position in range(len(tokens) - length + 1):
            shingle = tuple(tokens[position : position + length])
            index.setdefault(shingle, set()).add(relative)

    covered = [False] * len(embedded_tokens)
    matching_window_count = 0
    unique_counts: dict[str, int] = {}
    for position in range(len(embedded_tokens) - length + 1):
        shingle = tuple(
            embedded_tokens[position : position + length]
        )
        origins = index.get(shingle)
        if not origins:
            continue
        matching_window_count += 1
        for covered_position in range(position, position + length):
            covered[covered_position] = True
        if len(origins) == 1:
            origin = next(iter(origins))
            unique_counts[origin] = unique_counts.get(origin, 0) + 1

    unique_origins = []
    for relative, count in sorted(unique_counts.items()):
        path = official_root / relative
        unique_origins.append(
            {
                "path": relative,
                "sha256": sha256(path.read_bytes()),
                "unique_matching_window_count": count,
            }
        )
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


def generate_official_zstd_decoder(
    zstd_root: pathlib.Path, output: pathlib.Path
) -> dict[str, Any]:
    script_root = zstd_root / "build/single_file_libs"
    combine = script_root / "combine.py"
    template = script_root / "zstddeclib-in.c"
    process = subprocess.run(
        [
            sys.executable,
            str(combine),
            "-r",
            str(zstd_root / "lib"),
            "-x",
            "legacy/zstd_legacy.h",
            "-o",
            str(output),
            str(template),
        ],
        cwd=script_root,
        check=True,
        capture_output=True,
    )
    return {
        "combine_path": "build/single_file_libs/combine.py",
        "combine_sha256": sha256(combine.read_bytes()),
        "template_path": "build/single_file_libs/zstddeclib-in.c",
        "template_sha256": sha256(template.read_bytes()),
        "generated_sha256": sha256(output.read_bytes()),
    }


def build_inside_report(
    xarchive_root: pathlib.Path,
    brotli_root: pathlib.Path,
    zstd_root: pathlib.Path,
) -> dict[str, Any]:
    brotli_source = xarchive_root / "Algos/brotlideclib.cpp"
    zstd_source = xarchive_root / "Algos/zstddeclib.cpp"
    brotli_data = brotli_source.read_bytes()
    zstd_data = zstd_source.read_bytes()
    brotli_tokens = tokenize_c(brotli_data)
    zstd_tokens = tokenize_c(zstd_data)

    brotli_shingles = [
        shingle_evidence(brotli_tokens, brotli_root, length)
        for length in SHINGLE_LENGTHS
    ]
    with tempfile.TemporaryDirectory() as directory:
        generated = pathlib.Path(directory) / "zstddeclib.c"
        zstd_generation = generate_official_zstd_decoder(
            zstd_root, generated
        )
        official_zstd_data = generated.read_bytes()
        official_zstd_tokens = tokenize_c(official_zstd_data)

    zstd_wrapper_prefix = ["extern", '"C"', "{"]
    zstd_wrapper_suffix = ["}"]
    zstd_exact = (
        zstd_tokens[:3] == zstd_wrapper_prefix
        and zstd_tokens[-1:] == zstd_wrapper_suffix
        and zstd_tokens[3:-1] == official_zstd_tokens
    )
    relationships = {
        "embedded_brotli_declares_version_1_2_0": (
            parse_version(
                brotli_data,
                "BROTLI_VERSION_",
                ("MAJOR", "MINOR", "PATCH"),
            )
            == "1.2.0"
        ),
        "brotli_64_token_coverage_exceeds_98_percent": (
            brotli_shingles[1]["coverage"] > 0.98
        ),
        "embedded_zstd_declares_development_version_1_6_0": (
            parse_version(
                zstd_data,
                "ZSTD_VERSION_",
                ("MAJOR", "MINOR", "RELEASE"),
            )
            == "1.6.0"
        ),
        "embedded_zstd_is_exact_official_decoder_plus_cpp_wrapper": (
            zstd_exact
        ),
        "embedded_files_omit_license_words": (
            not has_license_words(brotli_data)
            and not has_license_words(zstd_data)
        ),
        "official_brotli_license_contains_mit_permission": (
            b"Permission is hereby granted, free of charge"
            in (brotli_root / "LICENSE").read_bytes()
        ),
        "official_zstd_license_contains_bsd_redistribution": (
            b"Redistribution and use in source and binary forms"
            in (zstd_root / "LICENSE").read_bytes()
        ),
        "official_zstd_copying_is_gpl_version_2": (
            b"GNU GENERAL PUBLIC LICENSE"
            in (zstd_root / "COPYING").read_bytes()
            and b"Version 2, June 1991"
            in (zstd_root / "COPYING").read_bytes()
        ),
    }
    if not all(relationships.values()):
        raise ValueError("embedded compression origin relationships failed")

    return {
        "schema_version": 1,
        "generator": (
            "tools/upstream/audit_embedded_compression_origins.py"
        ),
        "generator_sha256": sha256(pathlib.Path(__file__).read_bytes()),
        "upstream_commit": UPSTREAM_COMMIT,
        "xarchive_commit": XARCHIVE_COMMIT,
        "official_sources": {
            "brotli": {
                "remote": BROTLI_REMOTE,
                "commit": BROTLI_COMMIT,
                "tag": "v1.2.0",
                "declared_version": "1.2.0",
                "license": license_record(
                    brotli_root / "LICENSE", brotli_root
                ),
            },
            "zstandard": {
                "remote": ZSTD_REMOTE,
                "commit": ZSTD_COMMIT,
                "tag": None,
                "declared_version": "1.6.0",
                "license": license_record(
                    zstd_root / "LICENSE", zstd_root
                ),
                "copying": license_record(
                    zstd_root / "COPYING", zstd_root
                ),
            },
        },
        "embedded_sources": {
            "brotli": {
                "path": "Algos/brotlideclib.cpp",
                "bytes": len(brotli_data),
                "sha256": sha256(brotli_data),
                "token_count": len(brotli_tokens),
                "contains_license_words": has_license_words(
                    brotli_data
                ),
                "shingle_evidence": brotli_shingles,
            },
            "zstandard": {
                "path": "Algos/zstddeclib.cpp",
                "bytes": len(zstd_data),
                "sha256": sha256(zstd_data),
                "token_count": len(zstd_tokens),
                "contains_license_words": has_license_words(zstd_data),
                "official_generated_token_count": len(
                    official_zstd_tokens
                ),
                "wrapper_prefix_tokens": zstd_wrapper_prefix,
                "wrapper_suffix_tokens": zstd_wrapper_suffix,
                "exact_official_tokens_inside_wrapper": zstd_exact,
                "generation": zstd_generation,
            },
        },
        "relationships": relationships,
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
        raise ValueError("origin audit image revision mismatch")
    return document["Id"], revision


def run_in_fixed_image(
    repo: pathlib.Path,
    brotli_root: pathlib.Path,
    zstd_root: pathlib.Path,
) -> dict[str, Any]:
    verify_checkout(brotli_root, BROTLI_COMMIT, BROTLI_REMOTE)
    verify_checkout(zstd_root, ZSTD_COMMIT, ZSTD_REMOTE)
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
                f"type=bind,source={brotli_root},"
                "target=/official/brotli,readonly"
            ),
            "--mount",
            (
                f"type=bind,source={zstd_root},"
                "target=/official/zstd,readonly"
            ),
            "--entrypoint",
            "/usr/bin/python3",
            IMAGE,
            "/repo/tools/upstream/audit_embedded_compression_origins.py",
            "--inside",
            "--xarchive-root",
            "/opt/die-source/XArchive",
            "--brotli-root",
            "/official/brotli",
            "--zstd-root",
            "/official/zstd",
        ],
        check=True,
        capture_output=True,
    )
    if process.stderr:
        raise ValueError("inside embedded origin audit wrote stderr")
    report = json.loads(process.stdout)
    report["source_image"] = {
        "image": IMAGE,
        "image_id": image_id,
        "revision": revision,
        "network": "none",
        "repository_mount": "readonly",
        "official_source_mounts": "readonly",
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--xarchive-root", type=pathlib.Path)
    parser.add_argument("--brotli-root", type=pathlib.Path, required=True)
    parser.add_argument("--zstd-root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.inside:
        if args.xarchive_root is None:
            parser.error("--inside requires --xarchive-root")
        report = build_inside_report(
            args.xarchive_root, args.brotli_root, args.zstd_root
        )
    else:
        if args.output is None:
            parser.error("host mode requires --output")
        repo = pathlib.Path(__file__).resolve().parents[2]
        report = run_in_fixed_image(
            repo,
            args.brotli_root.resolve(),
            args.zstd_root.resolve(),
        )

    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(serialized)
    else:
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Capture pinned Qt 5/Qt 6 QObject HostApi arity/error oracles."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
from typing import Any


UPSTREAM_COMMIT = "74eaf505c250ab47e709024e9dc41657cd8f2254"
XSCANENGINE_COMMIT = "dfe4a419e4f491bb23688ba03c5a5bf39e34da83"
RULES_COMMIT = "c2c17dfa5ea4e078ba31eab55d87430c96622fb6"
PE_INIT_SHA256 = (
    "26f5912c5ac137ed44d0d9edade8d3ce65501a61ce06d0491db5e1faa59c1f90"
)
QT5_IMAGE = "die-rust/upstream-host-api-arity-harness:74eaf505"
QT6_IMAGE = "die-rust/upstream-host-api-arity-harness-qt6:74eaf505"
DEFAULT_BINARY = "/opt/die-build/src/console/die-host-api-arity-harness"
QT6_STDERR = (
    b"%entry@file:u8-extra.js:1\n"
    b"Too many arguments, ignoring 1\n"
    b'"Could not convert argument 0 at"\n'
    b'\t "%entry@file:u8-null.js:1"\n'
    b'"Could not convert argument 0 at"\n'
    b'\t "%entry@file:u8-undefined.js:1"\n'
    b"%entry@file:u24-extra.js:1\n"
    b"Too many arguments, ignoring 1\n"
    b"%entry@file:sa-extra.js:1\n"
    b"Too many arguments, ignoring 1\n"
    b"%entry@file:sc-extra.js:1\n"
    b"Too many arguments, ignoring 1\n"
    b"%entry@file:shru64-extra.js:1\n"
    b"Too many arguments, ignoring 1\n"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_observation(
    stdout: bytes,
    stderr: bytes,
    returncode: int,
    runtime: str = "qt5",
) -> dict[str, Any]:
    if returncode != 0:
        raise ValueError(f"harness exited with {returncode}")
    expected_stderr = b"" if runtime == "qt5" else QT6_STDERR
    if stderr != expected_stderr:
        raise ValueError("harness wrote unexpected stderr")
    try:
        text = stdout.decode("utf-8")
        observation, end = json.JSONDecoder().raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("harness did not emit one UTF-8 JSON document") from error
    if text[end:].strip():
        raise ValueError("harness emitted trailing stdout")
    validate_observation(observation, runtime)
    return observation


def _semantic_value(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "source"}


def validate_observation(
    observation: dict[str, Any],
    runtime: str = "qt5",
) -> None:
    if runtime not in {"qt5", "qt6"}:
        raise ValueError("unsupported runtime profile")
    identities = {
        "schema_version": 1,
        "upstream_commit": UPSTREAM_COMMIT,
        "xscanengine_commit": XSCANENGINE_COMMIT,
        "rules_commit": RULES_COMMIT,
        "qt_version": "5.15.13" if runtime == "qt5" else "6.4.2",
    }
    for key, expected in identities.items():
        if observation.get(key) != expected:
            raise ValueError(f"unexpected {key}")
    if observation.get("pe_init", {}).get("sha256") != PE_INIT_SHA256:
        raise ValueError("unexpected PE _init identity")

    def expect_value(
        value: dict[str, Any],
        kind: str,
        expected: Any,
    ) -> None:
        if value.get("is_error"):
            raise ValueError("successful invocation raised an exception")
        key = {"number": "number", "string": "string"}[kind]
        if value.get(key) != expected:
            raise ValueError(f"unexpected {kind} result")

    def expect_error(
        value: dict[str, Any],
        name: str,
        message: str,
    ) -> None:
        if (
            not value.get("is_error")
            or value.get("error_name") != name
            or value.get("error_message") != message
            or value.get("error_line") != 1
        ):
            raise ValueError("unexpected QObject invocation error")

    binary = observation["binary"]
    for name in ("u8", "sa", "sc"):
        exact = binary[f"{name}_exact"]
        extra = binary[f"{name}_extra"]
        if exact["is_error"] or extra["is_error"]:
            raise ValueError(f"{name} invocation raised an exception")
        if _semantic_value(exact) != _semantic_value(extra):
            raise ValueError(f"{name} extra arguments changed the result")
        length = binary[f"{name}_function_length"]
        if not length["is_number"] or length.get("number") != 0:
            raise ValueError(f"{name} wrapper length is not zero")

    for name in ("u24",):
        exact = binary[f"{name}_big_endian"]
        extra = binary[f"{name}_extra"]
        if exact["is_error"] or extra["is_error"]:
            raise ValueError(f"{name} invocation raised an exception")
        if _semantic_value(exact) != _semantic_value(extra):
            raise ValueError(f"{name} extra arguments changed the result")
        length = binary[f"{name}_function_length"]
        if not length["is_number"] or length.get("number") != 0:
            raise ValueError(f"{name} wrapper length is not zero")

    for key in (
        "u8_exact",
        "u8_extra",
        "u8_string",
        "u8_boolean",
    ):
        expect_value(binary[key], "number", 65)
    expect_value(binary["u24_little_endian"], "number", 0x563412)
    for key in (
        "u24_big_endian",
        "read_uint24_big_endian",
        "u24_extra",
    ):
        expect_value(binary[key], "number", 0x123456)
    if runtime == "qt5":
        expect_value(binary["u8_null"], "number", 65)
        expect_value(binary["u8_undefined"], "number", 65)
        expect_error(
            binary["u8_missing"],
            "SyntaxError",
            (
                "too few arguments in call to U8(); candidates are\n"
                "    U8(qlonglong)"
            ),
        )
    else:
        incompatible = (
            "Passing incompatible arguments to C++ functions from "
            "JavaScript is not allowed."
        )
        expect_error(binary["u8_null"], "TypeError", incompatible)
        expect_error(binary["u8_undefined"], "TypeError", incompatible)
        expect_error(
            binary["u8_missing"],
            "Error",
            "Insufficient arguments",
        )

    expect_value(binary["sa_exact"], "string", "A")
    expect_value(binary["sa_extra"], "string", "A")
    expect_value(binary["sa_missing"], "string", "ABC")
    for key in (
        "sc_exact",
        "sc_extra",
        "sc_default_one",
        "sc_default_two",
        "sc_null_encoding",
        "sc_number_encoding",
    ):
        expect_value(binary[key], "string", "")
    sc_candidates = (
        "    SC(qlonglong)\n"
        "    SC(qlonglong,qlonglong)\n"
        "    SC(qlonglong,qlonglong,QString)"
    )
    if runtime == "qt5":
        expect_error(
            binary["sc_missing"],
            "SyntaxError",
            (
                "too few arguments in call to SC(); candidates are\n"
                f"{sc_candidates}"
            ),
        )
    else:
        expect_error(
            binary["sc_missing"],
            "Error",
            (
                "Unable to determine callable overload.  Candidates are:\n"
                f"{sc_candidates}\n{sc_candidates}\n{sc_candidates}"
            ),
        )

    observed_error_sources = {
        value["source"]
        for value in binary.values()
        if isinstance(value, dict) and value.get("is_error")
    }
    expected_error_sources = {"X.U8()", "X.SC()"}
    if runtime == "qt6":
        expected_error_sources |= {"X.U8(null)", "X.U8(undefined)"}
    if observed_error_sources != expected_error_sources:
        raise ValueError("unexpected QObject error set")

    util = observation["util"]
    length = util["shru64_function_length"]
    if (
        not length["is_number"]
        or length.get("number") != 0
    ):
        raise ValueError("shru64 wrapper length is not zero")
    expect_value(util["shru64_zero"], "number", 0xFFFFFFFF)
    expect_value(util["shru64_four"], "number", 0x0FFFFFFF)
    expect_value(util["shru64_thirty_two"], "number", 0)
    if (
        util["shru64_extra"]["is_error"]
        or _semantic_value(util["shru64_four"])
        != _semantic_value(util["shru64_extra"])
    ):
        raise ValueError("shru64 extra arguments changed the result")
    if any(
        value.get("is_error")
        for value in util.values()
        if isinstance(value, dict)
    ):
        raise ValueError("shru64 invocation raised an exception")

    pe = observation["pe"]
    if pe["init_evaluation"]["is_error"]:
        raise ValueError("PE _init evaluation failed")
    expected_types = {
        "get_ep_signature_type_before_init": "undefined",
        "get_ep_signature_type_after_init": "undefined",
        "get_entry_point_signature_type_before_init": "undefined",
        "get_entry_point_signature_type_after_init": "function",
    }
    for key, expected in expected_types.items():
        if pe[key].get("string") != expected:
            raise ValueError(f"unexpected PE method type: {key}")
    error = pe["get_ep_signature_call"]
    if runtime == "qt5":
        expected_pe_error = (
            "Result of expression 'PE.getEPSignature' [undefined] "
            "is not a function."
        )
    else:
        expected_pe_error = (
            "Property 'getEPSignature' of object "
            "PE_Script(<address>) is not a function"
        )
    expect_error(error, "TypeError", expected_pe_error)


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
        process.stdout,
        process.stderr,
        process.returncode,
        runtime,
    )

    init = observation["pe"]["init_evaluation"]
    init_source = init.pop("source").encode("utf-8")
    if sha256(init_source) != PE_INIT_SHA256:
        raise ValueError("evaluated PE _init source identity mismatch")
    init["source_bytes"] = len(init_source)
    init["source_sha256"] = sha256(init_source)

    sources = {}
    for relative in (
        "tools/upstream/host_api_arity_harness_main.cpp",
        f"tools/upstream/Dockerfile.host-api-arity-harness-{runtime}",
        "tools/upstream/probe_host_api_arity.py",
    ):
        data = (repo / relative).read_bytes()
        sources[relative] = {"bytes": len(data), "sha256": sha256(data)}

    return {
        "schema_version": 1,
        "generator": "tools/upstream/probe_host_api_arity.py",
        "runtime_profile": runtime,
        "image": {
            "name": image,
            "id": image_id,
            "revision": revision,
        },
        "binary": {"path": binary, "sha256": binary_sha256(image, binary)},
        "stderr": {
            "bytes": len(process.stderr),
            "sha256": sha256(process.stderr),
            "utf8_lines": process.stderr.decode("utf-8").splitlines(),
        },
        "sources": sources,
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
        repo / f"docs/research/data/host-api-arity-{args.runtime}.json"
    )
    report = build_report(repo, args.runtime, args.image, args.binary)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

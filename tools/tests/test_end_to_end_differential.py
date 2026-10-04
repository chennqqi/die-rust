#!/usr/bin/env python3
"""End-to-end differential framework audit test for a minimal sample.

Verify that the differential framework can produce an auditable report for a
minimal sample by exercising the full pipeline:

1. Build the Rust ``diec`` skeleton binary.
2. Collect a raw execution record via ``collect_rust_execution.py``.
3. Verify the record via ``verify_raw_execution.py``.
4. Assert the verification report is well-formed and auditable.

This satisfies the Phase 1 exit condition: "差分框架能对最小样本给出可审计
报告".  The Rust side is a skeleton producer; the framework's auditability is
independent of whether detections match upstream.

See ``docs/design/testing.md`` section 8 and ``ROADMAP.md`` Phase 1 exit
conditions.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from typing import Any

# Ensure the tools/compat directory is importable.
ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPAT = ROOT / "tools" / "compat"
sys.path.insert(0, str(COMPAT))

import collect_rust_execution as rust_collector  # noqa: E402
import verify_raw_execution as raw_verifier  # noqa: E402

REPO_ROOT = ROOT


def _sha256_zero() -> str:
    """Return a zero SHA-256 for the placeholder case manifest."""
    return "0" * 64


def _build_diec(tmpdir: pathlib.Path) -> pathlib.Path:
    """Build the diec binary in debug mode and return its path."""
    binary_name = "diec.exe" if os.name == "nt" else "diec"
    target_dir = REPO_ROOT / "target" / "debug"
    binary = target_dir / binary_name
    if not binary.exists():
        subprocess.run(
            ["cargo", "build", "-p", "die-cli", "--locked"],
            cwd=str(REPO_ROOT),
            check=True,
            capture_output=True,
            timeout=120,
        )
    if not binary.exists():
        raise RuntimeError(f"diec binary not found after build: {binary}")
    return binary


def test_end_to_end_differential_audit() -> None:
    """The framework produces an auditable raw execution record for diec."""
    with tempfile.TemporaryDirectory(prefix="die-diff-e2e-") as tmp:
        tmpdir = pathlib.Path(tmp)
        artifact_root = tmpdir / "artifacts"
        artifact_root.mkdir()

        binary = _build_diec(tmpdir)

        case_id = "phase1.skeleton.die-no-args"
        case_manifest_sha = _sha256_zero()
        output_path = tmpdir / "rust-execution.json"

        # Collect: run the diec skeleton with no arguments.
        record = rust_collector.collect(
            binary,
            [],
            case_id=case_id,
            case_manifest_sha256=case_manifest_sha,
            producer_profile="rust-cli-skeleton",
            producer_revision="0" * 40,
            artifact_root=artifact_root,
            timeout_seconds=10,
            environment={"LC_ALL": "C", "TZ": "UTC"},
            logical_cwd=tmpdir,
        )

        # The skeleton exits 0 and prints "diec skeleton" to stdout.
        assert record["execution_schema"] == 1
        assert record["run_identity"]["side"] == "rust"
        assert record["run_identity"]["case_id"] == case_id
        assert record["termination"]["kind"] == "exit"
        assert record["termination"]["code"] == 0
        assert "stdout" in record["artifacts"]
        assert "stderr" in record["artifacts"]

        # Write the record and verify it with the raw execution verifier.
        output_path.write_text(
            json.dumps(record, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        manifest_sha = raw_verifier.sha256_bytes(output_path.read_bytes())
        verification = raw_verifier.verify_execution(
            record,
            manifest_sha,
            artifact_root,
            raw_verifier.DEFAULT_MAX_ARTIFACT_BYTES,
        )

        # The verification must pass and be auditable.
        assert verification["verification_schema"] == 1
        assert verification["verifier"]["name"] == raw_verifier.VERIFIER_NAME
        assert verification["result"] == "pass"
        assert verification["manifest_artifact"]["sha256"] == manifest_sha
        assert verification["manifest_artifact"]["canonical_execution_sha256"] is not None
        assert len(verification["artifacts"]) >= 2

        # The stdout artifact must match the skeleton's expected output.
        stdout_digest = record["artifacts"]["stdout"]["sha256"]
        stdout_path = artifact_root / "sha256" / stdout_digest
        stdout_bytes = stdout_path.read_bytes()
        assert stdout_bytes == b"diec skeleton\n"

        # Write the verification report for auditability.
        verification_path = tmpdir / "verification.json"
        verification_path.write_text(
            json.dumps(verification, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        # The verification report is self-contained and auditable:
        # it carries the manifest hash, canonical execution hash, artifact
        # hashes, and verifier identity.
        assert verification["manifest_artifact"]["sha256"] == manifest_sha


def test_collect_rust_execution_rejects_missing_executable() -> None:
    """The collector rejects a non-existent executable."""
    with tempfile.TemporaryDirectory(prefix="die-diff-missing-") as tmp:
        tmpdir = pathlib.Path(tmp)
        try:
            rust_collector.collect(
                tmpdir / "nonexistent",
                [],
                case_id="test.missing",
                case_manifest_sha256=_sha256_zero(),
                producer_profile="rust-cli-skeleton",
                producer_revision="0" * 40,
                artifact_root=tmpdir / "artifacts",
                timeout_seconds=5,
                environment=None,
                logical_cwd=tmpdir,
            )
        except rust_collector.CollectorError:
            return
        raise AssertionError("expected CollectorError for missing executable")


def test_collect_rust_execution_content_addressed() -> None:
    """Artifacts are content-addressed under sha256/<digest>."""
    with tempfile.TemporaryDirectory(prefix="die-diff-ca-") as tmp:
        tmpdir = pathlib.Path(tmp)
        artifact_root = tmpdir / "artifacts"
        binary = _build_diec(tmpdir)

        record = rust_collector.collect(
            binary,
            [],
            case_id="phase1.skeleton.content-addressed",
            case_manifest_sha256=_sha256_zero(),
            producer_profile="rust-cli-skeleton",
            producer_revision="0" * 40,
            artifact_root=artifact_root,
            timeout_seconds=10,
            environment={},
            logical_cwd=tmpdir,
        )

        stdout_digest = record["artifacts"]["stdout"]["sha256"]
        stdout_path = artifact_root / "sha256" / stdout_digest
        assert stdout_path.exists()
        assert stdout_path.read_bytes() == b"diec skeleton\n"

        stderr_digest = record["artifacts"]["stderr"]["sha256"]
        stderr_path = artifact_root / "sha256" / stderr_digest
        assert stderr_path.exists()
        assert stderr_path.read_bytes() == b""

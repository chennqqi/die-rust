#!/usr/bin/env python3
"""Sanitize local paths from macOS benchmark evidence files."""

from __future__ import annotations

import json
from pathlib import Path
import re


WORK_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = WORK_DIR / "evidence" / "macos-benchmark"
SANITIZED_DIR = WORK_DIR / "evidence-sanitized" / "macos-benchmark"

# Path replacements (longest first to avoid partial matches)
REPLACEMENTS = [
    ("/Users/chenq/dev/tmp/die-macos-work/", "<macos-work>/"),
]


def sanitize_text(text: str) -> str:
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)
    return text


def sanitize_json(obj):
    if isinstance(obj, str):
        return sanitize_text(obj)
    if isinstance(obj, dict):
        return {k: sanitize_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_json(item) for item in obj]
    return obj


def main() -> int:
    SANITIZED_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(EVIDENCE_DIR.glob("*.json"))
    for path in files:
        raw = path.read_bytes()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            print(f"skip non-JSON: {path.name}")
            continue
        sanitized = sanitize_json(data)
        output = SANITIZED_DIR / path.name
        output.write_text(
            json.dumps(sanitized, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"sanitized: {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

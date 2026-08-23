#!/usr/bin/env python3
"""Record golden JSON baselines from upstream DIE-engine diec.

Phase 15.1c: Records upstream diec output for each corpus sample to
create golden baseline files for true differential testing.

Usage:
    python3 tools/record_golden_baselines.py
"""

import json
import os
import subprocess
import sys
from pathlib import Path


def find_workspace_root() -> Path:
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "upstream" / "Detect-It-Easy").is_dir():
            return p
        p = p.parent
    raise RuntimeError("Cannot find workspace root")


def main():
    workspace = find_workspace_root()
    db_path = workspace / "upstream" / "Detect-It-Easy" / "db"
    extra_path = workspace / "upstream" / "Detect-It-Easy" / "db_extra"
    corpus_dir = workspace / "corpus"

    # Find upstream diec binary.
    diec_bin = os.environ.get("UPSTREAM_DIEC", "/tmp/die-engine-build/build/src/console/diec")
    if not Path(diec_bin).exists():
        print(f"ERROR: upstream diec not found at {diec_bin}", file=sys.stderr)
        print("Set UPSTREAM_DIEC environment variable or build from source.", file=sys.stderr)
        sys.exit(1)

    # Get diec version.
    version = subprocess.run([diec_bin, "--version"], capture_output=True, text=True)
    diec_version = version.stdout.strip()
    print(f"Upstream diec: {diec_version}")

    # Corpus files to record (same as corpus_differential.rs).
    corpus_files = [
        "minimal.exe", "minimal-pe64.exe", "with-tables.exe",
        "pe-with-resources.exe", "pe-dotnet.exe",
        "elf-with-deps.elf", "macho-with-dylib.macho",
        "minimal.elf", "minimal-elf32.elf",
        "minimal.macho", "minimal-macho32.macho", "minimal-fat.macho",
        "Minimal.class", "minimal.dex",
        "payload.zip", "minimal.apk", "minimal.jar", "minimal.ipa",
        "payload.tar", "minimal.cfbf",
        "minimal.pdf",
        "pixel.png", "pixel.jpg", "pixel.bmp",
        "plain.txt", "manifest.json",
        "minimal.rar", "payload.txt.gz",
        "empty.bin",
    ]

    # Also record with db_extra if the binary supports it.
    # Upstream 4.0.0 doesn't have --extradatabase, so we test with db only.
    # For db_extra coverage, we'll create a combined db directory symlink.
    golden = {
        "diec_version": diec_version,
        "database_commit": "c2c17dfa5",
        "recorded_at": subprocess.run(
            ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
            capture_output=True, text=True
        ).stdout.strip(),
        "cases": {}
    }

    for filename in corpus_files:
        filepath = corpus_dir / filename
        if not filepath.exists():
            print(f"  SKIP: {filename} not found")
            continue

        # Run upstream diec with JSON output.
        cmd = [diec_bin, "--json", "--database", str(db_path), str(filepath)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        # Parse JSON output (diec prints JSON then "Last error:" line).
        stdout = result.stdout
        # Extract JSON part (everything before "Last error:" if present).
        json_end = stdout.find("\nLast error:")
        if json_end >= 0:
            json_str = stdout[:json_end].strip()
            last_error = stdout[json_end + len("\nLast error:"):].strip()
        else:
            json_str = stdout.strip()
            last_error = ""

        try:
            parsed = json.loads(json_str) if json_str else {}
        except json.JSONDecodeError as e:
            print(f"  ERROR parsing {filename}: {e}")
            print(f"    stdout: {stdout[:200]}")
            continue

        golden["cases"][filename] = {
            "exit_code": result.returncode,
            "json": parsed,
            "last_error": last_error,
            "stderr": result.stderr.strip(),
        }

        detects = parsed.get("detects", [])
        n_detects = sum(len(d.get("values", [])) for d in detects)
        print(f"  {filename}: exit={result.returncode}, detects={n_detects}, "
              f"error='{last_error[:50]}'")

    # Save golden file.
    output_path = workspace / "tests" / "golden" / "upstream-diec-baseline.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(golden, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")

    print(f"\nGolden baseline written to: {output_path}")
    print(f"Total cases: {len(golden['cases'])}")


if __name__ == "__main__":
    main()

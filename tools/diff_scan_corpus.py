#!/usr/bin/env python3
"""Differential scan: compare die-rust vs upstream DIE-engine diec on real corpus.

Scans samples from /data/virus/{pe,elf}_{benign,malicious} with both engines
and reports detection discrepancies. Focuses on packer/protector detection
consistency.

Usage:
    python3 tools/diff_scan_corpus.py --category pe_malicious --limit 100
    python3 tools/diff_scan_corpus.py --category pe_malicious --limit 100 --output /tmp/diff_result.json
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
DB_PATH = WORKSPACE / "upstream" / "Detect-It-Easy" / "db"
EXTRA_DB_PATH = WORKSPACE / "upstream" / "Detect-It-Easy" / "db_extra"
DIE_RUST = WORKSPACE / "target" / "release" / "diec"
UPSTREAM_DIEC = Path(os.environ.get(
    "UPSTREAM_DIEC",
    str(WORKSPACE / "tools" / "upstream" / "bin" / "upstream_diec.sh"),
))

CORPUS_BASE = Path("/data/virus")

# Detection types that indicate packer/protector
PACKER_TYPES = {"packer", "protector", "cryptor", "installer"}


def log(msg):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def run_upstream(sample_path):
    """Run upstream diec, return parsed JSON or None.

    Upstream diec appends 'Last error: ...' text after JSON on stdout,
    so we extract only the JSON portion. Also loads db_extra via -C.
    """
    try:
        cmd = [str(UPSTREAM_DIEC), "-D", str(DB_PATH), "-C", str(EXTRA_DB_PATH),
               "--json", str(sample_path)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0 or not r.stdout.strip():
            return None, r.stderr.strip()
        # Extract JSON portion (upstream appends "Last error:" after JSON)
        stdout = r.stdout.strip()
        # Find the end of JSON object/array
        brace_count = 0
        json_end = 0
        for i, ch in enumerate(stdout):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    json_end = i + 1
                    break
        if json_end == 0:
            return None, "no JSON found"
        json_str = stdout[:json_end]
        data = json.loads(json_str)
        return data, ""
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
        return None, str(e)


def run_diec_rust(sample_path):
    """Run die-rust, return parsed JSON list or None."""
    env = dict(os.environ, DIE_DB_PATH=str(DB_PATH))
    try:
        cmd = [str(DIE_RUST), "--db", str(DB_PATH), "--extradb",
               str(EXTRA_DB_PATH), "--json-upstream", str(sample_path)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
        if r.returncode != 0 or not r.stdout.strip():
            return None, r.stderr.strip()
        data = json.loads(r.stdout)
        return data, r.stderr.strip()
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
        return None, str(e)


# Map upstream filetype display strings (XBinary::fileTypeIdToString) to our
# canonical rule-dir names.
FILETYPE_MAP = {
    "PE32": "PE", "PE64": "PE", "PE": "PE",
    "ELF32": "ELF", "ELF64": "ELF", "ELF": "ELF",
    "Mach-O32": "MACH", "Mach-O64": "MACH", "Mach-O": "MACH",
    "Mach-O FAT": "MACHOFAT",
    ".NET": "DOTNET",
    "PlainText": "PLAINTEXT",
    "MS-DOS": "MSDOS",
    "ISO 9660": "ISO9660",
    "Java Class": "JavaClass",
}


def normalize_filetype(ft):
    """Normalize filetype to canonical form (PE/ELF/MACH etc)."""
    return FILETYPE_MAP.get(ft, ft)


def normalize_upstream(data):
    """Extract detection set from upstream diec JSON.

    Returns set of (filetype, name, type, version) tuples.
    Filetype normalized to canonical form (PE32/PE64 -> PE).
    """
    detections = set()
    if not data or "detects" not in data:
        return detections
    for group in data["detects"]:
        ft = normalize_filetype(group.get("filetype", ""))
        for v in group.get("values", []):
            name = v.get("name", "")
            dtype = v.get("type", "").lower()
            version = v.get("version", "")
            detections.add((ft, name, dtype, version))
    return detections


def normalize_diec_rust(data):
    """Extract detection set from die-rust --json-upstream output.

    Returns set of (filetype, name, type, version) tuples.
    """
    detections = set()
    if not data or not isinstance(data, list):
        return detections
    for d in data:
        ft = normalize_filetype(d.get("fileType", ""))
        name = d.get("name", "")
        dtype = d.get("string", "").lower()
        version = d.get("version", "")
        detections.add((ft, name, dtype, version))
    return detections


def has_packer_protector(detections):
    """Check if any detection is a packer/protector type."""
    for _, _, dtype, _ in detections:
        if dtype in PACKER_TYPES:
            return True
    return False


def scan_sample(sample_path):
    """Scan one sample with both engines, return comparison result."""
    up_data, up_err = run_upstream(sample_path)
    rust_data, rust_err = run_diec_rust(sample_path)

    up_dets = normalize_upstream(up_data)
    rust_dets = normalize_diec_rust(rust_data)

    only_upstream = up_dets - rust_dets
    only_rust = rust_dets - up_dets
    common = up_dets & rust_dets

    up_packer = has_packer_protector(up_dets)
    rust_packer = has_packer_protector(rust_dets)

    return {
        "sample": str(sample_path),
        "sample_name": sample_path.name,
        "upstream_detections": sorted(up_dets),
        "rust_detections": sorted(rust_dets),
        "only_upstream": sorted(only_upstream),
        "only_rust": sorted(only_rust),
        "common": sorted(common),
        "upstream_packer_detected": up_packer,
        "rust_packer_detected": rust_packer,
        "packer_decision_match": up_packer == rust_packer,
        "upstream_error": up_err if up_data is None else "",
        "rust_error": rust_err if rust_data is None else "",
        "detection_match": len(only_upstream) == 0 and len(only_rust) == 0,
    }


def main():
    parser = argparse.ArgumentParser(description="Differential scan corpus")
    parser.add_argument("--category", default="pe_malicious",
                        help="Corpus category (pe_benign/pe_malicious/elf_benign/elf_malicious)")
    parser.add_argument("--limit", type=int, default=50,
                        help="Max samples to scan")
    parser.add_argument("--offset", type=int, default=0,
                        help="Skip first N samples")
    parser.add_argument("--output", default=None,
                        help="Output JSON file path")
    parser.add_argument("--only-mismatch", action="store_true",
                        help="Only print mismatched samples")
    parser.add_argument("--focus-packer", action="store_true",
                        help="Only report packer/protector decision mismatches")
    args = parser.parse_args()

    corpus_dir = CORPUS_BASE / args.category
    if not corpus_dir.is_dir():
        log(f"ERROR: corpus dir not found: {corpus_dir}")
        sys.exit(1)

    if not UPSTREAM_DIEC.exists():
        log(f"ERROR: upstream diec not found: {UPSTREAM_DIEC}")
        sys.exit(1)

    if not DIE_RUST.exists():
        log(f"ERROR: die-rust not found: {DIE_RUST}")
        sys.exit(1)

    samples = sorted(corpus_dir.iterdir())
    samples = [s for s in samples if s.is_file()]
    total = len(samples)
    log(f"Corpus: {corpus_dir} ({total} files total)")

    samples = samples[args.offset: args.offset + args.limit]
    log(f"Scanning {len(samples)} samples (offset={args.offset})")

    results = []
    stats = {
        "total": 0,
        "detection_match": 0,
        "detection_mismatch": 0,
        "packer_match": 0,
        "packer_mismatch": 0,
        "upstream_errors": 0,
        "rust_errors": 0,
    }

    for i, sample in enumerate(samples):
        stats["total"] += 1
        r = scan_sample(sample)
        results.append(r)

        if r["detection_match"]:
            stats["detection_match"] += 1
        else:
            stats["detection_mismatch"] += 1

        if r["packer_decision_match"]:
            stats["packer_match"] += 1
        else:
            stats["packer_mismatch"] += 1

        if r["upstream_error"]:
            stats["upstream_errors"] += 1
        if r["rust_error"]:
            stats["rust_errors"] += 1

        # Print progress
        if (i + 1) % 10 == 0 or i == len(samples) - 1:
            log(f"  [{i+1}/{len(samples)}] match={stats['detection_match']} "
                f"mismatch={stats['detection_mismatch']} "
                f"packer_mismatch={stats['packer_mismatch']}")

        # Print mismatches inline
        should_print = True
        if args.only_mismatch and r["detection_match"]:
            should_print = False
        if args.focus_packer and r["packer_decision_match"]:
            should_print = False

        if should_print and not r["detection_match"]:
            log(f"  MISMATCH: {sample.name}")
            if r["only_upstream"]:
                log(f"    only_upstream: {r['only_upstream']}")
            if r["only_rust"]:
                log(f"    only_rust: {r['only_rust']}")
        if should_print and not r["packer_decision_match"]:
            log(f"  PACKER MISMATCH: {sample.name}")
            log(f"    upstream_packer={r['upstream_packer_detected']} "
                f"rust_packer={r['rust_packer_detected']}")

    # Summary
    log("=" * 60)
    log(f"SUMMARY: {args.category} ({len(samples)} samples)")
    log(f"  Detection match:    {stats['detection_match']}/{stats['total']} "
        f"({100*stats['detection_match']/max(stats['total'],1):.1f}%)")
    log(f"  Detection mismatch: {stats['detection_mismatch']}/{stats['total']}")
    log(f"  Packer match:       {stats['packer_match']}/{stats['total']} "
        f"({100*stats['packer_match']/max(stats['total'],1):.1f}%)")
    log(f"  Packer mismatch:    {stats['packer_mismatch']}/{stats['total']}")
    log(f"  Upstream errors:    {stats['upstream_errors']}")
    log(f"  Rust errors:        {stats['rust_errors']}")

    if args.output:
        out = {
            "category": args.category,
            "sample_count": len(samples),
            "offset": args.offset,
            "stats": stats,
            "results": results,
        }
        Path(args.output).write_text(json.dumps(out, indent=2, default=str))
        log(f"Results written to {args.output}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generate the Tauri updater `latest.json` manifest from built updater
artifacts.

Scans per-OS artifact directories (as downloaded from CI artifacts) for
the updater payloads and their `.sig` sidecars produced by
`cargo tauri build` with `TAURI_SIGNING_PRIVATE_KEY` set:

- Linux:   `*.AppImage.tar.gz` + `*.AppImage.tar.gz.sig`
- macOS:   `*.app.tar.gz` + `*.app.tar.gz.sig`
- Windows: `*.nsis.zip` (v1-compatible) or `*-setup.exe` (v2) + `.sig`

Usage:

  gen_latest_json.py <artifacts-root> <tag> <owner/repo> <out-file>

Example:

  gen_latest_json.py artifacts v0.9.1 chennqqi/diec-rust latest.json
"""

import base64
import json
import pathlib
import re
import sys
from datetime import datetime, timezone

# artifact dir substring -> updater platform key
PLATFORMS = {
    "linux": "linux-x86_64",
    "windows": "windows-x86_64",
    "macos": "darwin-aarch64",
}

# payload filename patterns in priority order per platform
PATTERNS = {
    "linux-x86_64": [r".*\.AppImage\.tar\.gz$"],
    "darwin-aarch64": [r".*\.app\.tar\.gz$"],
    "windows-x86_64": [r".*\.nsis\.zip$", r".*-setup\.exe$"],
}


def find_payload(dir_path: pathlib.Path, platform: str) -> pathlib.Path | None:
    files = sorted(p for p in dir_path.iterdir() if p.is_file())
    for pattern in PATTERNS[platform]:
        rx = re.compile(pattern, re.IGNORECASE)
        matches = [p for p in files if rx.match(p.name) and not p.name.endswith(".sig")]
        if matches:
            return matches[0]
    return None


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__)
        return 2
    root, tag, repo, out_file = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    root = pathlib.Path(root)
    version = tag.lstrip("v")
    base_url = f"https://github.com/{repo}/releases/download/{tag}"

    platforms: dict[str, dict[str, str]] = {}
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        os_key = next((k for k in PLATFORMS if k in entry.name.lower()), None)
        if os_key is None:
            continue
        platform = PLATFORMS[os_key]
        payload = find_payload(entry, platform)
        if payload is None:
            print(f"WARN: no updater payload in {entry.name}", file=sys.stderr)
            continue
        sig_file = payload.with_name(payload.name + ".sig")
        if not sig_file.exists():
            print(f"WARN: missing signature {sig_file.name}", file=sys.stderr)
            continue
        # The manifest signature is the base64 of the ENTIRE .sig file
        # text (untrusted comment + signature + trusted comment + global
        # signature) — the format tauri-plugin-updater parses.
        signature = base64.b64encode(
            sig_file.read_bytes()
        ).decode()
        platforms[platform] = {
            "signature": signature,
            "url": f"{base_url}/{payload.name}",
        }
        print(f"{platform}: {payload.name}")

    if not platforms:
        print("ERROR: no updater artifacts found", file=sys.stderr)
        return 1

    manifest = {
        "version": f"v{version}",
        "notes": f"diec-rust {version}",
        "pub_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platforms": platforms,
    }
    pathlib.Path(out_file).write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {out_file} ({len(platforms)} platforms)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

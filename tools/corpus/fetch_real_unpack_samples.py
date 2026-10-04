#!/usr/bin/env python3
"""Fetch the real-world packed samples listed in
corpus/real-unpack/manifest.json into corpus/real-unpack/.

The samples are third-party binaries (official packer distributions and a
public test corpus) and are not committed to the repository. Each download
is verified against the manifest sha256 before extraction.
"""
import hashlib
import json
import pathlib
import sys
import urllib.request
import zipfile
import io

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
DEST = ROOT / "corpus" / "real-unpack"
MANIFEST = DEST / "manifest.json"

# name -> (url, member inside zip or None)
FETCHERS = {
    "petite23-petite.exe": (
        "https://www.un4seen.com/files/petite23.zip", "petite.exe"),
    "petite23-petgui.exe": (
        "https://www.un4seen.com/files/petite23.zip", "petgui.exe"),
    "lbop20-petite.exe": (
        "https://raw.githubusercontent.com/unipacker/unipacker/master/Sample/PEtite/lbop20_PEtite.exe", None),
    "lbop20-aspack.exe": (
        "https://raw.githubusercontent.com/unipacker/unipacker/master/Sample/ASPack/lbop20_aspack.exe", None),
    "installsimple-2024-setup.exe": (
        "http://installsimple.com/download/install-simple.zip", "Setup.exe"),
    "installsimple-2013-setup.exe": (
        "https://web.archive.org/web/20130924210723id_/http://www.installsimple.com/download/install-simple.zip", "Setup.exe"),
}


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    wanted = {s["name"]: s for s in manifest["samples"]}
    cache: dict[str, bytes] = {}
    ok = True
    for name, spec in wanted.items():
        url, member = FETCHERS[name]
        if url not in cache:
            print(f"downloading {url}")
            cache[url] = fetch(url)
        blob = cache[url]
        if member is not None:
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                data = z.read(member)
        else:
            data = blob
        digest = hashlib.sha256(data).hexdigest()
        if digest != spec["sha256"] or len(data) != spec["size"]:
            print(f"MISMATCH {name}: sha256 {digest} size {len(data)}")
            ok = False
            continue
        (DEST / name).write_bytes(data)
        print(f"ok {name} ({len(data)} bytes)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

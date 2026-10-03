#!/usr/bin/env python3
"""Phase 48 tooling — dev Ed25519 updater key + signed update fixtures.

The updater plugin (`tauri-plugin-updater`, minisign) expects:

- `plugins.updater.pubkey` in `tauri.conf.json`: base64 of the `.pub`
  file text ("untrusted comment: ...\\n<base64 payload>\\n").
- Manifest `signature`: base64 of the `.sig` file text
  ("untrusted comment: ...\\n<74B payload b64>\\ntrusted comment:
  <text>\\n<global-sig b64>\\n").

Payload layout (non-prehashed "Ed" mode): `b"Ed" || key_id(8) || X`
where the signature is Ed25519 over the raw artifact and the global
signature is Ed25519 over `sig || trusted_comment_text`.

Usage:

  tools/gen_updater_dev.py keygen      # create tools/updater/dev.key
  tools/gen_updater_dev.py pubkey      # print tauri.conf.json pubkey
  tools/gen_updater_dev.py fixture <version> <artifact> <outdir>
                                       # emit latest.json + artifact +
                                       # .sig text into <outdir>
  tools/gen_updater_dev.py sig <version> <artifact>
                                       # print the manifest signature

`tools/updater/dev.key` is gitignored — private keys never enter the
repo. Fixtures committed under `corpus/updater/` are reproducible only
with this dev key; regenerating the key requires regenerating fixtures
and the pubkey in `tauri.conf.json` together.
"""

import argparse
import base64
import json
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

ROOT = Path(__file__).resolve().parent.parent
KEY_PATH = ROOT / "tools/updater/dev.key"
KEY_ID = b"diecdev1"  # 8-byte minisign key id


def load_key() -> Ed25519PrivateKey:
    seed = bytes.fromhex(KEY_PATH.read_text().strip())
    return Ed25519PrivateKey.from_private_bytes(seed)


def cmd_keygen() -> None:
    if KEY_PATH.exists():
        print(f"key exists: {KEY_PATH} (delete to regenerate)", file=sys.stderr)
        return
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    KEY_PATH.write_text(seed.hex() + "\n")
    KEY_PATH.chmod(0o600)
    print(f"wrote {KEY_PATH} (mode 600, gitignored)")


def pub_payload(sk: Ed25519PrivateKey) -> bytes:
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b"Ed" + KEY_ID + pk


def pub_text(sk: Ed25519PrivateKey) -> str:
    b64 = base64.b64encode(pub_payload(sk)).decode()
    return f"untrusted comment: diec-rust dev updater key\n{b64}\n"


def cmd_pubkey() -> None:
    print(base64.b64encode(pub_text(load_key()).encode()).decode())


def sign_artifact(sk: Ed25519PrivateKey, artifact: bytes, version: str) -> str:
    """Return the `.sig` file text for `artifact` (Ed25519, "Ed" mode)."""
    sig = sk.sign(artifact)
    bin1 = b"Ed" + KEY_ID + sig
    trusted = f"timestamp:0\tversion:{version}"
    global_sig = sk.sign(sig + trusted.encode())
    b64 = base64.b64encode
    return (
        "untrusted comment: signature from diec-rust dev key\n"
        + b64(bin1).decode()
        + "\ntrusted comment: "
        + trusted
        + "\n"
        + b64(global_sig).decode()
        + "\n"
    )


def cmd_fixture(version: str, artifact: Path, outdir: Path) -> None:
    sk = load_key()
    data = artifact.read_bytes()
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "update.bin").write_bytes(data)
    sig_text = sign_artifact(sk, data, version)
    (outdir / "update.sig.txt").write_text(sig_text)
    manifest = {
        "version": version,
        "notes": "dev update fixture",
        "pub_date": "2026-10-12T00:00:00Z",
        "platforms": {
            "linux-x86_64": {
                "signature": base64.b64encode(sig_text.encode()).decode(),
                "url": "http://127.0.0.1:0/update.bin",
            }
        },
    }
    (outdir / "latest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote fixtures to {outdir}")


def cmd_sig(version: str, artifact: Path) -> None:
    sig_text = sign_artifact(load_key(), artifact.read_bytes(), version)
    print(base64.b64encode(sig_text.encode()).decode())


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    sub.add_parser("pubkey")
    fx = sub.add_parser("fixture")
    fx.add_argument("version")
    fx.add_argument("artifact", type=Path)
    fx.add_argument("outdir", type=Path)
    sg = sub.add_parser("sig")
    sg.add_argument("version")
    sg.add_argument("artifact", type=Path)
    args = p.parse_args()
    if args.cmd == "keygen":
        cmd_keygen()
    elif args.cmd == "pubkey":
        cmd_pubkey()
    elif args.cmd == "fixture":
        cmd_fixture(args.version, args.artifact, args.outdir)
    elif args.cmd == "sig":
        cmd_sig(args.version, args.artifact)
    return 0


if __name__ == "__main__":
    sys.exit(main())

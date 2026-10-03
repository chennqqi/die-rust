#!/usr/bin/env python3
"""Phase 45 i18n tooling — split inline locales to JSON and generate
terminology-anchored draft catalogs.

Sources of truth:
  - English catalog: frontend/src/i18n/locales/en.json (canonical keys)
  - Existing locales: extracted from the legacy inline blocks in
    config.ts (first run) or kept from locales/*.json afterwards
  - Terminology anchors: upstream XTranslation dicts
    (upstream/DIE-engine/dep/XTranslation/dicts/dict_*.po)

Anchor policy (deliberately conservative — ADR 0038/0042):
  - A locale value is translated ONLY when the English value matches a
    glossary msgid exactly (after whitespace normalization). Upstream
    Qt .ts catalogs are 100% unfinished skeletons and provide no
    strings; multi-word msgids do cover short phrases.
  - Every other value keeps the English text and is recorded in
    <lang>.draft.json as a machine-auditable draft. No pseudo-translation
    via in-sentence term substitution.

Usage:
  python3 tools/i18n/gen_locales.py           # full run: split + drafts
  python3 tools/i18n/gen_locales.py --check   # no writes; report only
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONFIG_TS = REPO / "crates/die-gui/frontend/src/i18n/config.ts"
LOCALES_DIR = REPO / "crates/die-gui/frontend/src/i18n/locales"
DICTS_DIR = REPO / "upstream/DIE-engine/dep/XTranslation/dicts"

# Upstream dict file stem -> our locale code.
LOCALE_MAP = {
    "ar": "ar", "bn": "bn", "de": "de", "en": "en", "es": "es",
    "fa": "fa", "fr": "fr", "he": "he", "hi_IN": "hi-IN", "id": "id",
    "it": "it", "ja": "ja", "ko": "ko", "pl": "pl", "pt-BR": "pt-BR",
    "pt-PT": "pt-PT", "ru": "ru", "sq": "sq", "sv": "sv", "tr": "tr",
    "uk": "uk", "vi": "vi", "zh": "zh-CN", "zh-TW": "zh-TW",
}

EXISTING = ["en", "zh-CN", "ru", "de", "fr"]


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t\n":
        i += 1
    return i


def _parse_string(s: str, i: int) -> tuple[str, int]:
    """Parse a JS double-quoted string literal at s[i]=='"'."""
    assert s[i] == '"'
    i += 1
    out = []
    while i < len(s):
        c = s[i]
        if c == '"':
            return "".join(out), i + 1
        if c == "\\":
            i += 1
            esc = s[i]
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(esc, esc))
            i += 1
            continue
        out.append(c)
        i += 1
    raise ValueError("unterminated string")


def parse_ts_object(s: str, i: int) -> tuple[dict, int]:
    """Parse `{ ... }` JS object literal of nested objects/strings."""
    assert s[i] == "{"
    i += 1
    obj: dict = {}
    while True:
        i = _skip_ws(s, i)
        if s[i] == "}":
            return obj, i + 1
        if s[i] == '"':
            key, i = _parse_string(s, i)
        else:
            m = re.match(r"[A-Za-z_$][\w$-]*", s[i:])
            if not m:
                raise ValueError(f"bad key at {i}: {s[i:i+30]!r}")
            key = m.group(0)
            i += len(key)
        i = _skip_ws(s, i)
        assert s[i] == ":", f"expected ':' at {i}"
        i = _skip_ws(s, i + 1)
        if s[i] == "{":
            val, i = parse_ts_object(s, i)
        elif s[i] == '"':
            val, i = _parse_string(s, i)
        else:
            raise ValueError(f"bad value at {i}: {s[i:i+30]!r}")
        obj[key] = val
        i = _skip_ws(s, i)
        if s[i] == ",":
            i += 1


def extract_locales(config: str) -> dict[str, dict]:
    """Extract each `code: { translation: {...} }` block."""
    locales: dict[str, dict] = {}
    for m in re.finditer(r'^    ("?)([\w-]+)\1:\s*{\s*\n?\s*translation:\s*', config, re.M):
        code = m.group(2)
        i = _skip_ws(config, m.end())
        if config[i] != "{":
            continue
        obj, _ = parse_ts_object(config, i)
        locales[code] = obj
    return locales


def parse_po(path: Path) -> dict[str, str]:
    """Parse msgid/msgstr pairs (single-line values only are kept;
    multi-line msgids concatenate per .po rules)."""
    terms: dict[str, str] = {}
    msgid: str | None = None
    msgstr: str | None = None
    cur: str | None = None

    def commit():
        nonlocal msgid, msgstr
        if msgid and msgstr:
            terms[_norm(msgid)] = msgstr
        msgid, msgstr = None, None

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("msgid "):
            commit()
            msgid = _po_str(line[6:])
            cur = "msgid"
        elif line.startswith("msgstr "):
            msgstr = _po_str(line[7:])
            cur = "msgstr"
        elif line.startswith('"') and cur is not None:
            if cur == "msgid" and msgid is not None:
                msgid += _po_str(line)
            elif cur == "msgstr" and msgstr is not None:
                msgstr += _po_str(line)
        else:
            cur = None
    commit()
    return terms


def _po_str(chunk: str) -> str:
    chunk = chunk.strip()
    if chunk.startswith('"') and chunk.endswith('"'):
        inner = chunk[1:-1]
        return inner.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
    return ""


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip()).lower()


def flatten(obj: dict, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in obj.items():
        p = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if isinstance(v, dict):
            out.update(flatten(v, p))
        else:
            out[p] = v
    return out


def unflatten(flat: dict[str, str]) -> dict:
    root: dict = {}
    for path, val in flat.items():
        node = root
        parts = path.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = val
    return root


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report only, write nothing")
    args = ap.parse_args()

    src_locales: dict[str, dict] = {}
    if all((LOCALES_DIR / f"{c}.json").exists() for c in EXISTING):
        for c in EXISTING:
            src_locales[c] = json.loads((LOCALES_DIR / f"{c}.json").read_text("utf-8"))
        print("locales/*.json already present — using them as source")
    else:
        src_locales = extract_locales(CONFIG_TS.read_text("utf-8"))
        missing = [c for c in EXISTING if c not in src_locales]
        if missing:
            print(f"ERROR: failed to extract locales: {missing}", file=sys.stderr)
            return 1
        print(f"extracted from config.ts: {sorted(src_locales)}")

    en = src_locales["en"]
    en_flat = flatten(en)
    print(f"en catalog: {len(en_flat)} keys")

    for code in EXISTING:
        flat = flatten(src_locales[code])
        diff = set(en_flat) ^ set(flat)
        if diff:
            print(f"WARNING: {code} key-parity gap: {sorted(diff)[:5]}... ({len(diff)})")

    glossaries: dict[str, dict[str, str]] = {}
    for stem, code in LOCALE_MAP.items():
        po = DICTS_DIR / f"dict_{stem}.po"
        if po.exists():
            glossaries[code] = parse_po(po)

    new_codes = [c for c in LOCALE_MAP.values() if c not in EXISTING]
    stats = {}
    writes: dict[Path, str] = {}
    for code in sorted(new_codes):
        glossary = glossaries.get(code, {})
        flat: dict[str, str] = {}
        drafts: list[str] = []
        anchored = 0
        for path, val in en_flat.items():
            hit = glossary.get(_norm(val))
            if hit and hit != val:
                flat[path] = hit
                anchored += 1
            else:
                # Untranslated glossary entries (msgstr == msgid) count
                # as drafts, not anchors — the value stays English.
                flat[path] = val
                drafts.append(path)
        stats[code] = (anchored, len(en_flat))
        catalog = unflatten(flat)
        writes[LOCALES_DIR / f"{code}.json"] = json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        writes[LOCALES_DIR / f"{code}.draft.json"] = json.dumps(
            {"drafts": sorted(drafts), "same": []}, ensure_ascii=False, indent=2) + "\n"

    for code, (anch, total) in sorted(stats.items()):
        print(f"{code:6s}: anchored {anch:3d}/{total} ({100*anch/total:.1f}%)")

    if args.check:
        return 0
    LOCALES_DIR.mkdir(parents=True, exist_ok=True)
    for code in EXISTING:
        if not (LOCALES_DIR / f"{code}.json").exists():
            writes[LOCALES_DIR / f"{code}.json"] = json.dumps(
                src_locales[code], ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        # Reviewed locales: English-identical values are intentional
        # cognates/proper nouns — record them in `same`, not `drafts`.
        flat = flatten(src_locales[code])
        same = sorted(p for p, v in flat.items() if v == en_flat[p])
        writes[LOCALES_DIR / f"{code}.draft.json"] = json.dumps(
            {"drafts": [], "same": same}, ensure_ascii=False, indent=2) + "\n"
    for path, text in writes.items():
        path.write_text(text, encoding="utf-8")
    print(f"wrote {len(writes)} files to {LOCALES_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

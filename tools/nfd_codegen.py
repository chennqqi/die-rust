#!/usr/bin/env python3
"""Generate Rust static tables from SpecAbstract C++ signature arrays.

Upstream source: upstream/DIE-engine/dep/SpecAbstract (MIT license,
horsicq). Locked commit is recorded in upstream/components.lock.toml.

Parses:
  - XScanEngine/xscanengine.cpp  : RECORD_NAME / RECORD_TYPE -> display strings
  - Formats/exec/xpe_def.h       : S_RT_* constants used by PE_RESOURCES_RECORD
  - SpecAbstract/modules/*.cpp   : *_records[] arrays (SIGNATURE_RECORD,
                                   STRING_RECORD, CONST_RECORD,
                                   PE_RESOURCES_RECORD, MSRICH_RECORD)

Output: crates/die-nfd/src/gen_tables.rs and gen_names.rs
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEP = os.path.join(REPO, "upstream", "DIE-engine", "dep")
SPEC = os.path.join(DEP, "SpecAbstract", "modules")
XSE = os.path.join(DEP, "XScanEngine", "xscanengine.cpp")
XPE_DEF = os.path.join(DEP, "Formats", "exec", "xpe_def.h")
OUT_DIR = os.path.join(REPO, "crates", "die-nfd", "src")


def read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def strip_comments(src):
    """Remove // and /* */ comments while preserving string literals."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        elif c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                i += 1
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def split_top_commas(s):
    """Split on top-level commas, respecting strings and nested braces."""
    parts, depth, cur, i, n = [], 0, [], 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            cur.append(s[i:j + 1])
            i = j + 1
            continue
        if c in "{([":
            depth += 1
        elif c in "})]":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def extract_array(src, ctype, name):
    """Return the body text of `CTYPE NAME[] = { ... };`."""
    pat = re.compile(re.escape(ctype) + r"\s+(?:\w+::)?" + re.escape(name) +
                     r"\s*\[\]\s*=\s*\{")
    m = pat.search(src)
    if not m:
        return None
    i = m.end()
    depth = 1
    j = i
    n = len(src)
    while j < n and depth:
        c = src[j]
        if c == '"':
            j += 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            j += 1
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        j += 1
    return src[i:j - 1]


def split_records(body):
    """Split an array body into top-level {...} record strings."""
    recs, i, n = [], 0, len(body)
    while i < n:
        if body[i] == "{":
            depth, j = 1, i + 1
            while j < n and depth:
                c = body[j]
                if c == '"':
                    j += 1
                    while j < n and body[j] != '"':
                        j += 2 if body[j] == "\\" else 1
                    j += 1
                    continue
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                j += 1
            recs.append(body[i + 1:j - 1])
            i = j
        else:
            i += 1
    return recs


def parse_c_string(tok):
    """Unquote and unescape C string literal(s); adjacent "a" "b" concatenate."""
    tok = tok.strip()
    lits = re.findall(r'"((?:[^"\\]|\\.)*)"', tok)
    if not lits:
        return None
    inner = "".join(lits)
    out = []
    i = 0
    while i < len(inner):
        c = inner[i]
        if c == "\\" and i + 1 < len(inner):
            nxt = inner[i + 1]
            table = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\",
                     '"': '"', "'": "'"}
            if nxt in table:
                out.append(table[nxt])
                i += 2
            elif nxt == "x":
                m = re.match(r"\\x([0-9a-fA-F]{1,2})", inner[i:])
                out.append(chr(int(m.group(1), 16)))
                i += 1 + len(m.group(0)) - 1
            else:
                out.append(nxt)
                i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def rust_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace(
        "\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'


def parse_const(tok, consts):
    tok = tok.strip()
    # Strip C-style casts like (quint32)-1
    tok = re.sub(r"^\(\w+\)\s*", "", tok)
    if tok in consts:
        return consts[tok]
    tok = tok.split("::")[-1]
    if tok in consts:
        return consts[tok]
    return int(tok, 0)


def enum_tail(tok):
    return tok.strip().split("::")[-1]


# ---------------------------------------------------------------- enum tables

def parse_xse_names():
    src = strip_comments(read(XSE))
    names, types = {}, {}
    m = re.search(r"_TABLE_XScanEngine_RECORD_NAME\[\]\s*=\s*\{", src)
    body = extract_array(src, "XBinary::XCONVERT", "_TABLE_XScanEngine_RECORD_NAME")
    if body is None:
        start = src.index("_TABLE_XScanEngine_RECORD_NAME[] = {") 
        start = src.index("{", start)
        depth, j = 1, start + 1
        while depth:
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
            j += 1
        body = src[start + 1:j - 1]
    for rec in split_records(body):
        fields = split_top_commas(rec)
        en = enum_tail(fields[0])
        disp = parse_c_string(fields[1])
        if disp is None:
            disp = fields[1].strip()
        names[en] = disp

    m2 = re.search(r"_TABLE_XScanEngine_RECORD_TYPE\[\]\s*=\s*\{", src)
    start = src.index("{", m2.end() - 1)
    depth, j = 1, start + 1
    while depth:
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
        j += 1
    tbody = src[start + 1:j - 1]
    for rec in split_records(tbody):
        fields = split_top_commas(rec)
        en = enum_tail(fields[0])
        disp = parse_c_string(fields[1])
        if disp is None:
            disp = fields[1].strip().strip('"')
        types[en] = disp
    return names, types


def parse_xpe_def_consts():
    src = strip_comments(read(XPE_DEF))
    consts = {}
    for m in re.finditer(r"const\s+(?:quint32|quint16|qint32)\s+(S_\w+)\s*=\s*(-?0x[0-9a-fA-F]+|-?\d+)", src):
        consts[m.group(1)] = int(m.group(2), 0) & 0xFFFFFFFF
    return consts


# -------------------------------------------------------------- record tables

REC_TYPES = ("SIGNATURE_RECORD", "STRING_RECORD", "CONST_RECORD",
             "PE_RESOURCES_RECORD", "MSRICH_RECORD")


def find_arrays(src):
    """Yield (ctype, name) for each `CTYPE name[] = {` in the source."""
    pat = re.compile(
        r"(?<![A-Za-z_])(?:NFD_Binary::)?(" + "|".join(REC_TYPES) +
        r")\s+(\w+)\s*\[\]\s*=\s*\{")
    return [(m.group(1), m.group(2)) for m in pat.finditer(src)]


def parse_basic(fields):
    """Parse the {_BASICINFO} first field: {v, FT, TYPE, NAME, "ver", "info"}."""
    f0 = fields[0].strip()
    assert f0.startswith("{"), f0[:40]
    inner = f0[1:f0.rindex("}")].strip()
    bf = split_top_commas(inner)
    assert len(bf) == 6, (bf, inner[:80])
    return {
        "variant": int(bf[0].strip(), 0),
        "ft": enum_tail(bf[1]),
        "rtype": enum_tail(bf[2]),
        "name": enum_tail(bf[3]),
        "version": parse_c_string(bf[4]) or "",
        "info": parse_c_string(bf[5]) or "",
    }


def collect_tables(consts):
    tables = []  # (rust_name, ctype, [records])
    for fn in sorted(os.listdir(SPEC)):
        if not fn.endswith(".cpp"):
            continue
        src = strip_comments(read(os.path.join(SPEC, fn)))
        for ctype, name in find_arrays(src):
            body = extract_array(src, ctype, name)
            if body is None:
                print(f"WARN: cannot extract {name} in {fn}", file=sys.stderr)
                continue
            recs = []
            for rec in split_records(body):
                fields = split_top_commas(rec)
                try:
                    basic = parse_basic(fields)
                except AssertionError as e:
                    print(f"WARN: bad record in {fn}:{name}: {e}",
                          file=sys.stderr)
                    continue
                rest = fields[1:]
                if ctype == "SIGNATURE_RECORD":
                    sig = parse_c_string(rest[0])
                    assert sig is not None, (fn, name, rest[0][:60])
                    recs.append((basic, sig))
                elif ctype == "STRING_RECORD":
                    st = parse_c_string(rest[0])
                    assert st is not None, (fn, name, rest[0][:60])
                    recs.append((basic, st))
                elif ctype == "CONST_RECORD":
                    recs.append((basic, parse_const(rest[0], consts) & 0xFFFFFFFFFFFFFFFF,
                                 parse_const(rest[1], consts) & 0xFFFFFFFFFFFFFFFF))
                elif ctype == "MSRICH_RECORD":
                    recs.append((basic, parse_const(rest[0], consts) & 0xFFFF,
                                 parse_const(rest[1], consts) & 0xFFFFFFFF))
                elif ctype == "PE_RESOURCES_RECORD":
                    is_s1 = rest[0].strip() == "true"
                    nm1 = parse_c_string(rest[1]) or ""
                    id1 = parse_const(rest[2], consts) & 0xFFFFFFFF
                    is_s2 = rest[3].strip() == "true"
                    nm2 = parse_c_string(rest[4]) or ""
                    id2 = parse_const(rest[5], consts) & 0xFFFFFFFF
                    recs.append((basic, is_s1, nm1, id1, is_s2, nm2, id2))
            tables.append((name, ctype, recs, fn))
    return tables


# ------------------------------------------------------------------ emission

def emit():
    names, types = parse_xse_names()
    consts = parse_xpe_def_consts()
    tables = collect_tables(consts)

    # Assign indices: names/types get dense u16/u8 ids.
    name_list = sorted(names)
    name_idx = {n: i for i, n in enumerate(name_list)}
    type_list = sorted(types)
    type_idx = {n: i for i, n in enumerate(type_list)}

    fts = {r[0]["ft"] for _, _, recs, _ in tables for r in recs}
    # Include every XBinary::FT_* enum member so engine-side constants exist.
    xh = read(os.path.join(DEP, "Formats", "xbinary.h"))
    start = xh.index("enum FT {")
    end = xh.index("};", start)
    for m in re.finditer(r"\b(FT_[A-Z0-9_]+)", xh[start:end]):
        fts.add(m.group(1))
    fts = sorted(fts)
    ft_idx = {n: i for i, n in enumerate(fts)}

    missing_types = {r[0]["rtype"] for _, _, recs, _ in tables for r in recs
                     if r[0]["rtype"] not in type_idx}
    missing_names = {r[0]["name"] for _, _, recs, _ in tables for r in recs
                     if r[0]["name"] not in name_idx}
    # RECORD_NAME ids referenced by handler code (not by signature tables or
    # the upstream display-name table), e.g. the binary promotion layer.
    missing_names |= {
        "RECORD_NAME_LZIP",
        "RECORD_NAME_LZMA",
        "RECORD_NAME_SKATERNET",
    }
    for n in sorted(missing_names):
        name_idx[n] = len(name_list)
        name_list.append(n)
    for t in sorted(missing_types):
        type_idx[t] = len(type_list)
        type_list.append(t)

    total = sum(len(r) for _, _, r, _ in tables)
    os.makedirs(OUT_DIR, exist_ok=True)

    # ---------------- gen_names.rs ----------------
    with open(os.path.join(OUT_DIR, "gen_names.rs"), "w") as f:
        f.write("//! Auto-generated by tools/nfd_codegen.py from\n")
        f.write("//! upstream/DIE-engine/dep/SpecAbstract @ 5188e047 (MIT, horsicq).\n")
        f.write("//! Do not edit; regenerate with `python3 tools/nfd_codegen.py`.\n\n")
        f.write("#![allow(missing_docs)]\n\n")
        f.write("/// Display strings for RECORD_NAME (index = u16 id).\n")
        f.write("pub static RECORD_NAME_STR: &[&str] = &[\n")
        for n in name_list:
            f.write(f"    {rust_str(names.get(n, n))},\n")
        f.write("];\n\n")
        f.write("/// Display strings for RECORD_TYPE (index = u8 id).\n")
        f.write("pub static RECORD_TYPE_STR: &[&str] = &[\n")
        for t in type_list:
            f.write(f"    {rust_str(types.get(t, t))},\n")
        f.write("];\n\n")
        f.write("/// Enum ordinal for XBinary::FT used by tables (index = u8 id).\n")
        f.write("pub static FT_STR: &[&str] = &[\n")
        for t in fts:
            f.write(f"    {rust_str(t)},\n")
        f.write("];\n\n")
        f.write("/// Named constants for RECORD_NAME ids used by heuristic code.\n")
        f.write("pub mod name {\n")
        for n in name_list:
            f.write(f"    pub const {n}: u16 = {name_idx[n]};\n")
        f.write("}\n\n")
        f.write("pub mod rtype {\n")
        for t in type_list:
            f.write(f"    pub const {t}: u8 = {type_idx[t]};\n")
        f.write("}\n\n")
        f.write("pub mod ft {\n")
        for t in fts:
            f.write(f"    pub const {t}: u16 = {ft_idx[t]};\n")
        f.write("}\n")

    # ---------------- gen_tables.rs ----------------
    with open(os.path.join(OUT_DIR, "gen_tables.rs"), "w") as f:
        f.write("//! Auto-generated by tools/nfd_codegen.py from\n")
        f.write("//! upstream/DIE-engine/dep/SpecAbstract @ 5188e047 (MIT, horsicq).\n")
        f.write("//! Do not edit; regenerate with `python3 tools/nfd_codegen.py`.\n\n")
        f.write("#![allow(missing_docs)]\n\n")
        f.write("use crate::records::*;\n")
        f.write("use crate::gen_names::{ft, name, rtype};\n\n")
        for tname, ctype, recs, srcfn in tables:
            rust_ty = {
                "SIGNATURE_RECORD": "SignatureRecord",
                "STRING_RECORD": "StringRecord",
                "CONST_RECORD": "ConstRecord",
                "PE_RESOURCES_RECORD": "ResourcesRecord",
                "MSRICH_RECORD": "MsRichRecord",
            }[ctype]
            rn = tname.upper().lstrip("_")
            f.write(f"/// From modules/{srcfn}:{tname} ({len(recs)} records).\n")
            f.write(f"pub static {rn}: &[{rust_ty}] = &[\n")
            for rec in recs:
                b = rec[0]
                base = (f"BasicRecord {{ variant: {b['variant']}, "
                        f"ft: ft::{b['ft']}, rtype: rtype::{b['rtype']}, "
                        f"name: name::{b['name']}, version: {rust_str(b['version'])}, "
                        f"info: {rust_str(b['info'])} }}")
                if ctype == "SIGNATURE_RECORD":
                    f.write(f"    SignatureRecord {{ basic: {base}, signature: {rust_str(rec[1])} }},\n")
                elif ctype == "STRING_RECORD":
                    f.write(f"    StringRecord {{ basic: {base}, string: {rust_str(rec[1])} }},\n")
                elif ctype == "CONST_RECORD":
                    f.write(f"    ConstRecord {{ basic: {base}, const1: {rec[1]}, const2: {rec[2]} }},\n")
                elif ctype == "MSRICH_RECORD":
                    f.write(f"    MsRichRecord {{ basic: {base}, id: {rec[1]}, build: {rec[2]} }},\n")
                elif ctype == "PE_RESOURCES_RECORD":
                    _, s1, n1, i1, s2, n2, i2 = rec
                    f.write(f"    ResourcesRecord {{ basic: {base}, is_string1: {str(s1).lower()}, "
                            f"name1: {rust_str(n1)}, id1: {i1}, is_string2: {str(s2).lower()}, "
                            f"name2: {rust_str(n2)}, id2: {i2} }},\n")
            f.write("];\n\n")

    print(f"tables={len(tables)} records={total} names={len(name_list)} "
          f"types={len(type_list)} fts={len(fts)}")
    if missing_names:
        print(f"note: {len(missing_names)} RECORD_NAME ids missing display "
              "strings (use enum token as fallback)")


if __name__ == "__main__":
    emit()

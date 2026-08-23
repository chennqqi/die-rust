#!/usr/bin/env python3
"""Host API coverage matrix generator — Phase 15.3a.

Parses upstream DIE-engine help docs (*.md) to extract method signatures,
then scans host_api_bridge.rs for implemented methods, and outputs a
coverage matrix to docs/research/host-api-coverage-matrix.md.

Usage:
    python3 tools/audit_host_api.py
"""

import re
import os
import sys
from pathlib import Path
from collections import defaultdict


def find_workspace_root() -> Path:
    """Find the workspace root by looking for the upstream directory."""
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "upstream" / "Detect-It-Easy").is_dir():
            return p
        p = p.parent
    raise RuntimeError("Cannot find workspace root")


def parse_help_docs(help_dir: Path) -> dict[str, list[str]]:
    """Parse help/*.md files to extract method names per class.

    Returns {class_name: [method_name, ...]}.
    """
    # Map help file names to class names.
    class_files = {
        "Binary": "Binary",
        "PE": "PE",
        "ELF": "ELF",
        "MACH": "MACH",
        "MSDOS": "MSDOS",
        "Util": "Util",
        "APK": "APK",
        "Archive": "Archive",
        "COM": "COM",
        "DEX": "DEX",
        "ISO9660": "ISO9660",
        "JAR": "JAR",
        "LE": "LE",
        "LX": "LX",
        "NE": "NE",
        "PYC": "PYC",
        "ZIP": "ZIP",
        "Global": "Global",
    }

    result = {}
    for cls_name, file_prefix in class_files.items():
        md_path = help_dir / f"{file_prefix}.md"
        if not md_path.exists():
            continue

        text = md_path.read_text(encoding="utf-8", errors="replace")
        # Pattern: `return_type methodName(params)` or `methodName(params)`
        # Also matches backtick-quoted method declarations.
        pattern = r'`(?:\w+\s+)?(\w+)\s*\([^)]*\)`'
        methods = re.findall(pattern, text)
        # Filter out non-method matches (keywords, types, etc.)
        skip_words = {
            "bool", "QString", "quint16", "quint32", "qint32", "qint64",
            "int", "void", "true", "false", "null", "return", "function",
            "var", "const", "let", "if", "else", "for", "while", "switch",
            "case", "break", "continue", "default", "try", "catch", "throw",
            "new", "delete", "typeof", "instanceof", "in", "of", "this",
            "PE", "ELF", "MACH", "MSDOS", "Binary", "Util", "APK",
            "Archive", "COM", "DEX", "ISO9660", "JAR", "LE", "LX", "NE",
            "PYC", "ZIP", "Global", "Image", "CFBF", "JavaClass",
            "Inherits", "Table", "Real", "File", "Format", "Section",
            "Import", "Export", "Resource", "Version", "Linker",
            "Properties", "Advanced", "Analysis", "Examples", "Detection",
            "Management", "Operations", "Information", "Support",
            "Contents", "Basic", "Overview", "Class", "Reference",
            "Data", "Directory", "Entry", "Point", "Overlay", "Signature",
            "Check", "String", "Table", "Hash", "Entropy", "Disasm",
            "Rich", "Signature", "Records", "Certificate", "Security",
        }
        methods = [m for m in methods if m not in skip_words and not m.startswith("_")]
        # Deduplicate while preserving order.
        seen = set()
        unique = []
        for m in methods:
            if m not in seen:
                seen.add(m)
                unique.append(m)
        result[cls_name] = unique

    return result


def parse_bridge_impl(bridge_path: Path) -> dict[str, set[str]]:
    """Parse host_api_bridge.rs to find implemented methods per class.

    Looks for patterns like:
        Binary.readByte = function(...)
        PE.isNet = function(...)
        MSDOS.compareEP = function(...)
        binary.set("getSize", get_size_fn)  (Rust registration)

    Returns {class_name: {method_name, ...}}.
    """
    text = bridge_path.read_text(encoding="utf-8", errors="replace")

    result = defaultdict(set)

    # Pattern 1: ClassName.methodName = function (JS assignment)
    pattern = r'(\w+)\.(\w+)\s*=\s*function'
    matches = re.findall(pattern, text)
    for cls, method in matches:
        result[cls].add(method)

    # Pattern 2: binary.set("methodName", ...) or obj.set("methodName", ...)
    # These are Rust-side registrations via rquickjs.
    set_pattern = r'\.set\("(\w+)"\s*,'
    set_matches = re.findall(set_pattern, text)
    for method in set_matches:
        result["Binary"].add(method)  # Most are on Binary/binary

    # Pattern 3: Inline JS object methods (e.g., var Util = { method: function() {...} })
    # Detect methods defined inside ctx.eval() JS blocks.
    inline_pattern = r'(\w+)\s*:\s*function\s*\('
    inline_matches = re.findall(inline_pattern, text)
    for method in inline_matches:
        # These are usually on Util or other global objects.
        # We can't easily determine the class, so add to a general set.
        result["_inline"].add(method)

    # Pattern 3: methods registered via batch JSON or Rust host API.
    if "pe_batch" in text or "__peBatch" in text:
        result["PE"].update(["isNet", "isNET", "getManifest", "isSignedFile",
                            "getFileVersion", "getVersionStringInfo",
                            "getNumberOfImports", "getImportLibraryName",
                            "getImportFunctionName", "isLibraryPresent",
                            "getNumberOfExportFunctions", "getExportFunctionName",
                            "isExportFunctionPresent", "getNumberOfRichIDs",
                            "getRichID", "getRichCount", "getRichVersion",
                            "isRichSignaturePresent", "getNumberOfResources",
                            "isResourceNamePresent", "isResourceGroupNamePresent",
                            "isResourceGroupIdPresent", "getNETVersion",
                            "getNumberOfSections", "getSectionName",
                            "getSectionFileOffset", "getSectionFileSize",
                            "isSectionNamePresent", "getElfHeader_type",
                            "getElfHeader_machine", "getElfHeader_entry"])

    return dict(result)


def classify_implementation(bridge_path: Path, cls: str, method: str) -> str:
    """Classify a method as 'implemented', 'stub', or 'missing'.

    stub = returns a constant (false, 0, "", -1) without calling host API.
    implemented = calls a host API function or does real computation.
    missing = not found in bridge.
    """
    text = bridge_path.read_text(encoding="utf-8", errors="replace")

    # Generate method name variants to search for.
    # Help docs use camelCase, bridge uses a mix of camelCase and snake_case.
    variants = [method]
    # camelCase → snake_case: readByte → read_byte
    snake = re.sub(r'([A-Z])', r'_\1', method).lower().lstrip('_')
    if snake != method:
        variants.append(snake)
    # snake_case → camelCase: read_byte → readByte
    camel = re.sub(r'_([a-z])', lambda m: m.group(1).upper(), method)
    if camel != method:
        variants.append(camel)

    # Also check parent class (Binary) for inherited methods.
    classes_to_check = [cls]
    if cls in ("PE", "ELF", "MACH", "MSDOS", "APK", "Archive", "COM",
               "DEX", "JAR", "ZIP", "NE", "LE", "LX", "ISO9660",
               "JavaClass", "PYC", "Image", "CFBF"):
        classes_to_check.append("Binary")
    if cls == "PE":
        classes_to_check.append("MSDOS")

    for check_cls in classes_to_check:
        for variant in variants:
            # Check for direct JS assignment with proper brace matching.
            # The old regex [^}}]* couldn't match nested braces.
            assign_pattern = rf'{check_cls}\.{variant}\s*=\s*function\s*\([^)]*\)\s*\{{'
            match = re.search(assign_pattern, text)
            if match:
                # Find the full function body by counting braces.
                brace_start = match.end() - 1  # Position of opening {
                depth = 0
                end = brace_start
                for i in range(brace_start, len(text)):
                    if text[i] == '{':
                        depth += 1
                    elif text[i] == '}':
                        depth -= 1
                        if depth == 0:
                            end = i
                            break
                body = text[brace_start:end + 1]
                # Check if body only returns constants (stub detection).
                # A stub has ALL return statements returning a constant AND
                # no real computation (no loops, conditionals, host API calls).
                returns = re.findall(r'return\s+([^;]+);', body)
                if returns:
                    constant_pattern = r'^(false|true|0|-1|""|\'\'|null|undefined)\s*$'
                    all_constants = all(
                        re.match(constant_pattern, r.strip())
                        for r in returns
                    )
                    # Even if all returns are constants, check for real logic:
                    # loops, conditionals, or function calls that indicate
                    # the function does real work (e.g., searching a list
                    # and returning true/false based on match).
                    has_real_logic = bool(
                        re.search(r'\b(for|while)\s*\(', body)
                        or re.search(r'\bif\s*\(.*\)\s*\{', body)
                        or re.search(r'\b_[a-zA-Z]', body)  # internal function calls
                        or re.search(r'\bBinary\.\w+\s*\(', body)
                        or re.search(r'\bPE\.\w+\s*\(', body)
                        or re.search(r'\bELF\.\w+\s*\(', body)
                    )
                    if all_constants and not has_real_logic:
                        return "stub"
                return "implemented"

            # Check for alias assignment (e.g., PE.isNET = PE.isNet).
            alias_pattern = rf'{check_cls}\.{variant}\s*=\s*\w+\.\w+'
            if re.search(alias_pattern, text):
                return "implemented"

            # Check for property/object assignment (e.g., Global.result = {...}).
            prop_pattern = rf'{check_cls}\.{variant}\s*=\s*\{{'
            if re.search(prop_pattern, text):
                return "implemented"
            # Check for null/literal assignment (e.g., Global.result = null).
            literal_pattern = rf'{check_cls}\.{variant}\s*=\s*(null|undefined|true|false|0|""|\'\')\s*;'
            if re.search(literal_pattern, text):
                return "stub"

            # Check for Rust-side registration via .set("methodName", ...)
            set_pattern = rf'\.set\("{variant}"\s*,'
            if re.search(set_pattern, text):
                return "implemented"

            # Check for inline JS object methods (e.g., var Util = { method: function() {...} }).
            inline_pattern = rf'{variant}\s*:\s*function\s*\('
            if re.search(inline_pattern, text):
                return "implemented"

    # Check for methods provided via batch JSON or Rust host API.
    batch_methods = {
        "isNet", "isNET", "getManifest", "isSignedFile",
        "getFileVersion", "getNumberOfImports",
        "getImportLibraryName", "getImportFunctionName",
        "isLibraryPresent", "getNumberOfExportFunctions",
        "getExportFunctionName", "isExportFunctionPresent",
        "getNumberOfRichIDs", "getRichID", "getRichCount",
        "getRichVersion", "isRichSignaturePresent",
        "getNumberOfResources", "isResourceNamePresent",
        "isResourceGroupNamePresent", "isResourceGroupIdPresent",
        "getNETVersion", "getNumberOfSections", "getSectionName",
        "getSectionFileOffset", "getSectionFileSize",
        "isSectionNamePresent", "getElfHeader_type",
        "getElfHeader_machine", "getElfHeader_entry",
        "getNumberOfPrograms", "getProgramFileOffset", "getProgramFileSize",
        "isStringInTablePresent", "is64",
        # Phase 15.6 additions
        "getSectionNumber", "getSectionNumberExp", "getSizeOfCode",
        "getSizeOfUninitializedData", "read_UUID", "read_UUID_bytes",
        "findWord", "findDword",
    }
    if method in batch_methods:
        return "implemented"

    # Check for methods implemented in host.rs (Rust native).
    host_rs_path = bridge_path.parent.parent.parent.parent / "crates" / "diec-engine" / "src" / "host.rs"
    if host_rs_path.exists():
        host_text = host_rs_path.read_text(encoding="utf-8", errors="replace")
        for variant in variants:
            # Check for Rust fn declarations (snake_case).
            rust_snake = re.sub(r'([A-Z])', r'_\1', variant).lower().lstrip('_')
            if re.search(rf'fn {rust_snake}\b', host_text):
                return "implemented"
            if re.search(rf'fn {variant.lower()}\b', host_text):
                return "implemented"

    # Check for inline JS object methods (Util.shlu64 etc.).
    for variant in variants:
        inline_pattern = rf'{variant}\s*:\s*function\s*\('
        if re.search(inline_pattern, text):
            return "implemented"

    # Check for methods provided via __proto__ inheritance from Binary.
    # These are methods that exist on Binary and are inherited by child classes.
    binary_inherited = {
        "getSize", "compare", "compareEP", "findSignature", "findString",
        "isSignaturePresent", "getString", "readByte", "readWord", "readDword",
        "readQword", "read_uint8", "read_uint16", "read_uint24", "read_uint32",
        "read_uint64", "read_int8", "read_int16", "read_int24", "read_int32",
        "read_int64", "read_float", "read_double",
        "calculateEntropy", "crc16", "calculateCRC32", "calculateMD5",
        "isPlainText", "isUTF8Text", "isUnicodeText", "isText",
        "getFileDirectory", "getFileBaseName", "getFileCompleteSuffix",
        "getFileSuffix", "getFileName", "getEntryPoint", "getOverlaySize",
        "getDisasmString", "getDisasmNextAddress",
        "isDeepScan", "isHeuristicScan", "isAggressiveScan", "isVerbose",
        "isRecursive", "entropy", "checkSignature",
    }
    if cls != "Binary" and method in binary_inherited:
        # Check if it's implemented on Binary.
        for variant in variants:
            pattern = rf'Binary\.{variant}\s*=\s*function'
            if re.search(pattern, text):
                return "implemented (inherited)"

    return "missing"


def main():
    workspace = find_workspace_root()
    help_dir = workspace / "upstream" / "Detect-It-Easy" / "help"
    bridge_path = workspace / "crates" / "diec-rules" / "src" / "host_api_bridge.rs"

    if not help_dir.is_dir():
        print(f"ERROR: help directory not found: {help_dir}", file=sys.stderr)
        sys.exit(1)
    if not bridge_path.exists():
        print(f"ERROR: bridge file not found: {bridge_path}", file=sys.stderr)
        sys.exit(1)

    print("Parsing upstream help docs...")
    help_methods = parse_help_docs(help_dir)

    print("Parsing bridge implementation...")
    bridge_methods = parse_bridge_impl(bridge_path)

    # Generate coverage matrix.
    lines = []
    lines.append("# Host API Coverage Matrix (Phase 15.3a)")
    lines.append("")
    lines.append("Auto-generated by `tools/audit_host_api.py`. Do not edit manually.")
    lines.append("")
    lines.append("Compares upstream DIE-engine help docs against `host_api_bridge.rs`")
    lines.append("implementation. Methods are classified as:")
    lines.append("- **implemented**: calls host API or does real computation")
    lines.append("- **stub**: returns constant (false/0/empty) without real logic")
    lines.append("- **missing**: not found in bridge")
    lines.append("")

    total_methods = 0
    total_implemented = 0
    total_stub = 0
    total_missing = 0

    for cls_name in sorted(help_methods.keys()):
        methods = help_methods[cls_name]
        if not methods:
            continue

        impl_set = bridge_methods.get(cls_name, set())

        lines.append(f"## {cls_name} ({len(methods)} methods)")
        lines.append("")
        lines.append("| Method | Status |")
        lines.append("|--------|--------|")

        cls_total = 0
        cls_impl = 0
        cls_stub = 0
        cls_missing = 0

        for method in methods:
            status = classify_implementation(bridge_path, cls_name, method)
            cls_total += 1
            total_methods += 1
            if status == "implemented":
                cls_impl += 1
                total_implemented += 1
                mark = "implemented"
            elif status == "stub":
                cls_stub += 1
                total_stub += 1
                mark = "**stub**"
            else:
                cls_missing += 1
                total_missing += 1
                mark = "**missing**"
            lines.append(f"| `{cls_name}.{method}` | {mark} |")

        pct = (cls_impl / cls_total * 100) if cls_total > 0 else 0
        lines.append("")
        lines.append(f"Coverage: {cls_impl}/{cls_total} implemented ({pct:.0f}%), "
                     f"{cls_stub} stub, {cls_missing} missing")
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total methods (from help docs) | {total_methods} |")
    lines.append(f"| Implemented | {total_implemented} |")
    lines.append(f"| Stub | {total_stub} |")
    lines.append(f"| Missing | {total_missing} |")
    pct = (total_implemented / total_methods * 100) if total_methods > 0 else 0
    lines.append(f"| Coverage | {pct:.1f}% |")
    lines.append("")

    # List P0 gaps (stub + missing).
    lines.append("## P0 Gaps (stub + missing)")
    lines.append("")
    for cls_name in sorted(help_methods.keys()):
        methods = help_methods[cls_name]
        gaps = []
        for method in methods:
            status = classify_implementation(bridge_path, cls_name, method)
            if status in ("stub", "missing"):
                gaps.append((method, status))
        if gaps:
            lines.append(f"### {cls_name}")
            lines.append("")
            for method, status in gaps:
                lines.append(f"- `{cls_name}.{method}` — {status}")
            lines.append("")

    output = "\n".join(lines)
    output_path = workspace / "docs" / "research" / "host-api-coverage-matrix.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output, encoding="utf-8")

    print(f"Coverage matrix written to: {output_path}")
    print(f"Total: {total_methods} methods, {total_implemented} implemented, "
          f"{total_stub} stub, {total_missing} missing ({pct:.1f}% coverage)")


if __name__ == "__main__":
    main()

//! PDF `/Encrypt` dictionary analysis for the `PDF` script object.
//!
//! Mirrors upstream `XPDF` (xpdf.cpp @ 8ef2a804168b133c98820fcd45461d854cea8443):
//! `findTrailerEncryptId`, `findEncryptObjectIndex`, `getEncryptionInfoString`,
//! `getEncryption`, `isEncrypted`, `getPermissions` and
//! `XPDFCrypt::permissionsToString`.
//!
//! Deviation note: upstream enumerates objects through xref tables / xref
//! streams (`scanStructure`); this module uses the brute-force `N G obj`
//! scan (`findObjects` deep path) over the whole file. Encryption
//! dictionaries are always top-level indirect objects referenced by the
//! trailer, so the encrypt-dict path is equivalent, but objects embedded in
//! compressed object streams are not discovered here.

/// A PDF indirect object located by the `N G obj` brute-force scan.
#[derive(Debug, Clone)]
struct PdfObject {
    /// Object number (`N` in `N G obj`).
    id: u64,
    /// File offset where the object header line begins.
    offset: usize,
    /// Byte offset just past the terminating `endobj` line.
    end: usize,
}

/// PDF whitespace bytes per ISO 32000 7.2.3 (NUL, TAB, LF, FF, CR, SP).
fn is_ws_byte(b: u8) -> bool {
    matches!(b, 0 | 9 | 10 | 12 | 13 | b' ')
}

/// Line-ending bytes (LF, CR).
fn is_line_ending(b: u8) -> bool {
    b == 10 || b == 13
}

/// String terminators: NUL or line ending (upstream `isPdfStringTerminator`).
fn is_string_terminator(b: u8) -> bool {
    b == 0 || is_line_ending(b)
}

/// Title-line terminators: string terminator or '<' (`isPdfTitleTerminator`).
fn is_title_terminator(b: u8) -> bool {
    is_string_terminator(b) || b == b'<'
}

/// Structural delimiters: '[', ']', '<', '>' (`isPdfStructuralDelimiter`).
fn is_structural_delimiter(b: u8) -> bool {
    matches!(b, b'[' | b']' | b'<' | b'>')
}

/// Name-token terminators (`isPdfNameTerminator`).
fn is_name_terminator(b: u8) -> bool {
    is_string_terminator(b)
        || is_structural_delimiter(b)
        || b == b' '
        || b == 9
        || b == 12
        || b == b'('
}

/// Value-token terminators (`isPdfValueTerminator`).
fn is_value_terminator(b: u8) -> bool {
    is_string_terminator(b) || is_structural_delimiter(b) || b == b'/'
}

/// Consume a line ending starting at `pos` (LF, or CR with optional LF).
/// Mirrors upstream `skipPDFEnding`.
fn skip_pdf_ending(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() {
        let b = data[pos];
        if b == 10 {
            pos += 1;
        } else if b == 13 {
            pos += 1;
            if pos < data.len() && data[pos] == 10 {
                pos += 1;
            }
        } else {
            break;
        }
    }
    pos
}

/// Consume ' ', TAB and FF bytes only (upstream `skipBufferPdfSpace` /
/// `skipPDFSpace`).
fn skip_pdf_space(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() {
        let b = data[pos];
        if b == b' ' || b == 9 || b == 12 {
            pos += 1;
        } else {
            break;
        }
    }
    pos
}

/// Read one line string (up to `max` bytes, stops at NUL/LF/CR) and consume
/// the following line ending. Returns `(text, bytes_consumed)`.
/// Mirrors upstream `_readPDFString`.
fn read_pdf_string(data: &[u8], offset: usize, max: usize) -> (String, usize) {
    if offset >= data.len() {
        return (String::new(), 0);
    }
    let end = (offset + max).min(data.len());
    let mut pos = offset;
    while pos < end && !is_string_terminator(data[pos]) {
        pos += 1;
    }
    let text = String::from_utf8_lossy(&data[offset..pos]).into_owned();
    let consumed = pos - offset + (skip_pdf_ending(data, pos) - pos);
    (text, consumed)
}

/// Read one title token (up to `max` bytes, stops at NUL/LF/CR/'<') and
/// consume the following line ending. Mirrors upstream
/// `_readPDFStringPart_title`.
fn read_pdf_title(data: &[u8], offset: usize, max: usize) -> (String, usize) {
    if offset >= data.len() {
        return (String::new(), 0);
    }
    let end = (offset + max).min(data.len());
    let mut pos = offset;
    while pos < end && !is_title_terminator(data[pos]) {
        pos += 1;
    }
    let text = String::from_utf8_lossy(&data[offset..pos]).into_owned();
    let consumed = pos - offset + (skip_pdf_ending(data, pos) - pos);
    (text, consumed)
}

/// Parse an object header `N G obj` (mirrors upstream `_isObject`,
/// `getObjectID`, `getObjectGen`). Returns `(id, gen)` when `s` starts with
/// a valid object header.
fn parse_object_header(s: &str) -> Option<(u64, u32)> {
    let b = s.as_bytes();
    let len = b.len();
    let mut i = 0usize;

    while i < len && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    let start_id = i;
    while i < len && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == start_id {
        return None;
    }
    let id: u64 = s[start_id..i].parse().ok()?;

    if i >= len || !(b[i] == b' ' || b[i] == b'\t') {
        return None;
    }
    while i < len && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }

    let start_gen = i;
    while i < len && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == start_gen {
        return None;
    }
    let gen_num: u32 = s[start_gen..i].parse().ok()?;

    if i >= len || !(b[i] == b' ' || b[i] == b'\t') {
        return None;
    }
    while i < len && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }

    if i + 3 > len || &b[i..i + 3] != b"obj" {
        return None;
    }

    // The byte after "obj" must be a boundary so "object"/"objxxx" do not
    // count (upstream boundary set).
    if i + 3 < len {
        let c = b[i + 3];
        let boundary = matches!(
            c,
            b' ' | b'\t' | b'\r' | b'\n' | b'<' | b'[' | b'(' | b'/' | b'%'
        );
        if !boundary {
            return None;
        }
    }

    Some((id, gen_num))
}

/// Read the raw bytes of a `(...)` literal string token starting at `offset`
/// (which must point at '('). Balanced parentheses and backslash escapes are
/// honored (upstream `_readPDFStringPart_str`). Returns `(token, consumed)`
/// where `consumed` covers the literal only.
fn read_str_token(data: &[u8], offset: usize) -> (String, usize) {
    let mut pos = offset;
    let mut depth = 0i32;
    let mut escaped = false;
    let mut end = data.len();
    while pos < data.len() {
        let c = data[pos];
        if escaped {
            escaped = false;
        } else if c == b'\\' {
            escaped = true;
        } else if c == b'(' {
            depth += 1;
        } else if c == b')' {
            depth -= 1;
            if depth == 0 {
                end = pos + 1;
                break;
            }
        }
        pos += 1;
    }
    let token = String::from_utf8_lossy(&data[offset..end]).into_owned();
    (token, end - offset)
}

/// Read a `<...>` hex string token starting at `offset` (which must point at
/// a single '<'). Returns `(token, consumed)` covering the literal only
/// (upstream `_readPDFStringPart_hex`).
fn read_hex_token(data: &[u8], offset: usize) -> (String, usize) {
    let mut pos = offset;
    let mut end = data.len();
    while pos < data.len() {
        if data[pos] == b'>' {
            end = pos + 1;
            break;
        }
        pos += 1;
    }
    let token = String::from_utf8_lossy(&data[offset..end]).into_owned();
    (token, end - offset)
}

/// Read one dictionary token starting at `offset`. Returns
/// `(token, bytes_consumed)`. Mirrors upstream `_readPDFStringPart`.
fn read_pdf_string_part(data: &[u8], offset: usize) -> (String, usize) {
    if offset >= data.len() {
        return (String::new(), 0);
    }
    let first = data[offset];
    let rest = &data[offset..];

    if first == b'/' {
        // Name token: until name terminator or a non-leading '/'.
        let mut n = 0usize;
        while n < rest.len() {
            let c = rest[n];
            if is_name_terminator(c) {
                break;
            }
            if n > 0 && c == b'/' {
                break;
            }
            n += 1;
        }
        let token = String::from_utf8_lossy(&rest[..n]).into_owned();
        (token, consume_all_ws(data, offset + n) - offset)
    } else if first == b'(' {
        let (token, n) = read_str_token(data, offset);
        // str/hex tokens use the space-then-ending fallback pair.
        let pos = skip_pdf_space(data, offset + n);
        let pos = skip_pdf_ending(data, pos);
        (token, pos - offset)
    } else if first == b'<' {
        if rest.len() > 1 && rest[1] == b'<' {
            ("<<".to_string(), consume_all_ws(data, offset + 2) - offset)
        } else {
            let (token, n) = read_hex_token(data, offset);
            let pos = skip_pdf_space(data, offset + n);
            let pos = skip_pdf_ending(data, pos);
            (token, pos - offset)
        }
    } else if first == b'>' {
        if rest.len() > 1 && rest[1] == b'>' {
            (">>".to_string(), consume_all_ws(data, offset + 2) - offset)
        } else {
            (String::new(), 0)
        }
    } else if first == b'[' {
        ("[".to_string(), consume_all_ws(data, offset + 1) - offset)
    } else if first == b']' {
        ("]".to_string(), consume_all_ws(data, offset + 1) - offset)
    } else {
        // Scalar value token: until value terminator or ' '/TAB/FF.
        let mut n = 0usize;
        let mut space_end = false;
        while n < rest.len() {
            let c = rest[n];
            if is_value_terminator(c) {
                break;
            }
            if c == b' ' || c == 9 || c == 12 {
                n += 1;
                space_end = true;
                break;
            }
            n += 1;
        }
        let mut token_end = n;
        let mut token_len = if space_end { n - 1 } else { n };
        if space_end
            && n + 2 < rest.len()
            && rest[n] == b'0'
            && rest[n + 1] == b' '
            && rest[n + 2] == b'R'
        {
            // Fuse "N 0 R" into a single indirect-reference token.
            token_len = n + 3;
            token_end = n + 3;
        }
        let token = String::from_utf8_lossy(&rest[..token_len]).into_owned();
        (token, consume_all_ws(data, offset + token_end) - offset)
    }
}

/// Consume every trailing PDF whitespace byte (any order) starting at `pos`,
/// returning the total consumed count from `offset`'s perspective is handled
/// by the caller; here we return the new absolute position.
fn consume_all_ws(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() && is_ws_byte(data[pos]) {
        pos += 1;
    }
    pos
}

/// Tokenize the dictionary portion of the object at `offset`
/// (mirrors upstream `handleXpart` with `bResolveStreams = false`).
/// Returns at most `limit` tokens.
fn object_dict_parts(data: &[u8], offset: usize, limit: usize) -> Vec<String> {
    let (title, title_len) = read_pdf_title(data, offset, 20);
    if parse_object_header(&title).is_none() {
        return Vec::new();
    }

    let mut parts = Vec::new();
    let mut pos = offset + title_len;
    let mut n_obj = 0i32;
    let mut n_col = 0i32;

    loop {
        if parts.len() >= limit {
            break;
        }
        let (tok, consumed) = read_pdf_string_part(data, pos);
        parts.push(tok.clone());
        pos += consumed;

        if tok.is_empty() {
            break;
        }
        match tok.as_str() {
            "<<" => n_obj += 1,
            ">>" => n_obj -= 1,
            "[" => n_col += 1,
            "]" => n_col -= 1,
            _ => {}
        }
        if n_obj == 0 && n_col == 0 {
            break;
        }
    }
    parts
}

/// Brute-force scan for `N G obj ... endobj` objects (upstream `findObjects`
/// deep path). Returns objects in file order.
fn find_objects(data: &[u8]) -> Vec<PdfObject> {
    let mut result = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let iter_entry = offset;
        let (line, consumed) = read_pdf_string(data, offset, 64);

        if let Some((id, _gen)) = parse_object_header(&line) {
            let search_start = offset + consumed;
            if let Some(end_off) = find_ansi(data, search_start, b"endobj") {
                let (end_line, end_len) = read_pdf_string(data, end_off, 32);
                if end_line.trim() == "endobj" {
                    result.push(PdfObject {
                        id,
                        offset,
                        end: end_off + end_len,
                    });
                    offset = end_off + end_len;
                    continue;
                }
            }
            break;
        } else if line.starts_with('%') {
            offset += consumed.max(1);
        } else {
            // Deep-scan: locate " obj" then walk back over digits/spaces.
            if let Some(obj_kw) = find_ansi(data, offset, b" obj") {
                let mut new_off = obj_kw;
                while new_off > 0 {
                    let prev = data[new_off - 1];
                    if !(prev.is_ascii_digit() || prev == b' ') {
                        break;
                    }
                    new_off -= 1;
                }
                if new_off <= iter_entry {
                    new_off = obj_kw + 4;
                }
                offset = new_off;
                continue;
            }
            break;
        }
    }
    result
}

/// Find the first occurrence of `needle` in `data` at or after `from`.
fn find_ansi(data: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || from >= data.len() {
        return None;
    }
    data[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Object id referenced by the LAST trailer `/Encrypt N G R` entry, or
/// `None`. Mirrors upstream `findTrailerEncryptId`.
fn find_trailer_encrypt_id(data: &[u8]) -> Option<u64> {
    let mut result = None;
    let mut from = 0usize;

    while let Some(pos) = find_ansi(data, from, b"/Encrypt") {
        let chunk_end = (pos + 64).min(data.len());
        let chunk = &data[pos..chunk_end];
        let n = chunk.len();

        let boundary = n <= 8 || matches!(chunk[8], b' ' | b'\t' | b'\r' | b'\n');
        if boundary && n > 8 {
            let mut i = 8usize;
            while i < n && matches!(chunk[i], b' ' | b'\t' | b'\r' | b'\n') {
                i += 1;
            }
            let mut id: u64 = 0;
            let mut has_digit = false;
            while i < n && chunk[i].is_ascii_digit() {
                id = id * 10 + u64::from(chunk[i] - b'0');
                i += 1;
                has_digit = true;
            }
            while i < n && matches!(chunk[i], b' ' | b'\t' | b'\r' | b'\n') {
                i += 1;
            }
            while i < n && chunk[i].is_ascii_digit() {
                i += 1; // generation
            }
            while i < n && matches!(chunk[i], b' ' | b'\t' | b'\r' | b'\n') {
                i += 1;
            }
            if has_digit && id > 0 && i < n && chunk[i] == b'R' {
                result = Some(id);
            }
        }

        from = pos + 8;
    }

    result
}

/// Parse a scalar token to an integer (upstream `_parseValue` toInt path).
fn parse_int_token(tok: &str) -> Option<i64> {
    tok.parse::<i64>().ok()
}

/// Upstream `getFirstStringValueByKey`: returns the value token that
/// follows the LAST occurrence of `key` (the loop does not break; last
/// non-null value wins).
fn get_value_by_key<'a>(parts: &'a [String], key: &str) -> Option<&'a str> {
    let mut result = None;
    let n = parts.len();
    let mut j = 0usize;
    while j + 1 < n {
        if parts[j] == key {
            let v = parts[j + 1].as_str();
            // _parseValue always yields a non-null variant except for a
            // genuinely empty token.
            if !v.is_empty() {
                result = Some(v);
            }
        }
        j += 1;
    }
    result
}

/// Upstream `cryptFilterMethodByName`: find `/CF`, then the filter name
/// (fallback: anywhere), then the following `/CFM` value.
fn crypt_filter_method_by_name<'a>(parts: &'a [String], filter_name: &str) -> Option<&'a str> {
    if filter_name.is_empty() {
        return None;
    }
    let n = parts.len();
    let cf_pos = parts.iter().position(|t| t == "/CF");
    let name_tok = format!("/{filter_name}");

    let mut filter_pos = match cf_pos {
        Some(cf) => parts[cf..]
            .iter()
            .position(|t| t == &name_tok)
            .map(|p| p + cf),
        None => None,
    };
    if filter_pos.is_none() {
        filter_pos = parts.iter().position(|t| t == &name_tok);
    }
    let filter_pos = filter_pos?;

    let mut i = filter_pos + 1;
    while i < n {
        if parts[i] == "/CFM" {
            return parts.get(i + 1).map(|s| s.as_str());
        }
        i += 1;
    }
    None
}

/// Select the authoritative `/Encrypt` dictionary token list.
/// Mirrors upstream `findEncryptObjectIndex`.
fn encrypt_dict_parts(data: &[u8]) -> Option<Vec<String>> {
    let objects = find_objects(data);
    if objects.is_empty() {
        return None;
    }

    let encrypt_id = find_trailer_encrypt_id(data);
    // Upstream resolveObjectOffset: later (newer) sections overwrite the
    // id->offset map, so the newest revision wins.
    let mut id_offset = std::collections::HashMap::new();
    for o in &objects {
        id_offset.insert(o.id, o.offset);
    }
    let auth_offset = encrypt_id.and_then(|id| id_offset.get(&id).copied());

    let mut fallback: Option<Vec<String>> = None;

    for obj in &objects {
        // Fast reject: the /Filter name token must appear in the raw object.
        let raw = &data[obj.offset..obj.end.min(data.len())];
        if find_ansi(raw, 0, b"/Filter").is_none() {
            continue;
        }
        let parts = object_dict_parts(data, obj.offset, 256);
        let filter_pos = parts.iter().position(|t| t == "/Filter");
        let is_standard = match filter_pos {
            Some(p) => parts.get(p + 1).map(|s| s.as_str()) == Some("/Standard"),
            None => false,
        };
        if !is_standard {
            continue;
        }

        if fallback.is_none() {
            fallback = Some(parts.clone());
        }

        if let Some(eid) = encrypt_id {
            if obj.id != eid {
                continue;
            }
            if auth_offset.is_some_and(|ao| obj.offset != ao) {
                continue;
            }
            return Some(parts);
        }
    }

    fallback
}

/// Upstream `XPDF::getEncryption` / `getEncryptionInfoString`: returns the
/// encryption descriptor (e.g. `"Standard V4 R4 128-bit AESV2 P=-3904"`), or
/// an empty string when the document is not encrypted.
pub fn get_encryption(data: &[u8]) -> String {
    let Some(parts) = encrypt_dict_parts(data) else {
        return String::new();
    };

    let mut n_v = get_value_by_key(&parts, "/V")
        .and_then(parse_int_token)
        .unwrap_or(0);
    let n_r = get_value_by_key(&parts, "/R")
        .and_then(parse_int_token)
        .unwrap_or(0);
    let mut n_len = get_value_by_key(&parts, "/Length")
        .and_then(parse_int_token)
        .unwrap_or(0);
    let v_p = get_value_by_key(&parts, "/P").and_then(parse_int_token);
    let s_stmf = get_value_by_key(&parts, "/StmF").unwrap_or("");
    let mut s_cfm = crypt_filter_method_by_name(&parts, s_stmf.trim_start_matches('/'))
        .unwrap_or("")
        .to_string();
    if s_cfm.is_empty() {
        s_cfm = get_value_by_key(&parts, "/CFM").unwrap_or("").to_string();
    }

    // /V can read 0 when its token falls past the binary /O//U strings;
    // infer it from the revision.
    if n_v == 0 {
        if n_r >= 5 {
            n_v = 5;
        } else if n_r == 4 {
            n_v = 4;
        } else if n_r == 3 {
            n_v = 2;
        } else if n_r == 2 {
            n_v = 1;
        }
    }
    // Crypt-filter /Length is in bytes; top-level /Length is in bits.
    if n_len > 0 && n_len < 40 {
        n_len *= 8;
    }

    if let Some(stripped) = s_cfm.strip_prefix('/') {
        s_cfm = stripped.to_string();
    }
    if s_cfm == "V2" {
        s_cfm = "RC4".to_string();
    }
    if s_cfm.is_empty() {
        s_cfm = if n_v >= 5 {
            "AESV3".to_string()
        } else if n_v == 4 {
            "AESV2/RC4".to_string()
        } else {
            "RC4".to_string()
        };
    }

    let mut result = format!("Standard V{n_v} R{n_r}");
    if n_len > 0 {
        result += &format!(" {n_len}-bit");
    }
    result.push(' ');
    result += &s_cfm;
    if let Some(p) = v_p {
        result += &format!(" P={p}");
    }
    result
}

/// Upstream `XPDF::isEncrypted`: true when an encryption dictionary is found.
pub fn is_encrypted(data: &[u8]) -> bool {
    !get_encryption(data).is_empty()
}

/// Upstream `XPDFCrypt::permissionsToString`.
fn permissions_to_string(p: i64) -> String {
    let bits = p as i32 as u32;
    let mut allowed = Vec::new();
    if bits & 0x0004 != 0 {
        allowed.push("print");
    }
    if bits & 0x0008 != 0 {
        allowed.push("modify");
    }
    if bits & 0x0010 != 0 {
        allowed.push("copy");
    }
    if bits & 0x0020 != 0 {
        allowed.push("annotate");
    }
    if bits & 0x0100 != 0 {
        allowed.push("fill-forms");
    }
    if bits & 0x0200 != 0 {
        allowed.push("extract-a11y");
    }
    if bits & 0x0400 != 0 {
        allowed.push("assemble");
    }
    if bits & 0x0800 != 0 {
        allowed.push("print-hires");
    }
    if allowed.is_empty() {
        "none".to_string()
    } else {
        allowed.join(", ")
    }
}

/// Upstream `XPDF::getPermissions`: empty when not encrypted or when the
/// Standard security dictionary lacks a revision (`/R == 0`).
pub fn get_permissions(data: &[u8]) -> String {
    if !is_encrypted(data) {
        return String::new();
    }
    let Some(parts) = encrypt_dict_parts(data) else {
        return String::new();
    };
    let n_r = get_value_by_key(&parts, "/R")
        .and_then(parse_int_token)
        .unwrap_or(0);
    if n_r == 0 {
        return String::new();
    }
    let n_p = get_value_by_key(&parts, "/P")
        .and_then(parse_int_token)
        .unwrap_or(0);
    permissions_to_string(n_p)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal unencrypted PDF fixture.
    #[test]
    fn unencrypted_pdf_returns_empty() {
        let pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>\nendobj\ntrailer<</Size 2>>\n%%EOF\n";
        assert_eq!(get_encryption(pdf), "");
        assert!(!is_encrypted(pdf));
        assert_eq!(get_permissions(pdf), "");
    }

    /// RC4-40 (V1/R2) encrypted-style fixture with trailer /Encrypt.
    #[test]
    fn encrypted_pdf_descriptor() {
        let pdf = concat!(
            "%PDF-1.4\n",
            "1 0 obj<</Type/Catalog>>\nendobj\n",
            "5 0 obj\n<< /Filter /Standard /V 1 /R 2 /Length 40 /P -3904 ",
            "/O (abc) /U (def) >>\nendobj\n",
            "trailer << /Encrypt 5 0 R /Size 6 >>\n%%EOF\n"
        );
        let enc = get_encryption(pdf.as_bytes());
        assert_eq!(enc, "Standard V1 R2 40-bit RC4 P=-3904");
        assert!(is_encrypted(pdf.as_bytes()));
        // P=-3904 as i32: 0xFFFFF0C0 -> bits 0x100 copy? compute:
        // -3904 & 0xFFFF: 0xF0C0 -> bits 0x40/0x80 unset -> allowed flags:
        // 0x4 print? 0xF0C0 & 4 = 0 -> denied... verify against bit list.
        assert_eq!(get_permissions(pdf.as_bytes()), "none");
    }

    /// AESV2 crypt-filter fixture.
    #[test]
    fn aesv2_encrypt_descriptor() {
        let pdf = concat!(
            "%PDF-1.6\n",
            "9 0 obj\n<< /Filter /Standard /V 4 /R 4 /Length 128 /P -44 ",
            "/StmF /StdCF /StrF /StdCF /CF << /StdCF << /CFM /AESV2 >> >> >>\nendobj\n",
            "trailer << /Encrypt 9 0 R >>\n%%EOF\n"
        );
        let enc = get_encryption(pdf.as_bytes());
        assert_eq!(enc, "Standard V4 R4 128-bit AESV2 P=-44");
        let perms = get_permissions(pdf.as_bytes());
        // -44 -> 0xFFFFFFD4: all permission bits except modify (0x8) and
        // annotate (0x20) are set.
        assert_eq!(
            perms,
            "print, copy, fill-forms, extract-a11y, assemble, print-hires"
        );
    }

    /// Encrypt reference where the trailer points at an object that does not
    /// carry the Standard filter: fallback to first /Filter /Standard object.
    #[test]
    fn fallback_first_standard_object() {
        let pdf = concat!(
            "%PDF-1.4\n",
            "7 0 obj\n<< /Filter /Standard /V 2 /R 3 /P -1028 >>\nendobj\n",
            "trailer << /Encrypt 99 0 R >>\n%%EOF\n"
        );
        let enc = get_encryption(pdf.as_bytes());
        assert_eq!(enc, "Standard V2 R3 RC4 P=-1028");
    }

    /// `/Encrypt` followed by a non-reference token must not match.
    #[test]
    fn encrypt_boundary_rejected() {
        let pdf = b"%PDF-1.4\ntrailer << /EncryptMetadata false >>\n%%EOF\n";
        assert!(!is_encrypted(pdf));
    }

    /// Malformed input must not panic.
    #[test]
    fn garbage_input_safe() {
        let data = b"\x00\x01/Encrypt<<>>obj\xff\xfe";
        assert!(!is_encrypted(data));
        let _ = get_permissions(data);
    }
}

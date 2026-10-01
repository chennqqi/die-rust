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

/// Read a `(...)` literal string token starting at `offset`. Faithful port
/// of upstream `_readPDFStringPart_str`:
/// - bytes before the opening `(` are appended verbatim; a leading
///   terminator ends the read immediately;
/// - `(`/`)` balance nesting, `\` escapes the next byte and is dropped from
///   the token text;
/// - a `FE FF` BOM right after `(` switches to UTF-16BE mode, where words
///   are decoded to chars and `(`/`)` only count in the high byte
///   (upstream quirk: those consume just one byte, letting the word
///   boundary shift);
/// - a 32 MiB cap guards unterminated literals.
///
/// Returns `(token, bytes_consumed)` covering the literal only.
fn read_str_token(data: &[u8], offset: usize) -> (String, usize) {
    let file_size = data.len();
    let mut token = String::new();
    let mut n_size = 0usize;
    let mut pos = offset;
    let mut b_start = false;
    let mut b_end = false;
    let mut b_unicode = false;
    let mut b_bslash = false;
    let mut depth = 0i32;

    loop {
        if pos >= file_size {
            break;
        }
        if n_size > 32 * 1024 * 1024 {
            break;
        }

        if !b_unicode {
            let c = data[pos];

            if !b_start && is_string_terminator(c) {
                break;
            }

            if !b_start {
                if c == b'(' {
                    b_start = true;
                    if pos + 2 < file_size && data[pos + 1] == 0xFE && data[pos + 2] == 0xFF {
                        b_unicode = true;
                        n_size += 2;
                        pos += 2;
                    }
                    token.push('(');
                } else {
                    if b_bslash {
                        b_bslash = false;
                    }
                    token.push(char::from(c));
                }
            } else if c == b'(' && !b_bslash {
                depth += 1;
                token.push('(');
            } else if c == b')' && !b_bslash {
                token.push(')');
                if depth > 0 {
                    depth -= 1;
                } else {
                    b_end = true;
                }
            } else if c == b'\\' {
                b_bslash = true;
            } else {
                if b_bslash {
                    b_bslash = false;
                }
                token.push(char::from(c));
            }
            n_size += 1;
            pos += 1;
        } else {
            if pos + 1 >= file_size {
                break;
            }
            let word = (u16::from(data[pos]) << 8) | u16::from(data[pos + 1]);

            if (word >> 8) == u16::from(b'(') && !b_bslash {
                depth += 1;
                token.push('(');
                n_size += 1;
            } else if (word >> 8) == u16::from(b')') && !b_bslash {
                token.push(')');
                n_size += 1;
                if depth > 0 {
                    depth -= 1;
                } else {
                    b_end = true;
                }
            } else if word == 0x005C {
                // '\\' as a full UTF-16 word
                b_bslash = true;
                pos += 2;
                n_size += 2;
                continue;
            } else if b_bslash && word == 0x6E29 {
                // 'n)' after an escape closes the string (upstream quirk)
                b_bslash = false;
                token.push(')');
                n_size += 1;
                b_end = true;
            } else {
                if b_bslash {
                    b_bslash = false;
                }
                token.push(char::from_u32(u32::from(word)).unwrap_or('\u{FFFD}'));
                pos += 2;
                n_size += 2;
                continue;
            }
            pos += 1;
        }

        if b_start && b_end {
            break;
        }
    }

    (token, n_size)
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

/// Brute-force scan for `N G obj ... endobj` objects (upstream `findObjects`).
/// `size` is a byte-range length; `None` scans to EOF. In non-deep mode the
/// scan stops at the first line that is neither an object header nor a
/// comment; deep mode re-synchronizes on the next `" obj"` keyword.
fn find_objects_range(
    data: &[u8],
    offset: usize,
    size: Option<usize>,
    deep: bool,
) -> Vec<PdfObject> {
    let mut result = Vec::new();
    let end_bound = match size {
        Some(s) => offset.saturating_add(s).min(data.len()),
        None => data.len(),
    };
    let mut offset = offset;

    while offset < end_bound {
        let iter_entry = offset;
        let (line, consumed) = read_pdf_string(data, offset, 64);

        if let Some((id, _gen)) = parse_object_header(&line) {
            let search_start = offset + consumed;
            let search_len = end_bound.saturating_sub(search_start);
            let end_off = if search_len > 0 {
                find_ansi(&data[..end_bound], search_start, b"endobj")
            } else {
                None
            };
            if let Some(end_off) = end_off {
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
            let mut b_continue = false;
            if deep {
                // Deep-scan: locate " obj" then walk back over digits/spaces.
                if let Some(obj_kw) = find_ansi(&data[..end_bound], offset, b" obj") {
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
                    b_continue = offset < end_bound;
                }
            }
            if !b_continue {
                break;
            }
        }
    }
    result
}

/// A `startxref` footer record (upstream `STARTHREF` from `findStartxrefs`).
#[derive(Debug)]
struct StartHref {
    /// Byte offset the `startxref` value points at (xref table or xref
    /// stream object).
    xref_offset: usize,
    /// Offset of the `startxref` keyword itself (footer start).
    footer_offset: usize,
    /// True when the target line is an `N G obj` header (cross-reference
    /// stream object).
    is_object: bool,
}

/// Upstream `_isXref`: line starts with `xref` and is either exactly
/// `xref` or continues with a space.
fn is_xref_line(s: &str) -> bool {
    s.starts_with("xref") && (s.len() == 4 || s.as_bytes().get(4) == Some(&b' '))
}

/// `QString::section(" ", i, i)`: the i-th space-separated field, `""` when
/// absent. Rust `split(' ')` keeps empty fields just like Qt.
fn q_section(s: &str, i: usize) -> &str {
    s.split(' ').nth(i).unwrap_or("")
}

/// `QString::toLongLong`: leading/trailing whitespace tolerated, failure
/// yields 0.
fn q_to_i64(s: &str) -> i64 {
    s.trim().parse().unwrap_or(0)
}

/// `QString::toULongLong` equivalent for xref fields.
fn q_to_u64(s: &str) -> u64 {
    s.trim().parse().unwrap_or(0)
}

/// Scan for `startxref` footers (upstream `findStartxrefs`). Each record is
/// validated: the referenced line must be an xref table or object header,
/// the target must precede the `startxref` keyword, and `%%EOF` must follow.
fn find_startxrefs(data: &[u8]) -> Vec<StartHref> {
    let mut result = Vec::new();
    let mut offset = 0usize;

    while let Some(pos) = find_ansi(data, offset, b"startxref") {
        let mut current = pos;
        let (_kw, n) = read_pdf_string(data, current, 20);
        current += n;

        let (off_str, off_len) = read_pdf_string(data, current, 20);
        let target = q_to_i64(&off_str);

        let target_usize = usize::try_from(target).unwrap_or(usize::MAX);
        let (href, _) = read_pdf_string(data, target_usize, 20);
        let is_xref = is_xref_line(&href);
        let is_object = parse_object_header(&href).is_some();

        if (is_xref || is_object) && target < current as i64 {
            current += off_len;

            let (os_end, _) = read_pdf_string(data, current, 20);
            if os_end.starts_with("%%EOF") {
                current += 5;
                if current < data.len() && data[current] == 13 {
                    current += 1;
                }
                if current < data.len() && data[current] == 10 {
                    current += 1;
                }

                result.push(StartHref {
                    xref_offset: target as usize,
                    footer_offset: pos,
                    is_object,
                });

                if os_end.len() != 5 {
                    break;
                }

                let (append, _) = read_pdf_string(data, current, 20);
                let ok = parse_object_header(&append).is_some()
                    || append.starts_with('%')
                    || is_xref_line(&append);
                if !ok {
                    break;
                }
            }
        }

        offset = pos + 10;
    }

    result
}

/// Walk a classic xref table (upstream `getObjectsFromStartxref`). Entries
/// marked `n` map object offsets to object numbers; object sizes are derived
/// from the offset of the following object (or the xref/file end for the
/// last one).
fn objects_from_xref_table(data: &[u8], xref_offset: usize) -> Vec<PdfObject> {
    let mut result = Vec::new();
    let mut current = xref_offset;

    let (line, n) = read_pdf_string(data, current, 20);
    if !is_xref_line(&line) {
        return result;
    }
    current += n;

    let mut map: std::collections::BTreeMap<usize, u64> = std::collections::BTreeMap::new();

    loop {
        let (sec, sec_len) = read_pdf_string(data, current, 20);
        if sec.is_empty() {
            break;
        }
        let id = q_to_u64(q_section(&sec, 0));
        let count = q_to_u64(q_section(&sec, 1));
        current += sec_len;
        if count == 0 {
            break;
        }
        for i in 0..count {
            let (obj_line, obj_len) = read_pdf_string(data, current, 20);
            // No forward progress means EOF was hit (a hostile subsection
            // count would otherwise spin forever).
            if obj_len == 0 {
                break;
            }
            if q_section(&obj_line, 2) == "n" {
                let off = q_to_u64(q_section(&obj_line, 0)) as usize;
                if off > 0 && off < data.len() {
                    map.insert(off, id + i);
                }
            }
            current += obj_len;
        }
    }

    for (offset, id) in map {
        result.push(PdfObject { id, offset, end: 0 });
    }

    for i in 0..result.len().saturating_sub(1) {
        result[i].end = result[i + 1].offset;
    }
    if let Some(last) = result.last_mut() {
        // Bound the last object by the xref table unless it physically lies
        // past it (linearized / early-xref layout).
        last.end = if xref_offset <= last.offset {
            data.len()
        } else {
            xref_offset
        };
    }

    result
}

/// `QString::getObjectID` equivalent: parse the leading integer of an
/// object header line (optional `-` sign). Returns the id as u64.
fn object_id_of(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut i = 0usize;
    let neg = i < b.len() && b[i] == b'-';
    if neg {
        i += 1;
    }
    let start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let v: i64 = s[start..i].parse().unwrap_or(0);
    (if neg { -v } else { v }) as u64
}

/// Upstream `_isIndirectRef`: a fused `"N G R"` token.
fn is_indirect_ref(s: &str) -> bool {
    if s.is_empty() || !s.as_bytes()[0].is_ascii_digit() {
        return false;
    }
    if q_section(s, 2) != "R" {
        return false;
    }
    s.split(' ')
        .next()
        .is_some_and(|f| f.parse::<i64>().is_ok())
        && s.split(' ')
            .nth(1)
            .is_some_and(|f| f.parse::<i64>().is_ok())
}

/// Read a scalar value token (upstream `_readPDFStringPart_val`): reads a
/// bare value and fuses the `"N 0 R"` indirect-reference form. No trailing
/// whitespace is consumed.
fn read_pdf_string_part_val(data: &[u8], offset: usize) -> (String, usize) {
    if offset >= data.len() {
        return (String::new(), 0);
    }
    let rest = &data[offset..];
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
    let mut token_len = if space_end { n - 1 } else { n };
    if space_end
        && n + 2 < rest.len()
        && rest[n] == b'0'
        && rest[n + 1] == b' '
        && rest[n + 2] == b'R'
    {
        token_len = n + 3;
    }
    (
        String::from_utf8_lossy(&rest[..token_len]).into_owned(),
        token_len,
    )
}

/// Upstream `findObjectHeaderInRange`: locate `"N 0 obj"` in
/// `[start, start+size)`, rejecting matches whose object number is preceded
/// by another digit.
fn find_obj_header_in_range(data: &[u8], id: u64, start: usize, size: usize) -> Option<usize> {
    if size == 0 {
        return None;
    }
    let needle = format!("{id} 0 obj");
    let end = start.saturating_add(size).min(data.len());
    let mut from = start;
    while from < end {
        let hit = find_ansi(&data[..end], from, needle.as_bytes())?;
        let boundary = hit == 0 || !data[hit - 1].is_ascii_digit();
        if boundary {
            return Some(hit);
        }
        from = hit + 1;
    }
    None
}

/// Upstream `resolveObjectOffset`: map lookup first, then a bounded scan
/// (±1 MiB) around the hint for `"N 0 obj"`.
fn resolve_object_offset(
    data: &[u8],
    id: u64,
    id_map: &std::collections::HashMap<u64, usize>,
    hint: usize,
) -> Option<usize> {
    if let Some(&off) = id_map.get(&id) {
        return Some(off);
    }
    let hint = hint.min(data.len());
    let fwd_size = 1048576usize.min(data.len() - hint);
    find_obj_header_in_range(data, id, hint, fwd_size).or_else(|| {
        let back_start = hint.saturating_sub(1048576);
        find_obj_header_in_range(data, id, back_start, hint - back_start)
    })
}

/// Parsed PDF object (upstream `XPART`): dictionary token list plus the
/// byte ranges of any `stream`/`endstream` bodies.
#[derive(Debug)]
struct XPart {
    /// Object number (from the `N G obj` header or the xref entry).
    id: u64,
    /// Dictionary/section tokens.
    parts: Vec<String>,
    /// `(offset, size)` pairs of stream bodies.
    streams: Vec<(usize, usize)>,
}

/// Upstream `handleXpart`: tokenize an object's dictionary and optionally
/// resolve `stream` bodies (with `/Length` handling for direct, fused
/// `N G R` and split indirect forms, plus `endstream` validation).
fn handle_xpart(
    data: &[u8],
    mut offset: usize,
    id: u64,
    part_limit: i64,
    resolve_streams: bool,
    id_map: &std::collections::HashMap<u64, usize>,
) -> XPart {
    let mut result = XPart {
        id,
        parts: Vec::new(),
        streams: Vec::new(),
    };
    let file_size = data.len();
    let mut s_length = String::new();
    let mut b_length = false;

    loop {
        let (title, tsize) = read_pdf_title(data, offset, 20);
        if result.id == 0 {
            result.id = object_id_of(&title);
        }
        offset += tsize;

        if let Some((_oid, _gen)) = parse_object_header(&title) {
            let mut n_obj = 0i32;
            let mut n_col = 0i32;
            let mut stop = false;
            loop {
                let (tok, tsz) = read_pdf_string_part(data, offset);
                if part_limit == -1 || (result.parts.len() as i64) < part_limit {
                    result.parts.push(tok.clone());
                } else {
                    stop = true;
                    break;
                }
                offset += tsz;
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
                if b_length {
                    b_length = false;
                    s_length = tok.clone();
                } else if tok == "/Length" {
                    b_length = true;
                }
                if n_obj == 0 && n_col == 0 {
                    break;
                }
            }
            if stop {
                break;
            }
        } else if title == "stream" {
            if !resolve_streams {
                break;
            }
            let stream_offset = offset;

            // Resolve the /Length token: fused "N G R", the split
            // "/Length N G R" form, or a direct number.
            let mut b_indirect = false;
            let mut s_len = s_length.clone();
            if is_indirect_ref(&s_len) {
                b_indirect = true;
            } else if let Ok(n_tok) = q_section(&s_len, 0).parse::<i64>() {
                let n_parts = result.parts.len();
                for np in 0..n_parts.saturating_sub(2) {
                    if result.parts[np] == n_tok.to_string()
                        && result.parts.get(np + 2).map(|s| s.as_str()) == Some("R")
                        && np > 0
                        && result.parts[np - 1] == "/Length"
                    {
                        b_indirect = true;
                        s_len = format!("{} {} R", result.parts[np], result.parts[np + 1]);
                        break;
                    }
                }
            }

            let mut stream_size = 0usize;
            let mut has_size = false;
            if !b_indirect {
                let v = q_to_i64(&s_len);
                if v >= 0 && !s_len.trim().is_empty() {
                    // toLongLong semantics: parse must succeed, not merely
                    // yield 0 on garbage.
                    if s_len.trim().parse::<i64>().is_ok() {
                        stream_size = v as usize;
                        has_size = true;
                    }
                }
            } else if q_section(&s_len, 2) == "R" {
                let ref_id = q_to_u64(q_section(&s_len, 0));
                if let Some(obj_off) = resolve_object_offset(data, ref_id, id_map, offset) {
                    let mut t = obj_off;
                    t += read_pdf_string(data, t, 64).1;
                    let (len_tok, _) = read_pdf_string_part_val(data, t);
                    if let Ok(v) = len_tok.parse::<i64>()
                        && v >= 0
                    {
                        stream_size = v as usize;
                        has_size = true;
                    }
                }
            }

            // Validate the declared size against the real endstream marker.
            if has_size {
                if stream_size > file_size - stream_offset {
                    has_size = false;
                } else {
                    let probe = stream_offset + stream_size;
                    let window = (file_size - probe).min(40);
                    let hit = if window > 0 {
                        find_ansi(&data[..probe + window], probe, b"endstream")
                    } else {
                        None
                    };
                    if hit.is_none() {
                        has_size = false;
                    }
                }
            }

            if !has_size {
                match find_ansi(data, stream_offset, b"endstream") {
                    Some(es) => {
                        let mut body_end = es;
                        if body_end > stream_offset && data[body_end - 1] == 10 {
                            body_end -= 1;
                        }
                        if body_end > stream_offset && data[body_end - 1] == 13 {
                            body_end -= 1;
                        }
                        stream_size = body_end - stream_offset;
                        offset = es + 9;
                        offset = skip_pdf_ending(data, offset);
                        result.streams.push((stream_offset, stream_size));
                        continue;
                    }
                    None => break,
                }
            }

            offset += stream_size;
            offset = skip_pdf_ending(data, offset);
            result.streams.push((stream_offset, stream_size));
        } else if title == "endstream" {
            // continue
        } else if title.trim() == "endobj" || title.is_empty() {
            break;
        }
    }

    result
}

/// Upstream `_resolveFilterList`: the first `/Filter` entry wins; both the
/// name form (`/FlateDecode`) and the array form (`[/A /B]`) are accepted.
fn resolve_filter_list(parts: &[String], key: &str) -> Vec<String> {
    let mut result = Vec::new();
    let n = parts.len();
    let mut i = 0usize;
    while i + 1 < n {
        if parts[i] == key {
            let next = &parts[i + 1];
            if next == "[" {
                for t in &parts[i + 2..] {
                    if t == "]" {
                        break;
                    }
                    if t.starts_with('/') {
                        result.push(t.clone());
                    }
                }
            } else if next.starts_with('/') {
                result.push(next.clone());
            }
            break;
        }
        i += 1;
    }
    result
}

/// Compute the Adler-32 checksum (RFC 1950) of `data`.
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a = 1u32;
    let mut b = 0u32;
    // Chunked to delay the modulo while staying deterministic.
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// Decode a zlib (FlateDecode) buffer mirroring upstream
/// `XDeflateDecoder::decompress_zlib` as used by `decompressPdfBuffer`:
/// the buffer must be a complete RFC 1950 stream — valid CMF/FLG header,
/// the raw-DEFLATE payload must terminate exactly at the end of the
/// declared region, and the Adler-32 footer must match the output.
/// Any deviation yields an empty buffer (upstream discards the staged
/// output on validation failure), even when the payload inflates to
/// usable bytes. Other filter methods yield an empty buffer, which
/// upstream treats as undecodable.
fn zlib_decode_bounded(raw: &[u8], max_out: u64) -> Vec<u8> {
    // Upstream rejects inputs smaller than header+footer (nInputLimit < 6).
    if raw.len() < 6 {
        return Vec::new();
    }
    let cmf = raw[0];
    let flg = raw[1];
    let header = (u16::from(cmf) << 8) | u16::from(flg);
    // RFC 1950: DEFLATE method, window <= 32 KiB, header divisible by 31,
    // and no preset dictionary.
    if (cmf & 0x0f) != 8 || (cmf >> 4) > 7 || (header % 31) != 0 || (flg & 0x20) != 0 {
        return Vec::new();
    }
    let expected_adler = u32::from_be_bytes(raw[raw.len() - 4..].try_into().unwrap());
    let deflate = &raw[2..raw.len() - 4];

    let mut decomp = flate2::Decompress::new(false);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let before_in = decomp.total_in() as usize;
        let before_out = decomp.total_out() as usize;
        let status = decomp.decompress(
            &deflate[before_in.min(deflate.len())..],
            &mut chunk,
            flate2::FlushDecompress::None,
        );
        let produced = decomp.total_out() as usize - before_out;
        out.extend_from_slice(&chunk[..produced]);
        match status {
            Ok(flate2::Status::StreamEnd) => break,
            Ok(flate2::Status::Ok) | Ok(flate2::Status::BufError) => {
                // No forward progress without a stream end means the input
                // was truncated or corrupt.
                let progressed = decomp.total_in() as usize != before_in || produced > 0;
                if !progressed || decomp.total_in() as usize >= deflate.len() {
                    return Vec::new();
                }
            }
            Err(_) => return Vec::new(),
        }
        if out.len() as u64 > max_out {
            return Vec::new();
        }
    }

    // The deflate member must consume the entire declared region and the
    // Adler-32 footer must authenticate the output.
    if decomp.total_in() as usize != deflate.len() {
        return Vec::new();
    }
    if out.len() as u64 > max_out || adler32(&out) != expected_adler {
        return Vec::new();
    }
    out
}

/// Upstream `_applyPredictor`: undo TIFF predictor 2 and PNG row filters
/// (predictor >= 10) on decoded xref-stream data.
fn apply_predictor(data_in: &[u8], predictor: i32, columns: i32, colors: i32, bpc: i32) -> Vec<u8> {
    if predictor < 2 {
        return data_in.to_vec();
    }
    if columns <= 0 || colors <= 0 || bpc <= 0 {
        return Vec::new();
    }
    let bpp_wide = ((i64::from(colors) * i64::from(bpc)) + 7) / 8;
    let row_len_wide = ((i64::from(columns) * i64::from(colors) * i64::from(bpc)) + 7) / 8;
    if row_len_wide <= 0 || row_len_wide > 64 * 1024 * 1024 {
        return Vec::new();
    }
    let bpp = bpp_wide.max(1) as usize;
    let row_len = row_len_wide as usize;

    if predictor == 2 {
        // TIFF predictor 2 (horizontal differencing); 8-bit only.
        if bpc != 8 {
            return Vec::new();
        }
        let mut out = data_in.to_vec();
        let rows = data_in.len() / row_len;
        for r in 0..rows {
            let base = r * row_len;
            for c in bpp..row_len {
                out[base + c] = out[base + c].wrapping_add(out[base + c - bpp]);
            }
        }
        return out;
    }

    // PNG predictors (>= 10): each row is prefixed by a filter-type byte.
    let stride = row_len + 1;
    let rows = data_in.len() / stride;
    let mut out = vec![0u8; rows * row_len];
    let mut prev = vec![0u8; row_len];
    for r in 0..rows {
        let in_base = r * stride;
        let filter = data_in[in_base];
        let mut row = vec![0u8; row_len];
        row.copy_from_slice(&data_in[in_base + 1..in_base + 1 + row_len]);
        for c in 0..row_len {
            let a = if c >= bpp { i32::from(row[c - bpp]) } else { 0 };
            let b = i32::from(prev[c]);
            let cc = if c >= bpp {
                i32::from(prev[c - bpp])
            } else {
                0
            };
            let x = i32::from(row[c]);
            let v = match filter {
                1 => x + a,
                2 => x + b,
                3 => x + ((a + b) >> 1),
                4 => {
                    let p = a + b - cc;
                    let pa = (p - a).abs();
                    let pb = (p - b).abs();
                    let pc = (p - cc).abs();
                    let pred = if pa <= pb && pa <= pc {
                        a
                    } else if pb <= pc {
                        b
                    } else {
                        cc
                    };
                    x + pred
                }
                _ => x,
            };
            row[c] = (v & 0xFF) as u8;
        }
        out[r * row_len..r * row_len + row_len].copy_from_slice(&row);
        prev = row;
    }
    out
}

/// Read a big-endian unsigned integer of `width` bytes (0..8) at `pos`
/// (upstream `readBEValue`).
fn read_be_value(data: &[u8], pos: usize, width: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..width {
        v = (v << 8) | u64::from(data[pos + i]);
    }
    v
}

/// Upstream `getObjectsFromXrefStream`: decode a cross-reference stream
/// object (and its `/Prev` chain) into an object list. Returns
/// `(objects, is_xref_stream)` — `is_xref_stream` is only true when objects
/// were actually recovered, so callers fall back to the brute-force scan on
/// corrupt bodies.
fn objects_from_xref_stream(
    data: &[u8],
    xref_offset: usize,
    id_map: &std::collections::HashMap<u64, usize>,
) -> (Vec<PdfObject>, bool) {
    const DECODE_LIMIT: u64 = 100 * 1024 * 1024;
    let mut result = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut seen_ids = std::collections::HashSet::new();
    let file_size = data.len();
    let mut current = xref_offset as i64;

    while current >= 0 && (current as usize) < file_size && !visited.contains(&current) {
        visited.insert(current);

        let (head, _) = read_pdf_string(data, current as usize, 40);
        if parse_object_header(&head).is_none() {
            break;
        }

        let xpart = handle_xpart(data, current as usize, 0, -1, true, id_map);
        if get_value_by_key(&xpart.parts, "/Type") != Some("/XRef") || xpart.streams.is_empty() {
            break;
        }

        // /W [ a b c ] field widths.
        let (mut w0, mut w1, mut w2) = (0i64, 0i64, 0i64);
        if let Some(wpos) = xpart.parts.iter().position(|t| t == "/W")
            && xpart.parts.get(wpos + 1).map(|s| s.as_str()) == Some("[")
        {
            let mut w = Vec::new();
            for t in &xpart.parts[wpos + 2..] {
                if t == "]" {
                    break;
                }
                w.push(q_to_i64(t));
            }
            if w.len() >= 3 {
                w0 = w[0];
                w1 = w[1];
                w2 = w[2];
            }
        }
        let row_len = w0 + w1 + w2;
        if row_len <= 0 || w0 < 0 || w1 < 0 || w2 < 0 || w0 > 8 || w1 > 8 || w2 > 8 {
            break;
        }

        let size_field = get_value_by_key(&xpart.parts, "/Size")
            .map(q_to_i64)
            .unwrap_or(0);

        // /Index [ start count ... ] (default [0 Size]).
        let mut index: Vec<i64> = Vec::new();
        if let Some(ipos) = xpart.parts.iter().position(|t| t == "/Index")
            && xpart.parts.get(ipos + 1).map(|s| s.as_str()) == Some("[")
        {
            for t in &xpart.parts[ipos + 2..] {
                if t == "]" {
                    break;
                }
                index.push(q_to_i64(t));
            }
        }
        if index.len() < 2 {
            index.clear();
            index.push(0);
            index.push(if size_field > 0 { size_field } else { 0 });
        }

        let filters = resolve_filter_list(&xpart.parts, "/Filter");
        let filter = filters.last().map(|s| s.as_str()).unwrap_or("");

        let (s_off, s_size) = xpart.streams[0];
        let mut stream_data: Vec<u8> = Vec::new();
        if s_off <= file_size
            && s_size > 0
            && s_size <= file_size - s_off
            && (s_size as u64) <= DECODE_LIMIT
        {
            let raw = &data[s_off..s_off + s_size];
            stream_data = match filter {
                "" => raw.to_vec(),
                "/FlateDecode" => zlib_decode_bounded(raw, DECODE_LIMIT),
                // No decoder for LZW/ASCII85/ASCIIHex/RunLength here; the
                // undecodable result mirrors a failed decompress.
                _ => Vec::new(),
            };
        }

        // Predictor fields.
        let mut predictor = 1i64;
        let mut columns = 1i64;
        let mut colors = 1i64;
        let mut bits = 8i64;
        for (key, slot) in [
            ("/Predictor", &mut predictor),
            ("/Columns", &mut columns),
            ("/Colors", &mut colors),
            ("/BitsPerComponent", &mut bits),
        ] {
            if let Some(v) = get_value_by_key(&xpart.parts, key) {
                *slot = q_to_i64(v);
            }
        }
        if predictor >= 2 {
            stream_data = apply_predictor(
                &stream_data,
                predictor as i32,
                columns as i32,
                colors as i32,
                bits as i32,
            );
        }

        let data_size = stream_data.len() as i64;
        let mut row = 0i64;
        let pairs = index.len() / 2;
        for s in 0..pairs {
            let start_id = index[s * 2];
            let count = index[s * 2 + 1];
            for k in 0..count {
                if (row + 1) * row_len > data_size {
                    break;
                }
                let base = (row * row_len) as usize;
                let f1 = if w0 == 0 {
                    1
                } else {
                    read_be_value(&stream_data, base, w0 as usize)
                };
                let f2 = read_be_value(&stream_data, base + w0 as usize, w1 as usize);
                let obj_id = (start_id + k) as u64;
                if f1 == 1 {
                    let off = f2 as usize;
                    if off > 0 && off < file_size && !seen_ids.contains(&obj_id) {
                        result.push(PdfObject {
                            id: obj_id,
                            offset: off,
                            end: 0,
                        });
                        seen_ids.insert(obj_id);
                    }
                }
                row += 1;
            }
        }

        current = get_value_by_key(&xpart.parts, "/Prev")
            .map(q_to_i64)
            .unwrap_or(-1);
    }

    let is_stream = !result.is_empty();

    if is_stream {
        // Order by file offset and derive per-object sizes.
        let mut by_off: std::collections::BTreeMap<usize, u64> = std::collections::BTreeMap::new();
        for o in result {
            by_off.insert(o.offset, o.id);
        }
        result = by_off
            .into_iter()
            .map(|(offset, id)| PdfObject { id, offset, end: 0 })
            .collect();
        for i in 0..result.len().saturating_sub(1) {
            result[i].end = result[i + 1].offset;
        }
        // Last object's end stays 0/unknown (upstream nSize = 0).
    }

    (result, is_stream)
}

/// Enumerate PDF objects the way upstream `XPDF::scanStructure` does:
/// `startxref` footers drive xref-table or xref-stream walks; when no valid
/// footer exists a non-deep `N G obj` line scan is used (it stops at the
/// first non-object/non-comment line). Objects are deduplicated by offset;
/// later sections overwrite the id→offset map.
fn scan_structure(data: &[u8]) -> (Vec<PdfObject>, std::collections::HashMap<u64, usize>) {
    let mut objects: Vec<PdfObject> = Vec::new();
    let mut id_map: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();

    let hrefs = find_startxrefs(data);
    if !hrefs.is_empty() {
        let mut seen_offsets = std::collections::HashSet::new();
        for href in &hrefs {
            let part = if href.is_object {
                let (objs, is_stream) = objects_from_xref_stream(data, href.xref_offset, &id_map);
                if is_stream {
                    objs
                } else {
                    // Not a decodable xref stream: fall back to the
                    // brute-force deep scan up to the footer.
                    find_objects_range(data, 0, Some(href.footer_offset), true)
                }
            } else {
                objects_from_xref_table(data, href.xref_offset)
            };
            for o in part {
                if seen_offsets.insert(o.offset) {
                    id_map.insert(o.id, o.offset);
                    objects.push(o);
                } else {
                    // Later (newer) sections overwrite the id map.
                    id_map.insert(o.id, o.offset);
                }
            }
        }
    } else {
        objects = find_objects_range(data, 0, None, false);
        for o in &objects {
            id_map.insert(o.id, o.offset);
        }
    }

    (objects, id_map)
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

/// Upstream `_isDateTime`: `(D:...)` with at least 18 bytes classifies as
/// VT_DATETIME in `_parseValue`, so it is NOT a string value even though it
/// has string parentheses.
fn is_pdf_datetime_token(tok: &str) -> bool {
    tok.len() >= 18 && tok.starts_with("(D:") && tok.ends_with(')')
}

/// Upstream `PDF_Script::getStringValuesByKey`: for every object's token
/// list (`getParts(20)` over the `scanStructure` object set), a token equal
/// to `key` takes the next token, which is kept only when `_parseValue`
/// yields a VT_STRING — i.e. a `(...)` literal that is not a `(D:...)`
/// datetime; `_getString` strips the outer parens (no escape processing).
/// Values are deduplicated in file order.
pub fn get_string_values_by_key(data: &[u8], key: &str) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    let (objects, _) = scan_structure(data);
    for obj in &objects {
        let parts = object_dict_parts(data, obj.offset, 20);
        let n = parts.len();
        let mut j = 0usize;
        while j + 1 < n {
            if parts[j] == key {
                let tok = &parts[j + 1];
                if tok.len() >= 2
                    && tok.starts_with('(')
                    && tok.ends_with(')')
                    && !is_pdf_datetime_token(tok)
                {
                    let value = &tok[1..tok.len() - 1];
                    if !result.iter().any(|v| v == value) {
                        result.push(value.to_string());
                    }
                }
            }
            j += 1;
        }
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
    let (objects, id_offset) = scan_structure(data);
    if objects.is_empty() {
        return None;
    }

    let encrypt_id = find_trailer_encrypt_id(data);
    let auth_offset = encrypt_id.and_then(|id| id_offset.get(&id).copied());

    let mut fallback: Option<Vec<String>> = None;

    for obj in &objects {
        // Fast reject: the /Filter name token must appear in the raw object.
        // xref-derived objects may carry end == 0 (unknown size, last
        // entry); fall back to EOF in that case.
        let end = if obj.end > obj.offset {
            obj.end.min(data.len())
        } else {
            data.len()
        };
        let raw = &data[obj.offset..end];
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

    /// Compress `payload` into a complete zlib stream (header + deflate +
    /// Adler-32 footer).
    fn zlib_stream(payload: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap()
    }

    /// Produce a zlib stream that was flushed with `Z_SYNC_FLUSH` and never
    /// finished — the deflate payload inflates fine but the final block and
    /// the Adler-32 footer are missing, which upstream
    /// `decompress_zlib` rejects wholesale.
    fn zlib_syncflush_truncated(payload: &[u8]) -> Vec<u8> {
        let mut comp = flate2::Compress::new(flate2::Compression::default(), true);
        let mut out = vec![0u8; payload.len() * 2 + 64];
        comp.compress_vec(payload, &mut out, flate2::FlushCompress::Sync)
            .unwrap();
        out.truncate(comp.total_out() as usize);
        out
    }

    /// Append an indirect object, returning its byte offset.
    fn append_obj(pdf: &mut Vec<u8>, id: u64, body: &str) -> usize {
        let off = pdf.len();
        pdf.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
        off
    }

    /// Append an xref-stream object covering `entries` `(id, offset)` pairs
    /// (each emitted as a one-object `/Index` run with `W[1 4 2]`),
    /// optionally chained to a previous xref at `prev`. When `truncated` is
    /// set, the stream body is a sync-flushed buffer that upstream cannot
    /// validate. Returns the stream object's offset.
    fn append_xref_stream(
        pdf: &mut Vec<u8>,
        id: u64,
        entries: &[(u64, usize)],
        prev: Option<usize>,
        truncated: bool,
    ) -> usize {
        let mut rows = Vec::new();
        let mut index = String::new();
        for &(oid, off) in entries {
            index.push_str(&format!("{oid} 1 "));
            rows.push(1u8);
            rows.extend_from_slice(&(off as u32).to_be_bytes());
            rows.extend_from_slice(&[0u8, 0u8]);
        }
        let comp = if truncated {
            zlib_syncflush_truncated(&rows)
        } else {
            zlib_stream(&rows)
        };
        let prev_part = prev.map(|p| format!("/Prev {p}")).unwrap_or_default();
        let off = pdf.len();
        pdf.extend_from_slice(
            format!(
                "{id} 0 obj\n<</Type/XRef/Size 1000/W[1 4 2]/Index[{index}]/Filter/FlateDecode/Length {}{prev_part}>>\nstream\n",
                comp.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&comp);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        off
    }

    /// Append `startxref` + `%%EOF` footer pointing at `xref_off`.
    fn append_footer(pdf: &mut Vec<u8>, xref_off: usize) {
        pdf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    }

    /// Header used by all fixture PDFs.
    fn pdf_header() -> Vec<u8> {
        b"%PDF-1.5\n%\xe4\xe5\xf2\xe5\n".to_vec()
    }

    /// Object reachable only through a valid xref stream.
    #[test]
    fn xref_stream_object_values() {
        let mut pdf = pdf_header();
        let off1 = append_obj(&mut pdf, 1, "<</Producer(TestProd)/Creator(TeX)>>");
        let xoff = append_xref_stream(&mut pdf, 9, &[(1, off1)], None, false);
        append_footer(&mut pdf, xoff);
        assert_eq!(
            get_string_values_by_key(&pdf, "/Producer"),
            vec!["TestProd".to_string()]
        );
        assert_eq!(
            get_string_values_by_key(&pdf, "/Creator"),
            vec!["TeX".to_string()]
        );
    }

    /// Classic xref table enumerates objects (upstream
    /// `getObjectsFromStartxref`).
    #[test]
    fn classic_xref_table_object_values() {
        let mut pdf = pdf_header();
        let off1 = append_obj(&mut pdf, 1, "<</Producer(ClassicProd)>>");
        let xref_off = pdf.len();
        pdf.extend_from_slice(
            format!("xref\n0 2\n0000000000 65535 f \n{off1:010} 00000 n \ntrailer\n<</Size 2>>\n")
                .as_bytes(),
        );
        append_footer(&mut pdf, xref_off);
        assert_eq!(
            get_string_values_by_key(&pdf, "/Producer"),
            vec!["ClassicProd".to_string()]
        );
    }

    /// Incremental update: the newer revision's xref stream adds its own
    /// objects and chains to the previous one via `/Prev`.
    #[test]
    fn incremental_xref_stream_chain() {
        let mut pdf = pdf_header();
        let off1 = append_obj(&mut pdf, 1, "<</Producer(OldProd)>>");
        let x1 = append_xref_stream(&mut pdf, 9, &[(1, off1)], None, false);
        append_footer(&mut pdf, x1);
        let off2 = append_obj(&mut pdf, 2, "<</Producer(NewProd)>>");
        let x2 = append_xref_stream(&mut pdf, 10, &[(2, off2)], Some(x1), false);
        append_footer(&mut pdf, x2);
        assert_eq!(
            get_string_values_by_key(&pdf, "/Producer"),
            vec!["OldProd".to_string(), "NewProd".to_string()]
        );
    }

    /// A truncated (sync-flushed, no Adler-32 trailer) xref stream cannot be
    /// validated upstream, so its rows are discarded; the `/Prev` chain still
    /// supplies the older revision's objects and suppresses the brute-force
    /// fallback (upstream `pdfjs_highlights.pdf` semantics).
    #[test]
    fn truncated_xref_stream_with_prev_drops_new_revision() {
        let mut pdf = pdf_header();
        let off1 = append_obj(&mut pdf, 1, "<</Producer(OldProd)>>");
        let x1 = append_xref_stream(&mut pdf, 9, &[(1, off1)], None, false);
        append_footer(&mut pdf, x1);
        let off2 = append_obj(&mut pdf, 2, "<</Producer(NewProd)>>");
        let x2 = append_xref_stream(&mut pdf, 10, &[(2, off2)], Some(x1), true);
        append_footer(&mut pdf, x2);
        assert_eq!(
            get_string_values_by_key(&pdf, "/Producer"),
            vec!["OldProd".to_string()]
        );
    }

    /// A truncated xref stream without `/Prev` yields no objects, so the
    /// caller falls back to the brute-force deep scan which still locates
    /// the physical objects.
    #[test]
    fn truncated_xref_stream_deep_scan_fallback() {
        let mut pdf = pdf_header();
        let off1 = append_obj(&mut pdf, 1, "<</Producer(FallbackProd)>>");
        let x1 = append_xref_stream(&mut pdf, 9, &[(1, off1)], None, true);
        append_footer(&mut pdf, x1);
        assert_eq!(
            get_string_values_by_key(&pdf, "/Producer"),
            vec!["FallbackProd".to_string()]
        );
    }

    /// `/Prev` forming a cycle must terminate via the visited set.
    #[test]
    fn cyclic_prev_terminates() {
        let mut pdf = pdf_header();
        let off1 = append_obj(&mut pdf, 1, "<</Producer(Cyclic)>>");
        // First emit a placeholder to learn the xref offset.
        let x_off = pdf.len();
        let mut rows = Vec::new();
        rows.push(1u8);
        rows.extend_from_slice(&(off1 as u32).to_be_bytes());
        rows.extend_from_slice(&[0u8, 0u8]);
        let comp = zlib_stream(&rows);
        pdf.extend_from_slice(
            format!(
                "9 0 obj\n<</Type/XRef/Size 1000/W[1 4 2]/Index[1 1]/Filter/FlateDecode/Length {}/Prev {x_off}>>\nstream\n",
                comp.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&comp);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        append_footer(&mut pdf, x_off);
        assert_eq!(
            get_string_values_by_key(&pdf, "/Producer"),
            vec!["Cyclic".to_string()]
        );
    }

    /// Without a valid `startxref` the non-deep fallback scan stops at the
    /// first line that is neither an object header nor a comment.
    #[test]
    fn no_startxref_nondeep_scan_stops() {
        let pdf = concat!(
            "%PDF-1.4\n",
            "1 0 obj\n<</Producer(First)>>\nendobj\n",
            "GARBAGE LINE\n",
            "2 0 obj\n<</Producer(Second)>>\nendobj\n"
        );
        assert_eq!(
            get_string_values_by_key(pdf.as_bytes(), "/Producer"),
            vec!["First".to_string()]
        );
    }

    /// `(D:...)` datetime literals classify as VT_DATETIME upstream and are
    /// not returned by `getStringValuesByKey`.
    #[test]
    fn datetime_values_excluded() {
        let mut pdf = pdf_header();
        let off1 = append_obj(
            &mut pdf,
            1,
            "<</ModDate(D:20240708143103Z00'00')/Producer(P)>>",
        );
        let xoff = append_xref_stream(&mut pdf, 9, &[(1, off1)], None, false);
        append_footer(&mut pdf, xoff);
        assert!(get_string_values_by_key(&pdf, "/ModDate").is_empty());
        assert_eq!(
            get_string_values_by_key(&pdf, "/Producer"),
            vec!["P".to_string()]
        );
    }

    /// Literal strings with nested parentheses and escaped parens tokenize
    /// like upstream `_readPDFStringPart_str`.
    #[test]
    fn literal_string_nested_and_escaped() {
        let mut pdf = pdf_header();
        let off1 = append_obj(&mut pdf, 1, "<</A(a(b)c)/B(x\\)y)/Producer(done)>>");
        let xoff = append_xref_stream(&mut pdf, 9, &[(1, off1)], None, false);
        append_footer(&mut pdf, xoff);
        assert_eq!(
            get_string_values_by_key(&pdf, "/A"),
            vec!["a(b)c".to_string()]
        );
        // Upstream drops the backslash itself; only the escaped char lands.
        assert_eq!(
            get_string_values_by_key(&pdf, "/B"),
            vec!["x)y".to_string()]
        );
        assert_eq!(
            get_string_values_by_key(&pdf, "/Producer"),
            vec!["done".to_string()]
        );
    }

    /// `(FEFF...)` literal strings take the UTF-16BE branch of upstream
    /// `_readPDFStringPart_str` and decode word-by-word.
    #[test]
    fn bom_literal_string_decodes_utf16() {
        let mut pdf = pdf_header();
        // (\xFE\xFF\x00H\x00i) decodes to "Hi".
        let off1 = {
            let off = pdf.len();
            pdf.extend_from_slice(b"1 0 obj\n<</A(\xfe\xff\x00H\x00i)/Producer(done)>>\nendobj\n");
            off
        };
        let xoff = append_xref_stream(&mut pdf, 9, &[(1, off1)], None, false);
        append_footer(&mut pdf, xoff);
        assert_eq!(get_string_values_by_key(&pdf, "/A"), vec!["Hi".to_string()]);
        assert_eq!(
            get_string_values_by_key(&pdf, "/Producer"),
            vec!["done".to_string()]
        );
    }

    /// `zlib_decode_bounded` is all-or-nothing like upstream
    /// `decompress_zlib`: a sync-flushed stream (missing final block and
    /// Adler-32) yields no data even though the payload inflates.
    #[test]
    fn zlib_decode_bounded_strict() {
        let payload = b"0123456789abcdef0123456789abcdef";
        let good = zlib_stream(payload);
        assert_eq!(zlib_decode_bounded(&good, 1024), payload);

        // Truncated (no adler): upstream discards the whole buffer.
        let trunc = zlib_syncflush_truncated(payload);
        assert!(zlib_decode_bounded(&trunc, 1024).is_empty());

        // Adler stripped: deflate ends early, validation fails.
        let no_adler = &good[..good.len() - 4];
        assert!(zlib_decode_bounded(no_adler, 1024).is_empty());

        // Corrupted adler.
        let mut bad_adler = good.clone();
        *bad_adler.last_mut().unwrap() ^= 0xFF;
        assert!(zlib_decode_bounded(&bad_adler, 1024).is_empty());

        // Garbage and too-short inputs.
        assert!(zlib_decode_bounded(b"\x00\x01\x02", 1024).is_empty());
        assert!(zlib_decode_bounded(b"", 1024).is_empty());
    }

    /// A hostile xref subsection count must terminate at EOF instead of
    /// spinning (upstream relies on `osObject.nSize <= 0` to break).
    #[test]
    fn hostile_subsection_count_safe() {
        let mut pdf = pdf_header();
        pdf.extend_from_slice(b"xref\n0 99999999999\n");
        let xoff_marker = pdf.len();
        let _ = xoff_marker;
        pdf.extend_from_slice(b"startxref\n15\n%%EOF\n");
        // Just must not hang; result content is not important.
        let _ = get_string_values_by_key(&pdf, "/Producer");
    }
}

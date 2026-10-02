//! XBinary signature engine: parser and matcher for DIE/NFD signature
//! strings (`hex`, `.`/`?` nibbles, `'ansi'` literals, `%%`/`%&`/`!%`/`_%`
//! byte classes, `*` non-null, `+` find-bytes, `$` relative-offset jump,
//! `#` address jump).
//!
//! Semantics mirror `XBinary::getSignatureRecords`/`compareSignature`/
//! `find_signature` in upstream `Formats/xbinary.cpp` (DIE-engine
//! 23fec32). Shared by the DIE rule host API and the NFD scan engine.

/// A parsed signature element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigElement {
    /// Exact byte match.
    Byte(u8),
    /// Wildcard: matches any single byte (`..` nibble pair or `?` in signature).
    Any,
    /// Non-null byte: `**` pair matches any byte != 0x00.
    NotNull,
    /// ANSI character: matches any printable ASCII byte (0x20-0x7E).
    /// `%%` in signature.
    Ansi,
    /// ANSI alphanumeric: `%&` matches 0-9, A-Z, a-z.
    AnsiNum,
    /// Non-ANSI byte: `!%` matches any byte outside 0x20-0x7E.
    NotAnsi,
    /// Non-ANSI non-null byte: `_%` matches byte outside 0x20-0x7E and != 0x00.
    NotAnsiNotNull,
    /// Relative offset jump: read N bytes as signed integer,
    /// compute target = current_offset + value + N, then continue
    /// matching at the target offset. Used for x86 call/jmp instructions.
    /// The target offset is resolved via RVA→file-offset conversion.
    RelOffset(usize),
    /// Forward byte search: `+` run (N times) followed by a byte pattern
    /// searches the pattern within the next `32 * N` bytes and continues
    /// matching right after the first hit (upstream ST_FINDBYTES).
    /// `+` operator: find `pattern` bytes within `delta` bytes ahead.
    FindBytes {
        /// Byte pattern to locate.
        pattern: Vec<u8>,
        /// Search window size in bytes (upstream: `32 * count`).
        delta: u64,
    },
}

/// A signature parse failure. `byte_level` mirrors whether upstream
/// `XBinary::_getSignatureBytes`/`convertSignature` would reject the
/// token — those failures make upstream record an "Invalid signature"
/// scan error. Structural failures that upstream's record validator
/// rejects silently (odd `.`/`$`/`#` runs, malformed `[base]`, a `+`
/// with no byte pattern) are flagged `byte_level == false`.
#[derive(Debug, Clone)]
pub struct SignatureError {
    /// Human-readable parse failure detail.
    pub detail: String,
    /// Whether upstream records "Invalid signature" for this failure class.
    pub byte_level: bool,
}

impl SignatureError {
    fn byte_level(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            byte_level: true,
        }
    }

    fn structural(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            byte_level: false,
        }
    }
}

/// Returns `Err` if the signature is malformed.
pub fn parse_signature(signature: &str) -> Result<Vec<SigElement>, String> {
    parse_signature_ex(signature).map_err(|e| e.detail)
}

/// Parse a signature into match elements, distinguishing byte-level
/// failures (upstream records "Invalid signature") from structural
/// failures (upstream rejects silently).
///
/// Mirrors `XBinary::getSignatureRecords` validity rules: hex runs and
/// `.`/`?` runs must consume an even number of nibbles; `$`/`#` runs must
/// produce a 1/2/4/8-byte address; lone `!`/`_`/`%` fall through to the
/// byte tokenizer and fail there; any other character is invalid.
pub fn parse_signature_ex(signature: &str) -> Result<Vec<SigElement>, SignatureError> {
    let mut elements = Vec::new();
    let chars: Vec<char> = signature.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if c.is_whitespace() {
            i += 1;
            continue;
        }

        if c == '\'' {
            // String literal: upstream convertSignature expands every
            // latin1 char into hex — no escape processing at this layer
            // (JS string literals were already unescaped when the rule
            // source was parsed). Chars > 0xFF invalidate the signature.
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                let ch = chars[i];
                if (ch as u32) > 0xFF {
                    return Err(SignatureError::byte_level(
                        "non-latin1 character in string literal",
                    ));
                }
                elements.push(SigElement::Byte(ch as u8));
                i += 1;
            }
            if i >= chars.len() {
                return Err(SignatureError::byte_level(
                    "unterminated string literal in signature",
                ));
            }
            i += 1; // skip closing quote
            continue;
        }

        if c == '$' {
            // Relative offset jump marker: read consecutive $ characters.
            // N pairs of $ = N-byte signed relative offset.
            // e.g. $$$$ = 2-byte rel offset, $$$$$$$$ = 4-byte rel offset.
            let mut count = 0usize;
            while i < chars.len() && chars[i] == '$' {
                count += 1;
                i += 1;
            }
            let addr_size = count / 2;
            if !count.is_multiple_of(2)
                || (addr_size != 1 && addr_size != 2 && addr_size != 4 && addr_size != 8)
            {
                return Err(SignatureError::structural(format!(
                    "invalid $ count ({count}) in signature"
                )));
            }
            elements.push(SigElement::RelOffset(addr_size));
            continue;
        }

        if c == '#' {
            // ST_ADDRESS: `#` run of N -> reads N/2-byte address and jumps.
            // Count must be even and produce a 1/2/4/8-byte address;
            // approximate the address resolution as a wildcard for now.
            let mut count = 0usize;
            while i < chars.len() && chars[i] == '#' {
                count += 1;
                i += 1;
            }
            // Optional [hexbase] suffix — consume it for syntax parity.
            // Upstream rejects a malformed base silently (no record is
            // appended and the validator fails the record-count check).
            if i < chars.len() && chars[i] == '[' {
                let mut j = i + 1;
                let mut valid_base = true;
                while j < chars.len() && chars[j] != ']' {
                    if !chars[j].is_ascii_hexdigit() {
                        valid_base = false;
                    }
                    j += 1;
                }
                if j >= chars.len() || j == i + 1 || !valid_base {
                    return Err(SignatureError::structural(
                        "invalid # base address in signature",
                    ));
                }
                i = j + 1;
            }
            let addr_size = count / 2;
            if !count.is_multiple_of(2)
                || (addr_size != 1 && addr_size != 2 && addr_size != 4 && addr_size != 8)
            {
                return Err(SignatureError::structural(format!(
                    "invalid # count ({count}) in signature"
                )));
            }
            for _ in 0..addr_size {
                elements.push(SigElement::Any);
            }
            continue;
        }

        if c == '!' {
            // `!%` pair: not-ANSI byte (outside 0x20-0x7E). Any other
            // sequence falls through to the byte tokenizer upstream and
            // fails as a non-hex character (byte-level error).
            if i + 1 < chars.len() && chars[i + 1] == '%' {
                elements.push(SigElement::NotAnsi);
                i += 2;
                continue;
            }
            return Err(SignatureError::byte_level(
                "invalid ! sequence in signature",
            ));
        }

        if c == '_' {
            // `_%` pair: not-ANSI and not-null byte.
            if i + 1 < chars.len() && chars[i + 1] == '%' {
                elements.push(SigElement::NotAnsiNotNull);
                i += 2;
                continue;
            }
            return Err(SignatureError::byte_level(
                "invalid _ sequence in signature",
            ));
        }

        if c == '%' {
            // `%%` = ANSI printable byte; `%&` = ANSI alphanumeric byte.
            if i + 1 < chars.len() && chars[i + 1] == '%' {
                elements.push(SigElement::Ansi);
                i += 2;
                continue;
            }
            if i + 1 < chars.len() && chars[i + 1] == '&' {
                elements.push(SigElement::AnsiNum);
                i += 2;
                continue;
            }
            return Err(SignatureError::byte_level(
                "invalid % sequence in signature",
            ));
        }

        if c == '+' {
            // ST_FINDBYTES: `+` run of N then a hex byte pattern — search
            // the pattern within the next 32*N bytes. Upstream delegates
            // the pattern to the byte tokenizer, so non-hex characters or
            // an odd hex run are byte-level errors; a `+` run followed by
            // nothing or another marker is a silent structural failure.
            let mut count = 0u64;
            while i < chars.len() && chars[i] == '+' {
                count += 1;
                i += 1;
            }
            let mut pattern = Vec::new();
            while i + 1 < chars.len()
                && chars[i].is_ascii_hexdigit()
                && chars[i + 1].is_ascii_hexdigit()
            {
                let h1 = chars[i].to_digit(16).unwrap_or(0) as u8;
                let h2 = chars[i + 1].to_digit(16).unwrap_or(0) as u8;
                pattern.push(h1 * 16 + h2);
                i += 2;
            }
            if i < chars.len() && chars[i].is_ascii_hexdigit() {
                return Err(SignatureError::byte_level(
                    "odd number of hex digits after +",
                ));
            }
            if pattern.is_empty() {
                if i < chars.len()
                    && !matches!(chars[i], '.' | '$' | '#' | '*' | '!' | '_' | '%' | '+')
                {
                    return Err(SignatureError::byte_level(format!(
                        "invalid character '{}' after + in signature",
                        chars[i]
                    )));
                }
                return Err(SignatureError::structural("missing byte pattern after +"));
            }
            elements.push(SigElement::FindBytes {
                pattern,
                delta: 32 * count,
            });
            continue;
        }

        if c == '*' {
            // ST_NOTNULL: `*` run of N -> N/2 bytes must all be non-null.
            let mut count = 0usize;
            while i < chars.len() && chars[i] == '*' {
                count += 1;
                i += 1;
            }
            if !count.is_multiple_of(2) {
                return Err(SignatureError::structural("odd number of * in signature"));
            }
            for _ in 0..(count / 2) {
                elements.push(SigElement::NotNull);
            }
            continue;
        }

        if c == '.' || c == '?' {
            // ST_SKIP: `.`/`?` run of N -> skip N/2 bytes. Odd runs are
            // rejected silently by upstream's record validator.
            let mut count = 0usize;
            while i < chars.len() && (chars[i] == '.' || chars[i] == '?') {
                count += 1;
                i += 1;
            }
            if !count.is_multiple_of(2) {
                return Err(SignatureError::structural(
                    "odd number of wildcard nibbles in signature",
                ));
            }
            for _ in 0..(count / 2) {
                elements.push(SigElement::Any);
            }
            continue;
        }

        if c.is_ascii_hexdigit() {
            // ST_COMPAREBYTES: contiguous hex run, must be an even number of
            // nibbles — upstream marks odd runs invalid (`nConsumed & 1`).
            let start = i;
            while i < chars.len() && chars[i].is_ascii_hexdigit() {
                i += 1;
            }
            let run = &chars[start..i];
            if !run.len().is_multiple_of(2) {
                return Err(SignatureError::byte_level("odd number of hex digits"));
            }
            for pair in run.chunks_exact(2) {
                let h1 = pair[0].to_digit(16).unwrap_or(0) as u8;
                let h2 = pair[1].to_digit(16).unwrap_or(0) as u8;
                elements.push(SigElement::Byte(h1 * 16 + h2));
            }
            continue;
        }

        return Err(SignatureError::byte_level(format!(
            "unexpected character '{c}' in signature"
        )));
    }

    Ok(elements)
}

/// Normalize a signature string the way upstream `XBinary::convertSignature`
/// does: `'literal'` runs become lowercase hex (latin1 chars only), `?`
/// becomes `.`, spaces outside quotes are dropped, and everything else is
/// lowercased. Marker characters are preserved.
///
/// Upstream never reports an error here: an unterminated literal or a
/// non-latin1 char inside quotes makes it return an empty `QString`, which
/// callers then treat as an empty normalized signature (silent fast-path
/// miss in `compare`, silent `-1` in `findSignature`). Reproduced by
/// returning an empty `String`.
pub fn convert_signature(signature: &str) -> String {
    let mut out = String::with_capacity(signature.len());
    let mut in_ansi = false;
    for c in signature.chars() {
        if c == '\'' {
            in_ansi = !in_ansi;
            continue;
        }
        if in_ansi {
            if (c as u32) > 0xFF {
                return String::new();
            }
            out.push_str(&format!("{:02x}", c as u32));
            continue;
        }
        if c == ' ' {
            continue;
        }
        if c == '?' {
            out.push('.');
            continue;
        }
        out.push(c.to_ascii_lowercase());
    }
    if in_ansi {
        return String::new();
    }
    out
}

/// Nibble-level comparison against `data` starting at `offset`, matching
/// upstream `compareSignatureStrings` semantics on the normalized pattern:
/// `.` is a wildcard nibble, hex digits compare exact nibbles, any other
/// character can never equal a file hex nibble and fails the match.
/// Odd pattern lengths are legal — a trailing nibble compares against the
/// high nibble of the next byte.
pub fn nibble_compare(data: &[u8], offset: usize, normalized: &str) -> bool {
    let chars: Vec<char> = normalized.chars().collect();
    let n = chars.len();
    if n == 0 || offset > data.len() {
        return false;
    }
    let avail = (data.len() - offset).saturating_mul(2);
    if avail < n {
        return false;
    }
    for (i, c) in chars.iter().enumerate() {
        if *c == '.' {
            continue;
        }
        let Some(v) = c.to_digit(16) else {
            return false;
        };
        let byte = data[offset + i / 2];
        let nib = if i % 2 == 0 { byte >> 4 } else { byte & 0x0F };
        if nib != v as u8 {
            return false;
        }
    }
    true
}

/// Return true when `byte` satisfies a fixed-width signature element.
fn element_matches_byte(elem: &SigElement, b: u8) -> bool {
    match elem {
        SigElement::Byte(v) => b == *v,
        SigElement::Any => true,
        SigElement::NotNull => b != 0,
        SigElement::Ansi => (0x20..=0x7E).contains(&b),
        SigElement::AnsiNum => b.is_ascii_alphanumeric(),
        SigElement::NotAnsi => !(0x20..=0x7E).contains(&b),
        SigElement::NotAnsiNotNull => !(0x20..=0x7E).contains(&b) && b != 0,
        // Variable-width elements are handled by the cursor matcher.
        SigElement::RelOffset(_) | SigElement::FindBytes { .. } => true,
    }
}

/// Return true when the element consumes a fixed number of bytes.
fn element_is_fixed(elem: &SigElement) -> bool {
    !matches!(
        elem,
        SigElement::RelOffset(_) | SigElement::FindBytes { .. }
    )
}

/// Advance `pos` past `pattern` found within `delta` bytes (ST_FINDBYTES).
/// Mirrors upstream: the search window is `delta + pattern.len()` bytes;
/// returns the position right after the first hit, or None.
fn match_find_bytes(data: &[u8], pos: usize, pattern: &[u8], delta: u64) -> Option<usize> {
    let limit = (delta as usize).saturating_add(pattern.len());
    if pos > data.len() || limit > data.len().saturating_sub(pos) {
        return None;
    }
    let end = pos + limit;
    data[pos..end]
        .windows(pattern.len())
        .position(|w| w == pattern)
        .map(|k| pos + k + pattern.len())
}

/// Read an `n`-byte little-endian signed integer at `pos` (n in 1/2/4/8).
fn read_le_signed(data: &[u8], pos: usize, n: usize) -> Option<i64> {
    if pos.checked_add(n).is_none_or(|end| end > data.len()) {
        return None;
    }
    match n {
        1 => Some(data[pos] as i8 as i64),
        2 => Some(i16::from_le_bytes([data[pos], data[pos + 1]]) as i64),
        4 => Some(i32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as i64),
        8 => Some(i64::from_le_bytes(data[pos..pos + 8].try_into().ok()?)),
        _ => None,
    }
}

/// Match a parsed signature against data at the given offset.
/// `RelOffset` elements follow the upstream flat-file semantics: read the
/// N-byte signed displacement at the current position and continue matching
/// at `pos + value + N` (for non-PE files the file offset is the address).
/// `FindBytes` searches forward per upstream ST_FINDBYTES semantics.
pub fn match_signature(data: &[u8], offset: usize, elements: &[SigElement]) -> bool {
    // An empty element list is not a valid signature upstream.
    if elements.is_empty() {
        return false;
    }
    // Fast path when every element is a fixed single byte.
    if elements.iter().all(element_is_fixed) {
        if offset
            .checked_add(elements.len())
            .is_none_or(|end| end > data.len())
        {
            return false;
        }
        return elements
            .iter()
            .enumerate()
            .all(|(i, elem)| element_matches_byte(elem, data[offset + i]));
    }
    let mut pos = offset;
    for elem in elements.iter() {
        match elem {
            SigElement::FindBytes { pattern, delta } => {
                match match_find_bytes(data, pos, pattern, *delta) {
                    Some(next) => pos = next,
                    None => return false,
                }
            }
            SigElement::RelOffset(n) => {
                // Flat-file jump: read N-byte signed displacement and land at
                // pos + value + N (upstream `ST_RELOFFSET` for raw buffers).
                let Some(value) = read_le_signed(data, pos, *n) else {
                    return false;
                };
                let Ok(delta) = isize::try_from(value) else {
                    return false;
                };
                let Some(target) = pos
                    .checked_add_signed(delta)
                    .and_then(|t| t.checked_add(*n))
                else {
                    return false;
                };
                pos = target;
            }
            _ => {
                if pos >= data.len() || !element_matches_byte(elem, data[pos]) {
                    return false;
                }
                pos += 1;
            }
        }
    }
    true
}

/// Match a parsed signature with PE-aware relative offset resolution.
/// `rva_to_offset` converts a file offset to an RVA (used to compute
/// the jump target for RelOffset elements).
/// Returns true if the signature matches starting at `offset`.
pub fn match_signature_pe(
    data: &[u8],
    offset: usize,
    elements: &[SigElement],
    rva_to_offset: &dyn Fn(u32) -> Option<u32>,
) -> bool {
    let mut pos = offset;
    for elem in elements.iter() {
        match elem {
            SigElement::FindBytes { pattern, delta } => {
                match match_find_bytes(data, pos, pattern, *delta) {
                    Some(next) => pos = next,
                    None => return false,
                }
            }
            SigElement::RelOffset(addr_size) => {
                // Read N-byte signed integer at current position (little-endian).
                if pos + addr_size > data.len() {
                    return false;
                }
                let value: i64 = match addr_size {
                    1 => data[pos] as i8 as i64,
                    2 => i16::from_le_bytes([data[pos], data[pos + 1]]) as i64,
                    4 => {
                        i32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                            as i64
                    }
                    8 => i64::from_le_bytes(data[pos..pos + 8].try_into().unwrap_or([0u8; 8])),
                    _ => return false,
                };
                // Compute target file offset:
                // target_rva = current_rva + value + addr_size
                // target_offset = rva_to_offset(target_rva)
                // We need the RVA of the current position (pos).
                // Since we don't have offset_to_rva here, we approximate:
                // For PE files, file_offset ≈ RVA when sections are aligned
                // (which is the common case for .text at RVA=0x1000, offset=0x1000).
                // The proper way: offset_to_rva(pos) + value + addr_size → rva → offset.
                // We use the inverse of rva_to_offset to get RVA from offset.
                // Since we don't have offset_to_rva, we compute:
                // current_rva = pos (approximation for aligned PE)
                // target_rva = current_rva + value + addr_size
                // target_offset = rva_to_offset(target_rva)
                let current_rva = pos as u32; // Approximation: works for aligned PEs
                let target_rva = current_rva
                    .wrapping_add(value as u32)
                    .wrapping_add(*addr_size as u32);
                match rva_to_offset(target_rva) {
                    Some(target_offset) => {
                        pos = target_offset as usize;
                    }
                    None => return false,
                }
            }
            _ => {
                if pos >= data.len() || !element_matches_byte(elem, data[pos]) {
                    return false;
                }
                pos += 1;
            }
        }
    }
    true
}

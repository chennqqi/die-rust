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
    /// Absolute address jump (`#` run of `2*N` chars): read an N-byte
    /// little-endian *address* and continue matching at the file offset
    /// it maps to through the memory map. Upstream `ST_ADDRESS`; the
    /// optional `[hex]` suffix (`nBaseAddress`) is parsed but unused by
    /// upstream `compareSignature`.
    AbsAddress(usize),
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
            elements.push(SigElement::AbsAddress(addr_size));
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
        SigElement::RelOffset(_) | SigElement::AbsAddress(_) | SigElement::FindBytes { .. } => true,
    }
}

/// Return true when the element consumes a fixed number of bytes.
fn element_is_fixed(elem: &SigElement) -> bool {
    !matches!(
        elem,
        SigElement::RelOffset(_) | SigElement::AbsAddress(_) | SigElement::FindBytes { .. }
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

/// Read an `n`-byte little-endian unsigned integer at `pos`.
fn read_le_unsigned(data: &[u8], pos: usize, n: usize) -> Option<u64> {
    if pos.checked_add(n).is_none_or(|end| end > data.len()) {
        return None;
    }
    match n {
        1 => Some(u64::from(data[pos])),
        2 => Some(u64::from(u16::from_le_bytes([data[pos], data[pos + 1]]))),
        4 => Some(u64::from(u32::from_le_bytes(
            data[pos..pos + 4].try_into().ok()?,
        ))),
        8 => Some(u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?)),
        _ => None,
    }
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

/// Address-space resolution context for `$$`/`#` signature elements,
/// mirroring the `_MEMORY_MAP` handling inside upstream
/// `XBinary::compareSignature`.
///
/// The identity (flat) context — `off_to_addr`/`addr_to_off` `None` —
/// gives the upstream FT_BINARY behavior where address == file offset.
#[derive(Default)]
pub struct SigCtx {
    /// File offset -> address (PE: RVA). `None` means identity.
    pub off_to_addr: Option<Box<dyn Fn(u64) -> Option<u64> + Send + Sync>>,
    /// Address -> file offset (PE: RVA/VA -> offset). `None` means
    /// identity.
    pub addr_to_off: Option<Box<dyn Fn(u64) -> Option<u64> + Send + Sync>>,
    /// FT_COM/FT_MSDOS `$$` semantics: the displacement wraps inside a
    /// 16-bit segment — `pos & !0xffff | u16(low16 + value)`.
    pub seg_wrap16: bool,
    /// FT_MSDOS `#` fields `(nCodeBase, nStartLoadOffset)`. Upstream
    /// leaves `nCodeBase` at 0 (the assignment is commented out).
    pub msdos_addr: Option<(i64, i64)>,
}

impl SigCtx {
    /// Flat identity context (FT_BINARY and friends).
    pub fn flat() -> Self {
        Self::default()
    }
}

/// Match a parsed signature against data at the given offset.
/// `RelOffset` elements follow the upstream flat-file semantics: read the
/// N-byte signed displacement at the current position and continue matching
/// at `pos + value + N` (for non-PE files the file offset is the address).
/// `FindBytes` searches forward per upstream ST_FINDBYTES semantics.
pub fn match_signature(data: &[u8], offset: usize, elements: &[SigElement]) -> bool {
    match_signature_ctx(data, offset, elements, &SigCtx::flat())
}

/// Match a parsed signature against data at `offset`, resolving `$$`
/// (`RelOffset`) and `#` (`AbsAddress`) elements through `ctx`'s address
/// map — the upstream `compareSignature` `_MEMORY_MAP` path.
///
/// - `$$` (`ST_RELOFFSET`): value = signed displacement + size. Under
///   `seg_wrap16` (COM/MSDOS) the jump wraps inside the current 16-bit
///   segment; otherwise `off_to_addr(pos) + value -> addr_to_off`.
/// - `#` (`ST_ADDRESS`): reads an unsigned address and jumps to its
///   mapped offset. Under `msdos_addr` (FT_MSDOS) 2-byte values gain
///   `nCodeBase` and 4-byte values decode seg:off relative to
///   `nStartLoadOffset`; sizes 1/8 leave `pos` unchanged upstream.
pub fn match_signature_ctx(
    data: &[u8],
    offset: usize,
    elements: &[SigElement],
    ctx: &SigCtx,
) -> bool {
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
    let off_to_addr = |pos: usize| -> Option<u64> {
        match &ctx.off_to_addr {
            Some(f) => f(pos as u64),
            None => Some(pos as u64),
        }
    };
    let addr_to_off = |addr: u64| -> Option<usize> {
        let mapped = match &ctx.addr_to_off {
            Some(f) => f(addr)?,
            None => addr,
        };
        usize::try_from(mapped).ok()
    };
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
                // value = signed displacement + size (upstream folds the
                // size into `nValue` before resolving the target).
                let Some(value) = read_le_signed(data, pos, *n) else {
                    return false;
                };
                let Some(value) = value.checked_add(*n as i64) else {
                    return false;
                };
                if ctx.seg_wrap16 {
                    let delta = (pos as u16).wrapping_add(value as u16) as usize;
                    pos = (pos & !0xffff) + delta;
                } else {
                    let Some(base) = off_to_addr(pos) else {
                        return false;
                    };
                    let Some(target) = base.checked_add_signed(value) else {
                        return false;
                    };
                    let Some(next) = addr_to_off(target) else {
                        return false;
                    };
                    pos = next;
                }
            }
            SigElement::AbsAddress(n) => {
                let Some(addr) = read_le_unsigned(data, pos, *n) else {
                    return false;
                };
                match ctx.msdos_addr {
                    // FT_MSDOS: 2-byte address += nCodeBase (0 upstream),
                    // 4-byte is a seg:off pair relative to the load offset;
                    // other sizes leave the cursor where it is upstream.
                    Some((_code_base, start_load)) => match n {
                        2 => {
                            let Some(next) = addr_to_off(addr) else {
                                return false;
                            };
                            pos = next;
                        }
                        4 => {
                            let low = addr & 0xffff;
                            let high = addr >> 16;
                            let Some(next) =
                                (start_load + (high * 16 + low) as i64).try_into().ok()
                            else {
                                return false;
                            };
                            pos = next;
                        }
                        _ => {}
                    },
                    None => {
                        let Some(next) = addr_to_off(addr) else {
                            return false;
                        };
                        pos = next;
                    }
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

/// Match a parsed signature with PE address-space resolution: `$$`/`#`
/// elements map file offsets to RVAs and back via the two closures.
/// Equivalent to `match_signature_ctx` with a section-extent map.
pub fn match_signature_pe(
    data: &[u8],
    offset: usize,
    elements: &[SigElement],
    off_to_rva: impl Fn(u64) -> Option<u64> + Send + Sync + 'static,
    rva_to_off: impl Fn(u64) -> Option<u64> + Send + Sync + 'static,
) -> bool {
    match_signature_ctx(
        data,
        offset,
        elements,
        &SigCtx {
            off_to_addr: Some(Box::new(off_to_rva)),
            addr_to_off: Some(Box::new(rva_to_off)),
            seg_wrap16: false,
            msdos_addr: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(s: &str) -> Vec<SigElement> {
        parse_signature(s).expect("signature parses")
    }

    /// Flat `$$` jump: `EB$$` reads a 1-byte signed displacement and
    /// continues at `pos + disp + 1`.
    #[test]
    fn reloffset_flat_jump() {
        // EB +4 -> jump to offset 2+... wait: at pos 1 read disp,
        // target = 1 + disp + 1.
        let d = [0xEBu8, 0x02, 0x00, 0x00, 0xAA, 0xBB];
        // At pos1 disp=2 -> target = 1+2+1 = 4 -> bytes AA BB.
        assert!(match_signature(&d, 0, &sig("EB$$AABB")));
        assert!(!match_signature(&d, 0, &sig("EB$$BBBB")));
    }

    /// `$$` under `seg_wrap16` wraps inside the 16-bit segment
    /// (upstream FT_COM/FT_MSDOS `ST_RELOFFSET` branch).
    #[test]
    fn reloffset_seg_wrap16() {
        let ctx = SigCtx {
            seg_wrap16: true,
            ..SigCtx::flat()
        };
        // COM image < 64 KiB: pos=0x0005, disp -10 -> low16 wraps to
        // 0xFFFC inside the same 16-bit segment.
        let mut d = vec![0u8; 0x10000];
        d[0x0005] = 0xEB;
        // disp is read at 0x0006: target low16 = 6 - 10 + 1 = wraps to
        // 0xFFFD inside the same segment.
        d[0x0006] = 0xF6;
        d[0xFFFD] = 0xCC;
        assert!(match_signature_ctx(&d, 0x0005, &sig("EB$$CC"), &ctx));
        // Flat semantics land at a negative offset and fail.
        assert!(!match_signature(&d, 0x0005, &sig("EB$$CC")));
    }

    /// `#` reads a little-endian address and jumps to its mapped offset.
    #[test]
    fn abs_address_flat_jump() {
        let d = [0x68u8, 0x06, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22];
        // At pos1 read u32 = 6 -> jump to offset 6 -> 11 22.
        assert!(match_signature(&d, 0, &sig("68########1122")));
        assert!(!match_signature(&d, 0, &sig("68########2211")));
    }

    /// `#` through a non-identity address map (offset->addr != addr->off).
    #[test]
    fn abs_address_mapped() {
        let ctx = SigCtx {
            off_to_addr: None,
            // address 0x4000 -> file offset 0x10 (image at 0x4000).
            addr_to_off: Some(Box::new(|a| a.checked_sub(0x4000))),
            ..SigCtx::flat()
        };
        let mut d = vec![0u8; 0x20];
        d[0] = 0x68;
        d[1..5].copy_from_slice(&0x4010u32.to_le_bytes());
        d[0x10] = 0xAA;
        assert!(match_signature_ctx(&d, 0, &sig("68########AA"), &ctx));
        // Flat: address 0x4010 lands outside the file -> fail.
        assert!(!match_signature(&d, 0, &sig("68########AA")));
    }

    /// `$$` through a PE-like map where file offset != RVA: the
    /// displacement applies to the *address*, not the file offset.
    #[test]
    fn reloffset_pe_map() {
        // sec1 file [0x200,0x400) <-> RVA [0x1000,0x1200);
        // sec2 file [0x400,0x600) <-> RVA [0x2000,0x2200).
        let ctx = SigCtx {
            off_to_addr: Some(Box::new(|o| {
                if (0x200..0x400).contains(&o) {
                    Some(o - 0x200 + 0x1000)
                } else {
                    (0x400..0x600).contains(&o).then_some(o - 0x400 + 0x2000)
                }
            })),
            addr_to_off: Some(Box::new(|a| {
                if (0x1000..0x1200).contains(&a) {
                    Some(a - 0x1000 + 0x200)
                } else {
                    (0x2000..0x2200).contains(&a).then_some(a - 0x2000 + 0x400)
                }
            })),
            seg_wrap16: false,
            msdos_addr: None,
        };
        let mut d = vec![0u8; 0x600];
        d[0x200] = 0xE9; // jmp rel32 at off 0x200
        // disp is read at 0x201 (RVA 0x1001): target RVA 0x2000 ->
        // file offset 0x400.
        d[0x201..0x205].copy_from_slice(&(0x2000i32 - 0x1001 - 4).to_le_bytes());
        d[0x400] = 0xAA;
        assert!(match_signature_ctx(&d, 0x200, &sig("E9$$$$$$$$AA"), &ctx));
        // Flat interpretation lands at 0x201+0xFFB+4 = 0x1000 -> fail.
        assert!(!match_signature(&d, 0x200, &sig("E9$$$$$$$$AA")));
    }

    /// MSDOS `#` 4-byte seg:off resolution relative to the load offset.
    #[test]
    fn abs_address_msdos_segoff() {
        let ctx = SigCtx {
            off_to_addr: Some(Box::new(|o| (o >= 0x20).then_some(0x1000_0000 + o - 0x20))),
            addr_to_off: Some(Box::new(|a| {
                (a >= 0x1000_0000).then(|| a - 0x1000_0000 + 0x20)
            })),
            seg_wrap16: true,
            msdos_addr: Some((0, 0x20)),
        };
        let mut d = vec![0u8; 0x100];
        d[0x00] = 0x68;
        // seg:off = 0x0000:0x0050 -> offset = 0x20 + 0x50 = 0x70.
        d[1..5].copy_from_slice(&0x0000_0050u32.to_le_bytes());
        d[0x70] = 0xBB;
        assert!(match_signature_ctx(&d, 0, &sig("68########BB"), &ctx));
    }
}

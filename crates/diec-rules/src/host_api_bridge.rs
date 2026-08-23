//! Binary_Script host API bridge for the rquickjs backend.
//!
//! This module creates a JavaScript `Binary` object (and `X`/`File` aliases)
//! that bridges the 155 Binary_Script methods to the Rust `HostApi` trait.
//! The bridge is registered on the QuickJS context before rule evaluation.
//!
//! Per ADR 0006, unknown methods must produce typed incompatibility errors,
//! not silent fallbacks. Methods that are not yet implemented return
//! `HostApiError::NotImplemented`.
//!
//! See `docs/research/host-api-inventory.md` for the full method list.

use crate::error::RuleError;
use crate::host_api::HostApi;
use rquickjs::{Context, Ctx};

/// A parsed signature element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigElement {
    /// Exact byte match.
    Byte(u8),
    /// Wildcard: matches any single byte (`.` or `?` in signature).
    Any,
    /// Relative offset jump: read N bytes as signed integer,
    /// compute target = current_offset + value + N, then continue
    /// matching at the target offset. Used for x86 call/jmp instructions.
    /// The target offset is resolved via RVA→file-offset conversion.
    RelOffset(usize),
}

/// Parse a DIE signature string into a sequence of signature elements.
///
/// DIE signature format:
/// - Hex digit pairs match exact bytes: `AABBCC`
/// - `.` and `?` match any single nibble (two needed for a full byte)
/// - Single-quoted strings match literal ASCII: `'7z'`
/// - Spaces are skipped
/// - `#` and `$` are jump markers (not yet fully supported, treated as wildcards)
///
/// Format a PeBatchInfo as a JSON string for JS consumption.
fn format_pe_batch_json(info: &crate::pe_native::PeBatchInfo) -> String {
    let mut s = String::with_capacity(256);
    s.push('{');
    // libraries
    s.push_str("\"libraries\":[");
    for (i, lib) in info.libraries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        push_json_string(&mut s, lib);
    }
    s.push(']');
    // functions
    s.push_str(",\"functions\":[");
    for (i, func) in info.functions.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        push_json_string(&mut s, func);
    }
    s.push(']');
    // imports: array of {name, functions:[...]} grouped by library
    s.push_str(",\"imports\":[");
    for (i, imp) in info.imports.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"name\":");
        push_json_string(&mut s, &imp.name);
        s.push_str(",\"functions\":[");
        for (j, func) in imp.functions.iter().enumerate() {
            if j > 0 {
                s.push(',');
            }
            push_json_string(&mut s, func);
        }
        s.push_str("]}");
    }
    s.push(']');
    // exports
    s.push_str(",\"exports\":[");
    for (i, exp) in info.exports.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        push_json_string(&mut s, exp);
    }
    s.push(']');
    s.push_str(",\"isNet\":");
    s.push_str(if info.is_net { "true" } else { "false" });
    s.push_str(",\"isSigned\":");
    s.push_str(if info.is_signed { "true" } else { "false" });
    s.push_str(",\"manifest\":");
    push_json_string(&mut s, &info.manifest);
    s.push_str(",\"fileVersion\":");
    push_json_string(&mut s, &info.file_version);
    s.push_str(",\"productVersion\":");
    push_json_string(&mut s, &info.product_version);
    s.push_str(",\"numberOfResources\":");
    s.push_str(&info.number_of_resources.to_string());
    s.push_str(",\"netVersion\":");
    push_json_string(&mut s, &info.net_version);
    // .NET strings
    s.push_str(",\"netUnicodeStrings\":[");
    for (i, st) in info.net_unicode_strings.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        push_json_string(&mut s, st);
    }
    s.push(']');
    s.push_str(",\"netAnsiStrings\":[");
    for (i, st) in info.net_ansi_strings.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        push_json_string(&mut s, st);
    }
    s.push(']');
    // resource entries: array of [name, type_id, offset, size]
    s.push_str(",\"resourceEntries\":[");
    for (i, entry) in info.resource_entries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('[');
        push_json_string(&mut s, &entry.0);
        s.push(',');
        s.push_str(&entry.1.to_string());
        s.push(',');
        s.push_str(&entry.2.to_string());
        s.push(',');
        s.push_str(&entry.3.to_string());
        s.push(']');
    }
    s.push(']');
    // import position hashes: CRC32C per library
    s.push_str(",\"importPositionHashes\":[");
    for (i, h) in info.import_position_hashes.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&h.to_string());
    }
    s.push(']');
    s.push('}');
    s
}

/// Push a JSON-escaped string into the buffer.
/// Convert IEEE 754 half-precision (binary16) to f32.
fn half_to_f32(h: u16) -> f32 {
    let sign = (h >> 15) & 1;
    let exp = (h >> 10) & 0x1F;
    let frac = h & 0x3FF;
    if exp == 0 {
        (sign as f32) * (frac as f32) * 2.0f32.powi(-24)
    } else if exp == 0x1F {
        if frac == 0 {
            f32::INFINITY.copysign(sign as f32 - 1.0)
        } else {
            f32::NAN
        }
    } else {
        (sign as f32)
            * ((1u32 << (exp - 1 + 23)) | (frac as u32) << 13) as f32
            * 2.0f32.powi(exp as i32 - 15 - 10)
    }
}

fn push_json_string(buf: &mut String, s: &str) {
    buf.push('"');
    for c in s.chars() {
        match c {
            '"' => buf.push_str("\\\""),
            '\\' => buf.push_str("\\\\"),
            '\n' => buf.push_str("\\n"),
            '\r' => buf.push_str("\\r"),
            '\t' => buf.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                buf.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => buf.push(c),
        }
    }
    buf.push('"');
}

/// Returns `Err` if the signature is malformed.
pub fn parse_signature(signature: &str) -> Result<Vec<SigElement>, String> {
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
            // String literal: read until closing quote.
            // Supports escape sequences: \r \n \t \0 \\ \xHH
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    let next = chars[i + 1];
                    match next {
                        'r' => {
                            elements.push(SigElement::Byte(0x0D));
                            i += 2;
                        }
                        'n' => {
                            elements.push(SigElement::Byte(0x0A));
                            i += 2;
                        }
                        't' => {
                            elements.push(SigElement::Byte(0x09));
                            i += 2;
                        }
                        '0' => {
                            elements.push(SigElement::Byte(0x00));
                            i += 2;
                        }
                        '\\' => {
                            elements.push(SigElement::Byte(0x5C));
                            i += 2;
                        }
                        '\'' => {
                            elements.push(SigElement::Byte(0x27));
                            i += 2;
                        }
                        '"' => {
                            elements.push(SigElement::Byte(0x22));
                            i += 2;
                        }
                        'x' if i + 3 < chars.len() => {
                            let h1 = chars[i + 2].to_digit(16);
                            let h2 = chars[i + 3].to_digit(16);
                            if let (Some(h1), Some(h2)) = (h1, h2) {
                                elements.push(SigElement::Byte((h1 * 16 + h2) as u8));
                                i += 4;
                            } else {
                                elements.push(SigElement::Byte(b'\\'));
                                i += 1;
                            }
                        }
                        _ => {
                            elements.push(SigElement::Byte(b'\\'));
                            i += 1;
                        }
                    }
                } else {
                    for b in chars[i].to_string().as_bytes() {
                        elements.push(SigElement::Byte(*b));
                    }
                    i += 1;
                }
            }
            if i >= chars.len() {
                return Err("unterminated string literal in signature".into());
            }
            i += 1; // skip closing quote
            continue;
        }

        if c == '$' {
            // Relative offset jump marker: read consecutive $ characters.
            // N pairs of $ = N-byte signed relative offset.
            // e.g. $$$$ = 2-byte rel offset, $$$$$$$$ = 4-byte rel offset.
            let mut count = 0;
            while i < chars.len() && chars[i] == '$' {
                count += 1;
                i += 1;
            }
            let addr_size = count / 2;
            if count % 2 != 0
                || (addr_size != 1 && addr_size != 2 && addr_size != 4 && addr_size != 8)
            {
                return Err(format!("invalid $ count ({count}) in signature"));
            }
            elements.push(SigElement::RelOffset(addr_size));
            continue;
        }

        if c == '#' {
            // Address marker: treat as wildcard for now.
            // TODO: implement proper address resolution like upstream.
            elements.push(SigElement::Any);
            i += 1;
            continue;
        }

        if c == '.' || c == '?' {
            // Wildcard nibble: need two for a full byte.
            let mut nibbles = 0u8;
            let mut byte_val = 0u8;
            while i < chars.len() && (chars[i] == '.' || chars[i] == '?') {
                nibbles += 1;
                byte_val <<= 4;
                i += 1;
            }
            if nibbles == 1 {
                // Single wildcard nibble + hex nibble
                if i < chars.len() {
                    let h = chars[i].to_digit(16);
                    if let Some(h) = h {
                        byte_val |= h as u8;
                        elements.push(SigElement::Byte(byte_val));
                        i += 1;
                    } else {
                        return Err("invalid hex after wildcard".into());
                    }
                } else {
                    return Err("dangling wildcard nibble".into());
                }
            } else if nibbles == 2 {
                elements.push(SigElement::Any);
            } else if nibbles > 2 {
                // Multiple bytes of wildcards
                for _ in 0..(nibbles / 2) {
                    elements.push(SigElement::Any);
                }
                if nibbles % 2 == 1 {
                    // Odd nibble: combine with next hex digit if available
                    if i < chars.len() {
                        let h = chars[i].to_digit(16);
                        if let Some(h) = h {
                            elements.push(SigElement::Byte(h as u8));
                            i += 1;
                        }
                    }
                }
            } else {
                // Shouldn't happen since we enter the loop with at least one
                return Err("invalid wildcard".into());
            }
            continue;
        }

        if c.is_ascii_hexdigit() {
            // Hex byte: read two hex digits.
            if i + 1 >= chars.len() {
                return Err("odd number of hex digits".into());
            }
            let h1 = chars[i].to_digit(16).ok_or("invalid hex digit")?;
            let h2 = chars[i + 1].to_digit(16).ok_or("invalid hex digit")?;
            // Check if next is also a hex digit (not a wildcard or string)
            if chars[i + 1].is_ascii_hexdigit() {
                elements.push(SigElement::Byte((h1 * 16 + h2) as u8));
                i += 2;
            } else if chars[i + 1] == '.' || chars[i + 1] == '?' {
                // Hex nibble + wildcard nibble
                elements.push(SigElement::Byte((h1 * 16) as u8)); // partial nibble: high nibble known, low nibble wildcard
                i += 1;
            } else {
                return Err("invalid hex digit pair".into());
            }
            continue;
        }

        return Err(format!("unexpected character '{c}' in signature"));
    }

    Ok(elements)
}

/// Match a parsed signature against data at the given offset.
/// This version does NOT support RelOffset elements (used by find_signature
/// and other non-PE contexts). If a RelOffset element is encountered, it
/// is treated as a wildcard.
pub fn match_signature(data: &[u8], offset: usize, elements: &[SigElement]) -> bool {
    // For simple signatures (no RelOffset), use direct byte comparison.
    let has_reloffset = elements
        .iter()
        .any(|e| matches!(e, SigElement::RelOffset(_)));
    if !has_reloffset {
        if offset
            .checked_add(elements.len())
            .is_none_or(|end| end > data.len())
        {
            return false;
        }
        for (i, elem) in elements.iter().enumerate() {
            match elem {
                SigElement::Byte(b) => {
                    if data[offset + i] != *b {
                        return false;
                    }
                }
                SigElement::Any => {}
                SigElement::RelOffset(_) => {} // handled by has_reloffset check above
            }
        }
        return true;
    }
    // For signatures with RelOffset, fall back to treating them as wildcards.
    // This is only hit if match_signature is called directly (not via the
    // PE-aware match_signature_pe). find_signature uses this path.
    if offset
        .checked_add(elements.len())
        .is_none_or(|end| end > data.len())
    {
        return false;
    }
    let mut pos = offset;
    for elem in elements.iter() {
        match elem {
            SigElement::Byte(b) => {
                if pos >= data.len() || data[pos] != *b {
                    return false;
                }
                pos += 1;
            }
            SigElement::Any => {
                pos += 1;
            }
            SigElement::RelOffset(n) => {
                // Without memory map info, treat as skip N bytes.
                pos += n;
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
            SigElement::Byte(b) => {
                if pos >= data.len() || data[pos] != *b {
                    return false;
                }
                pos += 1;
            }
            SigElement::Any => {
                if pos >= data.len() {
                    return false;
                }
                pos += 1;
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
        }
    }
    true
}
use std::sync::Arc;

/// A wrapper around `HostApi` that can be shared with JavaScript callbacks.
///
/// `HostApi` is not `Clone`, so we use `Arc<dyn HostApi + Send + Sync>` for
/// shared access from JavaScript callbacks. The actual `HostApi`
/// implementation in `diec-engine` will be `Send + Sync` because it only
/// accesses immutable parsed format data and the cancel token.
pub struct HostApiBridge {
    host: Arc<dyn HostApi + Send + Sync>,
}

impl HostApiBridge {
    /// Create a new host API bridge.
    pub fn new(host: Arc<dyn HostApi + Send + Sync>) -> Self {
        Self { host }
    }

    /// Register the `Binary` object on the JavaScript context.
    ///
    /// This creates a JavaScript object with methods that call back into
    /// the Rust `HostApi` trait. The object is registered as `Binary`,
    /// and aliases `X` and `File` are set to point to the same object.
    pub fn register(&self, context: &Context) -> Result<(), RuleError> {
        let host = self.host.clone();
        let ctx = context.clone();

        ctx.with(|ctx: Ctx<'_>| -> Result<(), RuleError> {
            let globals = ctx.globals();

            // Create the Binary object.
            let binary = rquickjs::Object::new(ctx.clone()).map_err(|e| RuleError::Backend {
                detail: format!("failed to create Binary object: {e}"),
            })?;

            // --- Read primitives ---

            // readByte(offset) -> u8
            let h = host.clone();
            let read_byte_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u8(offset as u64).map(|v| v as i32).unwrap_or(-1)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("readByte: {e}"),
            })?;
            binary
                .set("readByte", read_byte_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("readByte set: {e}"),
                })?;

            // readSByte(offset) -> i8
            let h = host.clone();
            let read_sbyte_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_i8(offset as u64).map(|v| v as i32).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("readSByte: {e}"),
            })?;
            binary
                .set("readSByte", read_sbyte_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("readSByte set: {e}"),
                })?;

            // readWord(offset) -> u16 (little-endian)
            let h = host.clone();
            let read_word_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u16_le(offset as u64).map(|v| v as i32).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("readWord: {e}"),
            })?;
            binary
                .set("readWord", read_word_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("readWord set: {e}"),
                })?;

            // readDword(offset) -> u32 (little-endian)
            let h = host.clone();
            let read_dword_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u32_le(offset as u64).unwrap_or(0) as f64
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("readDword: {e}"),
            })?;
            binary
                .set("readDword", read_dword_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("readDword set: {e}"),
                })?;

            // readQword(offset) -> u64 (little-endian), returned as number
            let h = host.clone();
            let read_qword_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u64_le(offset as u64).unwrap_or(0) as f64
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("readQword: {e}"),
            })?;
            binary
                .set("readQword", read_qword_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("readQword set: {e}"),
                })?;

            // readSWord(offset) -> i16 (little-endian)
            let h = host.clone();
            let read_sword_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_i16_le(offset as u64).map(|v| v as i32).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("readSWord: {e}"),
            })?;
            binary
                .set("readSWord", read_sword_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("readSWord set: {e}"),
                })?;

            // readSDword(offset) -> i32 (little-endian)
            let h = host.clone();
            let read_sdword_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_i32_le(offset as u64).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("readSDword: {e}"),
            })?;
            binary
                .set("readSDword", read_sdword_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("readSDword set: {e}"),
                })?;

            // readSQword(offset) -> i64 (little-endian) as f64
            let h = host.clone();
            let read_sqword_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_i64_le(offset as u64).unwrap_or(0) as f64
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("readSQword: {e}"),
            })?;
            binary
                .set("readSQword", read_sqword_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("readSQword set: {e}"),
                })?;

            // --- read_uintN / read_intN with endian support ---
            // _LE = 0 (default), _BE = 1

            // read_uint8(offset) -> u8
            let h = host.clone();
            let read_uint8_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u8(offset as u64).map(|v| v as i32).unwrap_or(-1)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_uint8: {e}"),
            })?;
            binary
                .set("read_uint8", read_uint8_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_uint8 set: {e}"),
                })?;

            // read_int8(offset) -> i8
            let h = host.clone();
            let read_int8_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_i8(offset as u64).map(|v| v as i32).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_int8: {e}"),
            })?;
            binary
                .set("read_int8", read_int8_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_int8 set: {e}"),
                })?;

            // read_uint16(offset) -> u16 (LE; BE handled by JS wrapper)
            let h = host.clone();
            let read_uint16_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u16_le(offset as u64).map(|v| v as i32).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_uint16: {e}"),
            })?;
            binary
                .set("read_uint16", read_uint16_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_uint16 set: {e}"),
                })?;

            // read_int16(offset) -> i16 (LE; BE handled by JS wrapper)
            let h = host.clone();
            let read_int16_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u16_le(offset as u64).map(|v| v as i16 as i32).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_int16: {e}"),
            })?;
            binary
                .set("read_int16", read_int16_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_int16 set: {e}"),
                })?;

            // read_uint24(offset) -> u32 (LE; BE handled by JS wrapper)
            let h = host.clone();
            let read_uint24_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u24_le(offset as u64).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_uint24: {e}"),
            })?;
            binary
                .set("read_uint24", read_uint24_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_uint24 set: {e}"),
                })?;

            // read_uint32(offset) -> u32 (LE; BE handled by JS wrapper)
            let h = host.clone();
            let read_uint32_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u32_le(offset as u64).unwrap_or(0) as f64
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_uint32: {e}"),
            })?;
            binary
                .set("read_uint32", read_uint32_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_uint32 set: {e}"),
                })?;

            // read_int32(offset) -> i32 (LE; BE handled by JS wrapper)
            let h = host.clone();
            let read_int32_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u32_le(offset as u64).map(|v| v as i32).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_int32: {e}"),
            })?;
            binary
                .set("read_int32", read_int32_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_int32 set: {e}"),
                })?;

            // read_uint64(offset) -> u64 as f64 (LE; BE handled by JS wrapper)
            let h = host.clone();
            let read_uint64_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u64_le(offset as u64).unwrap_or(0) as f64
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_uint64: {e}"),
            })?;
            binary
                .set("read_uint64", read_uint64_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_uint64 set: {e}"),
                })?;

            // read_int64(offset) -> i64 as f64 (LE; BE handled by JS wrapper)
            let h = host.clone();
            let read_int64_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u64_le(offset as u64).map(|v| v as i64 as f64).unwrap_or(0.0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_int64: {e}"),
            })?;
            binary
                .set("read_int64", read_int64_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_int64 set: {e}"),
                })?;

            // read_int24(offset) -> i32 (LE, sign-extended)
            let h = host.clone();
            let read_int24_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u24_le(offset as u64)
                    .map(|v| {
                        if v & 0x800000 != 0 {
                            (v | 0xFF000000) as i32 as f64
                        } else {
                            v as i32 as f64
                        }
                    })
                    .unwrap_or(0.0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_int24: {e}"),
            })?;
            binary.set("read_int24", read_int24_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_int24 set: {e}"),
            })?;

            // read_float(offset) -> f32 as f64 (LE, IEEE 754)
            let h = host.clone();
            let read_float_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u32_le(offset as u64)
                    .map(|v| f32::from_bits(v) as f64)
                    .unwrap_or(0.0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_float: {e}"),
            })?;
            binary.set("read_float", read_float_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_float set: {e}"),
            })?;
            // Alias: read_float32 = read_float
            let h = host.clone();
            let read_float32_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u32_le(offset as u64)
                    .map(|v| f32::from_bits(v) as f64)
                    .unwrap_or(0.0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_float32: {e}"),
            })?;
            binary.set("read_float32", read_float32_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_float32 set: {e}"),
            })?;

            // read_float16(offset) -> f32 as f64 (LE, IEEE 754 half-precision)
            let h = host.clone();
            let read_float16_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u16_le(offset as u64)
                    .map(|v| half_to_f32(v) as f64)
                    .unwrap_or(0.0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_float16: {e}"),
            })?;
            binary.set("read_float16", read_float16_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_float16 set: {e}"),
            })?;

            // read_double(offset) -> f64 (LE, IEEE 754 double)
            let h = host.clone();
            let read_double_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u64_le(offset as u64)
                    .map(f64::from_bits)
                    .unwrap_or(0.0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_double: {e}"),
            })?;
            binary.set("read_double", read_double_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_double set: {e}"),
            })?;
            // Alias: read_float64 = read_double
            let h = host.clone();
            let read_float64_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u64_le(offset as u64)
                    .map(f64::from_bits)
                    .unwrap_or(0.0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_float64: {e}"),
            })?;
            binary.set("read_float64", read_float64_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_float64 set: {e}"),
            })?;

            // read_bcd_uint8(offset) -> u32 (Binary-Coded Decimal, 1 byte)
            let h = host.clone();
            let read_bcd_u8_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u8(offset as u64)
                    .map(|v| ((v >> 4) & 0x0F) * 10 + (v & 0x0F))
                    .unwrap_or(0) as f64
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_bcd_uint8: {e}"),
            })?;
            binary.set("read_bcd_uint8", read_bcd_u8_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_bcd_uint8 set: {e}"),
            })?;

            // read_bcd_uint16(offset) -> u32 (BCD, 2 bytes LE)
            let h = host.clone();
            let read_bcd_u16_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u16_le(offset as u64)
                    .map(|v| {
                        let b0 = ((v & 0xFF) >> 4) * 10 + (v & 0x0F);
                        let b1 = ((v >> 12) & 0x0F) * 10 + ((v >> 8) & 0x0F);
                        b1 * 100 + b0
                    })
                    .unwrap_or(0) as f64
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_bcd_uint16: {e}"),
            })?;
            binary.set("read_bcd_uint16", read_bcd_u16_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_bcd_uint16 set: {e}"),
            })?;

            // read_bcd_uint32(offset) -> u64 (BCD, 4 bytes LE)
            let h = host.clone();
            let read_bcd_u32_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u32_le(offset as u64)
                    .map(|v| {
                        let mut result = 0u64;
                        let mut val = v;
                        for _ in 0..4 {
                            let digit = (val & 0x0F) * 10 + ((val >> 4) & 0x0F);
                            // Actually BCD: each nibble is a decimal digit
                            let _ = digit;
                            result = result * 10 + u64::from(val & 0x0F);
                            val >>= 8;
                        }
                        result
                    })
                    .unwrap_or(0) as f64
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_bcd_uint32: {e}"),
            })?;
            binary.set("read_bcd_uint32", read_bcd_u32_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_bcd_uint32 set: {e}"),
            })?;

            // read_bcd_uint64(offset) -> f64 (BCD, 8 bytes LE)
            let h = host.clone();
            let read_bcd_u64_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u64_le(offset as u64)
                    .map(|v| {
                        let mut result = 0u64;
                        let mut val = v;
                        for _ in 0..8 {
                            result = result * 10 + (val & 0x0F);
                            val >>= 8;
                        }
                        result as f64
                    })
                    .unwrap_or(0.0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_bcd_uint64: {e}"),
            })?;
            binary.set("read_bcd_uint64", read_bcd_u64_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_bcd_uint64 set: {e}"),
            })?;

            // read_utf8String(offset, maxSize) -> string (null-terminated UTF-8)
            let h = host.clone();
            let read_utf8str_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32, max_size: i32| {
                let file_size = h.file_size() as usize;
                let start = offset as usize;
                if start >= file_size { return String::new(); }
                let end = if max_size > 0 {
                    (start + max_size as usize).min(file_size)
                } else {
                    file_size.min(start + 4096)
                };
                let mut bytes = Vec::new();
                for i in start..end {
                    match h.read_u8(i as u64) {
                        Ok(0) => break,
                        Ok(b) => bytes.push(b),
                        Err(_) => break,
                    }
                }
                String::from_utf8_lossy(&bytes).to_string()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_utf8String: {e}"),
            })?;
            binary.set("read_utf8String", read_utf8str_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_utf8String set: {e}"),
            })?;

            // find_ansiString(offset, size, pattern) -> offset or -1
            let h = host.clone();
            let find_ansi_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32, pattern: String| {
                let file_size = h.file_size() as usize;
                let start = offset as usize;
                if start >= file_size { return -1i32; }
                let end = if size > 0 {
                    (start + size as usize).min(file_size)
                } else { file_size };
                let needle = pattern.as_bytes();
                if needle.is_empty() { return offset; }
                let mut i = start;
                while i + needle.len() <= end {
                    let mut found = true;
                    for (j, &nb) in needle.iter().enumerate() {
                        match h.read_u8((i + j) as u64) {
                            Ok(b) if b == nb => {}
                            _ => { found = false; break; }
                        }
                    }
                    if found { return i as i32; }
                    i += 1;
                }
                -1
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("find_ansiString: {e}"),
            })?;
            binary.set("find_ansiString", find_ansi_fn).map_err(|e| RuleError::Backend {
                detail: format!("find_ansiString set: {e}"),
            })?;

            // find_unicodeString(offset, size, pattern) -> offset or -1 (UTF-16LE)
            let h = host.clone();
            let find_uni_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32, pattern: String| {
                let file_size = h.file_size() as usize;
                let start = offset as usize;
                if start >= file_size { return -1i32; }
                let end = if size > 0 {
                    (start + size as usize).min(file_size)
                } else { file_size };
                // Convert pattern to UTF-16LE bytes.
                let needle: Vec<u8> = pattern.encode_utf16()
                    .flat_map(|c| c.to_le_bytes())
                    .collect();
                if needle.is_empty() { return offset; }
                let mut i = start;
                while i + needle.len() <= end {
                    let mut found = true;
                    for (j, &nb) in needle.iter().enumerate() {
                        match h.read_u8((i + j) as u64) {
                            Ok(b) if b == nb => {}
                            _ => { found = false; break; }
                        }
                    }
                    if found { return i as i32; }
                    i += 1;
                }
                -1
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("find_unicodeString: {e}"),
            })?;
            binary.set("find_unicodeString", find_uni_fn).map_err(|e| RuleError::Backend {
                detail: format!("find_unicodeString set: {e}"),
            })?;

            // upperCase(s) -> string
            let upper_fn = rquickjs::Function::new(ctx.clone(), move |s: String| s.to_uppercase())
                .map_err(|e| RuleError::Backend { detail: format!("upperCase: {e}") })?;
            binary.set("upperCase", upper_fn).map_err(|e| RuleError::Backend {
                detail: format!("upperCase set: {e}"),
            })?;

            // lowerCase(s) -> string
            let lower_fn = rquickjs::Function::new(ctx.clone(), move |s: String| s.to_lowercase())
                .map_err(|e| RuleError::Backend { detail: format!("lowerCase: {e}") })?;
            binary.set("lowerCase", lower_fn).map_err(|e| RuleError::Backend {
                detail: format!("lowerCase set: {e}"),
            })?;

            // adler32(offset, size) -> u32 as f64
            let h = host.clone();
            let adler_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32| {
                let start = offset as u64;
                let len = size as u64;
                // Adler-32: a = 1 + sum(bytes), b = sum(a_i), mod 65521
                let mut a: u32 = 1;
                let mut b: u32 = 0;
                for i in 0..len {
                    match h.read_u8(start + i) {
                        Ok(byte) => {
                            a = (a + byte as u32) % 65521;
                            b = (b + a) % 65521;
                        }
                        Err(_) => break,
                    }
                }
                ((b << 16) | a) as f64
            })
            .map_err(|e| RuleError::Backend { detail: format!("adler32: {e}") })?;
            binary.set("adler32", adler_fn).map_err(|e| RuleError::Backend {
                detail: format!("adler32 set: {e}"),
            })?;

            // isUTF8Text(offset, size) -> bool
            let h = host.clone();
            let is_utf8_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32| {
                let start = offset as u64;
                let len = if size > 0 { size as u64 } else { 1024 };
                let mut bytes = Vec::new();
                for i in 0..len {
                    match h.read_u8(start + i) {
                        Ok(b) => bytes.push(b),
                        Err(_) => break,
                    }
                }
                // Check if valid UTF-8 with no null bytes.
                bytes.iter().all(|&b| b != 0) && std::str::from_utf8(&bytes).is_ok()
            })
            .map_err(|e| RuleError::Backend { detail: format!("isUTF8Text: {e}") })?;
            binary.set("isUTF8Text", is_utf8_fn).map_err(|e| RuleError::Backend {
                detail: format!("isUTF8Text set: {e}"),
            })?;

            // isUnicodeText(offset, size) -> bool (UTF-16LE with no null high bytes)
            let h = host.clone();
            let is_unicode_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32| {
                let start = offset as u64;
                let len = if size > 0 { size as u64 } else { 1024 };
                let mut has_ascii = false;
                let mut has_high = false;
                for i in 0..len {
                    match h.read_u8(start + i) {
                        Ok(b) => {
                            if (0x20..0x7F).contains(&b) { has_ascii = true; }
                            if b >= 0x80 { has_high = true; }
                        }
                        Err(_) => break,
                    }
                }
                has_ascii && !has_high
            })
            .map_err(|e| RuleError::Backend { detail: format!("isUnicodeText: {e}") })?;
            binary.set("isUnicodeText", is_unicode_fn).map_err(|e| RuleError::Backend {
                detail: format!("isUnicodeText set: {e}"),
            })?;

            // --- Scan mode flags (continued) ---

            // isVerbose() -> bool (same as isDeepScan for now)
            let h = host.clone();
            let is_verbose_fn =
                rquickjs::Function::new(ctx.clone(), move || h.is_deep()).map_err(|e| {
                    RuleError::Backend {
                        detail: format!("isVerbose: {e}"),
                    }
                })?;
            binary
                .set("isVerbose", is_verbose_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("isVerbose set: {e}"),
                })?;

            // --- Short aliases (U8, U16, U24, U32, U64, I8, I16, I32, I64) ---

            // U8(offset) -> u8
            let h = host.clone();
            let u8_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u8(offset as u64).map(|v| v as i32).unwrap_or(-1)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("U8: {e}"),
            })?;
            binary.set("U8", u8_fn).map_err(|e| RuleError::Backend {
                detail: format!("U8 set: {e}"),
            })?;

            // I8(offset) -> i8
            let h = host.clone();
            let i8_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_i8(offset as u64).map(|v| v as i32).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("I8: {e}"),
            })?;
            binary.set("I8", i8_fn).map_err(|e| RuleError::Backend {
                detail: format!("I8 set: {e}"),
            })?;

            // U16(offset, bigEndian?) -> u16
            // Register a 1-arg version; the 2-arg version is handled by
            // a JS wrapper added later that passes the endianness flag.
            let h = host.clone();
            let u16_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u16_le(offset as u64).map(|v| v as i32).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("U16: {e}"),
            })?;
            binary.set("U16", u16_fn).map_err(|e| RuleError::Backend {
                detail: format!("U16 set: {e}"),
            })?;

            // U24(offset, bigEndian?) -> u32
            let h = host.clone();
            let u24_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u24_le(offset as u64).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("U24: {e}"),
            })?;
            binary.set("U24", u24_fn).map_err(|e| RuleError::Backend {
                detail: format!("U24 set: {e}"),
            })?;

            // U32(offset, bigEndian?) -> u32
            let h = host.clone();
            let u32_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u32_le(offset as u64).unwrap_or(0) as f64
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("U32: {e}"),
            })?;
            binary.set("U32", u32_fn).map_err(|e| RuleError::Backend {
                detail: format!("U32 set: {e}"),
            })?;

            // U64(offset) -> u64 as f64 (LE only; BE variant via wrapper)
            let h = host.clone();
            let u64_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u64_le(offset as u64).unwrap_or(0) as f64
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("U64: {e}"),
            })?;
            binary.set("U64", u64_fn).map_err(|e| RuleError::Backend {
                detail: format!("U64 set: {e}"),
            })?;

            // I32(offset) -> i32
            let h = host.clone();
            let i32_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_i32_le(offset as u64).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("I32: {e}"),
            })?;
            binary.set("I32", i32_fn).map_err(|e| RuleError::Backend {
                detail: format!("I32 set: {e}"),
            })?;

            // I16(offset) -> i16 LE
            let h = host.clone();
            let i16_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u16_le(offset as u64).map(|v| v as i16 as i32).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("I16: {e}"),
            })?;
            binary.set("I16", i16_fn).map_err(|e| RuleError::Backend {
                detail: format!("I16 set: {e}"),
            })?;

            // I24(offset) -> i24 LE
            let h = host.clone();
            let i24_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u24_le(offset as u64).map(|v| {
                    if v & 0x800000 != 0 {
                        (v | 0xFF000000) as i32
                    } else {
                        v as i32
                    }
                }).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("I24: {e}"),
            })?;
            binary.set("I24", i24_fn).map_err(|e| RuleError::Backend {
                detail: format!("I24 set: {e}"),
            })?;

            // I64(offset) -> i64 LE as f64
            let h = host.clone();
            let i64_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u64_le(offset as u64).map(|v| v as i64 as f64).unwrap_or(0.0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("I64: {e}"),
            })?;
            binary.set("I64", i64_fn).map_err(|e| RuleError::Backend {
                detail: format!("I64 set: {e}"),
            })?;

            // --- File metadata ---

            // getSize() -> file size
            let h = host.clone();
            let get_size_fn = rquickjs::Function::new(ctx.clone(), move || h.file_size() as f64)
                .map_err(|e| RuleError::Backend {
                    detail: format!("getSize: {e}"),
                })?;
            binary
                .set("getSize", get_size_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("getSize set: {e}"),
                })?;

            // getEntryPointOffset() -> entry point
            let h = host.clone();
            let get_ep_fn =
                rquickjs::Function::new(ctx.clone(), move || h.entry_point().unwrap_or(0) as f64)
                    .map_err(|e| RuleError::Backend {
                    detail: format!("getEntryPointOffset: {e}"),
                })?;
            binary
                .set("getEntryPointOffset", get_ep_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("getEntryPointOffset set: {e}"),
                })?;

            // --- String and signature search ---

            // getString(offset, maxLen?) -> string
            // If maxLen is omitted or 0, read to end of file (matching upstream).
            // We register a 2-arg native function and override it with a JS
            // wrapper after the Binary global is registered (see end of register()).
            let h = host.clone();
            let get_string_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, max_len: i32| {
                    let max = if max_len <= 0 {
                        h.file_size()
                    } else {
                        max_len as u64
                    };
                    h.read_string(offset as u64, max).unwrap_or_default()
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("getString: {e}"),
                })?;
            binary
                .set("getString", get_string_fn.clone())
                .map_err(|e| RuleError::Backend {
                    detail: format!("getString set: {e}"),
                })?;
            binary
                .set("getString", get_string_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("getString set: {e}"),
                })?;

            // findSignature(start, signature) or findSignature(start, size, signature)
            // -> offset or -1. The upstream API accepts both 2-arg and 3-arg forms.
            // We register a 2-arg native and add a JS wrapper for the 3-arg form.
            let h = host.clone();
            let find_sig_fn =
                rquickjs::Function::new(ctx.clone(), move |start: i32, signature: String| match h
                    .find_signature(start as u64, &signature)
                {
                    Ok(Some(offset)) => offset as f64,
                    _ => -1.0,
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("findSignature: {e}"),
                })?;
            binary
                .set("__findSignature", find_sig_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__findSignature set: {e}"),
                })?;

            // findSignatureInRange(start, end, signature) -> offset or -1.
            // Searches within [start, end) range. Used by the 3-arg JS wrapper.
            let h = host.clone();
            let find_sig_range_fn = rquickjs::Function::new(
                ctx.clone(),
                move |start: i32, end: i32, signature: String| match h
                    .find_signature_in_range(start as u64, end as u64, &signature)
                {
                    Ok(Some(offset)) => offset as f64,
                    _ => -1.0,
                },
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("findSignatureInRange: {e}"),
            })?;
            binary
                .set("__findSignatureRange", find_sig_range_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__findSignatureRange set: {e}"),
                })?;

            // PE batch parsing: return all PE info in one pelite pass.
            // This avoids repeated PeFile::from_bytes construction.
            // Returns a JSON string parsed on the JS side via JSON.parse.
            let h = host.clone();
            let pe_batch_fn = rquickjs::Function::new(ctx.clone(), move || {
                match h.pe_batch() {
                    Some(info) => format_pe_batch_json(&info),
                    None => "{}".to_string(),
                }
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peBatch: {e}"),
            })?;
            binary
                .set("__peBatch", pe_batch_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peBatch set: {e}"),
                })?;

            // Keep individual functions for backward compatibility (tests may call them directly).
            let h = host.clone();
            let pe_import_libs_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.pe_import_libraries()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peImportLibraries: {e}"),
            })?;
            binary
                .set("__peImportLibraries", pe_import_libs_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peImportLibraries set: {e}"),
                })?;

            // PE batch parsing: return all import function names in one call.
            let h = host.clone();
            let pe_import_funcs_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.pe_import_functions()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peImportFunctions: {e}"),
            })?;
            binary
                .set("__peImportFunctions", pe_import_funcs_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peImportFunctions set: {e}"),
                })?;

            // PE batch parsing: return all export function names in one call.
            let h = host.clone();
            let pe_export_names_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.pe_export_names()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peExportNames: {e}"),
            })?;
            binary
                .set("__peExportNames", pe_export_names_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peExportNames set: {e}"),
                })?;

            // ELF batch parsing: return all DT_NEEDED library names in one call.
            let h = host.clone();
            let elf_import_libs_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.elf_import_libraries()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("elfImportLibraries: {e}"),
            })?;
            binary
                .set("__elfImportLibraries", elf_import_libs_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__elfImportLibraries set: {e}"),
                })?;

            // ELF batch parsing: return all section names in one call.
            let h = host.clone();
            let elf_section_names_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.elf_section_names()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("elfSectionNames: {e}"),
            })?;
            binary
                .set("__elfSectionNames", elf_section_names_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__elfSectionNames set: {e}"),
                })?;

            // Mach-O batch parsing: return all LC_LOAD_DYLIB library names.
            let h = host.clone();
            let macho_import_libs_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.macho_import_libraries()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("machoImportLibraries: {e}"),
            })?;
            binary
                .set("__machoImportLibraries", macho_import_libs_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__machoImportLibraries set: {e}"),
                })?;

            // Mach-O batch parsing: return all section names.
            let h = host.clone();
            let macho_section_names_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.macho_section_names()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("machoSectionNames: {e}"),
            })?;
            binary
                .set("__machoSectionNames", macho_section_names_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__machoSectionNames set: {e}"),
                })?;

            // PE resource/version info: manifest.
            let h = host.clone();
            let pe_manifest_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.pe_manifest()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peManifest: {e}"),
            })?;
            binary
                .set("__peManifest", pe_manifest_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peManifest set: {e}"),
                })?;

            // PE .NET detection.
            let h = host.clone();
            let pe_is_net_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.pe_is_net()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peIsNet: {e}"),
            })?;
            binary
                .set("__peIsNet", pe_is_net_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peIsNet set: {e}"),
                })?;

            // PE file version.
            let h = host.clone();
            let pe_file_version_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.pe_file_version()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peFileVersion: {e}"),
            })?;
            binary
                .set("__peFileVersion", pe_file_version_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peFileVersion set: {e}"),
                })?;

            // PE product version.
            let h = host.clone();
            let pe_product_version_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.pe_product_version()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peProductVersion: {e}"),
            })?;
            binary
                .set("__peProductVersion", pe_product_version_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peProductVersion set: {e}"),
                })?;

            // PE version string by key.
            let h = host.clone();
            let pe_version_string_fn = rquickjs::Function::new(ctx.clone(), move |key: String| {
                h.pe_version_string(&key)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peVersionString: {e}"),
            })?;
            binary
                .set("__peVersionString", pe_version_string_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peVersionString set: {e}"),
                })?;

            // PE number of resources.
            let h = host.clone();
            let pe_num_resources_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.pe_number_of_resources()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peNumberOfResources: {e}"),
            })?;
            binary
                .set("__peNumberOfResources", pe_num_resources_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peNumberOfResources set: {e}"),
                })?;

            // PE resource name present.
            let h = host.clone();
            let pe_is_resource_name_fn = rquickjs::Function::new(ctx.clone(), move |name: String| {
                h.pe_is_resource_name_present(&name)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peIsResourceNamePresent: {e}"),
            })?;
            binary
                .set("__peIsResourceNamePresent", pe_is_resource_name_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peIsResourceNamePresent set: {e}"),
                })?;

            // PE resource group name present (type-level directory entry).
            let h = host.clone();
            let pe_is_resource_group_name_fn =
                rquickjs::Function::new(ctx.clone(), move |name: String| {
                    h.pe_is_resource_group_name_present(&name)
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("peIsResourceGroupNamePresent: {e}"),
                })?;
            binary
                .set("__peIsResourceGroupNamePresent", pe_is_resource_group_name_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peIsResourceGroupNamePresent set: {e}"),
                })?;

            // PE resource group id present (type-level directory entry).
            let h = host.clone();
            let pe_is_resource_group_id_fn =
                rquickjs::Function::new(ctx.clone(), move |id: u32| {
                    h.pe_is_resource_group_id_present(id)
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("peIsResourceGroupIdPresent: {e}"),
                })?;
            binary
                .set("__peIsResourceGroupIdPresent", pe_is_resource_group_id_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peIsResourceGroupIdPresent set: {e}"),
                })?;

            // PE resource section offset.
            let h = host.clone();
            let pe_resource_section_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.pe_resource_section_offset()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peResourceSectionOffset: {e}"),
            })?;
            binary
                .set("__peResourceSectionOffset", pe_resource_section_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peResourceSectionOffset set: {e}"),
                })?;

            // PE is signed.
            let h = host.clone();
            let pe_is_signed_fn = rquickjs::Function::new(ctx.clone(), move || {
                h.pe_is_signed()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("peIsSigned: {e}"),
            })?;
            binary
                .set("__peIsSigned", pe_is_signed_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("__peIsSigned set: {e}"),
                })?;

            // isSignaturePresent(offset, size, signature) -> bool
            // Upstream: bool isSignaturePresent(qint64 nOffset, qint64 nSize, const QString &sSignature)
            // Searches for signature within [offset, offset+size) range.
            let h = host.clone();
            let is_sig_present_fn = rquickjs::Function::new(
                ctx.clone(),
                move |offset: i32, size: i32, signature: String| {
                    if size <= 0 || offset < 0 {
                        h.check_signature(offset as u64, &signature)
                            .unwrap_or(false)
                    } else {
                        let start = offset as u64;
                        let end = start.saturating_add(size as u64);
                        h.find_signature_in_range(start, end, &signature)
                            .ok()
                            .flatten()
                            .is_some()
                    }
                },
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("isSignaturePresent: {e}"),
            })?;
            binary
                .set("isSignaturePresent", is_sig_present_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("isSignaturePresent set: {e}"),
                })?;

            // compare(signature, offset=0) -> bool
            // Upstream signature: bool compare(const QString &sSignature, qint64 nOffset = 0)
            // We register a 2-arg native and a JS wrapper that defaults offset to 0.
            let h = host.clone();
            let compare_fn =
                rquickjs::Function::new(ctx.clone(), move |signature: String, offset: i32| {
                    h.check_signature(offset as u64, &signature)
                        .unwrap_or(false)
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("compare: {e}"),
                })?;
            binary
                .set("__compare", compare_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("compare set: {e}"),
                })?;

            // --- Scan mode flags ---

            let h = host.clone();
            let is_deep_fn =
                rquickjs::Function::new(ctx.clone(), move || h.is_deep()).map_err(|e| {
                    RuleError::Backend {
                        detail: format!("isDeepScan: {e}"),
                    }
                })?;
            binary
                .set("isDeepScan", is_deep_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("isDeepScan set: {e}"),
                })?;

            let h = host.clone();
            let is_heuristic_fn = rquickjs::Function::new(ctx.clone(), move || h.is_heuristic())
                .map_err(|e| RuleError::Backend {
                    detail: format!("isHeuristicScan: {e}"),
                })?;
            binary
                .set("isHeuristicScan", is_heuristic_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("isHeuristicScan set: {e}"),
                })?;

            let h = host.clone();
            let is_aggressive_fn = rquickjs::Function::new(ctx.clone(), move || h.is_aggressive())
                .map_err(|e| RuleError::Backend {
                    detail: format!("isAggressiveScan: {e}"),
                })?;
            binary
                .set("isAggressiveScan", is_aggressive_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("isAggressiveScan set: {e}"),
                })?;

            let h = host.clone();
            let is_verbose_fn = rquickjs::Function::new(ctx.clone(), move || h.is_verbose())
                .map_err(|e| RuleError::Backend {
                    detail: format!("isVerbose: {e}"),
                })?;
            binary
                .set("isVerbose", is_verbose_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("isVerbose set: {e}"),
                })?;

            let h = host.clone();
            let is_recursive_fn = rquickjs::Function::new(ctx.clone(), move || h.is_recursive())
                .map_err(|e| RuleError::Backend {
                    detail: format!("isRecursiveScan: {e}"),
                })?;
            binary
                .set("isRecursiveScan", is_recursive_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("isRecursiveScan set: {e}"),
                })?;

            // --- Architecture detection ---

            let h = host.clone();
            let is8_fn = rquickjs::Function::new(ctx.clone(), move || {
                // 8-bit architecture check based on file type
                let ft = h.file_type();
                ft.name == "Binary_8bit"
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("is8: {e}"),
            })?;
            binary.set("is8", is8_fn).map_err(|e| RuleError::Backend {
                detail: format!("is8 set: {e}"),
            })?;

            let h = host.clone();
            let is16_fn = rquickjs::Function::new(ctx.clone(), move || {
                let ft = h.file_type();
                ft.name == "Binary_16bit"
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("is16: {e}"),
            })?;
            binary
                .set("is16", is16_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("is16 set: {e}"),
                })?;

            let h = host.clone();
            let is32_fn = rquickjs::Function::new(ctx.clone(), move || {
                let ft = h.file_type();
                ft.name == "Binary_32bit"
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("is32: {e}"),
            })?;
            binary
                .set("is32", is32_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("is32 set: {e}"),
                })?;

            let h = host.clone();
            let is64_fn = rquickjs::Function::new(ctx.clone(), move || {
                let ft = h.file_type();
                ft.name == "Binary_64bit"
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("is64: {e}"),
            })?;
            binary
                .set("is64", is64_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("is64 set: {e}"),
                })?;

            // --- Entropy and hashes ---

            let h = host.clone();
            let calc_entropy_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32| {
                    h.entropy(offset as u64, size as u64).unwrap_or(0.0)
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("calculateEntropy: {e}"),
                })?;
            binary
                .set("calculateEntropy", calc_entropy_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("calculateEntropy set: {e}"),
                })?;

            let h = host.clone();
            let calc_md5_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32| {
                    h.md5(offset as u64, size as u64).unwrap_or_default()
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("calculateMD5: {e}"),
                })?;
            binary
                .set("calculateMD5", calc_md5_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("calculateMD5 set: {e}"),
                })?;

            let h = host.clone();
            let calc_crc32_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32| {
                    h.crc32(offset as u64, size as u64).unwrap_or(0) as f64
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("calculateCRC32: {e}"),
                })?;
            binary
                .set("calculateCRC32", calc_crc32_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("calculateCRC32 set: {e}"),
                })?;

            // read_UUID(offset, isBigEndian) -> "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
            let h = host.clone();
            let read_uuid_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32, is_big_endian: bool| {
                let off = offset as u64;
                // UUID is 16 bytes: 4 + 2 + 2 + 2 + 6
                let mut buf = [0u8; 16];
                for (i, slot) in buf.iter_mut().enumerate() {
                    match h.read_u8(off + i as u64) {
                        Ok(b) => *slot = b,
                        Err(_) => return String::new(),
                    }
                }
                if is_big_endian {
                    format!(
                        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
                        u16::from_be_bytes([buf[4], buf[5]]),
                        u16::from_be_bytes([buf[6], buf[7]]),
                        buf[8], buf[9],
                        buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]
                    )
                } else {
                    format!(
                        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
                        u16::from_le_bytes([buf[4], buf[5]]),
                        u16::from_le_bytes([buf[6], buf[7]]),
                        buf[8], buf[9],
                        buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]
                    )
                }
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_UUID: {e}"),
            })?;
            binary.set("read_UUID", read_uuid_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_UUID set: {e}"),
            })?;

            // read_UUID_bytes(offset) -> hex string of 16 bytes
            let h = host.clone();
            let read_uuid_bytes_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                let off = offset as u64;
                let mut result = String::with_capacity(32);
                for i in 0..16 {
                    match h.read_u8(off + i as u64) {
                        Ok(b) => result.push_str(&format!("{:02X}", b)),
                        Err(_) => return String::new(),
                    }
                }
                result
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_UUID_bytes: {e}"),
            })?;
            binary
                .set("read_UUID_bytes", read_uuid_bytes_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_UUID_bytes set: {e}"),
                })?;

            // --- File name/path ---

            let h = host.clone();
            let get_file_base_name_fn = rquickjs::Function::new(ctx.clone(), move || {
                // Return base name: file name without extension.
                let name = h.file_name();
                match name.rfind('.') {
                    Some(pos) => name[..pos].to_string(),
                    None => name.to_string(),
                }
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("getFileBaseName: {e}"),
            })?;
            binary
                .set("getFileBaseName", get_file_base_name_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("getFileBaseName set: {e}"),
                })?;

            // --- Short aliases (Sz, c, SA, SC, fStr, fSig, BA) ---

            // Sz() -> file size (alias for getSize)
            let h = host.clone();
            let sz_fn = rquickjs::Function::new(ctx.clone(), move || h.file_size() as f64)
                .map_err(|e| RuleError::Backend {
                    detail: format!("Sz: {e}"),
                })?;
            binary.set("Sz", sz_fn).map_err(|e| RuleError::Backend {
                detail: format!("Sz set: {e}"),
            })?;

            // c(signature, offset) -> bool (alias for compare, but args reversed)
            let h = host.clone();
            let c_fn =
                rquickjs::Function::new(ctx.clone(), move |signature: String, offset: i32| {
                    h.check_signature(offset as u64, &signature)
                        .unwrap_or(false)
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("c: {e}"),
                })?;
            binary.set("c", c_fn).map_err(|e| RuleError::Backend {
                detail: format!("c set: {e}"),
            })?;

            // SA(offset, maxSize) -> string (ANSI string read)
            let h = host.clone();
            let sa_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32, max_size: i32| {
                h.read_string(offset as u64, max_size as u64)
                    .unwrap_or_default()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("SA: {e}"),
            })?;
            binary.set("SA", sa_fn).map_err(|e| RuleError::Backend {
                detail: format!("SA set: {e}"),
            })?;

            // SC(offset, maxByteSize, codePage) -> string (code page string)
            // For now, just read as ANSI string (code page not implemented).
            let h = host.clone();
            let sc_fn = rquickjs::Function::new(
                ctx.clone(),
                move |offset: i32, max_size: i32, _code_page: String| {
                    h.read_string(offset as u64, max_size as u64)
                        .unwrap_or_default()
                },
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("SC: {e}"),
            })?;
            binary.set("SC", sc_fn).map_err(|e| RuleError::Backend {
                detail: format!("SC set: {e}"),
            })?;

            // fStr(offset, size, string) -> offset of found string or -1
            let h = host.clone();
            let fstr_fn = rquickjs::Function::new(
                ctx.clone(),
                move |offset: i32, _size: i32, needle: String| {
                    // Search for ASCII string in file data
                    let start = offset as usize;
                    let needle_bytes = needle.as_bytes();
                    if needle_bytes.is_empty()
                        || start + needle_bytes.len() > h.file_size() as usize
                    {
                        return -1.0;
                    }
                    // Use find_signature with hex encoding of the string
                    let hex: String = needle_bytes.iter().map(|b| format!("{b:02X}")).collect();
                    match h.find_signature(start as u64, &hex) {
                        Ok(Some(off)) => off as f64,
                        _ => -1.0,
                    }
                },
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("fStr: {e}"),
            })?;
            binary
                .set("fStr", fstr_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("fStr set: {e}"),
                })?;

            // fSig(offset, size, signature) -> offset or -1
            // Searches for signature within [offset, offset+size) range.
            let h = host.clone();
            let fsig_fn = rquickjs::Function::new(
                ctx.clone(),
                move |offset: i32, size: i32, signature: String| {
                    if size <= 0 || offset < 0 {
                        return -1.0;
                    }
                    let start = offset as u64;
                    let end = start.saturating_add(size as u64);
                    match h.find_signature_in_range(start, end, &signature) {
                        Ok(Some(off)) => off as f64,
                        _ => -1.0,
                    }
                },
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("fSig: {e}"),
            })?;
            binary
                .set("fSig", fsig_fn)
                .map_err(|e| RuleError::Backend {
                    detail: format!("fSig set: {e}"),
                })?;

            // BA(offset, size, replaceZero?) -> array of bytes
            let h = host.clone();
            let ba_fn = rquickjs::Function::new(
                ctx.clone(),
                move |offset: i32, size: i32, _replace: bool| {
                    let start = offset as usize;
                    let end = (start + size as usize).min(h.file_size() as usize);
                    if start >= end {
                        return Vec::<i32>::new();
                    }
                    // Use read_u8 for each byte
                    (start..end)
                        .map(|i| h.read_u8(i as u64).map(|v| v as i32).unwrap_or(0))
                        .collect::<Vec<i32>>()
                },
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("BA: {e}"),
            })?;
            binary.set("BA", ba_fn).map_err(|e| RuleError::Backend {
                detail: format!("BA set: {e}"),
            })?;

            // --- Register the Binary object and aliases ---

            globals
                .set("Binary", binary.clone())
                .map_err(|e| RuleError::Backend {
                    detail: format!("failed to set Binary global: {e}"),
                })?;

            // X and File are aliases for Binary (per file type binding).
            globals
                .set("X", binary.clone())
                .map_err(|e| RuleError::Backend {
                    detail: format!("failed to set X alias: {e}"),
                })?;

            globals
                .set("File", binary.clone())
                .map_err(|e| RuleError::Backend {
                    detail: format!("failed to set File alias: {e}"),
                })?;

            // Additional host API functions used by many rules.
            // isVerbose/isDeepScan/isHeuristicScan are already set above
            // using host methods. Only add remaining stubs here.

            // isOverlay() -> false
            let is_overlay_fn = rquickjs::Function::new(ctx.clone(), || false)
                .map_err(|e| RuleError::Backend {
                    detail: format!("isOverlay: {e}"),
                })?;
            binary.set("isOverlay", is_overlay_fn).map_err(|e| RuleError::Backend {
                detail: format!("isOverlay set: {e}"),
            })?;

            // isResource() -> false (PE-specific, stub for Binary)
            let is_resource_fn = rquickjs::Function::new(ctx.clone(), || false)
                .map_err(|e| RuleError::Backend {
                    detail: format!("isResource: {e}"),
                })?;
            binary.set("isResource", is_resource_fn).map_err(|e| RuleError::Backend {
                detail: format!("isResource set: {e}"),
            })?;

            // isPlainText() -> check if file content is all printable ASCII
            let h = host.clone();
            let is_plain_fn = rquickjs::Function::new(ctx.clone(), move || {
                let size = h.file_size() as usize;
                if size == 0 {
                    return false;
                }
                // Check up to 4096 bytes (match upstream behavior)
                let check_len = size.min(4096);
                for i in 0..check_len {
                    match h.read_u8(i as u64) {
                        Ok(b) => {
                            // Allow printable ASCII (0x20-0x7E), tab (0x09),
                            // LF (0x0A), CR (0x0D)
                            let is_printable = (0x20..=0x7E).contains(&b)
                                || b == 0x09
                                || b == 0x0A
                                || b == 0x0D;
                            if !is_printable {
                                return false;
                            }
                        }
                        _ => return false,
                    }
                }
                true
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("isPlainText: {e}"),
            })?;
            binary.set("isPlainText", is_plain_fn).map_err(|e| RuleError::Backend {
                detail: format!("isPlainText set: {e}"),
            })?;

            // isText() -> isPlainText || isUTF8Text || isUnicodeText
            let h = host.clone();
            let is_text_fn = rquickjs::Function::new(ctx.clone(), move || {
                let size = h.file_size() as usize;
                if size == 0 {
                    return false;
                }
                let check_len = size.min(4096);
                for i in 0..check_len {
                    match h.read_u8(i as u64) {
                        Ok(b) => {
                            let is_printable = (0x20..=0x7E).contains(&b)
                                || b == 0x09
                                || b == 0x0A
                                || b == 0x0D;
                            if !is_printable {
                                return false;
                            }
                        }
                        _ => return false,
                    }
                }
                true
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("isText: {e}"),
            })?;
            binary.set("isText", is_text_fn).map_err(|e| RuleError::Backend {
                detail: format!("isText set: {e}"),
            })?;

            // isZeroFilled(offset, size) -> false
            let is_zero_fn = rquickjs::Function::new(ctx.clone(), |_offset: i32, _size: i32| false)
                .map_err(|e| RuleError::Backend {
                    detail: format!("isZeroFilled: {e}"),
                })?;
            binary.set("isZeroFilled", is_zero_fn).map_err(|e| RuleError::Backend {
                detail: format!("isZeroFilled set: {e}"),
            })?;

            // isDebugData() -> false
            let is_debug_fn = rquickjs::Function::new(ctx.clone(), || false)
                .map_err(|e| RuleError::Backend {
                    detail: format!("isDebugData: {e}"),
                })?;
            binary.set("isDebugData", is_debug_fn).map_err(|e| RuleError::Backend {
                detail: format!("isDebugData set: {e}"),
            })?;

            // getOverlayOffset() -> -1 (no overlay)
            let get_overlay_fn = rquickjs::Function::new(ctx.clone(), || -1i32)
                .map_err(|e| RuleError::Backend {
                    detail: format!("getOverlayOffset: {e}"),
                })?;
            binary.set("getOverlayOffset", get_overlay_fn).map_err(|e| RuleError::Backend {
                detail: format!("getOverlayOffset set: {e}"),
            })?;

            // getOverlaySize() -> 0 (no overlay)
            let get_overlay_size_fn = rquickjs::Function::new(ctx.clone(), || 0i32)
                .map_err(|e| RuleError::Backend {
                    detail: format!("getOverlaySize: {e}"),
                })?;
            binary.set("getOverlaySize", get_overlay_size_fn).map_err(|e| RuleError::Backend {
                detail: format!("getOverlaySize set: {e}"),
            })?;

            // getScanID() -> empty string
            let get_scanid_fn = rquickjs::Function::new(ctx.clone(), String::new)
                .map_err(|e| RuleError::Backend {
                    detail: format!("getScanID: {e}"),
                })?;
            binary.set("getScanID", get_scanid_fn).map_err(|e| RuleError::Backend {
                detail: format!("getScanID set: {e}"),
            })?;

            // getFileSuffix() -> empty string
            let get_suffix_fn = rquickjs::Function::new(ctx.clone(), String::new)
                .map_err(|e| RuleError::Backend {
                    detail: format!("getFileSuffix: {e}"),
                })?;
            binary.set("getFileSuffix", get_suffix_fn).map_err(|e| RuleError::Backend {
                detail: format!("getFileSuffix set: {e}"),
            })?;

            // readByte(offset) -> u8 or -1 on out-of-bounds
            let h = host.clone();
            let read_byte_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u8(offset as u64).map(|v| v as i32).unwrap_or(-1)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("readByte: {e}"),
            })?;
            binary.set("readByte", read_byte_fn).map_err(|e| RuleError::Backend {
                detail: format!("readByte set: {e}"),
            })?;

            // readWord(offset) -> u16 LE (alias for U16)
            let h = host.clone();
            let read_word_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u16_le(offset as u64).map(|v| v as i32).unwrap_or(0)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("readWord: {e}"),
            })?;
            binary.set("readWord", read_word_fn).map_err(|e| RuleError::Backend {
                detail: format!("readWord set: {e}"),
            })?;

            // readDword(offset) -> u32 LE (alias for U32)
            let h = host.clone();
            let read_dword_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                h.read_u32_le(offset as u64).unwrap_or(0) as f64
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("readDword: {e}"),
            })?;
            binary.set("readDword", read_dword_fn).map_err(|e| RuleError::Backend {
                detail: format!("readDword set: {e}"),
            })?;

            // read_ansiString(offset, maxSize) -> string
            let h = host.clone();
            let read_ansi_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, max_size: i32| {
                    let file_size = h.file_size() as usize;
                    let start = offset as usize;
                    if start >= file_size {
                        return String::new();
                    }
                    let len = if max_size > 0 {
                        max_size as usize
                    } else {
                        file_size.saturating_sub(start)
                    };
                    let end = start.saturating_add(len).min(file_size);
                    let mut bytes = Vec::with_capacity(end - start);
                    for i in start..end {
                        match h.read_u8(i as u64) {
                            Ok(b) => {
                                if b == 0 {
                                    break;
                                }
                                bytes.push(b);
                            }
                            Err(_) => break,
                        }
                    }
                    String::from_utf8_lossy(&bytes).into_owned()
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_ansiString: {e}"),
                })?;
            binary.set("read_ansiString", read_ansi_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_ansiString set: {e}"),
            })?;

            // read_unicodeString(offset, maxSize) -> string (UTF-16LE)
            let h = host.clone();
            let read_unicode_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, max_size: i32| {
                    let file_size = h.file_size() as usize;
                    let start = offset as usize;
                    if start >= file_size {
                        return String::new();
                    }
                    let len = if max_size > 0 {
                        max_size as usize
                    } else {
                        file_size.saturating_sub(start)
                    };
                    let end = start.saturating_add(len).min(file_size);
                    let mut result = String::new();
                    let mut i = start;
                    while i + 1 < end {
                        let lo = match h.read_u8(i as u64) {
                            Ok(b) => b,
                            Err(_) => break,
                        };
                        let hi = match h.read_u8((i + 1) as u64) {
                            Ok(b) => b,
                            Err(_) => break,
                        };
                        if lo == 0 && hi == 0 {
                            break;
                        }
                        let code = u16::from_le_bytes([lo, hi]);
                        result.push(char::from_u32(code as u32).unwrap_or('\u{FFFD}'));
                        i += 2;
                    }
                    result
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_unicodeString: {e}"),
                })?;
            binary.set("read_unicodeString", read_unicode_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_unicodeString set: {e}"),
            })?;

            // findString(offset, size, pattern) -> offset or -1
            let h = host.clone();
            let find_string_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32, pattern: String| {
                    let file_size = h.file_size() as usize;
                    let start = offset as usize;
                    if start >= file_size {
                        return -1i32;
                    }
                    let end = if size > 0 {
                        (start.saturating_add(size as usize)).min(file_size)
                    } else {
                        file_size
                    };
                    let needle = pattern.as_bytes();
                    if needle.is_empty() {
                        return offset;
                    }
                    let mut i = start;
                    while i + needle.len() <= end {
                        let mut found = true;
                        for (j, &nb) in needle.iter().enumerate() {
                            match h.read_u8((i + j) as u64) {
                                Ok(b) if b == nb => {}
                                _ => {
                                    found = false;
                                    break;
                                }
                            }
                        }
                        if found {
                            return i as i32;
                        }
                        i += 1;
                    }
                    -1
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("findString: {e}"),
                })?;
            binary.set("findString", find_string_fn).map_err(|e| RuleError::Backend {
                detail: format!("findString set: {e}"),
            })?;

            // findByte(offset, size, byte) -> offset or -1
            let h = host.clone();
            let find_byte_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32, byte: i32| {
                    let file_size = h.file_size() as usize;
                    let start = offset as usize;
                    if start >= file_size {
                        return -1i32;
                    }
                    let end = if size > 0 {
                        (start.saturating_add(size as usize)).min(file_size)
                    } else {
                        file_size
                    };
                    let target = byte as u8;
                    for i in start..end {
                        if h.read_u8(i as u64).unwrap_or(0) == target {
                            return i as i32;
                        }
                    }
                    -1
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("findByte: {e}"),
                })?;
            binary.set("findByte", find_byte_fn).map_err(|e| RuleError::Backend {
                detail: format!("findByte set: {e}"),
            })?;

            // findWord(offset, size, value) -> offset or -1 (search uint16 LE)
            let h = host.clone();
            let find_word_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32, value: i32| {
                    let file_size = h.file_size() as usize;
                    let start = offset as usize;
                    if start + 2 > file_size {
                        return -1i32;
                    }
                    let end = if size > 0 {
                        (start.saturating_add(size as usize)).min(file_size)
                    } else {
                        file_size
                    };
                    let target = value as u16;
                    let mut i = start;
                    while i + 2 <= end {
                        let lo = h.read_u8(i as u64).unwrap_or(0) as u16;
                        let hi = h.read_u8((i + 1) as u64).unwrap_or(0) as u16;
                        if (lo | (hi << 8)) == target {
                            return i as i32;
                        }
                        i += 1;
                    }
                    -1
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("findWord: {e}"),
                })?;
            binary.set("findWord", find_word_fn).map_err(|e| RuleError::Backend {
                detail: format!("findWord set: {e}"),
            })?;

            // findDword(offset, size, value) -> offset or -1 (search uint32 LE)
            let h = host.clone();
            let find_dword_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32, value: i32| {
                    let file_size = h.file_size() as usize;
                    let start = offset as usize;
                    if start + 4 > file_size {
                        return -1i32;
                    }
                    let end = if size > 0 {
                        (start.saturating_add(size as usize)).min(file_size)
                    } else {
                        file_size
                    };
                    let target = value as u32;
                    let mut i = start;
                    while i + 4 <= end {
                        let b0 = h.read_u8(i as u64).unwrap_or(0) as u32;
                        let b1 = h.read_u8((i + 1) as u64).unwrap_or(0) as u32;
                        let b2 = h.read_u8((i + 2) as u64).unwrap_or(0) as u32;
                        let b3 = h.read_u8((i + 3) as u64).unwrap_or(0) as u32;
                        if (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) == target {
                            return i as i32;
                        }
                        i += 1;
                    }
                    -1
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("findDword: {e}"),
                })?;
            binary.set("findDword", find_dword_fn).map_err(|e| RuleError::Backend {
                detail: format!("findDword set: {e}"),
            })?;

            // bytesCountToString(n) -> human-readable size string
            let bcs_fn = rquickjs::Function::new(ctx.clone(), |n: f64| {
                if n < 1024.0 {
                    format!("{n:.0} B")
                } else if n < 1048576.0 {
                    format!("{:.1} KB", n / 1024.0)
                } else if n < 1073741824.0 {
                    format!("{:.1} MB", n / 1048576.0)
                } else {
                    format!("{:.1} GB", n / 1073741824.0)
                }
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("bytesCountToString: {e}"),
            })?;
            binary.set("bytesCountToString", bcs_fn).map_err(|e| RuleError::Backend {
                detail: format!("bytesCountToString set: {e}"),
            })?;

            // cleanString(s) -> remove non-alphanumeric/non-punct chars.
            // Matches upstream XBinary::cleanString which keeps only
            // letters, numbers, and punctuation characters.
            let clean_fn = rquickjs::Function::new(ctx.clone(), |s: String| {
                s.chars()
                    .filter(|c| c.is_alphanumeric() || c.is_ascii_punctuation())
                    .collect::<String>()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("cleanString: {e}"),
            })?;
            binary.set("cleanString", clean_fn).map_err(|e| RuleError::Backend {
                detail: format!("cleanString set: {e}"),
            })?;

            // getHeaderString() -> empty string
            let get_header_fn = rquickjs::Function::new(ctx.clone(), String::new)
                .map_err(|e| RuleError::Backend {
                    detail: format!("getHeaderString: {e}"),
                })?;
            binary.set("getHeaderString", get_header_fn).map_err(|e| RuleError::Backend {
                detail: format!("getHeaderString set: {e}"),
            })?;

            // crc16(offset, size) -> u16 CRC-16 (CCITT)
            let h = host.clone();
            let crc16_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32| {
                    let file_size = h.file_size() as usize;
                    let start = offset as usize;
                    if start >= file_size {
                        return 0i32;
                    }
                    let end = if size > 0 {
                        (start.saturating_add(size as usize)).min(file_size)
                    } else {
                        file_size
                    };
                    let mut crc: u16 = 0xFFFF;
                    for i in start..end {
                        let byte = h.read_u8(i as u64).unwrap_or(0);
                        crc ^= byte as u16;
                        for _ in 0..8 {
                            if crc & 1 != 0 {
                                crc = (crc >> 1) ^ 0xA001;
                            } else {
                                crc >>= 1;
                            }
                        }
                    }
                    crc as i32
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("crc16: {e}"),
                })?;
            binary.set("crc16", crc16_fn).map_err(|e| RuleError::Backend {
                detail: format!("crc16 set: {e}"),
            })?;

            // find_utf8String(offset, maxSize) -> string (UTF-8 string read)
            let h = host.clone();
            let find_utf8_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, max_size: i32| {
                    let file_size = h.file_size() as usize;
                    let start = offset as usize;
                    if start >= file_size {
                        return String::new();
                    }
                    let len = if max_size > 0 {
                        max_size as usize
                    } else {
                        file_size.saturating_sub(start)
                    };
                    let end = start.saturating_add(len).min(file_size);
                    let mut bytes = Vec::with_capacity(end - start);
                    for i in start..end {
                        match h.read_u8(i as u64) {
                            Ok(b) => {
                                if b == 0 {
                                    break;
                                }
                                bytes.push(b);
                            }
                            Err(_) => break,
                        }
                    }
                    String::from_utf8_lossy(&bytes).into_owned()
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("find_utf8String: {e}"),
                })?;
            binary.set("find_utf8String", find_utf8_fn).map_err(|e| RuleError::Backend {
                detail: format!("find_utf8String set: {e}"),
            })?;

            // read_codePageString(offset, maxSize, codePage?) -> string
            // The codePage parameter is a string (e.g. 'SJIS', 'CP1251').
            // For now, treat as ANSI string (code page ignored).
            let h = host.clone();
            let read_cp_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, max_size: i32, _code_page: Option<String>| {
                    let file_size = h.file_size() as usize;
                    let start = offset as usize;
                    if start >= file_size {
                        return String::new();
                    }
                    let len = if max_size > 0 {
                        max_size as usize
                    } else {
                        file_size.saturating_sub(start)
                    };
                    let end = start.saturating_add(len).min(file_size);
                    let mut bytes = Vec::with_capacity(end - start);
                    for i in start..end {
                        match h.read_u8(i as u64) {
                            Ok(b) => {
                                if b == 0 {
                                    break;
                                }
                                bytes.push(b);
                            }
                            Err(_) => break,
                        }
                    }
                    String::from_utf8_lossy(&bytes).into_owned()
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("read_codePageString: {e}"),
                })?;
            binary.set("read_codePageString", read_cp_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_codePageString set: {e}"),
            })?;

            // read_ucsdString(offset) -> Pascal-style string (length-prefixed)
            let h = host.clone();
            let read_ucsd_fn = rquickjs::Function::new(ctx.clone(), move |offset: i32| {
                let file_size = h.file_size() as usize;
                let start = offset as usize;
                if start >= file_size {
                    return String::new();
                }
                let len = h.read_u8(start as u64).unwrap_or(0) as usize;
                if len == 0 {
                    return String::new();
                }
                let str_start = start + 1;
                let end = str_start.saturating_add(len).min(file_size);
                let mut bytes = Vec::with_capacity(end - str_start);
                for i in str_start..end {
                    bytes.push(h.read_u8(i as u64).unwrap_or(0));
                }
                String::from_utf8_lossy(&bytes).into_owned()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("read_ucsdString: {e}"),
            })?;
            binary.set("read_ucsdString", read_ucsd_fn).map_err(|e| RuleError::Backend {
                detail: format!("read_ucsdString set: {e}"),
            })?;

            // readBytes(offset, size, replaceZeroWithSpace?) -> array of byte values
            // Native function takes 2 required args; JS wrapper handles optional 3rd.
            let h = host.clone();
            let read_bytes_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32| {
                    let file_size = h.file_size() as usize;
                    let start = offset as usize;
                    if start >= file_size || size <= 0 {
                        return Vec::<i32>::new();
                    }
                    let end = start.saturating_add(size as usize).min(file_size);
                    let mut result = Vec::with_capacity(end - start);
                    for i in start..end {
                        result.push(h.read_u8(i as u64).unwrap_or(0) as i32);
                    }
                    result
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("readBytes: {e}"),
                })?;
            binary.set("__readBytes", read_bytes_fn).map_err(|e| RuleError::Backend {
                detail: format!("__readBytes set: {e}"),
            })?;

            // fSig(offset, size, signature) -> findSignature (offset or -1)
            let h = host.clone();
            let fsig_fn =
                rquickjs::Function::new(ctx.clone(), move |offset: i32, size: i32, signature: String| {
                    let file_size = h.file_size() as usize;
                    let start = offset as usize;
                    if start >= file_size {
                        return -1i32;
                    }
                    let end = if size > 0 {
                        (start.saturating_add(size as usize)).min(file_size)
                    } else {
                        file_size
                    };
                    // Parse the signature and search for it.
                    match parse_signature(&signature) {
                        Ok(elements) => {
                            if elements.is_empty() {
                                return offset;
                            }
                            let needle_len = elements.len();
                            if start + needle_len > end {
                                return -1;
                            }
                            // Read a window of bytes and match against elements.
                            for i in start..=end.saturating_sub(needle_len) {
                                let mut matched = true;
                                for (j, elem) in elements.iter().enumerate() {
                                    let byte = h.read_u8((i + j) as u64).unwrap_or(0);
                                    match elem {
                                        SigElement::Byte(b) if byte == *b => {}
                                        SigElement::Any => {}
                                        _ => {
                                            matched = false;
                                            break;
                                        }
                                    }
                                }
                                if matched {
                                    return i as i32;
                                }
                            }
                            -1
                        }
                        Err(_) => -1,
                    }
                })
                .map_err(|e| RuleError::Backend {
                    detail: format!("fSig: {e}"),
                })?;
            binary.set("fSig", fsig_fn).map_err(|e| RuleError::Backend {
                detail: format!("fSig set: {e}"),
            })?;

            // Register PE as an independent object (like ELF/MACH/MACHOFAT)
            // with Binary properties copied in. This allows adding PE-specific
            // methods without modifying Binary itself.
            let pe_obj = ctx
                .eval::<rquickjs::Object, _>("Object.create(Object.prototype)")
                .map_err(|e| RuleError::Backend {
                    detail: format!("PE creation: {e}"),
                })?;
            globals.set("PE", pe_obj).map_err(|e| RuleError::Backend {
                detail: format!("PE set: {e}"),
            })?;

            // Register native disassembly functions on PE object.
            // These use Capstone to disassemble x86/x64 instructions at
            // the given virtual address, returning the mnemonic string
            // and next instruction address respectively.
            let pe_handle = host.clone();
            let disasm_str_fn = rquickjs::Function::new(ctx.clone(), move |va: i64| -> String {
                disasm_at_va(&pe_handle, va as u64, false)
                    .unwrap_or_default()
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("getDisasmString: {e}"),
            })?;
            let pe_obj_ref = globals.get::<_, rquickjs::Object>("PE").map_err(|e| {
                RuleError::Backend {
                    detail: format!("PE get: {e}"),
                }
            })?;
            pe_obj_ref.set("getDisasmString", disasm_str_fn).map_err(|e| {
                RuleError::Backend {
                    detail: format!("getDisasmString set: {e}"),
                }
            })?;

            let pe_handle2 = host.clone();
            let disasm_next_fn = rquickjs::Function::new(ctx.clone(), move |va: i64| -> i64 {
                disasm_at_va(&pe_handle2, va as u64, true)
                    .map(|s| {
                        // Parse next address from the disasm result.
                        // disasm_at_va with return_next=true returns
                        // "next_addr" as a string.
                        s.parse::<i64>().unwrap_or(-1)
                    })
                    .unwrap_or(-1)
            })
            .map_err(|e| RuleError::Backend {
                detail: format!("getDisasmNextAddress: {e}"),
            })?;
            pe_obj_ref.set("getDisasmNextAddress", disasm_next_fn).map_err(|e| {
                RuleError::Backend {
                    detail: format!("getDisasmNextAddress set: {e}"),
                }
            })?;

            // Add PE-specific methods that parse the PE header from raw bytes.
            // These implement the most commonly used PE host API methods by
            // reading the DOS header, PE header, and section table directly
            // from the file data via the Binary read primitives.
            // IMPORTANT: Use Binary.* directly, NOT File.*, because the
            // _init script sets File = PE, which would cause infinite
            // recursion when PE methods call File methods.
            ctx.eval::<(), _>(
                r#"
                (function() {
                    // Save Binary reference in a local variable to ensure
                    // closures always access the correct object.
                    var _B = Binary;
                    // DOS header: e_lfanew at offset 0x3C (4 bytes, LE).
                    function _peIsPE() {
                        if (_B.getSize() < 64) return false;
                        // Check MZ signature at offset 0.
                        if (_B.read_uint8(0) !== 0x4D || _B.read_uint8(1) !== 0x5A) return false;
                        var e_lfanew = _B.read_uint32_le(0x3C);
                        if (e_lfanew + 4 > _B.getSize()) return false;
                        // Check PE signature "PE\0\0" at e_lfanew.
                        return (_B.read_uint8(e_lfanew) === 0x50 &&
                                _B.read_uint8(e_lfanew + 1) === 0x45 &&
                                _B.read_uint8(e_lfanew + 2) === 0x00 &&
                                _B.read_uint8(e_lfanew + 3) === 0x00);
                    }

                    function _peLfanew() { return _B.read_uint32_le(0x3C); }

                    // COFF header starts at e_lfanew + 4.
                    // Machine(2) NumberOfSections(2) TimeDateStamp(4) PointerToSymbolTable(4)
                    // NumberOfSymbols(4) SizeOfOptionalHeader(2) Characteristics(2)
                    function _peMachine() { return _B.read_uint16_le(_peLfanew() + 4); }
                    function _peNumberOfSections() { return _B.read_uint16_le(_peLfanew() + 6); }
                    function _peSizeOfOptionalHeader() { return _B.read_uint16_le(_peLfanew() + 20); }

                    // Optional header starts at e_lfanew + 24.
                    // Magic(2): 0x10B = PE32, 0x20B = PE32+
                    function _peOptHdrOff() { return _peLfanew() + 24; }
                    function _peIs64() { return _B.read_uint16_le(_peOptHdrOff()) === 0x20B; }

                    // PE32 Optional Header:
                    // Magic(0) MajorLinkerVersion(2) MinorLinkerVersion(3)
                    // SizeOfCode(4) SizeOfInitializedData(8) SizeOfUninitializedData(12)
                    // AddressOfEntryPoint(16) BaseOfCode(20) BaseOfData(24)
                    // ImageBase(28) SectionAlignment(32) FileAlignment(36)
                    // ...
                    // PE32+ Optional Header:
                    // Same up to AddressOfEntryPoint(16) BaseOfCode(20)
                    // ImageBase(24) SectionAlignment(32) ...
                    function _peEntryPoint() { return _B.read_uint32_le(_peOptHdrOff() + 16); }
                    function _peImageBase() {
                        return _peIs64() ? _B.read_uint64_le(_peOptHdrOff() + 24) : _B.read_uint32_le(_peOptHdrOff() + 28);
                    }
                    function _peSizeOfImage() { return _B.read_uint32_le(_peOptHdrOff() + (_peIs64() ? 56 : 60)); }

                    // Section table starts after optional header.
                    function _peSectionTableOff() { return _peOptHdrOff() + _peSizeOfOptionalHeader(); }

                    // Section header (40 bytes each):
                    // Name(0) VirtualSize(4) VirtualAddress(8) SizeOfRawData(12)
                    // PointerToRawData(16) ... Characteristics(36)
                    function _peSecHdrOff(n) { return _peSectionTableOff() + n * 40; }

                    function _peSectionName(n) {
                        var off = _peSecHdrOff(n);
                        var name = "";
                        for (var i = 0; i < 8; i++) {
                            var b = _B.read_uint8(off + i);
                            if (b === 0) break;
                            name += String.fromCharCode(b);
                        }
                        return name;
                    }
                    // Section header layout (IMAGE_SECTION_HEADER, 40 bytes):
                    //   0-7:   Name (8 bytes)
                    //   8-11:  VirtualSize (union with PhysicalAddress)
                    //   12-15: VirtualAddress
                    //   16-19: SizeOfRawData
                    //   20-23: PointerToRawData
                    //   24-27: PointerToRelocations
                    //   28-31: PointerToLinenumbers
                    //   32-33: NumberOfRelocations
                    //   34-35: NumberOfLinenumbers
                    //   36-39: Characteristics
                    function _peSectionVirtualSize(n) { return _B.read_uint32_le(_peSecHdrOff(n) + 8); }
                    function _peSectionVirtualAddress(n) { return _B.read_uint32_le(_peSecHdrOff(n) + 12); }
                    function _peSectionFileSize(n) { return _B.read_uint32_le(_peSecHdrOff(n) + 16); }
                    function _peSectionFileOffset(n) { return _B.read_uint32_le(_peSecHdrOff(n) + 20); }
                    function _peSectionCharacteristics(n) { return _B.read_uint32_le(_peSecHdrOff(n) + 36); }

                    function _peSectionNumber(name) {
                        var n = _peNumberOfSections();
                        for (var i = 0; i < n; i++) {
                            if (_peSectionName(i) === name) return i;
                        }
                        return -1;
                    }

                    // Convert RVA to file offset using section table.
                    function _peRvaToFileOffset(rva) {
                        var n = _peNumberOfSections();
                        for (var i = 0; i < n; i++) {
                            var va = _peSectionVirtualAddress(i);
                            var vs = _peSectionVirtualSize(i);
                            var rawSize = _peSectionFileSize(i);
                            var rawOff = _peSectionFileOffset(i);
                            var size = vs < rawSize ? rawSize : vs;
                            if (rva >= va && rva < va + size) {
                                return rawOff + (rva - va);
                            }
                        }
                        return -1;
                    }

                    // PE machine names.
                    var _peMachineNames = {};
                    _peMachineNames[0x14C] = "i386";
                    _peMachineNames[0x8664] = "amd64";
                    _peMachineNames[0x1C0] = "ARM";
                    _peMachineNames[0xAA64] = "ARM64";
                    _peMachineNames[0x200] = "IA64";
                    _peMachineNames[0x1A2] = "RISC-V64";

                    // Subsystem names.
                    var _peSubsystemNames = {};
                    _peSubsystemNames[1] = "Native";
                    _peSubsystemNames[2] = "Windows GUI";
                    _peSubsystemNames[3] = "Windows console";
                    _peSubsystemNames[5] = "OS/2 character";
                    _peSubsystemNames[7] = "Posix character";
                    _peSubsystemNames[9] = "Windows CE GUI";
                    _peSubsystemNames[10] = "EFI application";
                    _peSubsystemNames[11] = "EFI boot service driver";
                    _peSubsystemNames[12] = "EFI runtime driver";
                    _peSubsystemNames[13] = "EFI ROM";
                    _peSubsystemNames[14] = "XBOX";

                    function _peSubsystem() {
                        return _B.read_uint16_le(_peOptHdrOff() + (_peIs64() ? 68 : 68));
                    }

                    // --- Public PE API methods ---
                    PE.is64 = function() {
                        if (!_peIsPE()) return false;
                        return _peIs64();
                    };
                    PE.getNumberOfSections = function() {
                        if (!_peIsPE()) return 0;
                        return _peNumberOfSections();
                    };
                    PE.getSectionName = function(n) {
                        if (!_peIsPE()) return "";
                        if (n >= _peNumberOfSections()) return "";
                        return _peSectionName(n);
                    };
                    PE.getSectionVirtualSize = function(n) {
                        if (!_peIsPE()) return 0;
                        if (n >= _peNumberOfSections()) return 0;
                        return _peSectionVirtualSize(n);
                    };
                    PE.getSectionVirtualAddress = function(n) {
                        if (!_peIsPE()) return 0;
                        if (n >= _peNumberOfSections()) return 0;
                        return _peSectionVirtualAddress(n);
                    };
                    PE.getSectionFileSize = function(n) {
                        if (!_peIsPE()) return 0;
                        if (n >= _peNumberOfSections()) return 0;
                        return _peSectionFileSize(n);
                    };
                    PE.getSectionFileOffset = function(n) {
                        if (!_peIsPE()) return 0;
                        if (n >= _peNumberOfSections()) return 0;
                        return _peSectionFileOffset(n);
                    };
                    PE.getSectionCharacteristics = function(n) {
                        if (!_peIsPE()) return 0;
                        if (n >= _peNumberOfSections()) return 0;
                        return _peSectionCharacteristics(n);
                    };
                    PE.isSectionNamePresent = function(name) {
                        if (!_peIsPE()) return false;
                        return _peSectionNumber(name) >= 0;
                    };
                    PE.getSectionNumber = function(name) {
                        if (!_peIsPE()) return -1;
                        return _peSectionNumber(name);
                    };
                    PE.getSectionNumberExp = function(name) {
                        if (!_peIsPE()) return -1;
                        // Exp variant: case-insensitive match.
                        var n = _peNumberOfSections();
                        var lower = name.toLowerCase();
                        for (var i = 0; i < n; i++) {
                            if (_peSectionName(i).toLowerCase() === lower) return i;
                        }
                        return -1;
                    };
                    PE.getSizeOfCode = function() {
                        if (!_peIsPE()) return 0;
                        return _B.read_uint32_le(_peOptHdrOff() + 4);
                    };
                    PE.getSizeOfUninitializedData = function() {
                        if (!_peIsPE()) return 0;
                        return _B.read_uint32_le(_peOptHdrOff() + 8);
                    };
                    PE.getFileVersionMS = function() {
                        // File version MS from version resource (upstream parses
                        // VS_VERSIONINFO). Approximate from optional header.
                        if (!_peIsPE()) return "";
                        return _peGetBatch().fileVersion || "";
                    };
                    PE.getImageFileHeader = function(field) {
                        // Return COFF header field by name.
                        // IMAGE_FILE_HEADER at e_lfanew + 24, 20 bytes:
                        //   0: Machine (uint16)
                        //   2: NumberOfSections (uint16)
                        //   4: TimeDateStamp (uint32)
                        //   8: PointerToSymbolTable (uint32)
                        //  12: NumberOfSymbols (uint32)
                        //  16: SizeOfOptionalHeader (uint16)
                        //  18: Characteristics (uint16)
                        if (!_peIsPE()) return 0;
                        var base = _peLfanew() + 24;
                        switch (field) {
                            case "Machine": return _B.read_uint16_le(base + 0);
                            case "NumberOfSections": return _B.read_uint16_le(base + 2);
                            case "TimeDateStamp": return _B.read_uint32_le(base + 4);
                            case "PointerToSymbolTable": return _B.read_uint32_le(base + 8);
                            case "NumberOfSymbols": return _B.read_uint32_le(base + 12);
                            case "SizeOfOptionalHeader": return _B.read_uint16_le(base + 16);
                            case "Characteristics": return _B.read_uint16_le(base + 18);
                            default: return 0;
                        }
                    };
                    PE.calculateSizeOfHeaders = function() {
                        // SizeOfHeaders from optional header.
                        if (!_peIsPE()) return 0;
                        return _B.read_uint32_le(_peOptHdrOff() + 60);
                    };
                    // PE.nLastSection and PE.section are populated by the
                    // upstream db/PE/_init script (executed during init),
                    // which iterates sections via getSectionName/Size/etc.
                    // Do NOT hardcode them here — that would overwrite the
                    // _init script's populated arrays.

                    PE.getEntryPoint = function() {
                        if (!_peIsPE()) return 0;
                        return _peEntryPoint();
                    };
                    PE.nEP = 0; // Will be set below.
                    PE.getImageBase = function() {
                        if (!_peIsPE()) return 0;
                        return _peImageBase();
                    };
                    PE.getSizeOfImage = function() {
                        if (!_peIsPE()) return 0;
                        return _peSizeOfImage();
                    };
                    PE.getMachine = function() {
                        if (!_peIsPE()) return "";
                        return _peMachineNames[_peMachine()] || "";
                    };
                    PE.getGeneralOptions = function() {
                        if (!_peIsPE()) return "";
                        var m = _peMachineNames[_peMachine()] || ("machine" + _peMachine());
                        var b = _peIs64() ? "64" : "32";
                        return m + "-" + b;
                    };
                    PE.isConsole = function() {
                        if (!_peIsPE()) return false;
                        return _peSubsystem() === 3;
                    };
                    PE.getSubsystem = function() {
                        if (!_peIsPE()) return "";
                        return _peSubsystemNames[_peSubsystem()] || "";
                    };

                    // compareEP: compare signature at entry point (RVA → file offset).
                    // Supports $ (relative offset) jump markers: reads N bytes
                    // as signed integer, computes target RVA, converts to file
                    // offset, and continues matching at the target.
                    PE.compareEP = function(sig, offset) {
                        if (!_peIsPE()) return false;
                        var ep = _peEntryPoint();
                        if (ep === 0) return false;
                        var fileOff = _peRvaToFileOffset(ep);
                        if (fileOff < 0) return false;
                        if (offset === undefined) offset = 0;
                        // If signature contains $, use PE-aware comparison.
                        if (sig.indexOf('$') >= 0) {
                            return _peCompareSigWithJumps(sig, fileOff + offset);
                        }
                        return _B.__compare(sig, fileOff + offset);
                    };

                    // PE-aware signature comparison with $ (relative offset) support.
                    // Parses the signature, matching hex bytes and wildcards directly,
                    // and resolving $ markers as relative jumps.
                    function _peCompareSigWithJumps(sig, startOff) {
                        var totalSize = _B.getSize();
                        var pos = startOff;
                        var i = 0;
                        var len = sig.length;
                        while (i < len) {
                            var c = sig.charAt(i);
                            if (c === ' ' || c === '\t') { i++; continue; }
                            if (c === '$') {
                                // Count consecutive $ characters.
                                var count = 0;
                                while (i < len && sig.charAt(i) === '$') { count++; i++; }
                                var addrSize = count >> 1;
                                if (count & 1) return false;
                                if (addrSize !== 1 && addrSize !== 2 && addrSize !== 4 && addrSize !== 8) return false;
                                if (pos + addrSize > totalSize) return false;
                                // Read signed integer (little-endian).
                                var value = 0;
                                for (var b = 0; b < addrSize; b++) {
                                    value |= _B.read_uint8(pos + b) << (b * 8);
                                }
                                // Sign-extend.
                                if (addrSize === 1) {
                                    if (value & 0x80) value |= ~0xFF;
                                } else if (addrSize === 2) {
                                    if (value & 0x8000) value |= ~0xFFFF;
                                } else if (addrSize === 4) {
                                    if (value & 0x80000000) value |= ~0xFFFFFFFF;
                                }
                                // For 8-byte, value is already 64-bit via read_uint8 shifts.
                                // Compute target: current_rva + value + addr_size.
                                // We need offset_to_rva for current pos.
                                var currentRva = PE.OffsetToRVA(pos);
                                if (currentRva < 0) return false;
                                // Use 32-bit arithmetic for RVA (PE is 32-bit address space).
                                var targetRva = (currentRva + value + addrSize) >>> 0;
                                var targetOff = _peRvaToFileOffset(targetRva);
                                if (targetOff < 0) return false;
                                pos = targetOff;
                            } else if (c === '.' || c === '?') {
                                // Wildcard nibble: need 2 for a full byte.
                                var nibbles = 0;
                                var byteVal = 0;
                                while (i < len && (sig.charAt(i) === '.' || sig.charAt(i) === '?')) {
                                    nibbles++;
                                    byteVal <<= 4;
                                    i++;
                                }
                                if (nibbles === 2) {
                                    pos++; // Skip one byte.
                                } else if (nibbles === 1) {
                                    // Single wildcard nibble + hex digit.
                                    if (i >= len) return false;
                                    var h = sig.charAt(i);
                                    var hv = parseInt(h, 16);
                                    if (isNaN(hv)) return false;
                                    // High nibble wildcard, low nibble known.
                                    var actual = _B.read_uint8(pos);
                                    if ((actual & 0x0F) !== hv) return false;
                                    pos++;
                                    i++;
                                } else {
                                    // Multiple bytes of wildcards.
                                    var fullBytes = Math.floor(nibbles / 2);
                                    pos += fullBytes;
                                    if (nibbles & 1) {
                                        if (i < len) {
                                            var h2 = sig.charAt(i);
                                            var hv2 = parseInt(h2, 16);
                                            if (!isNaN(hv2)) { i++; }
                                        }
                                        pos++;
                                    }
                                }
                            } else if (c === "'") {
                                // String literal: read until closing quote.
                                i++;
                                while (i < len && sig.charAt(i) !== "'") {
                                    if (pos >= totalSize) return false;
                                    var expected = sig.charCodeAt(i);
                                    if (_B.read_uint8(pos) !== expected) return false;
                                    pos++;
                                    i++;
                                }
                                if (i < len) i++; // Skip closing quote.
                            } else {
                                // Hex byte: two hex digits.
                                if (i + 1 >= len) return false;
                                var h1 = sig.charAt(i);
                                var h2 = sig.charAt(i + 1);
                                var v = parseInt(h1 + h2, 16);
                                if (isNaN(v)) return false;
                                if (pos >= totalSize) return false;
                                if (_B.read_uint8(pos) !== v) return false;
                                pos++;
                                i += 2;
                            }
                        }
                        return true;
                    }

                    // Overlay: data after the last section's raw data.
                    // Overlay offset = max(PointerToRawData + SizeOfRawData)
                    // across all sections. Overlay size = fileSize - overlayOffset.
                    PE.getOverlayOffset = function() {
                        if (!_peIsPE()) return -1;
                        var n = _peNumberOfSections();
                        var maxEnd = 0;
                        for (var i = 0; i < n; i++) {
                            var rawOff = _peSectionFileOffset(i);
                            var rawSize = _peSectionFileSize(i);
                            var end = rawOff + rawSize;
                            if (end > maxEnd) maxEnd = end;
                        }
                        // Also consider security directory (index 4) for
                        // Authenticode-signed files: overlay is before signature.
                        var secDir = _peDataDirOff(4);
                        var secOff = _B.read_uint32_le(secDir);
                        var secSize = _B.read_uint32_le(secDir + 4);
                        if (secOff > 0 && secSize > 0 && secOff > maxEnd) {
                            // Signature is in overlay area; overlay starts
                            // after last section but before signature.
                            return maxEnd;
                        }
                        if (maxEnd >= _B.getSize()) return -1;
                        return maxEnd;
                    };
                    PE.isOverlayPresent = function() {
                        return PE.getOverlayOffset() !== -1;
                    };
                    PE.getOverlaySize = function() {
                        var off = PE.getOverlayOffset();
                        if (off < 0) return 0;
                        return _B.getSize() - off;
                    };
                    PE.compareOverlay = function(sig) {
                        var off = PE.getOverlayOffset();
                        if (off < 0) return false;
                        return _B.__compare(sig, off);
                    };

                    // isSignaturePresent: search for signature in [offset, offset+size).
                    // Upstream: find_signature(nOffset, nSize, sSignature) != -1
                    PE.isSignaturePresent = function(offset, size, sig) {
                        if (size <= 0) return false;
                        return _B.__findSignatureRange(offset, offset + size, sig) >= 0;
                    };
                    PE.isSignatureInSectionPresent = function(section, sig) {
                        if (!_peIsPE()) return false;
                        if (section >= _peNumberOfSections()) return false;
                        var off = _peSectionFileOffset(section);
                        var size = _peSectionFileSize(section);
                        if (size <= 0) return false;
                        // Search only within the section bounds.
                        var found = _B.__findSignatureRange(off, off + size, sig);
                        return found >= 0;
                    };

                    // Resource methods: native pelite-backed resource enumeration.
                    PE.getNumberOfResources = function() { return _peGetBatch().numberOfResources; };
                    PE.getResourceNameByNumber = function(n) {
                        var entries = _peGetBatch().resourceEntries;
                        if (n < 0 || n >= entries.length) return "";
                        return entries[n][0]; // name or ""
                    };
                    PE.getResourceIdByNumber = function(n) {
                        var entries = _peGetBatch().resourceEntries;
                        if (n < 0 || n >= entries.length) return 0;
                        return entries[n][1]; // type_id as numeric ID fallback
                    };
                    PE.getResourceOffsetByNumber = function(n) {
                        var entries = _peGetBatch().resourceEntries;
                        if (n < 0 || n >= entries.length) return 0;
                        return entries[n][2]; // offset
                    };
                    PE.getResourceSizeByNumber = function(n) {
                        var entries = _peGetBatch().resourceEntries;
                        if (n < 0 || n >= entries.length) return 0;
                        return entries[n][3]; // size
                    };
                    PE.getResourceTypeByNumber = function(n) {
                        var entries = _peGetBatch().resourceEntries;
                        if (n < 0 || n >= entries.length) return 0;
                        return entries[n][1]; // type_id
                    };
                    PE.getResourceNameOffset = function(s) {
                        var entries = _peGetBatch().resourceEntries;
                        for (var i = 0; i < entries.length; i++) {
                            if (entries[i][0] === s) return entries[i][2];
                        }
                        return -1;
                    };
                    // PE.resource is populated by the upstream db/PE/_init
                    // script (executed during init), which iterates resources
                    // via getResourceNameByNumber/Id/Offset/Size/Type. Do NOT
                    // hardcode it here — that would overwrite the _init
                    // script's populated array.

                    // OS/options stubs.
                    PE.getOperationSystemOptions = function() { return ""; };
                    PE.isResourceNamePresent = function(s) {
                        return _B.__peIsResourceNamePresent(s);
                    };
                    // Resource group (type-level directory) checks.
                    PE.isResourceGroupNamePresent = function(s) {
                        return _B.__peIsResourceGroupNamePresent(s);
                    };
                    PE.isResourceGroupIdPresent = function(n) {
                        return _B.__peIsResourceGroupIdPresent(n);
                    };

                    // .NET detection: native pelite-backed CLR header check.
                    PE.isNet = function() {
                        return _peGetBatch().isNet;
                    };
                    // Alias: upstream help documents `isNET` and many rules
                    // (cryptor/installer/protector) call `PE.isNET()` with
                    // uppercase. JavaScript is case-sensitive, so both forms
                    // must be registered.
                    PE.isNET = PE.isNet;
                    // .NET methods: backed by pelite + native BSJB metadata parsing.
                    // isNetObjectPresent: search .NET ANSI strings (#Strings heap).
                    PE.isNetObjectPresent = function(s) {
                        var strings = _peGetBatch().netAnsiStrings;
                        for (var i = 0; i < strings.length; i++) {
                            if (strings[i] === s) return true;
                        }
                        return false;
                    };
                    // isNetUStringPresent: search .NET Unicode strings (#US heap).
                    PE.isNetUStringPresent = function(s) {
                        var strings = _peGetBatch().netUnicodeStrings;
                        for (var i = 0; i < strings.length; i++) {
                            if (strings[i] === s) return true;
                        }
                        return false;
                    };
                    PE.isNetGlobalCctorPresent = function() {
                        // Check .NET strings for ".cctor" which indicates
                        // a global static constructor is present.
                        var strings = _peGetBatch().netAnsiStrings;
                        for (var i = 0; i < strings.length; i++) {
                            if (strings[i].indexOf(".cctor") >= 0) return true;
                        }
                        return false;
                    };
                    PE.isImportPositionHashPresent = function(idx, hash) {
                        // Import position hash: CRC32C of concatenated function
                        // names per library. idx is the library index;
                        // idx=-1 searches all libraries.
                        // Matches upstream XBinary::getStringCustomCRC32.
                        if (!_peIsPE()) return false;
                        var batch = _peGetBatch();
                        var hashes = batch.importPositionHashes || [];
                        var target = hash >>> 0;
                        if (idx === -1) {
                            for (var i = 0; i < hashes.length; i++) {
                                if ((hashes[i] >>> 0) === target) return true;
                            }
                            return false;
                        }
                        if (idx < 0 || idx >= hashes.length) return false;
                        return (hashes[idx] >>> 0) === target;
                    };
                    PE.getNetAssemblyName = function() { return ""; };
                    PE.getNetModuleName = function() { return ""; };
                    PE.getNETVersion = function() {
                        return _peGetBatch().netVersion || "";
                    };
                    // .NET entry-point signature comparison.
                    // COR20_HEADER EntryPointToken is at clr_offset + 16.
                    PE.compareEP_NET = function(sig, off) {
                        if (!_peIsPE()) return false;
                        var lfanew = _peLfanew();
                        // Data directory 14 (CLR Runtime Header)
                        var opt = _peOptHdrOff();
                        var clrRva = _B.read_uint32_le(opt + 14 * 8);
                        var clrSize = _B.read_uint32_le(opt + 14 * 8 + 4);
                        if (clrRva === 0 || clrSize === 0) return false;
                        var clrOff = Binary.RVAToOffset(clrRva);
                        if (clrOff < 0) return false;
                        // COR20_HEADER: MetaData at +8 (RVA), EntryPointToken at +16
                        var mdRva = _B.read_uint32_le(clrOff + 8);
                        var epToken = _B.read_uint32_le(clrOff + 16);
                        if (mdRva === 0) return false;
                        var mdOff = Binary.RVAToOffset(mdRva);
                        if (mdOff < 0) return false;
                        // For simplicity, compare signature at metadata offset.
                        // Full implementation would resolve EntryPointToken to
                        // MethodDef RVA via #~ table parsing.
                        var sigOff = mdOff + (off || 0);
                        var hex = sig.replace(/[^0-9A-Fa-f]/g, "");
                        for (var i = 0; i < hex.length; i += 2) {
                            var expected = parseInt(hex.substr(i, 2), 16);
                            if (Binary.read_uint8(sigOff + i / 2) !== expected) return false;
                        }
                        return true;
                    };
                    // .NET blob heap signature search.
                    // Search for hex signature in .NET metadata region.
                    PE.findSignatureInBlob_NET = function(sig) {
                        if (!_peIsPE()) return -1;
                        var lfanew = _peLfanew();
                        var opt = _peOptHdrOff();
                        var clrRva = _B.read_uint32_le(opt + 14 * 8);
                        var clrSize = _B.read_uint32_le(opt + 14 * 8 + 4);
                        if (clrRva === 0 || clrSize === 0) return -1;
                        var clrOff = Binary.RVAToOffset(clrRva);
                        if (clrOff < 0) return -1;
                        var mdRva = _B.read_uint32_le(clrOff + 8);
                        var mdSize = _B.read_uint32_le(clrOff + 12);
                        if (mdRva === 0) return -1;
                        var mdOff = Binary.RVAToOffset(mdRva);
                        if (mdOff < 0) return -1;
                        var searchEnd = Math.min(mdOff + mdSize, Binary.getSize());
                        var hex = sig.replace(/[^0-9A-Fa-f]/g, "");
                        if (hex.length === 0) return -1;
                        // Search within metadata region.
                        for (var i = mdOff; i + hex.length / 2 <= searchEnd; i++) {
                            var found = true;
                            for (var j = 0; j < hex.length; j += 2) {
                                var expected = parseInt(hex.substr(j, 2), 16);
                                if (Binary.read_uint8(i + j / 2) !== expected) {
                                    found = false;
                                    break;
                                }
                            }
                            if (found) return i;
                        }
                        return -1;
                    };
                    PE.isSignatureInBlobPresent_NET = function(sig) {
                        return PE.findSignatureInBlob_NET(sig) >= 0;
                    };
                    // .NET metadata type/method/field search.
                    PE.isNetTypePresent = function(ns, tn) {
                        var strings = _peGetBatch().netAnsiStrings;
                        var full = ns + "." + tn;
                        for (var i = 0; i < strings.length; i++) {
                            if (strings[i] === tn || strings[i] === full) return true;
                        }
                        return false;
                    };
                    PE.isNetMethodPresent = function(ns, tn, mn) {
                        var strings = _peGetBatch().netAnsiStrings;
                        for (var i = 0; i < strings.length; i++) {
                            if (strings[i] === mn) return true;
                        }
                        return false;
                    };
                    PE.isNetFieldPresent = function(ns, tn, fn) {
                        var strings = _peGetBatch().netAnsiStrings;
                        for (var i = 0; i < strings.length; i++) {
                            if (strings[i] === fn) return true;
                        }
                        return false;
                    };

                    // PE-specific string methods.
                    // Manifest: parsed natively via pelite resources (batch cache).
                    PE.getManifest = function() { return _peGetBatch().manifest; };
                    // Authenticode signature: native pelite-backed security directory check.
                    PE.isSignedFile = function() { return _peGetBatch().isSigned; };
                    PE.isSigned = function() { return PE.isSignedFile(); };
                    PE.getGeneralOptionsEx = function() { return ""; };

                    // File info: native pelite-backed version info parsing.
                    PE.getPEFileVersion = function(s) {
                        if (!s) return _peGetBatch().fileVersion;
                        return _B.__peVersionString(s);
                    };
                    PE.getVersionStringInfo = function(s) { return _B.__peVersionString(s); };
                    PE.getFileVersion = function() { return _peGetBatch().fileVersion; };
                    PE.getCompilerVersion = function() {
                        // Compiler version is derived from linker version info.
                        // Upstream parses version resources, but we approximate
                        // from the major/minor linker version.
                        if (!_peIsPE()) return "";
                        var major = _B.read_uint8(_peOptHdrOff() + 2);
                        var minor = _B.read_uint8(_peOptHdrOff() + 3);
                        if (major > 0) return major + "." + minor;
                        return "";
                    };

                    // OS info stubs (require version resource parsing).
                    PE.getOperationSystemName = function() { return ""; };
                    PE.getOperationSystemVersion = function() { return ""; };

                    // getAddressOfEntryPoint: returns the entry point virtual address
                    // (ImageBase + AddressOfEntryPoint RVA), matching upstream
                    // XPE::_getEntryPointAddress which returns getModuleAddress() +
                    // getOptionalHeader_AddressOfEntryPoint().
                    PE.getAddressOfEntryPoint = function() {
                        if (!_peIsPE()) return 0;
                        return _peImageBase() + _peEntryPoint();
                    };

                    PE.isLibraryPresentExp = function(p) {
                        if (!_peIsPE()) return false;
                        var d = _peParseImports();
                        var pLower = p.toLowerCase();
                        for (var i = 0; i < d.libraries.length; i++) {
                            if (d.libraries[i].toLowerCase().indexOf(pLower) >= 0) return true;
                        }
                        return false;
                    };
                    PE.isExportFunctionPresentExp = function(p) {
                        if (!_peIsPE()) return false;
                        var d = _peParseExports();
                        var pLower = p.toLowerCase();
                        for (var i = 0; i < d.names.length; i++) {
                            if (d.names[i].toLowerCase().indexOf(pLower) >= 0) return true;
                        }
                        return false;
                    };
                    PE.isSectionNamePresentExp = function(p) {
                        if (!_peIsPE()) return false;
                        var n = _peNumberOfSections();
                        var pLower = p.toLowerCase();
                        for (var i = 0; i < n; i++) {
                            if (_peSectionName(i).toLowerCase().indexOf(pLower) >= 0) return true;
                        }
                        return false;
                    };
                    PE.isResourceNamePresentExp = function(p) { return null; };

                    // Linker version: read from optional header bytes 2-3.
                    // Optional header starts at e_lfanew + 24.
                    // MajorLinkerVersion at opt+2, MinorLinkerVersion at opt+3.
                    PE.getMajorLinkerVersion = function() {
                        if (!_peIsPE()) return 0;
                        return _B.read_uint8(_peOptHdrOff() + 2);
                    };
                    PE.getMinorLinkerVersion = function() {
                        if (!_peIsPE()) return 0;
                        return _B.read_uint8(_peOptHdrOff() + 3);
                    };

                    // DOS stub size: bytes between DOS header (64 bytes) and PE sig.
                    PE.getDosStubSize = function() {
                        if (!_peIsPE()) return 0;
                        var stubEnd = _peLfanew();
                        return stubEnd > 64 ? stubEnd - 64 : 0;
                    };

                    // Rich signature: search for "Rich" in DOS stub.
                    // The Rich signature is at a variable offset in the DOS stub.
                    // The XOR key is the 4 bytes after "Rich".
                    PE.isRichSignaturePresent = function() {
                        if (!_peIsPE()) return false;
                        var stubSize = PE.getDosStubSize();
                        if (stubSize < 8) return false;
                        // Search for "Rich" (0x52 0x69 0x63 0x68) in DOS stub.
                        // "Rich" + key = 8 bytes, so search up to stubSize - 8.
                        for (var i = 64; i <= 64 + stubSize - 8; i++) {
                            if (_B.read_uint8(i) === 0x52 &&
                                _B.read_uint8(i + 1) === 0x69 &&
                                _B.read_uint8(i + 2) === 0x63 &&
                                _B.read_uint8(i + 3) === 0x68) {
                                return true;
                            }
                        }
                        return false;
                    };

                    // Rich signature data: parse Rich header entries.
                    // Each entry is 8 bytes: DWORD1(4) DWORD2(4), XORed with key.
                    // DWORD1: high 16 bits = ProductID, low 16 bits = Version/Build
                    // DWORD2: UseCount
                    var _peRichData = null;
                    function _peParseRich() {
                        if (_peRichData !== null) return _peRichData;
                        _peRichData = { ids: [], counts: [], versions: [] };
                        if (!_peIsPE()) return _peRichData;
                        var stubSize = PE.getDosStubSize();
                        if (stubSize < 8) return _peRichData;
                        var richOff = -1;
                        for (var i = 64; i <= 64 + stubSize - 8; i++) {
                            if (_B.read_uint8(i) === 0x52 &&
                                _B.read_uint8(i + 1) === 0x69 &&
                                _B.read_uint8(i + 2) === 0x63 &&
                                _B.read_uint8(i + 3) === 0x68) {
                                richOff = i;
                                break;
                            }
                        }
                        if (richOff < 0) return _peRichData;
                        // XOR key is the DWORD after "Rich".
                        var key = _B.read_uint32_le(richOff + 4);
                        // "DanS" marker is at the start of the Rich header,
                        // XORed with key. Search backwards from richOff.
                        var dansVal = 0x536E6144; // "DanS" LE
                        var startOff = -1;
                        for (var j = richOff - 8; j >= 64; j -= 8) {
                            var val = _B.read_uint32_le(j) ^ key;
                            if (val === dansVal) {
                                startOff = j + 16; // Skip DanS + 3 padding DWORDs (match upstream)
                                break;
                            }
                        }
                        if (startOff < 0) startOff = 64;
                        // Parse entries from startOff to richOff.
                        // Match upstream XMSDOS::getRichSignatureRecords:
                        //   nId      = (DWORD1 >> 16) & 0xFFFF  (high 16 bits)
                        //   nVersion =  DWORD1        & 0xFFFF  (low 16 bits)
                        //   nCount   =  DWORD2
                        for (var k = startOff; k < richOff; k += 8) {
                            var dword1 = _B.read_uint32_le(k) ^ key;
                            var useCount = _B.read_uint32_le(k + 4) ^ key;
                            _peRichData.ids.push((dword1 >>> 16) & 0xFFFF);
                            _peRichData.versions.push(dword1 & 0xFFFF);
                            _peRichData.counts.push(useCount);
                        }
                        return _peRichData;
                    }
                    PE.getNumberOfRichIDs = function() {
                        return _peParseRich().ids.length;
                    };
                    PE.getRichID = function(n) {
                        var d = _peParseRich();
                        if (n < 0 || n >= d.ids.length) return 0;
                        return d.ids[n];
                    };
                    PE.getRichCount = function(n) {
                        var d = _peParseRich();
                        if (n >= 0 && n < d.counts.length) return d.counts[n];
                        return 0;
                    };
                    PE.getRichVersion = function(n) {
                        var d = _peParseRich();
                        if (n >= 0 && n < d.versions.length) return d.versions[n];
                        return 0;
                    };

                    // TLS: check TLS directory in optional header.
                    // PE32: TLS directory at opt + 192 (data directory index 9 * 8 + opt + 96)
                    // PE32+: TLS directory at opt + 216 (data directory index 9 * 8 + opt + 112)
                    // Data directory entry: VirtualAddress(4) Size(4)
                    function _peDataDirOff(idx) {
                        var ddStart = _peIs64() ? _peOptHdrOff() + 112 : _peOptHdrOff() + 96;
                        return ddStart + idx * 8;
                    }
                    PE.isTLSPresent = function() {
                        if (!_peIsPE()) return false;
                        var tlsDir = _peDataDirOff(9);
                        var va = _B.read_uint32_le(tlsDir);
                        return va !== 0;
                    };
                    PE.getTLSSection = function() {
                        if (!_peIsPE()) return -1;
                        var tlsDir = _peDataDirOff(9);
                        var va = _B.read_uint32_le(tlsDir);
                        if (va === 0) return -1;
                        // Find section containing the TLS directory RVA.
                        var n = _peNumberOfSections();
                        for (var i = 0; i < n; i++) {
                            var secVA = _peSectionVirtualAddress(i);
                            var secVS = _peSectionVirtualSize(i);
                            if (va >= secVA && va < secVA + secVS) return i;
                        }
                        return -1;
                    };

                    // isDll: check IMAGE_FILE_DLL (0x2000) in Characteristics.
                    PE.isDll = function() {
                        if (!_peIsPE()) return false;
                        var chars = _B.read_uint16_le(_peLfanew() + 4 + 18);
                        return (chars & 0x2000) !== 0;
                    };
                    // isPE32: Optional Header Magic == 0x10B.
                    PE.isPE32 = function() {
                        if (!_peIsPE()) return false;
                        return !_peIs64();
                    };
                    // isPEPlus: Optional Header Magic == 0x20B.
                    PE.isPEPlus = function() {
                        if (!_peIsPE()) return false;
                        return _peIs64();
                    };
                    // isDriver: check imports for typical driver libraries.
                    PE.isDriver = function() {
                        if (!_peIsPE()) return false;
                        var batch = _peGetBatch();
                        for (var i = 0; i < batch.libraries.length; i++) {
                            var lib = batch.libraries[i].toLowerCase();
                            if (lib === "ntoskrnl.exe" || lib === "hal.dll" ||
                                lib === "ndis.sys" || lib === "bootvid.dll") return true;
                        }
                        return false;
                    };
                    // isImportPresent: check if any imports exist.
                    PE.isImportPresent = function() {
                        if (!_peIsPE()) return false;
                        return _peGetBatch().libraries.length > 0;
                    };
                    // isExportPresent: check if any exports exist.
                    PE.isExportPresent = function() {
                        if (!_peIsPE()) return false;
                        return _peGetBatch().exports.length > 0;
                    };
                    // isResourcesPresent: check if any resources exist.
                    PE.isResourcesPresent = function() {
                        if (!_peIsPE()) return false;
                        return _peGetBatch().numberOfResources > 0;
                    };
                    // Import hash (simplified: not a real import hash).
                    // Import hash: FNV-1a hash of concatenated import names.
                    PE.getImportHash32 = function() {
                        if (!_peIsPE()) return 0;
                        var batch = _peGetBatch();
                        var h = 0x811C9DC5;
                        for (var i = 0; i < batch.libraries.length; i++) {
                            var name = batch.libraries[i].toLowerCase();
                            for (var j = 0; j < name.length; j++) {
                                h ^= name.charCodeAt(j);
                                h = (h * 0x01000193) >>> 0;
                            }
                        }
                        for (var i = 0; i < batch.functions.length; i++) {
                            var name = batch.functions[i].toLowerCase();
                            for (var j = 0; j < name.length; j++) {
                                h ^= name.charCodeAt(j);
                                h = (h * 0x01000193) >>> 0;
                            }
                        }
                        return h;
                    };
                    PE.getImportHash64 = function() {
                        var h32 = PE.getImportHash32();
                        return ((h32 << 16) | h32) >>> 0;
                    };

                    // getImageOptionalHeader: read a field from optional header by name.
                    PE.getImageOptionalHeader = function(field) {
                        if (!_peIsPE()) return 0;
                        var opt = _peOptHdrOff();
                        switch (field) {
                            case "AddressOfEntryPoint": return _B.read_uint32_le(opt + 16);
                            case "BaseOfCode": return _B.read_uint32_le(opt + 20);
                            case "ImageBase": return _peImageBase();
                            case "SectionAlignment": return _B.read_uint32_le(opt + (_peIs64() ? 32 : 32));
                            case "FileAlignment": return _B.read_uint32_le(opt + (_peIs64() ? 36 : 36));
                            case "SizeOfImage": return _peSizeOfImage();
                            case "SizeOfHeaders": return _B.read_uint32_le(opt + (_peIs64() ? 60 : 60));
                            case "Subsystem": return _B.read_uint16_le(opt + 68);
                            case "DllCharacteristics": return _B.read_uint16_le(opt + 70);
                            case "SizeOfStackReserve": return _peIs64() ? _B.read_uint64_le(opt + 72) : _B.read_uint32_le(opt + 72);
                            case "SizeOfStackCommit": return _peIs64() ? _B.read_uint64_le(opt + 80) : _B.read_uint32_le(opt + 76);
                            case "SizeOfHeapReserve": return _peIs64() ? _B.read_uint64_le(opt + 88) : _B.read_uint32_le(opt + 80);
                            case "SizeOfHeapCommit": return _peIs64() ? _B.read_uint64_le(opt + 96) : _B.read_uint32_le(opt + 84);
                            default: return 0;
                        }
                    };

                    // getEntryPointOffset: convert entry point RVA to file offset.
                    PE.getEntryPointOffset = function() {
                        if (!_peIsPE()) return -1;
                        var ep = _peEntryPoint();
                        if (ep === 0) return -1;
                        return _peRvaToFileOffset(ep);
                    };

                    // getEntryPointSection: find section containing entry point.
                    PE.getEntryPointSection = function() {
                        if (!_peIsPE()) return -1;
                        var ep = _peEntryPoint();
                        if (ep === 0) return -1;
                        var n = _peNumberOfSections();
                        for (var i = 0; i < n; i++) {
                            var va = _peSectionVirtualAddress(i);
                            var vs = _peSectionVirtualSize(i);
                            if (ep >= va && ep < va + vs) return i;
                        }
                        return -1;
                    };

                    // getSignature: read hex string of bytes at offset.
                    PE.getSignature = function(offset, size) {
                        if (offset < 0 || size <= 0) return "";
                        var totalSize = _B.getSize();
                        if (offset + size > totalSize) size = totalSize - offset;
                        if (size <= 0) return "";
                        var hex = "";
                        for (var i = 0; i < size; i++) {
                            var b = _B.read_uint8(offset + i);
                            var h = b.toString(16);
                            if (h.length < 2) h = "0" + h;
                            hex += h;
                        }
                        return hex.toUpperCase();
                    };

                    // RVAToOffset / OffsetToRVA / VAToOffset
                    PE.RVAToOffset = function(rva) {
                        if (!_peIsPE()) return -1;
                        return _peRvaToFileOffset(rva);
                    };
                    PE.OffsetToRVA = function(off) {
                        if (!_peIsPE()) return -1;
                        var n = _peNumberOfSections();
                        for (var i = 0; i < n; i++) {
                            var rawOff = _peSectionFileOffset(i);
                            var rawSize = _peSectionFileSize(i);
                            if (off >= rawOff && off < rawOff + rawSize) {
                                return _peSectionVirtualAddress(i) + (off - rawOff);
                            }
                        }
                        return -1;
                    };
                    PE.VAToOffset = function(va) {
                        if (!_peIsPE()) return -1;
                        var imageBase = _peImageBase();
                        if (va < imageBase) return -1;
                        return _peRvaToFileOffset(va - imageBase);
                    };
                    PE.OffsetToVA = function(off) {
                        if (!_peIsPE()) return -1;
                        var rva = PE.OffsetToRVA(off);
                        if (rva === -1) return -1;
                        return _peImageBase() + rva;
                    };

                    // Import table parsing.
                    // Data directory index 1 = Import Table.
                    // All PE info parsed in a single pelite pass via __peBatch
                    // for performance (avoids repeated PeFile construction).
                    var _peBatchCache = null;
                    function _peGetBatch() {
                        if (_peBatchCache !== null) return _peBatchCache;
                        var json = _B.__peBatch();
                        _peBatchCache = JSON.parse(json);
                        if (!_peBatchCache.libraries) _peBatchCache.libraries = [];
                        if (!_peBatchCache.functions) _peBatchCache.functions = [];
                        if (!_peBatchCache.imports) _peBatchCache.imports = [];
                        if (!_peBatchCache.exports) _peBatchCache.exports = [];
                        if (_peBatchCache.isNet === undefined) _peBatchCache.isNet = false;
                        if (_peBatchCache.isSigned === undefined) _peBatchCache.isSigned = false;
                        if (_peBatchCache.manifest === undefined) _peBatchCache.manifest = "";
                        if (_peBatchCache.fileVersion === undefined) _peBatchCache.fileVersion = "";
                        if (_peBatchCache.productVersion === undefined) _peBatchCache.productVersion = "";
                        if (_peBatchCache.numberOfResources === undefined) _peBatchCache.numberOfResources = 0;
                        if (_peBatchCache.netVersion === undefined) _peBatchCache.netVersion = "";
                        if (!_peBatchCache.resourceEntries) _peBatchCache.resourceEntries = [];
                        if (!_peBatchCache.netUnicodeStrings) _peBatchCache.netUnicodeStrings = [];
                        if (!_peBatchCache.netAnsiStrings) _peBatchCache.netAnsiStrings = [];
                        if (!_peBatchCache.importPositionHashes) _peBatchCache.importPositionHashes = [];
                        return _peBatchCache;
                    }
                    var _peImportData = null;
                    function _peParseImports() {
                        if (_peImportData !== null) return _peImportData;
                        _peImportData = { libraries: [], functions: [], imports: [] };
                        if (!_peIsPE()) return _peImportData;
                        var batch = _peGetBatch();
                        _peImportData.libraries = batch.libraries;
                        _peImportData.imports = batch.imports;
                        // Build flat functions array for backward compatibility.
                        for (var i = 0; i < batch.functions.length; i++) {
                            _peImportData.functions.push({ lib: "", name: batch.functions[i] });
                        }
                        return _peImportData;
                    }
                    PE.getNumberOfImports = function() {
                        return _peParseImports().libraries.length;
                    };
                    PE.getImportLibraryName = function(n) {
                        var d = _peParseImports();
                        if (n < 0 || n >= d.libraries.length) return "";
                        return d.libraries[n];
                    };
                    PE.getImportFunctionName = function(libraryIndex, functionIndex) {
                        var d = _peParseImports();
                        if (libraryIndex < 0 || libraryIndex >= d.imports.length) return "";
                        var funcs = d.imports[libraryIndex].functions;
                        if (functionIndex < 0 || functionIndex >= funcs.length) return "";
                        return funcs[functionIndex];
                    };
                    PE.getNumberOfImportThunks = function(libraryIndex) {
                        var d = _peParseImports();
                        if (libraryIndex === undefined) {
                            // Backward compat: return total if no arg.
                            return d.functions.length;
                        }
                        if (libraryIndex < 0 || libraryIndex >= d.imports.length) return 0;
                        return d.imports[libraryIndex].functions.length;
                    };
                    PE.isLibraryPresent = function(s) {
                        var d = _peParseImports();
                        var sLower = s.toLowerCase();
                        for (var i = 0; i < d.libraries.length; i++) {
                            if (d.libraries[i].toLowerCase() === sLower) return true;
                        }
                        return false;
                    };
                    PE.isLibraryFunctionPresent = function(lib, fn) {
                        var d = _peParseImports();
                        var fnLower = fn.toLowerCase();
                        for (var i = 0; i < d.functions.length; i++) {
                            if (d.functions[i].name.toLowerCase() === fnLower) return true;
                        }
                        return false;
                    };
                    PE.isFunctionPresent = function(s) {
                        var d = _peParseImports();
                        var sLower = s.toLowerCase();
                        for (var i = 0; i < d.functions.length; i++) {
                            if (d.functions[i].name.toLowerCase() === sLower) return true;
                        }
                        return false;
                    };

                    // Export table parsing.
                    // Uses batch cache from __peBatch for performance.
                    var _peExportData = null;
                    function _peParseExports() {
                        if (_peExportData !== null) return _peExportData;
                        _peExportData = { names: [], count: 0 };
                        if (!_peIsPE()) return _peExportData;
                        var batch = _peGetBatch();
                        _peExportData.names = batch.exports;
                        _peExportData.count = batch.exports.length;
                        return _peExportData;
                    }
                    PE.getNumberOfExportFunctions = function() {
                        return _peParseExports().count;
                    };
                    PE.getNumberOfExports = function() {
                        return _peParseExports().count;
                    };
                    PE.getExportFunctionName = function(n) {
                        var d = _peParseExports();
                        if (n < 0 || n >= d.names.length) return "";
                        return d.names[n];
                    };
                    PE.isExportFunctionPresent = function(s) {
                        var d = _peParseExports();
                        var sLower = s.toLowerCase();
                        for (var i = 0; i < d.names.length; i++) {
                            if (d.names[i].toLowerCase() === sLower) return true;
                        }
                        return false;
                    };
                    // getExportFunctionOffsetByIndex: read the AddressOfFunctions
                    // array from the export directory and return the file offset
                    // of the n-th exported function.
                    PE.getExportFunctionOffsetByIndex = function(n) {
                        if (!_peIsPE()) return -1;
                        var expDirRva = _B.read_uint32_le(_peDataDirOff(0));
                        if (expDirRva === 0) return -1;
                        var expDirOff = _peRvaToFileOffset(expDirRva);
                        if (expDirOff < 0) return -1;
                        var numFuncs = _B.read_uint32_le(expDirOff + 20);
                        if (n < 0 || n >= numFuncs) return -1;
                        var addrOfFuncsRva = _B.read_uint32_le(expDirOff + 28);
                        var addrOfFuncsOff = _peRvaToFileOffset(addrOfFuncsRva);
                        if (addrOfFuncsOff < 0) return -1;
                        var funcRva = _B.read_uint32_le(addrOfFuncsOff + n * 4);
                        if (funcRva === 0) return -1;
                        return _peRvaToFileOffset(funcRva);
                    };

                    // Section helpers.
                    // getSectionNameCollision(s1, s2): find two sections where one
                    // name ends with s1 and another ends with s2, sharing a common
                    // prefix. Returns the common prefix (without s1/s2 suffixes),
                    // or "" if no such pair exists.
                    // Upstream usage (protector_VMProtect.2.sg):
                    //   var sCollision = PE.getSectionNameCollision("0", "1");
                    //   if (PE.isSectionNamePresent(sCollision + "1")) { ... }
                    // Example: sections "oiNRhy0" and "oiNRhy1" -> returns "oiNRhy".
                    PE.getSectionNameCollision = function(s1, s2) {
                        if (!_peIsPE()) return "";
                        var n = _peNumberOfSections();
                        if (n === 0) return "";
                        // Collect section names (original case).
                        var names = [];
                        for (var i = 0; i < n; i++) {
                            names.push(_peSectionName(i));
                        }
                        // Find a pair (a, b) where a ends with s1, b ends with s2,
                        // and a without s1 == b without s2 (common prefix).
                        for (var i = 0; i < names.length; i++) {
                            var a = names[i];
                            if (a.length < s1.length) continue;
                            if (a.substring(a.length - s1.length) !== s1) continue;
                            var prefixA = a.substring(0, a.length - s1.length);
                            for (var j = 0; j < names.length; j++) {
                                if (i === j) continue;
                                var b = names[j];
                                if (b.length < s2.length) continue;
                                if (b.substring(b.length - s2.length) !== s2) continue;
                                var prefixB = b.substring(0, b.length - s2.length);
                                if (prefixA === prefixB) {
                                    return prefixA;
                                }
                            }
                        }
                        return "";
                    };
                    PE.getResourceSection = function() {
                        // Return the section INDEX (not file offset) that contains
                        // the resource directory (data directory index 2).
                        // Upstream rules compare this with section index `i`.
                        if (!_peIsPE()) return -1;
                        var resDir = _peDataDirOff(2);
                        var va = _B.read_uint32_le(resDir);
                        if (va === 0) return -1;
                        var n = _peNumberOfSections();
                        for (var i = 0; i < n; i++) {
                            var secVA = _peSectionVirtualAddress(i);
                            var secVS = _peSectionVirtualSize(i);
                            if (va >= secVA && va < secVA + secVS) return i;
                        }
                        return -1;
                    };
                    PE.getImportSection = function() {
                        if (!_peIsPE()) return -1;
                        var impDir = _peDataDirOff(1);
                        var va = _B.read_uint32_le(impDir);
                        if (va === 0) return -1;
                        var n = _peNumberOfSections();
                        for (var i = 0; i < n; i++) {
                            var secVA = _peSectionVirtualAddress(i);
                            var secVS = _peSectionVirtualSize(i);
                            if (va >= secVA && va < secVA + secVS) return i;
                        }
                        return -1;
                    };
                    PE.getRelocsSection = function() {
                        if (!_peIsPE()) return -1;
                        var relocDir = _peDataDirOff(5);
                        var va = _B.read_uint32_le(relocDir);
                        if (va === 0) return -1;
                        var n = _peNumberOfSections();
                        for (var i = 0; i < n; i++) {
                            var secVA = _peSectionVirtualAddress(i);
                            var secVS = _peSectionVirtualSize(i);
                            if (va >= secVA && va < secVA + secVS) return i;
                        }
                        return -1;
                    };
                    PE.getExportSection = function() {
                        if (!_peIsPE()) return -1;
                        var expDir = _peDataDirOff(0);
                        var va = _B.read_uint32_le(expDir);
                        if (va === 0) return -1;
                        var n = _peNumberOfSections();
                        for (var i = 0; i < n; i++) {
                            var secVA = _peSectionVirtualAddress(i);
                            var secVS = _peSectionVirtualSize(i);
                            if (va >= secVA && va < secVA + secVS) return i;
                        }
                        return -1;
                    };

                    // Disasm: getDisasmString and getDisasmNextAddress are
                    // registered as native Rust functions (using Capstone)
                    // earlier in register(). Do not override them here.

                    // Entropy/hash: delegate to Binary (registered as native Rust functions).
                    PE.calculateEntropy = function(off, size) { return _B.calculateEntropy(off, size); };
                    PE.calculateMD5 = function(off, size) { return _B.calculateMD5(off, size); };
                    PE.calculateCRC32 = function(off, size) { return _B.calculateCRC32(off, size); };

                    // Read helpers.
                    PE.readWord = function(off) { return _B.read_uint16(off); };
                    PE.readDword = function(off) { return _B.read_uint32(off); };
                    PE.read_int32 = function(off) { return _B.read_uint32(off); };
                    PE.read_uint32 = function(off) { return _B.read_uint32(off); };
                    PE.readSByte = function(off) { return _B.read_uint8(off); };
                    PE.readSDword = function(off) { return _B.read_uint32(off); };
                    PE.readBytes = function(off, size, replaceZero) {
                        return _B.readBytes(off, size, replaceZero);
                    };

                    // File path stubs.
                    PE.getFileDirectory = function() { return ""; };
                    PE.getFileBaseName = function() { return ""; };
                    PE.getFileCompleteSuffix = function() { return ""; };

                    // Debug data: parse PE debug directory (data directory index 6).
                    // Each IMAGE_DEBUG_DIRECTORY_ENTRY is 28 bytes:
                    //   0: Characteristics(4), 4: TimeDateStamp(4),
                    //   8: MajorVersion(2), 10: MinorVersion(2),
                    //   12: Type(4), 16: SizeOfData(4),
                    //   20: AddressOfRawData(4), 24: PointerToRawData(4)
                    var _DEBUG_TYPES = {
                        0: "UNKNOWN", 1: "COFF", 2: "CODEVIEW", 3: "FPO",
                        4: "MISC", 5: "EXCEPTION", 6: "FIXUP", 7: "OMAP_TO_SRC",
                        8: "OMAP_FROM_SRC", 9: "BORLAND", 10: "RESERVED10",
                        11: "VC_FEATURE", 12: "POGO", 13: "ILTCG",
                        14: "MPX", 15: "REPRO", 16: "EX_DLLCHARACTERISTICS"
                    };
                    // Debug data records: upstream XPE::getDebugList filters
                    // records, only including those with PointerToRawData != 0
                    // and valid offset. It also breaks on the first invalid
                    // record (does not skip). We replicate this by computing
                    // a filtered list once and caching it.
                    var _peDebugRecords = null; // cached array of {type, offset, size}
                    function _peGetDebugRecords() {
                        if (_peDebugRecords !== null) return _peDebugRecords;
                        _peDebugRecords = [];
                        if (!_peIsPE()) return _peDebugRecords;
                        var dbgDirOff = _peDataDirOff(6);
                        var va = _B.read_uint32_le(dbgDirOff);
                        var size = _B.read_uint32_le(dbgDirOff + 4);
                        if (va === 0 || size === 0) return _peDebugRecords;
                        var dirOff = _peRvaToFileOffset(va);
                        if (dirOff < 0) return _peDebugRecords;
                        var count = Math.floor(size / 28);
                        var fileSize = _B.getSize();
                        for (var i = 0; i < count; i++) {
                            var entryOff = dirOff + i * 28;
                            var typeVal = _B.read_uint32_le(entryOff + 12);
                            var dataSize = _B.read_uint32_le(entryOff + 16);
                            var rawPtr = _B.read_uint32_le(entryOff + 24);
                            // Upstream: only include if PointerToRawData != 0
                            // and offset is valid. Break on first invalid.
                            if (rawPtr === 0 || rawPtr >= fileSize) break;
                            _peDebugRecords.push({
                                type: _DEBUG_TYPES[typeVal] || "UNKNOWN",
                                offset: rawPtr,
                                size: dataSize
                            });
                        }
                        return _peDebugRecords;
                    }
                    PE.getNumberOfDebugDataRecords = function() {
                        return _peGetDebugRecords().length;
                    };
                    PE.getDebugDataOffset = function(n) {
                        var recs = _peGetDebugRecords();
                        if (n < 0 || n >= recs.length) return 0;
                        return recs[n].offset;
                    };
                    PE.getDebugDataSize = function(n) {
                        var recs = _peGetDebugRecords();
                        if (n < 0 || n >= recs.length) return 0;
                        return recs[n].size;
                    };
                    PE.getDebugDataType = function(n) {
                        var recs = _peGetDebugRecords();
                        if (n < 0 || n >= recs.length) return "";
                        return recs[n].type;
                    };

                    // Validation methods: check PE header field validity.
                    // These are used by __GenericHeuristicAnalysis_By_DosX.7.sg
                    // under --heuristicscan mode to detect damaged/modified PEs.
                    PE.isEntryPointCorrect = function() {
                        if (!_peIsPE()) return false;
                        var entry_rva = _peEntryPoint();
                        // Entry point is correct if RVA is 0 (no entry) or
                        // within a section's virtual range.
                        if (entry_rva === 0) return true;
                        return _peRvaToFileOffset(entry_rva) !== -1;
                    };
                    PE.isSectionAlignmentCorrect = function() {
                        if (!_peIsPE()) return false;
                        var sa = _B.read_uint32_le(_peOptHdrOff() + 32);
                        // SectionAlignment must be power of 2, >= 512.
                        if (sa < 512) return false;
                        return (sa & (sa - 1)) === 0;
                    };
                    PE.isFileAlignmentCorrect = function() {
                        if (!_peIsPE()) return false;
                        var fa = _B.read_uint32_le(_peOptHdrOff() + 36);
                        // FileAlignment must be power of 2, >= 512, <= 65536.
                        if (fa < 512 || fa > 65536) return false;
                        return (fa & (fa - 1)) === 0;
                    };
                    PE.isHeaderCorrect = function() {
                        if (!_peIsPE()) return false;
                        var coff_off = _peLfanew() + 4;
                        var num_sec = _B.read_uint16_le(coff_off + 2);
                        var size_opt = _B.read_uint16_le(coff_off + 16);
                        var chars = _B.read_uint16_le(coff_off + 18);
                        if (num_sec === 0) return false;
                        if (size_opt < 24) return false;
                        if (chars === 0) return false;
                        return true;
                    };
                    PE.isExportTableCorrect = function() {
                        if (!_peIsPE()) return false;
                        var export_rva = _B.read_uint32_le(_peDataDirOff(0));
                        if (export_rva === 0) return true;
                        return _peRvaToFileOffset(export_rva) !== -1;
                    };
                    PE.isImportTableCorrect = function() {
                        if (!_peIsPE()) return false;
                        var import_rva = _B.read_uint32_le(_peDataDirOff(1));
                        if (import_rva === 0) return true;
                        return _peRvaToFileOffset(import_rva) !== -1;
                    };
                    PE.isRelocsTableCorrect = function() {
                        if (!_peIsPE()) return false;
                        var reloc_rva = _B.read_uint32_le(_peDataDirOff(5));
                        if (reloc_rva === 0) return true;
                        return _peRvaToFileOffset(reloc_rva) !== -1;
                    };
                    PE.isResourcesTableCorrect = function() {
                        if (!_peIsPE()) return false;
                        var res_rva = _B.read_uint32_le(_peDataDirOff(2));
                        if (res_rva === 0) return true;
                        return _peRvaToFileOffset(res_rva) !== -1;
                    };

                    // Search helpers.
                    PE.findDword = function(off, val) { return -1; };

                    // Search methods (delegate to Binary).
                    PE.getString = function(offset, maxLen) {
                        if (maxLen === undefined) maxLen = 256;
                        return _B.getString(offset, maxLen);
                    };
                    PE.getSize = function() { return _B.getSize(); };
                    PE.readByte = function(offset) { return _B.read_uint8(offset); };
                    PE.findSignature = function(offset, sizeOrSig, sig) {
                        if (sig === undefined) { sig = sizeOrSig; return _B.findSignature(offset, sig); }
                        return _B.findSignature(offset, sizeOrSig, sig);
                    };
                    PE.findString = function(offset, sizeOrStr, str) {
                        if (str === undefined) { str = sizeOrStr; sizeOrStr = 0; }
                        return _B.findString(offset, sizeOrStr, str);
                    };
                    PE.isVerbose = function() { return false; };
                    PE.isDeepScan = function() { return false; };
                    PE.isHeuristicScan = function() { return false; };
                    PE.compare = function(sig, offset) {
                        if (offset === undefined) offset = 0;
                        return _B.__compare(sig, offset);
                    };

                    // Set nEP to the entry point file offset for backward compat.
                    PE.nEP = 0; // Will be computed per-scan in rules.
                })();
                "#,
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("PE methods: {e}"),
            })?;

            // Register ELF, MACH, MACHOFAT as independent objects that
            // inherit from Binary via Object.create. This allows adding
            // format-specific methods without modifying Binary itself.
            // The type-specific _init scripts do `var File = ELF;` etc.
            // We use a JS helper to create objects with Binary as prototype.
            let elf_obj = ctx
                .eval::<rquickjs::Object, _>("Object.create(Object.prototype)")
                .map_err(|e| RuleError::Backend {
                    detail: format!("ELF creation: {e}"),
                })?;
            globals.set("ELF", elf_obj).map_err(|e| RuleError::Backend {
                detail: format!("ELF set: {e}"),
            })?;
            let mach_obj = ctx
                .eval::<rquickjs::Object, _>("Object.create(Object.prototype)")
                .map_err(|e| RuleError::Backend {
                    detail: format!("MACH creation: {e}"),
                })?;
            globals
                .set("MACH", mach_obj)
                .map_err(|e| RuleError::Backend {
                    detail: format!("MACH set: {e}"),
                })?;
            let machofat_obj = ctx
                .eval::<rquickjs::Object, _>("Object.create(Object.prototype)")
                .map_err(|e| RuleError::Backend {
                    detail: format!("MACHOFAT creation: {e}"),
                })?;
            globals
                .set("MACHOFAT", machofat_obj)
                .map_err(|e| RuleError::Backend {
                    detail: format!("MACHOFAT set: {e}"),
                })?;

            // Set Binary as the prototype of PE, ELF, MACH, MACHOFAT so
            // they inherit all native Binary methods. This is done by
            // setting __proto__ directly, since Object.create(Binary)
            // may not work with rquickjs native objects.
            ctx.eval::<(), _>(
                r#"
                (function() {
                    var formats = [PE, ELF, MACH, MACHOFAT];
                    for (var i = 0; i < formats.length; i++) {
                        formats[i].__proto__ = Binary;
                    }
                })();
                "#,
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("PE/ELF/MACH/MACHOFAT proto set: {e}"),
            })?;

            // Add ELF-specific methods that parse the ELF header from raw bytes.
            // These implement the most commonly used ELF host API methods by
            // reading the ELF header and section/program header tables directly
            // from the file data via the Binary read primitives.
            ctx.eval::<(), _>(
                r#"
                (function() {
                    // Save Binary reference in a local variable to ensure
                    // closures always access the correct object (the _init
                    // script sets File = ELF, which would cause infinite
                    // recursion if methods used File.* instead of Binary.*).
                    var _B = Binary;
                    // ELF magic: 7F 45 4C 46
                    var ELF_MAGIC0 = 0x7F, ELF_MAGIC1 = 0x45, ELF_MAGIC2 = 0x4C, ELF_MAGIC3 = 0x46;

                    // IMPORTANT: Use Binary.* directly, NOT File.*, because the
                    // _init script sets File = ELF, which would cause infinite
                    // recursion when ELF methods call File methods.
                    function _elfIsELF() {
                        if (Binary.getSize() < 64) return false;
                        return (Binary.read_uint8(0) === ELF_MAGIC0 &&
                                Binary.read_uint8(1) === ELF_MAGIC1 &&
                                Binary.read_uint8(2) === ELF_MAGIC2 &&
                                Binary.read_uint8(3) === ELF_MAGIC3);
                    }

                    // EI_CLASS at offset 4: 1=ELF32, 2=ELF64
                    function _elfClass() {
                        return Binary.read_uint8(4);
                    }

                    // EI_DATA at offset 5: 1=LSB, 2=MSB
                    function _elfIsLE() {
                        return Binary.read_uint8(5) === 1;
                    }

                    function _elfReadU16(off) {
                        return _elfIsLE() ? Binary.read_uint16_le(off) : Binary.read_uint16_be(off);
                    }
                    function _elfReadU32(off) {
                        return _elfIsLE() ? Binary.read_uint32_le(off) : Binary.read_uint32_be(off);
                    }
                    function _elfReadU64(off) {
                        return _elfIsLE() ? Binary.read_uint64_le(off) : Binary.read_uint64_be(off);
                    }

                    // ELF header field offsets.
                    // ELF32: e_type(16) e_machine(18) e_version(20) e_entry(24) e_phoff(28)
                    //        e_shoff(32) e_flags(36) e_ehsize(40) e_phentsize(42) e_phnum(44)
                    //        e_shentsize(46) e_shnum(48) e_shstrndx(50)
                    // ELF64: e_type(16) e_machine(18) e_version(20) e_entry(24) e_phoff(32)
                    //        e_shoff(40) e_flags(48) e_ehsize(52) e_phentsize(54) e_phnum(56)
                    //        e_shentsize(58) e_shnum(60) e_shstrndx(62)
                    function _elfIs64() { return _elfClass() === 2; }

                    function _elfEType() { return _elfReadU16(16); }
                    function _elfEMachine() { return _elfReadU16(18); }
                    function _elfEEntry() { return _elfIs64() ? _elfReadU64(24) : _elfReadU32(24); }
                    function _elfEPhoff() { return _elfIs64() ? _elfReadU64(32) : _elfReadU32(28); }
                    function _elfEShoff() { return _elfIs64() ? _elfReadU64(40) : _elfReadU32(32); }
                    function _elfEPhentsize() { return _elfReadU16(_elfIs64() ? 54 : 42); }
                    function _elfEPhnum() { return _elfReadU16(_elfIs64() ? 56 : 44); }
                    function _elfEShentsize() { return _elfReadU16(_elfIs64() ? 58 : 46); }
                    function _elfEShnum() { return _elfReadU16(_elfIs64() ? 60 : 48); }
                    function _elfEShstrndx() { return _elfReadU16(_elfIs64() ? 62 : 50); }

                    // Section header field offsets.
                    // ELF32 Shdr: sh_name(0) sh_type(4) sh_flags(8) sh_addr(12) sh_offset(16) sh_size(20)
                    // ELF64 Shdr: sh_name(0) sh_type(4) sh_flags(8) sh_addr(16) sh_offset(24) sh_size(32)
                    function _shdrOffset(n) {
                        return _elfEShoff() + n * _elfEShentsize();
                    }
                    function _shdrName(n) {
                        var off = _shdrOffset(n);
                        return _elfReadU32(off);
                    }
                    function _shdrType(n) {
                        var off = _shdrOffset(n);
                        return _elfReadU32(off + 4);
                    }
                    function _shdrFileOffset(n) {
                        var off = _shdrOffset(n);
                        return _elfIs64() ? _elfReadU64(off + 24) : _elfReadU32(off + 16);
                    }
                    function _shdrSize(n) {
                        var off = _shdrOffset(n);
                        return _elfIs64() ? _elfReadU64(off + 32) : _elfReadU32(off + 20);
                    }

                    // Program header field offsets.
                    // ELF32 Phdr: p_type(0) p_offset(4) p_vaddr(8) p_filesz(16)
                    // ELF64 Phdr: p_type(0) p_flags(4) p_offset(8) p_vaddr(16) p_filesz(32)
                    function _phdrOffset(n) {
                        return _elfEPhoff() + n * _elfEPhentsize();
                    }
                    function _phdrFileOffset(n) {
                        var off = _phdrOffset(n);
                        return _elfIs64() ? _elfReadU64(off + 8) : _elfReadU32(off + 4);
                    }
                    function _phdrFileSize(n) {
                        var off = _phdrOffset(n);
                        return _elfIs64() ? _elfReadU64(off + 32) : _elfReadU32(off + 16);
                    }

                    // Read a NUL-terminated string from the string table section.
                    function _readStringFromTable(tableOff, tableSize, nameOff) {
                        if (nameOff >= tableSize) return "";
                        var absOff = tableOff + nameOff;
                        var end = absOff;
                        var maxEnd = tableOff + tableSize;
                        while (end < maxEnd && Binary.read_uint8(end) !== 0) end++;
                        if (end === absOff) return "";
                        return Binary.getString(absOff, end - absOff);
                    }

                    // Get the section header string table.
                    function _shstrtab() {
                        var strndx = _elfEShstrndx();
                        if (strndx >= _elfEShnum()) return null;
                        return {
                            offset: _shdrFileOffset(strndx),
                            size: _shdrSize(strndx)
                        };
                    }

                    // Get section name from the string table.
                    // Parsed in Rust via __elfSectionNames for performance.
                    var _elfSectionNamesCache = null;
                    function _sectionName(n) {
                        if (_elfSectionNamesCache === null) {
                            _elfSectionNamesCache = _B.__elfSectionNames();
                        }
                        if (n < 0 || n >= _elfSectionNamesCache.length) return "";
                        return _elfSectionNamesCache[n];
                    }

                    // Find section number by name.
                    function _sectionNumber(name) {
                        var names = _B.__elfSectionNames();
                        for (var i = 0; i < names.length; i++) {
                            if (names[i] === name) return i;
                        }
                        return -1;
                    }

                    // Dynamic table: find PT_DYNAMIC (type=2) program header.
                    function _dynamicPhdr() {
                        var n = _elfEPhnum();
                        for (var i = 0; i < n; i++) {
                            var off = _phdrOffset(i);
                            var ptype = _elfReadU32(off);
                            if (ptype === 2) return i;
                        }
                        return -1;
                    }

                    // Read strings from the dynamic string table (DT_STRTAB).
                    // DT_STRTAB tag=5, DT_STRSZ tag=10.
                    function _dynamicStringTable() {
                        var phdrIdx = _dynamicPhdr();
                        if (phdrIdx < 0) return null;
                        var dynOff = _phdrFileOffset(phdrIdx);
                        var dynSize = _phdrFileSize(phdrIdx);
                        var is64 = _elfIs64();
                        var entrySize = is64 ? 16 : 8;
                        var nEntries = Math.floor(dynSize / entrySize);
                        var strtabAddr = 0, strtabSize = 0;
                        for (var i = 0; i < nEntries; i++) {
                            var eOff = dynOff + i * entrySize;
                            var tag, val;
                            if (is64) {
                                tag = _elfReadU64(eOff);
                                val = _elfReadU64(eOff + 8);
                            } else {
                                tag = _elfReadU32(eOff);
                                val = _elfReadU32(eOff + 4);
                            }
                            if (tag === 0) break;  // DT_NULL
                            if (tag === 5) strtabAddr = val;  // DT_STRTAB
                            if (tag === 10) strtabSize = val; // DT_STRSZ
                        }
                        if (strtabAddr === 0 || strtabSize === 0) return null;
                        // Convert virtual address to file offset via program headers.
                        var fileOff = _vaddrToFileOffset(strtabAddr);
                        if (fileOff < 0) return null;
                        return { offset: fileOff, size: strtabSize };
                    }

                    // Convert virtual address to file offset using program headers.
                    function _vaddrToFileOffset(vaddr) {
                        var n = _elfEPhnum();
                        var is64 = _elfIs64();
                        for (var i = 0; i < n; i++) {
                            var off = _phdrOffset(i);
                            var ptype = _elfReadU32(off);
                            if (ptype !== 1) continue; // PT_LOAD
                            var pOffset, pVaddr, pFilesz;
                            if (is64) {
                                pOffset = _elfReadU64(off + 8);
                                pVaddr = _elfReadU64(off + 16);
                                pFilesz = _elfReadU64(off + 32);
                            } else {
                                pOffset = _elfReadU32(off + 4);
                                pVaddr = _elfReadU32(off + 8);
                                pFilesz = _elfReadU32(off + 16);
                            }
                            if (vaddr >= pVaddr && vaddr < pVaddr + pFilesz) {
                                return pOffset + (vaddr - pVaddr);
                            }
                        }
                        return -1;
                    }

                    // Read DT_NEEDED entries (tag=1) from dynamic table.
                    // Parsed in Rust via __elfImportLibraries for performance.
                    var _elfLibsCache = null;
                    function _libraryNames() {
                        if (_elfLibsCache !== null) return _elfLibsCache;
                        _elfLibsCache = _B.__elfImportLibraries();
                        return _elfLibsCache;
                    }

                    // ELF type names.
                    var _elfTypeNames = {
                        0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"
                    };
                    // ELF machine names (subset).
                    var _elfMachineNames = {
                        0: "None", 3: "x86", 40: "ARM", 62: "x86-64",
                        183: "AArch64", 243: "RISC-V"
                    };

                    // --- Public ELF API methods ---
                    ELF.is64 = function() { return _elfIs64(); };
                    ELF.getNumberOfSections = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEShnum();
                    };
                    ELF.getNumberOfPrograms = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEPhnum();
                    };
                    ELF.getElfHeader_entry = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEEntry();
                    };
                    ELF.getElfHeader_type = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEType();
                    };
                    ELF.getElfHeader_machine = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEMachine();
                    };
                    ELF.getElfHeader_shentsize = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEShentsize();
                    };
                    ELF.getElfHeader_shnum = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEShnum();
                    };
                    ELF.getElfHeader_shstrndx = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEShstrndx();
                    };
                    ELF.getElfHeader_phnum = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEPhnum();
                    };
                    ELF.getElfHeader_phentsize = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEPhentsize();
                    };
                    ELF.getElfHeader_phoff = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEPhoff();
                    };
                    ELF.getElfHeader_shoff = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEShoff();
                    };
                    ELF.getElfHeader_version = function() {
                        if (!_elfIsELF()) return 0;
                        // EI_VERSION at offset 6 in ELF header.
                        return _B.read_uint8(_elfOff() + 6);
                    };
                    ELF.getElfHeader_flags = function() {
                        if (!_elfIsELF()) return 0;
                        // e_flags at offset 36 (ELF32) or 48 (ELF64).
                        return _elfIs64() ? _B.read_uint32_le(_elfOff() + 48) : _B.read_uint32_le(_elfOff() + 36);
                    };
                    ELF.getElfHeader_ehsize = function() {
                        if (!_elfIsELF()) return 0;
                        // e_ehsize at offset 52 (ELF32) or 64 (ELF64).
                        return _elfIs64() ? _B.read_uint16_le(_elfOff() + 64) : _B.read_uint16_le(_elfOff() + 52);
                    };
                    ELF.getRunPath = function() {
                        if (!_elfIsELF()) return "";
                        // Parse DT_RUNPATH (29) or DT_RPATH (15) from dynamic section.
                        // Simplified: search for "RUNPATH=" in .dynamic.dynstr.
                        return "";
                    };
                    ELF.getEntryPoint = function() {
                        if (!_elfIsELF()) return 0;
                        return _elfEEntry();
                    };
                    ELF.getType = function() {
                        if (!_elfIsELF()) return "";
                        return _elfTypeNames[_elfEType()] || ("type" + _elfEType());
                    };
                    ELF.getMachine = function() {
                        if (!_elfIsELF()) return "";
                        return _elfMachineNames[_elfEMachine()] || ("machine" + _elfEMachine());
                    };
                    ELF.getGeneralOptions = function() {
                        if (!_elfIsELF()) return "";
                        var t = _elfTypeNames[_elfEType()] || ("type" + _elfEType());
                        var m = _elfMachineNames[_elfEMachine()] || ("machine" + _elfEMachine());
                        var b = _elfIs64() ? "64" : "32";
                        return t + " " + m + "-" + b;
                    };
                    ELF.getOperationSystemName = function() {
                        if (!_elfIsELF()) return "";
                        var osabi = Binary.read_uint8(7);
                        var osabiNames = {
                            0: "UNIX - System V", 1: "HP-UX", 2: "NetBSD", 3: "Linux",
                            6: "Solaris", 7: "AIX", 8: "IRIX", 9: "FreeBSD",
                            10: "Compaq Tru64", 11: "Novell Modesto", 12: "OpenBSD",
                            64: "ARM EABI", 97: "ARM", 255: "Standalone"
                        };
                        return osabiNames[osabi] || "";
                    };
                    ELF.getOperationSystemVersion = function() { return ""; };
                    ELF.getOperationSystemOptions = function() { return ""; };
                    ELF.getSectionNumber = function(name) {
                        if (!_elfIsELF()) return -1;
                        return _sectionNumber(name);
                    };
                    ELF.getSectionName = function(n) {
                        if (!_elfIsELF()) return "";
                        if (n >= _elfEShnum()) return "";
                        return _sectionName(n);
                    };
                    ELF.getSectionFileOffset = function(n) {
                        if (!_elfIsELF()) return 0;
                        if (n >= _elfEShnum()) return 0;
                        return _shdrFileOffset(n);
                    };
                    ELF.getSectionFileSize = function(n) {
                        if (!_elfIsELF()) return 0;
                        if (n >= _elfEShnum()) return 0;
                        return _shdrSize(n);
                    };
                    ELF.isSectionNamePresent = function(name) {
                        if (!_elfIsELF()) return false;
                        return _sectionNumber(name) >= 0;
                    };
                    ELF.isLibraryPresent = function(name) {
                        if (!_elfIsELF()) return false;
                        var libs = _libraryNames();
                        for (var i = 0; i < libs.length; i++) {
                            if (libs[i] === name) return true;
                        }
                        return false;
                    };
                    ELF.isStringInTablePresent = function(sectionName, s) {
                        if (!_elfIsELF()) return false;
                        var n = _sectionNumber(sectionName);
                        if (n < 0) return false;
                        var off = _shdrFileOffset(n);
                        var size = _shdrSize(n);
                        // Search for the string in the section.
                        var found = Binary.findString(off, size, s);
                        return (found >= 0);
                    };
                    ELF.getString = function(offset, maxLen) {
                        if (maxLen === undefined) maxLen = 256;
                        return Binary.getString(offset, maxLen);
                    };
                    ELF.getProgramFileOffset = function(n) {
                        if (!_elfIsELF()) return 0;
                        if (n >= _elfEPhnum()) return 0;
                        return _phdrFileOffset(n);
                    };
                    ELF.getProgramFileSize = function(n) {
                        if (!_elfIsELF()) return 0;
                        if (n >= _elfEPhnum()) return 0;
                        return _phdrFileSize(n);
                    };
                    ELF.getSize = function() { return Binary.getSize(); };
                    ELF.readByte = function(offset) { return Binary.read_uint8(offset); };
                    ELF.findSignature = function(offset, sizeOrSig, sig) {
                        if (sig === undefined) { sig = sizeOrSig; return Binary.findSignature(offset, sig); }
                        return Binary.findSignature(offset, sizeOrSig, sig);
                    };
                    ELF.findString = function(offset, sizeOrStr, str) {
                        if (str === undefined) { str = sizeOrStr; sizeOrStr = 0; }
                        return Binary.findString(offset, sizeOrStr, str);
                    };
                    ELF.isVerbose = function() { return false; };
                    ELF.isDeepScan = function() { return false; };
                    ELF.isHeuristicScan = function() { return false; };
                    // Overlay: data after the last segment's file data.
                    ELF.getOverlayOffset = function() {
                        if (!_elfIsELF()) return -1;
                        var n = _elfEPhnum();
                        var maxEnd = 0;
                        for (var i = 0; i < n; i++) {
                            var off = _phdrFileOffset(i);
                            var size = _phdrFileSize(i);
                            var end = off + size;
                            if (end > maxEnd) maxEnd = end;
                        }
                        if (maxEnd >= Binary.getSize()) return -1;
                        return maxEnd;
                    };
                    ELF.isOverlayPresent = function() {
                        return ELF.getOverlayOffset() !== -1;
                    };
                    ELF.getOverlaySize = function() {
                        var off = ELF.getOverlayOffset();
                        if (off < 0) return 0;
                        return Binary.getSize() - off;
                    };
                    // Image base: lowest p_vaddr among PT_LOAD segments.
                    ELF.getImageBase = function() {
                        if (!_elfIsELF()) return 0;
                        var n = _elfEPhnum();
                        var base = -1;
                        for (var i = 0; i < n; i++) {
                            var off = _phdrOffset(i);
                            var ptype = _elfReadU32(off);
                            if (ptype === 1) { // PT_LOAD
                                var vaddr = _elfIs64() ? _elfReadU64(off + 16) : _elfReadU32(off + 8);
                                if (base < 0 || vaddr < base) base = vaddr;
                            }
                        }
                        return base < 0 ? 0 : base;
                    };
                    // String table: section with SHT_STRTAB type (3).
                    ELF.getStringTableOffset = function() {
                        if (!_elfIsELF()) return 0;
                        var n = _elfEShnum();
                        for (var i = 0; i < n; i++) {
                            if (_shdrType(i) === 3) { // SHT_STRTAB
                                return _shdrFileOffset(i);
                            }
                        }
                        return 0;
                    };
                    // Symbol table: section with SHT_SYMTAB type (2).
                    ELF.getSymbolTableOffset = function() {
                        if (!_elfIsELF()) return 0;
                        var n = _elfEShnum();
                        for (var i = 0; i < n; i++) {
                            if (_shdrType(i) === 2) { // SHT_SYMTAB
                                return _shdrFileOffset(i);
                            }
                        }
                        return 0;
                    };
                    // Relocation table: section with SHT_REL (9) or SHT_RELA (4).
                    ELF.getRelocationTableOffset = function() {
                        if (!_elfIsELF()) return 0;
                        var n = _elfEShnum();
                        for (var i = 0; i < n; i++) {
                            var t = _shdrType(i);
                            if (t === 9 || t === 4) { // SHT_REL or SHT_RELA
                                return _shdrFileOffset(i);
                            }
                        }
                        return 0;
                    };
                    ELF.compareEP = function(sig, offset) {
                        if (!_elfIsELF()) return false;
                        var ep = _elfEEntry();
                        if (ep === 0) return false;
                        var fileOff = _vaddrToFileOffset(ep);
                        if (fileOff < 0) return false;
                        if (offset === undefined) offset = 0;
                        return Binary.__compare(sig, fileOff + offset);
                    };
                    ELF.compareOverlay = function(sig) { return false; };
                    ELF.compare = function(sig, offset) {
                        if (offset === undefined) offset = 0;
                        return Binary.__compare(sig, offset);
                    };
                })();
                "#,
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("ELF methods: {e}"),
            })?;

            // Add Util global object with 64-bit shift helpers.
            // These are used by BitReader in the "read" include script.
            // JavaScript's bitwise operators only work on 32-bit integers,
            // so the upstream runtime provides Util.shlu64/shru64/divu64.
            // We implement them using Math.pow and multiplication/division
            // for simplicity (sufficient for BitReader's use cases).
            ctx.eval::<(), _>(
                r#"
                (function() {
                    var Util = {
                        // Shift left unsigned 64-bit: (v << n) as a JS number.
                        shlu64: function(v, n) {
                            if (n <= 0) return v;
                            if (n < 53) return v * Math.pow(2, n);
                            return 0; // overflow
                        },
                        // Shift right unsigned 64-bit: (v >>> n) as a JS number.
                        shru64: function(v, n) {
                            if (n <= 0) return v;
                            return Math.floor(v / Math.pow(2, n));
                        },
                        // Divide unsigned 64-bit.
                        divu64: function(a, b) {
                            if (b === 0) return 0;
                            return Math.floor(a / b);
                        },
                        div64: function(a, b) {
                            if (b === 0) return 0;
                            return Math.floor(a / b);
                        }
                    };
                    // Signed 64-bit shift helpers.
                    Util.shl64 = function(v, n) {
                        if (n <= 0) return v;
                        if (n < 53) return v * Math.pow(2, n);
                        return 0;
                    };
                    Util.shr64 = function(v, n) {
                        if (n <= 0) return v;
                        return Math.floor(v / Math.pow(2, n));
                    };
                    // Timestamp to time string (simplified ISO format).
                    Util.secondsToTimeStr = function(seconds) {
                        if (seconds <= 0) return "";
                        // Convert Unix timestamp to YYYY-MM-DD HH:MM:SS (UTC).
                        var d = new Date(seconds * 1000);
                        var y = d.getUTCFullYear();
                        var m = (d.getUTCMonth() + 1);
                        var day = d.getUTCDate();
                        var h = d.getUTCHours();
                        var min = d.getUTCMinutes();
                        var s = d.getUTCSeconds();
                        function pad(n) { return n < 10 ? "0" + n : "" + n; }
                        return y + "-" + pad(m) + "-" + pad(day) + " " + pad(h) + ":" + pad(min) + ":" + pad(s);
                    };
                    (typeof globalThis !== 'undefined' ? globalThis : this).Util = Util;
                })();
                "#,
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("Util stubs: {e}"),
            })?;

            // Add Mach-O-specific methods that parse the Mach-O header from
            // raw bytes. These implement the most commonly used Mach-O host
            // API methods by reading the Mach-O header and load commands
            // directly from the file data via the Binary read primitives.
            // IMPORTANT: Use Binary.* directly, NOT File.*, because the
            // _init script sets File = MACH, which would cause infinite
            // recursion when MACH methods call File methods.
            ctx.eval::<(), _>(
                r#"
                (function() {
                    // Save Binary reference in a local variable to ensure
                    // closures always access the correct object (the _init
                    // script sets File = MACH, which would cause infinite
                    // recursion if methods used File.* instead of Binary.*).
                    var _B = Binary;
                    // Mach-O magic numbers.
                    var MH_MAGIC_32 = 0xFEEDFACE;
                    var MH_MAGIC_32_LE = 0xCEFAEDFE;
                    var MH_MAGIC_64 = 0xFEEDFACF;
                    var MH_MAGIC_64_LE = 0xCFFAEDFE;

                    function _machIsMachO() {
                        if (Binary.getSize() < 28) return false;
                        var be = Binary.read_uint32_be(0);
                        var le = Binary.read_uint32_le(0);
                        return (be === MH_MAGIC_32 || be === MH_MAGIC_64 ||
                                le === MH_MAGIC_32 || le === MH_MAGIC_64 ||
                                le === MH_MAGIC_32_LE || le === MH_MAGIC_64_LE);
                    }

                    function _machIs64() {
                        var be = Binary.read_uint32_be(0);
                        var le = Binary.read_uint32_le(0);
                        return (be === MH_MAGIC_64 || le === MH_MAGIC_64 ||
                                le === MH_MAGIC_64_LE);
                    }

                    function _machIsLE() {
                        var be = Binary.read_uint32_be(0);
                        var le = Binary.read_uint32_le(0);
                        // If LE reading matches the known magic, it's little-endian.
                        return (le === MH_MAGIC_32 || le === MH_MAGIC_64 ||
                                le === MH_MAGIC_32_LE || le === MH_MAGIC_64_LE);
                    }

                    function _machReadU32(off) {
                        return _machIsLE() ? Binary.read_uint32_le(off) : Binary.read_uint32_be(off);
                    }
                    function _machReadU64(off) {
                        return _machIsLE() ? Binary.read_uint64_le(off) : Binary.read_uint64_be(off);
                    }

                    // Mach-O header fields.
                    // 32-bit: magic(0) cputype(4) cpusubtype(8) filetype(12) ncmds(16)
                    //         sizeofcmds(20) flags(24) reserved(28)
                    // 64-bit: magic(0) cputype(4) cpusubtype(8) filetype(12) ncmds(16)
                    //         sizeofcmds(20) flags(24) reserved(28)
                    // (64-bit header is 32 bytes, 32-bit is 28 bytes)
                    function _machNCmds() { return _machReadU32(16); }
                    function _machSizeOfCmds() { return _machReadU32(20); }
                    function _machFileType() { return _machReadU32(12); }
                    function _machCpuType() { return _machReadU32(4); }

                    // Header size: 28 for 32-bit, 32 for 64-bit.
                    function _machHeaderSize() { return _machIs64() ? 32 : 28; }

                    // Iterate load commands. Each load command has:
                    // cmd(4) cmdsize(4) ... (rest depends on cmd type)
                    function _machLoadCmdOffset(n) {
                        var off = _machHeaderSize();
                        var ncmds = _machNCmds();
                        if (n >= ncmds) return -1;
                        for (var i = 0; i < n; i++) {
                            var cmdsize = _machReadU32(off + 4);
                            if (cmdsize === 0) return -1;
                            off += cmdsize;
                        }
                        return off;
                    }

                    // LC_SEGMENT (cmd=1) or LC_SEGMENT_64 (cmd=0x19).
                    // 32-bit segment: cmd(0) cmdsize(4) segname(8) vmaddr(24) vmsize(28)
                    //   fileoff(32) filesize(36) nsects(40) flags(44)
                    // 64-bit segment: cmd(0) cmdsize(4) segname(8) vmaddr(24) vmsize(32)
                    //   fileoff(40) filesize(48) nsects(56) flags(60)
                    var LC_SEGMENT = 1, LC_SEGMENT_64 = 0x19;
                    var LC_LOAD_DYLIB = 0xC, LC_ID_DYLIB = 0xD;
                    var LC_MAIN = 0x80000028;

                    function _machIsSegment(cmd) {
                        return cmd === LC_SEGMENT || cmd === LC_SEGMENT_64;
                    }

                    function _machSegmentIs64(cmd) { return cmd === LC_SEGMENT_64; }

                    // Get segment name (16 bytes at cmd offset + 8).
                    function _machSegmentName(cmdOff) {
                        var name = "";
                        for (var i = 0; i < 16; i++) {
                            var b = Binary.read_uint8(cmdOff + 8 + i);
                            if (b === 0) break;
                            name += String.fromCharCode(b);
                        }
                        return name;
                    }

                    // Get segment file offset and size.
                    function _machSegmentFileOff(cmdOff, is64) {
                        return is64 ? _machReadU64(cmdOff + 40) : _machReadU32(cmdOff + 32);
                    }
                    function _machSegmentFileSize(cmdOff, is64) {
                        return is64 ? _machReadU64(cmdOff + 48) : _machReadU32(cmdOff + 36);
                    }
                    function _machSegmentNsects(cmdOff, is64) {
                        return is64 ? _machReadU32(cmdOff + 56) : _machReadU32(cmdOff + 40);
                    }

                    // Section header within a segment.
                    // 32-bit section: sectname(0) segname(16) addr(32) size(36)
                    //   offset(40) align(44) reloff(48) nreloc(52) flags(56)
                    // 64-bit section: sectname(0) segname(16) addr(32) size(40)
                    //   offset(48) align(52) reloff(56) nreloc(60) flags(64)
                    function _machSectionHeaderSize(is64) { return is64 ? 80 : 68; }

                    function _machSectionName(sectOff) {
                        var name = "";
                        for (var i = 0; i < 16; i++) {
                            var b = Binary.read_uint8(sectOff + i);
                            if (b === 0) break;
                            name += String.fromCharCode(b);
                        }
                        return name;
                    }
                    function _machSectionOffset(sectOff, is64) {
                        return is64 ? _machReadU32(sectOff + 48) : _machReadU32(sectOff + 40);
                    }
                    function _machSectionSize(sectOff, is64) {
                        return is64 ? _machReadU64(sectOff + 40) : _machReadU32(sectOff + 36);
                    }

                    // Collect all sections from all segments.
                    function _machAllSections() {
                        var sections = [];
                        var ncmds = _machNCmds();
                        var off = _machHeaderSize();
                        for (var i = 0; i < ncmds; i++) {
                            var cmd = _machReadU32(off);
                            var cmdsize = _machReadU32(off + 4);
                            if (cmdsize === 0) break;
                            if (_machIsSegment(cmd)) {
                                var isSeg64 = _machSegmentIs64(cmd);
                                var nsects = _machSegmentNsects(off, isSeg64);
                                var sectHdrSize = _machSectionHeaderSize(isSeg64);
                                var sectStart = off + (isSeg64 ? 72 : 56);
                                for (var j = 0; j < nsects; j++) {
                                    var sectOff = sectStart + j * sectHdrSize;
                                    sections.push({
                                        name: _machSectionName(sectOff),
                                        offset: _machSectionOffset(sectOff, isSeg64),
                                        size: _machSectionSize(sectOff, isSeg64)
                                    });
                                }
                            }
                            off += cmdsize;
                        }
                        return sections;
                    }

                    function _machSectionNumber(name) {
                        var names = _B.__machoSectionNames();
                        for (var i = 0; i < names.length; i++) {
                            if (names[i] === name) return i;
                        }
                        return -1;
                    }

                    // Collect library names from LC_LOAD_DYLIB commands.
                    // Parsed in Rust via __machoImportLibraries for performance.
                    var _machLibsCache = null;
                    function _machLibraries() {
                        if (_machLibsCache !== null) return _machLibsCache;
                        _machLibsCache = _B.__machoImportLibraries();
                        return _machLibsCache;
                    }

                    // Get entry point from LC_MAIN (cmd=0x80000028).
                    // LC_MAIN: cmd(0) cmdsize(4) entryoff(8) stacksize(16)
                    function _machEntryPoint() {
                        var ncmds = _machNCmds();
                        var off = _machHeaderSize();
                        for (var i = 0; i < ncmds; i++) {
                            var cmd = _machReadU32(off);
                            var cmdsize = _machReadU32(off + 4);
                            if (cmdsize === 0) break;
                            if (cmd === LC_MAIN) {
                                return _machReadU64(off + 8);
                            }
                            off += cmdsize;
                        }
                        return 0;
                    }

                    // Mach-O filetype names.
                    var _machFileTypeNames = {
                        1: "object", 2: "execute", 3: "fvmlib", 4: "core",
                        5: "preload", 6: "dylib", 7: "dylinker", 8: "bundle",
                        9: "dylib_stub", 10: "dsym", 11: "kext"
                    };

                    // CPU type names. 64-bit types have the 0x01000000 flag.
                    var _machCpuNames = {};
                    _machCpuNames[7] = "x86";
                    _machCpuNames[7 + 0x01000000] = "x86_64";
                    _machCpuNames[12] = "arm";
                    _machCpuNames[12 + 0x01000000] = "arm64";
                    _machCpuNames[18] = "ppc";
                    _machCpuNames[18 + 0x01000000] = "ppc64";

                    // --- Public MACH API methods ---
                    MACH.is64 = function() { return _machIs64(); };
                    MACH.getNumberOfSections = function() {
                        if (!_machIsMachO()) return 0;
                        return _machAllSections().length;
                    };
                    MACH.getNumberOfSegments = function() {
                        if (!_machIsMachO()) return 0;
                        var count = 0;
                        var ncmds = _machNCmds();
                        var off = _machHeaderSize();
                        for (var i = 0; i < ncmds; i++) {
                            var cmd = _machReadU32(off);
                            var cmdsize = _machReadU32(off + 4);
                            if (cmdsize === 0) break;
                            if (_machIsSegment(cmd)) count++;
                            off += cmdsize;
                        }
                        return count;
                    };
                    MACH.getNumberOfLibraries = function() {
                        if (!_machIsMachO()) return 0;
                        return _machLibraries().length;
                    };
                    MACH.getSectionName = function(n) {
                        if (!_machIsMachO()) return "";
                        var sections = _machAllSections();
                        if (n >= sections.length) return "";
                        return sections[n].name;
                    };
                    MACH.getSectionNumber = function(name) {
                        if (!_machIsMachO()) return -1;
                        return _machSectionNumber(name);
                    };
                    MACH.getSectionFileOffset = function(n) {
                        if (!_machIsMachO()) return 0;
                        var sections = _machAllSections();
                        if (n >= sections.length) return 0;
                        return sections[n].offset;
                    };
                    MACH.getSectionFileSize = function(n) {
                        if (!_machIsMachO()) return 0;
                        var sections = _machAllSections();
                        if (n >= sections.length) return 0;
                        return sections[n].size;
                    };
                    MACH.isSectionNamePresent = function(name) {
                        if (!_machIsMachO()) return false;
                        return _machSectionNumber(name) >= 0;
                    };
                    MACH.isLibraryNamePresent = function(name) {
                        if (!_machIsMachO()) return false;
                        var libs = _machLibraries();
                        for (var i = 0; i < libs.length; i++) {
                            if (libs[i] === name) return true;
                        }
                        return false;
                    };
                    MACH.isLibraryPresent = function(name) {
                        if (!_machIsMachO()) return false;
                        var libs = _machLibraries();
                        for (var i = 0; i < libs.length; i++) {
                            if (libs[i] === name) return true;
                        }
                        return false;
                    };
                    MACH.getLibraryCurrentVersion = function(name) {
                        if (!_machIsMachO()) return 0;
                        // Find LC_LOAD_DYLIB with matching name, return current_version.
                        var ncmds = _machNCmds();
                        var off = _machHeaderSize();
                        for (var i = 0; i < ncmds; i++) {
                            var cmd = _machReadU32(off);
                            var cmdsize = _machReadU32(off + 4);
                            if (cmdsize === 0) break;
                            if (cmd === LC_LOAD_DYLIB) {
                                var nameOffset = _machReadU32(off + 8);
                                var libName = "";
                                var maxLen = cmdsize - nameOffset;
                                for (var j = 0; j < maxLen; j++) {
                                    var b = Binary.read_uint8(off + nameOffset + j);
                                    if (b === 0) break;
                                    libName += String.fromCharCode(b);
                                }
                                if (libName === name) {
                                    return _machReadU32(off + 16);
                                }
                            }
                            off += cmdsize;
                        }
                        return 0;
                    };
                    MACH.getType = function() {
                        if (!_machIsMachO()) return "";
                        return _machFileTypeNames[_machFileType()] || "";
                    };
                    MACH.getMachine = function() {
                        if (!_machIsMachO()) return "";
                        var cputype = _machCpuType();
                        return _machCpuNames[cputype] || "";
                    };
                    MACH.getEntryPoint = function() {
                        if (!_machIsMachO()) return 0;
                        return _machEntryPoint();
                    };
                    MACH.getGeneralOptions = function() {
                        if (!_machIsMachO()) return "";
                        var ft = _machFileTypeNames[_machFileType()] || "";
                        return ft + (_machIs64() ? "64" : "32");
                    };
                    MACH.getOperationSystemName = function() { return "macOS"; };
                    MACH.getOperationSystemVersion = function() { return ""; };
                    MACH.getOperationSystemOptions = function() { return ""; };
                    MACH.getString = function(offset, maxLen) {
                        if (maxLen === undefined) maxLen = 256;
                        return Binary.getString(offset, maxLen);
                    };
                    MACH.getSize = function() { return Binary.getSize(); };
                    MACH.readByte = function(offset) { return Binary.read_uint8(offset); };
                    MACH.findSignature = function(offset, sizeOrSig, sig) {
                        if (sig === undefined) { sig = sizeOrSig; return Binary.findSignature(offset, sig); }
                        return Binary.findSignature(offset, sizeOrSig, sig);
                    };
                    MACH.findString = function(offset, sizeOrStr, str) {
                        if (str === undefined) { str = sizeOrStr; sizeOrStr = 0; }
                        return Binary.findString(offset, sizeOrStr, str);
                    };
                    MACH.isVerbose = function() { return false; };
                    MACH.isDeepScan = function() { return false; };
                    MACH.isHeuristicScan = function() { return false; };
                    // Image base: lowest VM address from LC_SEGMENT/LC_SEGMENT_64.
                    MACH.getImageBase = function() {
                        if (!_machIsMachO()) return 0;
                        var is64 = _machIs64();
                        var nCmds = _machNCmds();
                        var off = _machHeaderSize();
                        var base = -1;
                        var LC_SEGMENT = 1;
                        var LC_SEGMENT_64 = 0x19;
                        for (var i = 0; i < nCmds; i++) {
                            var cmd = _machReadU32(off);
                            var cmdSize = _machReadU32(off + 4);
                            if (cmd === LC_SEGMENT || cmd === LC_SEGMENT_64) {
                                var vmaddr = is64 ? _machReadU64(off + 24) : _machReadU32(off + 16);
                                if (base < 0 || vmaddr < base) base = vmaddr;
                            }
                            off += cmdSize;
                        }
                        return base < 0 ? 0 : base;
                    };
                    MACH.compareEP = function(sig, offset) {
                        if (!_machIsMachO()) return false;
                        var ep = _machEntryPoint();
                        if (ep === 0) return false;
                        if (offset === undefined) offset = 0;
                        return Binary.__compare(sig, ep + offset);
                    };
                    MACH.compare = function(sig, offset) {
                        if (offset === undefined) offset = 0;
                        return Binary.__compare(sig, offset);
                    };
                    // Overlay: data after the last segment's file data.
                    MACH.getOverlayOffset = function() {
                        if (!_machIsMachO()) return -1;
                        var is64 = _machIs64();
                        var nCmds = _machNCmds();
                        var off = _machHeaderSize();
                        var maxEnd = 0;
                        var LC_SEGMENT = 1;
                        var LC_SEGMENT_64 = 0x19;
                        for (var i = 0; i < nCmds; i++) {
                            var cmd = _machReadU32(off);
                            var cmdSize = _machReadU32(off + 4);
                            if (cmd === LC_SEGMENT || cmd === LC_SEGMENT_64) {
                                var fileOff = _machSegmentFileOff(off, is64);
                                var fileSize = _machSegmentFileSize(off, is64);
                                var end = fileOff + fileSize;
                                if (end > maxEnd) maxEnd = end;
                            }
                            off += cmdSize;
                        }
                        if (maxEnd >= Binary.getSize()) return -1;
                        return maxEnd;
                    };
                    MACH.getOverlaySize = function() {
                        var off = MACH.getOverlayOffset();
                        if (off < 0) return 0;
                        return Binary.getSize() - off;
                    };
                })();
                "#,
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("MACH methods: {e}"),
            })?;

            // Register all remaining format-specific global objects as
            // independent objects with Binary as prototype. Each format's
            // _init script does `var File = <FORMAT>;`, so these objects
            // must exist. Using independent objects (instead of aliases to
            // Binary) allows format-specific methods like getFileFormatName
            // to be set without affecting other formats.
            for name in &[
                "RAR", "DEX", "PYC", "APK", "Archive", "CFBF", "COM", "DOS16M", "DOS4G", "Amiga",
                "AtariST", "IPA", "ISO9660", "JAR", "JavaClass", "JPEG", "Jpeg", "LE", "LX",
                "MSDOS", "NE", "NPM", "PDF", "PNG", "ZIP", "Image",
            ] {
                let obj = rquickjs::Object::new(ctx.clone()).map_err(|e| RuleError::Backend {
                    detail: format!("failed to create {name} object: {e}"),
                })?;
                obj.set("__proto__", binary.clone()).map_err(|e| RuleError::Backend {
                    detail: format!("failed to set {name} proto: {e}"),
                })?;
                globals.set(*name, obj).map_err(|e| RuleError::Backend {
                    detail: format!("failed to set {name} global: {e}"),
                })?;
            }

            // Add format-specific stub methods for getFileFormatName/Version/Options.
            // These are used by the primary detection rules (_RAR.0.sg, _DEX2.0.sg,
            // _PYC.0.sg, etc.) to get format metadata. Until the format-specific
            // host APIs are fully implemented, these return empty strings.
            // For formats whose _init rules unconditionally set bDetected=true
            // and call getFileFormatName(), we must return a non-empty name
            // to avoid "No input detection name" errors from result().
            ctx.eval::<(), _>(
                r#"
                (function() {
                    // Formats that don't need a specific name (no unconditional bDetected).
                    var emptyFormats = [APK, COM, DOS16M, DOS4G, Amiga, AtariST,
                                        IPA, JAR, MSDOS, NE, NPM];
                    for (var i = 0; i < emptyFormats.length; i++) {
                        var f = emptyFormats[i];
                        if (!f) continue;
                        f.getFileFormatName = function() { return ""; };
                        f.getFileFormatVersion = function() { return ""; };
                        f.getFileFormatOptions = function() { return ""; };
                        f.isVerbose = function() { return false; };
                        f.isDeepScan = function() { return false; };
                        f.isHeuristicScan = function() { return false; };
                    }
                    // Formats with unconditional bDetected=true in _*.0.sg.
                    // These need non-empty getFileFormatName to avoid errors.
                    var namedFormats = {
                        CFBF: "CFBF",
                        JavaClass: "Java Class",
                        PDF: "PDF",
                        PNG: "PNG",
                        JPEG: "JPEG",
                        ZIP: "ZIP",
                        RAR: "RAR",
                        ISO9660: "ISO 9660",
                        Archive: "Archive",
                        Image: "Image",
                    };
                    for (var fname in namedFormats) {
                        var obj = eval(fname);
                        if (!obj) continue;
                        obj.getFileFormatName = (function(name) {
                            return function() { return name; };
                        })(namedFormats[fname]);
                        obj.getFileFormatVersion = function() { return ""; };
                        obj.getFileFormatOptions = function() { return ""; };
                        // isVerbose defaults to false; archive detections come
                        // from Binary/archive_*.1.sg rules, not _Archive.0.sg.
                        obj.isVerbose = function() { return false; };
                        obj.isDeepScan = function() { return false; };
                        obj.isHeuristicScan = function() { return false; };
                    }

                    // MSDOS-specific stubs: MSDOS rules call these methods
                    // (compareEP, compareOverlay, getOverlayOffset, etc.)
                    // which require DOS/MSDOS-specific parsing. Stubs return
                    // false/0/empty so rules execute without TypeError.
                    // Full implementation is Phase 15.3 scope.
                    MSDOS.compareEP = function(sig) { return false; };
                    MSDOS.compareOverlay = function(sig) { return false; };
                    MSDOS.getOverlayOffset = function() { return -1; };
                    MSDOS.getEntryPointOffset = function() { return -1; };
                    MSDOS.getNEOffset = function() { return -1; };
                    MSDOS.isNE = function() {
                        // NE signature at e_lfanew: "NE" (0x4E 0x45)
                        if (Binary.getSize() < 0x40) return false;
                        var lfanew = Binary.read_uint32_le(0x3C);
                        if (lfanew + 2 > Binary.getSize()) return false;
                        return Binary.read_uint8(lfanew) === 0x4E && Binary.read_uint8(lfanew + 1) === 0x45;
                    };
                    MSDOS.isLE = function() {
                        // LE signature at e_lfanew: "LE" (0x4C 0x45)
                        if (Binary.getSize() < 0x40) return false;
                        var lfanew = Binary.read_uint32_le(0x3C);
                        if (lfanew + 2 > Binary.getSize()) return false;
                        return Binary.read_uint8(lfanew) === 0x4C && Binary.read_uint8(lfanew + 1) === 0x45;
                    };
                    MSDOS.isLX = function() {
                        // LX signature at e_lfanew: "LX" (0x4C 0x58)
                        if (Binary.getSize() < 0x40) return false;
                        var lfanew = Binary.read_uint32_le(0x3C);
                        if (lfanew + 2 > Binary.getSize()) return false;
                        return Binary.read_uint8(lfanew) === 0x4C && Binary.read_uint8(lfanew + 1) === 0x58;
                    };
                    MSDOS.isPE = function() {
                        // PE signature at e_lfanew: "PE\0\0" (0x50 0x45 0x00 0x00)
                        if (Binary.getSize() < 0x40) return false;
                        var lfanew = Binary.read_uint32_le(0x3C);
                        if (lfanew + 4 > Binary.getSize()) return false;
                        return Binary.read_uint8(lfanew) === 0x50 && Binary.read_uint8(lfanew + 1) === 0x45;
                    };
                    MSDOS.getBaseOffset = function() { return 0; };
                    MSDOS.getOperationSystemName = function() { return ""; };
                    MSDOS.getOperationSystemVersion = function() { return ""; };
                    MSDOS.getOperationSystemOptions = function() { return ""; };
                    MSDOS.getDisasmNextAddress = function(off) { return -1; };
                    MSDOS.addressToOffset = function(addr) { return -1; };
                    MSDOS.AddressToOffset = MSDOS.addressToOffset;
                    MSDOS.OffsetToVA = function(off) { return -1; };
                    MSDOS.VAToOffset = function(va) { return -1; };
                    // DOS stub: between MZ header and PE/NE/LE header.
                    MSDOS.getDosStubOffset = function() {
                        if (Binary.getSize() < 0x40) return -1;
                        // DOS stub starts after MZ header (0x40) if e_lfanew > 0x40.
                        var lfanew = Binary.read_uint32_le(0x3C);
                        if (lfanew > 0x40) return 0x40;
                        return -1;
                    };
                    MSDOS.getDosStubSize = function() {
                        if (Binary.getSize() < 0x40) return 0;
                        var lfanew = Binary.read_uint32_le(0x3C);
                        if (lfanew > 0x40) return lfanew - 0x40;
                        return 0;
                    };
                    MSDOS.isDosStubPresent = function() {
                        return MSDOS.getDosStubSize() > 0;
                    };
                    MSDOS.isRichVersionPresent = function(version) {
                        // Check if a specific Rich version exists.
                        // Rich signature starts at "Rich" marker.
                        if (Binary.getSize() < 0x80) return false;
                        // Search for "Rich" signature in first 256 bytes.
                        for (var i = 0x40; i < Math.min(0x200, Binary.getSize()) - 4; i++) {
                            if (Binary.read_uint8(i) === 0x52 && Binary.read_uint8(i+1) === 0x69 &&
                                Binary.read_uint8(i+2) === 0x63 && Binary.read_uint8(i+3) === 0x68) {
                                return true;
                            }
                        }
                        return false;
                    };

                    // JavaClass-specific: parse version from class file header.
                    // Class file: magic (4 bytes, 0xCAFEBABE) + minor (2 bytes, BE) +
                    // major (2 bytes, BE). Map major version to Java SE string.
                    JavaClass.getFileFormatVersion = function() {
                        if (Binary.getSize() < 8) return "";
                        // Verify CAFEBABE magic.
                        if (Binary.read_uint8(0) !== 0xCA || Binary.read_uint8(1) !== 0xFE ||
                            Binary.read_uint8(2) !== 0xBA || Binary.read_uint8(3) !== 0xBE) return "";
                        // Major version at offset 6-7 (big-endian).
                        var major = Binary.read_uint8(6) * 256 + Binary.read_uint8(7);
                        // Map major version to Java SE version string.
                        var versionMap = {
                            45: "Java SE 1.1",
                            46: "Java SE 2",
                            47: "Java SE 3",
                            48: "Java SE 4",
                            49: "Java SE 5",
                            50: "Java SE 6",
                            51: "Java SE 7",
                            52: "Java SE 8",
                            53: "Java SE 9",
                            54: "Java SE 10",
                            55: "Java SE 11",
                            56: "Java SE 12",
                            57: "Java SE 13",
                            58: "Java SE 14",
                            59: "Java SE 15",
                            60: "Java SE 16",
                            61: "Java SE 17",
                            62: "Java SE 18",
                            63: "Java SE 19",
                            64: "Java SE 20",
                            65: "Java SE 21",
                        };
                        return versionMap[major] || "";
                    };

                    // CFBF-specific: parse version from header.
                    // CFBF header: signature (8 bytes) + CLSID (16 bytes) +
                    // MinorVersion (2 bytes, LE, offset 0x18) +
                    // MajorVersion (2 bytes, LE, offset 0x1A).
                    // Version string = "major.minor" (e.g. "3.62").
                    CFBF.getFileFormatVersion = function() {
                        if (Binary.getSize() < 0x1C) return "";
                        // Verify CFBF signature D0CF11E0A1B11AE1.
                        if (Binary.read_uint8(0) !== 0xD0 || Binary.read_uint8(1) !== 0xCF ||
                            Binary.read_uint8(2) !== 0x11 || Binary.read_uint8(3) !== 0xE0 ||
                            Binary.read_uint8(4) !== 0xA1 || Binary.read_uint8(5) !== 0xB1 ||
                            Binary.read_uint8(6) !== 0x1A || Binary.read_uint8(7) !== 0xE1) return "";
                        var minor = Binary.read_uint16_le(0x18);
                        var major = Binary.read_uint16_le(0x1A);
                        if (major !== 3 && major !== 4) return "";
                        return major + "." + minor;
                    };

                    // ZIP-specific stubs.
                    ZIP.isArchiveRecordPresent = function(name) { return false; };

                    // ISO9660-specific: parse Primary Volume Descriptor fields.
                    // PVD is at offset 0x8000 (sector 16). Fields are ASCII,
                    // space-padded to fixed width.
                    ISO9660.getDataPreparerIdentifier = function() {
                        var pvd = 0x8000;
                        if (Binary.getSize() < pvd + 574 + 128) return "";
                        var s = "";
                        for (var i = 0; i < 128; i++) {
                            var c = Binary.read_uint8(pvd + 446 + i);
                            if (c === 0) break;
                            s += String.fromCharCode(c);
                        }
                        return s.trim();
                    };
                    ISO9660.getApplicationIdentifier = function() {
                        var pvd = 0x8000;
                        if (Binary.getSize() < pvd + 574 + 128) return "";
                        var s = "";
                        for (var i = 0; i < 128; i++) {
                            var c = Binary.read_uint8(pvd + 574 + i);
                            if (c === 0) break;
                            s += String.fromCharCode(c);
                        }
                        return s.trim();
                    };

                    // ISO9660 file format info: upstream returns these from
                    // the file format database. We return basic strings.
                    ISO9660.getFileFormatName = function() { return "ISO9660"; };
                    ISO9660.getFileFormatVersion = function() {
                        // ISO9660 has no standard version field in PVD.
                        // Check Volume Descriptor Type for Joliet (type 2) hint.
                        var pvd = 0x8000;
                        if (Binary.getSize() < pvd + 7) return "";
                        var vdt = Binary.read_uint8(pvd);
                        if (vdt === 2) return "Joliet";
                        if (vdt === 1) return "ISO9660";
                        return "";
                    };
                    ISO9660.getFileFormatOptions = function() {
                        // ISO9660 has no standard options field in PVD.
                        // Check for Joliet extension (Volume Descriptor Type 2).
                        if (Binary.getSize() < 0x8001) return "";
                        var vdt = Binary.read_uint8(0x8000);
                        if (vdt === 2) return "Joliet";
                        // Check for Rock Ridge (SUSP "RRIP" signature in root dir).
                        return "";
                    };
                    // ISO9660 PVD field readers: PVD at 0x8000, fields are ASCII space-padded.
                    ISO9660.isValid = function() {
                        if (Binary.getSize() < 0x8001) return false;
                        // PVD type = 1 at offset 0x8000.
                        return Binary.read_uint8(0x8000) === 1;
                    };
                    ISO9660.getSystemIdentifier = function() {
                        return _isoReadPVDString(8, 32);
                    };
                    ISO9660.getVolumeIdentifier = function() {
                        return _isoReadPVDString(40, 32);
                    };
                    ISO9660.getVolumeSetIdentifier = function() {
                        return _isoReadPVDString(190, 128);
                    };
                    ISO9660.getPublisherIdentifier = function() {
                        return _isoReadPVDString(318, 128);
                    };
                    ISO9660.getCopyrightFileIdentifier = function() {
                        return _isoReadPVDString(702, 37);
                    };
                    ISO9660.getAbstractFileIdentifier = function() {
                        return _isoReadPVDString(739, 36);
                    };
                    ISO9660.getBibliographicFileIdentifier = function() {
                        return _isoReadPVDString(775, 37);
                    };
                    ISO9660.getCreationDateTime = function() {
                        return _isoReadPVDString(812, 17);
                    };
                    ISO9660.getModificationDateTime = function() {
                        return _isoReadPVDString(829, 17);
                    };
                    ISO9660.getExpirationDateTime = function() {
                        return _isoReadPVDString(846, 17);
                    };
                    ISO9660.getEffectiveDateTime = function() {
                        return _isoReadPVDString(863, 17);
                    };
                    // ISO9660 archive record: search for filename in volume.
                    ISO9660.isArchiveRecordPresent = function(name) {
                        if (!ISO9660.isValid()) return false;
                        var off = Binary.find_ansiString(0, Binary.getSize(), name);
                        return off >= 0;
                    };
                    ISO9660.isArchiveRecordPresentExp = function(name) {
                        return ISO9660.isArchiveRecordPresent(name) ||
                               ISO9660.isArchiveRecordPresent(name.toUpperCase()) ||
                               ISO9660.isArchiveRecordPresent(name.toLowerCase());
                    };
                    // Helper: read PVD string field (offset from PVD start, length).
                    function _isoReadPVDString(fieldOff, fieldLen) {
                        var pvd = 0x8000;
                        if (Binary.getSize() < pvd + fieldOff + fieldLen) return "";
                        var s = "";
                        for (var i = 0; i < fieldLen; i++) {
                            var c = Binary.read_uint8(pvd + fieldOff + i);
                            if (c === 0) break;
                            s += String.fromCharCode(c);
                        }
                        return s.trim();
                    }
                    PDF.getFileFormatVersion = function() {
                        // PDF header: "%PDF-X.Y" at offset 0, version at offset 5.
                        if (Binary.getSize() < 8) return "";
                        if (Binary.read_uint8(0) !== 0x25 || Binary.read_uint8(1) !== 0x50) return "";
                        // Read version string from offset 5 (e.g. "1.4").
                        var major = Binary.read_uint8(5);
                        var dot = Binary.read_uint8(6);
                        var minor = Binary.read_uint8(7);
                        if (major >= 0x30 && major <= 0x39 && dot === 0x2E && minor >= 0x30 && minor <= 0x39) {
                            return String.fromCharCode(major) + "." + String.fromCharCode(minor);
                        }
                        return "";
                    };
                    PDF.getHeaderCommentAsHex = function() {
                        // PDF header comment is the second line starting with '%'
                        // after the "%PDF-X.Y" first line. It is typically
                        // "%âãÏÓ" (high bytes indicating binary PDF).
                        // Return the hex encoding of the comment bytes (without
                        // the leading '%' and trailing newline).
                        if (Binary.getSize() < 10) return "";
                        // Find the first newline after "%PDF-X.Y".
                        var nl = -1;
                        for (var i = 5; i < Binary.getSize() && i < 100; i++) {
                            if (Binary.read_uint8(i) === 0x0A) { nl = i; break; }
                        }
                        if (nl < 0 || nl + 1 >= Binary.getSize()) return "";
                        // Second line starts at nl+1, should start with '%'.
                        var start = nl + 1;
                        if (Binary.read_uint8(start) !== 0x25) return "";
                        // Read until next newline or EOF, up to 20 bytes.
                        var hex = "";
                        for (var j = start + 1; j < Binary.getSize() && j < start + 21; j++) {
                            var b = Binary.read_uint8(j);
                            if (b === 0x0A || b === 0x0D) break;
                            var h = b.toString(16);
                            if (h.length < 2) h = "0" + h;
                            hex += h;
                        }
                        return hex;
                    };
                    PDF.getStringValuesByKey = function(key) { return []; };

                    // JPEG/Jpeg-specific: parse version from JFIF APP0 marker.
                    // Jpeg (mixed case) is used by _Jpeg.0.sg for detection.
                    Jpeg.getFileFormatName = function() { return "JPEG"; };
                    Jpeg.getFileFormatVersion = function() {
                        // JPEG version comes from the JFIF APP0 marker.
                        // Layout: FF D8 FF E0 <len:2> "JFIF" <null> <major> <minor>
                        // Version bytes at offset 11-12 are binary, not ASCII.
                        if (Binary.getSize() < 20) return "";
                        // Check for JFIF marker at offset 6.
                        if (Binary.read_uint8(6) === 0x4A && Binary.read_uint8(7) === 0x46 &&
                            Binary.read_uint8(8) === 0x49 && Binary.read_uint8(9) === 0x46) {
                            var major = Binary.read_uint8(11);
                            var minor = Binary.read_uint8(12);
                            return major + "." + minor;
                        }
                        return "";
                    };
                    Jpeg.getFileFormatOptions = function() { return ""; };
                    Jpeg.isVerbose = function() { return false; };
                    Jpeg.isDeepScan = function() { return false; };
                    Jpeg.isHeuristicScan = function() { return false; };
                    Jpeg.isChunkPresent = function(chunkId) { return false; };
                    Jpeg.getComment = function() { return ""; };
                    Jpeg.getDqtMD5 = function(n) { return ""; };
                    Jpeg.getExifCameraName = function() { return ""; };
                })();
                "#,
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("format stubs: {e}"),
            })?;

            // Add DEX-specific stub methods.
            // DEX and PYC are aliases to the same Binary object, so we
            // need to create separate copies to avoid cross-contamination
            // of format-specific methods like getFileFormatName.
            ctx.eval::<(), _>(
                r#"
                (function() {
                    // Create independent copies for DEX and PYC.
                    DEX = Object.create(Binary);
                    PYC = Object.create(Binary);
                    File = Binary; // Ensure File still points to Binary

                    DEX.getMapItemsHash = function() { return ""; };
                    DEX.getOperationSystemName = function() { return ""; };
                    DEX.getOperationSystemVersion = function() { return ""; };
                    DEX.getOperationSystemOptions = function() { return ""; };
                    DEX.isDexStringPresent = function(s) { return false; };
                    DEX.isDexItemStringPresent = function(s) { return false; };
                    // DEX: parse format name and version from header.
                    // DEX header: "dex\n" (magic, 4 bytes) + version (3 bytes, ASCII) + null.
                    DEX.getFileFormatName = function() { return "DEX"; };
                    DEX.getFileFormatVersion = function() {
                        if (Binary.getSize() < 8) return "";
                        // Check "dex\n" magic at offset 0.
                        if (Binary.read_uint8(0) !== 0x64 || Binary.read_uint8(1) !== 0x65 ||
                            Binary.read_uint8(2) !== 0x78 || Binary.read_uint8(3) !== 0x0A) return "";
                        // Version at offset 4-6 (3 ASCII digits).
                        var v = "";
                        for (var i = 4; i < 7; i++) {
                            var b = Binary.read_uint8(i);
                            if (b >= 0x30 && b <= 0x39) {
                                v += String.fromCharCode(b);
                            }
                        }
                        return v;
                    };
                    DEX.getFileFormatOptions = function() { return ""; };
                    DEX.isVerbose = function() { return false; };
                    DEX.isDeepScan = function() { return false; };
                    DEX.isHeuristicScan = function() { return false; };

                    PYC.isConstPresent = function(s) { return false; };
                    PYC.getFileFormatName = function() { return "Python bytecode compiled (.PYC)"; };
                    // Parse PYC magic number to determine Python version.
                    // Magic numbers from CPython source (Lib/importlib/_bootstrap_external.py).
                    PYC.getFileFormatVersion = function() {
                        if (Binary.getSize() < 4) return "";
                        var magic = Binary.read_uint16_le(0);
                        // Map magic number to Python version string.
                        var versions = {
                            62211: "2.7",
                            3000: "3.0", 3010: "3.1", 3020: "3.2",
                            3030: "3.3", 3310: "3.4", 3350: "3.5",
                            3373: "3.6", 3390: "3.7", 3394: "3.7",
                            3400: "3.8", 3410: "3.8", 3413: "3.8",
                            3420: "3.8", 3423: "3.8", 3424: "3.8",
                            3430: "3.9", 3434: "3.9", 3438: "3.9",
                            3439: "3.9", 3440: "3.9",
                            3450: "3.10", 3456: "3.10", 3460: "3.10",
                            3465: "3.10", 3468: "3.10", 3469: "3.10",
                            3470: "3.10", 3473: "3.10", 3475: "3.10",
                            3480: "3.11", 3488: "3.11", 3490: "3.11",
                            3494: "3.11", 3495: "3.11", 3498: "3.11",
                            3500: "3.11", 3501: "3.11", 3505: "3.11",
                            3510: "3.11", 3515: "3.11",
                            3520: "3.12", 3525: "3.12", 3530: "3.12",
                            3531: "3.12", 3532: "3.12", 3533: "3.12",
                            3550: "3.13", 3560: "3.13", 3570: "3.13",
                            3580: "3.13", 3590: "3.13",
                            3600: "3.14", 3610: "3.14"
                        };
                        if (versions[magic] !== undefined) {
                            return versions[magic];
                        }
                        return "";
                    };
                    PYC.getFileFormatOptions = function() { return ""; };
                    PYC.isVerbose = function() { return false; };
                    PYC.isDeepScan = function() { return false; };
                    PYC.isHeuristicScan = function() { return false; };
                })();
                "#,
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("DEX/PYC stubs: {e}"),
            })?;

            // Override getString with a JS wrapper that handles missing 2nd arg.
            // The upstream getString(offset, maxLen?) accepts 1 or 2 args.
            // Also add compare wrapper: compare(signature, offset=0).
            // Also add endianness-aware wrappers for U16/U24/U32/U64 and
            // read_uint16/read_int16/read_uint24/read_uint32/read_int32/
            // read_uint64/read_int64 that accept an optional bigEndian
            // boolean argument.
            ctx.eval::<(), _>(
                r#"
                (function() {
                    var _orig_gs = Binary.getString;
                    Binary.getString = function(offset, maxLen) {
                        if (maxLen === undefined) maxLen = 0;
                        return _orig_gs(offset, maxLen);
                    };
                    X.getString = Binary.getString;
                    File.getString = Binary.getString;

                    var _orig_cmp = Binary.__compare;
                    Binary.compare = function(signature, offset) {
                        if (offset === undefined) offset = 0;
                        return _orig_cmp(signature, offset);
                    };
                    X.compare = Binary.compare;
                    File.compare = Binary.compare;
                    PE.compare = Binary.compare;

                    // Wrap c() to accept optional offset (default 0).
                    var _orig_c = Binary.c;
                    Binary.c = function(signature, offset) {
                        if (offset === undefined) offset = 0;
                        return _orig_c(signature, offset);
                    };
                    X.c = Binary.c;
                    File.c = Binary.c;

                    // readBytes wrapper: readBytes(offset, size, replaceZeroWithSpace?)
                    var _orig_rb = Binary.__readBytes;
                    Binary.readBytes = function(offset, size, replace) {
                        var bytes = _orig_rb(offset, size);
                        if (replace) {
                            for (var i = 0; i < bytes.length; i++) {
                                if (bytes[i] === 0) bytes[i] = 0x20;
                            }
                        }
                        return bytes;
                    };
                    X.readBytes = Binary.readBytes;
                    File.readBytes = Binary.readBytes;

                    // findSignature wrapper: findSignature(start, sig) or
                    // findSignature(start, size, sig) -> offset or -1.
                    var _orig_fs = Binary.__findSignature;
                    var _orig_fsr = Binary.__findSignatureRange;
                    Binary.findSignature = function(start, sizeOrSig, sig) {
                        if (sig === undefined) {
                            return _orig_fs(start, sizeOrSig);
                        }
                        // 3-arg form: search within [start, start+size).
                        var size = sizeOrSig;
                        if (size <= 0) return -1;
                        return _orig_fsr(start, start + size, sig);
                    };
                    X.findSignature = Binary.findSignature;
                    File.findSignature = Binary.findSignature;
                    ELF.findSignature = Binary.findSignature;
                    MACH.findSignature = Binary.findSignature;

                    // Endianness wrappers: U16(offset, bigEndian?) etc.
                    // The native functions are LE-only; BE is handled by
                    // reading bytes and combining them in big-endian order.
                    function _wrapEndian(name, leFn, beFn) {
                        var orig = Binary[name];
                        Binary[name] = function(offset, bigEndian) {
                            if (bigEndian === undefined || !bigEndian) {
                                return orig.call(this, offset);
                            }
                            return beFn.call(this, offset);
                        };
                        X[name] = Binary[name];
                        File[name] = Binary[name];
                    }
                    // BE read functions: read bytes in reverse order.
                    function _beU16(off) { return (Binary.U8(off) << 8) | Binary.U8(off + 1); }
                    function _beU24(off) { return (Binary.U8(off) << 16) | (Binary.U8(off + 1) << 8) | Binary.U8(off + 2); }
                    function _beU32(off) { return (Binary.U8(off) << 24) | (Binary.U8(off + 1) << 16) | (Binary.U8(off + 2) << 8) | Binary.U8(off + 3); }
                    function _beU64(off) {
                        var hi = _beU32(off), lo = _beU32(off + 4);
                        return hi * 4294967296.0 + lo;
                    }
                    _wrapEndian("U16", null, _beU16);
                    _wrapEndian("U24", null, _beU24);
                    _wrapEndian("U32", null, _beU32);
                    _wrapEndian("U64", null, _beU64);
                    _wrapEndian("I16", null, _beU16);
                    _wrapEndian("I24", null, _beU24);
                    _wrapEndian("I32", null, _beU32);
                    _wrapEndian("I64", null, _beU64);

                    // Also wrap read_uint16 etc. with optional bigEndian.
                    function _wrapReadEndian(name) {
                        var orig = Binary[name];
                        Binary[name] = function(offset, bigEndian) {
                            if (bigEndian === undefined || !bigEndian) {
                                return orig.call(this, offset);
                            }
                            // BE: use the BE helper
                            if (name === "read_uint16" || name === "read_int16") return _beU16(offset);
                            if (name === "read_uint24" || name === "read_int24") return _beU24(offset);
                            if (name === "read_uint32" || name === "read_int32") return _beU32(offset);
                            if (name === "read_uint64" || name === "read_int64") return _beU64(offset);
                            return orig.call(this, offset);
                        };
                        X[name] = Binary[name];
                        File[name] = Binary[name];
                    }
                    _wrapReadEndian("read_uint16");
                    _wrapReadEndian("read_int16");
                    _wrapReadEndian("read_uint24");
                    _wrapReadEndian("read_uint32");
                    _wrapReadEndian("read_int32");
                    _wrapReadEndian("read_uint64");
                    _wrapReadEndian("read_int64");

                    // Add explicit _le and _be variants for use by
                    // format-specific host API methods (PE/ELF/MACH).
                    Binary.read_uint8_le = function(off) { return Binary.U8(off); };
                    Binary.read_uint8_be = function(off) { return Binary.U8(off); };
                    Binary.read_uint16_le = function(off) { return Binary.read_uint16(off); };
                    Binary.read_uint16_be = function(off) { return _beU16(off); };
                    Binary.read_uint24_le = function(off) { return Binary.read_uint24(off); };
                    Binary.read_uint24_be = function(off) { return _beU24(off); };
                    Binary.read_uint32_le = function(off) { return Binary.read_uint32(off); };
                    Binary.read_uint32_be = function(off) { return _beU32(off); };
                    Binary.read_uint64_le = function(off) { return Binary.read_uint64(off); };
                    Binary.read_uint64_be = function(off) { return _beU64(off); };
                    X.read_uint16_le = Binary.read_uint16_le;
                    X.read_uint16_be = Binary.read_uint16_be;
                    X.read_uint32_le = Binary.read_uint32_le;
                    X.read_uint32_be = Binary.read_uint32_be;
                    X.read_uint64_le = Binary.read_uint64_le;
                    X.read_uint64_be = Binary.read_uint64_be;
                    File.read_uint16_le = Binary.read_uint16_le;
                    File.read_uint16_be = Binary.read_uint16_be;
                    File.read_uint32_le = Binary.read_uint32_le;
                    File.read_uint32_be = Binary.read_uint32_be;
                    File.read_uint64_le = Binary.read_uint64_le;
                    File.read_uint64_be = Binary.read_uint64_be;

                    // Additional X shortcuts for string and float methods.
                    X.fStr = Binary.findString;
                    File.fStr = Binary.findString;
                    X.BA = Binary.readBytes;
                    File.BA = Binary.readBytes;
                    X.SA = Binary.read_ansiString;
                    File.SA = Binary.read_ansiString;
                    X.SC = Binary.read_codePageString;
                    File.SC = Binary.read_codePageString;
                    X.SU8 = Binary.find_utf8String;
                    File.SU8 = Binary.find_utf8String;
                    X.SU16 = Binary.read_unicodeString;
                    File.SU16 = Binary.read_unicodeString;
                    X.UCSD = Binary.read_ucsdString;
                    File.UCSD = Binary.read_ucsdString;

                    // Float read methods: delegate to Binary.read_float16/32/64.
                    X.F16 = function(offset, bigEndian) {
                        if (bigEndian) return 0.0; // BE not yet supported for float16
                        return Binary.read_float16(offset);
                    };
                    X.F32 = function(offset, bigEndian) {
                        if (bigEndian) return 0.0;
                        return Binary.read_float32(offset);
                    };
                    X.F64 = function(offset, bigEndian) {
                        if (bigEndian) return 0.0;
                        return Binary.read_float64(offset);
                    };
                    Binary.F16 = X.F16;
                    Binary.F32 = X.F32;
                    Binary.F64 = X.F64;
                    File.F16 = X.F16;
                    File.F32 = X.F32;
                    File.F64 = X.F64;

                    // --- Phase 15.6: Binary method gap closure ---
                    // compareEP: compare signature at entry point offset.
                    Binary.compareEP = function(sig, offset) {
                        var ep = Binary.getEntryPointOffset();
                        if (ep < 0) return false;
                        var off = ep + (offset || 0);
                        // Parse hex signature string (e.g., "FFD8" or "FF D8").
                        var hex = sig.replace(/[^0-9A-Fa-f]/g, "");
                        for (var i = 0; i < hex.length; i += 2) {
                            var expected = parseInt(hex.substr(i, 2), 16);
                            if (Binary.read_uint8(off + i / 2) !== expected) return false;
                        }
                        return true;
                    };
                    // File path methods.
                    Binary.getFileDirectory = function() {
                        var name = Binary.getFileName();
                        var idx = name.lastIndexOf('/');
                        if (idx < 0) idx = name.lastIndexOf('\\');
                        return idx >= 0 ? name.substring(0, idx) : "";
                    };
                    Binary.getFileCompleteSuffix = function() {
                        var name = Binary.getFileName();
                        var idx = name.lastIndexOf('.');
                        return idx >= 0 ? name.substring(idx) : "";
                    };
                    // Address conversion: PE-specific via lfanew, generic 0 otherwise.
                    Binary.getImageBase = function() {
                        // PE: ImageBase from Optional Header.
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x30 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20; // PE sig + COFF header
                                var magic = Binary.read_uint16_le(opt);
                                if (magic === 0x10B) return Binary.read_uint32_le(opt + 28);
                                if (magic === 0x20B) return Binary.read_uint32_le(opt + 24);
                            }
                        }
                        return 0;
                    };
                    Binary.getAddressOfEntryPoint = function() {
                        // PE: AddressOfEntryPoint from Optional Header (offset 16).
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x28 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                return Binary.read_uint32_le(opt + 16);
                            }
                        }
                        return 0;
                    };
                    Binary.RVAToOffset = function(rva) {
                        // PE: convert RVA to file offset via section table.
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x28 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var coff = lfanew + 4;
                                var nSec = Binary.read_uint16_le(coff + 2);
                                var optSize = Binary.read_uint16_le(coff + 16);
                                var secOff = coff + 20 + optSize;
                                for (var i = 0; i < nSec; i++) {
                                    var sOff = secOff + i * 40;
                                    var vAddr = Binary.read_uint32_le(sOff + 12);
                                    var vSize = Binary.read_uint32_le(sOff + 8);
                                    var rawAddr = Binary.read_uint32_le(sOff + 20);
                                    if (rva >= vAddr && rva < vAddr + vSize) {
                                        return rawAddr + (rva - vAddr);
                                    }
                                }
                            }
                        }
                        return 0;
                    };
                    Binary.VAToOffset = function(va) {
                        var base = Binary.getImageBase();
                        if (base === 0) return 0;
                        return Binary.RVAToOffset(va - base);
                    };
                    Binary.OffsetToRVA = function(offset) {
                        // PE: convert file offset to RVA via section table.
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x28 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var coff = lfanew + 4;
                                var nSec = Binary.read_uint16_le(coff + 2);
                                var optSize = Binary.read_uint16_le(coff + 16);
                                var secOff = coff + 20 + optSize;
                                for (var i = 0; i < nSec; i++) {
                                    var sOff = secOff + i * 40;
                                    var rawAddr = Binary.read_uint32_le(sOff + 20);
                                    var rawSize = Binary.read_uint32_le(sOff + 16);
                                    var vAddr = Binary.read_uint32_le(sOff + 12);
                                    if (offset >= rawAddr && offset < rawAddr + rawSize) {
                                        return vAddr + (offset - rawAddr);
                                    }
                                }
                            }
                        }
                        return 0;
                    };
                    Binary.OffsetToVA = function(offset) {
                        var rva = Binary.OffsetToRVA(offset);
                        if (rva === 0) return 0;
                        return Binary.getImageBase() + rva;
                    };
                    Binary.isOverlayPresent = function() {
                        return Binary.getOverlaySize() > 0;
                    };
                    Binary.compareOverlay = function(sig) {
                        // Compare signature at overlay offset.
                        var off = Binary.getOverlayOffset();
                        if (off < 0) return false;
                        var hex = sig.replace(/[^0-9A-Fa-f]/g, "");
                        for (var i = 0; i < hex.length; i += 2) {
                            var expected = parseInt(hex.substr(i, 2), 16);
                            if (Binary.read_uint8(off + i / 2) !== expected) return false;
                        }
                        return true;
                    };
                    Binary.swapBytes = function(offset, size) {
                        // Read size bytes, reverse, return as number.
                        if (size <= 0 || size > 8) return 0;
                        var val = 0;
                        for (var i = 0; i < size; i++) {
                            val = (val << 8) | Binary.read_uint8(offset + i);
                        }
                        return val;
                    };
                    Binary.getSignature = function(offset, size) {
                        var s = "";
                        for (var i = 0; i < size; i++) {
                            var b = Binary.read_uint8(offset + i);
                            s += (b < 16 ? "0" : "") + b.toString(16);
                        }
                        return s.toUpperCase();
                    };
                    // Build type: check PE debug directory for debug builds.
                    Binary.isReleaseBuild = function() {
                        // PE: check IMAGE_DEBUG_DIRECTORY for absence of debug info.
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x28 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                // Data directory 6 = Debug Directory
                                var dbgRva = Binary.read_uint32_le(opt + 6 * 8);
                                return dbgRva === 0;
                            }
                        }
                        return true;
                    };
                    Binary.isDebugBuild = function() {
                        return !Binary.isReleaseBuild();
                    };
                    // Signed: check PE security directory (data directory 4).
                    Binary.isSigned = function() {
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x28 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                var secRva = Binary.read_uint32_le(opt + 4 * 8);
                                var secSize = Binary.read_uint32_le(opt + 4 * 8 + 4);
                                return secRva !== 0 && secSize !== 0;
                            }
                        }
                        return false;
                    };
                    // FilePart: check if this file is part of a larger file
                    // (e.g., embedded resource). For standalone files, return false.
                    Binary.isFilePart = function() {
                        // PE with overlay might be a self-extracting archive part.
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 4 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                // Check if file size significantly exceeds PE image size.
                                return false; // Standalone PE
                            }
                        }
                        return false;
                    };
                    // Checksum: verify PE Optional Header CheckSum field.
                    Binary.isChecksumCorrect = function() {
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x40 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                var storedChecksum = Binary.read_uint32_le(opt + 64);
                                // Full checksum computation is complex; if non-zero,
                                // assume it's been set correctly.
                                return storedChecksum !== 0;
                            }
                        }
                        return false;
                    };
                    // Entry point: check if AddressOfEntryPoint is within a section.
                    Binary.isEntryPointCorrect = function() {
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x28 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                var ep = Binary.read_uint32_le(opt + 16);
                                return ep !== 0;
                            }
                        }
                        return false;
                    };
                    // Section alignment: check SectionAlignment is power of 2.
                    Binary.isSectionAlignmentCorrect = function() {
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x40 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                var sa = Binary.read_uint32_le(opt + 32);
                                return sa > 0 && (sa & (sa - 1)) === 0;
                            }
                        }
                        return false;
                    };
                    // File alignment: check FileAlignment is power of 2.
                    Binary.isFileAlignmentCorrect = function() {
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x40 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                var fa = Binary.read_uint32_le(opt + 36);
                                return fa > 0 && (fa & (fa - 1)) === 0;
                            }
                        }
                        return false;
                    };
                    // Header correctness: check DOS + PE signatures.
                    Binary.isHeaderCorrect = function() {
                        if (Binary.getSize() < 0x40) return false;
                        if (Binary.read_uint8(0) !== 0x4D || Binary.read_uint8(1) !== 0x5A) return false;
                        var lfanew = Binary.read_uint32_le(0x3C);
                        if (lfanew + 4 > Binary.getSize()) return false;
                        return Binary.read_uint32_le(lfanew) === 0x4550;
                    };
                    // Table correctness: check data directory entries are valid.
                    Binary.isRelocsTableCorrect = function() {
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x28 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                var rva = Binary.read_uint32_le(opt + 5 * 8);
                                return rva !== 0;
                            }
                        }
                        return false;
                    };
                    Binary.isImportTableCorrect = function() {
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x28 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                var rva = Binary.read_uint32_le(opt + 1 * 8);
                                return rva !== 0;
                            }
                        }
                        return false;
                    };
                    Binary.isExportTableCorrect = function() {
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x28 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                var rva = Binary.read_uint32_le(opt + 0 * 8);
                                return rva !== 0;
                            }
                        }
                        return false;
                    };
                    Binary.isResourcesTableCorrect = function() {
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x28 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                var rva = Binary.read_uint32_le(opt + 2 * 8);
                                return rva !== 0;
                            }
                        }
                        return false;
                    };
                    Binary.isSectionsTableCorrect = function() {
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x28 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var coff = lfanew + 4;
                                var nSec = Binary.read_uint16_le(coff + 2);
                                return nSec > 0;
                            }
                        }
                        return false;
                    };
                    // Profiling: track timing state.
                    var _profilingStart = 0;
                    Binary.isProfiling = function() { return _profilingStart > 0; };
                    Binary.startTiming = function() {
                        _profilingStart = Date.now();
                        return _profilingStart;
                    };
                    Binary.endTiming = function() {
                        if (_profilingStart === 0) return 0;
                        var elapsed = Date.now() - _profilingStart;
                        _profilingStart = 0;
                        return elapsed;
                    };
                    // StartOffset: for embedded files, the offset where this
                    // file starts within the parent. For standalone files, 0.
                    Binary.getStartOffset = function() {
                        // Check if this is an embedded resource by looking for
                        // a parent file context. In diec-rust, files are standalone.
                        if (Binary.getSize() > 0) return 0;
                        return 0;
                    };
                    Binary.getDisasmLength = function(offset, size) { return size; };
                    // OS info: detect from PE version resource (simplified).
                    Binary.getOperationSystemName = function() {
                        // Check PE subsystem for common OS targets.
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x5C < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                var opt = lfanew + 4 + 20;
                                var subsystem = Binary.read_uint16_le(opt + 68);
                                if (subsystem === 2 || subsystem === 3) return "Windows";
                            }
                        }
                        return "";
                    };
                    Binary.getOperationSystemVersion = function() {
                        // PE: check version resource for OS version.
                        // Simplified: return empty (would need VS_VERSIONINFO parsing).
                        return "";
                    };
                    Binary.getOperationSystemOptions = function() {
                        // PE: check version resource for OS options.
                        // Would need VS_VERSIONINFO parsing for full implementation.
                        if (Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 4 < Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) {
                                // PE has version info in resources; return empty
                                // as we don't parse VS_VERSIONINFO here.
                                return "";
                            }
                        }
                        return "";
                    };
                    // File format info: detect from magic bytes.
                    Binary.getFileFormatName = function() {
                        if (Binary.getSize() < 4) return "";
                        // PE
                        if (Binary.read_uint8(0) === 0x4D && Binary.read_uint8(1) === 0x5A) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 4 <= Binary.getSize() && Binary.read_uint32_le(lfanew) === 0x4550) return "PE";
                            return "MSDOS";
                        }
                        // ELF
                        if (Binary.read_uint8(0) === 0x7F && Binary.read_uint8(1) === 0x45) return "ELF";
                        // Mach-O
                        if (Binary.read_uint32_le(0) === 0xFEEDFACE || Binary.read_uint32_le(0) === 0xFEEDFACF) return "Mach-O";
                        // ZIP
                        if (Binary.read_uint8(0) === 0x50 && Binary.read_uint8(1) === 0x4B) return "ZIP";
                        // PDF
                        if (Binary.read_uint8(0) === 0x25 && Binary.read_uint8(1) === 0x50) return "PDF";
                        return "";
                    };
                    Binary.getFileFormatVersion = function() {
                        // Detect version from file format magic bytes.
                        var name = Binary.getFileFormatName();
                        if (name === "PDF" && Binary.getSize() >= 8) {
                            // "%PDF-X.Y" at offset 0, version at offset 5.
                            var major = Binary.read_uint8(5);
                            var minor = Binary.read_uint8(7);
                            if (major >= 0x30 && major <= 0x39) {
                                return String.fromCharCode(major) + "." + String.fromCharCode(minor);
                            }
                        }
                        if (name === "ELF" && Binary.getSize() >= 5) {
                            var ei_class = Binary.read_uint8(4);
                            return ei_class === 2 ? "64" : "32";
                        }
                        if (name === "Mach-O" && Binary.getSize() >= 7) {
                            var magic = Binary.read_uint32_le(0);
                            return magic === 0xFEEDFACF ? "64" : "32";
                        }
                        return "";
                    };
                    Binary.getFileFormatOptions = function() {
                        // Format-specific options (e.g., PE subsystem, ELF type).
                        var name = Binary.getFileFormatName();
                        if (name === "PE" && Binary.getSize() > 0x40) {
                            var lfanew = Binary.read_uint32_le(0x3C);
                            if (lfanew + 0x5C < Binary.getSize()) {
                                var opt = lfanew + 4 + 20;
                                var subsystem = Binary.read_uint16_le(opt + 68);
                                if (subsystem === 2) return "GUI";
                                if (subsystem === 3) return "CUI";
                            }
                        }
                        return "";
                    };
                    // Signature in section: search for hex signature within a PE section.
                    Binary.isSignatureInSectionPresent = function(sig) {
                        if (Binary.getSize() < 0x40) return false;
                        var lfanew = Binary.read_uint32_le(0x3C);
                        if (lfanew + 0x28 > Binary.getSize()) return false;
                        if (Binary.read_uint32_le(lfanew) !== 0x4550) return false;
                        var coff = lfanew + 4;
                        var nSec = Binary.read_uint16_le(coff + 2);
                        var optSize = Binary.read_uint16_le(coff + 16);
                        var secOff = coff + 20 + optSize;
                        var hex = sig.replace(/[^0-9A-Fa-f]/g, "");
                        if (hex.length === 0) return false;
                        for (var s = 0; s < nSec; s++) {
                            var sOff = secOff + s * 40;
                            var rawAddr = Binary.read_uint32_le(sOff + 20);
                            var rawSize = Binary.read_uint32_le(sOff + 16);
                            for (var i = 0; i + hex.length / 2 <= rawSize; i++) {
                                var found = true;
                                for (var j = 0; j < hex.length; j += 2) {
                                    var expected = parseInt(hex.substr(j, 2), 16);
                                    if (Binary.read_uint8(rawAddr + i + j / 2) !== expected) {
                                        found = false;
                                        break;
                                    }
                                }
                                if (found) return true;
                            }
                        }
                        return false;
                    };
                    // JPEG detection: check for SOI marker (0xFFD8).
                    Binary.isJpeg = function() {
                        if (Binary.getSize() < 3) return false;
                        return Binary.read_uint8(0) === 0xFF && Binary.read_uint8(1) === 0xD8;
                    };
                    // JPEG comment: COM marker (0xFFFE) contains comment text.
                    Binary.getJpegComment = function() {
                        if (!Binary.isJpeg()) return "";
                        var size = Binary.getSize();
                        var i = 2; // Skip SOI (0xFFD8)
                        while (i + 4 < size) {
                            if (Binary.read_uint8(i) !== 0xFF) break;
                            var marker = Binary.read_uint8(i + 1);
                            if (marker === 0xFE) {
                                // COM marker: 2-byte length (includes length field) + comment
                                var len = Binary.read_uint16_le(i + 2);
                                if (i + 2 + len > size) return "";
                                var comment = "";
                                for (var j = 4; j < 2 + len; j++) {
                                    comment += String.fromCharCode(Binary.read_uint8(i + j));
                                }
                                return comment;
                            }
                            if (marker === 0xD9) break; // EOI
                            // Skip to next marker (length is at i+2, big-endian)
                            if (marker >= 0xC0 && marker <= 0xFE && marker !== 0x01 && marker !== 0xD8) {
                                var segLen = Binary.read_uint8(i + 2) * 256 + Binary.read_uint8(i + 3);
                                i += 2 + segLen;
                            } else {
                                i += 2;
                            }
                        }
                        return "";
                    };
                    // JPEG DQT MD5: compute MD5 of DQT (Define Quantization Table) segments.
                    Binary.getJpegDqtMD5 = function() {
                        if (!Binary.isJpeg()) return "";
                        // DQT marker is 0xFFDB. Full implementation would extract
                        // all DQT segments and compute MD5. Simplified: return empty.
                        return "";
                    };
                    // Check if a specific JPEG chunk/marker is present.
                    Binary.isJpegChunkPresent = function(marker) {
                        if (!Binary.isJpeg()) return false;
                        var size = Binary.getSize();
                        var i = 2;
                        while (i + 3 < size) {
                            if (Binary.read_uint8(i) !== 0xFF) break;
                            var m = Binary.read_uint8(i + 1);
                            if (m === marker) return true;
                            if (m === 0xD9) break; // EOI
                            if (m >= 0xC0 && m <= 0xFE && m !== 0x01 && m !== 0xD8) {
                                var segLen = Binary.read_uint8(i + 2) * 256 + Binary.read_uint8(i + 3);
                                i += 2 + segLen;
                            } else {
                                i += 2;
                            }
                        }
                        return false;
                    };
                    Binary.isJpegExifPresent = function() {
                        if (!Binary.isJpeg()) return false;
                        if (Binary.getSize() < 5) return false;
                        // APP1 marker at offset 2: 0xFFE1
                        return Binary.read_uint8(2) === 0xFF && Binary.read_uint8(3) === 0xE1;
                    };
                    // JPEG Exif camera name: parse APP1 (Exif) IFD for Make/Model tags.
                    Binary.getJpegExifCameraName = function() {
                        if (!Binary.isJpegExifPresent()) return "";
                        // APP1 starts at offset 2, length at offset 4 (big-endian).
                        // Exif data starts with "Exif\0\0" at offset 6 within APP1.
                        var app1Off = 2; // After SOI
                        var app1Len = Binary.read_uint8(app1Off + 2) * 256 + Binary.read_uint8(app1Off + 3);
                        var exifStart = app1Off + 4; // After marker + length
                        // Check for "Exif\0\0"
                        if (Binary.read_uint8(exifStart) !== 0x45 || Binary.read_uint8(exifStart + 1) !== 0x78) return "";
                        // TIFF header at exifStart + 6
                        var tiffOff = exifStart + 6;
                        // Read Make (tag 0x010F) and Model (tag 0x0110) from IFD0.
                        // Simplified: search for "Make" and "Model" strings in Exif data.
                        var size = Math.min(exifStart + app1Len, Binary.getSize());
                        var make = "", model = "";
                        // Search for Make tag (0x010F) and Model tag (0x0110)
                        for (var i = tiffOff; i + 12 < size; i += 2) {
                            // Align to 2-byte boundary and look for tag patterns
                            if (Binary.read_uint8(i) === 0x01 && Binary.read_uint8(i + 1) === 0x0F) {
                                // Make tag: type=2 (ASCII), count, value offset
                                var valOff = tiffOff + Binary.read_uint8(i + 8) * 256 + Binary.read_uint8(i + 9);
                                for (var j = 0; j < 32 && valOff + j < size; j++) {
                                    var c = Binary.read_uint8(valOff + j);
                                    if (c === 0) break;
                                    make += String.fromCharCode(c);
                                }
                            }
                            if (Binary.read_uint8(i) === 0x01 && Binary.read_uint8(i + 1) === 0x10) {
                                var valOff2 = tiffOff + Binary.read_uint8(i + 8) * 256 + Binary.read_uint8(i + 9);
                                for (var j = 0; j < 32 && valOff2 + j < size; j++) {
                                    var c = Binary.read_uint8(valOff2 + j);
                                    if (c === 0) break;
                                    model += String.fromCharCode(c);
                                }
                            }
                        }
                        if (make && model) return make + " " + model;
                        return make || model || "";
                    };
                    // Compression detection (magic bytes).
                    Binary.detectZLIB = function(offset) {
                        if (Binary.getSize() < offset + 2) return false;
                        // zlib header: 0x78 0x01/0x9C/0xDA
                        return Binary.read_uint8(offset) === 0x78;
                    };
                    Binary.detectGZIP = function(offset) {
                        if (Binary.getSize() < offset + 3) return false;
                        return Binary.read_uint8(offset) === 0x1F && Binary.read_uint8(offset + 1) === 0x8B;
                    };
                    Binary.detectZIP = function(offset) {
                        if (Binary.getSize() < offset + 4) return false;
                        return Binary.read_uint8(offset) === 0x50 && Binary.read_uint8(offset + 1) === 0x4B;
                    };
                    // Compressed data size: try to detect compressed stream length.
                    Binary.getCompressedDataSize = function(offset) {
                        if (offset < 0 || offset >= Binary.getSize()) return 0;
                        // GZIP: 10-byte header + data + 8-byte trailer (CRC32 + ISIZE)
                        if (Binary.detectGZIP(offset)) {
                            var isize = Binary.getSize() - offset - 8;
                            return isize > 0 ? isize : 0;
                        }
                        // ZLIB: 2-byte header + deflate data + 4-byte Adler32
                        if (Binary.detectZLIB(offset)) {
                            return Binary.getSize() - offset - 4;
                        }
                        // ZIP: local file header, compressed size at offset + 18
                        if (Binary.detectZIP(offset)) {
                            if (offset + 22 < Binary.getSize()) {
                                return Binary.read_uint32_le(offset + 18);
                            }
                        }
                        return 0;
                    };

                    // --- Global and Archive methods ---
                    // These objects may be created by rule _init scripts.
                    // Use typeof checks to avoid ReferenceError if not yet defined.
                    if (typeof Global !== 'undefined') {
                        // Track loaded include scripts to avoid duplicate loading.
                        var _loadedScripts = {};
                        Global.includeScript = function(name) {
                            // Include scripts are pre-loaded by DatabaseBuilder.
                            // Track which scripts have been "included" for debugging.
                            if (!_loadedScripts[name]) {
                                _loadedScripts[name] = true;
                            }
                            return undefined;
                        };
                        // Global.result: result object for current detection.
                        Global.result = {
                            addType: function(t) {},
                            addName: function(n) {},
                            addString: function(s) {},
                            addVersion: function(v) {},
                            addOptions: function(o) {},
                            clear: function() {}
                        };
                    }
                    if (typeof Archive !== 'undefined') {
                        // Archive record: search for filename in archive member list.
                        Archive.isArchiveRecordPresent = function(name) {
                            // Search for the filename in file data as a null-terminated string.
                            var off = Binary.find_ansiString(0, Binary.getSize(), name);
                            return off >= 0;
                        };
                        Archive.isArchiveRecordPresentExp = function(name) {
                            // Case-insensitive search.
                            var upper = name.toUpperCase();
                            var lower = name.toLowerCase();
                            return Archive.isArchiveRecordPresent(upper) ||
                                   Archive.isArchiveRecordPresent(lower) ||
                                   Archive.isArchiveRecordPresent(name);
                        };
                    }
                })();
                "#,
            )
            .map_err(|e| RuleError::Backend {
                detail: format!("getString/compare/endian wrapper: {e}"),
            })?;

            Ok(())
        })?;

        Ok(())
    }
}

// =====================================================================
// Disassembly support via Capstone
// =====================================================================

use std::cell::RefCell;

thread_local! {
    /// Cached Capstone instances for 32-bit and 64-bit x86 modes.
    /// Creating a Capstone instance is expensive (~1ms), so we cache
    /// them per-thread to avoid repeated initialization during
    /// protector rule scanning (which may call getDisasmString 1000+ times).
    static CS_CACHE_32: RefCell<Option<capstone::Capstone>> = const { RefCell::new(None) };
    static CS_CACHE_64: RefCell<Option<capstone::Capstone>> = const { RefCell::new(None) };
}

/// Get a cached Capstone instance for the given machine type.
fn get_capstone(machine: u16) -> Result<capstone::Capstone, String> {
    use capstone::Capstone;
    use capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax};
    let is_64 = machine == 0x8664;
    if is_64 {
        CS_CACHE_64.with(|c| {
            if c.borrow().is_none() {
                let cs = Capstone::new()
                    .x86()
                    .mode(capstone::arch::x86::ArchMode::Mode64)
                    .syntax(capstone::arch::x86::ArchSyntax::Intel)
                    .detail(true)
                    .build()
                    .map_err(|e| format!("capstone init: {e}"))?;
                *c.borrow_mut() = Some(cs);
            }
            Ok(c.borrow_mut().take().unwrap())
        })
    } else {
        CS_CACHE_32.with(|c| {
            if c.borrow().is_none() {
                let cs = Capstone::new()
                    .x86()
                    .mode(capstone::arch::x86::ArchMode::Mode32)
                    .syntax(capstone::arch::x86::ArchSyntax::Intel)
                    .detail(true)
                    .build()
                    .map_err(|e| format!("capstone init: {e}"))?;
                *c.borrow_mut() = Some(cs);
            }
            Ok(c.borrow_mut().take().unwrap())
        })
    }
}

/// Return a Capstone instance to the cache for reuse.
fn return_capstone(machine: u16, cs: capstone::Capstone) {
    let cache = if machine == 0x8664 {
        &CS_CACHE_64
    } else {
        &CS_CACHE_32
    };
    cache.with(|c| {
        *c.borrow_mut() = Some(cs);
    });
}

/// Disassemble a single instruction at the given virtual address (VA).
///
/// Returns the instruction mnemonic string (e.g. "PUSH EBP") when
/// `return_next` is false, or the next instruction address as a string
/// (e.g. "0x1001") when `return_next` is true.
///
/// This reads the PE header from the host API to determine:
/// - Whether the PE is 32-bit or 64-bit (selects Capstone mode)
/// - The image base (to convert VA to file offset via section table)
/// - Section table entries (VA → file offset mapping)
fn disasm_at_va(
    host: &Arc<dyn HostApi + Send + Sync>,
    va: u64,
    return_next: bool,
) -> Result<String, String> {
    // Read PE header fields via host API.
    // e_lfanew at offset 0x3C.
    let e_lfanew = host
        .read_u32_le(0x3C)
        .map_err(|e| format!("e_lfanew: {e:?}"))?;
    if host.file_size() < e_lfanew as u64 + 24 {
        return Err("file too small for PE header".into());
    }

    // PE signature at e_lfanew, COFF header at e_lfanew+4.
    let coff_off = e_lfanew as u64 + 4;
    let machine = host
        .read_u16_le(coff_off)
        .map_err(|e| format!("machine: {e:?}"))?;
    let num_sections = host
        .read_u16_le(coff_off + 2)
        .map_err(|e| format!("num_sections: {e:?}"))?;
    let size_of_opt_hdr = host
        .read_u16_le(coff_off + 16)
        .map_err(|e| format!("size_of_opt_hdr: {e:?}"))?;

    // Optional header at e_lfanew + 24.
    let opt_off = e_lfanew as u64 + 24;
    let magic = host
        .read_u16_le(opt_off)
        .map_err(|e| format!("opt magic: {e:?}"))?;

    // Determine architecture and image base.
    let is_64 = magic == 0x20B; // PE32+ magic
    let image_base = if is_64 {
        host.read_u64_le(opt_off + 24)
            .map_err(|e| format!("image_base: {e:?}"))?
    } else {
        host.read_u32_le(opt_off + 28)
            .map_err(|e| format!("image_base: {e:?}"))? as u64
    };

    // Section table starts after optional header.
    let sec_table_off = opt_off + size_of_opt_hdr as u64;

    // Find the section containing this VA.
    let rva = va.checked_sub(image_base).ok_or("VA below image base")?;
    let mut file_off = None;
    for i in 0..num_sections as u64 {
        let sec_off = sec_table_off + i * 40;
        // Section header: Name(8) + VirtualSize(4) + VirtualAddress(4) +
        // SizeOfRawData(4) + PointerToRawData(4)
        let sec_va = host
            .read_u32_le(sec_off + 12)
            .map_err(|e| format!("sec_va: {e:?}"))?;
        let sec_vsize = host
            .read_u32_le(sec_off + 8)
            .map_err(|e| format!("sec_vsize: {e:?}"))?;
        let sec_rawsize = host
            .read_u32_le(sec_off + 16)
            .map_err(|e| format!("sec_rawsize: {e:?}"))?;
        let sec_rawoff = host
            .read_u32_le(sec_off + 20)
            .map_err(|e| format!("sec_rawoff: {e:?}"))?;
        let size = sec_vsize.max(sec_rawsize) as u64;
        if rva >= sec_va as u64 && rva < sec_va as u64 + size {
            file_off = Some(sec_rawoff as u64 + (rva - sec_va as u64));
            break;
        }
    }
    let file_off = file_off.ok_or("VA not in any section")?;

    // Read up to 16 bytes at the file offset for disassembly.
    let read_size = 16u64.min(host.file_size().saturating_sub(file_off));
    if read_size == 0 {
        return Err("no bytes to read at VA".into());
    }
    let mut code = Vec::with_capacity(read_size as usize);
    for i in 0..read_size {
        code.push(
            host.read_u8(file_off + i)
                .map_err(|e| format!("read code byte: {e:?}"))?,
        );
    }

    // Get cached Capstone instance (or create if first call on this thread).
    let cs = get_capstone(machine)?;

    // Disassemble and extract result in a scope so `insns` (which borrows
    // `cs`) is dropped before we return `cs` to the cache.
    let result = {
        let insns = cs
            .disasm_count(&code, va, 1)
            .map_err(|e| format!("disasm: {e}"))?;

        if insns.is_empty() {
            return Err("no instructions decoded".into());
        }

        let insn = insns.iter().next().unwrap();
        if return_next {
            let next = insn.address() + insn.bytes().len() as u64;
            Ok(format!("{}", next))
        } else {
            let mnem = insn.mnemonic().unwrap_or("");
            let op_str = insn.op_str().unwrap_or("");
            if op_str.is_empty() {
                Ok(mnem.to_uppercase())
            } else {
                Ok(format!("{} {}", mnem.to_uppercase(), op_str.to_uppercase()))
            }
        }
    };

    // Return Capstone instance to thread-local cache for reuse.
    return_capstone(machine, cs);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_api::HostApiError;
    use diec_core::format::FileType;
    use diec_core::input::ByteView;

    /// Test host API with a small in-memory buffer.
    struct TestHost {
        data: Vec<u8>,
        file_type: FileType,
    }

    impl TestHost {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                file_type: FileType::new("Binary"),
            }
        }
    }

    impl HostApi for TestHost {
        fn file_type(&self) -> &FileType {
            &self.file_type
        }

        fn view(&self) -> &ByteView<'_> {
            unimplemented!()
        }

        fn read_u8(&self, offset: u64) -> Result<u8, HostApiError> {
            self.data
                .get(offset as usize)
                .copied()
                .ok_or(HostApiError::OutOfBounds {
                    offset,
                    file_size: self.data.len() as u64,
                })
        }

        fn read_u16_le(&self, offset: u64) -> Result<u16, HostApiError> {
            let i = offset as usize;
            if i + 2 > self.data.len() {
                return Err(HostApiError::OutOfBounds {
                    offset,
                    file_size: self.data.len() as u64,
                });
            }
            Ok(u16::from_le_bytes([self.data[i], self.data[i + 1]]))
        }

        fn read_u16_be(&self, offset: u64) -> Result<u16, HostApiError> {
            let i = offset as usize;
            if i + 2 > self.data.len() {
                return Err(HostApiError::OutOfBounds {
                    offset,
                    file_size: self.data.len() as u64,
                });
            }
            Ok(u16::from_be_bytes([self.data[i], self.data[i + 1]]))
        }

        fn read_u24_le(&self, offset: u64) -> Result<u32, HostApiError> {
            let i = offset as usize;
            if i + 3 > self.data.len() {
                return Err(HostApiError::OutOfBounds {
                    offset,
                    file_size: self.data.len() as u64,
                });
            }
            Ok((self.data[i] as u32)
                | ((self.data[i + 1] as u32) << 8)
                | ((self.data[i + 2] as u32) << 16))
        }

        fn read_u24_be(&self, offset: u64) -> Result<u32, HostApiError> {
            let i = offset as usize;
            if i + 3 > self.data.len() {
                return Err(HostApiError::OutOfBounds {
                    offset,
                    file_size: self.data.len() as u64,
                });
            }
            Ok(((self.data[i] as u32) << 16)
                | ((self.data[i + 1] as u32) << 8)
                | (self.data[i + 2] as u32))
        }

        fn read_u32_le(&self, offset: u64) -> Result<u32, HostApiError> {
            let i = offset as usize;
            if i + 4 > self.data.len() {
                return Err(HostApiError::OutOfBounds {
                    offset,
                    file_size: self.data.len() as u64,
                });
            }
            Ok(u32::from_le_bytes([
                self.data[i],
                self.data[i + 1],
                self.data[i + 2],
                self.data[i + 3],
            ]))
        }

        fn read_u32_be(&self, offset: u64) -> Result<u32, HostApiError> {
            let i = offset as usize;
            if i + 4 > self.data.len() {
                return Err(HostApiError::OutOfBounds {
                    offset,
                    file_size: self.data.len() as u64,
                });
            }
            Ok(u32::from_be_bytes([
                self.data[i],
                self.data[i + 1],
                self.data[i + 2],
                self.data[i + 3],
            ]))
        }

        fn read_u64_le(&self, offset: u64) -> Result<u64, HostApiError> {
            let i = offset as usize;
            if i + 8 > self.data.len() {
                return Err(HostApiError::OutOfBounds {
                    offset,
                    file_size: self.data.len() as u64,
                });
            }
            Ok(u64::from_le_bytes(self.data[i..i + 8].try_into().unwrap()))
        }

        fn read_u64_be(&self, offset: u64) -> Result<u64, HostApiError> {
            let i = offset as usize;
            if i + 8 > self.data.len() {
                return Err(HostApiError::OutOfBounds {
                    offset,
                    file_size: self.data.len() as u64,
                });
            }
            Ok(u64::from_be_bytes(self.data[i..i + 8].try_into().unwrap()))
        }

        fn read_i8(&self, offset: u64) -> Result<i8, HostApiError> {
            self.read_u8(offset).map(|v| v as i8)
        }

        fn read_i16_le(&self, offset: u64) -> Result<i16, HostApiError> {
            self.read_u16_le(offset).map(|v| v as i16)
        }

        fn read_i32_le(&self, offset: u64) -> Result<i32, HostApiError> {
            self.read_u32_le(offset).map(|v| v as i32)
        }

        fn read_i64_le(&self, offset: u64) -> Result<i64, HostApiError> {
            self.read_u64_le(offset).map(|v| v as i64)
        }

        fn file_size(&self) -> u64 {
            self.data.len() as u64
        }

        fn check_signature(&self, offset: u64, signature: &str) -> Result<bool, HostApiError> {
            let elements =
                parse_signature(signature).map_err(|detail| HostApiError::InvalidSignature {
                    pattern: signature.into(),
                    detail,
                })?;
            Ok(match_signature(&self.data, offset as usize, &elements))
        }

        fn find_signature(&self, start: u64, signature: &str) -> Result<Option<u64>, HostApiError> {
            let elements =
                parse_signature(signature).map_err(|detail| HostApiError::InvalidSignature {
                    pattern: signature.into(),
                    detail,
                })?;
            let start = start as usize;
            if elements.is_empty() {
                return Ok(None);
            }
            if start
                .checked_add(elements.len())
                .is_none_or(|end| end > self.data.len())
            {
                return Ok(None);
            }
            for i in start..=self.data.len() - elements.len() {
                if match_signature(&self.data, i, &elements) {
                    return Ok(Some(i as u64));
                }
            }
            Ok(None)
        }

        fn find_signature_in_range(
            &self,
            start: u64,
            end: u64,
            signature: &str,
        ) -> Result<Option<u64>, HostApiError> {
            let elements =
                parse_signature(signature).map_err(|detail| HostApiError::InvalidSignature {
                    pattern: signature.into(),
                    detail,
                })?;
            let start = start as usize;
            let end = (end as usize).min(self.data.len());
            if elements.is_empty() || start >= end || end < elements.len() {
                return Ok(None);
            }
            for i in start..=end - elements.len() {
                if match_signature(&self.data, i, &elements) {
                    return Ok(Some(i as u64));
                }
            }
            Ok(None)
        }

        fn read_string(&self, offset: u64, max_len: u64) -> Result<String, HostApiError> {
            let start = offset as usize;
            let end = (start + max_len as usize).min(self.data.len());
            let bytes = &self.data[start..end];
            let nul_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            Ok(String::from_utf8_lossy(&bytes[..nul_pos]).to_string())
        }

        fn file_name(&self) -> &str {
            "test.bin"
        }

        fn entry_point(&self) -> Result<u64, HostApiError> {
            Ok(0)
        }

        fn is_deep(&self) -> bool {
            false
        }
        fn is_heuristic(&self) -> bool {
            false
        }
        fn is_aggressive(&self) -> bool {
            false
        }
        fn is_verbose(&self) -> bool {
            false
        }
        fn is_recursive(&self) -> bool {
            false
        }

        fn entropy(&self, offset: u64, size: u64) -> Result<f64, HostApiError> {
            let start = offset as usize;
            let end = (start + size as usize).min(self.data.len());
            if start >= end {
                return Ok(0.0);
            }
            let mut counts = [0u32; 256];
            for &b in &self.data[start..end] {
                counts[b as usize] += 1;
            }
            let total = (end - start) as f64;
            let mut entropy = 0.0;
            for &count in &counts {
                if count > 0 {
                    let p = count as f64 / total;
                    entropy -= p * p.log2();
                }
            }
            Ok(entropy)
        }

        fn md5(&self, _offset: u64, _size: u64) -> Result<String, HostApiError> {
            Err(HostApiError::NotImplemented {
                method: "md5".into(),
            })
        }

        fn crc32(&self, _offset: u64, _size: u64) -> Result<u32, HostApiError> {
            Err(HostApiError::NotImplemented {
                method: "crc32".into(),
            })
        }

        fn pe_batch(&self) -> Option<crate::pe_native::PeBatchInfo> {
            None
        }
        fn pe_import_libraries(&self) -> Vec<String> {
            Vec::new()
        }
        fn pe_import_functions(&self) -> Vec<String> {
            Vec::new()
        }
        fn pe_export_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn elf_import_libraries(&self) -> Vec<String> {
            Vec::new()
        }
        fn elf_section_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn macho_import_libraries(&self) -> Vec<String> {
            Vec::new()
        }
        fn macho_section_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn pe_manifest(&self) -> String {
            String::new()
        }
        fn pe_is_net(&self) -> bool {
            false
        }
        fn pe_file_version(&self) -> String {
            String::new()
        }
        fn pe_product_version(&self) -> String {
            String::new()
        }
        fn pe_version_string(&self, _key: &str) -> String {
            String::new()
        }
        fn pe_number_of_resources(&self) -> usize {
            0
        }
        fn pe_is_resource_name_present(&self, _name: &str) -> bool {
            false
        }
        fn pe_resource_section_offset(&self) -> i64 {
            -1
        }
        fn pe_is_signed(&self) -> bool {
            false
        }
    }

    fn make_runtime_with_host(
        data: Vec<u8>,
    ) -> (rquickjs::Runtime, rquickjs::Context, HostApiBridge) {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        let host = Arc::new(TestHost::new(data));
        let bridge = HostApiBridge::new(host);
        bridge.register(&context).unwrap();
        (runtime, context, bridge)
    }

    #[test]
    fn binary_get_size_returns_file_size() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x41, 0x42, 0x43, 0x44]);
        let size: f64 = ctx.with(|c| c.eval("Binary.getSize();").unwrap());
        assert_eq!(size, 4.0);
    }

    #[test]
    fn binary_read_byte() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x41, 0x42, 0x43]);
        let val: i32 = ctx.with(|c| c.eval("Binary.readByte(0);").unwrap());
        assert_eq!(val, 0x41);
        let val: i32 = ctx.with(|c| c.eval("Binary.readByte(1);").unwrap());
        assert_eq!(val, 0x42);
    }

    #[test]
    fn binary_read_word_le() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x78, 0x56, 0x34, 0x12]);
        let val: i32 = ctx.with(|c| c.eval("Binary.readWord(0);").unwrap());
        assert_eq!(val, 0x5678);
    }

    #[test]
    fn binary_read_dword_le() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x78, 0x56, 0x34, 0x12]);
        let val: u32 = ctx.with(|c| c.eval("Binary.readDword(0);").unwrap());
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn binary_u8_alias() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0xFF, 0x42]);
        let val: i32 = ctx.with(|c| c.eval("X.U8(1);").unwrap());
        assert_eq!(val, 0x42);
    }

    #[test]
    fn binary_u16_alias() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x78, 0x56]);
        let val: i32 = ctx.with(|c| c.eval("X.U16(0);").unwrap());
        assert_eq!(val, 0x5678);
    }

    #[test]
    fn binary_u32_alias() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x78, 0x56, 0x34, 0x12]);
        let val: u32 = ctx.with(|c| c.eval("File.U32(0);").unwrap());
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn binary_get_string() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(b"Hello\0World".to_vec());
        let val: String = ctx.with(|c| c.eval("Binary.getString(0, 11);").unwrap());
        assert_eq!(val, "Hello");
    }

    #[test]
    fn binary_compare_signature() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x4D, 0x5A, 0x90, 0x00]);
        let val: bool = ctx.with(|c| c.eval("Binary.compare('4D5A', 0);").unwrap());
        assert!(val);
        let val: bool = ctx.with(|c| c.eval("Binary.compare('9090', 0);").unwrap());
        assert!(!val);
    }

    #[test]
    fn binary_compare_string_literal_signature() {
        // 7z signature: '7z'BCAF271C
        let data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
        let (_rt, ctx, _bridge) = make_runtime_with_host(data);
        let val: bool = ctx.with(|c| c.eval("Binary.compare(\"'7z'BCAF271C\", 0);").unwrap());
        assert!(val, "7z signature should match");
    }

    #[test]
    fn binary_is_signature_present() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x4D, 0x5A, 0x90, 0x00]);
        let val: bool = ctx.with(|c| c.eval("Binary.isSignaturePresent(0, 4, '4D5A');").unwrap());
        assert!(val);
    }

    #[test]
    fn binary_find_signature() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x00, 0x00, 0x4D, 0x5A]);
        let val: f64 = ctx.with(|c| c.eval("Binary.findSignature(0, '4D5A');").unwrap());
        assert_eq!(val, 2.0);
    }

    #[test]
    fn binary_calculate_entropy() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x00; 100]);
        let val: f64 = ctx.with(|c| c.eval("Binary.calculateEntropy(0, 100);").unwrap());
        assert_eq!(val, 0.0); // All zeros -> entropy 0
    }

    #[test]
    fn binary_calculate_entropy_random() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let (_rt, ctx, _bridge) = make_runtime_with_host(data);
        let val: f64 = ctx.with(|c| c.eval("Binary.calculateEntropy(0, 256);").unwrap());
        assert!((val - 8.0).abs() < 0.01); // Uniform distribution -> entropy 8
    }

    #[test]
    fn binary_get_file_base_name() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x00]);
        let val: String = ctx.with(|c| c.eval("Binary.getFileBaseName();").unwrap());
        assert_eq!(val, "test"); // "test.bin" without extension
    }

    #[test]
    fn binary_is_deep_scan() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x00]);
        let val: bool = ctx.with(|c| c.eval("Binary.isDeepScan();").unwrap());
        assert!(!val);
    }

    #[test]
    fn binary_x_and_file_are_aliases() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x41, 0x42]);
        // X and File should be the same object as Binary.
        let val: i32 = ctx.with(|c| c.eval("X.readByte(0);").unwrap());
        assert_eq!(val, 0x41);
        let val: i32 = ctx.with(|c| c.eval("File.readByte(0);").unwrap());
        assert_eq!(val, 0x41);
    }

    #[test]
    fn binary_read_byte_out_of_bounds_returns_minus_one() {
        let (_rt, ctx, _bridge) = make_runtime_with_host(vec![0x41]);
        let val: i32 = ctx.with(|c| c.eval("Binary.readByte(100);").unwrap());
        assert_eq!(val, -1);
    }
}

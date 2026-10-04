//! XBinary signature-string semantics ported from upstream `xbinary.cpp`
//! (`getSignature`, `convertSignature`, `compareSignatureStrings`,
//! `getStringCustomCRC32`).

/// Convert a signature string per `XBinary::convertSignature`:
/// spaces are dropped, `?` becomes `.`, `'ansi'` literals are expanded to
/// lowercase hex, and remaining characters are lowercased.
/// Returns `None` on unbalanced quotes or non-Latin-1 chars inside quotes.
pub fn convert_signature(sig: &str) -> Option<String> {
    let mut out = String::with_capacity(sig.len());
    let mut in_ansi = false;
    for c in sig.chars() {
        if c == '\'' {
            in_ansi = !in_ansi;
            continue;
        }
        if in_ansi {
            if !c.is_ascii() {
                return None;
            }
            let v = c as u8;
            out.push(char::from(b"0123456789abcdef"[(v >> 4) as usize]));
            out.push(char::from(b"0123456789abcdef"[(v & 0xF) as usize]));
        } else if c == ' ' {
            continue;
        } else if c == '?' {
            out.push('.');
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    if in_ansi {
        return None;
    }
    Some(out)
}

/// Port of `XBinary::compareSignatureStrings`: character-wise prefix match,
/// `.` is a wildcard on either side; the base (file) signature must be at
/// least as long as the pattern.
pub fn compare_signature_strings(base: &str, pattern: &str) -> bool {
    let base = match convert_signature(base) {
        Some(s) => s,
        None => return false,
    };
    let opt = match convert_signature(pattern) {
        Some(s) => s,
        None => return false,
    };
    if base.len() < opt.len() || opt.is_empty() {
        return false;
    }
    base.chars()
        .zip(opt.chars())
        .all(|(a, b)| a == '.' || b == '.' || a == b)
}

/// Hex string of the first `size` bytes at `offset` (uppercase, matching
/// `XBinary::getSignature`).
pub fn get_signature(data: &[u8], offset: usize, size: usize) -> String {
    if offset >= data.len() || size == 0 {
        return String::new();
    }
    let end = offset.saturating_add(size).min(data.len());
    data[offset..end]
        .iter()
        .map(|b| {
            char::from(b"0123456789ABCDEF"[(b >> 4) as usize]).to_string()
                + &char::from(b"0123456789ABCDEF"[(b & 0xF) as usize]).to_string()
        })
        .collect()
}

/// Port of `XBinary::getStringCustomCRC32`: CRC32C polynomial (0x82f63b78)
/// over UTF-8 bytes, initial value 0, final complement.
pub fn string_custom_crc32(s: &str) -> u32 {
    let mut crc = 0u32;
    for &b in s.as_bytes() {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_ansi_literal() {
        assert_eq!(convert_signature("'MZ'3500"), Some("4d5a3500".to_string()));
        assert_eq!(convert_signature("'MZ'"), Some("4d5a".to_string()));
        assert_eq!(convert_signature(" 4D 5A "), Some("4d5a".to_string()));
        assert_eq!(convert_signature("'MZ'??90"), Some("4d5a..90".to_string()));
        assert_eq!(convert_signature("'unterminated"), None);
    }

    #[test]
    fn compare_prefix_and_wildcards() {
        // Base comes from getSignature (uppercase); pattern is a record sig.
        assert!(compare_signature_strings(
            "D0CF11E0A1B11AE1",
            "D0CF11E0A1B11AE1"
        ));
        assert!(compare_signature_strings("B2C3C3D4E5", "....c3d4"));
        assert!(compare_signature_strings("A1B2C3D4E5", "a1b2"));
        assert!(!compare_signature_strings("A1B2", "a1b2c3")); // pattern longer
        assert!(!compare_signature_strings("A1B2", "a1b3"));
    }

    #[test]
    fn crc32_custom() {
        // getStringCustomCRC32("KERNEL32.DLL AddAtomA")-style check: just verify
        // deterministic properties (init 0, final complement, CRC32C poly).
        assert_eq!(string_custom_crc32(""), 0xFFFF_FFFF);
        assert_ne!(string_custom_crc32("a"), string_custom_crc32("b"));
        assert_eq!(string_custom_crc32("abc"), string_custom_crc32("abc"));
    }
}

//! Port of `NFDCompression` — compressed-stream recognizers that prove
//! the payload by decoding or validating its bitstream: PowerPacker
//! (PP20/PPLS), LZMA-alone, and (upstream-only for now) the
//! XAncientDecoder family RNC/TPWM/pack/Freeze.
//!
//! `ancient` is not ported yet: it requires a full decoder for four
//! formats upstream resolves through XAncientDecoder. See
//! `docs/design/` notes — PowerPacker and LZMA cover every corpus hit.

use crate::gen_names::{ft, name as n, rtype as rt};
use crate::scans::{ResultMaps, ScanRecord};

const MAX_PACKED: u64 = 4 * 1024 * 1024;
const MAX_OUTPUT: u64 = 16 * 1024 * 1024;

/// `add` — emit an `FT_ARCHIVE`/`RECORD_TYPE_FORMAT` record with a
/// `sName` display override into `mapResultArchives`.
fn add(res: &mut ResultMaps, name: u16, custom_name: &'static str, detail: &str) -> bool {
    let rec = ScanRecord {
        name,
        rtype: rt::RECORD_TYPE_FORMAT,
        ft: ft::FT_ARCHIVE,
        variant: 0,
        version: String::new(),
        info: detail.to_string(),
        heuristic: false,
        unknown: false,
        sname: Some(std::borrow::Cow::Borrowed(custom_name)),
        stype: None,
    };
    res.archives.insert(rec.name, rec);
    true
}

/// `powerPacker` — validate the backward bitstream of PP20/PPLS without
/// reconstructing its bytes.
fn power_packer(data: &[u8], res: &mut ResultMaps) -> bool {
    let is_ppls = data.starts_with(b"PPLS");
    let min_len = if is_ppls { 17 } else { 13 };
    if data.len() < min_len || !(is_ppls || data.starts_with(b"PP20")) {
        return false;
    }
    let mode_base = if is_ppls { 8 } else { 4 };
    let mode = u32::from_be_bytes(
        data[mode_base..mode_base + 4]
            .try_into()
            .unwrap_or_default(),
    );
    if ![0x09090909, 0x090A0A0A, 0x090A0B0B, 0x090A0C0C, 0x090A0C0D].contains(&mode) {
        return false;
    }
    let trailer = u32::from_be_bytes(data[data.len() - 4..].try_into().unwrap_or_default());
    let output_size = trailer >> 8;
    if output_size == 0 || u64::from(output_size) > MAX_OUTPUT || (trailer & 0xff) > 31 {
        return false;
    }
    let header_size = mode_base + 4;
    let mut cursor: i64 = data.len() as i64 - 5;
    let mut bit = 0u32;
    // Reads the PowerPacker stream backwards, advancing cursor/bit.
    macro_rules! read_bits {
        ($count:expr, $value:ident) => {{
            $value = 0u32;
            for _ in 0..$count {
                if cursor < 8 {
                    return false;
                }
                $value = ($value << 1) | (((data[cursor as usize] >> bit) & 1) as u32);
                bit += 1;
                if bit == 8 {
                    bit = 0;
                    cursor -= 1;
                }
            }
        }};
    }
    let mut value;
    read_bits!(trailer & 0xff, value);
    let mut produced = 0u32;
    // A reference is legal only when its source has already been produced.
    while produced < output_size {
        read_bits!(1, value);
        if value == 0 {
            let mut count = 1u32;
            loop {
                read_bits!(2, value);
                if value > output_size - produced - count {
                    return false;
                }
                count += value;
                if value != 3 {
                    break;
                }
            }
            for _ in 0..count {
                read_bits!(8, value);
            }
            produced += count;
            if produced == output_size {
                break;
            }
        }
        let mut mode_index: u32;
        let mut distance: u32;
        let mut count;
        read_bits!(2, mode_index);
        let mut width = u32::from(*data.get(mode_base + mode_index as usize).unwrap_or(&0));
        if mode_index == 3 {
            read_bits!(1, value);
            if value == 0 {
                width = 7;
            }
            read_bits!(width, distance);
            count = 5;
            if count > output_size - produced {
                return false;
            }
            loop {
                read_bits!(3, value);
                if value > output_size - produced - count {
                    return false;
                }
                count += value;
                if value != 7 {
                    break;
                }
            }
        } else {
            count = mode_index + 2;
            read_bits!(width, distance);
            if count > output_size - produced {
                return false;
            }
        }
        if u64::from(distance) >= u64::from(produced) {
            return false;
        }
        produced += count;
    }
    // Only alignment bits may precede the consumed stream.
    if (cursor - (header_size as i64 - 1)) * 8 - bit as i64 > 31 {
        return false;
    }
    add(
        res,
        n::RECORD_NAME_UNKNOWN,
        if is_ppls {
            "PowerPacker (PPLS)"
        } else {
            "PowerPacker (PP20)"
        },
        &format!("bitstream structure verified, {output_size} bytes unpacked"),
    )
}

/// `lzma` — LZMA-alone stream: plausible property bytes + dictionary
/// prefilter, then a full decode to prove the stream.
fn lzma(data: &[u8], res: &mut ResultMaps) -> bool {
    if data.len() < 18 || data[0] >= 225 || data[13] != 0 {
        return false;
    }
    let dictionary = u32::from_le_bytes(data[1..5].try_into().unwrap_or_default());
    // Plausible encoder dictionaries only as a prefilter; the complete
    // stream decode below is required for recognition.
    if dictionary < 4096
        || u64::from(dictionary) > MAX_OUTPUT
        || ((dictionary & (dictionary - 1)) != 0
            && (dictionary < 3 * 1024 * 1024 || (dictionary & 0xfffff) != 0))
    {
        return false;
    }
    let declared = u64::from_le_bytes(data[5..13].try_into().unwrap_or_default());
    let unknown_size = declared == u64::MAX;
    if !unknown_size && declared > MAX_OUTPUT {
        return false;
    }
    // LZMA-alone: properties (1B) + dictionary (4B) + size (8B), then the
    // compressed stream. lzma-rs decodes from the 13-byte header.
    let mut decoded: Vec<u8> = Vec::new();
    let decoded_len = {
        let stream = data;
        match lzma_rs::lzma_decompress(&mut std::io::Cursor::new(stream), &mut decoded) {
            Ok(()) => decoded.len() as u64,
            Err(_) => return false,
        }
    };
    if decoded_len > MAX_OUTPUT || (!unknown_size && decoded_len != declared) {
        return false;
    }
    add(
        res,
        n::RECORD_NAME_LZMA,
        "LZMA",
        &format!(
            "LZMA-alone stream verified, {decoded_len} bytes unpacked, {dictionary}-byte dictionary"
        ),
    )
}

/// `NFDCompression::detect` — bounded header prefilter then the full
/// validator for the recognized family.
pub fn detect(d: &[u8], res: &mut ResultMaps) -> bool {
    let size = d.len() as u64;
    if !(12..=MAX_PACKED).contains(&size) {
        return false;
    }
    let header = &d[..d.len().min(14)];
    if header.len() < 12 {
        return false;
    }
    let is_powerpacker = header.starts_with(b"PP20") || header.starts_with(b"PPLS");
    // XAncientDecoder family (RNC/TPWM/pack/Freeze) is not ported yet —
    // the upstream recognizer verifies with a full decode we cannot run.
    let dictionary = u32::from_le_bytes(header[1..5].try_into().unwrap_or_default());
    let possible_lzma = header.len() >= 14
        && header[0] < 225
        && header[13] == 0
        && (4096..=MAX_OUTPUT as u32).contains(&dictionary)
        && ((dictionary & (dictionary - 1)) == 0
            || (dictionary >= 3 * 1024 * 1024 && (dictionary & 0xfffff) == 0));
    if is_powerpacker {
        return power_packer(d, res);
    }
    if possible_lzma {
        return lzma(d, res);
    }
    false
}

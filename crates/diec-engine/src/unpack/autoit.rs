//! AutoIt (Aut2Exe) container extraction — port of upstream `XAUTOIT`.
//!
//! Three container flavors are supported, mirroring `_detect` +
//! `_parseV2`/`_parseEA05`/`_parseEA06`:
//! - **v2**: 16-byte GUID signature located via a trailing backlink
//!   DWORD (or a whole-file signature scan fallback), linear-congruential
//!   `_v2Decrypt`, `JB01` custom inflate (`_inflateV2`).
//! - **EA05**: `AU3!EA05` marker, MT19937-variant `_mtDecrypt`,
//!   `_u2a` UTF-16 name folding, `_inflate(bEA06=false)`.
//! - **EA06**: `AU3!EA06` marker, LAME-generator `aiLameDecrypt`,
//!   UTF-16LE names, `_inflate(bEA06=true)`.
//!
//! Output is a record list (`name`, `data`) — archive semantics rather
//! than the PE rebuild used by the compressor unpackers.

use super::UnpackError;

/// Upper bound for decrypted metadata blobs (upstream
/// `AI_V2_MAX_METADATA_SIZE`).
const MAX_METADATA: u64 = 1024 * 1024;
/// Per-record decompressed cap (upstream `256 * 1024 * 1024`).
const MAX_FILE: u64 = 256 * 1024 * 1024;
/// Total output cap across records.
const MAX_TOTAL: u64 = 512 * 1024 * 1024;
/// Upstream record-count bound.
const MAX_RECORDS: usize = 100000;

const V2_SIGNATURE: [u8; 16] = [
    0xa3, 0x48, 0x4b, 0xbe, 0x98, 0x6c, 0x4a, 0xa9, 0x99, 0x4c, 0x53, 0x0a, 0x86, 0xd6, 0x48, 0x7d,
];

/// One extracted AutoIt record.
#[derive(Debug, Clone)]
pub struct ContainerRecord {
    /// Sanitized member name (upstream `aiSafeRecordName` + fallbacks).
    pub name: String,
    /// Record payload (decoded and decompressed).
    pub data: Vec<u8>,
}

/// Detected AutoIt flavor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoItVersion {
    /// AutoIt v2 binary container.
    V2,
    /// `AU3!EA05` container.
    Ea05,
    /// `AU3!EA06` container.
    Ea06,
}

impl AutoItVersion {
    /// Upstream `sVersion` string.
    pub fn version_string(self) -> &'static str {
        match self {
            Self::V2 => "v2",
            Self::Ea05 => "EA05",
            Self::Ea06 => "EA06",
        }
    }
}

/// Detection metadata.
#[derive(Debug, Clone)]
pub struct AutoItInfo {
    /// Which container flavor matched.
    pub version: AutoItVersion,
    /// File offset of the container marker.
    pub marker_offset: usize,
}

fn rd32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

fn be32(d: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

// ---------------------------------------------------------------------------
// stream ciphers
// ---------------------------------------------------------------------------

/// `XAUTOIT::_v2Decrypt` — linear-congruential XOR stream.
fn v2_decrypt(buf: &mut [u8], mut seed: u32) {
    for b in buf.iter_mut() {
        seed = seed.wrapping_mul(214013).wrapping_add(2531011);
        *b ^= (seed >> 16) as u8;
    }
}

/// `XAUTOIT::_mtDecrypt` — MT19937 keystream variant (`r >> 1` byte).
fn mt_decrypt(buf: &mut [u8], seed: u32) {
    let mut mt = [0u32; 624];
    mt[0] = seed;
    for i in 1..624 {
        mt[i] = (i as u32).wrapping_add(0x6c078965u32.wrapping_mul((mt[i - 1] >> 30) ^ mt[i - 1]));
    }
    let mut items = 1u32;
    let mut next_idx = 0usize;
    for b in buf.iter_mut() {
        items -= 1;
        if items == 0 {
            items = 624;
            next_idx = 0;
            let mut i = 0usize;
            while i < 227 {
                mt[i] = ((((mt[i] ^ mt[i + 1]) & 0x7ffffffe) ^ mt[i]) >> 1)
                    ^ ((0u32.wrapping_sub(mt[i + 1] & 1)) & 0x9908b0df)
                    ^ mt[i + 397];
                i += 1;
            }
            while i < 623 {
                mt[i] = ((((mt[i] ^ mt[i + 1]) & 0x7ffffffe) ^ mt[i]) >> 1)
                    ^ ((0u32.wrapping_sub(mt[i + 1] & 1)) & 0x9908b0df)
                    ^ mt[i - 227];
                i += 1;
            }
            mt[623] = ((((mt[623] ^ mt[0]) & 0x7ffffffe) ^ mt[623]) >> 1)
                ^ ((0u32.wrapping_sub(mt[0] & 1)) & 0x9908b0df)
                ^ mt[i - 227];
        }
        let mut r = mt[next_idx];
        next_idx += 1;
        r ^= r >> 11;
        r ^= (r & 0xff3a58ad) << 7;
        r ^= (r & 0xffffdf8c) << 15;
        r ^= r >> 18;
        *b ^= (r >> 1) as u8;
    }
}

/// `AI_LAME_STATE` — EA06 LAME PRNG (rotl-based double-mantissa source).
struct LameState {
    index0: usize,
    index1: usize,
    values: [u32; 17],
}

impl LameState {
    fn new(mut seed: u32) -> Self {
        let mut st = Self {
            index0: 0,
            index1: 10,
            values: [0; 17],
        };
        for v in st.values.iter_mut() {
            seed = seed.wrapping_mul(0x53A9B4FB);
            seed = 1u32.wrapping_sub(seed);
            *v = seed;
        }
        for _ in 0..9 {
            st.push();
        }
        st
    }

    /// `aiLamePush` — one step; returns a mantissa-derived double in
    /// `[1,2)` minus one, exactly as upstream constructs it.
    fn push(&mut self) -> f64 {
        let rolled = self.values[self.index0]
            .rotate_left(9)
            .wrapping_add(self.values[self.index1].rotate_left(13));
        self.values[self.index0] = rolled;
        if self.index0 == 0 {
            self.index0 = 16;
        } else {
            self.index0 -= 1;
        }
        if self.index1 == 0 {
            self.index1 = 16;
        } else {
            self.index1 -= 1;
        }
        let bits = (u64::from(0x3ff00000u32 | (rolled >> 12)) << 32) | (u64::from(rolled) << 20);
        f64::from_bits(bits) - 1.0
    }

    fn next(&mut self) -> u8 {
        self.push();
        let v = (self.push() * 256.0) as i32;
        if v < 256 { v as u8 } else { 0xff }
    }
}

/// `aiLameDecrypt` — XOR stream via the LAME generator.
fn lame_decrypt(buf: &mut [u8], seed: u16) {
    let mut st = LameState::new(u32::from(seed));
    for b in buf.iter_mut() {
        *b ^= st.next();
    }
}

// ---------------------------------------------------------------------------
// custom inflate (MSB-first bit reader + literal/match loop)
// ---------------------------------------------------------------------------

/// `AI_BITREADER` — upstream's 16-bit-window MSB-first reader.
struct BitReader<'a> {
    input: &'a [u8],
    full: u32,
    bits_avail: u32,
    cur_input: usize,
    error: bool,
}

impl BitReader<'_> {
    /// `aiGetBits` — read `sz` bits (returns the consumed bits
    /// left-aligned count as upstream packs them).
    fn get_bits(&mut self, mut sz: u32) -> u32 {
        self.full &= 0x0000ffff;
        let remaining = (self.input.len() as u32).wrapping_sub(self.cur_input as u32);
        if sz > self.bits_avail && (sz - self.bits_avail - 1) / 16 + 1 > remaining / 2 {
            self.error = true;
            return 0;
        }
        while sz > 0 {
            if self.bits_avail == 0 {
                if self.cur_input + 2 > self.input.len() {
                    self.error = true;
                    return (self.full >> 16) & 0xffff;
                }
                let mut low = self.full & 0xffff;
                low |= u32::from(self.input[self.cur_input]) << 8;
                self.cur_input += 1;
                low |= u32::from(self.input[self.cur_input]);
                self.cur_input += 1;
                self.full = (self.full & 0xffff0000) | (low & 0xffff);
                self.bits_avail = 16;
            }
            self.full <<= 1;
            self.bits_avail -= 1;
            sz -= 1;
        }
        (self.full >> 16) & 0xffff
    }
}

/// `XAUTOIT::_inflate` — EA05/EA06 custom inflate (literal bit + match
/// distance/length trees). `ea06` inverts the literal flag.
fn inflate(input: &[u8], usize_out: usize, ea06: bool) -> Option<Vec<u8>> {
    let mut out = vec![0u8; usize_out];
    let mut cur = 0usize;
    let mut br = BitReader {
        input,
        full: 0,
        bits_avail: 0,
        cur_input: 8,
        error: false,
    };

    while !br.error && cur < usize_out {
        let mut b_copy = br.get_bits(1) != 0;
        if ea06 {
            b_copy = !b_copy;
        }
        if b_copy {
            let bb = br.get_bits(15) as usize;
            let mut bs = br.get_bits(2);
            let mut addme = 0u32;
            if bs == 3 {
                addme = 3;
                bs = br.get_bits(3);
                if bs == 7 {
                    addme = 10;
                    bs = br.get_bits(5);
                    if bs == 31 {
                        addme = 41;
                        bs = br.get_bits(8);
                        if bs == 255 {
                            addme = 296;
                            bs = br.get_bits(8);
                            while bs == 255 {
                                addme += 255;
                                bs = br.get_bits(8);
                                if br.error {
                                    return None;
                                }
                            }
                        }
                    }
                }
            }
            bs += 3 + addme;
            if br.error {
                break;
            }
            if bb == 0 || bb > cur || cur + bs as usize > usize_out {
                break;
            }
            for _ in 0..bs {
                out[cur] = out[cur - bb];
                cur += 1;
            }
        } else {
            if cur >= usize_out {
                break;
            }
            out[cur] = br.get_bits(8) as u8;
            cur += 1;
        }
    }

    if br.error || cur != usize_out {
        return None;
    }
    Some(out)
}

/// `XAUTOIT::_inflateV2` — `JB01` big-endian-size custom inflate
/// (13-bit distance / 4-bit length matches).
fn inflate_v2(input: &[u8], usize_out: usize) -> Option<Vec<u8>> {
    if input.len() < 8 || &input[..4] != b"JB01" || be32(input, 4) as usize != usize_out {
        return None;
    }
    let mut out = vec![0u8; usize_out];
    let mut n_out = 0usize;
    let mut br = BitReader {
        input,
        full: 0,
        bits_avail: 0,
        cur_input: 8,
        error: false,
    };
    while !br.error && n_out < usize_out {
        if br.get_bits(1) == 0 {
            out[n_out] = br.get_bits(8) as u8;
            n_out += 1;
            continue;
        }
        let distance = br.get_bits(13) as usize + 3;
        let length = br.get_bits(4) as usize + 3;
        if br.error || distance > n_out || n_out + length > usize_out {
            return None;
        }
        for _ in 0..length {
            out[n_out] = out[n_out - distance];
            n_out += 1;
        }
    }
    if br.error || n_out != usize_out {
        return None;
    }
    Some(out)
}

/// `XAUTOIT::_u2a` — fold a UTF-16LE-ish buffer to its low bytes when
/// it looks like UTF-16 (BOM or high ASCII density heuristic).
fn fold_u2a(buf: &[u8]) -> Vec<u8> {
    let len = buf.len();
    if len < 2 {
        return buf.to_vec();
    }
    let (src_off, n);
    if len > 4 && buf[0] == 0xff && buf[1] == 0xfe && buf[2] != 0 {
        src_off = 2;
        n = (len - 2) >> 1;
    } else {
        let j = if len > 20 { 20 } else { len & !1 };
        let mut cnt = 0u32;
        let mut i = 0;
        while i < j {
            if buf[i] != 0 && buf[i + 1] == 0 {
                cnt += 1;
            }
            i += 2;
        }
        if cnt * 4 < j as u32 {
            return buf.to_vec();
        }
        src_off = 0;
        n = len >> 1;
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n * 2 {
        if i % 2 == 0 {
            out.push(buf[src_off + i]);
        }
    }
    out
}

/// `aiSafeRecordName` — basename-only sanitization; `"."`/`".."` map
/// to empty so callers apply their fallback naming.
fn safe_record_name(name: &str) -> String {
    let mut s = name.replace('\\', "/");
    while s.ends_with('/') {
        s.pop();
    }
    if let Some(pos) = s.rfind('/') {
        s = s[pos + 1..].to_string();
    }
    if s == "." || s == ".." {
        return String::new();
    }
    s
}

/// `aiUtf16LeString` — decode UTF-16LE units until NUL; unpaired
/// surrogates map to U+FFFD (upstream keeps the raw `QChar`, which is
/// still inequal to every expected name so the loss is cosmetic).
fn utf16le_string(data: &[u8], chars: u32) -> String {
    if (chars as u64) * 2 != data.len() as u64 {
        return String::new();
    }
    let mut out = String::new();
    for i in 0..chars as usize {
        let v = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
        if v == 0 {
            break;
        }
        out.push(char::from_u32(u32::from(v)).unwrap_or('\u{fffd}'));
    }
    out
}

/// `QString::fromLatin1` equivalent — byte-by-byte mapping.
fn latin1(data: &[u8]) -> String {
    data.iter().map(|&b| b as char).collect()
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

/// `XAUTOIT::_detect` — v2 backlink/signature scan, then EA05/EA06
/// markers.
pub fn detect_autoit(data: &[u8]) -> Option<AutoItInfo> {
    if data.len() < 24 {
        return None;
    }

    // v2: trailing backlink DWORD -> signature + subtype byte 1.
    if data.len() >= 25 {
        let off = rd32(data, data.len() - 4) as usize;
        if off <= data.len() - 25
            && data
                .get(off..off + 17)
                .is_some_and(|h| h[..16] == V2_SIGNATURE && h[16] == 1)
        {
            return Some(AutoItInfo {
                version: AutoItVersion::V2,
                marker_offset: off,
            });
        }
    }

    // v2 fallback: scan the whole file for signature + subtype 1.
    if let Some(pos) = find_bytes(data, &V2_SIGNATURE)
        && pos + 16 < data.len()
        && data[pos + 16] == 1
    {
        return Some(AutoItInfo {
            version: AutoItVersion::V2,
            marker_offset: pos,
        });
    }

    if let Some(pos) = find_bytes(data, b"AU3!EA05") {
        return Some(AutoItInfo {
            version: AutoItVersion::Ea05,
            marker_offset: pos,
        });
    }
    find_bytes(data, b"AU3!EA06").map(|pos| AutoItInfo {
        version: AutoItVersion::Ea06,
        marker_offset: pos,
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// record parsers
// ---------------------------------------------------------------------------

/// `XAUTOIT::_parseV2` — v2 record walk. Empty list on any invalid
/// step (upstream returns the accumulated-but-discarded list only when
/// the walk lands exactly on the trailer).
fn parse_v2(data: &[u8], mut base: usize, output_limit: i64) -> Vec<ContainerRecord> {
    if data.len() < 25 || base > data.len() - 25 {
        return Vec::new();
    }
    let trailer = data.len() - 4;
    let mut records = Vec::new();
    let contains =
        |off: usize, len: u64| -> bool { off <= trailer && len <= (trailer - off) as u64 };

    // after signature
    base += V2_SIGNATURE.len();
    if data[base] != 1 {
        return Vec::new();
    }
    base += 1;
    if base + 4 > trailer {
        return Vec::new();
    }

    if !contains(base, 4) {
        return Vec::new();
    }
    let password_size = rd32(data, base) ^ 0xfac1;
    base += 4;
    if u64::from(password_size) > MAX_METADATA || !contains(base, u64::from(password_size)) {
        return Vec::new();
    }
    let mut password = data[base..base + password_size as usize].to_vec();
    if password_size != 0 {
        v2_decrypt(&mut password, 0xc3d2u32.wrapping_add(password_size));
    }
    base += password_size as usize;

    let mut password_sum: i64 = 0;
    for &c in &password {
        password_sum += (c as i8) as i64;
    }
    let data_seed = (password_sum + 0x22af) as u32;

    while base < trailer {
        if !contains(base, 4) {
            return Vec::new();
        }
        let mut marker = data[base..base + 4].to_vec();
        v2_decrypt(&mut marker, 0x16fa);
        if &marker != b"FILE" {
            return Vec::new();
        }
        base += 4;

        if !contains(base, 4) {
            return Vec::new();
        }
        let source_size = rd32(data, base) ^ 0x29bc;
        base += 4;
        if u64::from(source_size) > MAX_METADATA || !contains(base, u64::from(source_size)) {
            return Vec::new();
        }
        let mut source = data[base..base + source_size as usize].to_vec();
        if source_size != 0 {
            v2_decrypt(&mut source, 0xa25eu32.wrapping_add(source_size));
        }
        base += source_size as usize;

        if !contains(base, 4) {
            return Vec::new();
        }
        let name_size = rd32(data, base) ^ 0x29ac;
        base += 4;
        if u64::from(name_size) > MAX_METADATA || !contains(base, u64::from(name_size)) {
            return Vec::new();
        }
        let mut build_name = data[base..base + name_size as usize].to_vec();
        if name_size != 0 {
            v2_decrypt(&mut build_name, 0xf25eu32.wrapping_add(name_size));
        }
        base += name_size as usize;

        if !contains(base, 9) {
            return Vec::new();
        }
        let compression = data[base];
        base += 1;
        let compressed_size = rd32(data, base) ^ 0x45aa;
        base += 4;
        let uncompressed_size = rd32(data, base) ^ 0x45aa;
        base += 4;
        if (compression != 0 && compression != 1)
            || compressed_size > i32::MAX as u32
            || u64::from(uncompressed_size) > MAX_FILE
            || !contains(base, u64::from(compressed_size))
        {
            return Vec::new();
        }

        if output_limit >= 0 && u64::from(uncompressed_size) > output_limit as u64 {
            base += compressed_size as usize;
            continue;
        }

        let mut input = data[base..base + compressed_size as usize].to_vec();
        if compressed_size != 0 {
            v2_decrypt(&mut input, data_seed);
        }
        base += compressed_size as usize;

        let output = if compression == 1 {
            match inflate_v2(&input, uncompressed_size as usize) {
                Some(o) => o,
                None => return Vec::new(),
            }
        } else {
            if compressed_size != uncompressed_size {
                return Vec::new();
            }
            input
        };

        let source_str = latin1(&source);
        let build_str = latin1(&build_name);
        let mut name = if source_str.to_ascii_lowercase().contains("autoit script") {
            "autoit_script.aut".to_string()
        } else {
            safe_record_name(&source_str)
        };
        if name.is_empty() {
            name = safe_record_name(&build_str);
        }
        if name.is_empty() {
            name = format!("autoit_{:03}.bin", records.len());
        }
        if records.len() >= MAX_RECORDS {
            return Vec::new();
        }
        records.push(ContainerRecord { name, data: output });
    }

    if base != trailer {
        return Vec::new();
    }
    records
}

/// `XAUTOIT::_parseEA05` — EA05 record walk; tolerant loop that stops
/// at the first non-FILE block (upstream semantics).
fn parse_ea05(data: &[u8], mut base: usize, output_limit: i64) -> Vec<ContainerRecord> {
    let mut records = Vec::new();
    if base > data.len().saturating_sub(16) {
        return records;
    }

    let mut m4sum: u32 = 0;
    for i in 0..16 {
        m4sum = m4sum.wrapping_add(u32::from(data[base + i]));
    }
    base += 16;

    loop {
        if base + 8 > data.len() {
            break;
        }
        if rd32(data, base) != 0xceb06dff {
            break;
        }
        let s1 = (rd32(data, base + 4) ^ 0x29bc) as i32;
        if s1 < 0 {
            break;
        }
        base += 8;
        if base + s1 as usize > data.len() {
            break;
        }
        base += s1 as usize;

        if base + 4 > data.len() {
            break;
        }
        let s2 = (rd32(data, base) ^ 0x29ac) as i32;
        if s2 < 0 {
            break;
        }
        base += 4;
        if base + s2 as usize > data.len() {
            break;
        }
        let mut name = data[base..base + s2 as usize].to_vec();
        mt_decrypt(&mut name, (s2 as u32).wrapping_add(0xf25e));
        name = fold_u2a(&name);
        base += s2 as usize;

        if base + 13 > data.len() {
            break;
        }
        let comp = data[base];
        let csize = (rd32(data, base + 1) ^ 0x45aa) as i32;
        if csize < 0 {
            break;
        }
        if csize == 0 {
            base += 13 + 16;
            continue;
        }
        base += 13 + 16;
        if base + csize as usize > data.len() {
            break;
        }
        if comp != 1 && output_limit >= 0 && csize as u64 > output_limit as u64 {
            base += csize as usize;
            continue;
        }

        let mut input = data[base..base + csize as usize].to_vec();
        base += csize as usize;
        mt_decrypt(&mut input, 0x22afu32.wrapping_add(m4sum));

        let output = if comp == 1 {
            if csize < 8 || rd32(&input, 0) != 0x35304145 {
                continue;
            }
            let mut usize_out = be32(&input, 4);
            if usize_out == 0 {
                usize_out = csize as u32;
            }
            if u64::from(usize_out) > MAX_FILE
                || (output_limit >= 0 && u64::from(usize_out) > output_limit as u64)
            {
                continue;
            }
            match inflate(&input, usize_out as usize, false) {
                Some(o) => o,
                None => continue,
            }
        } else {
            input
        };

        if output.len() < 4 {
            continue;
        }
        let mut rec_name = safe_record_name(&latin1(&name));
        if rec_name.is_empty() {
            rec_name = format!("autoit_{:03}", records.len());
        }
        if records.len() >= MAX_RECORDS {
            return Vec::new();
        }
        records.push(ContainerRecord {
            name: rec_name,
            data: output,
        });
    }

    records
}

/// `XAUTOIT::_parseEA06` — EA06 record walk (LAME cipher + UTF-16
/// metadata + inverted-flag inflate).
fn parse_ea06(data: &[u8], mut base: usize, output_limit: i64) -> Vec<ContainerRecord> {
    let mut records = Vec::new();
    if base > data.len().saturating_sub(16) {
        return records;
    }
    base += 16;
    let size = data.len();
    let contains = |off: usize, len: u64| -> bool { off <= size && len <= (size - off) as u64 };

    loop {
        if !contains(base, 4) {
            break;
        }
        if rd32(data, base) != 0x52ca436b {
            break;
        }
        if !contains(base, 8) {
            return Vec::new();
        }
        let magic_chars = rd32(data, base + 4) ^ 0xadbc;
        if magic_chars > 0x10000 || magic_chars > u32::MAX / 2 {
            return Vec::new();
        }
        let magic_bytes = magic_chars * 2;
        base += 8;
        if !contains(base, u64::from(magic_bytes)) {
            return Vec::new();
        }
        let mut magic = data[base..base + magic_bytes as usize].to_vec();
        lame_decrypt(&mut magic, (magic_chars.wrapping_add(0xb33f)) as u16);
        let s_magic = utf16le_string(&magic, magic_chars);
        let b_script = s_magic == ">>>AUTOIT SCRIPT<<<";
        base += magic_bytes as usize;

        if !contains(base, 4) {
            return Vec::new();
        }
        let name_chars = rd32(data, base) ^ 0xf820;
        if name_chars > 0x10000 || name_chars > u32::MAX / 2 {
            return Vec::new();
        }
        let name_bytes = name_chars * 2;
        base += 4;
        if !contains(base, u64::from(name_bytes)) {
            return Vec::new();
        }
        let mut name_buf = data[base..base + name_bytes as usize].to_vec();
        lame_decrypt(&mut name_buf, (name_chars.wrapping_add(0xf479)) as u16);
        let s_build = utf16le_string(&name_buf, name_chars);
        base += name_bytes as usize;

        if !contains(base, 13) {
            return Vec::new();
        }
        let compression = data[base];
        let compressed_size = rd32(data, base + 1) ^ 0x87bc;
        if compression != 0 && compression != 1 {
            return Vec::new();
        }
        base += 13;
        if !contains(base, 16) {
            return Vec::new();
        }
        base += 16;
        if compressed_size == 0 {
            continue;
        }
        if compressed_size > i32::MAX as u32 || !contains(base, u64::from(compressed_size)) {
            return Vec::new();
        }
        if compression != 1 && output_limit >= 0 && u64::from(compressed_size) > output_limit as u64
        {
            base += compressed_size as usize;
            continue;
        }

        let mut input = data[base..base + compressed_size as usize].to_vec();
        base += compressed_size as usize;
        lame_decrypt(&mut input, 0x2477);

        let output = if compression == 1 {
            if compressed_size < 8 || rd32(&input, 0) != 0x36304145 {
                return Vec::new();
            }
            let mut usize_out = be32(&input, 4);
            if usize_out == 0 {
                usize_out = compressed_size;
            }
            if u64::from(usize_out) > MAX_FILE {
                return Vec::new();
            }
            if output_limit >= 0 && u64::from(usize_out) > output_limit as u64 {
                continue;
            }
            match inflate(&input, usize_out as usize, true) {
                Some(o) => o,
                None => return Vec::new(),
            }
        } else {
            input
        };

        if output.len() < 4 {
            continue;
        }
        let mut name = if b_script {
            "autoit_script.au3.tokens".to_string()
        } else {
            safe_record_name(&s_magic)
        };
        if name.is_empty() {
            name = safe_record_name(&s_build);
        }
        if name.is_empty() {
            name = format!("autoit_{:03}.bin", records.len());
        }
        if records.len() >= MAX_RECORDS {
            return Vec::new();
        }
        records.push(ContainerRecord { name, data: output });
    }

    records
}

/// `XAUTOIT::initUnpack` record enumeration — detect then run the
/// matching parser. Returns `Err(NotPacked)` when detection fails and
/// `Err(Malformed)` when the record list is empty (upstream
/// `listRecords.isEmpty() -> false`).
pub fn extract_autoit(data: &[u8], output_limit: i64) -> Result<Vec<ContainerRecord>, UnpackError> {
    let info = detect_autoit(data).ok_or(UnpackError::NotPacked)?;
    let records = match info.version {
        AutoItVersion::V2 => parse_v2(data, info.marker_offset, output_limit),
        AutoItVersion::Ea05 => parse_ea05(data, info.marker_offset + 8, output_limit),
        AutoItVersion::Ea06 => parse_ea06(data, info.marker_offset + 8, output_limit),
    };
    if records.is_empty() {
        return Err(UnpackError::Malformed("autoit: empty record list"));
    }
    if records.iter().map(|r| r.data.len() as u64).sum::<u64>() > MAX_TOTAL {
        return Err(UnpackError::Malformed("autoit: output cap"));
    }
    Ok(records)
}

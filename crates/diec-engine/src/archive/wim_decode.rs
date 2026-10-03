//! WIM compressed-resource decoders: XPRESS Huffman and LZX chunk
//! streams, ported from upstream `Algos/xxpressdecoder.cpp` (the
//! `xpress_huffman` path used by WIM) and `Algos/xlzxdecoder.cpp`
//! (`lzx_decompressStream` with `bWIMVariant = true`), plus the
//! `_stageChunkedResource` reassembly from `packages/xwim.cpp`.
//!
//! All functions return `None` on any deviation (fail-closed); callers
//! surface that as an empty extraction result, matching upstream which
//! produces no data when a decode check fails.

// ---- XPRESS Huffman (MS-XCA 2.2) ----

const XPRESS_NUM_SYMBOLS: usize = 512;
const XPRESS_TABLE_BYTES: usize = 256;
const XPRESS_MAX_CODEWORD_LEN: usize = 15;
const XPRESS_MIN_MATCH_LEN: usize = 3;
const XPRESS_HUFFMAN_MAX_BLOCK_SIZE: usize = 64 * 1024;

/// Canonical Huffman decode table (`XPRESS_HUFF`).
struct XpressHuff {
    count: [u16; XPRESS_MAX_CODEWORD_LEN + 1],
    symbol: [u16; XPRESS_NUM_SYMBOLS],
}

/// MSB-first bit reader over 16-bit little-endian words (`XPRESS_BITS`).
struct XpressBits<'a> {
    input: &'a [u8],
    pos: usize,
    bit_buf: u32,
    bit_count: i32,
    error: bool,
}

impl<'a> XpressBits<'a> {
    /// `xpress_initBits`: primes exactly two 16-bit words. Missing input
    /// must not be synthesized as zero bits because those bits can decode
    /// valid symbols.
    fn new(input: &'a [u8], start: usize) -> Self {
        let mut b = Self {
            input,
            pos: start,
            bit_buf: 0,
            bit_count: 0,
            error: false,
        };
        for _ in 0..2 {
            if b.pos + 1 >= b.input.len() {
                b.error = true;
                return b;
            }
            let word = u32::from(b.input[b.pos]) | (u32::from(b.input[b.pos + 1]) << 8);
            b.pos += 2;
            b.bit_buf |= word << (16 - b.bit_count);
            b.bit_count += 16;
        }
        b
    }

    /// `xpress_readBits`.
    fn read_bits(&mut self, n: i32) -> u32 {
        if self.error || !(0..=16).contains(&n) || n > self.bit_count {
            self.error = true;
            return 0;
        }
        if n == 0 {
            return 0;
        }
        let result = self.bit_buf >> (32 - n);
        self.bit_buf <<= n;
        self.bit_count -= n;

        if self.bit_count < 16 {
            if self.pos + 1 >= self.input.len() {
                self.error = true;
                return result;
            }
            let word = u32::from(self.input[self.pos]) | (u32::from(self.input[self.pos + 1]) << 8);
            self.pos += 2;
            self.bit_buf |= word << (16 - self.bit_count);
            self.bit_count += 16;
        }
        result
    }

    /// `xpress_readRaw`: one or two bytes read straight from the stream
    /// (not the bit buffer), used for extended match lengths.
    fn read_raw(&mut self, bytes: usize) -> u32 {
        if self.error
            || (bytes != 1 && bytes != 2)
            || self.pos > self.input.len().saturating_sub(bytes)
        {
            self.error = true;
            return 0;
        }
        let mut result = u32::from(self.input[self.pos]);
        self.pos += 1;
        if bytes == 2 {
            result |= u32::from(self.input[self.pos]) << 8;
            self.pos += 1;
        }
        result
    }
}

/// `xpress_buildHuff`: canonical Huffman table; requires a complete code.
fn xpress_build_huff(lens: &[u8; XPRESS_NUM_SYMBOLS]) -> Option<XpressHuff> {
    let mut count = [0u16; XPRESS_MAX_CODEWORD_LEN + 1];
    for &l in lens.iter() {
        count[l as usize] += 1;
    }
    let mut left = 1i32;
    for &c in count.iter().skip(1) {
        left <<= 1;
        left -= i32::from(c);
        if left < 0 {
            return None;
        }
    }
    if left != 0 {
        return None;
    }
    let mut offsets = [0u16; XPRESS_MAX_CODEWORD_LEN + 2];
    for l in 1..=XPRESS_MAX_CODEWORD_LEN {
        offsets[l + 1] = offsets[l] + count[l];
    }
    let mut symbol = [0u16; XPRESS_NUM_SYMBOLS];
    for (i, &l) in lens.iter().enumerate() {
        if l != 0 {
            symbol[offsets[l as usize] as usize] = i as u16;
            offsets[l as usize] += 1;
        }
    }
    Some(XpressHuff { count, symbol })
}

/// `xpress_decodeSym`.
fn xpress_decode_sym(bits: &mut XpressBits<'_>, table: &XpressHuff) -> i32 {
    let mut code = 0i32;
    let mut first = 0i32;
    let mut index = 0i32;
    for l in 1..=XPRESS_MAX_CODEWORD_LEN {
        code |= bits.read_bits(1) as i32;
        let count = i32::from(table.count[l]);
        if code - first < count {
            return i32::from(table.symbol[(index + (code - first)) as usize]);
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    bits.error = true;
    -1
}

/// `xpress_huffman` + `XXPressDecoder::decompressHuffman` guard clauses.
pub fn decompress_xpress_huffman(input: &[u8], out_size: usize) -> Option<Vec<u8>> {
    if input.len() < XPRESS_TABLE_BYTES + 4
        || out_size == 0
        || out_size > XPRESS_HUFFMAN_MAX_BLOCK_SIZE
    {
        return None;
    }
    let mut lens = [0u8; XPRESS_NUM_SYMBOLS];
    for i in 0..XPRESS_TABLE_BYTES {
        lens[2 * i] = input[i] & 0x0F;
        lens[2 * i + 1] = (input[i] >> 4) & 0x0F;
    }
    if lens.iter().any(|&l| l > 15) {
        return None;
    }
    let table = xpress_build_huff(&lens)?;
    let mut bits = XpressBits::new(input, XPRESS_TABLE_BYTES);
    if bits.error {
        return None;
    }

    let mut out = Vec::with_capacity(out_size);
    while !bits.error {
        let sym = xpress_decode_sym(&mut bits, &table);
        if bits.error || sym < 0 {
            return None;
        }
        if out.len() >= out_size {
            return ((sym == 256) && bits.bit_buf == 0 && bits.pos == bits.input.len())
                .then_some(out);
        }
        if sym < 256 {
            out.push(sym as u8);
        } else {
            let mut length = sym & 0x0F;
            let offset_slot = (sym >> 4) & 0x0F;

            if length == 15 {
                let extra = bits.read_raw(1) as i32;
                if bits.error {
                    return None;
                }
                if extra == 255 {
                    length = bits.read_raw(2) as i32;
                    if bits.error {
                        return None;
                    }
                    if length < 15 {
                        return None;
                    }
                } else {
                    length = extra + 15;
                }
            }
            length += XPRESS_MIN_MATCH_LEN as i32;

            let offset = (1usize << offset_slot) as i32 + bits.read_bits(offset_slot) as i32;
            if bits.error {
                return None;
            }
            let out_pos = out.len() as i32;
            if offset > out_pos || offset <= 0 || length > out_size as i32 - out_pos {
                return None;
            }
            let src = (out_pos - offset) as usize;
            for i in 0..length as usize {
                let byte = out[src + i];
                out.push(byte);
            }
        }
    }
    None
}

// ---- LZX, WIM variant (7-Zip-derived, upstream `xlzxdecoder.cpp`) ----

const LZX_FRAME_SIZE: usize = 32768;
const LZX_PRETREE_SYMBOLS: usize = 20;
const LZX_LENGTH_SYMBOLS: usize = 249;
const LZX_ALIGNED_SYMBOLS: usize = 8;
const LZX_MAX_MAIN_SYMBOLS: usize = 256 + 50 * 8;
const LZX_MAX_CODE_LENGTH: usize = 16;

const LZX_BLOCK_VERBATIM: u32 = 1;
const LZX_BLOCK_ALIGNED: u32 = 2;
const LZX_BLOCK_UNCOMPRESSED: u32 = 3;

const LZX_WIM_MAGIC_FILESIZE: i64 = 12_000_000;

/// Canonical Huffman table (`LZX_HUFF`).
struct LzxHuff {
    count: [u16; LZX_MAX_CODE_LENGTH + 1],
    symbol: [u16; LZX_MAX_MAIN_SYMBOLS],
    empty: bool,
}

/// `lzx_buildHuff`; `allow_empty` mirrors `LZX_HUFF_FULL_OR_EMPTY`.
fn lzx_build_huff(lens: &[u8], allow_empty: bool) -> Option<LzxHuff> {
    let n_symbols = lens.len();
    let mut count = [0u16; LZX_MAX_CODE_LENGTH + 1];
    for &l in lens {
        count[l as usize] += 1;
    }
    let empty = count[0] as usize == n_symbols;
    if empty {
        return allow_empty.then_some(LzxHuff {
            count,
            symbol: [0; LZX_MAX_MAIN_SYMBOLS],
            empty,
        });
    }
    let mut left = 1i32;
    for &c in count.iter().skip(1) {
        left <<= 1;
        left -= i32::from(c);
        if left < 0 {
            return None;
        }
    }
    if left != 0 {
        return None;
    }
    let mut offsets = [0u16; LZX_MAX_CODE_LENGTH + 1];
    for l in 1..LZX_MAX_CODE_LENGTH {
        offsets[l + 1] = offsets[l] + count[l];
    }
    let mut symbol = [0u16; LZX_MAX_MAIN_SYMBOLS];
    for (i, &l) in lens.iter().enumerate() {
        if l != 0 {
            symbol[offsets[l as usize] as usize] = i as u16;
            offsets[l as usize] += 1;
        }
    }
    Some(LzxHuff {
        count,
        symbol,
        empty,
    })
}

/// `LZX_STATE` bit reader: 16-bit LE words into the top of a 64-bit
/// buffer; consuming past the input is an overrun error.
struct LzxState<'a> {
    input: &'a [u8],
    pos: usize,
    bit_buf: u64,
    bit_count: i32,
    overrun: bool,
    error: bool,

    window: Vec<u8>,
    window_size: u32,
    window_pos: u32,

    r0: u32,
    r1: u32,
    r2: u32,

    main_symbols: usize,
    position_base: [u32; 51],
    extra_bits: [u8; 51],
    position_slots: usize,
}

impl<'a> LzxState<'a> {
    /// `lzx_ensureBits`.
    fn ensure_bits(&mut self, n: i32) {
        while self.bit_count < n {
            if self.pos + 1 < self.input.len() {
                let word =
                    u32::from(self.input[self.pos]) | (u32::from(self.input[self.pos + 1]) << 8);
                self.pos += 2;
                self.bit_buf |= u64::from(word) << (48 - self.bit_count);
                self.bit_count += 16;
            } else {
                self.overrun = true;
                self.error = true;
                return;
            }
        }
    }

    /// `lzx_readBits`.
    fn read_bits(&mut self, n: i32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.ensure_bits(n);
        if self.error || self.bit_count < n {
            return 0;
        }
        let result = (self.bit_buf >> (64 - n)) as u32;
        self.bit_buf <<= n;
        self.bit_count -= n;
        result
    }

    /// `lzx_decodeHuff`.
    fn decode_huff(&mut self, table: &LzxHuff) -> i32 {
        if table.empty {
            self.error = true;
            return -1;
        }
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for l in 1..=LZX_MAX_CODE_LENGTH {
            code |= self.read_bits(1) as i32;
            let count = i32::from(table.count[l]);
            if code - first < count {
                return i32::from(table.symbol[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        self.error = true;
        -1
    }

    /// `lzx_readLengths`: delta-coded code lengths via a 20-symbol
    /// pretree, covering `lens[first..last]`.
    fn read_lengths(&mut self, lens: &mut [u8], first: usize, last: usize) -> bool {
        let mut pre_lens = [0u8; LZX_PRETREE_SYMBOLS];
        for l in pre_lens.iter_mut() {
            *l = self.read_bits(4) as u8;
        }
        let Some(pre_tree) = lzx_build_huff(&pre_lens, false) else {
            return false;
        };
        let mut i = first;
        while i < last {
            let z = self.decode_huff(&pre_tree);
            if self.error {
                return false;
            }
            if z == 17 {
                let n = self.read_bits(4) as usize + 4;
                if n > last - i {
                    return false;
                }
                for _ in 0..n {
                    lens[i] = 0;
                    i += 1;
                }
            } else if z == 18 {
                let n = self.read_bits(5) as usize + 20;
                if n > last - i {
                    return false;
                }
                for _ in 0..n {
                    lens[i] = 0;
                    i += 1;
                }
            } else if z == 19 {
                let mut n = self.read_bits(1) as usize + 4;
                let z2 = self.decode_huff(&pre_tree);
                if self.error || !(0..=16).contains(&z2) {
                    return false;
                }
                if n > last - i {
                    return false;
                }
                let value = (u16::from(lens[i]) + 17 - z2 as u16) % 17;
                while n > 0 {
                    lens[i] = value as u8;
                    i += 1;
                    n -= 1;
                }
            } else if (0..=16).contains(&z) {
                lens[i] = ((u16::from(lens[i]) + 17 - z as u16) % 17) as u8;
                i += 1;
            } else {
                return false;
            }
        }
        true
    }

    /// `lzx_initPositionSlots`.
    fn init_position_slots(&mut self, window_bits: u32) {
        const SLOTS_BY_BITS: [usize; 7] = [30, 32, 34, 36, 38, 42, 50];
        self.position_slots = SLOTS_BY_BITS[window_bits.clamp(15, 21) as usize - 15];
        let mut base = 0u32;
        for i in 0..self.position_slots {
            self.extra_bits[i] = if i < 4 {
                0
            } else {
                ((i / 2) - 1).min(17) as u8
            };
            self.position_base[i] = base;
            base += 1u32 << self.extra_bits[i];
        }
    }

    /// `lzx_align16`: discard bits so the next read starts at a 16-bit
    /// stream boundary; `at_least_one` additionally consumes a full
    /// padding word when already aligned (uncompressed-block rule).
    fn align16(&mut self, at_least_one: bool) -> bool {
        let misaligned = self.bit_count & 15;
        if misaligned != 0 {
            if (self.bit_buf >> (64 - misaligned)) != 0 {
                return false;
            }
            self.bit_buf <<= misaligned;
            self.bit_count -= misaligned;
        } else if at_least_one && self.read_bits(16) != 0 {
            return false;
        }
        !self.error
    }

    /// `lzx_rawPosition`.
    fn raw_position(&self) -> i64 {
        self.pos as i64 - i64::from(self.bit_count / 8)
    }

    /// `lzx_outputByte`.
    fn output_byte(&mut self, out: &mut Vec<u8>, byte: u8) {
        self.window[self.window_pos as usize] = byte;
        self.window_pos = (self.window_pos + 1) & (self.window_size - 1);
        out.push(byte);
    }
}

/// `lzx_undoE8`: reverse the Intel E8 call translation on one frame.
fn lzx_undo_e8(
    data: &mut [u8],
    frame_offset: i64,
    frame_size: i64,
    data_base: usize,
    file_size: i64,
) {
    if file_size == 0 || frame_size <= 10 || frame_offset >= 0x4000_0000 {
        return;
    }
    let mut i = 0i64;
    while i < frame_size - 10 {
        let at = data_base + i as usize;
        if data[at] != 0xE8 {
            i += 1;
            continue;
        }
        let cur_pos = frame_offset + i;
        let abs_off = i32::from_le_bytes([data[at + 1], data[at + 2], data[at + 3], data[at + 4]]);
        if i64::from(abs_off) >= -cur_pos && i64::from(abs_off) < file_size {
            let rel_off = if abs_off >= 0 {
                (abs_off as i64 - cur_pos) as u32
            } else {
                (abs_off as i64 + file_size) as u32
            };
            data[at + 1..at + 5].copy_from_slice(&rel_off.to_le_bytes());
        }
        i += 5;
    }
}

/// `XLZXDecoder::decompressWIMChunk` → `lzx_decompressStream` with
/// `bWIMVariant = true`.
pub fn decompress_lzx_wim_chunk(
    input: &[u8],
    out_size: usize,
    window_bits: u32,
) -> Option<Vec<u8>> {
    if input.is_empty()
        || out_size == 0
        || !(15..=21).contains(&window_bits)
        || out_size > (1usize << window_bits)
    {
        return None;
    }

    let mut st = LzxState {
        input,
        pos: 0,
        bit_buf: 0,
        bit_count: 0,
        overrun: false,
        error: false,
        window: vec![0; 1usize << window_bits],
        window_size: 1u32 << window_bits,
        window_pos: 0,
        r0: 1,
        r1: 1,
        r2: 1,
        main_symbols: 0,
        position_base: [0; 51],
        extra_bits: [0; 51],
        position_slots: 0,
    };
    st.init_position_slots(window_bits);
    st.main_symbols = 256 + st.position_slots * 8;
    let mut main_lens = vec![0u8; st.main_symbols];
    let mut length_lens = [0u8; LZX_LENGTH_SYMBOLS];

    let mut out = Vec::with_capacity(out_size);
    let mut main_tree = LzxHuff {
        count: [0; LZX_MAX_CODE_LENGTH + 1],
        symbol: [0; LZX_MAX_MAIN_SYMBOLS],
        empty: true,
    };
    let mut length_tree = LzxHuff {
        count: [0; LZX_MAX_CODE_LENGTH + 1],
        symbol: [0; LZX_MAX_MAIN_SYMBOLS],
        empty: true,
    };
    let mut aligned_tree = LzxHuff {
        count: [0; LZX_MAX_CODE_LENGTH + 1],
        symbol: [0; LZX_MAX_MAIN_SYMBOLS],
        empty: true,
    };

    let mut out_count = 0usize;
    let mut block_remaining = 0i64;
    let mut block_type = 0u32;

    while out_count < out_size && !st.error {
        if block_remaining == 0 {
            block_type = st.read_bits(3);
            let block_size: i64 = if st.read_bits(1) != 0 {
                LZX_FRAME_SIZE as i64
            } else {
                let mut s = i64::from(st.read_bits(16));
                if window_bits >= 16 {
                    s = (s << 8) | i64::from(st.read_bits(8));
                }
                s
            };
            if st.error || block_size <= 0 || block_size > (out_size - out_count) as i64 {
                return None;
            }
            block_remaining = block_size;

            if block_type == LZX_BLOCK_ALIGNED {
                let mut aligned_lens = [0u8; LZX_ALIGNED_SYMBOLS];
                for l in aligned_lens.iter_mut() {
                    *l = st.read_bits(3) as u8;
                }
                aligned_tree = lzx_build_huff(&aligned_lens, false)?;
            }

            if block_type == LZX_BLOCK_VERBATIM || block_type == LZX_BLOCK_ALIGNED {
                if !st.read_lengths(&mut main_lens, 0, 256) {
                    return None;
                }
                if !st.read_lengths(&mut main_lens, 256, st.main_symbols) {
                    return None;
                }
                main_tree = lzx_build_huff(&main_lens, false)?;
                if !st.read_lengths(&mut length_lens, 0, LZX_LENGTH_SYMBOLS) {
                    return None;
                }
                length_tree = lzx_build_huff(&length_lens, true)?;
            } else if block_type == LZX_BLOCK_UNCOMPRESSED {
                // Align to a 16-bit boundary (1-16 pad bits), then 12
                // bytes of R0/R1/R2.
                if !st.align16(true) {
                    return None;
                }
                let mut raw_pos = st.raw_position();
                st.bit_buf = 0;
                st.bit_count = 0;
                if raw_pos < 0 || raw_pos + 12 > st.input.len() as i64 {
                    return None;
                }
                let p = &st.input[raw_pos as usize..];
                st.r0 = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
                st.r1 = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);
                st.r2 = u32::from_le_bytes([p[8], p[9], p[10], p[11]]);
                raw_pos += 12;

                let max_repeat = st.window_size - 3;
                if st.r0 == 0
                    || st.r0 > max_repeat
                    || st.r1 == 0
                    || st.r1 > max_repeat
                    || st.r2 == 0
                    || st.r2 > max_repeat
                {
                    return None;
                }
                if raw_pos + block_remaining > st.input.len() as i64 {
                    return None;
                }
                for i in 0..block_remaining {
                    st.output_byte(&mut out, st.input[(raw_pos + i) as usize]);
                }
                out_count += block_remaining as usize;
                raw_pos += block_remaining;

                if block_remaining & 1 != 0 {
                    // A zero pad byte is required before another block.
                    // The final odd uncompressed block may end exactly
                    // at EOF.
                    if raw_pos < st.input.len() as i64 {
                        if st.input[raw_pos as usize] != 0 {
                            return None;
                        }
                        raw_pos += 1;
                    } else if out_count != out_size {
                        return None;
                    }
                }
                block_remaining = 0;
                st.pos = raw_pos as usize;
                continue;
            } else {
                return None;
            }
        }

        // Decode one symbol from a verbatim/aligned block.
        let mut main_sym = st.decode_huff(&main_tree);
        if st.error || main_sym < 0 {
            return None;
        }
        if main_sym < 256 {
            if block_remaining <= 0 || out_count >= out_size {
                return None;
            }
            st.output_byte(&mut out, main_sym as u8);
            out_count += 1;
            block_remaining -= 1;
        } else {
            main_sym -= 256;
            let len_header = main_sym & 7;
            let pos_slot = main_sym >> 3;

            let mut match_len = len_header + 2;
            if len_header == 7 {
                let len_sym = st.decode_huff(&length_tree);
                if st.error || len_sym < 0 {
                    return None;
                }
                match_len = len_sym + 9;
            }

            let match_offset: u32;
            if pos_slot == 0 {
                match_offset = st.r0;
            } else if pos_slot == 1 {
                match_offset = st.r1;
                st.r1 = st.r0;
                st.r0 = match_offset;
            } else if pos_slot == 2 {
                match_offset = st.r2;
                st.r2 = st.r0;
                st.r0 = match_offset;
            } else {
                if pos_slot < 0
                    || pos_slot as usize >= st.position_slots
                    || pos_slot as usize >= st.extra_bits.len()
                {
                    return None;
                }
                let extra = st.extra_bits[pos_slot as usize] as i32;
                let mut verbatim = 0u32;
                if block_type == LZX_BLOCK_ALIGNED && extra >= 3 {
                    verbatim = st.read_bits(extra - 3);
                    let aligned_sym = st.decode_huff(&aligned_tree);
                    if st.error || aligned_sym < 0 {
                        return None;
                    }
                    match_offset = st.position_base[pos_slot as usize]
                        .wrapping_sub(2)
                        .wrapping_add(verbatim << 3)
                        .wrapping_add(aligned_sym as u32);
                } else {
                    if extra != 0 {
                        verbatim = st.read_bits(extra);
                    }
                    match_offset = st.position_base[pos_slot as usize]
                        .wrapping_sub(2)
                        .wrapping_add(verbatim);
                }
                st.r2 = st.r1;
                st.r1 = st.r0;
                st.r0 = match_offset;
            }

            if match_offset == 0
                || match_offset > st.window_size
                || u64::from(match_offset) > u64::min(out_count as u64, u64::from(st.window_size))
                || i64::from(match_len) > block_remaining
                || i64::from(match_len) > (out_size - out_count) as i64
            {
                return None;
            }
            let mut src = (st.window_pos + st.window_size - match_offset) & (st.window_size - 1);
            for _ in 0..match_len {
                let byte = st.window[src as usize];
                st.output_byte(&mut out, byte);
                src = (src + 1) & (st.window_size - 1);
            }
            out_count += match_len as usize;
            block_remaining -= i64::from(match_len);
        }

        if block_remaining < 0 {
            return None;
        }
    }

    if st.error
        || st.overrun
        || out_count != out_size
        || block_remaining != 0
        || st.pos != st.input.len()
        || st.bit_buf != 0
        || out.len() != out_size
    {
        return None;
    }

    // Intel E8 post-processing (WIM always applies it with the fixed
    // magic file size).
    lzx_undo_e8(&mut out, 0, out_size as i64, 0, LZX_WIM_MAGIC_FILESIZE);
    Some(out)
}

// ---- Chunked resource staging (`_stageChunkedResource`) ----

/// Compression selector for `stage_chunked_resource`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WimCompression {
    Lzx,
    Xpress,
}

/// `XWIM::_stageChunkedResource`: read the chunk table at the resource
/// offset, decode each chunk (or copy stored chunks verbatim), and
/// return the reassembled uncompressed resource.
///
/// `resource_offset`/`pack_size`/`unpack_size` come from the record's
/// `RESOURCE_INFO`; `chunk_size` is the header's effective chunk size
/// (already resolved to 32768 when the header field is zero).
pub fn stage_chunked_resource(
    d: &[u8],
    resource_offset: u64,
    pack_size: u64,
    unpack_size: u64,
    compression: WimCompression,
    chunk_size: u32,
) -> Option<Vec<u8>> {
    if chunk_size == 0
        || unpack_size == 0
        || unpack_size > i64::MAX as u64
        || pack_size == 0
        || resource_offset.checked_add(pack_size)? > d.len() as u64
    {
        return None;
    }
    if compression == WimCompression::Lzx && chunk_size > (1 << 21) {
        return None;
    }
    if compression == WimCompression::Xpress && chunk_size > XPRESS_HUFFMAN_MAX_BLOCK_SIZE as u32 {
        return None;
    }

    let window_bits = 31 - chunk_size.leading_zeros();
    let num_chunks = 1 + (unpack_size - 1) / u64::from(chunk_size);
    let entry_size: u64 = if unpack_size > 0xFFFF_FFFF { 8 } else { 4 };
    let table_entries = num_chunks - 1;
    if table_entries > i64::MAX as u64 / entry_size {
        return None;
    }
    let table_size = table_entries * entry_size;
    if table_size >= pack_size {
        return None;
    }
    let compressed_total = pack_size - table_size;
    let base = usize::try_from(resource_offset).ok()?;

    let mut out = Vec::with_capacity(usize::try_from(unpack_size).ok()?);
    let mut chunk_start = 0u64;
    let mut output_done = 0u64;

    for i in 0..num_chunks {
        let chunk_end = if i + 1 < num_chunks {
            let entry_off = base.checked_add((i * entry_size) as usize)?;
            let entry = d.get(entry_off..entry_off + entry_size as usize)?;
            if entry_size == 4 {
                u64::from(u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]))
            } else {
                u64::from_le_bytes([
                    entry[0], entry[1], entry[2], entry[3], entry[4], entry[5], entry[6], entry[7],
                ])
            }
        } else {
            compressed_total
        };
        if chunk_end <= chunk_start || chunk_end > compressed_total {
            return None;
        }
        let chunk_compressed = chunk_end - chunk_start;
        let chunk_uncompressed = u64::from(chunk_size).min(unpack_size - output_done);
        if chunk_compressed > i32::MAX as u64 || chunk_compressed > u64::from(chunk_size) {
            return None;
        }
        let data_off = base
            .checked_add(table_size as usize)?
            .checked_add(chunk_start as usize)?;
        let chunk = d.get(data_off..data_off + chunk_compressed as usize)?;

        if chunk_compressed == chunk_uncompressed {
            out.extend_from_slice(chunk);
            output_done += chunk_compressed;
        } else {
            if chunk_compressed >= u64::from(chunk_size) {
                return None;
            }
            let decoded = match compression {
                WimCompression::Lzx => {
                    decompress_lzx_wim_chunk(chunk, chunk_uncompressed as usize, window_bits)?
                }
                WimCompression::Xpress => {
                    decompress_xpress_huffman(chunk, chunk_uncompressed as usize)?
                }
            };
            out.extend_from_slice(&decoded);
            output_done += decoded.len() as u64;
        }
        chunk_start = chunk_end;
    }

    if chunk_start != compressed_total || output_done != unpack_size {
        return None;
    }
    Some(out)
}

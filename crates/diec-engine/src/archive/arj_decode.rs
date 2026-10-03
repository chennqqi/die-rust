//! ARJ compression decoder (methods 1-3 Huffman+LZSS, method 4 fast
//! LZSS), ported from upstream
//! `upstream/DIE-engine/dep/XArchive/Algos/xarjdecoder.cpp`
//! (pin 23fec32cac2a562342c1c2db8e22ce231b58f346), itself a port of the
//! classic ARJ `decode.c`.
//!
//! Exact-input contract mirrors upstream: the packed stream must be
//! consumed to the byte (the bit reader may look ahead into zero-padded
//! tail bits only when the buffer is exhausted) and the produced size
//! must equal the declared uncompressed size.

const DDICSIZ: usize = 26624;
const THRESHOLD: i32 = 3;
const MAXMATCH: i32 = 256;
const CODE_BIT: i32 = 16;
const NT: usize = CODE_BIT as usize + 3; // 19
const TBIT: i32 = 5;
const CBIT: i32 = 9;
const NC: usize = 255 + MAXMATCH as usize + 2 - THRESHOLD as usize; // 510
const NP: usize = 17;
const CTABLESIZE: usize = 4096;
const PTABLESIZE: usize = 256;
const STRTP: u16 = 9;
const STOPP: u16 = 13;
const STRTL: u16 = 0;
const STOPL: u16 = 7;
const NPT: usize = 19;

/// A writable slot during `make_table`: either a fast-table cell or a
/// left/right child of an extended-prefix node (upstream uses a raw
/// `quint16 *` roaming across three arrays).
#[derive(Clone, Copy)]
enum Slot {
    /// Index into the fast lookup table.
    Table(usize),
    /// Index into `arr_left`.
    Left(usize),
    /// Index into `arr_right`.
    Right(usize),
}

/// Which fast table `make_table` is currently building.
#[derive(Clone, Copy)]
enum TableSel {
    /// Literal/length table (`arr_ctable`, 12-bit).
    C,
    /// Position table (`arr_pttable`, 8-bit).
    Pt,
}

/// Decoder working state; one instance per member stream.
struct State<'a> {
    /// Whole packed member stream (consumed via `cursor`).
    input: &'a [u8],
    /// Read cursor into `input` (mirrors `pBuf`/`nCompLeft`).
    cursor: usize,
    bit_buf: u16,
    sub_bit_buf: u16,
    bit_count: i32,
    get_buf: u16,
    get_len: i32,
    block_size: u16,
    arr_left: [u16; 2 * NC - 1],
    arr_right: [u16; 2 * NC - 1],
    arr_clen: [u8; NC],
    arr_ptlen: [u8; NPT],
    arr_ctable: [u16; CTABLESIZE],
    arr_pttable: [u16; PTABLESIZE],
    /// Table the current `make_table` call writes to.
    cur: TableSel,
    error: bool,
}

impl<'a> State<'a> {
    /// Create a state over the packed `input` bytes.
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            cursor: 0,
            bit_buf: 0,
            sub_bit_buf: 0,
            bit_count: 0,
            get_buf: 0,
            get_len: 0,
            block_size: 0,
            arr_left: [0; 2 * NC - 1],
            arr_right: [0; 2 * NC - 1],
            arr_clen: [0; NC],
            arr_ptlen: [0; NPT],
            arr_ctable: [0; CTABLESIZE],
            arr_pttable: [0; PTABLESIZE],
            cur: TableSel::C,
            error: false,
        }
    }

    /// Pull the next input byte, or 0 when the stream is exhausted
    /// (upstream feeds zero bytes for the final look-ahead).
    fn pull_byte(&mut self) -> u16 {
        if self.cursor < self.input.len() {
            let b = self.input[self.cursor];
            self.cursor += 1;
            u16::from(b)
        } else {
            0
        }
    }

    /// `fillBuf`: demand `n` bits into `bit_buf`.
    fn fill_buf(&mut self, n: i32) -> bool {
        if self.error || !(0..=16).contains(&n) {
            self.error = true;
            return false;
        }
        let mut n = n;
        self.bit_buf = (u32::from(self.bit_buf) << n) as u16;
        while n > self.bit_count {
            // Upstream widens to u32 before the shift then truncates.
            self.bit_buf |= ((u32::from(self.sub_bit_buf) << (n - self.bit_count)) & 0xFFFF) as u16;
            n -= self.bit_count;
            self.sub_bit_buf = self.pull_byte();
            self.bit_count = 8;
        }
        self.bit_buf |= self.sub_bit_buf >> (self.bit_count - n);
        self.bit_count -= n;
        true
    }

    /// `getBits`: extract `n` bits.
    fn get_bits(&mut self, n: i32) -> u16 {
        if self.error || !(0..=16).contains(&n) {
            self.error = true;
            return 0;
        }
        let r = if n == 0 { 0 } else { self.bit_buf >> (16 - n) };
        if !self.fill_buf(n) {
            return 0;
        }
        r
    }

    /// `initGetBits`: prime the bit reader.
    fn init_get_bits(&mut self) -> bool {
        self.bit_buf = 0;
        self.sub_bit_buf = 0;
        self.bit_count = 0;
        self.fill_buf(16)
    }

    /// Read one `Slot` value; `Table` dispatches to the table
    /// currently under construction (`cur`).
    fn slot_get(&self, s: Slot) -> u16 {
        match s {
            Slot::Table(i) => match self.cur {
                TableSel::C => self.arr_ctable[i],
                TableSel::Pt => self.arr_pttable[i],
            },
            Slot::Left(i) => self.arr_left[i],
            Slot::Right(i) => self.arr_right[i],
        }
    }

    /// Write one `Slot` value (see [`State::slot_get`]).
    fn slot_set(&mut self, s: Slot, v: u16) {
        match s {
            Slot::Table(i) => match self.cur {
                TableSel::C => self.arr_ctable[i] = v,
                TableSel::Pt => self.arr_pttable[i] = v,
            },
            Slot::Left(i) => self.arr_left[i] = v,
            Slot::Right(i) => self.arr_right[i] = v,
        }
    }

    /// Set a cell in the table under construction.
    fn table_set(&mut self, i: usize, v: u16) {
        match self.cur {
            TableSel::C => self.arr_ctable[i] = v,
            TableSel::Pt => self.arr_pttable[i] = v,
        }
    }

    /// `makeTable`: build the canonical Huffman decode table for
    /// `n_char` symbols, `t_bits`-bit fast lookup plus left/right chain.
    fn make_table(
        &mut self,
        n_char: usize,
        bit_len: &[u8],
        t_bits: i32,
        table_size: usize,
    ) -> bool {
        let mut count = [0u16; 17];
        let mut weight = [0u16; 17];
        let mut start = [0u16; 18];
        for i in 0..n_char {
            if bit_len[i] >= 17 {
                self.error = true;
                return false;
            }
            count[bit_len[i] as usize] += 1;
        }
        start[1] = 0;
        for i in 1..=16 {
            start[i + 1] = start[i].wrapping_add(count[i] << (16 - i));
        }
        if start[17] != 0 {
            self.error = true;
            return false;
        }
        let jut_bits = 16 - t_bits;
        if t_bits >= 17 {
            self.error = true;
            return false;
        }
        for i in 1..=t_bits as usize {
            start[i] >>= jut_bits;
            weight[i] = 1 << (t_bits - i as i32);
        }
        for (i, w) in weight
            .iter_mut()
            .enumerate()
            .take(17)
            .skip(t_bits as usize + 1)
        {
            *w = 1 << (16 - i);
        }
        let mut pos = u32::from(start[t_bits as usize + 1] >> jut_bits);
        if pos != 0 {
            let end = 1u32 << t_bits;
            while pos < end {
                if pos as usize >= table_size {
                    self.error = true;
                    return false;
                }
                self.table_set(pos as usize, 0);
                pos += 1;
            }
        }
        let mut avail = n_char as u32;
        let mask = 1u16 << (15 - t_bits);
        for (ch, &bl) in bit_len.iter().enumerate().take(n_char) {
            let len = bl as i32;
            if len == 0 {
                continue;
            }
            let mut k = u32::from(start[len as usize]);
            let next = k + u32::from(weight[len as usize]);
            if len <= t_bits {
                if next > table_size as u32 {
                    self.error = true;
                    return false;
                }
                for i in k..next {
                    self.table_set(i as usize, ch as u16);
                }
            } else {
                let mut slot = Slot::Table((k >> jut_bits) as usize);
                let mut remaining = len - t_bits;
                while remaining > 0 {
                    if self.slot_get(slot) == 0 {
                        if avail >= (2 * NC - 1) as u32 {
                            self.error = true;
                            return false;
                        }
                        self.arr_left[avail as usize] = 0;
                        self.arr_right[avail as usize] = 0;
                        self.slot_set(slot, avail as u16);
                        avail += 1;
                    }
                    let node = self.slot_get(slot) as usize;
                    if node >= 2 * NC - 1 {
                        self.error = true;
                        return false;
                    }
                    slot = if k & u32::from(mask) != 0 {
                        Slot::Right(node)
                    } else {
                        Slot::Left(node)
                    };
                    k <<= 1;
                    remaining -= 1;
                }
                self.slot_set(slot, ch as u16);
            }
            start[len as usize] = next as u16;
        }
        true
    }

    /// `readPtLen`: read `n_count` code lengths, `n_bitwidth`-bit
    /// count field, `n_special` run-position.
    fn read_pt_len(&mut self, n_count: usize, n_bitwidth: i32, n_special: i32) -> bool {
        let n = self.get_bits(n_bitwidth) as usize;
        if self.error {
            return false;
        }
        if n == 0 {
            let c = self.get_bits(n_bitwidth) as usize;
            if self.error || c >= n_count || c >= NPT {
                self.error = true;
                return false;
            }
            for i in 0..n_count.min(NPT) {
                self.arr_ptlen[i] = 0;
            }
            for i in 0..PTABLESIZE {
                self.arr_pttable[i] = c as u16;
            }
        } else {
            if n > n_count || n > NPT {
                self.error = true;
                return false;
            }
            let mut i = 0usize;
            while i < n && i < NPT {
                let mut c = (self.bit_buf >> 13) as i32;
                if c == 7 {
                    let mut test_mask = 1u16 << 12;
                    while test_mask & self.bit_buf != 0 {
                        test_mask >>= 1;
                        c += 1;
                    }
                }
                if !self.fill_buf(if c < 7 { 3 } else { c - 3 }) {
                    return false;
                }
                self.arr_ptlen[i] = c as u8;
                i += 1;
                if i as i32 == n_special {
                    let skip = self.get_bits(2) as usize;
                    if self.error {
                        return false;
                    }
                    for _ in 0..skip {
                        if i < NPT {
                            self.arr_ptlen[i] = 0;
                            i += 1;
                        }
                    }
                }
            }
            while i < n_count && i < NPT {
                self.arr_ptlen[i] = 0;
                i += 1;
            }
            self.cur = TableSel::Pt;
            let lens = self.arr_ptlen;
            if !self.make_table(n_count, &lens, 8, PTABLESIZE) {
                return false;
            }
        }
        true
    }

    /// `readCLen`: read the literal/length code lengths via the
    /// previously built PT table.
    fn read_c_len(&mut self) -> bool {
        let n = self.get_bits(CBIT) as usize;
        if self.error {
            return false;
        }
        if n == 0 {
            let c = self.get_bits(CBIT) as usize;
            if self.error || c >= NC {
                self.error = true;
                return false;
            }
            for i in 0..NC {
                self.arr_clen[i] = 0;
            }
            for i in 0..CTABLESIZE {
                self.arr_ctable[i] = c as u16;
            }
        } else {
            if n > NC {
                self.error = true;
                return false;
            }
            let mut i = 0usize;
            while i < n {
                let mut c = self.arr_pttable[(self.bit_buf >> 8) as usize] as i32;
                if c >= NT as i32 {
                    let mut test_mask = 1u16 << 7;
                    loop {
                        if c >= (2 * NC - 1) as i32 {
                            self.error = true;
                            return false;
                        }
                        c = if self.bit_buf & test_mask != 0 {
                            self.arr_right[c as usize] as i32
                        } else {
                            self.arr_left[c as usize] as i32
                        };
                        test_mask >>= 1;
                        if c < NT as i32 {
                            break;
                        }
                    }
                }
                if c >= NPT as i32 {
                    self.error = true;
                    return false;
                }
                if !self.fill_buf(self.arr_ptlen[c as usize] as i32) {
                    return false;
                }
                if c <= 2 {
                    c = match c {
                        0 => 1,
                        1 => self.get_bits(4) as i32 + 3,
                        _ => self.get_bits(CBIT) as i32 + 20,
                    };
                    if self.error {
                        return false;
                    }
                    for _ in 0..c - 1 {
                        if i >= NC {
                            self.error = true;
                            return false;
                        }
                        self.arr_clen[i] = 0;
                        i += 1;
                    }
                } else {
                    if i >= NC {
                        self.error = true;
                        return false;
                    }
                    self.arr_clen[i] = (c - 2) as u8;
                    i += 1;
                }
            }
            while i < NC {
                self.arr_clen[i] = 0;
                i += 1;
            }
            self.cur = TableSel::C;
            let lens = self.arr_clen;
            if !self.make_table(NC, &lens, 12, CTABLESIZE) {
                return false;
            }
        }
        true
    }

    /// `decodeC`: decode one literal/match token.
    fn decode_c(&mut self) -> u16 {
        if self.block_size == 0 {
            self.block_size = self.get_bits(16);
            if self.error
                || self.block_size == 0
                || !self.read_pt_len(NT, TBIT, 3)
                || !self.read_c_len()
                || !self.read_pt_len(NP, 5, -1)
            {
                self.error = true;
                return 0;
            }
        }
        if self.error {
            return 0;
        }
        self.block_size -= 1;
        let mut j = self.arr_ctable[(self.bit_buf >> 4) as usize];
        if j as usize >= NC {
            let mut test_mask = 1u16 << 3;
            loop {
                if j as usize >= 2 * NC - 1 {
                    self.error = true;
                    return 0;
                }
                j = if self.bit_buf & test_mask != 0 {
                    self.arr_right[j as usize]
                } else {
                    self.arr_left[j as usize]
                };
                test_mask >>= 1;
                if (j as usize) < NC {
                    break;
                }
            }
        }
        self.fill_buf(self.arr_clen[j as usize] as i32);
        j
    }

    /// `decodeP`: decode one match position.
    fn decode_p(&mut self) -> u16 {
        let mut j = self.arr_pttable[(self.bit_buf >> 8) as usize];
        if j as usize >= NP {
            let mut test_mask = 1u16 << 7;
            loop {
                if j as usize >= 2 * NC - 1 {
                    self.error = true;
                    return 0;
                }
                j = if self.bit_buf & test_mask != 0 {
                    self.arr_right[j as usize]
                } else {
                    self.arr_left[j as usize]
                };
                test_mask >>= 1;
                if (j as usize) < NP {
                    break;
                }
            }
        }
        if !self.fill_buf(self.arr_ptlen[j as usize] as i32) {
            return 0;
        }
        if j != 0 {
            let bits = j - 1;
            j = (1 << bits) + self.get_bits(bits as i32);
        }
        j
    }

    /// Method-4 `decodeLen`: unary prefix + fixed-width tail.
    fn decode_len(&mut self) -> u16 {
        if self.error || self.get_len < 0 || self.get_len > CODE_BIT {
            self.error = true;
            return 0;
        }
        let mut c = 0u16;
        let mut width = STRTL;
        let mut plus = 0u16;
        let mut pwr = 1u16 << STRTL;
        while width < STOPL {
            // getbit
            if self.get_len <= 0 {
                self.get_buf |= self.bit_buf;
                if !self.fill_buf(CODE_BIT) {
                    return 0;
                }
                self.get_len = CODE_BIT;
            }
            c = if self.get_buf & 0x8000 != 0 { 1 } else { 0 };
            self.get_buf = self.get_buf.wrapping_mul(2);
            self.get_len -= 1;
            if self.error {
                return 0;
            }
            if c == 0 {
                break;
            }
            plus = plus.wrapping_add(pwr);
            pwr <<= 1;
            width += 1;
        }
        if width != 0 {
            // getbits
            if self.get_len < width as i32 {
                if self.get_len < 0 || self.get_len > CODE_BIT {
                    self.error = true;
                    return 0;
                }
                self.get_buf |= self.bit_buf >> self.get_len;
                if !self.fill_buf(CODE_BIT - self.get_len) {
                    return 0;
                }
                self.get_len = CODE_BIT;
            }
            c = self.get_buf >> (CODE_BIT - width as i32);
            for _ in 0..width {
                self.get_buf = self.get_buf.wrapping_mul(2);
            }
            self.get_len -= width as i32;
        }
        c.wrapping_add(plus)
    }

    /// Method-4 `decodePtr`: unary prefix + fixed-width tail.
    fn decode_ptr(&mut self) -> u16 {
        if self.error || self.get_len < 0 || self.get_len > CODE_BIT {
            self.error = true;
            return 0;
        }
        let mut c = 0u16;
        let mut width = STRTP;
        let mut plus = 0u16;
        let mut pwr = 1u16 << STRTP;
        while width < STOPP {
            if self.get_len <= 0 {
                self.get_buf |= self.bit_buf;
                if !self.fill_buf(CODE_BIT) {
                    return 0;
                }
                self.get_len = CODE_BIT;
            }
            c = if self.get_buf & 0x8000 != 0 { 1 } else { 0 };
            self.get_buf = self.get_buf.wrapping_mul(2);
            self.get_len -= 1;
            if self.error {
                return 0;
            }
            if c == 0 {
                break;
            }
            plus = plus.wrapping_add(pwr);
            pwr <<= 1;
            width += 1;
        }
        if width != 0 {
            if self.get_len < width as i32 {
                if self.get_len < 0 || self.get_len > CODE_BIT {
                    self.error = true;
                    return 0;
                }
                self.get_buf |= self.bit_buf >> self.get_len;
                if !self.fill_buf(CODE_BIT - self.get_len) {
                    return 0;
                }
                self.get_len = CODE_BIT;
            }
            c = self.get_buf >> (CODE_BIT - width as i32);
            for _ in 0..width {
                self.get_buf = self.get_buf.wrapping_mul(2);
            }
            self.get_len -= width as i32;
        }
        c.wrapping_add(plus)
    }
}

/// `decompressInternal`: decode a whole member to `out`.
///
/// `fastest` selects the method-4 (`ARJ_FASTEST`) code path. Returns
/// `None` on any structural error, size mismatch, or non-exact input
/// consumption — the same fail-closed contract as upstream.
pub fn decompress_arj(input: &[u8], original_size: usize, fastest: bool) -> Option<Vec<u8>> {
    if original_size == 0 {
        return input.is_empty().then(Vec::new);
    }
    let mut st = State::new(input);
    let mut text = vec![0u8; DDICSIZ];
    let mut out = Vec::with_capacity(original_size);
    if !st.init_get_bits() {
        return None;
    }
    let mut count = 0usize;
    let mut out_ptr = 0usize;
    while count < original_size && !st.error {
        let token = if fastest {
            st.decode_len() as i32
        } else {
            st.decode_c() as i32
        };
        if st.error {
            break;
        }
        let literal = if fastest { token == 0 } else { token <= 255 };
        if literal {
            let mut byte = token as u8;
            if fastest {
                if st.get_len < 0 || st.get_len > CODE_BIT {
                    st.error = true;
                    break;
                }
                if st.get_len < 8 {
                    st.get_buf |= st.bit_buf >> st.get_len;
                    if !st.fill_buf(CODE_BIT - st.get_len) {
                        break;
                    }
                    st.get_len = CODE_BIT;
                }
                byte = (st.get_buf >> (CODE_BIT - 8)) as u8;
                st.get_buf = st.get_buf.wrapping_shl(8);
                st.get_len -= 8;
            }
            text[out_ptr] = byte;
            out_ptr += 1;
            count += 1;
        } else {
            let match_len = if fastest {
                token - 1 + THRESHOLD
            } else {
                token - (255 + 1 - THRESHOLD)
            };
            if match_len <= 0 || match_len > MAXMATCH || match_len as usize > original_size - count
            {
                st.error = true;
                break;
            }
            let pos = if fastest {
                st.decode_ptr() as i32
            } else {
                st.decode_p() as i32
            };
            if st.error {
                break;
            }
            if pos < 0 || pos as usize >= DDICSIZ {
                st.error = true;
                break;
            }
            let mut src = out_ptr as i32 - pos - 1;
            if src < 0 {
                src += DDICSIZ as i32;
            }
            let mut src = src as usize;
            if src >= DDICSIZ {
                st.error = true;
                break;
            }
            count += match_len as usize;
            for _ in 0..match_len {
                text[out_ptr] = text[src];
                out_ptr += 1;
                src += 1;
                if out_ptr == DDICSIZ {
                    out.extend_from_slice(&text);
                    out_ptr = 0;
                }
                if src == DDICSIZ {
                    src = 0;
                }
            }
        }
        if !st.error && out_ptr == DDICSIZ {
            out.extend_from_slice(&text);
            out_ptr = 0;
        }
    }
    let exact_input = st.cursor == input.len();
    let codec_exact = fastest || st.block_size == 0;
    let decoded_exact = !st.error && count == original_size && exact_input && codec_exact;
    if decoded_exact && out_ptr != 0 {
        out.extend_from_slice(&text[..out_ptr]);
    }
    if !decoded_exact || out.len() != original_size {
        return None;
    }
    Some(out)
}

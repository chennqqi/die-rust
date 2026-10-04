//! LHA `-lh4-`..`-lh7-` decoder, ported from upstream
//! `upstream/DIE-engine/dep/XArchive/Algos/xlzhdecoder.cpp`
//! (pin 23fec32cac2a562342c1c2db8e22ce231b58f346), itself a port of
//! the libarchive/LHAforBSD `lzh_decode.c` static/dynamic Huffman
//! LZSS decoder.
//!
//! Stream contract mirrors upstream: the packed stream must be
//! consumed byte-exactly, at most 7 slack bits may trail the last
//! block, and the produced size must equal the declared uncompressed
//! size.

const LZH_MAXMATCH: i32 = 256;
const LZH_MINMATCH: i32 = 3;
const LZH_LT_BITLEN_SIZE: usize = 256 + LZH_MAXMATCH as usize - LZH_MINMATCH as usize + 1;
const LZH_PT_BITLEN_SIZE: usize = 19;
const LZH_HTBL_BITS: i32 = 10;
const CACHE_BITS: i32 = 64;

const ST_RD_BLOCK: i32 = 0;
const ST_RD_PT_1: i32 = 1;
const ST_RD_PT_2: i32 = 2;
const ST_RD_PT_3: i32 = 3;
const ST_RD_PT_4: i32 = 4;
const ST_RD_LITERAL_1: i32 = 5;
const ST_RD_LITERAL_2: i32 = 6;
const ST_RD_LITERAL_3: i32 = 7;
const ST_RD_POS_DATA_1: i32 = 8;
const ST_GET_LITERAL: i32 = 9;
const ST_GET_POS_1: i32 = 10;
const ST_GET_POS_2: i32 = 11;
const ST_COPY_DATA: i32 = 12;

const LZH_ARCHIVE_EOF: i32 = 1;
const LZH_ARCHIVE_OK: i32 = 0;
const LZH_ARCHIVE_FAILED: i32 = -25;

/// Number of leading 1-bits before the first 0 in a 13-bit pattern;
/// mirrors upstream `bitlen_tbl`.
const BITLEN_TBL: [u8; 0x400] = {
    let mut t = [0u8; 0x400];
    let mut i = 0usize;
    while i < 0x400 {
        let mut lead = 0u8;
        let mut v = 0x200u32;
        while lead < 10 && (i as u32) & v != 0 {
            lead += 1;
            v >>= 1;
        }
        t[i] = if lead >= 10 { 0 } else { lead + 7 };
        i += 1;
    }
    t
};

/// Binary-tree node for codes longer than the direct table.
#[derive(Clone, Copy, Default)]
struct Htree {
    left: u16,
    right: u16,
}

/// One Huffman code (literal or position).
struct Huffman {
    len_size: i32,
    len_avail: i32,
    len_bits: i32,
    freq: [i32; 17],
    bitlen: Vec<u8>,
    max_bits: i32,
    shift_bits: i32,
    tbl_bits: i32,
    tree_used: i32,
    tree_avail: i32,
    tbl: Vec<u16>,
    tree: Vec<Htree>,
}

impl Huffman {
    /// `lzh_huffman_init`: allocate bitlen/tbl/tree for `len_size`
    /// symbols and `tbl_bits` code width.
    fn new(len_size: usize, tbl_bits: i32) -> Option<Self> {
        if len_size == 0 || tbl_bits <= 0 || tbl_bits >= 64 {
            return None;
        }
        let bits = tbl_bits.min(LZH_HTBL_BITS);
        let tree_avail = if tbl_bits > LZH_HTBL_BITS {
            let n = tbl_bits - LZH_HTBL_BITS + 4;
            if !(0..64).contains(&n) || (1usize << n) > i32::MAX as usize {
                return None;
            }
            1usize << n
        } else {
            0
        };
        Some(Self {
            len_size: len_size as i32,
            len_avail: 0,
            len_bits: 0,
            freq: [0; 17],
            bitlen: vec![0; len_size],
            max_bits: 0,
            shift_bits: 0,
            tbl_bits,
            tree_used: 0,
            tree_avail: tree_avail as i32,
            tbl: vec![0; 1 << bits],
            tree: vec![Htree::default(); tree_avail],
        })
    }
}

/// Decoder working state (mirrors `lzh_dec` + `lzh_stream`).
struct State<'a> {
    state: i32,
    w_size: i32,
    w_mask: i32,
    w_buff: Vec<u8>,
    w_pos: i32,
    copy_pos: i32,
    copy_len: i32,

    cache_buffer: u64,
    cache_avail: i32,

    lt: Huffman,
    pt: Huffman,

    blocks_avail: i32,
    pos_pt_len_size: i32,
    pos_pt_len_bits: i32,
    literal_pt_len_size: i32,
    literal_pt_len_bits: i32,
    reading_position: i32,
    loop_: i32,
    error: i32,

    input: &'a [u8],
    /// Cursor into `input` (mirrors `next_in`).
    next_in: usize,
    /// Compressed bytes left (mirrors `avail_in`).
    avail_in: i32,
    /// Compressed bytes consumed (mirrors `total_in`).
    total_in: i64,
    /// Decoded output.
    out: Vec<u8>,
}

impl<'a> State<'a> {
    /// `lzh_decode_init`: `method` is 4/5/6/7.
    fn new(input: &'a [u8], method: i32) -> Option<Self> {
        let w_bits = match method {
            4 => 12,
            5 => 13,
            6 => 15,
            7 => 16,
            _ => return None,
        };
        let w_size = 1i32 << 17;
        let mut w_buff = vec![0u8; w_size as usize];
        let method_size = 1usize << w_bits;
        for b in &mut w_buff[w_size as usize - method_size..] {
            *b = 0x20;
        }
        let mut lt = Huffman::new(LZH_LT_BITLEN_SIZE, 16)?;
        let pt = Huffman::new(LZH_PT_BITLEN_SIZE, 16)?;
        lt.len_bits = 9;
        Some(Self {
            state: 0,
            w_size,
            w_mask: w_size - 1,
            w_buff,
            w_pos: 0,
            copy_pos: 0,
            copy_len: 0,
            cache_buffer: 0,
            cache_avail: 0,
            lt,
            pt,
            blocks_avail: 0,
            pos_pt_len_size: w_bits + 1,
            pos_pt_len_bits: if w_bits == 15 || w_bits == 16 { 5 } else { 4 },
            literal_pt_len_size: LZH_PT_BITLEN_SIZE as i32,
            literal_pt_len_bits: 5,
            reading_position: 0,
            loop_: 0,
            error: 0,
            input,
            next_in: 0,
            avail_in: input.len() as i32,
            total_in: 0,
            out: Vec::new(),
        })
    }

    /// `lzh_br_bit_count_is_valid`.
    fn bit_count_valid(n: i32) -> bool {
        (0..=16).contains(&n)
    }

    /// `lzh_br_fillup`: pull bytes into the 64-bit cache. Returns
    /// whether the cache was completely refilled.
    fn br_fillup(&mut self) -> bool {
        if self.cache_avail < 0 || self.cache_avail > CACHE_BITS || self.avail_in < 0 {
            return false;
        }
        let mut n = CACHE_BITS - self.cache_avail;
        loop {
            let x = n >> 3;
            if self.avail_in >= x {
                match x {
                    8 => {
                        let i = self.next_in;
                        self.cache_buffer = u64::from(self.input[i]) << 56
                            | u64::from(self.input[i + 1]) << 48
                            | u64::from(self.input[i + 2]) << 40
                            | u64::from(self.input[i + 3]) << 32
                            | u64::from(self.input[i + 4]) << 24
                            | u64::from(self.input[i + 5]) << 16
                            | u64::from(self.input[i + 6]) << 8
                            | u64::from(self.input[i + 7]);
                        self.next_in += 8;
                        self.avail_in -= 8;
                        self.cache_avail += 64;
                        return true;
                    }
                    0 => return true,
                    _ => {}
                }
            }
            if self.avail_in == 0 {
                return false;
            }
            self.cache_buffer = (self.cache_buffer << 8) | u64::from(self.input[self.next_in]);
            self.next_in += 1;
            self.avail_in -= 1;
            self.cache_avail += 8;
            n -= 8;
        }
    }

    /// `lzh_br_has`.
    fn br_has(&self, n: i32) -> bool {
        self.cache_avail >= n
    }

    /// `lzh_br_read_ahead_0` / `lzh_br_read_ahead` (identical once the
    /// whole input is resident: fill, then test).
    fn br_read_ahead(&mut self, n: i32) -> bool {
        self.br_has(n) || self.br_fillup() || self.br_has(n)
    }

    /// `lzh_br_consume`.
    fn br_consume(&mut self, n: i32) {
        self.cache_avail -= n;
    }

    /// `lzh_br_bits`: top `n` cached bits (0 on invalid/insufficient).
    fn br_bits(&self, n: i32) -> u16 {
        if !Self::bit_count_valid(n)
            || self.cache_avail < n
            || self.cache_avail > CACHE_BITS
            || n == 0
        {
            return 0;
        }
        let mask = (1u64 << n) - 1;
        ((self.cache_buffer >> (self.cache_avail - n)) & mask) as u16
    }

    /// `lzh_emit_window`: append `s` window bytes to the output.
    fn emit_window(&mut self, s: usize) {
        self.out.extend_from_slice(&self.w_buff[..s]);
    }

    /// `lzh_make_fake_table`: single-symbol table from a raw field.
    fn make_fake_table(hf: &mut Huffman, c: u16) -> bool {
        if c as i32 >= hf.len_size {
            return false;
        }
        hf.tbl[0] = c;
        hf.max_bits = 0;
        hf.shift_bits = 0;
        hf.bitlen[c as usize] = 0;
        true
    }

    /// `lzh_decode_huffman_tree`: walk the extra-bits binary tree.
    fn decode_huffman_tree(hf: &Huffman, rbits: u32, c: i32) -> i32 {
        let mut c = c;
        let mut extlen = hf.shift_bits;
        while c >= hf.len_avail {
            c -= hf.len_avail;
            if {
                extlen -= 1;
                extlen < 0
            } || c >= hf.tree_used
            {
                return 0;
            }
            c = if rbits & (1 << extlen) != 0 {
                i32::from(hf.tree[c as usize].left)
            } else {
                i32::from(hf.tree[c as usize].right)
            };
        }
        c
    }

    /// `lzh_decode_huffman`: direct-table lookup with tree fallback.
    fn decode_huffman(hf: &Huffman, rbits: u32) -> i32 {
        let c = i32::from(hf.tbl[(rbits >> hf.shift_bits) as usize]);
        if c < hf.len_avail || hf.len_avail == 0 {
            return c;
        }
        Self::decode_huffman_tree(hf, rbits, c)
    }

    /// `lzh_read_pt_bitlen`: read 3-bit bitlens (7+ via `BITLEN_TBL`)
    /// into `pt.bitlen[start..end]`. Returns the reached index or -1.
    fn read_pt_bitlen(&mut self, start: i32, end: i32) -> i32 {
        let mut i = start;
        while i < end {
            if !self.br_read_ahead(3) {
                return i;
            }
            let mut c = i32::from(self.br_bits(3));
            if c == 7 {
                if !self.br_read_ahead(13) {
                    return i;
                }
                c = i32::from(BITLEN_TBL[(self.br_bits(13) & 0x3FF) as usize]);
                if c != 0 {
                    self.br_consume(c - 3);
                } else {
                    return -1;
                }
            } else {
                self.br_consume(3);
            }
            self.pt.bitlen[i as usize] = c as u8;
            self.pt.freq[c as usize] += 1;
            i += 1;
        }
        i
    }

    /// `lzh_make_huffman_table`: canonical table from `bitlen`/`freq`.
    fn make_huffman_table(hf: &mut Huffman) -> bool {
        let mut bitptn = [0i32; 17];
        let mut weight = [0i32; 17];
        let mut ptn = 0i32;
        let mut maxbits = 0i32;
        let mut w = 1i32 << 15;
        for i in 1..=16usize {
            bitptn[i] = ptn;
            weight[i] = w;
            if hf.freq[i] != 0 {
                ptn += hf.freq[i] * w;
                maxbits = i as i32;
            }
            w >>= 1;
        }
        if ptn != 0x10000 || maxbits > hf.tbl_bits {
            return false;
        }
        hf.max_bits = maxbits;

        if maxbits < 16 {
            let ebits = 16 - maxbits;
            for i in 1..=maxbits as usize {
                bitptn[i] >>= ebits;
                weight[i] >>= ebits;
            }
        }
        let mut diffbits = 0i32;
        if maxbits > LZH_HTBL_BITS {
            diffbits = maxbits - LZH_HTBL_BITS;
            for i in 1..=LZH_HTBL_BITS as usize {
                bitptn[i] >>= diffbits;
                weight[i] >>= diffbits;
            }
            let htbl_max = (bitptn[LZH_HTBL_BITS as usize]
                + weight[LZH_HTBL_BITS as usize] * hf.freq[LZH_HTBL_BITS as usize])
                as usize;
            for p in hf.tbl.iter_mut().skip(htbl_max) {
                *p = 0;
            }
        }
        hf.shift_bits = diffbits;

        let tbl_size = 1i32 << LZH_HTBL_BITS;
        let len_avail = hf.len_avail;
        hf.tree_used = 0;
        for i in 0..len_avail as usize {
            if hf.bitlen[i] == 0 {
                continue;
            }
            let len = i32::from(hf.bitlen[i]);
            let ptn = bitptn[len as usize];
            let cnt = weight[len as usize];
            if len <= LZH_HTBL_BITS {
                bitptn[len as usize] = ptn + cnt;
                if bitptn[len as usize] > tbl_size {
                    return false;
                }
                let base = ptn as usize;
                hf.tbl[base..base + cnt as usize].fill(i as u16);
                continue;
            }

            // Extra bits live in the binary tree.
            bitptn[len as usize] = ptn + cnt;
            let mut bit = 1u32 << (diffbits - 1);
            let mut extlen = len - LZH_HTBL_BITS;

            let slot = (ptn >> diffbits) as usize;
            if hf.tbl[slot] == 0 {
                hf.tbl[slot] = (len_avail + hf.tree_used) as u16;
                hf.tree_used += 1;
                if hf.tree_used > hf.tree_avail {
                    return false;
                }
                let ht = &mut hf.tree[(hf.tree_used - 1) as usize];
                ht.left = 0;
                ht.right = 0;
            } else if i32::from(hf.tbl[slot]) < len_avail
                || i32::from(hf.tbl[slot]) >= len_avail + hf.tree_used
            {
                return false;
            }
            let mut ht_idx = (i32::from(hf.tbl[slot]) - len_avail) as usize;
            loop {
                extlen -= 1;
                if extlen <= 0 {
                    break;
                }
                if ptn & bit as i32 != 0 {
                    if i32::from(hf.tree[ht_idx].left) < len_avail {
                        hf.tree[ht_idx].left = (len_avail + hf.tree_used) as u16;
                        hf.tree_used += 1;
                        if hf.tree_used > hf.tree_avail {
                            return false;
                        }
                        let h = &mut hf.tree[(hf.tree_used - 1) as usize];
                        h.left = 0;
                        h.right = 0;
                    }
                    ht_idx = (i32::from(hf.tree[ht_idx].left) - len_avail) as usize;
                } else {
                    if i32::from(hf.tree[ht_idx].right) < len_avail {
                        hf.tree[ht_idx].right = (len_avail + hf.tree_used) as u16;
                        hf.tree_used += 1;
                        if hf.tree_used > hf.tree_avail {
                            return false;
                        }
                        let h = &mut hf.tree[(hf.tree_used - 1) as usize];
                        h.left = 0;
                        h.right = 0;
                    }
                    ht_idx = (i32::from(hf.tree[ht_idx].right) - len_avail) as usize;
                }
                bit >>= 1;
            }
            if ptn & bit as i32 != 0 {
                if hf.tree[ht_idx].left != 0 {
                    return false;
                }
                hf.tree[ht_idx].left = i as u16;
            } else {
                if hf.tree[ht_idx].right != 0 {
                    return false;
                }
                hf.tree[ht_idx].right = i as u16;
            }
        }
        true
    }

    /// `lzh_read_blocks`: block/table-header state machine. Returns
    /// 100 to enter token decode, OK to await input, EOF, or FAILED.
    fn read_blocks(&mut self, last: bool) -> i32 {
        loop {
            match self.state {
                ST_RD_BLOCK => {
                    if !self.br_read_ahead(16) {
                        if !last {
                            return LZH_ARCHIVE_OK;
                        }
                        if self.br_has(8) {
                            self.error = LZH_ARCHIVE_FAILED;
                            return self.error;
                        }
                        if self.w_pos > 0 {
                            self.emit_window(self.w_pos as usize);
                            self.w_pos = 0;
                            return LZH_ARCHIVE_OK;
                        }
                        return LZH_ARCHIVE_EOF;
                    }
                    self.blocks_avail = i32::from(self.br_bits(16));
                    if self.blocks_avail == 0 {
                        // Zero block termination is only used by the
                        // ZOO path; plain LHA treats it as an error.
                        self.error = LZH_ARCHIVE_FAILED;
                        return self.error;
                    }
                    self.br_consume(16);
                    self.pt.len_size = self.literal_pt_len_size;
                    self.pt.len_bits = self.literal_pt_len_bits;
                    self.reading_position = 0;
                    self.state = ST_RD_PT_1;
                }
                ST_RD_PT_1 => {
                    if !Self::bit_count_valid(self.pt.len_bits) {
                        self.error = LZH_ARCHIVE_FAILED;
                        return self.error;
                    }
                    if !self.br_read_ahead(self.pt.len_bits) {
                        if last {
                            self.error = LZH_ARCHIVE_FAILED;
                            return self.error;
                        }
                        self.state = ST_RD_PT_1;
                        return LZH_ARCHIVE_OK;
                    }
                    self.pt.len_avail = i32::from(self.br_bits(self.pt.len_bits));
                    self.br_consume(self.pt.len_bits);
                    self.state = ST_RD_PT_2;
                }
                ST_RD_PT_2 => {
                    if !Self::bit_count_valid(self.pt.len_bits) {
                        self.error = LZH_ARCHIVE_FAILED;
                        return self.error;
                    }
                    if self.pt.len_avail == 0 {
                        if !self.br_read_ahead(self.pt.len_bits) {
                            if last {
                                self.error = LZH_ARCHIVE_FAILED;
                                return self.error;
                            }
                            self.state = ST_RD_PT_2;
                            return LZH_ARCHIVE_OK;
                        }
                        let c = self.br_bits(self.pt.len_bits);
                        if !Self::make_fake_table(&mut self.pt, c) {
                            self.error = LZH_ARCHIVE_FAILED;
                            return self.error;
                        }
                        self.br_consume(self.pt.len_bits);
                        self.state = if self.reading_position != 0 {
                            ST_GET_LITERAL
                        } else {
                            ST_RD_LITERAL_1
                        };
                        continue;
                    } else if self.pt.len_avail > self.pt.len_size {
                        self.error = LZH_ARCHIVE_FAILED;
                        return self.error;
                    }
                    self.loop_ = 0;
                    self.pt.freq = [0; 17];
                    if self.pt.len_avail < 3 || self.pt.len_size == self.pos_pt_len_size {
                        self.state = ST_RD_PT_4;
                        continue;
                    }
                    self.state = ST_RD_PT_3;
                }
                ST_RD_PT_3 => {
                    self.loop_ = self.read_pt_bitlen(self.loop_, 3);
                    if self.loop_ < 3 {
                        if self.loop_ < 0 || last {
                            self.error = LZH_ARCHIVE_FAILED;
                            return self.error;
                        }
                        self.state = ST_RD_PT_3;
                        return LZH_ARCHIVE_OK;
                    }
                    if !self.br_read_ahead(2) {
                        if last {
                            self.error = LZH_ARCHIVE_FAILED;
                            return self.error;
                        }
                        self.state = ST_RD_PT_3;
                        return LZH_ARCHIVE_OK;
                    }
                    let mut c = i32::from(self.br_bits(2));
                    self.br_consume(2);
                    if c > self.pt.len_avail - 3 {
                        self.error = LZH_ARCHIVE_FAILED;
                        return self.error;
                    }
                    let mut i = 3usize;
                    while {
                        let t = c;
                        c -= 1;
                        t > 0
                    } {
                        self.pt.bitlen[i] = 0;
                        i += 1;
                    }
                    self.loop_ = i as i32;
                    self.state = ST_RD_PT_4;
                }
                ST_RD_PT_4 => {
                    self.loop_ = self.read_pt_bitlen(self.loop_, self.pt.len_avail);
                    if self.loop_ < self.pt.len_avail {
                        if self.loop_ < 0 || last {
                            self.error = LZH_ARCHIVE_FAILED;
                            return self.error;
                        }
                        self.state = ST_RD_PT_4;
                        return LZH_ARCHIVE_OK;
                    }
                    if !Self::make_huffman_table(&mut self.pt) {
                        self.error = LZH_ARCHIVE_FAILED;
                        return self.error;
                    }
                    if self.reading_position != 0 {
                        self.state = ST_GET_LITERAL;
                        continue;
                    }
                    self.state = ST_RD_LITERAL_1;
                }
                ST_RD_LITERAL_1 => {
                    if !Self::bit_count_valid(self.lt.len_bits) {
                        self.error = LZH_ARCHIVE_FAILED;
                        return self.error;
                    }
                    if !self.br_read_ahead(self.lt.len_bits) {
                        if last {
                            self.error = LZH_ARCHIVE_FAILED;
                            return self.error;
                        }
                        self.state = ST_RD_LITERAL_1;
                        return LZH_ARCHIVE_OK;
                    }
                    self.lt.len_avail = i32::from(self.br_bits(self.lt.len_bits));
                    self.br_consume(self.lt.len_bits);
                    self.state = ST_RD_LITERAL_2;
                }
                ST_RD_LITERAL_2 => {
                    if !Self::bit_count_valid(self.lt.len_bits) {
                        self.error = LZH_ARCHIVE_FAILED;
                        return self.error;
                    }
                    if self.lt.len_avail == 0 {
                        if !self.br_read_ahead(self.lt.len_bits) {
                            if last {
                                self.error = LZH_ARCHIVE_FAILED;
                                return self.error;
                            }
                            self.state = ST_RD_LITERAL_2;
                            return LZH_ARCHIVE_OK;
                        }
                        let c = self.br_bits(self.lt.len_bits);
                        if !Self::make_fake_table(&mut self.lt, c) {
                            self.error = LZH_ARCHIVE_FAILED;
                            return self.error;
                        }
                        self.br_consume(self.lt.len_bits);
                        self.state = ST_RD_POS_DATA_1;
                        continue;
                    } else if self.lt.len_avail > self.lt.len_size {
                        self.error = LZH_ARCHIVE_FAILED;
                        return self.error;
                    }
                    self.loop_ = 0;
                    self.lt.freq = [0; 17];
                    self.state = ST_RD_LITERAL_3;
                }
                ST_RD_LITERAL_3 => {
                    if !Self::bit_count_valid(self.pt.max_bits) {
                        self.error = LZH_ARCHIVE_FAILED;
                        return self.error;
                    }
                    let mut i = self.loop_;
                    while i < self.lt.len_avail {
                        if !self.br_read_ahead(self.pt.max_bits) {
                            if last {
                                self.error = LZH_ARCHIVE_FAILED;
                                return self.error;
                            }
                            self.loop_ = i;
                            self.state = ST_RD_LITERAL_3;
                            return LZH_ARCHIVE_OK;
                        }
                        let rbits = u32::from(self.br_bits(self.pt.max_bits));
                        let c = Self::decode_huffman(&self.pt, rbits);
                        if c > 2 {
                            self.br_consume(i32::from(self.pt.bitlen[c as usize]));
                            self.lt.freq[(c - 2) as usize] += 1;
                            self.lt.bitlen[i as usize] = (c - 2) as u8;
                            i += 1;
                        } else if c == 0 {
                            self.br_consume(i32::from(self.pt.bitlen[c as usize]));
                            self.lt.bitlen[i as usize] = 0;
                            i += 1;
                        } else {
                            let n = if c == 1 { 4 } else { 9 };
                            if !self.br_read_ahead(i32::from(self.pt.bitlen[c as usize]) + n) {
                                if last {
                                    self.error = LZH_ARCHIVE_FAILED;
                                    return self.error;
                                }
                                self.loop_ = i;
                                self.state = ST_RD_LITERAL_3;
                                return LZH_ARCHIVE_OK;
                            }
                            self.br_consume(i32::from(self.pt.bitlen[c as usize]));
                            let mut c2 = i32::from(self.br_bits(n));
                            self.br_consume(n);
                            c2 += if n == 4 { 3 } else { 20 };
                            if i + c2 > self.lt.len_avail {
                                self.error = LZH_ARCHIVE_FAILED;
                                return self.error;
                            }
                            for _ in 0..c2 {
                                self.lt.bitlen[i as usize] = 0;
                                i += 1;
                            }
                        }
                    }
                    if i > self.lt.len_avail || !Self::make_huffman_table(&mut self.lt) {
                        self.error = LZH_ARCHIVE_FAILED;
                        return self.error;
                    }
                    self.state = ST_RD_POS_DATA_1;
                }
                ST_RD_POS_DATA_1 => {
                    self.pt.len_size = self.pos_pt_len_size;
                    self.pt.len_bits = self.pos_pt_len_bits;
                    self.reading_position = 1;
                    self.state = ST_RD_PT_1;
                }
                _ => {
                    // ST_GET_LITERAL: hand over to the token loop.
                    return 100;
                }
            }
        }
    }

    /// `lzh_decode_blocks`: literal/match token state machine.
    /// Mirrors upstream's local `bre` snapshot: the bit-reader fields
    /// are copied into locals and written back on every exit.
    fn decode_blocks(&mut self, last: bool) -> i32 {
        let mut br = Br {
            cache_buffer: self.cache_buffer,
            cache_avail: self.cache_avail,
        };
        let mut blocks_avail = self.blocks_avail;
        let mut copy_len = self.copy_len;
        let mut copy_pos = self.copy_pos;
        let mut w_pos = self.w_pos;
        let mut state = self.state;

        if !Self::bit_count_valid(self.lt.max_bits) || !Self::bit_count_valid(self.pt.max_bits) {
            self.error = LZH_ARCHIVE_FAILED;
            return self.error;
        }

        macro_rules! next_data {
            ($st:expr) => {{
                self.cache_buffer = br.cache_buffer;
                self.cache_avail = br.cache_avail;
                self.blocks_avail = blocks_avail;
                self.state = $st;
                self.w_pos = w_pos;
                return LZH_ARCHIVE_OK;
            }};
        }
        macro_rules! failed {
            () => {{
                self.error = LZH_ARCHIVE_FAILED;
                return self.error;
            }};
        }

        loop {
            match state {
                ST_GET_LITERAL => {
                    let mut c;
                    loop {
                        if blocks_avail == 0 {
                            self.cache_buffer = br.cache_buffer;
                            self.cache_avail = br.cache_avail;
                            self.blocks_avail = 0;
                            self.w_pos = w_pos;
                            self.copy_pos = 0;
                            self.state = ST_RD_BLOCK;
                            return 100;
                        }
                        let lt_max = self.lt.max_bits;
                        // Re-check cache_avail after fillup: fillup mutates br.
                        let avail = br.cache_avail >= lt_max || {
                            self.br_fillup_bre(&mut br);
                            br.cache_avail >= lt_max
                        };
                        if !avail {
                            if !last {
                                next_data!(ST_GET_LITERAL);
                            }
                            let rbits = u32::from(br.bits_forced(lt_max));
                            c = Self::decode_huffman(&self.lt, rbits);
                            br.cache_avail -= i32::from(self.lt.bitlen[c as usize]);
                            if br.cache_avail < 0 {
                                failed!();
                            }
                        } else {
                            let rbits = u32::from(br.bits(lt_max));
                            c = Self::decode_huffman(&self.lt, rbits);
                            br.cache_avail -= i32::from(self.lt.bitlen[c as usize]);
                        }
                        blocks_avail -= 1;
                        if c > 255 {
                            break;
                        }
                        self.w_buff[w_pos as usize] = c as u8;
                        w_pos += 1;
                        if w_pos >= self.w_size {
                            w_pos = 0;
                            self.emit_window(self.w_size as usize);
                            next_data!(ST_GET_LITERAL);
                        }
                    }
                    copy_len = c - 256 + LZH_MINMATCH;
                    state = ST_GET_POS_1;
                }
                ST_GET_POS_1 => {
                    let pt_max = self.pt.max_bits;
                    let avail = br.cache_avail >= pt_max || {
                        self.br_fillup_bre(&mut br);
                        br.cache_avail >= pt_max
                    };
                    if !avail {
                        if !last {
                            self.copy_len = copy_len;
                            next_data!(ST_GET_POS_1);
                        }
                        let rbits = u32::from(br.bits_forced(pt_max));
                        copy_pos = Self::decode_huffman(&self.pt, rbits);
                        br.cache_avail -= i32::from(self.pt.bitlen[copy_pos as usize]);
                        if br.cache_avail < 0 {
                            failed!();
                        }
                    } else {
                        let rbits = u32::from(br.bits(pt_max));
                        copy_pos = Self::decode_huffman(&self.pt, rbits);
                        br.cache_avail -= i32::from(self.pt.bitlen[copy_pos as usize]);
                    }
                    state = ST_GET_POS_2;
                }
                ST_GET_POS_2 => {
                    if copy_pos > 1 {
                        let p = copy_pos - 1;
                        if !Self::bit_count_valid(p) {
                            failed!();
                        }
                        let avail = br.cache_avail >= p || {
                            self.br_fillup_bre(&mut br);
                            br.cache_avail >= p
                        };
                        if !avail {
                            if last {
                                failed!();
                            }
                            self.copy_len = copy_len;
                            self.copy_pos = copy_pos;
                            next_data!(ST_GET_POS_2);
                        }
                        copy_pos = (1 << p) + i32::from(br.bits(p));
                        br.cache_avail -= p;
                    }
                    copy_pos = (w_pos - copy_pos - 1) & self.w_mask;
                    state = ST_COPY_DATA;
                }
                ST_COPY_DATA => {
                    loop {
                        let mut l = copy_len;
                        if copy_pos > w_pos {
                            if l > self.w_size - copy_pos {
                                l = self.w_size - copy_pos;
                            }
                        } else if l > self.w_size - w_pos {
                            l = self.w_size - w_pos;
                        }
                        let (cp, wp, n) = (copy_pos as usize, w_pos as usize, l as usize);
                        if copy_pos + l < w_pos || w_pos + l < copy_pos {
                            self.w_buff.copy_within(cp..cp + n, wp);
                        } else {
                            for li in 0..n {
                                self.w_buff[wp + li] = self.w_buff[cp + li];
                            }
                        }
                        w_pos += l;
                        if w_pos == self.w_size {
                            w_pos = 0;
                            self.emit_window(self.w_size as usize);
                            if copy_len <= l {
                                state = ST_GET_LITERAL;
                            } else {
                                self.copy_len = copy_len - l;
                                self.copy_pos = (copy_pos + l) & self.w_mask;
                            }
                            next_data!(state);
                        }
                        if copy_len <= l {
                            break;
                        }
                        copy_len -= l;
                        copy_pos = (copy_pos + l) & self.w_mask;
                    }
                    state = ST_GET_LITERAL;
                }
                _ => unreachable!("decode_blocks entered in read state"),
            }
        }
    }

    /// `br_fillup` operating on an external `Br` (mirrors upstream's
    /// local `bre` copy of the bit reader).
    fn br_fillup_bre(&mut self, br: &mut Br) -> bool {
        if br.cache_avail < 0 || br.cache_avail > CACHE_BITS || self.avail_in < 0 {
            return false;
        }
        let mut n = CACHE_BITS - br.cache_avail;
        loop {
            let x = n >> 3;
            if self.avail_in >= x {
                match x {
                    8 => {
                        let i = self.next_in;
                        br.cache_buffer = u64::from(self.input[i]) << 56
                            | u64::from(self.input[i + 1]) << 48
                            | u64::from(self.input[i + 2]) << 40
                            | u64::from(self.input[i + 3]) << 32
                            | u64::from(self.input[i + 4]) << 24
                            | u64::from(self.input[i + 5]) << 16
                            | u64::from(self.input[i + 6]) << 8
                            | u64::from(self.input[i + 7]);
                        self.next_in += 8;
                        self.avail_in -= 8;
                        br.cache_avail += 64;
                        return true;
                    }
                    0 => return true,
                    _ => {}
                }
            }
            if self.avail_in == 0 {
                return false;
            }
            br.cache_buffer = (br.cache_buffer << 8) | u64::from(self.input[self.next_in]);
            self.next_in += 1;
            self.avail_in -= 1;
            br.cache_avail += 8;
            n -= 8;
        }
    }

    /// `lzh_decode`: run the state machine until a stop code.
    fn lzh_decode(&mut self, last: bool) -> i32 {
        if self.error != 0 {
            return self.error;
        }
        let avail_before = self.avail_in;
        let mut r;
        loop {
            r = if self.state < ST_GET_LITERAL {
                self.read_blocks(last)
            } else {
                self.decode_blocks(last)
            };
            if r != 100 {
                break;
            }
        }
        self.total_in += i64::from(avail_before - self.avail_in);
        r
    }
}

/// Bit-reader snapshot used inside `decode_blocks` (mirrors the
/// upstream local `lzh_br bre = ds->br`).
struct Br {
    cache_buffer: u64,
    cache_avail: i32,
}

impl Br {
    /// `lzh_br_bits` on the local snapshot.
    fn bits(&self, n: i32) -> u16 {
        if !(0..=16).contains(&n) || self.cache_avail < n || self.cache_avail > CACHE_BITS || n == 0
        {
            return 0;
        }
        ((self.cache_buffer >> (self.cache_avail - n)) & ((1u64 << n) - 1)) as u16
    }

    /// `lzh_br_bits_forced` on the local snapshot.
    fn bits_forced(&self, n: i32) -> u16 {
        if !(0..=16).contains(&n) || self.cache_avail < 0 || self.cache_avail > CACHE_BITS || n == 0
        {
            return 0;
        }
        if self.cache_avail >= n {
            return self.bits(n);
        }
        ((self.cache_buffer << (n - self.cache_avail)) & ((1u64 << n) - 1)) as u16
    }
}

/// Hard output cap (project fail-closed bound; upstream trusts the
/// declared uncompressed size, which an attacker controls).
const MAX_OUTPUT: usize = 256 * 1024 * 1024;

/// Decompress one LHA `-lh4-`..`-lh7-` member stream.
///
/// `method` is the digit in the tag (4/5/6/7). Returns `None` on any
/// stream violation (mirroring upstream's false return): truncated
/// input, trailing data >= 8 bits, oversized output, or table errors.
pub fn decompress_lzh(input: &[u8], original_size: usize, method: i32) -> Option<Vec<u8>> {
    if original_size > MAX_OUTPUT || !(4..=7).contains(&method) {
        return None;
    }
    let mut st = State::new(input, method)?;

    // Feed the whole member as one chunk (equivalent to upstream's
    // 64 KiB device reads since all input is resident).
    let mut reached_eof = false;
    while st.avail_in > 0 {
        let r = st.lzh_decode(false);
        if r == LZH_ARCHIVE_FAILED || st.out.len() > original_size {
            return None;
        }
        if r == LZH_ARCHIVE_EOF {
            reached_eof = true;
            break;
        }
        // r == OK: either the decoder is mid-block waiting for bits it
        // could not fill (avail_in == 0) or it just emitted a window.
    }

    // Flush with `last = true`.
    if !reached_eof {
        let r = st.lzh_decode(true);
        if r == LZH_ARCHIVE_FAILED || st.out.len() > original_size {
            return None;
        }
    }

    // Upstream requires the whole packed stream to be consumed and
    // the produced size to equal the declared uncompressed size.
    if st.error != 0 || st.next_in != input.len() || st.out.len() != original_size {
        return None;
    }
    Some(st.out)
}

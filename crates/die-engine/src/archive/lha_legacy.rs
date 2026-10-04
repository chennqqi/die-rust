//! LHA legacy compression decoders, ported from upstream
//! `upstream/DIE-engine/dep/XArchive/Algos/xlha_legacy_*` (the
//! ISC-licensed Lhasa implementations by Simon Howard; see
//! `xlha_legacy.LICENSE`/`PROVENANCE.md` in the upstream tree).
//!
//! Coverage: `-lzs-`, `-lz5-`, `-lhx-`, `-lk7-` (LHARK variant of the
//! shared lh_new template), `-pm1-`, `-pm2-`. The driver mirrors
//! `XLZHDecoder::decompressLegacyLha`: codec reads produce bounded
//! chunks until the declared unpacked size is reached; the final
//! chunk is clipped to the remaining count and short reads fail.

/// MSB-first bit reader over a byte slice, mirroring
/// `xlha_legacy_bits_p.inc` (`BitStreamReader`). Reads via a callback
/// equivalent: a cursor over `input`; `eof_pad` emulates PM1's
/// `read_callback_wrapper` which synthesizes up to 16 zero bytes past
/// EOF.
struct LegacyBits<'a> {
    input: &'a [u8],
    pos: usize,
    bit_buffer: u32,
    bits: u32,
    eof_pad_remaining: usize,
}

impl<'a> LegacyBits<'a> {
    /// Create a reader; `eof_pad` is the number of zero bytes the
    /// reader may synthesize after the input ends (0 for most codecs,
    /// 16 for -pm1-).
    fn new(input: &'a [u8], eof_pad: usize) -> Self {
        Self {
            input,
            pos: 0,
            bit_buffer: 0,
            bits: 0,
            eof_pad_remaining: eof_pad,
        }
    }

    /// `callback(buf, fill_bytes)`: pull up to `n` raw bytes.
    fn pull(&mut self, buf: &mut [u8], n: usize) -> usize {
        let avail = self.input.len().saturating_sub(self.pos);
        let take = avail.min(n).min(buf.len());
        buf[..take].copy_from_slice(&self.input[self.pos..self.pos + take]);
        self.pos += take;
        if take != 0 {
            return take;
        }
        // EOF: emulate the PM1 zero-padding wrapper.
        let pad = n.min(buf.len()).min(self.eof_pad_remaining);
        if pad == 0 {
            return 0;
        }
        self.eof_pad_remaining -= pad;
        buf[..pad].fill(0);
        pad
    }

    /// `peek_bits`: top `n` bits without consuming, -1 at hard EOF.
    fn peek_bits(&mut self, n: u32) -> i32 {
        if n == 0 {
            return 0;
        }
        while self.bits < n {
            let fill_bytes = ((32 - self.bits) / 8) as usize;
            if fill_bytes == 0 {
                break;
            }
            let mut buf = [0u8; 4];
            let got = self.pull(&mut buf, fill_bytes.min(4));
            if got == 0 {
                return -1;
            }
            for b in &buf[..got] {
                self.bit_buffer |= u32::from(*b) << (24 - self.bits);
                self.bits += 8;
            }
        }
        (self.bit_buffer >> (32 - n)) as i32
    }

    /// `read_bits`: consume and return `n` bits, -1 at hard EOF.
    fn read_bits(&mut self, n: u32) -> i32 {
        let r = self.peek_bits(n);
        if r >= 0 {
            self.bit_buffer <<= n;
            self.bits -= n;
        }
        r
    }

    /// `read_bit`: consume one bit, -1 at hard EOF.
    fn read_bit(&mut self) -> i32 {
        self.read_bits(1)
    }
}

/// Read `n` bytes through the byte-oriented callback contract used by
/// -lz5- (no bit framing). Returns the number of bytes delivered.
fn pull_bytes(input: &[u8], pos: &mut usize, buf: &mut [u8]) -> usize {
    let avail = input.len().saturating_sub(*pos);
    let take = avail.min(buf.len());
    buf[..take].copy_from_slice(&input[*pos..*pos + take]);
    *pos += take;
    take
}

// ---------------------------------------------------------------------
// Binary tree decoder, mirroring `xlha_legacy_tree_p.inc` (TreeElement
// = u16 for the lh_new template, u8 for -pm2-).
// ---------------------------------------------------------------------

/// Build a binary decode tree from code lengths, mirroring
/// `init_tree` + `build_tree` (level-order expansion; leaf nodes have
/// the top bit set).
fn build_tree(tree: &mut [u16], code_lengths: &[u8]) {
    let leaf = 0x8000u16;
    for t in tree.iter_mut() {
        *t = leaf;
    }
    // (next_entry, tree_allocated) queue bookkeeping.
    let mut next_entry = 0usize;
    let mut allocated = 1usize;
    let mut code_len = 0u32;
    loop {
        // expand_queue: allocate a child pair for every queued node.
        let new_nodes = (allocated - next_entry) * 2;
        if allocated + new_nodes <= tree.len() {
            let end = allocated;
            while next_entry < end {
                tree[next_entry] = allocated as u16;
                allocated += 2;
                next_entry += 1;
            }
        }
        code_len += 1;
        // add_codes_with_length: assign this level's leaves.
        // `read_next_entry` returns 0 without advancing when the
        // queue is empty — upstream then writes the leaf at index 0;
        // mirror that (malformed-length quirk).
        let mut remaining = false;
        for (i, &l) in code_lengths.iter().enumerate() {
            if u32::from(l) == code_len {
                let node = if next_entry < allocated {
                    let n = next_entry;
                    next_entry += 1;
                    n
                } else {
                    0
                };
                tree[node] = i as u16 | leaf;
            } else if u32::from(l) > code_len {
                remaining = true;
            }
        }
        if !remaining {
            break;
        }
        if code_len > 64 {
            break;
        }
    }
}

/// `set_tree_single`: every input decodes to `code`.
fn set_tree_single(tree: &mut [u16], code: u16) {
    tree[0] = code | 0x8000;
}

/// `read_from_tree`: walk the tree bit-by-bit to a leaf.
fn read_from_tree(reader: &mut LegacyBits<'_>, tree: &[u16]) -> i32 {
    let mut code = tree[0];
    while code & 0x8000 == 0 {
        let bit = reader.read_bit();
        if bit < 0 {
            return -1;
        }
        code = tree[usize::from(code) + bit as usize];
    }
    i32::from(code & !0x8000)
}

// ---------------------------------------------------------------------
// -lzs- (LArc): 2 KiB ring buffer, 1-bit command flag, 8-bit literal or
// 11-bit pos + 4-bit len(+2).
// ---------------------------------------------------------------------

const LZS_RING: usize = 2048;
const LZS_START: usize = 17;
const LZS_THRESHOLD: usize = 2;

/// Streaming -lzs- decoder state.
struct LzsDecoder<'a> {
    reader: LegacyBits<'a>,
    ringbuf: [u8; LZS_RING],
    pos: usize,
}

impl<'a> LzsDecoder<'a> {
    /// Initialize with the upstream ' '-filled ring buffer.
    fn new(input: &'a [u8]) -> Self {
        Self {
            reader: LegacyBits::new(input, 0),
            ringbuf: [b' '; LZS_RING],
            pos: LZS_RING - LZS_START,
        }
    }

    /// Decode one command; returns emitted bytes (empty at EOF/error).
    fn read(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(15 + LZS_THRESHOLD);
        let bit = self.reader.read_bit();
        if bit < 0 {
            return out;
        }
        if bit == 1 {
            let b = self.reader.read_bits(8);
            if b < 0 {
                return Vec::new();
            }
            let v = b as u8;
            out.push(v);
            self.ringbuf[self.pos] = v;
            self.pos = (self.pos + 1) % LZS_RING;
        } else {
            let pos = self.reader.read_bits(11);
            let len = self.reader.read_bits(4);
            if pos < 0 || len < 0 {
                return Vec::new();
            }
            let (start, n) = (pos as usize, len as usize + LZS_THRESHOLD);
            for i in 0..n {
                let v = self.ringbuf[(start + i) % LZS_RING];
                out.push(v);
                self.ringbuf[self.pos] = v;
                self.pos = (self.pos + 1) % LZS_RING;
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// -lz5- (LArc): 4 KiB ring buffer with the elaborate initial fill;
// byte-oriented runs of one bitmap byte + eight commands.
// ---------------------------------------------------------------------

const LZ5_RING: usize = 4096;
const LZ5_START: usize = 18;
const LZ5_THRESHOLD: usize = 3;

/// Streaming -lz5- decoder state.
struct Lz5Decoder<'a> {
    input: &'a [u8],
    pos_in: usize,
    ringbuf: [u8; LZ5_RING],
    pos: usize,
}

impl<'a> Lz5Decoder<'a> {
    /// Initialize, reproducing `fill_initial` exactly.
    fn new(input: &'a [u8]) -> Self {
        let mut ringbuf = [0u8; LZ5_RING];
        let mut p = 0usize;
        for i in 0..256usize {
            for _ in 0..13 {
                ringbuf[p] = i as u8;
                p += 1;
            }
        }
        for i in 0..256usize {
            ringbuf[p] = i as u8;
            p += 1;
        }
        for i in 0..256usize {
            ringbuf[p] = (255 - i) as u8;
            p += 1;
        }
        p += 128; // zero block already present
        for _ in 0..110 {
            ringbuf[p] = b' ';
            p += 1;
        }
        Self {
            input,
            pos_in: 0,
            ringbuf,
            pos: LZ5_RING - LZ5_START,
        }
    }

    /// Decode one eight-command run; a mid-run EOF yields the partial
    /// result (mirroring upstream's `break`).
    fn read(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity((15 + LZ5_THRESHOLD) * 8);
        let mut bitmap = [0u8; 1];
        if pull_bytes(self.input, &mut self.pos_in, &mut bitmap) == 0 {
            return out;
        }
        for bit in 0..8 {
            if bitmap[0] & (1 << bit) != 0 {
                let mut b = [0u8; 1];
                if pull_bytes(self.input, &mut self.pos_in, &mut b) == 0 {
                    break;
                }
                out.push(b[0]);
                self.ringbuf[self.pos] = b[0];
                self.pos = (self.pos + 1) % LZ5_RING;
            } else {
                let mut cmd = [0u8; 2];
                if pull_bytes(self.input, &mut self.pos_in, &mut cmd) == 0 {
                    break;
                }
                let start = (usize::from(cmd[1] & 0xF0) << 4) | usize::from(cmd[0]);
                let n = usize::from(cmd[1] & 0x0F) + LZ5_THRESHOLD;
                for i in 0..n {
                    let v = self.ringbuf[(start + i) % LZ5_RING];
                    out.push(v);
                    self.ringbuf[self.pos] = v;
                    self.pos = (self.pos + 1) % LZ5_RING;
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// lh_new template (`xlha_legacy_new_p.inc`): shared block decoder for
// -lhx- (HISTORY_BITS=20, OFFSET_BITS=5, NUM_CODES=510) and -lk7-
// (HISTORY_BITS=16, OFFSET_BITS=6, NUM_CODES=289, LHARK extensions).
// ---------------------------------------------------------------------

const COPY_THRESHOLD: i32 = 3;
const TEMP_CODE_BITS: u32 = 5;
const MAX_TEMP_CODES: usize = (1 << TEMP_CODE_BITS) - 1;

/// Parameters describing one lh_new template instantiation.
struct LhNewParams {
    history_bits: u32,
    offset_bits: u32,
    num_codes: usize,
    lhark: bool,
}

/// Streaming lh_new decoder state.
struct LhNewDecoder<'a> {
    p: LhNewParams,
    reader: LegacyBits<'a>,
    ringbuf: Vec<u8>,
    pos: usize,
    block_remaining: u32,
    temp_tree: Vec<u16>,
    code_tree: Vec<u16>,
    offset_tree: Vec<u16>,
}

impl<'a> LhNewDecoder<'a> {
    /// Initialize with the ' '-filled ring buffer and cleared trees.
    fn new(input: &'a [u8], p: LhNewParams) -> Self {
        let ring = 1usize << p.history_bits;
        Self {
            reader: LegacyBits::new(input, 0),
            ringbuf: vec![b' '; ring],
            pos: 0,
            block_remaining: 0,
            temp_tree: vec![0; MAX_TEMP_CODES * 2],
            code_tree: vec![0; p.num_codes * 2],
            offset_tree: vec![0; ((1usize << p.offset_bits) - 1) * 2],
            p,
        }
    }

    /// `read_length_value`: 3-bit length, extended by 1-bits while
    /// the next bit is set.
    fn read_length_value(&mut self) -> i32 {
        let mut len = self.reader.read_bits(3);
        if len < 0 {
            return -1;
        }
        if len == 7 {
            loop {
                let i = self.reader.read_bit();
                if i < 0 {
                    return -1;
                }
                if i == 0 {
                    break;
                }
                len += 1;
            }
        }
        len
    }

    /// `read_temp_table`: the meta tree that encodes the code table.
    fn read_temp_table(&mut self) -> bool {
        let n = self.reader.read_bits(TEMP_CODE_BITS);
        if n < 0 {
            return false;
        }
        if n == 0 {
            let code = self.reader.read_bits(5);
            if code < 0 {
                return false;
            }
            set_tree_single(&mut self.temp_tree, code as u16);
            return true;
        }
        let n = (n as usize).min(MAX_TEMP_CODES);
        let mut code_lengths = vec![0u8; n];
        let mut i = 0usize;
        while i < n {
            let len = self.read_length_value();
            if len < 0 {
                return false;
            }
            code_lengths[i] = len as u8;
            if i == 2 {
                let skip = self.reader.read_bits(2);
                if skip < 0 {
                    return false;
                }
                for _ in 0..skip {
                    i += 1;
                    if i < n {
                        code_lengths[i] = 0;
                    }
                }
            }
            i += 1;
        }
        build_tree(&mut self.temp_tree, &code_lengths);
        true
    }

    /// `read_skip_count` for code-table holes.
    fn read_skip_count(&mut self, skiprange: i32) -> i32 {
        match skiprange {
            0 => 1,
            1 => {
                let r = self.reader.read_bits(4);
                if r < 0 { -1 } else { r + 3 }
            }
            _ => {
                let r = self.reader.read_bits(9);
                if r < 0 { -1 } else { r + 20 }
            }
        }
    }

    /// `read_code_table`: literal/copy-symbol tree, coded via the
    /// temp tree with skip runs.
    fn read_code_table(&mut self) -> bool {
        let n = self.reader.read_bits(9);
        if n < 0 {
            return false;
        }
        if n == 0 {
            let code = self.reader.read_bits(9);
            if code < 0 {
                return false;
            }
            set_tree_single(&mut self.code_tree, code as u16);
            return true;
        }
        let n = (n as usize).min(self.p.num_codes);
        let mut code_lengths = vec![0u8; n];
        let mut i = 0usize;
        while i < n {
            let code = read_from_tree(&mut self.reader, &self.temp_tree);
            if code < 0 {
                return false;
            }
            if code <= 2 {
                let skip_count = self.read_skip_count(code);
                if skip_count < 0 {
                    return false;
                }
                for _ in 0..skip_count {
                    if i < n {
                        code_lengths[i] = 0;
                        i += 1;
                    }
                }
            } else {
                code_lengths[i] = (code - 2) as u8;
                i += 1;
            }
        }
        build_tree(&mut self.code_tree, &code_lengths);
        true
    }

    /// `read_offset_table`: the position-code tree.
    fn read_offset_table(&mut self) -> bool {
        let max_codes = (1usize << self.p.offset_bits) - 1;
        let n = self.reader.read_bits(self.p.offset_bits);
        if n < 0 {
            return false;
        }
        if n == 0 {
            let code = self.reader.read_bits(self.p.offset_bits);
            if code < 0 {
                return false;
            }
            set_tree_single(&mut self.offset_tree, code as u16);
            return true;
        }
        let n = (n as usize).min(max_codes);
        let mut code_lengths = vec![0u8; n];
        for item in code_lengths.iter_mut() {
            let len = self.read_length_value();
            if len < 0 {
                return false;
            }
            *item = len as u8;
        }
        build_tree(&mut self.offset_tree, &code_lengths);
        true
    }

    /// `start_new_block`: 16-bit command count + three trees.
    fn start_new_block(&mut self) -> bool {
        let len = self.reader.read_bits(16);
        if len < 0 {
            return false;
        }
        self.block_remaining = len as u32;
        self.read_temp_table() && self.read_code_table() && self.read_offset_table()
    }

    /// `lhark_read_offset_code`: LHARK's split offset encoding.
    fn lhark_read_offset_code(&mut self, code: i32) -> i32 {
        if code < 4 {
            return code;
        }
        let num_low = ((code - 2) / 2) as u32;
        let low = self.reader.read_bits(num_low);
        if low < 0 {
            return -1;
        }
        ((2 + (code % 2)) << num_low) + low
    }

    /// `read_offset_code`: tree code 0/1 direct, else extra bits.
    fn read_offset_code(&mut self) -> i32 {
        let bits = read_from_tree(&mut self.reader, &self.offset_tree);
        if bits < 0 {
            return -1;
        }
        if bits == 0 {
            return 0;
        }
        if bits == 1 {
            return 1;
        }
        if self.p.lhark {
            return self.lhark_read_offset_code(bits);
        }
        let extra = self.reader.read_bits((bits - 1) as u32);
        if extra < 0 {
            return -1;
        }
        extra + (1 << (bits - 1))
    }

    /// `lhark_decode_copy_count`: LHARK's extended length ranges.
    fn lhark_decode_copy_count(&mut self, code: i32) -> i32 {
        if code < 264 {
            return code - 256 + COPY_THRESHOLD;
        }
        if code < 288 {
            let num_low = ((code - 260) / 4) as u32;
            let low = self.reader.read_bits(num_low);
            if low < 0 {
                return -1;
            }
            return ((4 + (code % 4)) << num_low) + low + 3;
        }
        514
    }

    /// Emit one byte into out + history.
    fn output_byte(&mut self, out: &mut Vec<u8>, b: u8) {
        out.push(b);
        let ring = self.ringbuf.len();
        self.ringbuf[self.pos] = b;
        self.pos = (self.pos + 1) % ring;
    }

    /// Decode one command; returns emitted bytes (empty on EOF).
    fn read(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while self.block_remaining == 0 {
            if !self.start_new_block() {
                return out;
            }
        }
        self.block_remaining -= 1;
        let code = read_from_tree(&mut self.reader, &self.code_tree);
        if code < 0 {
            return out;
        }
        if code < 256 {
            self.output_byte(&mut out, code as u8);
            return out;
        }
        let count = if self.p.lhark {
            let c = self.lhark_decode_copy_count(code);
            if c < 0 {
                return out;
            }
            c
        } else {
            code - 256 + COPY_THRESHOLD
        };
        let offset = self.read_offset_code();
        if offset < 0 {
            return out;
        }
        let ring = self.ringbuf.len();
        let start = self.pos + ring - offset as usize - 1;
        for i in 0..count as usize {
            let v = self.ringbuf[(start + i) % ring];
            self.output_byte(&mut out, v);
        }
        out
    }
}

// ---------------------------------------------------------------------
// PMarc shared helpers (`xlha_legacy_pma_p.inc`).
// ---------------------------------------------------------------------

/// One entry of a `VariableLengthTable` (base offset + bit count).
struct VLEntry {
    offset: u32,
    bits: u32,
}

/// `decode_variable_length`: read `bits` and add the entry offset.
fn decode_variable_length(reader: &mut LegacyBits<'_>, table: &[VLEntry], header: usize) -> i32 {
    let e = &table[header];
    let v = reader.read_bits(e.bits);
    if v < 0 {
        return -1;
    }
    e.offset as i32 + v
}

/// Move-to-front byte history (`HistoryLinkedList`).
struct HistoryList {
    prev: [u8; 256],
    next: [u8; 256],
    head: u8,
}

impl HistoryList {
    /// `init_history_list`: chain arranged so ASCII sits at the head.
    fn new() -> Self {
        let mut h = Self {
            prev: [0; 256],
            next: [0; 256],
            head: 0x20,
        };
        for i in 0..256usize {
            h.prev[i] = (i as u8).wrapping_add(1);
            h.next[i] = (i as u8).wrapping_sub(1);
        }
        h.prev[0x7f] = 0x00;
        h.next[0x00] = 0x7f;
        h.prev[0x1f] = 0xa0;
        h.next[0xa0] = 0x1f;
        h.prev[0xdf] = 0x80;
        h.next[0x80] = 0xdf;
        h.prev[0x9f] = 0xe0;
        h.next[0xe0] = 0x9f;
        h.prev[0xff] = 0x20;
        h.next[0x20] = 0xff;
        h
    }

    /// `find_in_history_list`: walk `count` nodes from the head,
    /// backwards or forwards whichever is shorter.
    fn find(&self, count: u8) -> u8 {
        let mut code = self.head;
        if count < 128 {
            for _ in 0..count {
                code = self.prev[code as usize];
            }
        } else {
            for _ in 0..(256u32 - u32::from(count)) {
                code = self.next[code as usize];
            }
        }
        code
    }

    /// `update_history_list`: move `b` to the head.
    fn update(&mut self, b: u8) {
        if self.head == b {
            return;
        }
        let b = b as usize;
        let (p, n) = (self.prev[b] as usize, self.next[b] as usize);
        self.prev[n] = p as u8;
        self.next[p] = n as u8;
        let head = self.head as usize;
        self.prev[b] = head as u8;
        self.next[b] = self.next[head];
        let hn = self.next[head] as usize;
        self.prev[hn] = b as u8;
        self.next[head] = b as u8;
        self.head = b as u8;
    }
}

// ---------------------------------------------------------------------
// -pm1- (PMarc): 16 KiB history, adaptive byte decoding via the
// history list, EOF zero padding.
// ---------------------------------------------------------------------

const PM1_RING: usize = 16384;
const PM1_MAX_BYTE_BLOCK: usize = 216;

/// `copy_ranges` table (first 6 real entries + early-stream
/// redirects).
const PM1_COPY_RANGES: [VLEntry; 15] = [
    VLEntry { offset: 0, bits: 6 },
    VLEntry {
        offset: 64,
        bits: 8,
    },
    VLEntry { offset: 0, bits: 6 },
    VLEntry {
        offset: 64,
        bits: 9,
    },
    VLEntry {
        offset: 576,
        bits: 11,
    },
    VLEntry {
        offset: 2624,
        bits: 13,
    },
    VLEntry {
        offset: 64,
        bits: 8,
    },
    VLEntry {
        offset: 576,
        bits: 8,
    },
    VLEntry {
        offset: 576,
        bits: 9,
    },
    VLEntry {
        offset: 576,
        bits: 10,
    },
    VLEntry {
        offset: 2624,
        bits: 8,
    },
    VLEntry {
        offset: 2624,
        bits: 9,
    },
    VLEntry {
        offset: 2624,
        bits: 10,
    },
    VLEntry {
        offset: 2624,
        bits: 11,
    },
    VLEntry {
        offset: 2624,
        bits: 12,
    },
];

/// `byte_ranges` table.
const PM1_BYTE_RANGES: [VLEntry; 6] = [
    VLEntry { offset: 0, bits: 4 },
    VLEntry {
        offset: 16,
        bits: 4,
    },
    VLEntry {
        offset: 32,
        bits: 5,
    },
    VLEntry {
        offset: 64,
        bits: 6,
    },
    VLEntry {
        offset: 128,
        bits: 6,
    },
    VLEntry {
        offset: 192,
        bits: 6,
    },
];

/// `byte_decode_trees` — mini binary trees, one nybble pair per
/// node. Upstream declares `[][5]` so short literals are zero-padded;
/// the same is done here. The flattened view (`PM1_TREES_FLAT`)
/// mirrors upstream memory layout: a `ptr += child` walk that leaves
/// the 5-byte row continues into the next row, which valid trees
/// never do but malformed inputs can trigger.
const PM1_BYTE_DECODE_TREES: [[u8; 5]; 32] = [
    [0x12, 0x2d, 0xef, 0x1c, 0xab],
    [0x12, 0x23, 0xde, 0xab, 0xcf],
    [0x12, 0x2c, 0xd2, 0xab, 0xef],
    [0x12, 0xa2, 0xd2, 0xbc, 0xef],
    [0x12, 0xa2, 0xc2, 0xbd, 0xef],
    [0x12, 0xa2, 0xcd, 0xb1, 0xef],
    [0x12, 0xab, 0x12, 0xcd, 0xef],
    [0x12, 0xab, 0x1d, 0xc1, 0xef],
    [0x12, 0xab, 0xc1, 0xd1, 0xef],
    [0xa1, 0x12, 0x2c, 0xde, 0xbf],
    [0xa1, 0x1d, 0x1c, 0xb1, 0xef],
    [0xa1, 0x12, 0x2d, 0xef, 0xbc],
    [0xa1, 0x12, 0xb2, 0xde, 0xcf],
    [0xa1, 0x12, 0xbc, 0xd1, 0xef],
    [0xa1, 0x1c, 0xb1, 0xd1, 0xef],
    [0xa1, 0xb1, 0x12, 0xcd, 0xef],
    [0xa1, 0xb1, 0xc1, 0xd1, 0xef],
    [0x12, 0x1c, 0xde, 0xab, 0x00],
    [0x12, 0xa2, 0xcd, 0xbe, 0x00],
    [0x12, 0xab, 0xc1, 0xde, 0x00],
    [0xa1, 0x1d, 0x1c, 0xbe, 0x00],
    [0xa1, 0x12, 0xbc, 0xde, 0x00],
    [0xa1, 0x1c, 0xb1, 0xde, 0x00],
    [0xa1, 0xb1, 0xc1, 0xde, 0x00],
    [0x1d, 0x1c, 0xab, 0x00, 0x00],
    [0x1c, 0xa1, 0xbd, 0x00, 0x00],
    [0x12, 0xab, 0xcd, 0x00, 0x00],
    [0xa1, 0x1c, 0xbd, 0x00, 0x00],
    [0xa1, 0xb1, 0xcd, 0x00, 0x00],
    [0xa1, 0xbc, 0x00, 0x00, 0x00],
    [0xab, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00],
];

/// Flattened `PM1_BYTE_DECODE_TREES` for upstream-faithful
/// cross-row tree walks.
const PM1_TREES_FLAT: [u8; 32 * 5] = {
    let mut flat = [0u8; 32 * 5];
    let mut i = 0;
    while i < 32 {
        let mut j = 0;
        while j < 5 {
            flat[i * 5 + j] = PM1_BYTE_DECODE_TREES[i][j];
            j += 1;
        }
        i += 1;
    }
    flat
};

/// Streaming -pm1- decoder state.
struct Pm1Decoder<'a> {
    reader: LegacyBits<'a>,
    output_pos: usize,
    /// Index of the selected tree's first byte in `PM1_TREES_FLAT`
    /// (`None` until the start header is read).
    byte_tree_base: Option<usize>,
    ringbuf: [u8; PM1_RING],
    pos: usize,
    history: HistoryList,
}

impl<'a> Pm1Decoder<'a> {
    /// Initialize with 16 bytes of EOF zero padding (upstream
    /// `read_callback_wrapper`).
    fn new(input: &'a [u8]) -> Self {
        Self {
            reader: LegacyBits::new(input, 16),
            output_pos: 0,
            byte_tree_base: None,
            ringbuf: [0; PM1_RING],
            pos: 0,
            history: HistoryList::new(),
        }
    }

    /// `outputted_byte`: ring buffer + history list + position.
    fn outputted_byte(&mut self, b: u8) {
        self.ringbuf[self.pos] = b;
        self.pos = (self.pos + 1) % PM1_RING;
        self.history.update(b);
        self.output_pos += 1;
    }

    /// `read_copy_byte_count` static huffman ladder.
    fn read_copy_byte_count(&mut self) -> i32 {
        let x = self.reader.read_bits(2);
        if x < 0 {
            return -1;
        }
        if x < 3 {
            return x + 3;
        }
        let x = self.reader.read_bits(3);
        if x < 0 {
            return -1;
        }
        if x < 5 {
            return x + 6;
        }
        if x == 5 {
            let v = self.reader.read_bits(2);
            return if v < 0 { -1 } else { v + 11 };
        }
        if x == 6 {
            let v = self.reader.read_bits(3);
            return if v < 0 { -1 } else { v + 15 };
        }
        let x = self.reader.read_bits(6);
        if x < 0 {
            return -1;
        }
        if x < 62 {
            return x + 23;
        }
        if x == 62 {
            let v = self.reader.read_bits(5);
            return if v < 0 { -1 } else { v + 85 };
        }
        let v = self.reader.read_bits(7);
        if v < 0 { -1 } else { v + 117 }
    }

    /// `read_bit_after_threshold`.
    fn read_bit_after_threshold(&mut self, threshold: usize, def: i32) -> i32 {
        if self.output_pos >= threshold {
            self.reader.read_bit()
        } else {
            def
        }
    }

    /// `read_copy_type_range`: tree that grows with output position.
    fn read_copy_type_range(&mut self) -> i32 {
        let x = self.reader.read_bit();
        if x < 0 {
            return -1;
        }
        if x == 0 {
            let y = self.read_bit_after_threshold(576, 0);
            if y < 0 {
                return -1;
            }
            if y != 0 {
                return 4;
            }
            self.read_bit_after_threshold(64, 0)
        } else {
            let y = self.read_bit_after_threshold(64, 1);
            if y < 0 {
                return -1;
            }
            if y == 0 {
                return 3;
            }
            let z = self.read_bit_after_threshold(2624, 1);
            if z < 0 {
                return -1;
            }
            if z != 0 { 2 } else { 5 }
        }
    }

    /// `read_copy_command`: copy `count` bytes from history.
    fn read_copy_command(&mut self, buf: &mut Vec<u8>) -> bool {
        let mut range_index = self.read_copy_type_range();
        if range_index < 0 {
            return false;
        }
        let count = if range_index < 2 {
            2usize
        } else {
            let c = self.read_copy_byte_count();
            if c < 0 {
                return false;
            }
            c as usize
        };
        if range_index == 3 {
            if self.output_pos < 320 {
                range_index = 6;
            }
        } else if range_index == 4 {
            if self.output_pos < 832 {
                range_index = 7;
            } else if self.output_pos < 1088 {
                range_index = 8;
            } else if self.output_pos < 1600 {
                range_index = 9;
            }
        } else if range_index == 5 {
            if self.output_pos < 2880 {
                range_index = 10;
            } else if self.output_pos < 3136 {
                range_index = 11;
            } else if self.output_pos < 3648 {
                range_index = 12;
            } else if self.output_pos < 4672 {
                range_index = 13;
            } else if self.output_pos < 6720 {
                range_index = 14;
            }
        }
        let dist = decode_variable_length(&mut self.reader, &PM1_COPY_RANGES, range_index as usize);
        if dist < 0 || dist as usize >= self.output_pos {
            return false;
        }
        let mut idx = (self.pos + PM1_RING - dist as usize - 1) % PM1_RING;
        for _ in 0..count {
            let v = self.ringbuf[idx];
            buf.push(v);
            self.outputted_byte(v);
            idx = (idx + 1) % PM1_RING;
        }
        true
    }

    /// `read_byte_decode_index`: walk the nybble mini-tree. The walk
    /// uses the flattened table so a `child` offset that leaves the
    /// selected row continues into the next row like upstream's
    /// contiguous `byte_decode_trees` array.
    fn read_byte_decode_index(&mut self) -> i32 {
        let mut idx = match self.byte_tree_base {
            Some(b) => b,
            None => return -1,
        };
        if PM1_TREES_FLAT[idx] == 0 {
            return 0;
        }
        loop {
            let bit = self.reader.read_bit();
            if bit < 0 {
                return -1;
            }
            let node = PM1_TREES_FLAT[idx];
            let child = if bit == 0 {
                usize::from(node >> 4)
            } else {
                usize::from(node & 0x0F)
            };
            if child >= 10 {
                return (child - 10) as i32;
            }
            idx += child;
            if idx >= PM1_TREES_FLAT.len() {
                // Past the last row upstream would read unowned
                // memory; fail closed instead.
                return -1;
            }
        }
    }

    /// `read_byte`: index → variable-length → history list walk.
    fn read_byte(&mut self) -> i32 {
        let index = self.read_byte_decode_index();
        if index < 0 {
            return -1;
        }
        let count = decode_variable_length(&mut self.reader, &PM1_BYTE_RANGES, index as usize);
        if count < 0 {
            return -1;
        }
        i32::from(self.history.find(count as u8))
    }

    /// `read_byte_block_count` static huffman ladder.
    fn read_byte_block_count(&mut self) -> i32 {
        let x = self.reader.read_bits(2);
        if x < 0 {
            return 0;
        }
        if x < 3 {
            return x + 1;
        }
        let x = self.reader.read_bits(3);
        if x < 0 {
            return 0;
        }
        if x < 7 {
            return x + 4;
        }
        let x = self.reader.read_bits(4);
        if x < 0 {
            return 0;
        }
        if x < 14 {
            return x + 11;
        }
        if x == 14 {
            let v = self.reader.read_bits(6);
            return if v < 0 { 0 } else { v + 25 };
        }
        let v = self.reader.read_bits(7);
        if v < 0 { 0 } else { v + 89 }
    }

    /// `read_byte_block`: block of literals (+ trailing copy when the
    /// block was not maximal).
    fn read_byte_block(&mut self, buf: &mut Vec<u8>) -> bool {
        let block_len = self.read_byte_block_count();
        if block_len == 0 {
            return false;
        }
        for _ in 0..block_len {
            let b = self.read_byte();
            if b < 0 {
                return false;
            }
            buf.push(b as u8);
            self.outputted_byte(b as u8);
        }
        if block_len as usize == PM1_MAX_BYTE_BLOCK {
            return true;
        }
        self.read_copy_command(buf)
    }

    /// Decode one command (header on first call). Any inner failure
    /// yields zero bytes like upstream (`lha_pm1_read` returns 0 even
    /// after a partial block), which the driver treats as failure.
    fn read(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.byte_tree_base.is_none() {
            let index = self.reader.read_bits(5);
            if index < 0 {
                return out;
            }
            self.byte_tree_base = Some(index as usize * 5);
        }
        let ok = match self.reader.read_bit() {
            0 => self.read_copy_command(&mut out),
            1 => self.read_byte_block(&mut out),
            _ => false,
        };
        if ok { out } else { Vec::new() }
    }
}

// ---------------------------------------------------------------------
// -pm2- (PMarc/MSX): 8 KiB history, rebuildable code/offset trees.
// ---------------------------------------------------------------------

const PM2_RING: usize = 8192;
const PM2_CODE_TREE: usize = 65;
const PM2_OFFSET_TREE: usize = 17;
const PM2_OUTPUT_MAX: usize = 256;

/// `history_decode` table.
const PM2_HISTORY_DECODE: [VLEntry; 8] = [
    VLEntry { offset: 0, bits: 3 },
    VLEntry { offset: 8, bits: 3 },
    VLEntry {
        offset: 16,
        bits: 4,
    },
    VLEntry {
        offset: 32,
        bits: 5,
    },
    VLEntry {
        offset: 64,
        bits: 5,
    },
    VLEntry {
        offset: 96,
        bits: 5,
    },
    VLEntry {
        offset: 128,
        bits: 6,
    },
    VLEntry {
        offset: 192,
        bits: 6,
    },
];

/// `copy_decode` table.
const PM2_COPY_DECODE: [VLEntry; 6] = [
    VLEntry {
        offset: 17,
        bits: 3,
    },
    VLEntry {
        offset: 25,
        bits: 3,
    },
    VLEntry {
        offset: 33,
        bits: 5,
    },
    VLEntry {
        offset: 65,
        bits: 6,
    },
    VLEntry {
        offset: 129,
        bits: 7,
    },
    VLEntry {
        offset: 256,
        bits: 0,
    },
];

/// Tree rebuild state, mirroring `PM2RebuildState`.
#[derive(PartialEq, Clone, Copy)]
enum Pm2State {
    Unbuilt,
    Build1,
    Build2,
    Build3,
    Continuing,
}

/// Streaming -pm2- decoder state.
struct Pm2Decoder<'a> {
    reader: LegacyBits<'a>,
    state: Pm2State,
    rebuild_remaining: usize,
    ringbuf: [u8; PM2_RING],
    pos: usize,
    history: HistoryList,
    code_tree: [u16; PM2_CODE_TREE],
    offset_tree: [u16; PM2_OFFSET_TREE],
    need_offset_tree: bool,
}

impl<'a> Pm2Decoder<'a> {
    /// Initialize: ' ' ring buffer, unbuilt trees.
    fn new(input: &'a [u8]) -> Self {
        Self {
            reader: LegacyBits::new(input, 0),
            state: Pm2State::Unbuilt,
            rebuild_remaining: 0,
            ringbuf: [b' '; PM2_RING],
            pos: 0,
            history: HistoryList::new(),
            code_tree: [0x8000; PM2_CODE_TREE],
            offset_tree: [0x8000; PM2_OFFSET_TREE],
            need_offset_tree: false,
        }
    }

    /// `read_code_tree`: 5-bit count + 3-bit min length + per-code
    /// `length_bits` entries.
    fn read_code_tree(&mut self) -> bool {
        let num_codes = self.reader.read_bits(5);
        let min_len = self.reader.read_bits(3);
        if num_codes < 0 || min_len < 0 {
            return false;
        }
        let num_codes = num_codes as usize;
        if num_codes > 29 {
            return false;
        }
        self.need_offset_tree = num_codes >= 10 && !(num_codes == 29 && min_len == 0);
        if min_len == 0 {
            set_tree_single(&mut self.code_tree, (num_codes - 1) as u16);
            return true;
        }
        let length_bits = self.reader.read_bits(3);
        if length_bits < 0 {
            return false;
        }
        let mut code_lengths = [0u8; 31];
        for item in code_lengths.iter_mut().take(num_codes) {
            let val = self.reader.read_bits(length_bits as u32);
            if val < 0 {
                return false;
            }
            *item = if val == 0 {
                0
            } else {
                (min_len + val - 1) as u8
            };
        }
        build_tree(&mut self.code_tree, &code_lengths[..num_codes]);
        true
    }

    /// `read_offset_tree`: `num_offsets` 3-bit lengths; a single code
    /// collapses to a leaf-only tree.
    fn read_offset_tree(&mut self, num_offsets: usize) -> bool {
        if !self.need_offset_tree {
            return true;
        }
        let mut offset_lengths = [0u8; 8];
        let mut num_codes = 0usize;
        let mut single = 0usize;
        for (off, item) in offset_lengths.iter_mut().enumerate().take(num_offsets) {
            let len = self.reader.read_bits(3);
            if len < 0 {
                return false;
            }
            *item = len as u8;
            if len != 0 {
                single = off;
                num_codes += 1;
            }
        }
        if num_codes == 1 {
            set_tree_single(&mut self.offset_tree, single as u16);
            return true;
        }
        build_tree(&mut self.offset_tree, &offset_lengths[..num_offsets]);
        true
    }

    /// `rebuild_tree` state machine.
    fn rebuild_tree(&mut self) {
        match self.state {
            Pm2State::Unbuilt => {
                self.read_code_tree();
                self.read_offset_tree(5);
                self.state = Pm2State::Build1;
                self.rebuild_remaining = 1024;
            }
            Pm2State::Build1 => {
                self.read_offset_tree(6);
                self.state = Pm2State::Build2;
                self.rebuild_remaining = 1024;
            }
            Pm2State::Build2 => {
                self.read_offset_tree(7);
                self.state = Pm2State::Build3;
                self.rebuild_remaining = 2048;
            }
            Pm2State::Build3 => {
                if self.reader.read_bit() == 1 {
                    self.read_code_tree();
                }
                self.read_offset_tree(8);
                self.state = Pm2State::Continuing;
                self.rebuild_remaining = 4096;
            }
            Pm2State::Continuing => {
                if self.reader.read_bit() == 1 {
                    self.read_code_tree();
                    self.read_offset_tree(8);
                }
                self.rebuild_remaining = 4096;
            }
        }
    }

    /// `output_byte`: history + rebuild countdown.
    fn output_byte(&mut self, out: &mut Vec<u8>, b: u8) {
        self.ringbuf[self.pos] = b;
        self.pos = (self.pos + 1) % PM2_RING;
        out.push(b);
        self.history.update(b);
        // size_t wraparound semantics: when the counter is already
        // zero it wraps instead of triggering a rebuild every byte.
        self.rebuild_remaining = self.rebuild_remaining.wrapping_sub(1);
        if self.rebuild_remaining == 0 {
            self.rebuild_tree();
        }
    }

    /// `read_single_byte`: variable-length history index.
    fn read_single_byte(&mut self, code: usize, out: &mut Vec<u8>) {
        let off = decode_variable_length(&mut self.reader, &PM2_HISTORY_DECODE, code);
        if off < 0 {
            return;
        }
        let b = self.history.find(off as u8);
        self.output_byte(out, b);
    }

    /// `history_get_count`.
    fn history_get_count(&mut self, code: usize) -> i32 {
        if code < 15 {
            code as i32 + 2
        } else {
            decode_variable_length(&mut self.reader, &PM2_COPY_DECODE, code - 15)
        }
    }

    /// `history_get_offset`.
    fn history_get_offset(&mut self, code: usize) -> i32 {
        let mut result = 0i32;
        let bits: u32;
        if code == 0 {
            bits = 6;
        } else if code < 20 {
            let val = read_from_tree(&mut self.reader, &self.offset_tree);
            if val < 0 {
                return -1;
            }
            if val == 0 {
                bits = 6;
            } else {
                bits = val as u32 + 5;
                result = 1 << bits;
            }
        } else {
            return 0;
        }
        let val = self.reader.read_bits(bits);
        if val < 0 {
            return -1;
        }
        result + val
    }

    /// `copy_from_history`.
    fn copy_from_history(&mut self, code: usize, out: &mut Vec<u8>) {
        let to_copy = self.history_get_count(code);
        let offset = self.history_get_offset(code);
        if to_copy < 0 || offset < 0 || to_copy as usize > PM2_OUTPUT_MAX {
            return;
        }
        let start = self.pos + PM2_RING - 1 - offset as usize;
        for i in 0..to_copy as usize {
            let v = self.ringbuf[(start + i) % PM2_RING];
            self.output_byte(out, v);
        }
    }

    /// Decode one command (first bit of stream discarded, then the
    /// initial tree build).
    fn read(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.state == Pm2State::Unbuilt {
            let _ = self.reader.read_bit();
            self.rebuild_tree();
        }
        let code = read_from_tree(&mut self.reader, &self.code_tree);
        if code < 0 {
            return out;
        }
        if code < 8 {
            self.read_single_byte(code as usize, &mut out);
        } else {
            self.copy_from_history(code as usize - 8, &mut out);
        }
        out
    }
}

// ---------------------------------------------------------------------
// Driver (`decompressLegacyLha`).
// ---------------------------------------------------------------------

/// Per-codec `max_read` bound for a single `read` call and its
/// scratch requirement (mirrors `XLhaLegacyDecoderType`).
fn codec_max_read(tag: &[u8; 4]) -> Option<usize> {
    match tag {
        b"-lzs" => Some(15 + 2),
        b"-lz5" => Some((15 + 3) * 8),
        b"-lhx" => Some(1 << 20),
        b"-lk7" => Some(1 << 16),
        b"-pm1" => Some(216 + 244),
        b"-pm2" => Some(256),
        _ => None,
    }
}

/// Decode a legacy LHA member. `tag` is the first 4 bytes of the
/// 5-byte method tag (`-lzs` etc.; the trailing `-` is uniform).
/// Returns `Some` only when exactly `expected` bytes were produced —
/// mirroring `decompressLegacyLha` (codec reads fill a bounded
/// scratch buffer, the last chunk is clipped, short output fails
/// closed).
pub fn decompress_lha_legacy(input: &[u8], expected: usize, tag: &[u8; 4]) -> Option<Vec<u8>> {
    const MAX_OUT: usize = 128 * 1024 * 1024;
    if expected > MAX_OUT || input.len() > MAX_OUT {
        return None;
    }
    let max_read = codec_max_read(tag)?;
    let mut out: Vec<u8> = Vec::with_capacity(expected.min(1 << 20));

    macro_rules! run {
        ($dec:expr) => {{
            let mut dec = $dec;
            loop {
                if out.len() >= expected {
                    break;
                }
                let chunk = dec.read();
                if chunk.is_empty() || chunk.len() > max_read {
                    return None;
                }
                let take = (expected - out.len()).min(chunk.len());
                out.extend_from_slice(&chunk[..take]);
            }
        }};
    }

    match tag {
        b"-lzs" => run!(LzsDecoder::new(input)),
        b"-lz5" => run!(Lz5Decoder::new(input)),
        b"-lhx" => run!(LhNewDecoder::new(
            input,
            LhNewParams {
                history_bits: 20,
                offset_bits: 5,
                num_codes: 510,
                lhark: false,
            },
        )),
        b"-lk7" => run!(LhNewDecoder::new(
            input,
            LhNewParams {
                history_bits: 16,
                offset_bits: 6,
                num_codes: 289,
                lhark: true,
            },
        )),
        b"-pm1" => run!(Pm1Decoder::new(input)),
        b"-pm2" => run!(Pm2Decoder::new(input)),
        _ => return None,
    }

    if out.len() != expected {
        return None;
    }
    Some(out)
}

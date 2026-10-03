//! LHA `-lh1-` decoder, ported from the `Lzhuf` struct embedded in
//! `upstream/DIE-engine/dep/XArchive/Algos/xlzhdecoder.cpp`
//! (pin 23fec32cac2a562342c1c2db8e22ce231b58f346) — the classic
//! Okumura/Yoshizaki LZHUF scheme: a 4 KiB sliding dictionary whose
//! literal/length symbols use an adaptive (self-adjusting) Huffman
//! tree, and match positions use a fixed code table.
//!
//! Stream contract mirrors upstream `decompressLh1`: the declared
//! unpacked size bounds the output, up to two zero padding bytes may
//! be read past the packed stream, and the consumed bit count must
//! land within the last byte's 7-bit slack.

const N: usize = 4096; // ring buffer size
const LZF: usize = 60; // upper limit for match length
const THRESHOLD: usize = 2; // encode matches only when longer than this
const N_CHAR: usize = 256 - THRESHOLD + LZF; // 314 literal/length symbols
const T: usize = N_CHAR * 2 - 1; // 627 tree nodes
const R: usize = T - 1; // root position
const MAX_FREQ: i32 = 0x8000; // rebuild threshold for the root frequency

/// Maximum unpacked member size accepted by the upstream decoder
/// (`LH1_MAX_UNPACKED_BUFFER_SIZE`).
const MAX_UNPACKED: usize = 256 * 1024 * 1024;

/// Maximum packed member size (`LH1_MAX_PACKED_BUFFER_SIZE`); the
/// upstream whole-buffer decoder rejects larger input extents.
const MAX_PACKED: usize = 256 * 1024 * 1024;

/// Adaptive-Huffman LZHUF decoder state.
struct Lzhuf<'a> {
    input: &'a [u8],
    in_pos: usize,
    bits_consumed: i64,
    padding_reads: i32,
    input_error: bool,
    getbuf: u16,
    getlen: i32,

    freq: [i32; T + 1],
    prnt: [i32; T + N_CHAR],
    son: [i32; T],
    d_len: [u8; 256],
    d_code: [u8; 256],
    text_buf: [u8; N],
}

impl<'a> Lzhuf<'a> {
    /// Initialize the decoder state and the fixed position tables
    /// (`dCode`/`dLen`: canonical layout 1x3, 3x4, 8x5, 12x6, 24x7,
    /// 16x8).
    fn new(input: &'a [u8]) -> Self {
        let mut d = Self {
            input,
            in_pos: 0,
            bits_consumed: 0,
            padding_reads: 0,
            input_error: false,
            getbuf: 0,
            getlen: 0,
            freq: [0; T + 1],
            prnt: [0; T + N_CHAR],
            son: [0; T],
            d_len: [0; 256],
            d_code: [0; 256],
            text_buf: [0; N],
        };
        let n_syms = [1usize, 3, 8, 12, 24, 16];
        let (mut n_idx, mut n_sym) = (0usize, 0usize);
        for (i, &count) in n_syms.iter().enumerate() {
            let n_len = (i + 3) as u8;
            let n_span = 1usize << (8 - n_len);
            for _ in 0..count {
                for _ in 0..n_span {
                    d.d_len[n_idx] = n_len;
                    d.d_code[n_idx] = n_sym as u8;
                    n_idx += 1;
                }
                n_sym += 1;
            }
        }
        d.start_huff();
        d
    }

    /// `getbuf` refill: read one byte, tolerating up to two zero
    /// padding reads past the end of input.
    fn refill(&mut self) {
        let c = if self.in_pos < self.input.len() {
            let c = self.input[self.in_pos];
            self.in_pos += 1;
            c
        } else if self.padding_reads < 2 {
            self.padding_reads += 1;
            0
        } else {
            self.input_error = true;
            0
        };
        self.getbuf |= (c as u16) << (8 - self.getlen);
        self.getlen += 8;
    }

    /// `_getBit`: MSB-first single bit.
    fn get_bit(&mut self) -> i32 {
        while self.getlen <= 8 {
            self.refill();
        }
        let x = (self.getbuf >> 15) & 1;
        self.getbuf <<= 1;
        self.getlen -= 1;
        self.bits_consumed += 1;
        if self.bits_consumed > (self.input.len() as i64) * 8 {
            self.input_error = true;
        }
        i32::from(x)
    }

    /// `_getByte`: MSB-first byte.
    fn get_byte(&mut self) -> i32 {
        while self.getlen <= 8 {
            self.refill();
        }
        let x = (self.getbuf >> 8) & 0xFF;
        self.getbuf <<= 8;
        self.getlen -= 8;
        self.bits_consumed += 8;
        if self.bits_consumed > (self.input.len() as i64) * 8 {
            self.input_error = true;
        }
        i32::from(x)
    }

    /// `_startHuff`: build the initial uniform Huffman tree.
    fn start_huff(&mut self) {
        for i in 0..N_CHAR {
            self.freq[i] = 1;
            self.son[i] = (i + T) as i32;
            self.prnt[i + T] = i as i32;
        }
        let (mut i, mut j) = (0usize, N_CHAR);
        while j <= R {
            self.freq[j] = self.freq[i] + self.freq[i + 1];
            self.son[j] = i as i32;
            self.prnt[i] = j as i32;
            self.prnt[i + 1] = j as i32;
            i += 2;
            j += 1;
        }
        self.freq[T] = 0xFFFF;
        self.prnt[R] = 0;
    }

    /// `_reconst`: halve leaf frequencies and rebuild the tree
    /// bottom-up in frequency order.
    fn reconst(&mut self) {
        let mut j = 0usize;
        for i in 0..T {
            if self.son[i] >= T as i32 {
                self.freq[j] = (self.freq[i] + 1) / 2;
                self.son[j] = self.son[i];
                j += 1;
            }
        }
        let mut i = 0usize;
        let mut k = N_CHAR;
        while k < T {
            let f = self.freq[i] + self.freq[i + 1];
            self.freq[k] = f;
            let mut l = k as i32 - 1;
            while f < self.freq[l as usize] {
                l -= 1;
            }
            let l = (l + 1) as usize;
            for m in (l + 1..=k).rev() {
                self.freq[m] = self.freq[m - 1];
                self.son[m] = self.son[m - 1];
            }
            self.freq[l] = f;
            self.son[l] = i as i32;
            i += 2;
            k += 1;
        }
        for i in 0..T {
            let k = self.son[i] as usize;
            if k >= T {
                self.prnt[k] = i as i32;
            } else {
                self.prnt[k] = i as i32;
                self.prnt[k + 1] = i as i32;
            }
        }
    }

    /// `_update`: increment the frequency of symbol `c` and keep the
    /// node list frequency-ordered by swapping.
    fn update(&mut self, c: usize) {
        if self.freq[R] == MAX_FREQ {
            self.reconst();
        }
        let mut c = self.prnt[c + T] as usize;
        loop {
            self.freq[c] += 1;
            let k = self.freq[c];
            let mut l = c + 1;
            if k > self.freq[l] {
                while k > self.freq[l + 1] {
                    l += 1;
                }
                self.freq[c] = self.freq[l];
                self.freq[l] = k;
                let i = self.son[c] as usize;
                self.prnt[i] = l as i32;
                if i < T {
                    self.prnt[i + 1] = l as i32;
                }
                let j = self.son[l] as usize;
                self.son[l] = i as i32;
                self.prnt[j] = c as i32;
                if j < T {
                    self.prnt[j + 1] = c as i32;
                }
                self.son[c] = j as i32;
                c = l;
            }
            c = self.prnt[c] as usize;
            if c == 0 {
                break;
            }
        }
    }

    /// `_decodeChar`: walk the adaptive tree to a leaf.
    fn decode_char(&mut self) -> i32 {
        let mut c = self.son[R] as usize;
        while c < T {
            let bit = self.get_bit() as usize;
            c = self.son[c + bit] as usize;
        }
        c -= T;
        self.update(c);
        c as i32
    }

    /// `_decodePosition`: fixed-table high bits + literal low bits.
    fn decode_position(&mut self) -> i32 {
        let mut i = self.get_byte();
        if i < 0 {
            return -1;
        }
        let c = i32::from(self.d_code[i as usize]) << 6;
        let mut j = i32::from(self.d_len[i as usize]) - 2;
        while j > 0 {
            j -= 1;
            i = (i << 1) + self.get_bit();
        }
        c | (i & 0x3F)
    }

    /// `decode`: produce exactly `text_size` bytes, `None` on error.
    fn decode(&mut self, text_size: usize) -> Option<Vec<u8>> {
        if text_size > MAX_UNPACKED {
            return None;
        }
        for b in self.text_buf[..N - LZF].iter_mut() {
            *b = b' ';
        }
        let mut r = N - LZF;
        let mut out = vec![0u8; text_size];
        let mut count = 0usize;
        while count < text_size {
            let c = self.decode_char();
            if self.input_error {
                return None;
            }
            if c < 256 {
                out[count] = c as u8;
                self.text_buf[r] = c as u8;
                r = (r + 1) & (N - 1);
                count += 1;
            } else {
                let pos = self.decode_position();
                if self.input_error || pos < 0 {
                    return None;
                }
                let i = (r as i32 - pos - 1) & (N as i32 - 1);
                let j = c as usize - 255 + THRESHOLD;
                if j > text_size - count {
                    return None;
                }
                for k in 0..j {
                    let cc = self.text_buf[((i + k as i32) & (N as i32 - 1)) as usize];
                    out[count] = cc;
                    self.text_buf[r] = cc;
                    r = (r + 1) & (N - 1);
                    count += 1;
                }
            }
        }
        Some(out)
    }
}

/// Decode an `-lh1-` member. Mirrors `decompressLh1`: the packed
/// stream must end with at most 7 slack bits and the produced size
/// must equal `expected` exactly.
pub fn decompress_lh1(input: &[u8], expected: usize) -> Option<Vec<u8>> {
    if expected > MAX_UNPACKED || input.len() > MAX_PACKED || (input.is_empty() && expected != 0) {
        return None;
    }
    let mut dec = Lzhuf::new(input);
    let out = dec.decode(expected)?;
    let total_bits = (input.len() as i64) * 8;
    if dec.bits_consumed > total_bits || (total_bits - dec.bits_consumed) >= 8 {
        return None;
    }
    Some(out)
}

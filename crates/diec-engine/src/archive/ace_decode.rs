//! ACE compression decoder (tech type 1, LZ+Huffman), ported from
//! upstream `upstream/DIE-engine/dep/XArchive/Algos/xacedecoder.cpp`
//! (pin 23fec32cac2a562342c1c2db8e22ce231b58f346), itself a port of
//! `uac_dcpr.c` from unace.
//!
//! Stream contract mirrors upstream: the packed member size must be a
//! multiple of 4 (DWORD-graded bit stream), the decoded size must equal
//! the declared uncompressed size, and the bit reader must finish
//! within 32 bits of the end of the stream.

const ACE_MAXDIC: u32 = 22;
const ACE_MAXWD_MN: u32 = 11;
const ACE_MAXWD_LG: u32 = 11;
const ACE_MAXWD_SVWD: u32 = 7;
const ACE_MAXLENGTH: i32 = 259;
const ACE_MAXDIS2: u32 = 255;
const ACE_MAXDIS3: u32 = 8191;
const ACE_MAX_CD_MN: usize = 282;
const ACE_MAX_CD_LG: usize = 255;
const ACE_SVWD_CNT: u32 = 15;
const ACE_SIZE_RDB: usize = 2048;

/// Hard output cap (project fail-closed bound; upstream relies on the
/// declared uncompressed size, which an attacker controls). Streams
/// claiming more than this are rejected before decoding.
const MAX_OUTPUT: i64 = 256 * 1024 * 1024;

/// Which width array a `read_wd`/`make_code` call operates on.
#[derive(Clone, Copy)]
enum WdSel {
    /// Main symbol widths (`wd_mn`).
    Mn,
    /// Length symbol widths (`wd_lg`).
    Lg,
    /// Meta-Huffman widths (`wd_svwd`, transient inside `read_wd`).
    Sv,
}

/// Which decode table a `read_wd`/`make_code` call fills.
#[derive(Clone, Copy)]
enum CodeSel {
    /// Main symbol table (`code_mn`, 11-bit index).
    Mn,
    /// Length symbol table (`code_lg`, 11-bit index).
    Lg,
    /// Meta-Huffman table (`code_sv`, 7-bit index, transient).
    Sv,
}

/// Decoder working state; one instance per member stream.
struct State<'a> {
    /// Whole packed member stream.
    input: &'a [u8],
    /// Byte cursor into `input` (mirrors `nInputBytesRead`).
    input_pos: usize,
    /// Compressed bytes available (mirrors `nInputLimit`).
    input_limit: i64,

    /// DWORD read buffer (mirrors `nBufRd`).
    buf_rd: [u32; ACE_SIZE_RDB + 2],
    /// Current DWORD index (mirrors `nRPos`).
    rpos: usize,
    /// Bit offset within the current DWORD, 0-31 (mirrors `nBitsRd`).
    bits_rd: i32,
    /// Current 32-bit sliding code window (mirrors `nCodeRd`).
    code_rd: u32,
    /// Logical compressed bits consumed (mirrors `nBitsConsumed`).
    bits_consumed: i64,

    /// Main symbol decode table.
    code_mn: [u16; 1 << ACE_MAXWD_MN],
    /// Length symbol decode table.
    code_lg: [u16; 1 << ACE_MAXWD_LG],
    /// Meta-Huffman decode table.
    code_sv: [u16; 1 << ACE_MAXWD_SVWD],
    /// Main code widths.
    wd_mn: [u8; ACE_MAX_CD_MN + 2],
    /// Length code widths.
    wd_lg: [u8; ACE_MAX_CD_LG + 2],
    /// Meta-Huffman code widths.
    wd_svwd: [u8; ACE_SVWD_CNT as usize + 1],

    /// Quicksort scratch: original symbol index.
    sort_org: [u16; ACE_MAX_CD_MN + 2],
    /// Quicksort scratch: code width used as sort key.
    sort_freq: [u8; ACE_MAX_CD_MN + 2],

    /// LZ77 ring buffer.
    text: Vec<u8>,
    /// Ring-buffer write position.
    dpos: usize,
    /// `1 << dic_bits`.
    dic_siz: usize,
    /// `dic_siz - 1` wrap mask.
    dic_and: usize,
    /// Dictionary bytes available to matches.
    history_size: usize,

    /// Recent distances (ring of 4).
    old_dist: [u32; 4],
    /// Oldest slot index.
    old_num: usize,

    /// Remaining symbols in the current block.
    block_size: i32,
    /// Symbols output during the current `decompress_blk` call.
    dcr_do: i32,
    /// Target symbols for the current call.
    dcr_do_max: i32,
    /// Total bytes left to decompress.
    dcr_size: i64,

    /// Sticky decode error.
    error: bool,
    /// Sticky compressed-input error.
    read_error: bool,
}

impl<'a> State<'a> {
    /// Create a zeroed state (mirrors the upstream `memset`).
    fn new(input: &'a [u8], dic_bits: u32) -> Self {
        let dic_siz = 1usize << dic_bits;
        Self {
            input,
            input_pos: 0,
            input_limit: input.len() as i64,
            buf_rd: [0; ACE_SIZE_RDB + 2],
            rpos: 0,
            bits_rd: 0,
            code_rd: 0,
            bits_consumed: 0,
            code_mn: [0; 1 << ACE_MAXWD_MN],
            code_lg: [0; 1 << ACE_MAXWD_LG],
            code_sv: [0; 1 << ACE_MAXWD_SVWD],
            wd_mn: [0; ACE_MAX_CD_MN + 2],
            wd_lg: [0; ACE_MAX_CD_LG + 2],
            wd_svwd: [0; ACE_SVWD_CNT as usize + 1],
            sort_org: [0; ACE_MAX_CD_MN + 2],
            sort_freq: [0; ACE_MAX_CD_MN + 2],
            text: vec![0u8; dic_siz],
            dpos: 0,
            dic_siz,
            dic_and: dic_siz - 1,
            history_size: 0,
            old_dist: [0; 4],
            old_num: 0,
            block_size: 0,
            dcr_do: 0,
            dcr_do_max: 0,
            dcr_size: 0,
            error: false,
            read_error: false,
        }
    }

    /// `readInput`: copy up to `want` bytes from the stream into the
    /// read buffer at word `start_word`, zero-padding to `want` bytes.
    fn read_input(&mut self, start_word: usize, want: usize) {
        let remaining = (self.input_limit - self.input_pos as i64).max(0) as usize;
        let n = want.min(remaining);
        let src = self.input_pos;
        self.input_pos += n;
        for w in 0..want.div_ceil(4) {
            let mut v = 0u32;
            for j in 0..4 {
                let i = w * 4 + j;
                if i < n {
                    v |= u32::from(self.input[src + i]) << (8 * j);
                }
            }
            self.buf_rd[start_word + w] = v;
        }
    }

    /// `readdat`: slide the last two DWORDs to the front and refill.
    fn read_dat(&mut self) {
        if self.rpos != ACE_SIZE_RDB - 2 {
            self.error = true;
            return;
        }
        self.rpos = 0;
        self.buf_rd[0] = self.buf_rd[ACE_SIZE_RDB - 2];
        self.buf_rd[1] = self.buf_rd[ACE_SIZE_RDB - 1];
        self.read_input(2, (ACE_SIZE_RDB - 2) * 4);
    }

    /// `addbits`: consume `n` bits and rebuild the sliding code window.
    fn add_bits(&mut self, n: i32) {
        if self.error
            || !(0..=32).contains(&n)
            || self.rpos >= ACE_SIZE_RDB - 2
            || !(0..=31).contains(&self.bits_rd)
        {
            self.error = true;
            return;
        }
        let avail_bits = self.input_limit.saturating_mul(8);
        if self.bits_consumed > avail_bits || i64::from(n) > avail_bits - self.bits_consumed {
            self.error = true;
            self.read_error = true;
            return;
        }
        self.bits_consumed += i64::from(n);

        let acc = self.bits_rd + n;
        self.rpos += (acc >> 5) as usize;
        self.bits_rd = acc & 31;

        if self.rpos > ACE_SIZE_RDB - 2 {
            self.error = true;
            return;
        }
        if self.rpos == ACE_SIZE_RDB - 2 {
            self.read_dat();
            if self.error {
                return;
            }
        }
        let hi = self.buf_rd[self.rpos] << self.bits_rd;
        let lo = if self.bits_rd == 0 {
            0
        } else {
            self.buf_rd[self.rpos + 1] >> (32 - self.bits_rd)
        };
        self.code_rd = hi.wrapping_add(lo);
    }

    /// `peekbits`: top `n` bits of the sliding window (MSB-first).
    fn peek_bits(&mut self, n: i32) -> u32 {
        if self.error || !(1..=32).contains(&n) {
            self.error = true;
            return 0;
        }
        self.code_rd >> (32 - n)
    }

    /// `sortrange` partition recursion (ported verbatim; the order of
    /// equal-width symbols feeds `make_code` and is not stable).
    fn sort_range(&mut self, left: i32, right: i32) {
        let mut zl = left;
        let mut zr = right;
        let hyphen = self.sort_freq[right as usize];
        loop {
            while self.sort_freq[zl as usize] > hyphen {
                zl += 1;
            }
            while self.sort_freq[zr as usize] < hyphen {
                zr -= 1;
            }
            if zl <= zr {
                self.sort_freq.swap(zl as usize, zr as usize);
                self.sort_org.swap(zl as usize, zr as usize);
                zl += 1;
                zr -= 1;
            }
            if zl >= zr {
                break;
            }
        }
        if left < zr {
            if left < zr - 1 {
                self.sort_range(left, zr);
            } else if self.sort_freq[left as usize] < self.sort_freq[zr as usize] {
                self.sort_freq.swap(left as usize, zr as usize);
                self.sort_org.swap(left as usize, zr as usize);
            }
        }
        if right > zl {
            if zl < right - 1 {
                self.sort_range(zl, right);
            } else if self.sort_freq[zl as usize] < self.sort_freq[right as usize] {
                self.sort_freq.swap(zl as usize, right as usize);
                self.sort_org.swap(zl as usize, right as usize);
            }
        }
    }

    /// `quicksort`: init `sort_org` to identity and sort by width.
    fn quick_sort(&mut self, n: usize) {
        for (i, v) in self.sort_org.iter_mut().take(n + 1).enumerate() {
            *v = i as u16;
        }
        self.sort_range(0, n as i32);
    }

    /// Width array accessor.
    fn wd(&self, sel: WdSel) -> &[u8] {
        match sel {
            WdSel::Mn => &self.wd_mn,
            WdSel::Lg => &self.wd_lg,
            WdSel::Sv => &self.wd_svwd,
        }
    }

    /// Mutable width array accessor.
    fn wd_mut(&mut self, sel: WdSel) -> &mut [u8] {
        match sel {
            WdSel::Mn => &mut self.wd_mn,
            WdSel::Lg => &mut self.wd_lg,
            WdSel::Sv => &mut self.wd_svwd,
        }
    }

    /// Mutable decode-table accessor.
    fn code_mut(&mut self, sel: CodeSel) -> &mut [u16] {
        match sel {
            CodeSel::Mn => &mut self.code_mn,
            CodeSel::Lg => &mut self.code_lg,
            CodeSel::Sv => &mut self.code_sv,
        }
    }

    /// `makecode`: build the canonical decode table for `maxwd`-bit
    /// lookups. Returns false on an over-complete tree.
    fn make_code(&mut self, maxwd: u32, size1t: usize, wd_sel: WdSel, code_sel: CodeSel) -> bool {
        if maxwd == 0 || maxwd > ACE_MAXWD_MN || size1t > ACE_MAX_CD_MN {
            self.error = true;
            return false;
        }
        let mut wd_tmp = [0u8; ACE_MAX_CD_MN + 2];
        wd_tmp[..size1t + 1].copy_from_slice(&self.wd(wd_sel)[..size1t + 1]);
        self.sort_freq[..size1t + 1].copy_from_slice(&wd_tmp[..size1t + 1]);

        if size1t > 0 {
            self.quick_sort(size1t);
        } else {
            self.sort_org[0] = 0;
        }

        self.sort_freq[size1t + 1] = 0;
        let mut size2t = 0usize;
        while self.sort_freq[size2t] != 0 {
            size2t += 1;
        }
        if size2t < 2 {
            let idx = self.sort_org[0] as usize;
            self.wd_mut(wd_sel)[idx] = 1;
            if size2t == 0 {
                size2t = 1;
            }
        }
        size2t -= 1;

        let max_make = 1usize << maxwd;
        let mut c = 0usize;
        let mut i = size2t + 1;
        while i != 0 && c < max_make {
            i -= 1;
            let width = u32::from(self.sort_freq[i]);
            if width > maxwd {
                self.error = true;
                return false;
            }
            let maxc = 1usize << (maxwd - width);
            let l = self.sort_org[i];
            if maxc > max_make - c {
                self.error = true;
                return false;
            }
            self.code_mut(code_sel)[c..c + maxc].fill(l);
            c += maxc;
        }
        true
    }

    /// `read_wd`: read one Huffman table (num_el, lolim, uplim,
    /// meta-widths, delta-decoded symbol widths) from the bit stream.
    fn read_wd(&mut self, maxwd: u32, code_sel: CodeSel, wd_sel: WdSel, max_el: u32) -> bool {
        if maxwd == 0 || maxwd > ACE_MAXWD_MN || max_el as usize > ACE_MAX_CD_MN {
            self.error = true;
            return false;
        }
        let wd = self.wd_mut(wd_sel);
        for b in wd[..=max_el as usize].iter_mut() {
            *b = 0;
        }
        let invalid = u16::MAX;
        self.code_mut(code_sel)[..1 << maxwd].fill(invalid);
        self.code_sv.fill(invalid);

        let num_el = self.peek_bits(9);
        self.add_bits(9);
        if self.error || num_el > max_el {
            self.error = true;
            return false;
        }

        let lolim = self.peek_bits(4);
        self.add_bits(4);
        if self.error {
            return false;
        }

        let uplim = self.peek_bits(4);
        self.add_bits(4);
        if self.error || uplim > ACE_SVWD_CNT {
            self.error = true;
            return false;
        }

        for i in 0..=uplim as usize {
            self.wd_svwd[i] = self.peek_bits(3) as u8;
            self.add_bits(3);
            if self.error {
                return false;
            }
        }

        if !self.make_code(ACE_MAXWD_SVWD, uplim as usize, WdSel::Sv, CodeSel::Sv) {
            return false;
        }

        let mut j = 0u32;
        while j <= num_el {
            let nc = self.code_sv[self.peek_bits(ACE_MAXWD_SVWD as i32) as usize] as u32;
            if self.error || nc > uplim || nc > ACE_SVWD_CNT || self.wd_svwd[nc as usize] == 0 {
                self.error = true;
                return false;
            }
            let w = i32::from(self.wd_svwd[nc as usize]);
            self.add_bits(w);
            if self.error {
                return false;
            }

            if nc < uplim {
                self.wd_mut(wd_sel)[j as usize] = nc as u8;
                j += 1;
            } else {
                let run_len = self.peek_bits(4) + 4;
                self.add_bits(4);
                if self.error {
                    return false;
                }
                let mut k = 0;
                while k < run_len && j <= num_el {
                    self.wd_mut(wd_sel)[j as usize] = 0;
                    j += 1;
                    k += 1;
                }
            }
        }

        if uplim > 0 {
            for i in 1..=num_el as usize {
                let wd = self.wd_mut(wd_sel);
                let prev = u32::from(wd[i - 1]);
                wd[i] = ((u32::from(wd[i]) + prev) % uplim) as u8;
            }
        }

        let lolim = lolim as u8;
        for i in 0..=num_el as usize {
            let w = &mut self.wd_mut(wd_sel)[i];
            if *w != 0 {
                *w = w.wrapping_add(lolim);
            }
        }

        self.make_code(maxwd, num_el as usize, wd_sel, code_sel)
    }

    /// `calc_dectabs`: refresh both Huffman tables and the block size.
    fn calc_dec_tabs(&mut self) -> bool {
        if !self.read_wd(ACE_MAXWD_MN, CodeSel::Mn, WdSel::Mn, ACE_MAX_CD_MN as u32) {
            return false;
        }
        if !self.read_wd(ACE_MAXWD_LG, CodeSel::Lg, WdSel::Lg, ACE_MAX_CD_LG as u32) {
            return false;
        }
        self.block_size = self.peek_bits(15) as i32;
        self.add_bits(15);
        if self.error || self.block_size <= 0 {
            self.error = true;
            return false;
        }
        true
    }

    /// `copystr`: LZ77 ring-buffer match copy.
    fn copy_str(&mut self, dist: i32, len: i32) {
        if dist <= 0
            || dist as usize > self.dic_siz
            || dist as usize > self.history_size
            || len <= 0
            || len > ACE_MAXLENGTH
            || self.dcr_do < 0
            || self.dcr_size < i64::from(len)
            || i64::from(self.dcr_do) > self.dcr_size - i64::from(len)
            || self.dcr_do > i32::MAX - len
        {
            self.error = true;
            return;
        }
        self.dcr_do += len;

        let mut mpos = self.dpos.wrapping_sub(dist as usize) & self.dic_and;
        if mpos >= self.dic_siz - ACE_MAXLENGTH as usize
            || self.dpos >= self.dic_siz - ACE_MAXLENGTH as usize
        {
            for _ in 0..len {
                self.text[self.dpos] = self.text[mpos];
                self.dpos = (self.dpos + 1) & self.dic_and;
                mpos = (mpos + 1) & self.dic_and;
            }
        } else {
            for _ in 0..len {
                self.text[self.dpos] = self.text[mpos];
                self.dpos += 1;
                mpos += 1;
            }
            self.dpos &= self.dic_and;
        }
        self.history_size = self.dic_siz.min(self.history_size + len as usize);
    }

    /// `decompress`: decode up to `dcr_do_max` symbols into the ring
    /// buffer.
    fn decompress_block(&mut self) {
        while self.dcr_do < self.dcr_do_max {
            if self.error {
                return;
            }
            if self.block_size == 0 && !self.calc_dec_tabs() {
                self.error = true;
                return;
            }

            let main_index = self.peek_bits(ACE_MAXWD_MN as i32) as usize;
            if self.error {
                return;
            }
            let nc = i32::from(self.code_mn[main_index]);
            if nc as usize > ACE_MAX_CD_MN
                || self.wd_mn[nc as usize] == 0
                || u32::from(self.wd_mn[nc as usize]) > ACE_MAXWD_MN
            {
                self.error = true;
                return;
            }
            self.add_bits(i32::from(self.wd_mn[nc as usize]));
            if self.error {
                return;
            }
            self.block_size -= 1;

            if nc > 255 {
                let mut dist: u32;
                let mut i: i32;

                if nc > 259 {
                    let dc = nc - 260;
                    if !(0..=ACE_MAXDIC as i32).contains(&dc) {
                        self.error = true;
                        return;
                    }
                    if dc > 1 {
                        dist = (self.code_rd >> (33 - dc)) + (1u32 << (dc - 1));
                        self.add_bits(dc - 1);
                        if self.error {
                            return;
                        }
                    } else {
                        dist = dc as u32;
                    }
                    self.old_num = (self.old_num + 1) & 3;
                    self.old_dist[self.old_num] = dist;
                    i = 2;
                    if dist > ACE_MAXDIS2 {
                        i += 1;
                        if dist > ACE_MAXDIS3 {
                            i += 1;
                        }
                    }
                } else {
                    let r#ref = (nc & 255) as usize;
                    dist = self.old_dist[(self.old_num + 4 - r#ref) & 3];
                    let mut k = r#ref as i32 + 1;
                    while {
                        k -= 1;
                        k >= 0
                    } {
                        self.old_dist[(self.old_num + 4 - k as usize) & 3] =
                            self.old_dist[(self.old_num + 4 - k as usize + 1) & 3];
                    }
                    self.old_dist[self.old_num] = dist;
                    i = 2;
                    if r#ref > 1 {
                        i += 1;
                    }
                }

                let lg_index = self.peek_bits(ACE_MAXWD_LG as i32) as usize;
                if self.error {
                    return;
                }
                let lg = i32::from(self.code_lg[lg_index]);
                if lg as usize > ACE_MAX_CD_LG
                    || self.wd_lg[lg as usize] == 0
                    || u32::from(self.wd_lg[lg as usize]) > ACE_MAXWD_LG
                {
                    self.error = true;
                    return;
                }
                self.add_bits(i32::from(self.wd_lg[lg as usize]));
                if self.error || dist == u32::MAX {
                    self.error = true;
                    return;
                }
                dist += 1;
                let len = lg + i;
                self.copy_str(dist as i32, len);
                if self.error {
                    return;
                }
            } else {
                if self.dcr_do < 0 || i64::from(self.dcr_do) >= self.dcr_size {
                    self.error = true;
                    return;
                }
                self.dcr_do += 1;
                self.text[self.dpos] = nc as u8;
                self.dpos = (self.dpos + 1) & self.dic_and;
                self.history_size = self.dic_siz.min(self.history_size + 1);
            }
        }
    }

    /// `decompress_blk`: emit up to `n_len` bytes into `out`. Returns
    /// the byte count written.
    fn decompress_blk(&mut self, out: &mut Vec<u8>, n_len: i32) -> i32 {
        if n_len <= ACE_MAXLENGTH || self.dcr_size <= 0 {
            self.error = true;
            return 0;
        }
        let old_pos = self.dpos;
        self.dcr_do = 0;
        self.dcr_do_max = n_len - ACE_MAXLENGTH;
        if i64::from(self.dcr_do_max) > self.dcr_size {
            self.dcr_do_max = self.dcr_size as i32;
        }

        if self.dcr_size > 0 && self.dcr_do_max > 0 {
            self.decompress_block();
            if self.error
                || self.dcr_do <= 0
                || self.dcr_do > n_len
                || i64::from(self.dcr_do) > self.dcr_size
            {
                self.error = true;
                return 0;
            }
            let done = self.dcr_do as usize;
            if old_pos + done > self.dic_siz {
                let first = self.dic_siz - old_pos;
                out.extend_from_slice(&self.text[old_pos..old_pos + first]);
                out.extend_from_slice(&self.text[..done - first]);
            } else {
                out.extend_from_slice(&self.text[old_pos..old_pos + done]);
            }
        }
        self.dcr_size -= i64::from(self.dcr_do);
        self.dcr_do
    }
}

/// Decompress one ACE tech-type-1 member stream.
///
/// `window_size` is the dictionary size from the member's
/// `tech_parameter` (`1 << ((tech_parameter & 15) + 10)`); callers may
/// pass `1 << 20` when unknown, matching the upstream default. Returns
/// `None` on any stream violation (mirroring upstream `bOk == false`).
pub fn decompress_ace(input: &[u8], original_size: usize, window_size: u64) -> Option<Vec<u8>> {
    let input_limit = input.len() as i64;
    if input_limit < 0 || (input_limit & 3) != 0 || original_size as i64 > MAX_OUTPUT {
        return None;
    }
    if original_size == 0 {
        return if input_limit == 0 {
            Some(Vec::new())
        } else {
            None
        };
    }
    let mut dic_bits = 10u32;
    while (1u64 << dic_bits) < window_size && dic_bits < ACE_MAXDIC {
        dic_bits += 1;
    }
    if !(1u64 << 10..=1u64 << ACE_MAXDIC).contains(&window_size)
        || (1u64 << dic_bits) != window_size
    {
        return None;
    }

    let mut st = State::new(input, dic_bits);
    st.dcr_size = original_size as i64;

    // Initial fill: ACE_SIZE_RDB DWORDs, zero-padded past the stream end.
    st.read_input(0, ACE_SIZE_RDB * 4);
    st.code_rd = st.buf_rd[0];

    let mut out = Vec::with_capacity(original_size.min(MAX_OUTPUT as usize));
    let chunk = st.dic_siz as i32;
    while st.dcr_size > 0 && !st.error {
        let remaining_before = st.dcr_size;
        let done = st.decompress_blk(&mut out, chunk);
        if done <= 0
            || i64::from(done) > remaining_before
            || st.dcr_size != remaining_before - i64::from(done)
        {
            st.error = true;
            break;
        }
    }

    let avail_bits = st.input_limit.saturating_mul(8);
    let ok = !st.error
        && !st.read_error
        && st.dcr_size == 0
        && st.block_size == 0
        && out.len() == original_size
        && st.bits_consumed <= avail_bits
        && (avail_bits - st.bits_consumed) < 32;
    if ok { Some(out) } else { None }
}

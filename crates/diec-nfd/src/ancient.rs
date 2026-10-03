//! Pure-Rust port of upstream `XAncientDecoder` (MIT, Teemu Suutari)
//! restricted to the subset `NFDCompression::detect` consumes: RNC
//! (ProPack RNC1/RNC2, old and new streams), TPWM, UNIX pack (old and
//! new), and Freeze/Melt (1.x and 2.x).
//!
//! The recognizer only trusts a stream after a full decode, so every
//! reader below mirrors the upstream stream/bit-reader/Huffman helpers
//! bit-for-bit, including their bounded-read and exact-consumption
//! checks. All sizes are capped by the upstream limits.

use crate::parse;

/// `CodecDecoder::getMaxPackedSize` — upstream cap on packed input.
pub(crate) const MAX_PACKED: u64 = 128 * 1024 * 1024;
/// `CodecDecoder::getMaxRawSize` — upstream cap on decoded output.
pub(crate) const MAX_RAW: u64 = 128 * 1024 * 1024;
/// `XAncientDecoder::MAX_PACKED_SIZE`.
const MAX_PACKED_SIZE: u64 = MAX_PACKED;
/// `XAncientDecoder::MAX_RAW_SIZE`.
const MAX_RAW_SIZE: u64 = MAX_RAW;

/// Failure modes mirroring the upstream exception hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AncErr {
    /// `InvalidFormatError` / `OutOfBoundsError` on headers.
    Invalid,
    /// `VerificationError` — checksum mismatch.
    Verify,
    /// `DecompressionError` — malformed stream or overrun.
    Decomp,
}

type R<T> = Result<T, AncErr>;

// ---------------------------------------------------------------------
// Input streams & bit readers (xancientinputstream_p.*)
// ---------------------------------------------------------------------

/// Byte-order / width of the refill word used by a bit reader.
#[derive(Clone, Copy)]
enum Word {
    /// `InputReadByteWord` — 8-bit refill.
    Byte,
    /// `InputReadLE16Word` — 16-bit little-endian refill.
    Le16,
}

/// `ForwardInputStream` / `BackwardInputStream` unified with the
/// `MSBBitReader`/`LSBBitReader` bit-buffer state: each decoder uses a
/// single stream+reader pair, so the bit buffer lives on the stream.
/// For `back` the stream reads downward: `cur` starts at `end` and
/// `end` is the lower bound.
struct In<'a> {
    d: &'a [u8],
    cur: usize,
    end: usize,
    back: bool,
    allow: usize,
    buf: u32,
    blen: u8,
    msb: bool,
}

impl<'a> In<'a> {
    /// `ForwardInputStream(buffer, start, end, overrunAllowance)` plus
    /// the paired bit reader's order (`msb` = MSB-first).
    fn fwd(d: &'a [u8], start: usize, end: usize, allow: usize, msb: bool) -> R<Self> {
        if start > end || start > d.len() || end > d.len() {
            return Err(AncErr::Decomp);
        }
        Ok(Self {
            d,
            cur: start,
            end,
            back: false,
            allow,
            buf: 0,
            blen: 0,
            msb,
        })
    }

    /// `BackwardInputStream(buffer, start, end)` — `cur` walks down to
    /// `start`.
    fn bwd(d: &'a [u8], start: usize, end: usize, msb: bool) -> R<Self> {
        if end < start || end > d.len() || start > d.len() {
            return Err(AncErr::Decomp);
        }
        Ok(Self {
            d,
            cur: end,
            end: start,
            back: true,
            allow: 0,
            buf: 0,
            blen: 0,
            msb,
        })
    }

    fn byte(&mut self) -> R<u8> {
        if self.back {
            if self.cur <= self.end {
                return Err(AncErr::Decomp);
            }
            self.cur -= 1;
            return Ok(self.d[self.cur]);
        }
        if self.cur >= self.end {
            if self.allow != 0 {
                self.allow -= 1;
                return Ok(0);
            }
            return Err(AncErr::Decomp);
        }
        let b = self.d[self.cur];
        self.cur += 1;
        Ok(b)
    }

    fn le16(&mut self) -> R<u16> {
        Ok(u16::from(self.byte()?) | (u16::from(self.byte()?) << 8))
    }

    fn eof(&self) -> bool {
        self.cur == self.end
    }

    fn offset(&self) -> usize {
        self.cur
    }
}

impl In<'_> {
    /// `MSBBitReader::reset` (used by the RNC-old anchor-bit resync).
    fn bits_reset(&mut self, content: u32, len: u8) {
        self.buf = content;
        self.blen = len;
    }

    /// `readBitsGeneric` — pull `count` bits, refilling by `word`.
    fn bits(&mut self, count: u32, word: Word) -> R<u32> {
        if count > 32 {
            return Err(AncErr::Decomp);
        }
        let mut ret = 0u32;
        let mut pos = 0u32;
        let mut count = count;
        while count != 0 {
            if self.blen == 0 {
                let (v, w) = match word {
                    Word::Byte => (u32::from(self.byte()?), 8u8),
                    Word::Le16 => (u32::from(self.le16()?), 16u8),
                };
                self.buf = v;
                self.blen = w;
            }
            let take = count.min(u32::from(self.blen));
            if self.msb {
                self.blen -= take as u8;
                ret = (ret << take) | ((self.buf >> self.blen) & ((1 << take) - 1));
            } else {
                ret |= (self.buf & ((1 << take) - 1)) << pos;
                self.buf >>= take;
                self.blen -= take as u8;
                pos += take;
            }
            count -= take;
        }
        Ok(ret)
    }

    /// `readBits8` — byte-refill bit read.
    fn bits8(&mut self, count: u32) -> R<u32> {
        self.bits(count, Word::Byte)
    }

    /// `readBitsLE16` — 16-bit LE refill bit read.
    fn bits_le16(&mut self, count: u32) -> R<u32> {
        self.bits(count, Word::Le16)
    }
}

// --------------------------------------------------------------------
// Output streams (xancientoutputstream_p.*)
// ---------------------------------------------------------------------

/// `ForwardOutputStream` — fixed upper bound.
struct FOut<'a> {
    d: &'a mut [u8],
    start: usize,
    cur: usize,
    end: usize,
}

impl<'a> FOut<'a> {
    fn new(d: &'a mut [u8], start: usize, end: usize) -> R<Self> {
        if start > end || end > d.len() {
            return Err(AncErr::Decomp);
        }
        Ok(Self {
            d,
            start,
            cur: start,
            end,
        })
    }

    fn eof(&self) -> bool {
        self.cur == self.end
    }

    fn offset(&self) -> usize {
        self.cur
    }

    fn write(&mut self, v: u8) -> R<()> {
        if self.cur + 1 > self.end {
            return Err(AncErr::Decomp);
        }
        self.d[self.cur] = v;
        self.cur += 1;
        Ok(())
    }

    /// `copy(distance, count)` — strict back-reference.
    fn copy(&mut self, dist: usize, count: usize) -> R<()> {
        if self.cur.checked_add(count).ok_or(AncErr::Decomp)? > self.end {
            return Err(AncErr::Decomp);
        }
        if dist == 0 || self.start + dist > self.cur {
            return Err(AncErr::Decomp);
        }
        for _ in 0..count {
            self.d[self.cur] = self.d[self.cur - dist];
            self.cur += 1;
        }
        Ok(())
    }

    /// `copy(distance, count, defaultChar)` — out-of-range prefix fills
    /// with the default byte.
    fn copy_fill(&mut self, dist: usize, count: usize, dc: u8) -> R<()> {
        if self.cur.checked_add(count).ok_or(AncErr::Decomp)? > self.end {
            return Err(AncErr::Decomp);
        }
        if dist == 0 {
            return Err(AncErr::Decomp);
        }
        let mut done = 0usize;
        if self.start + dist > self.cur {
            let prev = count.min(self.start + dist - self.cur);
            for _ in 0..prev {
                self.d[self.cur] = dc;
                self.cur += 1;
            }
            done = prev;
        }
        for _ in done..count {
            self.d[self.cur] = self.d[self.cur - dist];
            self.cur += 1;
        }
        Ok(())
    }
}

/// `AutoExpandingForwardOutputStream` — grows up to `MAX_RAW`.
struct GOut {
    d: Vec<u8>,
    cur: usize,
}

impl GOut {
    fn new() -> Self {
        Self {
            d: Vec::new(),
            cur: 0,
        }
    }

    fn offset(&self) -> usize {
        self.cur
    }

    fn ensure(&mut self, off: usize) -> R<()> {
        if off as u64 > MAX_RAW {
            return Err(AncErr::Decomp);
        }
        if off > self.d.len() {
            self.d.resize(off + 65536, 0);
        }
        Ok(())
    }

    fn write(&mut self, v: u8) -> R<()> {
        self.ensure(self.cur + 1)?;
        self.d[self.cur] = v;
        self.cur += 1;
        Ok(())
    }

    /// `copy(distance, count, 0x20)` — expanding variant.
    fn copy_fill(&mut self, dist: usize, count: usize, dc: u8) -> R<()> {
        self.ensure(self.cur.checked_add(count).ok_or(AncErr::Decomp)?)?;
        if dist == 0 {
            return Err(AncErr::Decomp);
        }
        let mut done = 0usize;
        if dist > self.cur {
            let prev = count.min(dist - self.cur);
            for _ in 0..prev {
                self.d[self.cur] = dc;
                self.cur += 1;
            }
            done = prev;
        }
        for _ in done..count {
            self.d[self.cur] = self.d[self.cur - dist];
            self.cur += 1;
        }
        Ok(())
    }
}

/// `BackwardOutputStream` — writes downward from `end` to `start`.
struct BOut<'a> {
    d: &'a mut [u8],
    lo: usize,
    cur: usize,
    hi: usize,
}

impl<'a> BOut<'a> {
    /// `(buffer, startOffset, endOffset)` — `cur` starts at `end`.
    fn new(d: &'a mut [u8], lo: usize, hi: usize) -> R<Self> {
        if lo > hi || hi > d.len() {
            return Err(AncErr::Decomp);
        }
        Ok(Self { d, lo, cur: hi, hi })
    }

    fn eof(&self) -> bool {
        self.cur == self.lo
    }

    fn write(&mut self, v: u8) -> R<()> {
        if self.cur <= self.lo {
            return Err(AncErr::Decomp);
        }
        self.cur -= 1;
        self.d[self.cur] = v;
        Ok(())
    }

    /// `copy(distance, count)` — backward copy.
    fn copy(&mut self, dist: usize, count: usize) -> R<()> {
        if dist == 0
            || self.lo.checked_add(count).ok_or(AncErr::Decomp)? > self.cur
            || self.cur.checked_add(dist).ok_or(AncErr::Decomp)? > self.hi
        {
            return Err(AncErr::Decomp);
        }
        for _ in 0..count {
            self.d[self.cur - 1] = self.d[self.cur + dist - 1];
            self.cur -= 1;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Huffman / dynamic Huffman / VLC helpers
// ---------------------------------------------------------------------

/// `HuffmanDecoder<T>` — tree stored as a node vector; `left`/`right`
/// are child indices, 0 marks "absent" and a leaf has both zero.
struct Huff<T: Copy + Default> {
    t: Vec<(u32, u32, T)>,
}

impl<T: Copy + Default> Huff<T> {
    fn new() -> Self {
        Self { t: Vec::new() }
    }

    /// `insert` — upstream's incremental tree builder (exact port).
    fn insert(&mut self, len: u32, code: u32, value: T) -> R<()> {
        let mut i = 0u32;
        let mut length = self.t.len() as u32;
        let mut current = len as i64;
        while current >= 0 {
            let cb = current != 0 && ((code >> (current - 1)) & 1) != 0;
            if i != length {
                let node = &mut self.t[i as usize];
                if current == 0 || (node.0 == 0 && node.1 == 0) {
                    return Err(AncErr::Decomp);
                }
                let tmp = if cb { &mut node.1 } else { &mut node.0 };
                if *tmp == 0 {
                    *tmp = length;
                    i = length;
                } else {
                    i = *tmp;
                }
            } else {
                self.t.push((
                    if current != 0 && !cb { length + 1 } else { 0 },
                    if current != 0 && cb { length + 1 } else { 0 },
                    if current != 0 { T::default() } else { value },
                ));
                length += 1;
                i += 1;
            }
            current -= 1;
        }
        Ok(())
    }

    /// `decode` — walk one bit at a time until a leaf.
    fn decode<F: FnMut() -> R<u32>>(&self, mut read: F) -> R<T> {
        if self.t.is_empty() {
            return Err(AncErr::Decomp);
        }
        let mut i = 0usize;
        while self.t[i].0 != 0 || self.t[i].1 != 0 {
            i = if read()? != 0 {
                self.t[i].1
            } else {
                self.t[i].0
            } as usize;
            if i == 0 {
                return Err(AncErr::Decomp);
            }
        }
        Ok(self.t[i].2)
    }
}

/// Symbols stored in canonical tables are their table indices.
trait Idx: Copy + Default {
    /// Wrap an ordinal as the symbol type.
    fn idx(v: usize) -> Self;
}
impl Idx for u8 {
    fn idx(v: usize) -> Self {
        v as u8
    }
}
impl Idx for u16 {
    fn idx(v: usize) -> Self {
        v as u16
    }
}
impl Idx for u32 {
    fn idx(v: usize) -> Self {
        v as u32
    }
}

impl<T: Idx> Huff<T> {
    /// `createOrderlyHuffmanTable` — canonical deflate-style table.
    /// Symbol values are the table indices (`T(i)`).
    fn create_orderly(&mut self, bit_lengths: &[u8], table_len: usize) -> R<()> {
        if table_len > bit_lengths.len() {
            return Err(AncErr::Decomp);
        }
        let mut min_depth = 32u8;
        let mut max_depth = 0u8;
        let mut first = [u16::MAX; 33];
        let mut last = [0u16; 33];
        let mut next = vec![0u16; table_len];
        let mut real = 0usize;
        for (i, &length) in bit_lengths.iter().enumerate().take(table_len) {
            if length > 32 {
                return Err(AncErr::Decomp);
            }
            if length != 0 {
                min_depth = min_depth.min(length);
                max_depth = max_depth.max(length);
                let l = length as usize;
                if first[l] == u16::MAX {
                    first[l] = i as u16;
                } else {
                    next[last[l] as usize] = i as u16;
                }
                last[l] = i as u16;
                real += 1;
            }
        }
        if max_depth == 0 {
            return Err(AncErr::Decomp);
        }
        self.t.reserve(real * 3);
        let mut code = 0u32;
        for depth in min_depth..=max_depth {
            if first[depth as usize] != u16::MAX {
                next[last[depth as usize] as usize] = table_len as u16;
            }
            let mut i = first[depth as usize] as usize;
            while i < table_len {
                self.insert(u32::from(depth), code >> (max_depth - depth), T::idx(i))?;
                code += 1 << (max_depth - depth);
                i = next[i] as usize;
            }
        }
        Ok(())
    }
}

/// `DynamicHuffmanDecoder<maxCount>` — adaptive LH2-style tree.
struct DynHuff {
    count: u32,
    initial: u32,
    // frequency, index, parent, leftLeaf, rightLeaf
    nodes: Vec<[u32; 5]>,
    codemap: Vec<u32>,
}

impl DynHuff {
    const MAX: u32 = 511;

    fn new(initial: u32) -> R<Self> {
        if initial > Self::MAX {
            return Err(AncErr::Decomp);
        }
        let mut s = Self {
            count: 0,
            initial,
            nodes: vec![[0; 5]; (Self::MAX * 2 - 1) as usize],
            codemap: vec![0; (Self::MAX * 2 - 1) as usize],
        };
        s.reset();
        Ok(s)
    }

    fn reset(&mut self) {
        let max = Self::MAX;
        self.count = self.initial;
        if self.count == 0 {
            return;
        }
        for i in 0..self.count {
            let n = &mut self.nodes[i as usize];
            n[0] = 1;
            n[1] = i + (max - self.count) * 2;
            n[2] = max * 2 - self.count + (i >> 1);
            n[3] = 0;
            n[4] = 0;
            self.codemap[(i + (max - self.count) * 2) as usize] = i;
        }
        let mut i = max * 2 - self.count;
        let mut j = 0u32;
        while i < max * 2 - 1 {
            let l = if j >= self.count {
                j + (max - self.count) * 2
            } else {
                j
            };
            let r = if j + 1 >= self.count {
                j + 1 + (max - self.count) * 2
            } else {
                j + 1
            };
            let freq = self.nodes[l as usize][0] + self.nodes[r as usize][0];
            let n = &mut self.nodes[i as usize];
            n[0] = freq;
            n[1] = i;
            n[2] = max + (i >> 1);
            n[3] = l;
            n[4] = r;
            self.codemap[i as usize] = i;
            i += 1;
            j += 2;
        }
    }

    fn decode<F: FnMut() -> R<u32>>(&self, mut read: F) -> R<u32> {
        let max = Self::MAX;
        if self.count == 0 {
            return Err(AncErr::Decomp);
        }
        if self.count == 1 {
            return Ok(0);
        }
        let mut code = max * 2 - 2;
        while code >= max {
            code = if read()? != 0 {
                self.nodes[code as usize][4]
            } else {
                self.nodes[code as usize][3]
            };
        }
        Ok(code)
    }

    fn parent_leaf(&mut self, code: u32, val: u32) {
        let parent = self.nodes[code as usize][2] as usize;
        if self.nodes[parent][3] == code {
            self.nodes[parent][3] = val;
        } else {
            self.nodes[parent][4] = val;
        }
    }

    fn parent_leaf_get(&self, code: u32) -> u32 {
        let parent = self.nodes[code as usize][2] as usize;
        if self.nodes[parent][3] == code {
            self.nodes[parent][3]
        } else {
            self.nodes[parent][4]
        }
    }

    fn update(&mut self, mut code: u32) -> R<()> {
        let max = Self::MAX;
        if code >= self.count {
            return Err(AncErr::Decomp);
        }
        // Upstream LH2 quirk: single-code trees never grow.
        if self.count == 1 {
            self.nodes[0][0] = 1;
            return Ok(());
        }
        while code != max * 2 - 2 {
            self.nodes[code as usize][0] += 1;
            let index = self.nodes[code as usize][1];
            let mut dest = index;
            let freq = self.nodes[code as usize][0];
            while dest != max * 2 - 2
                && freq > self.nodes[self.codemap[(dest + 1) as usize] as usize][0]
            {
                dest += 1;
            }
            if index != dest {
                let dest_code = self.codemap[dest as usize];
                let (a, b) = (
                    self.nodes[code as usize][1],
                    self.nodes[dest_code as usize][1],
                );
                self.nodes[code as usize][1] = b;
                self.nodes[dest_code as usize][1] = a;
                self.codemap.swap(index as usize, dest as usize);
                let pl_a = self.parent_leaf_get(code);
                let pl_b = self.parent_leaf_get(dest_code);
                self.parent_leaf(code, pl_b);
                self.parent_leaf(dest_code, pl_a);
                let (pa, pb) = (
                    self.nodes[code as usize][2],
                    self.nodes[dest_code as usize][2],
                );
                self.nodes[code as usize][2] = pb;
                self.nodes[dest_code as usize][2] = pa;
            }
            code = self.nodes[code as usize][2];
        }
        self.nodes[code as usize][0] += 1;
        Ok(())
    }

    fn halve(&mut self) {
        let max = Self::MAX;
        if self.count == 0 {
            return;
        }
        if self.count == 1 {
            self.nodes[0][0] = self.nodes[0][0].div_ceil(2);
            return;
        }
        let mut j = (max - self.count) * 2;
        for i in (max - self.count) * 2..max * 2 - 1 {
            if self.codemap[i as usize] < max {
                self.nodes[self.codemap[i as usize] as usize][1] = j;
                j += 1;
            }
        }
        for i in 0..self.count {
            let n = &mut self.nodes[i as usize];
            n[0] = n[0].div_ceil(2);
            n[2] = max + (n[1] >> 1);
            self.codemap[n[1] as usize] = i;
        }
        let mut i = max * 2 - self.count;
        let mut j = (max - self.count) * 2;
        while i < max * 2 - 1 {
            let l = self.codemap[j as usize];
            let r = self.codemap[(j + 1) as usize];
            let freq = self.nodes[l as usize][0] + self.nodes[r as usize][0];
            let n = &mut self.nodes[i as usize];
            n[0] = freq;
            n[1] = i;
            n[2] = max + (i >> 1);
            n[3] = l;
            n[4] = r;
            self.codemap[i as usize] = i;
            // Bubble-sort the node back while its frequency is smaller.
            let mut k = i;
            while freq < self.nodes[self.codemap[(k - 1) as usize] as usize][0] {
                let code = self.codemap[k as usize];
                let dest_code = self.codemap[(k - 1) as usize];
                let (a, b) = (
                    self.nodes[code as usize][1],
                    self.nodes[dest_code as usize][1],
                );
                self.nodes[code as usize][1] = b;
                self.nodes[dest_code as usize][1] = a;
                let (pa, pb) = (
                    self.nodes[code as usize][2],
                    self.nodes[dest_code as usize][2],
                );
                self.nodes[code as usize][2] = pb;
                self.nodes[dest_code as usize][2] = pa;
                self.codemap.swap(k as usize, (k - 1) as usize);
                k -= 1;
            }
            i += 1;
            j += 2;
        }
    }

    fn max_frequency(&self) -> u32 {
        self.nodes[(Self::MAX * 2 - 2) as usize][0]
    }
}

/// `VariableLengthCodeDecoder<N>` — offsets built from a signed length
/// list (negative entries reset the running offset).
struct Vlc {
    lens: Vec<u8>,
    offs: Vec<u32>,
}

impl Vlc {
    /// Port of the fold-expression ctor: negative arg resets offset.
    fn new(args: &[i32]) -> Self {
        let mut lens = Vec::with_capacity(args.len());
        let mut offs = Vec::with_capacity(args.len());
        let mut length = 0u32;
        for &v in args {
            lens.push(v.unsigned_abs() as u8);
            if v < 0 {
                offs.push(0);
                length = 1 << (-v) as u32;
            } else {
                offs.push(length);
                length += 1 << v as u32;
            }
        }
        Self { lens, offs }
    }

    /// `decode(bitReader, base)`.
    fn decode<F: FnMut(u32) -> R<u32>>(&self, mut read: F, base: u32) -> R<u32> {
        if base as usize >= self.lens.len() {
            return Err(AncErr::Decomp);
        }
        Ok(self.offs[base as usize] + read(u32::from(self.lens[base as usize]))?)
    }

    /// `decodeCascade(bitReader)` — all entries must be non-zero length.
    fn cascade<F: FnMut(u32) -> R<u32>>(&self, mut read: F) -> R<u32> {
        for i in 0..self.lens.len() {
            if self.lens[i] == 0 {
                return Err(AncErr::Decomp);
            }
            let tmp = read(u32::from(self.lens[i]))?;
            if i == self.lens.len() - 1 || tmp != (1u32 << self.lens[i]) - 1 {
                return Ok(self.offs[i] - i as u32 + tmp);
            }
        }
        Err(AncErr::Decomp)
    }
}

// ---------------------------------------------------------------------
// CRC16 (xancientcrc16_p) — reflected poly 0xA001, identical to the
// upstream 256-entry table.
// ---------------------------------------------------------------------

fn crc16_byte(b: u8, acc: u16) -> u16 {
    let mut a = acc ^ u16::from(b);
    for _ in 0..8 {
        a = (a >> 1) ^ if a & 1 != 0 { 0xA001 } else { 0 };
    }
    a
}

fn crc16(d: &[u8], off: usize, len: usize, acc: u16) -> R<u16> {
    if len == 0 || off.checked_add(len).ok_or(AncErr::Invalid)? > d.len() {
        return Err(AncErr::Invalid);
    }
    let mut a = acc;
    for &b in &d[off..off + len] {
        a = crc16_byte(b, a);
    }
    Ok(a)
}

// ---------------------------------------------------------------------
// Public API — `XAncientDecoder::{identify, describe, decode}`
// ---------------------------------------------------------------------

/// Recognized `XAncientDecoder::TYPE` subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `TYPE_RNC` — `RNC\x01`/`RNC\x02`/`...\x01`.
    Rnc,
    /// `TYPE_TPWM`.
    Tpwm,
    /// `TYPE_UNIX_PACK` — `0x1f1e`/`0x1f1f`.
    UnixPack,
    /// `TYPE_FREEZE` — `0x1f9e`/`0x1f9f`.
    Freeze,
}

/// `identify` restricted to the families `NFDCompression` decodes.
pub(crate) fn identify(d: &[u8]) -> Option<Kind> {
    if d.len() >= 4 {
        let four = &d[..4];
        if four == b"RNC\x01" || four == b"RNC\x02" || four == b"...\x01" {
            return Some(Kind::Rnc);
        }
        if four == b"TPWM" {
            return Some(Kind::Tpwm);
        }
    }
    if d.len() >= 2 {
        let sig = u16::from_be_bytes([d[0], d[1]]);
        if sig == 0x1f9e || sig == 0x1f9f {
            return Some(Kind::Freeze);
        }
        if sig == 0x1f1e || sig == 0x1f1f {
            return Some(Kind::UnixPack);
        }
    }
    None
}

/// `XAncientDecoder::INFO`.
pub(crate) struct Info {
    /// `method` — decoder long name.
    pub(crate) method: &'static str,
    /// `packedSize` (-1 when unknown before decode).
    pub(crate) packed: i64,
    /// `rawSize` (-1 when unknown before decode).
    pub(crate) raw: i64,
    /// `imageSize` — equals `raw` for non-image formats.
    pub(crate) image: i64,
    /// `imageOffset`.
    #[allow(dead_code)]
    pub(crate) image_offset: i64,
}

// -- TPWM ---------------------------------------------------------------

/// `TpwmDecoder` — header `TPWM` + BE32 raw size; backward-incompatible
/// nothing: MSB bits, literal or (distance,count) pair.
struct Tpwm<'a> {
    d: &'a [u8],
    raw: u32,
    packed: usize,
}

impl<'a> Tpwm<'a> {
    fn new(d: &'a [u8]) -> R<Self> {
        if d.len() < 4 || &d[..4] != b"TPWM" || d.len() < 12 {
            return Err(AncErr::Invalid);
        }
        let raw = parse::rd_u32_be_le(d, 4, true).ok_or(AncErr::Invalid)?;
        if raw == 0 || u64::from(raw) > MAX_RAW {
            return Err(AncErr::Invalid);
        }
        Ok(Self { d, raw, packed: 0 })
    }

    fn decompress(&mut self, out: &mut [u8]) -> R<()> {
        if (out.len() as u64) < u64::from(self.raw) {
            return Err(AncErr::Decomp);
        }
        let mut inp = In::fwd(self.d, 8, self.d.len(), 0, true)?;
        let mut out_s = FOut::new(&mut out[..], 0, self.raw as usize)?;
        while !out_s.eof() {
            if inp.bits8(1)? != 0 {
                let b1 = inp.byte()?;
                let b2 = inp.byte()?;
                let mut dist = (u32::from(b1 & 0xf0) << 4) | u32::from(b2);
                if dist == 0 {
                    dist = 4096;
                }
                let count = (u32::from(b1 & 0xf) + 3).min(self.raw - out_s.offset() as u32);
                out_s.copy_fill(dist as usize, count as usize, 0)?;
            } else {
                out_s.write(inp.byte()?)?;
            }
        }
        self.packed = inp.offset();
        Ok(())
    }
}

// -- UNIX pack ----------------------------------------------------------

/// `UnixPackDecoder` — `0x1f1e` (new, dynamic canonical Huffman) or
/// `0x1f1f` (old, serialized tree; PDP-endian raw size).
struct UnixPack<'a> {
    d: &'a [u8],
    old: bool,
    raw: u32,
    packed: usize,
}

impl<'a> UnixPack<'a> {
    fn new(d: &'a [u8]) -> R<Self> {
        if d.len() < 6 {
            return Err(AncErr::Invalid);
        }
        let hdr = parse::rd_u16_be_le(d, 0, true).ok_or(AncErr::Invalid)?;
        if hdr != 0x1f1e && hdr != 0x1f1f {
            return Err(AncErr::Invalid);
        }
        let old = hdr == 0x1f1f;
        // PDP-endian on the old format: LE16@2 is the high word.
        let raw = if old {
            (u32::from(parse::rd_u16(d, 2).ok_or(AncErr::Invalid)?) << 16)
                | u32::from(parse::rd_u16(d, 4).ok_or(AncErr::Invalid)?)
        } else {
            parse::rd_u32_be_le(d, 2, true).ok_or(AncErr::Invalid)?
        };
        if u64::from(raw) > MAX_RAW || (old && raw == 0) {
            return Err(AncErr::Invalid);
        }
        Ok(Self {
            d,
            old,
            raw,
            packed: d.len(),
        })
    }

    /// `buildOldHuffmanDecoder` — recursive tree walk (depth ≤ 24).
    fn build_old(
        tree: &[u16; 1024],
        count: u32,
        dec: &mut Huff<u8>,
        node: u32,
        length: u32,
        bits: u32,
    ) -> R<()> {
        if node >= count {
            return Err(AncErr::Decomp);
        }
        if tree[node as usize] != 0 {
            let length = length + 1;
            let bits = bits << 1;
            if length > 24 {
                return Err(AncErr::Decomp);
            }
            Self::build_old(
                tree,
                count,
                dec,
                node + u32::from(tree[node as usize]),
                length,
                bits,
            )?;
            if node + 1 >= count {
                return Err(AncErr::Decomp);
            }
            Self::build_old(
                tree,
                count,
                dec,
                node + u32::from(tree[(node + 1) as usize]),
                length,
                bits | 1,
            )?;
        } else {
            if length == 0 {
                return Err(AncErr::Decomp);
            }
            dec.insert(length, bits, tree[(node + 1) as usize] as u8)?;
        }
        Ok(())
    }

    fn decompress(&mut self, out: &mut [u8]) -> R<()> {
        let end = if self.packed != 0 {
            self.packed
        } else {
            self.d.len()
        };
        let mut inp = In::fwd(self.d, 6, end, 0, true)?;
        let mut out_s = FOut::new(&mut out[..], 0, self.raw as usize)?;
        if self.old {
            let mut dec = Huff::<u8>::new();
            let mut tree = [0u16; 1024];
            let count = u32::from(inp.le16()?);
            if count >= 1024 {
                return Err(AncErr::Decomp);
            }
            for slot in tree.iter_mut().take(count as usize) {
                let tmp = inp.byte()?;
                *slot = if tmp < 255 {
                    u16::from(tmp)
                } else {
                    inp.le16()?
                };
            }
            Self::build_old(&tree, count, &mut dec, 0, 0, 0)?;
            while out_s.offset() != self.raw as usize {
                let v = dec.decode(|| inp.bits_le16(1))?;
                out_s.write(v)?;
            }
        } else {
            let mut dec = Huff::<u16>::new();
            let max_level = u32::from(inp.byte()?);
            if max_level == 0 || max_level > 24 {
                return Err(AncErr::Decomp);
            }
            let mut level_counts = [0u16; 24];
            for c in level_counts.iter_mut().take(max_level as usize) {
                *c = u16::from(inp.byte()?);
            }
            level_counts[max_level as usize - 1] += 2;
            let mut code = 0x100_0000u32;
            for (i, &c) in level_counts.iter().enumerate().take(max_level as usize) {
                code = code.wrapping_sub(u32::from(c) << (23 - i));
                for j in 0..c {
                    let symbol = if i == max_level as usize - 1 && j == c - 1 {
                        256u16
                    } else {
                        u16::from(inp.byte()?)
                    };
                    dec.insert(i as u32 + 1, code >> (23 - i), symbol)?;
                    code += 1 << (23 - i);
                }
                code = code.wrapping_sub(u32::from(c) << (23 - i));
            }
            while out_s.offset() != self.raw as usize {
                let c = dec.decode(|| inp.bits8(1))?;
                if c == 0x100 {
                    if out_s.offset() != self.raw as usize {
                        return Err(AncErr::Decomp);
                    }
                    break;
                }
                out_s.write(c as u8)?;
            }
        }
        // Upstream does not verify the exact packed length — the official
        // encoder tends to append a few bytes.
        self.packed = inp.offset();
        Ok(())
    }
}

// -- Freeze -------------------------------------------------------------

/// `FreezeDecoder` — `0x1f9e` (1.x, fixed table) / `0x1f9f` (2.x,
/// header-carried Huffman weight table) over an adaptive Huffman code.
struct Freeze<'a> {
    d: &'a [u8],
    old: bool,
    table: [u8; 8],
    packed: usize,
    raw: usize,
}

impl<'a> Freeze<'a> {
    fn new(d: &'a [u8]) -> R<Self> {
        if d.len() < 2 {
            return Err(AncErr::Invalid);
        }
        let hdr = parse::rd_u16_be_le(d, 0, true).ok_or(AncErr::Invalid)?;
        if hdr != 0x1f9e && hdr != 0x1f9f {
            return Err(AncErr::Invalid);
        }
        let old = hdr == 0x1f9e;
        let table;
        if old {
            table = [0u8, 0, 1, 3, 8, 12, 24, 16];
        } else {
            if d.len() < 5 {
                return Err(AncErr::Invalid);
            }
            let tmp = parse::rd_u16(d, 2).ok_or(AncErr::Invalid)?;
            if tmp & 0x8000 != 0 {
                return Err(AncErr::Invalid);
            }
            let t2 = *d.get(4).ok_or(AncErr::Invalid)?;
            if t2 & 0xc0 != 0 {
                return Err(AncErr::Invalid);
            }
            let mut t6 = [
                (tmp & 1) as u8,
                ((tmp >> 1) & 3) as u8,
                ((tmp >> 3) & 7) as u8,
                ((tmp >> 6) & 0xf) as u8,
                (tmp >> 10) as u8,
                t2,
                0,
                0,
            ];
            let mut count = 62u32;
            let mut weights = 256u32;
            for c in t6.iter().take(6) {
                count -= u32::from(*c);
            }
            for (i, c) in t6.iter().take(6).enumerate() {
                weights -= u32::from(*c) << (7 - i);
            }
            if weights < count || count * 2 < weights {
                return Err(AncErr::Invalid);
            }
            t6[6] = (weights - count) as u8;
            t6[7] = (count * 2 - weights) as u8;
            table = t6;
        }
        Ok(Self {
            d,
            old,
            table,
            packed: d.len(),
            raw: 0,
        })
    }

    fn decompress(&mut self, out: &mut Vec<u8>) -> R<()> {
        let end = if self.packed != 0 {
            self.packed
        } else {
            self.d.len()
        };
        let mut inp = In::fwd(self.d, if self.old { 2 } else { 5 }, end, 0, true)?;
        // Special case for an empty file.
        if inp.eof() {
            self.raw = 0;
            if self.packed != inp.offset() {
                return Err(AncErr::Decomp);
            }
            self.packed = inp.offset();
            return Ok(());
        }
        let mut out_s = GOut::new();
        let mut decoder = DynHuff::new(if self.old { 315 } else { 511 })?;
        let mut dist_dec = Huff::<u8>::new();
        {
            let mut high = [0u8; 64];
            let mut j = 0usize;
            for i in 0..8 {
                if j + self.table[i] as usize > 64 {
                    return Err(AncErr::Decomp);
                }
                for _ in 0..self.table[i] {
                    high[j] = i as u8 + 1;
                    j += 1;
                }
            }
            dist_dec.create_orderly(&high, j)?;
        }
        let distance_bits = if self.old { 6 } else { 7 };
        loop {
            let code = decoder.decode(|| inp.bits8(1))?;
            if decoder.max_frequency() == 0x8000 {
                decoder.halve();
            }
            decoder.update(code)?;
            if code == 256 {
                break;
            }
            if code < 256 {
                out_s.write(code as u8)?;
            } else {
                let mut dist = u32::from(dist_dec.decode(|| inp.bits8(1))?) << distance_bits;
                dist |= inp.bits8(distance_bits)?;
                dist += 1;
                let count = code - 254;
                out_s.copy_fill(dist as usize, count as usize, 0x20)?;
            }
        }
        self.raw = out_s.offset();
        if inp.offset() != self.packed {
            return Err(AncErr::Decomp);
        }
        self.packed = inp.offset();
        out_s.d.truncate(out_s.cur);
        out.clear();
        out.extend_from_slice(&out_s.d);
        Ok(())
    }
}

// -- RNC (ProPack) ------------------------------------------------------

/// `RncDecoder::Version`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RncVer {
    /// RNC1 old stream (12-byte header).
    Rnc1Old,
    /// RNC1 new stream (18-byte header, CRC fields, chunks).
    Rnc1New,
    /// RNC2 old stream.
    Rnc2Old,
    /// RNC2 new stream.
    Rnc2New,
}

/// `RncDecoder` — `RNC\x01`/`RNC\x02`/`...\x01` four-variant decoder.
struct Rnc<'a> {
    d: &'a [u8],
    ver: RncVer,
    raw: u32,
    packed: u32,
    raw_crc: u16,
    chunks: u8,
}

impl<'a> Rnc<'a> {
    fn new(d: &'a [u8], verify: bool) -> R<Self> {
        if d.len() < 12 {
            return Err(AncErr::Invalid);
        }
        let hdr = &d[..4];
        let raw = parse::rd_u32_be_le(d, 4, true).ok_or(AncErr::Invalid)?;
        let packed = parse::rd_u32_be_le(d, 8, true).ok_or(AncErr::Invalid)?;
        if raw == 0 || packed == 0 || u64::from(raw) > MAX_RAW || u64::from(packed) > MAX_PACKED {
            return Err(AncErr::Invalid);
        }
        let ver;
        let mut verified = false;
        if hdr == b"RNC\x01" {
            // CRC-first detection — see the upstream comment: a matching
            // packed-stream CRC at 14 is the definitive new-format sign.
            if d.len() <= 18 {
                ver = RncVer::Rnc1Old;
            } else if (d.len() as u64) >= u64::from(packed) + 18
                && crc16(d, 18, packed as usize, 0).ok() == parse::rd_u16_be_le(d, 14, true)
            {
                ver = RncVer::Rnc1New;
                verified = true;
            } else {
                let start = *d.get(packed as usize + 11).ok_or(AncErr::Invalid)?;
                ver = if start & 0x80 != 0 {
                    RncVer::Rnc1Old
                } else {
                    RncVer::Rnc1New
                };
            }
        } else if hdr == b"RNC\x02" {
            if d.len() <= 18 {
                ver = RncVer::Rnc2Old;
            } else if (d.len() as u64) >= u64::from(packed) + 18
                && crc16(d, 18, packed as usize, 0).ok() == parse::rd_u16_be_le(d, 14, true)
            {
                ver = RncVer::Rnc2New;
                verified = true;
            } else {
                let start = *d.get(packed as usize + 10).ok_or(AncErr::Invalid)?;
                ver = if start & 0x80 != 0 {
                    RncVer::Rnc2Old
                } else {
                    RncVer::Rnc2New
                };
            }
        } else if hdr == b"...\x01" {
            ver = RncVer::Rnc1New;
        } else {
            return Err(AncErr::Invalid);
        }
        let hdr_size = if matches!(ver, RncVer::Rnc1Old | RncVer::Rnc2Old) {
            12u64
        } else {
            18u64
        };
        if u64::from(packed) + hdr_size > d.len() as u64 {
            return Err(AncErr::Invalid);
        }
        let (mut raw_crc, mut chunks) = (0u16, 0u8);
        if !matches!(ver, RncVer::Rnc1Old | RncVer::Rnc2Old) {
            raw_crc = parse::rd_u16_be_le(d, 12, true).ok_or(AncErr::Invalid)?;
            chunks = *d.get(17).ok_or(AncErr::Invalid)?;
            if verify
                && !verified
                && crc16(d, 18, packed as usize, 0)?
                    != parse::rd_u16_be_le(d, 14, true).ok_or(AncErr::Invalid)?
            {
                return Err(AncErr::Verify);
            }
        }
        Ok(Self {
            d,
            ver,
            raw,
            packed,
            raw_crc,
            chunks,
        })
    }

    fn name(&self) -> &'static str {
        match self.ver {
            RncVer::Rnc1Old => "RNC1: Rob Northen RNC1 Compressor (old)",
            RncVer::Rnc1New => "RNC1: Rob Northen RNC1 Compressor",
            RncVer::Rnc2Old => "RNC2: Rob Northen RNC2 Compressor (old)",
            RncVer::Rnc2New => "RNC2: Rob Northen RNC2 Compressor",
        }
    }

    /// `getPackedSize` — header bytes plus the packed stream.
    fn packed_total(&self) -> u64 {
        u64::from(self.packed)
            + if matches!(self.ver, RncVer::Rnc1Old | RncVer::Rnc2Old) {
                12
            } else {
                18
            }
    }

    fn decompress(&mut self, out: &mut [u8], verify: bool) -> R<()> {
        if (out.len() as u64) < u64::from(self.raw) {
            return Err(AncErr::Decomp);
        }
        match self.ver {
            RncVer::Rnc1Old => self.decompress_old(out, verify, false),
            RncVer::Rnc1New => self.decompress_new1(out, verify),
            RncVer::Rnc2Old => self.decompress_old(out, verify, true),
            RncVer::Rnc2New => self.decompress_new2(out, verify),
        }
    }

    /// `RNCDecompressOld` — backward stream, VLC + tiny Huffman codes.
    fn decompress_old(&mut self, out: &mut [u8], verify: bool, rnc2: bool) -> R<()> {
        let mut inp = In::bwd(self.d, 12, self.packed as usize + 12, true)?;
        let mut last_dist_bits = 12u32;
        let mut last_len_bits = 10u32;
        if rnc2 {
            let tmp = u32::from(inp.byte()?) + 1;
            last_dist_bits = tmp & 0xf;
            last_len_bits = (tmp >> 4) + 1;
        }
        // Anchor-bit resync: scan the half-byte for the first set bit.
        {
            let half = inp.byte()?;
            for i in 0..7 {
                if half & (1 << i) != 0 {
                    inp.bits_reset(u32::from(half >> (i + 1)), (7 - i) as u8);
                    break;
                }
            }
        }
        let mut out_s = BOut::new(&mut out[..], 0, self.raw as usize)?;

        let mut len_h = Huff::<u8>::new();
        len_h.insert(1, 0x0, 0)?;
        len_h.insert(2, 0x2, 1)?;
        len_h.insert(3, 0x6, 2)?;
        len_h.insert(4, 0xe, 3)?;
        len_h.insert(4, 0xf, 4)?;

        let mut dist_h = Huff::<u8>::new();
        dist_h.insert(1, 0x0, 1)?;
        dist_h.insert(2, 0x2, 0)?;
        dist_h.insert(2, 0x3, 2)?;

        let lit_vlc1 = Vlc::new(&[1, 1, 2, 2, 3, 10]);
        let lit_vlc2 = Vlc::new(&[1, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let len_vlc = Vlc::new(&[0, 0, 1, 2, last_len_bits as i32]);
        let dist_vlc = Vlc::new(&[5, 8, last_dist_bits as i32]);

        loop {
            let lit_len = if rnc2 {
                lit_vlc2.cascade(|n| inp.bits8(n))?
            } else {
                lit_vlc1.cascade(|n| inp.bits8(n))?
            };
            for _ in 0..lit_len {
                out_s.write(inp.byte()?)?;
            }
            // The only successful way out of the loop.
            if out_s.eof() {
                break;
            }
            let len_base = len_h.decode(|| inp.bits8(1))? as u32;
            let count = len_vlc.decode(|n| inp.bits8(n), len_base)? + 2;
            let distance = if count != 2 {
                let dist_base = dist_h.decode(|| inp.bits8(1))? as u32;
                dist_vlc.decode(|n| inp.bits8(n), dist_base)?
            } else if inp.bits8(1)? == 0 {
                inp.bits8(6)?
            } else {
                inp.bits8(9)? + 64
            };
            out_s.copy(
                if distance != 0 {
                    (distance + count - 1) as usize
                } else {
                    1
                },
                count as usize,
            )?;
        }
        let _ = verify;
        Ok(())
    }

    /// `RNC1DecompressNew` — LSB bit order, per-chunk Huffman tables,
    /// optional "locked" (encrypted) stream support.
    fn decompress_new1(&mut self, out: &mut [u8], verify: bool) -> R<()> {
        let mut inp = In::fwd(self.d, 18, self.packed as usize + 18, 1, false)?;
        let mut out_s = FOut::new(&mut out[..], 0, self.raw as usize)?;

        // Locked (encrypted) stream support — see the upstream comment
        // for the deferred single-pass key recovery rationale.
        let mut run_index: Vec<u32> = Vec::new();
        let mut run_counter = 0u32;
        let mut track_pos = 0usize;

        let flags = inp.bits_le16(2)?;
        let encrypted = flags & 2 != 0;
        if encrypted {
            run_index.resize(self.raw as usize, 0);
        }

        macro_rules! read_huff_table {
            ($dec:ident) => {{
                let length = inp.bits_le16(5)?;
                if length != 0 {
                    let mut table = [0u8; 31];
                    for i in 0..length as usize {
                        table[i] = inp.bits_le16(4)? as u8;
                    }
                    $dec.create_orderly(&table, length as usize)?;
                }
            }};
        }
        macro_rules! huff_decode {
            ($dec:ident) => {{
                let ret = $dec.decode(|| inp.bits_le16(1))?;
                if ret >= 2 {
                    (1u32 << (ret - 1)) | inp.bits_le16(ret - 1)?
                } else {
                    ret
                }
            }};
        }
        macro_rules! process_literals {
            ($dec:ident) => {{
                let lit_len = huff_decode!($dec);
                for _ in 0..lit_len {
                    let b = inp.byte()?;
                    out_s.write(b)?;
                    if encrypted {
                        run_index[track_pos] = run_counter;
                        track_pos += 1;
                    }
                }
                // Empty literal runs do not advance the key rotation.
                if encrypted && lit_len != 0 {
                    run_counter += 1;
                }
            }};
        }

        // `ALLOW_MISSING_CHUNKS` — upstream tolerates unpatched PC
        // compressors by looping until the output fills.
        while !out_s.eof() {
            let mut lit_dec = Huff::<u32>::new();
            let mut dist_dec = Huff::<u32>::new();
            let mut len_dec = Huff::<u32>::new();
            read_huff_table!(lit_dec);
            read_huff_table!(dist_dec);
            read_huff_table!(len_dec);
            let count = inp.bits_le16(16)?;
            let mut sub = 1u32;
            while sub < count {
                process_literals!(lit_dec);
                let distance = huff_decode!(dist_dec);
                let sub_count = huff_decode!(len_dec);
                let distance = distance + 1;
                let sub_count = sub_count + 2;
                out_s.copy(distance as usize, sub_count as usize)?;
                if encrypted {
                    for _ in 0..sub_count {
                        run_index[track_pos] = run_index[track_pos - distance as usize];
                        track_pos += 1;
                    }
                }
                sub += 1;
            }
            process_literals!(lit_dec);
        }
        if !out_s.eof() {
            return Err(AncErr::Decomp);
        }

        // Recover and apply the decryption key for locked streams — the
        // key enters the 16-bit unpacked CRC linearly, so the key is a
        // GF(2) linear function of the target CRC.
        if encrypted {
            let base = crc16(out, 0, self.raw as usize, 0)?;
            if base != self.raw_crc {
                let ror16 = |key: u32, n: u32| -> u32 {
                    let n = n & 15;
                    ((key >> n) | (key << (16 - n))) & 0xffff
                };
                // deltas[j] = CRC contribution of key bit j.
                let mut deltas = [0u16; 16];
                for &item in run_index.iter().take(self.raw as usize) {
                    let r = item & 15;
                    for (j, d) in deltas.iter_mut().enumerate() {
                        let p = (j as i64 - r as i64) & 15;
                        let b = if p < 8 { 1u8 << p } else { 0 };
                        *d = crc16_byte(b, *d);
                    }
                }
                let predicted = |key: u32| -> u16 {
                    let mut x = base;
                    for (j, &d) in deltas.iter().enumerate() {
                        if key & (1 << j) != 0 {
                            x ^= d;
                        }
                    }
                    x
                };
                // Only decrypt when the key is safe to trust: a known
                // ProPack collection password, or a unique key in the
                // whole 16-bit space.
                const KNOWN_KEYS: [u16; 3] = [0x04d2, 0x1984, 0x5ed0];
                let mut key = 0u32;
                let mut have = false;
                for &k in &KNOWN_KEYS {
                    if predicted(u32::from(k)) == self.raw_crc {
                        key = u32::from(k);
                        have = true;
                        break;
                    }
                }
                if !have {
                    let mut matches = 0u32;
                    let mut k = 1u32;
                    while k < 0x10000 && matches < 2 {
                        if predicted(k) == self.raw_crc {
                            key = k;
                            matches += 1;
                        }
                        k += 1;
                    }
                    have = matches == 1;
                }
                if have {
                    for i in 0..self.raw as usize {
                        out[i] ^= (ror16(key, run_index[i]) & 0xff) as u8;
                    }
                }
            }
        }
        if verify && crc16(out, 0, self.raw as usize, 0)? != self.raw_crc {
            return Err(AncErr::Verify);
        }
        Ok(())
    }

    /// `RNC2DecompressNew` — MSB order, command-tree driven chunks.
    fn decompress_new2(&mut self, out: &mut [u8], verify: bool) -> R<()> {
        let mut inp = In::fwd(self.d, 18, self.packed as usize + 18, 0, true)?;
        let mut out_s = FOut::new(&mut out[..], 0, self.raw as usize)?;

        #[derive(Clone, Copy, Default)]
        enum Cmd {
            #[default]
            Lit,
            Mov,
            Mv2,
            Mv3,
            Cnd,
        }

        let mut cmd_dec = Huff::<Cmd>::new();
        cmd_dec.insert(1, 0x0, Cmd::Lit)?;
        cmd_dec.insert(2, 0x2, Cmd::Mov)?;
        cmd_dec.insert(3, 0x6, Cmd::Mv2)?;
        cmd_dec.insert(4, 0xe, Cmd::Mv3)?;
        cmd_dec.insert(4, 0xf, Cmd::Cnd)?;

        let mut len_dec = Huff::<u8>::new();
        len_dec.insert(2, 0x0, 4)?;
        len_dec.insert(2, 0x2, 5)?;
        len_dec.insert(3, 0x2, 6)?;
        len_dec.insert(3, 0x3, 7)?;
        len_dec.insert(3, 0x6, 8)?;
        len_dec.insert(3, 0x7, 9)?;

        let mut dist_dec = Huff::<u8>::new();
        dist_dec.insert(1, 0x00, 0)?;
        dist_dec.insert(3, 0x06, 1)?;
        dist_dec.insert(4, 0x08, 2)?;
        dist_dec.insert(4, 0x09, 3)?;
        dist_dec.insert(5, 0x15, 4)?;
        dist_dec.insert(5, 0x17, 5)?;
        dist_dec.insert(5, 0x1d, 6)?;
        dist_dec.insert(5, 0x1f, 7)?;
        dist_dec.insert(6, 0x28, 8)?;
        dist_dec.insert(6, 0x29, 9)?;
        dist_dec.insert(6, 0x2c, 10)?;
        dist_dec.insert(6, 0x2d, 11)?;
        dist_dec.insert(6, 0x38, 12)?;
        dist_dec.insert(6, 0x39, 13)?;
        dist_dec.insert(6, 0x3c, 14)?;
        dist_dec.insert(6, 0x3d, 15)?;

        macro_rules! read_distance {
            () => {{
                let dm = dist_dec.decode(|| inp.bits8(1))?;
                let db = inp.byte()?;
                (u32::from(db) | (u32::from(dm) << 8)) + 1
            }};
        }
        macro_rules! move_bytes {
            ($dist:expr, $count:expr) => {{
                let c: u32 = $count;
                if c == 0 {
                    return Err(AncErr::Decomp);
                }
                out_s.copy($dist as usize, c as usize)?;
            }};
        }

        inp.bits8(1)?;
        inp.bits8(1)?;
        let mut found = 0u8;
        let mut done = false;
        while !done && found < self.chunks {
            match cmd_dec.decode(|| inp.bits8(1))? {
                Cmd::Lit => out_s.write(inp.byte()?)?,
                Cmd::Mov => {
                    let count = len_dec.decode(|| inp.bits8(1))?;
                    if count != 9 {
                        let d2 = read_distance!();
                        move_bytes!(d2, u32::from(count));
                    } else {
                        let rep = (inp.bits8(4)? + 3) * 4;
                        for _ in 0..rep {
                            out_s.write(inp.byte()?)?;
                        }
                    }
                }
                Cmd::Mv2 => {
                    let d2 = u32::from(inp.byte()?) + 1;
                    move_bytes!(d2, 2);
                }
                Cmd::Mv3 => {
                    let d2 = read_distance!();
                    move_bytes!(d2, 3);
                }
                Cmd::Cnd => {
                    let count = inp.byte()?;
                    if count != 0 {
                        let d2 = read_distance!();
                        move_bytes!(d2, u32::from(count) + 8);
                    } else {
                        found += 1;
                        done = inp.bits8(1)? == 0;
                    }
                }
            }
        }
        if !out_s.eof() || self.chunks != found {
            return Err(AncErr::Decomp);
        }
        if verify && crc16(out, 0, self.raw as usize, 0)? != self.raw_crc {
            return Err(AncErr::Verify);
        }
        Ok(())
    }
}

// -- describe / decode --------------------------------------------------

/// `describe` — construct the decoder and read out its sizes.
pub(crate) fn describe(d: &[u8], kind: Kind) -> Option<Info> {
    if d.len() < 2 || d.len() as u64 > MAX_PACKED_SIZE || identify(d) != Some(kind) {
        return None;
    }
    let info = match kind {
        Kind::Tpwm => {
            let t = Tpwm::new(d).ok()?;
            Info {
                method: "TPWM: Turbo Packer",
                packed: -1,
                raw: i64::from(t.raw),
                image: i64::from(t.raw),
                image_offset: 0,
            }
        }
        Kind::UnixPack => {
            let u = UnixPack::new(d).ok()?;
            Info {
                method: if u.old { "z: Pack (Old)" } else { "z: Pack" },
                packed: i64::try_from(u.packed).unwrap_or(-1),
                raw: i64::from(u.raw),
                image: i64::from(u.raw),
                image_offset: 0,
            }
        }
        Kind::Freeze => {
            let f = Freeze::new(d).ok()?;
            Info {
                method: if f.old {
                    "F: Freeze/Melt 1.x"
                } else {
                    "F: Freeze/Melt 2.x"
                },
                packed: i64::try_from(f.packed).unwrap_or(-1),
                raw: 0,
                image: 0,
                image_offset: 0,
            }
        }
        Kind::Rnc => {
            let r = Rnc::new(d, true).ok()?;
            Info {
                method: r.name(),
                packed: i64::try_from(r.packed_total()).unwrap_or(-1),
                raw: i64::from(r.raw),
                image: i64::from(r.raw),
                image_offset: 0,
            }
        }
    };
    if info.packed > d.len() as i64
        || info.raw > MAX_RAW_SIZE as i64
        || info.image > MAX_RAW_SIZE as i64
    {
        return None;
    }
    Some(info)
}

/// `decode` — run the decoder and return the raw bytes plus info.
pub(crate) fn decode(d: &[u8], kind: Kind, verify: bool) -> R<(Vec<u8>, Info)> {
    if d.len() < 2 || d.len() as u64 > MAX_PACKED_SIZE || identify(d) != Some(kind) {
        return Err(AncErr::Invalid);
    }
    match kind {
        Kind::Tpwm => {
            let mut dec = Tpwm::new(d)?;
            let mut out = vec![0u8; dec.raw as usize];
            dec.decompress(&mut out)?;
            Ok((
                out,
                Info {
                    method: "TPWM: Turbo Packer",
                    packed: dec.packed as i64,
                    raw: i64::from(dec.raw),
                    image: i64::from(dec.raw),
                    image_offset: 0,
                },
            ))
        }
        Kind::UnixPack => {
            let mut dec = UnixPack::new(d)?;
            let mut out = vec![0u8; dec.raw as usize];
            dec.decompress(&mut out)?;
            Ok((
                out,
                Info {
                    method: if dec.old { "z: Pack (Old)" } else { "z: Pack" },
                    packed: dec.packed as i64,
                    raw: i64::from(dec.raw),
                    image: i64::from(dec.raw),
                    image_offset: 0,
                },
            ))
        }
        Kind::Freeze => {
            let mut dec = Freeze::new(d)?;
            let mut out = Vec::new();
            dec.decompress(&mut out)?;
            Ok((
                out,
                Info {
                    method: if dec.old {
                        "F: Freeze/Melt 1.x"
                    } else {
                        "F: Freeze/Melt 2.x"
                    },
                    packed: dec.packed as i64,
                    raw: dec.raw as i64,
                    image: dec.raw as i64,
                    image_offset: 0,
                },
            ))
        }
        Kind::Rnc => {
            let mut dec = Rnc::new(d, verify)?;
            let mut out = vec![0u8; dec.raw as usize];
            dec.decompress(&mut out, verify)?;
            Ok((
                out,
                Info {
                    method: dec.name(),
                    packed: dec.packed_total() as i64,
                    raw: i64::from(dec.raw),
                    image: i64::from(dec.raw),
                    image_offset: 0,
                },
            ))
        }
    }
}

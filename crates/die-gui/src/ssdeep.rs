//! SSDeep / SpamSum context-triggered piecewise hash (CTPH).
//!
//! Clean-room Rust implementation of the algorithm published by Tridgell
//! (spamsum) and Kornblum (CTPH, DFRWS 2006). Written against the public
//! algorithm description and validated against independent reference
//! digests produced by `ppdeep` (Apache-2.0 pure-Python port) — see
//! `tests/ssdeep_vectors.rs`. No code was taken from GPL-licensed
//! `libfuzzy`/`fuzzy.c`, so this file carries no copyleft contamination
//! (see `docs/design/decisions/0039-fuzzy-hashes.md`).

/// Smallest trigger block size; digest granularity floor.
const MIN_BLOCK_SIZE: u64 = 3;
/// Maximum digest characters emitted per trigger channel.
const SPAMSUM_LENGTH: usize = 64;
/// Rolling window used by the trigger hash.
const ROLL_WINDOW: usize = 7;
/// FNV-1 style multiplier for the per-block checksum.
const HASH_PRIME: u32 = 0x0100_0193;
/// Per-block checksum seed.
const HASH_INIT: u32 = 0x27;
/// Canonical ssdeep base-64 alphabet.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Rolling hash state (7-byte window, three running sums).
struct Rolling {
    window: [u8; ROLL_WINDOW],
    n: usize,
    h1: u32,
    h2: u32,
    h3: u32,
}

impl Rolling {
    /// Create a zeroed rolling state.
    fn new() -> Self {
        Self {
            window: [0; ROLL_WINDOW],
            n: 0,
            h1: 0,
            h2: 0,
            h3: 0,
        }
    }

    /// Feed one byte and return the current rolling digest.
    fn update(&mut self, b: u8) -> u32 {
        self.h2 = self
            .h2
            .wrapping_sub(self.h1)
            .wrapping_add((ROLL_WINDOW as u32).wrapping_mul(b as u32));
        self.h1 = self
            .h1
            .wrapping_add(b as u32)
            .wrapping_sub(self.window[self.n] as u32);
        self.window[self.n] = b;
        self.n = (self.n + 1) % ROLL_WINDOW;
        self.h3 = self.h3.wrapping_shl(5) ^ (b as u32);
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

/// Run one full pass over `data` at `block_size`, returning the two
/// digest channels. The second return value is the final rolling hash
/// (`0` when `data` is empty), which decides the tail emit semantics.
fn spamsum_pass(data: &[u8], block_size: u64) -> (String, String, u32) {
    let mut roll = Rolling::new();
    let mut h1 = HASH_INIT;
    let mut h2 = HASH_INIT;
    let mut s1 = String::new();
    let mut s2 = String::new();
    let mut last1 = String::new();
    let mut last2 = String::new();
    let mut rh = 0u32;

    for &b in data {
        h1 = h1.wrapping_mul(HASH_PRIME) ^ (b as u32);
        h2 = h2.wrapping_mul(HASH_PRIME) ^ (b as u32);
        rh = roll.update(b);

        if (rh as u64) % block_size != block_size - 1 {
            continue;
        }
        // Trigger level 1: record the candidate char even when the
        // channel is already full — the overflow char becomes the tail
        // value if the stream ends with a zero rolling hash.
        last1 = (B64[(h1 % 64) as usize] as char).to_string();
        if s1.len() < SPAMSUM_LENGTH - 1 {
            s1.push_str(&last1);
            h1 = HASH_INIT;
            last1.clear();
        }
        if (rh as u64) % (block_size * 2) != block_size * 2 - 1 {
            continue;
        }
        last2 = (B64[(h2 % 64) as usize] as char).to_string();
        if s2.len() < SPAMSUM_LENGTH / 2 - 1 {
            s2.push_str(&last2);
            h2 = HASH_INIT;
            last2.clear();
        }
    }

    if rh != 0 {
        s1.push(B64[(h1 % 64) as usize] as char);
        s2.push(B64[(h2 % 64) as usize] as char);
        return (s1, s2, rh);
    }
    s1.push_str(&last1);
    s2.push_str(&last2);
    (s1, s2, rh)
}

/// Compute the ssdeep fuzzy hash of `data`, formatted as
/// `blocksize:digest1:digest2` — byte-identical to libfuzzy output.
pub fn ssdeep(data: &[u8]) -> String {
    let mut block_size = MIN_BLOCK_SIZE;
    while block_size.wrapping_mul(SPAMSUM_LENGTH as u64) < data.len() as u64 {
        block_size *= 2;
    }
    loop {
        let (s1, s2, _rh) = spamsum_pass(data, block_size);
        // If the primary digest came out too short for the chosen block
        // size, halve and recompute so neighbouring edits stay local.
        if block_size > MIN_BLOCK_SIZE && s1.len() < SPAMSUM_LENGTH / 2 {
            block_size /= 2;
            continue;
        }
        return format!("{block_size}:{s1}:{s2}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // Reference digests produced by `ppdeep` 20260221 (Apache-2.0),
        // a pure-Python port of Tridgell's spamsum.
        assert_eq!(ssdeep(b""), "3::");
        assert_eq!(ssdeep(b"hello world"), "3:iKFSMPn:rJPn");
        assert_eq!(ssdeep(b"a"), "3:E:E");
        assert_eq!(ssdeep(b"abc"), "3:uG:uG");
    }

    /// Same deterministic LCG as `tools`-side vector generation
    /// (`corpus/ssdeep-vectors.json`), so payloads are rebuilt instead of
    /// being committed as opaque blobs.
    fn lcg_bytes(n: usize, seed: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut x = seed;
        for _ in 0..n {
            x = x.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fffffff;
            out.push(((x >> 16) & 0xff) as u8);
        }
        out
    }

    #[test]
    fn oracle_vectors() {
        // Expected digests captured from `ppdeep` 20260221 (see
        // corpus/ssdeep-vectors.json for the sha256 of each payload).
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (Vec::new(), "3::"),
            (b"hello world".to_vec(), "3:iKFSMPn:rJPn"),
            (
                vec![b'A'; 192],
                "3:Wttkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkw:Yu",
            ),
            (
                vec![b'A'; 193],
                "3:WttkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkR:Yr",
            ),
            (
                b"ABCD".repeat(1024),
                "12:+bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbC:n",
            ),
            (
                lcg_bytes(8192, 7),
                "192:jTEHgZraNfRwKZxmTym9e6X8N0d7ithsJw5xIFrk4o5C:0HgZrO+xv8C0hEpeC",
            ),
            (
                lcg_bytes(65536, 11),
                "1536:kf5OyxrLigmERSINwJSq9zR9JpTidqtUdpM/:kf53LogNiSeR9j4SeU",
            ),
            (
                (0u8..=255).cycle().take(256 * 7).collect(),
                "48:XDfLTTLTDfLTTf7fTL377fTL3TDfLTTLTDfLTTf7fTL377fTL3TDfLTTLTDfLTTn:zf33Pf3ff33Pf33Pf33Pf3ff33Pf33Pb",
            ),
            (
                lcg_bytes(300, 3),
                "6:sZAalycHGLYaf9C0e7gPmK7yBI4y0Ar/GYJrtX4wlDLp8Q0IlN+FqBrkR1Zgn:oAaHfaw0ec9mBIF5bfX4WDLSilNVBoIn",
            ),
        ];
        for (data, expected) in cases {
            assert_eq!(ssdeep(&data), expected, "len={}", data.len());
        }
    }

    #[test]
    fn block_size_scales_with_length() {
        // High-entropy input > 3*64 bytes must move past block size 3
        // (repetitive input collapses back to 3 via the halving retry —
        // that path is covered by the oracle vectors above).
        let hash = ssdeep(&lcg_bytes(8192, 7));
        let bs: u64 = hash.split(':').next().unwrap().parse().unwrap();
        assert!(bs > 3);
    }

    #[test]
    fn deterministic_and_bounded() {
        let data: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        let h1 = ssdeep(&data);
        let h2 = ssdeep(&data);
        assert_eq!(h1, h2);
        let mut it = h1.split(':');
        it.next();
        assert!(it.next().unwrap().len() <= SPAMSUM_LENGTH);
        assert!(it.next().unwrap().len() <= SPAMSUM_LENGTH / 2);
    }
}

//! Fuzz target: ByteSource read_at and read_exact_at.
//!
//! Invariant: no panic, no out-of-bounds read, typed errors for short reads.
//! See testing.md section 14.

#![no_main]

use die_core::input::{ByteSource, MemorySource};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let src = MemorySource::new(data);

    // read_at with various offsets and buffer sizes.
    for offset in [0u64, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        let mut out = [0u8; 64];
        let _ = src.read_at(offset, &mut out);
    }

    // read_exact_at with various offsets and buffer sizes.
    for offset in [0u64, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        let mut out = [0u8; 64];
        let _ = src.read_exact_at(offset, &mut out);
    }

    // read_exact_at with zero-length buffer (should always succeed).
    let _ = src.read_exact_at(0, &mut []);

    // read_at with zero-length buffer.
    let _ = src.read_at(0, &mut []);
});

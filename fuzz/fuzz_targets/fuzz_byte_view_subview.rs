//! Fuzz target: ByteView subview, read and typed integer reads.
//!
//! Invariant: no panic, no out-of-bounds read, view bounds never exceeded.
//! See testing.md section 14.

#![no_main]

use die_core::input::{ByteRange, ByteSource, ByteView, MemorySource};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let src = MemorySource::new(data);
    let total_len = src.len();
    if total_len == 0 {
        return;
    }

    // Create a view covering the entire source.
    let range = ByteRange::new(0, total_len).unwrap();
    let view = ByteView::new(&src, range).unwrap();

    // Try subviews with various offsets and lengths.
    for offset in [0u64, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        for length in [0u64, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
            if let Some(sub) = view.subview(offset, length) {
                // read_at on the subview must not exceed its bounds.
                let mut out = [0u8; 64];
                let _ = sub.read_at(0, &mut out);
                let _ = sub.read_at(offset, &mut out);

                // read_exact_at on the subview.
                let _ = sub.read_exact_at(0, &mut out);

                // Typed integer reads.
                let _ = sub.read_u8(0);
                let _ = sub.read_u16_le(0);
                let _ = sub.read_u16_be(0);
                let _ = sub.read_u32_le(0);
                let _ = sub.read_u32_be(0);
                let _ = sub.read_u64_le(0);
                let _ = sub.read_u64_be(0);
            }
        }
    }

    // Typed reads on the full view at various offsets.
    for offset in [0u64, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        let _ = view.read_u8(offset);
        let _ = view.read_u16_le(offset);
        let _ = view.read_u16_be(offset);
        let _ = view.read_u32_le(offset);
        let _ = view.read_u32_be(offset);
        let _ = view.read_u64_le(offset);
        let _ = view.read_u64_be(offset);
    }
});

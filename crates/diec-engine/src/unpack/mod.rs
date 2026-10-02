//! Static unpacking of packed executables (upstream `XStaticUnpacker` parity).
//!
//! Currently implemented: UPX-packed PE32/PE32+ files — detection via the
//! `UPX!` pack header, NRV2B/NRV2D/NRV2E (all three bit widths), LZMA and
//! DEFLATE decompression, and the PE rebuild pass (import/reloc/export/
//! resource restoration, input-filter reversal, overlay preservation).
//!
//! ELF, Mach-O and DOS UPX containers are detected through the pack header
//! but their rebuilders are not implemented yet.

mod nrv;
mod upx;

pub use nrv::{BitWidth, NrvAlgorithm, NrvError, nrv_decompress};
pub use upx::{
    UnpackError, UpxInfo, decompress_payload, detect_upx, is_upx_packed, unpack, unpack_pe,
};

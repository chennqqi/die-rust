//! Static unpacking of packed executables (upstream `XStaticUnpacker` parity).
//!
//! Currently implemented:
//! - UPX-packed PE32/PE32+ files — detection via the `UPX!` pack header,
//!   NRV2B/NRV2D/NRV2E (all three bit widths), LZMA and DEFLATE
//!   decompression, and the PE rebuild pass (import/reloc/export/resource
//!   restoration, input-filter reversal, overlay preservation).
//! - FSG (1.0-1.3 / 1.31 / 1.33 / 2.0 / encrypted 1.1-1.2 stub) PE32.
//! - MEW (10 and 11 SE; aPLib and raw-LZMA1 container paths) PE32.
//! - Petite (2.x and 2.x level 1) PE32.
//!
//! ELF, Mach-O and DOS UPX containers are detected through the pack header
//! but their rebuilders are not implemented yet.

mod aplib;
mod aspack;
mod fsg;
mod mew;
mod nrv;
mod nspack;
mod petite;
mod upx;
mod yoda;

pub(crate) use upx::PackedPe;

pub use aspack::{AspackInfo, detect_aspack, unpack_aspack};
pub use fsg::{FsgInfo, detect_fsg, unpack_fsg};
pub use mew::{MewInfo, detect_mew, unpack_mew};
pub use nrv::{BitWidth, NrvAlgorithm, NrvError, nrv_decompress};
pub use nspack::{NsPackInfo, detect_nspack, unpack_nspack};
pub use petite::{PetiteInfo, detect_petite, unpack_petite};
pub use upx::{
    UnpackError, UpxInfo, decompress_payload, detect_upx, is_upx_packed, unpack, unpack_pe,
};
pub use yoda::{YodaInfo, detect_yoda, unpack_yoda};

/// Packer family identified by [`detect_packed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackerKind {
    /// UPX (`UPX!` pack header).
    Upx,
    /// FSG (all supported stub versions).
    Fsg,
    /// MEW (10 / 11 SE).
    Mew,
    /// Petite (2.x).
    Petite,
    /// yoda's Crypter (yC).
    Yoda,
    /// ASPack (non-emulator layout rows).
    Aspack,
    /// NsPack (1.4/2.x/3.x loader stub).
    Nspack,
}

/// Detection result across all supported static unpackers.
#[derive(Debug, Clone)]
pub struct PackedInfo {
    /// Which packer matched.
    pub kind: PackerKind,
    /// Packer family name, e.g. `"FSG"`.
    pub name: &'static str,
    /// Version string as reported by the packer's detector.
    pub version: String,
}

/// `XStaticUnpacker`-level detection: tries every supported unpacker in
/// the upstream candidate order (UPX, FSG, MEW, Petite). First hit wins.
pub fn detect_packed(data: &[u8]) -> Option<PackedInfo> {
    if let Some(info) = detect_upx(data) {
        return Some(PackedInfo {
            kind: PackerKind::Upx,
            name: "UPX",
            version: format!("0x{:02x}", info.version),
        });
    }
    if let Some(info) = detect_fsg(data) {
        return Some(PackedInfo {
            kind: PackerKind::Fsg,
            name: "FSG",
            version: info.sversion.to_string(),
        });
    }
    if let Some(info) = detect_mew(data) {
        return Some(PackedInfo {
            kind: PackerKind::Mew,
            name: "MEW",
            version: info.sversion.to_string(),
        });
    }
    if let Some(info) = detect_petite(data) {
        return Some(PackedInfo {
            kind: PackerKind::Petite,
            name: "Petite",
            version: info.sversion.to_string(),
        });
    }
    if let Some(info) = detect_yoda(data) {
        return Some(PackedInfo {
            kind: PackerKind::Yoda,
            name: "yC",
            version: info.sversion.to_string(),
        });
    }
    if let Some(info) = detect_aspack(data) {
        return Some(PackedInfo {
            kind: PackerKind::Aspack,
            name: "ASPack",
            version: info.sversion.to_string(),
        });
    }
    // Upstream reports an empty version string for NsPack.
    detect_nspack(data).map(|_| PackedInfo {
        kind: PackerKind::Nspack,
        name: "NsPack",
        version: String::new(),
    })
}

/// `XStaticUnpacker`-level dispatch: unpacks whichever supported packer
/// [`detect_packed`] identifies. No output limit (upstream default `-1`).
/// Returns [`UnpackError::NotPacked`] when nothing matches.
pub fn unpack_any(data: &[u8]) -> Result<Vec<u8>, UnpackError> {
    match detect_packed(data) {
        Some(PackedInfo {
            kind: PackerKind::Upx,
            ..
        }) => upx::unpack(data),
        Some(PackedInfo {
            kind: PackerKind::Fsg,
            ..
        }) => unpack_fsg(data, -1),
        Some(PackedInfo {
            kind: PackerKind::Mew,
            ..
        }) => unpack_mew(data, -1),
        Some(PackedInfo {
            kind: PackerKind::Petite,
            ..
        }) => unpack_petite(data, -1),
        Some(PackedInfo {
            kind: PackerKind::Yoda,
            ..
        }) => unpack_yoda(data, -1),
        Some(PackedInfo {
            kind: PackerKind::Aspack,
            ..
        }) => unpack_aspack(data, -1),
        Some(PackedInfo {
            kind: PackerKind::Nspack,
            ..
        }) => unpack_nspack(data, -1),
        None => Err(UnpackError::NotPacked),
    }
}

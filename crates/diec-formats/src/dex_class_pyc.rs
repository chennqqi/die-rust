//! DEX, Java Class and PYC format probes (CAP-DISPATCH-005).
//!
//! - DEX: magic `dex\n035\0` (or `dex\n036\0`, `dex\n037\0`, `dex\n038\0`,
//!   `dex\n039\0`, `dex\n040\0`).
//! - Java Class: magic `0xCAFEBABE` (big-endian). Note: Mach-O FAT also uses
//!   `0xCAFEBABE`; the Mach-O probe runs before this one in the dispatch
//!   order, so FAT binaries are identified first. A Java class file has
//!   major/minor version fields after the magic that a FAT binary does not.
//! - PYC: Python compiled bytecode. The first 4 bytes are a version-specific
//!   u16 magic (little-endian) followed by the `0x0D 0x0A` marker at bytes
//!   2-3. Upstream `XPYC::isValid` requires the magic u16 to be in the known
//!   CPython magic table — arbitrary prefixes are not accepted.

use crate::probe::{FormatProbe, ProbeError, ProbeOutcome, strong_deferred};
use diec_core::format::FileType;
use diec_core::input::ByteView;

/// DEX format probe.
#[derive(Debug, Default)]
pub struct DexProbe;

/// Java Class format probe.
#[derive(Debug, Default)]
pub struct JavaClassProbe;

/// PYC (Python compiled) format probe.
#[derive(Debug, Default)]
pub struct PycProbe;

/// DEX magic prefix: `dex\n`.
const DEX_MAGIC_PREFIX: [u8; 4] = [0x64, 0x65, 0x78, 0x0A];
/// DEX magic is 8 bytes: `dex\n035\0` etc. The version is 3 ASCII digits
/// at offset 4-6, followed by `\0` at offset 7.
const DEX_MAGIC_LEN: u64 = 8;
/// Java Class magic: `0xCAFEBABE` big-endian.
const JAVA_CLASS_MAGIC: u32 = 0xCAFEBABE;

/// Known CPython PYC magic values (LE u16 at offset 0), sorted for binary
/// search. Ported verbatim from upstream `XPYC::g_records` (xpyc.cpp).
const PYC_KNOWN_MAGICS: &[u16] = &[
    2012, 3000, 3111, 3131, 3141, 3151, 3160, 3170, 3180, 3190, 3200, 3210, 3220, 3230, 3250, 3260,
    3270, 3280, 3290, 3300, 3310, 3320, 3330, 3340, 3350, 3351, 3360, 3361, 3370, 3371, 3372, 3373,
    3375, 3376, 3377, 3378, 3379, 3390, 3391, 3392, 3393, 3394, 3400, 3401, 3410, 3411, 3412, 3413,
    3420, 3421, 3422, 3423, 3424, 3425, 3430, 3431, 3432, 3433, 3434, 3435, 3436, 3437, 3438, 3439,
    3450, 3451, 3452, 3453, 3454, 3455, 3456, 3457, 3458, 3459, 3460, 3461, 3462, 3463, 3464, 3465,
    3466, 3467, 3468, 3469, 3470, 3471, 3472, 3473, 3474, 3475, 3476, 3477, 3478, 3479, 3480, 3481,
    3482, 3483, 3484, 3485, 3486, 3487, 3488, 3489, 3490, 3491, 3492, 3493, 3494, 3495, 3500, 3501,
    3502, 3503, 3504, 3505, 3506, 3507, 3508, 3509, 3510, 3511, 3512, 3513, 3514, 3515, 3516, 3517,
    3518, 3519, 3520, 3521, 3522, 3523, 3524, 3525, 3526, 3527, 3528, 3529, 3530, 3531, 3550, 3551,
    3552, 3553, 3554, 3555, 3556, 3557, 3558, 3559, 3560, 3561, 3562, 3563, 3564, 3565, 3566, 3567,
    3568, 3569, 3570, 3571, 3600, 5042, 5082, 6020, 6071, 6201, 6202, 6204, 6205, 6206, 6207, 6208,
    6209, 6210, 6211, 6212, 6213, 6215, 6216, 6217, 6218, 6219, 6220, 6221,
];

impl FormatProbe for DexProbe {
    fn file_type(&self) -> FileType {
        FileType::new("DEX")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        if view.len() < DEX_MAGIC_LEN {
            return Ok(None);
        }
        let mut magic = [0u8; 4];
        view.read_exact_at(0, &mut magic)
            .map_err(|cause| ProbeError::Truncated {
                file_type: FileType::new("DEX"),
                cause,
            })?;
        if magic != DEX_MAGIC_PREFIX {
            return Ok(None);
        }
        // Verify version digits at offset 4-6 are ASCII digits and byte 7 is 0.
        let d4 = view.read_u8(4).map_err(|cause| ProbeError::Truncated {
            file_type: FileType::new("DEX"),
            cause,
        })?;
        let d5 = view.read_u8(5).map_err(|cause| ProbeError::Truncated {
            file_type: FileType::new("DEX"),
            cause,
        })?;
        let d6 = view.read_u8(6).map_err(|cause| ProbeError::Truncated {
            file_type: FileType::new("DEX"),
            cause,
        })?;
        let d7 = view.read_u8(7).map_err(|cause| ProbeError::Truncated {
            file_type: FileType::new("DEX"),
            cause,
        })?;
        if d4.is_ascii_digit() && d5.is_ascii_digit() && d6.is_ascii_digit() && d7 == 0 {
            Ok(Some(ProbeOutcome {
                candidate: strong_deferred("DEX"),
            }))
        } else {
            Ok(None)
        }
    }
}

impl FormatProbe for JavaClassProbe {
    fn file_type(&self) -> FileType {
        FileType::new("Java Class")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        // Upstream XJavaClass::isValid: size >= 24, CAFEBABE magic, and the
        // big-endian u32 at offset 4 (minor<<16 | major) must exceed 10.
        // The >10 check is what separates class files from Mach-O FAT
        // binaries whose nfat_arch count at offset 4 stays small.
        if view.len() < 24 {
            return Ok(None);
        }
        let magic = view.read_u32_be(0).map_err(|cause| ProbeError::Truncated {
            file_type: FileType::new("Java Class"),
            cause,
        })?;
        if magic != JAVA_CLASS_MAGIC {
            return Ok(None);
        }
        let version = view.read_u32_be(4).map_err(|cause| ProbeError::Truncated {
            file_type: FileType::new("Java Class"),
            cause,
        })?;
        if version > 10 {
            Ok(Some(ProbeOutcome {
                candidate: strong_deferred("Java Class"),
            }))
        } else {
            Ok(None)
        }
    }
}

impl FormatProbe for PycProbe {
    fn file_type(&self) -> FileType {
        FileType::new("PYC")
    }

    fn probe(&self, view: &ByteView<'_>) -> Result<Option<ProbeOutcome>, ProbeError> {
        // Upstream XPYC::isValid: size >= 12, the LE u16 marker at offset 2
        // must be 0x0A0D (bytes 0x0D 0x0A), and the LE u16 magic at offset 0
        // must be a known CPython magic value.
        if view.len() < 12 {
            return Ok(None);
        }
        let Ok(marker) = view.read_u16_le(2) else {
            return Ok(None);
        };
        if marker != 0x0A0D {
            return Ok(None);
        }
        let Ok(magic) = view.read_u16_le(0) else {
            return Ok(None);
        };
        if PYC_KNOWN_MAGICS.binary_search(&magic).is_ok() {
            Ok(Some(ProbeOutcome {
                candidate: strong_deferred("PYC"),
            }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::FormatProbe;
    use diec_core::format::FormatStrength;
    use diec_core::input::{ByteRange, ByteSource, ByteView, MemorySource};

    fn view_of<'a>(src: &'a MemorySource<'a>) -> ByteView<'a> {
        ByteView::new(src, ByteRange::new(0, src.len()).unwrap()).unwrap()
    }

    #[test]
    fn dex_matches() {
        let data = b"dex\n035\0extra bytes here";
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = DexProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "DEX");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
    }

    #[test]
    fn dex_other_versions_match() {
        for ver in &["036", "037", "038", "039", "040"] {
            let mut data = vec![0x64, 0x65, 0x78, 0x0A];
            data.extend_from_slice(ver.as_bytes());
            data.push(0);
            data.extend_from_slice(b"more");
            let src = MemorySource::new(&data);
            let view = view_of(&src);
            let probe = DexProbe;
            assert!(probe.probe(&view).unwrap().is_some(), "version {ver}");
        }
    }

    #[test]
    fn dex_bad_version_does_not_match() {
        let data = b"dex\nabc\0extra";
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = DexProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn dex_too_short_does_not_match() {
        let data = b"dex\n";
        let src = MemorySource::new(data);
        let view = view_of(&src);
        let probe = DexProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    /// Build a 24-byte class header with the given minor/major versions.
    fn build_class(minor: u16, major: u16) -> Vec<u8> {
        let mut data = 0xCAFEBABEu32.to_be_bytes().to_vec();
        data.extend_from_slice(&minor.to_be_bytes());
        data.extend_from_slice(&major.to_be_bytes());
        data.resize(24, 0);
        data
    }

    #[test]
    fn java_class_matches() {
        // minor=0, major=52 (Java 8): upstream requires size>=24 and the
        // BE u32 version field > 10.
        let data = build_class(0, 52);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = JavaClassProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "Java Class");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
    }

    #[test]
    fn java_class_low_major_still_matches() {
        // Upstream accepts any version word > 10, so major=44 (below the
        // classic 45 minimum) is still a Java Class.
        let data = build_class(0, 44);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = JavaClassProbe;
        assert!(probe.probe(&view).unwrap().is_some());
    }

    #[test]
    fn java_class_tiny_version_does_not_match() {
        // Mach-O FAT disambiguation: version word <= 10 (e.g. nfat_arch=2).
        let data = build_class(0, 2);
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = JavaClassProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn java_class_under_24_bytes_does_not_match() {
        // Upstream requires at least 24 bytes even though the magic check
        // only reads 8.
        let mut data = 0xCAFEBABEu32.to_be_bytes().to_vec();
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&52u16.to_be_bytes());
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = JavaClassProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn java_class_too_short_does_not_match() {
        let data = 0xCAFEBABEu32.to_be_bytes();
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = JavaClassProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn pyc_matches() {
        // Python 3.7b5 magic 3394 = 0x0D42 -> LE bytes [0x42, 0x0D],
        // marker [0x0D, 0x0A]; upstream requires >= 12 bytes.
        let data = [
            0x42u8, 0x0D, 0x0D, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PycProbe;
        let outcome = probe.probe(&view).unwrap().unwrap();
        assert_eq!(outcome.candidate.file_type.name, "PYC");
        assert_eq!(outcome.candidate.strength, FormatStrength::Strong);
    }

    #[test]
    fn pyc_no_crlf_does_not_match() {
        let data = [0x42u8, 0x0D, 0x0A, 0x0D];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PycProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn pyc_unknown_magic_does_not_match() {
        // bytes [0x00, 0x01, 0x0D, 0x0A]: marker ok but magic 0x0100 is not
        // in the known CPython table (upstream XPYC::_isMagicKnown).
        let data = [
            0x00u8, 0x01, 0x0D, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PycProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn pyc_pcapng_does_not_match() {
        // PCAPNG section header [0x0A 0x0D 0x0D 0x0A]: marker at offset 2 is
        // 0x0D0D not 0x0A0D, so upstream rejects it as PYC.
        let data = [
            0x0Au8, 0x0D, 0x0D, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PycProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn pyc_zero_magic_does_not_match() {
        let data = [0x00u8, 0x00, 0x0D, 0x0A];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PycProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }

    #[test]
    fn pyc_too_short_does_not_match() {
        let data = [0x42u8, 0x0D, 0x0D];
        let src = MemorySource::new(&data);
        let view = view_of(&src);
        let probe = PycProbe;
        assert!(probe.probe(&view).unwrap().is_none());
    }
}

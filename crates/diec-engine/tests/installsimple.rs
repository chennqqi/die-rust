//! InstallSimple static-unpack regression tests (Phase 50).
//!
//! `corpus/installsimple-minimal.exe` is a synthetic package produced by
//! `tools/gen_installsimple_fixture.py`: a UPX-wrapped decoder stub
//! (DEFLATE payload) whose init/driver entry points carry the upstream
//! `is_load_decoder_image` signatures, plus a two-record overlay
//! (payload + manifest). The same file was verified end to end against
//! the upstream oracle (`xemulator-oracle unpack`); the reference
//! report is stored in `corpus/installsimple-minimal.oracle.json`.

use diec_engine::unpack::{self, UnpackError};

const FIXTURE: &[u8] = include_bytes!("../../../corpus/installsimple-minimal.exe");

/// Payload bytes baked into the fixture by the generator.
const EXPECTED_PAYLOAD: &[u8] = b"synthetic installsimple payload\n";

fn expected_payload() -> Vec<u8> {
    EXPECTED_PAYLOAD.repeat(5)
}

#[test]
fn detect_reports_352() {
    let info = unpack::detect_installsimple(FIXTURE).expect("detect failed");
    assert_eq!(info.sversion, "3.5.2");
}

#[test]
fn extract_yields_manifest_named_payload() {
    let records = unpack::extract_installsimple(FIXTURE, -1).expect("extract failed");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].name, "payload.bin");
    assert_eq!(records[0].data, expected_payload());
}

#[test]
fn oracle_report_matches() {
    // The oracle report (upstream XInstallSimple + XEmulator + XUPX)
    // lists exactly one member "payload.bin", 160 bytes, fnv64
    // ef20e706fcab011b — the same FNV-1a computed here over the record.
    let records = unpack::extract_installsimple(FIXTURE, -1).expect("extract failed");
    let data = &records[0].data;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    assert_eq!(h, 0xef20_e706_fcab_011b);
    assert_eq!(records[0].name, "payload.bin");
    assert_eq!(data.len(), 160);
}

#[test]
fn wrong_entry_point_rejected() {
    // AEP marker drives the 3.5.2/3.5 version split; any other value
    // is not InstallSimple. Entry point lives at opt+16; locate it.
    let mut data = FIXTURE.to_vec();
    let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    let opt = e_lfanew + 4 + 20;
    data[opt + 16..opt + 20].copy_from_slice(&0xE831u32.to_le_bytes());
    assert!(unpack::detect_installsimple(&data).is_none());
}

#[test]
fn renamed_section_rejected() {
    // The UPX0/UPX1/.rsrc triplet is required verbatim.
    for (i, name) in [b"UPX0".as_slice(), b"UPX1".as_slice(), b".rsrc".as_slice()]
        .iter()
        .enumerate()
    {
        let mut data = FIXTURE.to_vec();
        let needle = data
            .windows(name.len())
            .position(|w| w == *name)
            .unwrap_or_else(|| panic!("section {i} name not found"));
        data[needle] = b'X';
        assert!(
            unpack::detect_installsimple(&data).is_none(),
            "mutated section {i} still detected"
        );
    }
}

#[test]
fn corrupted_record_marker_rejected() {
    // Overlay begins after the last raw section; the first record's
    // +4 dword must be 0xFFFFFFFF.
    let overlay = overlay_offset(FIXTURE);
    let mut data = FIXTURE.to_vec();
    data[overlay + 4] = 0x00;
    assert!(unpack::detect_installsimple(&data).is_none());
}

#[test]
fn truncated_overlay_fails_closed() {
    // Cutting the file inside the manifest record must fail rather than
    // publish partial output.
    let overlay = overlay_offset(FIXTURE);
    let data = &FIXTURE[..overlay + 32];
    assert!(unpack::extract_installsimple(data, -1).is_err());
}

#[test]
fn bad_manifest_member_name_rejected() {
    // '?' is a forbidden filename character; manifest parsing must fail.
    let mut data = FIXTURE.to_vec();
    let pos = data
        .windows(b"payload.bin".len())
        .position(|w| w == b"payload.bin")
        .unwrap();
    data[pos] = b'?';
    assert!(matches!(
        unpack::extract_installsimple(&data, -1),
        Err(UnpackError::Malformed(_))
    ));
}

#[test]
fn archive_probe_reaches_installsimple() {
    // The archive container chain must expose the fixture as
    // INSTALLSIMPLE with one member.
    let (kind, members) =
        diec_engine::list_archive_members(FIXTURE).expect("archive listing failed");
    assert_eq!(kind.display_name(), "INSTALLSIMPLE");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].name, "payload.bin");
    assert_eq!(members[0].size, 160);
}

/// File offset where the overlay starts (end of the last raw section).
fn overlay_offset(data: &[u8]) -> usize {
    let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    let nsec = u16::from_le_bytes(data[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;
    let sect = e_lfanew + 4 + 20 + 0xE0;
    (0..nsec)
        .map(|i| {
            let sh = sect + i * 40;
            let raw_size = u32::from_le_bytes(data[sh + 16..sh + 20].try_into().unwrap()) as usize;
            let raw_ptr = u32::from_le_bytes(data[sh + 20..sh + 24].try_into().unwrap()) as usize;
            raw_ptr + raw_size
        })
        .max()
        .unwrap()
}

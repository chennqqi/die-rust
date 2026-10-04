//! InstallSimple 3.5/3.5.2 installer unpacker — port of upstream
//! `XStaticUnpacker/xinstallsimple.cpp` (`USE_XEMULATOR` only upstream;
//! this module exists because the `emulate` x86 core provides it).
//!
//! A package is a UPX-packed MASM32 host plus an overlay of range-coded
//! records. The stub's in-image decoder is run under the bounded x86
//! core: `is_load_decoder_image` maps it at 0x400000 with the upstream
//! init/driver signature check, `is_call_decoder` drives the two
//! entry points through the shared `IS_MAX_EMULATOR_STEPS` budget and
//! services the decoder's single stdcall allocator callback, and
//! `is_decode_stream` decodes one record per guest invocation until the
//! strict manifest grammar closes the archive.
//!
//! Upstream's Qt-device/lifetime/cancellation machinery (`PDSTRUCT`,
//! `LIFETIME_STATE`, `XMaterializedUnpackGuard`) has no analogue in the
//! library API; every upstream fail-closed bound that is not GUI state
//! is reproduced.

use super::PackedPe;
use super::autoit::ContainerRecord;
use super::upx::UnpackError;
use crate::emulate::regs::{GPR_RAX, GPR_RSP};
use crate::emulate::{MemoryFlags, MemoryManager, Registers, StepResult, X86};

const IS_IMAGE_BASE: u32 = 0x0040_0000;
const IS_INIT: u32 = 0x0040_1000;
const IS_DRIVER: u32 = 0x0040_1090;
const IS_TRAP: u32 = 0x0070_0000;
const IS_RETURN_TRAP: u32 = IS_TRAP + 0x100;
const IS_OUTER: u32 = 0x0090_0000;
const IS_HEAP: u32 = 0x0100_0000;
const IS_HEAP_SIZE: u32 = 0x0200_0000;
const IS_INPUT: u32 = 0x0400_0000;
const IS_OUTPUT: u32 = 0x0800_0000;
const IS_OUTPUT_SIZE: u32 = 0x0400_0000;
const IS_STACK: u32 = 0x0030_0000;
const IS_STACK_SIZE: u32 = 0x0010_0000;
const IS_MAX_EMULATOR_STEPS: u64 = 100_000_000;
const IS_CANCEL_CHECK_STEPS: u64 = 100_000;
const IS_MAX_RECORD_COUNT: usize = 1024;
const IS_MAX_PAYLOAD_COUNT: usize = 1023;
const IS_MAX_TOTAL_DECODED_SIZE: u64 = 256 * 1024 * 1024;
const IS_MAX_PACKED_STUB_SIZE: u64 = 64 * 1024 * 1024;
const IS_MAX_UNPACKED_STUB_SIZE: usize = 32 * 1024 * 1024;
const IS_MAX_ENCODED_ARCHIVE_SIZE: u64 = 256 * 1024 * 1024;
const IS_MAX_ENCODED_RECORD_SIZE: i64 = IS_OUTPUT as i64 - IS_INPUT as i64;

/// Little-endian dword read, 0 on short input (upstream `isRd32` is
/// only called on bounded slices).
fn is_rd32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

/// `isInstallerDataEnd` — the authenticode certificate table, when it
/// is the file tail, bounds the installer's data area.
fn installer_data_end(pe: &PackedPe, file_size: u64) -> i64 {
    let (offset, size) = pe.sign_offset_size();
    if offset > 0 && size > 0 && offset <= file_size && size == file_size - offset {
        return offset as i64;
    }
    file_size as i64
}

/// `isMap` — page-aligned fixed map, always rw (+x when `exec`).
fn is_map(memory: &mut MemoryManager, address: u32, size: u64, exec: bool, name: &str) -> bool {
    if size == 0 {
        return false;
    }
    let size = MemoryManager::align_up(size, crate::emulate::memory::PAGE_SIZE);
    memory.map_fixed(
        u64::from(address),
        size,
        MemoryFlags::new(true, true, exec, false),
        name,
    )
}

/// `isLoadDecoderImage` — map the UPX-unpacked decoder stub and refuse
/// unknown images via the shared init/driver prologue signatures.
fn is_load_decoder_image(stub: &[u8], memory: &mut MemoryManager) -> bool {
    let Ok(pe) = PackedPe::parse(stub) else {
        return false;
    };
    if pe.is64() || pe.image_base() != u64::from(IS_IMAGE_BASE) {
        return false;
    }

    let image_size = pe.size_of_image();
    if !(0xB000..=0x0100_0000).contains(&image_size)
        || !is_map(
            memory,
            IS_IMAGE_BASE,
            u64::from(image_size),
            true,
            "InstallSimple stub",
        )
    {
        return false;
    }

    for s in pe.sections() {
        let raw_offset = u64::from(s.raw_ptr);
        let raw_size = u64::from(s.raw_size);
        let virtual_address = u64::from(s.virtual_address);
        if raw_size == 0 {
            continue;
        }
        if raw_offset + raw_size > stub.len() as u64
            || virtual_address + raw_size > u64::from(image_size)
        {
            return false;
        }
        let raw = &stub[raw_offset as usize..(raw_offset + raw_size) as usize];
        if !memory.write(u64::from(IS_IMAGE_BASE) + virtual_address, raw) {
            return false;
        }
    }

    // Both supported builders share this decoder. Refuse to execute an
    // unknown stub even though the VM is sandboxed and step-budgeted.
    const INIT_SIG: &[u8] = b"\x53\x55\x56\x57\x8b\x74\x24\x14\x33\xd2\x8b\x6c\x24\x18\x8b\x46";
    const DRIVER_SIG: &[u8] = b"\x8b\x44\x24\x04\x56\x8b\x70\x20\x85\xf6\x75\x09\xb8\xfe\xff\xff";
    memory
        .read(u64::from(IS_INIT), INIT_SIG.len() as u64)
        .as_deref()
        == Some(INIT_SIG)
        && memory
            .read(u64::from(IS_DRIVER), DRIVER_SIG.len() as u64)
            .as_deref()
            == Some(DRIVER_SIG)
}

/// `isCallDecoder` — stdcall call into the guest: push `args`
/// right-to-left plus the `hlt` return trap, then run the shared step
/// budget until either the return trap or the allocator trap at
/// `IS_TRAP` is hit. The allocator implements the decoder's sole
/// `alloc(ctx, size, flag)` callback over the zero-filled heap region.
fn is_call_decoder(
    arch: &mut X86,
    registers: &mut Registers,
    function: u32,
    args: &[u32],
    heap_next: &mut u32,
    result: &mut u32,
    steps_remaining: &mut u64,
) -> bool {
    let mut stack = IS_STACK + IS_STACK_SIZE - 0x1000;
    for arg in args.iter().rev() {
        stack = stack.wrapping_sub(4);
        if !arch.memory_mut().write_u32(u64::from(stack), *arg) {
            return false;
        }
    }
    stack -= 4;
    if !arch
        .memory_mut()
        .write_u32(u64::from(stack), IS_RETURN_TRAP)
    {
        return false;
    }

    registers.set_gpr(GPR_RSP, 4, u64::from(stack));
    registers.rip = u64::from(function);

    let mut stop = crate::emulate::StepInfo::default();
    while *steps_remaining > 0 {
        // Upstream checks PDSTRUCT cancellation at this granularity;
        // the shared budget itself already bounds untrusted stub code.
        let chunk = (*steps_remaining).min(IS_CANCEL_CHECK_STEPS) as i64;
        let ran = arch.run(registers, chunk, &mut stop);
        if ran <= 0 || ran > chunk {
            return false;
        }
        *steps_remaining -= ran as u64;

        // STEP_OK means the bounded run slice completed normally;
        // continue with the same register state.
        if stop.result == StepResult::Ok {
            if ran != chunk {
                return false;
            }
            continue;
        }
        if stop.result != StepResult::Halt
            || (stop.address != u64::from(IS_TRAP) && stop.address != u64::from(IS_RETURN_TRAP))
        {
            return false;
        }

        if stop.address == u64::from(IS_RETURN_TRAP) {
            *result = registers.get_gpr(GPR_RAX, 4) as u32;
            return true;
        }

        // The decoder's sole callback is stdcall allocator(ctx,size,flag).
        // MemoryManager mappings are zero-filled, matching
        // HeapAlloc(HEAP_ZERO_MEMORY).
        let esp = registers.get_gpr(GPR_RSP, 4) as u32;
        let Some(ret) = arch.memory().read_u32(u64::from(esp)) else {
            return false;
        };
        let Some(allocation_size) = arch.memory().read_u32(u64::from(esp) + 8) else {
            return false;
        };
        if allocation_size == 0 {
            return false;
        }

        let allocation_end =
            u64::from(*heap_next) + MemoryManager::align_up(u64::from(allocation_size), 16) + 16;
        if allocation_end > u64::from(IS_HEAP) + u64::from(IS_HEAP_SIZE) {
            return false;
        }

        let allocation = *heap_next;
        *heap_next = allocation_end as u32;
        registers.set_gpr(GPR_RAX, 4, u64::from(allocation));
        registers.set_gpr(GPR_RSP, 4, u64::from(esp) + 16);
        registers.rip = u64::from(ret);
    }
    false
}

/// `isDecodeStream` — decode one range-coded record through the stub's
/// guest decoder. Reports `(decoded, used_exhaustion_fallback)`.
fn is_decode_stream(
    stub: &[u8],
    stream: &[u8],
    steps_remaining: &mut u64,
) -> Option<(Vec<u8>, bool)> {
    if stream.len() < 12 || stream.len() > 0x1000_0000 {
        return None;
    }

    let mut memory = MemoryManager::new();
    memory.set_bits(32);
    if !is_load_decoder_image(stub, &mut memory)
        || !is_map(
            &mut memory,
            IS_STACK,
            u64::from(IS_STACK_SIZE),
            false,
            "InstallSimple stack",
        )
        || !is_map(&mut memory, IS_TRAP, 0x1000, true, "InstallSimple traps")
        || !is_map(
            &mut memory,
            IS_OUTER,
            0x1000,
            false,
            "InstallSimple context",
        )
        || !is_map(
            &mut memory,
            IS_HEAP,
            u64::from(IS_HEAP_SIZE),
            false,
            "InstallSimple heap",
        )
        || !is_map(
            &mut memory,
            IS_INPUT,
            stream.len() as u64,
            false,
            "InstallSimple input",
        )
        || !is_map(
            &mut memory,
            IS_OUTPUT,
            u64::from(IS_OUTPUT_SIZE),
            false,
            "InstallSimple output",
        )
    {
        return None;
    }

    if !memory.write_u8(u64::from(IS_TRAP), 0xF4)
        || !memory.write_u8(u64::from(IS_RETURN_TRAP), 0xF4)
        || !memory.write(u64::from(IS_INPUT), stream)
    {
        return None;
    }
    for (off, v) in [
        (0x00u64, IS_INPUT),
        (0x04, stream.len() as u32),
        (0x10, IS_OUTPUT),
        (0x14, IS_OUTPUT_SIZE),
        (0x24, IS_TRAP),
    ] {
        if !memory.write_u32(u64::from(IS_OUTER) + off, v) {
            return None;
        }
    }

    let mut registers = Registers::default();
    let mut heap_next = IS_HEAP + 0x1000;
    let mut result = 0u32;
    let mut arch = X86::new(&mut memory, 32);

    if !is_call_decoder(
        &mut arch,
        &mut registers,
        IS_INIT,
        &[IS_OUTER, 0, 0],
        &mut heap_next,
        &mut result,
        steps_remaining,
    ) {
        return None;
    }

    let mut finished = false;
    let mut used_exhaustion_fallback = false;
    let mut previous_total = 0xFFFF_FFFFu32;
    for _ in 0..500 {
        if !is_call_decoder(
            &mut arch,
            &mut registers,
            IS_DRIVER,
            &[IS_OUTER],
            &mut heap_next,
            &mut result,
            steps_remaining,
        ) {
            return None;
        }

        let remaining = arch.memory().read_u32(u64::from(IS_OUTER) + 0x04)?;
        let total = arch.memory().read_u32(u64::from(IS_OUTER) + 0x18)?;
        if total > IS_OUTPUT_SIZE {
            return None;
        }

        // The decoder returns -1 only for the authenticated end marker;
        // other negative statuses are malformed-stream errors.
        if result == 0xFFFF_FFFF {
            finished = true;
            break;
        }
        if matches!(result, 0xFFFF_FFFC..=0xFFFF_FFFE) {
            return None;
        }
        if remaining == 0 && total == previous_total {
            // A few manifest/config records exhaust their range-coded
            // input without returning the normal -1 marker; accepted
            // only after the manifest grammar check in the caller.
            finished = true;
            used_exhaustion_fallback = true;
            break;
        }
        previous_total = total;
    }

    let remaining = arch.memory().read_u32(u64::from(IS_OUTER) + 0x04)?;
    let total = arch.memory().read_u32(u64::from(IS_OUTER) + 0x18)?;
    let overflow = arch.memory().read_u32(u64::from(IS_OUTER) + 0x1C)?;
    // A valid range-coded record consumes all input or leaves at most
    // 15 framing/padding bytes; more remaining input means an
    // authenticated prefix was followed by unvalidated data.
    if !finished
        || remaining > 15
        || (used_exhaustion_fallback && remaining != 0)
        || overflow != 0
        || total > IS_OUTPUT_SIZE
    {
        return None;
    }

    let output = arch.memory().read(u64::from(IS_OUTPUT), u64::from(total))?;
    if output.len() != total as usize {
        return None;
    }
    Some((output, used_exhaustion_fallback))
}

/// `isParseManifest` — strict manifest grammar: 19 leading zero bytes,
/// the `InstallSimple\0\0` marker, then `payload_count` NUL-terminated
/// ASCII names each followed by a ten-byte descriptor. Names must be
/// printable, non-reserved, unique (casefolded) relative paths.
fn is_parse_manifest(data: &[u8], payload_count: usize) -> Option<Vec<String>> {
    if payload_count == 0 || data.len() < 32 {
        return None;
    }
    if data[..19].iter().any(|&b| b != 0) {
        return None;
    }

    const MARKER: &[u8] = b"InstallSimple\0\0";
    let position = data.windows(MARKER.len()).position(|w| w == MARKER)?;
    if position < 19 {
        return None;
    }
    let mut position = position + MARKER.len();

    const FORBIDDEN: &[u8] = b"<>:\"/\\|?*";
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$",
        "CONOUT$", "CLOCK$",
    ];
    let mut names: Vec<String> = Vec::with_capacity(payload_count);
    let mut seen = std::collections::HashSet::new();

    for _ in 0..payload_count {
        let end = data[position..].iter().position(|&b| b == 0)? + position;
        if end <= position || end - position > 255 {
            return None;
        }
        let raw_name = &data[position..end];
        if raw_name.iter().any(|&c| !(0x20..=0x7E).contains(&c)) {
            return None;
        }
        let name = String::from_utf8_lossy(raw_name).into_owned();
        if name == "."
            || name == ".."
            || name.ends_with(' ')
            || name.ends_with('.')
            || raw_name.iter().any(|c| FORBIDDEN.contains(c))
        {
            return None;
        }
        // Upstream upper-cases the stem and maps the superscript digits
        // (¹²³ cannot appear — input is restricted to ASCII 0x20-0x7E).
        let stem = name.split('.').next().unwrap_or("").to_uppercase();
        let key = name.to_lowercase();
        if RESERVED.contains(&stem.as_str()) || !seen.insert(key) {
            return None;
        }
        names.push(name);

        // Each file name is followed by a fixed ten-byte descriptor.
        position = end + 1;
        if position + 10 > data.len() {
            return None;
        }
        position += 10;
    }

    (names.len() == payload_count).then_some(names)
}

/// Detection metadata for an InstallSimple package.
#[derive(Debug, Clone)]
pub struct InstallSimpleInfo {
    /// Upstream version string ("3.5.2" or "3.5").
    pub sversion: &'static str,
}

/// `XInstallSimple::_detect` — overlay offset + AEP version + the
/// UPX0/UPX1/.rsrc section layout + two independently-coded records.
pub fn detect_installsimple(data: &[u8]) -> Option<InstallSimpleInfo> {
    let pe = PackedPe::parse(data).ok()?;
    let overlay_offset = pe.overlay_offset() as i64;
    let data_end = installer_data_end(&pe, data.len() as u64);
    if overlay_offset <= 0 || overlay_offset >= data_end {
        return None;
    }

    let aep = pe.entry_rva();
    let sversion = match aep {
        0xE830 => "3.5.2",
        0xE860 => "3.5",
        _ => return None,
    };

    // UPX-packed stub layout.
    let sections = pe.sections();
    if sections.len() != 3 {
        return None;
    }
    const NAMES: [&[u8]; 3] = [b"UPX0", b"UPX1", b".rsrc"];
    for (i, s) in sections.iter().enumerate() {
        let name = s
            .name
            .split(|&b| b == 0)
            .next()
            .unwrap_or(s.name.as_slice());
        if name != NAMES[i] {
            return None;
        }
    }

    // Validate two independently-coded records. Every valid package
    // contains at least one payload record followed by its manifest (or
    // another payload and then the manifest).
    let first = data.get(overlay_offset as usize..overlay_offset as usize + 12)?;
    let first_length = is_rd32(first, 0);
    if is_rd32(first, 4) != 0xFFFF_FFFF
        || first_length < 12
        || i64::from(first_length) - 6 > IS_MAX_ENCODED_RECORD_SIZE - 6
    {
        return None;
    }

    let second_offset = overlay_offset + i64::from(first_length) - 6;
    if second_offset > data_end - 12 || second_offset <= overlay_offset {
        return None;
    }
    let second = data.get(second_offset as usize..second_offset as usize + 12)?;
    if second.len() != 12 || is_rd32(second, 4) != 0xFFFF_FFFF {
        return None;
    }
    let second_length = is_rd32(second, 0);
    if second_length < 12
        || i64::from(second_length) - 6 > IS_MAX_ENCODED_RECORD_SIZE - 6
        || i64::from(second_length) - 6 > data_end - second_offset
    {
        return None;
    }

    Some(InstallSimpleInfo { sversion })
}

/// `XInstallSimple::initUnpack` + member enumeration — UPX-unpacks the
/// fixed host stub, then decodes each overlay record under emulation
/// until the manifest record closes the archive. Returns payload
/// records in archive order. `output_limit < 0` = unlimited;
/// upstream's 256 MiB total-decoded bound applies regardless.
pub fn extract_installsimple(
    data: &[u8],
    output_limit: i64,
) -> Result<Vec<ContainerRecord>, UnpackError> {
    detect_installsimple(data).ok_or(UnpackError::NotPacked)?;

    let pe = PackedPe::parse(data).map_err(|_| UnpackError::NotPacked)?;
    let overlay_offset = pe.overlay_offset() as i64;
    let data_end = installer_data_end(&pe, data.len() as u64);
    let overlay_size = data_end - overlay_offset;
    if overlay_offset <= 0
        || overlay_offset as u64 > IS_MAX_PACKED_STUB_SIZE
        || overlay_size < 12
        || overlay_size as u64 > IS_MAX_ENCODED_ARCHIVE_SIZE
    {
        return Err(UnpackError::Malformed("installsimple: overlay"));
    }

    // Reconstruct only the fixed MASM32 host image. Passing the whole
    // installer to the UPX unpacker would duplicate the
    // attacker-controlled overlay before the archive-size checks run.
    let stub_data = &data[..overlay_offset as usize];
    let upx_info = super::upx::detect_upx(stub_data)
        .ok_or(UnpackError::Malformed("installsimple: stub detection"))?;
    if upx_info.u_len as usize > IS_MAX_UNPACKED_STUB_SIZE
        || upx_info.u_file_size as usize > IS_MAX_UNPACKED_STUB_SIZE
    {
        return Err(UnpackError::Malformed("installsimple: stub size"));
    }
    let stub = super::upx::unpack_pe(stub_data, &upx_info)
        .map_err(|_| UnpackError::Malformed("installsimple: stub unpack"))?;
    if stub.is_empty() || stub.len() > IS_MAX_UNPACKED_STUB_SIZE {
        return Err(UnpackError::Malformed("installsimple: stub bounds"));
    }

    let overlay = &data[overlay_offset as usize..data_end as usize];

    let mut payloads: Vec<Vec<u8>> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut manifest_found = false;
    let mut position = 0usize;
    let mut steps_remaining = IS_MAX_EMULATOR_STEPS;
    let mut total_decoded = 0u64;

    for _ in 0..IS_MAX_RECORD_COUNT {
        if position + 12 > overlay.len() {
            break;
        }
        let record = &overlay[position..];
        let length = is_rd32(record, 0);
        if is_rd32(record, 4) != 0xFFFF_FFFF {
            break;
        }
        if length < 12 {
            return Err(UnpackError::Malformed("installsimple: record length"));
        }

        let body_size = i64::from(length) - 6;
        if body_size <= 0
            || body_size > IS_MAX_ENCODED_RECORD_SIZE - 6
            || body_size > overlay.len() as i64 - position as i64
        {
            return Err(UnpackError::Malformed("installsimple: record bounds"));
        }

        // The loader allocates a zeroed buffer and reads the on-disk
        // record at +6: the length dword is part of the coded stream.
        let mut stream = vec![0u8; 6];
        stream.extend_from_slice(&record[..body_size as usize]);

        let Some((decoded, used_exhaustion_fallback)) =
            is_decode_stream(&stub, &stream, &mut steps_remaining)
        else {
            return Err(UnpackError::Decompress(
                "installsimple: decoder emulation".into(),
            ));
        };
        if decoded.len() as u64 > IS_MAX_TOTAL_DECODED_SIZE - total_decoded {
            return Err(UnpackError::Malformed("installsimple: decoded cap"));
        }
        total_decoded += decoded.len() as u64;

        if let Some(manifest_names) = is_parse_manifest(&decoded, payloads.len()) {
            names = manifest_names;
            manifest_found = true;
            break; // generated uninstaller/runtime records follow on v3.5
        }
        if used_exhaustion_fallback {
            return Err(UnpackError::Malformed("installsimple: exhaustion fallback"));
        }
        if payloads.len() >= IS_MAX_PAYLOAD_COUNT {
            return Err(UnpackError::Malformed("installsimple: payload cap"));
        }
        if output_limit >= 0 && total_decoded > output_limit as u64 {
            return Err(UnpackError::Malformed("installsimple: output limit"));
        }
        payloads.push(decoded);
        position += body_size as usize;
    }

    if !manifest_found || payloads.is_empty() || payloads.len() != names.len() {
        return Err(UnpackError::Malformed("installsimple: manifest"));
    }

    Ok(names
        .into_iter()
        .zip(payloads)
        .map(|(name, data)| ContainerRecord { name, data })
        .collect())
}

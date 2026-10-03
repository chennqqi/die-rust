//! Disassembler backend for die-gui.
//!
//! Uses `iced-x86` (pure Rust) for x86/x64 and `yaxpeax-arm` (pure Rust)
//! for ARM/ARM64. Supports Intel, AT&T, and NASM syntax for x86/x64.
//! Does NOT break on Ret/Retf — disassembles the full requested range.

use iced_x86::{
    Decoder as IcedDecoder, DecoderOptions, FlowControl, Formatter, GasFormatter, IntelFormatter,
    NasmFormatter,
};
use serde::{Deserialize, Serialize};

/// Disassembly syntax format (x86/x64 only).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Syntax {
    /// Intel syntax (default).
    Intel,
    /// AT&T syntax (GNU assembler).
    Gas,
    /// NASM syntax.
    Nasm,
}

/// Disassembly architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    /// x86 32-bit.
    X86,
    /// x86-64 64-bit.
    X64,
    /// ARM 32-bit (Thumb/ARM).
    Arm,
    /// ARM64/AArch64.
    Arm64,
    /// MIPS32 little-endian (upstream `DM_MIPS_LE`).
    Mips32le,
    /// MIPS32 big-endian (upstream `DM_MIPS_BE`).
    Mips32be,
    /// MIPS64 little-endian (upstream `DM_MIPS64_LE`).
    Mips64le,
    /// MIPS64 big-endian (upstream `DM_MIPS64_BE`).
    Mips64be,
    /// PowerPC 32-bit little-endian (upstream `DM_PPC_LE`).
    Ppc32le,
    /// PowerPC 32-bit big-endian (upstream `DM_PPC_BE`).
    Ppc32be,
    /// PowerPC 64-bit little-endian (upstream `DM_PPC64_LE`).
    Ppc64le,
    /// PowerPC 64-bit big-endian (upstream `DM_PPC64_BE`).
    Ppc64be,
    /// RISC-V 32-bit (upstream `DM_RISKV32`).
    Riscv32,
    /// RISC-V 64-bit (upstream `DM_RISKV64`).
    Riscv64,
    /// RISC-V compressed instructions (upstream `DM_RISKVC`).
    Riscvc,
    /// ARM big-endian (upstream `DM_ARM_BE`).
    ArmBe,
    /// AArch64 little-endian (upstream `DM_AARCH64_LE`).
    AArch64Le,
    /// AArch64 big-endian (upstream `DM_AARCH64_BE`).
    AArch64Be,
    /// ARM Cortex-M (upstream `DM_CORTEXM`, ARM|THUMB|MCLASS).
    CortexM,
    /// ARM Thumb little-endian (upstream `DM_THUMB_LE`).
    ThumbLe,
    /// ARM Thumb big-endian (upstream `DM_THUMB_BE`).
    ThumbBe,
    /// SPARC (upstream `DM_SPARC`).
    Sparc,
    /// SPARC V9 (upstream `DM_SPARCV9`).
    SparcV9,
    /// SystemZ / s390x (upstream `DM_S390X`).
    S390x,
    /// XCORE (upstream `DM_XCORE`).
    Xcore,
    /// M68K generic 680x0 (upstream `DM_M68K`).
    M68k,
    /// M68K 68000 (upstream `DM_M68K00`).
    M68k00,
    /// M68K 68010 (upstream `DM_M68K10`).
    M68k10,
    /// M68K 68020 (upstream `DM_M68K20`).
    M68k20,
    /// M68K 68030 (upstream `DM_M68K30`).
    M68k30,
    /// M68K 68040 (upstream `DM_M68K40`).
    M68k40,
    /// M68K 68060 (upstream `DM_M68K60`).
    M68k60,
    /// TMS320C64X (upstream `DM_TMS320C64X`).
    Tms320c64x,
    /// M6800 (upstream `DM_M6800`).
    M6800,
    /// M6801 (upstream `DM_M6801`).
    M6801,
    /// M6805 (upstream `DM_M6805`).
    M6805,
    /// M6808 (upstream `DM_M6808`).
    M6808,
    /// M6809 (upstream `DM_M6809`).
    M6809,
    /// M6811 (upstream `DM_M6811`).
    M6811,
    /// CPU12 (upstream `DM_CPU12`).
    Cpu12,
    /// HD6301 (upstream `DM_HD6301`).
    Hd6301,
    /// HD6309 (upstream `DM_HD6309`).
    Hd6309,
    /// HCS08 (upstream `DM_HCS08`).
    Hcs08,
    /// Ethereum VM bytecode (upstream `DM_EVM`).
    Evm,
    /// MOS65XX family (upstream `DM_MOS65XX`).
    Mos65xx,
    /// WebAssembly bytecode (upstream `DM_WASM`).
    Wasm,
    /// eBPF little-endian (upstream `DM_BPF_LE`).
    BpfLe,
    /// eBPF big-endian (upstream `DM_BPF_BE`).
    BpfBe,
}

impl Arch {
    /// Get the bitness for this architecture.
    ///
    /// Mirrors upstream `XBinary::getModeFromDisasmMode`: MODE_64 only
    /// for DM_X86_64 / DM_AARCH64_* / DM_MIPS64_*; every other DM —
    /// including PPC64 and RISCV64 — yields MODE_32 (upstream quirk
    /// preserved verbatim). Only consumed by the x86 path today.
    fn bitness(&self) -> u32 {
        match self {
            Arch::X64
            | Arch::Arm64
            | Arch::AArch64Le
            | Arch::AArch64Be
            | Arch::Mips64le
            | Arch::Mips64be => 64,
            _ => 32,
        }
    }

    /// Whether this architecture is decoded through the capstone backend.
    /// Everything except the four yaxpeax/iced-x86 variants is capstone.
    fn is_capstone(&self) -> bool {
        !matches!(self, Arch::X86 | Arch::X64 | Arch::Arm | Arch::Arm64)
    }
}

/// A single disassembled instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// Instruction address (hex string).
    pub address: String,
    /// Instruction bytes as hex string.
    pub bytes: String,
    /// Disassembled instruction text (mnemonic + operands).
    pub mnemonic: String,
    /// Optional label for this instruction (e.g. function name or jump target).
    pub label: Option<String>,
    /// Optional comment for this instruction (e.g. "; jump to 0x401000").
    pub comment: Option<String>,
    /// Optional jump/call target address (hex string), if this instruction
    /// is a branch.
    pub jump_target: Option<String>,
}

/// Disassembly response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    /// Starting address.
    pub start_address: u64,
    /// Number of instructions decoded.
    pub instruction_count: usize,
    /// Disassembled instructions.
    pub instructions: Vec<Instruction>,
}

/// Disassemble a byte range from a file.
///
/// Reads `max_bytes` bytes at `offset` and disassembles them using
/// the specified architecture and syntax. Does NOT break on Ret —
/// the full range is disassembled.
pub fn disassemble_file(
    path: &str,
    offset: u64,
    max_bytes: usize,
    arch: Arch,
    syntax: Syntax,
) -> Result<DisassemblyResult, String> {
    let bytes = read_file_range(path, offset, max_bytes)?;
    disassemble_bytes(&bytes, offset, arch, syntax)
}

/// Disassemble raw bytes.
///
/// Disassembles the full `data` buffer without breaking on Ret/Retf.
/// The architecture determines which disassembler engine is used:
/// - X86/X64: iced-x86
/// - Arm/Arm64: yaxpeax-arm
/// - MIPS/PowerPC/RISC-V: capstone (same engine family as upstream
///   XCapstone; mode flags mirror `XCapstone::openHandle`)
pub fn disassemble_bytes(
    data: &[u8],
    base_address: u64,
    arch: Arch,
    syntax: Syntax,
) -> Result<DisassemblyResult, String> {
    match arch {
        Arch::X86 | Arch::X64 => disassemble_x86(data, base_address, arch.bitness(), syntax),
        Arch::Arm => disassemble_arm(data, base_address),
        Arch::Arm64 => disassemble_arm64(data, base_address),
        a if a.is_capstone() => disassemble_capstone(data, base_address, a),
        // `Arch` is exhaustive above; unreachable, kept as a fail-closed
        // guard if a new variant forgets its backend wiring.
        #[allow(unreachable_patterns)]
        _ => Err("unsupported disassembly architecture".to_string()),
    }
}

/// Disassemble x86/x64 code using iced-x86.
fn disassemble_x86(
    data: &[u8],
    base_address: u64,
    bitness: u32,
    syntax: Syntax,
) -> Result<DisassemblyResult, String> {
    let options = DecoderOptions::NONE;
    let mut decoder = IcedDecoder::with_ip(bitness, data, base_address, options);

    let mut all_instrs: Vec<iced_x86::Instruction> = decoder.iter().collect();

    // Collect all jump/call targets for label generation.
    let mut jump_targets: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for instr in &all_instrs {
        let fc = instr.flow_control();
        if matches!(
            fc,
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::Call
        ) {
            let target = instr.near_branch_target();
            if target >= base_address && target < base_address + data.len() as u64 {
                jump_targets.insert(target);
            }
        }
    }

    let mut instructions = Vec::new();
    let mut intel_buf = String::new();
    let mut gas_buf = String::new();
    let mut nasm_buf = String::new();

    for instr in &mut all_instrs {
        let address = format!("{:016X}", instr.ip());
        let byte_len = instr.len();
        let byte_start = (instr.ip() - base_address) as usize;
        if byte_start + byte_len > data.len() {
            break;
        }
        let bytes = &data[byte_start..byte_start + byte_len];
        let bytes_hex: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();

        let mnemonic_str = match syntax {
            Syntax::Intel => {
                let mut fmt = IntelFormatter::new();
                fmt.format(instr, &mut intel_buf);
                intel_buf.clone()
            }
            Syntax::Gas => {
                let mut fmt = GasFormatter::new();
                fmt.format(instr, &mut gas_buf);
                gas_buf.clone()
            }
            Syntax::Nasm => {
                let mut fmt = NasmFormatter::new();
                fmt.format(instr, &mut nasm_buf);
                nasm_buf.clone()
            }
        };

        // Generate label if this address is a jump target.
        let label = if jump_targets.contains(&instr.ip()) {
            Some(format!("loc_{:X}", instr.ip()))
        } else {
            None
        };

        // Generate comment for branch instructions.
        let fc = instr.flow_control();
        let (comment, jump_target) = match fc {
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                let target = instr.near_branch_target();
                if target > 0 {
                    (
                        Some(format!("; jump to 0x{:X}", target)),
                        Some(format!("{:016X}", target)),
                    )
                } else {
                    (None, None)
                }
            }
            FlowControl::Call => {
                let target = instr.near_branch_target();
                if target > 0 {
                    (
                        Some(format!("; call to 0x{:X}", target)),
                        Some(format!("{:016X}", target)),
                    )
                } else {
                    (None, None)
                }
            }
            _ => (None, None),
        };

        instructions.push(Instruction {
            address,
            bytes: bytes_hex.join(" "),
            mnemonic: mnemonic_str,
            label,
            comment,
            jump_target,
        });
    }

    let count = instructions.len();
    Ok(DisassemblyResult {
        start_address: base_address,
        instruction_count: count,
        instructions,
    })
}

/// Disassemble ARM 32-bit code using yaxpeax-arm.
fn disassemble_arm(data: &[u8], base_address: u64) -> Result<DisassemblyResult, String> {
    use yaxpeax_arch::{Decoder, U8Reader};
    use yaxpeax_arm::armv7::InstDecoder;

    let decoder = InstDecoder::default();
    let mut instructions = Vec::new();
    let mut pos = 0usize;

    while pos < data.len() {
        let address = base_address + pos as u64;
        let remaining = &data[pos..];
        let mut reader = U8Reader::new(remaining);

        match decoder.decode(&mut reader) {
            Ok(instr) => {
                // Determine how many bytes were consumed.
                // yaxpeax-arm ARMv7 instructions are 4 bytes (ARM) or 2/4 bytes (Thumb).
                // We approximate by checking the reader position.
                let consumed = 4.min(remaining.len());
                let bytes_hex: Vec<String> = remaining[..consumed]
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect();
                instructions.push(Instruction {
                    address: format!("{:016X}", address),
                    bytes: bytes_hex.join(" "),
                    mnemonic: format!("{}", instr),
                    label: None,
                    comment: None,
                    jump_target: None,
                });
                pos += consumed;
            }
            Err(_) => {
                // On decode error, skip 1 byte and continue.
                let bytes_hex = format!("{:02X}", data[pos]);
                instructions.push(Instruction {
                    address: format!("{:016X}", address),
                    bytes: bytes_hex,
                    mnemonic: "db".to_string(),
                    label: None,
                    comment: Some("; decode error".to_string()),
                    jump_target: None,
                });
                pos += 1;
            }
        }
    }

    let count = instructions.len();
    Ok(DisassemblyResult {
        start_address: base_address,
        instruction_count: count,
        instructions,
    })
}

/// Disassemble ARM64/AArch64 code using yaxpeax-arm.
fn disassemble_arm64(data: &[u8], base_address: u64) -> Result<DisassemblyResult, String> {
    use yaxpeax_arch::{Decoder, U8Reader};
    use yaxpeax_arm::armv8::a64::InstDecoder as A64Decoder;

    let decoder = A64Decoder::default();
    let mut instructions = Vec::new();
    let mut pos = 0usize;

    while pos < data.len() {
        let address = base_address + pos as u64;
        let remaining = &data[pos..];
        let mut reader = U8Reader::new(remaining);

        match decoder.decode(&mut reader) {
            Ok(instr) => {
                // ARM64 instructions are always 4 bytes.
                let consumed = 4.min(remaining.len());
                let bytes_hex: Vec<String> = remaining[..consumed]
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect();
                instructions.push(Instruction {
                    address: format!("{:016X}", address),
                    bytes: bytes_hex.join(" "),
                    mnemonic: format!("{}", instr),
                    label: None,
                    comment: None,
                    jump_target: None,
                });
                pos += consumed;
            }
            Err(_) => {
                let bytes_hex = format!("{:02X}", data[pos]);
                instructions.push(Instruction {
                    address: format!("{:016X}", address),
                    bytes: bytes_hex,
                    mnemonic: "db".to_string(),
                    label: None,
                    comment: Some("; decode error".to_string()),
                    jump_target: None,
                });
                pos += 1;
            }
        }
    }

    let count = instructions.len();
    Ok(DisassemblyResult {
        start_address: base_address,
        instruction_count: count,
        instructions,
    })
}

/// Disassemble code via capstone — the same engine upstream
/// `XCapstone::openHandle` wraps. Every `(Arch, Mode, ExtraMode,
/// Endian)` triple below mirrors the `cs_open` call for the matching
/// `DM_*` case in upstream `xcapstone.cpp`, bit for bit.
///
/// `new_raw` is used throughout so the cs_mode bitmask is explicit:
/// `Mode::Default` is cs_mode(0), `Endian` contributes
/// `CS_MODE_LITTLE_ENDIAN`(0) or `CS_MODE_BIG_ENDIAN`(1<<31), and
/// `ExtraMode` contributes the remaining mode bits.
fn disassemble_capstone(
    data: &[u8],
    base_address: u64,
    arch: Arch,
) -> Result<DisassemblyResult, String> {
    use capstone::{Arch as CsArch, Capstone, Endian, ExtraMode, Mode};
    use std::iter::empty;

    // DM_WASM is handled by disassemble_wasm: `capstone::Arch` has no
    // WASM variant even though capstone-sys and upstream's vendored
    // capstone 5.0 support CS_ARCH_WASM.
    if arch == Arch::Wasm {
        return disassemble_wasm(data, base_address);
    }

    let no_extra = empty::<ExtraMode>();
    let cs = match arch {
        Arch::ArmBe => Capstone::new_raw(CsArch::ARM, Mode::Arm, no_extra, Some(Endian::Big)),
        Arch::AArch64Le => {
            Capstone::new_raw(CsArch::ARM64, Mode::Arm, no_extra, Some(Endian::Little))
        }
        Arch::AArch64Be => Capstone::new_raw(CsArch::ARM64, Mode::Arm, no_extra, Some(Endian::Big)),
        // DM_CORTEXM: cs_mode(ARM | THUMB | MCLASS) — THUMB and MCLASS
        // are both ExtraMode bits.
        Arch::CortexM => Capstone::new_raw(
            CsArch::ARM,
            Mode::Thumb,
            [ExtraMode::MClass].into_iter(),
            None,
        ),
        Arch::ThumbLe => {
            Capstone::new_raw(CsArch::ARM, Mode::Thumb, no_extra, Some(Endian::Little))
        }
        Arch::ThumbBe => Capstone::new_raw(CsArch::ARM, Mode::Thumb, no_extra, Some(Endian::Big)),
        Arch::Mips32le => {
            Capstone::new_raw(CsArch::MIPS, Mode::Mips32, no_extra, Some(Endian::Little))
        }
        Arch::Mips32be => {
            Capstone::new_raw(CsArch::MIPS, Mode::Mips32, no_extra, Some(Endian::Big))
        }
        Arch::Mips64le => {
            Capstone::new_raw(CsArch::MIPS, Mode::Mips64, no_extra, Some(Endian::Little))
        }
        Arch::Mips64be => {
            Capstone::new_raw(CsArch::MIPS, Mode::Mips64, no_extra, Some(Endian::Big))
        }
        Arch::Ppc32le => {
            Capstone::new_raw(CsArch::PPC, Mode::Mode32, no_extra, Some(Endian::Little))
        }
        Arch::Ppc32be => Capstone::new_raw(CsArch::PPC, Mode::Mode32, no_extra, Some(Endian::Big)),
        Arch::Ppc64le => {
            Capstone::new_raw(CsArch::PPC, Mode::Mode64, no_extra, Some(Endian::Little))
        }
        Arch::Ppc64be => Capstone::new_raw(CsArch::PPC, Mode::Mode64, no_extra, Some(Endian::Big)),
        Arch::Sparc => Capstone::new_raw(CsArch::SPARC, Mode::Default, no_extra, Some(Endian::Big)),
        Arch::SparcV9 => Capstone::new_raw(CsArch::SPARC, Mode::V9, no_extra, Some(Endian::Big)),
        Arch::S390x => Capstone::new_raw(CsArch::SYSZ, Mode::Default, no_extra, Some(Endian::Big)),
        Arch::Xcore => Capstone::new_raw(CsArch::XCORE, Mode::Default, no_extra, Some(Endian::Big)),
        Arch::M68k => Capstone::new_raw(CsArch::M68K, Mode::Default, no_extra, Some(Endian::Big)),
        // DM_M68K00..60 carry only the M68K_0n0 mode bits — no
        // endian flag upstream.
        Arch::M68k00 => Capstone::new_raw(CsArch::M68K, Mode::M68k000, no_extra, None),
        Arch::M68k10 => Capstone::new_raw(CsArch::M68K, Mode::M68k010, no_extra, None),
        Arch::M68k20 => Capstone::new_raw(CsArch::M68K, Mode::M68k020, no_extra, None),
        Arch::M68k30 => Capstone::new_raw(CsArch::M68K, Mode::M68k030, no_extra, None),
        Arch::M68k40 => Capstone::new_raw(CsArch::M68K, Mode::M68k040, no_extra, None),
        // CS_MODE_M68K_060 (1<<6) has no Mode variant in capstone 0.14;
        // Mode::Mips32R6 carries the same bit value.
        Arch::M68k60 => Capstone::new_raw(CsArch::M68K, Mode::Mips32R6, no_extra, None),
        Arch::Tms320c64x => Capstone::new_raw(
            CsArch::TMS320C64X,
            Mode::Default,
            no_extra,
            Some(Endian::Big),
        ),
        Arch::M6800 => Capstone::new_raw(CsArch::M680X, Mode::M680x6800, no_extra, None),
        Arch::M6801 => Capstone::new_raw(CsArch::M680X, Mode::M680x6801, no_extra, None),
        Arch::M6805 => Capstone::new_raw(CsArch::M680X, Mode::M680x6805, no_extra, None),
        Arch::M6808 => Capstone::new_raw(CsArch::M680X, Mode::M680x6808, no_extra, None),
        Arch::M6809 => Capstone::new_raw(CsArch::M680X, Mode::M680x6809, no_extra, None),
        Arch::M6811 => Capstone::new_raw(CsArch::M680X, Mode::M680x6811, no_extra, None),
        Arch::Cpu12 => Capstone::new_raw(CsArch::M680X, Mode::M680xCpu12, no_extra, None),
        Arch::Hd6301 => Capstone::new_raw(CsArch::M680X, Mode::M680x6301, no_extra, None),
        Arch::Hd6309 => Capstone::new_raw(CsArch::M680X, Mode::M680x6309, no_extra, None),
        Arch::Hcs08 => Capstone::new_raw(CsArch::M680X, Mode::M680xHcs08, no_extra, None),
        // DM_EVM / DM_MOS65XX: cs_open(arch, cs_mode(0)).
        Arch::Evm => Capstone::new_raw(CsArch::EVM, Mode::Default, no_extra, None),
        Arch::Mos65xx => Capstone::new_raw(CsArch::MOS65XX, Mode::Default, no_extra, None),
        Arch::Riscv32 => {
            Capstone::new_raw(CsArch::RISCV, Mode::RiscV32, no_extra, Some(Endian::Little))
        }
        Arch::Riscv64 => {
            Capstone::new_raw(CsArch::RISCV, Mode::RiscV64, no_extra, Some(Endian::Little))
        }
        // DM_RISKVC: cs_open(CS_ARCH_RISCV, CS_MODE_RISCVC) — the
        // compressed flag alone with no 32/64 mode bits.
        Arch::Riscvc => Capstone::new_raw(
            CsArch::RISCV,
            Mode::Default,
            [ExtraMode::RiscVC].into_iter(),
            None,
        ),
        // DM_BPF_*: CS_MODE_BPF_CLASSIC | endian.
        Arch::BpfLe => Capstone::new_raw(CsArch::BPF, Mode::Cbpf, no_extra, Some(Endian::Little)),
        Arch::BpfBe => Capstone::new_raw(CsArch::BPF, Mode::Cbpf, no_extra, Some(Endian::Big)),
        _ => return Err("not a capstone architecture".to_string()),
    }
    .map_err(|e| e.to_string())?;

    let insns = cs
        .disasm_all(data, base_address)
        .map_err(|e| e.to_string())?;
    let instructions: Vec<Instruction> = insns
        .iter()
        .map(|insn| {
            let text = match insn.op_str() {
                Some(ops) if !ops.is_empty() => {
                    format!("{} {}", insn.mnemonic().unwrap_or(""), ops)
                }
                _ => insn.mnemonic().unwrap_or("").to_string(),
            };
            Instruction {
                address: format!("{:x}", insn.address()),
                bytes: insn
                    .bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(""),
                mnemonic: text,
                label: None,
                comment: None,
                jump_target: None,
            }
        })
        .collect();
    let count = instructions.len();
    Ok(DisassemblyResult {
        start_address: base_address,
        instruction_count: count,
        instructions,
    })
}

/// Disassemble WebAssembly bytecode (upstream `DM_WASM`:
/// `cs_open(CS_ARCH_WASM, cs_mode(0))`).
///
/// `capstone::Arch` has no WASM variant even though capstone-sys and
/// upstream's vendored capstone 5.0 both support `CS_ARCH_WASM`, so
/// this drives the FFI layer directly and converts results through
/// `Insn::from_raw` — the same output glue as the safe path.
///
/// Safety invariants: `cs_open` on `CS_ERR_OK` writes a valid handle;
/// `cs_disasm` returns a capstone-owned instruction array valid until
/// `cs_free`; the handle is released with `cs_close` exactly once on
/// every exit path. No pointer escapes this function.
#[allow(unsafe_code)]
fn disassemble_wasm(data: &[u8], base_address: u64) -> Result<DisassemblyResult, String> {
    use capstone::Insn;
    use capstone_sys::{cs_arch, cs_close, cs_disasm, cs_err, cs_free, cs_insn, cs_mode, cs_open};
    use std::ptr;

    let mut handle: usize = 0;
    // SAFETY: `cs_open` writes the handle on success; args are valid enums.
    let err = unsafe { cs_open(cs_arch::CS_ARCH_WASM, cs_mode(0), &mut handle) };
    if err != cs_err::CS_ERR_OK {
        return Err(format!("cs_open CS_ARCH_WASM failed: {err:?}"));
    }

    let mut insns_ptr: *mut cs_insn = ptr::null_mut();
    // SAFETY: `handle` is a live handle; `data` outlives the call;
    // `insns_ptr` is written by cs_disasm.
    let count = unsafe {
        cs_disasm(
            handle,
            data.as_ptr(),
            data.len(),
            base_address,
            0,
            &mut insns_ptr,
        )
    };

    let mut instructions = Vec::with_capacity(count);
    if count > 0 && !insns_ptr.is_null() {
        // SAFETY: `insns_ptr` points to `count` contiguous cs_insn
        // entries owned by capstone until cs_free below.
        let raw: &[cs_insn] = unsafe { std::slice::from_raw_parts(insns_ptr, count) };
        for insn in raw {
            // SAFETY: each entry is a valid cs_insn for the open handle.
            let view = unsafe { Insn::from_raw(insn) };
            let text = match view.op_str() {
                Some(ops) if !ops.is_empty() => {
                    format!("{} {}", view.mnemonic().unwrap_or(""), ops)
                }
                _ => view.mnemonic().unwrap_or("").to_string(),
            };
            instructions.push(Instruction {
                address: format!("{:x}", view.address()),
                bytes: view
                    .bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(""),
                mnemonic: text,
                label: None,
                comment: None,
                jump_target: None,
            });
        }
        // SAFETY: releases the array cs_disasm allocated; entries are
        // no longer accessed after this call.
        unsafe { cs_free(insns_ptr, count) };
    }

    // SAFETY: handle was opened above; called exactly once.
    unsafe {
        let mut h = handle;
        cs_close(&mut h);
    }

    let count = instructions.len();
    Ok(DisassemblyResult {
        start_address: base_address,
        instruction_count: count,
        instructions,
    })
}

/// Read a range of bytes from a file.
fn read_file_range(path: &str, offset: u64, max_bytes: usize) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    let file_size = metadata.len();
    let bytes_to_read = std::cmp::min(max_bytes as u64, file_size.saturating_sub(offset)) as usize;
    let mut buf = vec![0u8; bytes_to_read];
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    file.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_x86_ret_not_break() {
        // x86 code: xor eax, eax; ret; nop; nop
        let code = [0x31, 0xC0, 0xC3, 0x90, 0x90];
        let result = disassemble_bytes(&code, 0x1000, Arch::X86, Syntax::Intel).unwrap();
        // Should NOT break on Ret — all instructions should be decoded.
        assert!(
            result.instruction_count >= 4,
            "Expected at least 4 instructions (no break on Ret), got {}: {:?}",
            result.instruction_count,
            result
                .instructions
                .iter()
                .map(|i| &i.mnemonic)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_disassemble_x64_basic() {
        // x64 code: 48 89 C8 = mov rax, rcx
        let code = [0x48, 0x89, 0xC8];
        let result = disassemble_bytes(&code, 0x1000, Arch::X64, Syntax::Intel).unwrap();
        assert!(result.instruction_count >= 1);
        assert!(result.instructions[0].mnemonic.contains("mov"));
    }

    #[test]
    fn test_disassemble_jump_target() {
        // x86: eb 02 = jmp short +2 (to 0x1004)
        // 90 90 = nop nop
        let code = [0xEB, 0x02, 0x90, 0x90];
        let result = disassemble_bytes(&code, 0x1000, Arch::X86, Syntax::Intel).unwrap();
        // First instruction should have a jump_target.
        assert!(result.instructions[0].jump_target.is_some());
        assert!(result.instructions[0].comment.is_some());
    }

    #[test]
    fn test_disassemble_label_generation() {
        // x86: eb 02 = jmp short +2 (to 0x1004)
        // 90 90 = nop nop (at 0x1002)
        // 90 = nop (at 0x1004 — this should get a label)
        let code = [0xEB, 0x02, 0x90, 0x90, 0x90];
        let result = disassemble_bytes(&code, 0x1000, Arch::X86, Syntax::Intel).unwrap();
        // The instruction at 0x1004 should have a label.
        let labeled = result.instructions.iter().find(|i| i.label.is_some());
        assert!(
            labeled.is_some(),
            "Expected at least one labeled instruction"
        );
    }

    #[test]
    fn test_disassemble_arm_basic() {
        // ARM NOP: e1a00000 (mov r0, r0) — little endian bytes
        let code = [0x00, 0x00, 0xa0, 0xe1];
        let result = disassemble_bytes(&code, 0x1000, Arch::Arm, Syntax::Intel).unwrap();
        assert!(result.instruction_count >= 1);
    }

    #[test]
    fn test_disassemble_arm64_basic() {
        // ARM64 NOP: d503201f — little endian bytes
        let code = [0x1f, 0x20, 0x03, 0xd5];
        let result = disassemble_bytes(&code, 0x1000, Arch::Arm64, Syntax::Intel).unwrap();
        assert!(result.instruction_count >= 1);
    }

    #[test]
    fn test_disassemble_empty_data() {
        let code: [u8; 0] = [];
        let result = disassemble_bytes(&code, 0x1000, Arch::X64, Syntax::Intel).unwrap();
        assert_eq!(result.instruction_count, 0);
    }

    #[test]
    fn test_disassemble_max_bytes_not_limited_to_256() {
        // Create 512 bytes of NOP instructions (90 repeated).
        let code = vec![0x90u8; 512];
        let result = disassemble_bytes(&code, 0x1000, Arch::X86, Syntax::Intel).unwrap();
        // Should decode all 512 NOPs, not stop at 256 bytes.
        assert!(
            result.instruction_count > 256,
            "Expected more than 256 instructions, got {} (old 256-byte limit should be removed)",
            result.instruction_count
        );
    }

    /// Differential test against the upstream-vendored capstone 5.0
    /// static lib (`dep/XCapstone/3rdparty/Capstone`). Snapshots are
    /// produced by `tools/capstone-oracle/disasm_oracle`, which replays
    /// `XCapstone::openHandle`'s DM->(arch,mode) table verbatim — so any
    /// wiring drift (mode bits, endianness, output glue) shows up here.
    #[test]
    fn test_capstone_arches_oracle_parity() {
        let cases: &[(&str, Arch)] = &[
            ("mips32be", Arch::Mips32be),
            ("mips32le", Arch::Mips32le),
            ("mips64be", Arch::Mips64be),
            ("mips64le", Arch::Mips64le),
            ("ppc32be", Arch::Ppc32be),
            ("ppc32le", Arch::Ppc32le),
            ("ppc64be", Arch::Ppc64be),
            ("ppc64le", Arch::Ppc64le),
            ("riscv32", Arch::Riscv32),
            ("riscv64", Arch::Riscv64),
            ("riscvc", Arch::Riscvc),
            ("armbe", Arch::ArmBe),
            ("aarch64le", Arch::AArch64Le),
            ("aarch64be", Arch::AArch64Be),
            ("cortexm", Arch::CortexM),
            ("thumble", Arch::ThumbLe),
            ("thumbbe", Arch::ThumbBe),
            ("sparc", Arch::Sparc),
            ("sparcv9", Arch::SparcV9),
            ("s390x", Arch::S390x),
            ("xcore", Arch::Xcore),
            ("m68k", Arch::M68k),
            ("m68k00", Arch::M68k00),
            ("m68k10", Arch::M68k10),
            ("m68k20", Arch::M68k20),
            ("m68k30", Arch::M68k30),
            ("m68k40", Arch::M68k40),
            ("m68k60", Arch::M68k60),
            ("tms320c64x", Arch::Tms320c64x),
            ("m6800", Arch::M6800),
            ("m6801", Arch::M6801),
            ("m6805", Arch::M6805),
            ("m6808", Arch::M6808),
            ("m6809", Arch::M6809),
            ("m6811", Arch::M6811),
            ("cpu12", Arch::Cpu12),
            ("hd6301", Arch::Hd6301),
            ("hd6309", Arch::Hd6309),
            ("hcs08", Arch::Hcs08),
            ("evm", Arch::Evm),
            ("mos65xx", Arch::Mos65xx),
            ("wasm", Arch::Wasm),
            ("bpfle", Arch::BpfLe),
            ("bpfbe", Arch::BpfBe),
        ];
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/disasm");
        for (dm, arch) in cases {
            let code = std::fs::read(corpus.join(format!("{dm}.bin")))
                .unwrap_or_else(|e| panic!("missing fixture {dm}.bin: {e}"));
            let oracle = std::fs::read_to_string(corpus.join(format!("{dm}.oracle.txt")))
                .unwrap_or_else(|e| panic!("missing oracle {dm}.oracle.txt: {e}"));
            let result = disassemble_bytes(&code, 0x1000, *arch, Syntax::Intel)
                .unwrap_or_else(|e| panic!("{dm}: disassemble failed: {e}"));
            let expected: Vec<&str> = oracle.lines().map(str::trim_end).collect();
            assert_eq!(
                result.instruction_count,
                expected.len(),
                "{dm}: instruction count mismatch"
            );
            for (i, (insn, want)) in result.instructions.iter().zip(expected.iter()).enumerate() {
                let got = format!("{}\t{}\t{}", insn.address, insn.bytes, insn.mnemonic);
                assert_eq!(got.trim_end(), *want, "{dm}: instruction {i} mismatch");
            }
        }
    }

    #[test]
    fn test_capstone_garbage_input_no_panic() {
        // Malformed byte streams must fail closed (short/zero decode),
        // never panic.
        let garbage: Vec<u8> = (0..255u8).cycle().take(97).collect();
        for arch in [
            Arch::Mips32be,
            Arch::Mips32le,
            Arch::Mips64be,
            Arch::Ppc32be,
            Arch::Ppc64le,
            Arch::Riscv32,
            Arch::Riscv64,
            Arch::Riscvc,
            Arch::ArmBe,
            Arch::AArch64Le,
            Arch::CortexM,
            Arch::ThumbBe,
            Arch::SparcV9,
            Arch::S390x,
            Arch::Xcore,
            Arch::M68k60,
            Arch::Tms320c64x,
            Arch::M6809,
            Arch::Cpu12,
            Arch::Evm,
            Arch::Mos65xx,
            Arch::Wasm,
            Arch::BpfLe,
            Arch::BpfBe,
        ] {
            let _ = disassemble_bytes(&garbage, 0x1000, arch, Syntax::Intel);
            let _ = disassemble_bytes(&[], 0x1000, arch, Syntax::Intel);
        }
    }
}

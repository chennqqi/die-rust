//! x86 emulator core — faithful port of upstream `arch/xemux86.cpp`
//! (XEmulator pin `655e6da`, the sibling-checkout SHA contemporary with
//! the XStaticUnpacker pin `746fb24`).
//!
//! The upstream engine decodes guest instructions into micro-ops,
//! groups them into translation blocks cached by guest address, and
//! interprets the cached micro-ops. This port keeps the micro-op
//! decode/execute split identical (observable semantics must match
//! bit-for-bit) but decodes on the fly inside `run` instead of keeping
//! a translation-block cache — the cache is a pure performance
//! optimization with no observable effect except one: writes to guest
//! memory invalidate cached blocks. Our decode-per-step model is
//! always coherent with guest writes, so no invalidation bookkeeping
//! is needed.
//!
//! Safety model for untrusted stub code: bounded step budgets at every
//! call site (mirroring upstream `pnStepsRemaining`), mapped-memory-only
//! accesses, and fail-closed `STEP_FAULT`/`STEP_UNIMPLEMENTED` stops —
//! the emulator never touches host state beyond its `MemoryManager`.

use super::memory::MemoryManager;
use super::regs::*;

mod decode;
mod exec;
mod fpu;
mod mmx;

/// One decoded operand: register, memory reference, or nothing
/// (upstream `XEmuOperand`; base/index default to -1 = "absent").
#[derive(Clone, Copy)]
pub struct Operand {
    /// Register operand.
    pub is_reg: bool,
    /// Memory operand.
    pub is_mem: bool,
    /// Register index for a register operand.
    pub reg: i32,
    /// Byte operand is a high-byte register (AH/CH/DH/BH).
    pub high8: bool,
    /// Register operand is an MMX register (0..7).
    pub mmx: bool,
    /// Memory base register index, or -1.
    pub base_reg: i32,
    /// Memory index register index, or -1.
    pub index_reg: i32,
    /// Index scale 1/2/4/8.
    pub scale: i32,
    /// Displacement.
    pub disp: i64,
    /// RIP-relative addressing.
    pub rip_rel: bool,
    /// Segment override: 0 none, 1 FS, 2 GS, 3 ES, 4 CS, 5 SS, 6 DS.
    pub seg_source: i32,
}

impl Default for Operand {
    fn default() -> Self {
        Self {
            is_reg: false,
            is_mem: false,
            reg: 0,
            high8: false,
            mmx: false,
            base_reg: -1,
            index_reg: -1,
            scale: 1,
            disp: 0,
            rip_rel: false,
            seg_source: 0,
        }
    }
}

impl Operand {
    /// Build a register operand.
    pub fn reg(index: i32) -> Self {
        Self {
            is_reg: true,
            reg: index,
            ..Default::default()
        }
    }

    /// Build an MMX register operand.
    pub fn mmx_reg(index: i32) -> Self {
        Self {
            is_reg: true,
            mmx: true,
            reg: index & 7,
            ..Default::default()
        }
    }

    /// Build a byte register operand from a raw 3-bit encoding, folding
    /// the legacy high-byte aliases when no REX prefix is present.
    pub fn reg8(raw: i32, has_rex: bool, rex_extend: bool) -> Self {
        let mut o = Self {
            is_reg: true,
            ..Default::default()
        };
        if !has_rex && (4..=7).contains(&raw) {
            o.reg = raw - 4;
            o.high8 = true;
        } else {
            o.reg = raw + if rex_extend { 8 } else { 0 };
        }
        o
    }
}

/// Legacy high-byte fixup: without a REX prefix, a byte-sized register
/// operand encoded 4..7 names AH/CH/DH/BH (upstream `x86FixHigh8`).
fn fix_high8(o: &mut Operand, width: i32) {
    if width == 1 && o.is_reg && !o.high8 && (4..=7).contains(&o.reg) {
        o.reg -= 4;
        o.high8 = true;
    }
}

/// Near-branch linear target with the 16-bit code-segment wrap
/// (upstream `wrapNearBranch`).
pub(crate) fn wrap_near_branch(bits: u8, code_seg_base: u64, linear_target: u64) -> u64 {
    if bits == 16 {
        code_seg_base.wrapping_add(linear_target.wrapping_sub(code_seg_base) & 0xFFFF)
    } else {
        linear_target
    }
}

/// Store AL/AH as a 16-bit AX write (upstream `setAxBytes`).
pub(crate) fn set_ax_bytes(registers: &mut Registers, al: u8, ah: u8) {
    registers.set_gpr(GPR_RAX, 2, (((ah as u16) << 8) | al as u16) as u64);
}

/// Micro-op kinds (upstream `XEmuMicroOpKind`). One guest instruction
/// maps to exactly one kind; operand slots carry the details.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MicroOpKind {
    /// No operation.
    Nop,
    /// rm = aluOp(rm, reg).
    AluRmR,
    /// reg = aluOp(reg, rm).
    AluRRm,
    /// rAX = aluOp(rAX, imm).
    AluRaxImm,
    /// rm = aluOp(rm, imm) (group 1).
    AluRmImm,
    /// dst = src.
    Mov,
    /// dst = imm.
    MovImm,
    /// reg = effective address.
    Lea,
    /// reg = zero_extend(rm).
    Movzx,
    /// reg = sign_extend(rm).
    Movsx,
    /// flags = src1 & src2.
    Test,
    /// flags = dst & imm.
    TestImm,
    /// push(src).
    Push,
    /// dst = pop().
    Pop,
    /// rm +/- 1 (alu_op: 0 inc, 1 dec).
    IncDec,
    /// rm = cond ? 1 : 0.
    Setcc,
    /// pc = branch_target.
    Jmp,
    /// pc = src.
    JmpInd,
    /// pc = cond ? branch_target : fallthrough.
    Jcc,
    /// push(next); pc = branch_target.
    Call,
    /// push(next); pc = src.
    CallInd,
    /// far jmp ptr16:16.
    JmpFar,
    /// far call ptr16:16.
    CallFar,
    /// far jmp m16:16.
    JmpFarInd,
    /// far call m16:16.
    CallFarInd,
    /// far ret.
    Retf,
    /// interrupt return.
    Iret,
    /// les/lds/lss/lfs/lgs far pointer load.
    LoadFar,
    /// pc = pop() (n_imm bytes released).
    Ret,
    /// int3/hlt/syscall stop.
    Halt,
    /// rdtsc.
    Rdtsc,
    /// cpuid.
    Cpuid,
    /// pushad/pushaw (32-bit only).
    Pusha,
    /// popad/popaw (32-bit only).
    Popa,
    /// shift/rotate (alu_op: 0 rol..7 sar; cond: 0 imm, 1 CL).
    Shift,
    /// string ops (alu_op: kind; cond: 0 none, 1 rep/repe, 2 repne).
    String,
    /// group-3 not/neg/mul/imul/div/idiv.
    MulDiv,
    /// swap(dst, src).
    Xchg,
    /// sign-extend accumulator.
    Cdq,
    /// byte-swap.
    Bswap,
    /// bit scan forward.
    Bsf,
    /// bit scan reverse.
    Bsr,
    /// exchange-and-add.
    Xadd,
    /// bit test group BT/BTS/BTR/BTC.
    Bt,
    /// double-precision shift SHLD/SHRD.
    ShiftD,
    /// MMX packed-integer op.
    Mmx,
    /// imul reg, rm (2- or 3-operand).
    Imul2,
    /// loopne/loope/loop/jecxz.
    Loop,
    /// syscall / int 0x80 / software interrupt.
    Syscall,
    /// clc/stc/cmc/cld/std/cli/sti.
    FlagOp,
    /// cmovcc reg, rm.
    Cmovcc,
    /// pushf.
    PushF,
    /// popf.
    PopF,
    /// sahf.
    Sahf,
    /// lahf.
    Lahf,
    /// leave.
    Leave,
    /// enter imm16, imm8.
    Enter,
    /// in AL/AX/eAX.
    In,
    /// out imm8/DX.
    Out,
    /// xlat.
    Xlat,
    /// salc (undocumented 0xD6).
    Salc,
    /// smsw r/m16.
    Smsw,
    /// lar/lsl (n_imm carries the value).
    Lsl,
    /// mov r32, crN.
    MovFromCr,
    /// mov r32,drN / mov drN,r32.
    MovDr,
    /// push segment register.
    PushSeg,
    /// pop segment register.
    PopSeg,
    /// BCD/ASCII adjust DAA/DAS/AAA/AAS/AAM/AAD.
    Bcd,
    /// mov Sreg,r/m16 or mov r/m16,Sreg.
    MovSeg,
    /// x87 ESC opcode.
    Fpu,
    /// into (0xCE).
    Into,
    /// arpl r/m16, r16.
    Arpl,
    /// opcode outside the supported subset.
    Unimpl,
}

impl MicroOpKind {
    /// Control-transfer / stop kinds that end a translation block.
    pub fn is_block_terminator(self) -> bool {
        use MicroOpKind::*;
        matches!(
            self,
            Jmp | JmpInd
                | Jcc
                | Call
                | CallInd
                | JmpFar
                | CallFar
                | JmpFarInd
                | CallFarInd
                | Retf
                | Iret
                | Ret
                | Loop
                | Halt
                | Syscall
                | Into
                | Unimpl
        )
    }
}

/// A single decoded micro-op (upstream `XEmuMicroOp`).
#[derive(Clone)]
pub struct MicroOp {
    /// Operation kind.
    pub kind: MicroOpKind,
    /// Operation width in bytes (1/2/4/8).
    pub size: i32,
    /// Source width (MOVZX/MOVSX).
    pub src_size: i32,
    /// ALU operation id / sub-op selector.
    pub alu_op: i32,
    /// Condition code (Jcc/SETcc) or secondary selector.
    pub cond: u8,
    /// Destination operand.
    pub dst: Operand,
    /// Source operand.
    pub src: Operand,
    /// Immediate value.
    pub imm: u64,
    /// Guest address of this instruction.
    pub address: u64,
    /// Encoded length in bytes.
    pub length: u32,
    /// Absolute target for direct control transfers.
    pub branch_target: u64,
    /// Short mnemonic (for tracing / oracle dumps).
    pub text: String,
}

impl Default for MicroOp {
    fn default() -> Self {
        Self {
            kind: MicroOpKind::Nop,
            size: 4,
            src_size: 1,
            alu_op: 0,
            cond: 0,
            dst: Operand::default(),
            src: Operand::default(),
            imm: 0,
            address: 0,
            length: 0,
            branch_target: 0,
            text: String::new(),
        }
    }
}

/// Step results (upstream `XEmuArch::STEP_RESULT`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum StepResult {
    /// Instruction executed normally.
    #[default]
    Ok = 0,
    /// INT3/HLT — normal stop.
    Halt,
    /// Memory access violation.
    Fault,
    /// Opcode not handled by this core.
    Unimplemented,
    /// syscall/int — OS layer must service it.
    Syscall,
}

/// Terminating-step info (upstream `XEmuArch::STEP_INFO`).
#[derive(Clone, Default)]
pub struct StepInfo {
    /// Step outcome.
    pub result: StepResult,
    /// Instruction pointer before the step.
    pub address: u64,
    /// Bytes consumed.
    pub length: u32,
    /// Best-effort textual form.
    pub text: String,
    /// Extra info (fault reason, target).
    pub comment: String,
    /// Software-interrupt vector for `Syscall` results.
    pub vector: i32,
}

impl StepInfo {
    fn ok() -> Self {
        Self {
            result: StepResult::Ok,
            vector: -1, // upstream STEP_INFO default
            ..Default::default()
        }
    }
}

/// Decoder state for one instruction (upstream `DEC`).
#[derive(Clone)]
struct Dec {
    start: u64,
    fetch: u64,
    rex_w: bool,
    rex_r: bool,
    rex_x: bool,
    rex_b: bool,
    has_rex: bool,
    op_size16: bool,
    seg_source: i32,
    op_size: i32,
    addr_size: i32,
    rep: i32,
    fault: bool,
}

impl Dec {
    fn new() -> Self {
        Self {
            start: 0,
            fetch: 0,
            rex_w: false,
            rex_r: false,
            rex_x: false,
            rex_b: false,
            has_rex: false,
            op_size16: false,
            seg_source: 0,
            op_size: 4,
            addr_size: 8,
            rep: 0,
            fault: false,
        }
    }
}

/// The x86 emulator core (upstream `XEmuX86`).
pub struct X86<'a> {
    mem: &'a mut MemoryManager,
    bits: u8,
    tsc: u64,
    io_ports: [u8; 0x400],
    insn_count: u64,
    pit_hi_byte: bool,
    trap_taken: bool,
    ss_block: bool,
    dr: [u32; 8],
    fpu_reg: [f64; 8],
    fpu_int: [i64; 8],
    fpu_is_int: [bool; 8],
    fpu_tag: [u8; 8],
    fpu_top: i32,
    fpu_control: u16,
    fpu_status_cc: u16,
    fpu_init_done: bool,
    exec_fault: bool,
    fault_addr: u64,
}

impl<'a> X86<'a> {
    /// Create a core bound to `mem` executing at `bits` width
    /// (16/32/64). Seeds the upstream defaults: IO ports open-bus 0xFF
    /// with port 0x21 = 0xF8, DR6/DR7 architectural reset values, and
    /// FPU reset.
    pub fn new(mem: &'a mut MemoryManager, bits: u8) -> Self {
        let mut io_ports = [0xFFu8; 0x400];
        io_ports[0x21] = 0xF8;
        let mut x = Self {
            mem,
            bits,
            tsc: 0,
            io_ports,
            insn_count: 0,
            pit_hi_byte: false,
            trap_taken: false,
            ss_block: false,
            dr: [0; 8],
            fpu_reg: [0.0; 8],
            fpu_int: [0; 8],
            fpu_is_int: [false; 8],
            fpu_tag: [0; 8],
            fpu_top: 0,
            fpu_control: 0x037F,
            fpu_status_cc: 0,
            fpu_init_done: false,
            exec_fault: false,
            fault_addr: 0,
        };
        x.dr[6] = 0xFFFF_0FF0;
        x.dr[7] = 0x0000_0400;
        x.fpu_init();
        x
    }

    /// Current mode width.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Linear address of the access that raised the last `Fault`.
    pub fn fault_address(&self) -> u64 {
        self.fault_addr
    }

    /// The guest memory image — the host driver shares it with the
    /// emulator between `run` calls, like the upstream `m_pMemory`
    /// member.
    pub fn memory(&self) -> &MemoryManager {
        self.mem
    }

    /// Mutable guest memory access for the host driver.
    pub fn memory_mut(&mut self) -> &mut MemoryManager {
        self.mem
    }

    fn wrap_a20(&self, address: u64) -> u64 {
        if self.bits == 16 {
            address & 0xFFFFF
        } else {
            address
        }
    }

    fn mask(size: i32) -> u64 {
        match size {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            _ => u64::MAX,
        }
    }

    fn sign_bit(size: i32) -> u64 {
        match size {
            1 => 0x80,
            2 => 0x8000,
            4 => 0x8000_0000,
            _ => 0x8000_0000_0000_0000,
        }
    }

    fn sign_extend(value: u64, size: i32) -> i64 {
        match size {
            1 => value as u8 as i8 as i64,
            2 => value as u16 as i16 as i64,
            4 => value as u32 as i32 as i64,
            _ => value as i64,
        }
    }

    fn parity(value: u8) -> bool {
        value.count_ones().is_multiple_of(2)
    }

    fn stack_size(&self, dec: &Dec) -> i32 {
        if self.bits == 64 {
            if dec.op_size16 { 2 } else { 8 }
        } else {
            dec.op_size
        }
    }

    // --- Translator -------------------------------------------------

    fn fetch8(&mut self, dec: &mut Dec) -> u8 {
        let v = self
            .mem
            .fetch_u8(self.wrap_a20(dec.fetch))
            .unwrap_or_else(|| {
                dec.fault = true;
                0
            });
        dec.fetch = dec.fetch.wrapping_add(1);
        v
    }

    fn fetch16(&mut self, dec: &mut Dec) -> u16 {
        let v = self.mem.fetch_u16(dec.fetch).unwrap_or_else(|| {
            dec.fault = true;
            0
        });
        dec.fetch = dec.fetch.wrapping_add(2);
        v
    }

    fn fetch32(&mut self, dec: &mut Dec) -> u32 {
        let v = self.mem.fetch_u32(dec.fetch).unwrap_or_else(|| {
            dec.fault = true;
            0
        });
        dec.fetch = dec.fetch.wrapping_add(4);
        v
    }

    fn fetch64(&mut self, dec: &mut Dec) -> u64 {
        let v = self.mem.fetch_u64(dec.fetch).unwrap_or_else(|| {
            dec.fault = true;
            0
        });
        dec.fetch = dec.fetch.wrapping_add(8);
        v
    }
}

//! Guest register file — faithful port of upstream `xemuregisters.cpp`
//! (pin `655e6da`). GPRs are always stored as 64-bit values; 32-bit mode
//! ignores the upper halves and 32-bit writes zero-extend.

/// GPR indices (upstream `XEmuRegisters::GPR`).
pub const GPR_RAX: usize = 0;
/// GPR index.
pub const GPR_RCX: usize = 1;
/// GPR index.
pub const GPR_RDX: usize = 2;
/// GPR index.
pub const GPR_RBX: usize = 3;
/// GPR index.
pub const GPR_RSP: usize = 4;
/// GPR index.
pub const GPR_RBP: usize = 5;
/// GPR index.
pub const GPR_RSI: usize = 6;
/// GPR index.
pub const GPR_RDI: usize = 7;
/// GPR index (x86-64 extended registers follow).
pub const GPR_R8: usize = 8;
/// GPR index.
pub const GPR_R9: usize = 9;
/// GPR index.
pub const GPR_R10: usize = 10;
/// GPR index.
pub const GPR_R11: usize = 11;
/// GPR index.
pub const GPR_R12: usize = 12;
/// GPR index.
pub const GPR_R13: usize = 13;
/// GPR index.
pub const GPR_R14: usize = 14;
/// GPR index.
pub const GPR_R15: usize = 15;

/// Carry flag bit.
pub const FLAG_CF: u64 = 1 << 0;
/// Parity flag bit.
pub const FLAG_PF: u64 = 1 << 2;
/// Auxiliary carry flag bit.
pub const FLAG_AF: u64 = 1 << 4;
/// Zero flag bit.
pub const FLAG_ZF: u64 = 1 << 6;
/// Sign flag bit.
pub const FLAG_SF: u64 = 1 << 7;
/// Trap flag bit.
pub const FLAG_TF: u64 = 1 << 8;
/// Interrupt-enable flag bit.
pub const FLAG_IF: u64 = 1 << 9;
/// Direction flag bit.
pub const FLAG_DF: u64 = 1 << 10;
/// Overflow flag bit.
pub const FLAG_OF: u64 = 1 << 11;

/// x86/x86-64 register file (upstream `XEmuRegisters`).
#[derive(Clone)]
pub struct Registers {
    /// General-purpose registers, stored as 64-bit values.
    pub gpr: [u64; 16],
    /// Stack pointer alias slot kept for upstream parity (unused slot 16+ is not modeled; gpr[4] is SP).
    pub nsp: u64,
    /// Program counter.
    pub rip: u64,
    /// Flags register (`0x202` at reset).
    pub rflags: u64,
    /// CS selector.
    pub cs: u16,
    /// DS selector.
    pub ds: u16,
    /// ES selector.
    pub es: u16,
    /// FS selector.
    pub fs: u16,
    /// GS selector.
    pub gs: u16,
    /// SS selector.
    pub ss: u16,
    /// FS segment base.
    pub fs_base: u64,
    /// GS segment base.
    pub gs_base: u64,
    /// ARM thread pointer (kept for struct parity; unused on x86).
    pub tpidr: u64,
    /// CR0 shadow.
    pub cr0: u64,
    /// CR3 shadow.
    pub cr3: u64,
    /// CR4 shadow.
    pub cr4: u64,
    /// MMX registers MM0-MM7.
    pub mmx: [u64; 8],
}

impl Default for Registers {
    fn default() -> Self {
        Self {
            gpr: [0; 16],
            nsp: 0,
            rip: 0,
            rflags: 0x202,
            cs: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
            ss: 0,
            fs_base: 0,
            gs_base: 0,
            tpidr: 0,
            cr0: 0,
            cr3: 0,
            cr4: 0,
            mmx: [0; 8],
        }
    }
}

impl Registers {
    /// Read a GPR truncated to `size` bytes (1/2/4/8); out-of-range index reads 0.
    pub fn get_gpr(&self, index: usize, size: usize) -> u64 {
        if index > 15 {
            return 0;
        }
        let v = self.gpr[index];
        match size {
            1 => v & 0xFF,
            2 => v & 0xFFFF,
            4 => v & 0xFFFF_FFFF,
            _ => v,
        }
    }

    /// Write a GPR at `size` bytes; size 4 zero-extends (x86-64 semantics),
    /// sizes 1/2 merge into the low bytes. Out-of-range index is ignored.
    pub fn set_gpr(&mut self, index: usize, size: usize, value: u64) {
        if index > 15 {
            return;
        }
        match size {
            1 => self.gpr[index] = (self.gpr[index] & !0xFF) | (value & 0xFF),
            2 => self.gpr[index] = (self.gpr[index] & !0xFFFF) | (value & 0xFFFF),
            4 => self.gpr[index] = value & 0xFFFF_FFFF,
            _ => self.gpr[index] = value,
        }
    }

    /// Test a flag bit (upstream `getFlag`).
    pub fn flag(&self, flag: u64) -> bool {
        self.rflags & flag != 0
    }

    /// Set or clear a flag bit (upstream `setFlag`).
    pub fn set_flag(&mut self, flag: u64, value: bool) {
        if value {
            self.rflags |= flag;
        } else {
            self.rflags &= !flag;
        }
    }
}

//! Deterministic micro-execution harness mirroring the upstream
//! `xemulator-oracle micro` mode exactly: same memory layout, register
//! initialization, step loop, and report shape, so JSON dumps can be
//! diffed field-by-field against the pinned Qt oracle.
//!
//! Layout (32-bit flat):
//! - code at 0x10000, one 4 KiB page, rwx — the bytes under test
//! - stack at 0x30000..0x31000, rw — zero-filled
//! - data at 0x40000, one 4 KiB page, rwx — a copy of the code bytes
//! - ESP = stack top - 0x10, EIP = code base

use super::memory::{MemoryFlags, MemoryManager};
use super::regs::{GPR_RSP, Registers};
use super::x86::{StepResult, X86};

/// Code region base (upstream `MICRO_CODE`).
pub const MICRO_CODE: u64 = 0x10000;
/// Stack region base (upstream `MICRO_STACK`).
pub const MICRO_STACK: u64 = 0x30000;
/// Stack region size (upstream `MICRO_STACK_SIZE`).
pub const MICRO_STACK_SIZE: u64 = 0x1000;
/// Data region base (upstream `MICRO_DATA`).
pub const MICRO_DATA: u64 = 0x40000;

/// FNV-1a 64 over a byte range — stable cross-process checksum matching
/// the oracle's `fnv1a`.
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(1099511628211);
    }
    h
}

/// Per-region report entry.
#[derive(Clone, Debug)]
pub struct RegionReport {
    /// Region base address.
    pub base: u64,
    /// FNV-1a over the full committed contents.
    pub fnv64: u64,
    /// First 64 bytes, hex.
    pub head: Vec<u8>,
}

/// One micro-run report; field-for-field comparable with the oracle's
/// JSON (gpr entries are the low 32 bits like upstream `getGPR(i, 4)`).
#[derive(Clone, Debug)]
pub struct MicroReport {
    /// Whether the harness layout was established.
    pub setup: bool,
    /// Low-32 GPR values (16 slots).
    pub gpr: [u64; 16],
    /// Final instruction pointer.
    pub rip: u64,
    /// Final EFLAGS.
    pub rflags: u64,
    /// Final segment selectors (cs, ds, es, fs, gs, ss).
    pub segs: [u16; 6],
    /// Number of successful steps (the terminating step is not counted).
    pub steps: i64,
    /// `StepResult` discriminant of the terminating step.
    pub stop_result: i32,
    /// Address of the terminating instruction.
    pub stop_address: u64,
    /// Disassembly text of the terminating instruction.
    pub stop_text: String,
    /// Comment of the terminating step.
    pub stop_comment: String,
    /// Committed-region reports.
    pub regions: Vec<RegionReport>,
}

/// Escape a string for embedding in compact JSON.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

impl MicroReport {
    /// Serialize in the exact field shape of the upstream
    /// `xemulator-oracle micro` JSON (hex numbers without `0x`, region
    /// heads as hex strings).
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str("{\"gpr\":[");
        for (i, v) in self.gpr.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            out.push_str(&format!("\"{v:x}\""));
        }
        out.push_str("],\"regions\":[");
        for (i, r) in self.regions.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            let head: String = r.head.iter().map(|b| format!("{b:02x}")).collect();
            out.push_str(&format!(
                "{{\"base\":\"{:x}\",\"fnv64\":\"{:x}\",\"head\":\"{}\"}}",
                r.base, r.fnv64, head
            ));
        }
        out.push_str(&format!(
            "],\"rflags\":\"{:x}\",\"rip\":\"{:x}\",\"segs\":{{\"cs\":{},\"ds\":{},\"es\":{},\"fs\":{},\"gs\":{},\"ss\":{}}},\"setup\":{},\"steps\":{},\"stop_address\":\"{:x}\",\"stop_comment\":\"{}\",\"stop_result\":{},\"stop_text\":\"{}\"}}",
            self.rflags,
            self.rip,
            self.segs[0],
            self.segs[1],
            self.segs[2],
            self.segs[3],
            self.segs[4],
            self.segs[5],
            self.setup,
            self.steps,
            self.stop_address,
            json_escape(&self.stop_comment),
            self.stop_result,
            json_escape(&self.stop_text),
        ));
        out
    }
}

/// Run `code` under the oracle-identical micro harness. `max_steps <= 0`
/// is unbounded — callers must pass a real budget for untrusted input.
pub fn micro_run(code: &[u8], max_steps: i64) -> MicroReport {
    let mut report = MicroReport {
        setup: false,
        gpr: [0; 16],
        rip: 0,
        rflags: 0,
        segs: [0; 6],
        steps: 0,
        stop_result: StepResult::Ok as i32,
        stop_address: 0,
        stop_text: String::new(),
        stop_comment: String::new(),
        regions: Vec::new(),
    };

    let rwx = MemoryFlags::new(true, true, true, false);
    let rw = MemoryFlags::new(true, true, false, false);

    let mut memory = MemoryManager::new();
    memory.set_bits(32);
    let mut data = [0u8; 0x1000];
    data[..code.len().min(0x1000)].copy_from_slice(&code[..code.len().min(0x1000)]);
    let setup = memory.map_fixed(MICRO_CODE, 0x1000, rwx, "code")
        && memory.map_fixed(MICRO_STACK, MICRO_STACK_SIZE, rw, "stack")
        && memory.map_fixed(MICRO_DATA, 0x1000, rwx, "data")
        && memory.write(MICRO_CODE, code)
        && memory.write(MICRO_DATA, &data);
    report.setup = setup;
    if !setup {
        return report;
    }

    let mut registers = Registers::default();
    registers.set_gpr(GPR_RSP, 4, MICRO_STACK + MICRO_STACK_SIZE - 0x10);
    registers.rip = MICRO_CODE;

    let mut steps: i64 = 0;
    {
        let mut arch = X86::new(&mut memory, 32);
        while steps < max_steps {
            // The oracle keeps the last step's info in `stop` even when
            // the budget is exhausted on an OK step.
            let stop = arch.step(&mut registers);
            report.stop_result = stop.result as i32;
            report.stop_address = stop.address;
            report.stop_text = stop.text.clone();
            report.stop_comment = stop.comment.clone();
            if stop.result != StepResult::Ok {
                break;
            }
            steps += 1;
        }
    }

    for (i, slot) in report.gpr.iter_mut().enumerate() {
        *slot = registers.get_gpr(i, 4);
    }
    report.rip = registers.rip;
    report.rflags = registers.rflags;
    report.segs = [
        registers.cs,
        registers.ds,
        registers.es,
        registers.fs,
        registers.gs,
        registers.ss,
    ];
    report.steps = steps;

    for region in memory.regions() {
        if let Some(bytes) = memory.read(region.address, region.size) {
            report.regions.push(RegionReport {
                base: region.address,
                fnv64: fnv1a64(&bytes),
                head: bytes[..bytes.len().min(64)].to_vec(),
            });
        }
    }
    report
}

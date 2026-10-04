//! Guest-code emulation for the static unpackers — a safe Rust port of
//! the upstream `XEmulator` subset that `XStaticUnpacker` requires
//! (pin `horsicq/XEmulator@655e6da`, the sibling-checkout SHA
//! contemporary with the pinned `XStaticUnpacker@746fb24`).
//!
//! Scope: `XEmuMemoryManager` (bounded mapped-memory model),
//! `XEmuRegisters` (x86/x86-64 register file), and `XEmuX86` (the x86
//! decoder + micro-op interpreter). The upstream OS personalities,
//! file-format loaders, and non-x86 architectures are out of scope —
//! the unpackers drive the arch core directly.
//!
//! Safety invariants for untrusted guest code:
//! - every memory access is range-checked against committed regions;
//! - region count and total commit are bounded (see [`memory`]);
//! - execution only proceeds under an explicit step budget supplied by
//!   the caller (upstream `pnStepsRemaining` semantics);
//! - invalid opcodes and unmapped accesses fail closed with
//!   [`StepResult::Unimplemented`]/[`StepResult::Fault`];
//! - guest code never executes on the host CPU — the upstream
//!   Windows-only `hostShiftExec`/`hostExecDiv` fast paths are not
//!   reproduced; the deterministic software fallbacks (what upstream
//!   runs on non-Windows hosts, i.e. the oracle baseline) are used.

pub mod memory;
pub mod micro;
pub mod regs;
pub mod x86;

pub use memory::{MemoryFlags, MemoryManager, Region};
pub use micro::{MicroReport, RegionReport, micro_run};
pub use regs::Registers;
pub use x86::{MicroOp, MicroOpKind, StepInfo, StepResult, X86};

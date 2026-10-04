//! XEmulator micro-op differential: replays the upstream
//! `xemulator-oracle micro` snapshots in `corpus/xemulator/oracle/`
//! against the Rust port's `micro_run`, field-by-field including the
//! FNV-1a memory digests. Snapshots are captured oracle output
//! (regenerate with `python3 tools/emu_diff.py --snapshot
//! corpus/xemulator/oracle`); none are hand-written.

use diec_engine::emulate::{MemoryFlags, MemoryManager, Registers, StepResult, X86, micro_run};
use serde_json::Value;
use std::path::Path;

fn corpus_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/xemulator")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("case hex"))
        .collect()
}

#[test]
fn micro_run_matches_upstream_oracle() {
    let dir = corpus_dir().join("oracle");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("oracle snapshot dir")
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "no oracle snapshots found");

    let mut compared = 0usize;
    for path in entries {
        let case: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("snapshot read"))
                .expect("snapshot json");
        let hex = case["hex"].as_str().expect("case hex");
        let oracle = &case["oracle"];
        let code = hex_to_bytes(hex);
        let report = micro_run(&code, 64);
        let ours: Value = serde_json::from_str(&report.to_json()).expect("micro report json");

        assert_eq!(
            ours,
            *oracle,
            "micro divergence on case {} ({})",
            path.display(),
            case["comment"].as_str().unwrap_or("")
        );
        compared += 1;
    }
    assert!(compared >= 400, "expected the full battery, got {compared}");
}

#[test]
fn unmapped_fetch_faults_closed() {
    let mut memory = MemoryManager::new();
    memory.set_bits(32);
    let rwx = MemoryFlags::new(true, true, true, false);
    assert!(memory.map_fixed(0x10000, 0x1000, rwx, "code"));
    assert!(memory.write(0x10000, &[0x90u8, 0x90]));

    let mut regs = Registers {
        rip: 0x10FFF, // last mapped byte: 0 -> group decode needs more bytes
        ..Default::default()
    };
    let mut arch = X86::new(&mut memory, 32);
    let info = arch.step(&mut regs);
    assert_eq!(info.result, StepResult::Fault);
    assert_eq!(info.address, 0x10FFF);
}

#[test]
fn unmapped_read_write_fault() {
    let mut memory = MemoryManager::new();
    memory.set_bits(32);
    let rwx = MemoryFlags::new(true, true, true, false);
    assert!(memory.map_fixed(0x10000, 0x1000, rwx, "code"));
    // mov eax, [ebx] with ebx = 0 -> unmapped read fault.
    assert!(memory.write(0x10000, &[0x8bu8, 0x1b]));

    let mut regs = Registers {
        rip: 0x10000,
        ..Default::default()
    };
    let mut arch = X86::new(&mut memory, 32);
    let info = arch.step(&mut regs);
    assert_eq!(info.result, StepResult::Fault);
    // RIP must stay at the faulting instruction (upstream leaves it).
    assert_eq!(regs.rip, 0x10000);
}

#[test]
fn hlt_halts_and_int_dispatches_to_os() {
    // Upstream: `hlt` is STEP_HALT; `int3`, `int N` and `ud2` are all
    // STEP_SYSCALL — the OS layer must service them (oracle-verified).
    let mut memory = MemoryManager::new();
    memory.set_bits(32);
    let rwx = MemoryFlags::new(true, true, true, false);
    assert!(memory.map_fixed(0x10000, 0x1000, rwx, "code"));
    assert!(memory.write(0x10000, &[0xf4u8]));
    let mut regs = Registers {
        rip: 0x10000,
        ..Default::default()
    };
    let mut arch = X86::new(&mut memory, 32);
    let info = arch.step(&mut regs);
    assert_eq!(info.result, StepResult::Halt);

    for (code, comment) in [
        (&[0xccu8][..], "int3"),
        (&[0xcd, 0x20][..], "int 0x20"),
        (&[0x0f, 0x0b][..], "ud2"),
    ] {
        let mut memory = MemoryManager::new();
        memory.set_bits(32);
        let rwx = MemoryFlags::new(true, true, true, false);
        assert!(memory.map_fixed(0x10000, 0x1000, rwx, "code"));
        assert!(memory.write(0x10000, code));
        let mut regs = Registers {
            rip: 0x10000,
            ..Default::default()
        };
        let mut arch = X86::new(&mut memory, 32);
        let info = arch.step(&mut regs);
        assert_eq!(info.result, StepResult::Syscall, "{comment}");
    }
}

#[test]
fn step_budget_bounds_execution() {
    // `jmp $` runs forever; the run() budget must bound it.
    let mut memory = MemoryManager::new();
    memory.set_bits(32);
    let rwx = MemoryFlags::new(true, true, true, false);
    assert!(memory.map_fixed(0x10000, 0x1000, rwx, "code"));
    assert!(memory.write(0x10000, &[0xebu8, 0xfe]));
    let mut regs = Registers {
        rip: 0x10000,
        ..Default::default()
    };
    let mut arch = X86::new(&mut memory, 32);
    let mut info = Default::default();
    let ran = arch.run(&mut regs, 1000, &mut info);
    assert_eq!(ran, 1000);
    assert_eq!(info.result, StepResult::Ok);
    assert_eq!(regs.rip, 0x10000);
}

#[test]
fn invalid_opcode_reports_unimplemented() {
    let mut memory = MemoryManager::new();
    memory.set_bits(32);
    let rwx = MemoryFlags::new(true, true, true, false);
    assert!(memory.map_fixed(0x10000, 0x1000, rwx, "code"));
    // `0f ff` (invalid group-5 /7) has no upstream decode — it must fail
    // closed as Unimplemented, never silently succeed.
    assert!(memory.write(0x10000, &[0x0fu8, 0xff]));
    let mut regs = Registers {
        rip: 0x10000,
        ..Default::default()
    };
    let mut arch = X86::new(&mut memory, 32);
    let info = arch.step(&mut regs);
    assert_eq!(info.result, StepResult::Unimplemented);
}

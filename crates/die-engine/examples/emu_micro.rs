//! Dev harness mirroring `xemulator-oracle micro <hex> [steps]` —
//! prints the same compact JSON so `tools/emu_diff.py` can compare the
//! Rust emulator against the pinned upstream oracle byte-for-byte.

use die_engine::emulate::micro_run;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: emu_micro <hex-bytes> [max-steps]");
        std::process::exit(2);
    }
    let hex: String = args[1].chars().filter(|c| !c.is_whitespace()).collect();
    if !hex.len().is_multiple_of(2) || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        eprintln!("invalid hex input");
        std::process::exit(2);
    }
    let code: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect();
    let max_steps: i64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(64);
    println!("{}", micro_run(&code, max_steps).to_json());
}

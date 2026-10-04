//! Unpack-report driver mirroring `tools/xemulator-oracle` `unpack` mode.
//!
//! Usage: `unpack_report <input>` — prints a JSON array with one report
//! per claiming unpacker (installsimple, aspack, petite), shaped like
//! the oracle output so `tools/emu_diff.py`-style comparisons apply.

use diec_engine::unpack;
use std::fmt::Write as _;

/// FNV-1a 64 over `data`, hex-formatted like the oracle.
fn fnv64(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// JSON-escape a string value (ASCII fixtures only need basics).
fn jesc(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Emit one oracle-shaped member object.
fn member_json(name: &str, unpacked: bool, out_size: usize, hash: &str) -> String {
    let mut s = String::from("{");
    let _ = write!(
        s,
        "\"fnv64\":\"{hash}\",\"info\":\"\",\"name\":\"{}\",\"out_size\":{out_size},\"unpacked\":{unpacked}",
        jesc(name)
    );
    s.push('}');
    s
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: unpack_report <input>");
        std::process::exit(2);
    });
    let data = std::fs::read(&path).expect("cannot open input");

    let mut reports: Vec<String> = Vec::new();

    // InstallSimple — container extractor; member names come from the
    // manifest record like upstream `infoCurrent`.
    if unpack::detect_installsimple(&data).is_some() {
        match unpack::extract_installsimple(&data, -1) {
            Ok(records) => {
                let members: Vec<String> = records
                    .iter()
                    .enumerate()
                    .map(|(i, r)| {
                        let name = if r.name.is_empty() {
                            format!("record_{i}")
                        } else {
                            r.name.clone()
                        };
                        member_json(&name, true, r.data.len(), &fnv64(&r.data))
                    })
                    .collect();
                reports.push(format!(
                    "{{\"init_unpack\":true,\"members\":[{}],\"packer\":\"installsimple\",\"records\":{},\"version\":\"\"}}",
                    members.join(","),
                    records.len()
                ));
            }
            Err(_) => reports.push(
                "{\"init_unpack\":false,\"packer\":\"installsimple\",\"version\":\"\"}".into(),
            ),
        }
    }

    // ASPack — single-record unpacker; the oracle writes one member file.
    if let Some(info) = unpack::detect_aspack(&data) {
        match unpack::unpack_aspack(&data, -1) {
            Ok(out) => reports.push(format!(
                "{{\"init_unpack\":true,\"members\":[{}],\"packer\":\"aspack\",\"records\":1,\"version\":\"{}\"}}",
                member_json(&path, true, out.len(), &fnv64(&out)),
                jesc(info.sversion)
            )),
            Err(_) => reports.push(format!(
                "{{\"init_unpack\":false,\"packer\":\"aspack\",\"version\":\"{}\"}}",
                jesc(info.sversion)
            )),
        }
    }

    // Petite — same single-record shape.
    if let Some(info) = unpack::detect_petite(&data) {
        match unpack::unpack_petite(&data, -1) {
            Ok(out) => reports.push(format!(
                "{{\"init_unpack\":true,\"members\":[{}],\"packer\":\"petite\",\"records\":1,\"version\":\"{}\"}}",
                member_json(&path, true, out.len(), &fnv64(&out)),
                jesc(info.sversion)
            )),
            Err(_) => reports.push(format!(
                "{{\"init_unpack\":false,\"packer\":\"petite\",\"version\":\"{}\"}}",
                jesc(info.sversion)
            )),
        }
    }

    println!("[{}]", reports.join(","));
}

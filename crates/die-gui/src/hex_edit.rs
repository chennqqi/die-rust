//! Hex edit session: tracked byte writes with an in-memory undo chain.
//!
//! `edit_bytes_at_offset` (string_extractor) already performs the atomic
//! `.bak` + in-place write; this module layers an edit *session* on top so
//! the hex view can undo the most recent writes (upstream XHexView's edit
//! mode semantics — edits are immediate but reversible while the view is
//! open). The undo stack is per-path, in-memory only, and capped to bound
//! memory use.

use std::collections::HashMap;
use std::sync::Mutex;

/// Maximum entries kept in a per-path undo stack.
const MAX_UNDO_DEPTH: usize = 256;

/// Maximum bytes remembered per undo record (mirrors `MAX_EDIT_BYTES`).
const MAX_UNDO_BYTES: usize = 1 << 20;

/// One reversible write: the bytes that were overwritten.
#[derive(Debug)]
struct UndoRecord {
    /// File offset that was written.
    offset: usize,
    /// Previous contents at `offset` (length = written byte count).
    old_bytes: Vec<u8>,
}

/// Per-path undo stacks keyed by the path string exactly as passed in.
static UNDO_STACKS: Mutex<Option<HashMap<String, Vec<UndoRecord>>>> = Mutex::new(None);

/// Access the stack map, initializing it on first use.
fn with_stacks<R>(f: impl FnOnce(&mut HashMap<String, Vec<UndoRecord>>) -> R) -> R {
    let mut guard = UNDO_STACKS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

/// Write `bytes` at `offset`, recording the overwritten bytes for undo.
///
/// The write itself reuses the established in-place edit semantics
/// (`.bak` creation, bounds checks, no file extension). If the underlying
/// write fails no undo record is pushed.
pub fn write(path: &str, offset: usize, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("Nothing to write".into());
    }
    // Read the previous contents for the undo record before writing.
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let end = offset.checked_add(bytes.len()).ok_or("Offset overflow")?;
    if end > data.len() {
        return Err("Write would exceed file size".into());
    }
    let old = data[offset..end].to_vec();
    crate::string_extractor::edit_bytes_at_offset(path, offset, bytes)?;
    with_stacks(|m| {
        let stack = m.entry(path.to_string()).or_default();
        stack.push(UndoRecord {
            offset,
            old_bytes: old,
        });
        if stack.len() > MAX_UNDO_DEPTH {
            // Drop the oldest entries beyond the cap.
            let excess = stack.len() - MAX_UNDO_DEPTH;
            stack.drain(0..excess);
        }
    });
    Ok(())
}

/// Undo the most recent write on `path` by restoring its previous bytes.
///
/// Returns the number of bytes restored. Errors when the stack is empty
/// or the file changed underneath us (size no longer covers the record —
/// contents may still differ; undo is best-effort like upstream).
pub fn undo(path: &str) -> Result<usize, String> {
    let record = with_stacks(|m| m.get_mut(path).and_then(|s| s.pop())).ok_or("Nothing to undo")?;
    // Restore in place; going through `edit_bytes_at_offset` would push a
    // new undo record, so write directly (backup already exists from the
    // original edit).
    let mut data = std::fs::read(path).map_err(|e| e.to_string())?;
    let end = record
        .offset
        .checked_add(record.old_bytes.len())
        .ok_or("Offset overflow")?;
    if end > data.len() {
        return Err("File shrank since edit; cannot undo safely".into());
    }
    data[record.offset..end].copy_from_slice(&record.old_bytes);
    std::fs::write(path, &data).map_err(|e| e.to_string())?;
    Ok(record.old_bytes.len())
}

/// Number of undoable writes recorded for `path`.
pub fn undo_depth(path: &str) -> usize {
    with_stacks(|m| m.get(path).map_or(0, |s| s.len()))
}

/// Drop the undo stack for `path` (e.g. when a different file is opened
/// or edits were saved externally). Missing keys are ignored.
pub fn discard(path: &str) {
    with_stacks(|m| {
        m.remove(path);
    });
}

/// Total bytes held across all undo stacks — diagnostics bound check.
#[cfg(test)]
fn retained_bytes() -> usize {
    with_stacks(|m| {
        m.values()
            .flat_map(|s| s.iter().map(|r| r.old_bytes.len()))
            .sum()
    })
}

/// Compile-time sanity: the undo ceiling stays bounded.
const _: () = assert!(MAX_UNDO_DEPTH * MAX_UNDO_BYTES <= (256 << 20));

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_file(bytes: &[u8]) -> (std::path::PathBuf, String) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        // Per-test subdirectory: tests run in parallel and each cleans up
        // its own dir, so they must not share a parent.
        let dir = std::env::temp_dir().join(format!(
            "die_hexedit_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.bin");
        fs::write(&p, bytes).unwrap();
        (dir, p.to_string_lossy().into_owned())
    }

    #[test]
    fn write_then_undo_restores_bytes() {
        let (dir, path) = temp_file(&[0u8; 16]);
        discard(&path);
        write(&path, 4, &[0xAA, 0xBB]).unwrap();
        write(&path, 8, &[0xCC]).unwrap();
        assert_eq!(undo_depth(&path), 2);
        assert_eq!(undo(&path).unwrap(), 1);
        assert_eq!(fs::read(&path).unwrap()[8], 0x00);
        assert_eq!(undo(&path).unwrap(), 2);
        assert!(fs::read(&path).unwrap().iter().all(|&b| b == 0));
        assert!(undo(&path).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bounds_and_stack_cap() {
        let (dir, path) = temp_file(&[0u8; 16]);
        discard(&path);
        assert!(write(&path, 14, &[1, 2, 3]).is_err());
        assert!(write(&path, 100, &[1]).is_err());
        assert_eq!(undo_depth(&path), 0);
        // Exceeding the depth cap drops the oldest records.
        for i in 0..(MAX_UNDO_DEPTH + 8) {
            write(&path, (i % 8) + 4, &[i as u8]).unwrap();
        }
        assert_eq!(undo_depth(&path), MAX_UNDO_DEPTH);
        assert!(retained_bytes() <= MAX_UNDO_DEPTH * MAX_UNDO_BYTES);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn write_creates_backup_once() {
        let (dir, path) = temp_file(&[0x11; 8]);
        discard(&path);
        let bak = format!("{path}.bak");
        let _ = fs::remove_file(&bak);
        write(&path, 0, &[0x22]).unwrap();
        // The .bak holds the pre-edit contents.
        assert_eq!(fs::read(&bak).unwrap(), vec![0x11; 8]);
        // Each write refreshes .bak with the immediately previous state.
        write(&path, 1, &[0x33]).unwrap();
        let mut prev = vec![0x11; 8];
        prev[0] = 0x22;
        assert_eq!(fs::read(&bak).unwrap(), prev);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn discard_drops_session() {
        let (dir, path) = temp_file(&[0u8; 8]);
        discard(&path);
        write(&path, 0, &[1]).unwrap();
        write(&path, 1, &[2]).unwrap();
        assert_eq!(undo_depth(&path), 2);
        discard(&path);
        assert_eq!(undo_depth(&path), 0);
        assert!(undo(&path).is_err());
        let _ = fs::remove_dir_all(dir);
    }
}

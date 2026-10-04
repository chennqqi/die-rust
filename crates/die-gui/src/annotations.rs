//! Per-file annotation store — upstream `XInfoDB` parity (Phase 19).
//!
//! Upstream persists bookmarks/comments/labels in a SQLite database next to
//! the analyzed file. This implementation stores a sidecar JSON file at
//! `<file>.die.json`: same user-visible behavior, pure-Rust, diffable, and
//! free of native dependencies (ADR 0037). Legacy `<file>.diec.json`
//! sidecars are still read for backward compatibility.
//!
//! Entries are keyed by file offset (or RVA for labels) and content-anchored:
//! the file's SHA-256 is recorded at write time, and readers flag `stale`
//! when the file changed underneath rather than silently dropping data.

use serde::{Deserialize, Serialize};

/// One bookmark/comment/label entry anchored at `offset`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationEntry {
    /// File offset (or RVA for labels) the entry is anchored to.
    pub offset: u64,
    /// Comment text, bookmark name, or label name.
    pub text: String,
    /// Optional color tag (`"#rrggbb"`), empty = default.
    #[serde(default)]
    pub color: String,
    /// Unix seconds when the entry was written.
    #[serde(default)]
    pub created: u64,
}

/// On-disk sidecar schema (`<file>.die.json`).
#[derive(Debug, Serialize, Deserialize)]
struct AnnotationsFile {
    /// Schema version, currently `1`.
    version: u32,
    /// SHA-256 of the file at last write (hex).
    file_sha256: String,
    #[serde(default)]
    bookmarks: Vec<AnnotationEntry>,
    #[serde(default)]
    comments: Vec<AnnotationEntry>,
    #[serde(default)]
    labels: Vec<AnnotationEntry>,
}

/// Annotation store snapshot returned to the frontend.
#[derive(Debug, Serialize)]
pub struct AnnotationsDto {
    /// SHA-256 of the current file contents (hex).
    pub file_sha256: String,
    /// True when the stored hash differs — entries may be orphaned.
    pub stale: bool,
    pub bookmarks: Vec<AnnotationEntry>,
    pub comments: Vec<AnnotationEntry>,
    pub labels: Vec<AnnotationEntry>,
}

/// Sidecar path for `path` (`<file>.die.json`).
fn sidecar_path(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}.die.json", path))
}

/// Legacy sidecar path (`<file>.diec.json`, pre-rename format).
fn legacy_sidecar_path(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}.diec.json", path))
}

/// Compute the SHA-256 of `path` (hex-encoded).
fn file_hash(path: &str) -> Result<String, String> {
    use sha2::Digest as _;
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(hex::encode(sha2::Sha256::digest(data)))
}

/// Load the sidecar for `path`; returns `None` when absent or unparseable
/// (corrupt sidecars are ignored rather than fatal). Falls back to the
/// legacy `<file>.diec.json` name so existing annotations survive the
/// rename.
fn load_sidecar(path: &str) -> Option<AnnotationsFile> {
    let data = std::fs::read(sidecar_path(path))
        .or_else(|_| std::fs::read(legacy_sidecar_path(path)))
        .ok()?;
    serde_json::from_slice(&data).ok()
}

/// Write the sidecar atomically (tmp + rename).
fn save_sidecar(path: &str, file: &AnnotationsFile) -> Result<(), String> {
    let dst = sidecar_path(path);
    let tmp = dst.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(file).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &dst).map_err(|e| e.to_string())
}

fn empty_file(hash: String) -> AnnotationsFile {
    AnnotationsFile {
        version: 1,
        file_sha256: hash,
        bookmarks: Vec::new(),
        comments: Vec::new(),
        labels: Vec::new(),
    }
}

/// Select the entry list for `kind` (`"bookmark"`, `"comment"`, `"label"`).
fn list_for<'a>(f: &'a mut AnnotationsFile, kind: &str) -> Option<&'a mut Vec<AnnotationEntry>> {
    match kind {
        "bookmark" => Some(&mut f.bookmarks),
        "comment" => Some(&mut f.comments),
        "label" => Some(&mut f.labels),
        _ => None,
    }
}

fn to_dto(file: &AnnotationsFile, current_hash: &str) -> AnnotationsDto {
    AnnotationsDto {
        file_sha256: current_hash.to_string(),
        stale: file.file_sha256 != current_hash,
        bookmarks: file.bookmarks.clone(),
        comments: file.comments.clone(),
        labels: file.labels.clone(),
    }
}

/// List annotations for `path` (fresh state when no sidecar exists).
pub fn list(path: &str) -> Result<AnnotationsDto, String> {
    let hash = file_hash(path)?;
    let file = load_sidecar(path).unwrap_or_else(|| empty_file(hash.clone()));
    Ok(to_dto(&file, &hash))
}

/// Insert or replace the entry at `(kind, offset)`; one entry per offset
/// per kind (mirrors upstream's unique-offset bookmark model).
///
/// Annotations are refused when the stored sidecar hash is stale relative
/// to the current file — entries anchored to a different file version must
/// be confirmed by the user first (see `stale` in [`list`]).
pub fn upsert(
    path: &str,
    kind: &str,
    offset: u64,
    text: String,
    color: String,
) -> Result<AnnotationsDto, String> {
    if text.is_empty() {
        return Err("annotation text must not be empty".into());
    }
    if text.len() > 4096 {
        return Err("annotation text too long (max 4096)".into());
    }
    let hash = file_hash(path)?;
    let mut file = load_sidecar(path).unwrap_or_else(|| empty_file(hash.clone()));
    if file.file_sha256 != hash {
        return Err("file changed since annotations were written".into());
    }
    let list = list_for(&mut file, kind).ok_or_else(|| format!("unknown kind: {}", kind))?;
    if list.len() >= 65536 {
        return Err("annotation count limit exceeded".into());
    }
    let entry = AnnotationEntry {
        offset,
        text,
        color,
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    if let Some(existing) = list.iter_mut().find(|e| e.offset == offset) {
        *existing = entry;
    } else {
        list.push(entry);
        list.sort_by_key(|e| e.offset);
    }
    save_sidecar(path, &file)?;
    Ok(to_dto(&file, &hash))
}

/// Delete the entry at `(kind, offset)`; missing entries are a no-op.
pub fn delete(path: &str, kind: &str, offset: u64) -> Result<AnnotationsDto, String> {
    let hash = file_hash(path)?;
    let mut file = match load_sidecar(path) {
        Some(f) => f,
        None => return Ok(to_dto(&empty_file(hash.clone()), &hash)),
    };
    if let Some(list) = list_for(&mut file, kind) {
        list.retain(|e| e.offset != offset);
        save_sidecar(path, &file)?;
    }
    Ok(to_dto(&file, &hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(data: &[u8]) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("die_ann_{}_{}", std::process::id(), nanos));
        std::fs::write(&p, data).unwrap();
        // Clean up a stale sidecar from a previous run.
        let _ = std::fs::remove_file(sidecar_path(p.to_str().unwrap()));
        let _ = std::fs::remove_file(legacy_sidecar_path(p.to_str().unwrap()));
        p.to_str().unwrap().to_string()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(sidecar_path(path));
        let _ = std::fs::remove_file(legacy_sidecar_path(path));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn upsert_list_delete_roundtrip() {
        let path = temp_file(b"MZ test data");
        let dto = upsert(&path, "comment", 4, "entry point".into(), "".into()).unwrap();
        assert_eq!(dto.comments.len(), 1);
        assert!(!dto.stale);
        upsert(&path, "bookmark", 0, "hdr".into(), "#ff0000".into()).unwrap();
        upsert(&path, "label", 0x401000, "start".into(), "".into()).unwrap();
        let dto = list(&path).unwrap();
        assert_eq!(dto.bookmarks.len(), 1);
        assert_eq!(dto.comments.len(), 1);
        assert_eq!(dto.labels.len(), 1);
        // Replace same offset — still one entry.
        upsert(&path, "comment", 4, "updated".into(), "".into()).unwrap();
        let dto = list(&path).unwrap();
        assert_eq!(dto.comments.len(), 1);
        assert_eq!(dto.comments[0].text, "updated");
        delete(&path, "comment", 4).unwrap();
        let dto = list(&path).unwrap();
        assert!(dto.comments.is_empty());
        assert_eq!(dto.bookmarks.len(), 1);
        cleanup(&path);
    }

    #[test]
    fn stale_flag_on_file_change() {
        let path = temp_file(b"version one");
        upsert(&path, "comment", 0, "v1".into(), "".into()).unwrap();
        std::fs::write(&path, b"version two").unwrap();
        let dto = list(&path).unwrap();
        assert!(dto.stale);
        // Writes against a stale file are refused.
        assert!(upsert(&path, "comment", 0, "v2".into(), "".into()).is_err());
        cleanup(&path);
    }

    #[test]
    fn corrupt_sidecar_ignored() {
        let path = temp_file(b"data");
        std::fs::write(sidecar_path(&path), b"not json").unwrap();
        let dto = list(&path).unwrap();
        assert!(dto.comments.is_empty());
        assert!(!dto.stale);
        cleanup(&path);
    }

    #[test]
    fn legacy_sidecar_still_read() {
        let path = temp_file(b"legacy data");
        // Write a sidecar under the old `.diec.json` name; list() must
        // pick it up via the fallback, and the next save migrates it.
        let legacy = AnnotationsFile {
            version: 1,
            file_sha256: file_hash(&path).unwrap(),
            bookmarks: vec![],
            comments: vec![AnnotationEntry {
                offset: 0,
                text: "old".into(),
                color: "".into(),
                created: 1,
            }],
            labels: vec![],
        };
        std::fs::write(
            legacy_sidecar_path(&path),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let dto = list(&path).unwrap();
        assert_eq!(dto.comments.len(), 1);
        assert_eq!(dto.comments[0].text, "old");
        cleanup(&path);
    }

    #[test]
    fn unknown_kind_rejected() {
        let path = temp_file(b"data");
        assert!(upsert(&path, "bogus", 0, "x".into(), "".into()).is_err());
        assert!(delete(&path, "bogus", 0).is_ok());
        cleanup(&path);
    }
}

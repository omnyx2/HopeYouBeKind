//! Folder manifest: the per-file (path, size, mtime, content-hash) summary the
//! two sides exchange to decide what to transfer.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Prefix for the atomic-write temp files we drop next to the target; never
/// included in a manifest so two nodes don't try to sync each other's scratch.
pub const TMP_PREFIX: &str = ".minisync-tmp-";

/// One file in the synced tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path relative to the sync root, `/`-separated, NFC-agnostic raw bytes as
    /// the OS reports them. (v0.2 does not Unicode-normalize — see README.)
    pub path: String,
    pub size: u64,
    /// Modification time in Unix milliseconds. The last-writer-wins clock.
    pub mtime_ms: i64,
    /// Lowercase hex SHA-256 of the file contents.
    pub hash: String,
}

/// Scan `root` recursively into a sorted manifest. Symlinks, the temp files, and
/// dotfiles/dotdirs (e.g. `.git`, `.minisync`) are skipped. Unreadable files are
/// logged and omitted rather than aborting the whole scan.
pub fn scan(root: &Path) -> Vec<FileEntry> {
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<FileEntry>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "cannot read dir; skipping");
            return;
        }
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        // Skip hidden entries (incl. .git, .minisync) and our scratch files.
        if name.starts_with('.') || name.starts_with(TMP_PREFIX) {
            continue;
        }
        let path = ent.path();
        let ft = match ent.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue; // v0.2: don't follow or sync symlinks
        }
        if ft.is_dir() {
            walk(root, &path, out);
        } else if ft.is_file() {
            if let Some(entry) = entry_for(root, &path) {
                out.push(entry);
            }
        }
    }
}

fn entry_for(root: &Path, path: &Path) -> Option<FileEntry> {
    let rel = path.strip_prefix(root).ok()?;
    let rel = rel_to_string(rel);
    let meta = std::fs::metadata(path).ok()?;
    let mtime_ms = system_time_to_ms(meta.modified().ok()?);
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(file = %path.display(), error = %e, "cannot read file; skipping");
            return None;
        }
    };
    Some(FileEntry {
        path: rel,
        size: meta.len(),
        mtime_ms,
        hash: hash_bytes(&bytes),
    })
}

/// Join relative components with `/` so the path is portable across OSes.
fn rel_to_string(rel: &Path) -> String {
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Resolve a manifest path (relative, `/`-separated) back to an absolute path
/// under `root`, **rejecting traversal** (`..`, absolute, empty). Returns `None`
/// if the path would escape the sync root — a hardening lesson carried over from
/// the standalone MiniSync (a peer must never write outside the shared folder).
pub fn safe_join(root: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() {
        return None;
    }
    let mut out = root.to_path_buf();
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return None;
        }
        // A backslash or a drive-ish component could smuggle traversal on some
        // platforms; keep the gate lexical and strict.
        if comp.contains('\\') || comp.contains(':') {
            return None;
        }
        out.push(comp);
    }
    Some(out)
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn system_time_to_ms(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        // Pre-1970 mtime: represent as negative ms.
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn safe_join_blocks_traversal() {
        let root = Path::new("/tmp/root");
        assert!(safe_join(root, "a/b.txt").is_some());
        assert!(safe_join(root, "../escape").is_none());
        assert!(safe_join(root, "a/../../escape").is_none());
        assert!(safe_join(root, "/etc/passwd").is_none());
        assert!(safe_join(root, "").is_none());
        assert!(safe_join(root, "a/b:c").is_none());
    }
}

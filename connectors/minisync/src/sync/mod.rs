//! The MiniSync folder-sync engine: a tiny last-writer-wins reconciler that runs
//! over a plain TCP link to each peer (Lattice routes/encrypts that link over the
//! overlay; this layer is oblivious to the mesh).
//!
//! ## Conflict policy (v0.2)
//! **Last-writer-wins by mtime.** For each path the side with the larger
//! modification time wins; the loser's copy is overwritten. Ties (equal mtime,
//! differing content) break deterministically on the larger SHA-256 hex, so both
//! peers independently pick the same winner and converge. Identical content
//! (equal hash) is never re-transferred regardless of mtime.
//!
//! ## Known v0.2 limitations (see README)
//! - Whole-file, in-memory transfers — no chunking/resume; [`wire::MAX_FRAME`]
//!   caps a file at 512 MiB.
//! - No deletion propagation (no tombstones): removing a file on one node does
//!   not remove it on others; it reappears on the next reconcile.
//! - No rename detection; a rename is a delete+create.

pub mod manifest;
pub mod wire;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use manifest::{safe_join, FileEntry};
use wire::{read_frame, write_frame, FileData, SyncMsg};

/// Per-peer session timeout — a hung peer can't stall the reconcile loop.
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Which side holds the winning copy of a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Winner {
    Local,
    Remote,
    Same,
}

fn compare(l: Option<&FileEntry>, r: Option<&FileEntry>) -> Winner {
    match (l, r) {
        (Some(_), None) => Winner::Local,
        (None, Some(_)) => Winner::Remote,
        (Some(a), Some(b)) => {
            if a.hash == b.hash {
                Winner::Same
            } else if a.mtime_ms > b.mtime_ms {
                Winner::Local
            } else if b.mtime_ms > a.mtime_ms {
                Winner::Remote
            } else if a.hash > b.hash {
                Winner::Local
            } else {
                Winner::Remote
            }
        }
        (None, None) => Winner::Same,
    }
}

/// What `local` needs to do vs `remote`: `pull` = paths to fetch from remote
/// (remote wins), `push` = paths to send to remote (local wins).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub pull: Vec<String>,
    pub push: Vec<String>,
}

pub fn diff(local: &[FileEntry], remote: &[FileEntry]) -> Diff {
    use std::collections::BTreeMap;
    let lm: BTreeMap<&str, &FileEntry> = local.iter().map(|e| (e.path.as_str(), e)).collect();
    let rm: BTreeMap<&str, &FileEntry> = remote.iter().map(|e| (e.path.as_str(), e)).collect();
    let mut paths: Vec<&str> = lm.keys().chain(rm.keys()).copied().collect();
    paths.sort_unstable();
    paths.dedup();

    let mut d = Diff::default();
    for p in paths {
        match compare(lm.get(p).copied(), rm.get(p).copied()) {
            Winner::Local => d.push.push(p.to_string()),
            Winner::Remote => d.pull.push(p.to_string()),
            Winner::Same => {}
        }
    }
    d
}

/// Load the given relative paths from disk into transferable [`FileData`].
/// Paths that no longer exist (changed/removed since the manifest) are skipped.
fn load_files(root: &Path, paths: &[String]) -> Vec<FileData> {
    let mut out = Vec::with_capacity(paths.len());
    for rel in paths {
        let Some(abs) = safe_join(root, rel) else {
            tracing::warn!(path = %rel, "refusing unsafe path on send");
            continue;
        };
        let meta = match std::fs::metadata(&abs) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let bytes = match std::fs::read(&abs) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(path = %rel, error = %e, "cannot read for send");
                continue;
            }
        };
        if bytes.len() as u64 > wire::MAX_FRAME as u64 {
            tracing::warn!(path = %rel, size = bytes.len(), "file exceeds MAX_FRAME; skipping");
            continue;
        }
        let mtime_ms = meta
            .modified()
            .map(manifest::system_time_to_ms)
            .unwrap_or(0);
        out.push(FileData {
            path: rel.clone(),
            mtime_ms,
            bytes,
        });
    }
    out
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Apply one received file under `root`, last-writer-wins. Returns `Ok(true)` if
/// the file was written. Rejects path traversal; refuses to clobber a strictly
/// newer local copy; writes atomically (temp + rename) and stamps the source
/// mtime so the two sides converge and stop re-transferring.
pub fn apply_file(root: &Path, fd: &FileData) -> std::io::Result<bool> {
    let Some(abs) = safe_join(root, &fd.path) else {
        tracing::warn!(path = %fd.path, "rejecting unsafe path on receive");
        return Ok(false);
    };

    // LWW guard: don't overwrite a local copy that is strictly newer, and don't
    // rewrite identical content.
    if let Ok(meta) = std::fs::metadata(&abs) {
        let local_mtime = meta
            .modified()
            .map(manifest::system_time_to_ms)
            .unwrap_or(0);
        if let Ok(existing) = std::fs::read(&abs) {
            if manifest::hash_bytes(&existing) == manifest::hash_bytes(&fd.bytes) {
                return Ok(false); // already converged
            }
            if local_mtime > fd.mtime_ms {
                tracing::debug!(path = %fd.path, "local newer; keeping local (LWW)");
                return Ok(false);
            }
        }
    }

    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let tmp = abs.with_file_name(format!("{}{pid}-{seq}", manifest::TMP_PREFIX,));
    std::fs::write(&tmp, &fd.bytes)?;
    // Stamp the source mtime before the rename so the visible file lands with the
    // converged time in one atomic step.
    let (secs, nanos) = ms_to_unix(fd.mtime_ms);
    let _ = filetime::set_file_mtime(&tmp, filetime::FileTime::from_unix_time(secs, nanos));
    std::fs::rename(&tmp, &abs)?;
    tracing::info!(path = %fd.path, bytes = fd.bytes.len(), "applied");
    Ok(true)
}

fn ms_to_unix(ms: i64) -> (i64, u32) {
    let secs = ms.div_euclid(1000);
    let nanos = (ms.rem_euclid(1000) * 1_000_000) as u32;
    (secs, nanos)
}

/// Serve one inbound peer session (we are the responder). Reads the peer's
/// manifest, replies with what we want pulled + the files we push, then applies
/// the files the peer sends back.
pub async fn serve_session<S>(root: &Path, mut stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let remote = match read_frame(&mut stream).await? {
        Some(SyncMsg::Manifest(m)) => m,
        other => {
            tracing::warn!(?other, "expected Manifest from peer");
            return Ok(());
        }
    };
    let local = manifest::scan(root);
    let d = diff(&local, &remote);
    let push = load_files(root, &d.push);
    tracing::debug!(
        want = d.pull.len(),
        push = push.len(),
        "responder reconcile"
    );
    write_frame(&mut stream, &SyncMsg::Reconcile { want: d.pull, push }).await?;

    match read_frame(&mut stream).await? {
        Some(SyncMsg::Files(files)) => {
            for fd in &files {
                if let Err(e) = apply_file(root, fd) {
                    tracing::warn!(path = %fd.path, error = %e, "apply failed");
                }
            }
        }
        Some(other) => tracing::warn!(?other, "expected Files from peer"),
        None => {}
    }
    Ok(())
}

/// Initiate a session to `addr` (we are the initiator). Sends our manifest,
/// applies what the peer pushes, then sends the files the peer asked for.
pub async fn sync_with_peer(root: &Path, addr: SocketAddr) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    let local = manifest::scan(root);
    write_frame(&mut stream, &SyncMsg::Manifest(local)).await?;

    let (want, push) = match read_frame(&mut stream).await? {
        Some(SyncMsg::Reconcile { want, push }) => (want, push),
        other => {
            tracing::warn!(?other, "expected Reconcile from peer");
            return Ok(());
        }
    };
    for fd in &push {
        if let Err(e) = apply_file(root, fd) {
            tracing::warn!(path = %fd.path, error = %e, "apply failed");
        }
    }
    let files = load_files(root, &want);
    tracing::debug!(applied = push.len(), sent = files.len(), peer = %addr, "initiator reconcile");
    write_frame(&mut stream, &SyncMsg::Files(files)).await?;
    Ok(())
}

/// Bind the sync server and accept peer sessions until the listener errors.
pub async fn run_server(root: PathBuf, listen: SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    run_server_on(root, listener).await
}

/// Accept peer sessions on an already-bound listener (lets a caller pick an
/// ephemeral port and learn the actual address first; used by the tests).
pub async fn run_server_on(root: PathBuf, listener: TcpListener) -> std::io::Result<()> {
    let actual = listener.local_addr()?;
    tracing::info!(addr = %actual, "sync server listening");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let root = root.clone();
        tokio::spawn(async move {
            tracing::debug!(peer = %peer, "inbound session");
            match tokio::time::timeout(SESSION_TIMEOUT, serve_session(&root, stream)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(peer = %peer, error = %e, "session error"),
                Err(_) => tracing::warn!(peer = %peer, "session timed out"),
            }
        });
    }
}

/// Drive reconcile passes: every `interval`, and whenever the discovered peer set
/// changes, sync against each known peer. Runs until the peers channel closes.
pub async fn run_sync_loop(
    root: PathBuf,
    mut peers_rx: watch::Receiver<Vec<SocketAddr>>,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let peers = peers_rx.borrow().clone();
        for addr in peers {
            match tokio::time::timeout(SESSION_TIMEOUT, sync_with_peer(&root, addr)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::debug!(peer = %addr, error = %e, "reconcile failed"),
                Err(_) => tracing::warn!(peer = %addr, "reconcile timed out"),
            }
        }
        tokio::select! {
            _ = tick.tick() => {}
            changed = peers_rx.changed() => {
                if changed.is_err() { break; } // sender dropped → shut down
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(path: &str, mtime: i64, hash: &str) -> FileEntry {
        FileEntry {
            path: path.into(),
            size: 0,
            mtime_ms: mtime,
            hash: hash.into(),
        }
    }

    #[test]
    fn diff_basic() {
        let local = vec![
            e("a", 10, "h1"),
            e("both_same", 5, "same"),
            e("local_new", 20, "L"),
        ];
        let remote = vec![
            e("b", 10, "h2"),
            e("both_same", 9, "same"),
            e("local_new", 10, "R"),
        ];
        let d = diff(&local, &remote);
        // local-only "a" → push; remote-only "b" → pull; same hash ignored;
        // local_new has larger mtime → push.
        assert_eq!(d.push, vec!["a".to_string(), "local_new".to_string()]);
        assert_eq!(d.pull, vec!["b".to_string()]);
    }

    #[test]
    fn diff_tiebreak_on_hash() {
        // equal mtime, differing content → larger hash wins deterministically.
        let local = vec![e("x", 5, "aaa")];
        let remote = vec![e("x", 5, "zzz")];
        let d = diff(&local, &remote);
        assert_eq!(d.pull, vec!["x".to_string()]); // remote "zzz" > "aaa"
        assert!(d.push.is_empty());
        // symmetric from the other side
        let d2 = diff(&remote, &local);
        assert_eq!(d2.push, vec!["x".to_string()]);
    }

    #[test]
    fn ms_to_unix_handles_fraction_and_negative() {
        assert_eq!(ms_to_unix(1500), (1, 500_000_000));
        assert_eq!(ms_to_unix(0), (0, 0));
        assert_eq!(ms_to_unix(-1), (-1, 999_000_000));
    }
}

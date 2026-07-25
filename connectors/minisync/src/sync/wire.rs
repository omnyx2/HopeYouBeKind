//! The MiniSync peer-to-peer sync wire protocol — self-contained and
//! independent of Lattice (Lattice only told us *where* the peer is; this is how
//! two MiniSync instances actually reconcile a folder over that overlay TCP link).
//!
//! Framing: each message is a 4-byte big-endian length prefix followed by a
//! `bincode`-encoded [`SyncMsg`]. bincode keeps binary file bytes compact (no
//! base64). A hard [`MAX_FRAME`] cap is enforced before allocating, so a peer
//! cannot trigger a multi-gigabyte allocation (memory-bomb hardening).

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::manifest::FileEntry;

/// Largest single frame we will read. 512 MiB is the effective per-file ceiling
/// for v0.2's whole-file transfers.
pub const MAX_FRAME: u32 = 512 * 1024 * 1024;

/// A file's full contents plus the mtime to stamp on the receiver so both sides
/// converge to an identical (mtime, hash) and stop re-transferring.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileData {
    pub path: String,
    pub mtime_ms: i64,
    pub bytes: Vec<u8>,
}

/// One step of the reconcile handshake. A session is exactly:
///   client → [`SyncMsg::Manifest`]
///   server → [`SyncMsg::Reconcile`]   (what server wants pulled + what it pushes)
///   client → [`SyncMsg::Files`]       (the files server asked for)
/// after which both folders hold the last-writer-wins union.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncMsg {
    /// Initiator's view of its folder.
    Manifest(Vec<FileEntry>),
    /// Responder's diff: `want` = paths it wants the initiator to send (initiator
    /// is newer / responder lacks them); `push` = files the responder is newer on
    /// and ships inline for the initiator to apply.
    Reconcile {
        want: Vec<String>,
        push: Vec<FileData>,
    },
    /// Initiator's reply to `want`: the requested files.
    Files(Vec<FileData>),
}

/// Write one length-prefixed bincode frame.
pub async fn write_frame<W>(w: &mut W, msg: &SyncMsg) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = bincode::serialize(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if body.len() as u64 > MAX_FRAME as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("outgoing frame {} exceeds MAX_FRAME", body.len()),
        ));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed bincode frame, or `None` on a clean EOF at a frame
/// boundary. Rejects oversized frames before allocating.
pub async fn read_frame<R>(r: &mut R) -> std::io::Result<Option<SyncMsg>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("incoming frame {len} exceeds MAX_FRAME"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    let msg = bincode::deserialize(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip() {
        let msg = SyncMsg::Files(vec![FileData {
            path: "a/b.txt".into(),
            mtime_ms: 123,
            bytes: vec![1, 2, 3, 4],
        }]);
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).await.unwrap();
        let mut cur = std::io::Cursor::new(buf);
        let got = read_frame(&mut cur).await.unwrap().unwrap();
        match got {
            SyncMsg::Files(v) => {
                assert_eq!(v[0].path, "a/b.txt");
                assert_eq!(v[0].bytes, vec![1, 2, 3, 4]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn clean_eof_is_none() {
        let mut cur = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_frame(&mut cur).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversize_len_rejected() {
        let mut buf = (MAX_FRAME + 1).to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        let mut cur = std::io::Cursor::new(buf);
        assert!(read_frame(&mut cur).await.is_err());
    }
}

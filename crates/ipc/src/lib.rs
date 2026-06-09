//! Local IPC between the privileged daemon and its unprivileged clients.
//!
//! Wire format: newline-delimited JSON. One [`Request`] per line client→daemon,
//! one [`Response`] per line back. Transport is a Unix domain socket (macOS /
//! Linux). Windows named-pipe support arrives with the Windows port (v0.5).

use std::future::Future;
use std::io;

use lattice_proto::ipc::{Request, Response};

/// Serve IPC requests until the listener errors. `handler` maps each request to
/// a response; it is cloned per connection so it may capture shared state (e.g.
/// an `EngineHandle`).
#[cfg(unix)]
pub async fn serve<H, F>(socket_path: &str, handler: H) -> io::Result<()>
where
    H: Fn(Request) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response> + Send,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    // Clear any stale socket from a previous run.
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;

    loop {
        let (stream, _addr) = listener.accept().await?;
        let handler = handler.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = stream.into_split();
            let mut lines = BufReader::new(read_half).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                let response = match serde_json::from_str::<Request>(&line) {
                    Ok(req) => handler(req).await,
                    Err(e) => Response::Error {
                        message: format!("bad request: {e}"),
                    },
                };
                let mut bytes = serde_json::to_vec(&response).unwrap_or_default();
                bytes.push(b'\n');
                if write_half.write_all(&bytes).await.is_err() {
                    break;
                }
            }
        });
    }
}

#[cfg(not(unix))]
pub async fn serve<H, F>(_socket_path: &str, _handler: H) -> io::Result<()>
where
    H: Fn(Request) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response> + Send,
{
    // Named-pipe IPC for Windows is future work; until then the daemon runs
    // without a control channel rather than exiting. Park forever.
    std::future::pending::<()>().await;
    Ok(())
}

/// Send one request to the daemon and read its response.
#[cfg(unix)]
pub async fn request(socket_path: &str, req: Request) -> io::Result<Response> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path).await?;
    let (read_half, mut write_half) = stream.into_split();

    let mut payload =
        serde_json::to_vec(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    payload.push(b'\n');
    write_half.write_all(&payload).await?;

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    serde_json::from_str(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(not(unix))]
pub async fn request(_socket_path: &str, _req: Request) -> io::Result<Response> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IPC client on this platform lands in v0.5 (named pipes)",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use lattice_proto::ipc::NodeStatus;
    use lattice_proto::NodeId;

    #[tokio::test]
    async fn request_response_round_trip() {
        let dir = std::env::temp_dir();
        let path = dir
            .join(format!("lattice-test-{}.sock", std::process::id()))
            .to_string_lossy()
            .to_string();

        let server_path = path.clone();
        tokio::spawn(async move {
            let _ = serve(&server_path, |req| async move {
                match req {
                    Request::Status => Response::Status(NodeStatus {
                        id: NodeId([7u8; 32]),
                        virtual_ip: None,
                        running: true,
                        peer_count: 3,
                    }),
                    _ => Response::Done,
                }
            })
            .await;
        });

        // Give the listener a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = request(&path, Request::Status).await.unwrap();
        match resp {
            Response::Status(s) => {
                assert!(s.running);
                assert_eq!(s.peer_count, 3);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        let done = request(&path, Request::Up).await.unwrap();
        assert!(matches!(done, Response::Done));
    }
}

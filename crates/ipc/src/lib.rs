//! Local IPC between the privileged daemon and its unprivileged clients.
//!
//! Wire format: newline-delimited JSON. One [`Request`] per line client→daemon,
//! one [`Response`] per line back. Transport is a Unix domain socket (macOS /
//! Linux). Windows named-pipe support arrives with the Windows port (v0.5).

use std::future::Future;
use std::io;

use lattice_proto::ipc::{Request, Response};

/// The process name of the client connected on `stream`, if it can be
/// determined — used to authorize sensitive requests (e.g. the mesh health
/// check) by caller identity. This is a WEAK check: a process can be named
/// anything, so it gates convenience, not a real trust boundary. See
/// docs/HEALTH_CHECK.md.
#[cfg(unix)]
fn peer_process_name(stream: &tokio::net::UnixStream) -> Option<String> {
    use std::os::unix::io::AsRawFd;
    let pid = peer_pid(stream.as_raw_fd())?;
    process_name(pid)
}

#[cfg(target_os = "linux")]
fn peer_pid(fd: std::os::unix::io::RawFd) -> Option<i32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0 && cred.pid > 0).then_some(cred.pid)
}

#[cfg(target_os = "macos")]
fn peer_pid(fd: std::os::unix::io::RawFd) -> Option<i32> {
    // Darwin <sys/un.h>: SOL_LOCAL = 0, LOCAL_PEERPID = 0x002.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0 && pid > 0).then_some(pid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_pid(_fd: std::os::unix::io::RawFd) -> Option<i32> {
    None
}

#[cfg(target_os = "linux")]
fn process_name(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "macos")]
fn process_name(pid: i32) -> Option<String> {
    // proc_pidpath yields the executable's full path; its basename is the
    // "process name" we match against the allow-list.
    const MAXLEN: usize = 4096; // PROC_PIDPATHINFO_MAXSIZE
    let mut buf = vec![0u8; MAXLEN];
    let n =
        unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, MAXLEN as u32) };
    if n <= 0 {
        return None;
    }
    let path = String::from_utf8_lossy(&buf[..n as usize]).to_string();
    path.rsplit('/')
        .next()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_name(_pid: i32) -> Option<String> {
    None
}

/// Serve IPC requests until the listener errors. `handler` maps each request —
/// plus the calling process's name, when it can be determined — to a response;
/// it is cloned per connection so it may capture shared state (e.g. an
/// `EngineHandle`). The caller name lets the daemon gate sensitive requests.
#[cfg(unix)]
pub async fn serve<H, F>(socket_path: &str, handler: H) -> io::Result<()>
where
    H: Fn(Request, Option<String>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response> + Send,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    // Clear any stale socket from a previous run.
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;

    // The daemon usually runs as root (to create the TUN device), which would
    // otherwise leave the socket root-only. Loosen it so the unprivileged CLI
    // and GUI can connect without sudo.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666));
    }

    loop {
        let (stream, _addr) = listener.accept().await?;
        // Resolve the connecting process once per connection; reused for every
        // request on it, so the daemon can authorize by caller identity.
        let peer = peer_process_name(&stream);
        let handler = handler.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = stream.into_split();
            let mut lines = BufReader::new(read_half).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                let response = match serde_json::from_str::<Request>(&line) {
                    Ok(req) => handler(req, peer.clone()).await,
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
    H: Fn(Request, Option<String>) -> F + Clone + Send + Sync + 'static,
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
            let _ = serve(&server_path, |req, _peer| async move {
                match req {
                    Request::Status => Response::Status(NodeStatus {
                        id: NodeId([7u8; 32]),
                        virtual_ip: None,
                        public_addr: None,
                        running: true,
                        peer_count: 3,
                        exit_node: None,
                        is_exit: false,
                        relay: None,
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

    /// The server must resolve the *connecting* process's name from the socket
    /// peer credentials (SO_PEERCRED / LOCAL_PEERPID) — this is what the daemon's
    /// health-check gate authorizes against. Here client and server are the same
    /// test binary, so the resolved name is this executable's basename; we only
    /// assert it resolves to a non-empty name (i.e. the peercred path works on
    /// this platform), not its exact value.
    #[tokio::test]
    async fn server_resolves_caller_process_name() {
        let dir = std::env::temp_dir();
        let path = dir
            .join(format!("lattice-peercred-{}.sock", std::process::id()))
            .to_string_lossy()
            .to_string();

        let server_path = path.clone();
        tokio::spawn(async move {
            // Echo the resolved caller name back as a Token so the client can
            // assert on it.
            let _ = serve(&server_path, |_req, peer| async move {
                Response::Token(peer.unwrap_or_default())
            })
            .await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        match request(&path, Request::Status).await.unwrap() {
            Response::Token(name) => assert!(
                !name.is_empty(),
                "peer credentials did not resolve a caller process name"
            ),
            other => panic!("unexpected response: {other:?}"),
        }
    }
}

//! Local IPC between the privileged daemon and its unprivileged clients.
//!
//! Wire format: newline-delimited JSON. One [`Request`] per line client→daemon,
//! one [`Response`] per line back. Transport is a Unix domain socket on macOS /
//! Linux and a named pipe (`\\.\pipe\lattice`) on Windows.

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

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
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

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
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

// ----------------------------------------------------------------------------
// Windows: named-pipe transport (\\.\pipe\lattice).
// ----------------------------------------------------------------------------

/// Map any IPC path to a Windows named-pipe name. The daemon/CLI/GUI all default
/// to `/tmp/lattice.sock`, whose stem (`lattice`) becomes `\\.\pipe\lattice`, so
/// they meet on the same pipe without any Windows-specific configuration. A path
/// that's already a pipe name is passed through unchanged.
#[cfg(windows)]
fn pipe_name(socket_path: &str) -> String {
    if socket_path.starts_with(r"\\.\pipe\") || socket_path.starts_with(r"\\?\pipe\") {
        return socket_path.to_string();
    }
    let stem = std::path::Path::new(socket_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("lattice");
    format!(r"\\.\pipe\{stem}")
}

/// The connecting process's name, resolved from the pipe's client PID — the
/// Windows analogue of the unix peer-credential lookup. Same WEAK guarantee: a
/// process can be named anything, so it gates convenience, not trust.
#[cfg(windows)]
fn peer_process_name(server: &tokio::net::windows::named_pipe::NamedPipeServer) -> Option<String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    let mut pid: u32 = 0;
    let ok = unsafe { GetNamedPipeClientProcessId(server.as_raw_handle() as _, &mut pid) };
    if ok == 0 || pid == 0 {
        return None;
    }
    process_name(pid)
}

#[cfg(windows)]
fn process_name(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle == 0 {
            return None;
        }
        let mut buf = [0u16; 260];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        // Match the unix convention (linux `/proc/pid/comm`, macOS basename): the
        // bare program name. Drop the directory and a trailing `.exe` so a default
        // allow-list entry like `minisync` matches `minisync.exe`.
        path.rsplit(['\\', '/'])
            .next()
            .map(|name| name.strip_suffix(".exe").unwrap_or(name).to_string())
            .filter(|s| !s.is_empty())
    }
}

/// Owns a pipe security descriptor that grants access to authenticated users,
/// SYSTEM, and Administrators. Without it, a pipe created by a daemon running as
/// admin would be unreachable by the unprivileged GUI/CLI. Lives for the serve
/// loop (i.e. process lifetime) and frees the descriptor on drop.
#[cfg(windows)]
struct PipeSecurity {
    sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

// The security descriptor is a heap pointer we allocate once and only read while
// creating pipe instances; it never mutates after construction. Marking the
// owner Send/Sync lets the serve future (which holds it across `connect().await`)
// satisfy tokio::spawn's Send bound.
#[cfg(windows)]
unsafe impl Send for PipeSecurity {}
#[cfg(windows)]
unsafe impl Sync for PipeSecurity {}

#[cfg(windows)]
impl PipeSecurity {
    fn local_users() -> io::Result<Self> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

        // GENERIC_ALL to Authenticated Users (AU), SYSTEM (SY), Administrators (BA).
        let sddl: Vec<u16> = "D:(A;;GA;;;AU)(A;;GA;;;SY)(A;;GA;;;BA)"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1, // SDDL_REVISION_1
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };
        Ok(Self { sa })
    }

    fn as_ptr(&mut self) -> *mut std::ffi::c_void {
        &mut self.sa as *mut _ as *mut std::ffi::c_void
    }
}

#[cfg(windows)]
impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.sa.lpSecurityDescriptor.is_null() {
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.sa.lpSecurityDescriptor as _) };
        }
    }
}

/// Serve IPC requests over the named pipe until an error. Mirrors the unix
/// [`serve`]: `handler` maps each request — plus the calling process's name when
/// resolvable — to a response, and is cloned per connection.
#[cfg(windows)]
pub async fn serve<H, F>(socket_path: &str, handler: H) -> io::Result<()>
where
    H: Fn(Request, Option<String>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response> + Send,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe = pipe_name(socket_path);
    let mut security = PipeSecurity::local_users()?;

    // One pipe instance is created up front; each time a client connects we hand
    // that instance to a task and create the next instance for the next client.
    let mut server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(&pipe, security.as_ptr())
    }?;

    loop {
        server.connect().await?;
        let connected = server;
        server = unsafe {
            ServerOptions::new().create_with_security_attributes_raw(&pipe, security.as_ptr())
        }?;

        let peer = peer_process_name(&connected);
        let handler = handler.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = tokio::io::split(connected);
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

#[cfg(not(any(unix, windows)))]
pub async fn serve<H, F>(_socket_path: &str, _handler: H) -> io::Result<()>
where
    H: Fn(Request, Option<String>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response> + Send,
{
    // No IPC transport on this platform; run without a control channel rather
    // than exiting. Park forever.
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

/// Send one request to the daemon over the named pipe and read its response.
#[cfg(windows)]
pub async fn request(socket_path: &str, req: Request) -> io::Result<Response> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    let pipe = pipe_name(socket_path);

    // All pipe instances may be momentarily busy between a client connecting and
    // the server spinning up the next instance; retry briefly on ERROR_PIPE_BUSY.
    let client = loop {
        match ClientOptions::new().open(&pipe) {
            Ok(client) => break client,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    };

    let (read_half, mut write_half) = tokio::io::split(client);

    let mut payload =
        serde_json::to_vec(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    payload.push(b'\n');
    write_half.write_all(&payload).await?;

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    serde_json::from_str(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(not(any(unix, windows)))]
pub async fn request(_socket_path: &str, _req: Request) -> io::Result<Response> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no IPC transport on this platform",
    ))
}

#[cfg(test)]
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

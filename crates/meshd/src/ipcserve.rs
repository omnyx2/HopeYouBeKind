//! The IPC transport layer: unix-socket / windows-named-pipe accept loops, the
//! single-instance guard (root DATA_PLANE daemon supersedes a rootless owner —
//! docs/ERRORS.md 2026-08-07), peer-uid auth, and [`serve_conn`] — the
//! per-connection request loop that dispatches to `handle` and executes
//! PostActions. SIGTERM/SIGINT → clean shutdown lives in the unix accept loop.
//! Pure code motion out of main.rs (Phase 2); behavior unchanged.

use crate::*;

/// Should a starting meshd DEFER to whoever already owns the IPC `socket` (and exit), or TAKE IT
/// OVER? Deferring is right when a healthy peer is serving — stealing its socket would orphan its
/// TUN + leave its data-plane UDP ports bound (`Address already in use`). BUT a **rootless** owner
/// can't create a TUN at all, so it has NO data plane and would block a real (root, `DATA_PLANE`)
/// daemon forever — the exact wedge that took lablinux off the mesh (docs/ERRORS.md). So: defer to a
/// live owner UNLESS we are a root data-plane daemon and the owner is a non-root (data-plane-less)
/// instance, in which case we take the socket over. Returns `true` = defer + exit.
#[cfg(unix)]
pub(crate) fn should_defer_to_socket_owner(socket: &str, data_plane: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    if std::os::unix::net::UnixStream::connect(socket).is_err() {
        return false; // no live owner (missing/stale file) — take over
    }
    let we_can_serve = data_plane && unsafe { libc::geteuid() } == 0;
    let owner_is_rootless = std::fs::metadata(socket).map(|m| m.uid()).unwrap_or(0) != 0;
    !(we_can_serve && owner_is_rootless)
}

/// Accept IPC connections forever. The transport is platform-specific (unix socket
/// vs named pipe) but the per-connection protocol ([`serve_conn`]) is shared.
#[cfg(unix)]
/// 🟡 IPC accept loop (unix socket): bind, then for each connection check [`peer_allowed`] and
/// spawn [`serve_conn`]. Includes the single-instance / stale-socket handling.
pub(crate) async fn accept_loop(socket: &str, state: Arc<Mutex<State>>) -> anyhow::Result<()> {
    // Single-instance guard (see `should_defer_to_socket_owner`). Blindly `remove_file` + re-`bind`
    // would steal the socket from a HEALTHY meshd — orphaning its TUN and leaving its data-plane UDP
    // ports bound (`Address already in use`). So defer to a live owner — UNLESS we're a root
    // data-plane daemon and the owner is a rootless (data-plane-less) instance that would block us
    // forever, in which case we take it over. (main() already ran this check before bringup; repeated
    // here to close the start↔bind race and for the macOS/no-data-plane path.)
    let data_plane = state.lock().unwrap().data_plane;
    if should_defer_to_socket_owner(socket, data_plane) {
        elog!("meshd: another meshd already owns {socket} — deferring to it, exiting (no second instance)");
        return Ok(());
    }
    // Either no live owner (stale file) or a rootless owner we're superseding — remove + take over.
    let _ = std::fs::remove_file(socket);
    let listener = tokio::net::UnixListener::bind(socket)?;
    // meshd runs as root (for the TUN) but the desktop app connects as the logged-in
    // user, so make the socket world-rw — otherwise the GUI can't reach it.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666));
    }
    // Clean up host DNS/routes on SIGTERM (systemctl stop/restart) and SIGINT (Ctrl-C), not just on
    // the Shutdown IPC — otherwise `systemctl restart` while a split/full-tunnel is on leaves
    // `/etc/resolv.conf` pointed at our dead 127.0.0.1 proxy and the box loses DNS (2026-07-28
    // incident, docs/ERRORS.md). `shutdown_daemon` restores then `exit(0)`s.
    #[cfg(unix)]
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                if !peer_allowed(&stream) {
                    continue; // peer_allowed logs the rejection
                }
                tokio::spawn(serve_conn(stream, Arc::clone(&state)));
            }
            _ = async {
                match sigterm.as_mut() {
                    Some(s) => { s.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                elog!("meshd: SIGTERM — restoring host routes/DNS before exit");
                shutdown_daemon(&state).await; // restores DNS/routes, aborts data plane, exit(0)
            }
            _ = tokio::signal::ctrl_c() => {
                elog!("meshd: SIGINT — restoring host routes/DNS before exit");
                shutdown_daemon(&state).await;
            }
        }
    }
}

/// The connecting process's uid, read from the socket (Linux `SO_PEERCRED`,
/// macOS/BSD `getpeereid`). `None` if it can't be determined (we then fail open).
/// 🟢 The connected peer's uid (Linux `SO_PEERCRED`) — for [`peer_allowed`].
#[cfg(target_os = "linux")]
pub(crate) fn peer_uid(fd: std::os::unix::io::RawFd) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
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
    (rc == 0).then_some(cred.uid)
}

/// 🟢 The connected peer's uid (BSD/macOS `LOCAL_PEERCRED`) — for [`peer_allowed`].
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn peer_uid(fd: std::os::unix::io::RawFd) -> Option<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

/// Local-access policy for the control socket. meshd runs as root but the desktop
/// app legitimately connects as the logged-in user, so the DEFAULT is permissive
/// (trust local processes — matches the documented threat model). Setting
/// `LATTICE_ALLOW_UID=<uid>[,uid…]` opts into STRICT mode: only root, our own uid,
/// `$SUDO_UID`, and the listed uids may connect — others are refused and logged.
/// Use it on shared/multi-user hosts to stop another local user driving the daemon.
#[cfg(unix)]
/// **RISK 🟡 MED** — the socket-peer authorization gate: decides who may talk to the daemon
/// (the opt-in `LATTICE_ALLOW_UID` policy over `SO_PEERCRED`). Loosening this exposes the IPC.
pub(crate) fn peer_allowed(stream: &tokio::net::UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let allow = match std::env::var("LATTICE_ALLOW_UID") {
        Ok(v) => v,
        Err(_) => return true, // permissive default — no per-connection logging (the GUI polls often)
    };
    let uid = match peer_uid(stream.as_raw_fd()) {
        Some(u) => u,
        None => return true, // can't read creds → don't lock ourselves out
    };
    let mut allowed: Vec<u32> = vec![0, unsafe { libc::geteuid() }];
    if let Ok(Ok(u)) = std::env::var("SUDO_UID").map(|s| s.parse()) {
        allowed.push(u);
    }
    allowed.extend(
        allow
            .split(',')
            .filter_map(|p| p.trim().parse::<u32>().ok()),
    );
    if allowed.contains(&uid) {
        true
    } else {
        elog!(
            "meshd: refused control connection from uid {uid} (not in LATTICE_ALLOW_UID={allow:?})"
        );
        false
    }
}

#[cfg(windows)]
/// 🟡 IPC accept loop (Windows named pipe): a pool of pipe instances, each handed to a
/// [`pipe_worker`]. (`max_instances` must be ≤254 — see the Windows meshd saga.)
pub(crate) async fn accept_loop(pipe: &str, state: Arc<Mutex<State>>) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    // A POOL of concurrent pipe instances so several simultaneous GUI requests don't get
    // ERROR_PIPE_BUSY (os error 231). The EXTRA instances are best-effort: if the OS
    // won't grant more, we run with however many we got rather than exiting — exiting
    // here was fatal (meshd kept starting, hitting "listening", then dying, so the GUI
    // relaunched it in a loop).
    const POOL: usize = 8;
    let pipe = pipe.to_string();
    // The first instance claims the pipe name. If THIS fails another meshd already owns
    // the pipe, so exit (don't run two).
    let first = match ServerOptions::new()
        .first_pipe_instance(true)
        .max_instances(254)
        .create(&pipe)
    {
        Ok(s) => s,
        Err(e) => {
            elog!("meshd: cannot create pipe {pipe} (another instance already running?): {e}");
            return Err(e.into());
        }
    };
    let mut instances = 1usize;
    for _ in 1..POOL {
        match ServerOptions::new().max_instances(254).create(&pipe) {
            Ok(s) => {
                instances += 1;
                tokio::spawn(pipe_worker(s, pipe.clone(), Arc::clone(&state)));
            }
            Err(e) => {
                elog!("meshd: pipe pool stopped at {instances} instance(s): {e}");
                break;
            }
        }
    }
    elog!("meshd: pipe server ready ({instances} instance(s)) — accepting clients");
    // Run the first worker inline so accept_loop never returns while serving.
    pipe_worker(first, pipe, state).await;
    Ok(())
}

/// One pipe-pool worker: wait for a client, immediately re-arm a fresh listening
/// instance (so the pool's listener count never dips), then serve the connection.
#[cfg(windows)]
/// 🟡 Serve one Windows named-pipe connection (the per-instance worker), then loop to accept.
pub(crate) async fn pipe_worker(
    mut server: tokio::net::windows::named_pipe::NamedPipeServer,
    pipe: String,
    state: Arc<Mutex<State>>,
) {
    use tokio::net::windows::named_pipe::ServerOptions;
    loop {
        if server.connect().await.is_err() {
            match ServerOptions::new().max_instances(254).create(&pipe) {
                Ok(s) => {
                    server = s;
                    continue;
                }
                Err(_) => return,
            }
        }
        let connected = server;
        server = match ServerOptions::new().max_instances(254).create(&pipe) {
            Ok(s) => s,
            Err(_) => return,
        };
        serve_conn(connected, Arc::clone(&state)).await;
    }
}

/// **RISK 🟡 MED** — bounded outbound channel (backpressure vs leak), the Shutdown-ack must FLUSH
/// before teardown, and an event-forwarder interleaves with request/response. Subtle ordering.
/// One IPC connection: newline-JSON [`Request`] in, [`Response`] out, until close.
///
/// A plain client (GUI/CLI) gets strict request→response. A connector that sends
/// [`Request::Subscribe`] turns the connection into a stream: the daemon keeps answering
/// its commands AND pushes [`Response::Event`] lines as mesh events occur. To let those
/// interleave safely, every outbound line goes through one writer task fed by an mpsc, so
/// the request loop and the event forwarder never half-write over each other.
pub(crate) async fn serve_conn<S>(stream: S, state: Arc<Mutex<State>>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = BufReader::new(rd).lines();
    // Bounded so a connector that stops draining its socket backpressures (responses) or is
    // dropped (events) instead of growing the daemon's memory without limit.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<String>(OUT_CHAN_CAP);
    let writer = tokio::spawn(async move {
        while let Some(mut line) = out_rx.recv().await {
            line.push('\n');
            if wr.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    let mut sess = ConnSession::default();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let mut shutdown = false;
        let resp = match serde_json::from_str::<Request>(&line) {
            // Session/streaming requests need the per-connection session + outbound channel,
            // so they're handled here rather than in the stateless `handle`.
            Ok(Request::Hello { id, version, token }) => {
                ext_hello(&state, &mut sess, id, version, token)
            }
            Ok(Request::Subscribe { topics }) => ext_subscribe(&state, &mut sess, &out_tx, topics),
            Ok(req) => {
                let denied = {
                    let st = state.lock().unwrap();
                    scope_gate(&req, &sess, &st)
                };
                if let Some(denied) = denied {
                    denied
                } else {
                    // Handle under the lock; do any async data-plane bringup AFTER
                    // releasing it (TUN/UDP open is async and must not block IPC).
                    let mutates = request_mutates(&req);
                    let (resp, action) = {
                        let mut st = state.lock().unwrap();
                        handle(req, &mut st)
                    };
                    match action {
                        Some(PostAction::Bringup(b)) => {
                            bringup_dataplane(b, Arc::clone(&state)).await
                        }
                        Some(PostAction::ArmKillSwitch(mesh)) => {
                            arm_kill_switch(mesh, Arc::clone(&state))
                        }
                        Some(PostAction::SplitOn(mesh)) => {
                            split_enable(mesh, Arc::clone(&state)).await
                        }
                        Some(PostAction::SplitOff) => split_disable(Arc::clone(&state)).await,
                        Some(PostAction::ApplyExitable(mesh)) => {
                            apply_exitable(mesh, Arc::clone(&state)).await
                        }
                        Some(PostAction::Shutdown) => shutdown = true,
                        None => {}
                    }
                    if mutates {
                        persist(&state.lock().unwrap()); // P-S1: save after a state change
                    }
                    resp
                }
            }
            Err(e) => Response::Error {
                message: format!("bad request: {e}"),
            },
        };
        let out = serde_json::to_string(&resp)
            .unwrap_or_else(|_| "{\"Error\":{\"message\":\"encode failed\"}}".to_string());
        // Responses use the blocking (await) send: if the client stops reading, this
        // backpressures the request loop rather than queueing unboundedly.
        let sent = out_tx.send(out).await.is_ok();
        // Acknowledge the request first, THEN tear the daemon down cleanly. The ack is
        // queued to the writer task, so on shutdown we FLUSH it (drop our sender + await
        // the writer) before stopping the daemon — preserving the original write-then-
        // shutdown ordering so the client always receives its Shutdown ack.
        if shutdown {
            if let Some(h) = sess.sub_abort.take() {
                h.abort();
            }
            drop(out_tx);
            let _ = writer.await;
            shutdown_daemon(&state).await;
            return;
        }
        if !sent {
            break;
        }
    }
    // Connection closed: stop the event forwarder + the writer so neither task leaks.
    if let Some(h) = sess.sub_abort.take() {
        h.abort();
    }
    drop(out_tx);
    let _ = writer.await;
}

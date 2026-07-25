//! `mock_meshd` — a tiny stand-in for the meshd connector framework
//! (docs/EXTENSIONS.md §3/§5), used by the integration test and for local demos
//! before the real daemon ships the framework.
//!
//! It speaks the exact newline-JSON wire of [`crate::ipc`]: accepts
//! `Hello`/`Subscribe`/`Advertise`/`Unadvertise`/`ListServices`, replies with a
//! granted-scope `HelloOk` and a canned `Services` list, and emits canned
//! `events:peer` after a `Subscribe`. Unix-only (the test platforms); the real
//! connector also supports Windows named pipes.
//!
//! Gated to unix by `lib.rs` (`#[cfg(unix)] pub mod mock;`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::ipc::{Request, Response, ServiceView};

/// What the mock should pretend the mesh looks like.
#[derive(Clone, Default)]
pub struct MockConfig {
    /// If set, `Hello` must present this token or the mock returns `Error`.
    pub expected_token: Option<String>,
    /// Scopes returned in `HelloOk`.
    pub grant_scopes: Vec<String>,
    /// Services returned for every `ListServices`.
    pub services: Vec<ServiceView>,
    /// `events:peer` `data` payloads pushed once, shortly after `Subscribe`.
    pub peer_events: Vec<serde_json::Value>,
}

impl MockConfig {
    /// A ready-to-use grant for MiniSync's three control-plane scopes.
    pub fn with_minisync_grant(token: &str) -> Self {
        Self {
            expected_token: Some(token.to_string()),
            grant_scopes: vec![
                "events:peer".into(),
                "registry:read".into(),
                "registry:advertise".into(),
            ],
            ..Default::default()
        }
    }
}

/// A running mock. Dropping it stops the listener and unlinks the socket.
pub struct MockHandle {
    pub path: PathBuf,
    accept: tokio::task::AbortHandle,
}

impl Drop for MockHandle {
    fn drop(&mut self) {
        self.accept.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

static SOCK_SEQ: AtomicU64 = AtomicU64::new(0);

/// Bind the mock on a fresh temp unix socket and start serving. Returns a handle
/// whose `path` is the endpoint to point a connector at.
pub async fn start(config: MockConfig) -> Result<MockHandle> {
    let seq = SOCK_SEQ.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("minisync-mock-{}-{seq}.sock", std::process::id()));
    start_at(path, config).await
}

/// Bind the mock on a caller-chosen socket path and start serving (used by the
/// standalone `mock_meshd` demo binary).
pub async fn start_at(path: PathBuf, config: MockConfig) -> Result<MockHandle> {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    let cfg = config;
    let accept = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let cfg = cfg.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve(stream, cfg).await {
                            tracing::debug!(error = %e, "mock conn ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::debug!(error = %e, "mock accept failed");
                    break;
                }
            }
        }
    });
    Ok(MockHandle {
        path,
        accept: accept.abort_handle(),
    })
}

async fn serve(stream: UnixStream, cfg: MockConfig) -> Result<()> {
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = BufReader::new(rd).lines();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        while let Some(mut line) = rx.recv().await {
            line.push('\n');
            if wr.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    let mut authed = false;
    let mut emitter: Option<tokio::task::JoinHandle<()>> = None;

    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                send(&tx, &err(&format!("bad request: {e}")));
                continue;
            }
        };
        match req {
            Request::Hello { token, .. } => {
                if let Some(exp) = &cfg.expected_token {
                    if &token != exp {
                        send(&tx, &err("invalid extension token"));
                        break;
                    }
                }
                authed = true;
                send(
                    &tx,
                    &Response::HelloOk {
                        scopes: cfg.grant_scopes.clone(),
                    },
                );
            }
            Request::Subscribe { .. } => {
                if !authed {
                    send(&tx, &err("not authenticated — send Hello first"));
                    continue;
                }
                send(&tx, &Response::Ok);
                // Emit canned peer events once, after a brief delay so the
                // connector is in its read loop.
                if emitter.is_none() && !cfg.peer_events.is_empty() {
                    let tx2 = tx.clone();
                    let events = cfg.peer_events.clone();
                    emitter = Some(tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        for (i, data) in events.into_iter().enumerate() {
                            send(
                                &tx2,
                                &Response::Event {
                                    topic: "peer".into(),
                                    seq: i as u64 + 1,
                                    ts_ms: 0,
                                    data,
                                },
                            );
                        }
                    }));
                }
            }
            Request::Advertise { .. } | Request::Unadvertise { .. } => {
                if !authed {
                    send(&tx, &err("not authenticated — send Hello first"));
                    continue;
                }
                send(&tx, &Response::Ok);
            }
            Request::ListServices { proto, .. } => {
                let services = cfg
                    .services
                    .iter()
                    .filter(|s| proto.as_ref().map(|p| p == &s.proto).unwrap_or(true))
                    .cloned()
                    .collect();
                send(&tx, &Response::Services(services));
            }
        }
    }

    if let Some(h) = emitter {
        h.abort();
    }
    writer.abort();
    Ok(())
}

fn err(message: &str) -> Response {
    Response::Error {
        message: message.to_string(),
    }
}

fn send(tx: &mpsc::UnboundedSender<String>, resp: &Response) {
    if let Ok(s) = serde_json::to_string(resp) {
        let _ = tx.send(s);
    }
}

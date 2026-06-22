//! The connector side of the Lattice extension protocol (docs/EXTENSIONS.md
//! §3/§5): connect to meshd, `Hello`, `Subscribe{["peer"]}`, `Advertise`, and
//! `ListServices`, then keep a `watch` channel of discovered peer sync addresses
//! up to date as `events:peer` arrive.
//!
//! Lattice answers only "who is here and where do I reach them"; the actual file
//! sync lives entirely in [`crate::sync`].

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, watch};

use crate::config::{Config, EXT_ID, PROTO, VERSION};
use crate::ipc::{PeerEventData, Request, Response, ServiceView};

/// Backoff between meshd reconnect attempts.
const RECONNECT_DELAY: Duration = Duration::from_secs(3);

/// Connect to the meshd endpoint and run the connector session forever,
/// reconnecting with backoff if meshd restarts or the link drops. Intended for
/// the binary; tests call [`run_session`] directly with a connected stream.
pub async fn run_client(config: Config, peers_tx: watch::Sender<Vec<SocketAddr>>) {
    loop {
        match connect(&config.meshd_endpoint).await {
            Ok(stream) => {
                tracing::info!(endpoint = %config.meshd_endpoint, "connected to meshd");
                if let Err(e) = run_session(&config, stream, &peers_tx).await {
                    tracing::warn!(error = %e, "meshd session ended");
                }
            }
            Err(e) => {
                tracing::warn!(endpoint = %config.meshd_endpoint, error = %e, "cannot reach meshd");
            }
        }
        // Peers are stale while we're disconnected; clear so we stop syncing.
        let _ = peers_tx.send(Vec::new());
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Connect to the platform meshd endpoint (unix socket / windows named pipe).
#[cfg(unix)]
pub async fn connect(endpoint: &str) -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(endpoint).await
}

#[cfg(windows)]
pub async fn connect(
    endpoint: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint)
}

/// Run one connector session over an already-connected meshd stream: handshake,
/// subscribe, advertise, discover, and stream events until the link closes.
pub async fn run_session<S>(
    config: &Config,
    stream: S,
    peers_tx: &watch::Sender<Vec<SocketAddr>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = BufReader::new(rd).lines();

    // One writer task drains a channel of ready-to-send JSON lines so the
    // handshake, the refresh ticker, and event-driven re-queries never interleave
    // a half-written line.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        while let Some(mut line) = out_rx.recv().await {
            line.push('\n');
            if wr.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    // 1. Hello → expect HelloOk.
    send(
        &out_tx,
        &Request::Hello {
            id: EXT_ID.to_string(),
            version: VERSION.to_string(),
            token: config.token.clone(),
        },
    )?;
    let scopes = loop {
        match next_response(&mut lines).await? {
            Some(Response::HelloOk { scopes }) => break scopes,
            Some(Response::Error { message }) => {
                writer.abort();
                return Err(anyhow!("Hello rejected: {message}"));
            }
            Some(other) => tracing::debug!(?other, "ignoring pre-HelloOk response"),
            None => {
                writer.abort();
                return Err(anyhow!("meshd closed before HelloOk"));
            }
        }
    };
    tracing::info!(?scopes, "extension authenticated");
    for need in ["events:peer", "registry:read", "registry:advertise"] {
        if !scopes.iter().any(|s| s == need) {
            tracing::warn!(scope = need, "scope not granted — some features degraded");
        }
    }

    // 2. Subscribe to peer events. NOTE: meshd matches the SHORT topic "peer"
    //    (not "events:peer"); see README contract gap.
    send(
        &out_tx,
        &Request::Subscribe {
            topics: vec!["peer".to_string()],
        },
    )?;

    // 3. Advertise our folder service, and 4. discover existing peers.
    send(&out_tx, &advertise_req(config))?;
    send(&out_tx, &list_req(config))?;

    // Periodic refresh: re-advertise (renew the registry TTL) and re-list (catch
    // any peers whose events we missed).
    let ticker = {
        let out_tx = out_tx.clone();
        let adv = advertise_req(config);
        let list = list_req(config);
        let period = Duration::from_secs(config.advertise_refresh_secs.max(1));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.tick().await; // consume the immediate first tick
            loop {
                tick.tick().await;
                if send(&out_tx, &adv).is_err() || send(&out_tx, &list).is_err() {
                    break;
                }
            }
        })
    };

    // 5. Event/response loop.
    let result = read_loop(config, &mut lines, &out_tx, peers_tx).await;
    ticker.abort();
    writer.abort();
    result
}

async fn read_loop<R>(
    config: &Config,
    lines: &mut tokio::io::Lines<BufReader<R>>,
    out_tx: &mpsc::UnboundedSender<String>,
    peers_tx: &watch::Sender<Vec<SocketAddr>>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    while let Some(resp) = next_response(lines).await? {
        match resp {
            Response::Services(list) => {
                let peers = peers_from_services(config, &list);
                tracing::info!(count = peers.len(), "discovered minisync peers");
                let _ = peers_tx.send(peers);
            }
            Response::Event { topic, data, .. } => {
                // Events are coarse: any peer/lag signal → re-query authoritative
                // state rather than trust the event payload (spec §5).
                if topic == "peer" || topic == "events:peer" || topic == "_lagged" {
                    if let Ok(pe) = serde_json::from_value::<PeerEventData>(data.clone()) {
                        tracing::info!(kind = %pe.kind, peer = ?pe.name, "peer event");
                    } else {
                        tracing::debug!(%topic, "peer/lag event; re-querying");
                    }
                    let _ = send(out_tx, &list_req(config));
                }
            }
            Response::Ok | Response::Info { .. } => {}
            Response::Error { message } => tracing::warn!(%message, "meshd error response"),
            Response::HelloOk { .. } => {}
        }
    }
    Ok(())
}

fn advertise_req(config: &Config) -> Request {
    Request::Advertise {
        mesh: config.mesh,
        proto: PROTO.to_string(),
        port: config.listen_port,
        name: format!("MiniSync — {}", config.folder_label()),
        meta: serde_json::json!({ "folder": config.folder_label() }),
    }
}

fn list_req(config: &Config) -> Request {
    Request::ListServices {
        mesh: config.mesh,
        proto: Some(PROTO.to_string()),
    }
}

/// Build the peer sync-address set from a `ListServices` reply: keep online
/// `minisync` services, drop ourselves, and resolve `overlay_ip:port`.
fn peers_from_services(config: &Config, services: &[ServiceView]) -> Vec<SocketAddr> {
    let mut peers = Vec::new();
    for sv in services {
        if sv.proto != PROTO || !sv.online {
            continue;
        }
        if Some(&sv.overlay_ip) == config.self_overlay_ip.as_ref() {
            continue; // skip self (meshd doesn't flag is_me; see README gap)
        }
        match format!("{}:{}", sv.overlay_ip, sv.port).parse::<SocketAddr>() {
            Ok(addr) => peers.push(addr),
            Err(e) => {
                tracing::warn!(ip = %sv.overlay_ip, port = sv.port, error = %e, "bad overlay addr")
            }
        }
    }
    peers.sort();
    peers.dedup();
    peers
}

fn send(tx: &mpsc::UnboundedSender<String>, req: &Request) -> Result<()> {
    let line = serde_json::to_string(req)?;
    tx.send(line).map_err(|_| anyhow!("meshd writer closed"))?;
    Ok(())
}

async fn next_response<R>(lines: &mut tokio::io::Lines<BufReader<R>>) -> Result<Option<Response>>
where
    R: AsyncRead + Unpin,
{
    loop {
        match lines.next_line().await? {
            Some(line) if line.trim().is_empty() => continue,
            Some(line) => match serde_json::from_str::<Response>(&line) {
                Ok(r) => return Ok(Some(r)),
                Err(e) => {
                    tracing::warn!(error = %e, line = %line, "unparseable meshd line");
                    continue;
                }
            },
            None => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg(self_ip: Option<&str>) -> Config {
        Config {
            folder: PathBuf::from("/tmp/x"),
            listen_port: 48211,
            meshd_endpoint: "/tmp/sock".into(),
            token: "t".into(),
            mesh: 0,
            sync_interval_secs: 5,
            advertise_refresh_secs: 30,
            self_overlay_ip: self_ip.map(|s| s.to_string()),
        }
    }

    fn sv(ip: &str, port: u16, online: bool) -> ServiceView {
        ServiceView {
            mesh: 0,
            member: 1,
            member_name: "n".into(),
            overlay_ip: ip.into(),
            proto: PROTO.into(),
            port,
            name: "".into(),
            meta: serde_json::Value::Null,
            online,
        }
    }

    #[test]
    fn peers_filtered_and_self_excluded() {
        let c = cfg(Some("100.80.0.1"));
        let list = vec![
            sv("100.80.0.1", 48211, true),  // self → skip
            sv("100.80.0.2", 48211, true),  // keep
            sv("100.80.0.3", 48211, false), // offline → skip
        ];
        let peers = peers_from_services(&c, &list);
        assert_eq!(peers, vec!["100.80.0.2:48211".parse().unwrap()]);
    }
}

//! The Lattice daemon: a long-running, privileged process that owns the TUN
//! device and the network sockets, hosts the [`Engine`], and answers control
//! requests from the GUI/CLI over a local IPC channel.
//!
//! Privileges are needed to create the virtual interface; everything user-facing
//! talks to this process instead of touching the network directly.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use lattice_crypto::Identity;
use lattice_dht::{DhtNode, Kademlia, KademliaNode};
use lattice_engine::{Engine, EngineConfig};
use lattice_net::discovery::{ChannelDiscovery, MdnsDiscovery};
use lattice_net::nat::Rendezvous;
use lattice_net::udp::UdpTransport;
use lattice_net::{DiscoveredPeer, Discovery, Transport};
use lattice_proto::{NodeId, PeerStatus, OVERLAY_SUBNET};
use lattice_tun::TunConfig;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use lattice_membership::{MemberCert, NetworkManifest};

mod exit;
mod membership;

use membership::Admin;

/// Lattice background service.
#[derive(Parser, Debug)]
#[command(name = "lattice-daemon", version, about)]
struct Args {
    /// Path to the local IPC socket the GUI/CLI connect to.
    #[arg(long, default_value = "/tmp/lattice.sock")]
    ipc_socket: String,

    /// UDP address to bind the transport to (port 0 = OS-assigned).
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: String,

    /// Run without creating a TUN device: IPC + discovery + handshakes only, no
    /// packet forwarding. Lets the daemon run unprivileged (no root needed).
    #[arg(long)]
    no_tun: bool,

    /// Where to persist this node's identity so its node id is stable across
    /// restarts (needed for manual peer pins). Generated on first run.
    #[arg(long, default_value = "/var/lib/lattice/identity.key")]
    identity: String,

    /// Enable the Kademlia DHT for serverless internet-wide rendezvous, bound to
    /// this UDP address (e.g. `0.0.0.0:0`). Off by default.
    #[arg(long)]
    dht_bind: Option<String>,

    /// DHT bootstrap node addresses to join the network through (repeatable).
    #[arg(long)]
    dht_bootstrap: Vec<String>,

    /// Node ids (64-hex) of peers to resolve via the DHT and connect to
    /// (repeatable). Their candidate addresses are looked up and fed to the engine.
    #[arg(long)]
    peer: Vec<String>,

    /// Manually pin a peer by `<node-id-hex>@<ip:port>` (repeatable). Connect
    /// across the internet without discovery — point this at a port-forwarded
    /// node's public address.
    #[arg(long)]
    peer_addr: Vec<String>,

    /// Run a relay forwarder on this UDP address (e.g. `0.0.0.0:42000`). A relay
    /// shuttles encrypted packets between peers that can't connect directly.
    #[arg(long)]
    relay_bind: Option<String>,

    /// Use this relay's address (`ip:port`) to reach peers that can't be reached
    /// directly (CGNAT/symmetric NAT).
    #[arg(long)]
    relay: Option<String>,

    /// Node ids (64-hex) of peers to reach *through* the configured `--relay`
    /// (repeatable). The other peer must also use the same relay.
    #[arg(long)]
    peer_relay: Vec<String>,

    /// Be this mesh's admin: hold the network CA key at this path (generated +
    /// saved on first run — that one act *creates* the network). Lets this node
    /// issue join tokens and evict members. Self-issues our own cert.
    #[arg(long)]
    network_key: Option<String>,

    /// Join an existing network by loading a membership cert (a join token a
    /// network admin issued for us) from this path. Persisted here when joining
    /// via the GUI/CLI at runtime.
    #[arg(long)]
    member_cert: Option<String>,

    /// Process name(s) allowed to call the mesh health check (every node's
    /// virtual IP at once). SECURITY-SENSITIVE — it exposes the whole network's
    /// address map; only a caller whose process name matches is answered.
    /// Repeatable; defaults to `minisync`. Pass `--health-allow ""` to disable.
    /// See docs/HEALTH_CHECK.md.
    #[arg(long, default_value = "minisync")]
    health_allow: Vec<String>,

    /// Process name(s) allowed to drive the admin packet capture (the packet
    /// inspector). SECURITY-SENSITIVE — captured packets are DECRYPTED plaintext.
    /// Repeatable; defaults to EMPTY (capture disabled). Name the admin console's
    /// binary here to enable it. See docs/ADMIN_CONSOLE.md.
    #[arg(long)]
    admin_allow: Vec<String>,

    /// Crypto suite to start under, by name (e.g. `noise-ik-chachapoly` or
    /// `noise-ik-aesgcm`). The admin crypto-lab can hot-swap it at runtime; this
    /// just sets the initial one. Unknown names fall back to the default.
    #[arg(long)]
    crypto: Option<String>,
}

/// Lowercase hex of bytes — for the crypto bench ciphertext over IPC.
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse lowercase/uppercase hex into bytes (tolerates internal whitespace so a
/// pasted ciphertext with spaces/newlines still decodes). `None` if malformed.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return None;
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).ok())
        .collect()
}

/// Is the calling process allowed to drive the admin packet capture? Same weak
/// "name ≠ identity" gate as the health check; empty allow-list = denied.
fn admin_permitted(caller: &Option<String>, allow: &[String]) -> bool {
    caller
        .as_deref()
        .is_some_and(|name| allow.iter().any(|a| a == name))
}

/// The refusal response when a caller is not on the `--admin-allow` list.
fn admin_denied(caller: &Option<String>, allow: &[String]) -> lattice_proto::ipc::Response {
    lattice_proto::ipc::Response::Error {
        message: format!(
            "packet capture denied for process {:?} (allowed: {:?}); enable with --admin-allow",
            caller.as_deref().unwrap_or("<unknown>"),
            allow
        ),
    }
}

/// Hex-encode bytes (for join tokens on the wire).
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Hex-decode a string, or `None` if it isn't valid hex.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Load a member cert from a file (raw 152 bytes or a hex token).
fn load_member_cert(path: &str) -> Option<MemberCert> {
    let bytes = std::fs::read(path).ok()?;
    MemberCert::from_bytes(&bytes).ok().or_else(|| {
        hex_decode(std::str::from_utf8(&bytes).ok()?.trim())
            .and_then(|b| MemberCert::from_bytes(&b).ok())
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // mdns-sd logs an ERROR per interface when IPv6 multicast has no
                // route (common on macOS with many utun interfaces) — noise, not
                // our concern. Quiet it by default; override with RUST_LOG.
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,mdns_sd=off")),
        )
        .init();

    let args = Args::parse();

    // Write our PID so the GUI can stop us reliably (process name = full path,
    // which breaks pkill -x / killall matching).
    let _ = std::fs::write("/tmp/lattice-daemon.pid", std::process::id().to_string());

    // Stable identity: load it from disk, or generate + save on first run.
    let identity = Identity::load_or_generate(std::path::Path::new(&args.identity))?;
    let node_id = identity.node_id();
    let public_key = identity.public_key().to_vec();
    tracing::info!(identity = %args.identity, "identity ready");

    let config = EngineConfig {
        bind_addr: args.bind.parse()?,
    };
    // Start under the requested crypto suite (the lab can hot-swap later); an
    // unknown name falls back to the default Noise-IK/ChaChaPoly suite.
    let suite = args
        .crypto
        .as_deref()
        .and_then(lattice_crypto::suite_by_name)
        .unwrap_or_else(|| std::sync::Arc::new(lattice_crypto::NoiseSuite::default()));
    if let Some(name) = &args.crypto {
        tracing::info!(suite = %suite.name(), requested = %name, "crypto suite selected");
    }
    let mut engine = Engine::with_suite(identity, config, suite);
    let virtual_ip = engine.virtual_ip();

    tracing::info!(
        node = %node_id.fingerprint(),
        %virtual_ip,
        ipc = %args.ipc_socket,
        "lattice-daemon starting"
    );

    // Membership. `--network-key` makes us the admin (hold the CA, self-issue a
    // cert). Otherwise `--member-cert` joins an existing network. Neither = open
    // mode (any peer that completes the handshake is admitted).
    let admin: Option<Arc<std::sync::Mutex<Admin>>> = if let Some(kp) = args.network_key.clone() {
        let mut a = Admin::load_or_create(&kp);
        let net = a.network_id();
        let cert = a.issue(&node_id, Some("admin".into()));
        engine.set_membership(net, cert);
        tracing::info!(network = %net.to_hex(), "admin: holding network CA, membership active");
        Some(Arc::new(std::sync::Mutex::new(a)))
    } else {
        if let Some(cp) = args.member_cert.clone() {
            match load_member_cert(&cp) {
                Some(cert) => {
                    let net = cert.network_id();
                    engine.set_membership(net, cert);
                    tracing::info!(network = %net.to_hex(), "joined network via member cert");
                }
                None => tracing::warn!(path = %cp, "could not load --member-cert (running open)"),
            }
        }
        None
    };

    // Bring up the data plane. Creating a real TUN device needs root; --no-tun
    // runs a headless node (IPC + discovery only) without it.
    let tun: Box<dyn lattice_tun::TunDevice> = if args.no_tun {
        tracing::warn!("--no-tun: headless mode, no packet forwarding");
        Box::new(lattice_tun::NullTun)
    } else {
        lattice_tun::open(TunConfig {
            address: virtual_ip,
            prefix_len: OVERLAY_SUBNET.1,
            mtu: 1380,
        })
        .await
        .map_err(|e| anyhow::anyhow!("failed to open TUN device (need sudo?): {e}"))?
    };
    // Captured for exit-node routing before the engine takes ownership of `tun`.
    let tun_name = tun.name().map(|s| s.to_string());

    let udp = UdpTransport::bind(args.bind.parse()?).await?;
    let udp_addr = udp.local_addr()?;
    tracing::info!(udp = %udp_addr, "transport bound");

    // Optionally run a relay forwarder for peers who can't connect directly.
    if let Some(relay_bind) = args.relay_bind.clone() {
        let sock = UdpSocket::bind(&relay_bind).await?;
        tracing::info!(relay = %sock.local_addr()?, "relay forwarder listening");
        tokio::spawn(async move {
            let _ = lattice_net::relay::run_relay(sock).await;
        });
    }

    // Wrap the transport so relayed peers look direct to the engine. `--relay`
    // sets the relay address; without it this is a pure pass-through.
    let relay_addr: Option<SocketAddr> = args.relay.as_deref().and_then(|s| s.parse().ok());
    let transport = std::sync::Arc::new(lattice_net::relay::RelayTransport::new(
        udp, relay_addr, node_id.0,
    ));
    // Keep our address registered with the relay so peers can be forwarded to
    // us. Runs always; `register` is a no-op until a relay is configured.
    {
        let reg = std::sync::Arc::clone(&transport);
        tokio::spawn(async move {
            loop {
                let _ = reg.register().await;
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        });
    }

    // Best-effort: learn our public (reflexive) address via STUN — a WAN
    // candidate we publish to the DHT for NAT hole punching.
    let reflexive: Option<SocketAddr> =
        match lattice_net::nat::reflexive_address("stun.l.google.com:19302").await {
            Ok(public) => {
                tracing::info!(%public, "public address (STUN)");
                Some(public)
            }
            Err(e) => {
                tracing::debug!(error = %e, "STUN lookup failed (LAN-only or offline)");
                None
            }
        };
    if let Some(public) = reflexive {
        engine.handle().set_public_addr(public);
    }

    // All discovery sources feed one channel the engine consumes.
    let (disc_tx, discovery) = ChannelDiscovery::new();

    // Serverless LAN discovery: advertise ourselves and browse for peers over
    // mDNS, forwarding each into the merged stream.
    let mut mdns = MdnsDiscovery::new(&public_key, udp_addr.port())?;
    {
        let tx = disc_tx.clone();
        tokio::spawn(async move {
            while let Some(peer) = mdns.next_peer().await {
                if tx.send(peer).await.is_err() {
                    break;
                }
            }
        });
    }

    // Optional: Kademlia DHT rendezvous for internet-wide peer resolution.
    if let Some(dht_bind) = args.dht_bind.clone() {
        if let Err(e) = start_dht(
            dht_bind,
            args.dht_bootstrap.clone(),
            args.peer.clone(),
            node_id,
            reflexive,
            udp_addr.port(),
            disc_tx.clone(),
            admin.clone(),
            engine.handle(),
            std::sync::Arc::clone(&transport),
        )
        .await
        {
            tracing::warn!(error = %e, "DHT setup failed");
        }
    }

    // Manually pinned peers (`--peer-addr <id>@<ip:port>`): re-announce each
    // periodically so the handshake retries until the remote is up.
    for spec in &args.peer_addr {
        match parse_peer_spec(spec) {
            Some((id, addr)) => {
                // A direct pin: we hold a reachable address, so initiate to it
                // regardless of the id tie-break (one-sided reachability case).
                engine.handle().pin_peer(id);
                let tx = disc_tx.clone();
                tokio::spawn(async move {
                    loop {
                        let _ = tx
                            .send(DiscoveredPeer {
                                id,
                                endpoints: vec![addr],
                            })
                            .await;
                        tokio::time::sleep(Duration::from_secs(20)).await;
                    }
                });
                tracing::info!(peer = %id.fingerprint(), %addr, "pinned peer");
            }
            None => tracing::warn!(spec, "ignoring invalid --peer-addr (need <id>@<ip:port>)"),
        }
    }

    // Peers reached through the relay (`--peer-relay <id>`): hand the engine a
    // synthetic endpoint that the RelayTransport routes via the relay.
    for id_hex in &args.peer_relay {
        match parse_hex_id(id_hex) {
            Some(id) => {
                let synth = transport.endpoint_for(id);
                let tx = disc_tx.clone();
                tokio::spawn(async move {
                    loop {
                        let _ = tx
                            .send(DiscoveredPeer {
                                id: NodeId(id),
                                endpoints: vec![synth],
                            })
                            .await;
                        tokio::time::sleep(Duration::from_secs(20)).await;
                    }
                });
                tracing::info!(peer = %NodeId(id).fingerprint(), "reaching peer via relay");
            }
            None => tracing::warn!(id_hex, "invalid --peer-relay id (need 64 hex)"),
        }
    }

    // IPC server lets the GUI/CLI query status and toggle the mesh while the
    // engine runs. The handler captures a cloneable handle to the engine.
    let ipc_handle = engine.handle();
    let ipc_tun = tun_name.clone();
    let ipc_disc = disc_tx.clone();
    let ipc_transport = std::sync::Arc::clone(&transport);
    let ipc_admin = admin.clone();
    let ipc_member_cert = args.member_cert.clone();
    // Process names allowed to call the health check (empty strings filtered out
    // so `--health-allow ""` disables it).
    let ipc_health_allow: Vec<String> = args
        .health_allow
        .iter()
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .collect();
    // Process names allowed to drive the packet capture (decrypted plaintext);
    // empty = disabled.
    let ipc_admin_allow: Vec<String> = args
        .admin_allow
        .iter()
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .collect();
    let ipc = lattice_ipc::serve(&args.ipc_socket, move |req, caller| {
        let handle = ipc_handle.clone();
        let tun_name = ipc_tun.clone();
        let disc_tx = ipc_disc.clone();
        let transport = std::sync::Arc::clone(&ipc_transport);
        let admin = ipc_admin.clone();
        let member_cert_path = ipc_member_cert.clone();
        let health_allow = ipc_health_allow.clone();
        let admin_allow = ipc_admin_allow.clone();
        async move {
            use lattice_proto::ipc::{HealthEntry, MemberEntry, NetworkInfo, Request, Response};
            match req {
                Request::Status => {
                    let mut s = handle.status().await;
                    s.relay = transport.current_relay();
                    Response::Status(s)
                }
                Request::Peers => Response::Peers(handle.peers().await),
                Request::Flows => Response::Flows(handle.flows()),
                Request::NetworkInfo => {
                    let net = handle.network_id();
                    let member_count = admin.as_ref().map(|a| a.lock().unwrap().members().len());
                    Response::NetworkInfo(NetworkInfo {
                        network_id: net.map(|n| n.to_hex()),
                        fingerprint: net.map(|n| n.fingerprint()),
                        is_admin: admin.is_some(),
                        member_count: member_count.unwrap_or(0),
                        revocation_count: handle.revocation_count(),
                    })
                }
                Request::IssueCert { node_id, label } => match &admin {
                    Some(a) => {
                        let cert = a.lock().unwrap().issue(&node_id, label);
                        Response::Token(hex_encode(&cert.to_bytes()))
                    }
                    None => Response::Error {
                        message: "not an admin node (start with --network-key to issue certs)"
                            .into(),
                    },
                },
                Request::JoinNetwork { token } => {
                    match hex_decode(&token).and_then(|b| MemberCert::from_bytes(&b).ok()) {
                        Some(cert) => {
                            let net = cert.network_id();
                            handle.join_network(cert);
                            // Persist so the membership survives a restart.
                            if let Some(path) = &member_cert_path {
                                let _ = std::fs::write(path, &token);
                            }
                            tracing::info!(network = %net.to_hex(), "joined network via token");
                            Response::Done
                        }
                        None => Response::Error {
                            message: "invalid join token".into(),
                        },
                    }
                }
                Request::RevokeMember { node_id } => match &admin {
                    Some(a) => match a.lock().unwrap().revoke(&node_id) {
                        Some(rev) => {
                            handle.add_revocation(rev);
                            Response::Done
                        }
                        None => Response::Error {
                            message: "no such member to revoke".into(),
                        },
                    },
                    None => Response::Error {
                        message: "not an admin node".into(),
                    },
                },
                Request::DesignateRelay { node_id, on } => match &admin {
                    Some(a) => {
                        if a.lock().unwrap().set_relay(&node_id, on) {
                            Response::Done
                        } else {
                            Response::Error {
                                message: "no such member to designate".into(),
                            }
                        }
                    }
                    None => Response::Error {
                        message: "not an admin node".into(),
                    },
                },
                Request::Members => match &admin {
                    Some(a) => {
                        let members = a
                            .lock()
                            .unwrap()
                            .members()
                            .iter()
                            .map(|m| MemberEntry {
                                node_id: m.node_id.clone(),
                                fingerprint: m.node_id.chars().take(8).collect(),
                                serial: m.serial,
                                label: m.label.clone(),
                                revoked: m.revoked,
                                relay: m.relay,
                            })
                            .collect();
                        Response::Members(members)
                    }
                    None => Response::Error {
                        message: "not an admin node".into(),
                    },
                },
                Request::HealthCheck => {
                    // SECURITY GATE: only an allow-listed process name may pull
                    // the whole mesh's virtual-IP map at once. This is a weak
                    // check by design (a process can be named anything); see
                    // docs/HEALTH_CHECK.md for the threat model.
                    let permitted = caller
                        .as_deref()
                        .is_some_and(|name| health_allow.iter().any(|a| a == name));
                    if !permitted {
                        Response::Error {
                            message: format!(
                                "health check denied for process {:?} (allowed: {:?})",
                                caller.as_deref().unwrap_or("<unknown>"),
                                health_allow
                            ),
                        }
                    } else {
                        let status = handle.status().await;
                        let mut entries = Vec::new();
                        if let Some(vip) = status.virtual_ip {
                            entries.push(HealthEntry {
                                virtual_ip: vip,
                                fingerprint: status.id.fingerprint(),
                                status: "self".into(),
                            });
                        }
                        for p in handle.peers().await {
                            entries.push(HealthEntry {
                                virtual_ip: p.virtual_ip,
                                fingerprint: p.id.fingerprint(),
                                status: format!("{:?}", p.status).to_lowercase(),
                            });
                        }
                        Response::Health(entries)
                    }
                }
                // Admin packet inspector (decrypted plaintext) — gated by
                // --admin-allow (empty = disabled). See docs/ADMIN_CONSOLE.md §B.
                Request::CaptureStart { filter } => {
                    if admin_permitted(&caller, &admin_allow) {
                        Response::CaptureState(handle.capture_start(filter))
                    } else {
                        admin_denied(&caller, &admin_allow)
                    }
                }
                Request::CaptureStop => {
                    if admin_permitted(&caller, &admin_allow) {
                        Response::CaptureState(handle.capture_stop())
                    } else {
                        admin_denied(&caller, &admin_allow)
                    }
                }
                Request::CaptureStatus => {
                    if admin_permitted(&caller, &admin_allow) {
                        Response::CaptureState(handle.capture_status())
                    } else {
                        admin_denied(&caller, &admin_allow)
                    }
                }
                Request::Packets { after } => {
                    if admin_permitted(&caller, &admin_allow) {
                        Response::Packets(handle.packets_since(after))
                    } else {
                        admin_denied(&caller, &admin_allow)
                    }
                }
                // Crypto-lab reads are informational (suite names, handshake sizes,
                // session counters — no plaintext), so they're ungated like status.
                Request::CryptoSuites => Response::CryptoSuites(handle.crypto_suites()),
                Request::CryptoCurrent => Response::CryptoSuite(handle.crypto_current()),
                Request::CryptoStats => Response::CryptoStats(handle.crypto_stats()),
                Request::SessionDetails => Response::SessionDetails(handle.session_details()),
                Request::CryptoEncrypt { text } => match handle.bench_encrypt(text.as_bytes()) {
                    Ok(ct) => Response::CryptoBytes { hex: to_hex(&ct) },
                    Err(message) => Response::Error { message },
                },
                Request::CryptoDecrypt { hex } => match from_hex(&hex) {
                    Some(ct) => match handle.bench_decrypt(&ct) {
                        Ok(pt) => Response::CryptoText {
                            text: String::from_utf8_lossy(&pt).to_string(),
                        },
                        Err(message) => Response::Error { message },
                    },
                    None => Response::Error {
                        message: "invalid hex ciphertext".into(),
                    },
                },
                // Swapping the live tunnel crypto is disruptive (drops every
                // session), so it's gated by the same admin capability as capture.
                Request::SetCryptoSuite { name } => {
                    if admin_permitted(&caller, &admin_allow) {
                        if handle.set_crypto_suite(&name) {
                            tracing::info!(suite = %name, "crypto suite swapped — re-handshaking all sessions");
                            Response::Done
                        } else {
                            Response::Error {
                                message: format!("unknown crypto suite: {name}"),
                            }
                        }
                    } else {
                        admin_denied(&caller, &admin_allow)
                    }
                }
                Request::Up => {
                    handle.set_enabled(true);
                    Response::Done
                }
                Request::Down => {
                    handle.set_enabled(false);
                    Response::Done
                }
                Request::SetExit { node_id } => {
                    handle.set_exit_node(node_id);
                    match node_id {
                        Some(id) => {
                            let endpoint_ip = handle
                                .peers()
                                .await
                                .iter()
                                .find(|p| p.id == id)
                                .and_then(|p| p.endpoints.first().map(|e| e.ip()));
                            match (tun_name.as_deref(), endpoint_ip) {
                                (Some(name), Some(ip)) => exit::route_through(name, ip),
                                _ => tracing::warn!("cannot route via exit (no tun or endpoint)"),
                            }
                        }
                        None => exit::restore_routes(),
                    }
                    Response::Done
                }
                Request::AllowExit { enabled } => {
                    handle.set_allow_exit(enabled);
                    if enabled {
                        exit::enable_nat();
                    } else {
                        exit::disable_nat();
                    }
                    Response::Done
                }
                Request::AddPeer { node_id, addr } => {
                    // Direct pin: bypass the id tie-break so we drive the
                    // handshake even if the peer is the smaller-id (anchor) side.
                    handle.pin_peer(node_id);
                    let _ = disc_tx
                        .send(DiscoveredPeer {
                            id: node_id,
                            endpoints: vec![addr],
                        })
                        .await;
                    Response::Done
                }
                Request::SetRelay { addr } => {
                    transport.set_relay(addr);
                    Response::Done
                }
                Request::RelayPeer { node_id } => {
                    let synth = transport.endpoint_for(node_id.0);
                    let _ = disc_tx
                        .send(DiscoveredPeer {
                            id: node_id,
                            endpoints: vec![synth],
                        })
                        .await;
                    Response::Done
                }
            }
        }
    });
    tracing::info!(ipc = %args.ipc_socket, "IPC server listening");

    tokio::select! {
        result = engine.run(tun, transport, discovery) => {
            result?;
            tracing::info!("engine loop ended");
        }
        result = ipc => {
            result?;
            tracing::info!("ipc server ended");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
        }
    }

    // Always undo exit-node OS changes so we never leave the host's routing or
    // NAT in a diverted state.
    exit::restore_routes();
    exit::disable_nat();
    let _ = std::fs::remove_file("/tmp/lattice-daemon.pid");
    Ok(())
}

/// Bring up a Kademlia DHT node: join via bootstrap addresses, publish our
/// candidate addresses under our node id, and resolve each `--peer` id (feeding
/// the discovered endpoints to the engine for handshaking).
#[allow(clippy::too_many_arguments)]
async fn start_dht(
    bind: String,
    bootstrap: Vec<String>,
    peers: Vec<String>,
    node_id: NodeId,
    reflexive: Option<SocketAddr>,
    mesh_port: u16,
    disc_tx: mpsc::Sender<DiscoveredPeer>,
    admin: Option<std::sync::Arc<std::sync::Mutex<membership::Admin>>>,
    handle: lattice_engine::EngineHandle,
    relay: Arc<lattice_net::relay::RelayTransport<UdpTransport>>,
) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(&bind).await?);
    let local = socket.local_addr()?;
    let kad_id = node_id.0;

    let node = Arc::new(Mutex::new(KademliaNode::new(kad_id)));
    let dht = DhtNode::new(socket, Arc::clone(&node));
    dht.spawn_server();
    let kad = Arc::new(Kademlia::with_shared(node, dht));
    tracing::info!(dht = %local, node = %node_id.fingerprint(), "DHT node listening");

    // Join the DHT through any bootstrap nodes — then keep re-joining on a timer.
    // A one-shot bootstrap is fragile: if the bootstrap node restarts it comes back
    // with an empty routing table, and if our contact to it is ever evicted we lose
    // our only entry point — either way the ring silently breaks and lookups stop
    // resolving (you then have to restart every node by hand). Re-pinging the
    // configured bootstrap addresses periodically re-teaches a restarted bootstrap
    // node about us and refreshes our own buckets (Kademlia's periodic refresh), so
    // the mesh self-heals within one interval instead of needing a manual restart.
    let boots: Vec<SocketAddr> = bootstrap.iter().filter_map(|a| a.parse().ok()).collect();
    if !boots.is_empty() {
        kad.bootstrap_addrs(&boots).await;
        tracing::info!(count = boots.len(), "DHT bootstrapped");
        let kad = Arc::clone(&kad);
        tokio::spawn(async move {
            const REBOOTSTRAP: Duration = Duration::from_secs(60);
            loop {
                tokio::time::sleep(REBOOTSTRAP).await;
                kad.bootstrap_addrs(&boots).await;
                tracing::debug!(count = boots.len(), "DHT re-bootstrapped");
            }
        });
    }

    // Publish our candidate addresses (LAN first, then reflexive/WAN) under our
    // node id, refreshed periodically so peers can resolve us by id and reach us
    // on whichever path works. The LAN candidate matters on a routed LAN where the
    // reflexive (public) address isn't hairpin-reachable between peers.
    {
        let kad = Arc::clone(&kad);
        let lan = primary_lan_addr(mesh_port);
        tokio::spawn(async move {
            loop {
                let mut candidates: Vec<SocketAddr> = Vec::new();
                if let Some(lan) = lan {
                    candidates.push(lan);
                }
                if let Some(public) = reflexive {
                    if !candidates.contains(&public) {
                        candidates.push(public);
                    }
                }
                if !candidates.is_empty() {
                    kad.publish(kad_id, &candidates).await.ok();
                    tracing::debug!(?candidates, "published endpoint candidates to DHT");
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    // Resolve each requested peer by id and feed its candidates to the engine.
    for p in peers {
        let Some(id) = parse_hex_id(&p) else {
            tracing::warn!(peer = %p, "ignoring invalid peer id (need 64 hex chars)");
            continue;
        };
        let kad = Arc::clone(&kad);
        let tx = disc_tx.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(addrs) = kad.lookup(id).await {
                    if !addrs.is_empty() {
                        tracing::info!(peer = %NodeId(id).fingerprint(), count = addrs.len(), "DHT resolved peer");
                        let _ = tx
                            .send(DiscoveredPeer {
                                id: NodeId(id),
                                endpoints: addrs,
                            })
                            .await;
                    }
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    // SDN×DHT control plane (docs/SDN_DHT_ARCHITECTURE.md): the admin publishes the
    // signed member directory to the DHT; every node fetches + verifies it and
    // resolves each member's endpoint, so a full mesh forms automatically with no
    // manual `--peer` list. Authority stays with the admin (only the CA can sign a
    // directory readers accept).
    if let Some(admin) = admin {
        let kad = Arc::clone(&kad);
        tokio::spawn(async move {
            loop {
                let (dir_key, dir_bytes, man_key, man_bytes) = {
                    let a = admin.lock().unwrap();
                    let net = a.network_id();
                    (
                        net.directory_key(),
                        a.signed_directory().to_bytes(),
                        net.manifest_key(),
                        a.signed_manifest().to_bytes(),
                    )
                };
                kad.publish_record(dir_key, dir_bytes).await;
                // The SDN "program": which members relay for unreachable pairs.
                kad.publish_record(man_key, man_bytes).await;
                tracing::debug!("published member directory + manifest to DHT");
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    // Shared: the relay node id currently selected from the signed manifest (None
    // if no relay is configured, or if we are the relay). Written by the manifest
    // consumer, read by the directory consumer to add a relay-fallback endpoint.
    let relay_id: Arc<std::sync::Mutex<Option<[u8; 32]>>> = Arc::new(std::sync::Mutex::new(None));

    // Manifest consumer (all nodes): fetch the admin-signed NetworkManifest, learn
    // the designated relay(s), and program the data plane — become a relay server
    // if we're listed, else point our RelayTransport at the first reachable relay.
    {
        let kad = Arc::clone(&kad);
        let relay = Arc::clone(&relay);
        let relay_id = Arc::clone(&relay_id);
        let handle = handle.clone();
        let me = node_id.0;
        tokio::spawn(async move {
            loop {
                if let Some(net) = handle.network_id() {
                    match kad.get_record(net.manifest_key()).await {
                        Some(bytes) => match NetworkManifest::from_bytes(&bytes) {
                            Ok(m) if m.verify(&net).is_ok() => {
                                tracing::debug!(relays = m.relays().len(), "manifest fetched");
                                if m.relays().contains(&me) {
                                    // We're designated a relay: forward on our mesh socket.
                                    if !relay.is_relay_server() {
                                        tracing::info!("designated as relay — forwarding on mesh socket");
                                    }
                                    relay.set_relay_server(true);
                                    *relay_id.lock().unwrap() = None;
                                } else if let Some(&rid) = m.relays().iter().find(|&&r| r != me) {
                                    // Point at the first relay that isn't us and resolves.
                                    match kad.lookup(rid).await {
                                        Ok(addrs) => match addrs.first().copied() {
                                            Some(addr) => {
                                                if relay.current_relay() != Some(addr) {
                                                    tracing::info!(relay = %NodeId(rid).fingerprint(), %addr, "relay selected from manifest");
                                                }
                                                relay.set_relay(Some(addr));
                                                *relay_id.lock().unwrap() = Some(rid);
                                            }
                                            None => tracing::debug!(relay = %NodeId(rid).fingerprint(), "relay designated but its endpoint did not resolve"),
                                        },
                                        Err(_) => tracing::debug!("relay endpoint lookup failed"),
                                    }
                                } else {
                                    relay.set_relay(None);
                                    *relay_id.lock().unwrap() = None;
                                }
                            }
                            Ok(_) => tracing::warn!("network manifest failed verification — ignoring"),
                            Err(_) => tracing::warn!("malformed network manifest in DHT"),
                        },
                        None => tracing::debug!("no network manifest in DHT yet"),
                    }
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    // Directory consumer (admin + members alike): learn the whole membership and
    // connect to everyone.
    {
        let kad = Arc::clone(&kad);
        let tx = disc_tx.clone();
        let relay = Arc::clone(&relay);
        let relay_id = Arc::clone(&relay_id);
        let me = node_id.0;
        tokio::spawn(async move {
            loop {
                if let Some(net) = handle.network_id() {
                    if let Some(bytes) = kad.get_record(net.directory_key()).await {
                        match lattice_membership::MemberDirectory::from_bytes(&bytes) {
                            Ok(dir) if dir.verify(&net).is_ok() => {
                                // Who are we already directly connected to? The relay
                                // is only a fallback for peers we can't reach directly.
                                let connected: std::collections::HashSet<[u8; 32]> = handle
                                    .peers()
                                    .await
                                    .iter()
                                    .filter(|p| p.status == PeerStatus::Connected)
                                    .map(|p| p.id.0)
                                    .collect();
                                let configured_relay = relay.current_relay().is_some();
                                let relay_node = *relay_id.lock().unwrap();
                                for &id in dir.node_ids() {
                                    if id == me {
                                        continue;
                                    }
                                    let mut endpoints = kad.lookup(id).await.unwrap_or_default();
                                    // Relay fallback: not yet connected directly, a
                                    // relay is configured, and this peer isn't the
                                    // relay itself → add its synthetic relay endpoint
                                    // so the engine's multi-candidate handshake can
                                    // connect through the relay when direct fails.
                                    if configured_relay
                                        && !connected.contains(&id)
                                        && relay_node != Some(id)
                                    {
                                        endpoints.push(relay.endpoint_for(id));
                                    }
                                    if !endpoints.is_empty() {
                                        let _ = tx
                                            .send(DiscoveredPeer {
                                                id: NodeId(id),
                                                endpoints,
                                            })
                                            .await;
                                    }
                                }
                            }
                            Ok(_) => {
                                tracing::warn!("member directory failed verification — ignoring")
                            }
                            Err(_) => tracing::warn!("malformed member directory in DHT"),
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    Ok(())
}

/// This node's primary LAN address (the source IP the OS would use to reach the
/// internet) paired with the mesh port — a reachable on-LAN candidate to publish
/// alongside the reflexive/WAN one. Uses the connected-UDP trick (no packet is
/// sent) so it works the same on macOS, Linux, and Windows.
fn primary_lan_addr(mesh_port: u16) -> Option<SocketAddr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("8.8.8.8:80").ok()?;
    let ip = probe.local_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        return None;
    }
    Some(SocketAddr::new(ip, mesh_port))
}

/// Parse a `<node-id-hex>@<ip:port>` peer pin.
fn parse_peer_spec(s: &str) -> Option<(NodeId, SocketAddr)> {
    let (id_hex, addr) = s.split_once('@')?;
    let id = parse_hex_id(id_hex)?;
    Some((NodeId(id), addr.parse().ok()?))
}

/// Parse a 64-character hex node id into 32 bytes.
fn parse_hex_id(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut id = [0u8; 32];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(id)
}

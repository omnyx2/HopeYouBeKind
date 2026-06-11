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
use lattice_proto::{NodeId, OVERLAY_SUBNET};
use lattice_tun::TunConfig;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

mod exit;

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

    // Stable identity: load it from disk, or generate + save on first run.
    let identity = Identity::load_or_generate(std::path::Path::new(&args.identity))?;
    let node_id = identity.node_id();
    let public_key = identity.public_key().to_vec();
    tracing::info!(identity = %args.identity, "identity ready");

    let config = EngineConfig {
        bind_addr: args.bind.parse()?,
    };
    let mut engine = Engine::new(identity, config);
    let virtual_ip = engine.virtual_ip();

    tracing::info!(
        node = %node_id.fingerprint(),
        %virtual_ip,
        ipc = %args.ipc_socket,
        "lattice-daemon starting"
    );

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
    // Keep our address registered with the relay so peers can be forwarded to us.
    if relay_addr.is_some() {
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
            disc_tx.clone(),
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
    let ipc = lattice_ipc::serve(&args.ipc_socket, move |req| {
        let handle = ipc_handle.clone();
        let tun_name = ipc_tun.clone();
        let disc_tx = ipc_disc.clone();
        async move {
            use lattice_proto::ipc::{Request, Response};
            match req {
                Request::Status => Response::Status(handle.status().await),
                Request::Peers => Response::Peers(handle.peers().await),
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
                    let _ = disc_tx
                        .send(DiscoveredPeer {
                            id: node_id,
                            endpoints: vec![addr],
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
    Ok(())
}

/// Bring up a Kademlia DHT node: join via bootstrap addresses, publish our
/// candidate addresses under our node id, and resolve each `--peer` id (feeding
/// the discovered endpoints to the engine for handshaking).
async fn start_dht(
    bind: String,
    bootstrap: Vec<String>,
    peers: Vec<String>,
    node_id: NodeId,
    reflexive: Option<SocketAddr>,
    disc_tx: mpsc::Sender<DiscoveredPeer>,
) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(&bind).await?);
    let local = socket.local_addr()?;
    let kad_id = node_id.0;

    let node = Arc::new(Mutex::new(KademliaNode::new(kad_id)));
    let dht = DhtNode::new(socket, Arc::clone(&node));
    dht.spawn_server();
    let kad = Arc::new(Kademlia::with_shared(node, dht));
    tracing::info!(dht = %local, node = %node_id.fingerprint(), "DHT node listening");

    // Join the DHT through any bootstrap nodes.
    let boots: Vec<SocketAddr> = bootstrap.iter().filter_map(|a| a.parse().ok()).collect();
    if !boots.is_empty() {
        kad.bootstrap_addrs(&boots).await;
        tracing::info!(count = boots.len(), "DHT bootstrapped");
    }

    // Publish our candidate addresses so peers can find us by node id.
    if let Some(public) = reflexive {
        match kad.publish(kad_id, &[public]).await {
            Ok(()) => tracing::info!(%public, "published candidate to DHT"),
            Err(e) => tracing::warn!(error = %e, "DHT publish failed"),
        }
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

    Ok(())
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

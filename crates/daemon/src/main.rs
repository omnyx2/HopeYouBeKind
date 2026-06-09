//! The Lattice daemon: a long-running, privileged process that owns the TUN
//! device and the network sockets, hosts the [`Engine`], and answers control
//! requests from the GUI/CLI over a local IPC channel.
//!
//! Privileges are needed to create the virtual interface; everything user-facing
//! talks to this process instead of touching the network directly.

use anyhow::Result;
use clap::Parser;
use lattice_crypto::Identity;
use lattice_engine::{Engine, EngineConfig};
use lattice_net::discovery::MdnsDiscovery;
use lattice_net::udp::UdpTransport;
use lattice_net::Transport;
use lattice_proto::OVERLAY_SUBNET;
use lattice_tun::TunConfig;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // TODO(v0.4): load a persisted identity from disk; generate on first run.
    let identity = Identity::generate()?;
    let node_id = identity.node_id();
    let public_key = identity.public_key().to_vec();

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

    // Bring up the real data plane. Creating the TUN device needs root.
    let tun = lattice_tun::open(TunConfig {
        address: virtual_ip,
        prefix_len: OVERLAY_SUBNET.1,
        mtu: 1380,
    })
    .await
    .map_err(|e| anyhow::anyhow!("failed to open TUN device (need sudo?): {e}"))?;

    let transport = UdpTransport::bind(args.bind.parse()?).await?;
    let udp_addr = transport.local_addr()?;
    tracing::info!(udp = %udp_addr, "transport bound");

    // Best-effort: learn our public (reflexive) address via STUN. Used as a
    // WAN candidate for NAT hole punching. (Distributing it to peers without a
    // server — the DHT rendezvous — is the remaining v0.6 work; today this is
    // informational + available for manual peer pinning.)
    match lattice_net::nat::reflexive_address("stun.l.google.com:19302").await {
        Ok(public) => tracing::info!(%public, "public address (STUN)"),
        Err(e) => tracing::debug!(error = %e, "STUN lookup failed (LAN-only or offline)"),
    }

    // Serverless LAN discovery: advertise ourselves and browse for peers over
    // mDNS. Discovered peers trigger an automatic handshake in the engine.
    let discovery = MdnsDiscovery::new(&public_key, udp_addr.port())?;

    // IPC server lets the GUI/CLI query status and toggle the mesh while the
    // engine runs. The handler captures a cloneable handle to the engine.
    let ipc_handle = engine.handle();
    let ipc = lattice_ipc::serve(&args.ipc_socket, move |req| {
        let handle = ipc_handle.clone();
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
    Ok(())
}

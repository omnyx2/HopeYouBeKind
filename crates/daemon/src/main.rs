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
    tracing::info!(udp = %transport.local_addr()?, "transport bound");

    // mDNS LAN discovery (browse/resolve lands in v0.3; until then no peers
    // are surfaced and the node simply holds the interface up).
    let discovery = MdnsDiscovery::new()?;

    // TODO(v0.4): also bind the IPC listener so the GUI/CLI can drive this node.
    tokio::select! {
        result = engine.run(tun, transport, discovery) => {
            result?;
            tracing::info!("engine loop ended");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
        }
    }
    Ok(())
}

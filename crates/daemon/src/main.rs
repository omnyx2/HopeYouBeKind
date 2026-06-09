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
    let engine = Engine::new(identity, config);

    tracing::info!(
        node = %node_id.fingerprint(),
        virtual_ip = %engine.virtual_ip(),
        ipc = %args.ipc_socket,
        "lattice-daemon ready (engine wiring lands in v0.2)"
    );

    // TODO(v0.4): bind the IPC listener, accept clients, and dispatch
    // lattice_proto::ipc::Request → engine actions. For now, idle until signal.
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}

//! MiniSync — the reference Lattice connector (docs/EXTENSIONS.md §10).
//!
//! A standalone program that keeps a folder in sync across mesh members,
//! peer-to-peer over the overlay. It uses Lattice purely for **identity +
//! discovery + events** (control-plane scopes `events:peer`, `registry:read`,
//! `registry:advertise`) and runs its own simple sync protocol over plain TCP to
//! each peer's overlay IP. It never touches packets or mesh crypto/routing.
//!
//! Module map:
//! - [`ipc`] — meshd's newline-JSON control wire, mirrored on the connector side.
//! - [`meshd`] — the connector handshake + discovery loop (peer set producer).
//! - [`sync`] — the folder reconcile engine (peer set consumer + TCP server).
//! - [`config`] — runtime configuration.
//! - [`mock`] — an in-process `mock_meshd` for tests/demos (unix only).

pub mod config;
pub mod ipc;
pub mod meshd;
pub mod sync;

#[cfg(unix)]
pub mod mock;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::watch;

pub use config::Config;

/// Wire up and run the connector: the sync TCP server, the meshd discovery
/// client, and the reconcile loop. Runs until Ctrl-C (or SIGTERM on unix).
pub async fn run(config: Config) -> Result<()> {
    let listen: SocketAddr = format!("0.0.0.0:{}", config.listen_port).parse()?;

    // Discovered peers flow from the meshd client to the sync loop.
    let (peers_tx, peers_rx) = watch::channel::<Vec<SocketAddr>>(Vec::new());

    let server = tokio::spawn(sync::run_server(config.folder.clone(), listen));

    let sync_loop = tokio::spawn(sync::run_sync_loop(
        config.folder.clone(),
        peers_rx,
        Duration::from_secs(config.sync_interval_secs.max(1)),
    ));

    let meshd_client = tokio::spawn(meshd::run_client(config.clone(), peers_tx));

    tracing::info!(
        folder = %config.folder.display(),
        port = config.listen_port,
        "minisync connector running"
    );

    shutdown_signal().await;
    tracing::info!("shutting down");
    server.abort();
    sync_loop.abort();
    meshd_client.abort();
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

//! `minisync` — the connector binary. Parses config, then runs the engine.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use minisync::config::{default_meshd_endpoint, Config, DEFAULT_LISTEN_PORT, ENV_MESHD, ENV_TOKEN};

/// MiniSync — folder-sync connector for the Lattice mesh VPN.
#[derive(Parser, Debug)]
#[command(name = "minisync", version, about)]
struct Cli {
    /// Folder to keep in sync.
    #[arg(long, value_name = "DIR")]
    folder: PathBuf,

    /// TCP port the sync server listens on (over the overlay IP).
    #[arg(long, default_value_t = DEFAULT_LISTEN_PORT)]
    port: u16,

    /// meshd IPC endpoint (unix socket path or `\\.\pipe\...`). Overridable with
    /// the LATTICE_MESHD_SOCK env var; defaults to the platform socket.
    #[arg(long)]
    meshd: Option<String>,

    /// Grant token from `EnableExtension`. Prefer the MINISYNC_TOKEN env var so
    /// it stays out of shell history / process listings.
    #[arg(long)]
    token: Option<String>,

    /// Mesh id to advertise/discover on. (The spec omits a mesh id from the
    /// Advertise/ListServices examples, but the IPC requires one — see README.)
    #[arg(long, default_value_t = 0)]
    mesh: u8,

    /// Our own overlay IP, to exclude self from discovery (meshd doesn't flag it).
    #[arg(long)]
    self_ip: Option<String>,

    /// Seconds between reconcile passes.
    #[arg(long, default_value_t = 5)]
    sync_interval: u64,

    /// Seconds between re-advertise + re-list refreshes.
    #[arg(long, default_value_t = 30)]
    advertise_refresh: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let token = cli
        .token
        .or_else(|| std::env::var(ENV_TOKEN).ok())
        .context(
            "no grant token: pass --token or set MINISYNC_TOKEN (from EnableExtension in the GUI)",
        )?;

    let meshd_endpoint = cli
        .meshd
        .or_else(|| std::env::var(ENV_MESHD).ok())
        .unwrap_or_else(default_meshd_endpoint);

    let folder = cli
        .folder
        .canonicalize()
        .with_context(|| format!("folder does not exist: {}", cli.folder.display()))?;

    let config = Config {
        folder,
        listen_port: cli.port,
        meshd_endpoint,
        token,
        mesh: cli.mesh,
        sync_interval_secs: cli.sync_interval,
        advertise_refresh_secs: cli.advertise_refresh,
        self_overlay_ip: cli.self_ip,
    };

    minisync::run(config).await
}

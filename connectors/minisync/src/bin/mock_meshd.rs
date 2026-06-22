//! `mock_meshd` — a standalone stand-in for the meshd connector framework, for
//! manual demos before the real daemon ships it (docs/EXTENSIONS.md §3/§5).
//!
//! It serves the connector IPC on a unix socket and answers `ListServices` with
//! a single canned peer, so a real `minisync` process can discover and sync with
//! another `minisync` process. Example (two terminals + this in two more):
//!
//! ```sh
//! mock_meshd --sock /tmp/a.sock --peer 127.0.0.1:48402
//! minisync --folder ./A --port 48401 --meshd /tmp/a.sock --token demo
//! ```

#[cfg(unix)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;
    use minisync::ipc::ServiceView;
    use minisync::mock::{self, MockConfig};

    #[derive(Parser)]
    #[command(name = "mock_meshd", about)]
    struct Cli {
        /// Unix socket to serve on (point `minisync --meshd` here).
        #[arg(long)]
        sock: String,
        /// The single peer to advertise as `overlay_ip:port` (the OTHER minisync).
        #[arg(long)]
        peer: String,
        /// Token a connector must present in `Hello`.
        #[arg(long, default_value = "demo")]
        token: String,
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let (ip, port) = cli
        .peer
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("--peer must be ip:port"))?;

    let mut cfg = MockConfig::with_minisync_grant(&cli.token);
    cfg.services = vec![ServiceView {
        mesh: 0,
        member: 2,
        member_name: "peer".into(),
        overlay_ip: ip.to_string(),
        proto: "minisync".into(),
        port: port.parse()?,
        name: "MiniSync peer".into(),
        meta: serde_json::json!({ "folder": "demo" }),
        online: true,
    }];
    cfg.peer_events = vec![serde_json::json!({
        "kind": "peer_up", "mesh": 0, "member": 2, "name": "peer", "overlay_ip": ip
    })];

    // Remove the socket path from any prior run, then serve until killed.
    let _ = std::fs::remove_file(&cli.sock);
    let handle = mock::start_at(std::path::PathBuf::from(&cli.sock), cfg).await?;
    tracing::info!(sock = %cli.sock, peer = %cli.peer, "mock_meshd serving");
    // Keep the process (and the listener inside `handle`) alive.
    let _ = tokio::signal::ctrl_c().await;
    drop(handle);
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("mock_meshd is unix-only");
}

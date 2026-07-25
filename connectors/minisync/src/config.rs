//! Connector configuration: where the folder is, what port to sync on, and how
//! to reach meshd. Values come from CLI flags with environment overrides.

use std::path::PathBuf;

/// Default sync listen port (docs/EXTENSIONS.md §10 / manifest `default_port`).
pub const DEFAULT_LISTEN_PORT: u16 = 48211;
/// Connector id, must match the enabled grant in meshd's `extensions.json`.
pub const EXT_ID: &str = "minisync";
/// Service proto advertised + queried in the registry.
pub const PROTO: &str = "minisync";
/// This connector's version, sent in `Hello` (informational to meshd).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Env var overriding the meshd endpoint (unix socket path / windows pipe name).
pub const ENV_MESHD: &str = "LATTICE_MESHD_SOCK";
/// Env var supplying the grant token (preferred over `--token` on the CLI so it
/// doesn't land in shell history / process listings).
pub const ENV_TOKEN: &str = "MINISYNC_TOKEN";

/// The platform default meshd endpoint (docs/EXTENSIONS.md §2).
pub fn default_meshd_endpoint() -> String {
    #[cfg(windows)]
    {
        r"\\.\pipe\lattice-meshd".to_string()
    }
    #[cfg(not(windows))]
    {
        "/tmp/lattice-meshd.sock".to_string()
    }
}

/// Fully resolved runtime configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Folder kept in sync.
    pub folder: PathBuf,
    /// TCP port the sync server listens on (over the overlay IP).
    pub listen_port: u16,
    /// meshd IPC endpoint — unix socket path or `\\.\pipe\...` named pipe.
    pub meshd_endpoint: String,
    /// Grant token from `EnableExtension` (0600 `extensions.json`).
    pub token: String,
    /// Which mesh to advertise/discover on. The spec's `Advertise`/`ListServices`
    /// examples omit a mesh id, but the real IPC requires one (see README gap).
    pub mesh: super::ipc::MeshId,
    /// Seconds between periodic reconcile passes against known peers.
    pub sync_interval_secs: u64,
    /// Seconds between re-advertising (refreshing the registry TTL) + re-listing.
    pub advertise_refresh_secs: u64,
    /// Our own overlay IP, if known — used to skip self in `ListServices`
    /// results (meshd does not flag `is_me`; see README gap). Optional.
    pub self_overlay_ip: Option<String>,
}

impl Config {
    /// The folder label advertised in the service `meta` (`{folder: ...}`).
    pub fn folder_label(&self) -> String {
        self.folder
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.folder.to_string_lossy().into_owned())
    }
}

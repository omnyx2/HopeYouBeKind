//! The node runtime — the conductor. It owns this node's identity and overlay
//! state and (once milestones land) drives the packet loop:
//!
//! ```text
//! TUN.read → overlay.route → crypto.encrypt → transport.send  ─► peer
//! TUN.write ← crypto.decrypt ← transport.recv                  ◄─ peer
//! ```
//!
//! The data-plane crates expose traits ([`TunDevice`], [`Transport`],
//! [`Discovery`]) so the engine is constructed with whichever implementations
//! fit — real devices in the daemon, in-memory fakes in tests.

use std::net::SocketAddr;
use std::sync::Arc;

use lattice_crypto::Identity;
use lattice_net::{Discovery, Transport};
use lattice_overlay::{derive_virtual_ip, Overlay};
use lattice_proto::ipc::NodeStatus;
use lattice_proto::VirtualIp;
use lattice_tun::TunDevice;
use tokio::sync::Mutex;

#[derive(thiserror::Error, Debug)]
pub enum EngineError {
    #[error(transparent)]
    Crypto(#[from] lattice_crypto::CryptoError),
    #[error(transparent)]
    Net(#[from] lattice_net::NetError),
    #[error(transparent)]
    Tun(#[from] lattice_tun::TunError),
    #[error(transparent)]
    Overlay(#[from] lattice_overlay::OverlayError),
}

/// Tunables for a node.
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Local UDP address to bind the transport to (port 0 = OS-assigned).
    pub bind_addr: SocketAddr,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().expect("valid bind addr"),
        }
    }
}

/// One Lattice node. Generic over the data-plane implementations so production
/// and test wiring share the same logic.
pub struct Engine {
    identity: Arc<Identity>,
    virtual_ip: VirtualIp,
    overlay: Arc<Mutex<Overlay>>,
    config: EngineConfig,
    running: bool,
}

impl Engine {
    /// Create a node from an identity. The virtual IP is derived from identity.
    pub fn new(identity: Identity, config: EngineConfig) -> Self {
        let virtual_ip = derive_virtual_ip(&identity.node_id());
        Self {
            identity: Arc::new(identity),
            virtual_ip,
            overlay: Arc::new(Mutex::new(Overlay::new())),
            config,
            running: false,
        }
    }

    pub fn virtual_ip(&self) -> VirtualIp {
        self.virtual_ip
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// A snapshot for the GUI/CLI dashboard.
    pub async fn status(&self) -> NodeStatus {
        NodeStatus {
            id: self.identity.node_id(),
            virtual_ip: Some(self.virtual_ip),
            running: self.running,
            peer_count: self.overlay.lock().await.peer_count(),
        }
    }

    /// Drive the node: discovery feeds the overlay; the packet loop tunnels
    /// traffic between the TUN device and peers. Fleshed out across v0.2–v0.3
    /// (see ROADMAP); the signature fixes the dependency shape now.
    pub async fn run<T, X, D>(
        &mut self,
        _tun: T,
        _transport: X,
        _discovery: D,
    ) -> Result<(), EngineError>
    where
        T: TunDevice,
        X: Transport,
        D: Discovery,
    {
        self.running = true;
        tracing::info!(virtual_ip = %self.virtual_ip, "engine started");
        // TODO(v0.2): select! over tun.read_packet / transport.recv_from /
        // discovery.next_peer and route between them.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn node_derives_a_stable_virtual_ip_from_identity() {
        let id = Identity::generate().unwrap();
        let node_id = id.node_id();
        let engine = Engine::new(id, EngineConfig::default());
        assert_eq!(engine.virtual_ip(), derive_virtual_ip(&node_id));
        let status = engine.status().await;
        assert!(!status.running);
        assert_eq!(status.peer_count, 0);
    }
}

//! The node runtime — the conductor. It owns this node's identity, its sessions
//! to peers, and the overlay routing state, and drives the packet loop:
//!
//! ```text
//! TUN.read → route(dst) → session.encrypt → transport.send  ─► peer
//! TUN.write ← session.decrypt ← transport.recv              ◄─ peer
//! ```
//!
//! The data-plane crates expose traits ([`TunDevice`], [`Transport`],
//! [`Discovery`]) so the engine runs against real devices in the daemon and
//! in-memory fakes in tests — same logic either way.
//!
//! v0.2 scope: a peer surfaced by discovery triggers an eager Noise-IK
//! handshake; once the session is up, overlay packets tunnel through it. Lazy
//! handshake queueing, rekeying, and lossy-path replay handling are later
//! milestones (see ROADMAP / PROTOCOL.md).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lattice_crypto::{respond, Handshake, Identity, NoiseSession, TunnelSession};
use lattice_net::{DiscoveredPeer, Discovery, Transport};
use lattice_overlay::{derive_virtual_ip, Overlay};
use lattice_proto::ipc::NodeStatus;
use lattice_proto::wire::{self, MessageType};
use lattice_proto::{NodeId, PeerInfo, PeerStatus, VirtualIp};
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

/// One Lattice node.
pub struct Engine {
    identity: Arc<Identity>,
    virtual_ip: VirtualIp,
    overlay: Arc<Mutex<Overlay>>,
    /// Live sessions, keyed by the peer's transport endpoint.
    sessions: HashMap<SocketAddr, NoiseSession>,
    /// Initiator handshakes awaiting a response, keyed by the peer's endpoint.
    pending: HashMap<SocketAddr, Handshake>,
    /// The endpoint each peer is actually reachable at, learned when its session
    /// establishes — the candidate whose NAT binding won the hole punch.
    connected: HashMap<NodeId, SocketAddr>,
    config: EngineConfig,
    /// Whether the engine loop is live (set while `run` is executing).
    running: Arc<AtomicBool>,
    /// Whether the mesh is administratively up (toggled via the IPC `up`/`down`).
    enabled: Arc<AtomicBool>,
}

impl Engine {
    /// Create a node from an identity. The virtual IP is derived from identity.
    pub fn new(identity: Identity, config: EngineConfig) -> Self {
        let virtual_ip = derive_virtual_ip(&identity.node_id());
        Self {
            identity: Arc::new(identity),
            virtual_ip,
            overlay: Arc::new(Mutex::new(Overlay::new())),
            sessions: HashMap::new(),
            pending: HashMap::new(),
            connected: HashMap::new(),
            config,
            running: Arc::new(AtomicBool::new(false)),
            enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn virtual_ip(&self) -> VirtualIp {
        self.virtual_ip
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// A cloneable handle for reading status and issuing control commands while
    /// the engine runs in its own task — used by the daemon's IPC server.
    pub fn handle(&self) -> EngineHandle {
        EngineHandle {
            node_id: self.identity.node_id(),
            virtual_ip: self.virtual_ip,
            overlay: Arc::clone(&self.overlay),
            running: Arc::clone(&self.running),
            enabled: Arc::clone(&self.enabled),
        }
    }

    /// A snapshot for the GUI/CLI dashboard.
    pub async fn status(&self) -> NodeStatus {
        self.handle().status().await
    }

    /// Drive the node until the TUN device or transport closes.
    pub async fn run<T, X, D>(
        &mut self,
        mut tun: T,
        transport: X,
        mut discovery: D,
    ) -> Result<(), EngineError>
    where
        T: TunDevice,
        X: Transport,
        D: Discovery,
    {
        self.running.store(true, Ordering::Relaxed);
        tracing::info!(virtual_ip = %self.virtual_ip, "engine started");

        let mut discovery_done = false;
        loop {
            tokio::select! {
                // A peer was discovered → start a handshake with it.
                maybe_peer = discovery.next_peer(), if !discovery_done => {
                    match maybe_peer {
                        Some(peer) => {
                            if let Err(e) = self.on_peer_discovered(peer, &transport).await {
                                tracing::warn!(error = %e, "handshake initiation failed");
                            }
                        }
                        None => discovery_done = true,
                    }
                }
                // An overlay packet came out of the local TUN → tunnel it.
                packet = tun.read_packet() => {
                    match packet {
                        Ok(p) => {
                            if let Err(e) = self.on_outbound(&p, &transport).await {
                                tracing::warn!(error = %e, "outbound packet dropped");
                            }
                        }
                        Err(_) => break,
                    }
                }
                // A datagram arrived from a peer → handshake step or decrypt.
                datagram = transport.recv_from() => {
                    match datagram {
                        Ok((data, from)) => {
                            if let Err(e) = self.on_inbound(&data, from, &transport, &mut tun).await {
                                tracing::warn!(error = %e, %from, "inbound datagram dropped");
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        self.running.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// Begin an IK handshake toward a freshly discovered peer.
    async fn on_peer_discovered<X: Transport>(
        &mut self,
        peer: DiscoveredPeer,
        transport: &X,
    ) -> Result<(), EngineError> {
        if peer.endpoints.is_empty() {
            return Ok(()); // no address to reach them yet
        }
        // Identity == public key in v0, so discovery carries everything we need.
        let public_key = peer.id.0.to_vec();
        let info = PeerInfo {
            id: peer.id,
            virtual_ip: derive_virtual_ip(&peer.id),
            public_key: public_key.clone(),
            endpoints: peer.endpoints.clone(),
            status: PeerStatus::Connecting,
        };
        self.overlay.lock().await.upsert_peer(info)?;

        let private = self.identity.private_key().to_vec();
        // Hole punch: initiate a handshake toward every candidate endpoint at
        // once. The first to answer wins — its NAT binding is the working path.
        // A single unreachable candidate must not abort the others.
        for &endpoint in &peer.endpoints {
            let (handshake, init_msg) = Handshake::initiate(&private, &public_key)?;
            let frame = wire::encode(MessageType::HandshakeInit, &init_msg);
            match transport.send_to(&frame, endpoint).await {
                Ok(()) => {
                    self.pending.insert(endpoint, handshake);
                }
                Err(e) => {
                    tracing::debug!(%endpoint, error = %e, "candidate unreachable, skipping");
                }
            }
        }
        tracing::info!(
            peer = %peer.id.fingerprint(),
            candidates = peer.endpoints.len(),
            "handshake initiated"
        );
        Ok(())
    }

    /// A local packet that needs to reach a peer's virtual IP.
    async fn on_outbound<X: Transport>(
        &mut self,
        packet: &[u8],
        transport: &X,
    ) -> Result<(), EngineError> {
        let Some(dst) = ipv4_dst(packet) else {
            return Ok(()); // not IPv4 / too short — ignore for now
        };
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(()); // mesh administratively down
        }
        let (peer_id, fallback) = {
            let overlay = self.overlay.lock().await;
            match overlay.route(&dst) {
                Ok(peer) => (peer.id, peer.endpoints.first().copied()),
                Err(_) => return Ok(()),
            }
        };
        // Prefer the endpoint whose session is live; fall back to the first
        // candidate while the handshake is still settling.
        let Some(endpoint) = self.connected.get(&peer_id).copied().or(fallback) else {
            return Ok(()); // no route yet
        };
        let Some(session) = self.sessions.get_mut(&endpoint) else {
            // Session still being established; drop (like a real net during setup).
            return Ok(());
        };
        let sealed = session.encrypt(packet)?;
        transport
            .send_to(&wire::encode(MessageType::Transport, &sealed), endpoint)
            .await?;
        Ok(())
    }

    /// A datagram from a peer: a handshake step or an encrypted overlay packet.
    async fn on_inbound<X: Transport, T: TunDevice>(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        transport: &X,
        tun: &mut T,
    ) -> Result<(), EngineError> {
        let Some((msg_type, payload)) = wire::decode(data) else {
            return Ok(());
        };
        match msg_type {
            MessageType::HandshakeInit => {
                let private = self.identity.private_key().to_vec();
                let pending = respond(&private, payload)?;
                let peer_id = node_id_from_pubkey(&pending.remote_static);
                let info = PeerInfo {
                    id: peer_id,
                    virtual_ip: derive_virtual_ip(&peer_id),
                    public_key: pending.remote_static,
                    endpoints: vec![from],
                    status: PeerStatus::Connected,
                };
                self.overlay.lock().await.upsert_peer(info)?;
                self.sessions.insert(from, pending.session);
                self.connected.insert(peer_id, from);
                transport
                    .send_to(
                        &wire::encode(MessageType::HandshakeResp, &pending.response),
                        from,
                    )
                    .await?;
                tracing::info!(peer = %peer_id.fingerprint(), %from, "session established (responder)");
            }
            MessageType::HandshakeResp => {
                if let Some(handshake) = self.pending.remove(&from) {
                    let session = handshake.complete(payload)?;
                    self.sessions.insert(from, session);
                    if let Some(peer_id) = self.peer_id_at(from).await {
                        self.connected.insert(peer_id, from);
                        self.overlay
                            .lock()
                            .await
                            .set_status(&peer_id, PeerStatus::Connected);
                    }
                    tracing::info!(%from, "session established (initiator)");
                }
            }
            MessageType::Transport => {
                let plaintext = match self.sessions.get_mut(&from) {
                    Some(session) => session.decrypt(payload)?,
                    None => return Ok(()), // no session for this source
                };
                tun.write_packet(&plaintext).await?;
            }
            MessageType::Keepalive => { /* v0.7: liveness tracking */ }
        }
        Ok(())
    }

    /// Find which known peer currently lives at `endpoint`.
    async fn peer_id_at(&self, endpoint: SocketAddr) -> Option<NodeId> {
        self.overlay
            .lock()
            .await
            .peers()
            .find(|p| p.endpoints.first() == Some(&endpoint))
            .map(|p| p.id)
    }
}

/// A cloneable, read/command handle to a running [`Engine`]. The daemon hands
/// these to its IPC server so the GUI/CLI can query status and toggle the mesh
/// while the engine loop runs in its own task.
#[derive(Clone)]
pub struct EngineHandle {
    node_id: NodeId,
    virtual_ip: VirtualIp,
    overlay: Arc<Mutex<Overlay>>,
    running: Arc<AtomicBool>,
    enabled: Arc<AtomicBool>,
}

impl EngineHandle {
    pub async fn status(&self) -> NodeStatus {
        let up = self.running.load(Ordering::Relaxed) && self.enabled.load(Ordering::Relaxed);
        NodeStatus {
            id: self.node_id,
            virtual_ip: Some(self.virtual_ip),
            running: up,
            peer_count: self.overlay.lock().await.peer_count(),
        }
    }

    pub async fn peers(&self) -> Vec<PeerInfo> {
        self.overlay.lock().await.peers().cloned().collect()
    }

    /// Bring the mesh up (`true`) or down (`false`). When down, the engine keeps
    /// running but stops forwarding overlay packets.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }
}

/// Extract the IPv4 destination address from a raw IP packet, if it is IPv4.
fn ipv4_dst(packet: &[u8]) -> Option<VirtualIp> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let o = &packet[16..20];
    Some(VirtualIp(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
}

/// In v0 the 32-byte public key is the NodeId.
fn node_id_from_pubkey(pubkey: &[u8]) -> NodeId {
    let mut id = [0u8; 32];
    let n = pubkey.len().min(32);
    id[..n].copy_from_slice(&pubkey[..n]);
    NodeId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_net::discovery::StaticDiscovery;
    use lattice_net::memory::duplex;
    use lattice_tun::memory::MemoryTun;
    use std::time::Duration;

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

    /// Two engines on one host, wired by an in-memory transport: A handshakes
    /// with B, then a packet injected into A's TUN comes out B's TUN decrypted.
    /// This is the v0.2 loopback-tunnel demo, runnable with no root or real NIC.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn packet_tunnels_end_to_end_between_two_nodes() {
        let id_a = Identity::generate().unwrap();
        let id_b = Identity::generate().unwrap();
        let vip_a = derive_virtual_ip(&id_a.node_id());
        let vip_b = derive_virtual_ip(&id_b.node_id());
        let id_b_nodeid = id_b.node_id();

        let addr_a: SocketAddr = "10.0.0.1:700".parse().unwrap();
        let addr_b: SocketAddr = "10.0.0.2:700".parse().unwrap();
        let (ta, tb) = duplex(addr_a, addr_b);

        let (tun_a, handle_a) = MemoryTun::new();
        let (tun_b, mut handle_b) = MemoryTun::new();

        // A discovers B (reachable at addr_b); B discovers nobody (learns A from
        // the incoming handshake).
        let disc_a = StaticDiscovery::new(vec![DiscoveredPeer {
            id: id_b_nodeid,
            endpoints: vec![addr_b],
        }]);
        let disc_b = StaticDiscovery::new(vec![]);

        let mut engine_a = Engine::new(id_a, EngineConfig::default());
        let mut engine_b = Engine::new(id_b, EngineConfig::default());

        tokio::spawn(async move {
            let _ = engine_a.run(tun_a, ta, disc_a).await;
        });
        tokio::spawn(async move {
            let _ = engine_b.run(tun_b, tb, disc_b).await;
        });

        // Let the handshake settle (in-memory: sub-millisecond).
        tokio::time::sleep(Duration::from_millis(100)).await;

        // A minimal IPv4 packet from vip_a → vip_b (only version + dst matter here).
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // IPv4, IHL 5
        packet[12..16].copy_from_slice(&vip_a.0.octets());
        packet[16..20].copy_from_slice(&vip_b.0.octets());

        handle_a.inject.send(packet.clone()).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), handle_b.observe.recv())
            .await
            .expect("packet should arrive at B within timeout")
            .expect("B's TUN channel stayed open");

        assert_eq!(
            received, packet,
            "B must receive A's original packet decrypted"
        );
    }
}

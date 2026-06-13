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
//! handshake; once the session is up, overlay packets tunnel through it. Sessions
//! are renegotiated on WireGuard's timer schedule — proactively rekeyed before
//! their keys go stale ([`REKEY_TIMEOUT`]-spaced retries off the suite's
//! [`rekey_due`](lattice_crypto::TunnelSession::rekey_due)) and hard-expired past
//! [`REJECT_AFTER_TIME`]. Lazy handshake queueing and lossy-path replay handling
//! are later milestones (see ROADMAP / PROTOCOL.md).

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lattice_crypto::{CryptoSuite, HandshakeState, Identity, NoiseSuite, TunnelSession};
use lattice_membership::{MemberCert, NetworkId, Revocation, RevocationList};
use lattice_net::{DiscoveredPeer, Discovery, Transport};
use lattice_overlay::{derive_virtual_ip, Overlay};
use lattice_proto::ipc::{FlowRecord, NodeStatus};
use lattice_proto::wire::{self, MessageType};
use lattice_proto::{NodeId, PeerInfo, PeerStatus, VirtualIp};
use lattice_tun::TunDevice;
use tokio::sync::Mutex;

pub mod monitor;
use monitor::{Direction, TrafficMonitor};

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
    /// The pluggable crypto suite driving every handshake + session. Swap this
    /// to research a different scheme; Noise-IK is the default.
    suite: Arc<dyn CryptoSuite>,
    /// Live sessions, keyed by the peer's transport endpoint.
    sessions: HashMap<SocketAddr, Box<dyn TunnelSession>>,
    /// Initiator handshakes awaiting a response, keyed by the peer's endpoint.
    pending: HashMap<SocketAddr, Box<dyn HandshakeState>>,
    /// The endpoint each peer is actually reachable at, learned when its session
    /// establishes — the candidate whose NAT binding won the hole punch.
    connected: HashMap<NodeId, SocketAddr>,
    /// When we last received any datagram from each endpoint — drives
    /// reachability (and keepalives keep NAT bindings open).
    last_seen: HashMap<SocketAddr, Instant>,
    config: EngineConfig,
    /// Whether the engine loop is live (set while `run` is executing).
    running: Arc<AtomicBool>,
    /// Whether the mesh is administratively up (toggled via the IPC `up`/`down`).
    enabled: Arc<AtomicBool>,
    /// Our public (reflexive) address from STUN, set by the daemon once known.
    public_addr: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    /// The peer we route internet-bound traffic through (exit node), if any.
    exit_node: Arc<std::sync::Mutex<Option<NodeId>>>,
    /// Whether we forward other nodes' internet traffic (act as an exit node).
    allow_exit: Arc<AtomicBool>,
    /// Passive observer of every packet crossing the tunnel — feeds the GUI's
    /// traffic monitor.
    monitor: Arc<TrafficMonitor>,
    /// The network we belong to and verify peers against. `None` = open mode
    /// (no membership gate — any peer that completes the handshake is admitted).
    network: Arc<std::sync::Mutex<Option<NetworkId>>>,
    /// Our own membership certificate, presented in the handshake. `None` in
    /// open mode. Shared so the IPC handle can join a network at runtime.
    cert: Arc<std::sync::Mutex<Option<MemberCert>>>,
    /// Revocations we know about, gossiped across the mesh. Shared so the IPC
    /// handle can inject new ones (the admin evicting a member).
    revocations: Arc<std::sync::Mutex<RevocationList>>,
    /// Cert serial of each connected peer, so a gossiped revocation can be
    /// matched to a live session and the peer dropped.
    peer_serial: HashMap<NodeId, u64>,
    /// Set when membership changes at runtime (a join): the loop drops all
    /// sessions on the next tick so they re-handshake under the new network.
    resync: Arc<AtomicBool>,
    /// Node ids we were handed an explicit reachable address for (a direct
    /// `--peer-addr` / runtime AddPeer pin). These bypass the id tie-break in
    /// `on_peer_discovered`, so the *pinning* side always initiates — required
    /// when reachability is one-sided (a port-forwarded anchor across NATs),
    /// where the tie-break's designated initiator may be the unreachable side.
    /// Shared so the IPC handle can register pins at runtime.
    force_initiate: Arc<std::sync::Mutex<HashSet<NodeId>>>,
    /// Initiator side: when we last sent a handshake INIT to each peer. Gates
    /// re-initiation to at most once per [`REKEY_TIMEOUT`] so a re-init never
    /// overwrites an in-flight `pending` before its response can complete it
    /// (WireGuard's "one handshake in flight" rule — fixes the half-open deadlock).
    last_init: HashMap<NodeId, Instant>,
    /// Responder side: when we last accepted an INIT from each peer and replied.
    /// Suppresses only a *burst* of duplicate inits (multi-candidate hole punch /
    /// retransmits) within [`REKEY_TIMEOUT`]; a genuine re-handshake after that is
    /// always honoured, so a peer whose session died can always reconnect.
    last_responded: HashMap<NodeId, Instant>,
    /// When each live session was established, keyed by its endpoint (parallel to
    /// `sessions`). Drives session lifetime: the suite's `rekey_due` against this
    /// age triggers a proactive rekey, and [`REJECT_AFTER_TIME`] forces expiry.
    established: HashMap<SocketAddr, Instant>,
}

/// Minimum interval between handshake initiations to one peer, and the window in
/// which a responder treats repeated inits as duplicates. From WireGuard's timer
/// state machine (REKEY_TIMEOUT). Keeps at most one handshake in flight so the
/// initiator's `pending` isn't churned out from under an arriving response.
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);

/// A session must not be used past this age — the engine tears it down and forces
/// a fresh handshake. WireGuard's REJECT_AFTER_TIME. The proactive rekey (driven
/// by the suite's shorter REKEY_AFTER_TIME, surfaced via
/// [`TunnelSession::rekey_due`](lattice_crypto::TunnelSession::rekey_due)) renews
/// the session well before this in the normal case; this is the safety net for
/// when a rekey can't complete yet keepalives keep the peer off the dead list, so
/// it never runs indefinitely on stale keys.
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

impl Engine {
    /// Create a node from an identity, using the default Noise-IK crypto suite.
    /// The virtual IP is derived from identity.
    pub fn new(identity: Identity, config: EngineConfig) -> Self {
        Self::with_suite(identity, config, Arc::new(NoiseSuite))
    }

    /// Create a node with an explicit crypto suite — the seam for researching
    /// alternative tunnel encryption without touching the engine.
    pub fn with_suite(
        identity: Identity,
        config: EngineConfig,
        suite: Arc<dyn CryptoSuite>,
    ) -> Self {
        let virtual_ip = derive_virtual_ip(&identity.node_id());
        Self {
            identity: Arc::new(identity),
            virtual_ip,
            suite,
            overlay: Arc::new(Mutex::new(Overlay::new())),
            sessions: HashMap::new(),
            pending: HashMap::new(),
            connected: HashMap::new(),
            last_seen: HashMap::new(),
            config,
            running: Arc::new(AtomicBool::new(false)),
            enabled: Arc::new(AtomicBool::new(true)),
            public_addr: Arc::new(std::sync::Mutex::new(None)),
            exit_node: Arc::new(std::sync::Mutex::new(None)),
            allow_exit: Arc::new(AtomicBool::new(false)),
            monitor: Arc::new(TrafficMonitor::new()),
            network: Arc::new(std::sync::Mutex::new(None)),
            cert: Arc::new(std::sync::Mutex::new(None)),
            revocations: Arc::new(std::sync::Mutex::new(RevocationList::new())),
            peer_serial: HashMap::new(),
            resync: Arc::new(AtomicBool::new(false)),
            force_initiate: Arc::new(std::sync::Mutex::new(HashSet::new())),
            last_init: HashMap::new(),
            last_responded: HashMap::new(),
            established: HashMap::new(),
        }
    }

    /// Join a network: present `cert` (signed by the network CA) on every
    /// handshake and require peers to present a valid, unrevoked cert for the
    /// same `network`. Without this, the node runs in open mode (no gate).
    pub fn set_membership(&mut self, network: NetworkId, cert: MemberCert) {
        *self.network.lock().unwrap() = Some(network);
        *self.cert.lock().unwrap() = Some(cert);
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
            public_addr: Arc::clone(&self.public_addr),
            exit_node: Arc::clone(&self.exit_node),
            allow_exit: Arc::clone(&self.allow_exit),
            monitor: Arc::clone(&self.monitor),
            network: Arc::clone(&self.network),
            cert: Arc::clone(&self.cert),
            revocations: Arc::clone(&self.revocations),
            resync: Arc::clone(&self.resync),
            force_initiate: Arc::clone(&self.force_initiate),
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

        // Periodic keepalive: detects reachability and keeps NAT bindings open.
        let mut keepalive = tokio::time::interval(Duration::from_secs(5));

        let mut discovery_done = false;
        loop {
            tokio::select! {
                // Every tick: probe peers and refresh their reachability.
                _ = keepalive.tick() => {
                    self.on_keepalive_tick(&transport).await;
                }
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

        // Already have a live session with this peer? Don't re-handshake — that
        // churns the Noise session and causes decrypt failures.
        if let Some(&ep) = self.connected.get(&peer.id) {
            let fresh = self
                .last_seen
                .get(&ep)
                .map(|t| t.elapsed() < Duration::from_secs(15))
                .unwrap_or(false);
            if fresh && self.sessions.contains_key(&ep) {
                return Ok(());
            }
        }

        // Tie-break: only the node with the smaller id initiates; the other just
        // waits for the INIT (the pin exception aside). See `should_initiate_to`.
        if !self.should_initiate_to(&peer.id) {
            return Ok(());
        }

        // Identity == public key in v0, so discovery carries everything we need.
        let info = PeerInfo {
            id: peer.id,
            virtual_ip: derive_virtual_ip(&peer.id),
            public_key: peer.id.0.to_vec(),
            endpoints: peer.endpoints.clone(),
            status: PeerStatus::Connecting,
            os: None, // learned from the handshake response
        };
        self.overlay.lock().await.upsert_peer(info)?;

        self.initiate_handshake(peer.id, &peer.endpoints, transport)
            .await?;
        tracing::info!(
            peer = %peer.id.fingerprint(),
            candidates = peer.endpoints.len(),
            "handshake initiated"
        );
        Ok(())
    }

    /// Whether this node should be the one to send the handshake INIT to `peer`:
    /// the id tie-break (the smaller id initiates, so the two sides don't both
    /// handshake at once and desync their sessions). Exception — an explicitly
    /// pinned peer: with a direct `--peer-addr`/AddPeer pin, reachability can be
    /// one-sided (a port-forwarded anchor behind NAT), so the tie-break's chosen
    /// initiator might have no route. The pinning side holds the address, so it
    /// drives the handshake regardless of id ordering (the unreachable side's
    /// INIT goes nowhere anyway).
    fn should_initiate_to(&self, peer: &NodeId) -> bool {
        self.force_initiate.lock().unwrap().contains(peer)
            || self.identity.node_id().0 < peer.0
    }

    /// Send a handshake INIT toward every candidate `endpoints` at once (hole
    /// punch — the first to answer wins, its NAT binding is the working path; a
    /// single unreachable candidate must not abort the others).
    ///
    /// Honours WireGuard's "one handshake in flight" rule: if an INIT we sent is
    /// still pending and was sent within [`REKEY_TIMEOUT`], we don't send another
    /// — re-initiating overwrites `pending`, so the responder's reply to the
    /// first INIT could never complete it (the re-init race that left sessions
    /// stuck "Connecting"). Shared by fresh handshakes and proactive rekeys.
    async fn initiate_handshake<X: Transport>(
        &mut self,
        peer_id: NodeId,
        endpoints: &[SocketAddr],
        transport: &X,
    ) -> Result<(), EngineError> {
        let has_pending = endpoints.iter().any(|ep| self.pending.contains_key(ep));
        if has_pending
            && self
                .last_init
                .get(&peer_id)
                .is_some_and(|t| t.elapsed() < REKEY_TIMEOUT)
        {
            return Ok(());
        }

        let public_key = peer_id.0.to_vec();
        let private = self.identity.private_key().to_vec();
        let meta = self.local_payload();
        for &endpoint in endpoints {
            let (handshake, init_msg) = self.suite.initiate(&private, &public_key, &meta)?;
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
        self.last_init.insert(peer_id, Instant::now());
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

        // Which peer carries this packet?
        let peer_id = if is_overlay_ip(dst) {
            // Mesh traffic → the peer that owns the destination virtual IP.
            match self.overlay.lock().await.route(&dst) {
                Ok(peer) => peer.id,
                Err(_) => return Ok(()),
            }
        } else {
            // Internet-bound traffic → our exit node, if one is selected.
            // (No exit set ⇒ drop, so nothing leaks outside the tunnel.)
            match *self.exit_node.lock().unwrap() {
                Some(id) => id,
                None => return Ok(()),
            }
        };

        let Some(endpoint) = self.endpoint_for(&peer_id).await else {
            return Ok(()); // no path to this peer yet
        };
        let Some(session) = self.sessions.get_mut(&endpoint) else {
            return Ok(()); // session still being established
        };
        // Observe what we're sending before it's sealed (the monitor needs the
        // plaintext IP header to classify the flow).
        self.monitor.record(peer_id, Direction::Tx, packet);
        let sealed = session.encrypt(packet)?;
        transport
            .send_to(&wire::encode(MessageType::Transport, &sealed), endpoint)
            .await?;
        Ok(())
    }

    /// The best endpoint to reach `peer_id`: its live-session endpoint, else its
    /// first known candidate.
    async fn endpoint_for(&self, peer_id: &NodeId) -> Option<SocketAddr> {
        if let Some(ep) = self.connected.get(peer_id) {
            return Some(*ep);
        }
        self.overlay
            .lock()
            .await
            .peers()
            .find(|p| &p.id == peer_id)
            .and_then(|p| p.endpoints.first().copied())
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
        // Any datagram from a peer proves it's alive right now.
        self.last_seen.insert(from, Instant::now());
        match msg_type {
            MessageType::HandshakeInit => {
                let private = self.identity.private_key().to_vec();
                let accepted = self
                    .suite
                    .respond(&private, payload, &self.local_payload())?;
                let peer_id = node_id_from_pubkey(&accepted.peer_identity);

                // Membership gate: in a network, the initiator must present a
                // valid, unrevoked cert for it, bound to its identity key.
                let (peer_cert, os_bytes) = decode_payload(&accepted.peer_payload);
                let serial = match self.verify_membership(&accepted.peer_identity, &peer_cert) {
                    Ok(serial) => serial,
                    Err(e) => {
                        tracing::warn!(peer = %peer_id.fingerprint(), %from, error = %e, "rejected handshake: membership");
                        return Ok(());
                    }
                };

                // WireGuard responder rule: accept a valid INIT and (re)establish
                // the session. Suppress only a *burst* — duplicate inits from
                // multi-candidate hole punching or retransmits within REKEY_TIMEOUT
                // — so we don't churn a session we just made. A genuine
                // re-handshake after REKEY_TIMEOUT is always honoured: that is what
                // breaks the half-open deadlock where the initiator's completion
                // failed yet we kept a one-sided "Connected" session and (because
                // the inits themselves refreshed last_seen) ignored its retries
                // forever.
                let burst = self
                    .last_responded
                    .get(&peer_id)
                    .is_some_and(|t| t.elapsed() < REKEY_TIMEOUT);
                let have_session = self
                    .connected
                    .get(&peer_id)
                    .is_some_and(|ep| self.sessions.contains_key(ep));
                if burst && have_session {
                    return Ok(());
                }
                self.last_responded.insert(peer_id, Instant::now());
                // Replacing at a new endpoint? Drop the stale session so we don't
                // leave an orphan (its keys are dead now anyway).
                if let Some(&old) = self.connected.get(&peer_id) {
                    if old != from {
                        self.sessions.remove(&old);
                        self.established.remove(&old);
                        self.last_seen.remove(&old);
                    }
                }

                let info = PeerInfo {
                    id: peer_id,
                    virtual_ip: derive_virtual_ip(&peer_id),
                    public_key: accepted.peer_identity,
                    endpoints: vec![from],
                    status: PeerStatus::Connected,
                    os: decode_os(&os_bytes),
                };
                self.overlay.lock().await.upsert_peer(info)?;
                self.sessions.insert(from, accepted.session);
                self.established.insert(from, Instant::now());
                self.connected.insert(peer_id, from);
                if let Some(serial) = serial {
                    self.peer_serial.insert(peer_id, serial);
                }
                transport
                    .send_to(
                        &wire::encode(MessageType::HandshakeResp, &accepted.response),
                        from,
                    )
                    .await?;
                tracing::info!(peer = %peer_id.fingerprint(), %from, "session established (responder)");
            }
            MessageType::HandshakeResp => {
                if let Some(handshake) = self.pending.remove(&from) {
                    let (session, peer_meta) = handshake.complete(payload)?;
                    let peer_id = self.peer_id_at(from).await;

                    // Membership gate: verify the responder's cert against the
                    // identity key we initiated to (peer_id == its public key).
                    let (peer_cert, os_bytes) = decode_payload(&peer_meta);
                    let expected = peer_id.map(|p| p.0).unwrap_or([0u8; 32]);
                    let serial = match self.verify_membership(&expected, &peer_cert) {
                        Ok(serial) => serial,
                        Err(e) => {
                            tracing::warn!(%from, error = %e, "rejected handshake response: membership");
                            return Ok(());
                        }
                    };

                    self.sessions.insert(from, session);
                    self.established.insert(from, Instant::now());
                    if let Some(peer_id) = peer_id {
                        self.connected.insert(peer_id, from);
                        if let Some(serial) = serial {
                            self.peer_serial.insert(peer_id, serial);
                        }
                        let mut overlay = self.overlay.lock().await;
                        overlay.set_status(&peer_id, PeerStatus::Connected);
                        if let Some(os) = decode_os(&os_bytes) {
                            overlay.set_os(&peer_id, os);
                        }
                    }
                    tracing::info!(%from, "session established (initiator)");
                }
            }
            MessageType::Transport => {
                let plaintext = match self.sessions.get_mut(&from) {
                    Some(session) => session.decrypt(payload)?,
                    None => return Ok(()), // no session for this source
                };
                // Observe everything that arrives over the tunnel, regardless of
                // whether we ultimately forward it locally.
                if let Some(peer_id) = self.peer_at_endpoint(from) {
                    self.monitor.record(peer_id, Direction::Rx, &plaintext);
                }
                // Internet-bound traffic from a peer is only forwarded to the OS
                // (to be NAT'd out) when we've volunteered as an exit node;
                // otherwise drop it so we never relay strangers' traffic.
                if let Some(dst) = ipv4_dst(&plaintext) {
                    if !is_overlay_ip(dst) && !self.allow_exit.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                }
                tun.write_packet(&plaintext).await?;
            }
            MessageType::Keepalive => { /* v0.7: liveness tracking */ }
            MessageType::Revocation => {
                // A peer gossiped its revocation list — merge any new, validly
                // signed entries, then drop connected peers they evict.
                if let (Some(network), Ok(incoming)) =
                    (self.network_id(), RevocationList::from_bytes(payload))
                {
                    let added = self.revocations.lock().unwrap().merge(&incoming, &network);
                    if added > 0 {
                        tracing::info!(added, "learned revocations from peer");
                        self.enforce_revocations().await;
                    }
                }
            }
        }
        Ok(())
    }

    /// Drop every connected peer whose cert serial has been revoked — closes the
    /// session, forgets the endpoint, and removes it from the overlay.
    async fn enforce_revocations(&mut self) {
        let revoked: Vec<(NodeId, SocketAddr)> = {
            let crl = self.revocations.lock().unwrap();
            self.peer_serial
                .iter()
                .filter(|(_, &serial)| crl.is_revoked(serial))
                .filter_map(|(id, _)| self.connected.get(id).map(|ep| (*id, *ep)))
                .collect()
        };
        if revoked.is_empty() {
            return;
        }
        let mut overlay = self.overlay.lock().await;
        for (id, ep) in revoked {
            self.sessions.remove(&ep);
            self.established.remove(&ep);
            self.connected.remove(&id);
            self.last_seen.remove(&ep);
            self.peer_serial.remove(&id);
            overlay.remove_peer(&id);
            tracing::info!(peer = %id.fingerprint(), "peer revoked, session dropped");
        }
    }

    /// Send a keepalive to every connected peer, then refresh reachability from
    /// how recently each was heard from. Peers unseen past a threshold are marked
    /// Lost; long-dead ones are dropped (clears stale "ghost" entries).
    async fn on_keepalive_tick<X: Transport>(&mut self, transport: &X) {
        const STALE: Duration = Duration::from_secs(15);
        const DEAD: Duration = Duration::from_secs(60);
        let now = Instant::now();

        // Membership just changed (joined a network): drop every existing session
        // so it re-handshakes and is re-verified under the new network. Without
        // this, a session formed in open mode keeps running unauthenticated and
        // isn't bound to a cert serial, so a later revocation can't evict it. We
        // keep the overlay peers (their endpoints) so the re-init below reconnects.
        if self.resync.swap(false, Ordering::Relaxed) {
            self.sessions.clear();
            self.established.clear();
            self.pending.clear();
            self.connected.clear();
            self.peer_serial.clear();
            self.last_init.clear();
            self.last_responded.clear();
            let ids: Vec<NodeId> = self.overlay.lock().await.peers().map(|p| p.id).collect();
            let mut overlay = self.overlay.lock().await;
            for id in &ids {
                overlay.set_status(id, PeerStatus::Connecting);
            }
            tracing::info!("membership changed — re-handshaking all peers");
        }

        // Probe each live session (also refreshes the NAT binding both ways).
        let frame = wire::encode(MessageType::Keepalive, &[]);
        let endpoints: Vec<SocketAddr> = self.sessions.keys().copied().collect();
        for ep in &endpoints {
            let _ = transport.send_to(&frame, *ep).await;
        }

        // Gossip our revocation list so evictions propagate across the mesh, then
        // drop any peer it now revokes.
        let crl_bytes = {
            let crl = self.revocations.lock().unwrap();
            (!crl.is_empty()).then(|| crl.to_bytes())
        };
        if let Some(bytes) = crl_bytes {
            let frame = wire::encode(MessageType::Revocation, &bytes);
            for ep in &endpoints {
                let _ = transport.send_to(&frame, *ep).await;
            }
            self.enforce_revocations().await;
        }

        // Re-classify peers by how recently we heard from their endpoint.
        let mut dead: Vec<(NodeId, SocketAddr)> = Vec::new();
        {
            let mut overlay = self.overlay.lock().await;
            for (node_id, ep) in &self.connected {
                let age = self.last_seen.get(ep).map(|t| now.duration_since(*t));
                match age {
                    Some(a) if a < STALE => overlay.set_status(node_id, PeerStatus::Connected),
                    Some(a) if a >= DEAD => dead.push((*node_id, *ep)),
                    _ => overlay.set_status(node_id, PeerStatus::Lost),
                }
            }
            for (id, _) in &dead {
                overlay.remove_peer(id);
            }
        }
        for (id, ep) in dead {
            self.sessions.remove(&ep);
            self.established.remove(&ep);
            self.connected.remove(&id);
            self.last_seen.remove(&ep);
            self.peer_serial.remove(&id);
            // Clear the handshake timers so the re-init below can reconnect at once
            // (a dropped peer should reconnect promptly, not wait out REKEY_TIMEOUT).
            self.last_init.remove(&id);
            self.last_responded.remove(&id);
            tracing::info!(peer = %id.fingerprint(), "peer timed out, removed");
        }

        // WireGuard session lifetime. The suite decides when a session's keys are
        // stale enough to renew (`rekey_due`, its REKEY_AFTER_TIME); the engine
        // enforces a hard ceiling past which a session must not be used at all
        // (REJECT_AFTER_TIME). The initiator (id tie-break / pin) drives a
        // proactive re-handshake while the live session keeps carrying traffic —
        // the response replaces it in place, so there's no gap. A session that
        // sails past REJECT_AFTER_TIME (its rekey never completed, yet keepalives
        // kept it off the dead list above) is torn down to force a fresh one.
        let mut rekey: Vec<(NodeId, SocketAddr)> = Vec::new();
        let mut expired: Vec<(NodeId, SocketAddr)> = Vec::new();
        for (id, ep) in &self.connected {
            let Some(session) = self.sessions.get(ep) else {
                continue;
            };
            let age = self
                .established
                .get(ep)
                .map_or(Duration::ZERO, |t| now.duration_since(*t));
            if age >= REJECT_AFTER_TIME {
                expired.push((*id, *ep));
            } else if session.rekey_due(age) && self.should_initiate_to(id) {
                rekey.push((*id, *ep));
            }
        }
        if !expired.is_empty() {
            let mut overlay = self.overlay.lock().await;
            for (id, ep) in &expired {
                self.sessions.remove(ep);
                self.established.remove(ep);
                self.connected.remove(id);
                self.last_seen.remove(ep);
                self.peer_serial.remove(id);
                self.last_init.remove(id);
                self.last_responded.remove(id);
                // Keep the overlay peer (its endpoints) so the re-init below
                // reconnects; just mark it Connecting again.
                overlay.set_status(id, PeerStatus::Connecting);
                tracing::info!(peer = %id.fingerprint(), "session expired (REJECT_AFTER_TIME) — re-handshaking");
            }
        }
        // Proactively rekey toward the proven connected endpoint (not the full
        // candidate list — that path already works). The live session stays in
        // place until the response swaps it, so traffic never stops.
        for (id, ep) in rekey {
            if self.initiate_handshake(id, &[ep], transport).await.is_ok() {
                tracing::debug!(peer = %id.fingerprint(), "proactive rekey initiated");
            }
        }

        // Re-initiate handshakes to known peers we have no live session with, so
        // reconnection is prompt (~one tick) instead of waiting for a slow
        // discovery re-emit — covers reconnect after a membership resync, a
        // dropped session, or a peer that came up after us. `on_peer_discovered`
        // applies the skip-if-connected guard and the id tie-break, so this is a
        // no-op for healthy sessions and for the responder side of each pair.
        let stale_peers: Vec<DiscoveredPeer> = {
            let overlay = self.overlay.lock().await;
            overlay
                .peers()
                .filter(|p| !self.connected.contains_key(&p.id) && !p.endpoints.is_empty())
                .map(|p| DiscoveredPeer {
                    id: p.id,
                    endpoints: p.endpoints.clone(),
                })
                .collect()
        };
        for peer in stale_peers {
            let _ = self.on_peer_discovered(peer, transport).await;
        }
    }

    /// The network we belong to, if any (open mode otherwise).
    fn network_id(&self) -> Option<NetworkId> {
        *self.network.lock().unwrap()
    }

    /// Our handshake payload: membership cert (if any) + OS.
    fn local_payload(&self) -> Vec<u8> {
        let cert = self.cert.lock().unwrap();
        encode_payload(cert.as_ref(), std::env::consts::OS.as_bytes())
    }

    /// Decide whether a peer presenting `cert` may join. In open mode (no
    /// network) everyone is admitted (`Ok(None)`). In a network the cert must be
    /// present, valid for our network, bound to `peer_identity`, and unrevoked;
    /// on success returns its serial so the session can be matched to future
    /// revocations.
    fn verify_membership(
        &self,
        peer_identity: &[u8],
        cert: &Option<MemberCert>,
    ) -> Result<Option<u64>, lattice_membership::MembershipError> {
        use lattice_membership::MembershipError;
        let Some(network) = self.network_id() else {
            return Ok(None); // open mode
        };
        let cert = cert.as_ref().ok_or(MembershipError::WrongNetwork)?;
        cert.verify(&network, peer_identity, now_unix())?;
        if self.revocations.lock().unwrap().is_revoked(cert.serial()) {
            return Err(MembershipError::Revoked);
        }
        Ok(Some(cert.serial()))
    }

    /// Which connected peer owns this transport `endpoint` — the reverse of the
    /// `connected` map, for attributing inbound packets to a peer.
    fn peer_at_endpoint(&self, endpoint: SocketAddr) -> Option<NodeId> {
        self.connected
            .iter()
            .find(|(_, &ep)| ep == endpoint)
            .map(|(id, _)| *id)
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
    public_addr: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    exit_node: Arc<std::sync::Mutex<Option<NodeId>>>,
    allow_exit: Arc<AtomicBool>,
    monitor: Arc<TrafficMonitor>,
    network: Arc<std::sync::Mutex<Option<NetworkId>>>,
    cert: Arc<std::sync::Mutex<Option<MemberCert>>>,
    revocations: Arc<std::sync::Mutex<RevocationList>>,
    resync: Arc<AtomicBool>,
    force_initiate: Arc<std::sync::Mutex<HashSet<NodeId>>>,
}

impl EngineHandle {
    pub async fn status(&self) -> NodeStatus {
        let up = self.running.load(Ordering::Relaxed) && self.enabled.load(Ordering::Relaxed);
        // Read the std-Mutexes into locals so no guard is held across the await.
        let public_addr = *self.public_addr.lock().unwrap();
        let exit_node = *self.exit_node.lock().unwrap();
        let is_exit = self.allow_exit.load(Ordering::Relaxed);
        let peer_count = self.overlay.lock().await.peer_count();
        NodeStatus {
            id: self.node_id,
            virtual_ip: Some(self.virtual_ip),
            public_addr,
            running: up,
            peer_count,
            exit_node,
            is_exit,
            relay: None, // patched in by the daemon (lives in the transport)
        }
    }

    /// Record our public (reflexive) address, learned via STUN.
    pub fn set_public_addr(&self, addr: SocketAddr) {
        *self.public_addr.lock().unwrap() = Some(addr);
    }

    /// Mark a peer as explicitly pinned (we hold a reachable address for it).
    /// The engine then initiates to it regardless of the id tie-break, so the
    /// pinning side drives the handshake even when reachability is one-sided.
    pub fn pin_peer(&self, id: NodeId) {
        self.force_initiate.lock().unwrap().insert(id);
    }

    /// Route this node's internet traffic through `node_id` (or `None` for direct).
    pub fn set_exit_node(&self, node_id: Option<NodeId>) {
        *self.exit_node.lock().unwrap() = node_id;
    }

    /// Volunteer (or stop volunteering) as an exit node for other peers.
    pub fn set_allow_exit(&self, allow: bool) {
        self.allow_exit.store(allow, Ordering::Relaxed);
    }

    pub async fn peers(&self) -> Vec<PeerInfo> {
        self.overlay.lock().await.peers().cloned().collect()
    }

    /// Live traffic flows observed crossing the tunnel, most-recent first.
    pub fn flows(&self) -> Vec<FlowRecord> {
        self.monitor.snapshot()
    }

    /// Arm the per-packet capture (admin packet inspector) with `filter`,
    /// clearing any previous buffer. Captured packets are decrypted plaintext —
    /// the daemon gates this behind `--admin-allow`.
    pub fn capture_start(
        &self,
        filter: lattice_proto::ipc::CaptureFilter,
    ) -> lattice_proto::ipc::CaptureState {
        self.monitor.capture_start(filter)
    }

    /// Stop the per-packet capture and clear its buffer.
    pub fn capture_stop(&self) -> lattice_proto::ipc::CaptureState {
        self.monitor.capture_stop()
    }

    /// Current capture state (without draining packets).
    pub fn capture_status(&self) -> lattice_proto::ipc::CaptureState {
        self.monitor.capture_status()
    }

    /// Drain captured packets with `seq > after`, oldest first (cursor poll).
    pub fn packets_since(&self, after: u64) -> Vec<lattice_proto::ipc::PacketRecord> {
        self.monitor.packets_since(after)
    }

    /// The network this node belongs to, if any.
    pub fn network_id(&self) -> Option<NetworkId> {
        *self.network.lock().unwrap()
    }

    /// Join a network at runtime by adopting a cert issued for us (the cert's
    /// own `network_id` becomes the network we verify peers against). Signals the
    /// engine to drop existing sessions so they re-handshake under the network —
    /// otherwise pre-join open-mode sessions would persist unauthenticated and
    /// couldn't be revoked.
    pub fn join_network(&self, cert: MemberCert) {
        *self.network.lock().unwrap() = Some(cert.network_id());
        *self.cert.lock().unwrap() = Some(cert);
        self.resync.store(true, Ordering::Relaxed);
    }

    /// Inject a revocation (the admin evicting a member). It's verified against
    /// our network before being accepted; once added, the engine loop gossips it
    /// and drops the evicted peer. Returns true if newly added.
    pub fn add_revocation(&self, rev: Revocation) -> bool {
        let Some(network) = self.network_id() else {
            return false;
        };
        self.revocations.lock().unwrap().add(rev, &network)
    }

    /// How many revocations this node currently knows about.
    pub fn revocation_count(&self) -> usize {
        self.revocations.lock().unwrap().len()
    }

    /// Bring the mesh up (`true`) or down (`false`). When down, the engine keeps
    /// running but stops forwarding overlay packets.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }
}

/// Current wall-clock time in unix seconds, for cert expiry checks.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build the authenticated handshake payload: an optional membership cert
/// followed by our OS string. Self-describing so open mode (no cert) and
/// membership mode share one format.
///
/// Layout: `[has_cert: 1][cert: 152 if has_cert][os: utf8 remainder]`.
fn encode_payload(cert: Option<&MemberCert>, os: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 152 + os.len());
    match cert {
        Some(c) => {
            out.push(1);
            out.extend_from_slice(&c.to_bytes());
        }
        None => out.push(0),
    }
    out.extend_from_slice(os);
    out
}

/// Inverse of [`encode_payload`]: split a handshake payload into the peer's cert
/// (if present and well-formed) and its OS bytes.
fn decode_payload(payload: &[u8]) -> (Option<MemberCert>, Vec<u8>) {
    match payload.split_first() {
        Some((1, rest)) if rest.len() >= 152 => {
            let cert = MemberCert::from_bytes(&rest[..152]).ok();
            (cert, rest[152..].to_vec())
        }
        Some((0, rest)) => (None, rest.to_vec()),
        // Unknown/legacy format: treat the whole thing as OS metadata, no cert.
        _ => (None, payload.to_vec()),
    }
}

/// Decode a peer's handshake metadata payload into an OS string, if present.
fn decode_os(payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(payload).to_string())
    }
}

/// Whether an address is in the overlay range `100.64.0.0/10` (mesh traffic);
/// anything else is internet-bound and only flows through an exit node.
fn is_overlay_ip(ip: VirtualIp) -> bool {
    let o = ip.0.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
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
        let id_a_nodeid = id_a.node_id();
        let id_b_nodeid = id_b.node_id();

        let addr_a: SocketAddr = "10.0.0.1:700".parse().unwrap();
        let addr_b: SocketAddr = "10.0.0.2:700".parse().unwrap();
        let (ta, tb) = duplex(addr_a, addr_b);

        let (tun_a, handle_a) = MemoryTun::new();
        let (tun_b, mut handle_b) = MemoryTun::new();

        // Both discover each other; the tie-break picks whichever id is smaller
        // to initiate, so this works regardless of the random id ordering.
        let disc_a = StaticDiscovery::new(vec![DiscoveredPeer {
            id: id_b_nodeid,
            endpoints: vec![addr_b],
        }]);
        let disc_b = StaticDiscovery::new(vec![DiscoveredPeer {
            id: id_a_nodeid,
            endpoints: vec![addr_a],
        }]);

        let mut engine_a = Engine::new(id_a, EngineConfig::default());
        let mut engine_b = Engine::new(id_b, EngineConfig::default());
        // Keep a handle to A so we can inspect the traffic monitor afterwards.
        let handle_a_mon = engine_a.handle();

        tokio::spawn(async move {
            let _ = engine_a.run(tun_a, ta, disc_a).await;
        });
        tokio::spawn(async move {
            let _ = engine_b.run(tun_b, tb, disc_b).await;
        });

        // Wait for the handshake to establish before injecting (the packet is
        // dropped if no session exists yet).
        wait_connected(&handle_a_mon, 1).await;

        // A minimal IPv4 packet from vip_a → vip_b (only version + dst matter here).
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // IPv4, IHL 5
        packet[12..16].copy_from_slice(&vip_a.0.octets());
        packet[16..20].copy_from_slice(&vip_b.0.octets());

        handle_a.inject.send(packet.clone()).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(8), handle_b.observe.recv())
            .await
            .expect("packet should arrive at B within timeout")
            .expect("B's TUN channel stayed open");

        assert_eq!(
            received, packet,
            "B must receive A's original packet decrypted"
        );

        // The traffic monitor must have observed A's outbound packet as a flow
        // from A's virtual IP to B's.
        let flows = handle_a_mon.flows();
        let flow = flows
            .iter()
            .find(|f| f.local.starts_with(&vip_a.to_string()))
            .expect("A's monitor should have recorded the tunneled packet");
        assert_eq!(flow.tx_packets, 1, "exactly one packet was sent");
        assert!(
            flow.remote.starts_with(&vip_b.to_string()),
            "flow's remote end is B's virtual IP, got {}",
            flow.remote
        );
    }

    /// A direct pin must initiate even when this node holds the LARGER id (which
    /// the tie-break normally silences). Models a one-sided reachable anchor: the
    /// pinning side is the only one that can reach the peer, so it must drive the
    /// handshake regardless of id ordering. The smaller-id side here has NO
    /// discovery, so without `pin_peer`'s tie-break bypass neither side would
    /// ever send an INIT and the connection would never form.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pinned_peer_initiates_despite_id_tie_break() {
        let id1 = Identity::generate().unwrap();
        let id2 = Identity::generate().unwrap();
        // big = larger node id (the side the tie-break would forbid from initiating).
        let (big, small) = if id1.node_id().0 > id2.node_id().0 {
            (id1, id2)
        } else {
            (id2, id1)
        };
        let small_nodeid = small.node_id();

        let big_addr: SocketAddr = "10.0.0.1:700".parse().unwrap();
        let small_addr: SocketAddr = "10.0.0.2:700".parse().unwrap();
        let (t_big, t_small) = duplex(big_addr, small_addr);
        let (tun_big, _hb) = MemoryTun::new();
        let (tun_small, _hs) = MemoryTun::new();

        // Only the larger-id side knows the peer (an explicit pin); the smaller-id
        // side has no discovery and can only respond, never initiate.
        let disc_big = StaticDiscovery::new(vec![DiscoveredPeer {
            id: small_nodeid,
            endpoints: vec![small_addr],
        }]);
        let disc_small = StaticDiscovery::new(vec![]);

        let mut engine_big = Engine::new(big, EngineConfig::default());
        let mut engine_small = Engine::new(small, EngineConfig::default());
        let big_handle = engine_big.handle();
        big_handle.pin_peer(small_nodeid); // the fix under test

        tokio::spawn(async move {
            let _ = engine_big.run(tun_big, t_big, disc_big).await;
        });
        tokio::spawn(async move {
            let _ = engine_small.run(tun_small, t_small, disc_small).await;
        });

        wait_connected(&big_handle, 1).await;
        let connected = big_handle
            .peers()
            .await
            .iter()
            .filter(|p| p.status == PeerStatus::Connected)
            .count();
        assert_eq!(
            connected, 1,
            "pinned larger-id node must initiate and connect despite the tie-break"
        );
    }

    /// A routes internet-bound traffic through B (its exit node): a packet to a
    /// public IP injected into A's TUN arrives at B's TUN to be forwarded out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exit_node_tunnels_internet_traffic_to_the_exit() {
        let id_a = Identity::generate().unwrap();
        let id_b = Identity::generate().unwrap();
        let vip_a = derive_virtual_ip(&id_a.node_id());
        let a_nodeid = id_a.node_id();
        let b_nodeid = id_b.node_id();

        let addr_a: SocketAddr = "10.0.0.1:701".parse().unwrap();
        let addr_b: SocketAddr = "10.0.0.2:701".parse().unwrap();
        let (ta, tb) = duplex(addr_a, addr_b);

        let (tun_a, handle_a) = MemoryTun::new();
        let (tun_b, mut handle_b) = MemoryTun::new();

        // Both discover each other so the id tie-break can pick the initiator.
        let disc_a = StaticDiscovery::new(vec![DiscoveredPeer {
            id: b_nodeid,
            endpoints: vec![addr_b],
        }]);
        let disc_b = StaticDiscovery::new(vec![DiscoveredPeer {
            id: a_nodeid,
            endpoints: vec![addr_a],
        }]);

        let mut engine_a = Engine::new(id_a, EngineConfig::default());
        let mut engine_b = Engine::new(id_b, EngineConfig::default());

        // A sends its internet traffic through B; B agrees to be an exit node.
        let a_mon = engine_a.handle();
        a_mon.set_exit_node(Some(b_nodeid));
        engine_b.handle().set_allow_exit(true);

        tokio::spawn(async move {
            let _ = engine_a.run(tun_a, ta, disc_a).await;
        });
        tokio::spawn(async move {
            let _ = engine_b.run(tun_b, tb, disc_b).await;
        });

        wait_connected(&a_mon, 1).await;

        // A packet bound for the public internet (8.8.8.8) — not the overlay.
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&vip_a.0.octets());
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]);

        handle_a.inject.send(packet.clone()).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(8), handle_b.observe.recv())
            .await
            .expect("internet-bound packet should reach the exit node")
            .expect("B's TUN channel stayed open");
        assert_eq!(
            received, packet,
            "exit node receives A's internet packet to forward"
        );
    }

    /// Poll until `h` reports at least `want` Connected peers (robust to CI load
    /// where the handshake can take longer than a fixed sleep).
    async fn wait_connected(h: &EngineHandle, want: usize) {
        for _ in 0..200 {
            let n = h
                .peers()
                .await
                .iter()
                .filter(|p| p.status == PeerStatus::Connected)
                .count();
            if n >= want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Build a minimal IPv4 packet from `src` → `dst` (version + addrs only).
    fn ipv4(src: VirtualIp, dst: VirtualIp) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src.0.octets());
        p[16..20].copy_from_slice(&dst.0.octets());
        p
    }

    /// Two nodes carrying valid certs for the same network form a tunnel, and
    /// once connected, revoking one tears its session down (eviction).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_network_connects_then_revocation_evicts() {
        use lattice_membership::NetworkKey;

        let net = NetworkKey::generate();
        let net_id = net.network_id();

        let id_a = Identity::generate().unwrap();
        let id_b = Identity::generate().unwrap();
        let (a_id, b_id) = (id_a.node_id(), id_b.node_id());
        let vip_a = derive_virtual_ip(&a_id);
        let vip_b = derive_virtual_ip(&b_id);

        // The CA admits both nodes (serials 1 and 2, no expiry).
        let cert_a = net.issue_cert(&a_id.0, 1, 0, 0);
        let cert_b = net.issue_cert(&b_id.0, 2, 0, 0);

        let addr_a: SocketAddr = "10.0.0.1:702".parse().unwrap();
        let addr_b: SocketAddr = "10.0.0.2:702".parse().unwrap();
        let (ta, tb) = duplex(addr_a, addr_b);
        let (tun_a, handle_a) = MemoryTun::new();
        let (tun_b, mut handle_b) = MemoryTun::new();

        let disc_a = StaticDiscovery::new(vec![DiscoveredPeer {
            id: b_id,
            endpoints: vec![addr_b],
        }]);
        let disc_b = StaticDiscovery::new(vec![DiscoveredPeer {
            id: a_id,
            endpoints: vec![addr_a],
        }]);

        let mut engine_a = Engine::new(id_a, EngineConfig::default());
        let mut engine_b = Engine::new(id_b, EngineConfig::default());
        engine_a.set_membership(net_id, cert_a);
        engine_b.set_membership(net_id, cert_b);
        let a_ctl = engine_a.handle();

        tokio::spawn(async move {
            let _ = engine_a.run(tun_a, ta, disc_a).await;
        });
        tokio::spawn(async move {
            let _ = engine_b.run(tun_b, tb, disc_b).await;
        });

        wait_connected(&a_ctl, 1).await;

        // Same network → the cert check passes both ways and a packet tunnels.
        handle_a.inject.send(ipv4(vip_a, vip_b)).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(8), handle_b.observe.recv())
            .await
            .expect("packet should arrive once membership is verified")
            .expect("B's TUN open");
        assert_eq!(got, ipv4(vip_a, vip_b));
        assert_eq!(a_ctl.peers().await.len(), 1, "B is a connected peer of A");

        // The admin evicts B (revokes serial 2). A learns it and drops B.
        assert!(a_ctl.add_revocation(net.revoke(2, 0)));
        let mut evicted = false;
        for _ in 0..14 {
            tokio::time::sleep(Duration::from_millis(600)).await;
            if a_ctl.peers().await.is_empty() {
                evicted = true;
                break;
            }
        }
        assert!(evicted, "revoked peer B must be dropped from A within ~8s");
    }

    /// Regression guard for the membership soundness gap: two nodes connect in
    /// OPEN mode (no serial bound), then both join the same network at runtime.
    /// The join must drop and re-handshake the open session so it becomes
    /// membership-bound — otherwise a later revocation couldn't evict it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn open_session_becomes_revocable_after_join() {
        use lattice_membership::NetworkKey;

        let net = NetworkKey::generate();
        let id_a = Identity::generate().unwrap();
        let id_b = Identity::generate().unwrap();
        let (a_id, b_id) = (id_a.node_id(), id_b.node_id());
        let cert_a = net.issue_cert(&a_id.0, 1, 0, 0);
        let cert_b = net.issue_cert(&b_id.0, 2, 0, 0);

        let addr_a: SocketAddr = "10.0.0.1:703".parse().unwrap();
        let addr_b: SocketAddr = "10.0.0.2:703".parse().unwrap();
        let (ta, tb) = duplex(addr_a, addr_b);
        let (tun_a, _ha) = MemoryTun::new();
        let (tun_b, _hb) = MemoryTun::new();
        let disc_a = StaticDiscovery::new(vec![DiscoveredPeer {
            id: b_id,
            endpoints: vec![addr_b],
        }]);
        let disc_b = StaticDiscovery::new(vec![DiscoveredPeer {
            id: a_id,
            endpoints: vec![addr_a],
        }]);

        // Both start in OPEN mode (no membership set).
        let mut engine_a = Engine::new(id_a, EngineConfig::default());
        let mut engine_b = Engine::new(id_b, EngineConfig::default());
        let a_ctl = engine_a.handle();
        let b_ctl = engine_b.handle();

        tokio::spawn(async move {
            let _ = engine_a.run(tun_a, ta, disc_a).await;
        });
        tokio::spawn(async move {
            let _ = engine_b.run(tun_b, tb, disc_b).await;
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(a_ctl.peers().await.len(), 1, "open-mode session forms");

        // Both join the network at runtime — the open session must be dropped and
        // re-handshaked under membership (so it becomes cert-serial-bound).
        a_ctl.join_network(cert_a);
        b_ctl.join_network(cert_b);

        // Wait for the membership-bound session to re-form.
        let mut rebound = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(600)).await;
            let peers = a_ctl.peers().await;
            if peers.iter().any(|p| p.status == PeerStatus::Connected) {
                rebound = true;
                break;
            }
        }
        assert!(
            rebound,
            "open session must re-handshake as a member after join"
        );

        // Now eviction must work on the re-bound session.
        a_ctl.add_revocation(net.revoke(2, 0));
        let mut evicted = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(600)).await;
            if !a_ctl
                .peers()
                .await
                .iter()
                .any(|p| p.status == PeerStatus::Connected)
            {
                evicted = true;
                break;
            }
        }
        assert!(evicted, "revoking the re-bound member must evict it");
    }

    use std::sync::atomic::AtomicUsize;
    use lattice_crypto::{Accepted, CryptoError};

    /// A crypto suite that wraps the real Noise suite but whose sessions report
    /// `rekey_due` almost immediately, and which counts every handshake it starts.
    /// Lets us prove the engine *proactively re-handshakes* a live session
    /// (WireGuard's REKEY_AFTER_TIME) in ~1s instead of the production 120s.
    struct FastRekeySuite {
        inner: NoiseSuite,
        inits: Arc<AtomicUsize>,
    }

    impl CryptoSuite for FastRekeySuite {
        fn name(&self) -> &'static str {
            "fast-rekey"
        }
        fn initiate(
            &self,
            local_private: &[u8],
            remote_public: &[u8],
            payload: &[u8],
        ) -> Result<(Box<dyn HandshakeState>, Vec<u8>), CryptoError> {
            self.inits.fetch_add(1, Ordering::Relaxed);
            let (hs, init) = self.inner.initiate(local_private, remote_public, payload)?;
            Ok((Box::new(FastRekeyHandshake(hs)), init))
        }
        fn respond(
            &self,
            local_private: &[u8],
            init: &[u8],
            payload: &[u8],
        ) -> Result<Accepted, CryptoError> {
            let acc = self.inner.respond(local_private, init, payload)?;
            Ok(Accepted {
                session: Box::new(FastRekeySession(acc.session)),
                response: acc.response,
                peer_identity: acc.peer_identity,
                peer_payload: acc.peer_payload,
            })
        }
    }

    struct FastRekeyHandshake(Box<dyn HandshakeState>);
    impl HandshakeState for FastRekeyHandshake {
        fn complete(
            self: Box<Self>,
            response: &[u8],
        ) -> Result<(Box<dyn TunnelSession>, Vec<u8>), CryptoError> {
            let (session, payload) = self.0.complete(response)?;
            Ok((Box::new(FastRekeySession(session)), payload))
        }
    }

    /// Delegates the real crypto but claims to be rekey-due after half a second.
    struct FastRekeySession(Box<dyn TunnelSession>);
    impl TunnelSession for FastRekeySession {
        fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            self.0.encrypt(plaintext)
        }
        fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            self.0.decrypt(ciphertext)
        }
        fn rekey_due(&self, age: Duration) -> bool {
            age >= Duration::from_millis(500)
        }
    }

    /// A live session whose suite reports it rekey-due must be proactively
    /// re-handshaked by the initiator (WireGuard's REKEY_AFTER_TIME) without the
    /// peer ever leaving Connected. We prove it by counting handshake initiations:
    /// after the first connect the count keeps climbing as the engine renews the
    /// session, and the peer stays Connected throughout (seamless rekey).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_session_is_proactively_rekeyed() {
        // Make A the smaller-id node so it's the tie-break initiator (and thus the
        // side that drives the rekey, where we count initiations).
        let id1 = Identity::generate().unwrap();
        let id2 = Identity::generate().unwrap();
        let (id_a, id_b) = if id1.node_id().0 < id2.node_id().0 {
            (id1, id2)
        } else {
            (id2, id1)
        };
        let a_nodeid = id_a.node_id();
        let b_nodeid = id_b.node_id();

        let addr_a: SocketAddr = "10.0.0.1:704".parse().unwrap();
        let addr_b: SocketAddr = "10.0.0.2:704".parse().unwrap();
        let (ta, tb) = duplex(addr_a, addr_b);
        let (tun_a, _ha) = MemoryTun::new();
        let (tun_b, _hb) = MemoryTun::new();
        let disc_a = StaticDiscovery::new(vec![DiscoveredPeer {
            id: b_nodeid,
            endpoints: vec![addr_b],
        }]);
        let disc_b = StaticDiscovery::new(vec![DiscoveredPeer {
            id: a_nodeid,
            endpoints: vec![addr_a],
        }]);

        let inits = Arc::new(AtomicUsize::new(0));
        let suite_a = Arc::new(FastRekeySuite {
            inner: NoiseSuite,
            inits: Arc::clone(&inits),
        });
        let suite_b = Arc::new(FastRekeySuite {
            inner: NoiseSuite,
            inits: Arc::new(AtomicUsize::new(0)),
        });
        let mut engine_a = Engine::with_suite(id_a, EngineConfig::default(), suite_a);
        let mut engine_b = Engine::with_suite(id_b, EngineConfig::default(), suite_b);
        let a_ctl = engine_a.handle();

        tokio::spawn(async move {
            let _ = engine_a.run(tun_a, ta, disc_a).await;
        });
        tokio::spawn(async move {
            let _ = engine_b.run(tun_b, tb, disc_b).await;
        });

        wait_connected(&a_ctl, 1).await;
        let after_connect = inits.load(Ordering::Relaxed);

        // The rekey fires off the 5s keepalive tick. Within a couple of ticks the
        // initiator must start at least one more handshake than the initial connect.
        let mut rekeyed = false;
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if inits.load(Ordering::Relaxed) > after_connect {
                rekeyed = true;
                break;
            }
        }
        assert!(
            rekeyed,
            "initiator must proactively re-handshake a rekey-due session"
        );
        assert!(
            a_ctl
                .peers()
                .await
                .iter()
                .any(|p| p.status == PeerStatus::Connected),
            "rekey must be seamless — the peer stays Connected"
        );
    }
}

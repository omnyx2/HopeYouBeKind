//! Shared types for Lattice: node identity, addressing, the on-wire tunnel
//! message format, and the daemon⇄client IPC contract.
//!
//! This crate has *no* networking or crypto logic — it is pure data so that
//! every other crate (and the GUI) can agree on the same vocabulary.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

pub mod ipc;
pub mod wire;

/// A stable, content-addressed identifier for a node.
///
/// Derived as a hash of the node's static public key (computed in
/// `lattice-crypto`). Used in discovery, the peer registry, and to derive the
/// node's virtual IP — so identity, not network position, names a node.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Short hex fingerprint for human verification in the GUI/CLI.
    pub fn fingerprint(&self) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(8);
        for b in &self.0[..4] {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Full 64-character hex id — what a peer passes to `--peer` to reach you.
    pub fn to_hex(&self) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({})", self.fingerprint())
    }
}

/// An address on the overlay network (inside the CGNAT range `100.64.0.0/10`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct VirtualIp(pub Ipv4Addr);

impl std::fmt::Display for VirtualIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Everything we know about one peer in the mesh.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: NodeId,
    pub virtual_ip: VirtualIp,
    /// Static public key (Curve25519), used to authenticate the handshake.
    pub public_key: Vec<u8>,
    /// Best-known physical endpoints to reach this peer, most-preferred first.
    pub endpoints: Vec<SocketAddr>,
    pub status: PeerStatus,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PeerStatus {
    /// Discovered but no live tunnel yet.
    Known,
    /// Handshake in progress.
    Connecting,
    /// Live, authenticated session.
    Connected,
    /// Was connected, now unreachable.
    Lost,
}

/// The overlay subnet every node's virtual IP is drawn from.
pub const OVERLAY_SUBNET: (Ipv4Addr, u8) = (Ipv4Addr::new(100, 64, 0, 0), 10);

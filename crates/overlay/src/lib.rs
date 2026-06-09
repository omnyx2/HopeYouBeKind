//! The SDN control plane: who is in the mesh, what virtual IP each node holds,
//! and which peer a given destination IP should be tunneled to.
//!
//! This is pure, side-effect-free logic (no I/O), which makes the routing and
//! addressing rules straightforward to unit-test.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use lattice_proto::{NodeId, PeerInfo, VirtualIp};

/// Derive a node's virtual IP deterministically from its identity, inside the
/// overlay range `100.64.0.0/10`. Identity-derived addressing means a node
/// cannot trivially claim another node's address (see SECURITY.md).
///
/// The low 22 bits (the host portion of a /10) are taken from the NodeId.
pub fn derive_virtual_ip(id: &NodeId) -> VirtualIp {
    // Base network: 100.64.0.0
    const BASE: u32 = 0x6440_0000;
    const HOST_MASK: u32 = 0x003F_FFFF; // low 22 bits

    let b = &id.0;
    let host = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & HOST_MASK;
    // Avoid the all-zero host (network address); nudge to .1 if needed.
    let host = if host == 0 { 1 } else { host };
    VirtualIp(Ipv4Addr::from(BASE | host))
}

#[derive(thiserror::Error, Debug)]
pub enum OverlayError {
    #[error("virtual IP {0} already assigned to a different node")]
    AddressCollision(VirtualIp),
    #[error("no route to {0}")]
    NoRoute(VirtualIp),
}

/// The authoritative view of the mesh from this node's perspective: the peer
/// registry plus the routing table (virtual IP → which peer to tunnel to).
#[derive(Default)]
pub struct Overlay {
    peers: HashMap<NodeId, PeerInfo>,
    routes: HashMap<VirtualIp, NodeId>,
}

impl Overlay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a peer. Rejects a virtual IP already owned by another node.
    pub fn upsert_peer(&mut self, peer: PeerInfo) -> Result<(), OverlayError> {
        if let Some(existing) = self.routes.get(&peer.virtual_ip) {
            if *existing != peer.id {
                return Err(OverlayError::AddressCollision(peer.virtual_ip));
            }
        }
        self.routes.insert(peer.virtual_ip, peer.id);
        self.peers.insert(peer.id, peer);
        Ok(())
    }

    pub fn remove_peer(&mut self, id: &NodeId) {
        if let Some(p) = self.peers.remove(id) {
            self.routes.remove(&p.virtual_ip);
        }
    }

    /// Update a known peer's connection status (no-op if unknown).
    pub fn set_status(&mut self, id: &NodeId, status: lattice_proto::PeerStatus) {
        if let Some(p) = self.peers.get_mut(id) {
            p.status = status;
        }
    }

    /// Which peer should a packet destined for `dst` be tunneled to?
    pub fn route(&self, dst: &VirtualIp) -> Result<&PeerInfo, OverlayError> {
        let id = self.routes.get(dst).ok_or(OverlayError::NoRoute(*dst))?;
        self.peers.get(id).ok_or(OverlayError::NoRoute(*dst))
    }

    pub fn peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_proto::PeerStatus;

    fn node(seed: u8) -> NodeId {
        NodeId([seed; 32])
    }

    fn peer(id: NodeId) -> PeerInfo {
        PeerInfo {
            id,
            virtual_ip: derive_virtual_ip(&id),
            public_key: id.0.to_vec(),
            endpoints: vec![],
            status: PeerStatus::Known,
        }
    }

    #[test]
    fn virtual_ip_is_in_overlay_range_and_deterministic() {
        let id = node(7);
        let ip = derive_virtual_ip(&id);
        // 100.64.0.0/10 → first octet 100, second octet 64..=127
        let octets = ip.0.octets();
        assert_eq!(octets[0], 100);
        assert!((64..=127).contains(&octets[1]));
        assert_eq!(ip, derive_virtual_ip(&id), "must be deterministic");
    }

    #[test]
    fn routing_resolves_to_the_owning_peer() {
        let mut o = Overlay::new();
        let p = peer(node(3));
        let ip = p.virtual_ip;
        o.upsert_peer(p).unwrap();
        assert_eq!(o.route(&ip).unwrap().id, node(3));
    }

    #[test]
    fn rejects_address_collision_from_a_different_node() {
        let mut o = Overlay::new();
        let mut a = peer(node(1));
        let b = peer(node(2));
        a.virtual_ip = b.virtual_ip; // force collision
        o.upsert_peer(b).unwrap();
        assert!(matches!(
            o.upsert_peer(a),
            Err(OverlayError::AddressCollision(_))
        ));
    }
}

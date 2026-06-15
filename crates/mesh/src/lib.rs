//! **lattice-mesh** — the v2 multi-mesh container (`docs/MESH_V2.md` §1, §8).
//!
//! A computer is one node belonging to many isolated meshes. This crate holds the
//! structural skeleton of that model — decoupled from the v1 engine, which it will
//! eventually replace:
//!
//! - [`charter`] — a mesh's immutable, master-signed genesis governance;
//! - [`roster`] — its 1-byte-addressed membership;
//! - [`Mesh`] — one mesh's runtime state (charter + roster + crypto epoch + this
//!   node's exit pick);
//! - [`MeshContainer`] — every mesh this computer joins, keyed by its local handle;
//! - [`policy`] — the per-computer routing table that demuxes one TUN across them.
//!
//! Crypto, membership/invite, capture-detection, and discovery are intentionally
//! *not* here yet — they depend on decisions still being finalized; this is the
//! load-bearing shell they plug into.

use std::collections::HashMap;

use lattice_proto::wire_v2::{MemberId, MeshId};

pub mod charter;
pub mod policy;
pub mod roster;

pub use charter::{CharterError, GenesisCharter, InviteTopology, RecipherTrigger};
pub use policy::{FlowKey, FlowMatch, PolicyTable, RouteDecision};
pub use roster::{Member, Roster, RosterError};

/// One mesh this node belongs to: its immutable charter, its roster, the current
/// crypto epoch, this node's own in-mesh id, and the member it exits through.
#[derive(Clone, Debug)]
pub struct Mesh {
    /// This computer's local 1-byte handle for the mesh (the `meshid` header field).
    pub id: MeshId,
    pub charter: GenesisCharter,
    pub roster: Roster,
    /// Monotonic crypto epoch — 0 at genesis, +1 per re-cipher (§5).
    pub epoch: u64,
    /// This node's own in-mesh id (its join-order address).
    pub me: MemberId,
    /// The member this node routes internet traffic through, or `None` for
    /// in-mesh-only (the §1 per-node exit pick).
    pub exit: Option<MemberId>,
}

impl Mesh {
    /// A freshly-joined mesh at epoch 0 with an empty exit selection.
    pub fn new(id: MeshId, charter: GenesisCharter, me: MemberId) -> Self {
        Self {
            id,
            charter,
            roster: Roster::new(),
            epoch: 0,
            me,
            exit: None,
        }
    }
}

/// Every mesh this computer participates in, keyed by its local 1-byte handle. One
/// TUN serves them all; the [`PolicyTable`] picks which one carries each flow.
#[derive(Default)]
pub struct MeshContainer {
    meshes: HashMap<MeshId, Mesh>,
}

impl MeshContainer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a mesh; returns the previous one at that handle, if any.
    pub fn add(&mut self, mesh: Mesh) -> Option<Mesh> {
        self.meshes.insert(mesh.id, mesh)
    }

    pub fn get(&self, id: MeshId) -> Option<&Mesh> {
        self.meshes.get(&id)
    }

    pub fn get_mut(&mut self, id: MeshId) -> Option<&mut Mesh> {
        self.meshes.get_mut(&id)
    }

    /// Remove a mesh (e.g. on the §5 "wipe only the affected mesh" response).
    pub fn remove(&mut self, id: MeshId) -> Option<Mesh> {
        self.meshes.remove(&id)
    }

    pub fn len(&self) -> usize {
        self.meshes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.meshes.is_empty()
    }

    pub fn ids(&self) -> impl Iterator<Item = MeshId> + '_ {
        self.meshes.keys().copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Mesh> {
        self.meshes.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn charter() -> GenesisCharter {
        GenesisCharter {
            master_pubkey: [9u8; 32],
            invite: InviteTopology::OpenChain,
            trigger: RecipherTrigger::Quorum { k: 2 },
            max_members: 254,
            initial_cipher: "noise-ik-chachapoly".into(),
            overlay_prefix: [100, 80],
        }
    }

    #[test]
    fn new_mesh_starts_at_epoch_zero_with_no_exit() {
        let m = Mesh::new(3, charter(), 1);
        assert_eq!(m.id, 3);
        assert_eq!(m.epoch, 0);
        assert_eq!(m.me, 1);
        assert_eq!(m.exit, None);
        assert!(m.roster.is_empty());
    }

    #[test]
    fn container_holds_meshes_by_handle() {
        let mut c = MeshContainer::new();
        assert!(c.is_empty());
        assert!(c.add(Mesh::new(1, charter(), 1)).is_none());
        assert!(c.add(Mesh::new(2, charter(), 1)).is_none());
        assert_eq!(c.len(), 2);
        assert_eq!(c.get(1).unwrap().id, 1);
        assert!(c.get(9).is_none());

        let mut ids: Vec<MeshId> = c.ids().collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2]);

        // wipe one mesh (the §5 compromise response) — the other survives.
        assert!(c.remove(1).is_some());
        assert_eq!(c.len(), 1);
        assert!(c.get(2).is_some());
    }

    #[test]
    fn add_returns_replaced_mesh() {
        let mut c = MeshContainer::new();
        c.add(Mesh::new(1, charter(), 1));
        let prev = c.add(Mesh::new(1, charter(), 5));
        assert_eq!(prev.unwrap().me, 1);
        assert_eq!(c.get(1).unwrap().me, 5);
    }
}

//! **lattice-mesh** — the v2 multi-mesh container (`docs/MESH_V2.md` §1, §8).
//!
//! A computer is one node belonging to many isolated meshes. This crate holds the
//! domain layer of that model — decoupled from the v1 engine, which it replaced:
//!
//! - [`charter`] — a mesh's immutable, master-signed genesis governance;
//! - [`membership`] — the cert-chain roster, grants, and revocations;
//! - [`Mesh`] — one mesh's runtime identity (charter + crypto epoch + this
//!   node's exit pick);
//! - [`crypto`] / [`dataplane`] — the per-mesh cipher suites and TUN demux;
//! - [`discovery`] / [`registry`] / [`invitewrap`] / [`keydist`] / [`ipc`] — endpoint
//!   records, the service registry, invite sealing, key distribution, and the
//!   daemon↔client contract.
//!
//! (The early pre-membership skeleton — a standalone `roster`, `policy` table and
//! `MeshContainer` — was superseded by [`membership`] + meshd's own `MeshState`
//! and deleted; see git history if archaeology is needed.)

use lattice_proto::wire_v2::{MemberId, MeshId};

pub mod charter;
pub mod crypto;
pub mod dataplane;
pub mod discovery;
pub mod invitewrap;
pub mod ipc;
pub mod keydist;
pub mod membership;
pub mod registry;

pub use charter::{CharterError, GenesisCharter, InviteTopology, RecipherTrigger};

/// One mesh this node belongs to: its immutable charter, the current crypto epoch,
/// this node's own in-mesh id, and the member it exits through. (The live roster is
/// the cert chain — [`membership`] — held by the daemon's `MeshState`.)
#[derive(Clone, Debug)]
pub struct Mesh {
    /// This computer's local 1-byte handle for the mesh (the `meshid` header field).
    pub id: MeshId,
    /// A human label for the mesh (UX only; not part of the signed charter).
    pub name: String,
    pub charter: GenesisCharter,
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
    pub fn new(id: MeshId, name: String, charter: GenesisCharter, me: MemberId) -> Self {
        Self {
            id,
            name,
            charter,
            epoch: 0,
            me,
            exit: None,
        }
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
            self_destruct: crate::charter::SelfDestruct::Off,
            expel: crate::charter::ExpelPolicy::CreatorOnly,
            header_placement: crate::charter::HeaderPlacement::Random,
            exit_policy: crate::charter::ExitPolicy::Isolate,
            join_floor: crate::charter::JoinFloor::Any,
        }
    }

    #[test]
    fn new_mesh_starts_at_epoch_zero_with_no_exit() {
        let m = Mesh::new(3, "home".into(), charter(), 1);
        assert_eq!(m.id, 3);
        assert_eq!(m.epoch, 0);
        assert_eq!(m.me, 1);
        assert_eq!(m.exit, None);
    }
}

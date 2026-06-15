//! The v2 control-plane IPC contract between `meshd` and its clients (the GUI/CLI).
//!
//! Wire format is newline-delimited JSON: one [`Request`] per line in, one
//! [`Response`] per line back. These are *view* DTOs — flat, serializable
//! projections of the [`crate`] domain types, so the daemon and the GUI agree on a
//! stable shape without sharing runtime state.
//!
//! This is the v2 control plane only (create / inspect / select meshes). The data
//! plane (TUN demux, per-mesh crypto, discovery) is not wired yet.

use lattice_proto::wire_v2::{MemberId, MeshId};
use serde::{Deserialize, Serialize};

/// A client → daemon request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    /// Genesis: create a new mesh and become member #1. Returns the new mesh id.
    CreateMesh {
        /// Human label for the mesh (UX).
        name: String,
        /// The creator's own in-mesh name (the §2 "name as CIDR").
        my_name: String,
        /// `1..=254`.
        max_members: u8,
    },
    /// Every mesh this node belongs to.
    ListMeshes,
    /// Full detail for one mesh.
    MeshInfo { mesh: MeshId },
    /// Admit a member to a mesh — skeleton/demo populate; the real cert-based
    /// invite lands with the membership layer.
    AdmitMember {
        mesh: MeshId,
        name: String,
        /// 64 hex chars (the member's public key).
        pubkey_hex: String,
    },
    /// This node's exit pick within a mesh (`None` clears it).
    SetExit {
        mesh: MeshId,
        exit: Option<MemberId>,
    },
    /// Select the current mesh for egress (its exit must be set), or `None` for
    /// idle / untouched (the §1 default).
    SetCurrent { mesh: Option<MeshId> },
    /// Wipe one mesh locally — the §5 compromise response.
    RemoveMesh { mesh: MeshId },
    /// The current routing policy.
    GetPolicy,
}

/// A daemon → client reply.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    MeshCreated { mesh: MeshId },
    Meshes(Vec<MeshSummary>),
    Mesh(MeshDetail),
    Policy(PolicyView),
    Ok,
    Error { message: String },
}

/// One row in the global "all meshes on this computer" view (§7).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshSummary {
    pub id: MeshId,
    pub name: String,
    pub members: usize,
    pub epoch: u64,
    pub exit: Option<MemberId>,
    pub is_current: bool,
}

/// One member in a mesh's roster.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberView {
    pub id: MemberId,
    pub name: String,
    /// Short hex fingerprint of the member's public key.
    pub pubkey_fp: String,
    pub is_me: bool,
}

/// The per-mesh detail view (§7).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshDetail {
    pub id: MeshId,
    pub name: String,
    pub epoch: u64,
    pub me: MemberId,
    pub exit: Option<MemberId>,
    /// Charter (immutable governance), rendered for display.
    pub invite: String,
    pub trigger: String,
    pub max_members: u8,
    pub cipher: String,
    pub members: Vec<MemberView>,
}

/// The routing policy summary (§1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyView {
    /// "direct" (untouched) or "via mesh N exit M".
    pub default: String,
    pub current_mesh: Option<MeshId>,
}

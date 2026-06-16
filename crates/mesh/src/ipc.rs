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

use crate::charter::GenesisCharter;
use crate::keydist::SealedSecret;
use crate::membership::Cert;

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
        /// The data-plane cipher, fixed at creation (the GUI dropbox — P-C1). One of
        /// [`crate::crypto::available_ciphers`]; `None` → the default. Changing it later
        /// is a re-cipher (≥60% quorum, docs/PROTOCOL_DESIGN.md §5-4).
        #[serde(default)]
        cipher: Option<String>,
    },
    /// List the data-plane ciphers a mesh can be created with (populates the dropbox).
    Ciphers,
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
    /// Seed where to reach a member (bootstrap for the data plane — the run loop
    /// learns the rest from inbound frames). `endpoint` is `ip:port`.
    SetPeer {
        mesh: MeshId,
        member: MemberId,
        endpoint: String,
    },
    /// Select the current mesh for egress (its exit must be set), or `None` for
    /// idle / untouched (the §1 default).
    SetCurrent { mesh: Option<MeshId> },
    /// Wipe one mesh locally — the §5 compromise response.
    RemoveMesh { mesh: MeshId },
    /// The current routing policy.
    GetPolicy,

    // --- join flow (cert + sealed-secret exchange) ---
    /// (Joiner) Mint a fresh member + encryption keypair to be invited under.
    /// Returns both public keys; the private halves are held until `JoinMesh`.
    NewIdentity,
    /// (Creator) Admit a member by their public keys: issue a cert AND seal the
    /// mesh secret to their encryption key. Returns an [`InviteBlob`] to hand to
    /// the joiner out-of-band.
    CreateInvite {
        mesh: MeshId,
        name: String,
        /// 64 hex — the joiner's member (ed25519) public key from `NewIdentity`.
        member_pubkey_hex: String,
        /// 64 hex — the joiner's encryption (x25519) public key from `NewIdentity`.
        enc_pubkey_hex: String,
    },
    /// (Joiner) Install a mesh from an invite: open the sealed secret with the held
    /// private key, adopt the roster, and (if data-plane) bring up the loop.
    JoinMesh { invite: InviteBlob },
}

/// A daemon → client reply.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    MeshCreated {
        mesh: MeshId,
    },
    Meshes(Vec<MeshSummary>),
    Mesh(MeshDetail),
    Policy(PolicyView),
    /// A freshly minted identity's public keys (from `NewIdentity`).
    Identity {
        member_pubkey_hex: String,
        enc_pubkey_hex: String,
    },
    /// An invite to hand to the joiner (from `CreateInvite`).
    Invite(InviteBlob),
    /// Available data-plane cipher names (from `Ciphers`).
    Ciphers(Vec<String>),
    Ok,
    Error {
        message: String,
    },
}

/// A self-contained invite: everything a joiner needs to install the mesh and key
/// its data plane. Travels out-of-band (the GUI/CLI shuttles the JSON).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteBlob {
    pub mesh_id: MeshId,
    pub mesh_name: String,
    /// The immutable governance — carries the master public key (root of trust).
    pub charter: GenesisCharter,
    /// The id the creator assigned to the joiner.
    pub member_id: MemberId,
    /// The full roster (every cert), so the joiner sees everyone and can verify the
    /// chain to the master.
    pub certs: Vec<Cert>,
    /// The mesh secret, sealed to the joiner's encryption public key.
    pub sealed_secret: SealedSecret,
    /// Bootstrap endpoints (`member_id`, `ip:port`) the joiner seeds its data plane
    /// with — at minimum the inviter's own address, plus any peers the inviter
    /// already reaches. Lets the joiner send to them immediately, before gossip
    /// converges (docs/DISCOVERY.md §1, P-D1). `#[serde(default)]` so older invites
    /// (no field) still deserialize.
    #[serde(default)]
    pub endpoints: Vec<(MemberId, String)>,
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
    /// Where we currently reach this member (`ip:port`), if known. `None` until it
    /// is seeded or heard from (P6.3c/d).
    pub endpoint: Option<String>,
    /// Live connection state for the UI: `me` | `live` | `idle` | `unknown`.
    pub state: String,
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

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
        /// Liveness self-destruct (P-C4): `Some(true)` = ephemeral (self-destruct when
        /// isolated); `None`/`Some(false)` = off (default — laptop-friendly).
        #[serde(default)]
        self_destruct: Option<bool>,
        /// Invite policy (charter topology): `Some(true)` = MasterGated (only the
        /// creator may invite); `None`/`Some(false)` = OpenChain (any member may invite,
        /// the default).
        #[serde(default)]
        master_gated: Option<bool>,
    },
    /// List the data-plane ciphers a mesh can be created with (populates the dropbox).
    Ciphers,
    /// Re-cipher a mesh (P-C3): rotate to a fresh secret (and optionally a new
    /// `cipher`), advancing the epoch. Needs ≥60% of the roster online; members that
    /// are offline at the time are evicted (docs/PROTOCOL_DESIGN.md §11).
    Recipher {
        mesh: MeshId,
        #[serde(default)]
        cipher: Option<String>,
    },
    /// Back up every mesh on this computer to a JSON file (the update-migration
    /// snapshot). `path` defaults to `<tempdir>/lattice-mesh-backup.json`; meshd reads
    /// + deletes it on next startup, so a reinstall never loses mesh membership even if
    /// the persist dir is wiped. Call this right before launching an installer/update.
    ExportState {
        #[serde(default)]
        path: Option<String>,
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
    /// mesh secret to their encryption key. Returns a [`WrappedInvite`] (P-C6) to
    /// hand to the joiner out-of-band.
    CreateInvite {
        mesh: MeshId,
        name: String,
        /// 64 hex — the joiner's member (ed25519) public key from `NewIdentity`.
        member_pubkey_hex: String,
        /// 64 hex — the joiner's encryption (x25519) public key from `NewIdentity`.
        enc_pubkey_hex: String,
        /// When the joiner's identity code was minted (from `NewIdentity`); rejected
        /// if older than `invitewrap::IDENTITY_TTL_SECS` (P-C6 time-expire).
        #[serde(default)]
        issued_at: u64,
        /// The invite-wrap transform to use (P-C6); `None` ⇒ the default. The joiner
        /// must be told this out-of-band to open the invite.
        #[serde(default)]
        algo: Option<String>,
    },
    /// List the invite-wrap transform algorithms (P-C6) — the secret the joiner needs.
    InviteAlgorithms,
    /// Flag an attack on a mesh (P-C7 §7): broadcast an alert and arm the destroy
    /// grace. **One-veto, fail-deadly** — unless the creator all-clears within the
    /// grace, every member self-destructs.
    ReportAttack { mesh: MeshId },
    /// (Creator only) Call off an attack alert before the grace destroys the mesh.
    AllClear { mesh: MeshId },
    /// (Joiner) Install a mesh from a wrapped invite: unwrap it with `algo` (learned
    /// out-of-band), open the sealed secret, adopt the roster, bring up the loop.
    JoinMesh {
        invite: WrappedInvite,
        #[serde(default)]
        algo: Option<String>,
    },
}

/// A P-C6 wrapped invite: the serialized [`InviteBlob`] sealed under (algo, salt, n).
/// The `algo` is **not** here — the joiner supplies it out-of-band.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedInvite {
    pub salt: [u8; 32],
    pub n: u32,
    pub ct: Vec<u8>,
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
    /// A freshly minted identity's public keys + mint time (from `NewIdentity`).
    Identity {
        member_pubkey_hex: String,
        enc_pubkey_hex: String,
        /// Unix-ms the identity was minted — carried in the identity code so the
        /// inviter can enforce the TTL (P-C6).
        #[serde(default)]
        issued_at: u64,
    },
    /// A **wrapped** invite to hand to the joiner (from `CreateInvite`, P-C6).
    Invite(WrappedInvite),
    /// Available names (from `Ciphers` = data-plane ciphers / `InviteAlgorithms` =
    /// invite-wrap transforms).
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
    /// The current cipher epoch (P-C3) — bumped by each re-cipher. The joiner brings
    /// its data plane up at this epoch so it shares the live key. `#[serde(default)]`
    /// = 0 for older invites.
    #[serde(default)]
    pub epoch: u64,
    /// The mesh's **current** cipher name (P-C3) — may differ from the charter's
    /// `initial_cipher` after a re-cipher. Empty (`serde(default)`) ⇒ use the charter.
    #[serde(default)]
    pub cipher: String,
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
    /// `Some(secs)` while an attack alert has armed this mesh's destroy grace (P-C7) —
    /// drives the global alert banner; `None` = not armed.
    #[serde(default)]
    pub attack_armed_secs_left: Option<u64>,
    /// True if this node created the mesh (shows the banner's `All clear` button).
    #[serde(default)]
    pub is_creator: bool,
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
    /// Live members incl. self (within the liveness window) — for the health pill (G-4).
    #[serde(default)]
    pub live: usize,
    /// `⌈0.6·roster⌉` — the live-paired self-destruct / re-cipher floor (P-C4/§5-4).
    #[serde(default)]
    pub threshold: usize,
    /// `Some(secs)` if an attack alert has armed the destroy grace (P-C7) — seconds
    /// until self-destruct, for the countdown banner; `None` = not armed.
    #[serde(default)]
    pub attack_armed_secs_left: Option<u64>,
    /// True if this node is the mesh creator (holds the master key) — shows the
    /// `All clear` control only to the creator (G-3).
    #[serde(default)]
    pub is_creator: bool,
    /// True if this mesh is ephemeral (liveness self-destruct armed, P-C4) — off by
    /// default; shown in the overview so the choice is visible.
    #[serde(default)]
    pub self_destruct: bool,
}

/// The routing policy summary (§1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyView {
    /// "direct" (untouched) or "via mesh N exit M".
    pub default: String,
    pub current_mesh: Option<MeshId>,
}

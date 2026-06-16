//! The **genesis charter** — a mesh's immutable, master-signed governance (§3 of
//! `docs/MESH_V2.md`). Every field is welded to the mesh's root at creation; none
//! can change for the mesh's life, so a compromised member cannot downgrade policy
//! (e.g. flip a quorum-protected mesh to rate-limit, or `MasterGated` → `OpenChain`).
//!
//! This module is just the data + validation; signing/verification lands with the
//! membership layer.

use serde::{Deserialize, Serialize};

/// Who may issue member certs (invite). Fixed at genesis.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum InviteTopology {
    /// C-i: only the master (or delegated master holders) may invite.
    MasterGated,
    /// C-ii (default): any member may invite; certs chain back to the master.
    OpenChain,
}

/// Who may trigger a mesh-wide re-cipher, and under what guard (§5/§6). Fixed at
/// genesis.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum RecipherTrigger {
    /// Master (or delegated holders) only — the natural pairing for `MasterGated`.
    MasterOnly,
    /// Any member, but a re-cipher needs `k` co-signers. Recommended for
    /// `OpenChain`: `k = 2` lets the two neighbors that caught a compromise
    /// authorize the very rekey that expels it.
    Quorum { k: u8 },
    /// Any member, capped to one trigger per `period_secs` (cheaper but a bad
    /// member can still force periodic churn).
    RateLimit { period_secs: u32 },
}

/// Whether the mesh self-destructs when it loses live quorum (P-C4 §5-2). A per-mesh
/// choice fixed at genesis: a laptop that sleeps shouldn't nuke a small mesh, so the
/// liveness self-destruct is **off by default** and opt-in. (The attack-veto
/// self-destruct, P-C7, is independent and always applies.)
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum SelfDestruct {
    /// Never self-destruct on liveness — survives members going offline (default).
    #[default]
    Off,
    /// Ephemeral: self-destruct once live members sit below the quorum floor for the
    /// grace window (keys unrecoverable when too few are live — §5-2).
    OnIsolation,
}

/// The 1-byte id space caps any mesh at 254 members (`0`/`255` reserved).
pub const MAX_MEMBERS_CEILING: u8 = 254;

/// The immutable genesis parameters of a mesh.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct GenesisCharter {
    /// Root of trust — the master public key.
    pub master_pubkey: [u8; 32],
    pub invite: InviteTopology,
    pub trigger: RecipherTrigger,
    /// `1..=254`; never above the 1-byte ceiling.
    pub max_members: u8,
    /// Name of the initial cipher suite (epoch 0). The *active* cipher rotates via
    /// re-cipher; this policy does not.
    pub initial_cipher: String,
    /// The first two octets of the overlay prefix this mesh draws member IPs from;
    /// the §9 coexistence pre-flight picks a collision-free one.
    pub overlay_prefix: [u8; 2],
    /// Liveness self-destruct policy (P-C4) — off by default. `#[serde(default)]` so
    /// older charters (invites/persisted state) still deserialize.
    #[serde(default)]
    pub self_destruct: SelfDestruct,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum CharterError {
    #[error("max_members {0} out of range (must be 1..=254)")]
    MaxMembers(u8),
    #[error("quorum k must be >= 1")]
    QuorumZero,
}

impl GenesisCharter {
    /// Reject a charter whose `max_members` is outside `1..=254` or whose quorum
    /// `k` is zero.
    pub fn validate(&self) -> Result<(), CharterError> {
        if self.max_members == 0 || self.max_members > MAX_MEMBERS_CEILING {
            return Err(CharterError::MaxMembers(self.max_members));
        }
        if let RecipherTrigger::Quorum { k } = self.trigger {
            if k == 0 {
                return Err(CharterError::QuorumZero);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn charter(max: u8, trigger: RecipherTrigger) -> GenesisCharter {
        GenesisCharter {
            master_pubkey: [1u8; 32],
            invite: InviteTopology::OpenChain,
            trigger,
            max_members: max,
            initial_cipher: "noise-ik-chachapoly".into(),
            overlay_prefix: [100, 80],
            self_destruct: SelfDestruct::Off,
        }
    }

    #[test]
    fn valid_charter_passes() {
        assert!(charter(254, RecipherTrigger::Quorum { k: 2 })
            .validate()
            .is_ok());
        assert!(charter(8, RecipherTrigger::MasterOnly).validate().is_ok());
    }

    #[test]
    fn rejects_bad_max_members() {
        assert_eq!(
            charter(0, RecipherTrigger::MasterOnly).validate(),
            Err(CharterError::MaxMembers(0))
        );
        assert_eq!(
            charter(255, RecipherTrigger::MasterOnly).validate(),
            Err(CharterError::MaxMembers(255))
        );
    }

    #[test]
    fn rejects_zero_quorum() {
        assert_eq!(
            charter(10, RecipherTrigger::Quorum { k: 0 }).validate(),
            Err(CharterError::QuorumZero)
        );
    }
}

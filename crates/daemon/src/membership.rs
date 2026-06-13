//! Admin-side membership management: the network CA key plus a registry of the
//! members it has enrolled, so the same node always gets the same cert serial
//! (stable revocation target) and the GUI can list + evict members.
//!
//! Only a node started with `--network-key` is an admin; everyone else just
//! carries a cert. The registry is a JSON sidecar next to the key file.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lattice_membership::{
    MemberCert, MemberDirectory, NetworkId, NetworkKey, NetworkManifest, Revocation,
};
use lattice_proto::NodeId;
use serde::{Deserialize, Serialize};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One enrolled member, as persisted by the admin.
#[derive(Clone, Serialize, Deserialize)]
pub struct Member {
    pub node_id: String,
    pub serial: u64,
    pub label: Option<String>,
    pub revoked: bool,
    /// Designated by the admin to relay for peers that can't connect directly
    /// (published in the signed `NetworkManifest`). `#[serde(default)]` so
    /// registries written before auto-relay load cleanly.
    #[serde(default)]
    pub relay: bool,
}

/// The admin's persistent record of who has been enrolled.
#[derive(Serialize, Deserialize)]
pub struct Registry {
    /// Next serial to hand out (serials start at 1).
    next_serial: u64,
    members: Vec<Member>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            next_serial: 1,
            members: Vec::new(),
        }
    }
}

impl Registry {
    fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, path: &Path) {
        if let Ok(json) = serde_json::to_vec_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }

    /// The serial for `node_hex`, allocating + recording a new one if unseen.
    fn serial_for(&mut self, node_hex: &str, label: Option<String>) -> u64 {
        if let Some(m) = self.members.iter().find(|m| m.node_id == node_hex) {
            return m.serial;
        }
        let serial = self.next_serial;
        self.next_serial += 1;
        self.members.push(Member {
            node_id: node_hex.to_string(),
            serial,
            label,
            revoked: false,
            relay: false,
        });
        serial
    }

    /// Set (or clear) the relay designation for `node_hex`. Returns false if we
    /// never enrolled that node (you can only designate an admitted member).
    fn set_relay(&mut self, node_hex: &str, on: bool) -> bool {
        match self.members.iter_mut().find(|m| m.node_id == node_hex) {
            Some(m) => {
                m.relay = on;
                true
            }
            None => false,
        }
    }
}

/// The network certificate authority held by an admin node.
pub struct Admin {
    key: NetworkKey,
    registry: Registry,
    registry_path: PathBuf,
}

impl Admin {
    /// Load the CA key at `key_path` (generating + saving a new network on first
    /// run) along with its member registry sidecar.
    pub fn load_or_create(key_path: &str) -> Self {
        let path = PathBuf::from(key_path);
        let key = NetworkKey::load(&path).unwrap_or_else(|| {
            let k = NetworkKey::generate();
            let _ = k.save(&path);
            k
        });
        let registry_path = path.with_extension("members.json");
        let registry = Registry::load(&registry_path);
        Self {
            key,
            registry,
            registry_path,
        }
    }

    pub fn network_id(&self) -> NetworkId {
        self.key.network_id()
    }

    /// Issue (or re-issue, with the node's stable serial) a membership cert.
    pub fn issue(&mut self, node: &NodeId, label: Option<String>) -> MemberCert {
        let serial = self.registry.serial_for(&node.to_hex(), label);
        self.registry.save(&self.registry_path);
        self.key.issue_cert(&node.0, serial, now_unix(), 0)
    }

    /// Evict a member by node id: mark it revoked and produce a signed
    /// revocation. Returns `None` if we never enrolled that node.
    pub fn revoke(&mut self, node: &NodeId) -> Option<Revocation> {
        let hex = node.to_hex();
        let serial = {
            let m = self
                .registry
                .members
                .iter_mut()
                .find(|m| m.node_id == hex)?;
            m.revoked = true;
            m.serial
        };
        self.registry.save(&self.registry_path);
        Some(self.key.revoke(serial, now_unix()))
    }

    pub fn members(&self) -> &[Member] {
        &self.registry.members
    }

    /// Designate (or undesignate) a member as a relay, persisting the change.
    /// Returns false if the node was never enrolled. The new designation takes
    /// effect on the next `signed_manifest()` publish.
    pub fn set_relay(&mut self, node: &NodeId, on: bool) -> bool {
        let changed = self.registry.set_relay(&node.to_hex(), on);
        if changed {
            self.registry.save(&self.registry_path);
        }
        changed
    }

    /// Build the admin-signed network manifest — the SDN "program" published over
    /// the DHT (docs/SDN_DHT_ARCHITECTURE.md §7). v1 carries the designated relay
    /// node ids (non-revoked members with `relay == true`), in registry order.
    /// Only the admin (CA holder) can sign one, keeping routing policy admin-only.
    pub fn signed_manifest(&self) -> NetworkManifest {
        let relays: Vec<[u8; 32]> = self
            .registry
            .members
            .iter()
            .filter(|m| m.relay && !m.revoked)
            .filter_map(|m| parse_hex32(&m.node_id))
            .collect();
        let now = now_unix();
        // `now` doubles as a monotonic version: readers keep the highest they see.
        self.key.sign_manifest(now, now, relays)
    }

    /// Build the admin-signed member directory — the non-revoked node ids — for
    /// distribution over the DHT (docs/SDN_DHT_ARCHITECTURE.md). Only the admin
    /// (CA holder) can produce a valid one, keeping membership an admin-only act.
    pub fn signed_directory(&self) -> MemberDirectory {
        let node_ids: Vec<[u8; 32]> = self
            .registry
            .members
            .iter()
            .filter(|m| !m.revoked)
            .filter_map(|m| parse_hex32(&m.node_id))
            .collect();
        let now = now_unix();
        // `now` doubles as a monotonic version: readers keep the highest they see.
        self.key.sign_directory(now, now, node_ids)
    }
}

/// Parse a 64-char hex node id into 32 bytes.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `signed_manifest()` carries exactly the members the admin designated as
    /// relays (non-revoked), and it verifies against the admin's network.
    #[test]
    fn signed_manifest_lists_designated_relays() {
        // Unique temp key path (no tempfile dep); clean up the sidecars after.
        let base = std::env::temp_dir().join(format!("lat-relay-test-{}.key", std::process::id()));
        let key = base.to_string_lossy().to_string();
        let mut admin = Admin::load_or_create(&key);

        let a = NodeId([0xA1; 32]);
        let b = NodeId([0xB2; 32]);
        admin.issue(&a, Some("relay-node".into()));
        admin.issue(&b, None);

        // Nothing designated yet → empty relay list.
        assert!(admin.signed_manifest().relays().is_empty());

        // Designate A as a relay; the manifest must list A only and verify.
        assert!(admin.set_relay(&a, true));
        let manifest = admin.signed_manifest();
        let net = admin.network_id();
        assert!(manifest.verify(&net).is_ok(), "manifest signed by the CA");
        assert_eq!(manifest.relays(), &[[0xA1; 32]], "exactly the designated relay");

        // Undesignate → back to empty.
        assert!(admin.set_relay(&a, false));
        assert!(admin.signed_manifest().relays().is_empty());
        // Designating a non-member is a no-op.
        assert!(!admin.set_relay(&NodeId([0xCC; 32]), true));

        let _ = std::fs::remove_file(&base);
        let _ = std::fs::remove_file(base.with_extension("members.json"));
    }
}

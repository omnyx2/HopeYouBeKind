//! Admin-side membership management: the network CA key plus a registry of the
//! members it has enrolled, so the same node always gets the same cert serial
//! (stable revocation target) and the GUI can list + evict members.
//!
//! Only a node started with `--network-key` is an admin; everyone else just
//! carries a cert. The registry is a JSON sidecar next to the key file.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lattice_membership::{MemberCert, NetworkId, NetworkKey, Revocation};
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
        });
        serial
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
}

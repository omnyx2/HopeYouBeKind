//! Mesh membership: who is allowed in a Lattice network, provable without a
//! coordination server, and revocable.
//!
//! A **network** is an Ed25519 keypair. Its public half is the [`NetworkId`] —
//! the mesh's stable, mathematically-random identity that users remember and
//! share to refer to "the same network". Its private half ([`NetworkKey`]) is
//! the certificate authority: whoever holds it can admit nodes (issue a
//! [`MemberCert`]) and evict them (sign a [`Revocation`]).
//!
//! This layer is deliberately **orthogonal to the tunnel crypto**
//! (`lattice-crypto`'s `CryptoSuite`): a member proves it belongs by presenting
//! a cert binding its *node identity key* to the network, and the proof is
//! checked regardless of which cipher suite encrypts the session. Membership and
//! encryption can be researched and changed independently.
//!
//! Trust model: certs and revocations are each independently signed by the
//! network key, so they can be gossiped peer-to-peer and merged by union — no
//! central list, no ordering, no server. A node rejects any peer whose cert
//! doesn't verify, has expired, or whose serial has been revoked.
//!
//! Time is injected (`now`, unix seconds) rather than read from the clock, so
//! verification is deterministic and testable.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use lattice_proto::flow::FlowRule;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Deterministic byte encoding of the flow table, used inside both the manifest's
/// signed bytes and its wire form so the signature stays consistent. bincode v1
/// is fixed-layout and deterministic for a given value.
fn flows_blob(flows: &[FlowRule]) -> Vec<u8> {
    bincode::serialize(flows).unwrap_or_default()
}

/// Domain-separation tags so a cert signature can never be reinterpreted as a
/// revocation signature (or vice versa) even with identical field bytes.
const CERT_DOMAIN: &[u8] = b"lattice-member-cert-v1";
const REVOKE_DOMAIN: &[u8] = b"lattice-revocation-v1";
/// Domain for the admin-signed member directory (the SDN control-plane record
/// distributed over the DHT; see docs/SDN_DHT_ARCHITECTURE.md).
const DIRECTORY_DOMAIN: &[u8] = b"lattice-member-directory-v1";
/// Tag mixed into the directory's DHT key so it can't collide with an endpoint
/// rendezvous key (which is keyed by raw node id).
const DIRECTORY_KEY_TAG: &[u8] = b"lattice-directory-key-v1";
/// Domain for the admin-signed network manifest (the SDN "program": which nodes
/// relay, etc. — Phase 2, see docs/SDN_DHT_ARCHITECTURE.md).
const MANIFEST_DOMAIN: &[u8] = b"lattice-network-manifest-v1";
/// Tag for the manifest's DHT key (distinct from the directory + endpoint keys).
const MANIFEST_KEY_TAG: &[u8] = b"lattice-manifest-key-v1";

const CERT_WIRE_LEN: usize = 32 + 32 + 8 + 8 + 8 + 64; // 152
const REVOKE_WIRE_LEN: usize = 32 + 8 + 8 + 64; // 112

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum MembershipError {
    #[error("malformed bytes")]
    Malformed,
    #[error("signature is not valid for this network")]
    BadSignature,
    #[error("certificate is for a different network")]
    WrongNetwork,
    #[error("certificate is bound to a different node")]
    WrongNode,
    #[error("certificate expired")]
    Expired,
    #[error("membership has been revoked")]
    Revoked,
}

/// A mesh's public identity: the network's Ed25519 verifying key. Public and
/// safe to share — it is what you hand someone so they can join "the same
/// network", and what every node uses to verify certs and revocations.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkId(pub [u8; 32]);

impl NetworkId {
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != 64 {
            return None;
        }
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self(id))
    }

    pub fn to_hex(&self) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Short human fingerprint (8 hex chars) for display.
    pub fn fingerprint(&self) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(8);
        for b in &self.0[..4] {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// A short public tag derived from the id, used to scope serverless
    /// discovery (mDNS/DHT) so only nodes in the same network find each other.
    /// Hashed (not the raw id) purely to keep the advertised label short+opaque.
    pub fn rendezvous_tag(&self) -> String {
        use blake2::digest::{Update, VariableOutput};
        use blake2::Blake2bVar;
        let mut h = Blake2bVar::new(8).expect("8 is a valid blake2 output len");
        h.update(&self.0);
        let mut out = [0u8; 8];
        h.finalize_variable(&mut out).expect("8-byte output");
        use std::fmt::Write;
        let mut s = String::with_capacity(16);
        for b in &out {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// The DHT key the admin-signed member directory is stored under. Derived from
    /// the network id so every member computes the same key without coordination.
    pub fn directory_key(&self) -> [u8; 32] {
        use blake2::digest::{Update, VariableOutput};
        use blake2::Blake2bVar;
        let mut h = Blake2bVar::new(32).expect("32 is a valid blake2 output len");
        h.update(DIRECTORY_KEY_TAG);
        h.update(&self.0);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32-byte output");
        out
    }

    /// The DHT key a node's self-published **connectivity record** is stored
    /// under (the set of peers it currently has direct sessions with). Keyed by
    /// network + node id so any member can fetch any node's connectivity to
    /// compute relay bridges automatically. See the daemon's bridge election.
    pub fn connectivity_key(&self, node_id: &[u8; 32]) -> [u8; 32] {
        use blake2::digest::{Update, VariableOutput};
        use blake2::Blake2bVar;
        let mut h = Blake2bVar::new(32).expect("32 is a valid blake2 output len");
        h.update(b"lattice-connectivity-key-v1");
        h.update(&self.0);
        h.update(node_id);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32-byte output");
        out
    }

    /// The DHT key the admin-signed network manifest is stored under.
    pub fn manifest_key(&self) -> [u8; 32] {
        use blake2::digest::{Update, VariableOutput};
        use blake2::Blake2bVar;
        let mut h = Blake2bVar::new(32).expect("32 is a valid blake2 output len");
        h.update(MANIFEST_KEY_TAG);
        h.update(&self.0);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32-byte output");
        out
    }

    fn verifying_key(&self) -> Result<VerifyingKey, MembershipError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| MembershipError::BadSignature)
    }
}

impl std::fmt::Debug for NetworkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NetworkId({})", self.fingerprint())
    }
}

/// The network's private signing key — the certificate authority. Whoever holds
/// this controls membership (admit + evict). Zeroized on drop.
pub struct NetworkKey {
    signing: SigningKey,
}

impl NetworkKey {
    /// Mint a brand-new network (the one-time "create the mesh" act).
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        Self {
            signing: SigningKey::generate(&mut csprng),
        }
    }

    /// Reconstruct from a 32-byte secret seed.
    pub fn from_secret(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte secret seed (handle with care — this *is* control of the mesh).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// This network's public id.
    pub fn network_id(&self) -> NetworkId {
        NetworkId(self.signing.verifying_key().to_bytes())
    }

    /// Admit a node: sign a certificate binding `node_pubkey` (its tunnel
    /// identity key) into this network. `expires_at == 0` means no expiry.
    pub fn issue_cert(
        &self,
        node_pubkey: &[u8; 32],
        serial: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> MemberCert {
        let net = self.network_id().0;
        let msg = cert_signing_bytes(&net, node_pubkey, serial, issued_at, expires_at);
        let sig = self.signing.sign(&msg).to_bytes();
        MemberCert {
            network_id: NetworkId(net),
            node_pubkey: *node_pubkey,
            serial,
            issued_at,
            expires_at,
            sig,
        }
    }

    /// Evict a member: sign a revocation of its certificate `serial`.
    pub fn revoke(&self, serial: u64, revoked_at: u64) -> Revocation {
        let net = self.network_id().0;
        let msg = revoke_signing_bytes(&net, serial, revoked_at);
        let sig = self.signing.sign(&msg).to_bytes();
        Revocation {
            network_id: NetworkId(net),
            serial,
            revoked_at,
            sig,
        }
    }

    /// Admin: sign a member directory (the authoritative list of admitted node
    /// ids) for distribution over the DHT. Only the CA holder can produce this, so
    /// it is the admin's sole authority over the network's membership view.
    pub fn sign_directory(
        &self,
        version: u64,
        issued_at: u64,
        node_ids: Vec<[u8; 32]>,
    ) -> MemberDirectory {
        let net = self.network_id().0;
        let msg = directory_signing_bytes(&net, version, issued_at, &node_ids);
        let sig = self.signing.sign(&msg).to_bytes();
        MemberDirectory {
            network_id: NetworkId(net),
            version,
            issued_at,
            node_ids,
            sig,
        }
    }

    /// Admin: sign the network manifest — the authoritative SDN "program"
    /// (currently the list of node ids designated as relays). Only the CA holder
    /// can produce one, so routing policy stays an admin-only act.
    pub fn sign_manifest(
        &self,
        version: u64,
        issued_at: u64,
        relays: Vec<[u8; 32]>,
        flows: Vec<FlowRule>,
    ) -> NetworkManifest {
        let net = self.network_id().0;
        let msg = manifest_signing_bytes(&net, version, issued_at, &relays, &flows);
        let sig = self.signing.sign(&msg).to_bytes();
        NetworkManifest {
            network_id: NetworkId(net),
            version,
            issued_at,
            relays,
            flows,
            sig,
        }
    }

    /// Load the network key from a 32-byte secret file, or `None` if missing/bad.
    pub fn load(path: &std::path::Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        let seed: [u8; 32] = bytes.get(..32)?.try_into().ok()?;
        Some(Self::from_secret(&seed))
    }

    /// Persist the network key (0600). This file is the mesh's master secret.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut seed = self.secret_bytes();
        std::fs::write(path, &seed[..])?;
        seed.zeroize();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

impl Drop for NetworkKey {
    fn drop(&mut self) {
        // SigningKey zeroizes its own scalar on drop (ed25519-dalek "zeroize").
    }
}

fn cert_signing_bytes(
    network_id: &[u8; 32],
    node_pubkey: &[u8; 32],
    serial: u64,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(CERT_DOMAIN.len() + 88);
    m.extend_from_slice(CERT_DOMAIN);
    m.extend_from_slice(network_id);
    m.extend_from_slice(node_pubkey);
    m.extend_from_slice(&serial.to_be_bytes());
    m.extend_from_slice(&issued_at.to_be_bytes());
    m.extend_from_slice(&expires_at.to_be_bytes());
    m
}

fn directory_signing_bytes(
    network_id: &[u8; 32],
    version: u64,
    issued_at: u64,
    node_ids: &[[u8; 32]],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(DIRECTORY_DOMAIN.len() + 48 + node_ids.len() * 32);
    m.extend_from_slice(DIRECTORY_DOMAIN);
    m.extend_from_slice(network_id);
    m.extend_from_slice(&version.to_be_bytes());
    m.extend_from_slice(&issued_at.to_be_bytes());
    m.extend_from_slice(&(node_ids.len() as u32).to_be_bytes());
    for id in node_ids {
        m.extend_from_slice(id);
    }
    m
}

fn manifest_signing_bytes(
    network_id: &[u8; 32],
    version: u64,
    issued_at: u64,
    relays: &[[u8; 32]],
    flows: &[FlowRule],
) -> Vec<u8> {
    let fb = flows_blob(flows);
    let mut m = Vec::with_capacity(MANIFEST_DOMAIN.len() + 52 + relays.len() * 32 + fb.len());
    m.extend_from_slice(MANIFEST_DOMAIN);
    m.extend_from_slice(network_id);
    m.extend_from_slice(&version.to_be_bytes());
    m.extend_from_slice(&issued_at.to_be_bytes());
    m.extend_from_slice(&(relays.len() as u32).to_be_bytes());
    for id in relays {
        m.extend_from_slice(id);
    }
    m.extend_from_slice(&(fb.len() as u32).to_be_bytes());
    m.extend_from_slice(&fb);
    m
}

fn revoke_signing_bytes(network_id: &[u8; 32], serial: u64, revoked_at: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(REVOKE_DOMAIN.len() + 48);
    m.extend_from_slice(REVOKE_DOMAIN);
    m.extend_from_slice(network_id);
    m.extend_from_slice(&serial.to_be_bytes());
    m.extend_from_slice(&revoked_at.to_be_bytes());
    m
}

/// The admin-signed list of admitted node ids — the authoritative membership view
/// distributed over the DHT so every node learns the whole mesh and forms a full
/// mesh automatically (no manual peer pins). Only the CA holder can sign one, so
/// changing who is in the network stays an admin-only act even though the record
/// itself rides untrusted DHT storage. See docs/SDN_DHT_ARCHITECTURE.md.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberDirectory {
    network_id: NetworkId,
    version: u64,
    issued_at: u64,
    node_ids: Vec<[u8; 32]>,
    sig: [u8; 64],
}

impl MemberDirectory {
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    /// The admitted node ids (each is also the node's static public key in v0).
    pub fn node_ids(&self) -> &[[u8; 32]] {
        &self.node_ids
    }

    /// Verify the directory is authentic for `network` (signed by its CA). Returns
    /// the version on success so a reader can keep only the newest it has seen.
    pub fn verify(&self, network: &NetworkId) -> Result<u64, MembershipError> {
        if self.network_id != *network {
            return Err(MembershipError::WrongNetwork);
        }
        let msg = directory_signing_bytes(&network.0, self.version, self.issued_at, &self.node_ids);
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig);
        network
            .verifying_key()?
            .verify(&msg, &sig)
            .map_err(|_| MembershipError::BadSignature)?;
        Ok(self.version)
    }

    /// Wire form: network_id(32) ‖ version(8) ‖ issued_at(8) ‖ count(4) ‖
    /// node_ids(32·n) ‖ sig(64). For DHT storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(52 + self.node_ids.len() * 32 + 64);
        b.extend_from_slice(&self.network_id.0);
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&self.issued_at.to_be_bytes());
        b.extend_from_slice(&(self.node_ids.len() as u32).to_be_bytes());
        for id in &self.node_ids {
            b.extend_from_slice(id);
        }
        b.extend_from_slice(&self.sig);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, MembershipError> {
        if b.len() < 52 {
            return Err(MembershipError::Malformed);
        }
        let network_id = NetworkId(b[0..32].try_into().unwrap());
        let version = u64::from_be_bytes(b[32..40].try_into().unwrap());
        let issued_at = u64::from_be_bytes(b[40..48].try_into().unwrap());
        let count = u32::from_be_bytes(b[48..52].try_into().unwrap()) as usize;
        let want = 52 + count * 32 + 64;
        if b.len() != want {
            return Err(MembershipError::Malformed);
        }
        let mut node_ids = Vec::with_capacity(count);
        for i in 0..count {
            let off = 52 + i * 32;
            node_ids.push(b[off..off + 32].try_into().unwrap());
        }
        let sig: [u8; 64] = b[want - 64..want].try_into().unwrap();
        Ok(Self {
            network_id,
            version,
            issued_at,
            node_ids,
            sig,
        })
    }
}

/// The admin-signed network manifest — the SDN control-plane "program" the admin
/// publishes over the DHT. v1 carries the **relays**: node ids the admin has
/// designated to forward traffic for peers that can't connect directly (the
/// Phase-2 auto-relay; see docs/SDN_DHT_ARCHITECTURE.md §7). Only the CA holder
/// can sign one, so routing policy stays an admin-only act.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkManifest {
    network_id: NetworkId,
    version: u64,
    issued_at: u64,
    relays: Vec<[u8; 32]>,
    /// The SDN flow table (docs/FLOW_TABLE.md). Empty ⇒ nodes use the built-in
    /// default (overlay→owner, internet→exit).
    flows: Vec<FlowRule>,
    sig: [u8; 64],
}

impl NetworkManifest {
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    /// Node ids the admin has designated as relays, in preference order.
    pub fn relays(&self) -> &[[u8; 32]] {
        &self.relays
    }
    /// The admin-signed SDN flow table (empty ⇒ default behavior).
    pub fn flows(&self) -> &[FlowRule] {
        &self.flows
    }

    /// Verify the manifest is authentic for `network` (signed by its CA). Returns
    /// the version so a reader can keep only the newest it has seen.
    pub fn verify(&self, network: &NetworkId) -> Result<u64, MembershipError> {
        if self.network_id != *network {
            return Err(MembershipError::WrongNetwork);
        }
        let msg = manifest_signing_bytes(
            &network.0,
            self.version,
            self.issued_at,
            &self.relays,
            &self.flows,
        );
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig);
        network
            .verifying_key()?
            .verify(&msg, &sig)
            .map_err(|_| MembershipError::BadSignature)?;
        Ok(self.version)
    }

    /// Wire form: network_id(32) ‖ version(8) ‖ issued_at(8) ‖ relay_count(4) ‖
    /// relays(32·n) ‖ flows_len(4) ‖ flows(bincode) ‖ sig(64). For DHT storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let fb = flows_blob(&self.flows);
        let mut b = Vec::with_capacity(56 + self.relays.len() * 32 + fb.len() + 64);
        b.extend_from_slice(&self.network_id.0);
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&self.issued_at.to_be_bytes());
        b.extend_from_slice(&(self.relays.len() as u32).to_be_bytes());
        for id in &self.relays {
            b.extend_from_slice(id);
        }
        b.extend_from_slice(&(fb.len() as u32).to_be_bytes());
        b.extend_from_slice(&fb);
        b.extend_from_slice(&self.sig);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, MembershipError> {
        if b.len() < 52 {
            return Err(MembershipError::Malformed);
        }
        let network_id = NetworkId(b[0..32].try_into().unwrap());
        let version = u64::from_be_bytes(b[32..40].try_into().unwrap());
        let issued_at = u64::from_be_bytes(b[40..48].try_into().unwrap());
        let count = u32::from_be_bytes(b[48..52].try_into().unwrap()) as usize;
        // relays
        let flows_len_off = 52 + count * 32;
        if b.len() < flows_len_off + 4 {
            return Err(MembershipError::Malformed);
        }
        let mut relays = Vec::with_capacity(count);
        for i in 0..count {
            let off = 52 + i * 32;
            relays.push(b[off..off + 32].try_into().unwrap());
        }
        // flows blob
        let flen =
            u32::from_be_bytes(b[flows_len_off..flows_len_off + 4].try_into().unwrap()) as usize;
        let flows_off = flows_len_off + 4;
        let want = flows_off + flen + 64;
        if b.len() != want {
            return Err(MembershipError::Malformed);
        }
        let flows: Vec<FlowRule> = if flen == 0 {
            Vec::new()
        } else {
            bincode::deserialize(&b[flows_off..flows_off + flen])
                .map_err(|_| MembershipError::Malformed)?
        };
        let sig: [u8; 64] = b[want - 64..want].try_into().unwrap();
        Ok(Self {
            network_id,
            version,
            issued_at,
            relays,
            flows,
            sig,
        })
    }
}

/// A signed proof that a node belongs to a network. Presented during the
/// handshake; the peer verifies it against the [`NetworkId`] it trusts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberCert {
    network_id: NetworkId,
    node_pubkey: [u8; 32],
    serial: u64,
    issued_at: u64,
    expires_at: u64,
    sig: [u8; 64],
}

impl MemberCert {
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    pub fn node_pubkey(&self) -> &[u8; 32] {
        &self.node_pubkey
    }
    pub fn serial(&self) -> u64 {
        self.serial
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Fixed 152-byte wire encoding (for the handshake payload).
    pub fn to_bytes(&self) -> [u8; CERT_WIRE_LEN] {
        let mut b = [0u8; CERT_WIRE_LEN];
        b[..32].copy_from_slice(&self.network_id.0);
        b[32..64].copy_from_slice(&self.node_pubkey);
        b[64..72].copy_from_slice(&self.serial.to_be_bytes());
        b[72..80].copy_from_slice(&self.issued_at.to_be_bytes());
        b[80..88].copy_from_slice(&self.expires_at.to_be_bytes());
        b[88..152].copy_from_slice(&self.sig);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, MembershipError> {
        if b.len() != CERT_WIRE_LEN {
            return Err(MembershipError::Malformed);
        }
        let net: [u8; 32] = b[..32].try_into().unwrap();
        let node: [u8; 32] = b[32..64].try_into().unwrap();
        let serial = u64::from_be_bytes(b[64..72].try_into().unwrap());
        let issued_at = u64::from_be_bytes(b[72..80].try_into().unwrap());
        let expires_at = u64::from_be_bytes(b[80..88].try_into().unwrap());
        let sig: [u8; 64] = b[88..152].try_into().unwrap();
        Ok(Self {
            network_id: NetworkId(net),
            node_pubkey: node,
            serial,
            issued_at,
            expires_at,
            sig,
        })
    }

    /// Verify this cert: it must be for `expected_network`, bound to
    /// `expected_node` (the peer's authenticated identity key), unexpired at
    /// `now`, and carry a valid network signature.
    pub fn verify(
        &self,
        expected_network: &NetworkId,
        expected_node: &[u8],
        now: u64,
    ) -> Result<(), MembershipError> {
        if &self.network_id != expected_network {
            return Err(MembershipError::WrongNetwork);
        }
        if expected_node != self.node_pubkey {
            return Err(MembershipError::WrongNode);
        }
        if self.expires_at != 0 && now >= self.expires_at {
            return Err(MembershipError::Expired);
        }
        let vk = self.network_id.verifying_key()?;
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig);
        let msg = cert_signing_bytes(
            &self.network_id.0,
            &self.node_pubkey,
            self.serial,
            self.issued_at,
            self.expires_at,
        );
        vk.verify(&msg, &sig)
            .map_err(|_| MembershipError::BadSignature)
    }
}

/// A signed eviction of a certificate `serial`. Independently verifiable and
/// freely gossipable — nodes union them into a [`RevocationList`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revocation {
    network_id: NetworkId,
    serial: u64,
    revoked_at: u64,
    sig: [u8; 64],
}

impl Revocation {
    pub fn serial(&self) -> u64 {
        self.serial
    }
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub fn to_bytes(&self) -> [u8; REVOKE_WIRE_LEN] {
        let mut b = [0u8; REVOKE_WIRE_LEN];
        b[..32].copy_from_slice(&self.network_id.0);
        b[32..40].copy_from_slice(&self.serial.to_be_bytes());
        b[40..48].copy_from_slice(&self.revoked_at.to_be_bytes());
        b[48..112].copy_from_slice(&self.sig);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, MembershipError> {
        if b.len() != REVOKE_WIRE_LEN {
            return Err(MembershipError::Malformed);
        }
        let net: [u8; 32] = b[..32].try_into().unwrap();
        let serial = u64::from_be_bytes(b[32..40].try_into().unwrap());
        let revoked_at = u64::from_be_bytes(b[40..48].try_into().unwrap());
        let sig: [u8; 64] = b[48..112].try_into().unwrap();
        Ok(Self {
            network_id: NetworkId(net),
            serial,
            revoked_at,
            sig,
        })
    }

    /// True iff this revocation carries a valid signature for `network`.
    pub fn verify(&self, network: &NetworkId) -> bool {
        if &self.network_id != network {
            return false;
        }
        let Ok(vk) = self.network_id.verifying_key() else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig);
        let msg = revoke_signing_bytes(&self.network_id.0, self.serial, self.revoked_at);
        vk.verify(&msg, &sig).is_ok()
    }
}

/// The set of revoked certificate serials a node knows about. Grows by union as
/// revocations are gossiped; only signature-valid entries are ever admitted.
#[derive(Default, Clone)]
pub struct RevocationList {
    revoked: BTreeMap<u64, Revocation>,
}

impl RevocationList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_revoked(&self, serial: u64) -> bool {
        self.revoked.contains_key(&serial)
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Admit a revocation if it verifies for `network` and is new. Returns true
    /// iff it was newly added (so callers can decide to re-gossip it).
    pub fn add(&mut self, rev: Revocation, network: &NetworkId) -> bool {
        if !rev.verify(network) || self.revoked.contains_key(&rev.serial) {
            return false;
        }
        self.revoked.insert(rev.serial, rev);
        true
    }

    /// Merge another list's entries (each re-verified). Returns how many were new.
    pub fn merge(&mut self, other: &RevocationList, network: &NetworkId) -> usize {
        let mut added = 0;
        for rev in other.revoked.values() {
            if self.add(rev.clone(), network) {
                added += 1;
            }
        }
        added
    }

    pub fn iter(&self) -> impl Iterator<Item = &Revocation> {
        self.revoked.values()
    }

    /// Encode all entries as `u32 count` + `count × 112-byte` revocations.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.revoked.len() * REVOKE_WIRE_LEN);
        out.extend_from_slice(&(self.revoked.len() as u32).to_be_bytes());
        for rev in self.revoked.values() {
            out.extend_from_slice(&rev.to_bytes());
        }
        out
    }

    /// Decode the wire form. Signatures are NOT checked here — feed the result
    /// through [`RevocationList::merge`] with the network id to verify.
    pub fn from_bytes(b: &[u8]) -> Result<Self, MembershipError> {
        if b.len() < 4 {
            return Err(MembershipError::Malformed);
        }
        let count = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
        if b.len() != 4 + count * REVOKE_WIRE_LEN {
            return Err(MembershipError::Malformed);
        }
        let mut revoked = BTreeMap::new();
        for i in 0..count {
            let start = 4 + i * REVOKE_WIRE_LEN;
            let rev = Revocation::from_bytes(&b[start..start + REVOKE_WIRE_LEN])?;
            revoked.insert(rev.serial, rev);
        }
        Ok(Self { revoked })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn issued_cert_verifies_and_round_trips() {
        let net = NetworkKey::generate();
        let id = net.network_id();
        let node = node_key(7);
        let cert = net.issue_cert(&node, 1, 1000, 0);

        // round-trips through the wire form unchanged
        let back = MemberCert::from_bytes(&cert.to_bytes()).unwrap();
        assert_eq!(back, cert);

        // verifies for the right network + node, at any time (no expiry)
        assert!(back.verify(&id, &node, 5000).is_ok());
    }

    #[test]
    fn cert_rejected_for_wrong_network_node_or_when_expired() {
        let net = NetworkKey::generate();
        let other = NetworkKey::generate();
        let id = net.network_id();
        let node = node_key(7);
        let cert = net.issue_cert(&node, 1, 1000, 2000);

        // wrong network id
        assert_eq!(
            cert.verify(&other.network_id(), &node, 1500),
            Err(MembershipError::WrongNetwork)
        );
        // wrong node binding
        assert_eq!(
            cert.verify(&id, &node_key(8), 1500),
            Err(MembershipError::WrongNode)
        );
        // expired
        assert_eq!(cert.verify(&id, &node, 2000), Err(MembershipError::Expired));
        // valid before expiry
        assert!(cert.verify(&id, &node, 1999).is_ok());
    }

    #[test]
    fn forged_signature_does_not_verify() {
        let net = NetworkKey::generate();
        let node = node_key(7);
        let mut cert = net.issue_cert(&node, 1, 1000, 0);
        cert.sig[0] ^= 0xff;
        assert_eq!(
            cert.verify(&net.network_id(), &node, 1500),
            Err(MembershipError::BadSignature)
        );
    }

    #[test]
    fn revocation_gossips_by_verified_union() {
        let net = NetworkKey::generate();
        let id = net.network_id();
        let imposter = NetworkKey::generate();

        let mut crl = RevocationList::new();
        assert!(
            crl.add(net.revoke(42, 3000), &id),
            "valid revocation admitted"
        );
        assert!(crl.is_revoked(42));
        assert!(
            !crl.add(net.revoke(42, 3000), &id),
            "duplicate not re-added"
        );

        // a revocation signed by a different network is rejected
        assert!(!crl.add(imposter.revoke(99, 3000), &id));
        assert!(!crl.is_revoked(99));

        // wire round-trip + merge re-verifies every entry
        let wire = crl.to_bytes();
        let decoded = RevocationList::from_bytes(&wire).unwrap();
        let mut fresh = RevocationList::new();
        assert_eq!(fresh.merge(&decoded, &id), 1);
        assert!(fresh.is_revoked(42));
    }

    #[test]
    fn network_id_hex_and_secret_round_trip() {
        let net = NetworkKey::generate();
        let id = net.network_id();
        assert_eq!(NetworkId::from_hex(&id.to_hex()).unwrap(), id);

        let seed = net.secret_bytes();
        let reloaded = NetworkKey::from_secret(&seed);
        assert_eq!(reloaded.network_id(), id, "same seed → same network");
        // rendezvous tag is stable + short
        assert_eq!(id.rendezvous_tag().len(), 16);
        assert_eq!(id.rendezvous_tag(), reloaded.network_id().rendezvous_tag());
    }

    #[test]
    fn member_directory_signs_verifies_and_round_trips() {
        let net = NetworkKey::generate();
        let id = net.network_id();
        let ids = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let dir = net.sign_directory(7, 1_000, ids.clone());

        // authentic for its network
        assert_eq!(dir.verify(&id).unwrap(), 7);
        assert_eq!(dir.node_ids(), ids.as_slice());

        // wire round-trip preserves everything + still verifies
        let back = MemberDirectory::from_bytes(&dir.to_bytes()).unwrap();
        assert_eq!(back, dir);
        assert_eq!(back.verify(&id).unwrap(), 7);

        // a different network rejects it; a tampered list fails the signature
        let other = NetworkKey::generate().network_id();
        assert_eq!(back.verify(&other), Err(MembershipError::WrongNetwork));
        let mut tampered = dir.to_bytes();
        tampered[52] ^= 0xff; // flip a byte of the first node id
        assert!(MemberDirectory::from_bytes(&tampered)
            .unwrap()
            .verify(&id)
            .is_err());

        // the DHT key is deterministic per network
        assert_eq!(id.directory_key(), reloaded_key(&net));
    }

    fn reloaded_key(net: &NetworkKey) -> [u8; 32] {
        NetworkKey::from_secret(&net.secret_bytes())
            .network_id()
            .directory_key()
    }

    #[test]
    fn network_manifest_signs_verifies_and_round_trips() {
        let net = NetworkKey::generate();
        let id = net.network_id();
        let relays = vec![[9u8; 32], [8u8; 32]];
        let flows = vec![lattice_proto::flow::FlowRule {
            priority: 90,
            match_: lattice_proto::flow::FlowMatch {
                proto: Some(17),
                dport: Some(53),
                ..Default::default()
            },
            action: lattice_proto::flow::FlowAction::Drop,
        }];
        let m = net.sign_manifest(3, 500, relays.clone(), flows.clone());

        assert_eq!(m.verify(&id).unwrap(), 3);
        assert_eq!(m.relays(), relays.as_slice());
        assert_eq!(m.flows(), flows.as_slice());

        let back = NetworkManifest::from_bytes(&m.to_bytes()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.verify(&id).unwrap(), 3);
        assert_eq!(
            back.flows(),
            flows.as_slice(),
            "signed flow table round-trips"
        );

        // wrong network + tamper both rejected
        assert_eq!(
            back.verify(&NetworkKey::generate().network_id()),
            Err(MembershipError::WrongNetwork)
        );
        let mut t = m.to_bytes();
        t[52] ^= 0xff;
        assert!(NetworkManifest::from_bytes(&t)
            .unwrap()
            .verify(&id)
            .is_err());

        // manifest key is deterministic and distinct from the directory key
        assert_ne!(id.manifest_key(), id.directory_key());
    }
}

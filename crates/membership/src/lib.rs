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
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Domain-separation tags so a cert signature can never be reinterpreted as a
/// revocation signature (or vice versa) even with identical field bytes.
const CERT_DOMAIN: &[u8] = b"lattice-member-cert-v1";
const REVOKE_DOMAIN: &[u8] = b"lattice-revocation-v1";

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

fn revoke_signing_bytes(network_id: &[u8; 32], serial: u64, revoked_at: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(REVOKE_DOMAIN.len() + 48);
    m.extend_from_slice(REVOKE_DOMAIN);
    m.extend_from_slice(network_id);
    m.extend_from_slice(&serial.to_be_bytes());
    m.extend_from_slice(&revoked_at.to_be_bytes());
    m
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
        assert!(crl.add(net.revoke(42, 3000), &id), "valid revocation admitted");
        assert!(crl.is_revoked(42));
        assert!(!crl.add(net.revoke(42, 3000), &id), "duplicate not re-added");

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
}

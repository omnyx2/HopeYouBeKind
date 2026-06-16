//! v2 discovery primitives (docs/MESH_V2.md §10) — **admin-free**.
//!
//! Each member self-publishes a **signed** [`EndpointRecord`] saying where it can
//! be reached. A reader verifies the signature against the member's own key — and
//! the cert chain ([`crate::membership`]) proves that key belongs to the mesh — so
//! an endpoint cannot be spoofed. Newest `seq` wins. There is no admin and no
//! signed directory: the **roster** is the set of valid certs (gossiped), and the
//! **"where"** is these records, gossiped the same way.

use std::collections::HashMap;
use std::net::SocketAddr;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::membership::{MemberKey, PubKey};

/// A self-signed advertisement of a member's reachable endpoints.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EndpointRecord {
    pub network: PubKey,
    /// Whose endpoints these are (and whose key signs the record).
    pub member: PubKey,
    pub endpoints: Vec<SocketAddr>,
    /// Monotonic per member — a higher `seq` supersedes a lower one.
    pub seq: u64,
    pub at_ms: u64,
    #[serde(with = "crate::membership::sig_serde")]
    pub sig: [u8; 64],
}

fn signing_bytes(
    network: &PubKey,
    member: &PubKey,
    endpoints: &[SocketAddr],
    seq: u64,
    at_ms: u64,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(network);
    b.extend_from_slice(member);
    b.extend_from_slice(&(endpoints.len() as u16).to_be_bytes());
    for e in endpoints {
        b.extend_from_slice(e.to_string().as_bytes());
        b.push(0);
    }
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&at_ms.to_be_bytes());
    b
}

impl EndpointRecord {
    /// Does the signature match the claimed `member` key over these fields?
    /// (That `member` is actually in the mesh is a separate cert check.)
    pub fn verify(&self) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.member) else {
            return false;
        };
        let sig = Signature::from_bytes(&self.sig);
        vk.verify(
            &signing_bytes(
                &self.network,
                &self.member,
                &self.endpoints,
                self.seq,
                self.at_ms,
            ),
            &sig,
        )
        .is_ok()
    }
}

impl MemberKey {
    /// Self-publish this member's reachable endpoints, signed.
    pub fn publish_endpoints(
        &self,
        network: PubKey,
        endpoints: Vec<SocketAddr>,
        seq: u64,
        at_ms: u64,
    ) -> EndpointRecord {
        let member = self.pubkey();
        let sig = self.sign(&signing_bytes(&network, &member, &endpoints, seq, at_ms));
        EndpointRecord {
            network,
            member,
            endpoints,
            seq,
            at_ms,
            sig,
        }
    }
}

/// The latest verified endpoint record per member — the "where" half of discovery.
#[derive(Default)]
pub struct EndpointBook {
    latest: HashMap<PubKey, EndpointRecord>,
}

impl EndpointBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take in a gossiped record: accept it only if its signature verifies and its
    /// `seq` is newer than what we hold for that member. Returns whether it was
    /// adopted.
    pub fn observe(&mut self, rec: EndpointRecord) -> bool {
        if !rec.verify() {
            return false;
        }
        match self.latest.get(&rec.member) {
            Some(cur) if cur.seq >= rec.seq => false,
            _ => {
                self.latest.insert(rec.member, rec);
                true
            }
        }
    }

    pub fn get(&self, member: &PubKey) -> Option<&EndpointRecord> {
        self.latest.get(member)
    }

    pub fn len(&self) -> usize {
        self.latest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.latest.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn publish_then_verify() {
        let net = [7u8; 32];
        let alice = MemberKey::from_seed(&[2u8; 32]);
        let rec = alice.publish_endpoints(net, vec![ep("203.0.113.5:41000")], 1, 1000);
        assert!(rec.verify());
        assert_eq!(rec.member, alice.pubkey());
    }

    #[test]
    fn tampered_endpoints_fail() {
        let net = [7u8; 32];
        let alice = MemberKey::from_seed(&[2u8; 32]);
        let mut rec = alice.publish_endpoints(net, vec![ep("203.0.113.5:41000")], 1, 1000);
        rec.endpoints = vec![ep("6.6.6.6:41000")]; // signature no longer matches
        assert!(!rec.verify());
    }

    #[test]
    fn book_keeps_newest_seq() {
        let net = [7u8; 32];
        let alice = MemberKey::from_seed(&[2u8; 32]);
        let mut book = EndpointBook::new();
        assert!(book.observe(alice.publish_endpoints(net, vec![ep("1.1.1.1:1")], 1, 1)));
        // newer seq wins
        assert!(book.observe(alice.publish_endpoints(net, vec![ep("2.2.2.2:2")], 2, 2)));
        assert_eq!(
            book.get(&alice.pubkey()).unwrap().endpoints,
            vec![ep("2.2.2.2:2")]
        );
        // stale (lower/equal seq) rejected
        assert!(!book.observe(alice.publish_endpoints(net, vec![ep("3.3.3.3:3")], 2, 9)));
        assert_eq!(
            book.get(&alice.pubkey()).unwrap().endpoints,
            vec![ep("2.2.2.2:2")]
        );
    }

    #[test]
    fn book_rejects_bad_signature() {
        let net = [7u8; 32];
        let alice = MemberKey::from_seed(&[2u8; 32]);
        let mut rec = alice.publish_endpoints(net, vec![ep("1.1.1.1:1")], 1, 1);
        rec.sig[0] ^= 0xff;
        let mut book = EndpointBook::new();
        assert!(!book.observe(rec));
        assert!(book.is_empty());
    }
}

//! The Kademlia routing table: k-buckets of known contacts, organized by XOR
//! distance from this node, and "find the k closest contacts to a target".

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::distance::{bucket_index, by_distance, Key};

/// Replication / bucket parameter `k`: contacts per bucket and the size of the
/// closest-set a lookup converges to.
pub const K: usize = 20;

/// A known peer in the DHT: its node id and where to reach it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub id: Key,
    pub addr: SocketAddr,
}

impl Contact {
    pub fn new(id: Key, addr: SocketAddr) -> Self {
        Self { id, addr }
    }
}

/// 256 k-buckets indexed by [`bucket_index`]. Within a bucket, contacts are kept
/// least-recently-seen first (front) so a full bucket evicts the stalest.
pub struct RoutingTable {
    self_id: Key,
    buckets: Vec<Vec<Contact>>,
}

impl RoutingTable {
    pub fn new(self_id: Key) -> Self {
        Self {
            self_id,
            buckets: vec![Vec::new(); 256],
        }
    }

    /// Record a contact we've heard from. Moves a known contact to most-recently
    /// -seen; inserts a new one; on a full bucket, evicts the stalest.
    pub fn insert(&mut self, contact: Contact) {
        if contact.id == self.self_id {
            return; // never store ourselves
        }
        let idx = bucket_index(&self.self_id, &contact.id);
        let bucket = &mut self.buckets[idx];
        if let Some(pos) = bucket.iter().position(|c| c.id == contact.id) {
            bucket.remove(pos);
            bucket.push(contact); // refresh recency
        } else if bucket.len() < K {
            bucket.push(contact);
        } else {
            // Bucket full: evict least-recently-seen (real Kademlia pings it
            // first; we evict eagerly).
            bucket.remove(0);
            bucket.push(contact);
        }
    }

    /// The up-to-`count` contacts closest to `target` by XOR distance.
    pub fn closest(&self, target: &Key, count: usize) -> Vec<Contact> {
        let mut all: Vec<Contact> = self.buckets.iter().flatten().cloned().collect();
        all.sort_by(|a, b| by_distance(target, &a.id, &b.id));
        all.truncate(count);
        all
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(byte: u8) -> Contact {
        Contact::new([byte; 32], "127.0.0.1:1".parse().unwrap())
    }

    #[test]
    fn rejects_self_insertion() {
        let me = [5u8; 32];
        let mut t = RoutingTable::new(me);
        t.insert(Contact::new(me, "127.0.0.1:1".parse().unwrap()));
        assert!(t.is_empty());
    }

    #[test]
    fn closest_returns_nearest_by_xor() {
        let mut t = RoutingTable::new([0u8; 32]);
        for b in [0x01u8, 0x02, 0x40, 0x80, 0xff] {
            t.insert(contact(b));
        }
        let target = [0u8; 32];
        let nearest = t.closest(&target, 2);
        // 0x01 (dist 1) and 0x02 (dist 2) are the two closest to all-zeros.
        assert_eq!(nearest[0].id[0], 0x01);
        assert_eq!(nearest[1].id[0], 0x02);
    }

    #[test]
    fn refreshes_recency_without_duplicating() {
        let mut t = RoutingTable::new([0u8; 32]);
        t.insert(contact(0x10));
        t.insert(contact(0x10));
        assert_eq!(t.len(), 1, "same id is not duplicated");
    }
}

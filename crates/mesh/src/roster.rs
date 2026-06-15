//! The per-mesh **roster**: 1-byte join-order ids ↔ members (§2 "name as CIDR").
//!
//! In-mesh there are no real IPs — a member is addressed by a 1-byte id (`1..=254`;
//! `0`/`255` reserved), assigned at join. The roster maps that id to the name the
//! member chose and its public key. It is shared by all members (full in-mesh
//! transparency), and in v2 it propagates as gossiped certs (no admin directory) —
//! this module is the in-memory shape; gossip/signing land with membership.

use std::collections::HashMap;

use lattice_proto::wire_v2::MemberId;
use serde::{Deserialize, Serialize};

/// One member's in-mesh record.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Member {
    /// The name picked at join (the §2 "name as CIDR").
    pub name: String,
    /// The member's static public key (its cert binds this to its id).
    pub pubkey: [u8; 32],
}

/// A mesh's members, keyed by their 1-byte join-order id.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roster {
    members: HashMap<MemberId, Member>,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum RosterError {
    #[error("mesh is full (max {0} members)")]
    Full(u8),
}

impl Roster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a member at the **lowest free** join-order id in `1..=254`, enforcing
    /// `max_members`. Returns the assigned id. (A freed id may be reused by a later
    /// join; the cap is the 1-byte space, so the scan always finds a slot when
    /// `len < max`.)
    pub fn admit(&mut self, member: Member, max_members: u8) -> Result<MemberId, RosterError> {
        if self.members.len() >= max_members as usize {
            return Err(RosterError::Full(max_members));
        }
        let id = (1u8..=254)
            .find(|id| !self.members.contains_key(id))
            .ok_or(RosterError::Full(max_members))?;
        self.members.insert(id, member);
        Ok(id)
    }

    pub fn get(&self, id: MemberId) -> Option<&Member> {
        self.members.get(&id)
    }

    pub fn contains(&self, id: MemberId) -> bool {
        self.members.contains_key(&id)
    }

    /// The id holding `pubkey`, if any.
    pub fn by_pubkey(&self, pubkey: &[u8; 32]) -> Option<MemberId> {
        self.members
            .iter()
            .find(|(_, m)| &m.pubkey == pubkey)
            .map(|(id, _)| *id)
    }

    /// Evict a member (e.g. on expulsion); returns the removed record.
    pub fn remove(&mut self, id: MemberId) -> Option<Member> {
        self.members.remove(&id)
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (MemberId, &Member)> {
        self.members.iter().map(|(id, m)| (*id, m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name: &str, pk: u8) -> Member {
        Member {
            name: name.into(),
            pubkey: [pk; 32],
        }
    }

    #[test]
    fn admits_in_join_order_from_one() {
        let mut r = Roster::new();
        assert_eq!(r.admit(member("alice", 1), 254).unwrap(), 1);
        assert_eq!(r.admit(member("bob", 2), 254).unwrap(), 2);
        assert_eq!(r.admit(member("carol", 3), 254).unwrap(), 3);
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn reuses_lowest_freed_id() {
        let mut r = Roster::new();
        r.admit(member("a", 1), 254).unwrap(); // 1
        r.admit(member("b", 2), 254).unwrap(); // 2
        r.admit(member("c", 3), 254).unwrap(); // 3
        assert_eq!(r.remove(2).unwrap().name, "b");
        // the freed slot 2 is the lowest free id
        assert_eq!(r.admit(member("d", 4), 254).unwrap(), 2);
    }

    #[test]
    fn enforces_max_members_cap() {
        let mut r = Roster::new();
        r.admit(member("a", 1), 2).unwrap();
        r.admit(member("b", 2), 2).unwrap();
        assert_eq!(r.admit(member("c", 3), 2), Err(RosterError::Full(2)));
    }

    #[test]
    fn lookup_by_pubkey() {
        let mut r = Roster::new();
        r.admit(member("a", 1), 254).unwrap();
        let id = r.admit(member("b", 7), 254).unwrap();
        assert_eq!(r.by_pubkey(&[7u8; 32]), Some(id));
        assert_eq!(r.by_pubkey(&[9u8; 32]), None);
    }
}

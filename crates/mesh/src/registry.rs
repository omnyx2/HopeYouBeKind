//! Mesh service registry (docs/EXTENSIONS.md §6).
//!
//! A connector advertises that *its* node offers some service (VNC, folder sync, …) on
//! the overlay, so other members' connectors can discover and reach it at the owner's
//! overlay IP. Records gossip mesh-wide exactly like the roster / flow table: one signed
//! channel, newest-per-(member, proto) wins.
//!
//! Unlike the roster these are **soft state** — they are *not* persisted and they expire
//! if a member stops re-advertising them (crash / unadvertise). The owning node re-gossips
//! its own records every tick, so a record that stops arriving for a few ticks is gone.
//! Expiry is enforced by the receiver (it stamps a local `last_refresh_ms` on merge); the
//! gossiped record itself carries no clock, so nodes never compare wall clocks.

use lattice_proto::wire_v2::MemberId;
use serde::{Deserialize, Serialize};

/// One advertised service, as it travels on the wire (gossiped). No timestamps: freshness
/// is tracked locally by the receiver (see [`ServiceEntry`]).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceRecord {
    /// The in-mesh member that offers the service (reached at its overlay IP).
    pub member: MemberId,
    /// Service kind, e.g. `"minisync"`, `"vnc"`. The discovery key.
    pub proto: String,
    /// Port the service listens on at the member's overlay IP.
    pub port: u16,
    /// Human label.
    #[serde(default)]
    pub name: String,
    /// Free-form connector metadata (e.g. `{ "folder": "SharedFolder" }`). Opaque to the
    /// mesh; treat as untrusted input on the consuming side.
    #[serde(default)]
    pub meta: serde_json::Value,
    /// Monotonic per-(member, proto) version. A re-advertise bumps it; a higher `seq`
    /// supersedes a lower one when records are merged, so updates converge.
    pub seq: u64,
}

/// A [`ServiceRecord`] plus the local clock when we last saw it. The timestamp is **local
/// only** — never gossiped — so soft-state expiry needs no clock agreement between nodes.
#[derive(Clone, Debug)]
pub struct ServiceEntry {
    pub rec: ServiceRecord,
    /// `now_ms()` when we last advertised (own) or merged (peer) this record.
    pub last_refresh_ms: u64,
}

/// How long a peer's record survives without a refresh before it is considered gone. The
/// owner re-gossips every roster tick (~20s), so a few missed ticks ⇒ dropped.
pub const SERVICE_TTL_MS: u64 = 90_000;

/// Merge an incoming batch of gossiped records into `book`, newest-per-(member, proto)
/// wins, stamping `now_ms` as the refresh time. `cap` bounds the table. Returns true if
/// anything changed (added / superseded), so the caller can emit an event + re-gossip.
pub fn merge(
    book: &mut Vec<ServiceEntry>,
    incoming: impl IntoIterator<Item = ServiceRecord>,
    now_ms: u64,
    cap: usize,
) -> bool {
    let mut changed = false;
    for rec in incoming {
        match book
            .iter_mut()
            .find(|e| e.rec.member == rec.member && e.rec.proto == rec.proto)
        {
            Some(existing) => {
                // A refresh of a record we already hold keeps it alive even if identical;
                // only a strictly newer seq (or a changed payload at >= seq) counts as a
                // visible change worth re-gossiping / eventing.
                if rec.seq > existing.rec.seq
                    || (rec.seq == existing.rec.seq && rec != existing.rec)
                {
                    changed |= rec != existing.rec;
                    existing.rec = rec;
                }
                existing.last_refresh_ms = now_ms;
            }
            None => {
                if book.len() >= cap {
                    continue;
                }
                book.push(ServiceEntry {
                    rec,
                    last_refresh_ms: now_ms,
                });
                changed = true;
            }
        }
    }
    changed
}

/// Drop entries from peers (not `own`) that haven't refreshed within [`SERVICE_TTL_MS`].
/// Our own records never expire here — they live as long as the connector keeps them
/// advertised. Returns true if anything was removed.
pub fn expire(book: &mut Vec<ServiceEntry>, own: MemberId, now_ms: u64) -> bool {
    let before = book.len();
    book.retain(|e| {
        e.rec.member == own || now_ms.saturating_sub(e.last_refresh_ms) < SERVICE_TTL_MS
    });
    book.len() != before
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(member: MemberId, proto: &str, port: u16, seq: u64) -> ServiceRecord {
        ServiceRecord {
            member,
            proto: proto.into(),
            port,
            name: String::new(),
            meta: serde_json::Value::Null,
            seq,
        }
    }

    #[test]
    fn merge_adds_then_newest_seq_wins() {
        let mut book = Vec::new();
        assert!(merge(&mut book, [rec(2, "minisync", 100, 1)], 1_000, 16));
        assert_eq!(book.len(), 1);
        assert_eq!(book[0].rec.port, 100);

        // A newer seq for the same (member, proto) supersedes; refreshes the timestamp.
        assert!(merge(&mut book, [rec(2, "minisync", 200, 2)], 2_000, 16));
        assert_eq!(book.len(), 1);
        assert_eq!(book[0].rec.port, 200);
        assert_eq!(book[0].last_refresh_ms, 2_000);

        // An older seq is ignored as a change, but still refreshes liveness.
        assert!(!merge(&mut book, [rec(2, "minisync", 999, 1)], 3_000, 16));
        assert_eq!(book[0].rec.port, 200);
        assert_eq!(book[0].last_refresh_ms, 3_000);
    }

    #[test]
    fn merge_distinct_proto_and_member_are_separate() {
        let mut book = Vec::new();
        merge(&mut book, [rec(2, "minisync", 1, 1)], 0, 16);
        merge(&mut book, [rec(2, "vnc", 2, 1)], 0, 16);
        merge(&mut book, [rec(3, "minisync", 3, 1)], 0, 16);
        assert_eq!(book.len(), 3);
    }

    #[test]
    fn merge_respects_cap() {
        let mut book = Vec::new();
        assert!(merge(&mut book, [rec(2, "a", 1, 1)], 0, 1));
        // Cap reached — a different key is dropped.
        assert!(!merge(&mut book, [rec(3, "b", 2, 1)], 0, 1));
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn expire_drops_stale_peers_keeps_own() {
        let mut book = Vec::new();
        merge(&mut book, [rec(1, "own", 1, 1)], 0, 16); // our own (member 1)
        merge(&mut book, [rec(2, "peer", 2, 1)], 0, 16); // a peer, last seen at t=0
        let now = SERVICE_TTL_MS + 1; // peer is now stale, own never expires
        assert!(expire(&mut book, 1, now));
        assert_eq!(book.len(), 1);
        assert_eq!(book[0].rec.member, 1);
        // Nothing to remove on a second pass.
        assert!(!expire(&mut book, 1, now));
    }
}

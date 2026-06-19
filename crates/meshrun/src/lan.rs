//! P-D4 LAN fast-path: same-router peers discover each other directly, with no WAN,
//! no exit, and no reflexion (docs/DISCOVERY.md P-D4).
//!
//! Each node periodically sends a tiny UDP **beacon** to a link-local multicast group.
//! The beacon carries, per mesh, an **opaque per-mesh tag** (`lattice_mesh::lan_tag`)
//! + our member id + our data-plane UDP port. A receiver matches the tag against the
//! meshes it belongs to; on a hit it seeds that mesh's [`PeerLinks`] with the sender's
//! LAN address (`src_ip : advertised_port`). The sealed gossip (P-D2) then confirms —
//! the mesh cipher is the real membership gate, so a non-member learns nothing beyond
//! "some lattice node is on this LAN" and an opaque tag it can't tie to a mesh.
//!
//! This beats WAN discovery on the LAN: lower latency, works with the exit/WAN down,
//! and needs no NAT traversal (LAN addresses are directly reachable).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use lattice_proto::wire_v2::MemberId;

use crate::{now_ms, Link, PeerLinks};

/// Link-local-scoped multicast group + port for the beacon. 239.255/16 is the IPv4
/// administratively-scoped (site-local) range; TTL 1 keeps it on the local segment.
const LAN_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 99);
const LAN_PORT: u16 = 42424;
/// Beacon cadence (seconds). Short enough to find a peer that just joined the LAN.
const LAN_BEACON_SECS: u64 = 7;
/// 4-byte magic so we ignore stray traffic on the port.
const BEACON_MAGIC: &[u8; 4] = b"LAT1";
/// Fixed beacon size: magic(4) + tag(8) + member(1) + port(2).
const BEACON_LEN: usize = 15;

/// One mesh's LAN-discoverable identity (a snapshot the runner reads each round).
pub struct LanMesh {
    /// Opaque per-mesh tag = `lattice_mesh::lan_tag(secret)`.
    pub tag: [u8; 8],
    /// Our own member id in this mesh (so we can skip our own beacon).
    pub member_id: MemberId,
    /// Our local data-plane UDP port — where peers send this mesh's sealed frames.
    pub dp_port: u16,
    /// This mesh's live peer table, seeded on a tag match.
    pub links: PeerLinks,
}

/// Encode a beacon for one mesh.
fn beacon_encode(tag: &[u8; 8], member: MemberId, port: u16) -> [u8; BEACON_LEN] {
    let mut b = [0u8; BEACON_LEN];
    b[0..4].copy_from_slice(BEACON_MAGIC);
    b[4..12].copy_from_slice(tag);
    b[12] = member;
    b[13..15].copy_from_slice(&port.to_be_bytes());
    b
}

/// Parse a beacon → (tag, member, data-plane port). `None` if it isn't one of ours.
fn beacon_parse(b: &[u8]) -> Option<([u8; 8], MemberId, u16)> {
    if b.len() != BEACON_LEN || &b[0..4] != BEACON_MAGIC {
        return None;
    }
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&b[4..12]);
    Some((tag, b[12], u16::from_be_bytes([b[13], b[14]])))
}

/// Open the multicast beacon socket (best-effort; `None` if the port can't be bound).
/// `SO_REUSEADDR` (+ `SO_REUSEPORT` on unix) lets it coexist and survive restarts.
fn open_socket() -> Option<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    sock.set_reuse_address(true).ok()?;
    #[cfg(unix)]
    sock.set_reuse_port(true).ok()?;
    let bind: SocketAddr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, LAN_PORT));
    sock.bind(&bind.into()).ok()?;
    sock.join_multicast_v4(&LAN_GROUP, &Ipv4Addr::UNSPECIFIED)
        .ok()?;
    sock.set_multicast_loop_v4(true).ok()?;
    sock.set_multicast_ttl_v4(1).ok()?; // never leave the local segment
    sock.set_nonblocking(true).ok()?;
    let std_sock: std::net::UdpSocket = sock.into();
    tokio::net::UdpSocket::from_std(std_sock).ok()
}

/// Run LAN discovery until the socket dies. `snapshot` yields the current set of
/// meshes to advertise + seed (it re-reads live state each round, so meshes added
/// after start are picked up). Best-effort: if the socket can't open, logs and
/// returns — the WAN paths (P-D1/2/3) still work.
pub async fn run_lan_discovery<F>(snapshot: F)
where
    F: Fn() -> Vec<LanMesh>,
{
    let Some(sock) = open_socket() else {
        eprintln!("meshrun: LAN discovery disabled (couldn't bind udp/{LAN_PORT})");
        return;
    };
    eprintln!("meshrun: LAN discovery live on {LAN_GROUP}:{LAN_PORT}");
    let dst = SocketAddr::V4(SocketAddrV4::new(LAN_GROUP, LAN_PORT));
    let mut beacon = tokio::time::interval(std::time::Duration::from_secs(LAN_BEACON_SECS));
    let mut buf = [0u8; 64];
    loop {
        tokio::select! {
            _ = beacon.tick() => {
                for m in snapshot() {
                    let pkt = beacon_encode(&m.tag, m.member_id, m.dp_port);
                    let _ = sock.send_to(&pkt, dst).await;
                }
            }
            r = sock.recv_from(&mut buf) => {
                let Ok((n, src)) = r else { break };
                let Some((tag, member, port)) = beacon_parse(&buf[..n]) else { continue };
                let SocketAddr::V4(src) = src else { continue };
                for m in snapshot() {
                    // Same mesh, and not our own beacon looping back.
                    if m.tag == tag && member != m.member_id {
                        let ep = SocketAddr::from((*src.ip(), port));
                        // Prefer the direct LAN path (overwrite any WAN endpoint). A LAN
                        // beacon is a same-segment direct reachability signal, so mark the
                        // direct path fresh too (docs/RELAY.md) — no need to relay a LAN peer.
                        let now = now_ms();
                        m.links.lock().unwrap().insert(
                            member,
                            Link {
                                endpoint: ep,
                                last_seen_ms: now,
                                last_direct_ms: now,
                            },
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed_links;
    use std::collections::HashMap;
    use std::time::Duration;

    #[test]
    fn beacon_roundtrips() {
        let tag = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let b = beacon_encode(&tag, 7, 42003);
        assert_eq!(beacon_parse(&b), Some((tag, 7, 42003)));
        // Wrong magic / wrong length are rejected.
        assert_eq!(beacon_parse(b"XXXX...."), None);
        assert_eq!(beacon_parse(&b[..14]), None);
    }

    #[test]
    fn tag_is_stable_and_secret_dependent() {
        let a = lattice_mesh::crypto::lan_tag(&[9u8; 32]);
        let b = lattice_mesh::crypto::lan_tag(&[9u8; 32]);
        let c = lattice_mesh::crypto::lan_tag(&[10u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// Two runners on the same host (multicast loopback): B's beacon should seed A's
    /// link table with B's member id at B's advertised LAN port.
    ///
    /// Ignored by default: it depends on the OS actually delivering multicast loopback
    /// between two sockets, which the sandboxed CI runners (macOS especially) don't do
    /// reliably. Run locally with `cargo test -p lattice-meshrun -- --ignored`; the
    /// wire format + tag derivation are covered by the deterministic tests above, and
    /// the live path is verified on real hardware (a beacon sniffed off the LAN).
    #[ignore = "needs real OS multicast loopback; flaky in CI — run locally with --ignored"]
    #[tokio::test]
    async fn beacon_seeds_a_same_mesh_peer() {
        let tag = lattice_mesh::crypto::lan_tag(&[42u8; 32]);
        let a_links = seed_links(HashMap::new());
        let b_links = seed_links(HashMap::new());
        let a_view = std::sync::Arc::clone(&a_links);

        // A is member 1 (dp port 42001); B is member 2 (dp port 42002), same tag.
        // `tag` is Copy so each `move` closure captures its own copy; the Arc is
        // cloned per call.
        let a_snap = move || {
            vec![LanMesh {
                tag,
                member_id: 1,
                dp_port: 42001,
                links: std::sync::Arc::clone(&a_links),
            }]
        };
        let b_snap = move || {
            vec![LanMesh {
                tag,
                member_id: 2,
                dp_port: 42002,
                links: std::sync::Arc::clone(&b_links),
            }]
        };
        tokio::spawn(run_lan_discovery(a_snap));
        tokio::spawn(run_lan_discovery(b_snap));

        // A should learn member 2 at its advertised port (the loopback IP varies, so
        // assert on the port + that an entry appeared).
        let learned = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(l) = a_view.lock().unwrap().get(&2u8) {
                    break l.endpoint;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("A never discovered B over the LAN beacon");
        assert_eq!(learned.port(), 42002);
    }
}

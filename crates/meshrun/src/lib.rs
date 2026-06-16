//! v2 data-plane runner (docs/DATA_PLANE.md P2): one loop tying a TUN, a transport,
//! and a mesh's [`MeshDataPlane`]. Outbound packets from the TUN are routed →
//! sealed → sent to the destination member's endpoint; inbound frames are opened
//! and written back to the TUN.
//!
//! The peer table ([`PeerLinks`]) and exit selection ([`SharedExit`]) are shared
//! handles: the loop updates a peer's endpoint + last-seen as frames arrive, and a
//! supervisor (the standalone binary, or `meshd`) reads them for live status and
//! writes the exit live. This is the seam P6.3c/d builds the daemon + GUI on.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use lattice_mesh::dataplane::{Inbound, MeshDataPlane};
use lattice_net::Transport;
use lattice_proto::wire_v2::MemberId;
use lattice_tun::TunDevice;

/// What we know about how to reach a peer, and when we last heard from it.
#[derive(Clone, Copy, Debug)]
pub struct Link {
    /// Where to send this peer's frames (seeded out-of-band, then kept fresh from
    /// the source address of inbound frames — peers roam / sit behind NAT).
    pub endpoint: SocketAddr,
    /// Unix-ms of the last frame received from this peer; 0 = never heard (a seed).
    pub last_seen_ms: u64,
}

/// The mesh's live peer table, shared between the run loop and its supervisor.
pub type PeerLinks = Arc<Mutex<HashMap<MemberId, Link>>>;

/// The member that internet-bound traffic egresses through (the exit). Shared so a
/// supervisor can change egress live (the GUI's egress toggle) without a respawn.
pub type SharedExit = Arc<Mutex<Option<MemberId>>>;

/// Unix epoch milliseconds (best-effort; 0 if the clock is before the epoch).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build a [`PeerLinks`] from seed endpoints (last_seen = 0 until they speak).
pub fn seed_links(endpoints: HashMap<MemberId, SocketAddr>) -> PeerLinks {
    let map = endpoints
        .into_iter()
        .map(|(m, endpoint)| {
            (
                m,
                Link {
                    endpoint,
                    last_seen_ms: 0,
                },
            )
        })
        .collect();
    Arc::new(Mutex::new(map))
}

/// The IPv4 destination of a raw IP packet (`TunDevice` yields raw IP — the macOS
/// AF header is stripped by `lattice-tun`). `None` if it isn't IPv4.
pub fn ipv4_dst(p: &[u8]) -> Option<Ipv4Addr> {
    if p.len() < 20 || (p[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(p[16], p[17], p[18], p[19]))
}

/// Run the data-plane loop until the TUN or transport closes. `links` maps a member
/// id → where to reach it + liveness (seeded out-of-band, learned thereafter);
/// `exit` is the egress member for non-mesh traffic (both shared, read/written live).
pub async fn run<X: Transport + 'static>(
    dp: MeshDataPlane,
    mut tun: Box<dyn TunDevice>,
    transport: X,
    links: PeerLinks,
    exit: SharedExit,
) {
    loop {
        tokio::select! {
            // App traffic out of the TUN → route to its member, else (internet-bound)
            // to the exit member, which NATs it out (P4; NAT is OS-side, exit.rs).
            outbound = tun.read_packet() => {
                let Ok(p) = outbound else { break };
                if let Some(dst) = ipv4_dst(&p) {
                    let member = dp.route(dst).or_else(|| *exit.lock().unwrap());
                    if let Some(member) = member {
                        let endpoint = links.lock().unwrap().get(&member).map(|l| l.endpoint);
                        if let Some(addr) = endpoint {
                            let _ = transport.send_to(&dp.seal_to(member, &p), addr).await;
                        }
                    }
                }
            }
            // A frame from a peer → open & deliver to the TUN, or relay it onward.
            inbound = transport.recv_from() => {
                let Ok((frame, from)) = inbound else { break };
                // Discovery + liveness: learn the sender's endpoint and stamp it, so
                // replies route back and the supervisor sees who's live (P6.3b/d).
                if let Some((hdr, _)) = lattice_proto::wire_v2::decode(&frame) {
                    links
                        .lock()
                        .unwrap()
                        .insert(hdr.src, Link { endpoint: from, last_seen_ms: now_ms() });
                }
                match dp.recv(&frame) {
                    Some(Inbound::Deliver(inner)) => { let _ = tun.write_packet(&inner).await; }
                    // P5 relay: we're a hop, not the destination — pass the frame on
                    // unchanged (we don't need to decrypt to forward).
                    Some(Inbound::Forward { to }) => {
                        let endpoint = links.lock().unwrap().get(&to).map(|l| l.endpoint);
                        if let Some(addr) = endpoint {
                            let _ = transport.send_to(&frame, addr).await;
                        }
                    }
                    None => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use lattice_mesh::crypto::suite;
    use lattice_net::memory::duplex;
    use lattice_tun::memory::MemoryTun;

    fn dp(my_id: MemberId) -> MeshDataPlane {
        // Mesh 3, overlay prefix 100.80, shared secret ⇒ same key for both nodes.
        MeshDataPlane::new(3, my_id, [100, 80], suite("default", &[42u8; 32], 0))
    }

    fn exit(member: Option<MemberId>) -> SharedExit {
        Arc::new(Mutex::new(member))
    }

    fn ipv4_to(dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; 28]; // 20B IPv4 header + 8B payload
        p[0] = 0x45; // v4, ihl 5
        p[16..20].copy_from_slice(&dst.octets());
        p[20..].copy_from_slice(b"ping-pkt");
        p
    }

    #[tokio::test]
    async fn two_nodes_in_mesh_packet_flows_end_to_end() {
        let a_addr: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b_addr: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let (ta, tb) = duplex(a_addr, b_addr);
        let (atun, ahandle) = MemoryTun::new();
        let (btun, mut bhandle) = MemoryTun::new();

        let a_eps = seed_links(std::iter::once((2u8, b_addr)).collect());
        let b_eps = seed_links(std::iter::once((1u8, a_addr)).collect());

        tokio::spawn(run(dp(1), Box::new(atun), ta, a_eps, exit(None))); // Alice (member 1)
        tokio::spawn(run(dp(2), Box::new(btun), tb, b_eps, exit(None))); // Bob   (member 2)

        // Inject an IP packet at Alice's TUN, destined for Bob's overlay IP.
        let packet = ipv4_to("100.80.3.2".parse().unwrap()); // mesh 3, member 2
        ahandle.inject.send(packet.clone()).await.unwrap();

        // It should come out of Bob's TUN, decrypted and intact.
        let got = tokio::time::timeout(Duration::from_secs(2), bhandle.observe.recv())
            .await
            .expect("timed out — packet did not cross the mesh")
            .expect("bob's tun closed");
        assert_eq!(got, packet);
    }

    #[tokio::test]
    async fn internet_bound_packet_is_routed_to_the_exit_member() {
        // Alice (member 1) sends all internet traffic via exit member 2 (Bob).
        let a_addr: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b_addr: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let (ta, tb) = duplex(a_addr, b_addr);
        let (atun, ahandle) = MemoryTun::new();
        let (btun, mut bhandle) = MemoryTun::new();

        let a_eps = seed_links(std::iter::once((2u8, b_addr)).collect());
        let b_eps = seed_links(std::iter::once((1u8, a_addr)).collect());

        tokio::spawn(run(dp(1), Box::new(atun), ta, a_eps, exit(Some(2)))); // exit = member 2
        tokio::spawn(run(dp(2), Box::new(btun), tb, b_eps, exit(None)));

        // A real internet destination (not in the mesh /24) → goes to the exit.
        let packet = ipv4_to("1.1.1.1".parse().unwrap());
        ahandle.inject.send(packet.clone()).await.unwrap();

        // The exit member receives the inner packet (it would then NAT it out).
        let got = tokio::time::timeout(Duration::from_secs(2), bhandle.observe.recv())
            .await
            .expect("timed out — internet packet did not reach the exit")
            .expect("exit tun closed");
        assert_eq!(got, packet);
    }

    /// A test-only in-memory N-node network: `send_to(addr)` delivers to whoever
    /// bound `addr`, so we can wire more than the point-to-point `duplex`.
    mod hub {
        use super::*;
        use tokio::sync::mpsc;

        type Inbox = mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>;

        #[derive(Clone, Default)]
        pub struct Hub(Arc<Mutex<std::collections::HashMap<SocketAddr, Inbox>>>);

        impl Hub {
            pub fn node(&self, addr: SocketAddr) -> Router {
                let (tx, rx) = mpsc::unbounded_channel();
                self.0.lock().unwrap().insert(addr, tx);
                Router {
                    me: addr,
                    hub: self.clone(),
                    rx: tokio::sync::Mutex::new(rx),
                }
            }
        }

        pub struct Router {
            me: SocketAddr,
            hub: Hub,
            rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
        }

        #[async_trait::async_trait]
        impl lattice_net::Transport for Router {
            async fn send_to(
                &self,
                data: &[u8],
                dest: SocketAddr,
            ) -> Result<(), lattice_net::NetError> {
                if let Some(tx) = self.hub.0.lock().unwrap().get(&dest) {
                    let _ = tx.send((data.to_vec(), self.me));
                }
                Ok(())
            }
            async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), lattice_net::NetError> {
                self.rx
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| lattice_net::NetError::Discovery("hub closed".into()))
            }
            fn local_addr(&self) -> Result<SocketAddr, lattice_net::NetError> {
                Ok(self.me)
            }
        }
    }

    #[tokio::test]
    async fn relay_forwards_a_frame_to_an_unreachable_member() {
        let net = hub::Hub::default();
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let c: SocketAddr = "10.0.0.3:3".parse().unwrap();
        let (atun, ahandle) = MemoryTun::new();
        let (btun, _bh) = MemoryTun::new();
        let (ctun, mut ch) = MemoryTun::new();

        // A reaches C only via the relay B; B reaches C directly.
        let a_eps = seed_links(std::iter::once((3u8, b)).collect());
        let b_eps = seed_links(std::iter::once((3u8, c)).collect());
        let c_eps = seed_links(HashMap::new());

        tokio::spawn(run(dp(1), Box::new(atun), net.node(a), a_eps, exit(None)));
        tokio::spawn(run(dp(2), Box::new(btun), net.node(b), b_eps, exit(None))); // relay hop
        tokio::spawn(run(dp(3), Box::new(ctun), net.node(c), c_eps, exit(None)));

        let packet = ipv4_to("100.80.3.3".parse().unwrap()); // member 3 = C
        ahandle.inject.send(packet.clone()).await.unwrap();

        let got = tokio::time::timeout(Duration::from_secs(2), ch.observe.recv())
            .await
            .expect("timed out — relayed packet did not reach C")
            .expect("c's tun closed");
        assert_eq!(got, packet);
    }
}

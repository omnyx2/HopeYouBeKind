//! v2 data-plane runner (docs/DATA_PLANE.md P2): one loop tying a TUN, a transport,
//! and a mesh's [`MeshDataPlane`]. Outbound packets from the TUN are routed →
//! sealed → sent to the destination member's endpoint; inbound frames are opened
//! and written back to the TUN.
//!
//! Phase 2: real packet flow between two nodes (out-of-band endpoints + shared
//! secret). Discovery, exit, and relay land in later phases.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use lattice_mesh::dataplane::{Inbound, MeshDataPlane};
use lattice_net::Transport;
use lattice_proto::wire_v2::MemberId;
use lattice_tun::TunDevice;

/// The IPv4 destination of a raw IP packet (`TunDevice` yields raw IP — the macOS
/// AF header is stripped by `lattice-tun`). `None` if it isn't IPv4.
pub fn ipv4_dst(p: &[u8]) -> Option<Ipv4Addr> {
    if p.len() < 20 || (p[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(p[16], p[17], p[18], p[19]))
}

/// Run the data-plane loop until the TUN or transport closes. `endpoints` maps a
/// member id → where to reach it (out-of-band in P2; discovery fills it later).
pub async fn run<X: Transport + 'static>(
    dp: MeshDataPlane,
    mut tun: Box<dyn TunDevice>,
    transport: X,
    endpoints: HashMap<MemberId, SocketAddr>,
) {
    loop {
        tokio::select! {
            // App traffic out of the TUN → route, seal, send to the member.
            outbound = tun.read_packet() => {
                let Ok(p) = outbound else { break };
                if let Some(dst) = ipv4_dst(&p) {
                    if let Some(member) = dp.route(dst) {
                        if let Some(addr) = endpoints.get(&member) {
                            let _ = transport.send_to(&dp.seal_to(member, &p), *addr).await;
                        }
                    }
                    // else: internet-bound — policy / exit lands in P4.
                }
            }
            // A frame from a peer → open, deliver to the TUN (or forward, later).
            inbound = transport.recv_from() => {
                let Ok((frame, _from)) = inbound else { break };
                if let Some(Inbound::Deliver(inner)) = dp.recv(&frame) {
                    let _ = tun.write_packet(&inner).await;
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

        let a_eps: HashMap<MemberId, SocketAddr> = std::iter::once((2u8, b_addr)).collect();
        let b_eps: HashMap<MemberId, SocketAddr> = std::iter::once((1u8, a_addr)).collect();

        tokio::spawn(run(dp(1), Box::new(atun), ta, a_eps)); // Alice (member 1)
        tokio::spawn(run(dp(2), Box::new(btun), tb, b_eps)); // Bob   (member 2)

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
}

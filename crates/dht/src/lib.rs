//! A Kademlia DHT for **serverless peer rendezvous**: a node publishes its
//! candidate addresses (LAN + STUN-reflexive) under its node id, and any other
//! node looks them up by id — no coordination server. This is the piece that
//! lets the NAT-traversal candidates from `lattice-net::nat` be exchanged across
//! the internet.
//!
//! The Kademlia algorithm (XOR distance, k-bucket routing, iterative lookup) is
//! implemented and tested here against an in-memory simulated network. A UDP
//! transport is provided for production; wiring the daemon to run a DHT server
//! loop and bootstrap against public nodes is the remaining integration (see
//! ROADMAP).

pub mod distance;
pub mod node;
pub mod routing;
pub mod rpc;
pub mod server;

pub use distance::Key;
pub use node::{Kademlia, KademliaNode, KademliaTransport, ALPHA};
pub use routing::{Contact, RoutingTable, K};
pub use rpc::Message;
pub use server::DhtNode;

use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

/// UDP-backed transport.
///
/// **Limitation:** this is single-flight (send, then await one reply on the
/// shared socket). It is correct for the sequential queries an iterative lookup
/// issues, but a production node that also *serves* requests needs a dispatcher
/// that correlates replies by a request id. That dispatcher is the remaining
/// integration work; the lookup algorithm above does not depend on it.
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    timeout: Duration,
}

impl UdpTransport {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            timeout: Duration::from_secs(2),
        }
    }
}

#[async_trait::async_trait]
impl KademliaTransport for UdpTransport {
    async fn query(&self, to: &Contact, msg: Message) -> Option<Message> {
        let bytes = bincode::serialize(&msg).ok()?;
        self.socket.send_to(&bytes, to.addr).await.ok()?;

        let mut buf = [0u8; 2048];
        let (n, _from) = tokio::time::timeout(self.timeout, self.socket.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        bincode::deserialize(&buf[..n]).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_net::nat::Rendezvous;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    /// Routes a query to the destination node's `handle`, in memory.
    #[derive(Default)]
    struct Switchboard {
        nodes: Mutex<HashMap<SocketAddr, Arc<Mutex<KademliaNode>>>>,
    }

    struct SimTransport {
        board: Arc<Switchboard>,
        from: Contact,
    }

    #[async_trait::async_trait]
    impl KademliaTransport for SimTransport {
        async fn query(&self, to: &Contact, msg: Message) -> Option<Message> {
            let target = self.board.nodes.lock().unwrap().get(&to.addr).cloned()?;
            let response = target.lock().unwrap().handle(msg, self.from.clone());
            Some(response)
        }
    }

    fn node_key(i: u8) -> Key {
        let mut k = [0u8; 32];
        k[0] = i;
        k
    }

    fn node_addr(i: u8) -> SocketAddr {
        format!("127.0.0.1:{}", 9000 + i as u16).parse().unwrap()
    }

    /// Build N nodes wired through a shared in-memory switchboard, each
    /// bootstrapped against node 0 (which knows everyone — a directory).
    async fn build_network(n: u8) -> Vec<Kademlia> {
        let board = Arc::new(Switchboard::default());
        let mut kads = Vec::new();

        for i in 1..=n {
            let id = node_key(i);
            let transport = Arc::new(SimTransport {
                board: Arc::clone(&board),
                from: Contact::new(id, node_addr(i)),
            });
            let kad = Kademlia::new(id, transport);
            board.nodes.lock().unwrap().insert(node_addr(i), kad.node());
            kads.push(kad);
        }

        let node0_contact = Contact::new(node_key(1), node_addr(1));
        // Node 0 (index 0, id 1) learns everyone; everyone else learns node 0.
        let all: Vec<Contact> = (1..=n)
            .map(|i| Contact::new(node_key(i), node_addr(i)))
            .collect();
        kads[0].bootstrap(&all).await;
        for kad in kads.iter().skip(1) {
            kad.bootstrap(&[node0_contact.clone()]).await;
        }
        kads
    }

    #[tokio::test]
    async fn publish_then_lookup_finds_candidates_across_the_dht() {
        // 40 nodes > K (20): the record is stored on a subset, so lookup must
        // actually route to find it rather than reading it off the bootstrap.
        let kads = build_network(40).await;

        let key = node_key(23);
        let candidates: Vec<SocketAddr> = vec![
            "203.0.113.23:51820".parse().unwrap(),
            "10.0.0.23:51820".parse().unwrap(),
        ];

        // Publish from one node...
        kads[5].publish(key, &candidates).await.unwrap();

        // ...and look it up from a different, distant node.
        let found = kads[30].lookup(key).await.unwrap();
        assert_eq!(
            found, candidates,
            "candidates must be retrievable by node id"
        );
    }

    #[tokio::test]
    async fn lookup_of_unknown_key_returns_empty() {
        let kads = build_network(20).await;
        let missing = kads[3].lookup(node_key(200)).await.unwrap();
        assert!(missing.is_empty());
    }

    #[tokio::test]
    async fn find_node_converges_on_the_target_neighbourhood() {
        let kads = build_network(30).await;
        let target = node_key(17);
        let closest = kads[8].find_node(&target).await;
        // The node whose id *is* the target should be among the closest found.
        assert!(
            closest.iter().any(|c| c.id == target),
            "iterative find_node should reach the target's own node"
        );
    }
}

//! A real UDP DHT node: a background server loop that answers incoming requests
//! and a request-id-demuxing transport so concurrent lookups and served requests
//! share one socket correctly.
//!
//! Wire frame (one per UDP datagram):
//!
//! ```text
//!   0        1                9                          41
//!   +--------+----------------+--------------------------+----------------+
//!   |  kind  |  request_id u64|   sender node id (32)    | bincode(Message)|
//!   +--------+----------------+--------------------------+----------------+
//!   kind 0 = request, kind 1 = response
//! ```
//!
//! A request carries the sender's node id so the receiver can learn the contact;
//! the observed UDP source address is used as the contact address (NAT-correct).
//! A response echoes the request's id so the issuer can match it to its waiter.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use crate::distance::Key;
use crate::node::{KademliaNode, KademliaTransport};
use crate::routing::Contact;
use crate::rpc::Message;

const KIND_REQUEST: u8 = 0;
const KIND_RESPONSE: u8 = 1;
const HEADER_LEN: usize = 1 + 8 + 32;

/// A DHT node bound to a UDP socket: serves requests against shared node state
/// and issues request-id-matched queries.
pub struct DhtNode {
    self_id: Key,
    socket: Arc<UdpSocket>,
    node: Arc<Mutex<KademliaNode>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Message>>>,
    next_id: AtomicU64,
    timeout: Duration,
}

impl DhtNode {
    /// Wrap a socket and shared node state. `node` is the same `Arc` a
    /// [`crate::Kademlia`] is built on via `with_shared`.
    pub fn new(socket: Arc<UdpSocket>, node: Arc<Mutex<KademliaNode>>) -> Arc<Self> {
        let self_id = node.lock().unwrap().id();
        Arc::new(Self {
            self_id,
            socket,
            node,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            timeout: Duration::from_secs(2),
        })
    }

    /// Spawn the background receive loop. Returns immediately.
    pub fn spawn_server(self: &Arc<Self>) {
        let me = Arc::clone(self);
        tokio::spawn(async move { me.serve().await });
    }

    async fn serve(self: Arc<Self>) {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, from)) = self.socket.recv_from(&mut buf).await else {
                continue;
            };
            let Some((kind, id, sender_id, msg)) = decode(&buf[..n]) else {
                continue;
            };
            match kind {
                KIND_REQUEST => {
                    let from_contact = Contact::new(sender_id, from);
                    let response = self.node.lock().unwrap().handle(msg, from_contact);
                    let frame = encode(KIND_RESPONSE, id, &self.self_id, &response);
                    let _ = self.socket.send_to(&frame, from).await;
                }
                KIND_RESPONSE => {
                    // Learn the responder from its real id + observed address —
                    // this is what lets a node bootstrap from an address alone.
                    self.node
                        .lock()
                        .unwrap()
                        .learn(Contact::new(sender_id, from));
                    if let Some(tx) = self.pending.lock().unwrap().remove(&id) {
                        let _ = tx.send(msg);
                    }
                }
                _ => {}
            }
        }
    }
}

#[async_trait::async_trait]
impl KademliaTransport for DhtNode {
    async fn query(&self, to: &Contact, msg: Message) -> Option<Message> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);

        let frame = encode(KIND_REQUEST, id, &self.self_id, &msg);
        if self.socket.send_to(&frame, to.addr).await.is_err() {
            self.pending.lock().unwrap().remove(&id);
            return None;
        }

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(response)) => Some(response),
            _ => {
                self.pending.lock().unwrap().remove(&id);
                None
            }
        }
    }
}

fn encode(kind: u8, id: u64, sender: &Key, msg: &Message) -> Vec<u8> {
    let body = bincode::serialize(msg).unwrap_or_default();
    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    frame.push(kind);
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(sender);
    frame.extend_from_slice(&body);
    frame
}

fn decode(buf: &[u8]) -> Option<(u8, u64, Key, Message)> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let kind = buf[0];
    let id = u64::from_be_bytes(buf[1..9].try_into().ok()?);
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&buf[9..41]);
    let msg = bincode::deserialize(&buf[HEADER_LEN..]).ok()?;
    Some((kind, id, sender, msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Kademlia, KademliaNode};
    use lattice_net::nat::Rendezvous;
    use std::net::SocketAddr;

    async fn spawn_node(id_byte: u8) -> (Kademlia, SocketAddr) {
        let mut id = [0u8; 32];
        id[0] = id_byte;
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let node = Arc::new(Mutex::new(KademliaNode::new(id)));
        let dht = DhtNode::new(socket, Arc::clone(&node));
        dht.spawn_server();
        let kad = Kademlia::with_shared(node, dht);
        (kad, addr)
    }

    /// Three real DHT nodes on localhost UDP: bootstrap, publish on one, retrieve
    /// from another — exercising the request-id demux over the wire.
    #[tokio::test]
    async fn publish_lookup_over_real_udp() {
        let (k1, a1) = spawn_node(1).await;
        let (k2, a2) = spawn_node(2).await;
        let (k3, a3) = spawn_node(3).await;

        let c1 = Contact::new(k1.id(), a1);
        // Everyone bootstraps off node 1; node 1 learns the others.
        k1.bootstrap(&[Contact::new(k2.id(), a2), Contact::new(k3.id(), a3)])
            .await;
        k2.bootstrap(&[c1.clone()]).await;
        k3.bootstrap(&[c1.clone()]).await;

        let mut key = [0u8; 32];
        key[0] = 2;
        let candidates: Vec<SocketAddr> = vec!["203.0.113.2:51820".parse().unwrap()];

        k2.publish(key, &candidates).await.unwrap();
        let found = k3.lookup(key).await.unwrap();
        assert_eq!(
            found, candidates,
            "retrieved over real UDP via request-id demux"
        );
    }

    /// A one-shot bootstrap is fragile: if the bootstrap node restarts it returns
    /// with an empty routing table and the ring silently breaks. The daemon's
    /// periodic re-bootstrap must heal it. Here the seed "restarts" (same address,
    /// emptied buckets); a member re-bootstrapping against it re-teaches it the
    /// ring, and a fresh joiner resolves a published value through it once more.
    #[tokio::test]
    async fn rebootstrap_heals_ring_after_bootstrap_restart() {
        let (k1, a1) = spawn_node(1).await; // seed / bootstrap node
        let (k2, _a2) = spawn_node(2).await; // member
        k2.bootstrap_addrs(&[a1]).await; // join; the seed learns k2

        let mut key = [0u8; 32];
        key[0] = 2;
        let cands: Vec<SocketAddr> = vec!["203.0.113.2:51820".parse().unwrap()];
        k2.publish(key, &cands).await.unwrap();

        // A late joiner resolves the value through the healthy seed.
        let (k3, _a3) = spawn_node(3).await;
        k3.bootstrap_addrs(&[a1]).await;
        assert_eq!(
            k3.lookup(key).await.unwrap(),
            cands,
            "resolves while the ring is healthy"
        );

        // The seed restarts: same address, empty routing table — it now knows nobody.
        k1.node().lock().unwrap().reset_routing();

        // Periodic re-bootstrap heals it: the member re-pings the seed (re-teaching
        // it the member) and republishes; a brand-new joiner then resolves again.
        k2.bootstrap_addrs(&[a1]).await;
        k2.publish(key, &cands).await.unwrap();
        let (k4, _a4) = spawn_node(4).await;
        k4.bootstrap_addrs(&[a1]).await;
        assert_eq!(
            k4.lookup(key).await.unwrap(),
            cands,
            "ring healed after re-bootstrap"
        );
    }
}

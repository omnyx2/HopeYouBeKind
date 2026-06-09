//! The Kademlia node: local state (routing table + value store) plus request
//! handling, and the iterative lookup that drives `Rendezvous`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::distance::{by_distance, Key};
use crate::routing::{Contact, RoutingTable, K};
use crate::rpc::Message;

/// Parallelism of an iterative lookup (Kademlia's α).
pub const ALPHA: usize = 3;

/// One DHT node's local state. `handle` processes an incoming request and
/// returns the response, learning the sender along the way.
pub struct KademliaNode {
    id: Key,
    table: RoutingTable,
    store: HashMap<Key, Vec<SocketAddr>>,
}

impl KademliaNode {
    pub fn new(id: Key) -> Self {
        Self {
            id,
            table: RoutingTable::new(id),
            store: HashMap::new(),
        }
    }

    pub fn id(&self) -> Key {
        self.id
    }

    pub fn learn(&mut self, contact: Contact) {
        self.table.insert(contact);
    }

    pub fn closest(&self, target: &Key, count: usize) -> Vec<Contact> {
        self.table.closest(target, count)
    }

    /// Process a request from `from`, returning the response.
    pub fn handle(&mut self, msg: Message, from: Contact) -> Message {
        self.table.insert(from);
        match msg {
            Message::Ping => Message::Pong,
            Message::FindNode { target } => Message::Nodes {
                contacts: self.table.closest(&target, K),
            },
            Message::FindValue { key } => match self.store.get(&key) {
                Some(addrs) => Message::Value {
                    addrs: addrs.clone(),
                },
                None => Message::Nodes {
                    contacts: self.table.closest(&key, K),
                },
            },
            Message::Store { key, addrs } => {
                self.store.insert(key, addrs);
                Message::Stored
            }
            // Responses are not valid requests; answer with a harmless Pong.
            Message::Pong | Message::Nodes { .. } | Message::Value { .. } | Message::Stored => {
                Message::Pong
            }
        }
    }
}

/// How a node sends a request to a peer and awaits its reply. The UDP transport
/// implements this in production; tests use an in-memory bus.
#[async_trait::async_trait]
pub trait KademliaTransport: Send + Sync {
    async fn query(&self, to: &Contact, msg: Message) -> Option<Message>;
}

/// A running Kademlia participant: local node state + a transport to reach
/// peers. Implements [`lattice_net::nat::Rendezvous`].
pub struct Kademlia {
    node: Arc<Mutex<KademliaNode>>,
    transport: Arc<dyn KademliaTransport>,
}

impl Kademlia {
    pub fn new(id: Key, transport: Arc<dyn KademliaTransport>) -> Self {
        Self {
            node: Arc::new(Mutex::new(KademliaNode::new(id))),
            transport,
        }
    }

    /// Share the underlying node so a server loop can `handle` incoming requests
    /// against the same state the lookups use.
    pub fn node(&self) -> Arc<Mutex<KademliaNode>> {
        Arc::clone(&self.node)
    }

    /// Seed the routing table with known contacts, then run a self-lookup so the
    /// network learns about us and we fill our buckets.
    pub async fn bootstrap(&self, seeds: &[Contact]) {
        {
            let mut node = self.node.lock().unwrap();
            for c in seeds {
                node.learn(c.clone());
            }
        }
        let id = self.id();
        let _ = self.iterative(&id, false).await;
    }

    pub fn id(&self) -> Key {
        self.node.lock().unwrap().id()
    }

    /// The core Kademlia node lookup. Queries progressively closer nodes until it
    /// either finds the value (`want_value`) or can get no closer. Returns the
    /// value (if found) and the closest contacts discovered.
    async fn iterative(
        &self,
        key: &Key,
        want_value: bool,
    ) -> (Option<Vec<SocketAddr>>, Vec<Contact>) {
        let mut shortlist: Vec<Contact> = self.node.lock().unwrap().closest(key, K);
        let mut queried: HashSet<Key> = HashSet::new();

        loop {
            // The α closest contacts we haven't queried yet.
            let batch: Vec<Contact> = shortlist
                .iter()
                .filter(|c| !queried.contains(&c.id))
                .take(ALPHA)
                .cloned()
                .collect();
            if batch.is_empty() {
                break;
            }

            for contact in &batch {
                queried.insert(contact.id);
                let request = if want_value {
                    Message::FindValue { key: *key }
                } else {
                    Message::FindNode { target: *key }
                };
                let Some(response) = self.transport.query(contact, request).await else {
                    continue; // unreachable / timed out
                };
                match response {
                    Message::Value { addrs } if want_value => {
                        return (Some(addrs), shortlist);
                    }
                    Message::Nodes { contacts } => {
                        let mut node = self.node.lock().unwrap();
                        for nc in contacts {
                            node.learn(nc.clone());
                            if !shortlist.iter().any(|c| c.id == nc.id) {
                                shortlist.push(nc);
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Keep the k closest candidates and continue toward the target.
            shortlist.sort_by(|a, b| by_distance(key, &a.id, &b.id));
            shortlist.truncate(K);
        }

        (None, shortlist)
    }

    /// Locate the contacts closest to `key` across the network.
    pub async fn find_node(&self, key: &Key) -> Vec<Contact> {
        self.iterative(key, false).await.1
    }
}

#[async_trait::async_trait]
impl lattice_net::nat::Rendezvous for Kademlia {
    async fn publish(
        &self,
        node_id: [u8; 32],
        candidates: &[SocketAddr],
    ) -> Result<(), lattice_net::NetError> {
        // Store on the k closest nodes to the key (and locally).
        let targets = self.find_node(&node_id).await;
        {
            let mut node = self.node.lock().unwrap();
            let self_contact = Contact::new(node.id(), "0.0.0.0:0".parse().unwrap());
            node.handle(
                Message::Store {
                    key: node_id,
                    addrs: candidates.to_vec(),
                },
                self_contact,
            );
        }
        for contact in targets {
            let _ = self
                .transport
                .query(
                    &contact,
                    Message::Store {
                        key: node_id,
                        addrs: candidates.to_vec(),
                    },
                )
                .await;
        }
        Ok(())
    }

    async fn lookup(&self, node_id: [u8; 32]) -> Result<Vec<SocketAddr>, lattice_net::NetError> {
        Ok(self.iterative(&node_id, true).await.0.unwrap_or_default())
    }
}

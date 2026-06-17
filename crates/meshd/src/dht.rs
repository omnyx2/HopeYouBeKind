//! Node-wide DHT rendezvous (docs/DHT_RENDEZVOUS.md) — **on by default; `MESHD_DHT=0` opts out**.
//!
//! Re-finds a peer whose address changed with **no overlapping live window** — the
//! gap that first-contact discovery (P-D1..P-D4) cannot cover. A Kademlia overlay
//! (reused wholesale from `lattice-dht`) stores **signed [`EndpointRecord`]s** keyed
//! by member public key. The DHT nodes hold opaque bytes and are never trusted; only
//! the *reader* verifies — the record's own signature (`EndpointRecord::verify`) plus
//! a `network`/`member` match and a newer `seq` (`EndpointBook::observe`). So a hostile
//! DHT node can withhold or return stale records (availability) but **cannot forge an
//! endpoint** (integrity). If the DHT is empty/unreachable, behaviour is exactly the
//! pre-DHT first-contact discovery — a returned record can only *improve* state.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use lattice_dht::{DhtNode, Kademlia, KademliaNode, KademliaTransport};
use lattice_mesh::discovery::EndpointRecord;
use lattice_mesh::membership::PubKey;
use tokio::net::UdpSocket;

/// The node-wide DHT rendezvous service: one Kademlia participant per machine,
/// serving + querying signed endpoint records for every mesh this node is in.
pub struct DhtService {
    kad: Kademlia,
}

impl DhtService {
    /// Bind the DHT socket, start its background server loop, and bootstrap off
    /// `seeds` (known peer endpoints — the always-on public node is the natural one).
    pub async fn start(bind: SocketAddr, seeds: Vec<SocketAddr>) -> anyhow::Result<Arc<Self>> {
        // The DHT node id governs only k-bucket placement, never identity (records are
        // self-authenticating), so a fresh random id per process is fine.
        let mut id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);

        let socket = Arc::new(UdpSocket::bind(bind).await?);
        let kn: Arc<Mutex<KademliaNode>> = Arc::new(Mutex::new(KademliaNode::new(id)));
        // One DhtNode is both the server (serves StoreRecord/FindRecord) and the
        // transport our own lookups go out on, sharing one routing table.
        let server = DhtNode::new(socket, Arc::clone(&kn));
        server.spawn_server();
        let transport: Arc<dyn KademliaTransport> = server;
        let kad = Kademlia::with_shared(kn, transport);
        if !seeds.is_empty() {
            kad.bootstrap_addrs(&seeds).await;
        }
        tracing::info!("dht: rendezvous live on {bind} ({} seed(s))", seeds.len());
        Ok(Arc::new(Self { kad }))
    }

    /// Publish our signed endpoint record, keyed by our member pubkey, so peers can
    /// re-find us after our address changes.
    pub async fn publish(&self, rec: &EndpointRecord) {
        match bincode::serialize(rec) {
            // The 32-byte member pubkey *is* the DHT key (unique per mesh membership).
            Ok(bytes) => self.kad.publish_record(rec.member, bytes).await,
            Err(e) => tracing::warn!("dht: serialize EndpointRecord failed: {e}"),
        }
    }

    /// Look up a peer's latest endpoint record by their member pubkey. Returns it
    /// only if it decodes AND its signature verifies for that exact member; the
    /// caller still gates on `network` match + newer `seq` via `EndpointBook::observe`.
    pub async fn lookup(&self, member: PubKey) -> Option<EndpointRecord> {
        let bytes = self.kad.get_record(member).await?;
        let rec: EndpointRecord = bincode::deserialize(&bytes).ok()?;
        (rec.verify() && rec.member == member).then_some(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_mesh::membership::MemberKey;

    /// Two DHT services on loopback: B bootstraps off A, A publishes its record,
    /// B looks it up by pubkey and the signed record verifies end-to-end.
    #[tokio::test]
    async fn publish_then_lookup_across_two_nodes() {
        let a_addr: SocketAddr = "127.0.0.1:45901".parse().unwrap();
        let b_addr: SocketAddr = "127.0.0.1:45902".parse().unwrap();
        let a = DhtService::start(a_addr, vec![]).await.unwrap();
        let b = DhtService::start(b_addr, vec![a_addr]).await.unwrap();

        let net: PubKey = [7u8; 32];
        let alice = MemberKey::from_seed(&[2u8; 32]);
        let rec = alice.publish_endpoints(net, vec!["203.0.113.5:42000".parse().unwrap()], 1, 1000);
        a.publish(&rec).await;

        let got = b.lookup(alice.pubkey()).await;
        assert!(
            got.is_some(),
            "B should re-discover A's published record via the DHT"
        );
        let got = got.unwrap();
        assert!(got.verify());
        assert_eq!(got.endpoints, rec.endpoints);
        assert_eq!(got.member, alice.pubkey());

        // A pubkey nobody published for returns nothing (never a forged endpoint).
        assert!(b.lookup([99u8; 32]).await.is_none());
    }
}

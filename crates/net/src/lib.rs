//! Transport (carry ciphertext over UDP) and serverless discovery (find peers
//! without a central server).
//!
//! - [`Transport`] is the abstraction the engine sends/receives encrypted
//!   datagrams over; [`udp::UdpTransport`] is the real implementation.
//! - [`Discovery`] surfaces peers as they are found. LAN discovery uses mDNS
//!   ([`discovery::MdnsDiscovery`]); WAN DHT + NAT hole-punching is roadmap.

use std::net::SocketAddr;

use lattice_proto::NodeId;

pub mod nat;
pub mod relay;

#[derive(thiserror::Error, Debug)]
pub enum NetError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("discovery error: {0}")]
    Discovery(String),
}

/// Sends and receives raw datagrams. The payloads are opaque here — encryption
/// happens in `lattice-crypto` before send and after recv.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<(), NetError>;
    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), NetError>;
    fn local_addr(&self) -> Result<SocketAddr, NetError>;
}

/// Lets an `Arc<Transport>` be used where a `Transport` is expected — so the
/// daemon can share one transport between the engine and a background task
/// (e.g. relay registration).
#[async_trait::async_trait]
impl<T: Transport> Transport for std::sync::Arc<T> {
    async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<(), NetError> {
        (**self).send_to(data, dest).await
    }
    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), NetError> {
        (**self).recv_from().await
    }
    fn local_addr(&self) -> Result<SocketAddr, NetError> {
        (**self).local_addr()
    }
}

/// A peer learned from discovery: who they are and where to reach them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub id: NodeId,
    pub endpoints: Vec<SocketAddr>,
}

/// Yields peers as they are discovered. Serverless by construction.
#[async_trait::async_trait]
pub trait Discovery: Send {
    async fn next_peer(&mut self) -> Option<DiscoveredPeer>;
}

pub mod udp {
    use super::*;
    use tokio::net::UdpSocket;

    /// Real UDP transport over a single bound socket.
    pub struct UdpTransport {
        socket: UdpSocket,
    }

    impl UdpTransport {
        /// Bind to the given local address (use port 0 to let the OS pick).
        pub async fn bind(addr: SocketAddr) -> Result<Self, NetError> {
            let socket = UdpSocket::bind(addr).await?;
            Ok(Self { socket })
        }
    }

    #[async_trait::async_trait]
    impl Transport for UdpTransport {
        async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<(), NetError> {
            self.socket.send_to(data, dest).await?;
            Ok(())
        }

        async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), NetError> {
            let mut buf = vec![0u8; 1500];
            let (n, from) = self.socket.recv_from(&mut buf).await?;
            buf.truncate(n);
            Ok((buf, from))
        }

        fn local_addr(&self) -> Result<SocketAddr, NetError> {
            Ok(self.socket.local_addr()?)
        }
    }
}

pub mod discovery {
    use super::*;
    use lattice_proto::NodeId;
    use tokio::sync::mpsc;

    /// mDNS service type all Lattice nodes advertise and browse for.
    const SERVICE_TYPE: &str = "_lattice._udp.local.";

    /// Serverless LAN discovery over mDNS. Advertises this node (its public key
    /// in a TXT record + its UDP port) under `_lattice._udp.local` and browses
    /// for other nodes, surfacing each as a [`DiscoveredPeer`].
    pub struct MdnsDiscovery {
        _daemon: mdns_sd::ServiceDaemon,
        rx: mpsc::Receiver<DiscoveredPeer>,
    }

    impl MdnsDiscovery {
        /// `public_key` is the node identity (also its NodeId); `port` is the
        /// UDP transport port peers should dial.
        pub fn new(public_key: &[u8], port: u16) -> Result<Self, NetError> {
            let daemon =
                mdns_sd::ServiceDaemon::new().map_err(|e| NetError::Discovery(e.to_string()))?;

            let pk_hex = to_hex(public_key);
            let instance = &pk_hex[..pk_hex.len().min(12)];
            let host = format!("{instance}.local.");

            // Advertise ourselves. `enable_addr_auto` lets the daemon fill in our
            // LAN addresses; the TXT "pk" carries our full identity.
            let props = [("pk", pk_hex.as_str())];
            let service =
                mdns_sd::ServiceInfo::new(SERVICE_TYPE, instance, &host, "", port, &props[..])
                    .map_err(|e| NetError::Discovery(e.to_string()))?
                    .enable_addr_auto();
            daemon
                .register(service)
                .map_err(|e| NetError::Discovery(e.to_string()))?;

            // Browse for peers. mdns-sd's event channel is blocking, so we drain
            // it on a dedicated thread and forward parsed peers to an async queue.
            let events = daemon
                .browse(SERVICE_TYPE)
                .map_err(|e| NetError::Discovery(e.to_string()))?;
            let (tx, rx) = mpsc::channel(64);
            let own = pk_hex;
            std::thread::spawn(move || {
                while let Ok(event) = events.recv() {
                    if let mdns_sd::ServiceEvent::ServiceResolved(info) = event {
                        if let Some(peer) = resolve_peer(&info, &own) {
                            if tx.blocking_send(peer).is_err() {
                                break; // discovery dropped
                            }
                        }
                    }
                }
            });

            Ok(Self {
                _daemon: daemon,
                rx,
            })
        }
    }

    /// Turn a resolved mDNS service into a peer, skipping our own advertisement.
    fn resolve_peer(info: &mdns_sd::ServiceInfo, own_pk: &str) -> Option<DiscoveredPeer> {
        let pk_hex = info.get_property_val_str("pk")?;
        if pk_hex.eq_ignore_ascii_case(own_pk) {
            return None; // that's us
        }
        let pk = from_hex(pk_hex)?;
        if pk.len() != 32 {
            return None;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&pk);

        let port = info.get_port();
        // Our transport binds IPv4 (0.0.0.0), so skip IPv6 candidates — sending
        // to one from an IPv4 socket fails with EINVAL, and link-local fe80::
        // addresses are unusable without a scope id anyway.
        let endpoints: Vec<SocketAddr> = info
            .get_addresses()
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        if endpoints.is_empty() {
            return None;
        }
        Some(DiscoveredPeer {
            id: NodeId(id),
            endpoints,
        })
    }

    fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn from_hex(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }

    #[async_trait::async_trait]
    impl Discovery for MdnsDiscovery {
        async fn next_peer(&mut self) -> Option<DiscoveredPeer> {
            self.rx.recv().await
        }
    }

    /// A fixed peer list — for tests and for manually pinning peers.
    pub struct StaticDiscovery {
        peers: std::vec::IntoIter<DiscoveredPeer>,
    }

    impl StaticDiscovery {
        pub fn new(peers: Vec<DiscoveredPeer>) -> Self {
            Self {
                peers: peers.into_iter(),
            }
        }
    }

    #[async_trait::async_trait]
    impl Discovery for StaticDiscovery {
        async fn next_peer(&mut self) -> Option<DiscoveredPeer> {
            self.peers.next()
        }
    }

    /// A discovery source fed from a channel. Lets the daemon merge several
    /// sources — mDNS on the LAN, DHT lookups across the internet — into the one
    /// stream the engine consumes.
    pub struct ChannelDiscovery {
        rx: mpsc::Receiver<DiscoveredPeer>,
    }

    impl ChannelDiscovery {
        pub fn new() -> (mpsc::Sender<DiscoveredPeer>, Self) {
            let (tx, rx) = mpsc::channel(64);
            (tx, Self { rx })
        }
    }

    #[async_trait::async_trait]
    impl Discovery for ChannelDiscovery {
        async fn next_peer(&mut self) -> Option<DiscoveredPeer> {
            self.rx.recv().await
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn hex_round_trips() {
            let bytes = [0x00u8, 0x9b, 0xff, 0x10];
            assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
            assert!(from_hex("xyz").is_none());
        }
    }
}

pub mod memory {
    //! In-memory point-to-point transport for tests: a wired pair where each
    //! side's `send_to` lands in the other's `recv_from`, stamped with the
    //! sender's address. Lets the engine's packet loop be tested with no sockets.
    use super::*;
    use tokio::sync::{mpsc, Mutex};

    pub struct MemoryTransport {
        local: SocketAddr,
        tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
        rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    }

    /// Create two transports wired to each other.
    pub fn duplex(a: SocketAddr, b: SocketAddr) -> (MemoryTransport, MemoryTransport) {
        let (tx_ab, rx_ab) = mpsc::channel(64);
        let (tx_ba, rx_ba) = mpsc::channel(64);
        (
            MemoryTransport {
                local: a,
                tx: tx_ab,
                rx: Mutex::new(rx_ba),
            },
            MemoryTransport {
                local: b,
                tx: tx_ba,
                rx: Mutex::new(rx_ab),
            },
        )
    }

    #[async_trait::async_trait]
    impl Transport for MemoryTransport {
        async fn send_to(&self, data: &[u8], _dest: SocketAddr) -> Result<(), NetError> {
            // Point-to-point: destination is implicit; stamp our own address so
            // the receiver knows who sent it.
            self.tx
                .send((data.to_vec(), self.local))
                .await
                .map_err(|_| NetError::Discovery("memory transport closed".into()))
        }

        async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), NetError> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| NetError::Discovery("memory transport closed".into()))
        }

        fn local_addr(&self) -> Result<SocketAddr, NetError> {
            Ok(self.local)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_transport_round_trip() {
        let a = udp::UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b = udp::UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b_addr = b.local_addr().unwrap();

        a.send_to(b"hello", b_addr).await.unwrap();
        let (data, _from) = b.recv_from().await.unwrap();
        assert_eq!(&data, b"hello");
    }
}

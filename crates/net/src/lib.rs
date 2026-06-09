//! Transport (carry ciphertext over UDP) and serverless discovery (find peers
//! without a central server).
//!
//! - [`Transport`] is the abstraction the engine sends/receives encrypted
//!   datagrams over; [`udp::UdpTransport`] is the real implementation.
//! - [`Discovery`] surfaces peers as they are found. LAN discovery uses mDNS
//!   ([`discovery::MdnsDiscovery`]); WAN DHT + NAT hole-punching is roadmap.

use std::net::SocketAddr;

use lattice_proto::NodeId;

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
    use tokio::sync::mpsc;

    /// mDNS-based LAN discovery. Advertises and browses `_lattice._udp.local`.
    /// The browse/resolve loop is filled in at v0.3; constructing the daemon is
    /// wired up now so the dependency and lifecycle are real.
    pub struct MdnsDiscovery {
        _daemon: mdns_sd::ServiceDaemon,
        rx: mpsc::Receiver<DiscoveredPeer>,
    }

    impl MdnsDiscovery {
        pub fn new() -> Result<Self, NetError> {
            let daemon =
                mdns_sd::ServiceDaemon::new().map_err(|e| NetError::Discovery(e.to_string()))?;
            // The (tx) side is handed to the browse task in v0.3.
            let (_tx, rx) = mpsc::channel(64);
            Ok(Self {
                _daemon: daemon,
                rx,
            })
        }
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

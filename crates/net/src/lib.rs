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

pub mod tcp {
    //! TCP transport: carries the same opaque datagrams as [`super::udp`] but over
    //! one connection per peer — a fallback for networks that block or throttle UDP
    //! (see `docs/MESH_V2.md` §6).
    //!
    //! TCP is connection-oriented, so it does not drop into the datagram
    //! [`Transport`] trait for free: an inbound connection's peer address is an
    //! ephemeral client port, useless as a reply target. So on connect the **dialer
    //! sends a one-frame hello announcing its own listening address**, and the
    //! acceptor keys the connection by that stable address. `recv_from` therefore
    //! always returns a peer's *listening* address, and a reply via
    //! `send_to(that_addr)` reuses the same connection (full duplex over one TCP
    //! stream). Datagrams are length-prefixed: `u16` big-endian length + bytes.
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, Mutex};

    /// Per-peer outbound queue of raw (unframed) payloads awaiting the socket.
    type Outbound = mpsc::Sender<Vec<u8>>;
    type Conns = Arc<Mutex<HashMap<SocketAddr, Outbound>>>;

    pub struct TcpTransport {
        local: SocketAddr,
        /// Peer *listening* address → its connection's outbound queue.
        conns: Conns,
        /// Inbound datagrams from every connection, tagged with the peer's
        /// listening address.
        rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
        tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    }

    impl TcpTransport {
        /// Bind a listening socket and start accepting peer connections.
        pub async fn bind(addr: SocketAddr) -> Result<Self, NetError> {
            let listener = TcpListener::bind(addr).await?;
            let local = listener.local_addr()?;
            let conns: Conns = Arc::new(Mutex::new(HashMap::new()));
            let (tx, rx) = mpsc::channel(1024);
            {
                let conns = Arc::clone(&conns);
                let tx = tx.clone();
                tokio::spawn(async move {
                    while let Ok((stream, _ephemeral)) = listener.accept().await {
                        tokio::spawn(serve_inbound(stream, Arc::clone(&conns), tx.clone()));
                    }
                });
            }
            Ok(Self {
                local,
                conns,
                rx: Mutex::new(rx),
                tx,
            })
        }
    }

    /// One inbound connection: the first frame is the dialer's hello (its listening
    /// address); the rest are datagrams. Register a reply queue keyed by that
    /// address so `send_to` can answer over the same stream.
    async fn serve_inbound(
        stream: TcpStream,
        conns: Conns,
        tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) {
        let (mut rd, wr) = stream.into_split();
        let peer: SocketAddr = match read_frame(&mut rd).await {
            Ok(hello) => match std::str::from_utf8(&hello)
                .ok()
                .and_then(|s| s.parse().ok())
            {
                Some(p) => p,
                None => return,
            },
            Err(_) => return,
        };
        // No hello back — the peer already knows our address, it dialed us.
        let (ctx, crx) = mpsc::channel::<Vec<u8>>(256);
        tokio::spawn(drive_writer(wr, None, crx));
        conns.lock().await.insert(peer, ctx);
        pump_reads(rd, peer, tx, conns).await;
    }

    /// Drain a per-connection outbound queue onto the socket, framing each payload.
    /// When `hello` is set (the dialer side) the listening address is announced
    /// first.
    async fn drive_writer(
        mut wr: OwnedWriteHalf,
        hello: Option<SocketAddr>,
        mut crx: mpsc::Receiver<Vec<u8>>,
    ) {
        if let Some(addr) = hello {
            if write_frame(&mut wr, addr.to_string().as_bytes())
                .await
                .is_err()
            {
                return;
            }
        }
        while let Some(buf) = crx.recv().await {
            if write_frame(&mut wr, &buf).await.is_err() {
                break;
            }
        }
    }

    /// Read frames off a connection and surface each as a datagram from `peer`'s
    /// listening address; drop the connection from the pool when it closes.
    async fn pump_reads(
        mut rd: OwnedReadHalf,
        peer: SocketAddr,
        tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
        conns: Conns,
    ) {
        loop {
            match read_frame(&mut rd).await {
                Ok(buf) => {
                    if tx.send((buf, peer)).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        conns.lock().await.remove(&peer);
    }

    async fn read_frame<R: AsyncReadExt + Unpin>(rd: &mut R) -> std::io::Result<Vec<u8>> {
        let mut len = [0u8; 2];
        rd.read_exact(&mut len).await?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        rd.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn write_frame<W: AsyncWriteExt + Unpin>(
        wr: &mut W,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let n: u16 = payload.len().try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large")
        })?;
        wr.write_all(&n.to_be_bytes()).await?;
        wr.write_all(payload).await?;
        wr.flush().await
    }

    #[async_trait::async_trait]
    impl Transport for TcpTransport {
        async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<(), NetError> {
            let closed = || NetError::Discovery("tcp peer connection closed".into());
            // Reuse an existing connection if we have one.
            if let Some(tx) = self.conns.lock().await.get(&dest).cloned() {
                return tx.send(data.to_vec()).await.map_err(|_| closed());
            }
            // Otherwise dial, announce our listening address, and register it.
            let (rd, wr) = TcpStream::connect(dest).await?.into_split();
            let (ctx, crx) = mpsc::channel::<Vec<u8>>(256);
            tokio::spawn(drive_writer(wr, Some(self.local), crx));
            tokio::spawn(pump_reads(
                rd,
                dest,
                self.tx.clone(),
                Arc::clone(&self.conns),
            ));
            // Race: a concurrent dial may have registered first — keep that one and
            // let ours close (its writer ends when this `ctx` drops).
            let tx = self.conns.lock().await.entry(dest).or_insert(ctx).clone();
            tx.send(data.to_vec()).await.map_err(|_| closed())
        }

        async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), NetError> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| NetError::Discovery("tcp transport closed".into()))
        }

        fn local_addr(&self) -> Result<SocketAddr, NetError> {
            Ok(self.local)
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

            // Advertise ourselves. We publish our real LAN IPv4 *explicitly*:
            // `enable_addr_auto` proved unreliable on hosts with many virtual
            // interfaces (e.g. a Mac with several utun devices), where it
            // published only IPv6 link-local — so peers had no usable address
            // and could never dial us. Fall back to addr_auto only if we can't
            // determine a v4. The TXT "pk" carries our full identity.
            let props = [("pk", pk_hex.as_str())];
            let service = match local_ipv4() {
                Some(ip) => {
                    let addr = ip.to_string();
                    mdns_sd::ServiceInfo::new(
                        SERVICE_TYPE,
                        instance,
                        &host,
                        addr.as_str(),
                        port,
                        &props[..],
                    )
                    .map_err(|e| NetError::Discovery(e.to_string()))?
                }
                None => {
                    mdns_sd::ServiceInfo::new(SERVICE_TYPE, instance, &host, "", port, &props[..])
                        .map_err(|e| NetError::Discovery(e.to_string()))?
                        .enable_addr_auto()
                }
            };
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

    /// Best-effort primary LAN IPv4: ask the OS which source address it would
    /// use to reach a public host. No packets are sent — a UDP `connect` just
    /// consults the routing table. We advertise this so peers have a reachable
    /// address even when interface auto-detection misfires.
    fn local_ipv4() -> Option<std::net::Ipv4Addr> {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.connect("8.8.8.8:80").ok()?;
        match sock.local_addr().ok()?.ip() {
            std::net::IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
            _ => None,
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
        // to one from an IPv4 socket fails with EINVAL, and fe80:: link-local
        // needs a scope id. Overlay (100.64/10) candidates are *kept* but de-
        // prioritised: a real address sorts first, and the engine's INIT dedup
        // stops a looping overlay handshake from clobbering a live session.
        let mut endpoints: Vec<SocketAddr> = info
            .get_addresses()
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        // Put non-overlay (physical) addresses first so the handshake uses them.
        endpoints.sort_by_key(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 100 && (64..=127).contains(&o[1])
            }
            _ => true,
        });
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

    #[tokio::test]
    async fn tcp_transport_round_trip_and_reply_reuses_connection() {
        let a = tcp::TcpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b = tcp::TcpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        a.send_to(b"hello", b_addr).await.unwrap();
        let (data, from) = b.recv_from().await.unwrap();
        assert_eq!(&data, b"hello");
        // `from` must be A's LISTENING address (via the hello), not an ephemeral
        // client port — so the reply below can reuse the connection.
        assert_eq!(from, a_addr);

        b.send_to(b"world", from).await.unwrap();
        let (data2, from2) = a.recv_from().await.unwrap();
        assert_eq!(&data2, b"world");
        assert_eq!(from2, b_addr);
    }

    #[tokio::test]
    async fn tcp_transport_framing_delimits_frames() {
        let a = tcp::TcpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b = tcp::TcpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b_addr = b.local_addr().unwrap();

        let big = vec![0xAB_u8; 1400];
        a.send_to(&big, b_addr).await.unwrap();
        let (data, _) = b.recv_from().await.unwrap();
        assert_eq!(data, big);

        // Back-to-back frames must not coalesce on the byte stream.
        a.send_to(b"one", b_addr).await.unwrap();
        a.send_to(b"two", b_addr).await.unwrap();
        let (d1, _) = b.recv_from().await.unwrap();
        let (d2, _) = b.recv_from().await.unwrap();
        assert_eq!(&d1, b"one");
        assert_eq!(&d2, b"two");
    }
}

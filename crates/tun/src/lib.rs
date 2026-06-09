//! The virtual network interface. The OS routes overlay-subnet packets into the
//! TUN device; we read raw IP packets from it and write replies back.
//!
//! The real per-OS devices (macOS utun, Linux /dev/net/tun, Windows Wintun) land
//! in later milestones (see ROADMAP). Today we define the `TunDevice` trait and
//! an in-memory implementation so the engine's packet loop is fully testable
//! without OS privileges or a real NIC.

use lattice_proto::VirtualIp;

#[cfg(target_os = "macos")]
mod macos;

#[derive(thiserror::Error, Debug)]
pub enum TunError {
    #[error("tun device closed")]
    Closed,
    #[error("io error: {0}")]
    Io(String),
    #[error("not supported on this platform yet")]
    Unsupported,
}

/// How to bring up a TUN device.
#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Address to assign the interface (this node's overlay IP).
    pub address: VirtualIp,
    /// Prefix length of the overlay subnet (e.g. 10 for `100.64.0.0/10`).
    pub prefix_len: u8,
    /// MTU; conservative default leaves room for tunnel framing + AEAD overhead.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            address: VirtualIp(std::net::Ipv4Addr::new(100, 64, 0, 1)),
            prefix_len: lattice_proto::OVERLAY_SUBNET.1,
            mtu: 1380,
        }
    }
}

/// A virtual NIC. `read_packet` yields one raw IP packet; `write_packet` injects
/// one back toward the local network stack.
#[async_trait::async_trait]
pub trait TunDevice: Send {
    async fn read_packet(&mut self) -> Result<Vec<u8>, TunError>;
    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError>;
}

/// Lets a boxed trait object be used wherever a `T: TunDevice` is expected
/// (e.g. the daemon, which opens the device dynamically per OS).
#[async_trait::async_trait]
impl TunDevice for Box<dyn TunDevice> {
    async fn read_packet(&mut self) -> Result<Vec<u8>, TunError> {
        (**self).read_packet().await
    }
    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
        (**self).write_packet(packet).await
    }
}

/// Open the platform-native TUN device. macOS (utun) is implemented; Linux and
/// Windows land in v0.5 (see ROADMAP).
#[cfg(target_os = "macos")]
pub async fn open(config: TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    Ok(Box::new(macos::MacTun::open(config).await?))
}

/// Open the platform-native TUN device. macOS (utun) is implemented; Linux and
/// Windows land in v0.5 (see ROADMAP).
#[cfg(not(target_os = "macos"))]
pub async fn open(_config: TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    Err(TunError::Unsupported)
}

/// In-memory TUN backed by channels — for tests. Packets "written" toward the
/// host can be observed, and packets can be "injected" as if the host sent them.
pub mod memory {
    use super::*;
    use tokio::sync::mpsc;

    pub struct MemoryTun {
        inbound_rx: mpsc::Receiver<Vec<u8>>,
        outbound_tx: mpsc::Sender<Vec<u8>>,
    }

    /// Handle for a test to drive the [`MemoryTun`] from the "host" side.
    pub struct MemoryTunHandle {
        pub inject: mpsc::Sender<Vec<u8>>,
        pub observe: mpsc::Receiver<Vec<u8>>,
    }

    impl MemoryTun {
        pub fn new() -> (Self, MemoryTunHandle) {
            let (inbound_tx, inbound_rx) = mpsc::channel(64);
            let (outbound_tx, outbound_rx) = mpsc::channel(64);
            (
                Self {
                    inbound_rx,
                    outbound_tx,
                },
                MemoryTunHandle {
                    inject: inbound_tx,
                    observe: outbound_rx,
                },
            )
        }
    }

    #[async_trait::async_trait]
    impl TunDevice for MemoryTun {
        async fn read_packet(&mut self) -> Result<Vec<u8>, TunError> {
            self.inbound_rx.recv().await.ok_or(TunError::Closed)
        }
        async fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
            self.outbound_tx
                .send(packet.to_vec())
                .await
                .map_err(|_| TunError::Closed)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn round_trips_packets_through_memory_tun() {
            let (mut tun, mut handle) = MemoryTun::new();
            handle.inject.send(vec![1, 2, 3]).await.unwrap();
            assert_eq!(tun.read_packet().await.unwrap(), vec![1, 2, 3]);

            tun.write_packet(&[4, 5, 6]).await.unwrap();
            assert_eq!(handle.observe.recv().await.unwrap(), vec![4, 5, 6]);
        }
    }
}

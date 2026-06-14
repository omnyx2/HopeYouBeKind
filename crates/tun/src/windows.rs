//! Windows TUN device via the [Wintun](https://www.wintun.net/) driver.
//!
//! Loads `wintun.dll`, creates a Wintun adapter, and drives its send/receive
//! rings. Wintun's API is blocking, so reads run on a blocking task. The adapter
//! address is assigned with `netsh`. Requires Administrator and `wintun.dll`
//! present next to the binary.

use std::process::Command;
use std::sync::Arc;

use crate::{TunConfig, TunDevice, TunError};

const ADAPTER_NAME: &str = "Lattice";

pub struct WinTun {
    // Keep the loaded library and adapter alive for the session's lifetime.
    // `wintun::Wintun` is already an `Arc` internally; the session we wrap so the
    // receive thread and `write_packet` can share it.
    _wintun: wintun::Wintun,
    _adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
    /// Inbound packets from the dedicated receive thread (see `open`).
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl WinTun {
    pub async fn open(config: TunConfig) -> Result<Self, TunError> {
        let wintun =
            unsafe { wintun::load() }.map_err(|e| TunError::Io(format!("load wintun.dll: {e}")))?;
        let adapter = wintun::Adapter::create(&wintun, ADAPTER_NAME, ADAPTER_NAME, None)
            .map_err(|e| TunError::Io(format!("create adapter: {e}")))?;
        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| TunError::Io(format!("start session: {e}")))?,
        );

        configure_interface(&config)?;

        // Wintun's `receive_blocking` blocks and is NOT safe to call concurrently.
        // The engine's `select!` cancels the `read_packet` future whenever another
        // branch fires, and the old code spawned a fresh blocking receive on each
        // poll — so cancelled receives piled up into concurrent calls that
        // eventually errored, breaking the engine loop and exiting the daemon a
        // few seconds after connecting. Instead, run receive in ONE dedicated
        // thread that forwards packets over a channel; `read_packet` just awaits
        // the channel, so dropping its future never starts a second receive.
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        let recv_session = Arc::clone(&session);
        std::thread::spawn(move || loop {
            match recv_session.receive_blocking() {
                Ok(packet) => {
                    if tx.blocking_send(packet.bytes().to_vec()).is_err() {
                        break; // engine dropped the receiver — shutting down
                    }
                }
                Err(_) => break, // session closed (adapter removed)
            }
        });

        Ok(Self {
            _wintun: wintun,
            _adapter: adapter,
            session,
            rx,
        })
    }
}

/// Assign the overlay address to the adapter via `netsh`.
fn configure_interface(config: &TunConfig) -> Result<(), TunError> {
    // /10 → mask 255.192.0.0.
    let mask = prefix_to_mask(config.prefix_len);
    let status = Command::new("netsh")
        .args([
            "interface",
            "ip",
            "set",
            "address",
            &format!("name={ADAPTER_NAME}"),
            "static",
            &config.address.to_string(),
            &mask,
        ])
        .status()
        .map_err(|e| TunError::Io(format!("spawn netsh: {e}")))?;
    if !status.success() {
        return Err(TunError::Io(format!("netsh set address failed: {status}")));
    }
    Ok(())
}

fn prefix_to_mask(prefix: u8) -> String {
    let bits: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    let o = bits.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

#[async_trait::async_trait]
impl TunDevice for WinTun {
    fn name(&self) -> Option<&str> {
        // The Wintun adapter name — needed so the daemon can install exit-node
        // routes against it (else `tun.name()` is None and SetExit can't route).
        Some(ADAPTER_NAME)
    }

    async fn read_packet(&mut self) -> Result<Vec<u8>, TunError> {
        // Cancellation-safe: just await the channel fed by the dedicated receive
        // thread (see `open`). A closed channel means the receive thread ended
        // (the adapter went away), so surface that as an error.
        self.rx
            .recv()
            .await
            .ok_or_else(|| TunError::Io("wintun receive thread ended".into()))
    }

    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
        let mut send = self
            .session
            .allocate_send_packet(packet.len() as u16)
            .map_err(|e| TunError::Io(format!("wintun allocate: {e}")))?;
        send.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(send);
        Ok(())
    }
}

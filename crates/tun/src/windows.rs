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
    // `wintun::Wintun` is already an `Arc` internally; the session we wrap so it
    // can be shared with the blocking read task.
    _wintun: wintun::Wintun,
    _adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
}

impl WinTun {
    pub async fn open(config: TunConfig) -> Result<Self, TunError> {
        let wintun =
            unsafe { wintun::load() }.map_err(|e| TunError::Io(format!("load wintun.dll: {e}")))?;
        let adapter = wintun::Adapter::create(&wintun, ADAPTER_NAME, ADAPTER_NAME, None)
            .map_err(|e| TunError::Io(format!("create adapter: {e}")))?;
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| TunError::Io(format!("start session: {e}")))?;

        configure_interface(&config)?;

        Ok(Self {
            _wintun: wintun,
            _adapter: adapter,
            session: Arc::new(session),
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
    async fn read_packet(&mut self) -> Result<Vec<u8>, TunError> {
        let session = Arc::clone(&self.session);
        // Wintun's receive is blocking; run it off the async runtime.
        tokio::task::spawn_blocking(move || match session.receive_blocking() {
            Ok(packet) => Ok(packet.bytes().to_vec()),
            Err(e) => Err(TunError::Io(format!("wintun receive: {e}"))),
        })
        .await
        .map_err(|e| TunError::Io(format!("read task: {e}")))?
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

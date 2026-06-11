//! Linux TUN device via `/dev/net/tun`.
//!
//! Open the clone device, `ioctl(TUNSETIFF, IFF_TUN | IFF_NO_PI)` to get a
//! `tunN` interface that carries bare IP packets (no per-packet header, unlike
//! macOS utun), then assign the address and route with `ip`. Needs root /
//! `CAP_NET_ADMIN`.

use std::ffi::{c_void, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

use tokio::io::unix::AsyncFd;

use crate::{TunConfig, TunDevice, TunError};

// From <linux/if_tun.h> / <net/if.h>.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

/// Minimal `struct ifreq` (40 bytes): name + flags are all TUNSETIFF needs.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16],
    flags: libc::c_short,
    _pad: [u8; 22],
}

fn last_err(context: &str) -> TunError {
    TunError::Io(format!("{context}: {}", io::Error::last_os_error()))
}

pub struct LinuxTun {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl LinuxTun {
    pub async fn open(config: TunConfig) -> Result<Self, TunError> {
        let path = CString::new("/dev/net/tun").expect("static path");
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        if raw < 0 {
            return Err(last_err("open(/dev/net/tun)"));
        }
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        let fd = owned.as_raw_fd();

        // Request a TUN interface carrying bare IP packets. Empty name → the
        // kernel assigns the next free tunN and writes it back into `req.name`.
        let mut req: IfReq = unsafe { std::mem::zeroed() };
        req.flags = IFF_TUN | IFF_NO_PI;
        // `ioctl`'s request arg is c_ulong on glibc but c_int on musl; `as _`
        // coerces our constant to whichever the target expects.
        if unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut req as *mut IfReq as *mut c_void) } < 0 {
            return Err(last_err("ioctl(TUNSETIFF)"));
        }

        let name = {
            let bytes: Vec<u8> = req
                .name
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            String::from_utf8_lossy(&bytes).to_string()
        };

        // Non-blocking so tokio can drive readiness.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(last_err("fcntl(O_NONBLOCK)"));
        }

        configure_interface(&name, &config)?;

        Ok(Self {
            fd: AsyncFd::new(owned).map_err(|e| TunError::Io(e.to_string()))?,
            name,
        })
    }
}

fn configure_interface(name: &str, config: &TunConfig) -> Result<(), TunError> {
    let cidr = format!("{}/{}", config.address, config.prefix_len);
    run(&["addr", "add", &cidr, "dev", name])?;
    run(&["link", "set", name, "up"])?;
    // Route the overlay subnet through this interface (non-fatal if it exists).
    let (net, prefix) = lattice_proto::OVERLAY_SUBNET;
    let _ = Command::new("ip")
        .args(["route", "add", &format!("{net}/{prefix}"), "dev", name])
        .status();
    Ok(())
}

fn run(args: &[&str]) -> Result<(), TunError> {
    let status = Command::new("ip")
        .args(args)
        .status()
        .map_err(|e| TunError::Io(format!("spawn ip: {e}")))?;
    if !status.success() {
        return Err(TunError::Io(format!(
            "`ip {}` failed: {status}",
            args.join(" ")
        )));
    }
    Ok(())
}

#[async_trait::async_trait]
impl TunDevice for LinuxTun {
    fn name(&self) -> Option<&str> {
        Some(&self.name)
    }

    async fn read_packet(&mut self) -> Result<Vec<u8>, TunError> {
        loop {
            let mut guard = self
                .fd
                .readable()
                .await
                .map_err(|e| TunError::Io(e.to_string()))?;
            let res = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let mut buf = vec![0u8; 1600];
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    buf.truncate(n as usize);
                    Ok(buf)
                }
            });
            match res {
                // IFF_NO_PI: bytes are a bare IP packet, no header to strip.
                Ok(Ok(buf)) => return Ok(buf),
                Ok(Err(e)) => return Err(TunError::Io(e.to_string())),
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
        loop {
            let mut guard = self
                .fd
                .writable()
                .await
                .map_err(|e| TunError::Io(e.to_string()))?;
            let res = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let n = unsafe { libc::write(fd, packet.as_ptr() as *const c_void, packet.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
            match res {
                Ok(r) => return r.map_err(|e| TunError::Io(e.to_string())),
                Err(_would_block) => continue,
            }
        }
    }
}

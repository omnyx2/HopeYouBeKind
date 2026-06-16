//! macOS `utun` device.
//!
//! A utun is created by opening a `PF_SYSTEM`/`SYSPROTO_CONTROL` socket and
//! connecting it to the kernel control named `com.apple.net.utun_control`. The
//! kernel hands back a `utunN` interface. Each datagram read/written carries a
//! 4-byte address-family header (network byte order) that we strip/prepend.
//!
//! Creating the interface and assigning its address require root — run the
//! daemon with `sudo`. This module compiles on macOS; the live path is exercised
//! with elevated privileges (see daemon).

use std::ffi::c_void;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

use tokio::io::unix::AsyncFd;

use crate::{TunConfig, TunDevice, TunError};

/// `getsockopt` option (level `SYSPROTO_CONTROL`) that returns the `utunN` name.
const UTUN_OPT_IFNAME: libc::c_int = 2;

fn last_err(context: &str) -> TunError {
    TunError::Io(format!("{context}: {}", io::Error::last_os_error()))
}

pub struct MacTun {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl MacTun {
    pub async fn open(config: TunConfig) -> Result<Self, TunError> {
        // 1. Open the system-control socket.
        let raw =
            unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if raw < 0 {
            return Err(last_err("socket(PF_SYSTEM)"));
        }
        // Own it immediately so any early return closes the fd.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        let fd = owned.as_raw_fd();

        // 2. Resolve the utun control id by name.
        let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
        let cname = b"com.apple.net.utun_control";
        for (i, b) in cname.iter().enumerate() {
            info.ctl_name[i] = *b as libc::c_char;
        }
        if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) } < 0 {
            return Err(last_err("ioctl(CTLIOCGINFO)"));
        }

        // 3. Connect to it (sc_unit = 0 lets the kernel pick the next free utun).
        let addr = libc::sockaddr_ctl {
            sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(last_err("connect(utun_control)"));
        }

        // 4. Read back the assigned interface name (utunN).
        let mut name_buf = [0u8; 64];
        let mut len = name_buf.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name_buf.as_mut_ptr() as *mut c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(last_err("getsockopt(UTUN_OPT_IFNAME)"));
        }
        let name = String::from_utf8_lossy(&name_buf[..len.saturating_sub(1) as usize]).to_string();

        // 5. Non-blocking so tokio can drive readiness.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(last_err("fcntl(O_NONBLOCK)"));
        }

        // 6. Assign the overlay address and route the overlay subnet here.
        configure_interface(&name, &config)?;

        tracing_name(&name);
        Ok(Self {
            fd: AsyncFd::new(owned).map_err(|e| TunError::Io(e.to_string()))?,
            name,
        })
    }
}

fn tracing_name(_name: &str) {
    // (Kept separate so the open() body stays readable; real logging is wired
    // by the daemon's tracing subscriber.)
}

/// Bring the interface up with its overlay address and route the overlay subnet.
fn configure_interface(name: &str, config: &TunConfig) -> Result<(), TunError> {
    let ip = config.address.to_string();
    let mtu = config.mtu.to_string();
    // utun is point-to-point: `ifconfig utunN <ip> <ip> mtu <mtu> up`.
    let status = Command::new("ifconfig")
        .args([name, &ip, &ip, "mtu", &mtu, "up"])
        .status()
        .map_err(|e| TunError::Io(format!("spawn ifconfig: {e}")))?;
    if !status.success() {
        return Err(TunError::Io(format!("ifconfig {name} failed: {status}")));
    }
    // Route THIS interface's own overlay subnet through it — derived from the
    // configured address + prefix, not a hard-coded range. utun's point-to-point
    // address only yields a host route, so the subnet route is required. (v1 passes
    // the 100.64/10 overlay with prefix 10, so it still gets its /10; v2 per-mesh
    // /24s like 10.99.3.0/24 now route correctly instead of leaking to the default
    // gateway.) Non-fatal if the route already exists.
    let net = subnet_base(config.address.0, config.prefix_len);
    let _ = Command::new("route")
        .args([
            "-q",
            "add",
            "-net",
            &format!("{net}/{}", config.prefix_len),
            "-interface",
            name,
        ])
        .status();
    Ok(())
}

/// Network base address for `ip`/`prefix` (e.g. 10.99.3.1/24 → 10.99.3.0).
fn subnet_base(ip: std::net::Ipv4Addr, prefix: u8) -> std::net::Ipv4Addr {
    let bits = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    std::net::Ipv4Addr::from(bits & mask)
}

#[async_trait::async_trait]
impl TunDevice for MacTun {
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
                Ok(Ok(buf)) => {
                    // Strip the 4-byte address-family header.
                    if buf.len() <= 4 {
                        continue;
                    }
                    return Ok(buf[4..].to_vec());
                }
                Ok(Err(e)) => return Err(TunError::Io(e.to_string())),
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
        // Prepend the 4-byte AF_INET (IPv4) header in network byte order.
        let mut framed = Vec::with_capacity(packet.len() + 4);
        framed.extend_from_slice(&[0, 0, 0, libc::AF_INET as u8]);
        framed.extend_from_slice(packet);

        loop {
            let mut guard = self
                .fd
                .writable()
                .await
                .map_err(|e| TunError::Io(e.to_string()))?;
            let res = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let n = unsafe { libc::write(fd, framed.as_ptr() as *const c_void, framed.len()) };
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

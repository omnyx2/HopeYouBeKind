//! `meshrun` — run the v2 data plane against a REAL TUN + UDP. Needs **root** (TUN
//! creation + the overlay route). Config via env vars:
//!
//! ```text
//! MESH_ID=3 MY_ID=1 PREFIX=100.80 SECRET=<64 hex> BIND=0.0.0.0:42001 \
//!   PEERS=2=192.168.0.5:42002 meshrun
//! ```
//!
//! Both nodes must share the same `SECRET` (out-of-band in P2) and `PREFIX`/mesh.
//! Then `ping 100.80.3.2` (member 2's overlay IP) flows over the mesh.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use lattice_mesh::crypto::suite;
use lattice_mesh::dataplane::MeshDataPlane;
use lattice_net::udp::UdpTransport;
use lattice_proto::wire_v2::{MemberId, MeshId};
use lattice_proto::VirtualIp;
use lattice_tun::{open, TunConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mesh: MeshId = env("MESH_ID")?.parse()?;
    let my: MemberId = env("MY_ID")?.parse()?;
    let prefix = parse_prefix(&env("PREFIX")?)?;
    let secret = parse_hex32(&env("SECRET")?)
        .ok_or_else(|| anyhow::anyhow!("SECRET must be 64 hex chars"))?;
    let bind: SocketAddr = env("BIND")?.parse()?;
    let endpoints = parse_peers(&std::env::var("PEERS").unwrap_or_default())?;
    // Optional: route internet-bound traffic via this member (the exit). The exit
    // node itself needs OS NAT + forwarding (reuse exit.rs at the live deploy).
    let exit: Option<MemberId> = std::env::var("EXIT").ok().and_then(|s| s.parse().ok());

    let overlay = Ipv4Addr::new(prefix[0], prefix[1], mesh, my);
    // Conservative overlay MTU. The sealed datagram = inner(≤MTU) + 29B (5B header
    // + 8B seq + 16B tag) + 28B IP/UDP. Keep it small enough to never need IP
    // fragmentation on a reduced-PMTU underlay (campus firewalls drop fragments,
    // which silently kills large packets like SSH's PQ KEX reply). 1280 mirrors
    // Tailscale's default. Override with MTU= if the path allows larger.
    let mtu: u16 = std::env::var("MTU")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1280);
    let tun = open(TunConfig {
        address: VirtualIp(overlay),
        prefix_len: 24,
        mtu,
    })
    .await?;
    eprintln!(
        "meshrun: mesh {mesh} member {my} overlay {overlay} iface {:?} bind {bind}",
        tun.name()
    );
    let transport = UdpTransport::bind(bind).await?;
    // If this node is the exit, NAT the mesh's overlay /24 out to the internet.
    if std::env::var("EXIT_NODE").as_deref() == Ok("1") {
        enable_exit_nat(prefix, mesh);
    }
    let dp = MeshDataPlane::new(mesh, my, prefix, suite("default", &secret, 0));
    let links = lattice_meshrun::seed_links(endpoints);
    let exit = std::sync::Arc::new(std::sync::Mutex::new(exit));
    // This node's own reachable address, advertised in the gossip (ADVERTISE= for a
    // public node; otherwise peers learn us from the frames we send).
    let advertise = std::env::var("ADVERTISE").ok().and_then(|s| s.parse().ok());
    lattice_meshrun::run(dp, tun, transport, links, exit, my, advertise).await;
    Ok(())
}

fn env(k: &str) -> anyhow::Result<String> {
    std::env::var(k).map_err(|_| anyhow::anyhow!("missing env {k}"))
}

/// Make this node an exit: forward + masquerade the mesh's overlay /24 out to the
/// real internet (Linux; reuses the v1 exit.rs recipe). macOS exit would use pf.
#[cfg(target_os = "linux")]
fn enable_exit_nat(prefix: [u8; 2], mesh: u8) {
    use std::process::Command;
    let cidr = format!("{}.{}.{}.0/24", prefix[0], prefix[1], mesh);
    let _ = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .status();
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            &cidr,
            "-j",
            "MASQUERADE",
        ])
        .status();
    // INSERT the forward-accepts at the TOP of FORWARD, not append. Distros like
    // Oracle/RHEL Linux ship a default `-A FORWARD -j REJECT`; appending would put
    // our ACCEPTs *after* that reject, so the overlay's exit traffic would be
    // dropped before it could be forwarded out. `-I FORWARD 1` jumps the queue.
    let _ = Command::new("iptables")
        .args(["-I", "FORWARD", "1", "-s", &cidr, "-j", "ACCEPT"])
        .status();
    let _ = Command::new("iptables")
        .args(["-I", "FORWARD", "1", "-d", &cidr, "-j", "ACCEPT"])
        .status();
    eprintln!("meshrun: exit NAT enabled for {cidr}");
}

#[cfg(not(target_os = "linux"))]
fn enable_exit_nat(_prefix: [u8; 2], _mesh: u8) {
    eprintln!("meshrun: exit NAT is implemented for Linux (the Oracle exit); skipped");
}

fn parse_prefix(s: &str) -> anyhow::Result<[u8; 2]> {
    let mut it = s.split('.');
    match (
        it.next().and_then(|x| x.parse().ok()),
        it.next().and_then(|x| x.parse().ok()),
    ) {
        (Some(a), Some(b)) => Ok([a, b]),
        _ => anyhow::bail!("PREFIX must be a.b (e.g. 100.80)"),
    }
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn parse_peers(s: &str) -> anyhow::Result<HashMap<MemberId, SocketAddr>> {
    let mut m = HashMap::new();
    for part in s.split(',').filter(|p| !p.is_empty()) {
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("PEERS item must be member=ip:port"))?;
        m.insert(k.trim().parse()?, v.trim().parse()?);
    }
    Ok(m)
}

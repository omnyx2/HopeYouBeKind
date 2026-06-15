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

    let overlay = Ipv4Addr::new(prefix[0], prefix[1], mesh, my);
    let tun = open(TunConfig {
        address: VirtualIp(overlay),
        prefix_len: 24,
        mtu: 1380,
    })
    .await?;
    eprintln!(
        "meshrun: mesh {mesh} member {my} overlay {overlay} iface {:?} bind {bind}",
        tun.name()
    );
    let transport = UdpTransport::bind(bind).await?;
    let dp = MeshDataPlane::new(mesh, my, prefix, suite("default", &secret, 0));
    lattice_meshrun::run(dp, tun, transport, endpoints).await;
    Ok(())
}

fn env(k: &str) -> anyhow::Result<String> {
    std::env::var(k).map_err(|_| anyhow::anyhow!("missing env {k}"))
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

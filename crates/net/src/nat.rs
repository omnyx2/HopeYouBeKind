//! NAT traversal: learn our public (reflexive) address via STUN, and open NAT
//! bindings toward a peer by UDP hole punching.
//!
//! Two nodes behind NATs cannot reach each other's private LAN addresses across
//! the internet. Each asks a STUN server "what address do you see me as?" to
//! learn its public `ip:port`, exchanges that candidate (via discovery), then
//! both fire probes at each other's candidates simultaneously so each NAT opens
//! an outbound binding the other's packets can ride back through.
//!
//! Implemented here: the STUN binding codec (RFC 5389, unit-tested),
//! [`reflexive_address`] (live query), and [`punch`] (probe a peer's
//! candidates). Wide-area *rendezvous* — distributing candidates without a
//! server (a Kademlia DHT) — is the remaining piece; see ROADMAP v0.6 and the
//! [`Rendezvous`] interface below.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use rand::Rng;

use crate::{NetError, Transport};

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAPPED_ADDRESS: u16 = 0x0001;
const STUN_HEADER_LEN: usize = 20;

/// Build a STUN Binding Request with the given transaction id.
pub fn binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(STUN_HEADER_LEN);
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // no attributes
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txid);
    msg
}

/// Parse the mapped address (our reflexive `ip:port`) out of a STUN response,
/// preferring XOR-MAPPED-ADDRESS and falling back to MAPPED-ADDRESS.
pub fn parse_mapped_address(buf: &[u8]) -> Option<SocketAddr> {
    if buf.len() < STUN_HEADER_LEN {
        return None;
    }
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = (STUN_HEADER_LEN + length).min(buf.len());

    let mut i = STUN_HEADER_LEN;
    while i + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let attr_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let val_start = i + 4;
        let val_end = val_start + attr_len;
        if val_end > buf.len() {
            break;
        }
        let val = &buf[val_start..val_end];
        match attr_type {
            XOR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_address(val, true) {
                    return Some(addr);
                }
            }
            MAPPED_ADDRESS => {
                if let Some(addr) = parse_address(val, false) {
                    return Some(addr);
                }
            }
            _ => {}
        }
        // Attribute values are padded to a 4-byte boundary.
        i = val_end + ((4 - (attr_len % 4)) % 4);
    }
    None
}

/// Parse a STUN address attribute value (`[reserved, family, port(2), addr(4)]`),
/// XOR-decoding with the magic cookie when `xored`. IPv4 only.
fn parse_address(val: &[u8], xored: bool) -> Option<SocketAddr> {
    if val.len() < 8 || val[1] != 0x01 {
        return None; // need IPv4 family
    }
    let mut port = u16::from_be_bytes([val[2], val[3]]);
    let mut addr = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
    if xored {
        port ^= (MAGIC_COOKIE >> 16) as u16;
        addr ^= MAGIC_COOKIE;
    }
    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
}

/// Ask a STUN server for our public address. `stun_server` is `host:port`
/// (e.g. `stun.l.google.com:19302`).
pub async fn reflexive_address(stun_server: &str) -> Result<SocketAddr, NetError> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(stun_server).await?;

    let mut txid = [0u8; 12];
    rand::thread_rng().fill(&mut txid[..]);
    socket.send(&binding_request(&txid)).await?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf))
        .await
        .map_err(|_| NetError::Discovery("STUN request timed out".into()))??;

    parse_mapped_address(&buf[..n])
        .ok_or_else(|| NetError::Discovery("STUN response had no mapped address".into()))
}

/// Fire probe datagrams at each of a peer's candidate addresses to open NAT
/// bindings. Sent a few times since the first packets are often dropped while
/// the far NAT is still opening.
pub async fn punch<T: Transport>(transport: &T, candidates: &[SocketAddr], probe: &[u8]) {
    for _round in 0..3 {
        for &candidate in candidates {
            let _ = transport.send_to(probe, candidate).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Serverless rendezvous: how a node publishes its candidate addresses and finds
/// a peer's, without a central coordinator. STUN + hole punching live above;
/// `lattice-dht` implements this trait with a Kademlia DHT (publish to the k
/// closest nodes, iterative lookup by node id).
#[async_trait::async_trait]
pub trait Rendezvous: Send {
    /// Publish our candidates under our node id so peers can find them.
    async fn publish(&self, node_id: [u8; 32], candidates: &[SocketAddr]) -> Result<(), NetError>;
    /// Look up a peer's candidate addresses by node id.
    async fn lookup(&self, node_id: [u8; 32]) -> Result<Vec<SocketAddr>, NetError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xor_mapped_address() {
        let txid = [1u8; 12];
        let ip = Ipv4Addr::new(203, 0, 113, 5);
        let port: u16 = 54321;

        let mut msg = Vec::new();
        msg.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success
        msg.extend_from_slice(&12u16.to_be_bytes()); // one 12-byte attribute
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&txid);
        // XOR-MAPPED-ADDRESS attribute
        msg.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&8u16.to_be_bytes());
        msg.push(0);
        msg.push(0x01); // IPv4
        msg.extend_from_slice(&(port ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        msg.extend_from_slice(&(u32::from(ip) ^ MAGIC_COOKIE).to_be_bytes());

        assert_eq!(
            parse_mapped_address(&msg),
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        );
    }

    #[test]
    fn binding_request_is_well_formed() {
        let txid = [9u8; 12];
        let req = binding_request(&txid);
        assert_eq!(req.len(), STUN_HEADER_LEN);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), BINDING_REQUEST);
        assert_eq!(&req[8..20], &txid);
    }
}

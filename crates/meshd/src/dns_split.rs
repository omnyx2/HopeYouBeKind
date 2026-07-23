//! Domain-based split-tunnel (docs/SPLIT_TUNNEL.md) — LOCAL to this node, not gossiped.
//!
//! Goal: the host uses its normal internet by default, but traffic to specific domains (e.g.
//! `*.pornhub.com`) egresses through a chosen mesh exit. Since packets carry only a dst IP (the
//! domain name is gone after resolution), we learn the name→IP mapping by proxying DNS:
//!
//! 1. meshd runs a tiny DNS proxy on `127.0.0.1:53`; while split mode is on, the host resolver
//!    is pointed at it (reuses `exit::set_dns`).
//! 2. Every query is forwarded upstream and the response parsed for A records.
//! 3. If the queried name matches a [`SplitRule`], each answered IP gets a `/32` host route
//!    injected INTO that mesh's tun (via `exit::route_host_via_iface`), WITHOUT touching the
//!    default route. Those packets then enter the data plane and follow the mesh's exit; every
//!    other destination keeps using the real default route (normal internet).
//!
//! This module holds the pure parts (rule types, suffix matching, DNS answer parsing); the proxy
//! task + route injection are wired in `main.rs` / `exit.rs`.
//!
//! ## Edit-risk
//! - 🟡 [`parse_a_records`] — hand-rolled DNS wire parser; a bug mis-reads answers (must never
//!   panic on malformed/attacker input — all bounds-checked, returns None/partial).
//! - 🟢 [`SplitRule`] / [`domain_matches`] — pure config + string suffix match.

use lattice_proto::wire_v2::MeshId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

/// One local split-tunnel rule: traffic to `domain` (and its subdomains) egresses via `mesh`'s
/// exit. Local to this node — never gossiped (docs/SPLIT_TUNNEL.md). The mesh's current exit
/// member carries it (v1); per-domain exit override is a later step.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SplitRule {
    /// The registrable domain, e.g. `"pornhub.com"`. Matches the domain itself and ALL
    /// subdomains (`www.pornhub.com`, `ads.pornhub.com`, …) — see [`domain_matches`].
    pub domain: String,
    /// Which mesh's tun (and thus exit) the matched traffic is routed into.
    pub mesh: MeshId,
}

/// Does DNS query name `qname` fall under `rule.domain`? True when `qname` equals the domain or
/// is a subdomain of it (suffix match on a label boundary). Case-insensitive; a trailing dot on
/// `qname` (as DNS names often have) is tolerated. So `pornhub.com` matches `pornhub.com`,
/// `www.pornhub.com`, `a.b.pornhub.com` — but NOT `notpornhub.com` or `pornhub.com.evil.com`.
pub fn domain_matches(rule_domain: &str, qname: &str) -> bool {
    let d = rule_domain.trim_matches('.').to_ascii_lowercase();
    let q = qname.trim_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return false;
    }
    q == d || q.ends_with(&format!(".{d}"))
}

/// Parse a DNS response message and return `(queried_name, [A-record IPv4s])`. Returns `None`
/// only if the header/question can't be read at all; a malformed answer section yields whatever
/// A records parsed cleanly before the corruption (best-effort, never panics). Name compression
/// in the answer `NAME` field is skipped correctly (2-byte pointer or inline labels).
pub fn parse_a_records(msg: &[u8]) -> Option<(String, Vec<Ipv4Addr>)> {
    if msg.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = 12usize;

    // --- Question section: read the first qname (questions are never compressed), then skip
    // the rest of the questions (each: name + qtype(2) + qclass(2)).
    let (qname, mut pos_after_first_q) = read_qname(msg, pos)?;
    pos_after_first_q += 4; // qtype + qclass of the first question
    pos = pos_after_first_q;
    for _ in 1..qdcount {
        let (_n, after) = read_qname(msg, pos)?;
        pos = after + 4;
    }

    // --- Answer section: for each RR, skip NAME, read TYPE/CLASS/TTL/RDLENGTH, grab A rdata.
    let mut ips = Vec::new();
    for _ in 0..ancount {
        let after_name = match skip_name(msg, pos) {
            Some(p) => p,
            None => break,
        };
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 bytes of fixed fields.
        if after_name + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[after_name], msg[after_name + 1]]);
        let rdlen = u16::from_be_bytes([msg[after_name + 8], msg[after_name + 9]]) as usize;
        let rdata = after_name + 10;
        if rdata + rdlen > msg.len() {
            break;
        }
        if rtype == 1 && rdlen == 4 {
            ips.push(Ipv4Addr::new(
                msg[rdata],
                msg[rdata + 1],
                msg[rdata + 2],
                msg[rdata + 3],
            ));
        }
        pos = rdata + rdlen;
    }
    Some((qname, ips))
}

/// Read an uncompressed domain name (labels ending in a 0 byte) starting at `pos`. Returns the
/// dotted name and the offset just past the terminating 0. `None` on truncation.
fn read_qname(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    loop {
        let len = *msg.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            // A compression pointer in a QUESTION is unusual/invalid; bail rather than chase it.
            return None;
        }
        if pos + len > msg.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&msg[pos..pos + len]));
        pos += len;
    }
    Some((name, pos))
}

/// Skip a name in an answer RR (which may be a 2-byte compression pointer, inline labels, or a
/// mix ending in a pointer or a 0). Returns the offset just past the name. `None` on truncation.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)? as usize;
        if len & 0xc0 == 0xc0 {
            // Compression pointer: 2 bytes total, name ends here.
            return Some(pos + 2);
        }
        pos += 1;
        if len == 0 {
            return Some(pos);
        }
        if len & 0xc0 != 0 {
            return None; // reserved bits — malformed
        }
        pos += len;
        if pos > msg.len() {
            return None;
        }
    }
}

/// The address the split-tunnel DNS proxy binds (loopback:53). Apps are pointed here (via
/// `exit::set_dns([127.0.0.1])`) while split mode is on.
pub const PROXY_BIND: &str = "127.0.0.1:53";

/// Best-effort: the host's REAL upstream resolver to forward proxied queries to, so normal
/// (non-split) names still resolve exactly as before. Reads the OS resolver config; falls back to
/// Cloudflare `1.1.1.1:53` if none is found. MUST be called BEFORE pointing the host at our proxy
/// (otherwise it would read `127.0.0.1`).
pub fn detect_upstream() -> SocketAddr {
    let fallback: SocketAddr = "1.1.1.1:53".parse().unwrap();
    // macOS: `scutil --dns` lists the active resolvers; take the first non-loopback nameserver.
    #[cfg(target_os = "macos")]
    if let Ok(out) = std::process::Command::new("scutil").arg("--dns").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("nameserver[") {
                if let Some((_, ip)) = rest.split_once("] : ") {
                    if let Ok(a) = ip.trim().parse::<std::net::IpAddr>() {
                        if !a.is_loopback() {
                            return SocketAddr::new(a, 53);
                        }
                    }
                }
            }
        }
    }
    // Linux (and macOS fallback): /etc/resolv.conf first non-loopback `nameserver`.
    if let Ok(txt) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in txt.lines() {
            if let Some(ip) = line.trim().strip_prefix("nameserver ") {
                if let Ok(a) = ip.trim().parse::<std::net::IpAddr>() {
                    if !a.is_loopback() {
                        return SocketAddr::new(a, 53);
                    }
                }
            }
        }
    }
    fallback
}

/// Run the split-tunnel DNS proxy until the task is aborted. Binds [`PROXY_BIND`], and for each
/// query: forwards it to `upstream`, parses the response for A records, and — if the queried name
/// matches any rule in `rules` — injects a `/32` host route for each answered IP into `tun` (via
/// `exit::route_host_via_iface`, recording it in `injected` for cleanup), then relays the answer
/// back to the app unchanged. Non-matching names just pass through. Rules are a static snapshot
/// taken at enable time (re-toggle split mode to pick up a newly-added rule).
pub async fn run_proxy(
    tun: String,
    rules: Vec<SplitRule>,
    upstream: SocketAddr,
    injected: Arc<Mutex<HashSet<Ipv4Addr>>>,
) {
    let sock = match tokio::net::UdpSocket::bind(PROXY_BIND).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!("split-tunnel: cannot bind {PROXY_BIND} ({e}); DNS proxy not started");
            return;
        }
    };
    tracing::warn!(%upstream, tun, rules = rules.len(), "split-tunnel DNS proxy listening");
    let rules = Arc::new(rules);
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, client) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let query = buf[..n].to_vec();
        let (sock, rules, injected, tun) = (
            Arc::clone(&sock),
            Arc::clone(&rules),
            Arc::clone(&injected),
            tun.clone(),
        );
        tokio::spawn(async move {
            let _ = handle_query(&sock, client, &query, upstream, &rules, &injected, &tun).await;
        });
    }
}

/// Forward one query upstream, inject routes for a matched name, relay the answer to `client`.
async fn handle_query(
    sock: &tokio::net::UdpSocket,
    client: SocketAddr,
    query: &[u8],
    upstream: SocketAddr,
    rules: &[SplitRule],
    injected: &Arc<Mutex<HashSet<Ipv4Addr>>>,
    tun: &str,
) -> std::io::Result<()> {
    // Ephemeral socket to the upstream resolver (its own path uses the real default route, so a
    // split /32 can't loop the resolver traffic into the mesh).
    let up = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    up.send_to(query, upstream).await?;
    let mut rbuf = vec![0u8; 4096];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(4), up.recv(&mut rbuf)).await
    {
        Ok(Ok(n)) => n,
        _ => return Ok(()), // upstream timeout/err: drop; the app will retry
    };
    let resp = &rbuf[..n];
    if let Some((qname, ips)) = parse_a_records(resp) {
        if rules.iter().any(|r| domain_matches(&r.domain, &qname)) {
            for ip in ips {
                let fresh = injected.lock().unwrap().insert(ip);
                if fresh {
                    let tun_s = tun.to_string();
                    // Route injection shells out — do it off the async loop.
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::exit::route_host_via_iface(ip, &tun_s)
                    })
                    .await;
                    tracing::warn!(%ip, name = %qname, tun, "split-tunnel: routed via mesh exit");
                }
            }
        }
    }
    sock.send_to(resp, client).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_match_is_label_bounded() {
        assert!(domain_matches("pornhub.com", "pornhub.com"));
        assert!(domain_matches("pornhub.com", "www.pornhub.com"));
        assert!(domain_matches("pornhub.com", "ads.cdn.pornhub.com"));
        assert!(domain_matches("pornhub.com", "WWW.PORNHUB.COM")); // case-insensitive
        assert!(domain_matches("pornhub.com", "www.pornhub.com.")); // trailing dot ok
        assert!(!domain_matches("pornhub.com", "notpornhub.com")); // not a label boundary
        assert!(!domain_matches("pornhub.com", "pornhub.com.evil.com")); // suffix, not prefix
        assert!(!domain_matches("pornhub.com", "example.org"));
    }

    #[test]
    fn parse_a_record_response() {
        // Response for www.example.com A → 93.184.216.34, with a compressed answer name (0xC00C).
        let msg: &[u8] = &[
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, // question: www.example.com A IN
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x5d, 0xb8,
            0xd8, 0x22, // answer: ptr, A, IN, ttl=256, rdlen=4, 93.184.216.34
        ];
        let (name, ips) = parse_a_records(msg).expect("parse");
        assert_eq!(name, "www.example.com");
        assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
    }

    #[test]
    fn parse_tolerates_two_answers_and_non_a() {
        // Question sub.test A; answers: a CNAME (type 5, skipped) then two A records.
        let msg: &[u8] = &[
            0xaa, 0xbb, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x00, // hdr, an=3
            0x03, b's', b'u', b'b', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00,
            0x01, // q: sub.test A IN
            // answer 1: CNAME (type 5), rdata = a 2-byte pointer (len 2)
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x02, 0xc0, 0x0c,
            // answer 2: A 10.0.0.1
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x04, 0x0a, 0x00,
            0x00, 0x01, // answer 3: A 10.0.0.2
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x04, 0x0a, 0x00,
            0x00, 0x02,
        ];
        let (name, ips) = parse_a_records(msg).expect("parse");
        assert_eq!(name, "sub.test");
        assert_eq!(
            ips,
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
    }

    #[test]
    fn malformed_never_panics() {
        assert!(parse_a_records(&[]).is_none());
        assert!(parse_a_records(&[0; 5]).is_none());
        // Truncated answer: header claims 1 answer, but bytes run out mid-RR → returns name + no IPs.
        let msg: &[u8] = &[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, b'a',
            0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
        ];
        let (name, ips) = parse_a_records(msg).expect("header/question ok");
        assert_eq!(name, "a");
        assert!(ips.is_empty());
    }
}

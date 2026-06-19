# IPv6 / dual-stack underlay — work plan (NOT yet built)

**Goal:** the mesh underlay works on **IPv6-only / NAT64 (464XLAT) cellular networks**, not
just IPv4. Today a node behind an IPv6-only carrier can't reach a peer advertised by an IPv4
literal (e.g. Oracle `<PUBLIC_IP>:41000`): the carrier does DNS64 (hostnames → IPv6) but the
device's CLAT may fail to translate raw IPv4 literals, so the UDP send has no route
(`EADDRNOTAVAIL`). The fix is to make the **overlay-carrying UDP underlay** speak IPv6.

Scope note: this is the **underlay** (how meshd packets reach peers). The **overlay** (the TUN,
`100.80.x.y`, member IPs) stays IPv4 — unchanged.

## Why it's mostly plumbing
`SocketAddr` / `IpAddr` already model both families, and several pieces are family-agnostic
already:
- `crates/net/src/lib.rs:73` `UdpTransport::bind(addr: SocketAddr)` — binds whatever it's given.
- `discovery::EndpointRecord.endpoints: Vec<SocketAddr>` — already a *list*, already v6-capable.
- `meshrun::is_public` already has a V6 branch (`lib.rs:78`).
- gossip encodes `"{member} {socketaddr}\n"` — `[v6]:port` has no spaces, so `split_once(' ')`
  + `parse::<SocketAddr>()` already round-trips v6.

The blockers are the **IPv4-hardcoded bind addresses** and the **v4-only local-address discovery
+ advertise** path.

## Concrete change list (by file)

### 1. Bind dual-stack instead of `0.0.0.0`
- **meshd data plane** (`crates/meshd/src/main.rs`, `bringup_dataplane`): the UDP bind is
  `0.0.0.0:port`. Bind `[::]:port` with `IPV6_V6ONLY=false` so ONE socket accepts both IPv4
  (as v4-mapped `::ffff:a.b.c.d`) and IPv6. Tokio's `UdpSocket` doesn't expose v6only directly;
  build via `socket2::Socket` (set_only_v6(false)), then `UdpSocket::from_std`.
- **DHT** (`meshd/main.rs`, ~`SocketAddr::from(([0,0,0,0], dht_port))`): same — bind `[::]`.
- **`crates/net` `UdpTransport`**: add a `bind_dual()` (or have `bind` detect `::` and set
  v6only=false). Keep the existing `bind(SocketAddr)` for tests.
- Gotcha: v4-mapped addresses arrive as `::ffff:1.2.3.4`. Normalize on receive
  (`to_canonical()` / strip `::ffff:` back to V4) before storing in `links`/`fails`/gossip so a
  peer isn't seen as two different addresses over v4 vs mapped-v6.

### 2. Learn + advertise an IPv6 address
- **`crates/net/src/lib.rs:375` `local_ipv4()`**: add `local_ipv6()` (UDP `connect` to a public
  v6 like `[2001:4860:4860::8888]:53`, read `local_addr`). The comment at `lib.rs:398` ("skip
  IPv6 candidates — our transport binds IPv4") is removed once the transport is dual-stack.
- **meshd `local_ip()`** + the `advertise` computation: produce BOTH a v4 and a v6 candidate
  when available.
- **`MESHD_ADVERTISE`**: already `parse::<SocketAddr>()`, so `[2001:...]:41000` works. Allow a
  COMMA-LIST so a public node can pin both: `MESHD_ADVERTISE=<PUBLIC_IP>:41000,[2001:..]:41000`.

### 3. Carry MULTIPLE endpoints per member (v4 + v6) end-to-end
This is the key design change — a peer should advertise every address it might be reached on,
and the other side picks one that's reachable.
- **`SharedEndpoint`** (`meshrun`) becomes a `Vec<SocketAddr>` (or a small struct) instead of
  one addr. `my_endpoint` → `my_endpoints`.
- **Gossip** (`encode_gossip`/`decode_gossip`) + the **invite `endpoints`** + the **DHT
  `EndpointRecord`** (already `Vec<SocketAddr>`): publish all of a member's addresses.
- **`links`**: store a primary + alternates per member; on send, try the family that matches our
  own stack (prefer v6 if we have v6, else v4). On inbound, learn the source addr (canonicalized)
  as the confirmed reachable one (the existing roaming-learn already does this — keep it).
- **P-D3 reflexion**: reflect the observed source family back (a v6 peer learns its v6 reflexive
  addr). `is_public` already handles v6.

### 4. DHT over v6
- DHT records already hold `Vec<SocketAddr>`; ensure the Kademlia transport (`legacy/crates/dht`)
  binds dual-stack and its bootstrap list accepts `[v6]:port`. Bootstrap the public node's v6.

### 5. Hostname endpoints (optional, smaller win)
- Allow `MESHD_ADVERTISE=oracle.example.org:41000` and resolve at use (getaddrinfo → prefers v6
  via DNS64 on cellular). Lets DNS64 do the work even without explicit v6 on the node. Lower
  priority than native v6 but cheap.

## Phasing
1. **P-1 dual-stack bind + v4-mapped normalization** (meshd data plane + DHT + net transport).
   Verifiable on a dual-stack LAN (still works for v4 peers).
2. **P-2 v6 local-addr discovery + advertise** (single v6 endpoint).
3. **P-3 multi-endpoint per member** (v4+v6 in gossip / invite / DHT; send-side family select).
4. **P-4 DHT v6 bootstrap.**
5. **P-5 hostname endpoints** (optional).

## Testing
- **Unit**: v4-mapped canonicalization; gossip encode/decode round-trips `[v6]:port`; multi-
  endpoint pick.
- **Live**: public node (Oracle) gets an IPv6 (OCI: add an IPv6 to the VCN/subnet + the
  instance, open UDP 41000 on v6 in the security list). Then from the Mac on the **IPv6-only
  hotspot**, join and confirm the overlay ping works over **native v6** (no CLAT). This is the
  exact scenario that fails today.
- **Regression**: campus IPv4 (Mac↔Oracle) still works; 3-platform build (incl. Windows v6
  socket behavior — Windows needs `IPV6_V6ONLY=false` set explicitly too).

## Gotchas
- `IPV6_V6ONLY` default differs by OS (Linux honors `bindv6only` sysctl; Windows/macOS default
  v6only=true) → always set it explicitly to false.
- v4-mapped (`::ffff:`) vs native v4 must be canonicalized everywhere an address is a KEY
  (`links`, `decrypt_fails`, dedup) or a peer doubles.
- Link-local v6 (`fe80::`) carries a scope id and is not routable off-link — exclude from
  advertise (extend `is_public`).
- OCI security lists are v4/v6 separate — the live test needs the v6 UDP rule added in console.

# Building a serverless mesh VPN in Rust

*How Lattice fuses a handful of machines into one private, encrypted network —
with no coordination server, a CA you run yourself, and a tunnel-crypto layer you
can rip out and replace.*

---

Tailscale and ZeroTier made mesh VPNs feel magical: install an agent on each
machine and they just find each other and talk over a flat, encrypted overlay.
But both lean on a coordination service to broker identity and connections.
**Lattice** is an experiment in doing the same thing *serverlessly* — and in
treating the encrypted tunnel itself as the research surface rather than a
checkbox.

This post walks through the pieces, in the order they matter.

## 1. The overlay: identity is the address

Every node generates a long-term Curve25519 keypair. The public key *is* the node
id, and the node's **virtual IP** in `100.64.0.0/10` is derived from it. So a
node's address is a function of its identity, not its network location — the same
machine keeps its overlay IP whether it's on Wi-Fi, LTE, or behind three NATs.

A virtual NIC (`utun` on macOS, `/dev/net/tun` on Linux, Wintun on Windows)
carries the overlay. The engine's loop is the whole VPN in four lines:

```text
TUN.read → route(dst) → session.encrypt → transport.send   ─► peer
TUN.write ← session.decrypt ← transport.recv               ◄─ peer
```

The data-plane crates (`tun`, `net`, `engine`) talk through traits, so the engine
runs against real devices in the daemon and in-memory fakes in tests — the same
logic either way. That made it possible to test an end-to-end tunnel between two
nodes with no root and no real NIC.

## 2. The tunnel: a custom protocol on vetted primitives

The research contribution isn't a new cipher — rolling your own AEAD is how you
get owned. It's the *protocol*: the handshake choreography, session framing,
replay handling, and rekeying. Those are built **on** the Noise framework
(`Noise_IK_25519_ChaChaPoly_BLAKE2s`, the same shape WireGuard uses): mutual
authentication, forward secrecy, AEAD.

One bug from early testing is worth remembering. We started on Noise's *in-order*
transport, and the tunnel would mysteriously die after a while on real networks.
The cause: UDP reorders and drops packets, and the in-order mode desyncs on the
first one. The fix was to move to a **stateless** transport — every packet
carries an explicit 8-byte nonce, with a sliding replay window — so loss and
reordering are normal, not fatal.

## 3. Finding each other with no server

Discovery is where "serverless" gets real. On a LAN, nodes advertise and browse
over **mDNS** — zero configuration, no bootstrap. For the internet, there's a
**Kademlia DHT** (XOR distance, k-buckets, iterative lookup) where a node
publishes its STUN-discovered public address under its node id, and peers resolve
each other by id. NAT traversal is UDP hole-punching across every candidate
endpoint at once — the first to answer wins.

Two lessons showed up immediately in live testing:

- **Advertise the right address.** An early version advertised only IPv6
  link-local addresses on the Mac (it has many `utun` interfaces), so peers had
  nothing dialable. We now explicitly publish the real LAN IPv4.
- **mDNS is not guaranteed.** On a campus Wi-Fi that filters multicast between
  clients, discovery silently never completed. The escape hatch is a manual pin:
  `--peer-addr <node-id>@<ip:port>`. (Amusingly, mDNS works fine *inside* a Docker
  bridge — a clean L2 segment — which is how the multi-node demo below ran with
  no pins at all.)

## 4. Pulling the crypto out into a seam

Here's the bet that shapes the codebase: **the tunnel encryption should be
swappable.** If you want to research a post-quantum KEM handshake or a different
AEAD, you shouldn't have to understand the engine.

So the engine doesn't name a cipher. It drives a trait:

```rust
pub trait CryptoSuite: Send + Sync {
    fn name(&self) -> &'static str;
    fn initiate(&self, local_priv: &[u8], remote_pub: &[u8], payload: &[u8])
        -> Result<(Box<dyn HandshakeState>, Vec<u8>), CryptoError>;
    fn respond(&self, local_priv: &[u8], init: &[u8], payload: &[u8])
        -> Result<Accepted, CryptoError>;
}
```

`NoiseSuite` is the default, a thin wrapper over the existing primitives. The
engine holds `Arc<dyn CryptoSuite>` and `Box<dyn TunnelSession>` — no compile-time
dependency on Noise. A new scheme is one `impl` and one `Engine::with_suite(...)`
call. The wire format is owned entirely by the suite; the engine just frames
`HandshakeInit` / `HandshakeResp` / `Transport` around its bytes.

(Rust footnote: making the engine's async loop hold sessions across `.await`
points meant the trait objects had to be `Send + Sync`. They're only ever mutated
through `&mut`, so that's sound — but the compiler made us say so.)

## 5. A certificate authority with no server

A mesh you can't *close* isn't much of a private network. We wanted: a network
you name and share, where one person decides who's in and can kick people out —
without a server brokering any of it.

The model is a **network keypair**. Its public half is the **Network ID** — the
stable, random name of the mesh that you remember and hand to people. Its private
half is the **CA**: whoever holds it admits members (signs a certificate binding
a node's identity key to the network) and evicts them (signs a revocation).

The elegant part is what *isn't* there:

- **No founder node.** The network lives in the secret, not in any machine. The
  first node online just waits; the network survives every node going offline.
- **No central list.** Certs and revocations are each independently signed, so
  they gossip peer-to-peer and merge by union — no ordering, no quorum, no server.

A node proves membership by presenting its cert in the handshake; the peer
verifies it against the network id, binds it to the handshake-authenticated
identity key, checks expiry, and rejects revoked serials. Crucially, this is
**orthogonal to the crypto suite** — membership decides *who is allowed*, the
suite secures *the channel*. Change one without the other.

### The bug the live demo caught

We thought we were done, then ran it on real nodes and watched an eviction
*fail*. The culprit was a soundness gap: two nodes that had connected in **open
mode** (before either joined the network) kept that session afterward — it was
never bound to a certificate serial, so a revocation had nothing to match. A node
could "join" a network and keep a session that membership never actually vetted.

The fix: **joining drops existing sessions and re-handshakes them under the
network.** No lingering unauthenticated tunnels; re-formed sessions are
serial-bound and revocable. We also made the engine re-initiate handshakes to
known-but-disconnected peers every keepalive tick, so reconnection is prompt
instead of waiting on a slow discovery re-emit — which incidentally fixed a
long-standing "why did it take two minutes to reconnect" annoyance.

## 6. Watching the traffic

Because a node sits on the plaintext path (it's the tunnel endpoint), it can show
you exactly what's flowing — passively. The traffic monitor records each packet
just before encryption and just after decryption, aggregates into bidirectional
**flows** keyed by `(peer, protocol, local, remote)`, and surfaces them in the GUI
and via `lattice flows`. It reads metadata only (addresses, ports, sizes), never
payloads, and persists nothing — a local diagnostic, not a wiretap.

## 7. Proof: three nodes, one SDN, on Docker

The satisfying test: spin up **three independent nodes as Docker containers** on
one Linux host — each with its own network namespace, TUN device, and identity —
on a single bridge network. One is the admin.

```
admin: net create                       → network id 7e074d71…
admin: net issue <node-2>, <node-3>      → join tokens
node-2/3: net join <token>               → members
            full mesh forms (mDNS, no pins)
ping 100.x across all pairs              → 0% loss, encrypted
admin: net revoke <node-3>               → gossiped
node-3 cut off: dropped by both peers, 100% packet loss
```

Three "computers", one self-assembled encrypted SDN, membership granted and
revoked from a CA running on one of the nodes — no server anywhere in the
picture. That's the whole idea, working.

## Where it's going

Discovery isn't scoped by network yet (different meshes on one LAN discover each
other; they just can't form a session without a valid cert) — wiring the
network's rendezvous tag into mDNS/DHT is the clean isolation step. A public DHT
bootstrap node, relay fallback hardening across real NATs, and config-driven
crypto-suite selection are next. The roadmap lives in
[ROADMAP.md](../ROADMAP.md); what works today is in [FEATURES.md](../FEATURES.md).

The fun of Lattice is that the hard parts — the tunnel and the trust model — are
the parts you're invited to take apart and rebuild.

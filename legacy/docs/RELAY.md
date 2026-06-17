# Relay (DERP-style)

When two nodes can't connect directly — both behind CGNAT or symmetric NAT, so
hole punching fails — a **relay** forwards their traffic. The relay is a dumb
shuttle: it maps `node id → address` and forwards frames. It never sees
plaintext (the Noise session stays end-to-end between the two nodes).

You need **one** machine the two peers can both reach — a small VPS, or any
host with a reachable UDP port.

## How it's wired

Implemented as a transport decorator (`crates/net/relay.rs`): `RelayTransport`
wraps the UDP transport, so relayed peers appear to the engine as ordinary
direct peers (via a stable synthetic address per peer). The engine has zero
relay-specific code. Verified over real UDP (A→relay→B and back).

Frame: `[0x05][dest id (32)][src id (32)][inner]`; an all-zero `dest` registers
the sender's address.

## Usage

**1. Run the relay** on the reachable host:
```bash
./lattice-daemon --no-tun --relay-bind 0.0.0.0:42000
```
(`--no-tun` because a pure relay doesn't need its own mesh interface. Note the
host's public ip:port — `<RELAY>` below.)

**2. The "callee" node** (the one being reached) registers with the relay:
```bash
sudo ./lattice-daemon --relay <RELAY-ip>:42000
```
Note its node id (shown in the GUI / `lattice status`).

**3. The "caller" node** reaches it through the relay:
```bash
sudo ./lattice-daemon --relay <RELAY-ip>:42000 --peer-relay <callee-node-id>
```

Both nodes now have an end-to-end-encrypted tunnel routed through the relay —
ping the other's `100.x.x.x` as usual.

## Notes & status

- The relay carries **encrypted** traffic only; it cannot read it.
- One relay can serve many peer pairs.
- ⚠️ The transport + relay forwarding are unit-tested over real UDP, but the
  full two-machine-through-a-VPS path hasn't been field-tested yet — try it on a
  spare relay host first.
- Direct connection is still preferred; the relay is the fallback. (Automatic
  "try direct, fall back to relay" promotion is a future refinement — today you
  choose direct (`--peer-addr`) vs relay (`--peer-relay`) explicitly.)

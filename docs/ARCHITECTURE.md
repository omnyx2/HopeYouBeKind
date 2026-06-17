# Architecture

Lattice is a **mesh overlay network**: each participating machine ("node") runs
the same software, and the nodes collectively form a single private IP network
on top of whatever physical networks they happen to be on. This is the same
class of system as Tailscale, ZeroTier, and Nebula — but serverless and with a
custom tunnel protocol.

## The three planes

Networking systems are easiest to reason about when split into planes. Lattice
maps each plane onto specific crates.

### 1. Data plane — "move the packets"

The hot path that every packet traverses. Must be fast and must never panic on
hostile input.

- **`lattice-tun`** — creates a virtual network interface (a TUN device) on the
  OS. The OS routes packets for the overlay subnet (e.g. `100.64.0.0/10`) into
  this device; we read raw IP packets out of it and write replies back in.
  - macOS: `utun` via `/dev/utunN`
  - Linux: `/dev/net/tun`
  - Windows: the Wintun driver
- **`lattice-crypto`** — the custom encrypted tunnel. Takes a plaintext IP
  packet destined for peer X, performs the session handshake with X (once), and
  produces an encrypted datagram; and the reverse. Built on the Noise framework
  (`snow`) so we design the *protocol* (handshake pattern, rekeying, framing)
  without hand-rolling ciphers. Spec: [`PROTOCOL.md`](../legacy/docs/PROTOCOL.md).

### 2. Transport & discovery — "find peers, carry ciphertext"

- **`lattice-net`** — owns the UDP socket(s). Two jobs:
  - **Transport:** send/receive the encrypted datagrams produced by `crypto`.
  - **Discovery (serverless):** find other nodes without a central server.
    - LAN: mDNS service advertisement/browse (`_lattice._udp.local`).
    - WAN (roadmap): a Kademlia DHT for rendezvous + UDP hole-punching for NAT
      traversal. See [`ROADMAP.md`](ROADMAP.md).

### 3. Control plane — "decide the topology"

- **`lattice-overlay`** — the SDN brain. Maintains the peer registry (who is in
  the network, their public keys and reachable endpoints), allocates each node a
  stable virtual IP, and maintains the routing table that maps a destination
  virtual IP → the peer to tunnel to.

## Composition

- **`lattice-engine`** is the runtime that owns one node's lifecycle. It wires
  the TUN device to crypto to transport, drives discovery, and feeds the overlay
  control plane. Everything above is a library; the engine is the conductor.
- **`lattice-daemon`** is the long-running privileged process (TUN creation
  needs elevated rights). It hosts the engine and exposes a local IPC endpoint.
- **`lattice-cli`** and the **Tauri GUI** are unprivileged clients that talk to
  the daemon over IPC (defined in `lattice-proto`). They never touch the network
  directly — they ask the daemon to.

```
packet in  ──> TUN ──> overlay(route lookup) ──> crypto(encrypt) ──> net(UDP) ──> peer
packet out <── TUN <── crypto(decrypt) <────────────────────────── net(UDP) <── peer
                         ▲
            engine drives this loop; daemon hosts engine; GUI/CLI command daemon
```

## Why this split

- **Independent evolution.** The custom tunnel (`crypto`) can be redesigned for
  the research project without touching discovery or the GUI.
- **Testability.** Each crate has a narrow, mockable interface — e.g. the TUN
  device and the UDP transport are traits, so the engine can be tested against
  in-memory fakes with no OS privileges.
- **Blast radius.** Untrusted-input parsing lives in `proto`/`crypto`/`net`;
  those get the most fuzzing and the strictest "no panic" rules.

## Key trait boundaries (for testing & ports)

| Trait              | Crate     | Real impl                | Test impl              |
| ------------------ | --------- | ------------------------ | ---------------------- |
| `TunDevice`        | `tun`     | per-OS TUN               | in-memory packet queue |
| `Transport`        | `net`     | UDP socket               | in-memory channel      |
| `Discovery`        | `net`     | mDNS / DHT               | static peer list       |
| `TunnelSession`    | `crypto`  | Noise-based session      | passthrough (no crypto)|

These boundaries are what let the whole engine run in a unit test without root,
a real NIC, or a network.

# SDN × DHT — serverless mesh VPN control plane

The design for combining a **software-defined control plane (SDN)** with a
**DHT-based serverless distribution layer**, so the mesh has a single coherent
network view and programmable policy **without any coordination server**.

Two non-negotiable requirements drive this design:

1. **SDN × DHT.** A global, programmable control plane (the network map + routing
   policy) that is distributed peer-to-peer over a DHT — no central server.
2. **Admin authority.** The mesh has one **administrator node** (the computer
   holding the network CA private key). *Only the admin* may change anything that
   defines the network — membership, policy/ACLs, addressing, relay/exit
   designation. Distribution is decentralized; **authority is not**.

The resolution of those two — *decentralized distribution, centralized
authority* — is the heart of this document: the DHT is dumb, untrusted storage;
**authority comes from admin signatures**, which a DHT node can withhold or
replay but never forge.

> Written before implementation. It is the architecture spec; the per-phase build
> plans follow it. See also [ARCHITECTURE.md](ARCHITECTURE.md) (current crates),
> [MEMBERSHIP.md](MEMBERSHIP.md) (the CA), and [ADMIN_CONSOLE.md](ADMIN_CONSOLE.md)
> (the admin UI).

---

## 1. What exists vs. what this adds

The two halves already exist but are **not connected**:

| Piece | Today | This design |
| --- | --- | --- |
| SDN control plane | `crates/overlay` — a *per-node* routing/addressing view ("who's in the mesh, what VIP, which peer to tunnel to") | a **global, admin-signed network map** every node reconstructs |
| DHT | `crates/dht` (Kademlia) — used only for `node_id → endpoint` rendezvous | the **serverless store/transport for the whole control plane** |
| Membership CA | `crates/membership` — admin issues/revokes certs | the **root of authority** signing the network map |
| Data plane | `crates/engine` — Noise tunnels | unchanged; programmed by the SDN layer |

The gap (surfaced in practice): there is **no peer/topology gossip** and **no
transit** today — each node only learns peers it independently discovers (mDNS,
which can't cross subnets, or manual `--peer-addr` pins). So a full mesh only
forms when discovery happens to reach everyone. This design replaces ad-hoc
discovery with a **DHT-distributed network map**, so every member learns the
*whole* topology and a full mesh forms automatically.

---

## 2. The authority model (read first)

Every control-plane artifact is one of two kinds, distinguished by **who signs
it** — this is how "only the admin computer can touch important things" is
enforced even though storage is decentralized:

| Kind | Signed by | Contains | Who can write |
| --- | --- | --- | --- |
| **Authoritative** | the **network CA** (admin's private key) | membership directory, policy/ACLs, VIP assignment, relay/exit designation, crypto policy, network config | **admin only** |
| **Self-published** | each **node's own member cert** | *its own* current endpoints, supported suites, liveness | that node, **about itself only** |

Consequences:

- A member **cannot** forge the directory/policy (no CA key) → cannot admit
  itself, change ACLs, reassign VIPs, or appoint relays.
- A member **cannot** impersonate another node's endpoints (endpoint records are
  self-signed per node) → cannot hijack traffic by claiming someone's VIP.
- A malicious/curious DHT participant can **withhold or replay** records but
  **cannot forge** them (signatures) — replay is defeated by monotonic, signed
  version numbers + timestamps.
- The **admin node is the only writer of the network's "program."** It is the SDN
  controller; the DHT is its distribution bus. The admin runs the controller from
  the admin console ([ADMIN_CONSOLE.md](ADMIN_CONSOLE.md)).

The admin key is the existing `--network-key` (the CA). No new trust root.

---

## 3. Layered architecture

```
  ┌──────────────────────────────────────────────────────────────────┐
  │ IDENTITY / CA            crates/membership                        │
  │   network CA (admin) → member certs (who is admitted)            │
  └───────────────┬──────────────────────────────────────────────────┘
                  │ admin signs the network "program"
  ┌───────────────▼──────────────────────────────────────────────────┐
  │ SDN CONTROL PLANE        crates/overlay (extended)                │
  │   network map = manifest + member directory + policy/ACL          │
  │   + per-node endpoint records → programs the routing table        │
  └───────────────┬──────────────────────────────────────────────────┘
                  │ publish / fetch / subscribe (signed records)
  ┌───────────────▼──────────────────────────────────────────────────┐
  │ DISTRIBUTION (serverless)  crates/dht (generalized)              │
  │   Kademlia store: key = H(netid:type:subject) → signed record     │
  │   no central server; any member (or a public bootstrap) seeds it  │
  └───────────────┬──────────────────────────────────────────────────┘
                  │ programmed routes (direct / relay / exit)
  ┌───────────────▼──────────────────────────────────────────────────┐
  │ DATA PLANE               crates/engine + crates/net               │
  │   Noise tunnels, relay (DERP-style), exit-node forwarding         │
  └──────────────────────────────────────────────────────────────────┘
```

---

## 4. The network map (data model)

### 4.1 Authoritative records (admin-signed)

**`NetworkManifest`** — the root of the SDN program. One per network, versioned.
```
NetworkManifest {
  network_id,                 // = CA public key id (existing)
  version: u64,               // monotonic; nodes adopt the highest valid version
  vip_subnet,                 // overlay CGNAT range (e.g. 100.64.0.0/10)
  crypto_policy,              // allowed CryptoSuite(s) (ties to CRYPTO_SUITE.md)
  relays: [node_id],          // nodes designated to relay for unreachable pairs
  exit_eligible: [node_id],   // nodes allowed to act as exit nodes
  default_acl,                // allow-all | deny-all + rule set ref
  issued_at, sig,             // CA signature
}
```

**`MemberDirectory`** — the admitted set (the published form of today's local
admin registry). Versioned, admin-signed.
```
MemberDirectory {
  network_id, version,
  members: [ { node_id, pubkey, vip, label, groups: [..], revoked: bool } ],
  issued_at, sig,             // CA signature
}
```
- `vip` is admin-assigned here (SDN addressing). v1 may keep the existing
  identity-derived VIP (`derive_virtual_ip`) and simply *record* it; admin
  override is a later capability.
- `revoked` mirrors the existing revocation list; the directory is the
  authoritative membership truth.

**`Policy`** — ACL / reachability rules (optional in v1; default allow-all among
members). Admin-signed, versioned.
```
Policy { network_id, version, rules: [ {from: group, to: group, action} ], sig }
```

### 4.2 Self-published records (node-signed)

**`EndpointRecord`** — where a node currently is. Signed by the node's **own**
member cert (authentic, self-scoped, short-lived).
```
EndpointRecord {
  node_id,
  endpoints: [ socketaddr ],  // reflexive (STUN), LAN, relay-reachable
  suites: [name],             // CryptoSuites it supports
  seq: u64, at_ms,            // freshness; refreshed every ~30–60s
  sig,                        // node's member-cert signature
}
```

---

## 5. DHT as the serverless control-plane store

Generalize the current `node_id → [addr]` Kademlia into a signed key→record
store.

- **Key:** `H(network_id ‖ record_type ‖ subject)`, e.g.
  `H(netid‖"manifest")`, `H(netid‖"directory")`, `H(netid‖"endpoint"‖node_id)`.
- **Value:** the signed record bytes (§4). Readers **always verify the signature**
  (CA key for authoritative, the member's cert for endpoints) and **reject lower
  versions/seqs** → forgery and replay are both defeated.
- **Refresh & TTL:** endpoint records re-published every 30–60 s (liveness);
  manifest/directory/policy are long-lived and re-published on change with a
  bumped `version`. DHT entries carry a TTL so dead nodes age out.
- **Bootstrap:** any reachable member (or a public bootstrap node, `--dht-bind`/
  `--dht-bootstrap`) seeds the Kademlia ring. No server is *authoritative* — a
  bootstrap is just an entry point.
- **Privacy (option):** keys/values can be encrypted to members with a symmetric
  key derived from the network secret, so the topology isn't readable by arbitrary
  DHT participants. v1 may ship cleartext (signed-but-public) and add member-only
  encryption later. (Stated as a deliberate trade-off, like HEALTH_CHECK.md.)

---

## 6. Mesh formation (how a full mesh self-assembles)

A node boots with its member cert + a DHT bootstrap and:

1. **Join the DHT** (bootstrap into the Kademlia ring).
2. **Fetch the manifest + directory + policy** (admin-signed) → learns the
   **entire membership**, VIPs, and what it's allowed to reach.
3. **Fetch each peer's `EndpointRecord`** → learns where everyone is.
4. **Program the SDN routing table** (§7): for every member the policy permits,
   establish a direct Noise session; for members it cannot reach directly, route
   via the assigned relay.
5. **Self-publish its own `EndpointRecord`**, refreshing periodically.
6. **Subscribe/poll** for changes — new members, policy/version bumps,
   revocations — and re-program as the map changes.

Result: every member independently reconstructs the *same* global map and
connects to *all* permitted peers → **automatic full mesh**, no manual pins, no
reliance on mDNS crossing subnets.

---

## 7. SDN routing & policy (the "software-defined" part)

The control plane doesn't just list peers — it **decides reachability**:

- **Direct** when a working endpoint pair exists (the common case).
- **Relay** when a pair can't connect directly (NAT/firewall/segment isolation —
  e.g. the Windows↔Ubuntu pair we hit). The manifest's `relays` list names nodes
  both ends can reach; the control plane routes the pair through one (existing
  DERP-style `crates/net/relay.rs`). This is a *control-plane decision*, made from
  the topology, not a manual per-node toggle.
- **Exit** for internet-bound traffic, restricted to `exit_eligible` nodes.
- **ACL** gates which pairs may form sessions at all (default allow-all among
  members; deny rules are admin policy).

This is the SDN payoff: **the admin programs intent** (who reaches whom, who
relays, who exits) once, signs it, and every node enforces it locally from the
distributed map.

---

## 8. Admin-only operations (the gated set)

Performed **only on the admin node** (it alone holds the CA key to sign), driven
from the admin console:

- Admit / evict members (issue / revoke certs) — *exists*.
- Edit the **manifest**: VIP subnet, crypto policy, **designate relays**,
  **designate exit nodes**, default ACL.
- Edit **policy/ACL** (group-to-group rules).
- Assign / override **VIPs**.
- Bump version, re-sign, publish to the DHT.

Every other node is **read-and-participate only**: it self-publishes its own
endpoint and enforces the admin's program. There is **no IPC or DHT path** for a
non-admin to mutate authoritative state — the daemon refuses admin ops unless it
holds the CA (today's `"not an admin node"` check), and authoritative DHT records
without a valid CA signature are ignored by every reader.

> Defense in depth: the admin console's *local* sensitive readouts (packet
> capture) keep their `--admin-allow` process gate ([ADMIN_CONSOLE.md](ADMIN_CONSOLE.md));
> the *network* authority here is the CA signature. Two independent gates.

---

## 9. Security model & threats

| Threat | Mitigation |
| --- | --- |
| Member forges membership/policy | No CA key → can't sign authoritative records; readers verify the CA sig |
| Node spoofs another's endpoint/VIP | Endpoint records are self-signed per node; VIP is bound in the admin directory |
| Malicious DHT node forges data | Can't — all records signed; it can only withhold/replay |
| Replay of an old manifest/directory | Monotonic signed `version`; endpoints use signed `seq` + timestamp |
| Revoked node lingers | Directory marks `revoked`; existing revocation gossip drops sessions |
| Topology disclosure via the DHT | Optional member-only encryption of records (§5); cleartext is signed-but-public in v1 |
| Admin key compromise | Full control (by design) — protect the admin key; rotation/secondary-admin is future work |

---

## 10. Mapping to current code

| Layer | Crate / file | Change |
| --- | --- | --- |
| CA / authority | `crates/membership` | add signing/verifying of manifest, directory, policy records |
| Control plane | `crates/overlay` | hold the global map; program routes from it (direct/relay/exit) |
| Distribution | `crates/dht` | generalize Kademlia store to signed key→record; publish/fetch/refresh manifest/directory/endpoint |
| Daemon wiring | `crates/daemon` | publish self endpoint; fetch+verify map; feed discovered peers from the directory into the engine |
| Data plane | `crates/engine`, `crates/net` | unchanged transport; relay selection driven by control plane |
| Admin UI | `gui-admin` | edit manifest/policy, designate relays/exits, publish (admin-only) |
| IPC | `crates/proto`, `crates/ipc` | new admin requests for manifest/policy edits + map readouts |

---

## 11. Phased plan (this doc = step "3"; then 1 → 2)

- **Phase 0 — this design doc.** ✅ Architecture + authority model agreed.
- **Phase 1 — DHT as control-plane store** (the user's "1"). Generalize the DHT to
  signed records; admin publishes the manifest + member directory; nodes fetch +
  verify + learn the **whole membership** and self-publish endpoints → **automatic
  full mesh** with no manual pins. Verify on Mac+Ubuntu+Windows
  ([[verify-all-three-platforms]]).
- **Phase 2 — SDN routing & policy** (the user's "2"). Topology-aware routing:
  ACL enforcement, automatic **relay selection for unreachable pairs**, exit-node
  policy — programmed by the admin, enforced everywhere.
- **Phase 3+ — hardening.** Member-only record encryption, admin-key rotation /
  secondary admins, map-change subscriptions (push vs poll).

Each phase is only "done" when it builds **and runs** on Ubuntu, Windows, and
macOS.

---

## 12. Open questions

- **VIP allocation:** keep identity-derived (`derive_virtual_ip`) or move to
  admin-assigned in the directory? (Identity-derived is simpler + collision-safe;
  admin-assigned is more SDN-pure.)
- **Map distribution:** poll the DHT on an interval (simple) vs. a
  subscribe/notify mechanism (timely, more complex). v1 = poll.
- **Bootstrap trust:** ship a default public bootstrap, or require the admin to
  run one? Either way it's non-authoritative.
- **Record privacy:** cleartext-signed (v1) vs member-only-encrypted (when?).
- **Multi-admin / key rotation:** out of scope for v1; the manifest could later
  carry multiple admin keys.

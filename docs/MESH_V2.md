# Lattice v2 — Multi-Mesh Architecture (admin-free)

> Status: **design**, supersedes the admin/CA-centric v1 control plane.
> Decided with the maintainer 2026-06-15. Open micro-decisions are marked
> **[DECIDE]** inline.

A single computer is **one node** that belongs to **many isolated meshes** at
once. There is no admin/CA. Authority is a decentralized **invite chain**. Each
mesh has its own cipher, its own crypto table, its own 1-byte address space, and
its own roster. Routing is **per-node exit selection** — every node picks its own
exit; there is no central, signed flow table.

The data plane stays **L3 TUN**: one virtual interface on the computer captures
all traffic, and a per-computer **policy table** decides, per flow, *which mesh*
(or `default` = untouched) carries it. Being at the TUN layer is what lets one
computer manage every mesh under a single policy.

---

## 0. What we tear out (vs v1)

**Removed entirely:**
- Network **CA / admin node** (`--network-key`, self-issued admin cert).
- Signed **`NetworkManifest`** + **`MemberDirectory`** DHT distribution.
- **Central SDN flow-table** (proto `flow.rs` as a *signed, shared* table) and
  its CLI (`lattice flow add/del/clear`) + the GUI flow-table editor.
- The separate **`gui-admin`** app (packet DPI inspector, crypto-swap lab,
  membership console).
- `lattice net issue / revoke / members`, `DesignateRelay`.

**Kept / repurposed:**
- L3 **TUN** data plane + the engine packet loop.
- **CryptoSuite** seam — but now *per-mesh* (each mesh selects its own cipher;
  the manifold/time-window research cipher is one choice among meshes).
- **Discovery** (mDNS LAN + Kademlia DHT) and **relay** + auto-election.
- **Exit-node** NAT/masquerade + kill-switch.

**Net effect:** the engine changes from *one network* to a *container of N
meshes*; authority changes from *one admin* to a *transitive invite chain*;
routing changes from *one signed flow table* to *each node's own exit pick*.

---

## 1. Node & multi-mesh model

- A computer = **one node** = one global identity keypair (Curve25519), stored
  once (`/var/lib/lattice/identity.key`). This is the "all-meshes" key.
- The node **creates or joins N meshes**. Each mesh is fully isolated: separate
  membership, cipher, crypto table, roster, 1-byte address space.
- **One TUN device** for the whole computer. A per-computer **policy table**
  (local, unsigned — it is *this user's* preference, not mesh state) maps each
  outbound flow to one of:
  - `default` → **untouched**, goes out the normal internet (VPN does nothing);
  - `mesh M via exit E` → encapsulated into mesh `M`, egressed at node `E`.
- **cur-mesh** = the mesh currently selected for egress in the app.
- **Priority rule:** if a flow resolves to `default` → untouched. If both a
  cur-mesh and an exit node are set → **cur-mesh's exit wins** and carries it.
- **Per-node exit:** each node independently chooses which mesh node is *its*
  exit. No node can impose routing on another (no central flow table).
- By default a mesh can reach **every network the computer can reach except the
  virtual addresses Lattice itself owns** (no mesh can hijack another mesh's
  overlay range).

---

## 2. Addressing — 1-byte, name-as-CIDR

In-mesh there are **no authenticated/real IPs**. Identity is a **name chosen at
join**, and the node is remembered as `name + join-order`.

- Each member gets a **1-byte in-mesh id** = join order, `1..=254`.
  `0` and `255` reserved (unset / broadcast).
- **Max 254 members per mesh** — this is exactly the 1-byte id space, and is
  configurable *downward*. (It also bounds invite-chain key growth, §3.)
- The **roster** maps `id ↔ name ↔ node-pubkey`, shared by all members
  (full in-mesh transparency, §4).
- **L3 mapping [DECIDE]:** the OS still needs an IP per peer for L3 routing. We
  present the 1-byte id as the **host octet** of a per-mesh overlay prefix, e.g.
  mesh `M` → `100.<f(M)>.<g(M)>.<id>/24`. So "name" is the byte; the kernel sees
  an IP whose last octet is that byte. (Alternative: a /16 per mesh with
  `id` in the low octet and a mesh index in the third — pick when we size the
  overlay range.) The base prefix is **not** fixed at `100.x`; it is the
  collision-free range chosen by the §9 coexistence pre-flight.

---

## 3. Membership — invite chain rooted in a master key (no CA admin)

**Genesis = key issuance.** Creating a mesh generates the **master keypair**
(public + private), picks the mesh cipher, and seeds the crypto table. The creator
is member **#1**. The **master private key lives ONLY on the creator's node** — it
is the mesh's root of trust, not an online CA.

**Genesis charter (immutable, master-signed).** All governance knobs are fixed at
creation and **welded to the mesh's root** — no field can change for the mesh's
life (immutable *for now*; a future controlled-amendment path is out of scope). The
charter is master-signed so a compromised member **cannot downgrade policy** (e.g.
flip a quorum-protected mesh to rate-limit, or C-i → C-ii). It carries:
- **invite topology** — `C-i` (master-gated) or `C-ii` (open chain);
- **re-cipher trigger policy** — for C-ii, `quorum(k)` or `rate-limit(period)`
  (§5); for C-i, master-only;
- **max members** (≤254);
- **initial cipher suite** (epoch 0; the *active* cipher then rotates via re-cipher,
  but the *policy* does not);
- the **master public key** (root of trust) + overlay prefix assignment.

**Member credential — no private-key sharing.** A joiner **generates its own
keypair** (private never leaves the device). The inviter issues a **signed cert**
binding `(member pubkey, node, name, join-order id)`. Day-to-day auth *and*
anti-theft challenge-response verify with **public keys + signatures** — *no
private key is ever shared to verify anything.* ("Combine the master with each node
into a unique per-node key" = exactly this cert binding, **not** copying the master
private into each node.)

**Invite topology (chosen at genesis):**
- **C-ii — open chain (DEFAULT):** *any* member may invite; the new cert is signed
  by the inviter and chains back to the master. No central approval — trust is
  transitive along the chain.
- **C-i — master-gated (opt-in at creation):** only the master (and any delegated
  master holders, below) may issue member certs.

**"Key complexity grows with members":** each cert chains to its inviter up to the
master, so verification walks a path that lengthens with depth — natural
back-pressure toward the **254 cap** (= the 1-byte id space).

**Two key kinds per node** (the "한 메쉬 / 모든 메쉬" keys): one **global node
identity** key (names the node everywhere) + one **per-mesh credential** (the signed
cert above). Same mesh ⇒ shared cipher ⇒ mutually decryptable; across meshes ⇒
nothing.

**Master authority delegation (disaster recovery).** Because the master private key
sits on a single node, losing that computer would strand the mesh (no future
rekey / expel / cert authority). The creator may therefore **delegate master
authority** to additional *deeply trusted* nodes — **only** for resilience, never
for verification (verification needs no private key, above):
- a **deliberate, manual export** — the user **copy-pastes** the master material
  (never an automatic transfer), and
- tags it with a **user-assigned number = a master-copy index**, so the mesh can
  **audit and individually revoke** a specific copy (if a backup holder is later
  compromised, revoke copy #N and rotate).

**[DECIDE / RECOMMENDED]** For the recovery goal specifically, prefer a **threshold
(k-of-n Shamir) backup** over a raw copy: split the master across trusted members so
it can be *reconstructed* only when k cooperate, and **no single backup node holds a
live master** day-to-day. Same loss-resilience, without multiplying the master's
attack surface. Raw copy-paste-with-index (passphrase-encrypted) is the simpler
fallback.

**Revocation** is not a CA action — it is **expel + rekey** (§5); delegated master
copies are revoked by index.

**[DECIDE]** cert-chain shape: linear chain (`cert_child` signed by `cert_parent`)
is simplest; a tree (path = credential) gives cheaper partial-rekey on expel. Lean
tree if expel/rekey cost matters.

---

## 4. Per-mesh crypto + crypto table

- **Every mesh has a different cipher** (always). The CryptoSuite is selected
  *per mesh* at genesis; the research manifold/time-window cipher is one option.
- **Crypto table:** each mesh owns a table recording its crypto methods **as
  hashes** (which suite, which epoch/keys, rotation history). Each table carries
  **permissions** (who may read / who may rotate).
- One computer holds **one crypto table per mesh**, each with distinct
  permissions — they never share keys or authority.
- This is the isolation guarantee: same mesh ⇒ shared cipher ⇒ readable;
  different mesh ⇒ different cipher + keys ⇒ opaque.

---

## 5. Capture detection & response (layered)

**Threat:** in-mesh transparency means everyone knows everyone's origin/identity.
So **one compromised node can leak the whole roster + mapping.** "Compromise"
splits into distinct attacks, and the defenses are layered (not exclusive):

| Attack | What the adversary gets | Defended by |
| --- | --- | --- |
| **Seized/stolen, powered-off** (offline disk) | reads stored crypto table + keys | **Layer A: at-rest split-key** |
| **Live malware/RAT** on a running node | table already unlocked in RAM | **Layer B: runtime cross-attestation** |
| **Malicious authenticated insider** | already holds the table | Layer B (detect → expel + rekey) |
| **Impostor / wrong-key join** | nothing, if caught | neighbor key verification |

- **Layer A — at rest (offline theft):** the crypto table is encrypted under a
  key that needs **neighbor assistance to unlock** (k-of-n share from the nearest
  neighbor node). A powered-off stolen disk is then useless. **Exempt when the
  mesh has only 1–2 nodes** (no neighbor to split with).
- **Layer B — runtime (live compromise):** neighbors **continuously
  cross-verify** keys. **≥2 verification failures → expel** that node from the
  mesh, **request immediate cipher change**, and **rekey/re-cipher the whole
  mesh**.
- **Scope of the 2-strike response = expel the node, NOT abolish the mesh.**
  Wiping the whole mesh on a per-node failure would be an attacker-pullable
  self-destruct (any glitch / one malicious member nukes everyone). Whole-mesh
  abolition is **parked** (dropped for now); if ever added it must sit behind a
  far higher bar — **quorum-confirmed** compromise or **master-key exposure** —
  never a single node's 2 strikes.
- **Local response on a compromise signal (decided):** the node **warns all its
  meshes**, then **wipes only the affected mesh's keys + crypto table** locally;
  its other meshes keep running.
- **Strength is a tunable knob** (the `k` in k-of-n, the cross-verify cadence,
  the failure threshold). **[DECIDE later]** — depends on the threat profile the
  maintainer wants to defend; default conservatively (k=2, exempt ≤2 nodes).

**How a mesh-wide rekey converges (serverless).** The mesh crypto state carries a
monotonic **epoch** (0 at genesis, +1 per re-cipher); every frame is tagged with its
epoch, and a node always adopts the **highest validly-signed epoch** — a lower (e.g.
broken) epoch can never be forced back (**rollback-proof**). A re-cipher is a
**signed record** `{ epoch+1, new cipher / derivation, reason, sig }` that **gossips**
member-to-member (reusing the revocation-gossip path, §10); because everyone takes
the highest valid epoch and epochs only rise, the mesh **converges with no
coordinator**, and offline nodes catch up on return. **Who may trigger is the
immutable genesis charter** (§3): `C-i` ⇒ master/delegated only; `C-ii` ⇒ either a
**quorum of `k` co-signers** or a **rate-limited single trigger**, fixed at creation.
Quorum `k=2` dovetails with capture detection — the two neighbors that caught a
compromise co-sign the very re-cipher that expels it.

---

## 6. Wire protocol & transport

**Transport is selectable: TCP, UDP, or QUIC** — chosen **per mesh** (and
overridable per flow). UDP is the default; QUIC (datagram mode, RFC 9221) for
DPI-hostile networks and roaming; TCP as a last-resort fallback. The existing
`net::Transport` trait is the seam; v2 adds `QuicTransport` and `TcpTransport`
beside `UdpTransport`.

**Header (front bytes), reconciled to L3.** The maintainer's spec was
`meshid(1) | source(1) | destination(url)`. At L3 the destination is an *in-mesh
node id*, and the real target IP rides inside the encapsulated packet (a URL is
an app-level name resolved *before* the TUN, so it never reaches this header).
We also add a **version** byte (v1 had none — no upgrade path) and a **type**
byte:

```
 0        1        2        3        4         5 ...
 +--------+--------+--------+--------+---------+------------------+
 | ver    | meshid | src    | dst    | type    |   payload        |
 +--------+--------+--------+--------+---------+------------------+
   1B       1B       1B       1B       1B        (cipher output)

 ver     protocol version (evolution)
 meshid  which mesh this frame belongs to        (≤256 meshes / computer)
 src     sender's in-mesh roster id              (1..=254)
 dst     recipient's roster id; = the EXIT node's id for egress
 type    0x01 HANDSHAKE_INIT  0x02 HANDSHAKE_RESP
         0x03 TRANSPORT (payload = encrypted raw IP packet)
         0x04 KEEPALIVE       0x05 CONTROL (rekey/expel/capture-alert)
 payload mesh-cipher AEAD output (per §4); for TRANSPORT the plaintext
         is the raw L3 IP packet from the TUN
```

- **Egress:** `dst` = the exit node's roster id; the exit decapsulates, reads the
  inner IP packet's real destination IP, and NATs it to the internet. Only the
  exit's location is exposed outside (the maintainer's anonymity rule).
- **In-mesh:** `dst` = the peer's roster id; origin is always visible in-mesh
  (`src` is in the clear-to-members header), satisfying "everyone sees who sent
  what".
- **[DECIDE]** whether `src`/`dst` live *outside* the AEAD (needed for relay
  forwarding without decrypt, but reveals the in-mesh graph to a relay) or are
  authenticated-but-encrypted (relay must be a member). Lean: outside-but-MAC'd,
  since relays are mesh members anyway.

---

## 7. UI — per-mesh view + computer-wide view (switchable)

The app must switch between **one mesh** and **the whole computer**:

- **Global view (computer-wide):** every mesh this node belongs to; which is
  cur-mesh; the **policy table** (flow → mesh/exit or default-untouched);
  per-mesh status + transport; capture-detection alerts across all meshes;
  add/leave a mesh.
- **Per-mesh view:** the selected mesh's **roster** (id / name / pubkey), this
  node's **exit selection**, the **crypto table** + active cipher + epoch, the
  in-mesh **live traffic** (who sent what — the transparency view), **invite**
  (mint a child key), **leave / force-rekey**, capture-detection status.
- **Switching** = a mesh selector (tabs or dropdown) plus a "global overview"
  mode. Default mesh selected ⇒ the global view shows "VPN idle, nothing routed".

---

## 8. Implementation impact

**Engine:** from single-network to a **`Mesh` container**. Today the engine holds
one membership/cipher/session set; v2 holds a `HashMap<MeshId, Mesh>` where each
`Mesh` owns its cipher, crypto table, roster (1-byte ids), transport choice,
sessions, and exit selection. The TUN read loop **demuxes** each outbound packet
to a mesh via the policy table, stamps the v2 header, and encrypts under that
mesh's cipher.

**New modules:**
- `mesh` — the per-mesh object (cipher, crypto table, roster, invite chain).
- `invite` — HKDF invite-chain key derivation + the 254 cap.
- `capture` — Layer A split-key at-rest + Layer B cross-attestation + expel/rekey.
- `policy` — the per-computer flow → mesh/exit table.
- `wire v2` — the 6-byte header + per-mesh AEAD framing.
- `transport` — add `QuicTransport`, `TcpTransport`.

**Removed code:** `membership::Admin` (CA/issue/revoke/manifest/directory),
daemon admin args + IPC arms (`IssueCert`/`RevokeMember`/`DesignateRelay`/
`Flow*`), `cli net issue/revoke/members` + `flow`, `gui-admin/`, the GUI
flow-table editor just added (`add_flow_rule`/`del_flow_rule`/`clear_flow_rules`
+ its panel).

**Migration note:** v1 and v2 wire formats are incompatible (header changes,
per-mesh ciphers, no manifest). This is a clean break, not an upgrade — v2 nodes
do not interop with v1.

---

## 9. Host-networking coexistence (Docker / Cilium / Tailscale)

**Decided: coexist, do not integrate.** Lattice v2 is a **host-level L3 overlay
that stays out of other networking systems' way**. Containers and pods are **not**
mesh members; making them members (a CNI plugin, per-netns TUN injection, sidecars)
is **explicitly out of scope** — a possible future track, not v2.

Why this is mostly free: Docker containers and k8s pods each live in their **own
network namespace** with their own routes; Lattice's TUN lives in the **host
namespace**. Different layers ⇒ they coexist by default. Conflict only arises on
three surfaces, which v2 must actively avoid:

1. **CIDR collision — the real landmine.** v1 hardcoded the overlay to
   `100.64.0.0/10`, which **Tailscale owns outright** and which **Cilium/k8s often
   use** for pod/service ranges. v2 **must not hardcode a range**:
   - the overlay prefix is **configurable**, and
   - at first run a **pre-flight scan** inspects host routes, Docker bridge subnets,
     and any CNI CIDRs, then **picks a free range and persists it** (so §2's
     `100.<f(M)>…` is *chosen*, not fixed). Refuse to start / warn if no clean range.
2. **No default-route hijack.** v1's full-tunnel exit does
   `ip route replace default dev tun`, which on a Docker/Cilium host swallows
   container egress and fights CNI routes. v2 uses **policy routing** instead:
   `ip rule` + a **dedicated routing table** carrying *only Lattice-owned flows*;
   the main `default` route is never replaced. The per-computer policy table (§1)
   is **namespace-aware** — host-only by default; it never captures another netns's
   traffic implicitly.
3. **Scoped netfilter.** Exit MASQUERADE/FORWARD rules go in **dedicated chains**,
   **respect Docker's `DOCKER-USER` chain**, and **never flip the global FORWARD
   policy** (the v1 `1c14706` "FORWARD REJECT" bug is exactly this hazard). On
   Cilium hosts, Lattice's port + overlay CIDR must be **allowlisted** in the host
   firewall, since Cilium's eBPF datapath can drop or short-circuit unrecognized
   traffic.

**MTU:** when a mesh runs *inside* another overlay (Cilium VXLAN/Geneve, a cloud
SDN), encapsulation stacks. Keep the §6 clamp **adaptive** (PMTUD-driven), not the
fixed 1380, so overlay-in-overlay doesn't silently fragment.

**Guarantee restated:** a mesh reaches every network the host can reach **except
Lattice's own auto-chosen overlay range and any range another tenant already owns**.

---

## 10. Discovery & rendezvous (admin-free)

Replaces v1's admin-signed **MemberDirectory** (torn out, §0). The primitives are
already built — DHT publish/lookup, mDNS, and the **revocation-gossip** transport
(`MessageType::Revocation`) — so this is **new admin-free semantics over existing
plumbing**, not from scratch.

- **Endpoint records — self-published, signed.** Each node publishes its own
  reachable endpoints to the DHT in a **self-signed `EndpointRecord`**
  `{ node, endpoints[], seq, at_ms, sig }` (already sketched in
  `SDN_DHT_ARCHITECTURE.md §4.2` — salvage that struct). Readers **verify the sig
  against the publisher's cert** (which chains to the master), so an endpoint can't
  be spoofed. v1 publishes endpoints **unsigned** today → adding the signature is
  the work.
- **Roster = gossiped certs, no signed directory, no quorum.** A node is "in the
  mesh" iff it holds a **valid cert chaining to the master**. Each cert is therefore
  **self-proving** — so the roster needs no admin and no quorum signature. It is just
  the **union of valid certs a node has seen**, gossiped member-to-member (the same
  union-CRDT pattern as revocation gossip, run on certs instead of serials;
  revocations subtract). Convergence is trivial because validity is per-cert.
- **Seed via the invite.** The invite blob carries the **inviter's endpoint(s)** as
  the bootstrap hint; the joiner dials the inviter to enter the mesh/DHT, then moves
  to self-published records + gossip. LAN peers also meet via mDNS. v1's invite is a
  bare 152-byte cert with no endpoint → embedding the seed is the work.

**Status (code audit):** primitives ~60% (DHT, cert signing, revocation gossip);
admin-free semantics ~0% built. New code = endpoint signatures, cert-gossip roster,
invite seed. No central directory; the **cert chain is the authority**.

---

## 11. Open decisions (collected)

**LOCKED:** coexist, not CNI [§9]; invite topology = **C-ii open-chain default,
C-i master-gated optional at genesis** [§3]; **whole-mesh abolition dropped** —
the 2-strike response is expel-node + rekey only [§5]; master private key held on
the creator node only, delegated for DR via manual copy + index [§3];
**re-cipher trigger + all governance knobs = immutable, master-signed genesis
charter** chosen at creation (C-ii: `quorum(k)` or `rate-limit`) — policy can't be
downgraded post-genesis [§3/§5].

1. **[§2/§9]** Overlay IP layout for the 1-byte id (per-mesh /24 vs /16 + mesh
   index) — within the auto-chosen, collision-free prefix.
2. **[§3]** Master backup scheme: threshold (k-of-n Shamir, **recommended**) vs
   raw passphrase-encrypted copy-paste-with-index.
3. **[§3]** Cert-chain shape: linear vs tree (tree = cheaper partial rekey on expel).
4. **[§5]** Capture-detection strength (`k`, cadence, threshold) + exact at-rest
   split-key scheme (Shamir vs pairwise neighbor wrap).
5. **[§6]** `src`/`dst` outside the AEAD (relay-friendly) vs inside (graph-hiding).
6. **Transport granularity:** per-mesh only, or also per-flow override.

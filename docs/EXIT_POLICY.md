# Exit Policy — chained vs isolated egress (genesis choice)

**Status:** design (not yet built). Chosen at mesh creation, immutable, carried in the
charter. Default = **isolate**.

This document fixes the exact semantics of how a mesh forwards traffic when nodes use
each other as **full-tunnel exits**, and adds a per-mesh, genesis-time choice between two
policies. It is grounded in the current data-plane code (`crates/mesh/src/dataplane.rs`
`decide()`, `crates/meshd/src/exit.rs`, `crates/meshrun/src/lib.rs`).

---

## 1. The invariant (NOT optional): member ↔ member is always direct

Every packet is classified by the data-plane flow table (`decide()`):

| Destination | Decision | Path |
| --- | --- | --- |
| an overlay address `100.<p>.<mesh>.<member>` (another **member**) | `ToOverlayOwner` | sealed **directly to that member** (`seal_to(owner)`) over this node's own underlay (or a relay) — **never via any exit** |
| anything else (the **internet**) | `ToExit(exit)` | sealed to the selected exit member, which NATs it out |

The overlay range `100.64.0.0/10` is a **more specific route** than the full-tunnel default
(`0.0.0.0/1` + `128.0.0.0/1`), so even with full-tunnel ON, member-addressed packets still
enter the TUN, hit `decide()`, and are sent straight to the owning member. **Turning on
full-tunnel never pulls member-to-member traffic through an exit.**

> So in the user's scenario — node 3 sending a request to node 2 — node 3 reaches node 2
> **directly over its own network** (overlay peer-to-peer), regardless of any exit/full-tunnel
> setting on either node. This is hard-wired by the flow table and is **not** governed by the
> exit policy below.

What the exit policy *does* govern is **internet (non-member) egress** only.

---

## 2. The problem: full-tunnel exit chaining

Setup (the user's example):

- **Node 1** full-tunnels through **Node 2** (`node1.exit = node2`).
- **Node 3** full-tunnels through **Node 1** (`node3.exit = node1`).

How an internet packet from node 3 flows **today**:

1. Node 3's default route is diverted to its TUN (full-tunnel). Packet `src=100.x.3 dst=1.1.1.1`
   → `decide()` → internet → `ToExit(node1)` → sealed to node 1.
2. Node 1 receives it, `Inbound::Deliver` → **writes it to node 1's TUN**. The kernel forwards
   it (`ip_forward=1`) by node 1's routes.
3. **Because node 1 *also* has full-tunnel ON**, node 1's default route is *its* TUN → the packet
   re-enters node 1's data plane → `decide()` → internet → `ToExit(node2)` → sealed to node 2.
4. Node 2 NATs it out its WAN.

Net egress path: **3 → 1 → 2 → internet**. The traffic node 3 meant to send out *node 1's*
network actually leaves from *node 2's* network. This "chaining" happens because **traffic a
node forwards on behalf of others follows that node's own default route**, and full-tunnel has
diverted that default route.

Whether this chaining is desirable depends on intent (onion-style multi-hop vs. "I picked node
1 because I want node 1's egress"). So it becomes a **per-mesh choice**.

---

## 3. The two policies

### `isolate` — egress at the exit's real network (default, recommended)

> **A node that exits traffic for others always sends that traffic out its own real WAN —
> even if the node full-tunnels its *own* traffic somewhere else.**

- Node 3 → exit node 1 ⇒ egress = **node 1's real network**. Full stop. No `3→1→2`.
- A node's *own* internet traffic still follows *its* full-tunnel; only **forwarded**
  (on-behalf-of-others) traffic is pinned to the real WAN.
- **No multi-hop chains, no routing loops** — even cyclic configs (node 2's exit = node 3,
  node 3's exit = node 1, …) cannot loop, because forwarded traffic never re-enters a tunnel.
- Matches the intent "each node can use its own original network."

### `chain` — forwarded traffic follows the exit's own tunnel (onion)

> **Traffic forwarded to an exit follows that exit node's own full-tunnel**, producing
> multi-hop egress (`3 → 1 → 2 → …`).

- Useful for deliberate layered/relayed egress (hide the true entry node behind several hops).
- The operator is responsible for avoiding cycles; the mesh does **not** guarantee loop-freedom
  under `chain`.
- This is exactly today's behavior.

Both policies keep the §1 invariant (member ↔ member always direct). The only difference is
the egress of **internet** traffic that a node forwards **for other members**.

---

## 4. Mechanism

The classification "is this packet one I am exiting *for someone else*?" is precisely
**source address ∈ overlay range `100.64.0.0/10`** (a node's own traffic is sourced from its
real LAN IP; forwarded traffic carries the originating member's overlay IP, and the exit NAT
already keys on `-s 100.64.0.0/10`). So the two policies differ by one OS-level rule installed
when a node becomes an exit (`enable_nat`):

### `isolate`
Keep a routing path to the **real** default gateway and force overlay-sourced traffic onto it,
independent of the full-tunnel default:

- **Linux** (canonical):
  ```sh
  # snapshot the real default into a side table once
  ip route add default via <real_gw> dev <real_if> table 100      # "real" table
  # overlay-sourced (=forwarded) traffic always uses the real table
  ip rule add from 100.64.0.0/10 lookup 100 priority 1000
  ```
  The node's own full-tunnel still does `ip route replace default dev tun` in the **main**
  table; the `ip rule` makes forwarded traffic bypass it. Torn down on `disable_nat`.
- **macOS:** pf `route-to` on the NAT ruleset, e.g.
  `pass out route-to (<real_if> <real_gw>) inet from 100.64.0.0/10 to any` so overlay-sourced
  forwarded traffic leaves via the real gateway even while the default route points at the TUN.
- **Windows:** WinNAT egresses its `InternalIPInterfaceAddressPrefix` (100.64.0.0/10) via the
  external adapter; verify it is the real adapter and not the Wintun under full-tunnel (pin with
  a per-prefix route / interface metric if needed).

### `chain`
Install **no** such rule. Forwarded traffic follows the main-table default — i.e. the exit's own
full-tunnel — exactly as today.

> The §1 member-direct invariant needs **no** OS rule — it is already enforced in user space by
> `decide()` (overlay → owner). The exit policy only adds/omits the egress rule above.

---

## 5. Where it's chosen — the charter

`exit_policy` joins the genesis charter next to `expel` / `header_placement`
(`crates/mesh/src/charter.rs`), with `#[serde(default)]` so older invites/persisted state still
deserialize (→ `Isolate`):

```rust
/// How a node egresses internet traffic it forwards AS AN EXIT for other members.
/// Member↔member traffic is always direct regardless (enforced by the flow table).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub enum ExitPolicy {
    /// Forwarded traffic always egresses the exit's REAL network, even if that node
    /// full-tunnels its own traffic. No chains, no loops. (default)
    #[default]
    Isolate,
    /// Forwarded traffic follows the exit's own full-tunnel → onion-style multi-hop egress.
    Chain,
}

pub struct GenesisCharter {
    // …
    #[serde(default)]
    pub exit_policy: ExitPolicy,
}
```

- **Immutable** (genesis-only), like the rest of the charter; carried into every invite and
  gossiped/validated as part of the charter, so all members agree.
- **CLI:** `lattice new <name> --me <id> [--exit-policy isolate|chain]` (default isolate). Shown
  in `lattice info` (e.g. `exit-policy  isolate`).
- **GUI:** a radio on the "create mesh" screen, with the friendly one-liner for each option and
  isolate pre-selected.

---

## 6. Interactions / edge cases

- **Kill-switch** (`arm_kill_switch`): unchanged. It probes the internet *through the tunnel*
  for the node's **own** egress; the isolate rule only affects forwarded traffic.
- **Exit NAT** (`enable_nat`): the masquerade rule (`-s 100.64.0.0/10`) is identical for both
  policies; isolate just adds the routing rule so the masqueraded packets leave the real WAN.
- **Relay** vs **exit**: orthogonal. Relay forwards *sealed mesh frames* between peers who can't
  connect directly; exit forwards *decrypted internet* packets. Exit policy concerns only the
  latter.
- **src-learn / reply path**: replies arrive at the real WAN (isolate) and reverse-NAT back into
  the TUN to the originating member — same as a normal single-hop exit.
- **No exit set / split-tunnel**: no effect; there is no forwarded internet traffic to pin.

---

## 7. Loop-freedom (isolate)

Under `isolate`, forwarded internet traffic **never re-enters any TUN** (it is pinned to a real
WAN by source-based routing). Therefore no sequence of per-node exit selections can form an
egress cycle. Under `chain`, loop-freedom is the operator's responsibility (documented).

---

## 8. Build plan

1. **Charter:** add `ExitPolicy` + `GenesisCharter.exit_policy` (serde default Isolate);
   thread through invite/validation; surface in `lattice info`.
2. **CLI/GUI genesis:** `--exit-policy` flag + create-screen radio (default isolate, friendly
   copy).
3. **Daemon (Linux first):** in `exit.rs`, when `enable_nat` runs under `Isolate`, install the
   side table + `ip rule`; tear down in `disable_nat`. Plumb the active mesh's `exit_policy` to
   the exit-enable call.
4. **macOS / Windows:** pf `route-to` / WinNAT verification.
5. **Verify live:** 3-node `3→1→2` matrix — under isolate node 3's egress IP = node 1's WAN
   (no chain); under chain node 3's egress IP = node 2's WAN. Member↔member ping stays direct in
   both.

Member-direct (§1) is already true today and is covered by existing flow-table tests; this work
adds only the internet-egress policy.

# Exit sharing (per-mesh `exitable`)

Whether THIS node lets a mesh's members use **my** internet connection as their exit. Per-mesh,
**opt-in, default OFF**, local to the node (never gossiped).

## Why (threat model)

Serving as an exit is the most sensitive thing a node can do: a member who routes their internet
through me uses **my IP** (it takes the blame for their traffic) and my bandwidth, and I see their
decrypted internet traffic. If serving were automatic, a **mesh intruder** (an admitted or
compromised member) could turn *every* node into a free proxy through their IP. So:

> A mesh member — including an attacker — can **not** route their internet through this node
> unless the node explicitly marked that mesh `exitable`. The blast radius of an in-mesh attacker
> stays on the nodes that *chose* to serve.

This is orthogonal to **consuming** an exit (routing MY internet through someone else — `lattice
exit` / `make egress` / split-tunnel). Provide and consume are two independent switches.

## Behaviour

- `exitable = false` (default): this mesh's subnet gets **no** forwarding/NAT — a member pointing
  their exit at me finds their traffic dies here (not proxied).
- `exitable = true`: this mesh's overlay subnet (`100.80.<mesh_id>.0/24`) gets IP forwarding +
  source-NAT out my WAN, so its members can egress through me. **Only that mesh's subnet** is
  NAT'd — serving one mesh never proxies another.
- A **dedicated pinned exit** (`MESHD_ADVERTISE` set, e.g. Oracle) is treated as exitable for its
  meshes automatically, so dedicated exits keep working with zero migration; ordinary nodes
  default off and opt in per mesh.

Membership/reachability is unaffected either way — you always reach a mesh's members (printer,
SSH, …) over the overlay regardless of `exitable`. `exitable` only controls internet forwarding.

## Usage

```bash
lattice exitable <mesh>          # show current
lattice exitable <mesh> on       # let this mesh's members use my internet as their exit
lattice exitable <mesh> off      # stop (default)
```
GUI: a per-mesh **exitable** toggle in the User-mode Meshes list. Persisted to the mesh's state
file (`exitable`), reloaded on start.

## How it maps to a per-node policy

The old "who may use me as an exit" policy question (all meshes / only the selected one / never)
is expressed as **per-mesh flags**: all-on = every mesh may; one-on = just that mesh; all-off
(default) = nobody. More granular and safe-by-default than a global enum.

## Implementation

- `crates/meshd/src/exit.rs` — `enable_nat(subnet, isolate)` / `disable_nat(subnet)` (3 OS, 🔴):
  forwarding + NAT for exactly one overlay subnet. Idempotent; **both paths** purge every legacy
  all-`100.64/10` MASQUERADE + FORWARD-ACCEPT rule from older always-on builds (v0.7.10 — a pinned
  exit only ever calls `enable_nat`, so the purge had to run there too, not just in `disable_nat`).
  Linux is per-subnet (multi-mesh correct); macOS keeps a single pf file (one exitable mesh at a
  time — a documented limit, since real exits are Linux); Windows per-subnet WinNAT.
- **`isolate` interaction (v0.7.9):** on a pinned exit the isolate rule pins *forwarded* traffic to
  the real WAN, but the served subnet contains the exit's OWN overlay IP — so overlay-internal
  traffic must bypass isolate (Linux `ip rule to 100.64.0.0/10 lookup main` at higher priority;
  macOS `route-to … to ! 100.64.0.0/10`), else member↔member replies leak out the WAN. See
  [`EXIT_POLICY.md`](EXIT_POLICY.md).
- `crates/meshd/src/main.rs` — `MeshState.exitable` (persisted, serde-default false); `bringup`
  serves only if `exitable || pinned`; IPC `SetExitable` → `PostAction::ApplyExitable` →
  `apply_exitable` enables/disables NAT for the subnet live.
- `crates/mesh/src/ipc.rs` — `SetExitable`, `MeshSummary.exitable`, `MeshDetail.exitable`.

## Related

- Extensions are separately scoped: a connector only sees/acts on meshes the user currently
  authorized in its grant (docs/EXTENSIONS.md §3, live-rechecked). Same "only what I authorized"
  principle for the connector plane.

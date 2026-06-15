# Lattice GUI — UX spec (v2 multi-mesh)

> **Source of truth for the user-facing GUI.** Pairs with `docs/MESH_V2.md` (the
> architecture) and `crates/mesh/src/ipc.rs` (the `meshd` control-plane contract).
> Build the GUI *from this doc* — do not improvise structure in code.

## 0. Principle — two perspectives, never mixed

The GUI has exactly **two modes**, and the **top widget bar is the only switch**:

- **User mode** — *this computer.* Manage the **set** of meshes you belong to.
- **Mesh mode** — *one selected mesh.* Operate that single mesh.

Rule of thumb: **everything that is about a specific mesh lives in Mesh mode;
only the meshes-list lives in User mode.**

## 1. Top widget bar (always visible, full width)

```
[● egress: home · exit #2]                 [ User | Mesh ]   [⬢ mesh ▾]
 └ STATUS — far left                        └ mode toggle     └ dropdown: meshes ONLY
```

- **Far left = status.** The *egress* summary: which mesh currently routes this
  computer's traffic and through which exit (or `egress: origin` — your computer's
  normal/original internet, no mesh routing — when none); a colored dot; `meshd
  offline` when the daemon is down. All status lives here.
- **Right = two SEPARATE controls (deliberately not redundant):**
  - A `User | Mesh` segmented **view toggle** — the perspective. `User` = the
    meshes list; `Mesh` = the mesh you opened via `manage ›`.
  - An **egress dropdown** `[Origin · mesh …]` — a widget to pick *where your
    traffic exits*: `Origin` (your normal internet) or a mesh. Changing it sets
    egress immediately. Egress can **also** be set in User mode's Meshes list (§2) —
    same underlying setting, two entry points.
- **Egress ≠ view.** The dropdown (egress) and the toggle / `manage` (view) are
  independent: you can *operate* mesh A while *routing through* mesh B or Origin.

## 2. User mode — manage the set of meshes

- **Sidebar: `Meshes` only.** No per-mesh tabs.
- **Content (Meshes):**
  - At the top sits **Origin** — your computer's normal internet (no mesh routing).
    `make egress` on it returns traffic to origin (clears the mesh egress). It wears
    the `egress` badge when no mesh routes traffic.
  - Below it, every mesh you belong to: name, `#id`, member count, epoch, exit, and
    an `egress` badge on the one that routes traffic.
  - **Create a mesh** (name, your in-mesh name, max members ≤254).
  - Per mesh row: **`manage ›`** → enter Mesh mode for it; **`make egress`** → route
    this computer's traffic through it.

## 3. Mesh mode — operate ONE mesh (the dropdown selection)

- **Sidebar: per-mesh tabs**, all scoped to the selected mesh:
  `Overview · Status · Peers · Traffic · Membership · Network · Topology`.
- **Overview** (the mesh's home):
  - Charter (immutable): invite topology, re-cipher trigger, cipher, max members.
  - Epoch; my exit.
  - **Roster**: `id · name · pubkey-fp` (this node marked *me*).
  - Actions: **set my exit**, **admit a member**, **make egress**, **wipe mesh**
    (the §5 local compromise response).
- **Status / Peers / Traffic / Network / Topology**: this mesh's operational
  views. **[TODO — backend]** these currently render the v1 single-node daemon's
  data; in v2 they must be re-scoped to *per-mesh* data, which needs `meshd` to
  expose per-mesh peers/traffic/topology. Until then they are placeholders here.

## 4. Data source

- The GUI talks to **`meshd`** (the v2 control-plane daemon) over the unix socket
  `/tmp/lattice-meshd.sock`; the protocol is `crates/mesh/src/ipc.rs` (newline
  JSON). The Tauri Rust layer is a **thin proxy** — a single `meshd(request)`
  command that ships one JSON line and returns the response. All UI logic lives in
  the front-end + `meshd`; the Rust side holds no v2 state.
- The legacy v1 daemon (`/tmp/lattice.sock`) is separate and only backs the
  not-yet-rescoped operational panels.

## 5. Front-end state model

- `MODE ∈ {"user","mesh"}` — the view perspective (widget-bar toggle).
- `CURRENT_MESH` — the mesh Mesh-mode operates on, set via `manage ›` (NOT the
  egress dropdown).
- **Egress is server state** (`meshd` `SetCurrent`): set by the egress dropdown or
  the User-mode list; the far-left status mirrors it.
- Sidebar nav items are tagged by mode group; only the active mode's group shows.

## 6. Out of scope / future (track here before coding)

1. Re-scope the operational panels (Status/Peers/Traffic/Network/Topology) to
   per-mesh `meshd` data — requires backend (`meshd` per-mesh queries).
2. Capture-detection status surface (§5 of MESH_V2.md): per-mesh alerts.
3. Invite flow (cert-based) + roster gossip view, replacing the demo `admit`.
4. Master-key / charter detail surfaces (read-only; never expose the master key).
5. Transport (TCP/UDP/QUIC) selector per mesh.

> Any GUI change starts by updating this doc, then the code — so structure is
> decided in prose, not re-litigated in the UI.

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
  - An **egress dropdown** `[Default network · mesh …]` — a widget to pick *where
    your traffic exits*: `Default network` (your normal internet) or a mesh. Changing
    it sets egress immediately. Egress can **also** be set in User mode's Meshes list
    (§2) — same underlying setting, two entry points.
- **Egress ≠ view.** The dropdown (egress) and the toggle / `manage` (view) are
  independent: you can *operate* mesh A while *routing through* mesh B or the Default
  network.

Below the widget bar sit **two stacked banners** (hidden unless active):

- **Update banner** — on launch the front-end calls the `check_update` Tauri
  command (queries GitHub Releases). If a newer build exists it shows *"New version
  X available"* with **Update** (backs up mesh state via `ExportState`, then
  `open_url` to the download page) and **Later** (dismiss).
- **Attack banner** — global; when any mesh is armed for self-destruct it shows the
  countdown and a creator-only **All clear**. (See `docs/GUI_CRYPTO.md` G-3.)

## 2. User mode — manage the set of meshes

- **Sidebar: `Meshes`, `Create mesh`, `Join mesh`.** No per-mesh tabs. (Create and
  Join are separate pages so the Meshes list stays a clean "what am I in / where
  does traffic exit" view.)
- **Meshes (the list):**
  - At the top sits **Default network** — your computer's normal internet (no mesh
    routing). `use this` returns traffic to it (clears the mesh egress). It wears
    the `egress`/`in use` badge when no mesh routes traffic.
  - Below it, every mesh you belong to: name, `#id`, member count, epoch, exit, and
    an `egress` badge on the one that routes traffic.
  - Per mesh row: **`manage ›`** → enter Mesh mode for it; **`make egress`** → route
    this computer's traffic through it.
  - A **`＋ New mesh`** button jumps to the Create mesh page.
- **Create mesh:** a *Basics* card (name, your in-mesh name, max members 1–254
  default 254, permanent cipher select) + a *Conditions* card with two toggles —
  **"Only I can invite" (master-gated)** (off = open-chain, any member can invite,
  the default) and **"Ephemeral — self-destruct when isolated"** (off by default,
  laptop-friendly). Create → `CreateMesh{ name, my_name, max_members, cipher,
  self_destruct, master_gated }`, then jump into the new mesh.
- **Join mesh:** the 3-message invite exchange (Get my join code → paste invite +
  algorithm → Join). See `docs/GUI_PAGES.md` §2b.

## 3. Mesh mode — operate ONE mesh (the dropdown selection)

- **Sidebar: per-mesh tabs**, all scoped to the selected mesh:
  `Overview · Peers · Topology · Warnings · Configs` (Warnings carries a red count
  badge of open alerts).
- **Overview** (the mesh's home — summary + roster only; the controls live in
  Configs):
  - A **warnings** link when any are active (jumps to the Warnings tab).
  - Charter line: invite topology · re-cipher trigger · max members ·
    persistent/ephemeral. Cipher; epoch; health (`live/total · floor T`); my exit.
  - **Roster**: `id · name · pubkey-fp` (this node marked *me*).
  - Action: **make egress**.
- **Peers / Topology**: live per-mesh views (`MemberView` carries `endpoint` +
  `state`; poll every 3 s). Peers is a member table with state badges; Topology is a
  radial graph (green = live, violet = exit, dashed = idle).
- **Warnings**: active alerts for this mesh, derived from `meshWarnings(d)` — a
  detailed **attack** card (countdown + creator-only All-clear) and a **below-quorum**
  amber card; "✓ No warnings" when healthy. A desktop notification (`notify`) fires
  once when an attack is first detected.
- **Configs**: all the controls as cards — Egress & routing (set exit / make egress),
  Peer address (`SetPeer`), Invite a member (`CreateInvite`), Security / re-cipher
  (`Recipher`), and a Danger zone (Report attack → `ReportAttack`; wipe mesh →
  `RemoveMesh`).

## 4. Data source

- The GUI talks to **`meshd`** (the v2 control-plane daemon) over the unix socket
  `/tmp/lattice-meshd.sock`; the protocol is `crates/mesh/src/ipc.rs` (newline
  JSON). The Tauri Rust layer is a **thin proxy** — a single `meshd(request)`
  command that ships one JSON line and returns the response. All UI logic lives in
  the front-end + `meshd`; the Rust side holds no v2 state.
- **A few non-meshd Tauri commands** back the desktop-shell features: `check_update`
  (GitHub Releases query), `open_url` (download page), `notify` (desktop
  notification on attack). The new meshd request `ExportState` backs up meshes
  before an update.

## 5. Front-end state model

- `MODE ∈ {"user","mesh"}` — the view perspective (widget-bar toggle).
- `CURRENT_MESH` — the mesh Mesh-mode operates on, set via `manage ›` (NOT the
  egress dropdown).
- **Egress is server state** (`meshd` `SetCurrent`): set by the egress dropdown or
  the User-mode list; the far-left status mirrors it.
- Sidebar nav items are tagged by mode group; only the active mode's group shows.

## 6. Out of scope / future (track here before coding)

1. Per-mesh **Traffic** view (who↔who, bytes/packets) — needs a `meshd` flows query.
2. A richer **Security** surface (capture-detection detail + crypto epoch/table,
   MESH_V2.md §4–§5) beyond the current Warnings page.
3. Transport (TCP/UDP/QUIC) selector per mesh.
4. Master-key / charter detail surfaces (read-only; never expose the master key).

> Any GUI change starts by updating this doc, then the code — so structure is
> decided in prose, not re-litigated in the UI.

# Lattice Extensions — connector framework

> Status: **daemon + GUI BUILT** (phases 1–3 of §11: event bus, `Hello`/`Subscribe`
> streaming, grant store, `Advertise`/`ListServices` + `CTRL_REGISTRY` gossip — IPC
> smoke-verified against a live `meshd`; plus the User-mode **Extensions** GUI page).
> **MiniSync connector still to do** (in progress). First reference connector: **MiniSync**
> (folder sync), see [§10](#10-reference-connector--minisync).

## 0. What an extension is

An **extension** is a **separate program** (its own process, any language) that
connects to the running `meshd` daemon and uses the mesh as a substrate: it learns
who the members are, advertises/discovers services, and reacts to mesh events. It is
a **connector** — it bridges some external app or service (VNC, a folder, Docker, a
document) onto the mesh. It is **not** a plugin compiled into the daemon and **not** a
browser extension.

Three properties drive the whole design:

1. **Connector** — it consumes mesh state (peers, services, events) and may advertise
   its own service; it does not implement mesh crypto/routing.
2. **Standalone program** — it runs as its own OS process. A crash, hang, or bug in an
   extension can never take down the tunnel or the daemon.
3. **Lattice decides what it sees** — on *enable*, the user grants a subset of the
   scopes the extension requested. `meshd` only emits granted topics on that connection
   and logs every access. This is the **auditable-scope** trust model (not a hard
   sandbox: the extension still runs as the user, but every grant is explicit and every
   access is recorded).

### Key insight — most connectors never touch packets

VNC, folder sync, Docker, etc. all run **over the overlay IP** (`100.x.x.x`) that the
mesh already provides. What they need from Lattice is **identity + discovery + events**,
not raw packets. So the default scope set is *control-plane only*; `data:packet-*` is a
separate, rarely-granted scope. This keeps the common case safe by construction.

## 1. Architecture

```
  ┌─────────────────────────────────────────────────────────────┐
  │ meshrun data-plane loop (TUN ↔ UDP hot path)                 │  ← never blocked
  │   crates/meshrun/src/lib.rs : run()                          │
  └───────────────┬─────────────────────────────────────────────┘
                  │ publish-only, fire-and-forget
                  ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Event bus  =  tokio::sync::broadcast<MeshEvent>             │  ← NEW, in meshd State
  │   bounded; a slow subscriber is dropped (lagged), never      │
  │   back-pressures the loop                                    │
  └───────────────┬─────────────────────────────────────────────┘
                  │
        ┌─────────┴──────────┐  one tokio task per connector connection
        ▼                    ▼
  ┌───────────┐        ┌───────────┐
  │ ext task A│        │ ext task B│   filter by granted scope → push events;
  │           │        │           │   accept commands ← gate by scope
  └─────┬─────┘        └─────┬─────┘
        │ unix socket / named pipe (same meshd endpoint, newline-JSON)
        ▼                    ▼
  ┌───────────┐        ┌───────────┐
  │connector A│        │connector B│   ← SEPARATE PROCESSES (any language)
  │ (minisync)│        │  (vnc)    │
  └───────────┘        └───────────┘
```

### Threading / isolation model (the "how to separate threads" answer)

- **No new OS threads in the daemon for extensions.** The only new concurrency is
  **one `tokio` task per connected extension** — same weight and pattern as the existing
  `gossip` / `kill-switch` / `self-destruct` background tasks in `meshd/main.rs`. They
  share state through `Arc<Mutex<…>>` and the broadcast bus.
- **The extension body is a separate process.** Its own threads/runtime are its own
  concern.
- **The critical boundary is a lossy channel, not a thread split.** The data-plane loop
  (`meshrun`) *publishes* events to a **bounded `broadcast`** and moves on. If an
  extension task can't keep up, its receiver lags and **events are dropped for that
  extension only** (`broadcast::error::RecvError::Lagged`) — the tunnel is never slowed.
  This is what makes a misbehaving connector harmless.

## 2. Transport & framing

Extensions speak the **same wire protocol as the GUI**: connect to the meshd endpoint
and exchange **newline-delimited JSON**.

- Unix: `/tmp/lattice-meshd.sock` (`DEFAULT_SOCKET`, `meshd/main.rs:56`)
- Windows: `\\.\pipe\lattice-meshd` (`meshd/main.rs:58`)
- One JSON value per line, `\n`-terminated, both directions.

The connection lifecycle in `serve_conn` (`meshd/main.rs:903`) is already a persistent
read loop (`while let Ok(Some(line)) = lines.next_line()`). Today it is strictly
request→one-response. Extensions add a **streaming mode**: after a successful
`Subscribe`, the same connection also carries **server-pushed `Event` lines**, while the
connector can keep sending commands. See [§6](#6-meshd-changes).

## 3. Connector handshake & manifest

### Manifest (shipped with the connector, declares what it wants)

```json
{
  "id": "minisync",
  "name": "MiniSync — folder sync",
  "version": "0.1.0",
  "exec": "minisync",                 // how meshd would launch it (Phase 2 lifecycle)
  "scopes": ["events:peer", "registry:read", "registry:advertise"],
  "service": { "proto": "minisync", "default_port": 48211 }
}
```

### Enable flow (the user decides what is shared)

1. User opens **Extensions** page in the GUI, picks a connector, sees its requested
   scopes, approves a subset, **and picks which meshes it may use** (an explicit allow-list,
   or "all meshes incl. future"). With nothing picked the extension is enabled but allowed
   on no mesh — so enabling never silently exposes a mesh the user didn't choose.
2. GUI → meshd `EnableExtension { id, scopes, all_meshes, meshes }`. meshd stores a grant:
   `{ id → { token (random 16B hex), scopes, enabled, all_meshes, meshes } }` in
   `~/.lattice/meshd/extensions.json` (0600), and returns the `token`.
3. The connector process authenticates with that token.

The per-mesh allow-list is enforced on every mesh-bearing call (`Advertise`/`Unadvertise`/
`ListServices` from a connector) and on the event stream — an event for a mesh outside the
grant is dropped before it reaches the connector. (`ListServices` from the management GUI —
no `Hello` — is not mesh-gated, so the GUI's cross-mesh services view still works.)

### Per-connection handshake (connector → meshd)

```jsonc
// 1. connector announces itself
{ "Hello": { "id": "minisync", "version": "0.1.0", "token": "ab12…" } }
// meshd → granted scopes (the scopes the grant holds)
{ "HelloOk": { "scopes": ["events:peer","registry:read","registry:advertise"] } }

// 2. connector subscribes to a subset of bus TOPICS (not scope names): each topic is
//    gated by its matching scope — `peer`→events:peer, `service`→registry:read, etc.
{ "Subscribe": { "topics": ["peer","service"] } }
"Ok"
// from here meshd pushes Event lines on this connection (see §5)
```

> **Topics vs scopes.** A *scope* is what the user grants (`events:peer`, `registry:read`,
> …). A *topic* is a bus channel you `Subscribe` to (`peer`, `service`, `exit`, `health`).
> Each topic requires its matching scope ([§4](#4-scope-catalog)/[§5](#5-event-stream)). The
> manifest lists **scopes**; `Subscribe` lists **topics**.
>
> **Wire note.** `Response::Ok` serializes as the bare JSON string `"Ok"` (a unit enum
> variant), not `{"Ok":null}`. Errors are `{"Error":{"message":"…"}}`.

`Hello` with an unknown/disabled/`token`-mismatched id → `Error{message}` and the
connection is closed.

## 4. Scope catalog

| Scope | Grants | Risk |
|---|---|---|
| `events:peer` | peer up/down, roster + overlay IPs, member online state | low |
| `events:exit` | exit / full-tunnel status changes | low |
| `events:health` | quorum/health, attack-armed, decrypt-fail warnings | low |
| `registry:read` | query services other members advertised | low |
| `registry:advertise` | publish "this node offers service X at `100.x.x.x:port`" | low |
| `command:exit` | call `SetExit` / `SetCurrent` (programmatic egress) | **high** — explicit |
| `command:flows` | edit the SDN flow table (`SetFlows`) | **high** — explicit |
| `data:packet-meta` | per-flow 5-tuple + byte counts (no payload) | medium |
| `data:packet-raw` | raw packet payloads | **very high** — explicit, off by default |

`data:packet-*` are **not** needed by the example connectors and should stay
ungranted unless a connector genuinely inspects traffic (IDS, DNS).

## 5. Event stream

After `Subscribe`, meshd pushes one JSON line per event:

```jsonc
{ "Event": {
    "topic": "events:peer",
    "seq": 1422,                 // monotonic per connection; gap ⇒ events were dropped (lagged)
    "ts_ms": 1718900000000,
    "data": {                    // shape depends on topic
      "kind": "peer_up",
      "mesh": 42, "member": 3, "name": "alice",
      "overlay_ip": "100.80.42.3", "endpoint": "203.0.113.5:41042"
    }
} }
```

Event `data` payloads reuse the existing view DTOs (`MemberView`, `MeshSummary`,
`TrafficView` in `crates/mesh/src/ipc.rs`) wherever possible, so connectors and the GUI
see the same shapes.

A `seq` gap is the connector's signal that it lagged and should re-query current state
(`ListServices`, `MeshInfo`) rather than assume it saw everything.

## 6. meshd changes

Concrete edits, all in `crates/meshd` + `crates/mesh/src/ipc.rs`:

1. **New `Request` variants** (`ipc.rs:20`): `Hello`, `Subscribe`, `EnableExtension`,
   `DisableExtension`, `ListExtensions`, `Advertise`, `Unadvertise`, `ListServices`.
   New `Response` variants (`ipc.rs:186`): `HelloOk`, `Services`, `Extensions`, plus a
   pushed `Event` envelope.
2. **Event bus**: add `bus: tokio::sync::broadcast::Sender<MeshEvent>` to meshd `State`.
   Subsystems that already produce `LoopEvent`s (the drainer at `main.rs:1138`) and the
   gossip/health tasks publish `MeshEvent`s to it. Bounded capacity (e.g. 1024);
   lag = drop-for-that-subscriber.
3. **Streaming in `serve_conn`** (`main.rs:903`): on `Subscribe`, split off a writer
   task that owns the write half and forwards `bus.subscribe()` events (scope-filtered)
   as `Event` lines; the read half keeps handling commands. (Restructure the single
   `wr` into an `mpsc` feeding one writer, so events and command-responses interleave
   safely.)
4. **Grant store**: `extensions.json` (0600) under the state dir; loaded at startup
   next to the mesh persistence (P-S1).
5. **`request_mutates`** (`main.rs:550`): register the mutating new variants
   (`EnableExtension`, `Advertise`, …) so they persist.
6. **Service registry gossip**: new control tag `CTRL_REGISTRY = 0x08` in
   `meshrun/lib.rs` (next after `CTRL_FLOWS = 0x07`, `lib.rs:431`). Advertised services
   gossip + merge mesh-wide exactly like the roster (`CTRL_ROSTER`) — newest-per-(member,
   service) wins. This is the one genuinely new mesh-core piece; everything else is
   plumbing existing state to a new consumer.

### Service registry shape

```rust
struct ServiceRecord {
    member: MemberId,
    proto: String,        // "minisync", "vnc", …
    port: u16,            // listening port on the member's overlay IP
    name: String,         // human label
    meta: serde_json::Value,
    seq: u64,             // newest-wins per (member, proto)
}
```

`ListServices { mesh, proto? }` → `Services([{ member, name, overlay_ip, proto, port,
meta, online }])`. `overlay_ip` is derived from the roster; `online` from peer liveness.

## 7. GUI changes

- New **Extensions** entry in the User-mode sidebar (`gui/index.html`,
  `gui/src/main.js`). Lists installed connectors, enable/disable toggle, and a scope
  approval panel (checkboxes for each requested scope). All via the existing `meshd()`
  proxy — no new Tauri command needed.
- Optional per-mesh "Services" view: render `ListServices` so users see what's
  advertised (e.g. "alice offers VNC on 100.80.42.3:5900").

## 8. Lifecycle ownership

- **Phase 1 (MVP):** connector is launched independently (by the user, a script, or the
  GUI) and authenticates with its grant token. `meshd` does not spawn it. Simplest,
  cross-platform, good enough to prove the model.
- **Phase 2:** `meshd` owns lifecycle — `EnableExtension` spawns `manifest.exec` and
  supervises/restarts it, so extensions work headless (CLI/server) with no GUI. Requires
  per-OS process management; defer until the protocol is proven.

## 9. Security notes

- Auditable, not sandboxed: the connector runs as the user. The value is **explicit
  grants + access logging**, not OS-level confinement. Document this honestly.
- The grant `token` is a local secret in a 0600 file; it authenticates *which* connector
  a connection claims to be, gating scopes. It is not a network credential.
- `registry:advertise` lets a connector publish reachability info that gossips mesh-wide
  — treat advertised `meta` as untrusted input on the consuming side.
- `command:*` and `data:packet-raw` are high-risk and must be surfaced distinctly in the
  enable UI (separate confirmation), never bundled into a one-click "allow all".
- Repo is public — no real infra IPs in examples (use `100.x.x.x` / `203.0.113.x`).

## 10. Reference connector — MiniSync

**Goal:** keep a folder in sync across mesh members, peer-to-peer over the overlay, with
zero manual addressing. It proves the whole framework using only **control-plane**
scopes — no packet access.

**Scopes:** `events:peer`, `registry:read`, `registry:advertise`.

**How it uses the framework:**
1. On start: `Hello` + `Subscribe{["events:peer"]}`.
2. `Advertise { proto:"minisync", port:48211, meta:{folder:"SharedFolder"} }` — tells the
   mesh "I sync this folder here".
3. `ListServices{ proto:"minisync" }` → discovers every other member running MiniSync
   and their `overlay_ip:port`.
4. Opens a normal TCP connection to each peer's `100.x.x.x:48211` **over the overlay**
   (Lattice already routes/encrypts it) and runs its own sync protocol there.
5. Reacts to `events:peer` (`peer_up`/`peer_down`) to start/stop syncing as members come
   and go.

MiniSync itself (the sync protocol, file watching, conflict handling) lives **entirely
in the connector process** and is independent of Lattice. Lattice only answers "who is
here and where do I reach them."

## 11. Build order

1. ✅ **meshd**: event bus + `Hello`/`Subscribe`/`Event` streaming in `serve_conn`; grant
   store (`extensions.json`); `EnableExtension`/`DisableExtension`/`ListExtensions`; coarse
   `peer` events on mesh add/remove + roster change.
2. ✅ **meshd**: service registry + `CTRL_REGISTRY` (`0x08`) gossip + `Advertise` /
   `Unadvertise` / `ListServices`; soft-state expiry; `service` events.
3. ✅ **GUI**: User-mode **Extensions** page (`gui/index.html` + `gui/src/main.js`
   `renderExtensions`) — enabled-grants list with per-grant scope chips + token copy +
   enable/disable, a bundled connector catalog with per-scope approval checkboxes (risk
   labelled), and a live **Discovered services** table aggregated across all meshes. All
   via the existing `meshd()` proxy; no new Tauri command. (meshd has no manifest catalog,
   so the connector's requested scopes are bundled in the GUI's `CONNECTOR_CATALOG`.)
4. ⬜ **MiniSync** connector (separate program) against the above.
5. ⬜ Phase-2 lifecycle (meshd-supervised connectors) once the protocol is proven.

Implemented seams (for the connector author): `crates/mesh/src/registry.rs`,
`crates/mesh/src/ipc.rs` (new `Request`/`Response` + `ExtensionView`/`ServiceView`),
`crates/meshd/src/main.rs` (`serve_conn` streaming, `ext_hello`/`ext_subscribe`/`scope_gate`,
`advertise`/`list_services`, the event bus + grant store), `crates/meshrun/src/lib.rs`
(`CTRL_REGISTRY`, `LoopEvent::Registry`).

# MiniSync — reference Lattice connector

MiniSync keeps a folder in sync across the members of a Lattice mesh,
peer-to-peer over the overlay. It is the **reference connector** for the Lattice
extension framework described in [`docs/EXTENSIONS.md`](../../docs/EXTENSIONS.md)
(§0–§5, §10).

It is a **separate program** — its own process, decoupled from the daemon. It
uses Lattice only for **identity + discovery + events** (control-plane scopes),
and runs its **own** simple sync protocol over plain TCP to each peer's overlay
IP. It never touches packets and implements no mesh crypto or routing. A crash or
hang here can never affect the tunnel or `meshd`.

```
 ┌────────────┐  newline-JSON over unix socket / named pipe   ┌────────────┐
 │  minisync  │ ───── Hello / Subscribe / Advertise ────────▶ │   meshd    │
 │ (this crate)│ ◀──── HelloOk / events:peer / Services ────── │ (daemon)   │
 └─────┬──────┘                                                 └────────────┘
       │  discovers peer overlay_ip:port via ListServices
       ▼
 ┌────────────┐   own TCP sync protocol over the overlay   ┌────────────┐
 │  minisync  │ ◀───── manifest + file transfer ─────────▶ │  minisync  │
 │  node A    │        (Lattice routes/encrypts this)      │  node B    │
 └────────────┘                                            └────────────┘
```

## Decoupling

This crate is **not** part of the core Cargo workspace — the same treatment
`gui/` and `fuzz/` get. Its `Cargo.toml` declares an empty `[workspace]`, making
this directory its own workspace root, so building or testing it never pulls in
or rebuilds `crates/mesh`, `crates/meshd`, etc. It has **no path dependency** on
any workspace crate; the meshd wire types it needs are mirrored in
[`src/ipc.rs`](src/ipc.rs).

## Build & test

```sh
cd connectors/minisync
cargo build --release
cargo test            # unit tests + the two-instance localhost sync demo
```

`cargo test` runs, among others,
`tests/integration.rs::two_instances_sync_through_mock_meshd`: it spins up an
in-process **`mock_meshd`** ([`src/mock.rs`](src/mock.rs)) for each of two
MiniSync instances, lets them discover each other through the mock, and asserts
that a folder converges between them on `127.0.0.1` — proving the connector
end-to-end **without a running daemon**.

## Running for real (once meshd ships the framework)

Phase 1 lifecycle (docs/EXTENSIONS.md §8): you launch the connector yourself and
it authenticates with a grant token.

1. **Enable the extension** in the Lattice GUI's *Extensions* page, approving the
   three scopes MiniSync requests: `events:peer`, `registry:read`,
   `registry:advertise`. This mints a token stored in
   `~/.lattice/meshd/extensions.json` (0600).
   *(Until the GUI page lands, a CLI/IPC `EnableExtension { id: "minisync",
   scopes: [...] }` against meshd produces the same grant + token.)*

2. **Run the connector**, giving it the folder, your mesh id, and the token:

   ```sh
   MINISYNC_TOKEN=<token-from-step-1> \
   minisync --folder ~/SharedFolder --mesh 0 --port 48211
   ```

   Run it on every member that should share the folder. Each one advertises
   `minisync` on its overlay IP, discovers the others via `ListServices`, and
   reconciles the folder over the overlay. New members are picked up
   automatically from `events:peer`.

### Options

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--folder DIR` | — | *(required)* | Folder to keep in sync. |
| `--port N` | — | `48211` | TCP port the sync server listens on. |
| `--meshd PATH` | `LATTICE_MESHD_SOCK` | `/tmp/lattice-meshd.sock` (unix) / `\\.\pipe\lattice-meshd` (windows) | meshd IPC endpoint. |
| `--token T` | `MINISYNC_TOKEN` | *(required)* | Grant token from *Enable*. Prefer the env var. |
| `--mesh N` | — | `0` | Mesh id to advertise/discover on (see gap #1). |
| `--self-ip IP` | — | — | This node's overlay IP, to exclude self from discovery (see gap #2). |
| `--sync-interval S` | — | `5` | Seconds between reconcile passes. |
| `--advertise-refresh S` | — | `30` | Seconds between re-advertise + re-list. |

Logging is via `tracing`; set `RUST_LOG=minisync=debug` for detail.

## Sync protocol & conflict policy

The sync wire ([`src/sync/wire.rs`](src/sync/wire.rs)) is our own,
self-contained, and independent of Lattice: length-prefixed `bincode` frames over
TCP. One session reconciles **both directions** at once:

1. initiator → `Manifest` (path, size, mtime, SHA-256 per file)
2. responder → `Reconcile { want, push }` — what it wants pulled, plus the files
   it is newer on (shipped inline)
3. initiator → `Files` — the files the responder asked for

**Conflict policy (v0.2): last-writer-wins by mtime.** For each path the larger
modification time wins; ties (equal mtime, different content) break on the larger
SHA-256 hex, so both peers independently pick the same winner and converge.
Identical content is never re-transferred. Received files are written atomically
(temp + rename) and stamped with the source mtime so both sides reach an
identical `(mtime, hash)` and stop transferring.

### v0.2 limitations

- **Whole-file, in-memory transfers** — no chunking or resume; a single file is
  capped at `MAX_FRAME` (512 MiB).
- **No deletion propagation** — there are no tombstones, so deleting a file on
  one node does not delete it elsewhere; it reappears on the next reconcile.
- **No rename detection** — a rename looks like delete + create.
- **No Unicode normalization** of paths — a file whose name differs only by
  NFC/NFD form between platforms can appear twice.
- Dotfiles/dotdirs (`.git`, `.minisync*`) and symlinks are skipped.

Path traversal is rejected on both send and receive (`safe_join`): a peer can
only ever write inside the configured sync root.

## Contract gaps found against `docs/EXTENSIONS.md`

While implementing against the spec (and the in-progress meshd code on the
`feat/extensions-meshd` branch) the following mismatches surfaced. Per the task
constraints these are recorded here rather than by editing the spec:

1. **`Advertise` / `ListServices` require a `mesh` id.** The §10 examples show
   `Advertise { proto, port, meta }` and `ListServices { proto }` with no mesh,
   but `crates/mesh/src/ipc.rs` makes `mesh: MeshId` mandatory on both. The
   connector therefore takes a `--mesh` flag (default `0`). There is also no
   control-plane request within the granted scopes for a connector to *enumerate*
   the meshes it is in (`ListMeshes`/`MeshInfo` are management calls), so the mesh
   id must be supplied out-of-band. Worth either adding a scoped "my meshes" query
   or documenting `mesh` in the §10 example.

2. **Subscribe topic name is the short form `"peer"`, not `"events:peer"`.**
   §3/§5 show `Subscribe { topics: ["events:peer"] }` and an event
   `"topic":"events:peer"`, but meshd's `scope_for_topic` matches only
   `"peer" | "exit" | "health" | "service"`, and the pushed `Event.topic` is the
   short `"peer"`. The connector subscribes with `"peer"` (so it works against the
   real daemon) and accepts either form on inbound events. The *scope* name
   granted in `HelloOk` remains the long `"events:peer"`.

3. **`Response::Ok` is the bare JSON string `"Ok"`**, not `{ "Ok": null }` as §3
   suggests — it is a serde unit variant. The connector parses the real form.

4. **No `is_me` flag on `ServiceView`.** `ListServices` returns the caller's own
   advertised service too, with no marker to identify self. The connector offers
   `--self-ip` to filter self out; absent that, a node may open a harmless
   no-op sync session to itself.

5. **`events:peer` is not emitted yet** by meshd (build order §11 step 1 is still
   in progress on the branch). The connector is written to react to it, and the
   `mock_meshd` emits it, so this side is ready; it also re-queries `ListServices`
   on its refresh timer, so discovery works even before peer events flow.

## Layout

```
src/
  ipc.rs       meshd's newline-JSON control wire, mirrored (no workspace dep)
  meshd.rs     connector handshake + discovery loop (produces the peer set)
  sync/        the folder reconcile engine (consumes the peer set)
    manifest.rs  scan → (path, size, mtime, hash); safe_join traversal guard
    wire.rs      length-prefixed bincode sync frames
    mod.rs       diff (LWW), atomic apply, TCP server + reconcile loop
  config.rs    runtime configuration
  mock.rs      in-process mock_meshd test harness (unix)
  lib.rs       wiring: server + meshd client + sync loop
  main.rs      CLI
tests/
  integration.rs   two instances sync through mock_meshd on localhost
```

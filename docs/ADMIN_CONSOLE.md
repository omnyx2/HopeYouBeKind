# Lattice Mesh Admin Console — design

A **separate** desktop application for the mesh administrator: manage membership
(enroll / evict), inspect traffic down to the individual packet, and run
encryption-protocol experiments by swapping the crypto suite at runtime and
comparing it live.

This is the design/plan written **before** implementation. It enumerates every
feature, the new daemon ⇄ console IPC contract, the daemon-side plumbing each
feature needs, the security trade-offs, the UI layout, and a phased build plan.

> Scope decisions (locked):
> 1. **Delivery:** a standalone admin app (`Lattice Admin.app`), distinct from the
>    user GUI — consistent with the deliberate admin/user split in commit
>    `826c362`.
> 2. **Traffic:** a **full packet-level inspector** (Wireshark-style: per-packet
>    timeline, header decode, payload hex). This exposes **decrypted plaintext**.
> 3. **Crypto:** **swap-experiment focused** — runtime selection/switching of the
>    `CryptoSuite`, with handshake size/timing comparison. Observability UI is
>    secondary.

---

## 1. Security posture (read first)

The admin console concentrates the mesh's most sensitive capabilities in one
surface. Like [HEALTH_CHECK.md](HEALTH_CHECK.md), we state the trade-offs plainly
rather than hide them.

What the console can see/do, and why it is sensitive:

| Capability | Exposure |
| --- | --- |
| Full member roster + topology | Every node's id, virtual IP, label, status |
| **Packet-level inspector** | **Decrypted inner-packet payloads in plaintext** — the daemon already holds these post-decrypt; the console surfaces them |
| Issue / revoke certs | Direct control of the network CA (admit or evict any node) |
| Runtime crypto swap | Changes the live encryption of all sessions |

**Gating.** The daemon must not answer these to any local process:

- **CA operations** (issue/revoke/members) are *already* gated daemon-side: only a
  daemon started with `--network-key` (an admin node) answers them; others get
  `"not an admin node"` (see `crates/daemon/src/main.rs`). No change needed.
- **Packet capture** (plaintext) and **crypto swap** are new and equally
  sensitive. They will be gated behind a single **admin capability gate**: a new
  `--admin-allow <process-name>` allow-list, mirroring the health-check gate
  (`SO_PEERCRED`/`LOCAL_PEERPID` → caller process name; see
  [HEALTH_CHECK.md](HEALTH_CHECK.md)). Default: empty (disabled) — capture and
  swap are **off** unless the operator opts in by naming the console binary.
  - This is the same "name ≠ identity" weak gate; documented as such. It exists
    to keep capture/swap off by default, not as a real trust boundary. The IPC
    socket is `0666`, so the real boundary remains "trust every local process."

**Payload visibility is deliberate.** The packet inspector showing plaintext is
the point (it is a research/diagnostic tool on a network you administer). It is
off unless `--admin-allow` names the console and a capture is explicitly started.

---

## 2. Architecture

```
┌────────────────────────┐         newline-JSON over /tmp/lattice.sock
│  Lattice Admin.app      │  ───────────────────────────────────────────►  ┌───────────────┐
│  (new Tauri app,        │   Request::{Members, IssueCert, RevokeMember,   │ lattice-daemon │
│   gui-admin/)           │             Revocations, CaptureStart/Stop,     │  (admin node)  │
│                         │             Packets{after}, CryptoSuites,       │                │
│  Overview · Members ·   │             SetCryptoSuite, SessionDetails, …}   │   engine +     │
│  Traffic · Crypto Lab   │  ◄───────────────────────────────────────────   │   monitor +    │
└────────────────────────┘         Response::{… new variants …}             │   crypto reg.  │
                                                                             └───────────────┘
```

- **New app:** `gui-admin/` — a second Tauri app in the repo, structurally a copy
  of `gui/` (vanilla JS + Vite + Tauri 1.6, same dark theme tokens). It depends on
  `lattice-ipc` + `lattice-proto` exactly like the user GUI. Bundle id
  `dev.lattice.admin`, productName `Lattice Admin`.
- **Daemon additions:** a bounded packet ring buffer in the traffic monitor, a
  crypto-suite registry with runtime swap, and the new IPC handlers + capability
  gate. No new transport; everything rides the existing Unix-socket IPC.
- **Transport model:** IPC stays **request/response, polling**. The packet stream
  is delivered by **cursor polling** (`Packets { after: <seq> }`), not a push
  stream — it fits the existing line-based `serve` loop with no protocol change.

---

## 3. Feature catalogue

### A. Membership & eviction (the "admin" pillar)

Re-exposes the three capabilities removed from the user GUI in `826c362`, plus a
revocation view.

1. **Network identity panel** — `NetworkInfo`: network id (full + fingerprint),
   **admin badge** (`is_admin`), member count, revocation count. (User GUI fetches
   but hides `is_admin`; the console shows it.)
2. **Member roster** — `Members` → `Vec<MemberEntry>` (node_id, fingerprint,
   serial, label, revoked). Live table, auto-refresh. Sort/filter by label/status.
3. **Enroll a member** — `IssueCert { node_id, label }` → `Token(hex)`. Form:
   node id (64-hex, validated) + optional label → returns a join token, shown with
   copy button (and optional QR for transfer).
4. **Evict a member** — `RevokeMember { node_id }`, with a confirm dialog. Shows
   that revocation gossips on the next keepalive tick (≈5 s) and that the peer's
   session drops mesh-wide. Roster row flips to `revoked`.
5. **Revocation list** — new `Revocations` request → list of `{ serial, node_id?,
   revoked_at }` the node knows (for audit). The CRL is already in the engine;
   this just surfaces it.

Daemon work: tiny — re-expose existing handlers; add one read-only `Revocations`
query. No engine logic changes.

### B. Packet-level traffic inspector (the "see everything" pillar — full DPI)

The monitor already observes the **plaintext inner IP packet** on both paths
(`on_outbound` pre-encrypt, `on_inbound` post-decrypt; see
`crates/engine/src/lib.rs`). Today it only keeps **aggregated flows**
(`FlowRecord`, max 512). The inspector adds a **per-packet ring buffer** beside
the aggregation.

1. **Capture control** — start/stop, with an optional filter (by peer, protocol,
   port). While stopped, no per-packet data is retained (only the existing
   aggregate flows keep running). `CaptureStart { filter }` / `CaptureStop` /
   `CaptureStatus`.
2. **Live packet timeline** — newest-first table of recent packets: `seq`,
   timestamp, direction (tx/rx), peer fingerprint, `src→dst` (ip:port), protocol,
   length, TCP flags. Cursor-polled via `Packets { after: <last_seq> }`.
3. **Packet detail** — click a row → full decode: IPv4 header fields (version,
   IHL, TTL, proto, total length, src/dst), TCP/UDP header (ports, and for TCP:
   flags, seq/ack, window), and the **payload as hex + ASCII**.
4. **Flow ↔ packet drill-down** — the existing aggregated-flow view (peers,
   protocols, throughput, duration) sits on top; selecting a flow filters the
   packet timeline to it.
5. **Aggregate analytics** (free from existing data): total mesh throughput,
   per-peer / per-protocol breakdown, top-talkers, flow duration (small monitor
   addition: track `created` alongside `last`).

Daemon work (new plumbing):
- `PacketRecord { seq, at_ms, dir, peer, protocol, src, dst, length, tcp_flags,
  payload: Vec<u8> }` and a bounded **ring buffer** (`VecDeque`, configurable cap,
  e.g. `--capture-buffer 4096`, default modest). Monotonic `seq` for cursor polls.
- Extend `parse_packet` to also pull **TCP flags / seq / ack / window** (today it
  stops at ports). Capture the payload slice (bounded length per packet, e.g.
  first N bytes, `--capture-snaplen`).
- `monitor.record()` gains a capture path guarded by the capture-on flag + filter;
  when off it is a no-op (zero overhead, zero retention).
- New IPC: `CaptureStart/Stop/Status`, `Packets { after }` → `Packets(Vec<…>)`.
  All gated by the admin capability gate (plaintext!).

### C. Crypto-suite swap lab (the "research" pillar — swap-experiment focused)

The crypto is abstracted behind `trait CryptoSuite` (`crates/crypto/src/suite.rs`)
with one impl today (`NoiseSuite` = `Noise_IK_25519_ChaChaPoly_BLAKE2s`).
Selection is **compile-time** (`Engine::with_suite`); `--crypto <name>` is noted
as "not wired yet" in `docs/CRYPTO_SUITE.md`. The lab wires runtime selection and
makes the seam comparable.

1. **Suite registry & catalogue** — a name→constructor registry. List available
   suites with their parameters: `CryptoSuites` → `Vec<CryptoSuiteInfo { name,
   pattern, dh, aead, hash }>`. Ship **≥2 suites** so comparison is meaningful —
   e.g. the default ChaChaPoly suite plus an AES-GCM variant
   (`Noise_IK_25519_AESGCM_SHA256`) behind the same trait.
2. **Current suite + runtime swap** — `CryptoCurrent` shows the active suite;
   `SetCryptoSuite { name }` swaps the engine's `Arc<dyn CryptoSuite>` and triggers
   the existing **resync** (drop sessions → re-handshake all under the new suite),
   the same mechanism `join_network` uses. Wire the `--crypto <name>` startup flag
   to the registry too.
3. **Handshake comparison** — capture per-handshake metrics: init/resp message
   sizes (bytes on the wire) and handshake wall-clock duration, tagged by suite.
   `CryptoStats` → a small table the console renders as a **side-by-side
   comparison** (suite × {init bytes, resp bytes, median handshake ms}).
4. **Session inspector** — per peer: active suite name, session age, **rekey
   countdown** (`rekey_due` uses age + message count; default 120 s / 2^60 msgs),
   send counter, replay-window position/rejections. `SessionDetails` →
   `Vec<SessionDetail>`. Read-only; for watching the live protocol.
5. **Handshake event log** — a scrolling log of `handshake initiated` / `session
   established (initiator|responder)` / `rekey` / `peer revoked, session dropped`,
   surfaced from the engine (today these are `tracing` logs; add a small bounded
   in-memory event ring + `CryptoEvents { after }`, reusing the cursor-poll
   pattern).

Daemon work (new plumbing):
- Crypto registry + a second `CryptoSuite` impl (AES-GCM) in `crates/crypto`.
- Engine: hold the suite behind a swappable handle; `set_suite(name)` → resync.
  Record handshake sizes/durations into a small stats struct; an event ring.
- New IPC: `CryptoSuites`, `CryptoCurrent`, `SetCryptoSuite`, `CryptoStats`,
  `SessionDetails`, `CryptoEvents`. Swap is gated (admin capability); reads can be
  admin-node-gated.

---

## 4. New IPC contract (`crates/proto/src/ipc.rs`)

All additive — existing variants unchanged. Requests use the existing
`#[serde(tag="cmd", rename_all="snake_case")]`; responses
`#[serde(tag="ok", content="data", rename_all="snake_case")]`.

**Requests (new):**

| Request | Fields | Gate | Returns |
| --- | --- | --- | --- |
| `Revocations` | — | admin node | `Revocations(Vec<RevocationEntry>)` |
| `CaptureStart` | `filter: CaptureFilter` | admin capability | `CaptureState` |
| `CaptureStop` | — | admin capability | `CaptureState` |
| `CaptureStatus` | — | admin capability | `CaptureState` |
| `Packets` | `after: u64` (cursor) | admin capability | `Packets(Vec<PacketRecord>)` |
| `CryptoSuites` | — | admin node | `CryptoSuites(Vec<CryptoSuiteInfo>)` |
| `CryptoCurrent` | — | admin node | `CryptoSuite(CryptoSuiteInfo)` |
| `SetCryptoSuite` | `name: String` | admin capability | `Done` / `Error` |
| `CryptoStats` | — | admin node | `CryptoStats(Vec<SuiteStat>)` |
| `SessionDetails` | — | admin node | `SessionDetails(Vec<SessionDetail>)` |
| `CryptoEvents` | `after: u64` | admin node | `CryptoEvents(Vec<CryptoEvent>)` |

**New structs (sketch):**

```rust
pub struct CaptureFilter { pub peer: Option<NodeId>, pub protocol: Option<String>, pub port: Option<u16> }
pub struct CaptureState  { pub active: bool, pub buffered: usize, pub cap: usize, pub dropped: u64, pub filter: CaptureFilter }
pub struct PacketRecord  { pub seq: u64, pub at_ms: u64, pub dir: String /*tx|rx*/, pub peer: Option<String>,
                           pub protocol: String, pub src: String, pub dst: String, pub length: u32,
                           pub tcp_flags: Option<String>, pub payload: Vec<u8> /*snaplen-bounded*/ }
pub struct CryptoSuiteInfo { pub name: String, pub pattern: String, pub dh: String, pub aead: String, pub hash: String, pub active: bool }
pub struct SuiteStat     { pub name: String, pub handshakes: u64, pub init_bytes: u32, pub resp_bytes: u32, pub median_ms: u32 }
pub struct SessionDetail  { pub peer: String, pub suite: String, pub age_secs: u64, pub rekey_in_secs: i64,
                           pub send_counter: u64, pub replay_latest: u64, pub replay_rejects: u64 }
pub struct RevocationEntry { pub serial: u64, pub node_id: Option<String>, pub revoked_at: u64 }
pub struct CryptoEvent   { pub seq: u64, pub at_ms: u64, pub kind: String, pub peer: Option<String>, pub detail: String }
```

The console (a Tauri app) wraps each in a `#[tauri::command]` exactly like the
user GUI wraps `Status`/`Peers`/`Flows`.

---

## 5. Daemon-side changes, by crate

| Crate | Change |
| --- | --- |
| `crates/proto` | New `Request`/`Response` variants + structs above. |
| `crates/crypto` | A `registry` (name→`Arc<dyn CryptoSuite>`); a 2nd suite (`Noise_IK_25519_AESGCM_SHA256`). Surface suite parameters via the trait (`pattern()/dh()/aead()/hash()` or one `info()`). |
| `crates/engine` (`monitor.rs`) | Per-packet ring buffer (capture-gated, filtered, snaplen-bounded), extended TCP parse (flags/seq/ack/window), flow `created` timestamp. |
| `crates/engine` (`lib.rs`) | Swappable suite handle + `set_suite()`→resync; handshake size/duration stats; session-detail accessor (age, rekey, counters, replay); bounded crypto-event ring. |
| `crates/daemon` | IPC handlers for all new requests; the `--admin-allow` capability gate (reuse the health-gate peer-name resolver in `lattice-ipc`); flags `--crypto`, `--capture-buffer`, `--capture-snaplen`. |
| `crates/ipc` | None (the peer-name resolver already exists for the health gate; reuse it for the admin gate). |

---

## 6. Admin app — UI / UX

Sidebar app, same dark theme tokens as `gui/src/styles.css`. Four sections:

```
┌───────────┬──────────────────────────────────────────────────────────┐
│ ◎ Overview│  Network 7e074d71…   ● admin   members 2   revocations 0   │
│ ⧉ Members │  ┌── Members ─────────────────────────────────────────┐   │
│ 📊 Traffic│  │ fp        node-id…   serial label      status  [⨯]  │   │
│ 🧪 Crypto │  │ 7dbce35e  7dbc…f917  3     ubuntu-host live   evict │   │
│           │  │ …                                                  │   │
│ ───────── │  └────────────────────────────────────────────────────┘   │
│ ● online  │  [ enroll: node-id ________  label ____  (Issue) ]        │
└───────────┴──────────────────────────────────────────────────────────┘
```

- **Overview** — network identity, admin badge, member/revocation counts, live
  peer map (reuse `Peers`), mesh health summary.
- **Members** — roster table with per-row **Evict**; enroll form → token (copy/QR);
  revocation list.
- **Traffic** — top: flow table (peers/protocols/throughput/duration) + capture
  controls (start/stop, filter). Bottom: **packet timeline** (seq, time, dir, peer,
  src→dst, proto, len, flags). Click a packet → **detail drawer** with header
  decode + hex/ASCII payload.
- **Crypto Lab** — current suite + **switch** dropdown; suite catalogue; **A/B
  comparison table** (init/resp bytes, median handshake ms per suite); per-session
  inspector (suite, age, rekey countdown, counters, replay); handshake event log.

ASCII mock — Crypto Lab:

```
Active suite:  Noise_IK_25519_ChaChaPoly_BLAKE2s     [ switch ▾ ]
Catalogue:
  • Noise_IK_25519_ChaChaPoly_BLAKE2s   DH 25519  AEAD ChaCha20Poly1305  Hash BLAKE2s   ● active
  • Noise_IK_25519_AESGCM_SHA256        DH 25519  AEAD AES-256-GCM        Hash SHA-256
Comparison (live):
  suite              handshakes  init B  resp B  median ms
  ChaChaPoly         12          120     120     3
  AES-GCM            5           120     120     4
Sessions:
  peer      suite       age   rekey-in  send#   replay-rej
  7dbce35e  ChaChaPoly  62s   58s       1.2k    0
```

---

## 7. Build & packaging

- New dir `gui-admin/` mirroring `gui/`: `package.json` (`lattice-admin-gui`),
  `vite.config.js` (port 5174 to coexist with the user GUI's 5173),
  `src-tauri/{Cargo.toml,tauri.conf.json,src/main.rs}`, `index.html`, `src/`.
- `tauri.conf.json`: productName `Lattice Admin`, identifier `dev.lattice.admin`,
  window title `Lattice Admin`, **no bundled daemon** (admin attaches to an
  already-running admin daemon; it does not spawn one).
- Dev: `cd gui-admin && npm i && npm run tauri dev`. Build: `npx tauri build
  --bundles app` → `Lattice Admin.app`.
- Add `gui-admin` to the workspace if the Rust side is a workspace member.

---

## 8. Phased implementation plan

Each phase is independently testable; daemon and console land together per phase.

- **Phase 0 — Scaffold + proto.** Create `gui-admin/` (copy `gui/`, restyle nav,
  strip user-only tabs). Add all new `Request`/`Response`/structs to
  `crates/proto` (compile only; handlers can return `Error "unimplemented"` until
  their phase). Admin app boots, connects, shows Overview from existing
  `Status`/`NetworkInfo`/`Peers`.
- **Phase 1 — Membership admin.** Re-expose `Members`/`IssueCert`/`RevokeMember`
  (daemon handlers already exist) + new read-only `Revocations`. Full Members tab.
  *No engine changes.* Verifiable live against the running Mac admin daemon.
- **Phase 2 — Packet inspector.** Daemon: ring buffer, capture gate
  (`--admin-allow`), extended parse, `CaptureStart/Stop/Status` + `Packets`.
  Console: capture controls, packet timeline, detail drawer. Verify by capturing
  the live Mac↔Ubuntu overlay traffic.
- **Phase 3 — Crypto lab.** Crypto: registry + AES-GCM suite. Engine: runtime
  `set_suite`→resync, handshake stats, session details, event ring. Daemon: the
  crypto IPC set. Console: Crypto Lab tab. Verify a live suite swap re-handshakes
  Mac↔Ubuntu and the comparison table fills.
- **Phase 4 — Hardening & docs.** Confirmation dialogs, the `--admin-allow` gate
  end-to-end, memory/perf bounds on buffers, and a user-facing
  `docs/ADMIN_CONSOLE` usage guide; index it in `docs/README.md`.

---

## 9. Open risks & decisions

- **Plaintext exposure** — packet payloads are decrypted application data. Gated
  off by default (`--admin-allow` empty); capture must be explicitly started.
  Snaplen-bound payloads to cap memory and limit incidental capture.
- **Ring-buffer memory** — bound packet + event rings; drop-oldest with a `dropped`
  counter surfaced in `CaptureState`.
- **Runtime suite swap correctness** — reuse the proven resync path; both ends must
  run the same suite to handshake, so a swap on one node briefly partitions until
  the other swaps. The lab must make this obvious (and ideally offer a
  mesh-wide-coordinated swap later; v1 is per-node).
- **Polling vs streaming** — cursor polling keeps the IPC model unchanged; if it
  proves too coarse for fast traffic, a streaming response is a later upgrade.
- **Gate strength** — `--admin-allow` is a weak name gate (same caveats as the
  health check). It keeps sensitive ops off by default; it is not a real authz
  boundary on a `0666` socket. Real authz (token/UID) is future work.

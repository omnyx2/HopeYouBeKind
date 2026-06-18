# Lattice — Errors & Design Lessons Log

A running log of real failures we hit, their root cause, what we shipped to fix the
*symptom*, and the **design gaps** they exposed (to remember next time we touch
membership / discovery / health). Newest first. Each entry: Incident → Root cause →
Why it was hard to diagnose → Shipped → Remaining design gaps.

---

## 2026-06-18 — "Oracle shows idle" was a silent split-brain

### Incident
On the user's Mac, peer **Oracle** sat permanently `idle` in `lattice info`. Both
daemons were up and healthy (meshd running, UDP 41000/41001 listening, DHT on), yet no
traffic flowed and nothing explained why.

### Root cause
**The two daemons were in *different* meshes.** Mac ran mesh `ㄹㄹㅁ` (its own master
key); Oracle ran mesh `conv` (a different master key). Each roster contained a member
that *pointed at the other's IP*, but they shared no `network id` (master pubkey) and no
secret. So:

- Mac held Oracle's address → showed it `idle` (address known, no decryptable frames in
  the live window).
- Oracle never learned Mac's address → showed Mac `unknown`.
- When Mac sent `ㄹㄹㅁ` frames to Oracle, Oracle's data plane **silently dropped** them
  (they didn't open under `conv`'s key), so Oracle never learned Mac's source and never
  replied. Permanent one-way dead state.

Leftover state from earlier teardown/re-test cycles — each node restored a *different*
stale mesh.

### Why it was hard to diagnose
The fix required SSHing into both daemons and comparing rosters by hand. Every signal
the daemon needed was *already in its hands* but never surfaced:

1. **Silent decrypt drops.** `meshrun::run` did `let Some(..) = dp.recv(&frame) else {
   continue }` — a frame from a *known peer endpoint* that fails to open is the strongest
   "different mesh / different epoch" signal there is, and it was thrown away.
2. **`idle`/`unknown` carried no reason.** The badge said *what*, never *why*.
3. **`mesh_id` is a per-daemon local counter.** Both meshes were "mesh 1", so re-joining
   one onto the other failed with the opaque `already in mesh 1`. The user-facing
   identity should be the `network id` (master pubkey fingerprint), not a local number.
4. **No real membership revocation.** A stale/phantom member cert never leaves the
   roster. `recipher` only rotates the key (denies offline members the new secret); the
   cert lingers, inflating the health denominator and the self-destruct floor.

### Shipped (this change — surface what the daemon already knows)
- **Reason codes** (`MemberView.reason`): an idle/unknown peer now explains itself —
  "frames arriving but failing to decrypt (likely a different mesh/epoch — re-invite)",
  "address known but never heard from (peer down / firewall / NAT)", "no endpoint yet
  (waiting on discovery/DHT)". Rendered under each member in `lattice info`.
- **Decrypt-fail warning** (`meshrun::DecryptFails` + `MeshDetail.warnings`): frames that
  fail to open are counted *keyed by source IP*; if the IP matches a known roster
  member's endpoint, it's raised as a mesh warning ("frames from X fail to decrypt —
  different mesh/epoch? check both nodes' net id") instead of dropped. Pure internet
  noise on the port is still ignored.
- **`network_fp`** surfaced in `MeshDetail` + shown as `net <fp>` in `info`, so two
  "mesh 1"s that are actually different are visibly different at a glance.
- **`lattice doctor`**: aggregates the above into a diagnosis + a concrete suggested fix
  per finding, across all meshes. Turns the 30-minute manual SSH dance into one command.

Code: `crates/meshrun/src/lib.rs` (DecryptFails type + record on decrypt-fail),
`crates/meshd/src/main.rs` (`detail()` reason/warnings/network_fp, MeshState/Bringup
wiring), `crates/mesh/src/ipc.rs` (DTO fields), `scripts/lattice` (`doctor` + `info`
rendering). All additive + `#[serde(default)]` → backward compatible with old clients.

### Remaining design gaps (TODO — remember when next touching this area)
- **Active keepalive for symmetric liveness.** Liveness only updates on *received*
  frames, so a one-way path or wrong-mesh shows up asymmetrically and slowly. A small
  signed ping on a timer to each known endpoint would make both sides converge fast.
- **Join keyed by `network id`, local slot auto-assigned.** Kills the `already in mesh 1`
  collision; same network → idempotent join, different network → an *actionable* error
  ("a DIFFERENT network <fp> already holds local id 1 — remove it first").
- **Real membership revocation + roster GC.** A master/quorum-signed `revoke` cert so an
  evicted/phantom member actually leaves the roster; `recipher` should optionally prune
  offline certs, not just rotate the key. Fix the self-destruct denominator to count
  revocable membership, not dangling certs.
- **Self-destruct guardrails on small meshes.** floor 2 on a 2-node mesh self-destructs
  the moment one laptop sleeps. Scale the threshold to mesh size, separate "everyone
  legitimately offline" from "attack", and warn at creation.
- **GUI surfacing.** The reason/warnings now exist in the IPC; the GUI should show them
  (member tooltip + a health banner) — currently only the CLI renders them.

### Live verification (2026-06-18, real internet + real data plane)
- **reason codes / `net` fp / doctor** — verified LIVE on Oracle (new build, conv over real
  internet): the phantom `#2 mac` shows "엔드포인트 미상", the real `#3 mac` shows "주소만
  알고 한 번도 수신 못함", `doctor` lists both + fixes, `net 32448838` rendered.
- **decrypt-fail warning** — fired LIVE on Oracle's data plane via a deliberate epoch
  desync (3 dev meshds; kill one, recipher with quorum, restart it stale): the daemon
  surfaced `⚠ … 프레임 N건이 복호 실패 — 다른 mesh/epoch 의심` + `doctor`, instead of the old
  silent drop.
- **dup-name guard** — verified locally (case-insensitive + empty rejected).
- **new build** runs on the real Linux server (Oracle), conv healthy on the new binary.
- Windows: cross-compile build-check (`x86_64-pc-windows-gnu`).

### Limitation found during live test — decrypt-fail is keyed by source IP
The desynced node was `b`, but the warning named `c`: all three dev nodes shared
`127.0.0.1`, and decrypt-fails are keyed by **source IP** (not member). So **two members
behind the same NAT / same IP** can be mis-attributed (and a member not yet in the local
roster, like a never-gossiped `b`, isn't named at all — the nearest same-IP roster member
takes the blame). On distinct real IPs it pinpoints correctly. Source *port* is unreliable
under NAT, so IP-keying was deliberate — but a future improvement could correlate the fail
to the member whose last successful decrypt just stopped, or key by (IP, advertised port)
when not NAT'd. Filed as a known edge, not a blocker.

### Diagnostic cheat-sheet (for next time)
- `lattice doctor` — one-shot health + suggested fixes for every mesh.
- Compare `net <fp>` in `lattice info` on each node: **different fp ⇒ split-brain**, they
  are not the same mesh. Re-invite one onto the other (id → invite → join).
- A member stuck `idle` with a known endpoint + a decrypt-fail warning ⇒ wrong
  mesh/epoch. Stuck `idle` with no warning + never-seen ⇒ peer down / firewall / NAT.
  `unknown` ⇒ no endpoint yet (discovery/DHT still working, or needs SetPeer).

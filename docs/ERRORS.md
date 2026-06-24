# Lattice — Errors & Design Lessons Log

A running log of real failures we hit, their root cause, what we shipped to fix the
*symptom*, and the **design gaps** they exposed (to remember next time we touch
membership / discovery / health). Newest first. Each entry: Incident → Root cause →
Why it was hard to diagnose → Shipped → Remaining design gaps.

---

## Blast-radius map — "if you edit X, re-test Y, because…"

A quick-reference regression map distilled from the incidents below. **Before editing an area
on the left, expect the middle to break and check it.** Most of these have already bitten us once.

| If you touch… | Re-test / re-check… | Because (the trap) |
|---|---|---|
| **`crates/meshd/src/exit.rs`** — `route_through` / `restore_routes` / `enable_nat` / `set_dns` | Full-tunnel on **all 3 OS**, the **kill-switch**, and **route loops** | Each `#[cfg(target_os)]` branch is INDEPENDENT — fixing macOS doesn't fix Windows/Linux (e.g. the v0.7.2 idempotent-routes fix was Windows-only; macOS kept looping). |
| pf/route selectors using **`100.64.0.0/10`** | Whether the rule hits THIS node's **own** overlay IP | The node's own TUN IP `100.80.x.y` ∈ `100.64/10`. A rule meant for "traffic we forward for others" also matches our own egress → on a full-tunnel client it diverts our own traffic (utun Opkts=0 → kill-switch revert). |
| Any host-route / pin op (`route add -host`, `/32`) | Idempotency + **pin-before-divert, fail-closed** | macOS `route add` fails "File exists" on a stale /32 → must `delete` first. And only divert the default into the tun if the exit /32 pin SUCCEEDED, else the exit's own outer packets loop back into the tun. |
| `run(...)` → `run_checked(...)` anywhere | The control flow after a **failed** shell-out | Switching to the checked variant changes whether a failed step aborts or silently continues — a "surface the error" change can turn a no-op into an abort (or vice-versa). |
| **`crates/mesh/src/charter.rs`** — `ExitPolicy` / any `#[default]` | Behaviour on a **pure client** node | A default-on policy runs at bringup on EVERY node, not just exits. (`Isolate` default is why an exit-only pf rule ran on clients.) |
| **`crates/meshrun/src/lib.rs`** — run loop, TUN read/write, MTU, `CTRL_*` | In-mesh overlay AND exit traffic; **wire-compat** with un-upgraded nodes | New `CTRL_*` tags must be additive (old nodes hit `_ => {}`); changing frame layout/MTU breaks the data path for nodes still on the old build. |
| **`crates/mesh/src/ipc.rs`** — `Request`/`Response` enums | CLI **and** GUI **and** connectors | Additive variants + `#[serde(default)]` ONLY. A removed/renamed/reordered variant → `"unknown variant"` errors ("extension unreachable" was exactly this: GUI newer than the running daemon). |
| **`crates/meshd/src/main.rs`** — `serve_conn` / channels / `scope_gate` / event bus | Backpressure, shutdown-ack flush, live-grant re-check | Unbounded channel = memory leak under a stuck client; the Shutdown ack must flush before teardown; scope checks must read the LIVE grant, not a Hello-time snapshot. |
| Data-plane crypto — nonce / `seq` / body+header keys | Nonce reuse **across a restart** | `seq` reset to 0 on restart while the key persists = keystream reuse. Seed `seq` from a random per-boot start. |
| **Build / packaging** — `Cargo.toml`, `build.rs`, bundling | That the RIGHT thing built (see `BUILD.md`) | Package `lattice-meshd` ≠ binary `meshd`; GUI builds on **stable**, core on **1.79**; a new dep can drag in an `edition2024`/high-MSRV crate that breaks 1.79 CI (getrandom, winnow). |
| **Anything you then "test live"** | That you're running the **current build** | A STALE binary masks regressions. Confirm `meshd: version vX.Y.Z build <sha>` in `/tmp/lattice-meshd.log` == `git rev-parse --short HEAD`. A stale 0.5.3 binary hid two full-tunnel regressions for hours (2026-06-24). |
| Restarting meshd on the **live Mac** | utun/route/pf state accumulation | Many restarts churn utun + leave stale routes/pf, confounding diagnosis. Prefer offline/clean-slate (reboot) testing; diagnose with `curl`/TCP, never `ping` (ICMP blocked on campus). |

**Diagnostic meta-lesson:** `Opkts=0` / "exit not passing traffic" has **multiple** causes —
a kernel utun wedge, a pf rule stealing packets, OR a route loop. They look identical from the
interface counter. **Discriminate** before concluding: send to an in-mesh overlay IP (isolates
the exit code out), read `/tmp/lattice-pf.conf`, and `route get <exit-ip>` (must be the WAN, not
the tun). On 2026-06-24 a "wedge" was wrongly assumed; it was a pf rule + a route loop.

---

## 2026-06-24 — two macOS full-tunnel regressions, unmasked by fixing a stale build

**Incident:** after finally deploying the *current* build to the Mac (earlier runs had silently
used a months-old binary), full-tunnel stopped working: the overlay TUN showed `Opkts=0` then a
huge `Opkts` flood with `Ipkts=0`, egress stayed on the campus IP, and the kill-switch logged
"full-tunnel exit not passing traffic — reverting".

**Root cause (two independent bugs, both macOS-only, both in the data plane):**
1. **pf `route-to` captured our own traffic.** `cb6c868` added, under the default
   `ExitPolicy::Isolate`, `pass out route-to (en0 <gw>) from 100.64.0.0/10 to any` at bringup on
   *every* node. Our own overlay IP `100.80.x.y` ∈ `100.64/10`, so on a full-tunnel client pf
   shoved our own egress back out en0 → `Opkts=0`.
2. **route_through diverted the default even when the exit /32 pin failed.** It did
   `route add -host <exit> <gw>` (NOT idempotent — fails "File exists" on a stale /32 from a
   prior on/off cycle) and then ALWAYS `route change default -interface utun`. With the pin
   failed, the exit's own outer tunnel packets followed the new default back into the tun → a
   routing loop (the `Opkts` flood), nothing reaches the exit, kill-switch reverts.

**Why it was hard to diagnose:** `Opkts=0` is *identical* to a macOS utun kernel wedge (a real
prior incident), so a wedge was wrongly assumed at first. Two things broke that assumption: an
in-mesh overlay packet test (to `100.80.1.1`) also showed `Opkts=0` — but that turned out to be
bug #1 (pf steals overlay-sourced packets too), not a wedge; and the static smoking gun was
reading `/tmp/lattice-pf.conf` + confirming `100.80.1.7 ∈ 100.64/10`. Bug #2 was then hidden
*behind* bug #1 — only once pf stopped stealing packets did the loop become visible.

**Shipped:** (1) `5cfa960` — only install the isolate `route-to` rule on a node that actually
serves as an exit (publicly-reachable / `MESHD_ADVERTISE` pinned); a client never forwards for
others. (2) `19465bb` — make the macOS exit pin idempotent (`route delete -host` first) and only
divert the default once the pin succeeded (fail closed, never loop). Both verified live: pf is
`nat`-only on the client, `route get <exit>` → en0.

**Remaining gaps (TODO when next here):**
- Full-tunnel still didn't complete after both fixes (`Ipkts=0`, no return from the exit) —
  client side is correct, so the next suspect is the **Oracle exit side** or a deeper data-plane
  change in `0.5.3..v0.6.1` (the v0.6.1..HEAD range was already compared clean). See
  the macOS-full-tunnel-regressions memory.
- A stale binary masking regressions is its own failure class → the `build <sha>` startup stamp
  + `scripts/build-app.sh` anti-stale gates exist now; USE them (BUILD.md).
- The `isolate`-on-exit heuristic uses `MESHD_ADVERTISE` as the "am I an exit" proxy; a
  non-pinned LAN exit would miss the rule. Acceptable trade vs. breaking every client; revisit
  if a real LAN-exit topology needs isolate.

---

## 2026-06-21 — four early-access hardening fixes (v0.6.1)

**Context:** a pre-distribution audit flagged four ways the daemon could silently
misbehave or be abused. None was a live incident yet; each was a latent gap closed
before wider distribution. Documented here so the *why* survives.

**The gaps and what shipped:**

1. **Silent route/DNS failure (UX trap).** Full-tunnel set-up shells out to set the
   default route + DNS; the helpers returned `()` and swallowed failures, so the GUI/CLI
   showed "VPN on" while traffic silently went nowhere. → `route_through`/`set_dns` now
   return `Result`; a failure is recorded in `dp_error` and shown by `lattice info` /
   the GUI. macOS/Linux get per-command detection; Windows catches launch failures
   (its PowerShell uses `SilentlyContinue`, so per-cmdlet failures still pass).

2. **Nonce reuse on restart (crypto correctness).** The data-plane AEAD nonce is the
   send counter (`seq`). It reset to **0** on every process start, but the body/header
   keys derive from the *persisted* secret+epoch — so a restart kept the **same key**
   and replayed nonces `0,1,2…` = ChaCha20-Poly1305 keystream reuse (an on-path observer
   who captured pre- and post-restart traffic could recover plaintext). → `send_seq`
   now seeds from a **random 63-bit per-boot start**. Wire-compatible: the receiver
   derives the nonce from the transmitted `seq` and has no replay window, so a high
   start "just works" and old nodes interoperate with new ones.

3. **Unbounded gossip (insider DoS).** A roster cert is merged on a network-id match
   *before* it validates to the master (`roster()` filters invalid ones later), so a
   malicious/buggy member could grow `certs` without bound by gossiping junk. →
   `MAX_GOSSIP_BYTES` (64 KiB) guard + per-collection caps
   (certs 1024 / revocations 512 / flow-rules 512). Member ids are 1 byte (≤254 live),
   so the caps sit far above any real mesh and only bite an abuse case.

4. **World-open control socket.** The unix socket is `0o666` so the root daemon's
   user-level GUI can reach it — which also let *any* local process drive the daemon.
   The root-daemon/user-GUI split means a strict uid allow-list can't be the default
   without breaking the GUI. → meshd now reads the peer uid (`SO_PEERCRED` on Linux,
   `getpeereid` on macOS); **permissive by default**, with opt-in strict mode via
   `LATTICE_ALLOW_UID=<uid>[,uid…]` (allows root + our uid + `$SUDO_UID` + listed) for
   shared/multi-user hosts.

**Live verification (2026-06-21, real internet + real data plane).** Built `meshd` on
the branch and rolled it to two nodes while Mac/Windows stayed on the old build:
- **Oracle** (`<PUBLIC_IP>`, seed+exit): restarted 3× — peers (Mac, Lablinux) re-linked
  each time with **zero decrypt-fail** (validates #2-nonce wire-compat under the same
  persisted key, incl. mixed old/new versions). `LATTICE_ALLOW_UID=0` → a uid-1001 client
  was refused + logged, root allowed (validates #4); reverted to permissive. 4-member
  roster still converged (validates #3 didn't break convergence).
- **Lablinux** (overlay `100.80.1.4`): same build; full-tunnel through Oracle made its
  egress = Oracle's IP **with no `dp_error`** on success (validates #1 surfacing has no
  false positives), then reverted clean.

**Remaining design gaps (TODO):**
- ~~The CLI prints a raw Python traceback when the uid gate refuses a connection.~~
  *Fixed:* `call()` now catches the accept-then-close (BrokenPipe/reset/empty reply)
  and prints a clean "not authorized — see `LATTICE_ALLOW_UID`" hint.
- Lablinux runs the **installed app's** bundled `meshd` (`/usr/lib/lattice/resources/meshd`,
  launched by the GUI as root), not a git/systemd build — so a field update means
  replacing that binary (atomic rename to dodge `ETXTBSY`) + relaunch, not `git pull`.

---

## 2026-06-18 — mesh unreachable on an IPv6-only / NAT64 cellular network

**Incident:** on an iPhone hotspot, the Mac couldn't reach Oracle (peer idle) AND SSH to
`<PUBLIC_IP>` failed with `Can't assign requested address`. Same hotspot had worked before.

**Root cause:** the carrier gave an **IPv6-only (NAT64/464XLAT)** stack that session — en0 had
`192.0.0.2` (CLAT) + IPv6, no usable IPv4. Hostnames worked (DNS64 → IPv6: `google.com` 200) but
**raw IPv4 literals failed** (`<PUBLIC_IP>` → 000): `ipv4only.arpa` returned empty, so CLAT
couldn't discover the NAT64 prefix and had no path to translate IPv4 literals. The mesh underlay
advertises Oracle as an **IPv4 literal**, so it was unreachable. "Worked before" = that session
the cellular gave IPv4 (dual-stack) or CLAT discovered the prefix. The program didn't change; the
carrier's per-session address assignment did.

**Not a code bug — a missing capability.** Fix is to make the underlay IPv6/dual-stack so a
node on an IPv6-only carrier reaches the public node over native v6 (no CLAT dependence).
Detailed work plan: **docs/IPV6_PLAN.md** (dual-stack bind, v6 advertise, multi-endpoint per
member, DHT v6). Deferred — planned, not built.

---

## 2026-06-18 — two bugs found while building membership expulsion

Both surfaced during live testing of the new expulsion feature (docs/EXPULSION.md).

### Bug A — back-to-back invites collide on the member id
`CreateInvite` picked the joiner's 1-byte id from the **current roster only**
(`used = roster ids`). Since the bedb9c0 fix, an invitee is NOT added to the roster until
it joins + gossips back — so inviting `b` then `c` before either connects gave **both id
#2** (the roster was still just `{a}` both times). The roster then showed two members at
`#2` sharing one link/endpoint, and `expel #3` hit nothing.
- **Fix:** the daemon **reserves** ids handed out in not-yet-joined invites
  (`MeshState.invited`, pruned on join or after `INVITE_RESERVE_MS`); id selection excludes
  roster ids ∪ reserved ids. Belt-and-suspenders: `effective_members` de-duplicates by id
  deterministically (earliest `issued_at`, then lowest pubkey) so any collision that slips
  through (cross-node) converges to the same single member everywhere. Live-verified:
  back-to-back invites now yield `#2`,`#3`.

### Bug B — quorum expel co-signers didn't accumulate
A quorum revocation signed over `(network, member, issued_at)`. Two members proposing the
same expulsion independently used **different `issued_at`** (each `now_ms()`), so their
revocations never merged — each stayed at 1 signer and `k` was never reached. Live test:
both A and B reported "1/2", member not removed.
- **Fix:** sign over **`(network, member)` only** — no timestamp. All signatures for "expel
  X from N" are now over identical bytes, so independent proposals merge and co-signers
  accumulate regardless of timing/order. Revocation is monotonic (re-admit = fresh keypair),
  so dropping the nonce is safe. `issued_at` stays as unsigned metadata. Live-verified:
  A proposes (1/2, stays) → B co-signs (2/2, removed).

**Lesson (the user's framing):** the daemon is the single authoritative actor — it performs
all logic; the GUI only visualizes it. A related cleanup this session: the GUI's
`meshWarnings()` was **re-deriving** health warnings client-side instead of showing the
daemon's authoritative `MeshDetail.warnings` (which is the only place the decrypt-fail /
split-brain warning lives). Now the GUI renders `d.warnings` verbatim.

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

**Mitigated (2026-06-18, live):** `detail()` now suppresses decrypt-fail attribution for any
IP that has a **currently-live** member — if we're successfully decrypting frames from that
IP, a fail on it is a *different* sender sharing the NAT, not this peer. This killed a real
false positive: a fresh `home` mesh (Mac↔Oracle) was healthy (overlay ping 3/3) but Oracle
kept warning about "mac" because another node behind the same campus NAT (public
`203.0.113.20`) was sending stale frames to Oracle's port. Since `mac` was live, its IP is
now in `live_ips` and the warning is suppressed. A genuinely idle/unknown peer on a private
IP still raises it. (Two members behind one NAT where BOTH are idle is still ambiguous.)

### Diagnostic cheat-sheet (for next time)
- `lattice doctor` — one-shot health + suggested fixes for every mesh.
- Compare `net <fp>` in `lattice info` on each node: **different fp ⇒ split-brain**, they
  are not the same mesh. Re-invite one onto the other (id → invite → join).
- A member stuck `idle` with a known endpoint + a decrypt-fail warning ⇒ wrong
  mesh/epoch. Stuck `idle` with no warning + never-seen ⇒ peer down / firewall / NAT.
  `unknown` ⇒ no endpoint yet (discovery/DHT still working, or needs SetPeer).

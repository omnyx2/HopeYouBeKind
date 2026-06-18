# Daemon self-healing — what `meshd` handles on its own

*(한국어 요약은 맨 아래)*

Lattice has **no operator and no server**. A mesh must therefore keep itself alive
through reboots, network changes, dead exits, crashed peers, and stale leftovers —
**without anyone watching it**. This document catalogs every place where `meshd`
detects a degraded condition and responds automatically, so the design intent is
explicit and the behaviour is testable.

Each mechanism is described as **Trigger → Detection → Automatic response → Config**,
with the source location.

---

## 1. Single-instance guard — never orphan a running daemon

- **Trigger:** a second `meshd` is launched while one is already running (a GUI
  relaunch race, a leftover from a previous session, a manual start).
- **Detection:** on startup `accept_loop` probes the IPC socket
  (`UnixStream::connect`) before taking it.
- **Response:** if a live `meshd` already answers, the new process **defers and
  exits cleanly** instead of `remove_file` + re-`bind`. Stealing the socket used to
  orphan the old instance, which kept its TUNs and **its already-bound data-plane
  UDP ports** — a zombie that then blocked every new data plane with
  `Address already in use`.
- **Config:** none. Always on (unix). *(Windows named-pipe single-instance would
  need a named mutex; the data-plane retry below covers the same failure there.)*
- **Source:** `crates/meshd/src/main.rs` `accept_loop` (unix).

## 2. Data-plane bind self-heal — recover a busy port, never fail silently

- **Trigger:** a mesh's data-plane UDP port is momentarily held (a just-removed
  mesh's socket still closing, a zombie daemon exiting, TIME_WAIT).
- **Detection:** `UdpTransport::bind` returns `Address already in use`.
- **Response:** **retry with backoff — 12 × 500 ms.** Once the port frees, the mesh
  comes up on its own. If it never frees, `meshd` logs **loudly** and records
  `dp_error` on the mesh; the old behaviour failed *open* — the GUI showed the mesh
  as "joined" while it could neither send nor receive (this was the actual
  "joined-but-can't-find-each-other" bug). The GUI now shows **"⛔ data plane DOWN"**
  on the overview and in **Warnings**.
- **Config:** none. Always on, cross-platform.
- **Source:** `crates/meshd/src/main.rs` `bringup_dataplane`; surfaced via
  `MeshDetail.dp_error` (`crates/mesh/src/ipc.rs`) and `gui/src/main.js`.

## 3. Full-tunnel kill-switch — auto-revert a dead exit to direct internet

- **Trigger:** full-tunnel egress is on (the host default route is diverted through
  a mesh exit) and that exit stops carrying traffic.
- **Detection:** a watchdog probes reachability through the tunnel every **20 s**.
- **Response:** if the exit isn't passing traffic, **auto-revert to direct internet**
  so the user is never cut off — then the route can be re-armed when the exit returns.
- **Config:** armed automatically whenever full tunnel goes up (`ArmKillSwitch`).
- **Source:** `crates/meshd/src/main.rs` `arm_kill_switch` (~L976).

## 4. Liveness self-destruct watchdog (P-C4) — fail-safe on isolation

- **Trigger:** an *ephemeral* mesh drops below its live-paired floor
  (`⌈0.6·roster⌉`) — by the threshold-sharing model the secret is then unrecoverable.
- **Detection:** a per-mesh watchdog re-checks liveness every **15 s**
  (`SELF_DESTRUCT_TICK_SECS`); `LIVE_WINDOW_MS = 30 s` defines "live".
- **Response:** after a **180 s** grace (`SELF_DESTRUCT_GRACE_SECS`) below floor, the
  mesh secret is wiped and the on-disk copy pruned. Off by default (laptop-friendly);
  opt-in per mesh.
- **Source:** `crates/meshd/src/main.rs` `spawn_self_destruct_watchdog` (~L891).

## 5. Attack-response grace (P-C7) — one-veto, fail-deadly

- **Trigger:** any member reports an attack (`ReportAttack`) or relays an alert.
- **Detection:** the destroy grace is armed (`attack_armed_at`).
- **Response:** after **30 s** (`ATTACK_GRACE_SECS`) every member self-destructs,
  unless the creator sends an all-clear first. A single member can arm it; only the
  creator can cancel — deliberately fail-deadly.
- **Source:** `crates/meshd/src/main.rs` (`ATTACK_GRACE_SECS`, the self-destruct
  watchdog also enforces this).

## 6. Automatic relay-bridge election — route around an unreachable peer

- **Trigger:** two peers can't reach each other directly (NAT/firewall, e.g. a
  campus block), but some third node is connected to both.
- **Detection / response:** any node connected to both ends can act as an
  **auto-elected bridge** — no manual designation. The bridge forwards via its own
  direct connections (`relay.learn`); replies return through the **same working
  path** the packet arrived on (`relay_path`), so asymmetric reachability still works.
- **Config:** election is automatic among nodes that can serve.
- **Source:** `crates/net/src/relay.rs` (`relay_path`, `learn`, ~L158–280).

## 7. State persistence + reload (P-S1) — survive reboots & network changes

- **Trigger:** reboot, daemon restart, or a network change.
- **Detection / response:** every state change is persisted (0600 JSON under
  `MESHD_STATE_DIR`, else `~/.lattice/meshd`) and **reloaded at startup**, so a node
  is not dropped from its meshes. **Last-known peer endpoints are re-seeded on load**
  so reconnect is fast — before gossip re-converges. A self-destruct / `RemoveMesh`
  erases the on-disk copy too.
- **Config:** `MESHD_STATE_DIR`; `MESHD_NO_PERSIST=1` to disable.
- **Source:** `crates/meshd/src/main.rs` persistence block (~L231–331).

## 8. Port-leak prevention on teardown — a re-created mesh can always bind

- **Trigger:** `RemoveMesh` / self-destruct of a mesh whose data-plane loop is live.
- **Detection / response:** the loop's `AbortHandle` (`dp_task`) is aborted so its
  future is dropped, **freeing the TUN and the UDP socket** — otherwise the port
  leaks and a re-created mesh on the same port can't bind. (This is the same class of
  bug §2 now also recovers from at the other end.)
- **Source:** `crates/meshd/src/main.rs` `dp_task` (~L141).

## 9. Endpoint discovery (P-D1…P-D4) — no manual peering

- **Trigger:** a member needs another member's reachable address.
- **Detection / response, layered:**
  - **P-D1** invite carries the inviter's endpoint (reach it immediately on join);
  - **P-D2** signed `EndpointRecord` gossip (newest `seq` wins, `EndpointBook`);
  - **P-D3** reflexive address via a public peer's reflexion — own advertised
    endpoint is **upgraded to the public address** when reflected;
  - **P-D4** LAN multicast beacon (`239.255.42.99:42424`) for same-router peers.
- **Config:** automatic; `MESHD_ADVERTISE=ip:port` pins a public node's address.
- **Source:** `crates/mesh/src/discovery.rs`, `crates/meshd/src/main.rs` (beacon ~L542,
  reflexive/advertise ~L806).
- **Gap (being addressed):** all four are **first-contact** mechanisms. A peer whose
  address changes with **no overlapping live window** cannot be re-found by id — see
  the planned **DHT rendezvous** (`docs/DHT_RENDEZVOUS.md`).

## 10. Liveness tracking — health without polling the user

- **Trigger / response:** every received data-plane packet updates `last_seen_ms`;
  members within `LIVE_WINDOW_MS = 30 s` count as live. Feeds the health pill, the
  quorum floor, and the self-destruct/relay decisions above. No heartbeat config.
- **Source:** `crates/meshd/src/main.rs` (`LIVE_WINDOW_MS`, `last_seen_ms`).

## 11. Startup preflight — boot from a known-good route state

- **Trigger:** a previous run left **stale full-tunnel route bookkeeping** — an exit `/32`
  pin and/or a saved default-gateway file — because it didn't clean up (crash, `kill -9`,
  reboot, or a network change while the default was diverted).
- **Detection:** full-tunnel state is **not persisted**, so on a fresh start it is always
  OFF; therefore *any* leftover route bookkeeping is by definition stale.
- **Response:** at boot, `startup_preflight()` clears the exit `/32` pin **and** the saved
  default-gateway file. Left behind, a stale `/32` blackholes the exit's IP (`connect` →
  `EADDRNOTAVAIL`, the real "Oracle idle on a new network" bug) and a stale saved gateway
  would make a later revert point the default route at a **dead** gateway (no internet).
- **Config:** none. Always on when the data plane is up.
- **Source:** `crates/meshd/src/main.rs` `startup_preflight` + `exit::clear_exit_pin`.

## 12. Network-change watcher — self-heal across IP/network changes

- **Trigger:** the host gets a new IP / default gateway (sleep–wake, Wi-Fi↔cellular roaming,
  a new network after an outage). The user shouldn't have to touch anything.
- **Detection:** a watcher polls the **default gateway** every `NETCHANGE_TICK_SECS = 8 s`;
  a change means the network moved.
- **Response:** (a) clean a now-stale exit `/32` pin — or **re-pin it via the new gateway**
  if a full tunnel is active, so the tunnel survives roaming; (b) drop a stale saved default
  gateway so a later revert can't apply a dead one; (c) **re-learn the local address** into
  each mesh's advertised endpoint, so the next gossip/DHT tick propagates it and peers
  re-discover us. The data-plane socket is wildcard-bound, so it keeps receiving across the
  change. Detailed flow in `docs/DYNAMIC_NETWORK.md`.
- **Config:** always on with the data plane; a pinned public node (`MESHD_ADVERTISE`) never
  re-learns its address.
- **Source:** `crates/meshd/src/main.rs` `spawn_netchange_watcher` + `exit::current_gateway`.

---

## Test matrix

| # | Mechanism | How to verify |
|---|-----------|---------------|
| 1 | Single-instance guard | launch a 2nd `meshd` → logs `deferring to it, exiting`, exit 0, 1 live daemon ✓ verified |
| 2 | Bind self-heal | hold the port, start a mesh → retries; free the port → mesh comes up; never frees → `dp_error` + GUI banner |
| 3 | Kill-switch | full-tunnel up, kill the exit → reverts to direct within ~20 s |
| 4 | Self-destruct | ephemeral mesh below floor 180 s → secret wiped |
| 5 | Attack grace | `ReportAttack`, no all-clear → self-destruct at 30 s |
| 6 | Relay election | block A↔B directly, both reach C → traffic bridges via C |
| 7 | Persistence | reboot/restart → meshes reload, peers re-seeded |
| 11 | Startup preflight | leave a stale exit `/32` + saved-gw file, restart meshd → both cleared at boot, log line printed |
| 12 | Network-change watcher | move Wi-Fi↔cellular → within ~8 s: stale pin cleared (or re-pinned), local address re-learned, peers re-discover |

---

## 한국어 요약 — 데몬이 알아서 대응하는 요소

Lattice는 **운영자도 서버도 없습니다.** 그래서 `meshd`는 재부팅·네트워크 변경·죽은
exit·끊긴 피어·남은 좀비 프로세스를 **아무도 지켜보지 않아도** 스스로 복구해야 합니다.
아래가 그 자기-대응 목록입니다(자세한 동작/소스는 위 영문 본문).

1. **단일-인스턴스 가드** — 살아있는 meshd가 있으면 새 프로세스는 **양보하고 종료**.
   소켓을 뺏어 옛 인스턴스를 좀비로 만들고 그 좀비가 포트를 쥐던 근본 버그 차단.
2. **데이터플레인 bind 자기-치유** — 포트가 잡혀 있으면 **0.5s×12회 재시도**, 풀리면
   알아서 복구. 끝내 실패하면 크게 로깅 + `dp_error`를 GUI **"⛔ data plane DOWN"** 배너로.
   더 이상 "Join된 척하는 죽은 메쉬"가 없음.
3. **풀-터널 킬-스위치** — exit가 트래픽을 못 나르면 **자동으로 직접 인터넷 복귀**(~20s).
4. **격리 자기파괴 워치독(P-C4)** — ephemeral 메쉬가 생존 정족수 아래로 떨어지면
   180s 후 시크릿 폐기. 기본 off, 메쉬별 opt-in.
5. **공격대응 유예(P-C7)** — 공격 신고 시 30s 후 전원 자기파괴(생성자 all-clear 없으면).
   1명이 발동, 생성자만 취소 — 의도적 fail-deadly.
6. **자동 릴레이-브리지 선출** — 직접 못 닿는 두 피어를, 양쪽에 닿는 제3노드가
   **자동으로** 브리지(수동 지정 없음). 도착한 경로 그대로 응답.
7. **상태 영속화+재로딩(P-S1)** — 재부팅/네트워크 변경에도 메쉬 유지, 마지막 endpoint
   재시드로 빠른 재연결.
8. **해제 시 포트 누수 방지** — `RemoveMesh`/자기파괴 때 dp_task abort로 TUN+UDP 즉시 반납.
9. **엔드포인트 디스커버리(P-D1~D4)** — 수동 피어링 없이 주소 자동 학습.
   **단, 모두 "첫 접촉"용** — 겹침 없이 주소가 바뀐 피어는 id로 재발견 불가 →
   **DHT 랑데부**로 보완 예정(`docs/DHT_RENDEZVOUS.md`).
10. **생존성 추적** — 수신 패킷마다 last-seen 갱신(30s 창)으로 health/정족수/위 판단에 사용.
11. **시작 점검(preflight)** — 풀터널 상태는 비영속이라 시작 시 항상 OFF → **남은 라우트
    부기록은 전부 stale**. 부팅 때 exit `/32` 핀 + 저장된 기본-게이트웨이 파일을 정리해
    **알려진-정상 라우트 상태에서 출발**. (옛 `/32`가 exit IP를 블랙홀시켜 "새 망에서 Oracle
    idle" 나던 버그의 근본 정리.) 워처 첫 틱(8s)에 의존하지 않고 즉시 처리.
12. **네트워크 변경 워처** — 기본 게이트웨이를 8s마다 보고 바뀌면(절전/복귀·Wi-Fi↔셀룰러·
    장애 복구): stale exit 핀 정리(풀터널이면 새 gw로 **재핀**) + stale 기본-gw 정리 +
    **로컬 주소 재학습** → 가십/DHT로 전파해 피어들이 재발견. `docs/DYNAMIC_NETWORK.md` 참조.

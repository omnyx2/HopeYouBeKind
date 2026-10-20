# COMPLETE.md — finished work log

Requirements moved here from `TEMP.md` as they complete (newest first). Each: what + date +
commit. The durable record; `TEMP.md` only holds open items.

---

## 리팩토링 Phase 1 — 죽은 코드 삭제 + net v1 feature 게이트 (2026-10-21)

Phase 0 감사 후속. 삭제 전 전 영역(crates/legacy/gui/connectors/fuzz) grep으로 소비자 0 재검증.

1. ✅ **mesh 죽은 스켈레톤 삭제** — policy.rs + roster.rs + MeshContainer + `Mesh.roster` 필드
   (~350줄+테스트 9개): membership.rs + meshd MeshState가 대체한 pre-membership 설계. 이름충돌
   (RouteDecision/FlowKey/FlowMatch 2벌)과 중복 cidr_contains도 함께 소멸. commit `7f5b7dc`.
2. ✅ **net::tcp 삭제(188줄, 소비자 0) + v1 스택 feature 게이트 + meshrun 바이너리 삭제** —
   `nat = ["dep:rand"]`(legacy-dht의 rendezvous가 필요 — meshd가 MESHD_DHT로 재사용 + fuzz
   stun_parse), `v1 = ["nat", "dep:mdns-sd"]`(legacy daemon/engine만). **meshd 빌드에서 mdns-sd
   완전 제거**(cargo tree 확인). meshrun dev-runner(main.rs)는 아무도 안 빌드 + exit NAT 3번째
   복사본이라 삭제, anyhow dep도 제거. ⚠️ 발견한 함정: meshrun/lan.rs의 `set_reuse_port`가
   tokio의 socket2 feature unification에 우연히 의존 → 루트에 `socket2 features=["all"]` 명시
   (docs/ERRORS.md 2026-10-21). commit `f8f9b4f`.
3. ✅ **GUI vestigial deps + tun 빈 함수** — gui/src-tauri에서 lattice-proto/lattice-ipc(미사용,
   legacy로 가는 마지막 빌드 엣지) 제거, package.json에서 @tauri-apps/api(미import,
   withGlobalTauri) 제거, tun/macos.rs 빈 tracing_name 삭제. commit `6124c4d`.

검증: workspace build+test(1.79) 169 passed/0 failed, clippy 0 error, fmt, fuzz 워크스페이스
stable check, gui/src-tauri stable check, vite build+eslint, meshd 단독 tree에 mdns 0건.
legacy 62k줄의 워크스페이스 분리는 보류(여전히 CI에서 빌드됨 — 사용자 결정 필요시 Phase 2+).

---

## 리팩토링 Phase 0 — 안전망(테스트/린트/fuzz) + 소규모 버그 4건 (2026-10-20)

4-영역 코드 감사(meshd / mesh+proto / net·tun·meshrun / GUI+CLI)에서 나온 첫 PR. 전부
오프라인 검증(라이브 데몬 불가침); 커밋 4개, 모두 feat/extensions-meshd.

1. ✅ **버그: `request_mutates`에 AdmitMember 누락** — admit이 `ms.certs`에 push해도 persist가
   안 불려 재시작 시 cert 유실. + `persist_default_mesh`만 0600 chmod 빠진 비대칭(형제 파일은
   전부 0600) 수정. persist 4종(split/split-active/default-mesh/extensions) 라운드트립 테스트 +
   request_mutates 완전성 테이블 테스트(이 버그를 잡았을 테스트) 추가. commit `f2c93d6`.
2. ✅ **테스트: mesh/ipc.rs 와이어 계약 동결** — Request 39 + Response 18 variant 전수 JSON
   라운드트립 + golden wire-token(exhaustive match = 컴파일타임 완전성 가드) + 구버전 최소 JSON
   파싱 테스트. variant rename이 이제 런타임 version-skew 대신 CI에서 터짐. commit `65c6df4`.
3. ✅ **fuzz: meshrun 네트워크 파서 4종** — decode_gossip/decode_recipher/beacon_parse/parse_flow
   타깃 추가(기존엔 legacy stun/wire만). 파서는 `#[doc(hidden)] pub`(fuzz 전용), 동작 무변경.
   fuzz/는 자체 워크스페이스라 1.79로 안 풀림(기존과 동일) — stable check 통과,
   `cargo +nightly fuzz run <target>`로 실행(cargo-fuzz 미설치 상태). commit `18c2d11`.
4. ✅ **버그: CLI→GUI base64 불일치** — CLI는 urlsafe(`-_`), GUI `atob`는 표준(`+/`)만 → `-`/`_`
   포함 초대/identity 코드가 GUI에서 "invalid". b64decode가 디코드 전 정규화; node+python
   크로스체크로 양방향 검증. **버그: `esc()`가 `'` 미이스케이프** — 싱글쿼트 속성
   (`data-scopes='…'`)에서 커넥터발 scope 문자열로 속성 탈출 가능 → `'`→`&#39;` 추가 + 누락
   esc() 보강(state/pubkey_fp/charter invite/flow proto). 죽은 randHex64 + CLI `if False` 잔재
   삭제. **ESLint**(no-undef/no-unused-vars) + `npm run lint` + CI eslint job 신설(vite 빌드는
   JS를 전혀 검사 안 했음). commit `c9086f8`. ⚠️ GUI 변경은 커밋만 — 라이브 앱 스왑 안 함
   (frontend는 앱 바이너리 임베드, 반영은 다음 번들 빌드 때).

검증 게이트: `cargo test --workspace`(1.79) 전부 green(+신규 10개), clippy exit 0(신규 경고 0,
struct-init으로 정리), plain `cargo fmt --all`, eslint 0건, vite 번들 OK, opsec-scan은 기존
COMPLETE.md IP만 플래그(이번 변경엔 신규 IP 없음).

---

## v0.7.15 — egress 3모드 명시화 (Off / Split / Full) + None exit 제거 (2026-08-22)

사용자 지적: "config에서 None 없애야 + full-tunnel이 기본인데 자기 네트워크 쓰면 그건 메쉬 egress
꺼진 상태지 full-tunnel이 아님." 진단: 라우팅 버그 아님(실증: exit=1 8초 유지+persist, 인터넷 직결
정상). **개념/UI 결함** — "exit/egress"가 3군데서 다른 뜻(mesh.exit 관문 / SetCurrent egress /
Default network)으로 뒤섞여 topbar가 Default network를 full-tunnel의 peer 선택지처럼 노출.
사용자 선택(AskUserQuestion): **명시적 3모드 Off/Split/Full**.
- Config "Egress & routing": `— none —` 제거(관문은 남 멤버만, 자기 제외; 라우팅하는 메쉬는 항상
  관문 있음, 내부 메쉬는 Off 유지). 3모드 세그먼트(Off/Split/Full) = `setEgressMode`. 전환은 항상
  `SetCurrent{None}`(routes/DNS 복원+split off) baseline 경유 → idempotent, split↔full 안 겹침.
  Full→SetCurrent{Some}, Split→SplitOn, 둘 다 관문 SetExit 선반영.
- 모드 판별(IPC 추가 없이): SplitList.active_mesh==mesh→Split, 아니고 is_current→Full, 아니면 Off.
- topbar 리라벨: "Default network"→"직접 인터넷 (off)", 상태= `Full tunnel · <mesh>` /
  `Split tunnel · <mesh>` / `직접 인터넷 (메쉬 egress off)`. Overview는 읽기전용 `egress: Off/Split/Full`
  뱃지 + "make egress" 버튼 제거.
- **데몬 라우팅 코드 무변경** (GUI-only, 기존 SetCurrent/SplitOn/SetExit 조합). commit `0ba7f44`.
검증: node --check(구문) + vite frontend 번들 OK + `scripts/build-app.sh`(stale-SHA & anti-mix 게이트
통과: bundled meshd==0ba7f44, app v0.7.15). **라이브 반영**: frontend가 앱 바이너리에 임베드 →
전체 Tauri 번들 재빌드 필요. 빌드 중 dmg 단계가 /Volumes/Lattice auto-mount→새 앱이 그 볼륨에서
떠 라이브 meshd를 넘겨받는 부작용 발생 → **clean teardown 후 빌드 산출물 .app을 /Applications에
ditto 설치 + DMG 언마운트 + 재실행**으로 정리. 최종 `/Applications`에서 v0.7.15 0ba7f44 실행,
oracle direct, EXIT #1 유지. 버전 0.7.15 범프(Cargo/gui Cargo/tauri.conf/package.json).
브랜치 feat/extensions-meshd, **main 미머지**. 백업 /Applications/Lattice.app.prev.
LESSON: `npm run tauri build`의 dmg 단계는 볼륨을 마운트하고 새 앱이 거기서 실행될 수 있다 —
라이브 VPN 중엔 빌드 자체가 데몬을 스왑할 수 있으니 빌드 후 실행 경로(/Volumes vs /Applications) 확인.

## v0.7.14 — full-tunnel egress + exit 지정 sticky (재시작에도 유지) (2026-08-07)

증상: GUI에서 "왜 자꾸 Default network로 감?" — 라우팅이 재시작마다 디폴트로 리셋.
원인(코드, NAT 아님): **두 개의 persistence 갭**.
- `current`+`full_tunnel`(full-tunnel egress 선택)이 persist 안 됨 — split만 `split-active.json`으로
  유지되던 비대칭 → meshd 재시작(세션 중 수십 회)마다 `current=None, full_tunnel=false` → Default network.
- `SetExit`(mesh.exit, 어느 멤버가 인터넷 exit인지)가 `persist()` 호출을 안 함 → exit 지정도 재시작에
  유실(#4→null) → full-tunnel 복원이 exit을 못 찾음(반쪽 버그).
고침(commits `dd4be32` egress + `3a46391` exit):
- `persist_egress`/`load_egress`(`egress.json` 0600, `current.filter(|_| full_tunnel)`), SetCurrent/
  RemoveMesh/self-destruct에서 호출. 부팅 복원 블록 = intent(current+full_tunnel) 즉시 세팅 +
  `restore_full_tunnel`이 **exit 도달 가능해질 때까지 대기 후** divert(부팅 시 dead-exit 블랙홀/kill-switch
  방지) + kill-switch 재무장. exit 끝내 안 뜨면 intent 유지 → 네트워크변경/수동 재선택 때 적용.
- `SetExit`에 `persist(st)` 추가(+ exit 삭제 시 `persist_egress`).
- 사용자 선택(AskUserQuestion): "자동 복원(완전 sticky) + preflight 가드".
검증: 빌드(1.79) + 단위테스트 7/7(egress 게이팅 round-trip 신규) + fmt + clippy(기존 needless_borrow와
동일 패턴) + startup 스모크. **라이브 Mac clean-swap 2회**(off→shutdown→quit→ditto→relaunch once,
utun-safe): 최종 `v0.7.14 build 3a46391`==HEAD, 홈 메쉬 재연결(Oracle direct/lablinux relay).
**exit-persist 라이브 검증**: SetExit(home→oracle) → `mesh-1.json` `"exit":1` 디스크 저장 확인.
egress-persist는 단위테스트로 검증(라이브 full-tunnel divert는 사용자 인터넷 방해라 미실행).
NOTE: 검증 중 home.exit=oracle(#1) 지정해둠(inert — full-tunnel 켤 때만 사용, `lattice exit home none`로 해제).
버전 0.7.14 범프(Cargo/tauri.conf). 브랜치 feat/extensions-meshd, **main 미머지 + fleet 미배포**.

## v0.7.13 정식 롤아웃 (fleet 전부 dab561f) + join-modes 라이브 검증 (2026-08-07)

v0.7.13 = extensions + per-mesh `exitable` + exit-fixes + **join-modes(secure/quick)** +
split-persist + meshd single-instance fix + default-mesh. Cert 와이어 byte-identical +
`CTRL_QGRANT`(0x09) append-only → 혼합버전 배포 안전.
- **Fleet 전부 v0.7.13 build dab561f + 연결**: Oracle(systemctl restart, direct
  138.2.14.219:41000), lablinux(LAN SSH 172.28.7.32 바이너리 스왑, relay), Mac(CI dmg
  clean-swap: backup→shutdown→quit→ditto→relaunch once; `version v0.7.13 build dab561f`,
  `default` 명령 동작). 홈 메쉬 3노드 정상.
- **join-modes 라이브 검증**: Oracle이 quick 초대(`invite --quick --max 3 --expire 1h`,
  12101B bearer 코드) 발행 → lablinux가 신원단계 없이 그 코드로 self-register
  (`JoinMesh{name:"lab"}` → `MeshCreated`, GrantCert 로컬 유효, 멤버 `lab`). quick bearer
  가입 경로 e2e 동작 확인. gossip merge 로직은 오프라인 72 유닛테스트로 검증됨.
- **발견(기존 제약, join-modes 무관)**: pinned-port 노드(Oracle=advertise 41000)는 **2번째
  메쉬 데이터플레인이 같은 41000에 바인드 충돌**(`Address already in use` → mesh DOWN) →
  fresh 테스트메쉬(qtest)의 라이브 cross-node gossip은 여기서 막힘. 포트선택 코드는 이번에
  안 건드림 = pre-existing. ERRORS.md 퀵로그 기록. 테스트메쉬 qtest는 양쪽 정리(rm/RemoveMesh).
  — deploy+verify, no code change

## Mac clean-slate reinstall + macOS-fix verification (2026-07-22)

- **Wiped every stale install** (/Applications 0.7.3 app, 0.7.3 dev bundle, ancient Downloads
  dmgs) and **installed the official `Lattice_0.7.4_aarch64.dmg`** to /Applications. State dir
  kept → both meshes auto-rejoined on launch.
- **VERIFIED the two macOS full-tunnel fixes on a fresh, non-churned daemon**: meshd logs
  `v0.7.4 build c00836b`; pf conf is nat-only (no route-to on a client — fix 5cfa960); exit /32
  pin → en0 (no loop — fix 19465bb); **full-tunnel egress = Oracle on try 1** and stays up past
  the kill-switch window. Closes the "clean verification" TEMP item. — config/deploy, no commit

## Per-mesh `exitable` (opt-in serving as exit) — BUILT + macOS live-verified (2026-07-25)

User security policy: serving as an internet exit for a mesh's members = per-mesh opt-in, default
OFF, decoupled from my own egress. A mesh intruder can't proxy through a node unless it made that
mesh exitable. Expresses the "all meshes / selected only / never" policy as per-mesh flags.
- exit.rs enable_nat(subnet)/disable_nat(subnet): NAT only the mesh's overlay subnet
  (100.80.<id>.0/24), not all 100.64/10 — serving one mesh never proxies another. 3 OS, idempotent,
  cleans legacy all-overlay rule. bringup serves only if exitable||pinned (Oracle stays working).
- MeshState/PersistedMesh exitable (local, persisted, serde-default false); IPC SetExitable +
  ApplyExitable; MeshSummary/MeshDetail.exitable; CLI `lattice exitable <mesh> [on|off]` + info;
  GUI toggle in User>Meshes row. Extension per-mesh scoping (policy #3) already existed.
- Commits 42eadac (core+CLI) + 1ef6032 (GUI+docs+EXIT_SHARING.md). 86 tests, fmt/clippy clean,
  offline on/off/persist verified.
- **LIVE (Mac, build 1ef6032): exitable OFF = no active NAT (stale pf file was old build's, not
  loaded); exitable ON = pf `nat on en0 from 100.80.1.0/24` (mesh-1 subnet ONLY, not 100.64/10);
  OFF removes it.** Per-mesh scoping proven. TODO: full cross-node (lablinux→Mac only when Mac
  exitable) + Oracle/lablinux deploy + fleet reinstall.
- Note: Mac GUI showed a white screen after the meshd swap — webview glitch (frontend unchanged);
  ⌘Q + relaunch fixes it. meshd was fine (CLI worked throughout).

## Current-computer-as-exit — cross-node LIVE-verified on lablinux (2026-07-23)

Verified per-domain split-tunnel where the exit is ANOTHER member (incl. this computer acting as
an exit for someone else): updated lablinux to a07da4d (built on Oracle, scp'd; **gave lablinux a
systemd unit** since setsid launches over ssh didn't persist). On lablinux, rule `ifconfig.me →
member #7 (Mac)`, split on → `curl ifconfig.me` returned **203.247.167.58 (the Mac's egress)**,
not lablinux's own 210.107.188.8 — so lablinux's traffic exited through the Mac (path: lablinux →
Oracle relay → Mac NAT → internet), even though Mac↔lablinux can't reach directly (campus
isolation, relayed). off reverted to 210.107.188.8. Mac forwards+NATs as a client (forwarding=1,
pf nat 100.64/10) so it works as an exit without being a pinned exit node.

## Per-domain split-tunnel exit — BUILT + LIVE-verified (2026-07-23)

The user's model: split-tunnel keeps normal traffic on your OWN network by default; only registered
domains use a designated exit — and the RULE should carry the exit, not a mesh-wide setting (the
recurring "set exit to self #7 → can't connect" bug came from the mesh-exit coupling).
- SplitRule gains `exit: MemberId`; a shared `SharedSplitRoutes` map (matched IP → rule exit) is
  passed meshd↔run loop; the run loop checks it BEFORE the flow table → routes that IP to the
  rule's exit, bypassing the mesh exit. Local, no wire change, exit=0 falls back to mesh exit.
- Guard: exit can't be self or an unknown member (kills the trap at the source).
- CLI `split add <domain> <mesh> <exit>`; GUI exit-member picker.
- **LIVE (build 02a37dc): mesh exit = NONE, rule pornhub→member#1(Oracle); pornhub egressed via
  Oracle (utun6, HTTP 200, Oracle RX+21712) while ifconfig.me stayed campus; off restored clean.**
- Commit 02a37dc (+ docs/GUI/CHANGELOG follow-up). Root-cause note: the exit-drift to #2/#7 was
  the USER setting a bad mesh exit in the GUI; per-domain exit + the self-guard remove the whole class.

## Fleet clean-slate reinstall to v0.7.5 (2026-07-23)

Tagged v0.7.5 @ 975d26c (F1 split-tunnel + F2 conns); CI built all-platform installers.
Fresh-installed on every reachable node, GUI + daemon, all verified `v0.7.5 build 975d26c`:
- **Mac**: removed old /Applications app, installed official 0.7.5 dmg fresh, relaunched — LIVE.
- **Oracle** (ubuntu systemd): swapped meshd-Linux-X64 into ~/myVpn/target/release/meshd, restart — LIVE direct exit.
- **lablinux** (hyunseok): `dpkg -i` the 0.7.5 deb (GUI /usr/bin/lattice + meshd both updated),
  relaunched via /tmp/lab-start.sh — LIVE, now DIRECT to Mac (path re-converged on fresh install).
- **Windows**: offline (192.168.0.6 + 10.32.86.243 down) — skipped.
Connection book confirms oracle+lablinux both `direct`. Gotcha: the poisoned `grep` shell wrapper
masked dpkg success output — use `command grep` when reading remote command output.

## F2 connection book — BUILT + LIVE-verified (2026-07-23)

"Auto-discover reachable live members, auto-connect, persist for fast reconnect + surface as
key→value." Auto-discovery/connect/endpoint-persistence ALREADY existed (DHT + gossip +
relay→direct + to_persisted.peers reloaded on start). New: surface the RESULT as a connection
book. MemberView gained `path` (direct/relay/offline/me) + `last_seen_secs`, derived in detail()
from the Link's last_seen_ms/last_direct_ms. `lattice conns <mesh>` renders per-member key→value.
LIVE (build bc0aee3): oracle shown `direct` 11s-ago at 138.2.14.219, correctly classified. — bc0aee3
Deferred: persist path-history for post-restart view; GUI conns card; F2 relay-case live shot
(same last_direct_ms logic, shown in logs earlier).

## F1 domain split-tunnel — BUILT + LIVE-verified (2026-07-23)

Default internet stays direct; specific domains egress via a chosen mesh exit. Local to this node.
- DNS parser + rule types (dns_split.rs, 4 tests) — e12da6f
- exit.rs route_host_via_iface/unroute_host (3 OS, /32, no default touch) — d425584
- DNS proxy + upstream detect (run_proxy/detect_upstream) — d1a96cc
- meshd wiring (IPC SplitAdd/Del/List/On/Off, split.json persist, split_enable/disable 🔴) — 4d5663f
- lattice split CLI (offline-verified) — 105789f
- **LIVE (build 40eb106): pornhub→Oracle (utun6, HTTP 200, Oracle RX+8601); normal traffic
  en0/campus, Oracle RX+0; on/off restores DNS+/32 cleanly** — 91004d5
- docs/SPLIT_TUNNEL.md + GUI Configs split-tunnel card — 42900ad
Deferred: per-domain different exits (ToExit(Some)), AAAA, SNI.

## Release v0.7.4 pushed + tagged (2026-06-24)

- **Pushed `feat/extensions-meshd` (e069aa7..c00836b) + annotated tag `v0.7.4` at c00836b** → Release workflow triggered (run 28096210159, in_progress). NOTE: v0.7.3 release build had failed.
- **Release build SUCCEEDED** (7m20s) — GitHub Release v0.7.4 published with the full asset set
  (macOS .dmg, Windows .msi/-setup.exe, Linux .AppImage/.deb ×2 arch, standalone meshd Linux
  binaries). The v0.7.3 failure did not recur; release.yml needed no fix. (verified 2026-07-22)

## Code documentation pass + process hardening (2026-06-24)

- **meshd/src/main.rs: module edit-risk map + RISK tags on the dangerous fns + `///` on every
  previously-undocumented fn** (🔴 bringup_dataplane/arm_kill_switch/shutdown_daemon; 🟡 handle/
  serve_conn/scope_gate/peer_allowed/main/accept_loop/join_mesh/create_mesh; 🟢 helpers). — this commit
- **meshrun/src/lib.rs: module edit-risk + wire-compat invariant + RISK tags** (🔴6/🟡5/🟢2 on the
  hot loop, wire encode/decode, CTRL_* tags, route/relay, parsers). — this commit
- **CLAUDE.md: working-memory charter** (TEMP.md / COMPLETE.md / docs/ERRORS.md workflow). — `cab97cd`
- **exit.rs: edit-risk ratings on every fn** (🔴 HIGH 14 / 🟡 MED 18 + legend). — `8851c46`
- **exit.rs: module API contract + `///` on every public fn** (3 OS branches; 0% → full). — `9f69ace`
- **CLAUDE.md: "diff the stable baseline first" diagnostic rule.** — `9f69ace`
- **docs/ERRORS.md: blast-radius regression map** ("edit X → re-test Y") + 2026-06-24 incident. — `e069aa7`

## v0.7.4 + macOS full-tunnel fixes (2026-06-24)

- **v0.7.4 version bump** (4 version files + locks + CHANGELOG). — `e8c0d8c`
- **Fix #2 (loop): macOS exit pin idempotent + divert-only-if-pinned (fail closed).** — `19465bb`
- **Fix #1 (own-IP): isolate pf `route-to` only on real exit nodes.** — `5cfa960`
- **Build tooling: meshd build-identity stamp + `scripts/build-app.sh` + BUILD.md/CLAUDE.md charter + Windows VERSIONINFO.** — `24d617b` / `0457b74`
- **Runtime fix: mesh 1 exit was mis-set to #2 (idle) → set to #1 (Oracle); full-tunnel works.** — `lattice exit 1 1` (config, no commit)
- **Oracle updated cb6c868 → e069aa7, restarted; fleet data-plane version-matched.** — deploy
- **Extensions/connector framework committed (+ 2 pre-commit hardening fixes).** — `d2370c1`
- **GUI version sync to 0.7.3.** — `7e50ea9`

## 2026-07-25 — Per-mesh `exitable` (opt-in exit serving) + legacy-NAT purge
- **Per-mesh `exitable` toggle, default OFF** — members can only use my internet as exit if I made
  that mesh exitable; only the mesh's own subnet `100.80.<id>.0/24` is NAT'd (not 100.64/10);
  pinned exits (`MESHD_ADVERTISE`) stay exitable automatically. — `v0.7.7`
- **fix: `exitable=off` now actually stops serving** — a node upgraded from the old always-on
  build kept leftover `100.64.0.0/10` MASQUERADE rules (14 dups on lablinux) → forwarded for
  everyone. meshd now reconciles NAT at bringup + `disable_nat` purges every legacy all-overlay
  rule. Found by the cross-node test. — `af13e63` / released `v0.7.8` (`40aa1f2`)
- **Cross-node verified (Mac client ↔ lablinux #4 exit, v0.7.8 fresh install):**
  exitable OFF → curl ifconfig.me FAILS (dropped; route→utun6 + overlay healthy, so genuinely
  dropped at exit); exitable ON → NAT scoped to `100.80.1.0/24` only, curl → 210.107.188.8
  (lablinux egress); ON→OFF live (no restart) → NAT purged, curl fails again. — verified

## 2026-07-25 — v0.7.9: pinned-exit isolate/own-IP regression (found by user's "diff the code" call)
- **fix**: v0.7.8's per-subnet isolate rule (`ip rule from 100.80.<id>.0/24 lookup 100`, and macOS
  `route-to … to any`) also matched the exit's OWN overlay IP → member↔member replies leaked out
  the real WAN → pinned exit (Oracle) visible in gossip but overlay data path dead after restart.
  Fix: overlay-dest traffic bypasses isolate (Linux `ip rule to 100.64.0.0/10 lookup main prio
  999`; macOS `to ! 100.64.0.0/10`). Only forwarded INTERNET isolates. — `3a3646e` / `v0.7.9`
- **Oracle deployed v0.7.9 + code-path verified**: cleared rules → restart → bringup AUTO-added
  999 bypass + 1000 isolate; `ip route get 100.80.1.7 from 100.80.1.1` → `dev tun0`; Mac→Oracle
  overlay ssh `TUNNEL_OK`; Oracle-exit egress = 138.2.14.219 (isolate still works); NAT =
  `100.80.1.0/24` only. Diagnosis method: diffed last-working baseline (NOT a guessed rekey/OS
  wedge) — logged in docs/ERRORS.md. — verified

## 2026-07-25 — full empirical cross-check (Mac on hotspot) + v0.7.10 hygiene fix
- **Cross-check matrix ALL PASS** after Mac switched to an IPv6/CGNAT hotspot: self-healing
  re-learned the new endpoint and reconnected to both nodes (data-path TCP verified, not just
  gossip); version uniformity; full connectivity matrix; exitable OFF→drop / ON→210.107.188.8 /
  ON→OFF-live-purge / per-subnet NAT; Oracle isolate exit egress 138.2.14.219 + overlay
  simultaneously; split-tunnel; 66+6 unit tests, fmt, clippy clean.
- **Finding #1 (fixed, v0.7.10 `205495d`)**: the v0.7.8 legacy-`100.64/10` purge only ran in
  `disable_nat`, so a pinned exit (enable_nat-only) accumulated 130 leftover `FORWARD 100.64/10
  ACCEPT` rules. `enable_nat` now purges too. Oracle cleaned live + **auto-purge code-path
  validated** (injected 7 fake rules → restart → bringup auto-cleared to 0). lablinux→v0.7.10 too.
- **Finding #2 (documented limitation)**: split/full-tunnel is IPv4-only → on a dual-stack/IPv6
  network a matched domain (AAAA) leaks out over IPv6, bypassing the exit; `curl -4` workaround.
  docs/SPLIT_TUNNEL.md + IPV6_PLAN.md.
- **Finding #3 (minor)**: changing an active split rule's exit member needs `split off/on` re-inject.
- Docs organized: SPLIT_TUNNEL / EXIT_SHARING / EXIT_POLICY (§4 Mechanism → per-subnet + overlay
  bypass) / ERRORS.md / CHANGELOG. Fleet: Oracle+lablinux v0.7.10, Mac v0.7.9 (Linux-only fix).
- **Mac kept at v0.7.9 (user decision 2026-07-25)** — the v0.7.10 fix is Linux-only
  (`#[cfg(target_os="linux")]`), so the macOS binary is functionally identical; avoided another
  utun-risky live-VPN dmg swap. Fleet: Oracle+lablinux v0.7.10, Mac v0.7.9 (byte-equivalent behavior).

## 2026-07-25 — v0.7.11: split-tunnel tied to mesh selection (user: "fix the FUNCTIONALITY")
- **Bug**: split-tunnel was a hidden global switch decoupled from egress selection — on Default
  (`current=None`) it still hijacked host DNS (127.0.0.1) + routed matched domains via a mesh,
  invisible in ls/status ("network is Default, why does pornhub go via Oracle?"). Surfacing it in
  ls/status (first attempt) was rejected — wanted the behavior fixed.
- **Fix (1ab77c2)**: split now SELECTS its mesh (sets `current`, new `full_tunnel=false` flag so
  it's NOT a full tunnel — general traffic stays direct); the **Default network turns split off**
  (restores DNS + removes /32s); shutdown restores DNS when split is on. `current` was hard-wired
  to full-tunnel (network-change re-route loop + shutdown keyed on `current.is_some()`) → added
  `full_tunnel: bool` and gated those on it so a split selection never diverts the default route.
  CLI + GUI show `split` vs full `egress`.
- **Validated**: offline (state gating) + lablinux data-plane (SplitOn→is_current=1 & egress=direct
  & DNS=127.0.0.1; SplitOff→deselect+DNS restored; SetCurrent(None)→split off) + **Mac LIVE**
  (split on → pornhub via utun6/Oracle, ls shows SPLIT; Default network → pornhub via en0 direct,
  DNS restored). Fleet all v0.7.11 (Mac dmg, Oracle+lablinux binary). Merged to main (PR + 77e54a3).

## 2026-07-28 — v0.7.12: split/full-tunnel could strand host DNS at dead 127.0.0.1 (SIGTERM)
- **Bug** (reported on lablinux: "default network → 인터넷 안 됨"): split/full-tunnel points
  /etc/resolv.conf at meshd's 127.0.0.1:53 proxy; when it turned off the resolver was left at the
  now-dead 127.0.0.1 → DNS `connection refused` (routing fine, only name resolution died). Three
  compounding causes: no SIGTERM handler (systemctl stop/restart — used for every deploy — skipped
  the restore), restore_dns no fallback when backup lost, set_dns could back up the hijacked value.
- **Fix (1ff85a8)**: SIGTERM/SIGINT now run shutdown_daemon (restore routes+DNS); restore_dns falls
  back to the systemd-resolved stub / 1.1.1.1 if backup missing & resolv.conf still loopback; set_dns
  captures the backup once. Immediate lablinux repair: relink resolv.conf → systemd stub.
- **Validated**: lablinux data-plane — SplitOn→resolv=127.0.0.1, **systemctl restart (SIGTERM)→resolv
  RESTORED to systemd symlink + DNS works** (was the bug). Deployed all: Mac dmg + Oracle + lablinux
  binary, all v0.7.12, DNS clean, internet 200, mesh reconnected. Merged to main. Note: the running
  meshd was v0.7.11 (not the suspected 7.9); systemd unit showed inactive but a manual process held
  the socket — check /proc/<pid>/exe, not unit state.

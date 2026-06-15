# Lattice GUI — per-page detailed spec / 페이지별 상세 명세

> **Source of truth for the GUI.** Anything in the GUI that is NOT described here
> must be **removed** from the code. Pairs with `docs/GUI.md` (high-level
> structure), `docs/MESH_V2.md` (architecture), and `crates/mesh/src/ipc.rs` (the
> `meshd` IPC contract). Update this doc *first*, then the code.
>
> **GUI의 진실의 원본.** 여기에 설명되지 않은 GUI 기능은 코드에서 **제거**한다.
> `docs/GUI.md`(상위 구조), `docs/MESH_V2.md`(아키텍처), `crates/mesh/src/ipc.rs`
> (`meshd` IPC 계약)와 짝을 이룬다. 항상 **문서를 먼저** 고치고 코드를 고친다.

## 0. Conventions / 규약

- **Data source / 데이터 소스:** the GUI speaks only to **`meshd`** (the v2 control
  plane) over `/tmp/lattice-meshd.sock`. The Tauri Rust layer is one thin proxy
  command `meshd(request: json) → json`; all logic is in the front-end + meshd. The
  legacy v1 daemon (`/tmp/lattice.sock`) is **not used by v2 pages**.
  / GUI는 오직 **`meshd`**(v2 컨트롤 플레인)와 `/tmp/lattice-meshd.sock`으로 통신한다.
  Tauri Rust는 얇은 프록시 명령 `meshd(request)→json` 하나뿐이고 로직은 전부
  프론트+meshd에 있다. v1 데몬은 **v2 페이지에서 쓰지 않는다.**
- **meshd requests / 요청:** `CreateMesh`, `ListMeshes`, `MeshInfo`, `AdmitMember`,
  `SetExit`, `SetCurrent`, `RemoveMesh`, `GetPolicy`.
- **Status legend / 상태 표기:** ✅ implementable now (meshd-backed) · 🔭 planned
  (needs a backend extension named in the page) · ❌ removed.

---

## 1. Top widget bar (global) / 상단 위젯바 (전역)

**Purpose / 목적.** Show at-a-glance status and hold the two global controls:
the **view** (which perspective) and the **egress** (where traffic exits). Present
on every page.
/ 한눈에 보는 상태 + 두 전역 컨트롤(**뷰** = 어떤 관점, **egress** = 트래픽 출구)을
담는다. 모든 페이지 상단에 항상 표시.

**Elements / 구성요소.**
- **Status, far left / 상태(맨 왼쪽):** a colored dot + the current egress summary —
  `egress: <mesh> · exit #<id>`, or `egress: origin` when no mesh routes traffic, or
  `meshd offline` when the socket is unreachable. Read-only.
  / 색 점 + 현재 egress 요약. 메쉬 라우팅이면 `egress: <mesh> · exit #<id>`, 없으면
  `egress: origin`, 소켓 불통이면 `meshd offline`. 읽기 전용.
- **View toggle `User | Mesh` / 뷰 토글:** switches the content perspective. `User`
  = the Meshes page (§2). `Mesh` = the opened mesh's pages (§3), the mesh chosen via
  `manage ›`. Defaults to the first mesh if none opened yet.
  / 콘텐츠 관점 전환. `User`=Meshes 페이지, `Mesh`=`manage ›`로 연 메쉬의 페이지들.
  연 메쉬가 없으면 첫 메쉬로.
- **Egress dropdown `[Origin · mesh …]` / egress 드롭다운:** picks where this
  computer's traffic exits. `Origin` = your normal internet. Selecting a mesh routes
  through it. **Independent of the view toggle.** The selected option mirrors the
  current egress.
  / 이 컴퓨터 트래픽의 출구를 고른다. `Origin`=원래 인터넷, 메쉬 선택=그 메쉬로 라우팅.
  **뷰 토글과 독립.** 선택값은 현재 egress를 반영.

**Daemon connection / 데몬 연결.**
- Refresh (poll ~3s) → `ListMeshes` → `Meshes(MeshSummary[])`; the summary with
  `is_current = true` is the egress; its `exit` fills the status text.
  / 갱신(약 3초 폴링) → `ListMeshes`. `is_current=true`인 항목이 egress이고 그 `exit`가
  상태 텍스트에 들어간다.
- Egress dropdown change → `SetCurrent { mesh: <id|null> }` (`Origin` = `null`).
  / egress 드롭다운 변경 → `SetCurrent { mesh: <id|null> }` (`Origin`=`null`).
- View toggle → **no daemon call** (front-end view state only).
  / 뷰 토글 → **데몬 호출 없음** (프론트 뷰 상태만).

**States & errors / 상태·오류.** Selecting a mesh as egress that has **no exit set**
→ meshd returns `Error("set an exit …")`; show it as a toast and the dropdown
reverts on the next poll. `meshd offline` → dot grey, dropdown disabled.
/ exit가 없는 메쉬를 egress로 고르면 meshd가 `Error`를 반환 → 토스트로 표시, 다음
폴링에 드롭다운 원복. `meshd offline`이면 점 회색, 드롭다운 비활성.

**Status:** ✅

---

## 2. User mode — Meshes page / User 모드 — Meshes 페이지

**Purpose / 목적.** The computer's view of **all the meshes it belongs to**. Create,
inspect, route through (egress), or enter a mesh to manage it. This is the only User
page. / 이 컴퓨터가 속한 **모든 메쉬**의 관점. 생성·확인·egress 지정·관리 진입.
User 모드의 유일한 페이지.

**Elements / 구성요소.**
- **Create-a-mesh form / 메쉬 생성 폼:** inputs `name`, `your name in it` (the §2
  in-mesh name), `max members` (1–254, default 254); **Create** button. On success,
  jumps into the new mesh (Mesh mode, Overview).
  / 입력 `name`, `메쉬 내 내 이름`, `최대 인원(1–254, 기본 254)` + **Create**. 성공 시
  새 메쉬로 진입(Mesh 모드 Overview).
- **Origin row / Origin 행 (top of list / 목록 맨 위):** "your computer's normal
  internet — no mesh." Wears the `egress` badge when no mesh routes traffic. Its
  **make egress** button returns traffic to origin.
  / "원래 인터넷 — 메쉬 없음". 메쉬 라우팅이 없을 때 `egress` 뱃지. **make egress**로
  원래 인터넷 복귀.
- **Mesh rows / 메쉬 행:** each shows `name`, `#id`, member count, epoch, exit, and an
  `egress` badge if it routes traffic. Two buttons: **`manage ›`** (enter Mesh mode
  for it) and **`make egress`** (route traffic through it).
  / 각 행: `name`, `#id`, 인원수, epoch, exit, (라우팅 중이면) `egress` 뱃지. 버튼:
  **`manage ›`**(그 메쉬 관리로 진입), **`make egress`**(그 메쉬로 라우팅).

**Daemon connection / 데몬 연결.**
- List render → `ListMeshes` → `Meshes(MeshSummary{id,name,members,epoch,exit,is_current}[])`.
- Create → `CreateMesh { name, my_name, max_members }` → `MeshCreated { mesh }`.
- `make egress` (mesh row) → `SetCurrent { mesh: id }`; (Origin row) → `SetCurrent { mesh: null }`.
- `manage ›` → front-end: set the viewed mesh and switch to Mesh mode (no call yet;
  Overview then loads via `MeshInfo`).
  / `manage ›` → 프론트: 보는 메쉬 설정 후 Mesh 모드 전환(이 시점 호출 없음, Overview가
  `MeshInfo`로 로드).

**States & errors / 상태·오류.** Empty list → "no meshes yet — create one above"
(Origin row still shown). `make egress` on a mesh without an exit → toast the meshd
error. / 빈 목록 → 안내 문구(Origin 행은 유지). exit 없는 메쉬에 `make egress` →
meshd 오류 토스트.

**Status:** ✅

---

## 3. Mesh mode — Overview page / Mesh 모드 — Overview 페이지

**Purpose / 목적.** The home of a single mesh: see and change everything `meshd`
knows about it. Default page when entering Mesh mode.
/ 단일 메쉬의 홈. `meshd`가 아는 그 메쉬의 모든 것을 보고 바꾼다. Mesh 모드 기본 페이지.

**Elements / 구성요소.**
- **Header / 헤더:** `⬢ <name> #<id>` + actions **make egress** (route traffic
  through this mesh) and **wipe mesh** (local removal — the §5 compromise response;
  confirm dialog).
  / `⬢ <name> #<id>` + **make egress**(이 메쉬로 라우팅), **wipe mesh**(로컬 제거 — §5
  탈취 대응; 확인 다이얼로그).
- **Charter (read-only, immutable) / 헌장(읽기 전용·불변):** invite topology,
  re-cipher trigger, cipher, max members, epoch, my exit. (Per MESH_V2.md §3 the
  charter never changes.)
  / 초대 방식, re-cipher 트리거, cipher, 최대 인원, epoch, 내 exit. (헌장은 불변.)
- **Roster table / 로스터 표:** every member — `id` (1-byte join order), `name`,
  `pubkey` fingerprint; this node marked `(me)`.
  / 멤버 전원 — `id`(1바이트 가입순서), `name`, `pubkey` 지문; 본 노드는 `(me)`.
- **Set my exit / 내 exit 설정:** a select of members → **set exit**. Chooses which
  member this node egresses through *inside this mesh* (per-node exit).
  / 멤버 셀렉트 + **set exit**. 이 메쉬 안에서 이 노드가 어느 멤버로 나갈지(노드별 exit).
- **Admit a member (demo) / 멤버 초대(데모):** `name` + `pubkey (64 hex)` → **admit**.
  Placeholder until the real cert-based invite lands (MESH_V2.md §3).
  / `name` + `pubkey(64 hex)` → **admit**. 실제 cert 기반 초대 전까지의 임시.

**Daemon connection / 데몬 연결.**
- Load → `MeshInfo { mesh }` → `Mesh(MeshDetail{id,name,epoch,me,exit,invite,trigger,
  max_members,cipher,members[]})`.
- set exit → `SetExit { mesh, exit: <id|null> }`.
- admit → `AdmitMember { mesh, name, pubkey_hex }`.
- make egress → `SetCurrent { mesh }`. wipe → `RemoveMesh { mesh }`.

**States & errors / 상태·오류.** `set exit` to a non-member, `admit` with a non-hex
key, or `make egress` without an exit → meshd `Error` shown as a toast. After
**wipe**, return to User mode. / 비멤버 exit 설정, 비-hex 키 admit, exit 없이 make
egress → meshd `Error` 토스트. **wipe** 후 User 모드 복귀.

**Status:** ✅

---

## 4. Mesh mode — planned pages / Mesh 모드 — 계획 페이지

These pages are **specified but not implemented**; they need `meshd` extensions and
must **not** be shown until backed by real per-mesh data. Listing them here is the
contract for when their backend exists.
/ 아래는 **명세만 있고 미구현**. `meshd` 확장이 필요하며 실제 per-mesh 데이터가 생기기
전엔 **표시하지 않는다.** 백엔드가 생겼을 때의 계약으로 여기 적어둔다.

- **Peers / 피어 (🔭):** live connection state of each member in this mesh
  (connected / connecting / via-relay), endpoints, latency. *Needs:* `meshd` to
  expose per-mesh session state (data plane). Until then, member identity lives in
  Overview's roster.
  / 이 메쉬 멤버들의 실시간 연결 상태(직결/연결중/릴레이), 엔드포인트, 지연. *필요:*
  meshd가 per-mesh 세션 상태(데이터 플레인) 노출. 그 전엔 멤버 신원은 Overview 로스터로.
- **Traffic / 트래픽 (🔭):** per-mesh flows (who↔who, bytes/packets). *Needs:* data
  plane + a `meshd` flows query.
  / per-mesh 플로우(누구↔누구, 바이트/패킷). *필요:* 데이터 플레인 + meshd 플로우 질의.
- **Topology / 토폴로지 (◑ static now, live later):** this mesh's graph. The
  **structure** (members + the exit edge) renders now from `MeshInfo` (the cert
  roster + charter exit); **live** connection state (direct/relay/offline) arrives
  with the data plane (P6.3).
  / 이 메쉬의 그래프. **구조**(멤버 + exit 간선)는 지금 `MeshInfo`(cert 로스터 + 헌장
  exit)로 렌더; **라이브** 연결상태(직결/릴레이/오프라인)는 데이터플레인(P6.3) 후.
- **Security / 보안 (🔭):** capture-detection status + crypto epoch/table
  (MESH_V2.md §4–§5). *Needs:* `meshd` to surface epoch + capture state.
  / 탈취 감지 상태 + 암호 epoch/테이블. *필요:* meshd가 epoch·탈취 상태 노출.

---

## 5. Removed from the GUI / GUI에서 제거 (❌)

The v1 GUI carried these; v2 has no use for them, so the code must drop them:
/ v1 GUI에 있던 아래 항목은 v2에 불필요 → 코드에서 제거한다:

- **v1 single-node panels / v1 단일 노드 패널:** the standalone `Status`, `Peers`,
  `Traffic`, `Mesh/Membership`, `Network` sidebar tabs that read the **v1** daemon.
  Their useful parts are folded into §2/§3 or deferred to §4.
  / v1 데몬을 읽던 `Status·Peers·Traffic·Mesh/Membership·Network` 탭. 유용한 부분은
  §2/§3로 흡수했거나 §4로 연기.
- **Central flow-table editor / 중앙 flow-table 편집기:** the `Topology` panel's
  flow add/del/clear UI and the `add_flow_rule`/`del_flow_rule`/`clear_flow_rules`
  Tauri commands. v2 has **no central flow table** (per-node exit instead,
  MESH_V2.md §0).
  / `Topology` 패널의 flow 추가/삭제/초기화 UI + 해당 Tauri 명령들. v2엔 **중앙 flow
  테이블이 없다**(노드별 exit).
- **v1 daemon controls / v1 데몬 제어:** start/stop the v1 daemon, mesh up/down,
  v1 exit/relay/add-peer/join-network controls. (meshd lifecycle + v2 enrollment
  will get their own surfaces later.)
  / v1 데몬 start/stop, mesh up/down, v1 exit/relay/add-peer/join 제어. (meshd 수명주기
  + v2 가입은 추후 별도 표면.)

> Result: v2 GUI = the **widget bar** (§1) + **Meshes** (§2) + **Mesh:Overview**
> (§3). Planned pages (§4) appear only when their backend exists.
> / 결과: v2 GUI = **위젯바**(§1) + **Meshes**(§2) + **Mesh:Overview**(§3). 계획
> 페이지(§4)는 백엔드가 생길 때만 등장.

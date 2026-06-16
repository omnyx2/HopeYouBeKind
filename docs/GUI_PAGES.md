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
  `SetExit`, `SetCurrent`, `RemoveMesh`, `GetPolicy`, **`SetPeer`** (seed a member's
  endpoint), and the join flow **`NewIdentity` / `CreateInvite` / `JoinMesh`**
  (MEMBERSHIP.md §A). The Tauri `meshd` proxy is **async with a 5 s timeout** on a
  blocking thread, so a slow/unresponsive meshd can never freeze the webview.
  / `SetPeer`(멤버 엔드포인트 시드)와 가입 플로우 `NewIdentity`/`CreateInvite`/`JoinMesh`
  추가. Tauri `meshd` 프록시는 별도 블로킹 스레드에서 **async + 5초 타임아웃**이라 meshd가
  느려도 웹뷰가 멈추지 않는다.
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
  `Routing via <mesh> · exit #<id>` when a mesh routes traffic, `Using default
  network` when none does, or `meshd offline` when the socket is unreachable.
  Read-only.
  / 색 점 + 현재 egress 요약. 메쉬 라우팅이면 `Routing via <mesh> · exit #<id>`, 없으면
  `Using default network`, 소켓 불통이면 `meshd offline`. 읽기 전용.
- **View toggle `User | Mesh` / 뷰 토글:** switches the content perspective. `User`
  = the Meshes page (§2). `Mesh` = the current mesh's pages (§3). The current mesh is
  whatever the egress dropdown / `manage ›` selected; on **Default network** (no
  mesh) the Mesh page is **plain** (§3) — it does **not** auto-pick a mesh.
  / 콘텐츠 관점 전환. `User`=Meshes 페이지, `Mesh`=현재 메쉬의 페이지들. 현재 메쉬는 egress
  드롭다운/`manage ›`가 고른 것이고, **Default network**(메쉬 없음)면 Mesh 페이지는
  **플레인**(§3) — 첫 메쉬를 자동 선택하지 않는다.
- **Egress dropdown `[Default network · mesh …]` / egress 드롭다운:** picks where
  this computer's traffic exits. **`Default network`** = your normal internet (no
  mesh). Selecting a mesh routes through it (and makes it the current mesh for the
  Mesh view). **Independent of the view toggle.** The selected option mirrors the
  current egress.
  / 이 컴퓨터 트래픽의 출구를 고른다. **`Default network`**=원래 인터넷(메쉬 없음), 메쉬
  선택=그 메쉬로 라우팅(+그 메쉬가 Mesh 뷰의 현재 메쉬). **뷰 토글과 독립.** 선택값은 현재
  egress를 반영.

**Daemon connection / 데몬 연결.**
- Refresh (poll ~3s) → `ListMeshes` → `Meshes(MeshSummary[])`; the summary with
  `is_current = true` is the egress; its `exit` fills the status text.
  / 갱신(약 3초 폴링) → `ListMeshes`. `is_current=true`인 항목이 egress이고 그 `exit`가
  상태 텍스트에 들어간다.
- Egress dropdown change → `SetCurrent { mesh: <id|null> }` (`Default network` =
  `null`); the front-end also sets the current mesh to that id (or none).
  / egress 드롭다운 변경 → `SetCurrent { mesh: <id|null> }` (`Default network`=`null`);
  프론트는 현재 메쉬도 그 id(또는 없음)로 설정.
- View toggle → **no daemon call** (front-end view state only).
  / 뷰 토글 → **데몬 호출 없음** (프론트 뷰 상태만).

**States & errors / 상태·오류.** Selecting a mesh as egress that has **no exit set**
→ meshd returns `Error("set an exit …")`; show it as a toast and the dropdown
reverts on the next poll. `meshd offline` → dot grey, dropdown disabled.
/ exit가 없는 메쉬를 egress로 고르면 meshd가 `Error`를 반환 → 토스트로 표시, 다음
폴링에 드롭다운 원복. `meshd offline`이면 점 회색, 드롭다운 비활성.

**Status:** ✅

---

User mode has **two pages** (sidebar): **Meshes** (the list you belong to) and **New
mesh** (create one, or join one by invite). Create/join is split out of the list so
the list stays a clean "what am I in / where does my traffic exit" view.
/ User 모드는 사이드바에 **두 페이지**: **Meshes**(속한 목록)와 **New mesh**(생성 또는 초대로
합류). 생성/합류를 목록에서 분리해, 목록은 "내가 뭐에 속했나 / 출구는 어디냐"만 깔끔히 보여준다.

## 2. User mode — Meshes page (the list) / User 모드 — Meshes 페이지(목록)

**Purpose / 목적.** Every mesh this computer belongs to: route through one (egress) or
enter it to manage. No create/join here — that's the New mesh page.
/ 이 컴퓨터가 속한 모든 메쉬: egress 지정 또는 관리 진입. 생성/합류는 여기 없음(New mesh 페이지).

**Elements / 구성요소.**
- **Default network row / Default network 행 (top / 맨 위):** "your computer's normal
  internet — no mesh." **in use** badge when no mesh routes traffic; **use this**
  returns to it. / "원래 인터넷 — 메쉬 없음". 라우팅 없을 때 **in use** 뱃지, **use this**로 복귀.
- **Mesh rows / 메쉬 행:** `name`, `#id`, member count, epoch, exit, `egress` badge if
  routing. **`manage ›`** enters Mesh mode; the egress button **toggles** —
  **`make egress`** ⇄ **`stop egress`** (→ `SetCurrent{null}`).
  / `name`, `#id`, 인원수, epoch, exit, (라우팅 중) `egress` 뱃지. **`manage ›`** 관리 진입;
  egress 버튼 **토글** — **`make egress`** ⇄ **`stop egress`**.
- **`＋ New mesh` button / `＋ New mesh` 버튼:** goes to the New mesh page (§2b).
  / New mesh 페이지(§2b)로 이동.

**Daemon connection / 데몬 연결.**
- List → `ListMeshes` → `Meshes(MeshSummary[])`.
- `make egress` → `SetCurrent { mesh: id }`; `stop egress` / Default-network →
  `SetCurrent { mesh: null }`.
- `manage ›` → front-end: set the viewed mesh + switch to Mesh mode.

**States / 상태.** Empty list → "no meshes yet — create or join one" (Default network
row still shown). / 빈 목록 → 안내 문구(Default network 행 유지).

**Status:** ✅

---

## 2b. User mode — New mesh page (Create / Join) / User 모드 — New mesh 페이지(생성/합류)

**Purpose / 목적.** Get into a mesh: **create** a fresh one (you become member #1 and
the owner), or **join** an existing one with an invite. Two sections on one page.
/ 메쉬에 들어가기: **생성**(내가 member #1 = 소유자) 또는 초대로 **합류**. 한 페이지에 두 섹션.

### A. Create a mesh / 메쉬 생성
- Inputs `name`, `your name in it`, `max members` (1–254, default 254) + **Create** →
  `CreateMesh { name, my_name, max_members }` → `MeshCreated { mesh }` → jump into the
  new mesh (Mesh mode, Overview). / 입력 후 **Create** → 새 메쉬로 진입.

### B. Join a mesh (3-message invite exchange) / 메쉬 합류 (3-메시지 초대 교환)
A **3-message** out-of-band exchange between the **joiner (B)** and the mesh **owner
(A)** — each message is a copy-paste code: / **합류자(B)**와 **소유자(A)** 간 **3-메시지**
대역외 교환 — 각 메시지는 복붙 코드:

1. **B → A: identity code.** B clicks **"Get my join code"** → `NewIdentity` →
   `Identity { member_pubkey_hex, enc_pubkey_hex }`. Front-end encodes
   **`identity code` = base64(JSON{ m, e })**, shown with **Copy**. B sends it to A.
   / B가 **"Get my join code"** → `NewIdentity` → 두 공개키 → **`identity code`=base64(JSON{m,e})**
   를 **Copy**와 함께 표시 → A에게 전달.
2. **A → B: invite code.** A (in that mesh's Overview §3) pastes B's identity code →
   decode → `CreateInvite { mesh, name, member_pubkey_hex, enc_pubkey_hex }` →
   `Invite(InviteBlob)` → **`invite code` = base64(JSON(InviteBlob))** + **Copy** →
   sends it to B. / A가 메쉬 Overview(§3)에서 B의 identity code 붙여넣기 → `CreateInvite` →
   `Invite` → **`invite code`=base64(JSON(InviteBlob))** + **Copy** → B에게 전달.
3. **B joins.** B pastes the invite code into **"Paste invite"** → decode →
   `JoinMesh { invite }` → `MeshCreated { mesh }` → jump into the mesh.
   / B가 invite code를 **"Paste invite"**에 붙여넣기 → `JoinMesh` → 메쉬로 진입.

**Elements / 구성요소.** **"Get my join code"** button → read-only **identity code**
box + **Copy**; **"Paste invite"** textarea + **Join**. (The owner's "create invite"
UI lives on the per-mesh Overview §3 — it needs the master key, which only the owner's
mesh holds.) / **"Get my join code"** → identity code 박스 + **Copy**; **"Paste invite"**
+ **Join**. (소유자의 "초대 만들기"는 per-mesh Overview §3 — master 키 보유 메쉬만 가능.)

**Codes / 코드 형식.** `identity code` / `invite code` are **base64 of compact JSON** —
one copy-pasteable string each (identity short; invite ≈ 1–2 KB: it carries the roster
+ sealed secret). Encode/decode is front-end only; meshd sees raw hex / `InviteBlob`.
/ 둘 다 **compact JSON의 base64** — 한 줄 복붙. invite는 로스터+sealed secret으로 1–2KB.
인코딩/디코딩은 프론트에서만.

**States & errors / 상태·오류.** Bad code → toast "invalid code". Join when already in
that mesh → `Error("already in mesh N")`. `NewIdentity` runs on **B's** machine (private
keys stay there); the identity code carries only public keys.
/ 잘못된 코드 → 토스트. 이미 속한 메쉬 합류 → `Error`. `NewIdentity`는 **B 머신**에서(개인키
보관), identity code엔 공개키만.

**Status:** ⏳ to build / 구현 예정

---

## 3. Mesh mode — Overview page / Mesh 모드 — Overview 페이지

**Purpose / 목적.** The home of a single mesh: see and change everything `meshd`
knows about it. Default page when entering Mesh mode. When there is **no current
mesh** (egress = Default network), this page is **plain** — "On the default network
— no mesh selected" — it does not auto-open a mesh.
/ 단일 메쉬의 홈. `meshd`가 아는 그 메쉬의 모든 것을 보고 바꾼다. Mesh 모드 기본 페이지.
**현재 메쉬가 없으면**(egress=Default network) 이 페이지는 **플레인**("On the default
network — no mesh selected") — 메쉬를 자동으로 열지 않는다.

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
- **Invite a member (owner) / 멤버 초대(소유자):** paste the joiner's **identity code**
  (from their "Get my join code", §2b) + a `name` → **Create invite** → shows the
  **invite code** to **Copy** and send back to the joiner. Only on a mesh you own (it
  holds the master key); for non-owned meshes this section is hidden/disabled. This
  is step 2 of the §2b exchange. / 합류자의 **identity code**(그쪽 "Get my join code", §2b)
  + `name` 붙여넣기 → **Create invite** → 복사할 **invite code** 표시 → 합류자에게 회신.
  소유 메쉬(master 키)에서만; 그 외엔 숨김/비활성. §2b 교환의 2단계.

**Daemon connection / 데몬 연결.**
- Load → `MeshInfo { mesh }` → `Mesh(MeshDetail{id,name,epoch,me,exit,invite,trigger,
  max_members,cipher,members[]})`.
- set exit → `SetExit { mesh, exit: <id|null> }`.
- create invite → decode the pasted identity code → `CreateInvite { mesh, name,
  member_pubkey_hex, enc_pubkey_hex }` → `Invite(InviteBlob)` → front-end base64-encodes
  the blob into the **invite code**.
- make egress → `SetCurrent { mesh }`. wipe → `RemoveMesh { mesh }`.

**States & errors / 상태·오류.** `set exit` to a non-member, an invalid identity code,
a full/duplicate-member invite, or `make egress` without an exit → meshd/decode
`Error` shown as a toast. After **wipe**, return to User mode. / 비멤버 exit, 잘못된
identity code, 가득 찼거나 중복 멤버 초대, exit 없이 make egress → 오류 토스트. **wipe** 후
User 모드 복귀.

**Status:** ✅

---

## 4. Mesh mode — Peers, Topology (live), Traffic/Security (planned) / Mesh 모드

Peers and Topology are **live** (P6.3 done): `MeshInfo`'s `MemberView` now carries
`endpoint` + `state` (`me` | `live` | `idle` | `unknown`; `live` = heard within
30 s). Both poll every **3 s** while open. Traffic and Security remain planned.
/ Peers·Topology는 **라이브**(P6.3 완료): `MeshInfo`의 `MemberView`가 `endpoint`+`state`
(`me`|`live`|`idle`|`unknown`; `live`=30초 내 수신)를 실어 보낸다. 둘 다 열려 있는 동안
**3초** 폴링. Traffic·Security는 계획.

- **Peers / 피어 (✅ live):** a member table — `id · name · pubkey · role` plus a
  coloured **state badge** (`me`/`live`/`idle`/`unknown`) and the member's endpoint.
  / 멤버 표 — `id · name · pubkey · 역할` + 색 **state 뱃지** + 엔드포인트.
- **Topology / 토폴로지 (✅ live):** a radial graph from `MeshInfo`. Node + edge
  colour by liveness: **green = live link**, **violet = exit**, **dashed slate =
  idle**, blue = this node.
  / `MeshInfo` 기반 방사형 그래프. 노드·간선 색으로 상태 표현: **초록=라이브**, **보라=exit**,
  **점선 회색=idle**, 파랑=본 노드.
- **Traffic / 트래픽 (🔭):** per-mesh flows (who↔who, bytes/packets). *Needs:* a
  `meshd` flows query.
  / per-mesh 플로우. *필요:* meshd 플로우 질의.
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
> (§3) + the live **Peers** and **Topology** (§4). Traffic/Security (§4) appear only
> when their backend exists.
> / 결과: v2 GUI = **위젯바**(§1) + **Meshes**(§2) + **Mesh:Overview**(§3) + 라이브
> **Peers·Topology**(§4). Traffic·Security(§4)는 백엔드가 생길 때만 등장.

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
- **meshd requests / 요청:** `CreateMesh`, `ListMeshes`, `MeshInfo`, `SetExit`,
  `SetCurrent`, `RemoveMesh`, **`SetPeer`** (seed a member's endpoint), the join flow
  **`NewIdentity` / `CreateInvite` / `JoinMesh`** (MEMBERSHIP.md §A), the
  crypto/attack ops **`Recipher` / `ReportAttack` / `AllClear`** + the lists
  **`Ciphers` / `InviteAlgorithms`** (docs/GUI_CRYPTO.md), and **`ExportState`**
  (back up all meshes to disk before an update). The Tauri `meshd` proxy is **async
  with a 5 s timeout** on a blocking thread, so a slow/unresponsive meshd can never
  freeze the webview.
  / `SetPeer`(멤버 엔드포인트 시드), 가입 플로우 `NewIdentity`/`CreateInvite`/`JoinMesh`,
  암호/공격 op `Recipher`/`ReportAttack`/`AllClear` + 목록 `Ciphers`/`InviteAlgorithms`,
  그리고 `ExportState`(업데이트 전 전체 메쉬 백업) 사용. Tauri `meshd` 프록시는 별도
  블로킹 스레드에서 **async + 5초 타임아웃**이라 meshd가 느려도 웹뷰가 멈추지 않는다.
- **Non-meshd Tauri commands / meshd 외 Tauri 명령:** `check_update` (queries GitHub
  Releases on launch), `open_url` (open the download page), `notify` (desktop
  notification when an attack is first detected). These back the desktop shell, not
  the mesh control plane.
  / `check_update`(실행 시 GitHub Releases 질의), `open_url`(다운로드 페이지 열기),
  `notify`(공격 최초 감지 시 데스크톱 알림). 메쉬 컨트롤 플레인이 아닌 데스크톱 셸용.
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

**Banners (stacked below the bar) / 배너(바 아래에 적층).**
- **Update banner / 업데이트 배너:** on launch `checkForUpdate()` → `check_update`
  (GitHub Releases). If a newer build exists: *"New version X available (you have Y)"*
  + **Update** (→ `ExportState` to back up meshes, then `open_url` to the download
  page) + **Later** (dismiss). Hidden when up to date / offline.
  / 실행 시 `checkForUpdate()`→`check_update`. 최신 빌드 있으면 안내 + **Update**(메쉬 백업
  `ExportState` → `open_url`로 다운로드 페이지) + **Later**(닫기). 최신/오프라인이면 숨김.
- **Attack banner / 공격 배너:** global; when any mesh is armed for self-destruct,
  a red countdown bar + a creator-only **All clear**. Polls `ListMeshes` every 3 s.
  (Detail in docs/GUI_CRYPTO.md G-3.)
  / 전역; 어떤 메쉬가 자폭 무장되면 빨간 카운트다운 바 + 생성자 전용 **All clear**.
  `ListMeshes` 3초 폴링. (자세한 건 docs/GUI_CRYPTO.md G-3.)

**States & errors / 상태·오류.** Selecting a mesh as egress that has **no exit set**
→ meshd returns `Error("set an exit …")`; show it as a toast and the dropdown
reverts on the next poll. `meshd offline` → dot grey, dropdown disabled.
/ exit가 없는 메쉬를 egress로 고르면 meshd가 `Error`를 반환 → 토스트로 표시, 다음
폴링에 드롭다운 원복. `meshd offline`이면 점 회색, 드롭다운 비활성.

**Status:** ✅

---

User mode has **three pages** (sidebar): **Meshes** (the list you belong to),
**Create mesh** (start a fresh one), and **Join mesh** (join one by invite).
Create and Join are split out of the list — and from each other — so the list stays
a clean "what am I in / where does my traffic exit" view.
/ User 모드는 사이드바에 **세 페이지**: **Meshes**(속한 목록), **Create mesh**(새로 생성),
**Join mesh**(초대로 합류). 생성/합류를 목록에서, 그리고 서로에서 분리해 목록은 "내가 뭐에
속했나 / 출구는 어디냐"만 깔끔히 보여준다.

## 2. User mode — Meshes page (the list) / User 모드 — Meshes 페이지(목록)

**Purpose / 목적.** Every mesh this computer belongs to: route through one (egress) or
enter it to manage. No create/join here — those are the Create mesh / Join mesh pages.
/ 이 컴퓨터가 속한 모든 메쉬: egress 지정 또는 관리 진입. 생성/합류는 여기 없음(Create mesh /
Join mesh 페이지).

**Elements / 구성요소.**
- **Default network row / Default network 행 (top / 맨 위):** "your computer's normal
  internet — no mesh." **in use** badge when no mesh routes traffic; **use this**
  returns to it. / "원래 인터넷 — 메쉬 없음". 라우팅 없을 때 **in use** 뱃지, **use this**로 복귀.
- **Mesh rows / 메쉬 행:** `name`, `#id`, member count, epoch, exit, `egress` badge if
  routing. **`manage ›`** enters Mesh mode; the egress button **toggles** —
  **`make egress`** ⇄ **`stop egress`** (→ `SetCurrent{null}`).
  / `name`, `#id`, 인원수, epoch, exit, (라우팅 중) `egress` 뱃지. **`manage ›`** 관리 진입;
  egress 버튼 **토글** — **`make egress`** ⇄ **`stop egress`**.
- **`＋ New mesh` button / `＋ New mesh` 버튼:** goes to the Create mesh page (§2b-A).
  / Create mesh 페이지(§2b-A)로 이동.

**Daemon connection / 데몬 연결.**
- List → `ListMeshes` → `Meshes(MeshSummary[])`.
- `make egress` → `SetCurrent { mesh: id }`; `stop egress` / Default-network →
  `SetCurrent { mesh: null }`.
- `manage ›` → front-end: set the viewed mesh + switch to Mesh mode.

**States / 상태.** Empty list → "no meshes yet — create or join one" (Default network
row still shown). / 빈 목록 → 안내 문구(Default network 행 유지).

**Status:** ✅

---

## 2b-A. User mode — Create mesh page / User 모드 — Create mesh 페이지

**Purpose / 목적.** Create a fresh mesh: you become member #1 and hold the root key.
The conditions are fixed at creation. / 새 메쉬 생성: 내가 member #1이며 루트 키 보유.
조건은 생성 시 고정.

**Elements / 구성요소.**
- **Basics card / 기본 카드:** `mesh name`, `your name in it`, `max members`
  (1–254, default 254), and a **permanent cipher `<select>`** (from `Ciphers`;
  default first) with an *experimental-cipher* warning line that shows when a
  non-default cipher is picked. / 메쉬 이름, 내 이름, 최대 인원(1–254, 기본 254),
  **영구 cipher `<select>`**(`Ciphers`, 기본 첫번째) + 비기본 선택 시 *실험 cipher* 경고.
- **Conditions card (two toggles) / 조건 카드(토글 두 개):**
  - **"Only I can invite" (master-gated) / "나만 초대 가능"(마스터 게이트):** off (default)
    = open-chain, **any member can invite**; on = only the creator. / 꺼짐(기본)=오픈체인
    (아무 멤버나 초대), 켜짐=생성자만.
  - **"Ephemeral — self-destruct when isolated" / "임시 — 고립 시 자폭":** off by default;
    when on, the mesh keys self-destruct if too few members stay live (laptop-friendly
    to leave off). / 기본 꺼짐; 켜면 살아있는 멤버가 너무 적을 때 키 자폭(노트북은 꺼두는 게 편함).
- **Create mesh button / 생성 버튼.**

**Daemon connection / 데몬 연결.** **Create** → `CreateMesh { name, my_name,
max_members, cipher, self_destruct, master_gated }` → `MeshCreated { mesh }` → jump
into the new mesh (Mesh mode, Overview). / **Create** → `CreateMesh{…, self_destruct,
master_gated}` → 새 메쉬로 진입.

**States & errors / 상태·오류.** Empty name or `max` outside 1–254 → toast, no call.
/ 이름 누락 또는 max 범위 밖 → 토스트, 호출 없음.

**Status:** ✅ built / 구현됨

---

## 2b-B. User mode — Join mesh page (3-message invite exchange) / User 모드 — Join mesh 페이지

**Purpose / 목적.** Join an existing mesh with an invite. / 초대로 기존 메쉬에 합류.

### Join a mesh (3-message invite exchange) / 메쉬 합류 (3-메시지 초대 교환)
A **3-message** out-of-band exchange between the **joiner (B)** and the mesh **owner
(A)** — each message is a copy-paste code: / **합류자(B)**와 **소유자(A)** 간 **3-메시지**
대역외 교환 — 각 메시지는 복붙 코드:

1. **B → A: identity code.** B clicks **"Get my join code"** → `NewIdentity` →
   `Identity { member_pubkey_hex, enc_pubkey_hex }`. Front-end encodes
   **`identity code` = base64(JSON{ m, e })**, shown with **Copy**. B sends it to A.
   / B가 **"Get my join code"** → `NewIdentity` → 두 공개키 → **`identity code`=base64(JSON{m,e})**
   를 **Copy**와 함께 표시 → A에게 전달.
2. **A → B: invite code.** A (in that mesh's **Configs ▸ Invite a member** §5) pastes
   B's identity code → decode → `CreateInvite { mesh, name, member_pubkey_hex,
   enc_pubkey_hex, issued_at, algo }` → `Invite(WrappedInvite)` → **`invite code` =
   base64(JSON(WrappedInvite))** + **Copy** → sends it (and, separately, the
   **algorithm** name, P-C6) to B. / A가 메쉬 **Configs ▸ Invite a member**(§5)에서 B의
   identity code 붙여넣기 → `CreateInvite` → **`invite code`** + **Copy** → B에게 코드와
   (별도로) **알고리즘** 이름을 전달.
3. **B joins.** B pastes the invite code into **"Paste invite"**, sets the
   **algorithm `<select>`** to what A told them → decode → `JoinMesh { invite, algo }`
   → `MeshCreated { mesh }` → jump into the mesh.
   / B가 invite code를 붙여넣고 **algorithm `<select>`**을 A가 알려준 값으로 → `JoinMesh{invite,algo}`
   → 메쉬로 진입.

**Elements / 구성요소.** **"Get my join code"** button → read-only **identity code**
box + **Copy**; a **"Paste invite"** textarea + an **algorithm `<select>`** (from
`InviteAlgorithms`, P-C6) + **Join**. (The owner's "create invite" UI lives on the
per-mesh **Configs** §5 — it needs the master key, which only the owner's mesh holds.)
/ **"Get my join code"** → identity code 박스 + **Copy**; **"Paste invite"** + **algorithm
`<select>`**(`InviteAlgorithms`, P-C6) + **Join**. (소유자의 "초대 만들기"는 per-mesh
**Configs** §5 — master 키 보유 메쉬만 가능.)

**Codes / 코드 형식.** `identity code` / `invite code` are **base64 of compact JSON** —
one copy-pasteable string each (identity short; invite ≈ 1–2 KB: it carries the roster
+ sealed secret). Encode/decode is front-end only; meshd sees raw hex / `InviteBlob`.
/ 둘 다 **compact JSON의 base64** — 한 줄 복붙. invite는 로스터+sealed secret으로 1–2KB.
인코딩/디코딩은 프론트에서만.

**States & errors / 상태·오류.** Bad code → toast "invalid invite code". Wrong
**algorithm** → `Error("could not open the invite …")`. Join when already in that mesh
→ `Error("already in mesh N")`. `NewIdentity` runs on **B's** machine (private keys
stay there); the identity code carries only public keys.
/ 잘못된 코드 → 토스트. 잘못된 **알고리즘** → `Error`. 이미 속한 메쉬 합류 → `Error`.
`NewIdentity`는 **B 머신**에서(개인키 보관), identity code엔 공개키만.

**Status:** ✅ built / 구현됨

---

Mesh mode has **five tabs** (sidebar): **Overview** (summary + roster), **Peers**,
**Topology**, **Warnings** (red badge = open-alert count), and **Configs** (all the
controls). The controls used to sit on Overview; they were moved out to **Configs** so
Overview reads at a glance.
/ Mesh 모드 사이드바 **다섯 탭**: **Overview**(요약+로스터), **Peers**, **Topology**,
**Warnings**(빨간 뱃지=열린 경고 수), **Configs**(모든 컨트롤). 컨트롤은 Overview에서
**Configs**로 이동해 Overview를 한눈에 읽게 했다.

## 3. Mesh mode — Overview page (summary + roster) / Mesh 모드 — Overview 페이지(요약+로스터)

**Purpose / 목적.** The home of a single mesh: a read-at-a-glance summary + the
roster. Default page when entering Mesh mode. When there is **no current mesh**
(egress = Default network), this page is **plain** — "On the default network — no mesh
selected" — it does not auto-open a mesh. The controls live on **Configs** (§5);
alerts on **Warnings** (§6).
/ 단일 메쉬의 홈: 한눈에 보는 요약 + 로스터. Mesh 모드 기본 페이지. **현재 메쉬가
없으면**(egress=Default network) **플레인**("On the default network — no mesh selected")
— 자동으로 열지 않는다. 컨트롤은 **Configs**(§5), 경고는 **Warnings**(§6).

**Elements / 구성요소.**
- **Header / 헤더:** `⬢ <name> #<id>` + a single action **make egress** (route traffic
  through this mesh). / `⬢ <name> #<id>` + 단일 액션 **make egress**.
- **Warnings link / 경고 링크:** when any warnings are active, a red *"⚠ N active —
  open Warnings"* link that jumps to the Warnings tab (§6). / 경고가 있으면 빨간 *"⚠ N
  active"* 링크 → Warnings 탭(§6)으로 이동.
- **Charter line / 헌장 줄:** invite topology · re-cipher trigger · max members ·
  **persistent / ephemeral (self-destruct)**. (Per MESH_V2.md §3 the charter never
  changes.) / 초대 방식 · re-cipher 트리거 · 최대 인원 · **persistent / ephemeral(자폭)**. (헌장 불변.)
- **Cipher · epoch · health · my exit:** cipher; epoch; **health** = `live/total ·
  floor T` (+ an `⚠ ARMED Ns` flag when attack-armed, G-4); my exit (`#id` or none).
  / cipher; epoch; **health** = `live/total · floor T`(무장 시 `⚠ ARMED Ns`, G-4); 내 exit.
- **Roster table / 로스터 표:** every member — `id` (1-byte join order), `name`,
  `pubkey` fingerprint; this node marked `(me)`.
  / 멤버 전원 — `id`(1바이트 가입순서), `name`, `pubkey` 지문; 본 노드는 `(me)`.

**Daemon connection / 데몬 연결.**
- Load → `MeshInfo { mesh }` → `Mesh(MeshDetail{id,name,epoch,exit,invite,trigger,
  max_members,cipher,self_destruct,live,threshold,attack_armed_secs_left,is_creator,
  members[]})`.
- make egress → `SetCurrent { mesh }`.

**States & errors / 상태·오류.** `make egress` without an exit set → meshd `Error`
toast. / exit 없이 make egress → 오류 토스트.

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
  `meshd` flows query. / per-mesh 플로우. *필요:* meshd 플로우 질의.

(Capture-detection / attack alerts now have their own **Warnings** tab — §6; the
mesh's controls live on **Configs** — §5.) / 탈취 감지·공격 경고는 이제 **Warnings**
탭(§6), 메쉬 컨트롤은 **Configs**(§5).

---

## 5. Mesh mode — Configs page / Mesh 모드 — Configs 페이지

**Purpose / 목적.** All of a mesh's controls, as cards — what used to live on
Overview. / 메쉬의 모든 컨트롤을 카드로 — 예전엔 Overview에 있던 것들.

**Cards / 카드.**
- **Egress & routing / Egress·라우팅:** shows `my exit`; a members `<select>` →
  **set exit** (per-node exit *inside this mesh*); **make egress** (route this
  computer's traffic through the mesh). IPC: `SetExit { mesh, exit:<id|null> }`,
  `SetCurrent { mesh }`. / `my exit` 표시; 멤버 `<select>` → **set exit**(이 메쉬 안
  노드별 exit); **make egress**. IPC: `SetExit`, `SetCurrent`.
- **Peer address (manual) / 피어 주소(수동):** a member `<select>` + an `ip:port`
  input → **set address**. Seeds where to reach a member (the rest is learned once a
  peer speaks). IPC: `SetPeer { mesh, member, endpoint }`. / 멤버 `<select>` +
  `ip:port` → **set address**. IPC: `SetPeer`.
- **Invite a member (owner) / 멤버 초대(소유자):** a `name` input, an **algorithm
  `<select>`** (from `InviteAlgorithms`, P-C6), and a textarea for the joiner's
  **identity code** → **create invite** → shows the **invite code** to **Copy** +
  a reminder to tell them the algorithm over a different channel. This is step 2 of
  the §2b-B exchange. IPC: `CreateInvite { mesh, name, member_pubkey_hex,
  enc_pubkey_hex, issued_at, algo }` → `Invite(WrappedInvite)`. / 이름 + **algorithm
  `<select>`** + identity code 붙여넣기 → **create invite** → **invite code**(Copy) +
  알고리즘은 다른 채널로 전달. §2b-B 2단계. IPC: `CreateInvite` → `Invite`.
- **Security / re-cipher (P-C3) / 보안·재암호화:** a cipher `<select>` (current
  selected) + **re-cipher** → a confirm dialog, then `Recipher { mesh, cipher:<select
  or null> }`. Rotates the key (and cipher if changed); needs ≥60% online — anyone
  offline now is evicted. / cipher `<select>` + **re-cipher** → 확인 후 `Recipher`.
  키(변경 시 cipher) 회전; ≥60% 온라인 필요, 지금 오프라인은 축출.
- **Danger zone / 위험 구역:** **Report attack** → a *type-the-mesh-name* confirm →
  `ReportAttack { mesh }` (alerts every member, self-destructs in 30 s unless the
  creator all-clears — see §6 / GUI_CRYPTO G-3); **wipe mesh** → confirm →
  `RemoveMesh { mesh }` (local removal only; the §5 compromise response). / **Report
  attack** → *메쉬 이름 입력* 확인 → `ReportAttack`(전원 경보, 30초 자폭, 생성자 all-clear
  전까지 — §6/GUI_CRYPTO G-3); **wipe mesh** → 확인 → `RemoveMesh`(로컬 제거).

**States & errors / 상태·오류.** Non-member exit, invalid identity code,
full/duplicate-member invite, re-cipher below quorum, or `make egress` without an
exit → meshd/decode `Error` toast. After **wipe**, return to User mode.
/ 비멤버 exit, 잘못된 identity code, 가득/중복 초대, 쿼럼 미달 재암호화, exit 없이 make egress
→ 오류 토스트. **wipe** 후 User 모드 복귀.

**Status:** ✅

---

## 6. Mesh mode — Warnings page / Mesh 모드 — Warnings 페이지

**Purpose / 목적.** Active alerts for the current mesh — attack detection and
liveness/health — derived front-end from `MeshDetail` (`meshWarnings(d)`). The
sidebar tab carries a **red count badge** of open warnings. / 현재 메쉬의 활성 경고 —
공격 감지 + 생존/건강 — `MeshDetail`에서 프론트가 도출(`meshWarnings(d)`). 사이드바 탭에
열린 경고 수의 **빨간 뱃지**.

**Warnings / 경고.**
- **Attack — mesh self-destructing / 공격 — 메쉬 자폭** (when `attack_armed_secs_left
  != null`): a detailed card — the one-veto / fail-deadly explanation (P-C7), a live
  **"Self-destruct in Ns"** countdown, and a creator-only **All clear** button
  (`AllClear { mesh }`). / 상세 카드 — one-veto/fail-deadly 설명(P-C7), **"Self-destruct
  in Ns"** 카운트다운, 생성자 전용 **All clear**(`AllClear`).
- **Below live quorum / 라이브 쿼럼 미달** (when `live < threshold`): an amber card —
  *"X/Y live, floor Z"*; an ephemeral mesh adds a note that it self-destructs if it
  stays below the floor. / 앰버 카드 — *"X/Y live, floor Z"*; ephemeral 메쉬는 바닥 아래
  지속 시 자폭 주석 추가.
- **No warnings / 경고 없음:** *"✓ No warnings — healthy."* / *"✓ No warnings — healthy."*

**Refresh & notify / 갱신·알림.**
- `updateMeshWarnings()` polls `MeshInfo` every **3 s**, updates the badge count, and
  re-renders the page if it's open. / `updateMeshWarnings()`가 `MeshInfo`를 **3초**
  폴링해 뱃지 수 갱신, 열려 있으면 페이지 재렌더.
- A **desktop notification** (`notify`) fires **once** when an attack is first
  detected for a mesh. / 메쉬에 공격이 처음 감지되면 **데스크톱 알림**(`notify`)이 **한 번**.

**Status:** ✅

---

## 7. Removed from the GUI / GUI에서 제거 (❌)

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

> Result: v2 GUI = the **widget bar** (§1, + Update/Attack banners) + User mode
> **Meshes / Create mesh / Join mesh** (§2, §2b-A, §2b-B) + Mesh mode
> **Overview · Peers · Topology · Warnings · Configs** (§3, §4, §5, §6). Traffic
> (§4) appears only when its backend exists.
> / 결과: v2 GUI = **위젯바**(§1, +업데이트/공격 배너) + User 모드 **Meshes / Create mesh
> / Join mesh**(§2, §2b-A, §2b-B) + Mesh 모드 **Overview · Peers · Topology · Warnings
> · Configs**(§3, §4, §5, §6). Traffic(§4)는 백엔드가 생길 때만 등장.

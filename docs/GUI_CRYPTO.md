# GUI spec — protocol features (P-C1..P-C7) / GUI 명세 — 프로토콜 기능

How the new crypto/attack-response protocol surfaces in the desktop GUI. **Docs-first:
every feature → its panel location, the control, the IPC binding, the UX/safeguards,
and any IPC additions needed.** Build order at the end (G-1..G-4). / 새 프로토콜이 GUI에
어떻게 드러나는지. **문서 먼저:** 기능 → 위치 → 컨트롤 → IPC → UX/안전장치 → 필요한 IPC 추가.

> Threat model (user, 2026-06-16): **members are trusted** (no malicious insider).
> So the dangerous controls below are about *operator mistakes*, not defending against
> a hostile member. / 위협모델: **멤버는 신뢰**(악의 내부자 없음) → 위험 컨트롤은 *운영자 실수*
> 방지용.

---

## 1. Exposed now vs new / 현재 노출 vs 신규

| Feature | IPC | GUI today | Plan |
|---|---|---|---|
| Per-mesh cipher at creation (P-C1) | `CreateMesh{cipher}`, `Ciphers` | ✅ Create-form dropbox + warning | — done |
| Re-cipher / rotate key (P-C3) | `Recipher{mesh,cipher?}` | ❌ none | **G-1** |
| Invite algorithm secrecy (P-C6) | `CreateInvite{algo}`, `JoinMesh{algo}`, `InviteAlgorithms` | ❌ defaulted, no UI | **G-2** |
| Attack report / all-clear (P-C7) | `ReportAttack`, `AllClear` | ❌ none | **G-3** |
| Live-paired health + armed state (P-C4/P-C7) | (needs MeshDetail fields) | ❌ not surfaced | **G-4** |
| Current cipher + epoch (P-C3) | `MeshInfo` (`cipher`,`epoch`) | partial (charter line) | G-4 |

---

## 2. Feature specs / 기능별 명세

### G-1. Re-cipher (rotate key / change cipher) — Mesh ▸ Overview
- **Where:** a card on the **mesh-overview** panel, "Security".
- **Control:** a **`Re-cipher`** button + a cipher `<select>` (current selected; from `Ciphers`).
  Optional: leave the select unchanged ⇒ key-only rotation; change it ⇒ also switch cipher.
- **IPC:** `Recipher { mesh, cipher: <select or null> }` → `Ok` / `Error`.
- **UX / safeguards (operator-mistake guard):** a **confirm dialog**: *"Re-cipher rotates this
  mesh's key (and cipher). It needs ≥60% of members online; anyone offline right now is
  evicted and must be re-invited. Continue?"* On `Error` (quorum not met) show the daemon's
  message (`re-cipher needs ≥60% online — X/N up`).
- **After:** toast "re-ciphered → epoch N+1"; the Overview cipher/epoch (G-4) updates.

### G-2. Invite algorithm secrecy — New mesh ▸ Join, and Overview ▸ Invite
The invite-wrap algorithm is **not** in the invite code; it's shared human-to-human (P-C6).
- **Inviter side (Overview ▸ "Invite a member"):**
  - An **algorithm `<select>`** (from `InviteAlgorithms`; default first). 
  - On creating the invite, show **two things to send the joiner separately**: the invite
    code (textarea) **and** a clear line *"Tell them the algorithm: **mix-chacha-v1**"* — with
    a hint to send it over a *different* channel than the code.
  - **IPC:** `CreateInvite { …, algo: <select> }`.
- **Joiner side (New mesh ▸ Join a mesh):**
  - An **algorithm `<select>`** (from `InviteAlgorithms`) the joiner sets to what the inviter
    told them, next to the "paste invite" box.
  - **IPC:** `JoinMesh { invite, algo: <select> }`. On the wrong algorithm the daemon returns
    *"could not open the invite — wrong algorithm or corrupt code"* → show it inline (and, per
    P-C7b later, this is what would feed the 3-strike).
- **Identity TTL (P-C6):** the join code carries `issued_at` and expires in 10 min. Show a small
  *"code valid ~10 min"* note by "Get my join code"; if `CreateInvite` errors *"identity code
  expired"*, prompt the joiner to regenerate.

### G-3. Attack response (report / all-clear) — Overview + global banner
**Fail-deadly, one-veto** (§7): a report destroys the mesh in `ATTACK_GRACE` (30s) unless the
creator all-clears. The GUI must make this **hard to trigger by accident** and **obvious when
armed**.
- **Report control (Overview ▸ Security, danger zone):** a red **`Report attack`** button →
  a **strong confirm** (type the mesh name, or a two-step "Yes, this is an attack"): *"This
  ALERTS every member and DESTROYS the mesh in 30s unless the creator calls it off. The mesh and
  its keys are wiped everywhere. Continue?"* → `ReportAttack { mesh }`.
- **Armed banner (global, top of window):** when this mesh is armed (G-4 status), a persistent
  red banner: *"⚠ ATTACK ALERT — this mesh self-destructs in ~Ns"* with a live countdown.
  - **Creator** sees an **`All clear`** button in the banner → `AllClear { mesh }` (creator-only;
    daemon rejects non-creators).
  - **Non-creator** sees *"waiting for the creator to clear or the mesh self-destructs"*.
- **After self-destruct:** the mesh disappears from the list; toast *"mesh self-destructed"*.

### G-4. Mesh health + state surface — Overview
- **Show:** current **cipher** + **epoch**, and **live N/total (threshold T)** so the user
  understands the P-C4 self-destruct floor. If `attack_armed_at` is set, show the armed state
  (drives G-3's banner). A subtle health pill: green (≥T live), amber (forming / below T),
  red (armed).
- **Requires IPC additions** (see §3) — MeshDetail doesn't carry this yet.

---

## 3. IPC additions needed / 필요한 IPC 추가
G-3's banner + G-4's health need state the GUI can't see today. Add to `MeshDetail`
(`ipc.rs`) + populate in `meshd` `mesh_detail`:
- `live: usize` — members heard within the live window (incl. self).
- `threshold: usize` — `quorum_threshold(roster)` (the self-destruct / re-cipher floor).
- `attack_armed_secs_left: Option<u64>` — `None` if not armed, else seconds until self-destruct
  (`ATTACK_GRACE - (now - attack_armed_at)`), so the banner can count down.
- `is_creator: bool` — `master.is_some()`, to show the `All clear` button only to the creator.

(`cipher` + `epoch` are already in `MeshDetail`.)

---

## 4. Build order / 단계
1. **G-0 IPC status** — add the §3 fields to `MeshDetail` + `mesh_detail`. (unblocks G-3/G-4)
2. **G-1 Re-cipher** — Overview Security card + confirm + `Recipher`.
3. **G-2 Invite algorithm** — algo selects on invite + join + the "tell them the algorithm" UX.
4. **G-3 Attack response** — danger-zone report + global armed banner + creator all-clear.
5. **G-4 Health surface** — cipher/epoch/live-threshold pill (uses G-0).

Then: implement (per phase, `node --check` + verify via the CLI IPC harness), and a 2-node
**live test** (re-cipher rotates both; an attack report on one arms the other; creator all-clear
cancels; cipher dropbox end-to-end). / 그 다음 단계별 구현(CLI IPC로 검증) + 2노드 라이브 테스트.

> Note on verifying GUI live: the dev webview proved flaky (WKWebView/HMR); verify the IPC via
> the CLI harness (`/tmp/ipc.py`) and the **production bundle** (`npm run tauri build`), not the
> dev webview. / dev webview는 불안정 → CLI + 프로덕션 빌드로 검증.

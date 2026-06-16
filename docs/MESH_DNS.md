# Mesh-internal name resolution / 메쉬 내부 이름 해석

**Goal / 목표.** Reach a member by **name**, not a number — `ssh oracle.mesh` instead of
`ssh 100.80.1.1`. Human-friendly names for in-mesh hosts. / 멤버를 **이름**으로 — 숫자 대신
`ssh oracle.mesh`. 메쉬 호스트에 사람이 읽는 이름.

> This is **not** public DNS and has **nothing to do with the full-tunnel exit / `10.0.0.53`
> problem** (that was about resolving *public* sites through the exit, docs/DISCOVERY.md is the
> mesh side). Mesh names never leave the machine. / 공인 DNS 아님, 풀터널 exit/DNS 문제와 무관.
> 메쉬 이름은 기기 밖으로 안 나감.

---

## 1. The key insight — it's a local lookup / 핵심: 로컬 룩업이다

Every node already holds the full **roster** (the validated `Cert`s) from the invite + gossip
(docs/DISCOVERY.md). Each cert carries `name` + `id`, and the overlay IP is *derived*:
`overlay = prefix.prefix.mesh_id.member_id` (`mesh/src/dataplane.rs::route`). So: / 모든 노드가
이미 invite+gossip으로 **roster** 보유. cert엔 `name`+`id`, overlay IP는 계산값. 그래서:

```
name "oracle" → roster cert{name:"oracle", id:1} → overlay 100.80.<mesh>.1
```

**No network query, no central server, no new protocol** — name resolution is a pure function
of state we *already have*. Discovery solved "everyone knows everyone"; naming is just a view
over it. / **네트워크 쿼리·중앙 서버·새 프로토콜 0** — 이미 가진 상태의 순수 함수. discovery가
끝낸 일의 다른 뷰일 뿐.

This is the same model as Tailscale **MagicDNS** (resolve peer names locally from the known
peer set), adapted to the per-mesh roster. / Tailscale MagicDNS와 같은 모델(아는 피어 집합에서
로컬 해석)을 per-mesh roster에 맞춤.

---

## 2. Namespace / 네임스페이스

A computer can be in **multiple meshes**, and `name` is unique only *within* a mesh, so the
scheme must disambiguate. / 한 컴퓨터가 **여러 메쉬**에 속할 수 있고 `name`은 메쉬 안에서만
유일 → 구분 필요.

**Suffix:** `.mesh` (reserved, never a real TLD). / 접미사 `.mesh`.

| Form | Resolves to | Use |
|---|---|---|
| `<member>.<mesh>.mesh` | that member in that mesh (fully-qualified, unambiguous) | always works, e.g. `oracle.live.mesh` |
| `<member>.mesh` | that member in the **current/egress** mesh (convenience) | single-mesh / the active one |

**Slugging.** `name`/mesh-name are free text (may have spaces, caps, unicode). Slugify to a
DNS label: lowercase, `[a-z0-9-]`, other → `-`, collapse repeats, trim. Collisions after
slugging fall back to `<member>-<id>`. / 이름은 자유 텍스트라 DNS 라벨로 슬러그화(소문자,
`[a-z0-9-]`); 충돌 시 `<member>-<id>`.

**No name?** Fallback label `m<id>` (e.g. `m3.live.mesh`). / 이름 없으면 `m<id>`.

> **Decision point.** Bare `<member>.mesh` = "current mesh" is convenient but ambiguous if no
> mesh is current. Alternative: always require the mesh-qualified form and skip the bare one.
> Recommend: support both, bare resolves only when exactly one mesh is up or one is current. /
> **결정 포인트:** bare 형식을 current 메쉬로 풀지 vs 항상 정규화 강제할지. 권장: 둘 다, bare는
> 메쉬가 하나거나 current일 때만.

---

## 3. Records served / 제공 레코드

From the live roster (always fresh — read at query time): / 라이브 roster에서 (쿼리 시점 조회):

- **Forward A** — `oracle.live.mesh → 100.80.<mesh>.1` (member's overlay IPv4).
- **Reverse PTR** — `1.<mesh>.80.100.in-addr.arpa → oracle.live.mesh` (overlay IP → name; nice
  for logs/UX). / 역방향(로그·UX용).
- (Later) **self / `me.mesh`** → this node's own overlay IP. / 자기 자신.

Only the mesh's own `/24` overlay range is answerable; anything else is **not ours** (see §5).
/ 메쉬 overlay /24만 응답, 나머진 우리 것 아님.

---

## 4. Resolution mechanism / 해석 메커니즘 — 2 phases

### P-N1 — `/etc/hosts` injection (fastest path) / hosts 주입 (가장 빠른 길)
meshd writes a managed block into `/etc/hosts` (it already runs as root): / meshd가 root로
`/etc/hosts`에 관리 블록 작성:

```
# >>> lattice-mesh (managed; do not edit) >>>
100.80.1.1   oracle.live.mesh oracle.mesh
100.80.1.3   mac.live.mesh    mac.mesh
# <<< lattice-mesh <<<
```

Rewritten whenever the roster changes (a join/admit). Pro: dead simple, works on every OS, no
DNS server, no resolver config. Con: static snapshot, no PTR/wildcard, touches a global file.
Good enough to make `ssh oracle.mesh` work **today**. / roster 바뀔 때마다 재작성. 장점: 단순,
전 OS, 리졸버 설정 불필요. 단점: 정적 스냅샷, PTR/와일드카드 없음. `ssh oracle.mesh` 당장 됨.

### P-N2 — split-DNS responder (the real thing) / 스플릿-DNS 응답자 (제대로)
meshd runs a tiny DNS server (one task, like the LAN beacon) bound to loopback (e.g.
`127.0.0.1:5354`) that answers A/PTR for `*.mesh` **from the live roster** and serves nothing
else. The OS is told to route only the `.mesh` domain to it: / meshd가 loopback에 작은 DNS
서버(태스크 하나)를 띄워 `*.mesh`만 라이브 roster로 응답, OS는 `.mesh`만 거기로 라우팅:

- **macOS:** `/etc/resolver/mesh` → `nameserver 127.0.0.1` + `port 5354`. macOS scopes
  `*.mesh` queries to it automatically. / `/etc/resolver/mesh` 파일.
- **Linux (systemd-resolved):** `resolvectl dns <iface> 127.0.0.1` + `resolvectl domain <iface>
  ~mesh` (routing-only domain). Fallback: dnsmasq, or just P-N1 hosts. / resolvectl 라우팅
  도메인, 폴백은 hosts.
- **Windows:** NRPT rule — `Add-DnsClientNrptRule -Namespace ".mesh" -NameServers 127.0.0.1`. /
  NRPT 규칙.

Dynamic (always live), supports PTR + wildcard, never pollutes `/etc/hosts`. This is the
MagicDNS-grade target. / 동적·PTR·와일드카드, hosts 안 건드림. MagicDNS급 목표.

### P-N3 — UX / integration
GUI shows names everywhere (topology, peer list use the resolved name already); `me.mesh`;
optional search-domain so bare `ssh oracle` works. / GUI 이름 표기, `me.mesh`, 검색 도메인으로
`ssh oracle`까지.

---

## 5. Safety — never break normal resolution / 안전 — 일반 해석 절대 안 깸

The **one** hard rule: only `*.mesh` (and the overlay PTR zone) is ours; **every other name
must fall through to the system's normal resolver untouched.** P-N1 only *adds* hosts entries
(non-`.mesh` unaffected); P-N2's resolver scoping routes *only* `.mesh` to us. No full-tunnel,
no DNS hijack, no dependence on the exit. / **유일한 철칙:** `*.mesh`(+overlay PTR)만 우리 것,
나머지는 전부 시스템 리졸버로 그대로 통과. 풀터널·DNS 하이재킹·exit 의존 전혀 없음.

This is why mesh naming is **orthogonal** to the full-tunnel DNS issue: it works whether egress
is direct or tunneled, online or offline. / 그래서 메쉬 네이밍은 풀터널 DNS 문제와 **직교** —
egress가 direct든 터널이든, 온라인이든 오프라인이든 동작.

---

## 6. Data source & freshness / 데이터 출처·신선도

Source = `MeshState` per mesh: `certs` (→ `roster()` for name+id), `mesh.charter.overlay_prefix`,
`mesh.id`. The P-N2 responder reads this **at query time** → always current. P-N1 rewrites the
hosts block on roster-changing events (`CreateInvite` admit, `JoinMesh`, `RemoveMesh`). /
출처 = `MeshState`(certs→roster, prefix, mesh id). P-N2는 쿼리 시점 조회(항상 최신), P-N1은
roster 변경 이벤트마다 재작성.

No liveness needed for *resolution* — a name resolves to an overlay IP even if the peer is
currently offline (reachability is the data plane's job, separate). / 해석엔 liveness 불필요 —
오프라인이어도 이름→overlay IP는 풀림(도달성은 데이터플레인 몫, 별개).

---

## 7. Edge cases / 엣지

- **Multi-mesh same name** (`oracle` in two meshes) → mesh-qualified form disambiguates; bare
  form only when unambiguous. / 다중 메쉬 동명 → 정규형으로 구분.
- **Renamed/re-admitted member** → roster is the source of truth; next read reflects it. /
  이름 변경 → roster가 진실.
- **`/etc/hosts` already has the name** → managed block is clearly delimited; never touch lines
  outside it; back up once. / hosts 기존 항목 → 관리 블록만, 밖은 안 건드림.
- **Name = a real-looking host** → the `.mesh` suffix keeps us out of the public namespace. /
  `.mesh` 접미사로 공인 네임스페이스 침범 안 함.

---

## 8. Phases / 단계
1. **P-N1 hosts injection** — `name.mesh`/`name.<mesh>.mesh` → overlay IP via a managed
   `/etc/hosts` block, rewritten on roster change. Forward only. Ships `ssh oracle.mesh` fast. /
   hosts 주입, 정방향, 빠른 출시.
2. **P-N2 split-DNS responder** — loopback DNS server over the live roster + per-OS `.mesh`
   resolver scoping; A + PTR + wildcard, dynamic. / 스플릿-DNS 응답자, 동적+PTR.
3. **P-N3 UX** — `me.mesh`, GUI name surfaces, search-domain for bare `ssh oracle`. / UX.

---

## TL;DR
Mesh naming = a **local view over the roster we already have** (name+id → overlay IP), served
first by an `/etc/hosts` block (P-N1) then a scoped loopback DNS responder for `*.mesh` (P-N2).
Zero network, zero central server, fully orthogonal to public DNS / the exit. / 메쉬 네이밍 =
**이미 가진 roster의 로컬 뷰**, hosts(P-N1)→`*.mesh` 스코프 DNS 응답자(P-N2)로 제공. 네트워크·중앙
서버 0, 공인 DNS/exit과 완전 직교.
